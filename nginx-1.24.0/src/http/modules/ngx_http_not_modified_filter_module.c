[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] static ngx_uint_t ngx_http_test_if_unmodified(ngx_http_request_t *r);
[14] static ngx_uint_t ngx_http_test_if_modified(ngx_http_request_t *r);
[15] static ngx_uint_t ngx_http_test_if_match(ngx_http_request_t *r,
[16]     ngx_table_elt_t *header, ngx_uint_t weak);
[17] static ngx_int_t ngx_http_not_modified_filter_init(ngx_conf_t *cf);
[18] 
[19] 
[20] static ngx_http_module_t  ngx_http_not_modified_filter_module_ctx = {
[21]     NULL,                                  /* preconfiguration */
[22]     ngx_http_not_modified_filter_init,     /* postconfiguration */
[23] 
[24]     NULL,                                  /* create main configuration */
[25]     NULL,                                  /* init main configuration */
[26] 
[27]     NULL,                                  /* create server configuration */
[28]     NULL,                                  /* merge server configuration */
[29] 
[30]     NULL,                                  /* create location configuration */
[31]     NULL                                   /* merge location configuration */
[32] };
[33] 
[34] 
[35] ngx_module_t  ngx_http_not_modified_filter_module = {
[36]     NGX_MODULE_V1,
[37]     &ngx_http_not_modified_filter_module_ctx, /* module context */
[38]     NULL,                                  /* module directives */
[39]     NGX_HTTP_MODULE,                       /* module type */
[40]     NULL,                                  /* init master */
[41]     NULL,                                  /* init module */
[42]     NULL,                                  /* init process */
[43]     NULL,                                  /* init thread */
[44]     NULL,                                  /* exit thread */
[45]     NULL,                                  /* exit process */
[46]     NULL,                                  /* exit master */
[47]     NGX_MODULE_V1_PADDING
[48] };
[49] 
[50] 
[51] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[52] 
[53] 
[54] static ngx_int_t
[55] ngx_http_not_modified_header_filter(ngx_http_request_t *r)
[56] {
[57]     if (r->headers_out.status != NGX_HTTP_OK
[58]         || r != r->main
[59]         || r->disable_not_modified)
[60]     {
[61]         return ngx_http_next_header_filter(r);
[62]     }
[63] 
[64]     if (r->headers_in.if_unmodified_since
[65]         && !ngx_http_test_if_unmodified(r))
[66]     {
[67]         return ngx_http_filter_finalize_request(r, NULL,
[68]                                                 NGX_HTTP_PRECONDITION_FAILED);
[69]     }
[70] 
[71]     if (r->headers_in.if_match
[72]         && !ngx_http_test_if_match(r, r->headers_in.if_match, 0))
[73]     {
[74]         return ngx_http_filter_finalize_request(r, NULL,
[75]                                                 NGX_HTTP_PRECONDITION_FAILED);
[76]     }
[77] 
[78]     if (r->headers_in.if_modified_since || r->headers_in.if_none_match) {
[79] 
[80]         if (r->headers_in.if_modified_since
[81]             && ngx_http_test_if_modified(r))
[82]         {
[83]             return ngx_http_next_header_filter(r);
[84]         }
[85] 
[86]         if (r->headers_in.if_none_match
[87]             && !ngx_http_test_if_match(r, r->headers_in.if_none_match, 1))
[88]         {
[89]             return ngx_http_next_header_filter(r);
[90]         }
[91] 
[92]         /* not modified */
[93] 
[94]         r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
[95]         r->headers_out.status_line.len = 0;
[96]         r->headers_out.content_type.len = 0;
[97]         ngx_http_clear_content_length(r);
[98]         ngx_http_clear_accept_ranges(r);
[99] 
[100]         if (r->headers_out.content_encoding) {
[101]             r->headers_out.content_encoding->hash = 0;
[102]             r->headers_out.content_encoding = NULL;
[103]         }
[104] 
[105]         return ngx_http_next_header_filter(r);
[106]     }
[107] 
[108]     return ngx_http_next_header_filter(r);
[109] }
[110] 
[111] 
[112] static ngx_uint_t
[113] ngx_http_test_if_unmodified(ngx_http_request_t *r)
[114] {
[115]     time_t  iums;
[116] 
[117]     if (r->headers_out.last_modified_time == (time_t) -1) {
[118]         return 0;
[119]     }
[120] 
[121]     iums = ngx_parse_http_time(r->headers_in.if_unmodified_since->value.data,
[122]                                r->headers_in.if_unmodified_since->value.len);
[123] 
[124]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[125]                  "http iums:%T lm:%T", iums, r->headers_out.last_modified_time);
[126] 
[127]     if (iums >= r->headers_out.last_modified_time) {
[128]         return 1;
[129]     }
[130] 
[131]     return 0;
[132] }
[133] 
[134] 
[135] static ngx_uint_t
[136] ngx_http_test_if_modified(ngx_http_request_t *r)
[137] {
[138]     time_t                     ims;
[139]     ngx_http_core_loc_conf_t  *clcf;
[140] 
[141]     if (r->headers_out.last_modified_time == (time_t) -1) {
[142]         return 1;
[143]     }
[144] 
[145]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[146] 
[147]     if (clcf->if_modified_since == NGX_HTTP_IMS_OFF) {
[148]         return 1;
[149]     }
[150] 
[151]     ims = ngx_parse_http_time(r->headers_in.if_modified_since->value.data,
[152]                               r->headers_in.if_modified_since->value.len);
[153] 
[154]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[155]                    "http ims:%T lm:%T", ims, r->headers_out.last_modified_time);
[156] 
[157]     if (ims == r->headers_out.last_modified_time) {
[158]         return 0;
[159]     }
[160] 
[161]     if (clcf->if_modified_since == NGX_HTTP_IMS_EXACT
[162]         || ims < r->headers_out.last_modified_time)
[163]     {
[164]         return 1;
[165]     }
[166] 
[167]     return 0;
[168] }
[169] 
[170] 
[171] static ngx_uint_t
[172] ngx_http_test_if_match(ngx_http_request_t *r, ngx_table_elt_t *header,
[173]     ngx_uint_t weak)
[174] {
[175]     u_char     *start, *end, ch;
[176]     ngx_str_t   etag, *list;
[177] 
[178]     list = &header->value;
[179] 
[180]     if (list->len == 1 && list->data[0] == '*') {
[181]         return 1;
[182]     }
[183] 
[184]     if (r->headers_out.etag == NULL) {
[185]         return 0;
[186]     }
[187] 
[188]     etag = r->headers_out.etag->value;
[189] 
[190]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[191]                    "http im:\"%V\" etag:%V", list, &etag);
[192] 
[193]     if (weak
[194]         && etag.len > 2
[195]         && etag.data[0] == 'W'
[196]         && etag.data[1] == '/')
[197]     {
[198]         etag.len -= 2;
[199]         etag.data += 2;
[200]     }
[201] 
[202]     start = list->data;
[203]     end = list->data + list->len;
[204] 
[205]     while (start < end) {
[206] 
[207]         if (weak
[208]             && end - start > 2
[209]             && start[0] == 'W'
[210]             && start[1] == '/')
[211]         {
[212]             start += 2;
[213]         }
[214] 
[215]         if (etag.len > (size_t) (end - start)) {
[216]             return 0;
[217]         }
[218] 
[219]         if (ngx_strncmp(start, etag.data, etag.len) != 0) {
[220]             goto skip;
[221]         }
[222] 
[223]         start += etag.len;
[224] 
[225]         while (start < end) {
[226]             ch = *start;
[227] 
[228]             if (ch == ' ' || ch == '\t') {
[229]                 start++;
[230]                 continue;
[231]             }
[232] 
[233]             break;
[234]         }
[235] 
[236]         if (start == end || *start == ',') {
[237]             return 1;
[238]         }
[239] 
[240]     skip:
[241] 
[242]         while (start < end && *start != ',') { start++; }
[243]         while (start < end) {
[244]             ch = *start;
[245] 
[246]             if (ch == ' ' || ch == '\t' || ch == ',') {
[247]                 start++;
[248]                 continue;
[249]             }
[250] 
[251]             break;
[252]         }
[253]     }
[254] 
[255]     return 0;
[256] }
[257] 
[258] 
[259] static ngx_int_t
[260] ngx_http_not_modified_filter_init(ngx_conf_t *cf)
[261] {
[262]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[263]     ngx_http_top_header_filter = ngx_http_not_modified_header_filter;
[264] 
[265]     return NGX_OK;
[266] }
