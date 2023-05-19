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
[13] /*
[14]  * the single part format:
[15]  *
[16]  * "HTTP/1.0 206 Partial Content" CRLF
[17]  * ... header ...
[18]  * "Content-Type: image/jpeg" CRLF
[19]  * "Content-Length: SIZE" CRLF
[20]  * "Content-Range: bytes START-END/SIZE" CRLF
[21]  * CRLF
[22]  * ... data ...
[23]  *
[24]  *
[25]  * the multipart format:
[26]  *
[27]  * "HTTP/1.0 206 Partial Content" CRLF
[28]  * ... header ...
[29]  * "Content-Type: multipart/byteranges; boundary=0123456789" CRLF
[30]  * CRLF
[31]  * CRLF
[32]  * "--0123456789" CRLF
[33]  * "Content-Type: image/jpeg" CRLF
[34]  * "Content-Range: bytes START0-END0/SIZE" CRLF
[35]  * CRLF
[36]  * ... data ...
[37]  * CRLF
[38]  * "--0123456789" CRLF
[39]  * "Content-Type: image/jpeg" CRLF
[40]  * "Content-Range: bytes START1-END1/SIZE" CRLF
[41]  * CRLF
[42]  * ... data ...
[43]  * CRLF
[44]  * "--0123456789--" CRLF
[45]  */
[46] 
[47] 
[48] typedef struct {
[49]     off_t        start;
[50]     off_t        end;
[51]     ngx_str_t    content_range;
[52] } ngx_http_range_t;
[53] 
[54] 
[55] typedef struct {
[56]     off_t        offset;
[57]     ngx_str_t    boundary_header;
[58]     ngx_array_t  ranges;
[59] } ngx_http_range_filter_ctx_t;
[60] 
[61] 
[62] static ngx_int_t ngx_http_range_parse(ngx_http_request_t *r,
[63]     ngx_http_range_filter_ctx_t *ctx, ngx_uint_t ranges);
[64] static ngx_int_t ngx_http_range_singlepart_header(ngx_http_request_t *r,
[65]     ngx_http_range_filter_ctx_t *ctx);
[66] static ngx_int_t ngx_http_range_multipart_header(ngx_http_request_t *r,
[67]     ngx_http_range_filter_ctx_t *ctx);
[68] static ngx_int_t ngx_http_range_not_satisfiable(ngx_http_request_t *r);
[69] static ngx_int_t ngx_http_range_test_overlapped(ngx_http_request_t *r,
[70]     ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
[71] static ngx_int_t ngx_http_range_singlepart_body(ngx_http_request_t *r,
[72]     ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
[73] static ngx_int_t ngx_http_range_multipart_body(ngx_http_request_t *r,
[74]     ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in);
[75] 
[76] static ngx_int_t ngx_http_range_header_filter_init(ngx_conf_t *cf);
[77] static ngx_int_t ngx_http_range_body_filter_init(ngx_conf_t *cf);
[78] 
[79] 
[80] static ngx_http_module_t  ngx_http_range_header_filter_module_ctx = {
[81]     NULL,                                  /* preconfiguration */
[82]     ngx_http_range_header_filter_init,     /* postconfiguration */
[83] 
[84]     NULL,                                  /* create main configuration */
[85]     NULL,                                  /* init main configuration */
[86] 
[87]     NULL,                                  /* create server configuration */
[88]     NULL,                                  /* merge server configuration */
[89] 
[90]     NULL,                                  /* create location configuration */
[91]     NULL,                                  /* merge location configuration */
[92] };
[93] 
[94] 
[95] ngx_module_t  ngx_http_range_header_filter_module = {
[96]     NGX_MODULE_V1,
[97]     &ngx_http_range_header_filter_module_ctx, /* module context */
[98]     NULL,                                  /* module directives */
[99]     NGX_HTTP_MODULE,                       /* module type */
[100]     NULL,                                  /* init master */
[101]     NULL,                                  /* init module */
[102]     NULL,                                  /* init process */
[103]     NULL,                                  /* init thread */
[104]     NULL,                                  /* exit thread */
[105]     NULL,                                  /* exit process */
[106]     NULL,                                  /* exit master */
[107]     NGX_MODULE_V1_PADDING
[108] };
[109] 
[110] 
[111] static ngx_http_module_t  ngx_http_range_body_filter_module_ctx = {
[112]     NULL,                                  /* preconfiguration */
[113]     ngx_http_range_body_filter_init,       /* postconfiguration */
[114] 
[115]     NULL,                                  /* create main configuration */
[116]     NULL,                                  /* init main configuration */
[117] 
[118]     NULL,                                  /* create server configuration */
[119]     NULL,                                  /* merge server configuration */
[120] 
[121]     NULL,                                  /* create location configuration */
[122]     NULL,                                  /* merge location configuration */
[123] };
[124] 
[125] 
[126] ngx_module_t  ngx_http_range_body_filter_module = {
[127]     NGX_MODULE_V1,
[128]     &ngx_http_range_body_filter_module_ctx, /* module context */
[129]     NULL,                                  /* module directives */
[130]     NGX_HTTP_MODULE,                       /* module type */
[131]     NULL,                                  /* init master */
[132]     NULL,                                  /* init module */
[133]     NULL,                                  /* init process */
[134]     NULL,                                  /* init thread */
[135]     NULL,                                  /* exit thread */
[136]     NULL,                                  /* exit process */
[137]     NULL,                                  /* exit master */
[138]     NGX_MODULE_V1_PADDING
[139] };
[140] 
[141] 
[142] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[143] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[144] 
[145] 
[146] static ngx_int_t
[147] ngx_http_range_header_filter(ngx_http_request_t *r)
[148] {
[149]     time_t                        if_range_time;
[150]     ngx_str_t                    *if_range, *etag;
[151]     ngx_uint_t                    ranges;
[152]     ngx_http_core_loc_conf_t     *clcf;
[153]     ngx_http_range_filter_ctx_t  *ctx;
[154] 
[155]     if (r->http_version < NGX_HTTP_VERSION_10
[156]         || r->headers_out.status != NGX_HTTP_OK
[157]         || (r != r->main && !r->subrequest_ranges)
[158]         || r->headers_out.content_length_n == -1
[159]         || !r->allow_ranges)
[160]     {
[161]         return ngx_http_next_header_filter(r);
[162]     }
[163] 
[164]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[165] 
[166]     if (clcf->max_ranges == 0) {
[167]         return ngx_http_next_header_filter(r);
[168]     }
[169] 
[170]     if (r->headers_in.range == NULL
[171]         || r->headers_in.range->value.len < 7
[172]         || ngx_strncasecmp(r->headers_in.range->value.data,
[173]                            (u_char *) "bytes=", 6)
[174]            != 0)
[175]     {
[176]         goto next_filter;
[177]     }
[178] 
[179]     if (r->headers_in.if_range) {
[180] 
[181]         if_range = &r->headers_in.if_range->value;
[182] 
[183]         if (if_range->len >= 2 && if_range->data[if_range->len - 1] == '"') {
[184] 
[185]             if (r->headers_out.etag == NULL) {
[186]                 goto next_filter;
[187]             }
[188] 
[189]             etag = &r->headers_out.etag->value;
[190] 
[191]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[192]                            "http ir:%V etag:%V", if_range, etag);
[193] 
[194]             if (if_range->len != etag->len
[195]                 || ngx_strncmp(if_range->data, etag->data, etag->len) != 0)
[196]             {
[197]                 goto next_filter;
[198]             }
[199] 
[200]             goto parse;
[201]         }
[202] 
[203]         if (r->headers_out.last_modified_time == (time_t) -1) {
[204]             goto next_filter;
[205]         }
[206] 
[207]         if_range_time = ngx_parse_http_time(if_range->data, if_range->len);
[208] 
[209]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[210]                        "http ir:%T lm:%T",
[211]                        if_range_time, r->headers_out.last_modified_time);
[212] 
[213]         if (if_range_time != r->headers_out.last_modified_time) {
[214]             goto next_filter;
[215]         }
[216]     }
[217] 
[218] parse:
[219] 
[220]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_range_filter_ctx_t));
[221]     if (ctx == NULL) {
[222]         return NGX_ERROR;
[223]     }
[224] 
[225]     ctx->offset = r->headers_out.content_offset;
[226] 
[227]     ranges = r->single_range ? 1 : clcf->max_ranges;
[228] 
[229]     switch (ngx_http_range_parse(r, ctx, ranges)) {
[230] 
[231]     case NGX_OK:
[232]         ngx_http_set_ctx(r, ctx, ngx_http_range_body_filter_module);
[233] 
[234]         r->headers_out.status = NGX_HTTP_PARTIAL_CONTENT;
[235]         r->headers_out.status_line.len = 0;
[236] 
[237]         if (ctx->ranges.nelts == 1) {
[238]             return ngx_http_range_singlepart_header(r, ctx);
[239]         }
[240] 
[241]         return ngx_http_range_multipart_header(r, ctx);
[242] 
[243]     case NGX_HTTP_RANGE_NOT_SATISFIABLE:
[244]         return ngx_http_range_not_satisfiable(r);
[245] 
[246]     case NGX_ERROR:
[247]         return NGX_ERROR;
[248] 
[249]     default: /* NGX_DECLINED */
[250]         break;
[251]     }
[252] 
[253] next_filter:
[254] 
[255]     r->headers_out.accept_ranges = ngx_list_push(&r->headers_out.headers);
[256]     if (r->headers_out.accept_ranges == NULL) {
[257]         return NGX_ERROR;
[258]     }
[259] 
[260]     r->headers_out.accept_ranges->hash = 1;
[261]     r->headers_out.accept_ranges->next = NULL;
[262]     ngx_str_set(&r->headers_out.accept_ranges->key, "Accept-Ranges");
[263]     ngx_str_set(&r->headers_out.accept_ranges->value, "bytes");
[264] 
[265]     return ngx_http_next_header_filter(r);
[266] }
[267] 
[268] 
[269] static ngx_int_t
[270] ngx_http_range_parse(ngx_http_request_t *r, ngx_http_range_filter_ctx_t *ctx,
[271]     ngx_uint_t ranges)
[272] {
[273]     u_char                       *p;
[274]     off_t                         start, end, size, content_length, cutoff,
[275]                                   cutlim;
[276]     ngx_uint_t                    suffix;
[277]     ngx_http_range_t             *range;
[278]     ngx_http_range_filter_ctx_t  *mctx;
[279] 
[280]     if (r != r->main) {
[281]         mctx = ngx_http_get_module_ctx(r->main,
[282]                                        ngx_http_range_body_filter_module);
[283]         if (mctx) {
[284]             ctx->ranges = mctx->ranges;
[285]             return NGX_OK;
[286]         }
[287]     }
[288] 
[289]     if (ngx_array_init(&ctx->ranges, r->pool, 1, sizeof(ngx_http_range_t))
[290]         != NGX_OK)
[291]     {
[292]         return NGX_ERROR;
[293]     }
[294] 
[295]     p = r->headers_in.range->value.data + 6;
[296]     size = 0;
[297]     content_length = r->headers_out.content_length_n;
[298] 
[299]     cutoff = NGX_MAX_OFF_T_VALUE / 10;
[300]     cutlim = NGX_MAX_OFF_T_VALUE % 10;
[301] 
[302]     for ( ;; ) {
[303]         start = 0;
[304]         end = 0;
[305]         suffix = 0;
[306] 
[307]         while (*p == ' ') { p++; }
[308] 
[309]         if (*p != '-') {
[310]             if (*p < '0' || *p > '9') {
[311]                 return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[312]             }
[313] 
[314]             while (*p >= '0' && *p <= '9') {
[315]                 if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
[316]                     return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[317]                 }
[318] 
[319]                 start = start * 10 + (*p++ - '0');
[320]             }
[321] 
[322]             while (*p == ' ') { p++; }
[323] 
[324]             if (*p++ != '-') {
[325]                 return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[326]             }
[327] 
[328]             while (*p == ' ') { p++; }
[329] 
[330]             if (*p == ',' || *p == '\0') {
[331]                 end = content_length;
[332]                 goto found;
[333]             }
[334] 
[335]         } else {
[336]             suffix = 1;
[337]             p++;
[338]         }
[339] 
[340]         if (*p < '0' || *p > '9') {
[341]             return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[342]         }
[343] 
[344]         while (*p >= '0' && *p <= '9') {
[345]             if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
[346]                 return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[347]             }
[348] 
[349]             end = end * 10 + (*p++ - '0');
[350]         }
[351] 
[352]         while (*p == ' ') { p++; }
[353] 
[354]         if (*p != ',' && *p != '\0') {
[355]             return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[356]         }
[357] 
[358]         if (suffix) {
[359]             start = (end < content_length) ? content_length - end : 0;
[360]             end = content_length - 1;
[361]         }
[362] 
[363]         if (end >= content_length) {
[364]             end = content_length;
[365] 
[366]         } else {
[367]             end++;
[368]         }
[369] 
[370]     found:
[371] 
[372]         if (start < end) {
[373]             range = ngx_array_push(&ctx->ranges);
[374]             if (range == NULL) {
[375]                 return NGX_ERROR;
[376]             }
[377] 
[378]             range->start = start;
[379]             range->end = end;
[380] 
[381]             if (size > NGX_MAX_OFF_T_VALUE - (end - start)) {
[382]                 return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[383]             }
[384] 
[385]             size += end - start;
[386] 
[387]             if (ranges-- == 0) {
[388]                 return NGX_DECLINED;
[389]             }
[390] 
[391]         } else if (start == 0) {
[392]             return NGX_DECLINED;
[393]         }
[394] 
[395]         if (*p++ != ',') {
[396]             break;
[397]         }
[398]     }
[399] 
[400]     if (ctx->ranges.nelts == 0) {
[401]         return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[402]     }
[403] 
[404]     if (size > content_length) {
[405]         return NGX_DECLINED;
[406]     }
[407] 
[408]     return NGX_OK;
[409] }
[410] 
[411] 
[412] static ngx_int_t
[413] ngx_http_range_singlepart_header(ngx_http_request_t *r,
[414]     ngx_http_range_filter_ctx_t *ctx)
[415] {
[416]     ngx_table_elt_t   *content_range;
[417]     ngx_http_range_t  *range;
[418] 
[419]     if (r != r->main) {
[420]         return ngx_http_next_header_filter(r);
[421]     }
[422] 
[423]     content_range = ngx_list_push(&r->headers_out.headers);
[424]     if (content_range == NULL) {
[425]         return NGX_ERROR;
[426]     }
[427] 
[428]     if (r->headers_out.content_range) {
[429]         r->headers_out.content_range->hash = 0;
[430]     }
[431] 
[432]     r->headers_out.content_range = content_range;
[433] 
[434]     content_range->hash = 1;
[435]     content_range->next = NULL;
[436]     ngx_str_set(&content_range->key, "Content-Range");
[437] 
[438]     content_range->value.data = ngx_pnalloc(r->pool,
[439]                                     sizeof("bytes -/") - 1 + 3 * NGX_OFF_T_LEN);
[440]     if (content_range->value.data == NULL) {
[441]         content_range->hash = 0;
[442]         r->headers_out.content_range = NULL;
[443]         return NGX_ERROR;
[444]     }
[445] 
[446]     /* "Content-Range: bytes SSSS-EEEE/TTTT" header */
[447] 
[448]     range = ctx->ranges.elts;
[449] 
[450]     content_range->value.len = ngx_sprintf(content_range->value.data,
[451]                                            "bytes %O-%O/%O",
[452]                                            range->start, range->end - 1,
[453]                                            r->headers_out.content_length_n)
[454]                                - content_range->value.data;
[455] 
[456]     r->headers_out.content_length_n = range->end - range->start;
[457]     r->headers_out.content_offset = range->start;
[458] 
[459]     if (r->headers_out.content_length) {
[460]         r->headers_out.content_length->hash = 0;
[461]         r->headers_out.content_length = NULL;
[462]     }
[463] 
[464]     return ngx_http_next_header_filter(r);
[465] }
[466] 
[467] 
[468] static ngx_int_t
[469] ngx_http_range_multipart_header(ngx_http_request_t *r,
[470]     ngx_http_range_filter_ctx_t *ctx)
[471] {
[472]     off_t               len;
[473]     size_t              size;
[474]     ngx_uint_t          i;
[475]     ngx_http_range_t   *range;
[476]     ngx_atomic_uint_t   boundary;
[477] 
[478]     size = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
[479]            + sizeof(CRLF "Content-Type: ") - 1
[480]            + r->headers_out.content_type.len
[481]            + sizeof(CRLF "Content-Range: bytes ") - 1;
[482] 
[483]     if (r->headers_out.content_type_len == r->headers_out.content_type.len
[484]         && r->headers_out.charset.len)
[485]     {
[486]         size += sizeof("; charset=") - 1 + r->headers_out.charset.len;
[487]     }
[488] 
[489]     ctx->boundary_header.data = ngx_pnalloc(r->pool, size);
[490]     if (ctx->boundary_header.data == NULL) {
[491]         return NGX_ERROR;
[492]     }
[493] 
[494]     boundary = ngx_next_temp_number(0);
[495] 
[496]     /*
[497]      * The boundary header of the range:
[498]      * CRLF
[499]      * "--0123456789" CRLF
[500]      * "Content-Type: image/jpeg" CRLF
[501]      * "Content-Range: bytes "
[502]      */
[503] 
[504]     if (r->headers_out.content_type_len == r->headers_out.content_type.len
[505]         && r->headers_out.charset.len)
[506]     {
[507]         ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
[508]                                            CRLF "--%0muA" CRLF
[509]                                            "Content-Type: %V; charset=%V" CRLF
[510]                                            "Content-Range: bytes ",
[511]                                            boundary,
[512]                                            &r->headers_out.content_type,
[513]                                            &r->headers_out.charset)
[514]                                    - ctx->boundary_header.data;
[515] 
[516]     } else if (r->headers_out.content_type.len) {
[517]         ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
[518]                                            CRLF "--%0muA" CRLF
[519]                                            "Content-Type: %V" CRLF
[520]                                            "Content-Range: bytes ",
[521]                                            boundary,
[522]                                            &r->headers_out.content_type)
[523]                                    - ctx->boundary_header.data;
[524] 
[525]     } else {
[526]         ctx->boundary_header.len = ngx_sprintf(ctx->boundary_header.data,
[527]                                            CRLF "--%0muA" CRLF
[528]                                            "Content-Range: bytes ",
[529]                                            boundary)
[530]                                    - ctx->boundary_header.data;
[531]     }
[532] 
[533]     r->headers_out.content_type.data =
[534]         ngx_pnalloc(r->pool,
[535]                     sizeof("Content-Type: multipart/byteranges; boundary=") - 1
[536]                     + NGX_ATOMIC_T_LEN);
[537] 
[538]     if (r->headers_out.content_type.data == NULL) {
[539]         return NGX_ERROR;
[540]     }
[541] 
[542]     r->headers_out.content_type_lowcase = NULL;
[543] 
[544]     /* "Content-Type: multipart/byteranges; boundary=0123456789" */
[545] 
[546]     r->headers_out.content_type.len =
[547]                            ngx_sprintf(r->headers_out.content_type.data,
[548]                                        "multipart/byteranges; boundary=%0muA",
[549]                                        boundary)
[550]                            - r->headers_out.content_type.data;
[551] 
[552]     r->headers_out.content_type_len = r->headers_out.content_type.len;
[553] 
[554]     r->headers_out.charset.len = 0;
[555] 
[556]     /* the size of the last boundary CRLF "--0123456789--" CRLF */
[557] 
[558]     len = sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN + sizeof("--" CRLF) - 1;
[559] 
[560]     range = ctx->ranges.elts;
[561]     for (i = 0; i < ctx->ranges.nelts; i++) {
[562] 
[563]         /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */
[564] 
[565]         range[i].content_range.data =
[566]                                ngx_pnalloc(r->pool, 3 * NGX_OFF_T_LEN + 2 + 4);
[567] 
[568]         if (range[i].content_range.data == NULL) {
[569]             return NGX_ERROR;
[570]         }
[571] 
[572]         range[i].content_range.len = ngx_sprintf(range[i].content_range.data,
[573]                                                "%O-%O/%O" CRLF CRLF,
[574]                                                range[i].start, range[i].end - 1,
[575]                                                r->headers_out.content_length_n)
[576]                                      - range[i].content_range.data;
[577] 
[578]         len += ctx->boundary_header.len + range[i].content_range.len
[579]                                              + (range[i].end - range[i].start);
[580]     }
[581] 
[582]     r->headers_out.content_length_n = len;
[583] 
[584]     if (r->headers_out.content_length) {
[585]         r->headers_out.content_length->hash = 0;
[586]         r->headers_out.content_length = NULL;
[587]     }
[588] 
[589]     if (r->headers_out.content_range) {
[590]         r->headers_out.content_range->hash = 0;
[591]         r->headers_out.content_range = NULL;
[592]     }
[593] 
[594]     return ngx_http_next_header_filter(r);
[595] }
[596] 
[597] 
[598] static ngx_int_t
[599] ngx_http_range_not_satisfiable(ngx_http_request_t *r)
[600] {
[601]     ngx_table_elt_t  *content_range;
[602] 
[603]     r->headers_out.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
[604] 
[605]     content_range = ngx_list_push(&r->headers_out.headers);
[606]     if (content_range == NULL) {
[607]         return NGX_ERROR;
[608]     }
[609] 
[610]     if (r->headers_out.content_range) {
[611]         r->headers_out.content_range->hash = 0;
[612]     }
[613] 
[614]     r->headers_out.content_range = content_range;
[615] 
[616]     content_range->hash = 1;
[617]     content_range->next = NULL;
[618]     ngx_str_set(&content_range->key, "Content-Range");
[619] 
[620]     content_range->value.data = ngx_pnalloc(r->pool,
[621]                                        sizeof("bytes */") - 1 + NGX_OFF_T_LEN);
[622]     if (content_range->value.data == NULL) {
[623]         content_range->hash = 0;
[624]         r->headers_out.content_range = NULL;
[625]         return NGX_ERROR;
[626]     }
[627] 
[628]     content_range->value.len = ngx_sprintf(content_range->value.data,
[629]                                            "bytes */%O",
[630]                                            r->headers_out.content_length_n)
[631]                                - content_range->value.data;
[632] 
[633]     ngx_http_clear_content_length(r);
[634] 
[635]     return NGX_HTTP_RANGE_NOT_SATISFIABLE;
[636] }
[637] 
[638] 
[639] static ngx_int_t
[640] ngx_http_range_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[641] {
[642]     ngx_http_range_filter_ctx_t  *ctx;
[643] 
[644]     if (in == NULL) {
[645]         return ngx_http_next_body_filter(r, in);
[646]     }
[647] 
[648]     ctx = ngx_http_get_module_ctx(r, ngx_http_range_body_filter_module);
[649] 
[650]     if (ctx == NULL) {
[651]         return ngx_http_next_body_filter(r, in);
[652]     }
[653] 
[654]     if (ctx->ranges.nelts == 1) {
[655]         return ngx_http_range_singlepart_body(r, ctx, in);
[656]     }
[657] 
[658]     /*
[659]      * multipart ranges are supported only if whole body is in a single buffer
[660]      */
[661] 
[662]     if (ngx_buf_special(in->buf)) {
[663]         return ngx_http_next_body_filter(r, in);
[664]     }
[665] 
[666]     if (ngx_http_range_test_overlapped(r, ctx, in) != NGX_OK) {
[667]         return NGX_ERROR;
[668]     }
[669] 
[670]     return ngx_http_range_multipart_body(r, ctx, in);
[671] }
[672] 
[673] 
[674] static ngx_int_t
[675] ngx_http_range_test_overlapped(ngx_http_request_t *r,
[676]     ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
[677] {
[678]     off_t              start, last;
[679]     ngx_buf_t         *buf;
[680]     ngx_uint_t         i;
[681]     ngx_http_range_t  *range;
[682] 
[683]     if (ctx->offset) {
[684]         goto overlapped;
[685]     }
[686] 
[687]     buf = in->buf;
[688] 
[689]     if (!buf->last_buf) {
[690]         start = ctx->offset;
[691]         last = ctx->offset + ngx_buf_size(buf);
[692] 
[693]         range = ctx->ranges.elts;
[694]         for (i = 0; i < ctx->ranges.nelts; i++) {
[695]             if (start > range[i].start || last < range[i].end) {
[696]                 goto overlapped;
[697]             }
[698]         }
[699]     }
[700] 
[701]     ctx->offset = ngx_buf_size(buf);
[702] 
[703]     return NGX_OK;
[704] 
[705] overlapped:
[706] 
[707]     ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[708]                   "range in overlapped buffers");
[709] 
[710]     return NGX_ERROR;
[711] }
[712] 
[713] 
[714] static ngx_int_t
[715] ngx_http_range_singlepart_body(ngx_http_request_t *r,
[716]     ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
[717] {
[718]     off_t              start, last;
[719]     ngx_int_t          rc;
[720]     ngx_buf_t         *buf;
[721]     ngx_chain_t       *out, *cl, *tl, **ll;
[722]     ngx_http_range_t  *range;
[723] 
[724]     out = NULL;
[725]     ll = &out;
[726]     range = ctx->ranges.elts;
[727] 
[728]     for (cl = in; cl; cl = cl->next) {
[729] 
[730]         buf = cl->buf;
[731] 
[732]         start = ctx->offset;
[733]         last = ctx->offset + ngx_buf_size(buf);
[734] 
[735]         ctx->offset = last;
[736] 
[737]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[738]                        "http range body buf: %O-%O", start, last);
[739] 
[740]         if (ngx_buf_special(buf)) {
[741] 
[742]             if (range->end <= start) {
[743]                 continue;
[744]             }
[745] 
[746]             tl = ngx_alloc_chain_link(r->pool);
[747]             if (tl == NULL) {
[748]                 return NGX_ERROR;
[749]             }
[750] 
[751]             tl->buf = buf;
[752]             tl->next = NULL;
[753] 
[754]             *ll = tl;
[755]             ll = &tl->next;
[756] 
[757]             continue;
[758]         }
[759] 
[760]         if (range->end <= start || range->start >= last) {
[761] 
[762]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[763]                            "http range body skip");
[764] 
[765]             if (buf->in_file) {
[766]                 buf->file_pos = buf->file_last;
[767]             }
[768] 
[769]             buf->pos = buf->last;
[770]             buf->sync = 1;
[771] 
[772]             continue;
[773]         }
[774] 
[775]         if (range->start > start) {
[776] 
[777]             if (buf->in_file) {
[778]                 buf->file_pos += range->start - start;
[779]             }
[780] 
[781]             if (ngx_buf_in_memory(buf)) {
[782]                 buf->pos += (size_t) (range->start - start);
[783]             }
[784]         }
[785] 
[786]         if (range->end <= last) {
[787] 
[788]             if (buf->in_file) {
[789]                 buf->file_last -= last - range->end;
[790]             }
[791] 
[792]             if (ngx_buf_in_memory(buf)) {
[793]                 buf->last -= (size_t) (last - range->end);
[794]             }
[795] 
[796]             buf->last_buf = (r == r->main) ? 1 : 0;
[797]             buf->last_in_chain = 1;
[798] 
[799]             tl = ngx_alloc_chain_link(r->pool);
[800]             if (tl == NULL) {
[801]                 return NGX_ERROR;
[802]             }
[803] 
[804]             tl->buf = buf;
[805]             tl->next = NULL;
[806] 
[807]             *ll = tl;
[808]             ll = &tl->next;
[809] 
[810]             continue;
[811]         }
[812] 
[813]         tl = ngx_alloc_chain_link(r->pool);
[814]         if (tl == NULL) {
[815]             return NGX_ERROR;
[816]         }
[817] 
[818]         tl->buf = buf;
[819]         tl->next = NULL;
[820] 
[821]         *ll = tl;
[822]         ll = &tl->next;
[823]     }
[824] 
[825]     rc = ngx_http_next_body_filter(r, out);
[826] 
[827]     while (out) {
[828]         cl = out;
[829]         out = out->next;
[830]         ngx_free_chain(r->pool, cl);
[831]     }
[832] 
[833]     return rc;
[834] }
[835] 
[836] 
[837] static ngx_int_t
[838] ngx_http_range_multipart_body(ngx_http_request_t *r,
[839]     ngx_http_range_filter_ctx_t *ctx, ngx_chain_t *in)
[840] {
[841]     ngx_buf_t         *b, *buf;
[842]     ngx_uint_t         i;
[843]     ngx_chain_t       *out, *hcl, *rcl, *dcl, **ll;
[844]     ngx_http_range_t  *range;
[845] 
[846]     ll = &out;
[847]     buf = in->buf;
[848]     range = ctx->ranges.elts;
[849] 
[850]     for (i = 0; i < ctx->ranges.nelts; i++) {
[851] 
[852]         /*
[853]          * The boundary header of the range:
[854]          * CRLF
[855]          * "--0123456789" CRLF
[856]          * "Content-Type: image/jpeg" CRLF
[857]          * "Content-Range: bytes "
[858]          */
[859] 
[860]         b = ngx_calloc_buf(r->pool);
[861]         if (b == NULL) {
[862]             return NGX_ERROR;
[863]         }
[864] 
[865]         b->memory = 1;
[866]         b->pos = ctx->boundary_header.data;
[867]         b->last = ctx->boundary_header.data + ctx->boundary_header.len;
[868] 
[869]         hcl = ngx_alloc_chain_link(r->pool);
[870]         if (hcl == NULL) {
[871]             return NGX_ERROR;
[872]         }
[873] 
[874]         hcl->buf = b;
[875] 
[876] 
[877]         /* "SSSS-EEEE/TTTT" CRLF CRLF */
[878] 
[879]         b = ngx_calloc_buf(r->pool);
[880]         if (b == NULL) {
[881]             return NGX_ERROR;
[882]         }
[883] 
[884]         b->temporary = 1;
[885]         b->pos = range[i].content_range.data;
[886]         b->last = range[i].content_range.data + range[i].content_range.len;
[887] 
[888]         rcl = ngx_alloc_chain_link(r->pool);
[889]         if (rcl == NULL) {
[890]             return NGX_ERROR;
[891]         }
[892] 
[893]         rcl->buf = b;
[894] 
[895] 
[896]         /* the range data */
[897] 
[898]         b = ngx_calloc_buf(r->pool);
[899]         if (b == NULL) {
[900]             return NGX_ERROR;
[901]         }
[902] 
[903]         b->in_file = buf->in_file;
[904]         b->temporary = buf->temporary;
[905]         b->memory = buf->memory;
[906]         b->mmap = buf->mmap;
[907]         b->file = buf->file;
[908] 
[909]         if (buf->in_file) {
[910]             b->file_pos = buf->file_pos + range[i].start;
[911]             b->file_last = buf->file_pos + range[i].end;
[912]         }
[913] 
[914]         if (ngx_buf_in_memory(buf)) {
[915]             b->pos = buf->pos + (size_t) range[i].start;
[916]             b->last = buf->pos + (size_t) range[i].end;
[917]         }
[918] 
[919]         dcl = ngx_alloc_chain_link(r->pool);
[920]         if (dcl == NULL) {
[921]             return NGX_ERROR;
[922]         }
[923] 
[924]         dcl->buf = b;
[925] 
[926]         *ll = hcl;
[927]         hcl->next = rcl;
[928]         rcl->next = dcl;
[929]         ll = &dcl->next;
[930]     }
[931] 
[932]     /* the last boundary CRLF "--0123456789--" CRLF  */
[933] 
[934]     b = ngx_calloc_buf(r->pool);
[935]     if (b == NULL) {
[936]         return NGX_ERROR;
[937]     }
[938] 
[939]     b->temporary = 1;
[940]     b->last_buf = 1;
[941] 
[942]     b->pos = ngx_pnalloc(r->pool, sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN
[943]                                   + sizeof("--" CRLF) - 1);
[944]     if (b->pos == NULL) {
[945]         return NGX_ERROR;
[946]     }
[947] 
[948]     b->last = ngx_cpymem(b->pos, ctx->boundary_header.data,
[949]                          sizeof(CRLF "--") - 1 + NGX_ATOMIC_T_LEN);
[950]     *b->last++ = '-'; *b->last++ = '-';
[951]     *b->last++ = CR; *b->last++ = LF;
[952] 
[953]     hcl = ngx_alloc_chain_link(r->pool);
[954]     if (hcl == NULL) {
[955]         return NGX_ERROR;
[956]     }
[957] 
[958]     hcl->buf = b;
[959]     hcl->next = NULL;
[960] 
[961]     *ll = hcl;
[962] 
[963]     return ngx_http_next_body_filter(r, out);
[964] }
[965] 
[966] 
[967] static ngx_int_t
[968] ngx_http_range_header_filter_init(ngx_conf_t *cf)
[969] {
[970]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[971]     ngx_http_top_header_filter = ngx_http_range_header_filter;
[972] 
[973]     return NGX_OK;
[974] }
[975] 
[976] 
[977] static ngx_int_t
[978] ngx_http_range_body_filter_init(ngx_conf_t *cf)
[979] {
[980]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[981]     ngx_http_top_body_filter = ngx_http_range_body_filter;
[982] 
[983]     return NGX_OK;
[984] }
