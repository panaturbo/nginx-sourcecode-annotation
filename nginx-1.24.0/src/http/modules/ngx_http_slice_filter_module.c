[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] typedef struct {
[14]     size_t               size;
[15] } ngx_http_slice_loc_conf_t;
[16] 
[17] 
[18] typedef struct {
[19]     off_t                start;
[20]     off_t                end;
[21]     ngx_str_t            range;
[22]     ngx_str_t            etag;
[23]     unsigned             last:1;
[24]     unsigned             active:1;
[25]     ngx_http_request_t  *sr;
[26] } ngx_http_slice_ctx_t;
[27] 
[28] 
[29] typedef struct {
[30]     off_t                start;
[31]     off_t                end;
[32]     off_t                complete_length;
[33] } ngx_http_slice_content_range_t;
[34] 
[35] 
[36] static ngx_int_t ngx_http_slice_header_filter(ngx_http_request_t *r);
[37] static ngx_int_t ngx_http_slice_body_filter(ngx_http_request_t *r,
[38]     ngx_chain_t *in);
[39] static ngx_int_t ngx_http_slice_parse_content_range(ngx_http_request_t *r,
[40]     ngx_http_slice_content_range_t *cr);
[41] static ngx_int_t ngx_http_slice_range_variable(ngx_http_request_t *r,
[42]     ngx_http_variable_value_t *v, uintptr_t data);
[43] static off_t ngx_http_slice_get_start(ngx_http_request_t *r);
[44] static void *ngx_http_slice_create_loc_conf(ngx_conf_t *cf);
[45] static char *ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent,
[46]     void *child);
[47] static ngx_int_t ngx_http_slice_add_variables(ngx_conf_t *cf);
[48] static ngx_int_t ngx_http_slice_init(ngx_conf_t *cf);
[49] 
[50] 
[51] static ngx_command_t  ngx_http_slice_filter_commands[] = {
[52] 
[53]     { ngx_string("slice"),
[54]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[55]       ngx_conf_set_size_slot,
[56]       NGX_HTTP_LOC_CONF_OFFSET,
[57]       offsetof(ngx_http_slice_loc_conf_t, size),
[58]       NULL },
[59] 
[60]       ngx_null_command
[61] };
[62] 
[63] 
[64] static ngx_http_module_t  ngx_http_slice_filter_module_ctx = {
[65]     ngx_http_slice_add_variables,          /* preconfiguration */
[66]     ngx_http_slice_init,                   /* postconfiguration */
[67] 
[68]     NULL,                                  /* create main configuration */
[69]     NULL,                                  /* init main configuration */
[70] 
[71]     NULL,                                  /* create server configuration */
[72]     NULL,                                  /* merge server configuration */
[73] 
[74]     ngx_http_slice_create_loc_conf,        /* create location configuration */
[75]     ngx_http_slice_merge_loc_conf          /* merge location configuration */
[76] };
[77] 
[78] 
[79] ngx_module_t  ngx_http_slice_filter_module = {
[80]     NGX_MODULE_V1,
[81]     &ngx_http_slice_filter_module_ctx,     /* module context */
[82]     ngx_http_slice_filter_commands,        /* module directives */
[83]     NGX_HTTP_MODULE,                       /* module type */
[84]     NULL,                                  /* init master */
[85]     NULL,                                  /* init module */
[86]     NULL,                                  /* init process */
[87]     NULL,                                  /* init thread */
[88]     NULL,                                  /* exit thread */
[89]     NULL,                                  /* exit process */
[90]     NULL,                                  /* exit master */
[91]     NGX_MODULE_V1_PADDING
[92] };
[93] 
[94] 
[95] static ngx_str_t  ngx_http_slice_range_name = ngx_string("slice_range");
[96] 
[97] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[98] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[99] 
[100] 
[101] static ngx_int_t
[102] ngx_http_slice_header_filter(ngx_http_request_t *r)
[103] {
[104]     off_t                            end;
[105]     ngx_int_t                        rc;
[106]     ngx_table_elt_t                 *h;
[107]     ngx_http_slice_ctx_t            *ctx;
[108]     ngx_http_slice_loc_conf_t       *slcf;
[109]     ngx_http_slice_content_range_t   cr;
[110] 
[111]     ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
[112]     if (ctx == NULL) {
[113]         return ngx_http_next_header_filter(r);
[114]     }
[115] 
[116]     if (r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT) {
[117]         if (r == r->main) {
[118]             ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
[119]             return ngx_http_next_header_filter(r);
[120]         }
[121] 
[122]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[123]                       "unexpected status code %ui in slice response",
[124]                       r->headers_out.status);
[125]         return NGX_ERROR;
[126]     }
[127] 
[128]     h = r->headers_out.etag;
[129] 
[130]     if (ctx->etag.len) {
[131]         if (h == NULL
[132]             || h->value.len != ctx->etag.len
[133]             || ngx_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
[134]                != 0)
[135]         {
[136]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[137]                           "etag mismatch in slice response");
[138]             return NGX_ERROR;
[139]         }
[140]     }
[141] 
[142]     if (h) {
[143]         ctx->etag = h->value;
[144]     }
[145] 
[146]     if (ngx_http_slice_parse_content_range(r, &cr) != NGX_OK) {
[147]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[148]                       "invalid range in slice response");
[149]         return NGX_ERROR;
[150]     }
[151] 
[152]     if (cr.complete_length == -1) {
[153]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[154]                       "no complete length in slice response");
[155]         return NGX_ERROR;
[156]     }
[157] 
[158]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[159]                    "http slice response range: %O-%O/%O",
[160]                    cr.start, cr.end, cr.complete_length);
[161] 
[162]     slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);
[163] 
[164]     end = ngx_min(cr.start + (off_t) slcf->size, cr.complete_length);
[165] 
[166]     if (cr.start != ctx->start || cr.end != end) {
[167]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[168]                       "unexpected range in slice response: %O-%O",
[169]                       cr.start, cr.end);
[170]         return NGX_ERROR;
[171]     }
[172] 
[173]     ctx->start = end;
[174]     ctx->active = 1;
[175] 
[176]     r->headers_out.status = NGX_HTTP_OK;
[177]     r->headers_out.status_line.len = 0;
[178]     r->headers_out.content_length_n = cr.complete_length;
[179]     r->headers_out.content_offset = cr.start;
[180]     r->headers_out.content_range->hash = 0;
[181]     r->headers_out.content_range = NULL;
[182] 
[183]     if (r->headers_out.accept_ranges) {
[184]         r->headers_out.accept_ranges->hash = 0;
[185]         r->headers_out.accept_ranges = NULL;
[186]     }
[187] 
[188]     r->allow_ranges = 1;
[189]     r->subrequest_ranges = 1;
[190]     r->single_range = 1;
[191] 
[192]     rc = ngx_http_next_header_filter(r);
[193] 
[194]     if (r != r->main) {
[195]         return rc;
[196]     }
[197] 
[198]     r->preserve_body = 1;
[199] 
[200]     if (r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT) {
[201]         if (ctx->start + (off_t) slcf->size <= r->headers_out.content_offset) {
[202]             ctx->start = slcf->size
[203]                          * (r->headers_out.content_offset / slcf->size);
[204]         }
[205] 
[206]         ctx->end = r->headers_out.content_offset
[207]                    + r->headers_out.content_length_n;
[208] 
[209]     } else {
[210]         ctx->end = cr.complete_length;
[211]     }
[212] 
[213]     return rc;
[214] }
[215] 
[216] 
[217] static ngx_int_t
[218] ngx_http_slice_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[219] {
[220]     ngx_int_t                   rc;
[221]     ngx_chain_t                *cl;
[222]     ngx_http_slice_ctx_t       *ctx;
[223]     ngx_http_slice_loc_conf_t  *slcf;
[224] 
[225]     ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
[226] 
[227]     if (ctx == NULL || r != r->main) {
[228]         return ngx_http_next_body_filter(r, in);
[229]     }
[230] 
[231]     for (cl = in; cl; cl = cl->next) {
[232]         if (cl->buf->last_buf) {
[233]             cl->buf->last_buf = 0;
[234]             cl->buf->last_in_chain = 1;
[235]             cl->buf->sync = 1;
[236]             ctx->last = 1;
[237]         }
[238]     }
[239] 
[240]     rc = ngx_http_next_body_filter(r, in);
[241] 
[242]     if (rc == NGX_ERROR || !ctx->last) {
[243]         return rc;
[244]     }
[245] 
[246]     if (ctx->sr && !ctx->sr->done) {
[247]         return rc;
[248]     }
[249] 
[250]     if (!ctx->active) {
[251]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[252]                       "missing slice response");
[253]         return NGX_ERROR;
[254]     }
[255] 
[256]     if (ctx->start >= ctx->end) {
[257]         ngx_http_set_ctx(r, NULL, ngx_http_slice_filter_module);
[258]         ngx_http_send_special(r, NGX_HTTP_LAST);
[259]         return rc;
[260]     }
[261] 
[262]     if (r->buffered) {
[263]         return rc;
[264]     }
[265] 
[266]     if (ngx_http_subrequest(r, &r->uri, &r->args, &ctx->sr, NULL,
[267]                             NGX_HTTP_SUBREQUEST_CLONE)
[268]         != NGX_OK)
[269]     {
[270]         return NGX_ERROR;
[271]     }
[272] 
[273]     ngx_http_set_ctx(ctx->sr, ctx, ngx_http_slice_filter_module);
[274] 
[275]     slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);
[276] 
[277]     ctx->range.len = ngx_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start,
[278]                                  ctx->start + (off_t) slcf->size - 1)
[279]                      - ctx->range.data;
[280] 
[281]     ctx->active = 0;
[282] 
[283]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[284]                    "http slice subrequest: \"%V\"", &ctx->range);
[285] 
[286]     return rc;
[287] }
[288] 
[289] 
[290] static ngx_int_t
[291] ngx_http_slice_parse_content_range(ngx_http_request_t *r,
[292]     ngx_http_slice_content_range_t *cr)
[293] {
[294]     off_t             start, end, complete_length, cutoff, cutlim;
[295]     u_char           *p;
[296]     ngx_table_elt_t  *h;
[297] 
[298]     h = r->headers_out.content_range;
[299] 
[300]     if (h == NULL
[301]         || h->value.len < 7
[302]         || ngx_strncmp(h->value.data, "bytes ", 6) != 0)
[303]     {
[304]         return NGX_ERROR;
[305]     }
[306] 
[307]     p = h->value.data + 6;
[308] 
[309]     cutoff = NGX_MAX_OFF_T_VALUE / 10;
[310]     cutlim = NGX_MAX_OFF_T_VALUE % 10;
[311] 
[312]     start = 0;
[313]     end = 0;
[314]     complete_length = 0;
[315] 
[316]     while (*p == ' ') { p++; }
[317] 
[318]     if (*p < '0' || *p > '9') {
[319]         return NGX_ERROR;
[320]     }
[321] 
[322]     while (*p >= '0' && *p <= '9') {
[323]         if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
[324]             return NGX_ERROR;
[325]         }
[326] 
[327]         start = start * 10 + (*p++ - '0');
[328]     }
[329] 
[330]     while (*p == ' ') { p++; }
[331] 
[332]     if (*p++ != '-') {
[333]         return NGX_ERROR;
[334]     }
[335] 
[336]     while (*p == ' ') { p++; }
[337] 
[338]     if (*p < '0' || *p > '9') {
[339]         return NGX_ERROR;
[340]     }
[341] 
[342]     while (*p >= '0' && *p <= '9') {
[343]         if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
[344]             return NGX_ERROR;
[345]         }
[346] 
[347]         end = end * 10 + (*p++ - '0');
[348]     }
[349] 
[350]     end++;
[351] 
[352]     while (*p == ' ') { p++; }
[353] 
[354]     if (*p++ != '/') {
[355]         return NGX_ERROR;
[356]     }
[357] 
[358]     while (*p == ' ') { p++; }
[359] 
[360]     if (*p != '*') {
[361]         if (*p < '0' || *p > '9') {
[362]             return NGX_ERROR;
[363]         }
[364] 
[365]         while (*p >= '0' && *p <= '9') {
[366]             if (complete_length >= cutoff
[367]                 && (complete_length > cutoff || *p - '0' > cutlim))
[368]             {
[369]                 return NGX_ERROR;
[370]             }
[371] 
[372]             complete_length = complete_length * 10 + (*p++ - '0');
[373]         }
[374] 
[375]     } else {
[376]         complete_length = -1;
[377]         p++;
[378]     }
[379] 
[380]     while (*p == ' ') { p++; }
[381] 
[382]     if (*p != '\0') {
[383]         return NGX_ERROR;
[384]     }
[385] 
[386]     cr->start = start;
[387]     cr->end = end;
[388]     cr->complete_length = complete_length;
[389] 
[390]     return NGX_OK;
[391] }
[392] 
[393] 
[394] static ngx_int_t
[395] ngx_http_slice_range_variable(ngx_http_request_t *r,
[396]     ngx_http_variable_value_t *v, uintptr_t data)
[397] {
[398]     u_char                     *p;
[399]     ngx_http_slice_ctx_t       *ctx;
[400]     ngx_http_slice_loc_conf_t  *slcf;
[401] 
[402]     ctx = ngx_http_get_module_ctx(r, ngx_http_slice_filter_module);
[403] 
[404]     if (ctx == NULL) {
[405]         if (r != r->main || r->headers_out.status) {
[406]             v->not_found = 1;
[407]             return NGX_OK;
[408]         }
[409] 
[410]         slcf = ngx_http_get_module_loc_conf(r, ngx_http_slice_filter_module);
[411] 
[412]         if (slcf->size == 0) {
[413]             v->not_found = 1;
[414]             return NGX_OK;
[415]         }
[416] 
[417]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_slice_ctx_t));
[418]         if (ctx == NULL) {
[419]             return NGX_ERROR;
[420]         }
[421] 
[422]         ngx_http_set_ctx(r, ctx, ngx_http_slice_filter_module);
[423] 
[424]         p = ngx_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * NGX_OFF_T_LEN);
[425]         if (p == NULL) {
[426]             return NGX_ERROR;
[427]         }
[428] 
[429]         ctx->start = slcf->size * (ngx_http_slice_get_start(r) / slcf->size);
[430] 
[431]         ctx->range.data = p;
[432]         ctx->range.len = ngx_sprintf(p, "bytes=%O-%O", ctx->start,
[433]                                      ctx->start + (off_t) slcf->size - 1)
[434]                          - p;
[435]     }
[436] 
[437]     v->data = ctx->range.data;
[438]     v->valid = 1;
[439]     v->not_found = 0;
[440]     v->no_cacheable = 1;
[441]     v->len = ctx->range.len;
[442] 
[443]     return NGX_OK;
[444] }
[445] 
[446] 
[447] static off_t
[448] ngx_http_slice_get_start(ngx_http_request_t *r)
[449] {
[450]     off_t             start, cutoff, cutlim;
[451]     u_char           *p;
[452]     ngx_table_elt_t  *h;
[453] 
[454]     if (r->headers_in.if_range) {
[455]         return 0;
[456]     }
[457] 
[458]     h = r->headers_in.range;
[459] 
[460]     if (h == NULL
[461]         || h->value.len < 7
[462]         || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
[463]     {
[464]         return 0;
[465]     }
[466] 
[467]     p = h->value.data + 6;
[468] 
[469]     if (ngx_strchr(p, ',')) {
[470]         return 0;
[471]     }
[472] 
[473]     while (*p == ' ') { p++; }
[474] 
[475]     if (*p == '-') {
[476]         return 0;
[477]     }
[478] 
[479]     cutoff = NGX_MAX_OFF_T_VALUE / 10;
[480]     cutlim = NGX_MAX_OFF_T_VALUE % 10;
[481] 
[482]     start = 0;
[483] 
[484]     while (*p >= '0' && *p <= '9') {
[485]         if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
[486]             return 0;
[487]         }
[488] 
[489]         start = start * 10 + (*p++ - '0');
[490]     }
[491] 
[492]     return start;
[493] }
[494] 
[495] 
[496] static void *
[497] ngx_http_slice_create_loc_conf(ngx_conf_t *cf)
[498] {
[499]     ngx_http_slice_loc_conf_t  *slcf;
[500] 
[501]     slcf = ngx_palloc(cf->pool, sizeof(ngx_http_slice_loc_conf_t));
[502]     if (slcf == NULL) {
[503]         return NULL;
[504]     }
[505] 
[506]     slcf->size = NGX_CONF_UNSET_SIZE;
[507] 
[508]     return slcf;
[509] }
[510] 
[511] 
[512] static char *
[513] ngx_http_slice_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[514] {
[515]     ngx_http_slice_loc_conf_t *prev = parent;
[516]     ngx_http_slice_loc_conf_t *conf = child;
[517] 
[518]     ngx_conf_merge_size_value(conf->size, prev->size, 0);
[519] 
[520]     return NGX_CONF_OK;
[521] }
[522] 
[523] 
[524] static ngx_int_t
[525] ngx_http_slice_add_variables(ngx_conf_t *cf)
[526] {
[527]     ngx_http_variable_t  *var;
[528] 
[529]     var = ngx_http_add_variable(cf, &ngx_http_slice_range_name, 0);
[530]     if (var == NULL) {
[531]         return NGX_ERROR;
[532]     }
[533] 
[534]     var->get_handler = ngx_http_slice_range_variable;
[535] 
[536]     return NGX_OK;
[537] }
[538] 
[539] 
[540] static ngx_int_t
[541] ngx_http_slice_init(ngx_conf_t *cf)
[542] {
[543]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[544]     ngx_http_top_header_filter = ngx_http_slice_header_filter;
[545] 
[546]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[547]     ngx_http_top_body_filter = ngx_http_slice_body_filter;
[548] 
[549]     return NGX_OK;
[550] }
