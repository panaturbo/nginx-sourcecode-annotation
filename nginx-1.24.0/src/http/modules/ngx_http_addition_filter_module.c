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
[13] typedef struct {
[14]     ngx_str_t     before_body;
[15]     ngx_str_t     after_body;
[16] 
[17]     ngx_hash_t    types;
[18]     ngx_array_t  *types_keys;
[19] } ngx_http_addition_conf_t;
[20] 
[21] 
[22] typedef struct {
[23]     ngx_uint_t    before_body_sent;
[24] } ngx_http_addition_ctx_t;
[25] 
[26] 
[27] static void *ngx_http_addition_create_conf(ngx_conf_t *cf);
[28] static char *ngx_http_addition_merge_conf(ngx_conf_t *cf, void *parent,
[29]     void *child);
[30] static ngx_int_t ngx_http_addition_filter_init(ngx_conf_t *cf);
[31] 
[32] 
[33] static ngx_command_t  ngx_http_addition_commands[] = {
[34] 
[35]     { ngx_string("add_before_body"),
[36]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[37]       ngx_conf_set_str_slot,
[38]       NGX_HTTP_LOC_CONF_OFFSET,
[39]       offsetof(ngx_http_addition_conf_t, before_body),
[40]       NULL },
[41] 
[42]     { ngx_string("add_after_body"),
[43]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[44]       ngx_conf_set_str_slot,
[45]       NGX_HTTP_LOC_CONF_OFFSET,
[46]       offsetof(ngx_http_addition_conf_t, after_body),
[47]       NULL },
[48] 
[49]     { ngx_string("addition_types"),
[50]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[51]       ngx_http_types_slot,
[52]       NGX_HTTP_LOC_CONF_OFFSET,
[53]       offsetof(ngx_http_addition_conf_t, types_keys),
[54]       &ngx_http_html_default_types[0] },
[55] 
[56]       ngx_null_command
[57] };
[58] 
[59] 
[60] static ngx_http_module_t  ngx_http_addition_filter_module_ctx = {
[61]     NULL,                                  /* preconfiguration */
[62]     ngx_http_addition_filter_init,         /* postconfiguration */
[63] 
[64]     NULL,                                  /* create main configuration */
[65]     NULL,                                  /* init main configuration */
[66] 
[67]     NULL,                                  /* create server configuration */
[68]     NULL,                                  /* merge server configuration */
[69] 
[70]     ngx_http_addition_create_conf,         /* create location configuration */
[71]     ngx_http_addition_merge_conf           /* merge location configuration */
[72] };
[73] 
[74] 
[75] ngx_module_t  ngx_http_addition_filter_module = {
[76]     NGX_MODULE_V1,
[77]     &ngx_http_addition_filter_module_ctx,  /* module context */
[78]     ngx_http_addition_commands,            /* module directives */
[79]     NGX_HTTP_MODULE,                       /* module type */
[80]     NULL,                                  /* init master */
[81]     NULL,                                  /* init module */
[82]     NULL,                                  /* init process */
[83]     NULL,                                  /* init thread */
[84]     NULL,                                  /* exit thread */
[85]     NULL,                                  /* exit process */
[86]     NULL,                                  /* exit master */
[87]     NGX_MODULE_V1_PADDING
[88] };
[89] 
[90] 
[91] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[92] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[93] 
[94] 
[95] static ngx_int_t
[96] ngx_http_addition_header_filter(ngx_http_request_t *r)
[97] {
[98]     ngx_http_addition_ctx_t   *ctx;
[99]     ngx_http_addition_conf_t  *conf;
[100] 
[101]     if (r->headers_out.status != NGX_HTTP_OK || r != r->main) {
[102]         return ngx_http_next_header_filter(r);
[103]     }
[104] 
[105]     conf = ngx_http_get_module_loc_conf(r, ngx_http_addition_filter_module);
[106] 
[107]     if (conf->before_body.len == 0 && conf->after_body.len == 0) {
[108]         return ngx_http_next_header_filter(r);
[109]     }
[110] 
[111]     if (ngx_http_test_content_type(r, &conf->types) == NULL) {
[112]         return ngx_http_next_header_filter(r);
[113]     }
[114] 
[115]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_addition_ctx_t));
[116]     if (ctx == NULL) {
[117]         return NGX_ERROR;
[118]     }
[119] 
[120]     ngx_http_set_ctx(r, ctx, ngx_http_addition_filter_module);
[121] 
[122]     ngx_http_clear_content_length(r);
[123]     ngx_http_clear_accept_ranges(r);
[124]     ngx_http_weak_etag(r);
[125] 
[126]     r->preserve_body = 1;
[127] 
[128]     return ngx_http_next_header_filter(r);
[129] }
[130] 
[131] 
[132] static ngx_int_t
[133] ngx_http_addition_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[134] {
[135]     ngx_int_t                  rc;
[136]     ngx_uint_t                 last;
[137]     ngx_chain_t               *cl;
[138]     ngx_http_request_t        *sr;
[139]     ngx_http_addition_ctx_t   *ctx;
[140]     ngx_http_addition_conf_t  *conf;
[141] 
[142]     if (in == NULL || r->header_only) {
[143]         return ngx_http_next_body_filter(r, in);
[144]     }
[145] 
[146]     ctx = ngx_http_get_module_ctx(r, ngx_http_addition_filter_module);
[147] 
[148]     if (ctx == NULL) {
[149]         return ngx_http_next_body_filter(r, in);
[150]     }
[151] 
[152]     conf = ngx_http_get_module_loc_conf(r, ngx_http_addition_filter_module);
[153] 
[154]     if (!ctx->before_body_sent) {
[155]         ctx->before_body_sent = 1;
[156] 
[157]         if (conf->before_body.len) {
[158]             if (ngx_http_subrequest(r, &conf->before_body, NULL, &sr, NULL, 0)
[159]                 != NGX_OK)
[160]             {
[161]                 return NGX_ERROR;
[162]             }
[163]         }
[164]     }
[165] 
[166]     if (conf->after_body.len == 0) {
[167]         ngx_http_set_ctx(r, NULL, ngx_http_addition_filter_module);
[168]         return ngx_http_next_body_filter(r, in);
[169]     }
[170] 
[171]     last = 0;
[172] 
[173]     for (cl = in; cl; cl = cl->next) {
[174]         if (cl->buf->last_buf) {
[175]             cl->buf->last_buf = 0;
[176]             cl->buf->last_in_chain = 1;
[177]             cl->buf->sync = 1;
[178]             last = 1;
[179]         }
[180]     }
[181] 
[182]     rc = ngx_http_next_body_filter(r, in);
[183] 
[184]     if (rc == NGX_ERROR || !last || conf->after_body.len == 0) {
[185]         return rc;
[186]     }
[187] 
[188]     if (ngx_http_subrequest(r, &conf->after_body, NULL, &sr, NULL, 0)
[189]         != NGX_OK)
[190]     {
[191]         return NGX_ERROR;
[192]     }
[193] 
[194]     ngx_http_set_ctx(r, NULL, ngx_http_addition_filter_module);
[195] 
[196]     return ngx_http_send_special(r, NGX_HTTP_LAST);
[197] }
[198] 
[199] 
[200] static ngx_int_t
[201] ngx_http_addition_filter_init(ngx_conf_t *cf)
[202] {
[203]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[204]     ngx_http_top_header_filter = ngx_http_addition_header_filter;
[205] 
[206]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[207]     ngx_http_top_body_filter = ngx_http_addition_body_filter;
[208] 
[209]     return NGX_OK;
[210] }
[211] 
[212] 
[213] static void *
[214] ngx_http_addition_create_conf(ngx_conf_t *cf)
[215] {
[216]     ngx_http_addition_conf_t  *conf;
[217] 
[218]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_addition_conf_t));
[219]     if (conf == NULL) {
[220]         return NULL;
[221]     }
[222] 
[223]     /*
[224]      * set by ngx_pcalloc():
[225]      *
[226]      *     conf->before_body = { 0, NULL };
[227]      *     conf->after_body = { 0, NULL };
[228]      *     conf->types = { NULL };
[229]      *     conf->types_keys = NULL;
[230]      */
[231] 
[232]     return conf;
[233] }
[234] 
[235] 
[236] static char *
[237] ngx_http_addition_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[238] {
[239]     ngx_http_addition_conf_t *prev = parent;
[240]     ngx_http_addition_conf_t *conf = child;
[241] 
[242]     ngx_conf_merge_str_value(conf->before_body, prev->before_body, "");
[243]     ngx_conf_merge_str_value(conf->after_body, prev->after_body, "");
[244] 
[245]     if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
[246]                              &prev->types_keys, &prev->types,
[247]                              ngx_http_html_default_types)
[248]         != NGX_OK)
[249]     {
[250]         return NGX_CONF_ERROR;
[251]     }
[252] 
[253]     return NGX_CONF_OK;
[254] }
