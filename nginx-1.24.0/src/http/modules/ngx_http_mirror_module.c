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
[14]     ngx_array_t  *mirror;
[15]     ngx_flag_t    request_body;
[16] } ngx_http_mirror_loc_conf_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_int_t     status;
[21] } ngx_http_mirror_ctx_t;
[22] 
[23] 
[24] static ngx_int_t ngx_http_mirror_handler(ngx_http_request_t *r);
[25] static void ngx_http_mirror_body_handler(ngx_http_request_t *r);
[26] static ngx_int_t ngx_http_mirror_handler_internal(ngx_http_request_t *r);
[27] static void *ngx_http_mirror_create_loc_conf(ngx_conf_t *cf);
[28] static char *ngx_http_mirror_merge_loc_conf(ngx_conf_t *cf, void *parent,
[29]     void *child);
[30] static char *ngx_http_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[31] static ngx_int_t ngx_http_mirror_init(ngx_conf_t *cf);
[32] 
[33] 
[34] static ngx_command_t  ngx_http_mirror_commands[] = {
[35] 
[36]     { ngx_string("mirror"),
[37]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[38]       ngx_http_mirror,
[39]       NGX_HTTP_LOC_CONF_OFFSET,
[40]       0,
[41]       NULL },
[42] 
[43]     { ngx_string("mirror_request_body"),
[44]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[45]       ngx_conf_set_flag_slot,
[46]       NGX_HTTP_LOC_CONF_OFFSET,
[47]       offsetof(ngx_http_mirror_loc_conf_t, request_body),
[48]       NULL },
[49] 
[50]       ngx_null_command
[51] };
[52] 
[53] 
[54] static ngx_http_module_t  ngx_http_mirror_module_ctx = {
[55]     NULL,                                  /* preconfiguration */
[56]     ngx_http_mirror_init,                  /* postconfiguration */
[57] 
[58]     NULL,                                  /* create main configuration */
[59]     NULL,                                  /* init main configuration */
[60] 
[61]     NULL,                                  /* create server configuration */
[62]     NULL,                                  /* merge server configuration */
[63] 
[64]     ngx_http_mirror_create_loc_conf,       /* create location configuration */
[65]     ngx_http_mirror_merge_loc_conf         /* merge location configuration */
[66] };
[67] 
[68] 
[69] ngx_module_t  ngx_http_mirror_module = {
[70]     NGX_MODULE_V1,
[71]     &ngx_http_mirror_module_ctx,           /* module context */
[72]     ngx_http_mirror_commands,              /* module directives */
[73]     NGX_HTTP_MODULE,                       /* module type */
[74]     NULL,                                  /* init master */
[75]     NULL,                                  /* init module */
[76]     NULL,                                  /* init process */
[77]     NULL,                                  /* init thread */
[78]     NULL,                                  /* exit thread */
[79]     NULL,                                  /* exit process */
[80]     NULL,                                  /* exit master */
[81]     NGX_MODULE_V1_PADDING
[82] };
[83] 
[84] 
[85] static ngx_int_t
[86] ngx_http_mirror_handler(ngx_http_request_t *r)
[87] {
[88]     ngx_int_t                    rc;
[89]     ngx_http_mirror_ctx_t       *ctx;
[90]     ngx_http_mirror_loc_conf_t  *mlcf;
[91] 
[92]     if (r != r->main) {
[93]         return NGX_DECLINED;
[94]     }
[95] 
[96]     mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mirror_module);
[97] 
[98]     if (mlcf->mirror == NULL) {
[99]         return NGX_DECLINED;
[100]     }
[101] 
[102]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "mirror handler");
[103] 
[104]     if (mlcf->request_body) {
[105]         ctx = ngx_http_get_module_ctx(r, ngx_http_mirror_module);
[106] 
[107]         if (ctx) {
[108]             return ctx->status;
[109]         }
[110] 
[111]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mirror_ctx_t));
[112]         if (ctx == NULL) {
[113]             return NGX_ERROR;
[114]         }
[115] 
[116]         ctx->status = NGX_DONE;
[117] 
[118]         ngx_http_set_ctx(r, ctx, ngx_http_mirror_module);
[119] 
[120]         rc = ngx_http_read_client_request_body(r, ngx_http_mirror_body_handler);
[121]         if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[122]             return rc;
[123]         }
[124] 
[125]         ngx_http_finalize_request(r, NGX_DONE);
[126]         return NGX_DONE;
[127]     }
[128] 
[129]     return ngx_http_mirror_handler_internal(r);
[130] }
[131] 
[132] 
[133] static void
[134] ngx_http_mirror_body_handler(ngx_http_request_t *r)
[135] {
[136]     ngx_http_mirror_ctx_t  *ctx;
[137] 
[138]     ctx = ngx_http_get_module_ctx(r, ngx_http_mirror_module);
[139] 
[140]     ctx->status = ngx_http_mirror_handler_internal(r);
[141] 
[142]     r->preserve_body = 1;
[143] 
[144]     r->write_event_handler = ngx_http_core_run_phases;
[145]     ngx_http_core_run_phases(r);
[146] }
[147] 
[148] 
[149] static ngx_int_t
[150] ngx_http_mirror_handler_internal(ngx_http_request_t *r)
[151] {
[152]     ngx_str_t                   *name;
[153]     ngx_uint_t                   i;
[154]     ngx_http_request_t          *sr;
[155]     ngx_http_mirror_loc_conf_t  *mlcf;
[156] 
[157]     mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mirror_module);
[158] 
[159]     name = mlcf->mirror->elts;
[160] 
[161]     for (i = 0; i < mlcf->mirror->nelts; i++) {
[162]         if (ngx_http_subrequest(r, &name[i], &r->args, &sr, NULL,
[163]                                 NGX_HTTP_SUBREQUEST_BACKGROUND)
[164]             != NGX_OK)
[165]         {
[166]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[167]         }
[168] 
[169]         sr->header_only = 1;
[170]         sr->method = r->method;
[171]         sr->method_name = r->method_name;
[172]     }
[173] 
[174]     return NGX_DECLINED;
[175] }
[176] 
[177] 
[178] static void *
[179] ngx_http_mirror_create_loc_conf(ngx_conf_t *cf)
[180] {
[181]     ngx_http_mirror_loc_conf_t  *mlcf;
[182] 
[183]     mlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mirror_loc_conf_t));
[184]     if (mlcf == NULL) {
[185]         return NULL;
[186]     }
[187] 
[188]     mlcf->mirror = NGX_CONF_UNSET_PTR;
[189]     mlcf->request_body = NGX_CONF_UNSET;
[190] 
[191]     return mlcf;
[192] }
[193] 
[194] 
[195] static char *
[196] ngx_http_mirror_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[197] {
[198]     ngx_http_mirror_loc_conf_t *prev = parent;
[199]     ngx_http_mirror_loc_conf_t *conf = child;
[200] 
[201]     ngx_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL);
[202]     ngx_conf_merge_value(conf->request_body, prev->request_body, 1);
[203] 
[204]     return NGX_CONF_OK;
[205] }
[206] 
[207] 
[208] static char *
[209] ngx_http_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[210] {
[211]     ngx_http_mirror_loc_conf_t *mlcf = conf;
[212] 
[213]     ngx_str_t  *value, *s;
[214] 
[215]     value = cf->args->elts;
[216] 
[217]     if (ngx_strcmp(value[1].data, "off") == 0) {
[218]         if (mlcf->mirror != NGX_CONF_UNSET_PTR) {
[219]             return "is duplicate";
[220]         }
[221] 
[222]         mlcf->mirror = NULL;
[223]         return NGX_CONF_OK;
[224]     }
[225] 
[226]     if (mlcf->mirror == NULL) {
[227]         return "is duplicate";
[228]     }
[229] 
[230]     if (mlcf->mirror == NGX_CONF_UNSET_PTR) {
[231]         mlcf->mirror = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
[232]         if (mlcf->mirror == NULL) {
[233]             return NGX_CONF_ERROR;
[234]         }
[235]     }
[236] 
[237]     s = ngx_array_push(mlcf->mirror);
[238]     if (s == NULL) {
[239]         return NGX_CONF_ERROR;
[240]     }
[241] 
[242]     *s = value[1];
[243] 
[244]     return NGX_CONF_OK;
[245] }
[246] 
[247] 
[248] static ngx_int_t
[249] ngx_http_mirror_init(ngx_conf_t *cf)
[250] {
[251]     ngx_http_handler_pt        *h;
[252]     ngx_http_core_main_conf_t  *cmcf;
[253] 
[254]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[255] 
[256]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
[257]     if (h == NULL) {
[258]         return NGX_ERROR;
[259]     }
[260] 
[261]     *h = ngx_http_mirror_handler;
[262] 
[263]     return NGX_OK;
[264] }
