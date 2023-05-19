[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
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
[14]     ngx_str_t                 uri;
[15]     ngx_array_t              *vars;
[16] } ngx_http_auth_request_conf_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_uint_t                done;
[21]     ngx_uint_t                status;
[22]     ngx_http_request_t       *subrequest;
[23] } ngx_http_auth_request_ctx_t;
[24] 
[25] 
[26] typedef struct {
[27]     ngx_int_t                 index;
[28]     ngx_http_complex_value_t  value;
[29]     ngx_http_set_variable_pt  set_handler;
[30] } ngx_http_auth_request_variable_t;
[31] 
[32] 
[33] static ngx_int_t ngx_http_auth_request_handler(ngx_http_request_t *r);
[34] static ngx_int_t ngx_http_auth_request_done(ngx_http_request_t *r,
[35]     void *data, ngx_int_t rc);
[36] static ngx_int_t ngx_http_auth_request_set_variables(ngx_http_request_t *r,
[37]     ngx_http_auth_request_conf_t *arcf, ngx_http_auth_request_ctx_t *ctx);
[38] static ngx_int_t ngx_http_auth_request_variable(ngx_http_request_t *r,
[39]     ngx_http_variable_value_t *v, uintptr_t data);
[40] static void *ngx_http_auth_request_create_conf(ngx_conf_t *cf);
[41] static char *ngx_http_auth_request_merge_conf(ngx_conf_t *cf,
[42]     void *parent, void *child);
[43] static ngx_int_t ngx_http_auth_request_init(ngx_conf_t *cf);
[44] static char *ngx_http_auth_request(ngx_conf_t *cf, ngx_command_t *cmd,
[45]     void *conf);
[46] static char *ngx_http_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd,
[47]     void *conf);
[48] 
[49] 
[50] static ngx_command_t  ngx_http_auth_request_commands[] = {
[51] 
[52]     { ngx_string("auth_request"),
[53]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[54]       ngx_http_auth_request,
[55]       NGX_HTTP_LOC_CONF_OFFSET,
[56]       0,
[57]       NULL },
[58] 
[59]     { ngx_string("auth_request_set"),
[60]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[61]       ngx_http_auth_request_set,
[62]       NGX_HTTP_LOC_CONF_OFFSET,
[63]       0,
[64]       NULL },
[65] 
[66]       ngx_null_command
[67] };
[68] 
[69] 
[70] static ngx_http_module_t  ngx_http_auth_request_module_ctx = {
[71]     NULL,                                  /* preconfiguration */
[72]     ngx_http_auth_request_init,            /* postconfiguration */
[73] 
[74]     NULL,                                  /* create main configuration */
[75]     NULL,                                  /* init main configuration */
[76] 
[77]     NULL,                                  /* create server configuration */
[78]     NULL,                                  /* merge server configuration */
[79] 
[80]     ngx_http_auth_request_create_conf,     /* create location configuration */
[81]     ngx_http_auth_request_merge_conf       /* merge location configuration */
[82] };
[83] 
[84] 
[85] ngx_module_t  ngx_http_auth_request_module = {
[86]     NGX_MODULE_V1,
[87]     &ngx_http_auth_request_module_ctx,     /* module context */
[88]     ngx_http_auth_request_commands,        /* module directives */
[89]     NGX_HTTP_MODULE,                       /* module type */
[90]     NULL,                                  /* init master */
[91]     NULL,                                  /* init module */
[92]     NULL,                                  /* init process */
[93]     NULL,                                  /* init thread */
[94]     NULL,                                  /* exit thread */
[95]     NULL,                                  /* exit process */
[96]     NULL,                                  /* exit master */
[97]     NGX_MODULE_V1_PADDING
[98] };
[99] 
[100] 
[101] static ngx_int_t
[102] ngx_http_auth_request_handler(ngx_http_request_t *r)
[103] {
[104]     ngx_table_elt_t               *h, *ho, **ph;
[105]     ngx_http_request_t            *sr;
[106]     ngx_http_post_subrequest_t    *ps;
[107]     ngx_http_auth_request_ctx_t   *ctx;
[108]     ngx_http_auth_request_conf_t  *arcf;
[109] 
[110]     arcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_request_module);
[111] 
[112]     if (arcf->uri.len == 0) {
[113]         return NGX_DECLINED;
[114]     }
[115] 
[116]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[117]                    "auth request handler");
[118] 
[119]     ctx = ngx_http_get_module_ctx(r, ngx_http_auth_request_module);
[120] 
[121]     if (ctx != NULL) {
[122]         if (!ctx->done) {
[123]             return NGX_AGAIN;
[124]         }
[125] 
[126]         /*
[127]          * as soon as we are done - explicitly set variables to make
[128]          * sure they will be available after internal redirects
[129]          */
[130] 
[131]         if (ngx_http_auth_request_set_variables(r, arcf, ctx) != NGX_OK) {
[132]             return NGX_ERROR;
[133]         }
[134] 
[135]         /* return appropriate status */
[136] 
[137]         if (ctx->status == NGX_HTTP_FORBIDDEN) {
[138]             return ctx->status;
[139]         }
[140] 
[141]         if (ctx->status == NGX_HTTP_UNAUTHORIZED) {
[142]             sr = ctx->subrequest;
[143] 
[144]             h = sr->headers_out.www_authenticate;
[145] 
[146]             if (!h && sr->upstream) {
[147]                 h = sr->upstream->headers_in.www_authenticate;
[148]             }
[149] 
[150]             ph = &r->headers_out.www_authenticate;
[151] 
[152]             while (h) {
[153]                 ho = ngx_list_push(&r->headers_out.headers);
[154]                 if (ho == NULL) {
[155]                     return NGX_ERROR;
[156]                 }
[157] 
[158]                 *ho = *h;
[159]                 ho->next = NULL;
[160] 
[161]                 *ph = ho;
[162]                 ph = &ho->next;
[163] 
[164]                 h = h->next;
[165]             }
[166] 
[167]             return ctx->status;
[168]         }
[169] 
[170]         if (ctx->status >= NGX_HTTP_OK
[171]             && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
[172]         {
[173]             return NGX_OK;
[174]         }
[175] 
[176]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[177]                       "auth request unexpected status: %ui", ctx->status);
[178] 
[179]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[180]     }
[181] 
[182]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_request_ctx_t));
[183]     if (ctx == NULL) {
[184]         return NGX_ERROR;
[185]     }
[186] 
[187]     ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
[188]     if (ps == NULL) {
[189]         return NGX_ERROR;
[190]     }
[191] 
[192]     ps->handler = ngx_http_auth_request_done;
[193]     ps->data = ctx;
[194] 
[195]     if (ngx_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
[196]                             NGX_HTTP_SUBREQUEST_WAITED)
[197]         != NGX_OK)
[198]     {
[199]         return NGX_ERROR;
[200]     }
[201] 
[202]     /*
[203]      * allocate fake request body to avoid attempts to read it and to make
[204]      * sure real body file (if already read) won't be closed by upstream
[205]      */
[206] 
[207]     sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
[208]     if (sr->request_body == NULL) {
[209]         return NGX_ERROR;
[210]     }
[211] 
[212]     sr->header_only = 1;
[213] 
[214]     ctx->subrequest = sr;
[215] 
[216]     ngx_http_set_ctx(r, ctx, ngx_http_auth_request_module);
[217] 
[218]     return NGX_AGAIN;
[219] }
[220] 
[221] 
[222] static ngx_int_t
[223] ngx_http_auth_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
[224] {
[225]     ngx_http_auth_request_ctx_t   *ctx = data;
[226] 
[227]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[228]                    "auth request done s:%ui", r->headers_out.status);
[229] 
[230]     ctx->done = 1;
[231]     ctx->status = r->headers_out.status;
[232] 
[233]     return rc;
[234] }
[235] 
[236] 
[237] static ngx_int_t
[238] ngx_http_auth_request_set_variables(ngx_http_request_t *r,
[239]     ngx_http_auth_request_conf_t *arcf, ngx_http_auth_request_ctx_t *ctx)
[240] {
[241]     ngx_str_t                          val;
[242]     ngx_http_variable_t               *v;
[243]     ngx_http_variable_value_t         *vv;
[244]     ngx_http_auth_request_variable_t  *av, *last;
[245]     ngx_http_core_main_conf_t         *cmcf;
[246] 
[247]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[248]                    "auth request set variables");
[249] 
[250]     if (arcf->vars == NULL) {
[251]         return NGX_OK;
[252]     }
[253] 
[254]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[255]     v = cmcf->variables.elts;
[256] 
[257]     av = arcf->vars->elts;
[258]     last = av + arcf->vars->nelts;
[259] 
[260]     while (av < last) {
[261]         /*
[262]          * explicitly set new value to make sure it will be available after
[263]          * internal redirects
[264]          */
[265] 
[266]         vv = &r->variables[av->index];
[267] 
[268]         if (ngx_http_complex_value(ctx->subrequest, &av->value, &val)
[269]             != NGX_OK)
[270]         {
[271]             return NGX_ERROR;
[272]         }
[273] 
[274]         vv->valid = 1;
[275]         vv->not_found = 0;
[276]         vv->data = val.data;
[277]         vv->len = val.len;
[278] 
[279]         if (av->set_handler) {
[280]             /*
[281]              * set_handler only available in cmcf->variables_keys, so we store
[282]              * it explicitly
[283]              */
[284] 
[285]             av->set_handler(r, vv, v[av->index].data);
[286]         }
[287] 
[288]         av++;
[289]     }
[290] 
[291]     return NGX_OK;
[292] }
[293] 
[294] 
[295] static ngx_int_t
[296] ngx_http_auth_request_variable(ngx_http_request_t *r,
[297]     ngx_http_variable_value_t *v, uintptr_t data)
[298] {
[299]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[300]                    "auth request variable");
[301] 
[302]     v->not_found = 1;
[303] 
[304]     return NGX_OK;
[305] }
[306] 
[307] 
[308] static void *
[309] ngx_http_auth_request_create_conf(ngx_conf_t *cf)
[310] {
[311]     ngx_http_auth_request_conf_t  *conf;
[312] 
[313]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_request_conf_t));
[314]     if (conf == NULL) {
[315]         return NULL;
[316]     }
[317] 
[318]     /*
[319]      * set by ngx_pcalloc():
[320]      *
[321]      *     conf->uri = { 0, NULL };
[322]      */
[323] 
[324]     conf->vars = NGX_CONF_UNSET_PTR;
[325] 
[326]     return conf;
[327] }
[328] 
[329] 
[330] static char *
[331] ngx_http_auth_request_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[332] {
[333]     ngx_http_auth_request_conf_t *prev = parent;
[334]     ngx_http_auth_request_conf_t *conf = child;
[335] 
[336]     ngx_conf_merge_str_value(conf->uri, prev->uri, "");
[337]     ngx_conf_merge_ptr_value(conf->vars, prev->vars, NULL);
[338] 
[339]     return NGX_CONF_OK;
[340] }
[341] 
[342] 
[343] static ngx_int_t
[344] ngx_http_auth_request_init(ngx_conf_t *cf)
[345] {
[346]     ngx_http_handler_pt        *h;
[347]     ngx_http_core_main_conf_t  *cmcf;
[348] 
[349]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[350] 
[351]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
[352]     if (h == NULL) {
[353]         return NGX_ERROR;
[354]     }
[355] 
[356]     *h = ngx_http_auth_request_handler;
[357] 
[358]     return NGX_OK;
[359] }
[360] 
[361] 
[362] static char *
[363] ngx_http_auth_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[364] {
[365]     ngx_http_auth_request_conf_t *arcf = conf;
[366] 
[367]     ngx_str_t        *value;
[368] 
[369]     if (arcf->uri.data != NULL) {
[370]         return "is duplicate";
[371]     }
[372] 
[373]     value = cf->args->elts;
[374] 
[375]     if (ngx_strcmp(value[1].data, "off") == 0) {
[376]         arcf->uri.len = 0;
[377]         arcf->uri.data = (u_char *) "";
[378] 
[379]         return NGX_CONF_OK;
[380]     }
[381] 
[382]     arcf->uri = value[1];
[383] 
[384]     return NGX_CONF_OK;
[385] }
[386] 
[387] 
[388] static char *
[389] ngx_http_auth_request_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[390] {
[391]     ngx_http_auth_request_conf_t *arcf = conf;
[392] 
[393]     ngx_str_t                         *value;
[394]     ngx_http_variable_t               *v;
[395]     ngx_http_auth_request_variable_t  *av;
[396]     ngx_http_compile_complex_value_t   ccv;
[397] 
[398]     value = cf->args->elts;
[399] 
[400]     if (value[1].data[0] != '$') {
[401]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[402]                            "invalid variable name \"%V\"", &value[1]);
[403]         return NGX_CONF_ERROR;
[404]     }
[405] 
[406]     value[1].len--;
[407]     value[1].data++;
[408] 
[409]     if (arcf->vars == NGX_CONF_UNSET_PTR) {
[410]         arcf->vars = ngx_array_create(cf->pool, 1,
[411]                                       sizeof(ngx_http_auth_request_variable_t));
[412]         if (arcf->vars == NULL) {
[413]             return NGX_CONF_ERROR;
[414]         }
[415]     }
[416] 
[417]     av = ngx_array_push(arcf->vars);
[418]     if (av == NULL) {
[419]         return NGX_CONF_ERROR;
[420]     }
[421] 
[422]     v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
[423]     if (v == NULL) {
[424]         return NGX_CONF_ERROR;
[425]     }
[426] 
[427]     av->index = ngx_http_get_variable_index(cf, &value[1]);
[428]     if (av->index == NGX_ERROR) {
[429]         return NGX_CONF_ERROR;
[430]     }
[431] 
[432]     if (v->get_handler == NULL) {
[433]         v->get_handler = ngx_http_auth_request_variable;
[434]         v->data = (uintptr_t) av;
[435]     }
[436] 
[437]     av->set_handler = v->set_handler;
[438] 
[439]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[440] 
[441]     ccv.cf = cf;
[442]     ccv.value = &value[2];
[443]     ccv.complex_value = &av->value;
[444] 
[445]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[446]         return NGX_CONF_ERROR;
[447]     }
[448] 
[449]     return NGX_CONF_OK;
[450] }
