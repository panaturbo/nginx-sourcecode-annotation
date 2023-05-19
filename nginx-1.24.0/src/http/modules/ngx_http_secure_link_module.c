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
[11] #include <ngx_md5.h>
[12] 
[13] 
[14] typedef struct {
[15]     ngx_http_complex_value_t  *variable;
[16]     ngx_http_complex_value_t  *md5;
[17]     ngx_str_t                  secret;
[18] } ngx_http_secure_link_conf_t;
[19] 
[20] 
[21] typedef struct {
[22]     ngx_str_t                  expires;
[23] } ngx_http_secure_link_ctx_t;
[24] 
[25] 
[26] static ngx_int_t ngx_http_secure_link_old_variable(ngx_http_request_t *r,
[27]     ngx_http_secure_link_conf_t *conf, ngx_http_variable_value_t *v,
[28]     uintptr_t data);
[29] static ngx_int_t ngx_http_secure_link_expires_variable(ngx_http_request_t *r,
[30]     ngx_http_variable_value_t *v, uintptr_t data);
[31] static void *ngx_http_secure_link_create_conf(ngx_conf_t *cf);
[32] static char *ngx_http_secure_link_merge_conf(ngx_conf_t *cf, void *parent,
[33]     void *child);
[34] static ngx_int_t ngx_http_secure_link_add_variables(ngx_conf_t *cf);
[35] 
[36] 
[37] static ngx_command_t  ngx_http_secure_link_commands[] = {
[38] 
[39]     { ngx_string("secure_link"),
[40]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[41]       ngx_http_set_complex_value_slot,
[42]       NGX_HTTP_LOC_CONF_OFFSET,
[43]       offsetof(ngx_http_secure_link_conf_t, variable),
[44]       NULL },
[45] 
[46]     { ngx_string("secure_link_md5"),
[47]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[48]       ngx_http_set_complex_value_slot,
[49]       NGX_HTTP_LOC_CONF_OFFSET,
[50]       offsetof(ngx_http_secure_link_conf_t, md5),
[51]       NULL },
[52] 
[53]     { ngx_string("secure_link_secret"),
[54]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[55]       ngx_conf_set_str_slot,
[56]       NGX_HTTP_LOC_CONF_OFFSET,
[57]       offsetof(ngx_http_secure_link_conf_t, secret),
[58]       NULL },
[59] 
[60]       ngx_null_command
[61] };
[62] 
[63] 
[64] static ngx_http_module_t  ngx_http_secure_link_module_ctx = {
[65]     ngx_http_secure_link_add_variables,    /* preconfiguration */
[66]     NULL,                                  /* postconfiguration */
[67] 
[68]     NULL,                                  /* create main configuration */
[69]     NULL,                                  /* init main configuration */
[70] 
[71]     NULL,                                  /* create server configuration */
[72]     NULL,                                  /* merge server configuration */
[73] 
[74]     ngx_http_secure_link_create_conf,      /* create location configuration */
[75]     ngx_http_secure_link_merge_conf        /* merge location configuration */
[76] };
[77] 
[78] 
[79] ngx_module_t  ngx_http_secure_link_module = {
[80]     NGX_MODULE_V1,
[81]     &ngx_http_secure_link_module_ctx,      /* module context */
[82]     ngx_http_secure_link_commands,         /* module directives */
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
[95] static ngx_str_t  ngx_http_secure_link_name = ngx_string("secure_link");
[96] static ngx_str_t  ngx_http_secure_link_expires_name =
[97]     ngx_string("secure_link_expires");
[98] 
[99] 
[100] static ngx_int_t
[101] ngx_http_secure_link_variable(ngx_http_request_t *r,
[102]     ngx_http_variable_value_t *v, uintptr_t data)
[103] {
[104]     u_char                       *p, *last;
[105]     ngx_str_t                     val, hash;
[106]     time_t                        expires;
[107]     ngx_md5_t                     md5;
[108]     ngx_http_secure_link_ctx_t   *ctx;
[109]     ngx_http_secure_link_conf_t  *conf;
[110]     u_char                        hash_buf[18], md5_buf[16];
[111] 
[112]     conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_link_module);
[113] 
[114]     if (conf->secret.data) {
[115]         return ngx_http_secure_link_old_variable(r, conf, v, data);
[116]     }
[117] 
[118]     if (conf->variable == NULL || conf->md5 == NULL) {
[119]         goto not_found;
[120]     }
[121] 
[122]     if (ngx_http_complex_value(r, conf->variable, &val) != NGX_OK) {
[123]         return NGX_ERROR;
[124]     }
[125] 
[126]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[127]                    "secure link: \"%V\"", &val);
[128] 
[129]     last = val.data + val.len;
[130] 
[131]     p = ngx_strlchr(val.data, last, ',');
[132]     expires = 0;
[133] 
[134]     if (p) {
[135]         val.len = p++ - val.data;
[136] 
[137]         expires = ngx_atotm(p, last - p);
[138]         if (expires <= 0) {
[139]             goto not_found;
[140]         }
[141] 
[142]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_secure_link_ctx_t));
[143]         if (ctx == NULL) {
[144]             return NGX_ERROR;
[145]         }
[146] 
[147]         ngx_http_set_ctx(r, ctx, ngx_http_secure_link_module);
[148] 
[149]         ctx->expires.len = last - p;
[150]         ctx->expires.data = p;
[151]     }
[152] 
[153]     if (val.len > 24) {
[154]         goto not_found;
[155]     }
[156] 
[157]     hash.data = hash_buf;
[158] 
[159]     if (ngx_decode_base64url(&hash, &val) != NGX_OK) {
[160]         goto not_found;
[161]     }
[162] 
[163]     if (hash.len != 16) {
[164]         goto not_found;
[165]     }
[166] 
[167]     if (ngx_http_complex_value(r, conf->md5, &val) != NGX_OK) {
[168]         return NGX_ERROR;
[169]     }
[170] 
[171]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[172]                    "secure link md5: \"%V\"", &val);
[173] 
[174]     ngx_md5_init(&md5);
[175]     ngx_md5_update(&md5, val.data, val.len);
[176]     ngx_md5_final(md5_buf, &md5);
[177] 
[178]     if (ngx_memcmp(hash_buf, md5_buf, 16) != 0) {
[179]         goto not_found;
[180]     }
[181] 
[182]     v->data = (u_char *) ((expires && expires < ngx_time()) ? "0" : "1");
[183]     v->len = 1;
[184]     v->valid = 1;
[185]     v->no_cacheable = 0;
[186]     v->not_found = 0;
[187] 
[188]     return NGX_OK;
[189] 
[190] not_found:
[191] 
[192]     v->not_found = 1;
[193] 
[194]     return NGX_OK;
[195] }
[196] 
[197] 
[198] static ngx_int_t
[199] ngx_http_secure_link_old_variable(ngx_http_request_t *r,
[200]     ngx_http_secure_link_conf_t *conf, ngx_http_variable_value_t *v,
[201]     uintptr_t data)
[202] {
[203]     u_char      *p, *start, *end, *last;
[204]     size_t       len;
[205]     ngx_int_t    n;
[206]     ngx_uint_t   i;
[207]     ngx_md5_t    md5;
[208]     u_char       hash[16];
[209] 
[210]     p = &r->unparsed_uri.data[1];
[211]     last = r->unparsed_uri.data + r->unparsed_uri.len;
[212] 
[213]     while (p < last) {
[214]         if (*p++ == '/') {
[215]             start = p;
[216]             goto md5_start;
[217]         }
[218]     }
[219] 
[220]     goto not_found;
[221] 
[222] md5_start:
[223] 
[224]     while (p < last) {
[225]         if (*p++ == '/') {
[226]             end = p - 1;
[227]             goto url_start;
[228]         }
[229]     }
[230] 
[231]     goto not_found;
[232] 
[233] url_start:
[234] 
[235]     len = last - p;
[236] 
[237]     if (end - start != 32 || len == 0) {
[238]         goto not_found;
[239]     }
[240] 
[241]     ngx_md5_init(&md5);
[242]     ngx_md5_update(&md5, p, len);
[243]     ngx_md5_update(&md5, conf->secret.data, conf->secret.len);
[244]     ngx_md5_final(hash, &md5);
[245] 
[246]     for (i = 0; i < 16; i++) {
[247]         n = ngx_hextoi(&start[2 * i], 2);
[248]         if (n == NGX_ERROR || n != hash[i]) {
[249]             goto not_found;
[250]         }
[251]     }
[252] 
[253]     v->len = len;
[254]     v->valid = 1;
[255]     v->no_cacheable = 0;
[256]     v->not_found = 0;
[257]     v->data = p;
[258] 
[259]     return NGX_OK;
[260] 
[261] not_found:
[262] 
[263]     v->not_found = 1;
[264] 
[265]     return NGX_OK;
[266] }
[267] 
[268] 
[269] static ngx_int_t
[270] ngx_http_secure_link_expires_variable(ngx_http_request_t *r,
[271]     ngx_http_variable_value_t *v, uintptr_t data)
[272] {
[273]     ngx_http_secure_link_ctx_t  *ctx;
[274] 
[275]     ctx = ngx_http_get_module_ctx(r, ngx_http_secure_link_module);
[276] 
[277]     if (ctx) {
[278]         v->len = ctx->expires.len;
[279]         v->valid = 1;
[280]         v->no_cacheable = 0;
[281]         v->not_found = 0;
[282]         v->data = ctx->expires.data;
[283] 
[284]     } else {
[285]         v->not_found = 1;
[286]     }
[287] 
[288]     return NGX_OK;
[289] }
[290] 
[291] 
[292] static void *
[293] ngx_http_secure_link_create_conf(ngx_conf_t *cf)
[294] {
[295]     ngx_http_secure_link_conf_t  *conf;
[296] 
[297]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_link_conf_t));
[298]     if (conf == NULL) {
[299]         return NULL;
[300]     }
[301] 
[302]     /*
[303]      * set by ngx_pcalloc():
[304]      *
[305]      *     conf->secret = { 0, NULL };
[306]      */
[307] 
[308]     conf->variable = NGX_CONF_UNSET_PTR;
[309]     conf->md5 = NGX_CONF_UNSET_PTR;
[310] 
[311]     return conf;
[312] }
[313] 
[314] 
[315] static char *
[316] ngx_http_secure_link_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[317] {
[318]     ngx_http_secure_link_conf_t *prev = parent;
[319]     ngx_http_secure_link_conf_t *conf = child;
[320] 
[321]     if (conf->secret.data) {
[322]         ngx_conf_init_ptr_value(conf->variable, NULL);
[323]         ngx_conf_init_ptr_value(conf->md5, NULL);
[324] 
[325]         if (conf->variable || conf->md5) {
[326]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[327]                                "\"secure_link_secret\" cannot be mixed with "
[328]                                "\"secure_link\" and \"secure_link_md5\"");
[329]             return NGX_CONF_ERROR;
[330]         }
[331] 
[332]         return NGX_CONF_OK;
[333]     }
[334] 
[335]     ngx_conf_merge_ptr_value(conf->variable, prev->variable, NULL);
[336]     ngx_conf_merge_ptr_value(conf->md5, prev->md5, NULL);
[337] 
[338]     if (conf->variable == NULL && conf->md5 == NULL) {
[339]         conf->secret = prev->secret;
[340]     }
[341] 
[342]     return NGX_CONF_OK;
[343] }
[344] 
[345] 
[346] static ngx_int_t
[347] ngx_http_secure_link_add_variables(ngx_conf_t *cf)
[348] {
[349]     ngx_http_variable_t  *var;
[350] 
[351]     var = ngx_http_add_variable(cf, &ngx_http_secure_link_name, 0);
[352]     if (var == NULL) {
[353]         return NGX_ERROR;
[354]     }
[355] 
[356]     var->get_handler = ngx_http_secure_link_variable;
[357] 
[358]     var = ngx_http_add_variable(cf, &ngx_http_secure_link_expires_name, 0);
[359]     if (var == NULL) {
[360]         return NGX_ERROR;
[361]     }
[362] 
[363]     var->get_handler = ngx_http_secure_link_expires_variable;
[364] 
[365]     return NGX_OK;
[366] }
