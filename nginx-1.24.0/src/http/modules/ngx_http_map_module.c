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
[14]     ngx_uint_t                  hash_max_size;
[15]     ngx_uint_t                  hash_bucket_size;
[16] } ngx_http_map_conf_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_hash_keys_arrays_t      keys;
[21] 
[22]     ngx_array_t                *values_hash;
[23] #if (NGX_PCRE)
[24]     ngx_array_t                 regexes;
[25] #endif
[26] 
[27]     ngx_http_variable_value_t  *default_value;
[28]     ngx_conf_t                 *cf;
[29]     unsigned                    hostnames:1;
[30]     unsigned                    no_cacheable:1;
[31] } ngx_http_map_conf_ctx_t;
[32] 
[33] 
[34] typedef struct {
[35]     ngx_http_map_t              map;
[36]     ngx_http_complex_value_t    value;
[37]     ngx_http_variable_value_t  *default_value;
[38]     ngx_uint_t                  hostnames;      /* unsigned  hostnames:1 */
[39] } ngx_http_map_ctx_t;
[40] 
[41] 
[42] static int ngx_libc_cdecl ngx_http_map_cmp_dns_wildcards(const void *one,
[43]     const void *two);
[44] static void *ngx_http_map_create_conf(ngx_conf_t *cf);
[45] static char *ngx_http_map_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[46] static char *ngx_http_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
[47] 
[48] 
[49] static ngx_command_t  ngx_http_map_commands[] = {
[50] 
[51]     { ngx_string("map"),
[52]       NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
[53]       ngx_http_map_block,
[54]       NGX_HTTP_MAIN_CONF_OFFSET,
[55]       0,
[56]       NULL },
[57] 
[58]     { ngx_string("map_hash_max_size"),
[59]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[60]       ngx_conf_set_num_slot,
[61]       NGX_HTTP_MAIN_CONF_OFFSET,
[62]       offsetof(ngx_http_map_conf_t, hash_max_size),
[63]       NULL },
[64] 
[65]     { ngx_string("map_hash_bucket_size"),
[66]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[67]       ngx_conf_set_num_slot,
[68]       NGX_HTTP_MAIN_CONF_OFFSET,
[69]       offsetof(ngx_http_map_conf_t, hash_bucket_size),
[70]       NULL },
[71] 
[72]       ngx_null_command
[73] };
[74] 
[75] 
[76] static ngx_http_module_t  ngx_http_map_module_ctx = {
[77]     NULL,                                  /* preconfiguration */
[78]     NULL,                                  /* postconfiguration */
[79] 
[80]     ngx_http_map_create_conf,              /* create main configuration */
[81]     NULL,                                  /* init main configuration */
[82] 
[83]     NULL,                                  /* create server configuration */
[84]     NULL,                                  /* merge server configuration */
[85] 
[86]     NULL,                                  /* create location configuration */
[87]     NULL                                   /* merge location configuration */
[88] };
[89] 
[90] 
[91] ngx_module_t  ngx_http_map_module = {
[92]     NGX_MODULE_V1,
[93]     &ngx_http_map_module_ctx,              /* module context */
[94]     ngx_http_map_commands,                 /* module directives */
[95]     NGX_HTTP_MODULE,                       /* module type */
[96]     NULL,                                  /* init master */
[97]     NULL,                                  /* init module */
[98]     NULL,                                  /* init process */
[99]     NULL,                                  /* init thread */
[100]     NULL,                                  /* exit thread */
[101]     NULL,                                  /* exit process */
[102]     NULL,                                  /* exit master */
[103]     NGX_MODULE_V1_PADDING
[104] };
[105] 
[106] 
[107] static ngx_int_t
[108] ngx_http_map_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[109]     uintptr_t data)
[110] {
[111]     ngx_http_map_ctx_t  *map = (ngx_http_map_ctx_t *) data;
[112] 
[113]     ngx_str_t                   val, str;
[114]     ngx_http_complex_value_t   *cv;
[115]     ngx_http_variable_value_t  *value;
[116] 
[117]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[118]                    "http map started");
[119] 
[120]     if (ngx_http_complex_value(r, &map->value, &val) != NGX_OK) {
[121]         return NGX_ERROR;
[122]     }
[123] 
[124]     if (map->hostnames && val.len > 0 && val.data[val.len - 1] == '.') {
[125]         val.len--;
[126]     }
[127] 
[128]     value = ngx_http_map_find(r, &map->map, &val);
[129] 
[130]     if (value == NULL) {
[131]         value = map->default_value;
[132]     }
[133] 
[134]     if (!value->valid) {
[135]         cv = (ngx_http_complex_value_t *) value->data;
[136] 
[137]         if (ngx_http_complex_value(r, cv, &str) != NGX_OK) {
[138]             return NGX_ERROR;
[139]         }
[140] 
[141]         v->valid = 1;
[142]         v->no_cacheable = 0;
[143]         v->not_found = 0;
[144]         v->len = str.len;
[145]         v->data = str.data;
[146] 
[147]     } else {
[148]         *v = *value;
[149]     }
[150] 
[151]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[152]                    "http map: \"%V\" \"%v\"", &val, v);
[153] 
[154]     return NGX_OK;
[155] }
[156] 
[157] 
[158] static void *
[159] ngx_http_map_create_conf(ngx_conf_t *cf)
[160] {
[161]     ngx_http_map_conf_t  *mcf;
[162] 
[163]     mcf = ngx_palloc(cf->pool, sizeof(ngx_http_map_conf_t));
[164]     if (mcf == NULL) {
[165]         return NULL;
[166]     }
[167] 
[168]     mcf->hash_max_size = NGX_CONF_UNSET_UINT;
[169]     mcf->hash_bucket_size = NGX_CONF_UNSET_UINT;
[170] 
[171]     return mcf;
[172] }
[173] 
[174] 
[175] static char *
[176] ngx_http_map_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[177] {
[178]     ngx_http_map_conf_t  *mcf = conf;
[179] 
[180]     char                              *rv;
[181]     ngx_str_t                         *value, name;
[182]     ngx_conf_t                         save;
[183]     ngx_pool_t                        *pool;
[184]     ngx_hash_init_t                    hash;
[185]     ngx_http_map_ctx_t                *map;
[186]     ngx_http_variable_t               *var;
[187]     ngx_http_map_conf_ctx_t            ctx;
[188]     ngx_http_compile_complex_value_t   ccv;
[189] 
[190]     if (mcf->hash_max_size == NGX_CONF_UNSET_UINT) {
[191]         mcf->hash_max_size = 2048;
[192]     }
[193] 
[194]     if (mcf->hash_bucket_size == NGX_CONF_UNSET_UINT) {
[195]         mcf->hash_bucket_size = ngx_cacheline_size;
[196] 
[197]     } else {
[198]         mcf->hash_bucket_size = ngx_align(mcf->hash_bucket_size,
[199]                                           ngx_cacheline_size);
[200]     }
[201] 
[202]     map = ngx_pcalloc(cf->pool, sizeof(ngx_http_map_ctx_t));
[203]     if (map == NULL) {
[204]         return NGX_CONF_ERROR;
[205]     }
[206] 
[207]     value = cf->args->elts;
[208] 
[209]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[210] 
[211]     ccv.cf = cf;
[212]     ccv.value = &value[1];
[213]     ccv.complex_value = &map->value;
[214] 
[215]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[216]         return NGX_CONF_ERROR;
[217]     }
[218] 
[219]     name = value[2];
[220] 
[221]     if (name.data[0] != '$') {
[222]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[223]                            "invalid variable name \"%V\"", &name);
[224]         return NGX_CONF_ERROR;
[225]     }
[226] 
[227]     name.len--;
[228]     name.data++;
[229] 
[230]     var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
[231]     if (var == NULL) {
[232]         return NGX_CONF_ERROR;
[233]     }
[234] 
[235]     var->get_handler = ngx_http_map_variable;
[236]     var->data = (uintptr_t) map;
[237] 
[238]     pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[239]     if (pool == NULL) {
[240]         return NGX_CONF_ERROR;
[241]     }
[242] 
[243]     ctx.keys.pool = cf->pool;
[244]     ctx.keys.temp_pool = pool;
[245] 
[246]     if (ngx_hash_keys_array_init(&ctx.keys, NGX_HASH_LARGE) != NGX_OK) {
[247]         ngx_destroy_pool(pool);
[248]         return NGX_CONF_ERROR;
[249]     }
[250] 
[251]     ctx.values_hash = ngx_pcalloc(pool, sizeof(ngx_array_t) * ctx.keys.hsize);
[252]     if (ctx.values_hash == NULL) {
[253]         ngx_destroy_pool(pool);
[254]         return NGX_CONF_ERROR;
[255]     }
[256] 
[257] #if (NGX_PCRE)
[258]     if (ngx_array_init(&ctx.regexes, cf->pool, 2, sizeof(ngx_http_map_regex_t))
[259]         != NGX_OK)
[260]     {
[261]         ngx_destroy_pool(pool);
[262]         return NGX_CONF_ERROR;
[263]     }
[264] #endif
[265] 
[266]     ctx.default_value = NULL;
[267]     ctx.cf = &save;
[268]     ctx.hostnames = 0;
[269]     ctx.no_cacheable = 0;
[270] 
[271]     save = *cf;
[272]     cf->pool = pool;
[273]     cf->ctx = &ctx;
[274]     cf->handler = ngx_http_map;
[275]     cf->handler_conf = conf;
[276] 
[277]     rv = ngx_conf_parse(cf, NULL);
[278] 
[279]     *cf = save;
[280] 
[281]     if (rv != NGX_CONF_OK) {
[282]         ngx_destroy_pool(pool);
[283]         return rv;
[284]     }
[285] 
[286]     if (ctx.no_cacheable) {
[287]         var->flags |= NGX_HTTP_VAR_NOCACHEABLE;
[288]     }
[289] 
[290]     map->default_value = ctx.default_value ? ctx.default_value:
[291]                                              &ngx_http_variable_null_value;
[292] 
[293]     map->hostnames = ctx.hostnames;
[294] 
[295]     hash.key = ngx_hash_key_lc;
[296]     hash.max_size = mcf->hash_max_size;
[297]     hash.bucket_size = mcf->hash_bucket_size;
[298]     hash.name = "map_hash";
[299]     hash.pool = cf->pool;
[300] 
[301]     if (ctx.keys.keys.nelts) {
[302]         hash.hash = &map->map.hash.hash;
[303]         hash.temp_pool = NULL;
[304] 
[305]         if (ngx_hash_init(&hash, ctx.keys.keys.elts, ctx.keys.keys.nelts)
[306]             != NGX_OK)
[307]         {
[308]             ngx_destroy_pool(pool);
[309]             return NGX_CONF_ERROR;
[310]         }
[311]     }
[312] 
[313]     if (ctx.keys.dns_wc_head.nelts) {
[314] 
[315]         ngx_qsort(ctx.keys.dns_wc_head.elts,
[316]                   (size_t) ctx.keys.dns_wc_head.nelts,
[317]                   sizeof(ngx_hash_key_t), ngx_http_map_cmp_dns_wildcards);
[318] 
[319]         hash.hash = NULL;
[320]         hash.temp_pool = pool;
[321] 
[322]         if (ngx_hash_wildcard_init(&hash, ctx.keys.dns_wc_head.elts,
[323]                                    ctx.keys.dns_wc_head.nelts)
[324]             != NGX_OK)
[325]         {
[326]             ngx_destroy_pool(pool);
[327]             return NGX_CONF_ERROR;
[328]         }
[329] 
[330]         map->map.hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
[331]     }
[332] 
[333]     if (ctx.keys.dns_wc_tail.nelts) {
[334] 
[335]         ngx_qsort(ctx.keys.dns_wc_tail.elts,
[336]                   (size_t) ctx.keys.dns_wc_tail.nelts,
[337]                   sizeof(ngx_hash_key_t), ngx_http_map_cmp_dns_wildcards);
[338] 
[339]         hash.hash = NULL;
[340]         hash.temp_pool = pool;
[341] 
[342]         if (ngx_hash_wildcard_init(&hash, ctx.keys.dns_wc_tail.elts,
[343]                                    ctx.keys.dns_wc_tail.nelts)
[344]             != NGX_OK)
[345]         {
[346]             ngx_destroy_pool(pool);
[347]             return NGX_CONF_ERROR;
[348]         }
[349] 
[350]         map->map.hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
[351]     }
[352] 
[353] #if (NGX_PCRE)
[354] 
[355]     if (ctx.regexes.nelts) {
[356]         map->map.regex = ctx.regexes.elts;
[357]         map->map.nregex = ctx.regexes.nelts;
[358]     }
[359] 
[360] #endif
[361] 
[362]     ngx_destroy_pool(pool);
[363] 
[364]     return rv;
[365] }
[366] 
[367] 
[368] static int ngx_libc_cdecl
[369] ngx_http_map_cmp_dns_wildcards(const void *one, const void *two)
[370] {
[371]     ngx_hash_key_t  *first, *second;
[372] 
[373]     first = (ngx_hash_key_t *) one;
[374]     second = (ngx_hash_key_t *) two;
[375] 
[376]     return ngx_dns_strcmp(first->key.data, second->key.data);
[377] }
[378] 
[379] 
[380] static char *
[381] ngx_http_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[382] {
[383]     u_char                            *data;
[384]     size_t                             len;
[385]     ngx_int_t                          rv;
[386]     ngx_str_t                         *value, v;
[387]     ngx_uint_t                         i, key;
[388]     ngx_http_map_conf_ctx_t           *ctx;
[389]     ngx_http_complex_value_t           cv, *cvp;
[390]     ngx_http_variable_value_t         *var, **vp;
[391]     ngx_http_compile_complex_value_t   ccv;
[392] 
[393]     ctx = cf->ctx;
[394] 
[395]     value = cf->args->elts;
[396] 
[397]     if (cf->args->nelts == 1
[398]         && ngx_strcmp(value[0].data, "hostnames") == 0)
[399]     {
[400]         ctx->hostnames = 1;
[401]         return NGX_CONF_OK;
[402]     }
[403] 
[404]     if (cf->args->nelts == 1
[405]         && ngx_strcmp(value[0].data, "volatile") == 0)
[406]     {
[407]         ctx->no_cacheable = 1;
[408]         return NGX_CONF_OK;
[409]     }
[410] 
[411]     if (cf->args->nelts != 2) {
[412]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[413]                            "invalid number of the map parameters");
[414]         return NGX_CONF_ERROR;
[415]     }
[416] 
[417]     if (ngx_strcmp(value[0].data, "include") == 0) {
[418]         return ngx_conf_include(cf, dummy, conf);
[419]     }
[420] 
[421]     key = 0;
[422] 
[423]     for (i = 0; i < value[1].len; i++) {
[424]         key = ngx_hash(key, value[1].data[i]);
[425]     }
[426] 
[427]     key %= ctx->keys.hsize;
[428] 
[429]     vp = ctx->values_hash[key].elts;
[430] 
[431]     if (vp) {
[432]         for (i = 0; i < ctx->values_hash[key].nelts; i++) {
[433] 
[434]             if (vp[i]->valid) {
[435]                 data = vp[i]->data;
[436]                 len = vp[i]->len;
[437] 
[438]             } else {
[439]                 cvp = (ngx_http_complex_value_t *) vp[i]->data;
[440]                 data = cvp->value.data;
[441]                 len = cvp->value.len;
[442]             }
[443] 
[444]             if (value[1].len != len) {
[445]                 continue;
[446]             }
[447] 
[448]             if (ngx_strncmp(value[1].data, data, len) == 0) {
[449]                 var = vp[i];
[450]                 goto found;
[451]             }
[452]         }
[453] 
[454]     } else {
[455]         if (ngx_array_init(&ctx->values_hash[key], cf->pool, 4,
[456]                            sizeof(ngx_http_variable_value_t *))
[457]             != NGX_OK)
[458]         {
[459]             return NGX_CONF_ERROR;
[460]         }
[461]     }
[462] 
[463]     var = ngx_palloc(ctx->keys.pool, sizeof(ngx_http_variable_value_t));
[464]     if (var == NULL) {
[465]         return NGX_CONF_ERROR;
[466]     }
[467] 
[468]     v.len = value[1].len;
[469]     v.data = ngx_pstrdup(ctx->keys.pool, &value[1]);
[470]     if (v.data == NULL) {
[471]         return NGX_CONF_ERROR;
[472]     }
[473] 
[474]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[475] 
[476]     ccv.cf = ctx->cf;
[477]     ccv.value = &v;
[478]     ccv.complex_value = &cv;
[479] 
[480]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[481]         return NGX_CONF_ERROR;
[482]     }
[483] 
[484]     if (cv.lengths != NULL) {
[485]         cvp = ngx_palloc(ctx->keys.pool, sizeof(ngx_http_complex_value_t));
[486]         if (cvp == NULL) {
[487]             return NGX_CONF_ERROR;
[488]         }
[489] 
[490]         *cvp = cv;
[491] 
[492]         var->len = 0;
[493]         var->data = (u_char *) cvp;
[494]         var->valid = 0;
[495] 
[496]     } else {
[497]         var->len = v.len;
[498]         var->data = v.data;
[499]         var->valid = 1;
[500]     }
[501] 
[502]     var->no_cacheable = 0;
[503]     var->not_found = 0;
[504] 
[505]     vp = ngx_array_push(&ctx->values_hash[key]);
[506]     if (vp == NULL) {
[507]         return NGX_CONF_ERROR;
[508]     }
[509] 
[510]     *vp = var;
[511] 
[512] found:
[513] 
[514]     if (ngx_strcmp(value[0].data, "default") == 0) {
[515] 
[516]         if (ctx->default_value) {
[517]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[518]                                "duplicate default map parameter");
[519]             return NGX_CONF_ERROR;
[520]         }
[521] 
[522]         ctx->default_value = var;
[523] 
[524]         return NGX_CONF_OK;
[525]     }
[526] 
[527] #if (NGX_PCRE)
[528] 
[529]     if (value[0].len && value[0].data[0] == '~') {
[530]         ngx_regex_compile_t    rc;
[531]         ngx_http_map_regex_t  *regex;
[532]         u_char                 errstr[NGX_MAX_CONF_ERRSTR];
[533] 
[534]         regex = ngx_array_push(&ctx->regexes);
[535]         if (regex == NULL) {
[536]             return NGX_CONF_ERROR;
[537]         }
[538] 
[539]         value[0].len--;
[540]         value[0].data++;
[541] 
[542]         ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[543] 
[544]         if (value[0].data[0] == '*') {
[545]             value[0].len--;
[546]             value[0].data++;
[547]             rc.options = NGX_REGEX_CASELESS;
[548]         }
[549] 
[550]         rc.pattern = value[0];
[551]         rc.err.len = NGX_MAX_CONF_ERRSTR;
[552]         rc.err.data = errstr;
[553] 
[554]         regex->regex = ngx_http_regex_compile(ctx->cf, &rc);
[555]         if (regex->regex == NULL) {
[556]             return NGX_CONF_ERROR;
[557]         }
[558] 
[559]         regex->value = var;
[560] 
[561]         return NGX_CONF_OK;
[562]     }
[563] 
[564] #endif
[565] 
[566]     if (value[0].len && value[0].data[0] == '\\') {
[567]         value[0].len--;
[568]         value[0].data++;
[569]     }
[570] 
[571]     rv = ngx_hash_add_key(&ctx->keys, &value[0], var,
[572]                           (ctx->hostnames) ? NGX_HASH_WILDCARD_KEY : 0);
[573] 
[574]     if (rv == NGX_OK) {
[575]         return NGX_CONF_OK;
[576]     }
[577] 
[578]     if (rv == NGX_DECLINED) {
[579]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[580]                            "invalid hostname or wildcard \"%V\"", &value[0]);
[581]     }
[582] 
[583]     if (rv == NGX_BUSY) {
[584]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[585]                            "conflicting parameter \"%V\"", &value[0]);
[586]     }
[587] 
[588]     return NGX_CONF_ERROR;
[589] }
