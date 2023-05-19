[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] typedef struct {
[14]     ngx_uint_t                    hash_max_size;
[15]     ngx_uint_t                    hash_bucket_size;
[16] } ngx_stream_map_conf_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_hash_keys_arrays_t        keys;
[21] 
[22]     ngx_array_t                  *values_hash;
[23] #if (NGX_PCRE)
[24]     ngx_array_t                   regexes;
[25] #endif
[26] 
[27]     ngx_stream_variable_value_t  *default_value;
[28]     ngx_conf_t                   *cf;
[29]     unsigned                      hostnames:1;
[30]     unsigned                      no_cacheable:1;
[31] } ngx_stream_map_conf_ctx_t;
[32] 
[33] 
[34] typedef struct {
[35]     ngx_stream_map_t              map;
[36]     ngx_stream_complex_value_t    value;
[37]     ngx_stream_variable_value_t  *default_value;
[38]     ngx_uint_t                    hostnames;      /* unsigned  hostnames:1 */
[39] } ngx_stream_map_ctx_t;
[40] 
[41] 
[42] static int ngx_libc_cdecl ngx_stream_map_cmp_dns_wildcards(const void *one,
[43]     const void *two);
[44] static void *ngx_stream_map_create_conf(ngx_conf_t *cf);
[45] static char *ngx_stream_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
[46]     void *conf);
[47] static char *ngx_stream_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
[48] 
[49] 
[50] static ngx_command_t  ngx_stream_map_commands[] = {
[51] 
[52]     { ngx_string("map"),
[53]       NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
[54]       ngx_stream_map_block,
[55]       NGX_STREAM_MAIN_CONF_OFFSET,
[56]       0,
[57]       NULL },
[58] 
[59]     { ngx_string("map_hash_max_size"),
[60]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
[61]       ngx_conf_set_num_slot,
[62]       NGX_STREAM_MAIN_CONF_OFFSET,
[63]       offsetof(ngx_stream_map_conf_t, hash_max_size),
[64]       NULL },
[65] 
[66]     { ngx_string("map_hash_bucket_size"),
[67]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
[68]       ngx_conf_set_num_slot,
[69]       NGX_STREAM_MAIN_CONF_OFFSET,
[70]       offsetof(ngx_stream_map_conf_t, hash_bucket_size),
[71]       NULL },
[72] 
[73]       ngx_null_command
[74] };
[75] 
[76] 
[77] static ngx_stream_module_t  ngx_stream_map_module_ctx = {
[78]     NULL,                                  /* preconfiguration */
[79]     NULL,                                  /* postconfiguration */
[80] 
[81]     ngx_stream_map_create_conf,            /* create main configuration */
[82]     NULL,                                  /* init main configuration */
[83] 
[84]     NULL,                                  /* create server configuration */
[85]     NULL                                   /* merge server configuration */
[86] };
[87] 
[88] 
[89] ngx_module_t  ngx_stream_map_module = {
[90]     NGX_MODULE_V1,
[91]     &ngx_stream_map_module_ctx,            /* module context */
[92]     ngx_stream_map_commands,               /* module directives */
[93]     NGX_STREAM_MODULE,                     /* module type */
[94]     NULL,                                  /* init master */
[95]     NULL,                                  /* init module */
[96]     NULL,                                  /* init process */
[97]     NULL,                                  /* init thread */
[98]     NULL,                                  /* exit thread */
[99]     NULL,                                  /* exit process */
[100]     NULL,                                  /* exit master */
[101]     NGX_MODULE_V1_PADDING
[102] };
[103] 
[104] 
[105] static ngx_int_t
[106] ngx_stream_map_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
[107]     uintptr_t data)
[108] {
[109]     ngx_stream_map_ctx_t  *map = (ngx_stream_map_ctx_t *) data;
[110] 
[111]     ngx_str_t                     val, str;
[112]     ngx_stream_complex_value_t   *cv;
[113]     ngx_stream_variable_value_t  *value;
[114] 
[115]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[116]                    "stream map started");
[117] 
[118]     if (ngx_stream_complex_value(s, &map->value, &val) != NGX_OK) {
[119]         return NGX_ERROR;
[120]     }
[121] 
[122]     if (map->hostnames && val.len > 0 && val.data[val.len - 1] == '.') {
[123]         val.len--;
[124]     }
[125] 
[126]     value = ngx_stream_map_find(s, &map->map, &val);
[127] 
[128]     if (value == NULL) {
[129]         value = map->default_value;
[130]     }
[131] 
[132]     if (!value->valid) {
[133]         cv = (ngx_stream_complex_value_t *) value->data;
[134] 
[135]         if (ngx_stream_complex_value(s, cv, &str) != NGX_OK) {
[136]             return NGX_ERROR;
[137]         }
[138] 
[139]         v->valid = 1;
[140]         v->no_cacheable = 0;
[141]         v->not_found = 0;
[142]         v->len = str.len;
[143]         v->data = str.data;
[144] 
[145]     } else {
[146]         *v = *value;
[147]     }
[148] 
[149]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[150]                    "stream map: \"%V\" \"%v\"", &val, v);
[151] 
[152]     return NGX_OK;
[153] }
[154] 
[155] 
[156] static void *
[157] ngx_stream_map_create_conf(ngx_conf_t *cf)
[158] {
[159]     ngx_stream_map_conf_t  *mcf;
[160] 
[161]     mcf = ngx_palloc(cf->pool, sizeof(ngx_stream_map_conf_t));
[162]     if (mcf == NULL) {
[163]         return NULL;
[164]     }
[165] 
[166]     mcf->hash_max_size = NGX_CONF_UNSET_UINT;
[167]     mcf->hash_bucket_size = NGX_CONF_UNSET_UINT;
[168] 
[169]     return mcf;
[170] }
[171] 
[172] 
[173] static char *
[174] ngx_stream_map_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[175] {
[176]     ngx_stream_map_conf_t  *mcf = conf;
[177] 
[178]     char                                *rv;
[179]     ngx_str_t                           *value, name;
[180]     ngx_conf_t                           save;
[181]     ngx_pool_t                          *pool;
[182]     ngx_hash_init_t                      hash;
[183]     ngx_stream_map_ctx_t                *map;
[184]     ngx_stream_variable_t               *var;
[185]     ngx_stream_map_conf_ctx_t            ctx;
[186]     ngx_stream_compile_complex_value_t   ccv;
[187] 
[188]     if (mcf->hash_max_size == NGX_CONF_UNSET_UINT) {
[189]         mcf->hash_max_size = 2048;
[190]     }
[191] 
[192]     if (mcf->hash_bucket_size == NGX_CONF_UNSET_UINT) {
[193]         mcf->hash_bucket_size = ngx_cacheline_size;
[194] 
[195]     } else {
[196]         mcf->hash_bucket_size = ngx_align(mcf->hash_bucket_size,
[197]                                           ngx_cacheline_size);
[198]     }
[199] 
[200]     map = ngx_pcalloc(cf->pool, sizeof(ngx_stream_map_ctx_t));
[201]     if (map == NULL) {
[202]         return NGX_CONF_ERROR;
[203]     }
[204] 
[205]     value = cf->args->elts;
[206] 
[207]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[208] 
[209]     ccv.cf = cf;
[210]     ccv.value = &value[1];
[211]     ccv.complex_value = &map->value;
[212] 
[213]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[214]         return NGX_CONF_ERROR;
[215]     }
[216] 
[217]     name = value[2];
[218] 
[219]     if (name.data[0] != '$') {
[220]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[221]                            "invalid variable name \"%V\"", &name);
[222]         return NGX_CONF_ERROR;
[223]     }
[224] 
[225]     name.len--;
[226]     name.data++;
[227] 
[228]     var = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
[229]     if (var == NULL) {
[230]         return NGX_CONF_ERROR;
[231]     }
[232] 
[233]     var->get_handler = ngx_stream_map_variable;
[234]     var->data = (uintptr_t) map;
[235] 
[236]     pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[237]     if (pool == NULL) {
[238]         return NGX_CONF_ERROR;
[239]     }
[240] 
[241]     ctx.keys.pool = cf->pool;
[242]     ctx.keys.temp_pool = pool;
[243] 
[244]     if (ngx_hash_keys_array_init(&ctx.keys, NGX_HASH_LARGE) != NGX_OK) {
[245]         ngx_destroy_pool(pool);
[246]         return NGX_CONF_ERROR;
[247]     }
[248] 
[249]     ctx.values_hash = ngx_pcalloc(pool, sizeof(ngx_array_t) * ctx.keys.hsize);
[250]     if (ctx.values_hash == NULL) {
[251]         ngx_destroy_pool(pool);
[252]         return NGX_CONF_ERROR;
[253]     }
[254] 
[255] #if (NGX_PCRE)
[256]     if (ngx_array_init(&ctx.regexes, cf->pool, 2,
[257]                        sizeof(ngx_stream_map_regex_t))
[258]         != NGX_OK)
[259]     {
[260]         ngx_destroy_pool(pool);
[261]         return NGX_CONF_ERROR;
[262]     }
[263] #endif
[264] 
[265]     ctx.default_value = NULL;
[266]     ctx.cf = &save;
[267]     ctx.hostnames = 0;
[268]     ctx.no_cacheable = 0;
[269] 
[270]     save = *cf;
[271]     cf->pool = pool;
[272]     cf->ctx = &ctx;
[273]     cf->handler = ngx_stream_map;
[274]     cf->handler_conf = conf;
[275] 
[276]     rv = ngx_conf_parse(cf, NULL);
[277] 
[278]     *cf = save;
[279] 
[280]     if (rv != NGX_CONF_OK) {
[281]         ngx_destroy_pool(pool);
[282]         return rv;
[283]     }
[284] 
[285]     if (ctx.no_cacheable) {
[286]         var->flags |= NGX_STREAM_VAR_NOCACHEABLE;
[287]     }
[288] 
[289]     map->default_value = ctx.default_value ? ctx.default_value:
[290]                                              &ngx_stream_variable_null_value;
[291] 
[292]     map->hostnames = ctx.hostnames;
[293] 
[294]     hash.key = ngx_hash_key_lc;
[295]     hash.max_size = mcf->hash_max_size;
[296]     hash.bucket_size = mcf->hash_bucket_size;
[297]     hash.name = "map_hash";
[298]     hash.pool = cf->pool;
[299] 
[300]     if (ctx.keys.keys.nelts) {
[301]         hash.hash = &map->map.hash.hash;
[302]         hash.temp_pool = NULL;
[303] 
[304]         if (ngx_hash_init(&hash, ctx.keys.keys.elts, ctx.keys.keys.nelts)
[305]             != NGX_OK)
[306]         {
[307]             ngx_destroy_pool(pool);
[308]             return NGX_CONF_ERROR;
[309]         }
[310]     }
[311] 
[312]     if (ctx.keys.dns_wc_head.nelts) {
[313] 
[314]         ngx_qsort(ctx.keys.dns_wc_head.elts,
[315]                   (size_t) ctx.keys.dns_wc_head.nelts,
[316]                   sizeof(ngx_hash_key_t), ngx_stream_map_cmp_dns_wildcards);
[317] 
[318]         hash.hash = NULL;
[319]         hash.temp_pool = pool;
[320] 
[321]         if (ngx_hash_wildcard_init(&hash, ctx.keys.dns_wc_head.elts,
[322]                                    ctx.keys.dns_wc_head.nelts)
[323]             != NGX_OK)
[324]         {
[325]             ngx_destroy_pool(pool);
[326]             return NGX_CONF_ERROR;
[327]         }
[328] 
[329]         map->map.hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
[330]     }
[331] 
[332]     if (ctx.keys.dns_wc_tail.nelts) {
[333] 
[334]         ngx_qsort(ctx.keys.dns_wc_tail.elts,
[335]                   (size_t) ctx.keys.dns_wc_tail.nelts,
[336]                   sizeof(ngx_hash_key_t), ngx_stream_map_cmp_dns_wildcards);
[337] 
[338]         hash.hash = NULL;
[339]         hash.temp_pool = pool;
[340] 
[341]         if (ngx_hash_wildcard_init(&hash, ctx.keys.dns_wc_tail.elts,
[342]                                    ctx.keys.dns_wc_tail.nelts)
[343]             != NGX_OK)
[344]         {
[345]             ngx_destroy_pool(pool);
[346]             return NGX_CONF_ERROR;
[347]         }
[348] 
[349]         map->map.hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
[350]     }
[351] 
[352] #if (NGX_PCRE)
[353] 
[354]     if (ctx.regexes.nelts) {
[355]         map->map.regex = ctx.regexes.elts;
[356]         map->map.nregex = ctx.regexes.nelts;
[357]     }
[358] 
[359] #endif
[360] 
[361]     ngx_destroy_pool(pool);
[362] 
[363]     return rv;
[364] }
[365] 
[366] 
[367] static int ngx_libc_cdecl
[368] ngx_stream_map_cmp_dns_wildcards(const void *one, const void *two)
[369] {
[370]     ngx_hash_key_t  *first, *second;
[371] 
[372]     first = (ngx_hash_key_t *) one;
[373]     second = (ngx_hash_key_t *) two;
[374] 
[375]     return ngx_dns_strcmp(first->key.data, second->key.data);
[376] }
[377] 
[378] 
[379] static char *
[380] ngx_stream_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[381] {
[382]     u_char                              *data;
[383]     size_t                               len;
[384]     ngx_int_t                            rv;
[385]     ngx_str_t                           *value, v;
[386]     ngx_uint_t                           i, key;
[387]     ngx_stream_map_conf_ctx_t           *ctx;
[388]     ngx_stream_complex_value_t           cv, *cvp;
[389]     ngx_stream_variable_value_t         *var, **vp;
[390]     ngx_stream_compile_complex_value_t   ccv;
[391] 
[392]     ctx = cf->ctx;
[393] 
[394]     value = cf->args->elts;
[395] 
[396]     if (cf->args->nelts == 1
[397]         && ngx_strcmp(value[0].data, "hostnames") == 0)
[398]     {
[399]         ctx->hostnames = 1;
[400]         return NGX_CONF_OK;
[401]     }
[402] 
[403]     if (cf->args->nelts == 1
[404]         && ngx_strcmp(value[0].data, "volatile") == 0)
[405]     {
[406]         ctx->no_cacheable = 1;
[407]         return NGX_CONF_OK;
[408]     }
[409] 
[410]     if (cf->args->nelts != 2) {
[411]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[412]                            "invalid number of the map parameters");
[413]         return NGX_CONF_ERROR;
[414]     }
[415] 
[416]     if (ngx_strcmp(value[0].data, "include") == 0) {
[417]         return ngx_conf_include(cf, dummy, conf);
[418]     }
[419] 
[420]     key = 0;
[421] 
[422]     for (i = 0; i < value[1].len; i++) {
[423]         key = ngx_hash(key, value[1].data[i]);
[424]     }
[425] 
[426]     key %= ctx->keys.hsize;
[427] 
[428]     vp = ctx->values_hash[key].elts;
[429] 
[430]     if (vp) {
[431]         for (i = 0; i < ctx->values_hash[key].nelts; i++) {
[432] 
[433]             if (vp[i]->valid) {
[434]                 data = vp[i]->data;
[435]                 len = vp[i]->len;
[436] 
[437]             } else {
[438]                 cvp = (ngx_stream_complex_value_t *) vp[i]->data;
[439]                 data = cvp->value.data;
[440]                 len = cvp->value.len;
[441]             }
[442] 
[443]             if (value[1].len != len) {
[444]                 continue;
[445]             }
[446] 
[447]             if (ngx_strncmp(value[1].data, data, len) == 0) {
[448]                 var = vp[i];
[449]                 goto found;
[450]             }
[451]         }
[452] 
[453]     } else {
[454]         if (ngx_array_init(&ctx->values_hash[key], cf->pool, 4,
[455]                            sizeof(ngx_stream_variable_value_t *))
[456]             != NGX_OK)
[457]         {
[458]             return NGX_CONF_ERROR;
[459]         }
[460]     }
[461] 
[462]     var = ngx_palloc(ctx->keys.pool, sizeof(ngx_stream_variable_value_t));
[463]     if (var == NULL) {
[464]         return NGX_CONF_ERROR;
[465]     }
[466] 
[467]     v.len = value[1].len;
[468]     v.data = ngx_pstrdup(ctx->keys.pool, &value[1]);
[469]     if (v.data == NULL) {
[470]         return NGX_CONF_ERROR;
[471]     }
[472] 
[473]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[474] 
[475]     ccv.cf = ctx->cf;
[476]     ccv.value = &v;
[477]     ccv.complex_value = &cv;
[478] 
[479]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[480]         return NGX_CONF_ERROR;
[481]     }
[482] 
[483]     if (cv.lengths != NULL) {
[484]         cvp = ngx_palloc(ctx->keys.pool, sizeof(ngx_stream_complex_value_t));
[485]         if (cvp == NULL) {
[486]             return NGX_CONF_ERROR;
[487]         }
[488] 
[489]         *cvp = cv;
[490] 
[491]         var->len = 0;
[492]         var->data = (u_char *) cvp;
[493]         var->valid = 0;
[494] 
[495]     } else {
[496]         var->len = v.len;
[497]         var->data = v.data;
[498]         var->valid = 1;
[499]     }
[500] 
[501]     var->no_cacheable = 0;
[502]     var->not_found = 0;
[503] 
[504]     vp = ngx_array_push(&ctx->values_hash[key]);
[505]     if (vp == NULL) {
[506]         return NGX_CONF_ERROR;
[507]     }
[508] 
[509]     *vp = var;
[510] 
[511] found:
[512] 
[513]     if (ngx_strcmp(value[0].data, "default") == 0) {
[514] 
[515]         if (ctx->default_value) {
[516]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[517]                                "duplicate default map parameter");
[518]             return NGX_CONF_ERROR;
[519]         }
[520] 
[521]         ctx->default_value = var;
[522] 
[523]         return NGX_CONF_OK;
[524]     }
[525] 
[526] #if (NGX_PCRE)
[527] 
[528]     if (value[0].len && value[0].data[0] == '~') {
[529]         ngx_regex_compile_t      rc;
[530]         ngx_stream_map_regex_t  *regex;
[531]         u_char                   errstr[NGX_MAX_CONF_ERRSTR];
[532] 
[533]         regex = ngx_array_push(&ctx->regexes);
[534]         if (regex == NULL) {
[535]             return NGX_CONF_ERROR;
[536]         }
[537] 
[538]         value[0].len--;
[539]         value[0].data++;
[540] 
[541]         ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[542] 
[543]         if (value[0].data[0] == '*') {
[544]             value[0].len--;
[545]             value[0].data++;
[546]             rc.options = NGX_REGEX_CASELESS;
[547]         }
[548] 
[549]         rc.pattern = value[0];
[550]         rc.err.len = NGX_MAX_CONF_ERRSTR;
[551]         rc.err.data = errstr;
[552] 
[553]         regex->regex = ngx_stream_regex_compile(ctx->cf, &rc);
[554]         if (regex->regex == NULL) {
[555]             return NGX_CONF_ERROR;
[556]         }
[557] 
[558]         regex->value = var;
[559] 
[560]         return NGX_CONF_OK;
[561]     }
[562] 
[563] #endif
[564] 
[565]     if (value[0].len && value[0].data[0] == '\\') {
[566]         value[0].len--;
[567]         value[0].data++;
[568]     }
[569] 
[570]     rv = ngx_hash_add_key(&ctx->keys, &value[0], var,
[571]                           (ctx->hostnames) ? NGX_HASH_WILDCARD_KEY : 0);
[572] 
[573]     if (rv == NGX_OK) {
[574]         return NGX_CONF_OK;
[575]     }
[576] 
[577]     if (rv == NGX_DECLINED) {
[578]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[579]                            "invalid hostname or wildcard \"%V\"", &value[0]);
[580]     }
[581] 
[582]     if (rv == NGX_BUSY) {
[583]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[584]                            "conflicting parameter \"%V\"", &value[0]);
[585]     }
[586] 
[587]     return NGX_CONF_ERROR;
[588] }
