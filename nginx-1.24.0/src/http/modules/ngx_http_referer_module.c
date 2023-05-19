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
[13] #define NGX_HTTP_REFERER_NO_URI_PART  ((void *) 4)
[14] 
[15] 
[16] typedef struct {
[17]     ngx_hash_combined_t      hash;
[18] 
[19] #if (NGX_PCRE)
[20]     ngx_array_t             *regex;
[21]     ngx_array_t             *server_name_regex;
[22] #endif
[23] 
[24]     ngx_flag_t               no_referer;
[25]     ngx_flag_t               blocked_referer;
[26]     ngx_flag_t               server_names;
[27] 
[28]     ngx_hash_keys_arrays_t  *keys;
[29] 
[30]     ngx_uint_t               referer_hash_max_size;
[31]     ngx_uint_t               referer_hash_bucket_size;
[32] } ngx_http_referer_conf_t;
[33] 
[34] 
[35] static ngx_int_t ngx_http_referer_add_variables(ngx_conf_t *cf);
[36] static void * ngx_http_referer_create_conf(ngx_conf_t *cf);
[37] static char * ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent,
[38]     void *child);
[39] static char *ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd,
[40]     void *conf);
[41] static ngx_int_t ngx_http_add_referer(ngx_conf_t *cf,
[42]     ngx_hash_keys_arrays_t *keys, ngx_str_t *value, ngx_str_t *uri);
[43] static ngx_int_t ngx_http_add_regex_referer(ngx_conf_t *cf,
[44]     ngx_http_referer_conf_t *rlcf, ngx_str_t *name);
[45] #if (NGX_PCRE)
[46] static ngx_int_t ngx_http_add_regex_server_name(ngx_conf_t *cf,
[47]     ngx_http_referer_conf_t *rlcf, ngx_http_regex_t *regex);
[48] #endif
[49] static int ngx_libc_cdecl ngx_http_cmp_referer_wildcards(const void *one,
[50]     const void *two);
[51] 
[52] 
[53] static ngx_command_t  ngx_http_referer_commands[] = {
[54] 
[55]     { ngx_string("valid_referers"),
[56]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[57]       ngx_http_valid_referers,
[58]       NGX_HTTP_LOC_CONF_OFFSET,
[59]       0,
[60]       NULL },
[61] 
[62]     { ngx_string("referer_hash_max_size"),
[63]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[64]       ngx_conf_set_num_slot,
[65]       NGX_HTTP_LOC_CONF_OFFSET,
[66]       offsetof(ngx_http_referer_conf_t, referer_hash_max_size),
[67]       NULL },
[68] 
[69]     { ngx_string("referer_hash_bucket_size"),
[70]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[71]       ngx_conf_set_num_slot,
[72]       NGX_HTTP_LOC_CONF_OFFSET,
[73]       offsetof(ngx_http_referer_conf_t, referer_hash_bucket_size),
[74]       NULL },
[75] 
[76]       ngx_null_command
[77] };
[78] 
[79] 
[80] static ngx_http_module_t  ngx_http_referer_module_ctx = {
[81]     ngx_http_referer_add_variables,        /* preconfiguration */
[82]     NULL,                                  /* postconfiguration */
[83] 
[84]     NULL,                                  /* create main configuration */
[85]     NULL,                                  /* init main configuration */
[86] 
[87]     NULL,                                  /* create server configuration */
[88]     NULL,                                  /* merge server configuration */
[89] 
[90]     ngx_http_referer_create_conf,          /* create location configuration */
[91]     ngx_http_referer_merge_conf            /* merge location configuration */
[92] };
[93] 
[94] 
[95] ngx_module_t  ngx_http_referer_module = {
[96]     NGX_MODULE_V1,
[97]     &ngx_http_referer_module_ctx,          /* module context */
[98]     ngx_http_referer_commands,             /* module directives */
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
[111] static ngx_str_t  ngx_http_invalid_referer_name = ngx_string("invalid_referer");
[112] 
[113] 
[114] static ngx_int_t
[115] ngx_http_referer_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[116]     uintptr_t data)
[117] {
[118]     u_char                    *p, *ref, *last;
[119]     size_t                     len;
[120]     ngx_str_t                 *uri;
[121]     ngx_uint_t                 i, key;
[122]     ngx_http_referer_conf_t   *rlcf;
[123]     u_char                     buf[256];
[124] #if (NGX_PCRE)
[125]     ngx_int_t                  rc;
[126]     ngx_str_t                  referer;
[127] #endif
[128] 
[129]     rlcf = ngx_http_get_module_loc_conf(r, ngx_http_referer_module);
[130] 
[131]     if (rlcf->hash.hash.buckets == NULL
[132]         && rlcf->hash.wc_head == NULL
[133]         && rlcf->hash.wc_tail == NULL
[134] #if (NGX_PCRE)
[135]         && rlcf->regex == NULL
[136]         && rlcf->server_name_regex == NULL
[137] #endif
[138]        )
[139]     {
[140]         goto valid;
[141]     }
[142] 
[143]     if (r->headers_in.referer == NULL) {
[144]         if (rlcf->no_referer) {
[145]             goto valid;
[146]         }
[147] 
[148]         goto invalid;
[149]     }
[150] 
[151]     len = r->headers_in.referer->value.len;
[152]     ref = r->headers_in.referer->value.data;
[153] 
[154]     if (len >= sizeof("http://i.ru") - 1) {
[155]         last = ref + len;
[156] 
[157]         if (ngx_strncasecmp(ref, (u_char *) "http://", 7) == 0) {
[158]             ref += 7;
[159]             len -= 7;
[160]             goto valid_scheme;
[161] 
[162]         } else if (ngx_strncasecmp(ref, (u_char *) "https://", 8) == 0) {
[163]             ref += 8;
[164]             len -= 8;
[165]             goto valid_scheme;
[166]         }
[167]     }
[168] 
[169]     if (rlcf->blocked_referer) {
[170]         goto valid;
[171]     }
[172] 
[173]     goto invalid;
[174] 
[175] valid_scheme:
[176] 
[177]     i = 0;
[178]     key = 0;
[179] 
[180]     for (p = ref; p < last; p++) {
[181]         if (*p == '/' || *p == ':') {
[182]             break;
[183]         }
[184] 
[185]         if (i == 256) {
[186]             goto invalid;
[187]         }
[188] 
[189]         buf[i] = ngx_tolower(*p);
[190]         key = ngx_hash(key, buf[i++]);
[191]     }
[192] 
[193]     uri = ngx_hash_find_combined(&rlcf->hash, key, buf, p - ref);
[194] 
[195]     if (uri) {
[196]         goto uri;
[197]     }
[198] 
[199] #if (NGX_PCRE)
[200] 
[201]     if (rlcf->server_name_regex) {
[202]         referer.len = p - ref;
[203]         referer.data = buf;
[204] 
[205]         rc = ngx_regex_exec_array(rlcf->server_name_regex, &referer,
[206]                                   r->connection->log);
[207] 
[208]         if (rc == NGX_OK) {
[209]             goto valid;
[210]         }
[211] 
[212]         if (rc == NGX_ERROR) {
[213]             return rc;
[214]         }
[215] 
[216]         /* NGX_DECLINED */
[217]     }
[218] 
[219]     if (rlcf->regex) {
[220]         referer.len = len;
[221]         referer.data = ref;
[222] 
[223]         rc = ngx_regex_exec_array(rlcf->regex, &referer, r->connection->log);
[224] 
[225]         if (rc == NGX_OK) {
[226]             goto valid;
[227]         }
[228] 
[229]         if (rc == NGX_ERROR) {
[230]             return rc;
[231]         }
[232] 
[233]         /* NGX_DECLINED */
[234]     }
[235] 
[236] #endif
[237] 
[238] invalid:
[239] 
[240]     *v = ngx_http_variable_true_value;
[241] 
[242]     return NGX_OK;
[243] 
[244] uri:
[245] 
[246]     for ( /* void */ ; p < last; p++) {
[247]         if (*p == '/') {
[248]             break;
[249]         }
[250]     }
[251] 
[252]     len = last - p;
[253] 
[254]     if (uri == NGX_HTTP_REFERER_NO_URI_PART) {
[255]         goto valid;
[256]     }
[257] 
[258]     if (len < uri->len || ngx_strncmp(uri->data, p, uri->len) != 0) {
[259]         goto invalid;
[260]     }
[261] 
[262] valid:
[263] 
[264]     *v = ngx_http_variable_null_value;
[265] 
[266]     return NGX_OK;
[267] }
[268] 
[269] 
[270] static ngx_int_t
[271] ngx_http_referer_add_variables(ngx_conf_t *cf)
[272] {
[273]     ngx_http_variable_t  *var;
[274] 
[275]     var = ngx_http_add_variable(cf, &ngx_http_invalid_referer_name,
[276]                                 NGX_HTTP_VAR_CHANGEABLE);
[277]     if (var == NULL) {
[278]         return NGX_ERROR;
[279]     }
[280] 
[281]     var->get_handler = ngx_http_referer_variable;
[282] 
[283]     return NGX_OK;
[284] }
[285] 
[286] 
[287] static void *
[288] ngx_http_referer_create_conf(ngx_conf_t *cf)
[289] {
[290]     ngx_http_referer_conf_t  *conf;
[291] 
[292]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_referer_conf_t));
[293]     if (conf == NULL) {
[294]         return NULL;
[295]     }
[296] 
[297]     /*
[298]      * set by ngx_pcalloc():
[299]      *
[300]      *     conf->hash = { NULL };
[301]      *     conf->server_names = 0;
[302]      *     conf->keys = NULL;
[303]      */
[304] 
[305] #if (NGX_PCRE)
[306]     conf->regex = NGX_CONF_UNSET_PTR;
[307]     conf->server_name_regex = NGX_CONF_UNSET_PTR;
[308] #endif
[309] 
[310]     conf->no_referer = NGX_CONF_UNSET;
[311]     conf->blocked_referer = NGX_CONF_UNSET;
[312]     conf->referer_hash_max_size = NGX_CONF_UNSET_UINT;
[313]     conf->referer_hash_bucket_size = NGX_CONF_UNSET_UINT;
[314] 
[315]     return conf;
[316] }
[317] 
[318] 
[319] static char *
[320] ngx_http_referer_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[321] {
[322]     ngx_http_referer_conf_t *prev = parent;
[323]     ngx_http_referer_conf_t *conf = child;
[324] 
[325]     ngx_uint_t                 n;
[326]     ngx_hash_init_t            hash;
[327]     ngx_http_server_name_t    *sn;
[328]     ngx_http_core_srv_conf_t  *cscf;
[329] 
[330]     if (conf->keys == NULL) {
[331]         conf->hash = prev->hash;
[332] 
[333] #if (NGX_PCRE)
[334]         ngx_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
[335]         ngx_conf_merge_ptr_value(conf->server_name_regex,
[336]                                  prev->server_name_regex, NULL);
[337] #endif
[338]         ngx_conf_merge_value(conf->no_referer, prev->no_referer, 0);
[339]         ngx_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);
[340]         ngx_conf_merge_uint_value(conf->referer_hash_max_size,
[341]                                   prev->referer_hash_max_size, 2048);
[342]         ngx_conf_merge_uint_value(conf->referer_hash_bucket_size,
[343]                                   prev->referer_hash_bucket_size, 64);
[344] 
[345]         return NGX_CONF_OK;
[346]     }
[347] 
[348]     if (conf->server_names == 1) {
[349]         cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
[350] 
[351]         sn = cscf->server_names.elts;
[352]         for (n = 0; n < cscf->server_names.nelts; n++) {
[353] 
[354] #if (NGX_PCRE)
[355]             if (sn[n].regex) {
[356] 
[357]                 if (ngx_http_add_regex_server_name(cf, conf, sn[n].regex)
[358]                     != NGX_OK)
[359]                 {
[360]                     return NGX_CONF_ERROR;
[361]                 }
[362] 
[363]                 continue;
[364]             }
[365] #endif
[366] 
[367]             if (ngx_http_add_referer(cf, conf->keys, &sn[n].name, NULL)
[368]                 != NGX_OK)
[369]             {
[370]                 return NGX_CONF_ERROR;
[371]             }
[372]         }
[373]     }
[374] 
[375]     if ((conf->no_referer == 1 || conf->blocked_referer == 1)
[376]         && conf->keys->keys.nelts == 0
[377]         && conf->keys->dns_wc_head.nelts == 0
[378]         && conf->keys->dns_wc_tail.nelts == 0)
[379]     {
[380]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[381]                       "the \"none\" or \"blocked\" referers are specified "
[382]                       "in the \"valid_referers\" directive "
[383]                       "without any valid referer");
[384]         return NGX_CONF_ERROR;
[385]     }
[386] 
[387]     ngx_conf_merge_uint_value(conf->referer_hash_max_size,
[388]                               prev->referer_hash_max_size, 2048);
[389]     ngx_conf_merge_uint_value(conf->referer_hash_bucket_size,
[390]                               prev->referer_hash_bucket_size, 64);
[391]     conf->referer_hash_bucket_size = ngx_align(conf->referer_hash_bucket_size,
[392]                                                ngx_cacheline_size);
[393] 
[394]     hash.key = ngx_hash_key_lc;
[395]     hash.max_size = conf->referer_hash_max_size;
[396]     hash.bucket_size = conf->referer_hash_bucket_size;
[397]     hash.name = "referer_hash";
[398]     hash.pool = cf->pool;
[399] 
[400]     if (conf->keys->keys.nelts) {
[401]         hash.hash = &conf->hash.hash;
[402]         hash.temp_pool = NULL;
[403] 
[404]         if (ngx_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
[405]             != NGX_OK)
[406]         {
[407]             return NGX_CONF_ERROR;
[408]         }
[409]     }
[410] 
[411]     if (conf->keys->dns_wc_head.nelts) {
[412] 
[413]         ngx_qsort(conf->keys->dns_wc_head.elts,
[414]                   (size_t) conf->keys->dns_wc_head.nelts,
[415]                   sizeof(ngx_hash_key_t),
[416]                   ngx_http_cmp_referer_wildcards);
[417] 
[418]         hash.hash = NULL;
[419]         hash.temp_pool = cf->temp_pool;
[420] 
[421]         if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
[422]                                    conf->keys->dns_wc_head.nelts)
[423]             != NGX_OK)
[424]         {
[425]             return NGX_CONF_ERROR;
[426]         }
[427] 
[428]         conf->hash.wc_head = (ngx_hash_wildcard_t *) hash.hash;
[429]     }
[430] 
[431]     if (conf->keys->dns_wc_tail.nelts) {
[432] 
[433]         ngx_qsort(conf->keys->dns_wc_tail.elts,
[434]                   (size_t) conf->keys->dns_wc_tail.nelts,
[435]                   sizeof(ngx_hash_key_t),
[436]                   ngx_http_cmp_referer_wildcards);
[437] 
[438]         hash.hash = NULL;
[439]         hash.temp_pool = cf->temp_pool;
[440] 
[441]         if (ngx_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
[442]                                    conf->keys->dns_wc_tail.nelts)
[443]             != NGX_OK)
[444]         {
[445]             return NGX_CONF_ERROR;
[446]         }
[447] 
[448]         conf->hash.wc_tail = (ngx_hash_wildcard_t *) hash.hash;
[449]     }
[450] 
[451] #if (NGX_PCRE)
[452]     ngx_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
[453]     ngx_conf_merge_ptr_value(conf->server_name_regex, prev->server_name_regex,
[454]                              NULL);
[455] #endif
[456] 
[457]     if (conf->no_referer == NGX_CONF_UNSET) {
[458]         conf->no_referer = 0;
[459]     }
[460] 
[461]     if (conf->blocked_referer == NGX_CONF_UNSET) {
[462]         conf->blocked_referer = 0;
[463]     }
[464] 
[465]     conf->keys = NULL;
[466] 
[467]     return NGX_CONF_OK;
[468] }
[469] 
[470] 
[471] static char *
[472] ngx_http_valid_referers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[473] {
[474]     ngx_http_referer_conf_t  *rlcf = conf;
[475] 
[476]     u_char      *p;
[477]     ngx_str_t   *value, uri;
[478]     ngx_uint_t   i;
[479] 
[480]     if (rlcf->keys == NULL) {
[481]         rlcf->keys = ngx_pcalloc(cf->temp_pool, sizeof(ngx_hash_keys_arrays_t));
[482]         if (rlcf->keys == NULL) {
[483]             return NGX_CONF_ERROR;
[484]         }
[485] 
[486]         rlcf->keys->pool = cf->pool;
[487]         rlcf->keys->temp_pool = cf->pool;
[488] 
[489]         if (ngx_hash_keys_array_init(rlcf->keys, NGX_HASH_SMALL) != NGX_OK) {
[490]             return NGX_CONF_ERROR;
[491]         }
[492]     }
[493] 
[494]     value = cf->args->elts;
[495] 
[496]     for (i = 1; i < cf->args->nelts; i++) {
[497]         if (value[i].len == 0) {
[498]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[499]                                "invalid referer \"%V\"", &value[i]);
[500]             return NGX_CONF_ERROR;
[501]         }
[502] 
[503]         if (ngx_strcmp(value[i].data, "none") == 0) {
[504]             rlcf->no_referer = 1;
[505]             continue;
[506]         }
[507] 
[508]         if (ngx_strcmp(value[i].data, "blocked") == 0) {
[509]             rlcf->blocked_referer = 1;
[510]             continue;
[511]         }
[512] 
[513]         if (ngx_strcmp(value[i].data, "server_names") == 0) {
[514]             rlcf->server_names = 1;
[515]             continue;
[516]         }
[517] 
[518]         if (value[i].data[0] == '~') {
[519]             if (ngx_http_add_regex_referer(cf, rlcf, &value[i]) != NGX_OK) {
[520]                 return NGX_CONF_ERROR;
[521]             }
[522] 
[523]             continue;
[524]         }
[525] 
[526]         ngx_str_null(&uri);
[527] 
[528]         p = (u_char *) ngx_strchr(value[i].data, '/');
[529] 
[530]         if (p) {
[531]             uri.len = (value[i].data + value[i].len) - p;
[532]             uri.data = p;
[533]             value[i].len = p - value[i].data;
[534]         }
[535] 
[536]         if (ngx_http_add_referer(cf, rlcf->keys, &value[i], &uri) != NGX_OK) {
[537]             return NGX_CONF_ERROR;
[538]         }
[539]     }
[540] 
[541]     return NGX_CONF_OK;
[542] }
[543] 
[544] 
[545] static ngx_int_t
[546] ngx_http_add_referer(ngx_conf_t *cf, ngx_hash_keys_arrays_t *keys,
[547]     ngx_str_t *value, ngx_str_t *uri)
[548] {
[549]     ngx_int_t   rc;
[550]     ngx_str_t  *u;
[551] 
[552]     if (uri == NULL || uri->len == 0) {
[553]         u = NGX_HTTP_REFERER_NO_URI_PART;
[554] 
[555]     } else {
[556]         u = ngx_palloc(cf->pool, sizeof(ngx_str_t));
[557]         if (u == NULL) {
[558]             return NGX_ERROR;
[559]         }
[560] 
[561]         *u = *uri;
[562]     }
[563] 
[564]     rc = ngx_hash_add_key(keys, value, u, NGX_HASH_WILDCARD_KEY);
[565] 
[566]     if (rc == NGX_OK) {
[567]         return NGX_OK;
[568]     }
[569] 
[570]     if (rc == NGX_DECLINED) {
[571]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[572]                            "invalid hostname or wildcard \"%V\"", value);
[573]     }
[574] 
[575]     if (rc == NGX_BUSY) {
[576]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[577]                            "conflicting parameter \"%V\"", value);
[578]     }
[579] 
[580]     return NGX_ERROR;
[581] }
[582] 
[583] 
[584] static ngx_int_t
[585] ngx_http_add_regex_referer(ngx_conf_t *cf, ngx_http_referer_conf_t *rlcf,
[586]     ngx_str_t *name)
[587] {
[588] #if (NGX_PCRE)
[589]     ngx_regex_elt_t      *re;
[590]     ngx_regex_compile_t   rc;
[591]     u_char                errstr[NGX_MAX_CONF_ERRSTR];
[592] 
[593]     if (name->len == 1) {
[594]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty regex in \"%V\"", name);
[595]         return NGX_ERROR;
[596]     }
[597] 
[598]     if (rlcf->regex == NGX_CONF_UNSET_PTR) {
[599]         rlcf->regex = ngx_array_create(cf->pool, 2, sizeof(ngx_regex_elt_t));
[600]         if (rlcf->regex == NULL) {
[601]             return NGX_ERROR;
[602]         }
[603]     }
[604] 
[605]     re = ngx_array_push(rlcf->regex);
[606]     if (re == NULL) {
[607]         return NGX_ERROR;
[608]     }
[609] 
[610]     name->len--;
[611]     name->data++;
[612] 
[613]     ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[614] 
[615]     rc.pattern = *name;
[616]     rc.pool = cf->pool;
[617]     rc.options = NGX_REGEX_CASELESS;
[618]     rc.err.len = NGX_MAX_CONF_ERRSTR;
[619]     rc.err.data = errstr;
[620] 
[621]     if (ngx_regex_compile(&rc) != NGX_OK) {
[622]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
[623]         return NGX_ERROR;
[624]     }
[625] 
[626]     re->regex = rc.regex;
[627]     re->name = name->data;
[628] 
[629]     return NGX_OK;
[630] 
[631] #else
[632] 
[633]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[634]                        "the using of the regex \"%V\" requires PCRE library",
[635]                        name);
[636] 
[637]     return NGX_ERROR;
[638] 
[639] #endif
[640] }
[641] 
[642] 
[643] #if (NGX_PCRE)
[644] 
[645] static ngx_int_t
[646] ngx_http_add_regex_server_name(ngx_conf_t *cf, ngx_http_referer_conf_t *rlcf,
[647]     ngx_http_regex_t *regex)
[648] {
[649]     ngx_regex_elt_t  *re;
[650] 
[651]     if (rlcf->server_name_regex == NGX_CONF_UNSET_PTR) {
[652]         rlcf->server_name_regex = ngx_array_create(cf->pool, 2,
[653]                                                    sizeof(ngx_regex_elt_t));
[654]         if (rlcf->server_name_regex == NULL) {
[655]             return NGX_ERROR;
[656]         }
[657]     }
[658] 
[659]     re = ngx_array_push(rlcf->server_name_regex);
[660]     if (re == NULL) {
[661]         return NGX_ERROR;
[662]     }
[663] 
[664]     re->regex = regex->regex;
[665]     re->name = regex->name.data;
[666] 
[667]     return NGX_OK;
[668] }
[669] 
[670] #endif
[671] 
[672] 
[673] static int ngx_libc_cdecl
[674] ngx_http_cmp_referer_wildcards(const void *one, const void *two)
[675] {
[676]     ngx_hash_key_t  *first, *second;
[677] 
[678]     first = (ngx_hash_key_t *) one;
[679]     second = (ngx_hash_key_t *) two;
[680] 
[681]     return ngx_dns_strcmp(first->key.data, second->key.data);
[682] }
