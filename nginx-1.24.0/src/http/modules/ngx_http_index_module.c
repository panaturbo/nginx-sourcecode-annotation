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
[14]     ngx_str_t                name;
[15]     ngx_array_t             *lengths;
[16]     ngx_array_t             *values;
[17] } ngx_http_index_t;
[18] 
[19] 
[20] typedef struct {
[21]     ngx_array_t             *indices;    /* array of ngx_http_index_t */
[22]     size_t                   max_index_len;
[23] } ngx_http_index_loc_conf_t;
[24] 
[25] 
[26] #define NGX_HTTP_DEFAULT_INDEX   "index.html"
[27] 
[28] 
[29] static ngx_int_t ngx_http_index_test_dir(ngx_http_request_t *r,
[30]     ngx_http_core_loc_conf_t *clcf, u_char *path, u_char *last);
[31] static ngx_int_t ngx_http_index_error(ngx_http_request_t *r,
[32]     ngx_http_core_loc_conf_t *clcf, u_char *file, ngx_err_t err);
[33] 
[34] static ngx_int_t ngx_http_index_init(ngx_conf_t *cf);
[35] static void *ngx_http_index_create_loc_conf(ngx_conf_t *cf);
[36] static char *ngx_http_index_merge_loc_conf(ngx_conf_t *cf,
[37]     void *parent, void *child);
[38] static char *ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd,
[39]     void *conf);
[40] 
[41] 
[42] static ngx_command_t  ngx_http_index_commands[] = {
[43] 
[44]     { ngx_string("index"),
[45]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[46]       ngx_http_index_set_index,
[47]       NGX_HTTP_LOC_CONF_OFFSET,
[48]       0,
[49]       NULL },
[50] 
[51]       ngx_null_command
[52] };
[53] 
[54] 
[55] static ngx_http_module_t  ngx_http_index_module_ctx = {
[56]     NULL,                                  /* preconfiguration */
[57]     ngx_http_index_init,                   /* postconfiguration */
[58] 
[59]     NULL,                                  /* create main configuration */
[60]     NULL,                                  /* init main configuration */
[61] 
[62]     NULL,                                  /* create server configuration */
[63]     NULL,                                  /* merge server configuration */
[64] 
[65]     ngx_http_index_create_loc_conf,        /* create location configuration */
[66]     ngx_http_index_merge_loc_conf          /* merge location configuration */
[67] };
[68] 
[69] 
[70] ngx_module_t  ngx_http_index_module = {
[71]     NGX_MODULE_V1,
[72]     &ngx_http_index_module_ctx,            /* module context */
[73]     ngx_http_index_commands,               /* module directives */
[74]     NGX_HTTP_MODULE,                       /* module type */
[75]     NULL,                                  /* init master */
[76]     NULL,                                  /* init module */
[77]     NULL,                                  /* init process */
[78]     NULL,                                  /* init thread */
[79]     NULL,                                  /* exit thread */
[80]     NULL,                                  /* exit process */
[81]     NULL,                                  /* exit master */
[82]     NGX_MODULE_V1_PADDING
[83] };
[84] 
[85] 
[86] /*
[87]  * Try to open/test the first index file before the test of directory
[88]  * existence because valid requests should prevail over invalid ones.
[89]  * If open()/stat() of a file will fail then stat() of a directory
[90]  * should be faster because kernel may have already cached some data.
[91]  * Besides, Win32 may return ERROR_PATH_NOT_FOUND (NGX_ENOTDIR) at once.
[92]  * Unix has ENOTDIR error; however, it's less helpful than Win32's one:
[93]  * it only indicates that path points to a regular file, not a directory.
[94]  */
[95] 
[96] static ngx_int_t
[97] ngx_http_index_handler(ngx_http_request_t *r)
[98] {
[99]     u_char                       *p, *name;
[100]     size_t                        len, root, reserve, allocated;
[101]     ngx_int_t                     rc;
[102]     ngx_str_t                     path, uri;
[103]     ngx_uint_t                    i, dir_tested;
[104]     ngx_http_index_t             *index;
[105]     ngx_open_file_info_t          of;
[106]     ngx_http_script_code_pt       code;
[107]     ngx_http_script_engine_t      e;
[108]     ngx_http_core_loc_conf_t     *clcf;
[109]     ngx_http_index_loc_conf_t    *ilcf;
[110]     ngx_http_script_len_code_pt   lcode;
[111] 
[112]     if (r->uri.data[r->uri.len - 1] != '/') {
[113]         return NGX_DECLINED;
[114]     }
[115] 
[116]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
[117]         return NGX_DECLINED;
[118]     }
[119] 
[120]     ilcf = ngx_http_get_module_loc_conf(r, ngx_http_index_module);
[121]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[122] 
[123]     allocated = 0;
[124]     root = 0;
[125]     dir_tested = 0;
[126]     name = NULL;
[127]     /* suppress MSVC warning */
[128]     path.data = NULL;
[129] 
[130]     index = ilcf->indices->elts;
[131]     for (i = 0; i < ilcf->indices->nelts; i++) {
[132] 
[133]         if (index[i].lengths == NULL) {
[134] 
[135]             if (index[i].name.data[0] == '/') {
[136]                 return ngx_http_internal_redirect(r, &index[i].name, &r->args);
[137]             }
[138] 
[139]             reserve = ilcf->max_index_len;
[140]             len = index[i].name.len;
[141] 
[142]         } else {
[143]             ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[144] 
[145]             e.ip = index[i].lengths->elts;
[146]             e.request = r;
[147]             e.flushed = 1;
[148] 
[149]             /* 1 is for terminating '\0' as in static names */
[150]             len = 1;
[151] 
[152]             while (*(uintptr_t *) e.ip) {
[153]                 lcode = *(ngx_http_script_len_code_pt *) e.ip;
[154]                 len += lcode(&e);
[155]             }
[156] 
[157]             /* 16 bytes are preallocation */
[158] 
[159]             reserve = len + 16;
[160]         }
[161] 
[162]         if (reserve > allocated) {
[163] 
[164]             name = ngx_http_map_uri_to_path(r, &path, &root, reserve);
[165]             if (name == NULL) {
[166]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[167]             }
[168] 
[169]             allocated = path.data + path.len - name;
[170]         }
[171] 
[172]         if (index[i].values == NULL) {
[173] 
[174]             /* index[i].name.len includes the terminating '\0' */
[175] 
[176]             ngx_memcpy(name, index[i].name.data, index[i].name.len);
[177] 
[178]             path.len = (name + index[i].name.len - 1) - path.data;
[179] 
[180]         } else {
[181]             e.ip = index[i].values->elts;
[182]             e.pos = name;
[183] 
[184]             while (*(uintptr_t *) e.ip) {
[185]                 code = *(ngx_http_script_code_pt *) e.ip;
[186]                 code((ngx_http_script_engine_t *) &e);
[187]             }
[188] 
[189]             if (*name == '/') {
[190]                 uri.len = len - 1;
[191]                 uri.data = name;
[192]                 return ngx_http_internal_redirect(r, &uri, &r->args);
[193]             }
[194] 
[195]             path.len = e.pos - path.data;
[196] 
[197]             *e.pos = '\0';
[198]         }
[199] 
[200]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[201]                        "open index \"%V\"", &path);
[202] 
[203]         ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[204] 
[205]         of.read_ahead = clcf->read_ahead;
[206]         of.directio = clcf->directio;
[207]         of.valid = clcf->open_file_cache_valid;
[208]         of.min_uses = clcf->open_file_cache_min_uses;
[209]         of.test_only = 1;
[210]         of.errors = clcf->open_file_cache_errors;
[211]         of.events = clcf->open_file_cache_events;
[212] 
[213]         if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[214]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[215]         }
[216] 
[217]         if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[218]             != NGX_OK)
[219]         {
[220]             if (of.err == 0) {
[221]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[222]             }
[223] 
[224]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, of.err,
[225]                            "%s \"%s\" failed", of.failed, path.data);
[226] 
[227] #if (NGX_HAVE_OPENAT)
[228]             if (of.err == NGX_EMLINK
[229]                 || of.err == NGX_ELOOP)
[230]             {
[231]                 return NGX_HTTP_FORBIDDEN;
[232]             }
[233] #endif
[234] 
[235]             if (of.err == NGX_ENOTDIR
[236]                 || of.err == NGX_ENAMETOOLONG
[237]                 || of.err == NGX_EACCES)
[238]             {
[239]                 return ngx_http_index_error(r, clcf, path.data, of.err);
[240]             }
[241] 
[242]             if (!dir_tested) {
[243]                 rc = ngx_http_index_test_dir(r, clcf, path.data, name - 1);
[244] 
[245]                 if (rc != NGX_OK) {
[246]                     return rc;
[247]                 }
[248] 
[249]                 dir_tested = 1;
[250]             }
[251] 
[252]             if (of.err == NGX_ENOENT) {
[253]                 continue;
[254]             }
[255] 
[256]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
[257]                           "%s \"%s\" failed", of.failed, path.data);
[258] 
[259]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[260]         }
[261] 
[262]         uri.len = r->uri.len + len - 1;
[263] 
[264]         if (!clcf->alias) {
[265]             uri.data = path.data + root;
[266] 
[267]         } else {
[268]             uri.data = ngx_pnalloc(r->pool, uri.len);
[269]             if (uri.data == NULL) {
[270]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[271]             }
[272] 
[273]             p = ngx_copy(uri.data, r->uri.data, r->uri.len);
[274]             ngx_memcpy(p, name, len - 1);
[275]         }
[276] 
[277]         return ngx_http_internal_redirect(r, &uri, &r->args);
[278]     }
[279] 
[280]     return NGX_DECLINED;
[281] }
[282] 
[283] 
[284] static ngx_int_t
[285] ngx_http_index_test_dir(ngx_http_request_t *r, ngx_http_core_loc_conf_t *clcf,
[286]     u_char *path, u_char *last)
[287] {
[288]     u_char                c;
[289]     ngx_str_t             dir;
[290]     ngx_open_file_info_t  of;
[291] 
[292]     c = *last;
[293]     if (c != '/' || path == last) {
[294]         /* "alias" without trailing slash */
[295]         c = *(++last);
[296]     }
[297]     *last = '\0';
[298] 
[299]     dir.len = last - path;
[300]     dir.data = path;
[301] 
[302]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[303]                    "http index check dir: \"%V\"", &dir);
[304] 
[305]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[306] 
[307]     of.test_dir = 1;
[308]     of.test_only = 1;
[309]     of.valid = clcf->open_file_cache_valid;
[310]     of.errors = clcf->open_file_cache_errors;
[311] 
[312]     if (ngx_http_set_disable_symlinks(r, clcf, &dir, &of) != NGX_OK) {
[313]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[314]     }
[315] 
[316]     if (ngx_open_cached_file(clcf->open_file_cache, &dir, &of, r->pool)
[317]         != NGX_OK)
[318]     {
[319]         if (of.err) {
[320] 
[321] #if (NGX_HAVE_OPENAT)
[322]             if (of.err == NGX_EMLINK
[323]                 || of.err == NGX_ELOOP)
[324]             {
[325]                 return NGX_HTTP_FORBIDDEN;
[326]             }
[327] #endif
[328] 
[329]             if (of.err == NGX_ENOENT) {
[330]                 *last = c;
[331]                 return ngx_http_index_error(r, clcf, dir.data, NGX_ENOENT);
[332]             }
[333] 
[334]             if (of.err == NGX_EACCES) {
[335] 
[336]                 *last = c;
[337] 
[338]                 /*
[339]                  * ngx_http_index_test_dir() is called after the first index
[340]                  * file testing has returned an error distinct from NGX_EACCES.
[341]                  * This means that directory searching is allowed.
[342]                  */
[343] 
[344]                 return NGX_OK;
[345]             }
[346] 
[347]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
[348]                           "%s \"%s\" failed", of.failed, dir.data);
[349]         }
[350] 
[351]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[352]     }
[353] 
[354]     *last = c;
[355] 
[356]     if (of.is_dir) {
[357]         return NGX_OK;
[358]     }
[359] 
[360]     ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[361]                   "\"%s\" is not a directory", dir.data);
[362] 
[363]     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[364] }
[365] 
[366] 
[367] static ngx_int_t
[368] ngx_http_index_error(ngx_http_request_t *r, ngx_http_core_loc_conf_t  *clcf,
[369]     u_char *file, ngx_err_t err)
[370] {
[371]     if (err == NGX_EACCES) {
[372]         ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
[373]                       "\"%s\" is forbidden", file);
[374] 
[375]         return NGX_HTTP_FORBIDDEN;
[376]     }
[377] 
[378]     if (clcf->log_not_found) {
[379]         ngx_log_error(NGX_LOG_ERR, r->connection->log, err,
[380]                       "\"%s\" is not found", file);
[381]     }
[382] 
[383]     return NGX_HTTP_NOT_FOUND;
[384] }
[385] 
[386] 
[387] static void *
[388] ngx_http_index_create_loc_conf(ngx_conf_t *cf)
[389] {
[390]     ngx_http_index_loc_conf_t  *conf;
[391] 
[392]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_index_loc_conf_t));
[393]     if (conf == NULL) {
[394]         return NULL;
[395]     }
[396] 
[397]     conf->indices = NULL;
[398]     conf->max_index_len = 0;
[399] 
[400]     return conf;
[401] }
[402] 
[403] 
[404] static char *
[405] ngx_http_index_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[406] {
[407]     ngx_http_index_loc_conf_t  *prev = parent;
[408]     ngx_http_index_loc_conf_t  *conf = child;
[409] 
[410]     ngx_http_index_t  *index;
[411] 
[412]     if (conf->indices == NULL) {
[413]         conf->indices = prev->indices;
[414]         conf->max_index_len = prev->max_index_len;
[415]     }
[416] 
[417]     if (conf->indices == NULL) {
[418]         conf->indices = ngx_array_create(cf->pool, 1, sizeof(ngx_http_index_t));
[419]         if (conf->indices == NULL) {
[420]             return NGX_CONF_ERROR;
[421]         }
[422] 
[423]         index = ngx_array_push(conf->indices);
[424]         if (index == NULL) {
[425]             return NGX_CONF_ERROR;
[426]         }
[427] 
[428]         index->name.len = sizeof(NGX_HTTP_DEFAULT_INDEX);
[429]         index->name.data = (u_char *) NGX_HTTP_DEFAULT_INDEX;
[430]         index->lengths = NULL;
[431]         index->values = NULL;
[432] 
[433]         conf->max_index_len = sizeof(NGX_HTTP_DEFAULT_INDEX);
[434] 
[435]         return NGX_CONF_OK;
[436]     }
[437] 
[438]     return NGX_CONF_OK;
[439] }
[440] 
[441] 
[442] static ngx_int_t
[443] ngx_http_index_init(ngx_conf_t *cf)
[444] {
[445]     ngx_http_handler_pt        *h;
[446]     ngx_http_core_main_conf_t  *cmcf;
[447] 
[448]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[449] 
[450]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
[451]     if (h == NULL) {
[452]         return NGX_ERROR;
[453]     }
[454] 
[455]     *h = ngx_http_index_handler;
[456] 
[457]     return NGX_OK;
[458] }
[459] 
[460] 
[461] /* TODO: warn about duplicate indices */
[462] 
[463] static char *
[464] ngx_http_index_set_index(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[465] {
[466]     ngx_http_index_loc_conf_t *ilcf = conf;
[467] 
[468]     ngx_str_t                  *value;
[469]     ngx_uint_t                  i, n;
[470]     ngx_http_index_t           *index;
[471]     ngx_http_script_compile_t   sc;
[472] 
[473]     if (ilcf->indices == NULL) {
[474]         ilcf->indices = ngx_array_create(cf->pool, 2, sizeof(ngx_http_index_t));
[475]         if (ilcf->indices == NULL) {
[476]             return NGX_CONF_ERROR;
[477]         }
[478]     }
[479] 
[480]     value = cf->args->elts;
[481] 
[482]     for (i = 1; i < cf->args->nelts; i++) {
[483] 
[484]         if (value[i].data[0] == '/' && i != cf->args->nelts - 1) {
[485]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[486]                                "only the last index in \"index\" directive "
[487]                                "should be absolute");
[488]         }
[489] 
[490]         if (value[i].len == 0) {
[491]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[492]                                "index \"%V\" in \"index\" directive is invalid",
[493]                                &value[1]);
[494]             return NGX_CONF_ERROR;
[495]         }
[496] 
[497]         index = ngx_array_push(ilcf->indices);
[498]         if (index == NULL) {
[499]             return NGX_CONF_ERROR;
[500]         }
[501] 
[502]         index->name.len = value[i].len;
[503]         index->name.data = value[i].data;
[504]         index->lengths = NULL;
[505]         index->values = NULL;
[506] 
[507]         n = ngx_http_script_variables_count(&value[i]);
[508] 
[509]         if (n == 0) {
[510]             if (ilcf->max_index_len < index->name.len) {
[511]                 ilcf->max_index_len = index->name.len;
[512]             }
[513] 
[514]             if (index->name.data[0] == '/') {
[515]                 continue;
[516]             }
[517] 
[518]             /* include the terminating '\0' to the length to use ngx_memcpy() */
[519]             index->name.len++;
[520] 
[521]             continue;
[522]         }
[523] 
[524]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[525] 
[526]         sc.cf = cf;
[527]         sc.source = &value[i];
[528]         sc.lengths = &index->lengths;
[529]         sc.values = &index->values;
[530]         sc.variables = n;
[531]         sc.complete_lengths = 1;
[532]         sc.complete_values = 1;
[533] 
[534]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[535]             return NGX_CONF_ERROR;
[536]         }
[537]     }
[538] 
[539]     return NGX_CONF_OK;
[540] }
