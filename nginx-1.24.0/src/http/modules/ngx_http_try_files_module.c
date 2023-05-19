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
[14]     ngx_array_t           *lengths;
[15]     ngx_array_t           *values;
[16]     ngx_str_t              name;
[17] 
[18]     unsigned               code:10;
[19]     unsigned               test_dir:1;
[20] } ngx_http_try_file_t;
[21] 
[22] 
[23] typedef struct {
[24]     ngx_http_try_file_t   *try_files;
[25] } ngx_http_try_files_loc_conf_t;
[26] 
[27] 
[28] static ngx_int_t ngx_http_try_files_handler(ngx_http_request_t *r);
[29] static char *ngx_http_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[30] static void *ngx_http_try_files_create_loc_conf(ngx_conf_t *cf);
[31] static ngx_int_t ngx_http_try_files_init(ngx_conf_t *cf);
[32] 
[33] 
[34] static ngx_command_t  ngx_http_try_files_commands[] = {
[35] 
[36]     { ngx_string("try_files"),
[37]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
[38]       ngx_http_try_files,
[39]       NGX_HTTP_LOC_CONF_OFFSET,
[40]       0,
[41]       NULL },
[42] 
[43]       ngx_null_command
[44] };
[45] 
[46] 
[47] static ngx_http_module_t  ngx_http_try_files_module_ctx = {
[48]     NULL,                                  /* preconfiguration */
[49]     ngx_http_try_files_init,               /* postconfiguration */
[50] 
[51]     NULL,                                  /* create main configuration */
[52]     NULL,                                  /* init main configuration */
[53] 
[54]     NULL,                                  /* create server configuration */
[55]     NULL,                                  /* merge server configuration */
[56] 
[57]     ngx_http_try_files_create_loc_conf,    /* create location configuration */
[58]     NULL                                   /* merge location configuration */
[59] };
[60] 
[61] 
[62] ngx_module_t  ngx_http_try_files_module = {
[63]     NGX_MODULE_V1,
[64]     &ngx_http_try_files_module_ctx,        /* module context */
[65]     ngx_http_try_files_commands,           /* module directives */
[66]     NGX_HTTP_MODULE,                       /* module type */
[67]     NULL,                                  /* init master */
[68]     NULL,                                  /* init module */
[69]     NULL,                                  /* init process */
[70]     NULL,                                  /* init thread */
[71]     NULL,                                  /* exit thread */
[72]     NULL,                                  /* exit process */
[73]     NULL,                                  /* exit master */
[74]     NGX_MODULE_V1_PADDING
[75] };
[76] 
[77] 
[78] static ngx_int_t
[79] ngx_http_try_files_handler(ngx_http_request_t *r)
[80] {
[81]     size_t                          len, root, alias, reserve, allocated;
[82]     u_char                         *p, *name;
[83]     ngx_str_t                       path, args;
[84]     ngx_uint_t                      test_dir;
[85]     ngx_http_try_file_t            *tf;
[86]     ngx_open_file_info_t            of;
[87]     ngx_http_script_code_pt         code;
[88]     ngx_http_script_engine_t        e;
[89]     ngx_http_core_loc_conf_t       *clcf;
[90]     ngx_http_script_len_code_pt     lcode;
[91]     ngx_http_try_files_loc_conf_t  *tlcf;
[92] 
[93]     tlcf = ngx_http_get_module_loc_conf(r, ngx_http_try_files_module);
[94] 
[95]     if (tlcf->try_files == NULL) {
[96]         return NGX_DECLINED;
[97]     }
[98] 
[99]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[100]                    "try files handler");
[101] 
[102]     allocated = 0;
[103]     root = 0;
[104]     name = NULL;
[105]     /* suppress MSVC warning */
[106]     path.data = NULL;
[107] 
[108]     tf = tlcf->try_files;
[109] 
[110]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[111] 
[112]     alias = clcf->alias;
[113] 
[114]     for ( ;; ) {
[115] 
[116]         if (tf->lengths) {
[117]             ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[118] 
[119]             e.ip = tf->lengths->elts;
[120]             e.request = r;
[121] 
[122]             /* 1 is for terminating '\0' as in static names */
[123]             len = 1;
[124] 
[125]             while (*(uintptr_t *) e.ip) {
[126]                 lcode = *(ngx_http_script_len_code_pt *) e.ip;
[127]                 len += lcode(&e);
[128]             }
[129] 
[130]         } else {
[131]             len = tf->name.len;
[132]         }
[133] 
[134]         if (!alias) {
[135]             reserve = len > r->uri.len ? len - r->uri.len : 0;
[136] 
[137]         } else if (alias == NGX_MAX_SIZE_T_VALUE) {
[138]             reserve = len;
[139] 
[140]         } else {
[141]             reserve = len > r->uri.len - alias ? len - (r->uri.len - alias) : 0;
[142]         }
[143] 
[144]         if (reserve > allocated || !allocated) {
[145] 
[146]             /* 16 bytes are preallocation */
[147]             allocated = reserve + 16;
[148] 
[149]             if (ngx_http_map_uri_to_path(r, &path, &root, allocated) == NULL) {
[150]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[151]             }
[152] 
[153]             name = path.data + root;
[154]         }
[155] 
[156]         if (tf->values == NULL) {
[157] 
[158]             /* tf->name.len includes the terminating '\0' */
[159] 
[160]             ngx_memcpy(name, tf->name.data, tf->name.len);
[161] 
[162]             path.len = (name + tf->name.len - 1) - path.data;
[163] 
[164]         } else {
[165]             e.ip = tf->values->elts;
[166]             e.pos = name;
[167]             e.flushed = 1;
[168] 
[169]             while (*(uintptr_t *) e.ip) {
[170]                 code = *(ngx_http_script_code_pt *) e.ip;
[171]                 code((ngx_http_script_engine_t *) &e);
[172]             }
[173] 
[174]             path.len = e.pos - path.data;
[175] 
[176]             *e.pos = '\0';
[177] 
[178]             if (alias && alias != NGX_MAX_SIZE_T_VALUE
[179]                 && ngx_strncmp(name, r->uri.data, alias) == 0)
[180]             {
[181]                 ngx_memmove(name, name + alias, len - alias);
[182]                 path.len -= alias;
[183]             }
[184]         }
[185] 
[186]         test_dir = tf->test_dir;
[187] 
[188]         tf++;
[189] 
[190]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[191]                        "trying to use %s: \"%s\" \"%s\"",
[192]                        test_dir ? "dir" : "file", name, path.data);
[193] 
[194]         if (tf->lengths == NULL && tf->name.len == 0) {
[195] 
[196]             if (tf->code) {
[197]                 return tf->code;
[198]             }
[199] 
[200]             path.len -= root;
[201]             path.data += root;
[202] 
[203]             if (path.data[0] == '@') {
[204]                 (void) ngx_http_named_location(r, &path);
[205] 
[206]             } else {
[207]                 ngx_http_split_args(r, &path, &args);
[208] 
[209]                 (void) ngx_http_internal_redirect(r, &path, &args);
[210]             }
[211] 
[212]             ngx_http_finalize_request(r, NGX_DONE);
[213]             return NGX_DONE;
[214]         }
[215] 
[216]         ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[217] 
[218]         of.read_ahead = clcf->read_ahead;
[219]         of.directio = clcf->directio;
[220]         of.valid = clcf->open_file_cache_valid;
[221]         of.min_uses = clcf->open_file_cache_min_uses;
[222]         of.test_only = 1;
[223]         of.errors = clcf->open_file_cache_errors;
[224]         of.events = clcf->open_file_cache_events;
[225] 
[226]         if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[227]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[228]         }
[229] 
[230]         if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[231]             != NGX_OK)
[232]         {
[233]             if (of.err == 0) {
[234]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[235]             }
[236] 
[237]             if (of.err != NGX_ENOENT
[238]                 && of.err != NGX_ENOTDIR
[239]                 && of.err != NGX_ENAMETOOLONG)
[240]             {
[241]                 ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
[242]                               "%s \"%s\" failed", of.failed, path.data);
[243]             }
[244] 
[245]             continue;
[246]         }
[247] 
[248]         if (of.is_dir != test_dir) {
[249]             continue;
[250]         }
[251] 
[252]         path.len -= root;
[253]         path.data += root;
[254] 
[255]         if (!alias) {
[256]             r->uri = path;
[257] 
[258]         } else if (alias == NGX_MAX_SIZE_T_VALUE) {
[259]             if (!test_dir) {
[260]                 r->uri = path;
[261]                 r->add_uri_to_alias = 1;
[262]             }
[263] 
[264]         } else {
[265]             name = r->uri.data;
[266] 
[267]             r->uri.len = alias + path.len;
[268]             r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
[269]             if (r->uri.data == NULL) {
[270]                 r->uri.len = 0;
[271]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[272]             }
[273] 
[274]             p = ngx_copy(r->uri.data, name, alias);
[275]             ngx_memcpy(p, path.data, path.len);
[276]         }
[277] 
[278]         ngx_http_set_exten(r);
[279] 
[280]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[281]                        "try file uri: \"%V\"", &r->uri);
[282] 
[283]         return NGX_DECLINED;
[284]     }
[285] 
[286]     /* not reached */
[287] }
[288] 
[289] 
[290] static char *
[291] ngx_http_try_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[292] {
[293]     ngx_http_try_files_loc_conf_t *tlcf = conf;
[294] 
[295]     ngx_str_t                  *value;
[296]     ngx_int_t                   code;
[297]     ngx_uint_t                  i, n;
[298]     ngx_http_try_file_t        *tf;
[299]     ngx_http_script_compile_t   sc;
[300] 
[301]     if (tlcf->try_files) {
[302]         return "is duplicate";
[303]     }
[304] 
[305]     tf = ngx_pcalloc(cf->pool, cf->args->nelts * sizeof(ngx_http_try_file_t));
[306]     if (tf == NULL) {
[307]         return NGX_CONF_ERROR;
[308]     }
[309] 
[310]     tlcf->try_files = tf;
[311] 
[312]     value = cf->args->elts;
[313] 
[314]     for (i = 0; i < cf->args->nelts - 1; i++) {
[315] 
[316]         tf[i].name = value[i + 1];
[317] 
[318]         if (tf[i].name.len > 0
[319]             && tf[i].name.data[tf[i].name.len - 1] == '/'
[320]             && i + 2 < cf->args->nelts)
[321]         {
[322]             tf[i].test_dir = 1;
[323]             tf[i].name.len--;
[324]             tf[i].name.data[tf[i].name.len] = '\0';
[325]         }
[326] 
[327]         n = ngx_http_script_variables_count(&tf[i].name);
[328] 
[329]         if (n) {
[330]             ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[331] 
[332]             sc.cf = cf;
[333]             sc.source = &tf[i].name;
[334]             sc.lengths = &tf[i].lengths;
[335]             sc.values = &tf[i].values;
[336]             sc.variables = n;
[337]             sc.complete_lengths = 1;
[338]             sc.complete_values = 1;
[339] 
[340]             if (ngx_http_script_compile(&sc) != NGX_OK) {
[341]                 return NGX_CONF_ERROR;
[342]             }
[343] 
[344]         } else {
[345]             /* add trailing '\0' to length */
[346]             tf[i].name.len++;
[347]         }
[348]     }
[349] 
[350]     if (tf[i - 1].name.data[0] == '=') {
[351] 
[352]         code = ngx_atoi(tf[i - 1].name.data + 1, tf[i - 1].name.len - 2);
[353] 
[354]         if (code == NGX_ERROR || code > 999) {
[355]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[356]                                "invalid code \"%*s\"",
[357]                                tf[i - 1].name.len - 1, tf[i - 1].name.data);
[358]             return NGX_CONF_ERROR;
[359]         }
[360] 
[361]         tf[i].code = code;
[362]     }
[363] 
[364]     return NGX_CONF_OK;
[365] }
[366] 
[367] 
[368] static void *
[369] ngx_http_try_files_create_loc_conf(ngx_conf_t *cf)
[370] {
[371]     ngx_http_try_files_loc_conf_t  *tlcf;
[372] 
[373]     tlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_try_files_loc_conf_t));
[374]     if (tlcf == NULL) {
[375]         return NULL;
[376]     }
[377] 
[378]     /*
[379]      * set by ngx_pcalloc():
[380]      *
[381]      *     tlcf->try_files = NULL;
[382]      */
[383] 
[384]     return tlcf;
[385] }
[386] 
[387] 
[388] static ngx_int_t
[389] ngx_http_try_files_init(ngx_conf_t *cf)
[390] {
[391]     ngx_http_handler_pt        *h;
[392]     ngx_http_core_main_conf_t  *cmcf;
[393] 
[394]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[395] 
[396]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
[397]     if (h == NULL) {
[398]         return NGX_ERROR;
[399]     }
[400] 
[401]     *h = ngx_http_try_files_handler;
[402] 
[403]     return NGX_OK;
[404] }
