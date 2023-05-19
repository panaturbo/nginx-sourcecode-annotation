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
[14]     ngx_flag_t  enable;
[15] } ngx_http_random_index_loc_conf_t;
[16] 
[17] 
[18] #define NGX_HTTP_RANDOM_INDEX_PREALLOCATE  50
[19] 
[20] 
[21] static ngx_int_t ngx_http_random_index_error(ngx_http_request_t *r,
[22]     ngx_dir_t *dir, ngx_str_t *name);
[23] static ngx_int_t ngx_http_random_index_init(ngx_conf_t *cf);
[24] static void *ngx_http_random_index_create_loc_conf(ngx_conf_t *cf);
[25] static char *ngx_http_random_index_merge_loc_conf(ngx_conf_t *cf,
[26]     void *parent, void *child);
[27] 
[28] 
[29] static ngx_command_t  ngx_http_random_index_commands[] = {
[30] 
[31]     { ngx_string("random_index"),
[32]       NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[33]       ngx_conf_set_flag_slot,
[34]       NGX_HTTP_LOC_CONF_OFFSET,
[35]       offsetof(ngx_http_random_index_loc_conf_t, enable),
[36]       NULL },
[37] 
[38]       ngx_null_command
[39] };
[40] 
[41] 
[42] static ngx_http_module_t  ngx_http_random_index_module_ctx = {
[43]     NULL,                                  /* preconfiguration */
[44]     ngx_http_random_index_init,            /* postconfiguration */
[45] 
[46]     NULL,                                  /* create main configuration */
[47]     NULL,                                  /* init main configuration */
[48] 
[49]     NULL,                                  /* create server configuration */
[50]     NULL,                                  /* merge server configuration */
[51] 
[52]     ngx_http_random_index_create_loc_conf, /* create location configuration */
[53]     ngx_http_random_index_merge_loc_conf   /* merge location configuration */
[54] };
[55] 
[56] 
[57] ngx_module_t  ngx_http_random_index_module = {
[58]     NGX_MODULE_V1,
[59]     &ngx_http_random_index_module_ctx,     /* module context */
[60]     ngx_http_random_index_commands,        /* module directives */
[61]     NGX_HTTP_MODULE,                       /* module type */
[62]     NULL,                                  /* init master */
[63]     NULL,                                  /* init module */
[64]     NULL,                                  /* init process */
[65]     NULL,                                  /* init thread */
[66]     NULL,                                  /* exit thread */
[67]     NULL,                                  /* exit process */
[68]     NULL,                                  /* exit master */
[69]     NGX_MODULE_V1_PADDING
[70] };
[71] 
[72] 
[73] static ngx_int_t
[74] ngx_http_random_index_handler(ngx_http_request_t *r)
[75] {
[76]     u_char                            *last, *filename;
[77]     size_t                             len, allocated, root;
[78]     ngx_err_t                          err;
[79]     ngx_int_t                          rc;
[80]     ngx_str_t                          path, uri, *name;
[81]     ngx_dir_t                          dir;
[82]     ngx_uint_t                         n, level;
[83]     ngx_array_t                        names;
[84]     ngx_http_random_index_loc_conf_t  *rlcf;
[85] 
[86]     if (r->uri.data[r->uri.len - 1] != '/') {
[87]         return NGX_DECLINED;
[88]     }
[89] 
[90]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
[91]         return NGX_DECLINED;
[92]     }
[93] 
[94]     rlcf = ngx_http_get_module_loc_conf(r, ngx_http_random_index_module);
[95] 
[96]     if (!rlcf->enable) {
[97]         return NGX_DECLINED;
[98]     }
[99] 
[100] #if (NGX_HAVE_D_TYPE)
[101]     len = 0;
[102] #else
[103]     len = NGX_HTTP_RANDOM_INDEX_PREALLOCATE;
[104] #endif
[105] 
[106]     last = ngx_http_map_uri_to_path(r, &path, &root, len);
[107]     if (last == NULL) {
[108]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[109]     }
[110] 
[111]     allocated = path.len;
[112] 
[113]     path.len = last - path.data - 1;
[114]     path.data[path.len] = '\0';
[115] 
[116]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[117]                    "http random index: \"%s\"", path.data);
[118] 
[119]     if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
[120]         err = ngx_errno;
[121] 
[122]         if (err == NGX_ENOENT
[123]             || err == NGX_ENOTDIR
[124]             || err == NGX_ENAMETOOLONG)
[125]         {
[126]             level = NGX_LOG_ERR;
[127]             rc = NGX_HTTP_NOT_FOUND;
[128] 
[129]         } else if (err == NGX_EACCES) {
[130]             level = NGX_LOG_ERR;
[131]             rc = NGX_HTTP_FORBIDDEN;
[132] 
[133]         } else {
[134]             level = NGX_LOG_CRIT;
[135]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[136]         }
[137] 
[138]         ngx_log_error(level, r->connection->log, err,
[139]                       ngx_open_dir_n " \"%s\" failed", path.data);
[140] 
[141]         return rc;
[142]     }
[143] 
[144]     if (ngx_array_init(&names, r->pool, 32, sizeof(ngx_str_t)) != NGX_OK) {
[145]         return ngx_http_random_index_error(r, &dir, &path);
[146]     }
[147] 
[148]     filename = path.data;
[149]     filename[path.len] = '/';
[150] 
[151]     for ( ;; ) {
[152]         ngx_set_errno(0);
[153] 
[154]         if (ngx_read_dir(&dir) == NGX_ERROR) {
[155]             err = ngx_errno;
[156] 
[157]             if (err != NGX_ENOMOREFILES) {
[158]                 ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
[159]                               ngx_read_dir_n " \"%V\" failed", &path);
[160]                 return ngx_http_random_index_error(r, &dir, &path);
[161]             }
[162] 
[163]             break;
[164]         }
[165] 
[166]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[167]                        "http random index file: \"%s\"", ngx_de_name(&dir));
[168] 
[169]         if (ngx_de_name(&dir)[0] == '.') {
[170]             continue;
[171]         }
[172] 
[173]         len = ngx_de_namelen(&dir);
[174] 
[175]         if (dir.type == 0 || ngx_de_is_link(&dir)) {
[176] 
[177]             /* 1 byte for '/' and 1 byte for terminating '\0' */
[178] 
[179]             if (path.len + 1 + len + 1 > allocated) {
[180]                 allocated = path.len + 1 + len + 1
[181]                                      + NGX_HTTP_RANDOM_INDEX_PREALLOCATE;
[182] 
[183]                 filename = ngx_pnalloc(r->pool, allocated);
[184]                 if (filename == NULL) {
[185]                     return ngx_http_random_index_error(r, &dir, &path);
[186]                 }
[187] 
[188]                 last = ngx_cpystrn(filename, path.data, path.len + 1);
[189]                 *last++ = '/';
[190]             }
[191] 
[192]             ngx_cpystrn(last, ngx_de_name(&dir), len + 1);
[193] 
[194]             if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
[195]                 err = ngx_errno;
[196] 
[197]                 if (err != NGX_ENOENT) {
[198]                     ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
[199]                                   ngx_de_info_n " \"%s\" failed", filename);
[200]                     return ngx_http_random_index_error(r, &dir, &path);
[201]                 }
[202] 
[203]                 if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
[204]                     ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[205]                                   ngx_de_link_info_n " \"%s\" failed",
[206]                                   filename);
[207]                     return ngx_http_random_index_error(r, &dir, &path);
[208]                 }
[209]             }
[210]         }
[211] 
[212]         if (!ngx_de_is_file(&dir)) {
[213]             continue;
[214]         }
[215] 
[216]         name = ngx_array_push(&names);
[217]         if (name == NULL) {
[218]             return ngx_http_random_index_error(r, &dir, &path);
[219]         }
[220] 
[221]         name->len = len;
[222] 
[223]         name->data = ngx_pnalloc(r->pool, len);
[224]         if (name->data == NULL) {
[225]             return ngx_http_random_index_error(r, &dir, &path);
[226]         }
[227] 
[228]         ngx_memcpy(name->data, ngx_de_name(&dir), len);
[229]     }
[230] 
[231]     if (ngx_close_dir(&dir) == NGX_ERROR) {
[232]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[233]                       ngx_close_dir_n " \"%V\" failed", &path);
[234]     }
[235] 
[236]     n = names.nelts;
[237] 
[238]     if (n == 0) {
[239]         return NGX_DECLINED;
[240]     }
[241] 
[242]     name = names.elts;
[243] 
[244]     n = (ngx_uint_t) (((uint64_t) ngx_random() * n) / 0x80000000);
[245] 
[246]     uri.len = r->uri.len + name[n].len;
[247] 
[248]     uri.data = ngx_pnalloc(r->pool, uri.len);
[249]     if (uri.data == NULL) {
[250]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[251]     }
[252] 
[253]     last = ngx_copy(uri.data, r->uri.data, r->uri.len);
[254]     ngx_memcpy(last, name[n].data, name[n].len);
[255] 
[256]     return ngx_http_internal_redirect(r, &uri, &r->args);
[257] }
[258] 
[259] 
[260] static ngx_int_t
[261] ngx_http_random_index_error(ngx_http_request_t *r, ngx_dir_t *dir,
[262]     ngx_str_t *name)
[263] {
[264]     if (ngx_close_dir(dir) == NGX_ERROR) {
[265]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[266]                       ngx_close_dir_n " \"%V\" failed", name);
[267]     }
[268] 
[269]     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[270] }
[271] 
[272] 
[273] static void *
[274] ngx_http_random_index_create_loc_conf(ngx_conf_t *cf)
[275] {
[276]     ngx_http_random_index_loc_conf_t  *conf;
[277] 
[278]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_random_index_loc_conf_t));
[279]     if (conf == NULL) {
[280]         return NULL;
[281]     }
[282] 
[283]     conf->enable = NGX_CONF_UNSET;
[284] 
[285]     return conf;
[286] }
[287] 
[288] 
[289] static char *
[290] ngx_http_random_index_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[291] {
[292]     ngx_http_random_index_loc_conf_t *prev = parent;
[293]     ngx_http_random_index_loc_conf_t *conf = child;
[294] 
[295]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[296] 
[297]     return NGX_CONF_OK;
[298] }
[299] 
[300] 
[301] static ngx_int_t
[302] ngx_http_random_index_init(ngx_conf_t *cf)
[303] {
[304]     ngx_http_handler_pt        *h;
[305]     ngx_http_core_main_conf_t  *cmcf;
[306] 
[307]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[308] 
[309]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
[310]     if (h == NULL) {
[311]         return NGX_ERROR;
[312]     }
[313] 
[314]     *h = ngx_http_random_index_handler;
[315] 
[316]     return NGX_OK;
[317] }
