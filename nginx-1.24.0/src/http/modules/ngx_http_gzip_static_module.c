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
[13] #define NGX_HTTP_GZIP_STATIC_OFF     0
[14] #define NGX_HTTP_GZIP_STATIC_ON      1
[15] #define NGX_HTTP_GZIP_STATIC_ALWAYS  2
[16] 
[17] 
[18] typedef struct {
[19]     ngx_uint_t  enable;
[20] } ngx_http_gzip_static_conf_t;
[21] 
[22] 
[23] static ngx_int_t ngx_http_gzip_static_handler(ngx_http_request_t *r);
[24] static void *ngx_http_gzip_static_create_conf(ngx_conf_t *cf);
[25] static char *ngx_http_gzip_static_merge_conf(ngx_conf_t *cf, void *parent,
[26]     void *child);
[27] static ngx_int_t ngx_http_gzip_static_init(ngx_conf_t *cf);
[28] 
[29] 
[30] static ngx_conf_enum_t  ngx_http_gzip_static[] = {
[31]     { ngx_string("off"), NGX_HTTP_GZIP_STATIC_OFF },
[32]     { ngx_string("on"), NGX_HTTP_GZIP_STATIC_ON },
[33]     { ngx_string("always"), NGX_HTTP_GZIP_STATIC_ALWAYS },
[34]     { ngx_null_string, 0 }
[35] };
[36] 
[37] 
[38] static ngx_command_t  ngx_http_gzip_static_commands[] = {
[39] 
[40]     { ngx_string("gzip_static"),
[41]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[42]       ngx_conf_set_enum_slot,
[43]       NGX_HTTP_LOC_CONF_OFFSET,
[44]       offsetof(ngx_http_gzip_static_conf_t, enable),
[45]       &ngx_http_gzip_static },
[46] 
[47]       ngx_null_command
[48] };
[49] 
[50] 
[51] static ngx_http_module_t  ngx_http_gzip_static_module_ctx = {
[52]     NULL,                                  /* preconfiguration */
[53]     ngx_http_gzip_static_init,             /* postconfiguration */
[54] 
[55]     NULL,                                  /* create main configuration */
[56]     NULL,                                  /* init main configuration */
[57] 
[58]     NULL,                                  /* create server configuration */
[59]     NULL,                                  /* merge server configuration */
[60] 
[61]     ngx_http_gzip_static_create_conf,      /* create location configuration */
[62]     ngx_http_gzip_static_merge_conf        /* merge location configuration */
[63] };
[64] 
[65] 
[66] ngx_module_t  ngx_http_gzip_static_module = {
[67]     NGX_MODULE_V1,
[68]     &ngx_http_gzip_static_module_ctx,      /* module context */
[69]     ngx_http_gzip_static_commands,         /* module directives */
[70]     NGX_HTTP_MODULE,                       /* module type */
[71]     NULL,                                  /* init master */
[72]     NULL,                                  /* init module */
[73]     NULL,                                  /* init process */
[74]     NULL,                                  /* init thread */
[75]     NULL,                                  /* exit thread */
[76]     NULL,                                  /* exit process */
[77]     NULL,                                  /* exit master */
[78]     NGX_MODULE_V1_PADDING
[79] };
[80] 
[81] 
[82] static ngx_int_t
[83] ngx_http_gzip_static_handler(ngx_http_request_t *r)
[84] {
[85]     u_char                       *p;
[86]     size_t                        root;
[87]     ngx_str_t                     path;
[88]     ngx_int_t                     rc;
[89]     ngx_uint_t                    level;
[90]     ngx_log_t                    *log;
[91]     ngx_buf_t                    *b;
[92]     ngx_chain_t                   out;
[93]     ngx_table_elt_t              *h;
[94]     ngx_open_file_info_t          of;
[95]     ngx_http_core_loc_conf_t     *clcf;
[96]     ngx_http_gzip_static_conf_t  *gzcf;
[97] 
[98]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[99]         return NGX_DECLINED;
[100]     }
[101] 
[102]     if (r->uri.data[r->uri.len - 1] == '/') {
[103]         return NGX_DECLINED;
[104]     }
[105] 
[106]     gzcf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_static_module);
[107] 
[108]     if (gzcf->enable == NGX_HTTP_GZIP_STATIC_OFF) {
[109]         return NGX_DECLINED;
[110]     }
[111] 
[112]     if (gzcf->enable == NGX_HTTP_GZIP_STATIC_ON) {
[113]         rc = ngx_http_gzip_ok(r);
[114] 
[115]     } else {
[116]         /* always */
[117]         rc = NGX_OK;
[118]     }
[119] 
[120]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[121] 
[122]     if (!clcf->gzip_vary && rc != NGX_OK) {
[123]         return NGX_DECLINED;
[124]     }
[125] 
[126]     log = r->connection->log;
[127] 
[128]     p = ngx_http_map_uri_to_path(r, &path, &root, sizeof(".gz") - 1);
[129]     if (p == NULL) {
[130]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[131]     }
[132] 
[133]     *p++ = '.';
[134]     *p++ = 'g';
[135]     *p++ = 'z';
[136]     *p = '\0';
[137] 
[138]     path.len = p - path.data;
[139] 
[140]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
[141]                    "http filename: \"%s\"", path.data);
[142] 
[143]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[144] 
[145]     of.read_ahead = clcf->read_ahead;
[146]     of.directio = clcf->directio;
[147]     of.valid = clcf->open_file_cache_valid;
[148]     of.min_uses = clcf->open_file_cache_min_uses;
[149]     of.errors = clcf->open_file_cache_errors;
[150]     of.events = clcf->open_file_cache_events;
[151] 
[152]     if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[153]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[154]     }
[155] 
[156]     if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[157]         != NGX_OK)
[158]     {
[159]         switch (of.err) {
[160] 
[161]         case 0:
[162]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[163] 
[164]         case NGX_ENOENT:
[165]         case NGX_ENOTDIR:
[166]         case NGX_ENAMETOOLONG:
[167] 
[168]             return NGX_DECLINED;
[169] 
[170]         case NGX_EACCES:
[171] #if (NGX_HAVE_OPENAT)
[172]         case NGX_EMLINK:
[173]         case NGX_ELOOP:
[174] #endif
[175] 
[176]             level = NGX_LOG_ERR;
[177]             break;
[178] 
[179]         default:
[180] 
[181]             level = NGX_LOG_CRIT;
[182]             break;
[183]         }
[184] 
[185]         ngx_log_error(level, log, of.err,
[186]                       "%s \"%s\" failed", of.failed, path.data);
[187] 
[188]         return NGX_DECLINED;
[189]     }
[190] 
[191]     if (gzcf->enable == NGX_HTTP_GZIP_STATIC_ON) {
[192]         r->gzip_vary = 1;
[193] 
[194]         if (rc != NGX_OK) {
[195]             return NGX_DECLINED;
[196]         }
[197]     }
[198] 
[199]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);
[200] 
[201]     if (of.is_dir) {
[202]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
[203]         return NGX_DECLINED;
[204]     }
[205] 
[206] #if !(NGX_WIN32) /* the not regular files are probably Unix specific */
[207] 
[208]     if (!of.is_file) {
[209]         ngx_log_error(NGX_LOG_CRIT, log, 0,
[210]                       "\"%s\" is not a regular file", path.data);
[211] 
[212]         return NGX_HTTP_NOT_FOUND;
[213]     }
[214] 
[215] #endif
[216] 
[217]     r->root_tested = !r->error_page;
[218] 
[219]     rc = ngx_http_discard_request_body(r);
[220] 
[221]     if (rc != NGX_OK) {
[222]         return rc;
[223]     }
[224] 
[225]     log->action = "sending response to client";
[226] 
[227]     r->headers_out.status = NGX_HTTP_OK;
[228]     r->headers_out.content_length_n = of.size;
[229]     r->headers_out.last_modified_time = of.mtime;
[230] 
[231]     if (ngx_http_set_etag(r) != NGX_OK) {
[232]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[233]     }
[234] 
[235]     if (ngx_http_set_content_type(r) != NGX_OK) {
[236]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[237]     }
[238] 
[239]     h = ngx_list_push(&r->headers_out.headers);
[240]     if (h == NULL) {
[241]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[242]     }
[243] 
[244]     h->hash = 1;
[245]     h->next = NULL;
[246]     ngx_str_set(&h->key, "Content-Encoding");
[247]     ngx_str_set(&h->value, "gzip");
[248]     r->headers_out.content_encoding = h;
[249] 
[250]     r->allow_ranges = 1;
[251] 
[252]     /* we need to allocate all before the header would be sent */
[253] 
[254]     b = ngx_calloc_buf(r->pool);
[255]     if (b == NULL) {
[256]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[257]     }
[258] 
[259]     b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
[260]     if (b->file == NULL) {
[261]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[262]     }
[263] 
[264]     rc = ngx_http_send_header(r);
[265] 
[266]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[267]         return rc;
[268]     }
[269] 
[270]     b->file_pos = 0;
[271]     b->file_last = of.size;
[272] 
[273]     b->in_file = b->file_last ? 1 : 0;
[274]     b->last_buf = (r == r->main) ? 1 : 0;
[275]     b->last_in_chain = 1;
[276]     b->sync = (b->last_buf || b->in_file) ? 0 : 1;
[277] 
[278]     b->file->fd = of.fd;
[279]     b->file->name = path;
[280]     b->file->log = log;
[281]     b->file->directio = of.is_directio;
[282] 
[283]     out.buf = b;
[284]     out.next = NULL;
[285] 
[286]     return ngx_http_output_filter(r, &out);
[287] }
[288] 
[289] 
[290] static void *
[291] ngx_http_gzip_static_create_conf(ngx_conf_t *cf)
[292] {
[293]     ngx_http_gzip_static_conf_t  *conf;
[294] 
[295]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_gzip_static_conf_t));
[296]     if (conf == NULL) {
[297]         return NULL;
[298]     }
[299] 
[300]     conf->enable = NGX_CONF_UNSET_UINT;
[301] 
[302]     return conf;
[303] }
[304] 
[305] 
[306] static char *
[307] ngx_http_gzip_static_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[308] {
[309]     ngx_http_gzip_static_conf_t *prev = parent;
[310]     ngx_http_gzip_static_conf_t *conf = child;
[311] 
[312]     ngx_conf_merge_uint_value(conf->enable, prev->enable,
[313]                               NGX_HTTP_GZIP_STATIC_OFF);
[314] 
[315]     return NGX_CONF_OK;
[316] }
[317] 
[318] 
[319] static ngx_int_t
[320] ngx_http_gzip_static_init(ngx_conf_t *cf)
[321] {
[322]     ngx_http_handler_pt        *h;
[323]     ngx_http_core_main_conf_t  *cmcf;
[324] 
[325]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[326] 
[327]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
[328]     if (h == NULL) {
[329]         return NGX_ERROR;
[330]     }
[331] 
[332]     *h = ngx_http_gzip_static_handler;
[333] 
[334]     return NGX_OK;
[335] }
