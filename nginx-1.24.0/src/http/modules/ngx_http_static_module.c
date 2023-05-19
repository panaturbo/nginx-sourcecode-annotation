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
[13] static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r);
[14] static ngx_int_t ngx_http_static_init(ngx_conf_t *cf);
[15] 
[16] 
[17] static ngx_http_module_t  ngx_http_static_module_ctx = {
[18]     NULL,                                  /* preconfiguration */
[19]     ngx_http_static_init,                  /* postconfiguration */
[20] 
[21]     NULL,                                  /* create main configuration */
[22]     NULL,                                  /* init main configuration */
[23] 
[24]     NULL,                                  /* create server configuration */
[25]     NULL,                                  /* merge server configuration */
[26] 
[27]     NULL,                                  /* create location configuration */
[28]     NULL                                   /* merge location configuration */
[29] };
[30] 
[31] 
[32] ngx_module_t  ngx_http_static_module = {
[33]     NGX_MODULE_V1,
[34]     &ngx_http_static_module_ctx,           /* module context */
[35]     NULL,                                  /* module directives */
[36]     NGX_HTTP_MODULE,                       /* module type */
[37]     NULL,                                  /* init master */
[38]     NULL,                                  /* init module */
[39]     NULL,                                  /* init process */
[40]     NULL,                                  /* init thread */
[41]     NULL,                                  /* exit thread */
[42]     NULL,                                  /* exit process */
[43]     NULL,                                  /* exit master */
[44]     NGX_MODULE_V1_PADDING
[45] };
[46] 
[47] 
[48] static ngx_int_t
[49] ngx_http_static_handler(ngx_http_request_t *r)
[50] {
[51]     u_char                    *last, *location;
[52]     size_t                     root, len;
[53]     uintptr_t                  escape;
[54]     ngx_str_t                  path;
[55]     ngx_int_t                  rc;
[56]     ngx_uint_t                 level;
[57]     ngx_log_t                 *log;
[58]     ngx_buf_t                 *b;
[59]     ngx_chain_t                out;
[60]     ngx_open_file_info_t       of;
[61]     ngx_http_core_loc_conf_t  *clcf;
[62] 
[63]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
[64]         return NGX_HTTP_NOT_ALLOWED;
[65]     }
[66] 
[67]     if (r->uri.data[r->uri.len - 1] == '/') {
[68]         return NGX_DECLINED;
[69]     }
[70] 
[71]     log = r->connection->log;
[72] 
[73]     /*
[74]      * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
[75]      * so we do not need to reserve memory for '/' for possible redirect
[76]      */
[77] 
[78]     last = ngx_http_map_uri_to_path(r, &path, &root, 0);
[79]     if (last == NULL) {
[80]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[81]     }
[82] 
[83]     path.len = last - path.data;
[84] 
[85]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
[86]                    "http filename: \"%s\"", path.data);
[87] 
[88]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[89] 
[90]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[91] 
[92]     of.read_ahead = clcf->read_ahead;
[93]     of.directio = clcf->directio;
[94]     of.valid = clcf->open_file_cache_valid;
[95]     of.min_uses = clcf->open_file_cache_min_uses;
[96]     of.errors = clcf->open_file_cache_errors;
[97]     of.events = clcf->open_file_cache_events;
[98] 
[99]     if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[100]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[101]     }
[102] 
[103]     if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[104]         != NGX_OK)
[105]     {
[106]         switch (of.err) {
[107] 
[108]         case 0:
[109]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[110] 
[111]         case NGX_ENOENT:
[112]         case NGX_ENOTDIR:
[113]         case NGX_ENAMETOOLONG:
[114] 
[115]             level = NGX_LOG_ERR;
[116]             rc = NGX_HTTP_NOT_FOUND;
[117]             break;
[118] 
[119]         case NGX_EACCES:
[120] #if (NGX_HAVE_OPENAT)
[121]         case NGX_EMLINK:
[122]         case NGX_ELOOP:
[123] #endif
[124] 
[125]             level = NGX_LOG_ERR;
[126]             rc = NGX_HTTP_FORBIDDEN;
[127]             break;
[128] 
[129]         default:
[130] 
[131]             level = NGX_LOG_CRIT;
[132]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[133]             break;
[134]         }
[135] 
[136]         if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
[137]             ngx_log_error(level, log, of.err,
[138]                           "%s \"%s\" failed", of.failed, path.data);
[139]         }
[140] 
[141]         return rc;
[142]     }
[143] 
[144]     r->root_tested = !r->error_page;
[145] 
[146]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);
[147] 
[148]     if (of.is_dir) {
[149] 
[150]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
[151] 
[152]         ngx_http_clear_location(r);
[153] 
[154]         r->headers_out.location = ngx_list_push(&r->headers_out.headers);
[155]         if (r->headers_out.location == NULL) {
[156]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[157]         }
[158] 
[159]         escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
[160]                                     NGX_ESCAPE_URI);
[161] 
[162]         if (!clcf->alias && r->args.len == 0 && escape == 0) {
[163]             len = r->uri.len + 1;
[164]             location = path.data + root;
[165] 
[166]             *last = '/';
[167] 
[168]         } else {
[169]             len = r->uri.len + escape + 1;
[170] 
[171]             if (r->args.len) {
[172]                 len += r->args.len + 1;
[173]             }
[174] 
[175]             location = ngx_pnalloc(r->pool, len);
[176]             if (location == NULL) {
[177]                 ngx_http_clear_location(r);
[178]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[179]             }
[180] 
[181]             if (escape) {
[182]                 last = (u_char *) ngx_escape_uri(location, r->uri.data,
[183]                                                  r->uri.len, NGX_ESCAPE_URI);
[184] 
[185]             } else {
[186]                 last = ngx_copy(location, r->uri.data, r->uri.len);
[187]             }
[188] 
[189]             *last = '/';
[190] 
[191]             if (r->args.len) {
[192]                 *++last = '?';
[193]                 ngx_memcpy(++last, r->args.data, r->args.len);
[194]             }
[195]         }
[196] 
[197]         r->headers_out.location->hash = 1;
[198]         r->headers_out.location->next = NULL;
[199]         ngx_str_set(&r->headers_out.location->key, "Location");
[200]         r->headers_out.location->value.len = len;
[201]         r->headers_out.location->value.data = location;
[202] 
[203]         return NGX_HTTP_MOVED_PERMANENTLY;
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
[217]     if (r->method == NGX_HTTP_POST) {
[218]         return NGX_HTTP_NOT_ALLOWED;
[219]     }
[220] 
[221]     rc = ngx_http_discard_request_body(r);
[222] 
[223]     if (rc != NGX_OK) {
[224]         return rc;
[225]     }
[226] 
[227]     log->action = "sending response to client";
[228] 
[229]     r->headers_out.status = NGX_HTTP_OK;
[230]     r->headers_out.content_length_n = of.size;
[231]     r->headers_out.last_modified_time = of.mtime;
[232] 
[233]     if (ngx_http_set_etag(r) != NGX_OK) {
[234]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[235]     }
[236] 
[237]     if (ngx_http_set_content_type(r) != NGX_OK) {
[238]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[239]     }
[240] 
[241]     r->allow_ranges = 1;
[242] 
[243]     /* we need to allocate all before the header would be sent */
[244] 
[245]     b = ngx_calloc_buf(r->pool);
[246]     if (b == NULL) {
[247]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[248]     }
[249] 
[250]     b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
[251]     if (b->file == NULL) {
[252]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[253]     }
[254] 
[255]     rc = ngx_http_send_header(r);
[256] 
[257]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[258]         return rc;
[259]     }
[260] 
[261]     b->file_pos = 0;
[262]     b->file_last = of.size;
[263] 
[264]     b->in_file = b->file_last ? 1 : 0;
[265]     b->last_buf = (r == r->main) ? 1 : 0;
[266]     b->last_in_chain = 1;
[267]     b->sync = (b->last_buf || b->in_file) ? 0 : 1;
[268] 
[269]     b->file->fd = of.fd;
[270]     b->file->name = path;
[271]     b->file->log = log;
[272]     b->file->directio = of.is_directio;
[273] 
[274]     out.buf = b;
[275]     out.next = NULL;
[276] 
[277]     return ngx_http_output_filter(r, &out);
[278] }
[279] 
[280] 
[281] static ngx_int_t
[282] ngx_http_static_init(ngx_conf_t *cf)
[283] {
[284]     ngx_http_handler_pt        *h;
[285]     ngx_http_core_main_conf_t  *cmcf;
[286] 
[287]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[288] 
[289]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
[290]     if (h == NULL) {
[291]         return NGX_ERROR;
[292]     }
[293] 
[294]     *h = ngx_http_static_handler;
[295] 
[296]     return NGX_OK;
[297] }
