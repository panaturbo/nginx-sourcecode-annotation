[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_http.h>
[10] 
[11] 
[12] static char *ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[13] 
[14] static ngx_command_t  ngx_http_flv_commands[] = {
[15] 
[16]     { ngx_string("flv"),
[17]       NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
[18]       ngx_http_flv,
[19]       0,
[20]       0,
[21]       NULL },
[22] 
[23]       ngx_null_command
[24] };
[25] 
[26] 
[27] static u_char  ngx_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";
[28] 
[29] 
[30] static ngx_http_module_t  ngx_http_flv_module_ctx = {
[31]     NULL,                          /* preconfiguration */
[32]     NULL,                          /* postconfiguration */
[33] 
[34]     NULL,                          /* create main configuration */
[35]     NULL,                          /* init main configuration */
[36] 
[37]     NULL,                          /* create server configuration */
[38]     NULL,                          /* merge server configuration */
[39] 
[40]     NULL,                          /* create location configuration */
[41]     NULL                           /* merge location configuration */
[42] };
[43] 
[44] 
[45] ngx_module_t  ngx_http_flv_module = {
[46]     NGX_MODULE_V1,
[47]     &ngx_http_flv_module_ctx,      /* module context */
[48]     ngx_http_flv_commands,         /* module directives */
[49]     NGX_HTTP_MODULE,               /* module type */
[50]     NULL,                          /* init master */
[51]     NULL,                          /* init module */
[52]     NULL,                          /* init process */
[53]     NULL,                          /* init thread */
[54]     NULL,                          /* exit thread */
[55]     NULL,                          /* exit process */
[56]     NULL,                          /* exit master */
[57]     NGX_MODULE_V1_PADDING
[58] };
[59] 
[60] 
[61] static ngx_int_t
[62] ngx_http_flv_handler(ngx_http_request_t *r)
[63] {
[64]     u_char                    *last;
[65]     off_t                      start, len;
[66]     size_t                     root;
[67]     ngx_int_t                  rc;
[68]     ngx_uint_t                 level, i;
[69]     ngx_str_t                  path, value;
[70]     ngx_log_t                 *log;
[71]     ngx_buf_t                 *b;
[72]     ngx_chain_t                out[2];
[73]     ngx_open_file_info_t       of;
[74]     ngx_http_core_loc_conf_t  *clcf;
[75] 
[76]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[77]         return NGX_HTTP_NOT_ALLOWED;
[78]     }
[79] 
[80]     if (r->uri.data[r->uri.len - 1] == '/') {
[81]         return NGX_DECLINED;
[82]     }
[83] 
[84]     rc = ngx_http_discard_request_body(r);
[85] 
[86]     if (rc != NGX_OK) {
[87]         return rc;
[88]     }
[89] 
[90]     last = ngx_http_map_uri_to_path(r, &path, &root, 0);
[91]     if (last == NULL) {
[92]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[93]     }
[94] 
[95]     log = r->connection->log;
[96] 
[97]     path.len = last - path.data;
[98] 
[99]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
[100]                    "http flv filename: \"%V\"", &path);
[101] 
[102]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[103] 
[104]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[105] 
[106]     of.read_ahead = clcf->read_ahead;
[107]     of.directio = clcf->directio;
[108]     of.valid = clcf->open_file_cache_valid;
[109]     of.min_uses = clcf->open_file_cache_min_uses;
[110]     of.errors = clcf->open_file_cache_errors;
[111]     of.events = clcf->open_file_cache_events;
[112] 
[113]     if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[114]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[115]     }
[116] 
[117]     if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[118]         != NGX_OK)
[119]     {
[120]         switch (of.err) {
[121] 
[122]         case 0:
[123]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[124] 
[125]         case NGX_ENOENT:
[126]         case NGX_ENOTDIR:
[127]         case NGX_ENAMETOOLONG:
[128] 
[129]             level = NGX_LOG_ERR;
[130]             rc = NGX_HTTP_NOT_FOUND;
[131]             break;
[132] 
[133]         case NGX_EACCES:
[134] #if (NGX_HAVE_OPENAT)
[135]         case NGX_EMLINK:
[136]         case NGX_ELOOP:
[137] #endif
[138] 
[139]             level = NGX_LOG_ERR;
[140]             rc = NGX_HTTP_FORBIDDEN;
[141]             break;
[142] 
[143]         default:
[144] 
[145]             level = NGX_LOG_CRIT;
[146]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[147]             break;
[148]         }
[149] 
[150]         if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
[151]             ngx_log_error(level, log, of.err,
[152]                           "%s \"%s\" failed", of.failed, path.data);
[153]         }
[154] 
[155]         return rc;
[156]     }
[157] 
[158]     if (!of.is_file) {
[159]         return NGX_DECLINED;
[160]     }
[161] 
[162]     r->root_tested = !r->error_page;
[163] 
[164]     start = 0;
[165]     len = of.size;
[166]     i = 1;
[167] 
[168]     if (r->args.len) {
[169] 
[170]         if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {
[171] 
[172]             start = ngx_atoof(value.data, value.len);
[173] 
[174]             if (start == NGX_ERROR || start >= len) {
[175]                 start = 0;
[176]             }
[177] 
[178]             if (start) {
[179]                 len = sizeof(ngx_flv_header) - 1 + len - start;
[180]                 i = 0;
[181]             }
[182]         }
[183]     }
[184] 
[185]     log->action = "sending flv to client";
[186] 
[187]     r->headers_out.status = NGX_HTTP_OK;
[188]     r->headers_out.content_length_n = len;
[189]     r->headers_out.last_modified_time = of.mtime;
[190] 
[191]     if (ngx_http_set_etag(r) != NGX_OK) {
[192]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[193]     }
[194] 
[195]     if (ngx_http_set_content_type(r) != NGX_OK) {
[196]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[197]     }
[198] 
[199]     if (i == 0) {
[200]         b = ngx_calloc_buf(r->pool);
[201]         if (b == NULL) {
[202]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[203]         }
[204] 
[205]         b->pos = ngx_flv_header;
[206]         b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
[207]         b->memory = 1;
[208] 
[209]         out[0].buf = b;
[210]         out[0].next = &out[1];
[211]     }
[212] 
[213] 
[214]     b = ngx_calloc_buf(r->pool);
[215]     if (b == NULL) {
[216]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[217]     }
[218] 
[219]     b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
[220]     if (b->file == NULL) {
[221]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[222]     }
[223] 
[224]     r->allow_ranges = 1;
[225] 
[226]     rc = ngx_http_send_header(r);
[227] 
[228]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[229]         return rc;
[230]     }
[231] 
[232]     b->file_pos = start;
[233]     b->file_last = of.size;
[234] 
[235]     b->in_file = b->file_last ? 1 : 0;
[236]     b->last_buf = (r == r->main) ? 1 : 0;
[237]     b->last_in_chain = 1;
[238]     b->sync = (b->last_buf || b->in_file) ? 0 : 1;
[239] 
[240]     b->file->fd = of.fd;
[241]     b->file->name = path;
[242]     b->file->log = log;
[243]     b->file->directio = of.is_directio;
[244] 
[245]     out[1].buf = b;
[246]     out[1].next = NULL;
[247] 
[248]     return ngx_http_output_filter(r, &out[i]);
[249] }
[250] 
[251] 
[252] static char *
[253] ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[254] {
[255]     ngx_http_core_loc_conf_t  *clcf;
[256] 
[257]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[258]     clcf->handler = ngx_http_flv_handler;
[259] 
[260]     return NGX_CONF_OK;
[261] }
