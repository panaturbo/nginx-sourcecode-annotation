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
[13] #if (NGX_HTTP_CACHE)
[14] static ngx_int_t ngx_http_upstream_cache(ngx_http_request_t *r,
[15]     ngx_http_upstream_t *u);
[16] static ngx_int_t ngx_http_upstream_cache_get(ngx_http_request_t *r,
[17]     ngx_http_upstream_t *u, ngx_http_file_cache_t **cache);
[18] static ngx_int_t ngx_http_upstream_cache_send(ngx_http_request_t *r,
[19]     ngx_http_upstream_t *u);
[20] static ngx_int_t ngx_http_upstream_cache_background_update(
[21]     ngx_http_request_t *r, ngx_http_upstream_t *u);
[22] static ngx_int_t ngx_http_upstream_cache_check_range(ngx_http_request_t *r,
[23]     ngx_http_upstream_t *u);
[24] static ngx_int_t ngx_http_upstream_cache_status(ngx_http_request_t *r,
[25]     ngx_http_variable_value_t *v, uintptr_t data);
[26] static ngx_int_t ngx_http_upstream_cache_last_modified(ngx_http_request_t *r,
[27]     ngx_http_variable_value_t *v, uintptr_t data);
[28] static ngx_int_t ngx_http_upstream_cache_etag(ngx_http_request_t *r,
[29]     ngx_http_variable_value_t *v, uintptr_t data);
[30] #endif
[31] 
[32] static void ngx_http_upstream_init_request(ngx_http_request_t *r);
[33] static void ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
[34] static void ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r);
[35] static void ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r);
[36] static void ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
[37]     ngx_event_t *ev);
[38] static void ngx_http_upstream_connect(ngx_http_request_t *r,
[39]     ngx_http_upstream_t *u);
[40] static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r,
[41]     ngx_http_upstream_t *u);
[42] static void ngx_http_upstream_send_request(ngx_http_request_t *r,
[43]     ngx_http_upstream_t *u, ngx_uint_t do_write);
[44] static ngx_int_t ngx_http_upstream_send_request_body(ngx_http_request_t *r,
[45]     ngx_http_upstream_t *u, ngx_uint_t do_write);
[46] static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r,
[47]     ngx_http_upstream_t *u);
[48] static void ngx_http_upstream_read_request_handler(ngx_http_request_t *r);
[49] static void ngx_http_upstream_process_header(ngx_http_request_t *r,
[50]     ngx_http_upstream_t *u);
[51] static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r,
[52]     ngx_http_upstream_t *u);
[53] static ngx_int_t ngx_http_upstream_intercept_errors(ngx_http_request_t *r,
[54]     ngx_http_upstream_t *u);
[55] static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
[56] static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r,
[57]     ngx_http_upstream_t *u);
[58] static ngx_int_t ngx_http_upstream_process_trailers(ngx_http_request_t *r,
[59]     ngx_http_upstream_t *u);
[60] static void ngx_http_upstream_send_response(ngx_http_request_t *r,
[61]     ngx_http_upstream_t *u);
[62] static void ngx_http_upstream_upgrade(ngx_http_request_t *r,
[63]     ngx_http_upstream_t *u);
[64] static void ngx_http_upstream_upgraded_read_downstream(ngx_http_request_t *r);
[65] static void ngx_http_upstream_upgraded_write_downstream(ngx_http_request_t *r);
[66] static void ngx_http_upstream_upgraded_read_upstream(ngx_http_request_t *r,
[67]     ngx_http_upstream_t *u);
[68] static void ngx_http_upstream_upgraded_write_upstream(ngx_http_request_t *r,
[69]     ngx_http_upstream_t *u);
[70] static void ngx_http_upstream_process_upgraded(ngx_http_request_t *r,
[71]     ngx_uint_t from_upstream, ngx_uint_t do_write);
[72] static void
[73]     ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r);
[74] static void
[75]     ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r,
[76]     ngx_http_upstream_t *u);
[77] static void
[78]     ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r,
[79]     ngx_uint_t do_write);
[80] #if (NGX_THREADS)
[81] static ngx_int_t ngx_http_upstream_thread_handler(ngx_thread_task_t *task,
[82]     ngx_file_t *file);
[83] static void ngx_http_upstream_thread_event_handler(ngx_event_t *ev);
[84] #endif
[85] static ngx_int_t ngx_http_upstream_output_filter(void *data,
[86]     ngx_chain_t *chain);
[87] static void ngx_http_upstream_process_downstream(ngx_http_request_t *r);
[88] static void ngx_http_upstream_process_upstream(ngx_http_request_t *r,
[89]     ngx_http_upstream_t *u);
[90] static void ngx_http_upstream_process_request(ngx_http_request_t *r,
[91]     ngx_http_upstream_t *u);
[92] static void ngx_http_upstream_store(ngx_http_request_t *r,
[93]     ngx_http_upstream_t *u);
[94] static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
[95]     ngx_http_upstream_t *u);
[96] static void ngx_http_upstream_next(ngx_http_request_t *r,
[97]     ngx_http_upstream_t *u, ngx_uint_t ft_type);
[98] static void ngx_http_upstream_cleanup(void *data);
[99] static void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
[100]     ngx_http_upstream_t *u, ngx_int_t rc);
[101] 
[102] static ngx_int_t ngx_http_upstream_process_header_line(ngx_http_request_t *r,
[103]     ngx_table_elt_t *h, ngx_uint_t offset);
[104] static ngx_int_t
[105]     ngx_http_upstream_process_multi_header_lines(ngx_http_request_t *r,
[106]     ngx_table_elt_t *h, ngx_uint_t offset);
[107] static ngx_int_t ngx_http_upstream_process_content_length(ngx_http_request_t *r,
[108]     ngx_table_elt_t *h, ngx_uint_t offset);
[109] static ngx_int_t ngx_http_upstream_process_last_modified(ngx_http_request_t *r,
[110]     ngx_table_elt_t *h, ngx_uint_t offset);
[111] static ngx_int_t ngx_http_upstream_process_set_cookie(ngx_http_request_t *r,
[112]     ngx_table_elt_t *h, ngx_uint_t offset);
[113] static ngx_int_t
[114]     ngx_http_upstream_process_cache_control(ngx_http_request_t *r,
[115]     ngx_table_elt_t *h, ngx_uint_t offset);
[116] static ngx_int_t ngx_http_upstream_ignore_header_line(ngx_http_request_t *r,
[117]     ngx_table_elt_t *h, ngx_uint_t offset);
[118] static ngx_int_t ngx_http_upstream_process_expires(ngx_http_request_t *r,
[119]     ngx_table_elt_t *h, ngx_uint_t offset);
[120] static ngx_int_t ngx_http_upstream_process_accel_expires(ngx_http_request_t *r,
[121]     ngx_table_elt_t *h, ngx_uint_t offset);
[122] static ngx_int_t ngx_http_upstream_process_limit_rate(ngx_http_request_t *r,
[123]     ngx_table_elt_t *h, ngx_uint_t offset);
[124] static ngx_int_t ngx_http_upstream_process_buffering(ngx_http_request_t *r,
[125]     ngx_table_elt_t *h, ngx_uint_t offset);
[126] static ngx_int_t ngx_http_upstream_process_charset(ngx_http_request_t *r,
[127]     ngx_table_elt_t *h, ngx_uint_t offset);
[128] static ngx_int_t ngx_http_upstream_process_connection(ngx_http_request_t *r,
[129]     ngx_table_elt_t *h, ngx_uint_t offset);
[130] static ngx_int_t
[131]     ngx_http_upstream_process_transfer_encoding(ngx_http_request_t *r,
[132]     ngx_table_elt_t *h, ngx_uint_t offset);
[133] static ngx_int_t ngx_http_upstream_process_vary(ngx_http_request_t *r,
[134]     ngx_table_elt_t *h, ngx_uint_t offset);
[135] static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r,
[136]     ngx_table_elt_t *h, ngx_uint_t offset);
[137] static ngx_int_t
[138]     ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r,
[139]     ngx_table_elt_t *h, ngx_uint_t offset);
[140] static ngx_int_t ngx_http_upstream_copy_content_type(ngx_http_request_t *r,
[141]     ngx_table_elt_t *h, ngx_uint_t offset);
[142] static ngx_int_t ngx_http_upstream_copy_last_modified(ngx_http_request_t *r,
[143]     ngx_table_elt_t *h, ngx_uint_t offset);
[144] static ngx_int_t ngx_http_upstream_rewrite_location(ngx_http_request_t *r,
[145]     ngx_table_elt_t *h, ngx_uint_t offset);
[146] static ngx_int_t ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r,
[147]     ngx_table_elt_t *h, ngx_uint_t offset);
[148] static ngx_int_t ngx_http_upstream_rewrite_set_cookie(ngx_http_request_t *r,
[149]     ngx_table_elt_t *h, ngx_uint_t offset);
[150] static ngx_int_t ngx_http_upstream_copy_allow_ranges(ngx_http_request_t *r,
[151]     ngx_table_elt_t *h, ngx_uint_t offset);
[152] 
[153] static ngx_int_t ngx_http_upstream_add_variables(ngx_conf_t *cf);
[154] static ngx_int_t ngx_http_upstream_addr_variable(ngx_http_request_t *r,
[155]     ngx_http_variable_value_t *v, uintptr_t data);
[156] static ngx_int_t ngx_http_upstream_status_variable(ngx_http_request_t *r,
[157]     ngx_http_variable_value_t *v, uintptr_t data);
[158] static ngx_int_t ngx_http_upstream_response_time_variable(ngx_http_request_t *r,
[159]     ngx_http_variable_value_t *v, uintptr_t data);
[160] static ngx_int_t ngx_http_upstream_response_length_variable(
[161]     ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
[162] static ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
[163]     ngx_http_variable_value_t *v, uintptr_t data);
[164] static ngx_int_t ngx_http_upstream_trailer_variable(ngx_http_request_t *r,
[165]     ngx_http_variable_value_t *v, uintptr_t data);
[166] static ngx_int_t ngx_http_upstream_cookie_variable(ngx_http_request_t *r,
[167]     ngx_http_variable_value_t *v, uintptr_t data);
[168] 
[169] static char *ngx_http_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
[170] static char *ngx_http_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
[171]     void *conf);
[172] 
[173] static ngx_int_t ngx_http_upstream_set_local(ngx_http_request_t *r,
[174]   ngx_http_upstream_t *u, ngx_http_upstream_local_t *local);
[175] 
[176] static void *ngx_http_upstream_create_main_conf(ngx_conf_t *cf);
[177] static char *ngx_http_upstream_init_main_conf(ngx_conf_t *cf, void *conf);
[178] 
[179] #if (NGX_HTTP_SSL)
[180] static void ngx_http_upstream_ssl_init_connection(ngx_http_request_t *,
[181]     ngx_http_upstream_t *u, ngx_connection_t *c);
[182] static void ngx_http_upstream_ssl_handshake_handler(ngx_connection_t *c);
[183] static void ngx_http_upstream_ssl_handshake(ngx_http_request_t *,
[184]     ngx_http_upstream_t *u, ngx_connection_t *c);
[185] static void ngx_http_upstream_ssl_save_session(ngx_connection_t *c);
[186] static ngx_int_t ngx_http_upstream_ssl_name(ngx_http_request_t *r,
[187]     ngx_http_upstream_t *u, ngx_connection_t *c);
[188] static ngx_int_t ngx_http_upstream_ssl_certificate(ngx_http_request_t *r,
[189]     ngx_http_upstream_t *u, ngx_connection_t *c);
[190] #endif
[191] 
[192] 
[193] static ngx_http_upstream_header_t  ngx_http_upstream_headers_in[] = {
[194] 
[195]     { ngx_string("Status"),
[196]                  ngx_http_upstream_process_header_line,
[197]                  offsetof(ngx_http_upstream_headers_in_t, status),
[198]                  ngx_http_upstream_copy_header_line, 0, 0 },
[199] 
[200]     { ngx_string("Content-Type"),
[201]                  ngx_http_upstream_process_header_line,
[202]                  offsetof(ngx_http_upstream_headers_in_t, content_type),
[203]                  ngx_http_upstream_copy_content_type, 0, 1 },
[204] 
[205]     { ngx_string("Content-Length"),
[206]                  ngx_http_upstream_process_content_length, 0,
[207]                  ngx_http_upstream_ignore_header_line, 0, 0 },
[208] 
[209]     { ngx_string("Date"),
[210]                  ngx_http_upstream_process_header_line,
[211]                  offsetof(ngx_http_upstream_headers_in_t, date),
[212]                  ngx_http_upstream_copy_header_line,
[213]                  offsetof(ngx_http_headers_out_t, date), 0 },
[214] 
[215]     { ngx_string("Last-Modified"),
[216]                  ngx_http_upstream_process_last_modified, 0,
[217]                  ngx_http_upstream_copy_last_modified, 0, 0 },
[218] 
[219]     { ngx_string("ETag"),
[220]                  ngx_http_upstream_process_header_line,
[221]                  offsetof(ngx_http_upstream_headers_in_t, etag),
[222]                  ngx_http_upstream_copy_header_line,
[223]                  offsetof(ngx_http_headers_out_t, etag), 0 },
[224] 
[225]     { ngx_string("Server"),
[226]                  ngx_http_upstream_process_header_line,
[227]                  offsetof(ngx_http_upstream_headers_in_t, server),
[228]                  ngx_http_upstream_copy_header_line,
[229]                  offsetof(ngx_http_headers_out_t, server), 0 },
[230] 
[231]     { ngx_string("WWW-Authenticate"),
[232]                  ngx_http_upstream_process_multi_header_lines,
[233]                  offsetof(ngx_http_upstream_headers_in_t, www_authenticate),
[234]                  ngx_http_upstream_copy_header_line, 0, 0 },
[235] 
[236]     { ngx_string("Location"),
[237]                  ngx_http_upstream_process_header_line,
[238]                  offsetof(ngx_http_upstream_headers_in_t, location),
[239]                  ngx_http_upstream_rewrite_location, 0, 0 },
[240] 
[241]     { ngx_string("Refresh"),
[242]                  ngx_http_upstream_process_header_line,
[243]                  offsetof(ngx_http_upstream_headers_in_t, refresh),
[244]                  ngx_http_upstream_rewrite_refresh, 0, 0 },
[245] 
[246]     { ngx_string("Set-Cookie"),
[247]                  ngx_http_upstream_process_set_cookie,
[248]                  offsetof(ngx_http_upstream_headers_in_t, set_cookie),
[249]                  ngx_http_upstream_rewrite_set_cookie, 0, 1 },
[250] 
[251]     { ngx_string("Content-Disposition"),
[252]                  ngx_http_upstream_ignore_header_line, 0,
[253]                  ngx_http_upstream_copy_header_line, 0, 1 },
[254] 
[255]     { ngx_string("Cache-Control"),
[256]                  ngx_http_upstream_process_cache_control, 0,
[257]                  ngx_http_upstream_copy_multi_header_lines,
[258]                  offsetof(ngx_http_headers_out_t, cache_control), 1 },
[259] 
[260]     { ngx_string("Expires"),
[261]                  ngx_http_upstream_process_expires, 0,
[262]                  ngx_http_upstream_copy_header_line,
[263]                  offsetof(ngx_http_headers_out_t, expires), 1 },
[264] 
[265]     { ngx_string("Accept-Ranges"),
[266]                  ngx_http_upstream_ignore_header_line, 0,
[267]                  ngx_http_upstream_copy_allow_ranges,
[268]                  offsetof(ngx_http_headers_out_t, accept_ranges), 1 },
[269] 
[270]     { ngx_string("Content-Range"),
[271]                  ngx_http_upstream_ignore_header_line, 0,
[272]                  ngx_http_upstream_copy_header_line,
[273]                  offsetof(ngx_http_headers_out_t, content_range), 0 },
[274] 
[275]     { ngx_string("Connection"),
[276]                  ngx_http_upstream_process_connection, 0,
[277]                  ngx_http_upstream_ignore_header_line, 0, 0 },
[278] 
[279]     { ngx_string("Keep-Alive"),
[280]                  ngx_http_upstream_ignore_header_line, 0,
[281]                  ngx_http_upstream_ignore_header_line, 0, 0 },
[282] 
[283]     { ngx_string("Vary"),
[284]                  ngx_http_upstream_process_vary, 0,
[285]                  ngx_http_upstream_copy_header_line, 0, 0 },
[286] 
[287]     { ngx_string("Link"),
[288]                  ngx_http_upstream_ignore_header_line, 0,
[289]                  ngx_http_upstream_copy_multi_header_lines,
[290]                  offsetof(ngx_http_headers_out_t, link), 0 },
[291] 
[292]     { ngx_string("X-Accel-Expires"),
[293]                  ngx_http_upstream_process_accel_expires, 0,
[294]                  ngx_http_upstream_copy_header_line, 0, 0 },
[295] 
[296]     { ngx_string("X-Accel-Redirect"),
[297]                  ngx_http_upstream_process_header_line,
[298]                  offsetof(ngx_http_upstream_headers_in_t, x_accel_redirect),
[299]                  ngx_http_upstream_copy_header_line, 0, 0 },
[300] 
[301]     { ngx_string("X-Accel-Limit-Rate"),
[302]                  ngx_http_upstream_process_limit_rate, 0,
[303]                  ngx_http_upstream_copy_header_line, 0, 0 },
[304] 
[305]     { ngx_string("X-Accel-Buffering"),
[306]                  ngx_http_upstream_process_buffering, 0,
[307]                  ngx_http_upstream_copy_header_line, 0, 0 },
[308] 
[309]     { ngx_string("X-Accel-Charset"),
[310]                  ngx_http_upstream_process_charset, 0,
[311]                  ngx_http_upstream_copy_header_line, 0, 0 },
[312] 
[313]     { ngx_string("Transfer-Encoding"),
[314]                  ngx_http_upstream_process_transfer_encoding, 0,
[315]                  ngx_http_upstream_ignore_header_line, 0, 0 },
[316] 
[317]     { ngx_string("Content-Encoding"),
[318]                  ngx_http_upstream_ignore_header_line, 0,
[319]                  ngx_http_upstream_copy_header_line,
[320]                  offsetof(ngx_http_headers_out_t, content_encoding), 0 },
[321] 
[322]     { ngx_null_string, NULL, 0, NULL, 0, 0 }
[323] };
[324] 
[325] 
[326] static ngx_command_t  ngx_http_upstream_commands[] = {
[327] 
[328]     { ngx_string("upstream"),
[329]       NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
[330]       ngx_http_upstream,
[331]       0,
[332]       0,
[333]       NULL },
[334] 
[335]     { ngx_string("server"),
[336]       NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
[337]       ngx_http_upstream_server,
[338]       NGX_HTTP_SRV_CONF_OFFSET,
[339]       0,
[340]       NULL },
[341] 
[342]       ngx_null_command
[343] };
[344] 
[345] 
[346] static ngx_http_module_t  ngx_http_upstream_module_ctx = {
[347]     ngx_http_upstream_add_variables,       /* preconfiguration */
[348]     NULL,                                  /* postconfiguration */
[349] 
[350]     ngx_http_upstream_create_main_conf,    /* create main configuration */
[351]     ngx_http_upstream_init_main_conf,      /* init main configuration */
[352] 
[353]     NULL,                                  /* create server configuration */
[354]     NULL,                                  /* merge server configuration */
[355] 
[356]     NULL,                                  /* create location configuration */
[357]     NULL                                   /* merge location configuration */
[358] };
[359] 
[360] 
[361] ngx_module_t  ngx_http_upstream_module = {
[362]     NGX_MODULE_V1,
[363]     &ngx_http_upstream_module_ctx,         /* module context */
[364]     ngx_http_upstream_commands,            /* module directives */
[365]     NGX_HTTP_MODULE,                       /* module type */
[366]     NULL,                                  /* init master */
[367]     NULL,                                  /* init module */
[368]     NULL,                                  /* init process */
[369]     NULL,                                  /* init thread */
[370]     NULL,                                  /* exit thread */
[371]     NULL,                                  /* exit process */
[372]     NULL,                                  /* exit master */
[373]     NGX_MODULE_V1_PADDING
[374] };
[375] 
[376] 
[377] static ngx_http_variable_t  ngx_http_upstream_vars[] = {
[378] 
[379]     { ngx_string("upstream_addr"), NULL,
[380]       ngx_http_upstream_addr_variable, 0,
[381]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[382] 
[383]     { ngx_string("upstream_status"), NULL,
[384]       ngx_http_upstream_status_variable, 0,
[385]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[386] 
[387]     { ngx_string("upstream_connect_time"), NULL,
[388]       ngx_http_upstream_response_time_variable, 2,
[389]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[390] 
[391]     { ngx_string("upstream_header_time"), NULL,
[392]       ngx_http_upstream_response_time_variable, 1,
[393]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[394] 
[395]     { ngx_string("upstream_response_time"), NULL,
[396]       ngx_http_upstream_response_time_variable, 0,
[397]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[398] 
[399]     { ngx_string("upstream_response_length"), NULL,
[400]       ngx_http_upstream_response_length_variable, 0,
[401]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[402] 
[403]     { ngx_string("upstream_bytes_received"), NULL,
[404]       ngx_http_upstream_response_length_variable, 1,
[405]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[406] 
[407]     { ngx_string("upstream_bytes_sent"), NULL,
[408]       ngx_http_upstream_response_length_variable, 2,
[409]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[410] 
[411] #if (NGX_HTTP_CACHE)
[412] 
[413]     { ngx_string("upstream_cache_status"), NULL,
[414]       ngx_http_upstream_cache_status, 0,
[415]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[416] 
[417]     { ngx_string("upstream_cache_last_modified"), NULL,
[418]       ngx_http_upstream_cache_last_modified, 0,
[419]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[420] 
[421]     { ngx_string("upstream_cache_etag"), NULL,
[422]       ngx_http_upstream_cache_etag, 0,
[423]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[424] 
[425] #endif
[426] 
[427]     { ngx_string("upstream_http_"), NULL, ngx_http_upstream_header_variable,
[428]       0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },
[429] 
[430]     { ngx_string("upstream_trailer_"), NULL, ngx_http_upstream_trailer_variable,
[431]       0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },
[432] 
[433]     { ngx_string("upstream_cookie_"), NULL, ngx_http_upstream_cookie_variable,
[434]       0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },
[435] 
[436]       ngx_http_null_variable
[437] };
[438] 
[439] 
[440] static ngx_http_upstream_next_t  ngx_http_upstream_next_errors[] = {
[441]     { 500, NGX_HTTP_UPSTREAM_FT_HTTP_500 },
[442]     { 502, NGX_HTTP_UPSTREAM_FT_HTTP_502 },
[443]     { 503, NGX_HTTP_UPSTREAM_FT_HTTP_503 },
[444]     { 504, NGX_HTTP_UPSTREAM_FT_HTTP_504 },
[445]     { 403, NGX_HTTP_UPSTREAM_FT_HTTP_403 },
[446]     { 404, NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[447]     { 429, NGX_HTTP_UPSTREAM_FT_HTTP_429 },
[448]     { 0, 0 }
[449] };
[450] 
[451] 
[452] ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[] = {
[453]     { ngx_string("GET"), NGX_HTTP_GET },
[454]     { ngx_string("HEAD"), NGX_HTTP_HEAD },
[455]     { ngx_string("POST"), NGX_HTTP_POST },
[456]     { ngx_null_string, 0 }
[457] };
[458] 
[459] 
[460] ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[] = {
[461]     { ngx_string("X-Accel-Redirect"), NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT },
[462]     { ngx_string("X-Accel-Expires"), NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES },
[463]     { ngx_string("X-Accel-Limit-Rate"), NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE },
[464]     { ngx_string("X-Accel-Buffering"), NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING },
[465]     { ngx_string("X-Accel-Charset"), NGX_HTTP_UPSTREAM_IGN_XA_CHARSET },
[466]     { ngx_string("Expires"), NGX_HTTP_UPSTREAM_IGN_EXPIRES },
[467]     { ngx_string("Cache-Control"), NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL },
[468]     { ngx_string("Set-Cookie"), NGX_HTTP_UPSTREAM_IGN_SET_COOKIE },
[469]     { ngx_string("Vary"), NGX_HTTP_UPSTREAM_IGN_VARY },
[470]     { ngx_null_string, 0 }
[471] };
[472] 
[473] 
[474] ngx_int_t
[475] ngx_http_upstream_create(ngx_http_request_t *r)
[476] {
[477]     ngx_http_upstream_t  *u;
[478] 
[479]     u = r->upstream;
[480] 
[481]     if (u && u->cleanup) {
[482]         r->main->count++;
[483]         ngx_http_upstream_cleanup(r);
[484]     }
[485] 
[486]     u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
[487]     if (u == NULL) {
[488]         return NGX_ERROR;
[489]     }
[490] 
[491]     r->upstream = u;
[492] 
[493]     u->peer.log = r->connection->log;
[494]     u->peer.log_error = NGX_ERROR_ERR;
[495] 
[496] #if (NGX_HTTP_CACHE)
[497]     r->cache = NULL;
[498] #endif
[499] 
[500]     u->headers_in.content_length_n = -1;
[501]     u->headers_in.last_modified_time = -1;
[502] 
[503]     return NGX_OK;
[504] }
[505] 
[506] 
[507] void
[508] ngx_http_upstream_init(ngx_http_request_t *r)
[509] {
[510]     ngx_connection_t     *c;
[511] 
[512]     c = r->connection;
[513] 
[514]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[515]                    "http init upstream, client timer: %d", c->read->timer_set);
[516] 
[517] #if (NGX_HTTP_V2)
[518]     if (r->stream) {
[519]         ngx_http_upstream_init_request(r);
[520]         return;
[521]     }
[522] #endif
[523] 
[524]     if (c->read->timer_set) {
[525]         ngx_del_timer(c->read);
[526]     }
[527] 
[528]     if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
[529] 
[530]         if (!c->write->active) {
[531]             if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
[532]                 == NGX_ERROR)
[533]             {
[534]                 ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[535]                 return;
[536]             }
[537]         }
[538]     }
[539] 
[540]     ngx_http_upstream_init_request(r);
[541] }
[542] 
[543] 
[544] static void
[545] ngx_http_upstream_init_request(ngx_http_request_t *r)
[546] {
[547]     ngx_str_t                      *host;
[548]     ngx_uint_t                      i;
[549]     ngx_resolver_ctx_t             *ctx, temp;
[550]     ngx_http_cleanup_t             *cln;
[551]     ngx_http_upstream_t            *u;
[552]     ngx_http_core_loc_conf_t       *clcf;
[553]     ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
[554]     ngx_http_upstream_main_conf_t  *umcf;
[555] 
[556]     if (r->aio) {
[557]         return;
[558]     }
[559] 
[560]     u = r->upstream;
[561] 
[562] #if (NGX_HTTP_CACHE)
[563] 
[564]     if (u->conf->cache) {
[565]         ngx_int_t  rc;
[566] 
[567]         rc = ngx_http_upstream_cache(r, u);
[568] 
[569]         if (rc == NGX_BUSY) {
[570]             r->write_event_handler = ngx_http_upstream_init_request;
[571]             return;
[572]         }
[573] 
[574]         r->write_event_handler = ngx_http_request_empty_handler;
[575] 
[576]         if (rc == NGX_ERROR) {
[577]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[578]             return;
[579]         }
[580] 
[581]         if (rc == NGX_OK) {
[582]             rc = ngx_http_upstream_cache_send(r, u);
[583] 
[584]             if (rc == NGX_DONE) {
[585]                 return;
[586]             }
[587] 
[588]             if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
[589]                 rc = NGX_DECLINED;
[590]                 r->cached = 0;
[591]                 u->buffer.start = NULL;
[592]                 u->cache_status = NGX_HTTP_CACHE_MISS;
[593]                 u->request_sent = 1;
[594]             }
[595]         }
[596] 
[597]         if (rc != NGX_DECLINED) {
[598]             ngx_http_finalize_request(r, rc);
[599]             return;
[600]         }
[601]     }
[602] 
[603] #endif
[604] 
[605]     u->store = u->conf->store;
[606] 
[607]     if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
[608] 
[609]         if (r->connection->read->ready) {
[610]             ngx_post_event(r->connection->read, &ngx_posted_events);
[611] 
[612]         } else {
[613]             if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
[614]                 ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[615]                 return;
[616]             }
[617]         }
[618] 
[619]         r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
[620]         r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
[621]     }
[622] 
[623]     if (r->request_body) {
[624]         u->request_bufs = r->request_body->bufs;
[625]     }
[626] 
[627]     if (u->create_request(r) != NGX_OK) {
[628]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[629]         return;
[630]     }
[631] 
[632]     if (ngx_http_upstream_set_local(r, u, u->conf->local) != NGX_OK) {
[633]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[634]         return;
[635]     }
[636] 
[637]     if (u->conf->socket_keepalive) {
[638]         u->peer.so_keepalive = 1;
[639]     }
[640] 
[641]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[642] 
[643]     u->output.alignment = clcf->directio_alignment;
[644]     u->output.pool = r->pool;
[645]     u->output.bufs.num = 1;
[646]     u->output.bufs.size = clcf->client_body_buffer_size;
[647] 
[648]     if (u->output.output_filter == NULL) {
[649]         u->output.output_filter = ngx_chain_writer;
[650]         u->output.filter_ctx = &u->writer;
[651]     }
[652] 
[653]     u->writer.pool = r->pool;
[654] 
[655]     if (r->upstream_states == NULL) {
[656] 
[657]         r->upstream_states = ngx_array_create(r->pool, 1,
[658]                                             sizeof(ngx_http_upstream_state_t));
[659]         if (r->upstream_states == NULL) {
[660]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[661]             return;
[662]         }
[663] 
[664]     } else {
[665] 
[666]         u->state = ngx_array_push(r->upstream_states);
[667]         if (u->state == NULL) {
[668]             ngx_http_upstream_finalize_request(r, u,
[669]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[670]             return;
[671]         }
[672] 
[673]         ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
[674]     }
[675] 
[676]     cln = ngx_http_cleanup_add(r, 0);
[677]     if (cln == NULL) {
[678]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[679]         return;
[680]     }
[681] 
[682]     cln->handler = ngx_http_upstream_cleanup;
[683]     cln->data = r;
[684]     u->cleanup = &cln->handler;
[685] 
[686]     if (u->resolved == NULL) {
[687] 
[688]         uscf = u->conf->upstream;
[689] 
[690]     } else {
[691] 
[692] #if (NGX_HTTP_SSL)
[693]         u->ssl_name = u->resolved->host;
[694] #endif
[695] 
[696]         host = &u->resolved->host;
[697] 
[698]         umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[699] 
[700]         uscfp = umcf->upstreams.elts;
[701] 
[702]         for (i = 0; i < umcf->upstreams.nelts; i++) {
[703] 
[704]             uscf = uscfp[i];
[705] 
[706]             if (uscf->host.len == host->len
[707]                 && ((uscf->port == 0 && u->resolved->no_port)
[708]                      || uscf->port == u->resolved->port)
[709]                 && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
[710]             {
[711]                 goto found;
[712]             }
[713]         }
[714] 
[715]         if (u->resolved->sockaddr) {
[716] 
[717]             if (u->resolved->port == 0
[718]                 && u->resolved->sockaddr->sa_family != AF_UNIX)
[719]             {
[720]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[721]                               "no port in upstream \"%V\"", host);
[722]                 ngx_http_upstream_finalize_request(r, u,
[723]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[724]                 return;
[725]             }
[726] 
[727]             if (ngx_http_upstream_create_round_robin_peer(r, u->resolved)
[728]                 != NGX_OK)
[729]             {
[730]                 ngx_http_upstream_finalize_request(r, u,
[731]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[732]                 return;
[733]             }
[734] 
[735]             ngx_http_upstream_connect(r, u);
[736] 
[737]             return;
[738]         }
[739] 
[740]         if (u->resolved->port == 0) {
[741]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[742]                           "no port in upstream \"%V\"", host);
[743]             ngx_http_upstream_finalize_request(r, u,
[744]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[745]             return;
[746]         }
[747] 
[748]         temp.name = *host;
[749] 
[750]         ctx = ngx_resolve_start(clcf->resolver, &temp);
[751]         if (ctx == NULL) {
[752]             ngx_http_upstream_finalize_request(r, u,
[753]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[754]             return;
[755]         }
[756] 
[757]         if (ctx == NGX_NO_RESOLVER) {
[758]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[759]                           "no resolver defined to resolve %V", host);
[760] 
[761]             ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
[762]             return;
[763]         }
[764] 
[765]         ctx->name = *host;
[766]         ctx->handler = ngx_http_upstream_resolve_handler;
[767]         ctx->data = r;
[768]         ctx->timeout = clcf->resolver_timeout;
[769] 
[770]         u->resolved->ctx = ctx;
[771] 
[772]         if (ngx_resolve_name(ctx) != NGX_OK) {
[773]             u->resolved->ctx = NULL;
[774]             ngx_http_upstream_finalize_request(r, u,
[775]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[776]             return;
[777]         }
[778] 
[779]         return;
[780]     }
[781] 
[782] found:
[783] 
[784]     if (uscf == NULL) {
[785]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[786]                       "no upstream configuration");
[787]         ngx_http_upstream_finalize_request(r, u,
[788]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[789]         return;
[790]     }
[791] 
[792]     u->upstream = uscf;
[793] 
[794] #if (NGX_HTTP_SSL)
[795]     u->ssl_name = uscf->host;
[796] #endif
[797] 
[798]     if (uscf->peer.init(r, uscf) != NGX_OK) {
[799]         ngx_http_upstream_finalize_request(r, u,
[800]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[801]         return;
[802]     }
[803] 
[804]     u->peer.start_time = ngx_current_msec;
[805] 
[806]     if (u->conf->next_upstream_tries
[807]         && u->peer.tries > u->conf->next_upstream_tries)
[808]     {
[809]         u->peer.tries = u->conf->next_upstream_tries;
[810]     }
[811] 
[812]     ngx_http_upstream_connect(r, u);
[813] }
[814] 
[815] 
[816] #if (NGX_HTTP_CACHE)
[817] 
[818] static ngx_int_t
[819] ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)
[820] {
[821]     ngx_int_t               rc;
[822]     ngx_http_cache_t       *c;
[823]     ngx_http_file_cache_t  *cache;
[824] 
[825]     c = r->cache;
[826] 
[827]     if (c == NULL) {
[828] 
[829]         if (!(r->method & u->conf->cache_methods)) {
[830]             return NGX_DECLINED;
[831]         }
[832] 
[833]         rc = ngx_http_upstream_cache_get(r, u, &cache);
[834] 
[835]         if (rc != NGX_OK) {
[836]             return rc;
[837]         }
[838] 
[839]         if (r->method == NGX_HTTP_HEAD && u->conf->cache_convert_head) {
[840]             u->method = ngx_http_core_get_method;
[841]         }
[842] 
[843]         if (ngx_http_file_cache_new(r) != NGX_OK) {
[844]             return NGX_ERROR;
[845]         }
[846] 
[847]         if (u->create_key(r) != NGX_OK) {
[848]             return NGX_ERROR;
[849]         }
[850] 
[851]         /* TODO: add keys */
[852] 
[853]         ngx_http_file_cache_create_key(r);
[854] 
[855]         if (r->cache->header_start + 256 > u->conf->buffer_size) {
[856]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[857]                           "%V_buffer_size %uz is not enough for cache key, "
[858]                           "it should be increased to at least %uz",
[859]                           &u->conf->module, u->conf->buffer_size,
[860]                           ngx_align(r->cache->header_start + 256, 1024));
[861] 
[862]             r->cache = NULL;
[863]             return NGX_DECLINED;
[864]         }
[865] 
[866]         u->cacheable = 1;
[867] 
[868]         c = r->cache;
[869] 
[870]         c->body_start = u->conf->buffer_size;
[871]         c->min_uses = u->conf->cache_min_uses;
[872]         c->file_cache = cache;
[873] 
[874]         switch (ngx_http_test_predicates(r, u->conf->cache_bypass)) {
[875] 
[876]         case NGX_ERROR:
[877]             return NGX_ERROR;
[878] 
[879]         case NGX_DECLINED:
[880]             u->cache_status = NGX_HTTP_CACHE_BYPASS;
[881]             return NGX_DECLINED;
[882] 
[883]         default: /* NGX_OK */
[884]             break;
[885]         }
[886] 
[887]         c->lock = u->conf->cache_lock;
[888]         c->lock_timeout = u->conf->cache_lock_timeout;
[889]         c->lock_age = u->conf->cache_lock_age;
[890] 
[891]         u->cache_status = NGX_HTTP_CACHE_MISS;
[892]     }
[893] 
[894]     rc = ngx_http_file_cache_open(r);
[895] 
[896]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[897]                    "http upstream cache: %i", rc);
[898] 
[899]     switch (rc) {
[900] 
[901]     case NGX_HTTP_CACHE_STALE:
[902] 
[903]         if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
[904]              || c->stale_updating) && !r->background
[905]             && u->conf->cache_background_update)
[906]         {
[907]             if (ngx_http_upstream_cache_background_update(r, u) == NGX_OK) {
[908]                 r->cache->background = 1;
[909]                 u->cache_status = rc;
[910]                 rc = NGX_OK;
[911] 
[912]             } else {
[913]                 rc = NGX_ERROR;
[914]             }
[915]         }
[916] 
[917]         break;
[918] 
[919]     case NGX_HTTP_CACHE_UPDATING:
[920] 
[921]         if (((u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING)
[922]              || c->stale_updating) && !r->background)
[923]         {
[924]             u->cache_status = rc;
[925]             rc = NGX_OK;
[926] 
[927]         } else {
[928]             rc = NGX_HTTP_CACHE_STALE;
[929]         }
[930] 
[931]         break;
[932] 
[933]     case NGX_OK:
[934]         u->cache_status = NGX_HTTP_CACHE_HIT;
[935]     }
[936] 
[937]     switch (rc) {
[938] 
[939]     case NGX_OK:
[940] 
[941]         return NGX_OK;
[942] 
[943]     case NGX_HTTP_CACHE_STALE:
[944] 
[945]         c->valid_sec = 0;
[946]         c->updating_sec = 0;
[947]         c->error_sec = 0;
[948] 
[949]         u->buffer.start = NULL;
[950]         u->cache_status = NGX_HTTP_CACHE_EXPIRED;
[951] 
[952]         break;
[953] 
[954]     case NGX_DECLINED:
[955] 
[956]         if ((size_t) (u->buffer.end - u->buffer.start) < u->conf->buffer_size) {
[957]             u->buffer.start = NULL;
[958] 
[959]         } else {
[960]             u->buffer.pos = u->buffer.start + c->header_start;
[961]             u->buffer.last = u->buffer.pos;
[962]         }
[963] 
[964]         break;
[965] 
[966]     case NGX_HTTP_CACHE_SCARCE:
[967] 
[968]         u->cacheable = 0;
[969] 
[970]         break;
[971] 
[972]     case NGX_AGAIN:
[973] 
[974]         return NGX_BUSY;
[975] 
[976]     case NGX_ERROR:
[977] 
[978]         return NGX_ERROR;
[979] 
[980]     default:
[981] 
[982]         /* cached NGX_HTTP_BAD_GATEWAY, NGX_HTTP_GATEWAY_TIME_OUT, etc. */
[983] 
[984]         u->cache_status = NGX_HTTP_CACHE_HIT;
[985] 
[986]         return rc;
[987]     }
[988] 
[989]     if (ngx_http_upstream_cache_check_range(r, u) == NGX_DECLINED) {
[990]         u->cacheable = 0;
[991]     }
[992] 
[993]     r->cached = 0;
[994] 
[995]     return NGX_DECLINED;
[996] }
[997] 
[998] 
[999] static ngx_int_t
[1000] ngx_http_upstream_cache_get(ngx_http_request_t *r, ngx_http_upstream_t *u,
[1001]     ngx_http_file_cache_t **cache)
[1002] {
[1003]     ngx_str_t               *name, val;
[1004]     ngx_uint_t               i;
[1005]     ngx_http_file_cache_t  **caches;
[1006] 
[1007]     if (u->conf->cache_zone) {
[1008]         *cache = u->conf->cache_zone->data;
[1009]         return NGX_OK;
[1010]     }
[1011] 
[1012]     if (ngx_http_complex_value(r, u->conf->cache_value, &val) != NGX_OK) {
[1013]         return NGX_ERROR;
[1014]     }
[1015] 
[1016]     if (val.len == 0
[1017]         || (val.len == 3 && ngx_strncmp(val.data, "off", 3) == 0))
[1018]     {
[1019]         return NGX_DECLINED;
[1020]     }
[1021] 
[1022]     caches = u->caches->elts;
[1023] 
[1024]     for (i = 0; i < u->caches->nelts; i++) {
[1025]         name = &caches[i]->shm_zone->shm.name;
[1026] 
[1027]         if (name->len == val.len
[1028]             && ngx_strncmp(name->data, val.data, val.len) == 0)
[1029]         {
[1030]             *cache = caches[i];
[1031]             return NGX_OK;
[1032]         }
[1033]     }
[1034] 
[1035]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1036]                   "cache \"%V\" not found", &val);
[1037] 
[1038]     return NGX_ERROR;
[1039] }
[1040] 
[1041] 
[1042] static ngx_int_t
[1043] ngx_http_upstream_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u)
[1044] {
[1045]     ngx_int_t          rc;
[1046]     ngx_http_cache_t  *c;
[1047] 
[1048]     r->cached = 1;
[1049]     c = r->cache;
[1050] 
[1051]     if (c->header_start == c->body_start) {
[1052]         r->http_version = NGX_HTTP_VERSION_9;
[1053]         return ngx_http_cache_send(r);
[1054]     }
[1055] 
[1056]     /* TODO: cache stack */
[1057] 
[1058]     u->buffer = *c->buf;
[1059]     u->buffer.pos += c->header_start;
[1060] 
[1061]     ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
[1062]     u->headers_in.content_length_n = -1;
[1063]     u->headers_in.last_modified_time = -1;
[1064] 
[1065]     if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
[1066]                       sizeof(ngx_table_elt_t))
[1067]         != NGX_OK)
[1068]     {
[1069]         return NGX_ERROR;
[1070]     }
[1071] 
[1072]     if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
[1073]                       sizeof(ngx_table_elt_t))
[1074]         != NGX_OK)
[1075]     {
[1076]         return NGX_ERROR;
[1077]     }
[1078] 
[1079]     rc = u->process_header(r);
[1080] 
[1081]     if (rc == NGX_OK) {
[1082] 
[1083]         if (ngx_http_upstream_process_headers(r, u) != NGX_OK) {
[1084]             return NGX_DONE;
[1085]         }
[1086] 
[1087]         return ngx_http_cache_send(r);
[1088]     }
[1089] 
[1090]     if (rc == NGX_ERROR) {
[1091]         return NGX_ERROR;
[1092]     }
[1093] 
[1094]     if (rc == NGX_AGAIN) {
[1095]         rc = NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1096]     }
[1097] 
[1098]     /* rc == NGX_HTTP_UPSTREAM_INVALID_HEADER */
[1099] 
[1100]     ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[1101]                   "cache file \"%s\" contains invalid header",
[1102]                   c->file.name.data);
[1103] 
[1104]     /* TODO: delete file */
[1105] 
[1106]     return rc;
[1107] }
[1108] 
[1109] 
[1110] static ngx_int_t
[1111] ngx_http_upstream_cache_background_update(ngx_http_request_t *r,
[1112]     ngx_http_upstream_t *u)
[1113] {
[1114]     ngx_http_request_t  *sr;
[1115] 
[1116]     if (r == r->main) {
[1117]         r->preserve_body = 1;
[1118]     }
[1119] 
[1120]     if (ngx_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
[1121]                             NGX_HTTP_SUBREQUEST_CLONE
[1122]                             |NGX_HTTP_SUBREQUEST_BACKGROUND)
[1123]         != NGX_OK)
[1124]     {
[1125]         return NGX_ERROR;
[1126]     }
[1127] 
[1128]     sr->header_only = 1;
[1129] 
[1130]     return NGX_OK;
[1131] }
[1132] 
[1133] 
[1134] static ngx_int_t
[1135] ngx_http_upstream_cache_check_range(ngx_http_request_t *r,
[1136]     ngx_http_upstream_t *u)
[1137] {
[1138]     off_t             offset;
[1139]     u_char           *p, *start;
[1140]     ngx_table_elt_t  *h;
[1141] 
[1142]     h = r->headers_in.range;
[1143] 
[1144]     if (h == NULL
[1145]         || !u->cacheable
[1146]         || u->conf->cache_max_range_offset == NGX_MAX_OFF_T_VALUE)
[1147]     {
[1148]         return NGX_OK;
[1149]     }
[1150] 
[1151]     if (u->conf->cache_max_range_offset == 0) {
[1152]         return NGX_DECLINED;
[1153]     }
[1154] 
[1155]     if (h->value.len < 7
[1156]         || ngx_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
[1157]     {
[1158]         return NGX_OK;
[1159]     }
[1160] 
[1161]     p = h->value.data + 6;
[1162] 
[1163]     while (*p == ' ') { p++; }
[1164] 
[1165]     if (*p == '-') {
[1166]         return NGX_DECLINED;
[1167]     }
[1168] 
[1169]     start = p;
[1170] 
[1171]     while (*p >= '0' && *p <= '9') { p++; }
[1172] 
[1173]     offset = ngx_atoof(start, p - start);
[1174] 
[1175]     if (offset >= u->conf->cache_max_range_offset) {
[1176]         return NGX_DECLINED;
[1177]     }
[1178] 
[1179]     return NGX_OK;
[1180] }
[1181] 
[1182] #endif
[1183] 
[1184] 
[1185] static void
[1186] ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
[1187] {
[1188]     ngx_uint_t                     run_posted;
[1189]     ngx_connection_t              *c;
[1190]     ngx_http_request_t            *r;
[1191]     ngx_http_upstream_t           *u;
[1192]     ngx_http_upstream_resolved_t  *ur;
[1193] 
[1194]     run_posted = ctx->async;
[1195] 
[1196]     r = ctx->data;
[1197]     c = r->connection;
[1198] 
[1199]     u = r->upstream;
[1200]     ur = u->resolved;
[1201] 
[1202]     ngx_http_set_log_request(c->log, r);
[1203] 
[1204]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1205]                    "http upstream resolve: \"%V?%V\"", &r->uri, &r->args);
[1206] 
[1207]     if (ctx->state) {
[1208]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1209]                       "%V could not be resolved (%i: %s)",
[1210]                       &ctx->name, ctx->state,
[1211]                       ngx_resolver_strerror(ctx->state));
[1212] 
[1213]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
[1214]         goto failed;
[1215]     }
[1216] 
[1217]     ur->naddrs = ctx->naddrs;
[1218]     ur->addrs = ctx->addrs;
[1219] 
[1220] #if (NGX_DEBUG)
[1221]     {
[1222]     u_char      text[NGX_SOCKADDR_STRLEN];
[1223]     ngx_str_t   addr;
[1224]     ngx_uint_t  i;
[1225] 
[1226]     addr.data = text;
[1227] 
[1228]     for (i = 0; i < ctx->naddrs; i++) {
[1229]         addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
[1230]                                  text, NGX_SOCKADDR_STRLEN, 0);
[1231] 
[1232]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1233]                        "name was resolved to %V", &addr);
[1234]     }
[1235]     }
[1236] #endif
[1237] 
[1238]     if (ngx_http_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
[1239]         ngx_http_upstream_finalize_request(r, u,
[1240]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[1241]         goto failed;
[1242]     }
[1243] 
[1244]     ngx_resolve_name_done(ctx);
[1245]     ur->ctx = NULL;
[1246] 
[1247]     u->peer.start_time = ngx_current_msec;
[1248] 
[1249]     if (u->conf->next_upstream_tries
[1250]         && u->peer.tries > u->conf->next_upstream_tries)
[1251]     {
[1252]         u->peer.tries = u->conf->next_upstream_tries;
[1253]     }
[1254] 
[1255]     ngx_http_upstream_connect(r, u);
[1256] 
[1257] failed:
[1258] 
[1259]     if (run_posted) {
[1260]         ngx_http_run_posted_requests(c);
[1261]     }
[1262] }
[1263] 
[1264] 
[1265] static void
[1266] ngx_http_upstream_handler(ngx_event_t *ev)
[1267] {
[1268]     ngx_connection_t     *c;
[1269]     ngx_http_request_t   *r;
[1270]     ngx_http_upstream_t  *u;
[1271] 
[1272]     c = ev->data;
[1273]     r = c->data;
[1274] 
[1275]     u = r->upstream;
[1276]     c = r->connection;
[1277] 
[1278]     ngx_http_set_log_request(c->log, r);
[1279] 
[1280]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1281]                    "http upstream request: \"%V?%V\"", &r->uri, &r->args);
[1282] 
[1283]     if (ev->delayed && ev->timedout) {
[1284]         ev->delayed = 0;
[1285]         ev->timedout = 0;
[1286]     }
[1287] 
[1288]     if (ev->write) {
[1289]         u->write_event_handler(r, u);
[1290] 
[1291]     } else {
[1292]         u->read_event_handler(r, u);
[1293]     }
[1294] 
[1295]     ngx_http_run_posted_requests(c);
[1296] }
[1297] 
[1298] 
[1299] static void
[1300] ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r)
[1301] {
[1302]     ngx_http_upstream_check_broken_connection(r, r->connection->read);
[1303] }
[1304] 
[1305] 
[1306] static void
[1307] ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r)
[1308] {
[1309]     ngx_http_upstream_check_broken_connection(r, r->connection->write);
[1310] }
[1311] 
[1312] 
[1313] static void
[1314] ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
[1315]     ngx_event_t *ev)
[1316] {
[1317]     int                  n;
[1318]     char                 buf[1];
[1319]     ngx_err_t            err;
[1320]     ngx_int_t            event;
[1321]     ngx_connection_t     *c;
[1322]     ngx_http_upstream_t  *u;
[1323] 
[1324]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
[1325]                    "http upstream check client, write event:%d, \"%V\"",
[1326]                    ev->write, &r->uri);
[1327] 
[1328]     c = r->connection;
[1329]     u = r->upstream;
[1330] 
[1331]     if (c->error) {
[1332]         if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
[1333] 
[1334]             event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;
[1335] 
[1336]             if (ngx_del_event(ev, event, 0) != NGX_OK) {
[1337]                 ngx_http_upstream_finalize_request(r, u,
[1338]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1339]                 return;
[1340]             }
[1341]         }
[1342] 
[1343]         if (!u->cacheable) {
[1344]             ngx_http_upstream_finalize_request(r, u,
[1345]                                                NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1346]         }
[1347] 
[1348]         return;
[1349]     }
[1350] 
[1351] #if (NGX_HTTP_V2)
[1352]     if (r->stream) {
[1353]         return;
[1354]     }
[1355] #endif
[1356] 
[1357] #if (NGX_HAVE_KQUEUE)
[1358] 
[1359]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[1360] 
[1361]         if (!ev->pending_eof) {
[1362]             return;
[1363]         }
[1364] 
[1365]         ev->eof = 1;
[1366]         c->error = 1;
[1367] 
[1368]         if (ev->kq_errno) {
[1369]             ev->error = 1;
[1370]         }
[1371] 
[1372]         if (!u->cacheable && u->peer.connection) {
[1373]             ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
[1374]                           "kevent() reported that client prematurely closed "
[1375]                           "connection, so upstream connection is closed too");
[1376]             ngx_http_upstream_finalize_request(r, u,
[1377]                                                NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1378]             return;
[1379]         }
[1380] 
[1381]         ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
[1382]                       "kevent() reported that client prematurely closed "
[1383]                       "connection");
[1384] 
[1385]         if (u->peer.connection == NULL) {
[1386]             ngx_http_upstream_finalize_request(r, u,
[1387]                                                NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1388]         }
[1389] 
[1390]         return;
[1391]     }
[1392] 
[1393] #endif
[1394] 
[1395] #if (NGX_HAVE_EPOLLRDHUP)
[1396] 
[1397]     if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
[1398]         socklen_t  len;
[1399] 
[1400]         if (!ev->pending_eof) {
[1401]             return;
[1402]         }
[1403] 
[1404]         ev->eof = 1;
[1405]         c->error = 1;
[1406] 
[1407]         err = 0;
[1408]         len = sizeof(ngx_err_t);
[1409] 
[1410]         /*
[1411]          * BSDs and Linux return 0 and set a pending error in err
[1412]          * Solaris returns -1 and sets errno
[1413]          */
[1414] 
[1415]         if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
[1416]             == -1)
[1417]         {
[1418]             err = ngx_socket_errno;
[1419]         }
[1420] 
[1421]         if (err) {
[1422]             ev->error = 1;
[1423]         }
[1424] 
[1425]         if (!u->cacheable && u->peer.connection) {
[1426]             ngx_log_error(NGX_LOG_INFO, ev->log, err,
[1427]                         "epoll_wait() reported that client prematurely closed "
[1428]                         "connection, so upstream connection is closed too");
[1429]             ngx_http_upstream_finalize_request(r, u,
[1430]                                                NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1431]             return;
[1432]         }
[1433] 
[1434]         ngx_log_error(NGX_LOG_INFO, ev->log, err,
[1435]                       "epoll_wait() reported that client prematurely closed "
[1436]                       "connection");
[1437] 
[1438]         if (u->peer.connection == NULL) {
[1439]             ngx_http_upstream_finalize_request(r, u,
[1440]                                                NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1441]         }
[1442] 
[1443]         return;
[1444]     }
[1445] 
[1446] #endif
[1447] 
[1448]     n = recv(c->fd, buf, 1, MSG_PEEK);
[1449] 
[1450]     err = ngx_socket_errno;
[1451] 
[1452]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, err,
[1453]                    "http upstream recv(): %d", n);
[1454] 
[1455]     if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
[1456]         return;
[1457]     }
[1458] 
[1459]     if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
[1460] 
[1461]         event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;
[1462] 
[1463]         if (ngx_del_event(ev, event, 0) != NGX_OK) {
[1464]             ngx_http_upstream_finalize_request(r, u,
[1465]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1466]             return;
[1467]         }
[1468]     }
[1469] 
[1470]     if (n > 0) {
[1471]         return;
[1472]     }
[1473] 
[1474]     if (n == -1) {
[1475]         if (err == NGX_EAGAIN) {
[1476]             return;
[1477]         }
[1478] 
[1479]         ev->error = 1;
[1480] 
[1481]     } else { /* n == 0 */
[1482]         err = 0;
[1483]     }
[1484] 
[1485]     ev->eof = 1;
[1486]     c->error = 1;
[1487] 
[1488]     if (!u->cacheable && u->peer.connection) {
[1489]         ngx_log_error(NGX_LOG_INFO, ev->log, err,
[1490]                       "client prematurely closed connection, "
[1491]                       "so upstream connection is closed too");
[1492]         ngx_http_upstream_finalize_request(r, u,
[1493]                                            NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1494]         return;
[1495]     }
[1496] 
[1497]     ngx_log_error(NGX_LOG_INFO, ev->log, err,
[1498]                   "client prematurely closed connection");
[1499] 
[1500]     if (u->peer.connection == NULL) {
[1501]         ngx_http_upstream_finalize_request(r, u,
[1502]                                            NGX_HTTP_CLIENT_CLOSED_REQUEST);
[1503]     }
[1504] }
[1505] 
[1506] 
[1507] static void
[1508] ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
[1509] {
[1510]     ngx_int_t                  rc;
[1511]     ngx_connection_t          *c;
[1512]     ngx_http_core_loc_conf_t  *clcf;
[1513] 
[1514]     r->connection->log->action = "connecting to upstream";
[1515] 
[1516]     if (u->state && u->state->response_time == (ngx_msec_t) -1) {
[1517]         u->state->response_time = ngx_current_msec - u->start_time;
[1518]     }
[1519] 
[1520]     u->state = ngx_array_push(r->upstream_states);
[1521]     if (u->state == NULL) {
[1522]         ngx_http_upstream_finalize_request(r, u,
[1523]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[1524]         return;
[1525]     }
[1526] 
[1527]     ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
[1528] 
[1529]     u->start_time = ngx_current_msec;
[1530] 
[1531]     u->state->response_time = (ngx_msec_t) -1;
[1532]     u->state->connect_time = (ngx_msec_t) -1;
[1533]     u->state->header_time = (ngx_msec_t) -1;
[1534] 
[1535]     rc = ngx_event_connect_peer(&u->peer);
[1536] 
[1537]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1538]                    "http upstream connect: %i", rc);
[1539] 
[1540]     if (rc == NGX_ERROR) {
[1541]         ngx_http_upstream_finalize_request(r, u,
[1542]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[1543]         return;
[1544]     }
[1545] 
[1546]     u->state->peer = u->peer.name;
[1547] 
[1548]     if (rc == NGX_BUSY) {
[1549]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
[1550]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
[1551]         return;
[1552]     }
[1553] 
[1554]     if (rc == NGX_DECLINED) {
[1555]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[1556]         return;
[1557]     }
[1558] 
[1559]     /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */
[1560] 
[1561]     c = u->peer.connection;
[1562] 
[1563]     c->requests++;
[1564] 
[1565]     c->data = r;
[1566] 
[1567]     c->write->handler = ngx_http_upstream_handler;
[1568]     c->read->handler = ngx_http_upstream_handler;
[1569] 
[1570]     u->write_event_handler = ngx_http_upstream_send_request_handler;
[1571]     u->read_event_handler = ngx_http_upstream_process_header;
[1572] 
[1573]     c->sendfile &= r->connection->sendfile;
[1574]     u->output.sendfile = c->sendfile;
[1575] 
[1576]     if (r->connection->tcp_nopush == NGX_TCP_NOPUSH_DISABLED) {
[1577]         c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
[1578]     }
[1579] 
[1580]     if (c->pool == NULL) {
[1581] 
[1582]         /* we need separate pool here to be able to cache SSL connections */
[1583] 
[1584]         c->pool = ngx_create_pool(128, r->connection->log);
[1585]         if (c->pool == NULL) {
[1586]             ngx_http_upstream_finalize_request(r, u,
[1587]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1588]             return;
[1589]         }
[1590]     }
[1591] 
[1592]     c->log = r->connection->log;
[1593]     c->pool->log = c->log;
[1594]     c->read->log = c->log;
[1595]     c->write->log = c->log;
[1596] 
[1597]     /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */
[1598] 
[1599]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1600] 
[1601]     u->writer.out = NULL;
[1602]     u->writer.last = &u->writer.out;
[1603]     u->writer.connection = c;
[1604]     u->writer.limit = clcf->sendfile_max_chunk;
[1605] 
[1606]     if (u->request_sent) {
[1607]         if (ngx_http_upstream_reinit(r, u) != NGX_OK) {
[1608]             ngx_http_upstream_finalize_request(r, u,
[1609]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1610]             return;
[1611]         }
[1612]     }
[1613] 
[1614]     if (r->request_body
[1615]         && r->request_body->buf
[1616]         && r->request_body->temp_file
[1617]         && r == r->main)
[1618]     {
[1619]         /*
[1620]          * the r->request_body->buf can be reused for one request only,
[1621]          * the subrequests should allocate their own temporary bufs
[1622]          */
[1623] 
[1624]         u->output.free = ngx_alloc_chain_link(r->pool);
[1625]         if (u->output.free == NULL) {
[1626]             ngx_http_upstream_finalize_request(r, u,
[1627]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1628]             return;
[1629]         }
[1630] 
[1631]         u->output.free->buf = r->request_body->buf;
[1632]         u->output.free->next = NULL;
[1633]         u->output.allocated = 1;
[1634] 
[1635]         r->request_body->buf->pos = r->request_body->buf->start;
[1636]         r->request_body->buf->last = r->request_body->buf->start;
[1637]         r->request_body->buf->tag = u->output.tag;
[1638]     }
[1639] 
[1640]     u->request_sent = 0;
[1641]     u->request_body_sent = 0;
[1642]     u->request_body_blocked = 0;
[1643] 
[1644]     if (rc == NGX_AGAIN) {
[1645]         ngx_add_timer(c->write, u->conf->connect_timeout);
[1646]         return;
[1647]     }
[1648] 
[1649] #if (NGX_HTTP_SSL)
[1650] 
[1651]     if (u->ssl && c->ssl == NULL) {
[1652]         ngx_http_upstream_ssl_init_connection(r, u, c);
[1653]         return;
[1654]     }
[1655] 
[1656] #endif
[1657] 
[1658]     ngx_http_upstream_send_request(r, u, 1);
[1659] }
[1660] 
[1661] 
[1662] #if (NGX_HTTP_SSL)
[1663] 
[1664] static void
[1665] ngx_http_upstream_ssl_init_connection(ngx_http_request_t *r,
[1666]     ngx_http_upstream_t *u, ngx_connection_t *c)
[1667] {
[1668]     ngx_int_t                  rc;
[1669]     ngx_http_core_loc_conf_t  *clcf;
[1670] 
[1671]     if (ngx_http_upstream_test_connect(c) != NGX_OK) {
[1672]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[1673]         return;
[1674]     }
[1675] 
[1676]     if (ngx_ssl_create_connection(u->conf->ssl, c,
[1677]                                   NGX_SSL_BUFFER|NGX_SSL_CLIENT)
[1678]         != NGX_OK)
[1679]     {
[1680]         ngx_http_upstream_finalize_request(r, u,
[1681]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[1682]         return;
[1683]     }
[1684] 
[1685]     if (u->conf->ssl_server_name || u->conf->ssl_verify) {
[1686]         if (ngx_http_upstream_ssl_name(r, u, c) != NGX_OK) {
[1687]             ngx_http_upstream_finalize_request(r, u,
[1688]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1689]             return;
[1690]         }
[1691]     }
[1692] 
[1693]     if (u->conf->ssl_certificate
[1694]         && u->conf->ssl_certificate->value.len
[1695]         && (u->conf->ssl_certificate->lengths
[1696]             || u->conf->ssl_certificate_key->lengths))
[1697]     {
[1698]         if (ngx_http_upstream_ssl_certificate(r, u, c) != NGX_OK) {
[1699]             ngx_http_upstream_finalize_request(r, u,
[1700]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1701]             return;
[1702]         }
[1703]     }
[1704] 
[1705]     if (u->conf->ssl_session_reuse) {
[1706]         c->ssl->save_session = ngx_http_upstream_ssl_save_session;
[1707] 
[1708]         if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
[1709]             ngx_http_upstream_finalize_request(r, u,
[1710]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1711]             return;
[1712]         }
[1713] 
[1714]         /* abbreviated SSL handshake may interact badly with Nagle */
[1715] 
[1716]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1717] 
[1718]         if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[1719]             ngx_http_upstream_finalize_request(r, u,
[1720]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[1721]             return;
[1722]         }
[1723]     }
[1724] 
[1725]     r->connection->log->action = "SSL handshaking to upstream";
[1726] 
[1727]     rc = ngx_ssl_handshake(c);
[1728] 
[1729]     if (rc == NGX_AGAIN) {
[1730] 
[1731]         if (!c->write->timer_set) {
[1732]             ngx_add_timer(c->write, u->conf->connect_timeout);
[1733]         }
[1734] 
[1735]         c->ssl->handler = ngx_http_upstream_ssl_handshake_handler;
[1736]         return;
[1737]     }
[1738] 
[1739]     ngx_http_upstream_ssl_handshake(r, u, c);
[1740] }
[1741] 
[1742] 
[1743] static void
[1744] ngx_http_upstream_ssl_handshake_handler(ngx_connection_t *c)
[1745] {
[1746]     ngx_http_request_t   *r;
[1747]     ngx_http_upstream_t  *u;
[1748] 
[1749]     r = c->data;
[1750] 
[1751]     u = r->upstream;
[1752]     c = r->connection;
[1753] 
[1754]     ngx_http_set_log_request(c->log, r);
[1755] 
[1756]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1757]                    "http upstream ssl handshake: \"%V?%V\"",
[1758]                    &r->uri, &r->args);
[1759] 
[1760]     ngx_http_upstream_ssl_handshake(r, u, u->peer.connection);
[1761] 
[1762]     ngx_http_run_posted_requests(c);
[1763] }
[1764] 
[1765] 
[1766] static void
[1767] ngx_http_upstream_ssl_handshake(ngx_http_request_t *r, ngx_http_upstream_t *u,
[1768]     ngx_connection_t *c)
[1769] {
[1770]     long  rc;
[1771] 
[1772]     if (c->ssl->handshaked) {
[1773] 
[1774]         if (u->conf->ssl_verify) {
[1775]             rc = SSL_get_verify_result(c->ssl->connection);
[1776] 
[1777]             if (rc != X509_V_OK) {
[1778]                 ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1779]                               "upstream SSL certificate verify error: (%l:%s)",
[1780]                               rc, X509_verify_cert_error_string(rc));
[1781]                 goto failed;
[1782]             }
[1783] 
[1784]             if (ngx_ssl_check_host(c, &u->ssl_name) != NGX_OK) {
[1785]                 ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1786]                               "upstream SSL certificate does not match \"%V\"",
[1787]                               &u->ssl_name);
[1788]                 goto failed;
[1789]             }
[1790]         }
[1791] 
[1792]         if (!c->ssl->sendfile) {
[1793]             c->sendfile = 0;
[1794]             u->output.sendfile = 0;
[1795]         }
[1796] 
[1797]         c->write->handler = ngx_http_upstream_handler;
[1798]         c->read->handler = ngx_http_upstream_handler;
[1799] 
[1800]         ngx_http_upstream_send_request(r, u, 1);
[1801] 
[1802]         return;
[1803]     }
[1804] 
[1805]     if (c->write->timedout) {
[1806]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
[1807]         return;
[1808]     }
[1809] 
[1810] failed:
[1811] 
[1812]     ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[1813] }
[1814] 
[1815] 
[1816] static void
[1817] ngx_http_upstream_ssl_save_session(ngx_connection_t *c)
[1818] {
[1819]     ngx_http_request_t   *r;
[1820]     ngx_http_upstream_t  *u;
[1821] 
[1822]     if (c->idle) {
[1823]         return;
[1824]     }
[1825] 
[1826]     r = c->data;
[1827] 
[1828]     u = r->upstream;
[1829]     c = r->connection;
[1830] 
[1831]     ngx_http_set_log_request(c->log, r);
[1832] 
[1833]     u->peer.save_session(&u->peer, u->peer.data);
[1834] }
[1835] 
[1836] 
[1837] static ngx_int_t
[1838] ngx_http_upstream_ssl_name(ngx_http_request_t *r, ngx_http_upstream_t *u,
[1839]     ngx_connection_t *c)
[1840] {
[1841]     u_char     *p, *last;
[1842]     ngx_str_t   name;
[1843] 
[1844]     if (u->conf->ssl_name) {
[1845]         if (ngx_http_complex_value(r, u->conf->ssl_name, &name) != NGX_OK) {
[1846]             return NGX_ERROR;
[1847]         }
[1848] 
[1849]     } else {
[1850]         name = u->ssl_name;
[1851]     }
[1852] 
[1853]     if (name.len == 0) {
[1854]         goto done;
[1855]     }
[1856] 
[1857]     /*
[1858]      * ssl name here may contain port, notably if derived from $proxy_host
[1859]      * or $http_host; we have to strip it
[1860]      */
[1861] 
[1862]     p = name.data;
[1863]     last = name.data + name.len;
[1864] 
[1865]     if (*p == '[') {
[1866]         p = ngx_strlchr(p, last, ']');
[1867] 
[1868]         if (p == NULL) {
[1869]             p = name.data;
[1870]         }
[1871]     }
[1872] 
[1873]     p = ngx_strlchr(p, last, ':');
[1874] 
[1875]     if (p != NULL) {
[1876]         name.len = p - name.data;
[1877]     }
[1878] 
[1879]     if (!u->conf->ssl_server_name) {
[1880]         goto done;
[1881]     }
[1882] 
[1883] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[1884] 
[1885]     /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */
[1886] 
[1887]     if (name.len == 0 || *name.data == '[') {
[1888]         goto done;
[1889]     }
[1890] 
[1891]     if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
[1892]         goto done;
[1893]     }
[1894] 
[1895]     /*
[1896]      * SSL_set_tlsext_host_name() needs a null-terminated string,
[1897]      * hence we explicitly null-terminate name here
[1898]      */
[1899] 
[1900]     p = ngx_pnalloc(r->pool, name.len + 1);
[1901]     if (p == NULL) {
[1902]         return NGX_ERROR;
[1903]     }
[1904] 
[1905]     (void) ngx_cpystrn(p, name.data, name.len + 1);
[1906] 
[1907]     name.data = p;
[1908] 
[1909]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1910]                    "upstream SSL server name: \"%s\"", name.data);
[1911] 
[1912]     if (SSL_set_tlsext_host_name(c->ssl->connection,
[1913]                                  (char *) name.data)
[1914]         == 0)
[1915]     {
[1916]         ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
[1917]                       "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
[1918]         return NGX_ERROR;
[1919]     }
[1920] 
[1921] #endif
[1922] 
[1923] done:
[1924] 
[1925]     u->ssl_name = name;
[1926] 
[1927]     return NGX_OK;
[1928] }
[1929] 
[1930] 
[1931] static ngx_int_t
[1932] ngx_http_upstream_ssl_certificate(ngx_http_request_t *r,
[1933]     ngx_http_upstream_t *u, ngx_connection_t *c)
[1934] {
[1935]     ngx_str_t  cert, key;
[1936] 
[1937]     if (ngx_http_complex_value(r, u->conf->ssl_certificate, &cert)
[1938]         != NGX_OK)
[1939]     {
[1940]         return NGX_ERROR;
[1941]     }
[1942] 
[1943]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1944]                    "http upstream ssl cert: \"%s\"", cert.data);
[1945] 
[1946]     if (*cert.data == '\0') {
[1947]         return NGX_OK;
[1948]     }
[1949] 
[1950]     if (ngx_http_complex_value(r, u->conf->ssl_certificate_key, &key)
[1951]         != NGX_OK)
[1952]     {
[1953]         return NGX_ERROR;
[1954]     }
[1955] 
[1956]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1957]                    "http upstream ssl key: \"%s\"", key.data);
[1958] 
[1959]     if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
[1960]                                        u->conf->ssl_passwords)
[1961]         != NGX_OK)
[1962]     {
[1963]         return NGX_ERROR;
[1964]     }
[1965] 
[1966]     return NGX_OK;
[1967] }
[1968] 
[1969] #endif
[1970] 
[1971] 
[1972] static ngx_int_t
[1973] ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u)
[1974] {
[1975]     off_t         file_pos;
[1976]     ngx_chain_t  *cl;
[1977] 
[1978]     if (u->reinit_request(r) != NGX_OK) {
[1979]         return NGX_ERROR;
[1980]     }
[1981] 
[1982]     u->keepalive = 0;
[1983]     u->upgrade = 0;
[1984]     u->error = 0;
[1985] 
[1986]     ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
[1987]     u->headers_in.content_length_n = -1;
[1988]     u->headers_in.last_modified_time = -1;
[1989] 
[1990]     if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
[1991]                       sizeof(ngx_table_elt_t))
[1992]         != NGX_OK)
[1993]     {
[1994]         return NGX_ERROR;
[1995]     }
[1996] 
[1997]     if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
[1998]                       sizeof(ngx_table_elt_t))
[1999]         != NGX_OK)
[2000]     {
[2001]         return NGX_ERROR;
[2002]     }
[2003] 
[2004]     /* reinit the request chain */
[2005] 
[2006]     file_pos = 0;
[2007] 
[2008]     for (cl = u->request_bufs; cl; cl = cl->next) {
[2009]         cl->buf->pos = cl->buf->start;
[2010] 
[2011]         /* there is at most one file */
[2012] 
[2013]         if (cl->buf->in_file) {
[2014]             cl->buf->file_pos = file_pos;
[2015]             file_pos = cl->buf->file_last;
[2016]         }
[2017]     }
[2018] 
[2019]     /* reinit the subrequest's ngx_output_chain() context */
[2020] 
[2021]     if (r->request_body && r->request_body->temp_file
[2022]         && r != r->main && u->output.buf)
[2023]     {
[2024]         u->output.free = ngx_alloc_chain_link(r->pool);
[2025]         if (u->output.free == NULL) {
[2026]             return NGX_ERROR;
[2027]         }
[2028] 
[2029]         u->output.free->buf = u->output.buf;
[2030]         u->output.free->next = NULL;
[2031] 
[2032]         u->output.buf->pos = u->output.buf->start;
[2033]         u->output.buf->last = u->output.buf->start;
[2034]     }
[2035] 
[2036]     u->output.buf = NULL;
[2037]     u->output.in = NULL;
[2038]     u->output.busy = NULL;
[2039] 
[2040]     /* reinit u->buffer */
[2041] 
[2042]     u->buffer.pos = u->buffer.start;
[2043] 
[2044] #if (NGX_HTTP_CACHE)
[2045] 
[2046]     if (r->cache) {
[2047]         u->buffer.pos += r->cache->header_start;
[2048]     }
[2049] 
[2050] #endif
[2051] 
[2052]     u->buffer.last = u->buffer.pos;
[2053] 
[2054]     return NGX_OK;
[2055] }
[2056] 
[2057] 
[2058] static void
[2059] ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u,
[2060]     ngx_uint_t do_write)
[2061] {
[2062]     ngx_int_t          rc;
[2063]     ngx_connection_t  *c;
[2064] 
[2065]     c = u->peer.connection;
[2066] 
[2067]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2068]                    "http upstream send request");
[2069] 
[2070]     if (u->state->connect_time == (ngx_msec_t) -1) {
[2071]         u->state->connect_time = ngx_current_msec - u->start_time;
[2072]     }
[2073] 
[2074]     if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) {
[2075]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[2076]         return;
[2077]     }
[2078] 
[2079]     c->log->action = "sending request to upstream";
[2080] 
[2081]     rc = ngx_http_upstream_send_request_body(r, u, do_write);
[2082] 
[2083]     if (rc == NGX_ERROR) {
[2084]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[2085]         return;
[2086]     }
[2087] 
[2088]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[2089]         ngx_http_upstream_finalize_request(r, u, rc);
[2090]         return;
[2091]     }
[2092] 
[2093]     if (rc == NGX_AGAIN) {
[2094]         if (!c->write->ready || u->request_body_blocked) {
[2095]             ngx_add_timer(c->write, u->conf->send_timeout);
[2096] 
[2097]         } else if (c->write->timer_set) {
[2098]             ngx_del_timer(c->write);
[2099]         }
[2100] 
[2101]         if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
[2102]             ngx_http_upstream_finalize_request(r, u,
[2103]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2104]             return;
[2105]         }
[2106] 
[2107]         if (c->write->ready && c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
[2108]             if (ngx_tcp_push(c->fd) == -1) {
[2109]                 ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
[2110]                               ngx_tcp_push_n " failed");
[2111]                 ngx_http_upstream_finalize_request(r, u,
[2112]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2113]                 return;
[2114]             }
[2115] 
[2116]             c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
[2117]         }
[2118] 
[2119]         if (c->read->ready) {
[2120]             ngx_post_event(c->read, &ngx_posted_events);
[2121]         }
[2122] 
[2123]         return;
[2124]     }
[2125] 
[2126]     /* rc == NGX_OK */
[2127] 
[2128]     if (c->write->timer_set) {
[2129]         ngx_del_timer(c->write);
[2130]     }
[2131] 
[2132]     if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
[2133]         if (ngx_tcp_push(c->fd) == -1) {
[2134]             ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
[2135]                           ngx_tcp_push_n " failed");
[2136]             ngx_http_upstream_finalize_request(r, u,
[2137]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2138]             return;
[2139]         }
[2140] 
[2141]         c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
[2142]     }
[2143] 
[2144]     if (!u->conf->preserve_output) {
[2145]         u->write_event_handler = ngx_http_upstream_dummy_handler;
[2146]     }
[2147] 
[2148]     if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[2149]         ngx_http_upstream_finalize_request(r, u,
[2150]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[2151]         return;
[2152]     }
[2153] 
[2154]     if (!u->request_body_sent) {
[2155]         u->request_body_sent = 1;
[2156] 
[2157]         if (u->header_sent) {
[2158]             return;
[2159]         }
[2160] 
[2161]         ngx_add_timer(c->read, u->conf->read_timeout);
[2162] 
[2163]         if (c->read->ready) {
[2164]             ngx_http_upstream_process_header(r, u);
[2165]             return;
[2166]         }
[2167]     }
[2168] }
[2169] 
[2170] 
[2171] static ngx_int_t
[2172] ngx_http_upstream_send_request_body(ngx_http_request_t *r,
[2173]     ngx_http_upstream_t *u, ngx_uint_t do_write)
[2174] {
[2175]     ngx_int_t                  rc;
[2176]     ngx_chain_t               *out, *cl, *ln;
[2177]     ngx_connection_t          *c;
[2178]     ngx_http_core_loc_conf_t  *clcf;
[2179] 
[2180]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2181]                    "http upstream send request body");
[2182] 
[2183]     if (!r->request_body_no_buffering) {
[2184] 
[2185]         /* buffered request body */
[2186] 
[2187]         if (!u->request_sent) {
[2188]             u->request_sent = 1;
[2189]             out = u->request_bufs;
[2190] 
[2191]         } else {
[2192]             out = NULL;
[2193]         }
[2194] 
[2195]         rc = ngx_output_chain(&u->output, out);
[2196] 
[2197]         if (rc == NGX_AGAIN) {
[2198]             u->request_body_blocked = 1;
[2199] 
[2200]         } else {
[2201]             u->request_body_blocked = 0;
[2202]         }
[2203] 
[2204]         return rc;
[2205]     }
[2206] 
[2207]     if (!u->request_sent) {
[2208]         u->request_sent = 1;
[2209]         out = u->request_bufs;
[2210] 
[2211]         if (r->request_body->bufs) {
[2212]             for (cl = out; cl->next; cl = cl->next) { /* void */ }
[2213]             cl->next = r->request_body->bufs;
[2214]             r->request_body->bufs = NULL;
[2215]         }
[2216] 
[2217]         c = u->peer.connection;
[2218]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2219] 
[2220]         if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[2221]             return NGX_ERROR;
[2222]         }
[2223] 
[2224]         r->read_event_handler = ngx_http_upstream_read_request_handler;
[2225] 
[2226]     } else {
[2227]         out = NULL;
[2228]     }
[2229] 
[2230]     for ( ;; ) {
[2231] 
[2232]         if (do_write) {
[2233]             rc = ngx_output_chain(&u->output, out);
[2234] 
[2235]             if (rc == NGX_ERROR) {
[2236]                 return NGX_ERROR;
[2237]             }
[2238] 
[2239]             while (out) {
[2240]                 ln = out;
[2241]                 out = out->next;
[2242]                 ngx_free_chain(r->pool, ln);
[2243]             }
[2244] 
[2245]             if (rc == NGX_AGAIN) {
[2246]                 u->request_body_blocked = 1;
[2247] 
[2248]             } else {
[2249]                 u->request_body_blocked = 0;
[2250]             }
[2251] 
[2252]             if (rc == NGX_OK && !r->reading_body) {
[2253]                 break;
[2254]             }
[2255]         }
[2256] 
[2257]         if (r->reading_body) {
[2258]             /* read client request body */
[2259] 
[2260]             rc = ngx_http_read_unbuffered_request_body(r);
[2261] 
[2262]             if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[2263]                 return rc;
[2264]             }
[2265] 
[2266]             out = r->request_body->bufs;
[2267]             r->request_body->bufs = NULL;
[2268]         }
[2269] 
[2270]         /* stop if there is nothing to send */
[2271] 
[2272]         if (out == NULL) {
[2273]             rc = NGX_AGAIN;
[2274]             break;
[2275]         }
[2276] 
[2277]         do_write = 1;
[2278]     }
[2279] 
[2280]     if (!r->reading_body) {
[2281]         if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
[2282]             r->read_event_handler =
[2283]                                   ngx_http_upstream_rd_check_broken_connection;
[2284]         }
[2285]     }
[2286] 
[2287]     return rc;
[2288] }
[2289] 
[2290] 
[2291] static void
[2292] ngx_http_upstream_send_request_handler(ngx_http_request_t *r,
[2293]     ngx_http_upstream_t *u)
[2294] {
[2295]     ngx_connection_t  *c;
[2296] 
[2297]     c = u->peer.connection;
[2298] 
[2299]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2300]                    "http upstream send request handler");
[2301] 
[2302]     if (c->write->timedout) {
[2303]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
[2304]         return;
[2305]     }
[2306] 
[2307] #if (NGX_HTTP_SSL)
[2308] 
[2309]     if (u->ssl && c->ssl == NULL) {
[2310]         ngx_http_upstream_ssl_init_connection(r, u, c);
[2311]         return;
[2312]     }
[2313] 
[2314] #endif
[2315] 
[2316]     if (u->header_sent && !u->conf->preserve_output) {
[2317]         u->write_event_handler = ngx_http_upstream_dummy_handler;
[2318] 
[2319]         (void) ngx_handle_write_event(c->write, 0);
[2320] 
[2321]         return;
[2322]     }
[2323] 
[2324]     ngx_http_upstream_send_request(r, u, 1);
[2325] }
[2326] 
[2327] 
[2328] static void
[2329] ngx_http_upstream_read_request_handler(ngx_http_request_t *r)
[2330] {
[2331]     ngx_connection_t     *c;
[2332]     ngx_http_upstream_t  *u;
[2333] 
[2334]     c = r->connection;
[2335]     u = r->upstream;
[2336] 
[2337]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2338]                    "http upstream read request handler");
[2339] 
[2340]     if (c->read->timedout) {
[2341]         c->timedout = 1;
[2342]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
[2343]         return;
[2344]     }
[2345] 
[2346]     ngx_http_upstream_send_request(r, u, 0);
[2347] }
[2348] 
[2349] 
[2350] static void
[2351] ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u)
[2352] {
[2353]     ssize_t            n;
[2354]     ngx_int_t          rc;
[2355]     ngx_connection_t  *c;
[2356] 
[2357]     c = u->peer.connection;
[2358] 
[2359]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2360]                    "http upstream process header");
[2361] 
[2362]     c->log->action = "reading response header from upstream";
[2363] 
[2364]     if (c->read->timedout) {
[2365]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
[2366]         return;
[2367]     }
[2368] 
[2369]     if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) {
[2370]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[2371]         return;
[2372]     }
[2373] 
[2374]     if (u->buffer.start == NULL) {
[2375]         u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
[2376]         if (u->buffer.start == NULL) {
[2377]             ngx_http_upstream_finalize_request(r, u,
[2378]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2379]             return;
[2380]         }
[2381] 
[2382]         u->buffer.pos = u->buffer.start;
[2383]         u->buffer.last = u->buffer.start;
[2384]         u->buffer.end = u->buffer.start + u->conf->buffer_size;
[2385]         u->buffer.temporary = 1;
[2386] 
[2387]         u->buffer.tag = u->output.tag;
[2388] 
[2389]         if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
[2390]                           sizeof(ngx_table_elt_t))
[2391]             != NGX_OK)
[2392]         {
[2393]             ngx_http_upstream_finalize_request(r, u,
[2394]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2395]             return;
[2396]         }
[2397] 
[2398]         if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
[2399]                           sizeof(ngx_table_elt_t))
[2400]             != NGX_OK)
[2401]         {
[2402]             ngx_http_upstream_finalize_request(r, u,
[2403]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2404]             return;
[2405]         }
[2406] 
[2407] #if (NGX_HTTP_CACHE)
[2408] 
[2409]         if (r->cache) {
[2410]             u->buffer.pos += r->cache->header_start;
[2411]             u->buffer.last = u->buffer.pos;
[2412]         }
[2413] #endif
[2414]     }
[2415] 
[2416]     for ( ;; ) {
[2417] 
[2418]         n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);
[2419] 
[2420]         if (n == NGX_AGAIN) {
[2421] #if 0
[2422]             ngx_add_timer(rev, u->read_timeout);
[2423] #endif
[2424] 
[2425]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2426]                 ngx_http_upstream_finalize_request(r, u,
[2427]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2428]                 return;
[2429]             }
[2430] 
[2431]             return;
[2432]         }
[2433] 
[2434]         if (n == 0) {
[2435]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[2436]                           "upstream prematurely closed connection");
[2437]         }
[2438] 
[2439]         if (n == NGX_ERROR || n == 0) {
[2440]             ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
[2441]             return;
[2442]         }
[2443] 
[2444]         u->state->bytes_received += n;
[2445] 
[2446]         u->buffer.last += n;
[2447] 
[2448] #if 0
[2449]         u->valid_header_in = 0;
[2450] 
[2451]         u->peer.cached = 0;
[2452] #endif
[2453] 
[2454]         rc = u->process_header(r);
[2455] 
[2456]         if (rc == NGX_AGAIN) {
[2457] 
[2458]             if (u->buffer.last == u->buffer.end) {
[2459]                 ngx_log_error(NGX_LOG_ERR, c->log, 0,
[2460]                               "upstream sent too big header");
[2461] 
[2462]                 ngx_http_upstream_next(r, u,
[2463]                                        NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
[2464]                 return;
[2465]             }
[2466] 
[2467]             continue;
[2468]         }
[2469] 
[2470]         break;
[2471]     }
[2472] 
[2473]     if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
[2474]         ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
[2475]         return;
[2476]     }
[2477] 
[2478]     if (rc == NGX_ERROR) {
[2479]         ngx_http_upstream_finalize_request(r, u,
[2480]                                            NGX_HTTP_INTERNAL_SERVER_ERROR);
[2481]         return;
[2482]     }
[2483] 
[2484]     /* rc == NGX_OK */
[2485] 
[2486]     u->state->header_time = ngx_current_msec - u->start_time;
[2487] 
[2488]     if (u->headers_in.status_n >= NGX_HTTP_SPECIAL_RESPONSE) {
[2489] 
[2490]         if (ngx_http_upstream_test_next(r, u) == NGX_OK) {
[2491]             return;
[2492]         }
[2493] 
[2494]         if (ngx_http_upstream_intercept_errors(r, u) == NGX_OK) {
[2495]             return;
[2496]         }
[2497]     }
[2498] 
[2499]     if (ngx_http_upstream_process_headers(r, u) != NGX_OK) {
[2500]         return;
[2501]     }
[2502] 
[2503]     ngx_http_upstream_send_response(r, u);
[2504] }
[2505] 
[2506] 
[2507] static ngx_int_t
[2508] ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u)
[2509] {
[2510]     ngx_msec_t                 timeout;
[2511]     ngx_uint_t                 status, mask;
[2512]     ngx_http_upstream_next_t  *un;
[2513] 
[2514]     status = u->headers_in.status_n;
[2515] 
[2516]     for (un = ngx_http_upstream_next_errors; un->status; un++) {
[2517] 
[2518]         if (status != un->status) {
[2519]             continue;
[2520]         }
[2521] 
[2522]         timeout = u->conf->next_upstream_timeout;
[2523] 
[2524]         if (u->request_sent
[2525]             && (r->method & (NGX_HTTP_POST|NGX_HTTP_LOCK|NGX_HTTP_PATCH)))
[2526]         {
[2527]             mask = un->mask | NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
[2528] 
[2529]         } else {
[2530]             mask = un->mask;
[2531]         }
[2532] 
[2533]         if (u->peer.tries > 1
[2534]             && ((u->conf->next_upstream & mask) == mask)
[2535]             && !(u->request_sent && r->request_body_no_buffering)
[2536]             && !(timeout && ngx_current_msec - u->peer.start_time >= timeout))
[2537]         {
[2538]             ngx_http_upstream_next(r, u, un->mask);
[2539]             return NGX_OK;
[2540]         }
[2541] 
[2542] #if (NGX_HTTP_CACHE)
[2543] 
[2544]         if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
[2545]             && (u->conf->cache_use_stale & un->mask))
[2546]         {
[2547]             ngx_int_t  rc;
[2548] 
[2549]             rc = u->reinit_request(r);
[2550] 
[2551]             if (rc != NGX_OK) {
[2552]                 ngx_http_upstream_finalize_request(r, u, rc);
[2553]                 return NGX_OK;
[2554]             }
[2555] 
[2556]             u->cache_status = NGX_HTTP_CACHE_STALE;
[2557]             rc = ngx_http_upstream_cache_send(r, u);
[2558] 
[2559]             if (rc == NGX_DONE) {
[2560]                 return NGX_OK;
[2561]             }
[2562] 
[2563]             if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
[2564]                 rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[2565]             }
[2566] 
[2567]             ngx_http_upstream_finalize_request(r, u, rc);
[2568]             return NGX_OK;
[2569]         }
[2570] 
[2571] #endif
[2572] 
[2573]         break;
[2574]     }
[2575] 
[2576] #if (NGX_HTTP_CACHE)
[2577] 
[2578]     if (status == NGX_HTTP_NOT_MODIFIED
[2579]         && u->cache_status == NGX_HTTP_CACHE_EXPIRED
[2580]         && u->conf->cache_revalidate)
[2581]     {
[2582]         time_t     now, valid, updating, error;
[2583]         ngx_int_t  rc;
[2584] 
[2585]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2586]                        "http upstream not modified");
[2587] 
[2588]         now = ngx_time();
[2589] 
[2590]         valid = r->cache->valid_sec;
[2591]         updating = r->cache->updating_sec;
[2592]         error = r->cache->error_sec;
[2593] 
[2594]         rc = u->reinit_request(r);
[2595] 
[2596]         if (rc != NGX_OK) {
[2597]             ngx_http_upstream_finalize_request(r, u, rc);
[2598]             return NGX_OK;
[2599]         }
[2600] 
[2601]         u->cache_status = NGX_HTTP_CACHE_REVALIDATED;
[2602]         rc = ngx_http_upstream_cache_send(r, u);
[2603] 
[2604]         if (rc == NGX_DONE) {
[2605]             return NGX_OK;
[2606]         }
[2607] 
[2608]         if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
[2609]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[2610]         }
[2611] 
[2612]         if (valid == 0) {
[2613]             valid = r->cache->valid_sec;
[2614]             updating = r->cache->updating_sec;
[2615]             error = r->cache->error_sec;
[2616]         }
[2617] 
[2618]         if (valid == 0) {
[2619]             valid = ngx_http_file_cache_valid(u->conf->cache_valid,
[2620]                                               u->headers_in.status_n);
[2621]             if (valid) {
[2622]                 valid = now + valid;
[2623]             }
[2624]         }
[2625] 
[2626]         if (valid) {
[2627]             r->cache->valid_sec = valid;
[2628]             r->cache->updating_sec = updating;
[2629]             r->cache->error_sec = error;
[2630] 
[2631]             r->cache->date = now;
[2632] 
[2633]             ngx_http_file_cache_update_header(r);
[2634]         }
[2635] 
[2636]         ngx_http_upstream_finalize_request(r, u, rc);
[2637]         return NGX_OK;
[2638]     }
[2639] 
[2640] #endif
[2641] 
[2642]     return NGX_DECLINED;
[2643] }
[2644] 
[2645] 
[2646] static ngx_int_t
[2647] ngx_http_upstream_intercept_errors(ngx_http_request_t *r,
[2648]     ngx_http_upstream_t *u)
[2649] {
[2650]     ngx_int_t                  status;
[2651]     ngx_uint_t                 i;
[2652]     ngx_table_elt_t           *h, *ho, **ph;
[2653]     ngx_http_err_page_t       *err_page;
[2654]     ngx_http_core_loc_conf_t  *clcf;
[2655] 
[2656]     status = u->headers_in.status_n;
[2657] 
[2658]     if (status == NGX_HTTP_NOT_FOUND && u->conf->intercept_404) {
[2659]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_NOT_FOUND);
[2660]         return NGX_OK;
[2661]     }
[2662] 
[2663]     if (!u->conf->intercept_errors) {
[2664]         return NGX_DECLINED;
[2665]     }
[2666] 
[2667]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2668] 
[2669]     if (clcf->error_pages == NULL) {
[2670]         return NGX_DECLINED;
[2671]     }
[2672] 
[2673]     err_page = clcf->error_pages->elts;
[2674]     for (i = 0; i < clcf->error_pages->nelts; i++) {
[2675] 
[2676]         if (err_page[i].status == status) {
[2677] 
[2678]             if (status == NGX_HTTP_UNAUTHORIZED
[2679]                 && u->headers_in.www_authenticate)
[2680]             {
[2681]                 h = u->headers_in.www_authenticate;
[2682]                 ph = &r->headers_out.www_authenticate;
[2683] 
[2684]                 while (h) {
[2685]                     ho = ngx_list_push(&r->headers_out.headers);
[2686] 
[2687]                     if (ho == NULL) {
[2688]                         ngx_http_upstream_finalize_request(r, u,
[2689]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2690]                         return NGX_OK;
[2691]                     }
[2692] 
[2693]                     *ho = *h;
[2694]                     ho->next = NULL;
[2695] 
[2696]                     *ph = ho;
[2697]                     ph = &ho->next;
[2698] 
[2699]                     h = h->next;
[2700]                 }
[2701]             }
[2702] 
[2703] #if (NGX_HTTP_CACHE)
[2704] 
[2705]             if (r->cache) {
[2706] 
[2707]                 if (u->headers_in.no_cache || u->headers_in.expired) {
[2708]                     u->cacheable = 0;
[2709]                 }
[2710] 
[2711]                 if (u->cacheable) {
[2712]                     time_t  valid;
[2713] 
[2714]                     valid = r->cache->valid_sec;
[2715] 
[2716]                     if (valid == 0) {
[2717]                         valid = ngx_http_file_cache_valid(u->conf->cache_valid,
[2718]                                                           status);
[2719]                         if (valid) {
[2720]                             r->cache->valid_sec = ngx_time() + valid;
[2721]                         }
[2722]                     }
[2723] 
[2724]                     if (valid) {
[2725]                         r->cache->error = status;
[2726]                     }
[2727]                 }
[2728] 
[2729]                 ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
[2730]             }
[2731] #endif
[2732]             ngx_http_upstream_finalize_request(r, u, status);
[2733] 
[2734]             return NGX_OK;
[2735]         }
[2736]     }
[2737] 
[2738]     return NGX_DECLINED;
[2739] }
[2740] 
[2741] 
[2742] static ngx_int_t
[2743] ngx_http_upstream_test_connect(ngx_connection_t *c)
[2744] {
[2745]     int        err;
[2746]     socklen_t  len;
[2747] 
[2748] #if (NGX_HAVE_KQUEUE)
[2749] 
[2750]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
[2751]         if (c->write->pending_eof || c->read->pending_eof) {
[2752]             if (c->write->pending_eof) {
[2753]                 err = c->write->kq_errno;
[2754] 
[2755]             } else {
[2756]                 err = c->read->kq_errno;
[2757]             }
[2758] 
[2759]             c->log->action = "connecting to upstream";
[2760]             (void) ngx_connection_error(c, err,
[2761]                                     "kevent() reported that connect() failed");
[2762]             return NGX_ERROR;
[2763]         }
[2764] 
[2765]     } else
[2766] #endif
[2767]     {
[2768]         err = 0;
[2769]         len = sizeof(int);
[2770] 
[2771]         /*
[2772]          * BSDs and Linux return 0 and set a pending error in err
[2773]          * Solaris returns -1 and sets errno
[2774]          */
[2775] 
[2776]         if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
[2777]             == -1)
[2778]         {
[2779]             err = ngx_socket_errno;
[2780]         }
[2781] 
[2782]         if (err) {
[2783]             c->log->action = "connecting to upstream";
[2784]             (void) ngx_connection_error(c, err, "connect() failed");
[2785]             return NGX_ERROR;
[2786]         }
[2787]     }
[2788] 
[2789]     return NGX_OK;
[2790] }
[2791] 
[2792] 
[2793] static ngx_int_t
[2794] ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u)
[2795] {
[2796]     ngx_str_t                       uri, args;
[2797]     ngx_uint_t                      i, flags;
[2798]     ngx_list_part_t                *part;
[2799]     ngx_table_elt_t                *h;
[2800]     ngx_http_upstream_header_t     *hh;
[2801]     ngx_http_upstream_main_conf_t  *umcf;
[2802] 
[2803]     umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[2804] 
[2805]     if (u->headers_in.no_cache || u->headers_in.expired) {
[2806]         u->cacheable = 0;
[2807]     }
[2808] 
[2809]     if (u->headers_in.x_accel_redirect
[2810]         && !(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT))
[2811]     {
[2812]         ngx_http_upstream_finalize_request(r, u, NGX_DECLINED);
[2813] 
[2814]         part = &u->headers_in.headers.part;
[2815]         h = part->elts;
[2816] 
[2817]         for (i = 0; /* void */; i++) {
[2818] 
[2819]             if (i >= part->nelts) {
[2820]                 if (part->next == NULL) {
[2821]                     break;
[2822]                 }
[2823] 
[2824]                 part = part->next;
[2825]                 h = part->elts;
[2826]                 i = 0;
[2827]             }
[2828] 
[2829]             if (h[i].hash == 0) {
[2830]                 continue;
[2831]             }
[2832] 
[2833]             hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
[2834]                                h[i].lowcase_key, h[i].key.len);
[2835] 
[2836]             if (hh && hh->redirect) {
[2837]                 if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
[2838]                     ngx_http_finalize_request(r,
[2839]                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
[2840]                     return NGX_DONE;
[2841]                 }
[2842]             }
[2843]         }
[2844] 
[2845]         uri = u->headers_in.x_accel_redirect->value;
[2846] 
[2847]         if (uri.data[0] == '@') {
[2848]             ngx_http_named_location(r, &uri);
[2849] 
[2850]         } else {
[2851]             ngx_str_null(&args);
[2852]             flags = NGX_HTTP_LOG_UNSAFE;
[2853] 
[2854]             if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
[2855]                 ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
[2856]                 return NGX_DONE;
[2857]             }
[2858] 
[2859]             if (r->method != NGX_HTTP_HEAD) {
[2860]                 r->method = NGX_HTTP_GET;
[2861]                 r->method_name = ngx_http_core_get_method;
[2862]             }
[2863] 
[2864]             ngx_http_internal_redirect(r, &uri, &args);
[2865]         }
[2866] 
[2867]         ngx_http_finalize_request(r, NGX_DONE);
[2868]         return NGX_DONE;
[2869]     }
[2870] 
[2871]     part = &u->headers_in.headers.part;
[2872]     h = part->elts;
[2873] 
[2874]     for (i = 0; /* void */; i++) {
[2875] 
[2876]         if (i >= part->nelts) {
[2877]             if (part->next == NULL) {
[2878]                 break;
[2879]             }
[2880] 
[2881]             part = part->next;
[2882]             h = part->elts;
[2883]             i = 0;
[2884]         }
[2885] 
[2886]         if (h[i].hash == 0) {
[2887]             continue;
[2888]         }
[2889] 
[2890]         if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
[2891]                           h[i].lowcase_key, h[i].key.len))
[2892]         {
[2893]             continue;
[2894]         }
[2895] 
[2896]         hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
[2897]                            h[i].lowcase_key, h[i].key.len);
[2898] 
[2899]         if (hh) {
[2900]             if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
[2901]                 ngx_http_upstream_finalize_request(r, u,
[2902]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2903]                 return NGX_DONE;
[2904]             }
[2905] 
[2906]             continue;
[2907]         }
[2908] 
[2909]         if (ngx_http_upstream_copy_header_line(r, &h[i], 0) != NGX_OK) {
[2910]             ngx_http_upstream_finalize_request(r, u,
[2911]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[2912]             return NGX_DONE;
[2913]         }
[2914]     }
[2915] 
[2916]     if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
[2917]         r->headers_out.server->hash = 0;
[2918]     }
[2919] 
[2920]     if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
[2921]         r->headers_out.date->hash = 0;
[2922]     }
[2923] 
[2924]     r->headers_out.status = u->headers_in.status_n;
[2925]     r->headers_out.status_line = u->headers_in.status_line;
[2926] 
[2927]     r->headers_out.content_length_n = u->headers_in.content_length_n;
[2928] 
[2929]     r->disable_not_modified = !u->cacheable;
[2930] 
[2931]     if (u->conf->force_ranges) {
[2932]         r->allow_ranges = 1;
[2933]         r->single_range = 1;
[2934] 
[2935] #if (NGX_HTTP_CACHE)
[2936]         if (r->cached) {
[2937]             r->single_range = 0;
[2938]         }
[2939] #endif
[2940]     }
[2941] 
[2942]     u->length = -1;
[2943] 
[2944]     return NGX_OK;
[2945] }
[2946] 
[2947] 
[2948] static ngx_int_t
[2949] ngx_http_upstream_process_trailers(ngx_http_request_t *r,
[2950]     ngx_http_upstream_t *u)
[2951] {
[2952]     ngx_uint_t        i;
[2953]     ngx_list_part_t  *part;
[2954]     ngx_table_elt_t  *h, *ho;
[2955] 
[2956]     if (!u->conf->pass_trailers) {
[2957]         return NGX_OK;
[2958]     }
[2959] 
[2960]     part = &u->headers_in.trailers.part;
[2961]     h = part->elts;
[2962] 
[2963]     for (i = 0; /* void */; i++) {
[2964] 
[2965]         if (i >= part->nelts) {
[2966]             if (part->next == NULL) {
[2967]                 break;
[2968]             }
[2969] 
[2970]             part = part->next;
[2971]             h = part->elts;
[2972]             i = 0;
[2973]         }
[2974] 
[2975]         if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
[2976]                           h[i].lowcase_key, h[i].key.len))
[2977]         {
[2978]             continue;
[2979]         }
[2980] 
[2981]         ho = ngx_list_push(&r->headers_out.trailers);
[2982]         if (ho == NULL) {
[2983]             return NGX_ERROR;
[2984]         }
[2985] 
[2986]         *ho = h[i];
[2987]     }
[2988] 
[2989]     return NGX_OK;
[2990] }
[2991] 
[2992] 
[2993] static void
[2994] ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
[2995] {
[2996]     ssize_t                    n;
[2997]     ngx_int_t                  rc;
[2998]     ngx_event_pipe_t          *p;
[2999]     ngx_connection_t          *c;
[3000]     ngx_http_core_loc_conf_t  *clcf;
[3001] 
[3002]     rc = ngx_http_send_header(r);
[3003] 
[3004]     if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
[3005]         ngx_http_upstream_finalize_request(r, u, rc);
[3006]         return;
[3007]     }
[3008] 
[3009]     u->header_sent = 1;
[3010] 
[3011]     if (u->upgrade) {
[3012] 
[3013] #if (NGX_HTTP_CACHE)
[3014] 
[3015]         if (r->cache) {
[3016]             ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
[3017]         }
[3018] 
[3019] #endif
[3020] 
[3021]         ngx_http_upstream_upgrade(r, u);
[3022]         return;
[3023]     }
[3024] 
[3025]     c = r->connection;
[3026] 
[3027]     if (r->header_only) {
[3028] 
[3029]         if (!u->buffering) {
[3030]             ngx_http_upstream_finalize_request(r, u, rc);
[3031]             return;
[3032]         }
[3033] 
[3034]         if (!u->cacheable && !u->store) {
[3035]             ngx_http_upstream_finalize_request(r, u, rc);
[3036]             return;
[3037]         }
[3038] 
[3039]         u->pipe->downstream_error = 1;
[3040]     }
[3041] 
[3042]     if (r->request_body && r->request_body->temp_file
[3043]         && r == r->main && !r->preserve_body
[3044]         && !u->conf->preserve_output)
[3045]     {
[3046]         ngx_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
[3047]         r->request_body->temp_file->file.fd = NGX_INVALID_FILE;
[3048]     }
[3049] 
[3050]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3051] 
[3052]     if (!u->buffering) {
[3053] 
[3054] #if (NGX_HTTP_CACHE)
[3055] 
[3056]         if (r->cache) {
[3057]             ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
[3058]         }
[3059] 
[3060] #endif
[3061] 
[3062]         if (u->input_filter == NULL) {
[3063]             u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
[3064]             u->input_filter = ngx_http_upstream_non_buffered_filter;
[3065]             u->input_filter_ctx = r;
[3066]         }
[3067] 
[3068]         u->read_event_handler = ngx_http_upstream_process_non_buffered_upstream;
[3069]         r->write_event_handler =
[3070]                              ngx_http_upstream_process_non_buffered_downstream;
[3071] 
[3072]         r->limit_rate = 0;
[3073]         r->limit_rate_set = 1;
[3074] 
[3075]         if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) {
[3076]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3077]             return;
[3078]         }
[3079] 
[3080]         if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[3081]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3082]             return;
[3083]         }
[3084] 
[3085]         n = u->buffer.last - u->buffer.pos;
[3086] 
[3087]         if (n) {
[3088]             u->buffer.last = u->buffer.pos;
[3089] 
[3090]             u->state->response_length += n;
[3091] 
[3092]             if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
[3093]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3094]                 return;
[3095]             }
[3096] 
[3097]             ngx_http_upstream_process_non_buffered_downstream(r);
[3098] 
[3099]         } else {
[3100]             u->buffer.pos = u->buffer.start;
[3101]             u->buffer.last = u->buffer.start;
[3102] 
[3103]             if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
[3104]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3105]                 return;
[3106]             }
[3107] 
[3108]             ngx_http_upstream_process_non_buffered_upstream(r, u);
[3109]         }
[3110] 
[3111]         return;
[3112]     }
[3113] 
[3114]     /* TODO: preallocate event_pipe bufs, look "Content-Length" */
[3115] 
[3116] #if (NGX_HTTP_CACHE)
[3117] 
[3118]     if (r->cache && r->cache->file.fd != NGX_INVALID_FILE) {
[3119]         ngx_pool_run_cleanup_file(r->pool, r->cache->file.fd);
[3120]         r->cache->file.fd = NGX_INVALID_FILE;
[3121]     }
[3122] 
[3123]     switch (ngx_http_test_predicates(r, u->conf->no_cache)) {
[3124] 
[3125]     case NGX_ERROR:
[3126]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3127]         return;
[3128] 
[3129]     case NGX_DECLINED:
[3130]         u->cacheable = 0;
[3131]         break;
[3132] 
[3133]     default: /* NGX_OK */
[3134] 
[3135]         if (u->cache_status == NGX_HTTP_CACHE_BYPASS) {
[3136] 
[3137]             /* create cache if previously bypassed */
[3138] 
[3139]             if (ngx_http_file_cache_create(r) != NGX_OK) {
[3140]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3141]                 return;
[3142]             }
[3143]         }
[3144] 
[3145]         break;
[3146]     }
[3147] 
[3148]     if (u->cacheable) {
[3149]         time_t  now, valid;
[3150] 
[3151]         now = ngx_time();
[3152] 
[3153]         valid = r->cache->valid_sec;
[3154] 
[3155]         if (valid == 0) {
[3156]             valid = ngx_http_file_cache_valid(u->conf->cache_valid,
[3157]                                               u->headers_in.status_n);
[3158]             if (valid) {
[3159]                 r->cache->valid_sec = now + valid;
[3160]             }
[3161]         }
[3162] 
[3163]         if (valid) {
[3164]             r->cache->date = now;
[3165]             r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);
[3166] 
[3167]             if (u->headers_in.status_n == NGX_HTTP_OK
[3168]                 || u->headers_in.status_n == NGX_HTTP_PARTIAL_CONTENT)
[3169]             {
[3170]                 r->cache->last_modified = u->headers_in.last_modified_time;
[3171] 
[3172]                 if (u->headers_in.etag) {
[3173]                     r->cache->etag = u->headers_in.etag->value;
[3174] 
[3175]                 } else {
[3176]                     ngx_str_null(&r->cache->etag);
[3177]                 }
[3178] 
[3179]             } else {
[3180]                 r->cache->last_modified = -1;
[3181]                 ngx_str_null(&r->cache->etag);
[3182]             }
[3183] 
[3184]             if (ngx_http_file_cache_set_header(r, u->buffer.start) != NGX_OK) {
[3185]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3186]                 return;
[3187]             }
[3188] 
[3189]         } else {
[3190]             u->cacheable = 0;
[3191]         }
[3192]     }
[3193] 
[3194]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3195]                    "http cacheable: %d", u->cacheable);
[3196] 
[3197]     if (u->cacheable == 0 && r->cache) {
[3198]         ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
[3199]     }
[3200] 
[3201]     if (r->header_only && !u->cacheable && !u->store) {
[3202]         ngx_http_upstream_finalize_request(r, u, 0);
[3203]         return;
[3204]     }
[3205] 
[3206] #endif
[3207] 
[3208]     p = u->pipe;
[3209] 
[3210]     p->output_filter = ngx_http_upstream_output_filter;
[3211]     p->output_ctx = r;
[3212]     p->tag = u->output.tag;
[3213]     p->bufs = u->conf->bufs;
[3214]     p->busy_size = u->conf->busy_buffers_size;
[3215]     p->upstream = u->peer.connection;
[3216]     p->downstream = c;
[3217]     p->pool = r->pool;
[3218]     p->log = c->log;
[3219]     p->limit_rate = u->conf->limit_rate;
[3220]     p->start_sec = ngx_time();
[3221] 
[3222]     p->cacheable = u->cacheable || u->store;
[3223] 
[3224]     p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
[3225]     if (p->temp_file == NULL) {
[3226]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3227]         return;
[3228]     }
[3229] 
[3230]     p->temp_file->file.fd = NGX_INVALID_FILE;
[3231]     p->temp_file->file.log = c->log;
[3232]     p->temp_file->path = u->conf->temp_path;
[3233]     p->temp_file->pool = r->pool;
[3234] 
[3235]     if (p->cacheable) {
[3236]         p->temp_file->persistent = 1;
[3237] 
[3238] #if (NGX_HTTP_CACHE)
[3239]         if (r->cache && !r->cache->file_cache->use_temp_path) {
[3240]             p->temp_file->path = r->cache->file_cache->path;
[3241]             p->temp_file->file.name = r->cache->file.name;
[3242]         }
[3243] #endif
[3244] 
[3245]     } else {
[3246]         p->temp_file->log_level = NGX_LOG_WARN;
[3247]         p->temp_file->warn = "an upstream response is buffered "
[3248]                              "to a temporary file";
[3249]     }
[3250] 
[3251]     p->max_temp_file_size = u->conf->max_temp_file_size;
[3252]     p->temp_file_write_size = u->conf->temp_file_write_size;
[3253] 
[3254] #if (NGX_THREADS)
[3255]     if (clcf->aio == NGX_HTTP_AIO_THREADS && clcf->aio_write) {
[3256]         p->thread_handler = ngx_http_upstream_thread_handler;
[3257]         p->thread_ctx = r;
[3258]     }
[3259] #endif
[3260] 
[3261]     p->preread_bufs = ngx_alloc_chain_link(r->pool);
[3262]     if (p->preread_bufs == NULL) {
[3263]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3264]         return;
[3265]     }
[3266] 
[3267]     p->preread_bufs->buf = &u->buffer;
[3268]     p->preread_bufs->next = NULL;
[3269]     u->buffer.recycled = 1;
[3270] 
[3271]     p->preread_size = u->buffer.last - u->buffer.pos;
[3272] 
[3273]     if (u->cacheable) {
[3274] 
[3275]         p->buf_to_file = ngx_calloc_buf(r->pool);
[3276]         if (p->buf_to_file == NULL) {
[3277]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3278]             return;
[3279]         }
[3280] 
[3281]         p->buf_to_file->start = u->buffer.start;
[3282]         p->buf_to_file->pos = u->buffer.start;
[3283]         p->buf_to_file->last = u->buffer.pos;
[3284]         p->buf_to_file->temporary = 1;
[3285]     }
[3286] 
[3287]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[3288]         /* the posted aio operation may corrupt a shadow buffer */
[3289]         p->single_buf = 1;
[3290]     }
[3291] 
[3292]     /* TODO: p->free_bufs = 0 if use ngx_create_chain_of_bufs() */
[3293]     p->free_bufs = 1;
[3294] 
[3295]     /*
[3296]      * event_pipe would do u->buffer.last += p->preread_size
[3297]      * as though these bytes were read
[3298]      */
[3299]     u->buffer.last = u->buffer.pos;
[3300] 
[3301]     if (u->conf->cyclic_temp_file) {
[3302] 
[3303]         /*
[3304]          * we need to disable the use of sendfile() if we use cyclic temp file
[3305]          * because the writing a new data may interfere with sendfile()
[3306]          * that uses the same kernel file pages (at least on FreeBSD)
[3307]          */
[3308] 
[3309]         p->cyclic_temp_file = 1;
[3310]         c->sendfile = 0;
[3311] 
[3312]     } else {
[3313]         p->cyclic_temp_file = 0;
[3314]     }
[3315] 
[3316]     p->read_timeout = u->conf->read_timeout;
[3317]     p->send_timeout = clcf->send_timeout;
[3318]     p->send_lowat = clcf->send_lowat;
[3319] 
[3320]     p->length = -1;
[3321] 
[3322]     if (u->input_filter_init
[3323]         && u->input_filter_init(p->input_ctx) != NGX_OK)
[3324]     {
[3325]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3326]         return;
[3327]     }
[3328] 
[3329]     u->read_event_handler = ngx_http_upstream_process_upstream;
[3330]     r->write_event_handler = ngx_http_upstream_process_downstream;
[3331] 
[3332]     ngx_http_upstream_process_upstream(r, u);
[3333] }
[3334] 
[3335] 
[3336] static void
[3337] ngx_http_upstream_upgrade(ngx_http_request_t *r, ngx_http_upstream_t *u)
[3338] {
[3339]     ngx_connection_t          *c;
[3340]     ngx_http_core_loc_conf_t  *clcf;
[3341] 
[3342]     c = r->connection;
[3343]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3344] 
[3345]     /* TODO: prevent upgrade if not requested or not possible */
[3346] 
[3347]     if (r != r->main) {
[3348]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[3349]                       "connection upgrade in subrequest");
[3350]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3351]         return;
[3352]     }
[3353] 
[3354]     r->keepalive = 0;
[3355]     c->log->action = "proxying upgraded connection";
[3356] 
[3357]     u->read_event_handler = ngx_http_upstream_upgraded_read_upstream;
[3358]     u->write_event_handler = ngx_http_upstream_upgraded_write_upstream;
[3359]     r->read_event_handler = ngx_http_upstream_upgraded_read_downstream;
[3360]     r->write_event_handler = ngx_http_upstream_upgraded_write_downstream;
[3361] 
[3362]     if (clcf->tcp_nodelay) {
[3363] 
[3364]         if (ngx_tcp_nodelay(c) != NGX_OK) {
[3365]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3366]             return;
[3367]         }
[3368] 
[3369]         if (ngx_tcp_nodelay(u->peer.connection) != NGX_OK) {
[3370]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3371]             return;
[3372]         }
[3373]     }
[3374] 
[3375]     if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
[3376]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3377]         return;
[3378]     }
[3379] 
[3380]     if (u->peer.connection->read->ready
[3381]         || u->buffer.pos != u->buffer.last)
[3382]     {
[3383]         ngx_post_event(c->read, &ngx_posted_events);
[3384]         ngx_http_upstream_process_upgraded(r, 1, 1);
[3385]         return;
[3386]     }
[3387] 
[3388]     ngx_http_upstream_process_upgraded(r, 0, 1);
[3389] }
[3390] 
[3391] 
[3392] static void
[3393] ngx_http_upstream_upgraded_read_downstream(ngx_http_request_t *r)
[3394] {
[3395]     ngx_http_upstream_process_upgraded(r, 0, 0);
[3396] }
[3397] 
[3398] 
[3399] static void
[3400] ngx_http_upstream_upgraded_write_downstream(ngx_http_request_t *r)
[3401] {
[3402]     ngx_http_upstream_process_upgraded(r, 1, 1);
[3403] }
[3404] 
[3405] 
[3406] static void
[3407] ngx_http_upstream_upgraded_read_upstream(ngx_http_request_t *r,
[3408]     ngx_http_upstream_t *u)
[3409] {
[3410]     ngx_http_upstream_process_upgraded(r, 1, 0);
[3411] }
[3412] 
[3413] 
[3414] static void
[3415] ngx_http_upstream_upgraded_write_upstream(ngx_http_request_t *r,
[3416]     ngx_http_upstream_t *u)
[3417] {
[3418]     ngx_http_upstream_process_upgraded(r, 0, 1);
[3419] }
[3420] 
[3421] 
[3422] static void
[3423] ngx_http_upstream_process_upgraded(ngx_http_request_t *r,
[3424]     ngx_uint_t from_upstream, ngx_uint_t do_write)
[3425] {
[3426]     size_t                     size;
[3427]     ssize_t                    n;
[3428]     ngx_buf_t                 *b;
[3429]     ngx_uint_t                 flags;
[3430]     ngx_connection_t          *c, *downstream, *upstream, *dst, *src;
[3431]     ngx_http_upstream_t       *u;
[3432]     ngx_http_core_loc_conf_t  *clcf;
[3433] 
[3434]     c = r->connection;
[3435]     u = r->upstream;
[3436] 
[3437]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3438]                    "http upstream process upgraded, fu:%ui", from_upstream);
[3439] 
[3440]     downstream = c;
[3441]     upstream = u->peer.connection;
[3442] 
[3443]     if (downstream->write->timedout) {
[3444]         c->timedout = 1;
[3445]         ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
[3446]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
[3447]         return;
[3448]     }
[3449] 
[3450]     if (upstream->read->timedout || upstream->write->timedout) {
[3451]         ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
[3452]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
[3453]         return;
[3454]     }
[3455] 
[3456]     if (from_upstream) {
[3457]         src = upstream;
[3458]         dst = downstream;
[3459]         b = &u->buffer;
[3460] 
[3461]     } else {
[3462]         src = downstream;
[3463]         dst = upstream;
[3464]         b = &u->from_client;
[3465] 
[3466]         if (r->header_in->last > r->header_in->pos) {
[3467]             b = r->header_in;
[3468]             b->end = b->last;
[3469]             do_write = 1;
[3470]         }
[3471] 
[3472]         if (b->start == NULL) {
[3473]             b->start = ngx_palloc(r->pool, u->conf->buffer_size);
[3474]             if (b->start == NULL) {
[3475]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3476]                 return;
[3477]             }
[3478] 
[3479]             b->pos = b->start;
[3480]             b->last = b->start;
[3481]             b->end = b->start + u->conf->buffer_size;
[3482]             b->temporary = 1;
[3483]             b->tag = u->output.tag;
[3484]         }
[3485]     }
[3486] 
[3487]     for ( ;; ) {
[3488] 
[3489]         if (do_write) {
[3490] 
[3491]             size = b->last - b->pos;
[3492] 
[3493]             if (size && dst->write->ready) {
[3494] 
[3495]                 n = dst->send(dst, b->pos, size);
[3496] 
[3497]                 if (n == NGX_ERROR) {
[3498]                     ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3499]                     return;
[3500]                 }
[3501] 
[3502]                 if (n > 0) {
[3503]                     b->pos += n;
[3504] 
[3505]                     if (b->pos == b->last) {
[3506]                         b->pos = b->start;
[3507]                         b->last = b->start;
[3508]                     }
[3509]                 }
[3510]             }
[3511]         }
[3512] 
[3513]         size = b->end - b->last;
[3514] 
[3515]         if (size && src->read->ready) {
[3516] 
[3517]             n = src->recv(src, b->last, size);
[3518] 
[3519]             if (n == NGX_AGAIN || n == 0) {
[3520]                 break;
[3521]             }
[3522] 
[3523]             if (n > 0) {
[3524]                 do_write = 1;
[3525]                 b->last += n;
[3526] 
[3527]                 if (from_upstream) {
[3528]                     u->state->bytes_received += n;
[3529]                 }
[3530] 
[3531]                 continue;
[3532]             }
[3533] 
[3534]             if (n == NGX_ERROR) {
[3535]                 src->read->eof = 1;
[3536]             }
[3537]         }
[3538] 
[3539]         break;
[3540]     }
[3541] 
[3542]     if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
[3543]         || (downstream->read->eof && u->from_client.pos == u->from_client.last)
[3544]         || (downstream->read->eof && upstream->read->eof))
[3545]     {
[3546]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3547]                        "http upstream upgraded done");
[3548]         ngx_http_upstream_finalize_request(r, u, 0);
[3549]         return;
[3550]     }
[3551] 
[3552]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3553] 
[3554]     if (ngx_handle_write_event(upstream->write, u->conf->send_lowat)
[3555]         != NGX_OK)
[3556]     {
[3557]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3558]         return;
[3559]     }
[3560] 
[3561]     if (upstream->write->active && !upstream->write->ready) {
[3562]         ngx_add_timer(upstream->write, u->conf->send_timeout);
[3563] 
[3564]     } else if (upstream->write->timer_set) {
[3565]         ngx_del_timer(upstream->write);
[3566]     }
[3567] 
[3568]     if (upstream->read->eof || upstream->read->error) {
[3569]         flags = NGX_CLOSE_EVENT;
[3570] 
[3571]     } else {
[3572]         flags = 0;
[3573]     }
[3574] 
[3575]     if (ngx_handle_read_event(upstream->read, flags) != NGX_OK) {
[3576]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3577]         return;
[3578]     }
[3579] 
[3580]     if (upstream->read->active && !upstream->read->ready) {
[3581]         ngx_add_timer(upstream->read, u->conf->read_timeout);
[3582] 
[3583]     } else if (upstream->read->timer_set) {
[3584]         ngx_del_timer(upstream->read);
[3585]     }
[3586] 
[3587]     if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
[3588]         != NGX_OK)
[3589]     {
[3590]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3591]         return;
[3592]     }
[3593] 
[3594]     if (downstream->read->eof || downstream->read->error) {
[3595]         flags = NGX_CLOSE_EVENT;
[3596] 
[3597]     } else {
[3598]         flags = 0;
[3599]     }
[3600] 
[3601]     if (ngx_handle_read_event(downstream->read, flags) != NGX_OK) {
[3602]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3603]         return;
[3604]     }
[3605] 
[3606]     if (downstream->write->active && !downstream->write->ready) {
[3607]         ngx_add_timer(downstream->write, clcf->send_timeout);
[3608] 
[3609]     } else if (downstream->write->timer_set) {
[3610]         ngx_del_timer(downstream->write);
[3611]     }
[3612] }
[3613] 
[3614] 
[3615] static void
[3616] ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r)
[3617] {
[3618]     ngx_event_t          *wev;
[3619]     ngx_connection_t     *c;
[3620]     ngx_http_upstream_t  *u;
[3621] 
[3622]     c = r->connection;
[3623]     u = r->upstream;
[3624]     wev = c->write;
[3625] 
[3626]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3627]                    "http upstream process non buffered downstream");
[3628] 
[3629]     c->log->action = "sending to client";
[3630] 
[3631]     if (wev->timedout) {
[3632]         c->timedout = 1;
[3633]         ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
[3634]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
[3635]         return;
[3636]     }
[3637] 
[3638]     ngx_http_upstream_process_non_buffered_request(r, 1);
[3639] }
[3640] 
[3641] 
[3642] static void
[3643] ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r,
[3644]     ngx_http_upstream_t *u)
[3645] {
[3646]     ngx_connection_t  *c;
[3647] 
[3648]     c = u->peer.connection;
[3649] 
[3650]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3651]                    "http upstream process non buffered upstream");
[3652] 
[3653]     c->log->action = "reading upstream";
[3654] 
[3655]     if (c->read->timedout) {
[3656]         ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
[3657]         ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
[3658]         return;
[3659]     }
[3660] 
[3661]     ngx_http_upstream_process_non_buffered_request(r, 0);
[3662] }
[3663] 
[3664] 
[3665] static void
[3666] ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r,
[3667]     ngx_uint_t do_write)
[3668] {
[3669]     size_t                     size;
[3670]     ssize_t                    n;
[3671]     ngx_buf_t                 *b;
[3672]     ngx_int_t                  rc;
[3673]     ngx_uint_t                 flags;
[3674]     ngx_connection_t          *downstream, *upstream;
[3675]     ngx_http_upstream_t       *u;
[3676]     ngx_http_core_loc_conf_t  *clcf;
[3677] 
[3678]     u = r->upstream;
[3679]     downstream = r->connection;
[3680]     upstream = u->peer.connection;
[3681] 
[3682]     b = &u->buffer;
[3683] 
[3684]     do_write = do_write || u->length == 0;
[3685] 
[3686]     for ( ;; ) {
[3687] 
[3688]         if (do_write) {
[3689] 
[3690]             if (u->out_bufs || u->busy_bufs || downstream->buffered) {
[3691]                 rc = ngx_http_output_filter(r, u->out_bufs);
[3692] 
[3693]                 if (rc == NGX_ERROR) {
[3694]                     ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3695]                     return;
[3696]                 }
[3697] 
[3698]                 ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
[3699]                                         &u->out_bufs, u->output.tag);
[3700]             }
[3701] 
[3702]             if (u->busy_bufs == NULL) {
[3703] 
[3704]                 if (u->length == 0
[3705]                     || (upstream->read->eof && u->length == -1))
[3706]                 {
[3707]                     ngx_http_upstream_finalize_request(r, u, 0);
[3708]                     return;
[3709]                 }
[3710] 
[3711]                 if (upstream->read->eof) {
[3712]                     ngx_log_error(NGX_LOG_ERR, upstream->log, 0,
[3713]                                   "upstream prematurely closed connection");
[3714] 
[3715]                     ngx_http_upstream_finalize_request(r, u,
[3716]                                                        NGX_HTTP_BAD_GATEWAY);
[3717]                     return;
[3718]                 }
[3719] 
[3720]                 if (upstream->read->error || u->error) {
[3721]                     ngx_http_upstream_finalize_request(r, u,
[3722]                                                        NGX_HTTP_BAD_GATEWAY);
[3723]                     return;
[3724]                 }
[3725] 
[3726]                 b->pos = b->start;
[3727]                 b->last = b->start;
[3728]             }
[3729]         }
[3730] 
[3731]         size = b->end - b->last;
[3732] 
[3733]         if (size && upstream->read->ready) {
[3734] 
[3735]             n = upstream->recv(upstream, b->last, size);
[3736] 
[3737]             if (n == NGX_AGAIN) {
[3738]                 break;
[3739]             }
[3740] 
[3741]             if (n > 0) {
[3742]                 u->state->bytes_received += n;
[3743]                 u->state->response_length += n;
[3744] 
[3745]                 if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
[3746]                     ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3747]                     return;
[3748]                 }
[3749]             }
[3750] 
[3751]             do_write = 1;
[3752] 
[3753]             continue;
[3754]         }
[3755] 
[3756]         break;
[3757]     }
[3758] 
[3759]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3760] 
[3761]     if (downstream->data == r) {
[3762]         if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
[3763]             != NGX_OK)
[3764]         {
[3765]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3766]             return;
[3767]         }
[3768]     }
[3769] 
[3770]     if (downstream->write->active && !downstream->write->ready) {
[3771]         ngx_add_timer(downstream->write, clcf->send_timeout);
[3772] 
[3773]     } else if (downstream->write->timer_set) {
[3774]         ngx_del_timer(downstream->write);
[3775]     }
[3776] 
[3777]     if (upstream->read->eof || upstream->read->error) {
[3778]         flags = NGX_CLOSE_EVENT;
[3779] 
[3780]     } else {
[3781]         flags = 0;
[3782]     }
[3783] 
[3784]     if (ngx_handle_read_event(upstream->read, flags) != NGX_OK) {
[3785]         ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[3786]         return;
[3787]     }
[3788] 
[3789]     if (upstream->read->active && !upstream->read->ready) {
[3790]         ngx_add_timer(upstream->read, u->conf->read_timeout);
[3791] 
[3792]     } else if (upstream->read->timer_set) {
[3793]         ngx_del_timer(upstream->read);
[3794]     }
[3795] }
[3796] 
[3797] 
[3798] ngx_int_t
[3799] ngx_http_upstream_non_buffered_filter_init(void *data)
[3800] {
[3801]     return NGX_OK;
[3802] }
[3803] 
[3804] 
[3805] ngx_int_t
[3806] ngx_http_upstream_non_buffered_filter(void *data, ssize_t bytes)
[3807] {
[3808]     ngx_http_request_t  *r = data;
[3809] 
[3810]     ngx_buf_t            *b;
[3811]     ngx_chain_t          *cl, **ll;
[3812]     ngx_http_upstream_t  *u;
[3813] 
[3814]     u = r->upstream;
[3815] 
[3816]     if (u->length == 0) {
[3817]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[3818]                       "upstream sent more data than specified in "
[3819]                       "\"Content-Length\" header");
[3820]         return NGX_OK;
[3821]     }
[3822] 
[3823]     for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
[3824]         ll = &cl->next;
[3825]     }
[3826] 
[3827]     cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
[3828]     if (cl == NULL) {
[3829]         return NGX_ERROR;
[3830]     }
[3831] 
[3832]     *ll = cl;
[3833] 
[3834]     cl->buf->flush = 1;
[3835]     cl->buf->memory = 1;
[3836] 
[3837]     b = &u->buffer;
[3838] 
[3839]     cl->buf->pos = b->last;
[3840]     b->last += bytes;
[3841]     cl->buf->last = b->last;
[3842]     cl->buf->tag = u->output.tag;
[3843] 
[3844]     if (u->length == -1) {
[3845]         return NGX_OK;
[3846]     }
[3847] 
[3848]     if (bytes > u->length) {
[3849] 
[3850]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[3851]                       "upstream sent more data than specified in "
[3852]                       "\"Content-Length\" header");
[3853] 
[3854]         cl->buf->last = cl->buf->pos + u->length;
[3855]         u->length = 0;
[3856] 
[3857]         return NGX_OK;
[3858]     }
[3859] 
[3860]     u->length -= bytes;
[3861] 
[3862]     return NGX_OK;
[3863] }
[3864] 
[3865] 
[3866] #if (NGX_THREADS)
[3867] 
[3868] static ngx_int_t
[3869] ngx_http_upstream_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)
[3870] {
[3871]     ngx_str_t                  name;
[3872]     ngx_event_pipe_t          *p;
[3873]     ngx_connection_t          *c;
[3874]     ngx_thread_pool_t         *tp;
[3875]     ngx_http_request_t        *r;
[3876]     ngx_http_core_loc_conf_t  *clcf;
[3877] 
[3878]     r = file->thread_ctx;
[3879]     p = r->upstream->pipe;
[3880] 
[3881]     if (r->aio) {
[3882]         /*
[3883]          * tolerate sendfile() calls if another operation is already
[3884]          * running; this can happen due to subrequests, multiple calls
[3885]          * of the next body filter from a filter, or in HTTP/2 due to
[3886]          * a write event on the main connection
[3887]          */
[3888] 
[3889]         c = r->connection;
[3890] 
[3891] #if (NGX_HTTP_V2)
[3892]         if (r->stream) {
[3893]             c = r->stream->connection->connection;
[3894]         }
[3895] #endif
[3896] 
[3897]         if (task == c->sendfile_task) {
[3898]             return NGX_OK;
[3899]         }
[3900]     }
[3901] 
[3902]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3903]     tp = clcf->thread_pool;
[3904] 
[3905]     if (tp == NULL) {
[3906]         if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
[3907]             != NGX_OK)
[3908]         {
[3909]             return NGX_ERROR;
[3910]         }
[3911] 
[3912]         tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);
[3913] 
[3914]         if (tp == NULL) {
[3915]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3916]                           "thread pool \"%V\" not found", &name);
[3917]             return NGX_ERROR;
[3918]         }
[3919]     }
[3920] 
[3921]     task->event.data = r;
[3922]     task->event.handler = ngx_http_upstream_thread_event_handler;
[3923] 
[3924]     if (ngx_thread_task_post(tp, task) != NGX_OK) {
[3925]         return NGX_ERROR;
[3926]     }
[3927] 
[3928]     r->main->blocked++;
[3929]     r->aio = 1;
[3930]     p->aio = 1;
[3931] 
[3932]     return NGX_OK;
[3933] }
[3934] 
[3935] 
[3936] static void
[3937] ngx_http_upstream_thread_event_handler(ngx_event_t *ev)
[3938] {
[3939]     ngx_connection_t    *c;
[3940]     ngx_http_request_t  *r;
[3941] 
[3942]     r = ev->data;
[3943]     c = r->connection;
[3944] 
[3945]     ngx_http_set_log_request(c->log, r);
[3946] 
[3947]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3948]                    "http upstream thread: \"%V?%V\"", &r->uri, &r->args);
[3949] 
[3950]     r->main->blocked--;
[3951]     r->aio = 0;
[3952] 
[3953] #if (NGX_HTTP_V2)
[3954] 
[3955]     if (r->stream) {
[3956]         /*
[3957]          * for HTTP/2, update write event to make sure processing will
[3958]          * reach the main connection to handle sendfile() in threads
[3959]          */
[3960] 
[3961]         c->write->ready = 1;
[3962]         c->write->active = 0;
[3963]     }
[3964] 
[3965] #endif
[3966] 
[3967]     if (r->done) {
[3968]         /*
[3969]          * trigger connection event handler if the subrequest was
[3970]          * already finalized; this can happen if the handler is used
[3971]          * for sendfile() in threads
[3972]          */
[3973] 
[3974]         c->write->handler(c->write);
[3975] 
[3976]     } else {
[3977]         r->write_event_handler(r);
[3978]         ngx_http_run_posted_requests(c);
[3979]     }
[3980] }
[3981] 
[3982] #endif
[3983] 
[3984] 
[3985] static ngx_int_t
[3986] ngx_http_upstream_output_filter(void *data, ngx_chain_t *chain)
[3987] {
[3988]     ngx_int_t            rc;
[3989]     ngx_event_pipe_t    *p;
[3990]     ngx_http_request_t  *r;
[3991] 
[3992]     r = data;
[3993]     p = r->upstream->pipe;
[3994] 
[3995]     rc = ngx_http_output_filter(r, chain);
[3996] 
[3997]     p->aio = r->aio;
[3998] 
[3999]     return rc;
[4000] }
[4001] 
[4002] 
[4003] static void
[4004] ngx_http_upstream_process_downstream(ngx_http_request_t *r)
[4005] {
[4006]     ngx_event_t          *wev;
[4007]     ngx_connection_t     *c;
[4008]     ngx_event_pipe_t     *p;
[4009]     ngx_http_upstream_t  *u;
[4010] 
[4011]     c = r->connection;
[4012]     u = r->upstream;
[4013]     p = u->pipe;
[4014]     wev = c->write;
[4015] 
[4016]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[4017]                    "http upstream process downstream");
[4018] 
[4019]     c->log->action = "sending to client";
[4020] 
[4021] #if (NGX_THREADS)
[4022]     p->aio = r->aio;
[4023] #endif
[4024] 
[4025]     if (wev->timedout) {
[4026] 
[4027]         p->downstream_error = 1;
[4028]         c->timedout = 1;
[4029]         ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
[4030] 
[4031]     } else {
[4032] 
[4033]         if (wev->delayed) {
[4034] 
[4035]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[4036]                            "http downstream delayed");
[4037] 
[4038]             if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
[4039]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[4040]             }
[4041] 
[4042]             return;
[4043]         }
[4044] 
[4045]         if (ngx_event_pipe(p, 1) == NGX_ABORT) {
[4046]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[4047]             return;
[4048]         }
[4049]     }
[4050] 
[4051]     ngx_http_upstream_process_request(r, u);
[4052] }
[4053] 
[4054] 
[4055] static void
[4056] ngx_http_upstream_process_upstream(ngx_http_request_t *r,
[4057]     ngx_http_upstream_t *u)
[4058] {
[4059]     ngx_event_t       *rev;
[4060]     ngx_event_pipe_t  *p;
[4061]     ngx_connection_t  *c;
[4062] 
[4063]     c = u->peer.connection;
[4064]     p = u->pipe;
[4065]     rev = c->read;
[4066] 
[4067]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[4068]                    "http upstream process upstream");
[4069] 
[4070]     c->log->action = "reading upstream";
[4071] 
[4072]     if (rev->timedout) {
[4073] 
[4074]         p->upstream_error = 1;
[4075]         ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
[4076] 
[4077]     } else {
[4078] 
[4079]         if (rev->delayed) {
[4080] 
[4081]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[4082]                            "http upstream delayed");
[4083] 
[4084]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[4085]                 ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[4086]             }
[4087] 
[4088]             return;
[4089]         }
[4090] 
[4091]         if (ngx_event_pipe(p, 0) == NGX_ABORT) {
[4092]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[4093]             return;
[4094]         }
[4095]     }
[4096] 
[4097]     ngx_http_upstream_process_request(r, u);
[4098] }
[4099] 
[4100] 
[4101] static void
[4102] ngx_http_upstream_process_request(ngx_http_request_t *r,
[4103]     ngx_http_upstream_t *u)
[4104] {
[4105]     ngx_temp_file_t   *tf;
[4106]     ngx_event_pipe_t  *p;
[4107] 
[4108]     p = u->pipe;
[4109] 
[4110] #if (NGX_THREADS)
[4111] 
[4112]     if (p->writing && !p->aio) {
[4113] 
[4114]         /*
[4115]          * make sure to call ngx_event_pipe()
[4116]          * if there is an incomplete aio write
[4117]          */
[4118] 
[4119]         if (ngx_event_pipe(p, 1) == NGX_ABORT) {
[4120]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[4121]             return;
[4122]         }
[4123]     }
[4124] 
[4125]     if (p->writing) {
[4126]         return;
[4127]     }
[4128] 
[4129] #endif
[4130] 
[4131]     if (u->peer.connection) {
[4132] 
[4133]         if (u->store) {
[4134] 
[4135]             if (p->upstream_eof || p->upstream_done) {
[4136] 
[4137]                 tf = p->temp_file;
[4138] 
[4139]                 if (u->headers_in.status_n == NGX_HTTP_OK
[4140]                     && (p->upstream_done || p->length == -1)
[4141]                     && (u->headers_in.content_length_n == -1
[4142]                         || u->headers_in.content_length_n == tf->offset))
[4143]                 {
[4144]                     ngx_http_upstream_store(r, u);
[4145]                 }
[4146]             }
[4147]         }
[4148] 
[4149] #if (NGX_HTTP_CACHE)
[4150] 
[4151]         if (u->cacheable) {
[4152] 
[4153]             if (p->upstream_done) {
[4154]                 ngx_http_file_cache_update(r, p->temp_file);
[4155] 
[4156]             } else if (p->upstream_eof) {
[4157] 
[4158]                 tf = p->temp_file;
[4159] 
[4160]                 if (p->length == -1
[4161]                     && (u->headers_in.content_length_n == -1
[4162]                         || u->headers_in.content_length_n
[4163]                            == tf->offset - (off_t) r->cache->body_start))
[4164]                 {
[4165]                     ngx_http_file_cache_update(r, tf);
[4166] 
[4167]                 } else {
[4168]                     ngx_http_file_cache_free(r->cache, tf);
[4169]                 }
[4170] 
[4171]             } else if (p->upstream_error) {
[4172]                 ngx_http_file_cache_free(r->cache, p->temp_file);
[4173]             }
[4174]         }
[4175] 
[4176] #endif
[4177] 
[4178]         if (p->upstream_done || p->upstream_eof || p->upstream_error) {
[4179]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4180]                            "http upstream exit: %p", p->out);
[4181] 
[4182]             if (p->upstream_done
[4183]                 || (p->upstream_eof && p->length == -1))
[4184]             {
[4185]                 ngx_http_upstream_finalize_request(r, u, 0);
[4186]                 return;
[4187]             }
[4188] 
[4189]             if (p->upstream_eof) {
[4190]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[4191]                               "upstream prematurely closed connection");
[4192]             }
[4193] 
[4194]             ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
[4195]             return;
[4196]         }
[4197]     }
[4198] 
[4199]     if (p->downstream_error) {
[4200]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4201]                        "http upstream downstream error");
[4202] 
[4203]         if (!u->cacheable && !u->store && u->peer.connection) {
[4204]             ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
[4205]         }
[4206]     }
[4207] }
[4208] 
[4209] 
[4210] static void
[4211] ngx_http_upstream_store(ngx_http_request_t *r, ngx_http_upstream_t *u)
[4212] {
[4213]     size_t                  root;
[4214]     time_t                  lm;
[4215]     ngx_str_t               path;
[4216]     ngx_temp_file_t        *tf;
[4217]     ngx_ext_rename_file_t   ext;
[4218] 
[4219]     tf = u->pipe->temp_file;
[4220] 
[4221]     if (tf->file.fd == NGX_INVALID_FILE) {
[4222] 
[4223]         /* create file for empty 200 response */
[4224] 
[4225]         tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
[4226]         if (tf == NULL) {
[4227]             return;
[4228]         }
[4229] 
[4230]         tf->file.fd = NGX_INVALID_FILE;
[4231]         tf->file.log = r->connection->log;
[4232]         tf->path = u->conf->temp_path;
[4233]         tf->pool = r->pool;
[4234]         tf->persistent = 1;
[4235] 
[4236]         if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
[4237]                                  tf->persistent, tf->clean, tf->access)
[4238]             != NGX_OK)
[4239]         {
[4240]             return;
[4241]         }
[4242] 
[4243]         u->pipe->temp_file = tf;
[4244]     }
[4245] 
[4246]     ext.access = u->conf->store_access;
[4247]     ext.path_access = u->conf->store_access;
[4248]     ext.time = -1;
[4249]     ext.create_path = 1;
[4250]     ext.delete_file = 1;
[4251]     ext.log = r->connection->log;
[4252] 
[4253]     if (u->headers_in.last_modified) {
[4254] 
[4255]         lm = ngx_parse_http_time(u->headers_in.last_modified->value.data,
[4256]                                  u->headers_in.last_modified->value.len);
[4257] 
[4258]         if (lm != NGX_ERROR) {
[4259]             ext.time = lm;
[4260]             ext.fd = tf->file.fd;
[4261]         }
[4262]     }
[4263] 
[4264]     if (u->conf->store_lengths == NULL) {
[4265] 
[4266]         if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
[4267]             return;
[4268]         }
[4269] 
[4270]     } else {
[4271]         if (ngx_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
[4272]                                 u->conf->store_values->elts)
[4273]             == NULL)
[4274]         {
[4275]             return;
[4276]         }
[4277]     }
[4278] 
[4279]     path.len--;
[4280] 
[4281]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4282]                    "upstream stores \"%s\" to \"%s\"",
[4283]                    tf->file.name.data, path.data);
[4284] 
[4285]     (void) ngx_ext_rename_file(&tf->file.name, &path, &ext);
[4286] 
[4287]     u->store = 0;
[4288] }
[4289] 
[4290] 
[4291] static void
[4292] ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
[4293] {
[4294]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4295]                    "http upstream dummy handler");
[4296] }
[4297] 
[4298] 
[4299] static void
[4300] ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u,
[4301]     ngx_uint_t ft_type)
[4302] {
[4303]     ngx_msec_t  timeout;
[4304]     ngx_uint_t  status, state;
[4305] 
[4306]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4307]                    "http next upstream, %xi", ft_type);
[4308] 
[4309]     if (u->peer.sockaddr) {
[4310] 
[4311]         if (u->peer.connection) {
[4312]             u->state->bytes_sent = u->peer.connection->sent;
[4313]         }
[4314] 
[4315]         if (ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_403
[4316]             || ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404)
[4317]         {
[4318]             state = NGX_PEER_NEXT;
[4319] 
[4320]         } else {
[4321]             state = NGX_PEER_FAILED;
[4322]         }
[4323] 
[4324]         u->peer.free(&u->peer, u->peer.data, state);
[4325]         u->peer.sockaddr = NULL;
[4326]     }
[4327] 
[4328]     if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
[4329]         ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
[4330]                       "upstream timed out");
[4331]     }
[4332] 
[4333]     if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) {
[4334]         /* TODO: inform balancer instead */
[4335]         u->peer.tries++;
[4336]     }
[4337] 
[4338]     switch (ft_type) {
[4339] 
[4340]     case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
[4341]     case NGX_HTTP_UPSTREAM_FT_HTTP_504:
[4342]         status = NGX_HTTP_GATEWAY_TIME_OUT;
[4343]         break;
[4344] 
[4345]     case NGX_HTTP_UPSTREAM_FT_HTTP_500:
[4346]         status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[4347]         break;
[4348] 
[4349]     case NGX_HTTP_UPSTREAM_FT_HTTP_503:
[4350]         status = NGX_HTTP_SERVICE_UNAVAILABLE;
[4351]         break;
[4352] 
[4353]     case NGX_HTTP_UPSTREAM_FT_HTTP_403:
[4354]         status = NGX_HTTP_FORBIDDEN;
[4355]         break;
[4356] 
[4357]     case NGX_HTTP_UPSTREAM_FT_HTTP_404:
[4358]         status = NGX_HTTP_NOT_FOUND;
[4359]         break;
[4360] 
[4361]     case NGX_HTTP_UPSTREAM_FT_HTTP_429:
[4362]         status = NGX_HTTP_TOO_MANY_REQUESTS;
[4363]         break;
[4364] 
[4365]     /*
[4366]      * NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING
[4367]      * never reach here
[4368]      */
[4369] 
[4370]     default:
[4371]         status = NGX_HTTP_BAD_GATEWAY;
[4372]     }
[4373] 
[4374]     if (r->connection->error) {
[4375]         ngx_http_upstream_finalize_request(r, u,
[4376]                                            NGX_HTTP_CLIENT_CLOSED_REQUEST);
[4377]         return;
[4378]     }
[4379] 
[4380]     u->state->status = status;
[4381] 
[4382]     timeout = u->conf->next_upstream_timeout;
[4383] 
[4384]     if (u->request_sent
[4385]         && (r->method & (NGX_HTTP_POST|NGX_HTTP_LOCK|NGX_HTTP_PATCH)))
[4386]     {
[4387]         ft_type |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
[4388]     }
[4389] 
[4390]     if (u->peer.tries == 0
[4391]         || ((u->conf->next_upstream & ft_type) != ft_type)
[4392]         || (u->request_sent && r->request_body_no_buffering)
[4393]         || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
[4394]     {
[4395] #if (NGX_HTTP_CACHE)
[4396] 
[4397]         if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
[4398]             && ((u->conf->cache_use_stale & ft_type) || r->cache->stale_error))
[4399]         {
[4400]             ngx_int_t  rc;
[4401] 
[4402]             rc = u->reinit_request(r);
[4403] 
[4404]             if (rc != NGX_OK) {
[4405]                 ngx_http_upstream_finalize_request(r, u, rc);
[4406]                 return;
[4407]             }
[4408] 
[4409]             u->cache_status = NGX_HTTP_CACHE_STALE;
[4410]             rc = ngx_http_upstream_cache_send(r, u);
[4411] 
[4412]             if (rc == NGX_DONE) {
[4413]                 return;
[4414]             }
[4415] 
[4416]             if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) {
[4417]                 rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[4418]             }
[4419] 
[4420]             ngx_http_upstream_finalize_request(r, u, rc);
[4421]             return;
[4422]         }
[4423] #endif
[4424] 
[4425]         ngx_http_upstream_finalize_request(r, u, status);
[4426]         return;
[4427]     }
[4428] 
[4429]     if (u->peer.connection) {
[4430]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4431]                        "close http upstream connection: %d",
[4432]                        u->peer.connection->fd);
[4433] #if (NGX_HTTP_SSL)
[4434] 
[4435]         if (u->peer.connection->ssl) {
[4436]             u->peer.connection->ssl->no_wait_shutdown = 1;
[4437]             u->peer.connection->ssl->no_send_shutdown = 1;
[4438] 
[4439]             (void) ngx_ssl_shutdown(u->peer.connection);
[4440]         }
[4441] #endif
[4442] 
[4443]         if (u->peer.connection->pool) {
[4444]             ngx_destroy_pool(u->peer.connection->pool);
[4445]         }
[4446] 
[4447]         ngx_close_connection(u->peer.connection);
[4448]         u->peer.connection = NULL;
[4449]     }
[4450] 
[4451]     ngx_http_upstream_connect(r, u);
[4452] }
[4453] 
[4454] 
[4455] static void
[4456] ngx_http_upstream_cleanup(void *data)
[4457] {
[4458]     ngx_http_request_t *r = data;
[4459] 
[4460]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4461]                    "cleanup http upstream request: \"%V\"", &r->uri);
[4462] 
[4463]     ngx_http_upstream_finalize_request(r, r->upstream, NGX_DONE);
[4464] }
[4465] 
[4466] 
[4467] static void
[4468] ngx_http_upstream_finalize_request(ngx_http_request_t *r,
[4469]     ngx_http_upstream_t *u, ngx_int_t rc)
[4470] {
[4471]     ngx_uint_t  flush;
[4472] 
[4473]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4474]                    "finalize http upstream request: %i", rc);
[4475] 
[4476]     if (u->cleanup == NULL) {
[4477]         /* the request was already finalized */
[4478]         ngx_http_finalize_request(r, NGX_DONE);
[4479]         return;
[4480]     }
[4481] 
[4482]     *u->cleanup = NULL;
[4483]     u->cleanup = NULL;
[4484] 
[4485]     if (u->resolved && u->resolved->ctx) {
[4486]         ngx_resolve_name_done(u->resolved->ctx);
[4487]         u->resolved->ctx = NULL;
[4488]     }
[4489] 
[4490]     if (u->state && u->state->response_time == (ngx_msec_t) -1) {
[4491]         u->state->response_time = ngx_current_msec - u->start_time;
[4492] 
[4493]         if (u->pipe && u->pipe->read_length) {
[4494]             u->state->bytes_received += u->pipe->read_length
[4495]                                         - u->pipe->preread_size;
[4496]             u->state->response_length = u->pipe->read_length;
[4497]         }
[4498] 
[4499]         if (u->peer.connection) {
[4500]             u->state->bytes_sent = u->peer.connection->sent;
[4501]         }
[4502]     }
[4503] 
[4504]     u->finalize_request(r, rc);
[4505] 
[4506]     if (u->peer.free && u->peer.sockaddr) {
[4507]         u->peer.free(&u->peer, u->peer.data, 0);
[4508]         u->peer.sockaddr = NULL;
[4509]     }
[4510] 
[4511]     if (u->peer.connection) {
[4512] 
[4513] #if (NGX_HTTP_SSL)
[4514] 
[4515]         /* TODO: do not shutdown persistent connection */
[4516] 
[4517]         if (u->peer.connection->ssl) {
[4518] 
[4519]             /*
[4520]              * We send the "close notify" shutdown alert to the upstream only
[4521]              * and do not wait its "close notify" shutdown alert.
[4522]              * It is acceptable according to the TLS standard.
[4523]              */
[4524] 
[4525]             u->peer.connection->ssl->no_wait_shutdown = 1;
[4526] 
[4527]             (void) ngx_ssl_shutdown(u->peer.connection);
[4528]         }
[4529] #endif
[4530] 
[4531]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4532]                        "close http upstream connection: %d",
[4533]                        u->peer.connection->fd);
[4534] 
[4535]         if (u->peer.connection->pool) {
[4536]             ngx_destroy_pool(u->peer.connection->pool);
[4537]         }
[4538] 
[4539]         ngx_close_connection(u->peer.connection);
[4540]     }
[4541] 
[4542]     u->peer.connection = NULL;
[4543] 
[4544]     if (u->pipe && u->pipe->temp_file) {
[4545]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4546]                        "http upstream temp fd: %d",
[4547]                        u->pipe->temp_file->file.fd);
[4548]     }
[4549] 
[4550]     if (u->store && u->pipe && u->pipe->temp_file
[4551]         && u->pipe->temp_file->file.fd != NGX_INVALID_FILE)
[4552]     {
[4553]         if (ngx_delete_file(u->pipe->temp_file->file.name.data)
[4554]             == NGX_FILE_ERROR)
[4555]         {
[4556]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[4557]                           ngx_delete_file_n " \"%s\" failed",
[4558]                           u->pipe->temp_file->file.name.data);
[4559]         }
[4560]     }
[4561] 
[4562] #if (NGX_HTTP_CACHE)
[4563] 
[4564]     if (r->cache) {
[4565] 
[4566]         if (u->cacheable) {
[4567] 
[4568]             if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT) {
[4569]                 time_t  valid;
[4570] 
[4571]                 valid = ngx_http_file_cache_valid(u->conf->cache_valid, rc);
[4572] 
[4573]                 if (valid) {
[4574]                     r->cache->valid_sec = ngx_time() + valid;
[4575]                     r->cache->error = rc;
[4576]                 }
[4577]             }
[4578]         }
[4579] 
[4580]         ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
[4581]     }
[4582] 
[4583] #endif
[4584] 
[4585]     r->read_event_handler = ngx_http_block_reading;
[4586] 
[4587]     if (rc == NGX_DECLINED) {
[4588]         return;
[4589]     }
[4590] 
[4591]     r->connection->log->action = "sending to client";
[4592] 
[4593]     if (!u->header_sent
[4594]         || rc == NGX_HTTP_REQUEST_TIME_OUT
[4595]         || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST)
[4596]     {
[4597]         ngx_http_finalize_request(r, rc);
[4598]         return;
[4599]     }
[4600] 
[4601]     flush = 0;
[4602] 
[4603]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[4604]         rc = NGX_ERROR;
[4605]         flush = 1;
[4606]     }
[4607] 
[4608]     if (r->header_only
[4609]         || (u->pipe && u->pipe->downstream_error))
[4610]     {
[4611]         ngx_http_finalize_request(r, rc);
[4612]         return;
[4613]     }
[4614] 
[4615]     if (rc == 0) {
[4616] 
[4617]         if (ngx_http_upstream_process_trailers(r, u) != NGX_OK) {
[4618]             ngx_http_finalize_request(r, NGX_ERROR);
[4619]             return;
[4620]         }
[4621] 
[4622]         rc = ngx_http_send_special(r, NGX_HTTP_LAST);
[4623] 
[4624]     } else if (flush) {
[4625]         r->keepalive = 0;
[4626]         rc = ngx_http_send_special(r, NGX_HTTP_FLUSH);
[4627]     }
[4628] 
[4629]     ngx_http_finalize_request(r, rc);
[4630] }
[4631] 
[4632] 
[4633] static ngx_int_t
[4634] ngx_http_upstream_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
[4635]     ngx_uint_t offset)
[4636] {
[4637]     ngx_table_elt_t  **ph;
[4638] 
[4639]     ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);
[4640] 
[4641]     if (*ph) {
[4642]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[4643]                       "upstream sent duplicate header line: \"%V: %V\", "
[4644]                       "previous value: \"%V: %V\", ignored",
[4645]                       &h->key, &h->value,
[4646]                       &(*ph)->key, &(*ph)->value);
[4647]         h->hash = 0;
[4648]         return NGX_OK;
[4649]     }
[4650] 
[4651]     *ph = h;
[4652]     h->next = NULL;
[4653] 
[4654]     return NGX_OK;
[4655] }
[4656] 
[4657] 
[4658] static ngx_int_t
[4659] ngx_http_upstream_process_multi_header_lines(ngx_http_request_t *r,
[4660]     ngx_table_elt_t *h, ngx_uint_t offset)
[4661] {
[4662]     ngx_table_elt_t  **ph;
[4663] 
[4664]     ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);
[4665] 
[4666]     while (*ph) { ph = &(*ph)->next; }
[4667] 
[4668]     *ph = h;
[4669]     h->next = NULL;
[4670] 
[4671]     return NGX_OK;
[4672] }
[4673] 
[4674] 
[4675] static ngx_int_t
[4676] ngx_http_upstream_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
[4677]     ngx_uint_t offset)
[4678] {
[4679]     return NGX_OK;
[4680] }
[4681] 
[4682] 
[4683] static ngx_int_t
[4684] ngx_http_upstream_process_content_length(ngx_http_request_t *r,
[4685]     ngx_table_elt_t *h, ngx_uint_t offset)
[4686] {
[4687]     ngx_http_upstream_t  *u;
[4688] 
[4689]     u = r->upstream;
[4690] 
[4691]     if (u->headers_in.content_length) {
[4692]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[4693]                       "upstream sent duplicate header line: \"%V: %V\", "
[4694]                       "previous value: \"%V: %V\"",
[4695]                       &h->key, &h->value,
[4696]                       &u->headers_in.content_length->key,
[4697]                       &u->headers_in.content_length->value);
[4698]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[4699]     }
[4700] 
[4701]     if (u->headers_in.transfer_encoding) {
[4702]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[4703]                       "upstream sent \"Content-Length\" and "
[4704]                       "\"Transfer-Encoding\" headers at the same time");
[4705]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[4706]     }
[4707] 
[4708]     h->next = NULL;
[4709]     u->headers_in.content_length = h;
[4710]     u->headers_in.content_length_n = ngx_atoof(h->value.data, h->value.len);
[4711] 
[4712]     if (u->headers_in.content_length_n == NGX_ERROR) {
[4713]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[4714]                       "upstream sent invalid \"Content-Length\" header: "
[4715]                       "\"%V: %V\"", &h->key, &h->value);
[4716]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[4717]     }
[4718] 
[4719]     return NGX_OK;
[4720] }
[4721] 
[4722] 
[4723] static ngx_int_t
[4724] ngx_http_upstream_process_last_modified(ngx_http_request_t *r,
[4725]     ngx_table_elt_t *h, ngx_uint_t offset)
[4726] {
[4727]     ngx_http_upstream_t  *u;
[4728] 
[4729]     u = r->upstream;
[4730] 
[4731]     if (u->headers_in.last_modified) {
[4732]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[4733]                       "upstream sent duplicate header line: \"%V: %V\", "
[4734]                       "previous value: \"%V: %V\", ignored",
[4735]                       &h->key, &h->value,
[4736]                       &u->headers_in.last_modified->key,
[4737]                       &u->headers_in.last_modified->value);
[4738]         h->hash = 0;
[4739]         return NGX_OK;
[4740]     }
[4741] 
[4742]     h->next = NULL;
[4743]     u->headers_in.last_modified = h;
[4744]     u->headers_in.last_modified_time = ngx_parse_http_time(h->value.data,
[4745]                                                            h->value.len);
[4746] 
[4747]     return NGX_OK;
[4748] }
[4749] 
[4750] 
[4751] static ngx_int_t
[4752] ngx_http_upstream_process_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h,
[4753]     ngx_uint_t offset)
[4754] {
[4755]     ngx_table_elt_t      **ph;
[4756]     ngx_http_upstream_t   *u;
[4757] 
[4758]     u = r->upstream;
[4759]     ph = &u->headers_in.set_cookie;
[4760] 
[4761]     while (*ph) { ph = &(*ph)->next; }
[4762] 
[4763]     *ph = h;
[4764]     h->next = NULL;
[4765] 
[4766] #if (NGX_HTTP_CACHE)
[4767]     if (!(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_SET_COOKIE)) {
[4768]         u->cacheable = 0;
[4769]     }
[4770] #endif
[4771] 
[4772]     return NGX_OK;
[4773] }
[4774] 
[4775] 
[4776] static ngx_int_t
[4777] ngx_http_upstream_process_cache_control(ngx_http_request_t *r,
[4778]     ngx_table_elt_t *h, ngx_uint_t offset)
[4779] {
[4780]     ngx_table_elt_t      **ph;
[4781]     ngx_http_upstream_t   *u;
[4782] 
[4783]     u = r->upstream;
[4784]     ph = &u->headers_in.cache_control;
[4785] 
[4786]     while (*ph) { ph = &(*ph)->next; }
[4787] 
[4788]     *ph = h;
[4789]     h->next = NULL;
[4790] 
[4791] #if (NGX_HTTP_CACHE)
[4792]     {
[4793]     u_char     *p, *start, *last;
[4794]     ngx_int_t   n;
[4795] 
[4796]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL) {
[4797]         return NGX_OK;
[4798]     }
[4799] 
[4800]     if (r->cache == NULL) {
[4801]         return NGX_OK;
[4802]     }
[4803] 
[4804]     start = h->value.data;
[4805]     last = start + h->value.len;
[4806] 
[4807]     if (r->cache->valid_sec != 0 && u->headers_in.x_accel_expires != NULL) {
[4808]         goto extensions;
[4809]     }
[4810] 
[4811]     if (ngx_strlcasestrn(start, last, (u_char *) "no-cache", 8 - 1) != NULL
[4812]         || ngx_strlcasestrn(start, last, (u_char *) "no-store", 8 - 1) != NULL
[4813]         || ngx_strlcasestrn(start, last, (u_char *) "private", 7 - 1) != NULL)
[4814]     {
[4815]         u->headers_in.no_cache = 1;
[4816]         return NGX_OK;
[4817]     }
[4818] 
[4819]     p = ngx_strlcasestrn(start, last, (u_char *) "s-maxage=", 9 - 1);
[4820]     offset = 9;
[4821] 
[4822]     if (p == NULL) {
[4823]         p = ngx_strlcasestrn(start, last, (u_char *) "max-age=", 8 - 1);
[4824]         offset = 8;
[4825]     }
[4826] 
[4827]     if (p) {
[4828]         n = 0;
[4829] 
[4830]         for (p += offset; p < last; p++) {
[4831]             if (*p == ',' || *p == ';' || *p == ' ') {
[4832]                 break;
[4833]             }
[4834] 
[4835]             if (*p >= '0' && *p <= '9') {
[4836]                 n = n * 10 + (*p - '0');
[4837]                 continue;
[4838]             }
[4839] 
[4840]             u->cacheable = 0;
[4841]             return NGX_OK;
[4842]         }
[4843] 
[4844]         if (n == 0) {
[4845]             u->headers_in.no_cache = 1;
[4846]             return NGX_OK;
[4847]         }
[4848] 
[4849]         r->cache->valid_sec = ngx_time() + n;
[4850]         u->headers_in.expired = 0;
[4851]     }
[4852] 
[4853] extensions:
[4854] 
[4855]     p = ngx_strlcasestrn(start, last, (u_char *) "stale-while-revalidate=",
[4856]                          23 - 1);
[4857] 
[4858]     if (p) {
[4859]         n = 0;
[4860] 
[4861]         for (p += 23; p < last; p++) {
[4862]             if (*p == ',' || *p == ';' || *p == ' ') {
[4863]                 break;
[4864]             }
[4865] 
[4866]             if (*p >= '0' && *p <= '9') {
[4867]                 n = n * 10 + (*p - '0');
[4868]                 continue;
[4869]             }
[4870] 
[4871]             u->cacheable = 0;
[4872]             return NGX_OK;
[4873]         }
[4874] 
[4875]         r->cache->updating_sec = n;
[4876]         r->cache->error_sec = n;
[4877]     }
[4878] 
[4879]     p = ngx_strlcasestrn(start, last, (u_char *) "stale-if-error=", 15 - 1);
[4880] 
[4881]     if (p) {
[4882]         n = 0;
[4883] 
[4884]         for (p += 15; p < last; p++) {
[4885]             if (*p == ',' || *p == ';' || *p == ' ') {
[4886]                 break;
[4887]             }
[4888] 
[4889]             if (*p >= '0' && *p <= '9') {
[4890]                 n = n * 10 + (*p - '0');
[4891]                 continue;
[4892]             }
[4893] 
[4894]             u->cacheable = 0;
[4895]             return NGX_OK;
[4896]         }
[4897] 
[4898]         r->cache->error_sec = n;
[4899]     }
[4900]     }
[4901] #endif
[4902] 
[4903]     return NGX_OK;
[4904] }
[4905] 
[4906] 
[4907] static ngx_int_t
[4908] ngx_http_upstream_process_expires(ngx_http_request_t *r, ngx_table_elt_t *h,
[4909]     ngx_uint_t offset)
[4910] {
[4911]     ngx_http_upstream_t  *u;
[4912] 
[4913]     u = r->upstream;
[4914] 
[4915]     if (u->headers_in.expires) {
[4916]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[4917]                       "upstream sent duplicate header line: \"%V: %V\", "
[4918]                       "previous value: \"%V: %V\", ignored",
[4919]                       &h->key, &h->value,
[4920]                       &u->headers_in.expires->key,
[4921]                       &u->headers_in.expires->value);
[4922]         h->hash = 0;
[4923]         return NGX_OK;
[4924]     }
[4925] 
[4926]     u->headers_in.expires = h;
[4927]     h->next = NULL;
[4928] 
[4929] #if (NGX_HTTP_CACHE)
[4930]     {
[4931]     time_t  expires;
[4932] 
[4933]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_EXPIRES) {
[4934]         return NGX_OK;
[4935]     }
[4936] 
[4937]     if (r->cache == NULL) {
[4938]         return NGX_OK;
[4939]     }
[4940] 
[4941]     if (r->cache->valid_sec != 0) {
[4942]         return NGX_OK;
[4943]     }
[4944] 
[4945]     expires = ngx_parse_http_time(h->value.data, h->value.len);
[4946] 
[4947]     if (expires == NGX_ERROR || expires < ngx_time()) {
[4948]         u->headers_in.expired = 1;
[4949]         return NGX_OK;
[4950]     }
[4951] 
[4952]     r->cache->valid_sec = expires;
[4953]     }
[4954] #endif
[4955] 
[4956]     return NGX_OK;
[4957] }
[4958] 
[4959] 
[4960] static ngx_int_t
[4961] ngx_http_upstream_process_accel_expires(ngx_http_request_t *r,
[4962]     ngx_table_elt_t *h, ngx_uint_t offset)
[4963] {
[4964]     ngx_http_upstream_t  *u;
[4965] 
[4966]     u = r->upstream;
[4967] 
[4968]     if (u->headers_in.x_accel_expires) {
[4969]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[4970]                       "upstream sent duplicate header line: \"%V: %V\", "
[4971]                       "previous value: \"%V: %V\", ignored",
[4972]                       &h->key, &h->value,
[4973]                       &u->headers_in.x_accel_expires->key,
[4974]                       &u->headers_in.x_accel_expires->value);
[4975]         h->hash = 0;
[4976]         return NGX_OK;
[4977]     }
[4978] 
[4979]     u->headers_in.x_accel_expires = h;
[4980]     h->next = NULL;
[4981] 
[4982] #if (NGX_HTTP_CACHE)
[4983]     {
[4984]     u_char     *p;
[4985]     size_t      len;
[4986]     ngx_int_t   n;
[4987] 
[4988]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES) {
[4989]         return NGX_OK;
[4990]     }
[4991] 
[4992]     if (r->cache == NULL) {
[4993]         return NGX_OK;
[4994]     }
[4995] 
[4996]     len = h->value.len;
[4997]     p = h->value.data;
[4998] 
[4999]     if (p[0] != '@') {
[5000]         n = ngx_atoi(p, len);
[5001] 
[5002]         switch (n) {
[5003]         case 0:
[5004]             u->cacheable = 0;
[5005]             /* fall through */
[5006] 
[5007]         case NGX_ERROR:
[5008]             return NGX_OK;
[5009] 
[5010]         default:
[5011]             r->cache->valid_sec = ngx_time() + n;
[5012]             u->headers_in.no_cache = 0;
[5013]             u->headers_in.expired = 0;
[5014]             return NGX_OK;
[5015]         }
[5016]     }
[5017] 
[5018]     p++;
[5019]     len--;
[5020] 
[5021]     n = ngx_atoi(p, len);
[5022] 
[5023]     if (n != NGX_ERROR) {
[5024]         r->cache->valid_sec = n;
[5025]         u->headers_in.no_cache = 0;
[5026]         u->headers_in.expired = 0;
[5027]     }
[5028]     }
[5029] #endif
[5030] 
[5031]     return NGX_OK;
[5032] }
[5033] 
[5034] 
[5035] static ngx_int_t
[5036] ngx_http_upstream_process_limit_rate(ngx_http_request_t *r, ngx_table_elt_t *h,
[5037]     ngx_uint_t offset)
[5038] {
[5039]     ngx_int_t             n;
[5040]     ngx_http_upstream_t  *u;
[5041] 
[5042]     u = r->upstream;
[5043] 
[5044]     if (u->headers_in.x_accel_limit_rate) {
[5045]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[5046]                       "upstream sent duplicate header line: \"%V: %V\", "
[5047]                       "previous value: \"%V: %V\", ignored",
[5048]                       &h->key, &h->value,
[5049]                       &u->headers_in.x_accel_limit_rate->key,
[5050]                       &u->headers_in.x_accel_limit_rate->value);
[5051]         h->hash = 0;
[5052]         return NGX_OK;
[5053]     }
[5054] 
[5055]     u->headers_in.x_accel_limit_rate = h;
[5056]     h->next = NULL;
[5057] 
[5058]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
[5059]         return NGX_OK;
[5060]     }
[5061] 
[5062]     n = ngx_atoi(h->value.data, h->value.len);
[5063] 
[5064]     if (n != NGX_ERROR) {
[5065]         r->limit_rate = (size_t) n;
[5066]         r->limit_rate_set = 1;
[5067]     }
[5068] 
[5069]     return NGX_OK;
[5070] }
[5071] 
[5072] 
[5073] static ngx_int_t
[5074] ngx_http_upstream_process_buffering(ngx_http_request_t *r, ngx_table_elt_t *h,
[5075]     ngx_uint_t offset)
[5076] {
[5077]     u_char                c0, c1, c2;
[5078]     ngx_http_upstream_t  *u;
[5079] 
[5080]     u = r->upstream;
[5081] 
[5082]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING) {
[5083]         return NGX_OK;
[5084]     }
[5085] 
[5086]     if (u->conf->change_buffering) {
[5087] 
[5088]         if (h->value.len == 2) {
[5089]             c0 = ngx_tolower(h->value.data[0]);
[5090]             c1 = ngx_tolower(h->value.data[1]);
[5091] 
[5092]             if (c0 == 'n' && c1 == 'o') {
[5093]                 u->buffering = 0;
[5094]             }
[5095] 
[5096]         } else if (h->value.len == 3) {
[5097]             c0 = ngx_tolower(h->value.data[0]);
[5098]             c1 = ngx_tolower(h->value.data[1]);
[5099]             c2 = ngx_tolower(h->value.data[2]);
[5100] 
[5101]             if (c0 == 'y' && c1 == 'e' && c2 == 's') {
[5102]                 u->buffering = 1;
[5103]             }
[5104]         }
[5105]     }
[5106] 
[5107]     return NGX_OK;
[5108] }
[5109] 
[5110] 
[5111] static ngx_int_t
[5112] ngx_http_upstream_process_charset(ngx_http_request_t *r, ngx_table_elt_t *h,
[5113]     ngx_uint_t offset)
[5114] {
[5115]     ngx_http_upstream_t  *u;
[5116] 
[5117]     u = r->upstream;
[5118] 
[5119]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_CHARSET) {
[5120]         return NGX_OK;
[5121]     }
[5122] 
[5123]     r->headers_out.override_charset = &h->value;
[5124] 
[5125]     return NGX_OK;
[5126] }
[5127] 
[5128] 
[5129] static ngx_int_t
[5130] ngx_http_upstream_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
[5131]     ngx_uint_t offset)
[5132] {
[5133]     ngx_table_elt_t      **ph;
[5134]     ngx_http_upstream_t   *u;
[5135] 
[5136]     u = r->upstream;
[5137]     ph = &u->headers_in.connection;
[5138] 
[5139]     while (*ph) { ph = &(*ph)->next; }
[5140] 
[5141]     *ph = h;
[5142]     h->next = NULL;
[5143] 
[5144]     if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
[5145]                          (u_char *) "close", 5 - 1)
[5146]         != NULL)
[5147]     {
[5148]         u->headers_in.connection_close = 1;
[5149]     }
[5150] 
[5151]     return NGX_OK;
[5152] }
[5153] 
[5154] 
[5155] static ngx_int_t
[5156] ngx_http_upstream_process_transfer_encoding(ngx_http_request_t *r,
[5157]     ngx_table_elt_t *h, ngx_uint_t offset)
[5158] {
[5159]     ngx_http_upstream_t  *u;
[5160] 
[5161]     u = r->upstream;
[5162] 
[5163]     if (u->headers_in.transfer_encoding) {
[5164]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[5165]                       "upstream sent duplicate header line: \"%V: %V\", "
[5166]                       "previous value: \"%V: %V\"",
[5167]                       &h->key, &h->value,
[5168]                       &u->headers_in.transfer_encoding->key,
[5169]                       &u->headers_in.transfer_encoding->value);
[5170]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[5171]     }
[5172] 
[5173]     if (u->headers_in.content_length) {
[5174]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[5175]                       "upstream sent \"Content-Length\" and "
[5176]                       "\"Transfer-Encoding\" headers at the same time");
[5177]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[5178]     }
[5179] 
[5180]     u->headers_in.transfer_encoding = h;
[5181]     h->next = NULL;
[5182] 
[5183]     if (h->value.len == 7
[5184]         && ngx_strncasecmp(h->value.data, (u_char *) "chunked", 7) == 0)
[5185]     {
[5186]         u->headers_in.chunked = 1;
[5187] 
[5188]     } else {
[5189]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[5190]                       "upstream sent unknown \"Transfer-Encoding\": \"%V\"",
[5191]                       &h->value);
[5192]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[5193]     }
[5194] 
[5195]     return NGX_OK;
[5196] }
[5197] 
[5198] 
[5199] static ngx_int_t
[5200] ngx_http_upstream_process_vary(ngx_http_request_t *r,
[5201]     ngx_table_elt_t *h, ngx_uint_t offset)
[5202] {
[5203]     ngx_table_elt_t      **ph;
[5204]     ngx_http_upstream_t   *u;
[5205] 
[5206]     u = r->upstream;
[5207]     ph = &u->headers_in.vary;
[5208] 
[5209]     while (*ph) { ph = &(*ph)->next; }
[5210] 
[5211]     *ph = h;
[5212]     h->next = NULL;
[5213] 
[5214] #if (NGX_HTTP_CACHE)
[5215]     {
[5216]     u_char     *p;
[5217]     size_t      len;
[5218]     ngx_str_t   vary;
[5219] 
[5220]     if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_VARY) {
[5221]         return NGX_OK;
[5222]     }
[5223] 
[5224]     if (r->cache == NULL || !u->cacheable) {
[5225]         return NGX_OK;
[5226]     }
[5227] 
[5228]     if (h->value.len == 1 && h->value.data[0] == '*') {
[5229]         u->cacheable = 0;
[5230]         return NGX_OK;
[5231]     }
[5232] 
[5233]     if (u->headers_in.vary->next) {
[5234] 
[5235]         len = 0;
[5236] 
[5237]         for (h = u->headers_in.vary; h; h = h->next) {
[5238]             len += h->value.len + 2;
[5239]         }
[5240] 
[5241]         len -= 2;
[5242] 
[5243]         p = ngx_pnalloc(r->pool, len);
[5244]         if (p == NULL) {
[5245]             return NGX_ERROR;
[5246]         }
[5247] 
[5248]         vary.len = len;
[5249]         vary.data = p;
[5250] 
[5251]         for (h = u->headers_in.vary; h; h = h->next) {
[5252]             p = ngx_copy(p, h->value.data, h->value.len);
[5253] 
[5254]             if (h->next == NULL) {
[5255]                 break;
[5256]             }
[5257] 
[5258]             *p++ = ','; *p++ = ' ';
[5259]         }
[5260] 
[5261]     } else {
[5262]         vary = h->value;
[5263]     }
[5264] 
[5265]     if (vary.len > NGX_HTTP_CACHE_VARY_LEN) {
[5266]         u->cacheable = 0;
[5267]     }
[5268] 
[5269]     r->cache->vary = vary;
[5270]     }
[5271] #endif
[5272] 
[5273]     return NGX_OK;
[5274] }
[5275] 
[5276] 
[5277] static ngx_int_t
[5278] ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
[5279]     ngx_uint_t offset)
[5280] {
[5281]     ngx_table_elt_t  *ho, **ph;
[5282] 
[5283]     ho = ngx_list_push(&r->headers_out.headers);
[5284]     if (ho == NULL) {
[5285]         return NGX_ERROR;
[5286]     }
[5287] 
[5288]     *ho = *h;
[5289] 
[5290]     if (offset) {
[5291]         ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
[5292]         *ph = ho;
[5293]         ho->next = NULL;
[5294]     }
[5295] 
[5296]     return NGX_OK;
[5297] }
[5298] 
[5299] 
[5300] static ngx_int_t
[5301] ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r,
[5302]     ngx_table_elt_t *h, ngx_uint_t offset)
[5303] {
[5304]     ngx_table_elt_t  *ho, **ph;
[5305] 
[5306]     ho = ngx_list_push(&r->headers_out.headers);
[5307]     if (ho == NULL) {
[5308]         return NGX_ERROR;
[5309]     }
[5310] 
[5311]     *ho = *h;
[5312] 
[5313]     ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
[5314] 
[5315]     while (*ph) { ph = &(*ph)->next; }
[5316] 
[5317]     *ph = ho;
[5318]     ho->next = NULL;
[5319] 
[5320]     return NGX_OK;
[5321] }
[5322] 
[5323] 
[5324] static ngx_int_t
[5325] ngx_http_upstream_copy_content_type(ngx_http_request_t *r, ngx_table_elt_t *h,
[5326]     ngx_uint_t offset)
[5327] {
[5328]     u_char  *p, *last;
[5329] 
[5330]     r->headers_out.content_type_len = h->value.len;
[5331]     r->headers_out.content_type = h->value;
[5332]     r->headers_out.content_type_lowcase = NULL;
[5333] 
[5334]     for (p = h->value.data; *p; p++) {
[5335] 
[5336]         if (*p != ';') {
[5337]             continue;
[5338]         }
[5339] 
[5340]         last = p;
[5341] 
[5342]         while (*++p == ' ') { /* void */ }
[5343] 
[5344]         if (*p == '\0') {
[5345]             return NGX_OK;
[5346]         }
[5347] 
[5348]         if (ngx_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
[5349]             continue;
[5350]         }
[5351] 
[5352]         p += 8;
[5353] 
[5354]         r->headers_out.content_type_len = last - h->value.data;
[5355] 
[5356]         if (*p == '"') {
[5357]             p++;
[5358]         }
[5359] 
[5360]         last = h->value.data + h->value.len;
[5361] 
[5362]         if (*(last - 1) == '"') {
[5363]             last--;
[5364]         }
[5365] 
[5366]         r->headers_out.charset.len = last - p;
[5367]         r->headers_out.charset.data = p;
[5368] 
[5369]         return NGX_OK;
[5370]     }
[5371] 
[5372]     return NGX_OK;
[5373] }
[5374] 
[5375] 
[5376] static ngx_int_t
[5377] ngx_http_upstream_copy_last_modified(ngx_http_request_t *r, ngx_table_elt_t *h,
[5378]     ngx_uint_t offset)
[5379] {
[5380]     ngx_table_elt_t  *ho;
[5381] 
[5382]     ho = ngx_list_push(&r->headers_out.headers);
[5383]     if (ho == NULL) {
[5384]         return NGX_ERROR;
[5385]     }
[5386] 
[5387]     *ho = *h;
[5388]     ho->next = NULL;
[5389] 
[5390]     r->headers_out.last_modified = ho;
[5391]     r->headers_out.last_modified_time =
[5392]                                     r->upstream->headers_in.last_modified_time;
[5393] 
[5394]     return NGX_OK;
[5395] }
[5396] 
[5397] 
[5398] static ngx_int_t
[5399] ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h,
[5400]     ngx_uint_t offset)
[5401] {
[5402]     ngx_int_t         rc;
[5403]     ngx_table_elt_t  *ho;
[5404] 
[5405]     ho = ngx_list_push(&r->headers_out.headers);
[5406]     if (ho == NULL) {
[5407]         return NGX_ERROR;
[5408]     }
[5409] 
[5410]     *ho = *h;
[5411]     ho->next = NULL;
[5412] 
[5413]     if (r->upstream->rewrite_redirect) {
[5414]         rc = r->upstream->rewrite_redirect(r, ho, 0);
[5415] 
[5416]         if (rc == NGX_DECLINED) {
[5417]             return NGX_OK;
[5418]         }
[5419] 
[5420]         if (rc == NGX_OK) {
[5421]             r->headers_out.location = ho;
[5422] 
[5423]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[5424]                            "rewritten location: \"%V\"", &ho->value);
[5425]         }
[5426] 
[5427]         return rc;
[5428]     }
[5429] 
[5430]     if (ho->value.data[0] != '/') {
[5431]         r->headers_out.location = ho;
[5432]     }
[5433] 
[5434]     /*
[5435]      * we do not set r->headers_out.location here to avoid handling
[5436]      * relative redirects in ngx_http_header_filter()
[5437]      */
[5438] 
[5439]     return NGX_OK;
[5440] }
[5441] 
[5442] 
[5443] static ngx_int_t
[5444] ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r, ngx_table_elt_t *h,
[5445]     ngx_uint_t offset)
[5446] {
[5447]     u_char           *p;
[5448]     ngx_int_t         rc;
[5449]     ngx_table_elt_t  *ho;
[5450] 
[5451]     ho = ngx_list_push(&r->headers_out.headers);
[5452]     if (ho == NULL) {
[5453]         return NGX_ERROR;
[5454]     }
[5455] 
[5456]     *ho = *h;
[5457]     ho->next = NULL;
[5458] 
[5459]     if (r->upstream->rewrite_redirect) {
[5460] 
[5461]         p = ngx_strcasestrn(ho->value.data, "url=", 4 - 1);
[5462] 
[5463]         if (p) {
[5464]             rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);
[5465] 
[5466]         } else {
[5467]             return NGX_OK;
[5468]         }
[5469] 
[5470]         if (rc == NGX_DECLINED) {
[5471]             return NGX_OK;
[5472]         }
[5473] 
[5474]         if (rc == NGX_OK) {
[5475]             r->headers_out.refresh = ho;
[5476] 
[5477]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[5478]                            "rewritten refresh: \"%V\"", &ho->value);
[5479]         }
[5480] 
[5481]         return rc;
[5482]     }
[5483] 
[5484]     r->headers_out.refresh = ho;
[5485] 
[5486]     return NGX_OK;
[5487] }
[5488] 
[5489] 
[5490] static ngx_int_t
[5491] ngx_http_upstream_rewrite_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h,
[5492]     ngx_uint_t offset)
[5493] {
[5494]     ngx_int_t         rc;
[5495]     ngx_table_elt_t  *ho;
[5496] 
[5497]     ho = ngx_list_push(&r->headers_out.headers);
[5498]     if (ho == NULL) {
[5499]         return NGX_ERROR;
[5500]     }
[5501] 
[5502]     *ho = *h;
[5503]     ho->next = NULL;
[5504] 
[5505]     if (r->upstream->rewrite_cookie) {
[5506]         rc = r->upstream->rewrite_cookie(r, ho);
[5507] 
[5508]         if (rc == NGX_DECLINED) {
[5509]             return NGX_OK;
[5510]         }
[5511] 
[5512] #if (NGX_DEBUG)
[5513]         if (rc == NGX_OK) {
[5514]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[5515]                            "rewritten cookie: \"%V\"", &ho->value);
[5516]         }
[5517] #endif
[5518] 
[5519]         return rc;
[5520]     }
[5521] 
[5522]     return NGX_OK;
[5523] }
[5524] 
[5525] 
[5526] static ngx_int_t
[5527] ngx_http_upstream_copy_allow_ranges(ngx_http_request_t *r,
[5528]     ngx_table_elt_t *h, ngx_uint_t offset)
[5529] {
[5530]     ngx_table_elt_t  *ho;
[5531] 
[5532]     if (r->upstream->conf->force_ranges) {
[5533]         return NGX_OK;
[5534]     }
[5535] 
[5536] #if (NGX_HTTP_CACHE)
[5537] 
[5538]     if (r->cached) {
[5539]         r->allow_ranges = 1;
[5540]         return NGX_OK;
[5541]     }
[5542] 
[5543]     if (r->upstream->cacheable) {
[5544]         r->allow_ranges = 1;
[5545]         r->single_range = 1;
[5546]         return NGX_OK;
[5547]     }
[5548] 
[5549] #endif
[5550] 
[5551]     ho = ngx_list_push(&r->headers_out.headers);
[5552]     if (ho == NULL) {
[5553]         return NGX_ERROR;
[5554]     }
[5555] 
[5556]     *ho = *h;
[5557]     ho->next = NULL;
[5558] 
[5559]     r->headers_out.accept_ranges = ho;
[5560] 
[5561]     return NGX_OK;
[5562] }
[5563] 
[5564] 
[5565] static ngx_int_t
[5566] ngx_http_upstream_add_variables(ngx_conf_t *cf)
[5567] {
[5568]     ngx_http_variable_t  *var, *v;
[5569] 
[5570]     for (v = ngx_http_upstream_vars; v->name.len; v++) {
[5571]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[5572]         if (var == NULL) {
[5573]             return NGX_ERROR;
[5574]         }
[5575] 
[5576]         var->get_handler = v->get_handler;
[5577]         var->data = v->data;
[5578]     }
[5579] 
[5580]     return NGX_OK;
[5581] }
[5582] 
[5583] 
[5584] static ngx_int_t
[5585] ngx_http_upstream_addr_variable(ngx_http_request_t *r,
[5586]     ngx_http_variable_value_t *v, uintptr_t data)
[5587] {
[5588]     u_char                     *p;
[5589]     size_t                      len;
[5590]     ngx_uint_t                  i;
[5591]     ngx_http_upstream_state_t  *state;
[5592] 
[5593]     v->valid = 1;
[5594]     v->no_cacheable = 0;
[5595]     v->not_found = 0;
[5596] 
[5597]     if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
[5598]         v->not_found = 1;
[5599]         return NGX_OK;
[5600]     }
[5601] 
[5602]     len = 0;
[5603]     state = r->upstream_states->elts;
[5604] 
[5605]     for (i = 0; i < r->upstream_states->nelts; i++) {
[5606]         if (state[i].peer) {
[5607]             len += state[i].peer->len + 2;
[5608] 
[5609]         } else {
[5610]             len += 3;
[5611]         }
[5612]     }
[5613] 
[5614]     p = ngx_pnalloc(r->pool, len);
[5615]     if (p == NULL) {
[5616]         return NGX_ERROR;
[5617]     }
[5618] 
[5619]     v->data = p;
[5620] 
[5621]     i = 0;
[5622] 
[5623]     for ( ;; ) {
[5624]         if (state[i].peer) {
[5625]             p = ngx_cpymem(p, state[i].peer->data, state[i].peer->len);
[5626]         }
[5627] 
[5628]         if (++i == r->upstream_states->nelts) {
[5629]             break;
[5630]         }
[5631] 
[5632]         if (state[i].peer) {
[5633]             *p++ = ',';
[5634]             *p++ = ' ';
[5635] 
[5636]         } else {
[5637]             *p++ = ' ';
[5638]             *p++ = ':';
[5639]             *p++ = ' ';
[5640] 
[5641]             if (++i == r->upstream_states->nelts) {
[5642]                 break;
[5643]             }
[5644] 
[5645]             continue;
[5646]         }
[5647]     }
[5648] 
[5649]     v->len = p - v->data;
[5650] 
[5651]     return NGX_OK;
[5652] }
[5653] 
[5654] 
[5655] static ngx_int_t
[5656] ngx_http_upstream_status_variable(ngx_http_request_t *r,
[5657]     ngx_http_variable_value_t *v, uintptr_t data)
[5658] {
[5659]     u_char                     *p;
[5660]     size_t                      len;
[5661]     ngx_uint_t                  i;
[5662]     ngx_http_upstream_state_t  *state;
[5663] 
[5664]     v->valid = 1;
[5665]     v->no_cacheable = 0;
[5666]     v->not_found = 0;
[5667] 
[5668]     if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
[5669]         v->not_found = 1;
[5670]         return NGX_OK;
[5671]     }
[5672] 
[5673]     len = r->upstream_states->nelts * (3 + 2);
[5674] 
[5675]     p = ngx_pnalloc(r->pool, len);
[5676]     if (p == NULL) {
[5677]         return NGX_ERROR;
[5678]     }
[5679] 
[5680]     v->data = p;
[5681] 
[5682]     i = 0;
[5683]     state = r->upstream_states->elts;
[5684] 
[5685]     for ( ;; ) {
[5686]         if (state[i].status) {
[5687]             p = ngx_sprintf(p, "%ui", state[i].status);
[5688] 
[5689]         } else {
[5690]             *p++ = '-';
[5691]         }
[5692] 
[5693]         if (++i == r->upstream_states->nelts) {
[5694]             break;
[5695]         }
[5696] 
[5697]         if (state[i].peer) {
[5698]             *p++ = ',';
[5699]             *p++ = ' ';
[5700] 
[5701]         } else {
[5702]             *p++ = ' ';
[5703]             *p++ = ':';
[5704]             *p++ = ' ';
[5705] 
[5706]             if (++i == r->upstream_states->nelts) {
[5707]                 break;
[5708]             }
[5709] 
[5710]             continue;
[5711]         }
[5712]     }
[5713] 
[5714]     v->len = p - v->data;
[5715] 
[5716]     return NGX_OK;
[5717] }
[5718] 
[5719] 
[5720] static ngx_int_t
[5721] ngx_http_upstream_response_time_variable(ngx_http_request_t *r,
[5722]     ngx_http_variable_value_t *v, uintptr_t data)
[5723] {
[5724]     u_char                     *p;
[5725]     size_t                      len;
[5726]     ngx_uint_t                  i;
[5727]     ngx_msec_int_t              ms;
[5728]     ngx_http_upstream_state_t  *state;
[5729] 
[5730]     v->valid = 1;
[5731]     v->no_cacheable = 0;
[5732]     v->not_found = 0;
[5733] 
[5734]     if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
[5735]         v->not_found = 1;
[5736]         return NGX_OK;
[5737]     }
[5738] 
[5739]     len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);
[5740] 
[5741]     p = ngx_pnalloc(r->pool, len);
[5742]     if (p == NULL) {
[5743]         return NGX_ERROR;
[5744]     }
[5745] 
[5746]     v->data = p;
[5747] 
[5748]     i = 0;
[5749]     state = r->upstream_states->elts;
[5750] 
[5751]     for ( ;; ) {
[5752] 
[5753]         if (data == 1) {
[5754]             ms = state[i].header_time;
[5755] 
[5756]         } else if (data == 2) {
[5757]             ms = state[i].connect_time;
[5758] 
[5759]         } else {
[5760]             ms = state[i].response_time;
[5761]         }
[5762] 
[5763]         if (ms != -1) {
[5764]             ms = ngx_max(ms, 0);
[5765]             p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);
[5766] 
[5767]         } else {
[5768]             *p++ = '-';
[5769]         }
[5770] 
[5771]         if (++i == r->upstream_states->nelts) {
[5772]             break;
[5773]         }
[5774] 
[5775]         if (state[i].peer) {
[5776]             *p++ = ',';
[5777]             *p++ = ' ';
[5778] 
[5779]         } else {
[5780]             *p++ = ' ';
[5781]             *p++ = ':';
[5782]             *p++ = ' ';
[5783] 
[5784]             if (++i == r->upstream_states->nelts) {
[5785]                 break;
[5786]             }
[5787] 
[5788]             continue;
[5789]         }
[5790]     }
[5791] 
[5792]     v->len = p - v->data;
[5793] 
[5794]     return NGX_OK;
[5795] }
[5796] 
[5797] 
[5798] static ngx_int_t
[5799] ngx_http_upstream_response_length_variable(ngx_http_request_t *r,
[5800]     ngx_http_variable_value_t *v, uintptr_t data)
[5801] {
[5802]     u_char                     *p;
[5803]     size_t                      len;
[5804]     ngx_uint_t                  i;
[5805]     ngx_http_upstream_state_t  *state;
[5806] 
[5807]     v->valid = 1;
[5808]     v->no_cacheable = 0;
[5809]     v->not_found = 0;
[5810] 
[5811]     if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
[5812]         v->not_found = 1;
[5813]         return NGX_OK;
[5814]     }
[5815] 
[5816]     len = r->upstream_states->nelts * (NGX_OFF_T_LEN + 2);
[5817] 
[5818]     p = ngx_pnalloc(r->pool, len);
[5819]     if (p == NULL) {
[5820]         return NGX_ERROR;
[5821]     }
[5822] 
[5823]     v->data = p;
[5824] 
[5825]     i = 0;
[5826]     state = r->upstream_states->elts;
[5827] 
[5828]     for ( ;; ) {
[5829] 
[5830]         if (data == 1) {
[5831]             p = ngx_sprintf(p, "%O", state[i].bytes_received);
[5832] 
[5833]         } else if (data == 2) {
[5834]             p = ngx_sprintf(p, "%O", state[i].bytes_sent);
[5835] 
[5836]         } else {
[5837]             p = ngx_sprintf(p, "%O", state[i].response_length);
[5838]         }
[5839] 
[5840]         if (++i == r->upstream_states->nelts) {
[5841]             break;
[5842]         }
[5843] 
[5844]         if (state[i].peer) {
[5845]             *p++ = ',';
[5846]             *p++ = ' ';
[5847] 
[5848]         } else {
[5849]             *p++ = ' ';
[5850]             *p++ = ':';
[5851]             *p++ = ' ';
[5852] 
[5853]             if (++i == r->upstream_states->nelts) {
[5854]                 break;
[5855]             }
[5856] 
[5857]             continue;
[5858]         }
[5859]     }
[5860] 
[5861]     v->len = p - v->data;
[5862] 
[5863]     return NGX_OK;
[5864] }
[5865] 
[5866] 
[5867] static ngx_int_t
[5868] ngx_http_upstream_header_variable(ngx_http_request_t *r,
[5869]     ngx_http_variable_value_t *v, uintptr_t data)
[5870] {
[5871]     if (r->upstream == NULL) {
[5872]         v->not_found = 1;
[5873]         return NGX_OK;
[5874]     }
[5875] 
[5876]     return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
[5877]                                          &r->upstream->headers_in.headers.part,
[5878]                                          sizeof("upstream_http_") - 1);
[5879] }
[5880] 
[5881] 
[5882] static ngx_int_t
[5883] ngx_http_upstream_trailer_variable(ngx_http_request_t *r,
[5884]     ngx_http_variable_value_t *v, uintptr_t data)
[5885] {
[5886]     if (r->upstream == NULL) {
[5887]         v->not_found = 1;
[5888]         return NGX_OK;
[5889]     }
[5890] 
[5891]     return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
[5892]                                         &r->upstream->headers_in.trailers.part,
[5893]                                         sizeof("upstream_trailer_") - 1);
[5894] }
[5895] 
[5896] 
[5897] static ngx_int_t
[5898] ngx_http_upstream_cookie_variable(ngx_http_request_t *r,
[5899]     ngx_http_variable_value_t *v, uintptr_t data)
[5900] {
[5901]     ngx_str_t  *name = (ngx_str_t *) data;
[5902] 
[5903]     ngx_str_t   cookie, s;
[5904] 
[5905]     if (r->upstream == NULL) {
[5906]         v->not_found = 1;
[5907]         return NGX_OK;
[5908]     }
[5909] 
[5910]     s.len = name->len - (sizeof("upstream_cookie_") - 1);
[5911]     s.data = name->data + sizeof("upstream_cookie_") - 1;
[5912] 
[5913]     if (ngx_http_parse_set_cookie_lines(r, r->upstream->headers_in.set_cookie,
[5914]                                         &s, &cookie)
[5915]         == NULL)
[5916]     {
[5917]         v->not_found = 1;
[5918]         return NGX_OK;
[5919]     }
[5920] 
[5921]     v->len = cookie.len;
[5922]     v->valid = 1;
[5923]     v->no_cacheable = 0;
[5924]     v->not_found = 0;
[5925]     v->data = cookie.data;
[5926] 
[5927]     return NGX_OK;
[5928] }
[5929] 
[5930] 
[5931] #if (NGX_HTTP_CACHE)
[5932] 
[5933] static ngx_int_t
[5934] ngx_http_upstream_cache_status(ngx_http_request_t *r,
[5935]     ngx_http_variable_value_t *v, uintptr_t data)
[5936] {
[5937]     ngx_uint_t  n;
[5938] 
[5939]     if (r->upstream == NULL || r->upstream->cache_status == 0) {
[5940]         v->not_found = 1;
[5941]         return NGX_OK;
[5942]     }
[5943] 
[5944]     n = r->upstream->cache_status - 1;
[5945] 
[5946]     v->valid = 1;
[5947]     v->no_cacheable = 0;
[5948]     v->not_found = 0;
[5949]     v->len = ngx_http_cache_status[n].len;
[5950]     v->data = ngx_http_cache_status[n].data;
[5951] 
[5952]     return NGX_OK;
[5953] }
[5954] 
[5955] 
[5956] static ngx_int_t
[5957] ngx_http_upstream_cache_last_modified(ngx_http_request_t *r,
[5958]     ngx_http_variable_value_t *v, uintptr_t data)
[5959] {
[5960]     u_char  *p;
[5961] 
[5962]     if (r->upstream == NULL
[5963]         || !r->upstream->conf->cache_revalidate
[5964]         || r->upstream->cache_status != NGX_HTTP_CACHE_EXPIRED
[5965]         || r->cache->last_modified == -1)
[5966]     {
[5967]         v->not_found = 1;
[5968]         return NGX_OK;
[5969]     }
[5970] 
[5971]     p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
[5972]     if (p == NULL) {
[5973]         return NGX_ERROR;
[5974]     }
[5975] 
[5976]     v->len = ngx_http_time(p, r->cache->last_modified) - p;
[5977]     v->valid = 1;
[5978]     v->no_cacheable = 0;
[5979]     v->not_found = 0;
[5980]     v->data = p;
[5981] 
[5982]     return NGX_OK;
[5983] }
[5984] 
[5985] 
[5986] static ngx_int_t
[5987] ngx_http_upstream_cache_etag(ngx_http_request_t *r,
[5988]     ngx_http_variable_value_t *v, uintptr_t data)
[5989] {
[5990]     if (r->upstream == NULL
[5991]         || !r->upstream->conf->cache_revalidate
[5992]         || r->upstream->cache_status != NGX_HTTP_CACHE_EXPIRED
[5993]         || r->cache->etag.len == 0)
[5994]     {
[5995]         v->not_found = 1;
[5996]         return NGX_OK;
[5997]     }
[5998] 
[5999]     v->valid = 1;
[6000]     v->no_cacheable = 0;
[6001]     v->not_found = 0;
[6002]     v->len = r->cache->etag.len;
[6003]     v->data = r->cache->etag.data;
[6004] 
[6005]     return NGX_OK;
[6006] }
[6007] 
[6008] #endif
[6009] 
[6010] 
[6011] static char *
[6012] ngx_http_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
[6013] {
[6014]     char                          *rv;
[6015]     void                          *mconf;
[6016]     ngx_str_t                     *value;
[6017]     ngx_url_t                      u;
[6018]     ngx_uint_t                     m;
[6019]     ngx_conf_t                     pcf;
[6020]     ngx_http_module_t             *module;
[6021]     ngx_http_conf_ctx_t           *ctx, *http_ctx;
[6022]     ngx_http_upstream_srv_conf_t  *uscf;
[6023] 
[6024]     ngx_memzero(&u, sizeof(ngx_url_t));
[6025] 
[6026]     value = cf->args->elts;
[6027]     u.host = value[1];
[6028]     u.no_resolve = 1;
[6029]     u.no_port = 1;
[6030] 
[6031]     uscf = ngx_http_upstream_add(cf, &u, NGX_HTTP_UPSTREAM_CREATE
[6032]                                          |NGX_HTTP_UPSTREAM_WEIGHT
[6033]                                          |NGX_HTTP_UPSTREAM_MAX_CONNS
[6034]                                          |NGX_HTTP_UPSTREAM_MAX_FAILS
[6035]                                          |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
[6036]                                          |NGX_HTTP_UPSTREAM_DOWN
[6037]                                          |NGX_HTTP_UPSTREAM_BACKUP);
[6038]     if (uscf == NULL) {
[6039]         return NGX_CONF_ERROR;
[6040]     }
[6041] 
[6042] 
[6043]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
[6044]     if (ctx == NULL) {
[6045]         return NGX_CONF_ERROR;
[6046]     }
[6047] 
[6048]     http_ctx = cf->ctx;
[6049]     ctx->main_conf = http_ctx->main_conf;
[6050] 
[6051]     /* the upstream{}'s srv_conf */
[6052] 
[6053]     ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[6054]     if (ctx->srv_conf == NULL) {
[6055]         return NGX_CONF_ERROR;
[6056]     }
[6057] 
[6058]     ctx->srv_conf[ngx_http_upstream_module.ctx_index] = uscf;
[6059] 
[6060]     uscf->srv_conf = ctx->srv_conf;
[6061] 
[6062] 
[6063]     /* the upstream{}'s loc_conf */
[6064] 
[6065]     ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[6066]     if (ctx->loc_conf == NULL) {
[6067]         return NGX_CONF_ERROR;
[6068]     }
[6069] 
[6070]     for (m = 0; cf->cycle->modules[m]; m++) {
[6071]         if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
[6072]             continue;
[6073]         }
[6074] 
[6075]         module = cf->cycle->modules[m]->ctx;
[6076] 
[6077]         if (module->create_srv_conf) {
[6078]             mconf = module->create_srv_conf(cf);
[6079]             if (mconf == NULL) {
[6080]                 return NGX_CONF_ERROR;
[6081]             }
[6082] 
[6083]             ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
[6084]         }
[6085] 
[6086]         if (module->create_loc_conf) {
[6087]             mconf = module->create_loc_conf(cf);
[6088]             if (mconf == NULL) {
[6089]                 return NGX_CONF_ERROR;
[6090]             }
[6091] 
[6092]             ctx->loc_conf[cf->cycle->modules[m]->ctx_index] = mconf;
[6093]         }
[6094]     }
[6095] 
[6096]     uscf->servers = ngx_array_create(cf->pool, 4,
[6097]                                      sizeof(ngx_http_upstream_server_t));
[6098]     if (uscf->servers == NULL) {
[6099]         return NGX_CONF_ERROR;
[6100]     }
[6101] 
[6102] 
[6103]     /* parse inside upstream{} */
[6104] 
[6105]     pcf = *cf;
[6106]     cf->ctx = ctx;
[6107]     cf->cmd_type = NGX_HTTP_UPS_CONF;
[6108] 
[6109]     rv = ngx_conf_parse(cf, NULL);
[6110] 
[6111]     *cf = pcf;
[6112] 
[6113]     if (rv != NGX_CONF_OK) {
[6114]         return rv;
[6115]     }
[6116] 
[6117]     if (uscf->servers->nelts == 0) {
[6118]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6119]                            "no servers are inside upstream");
[6120]         return NGX_CONF_ERROR;
[6121]     }
[6122] 
[6123]     return rv;
[6124] }
[6125] 
[6126] 
[6127] static char *
[6128] ngx_http_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[6129] {
[6130]     ngx_http_upstream_srv_conf_t  *uscf = conf;
[6131] 
[6132]     time_t                       fail_timeout;
[6133]     ngx_str_t                   *value, s;
[6134]     ngx_url_t                    u;
[6135]     ngx_int_t                    weight, max_conns, max_fails;
[6136]     ngx_uint_t                   i;
[6137]     ngx_http_upstream_server_t  *us;
[6138] 
[6139]     us = ngx_array_push(uscf->servers);
[6140]     if (us == NULL) {
[6141]         return NGX_CONF_ERROR;
[6142]     }
[6143] 
[6144]     ngx_memzero(us, sizeof(ngx_http_upstream_server_t));
[6145] 
[6146]     value = cf->args->elts;
[6147] 
[6148]     weight = 1;
[6149]     max_conns = 0;
[6150]     max_fails = 1;
[6151]     fail_timeout = 10;
[6152] 
[6153]     for (i = 2; i < cf->args->nelts; i++) {
[6154] 
[6155]         if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
[6156] 
[6157]             if (!(uscf->flags & NGX_HTTP_UPSTREAM_WEIGHT)) {
[6158]                 goto not_supported;
[6159]             }
[6160] 
[6161]             weight = ngx_atoi(&value[i].data[7], value[i].len - 7);
[6162] 
[6163]             if (weight == NGX_ERROR || weight == 0) {
[6164]                 goto invalid;
[6165]             }
[6166] 
[6167]             continue;
[6168]         }
[6169] 
[6170]         if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {
[6171] 
[6172]             if (!(uscf->flags & NGX_HTTP_UPSTREAM_MAX_CONNS)) {
[6173]                 goto not_supported;
[6174]             }
[6175] 
[6176]             max_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);
[6177] 
[6178]             if (max_conns == NGX_ERROR) {
[6179]                 goto invalid;
[6180]             }
[6181] 
[6182]             continue;
[6183]         }
[6184] 
[6185]         if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
[6186] 
[6187]             if (!(uscf->flags & NGX_HTTP_UPSTREAM_MAX_FAILS)) {
[6188]                 goto not_supported;
[6189]             }
[6190] 
[6191]             max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);
[6192] 
[6193]             if (max_fails == NGX_ERROR) {
[6194]                 goto invalid;
[6195]             }
[6196] 
[6197]             continue;
[6198]         }
[6199] 
[6200]         if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {
[6201] 
[6202]             if (!(uscf->flags & NGX_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
[6203]                 goto not_supported;
[6204]             }
[6205] 
[6206]             s.len = value[i].len - 13;
[6207]             s.data = &value[i].data[13];
[6208] 
[6209]             fail_timeout = ngx_parse_time(&s, 1);
[6210] 
[6211]             if (fail_timeout == (time_t) NGX_ERROR) {
[6212]                 goto invalid;
[6213]             }
[6214] 
[6215]             continue;
[6216]         }
[6217] 
[6218]         if (ngx_strcmp(value[i].data, "backup") == 0) {
[6219] 
[6220]             if (!(uscf->flags & NGX_HTTP_UPSTREAM_BACKUP)) {
[6221]                 goto not_supported;
[6222]             }
[6223] 
[6224]             us->backup = 1;
[6225] 
[6226]             continue;
[6227]         }
[6228] 
[6229]         if (ngx_strcmp(value[i].data, "down") == 0) {
[6230] 
[6231]             if (!(uscf->flags & NGX_HTTP_UPSTREAM_DOWN)) {
[6232]                 goto not_supported;
[6233]             }
[6234] 
[6235]             us->down = 1;
[6236] 
[6237]             continue;
[6238]         }
[6239] 
[6240]         goto invalid;
[6241]     }
[6242] 
[6243]     ngx_memzero(&u, sizeof(ngx_url_t));
[6244] 
[6245]     u.url = value[1];
[6246]     u.default_port = 80;
[6247] 
[6248]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[6249]         if (u.err) {
[6250]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6251]                                "%s in upstream \"%V\"", u.err, &u.url);
[6252]         }
[6253] 
[6254]         return NGX_CONF_ERROR;
[6255]     }
[6256] 
[6257]     us->name = u.url;
[6258]     us->addrs = u.addrs;
[6259]     us->naddrs = u.naddrs;
[6260]     us->weight = weight;
[6261]     us->max_conns = max_conns;
[6262]     us->max_fails = max_fails;
[6263]     us->fail_timeout = fail_timeout;
[6264] 
[6265]     return NGX_CONF_OK;
[6266] 
[6267] invalid:
[6268] 
[6269]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6270]                        "invalid parameter \"%V\"", &value[i]);
[6271] 
[6272]     return NGX_CONF_ERROR;
[6273] 
[6274] not_supported:
[6275] 
[6276]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6277]                        "balancing method does not support parameter \"%V\"",
[6278]                        &value[i]);
[6279] 
[6280]     return NGX_CONF_ERROR;
[6281] }
[6282] 
[6283] 
[6284] ngx_http_upstream_srv_conf_t *
[6285] ngx_http_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
[6286] {
[6287]     ngx_uint_t                      i;
[6288]     ngx_http_upstream_server_t     *us;
[6289]     ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
[6290]     ngx_http_upstream_main_conf_t  *umcf;
[6291] 
[6292]     if (!(flags & NGX_HTTP_UPSTREAM_CREATE)) {
[6293] 
[6294]         if (ngx_parse_url(cf->pool, u) != NGX_OK) {
[6295]             if (u->err) {
[6296]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6297]                                    "%s in upstream \"%V\"", u->err, &u->url);
[6298]             }
[6299] 
[6300]             return NULL;
[6301]         }
[6302]     }
[6303] 
[6304]     umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
[6305] 
[6306]     uscfp = umcf->upstreams.elts;
[6307] 
[6308]     for (i = 0; i < umcf->upstreams.nelts; i++) {
[6309] 
[6310]         if (uscfp[i]->host.len != u->host.len
[6311]             || ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
[6312]                != 0)
[6313]         {
[6314]             continue;
[6315]         }
[6316] 
[6317]         if ((flags & NGX_HTTP_UPSTREAM_CREATE)
[6318]              && (uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE))
[6319]         {
[6320]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6321]                                "duplicate upstream \"%V\"", &u->host);
[6322]             return NULL;
[6323]         }
[6324] 
[6325]         if ((uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE) && !u->no_port) {
[6326]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6327]                                "upstream \"%V\" may not have port %d",
[6328]                                &u->host, u->port);
[6329]             return NULL;
[6330]         }
[6331] 
[6332]         if ((flags & NGX_HTTP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
[6333]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[6334]                           "upstream \"%V\" may not have port %d in %s:%ui",
[6335]                           &u->host, uscfp[i]->port,
[6336]                           uscfp[i]->file_name, uscfp[i]->line);
[6337]             return NULL;
[6338]         }
[6339] 
[6340]         if (uscfp[i]->port && u->port
[6341]             && uscfp[i]->port != u->port)
[6342]         {
[6343]             continue;
[6344]         }
[6345] 
[6346]         if (flags & NGX_HTTP_UPSTREAM_CREATE) {
[6347]             uscfp[i]->flags = flags;
[6348]             uscfp[i]->port = 0;
[6349]         }
[6350] 
[6351]         return uscfp[i];
[6352]     }
[6353] 
[6354]     uscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_srv_conf_t));
[6355]     if (uscf == NULL) {
[6356]         return NULL;
[6357]     }
[6358] 
[6359]     uscf->flags = flags;
[6360]     uscf->host = u->host;
[6361]     uscf->file_name = cf->conf_file->file.name.data;
[6362]     uscf->line = cf->conf_file->line;
[6363]     uscf->port = u->port;
[6364]     uscf->no_port = u->no_port;
[6365] 
[6366]     if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
[6367]         uscf->servers = ngx_array_create(cf->pool, 1,
[6368]                                          sizeof(ngx_http_upstream_server_t));
[6369]         if (uscf->servers == NULL) {
[6370]             return NULL;
[6371]         }
[6372] 
[6373]         us = ngx_array_push(uscf->servers);
[6374]         if (us == NULL) {
[6375]             return NULL;
[6376]         }
[6377] 
[6378]         ngx_memzero(us, sizeof(ngx_http_upstream_server_t));
[6379] 
[6380]         us->addrs = u->addrs;
[6381]         us->naddrs = 1;
[6382]     }
[6383] 
[6384]     uscfp = ngx_array_push(&umcf->upstreams);
[6385]     if (uscfp == NULL) {
[6386]         return NULL;
[6387]     }
[6388] 
[6389]     *uscfp = uscf;
[6390] 
[6391]     return uscf;
[6392] }
[6393] 
[6394] 
[6395] char *
[6396] ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[6397]     void *conf)
[6398] {
[6399]     char  *p = conf;
[6400] 
[6401]     ngx_int_t                           rc;
[6402]     ngx_str_t                          *value;
[6403]     ngx_http_complex_value_t            cv;
[6404]     ngx_http_upstream_local_t         **plocal, *local;
[6405]     ngx_http_compile_complex_value_t    ccv;
[6406] 
[6407]     plocal = (ngx_http_upstream_local_t **) (p + cmd->offset);
[6408] 
[6409]     if (*plocal != NGX_CONF_UNSET_PTR) {
[6410]         return "is duplicate";
[6411]     }
[6412] 
[6413]     value = cf->args->elts;
[6414] 
[6415]     if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
[6416]         *plocal = NULL;
[6417]         return NGX_CONF_OK;
[6418]     }
[6419] 
[6420]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[6421] 
[6422]     ccv.cf = cf;
[6423]     ccv.value = &value[1];
[6424]     ccv.complex_value = &cv;
[6425] 
[6426]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[6427]         return NGX_CONF_ERROR;
[6428]     }
[6429] 
[6430]     local = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_local_t));
[6431]     if (local == NULL) {
[6432]         return NGX_CONF_ERROR;
[6433]     }
[6434] 
[6435]     *plocal = local;
[6436] 
[6437]     if (cv.lengths) {
[6438]         local->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[6439]         if (local->value == NULL) {
[6440]             return NGX_CONF_ERROR;
[6441]         }
[6442] 
[6443]         *local->value = cv;
[6444] 
[6445]     } else {
[6446]         local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
[6447]         if (local->addr == NULL) {
[6448]             return NGX_CONF_ERROR;
[6449]         }
[6450] 
[6451]         rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
[6452]                                  value[1].len);
[6453] 
[6454]         switch (rc) {
[6455]         case NGX_OK:
[6456]             local->addr->name = value[1];
[6457]             break;
[6458] 
[6459]         case NGX_DECLINED:
[6460]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6461]                                "invalid address \"%V\"", &value[1]);
[6462]             /* fall through */
[6463] 
[6464]         default:
[6465]             return NGX_CONF_ERROR;
[6466]         }
[6467]     }
[6468] 
[6469]     if (cf->args->nelts > 2) {
[6470]         if (ngx_strcmp(value[2].data, "transparent") == 0) {
[6471] #if (NGX_HAVE_TRANSPARENT_PROXY)
[6472]             ngx_core_conf_t  *ccf;
[6473] 
[6474]             ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
[6475]                                                    ngx_core_module);
[6476] 
[6477]             ccf->transparent = 1;
[6478]             local->transparent = 1;
[6479] #else
[6480]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6481]                                "transparent proxying is not supported "
[6482]                                "on this platform, ignored");
[6483] #endif
[6484]         } else {
[6485]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6486]                                "invalid parameter \"%V\"", &value[2]);
[6487]             return NGX_CONF_ERROR;
[6488]         }
[6489]     }
[6490] 
[6491]     return NGX_CONF_OK;
[6492] }
[6493] 
[6494] 
[6495] static ngx_int_t
[6496] ngx_http_upstream_set_local(ngx_http_request_t *r, ngx_http_upstream_t *u,
[6497]     ngx_http_upstream_local_t *local)
[6498] {
[6499]     ngx_int_t    rc;
[6500]     ngx_str_t    val;
[6501]     ngx_addr_t  *addr;
[6502] 
[6503]     if (local == NULL) {
[6504]         u->peer.local = NULL;
[6505]         return NGX_OK;
[6506]     }
[6507] 
[6508] #if (NGX_HAVE_TRANSPARENT_PROXY)
[6509]     u->peer.transparent = local->transparent;
[6510] #endif
[6511] 
[6512]     if (local->value == NULL) {
[6513]         u->peer.local = local->addr;
[6514]         return NGX_OK;
[6515]     }
[6516] 
[6517]     if (ngx_http_complex_value(r, local->value, &val) != NGX_OK) {
[6518]         return NGX_ERROR;
[6519]     }
[6520] 
[6521]     if (val.len == 0) {
[6522]         return NGX_OK;
[6523]     }
[6524] 
[6525]     addr = ngx_palloc(r->pool, sizeof(ngx_addr_t));
[6526]     if (addr == NULL) {
[6527]         return NGX_ERROR;
[6528]     }
[6529] 
[6530]     rc = ngx_parse_addr_port(r->pool, addr, val.data, val.len);
[6531]     if (rc == NGX_ERROR) {
[6532]         return NGX_ERROR;
[6533]     }
[6534] 
[6535]     if (rc != NGX_OK) {
[6536]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[6537]                       "invalid local address \"%V\"", &val);
[6538]         return NGX_OK;
[6539]     }
[6540] 
[6541]     addr->name = val;
[6542]     u->peer.local = addr;
[6543] 
[6544]     return NGX_OK;
[6545] }
[6546] 
[6547] 
[6548] char *
[6549] ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[6550]     void *conf)
[6551] {
[6552]     char  *p = conf;
[6553] 
[6554]     ngx_str_t                   *value;
[6555]     ngx_array_t                **a;
[6556]     ngx_http_upstream_param_t   *param;
[6557] 
[6558]     a = (ngx_array_t **) (p + cmd->offset);
[6559] 
[6560]     if (*a == NULL) {
[6561]         *a = ngx_array_create(cf->pool, 4, sizeof(ngx_http_upstream_param_t));
[6562]         if (*a == NULL) {
[6563]             return NGX_CONF_ERROR;
[6564]         }
[6565]     }
[6566] 
[6567]     param = ngx_array_push(*a);
[6568]     if (param == NULL) {
[6569]         return NGX_CONF_ERROR;
[6570]     }
[6571] 
[6572]     value = cf->args->elts;
[6573] 
[6574]     param->key = value[1];
[6575]     param->value = value[2];
[6576]     param->skip_empty = 0;
[6577] 
[6578]     if (cf->args->nelts == 4) {
[6579]         if (ngx_strcmp(value[3].data, "if_not_empty") != 0) {
[6580]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[6581]                                "invalid parameter \"%V\"", &value[3]);
[6582]             return NGX_CONF_ERROR;
[6583]         }
[6584] 
[6585]         param->skip_empty = 1;
[6586]     }
[6587] 
[6588]     return NGX_CONF_OK;
[6589] }
[6590] 
[6591] 
[6592] ngx_int_t
[6593] ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
[6594]     ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
[6595]     ngx_str_t *default_hide_headers, ngx_hash_init_t *hash)
[6596] {
[6597]     ngx_str_t       *h;
[6598]     ngx_uint_t       i, j;
[6599]     ngx_array_t      hide_headers;
[6600]     ngx_hash_key_t  *hk;
[6601] 
[6602]     if (conf->hide_headers == NGX_CONF_UNSET_PTR
[6603]         && conf->pass_headers == NGX_CONF_UNSET_PTR)
[6604]     {
[6605]         conf->hide_headers = prev->hide_headers;
[6606]         conf->pass_headers = prev->pass_headers;
[6607] 
[6608]         conf->hide_headers_hash = prev->hide_headers_hash;
[6609] 
[6610]         if (conf->hide_headers_hash.buckets) {
[6611]             return NGX_OK;
[6612]         }
[6613] 
[6614]     } else {
[6615]         if (conf->hide_headers == NGX_CONF_UNSET_PTR) {
[6616]             conf->hide_headers = prev->hide_headers;
[6617]         }
[6618] 
[6619]         if (conf->pass_headers == NGX_CONF_UNSET_PTR) {
[6620]             conf->pass_headers = prev->pass_headers;
[6621]         }
[6622]     }
[6623] 
[6624]     if (ngx_array_init(&hide_headers, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
[6625]         != NGX_OK)
[6626]     {
[6627]         return NGX_ERROR;
[6628]     }
[6629] 
[6630]     for (h = default_hide_headers; h->len; h++) {
[6631]         hk = ngx_array_push(&hide_headers);
[6632]         if (hk == NULL) {
[6633]             return NGX_ERROR;
[6634]         }
[6635] 
[6636]         hk->key = *h;
[6637]         hk->key_hash = ngx_hash_key_lc(h->data, h->len);
[6638]         hk->value = (void *) 1;
[6639]     }
[6640] 
[6641]     if (conf->hide_headers != NGX_CONF_UNSET_PTR) {
[6642] 
[6643]         h = conf->hide_headers->elts;
[6644] 
[6645]         for (i = 0; i < conf->hide_headers->nelts; i++) {
[6646] 
[6647]             hk = hide_headers.elts;
[6648] 
[6649]             for (j = 0; j < hide_headers.nelts; j++) {
[6650]                 if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
[6651]                     goto exist;
[6652]                 }
[6653]             }
[6654] 
[6655]             hk = ngx_array_push(&hide_headers);
[6656]             if (hk == NULL) {
[6657]                 return NGX_ERROR;
[6658]             }
[6659] 
[6660]             hk->key = h[i];
[6661]             hk->key_hash = ngx_hash_key_lc(h[i].data, h[i].len);
[6662]             hk->value = (void *) 1;
[6663] 
[6664]         exist:
[6665] 
[6666]             continue;
[6667]         }
[6668]     }
[6669] 
[6670]     if (conf->pass_headers != NGX_CONF_UNSET_PTR) {
[6671] 
[6672]         h = conf->pass_headers->elts;
[6673]         hk = hide_headers.elts;
[6674] 
[6675]         for (i = 0; i < conf->pass_headers->nelts; i++) {
[6676]             for (j = 0; j < hide_headers.nelts; j++) {
[6677] 
[6678]                 if (hk[j].key.data == NULL) {
[6679]                     continue;
[6680]                 }
[6681] 
[6682]                 if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
[6683]                     hk[j].key.data = NULL;
[6684]                     break;
[6685]                 }
[6686]             }
[6687]         }
[6688]     }
[6689] 
[6690]     hash->hash = &conf->hide_headers_hash;
[6691]     hash->key = ngx_hash_key_lc;
[6692]     hash->pool = cf->pool;
[6693]     hash->temp_pool = NULL;
[6694] 
[6695]     if (ngx_hash_init(hash, hide_headers.elts, hide_headers.nelts) != NGX_OK) {
[6696]         return NGX_ERROR;
[6697]     }
[6698] 
[6699]     /*
[6700]      * special handling to preserve conf->hide_headers_hash
[6701]      * in the "http" section to inherit it to all servers
[6702]      */
[6703] 
[6704]     if (prev->hide_headers_hash.buckets == NULL
[6705]         && conf->hide_headers == prev->hide_headers
[6706]         && conf->pass_headers == prev->pass_headers)
[6707]     {
[6708]         prev->hide_headers_hash = conf->hide_headers_hash;
[6709]     }
[6710] 
[6711]     return NGX_OK;
[6712] }
[6713] 
[6714] 
[6715] static void *
[6716] ngx_http_upstream_create_main_conf(ngx_conf_t *cf)
[6717] {
[6718]     ngx_http_upstream_main_conf_t  *umcf;
[6719] 
[6720]     umcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_main_conf_t));
[6721]     if (umcf == NULL) {
[6722]         return NULL;
[6723]     }
[6724] 
[6725]     if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
[6726]                        sizeof(ngx_http_upstream_srv_conf_t *))
[6727]         != NGX_OK)
[6728]     {
[6729]         return NULL;
[6730]     }
[6731] 
[6732]     return umcf;
[6733] }
[6734] 
[6735] 
[6736] static char *
[6737] ngx_http_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
[6738] {
[6739]     ngx_http_upstream_main_conf_t  *umcf = conf;
[6740] 
[6741]     ngx_uint_t                      i;
[6742]     ngx_array_t                     headers_in;
[6743]     ngx_hash_key_t                 *hk;
[6744]     ngx_hash_init_t                 hash;
[6745]     ngx_http_upstream_init_pt       init;
[6746]     ngx_http_upstream_header_t     *header;
[6747]     ngx_http_upstream_srv_conf_t  **uscfp;
[6748] 
[6749]     uscfp = umcf->upstreams.elts;
[6750] 
[6751]     for (i = 0; i < umcf->upstreams.nelts; i++) {
[6752] 
[6753]         init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
[6754]                                             ngx_http_upstream_init_round_robin;
[6755] 
[6756]         if (init(cf, uscfp[i]) != NGX_OK) {
[6757]             return NGX_CONF_ERROR;
[6758]         }
[6759]     }
[6760] 
[6761] 
[6762]     /* upstream_headers_in_hash */
[6763] 
[6764]     if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
[6765]         != NGX_OK)
[6766]     {
[6767]         return NGX_CONF_ERROR;
[6768]     }
[6769] 
[6770]     for (header = ngx_http_upstream_headers_in; header->name.len; header++) {
[6771]         hk = ngx_array_push(&headers_in);
[6772]         if (hk == NULL) {
[6773]             return NGX_CONF_ERROR;
[6774]         }
[6775] 
[6776]         hk->key = header->name;
[6777]         hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
[6778]         hk->value = header;
[6779]     }
[6780] 
[6781]     hash.hash = &umcf->headers_in_hash;
[6782]     hash.key = ngx_hash_key_lc;
[6783]     hash.max_size = 512;
[6784]     hash.bucket_size = ngx_align(64, ngx_cacheline_size);
[6785]     hash.name = "upstream_headers_in_hash";
[6786]     hash.pool = cf->pool;
[6787]     hash.temp_pool = NULL;
[6788] 
[6789]     if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
[6790]         return NGX_CONF_ERROR;
[6791]     }
[6792] 
[6793]     return NGX_CONF_OK;
[6794] }
