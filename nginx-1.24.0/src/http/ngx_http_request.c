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
[13] static void ngx_http_wait_request_handler(ngx_event_t *ev);
[14] static ngx_http_request_t *ngx_http_alloc_request(ngx_connection_t *c);
[15] static void ngx_http_process_request_line(ngx_event_t *rev);
[16] static void ngx_http_process_request_headers(ngx_event_t *rev);
[17] static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);
[18] static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
[19]     ngx_uint_t request_line);
[20] 
[21] static ngx_int_t ngx_http_process_header_line(ngx_http_request_t *r,
[22]     ngx_table_elt_t *h, ngx_uint_t offset);
[23] static ngx_int_t ngx_http_process_unique_header_line(ngx_http_request_t *r,
[24]     ngx_table_elt_t *h, ngx_uint_t offset);
[25] static ngx_int_t ngx_http_process_host(ngx_http_request_t *r,
[26]     ngx_table_elt_t *h, ngx_uint_t offset);
[27] static ngx_int_t ngx_http_process_connection(ngx_http_request_t *r,
[28]     ngx_table_elt_t *h, ngx_uint_t offset);
[29] static ngx_int_t ngx_http_process_user_agent(ngx_http_request_t *r,
[30]     ngx_table_elt_t *h, ngx_uint_t offset);
[31] 
[32] static ngx_int_t ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool,
[33]     ngx_uint_t alloc);
[34] static ngx_int_t ngx_http_set_virtual_server(ngx_http_request_t *r,
[35]     ngx_str_t *host);
[36] static ngx_int_t ngx_http_find_virtual_server(ngx_connection_t *c,
[37]     ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
[38]     ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp);
[39] 
[40] static void ngx_http_request_handler(ngx_event_t *ev);
[41] static void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc);
[42] static void ngx_http_terminate_handler(ngx_http_request_t *r);
[43] static void ngx_http_finalize_connection(ngx_http_request_t *r);
[44] static ngx_int_t ngx_http_set_write_handler(ngx_http_request_t *r);
[45] static void ngx_http_writer(ngx_http_request_t *r);
[46] static void ngx_http_request_finalizer(ngx_http_request_t *r);
[47] 
[48] static void ngx_http_set_keepalive(ngx_http_request_t *r);
[49] static void ngx_http_keepalive_handler(ngx_event_t *ev);
[50] static void ngx_http_set_lingering_close(ngx_connection_t *c);
[51] static void ngx_http_lingering_close_handler(ngx_event_t *ev);
[52] static ngx_int_t ngx_http_post_action(ngx_http_request_t *r);
[53] static void ngx_http_close_request(ngx_http_request_t *r, ngx_int_t error);
[54] static void ngx_http_log_request(ngx_http_request_t *r);
[55] 
[56] static u_char *ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len);
[57] static u_char *ngx_http_log_error_handler(ngx_http_request_t *r,
[58]     ngx_http_request_t *sr, u_char *buf, size_t len);
[59] 
[60] #if (NGX_HTTP_SSL)
[61] static void ngx_http_ssl_handshake(ngx_event_t *rev);
[62] static void ngx_http_ssl_handshake_handler(ngx_connection_t *c);
[63] #endif
[64] 
[65] 
[66] static char *ngx_http_client_errors[] = {
[67] 
[68]     /* NGX_HTTP_PARSE_INVALID_METHOD */
[69]     "client sent invalid method",
[70] 
[71]     /* NGX_HTTP_PARSE_INVALID_REQUEST */
[72]     "client sent invalid request",
[73] 
[74]     /* NGX_HTTP_PARSE_INVALID_VERSION */
[75]     "client sent invalid version",
[76] 
[77]     /* NGX_HTTP_PARSE_INVALID_09_METHOD */
[78]     "client sent invalid method in HTTP/0.9 request"
[79] };
[80] 
[81] 
[82] ngx_http_header_t  ngx_http_headers_in[] = {
[83]     { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host),
[84]                  ngx_http_process_host },
[85] 
[86]     { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection),
[87]                  ngx_http_process_connection },
[88] 
[89]     { ngx_string("If-Modified-Since"),
[90]                  offsetof(ngx_http_headers_in_t, if_modified_since),
[91]                  ngx_http_process_unique_header_line },
[92] 
[93]     { ngx_string("If-Unmodified-Since"),
[94]                  offsetof(ngx_http_headers_in_t, if_unmodified_since),
[95]                  ngx_http_process_unique_header_line },
[96] 
[97]     { ngx_string("If-Match"),
[98]                  offsetof(ngx_http_headers_in_t, if_match),
[99]                  ngx_http_process_unique_header_line },
[100] 
[101]     { ngx_string("If-None-Match"),
[102]                  offsetof(ngx_http_headers_in_t, if_none_match),
[103]                  ngx_http_process_unique_header_line },
[104] 
[105]     { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent),
[106]                  ngx_http_process_user_agent },
[107] 
[108]     { ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer),
[109]                  ngx_http_process_header_line },
[110] 
[111]     { ngx_string("Content-Length"),
[112]                  offsetof(ngx_http_headers_in_t, content_length),
[113]                  ngx_http_process_unique_header_line },
[114] 
[115]     { ngx_string("Content-Range"),
[116]                  offsetof(ngx_http_headers_in_t, content_range),
[117]                  ngx_http_process_unique_header_line },
[118] 
[119]     { ngx_string("Content-Type"),
[120]                  offsetof(ngx_http_headers_in_t, content_type),
[121]                  ngx_http_process_header_line },
[122] 
[123]     { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range),
[124]                  ngx_http_process_header_line },
[125] 
[126]     { ngx_string("If-Range"),
[127]                  offsetof(ngx_http_headers_in_t, if_range),
[128]                  ngx_http_process_unique_header_line },
[129] 
[130]     { ngx_string("Transfer-Encoding"),
[131]                  offsetof(ngx_http_headers_in_t, transfer_encoding),
[132]                  ngx_http_process_unique_header_line },
[133] 
[134]     { ngx_string("TE"),
[135]                  offsetof(ngx_http_headers_in_t, te),
[136]                  ngx_http_process_header_line },
[137] 
[138]     { ngx_string("Expect"),
[139]                  offsetof(ngx_http_headers_in_t, expect),
[140]                  ngx_http_process_unique_header_line },
[141] 
[142]     { ngx_string("Upgrade"),
[143]                  offsetof(ngx_http_headers_in_t, upgrade),
[144]                  ngx_http_process_header_line },
[145] 
[146] #if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
[147]     { ngx_string("Accept-Encoding"),
[148]                  offsetof(ngx_http_headers_in_t, accept_encoding),
[149]                  ngx_http_process_header_line },
[150] 
[151]     { ngx_string("Via"), offsetof(ngx_http_headers_in_t, via),
[152]                  ngx_http_process_header_line },
[153] #endif
[154] 
[155]     { ngx_string("Authorization"),
[156]                  offsetof(ngx_http_headers_in_t, authorization),
[157]                  ngx_http_process_unique_header_line },
[158] 
[159]     { ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive),
[160]                  ngx_http_process_header_line },
[161] 
[162] #if (NGX_HTTP_X_FORWARDED_FOR)
[163]     { ngx_string("X-Forwarded-For"),
[164]                  offsetof(ngx_http_headers_in_t, x_forwarded_for),
[165]                  ngx_http_process_header_line },
[166] #endif
[167] 
[168] #if (NGX_HTTP_REALIP)
[169]     { ngx_string("X-Real-IP"),
[170]                  offsetof(ngx_http_headers_in_t, x_real_ip),
[171]                  ngx_http_process_header_line },
[172] #endif
[173] 
[174] #if (NGX_HTTP_HEADERS)
[175]     { ngx_string("Accept"), offsetof(ngx_http_headers_in_t, accept),
[176]                  ngx_http_process_header_line },
[177] 
[178]     { ngx_string("Accept-Language"),
[179]                  offsetof(ngx_http_headers_in_t, accept_language),
[180]                  ngx_http_process_header_line },
[181] #endif
[182] 
[183] #if (NGX_HTTP_DAV)
[184]     { ngx_string("Depth"), offsetof(ngx_http_headers_in_t, depth),
[185]                  ngx_http_process_header_line },
[186] 
[187]     { ngx_string("Destination"), offsetof(ngx_http_headers_in_t, destination),
[188]                  ngx_http_process_header_line },
[189] 
[190]     { ngx_string("Overwrite"), offsetof(ngx_http_headers_in_t, overwrite),
[191]                  ngx_http_process_header_line },
[192] 
[193]     { ngx_string("Date"), offsetof(ngx_http_headers_in_t, date),
[194]                  ngx_http_process_header_line },
[195] #endif
[196] 
[197]     { ngx_string("Cookie"), offsetof(ngx_http_headers_in_t, cookie),
[198]                  ngx_http_process_header_line },
[199] 
[200]     { ngx_null_string, 0, NULL }
[201] };
[202] 
[203] 
[204] void
[205] ngx_http_init_connection(ngx_connection_t *c)
[206] {
[207]     ngx_uint_t                 i;
[208]     ngx_event_t               *rev;
[209]     struct sockaddr_in        *sin;
[210]     ngx_http_port_t           *port;
[211]     ngx_http_in_addr_t        *addr;
[212]     ngx_http_log_ctx_t        *ctx;
[213]     ngx_http_connection_t     *hc;
[214]     ngx_http_core_srv_conf_t  *cscf;
[215] #if (NGX_HAVE_INET6)
[216]     struct sockaddr_in6       *sin6;
[217]     ngx_http_in6_addr_t       *addr6;
[218] #endif
[219] 
[220]     hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
[221]     if (hc == NULL) {
[222]         ngx_http_close_connection(c);
[223]         return;
[224]     }
[225] 
[226]     c->data = hc;
[227] 
[228]     /* find the server configuration for the address:port */
[229] 
[230]     port = c->listening->servers;
[231] 
[232]     if (port->naddrs > 1) {
[233] 
[234]         /*
[235]          * there are several addresses on this port and one of them
[236]          * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
[237]          * is required to determine a server address
[238]          */
[239] 
[240]         if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
[241]             ngx_http_close_connection(c);
[242]             return;
[243]         }
[244] 
[245]         switch (c->local_sockaddr->sa_family) {
[246] 
[247] #if (NGX_HAVE_INET6)
[248]         case AF_INET6:
[249]             sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
[250] 
[251]             addr6 = port->addrs;
[252] 
[253]             /* the last address is "*" */
[254] 
[255]             for (i = 0; i < port->naddrs - 1; i++) {
[256]                 if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
[257]                     break;
[258]                 }
[259]             }
[260] 
[261]             hc->addr_conf = &addr6[i].conf;
[262] 
[263]             break;
[264] #endif
[265] 
[266]         default: /* AF_INET */
[267]             sin = (struct sockaddr_in *) c->local_sockaddr;
[268] 
[269]             addr = port->addrs;
[270] 
[271]             /* the last address is "*" */
[272] 
[273]             for (i = 0; i < port->naddrs - 1; i++) {
[274]                 if (addr[i].addr == sin->sin_addr.s_addr) {
[275]                     break;
[276]                 }
[277]             }
[278] 
[279]             hc->addr_conf = &addr[i].conf;
[280] 
[281]             break;
[282]         }
[283] 
[284]     } else {
[285] 
[286]         switch (c->local_sockaddr->sa_family) {
[287] 
[288] #if (NGX_HAVE_INET6)
[289]         case AF_INET6:
[290]             addr6 = port->addrs;
[291]             hc->addr_conf = &addr6[0].conf;
[292]             break;
[293] #endif
[294] 
[295]         default: /* AF_INET */
[296]             addr = port->addrs;
[297]             hc->addr_conf = &addr[0].conf;
[298]             break;
[299]         }
[300]     }
[301] 
[302]     /* the default server configuration for the address:port */
[303]     hc->conf_ctx = hc->addr_conf->default_server->ctx;
[304] 
[305]     ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
[306]     if (ctx == NULL) {
[307]         ngx_http_close_connection(c);
[308]         return;
[309]     }
[310] 
[311]     ctx->connection = c;
[312]     ctx->request = NULL;
[313]     ctx->current_request = NULL;
[314] 
[315]     c->log->connection = c->number;
[316]     c->log->handler = ngx_http_log_error;
[317]     c->log->data = ctx;
[318]     c->log->action = "waiting for request";
[319] 
[320]     c->log_error = NGX_ERROR_INFO;
[321] 
[322]     rev = c->read;
[323]     rev->handler = ngx_http_wait_request_handler;
[324]     c->write->handler = ngx_http_empty_handler;
[325] 
[326] #if (NGX_HTTP_V2)
[327]     if (hc->addr_conf->http2) {
[328]         rev->handler = ngx_http_v2_init;
[329]     }
[330] #endif
[331] 
[332] #if (NGX_HTTP_SSL)
[333]     {
[334]     ngx_http_ssl_srv_conf_t  *sscf;
[335] 
[336]     sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);
[337] 
[338]     if (sscf->enable || hc->addr_conf->ssl) {
[339]         hc->ssl = 1;
[340]         c->log->action = "SSL handshaking";
[341]         rev->handler = ngx_http_ssl_handshake;
[342]     }
[343]     }
[344] #endif
[345] 
[346]     if (hc->addr_conf->proxy_protocol) {
[347]         hc->proxy_protocol = 1;
[348]         c->log->action = "reading PROXY protocol";
[349]     }
[350] 
[351]     if (rev->ready) {
[352]         /* the deferred accept(), iocp */
[353] 
[354]         if (ngx_use_accept_mutex) {
[355]             ngx_post_event(rev, &ngx_posted_events);
[356]             return;
[357]         }
[358] 
[359]         rev->handler(rev);
[360]         return;
[361]     }
[362] 
[363]     cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);
[364] 
[365]     ngx_add_timer(rev, cscf->client_header_timeout);
[366]     ngx_reusable_connection(c, 1);
[367] 
[368]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[369]         ngx_http_close_connection(c);
[370]         return;
[371]     }
[372] }
[373] 
[374] 
[375] static void
[376] ngx_http_wait_request_handler(ngx_event_t *rev)
[377] {
[378]     u_char                    *p;
[379]     size_t                     size;
[380]     ssize_t                    n;
[381]     ngx_buf_t                 *b;
[382]     ngx_connection_t          *c;
[383]     ngx_http_connection_t     *hc;
[384]     ngx_http_core_srv_conf_t  *cscf;
[385] 
[386]     c = rev->data;
[387] 
[388]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");
[389] 
[390]     if (rev->timedout) {
[391]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[392]         ngx_http_close_connection(c);
[393]         return;
[394]     }
[395] 
[396]     if (c->close) {
[397]         ngx_http_close_connection(c);
[398]         return;
[399]     }
[400] 
[401]     hc = c->data;
[402]     cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);
[403] 
[404]     size = cscf->client_header_buffer_size;
[405] 
[406]     b = c->buffer;
[407] 
[408]     if (b == NULL) {
[409]         b = ngx_create_temp_buf(c->pool, size);
[410]         if (b == NULL) {
[411]             ngx_http_close_connection(c);
[412]             return;
[413]         }
[414] 
[415]         c->buffer = b;
[416] 
[417]     } else if (b->start == NULL) {
[418] 
[419]         b->start = ngx_palloc(c->pool, size);
[420]         if (b->start == NULL) {
[421]             ngx_http_close_connection(c);
[422]             return;
[423]         }
[424] 
[425]         b->pos = b->start;
[426]         b->last = b->start;
[427]         b->end = b->last + size;
[428]     }
[429] 
[430]     n = c->recv(c, b->last, size);
[431] 
[432]     if (n == NGX_AGAIN) {
[433] 
[434]         if (!rev->timer_set) {
[435]             ngx_add_timer(rev, cscf->client_header_timeout);
[436]             ngx_reusable_connection(c, 1);
[437]         }
[438] 
[439]         if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[440]             ngx_http_close_connection(c);
[441]             return;
[442]         }
[443] 
[444]         /*
[445]          * We are trying to not hold c->buffer's memory for an idle connection.
[446]          */
[447] 
[448]         if (ngx_pfree(c->pool, b->start) == NGX_OK) {
[449]             b->start = NULL;
[450]         }
[451] 
[452]         return;
[453]     }
[454] 
[455]     if (n == NGX_ERROR) {
[456]         ngx_http_close_connection(c);
[457]         return;
[458]     }
[459] 
[460]     if (n == 0) {
[461]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[462]                       "client closed connection");
[463]         ngx_http_close_connection(c);
[464]         return;
[465]     }
[466] 
[467]     b->last += n;
[468] 
[469]     if (hc->proxy_protocol) {
[470]         hc->proxy_protocol = 0;
[471] 
[472]         p = ngx_proxy_protocol_read(c, b->pos, b->last);
[473] 
[474]         if (p == NULL) {
[475]             ngx_http_close_connection(c);
[476]             return;
[477]         }
[478] 
[479]         b->pos = p;
[480] 
[481]         if (b->pos == b->last) {
[482]             c->log->action = "waiting for request";
[483]             b->pos = b->start;
[484]             b->last = b->start;
[485]             ngx_post_event(rev, &ngx_posted_events);
[486]             return;
[487]         }
[488]     }
[489] 
[490]     c->log->action = "reading client request line";
[491] 
[492]     ngx_reusable_connection(c, 0);
[493] 
[494]     c->data = ngx_http_create_request(c);
[495]     if (c->data == NULL) {
[496]         ngx_http_close_connection(c);
[497]         return;
[498]     }
[499] 
[500]     rev->handler = ngx_http_process_request_line;
[501]     ngx_http_process_request_line(rev);
[502] }
[503] 
[504] 
[505] ngx_http_request_t *
[506] ngx_http_create_request(ngx_connection_t *c)
[507] {
[508]     ngx_http_request_t        *r;
[509]     ngx_http_log_ctx_t        *ctx;
[510]     ngx_http_core_loc_conf_t  *clcf;
[511] 
[512]     r = ngx_http_alloc_request(c);
[513]     if (r == NULL) {
[514]         return NULL;
[515]     }
[516] 
[517]     c->requests++;
[518] 
[519]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[520] 
[521]     ngx_set_connection_log(c, clcf->error_log);
[522] 
[523]     ctx = c->log->data;
[524]     ctx->request = r;
[525]     ctx->current_request = r;
[526] 
[527] #if (NGX_STAT_STUB)
[528]     (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
[529]     r->stat_reading = 1;
[530]     (void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
[531] #endif
[532] 
[533]     return r;
[534] }
[535] 
[536] 
[537] static ngx_http_request_t *
[538] ngx_http_alloc_request(ngx_connection_t *c)
[539] {
[540]     ngx_pool_t                 *pool;
[541]     ngx_time_t                 *tp;
[542]     ngx_http_request_t         *r;
[543]     ngx_http_connection_t      *hc;
[544]     ngx_http_core_srv_conf_t   *cscf;
[545]     ngx_http_core_main_conf_t  *cmcf;
[546] 
[547]     hc = c->data;
[548] 
[549]     cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);
[550] 
[551]     pool = ngx_create_pool(cscf->request_pool_size, c->log);
[552]     if (pool == NULL) {
[553]         return NULL;
[554]     }
[555] 
[556]     r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
[557]     if (r == NULL) {
[558]         ngx_destroy_pool(pool);
[559]         return NULL;
[560]     }
[561] 
[562]     r->pool = pool;
[563] 
[564]     r->http_connection = hc;
[565]     r->signature = NGX_HTTP_MODULE;
[566]     r->connection = c;
[567] 
[568]     r->main_conf = hc->conf_ctx->main_conf;
[569]     r->srv_conf = hc->conf_ctx->srv_conf;
[570]     r->loc_conf = hc->conf_ctx->loc_conf;
[571] 
[572]     r->read_event_handler = ngx_http_block_reading;
[573] 
[574]     r->header_in = hc->busy ? hc->busy->buf : c->buffer;
[575] 
[576]     if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
[577]                       sizeof(ngx_table_elt_t))
[578]         != NGX_OK)
[579]     {
[580]         ngx_destroy_pool(r->pool);
[581]         return NULL;
[582]     }
[583] 
[584]     if (ngx_list_init(&r->headers_out.trailers, r->pool, 4,
[585]                       sizeof(ngx_table_elt_t))
[586]         != NGX_OK)
[587]     {
[588]         ngx_destroy_pool(r->pool);
[589]         return NULL;
[590]     }
[591] 
[592]     r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
[593]     if (r->ctx == NULL) {
[594]         ngx_destroy_pool(r->pool);
[595]         return NULL;
[596]     }
[597] 
[598]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[599] 
[600]     r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
[601]                                         * sizeof(ngx_http_variable_value_t));
[602]     if (r->variables == NULL) {
[603]         ngx_destroy_pool(r->pool);
[604]         return NULL;
[605]     }
[606] 
[607] #if (NGX_HTTP_SSL)
[608]     if (c->ssl && !c->ssl->sendfile) {
[609]         r->main_filter_need_in_memory = 1;
[610]     }
[611] #endif
[612] 
[613]     r->main = r;
[614]     r->count = 1;
[615] 
[616]     tp = ngx_timeofday();
[617]     r->start_sec = tp->sec;
[618]     r->start_msec = tp->msec;
[619] 
[620]     r->method = NGX_HTTP_UNKNOWN;
[621]     r->http_version = NGX_HTTP_VERSION_10;
[622] 
[623]     r->headers_in.content_length_n = -1;
[624]     r->headers_in.keep_alive_n = -1;
[625]     r->headers_out.content_length_n = -1;
[626]     r->headers_out.last_modified_time = -1;
[627] 
[628]     r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
[629]     r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;
[630] 
[631]     r->http_state = NGX_HTTP_READING_REQUEST_STATE;
[632] 
[633]     r->log_handler = ngx_http_log_error_handler;
[634] 
[635]     return r;
[636] }
[637] 
[638] 
[639] #if (NGX_HTTP_SSL)
[640] 
[641] static void
[642] ngx_http_ssl_handshake(ngx_event_t *rev)
[643] {
[644]     u_char                    *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER + 1];
[645]     size_t                     size;
[646]     ssize_t                    n;
[647]     ngx_err_t                  err;
[648]     ngx_int_t                  rc;
[649]     ngx_connection_t          *c;
[650]     ngx_http_connection_t     *hc;
[651]     ngx_http_ssl_srv_conf_t   *sscf;
[652]     ngx_http_core_loc_conf_t  *clcf;
[653]     ngx_http_core_srv_conf_t  *cscf;
[654] 
[655]     c = rev->data;
[656]     hc = c->data;
[657] 
[658]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
[659]                    "http check ssl handshake");
[660] 
[661]     if (rev->timedout) {
[662]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[663]         ngx_http_close_connection(c);
[664]         return;
[665]     }
[666] 
[667]     if (c->close) {
[668]         ngx_http_close_connection(c);
[669]         return;
[670]     }
[671] 
[672]     size = hc->proxy_protocol ? sizeof(buf) : 1;
[673] 
[674]     n = recv(c->fd, (char *) buf, size, MSG_PEEK);
[675] 
[676]     err = ngx_socket_errno;
[677] 
[678]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);
[679] 
[680]     if (n == -1) {
[681]         if (err == NGX_EAGAIN) {
[682]             rev->ready = 0;
[683] 
[684]             if (!rev->timer_set) {
[685]                 cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
[686]                                                     ngx_http_core_module);
[687]                 ngx_add_timer(rev, cscf->client_header_timeout);
[688]                 ngx_reusable_connection(c, 1);
[689]             }
[690] 
[691]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[692]                 ngx_http_close_connection(c);
[693]             }
[694] 
[695]             return;
[696]         }
[697] 
[698]         ngx_connection_error(c, err, "recv() failed");
[699]         ngx_http_close_connection(c);
[700] 
[701]         return;
[702]     }
[703] 
[704]     if (hc->proxy_protocol) {
[705]         hc->proxy_protocol = 0;
[706] 
[707]         p = ngx_proxy_protocol_read(c, buf, buf + n);
[708] 
[709]         if (p == NULL) {
[710]             ngx_http_close_connection(c);
[711]             return;
[712]         }
[713] 
[714]         size = p - buf;
[715] 
[716]         if (c->recv(c, buf, size) != (ssize_t) size) {
[717]             ngx_http_close_connection(c);
[718]             return;
[719]         }
[720] 
[721]         c->log->action = "SSL handshaking";
[722] 
[723]         if (n == (ssize_t) size) {
[724]             ngx_post_event(rev, &ngx_posted_events);
[725]             return;
[726]         }
[727] 
[728]         n = 1;
[729]         buf[0] = *p;
[730]     }
[731] 
[732]     if (n == 1) {
[733]         if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
[734]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
[735]                            "https ssl handshake: 0x%02Xd", buf[0]);
[736] 
[737]             clcf = ngx_http_get_module_loc_conf(hc->conf_ctx,
[738]                                                 ngx_http_core_module);
[739] 
[740]             if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[741]                 ngx_http_close_connection(c);
[742]                 return;
[743]             }
[744] 
[745]             sscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
[746]                                                 ngx_http_ssl_module);
[747] 
[748]             if (ngx_ssl_create_connection(&sscf->ssl, c, NGX_SSL_BUFFER)
[749]                 != NGX_OK)
[750]             {
[751]                 ngx_http_close_connection(c);
[752]                 return;
[753]             }
[754] 
[755]             ngx_reusable_connection(c, 0);
[756] 
[757]             rc = ngx_ssl_handshake(c);
[758] 
[759]             if (rc == NGX_AGAIN) {
[760] 
[761]                 if (!rev->timer_set) {
[762]                     cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
[763]                                                         ngx_http_core_module);
[764]                     ngx_add_timer(rev, cscf->client_header_timeout);
[765]                 }
[766] 
[767]                 c->ssl->handler = ngx_http_ssl_handshake_handler;
[768]                 return;
[769]             }
[770] 
[771]             ngx_http_ssl_handshake_handler(c);
[772] 
[773]             return;
[774]         }
[775] 
[776]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "plain http");
[777] 
[778]         c->log->action = "waiting for request";
[779] 
[780]         rev->handler = ngx_http_wait_request_handler;
[781]         ngx_http_wait_request_handler(rev);
[782] 
[783]         return;
[784]     }
[785] 
[786]     ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
[787]     ngx_http_close_connection(c);
[788] }
[789] 
[790] 
[791] static void
[792] ngx_http_ssl_handshake_handler(ngx_connection_t *c)
[793] {
[794]     if (c->ssl->handshaked) {
[795] 
[796]         /*
[797]          * The majority of browsers do not send the "close notify" alert.
[798]          * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
[799]          * and Links.  And what is more, MSIE ignores the server's alert.
[800]          *
[801]          * Opera and recent Mozilla send the alert.
[802]          */
[803] 
[804]         c->ssl->no_wait_shutdown = 1;
[805] 
[806] #if (NGX_HTTP_V2                                                              \
[807]      && defined TLSEXT_TYPE_application_layer_protocol_negotiation)
[808]         {
[809]         unsigned int            len;
[810]         const unsigned char    *data;
[811]         ngx_http_connection_t  *hc;
[812] 
[813]         hc = c->data;
[814] 
[815]         if (hc->addr_conf->http2) {
[816] 
[817]             SSL_get0_alpn_selected(c->ssl->connection, &data, &len);
[818] 
[819]             if (len == 2 && data[0] == 'h' && data[1] == '2') {
[820]                 ngx_http_v2_init(c->read);
[821]                 return;
[822]             }
[823]         }
[824]         }
[825] #endif
[826] 
[827]         c->log->action = "waiting for request";
[828] 
[829]         c->read->handler = ngx_http_wait_request_handler;
[830]         /* STUB: epoll edge */ c->write->handler = ngx_http_empty_handler;
[831] 
[832]         ngx_reusable_connection(c, 1);
[833] 
[834]         ngx_http_wait_request_handler(c->read);
[835] 
[836]         return;
[837]     }
[838] 
[839]     if (c->read->timedout) {
[840]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[841]     }
[842] 
[843]     ngx_http_close_connection(c);
[844] }
[845] 
[846] 
[847] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[848] 
[849] int
[850] ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
[851] {
[852]     ngx_int_t                  rc;
[853]     ngx_str_t                  host;
[854]     const char                *servername;
[855]     ngx_connection_t          *c;
[856]     ngx_http_connection_t     *hc;
[857]     ngx_http_ssl_srv_conf_t   *sscf;
[858]     ngx_http_core_loc_conf_t  *clcf;
[859]     ngx_http_core_srv_conf_t  *cscf;
[860] 
[861]     c = ngx_ssl_get_connection(ssl_conn);
[862] 
[863]     if (c->ssl->handshaked) {
[864]         *ad = SSL_AD_NO_RENEGOTIATION;
[865]         return SSL_TLSEXT_ERR_ALERT_FATAL;
[866]     }
[867] 
[868]     hc = c->data;
[869] 
[870]     servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);
[871] 
[872]     if (servername == NULL) {
[873]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[874]                        "SSL server name: null");
[875]         goto done;
[876]     }
[877] 
[878]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[879]                    "SSL server name: \"%s\"", servername);
[880] 
[881]     host.len = ngx_strlen(servername);
[882] 
[883]     if (host.len == 0) {
[884]         goto done;
[885]     }
[886] 
[887]     host.data = (u_char *) servername;
[888] 
[889]     rc = ngx_http_validate_host(&host, c->pool, 1);
[890] 
[891]     if (rc == NGX_ERROR) {
[892]         goto error;
[893]     }
[894] 
[895]     if (rc == NGX_DECLINED) {
[896]         goto done;
[897]     }
[898] 
[899]     rc = ngx_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
[900]                                       NULL, &cscf);
[901] 
[902]     if (rc == NGX_ERROR) {
[903]         goto error;
[904]     }
[905] 
[906]     if (rc == NGX_DECLINED) {
[907]         goto done;
[908]     }
[909] 
[910]     hc->ssl_servername = ngx_palloc(c->pool, sizeof(ngx_str_t));
[911]     if (hc->ssl_servername == NULL) {
[912]         goto error;
[913]     }
[914] 
[915]     *hc->ssl_servername = host;
[916] 
[917]     hc->conf_ctx = cscf->ctx;
[918] 
[919]     clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);
[920] 
[921]     ngx_set_connection_log(c, clcf->error_log);
[922] 
[923]     sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);
[924] 
[925]     c->ssl->buffer_size = sscf->buffer_size;
[926] 
[927]     if (sscf->ssl.ctx) {
[928]         if (SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx) == NULL) {
[929]             goto error;
[930]         }
[931] 
[932]         /*
[933]          * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
[934]          * adjust other things we care about
[935]          */
[936] 
[937]         SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
[938]                        SSL_CTX_get_verify_callback(sscf->ssl.ctx));
[939] 
[940]         SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));
[941] 
[942] #if OPENSSL_VERSION_NUMBER >= 0x009080dfL
[943]         /* only in 0.9.8m+ */
[944]         SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
[945]                                     ~SSL_CTX_get_options(sscf->ssl.ctx));
[946] #endif
[947] 
[948]         SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));
[949] 
[950] #ifdef SSL_OP_NO_RENEGOTIATION
[951]         SSL_set_options(ssl_conn, SSL_OP_NO_RENEGOTIATION);
[952] #endif
[953]     }
[954] 
[955] done:
[956] 
[957]     sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);
[958] 
[959]     if (sscf->reject_handshake) {
[960]         c->ssl->handshake_rejected = 1;
[961]         *ad = SSL_AD_UNRECOGNIZED_NAME;
[962]         return SSL_TLSEXT_ERR_ALERT_FATAL;
[963]     }
[964] 
[965]     return SSL_TLSEXT_ERR_OK;
[966] 
[967] error:
[968] 
[969]     *ad = SSL_AD_INTERNAL_ERROR;
[970]     return SSL_TLSEXT_ERR_ALERT_FATAL;
[971] }
[972] 
[973] #endif
[974] 
[975] 
[976] #ifdef SSL_R_CERT_CB_ERROR
[977] 
[978] int
[979] ngx_http_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg)
[980] {
[981]     ngx_str_t                  cert, key;
[982]     ngx_uint_t                 i, nelts;
[983]     ngx_connection_t          *c;
[984]     ngx_http_request_t        *r;
[985]     ngx_http_ssl_srv_conf_t   *sscf;
[986]     ngx_http_complex_value_t  *certs, *keys;
[987] 
[988]     c = ngx_ssl_get_connection(ssl_conn);
[989] 
[990]     if (c->ssl->handshaked) {
[991]         return 0;
[992]     }
[993] 
[994]     r = ngx_http_alloc_request(c);
[995]     if (r == NULL) {
[996]         return 0;
[997]     }
[998] 
[999]     r->logged = 1;
[1000] 
[1001]     sscf = arg;
[1002] 
[1003]     nelts = sscf->certificate_values->nelts;
[1004]     certs = sscf->certificate_values->elts;
[1005]     keys = sscf->certificate_key_values->elts;
[1006] 
[1007]     for (i = 0; i < nelts; i++) {
[1008] 
[1009]         if (ngx_http_complex_value(r, &certs[i], &cert) != NGX_OK) {
[1010]             goto failed;
[1011]         }
[1012] 
[1013]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1014]                        "ssl cert: \"%s\"", cert.data);
[1015] 
[1016]         if (ngx_http_complex_value(r, &keys[i], &key) != NGX_OK) {
[1017]             goto failed;
[1018]         }
[1019] 
[1020]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1021]                        "ssl key: \"%s\"", key.data);
[1022] 
[1023]         if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
[1024]                                            sscf->passwords)
[1025]             != NGX_OK)
[1026]         {
[1027]             goto failed;
[1028]         }
[1029]     }
[1030] 
[1031]     ngx_http_free_request(r, 0);
[1032]     c->log->action = "SSL handshaking";
[1033]     c->destroyed = 0;
[1034]     return 1;
[1035] 
[1036] failed:
[1037] 
[1038]     ngx_http_free_request(r, 0);
[1039]     c->log->action = "SSL handshaking";
[1040]     c->destroyed = 0;
[1041]     return 0;
[1042] }
[1043] 
[1044] #endif
[1045] 
[1046] #endif
[1047] 
[1048] 
[1049] static void
[1050] ngx_http_process_request_line(ngx_event_t *rev)
[1051] {
[1052]     ssize_t              n;
[1053]     ngx_int_t            rc, rv;
[1054]     ngx_str_t            host;
[1055]     ngx_connection_t    *c;
[1056]     ngx_http_request_t  *r;
[1057] 
[1058]     c = rev->data;
[1059]     r = c->data;
[1060] 
[1061]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
[1062]                    "http process request line");
[1063] 
[1064]     if (rev->timedout) {
[1065]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[1066]         c->timedout = 1;
[1067]         ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
[1068]         return;
[1069]     }
[1070] 
[1071]     rc = NGX_AGAIN;
[1072] 
[1073]     for ( ;; ) {
[1074] 
[1075]         if (rc == NGX_AGAIN) {
[1076]             n = ngx_http_read_request_header(r);
[1077] 
[1078]             if (n == NGX_AGAIN || n == NGX_ERROR) {
[1079]                 break;
[1080]             }
[1081]         }
[1082] 
[1083]         rc = ngx_http_parse_request_line(r, r->header_in);
[1084] 
[1085]         if (rc == NGX_OK) {
[1086] 
[1087]             /* the request line has been parsed successfully */
[1088] 
[1089]             r->request_line.len = r->request_end - r->request_start;
[1090]             r->request_line.data = r->request_start;
[1091]             r->request_length = r->header_in->pos - r->request_start;
[1092] 
[1093]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1094]                            "http request line: \"%V\"", &r->request_line);
[1095] 
[1096]             r->method_name.len = r->method_end - r->request_start + 1;
[1097]             r->method_name.data = r->request_line.data;
[1098] 
[1099]             if (r->http_protocol.data) {
[1100]                 r->http_protocol.len = r->request_end - r->http_protocol.data;
[1101]             }
[1102] 
[1103]             if (ngx_http_process_request_uri(r) != NGX_OK) {
[1104]                 break;
[1105]             }
[1106] 
[1107]             if (r->schema_end) {
[1108]                 r->schema.len = r->schema_end - r->schema_start;
[1109]                 r->schema.data = r->schema_start;
[1110]             }
[1111] 
[1112]             if (r->host_end) {
[1113] 
[1114]                 host.len = r->host_end - r->host_start;
[1115]                 host.data = r->host_start;
[1116] 
[1117]                 rc = ngx_http_validate_host(&host, r->pool, 0);
[1118] 
[1119]                 if (rc == NGX_DECLINED) {
[1120]                     ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1121]                                   "client sent invalid host in request line");
[1122]                     ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1123]                     break;
[1124]                 }
[1125] 
[1126]                 if (rc == NGX_ERROR) {
[1127]                     ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1128]                     break;
[1129]                 }
[1130] 
[1131]                 if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
[1132]                     break;
[1133]                 }
[1134] 
[1135]                 r->headers_in.server = host;
[1136]             }
[1137] 
[1138]             if (r->http_version < NGX_HTTP_VERSION_10) {
[1139] 
[1140]                 if (r->headers_in.server.len == 0
[1141]                     && ngx_http_set_virtual_server(r, &r->headers_in.server)
[1142]                        == NGX_ERROR)
[1143]                 {
[1144]                     break;
[1145]                 }
[1146] 
[1147]                 ngx_http_process_request(r);
[1148]                 break;
[1149]             }
[1150] 
[1151] 
[1152]             if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
[1153]                               sizeof(ngx_table_elt_t))
[1154]                 != NGX_OK)
[1155]             {
[1156]                 ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1157]                 break;
[1158]             }
[1159] 
[1160]             c->log->action = "reading client request headers";
[1161] 
[1162]             rev->handler = ngx_http_process_request_headers;
[1163]             ngx_http_process_request_headers(rev);
[1164] 
[1165]             break;
[1166]         }
[1167] 
[1168]         if (rc != NGX_AGAIN) {
[1169] 
[1170]             /* there was error while a request line parsing */
[1171] 
[1172]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1173]                           ngx_http_client_errors[rc - NGX_HTTP_CLIENT_ERROR]);
[1174] 
[1175]             if (rc == NGX_HTTP_PARSE_INVALID_VERSION) {
[1176]                 ngx_http_finalize_request(r, NGX_HTTP_VERSION_NOT_SUPPORTED);
[1177] 
[1178]             } else {
[1179]                 ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1180]             }
[1181] 
[1182]             break;
[1183]         }
[1184] 
[1185]         /* NGX_AGAIN: a request line parsing is still incomplete */
[1186] 
[1187]         if (r->header_in->pos == r->header_in->end) {
[1188] 
[1189]             rv = ngx_http_alloc_large_header_buffer(r, 1);
[1190] 
[1191]             if (rv == NGX_ERROR) {
[1192]                 ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1193]                 break;
[1194]             }
[1195] 
[1196]             if (rv == NGX_DECLINED) {
[1197]                 r->request_line.len = r->header_in->end - r->request_start;
[1198]                 r->request_line.data = r->request_start;
[1199] 
[1200]                 ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1201]                               "client sent too long URI");
[1202]                 ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
[1203]                 break;
[1204]             }
[1205]         }
[1206]     }
[1207] 
[1208]     ngx_http_run_posted_requests(c);
[1209] }
[1210] 
[1211] 
[1212] ngx_int_t
[1213] ngx_http_process_request_uri(ngx_http_request_t *r)
[1214] {
[1215]     ngx_http_core_srv_conf_t  *cscf;
[1216] 
[1217]     if (r->args_start) {
[1218]         r->uri.len = r->args_start - 1 - r->uri_start;
[1219]     } else {
[1220]         r->uri.len = r->uri_end - r->uri_start;
[1221]     }
[1222] 
[1223]     if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {
[1224] 
[1225]         if (r->empty_path_in_uri) {
[1226]             r->uri.len++;
[1227]         }
[1228] 
[1229]         r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
[1230]         if (r->uri.data == NULL) {
[1231]             ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1232]             return NGX_ERROR;
[1233]         }
[1234] 
[1235]         cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1236] 
[1237]         if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
[1238]             r->uri.len = 0;
[1239] 
[1240]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1241]                           "client sent invalid request");
[1242]             ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1243]             return NGX_ERROR;
[1244]         }
[1245] 
[1246]     } else {
[1247]         r->uri.data = r->uri_start;
[1248]     }
[1249] 
[1250]     r->unparsed_uri.len = r->uri_end - r->uri_start;
[1251]     r->unparsed_uri.data = r->uri_start;
[1252] 
[1253]     r->valid_unparsed_uri = r->empty_path_in_uri ? 0 : 1;
[1254] 
[1255]     if (r->uri_ext) {
[1256]         if (r->args_start) {
[1257]             r->exten.len = r->args_start - 1 - r->uri_ext;
[1258]         } else {
[1259]             r->exten.len = r->uri_end - r->uri_ext;
[1260]         }
[1261] 
[1262]         r->exten.data = r->uri_ext;
[1263]     }
[1264] 
[1265]     if (r->args_start && r->uri_end > r->args_start) {
[1266]         r->args.len = r->uri_end - r->args_start;
[1267]         r->args.data = r->args_start;
[1268]     }
[1269] 
[1270] #if (NGX_WIN32)
[1271]     {
[1272]     u_char  *p, *last;
[1273] 
[1274]     p = r->uri.data;
[1275]     last = r->uri.data + r->uri.len;
[1276] 
[1277]     while (p < last) {
[1278] 
[1279]         if (*p++ == ':') {
[1280] 
[1281]             /*
[1282]              * this check covers "::$data", "::$index_allocation" and
[1283]              * ":$i30:$index_allocation"
[1284]              */
[1285] 
[1286]             if (p < last && *p == '$') {
[1287]                 ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1288]                               "client sent unsafe win32 URI");
[1289]                 ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1290]                 return NGX_ERROR;
[1291]             }
[1292]         }
[1293]     }
[1294] 
[1295]     p = r->uri.data + r->uri.len - 1;
[1296] 
[1297]     while (p > r->uri.data) {
[1298] 
[1299]         if (*p == ' ') {
[1300]             p--;
[1301]             continue;
[1302]         }
[1303] 
[1304]         if (*p == '.') {
[1305]             p--;
[1306]             continue;
[1307]         }
[1308] 
[1309]         break;
[1310]     }
[1311] 
[1312]     if (p != r->uri.data + r->uri.len - 1) {
[1313]         r->uri.len = p + 1 - r->uri.data;
[1314]         ngx_http_set_exten(r);
[1315]     }
[1316] 
[1317]     }
[1318] #endif
[1319] 
[1320]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1321]                    "http uri: \"%V\"", &r->uri);
[1322] 
[1323]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1324]                    "http args: \"%V\"", &r->args);
[1325] 
[1326]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1327]                    "http exten: \"%V\"", &r->exten);
[1328] 
[1329]     return NGX_OK;
[1330] }
[1331] 
[1332] 
[1333] static void
[1334] ngx_http_process_request_headers(ngx_event_t *rev)
[1335] {
[1336]     u_char                     *p;
[1337]     size_t                      len;
[1338]     ssize_t                     n;
[1339]     ngx_int_t                   rc, rv;
[1340]     ngx_table_elt_t            *h;
[1341]     ngx_connection_t           *c;
[1342]     ngx_http_header_t          *hh;
[1343]     ngx_http_request_t         *r;
[1344]     ngx_http_core_srv_conf_t   *cscf;
[1345]     ngx_http_core_main_conf_t  *cmcf;
[1346] 
[1347]     c = rev->data;
[1348]     r = c->data;
[1349] 
[1350]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
[1351]                    "http process request header line");
[1352] 
[1353]     if (rev->timedout) {
[1354]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[1355]         c->timedout = 1;
[1356]         ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
[1357]         return;
[1358]     }
[1359] 
[1360]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[1361] 
[1362]     rc = NGX_AGAIN;
[1363] 
[1364]     for ( ;; ) {
[1365] 
[1366]         if (rc == NGX_AGAIN) {
[1367] 
[1368]             if (r->header_in->pos == r->header_in->end) {
[1369] 
[1370]                 rv = ngx_http_alloc_large_header_buffer(r, 0);
[1371] 
[1372]                 if (rv == NGX_ERROR) {
[1373]                     ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1374]                     break;
[1375]                 }
[1376] 
[1377]                 if (rv == NGX_DECLINED) {
[1378]                     p = r->header_name_start;
[1379] 
[1380]                     r->lingering_close = 1;
[1381] 
[1382]                     if (p == NULL) {
[1383]                         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1384]                                       "client sent too large request");
[1385]                         ngx_http_finalize_request(r,
[1386]                                             NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
[1387]                         break;
[1388]                     }
[1389] 
[1390]                     len = r->header_in->end - p;
[1391] 
[1392]                     if (len > NGX_MAX_ERROR_STR - 300) {
[1393]                         len = NGX_MAX_ERROR_STR - 300;
[1394]                     }
[1395] 
[1396]                     ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1397]                                 "client sent too long header line: \"%*s...\"",
[1398]                                 len, r->header_name_start);
[1399] 
[1400]                     ngx_http_finalize_request(r,
[1401]                                             NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
[1402]                     break;
[1403]                 }
[1404]             }
[1405] 
[1406]             n = ngx_http_read_request_header(r);
[1407] 
[1408]             if (n == NGX_AGAIN || n == NGX_ERROR) {
[1409]                 break;
[1410]             }
[1411]         }
[1412] 
[1413]         /* the host header could change the server configuration context */
[1414]         cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1415] 
[1416]         rc = ngx_http_parse_header_line(r, r->header_in,
[1417]                                         cscf->underscores_in_headers);
[1418] 
[1419]         if (rc == NGX_OK) {
[1420] 
[1421]             r->request_length += r->header_in->pos - r->header_name_start;
[1422] 
[1423]             if (r->invalid_header && cscf->ignore_invalid_headers) {
[1424] 
[1425]                 /* there was error while a header line parsing */
[1426] 
[1427]                 ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1428]                               "client sent invalid header line: \"%*s\"",
[1429]                               r->header_end - r->header_name_start,
[1430]                               r->header_name_start);
[1431]                 continue;
[1432]             }
[1433] 
[1434]             /* a header line has been parsed successfully */
[1435] 
[1436]             h = ngx_list_push(&r->headers_in.headers);
[1437]             if (h == NULL) {
[1438]                 ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1439]                 break;
[1440]             }
[1441] 
[1442]             h->hash = r->header_hash;
[1443] 
[1444]             h->key.len = r->header_name_end - r->header_name_start;
[1445]             h->key.data = r->header_name_start;
[1446]             h->key.data[h->key.len] = '\0';
[1447] 
[1448]             h->value.len = r->header_end - r->header_start;
[1449]             h->value.data = r->header_start;
[1450]             h->value.data[h->value.len] = '\0';
[1451] 
[1452]             h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
[1453]             if (h->lowcase_key == NULL) {
[1454]                 ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1455]                 break;
[1456]             }
[1457] 
[1458]             if (h->key.len == r->lowcase_index) {
[1459]                 ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
[1460] 
[1461]             } else {
[1462]                 ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
[1463]             }
[1464] 
[1465]             hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
[1466]                                h->lowcase_key, h->key.len);
[1467] 
[1468]             if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
[1469]                 break;
[1470]             }
[1471] 
[1472]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1473]                            "http header: \"%V: %V\"",
[1474]                            &h->key, &h->value);
[1475] 
[1476]             continue;
[1477]         }
[1478] 
[1479]         if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[1480] 
[1481]             /* a whole header has been parsed successfully */
[1482] 
[1483]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1484]                            "http header done");
[1485] 
[1486]             r->request_length += r->header_in->pos - r->header_name_start;
[1487] 
[1488]             r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;
[1489] 
[1490]             rc = ngx_http_process_request_header(r);
[1491] 
[1492]             if (rc != NGX_OK) {
[1493]                 break;
[1494]             }
[1495] 
[1496]             ngx_http_process_request(r);
[1497] 
[1498]             break;
[1499]         }
[1500] 
[1501]         if (rc == NGX_AGAIN) {
[1502] 
[1503]             /* a header line parsing is still not complete */
[1504] 
[1505]             continue;
[1506]         }
[1507] 
[1508]         /* rc == NGX_HTTP_PARSE_INVALID_HEADER */
[1509] 
[1510]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1511]                       "client sent invalid header line: \"%*s\\x%02xd...\"",
[1512]                       r->header_end - r->header_name_start,
[1513]                       r->header_name_start, *r->header_end);
[1514] 
[1515]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1516]         break;
[1517]     }
[1518] 
[1519]     ngx_http_run_posted_requests(c);
[1520] }
[1521] 
[1522] 
[1523] static ssize_t
[1524] ngx_http_read_request_header(ngx_http_request_t *r)
[1525] {
[1526]     ssize_t                    n;
[1527]     ngx_event_t               *rev;
[1528]     ngx_connection_t          *c;
[1529]     ngx_http_core_srv_conf_t  *cscf;
[1530] 
[1531]     c = r->connection;
[1532]     rev = c->read;
[1533] 
[1534]     n = r->header_in->last - r->header_in->pos;
[1535] 
[1536]     if (n > 0) {
[1537]         return n;
[1538]     }
[1539] 
[1540]     if (rev->ready) {
[1541]         n = c->recv(c, r->header_in->last,
[1542]                     r->header_in->end - r->header_in->last);
[1543]     } else {
[1544]         n = NGX_AGAIN;
[1545]     }
[1546] 
[1547]     if (n == NGX_AGAIN) {
[1548]         if (!rev->timer_set) {
[1549]             cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1550]             ngx_add_timer(rev, cscf->client_header_timeout);
[1551]         }
[1552] 
[1553]         if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[1554]             ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1555]             return NGX_ERROR;
[1556]         }
[1557] 
[1558]         return NGX_AGAIN;
[1559]     }
[1560] 
[1561]     if (n == 0) {
[1562]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1563]                       "client prematurely closed connection");
[1564]     }
[1565] 
[1566]     if (n == 0 || n == NGX_ERROR) {
[1567]         c->error = 1;
[1568]         c->log->action = "reading client request headers";
[1569] 
[1570]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1571]         return NGX_ERROR;
[1572]     }
[1573] 
[1574]     r->header_in->last += n;
[1575] 
[1576]     return n;
[1577] }
[1578] 
[1579] 
[1580] static ngx_int_t
[1581] ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
[1582]     ngx_uint_t request_line)
[1583] {
[1584]     u_char                    *old, *new;
[1585]     ngx_buf_t                 *b;
[1586]     ngx_chain_t               *cl;
[1587]     ngx_http_connection_t     *hc;
[1588]     ngx_http_core_srv_conf_t  *cscf;
[1589] 
[1590]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1591]                    "http alloc large header buffer");
[1592] 
[1593]     if (request_line && r->state == 0) {
[1594] 
[1595]         /* the client fills up the buffer with "\r\n" */
[1596] 
[1597]         r->header_in->pos = r->header_in->start;
[1598]         r->header_in->last = r->header_in->start;
[1599] 
[1600]         return NGX_OK;
[1601]     }
[1602] 
[1603]     old = request_line ? r->request_start : r->header_name_start;
[1604] 
[1605]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1606] 
[1607]     if (r->state != 0
[1608]         && (size_t) (r->header_in->pos - old)
[1609]                                      >= cscf->large_client_header_buffers.size)
[1610]     {
[1611]         return NGX_DECLINED;
[1612]     }
[1613] 
[1614]     hc = r->http_connection;
[1615] 
[1616]     if (hc->free) {
[1617]         cl = hc->free;
[1618]         hc->free = cl->next;
[1619] 
[1620]         b = cl->buf;
[1621] 
[1622]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1623]                        "http large header free: %p %uz",
[1624]                        b->pos, b->end - b->last);
[1625] 
[1626]     } else if (hc->nbusy < cscf->large_client_header_buffers.num) {
[1627] 
[1628]         b = ngx_create_temp_buf(r->connection->pool,
[1629]                                 cscf->large_client_header_buffers.size);
[1630]         if (b == NULL) {
[1631]             return NGX_ERROR;
[1632]         }
[1633] 
[1634]         cl = ngx_alloc_chain_link(r->connection->pool);
[1635]         if (cl == NULL) {
[1636]             return NGX_ERROR;
[1637]         }
[1638] 
[1639]         cl->buf = b;
[1640] 
[1641]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1642]                        "http large header alloc: %p %uz",
[1643]                        b->pos, b->end - b->last);
[1644] 
[1645]     } else {
[1646]         return NGX_DECLINED;
[1647]     }
[1648] 
[1649]     cl->next = hc->busy;
[1650]     hc->busy = cl;
[1651]     hc->nbusy++;
[1652] 
[1653]     if (r->state == 0) {
[1654]         /*
[1655]          * r->state == 0 means that a header line was parsed successfully
[1656]          * and we do not need to copy incomplete header line and
[1657]          * to relocate the parser header pointers
[1658]          */
[1659] 
[1660]         r->header_in = b;
[1661] 
[1662]         return NGX_OK;
[1663]     }
[1664] 
[1665]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1666]                    "http large header copy: %uz", r->header_in->pos - old);
[1667] 
[1668]     if (r->header_in->pos - old > b->end - b->start) {
[1669]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1670]                       "too large header to copy");
[1671]         return NGX_ERROR;
[1672]     }
[1673] 
[1674]     new = b->start;
[1675] 
[1676]     ngx_memcpy(new, old, r->header_in->pos - old);
[1677] 
[1678]     b->pos = new + (r->header_in->pos - old);
[1679]     b->last = new + (r->header_in->pos - old);
[1680] 
[1681]     if (request_line) {
[1682]         r->request_start = new;
[1683] 
[1684]         if (r->request_end) {
[1685]             r->request_end = new + (r->request_end - old);
[1686]         }
[1687] 
[1688]         r->method_end = new + (r->method_end - old);
[1689] 
[1690]         r->uri_start = new + (r->uri_start - old);
[1691]         r->uri_end = new + (r->uri_end - old);
[1692] 
[1693]         if (r->schema_start) {
[1694]             r->schema_start = new + (r->schema_start - old);
[1695]             r->schema_end = new + (r->schema_end - old);
[1696]         }
[1697] 
[1698]         if (r->host_start) {
[1699]             r->host_start = new + (r->host_start - old);
[1700]             if (r->host_end) {
[1701]                 r->host_end = new + (r->host_end - old);
[1702]             }
[1703]         }
[1704] 
[1705]         if (r->port_start) {
[1706]             r->port_start = new + (r->port_start - old);
[1707]             r->port_end = new + (r->port_end - old);
[1708]         }
[1709] 
[1710]         if (r->uri_ext) {
[1711]             r->uri_ext = new + (r->uri_ext - old);
[1712]         }
[1713] 
[1714]         if (r->args_start) {
[1715]             r->args_start = new + (r->args_start - old);
[1716]         }
[1717] 
[1718]         if (r->http_protocol.data) {
[1719]             r->http_protocol.data = new + (r->http_protocol.data - old);
[1720]         }
[1721] 
[1722]     } else {
[1723]         r->header_name_start = new;
[1724]         r->header_name_end = new + (r->header_name_end - old);
[1725]         r->header_start = new + (r->header_start - old);
[1726]         r->header_end = new + (r->header_end - old);
[1727]     }
[1728] 
[1729]     r->header_in = b;
[1730] 
[1731]     return NGX_OK;
[1732] }
[1733] 
[1734] 
[1735] static ngx_int_t
[1736] ngx_http_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
[1737]     ngx_uint_t offset)
[1738] {
[1739]     ngx_table_elt_t  **ph;
[1740] 
[1741]     ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);
[1742] 
[1743]     while (*ph) { ph = &(*ph)->next; }
[1744] 
[1745]     *ph = h;
[1746]     h->next = NULL;
[1747] 
[1748]     return NGX_OK;
[1749] }
[1750] 
[1751] 
[1752] static ngx_int_t
[1753] ngx_http_process_unique_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
[1754]     ngx_uint_t offset)
[1755] {
[1756]     ngx_table_elt_t  **ph;
[1757] 
[1758]     ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);
[1759] 
[1760]     if (*ph == NULL) {
[1761]         *ph = h;
[1762]         h->next = NULL;
[1763]         return NGX_OK;
[1764]     }
[1765] 
[1766]     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1767]                   "client sent duplicate header line: \"%V: %V\", "
[1768]                   "previous value: \"%V: %V\"",
[1769]                   &h->key, &h->value, &(*ph)->key, &(*ph)->value);
[1770] 
[1771]     ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1772] 
[1773]     return NGX_ERROR;
[1774] }
[1775] 
[1776] 
[1777] static ngx_int_t
[1778] ngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h,
[1779]     ngx_uint_t offset)
[1780] {
[1781]     ngx_int_t  rc;
[1782]     ngx_str_t  host;
[1783] 
[1784]     if (r->headers_in.host) {
[1785]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1786]                       "client sent duplicate host header: \"%V: %V\", "
[1787]                       "previous value: \"%V: %V\"",
[1788]                       &h->key, &h->value, &r->headers_in.host->key,
[1789]                       &r->headers_in.host->value);
[1790]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1791]         return NGX_ERROR;
[1792]     }
[1793] 
[1794]     r->headers_in.host = h;
[1795]     h->next = NULL;
[1796] 
[1797]     host = h->value;
[1798] 
[1799]     rc = ngx_http_validate_host(&host, r->pool, 0);
[1800] 
[1801]     if (rc == NGX_DECLINED) {
[1802]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1803]                       "client sent invalid host header");
[1804]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1805]         return NGX_ERROR;
[1806]     }
[1807] 
[1808]     if (rc == NGX_ERROR) {
[1809]         ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1810]         return NGX_ERROR;
[1811]     }
[1812] 
[1813]     if (r->headers_in.server.len) {
[1814]         return NGX_OK;
[1815]     }
[1816] 
[1817]     if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
[1818]         return NGX_ERROR;
[1819]     }
[1820] 
[1821]     r->headers_in.server = host;
[1822] 
[1823]     return NGX_OK;
[1824] }
[1825] 
[1826] 
[1827] static ngx_int_t
[1828] ngx_http_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
[1829]     ngx_uint_t offset)
[1830] {
[1831]     if (ngx_http_process_header_line(r, h, offset) != NGX_OK) {
[1832]         return NGX_ERROR;
[1833]     }
[1834] 
[1835]     if (ngx_strcasestrn(h->value.data, "close", 5 - 1)) {
[1836]         r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;
[1837] 
[1838]     } else if (ngx_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
[1839]         r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
[1840]     }
[1841] 
[1842]     return NGX_OK;
[1843] }
[1844] 
[1845] 
[1846] static ngx_int_t
[1847] ngx_http_process_user_agent(ngx_http_request_t *r, ngx_table_elt_t *h,
[1848]     ngx_uint_t offset)
[1849] {
[1850]     u_char  *user_agent, *msie;
[1851] 
[1852]     if (ngx_http_process_header_line(r, h, offset) != NGX_OK) {
[1853]         return NGX_ERROR;
[1854]     }
[1855] 
[1856]     /* check some widespread browsers while the header is in CPU cache */
[1857] 
[1858]     user_agent = h->value.data;
[1859] 
[1860]     msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);
[1861] 
[1862]     if (msie && msie + 7 < user_agent + h->value.len) {
[1863] 
[1864]         r->headers_in.msie = 1;
[1865] 
[1866]         if (msie[6] == '.') {
[1867] 
[1868]             switch (msie[5]) {
[1869]             case '4':
[1870]             case '5':
[1871]                 r->headers_in.msie6 = 1;
[1872]                 break;
[1873]             case '6':
[1874]                 if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
[1875]                     r->headers_in.msie6 = 1;
[1876]                 }
[1877]                 break;
[1878]             }
[1879]         }
[1880] 
[1881] #if 0
[1882]         /* MSIE ignores the SSL "close notify" alert */
[1883]         if (c->ssl) {
[1884]             c->ssl->no_send_shutdown = 1;
[1885]         }
[1886] #endif
[1887]     }
[1888] 
[1889]     if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
[1890]         r->headers_in.opera = 1;
[1891]         r->headers_in.msie = 0;
[1892]         r->headers_in.msie6 = 0;
[1893]     }
[1894] 
[1895]     if (!r->headers_in.msie && !r->headers_in.opera) {
[1896] 
[1897]         if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
[1898]             r->headers_in.gecko = 1;
[1899] 
[1900]         } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
[1901]             r->headers_in.chrome = 1;
[1902] 
[1903]         } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
[1904]                    && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
[1905]         {
[1906]             r->headers_in.safari = 1;
[1907] 
[1908]         } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
[1909]             r->headers_in.konqueror = 1;
[1910]         }
[1911]     }
[1912] 
[1913]     return NGX_OK;
[1914] }
[1915] 
[1916] 
[1917] ngx_int_t
[1918] ngx_http_process_request_header(ngx_http_request_t *r)
[1919] {
[1920]     if (r->headers_in.server.len == 0
[1921]         && ngx_http_set_virtual_server(r, &r->headers_in.server)
[1922]            == NGX_ERROR)
[1923]     {
[1924]         return NGX_ERROR;
[1925]     }
[1926] 
[1927]     if (r->headers_in.host == NULL && r->http_version > NGX_HTTP_VERSION_10) {
[1928]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1929]                    "client sent HTTP/1.1 request without \"Host\" header");
[1930]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1931]         return NGX_ERROR;
[1932]     }
[1933] 
[1934]     if (r->headers_in.content_length) {
[1935]         r->headers_in.content_length_n =
[1936]                             ngx_atoof(r->headers_in.content_length->value.data,
[1937]                                       r->headers_in.content_length->value.len);
[1938] 
[1939]         if (r->headers_in.content_length_n == NGX_ERROR) {
[1940]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1941]                           "client sent invalid \"Content-Length\" header");
[1942]             ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1943]             return NGX_ERROR;
[1944]         }
[1945]     }
[1946] 
[1947]     if (r->headers_in.transfer_encoding) {
[1948]         if (r->http_version < NGX_HTTP_VERSION_11) {
[1949]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1950]                           "client sent HTTP/1.0 request with "
[1951]                           "\"Transfer-Encoding\" header");
[1952]             ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1953]             return NGX_ERROR;
[1954]         }
[1955] 
[1956]         if (r->headers_in.transfer_encoding->value.len == 7
[1957]             && ngx_strncasecmp(r->headers_in.transfer_encoding->value.data,
[1958]                                (u_char *) "chunked", 7) == 0)
[1959]         {
[1960]             if (r->headers_in.content_length) {
[1961]                 ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1962]                               "client sent \"Content-Length\" and "
[1963]                               "\"Transfer-Encoding\" headers "
[1964]                               "at the same time");
[1965]                 ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1966]                 return NGX_ERROR;
[1967]             }
[1968] 
[1969]             r->headers_in.chunked = 1;
[1970] 
[1971]         } else {
[1972]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1973]                           "client sent unknown \"Transfer-Encoding\": \"%V\"",
[1974]                           &r->headers_in.transfer_encoding->value);
[1975]             ngx_http_finalize_request(r, NGX_HTTP_NOT_IMPLEMENTED);
[1976]             return NGX_ERROR;
[1977]         }
[1978]     }
[1979] 
[1980]     if (r->headers_in.connection_type == NGX_HTTP_CONNECTION_KEEP_ALIVE) {
[1981]         if (r->headers_in.keep_alive) {
[1982]             r->headers_in.keep_alive_n =
[1983]                             ngx_atotm(r->headers_in.keep_alive->value.data,
[1984]                                       r->headers_in.keep_alive->value.len);
[1985]         }
[1986]     }
[1987] 
[1988]     if (r->method == NGX_HTTP_CONNECT) {
[1989]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1990]                       "client sent CONNECT method");
[1991]         ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
[1992]         return NGX_ERROR;
[1993]     }
[1994] 
[1995]     if (r->method == NGX_HTTP_TRACE) {
[1996]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1997]                       "client sent TRACE method");
[1998]         ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
[1999]         return NGX_ERROR;
[2000]     }
[2001] 
[2002]     return NGX_OK;
[2003] }
[2004] 
[2005] 
[2006] void
[2007] ngx_http_process_request(ngx_http_request_t *r)
[2008] {
[2009]     ngx_connection_t  *c;
[2010] 
[2011]     c = r->connection;
[2012] 
[2013] #if (NGX_HTTP_SSL)
[2014] 
[2015]     if (r->http_connection->ssl) {
[2016]         long                      rc;
[2017]         X509                     *cert;
[2018]         const char               *s;
[2019]         ngx_http_ssl_srv_conf_t  *sscf;
[2020] 
[2021]         if (c->ssl == NULL) {
[2022]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[2023]                           "client sent plain HTTP request to HTTPS port");
[2024]             ngx_http_finalize_request(r, NGX_HTTP_TO_HTTPS);
[2025]             return;
[2026]         }
[2027] 
[2028]         sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);
[2029] 
[2030]         if (sscf->verify) {
[2031]             rc = SSL_get_verify_result(c->ssl->connection);
[2032] 
[2033]             if (rc != X509_V_OK
[2034]                 && (sscf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
[2035]             {
[2036]                 ngx_log_error(NGX_LOG_INFO, c->log, 0,
[2037]                               "client SSL certificate verify error: (%l:%s)",
[2038]                               rc, X509_verify_cert_error_string(rc));
[2039] 
[2040]                 ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[2041]                                        (SSL_get0_session(c->ssl->connection)));
[2042] 
[2043]                 ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);
[2044]                 return;
[2045]             }
[2046] 
[2047]             if (sscf->verify == 1) {
[2048]                 cert = SSL_get_peer_certificate(c->ssl->connection);
[2049] 
[2050]                 if (cert == NULL) {
[2051]                     ngx_log_error(NGX_LOG_INFO, c->log, 0,
[2052]                                   "client sent no required SSL certificate");
[2053] 
[2054]                     ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[2055]                                        (SSL_get0_session(c->ssl->connection)));
[2056] 
[2057]                     ngx_http_finalize_request(r, NGX_HTTPS_NO_CERT);
[2058]                     return;
[2059]                 }
[2060] 
[2061]                 X509_free(cert);
[2062]             }
[2063] 
[2064]             if (ngx_ssl_ocsp_get_status(c, &s) != NGX_OK) {
[2065]                 ngx_log_error(NGX_LOG_INFO, c->log, 0,
[2066]                               "client SSL certificate verify error: %s", s);
[2067] 
[2068]                 ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[2069]                                        (SSL_get0_session(c->ssl->connection)));
[2070] 
[2071]                 ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);
[2072]                 return;
[2073]             }
[2074]         }
[2075]     }
[2076] 
[2077] #endif
[2078] 
[2079]     if (c->read->timer_set) {
[2080]         ngx_del_timer(c->read);
[2081]     }
[2082] 
[2083] #if (NGX_STAT_STUB)
[2084]     (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
[2085]     r->stat_reading = 0;
[2086]     (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);
[2087]     r->stat_writing = 1;
[2088] #endif
[2089] 
[2090]     c->read->handler = ngx_http_request_handler;
[2091]     c->write->handler = ngx_http_request_handler;
[2092]     r->read_event_handler = ngx_http_block_reading;
[2093] 
[2094]     ngx_http_handler(r);
[2095] }
[2096] 
[2097] 
[2098] static ngx_int_t
[2099] ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
[2100] {
[2101]     u_char  *h, ch;
[2102]     size_t   i, dot_pos, host_len;
[2103] 
[2104]     enum {
[2105]         sw_usual = 0,
[2106]         sw_literal,
[2107]         sw_rest
[2108]     } state;
[2109] 
[2110]     dot_pos = host->len;
[2111]     host_len = host->len;
[2112] 
[2113]     h = host->data;
[2114] 
[2115]     state = sw_usual;
[2116] 
[2117]     for (i = 0; i < host->len; i++) {
[2118]         ch = h[i];
[2119] 
[2120]         switch (ch) {
[2121] 
[2122]         case '.':
[2123]             if (dot_pos == i - 1) {
[2124]                 return NGX_DECLINED;
[2125]             }
[2126]             dot_pos = i;
[2127]             break;
[2128] 
[2129]         case ':':
[2130]             if (state == sw_usual) {
[2131]                 host_len = i;
[2132]                 state = sw_rest;
[2133]             }
[2134]             break;
[2135] 
[2136]         case '[':
[2137]             if (i == 0) {
[2138]                 state = sw_literal;
[2139]             }
[2140]             break;
[2141] 
[2142]         case ']':
[2143]             if (state == sw_literal) {
[2144]                 host_len = i + 1;
[2145]                 state = sw_rest;
[2146]             }
[2147]             break;
[2148] 
[2149]         default:
[2150] 
[2151]             if (ngx_path_separator(ch)) {
[2152]                 return NGX_DECLINED;
[2153]             }
[2154] 
[2155]             if (ch <= 0x20 || ch == 0x7f) {
[2156]                 return NGX_DECLINED;
[2157]             }
[2158] 
[2159]             if (ch >= 'A' && ch <= 'Z') {
[2160]                 alloc = 1;
[2161]             }
[2162] 
[2163]             break;
[2164]         }
[2165]     }
[2166] 
[2167]     if (dot_pos == host_len - 1) {
[2168]         host_len--;
[2169]     }
[2170] 
[2171]     if (host_len == 0) {
[2172]         return NGX_DECLINED;
[2173]     }
[2174] 
[2175]     if (alloc) {
[2176]         host->data = ngx_pnalloc(pool, host_len);
[2177]         if (host->data == NULL) {
[2178]             return NGX_ERROR;
[2179]         }
[2180] 
[2181]         ngx_strlow(host->data, h, host_len);
[2182]     }
[2183] 
[2184]     host->len = host_len;
[2185] 
[2186]     return NGX_OK;
[2187] }
[2188] 
[2189] 
[2190] static ngx_int_t
[2191] ngx_http_set_virtual_server(ngx_http_request_t *r, ngx_str_t *host)
[2192] {
[2193]     ngx_int_t                  rc;
[2194]     ngx_http_connection_t     *hc;
[2195]     ngx_http_core_loc_conf_t  *clcf;
[2196]     ngx_http_core_srv_conf_t  *cscf;
[2197] 
[2198] #if (NGX_SUPPRESS_WARN)
[2199]     cscf = NULL;
[2200] #endif
[2201] 
[2202]     hc = r->http_connection;
[2203] 
[2204] #if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
[2205] 
[2206]     if (hc->ssl_servername) {
[2207]         if (hc->ssl_servername->len == host->len
[2208]             && ngx_strncmp(hc->ssl_servername->data,
[2209]                            host->data, host->len) == 0)
[2210]         {
[2211] #if (NGX_PCRE)
[2212]             if (hc->ssl_servername_regex
[2213]                 && ngx_http_regex_exec(r, hc->ssl_servername_regex,
[2214]                                           hc->ssl_servername) != NGX_OK)
[2215]             {
[2216]                 ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2217]                 return NGX_ERROR;
[2218]             }
[2219] #endif
[2220]             return NGX_OK;
[2221]         }
[2222]     }
[2223] 
[2224] #endif
[2225] 
[2226]     rc = ngx_http_find_virtual_server(r->connection,
[2227]                                       hc->addr_conf->virtual_names,
[2228]                                       host, r, &cscf);
[2229] 
[2230]     if (rc == NGX_ERROR) {
[2231]         ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2232]         return NGX_ERROR;
[2233]     }
[2234] 
[2235] #if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
[2236] 
[2237]     if (hc->ssl_servername) {
[2238]         ngx_http_ssl_srv_conf_t  *sscf;
[2239] 
[2240]         if (rc == NGX_DECLINED) {
[2241]             cscf = hc->addr_conf->default_server;
[2242]             rc = NGX_OK;
[2243]         }
[2244] 
[2245]         sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);
[2246] 
[2247]         if (sscf->verify) {
[2248]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[2249]                           "client attempted to request the server name "
[2250]                           "different from the one that was negotiated");
[2251]             ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
[2252]             return NGX_ERROR;
[2253]         }
[2254]     }
[2255] 
[2256] #endif
[2257] 
[2258]     if (rc == NGX_DECLINED) {
[2259]         return NGX_OK;
[2260]     }
[2261] 
[2262]     r->srv_conf = cscf->ctx->srv_conf;
[2263]     r->loc_conf = cscf->ctx->loc_conf;
[2264] 
[2265]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2266] 
[2267]     ngx_set_connection_log(r->connection, clcf->error_log);
[2268] 
[2269]     return NGX_OK;
[2270] }
[2271] 
[2272] 
[2273] static ngx_int_t
[2274] ngx_http_find_virtual_server(ngx_connection_t *c,
[2275]     ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
[2276]     ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
[2277] {
[2278]     ngx_http_core_srv_conf_t  *cscf;
[2279] 
[2280]     if (virtual_names == NULL) {
[2281]         return NGX_DECLINED;
[2282]     }
[2283] 
[2284]     cscf = ngx_hash_find_combined(&virtual_names->names,
[2285]                                   ngx_hash_key(host->data, host->len),
[2286]                                   host->data, host->len);
[2287] 
[2288]     if (cscf) {
[2289]         *cscfp = cscf;
[2290]         return NGX_OK;
[2291]     }
[2292] 
[2293] #if (NGX_PCRE)
[2294] 
[2295]     if (host->len && virtual_names->nregex) {
[2296]         ngx_int_t                n;
[2297]         ngx_uint_t               i;
[2298]         ngx_http_server_name_t  *sn;
[2299] 
[2300]         sn = virtual_names->regex;
[2301] 
[2302] #if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
[2303] 
[2304]         if (r == NULL) {
[2305]             ngx_http_connection_t  *hc;
[2306] 
[2307]             for (i = 0; i < virtual_names->nregex; i++) {
[2308] 
[2309]                 n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);
[2310] 
[2311]                 if (n == NGX_REGEX_NO_MATCHED) {
[2312]                     continue;
[2313]                 }
[2314] 
[2315]                 if (n >= 0) {
[2316]                     hc = c->data;
[2317]                     hc->ssl_servername_regex = sn[i].regex;
[2318] 
[2319]                     *cscfp = sn[i].server;
[2320]                     return NGX_OK;
[2321]                 }
[2322] 
[2323]                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[2324]                               ngx_regex_exec_n " failed: %i "
[2325]                               "on \"%V\" using \"%V\"",
[2326]                               n, host, &sn[i].regex->name);
[2327] 
[2328]                 return NGX_ERROR;
[2329]             }
[2330] 
[2331]             return NGX_DECLINED;
[2332]         }
[2333] 
[2334] #endif /* NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */
[2335] 
[2336]         for (i = 0; i < virtual_names->nregex; i++) {
[2337] 
[2338]             n = ngx_http_regex_exec(r, sn[i].regex, host);
[2339] 
[2340]             if (n == NGX_DECLINED) {
[2341]                 continue;
[2342]             }
[2343] 
[2344]             if (n == NGX_OK) {
[2345]                 *cscfp = sn[i].server;
[2346]                 return NGX_OK;
[2347]             }
[2348] 
[2349]             return NGX_ERROR;
[2350]         }
[2351]     }
[2352] 
[2353] #endif /* NGX_PCRE */
[2354] 
[2355]     return NGX_DECLINED;
[2356] }
[2357] 
[2358] 
[2359] static void
[2360] ngx_http_request_handler(ngx_event_t *ev)
[2361] {
[2362]     ngx_connection_t    *c;
[2363]     ngx_http_request_t  *r;
[2364] 
[2365]     c = ev->data;
[2366]     r = c->data;
[2367] 
[2368]     ngx_http_set_log_request(c->log, r);
[2369] 
[2370]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2371]                    "http run request: \"%V?%V\"", &r->uri, &r->args);
[2372] 
[2373]     if (c->close) {
[2374]         r->main->count++;
[2375]         ngx_http_terminate_request(r, 0);
[2376]         ngx_http_run_posted_requests(c);
[2377]         return;
[2378]     }
[2379] 
[2380]     if (ev->delayed && ev->timedout) {
[2381]         ev->delayed = 0;
[2382]         ev->timedout = 0;
[2383]     }
[2384] 
[2385]     if (ev->write) {
[2386]         r->write_event_handler(r);
[2387] 
[2388]     } else {
[2389]         r->read_event_handler(r);
[2390]     }
[2391] 
[2392]     ngx_http_run_posted_requests(c);
[2393] }
[2394] 
[2395] 
[2396] void
[2397] ngx_http_run_posted_requests(ngx_connection_t *c)
[2398] {
[2399]     ngx_http_request_t         *r;
[2400]     ngx_http_posted_request_t  *pr;
[2401] 
[2402]     for ( ;; ) {
[2403] 
[2404]         if (c->destroyed) {
[2405]             return;
[2406]         }
[2407] 
[2408]         r = c->data;
[2409]         pr = r->main->posted_requests;
[2410] 
[2411]         if (pr == NULL) {
[2412]             return;
[2413]         }
[2414] 
[2415]         r->main->posted_requests = pr->next;
[2416] 
[2417]         r = pr->request;
[2418] 
[2419]         ngx_http_set_log_request(c->log, r);
[2420] 
[2421]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2422]                        "http posted request: \"%V?%V\"", &r->uri, &r->args);
[2423] 
[2424]         r->write_event_handler(r);
[2425]     }
[2426] }
[2427] 
[2428] 
[2429] ngx_int_t
[2430] ngx_http_post_request(ngx_http_request_t *r, ngx_http_posted_request_t *pr)
[2431] {
[2432]     ngx_http_posted_request_t  **p;
[2433] 
[2434]     if (pr == NULL) {
[2435]         pr = ngx_palloc(r->pool, sizeof(ngx_http_posted_request_t));
[2436]         if (pr == NULL) {
[2437]             return NGX_ERROR;
[2438]         }
[2439]     }
[2440] 
[2441]     pr->request = r;
[2442]     pr->next = NULL;
[2443] 
[2444]     for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }
[2445] 
[2446]     *p = pr;
[2447] 
[2448]     return NGX_OK;
[2449] }
[2450] 
[2451] 
[2452] void
[2453] ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[2454] {
[2455]     ngx_connection_t          *c;
[2456]     ngx_http_request_t        *pr;
[2457]     ngx_http_core_loc_conf_t  *clcf;
[2458] 
[2459]     c = r->connection;
[2460] 
[2461]     ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2462]                    "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
[2463]                    rc, &r->uri, &r->args, r == c->data, r->main->count);
[2464] 
[2465]     if (rc == NGX_DONE) {
[2466]         ngx_http_finalize_connection(r);
[2467]         return;
[2468]     }
[2469] 
[2470]     if (rc == NGX_OK && r->filter_finalize) {
[2471]         c->error = 1;
[2472]     }
[2473] 
[2474]     if (rc == NGX_DECLINED) {
[2475]         r->content_handler = NULL;
[2476]         r->write_event_handler = ngx_http_core_run_phases;
[2477]         ngx_http_core_run_phases(r);
[2478]         return;
[2479]     }
[2480] 
[2481]     if (r != r->main && r->post_subrequest) {
[2482]         rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
[2483]     }
[2484] 
[2485]     if (rc == NGX_ERROR
[2486]         || rc == NGX_HTTP_REQUEST_TIME_OUT
[2487]         || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST
[2488]         || c->error)
[2489]     {
[2490]         if (ngx_http_post_action(r) == NGX_OK) {
[2491]             return;
[2492]         }
[2493] 
[2494]         ngx_http_terminate_request(r, rc);
[2495]         return;
[2496]     }
[2497] 
[2498]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE
[2499]         || rc == NGX_HTTP_CREATED
[2500]         || rc == NGX_HTTP_NO_CONTENT)
[2501]     {
[2502]         if (rc == NGX_HTTP_CLOSE) {
[2503]             c->timedout = 1;
[2504]             ngx_http_terminate_request(r, rc);
[2505]             return;
[2506]         }
[2507] 
[2508]         if (r == r->main) {
[2509]             if (c->read->timer_set) {
[2510]                 ngx_del_timer(c->read);
[2511]             }
[2512] 
[2513]             if (c->write->timer_set) {
[2514]                 ngx_del_timer(c->write);
[2515]             }
[2516]         }
[2517] 
[2518]         c->read->handler = ngx_http_request_handler;
[2519]         c->write->handler = ngx_http_request_handler;
[2520] 
[2521]         ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
[2522]         return;
[2523]     }
[2524] 
[2525]     if (r != r->main) {
[2526] 
[2527]         if (r->buffered || r->postponed) {
[2528] 
[2529]             if (ngx_http_set_write_handler(r) != NGX_OK) {
[2530]                 ngx_http_terminate_request(r, 0);
[2531]             }
[2532] 
[2533]             return;
[2534]         }
[2535] 
[2536]         pr = r->parent;
[2537] 
[2538]         if (r == c->data || r->background) {
[2539] 
[2540]             if (!r->logged) {
[2541] 
[2542]                 clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2543] 
[2544]                 if (clcf->log_subrequest) {
[2545]                     ngx_http_log_request(r);
[2546]                 }
[2547] 
[2548]                 r->logged = 1;
[2549] 
[2550]             } else {
[2551]                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[2552]                               "subrequest: \"%V?%V\" logged again",
[2553]                               &r->uri, &r->args);
[2554]             }
[2555] 
[2556]             r->done = 1;
[2557] 
[2558]             if (r->background) {
[2559]                 ngx_http_finalize_connection(r);
[2560]                 return;
[2561]             }
[2562] 
[2563]             r->main->count--;
[2564] 
[2565]             if (pr->postponed && pr->postponed->request == r) {
[2566]                 pr->postponed = pr->postponed->next;
[2567]             }
[2568] 
[2569]             c->data = pr;
[2570] 
[2571]         } else {
[2572] 
[2573]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2574]                            "http finalize non-active request: \"%V?%V\"",
[2575]                            &r->uri, &r->args);
[2576] 
[2577]             r->write_event_handler = ngx_http_request_finalizer;
[2578] 
[2579]             if (r->waited) {
[2580]                 r->done = 1;
[2581]             }
[2582]         }
[2583] 
[2584]         if (ngx_http_post_request(pr, NULL) != NGX_OK) {
[2585]             r->main->count++;
[2586]             ngx_http_terminate_request(r, 0);
[2587]             return;
[2588]         }
[2589] 
[2590]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2591]                        "http wake parent request: \"%V?%V\"",
[2592]                        &pr->uri, &pr->args);
[2593] 
[2594]         return;
[2595]     }
[2596] 
[2597]     if (r->buffered || c->buffered || r->postponed) {
[2598] 
[2599]         if (ngx_http_set_write_handler(r) != NGX_OK) {
[2600]             ngx_http_terminate_request(r, 0);
[2601]         }
[2602] 
[2603]         return;
[2604]     }
[2605] 
[2606]     if (r != c->data) {
[2607]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[2608]                       "http finalize non-active request: \"%V?%V\"",
[2609]                       &r->uri, &r->args);
[2610]         return;
[2611]     }
[2612] 
[2613]     r->done = 1;
[2614] 
[2615]     r->read_event_handler = ngx_http_block_reading;
[2616]     r->write_event_handler = ngx_http_request_empty_handler;
[2617] 
[2618]     if (!r->post_action) {
[2619]         r->request_complete = 1;
[2620]     }
[2621] 
[2622]     if (ngx_http_post_action(r) == NGX_OK) {
[2623]         return;
[2624]     }
[2625] 
[2626]     if (c->read->timer_set) {
[2627]         ngx_del_timer(c->read);
[2628]     }
[2629] 
[2630]     if (c->write->timer_set) {
[2631]         c->write->delayed = 0;
[2632]         ngx_del_timer(c->write);
[2633]     }
[2634] 
[2635]     ngx_http_finalize_connection(r);
[2636] }
[2637] 
[2638] 
[2639] static void
[2640] ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc)
[2641] {
[2642]     ngx_http_cleanup_t    *cln;
[2643]     ngx_http_request_t    *mr;
[2644]     ngx_http_ephemeral_t  *e;
[2645] 
[2646]     mr = r->main;
[2647] 
[2648]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2649]                    "http terminate request count:%d", mr->count);
[2650] 
[2651]     if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
[2652]         mr->headers_out.status = rc;
[2653]     }
[2654] 
[2655]     cln = mr->cleanup;
[2656]     mr->cleanup = NULL;
[2657] 
[2658]     while (cln) {
[2659]         if (cln->handler) {
[2660]             cln->handler(cln->data);
[2661]         }
[2662] 
[2663]         cln = cln->next;
[2664]     }
[2665] 
[2666]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2667]                    "http terminate cleanup count:%d blk:%d",
[2668]                    mr->count, mr->blocked);
[2669] 
[2670]     if (mr->write_event_handler) {
[2671] 
[2672]         if (mr->blocked) {
[2673]             r->connection->error = 1;
[2674]             r->write_event_handler = ngx_http_request_finalizer;
[2675]             return;
[2676]         }
[2677] 
[2678]         e = ngx_http_ephemeral(mr);
[2679]         mr->posted_requests = NULL;
[2680]         mr->write_event_handler = ngx_http_terminate_handler;
[2681]         (void) ngx_http_post_request(mr, &e->terminal_posted_request);
[2682]         return;
[2683]     }
[2684] 
[2685]     ngx_http_close_request(mr, rc);
[2686] }
[2687] 
[2688] 
[2689] static void
[2690] ngx_http_terminate_handler(ngx_http_request_t *r)
[2691] {
[2692]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2693]                    "http terminate handler count:%d", r->count);
[2694] 
[2695]     r->count = 1;
[2696] 
[2697]     ngx_http_close_request(r, 0);
[2698] }
[2699] 
[2700] 
[2701] static void
[2702] ngx_http_finalize_connection(ngx_http_request_t *r)
[2703] {
[2704]     ngx_http_core_loc_conf_t  *clcf;
[2705] 
[2706] #if (NGX_HTTP_V2)
[2707]     if (r->stream) {
[2708]         ngx_http_close_request(r, 0);
[2709]         return;
[2710]     }
[2711] #endif
[2712] 
[2713]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2714] 
[2715]     if (r->main->count != 1) {
[2716] 
[2717]         if (r->discard_body) {
[2718]             r->read_event_handler = ngx_http_discarded_request_body_handler;
[2719]             ngx_add_timer(r->connection->read, clcf->lingering_timeout);
[2720] 
[2721]             if (r->lingering_time == 0) {
[2722]                 r->lingering_time = ngx_time()
[2723]                                       + (time_t) (clcf->lingering_time / 1000);
[2724]             }
[2725]         }
[2726] 
[2727]         ngx_http_close_request(r, 0);
[2728]         return;
[2729]     }
[2730] 
[2731]     r = r->main;
[2732] 
[2733]     if (r->connection->read->eof) {
[2734]         ngx_http_close_request(r, 0);
[2735]         return;
[2736]     }
[2737] 
[2738]     if (r->reading_body) {
[2739]         r->keepalive = 0;
[2740]         r->lingering_close = 1;
[2741]     }
[2742] 
[2743]     if (!ngx_terminate
[2744]          && !ngx_exiting
[2745]          && r->keepalive
[2746]          && clcf->keepalive_timeout > 0)
[2747]     {
[2748]         ngx_http_set_keepalive(r);
[2749]         return;
[2750]     }
[2751] 
[2752]     if (clcf->lingering_close == NGX_HTTP_LINGERING_ALWAYS
[2753]         || (clcf->lingering_close == NGX_HTTP_LINGERING_ON
[2754]             && (r->lingering_close
[2755]                 || r->header_in->pos < r->header_in->last
[2756]                 || r->connection->read->ready
[2757]                 || r->connection->pipeline)))
[2758]     {
[2759]         ngx_http_set_lingering_close(r->connection);
[2760]         return;
[2761]     }
[2762] 
[2763]     ngx_http_close_request(r, 0);
[2764] }
[2765] 
[2766] 
[2767] static ngx_int_t
[2768] ngx_http_set_write_handler(ngx_http_request_t *r)
[2769] {
[2770]     ngx_event_t               *wev;
[2771]     ngx_http_core_loc_conf_t  *clcf;
[2772] 
[2773]     r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;
[2774] 
[2775]     r->read_event_handler = r->discard_body ?
[2776]                                 ngx_http_discarded_request_body_handler:
[2777]                                 ngx_http_test_reading;
[2778]     r->write_event_handler = ngx_http_writer;
[2779] 
[2780]     wev = r->connection->write;
[2781] 
[2782]     if (wev->ready && wev->delayed) {
[2783]         return NGX_OK;
[2784]     }
[2785] 
[2786]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2787]     if (!wev->delayed) {
[2788]         ngx_add_timer(wev, clcf->send_timeout);
[2789]     }
[2790] 
[2791]     if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
[2792]         ngx_http_close_request(r, 0);
[2793]         return NGX_ERROR;
[2794]     }
[2795] 
[2796]     return NGX_OK;
[2797] }
[2798] 
[2799] 
[2800] static void
[2801] ngx_http_writer(ngx_http_request_t *r)
[2802] {
[2803]     ngx_int_t                  rc;
[2804]     ngx_event_t               *wev;
[2805]     ngx_connection_t          *c;
[2806]     ngx_http_core_loc_conf_t  *clcf;
[2807] 
[2808]     c = r->connection;
[2809]     wev = c->write;
[2810] 
[2811]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
[2812]                    "http writer handler: \"%V?%V\"", &r->uri, &r->args);
[2813] 
[2814]     clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);
[2815] 
[2816]     if (wev->timedout) {
[2817]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
[2818]                       "client timed out");
[2819]         c->timedout = 1;
[2820] 
[2821]         ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
[2822]         return;
[2823]     }
[2824] 
[2825]     if (wev->delayed || r->aio) {
[2826]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
[2827]                        "http writer delayed");
[2828] 
[2829]         if (!wev->delayed) {
[2830]             ngx_add_timer(wev, clcf->send_timeout);
[2831]         }
[2832] 
[2833]         if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
[2834]             ngx_http_close_request(r, 0);
[2835]         }
[2836] 
[2837]         return;
[2838]     }
[2839] 
[2840]     rc = ngx_http_output_filter(r, NULL);
[2841] 
[2842]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2843]                    "http writer output filter: %i, \"%V?%V\"",
[2844]                    rc, &r->uri, &r->args);
[2845] 
[2846]     if (rc == NGX_ERROR) {
[2847]         ngx_http_finalize_request(r, rc);
[2848]         return;
[2849]     }
[2850] 
[2851]     if (r->buffered || r->postponed || (r == r->main && c->buffered)) {
[2852] 
[2853]         if (!wev->delayed) {
[2854]             ngx_add_timer(wev, clcf->send_timeout);
[2855]         }
[2856] 
[2857]         if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
[2858]             ngx_http_close_request(r, 0);
[2859]         }
[2860] 
[2861]         return;
[2862]     }
[2863] 
[2864]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
[2865]                    "http writer done: \"%V?%V\"", &r->uri, &r->args);
[2866] 
[2867]     r->write_event_handler = ngx_http_request_empty_handler;
[2868] 
[2869]     ngx_http_finalize_request(r, rc);
[2870] }
[2871] 
[2872] 
[2873] static void
[2874] ngx_http_request_finalizer(ngx_http_request_t *r)
[2875] {
[2876]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2877]                    "http finalizer done: \"%V?%V\"", &r->uri, &r->args);
[2878] 
[2879]     ngx_http_finalize_request(r, 0);
[2880] }
[2881] 
[2882] 
[2883] void
[2884] ngx_http_block_reading(ngx_http_request_t *r)
[2885] {
[2886]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2887]                    "http reading blocked");
[2888] 
[2889]     /* aio does not call this handler */
[2890] 
[2891]     if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
[2892]         && r->connection->read->active)
[2893]     {
[2894]         if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
[2895]             ngx_http_close_request(r, 0);
[2896]         }
[2897]     }
[2898] }
[2899] 
[2900] 
[2901] void
[2902] ngx_http_test_reading(ngx_http_request_t *r)
[2903] {
[2904]     int                n;
[2905]     char               buf[1];
[2906]     ngx_err_t          err;
[2907]     ngx_event_t       *rev;
[2908]     ngx_connection_t  *c;
[2909] 
[2910]     c = r->connection;
[2911]     rev = c->read;
[2912] 
[2913]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http test reading");
[2914] 
[2915] #if (NGX_HTTP_V2)
[2916] 
[2917]     if (r->stream) {
[2918]         if (c->error) {
[2919]             err = 0;
[2920]             goto closed;
[2921]         }
[2922] 
[2923]         return;
[2924]     }
[2925] 
[2926] #endif
[2927] 
[2928] #if (NGX_HAVE_KQUEUE)
[2929] 
[2930]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[2931] 
[2932]         if (!rev->pending_eof) {
[2933]             return;
[2934]         }
[2935] 
[2936]         rev->eof = 1;
[2937]         c->error = 1;
[2938]         err = rev->kq_errno;
[2939] 
[2940]         goto closed;
[2941]     }
[2942] 
[2943] #endif
[2944] 
[2945] #if (NGX_HAVE_EPOLLRDHUP)
[2946] 
[2947]     if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
[2948]         socklen_t  len;
[2949] 
[2950]         if (!rev->pending_eof) {
[2951]             return;
[2952]         }
[2953] 
[2954]         rev->eof = 1;
[2955]         c->error = 1;
[2956] 
[2957]         err = 0;
[2958]         len = sizeof(ngx_err_t);
[2959] 
[2960]         /*
[2961]          * BSDs and Linux return 0 and set a pending error in err
[2962]          * Solaris returns -1 and sets errno
[2963]          */
[2964] 
[2965]         if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
[2966]             == -1)
[2967]         {
[2968]             err = ngx_socket_errno;
[2969]         }
[2970] 
[2971]         goto closed;
[2972]     }
[2973] 
[2974] #endif
[2975] 
[2976]     n = recv(c->fd, buf, 1, MSG_PEEK);
[2977] 
[2978]     if (n == 0) {
[2979]         rev->eof = 1;
[2980]         c->error = 1;
[2981]         err = 0;
[2982] 
[2983]         goto closed;
[2984] 
[2985]     } else if (n == -1) {
[2986]         err = ngx_socket_errno;
[2987] 
[2988]         if (err != NGX_EAGAIN) {
[2989]             rev->eof = 1;
[2990]             c->error = 1;
[2991] 
[2992]             goto closed;
[2993]         }
[2994]     }
[2995] 
[2996]     /* aio does not call this handler */
[2997] 
[2998]     if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {
[2999] 
[3000]         if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
[3001]             ngx_http_close_request(r, 0);
[3002]         }
[3003]     }
[3004] 
[3005]     return;
[3006] 
[3007] closed:
[3008] 
[3009]     if (err) {
[3010]         rev->error = 1;
[3011]     }
[3012] 
[3013] #if (NGX_HTTP_SSL)
[3014]     if (c->ssl) {
[3015]         c->ssl->no_send_shutdown = 1;
[3016]     }
[3017] #endif
[3018] 
[3019]     ngx_log_error(NGX_LOG_INFO, c->log, err,
[3020]                   "client prematurely closed connection");
[3021] 
[3022]     ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
[3023] }
[3024] 
[3025] 
[3026] static void
[3027] ngx_http_set_keepalive(ngx_http_request_t *r)
[3028] {
[3029]     int                        tcp_nodelay;
[3030]     ngx_buf_t                 *b, *f;
[3031]     ngx_chain_t               *cl, *ln;
[3032]     ngx_event_t               *rev, *wev;
[3033]     ngx_connection_t          *c;
[3034]     ngx_http_connection_t     *hc;
[3035]     ngx_http_core_loc_conf_t  *clcf;
[3036] 
[3037]     c = r->connection;
[3038]     rev = c->read;
[3039] 
[3040]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3041] 
[3042]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");
[3043] 
[3044]     c->log->action = "closing request";
[3045] 
[3046]     hc = r->http_connection;
[3047]     b = r->header_in;
[3048] 
[3049]     if (b->pos < b->last) {
[3050] 
[3051]         /* the pipelined request */
[3052] 
[3053]         if (b != c->buffer) {
[3054] 
[3055]             /*
[3056]              * If the large header buffers were allocated while the previous
[3057]              * request processing then we do not use c->buffer for
[3058]              * the pipelined request (see ngx_http_create_request()).
[3059]              *
[3060]              * Now we would move the large header buffers to the free list.
[3061]              */
[3062] 
[3063]             for (cl = hc->busy; cl; /* void */) {
[3064]                 ln = cl;
[3065]                 cl = cl->next;
[3066] 
[3067]                 if (ln->buf == b) {
[3068]                     ngx_free_chain(c->pool, ln);
[3069]                     continue;
[3070]                 }
[3071] 
[3072]                 f = ln->buf;
[3073]                 f->pos = f->start;
[3074]                 f->last = f->start;
[3075] 
[3076]                 ln->next = hc->free;
[3077]                 hc->free = ln;
[3078]             }
[3079] 
[3080]             cl = ngx_alloc_chain_link(c->pool);
[3081]             if (cl == NULL) {
[3082]                 ngx_http_close_request(r, 0);
[3083]                 return;
[3084]             }
[3085] 
[3086]             cl->buf = b;
[3087]             cl->next = NULL;
[3088] 
[3089]             hc->busy = cl;
[3090]             hc->nbusy = 1;
[3091]         }
[3092]     }
[3093] 
[3094]     /* guard against recursive call from ngx_http_finalize_connection() */
[3095]     r->keepalive = 0;
[3096] 
[3097]     ngx_http_free_request(r, 0);
[3098] 
[3099]     c->data = hc;
[3100] 
[3101]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[3102]         ngx_http_close_connection(c);
[3103]         return;
[3104]     }
[3105] 
[3106]     wev = c->write;
[3107]     wev->handler = ngx_http_empty_handler;
[3108] 
[3109]     if (b->pos < b->last) {
[3110] 
[3111]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");
[3112] 
[3113]         c->log->action = "reading client pipelined request line";
[3114] 
[3115]         r = ngx_http_create_request(c);
[3116]         if (r == NULL) {
[3117]             ngx_http_close_connection(c);
[3118]             return;
[3119]         }
[3120] 
[3121]         r->pipeline = 1;
[3122] 
[3123]         c->data = r;
[3124] 
[3125]         c->sent = 0;
[3126]         c->destroyed = 0;
[3127]         c->pipeline = 1;
[3128] 
[3129]         if (rev->timer_set) {
[3130]             ngx_del_timer(rev);
[3131]         }
[3132] 
[3133]         rev->handler = ngx_http_process_request_line;
[3134]         ngx_post_event(rev, &ngx_posted_events);
[3135]         return;
[3136]     }
[3137] 
[3138]     /*
[3139]      * To keep a memory footprint as small as possible for an idle keepalive
[3140]      * connection we try to free c->buffer's memory if it was allocated outside
[3141]      * the c->pool.  The large header buffers are always allocated outside the
[3142]      * c->pool and are freed too.
[3143]      */
[3144] 
[3145]     b = c->buffer;
[3146] 
[3147]     if (ngx_pfree(c->pool, b->start) == NGX_OK) {
[3148] 
[3149]         /*
[3150]          * the special note for ngx_http_keepalive_handler() that
[3151]          * c->buffer's memory was freed
[3152]          */
[3153] 
[3154]         b->pos = NULL;
[3155] 
[3156]     } else {
[3157]         b->pos = b->start;
[3158]         b->last = b->start;
[3159]     }
[3160] 
[3161]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
[3162]                    hc->free);
[3163] 
[3164]     if (hc->free) {
[3165]         for (cl = hc->free; cl; /* void */) {
[3166]             ln = cl;
[3167]             cl = cl->next;
[3168]             ngx_pfree(c->pool, ln->buf->start);
[3169]             ngx_free_chain(c->pool, ln);
[3170]         }
[3171] 
[3172]         hc->free = NULL;
[3173]     }
[3174] 
[3175]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
[3176]                    hc->busy, hc->nbusy);
[3177] 
[3178]     if (hc->busy) {
[3179]         for (cl = hc->busy; cl; /* void */) {
[3180]             ln = cl;
[3181]             cl = cl->next;
[3182]             ngx_pfree(c->pool, ln->buf->start);
[3183]             ngx_free_chain(c->pool, ln);
[3184]         }
[3185] 
[3186]         hc->busy = NULL;
[3187]         hc->nbusy = 0;
[3188]     }
[3189] 
[3190] #if (NGX_HTTP_SSL)
[3191]     if (c->ssl) {
[3192]         ngx_ssl_free_buffer(c);
[3193]     }
[3194] #endif
[3195] 
[3196]     rev->handler = ngx_http_keepalive_handler;
[3197] 
[3198]     if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
[3199]         if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
[3200]             ngx_http_close_connection(c);
[3201]             return;
[3202]         }
[3203]     }
[3204] 
[3205]     c->log->action = "keepalive";
[3206] 
[3207]     if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
[3208]         if (ngx_tcp_push(c->fd) == -1) {
[3209]             ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
[3210]             ngx_http_close_connection(c);
[3211]             return;
[3212]         }
[3213] 
[3214]         c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
[3215]         tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;
[3216] 
[3217]     } else {
[3218]         tcp_nodelay = 1;
[3219]     }
[3220] 
[3221]     if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[3222]         ngx_http_close_connection(c);
[3223]         return;
[3224]     }
[3225] 
[3226] #if 0
[3227]     /* if ngx_http_request_t was freed then we need some other place */
[3228]     r->http_state = NGX_HTTP_KEEPALIVE_STATE;
[3229] #endif
[3230] 
[3231]     c->idle = 1;
[3232]     ngx_reusable_connection(c, 1);
[3233] 
[3234]     ngx_add_timer(rev, clcf->keepalive_timeout);
[3235] 
[3236]     if (rev->ready) {
[3237]         ngx_post_event(rev, &ngx_posted_events);
[3238]     }
[3239] }
[3240] 
[3241] 
[3242] static void
[3243] ngx_http_keepalive_handler(ngx_event_t *rev)
[3244] {
[3245]     size_t             size;
[3246]     ssize_t            n;
[3247]     ngx_buf_t         *b;
[3248]     ngx_connection_t  *c;
[3249] 
[3250]     c = rev->data;
[3251] 
[3252]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");
[3253] 
[3254]     if (rev->timedout || c->close) {
[3255]         ngx_http_close_connection(c);
[3256]         return;
[3257]     }
[3258] 
[3259] #if (NGX_HAVE_KQUEUE)
[3260] 
[3261]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[3262]         if (rev->pending_eof) {
[3263]             c->log->handler = NULL;
[3264]             ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
[3265]                           "kevent() reported that client %V closed "
[3266]                           "keepalive connection", &c->addr_text);
[3267] #if (NGX_HTTP_SSL)
[3268]             if (c->ssl) {
[3269]                 c->ssl->no_send_shutdown = 1;
[3270]             }
[3271] #endif
[3272]             ngx_http_close_connection(c);
[3273]             return;
[3274]         }
[3275]     }
[3276] 
[3277] #endif
[3278] 
[3279]     b = c->buffer;
[3280]     size = b->end - b->start;
[3281] 
[3282]     if (b->pos == NULL) {
[3283] 
[3284]         /*
[3285]          * The c->buffer's memory was freed by ngx_http_set_keepalive().
[3286]          * However, the c->buffer->start and c->buffer->end were not changed
[3287]          * to keep the buffer size.
[3288]          */
[3289] 
[3290]         b->pos = ngx_palloc(c->pool, size);
[3291]         if (b->pos == NULL) {
[3292]             ngx_http_close_connection(c);
[3293]             return;
[3294]         }
[3295] 
[3296]         b->start = b->pos;
[3297]         b->last = b->pos;
[3298]         b->end = b->pos + size;
[3299]     }
[3300] 
[3301]     /*
[3302]      * MSIE closes a keepalive connection with RST flag
[3303]      * so we ignore ECONNRESET here.
[3304]      */
[3305] 
[3306]     c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
[3307]     ngx_set_socket_errno(0);
[3308] 
[3309]     n = c->recv(c, b->last, size);
[3310]     c->log_error = NGX_ERROR_INFO;
[3311] 
[3312]     if (n == NGX_AGAIN) {
[3313]         if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[3314]             ngx_http_close_connection(c);
[3315]             return;
[3316]         }
[3317] 
[3318]         /*
[3319]          * Like ngx_http_set_keepalive() we are trying to not hold
[3320]          * c->buffer's memory for a keepalive connection.
[3321]          */
[3322] 
[3323]         if (ngx_pfree(c->pool, b->start) == NGX_OK) {
[3324] 
[3325]             /*
[3326]              * the special note that c->buffer's memory was freed
[3327]              */
[3328] 
[3329]             b->pos = NULL;
[3330]         }
[3331] 
[3332]         return;
[3333]     }
[3334] 
[3335]     if (n == NGX_ERROR) {
[3336]         ngx_http_close_connection(c);
[3337]         return;
[3338]     }
[3339] 
[3340]     c->log->handler = NULL;
[3341] 
[3342]     if (n == 0) {
[3343]         ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
[3344]                       "client %V closed keepalive connection", &c->addr_text);
[3345]         ngx_http_close_connection(c);
[3346]         return;
[3347]     }
[3348] 
[3349]     b->last += n;
[3350] 
[3351]     c->log->handler = ngx_http_log_error;
[3352]     c->log->action = "reading client request line";
[3353] 
[3354]     c->idle = 0;
[3355]     ngx_reusable_connection(c, 0);
[3356] 
[3357]     c->data = ngx_http_create_request(c);
[3358]     if (c->data == NULL) {
[3359]         ngx_http_close_connection(c);
[3360]         return;
[3361]     }
[3362] 
[3363]     c->sent = 0;
[3364]     c->destroyed = 0;
[3365] 
[3366]     ngx_del_timer(rev);
[3367] 
[3368]     rev->handler = ngx_http_process_request_line;
[3369]     ngx_http_process_request_line(rev);
[3370] }
[3371] 
[3372] 
[3373] static void
[3374] ngx_http_set_lingering_close(ngx_connection_t *c)
[3375] {
[3376]     ngx_event_t               *rev, *wev;
[3377]     ngx_http_request_t        *r;
[3378]     ngx_http_core_loc_conf_t  *clcf;
[3379] 
[3380]     r = c->data;
[3381] 
[3382]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3383] 
[3384]     if (r->lingering_time == 0) {
[3385]         r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
[3386]     }
[3387] 
[3388] #if (NGX_HTTP_SSL)
[3389]     if (c->ssl) {
[3390]         ngx_int_t  rc;
[3391] 
[3392]         c->ssl->shutdown_without_free = 1;
[3393] 
[3394]         rc = ngx_ssl_shutdown(c);
[3395] 
[3396]         if (rc == NGX_ERROR) {
[3397]             ngx_http_close_request(r, 0);
[3398]             return;
[3399]         }
[3400] 
[3401]         if (rc == NGX_AGAIN) {
[3402]             c->ssl->handler = ngx_http_set_lingering_close;
[3403]             return;
[3404]         }
[3405]     }
[3406] #endif
[3407] 
[3408]     rev = c->read;
[3409]     rev->handler = ngx_http_lingering_close_handler;
[3410] 
[3411]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[3412]         ngx_http_close_request(r, 0);
[3413]         return;
[3414]     }
[3415] 
[3416]     wev = c->write;
[3417]     wev->handler = ngx_http_empty_handler;
[3418] 
[3419]     if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
[3420]         if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
[3421]             ngx_http_close_request(r, 0);
[3422]             return;
[3423]         }
[3424]     }
[3425] 
[3426]     if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
[3427]         ngx_connection_error(c, ngx_socket_errno,
[3428]                              ngx_shutdown_socket_n " failed");
[3429]         ngx_http_close_request(r, 0);
[3430]         return;
[3431]     }
[3432] 
[3433]     c->close = 0;
[3434]     ngx_reusable_connection(c, 1);
[3435] 
[3436]     ngx_add_timer(rev, clcf->lingering_timeout);
[3437] 
[3438]     if (rev->ready) {
[3439]         ngx_http_lingering_close_handler(rev);
[3440]     }
[3441] }
[3442] 
[3443] 
[3444] static void
[3445] ngx_http_lingering_close_handler(ngx_event_t *rev)
[3446] {
[3447]     ssize_t                    n;
[3448]     ngx_msec_t                 timer;
[3449]     ngx_connection_t          *c;
[3450]     ngx_http_request_t        *r;
[3451]     ngx_http_core_loc_conf_t  *clcf;
[3452]     u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];
[3453] 
[3454]     c = rev->data;
[3455]     r = c->data;
[3456] 
[3457]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3458]                    "http lingering close handler");
[3459] 
[3460]     if (rev->timedout || c->close) {
[3461]         ngx_http_close_request(r, 0);
[3462]         return;
[3463]     }
[3464] 
[3465]     timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();
[3466]     if ((ngx_msec_int_t) timer <= 0) {
[3467]         ngx_http_close_request(r, 0);
[3468]         return;
[3469]     }
[3470] 
[3471]     do {
[3472]         n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);
[3473] 
[3474]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);
[3475] 
[3476]         if (n == NGX_AGAIN) {
[3477]             break;
[3478]         }
[3479] 
[3480]         if (n == NGX_ERROR || n == 0) {
[3481]             ngx_http_close_request(r, 0);
[3482]             return;
[3483]         }
[3484] 
[3485]     } while (rev->ready);
[3486] 
[3487]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[3488]         ngx_http_close_request(r, 0);
[3489]         return;
[3490]     }
[3491] 
[3492]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3493] 
[3494]     timer *= 1000;
[3495] 
[3496]     if (timer > clcf->lingering_timeout) {
[3497]         timer = clcf->lingering_timeout;
[3498]     }
[3499] 
[3500]     ngx_add_timer(rev, timer);
[3501] }
[3502] 
[3503] 
[3504] void
[3505] ngx_http_empty_handler(ngx_event_t *wev)
[3506] {
[3507]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");
[3508] 
[3509]     return;
[3510] }
[3511] 
[3512] 
[3513] void
[3514] ngx_http_request_empty_handler(ngx_http_request_t *r)
[3515] {
[3516]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3517]                    "http request empty handler");
[3518] 
[3519]     return;
[3520] }
[3521] 
[3522] 
[3523] ngx_int_t
[3524] ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags)
[3525] {
[3526]     ngx_buf_t    *b;
[3527]     ngx_chain_t   out;
[3528] 
[3529]     b = ngx_calloc_buf(r->pool);
[3530]     if (b == NULL) {
[3531]         return NGX_ERROR;
[3532]     }
[3533] 
[3534]     if (flags & NGX_HTTP_LAST) {
[3535] 
[3536]         if (r == r->main && !r->post_action) {
[3537]             b->last_buf = 1;
[3538] 
[3539]         } else {
[3540]             b->sync = 1;
[3541]             b->last_in_chain = 1;
[3542]         }
[3543]     }
[3544] 
[3545]     if (flags & NGX_HTTP_FLUSH) {
[3546]         b->flush = 1;
[3547]     }
[3548] 
[3549]     out.buf = b;
[3550]     out.next = NULL;
[3551] 
[3552]     return ngx_http_output_filter(r, &out);
[3553] }
[3554] 
[3555] 
[3556] static ngx_int_t
[3557] ngx_http_post_action(ngx_http_request_t *r)
[3558] {
[3559]     ngx_http_core_loc_conf_t  *clcf;
[3560] 
[3561]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3562] 
[3563]     if (clcf->post_action.data == NULL) {
[3564]         return NGX_DECLINED;
[3565]     }
[3566] 
[3567]     if (r->post_action && r->uri_changes == 0) {
[3568]         return NGX_DECLINED;
[3569]     }
[3570] 
[3571]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3572]                    "post action: \"%V\"", &clcf->post_action);
[3573] 
[3574]     r->main->count--;
[3575] 
[3576]     r->http_version = NGX_HTTP_VERSION_9;
[3577]     r->header_only = 1;
[3578]     r->post_action = 1;
[3579] 
[3580]     r->read_event_handler = ngx_http_block_reading;
[3581] 
[3582]     if (clcf->post_action.data[0] == '/') {
[3583]         ngx_http_internal_redirect(r, &clcf->post_action, NULL);
[3584] 
[3585]     } else {
[3586]         ngx_http_named_location(r, &clcf->post_action);
[3587]     }
[3588] 
[3589]     return NGX_OK;
[3590] }
[3591] 
[3592] 
[3593] static void
[3594] ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc)
[3595] {
[3596]     ngx_connection_t  *c;
[3597] 
[3598]     r = r->main;
[3599]     c = r->connection;
[3600] 
[3601]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3602]                    "http request count:%d blk:%d", r->count, r->blocked);
[3603] 
[3604]     if (r->count == 0) {
[3605]         ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
[3606]     }
[3607] 
[3608]     r->count--;
[3609] 
[3610]     if (r->count || r->blocked) {
[3611]         return;
[3612]     }
[3613] 
[3614] #if (NGX_HTTP_V2)
[3615]     if (r->stream) {
[3616]         ngx_http_v2_close_stream(r->stream, rc);
[3617]         return;
[3618]     }
[3619] #endif
[3620] 
[3621]     ngx_http_free_request(r, rc);
[3622]     ngx_http_close_connection(c);
[3623] }
[3624] 
[3625] 
[3626] void
[3627] ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc)
[3628] {
[3629]     ngx_log_t                 *log;
[3630]     ngx_pool_t                *pool;
[3631]     struct linger              linger;
[3632]     ngx_http_cleanup_t        *cln;
[3633]     ngx_http_log_ctx_t        *ctx;
[3634]     ngx_http_core_loc_conf_t  *clcf;
[3635] 
[3636]     log = r->connection->log;
[3637] 
[3638]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");
[3639] 
[3640]     if (r->pool == NULL) {
[3641]         ngx_log_error(NGX_LOG_ALERT, log, 0, "http request already closed");
[3642]         return;
[3643]     }
[3644] 
[3645]     cln = r->cleanup;
[3646]     r->cleanup = NULL;
[3647] 
[3648]     while (cln) {
[3649]         if (cln->handler) {
[3650]             cln->handler(cln->data);
[3651]         }
[3652] 
[3653]         cln = cln->next;
[3654]     }
[3655] 
[3656] #if (NGX_STAT_STUB)
[3657] 
[3658]     if (r->stat_reading) {
[3659]         (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
[3660]     }
[3661] 
[3662]     if (r->stat_writing) {
[3663]         (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
[3664]     }
[3665] 
[3666] #endif
[3667] 
[3668]     if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
[3669]         r->headers_out.status = rc;
[3670]     }
[3671] 
[3672]     if (!r->logged) {
[3673]         log->action = "logging request";
[3674] 
[3675]         ngx_http_log_request(r);
[3676]     }
[3677] 
[3678]     log->action = "closing request";
[3679] 
[3680]     if (r->connection->timedout) {
[3681]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[3682] 
[3683]         if (clcf->reset_timedout_connection) {
[3684]             linger.l_onoff = 1;
[3685]             linger.l_linger = 0;
[3686] 
[3687]             if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
[3688]                            (const void *) &linger, sizeof(struct linger)) == -1)
[3689]             {
[3690]                 ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
[3691]                               "setsockopt(SO_LINGER) failed");
[3692]             }
[3693]         }
[3694]     }
[3695] 
[3696]     /* the various request strings were allocated from r->pool */
[3697]     ctx = log->data;
[3698]     ctx->request = NULL;
[3699] 
[3700]     r->request_line.len = 0;
[3701] 
[3702]     r->connection->destroyed = 1;
[3703] 
[3704]     /*
[3705]      * Setting r->pool to NULL will increase probability to catch double close
[3706]      * of request since the request object is allocated from its own pool.
[3707]      */
[3708] 
[3709]     pool = r->pool;
[3710]     r->pool = NULL;
[3711] 
[3712]     ngx_destroy_pool(pool);
[3713] }
[3714] 
[3715] 
[3716] static void
[3717] ngx_http_log_request(ngx_http_request_t *r)
[3718] {
[3719]     ngx_uint_t                  i, n;
[3720]     ngx_http_handler_pt        *log_handler;
[3721]     ngx_http_core_main_conf_t  *cmcf;
[3722] 
[3723]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[3724] 
[3725]     log_handler = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.elts;
[3726]     n = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.nelts;
[3727] 
[3728]     for (i = 0; i < n; i++) {
[3729]         log_handler[i](r);
[3730]     }
[3731] }
[3732] 
[3733] 
[3734] void
[3735] ngx_http_close_connection(ngx_connection_t *c)
[3736] {
[3737]     ngx_pool_t  *pool;
[3738] 
[3739]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[3740]                    "close http connection: %d", c->fd);
[3741] 
[3742] #if (NGX_HTTP_SSL)
[3743] 
[3744]     if (c->ssl) {
[3745]         if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
[3746]             c->ssl->handler = ngx_http_close_connection;
[3747]             return;
[3748]         }
[3749]     }
[3750] 
[3751] #endif
[3752] 
[3753] #if (NGX_STAT_STUB)
[3754]     (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
[3755] #endif
[3756] 
[3757]     c->destroyed = 1;
[3758] 
[3759]     pool = c->pool;
[3760] 
[3761]     ngx_close_connection(c);
[3762] 
[3763]     ngx_destroy_pool(pool);
[3764] }
[3765] 
[3766] 
[3767] static u_char *
[3768] ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len)
[3769] {
[3770]     u_char              *p;
[3771]     ngx_http_request_t  *r;
[3772]     ngx_http_log_ctx_t  *ctx;
[3773] 
[3774]     if (log->action) {
[3775]         p = ngx_snprintf(buf, len, " while %s", log->action);
[3776]         len -= p - buf;
[3777]         buf = p;
[3778]     }
[3779] 
[3780]     ctx = log->data;
[3781] 
[3782]     p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
[3783]     len -= p - buf;
[3784] 
[3785]     r = ctx->request;
[3786] 
[3787]     if (r) {
[3788]         return r->log_handler(r, ctx->current_request, p, len);
[3789] 
[3790]     } else {
[3791]         p = ngx_snprintf(p, len, ", server: %V",
[3792]                          &ctx->connection->listening->addr_text);
[3793]     }
[3794] 
[3795]     return p;
[3796] }
[3797] 
[3798] 
[3799] static u_char *
[3800] ngx_http_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
[3801]     u_char *buf, size_t len)
[3802] {
[3803]     char                      *uri_separator;
[3804]     u_char                    *p;
[3805]     ngx_http_upstream_t       *u;
[3806]     ngx_http_core_srv_conf_t  *cscf;
[3807] 
[3808]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[3809] 
[3810]     p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
[3811]     len -= p - buf;
[3812]     buf = p;
[3813] 
[3814]     if (r->request_line.data == NULL && r->request_start) {
[3815]         for (p = r->request_start; p < r->header_in->last; p++) {
[3816]             if (*p == CR || *p == LF) {
[3817]                 break;
[3818]             }
[3819]         }
[3820] 
[3821]         r->request_line.len = p - r->request_start;
[3822]         r->request_line.data = r->request_start;
[3823]     }
[3824] 
[3825]     if (r->request_line.len) {
[3826]         p = ngx_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
[3827]         len -= p - buf;
[3828]         buf = p;
[3829]     }
[3830] 
[3831]     if (r != sr) {
[3832]         p = ngx_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
[3833]         len -= p - buf;
[3834]         buf = p;
[3835]     }
[3836] 
[3837]     u = sr->upstream;
[3838] 
[3839]     if (u && u->peer.name) {
[3840] 
[3841]         uri_separator = "";
[3842] 
[3843] #if (NGX_HAVE_UNIX_DOMAIN)
[3844]         if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
[3845]             uri_separator = ":";
[3846]         }
[3847] #endif
[3848] 
[3849]         p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
[3850]                          &u->schema, u->peer.name,
[3851]                          uri_separator, &u->uri);
[3852]         len -= p - buf;
[3853]         buf = p;
[3854]     }
[3855] 
[3856]     if (r->headers_in.host) {
[3857]         p = ngx_snprintf(buf, len, ", host: \"%V\"",
[3858]                          &r->headers_in.host->value);
[3859]         len -= p - buf;
[3860]         buf = p;
[3861]     }
[3862] 
[3863]     if (r->headers_in.referer) {
[3864]         p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
[3865]                          &r->headers_in.referer->value);
[3866]         buf = p;
[3867]     }
[3868] 
[3869]     return buf;
[3870] }
