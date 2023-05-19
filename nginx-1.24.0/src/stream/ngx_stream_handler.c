[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] #include <ngx_stream.h>
[12] 
[13] 
[14] static void ngx_stream_log_session(ngx_stream_session_t *s);
[15] static void ngx_stream_close_connection(ngx_connection_t *c);
[16] static u_char *ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len);
[17] static void ngx_stream_proxy_protocol_handler(ngx_event_t *rev);
[18] 
[19] 
[20] void
[21] ngx_stream_init_connection(ngx_connection_t *c)
[22] {
[23]     u_char                        text[NGX_SOCKADDR_STRLEN];
[24]     size_t                        len;
[25]     ngx_uint_t                    i;
[26]     ngx_time_t                   *tp;
[27]     ngx_event_t                  *rev;
[28]     struct sockaddr              *sa;
[29]     ngx_stream_port_t            *port;
[30]     struct sockaddr_in           *sin;
[31]     ngx_stream_in_addr_t         *addr;
[32]     ngx_stream_session_t         *s;
[33]     ngx_stream_addr_conf_t       *addr_conf;
[34] #if (NGX_HAVE_INET6)
[35]     struct sockaddr_in6          *sin6;
[36]     ngx_stream_in6_addr_t        *addr6;
[37] #endif
[38]     ngx_stream_core_srv_conf_t   *cscf;
[39]     ngx_stream_core_main_conf_t  *cmcf;
[40] 
[41]     /* find the server configuration for the address:port */
[42] 
[43]     port = c->listening->servers;
[44] 
[45]     if (port->naddrs > 1) {
[46] 
[47]         /*
[48]          * There are several addresses on this port and one of them
[49]          * is the "*:port" wildcard so getsockname() is needed to determine
[50]          * the server address.
[51]          *
[52]          * AcceptEx() and recvmsg() already gave this address.
[53]          */
[54] 
[55]         if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
[56]             ngx_stream_close_connection(c);
[57]             return;
[58]         }
[59] 
[60]         sa = c->local_sockaddr;
[61] 
[62]         switch (sa->sa_family) {
[63] 
[64] #if (NGX_HAVE_INET6)
[65]         case AF_INET6:
[66]             sin6 = (struct sockaddr_in6 *) sa;
[67] 
[68]             addr6 = port->addrs;
[69] 
[70]             /* the last address is "*" */
[71] 
[72]             for (i = 0; i < port->naddrs - 1; i++) {
[73]                 if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
[74]                     break;
[75]                 }
[76]             }
[77] 
[78]             addr_conf = &addr6[i].conf;
[79] 
[80]             break;
[81] #endif
[82] 
[83]         default: /* AF_INET */
[84]             sin = (struct sockaddr_in *) sa;
[85] 
[86]             addr = port->addrs;
[87] 
[88]             /* the last address is "*" */
[89] 
[90]             for (i = 0; i < port->naddrs - 1; i++) {
[91]                 if (addr[i].addr == sin->sin_addr.s_addr) {
[92]                     break;
[93]                 }
[94]             }
[95] 
[96]             addr_conf = &addr[i].conf;
[97] 
[98]             break;
[99]         }
[100] 
[101]     } else {
[102]         switch (c->local_sockaddr->sa_family) {
[103] 
[104] #if (NGX_HAVE_INET6)
[105]         case AF_INET6:
[106]             addr6 = port->addrs;
[107]             addr_conf = &addr6[0].conf;
[108]             break;
[109] #endif
[110] 
[111]         default: /* AF_INET */
[112]             addr = port->addrs;
[113]             addr_conf = &addr[0].conf;
[114]             break;
[115]         }
[116]     }
[117] 
[118]     s = ngx_pcalloc(c->pool, sizeof(ngx_stream_session_t));
[119]     if (s == NULL) {
[120]         ngx_stream_close_connection(c);
[121]         return;
[122]     }
[123] 
[124]     s->signature = NGX_STREAM_MODULE;
[125]     s->main_conf = addr_conf->ctx->main_conf;
[126]     s->srv_conf = addr_conf->ctx->srv_conf;
[127] 
[128] #if (NGX_STREAM_SSL)
[129]     s->ssl = addr_conf->ssl;
[130] #endif
[131] 
[132]     if (c->buffer) {
[133]         s->received += c->buffer->last - c->buffer->pos;
[134]     }
[135] 
[136]     s->connection = c;
[137]     c->data = s;
[138] 
[139]     cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
[140] 
[141]     ngx_set_connection_log(c, cscf->error_log);
[142] 
[143]     len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);
[144] 
[145]     ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
[146]                   c->number, c->type == SOCK_DGRAM ? "udp " : "",
[147]                   len, text, &addr_conf->addr_text);
[148] 
[149]     c->log->connection = c->number;
[150]     c->log->handler = ngx_stream_log_error;
[151]     c->log->data = s;
[152]     c->log->action = "initializing session";
[153]     c->log_error = NGX_ERROR_INFO;
[154] 
[155]     s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_stream_max_module);
[156]     if (s->ctx == NULL) {
[157]         ngx_stream_close_connection(c);
[158]         return;
[159]     }
[160] 
[161]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[162] 
[163]     s->variables = ngx_pcalloc(s->connection->pool,
[164]                                cmcf->variables.nelts
[165]                                * sizeof(ngx_stream_variable_value_t));
[166] 
[167]     if (s->variables == NULL) {
[168]         ngx_stream_close_connection(c);
[169]         return;
[170]     }
[171] 
[172]     tp = ngx_timeofday();
[173]     s->start_sec = tp->sec;
[174]     s->start_msec = tp->msec;
[175] 
[176]     rev = c->read;
[177]     rev->handler = ngx_stream_session_handler;
[178] 
[179]     if (addr_conf->proxy_protocol) {
[180]         c->log->action = "reading PROXY protocol";
[181] 
[182]         rev->handler = ngx_stream_proxy_protocol_handler;
[183] 
[184]         if (!rev->ready) {
[185]             ngx_add_timer(rev, cscf->proxy_protocol_timeout);
[186] 
[187]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[188]                 ngx_stream_finalize_session(s,
[189]                                             NGX_STREAM_INTERNAL_SERVER_ERROR);
[190]             }
[191] 
[192]             return;
[193]         }
[194]     }
[195] 
[196]     if (ngx_use_accept_mutex) {
[197]         ngx_post_event(rev, &ngx_posted_events);
[198]         return;
[199]     }
[200] 
[201]     rev->handler(rev);
[202] }
[203] 
[204] 
[205] static void
[206] ngx_stream_proxy_protocol_handler(ngx_event_t *rev)
[207] {
[208]     u_char                      *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER];
[209]     size_t                       size;
[210]     ssize_t                      n;
[211]     ngx_err_t                    err;
[212]     ngx_connection_t            *c;
[213]     ngx_stream_session_t        *s;
[214]     ngx_stream_core_srv_conf_t  *cscf;
[215] 
[216]     c = rev->data;
[217]     s = c->data;
[218] 
[219]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[220]                    "stream PROXY protocol handler");
[221] 
[222]     if (rev->timedout) {
[223]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[224]         ngx_stream_finalize_session(s, NGX_STREAM_OK);
[225]         return;
[226]     }
[227] 
[228]     n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);
[229] 
[230]     err = ngx_socket_errno;
[231] 
[232]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);
[233] 
[234]     if (n == -1) {
[235]         if (err == NGX_EAGAIN) {
[236]             rev->ready = 0;
[237] 
[238]             if (!rev->timer_set) {
[239]                 cscf = ngx_stream_get_module_srv_conf(s,
[240]                                                       ngx_stream_core_module);
[241] 
[242]                 ngx_add_timer(rev, cscf->proxy_protocol_timeout);
[243]             }
[244] 
[245]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[246]                 ngx_stream_finalize_session(s,
[247]                                             NGX_STREAM_INTERNAL_SERVER_ERROR);
[248]             }
[249] 
[250]             return;
[251]         }
[252] 
[253]         ngx_connection_error(c, err, "recv() failed");
[254] 
[255]         ngx_stream_finalize_session(s, NGX_STREAM_OK);
[256]         return;
[257]     }
[258] 
[259]     if (rev->timer_set) {
[260]         ngx_del_timer(rev);
[261]     }
[262] 
[263]     p = ngx_proxy_protocol_read(c, buf, buf + n);
[264] 
[265]     if (p == NULL) {
[266]         ngx_stream_finalize_session(s, NGX_STREAM_BAD_REQUEST);
[267]         return;
[268]     }
[269] 
[270]     size = p - buf;
[271] 
[272]     if (c->recv(c, buf, size) != (ssize_t) size) {
[273]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[274]         return;
[275]     }
[276] 
[277]     c->log->action = "initializing session";
[278] 
[279]     ngx_stream_session_handler(rev);
[280] }
[281] 
[282] 
[283] void
[284] ngx_stream_session_handler(ngx_event_t *rev)
[285] {
[286]     ngx_connection_t      *c;
[287]     ngx_stream_session_t  *s;
[288] 
[289]     c = rev->data;
[290]     s = c->data;
[291] 
[292]     ngx_stream_core_run_phases(s);
[293] }
[294] 
[295] 
[296] void
[297] ngx_stream_finalize_session(ngx_stream_session_t *s, ngx_uint_t rc)
[298] {
[299]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[300]                    "finalize stream session: %i", rc);
[301] 
[302]     s->status = rc;
[303] 
[304]     ngx_stream_log_session(s);
[305] 
[306]     ngx_stream_close_connection(s->connection);
[307] }
[308] 
[309] 
[310] static void
[311] ngx_stream_log_session(ngx_stream_session_t *s)
[312] {
[313]     ngx_uint_t                    i, n;
[314]     ngx_stream_handler_pt        *log_handler;
[315]     ngx_stream_core_main_conf_t  *cmcf;
[316] 
[317]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[318] 
[319]     log_handler = cmcf->phases[NGX_STREAM_LOG_PHASE].handlers.elts;
[320]     n = cmcf->phases[NGX_STREAM_LOG_PHASE].handlers.nelts;
[321] 
[322]     for (i = 0; i < n; i++) {
[323]         log_handler[i](s);
[324]     }
[325] }
[326] 
[327] 
[328] static void
[329] ngx_stream_close_connection(ngx_connection_t *c)
[330] {
[331]     ngx_pool_t  *pool;
[332] 
[333]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[334]                    "close stream connection: %d", c->fd);
[335] 
[336] #if (NGX_STREAM_SSL)
[337] 
[338]     if (c->ssl) {
[339]         if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
[340]             c->ssl->handler = ngx_stream_close_connection;
[341]             return;
[342]         }
[343]     }
[344] 
[345] #endif
[346] 
[347] #if (NGX_STAT_STUB)
[348]     (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
[349] #endif
[350] 
[351]     pool = c->pool;
[352] 
[353]     ngx_close_connection(c);
[354] 
[355]     ngx_destroy_pool(pool);
[356] }
[357] 
[358] 
[359] static u_char *
[360] ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len)
[361] {
[362]     u_char                *p;
[363]     ngx_stream_session_t  *s;
[364] 
[365]     if (log->action) {
[366]         p = ngx_snprintf(buf, len, " while %s", log->action);
[367]         len -= p - buf;
[368]         buf = p;
[369]     }
[370] 
[371]     s = log->data;
[372] 
[373]     p = ngx_snprintf(buf, len, ", %sclient: %V, server: %V",
[374]                      s->connection->type == SOCK_DGRAM ? "udp " : "",
[375]                      &s->connection->addr_text,
[376]                      &s->connection->listening->addr_text);
[377]     len -= p - buf;
[378]     buf = p;
[379] 
[380]     if (s->log_handler) {
[381]         p = s->log_handler(log, buf, len);
[382]     }
[383] 
[384]     return p;
[385] }
