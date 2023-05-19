[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] 
[12] 
[13] static ngx_int_t ngx_disable_accept_events(ngx_cycle_t *cycle, ngx_uint_t all);
[14] #if (NGX_HAVE_EPOLLEXCLUSIVE)
[15] static void ngx_reorder_accept_events(ngx_listening_t *ls);
[16] #endif
[17] static void ngx_close_accepted_connection(ngx_connection_t *c);
[18] 
[19] 
[20] void
[21] ngx_event_accept(ngx_event_t *ev)
[22] {
[23]     socklen_t          socklen;
[24]     ngx_err_t          err;
[25]     ngx_log_t         *log;
[26]     ngx_uint_t         level;
[27]     ngx_socket_t       s;
[28]     ngx_event_t       *rev, *wev;
[29]     ngx_sockaddr_t     sa;
[30]     ngx_listening_t   *ls;
[31]     ngx_connection_t  *c, *lc;
[32]     ngx_event_conf_t  *ecf;
[33] #if (NGX_HAVE_ACCEPT4)
[34]     static ngx_uint_t  use_accept4 = 1;
[35] #endif
[36] 
[37]     if (ev->timedout) {
[38]         if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
[39]             return;
[40]         }
[41] 
[42]         ev->timedout = 0;
[43]     }
[44] 
[45]     ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);
[46] 
[47]     if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
[48]         ev->available = ecf->multi_accept;
[49]     }
[50] 
[51]     lc = ev->data;
[52]     ls = lc->listening;
[53]     ev->ready = 0;
[54] 
[55]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[56]                    "accept on %V, ready: %d", &ls->addr_text, ev->available);
[57] 
[58]     do {
[59]         socklen = sizeof(ngx_sockaddr_t);
[60] 
[61] #if (NGX_HAVE_ACCEPT4)
[62]         if (use_accept4) {
[63]             s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK);
[64]         } else {
[65]             s = accept(lc->fd, &sa.sockaddr, &socklen);
[66]         }
[67] #else
[68]         s = accept(lc->fd, &sa.sockaddr, &socklen);
[69] #endif
[70] 
[71]         if (s == (ngx_socket_t) -1) {
[72]             err = ngx_socket_errno;
[73] 
[74]             if (err == NGX_EAGAIN) {
[75]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
[76]                                "accept() not ready");
[77]                 return;
[78]             }
[79] 
[80]             level = NGX_LOG_ALERT;
[81] 
[82]             if (err == NGX_ECONNABORTED) {
[83]                 level = NGX_LOG_ERR;
[84] 
[85]             } else if (err == NGX_EMFILE || err == NGX_ENFILE) {
[86]                 level = NGX_LOG_CRIT;
[87]             }
[88] 
[89] #if (NGX_HAVE_ACCEPT4)
[90]             ngx_log_error(level, ev->log, err,
[91]                           use_accept4 ? "accept4() failed" : "accept() failed");
[92] 
[93]             if (use_accept4 && err == NGX_ENOSYS) {
[94]                 use_accept4 = 0;
[95]                 ngx_inherited_nonblocking = 0;
[96]                 continue;
[97]             }
[98] #else
[99]             ngx_log_error(level, ev->log, err, "accept() failed");
[100] #endif
[101] 
[102]             if (err == NGX_ECONNABORTED) {
[103]                 if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[104]                     ev->available--;
[105]                 }
[106] 
[107]                 if (ev->available) {
[108]                     continue;
[109]                 }
[110]             }
[111] 
[112]             if (err == NGX_EMFILE || err == NGX_ENFILE) {
[113]                 if (ngx_disable_accept_events((ngx_cycle_t *) ngx_cycle, 1)
[114]                     != NGX_OK)
[115]                 {
[116]                     return;
[117]                 }
[118] 
[119]                 if (ngx_use_accept_mutex) {
[120]                     if (ngx_accept_mutex_held) {
[121]                         ngx_shmtx_unlock(&ngx_accept_mutex);
[122]                         ngx_accept_mutex_held = 0;
[123]                     }
[124] 
[125]                     ngx_accept_disabled = 1;
[126] 
[127]                 } else {
[128]                     ngx_add_timer(ev, ecf->accept_mutex_delay);
[129]                 }
[130]             }
[131] 
[132]             return;
[133]         }
[134] 
[135] #if (NGX_STAT_STUB)
[136]         (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
[137] #endif
[138] 
[139]         ngx_accept_disabled = ngx_cycle->connection_n / 8
[140]                               - ngx_cycle->free_connection_n;
[141] 
[142]         c = ngx_get_connection(s, ev->log);
[143] 
[144]         if (c == NULL) {
[145]             if (ngx_close_socket(s) == -1) {
[146]                 ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
[147]                               ngx_close_socket_n " failed");
[148]             }
[149] 
[150]             return;
[151]         }
[152] 
[153]         c->type = SOCK_STREAM;
[154] 
[155] #if (NGX_STAT_STUB)
[156]         (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
[157] #endif
[158] 
[159]         c->pool = ngx_create_pool(ls->pool_size, ev->log);
[160]         if (c->pool == NULL) {
[161]             ngx_close_accepted_connection(c);
[162]             return;
[163]         }
[164] 
[165]         if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
[166]             socklen = sizeof(ngx_sockaddr_t);
[167]         }
[168] 
[169]         c->sockaddr = ngx_palloc(c->pool, socklen);
[170]         if (c->sockaddr == NULL) {
[171]             ngx_close_accepted_connection(c);
[172]             return;
[173]         }
[174] 
[175]         ngx_memcpy(c->sockaddr, &sa, socklen);
[176] 
[177]         log = ngx_palloc(c->pool, sizeof(ngx_log_t));
[178]         if (log == NULL) {
[179]             ngx_close_accepted_connection(c);
[180]             return;
[181]         }
[182] 
[183]         /* set a blocking mode for iocp and non-blocking mode for others */
[184] 
[185]         if (ngx_inherited_nonblocking) {
[186]             if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[187]                 if (ngx_blocking(s) == -1) {
[188]                     ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
[189]                                   ngx_blocking_n " failed");
[190]                     ngx_close_accepted_connection(c);
[191]                     return;
[192]                 }
[193]             }
[194] 
[195]         } else {
[196]             if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
[197]                 if (ngx_nonblocking(s) == -1) {
[198]                     ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
[199]                                   ngx_nonblocking_n " failed");
[200]                     ngx_close_accepted_connection(c);
[201]                     return;
[202]                 }
[203]             }
[204]         }
[205] 
[206]         *log = ls->log;
[207] 
[208]         c->recv = ngx_recv;
[209]         c->send = ngx_send;
[210]         c->recv_chain = ngx_recv_chain;
[211]         c->send_chain = ngx_send_chain;
[212] 
[213]         c->log = log;
[214]         c->pool->log = log;
[215] 
[216]         c->socklen = socklen;
[217]         c->listening = ls;
[218]         c->local_sockaddr = ls->sockaddr;
[219]         c->local_socklen = ls->socklen;
[220] 
[221] #if (NGX_HAVE_UNIX_DOMAIN)
[222]         if (c->sockaddr->sa_family == AF_UNIX) {
[223]             c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
[224]             c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
[225] #if (NGX_SOLARIS)
[226]             /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
[227]             c->sendfile = 0;
[228] #endif
[229]         }
[230] #endif
[231] 
[232]         rev = c->read;
[233]         wev = c->write;
[234] 
[235]         wev->ready = 1;
[236] 
[237]         if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[238]             rev->ready = 1;
[239]         }
[240] 
[241]         if (ev->deferred_accept) {
[242]             rev->ready = 1;
[243] #if (NGX_HAVE_KQUEUE || NGX_HAVE_EPOLLRDHUP)
[244]             rev->available = 1;
[245] #endif
[246]         }
[247] 
[248]         rev->log = log;
[249]         wev->log = log;
[250] 
[251]         /*
[252]          * TODO: MT: - ngx_atomic_fetch_add()
[253]          *             or protection by critical section or light mutex
[254]          *
[255]          * TODO: MP: - allocated in a shared memory
[256]          *           - ngx_atomic_fetch_add()
[257]          *             or protection by critical section or light mutex
[258]          */
[259] 
[260]         c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
[261] 
[262]         c->start_time = ngx_current_msec;
[263] 
[264] #if (NGX_STAT_STUB)
[265]         (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
[266] #endif
[267] 
[268]         if (ls->addr_ntop) {
[269]             c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
[270]             if (c->addr_text.data == NULL) {
[271]                 ngx_close_accepted_connection(c);
[272]                 return;
[273]             }
[274] 
[275]             c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
[276]                                              c->addr_text.data,
[277]                                              ls->addr_text_max_len, 0);
[278]             if (c->addr_text.len == 0) {
[279]                 ngx_close_accepted_connection(c);
[280]                 return;
[281]             }
[282]         }
[283] 
[284] #if (NGX_DEBUG)
[285]         {
[286]         ngx_str_t  addr;
[287]         u_char     text[NGX_SOCKADDR_STRLEN];
[288] 
[289]         ngx_debug_accepted_connection(ecf, c);
[290] 
[291]         if (log->log_level & NGX_LOG_DEBUG_EVENT) {
[292]             addr.data = text;
[293]             addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
[294]                                      NGX_SOCKADDR_STRLEN, 1);
[295] 
[296]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
[297]                            "*%uA accept: %V fd:%d", c->number, &addr, s);
[298]         }
[299] 
[300]         }
[301] #endif
[302] 
[303]         if (ngx_add_conn && (ngx_event_flags & NGX_USE_EPOLL_EVENT) == 0) {
[304]             if (ngx_add_conn(c) == NGX_ERROR) {
[305]                 ngx_close_accepted_connection(c);
[306]                 return;
[307]             }
[308]         }
[309] 
[310]         log->data = NULL;
[311]         log->handler = NULL;
[312] 
[313]         ls->handler(c);
[314] 
[315]         if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[316]             ev->available--;
[317]         }
[318] 
[319]     } while (ev->available);
[320] 
[321] #if (NGX_HAVE_EPOLLEXCLUSIVE)
[322]     ngx_reorder_accept_events(ls);
[323] #endif
[324] }
[325] 
[326] 
[327] ngx_int_t
[328] ngx_trylock_accept_mutex(ngx_cycle_t *cycle)
[329] {
[330]     if (ngx_shmtx_trylock(&ngx_accept_mutex)) {
[331] 
[332]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[333]                        "accept mutex locked");
[334] 
[335]         if (ngx_accept_mutex_held && ngx_accept_events == 0) {
[336]             return NGX_OK;
[337]         }
[338] 
[339]         if (ngx_enable_accept_events(cycle) == NGX_ERROR) {
[340]             ngx_shmtx_unlock(&ngx_accept_mutex);
[341]             return NGX_ERROR;
[342]         }
[343] 
[344]         ngx_accept_events = 0;
[345]         ngx_accept_mutex_held = 1;
[346] 
[347]         return NGX_OK;
[348]     }
[349] 
[350]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[351]                    "accept mutex lock failed: %ui", ngx_accept_mutex_held);
[352] 
[353]     if (ngx_accept_mutex_held) {
[354]         if (ngx_disable_accept_events(cycle, 0) == NGX_ERROR) {
[355]             return NGX_ERROR;
[356]         }
[357] 
[358]         ngx_accept_mutex_held = 0;
[359]     }
[360] 
[361]     return NGX_OK;
[362] }
[363] 
[364] 
[365] ngx_int_t
[366] ngx_enable_accept_events(ngx_cycle_t *cycle)
[367] {
[368]     ngx_uint_t         i;
[369]     ngx_listening_t   *ls;
[370]     ngx_connection_t  *c;
[371] 
[372]     ls = cycle->listening.elts;
[373]     for (i = 0; i < cycle->listening.nelts; i++) {
[374] 
[375]         c = ls[i].connection;
[376] 
[377]         if (c == NULL || c->read->active) {
[378]             continue;
[379]         }
[380] 
[381]         if (ngx_add_event(c->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
[382]             return NGX_ERROR;
[383]         }
[384]     }
[385] 
[386]     return NGX_OK;
[387] }
[388] 
[389] 
[390] static ngx_int_t
[391] ngx_disable_accept_events(ngx_cycle_t *cycle, ngx_uint_t all)
[392] {
[393]     ngx_uint_t         i;
[394]     ngx_listening_t   *ls;
[395]     ngx_connection_t  *c;
[396] 
[397]     ls = cycle->listening.elts;
[398]     for (i = 0; i < cycle->listening.nelts; i++) {
[399] 
[400]         c = ls[i].connection;
[401] 
[402]         if (c == NULL || !c->read->active) {
[403]             continue;
[404]         }
[405] 
[406] #if (NGX_HAVE_REUSEPORT)
[407] 
[408]         /*
[409]          * do not disable accept on worker's own sockets
[410]          * when disabling accept events due to accept mutex
[411]          */
[412] 
[413]         if (ls[i].reuseport && !all) {
[414]             continue;
[415]         }
[416] 
[417] #endif
[418] 
[419]         if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT)
[420]             == NGX_ERROR)
[421]         {
[422]             return NGX_ERROR;
[423]         }
[424]     }
[425] 
[426]     return NGX_OK;
[427] }
[428] 
[429] 
[430] #if (NGX_HAVE_EPOLLEXCLUSIVE)
[431] 
[432] static void
[433] ngx_reorder_accept_events(ngx_listening_t *ls)
[434] {
[435]     ngx_connection_t  *c;
[436] 
[437]     /*
[438]      * Linux with EPOLLEXCLUSIVE usually notifies only the process which
[439]      * was first to add the listening socket to the epoll instance.  As
[440]      * a result most of the connections are handled by the first worker
[441]      * process.  To fix this, we re-add the socket periodically, so other
[442]      * workers will get a chance to accept connections.
[443]      */
[444] 
[445]     if (!ngx_use_exclusive_accept) {
[446]         return;
[447]     }
[448] 
[449] #if (NGX_HAVE_REUSEPORT)
[450] 
[451]     if (ls->reuseport) {
[452]         return;
[453]     }
[454] 
[455] #endif
[456] 
[457]     c = ls->connection;
[458] 
[459]     if (c->requests++ % 16 != 0
[460]         && ngx_accept_disabled <= 0)
[461]     {
[462]         return;
[463]     }
[464] 
[465]     if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT)
[466]         == NGX_ERROR)
[467]     {
[468]         return;
[469]     }
[470] 
[471]     if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_EXCLUSIVE_EVENT)
[472]         == NGX_ERROR)
[473]     {
[474]         return;
[475]     }
[476] }
[477] 
[478] #endif
[479] 
[480] 
[481] static void
[482] ngx_close_accepted_connection(ngx_connection_t *c)
[483] {
[484]     ngx_socket_t  fd;
[485] 
[486]     ngx_free_connection(c);
[487] 
[488]     fd = c->fd;
[489]     c->fd = (ngx_socket_t) -1;
[490] 
[491]     if (ngx_close_socket(fd) == -1) {
[492]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
[493]                       ngx_close_socket_n " failed");
[494]     }
[495] 
[496]     if (c->pool) {
[497]         ngx_destroy_pool(c->pool);
[498]     }
[499] 
[500] #if (NGX_STAT_STUB)
[501]     (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
[502] #endif
[503] }
[504] 
[505] 
[506] u_char *
[507] ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len)
[508] {
[509]     return ngx_snprintf(buf, len, " while accepting new connection on %V",
[510]                         log->data);
[511] }
[512] 
[513] 
[514] #if (NGX_DEBUG)
[515] 
[516] void
[517] ngx_debug_accepted_connection(ngx_event_conf_t *ecf, ngx_connection_t *c)
[518] {
[519]     struct sockaddr_in   *sin;
[520]     ngx_cidr_t           *cidr;
[521]     ngx_uint_t            i;
[522] #if (NGX_HAVE_INET6)
[523]     struct sockaddr_in6  *sin6;
[524]     ngx_uint_t            n;
[525] #endif
[526] 
[527]     cidr = ecf->debug_connection.elts;
[528]     for (i = 0; i < ecf->debug_connection.nelts; i++) {
[529]         if (cidr[i].family != (ngx_uint_t) c->sockaddr->sa_family) {
[530]             goto next;
[531]         }
[532] 
[533]         switch (cidr[i].family) {
[534] 
[535] #if (NGX_HAVE_INET6)
[536]         case AF_INET6:
[537]             sin6 = (struct sockaddr_in6 *) c->sockaddr;
[538]             for (n = 0; n < 16; n++) {
[539]                 if ((sin6->sin6_addr.s6_addr[n]
[540]                     & cidr[i].u.in6.mask.s6_addr[n])
[541]                     != cidr[i].u.in6.addr.s6_addr[n])
[542]                 {
[543]                     goto next;
[544]                 }
[545]             }
[546]             break;
[547] #endif
[548] 
[549] #if (NGX_HAVE_UNIX_DOMAIN)
[550]         case AF_UNIX:
[551]             break;
[552] #endif
[553] 
[554]         default: /* AF_INET */
[555]             sin = (struct sockaddr_in *) c->sockaddr;
[556]             if ((sin->sin_addr.s_addr & cidr[i].u.in.mask)
[557]                 != cidr[i].u.in.addr)
[558]             {
[559]                 goto next;
[560]             }
[561]             break;
[562]         }
[563] 
[564]         c->log->log_level = NGX_LOG_DEBUG_CONNECTION|NGX_LOG_DEBUG_ALL;
[565]         break;
[566] 
[567]     next:
[568]         continue;
[569]     }
[570] }
[571] 
[572] #endif
