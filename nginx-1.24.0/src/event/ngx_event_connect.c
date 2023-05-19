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
[11] #include <ngx_event_connect.h>
[12] 
[13] 
[14] #if (NGX_HAVE_TRANSPARENT_PROXY)
[15] static ngx_int_t ngx_event_connect_set_transparent(ngx_peer_connection_t *pc,
[16]     ngx_socket_t s);
[17] #endif
[18] 
[19] 
[20] ngx_int_t
[21] ngx_event_connect_peer(ngx_peer_connection_t *pc)
[22] {
[23]     int                rc, type, value;
[24] #if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT || NGX_LINUX)
[25]     in_port_t          port;
[26] #endif
[27]     ngx_int_t          event;
[28]     ngx_err_t          err;
[29]     ngx_uint_t         level;
[30]     ngx_socket_t       s;
[31]     ngx_event_t       *rev, *wev;
[32]     ngx_connection_t  *c;
[33] 
[34]     rc = pc->get(pc, pc->data);
[35]     if (rc != NGX_OK) {
[36]         return rc;
[37]     }
[38] 
[39]     type = (pc->type ? pc->type : SOCK_STREAM);
[40] 
[41]     s = ngx_socket(pc->sockaddr->sa_family, type, 0);
[42] 
[43]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
[44]                    (type == SOCK_STREAM) ? "stream" : "dgram", s);
[45] 
[46]     if (s == (ngx_socket_t) -1) {
[47]         ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[48]                       ngx_socket_n " failed");
[49]         return NGX_ERROR;
[50]     }
[51] 
[52] 
[53]     c = ngx_get_connection(s, pc->log);
[54] 
[55]     if (c == NULL) {
[56]         if (ngx_close_socket(s) == -1) {
[57]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[58]                           ngx_close_socket_n " failed");
[59]         }
[60] 
[61]         return NGX_ERROR;
[62]     }
[63] 
[64]     c->type = type;
[65] 
[66]     if (pc->rcvbuf) {
[67]         if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
[68]                        (const void *) &pc->rcvbuf, sizeof(int)) == -1)
[69]         {
[70]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[71]                           "setsockopt(SO_RCVBUF) failed");
[72]             goto failed;
[73]         }
[74]     }
[75] 
[76]     if (pc->so_keepalive) {
[77]         value = 1;
[78] 
[79]         if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
[80]                        (const void *) &value, sizeof(int))
[81]             == -1)
[82]         {
[83]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[84]                           "setsockopt(SO_KEEPALIVE) failed, ignored");
[85]         }
[86]     }
[87] 
[88]     if (ngx_nonblocking(s) == -1) {
[89]         ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[90]                       ngx_nonblocking_n " failed");
[91] 
[92]         goto failed;
[93]     }
[94] 
[95]     if (pc->local) {
[96] 
[97] #if (NGX_HAVE_TRANSPARENT_PROXY)
[98]         if (pc->transparent) {
[99]             if (ngx_event_connect_set_transparent(pc, s) != NGX_OK) {
[100]                 goto failed;
[101]             }
[102]         }
[103] #endif
[104] 
[105] #if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT || NGX_LINUX)
[106]         port = ngx_inet_get_port(pc->local->sockaddr);
[107] #endif
[108] 
[109] #if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT)
[110] 
[111]         if (pc->sockaddr->sa_family != AF_UNIX && port == 0) {
[112]             static int  bind_address_no_port = 1;
[113] 
[114]             if (bind_address_no_port) {
[115]                 if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
[116]                                (const void *) &bind_address_no_port,
[117]                                sizeof(int)) == -1)
[118]                 {
[119]                     err = ngx_socket_errno;
[120] 
[121]                     if (err != NGX_EOPNOTSUPP && err != NGX_ENOPROTOOPT) {
[122]                         ngx_log_error(NGX_LOG_ALERT, pc->log, err,
[123]                                       "setsockopt(IP_BIND_ADDRESS_NO_PORT) "
[124]                                       "failed, ignored");
[125] 
[126]                     } else {
[127]                         bind_address_no_port = 0;
[128]                     }
[129]                 }
[130]             }
[131]         }
[132] 
[133] #endif
[134] 
[135] #if (NGX_LINUX)
[136] 
[137]         if (pc->type == SOCK_DGRAM && port != 0) {
[138]             int  reuse_addr = 1;
[139] 
[140]             if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
[141]                            (const void *) &reuse_addr, sizeof(int))
[142]                  == -1)
[143]             {
[144]                 ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[145]                               "setsockopt(SO_REUSEADDR) failed");
[146]                 goto failed;
[147]             }
[148]         }
[149] 
[150] #endif
[151] 
[152]         if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
[153]             ngx_log_error(NGX_LOG_CRIT, pc->log, ngx_socket_errno,
[154]                           "bind(%V) failed", &pc->local->name);
[155] 
[156]             goto failed;
[157]         }
[158]     }
[159] 
[160]     if (type == SOCK_STREAM) {
[161]         c->recv = ngx_recv;
[162]         c->send = ngx_send;
[163]         c->recv_chain = ngx_recv_chain;
[164]         c->send_chain = ngx_send_chain;
[165] 
[166]         c->sendfile = 1;
[167] 
[168]         if (pc->sockaddr->sa_family == AF_UNIX) {
[169]             c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
[170]             c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
[171] 
[172] #if (NGX_SOLARIS)
[173]             /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
[174]             c->sendfile = 0;
[175] #endif
[176]         }
[177] 
[178]     } else { /* type == SOCK_DGRAM */
[179]         c->recv = ngx_udp_recv;
[180]         c->send = ngx_send;
[181]         c->send_chain = ngx_udp_send_chain;
[182] 
[183]         c->need_flush_buf = 1;
[184]     }
[185] 
[186]     c->log_error = pc->log_error;
[187] 
[188]     rev = c->read;
[189]     wev = c->write;
[190] 
[191]     rev->log = pc->log;
[192]     wev->log = pc->log;
[193] 
[194]     pc->connection = c;
[195] 
[196]     c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
[197] 
[198]     c->start_time = ngx_current_msec;
[199] 
[200]     if (ngx_add_conn) {
[201]         if (ngx_add_conn(c) == NGX_ERROR) {
[202]             goto failed;
[203]         }
[204]     }
[205] 
[206]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
[207]                    "connect to %V, fd:%d #%uA", pc->name, s, c->number);
[208] 
[209]     rc = connect(s, pc->sockaddr, pc->socklen);
[210] 
[211]     if (rc == -1) {
[212]         err = ngx_socket_errno;
[213] 
[214] 
[215]         if (err != NGX_EINPROGRESS
[216] #if (NGX_WIN32)
[217]             /* Winsock returns WSAEWOULDBLOCK (NGX_EAGAIN) */
[218]             && err != NGX_EAGAIN
[219] #endif
[220]             )
[221]         {
[222]             if (err == NGX_ECONNREFUSED
[223] #if (NGX_LINUX)
[224]                 /*
[225]                  * Linux returns EAGAIN instead of ECONNREFUSED
[226]                  * for unix sockets if listen queue is full
[227]                  */
[228]                 || err == NGX_EAGAIN
[229] #endif
[230]                 || err == NGX_ECONNRESET
[231]                 || err == NGX_ENETDOWN
[232]                 || err == NGX_ENETUNREACH
[233]                 || err == NGX_EHOSTDOWN
[234]                 || err == NGX_EHOSTUNREACH)
[235]             {
[236]                 level = NGX_LOG_ERR;
[237] 
[238]             } else {
[239]                 level = NGX_LOG_CRIT;
[240]             }
[241] 
[242]             ngx_log_error(level, c->log, err, "connect() to %V failed",
[243]                           pc->name);
[244] 
[245]             ngx_close_connection(c);
[246]             pc->connection = NULL;
[247] 
[248]             return NGX_DECLINED;
[249]         }
[250]     }
[251] 
[252]     if (ngx_add_conn) {
[253]         if (rc == -1) {
[254] 
[255]             /* NGX_EINPROGRESS */
[256] 
[257]             return NGX_AGAIN;
[258]         }
[259] 
[260]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");
[261] 
[262]         wev->ready = 1;
[263] 
[264]         return NGX_OK;
[265]     }
[266] 
[267]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[268] 
[269]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pc->log, ngx_socket_errno,
[270]                        "connect(): %d", rc);
[271] 
[272]         if (ngx_blocking(s) == -1) {
[273]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[274]                           ngx_blocking_n " failed");
[275]             goto failed;
[276]         }
[277] 
[278]         /*
[279]          * FreeBSD's aio allows to post an operation on non-connected socket.
[280]          * NT does not support it.
[281]          *
[282]          * TODO: check in Win32, etc. As workaround we can use NGX_ONESHOT_EVENT
[283]          */
[284] 
[285]         rev->ready = 1;
[286]         wev->ready = 1;
[287] 
[288]         return NGX_OK;
[289]     }
[290] 
[291]     if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
[292] 
[293]         /* kqueue */
[294] 
[295]         event = NGX_CLEAR_EVENT;
[296] 
[297]     } else {
[298] 
[299]         /* select, poll, /dev/poll */
[300] 
[301]         event = NGX_LEVEL_EVENT;
[302]     }
[303] 
[304]     if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
[305]         goto failed;
[306]     }
[307] 
[308]     if (rc == -1) {
[309] 
[310]         /* NGX_EINPROGRESS */
[311] 
[312]         if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
[313]             goto failed;
[314]         }
[315] 
[316]         return NGX_AGAIN;
[317]     }
[318] 
[319]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");
[320] 
[321]     wev->ready = 1;
[322] 
[323]     return NGX_OK;
[324] 
[325] failed:
[326] 
[327]     ngx_close_connection(c);
[328]     pc->connection = NULL;
[329] 
[330]     return NGX_ERROR;
[331] }
[332] 
[333] 
[334] #if (NGX_HAVE_TRANSPARENT_PROXY)
[335] 
[336] static ngx_int_t
[337] ngx_event_connect_set_transparent(ngx_peer_connection_t *pc, ngx_socket_t s)
[338] {
[339]     int  value;
[340] 
[341]     value = 1;
[342] 
[343] #if defined(SO_BINDANY)
[344] 
[345]     if (setsockopt(s, SOL_SOCKET, SO_BINDANY,
[346]                    (const void *) &value, sizeof(int)) == -1)
[347]     {
[348]         ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[349]                       "setsockopt(SO_BINDANY) failed");
[350]         return NGX_ERROR;
[351]     }
[352] 
[353] #else
[354] 
[355]     switch (pc->local->sockaddr->sa_family) {
[356] 
[357]     case AF_INET:
[358] 
[359] #if defined(IP_TRANSPARENT)
[360] 
[361]         if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT,
[362]                        (const void *) &value, sizeof(int)) == -1)
[363]         {
[364]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[365]                           "setsockopt(IP_TRANSPARENT) failed");
[366]             return NGX_ERROR;
[367]         }
[368] 
[369] #elif defined(IP_BINDANY)
[370] 
[371]         if (setsockopt(s, IPPROTO_IP, IP_BINDANY,
[372]                        (const void *) &value, sizeof(int)) == -1)
[373]         {
[374]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[375]                           "setsockopt(IP_BINDANY) failed");
[376]             return NGX_ERROR;
[377]         }
[378] 
[379] #endif
[380] 
[381]         break;
[382] 
[383] #if (NGX_HAVE_INET6)
[384] 
[385]     case AF_INET6:
[386] 
[387] #if defined(IPV6_TRANSPARENT)
[388] 
[389]         if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT,
[390]                        (const void *) &value, sizeof(int)) == -1)
[391]         {
[392]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[393]                           "setsockopt(IPV6_TRANSPARENT) failed");
[394]             return NGX_ERROR;
[395]         }
[396] 
[397] #elif defined(IPV6_BINDANY)
[398] 
[399]         if (setsockopt(s, IPPROTO_IPV6, IPV6_BINDANY,
[400]                        (const void *) &value, sizeof(int)) == -1)
[401]         {
[402]             ngx_log_error(NGX_LOG_ALERT, pc->log, ngx_socket_errno,
[403]                           "setsockopt(IPV6_BINDANY) failed");
[404]             return NGX_ERROR;
[405]         }
[406] 
[407] #else
[408] 
[409]         ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
[410]                       "could not enable transparent proxying for IPv6 "
[411]                       "on this platform");
[412] 
[413]         return NGX_ERROR;
[414] 
[415] #endif
[416] 
[417]         break;
[418] 
[419] #endif /* NGX_HAVE_INET6 */
[420] 
[421]     }
[422] 
[423] #endif /* SO_BINDANY */
[424] 
[425]     return NGX_OK;
[426] }
[427] 
[428] #endif
[429] 
[430] 
[431] ngx_int_t
[432] ngx_event_get_peer(ngx_peer_connection_t *pc, void *data)
[433] {
[434]     return NGX_OK;
[435] }
