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
[13] ngx_os_io_t  ngx_io;
[14] 
[15] 
[16] static void ngx_drain_connections(ngx_cycle_t *cycle);
[17] 
[18] 
[19] ngx_listening_t *
[20] ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
[21]     socklen_t socklen)
[22] {
[23]     size_t            len;
[24]     ngx_listening_t  *ls;
[25]     struct sockaddr  *sa;
[26]     u_char            text[NGX_SOCKADDR_STRLEN];
[27] 
[28]     ls = ngx_array_push(&cf->cycle->listening);
[29]     if (ls == NULL) {
[30]         return NULL;
[31]     }
[32] 
[33]     ngx_memzero(ls, sizeof(ngx_listening_t));
[34] 
[35]     sa = ngx_palloc(cf->pool, socklen);
[36]     if (sa == NULL) {
[37]         return NULL;
[38]     }
[39] 
[40]     ngx_memcpy(sa, sockaddr, socklen);
[41] 
[42]     ls->sockaddr = sa;
[43]     ls->socklen = socklen;
[44] 
[45]     len = ngx_sock_ntop(sa, socklen, text, NGX_SOCKADDR_STRLEN, 1);
[46]     ls->addr_text.len = len;
[47] 
[48]     switch (ls->sockaddr->sa_family) {
[49] #if (NGX_HAVE_INET6)
[50]     case AF_INET6:
[51]         ls->addr_text_max_len = NGX_INET6_ADDRSTRLEN;
[52]         break;
[53] #endif
[54] #if (NGX_HAVE_UNIX_DOMAIN)
[55]     case AF_UNIX:
[56]         ls->addr_text_max_len = NGX_UNIX_ADDRSTRLEN;
[57]         len++;
[58]         break;
[59] #endif
[60]     case AF_INET:
[61]         ls->addr_text_max_len = NGX_INET_ADDRSTRLEN;
[62]         break;
[63]     default:
[64]         ls->addr_text_max_len = NGX_SOCKADDR_STRLEN;
[65]         break;
[66]     }
[67] 
[68]     ls->addr_text.data = ngx_pnalloc(cf->pool, len);
[69]     if (ls->addr_text.data == NULL) {
[70]         return NULL;
[71]     }
[72] 
[73]     ngx_memcpy(ls->addr_text.data, text, len);
[74] 
[75] #if !(NGX_WIN32)
[76]     ngx_rbtree_init(&ls->rbtree, &ls->sentinel, ngx_udp_rbtree_insert_value);
[77] #endif
[78] 
[79]     ls->fd = (ngx_socket_t) -1;
[80]     ls->type = SOCK_STREAM;
[81] 
[82]     ls->backlog = NGX_LISTEN_BACKLOG;
[83]     ls->rcvbuf = -1;
[84]     ls->sndbuf = -1;
[85] 
[86] #if (NGX_HAVE_SETFIB)
[87]     ls->setfib = -1;
[88] #endif
[89] 
[90] #if (NGX_HAVE_TCP_FASTOPEN)
[91]     ls->fastopen = -1;
[92] #endif
[93] 
[94]     return ls;
[95] }
[96] 
[97] 
[98] ngx_int_t
[99] ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls)
[100] {
[101] #if (NGX_HAVE_REUSEPORT)
[102] 
[103]     ngx_int_t         n;
[104]     ngx_core_conf_t  *ccf;
[105]     ngx_listening_t   ols;
[106] 
[107]     if (!ls->reuseport || ls->worker != 0) {
[108]         return NGX_OK;
[109]     }
[110] 
[111]     ols = *ls;
[112] 
[113]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[114] 
[115]     for (n = 1; n < ccf->worker_processes; n++) {
[116] 
[117]         /* create a socket for each worker process */
[118] 
[119]         ls = ngx_array_push(&cycle->listening);
[120]         if (ls == NULL) {
[121]             return NGX_ERROR;
[122]         }
[123] 
[124]         *ls = ols;
[125]         ls->worker = n;
[126]     }
[127] 
[128] #endif
[129] 
[130]     return NGX_OK;
[131] }
[132] 
[133] 
[134] ngx_int_t
[135] ngx_set_inherited_sockets(ngx_cycle_t *cycle)
[136] {
[137]     size_t                     len;
[138]     ngx_uint_t                 i;
[139]     ngx_listening_t           *ls;
[140]     socklen_t                  olen;
[141] #if (NGX_HAVE_DEFERRED_ACCEPT || NGX_HAVE_TCP_FASTOPEN)
[142]     ngx_err_t                  err;
[143] #endif
[144] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[145]     struct accept_filter_arg   af;
[146] #endif
[147] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[148]     int                        timeout;
[149] #endif
[150] #if (NGX_HAVE_REUSEPORT)
[151]     int                        reuseport;
[152] #endif
[153] 
[154]     ls = cycle->listening.elts;
[155]     for (i = 0; i < cycle->listening.nelts; i++) {
[156] 
[157]         ls[i].sockaddr = ngx_palloc(cycle->pool, sizeof(ngx_sockaddr_t));
[158]         if (ls[i].sockaddr == NULL) {
[159]             return NGX_ERROR;
[160]         }
[161] 
[162]         ls[i].socklen = sizeof(ngx_sockaddr_t);
[163]         if (getsockname(ls[i].fd, ls[i].sockaddr, &ls[i].socklen) == -1) {
[164]             ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
[165]                           "getsockname() of the inherited "
[166]                           "socket #%d failed", ls[i].fd);
[167]             ls[i].ignore = 1;
[168]             continue;
[169]         }
[170] 
[171]         if (ls[i].socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
[172]             ls[i].socklen = sizeof(ngx_sockaddr_t);
[173]         }
[174] 
[175]         switch (ls[i].sockaddr->sa_family) {
[176] 
[177] #if (NGX_HAVE_INET6)
[178]         case AF_INET6:
[179]             ls[i].addr_text_max_len = NGX_INET6_ADDRSTRLEN;
[180]             len = NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1;
[181]             break;
[182] #endif
[183] 
[184] #if (NGX_HAVE_UNIX_DOMAIN)
[185]         case AF_UNIX:
[186]             ls[i].addr_text_max_len = NGX_UNIX_ADDRSTRLEN;
[187]             len = NGX_UNIX_ADDRSTRLEN;
[188]             break;
[189] #endif
[190] 
[191]         case AF_INET:
[192]             ls[i].addr_text_max_len = NGX_INET_ADDRSTRLEN;
[193]             len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
[194]             break;
[195] 
[196]         default:
[197]             ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
[198]                           "the inherited socket #%d has "
[199]                           "an unsupported protocol family", ls[i].fd);
[200]             ls[i].ignore = 1;
[201]             continue;
[202]         }
[203] 
[204]         ls[i].addr_text.data = ngx_pnalloc(cycle->pool, len);
[205]         if (ls[i].addr_text.data == NULL) {
[206]             return NGX_ERROR;
[207]         }
[208] 
[209]         len = ngx_sock_ntop(ls[i].sockaddr, ls[i].socklen,
[210]                             ls[i].addr_text.data, len, 1);
[211]         if (len == 0) {
[212]             return NGX_ERROR;
[213]         }
[214] 
[215]         ls[i].addr_text.len = len;
[216] 
[217]         ls[i].backlog = NGX_LISTEN_BACKLOG;
[218] 
[219]         olen = sizeof(int);
[220] 
[221]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_TYPE, (void *) &ls[i].type,
[222]                        &olen)
[223]             == -1)
[224]         {
[225]             ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_socket_errno,
[226]                           "getsockopt(SO_TYPE) %V failed", &ls[i].addr_text);
[227]             ls[i].ignore = 1;
[228]             continue;
[229]         }
[230] 
[231]         olen = sizeof(int);
[232] 
[233]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF, (void *) &ls[i].rcvbuf,
[234]                        &olen)
[235]             == -1)
[236]         {
[237]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[238]                           "getsockopt(SO_RCVBUF) %V failed, ignored",
[239]                           &ls[i].addr_text);
[240] 
[241]             ls[i].rcvbuf = -1;
[242]         }
[243] 
[244]         olen = sizeof(int);
[245] 
[246]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF, (void *) &ls[i].sndbuf,
[247]                        &olen)
[248]             == -1)
[249]         {
[250]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[251]                           "getsockopt(SO_SNDBUF) %V failed, ignored",
[252]                           &ls[i].addr_text);
[253] 
[254]             ls[i].sndbuf = -1;
[255]         }
[256] 
[257] #if 0
[258]         /* SO_SETFIB is currently a set only option */
[259] 
[260] #if (NGX_HAVE_SETFIB)
[261] 
[262]         olen = sizeof(int);
[263] 
[264]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
[265]                        (void *) &ls[i].setfib, &olen)
[266]             == -1)
[267]         {
[268]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[269]                           "getsockopt(SO_SETFIB) %V failed, ignored",
[270]                           &ls[i].addr_text);
[271] 
[272]             ls[i].setfib = -1;
[273]         }
[274] 
[275] #endif
[276] #endif
[277] 
[278] #if (NGX_HAVE_REUSEPORT)
[279] 
[280]         reuseport = 0;
[281]         olen = sizeof(int);
[282] 
[283] #ifdef SO_REUSEPORT_LB
[284] 
[285]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
[286]                        (void *) &reuseport, &olen)
[287]             == -1)
[288]         {
[289]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[290]                           "getsockopt(SO_REUSEPORT_LB) %V failed, ignored",
[291]                           &ls[i].addr_text);
[292] 
[293]         } else {
[294]             ls[i].reuseport = reuseport ? 1 : 0;
[295]         }
[296] 
[297] #else
[298] 
[299]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
[300]                        (void *) &reuseport, &olen)
[301]             == -1)
[302]         {
[303]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[304]                           "getsockopt(SO_REUSEPORT) %V failed, ignored",
[305]                           &ls[i].addr_text);
[306] 
[307]         } else {
[308]             ls[i].reuseport = reuseport ? 1 : 0;
[309]         }
[310] #endif
[311] 
[312] #endif
[313] 
[314]         if (ls[i].type != SOCK_STREAM) {
[315]             continue;
[316]         }
[317] 
[318] #if (NGX_HAVE_TCP_FASTOPEN)
[319] 
[320]         olen = sizeof(int);
[321] 
[322]         if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
[323]                        (void *) &ls[i].fastopen, &olen)
[324]             == -1)
[325]         {
[326]             err = ngx_socket_errno;
[327] 
[328]             if (err != NGX_EOPNOTSUPP && err != NGX_ENOPROTOOPT
[329]                 && err != NGX_EINVAL)
[330]             {
[331]                 ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
[332]                               "getsockopt(TCP_FASTOPEN) %V failed, ignored",
[333]                               &ls[i].addr_text);
[334]             }
[335] 
[336]             ls[i].fastopen = -1;
[337]         }
[338] 
[339] #endif
[340] 
[341] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[342] 
[343]         ngx_memzero(&af, sizeof(struct accept_filter_arg));
[344]         olen = sizeof(struct accept_filter_arg);
[345] 
[346]         if (getsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &olen)
[347]             == -1)
[348]         {
[349]             err = ngx_socket_errno;
[350] 
[351]             if (err == NGX_EINVAL) {
[352]                 continue;
[353]             }
[354] 
[355]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
[356]                           "getsockopt(SO_ACCEPTFILTER) for %V failed, ignored",
[357]                           &ls[i].addr_text);
[358]             continue;
[359]         }
[360] 
[361]         if (olen < sizeof(struct accept_filter_arg) || af.af_name[0] == '\0') {
[362]             continue;
[363]         }
[364] 
[365]         ls[i].accept_filter = ngx_palloc(cycle->pool, 16);
[366]         if (ls[i].accept_filter == NULL) {
[367]             return NGX_ERROR;
[368]         }
[369] 
[370]         (void) ngx_cpystrn((u_char *) ls[i].accept_filter,
[371]                            (u_char *) af.af_name, 16);
[372] #endif
[373] 
[374] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[375] 
[376]         timeout = 0;
[377]         olen = sizeof(int);
[378] 
[379]         if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, &olen)
[380]             == -1)
[381]         {
[382]             err = ngx_socket_errno;
[383] 
[384]             if (err == NGX_EOPNOTSUPP) {
[385]                 continue;
[386]             }
[387] 
[388]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, err,
[389]                           "getsockopt(TCP_DEFER_ACCEPT) for %V failed, ignored",
[390]                           &ls[i].addr_text);
[391]             continue;
[392]         }
[393] 
[394]         if (olen < sizeof(int) || timeout == 0) {
[395]             continue;
[396]         }
[397] 
[398]         ls[i].deferred_accept = 1;
[399] #endif
[400]     }
[401] 
[402]     return NGX_OK;
[403] }
[404] 
[405] 
[406] ngx_int_t
[407] ngx_open_listening_sockets(ngx_cycle_t *cycle)
[408] {
[409]     int               reuseaddr;
[410]     ngx_uint_t        i, tries, failed;
[411]     ngx_err_t         err;
[412]     ngx_log_t        *log;
[413]     ngx_socket_t      s;
[414]     ngx_listening_t  *ls;
[415] 
[416]     reuseaddr = 1;
[417] #if (NGX_SUPPRESS_WARN)
[418]     failed = 0;
[419] #endif
[420] 
[421]     log = cycle->log;
[422] 
[423]     /* TODO: configurable try number */
[424] 
[425]     for (tries = 5; tries; tries--) {
[426]         failed = 0;
[427] 
[428]         /* for each listening socket */
[429] 
[430]         ls = cycle->listening.elts;
[431]         for (i = 0; i < cycle->listening.nelts; i++) {
[432] 
[433]             if (ls[i].ignore) {
[434]                 continue;
[435]             }
[436] 
[437] #if (NGX_HAVE_REUSEPORT)
[438] 
[439]             if (ls[i].add_reuseport) {
[440] 
[441]                 /*
[442]                  * to allow transition from a socket without SO_REUSEPORT
[443]                  * to multiple sockets with SO_REUSEPORT, we have to set
[444]                  * SO_REUSEPORT on the old socket before opening new ones
[445]                  */
[446] 
[447]                 int  reuseport = 1;
[448] 
[449] #ifdef SO_REUSEPORT_LB
[450] 
[451]                 if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
[452]                                (const void *) &reuseport, sizeof(int))
[453]                     == -1)
[454]                 {
[455]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[456]                                   "setsockopt(SO_REUSEPORT_LB) %V failed, "
[457]                                   "ignored",
[458]                                   &ls[i].addr_text);
[459]                 }
[460] 
[461] #else
[462] 
[463]                 if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
[464]                                (const void *) &reuseport, sizeof(int))
[465]                     == -1)
[466]                 {
[467]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[468]                                   "setsockopt(SO_REUSEPORT) %V failed, ignored",
[469]                                   &ls[i].addr_text);
[470]                 }
[471] #endif
[472] 
[473]                 ls[i].add_reuseport = 0;
[474]             }
[475] #endif
[476] 
[477]             if (ls[i].fd != (ngx_socket_t) -1) {
[478]                 continue;
[479]             }
[480] 
[481]             if (ls[i].inherited) {
[482] 
[483]                 /* TODO: close on exit */
[484]                 /* TODO: nonblocking */
[485]                 /* TODO: deferred accept */
[486] 
[487]                 continue;
[488]             }
[489] 
[490]             s = ngx_socket(ls[i].sockaddr->sa_family, ls[i].type, 0);
[491] 
[492]             if (s == (ngx_socket_t) -1) {
[493]                 ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[494]                               ngx_socket_n " %V failed", &ls[i].addr_text);
[495]                 return NGX_ERROR;
[496]             }
[497] 
[498]             if (ls[i].type != SOCK_DGRAM || !ngx_test_config) {
[499] 
[500]                 if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
[501]                                (const void *) &reuseaddr, sizeof(int))
[502]                     == -1)
[503]                 {
[504]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[505]                                   "setsockopt(SO_REUSEADDR) %V failed",
[506]                                   &ls[i].addr_text);
[507] 
[508]                     if (ngx_close_socket(s) == -1) {
[509]                         ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[510]                                       ngx_close_socket_n " %V failed",
[511]                                       &ls[i].addr_text);
[512]                     }
[513] 
[514]                     return NGX_ERROR;
[515]                 }
[516]             }
[517] 
[518] #if (NGX_HAVE_REUSEPORT)
[519] 
[520]             if (ls[i].reuseport && !ngx_test_config) {
[521]                 int  reuseport;
[522] 
[523]                 reuseport = 1;
[524] 
[525] #ifdef SO_REUSEPORT_LB
[526] 
[527]                 if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT_LB,
[528]                                (const void *) &reuseport, sizeof(int))
[529]                     == -1)
[530]                 {
[531]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[532]                                   "setsockopt(SO_REUSEPORT_LB) %V failed",
[533]                                   &ls[i].addr_text);
[534] 
[535]                     if (ngx_close_socket(s) == -1) {
[536]                         ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[537]                                       ngx_close_socket_n " %V failed",
[538]                                       &ls[i].addr_text);
[539]                     }
[540] 
[541]                     return NGX_ERROR;
[542]                 }
[543] 
[544] #else
[545] 
[546]                 if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
[547]                                (const void *) &reuseport, sizeof(int))
[548]                     == -1)
[549]                 {
[550]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[551]                                   "setsockopt(SO_REUSEPORT) %V failed",
[552]                                   &ls[i].addr_text);
[553] 
[554]                     if (ngx_close_socket(s) == -1) {
[555]                         ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[556]                                       ngx_close_socket_n " %V failed",
[557]                                       &ls[i].addr_text);
[558]                     }
[559] 
[560]                     return NGX_ERROR;
[561]                 }
[562] #endif
[563]             }
[564] #endif
[565] 
[566] #if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
[567] 
[568]             if (ls[i].sockaddr->sa_family == AF_INET6) {
[569]                 int  ipv6only;
[570] 
[571]                 ipv6only = ls[i].ipv6only;
[572] 
[573]                 if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
[574]                                (const void *) &ipv6only, sizeof(int))
[575]                     == -1)
[576]                 {
[577]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[578]                                   "setsockopt(IPV6_V6ONLY) %V failed, ignored",
[579]                                   &ls[i].addr_text);
[580]                 }
[581]             }
[582] #endif
[583]             /* TODO: close on exit */
[584] 
[585]             if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
[586]                 if (ngx_nonblocking(s) == -1) {
[587]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[588]                                   ngx_nonblocking_n " %V failed",
[589]                                   &ls[i].addr_text);
[590] 
[591]                     if (ngx_close_socket(s) == -1) {
[592]                         ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[593]                                       ngx_close_socket_n " %V failed",
[594]                                       &ls[i].addr_text);
[595]                     }
[596] 
[597]                     return NGX_ERROR;
[598]                 }
[599]             }
[600] 
[601]             ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0,
[602]                            "bind() %V #%d ", &ls[i].addr_text, s);
[603] 
[604]             if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
[605]                 err = ngx_socket_errno;
[606] 
[607]                 if (err != NGX_EADDRINUSE || !ngx_test_config) {
[608]                     ngx_log_error(NGX_LOG_EMERG, log, err,
[609]                                   "bind() to %V failed", &ls[i].addr_text);
[610]                 }
[611] 
[612]                 if (ngx_close_socket(s) == -1) {
[613]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[614]                                   ngx_close_socket_n " %V failed",
[615]                                   &ls[i].addr_text);
[616]                 }
[617] 
[618]                 if (err != NGX_EADDRINUSE) {
[619]                     return NGX_ERROR;
[620]                 }
[621] 
[622]                 if (!ngx_test_config) {
[623]                     failed = 1;
[624]                 }
[625] 
[626]                 continue;
[627]             }
[628] 
[629] #if (NGX_HAVE_UNIX_DOMAIN)
[630] 
[631]             if (ls[i].sockaddr->sa_family == AF_UNIX) {
[632]                 mode_t   mode;
[633]                 u_char  *name;
[634] 
[635]                 name = ls[i].addr_text.data + sizeof("unix:") - 1;
[636]                 mode = (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
[637] 
[638]                 if (chmod((char *) name, mode) == -1) {
[639]                     ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[640]                                   "chmod() \"%s\" failed", name);
[641]                 }
[642] 
[643]                 if (ngx_test_config) {
[644]                     if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[645]                         ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[646]                                       ngx_delete_file_n " %s failed", name);
[647]                     }
[648]                 }
[649]             }
[650] #endif
[651] 
[652]             if (ls[i].type != SOCK_STREAM) {
[653]                 ls[i].fd = s;
[654]                 continue;
[655]             }
[656] 
[657]             if (listen(s, ls[i].backlog) == -1) {
[658]                 err = ngx_socket_errno;
[659] 
[660]                 /*
[661]                  * on OpenVZ after suspend/resume EADDRINUSE
[662]                  * may be returned by listen() instead of bind(), see
[663]                  * https://bugs.openvz.org/browse/OVZ-5587
[664]                  */
[665] 
[666]                 if (err != NGX_EADDRINUSE || !ngx_test_config) {
[667]                     ngx_log_error(NGX_LOG_EMERG, log, err,
[668]                                   "listen() to %V, backlog %d failed",
[669]                                   &ls[i].addr_text, ls[i].backlog);
[670]                 }
[671] 
[672]                 if (ngx_close_socket(s) == -1) {
[673]                     ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[674]                                   ngx_close_socket_n " %V failed",
[675]                                   &ls[i].addr_text);
[676]                 }
[677] 
[678]                 if (err != NGX_EADDRINUSE) {
[679]                     return NGX_ERROR;
[680]                 }
[681] 
[682]                 if (!ngx_test_config) {
[683]                     failed = 1;
[684]                 }
[685] 
[686]                 continue;
[687]             }
[688] 
[689]             ls[i].listen = 1;
[690] 
[691]             ls[i].fd = s;
[692]         }
[693] 
[694]         if (!failed) {
[695]             break;
[696]         }
[697] 
[698]         /* TODO: delay configurable */
[699] 
[700]         ngx_log_error(NGX_LOG_NOTICE, log, 0,
[701]                       "try again to bind() after 500ms");
[702] 
[703]         ngx_msleep(500);
[704]     }
[705] 
[706]     if (failed) {
[707]         ngx_log_error(NGX_LOG_EMERG, log, 0, "still could not bind()");
[708]         return NGX_ERROR;
[709]     }
[710] 
[711]     return NGX_OK;
[712] }
[713] 
[714] 
[715] void
[716] ngx_configure_listening_sockets(ngx_cycle_t *cycle)
[717] {
[718]     int                        value;
[719]     ngx_uint_t                 i;
[720]     ngx_listening_t           *ls;
[721] 
[722] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[723]     struct accept_filter_arg   af;
[724] #endif
[725] 
[726]     ls = cycle->listening.elts;
[727]     for (i = 0; i < cycle->listening.nelts; i++) {
[728] 
[729]         ls[i].log = *ls[i].logp;
[730] 
[731]         if (ls[i].rcvbuf != -1) {
[732]             if (setsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF,
[733]                            (const void *) &ls[i].rcvbuf, sizeof(int))
[734]                 == -1)
[735]             {
[736]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[737]                               "setsockopt(SO_RCVBUF, %d) %V failed, ignored",
[738]                               ls[i].rcvbuf, &ls[i].addr_text);
[739]             }
[740]         }
[741] 
[742]         if (ls[i].sndbuf != -1) {
[743]             if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF,
[744]                            (const void *) &ls[i].sndbuf, sizeof(int))
[745]                 == -1)
[746]             {
[747]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[748]                               "setsockopt(SO_SNDBUF, %d) %V failed, ignored",
[749]                               ls[i].sndbuf, &ls[i].addr_text);
[750]             }
[751]         }
[752] 
[753]         if (ls[i].keepalive) {
[754]             value = (ls[i].keepalive == 1) ? 1 : 0;
[755] 
[756]             if (setsockopt(ls[i].fd, SOL_SOCKET, SO_KEEPALIVE,
[757]                            (const void *) &value, sizeof(int))
[758]                 == -1)
[759]             {
[760]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[761]                               "setsockopt(SO_KEEPALIVE, %d) %V failed, ignored",
[762]                               value, &ls[i].addr_text);
[763]             }
[764]         }
[765] 
[766] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[767] 
[768]         if (ls[i].keepidle) {
[769]             value = ls[i].keepidle;
[770] 
[771] #if (NGX_KEEPALIVE_FACTOR)
[772]             value *= NGX_KEEPALIVE_FACTOR;
[773] #endif
[774] 
[775]             if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPIDLE,
[776]                            (const void *) &value, sizeof(int))
[777]                 == -1)
[778]             {
[779]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[780]                               "setsockopt(TCP_KEEPIDLE, %d) %V failed, ignored",
[781]                               value, &ls[i].addr_text);
[782]             }
[783]         }
[784] 
[785]         if (ls[i].keepintvl) {
[786]             value = ls[i].keepintvl;
[787] 
[788] #if (NGX_KEEPALIVE_FACTOR)
[789]             value *= NGX_KEEPALIVE_FACTOR;
[790] #endif
[791] 
[792]             if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPINTVL,
[793]                            (const void *) &value, sizeof(int))
[794]                 == -1)
[795]             {
[796]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[797]                              "setsockopt(TCP_KEEPINTVL, %d) %V failed, ignored",
[798]                              value, &ls[i].addr_text);
[799]             }
[800]         }
[801] 
[802]         if (ls[i].keepcnt) {
[803]             if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPCNT,
[804]                            (const void *) &ls[i].keepcnt, sizeof(int))
[805]                 == -1)
[806]             {
[807]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[808]                               "setsockopt(TCP_KEEPCNT, %d) %V failed, ignored",
[809]                               ls[i].keepcnt, &ls[i].addr_text);
[810]             }
[811]         }
[812] 
[813] #endif
[814] 
[815] #if (NGX_HAVE_SETFIB)
[816]         if (ls[i].setfib != -1) {
[817]             if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
[818]                            (const void *) &ls[i].setfib, sizeof(int))
[819]                 == -1)
[820]             {
[821]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[822]                               "setsockopt(SO_SETFIB, %d) %V failed, ignored",
[823]                               ls[i].setfib, &ls[i].addr_text);
[824]             }
[825]         }
[826] #endif
[827] 
[828] #if (NGX_HAVE_TCP_FASTOPEN)
[829]         if (ls[i].fastopen != -1) {
[830]             if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
[831]                            (const void *) &ls[i].fastopen, sizeof(int))
[832]                 == -1)
[833]             {
[834]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[835]                               "setsockopt(TCP_FASTOPEN, %d) %V failed, ignored",
[836]                               ls[i].fastopen, &ls[i].addr_text);
[837]             }
[838]         }
[839] #endif
[840] 
[841] #if 0
[842]         if (1) {
[843]             int tcp_nodelay = 1;
[844] 
[845]             if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_NODELAY,
[846]                        (const void *) &tcp_nodelay, sizeof(int))
[847]                 == -1)
[848]             {
[849]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[850]                               "setsockopt(TCP_NODELAY) %V failed, ignored",
[851]                               &ls[i].addr_text);
[852]             }
[853]         }
[854] #endif
[855] 
[856]         if (ls[i].listen) {
[857] 
[858]             /* change backlog via listen() */
[859] 
[860]             if (listen(ls[i].fd, ls[i].backlog) == -1) {
[861]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[862]                               "listen() to %V, backlog %d failed, ignored",
[863]                               &ls[i].addr_text, ls[i].backlog);
[864]             }
[865]         }
[866] 
[867]         /*
[868]          * setting deferred mode should be last operation on socket,
[869]          * because code may prematurely continue cycle on failure
[870]          */
[871] 
[872] #if (NGX_HAVE_DEFERRED_ACCEPT)
[873] 
[874] #ifdef SO_ACCEPTFILTER
[875] 
[876]         if (ls[i].delete_deferred) {
[877]             if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, NULL, 0)
[878]                 == -1)
[879]             {
[880]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[881]                               "setsockopt(SO_ACCEPTFILTER, NULL) "
[882]                               "for %V failed, ignored",
[883]                               &ls[i].addr_text);
[884] 
[885]                 if (ls[i].accept_filter) {
[886]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[887]                                   "could not change the accept filter "
[888]                                   "to \"%s\" for %V, ignored",
[889]                                   ls[i].accept_filter, &ls[i].addr_text);
[890]                 }
[891] 
[892]                 continue;
[893]             }
[894] 
[895]             ls[i].deferred_accept = 0;
[896]         }
[897] 
[898]         if (ls[i].add_deferred) {
[899]             ngx_memzero(&af, sizeof(struct accept_filter_arg));
[900]             (void) ngx_cpystrn((u_char *) af.af_name,
[901]                                (u_char *) ls[i].accept_filter, 16);
[902] 
[903]             if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER,
[904]                            &af, sizeof(struct accept_filter_arg))
[905]                 == -1)
[906]             {
[907]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[908]                               "setsockopt(SO_ACCEPTFILTER, \"%s\") "
[909]                               "for %V failed, ignored",
[910]                               ls[i].accept_filter, &ls[i].addr_text);
[911]                 continue;
[912]             }
[913] 
[914]             ls[i].deferred_accept = 1;
[915]         }
[916] 
[917] #endif
[918] 
[919] #ifdef TCP_DEFER_ACCEPT
[920] 
[921]         if (ls[i].add_deferred || ls[i].delete_deferred) {
[922] 
[923]             if (ls[i].add_deferred) {
[924]                 /*
[925]                  * There is no way to find out how long a connection was
[926]                  * in queue (and a connection may bypass deferred queue at all
[927]                  * if syncookies were used), hence we use 1 second timeout
[928]                  * here.
[929]                  */
[930]                 value = 1;
[931] 
[932]             } else {
[933]                 value = 0;
[934]             }
[935] 
[936]             if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
[937]                            &value, sizeof(int))
[938]                 == -1)
[939]             {
[940]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[941]                               "setsockopt(TCP_DEFER_ACCEPT, %d) for %V failed, "
[942]                               "ignored",
[943]                               value, &ls[i].addr_text);
[944] 
[945]                 continue;
[946]             }
[947]         }
[948] 
[949]         if (ls[i].add_deferred) {
[950]             ls[i].deferred_accept = 1;
[951]         }
[952] 
[953] #endif
[954] 
[955] #endif /* NGX_HAVE_DEFERRED_ACCEPT */
[956] 
[957] #if (NGX_HAVE_IP_RECVDSTADDR)
[958] 
[959]         if (ls[i].wildcard
[960]             && ls[i].type == SOCK_DGRAM
[961]             && ls[i].sockaddr->sa_family == AF_INET)
[962]         {
[963]             value = 1;
[964] 
[965]             if (setsockopt(ls[i].fd, IPPROTO_IP, IP_RECVDSTADDR,
[966]                            (const void *) &value, sizeof(int))
[967]                 == -1)
[968]             {
[969]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[970]                               "setsockopt(IP_RECVDSTADDR) "
[971]                               "for %V failed, ignored",
[972]                               &ls[i].addr_text);
[973]             }
[974]         }
[975] 
[976] #elif (NGX_HAVE_IP_PKTINFO)
[977] 
[978]         if (ls[i].wildcard
[979]             && ls[i].type == SOCK_DGRAM
[980]             && ls[i].sockaddr->sa_family == AF_INET)
[981]         {
[982]             value = 1;
[983] 
[984]             if (setsockopt(ls[i].fd, IPPROTO_IP, IP_PKTINFO,
[985]                            (const void *) &value, sizeof(int))
[986]                 == -1)
[987]             {
[988]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[989]                               "setsockopt(IP_PKTINFO) "
[990]                               "for %V failed, ignored",
[991]                               &ls[i].addr_text);
[992]             }
[993]         }
[994] 
[995] #endif
[996] 
[997] #if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
[998] 
[999]         if (ls[i].wildcard
[1000]             && ls[i].type == SOCK_DGRAM
[1001]             && ls[i].sockaddr->sa_family == AF_INET6)
[1002]         {
[1003]             value = 1;
[1004] 
[1005]             if (setsockopt(ls[i].fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
[1006]                            (const void *) &value, sizeof(int))
[1007]                 == -1)
[1008]             {
[1009]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
[1010]                               "setsockopt(IPV6_RECVPKTINFO) "
[1011]                               "for %V failed, ignored",
[1012]                               &ls[i].addr_text);
[1013]             }
[1014]         }
[1015] 
[1016] #endif
[1017]     }
[1018] 
[1019]     return;
[1020] }
[1021] 
[1022] 
[1023] void
[1024] ngx_close_listening_sockets(ngx_cycle_t *cycle)
[1025] {
[1026]     ngx_uint_t         i;
[1027]     ngx_listening_t   *ls;
[1028]     ngx_connection_t  *c;
[1029] 
[1030]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[1031]         return;
[1032]     }
[1033] 
[1034]     ngx_accept_mutex_held = 0;
[1035]     ngx_use_accept_mutex = 0;
[1036] 
[1037]     ls = cycle->listening.elts;
[1038]     for (i = 0; i < cycle->listening.nelts; i++) {
[1039] 
[1040]         c = ls[i].connection;
[1041] 
[1042]         if (c) {
[1043]             if (c->read->active) {
[1044]                 if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
[1045] 
[1046]                     /*
[1047]                      * it seems that Linux-2.6.x OpenVZ sends events
[1048]                      * for closed shared listening sockets unless
[1049]                      * the events was explicitly deleted
[1050]                      */
[1051] 
[1052]                     ngx_del_event(c->read, NGX_READ_EVENT, 0);
[1053] 
[1054]                 } else {
[1055]                     ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
[1056]                 }
[1057]             }
[1058] 
[1059]             ngx_free_connection(c);
[1060] 
[1061]             c->fd = (ngx_socket_t) -1;
[1062]         }
[1063] 
[1064]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[1065]                        "close listening %V #%d ", &ls[i].addr_text, ls[i].fd);
[1066] 
[1067]         if (ngx_close_socket(ls[i].fd) == -1) {
[1068]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
[1069]                           ngx_close_socket_n " %V failed", &ls[i].addr_text);
[1070]         }
[1071] 
[1072] #if (NGX_HAVE_UNIX_DOMAIN)
[1073] 
[1074]         if (ls[i].sockaddr->sa_family == AF_UNIX
[1075]             && ngx_process <= NGX_PROCESS_MASTER
[1076]             && ngx_new_binary == 0
[1077]             && (!ls[i].inherited || ngx_getppid() != ngx_parent))
[1078]         {
[1079]             u_char *name = ls[i].addr_text.data + sizeof("unix:") - 1;
[1080] 
[1081]             if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[1082]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
[1083]                               ngx_delete_file_n " %s failed", name);
[1084]             }
[1085]         }
[1086] 
[1087] #endif
[1088] 
[1089]         ls[i].fd = (ngx_socket_t) -1;
[1090]     }
[1091] 
[1092]     cycle->listening.nelts = 0;
[1093] }
[1094] 
[1095] 
[1096] ngx_connection_t *
[1097] ngx_get_connection(ngx_socket_t s, ngx_log_t *log)
[1098] {
[1099]     ngx_uint_t         instance;
[1100]     ngx_event_t       *rev, *wev;
[1101]     ngx_connection_t  *c;
[1102] 
[1103]     /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */
[1104] 
[1105]     if (ngx_cycle->files && (ngx_uint_t) s >= ngx_cycle->files_n) {
[1106]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[1107]                       "the new socket has number %d, "
[1108]                       "but only %ui files are available",
[1109]                       s, ngx_cycle->files_n);
[1110]         return NULL;
[1111]     }
[1112] 
[1113]     ngx_drain_connections((ngx_cycle_t *) ngx_cycle);
[1114] 
[1115]     c = ngx_cycle->free_connections;
[1116] 
[1117]     if (c == NULL) {
[1118]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[1119]                       "%ui worker_connections are not enough",
[1120]                       ngx_cycle->connection_n);
[1121] 
[1122]         return NULL;
[1123]     }
[1124] 
[1125]     ngx_cycle->free_connections = c->data;
[1126]     ngx_cycle->free_connection_n--;
[1127] 
[1128]     if (ngx_cycle->files && ngx_cycle->files[s] == NULL) {
[1129]         ngx_cycle->files[s] = c;
[1130]     }
[1131] 
[1132]     rev = c->read;
[1133]     wev = c->write;
[1134] 
[1135]     ngx_memzero(c, sizeof(ngx_connection_t));
[1136] 
[1137]     c->read = rev;
[1138]     c->write = wev;
[1139]     c->fd = s;
[1140]     c->log = log;
[1141] 
[1142]     instance = rev->instance;
[1143] 
[1144]     ngx_memzero(rev, sizeof(ngx_event_t));
[1145]     ngx_memzero(wev, sizeof(ngx_event_t));
[1146] 
[1147]     rev->instance = !instance;
[1148]     wev->instance = !instance;
[1149] 
[1150]     rev->index = NGX_INVALID_INDEX;
[1151]     wev->index = NGX_INVALID_INDEX;
[1152] 
[1153]     rev->data = c;
[1154]     wev->data = c;
[1155] 
[1156]     wev->write = 1;
[1157] 
[1158]     return c;
[1159] }
[1160] 
[1161] 
[1162] void
[1163] ngx_free_connection(ngx_connection_t *c)
[1164] {
[1165]     c->data = ngx_cycle->free_connections;
[1166]     ngx_cycle->free_connections = c;
[1167]     ngx_cycle->free_connection_n++;
[1168] 
[1169]     if (ngx_cycle->files && ngx_cycle->files[c->fd] == c) {
[1170]         ngx_cycle->files[c->fd] = NULL;
[1171]     }
[1172] }
[1173] 
[1174] 
[1175] void
[1176] ngx_close_connection(ngx_connection_t *c)
[1177] {
[1178]     ngx_err_t     err;
[1179]     ngx_uint_t    log_error, level;
[1180]     ngx_socket_t  fd;
[1181] 
[1182]     if (c->fd == (ngx_socket_t) -1) {
[1183]         ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
[1184]         return;
[1185]     }
[1186] 
[1187]     if (c->read->timer_set) {
[1188]         ngx_del_timer(c->read);
[1189]     }
[1190] 
[1191]     if (c->write->timer_set) {
[1192]         ngx_del_timer(c->write);
[1193]     }
[1194] 
[1195]     if (!c->shared) {
[1196]         if (ngx_del_conn) {
[1197]             ngx_del_conn(c, NGX_CLOSE_EVENT);
[1198] 
[1199]         } else {
[1200]             if (c->read->active || c->read->disabled) {
[1201]                 ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
[1202]             }
[1203] 
[1204]             if (c->write->active || c->write->disabled) {
[1205]                 ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
[1206]             }
[1207]         }
[1208]     }
[1209] 
[1210]     if (c->read->posted) {
[1211]         ngx_delete_posted_event(c->read);
[1212]     }
[1213] 
[1214]     if (c->write->posted) {
[1215]         ngx_delete_posted_event(c->write);
[1216]     }
[1217] 
[1218]     c->read->closed = 1;
[1219]     c->write->closed = 1;
[1220] 
[1221]     ngx_reusable_connection(c, 0);
[1222] 
[1223]     log_error = c->log_error;
[1224] 
[1225]     ngx_free_connection(c);
[1226] 
[1227]     fd = c->fd;
[1228]     c->fd = (ngx_socket_t) -1;
[1229] 
[1230]     if (c->shared) {
[1231]         return;
[1232]     }
[1233] 
[1234]     if (ngx_close_socket(fd) == -1) {
[1235] 
[1236]         err = ngx_socket_errno;
[1237] 
[1238]         if (err == NGX_ECONNRESET || err == NGX_ENOTCONN) {
[1239] 
[1240]             switch (log_error) {
[1241] 
[1242]             case NGX_ERROR_INFO:
[1243]                 level = NGX_LOG_INFO;
[1244]                 break;
[1245] 
[1246]             case NGX_ERROR_ERR:
[1247]                 level = NGX_LOG_ERR;
[1248]                 break;
[1249] 
[1250]             default:
[1251]                 level = NGX_LOG_CRIT;
[1252]             }
[1253] 
[1254]         } else {
[1255]             level = NGX_LOG_CRIT;
[1256]         }
[1257] 
[1258]         ngx_log_error(level, c->log, err, ngx_close_socket_n " %d failed", fd);
[1259]     }
[1260] }
[1261] 
[1262] 
[1263] void
[1264] ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable)
[1265] {
[1266]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[1267]                    "reusable connection: %ui", reusable);
[1268] 
[1269]     if (c->reusable) {
[1270]         ngx_queue_remove(&c->queue);
[1271]         ngx_cycle->reusable_connections_n--;
[1272] 
[1273] #if (NGX_STAT_STUB)
[1274]         (void) ngx_atomic_fetch_add(ngx_stat_waiting, -1);
[1275] #endif
[1276]     }
[1277] 
[1278]     c->reusable = reusable;
[1279] 
[1280]     if (reusable) {
[1281]         /* need cast as ngx_cycle is volatile */
[1282] 
[1283]         ngx_queue_insert_head(
[1284]             (ngx_queue_t *) &ngx_cycle->reusable_connections_queue, &c->queue);
[1285]         ngx_cycle->reusable_connections_n++;
[1286] 
[1287] #if (NGX_STAT_STUB)
[1288]         (void) ngx_atomic_fetch_add(ngx_stat_waiting, 1);
[1289] #endif
[1290]     }
[1291] }
[1292] 
[1293] 
[1294] static void
[1295] ngx_drain_connections(ngx_cycle_t *cycle)
[1296] {
[1297]     ngx_uint_t         i, n;
[1298]     ngx_queue_t       *q;
[1299]     ngx_connection_t  *c;
[1300] 
[1301]     if (cycle->free_connection_n > cycle->connection_n / 16
[1302]         || cycle->reusable_connections_n == 0)
[1303]     {
[1304]         return;
[1305]     }
[1306] 
[1307]     if (cycle->connections_reuse_time != ngx_time()) {
[1308]         cycle->connections_reuse_time = ngx_time();
[1309] 
[1310]         ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
[1311]                       "%ui worker_connections are not enough, "
[1312]                       "reusing connections",
[1313]                       cycle->connection_n);
[1314]     }
[1315] 
[1316]     c = NULL;
[1317]     n = ngx_max(ngx_min(32, cycle->reusable_connections_n / 8), 1);
[1318] 
[1319]     for (i = 0; i < n; i++) {
[1320]         if (ngx_queue_empty(&cycle->reusable_connections_queue)) {
[1321]             break;
[1322]         }
[1323] 
[1324]         q = ngx_queue_last(&cycle->reusable_connections_queue);
[1325]         c = ngx_queue_data(q, ngx_connection_t, queue);
[1326] 
[1327]         ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
[1328]                        "reusing connection");
[1329] 
[1330]         c->close = 1;
[1331]         c->read->handler(c->read);
[1332]     }
[1333] 
[1334]     if (cycle->free_connection_n == 0 && c && c->reusable) {
[1335] 
[1336]         /*
[1337]          * if no connections were freed, try to reuse the last
[1338]          * connection again: this should free it as long as
[1339]          * previous reuse moved it to lingering close
[1340]          */
[1341] 
[1342]         ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
[1343]                        "reusing connection again");
[1344] 
[1345]         c->close = 1;
[1346]         c->read->handler(c->read);
[1347]     }
[1348] }
[1349] 
[1350] 
[1351] void
[1352] ngx_close_idle_connections(ngx_cycle_t *cycle)
[1353] {
[1354]     ngx_uint_t         i;
[1355]     ngx_connection_t  *c;
[1356] 
[1357]     c = cycle->connections;
[1358] 
[1359]     for (i = 0; i < cycle->connection_n; i++) {
[1360] 
[1361]         /* THREAD: lock */
[1362] 
[1363]         if (c[i].fd != (ngx_socket_t) -1 && c[i].idle) {
[1364]             c[i].close = 1;
[1365]             c[i].read->handler(c[i].read);
[1366]         }
[1367]     }
[1368] }
[1369] 
[1370] 
[1371] ngx_int_t
[1372] ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
[1373]     ngx_uint_t port)
[1374] {
[1375]     socklen_t             len;
[1376]     ngx_uint_t            addr;
[1377]     ngx_sockaddr_t        sa;
[1378]     struct sockaddr_in   *sin;
[1379] #if (NGX_HAVE_INET6)
[1380]     ngx_uint_t            i;
[1381]     struct sockaddr_in6  *sin6;
[1382] #endif
[1383] 
[1384]     addr = 0;
[1385] 
[1386]     if (c->local_socklen) {
[1387]         switch (c->local_sockaddr->sa_family) {
[1388] 
[1389] #if (NGX_HAVE_INET6)
[1390]         case AF_INET6:
[1391]             sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
[1392] 
[1393]             for (i = 0; addr == 0 && i < 16; i++) {
[1394]                 addr |= sin6->sin6_addr.s6_addr[i];
[1395]             }
[1396] 
[1397]             break;
[1398] #endif
[1399] 
[1400] #if (NGX_HAVE_UNIX_DOMAIN)
[1401]         case AF_UNIX:
[1402]             addr = 1;
[1403]             break;
[1404] #endif
[1405] 
[1406]         default: /* AF_INET */
[1407]             sin = (struct sockaddr_in *) c->local_sockaddr;
[1408]             addr = sin->sin_addr.s_addr;
[1409]             break;
[1410]         }
[1411]     }
[1412] 
[1413]     if (addr == 0) {
[1414] 
[1415]         len = sizeof(ngx_sockaddr_t);
[1416] 
[1417]         if (getsockname(c->fd, &sa.sockaddr, &len) == -1) {
[1418]             ngx_connection_error(c, ngx_socket_errno, "getsockname() failed");
[1419]             return NGX_ERROR;
[1420]         }
[1421] 
[1422]         c->local_sockaddr = ngx_palloc(c->pool, len);
[1423]         if (c->local_sockaddr == NULL) {
[1424]             return NGX_ERROR;
[1425]         }
[1426] 
[1427]         ngx_memcpy(c->local_sockaddr, &sa, len);
[1428] 
[1429]         c->local_socklen = len;
[1430]     }
[1431] 
[1432]     if (s == NULL) {
[1433]         return NGX_OK;
[1434]     }
[1435] 
[1436]     s->len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen,
[1437]                            s->data, s->len, port);
[1438] 
[1439]     return NGX_OK;
[1440] }
[1441] 
[1442] 
[1443] ngx_int_t
[1444] ngx_tcp_nodelay(ngx_connection_t *c)
[1445] {
[1446]     int  tcp_nodelay;
[1447] 
[1448]     if (c->tcp_nodelay != NGX_TCP_NODELAY_UNSET) {
[1449]         return NGX_OK;
[1450]     }
[1451] 
[1452]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0, "tcp_nodelay");
[1453] 
[1454]     tcp_nodelay = 1;
[1455] 
[1456]     if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
[1457]                    (const void *) &tcp_nodelay, sizeof(int))
[1458]         == -1)
[1459]     {
[1460] #if (NGX_SOLARIS)
[1461]         if (c->log_error == NGX_ERROR_INFO) {
[1462] 
[1463]             /* Solaris returns EINVAL if a socket has been shut down */
[1464]             c->log_error = NGX_ERROR_IGNORE_EINVAL;
[1465] 
[1466]             ngx_connection_error(c, ngx_socket_errno,
[1467]                                  "setsockopt(TCP_NODELAY) failed");
[1468] 
[1469]             c->log_error = NGX_ERROR_INFO;
[1470] 
[1471]             return NGX_ERROR;
[1472]         }
[1473] #endif
[1474] 
[1475]         ngx_connection_error(c, ngx_socket_errno,
[1476]                              "setsockopt(TCP_NODELAY) failed");
[1477]         return NGX_ERROR;
[1478]     }
[1479] 
[1480]     c->tcp_nodelay = NGX_TCP_NODELAY_SET;
[1481] 
[1482]     return NGX_OK;
[1483] }
[1484] 
[1485] 
[1486] ngx_int_t
[1487] ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text)
[1488] {
[1489]     ngx_uint_t  level;
[1490] 
[1491]     /* Winsock may return NGX_ECONNABORTED instead of NGX_ECONNRESET */
[1492] 
[1493]     if ((err == NGX_ECONNRESET
[1494] #if (NGX_WIN32)
[1495]          || err == NGX_ECONNABORTED
[1496] #endif
[1497]         ) && c->log_error == NGX_ERROR_IGNORE_ECONNRESET)
[1498]     {
[1499]         return 0;
[1500]     }
[1501] 
[1502] #if (NGX_SOLARIS)
[1503]     if (err == NGX_EINVAL && c->log_error == NGX_ERROR_IGNORE_EINVAL) {
[1504]         return 0;
[1505]     }
[1506] #endif
[1507] 
[1508]     if (err == 0
[1509]         || err == NGX_ECONNRESET
[1510] #if (NGX_WIN32)
[1511]         || err == NGX_ECONNABORTED
[1512] #else
[1513]         || err == NGX_EPIPE
[1514] #endif
[1515]         || err == NGX_ENOTCONN
[1516]         || err == NGX_ETIMEDOUT
[1517]         || err == NGX_ECONNREFUSED
[1518]         || err == NGX_ENETDOWN
[1519]         || err == NGX_ENETUNREACH
[1520]         || err == NGX_EHOSTDOWN
[1521]         || err == NGX_EHOSTUNREACH)
[1522]     {
[1523]         switch (c->log_error) {
[1524] 
[1525]         case NGX_ERROR_IGNORE_EINVAL:
[1526]         case NGX_ERROR_IGNORE_ECONNRESET:
[1527]         case NGX_ERROR_INFO:
[1528]             level = NGX_LOG_INFO;
[1529]             break;
[1530] 
[1531]         default:
[1532]             level = NGX_LOG_ERR;
[1533]         }
[1534] 
[1535]     } else {
[1536]         level = NGX_LOG_ALERT;
[1537]     }
[1538] 
[1539]     ngx_log_error(level, c->log, err, text);
[1540] 
[1541]     return NGX_ERROR;
[1542] }
