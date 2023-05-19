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
[11] 
[12] 
[13] #if !(NGX_WIN32)
[14] 
[15] struct ngx_udp_connection_s {
[16]     ngx_rbtree_node_t   node;
[17]     ngx_connection_t   *connection;
[18]     ngx_buf_t          *buffer;
[19] };
[20] 
[21] 
[22] static void ngx_close_accepted_udp_connection(ngx_connection_t *c);
[23] static ssize_t ngx_udp_shared_recv(ngx_connection_t *c, u_char *buf,
[24]     size_t size);
[25] static ngx_int_t ngx_insert_udp_connection(ngx_connection_t *c);
[26] static ngx_connection_t *ngx_lookup_udp_connection(ngx_listening_t *ls,
[27]     struct sockaddr *sockaddr, socklen_t socklen,
[28]     struct sockaddr *local_sockaddr, socklen_t local_socklen);
[29] 
[30] 
[31] void
[32] ngx_event_recvmsg(ngx_event_t *ev)
[33] {
[34]     ssize_t            n;
[35]     ngx_buf_t          buf;
[36]     ngx_log_t         *log;
[37]     ngx_err_t          err;
[38]     socklen_t          socklen, local_socklen;
[39]     ngx_event_t       *rev, *wev;
[40]     struct iovec       iov[1];
[41]     struct msghdr      msg;
[42]     ngx_sockaddr_t     sa, lsa;
[43]     struct sockaddr   *sockaddr, *local_sockaddr;
[44]     ngx_listening_t   *ls;
[45]     ngx_event_conf_t  *ecf;
[46]     ngx_connection_t  *c, *lc;
[47]     static u_char      buffer[65535];
[48] 
[49] #if (NGX_HAVE_ADDRINFO_CMSG)
[50]     u_char             msg_control[CMSG_SPACE(sizeof(ngx_addrinfo_t))];
[51] #endif
[52] 
[53]     if (ev->timedout) {
[54]         if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
[55]             return;
[56]         }
[57] 
[58]         ev->timedout = 0;
[59]     }
[60] 
[61]     ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);
[62] 
[63]     if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
[64]         ev->available = ecf->multi_accept;
[65]     }
[66] 
[67]     lc = ev->data;
[68]     ls = lc->listening;
[69]     ev->ready = 0;
[70] 
[71]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[72]                    "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);
[73] 
[74]     do {
[75]         ngx_memzero(&msg, sizeof(struct msghdr));
[76] 
[77]         iov[0].iov_base = (void *) buffer;
[78]         iov[0].iov_len = sizeof(buffer);
[79] 
[80]         msg.msg_name = &sa;
[81]         msg.msg_namelen = sizeof(ngx_sockaddr_t);
[82]         msg.msg_iov = iov;
[83]         msg.msg_iovlen = 1;
[84] 
[85] #if (NGX_HAVE_ADDRINFO_CMSG)
[86]         if (ls->wildcard) {
[87]             msg.msg_control = &msg_control;
[88]             msg.msg_controllen = sizeof(msg_control);
[89] 
[90]             ngx_memzero(&msg_control, sizeof(msg_control));
[91]         }
[92] #endif
[93] 
[94]         n = recvmsg(lc->fd, &msg, 0);
[95] 
[96]         if (n == -1) {
[97]             err = ngx_socket_errno;
[98] 
[99]             if (err == NGX_EAGAIN) {
[100]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
[101]                                "recvmsg() not ready");
[102]                 return;
[103]             }
[104] 
[105]             ngx_log_error(NGX_LOG_ALERT, ev->log, err, "recvmsg() failed");
[106] 
[107]             return;
[108]         }
[109] 
[110] #if (NGX_HAVE_ADDRINFO_CMSG)
[111]         if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
[112]             ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[113]                           "recvmsg() truncated data");
[114]             continue;
[115]         }
[116] #endif
[117] 
[118]         sockaddr = msg.msg_name;
[119]         socklen = msg.msg_namelen;
[120] 
[121]         if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
[122]             socklen = sizeof(ngx_sockaddr_t);
[123]         }
[124] 
[125]         if (socklen == 0) {
[126] 
[127]             /*
[128]              * on Linux recvmsg() returns zero msg_namelen
[129]              * when receiving packets from unbound AF_UNIX sockets
[130]              */
[131] 
[132]             socklen = sizeof(struct sockaddr);
[133]             ngx_memzero(&sa, sizeof(struct sockaddr));
[134]             sa.sockaddr.sa_family = ls->sockaddr->sa_family;
[135]         }
[136] 
[137]         local_sockaddr = ls->sockaddr;
[138]         local_socklen = ls->socklen;
[139] 
[140] #if (NGX_HAVE_ADDRINFO_CMSG)
[141] 
[142]         if (ls->wildcard) {
[143]             struct cmsghdr  *cmsg;
[144] 
[145]             ngx_memcpy(&lsa, local_sockaddr, local_socklen);
[146]             local_sockaddr = &lsa.sockaddr;
[147] 
[148]             for (cmsg = CMSG_FIRSTHDR(&msg);
[149]                  cmsg != NULL;
[150]                  cmsg = CMSG_NXTHDR(&msg, cmsg))
[151]             {
[152]                 if (ngx_get_srcaddr_cmsg(cmsg, local_sockaddr) == NGX_OK) {
[153]                     break;
[154]                 }
[155]             }
[156]         }
[157] 
[158] #endif
[159] 
[160]         c = ngx_lookup_udp_connection(ls, sockaddr, socklen, local_sockaddr,
[161]                                       local_socklen);
[162] 
[163]         if (c) {
[164] 
[165] #if (NGX_DEBUG)
[166]             if (c->log->log_level & NGX_LOG_DEBUG_EVENT) {
[167]                 ngx_log_handler_pt  handler;
[168] 
[169]                 handler = c->log->handler;
[170]                 c->log->handler = NULL;
[171] 
[172]                 ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[173]                                "recvmsg: fd:%d n:%z", c->fd, n);
[174] 
[175]                 c->log->handler = handler;
[176]             }
[177] #endif
[178] 
[179]             ngx_memzero(&buf, sizeof(ngx_buf_t));
[180] 
[181]             buf.pos = buffer;
[182]             buf.last = buffer + n;
[183] 
[184]             rev = c->read;
[185] 
[186]             c->udp->buffer = &buf;
[187] 
[188]             rev->ready = 1;
[189]             rev->active = 0;
[190] 
[191]             rev->handler(rev);
[192] 
[193]             if (c->udp) {
[194]                 c->udp->buffer = NULL;
[195]             }
[196] 
[197]             rev->ready = 0;
[198]             rev->active = 1;
[199] 
[200]             goto next;
[201]         }
[202] 
[203] #if (NGX_STAT_STUB)
[204]         (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
[205] #endif
[206] 
[207]         ngx_accept_disabled = ngx_cycle->connection_n / 8
[208]                               - ngx_cycle->free_connection_n;
[209] 
[210]         c = ngx_get_connection(lc->fd, ev->log);
[211]         if (c == NULL) {
[212]             return;
[213]         }
[214] 
[215]         c->shared = 1;
[216]         c->type = SOCK_DGRAM;
[217]         c->socklen = socklen;
[218] 
[219] #if (NGX_STAT_STUB)
[220]         (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
[221] #endif
[222] 
[223]         c->pool = ngx_create_pool(ls->pool_size, ev->log);
[224]         if (c->pool == NULL) {
[225]             ngx_close_accepted_udp_connection(c);
[226]             return;
[227]         }
[228] 
[229]         c->sockaddr = ngx_palloc(c->pool, socklen);
[230]         if (c->sockaddr == NULL) {
[231]             ngx_close_accepted_udp_connection(c);
[232]             return;
[233]         }
[234] 
[235]         ngx_memcpy(c->sockaddr, sockaddr, socklen);
[236] 
[237]         log = ngx_palloc(c->pool, sizeof(ngx_log_t));
[238]         if (log == NULL) {
[239]             ngx_close_accepted_udp_connection(c);
[240]             return;
[241]         }
[242] 
[243]         *log = ls->log;
[244] 
[245]         c->recv = ngx_udp_shared_recv;
[246]         c->send = ngx_udp_send;
[247]         c->send_chain = ngx_udp_send_chain;
[248] 
[249]         c->need_flush_buf = 1;
[250] 
[251]         c->log = log;
[252]         c->pool->log = log;
[253]         c->listening = ls;
[254] 
[255]         if (local_sockaddr == &lsa.sockaddr) {
[256]             local_sockaddr = ngx_palloc(c->pool, local_socklen);
[257]             if (local_sockaddr == NULL) {
[258]                 ngx_close_accepted_udp_connection(c);
[259]                 return;
[260]             }
[261] 
[262]             ngx_memcpy(local_sockaddr, &lsa, local_socklen);
[263]         }
[264] 
[265]         c->local_sockaddr = local_sockaddr;
[266]         c->local_socklen = local_socklen;
[267] 
[268]         c->buffer = ngx_create_temp_buf(c->pool, n);
[269]         if (c->buffer == NULL) {
[270]             ngx_close_accepted_udp_connection(c);
[271]             return;
[272]         }
[273] 
[274]         c->buffer->last = ngx_cpymem(c->buffer->last, buffer, n);
[275] 
[276]         rev = c->read;
[277]         wev = c->write;
[278] 
[279]         rev->active = 1;
[280]         wev->ready = 1;
[281] 
[282]         rev->log = log;
[283]         wev->log = log;
[284] 
[285]         /*
[286]          * TODO: MT: - ngx_atomic_fetch_add()
[287]          *             or protection by critical section or light mutex
[288]          *
[289]          * TODO: MP: - allocated in a shared memory
[290]          *           - ngx_atomic_fetch_add()
[291]          *             or protection by critical section or light mutex
[292]          */
[293] 
[294]         c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
[295] 
[296]         c->start_time = ngx_current_msec;
[297] 
[298] #if (NGX_STAT_STUB)
[299]         (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
[300] #endif
[301] 
[302]         if (ls->addr_ntop) {
[303]             c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
[304]             if (c->addr_text.data == NULL) {
[305]                 ngx_close_accepted_udp_connection(c);
[306]                 return;
[307]             }
[308] 
[309]             c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
[310]                                              c->addr_text.data,
[311]                                              ls->addr_text_max_len, 0);
[312]             if (c->addr_text.len == 0) {
[313]                 ngx_close_accepted_udp_connection(c);
[314]                 return;
[315]             }
[316]         }
[317] 
[318] #if (NGX_DEBUG)
[319]         {
[320]         ngx_str_t  addr;
[321]         u_char     text[NGX_SOCKADDR_STRLEN];
[322] 
[323]         ngx_debug_accepted_connection(ecf, c);
[324] 
[325]         if (log->log_level & NGX_LOG_DEBUG_EVENT) {
[326]             addr.data = text;
[327]             addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
[328]                                      NGX_SOCKADDR_STRLEN, 1);
[329] 
[330]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
[331]                            "*%uA recvmsg: %V fd:%d n:%z",
[332]                            c->number, &addr, c->fd, n);
[333]         }
[334] 
[335]         }
[336] #endif
[337] 
[338]         if (ngx_insert_udp_connection(c) != NGX_OK) {
[339]             ngx_close_accepted_udp_connection(c);
[340]             return;
[341]         }
[342] 
[343]         log->data = NULL;
[344]         log->handler = NULL;
[345] 
[346]         ls->handler(c);
[347] 
[348]     next:
[349] 
[350]         if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[351]             ev->available -= n;
[352]         }
[353] 
[354]     } while (ev->available);
[355] }
[356] 
[357] 
[358] static void
[359] ngx_close_accepted_udp_connection(ngx_connection_t *c)
[360] {
[361]     ngx_free_connection(c);
[362] 
[363]     c->fd = (ngx_socket_t) -1;
[364] 
[365]     if (c->pool) {
[366]         ngx_destroy_pool(c->pool);
[367]     }
[368] 
[369] #if (NGX_STAT_STUB)
[370]     (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
[371] #endif
[372] }
[373] 
[374] 
[375] static ssize_t
[376] ngx_udp_shared_recv(ngx_connection_t *c, u_char *buf, size_t size)
[377] {
[378]     ssize_t     n;
[379]     ngx_buf_t  *b;
[380] 
[381]     if (c->udp == NULL || c->udp->buffer == NULL) {
[382]         return NGX_AGAIN;
[383]     }
[384] 
[385]     b = c->udp->buffer;
[386] 
[387]     n = ngx_min(b->last - b->pos, (ssize_t) size);
[388] 
[389]     ngx_memcpy(buf, b->pos, n);
[390] 
[391]     c->udp->buffer = NULL;
[392] 
[393]     c->read->ready = 0;
[394]     c->read->active = 1;
[395] 
[396]     return n;
[397] }
[398] 
[399] 
[400] void
[401] ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
[402]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[403] {
[404]     ngx_int_t               rc;
[405]     ngx_connection_t       *c, *ct;
[406]     ngx_rbtree_node_t     **p;
[407]     ngx_udp_connection_t   *udp, *udpt;
[408] 
[409]     for ( ;; ) {
[410] 
[411]         if (node->key < temp->key) {
[412] 
[413]             p = &temp->left;
[414] 
[415]         } else if (node->key > temp->key) {
[416] 
[417]             p = &temp->right;
[418] 
[419]         } else { /* node->key == temp->key */
[420] 
[421]             udp = (ngx_udp_connection_t *) node;
[422]             c = udp->connection;
[423] 
[424]             udpt = (ngx_udp_connection_t *) temp;
[425]             ct = udpt->connection;
[426] 
[427]             rc = ngx_cmp_sockaddr(c->sockaddr, c->socklen,
[428]                                   ct->sockaddr, ct->socklen, 1);
[429] 
[430]             if (rc == 0 && c->listening->wildcard) {
[431]                 rc = ngx_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
[432]                                       ct->local_sockaddr, ct->local_socklen, 1);
[433]             }
[434] 
[435]             p = (rc < 0) ? &temp->left : &temp->right;
[436]         }
[437] 
[438]         if (*p == sentinel) {
[439]             break;
[440]         }
[441] 
[442]         temp = *p;
[443]     }
[444] 
[445]     *p = node;
[446]     node->parent = temp;
[447]     node->left = sentinel;
[448]     node->right = sentinel;
[449]     ngx_rbt_red(node);
[450] }
[451] 
[452] 
[453] static ngx_int_t
[454] ngx_insert_udp_connection(ngx_connection_t *c)
[455] {
[456]     uint32_t               hash;
[457]     ngx_pool_cleanup_t    *cln;
[458]     ngx_udp_connection_t  *udp;
[459] 
[460]     if (c->udp) {
[461]         return NGX_OK;
[462]     }
[463] 
[464]     udp = ngx_pcalloc(c->pool, sizeof(ngx_udp_connection_t));
[465]     if (udp == NULL) {
[466]         return NGX_ERROR;
[467]     }
[468] 
[469]     udp->connection = c;
[470] 
[471]     ngx_crc32_init(hash);
[472]     ngx_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);
[473] 
[474]     if (c->listening->wildcard) {
[475]         ngx_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
[476]     }
[477] 
[478]     ngx_crc32_final(hash);
[479] 
[480]     udp->node.key = hash;
[481] 
[482]     cln = ngx_pool_cleanup_add(c->pool, 0);
[483]     if (cln == NULL) {
[484]         return NGX_ERROR;
[485]     }
[486] 
[487]     cln->data = c;
[488]     cln->handler = ngx_delete_udp_connection;
[489] 
[490]     ngx_rbtree_insert(&c->listening->rbtree, &udp->node);
[491] 
[492]     c->udp = udp;
[493] 
[494]     return NGX_OK;
[495] }
[496] 
[497] 
[498] void
[499] ngx_delete_udp_connection(void *data)
[500] {
[501]     ngx_connection_t  *c = data;
[502] 
[503]     if (c->udp == NULL) {
[504]         return;
[505]     }
[506] 
[507]     ngx_rbtree_delete(&c->listening->rbtree, &c->udp->node);
[508] 
[509]     c->udp = NULL;
[510] }
[511] 
[512] 
[513] static ngx_connection_t *
[514] ngx_lookup_udp_connection(ngx_listening_t *ls, struct sockaddr *sockaddr,
[515]     socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
[516] {
[517]     uint32_t               hash;
[518]     ngx_int_t              rc;
[519]     ngx_connection_t      *c;
[520]     ngx_rbtree_node_t     *node, *sentinel;
[521]     ngx_udp_connection_t  *udp;
[522] 
[523] #if (NGX_HAVE_UNIX_DOMAIN)
[524] 
[525]     if (sockaddr->sa_family == AF_UNIX) {
[526]         struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;
[527] 
[528]         if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
[529]             || saun->sun_path[0] == '\0')
[530]         {
[531]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
[532]                            "unbound unix socket");
[533]             return NULL;
[534]         }
[535]     }
[536] 
[537] #endif
[538] 
[539]     node = ls->rbtree.root;
[540]     sentinel = ls->rbtree.sentinel;
[541] 
[542]     ngx_crc32_init(hash);
[543]     ngx_crc32_update(&hash, (u_char *) sockaddr, socklen);
[544] 
[545]     if (ls->wildcard) {
[546]         ngx_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
[547]     }
[548] 
[549]     ngx_crc32_final(hash);
[550] 
[551]     while (node != sentinel) {
[552] 
[553]         if (hash < node->key) {
[554]             node = node->left;
[555]             continue;
[556]         }
[557] 
[558]         if (hash > node->key) {
[559]             node = node->right;
[560]             continue;
[561]         }
[562] 
[563]         /* hash == node->key */
[564] 
[565]         udp = (ngx_udp_connection_t *) node;
[566] 
[567]         c = udp->connection;
[568] 
[569]         rc = ngx_cmp_sockaddr(sockaddr, socklen,
[570]                               c->sockaddr, c->socklen, 1);
[571] 
[572]         if (rc == 0 && ls->wildcard) {
[573]             rc = ngx_cmp_sockaddr(local_sockaddr, local_socklen,
[574]                                   c->local_sockaddr, c->local_socklen, 1);
[575]         }
[576] 
[577]         if (rc == 0) {
[578]             return c;
[579]         }
[580] 
[581]         node = (rc < 0) ? node->left : node->right;
[582]     }
[583] 
[584]     return NULL;
[585] }
[586] 
[587] #else
[588] 
[589] void
[590] ngx_delete_udp_connection(void *data)
[591] {
[592]     return;
[593] }
[594] 
[595] #endif
