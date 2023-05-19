[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] #define ngx_stream_upstream_tries(p) ((p)->tries                              \
[14]                                       + ((p)->next ? (p)->next->tries : 0))
[15] 
[16] 
[17] static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_get_peer(
[18]     ngx_stream_upstream_rr_peer_data_t *rrp);
[19] static void ngx_stream_upstream_notify_round_robin_peer(
[20]     ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
[21] 
[22] #if (NGX_STREAM_SSL)
[23] 
[24] static ngx_int_t ngx_stream_upstream_set_round_robin_peer_session(
[25]     ngx_peer_connection_t *pc, void *data);
[26] static void ngx_stream_upstream_save_round_robin_peer_session(
[27]     ngx_peer_connection_t *pc, void *data);
[28] static ngx_int_t ngx_stream_upstream_empty_set_session(
[29]     ngx_peer_connection_t *pc, void *data);
[30] static void ngx_stream_upstream_empty_save_session(ngx_peer_connection_t *pc,
[31]     void *data);
[32] 
[33] #endif
[34] 
[35] 
[36] ngx_int_t
[37] ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
[38]     ngx_stream_upstream_srv_conf_t *us)
[39] {
[40]     ngx_url_t                        u;
[41]     ngx_uint_t                       i, j, n, w, t;
[42]     ngx_stream_upstream_server_t    *server;
[43]     ngx_stream_upstream_rr_peer_t   *peer, **peerp;
[44]     ngx_stream_upstream_rr_peers_t  *peers, *backup;
[45] 
[46]     us->peer.init = ngx_stream_upstream_init_round_robin_peer;
[47] 
[48]     if (us->servers) {
[49]         server = us->servers->elts;
[50] 
[51]         n = 0;
[52]         w = 0;
[53]         t = 0;
[54] 
[55]         for (i = 0; i < us->servers->nelts; i++) {
[56]             if (server[i].backup) {
[57]                 continue;
[58]             }
[59] 
[60]             n += server[i].naddrs;
[61]             w += server[i].naddrs * server[i].weight;
[62] 
[63]             if (!server[i].down) {
[64]                 t += server[i].naddrs;
[65]             }
[66]         }
[67] 
[68]         if (n == 0) {
[69]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[70]                           "no servers in upstream \"%V\" in %s:%ui",
[71]                           &us->host, us->file_name, us->line);
[72]             return NGX_ERROR;
[73]         }
[74] 
[75]         peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
[76]         if (peers == NULL) {
[77]             return NGX_ERROR;
[78]         }
[79] 
[80]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
[81]         if (peer == NULL) {
[82]             return NGX_ERROR;
[83]         }
[84] 
[85]         peers->single = (n == 1);
[86]         peers->number = n;
[87]         peers->weighted = (w != n);
[88]         peers->total_weight = w;
[89]         peers->tries = t;
[90]         peers->name = &us->host;
[91] 
[92]         n = 0;
[93]         peerp = &peers->peer;
[94] 
[95]         for (i = 0; i < us->servers->nelts; i++) {
[96]             if (server[i].backup) {
[97]                 continue;
[98]             }
[99] 
[100]             for (j = 0; j < server[i].naddrs; j++) {
[101]                 peer[n].sockaddr = server[i].addrs[j].sockaddr;
[102]                 peer[n].socklen = server[i].addrs[j].socklen;
[103]                 peer[n].name = server[i].addrs[j].name;
[104]                 peer[n].weight = server[i].weight;
[105]                 peer[n].effective_weight = server[i].weight;
[106]                 peer[n].current_weight = 0;
[107]                 peer[n].max_conns = server[i].max_conns;
[108]                 peer[n].max_fails = server[i].max_fails;
[109]                 peer[n].fail_timeout = server[i].fail_timeout;
[110]                 peer[n].down = server[i].down;
[111]                 peer[n].server = server[i].name;
[112] 
[113]                 *peerp = &peer[n];
[114]                 peerp = &peer[n].next;
[115]                 n++;
[116]             }
[117]         }
[118] 
[119]         us->peer.data = peers;
[120] 
[121]         /* backup servers */
[122] 
[123]         n = 0;
[124]         w = 0;
[125]         t = 0;
[126] 
[127]         for (i = 0; i < us->servers->nelts; i++) {
[128]             if (!server[i].backup) {
[129]                 continue;
[130]             }
[131] 
[132]             n += server[i].naddrs;
[133]             w += server[i].naddrs * server[i].weight;
[134] 
[135]             if (!server[i].down) {
[136]                 t += server[i].naddrs;
[137]             }
[138]         }
[139] 
[140]         if (n == 0) {
[141]             return NGX_OK;
[142]         }
[143] 
[144]         backup = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
[145]         if (backup == NULL) {
[146]             return NGX_ERROR;
[147]         }
[148] 
[149]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
[150]         if (peer == NULL) {
[151]             return NGX_ERROR;
[152]         }
[153] 
[154]         peers->single = 0;
[155]         backup->single = 0;
[156]         backup->number = n;
[157]         backup->weighted = (w != n);
[158]         backup->total_weight = w;
[159]         backup->tries = t;
[160]         backup->name = &us->host;
[161] 
[162]         n = 0;
[163]         peerp = &backup->peer;
[164] 
[165]         for (i = 0; i < us->servers->nelts; i++) {
[166]             if (!server[i].backup) {
[167]                 continue;
[168]             }
[169] 
[170]             for (j = 0; j < server[i].naddrs; j++) {
[171]                 peer[n].sockaddr = server[i].addrs[j].sockaddr;
[172]                 peer[n].socklen = server[i].addrs[j].socklen;
[173]                 peer[n].name = server[i].addrs[j].name;
[174]                 peer[n].weight = server[i].weight;
[175]                 peer[n].effective_weight = server[i].weight;
[176]                 peer[n].current_weight = 0;
[177]                 peer[n].max_conns = server[i].max_conns;
[178]                 peer[n].max_fails = server[i].max_fails;
[179]                 peer[n].fail_timeout = server[i].fail_timeout;
[180]                 peer[n].down = server[i].down;
[181]                 peer[n].server = server[i].name;
[182] 
[183]                 *peerp = &peer[n];
[184]                 peerp = &peer[n].next;
[185]                 n++;
[186]             }
[187]         }
[188] 
[189]         peers->next = backup;
[190] 
[191]         return NGX_OK;
[192]     }
[193] 
[194] 
[195]     /* an upstream implicitly defined by proxy_pass, etc. */
[196] 
[197]     if (us->port == 0) {
[198]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[199]                       "no port in upstream \"%V\" in %s:%ui",
[200]                       &us->host, us->file_name, us->line);
[201]         return NGX_ERROR;
[202]     }
[203] 
[204]     ngx_memzero(&u, sizeof(ngx_url_t));
[205] 
[206]     u.host = us->host;
[207]     u.port = us->port;
[208] 
[209]     if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
[210]         if (u.err) {
[211]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[212]                           "%s in upstream \"%V\" in %s:%ui",
[213]                           u.err, &us->host, us->file_name, us->line);
[214]         }
[215] 
[216]         return NGX_ERROR;
[217]     }
[218] 
[219]     n = u.naddrs;
[220] 
[221]     peers = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peers_t));
[222]     if (peers == NULL) {
[223]         return NGX_ERROR;
[224]     }
[225] 
[226]     peer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_rr_peer_t) * n);
[227]     if (peer == NULL) {
[228]         return NGX_ERROR;
[229]     }
[230] 
[231]     peers->single = (n == 1);
[232]     peers->number = n;
[233]     peers->weighted = 0;
[234]     peers->total_weight = n;
[235]     peers->tries = n;
[236]     peers->name = &us->host;
[237] 
[238]     peerp = &peers->peer;
[239] 
[240]     for (i = 0; i < u.naddrs; i++) {
[241]         peer[i].sockaddr = u.addrs[i].sockaddr;
[242]         peer[i].socklen = u.addrs[i].socklen;
[243]         peer[i].name = u.addrs[i].name;
[244]         peer[i].weight = 1;
[245]         peer[i].effective_weight = 1;
[246]         peer[i].current_weight = 0;
[247]         peer[i].max_conns = 0;
[248]         peer[i].max_fails = 1;
[249]         peer[i].fail_timeout = 10;
[250]         *peerp = &peer[i];
[251]         peerp = &peer[i].next;
[252]     }
[253] 
[254]     us->peer.data = peers;
[255] 
[256]     /* implicitly defined upstream has no backup servers */
[257] 
[258]     return NGX_OK;
[259] }
[260] 
[261] 
[262] ngx_int_t
[263] ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
[264]     ngx_stream_upstream_srv_conf_t *us)
[265] {
[266]     ngx_uint_t                           n;
[267]     ngx_stream_upstream_rr_peer_data_t  *rrp;
[268] 
[269]     rrp = s->upstream->peer.data;
[270] 
[271]     if (rrp == NULL) {
[272]         rrp = ngx_palloc(s->connection->pool,
[273]                          sizeof(ngx_stream_upstream_rr_peer_data_t));
[274]         if (rrp == NULL) {
[275]             return NGX_ERROR;
[276]         }
[277] 
[278]         s->upstream->peer.data = rrp;
[279]     }
[280] 
[281]     rrp->peers = us->peer.data;
[282]     rrp->current = NULL;
[283]     rrp->config = 0;
[284] 
[285]     n = rrp->peers->number;
[286] 
[287]     if (rrp->peers->next && rrp->peers->next->number > n) {
[288]         n = rrp->peers->next->number;
[289]     }
[290] 
[291]     if (n <= 8 * sizeof(uintptr_t)) {
[292]         rrp->tried = &rrp->data;
[293]         rrp->data = 0;
[294] 
[295]     } else {
[296]         n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));
[297] 
[298]         rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
[299]         if (rrp->tried == NULL) {
[300]             return NGX_ERROR;
[301]         }
[302]     }
[303] 
[304]     s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
[305]     s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
[306]     s->upstream->peer.notify = ngx_stream_upstream_notify_round_robin_peer;
[307]     s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);
[308] #if (NGX_STREAM_SSL)
[309]     s->upstream->peer.set_session =
[310]                              ngx_stream_upstream_set_round_robin_peer_session;
[311]     s->upstream->peer.save_session =
[312]                              ngx_stream_upstream_save_round_robin_peer_session;
[313] #endif
[314] 
[315]     return NGX_OK;
[316] }
[317] 
[318] 
[319] ngx_int_t
[320] ngx_stream_upstream_create_round_robin_peer(ngx_stream_session_t *s,
[321]     ngx_stream_upstream_resolved_t *ur)
[322] {
[323]     u_char                              *p;
[324]     size_t                               len;
[325]     socklen_t                            socklen;
[326]     ngx_uint_t                           i, n;
[327]     struct sockaddr                     *sockaddr;
[328]     ngx_stream_upstream_rr_peer_t       *peer, **peerp;
[329]     ngx_stream_upstream_rr_peers_t      *peers;
[330]     ngx_stream_upstream_rr_peer_data_t  *rrp;
[331] 
[332]     rrp = s->upstream->peer.data;
[333] 
[334]     if (rrp == NULL) {
[335]         rrp = ngx_palloc(s->connection->pool,
[336]                          sizeof(ngx_stream_upstream_rr_peer_data_t));
[337]         if (rrp == NULL) {
[338]             return NGX_ERROR;
[339]         }
[340] 
[341]         s->upstream->peer.data = rrp;
[342]     }
[343] 
[344]     peers = ngx_pcalloc(s->connection->pool,
[345]                         sizeof(ngx_stream_upstream_rr_peers_t));
[346]     if (peers == NULL) {
[347]         return NGX_ERROR;
[348]     }
[349] 
[350]     peer = ngx_pcalloc(s->connection->pool,
[351]                        sizeof(ngx_stream_upstream_rr_peer_t) * ur->naddrs);
[352]     if (peer == NULL) {
[353]         return NGX_ERROR;
[354]     }
[355] 
[356]     peers->single = (ur->naddrs == 1);
[357]     peers->number = ur->naddrs;
[358]     peers->tries = ur->naddrs;
[359]     peers->name = &ur->host;
[360] 
[361]     if (ur->sockaddr) {
[362]         peer[0].sockaddr = ur->sockaddr;
[363]         peer[0].socklen = ur->socklen;
[364]         peer[0].name = ur->name;
[365]         peer[0].weight = 1;
[366]         peer[0].effective_weight = 1;
[367]         peer[0].current_weight = 0;
[368]         peer[0].max_conns = 0;
[369]         peer[0].max_fails = 1;
[370]         peer[0].fail_timeout = 10;
[371]         peers->peer = peer;
[372] 
[373]     } else {
[374]         peerp = &peers->peer;
[375] 
[376]         for (i = 0; i < ur->naddrs; i++) {
[377] 
[378]             socklen = ur->addrs[i].socklen;
[379] 
[380]             sockaddr = ngx_palloc(s->connection->pool, socklen);
[381]             if (sockaddr == NULL) {
[382]                 return NGX_ERROR;
[383]             }
[384] 
[385]             ngx_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);
[386]             ngx_inet_set_port(sockaddr, ur->port);
[387] 
[388]             p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
[389]             if (p == NULL) {
[390]                 return NGX_ERROR;
[391]             }
[392] 
[393]             len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);
[394] 
[395]             peer[i].sockaddr = sockaddr;
[396]             peer[i].socklen = socklen;
[397]             peer[i].name.len = len;
[398]             peer[i].name.data = p;
[399]             peer[i].weight = 1;
[400]             peer[i].effective_weight = 1;
[401]             peer[i].current_weight = 0;
[402]             peer[i].max_conns = 0;
[403]             peer[i].max_fails = 1;
[404]             peer[i].fail_timeout = 10;
[405]             *peerp = &peer[i];
[406]             peerp = &peer[i].next;
[407]         }
[408]     }
[409] 
[410]     rrp->peers = peers;
[411]     rrp->current = NULL;
[412]     rrp->config = 0;
[413] 
[414]     if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
[415]         rrp->tried = &rrp->data;
[416]         rrp->data = 0;
[417] 
[418]     } else {
[419]         n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
[420]                 / (8 * sizeof(uintptr_t));
[421] 
[422]         rrp->tried = ngx_pcalloc(s->connection->pool, n * sizeof(uintptr_t));
[423]         if (rrp->tried == NULL) {
[424]             return NGX_ERROR;
[425]         }
[426]     }
[427] 
[428]     s->upstream->peer.get = ngx_stream_upstream_get_round_robin_peer;
[429]     s->upstream->peer.free = ngx_stream_upstream_free_round_robin_peer;
[430]     s->upstream->peer.tries = ngx_stream_upstream_tries(rrp->peers);
[431] #if (NGX_STREAM_SSL)
[432]     s->upstream->peer.set_session = ngx_stream_upstream_empty_set_session;
[433]     s->upstream->peer.save_session = ngx_stream_upstream_empty_save_session;
[434] #endif
[435] 
[436]     return NGX_OK;
[437] }
[438] 
[439] 
[440] ngx_int_t
[441] ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
[442] {
[443]     ngx_stream_upstream_rr_peer_data_t *rrp = data;
[444] 
[445]     ngx_int_t                        rc;
[446]     ngx_uint_t                       i, n;
[447]     ngx_stream_upstream_rr_peer_t   *peer;
[448]     ngx_stream_upstream_rr_peers_t  *peers;
[449] 
[450]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[451]                    "get rr peer, try: %ui", pc->tries);
[452] 
[453]     pc->connection = NULL;
[454] 
[455]     peers = rrp->peers;
[456]     ngx_stream_upstream_rr_peers_wlock(peers);
[457] 
[458]     if (peers->single) {
[459]         peer = peers->peer;
[460] 
[461]         if (peer->down) {
[462]             goto failed;
[463]         }
[464] 
[465]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[466]             goto failed;
[467]         }
[468] 
[469]         rrp->current = peer;
[470] 
[471]     } else {
[472] 
[473]         /* there are several peers */
[474] 
[475]         peer = ngx_stream_upstream_get_peer(rrp);
[476] 
[477]         if (peer == NULL) {
[478]             goto failed;
[479]         }
[480] 
[481]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[482]                        "get rr peer, current: %p %i",
[483]                        peer, peer->current_weight);
[484]     }
[485] 
[486]     pc->sockaddr = peer->sockaddr;
[487]     pc->socklen = peer->socklen;
[488]     pc->name = &peer->name;
[489] 
[490]     peer->conns++;
[491] 
[492]     ngx_stream_upstream_rr_peers_unlock(peers);
[493] 
[494]     return NGX_OK;
[495] 
[496] failed:
[497] 
[498]     if (peers->next) {
[499] 
[500]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "backup servers");
[501] 
[502]         rrp->peers = peers->next;
[503] 
[504]         n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
[505]                 / (8 * sizeof(uintptr_t));
[506] 
[507]         for (i = 0; i < n; i++) {
[508]             rrp->tried[i] = 0;
[509]         }
[510] 
[511]         ngx_stream_upstream_rr_peers_unlock(peers);
[512] 
[513]         rc = ngx_stream_upstream_get_round_robin_peer(pc, rrp);
[514] 
[515]         if (rc != NGX_BUSY) {
[516]             return rc;
[517]         }
[518] 
[519]         ngx_stream_upstream_rr_peers_wlock(peers);
[520]     }
[521] 
[522]     ngx_stream_upstream_rr_peers_unlock(peers);
[523] 
[524]     pc->name = peers->name;
[525] 
[526]     return NGX_BUSY;
[527] }
[528] 
[529] 
[530] static ngx_stream_upstream_rr_peer_t *
[531] ngx_stream_upstream_get_peer(ngx_stream_upstream_rr_peer_data_t *rrp)
[532] {
[533]     time_t                          now;
[534]     uintptr_t                       m;
[535]     ngx_int_t                       total;
[536]     ngx_uint_t                      i, n, p;
[537]     ngx_stream_upstream_rr_peer_t  *peer, *best;
[538] 
[539]     now = ngx_time();
[540] 
[541]     best = NULL;
[542]     total = 0;
[543] 
[544] #if (NGX_SUPPRESS_WARN)
[545]     p = 0;
[546] #endif
[547] 
[548]     for (peer = rrp->peers->peer, i = 0;
[549]          peer;
[550]          peer = peer->next, i++)
[551]     {
[552]         n = i / (8 * sizeof(uintptr_t));
[553]         m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[554] 
[555]         if (rrp->tried[n] & m) {
[556]             continue;
[557]         }
[558] 
[559]         if (peer->down) {
[560]             continue;
[561]         }
[562] 
[563]         if (peer->max_fails
[564]             && peer->fails >= peer->max_fails
[565]             && now - peer->checked <= peer->fail_timeout)
[566]         {
[567]             continue;
[568]         }
[569] 
[570]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[571]             continue;
[572]         }
[573] 
[574]         peer->current_weight += peer->effective_weight;
[575]         total += peer->effective_weight;
[576] 
[577]         if (peer->effective_weight < peer->weight) {
[578]             peer->effective_weight++;
[579]         }
[580] 
[581]         if (best == NULL || peer->current_weight > best->current_weight) {
[582]             best = peer;
[583]             p = i;
[584]         }
[585]     }
[586] 
[587]     if (best == NULL) {
[588]         return NULL;
[589]     }
[590] 
[591]     rrp->current = best;
[592] 
[593]     n = p / (8 * sizeof(uintptr_t));
[594]     m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[595] 
[596]     rrp->tried[n] |= m;
[597] 
[598]     best->current_weight -= total;
[599] 
[600]     if (now - best->checked > best->fail_timeout) {
[601]         best->checked = now;
[602]     }
[603] 
[604]     return best;
[605] }
[606] 
[607] 
[608] void
[609] ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
[610]     ngx_uint_t state)
[611] {
[612]     ngx_stream_upstream_rr_peer_data_t  *rrp = data;
[613] 
[614]     time_t                          now;
[615]     ngx_stream_upstream_rr_peer_t  *peer;
[616] 
[617]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[618]                    "free rr peer %ui %ui", pc->tries, state);
[619] 
[620]     peer = rrp->current;
[621] 
[622]     ngx_stream_upstream_rr_peers_rlock(rrp->peers);
[623]     ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);
[624] 
[625]     if (rrp->peers->single) {
[626]         peer->conns--;
[627] 
[628]         ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
[629]         ngx_stream_upstream_rr_peers_unlock(rrp->peers);
[630] 
[631]         pc->tries = 0;
[632]         return;
[633]     }
[634] 
[635]     if (state & NGX_PEER_FAILED) {
[636]         now = ngx_time();
[637] 
[638]         peer->fails++;
[639]         peer->accessed = now;
[640]         peer->checked = now;
[641] 
[642]         if (peer->max_fails) {
[643]             peer->effective_weight -= peer->weight / peer->max_fails;
[644] 
[645]             if (peer->fails >= peer->max_fails) {
[646]                 ngx_log_error(NGX_LOG_WARN, pc->log, 0,
[647]                               "upstream server temporarily disabled");
[648]             }
[649]         }
[650] 
[651]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[652]                        "free rr peer failed: %p %i",
[653]                        peer, peer->effective_weight);
[654] 
[655]         if (peer->effective_weight < 0) {
[656]             peer->effective_weight = 0;
[657]         }
[658] 
[659]     } else {
[660] 
[661]         /* mark peer live if check passed */
[662] 
[663]         if (peer->accessed < peer->checked) {
[664]             peer->fails = 0;
[665]         }
[666]     }
[667] 
[668]     peer->conns--;
[669] 
[670]     ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
[671]     ngx_stream_upstream_rr_peers_unlock(rrp->peers);
[672] 
[673]     if (pc->tries) {
[674]         pc->tries--;
[675]     }
[676] }
[677] 
[678] 
[679] static void
[680] ngx_stream_upstream_notify_round_robin_peer(ngx_peer_connection_t *pc,
[681]     void *data, ngx_uint_t type)
[682] {
[683]     ngx_stream_upstream_rr_peer_data_t  *rrp = data;
[684] 
[685]     ngx_stream_upstream_rr_peer_t  *peer;
[686] 
[687]     peer = rrp->current;
[688] 
[689]     if (type == NGX_STREAM_UPSTREAM_NOTIFY_CONNECT
[690]         && pc->connection->type == SOCK_STREAM)
[691]     {
[692]         ngx_stream_upstream_rr_peers_rlock(rrp->peers);
[693]         ngx_stream_upstream_rr_peer_lock(rrp->peers, peer);
[694] 
[695]         if (peer->accessed < peer->checked) {
[696]             peer->fails = 0;
[697]         }
[698] 
[699]         ngx_stream_upstream_rr_peer_unlock(rrp->peers, peer);
[700]         ngx_stream_upstream_rr_peers_unlock(rrp->peers);
[701]     }
[702] }
[703] 
[704] 
[705] #if (NGX_STREAM_SSL)
[706] 
[707] static ngx_int_t
[708] ngx_stream_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
[709]     void *data)
[710] {
[711]     ngx_stream_upstream_rr_peer_data_t  *rrp = data;
[712] 
[713]     ngx_int_t                        rc;
[714]     ngx_ssl_session_t               *ssl_session;
[715]     ngx_stream_upstream_rr_peer_t   *peer;
[716] #if (NGX_STREAM_UPSTREAM_ZONE)
[717]     int                              len;
[718]     const u_char                    *p;
[719]     ngx_stream_upstream_rr_peers_t  *peers;
[720]     u_char                           buf[NGX_SSL_MAX_SESSION_SIZE];
[721] #endif
[722] 
[723]     peer = rrp->current;
[724] 
[725] #if (NGX_STREAM_UPSTREAM_ZONE)
[726]     peers = rrp->peers;
[727] 
[728]     if (peers->shpool) {
[729]         ngx_stream_upstream_rr_peers_rlock(peers);
[730]         ngx_stream_upstream_rr_peer_lock(peers, peer);
[731] 
[732]         if (peer->ssl_session == NULL) {
[733]             ngx_stream_upstream_rr_peer_unlock(peers, peer);
[734]             ngx_stream_upstream_rr_peers_unlock(peers);
[735]             return NGX_OK;
[736]         }
[737] 
[738]         len = peer->ssl_session_len;
[739] 
[740]         ngx_memcpy(buf, peer->ssl_session, len);
[741] 
[742]         ngx_stream_upstream_rr_peer_unlock(peers, peer);
[743]         ngx_stream_upstream_rr_peers_unlock(peers);
[744] 
[745]         p = buf;
[746]         ssl_session = d2i_SSL_SESSION(NULL, &p, len);
[747] 
[748]         rc = ngx_ssl_set_session(pc->connection, ssl_session);
[749] 
[750]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[751]                        "set session: %p", ssl_session);
[752] 
[753]         ngx_ssl_free_session(ssl_session);
[754] 
[755]         return rc;
[756]     }
[757] #endif
[758] 
[759]     ssl_session = peer->ssl_session;
[760] 
[761]     rc = ngx_ssl_set_session(pc->connection, ssl_session);
[762] 
[763]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[764]                    "set session: %p", ssl_session);
[765] 
[766]     return rc;
[767] }
[768] 
[769] 
[770] static void
[771] ngx_stream_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
[772]     void *data)
[773] {
[774]     ngx_stream_upstream_rr_peer_data_t  *rrp = data;
[775] 
[776]     ngx_ssl_session_t               *old_ssl_session, *ssl_session;
[777]     ngx_stream_upstream_rr_peer_t   *peer;
[778] #if (NGX_STREAM_UPSTREAM_ZONE)
[779]     int                              len;
[780]     u_char                          *p;
[781]     ngx_stream_upstream_rr_peers_t  *peers;
[782]     u_char                           buf[NGX_SSL_MAX_SESSION_SIZE];
[783] #endif
[784] 
[785] #if (NGX_STREAM_UPSTREAM_ZONE)
[786]     peers = rrp->peers;
[787] 
[788]     if (peers->shpool) {
[789] 
[790]         ssl_session = ngx_ssl_get0_session(pc->connection);
[791] 
[792]         if (ssl_session == NULL) {
[793]             return;
[794]         }
[795] 
[796]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[797]                        "save session: %p", ssl_session);
[798] 
[799]         len = i2d_SSL_SESSION(ssl_session, NULL);
[800] 
[801]         /* do not cache too big session */
[802] 
[803]         if (len > NGX_SSL_MAX_SESSION_SIZE) {
[804]             return;
[805]         }
[806] 
[807]         p = buf;
[808]         (void) i2d_SSL_SESSION(ssl_session, &p);
[809] 
[810]         peer = rrp->current;
[811] 
[812]         ngx_stream_upstream_rr_peers_rlock(peers);
[813]         ngx_stream_upstream_rr_peer_lock(peers, peer);
[814] 
[815]         if (len > peer->ssl_session_len) {
[816]             ngx_shmtx_lock(&peers->shpool->mutex);
[817] 
[818]             if (peer->ssl_session) {
[819]                 ngx_slab_free_locked(peers->shpool, peer->ssl_session);
[820]             }
[821] 
[822]             peer->ssl_session = ngx_slab_alloc_locked(peers->shpool, len);
[823] 
[824]             ngx_shmtx_unlock(&peers->shpool->mutex);
[825] 
[826]             if (peer->ssl_session == NULL) {
[827]                 peer->ssl_session_len = 0;
[828] 
[829]                 ngx_stream_upstream_rr_peer_unlock(peers, peer);
[830]                 ngx_stream_upstream_rr_peers_unlock(peers);
[831]                 return;
[832]             }
[833] 
[834]             peer->ssl_session_len = len;
[835]         }
[836] 
[837]         ngx_memcpy(peer->ssl_session, buf, len);
[838] 
[839]         ngx_stream_upstream_rr_peer_unlock(peers, peer);
[840]         ngx_stream_upstream_rr_peers_unlock(peers);
[841] 
[842]         return;
[843]     }
[844] #endif
[845] 
[846]     ssl_session = ngx_ssl_get_session(pc->connection);
[847] 
[848]     if (ssl_session == NULL) {
[849]         return;
[850]     }
[851] 
[852]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[853]                    "save session: %p", ssl_session);
[854] 
[855]     peer = rrp->current;
[856] 
[857]     old_ssl_session = peer->ssl_session;
[858]     peer->ssl_session = ssl_session;
[859] 
[860]     if (old_ssl_session) {
[861] 
[862]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[863]                        "old session: %p", old_ssl_session);
[864] 
[865]         /* TODO: may block */
[866] 
[867]         ngx_ssl_free_session(old_ssl_session);
[868]     }
[869] }
[870] 
[871] 
[872] static ngx_int_t
[873] ngx_stream_upstream_empty_set_session(ngx_peer_connection_t *pc, void *data)
[874] {
[875]     return NGX_OK;
[876] }
[877] 
[878] 
[879] static void
[880] ngx_stream_upstream_empty_save_session(ngx_peer_connection_t *pc, void *data)
[881] {
[882]     return;
[883] }
[884] 
[885] #endif
