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
[13] #define ngx_http_upstream_tries(p) ((p)->tries                                \
[14]                                     + ((p)->next ? (p)->next->tries : 0))
[15] 
[16] 
[17] static ngx_http_upstream_rr_peer_t *ngx_http_upstream_get_peer(
[18]     ngx_http_upstream_rr_peer_data_t *rrp);
[19] 
[20] #if (NGX_HTTP_SSL)
[21] 
[22] static ngx_int_t ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc,
[23]     void *data);
[24] static void ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc,
[25]     void *data);
[26] 
[27] #endif
[28] 
[29] 
[30] ngx_int_t
[31] ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
[32]     ngx_http_upstream_srv_conf_t *us)
[33] {
[34]     ngx_url_t                      u;
[35]     ngx_uint_t                     i, j, n, w, t;
[36]     ngx_http_upstream_server_t    *server;
[37]     ngx_http_upstream_rr_peer_t   *peer, **peerp;
[38]     ngx_http_upstream_rr_peers_t  *peers, *backup;
[39] 
[40]     us->peer.init = ngx_http_upstream_init_round_robin_peer;
[41] 
[42]     if (us->servers) {
[43]         server = us->servers->elts;
[44] 
[45]         n = 0;
[46]         w = 0;
[47]         t = 0;
[48] 
[49]         for (i = 0; i < us->servers->nelts; i++) {
[50]             if (server[i].backup) {
[51]                 continue;
[52]             }
[53] 
[54]             n += server[i].naddrs;
[55]             w += server[i].naddrs * server[i].weight;
[56] 
[57]             if (!server[i].down) {
[58]                 t += server[i].naddrs;
[59]             }
[60]         }
[61] 
[62]         if (n == 0) {
[63]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[64]                           "no servers in upstream \"%V\" in %s:%ui",
[65]                           &us->host, us->file_name, us->line);
[66]             return NGX_ERROR;
[67]         }
[68] 
[69]         peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
[70]         if (peers == NULL) {
[71]             return NGX_ERROR;
[72]         }
[73] 
[74]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t) * n);
[75]         if (peer == NULL) {
[76]             return NGX_ERROR;
[77]         }
[78] 
[79]         peers->single = (n == 1);
[80]         peers->number = n;
[81]         peers->weighted = (w != n);
[82]         peers->total_weight = w;
[83]         peers->tries = t;
[84]         peers->name = &us->host;
[85] 
[86]         n = 0;
[87]         peerp = &peers->peer;
[88] 
[89]         for (i = 0; i < us->servers->nelts; i++) {
[90]             if (server[i].backup) {
[91]                 continue;
[92]             }
[93] 
[94]             for (j = 0; j < server[i].naddrs; j++) {
[95]                 peer[n].sockaddr = server[i].addrs[j].sockaddr;
[96]                 peer[n].socklen = server[i].addrs[j].socklen;
[97]                 peer[n].name = server[i].addrs[j].name;
[98]                 peer[n].weight = server[i].weight;
[99]                 peer[n].effective_weight = server[i].weight;
[100]                 peer[n].current_weight = 0;
[101]                 peer[n].max_conns = server[i].max_conns;
[102]                 peer[n].max_fails = server[i].max_fails;
[103]                 peer[n].fail_timeout = server[i].fail_timeout;
[104]                 peer[n].down = server[i].down;
[105]                 peer[n].server = server[i].name;
[106] 
[107]                 *peerp = &peer[n];
[108]                 peerp = &peer[n].next;
[109]                 n++;
[110]             }
[111]         }
[112] 
[113]         us->peer.data = peers;
[114] 
[115]         /* backup servers */
[116] 
[117]         n = 0;
[118]         w = 0;
[119]         t = 0;
[120] 
[121]         for (i = 0; i < us->servers->nelts; i++) {
[122]             if (!server[i].backup) {
[123]                 continue;
[124]             }
[125] 
[126]             n += server[i].naddrs;
[127]             w += server[i].naddrs * server[i].weight;
[128] 
[129]             if (!server[i].down) {
[130]                 t += server[i].naddrs;
[131]             }
[132]         }
[133] 
[134]         if (n == 0) {
[135]             return NGX_OK;
[136]         }
[137] 
[138]         backup = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
[139]         if (backup == NULL) {
[140]             return NGX_ERROR;
[141]         }
[142] 
[143]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t) * n);
[144]         if (peer == NULL) {
[145]             return NGX_ERROR;
[146]         }
[147] 
[148]         peers->single = 0;
[149]         backup->single = 0;
[150]         backup->number = n;
[151]         backup->weighted = (w != n);
[152]         backup->total_weight = w;
[153]         backup->tries = t;
[154]         backup->name = &us->host;
[155] 
[156]         n = 0;
[157]         peerp = &backup->peer;
[158] 
[159]         for (i = 0; i < us->servers->nelts; i++) {
[160]             if (!server[i].backup) {
[161]                 continue;
[162]             }
[163] 
[164]             for (j = 0; j < server[i].naddrs; j++) {
[165]                 peer[n].sockaddr = server[i].addrs[j].sockaddr;
[166]                 peer[n].socklen = server[i].addrs[j].socklen;
[167]                 peer[n].name = server[i].addrs[j].name;
[168]                 peer[n].weight = server[i].weight;
[169]                 peer[n].effective_weight = server[i].weight;
[170]                 peer[n].current_weight = 0;
[171]                 peer[n].max_conns = server[i].max_conns;
[172]                 peer[n].max_fails = server[i].max_fails;
[173]                 peer[n].fail_timeout = server[i].fail_timeout;
[174]                 peer[n].down = server[i].down;
[175]                 peer[n].server = server[i].name;
[176] 
[177]                 *peerp = &peer[n];
[178]                 peerp = &peer[n].next;
[179]                 n++;
[180]             }
[181]         }
[182] 
[183]         peers->next = backup;
[184] 
[185]         return NGX_OK;
[186]     }
[187] 
[188] 
[189]     /* an upstream implicitly defined by proxy_pass, etc. */
[190] 
[191]     if (us->port == 0) {
[192]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[193]                       "no port in upstream \"%V\" in %s:%ui",
[194]                       &us->host, us->file_name, us->line);
[195]         return NGX_ERROR;
[196]     }
[197] 
[198]     ngx_memzero(&u, sizeof(ngx_url_t));
[199] 
[200]     u.host = us->host;
[201]     u.port = us->port;
[202] 
[203]     if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
[204]         if (u.err) {
[205]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[206]                           "%s in upstream \"%V\" in %s:%ui",
[207]                           u.err, &us->host, us->file_name, us->line);
[208]         }
[209] 
[210]         return NGX_ERROR;
[211]     }
[212] 
[213]     n = u.naddrs;
[214] 
[215]     peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peers_t));
[216]     if (peers == NULL) {
[217]         return NGX_ERROR;
[218]     }
[219] 
[220]     peer = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_rr_peer_t) * n);
[221]     if (peer == NULL) {
[222]         return NGX_ERROR;
[223]     }
[224] 
[225]     peers->single = (n == 1);
[226]     peers->number = n;
[227]     peers->weighted = 0;
[228]     peers->total_weight = n;
[229]     peers->tries = n;
[230]     peers->name = &us->host;
[231] 
[232]     peerp = &peers->peer;
[233] 
[234]     for (i = 0; i < u.naddrs; i++) {
[235]         peer[i].sockaddr = u.addrs[i].sockaddr;
[236]         peer[i].socklen = u.addrs[i].socklen;
[237]         peer[i].name = u.addrs[i].name;
[238]         peer[i].weight = 1;
[239]         peer[i].effective_weight = 1;
[240]         peer[i].current_weight = 0;
[241]         peer[i].max_conns = 0;
[242]         peer[i].max_fails = 1;
[243]         peer[i].fail_timeout = 10;
[244]         *peerp = &peer[i];
[245]         peerp = &peer[i].next;
[246]     }
[247] 
[248]     us->peer.data = peers;
[249] 
[250]     /* implicitly defined upstream has no backup servers */
[251] 
[252]     return NGX_OK;
[253] }
[254] 
[255] 
[256] ngx_int_t
[257] ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
[258]     ngx_http_upstream_srv_conf_t *us)
[259] {
[260]     ngx_uint_t                         n;
[261]     ngx_http_upstream_rr_peer_data_t  *rrp;
[262] 
[263]     rrp = r->upstream->peer.data;
[264] 
[265]     if (rrp == NULL) {
[266]         rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
[267]         if (rrp == NULL) {
[268]             return NGX_ERROR;
[269]         }
[270] 
[271]         r->upstream->peer.data = rrp;
[272]     }
[273] 
[274]     rrp->peers = us->peer.data;
[275]     rrp->current = NULL;
[276]     rrp->config = 0;
[277] 
[278]     n = rrp->peers->number;
[279] 
[280]     if (rrp->peers->next && rrp->peers->next->number > n) {
[281]         n = rrp->peers->next->number;
[282]     }
[283] 
[284]     if (n <= 8 * sizeof(uintptr_t)) {
[285]         rrp->tried = &rrp->data;
[286]         rrp->data = 0;
[287] 
[288]     } else {
[289]         n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));
[290] 
[291]         rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
[292]         if (rrp->tried == NULL) {
[293]             return NGX_ERROR;
[294]         }
[295]     }
[296] 
[297]     r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
[298]     r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
[299]     r->upstream->peer.tries = ngx_http_upstream_tries(rrp->peers);
[300] #if (NGX_HTTP_SSL)
[301]     r->upstream->peer.set_session =
[302]                                ngx_http_upstream_set_round_robin_peer_session;
[303]     r->upstream->peer.save_session =
[304]                                ngx_http_upstream_save_round_robin_peer_session;
[305] #endif
[306] 
[307]     return NGX_OK;
[308] }
[309] 
[310] 
[311] ngx_int_t
[312] ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
[313]     ngx_http_upstream_resolved_t *ur)
[314] {
[315]     u_char                            *p;
[316]     size_t                             len;
[317]     socklen_t                          socklen;
[318]     ngx_uint_t                         i, n;
[319]     struct sockaddr                   *sockaddr;
[320]     ngx_http_upstream_rr_peer_t       *peer, **peerp;
[321]     ngx_http_upstream_rr_peers_t      *peers;
[322]     ngx_http_upstream_rr_peer_data_t  *rrp;
[323] 
[324]     rrp = r->upstream->peer.data;
[325] 
[326]     if (rrp == NULL) {
[327]         rrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_peer_data_t));
[328]         if (rrp == NULL) {
[329]             return NGX_ERROR;
[330]         }
[331] 
[332]         r->upstream->peer.data = rrp;
[333]     }
[334] 
[335]     peers = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_rr_peers_t));
[336]     if (peers == NULL) {
[337]         return NGX_ERROR;
[338]     }
[339] 
[340]     peer = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_rr_peer_t)
[341]                                 * ur->naddrs);
[342]     if (peer == NULL) {
[343]         return NGX_ERROR;
[344]     }
[345] 
[346]     peers->single = (ur->naddrs == 1);
[347]     peers->number = ur->naddrs;
[348]     peers->tries = ur->naddrs;
[349]     peers->name = &ur->host;
[350] 
[351]     if (ur->sockaddr) {
[352]         peer[0].sockaddr = ur->sockaddr;
[353]         peer[0].socklen = ur->socklen;
[354]         peer[0].name = ur->name.data ? ur->name : ur->host;
[355]         peer[0].weight = 1;
[356]         peer[0].effective_weight = 1;
[357]         peer[0].current_weight = 0;
[358]         peer[0].max_conns = 0;
[359]         peer[0].max_fails = 1;
[360]         peer[0].fail_timeout = 10;
[361]         peers->peer = peer;
[362] 
[363]     } else {
[364]         peerp = &peers->peer;
[365] 
[366]         for (i = 0; i < ur->naddrs; i++) {
[367] 
[368]             socklen = ur->addrs[i].socklen;
[369] 
[370]             sockaddr = ngx_palloc(r->pool, socklen);
[371]             if (sockaddr == NULL) {
[372]                 return NGX_ERROR;
[373]             }
[374] 
[375]             ngx_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);
[376]             ngx_inet_set_port(sockaddr, ur->port);
[377] 
[378]             p = ngx_pnalloc(r->pool, NGX_SOCKADDR_STRLEN);
[379]             if (p == NULL) {
[380]                 return NGX_ERROR;
[381]             }
[382] 
[383]             len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);
[384] 
[385]             peer[i].sockaddr = sockaddr;
[386]             peer[i].socklen = socklen;
[387]             peer[i].name.len = len;
[388]             peer[i].name.data = p;
[389]             peer[i].weight = 1;
[390]             peer[i].effective_weight = 1;
[391]             peer[i].current_weight = 0;
[392]             peer[i].max_conns = 0;
[393]             peer[i].max_fails = 1;
[394]             peer[i].fail_timeout = 10;
[395]             *peerp = &peer[i];
[396]             peerp = &peer[i].next;
[397]         }
[398]     }
[399] 
[400]     rrp->peers = peers;
[401]     rrp->current = NULL;
[402]     rrp->config = 0;
[403] 
[404]     if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
[405]         rrp->tried = &rrp->data;
[406]         rrp->data = 0;
[407] 
[408]     } else {
[409]         n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
[410]                 / (8 * sizeof(uintptr_t));
[411] 
[412]         rrp->tried = ngx_pcalloc(r->pool, n * sizeof(uintptr_t));
[413]         if (rrp->tried == NULL) {
[414]             return NGX_ERROR;
[415]         }
[416]     }
[417] 
[418]     r->upstream->peer.get = ngx_http_upstream_get_round_robin_peer;
[419]     r->upstream->peer.free = ngx_http_upstream_free_round_robin_peer;
[420]     r->upstream->peer.tries = ngx_http_upstream_tries(rrp->peers);
[421] #if (NGX_HTTP_SSL)
[422]     r->upstream->peer.set_session = ngx_http_upstream_empty_set_session;
[423]     r->upstream->peer.save_session = ngx_http_upstream_empty_save_session;
[424] #endif
[425] 
[426]     return NGX_OK;
[427] }
[428] 
[429] 
[430] ngx_int_t
[431] ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
[432] {
[433]     ngx_http_upstream_rr_peer_data_t  *rrp = data;
[434] 
[435]     ngx_int_t                      rc;
[436]     ngx_uint_t                     i, n;
[437]     ngx_http_upstream_rr_peer_t   *peer;
[438]     ngx_http_upstream_rr_peers_t  *peers;
[439] 
[440]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[441]                    "get rr peer, try: %ui", pc->tries);
[442] 
[443]     pc->cached = 0;
[444]     pc->connection = NULL;
[445] 
[446]     peers = rrp->peers;
[447]     ngx_http_upstream_rr_peers_wlock(peers);
[448] 
[449]     if (peers->single) {
[450]         peer = peers->peer;
[451] 
[452]         if (peer->down) {
[453]             goto failed;
[454]         }
[455] 
[456]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[457]             goto failed;
[458]         }
[459] 
[460]         rrp->current = peer;
[461] 
[462]     } else {
[463] 
[464]         /* there are several peers */
[465] 
[466]         peer = ngx_http_upstream_get_peer(rrp);
[467] 
[468]         if (peer == NULL) {
[469]             goto failed;
[470]         }
[471] 
[472]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[473]                        "get rr peer, current: %p %i",
[474]                        peer, peer->current_weight);
[475]     }
[476] 
[477]     pc->sockaddr = peer->sockaddr;
[478]     pc->socklen = peer->socklen;
[479]     pc->name = &peer->name;
[480] 
[481]     peer->conns++;
[482] 
[483]     ngx_http_upstream_rr_peers_unlock(peers);
[484] 
[485]     return NGX_OK;
[486] 
[487] failed:
[488] 
[489]     if (peers->next) {
[490] 
[491]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "backup servers");
[492] 
[493]         rrp->peers = peers->next;
[494] 
[495]         n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
[496]                 / (8 * sizeof(uintptr_t));
[497] 
[498]         for (i = 0; i < n; i++) {
[499]             rrp->tried[i] = 0;
[500]         }
[501] 
[502]         ngx_http_upstream_rr_peers_unlock(peers);
[503] 
[504]         rc = ngx_http_upstream_get_round_robin_peer(pc, rrp);
[505] 
[506]         if (rc != NGX_BUSY) {
[507]             return rc;
[508]         }
[509] 
[510]         ngx_http_upstream_rr_peers_wlock(peers);
[511]     }
[512] 
[513]     ngx_http_upstream_rr_peers_unlock(peers);
[514] 
[515]     pc->name = peers->name;
[516] 
[517]     return NGX_BUSY;
[518] }
[519] 
[520] 
[521] static ngx_http_upstream_rr_peer_t *
[522] ngx_http_upstream_get_peer(ngx_http_upstream_rr_peer_data_t *rrp)
[523] {
[524]     time_t                        now;
[525]     uintptr_t                     m;
[526]     ngx_int_t                     total;
[527]     ngx_uint_t                    i, n, p;
[528]     ngx_http_upstream_rr_peer_t  *peer, *best;
[529] 
[530]     now = ngx_time();
[531] 
[532]     best = NULL;
[533]     total = 0;
[534] 
[535] #if (NGX_SUPPRESS_WARN)
[536]     p = 0;
[537] #endif
[538] 
[539]     for (peer = rrp->peers->peer, i = 0;
[540]          peer;
[541]          peer = peer->next, i++)
[542]     {
[543]         n = i / (8 * sizeof(uintptr_t));
[544]         m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[545] 
[546]         if (rrp->tried[n] & m) {
[547]             continue;
[548]         }
[549] 
[550]         if (peer->down) {
[551]             continue;
[552]         }
[553] 
[554]         if (peer->max_fails
[555]             && peer->fails >= peer->max_fails
[556]             && now - peer->checked <= peer->fail_timeout)
[557]         {
[558]             continue;
[559]         }
[560] 
[561]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[562]             continue;
[563]         }
[564] 
[565]         peer->current_weight += peer->effective_weight;
[566]         total += peer->effective_weight;
[567] 
[568]         if (peer->effective_weight < peer->weight) {
[569]             peer->effective_weight++;
[570]         }
[571] 
[572]         if (best == NULL || peer->current_weight > best->current_weight) {
[573]             best = peer;
[574]             p = i;
[575]         }
[576]     }
[577] 
[578]     if (best == NULL) {
[579]         return NULL;
[580]     }
[581] 
[582]     rrp->current = best;
[583] 
[584]     n = p / (8 * sizeof(uintptr_t));
[585]     m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[586] 
[587]     rrp->tried[n] |= m;
[588] 
[589]     best->current_weight -= total;
[590] 
[591]     if (now - best->checked > best->fail_timeout) {
[592]         best->checked = now;
[593]     }
[594] 
[595]     return best;
[596] }
[597] 
[598] 
[599] void
[600] ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
[601]     ngx_uint_t state)
[602] {
[603]     ngx_http_upstream_rr_peer_data_t  *rrp = data;
[604] 
[605]     time_t                       now;
[606]     ngx_http_upstream_rr_peer_t  *peer;
[607] 
[608]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[609]                    "free rr peer %ui %ui", pc->tries, state);
[610] 
[611]     /* TODO: NGX_PEER_KEEPALIVE */
[612] 
[613]     peer = rrp->current;
[614] 
[615]     ngx_http_upstream_rr_peers_rlock(rrp->peers);
[616]     ngx_http_upstream_rr_peer_lock(rrp->peers, peer);
[617] 
[618]     if (rrp->peers->single) {
[619] 
[620]         peer->conns--;
[621] 
[622]         ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
[623]         ngx_http_upstream_rr_peers_unlock(rrp->peers);
[624] 
[625]         pc->tries = 0;
[626]         return;
[627]     }
[628] 
[629]     if (state & NGX_PEER_FAILED) {
[630]         now = ngx_time();
[631] 
[632]         peer->fails++;
[633]         peer->accessed = now;
[634]         peer->checked = now;
[635] 
[636]         if (peer->max_fails) {
[637]             peer->effective_weight -= peer->weight / peer->max_fails;
[638] 
[639]             if (peer->fails >= peer->max_fails) {
[640]                 ngx_log_error(NGX_LOG_WARN, pc->log, 0,
[641]                               "upstream server temporarily disabled");
[642]             }
[643]         }
[644] 
[645]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[646]                        "free rr peer failed: %p %i",
[647]                        peer, peer->effective_weight);
[648] 
[649]         if (peer->effective_weight < 0) {
[650]             peer->effective_weight = 0;
[651]         }
[652] 
[653]     } else {
[654] 
[655]         /* mark peer live if check passed */
[656] 
[657]         if (peer->accessed < peer->checked) {
[658]             peer->fails = 0;
[659]         }
[660]     }
[661] 
[662]     peer->conns--;
[663] 
[664]     ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
[665]     ngx_http_upstream_rr_peers_unlock(rrp->peers);
[666] 
[667]     if (pc->tries) {
[668]         pc->tries--;
[669]     }
[670] }
[671] 
[672] 
[673] #if (NGX_HTTP_SSL)
[674] 
[675] ngx_int_t
[676] ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
[677]     void *data)
[678] {
[679]     ngx_http_upstream_rr_peer_data_t  *rrp = data;
[680] 
[681]     ngx_int_t                      rc;
[682]     ngx_ssl_session_t             *ssl_session;
[683]     ngx_http_upstream_rr_peer_t   *peer;
[684] #if (NGX_HTTP_UPSTREAM_ZONE)
[685]     int                            len;
[686]     const u_char                  *p;
[687]     ngx_http_upstream_rr_peers_t  *peers;
[688]     u_char                         buf[NGX_SSL_MAX_SESSION_SIZE];
[689] #endif
[690] 
[691]     peer = rrp->current;
[692] 
[693] #if (NGX_HTTP_UPSTREAM_ZONE)
[694]     peers = rrp->peers;
[695] 
[696]     if (peers->shpool) {
[697]         ngx_http_upstream_rr_peers_rlock(peers);
[698]         ngx_http_upstream_rr_peer_lock(peers, peer);
[699] 
[700]         if (peer->ssl_session == NULL) {
[701]             ngx_http_upstream_rr_peer_unlock(peers, peer);
[702]             ngx_http_upstream_rr_peers_unlock(peers);
[703]             return NGX_OK;
[704]         }
[705] 
[706]         len = peer->ssl_session_len;
[707] 
[708]         ngx_memcpy(buf, peer->ssl_session, len);
[709] 
[710]         ngx_http_upstream_rr_peer_unlock(peers, peer);
[711]         ngx_http_upstream_rr_peers_unlock(peers);
[712] 
[713]         p = buf;
[714]         ssl_session = d2i_SSL_SESSION(NULL, &p, len);
[715] 
[716]         rc = ngx_ssl_set_session(pc->connection, ssl_session);
[717] 
[718]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[719]                        "set session: %p", ssl_session);
[720] 
[721]         ngx_ssl_free_session(ssl_session);
[722] 
[723]         return rc;
[724]     }
[725] #endif
[726] 
[727]     ssl_session = peer->ssl_session;
[728] 
[729]     rc = ngx_ssl_set_session(pc->connection, ssl_session);
[730] 
[731]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[732]                    "set session: %p", ssl_session);
[733] 
[734]     return rc;
[735] }
[736] 
[737] 
[738] void
[739] ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
[740]     void *data)
[741] {
[742]     ngx_http_upstream_rr_peer_data_t  *rrp = data;
[743] 
[744]     ngx_ssl_session_t             *old_ssl_session, *ssl_session;
[745]     ngx_http_upstream_rr_peer_t   *peer;
[746] #if (NGX_HTTP_UPSTREAM_ZONE)
[747]     int                            len;
[748]     u_char                        *p;
[749]     ngx_http_upstream_rr_peers_t  *peers;
[750]     u_char                         buf[NGX_SSL_MAX_SESSION_SIZE];
[751] #endif
[752] 
[753] #if (NGX_HTTP_UPSTREAM_ZONE)
[754]     peers = rrp->peers;
[755] 
[756]     if (peers->shpool) {
[757] 
[758]         ssl_session = ngx_ssl_get0_session(pc->connection);
[759] 
[760]         if (ssl_session == NULL) {
[761]             return;
[762]         }
[763] 
[764]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[765]                        "save session: %p", ssl_session);
[766] 
[767]         len = i2d_SSL_SESSION(ssl_session, NULL);
[768] 
[769]         /* do not cache too big session */
[770] 
[771]         if (len > NGX_SSL_MAX_SESSION_SIZE) {
[772]             return;
[773]         }
[774] 
[775]         p = buf;
[776]         (void) i2d_SSL_SESSION(ssl_session, &p);
[777] 
[778]         peer = rrp->current;
[779] 
[780]         ngx_http_upstream_rr_peers_rlock(peers);
[781]         ngx_http_upstream_rr_peer_lock(peers, peer);
[782] 
[783]         if (len > peer->ssl_session_len) {
[784]             ngx_shmtx_lock(&peers->shpool->mutex);
[785] 
[786]             if (peer->ssl_session) {
[787]                 ngx_slab_free_locked(peers->shpool, peer->ssl_session);
[788]             }
[789] 
[790]             peer->ssl_session = ngx_slab_alloc_locked(peers->shpool, len);
[791] 
[792]             ngx_shmtx_unlock(&peers->shpool->mutex);
[793] 
[794]             if (peer->ssl_session == NULL) {
[795]                 peer->ssl_session_len = 0;
[796] 
[797]                 ngx_http_upstream_rr_peer_unlock(peers, peer);
[798]                 ngx_http_upstream_rr_peers_unlock(peers);
[799]                 return;
[800]             }
[801] 
[802]             peer->ssl_session_len = len;
[803]         }
[804] 
[805]         ngx_memcpy(peer->ssl_session, buf, len);
[806] 
[807]         ngx_http_upstream_rr_peer_unlock(peers, peer);
[808]         ngx_http_upstream_rr_peers_unlock(peers);
[809] 
[810]         return;
[811]     }
[812] #endif
[813] 
[814]     ssl_session = ngx_ssl_get_session(pc->connection);
[815] 
[816]     if (ssl_session == NULL) {
[817]         return;
[818]     }
[819] 
[820]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[821]                    "save session: %p", ssl_session);
[822] 
[823]     peer = rrp->current;
[824] 
[825]     old_ssl_session = peer->ssl_session;
[826]     peer->ssl_session = ssl_session;
[827] 
[828]     if (old_ssl_session) {
[829] 
[830]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[831]                        "old session: %p", old_ssl_session);
[832] 
[833]         /* TODO: may block */
[834] 
[835]         ngx_ssl_free_session(old_ssl_session);
[836]     }
[837] }
[838] 
[839] 
[840] static ngx_int_t
[841] ngx_http_upstream_empty_set_session(ngx_peer_connection_t *pc, void *data)
[842] {
[843]     return NGX_OK;
[844] }
[845] 
[846] 
[847] static void
[848] ngx_http_upstream_empty_save_session(ngx_peer_connection_t *pc, void *data)
[849] {
[850]     return;
[851] }
[852] 
[853] #endif
