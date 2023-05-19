[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] typedef struct {
[14]     uint32_t                              hash;
[15]     ngx_str_t                            *server;
[16] } ngx_stream_upstream_chash_point_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_uint_t                            number;
[21]     ngx_stream_upstream_chash_point_t     point[1];
[22] } ngx_stream_upstream_chash_points_t;
[23] 
[24] 
[25] typedef struct {
[26]     ngx_stream_complex_value_t            key;
[27]     ngx_stream_upstream_chash_points_t   *points;
[28] } ngx_stream_upstream_hash_srv_conf_t;
[29] 
[30] 
[31] typedef struct {
[32]     /* the round robin data must be first */
[33]     ngx_stream_upstream_rr_peer_data_t    rrp;
[34]     ngx_stream_upstream_hash_srv_conf_t  *conf;
[35]     ngx_str_t                             key;
[36]     ngx_uint_t                            tries;
[37]     ngx_uint_t                            rehash;
[38]     uint32_t                              hash;
[39]     ngx_event_get_peer_pt                 get_rr_peer;
[40] } ngx_stream_upstream_hash_peer_data_t;
[41] 
[42] 
[43] static ngx_int_t ngx_stream_upstream_init_hash(ngx_conf_t *cf,
[44]     ngx_stream_upstream_srv_conf_t *us);
[45] static ngx_int_t ngx_stream_upstream_init_hash_peer(ngx_stream_session_t *s,
[46]     ngx_stream_upstream_srv_conf_t *us);
[47] static ngx_int_t ngx_stream_upstream_get_hash_peer(ngx_peer_connection_t *pc,
[48]     void *data);
[49] 
[50] static ngx_int_t ngx_stream_upstream_init_chash(ngx_conf_t *cf,
[51]     ngx_stream_upstream_srv_conf_t *us);
[52] static int ngx_libc_cdecl
[53]     ngx_stream_upstream_chash_cmp_points(const void *one, const void *two);
[54] static ngx_uint_t ngx_stream_upstream_find_chash_point(
[55]     ngx_stream_upstream_chash_points_t *points, uint32_t hash);
[56] static ngx_int_t ngx_stream_upstream_init_chash_peer(ngx_stream_session_t *s,
[57]     ngx_stream_upstream_srv_conf_t *us);
[58] static ngx_int_t ngx_stream_upstream_get_chash_peer(ngx_peer_connection_t *pc,
[59]     void *data);
[60] 
[61] static void *ngx_stream_upstream_hash_create_conf(ngx_conf_t *cf);
[62] static char *ngx_stream_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd,
[63]     void *conf);
[64] 
[65] 
[66] static ngx_command_t  ngx_stream_upstream_hash_commands[] = {
[67] 
[68]     { ngx_string("hash"),
[69]       NGX_STREAM_UPS_CONF|NGX_CONF_TAKE12,
[70]       ngx_stream_upstream_hash,
[71]       NGX_STREAM_SRV_CONF_OFFSET,
[72]       0,
[73]       NULL },
[74] 
[75]       ngx_null_command
[76] };
[77] 
[78] 
[79] static ngx_stream_module_t  ngx_stream_upstream_hash_module_ctx = {
[80]     NULL,                                  /* preconfiguration */
[81]     NULL,                                  /* postconfiguration */
[82] 
[83]     NULL,                                  /* create main configuration */
[84]     NULL,                                  /* init main configuration */
[85] 
[86]     ngx_stream_upstream_hash_create_conf,  /* create server configuration */
[87]     NULL                                   /* merge server configuration */
[88] };
[89] 
[90] 
[91] ngx_module_t  ngx_stream_upstream_hash_module = {
[92]     NGX_MODULE_V1,
[93]     &ngx_stream_upstream_hash_module_ctx,  /* module context */
[94]     ngx_stream_upstream_hash_commands,     /* module directives */
[95]     NGX_STREAM_MODULE,                     /* module type */
[96]     NULL,                                  /* init master */
[97]     NULL,                                  /* init module */
[98]     NULL,                                  /* init process */
[99]     NULL,                                  /* init thread */
[100]     NULL,                                  /* exit thread */
[101]     NULL,                                  /* exit process */
[102]     NULL,                                  /* exit master */
[103]     NGX_MODULE_V1_PADDING
[104] };
[105] 
[106] 
[107] static ngx_int_t
[108] ngx_stream_upstream_init_hash(ngx_conf_t *cf,
[109]     ngx_stream_upstream_srv_conf_t *us)
[110] {
[111]     if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
[112]         return NGX_ERROR;
[113]     }
[114] 
[115]     us->peer.init = ngx_stream_upstream_init_hash_peer;
[116] 
[117]     return NGX_OK;
[118] }
[119] 
[120] 
[121] static ngx_int_t
[122] ngx_stream_upstream_init_hash_peer(ngx_stream_session_t *s,
[123]     ngx_stream_upstream_srv_conf_t *us)
[124] {
[125]     ngx_stream_upstream_hash_srv_conf_t   *hcf;
[126]     ngx_stream_upstream_hash_peer_data_t  *hp;
[127] 
[128]     hp = ngx_palloc(s->connection->pool,
[129]                     sizeof(ngx_stream_upstream_hash_peer_data_t));
[130]     if (hp == NULL) {
[131]         return NGX_ERROR;
[132]     }
[133] 
[134]     s->upstream->peer.data = &hp->rrp;
[135] 
[136]     if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
[137]         return NGX_ERROR;
[138]     }
[139] 
[140]     s->upstream->peer.get = ngx_stream_upstream_get_hash_peer;
[141] 
[142]     hcf = ngx_stream_conf_upstream_srv_conf(us,
[143]                                             ngx_stream_upstream_hash_module);
[144] 
[145]     if (ngx_stream_complex_value(s, &hcf->key, &hp->key) != NGX_OK) {
[146]         return NGX_ERROR;
[147]     }
[148] 
[149]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[150]                    "upstream hash key:\"%V\"", &hp->key);
[151] 
[152]     hp->conf = hcf;
[153]     hp->tries = 0;
[154]     hp->rehash = 0;
[155]     hp->hash = 0;
[156]     hp->get_rr_peer = ngx_stream_upstream_get_round_robin_peer;
[157] 
[158]     return NGX_OK;
[159] }
[160] 
[161] 
[162] static ngx_int_t
[163] ngx_stream_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data)
[164] {
[165]     ngx_stream_upstream_hash_peer_data_t *hp = data;
[166] 
[167]     time_t                          now;
[168]     u_char                          buf[NGX_INT_T_LEN];
[169]     size_t                          size;
[170]     uint32_t                        hash;
[171]     ngx_int_t                       w;
[172]     uintptr_t                       m;
[173]     ngx_uint_t                      n, p;
[174]     ngx_stream_upstream_rr_peer_t  *peer;
[175] 
[176]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[177]                    "get hash peer, try: %ui", pc->tries);
[178] 
[179]     ngx_stream_upstream_rr_peers_rlock(hp->rrp.peers);
[180] 
[181]     if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
[182]         ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[183]         return hp->get_rr_peer(pc, &hp->rrp);
[184]     }
[185] 
[186]     now = ngx_time();
[187] 
[188]     pc->connection = NULL;
[189] 
[190]     for ( ;; ) {
[191] 
[192]         /*
[193]          * Hash expression is compatible with Cache::Memcached:
[194]          * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
[195]          * with REHASH omitted at the first iteration.
[196]          */
[197] 
[198]         ngx_crc32_init(hash);
[199] 
[200]         if (hp->rehash > 0) {
[201]             size = ngx_sprintf(buf, "%ui", hp->rehash) - buf;
[202]             ngx_crc32_update(&hash, buf, size);
[203]         }
[204] 
[205]         ngx_crc32_update(&hash, hp->key.data, hp->key.len);
[206]         ngx_crc32_final(hash);
[207] 
[208]         hash = (hash >> 16) & 0x7fff;
[209] 
[210]         hp->hash += hash;
[211]         hp->rehash++;
[212] 
[213]         w = hp->hash % hp->rrp.peers->total_weight;
[214]         peer = hp->rrp.peers->peer;
[215]         p = 0;
[216] 
[217]         while (w >= peer->weight) {
[218]             w -= peer->weight;
[219]             peer = peer->next;
[220]             p++;
[221]         }
[222] 
[223]         n = p / (8 * sizeof(uintptr_t));
[224]         m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[225] 
[226]         if (hp->rrp.tried[n] & m) {
[227]             goto next;
[228]         }
[229] 
[230]         ngx_stream_upstream_rr_peer_lock(hp->rrp.peers, peer);
[231] 
[232]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[233]                        "get hash peer, value:%uD, peer:%ui", hp->hash, p);
[234] 
[235]         if (peer->down) {
[236]             ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[237]             goto next;
[238]         }
[239] 
[240]         if (peer->max_fails
[241]             && peer->fails >= peer->max_fails
[242]             && now - peer->checked <= peer->fail_timeout)
[243]         {
[244]             ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[245]             goto next;
[246]         }
[247] 
[248]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[249]             ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[250]             goto next;
[251]         }
[252] 
[253]         break;
[254] 
[255]     next:
[256] 
[257]         if (++hp->tries > 20) {
[258]             ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[259]             return hp->get_rr_peer(pc, &hp->rrp);
[260]         }
[261]     }
[262] 
[263]     hp->rrp.current = peer;
[264] 
[265]     pc->sockaddr = peer->sockaddr;
[266]     pc->socklen = peer->socklen;
[267]     pc->name = &peer->name;
[268] 
[269]     peer->conns++;
[270] 
[271]     if (now - peer->checked > peer->fail_timeout) {
[272]         peer->checked = now;
[273]     }
[274] 
[275]     ngx_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[276]     ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[277] 
[278]     hp->rrp.tried[n] |= m;
[279] 
[280]     return NGX_OK;
[281] }
[282] 
[283] 
[284] static ngx_int_t
[285] ngx_stream_upstream_init_chash(ngx_conf_t *cf,
[286]     ngx_stream_upstream_srv_conf_t *us)
[287] {
[288]     u_char                               *host, *port, c;
[289]     size_t                                host_len, port_len, size;
[290]     uint32_t                              hash, base_hash;
[291]     ngx_str_t                            *server;
[292]     ngx_uint_t                            npoints, i, j;
[293]     ngx_stream_upstream_rr_peer_t        *peer;
[294]     ngx_stream_upstream_rr_peers_t       *peers;
[295]     ngx_stream_upstream_chash_points_t   *points;
[296]     ngx_stream_upstream_hash_srv_conf_t  *hcf;
[297]     union {
[298]         uint32_t                          value;
[299]         u_char                            byte[4];
[300]     } prev_hash;
[301] 
[302]     if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
[303]         return NGX_ERROR;
[304]     }
[305] 
[306]     us->peer.init = ngx_stream_upstream_init_chash_peer;
[307] 
[308]     peers = us->peer.data;
[309]     npoints = peers->total_weight * 160;
[310] 
[311]     size = sizeof(ngx_stream_upstream_chash_points_t)
[312]            + sizeof(ngx_stream_upstream_chash_point_t) * (npoints - 1);
[313] 
[314]     points = ngx_palloc(cf->pool, size);
[315]     if (points == NULL) {
[316]         return NGX_ERROR;
[317]     }
[318] 
[319]     points->number = 0;
[320] 
[321]     for (peer = peers->peer; peer; peer = peer->next) {
[322]         server = &peer->server;
[323] 
[324]         /*
[325]          * Hash expression is compatible with Cache::Memcached::Fast:
[326]          * crc32(HOST \0 PORT PREV_HASH).
[327]          */
[328] 
[329]         if (server->len >= 5
[330]             && ngx_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
[331]         {
[332]             host = server->data + 5;
[333]             host_len = server->len - 5;
[334]             port = NULL;
[335]             port_len = 0;
[336]             goto done;
[337]         }
[338] 
[339]         for (j = 0; j < server->len; j++) {
[340]             c = server->data[server->len - j - 1];
[341] 
[342]             if (c == ':') {
[343]                 host = server->data;
[344]                 host_len = server->len - j - 1;
[345]                 port = server->data + server->len - j;
[346]                 port_len = j;
[347]                 goto done;
[348]             }
[349] 
[350]             if (c < '0' || c > '9') {
[351]                 break;
[352]             }
[353]         }
[354] 
[355]         host = server->data;
[356]         host_len = server->len;
[357]         port = NULL;
[358]         port_len = 0;
[359] 
[360]     done:
[361] 
[362]         ngx_crc32_init(base_hash);
[363]         ngx_crc32_update(&base_hash, host, host_len);
[364]         ngx_crc32_update(&base_hash, (u_char *) "", 1);
[365]         ngx_crc32_update(&base_hash, port, port_len);
[366] 
[367]         prev_hash.value = 0;
[368]         npoints = peer->weight * 160;
[369] 
[370]         for (j = 0; j < npoints; j++) {
[371]             hash = base_hash;
[372] 
[373]             ngx_crc32_update(&hash, prev_hash.byte, 4);
[374]             ngx_crc32_final(hash);
[375] 
[376]             points->point[points->number].hash = hash;
[377]             points->point[points->number].server = server;
[378]             points->number++;
[379] 
[380] #if (NGX_HAVE_LITTLE_ENDIAN)
[381]             prev_hash.value = hash;
[382] #else
[383]             prev_hash.byte[0] = (u_char) (hash & 0xff);
[384]             prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
[385]             prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
[386]             prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
[387] #endif
[388]         }
[389]     }
[390] 
[391]     ngx_qsort(points->point,
[392]               points->number,
[393]               sizeof(ngx_stream_upstream_chash_point_t),
[394]               ngx_stream_upstream_chash_cmp_points);
[395] 
[396]     for (i = 0, j = 1; j < points->number; j++) {
[397]         if (points->point[i].hash != points->point[j].hash) {
[398]             points->point[++i] = points->point[j];
[399]         }
[400]     }
[401] 
[402]     points->number = i + 1;
[403] 
[404]     hcf = ngx_stream_conf_upstream_srv_conf(us,
[405]                                             ngx_stream_upstream_hash_module);
[406]     hcf->points = points;
[407] 
[408]     return NGX_OK;
[409] }
[410] 
[411] 
[412] static int ngx_libc_cdecl
[413] ngx_stream_upstream_chash_cmp_points(const void *one, const void *two)
[414] {
[415]     ngx_stream_upstream_chash_point_t *first =
[416]                                      (ngx_stream_upstream_chash_point_t *) one;
[417]     ngx_stream_upstream_chash_point_t *second =
[418]                                      (ngx_stream_upstream_chash_point_t *) two;
[419] 
[420]     if (first->hash < second->hash) {
[421]         return -1;
[422] 
[423]     } else if (first->hash > second->hash) {
[424]         return 1;
[425] 
[426]     } else {
[427]         return 0;
[428]     }
[429] }
[430] 
[431] 
[432] static ngx_uint_t
[433] ngx_stream_upstream_find_chash_point(ngx_stream_upstream_chash_points_t *points,
[434]     uint32_t hash)
[435] {
[436]     ngx_uint_t                          i, j, k;
[437]     ngx_stream_upstream_chash_point_t  *point;
[438] 
[439]     /* find first point >= hash */
[440] 
[441]     point = &points->point[0];
[442] 
[443]     i = 0;
[444]     j = points->number;
[445] 
[446]     while (i < j) {
[447]         k = (i + j) / 2;
[448] 
[449]         if (hash > point[k].hash) {
[450]             i = k + 1;
[451] 
[452]         } else if (hash < point[k].hash) {
[453]             j = k;
[454] 
[455]         } else {
[456]             return k;
[457]         }
[458]     }
[459] 
[460]     return i;
[461] }
[462] 
[463] 
[464] static ngx_int_t
[465] ngx_stream_upstream_init_chash_peer(ngx_stream_session_t *s,
[466]     ngx_stream_upstream_srv_conf_t *us)
[467] {
[468]     uint32_t                               hash;
[469]     ngx_stream_upstream_hash_srv_conf_t   *hcf;
[470]     ngx_stream_upstream_hash_peer_data_t  *hp;
[471] 
[472]     if (ngx_stream_upstream_init_hash_peer(s, us) != NGX_OK) {
[473]         return NGX_ERROR;
[474]     }
[475] 
[476]     s->upstream->peer.get = ngx_stream_upstream_get_chash_peer;
[477] 
[478]     hp = s->upstream->peer.data;
[479]     hcf = ngx_stream_conf_upstream_srv_conf(us,
[480]                                             ngx_stream_upstream_hash_module);
[481] 
[482]     hash = ngx_crc32_long(hp->key.data, hp->key.len);
[483] 
[484]     ngx_stream_upstream_rr_peers_rlock(hp->rrp.peers);
[485] 
[486]     hp->hash = ngx_stream_upstream_find_chash_point(hcf->points, hash);
[487] 
[488]     ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[489] 
[490]     return NGX_OK;
[491] }
[492] 
[493] 
[494] static ngx_int_t
[495] ngx_stream_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data)
[496] {
[497]     ngx_stream_upstream_hash_peer_data_t *hp = data;
[498] 
[499]     time_t                                now;
[500]     intptr_t                              m;
[501]     ngx_str_t                            *server;
[502]     ngx_int_t                             total;
[503]     ngx_uint_t                            i, n, best_i;
[504]     ngx_stream_upstream_rr_peer_t        *peer, *best;
[505]     ngx_stream_upstream_chash_point_t    *point;
[506]     ngx_stream_upstream_chash_points_t   *points;
[507]     ngx_stream_upstream_hash_srv_conf_t  *hcf;
[508] 
[509]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[510]                    "get consistent hash peer, try: %ui", pc->tries);
[511] 
[512]     ngx_stream_upstream_rr_peers_wlock(hp->rrp.peers);
[513] 
[514]     if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
[515]         ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[516]         return hp->get_rr_peer(pc, &hp->rrp);
[517]     }
[518] 
[519]     pc->connection = NULL;
[520] 
[521]     now = ngx_time();
[522]     hcf = hp->conf;
[523] 
[524]     points = hcf->points;
[525]     point = &points->point[0];
[526] 
[527]     for ( ;; ) {
[528]         server = point[hp->hash % points->number].server;
[529] 
[530]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[531]                        "consistent hash peer:%uD, server:\"%V\"",
[532]                        hp->hash, server);
[533] 
[534]         best = NULL;
[535]         best_i = 0;
[536]         total = 0;
[537] 
[538]         for (peer = hp->rrp.peers->peer, i = 0;
[539]              peer;
[540]              peer = peer->next, i++)
[541]         {
[542]             n = i / (8 * sizeof(uintptr_t));
[543]             m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[544] 
[545]             if (hp->rrp.tried[n] & m) {
[546]                 continue;
[547]             }
[548] 
[549]             if (peer->down) {
[550]                 continue;
[551]             }
[552] 
[553]             if (peer->max_fails
[554]                 && peer->fails >= peer->max_fails
[555]                 && now - peer->checked <= peer->fail_timeout)
[556]             {
[557]                 continue;
[558]             }
[559] 
[560]             if (peer->max_conns && peer->conns >= peer->max_conns) {
[561]                 continue;
[562]             }
[563] 
[564]             if (peer->server.len != server->len
[565]                 || ngx_strncmp(peer->server.data, server->data, server->len)
[566]                    != 0)
[567]             {
[568]                 continue;
[569]             }
[570] 
[571]             peer->current_weight += peer->effective_weight;
[572]             total += peer->effective_weight;
[573] 
[574]             if (peer->effective_weight < peer->weight) {
[575]                 peer->effective_weight++;
[576]             }
[577] 
[578]             if (best == NULL || peer->current_weight > best->current_weight) {
[579]                 best = peer;
[580]                 best_i = i;
[581]             }
[582]         }
[583] 
[584]         if (best) {
[585]             best->current_weight -= total;
[586]             break;
[587]         }
[588] 
[589]         hp->hash++;
[590]         hp->tries++;
[591] 
[592]         if (hp->tries > 20) {
[593]             ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[594]             return hp->get_rr_peer(pc, &hp->rrp);
[595]         }
[596]     }
[597] 
[598]     hp->rrp.current = best;
[599] 
[600]     pc->sockaddr = best->sockaddr;
[601]     pc->socklen = best->socklen;
[602]     pc->name = &best->name;
[603] 
[604]     best->conns++;
[605] 
[606]     if (now - best->checked > best->fail_timeout) {
[607]         best->checked = now;
[608]     }
[609] 
[610]     ngx_stream_upstream_rr_peers_unlock(hp->rrp.peers);
[611] 
[612]     n = best_i / (8 * sizeof(uintptr_t));
[613]     m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));
[614] 
[615]     hp->rrp.tried[n] |= m;
[616] 
[617]     return NGX_OK;
[618] }
[619] 
[620] 
[621] static void *
[622] ngx_stream_upstream_hash_create_conf(ngx_conf_t *cf)
[623] {
[624]     ngx_stream_upstream_hash_srv_conf_t  *conf;
[625] 
[626]     conf = ngx_palloc(cf->pool, sizeof(ngx_stream_upstream_hash_srv_conf_t));
[627]     if (conf == NULL) {
[628]         return NULL;
[629]     }
[630] 
[631]     conf->points = NULL;
[632] 
[633]     return conf;
[634] }
[635] 
[636] 
[637] static char *
[638] ngx_stream_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[639] {
[640]     ngx_stream_upstream_hash_srv_conf_t  *hcf = conf;
[641] 
[642]     ngx_str_t                           *value;
[643]     ngx_stream_upstream_srv_conf_t      *uscf;
[644]     ngx_stream_compile_complex_value_t   ccv;
[645] 
[646]     value = cf->args->elts;
[647] 
[648]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[649] 
[650]     ccv.cf = cf;
[651]     ccv.value = &value[1];
[652]     ccv.complex_value = &hcf->key;
[653] 
[654]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[655]         return NGX_CONF_ERROR;
[656]     }
[657] 
[658]     uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);
[659] 
[660]     if (uscf->peer.init_upstream) {
[661]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[662]                            "load balancing method redefined");
[663]     }
[664] 
[665]     uscf->flags = NGX_STREAM_UPSTREAM_CREATE
[666]                   |NGX_STREAM_UPSTREAM_WEIGHT
[667]                   |NGX_STREAM_UPSTREAM_MAX_CONNS
[668]                   |NGX_STREAM_UPSTREAM_MAX_FAILS
[669]                   |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
[670]                   |NGX_STREAM_UPSTREAM_DOWN;
[671] 
[672]     if (cf->args->nelts == 2) {
[673]         uscf->peer.init_upstream = ngx_stream_upstream_init_hash;
[674] 
[675]     } else if (ngx_strcmp(value[2].data, "consistent") == 0) {
[676]         uscf->peer.init_upstream = ngx_stream_upstream_init_chash;
[677] 
[678]     } else {
[679]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[680]                            "invalid parameter \"%V\"", &value[2]);
[681]         return NGX_CONF_ERROR;
[682]     }
[683] 
[684]     return NGX_CONF_OK;
[685] }
