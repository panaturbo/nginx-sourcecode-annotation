[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] typedef struct {
[14]     uint32_t                            hash;
[15]     ngx_str_t                          *server;
[16] } ngx_http_upstream_chash_point_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_uint_t                          number;
[21]     ngx_http_upstream_chash_point_t     point[1];
[22] } ngx_http_upstream_chash_points_t;
[23] 
[24] 
[25] typedef struct {
[26]     ngx_http_complex_value_t            key;
[27]     ngx_http_upstream_chash_points_t   *points;
[28] } ngx_http_upstream_hash_srv_conf_t;
[29] 
[30] 
[31] typedef struct {
[32]     /* the round robin data must be first */
[33]     ngx_http_upstream_rr_peer_data_t    rrp;
[34]     ngx_http_upstream_hash_srv_conf_t  *conf;
[35]     ngx_str_t                           key;
[36]     ngx_uint_t                          tries;
[37]     ngx_uint_t                          rehash;
[38]     uint32_t                            hash;
[39]     ngx_event_get_peer_pt               get_rr_peer;
[40] } ngx_http_upstream_hash_peer_data_t;
[41] 
[42] 
[43] static ngx_int_t ngx_http_upstream_init_hash(ngx_conf_t *cf,
[44]     ngx_http_upstream_srv_conf_t *us);
[45] static ngx_int_t ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
[46]     ngx_http_upstream_srv_conf_t *us);
[47] static ngx_int_t ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc,
[48]     void *data);
[49] 
[50] static ngx_int_t ngx_http_upstream_init_chash(ngx_conf_t *cf,
[51]     ngx_http_upstream_srv_conf_t *us);
[52] static int ngx_libc_cdecl
[53]     ngx_http_upstream_chash_cmp_points(const void *one, const void *two);
[54] static ngx_uint_t ngx_http_upstream_find_chash_point(
[55]     ngx_http_upstream_chash_points_t *points, uint32_t hash);
[56] static ngx_int_t ngx_http_upstream_init_chash_peer(ngx_http_request_t *r,
[57]     ngx_http_upstream_srv_conf_t *us);
[58] static ngx_int_t ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc,
[59]     void *data);
[60] 
[61] static void *ngx_http_upstream_hash_create_conf(ngx_conf_t *cf);
[62] static char *ngx_http_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd,
[63]     void *conf);
[64] 
[65] 
[66] static ngx_command_t  ngx_http_upstream_hash_commands[] = {
[67] 
[68]     { ngx_string("hash"),
[69]       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
[70]       ngx_http_upstream_hash,
[71]       NGX_HTTP_SRV_CONF_OFFSET,
[72]       0,
[73]       NULL },
[74] 
[75]       ngx_null_command
[76] };
[77] 
[78] 
[79] static ngx_http_module_t  ngx_http_upstream_hash_module_ctx = {
[80]     NULL,                                  /* preconfiguration */
[81]     NULL,                                  /* postconfiguration */
[82] 
[83]     NULL,                                  /* create main configuration */
[84]     NULL,                                  /* init main configuration */
[85] 
[86]     ngx_http_upstream_hash_create_conf,    /* create server configuration */
[87]     NULL,                                  /* merge server configuration */
[88] 
[89]     NULL,                                  /* create location configuration */
[90]     NULL                                   /* merge location configuration */
[91] };
[92] 
[93] 
[94] ngx_module_t  ngx_http_upstream_hash_module = {
[95]     NGX_MODULE_V1,
[96]     &ngx_http_upstream_hash_module_ctx,    /* module context */
[97]     ngx_http_upstream_hash_commands,       /* module directives */
[98]     NGX_HTTP_MODULE,                       /* module type */
[99]     NULL,                                  /* init master */
[100]     NULL,                                  /* init module */
[101]     NULL,                                  /* init process */
[102]     NULL,                                  /* init thread */
[103]     NULL,                                  /* exit thread */
[104]     NULL,                                  /* exit process */
[105]     NULL,                                  /* exit master */
[106]     NGX_MODULE_V1_PADDING
[107] };
[108] 
[109] 
[110] static ngx_int_t
[111] ngx_http_upstream_init_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
[112] {
[113]     if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
[114]         return NGX_ERROR;
[115]     }
[116] 
[117]     us->peer.init = ngx_http_upstream_init_hash_peer;
[118] 
[119]     return NGX_OK;
[120] }
[121] 
[122] 
[123] static ngx_int_t
[124] ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
[125]     ngx_http_upstream_srv_conf_t *us)
[126] {
[127]     ngx_http_upstream_hash_srv_conf_t   *hcf;
[128]     ngx_http_upstream_hash_peer_data_t  *hp;
[129] 
[130]     hp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_hash_peer_data_t));
[131]     if (hp == NULL) {
[132]         return NGX_ERROR;
[133]     }
[134] 
[135]     r->upstream->peer.data = &hp->rrp;
[136] 
[137]     if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
[138]         return NGX_ERROR;
[139]     }
[140] 
[141]     r->upstream->peer.get = ngx_http_upstream_get_hash_peer;
[142] 
[143]     hcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);
[144] 
[145]     if (ngx_http_complex_value(r, &hcf->key, &hp->key) != NGX_OK) {
[146]         return NGX_ERROR;
[147]     }
[148] 
[149]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[150]                    "upstream hash key:\"%V\"", &hp->key);
[151] 
[152]     hp->conf = hcf;
[153]     hp->tries = 0;
[154]     hp->rehash = 0;
[155]     hp->hash = 0;
[156]     hp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
[157] 
[158]     return NGX_OK;
[159] }
[160] 
[161] 
[162] static ngx_int_t
[163] ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data)
[164] {
[165]     ngx_http_upstream_hash_peer_data_t  *hp = data;
[166] 
[167]     time_t                        now;
[168]     u_char                        buf[NGX_INT_T_LEN];
[169]     size_t                        size;
[170]     uint32_t                      hash;
[171]     ngx_int_t                     w;
[172]     uintptr_t                     m;
[173]     ngx_uint_t                    n, p;
[174]     ngx_http_upstream_rr_peer_t  *peer;
[175] 
[176]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[177]                    "get hash peer, try: %ui", pc->tries);
[178] 
[179]     ngx_http_upstream_rr_peers_rlock(hp->rrp.peers);
[180] 
[181]     if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
[182]         ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[183]         return hp->get_rr_peer(pc, &hp->rrp);
[184]     }
[185] 
[186]     now = ngx_time();
[187] 
[188]     pc->cached = 0;
[189]     pc->connection = NULL;
[190] 
[191]     for ( ;; ) {
[192] 
[193]         /*
[194]          * Hash expression is compatible with Cache::Memcached:
[195]          * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
[196]          * with REHASH omitted at the first iteration.
[197]          */
[198] 
[199]         ngx_crc32_init(hash);
[200] 
[201]         if (hp->rehash > 0) {
[202]             size = ngx_sprintf(buf, "%ui", hp->rehash) - buf;
[203]             ngx_crc32_update(&hash, buf, size);
[204]         }
[205] 
[206]         ngx_crc32_update(&hash, hp->key.data, hp->key.len);
[207]         ngx_crc32_final(hash);
[208] 
[209]         hash = (hash >> 16) & 0x7fff;
[210] 
[211]         hp->hash += hash;
[212]         hp->rehash++;
[213] 
[214]         w = hp->hash % hp->rrp.peers->total_weight;
[215]         peer = hp->rrp.peers->peer;
[216]         p = 0;
[217] 
[218]         while (w >= peer->weight) {
[219]             w -= peer->weight;
[220]             peer = peer->next;
[221]             p++;
[222]         }
[223] 
[224]         n = p / (8 * sizeof(uintptr_t));
[225]         m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[226] 
[227]         if (hp->rrp.tried[n] & m) {
[228]             goto next;
[229]         }
[230] 
[231]         ngx_http_upstream_rr_peer_lock(hp->rrp.peers, peer);
[232] 
[233]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[234]                        "get hash peer, value:%uD, peer:%ui", hp->hash, p);
[235] 
[236]         if (peer->down) {
[237]             ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[238]             goto next;
[239]         }
[240] 
[241]         if (peer->max_fails
[242]             && peer->fails >= peer->max_fails
[243]             && now - peer->checked <= peer->fail_timeout)
[244]         {
[245]             ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[246]             goto next;
[247]         }
[248] 
[249]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[250]             ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[251]             goto next;
[252]         }
[253] 
[254]         break;
[255] 
[256]     next:
[257] 
[258]         if (++hp->tries > 20) {
[259]             ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[260]             return hp->get_rr_peer(pc, &hp->rrp);
[261]         }
[262]     }
[263] 
[264]     hp->rrp.current = peer;
[265] 
[266]     pc->sockaddr = peer->sockaddr;
[267]     pc->socklen = peer->socklen;
[268]     pc->name = &peer->name;
[269] 
[270]     peer->conns++;
[271] 
[272]     if (now - peer->checked > peer->fail_timeout) {
[273]         peer->checked = now;
[274]     }
[275] 
[276]     ngx_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
[277]     ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[278] 
[279]     hp->rrp.tried[n] |= m;
[280] 
[281]     return NGX_OK;
[282] }
[283] 
[284] 
[285] static ngx_int_t
[286] ngx_http_upstream_init_chash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
[287] {
[288]     u_char                             *host, *port, c;
[289]     size_t                              host_len, port_len, size;
[290]     uint32_t                            hash, base_hash;
[291]     ngx_str_t                          *server;
[292]     ngx_uint_t                          npoints, i, j;
[293]     ngx_http_upstream_rr_peer_t        *peer;
[294]     ngx_http_upstream_rr_peers_t       *peers;
[295]     ngx_http_upstream_chash_points_t   *points;
[296]     ngx_http_upstream_hash_srv_conf_t  *hcf;
[297]     union {
[298]         uint32_t                        value;
[299]         u_char                          byte[4];
[300]     } prev_hash;
[301] 
[302]     if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
[303]         return NGX_ERROR;
[304]     }
[305] 
[306]     us->peer.init = ngx_http_upstream_init_chash_peer;
[307] 
[308]     peers = us->peer.data;
[309]     npoints = peers->total_weight * 160;
[310] 
[311]     size = sizeof(ngx_http_upstream_chash_points_t)
[312]            + sizeof(ngx_http_upstream_chash_point_t) * (npoints - 1);
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
[393]               sizeof(ngx_http_upstream_chash_point_t),
[394]               ngx_http_upstream_chash_cmp_points);
[395] 
[396]     for (i = 0, j = 1; j < points->number; j++) {
[397]         if (points->point[i].hash != points->point[j].hash) {
[398]             points->point[++i] = points->point[j];
[399]         }
[400]     }
[401] 
[402]     points->number = i + 1;
[403] 
[404]     hcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);
[405]     hcf->points = points;
[406] 
[407]     return NGX_OK;
[408] }
[409] 
[410] 
[411] static int ngx_libc_cdecl
[412] ngx_http_upstream_chash_cmp_points(const void *one, const void *two)
[413] {
[414]     ngx_http_upstream_chash_point_t *first =
[415]                                        (ngx_http_upstream_chash_point_t *) one;
[416]     ngx_http_upstream_chash_point_t *second =
[417]                                        (ngx_http_upstream_chash_point_t *) two;
[418] 
[419]     if (first->hash < second->hash) {
[420]         return -1;
[421] 
[422]     } else if (first->hash > second->hash) {
[423]         return 1;
[424] 
[425]     } else {
[426]         return 0;
[427]     }
[428] }
[429] 
[430] 
[431] static ngx_uint_t
[432] ngx_http_upstream_find_chash_point(ngx_http_upstream_chash_points_t *points,
[433]     uint32_t hash)
[434] {
[435]     ngx_uint_t                        i, j, k;
[436]     ngx_http_upstream_chash_point_t  *point;
[437] 
[438]     /* find first point >= hash */
[439] 
[440]     point = &points->point[0];
[441] 
[442]     i = 0;
[443]     j = points->number;
[444] 
[445]     while (i < j) {
[446]         k = (i + j) / 2;
[447] 
[448]         if (hash > point[k].hash) {
[449]             i = k + 1;
[450] 
[451]         } else if (hash < point[k].hash) {
[452]             j = k;
[453] 
[454]         } else {
[455]             return k;
[456]         }
[457]     }
[458] 
[459]     return i;
[460] }
[461] 
[462] 
[463] static ngx_int_t
[464] ngx_http_upstream_init_chash_peer(ngx_http_request_t *r,
[465]     ngx_http_upstream_srv_conf_t *us)
[466] {
[467]     uint32_t                             hash;
[468]     ngx_http_upstream_hash_srv_conf_t   *hcf;
[469]     ngx_http_upstream_hash_peer_data_t  *hp;
[470] 
[471]     if (ngx_http_upstream_init_hash_peer(r, us) != NGX_OK) {
[472]         return NGX_ERROR;
[473]     }
[474] 
[475]     r->upstream->peer.get = ngx_http_upstream_get_chash_peer;
[476] 
[477]     hp = r->upstream->peer.data;
[478]     hcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_hash_module);
[479] 
[480]     hash = ngx_crc32_long(hp->key.data, hp->key.len);
[481] 
[482]     ngx_http_upstream_rr_peers_rlock(hp->rrp.peers);
[483] 
[484]     hp->hash = ngx_http_upstream_find_chash_point(hcf->points, hash);
[485] 
[486]     ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[487] 
[488]     return NGX_OK;
[489] }
[490] 
[491] 
[492] static ngx_int_t
[493] ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data)
[494] {
[495]     ngx_http_upstream_hash_peer_data_t  *hp = data;
[496] 
[497]     time_t                              now;
[498]     intptr_t                            m;
[499]     ngx_str_t                          *server;
[500]     ngx_int_t                           total;
[501]     ngx_uint_t                          i, n, best_i;
[502]     ngx_http_upstream_rr_peer_t        *peer, *best;
[503]     ngx_http_upstream_chash_point_t    *point;
[504]     ngx_http_upstream_chash_points_t   *points;
[505]     ngx_http_upstream_hash_srv_conf_t  *hcf;
[506] 
[507]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[508]                    "get consistent hash peer, try: %ui", pc->tries);
[509] 
[510]     ngx_http_upstream_rr_peers_wlock(hp->rrp.peers);
[511] 
[512]     if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
[513]         ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[514]         return hp->get_rr_peer(pc, &hp->rrp);
[515]     }
[516] 
[517]     pc->cached = 0;
[518]     pc->connection = NULL;
[519] 
[520]     now = ngx_time();
[521]     hcf = hp->conf;
[522] 
[523]     points = hcf->points;
[524]     point = &points->point[0];
[525] 
[526]     for ( ;; ) {
[527]         server = point[hp->hash % points->number].server;
[528] 
[529]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[530]                        "consistent hash peer:%uD, server:\"%V\"",
[531]                        hp->hash, server);
[532] 
[533]         best = NULL;
[534]         best_i = 0;
[535]         total = 0;
[536] 
[537]         for (peer = hp->rrp.peers->peer, i = 0;
[538]              peer;
[539]              peer = peer->next, i++)
[540]         {
[541]             n = i / (8 * sizeof(uintptr_t));
[542]             m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[543] 
[544]             if (hp->rrp.tried[n] & m) {
[545]                 continue;
[546]             }
[547] 
[548]             if (peer->down) {
[549]                 continue;
[550]             }
[551] 
[552]             if (peer->max_fails
[553]                 && peer->fails >= peer->max_fails
[554]                 && now - peer->checked <= peer->fail_timeout)
[555]             {
[556]                 continue;
[557]             }
[558] 
[559]             if (peer->max_conns && peer->conns >= peer->max_conns) {
[560]                 continue;
[561]             }
[562] 
[563]             if (peer->server.len != server->len
[564]                 || ngx_strncmp(peer->server.data, server->data, server->len)
[565]                    != 0)
[566]             {
[567]                 continue;
[568]             }
[569] 
[570]             peer->current_weight += peer->effective_weight;
[571]             total += peer->effective_weight;
[572] 
[573]             if (peer->effective_weight < peer->weight) {
[574]                 peer->effective_weight++;
[575]             }
[576] 
[577]             if (best == NULL || peer->current_weight > best->current_weight) {
[578]                 best = peer;
[579]                 best_i = i;
[580]             }
[581]         }
[582] 
[583]         if (best) {
[584]             best->current_weight -= total;
[585]             goto found;
[586]         }
[587] 
[588]         hp->hash++;
[589]         hp->tries++;
[590] 
[591]         if (hp->tries > 20) {
[592]             ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[593]             return hp->get_rr_peer(pc, &hp->rrp);
[594]         }
[595]     }
[596] 
[597] found:
[598] 
[599]     hp->rrp.current = best;
[600] 
[601]     pc->sockaddr = best->sockaddr;
[602]     pc->socklen = best->socklen;
[603]     pc->name = &best->name;
[604] 
[605]     best->conns++;
[606] 
[607]     if (now - best->checked > best->fail_timeout) {
[608]         best->checked = now;
[609]     }
[610] 
[611]     ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
[612] 
[613]     n = best_i / (8 * sizeof(uintptr_t));
[614]     m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));
[615] 
[616]     hp->rrp.tried[n] |= m;
[617] 
[618]     return NGX_OK;
[619] }
[620] 
[621] 
[622] static void *
[623] ngx_http_upstream_hash_create_conf(ngx_conf_t *cf)
[624] {
[625]     ngx_http_upstream_hash_srv_conf_t  *conf;
[626] 
[627]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_hash_srv_conf_t));
[628]     if (conf == NULL) {
[629]         return NULL;
[630]     }
[631] 
[632]     conf->points = NULL;
[633] 
[634]     return conf;
[635] }
[636] 
[637] 
[638] static char *
[639] ngx_http_upstream_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[640] {
[641]     ngx_http_upstream_hash_srv_conf_t  *hcf = conf;
[642] 
[643]     ngx_str_t                         *value;
[644]     ngx_http_upstream_srv_conf_t      *uscf;
[645]     ngx_http_compile_complex_value_t   ccv;
[646] 
[647]     value = cf->args->elts;
[648] 
[649]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[650] 
[651]     ccv.cf = cf;
[652]     ccv.value = &value[1];
[653]     ccv.complex_value = &hcf->key;
[654] 
[655]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[656]         return NGX_CONF_ERROR;
[657]     }
[658] 
[659]     uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
[660] 
[661]     if (uscf->peer.init_upstream) {
[662]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[663]                            "load balancing method redefined");
[664]     }
[665] 
[666]     uscf->flags = NGX_HTTP_UPSTREAM_CREATE
[667]                   |NGX_HTTP_UPSTREAM_WEIGHT
[668]                   |NGX_HTTP_UPSTREAM_MAX_CONNS
[669]                   |NGX_HTTP_UPSTREAM_MAX_FAILS
[670]                   |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
[671]                   |NGX_HTTP_UPSTREAM_DOWN;
[672] 
[673]     if (cf->args->nelts == 2) {
[674]         uscf->peer.init_upstream = ngx_http_upstream_init_hash;
[675] 
[676]     } else if (ngx_strcmp(value[2].data, "consistent") == 0) {
[677]         uscf->peer.init_upstream = ngx_http_upstream_init_chash;
[678] 
[679]     } else {
[680]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[681]                            "invalid parameter \"%V\"", &value[2]);
[682]         return NGX_CONF_ERROR;
[683]     }
[684] 
[685]     return NGX_CONF_OK;
[686] }
