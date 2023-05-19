[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_http.h>
[10] 
[11] 
[12] typedef struct {
[13]     ngx_http_upstream_rr_peer_t          *peer;
[14]     ngx_uint_t                            range;
[15] } ngx_http_upstream_random_range_t;
[16] 
[17] 
[18] typedef struct {
[19]     ngx_uint_t                            two;
[20]     ngx_http_upstream_random_range_t     *ranges;
[21] } ngx_http_upstream_random_srv_conf_t;
[22] 
[23] 
[24] typedef struct {
[25]     /* the round robin data must be first */
[26]     ngx_http_upstream_rr_peer_data_t      rrp;
[27] 
[28]     ngx_http_upstream_random_srv_conf_t  *conf;
[29]     u_char                                tries;
[30] } ngx_http_upstream_random_peer_data_t;
[31] 
[32] 
[33] static ngx_int_t ngx_http_upstream_init_random(ngx_conf_t *cf,
[34]     ngx_http_upstream_srv_conf_t *us);
[35] static ngx_int_t ngx_http_upstream_update_random(ngx_pool_t *pool,
[36]     ngx_http_upstream_srv_conf_t *us);
[37] 
[38] static ngx_int_t ngx_http_upstream_init_random_peer(ngx_http_request_t *r,
[39]     ngx_http_upstream_srv_conf_t *us);
[40] static ngx_int_t ngx_http_upstream_get_random_peer(ngx_peer_connection_t *pc,
[41]     void *data);
[42] static ngx_int_t ngx_http_upstream_get_random2_peer(ngx_peer_connection_t *pc,
[43]     void *data);
[44] static ngx_uint_t ngx_http_upstream_peek_random_peer(
[45]     ngx_http_upstream_rr_peers_t *peers,
[46]     ngx_http_upstream_random_peer_data_t *rp);
[47] static void *ngx_http_upstream_random_create_conf(ngx_conf_t *cf);
[48] static char *ngx_http_upstream_random(ngx_conf_t *cf, ngx_command_t *cmd,
[49]     void *conf);
[50] 
[51] 
[52] static ngx_command_t  ngx_http_upstream_random_commands[] = {
[53] 
[54]     { ngx_string("random"),
[55]       NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE12,
[56]       ngx_http_upstream_random,
[57]       NGX_HTTP_SRV_CONF_OFFSET,
[58]       0,
[59]       NULL },
[60] 
[61]       ngx_null_command
[62] };
[63] 
[64] 
[65] static ngx_http_module_t  ngx_http_upstream_random_module_ctx = {
[66]     NULL,                                  /* preconfiguration */
[67]     NULL,                                  /* postconfiguration */
[68] 
[69]     NULL,                                  /* create main configuration */
[70]     NULL,                                  /* init main configuration */
[71] 
[72]     ngx_http_upstream_random_create_conf,  /* create server configuration */
[73]     NULL,                                  /* merge server configuration */
[74] 
[75]     NULL,                                  /* create location configuration */
[76]     NULL                                   /* merge location configuration */
[77] };
[78] 
[79] 
[80] ngx_module_t  ngx_http_upstream_random_module = {
[81]     NGX_MODULE_V1,
[82]     &ngx_http_upstream_random_module_ctx,  /* module context */
[83]     ngx_http_upstream_random_commands,     /* module directives */
[84]     NGX_HTTP_MODULE,                       /* module type */
[85]     NULL,                                  /* init master */
[86]     NULL,                                  /* init module */
[87]     NULL,                                  /* init process */
[88]     NULL,                                  /* init thread */
[89]     NULL,                                  /* exit thread */
[90]     NULL,                                  /* exit process */
[91]     NULL,                                  /* exit master */
[92]     NGX_MODULE_V1_PADDING
[93] };
[94] 
[95] 
[96] static ngx_int_t
[97] ngx_http_upstream_init_random(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
[98] {
[99]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "init random");
[100] 
[101]     if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
[102]         return NGX_ERROR;
[103]     }
[104] 
[105]     us->peer.init = ngx_http_upstream_init_random_peer;
[106] 
[107] #if (NGX_HTTP_UPSTREAM_ZONE)
[108]     if (us->shm_zone) {
[109]         return NGX_OK;
[110]     }
[111] #endif
[112] 
[113]     return ngx_http_upstream_update_random(cf->pool, us);
[114] }
[115] 
[116] 
[117] static ngx_int_t
[118] ngx_http_upstream_update_random(ngx_pool_t *pool,
[119]     ngx_http_upstream_srv_conf_t *us)
[120] {
[121]     size_t                                size;
[122]     ngx_uint_t                            i, total_weight;
[123]     ngx_http_upstream_rr_peer_t          *peer;
[124]     ngx_http_upstream_rr_peers_t         *peers;
[125]     ngx_http_upstream_random_range_t     *ranges;
[126]     ngx_http_upstream_random_srv_conf_t  *rcf;
[127] 
[128]     rcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_random_module);
[129] 
[130]     peers = us->peer.data;
[131] 
[132]     size = peers->number * sizeof(ngx_http_upstream_random_range_t);
[133] 
[134]     ranges = pool ? ngx_palloc(pool, size) : ngx_alloc(size, ngx_cycle->log);
[135]     if (ranges == NULL) {
[136]         return NGX_ERROR;
[137]     }
[138] 
[139]     total_weight = 0;
[140] 
[141]     for (peer = peers->peer, i = 0; peer; peer = peer->next, i++) {
[142]         ranges[i].peer = peer;
[143]         ranges[i].range = total_weight;
[144]         total_weight += peer->weight;
[145]     }
[146] 
[147]     rcf->ranges = ranges;
[148] 
[149]     return NGX_OK;
[150] }
[151] 
[152] 
[153] static ngx_int_t
[154] ngx_http_upstream_init_random_peer(ngx_http_request_t *r,
[155]     ngx_http_upstream_srv_conf_t *us)
[156] {
[157]     ngx_http_upstream_random_srv_conf_t   *rcf;
[158]     ngx_http_upstream_random_peer_data_t  *rp;
[159] 
[160]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[161]                    "init random peer");
[162] 
[163]     rcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_random_module);
[164] 
[165]     rp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_random_peer_data_t));
[166]     if (rp == NULL) {
[167]         return NGX_ERROR;
[168]     }
[169] 
[170]     r->upstream->peer.data = &rp->rrp;
[171] 
[172]     if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
[173]         return NGX_ERROR;
[174]     }
[175] 
[176]     if (rcf->two) {
[177]         r->upstream->peer.get = ngx_http_upstream_get_random2_peer;
[178] 
[179]     } else {
[180]         r->upstream->peer.get = ngx_http_upstream_get_random_peer;
[181]     }
[182] 
[183]     rp->conf = rcf;
[184]     rp->tries = 0;
[185] 
[186]     ngx_http_upstream_rr_peers_rlock(rp->rrp.peers);
[187] 
[188] #if (NGX_HTTP_UPSTREAM_ZONE)
[189]     if (rp->rrp.peers->shpool && rcf->ranges == NULL) {
[190]         if (ngx_http_upstream_update_random(NULL, us) != NGX_OK) {
[191]             ngx_http_upstream_rr_peers_unlock(rp->rrp.peers);
[192]             return NGX_ERROR;
[193]         }
[194]     }
[195] #endif
[196] 
[197]     ngx_http_upstream_rr_peers_unlock(rp->rrp.peers);
[198] 
[199]     return NGX_OK;
[200] }
[201] 
[202] 
[203] static ngx_int_t
[204] ngx_http_upstream_get_random_peer(ngx_peer_connection_t *pc, void *data)
[205] {
[206]     ngx_http_upstream_random_peer_data_t  *rp = data;
[207] 
[208]     time_t                             now;
[209]     uintptr_t                          m;
[210]     ngx_uint_t                         i, n;
[211]     ngx_http_upstream_rr_peer_t       *peer;
[212]     ngx_http_upstream_rr_peers_t      *peers;
[213]     ngx_http_upstream_rr_peer_data_t  *rrp;
[214] 
[215]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[216]                    "get random peer, try: %ui", pc->tries);
[217] 
[218]     rrp = &rp->rrp;
[219]     peers = rrp->peers;
[220] 
[221]     ngx_http_upstream_rr_peers_rlock(peers);
[222] 
[223]     if (rp->tries > 20 || peers->single) {
[224]         ngx_http_upstream_rr_peers_unlock(peers);
[225]         return ngx_http_upstream_get_round_robin_peer(pc, rrp);
[226]     }
[227] 
[228]     pc->cached = 0;
[229]     pc->connection = NULL;
[230] 
[231]     now = ngx_time();
[232] 
[233]     for ( ;; ) {
[234] 
[235]         i = ngx_http_upstream_peek_random_peer(peers, rp);
[236] 
[237]         peer = rp->conf->ranges[i].peer;
[238] 
[239]         n = i / (8 * sizeof(uintptr_t));
[240]         m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[241] 
[242]         if (rrp->tried[n] & m) {
[243]             goto next;
[244]         }
[245] 
[246]         ngx_http_upstream_rr_peer_lock(peers, peer);
[247] 
[248]         if (peer->down) {
[249]             ngx_http_upstream_rr_peer_unlock(peers, peer);
[250]             goto next;
[251]         }
[252] 
[253]         if (peer->max_fails
[254]             && peer->fails >= peer->max_fails
[255]             && now - peer->checked <= peer->fail_timeout)
[256]         {
[257]             ngx_http_upstream_rr_peer_unlock(peers, peer);
[258]             goto next;
[259]         }
[260] 
[261]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[262]             ngx_http_upstream_rr_peer_unlock(peers, peer);
[263]             goto next;
[264]         }
[265] 
[266]         break;
[267] 
[268]     next:
[269] 
[270]         if (++rp->tries > 20) {
[271]             ngx_http_upstream_rr_peers_unlock(peers);
[272]             return ngx_http_upstream_get_round_robin_peer(pc, rrp);
[273]         }
[274]     }
[275] 
[276]     rrp->current = peer;
[277] 
[278]     if (now - peer->checked > peer->fail_timeout) {
[279]         peer->checked = now;
[280]     }
[281] 
[282]     pc->sockaddr = peer->sockaddr;
[283]     pc->socklen = peer->socklen;
[284]     pc->name = &peer->name;
[285] 
[286]     peer->conns++;
[287] 
[288]     ngx_http_upstream_rr_peer_unlock(peers, peer);
[289]     ngx_http_upstream_rr_peers_unlock(peers);
[290] 
[291]     rrp->tried[n] |= m;
[292] 
[293]     return NGX_OK;
[294] }
[295] 
[296] 
[297] static ngx_int_t
[298] ngx_http_upstream_get_random2_peer(ngx_peer_connection_t *pc, void *data)
[299] {
[300]     ngx_http_upstream_random_peer_data_t  *rp = data;
[301] 
[302]     time_t                             now;
[303]     uintptr_t                          m;
[304]     ngx_uint_t                         i, n, p;
[305]     ngx_http_upstream_rr_peer_t       *peer, *prev;
[306]     ngx_http_upstream_rr_peers_t      *peers;
[307]     ngx_http_upstream_rr_peer_data_t  *rrp;
[308] 
[309]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[310]                    "get random2 peer, try: %ui", pc->tries);
[311] 
[312]     rrp = &rp->rrp;
[313]     peers = rrp->peers;
[314] 
[315]     ngx_http_upstream_rr_peers_wlock(peers);
[316] 
[317]     if (rp->tries > 20 || peers->single) {
[318]         ngx_http_upstream_rr_peers_unlock(peers);
[319]         return ngx_http_upstream_get_round_robin_peer(pc, rrp);
[320]     }
[321] 
[322]     pc->cached = 0;
[323]     pc->connection = NULL;
[324] 
[325]     now = ngx_time();
[326] 
[327]     prev = NULL;
[328] 
[329] #if (NGX_SUPPRESS_WARN)
[330]     p = 0;
[331] #endif
[332] 
[333]     for ( ;; ) {
[334] 
[335]         i = ngx_http_upstream_peek_random_peer(peers, rp);
[336] 
[337]         peer = rp->conf->ranges[i].peer;
[338] 
[339]         if (peer == prev) {
[340]             goto next;
[341]         }
[342] 
[343]         n = i / (8 * sizeof(uintptr_t));
[344]         m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[345] 
[346]         if (rrp->tried[n] & m) {
[347]             goto next;
[348]         }
[349] 
[350]         if (peer->down) {
[351]             goto next;
[352]         }
[353] 
[354]         if (peer->max_fails
[355]             && peer->fails >= peer->max_fails
[356]             && now - peer->checked <= peer->fail_timeout)
[357]         {
[358]             goto next;
[359]         }
[360] 
[361]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[362]             goto next;
[363]         }
[364] 
[365]         if (prev) {
[366]             if (peer->conns * prev->weight > prev->conns * peer->weight) {
[367]                 peer = prev;
[368]                 n = p / (8 * sizeof(uintptr_t));
[369]                 m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[370]             }
[371] 
[372]             break;
[373]         }
[374] 
[375]         prev = peer;
[376]         p = i;
[377] 
[378]     next:
[379] 
[380]         if (++rp->tries > 20) {
[381]             ngx_http_upstream_rr_peers_unlock(peers);
[382]             return ngx_http_upstream_get_round_robin_peer(pc, rrp);
[383]         }
[384]     }
[385] 
[386]     rrp->current = peer;
[387] 
[388]     if (now - peer->checked > peer->fail_timeout) {
[389]         peer->checked = now;
[390]     }
[391] 
[392]     pc->sockaddr = peer->sockaddr;
[393]     pc->socklen = peer->socklen;
[394]     pc->name = &peer->name;
[395] 
[396]     peer->conns++;
[397] 
[398]     ngx_http_upstream_rr_peers_unlock(peers);
[399] 
[400]     rrp->tried[n] |= m;
[401] 
[402]     return NGX_OK;
[403] }
[404] 
[405] 
[406] static ngx_uint_t
[407] ngx_http_upstream_peek_random_peer(ngx_http_upstream_rr_peers_t *peers,
[408]     ngx_http_upstream_random_peer_data_t *rp)
[409] {
[410]     ngx_uint_t  i, j, k, x;
[411] 
[412]     x = ngx_random() % peers->total_weight;
[413] 
[414]     i = 0;
[415]     j = peers->number;
[416] 
[417]     while (j - i > 1) {
[418]         k = (i + j) / 2;
[419] 
[420]         if (x < rp->conf->ranges[k].range) {
[421]             j = k;
[422] 
[423]         } else {
[424]             i = k;
[425]         }
[426]     }
[427] 
[428]     return i;
[429] }
[430] 
[431] 
[432] static void *
[433] ngx_http_upstream_random_create_conf(ngx_conf_t *cf)
[434] {
[435]     ngx_http_upstream_random_srv_conf_t  *conf;
[436] 
[437]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_random_srv_conf_t));
[438]     if (conf == NULL) {
[439]         return NULL;
[440]     }
[441] 
[442]     /*
[443]      * set by ngx_pcalloc():
[444]      *
[445]      *     conf->two = 0;
[446]      */
[447] 
[448]     return conf;
[449] }
[450] 
[451] 
[452] static char *
[453] ngx_http_upstream_random(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[454] {
[455]     ngx_http_upstream_random_srv_conf_t  *rcf = conf;
[456] 
[457]     ngx_str_t                     *value;
[458]     ngx_http_upstream_srv_conf_t  *uscf;
[459] 
[460]     uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
[461] 
[462]     if (uscf->peer.init_upstream) {
[463]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[464]                            "load balancing method redefined");
[465]     }
[466] 
[467]     uscf->peer.init_upstream = ngx_http_upstream_init_random;
[468] 
[469]     uscf->flags = NGX_HTTP_UPSTREAM_CREATE
[470]                   |NGX_HTTP_UPSTREAM_WEIGHT
[471]                   |NGX_HTTP_UPSTREAM_MAX_CONNS
[472]                   |NGX_HTTP_UPSTREAM_MAX_FAILS
[473]                   |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
[474]                   |NGX_HTTP_UPSTREAM_DOWN;
[475] 
[476]     if (cf->args->nelts == 1) {
[477]         return NGX_CONF_OK;
[478]     }
[479] 
[480]     value = cf->args->elts;
[481] 
[482]     if (ngx_strcmp(value[1].data, "two") == 0) {
[483]         rcf->two = 1;
[484] 
[485]     } else {
[486]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[487]                            "invalid parameter \"%V\"", &value[1]);
[488]         return NGX_CONF_ERROR;
[489]     }
[490] 
[491]     if (cf->args->nelts == 2) {
[492]         return NGX_CONF_OK;
[493]     }
[494] 
[495]     if (ngx_strcmp(value[2].data, "least_conn") != 0) {
[496]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[497]                            "invalid parameter \"%V\"", &value[2]);
[498]         return NGX_CONF_ERROR;
[499]     }
[500] 
[501]     return NGX_CONF_OK;
[502] }
