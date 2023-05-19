[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] static ngx_int_t ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
[14]     ngx_http_upstream_srv_conf_t *us);
[15] static ngx_int_t ngx_http_upstream_get_least_conn_peer(
[16]     ngx_peer_connection_t *pc, void *data);
[17] static char *ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
[18]     void *conf);
[19] 
[20] 
[21] static ngx_command_t  ngx_http_upstream_least_conn_commands[] = {
[22] 
[23]     { ngx_string("least_conn"),
[24]       NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
[25]       ngx_http_upstream_least_conn,
[26]       0,
[27]       0,
[28]       NULL },
[29] 
[30]       ngx_null_command
[31] };
[32] 
[33] 
[34] static ngx_http_module_t  ngx_http_upstream_least_conn_module_ctx = {
[35]     NULL,                                  /* preconfiguration */
[36]     NULL,                                  /* postconfiguration */
[37] 
[38]     NULL,                                  /* create main configuration */
[39]     NULL,                                  /* init main configuration */
[40] 
[41]     NULL,                                  /* create server configuration */
[42]     NULL,                                  /* merge server configuration */
[43] 
[44]     NULL,                                  /* create location configuration */
[45]     NULL                                   /* merge location configuration */
[46] };
[47] 
[48] 
[49] ngx_module_t  ngx_http_upstream_least_conn_module = {
[50]     NGX_MODULE_V1,
[51]     &ngx_http_upstream_least_conn_module_ctx, /* module context */
[52]     ngx_http_upstream_least_conn_commands, /* module directives */
[53]     NGX_HTTP_MODULE,                       /* module type */
[54]     NULL,                                  /* init master */
[55]     NULL,                                  /* init module */
[56]     NULL,                                  /* init process */
[57]     NULL,                                  /* init thread */
[58]     NULL,                                  /* exit thread */
[59]     NULL,                                  /* exit process */
[60]     NULL,                                  /* exit master */
[61]     NGX_MODULE_V1_PADDING
[62] };
[63] 
[64] 
[65] static ngx_int_t
[66] ngx_http_upstream_init_least_conn(ngx_conf_t *cf,
[67]     ngx_http_upstream_srv_conf_t *us)
[68] {
[69]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
[70]                    "init least conn");
[71] 
[72]     if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
[73]         return NGX_ERROR;
[74]     }
[75] 
[76]     us->peer.init = ngx_http_upstream_init_least_conn_peer;
[77] 
[78]     return NGX_OK;
[79] }
[80] 
[81] 
[82] static ngx_int_t
[83] ngx_http_upstream_init_least_conn_peer(ngx_http_request_t *r,
[84]     ngx_http_upstream_srv_conf_t *us)
[85] {
[86]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[87]                    "init least conn peer");
[88] 
[89]     if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
[90]         return NGX_ERROR;
[91]     }
[92] 
[93]     r->upstream->peer.get = ngx_http_upstream_get_least_conn_peer;
[94] 
[95]     return NGX_OK;
[96] }
[97] 
[98] 
[99] static ngx_int_t
[100] ngx_http_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
[101] {
[102]     ngx_http_upstream_rr_peer_data_t  *rrp = data;
[103] 
[104]     time_t                         now;
[105]     uintptr_t                      m;
[106]     ngx_int_t                      rc, total;
[107]     ngx_uint_t                     i, n, p, many;
[108]     ngx_http_upstream_rr_peer_t   *peer, *best;
[109]     ngx_http_upstream_rr_peers_t  *peers;
[110] 
[111]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[112]                    "get least conn peer, try: %ui", pc->tries);
[113] 
[114]     if (rrp->peers->single) {
[115]         return ngx_http_upstream_get_round_robin_peer(pc, rrp);
[116]     }
[117] 
[118]     pc->cached = 0;
[119]     pc->connection = NULL;
[120] 
[121]     now = ngx_time();
[122] 
[123]     peers = rrp->peers;
[124] 
[125]     ngx_http_upstream_rr_peers_wlock(peers);
[126] 
[127]     best = NULL;
[128]     total = 0;
[129] 
[130] #if (NGX_SUPPRESS_WARN)
[131]     many = 0;
[132]     p = 0;
[133] #endif
[134] 
[135]     for (peer = peers->peer, i = 0;
[136]          peer;
[137]          peer = peer->next, i++)
[138]     {
[139]         n = i / (8 * sizeof(uintptr_t));
[140]         m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[141] 
[142]         if (rrp->tried[n] & m) {
[143]             continue;
[144]         }
[145] 
[146]         if (peer->down) {
[147]             continue;
[148]         }
[149] 
[150]         if (peer->max_fails
[151]             && peer->fails >= peer->max_fails
[152]             && now - peer->checked <= peer->fail_timeout)
[153]         {
[154]             continue;
[155]         }
[156] 
[157]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[158]             continue;
[159]         }
[160] 
[161]         /*
[162]          * select peer with least number of connections; if there are
[163]          * multiple peers with the same number of connections, select
[164]          * based on round-robin
[165]          */
[166] 
[167]         if (best == NULL
[168]             || peer->conns * best->weight < best->conns * peer->weight)
[169]         {
[170]             best = peer;
[171]             many = 0;
[172]             p = i;
[173] 
[174]         } else if (peer->conns * best->weight == best->conns * peer->weight) {
[175]             many = 1;
[176]         }
[177]     }
[178] 
[179]     if (best == NULL) {
[180]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[181]                        "get least conn peer, no peer found");
[182] 
[183]         goto failed;
[184]     }
[185] 
[186]     if (many) {
[187]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[188]                        "get least conn peer, many");
[189] 
[190]         for (peer = best, i = p;
[191]              peer;
[192]              peer = peer->next, i++)
[193]         {
[194]             n = i / (8 * sizeof(uintptr_t));
[195]             m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[196] 
[197]             if (rrp->tried[n] & m) {
[198]                 continue;
[199]             }
[200] 
[201]             if (peer->down) {
[202]                 continue;
[203]             }
[204] 
[205]             if (peer->conns * best->weight != best->conns * peer->weight) {
[206]                 continue;
[207]             }
[208] 
[209]             if (peer->max_fails
[210]                 && peer->fails >= peer->max_fails
[211]                 && now - peer->checked <= peer->fail_timeout)
[212]             {
[213]                 continue;
[214]             }
[215] 
[216]             if (peer->max_conns && peer->conns >= peer->max_conns) {
[217]                 continue;
[218]             }
[219] 
[220]             peer->current_weight += peer->effective_weight;
[221]             total += peer->effective_weight;
[222] 
[223]             if (peer->effective_weight < peer->weight) {
[224]                 peer->effective_weight++;
[225]             }
[226] 
[227]             if (peer->current_weight > best->current_weight) {
[228]                 best = peer;
[229]                 p = i;
[230]             }
[231]         }
[232]     }
[233] 
[234]     best->current_weight -= total;
[235] 
[236]     if (now - best->checked > best->fail_timeout) {
[237]         best->checked = now;
[238]     }
[239] 
[240]     pc->sockaddr = best->sockaddr;
[241]     pc->socklen = best->socklen;
[242]     pc->name = &best->name;
[243] 
[244]     best->conns++;
[245] 
[246]     rrp->current = best;
[247] 
[248]     n = p / (8 * sizeof(uintptr_t));
[249]     m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[250] 
[251]     rrp->tried[n] |= m;
[252] 
[253]     ngx_http_upstream_rr_peers_unlock(peers);
[254] 
[255]     return NGX_OK;
[256] 
[257] failed:
[258] 
[259]     if (peers->next) {
[260]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[261]                        "get least conn peer, backup servers");
[262] 
[263]         rrp->peers = peers->next;
[264] 
[265]         n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
[266]                 / (8 * sizeof(uintptr_t));
[267] 
[268]         for (i = 0; i < n; i++) {
[269]             rrp->tried[i] = 0;
[270]         }
[271] 
[272]         ngx_http_upstream_rr_peers_unlock(peers);
[273] 
[274]         rc = ngx_http_upstream_get_least_conn_peer(pc, rrp);
[275] 
[276]         if (rc != NGX_BUSY) {
[277]             return rc;
[278]         }
[279] 
[280]         ngx_http_upstream_rr_peers_wlock(peers);
[281]     }
[282] 
[283]     ngx_http_upstream_rr_peers_unlock(peers);
[284] 
[285]     pc->name = peers->name;
[286] 
[287]     return NGX_BUSY;
[288] }
[289] 
[290] 
[291] static char *
[292] ngx_http_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[293] {
[294]     ngx_http_upstream_srv_conf_t  *uscf;
[295] 
[296]     uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
[297] 
[298]     if (uscf->peer.init_upstream) {
[299]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[300]                            "load balancing method redefined");
[301]     }
[302] 
[303]     uscf->peer.init_upstream = ngx_http_upstream_init_least_conn;
[304] 
[305]     uscf->flags = NGX_HTTP_UPSTREAM_CREATE
[306]                   |NGX_HTTP_UPSTREAM_WEIGHT
[307]                   |NGX_HTTP_UPSTREAM_MAX_CONNS
[308]                   |NGX_HTTP_UPSTREAM_MAX_FAILS
[309]                   |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
[310]                   |NGX_HTTP_UPSTREAM_DOWN
[311]                   |NGX_HTTP_UPSTREAM_BACKUP;
[312] 
[313]     return NGX_CONF_OK;
[314] }
