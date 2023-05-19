[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] static ngx_int_t ngx_stream_upstream_init_least_conn_peer(
[14]     ngx_stream_session_t *s, ngx_stream_upstream_srv_conf_t *us);
[15] static ngx_int_t ngx_stream_upstream_get_least_conn_peer(
[16]     ngx_peer_connection_t *pc, void *data);
[17] static char *ngx_stream_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd,
[18]     void *conf);
[19] 
[20] 
[21] static ngx_command_t  ngx_stream_upstream_least_conn_commands[] = {
[22] 
[23]     { ngx_string("least_conn"),
[24]       NGX_STREAM_UPS_CONF|NGX_CONF_NOARGS,
[25]       ngx_stream_upstream_least_conn,
[26]       0,
[27]       0,
[28]       NULL },
[29] 
[30]       ngx_null_command
[31] };
[32] 
[33] 
[34] static ngx_stream_module_t  ngx_stream_upstream_least_conn_module_ctx = {
[35]     NULL,                                    /* preconfiguration */
[36]     NULL,                                    /* postconfiguration */
[37] 
[38]     NULL,                                    /* create main configuration */
[39]     NULL,                                    /* init main configuration */
[40] 
[41]     NULL,                                    /* create server configuration */
[42]     NULL                                     /* merge server configuration */
[43] };
[44] 
[45] 
[46] ngx_module_t  ngx_stream_upstream_least_conn_module = {
[47]     NGX_MODULE_V1,
[48]     &ngx_stream_upstream_least_conn_module_ctx, /* module context */
[49]     ngx_stream_upstream_least_conn_commands, /* module directives */
[50]     NGX_STREAM_MODULE,                       /* module type */
[51]     NULL,                                    /* init master */
[52]     NULL,                                    /* init module */
[53]     NULL,                                    /* init process */
[54]     NULL,                                    /* init thread */
[55]     NULL,                                    /* exit thread */
[56]     NULL,                                    /* exit process */
[57]     NULL,                                    /* exit master */
[58]     NGX_MODULE_V1_PADDING
[59] };
[60] 
[61] 
[62] static ngx_int_t
[63] ngx_stream_upstream_init_least_conn(ngx_conf_t *cf,
[64]     ngx_stream_upstream_srv_conf_t *us)
[65] {
[66]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cf->log, 0,
[67]                    "init least conn");
[68] 
[69]     if (ngx_stream_upstream_init_round_robin(cf, us) != NGX_OK) {
[70]         return NGX_ERROR;
[71]     }
[72] 
[73]     us->peer.init = ngx_stream_upstream_init_least_conn_peer;
[74] 
[75]     return NGX_OK;
[76] }
[77] 
[78] 
[79] static ngx_int_t
[80] ngx_stream_upstream_init_least_conn_peer(ngx_stream_session_t *s,
[81]     ngx_stream_upstream_srv_conf_t *us)
[82] {
[83]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[84]                    "init least conn peer");
[85] 
[86]     if (ngx_stream_upstream_init_round_robin_peer(s, us) != NGX_OK) {
[87]         return NGX_ERROR;
[88]     }
[89] 
[90]     s->upstream->peer.get = ngx_stream_upstream_get_least_conn_peer;
[91] 
[92]     return NGX_OK;
[93] }
[94] 
[95] 
[96] static ngx_int_t
[97] ngx_stream_upstream_get_least_conn_peer(ngx_peer_connection_t *pc, void *data)
[98] {
[99]     ngx_stream_upstream_rr_peer_data_t *rrp = data;
[100] 
[101]     time_t                           now;
[102]     uintptr_t                        m;
[103]     ngx_int_t                        rc, total;
[104]     ngx_uint_t                       i, n, p, many;
[105]     ngx_stream_upstream_rr_peer_t   *peer, *best;
[106]     ngx_stream_upstream_rr_peers_t  *peers;
[107] 
[108]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[109]                    "get least conn peer, try: %ui", pc->tries);
[110] 
[111]     if (rrp->peers->single) {
[112]         return ngx_stream_upstream_get_round_robin_peer(pc, rrp);
[113]     }
[114] 
[115]     pc->connection = NULL;
[116] 
[117]     now = ngx_time();
[118] 
[119]     peers = rrp->peers;
[120] 
[121]     ngx_stream_upstream_rr_peers_wlock(peers);
[122] 
[123]     best = NULL;
[124]     total = 0;
[125] 
[126] #if (NGX_SUPPRESS_WARN)
[127]     many = 0;
[128]     p = 0;
[129] #endif
[130] 
[131]     for (peer = peers->peer, i = 0;
[132]          peer;
[133]          peer = peer->next, i++)
[134]     {
[135]         n = i / (8 * sizeof(uintptr_t));
[136]         m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[137] 
[138]         if (rrp->tried[n] & m) {
[139]             continue;
[140]         }
[141] 
[142]         if (peer->down) {
[143]             continue;
[144]         }
[145] 
[146]         if (peer->max_fails
[147]             && peer->fails >= peer->max_fails
[148]             && now - peer->checked <= peer->fail_timeout)
[149]         {
[150]             continue;
[151]         }
[152] 
[153]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[154]             continue;
[155]         }
[156] 
[157]         /*
[158]          * select peer with least number of connections; if there are
[159]          * multiple peers with the same number of connections, select
[160]          * based on round-robin
[161]          */
[162] 
[163]         if (best == NULL
[164]             || peer->conns * best->weight < best->conns * peer->weight)
[165]         {
[166]             best = peer;
[167]             many = 0;
[168]             p = i;
[169] 
[170]         } else if (peer->conns * best->weight == best->conns * peer->weight) {
[171]             many = 1;
[172]         }
[173]     }
[174] 
[175]     if (best == NULL) {
[176]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[177]                        "get least conn peer, no peer found");
[178] 
[179]         goto failed;
[180]     }
[181] 
[182]     if (many) {
[183]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[184]                        "get least conn peer, many");
[185] 
[186]         for (peer = best, i = p;
[187]              peer;
[188]              peer = peer->next, i++)
[189]         {
[190]             n = i / (8 * sizeof(uintptr_t));
[191]             m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
[192] 
[193]             if (rrp->tried[n] & m) {
[194]                 continue;
[195]             }
[196] 
[197]             if (peer->down) {
[198]                 continue;
[199]             }
[200] 
[201]             if (peer->conns * best->weight != best->conns * peer->weight) {
[202]                 continue;
[203]             }
[204] 
[205]             if (peer->max_fails
[206]                 && peer->fails >= peer->max_fails
[207]                 && now - peer->checked <= peer->fail_timeout)
[208]             {
[209]                 continue;
[210]             }
[211] 
[212]             if (peer->max_conns && peer->conns >= peer->max_conns) {
[213]                 continue;
[214]             }
[215] 
[216]             peer->current_weight += peer->effective_weight;
[217]             total += peer->effective_weight;
[218] 
[219]             if (peer->effective_weight < peer->weight) {
[220]                 peer->effective_weight++;
[221]             }
[222] 
[223]             if (peer->current_weight > best->current_weight) {
[224]                 best = peer;
[225]                 p = i;
[226]             }
[227]         }
[228]     }
[229] 
[230]     best->current_weight -= total;
[231] 
[232]     if (now - best->checked > best->fail_timeout) {
[233]         best->checked = now;
[234]     }
[235] 
[236]     pc->sockaddr = best->sockaddr;
[237]     pc->socklen = best->socklen;
[238]     pc->name = &best->name;
[239] 
[240]     best->conns++;
[241] 
[242]     rrp->current = best;
[243] 
[244]     n = p / (8 * sizeof(uintptr_t));
[245]     m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[246] 
[247]     rrp->tried[n] |= m;
[248] 
[249]     ngx_stream_upstream_rr_peers_unlock(peers);
[250] 
[251]     return NGX_OK;
[252] 
[253] failed:
[254] 
[255]     if (peers->next) {
[256]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0,
[257]                        "get least conn peer, backup servers");
[258] 
[259]         rrp->peers = peers->next;
[260] 
[261]         n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
[262]                 / (8 * sizeof(uintptr_t));
[263] 
[264]         for (i = 0; i < n; i++) {
[265]             rrp->tried[i] = 0;
[266]         }
[267] 
[268]         ngx_stream_upstream_rr_peers_unlock(peers);
[269] 
[270]         rc = ngx_stream_upstream_get_least_conn_peer(pc, rrp);
[271] 
[272]         if (rc != NGX_BUSY) {
[273]             return rc;
[274]         }
[275] 
[276]         ngx_stream_upstream_rr_peers_wlock(peers);
[277]     }
[278] 
[279]     ngx_stream_upstream_rr_peers_unlock(peers);
[280] 
[281]     pc->name = peers->name;
[282] 
[283]     return NGX_BUSY;
[284] }
[285] 
[286] 
[287] static char *
[288] ngx_stream_upstream_least_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[289] {
[290]     ngx_stream_upstream_srv_conf_t  *uscf;
[291] 
[292]     uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);
[293] 
[294]     if (uscf->peer.init_upstream) {
[295]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[296]                            "load balancing method redefined");
[297]     }
[298] 
[299]     uscf->peer.init_upstream = ngx_stream_upstream_init_least_conn;
[300] 
[301]     uscf->flags = NGX_STREAM_UPSTREAM_CREATE
[302]                   |NGX_STREAM_UPSTREAM_WEIGHT
[303]                   |NGX_STREAM_UPSTREAM_MAX_CONNS
[304]                   |NGX_STREAM_UPSTREAM_MAX_FAILS
[305]                   |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
[306]                   |NGX_STREAM_UPSTREAM_DOWN
[307]                   |NGX_STREAM_UPSTREAM_BACKUP;
[308] 
[309]     return NGX_CONF_OK;
[310] }
