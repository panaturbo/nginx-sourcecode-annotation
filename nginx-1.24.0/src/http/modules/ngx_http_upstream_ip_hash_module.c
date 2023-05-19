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
[13] typedef struct {
[14]     /* the round robin data must be first */
[15]     ngx_http_upstream_rr_peer_data_t   rrp;
[16] 
[17]     ngx_uint_t                         hash;
[18] 
[19]     u_char                             addrlen;
[20]     u_char                            *addr;
[21] 
[22]     u_char                             tries;
[23] 
[24]     ngx_event_get_peer_pt              get_rr_peer;
[25] } ngx_http_upstream_ip_hash_peer_data_t;
[26] 
[27] 
[28] static ngx_int_t ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
[29]     ngx_http_upstream_srv_conf_t *us);
[30] static ngx_int_t ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
[31]     void *data);
[32] static char *ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd,
[33]     void *conf);
[34] 
[35] 
[36] static ngx_command_t  ngx_http_upstream_ip_hash_commands[] = {
[37] 
[38]     { ngx_string("ip_hash"),
[39]       NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
[40]       ngx_http_upstream_ip_hash,
[41]       0,
[42]       0,
[43]       NULL },
[44] 
[45]       ngx_null_command
[46] };
[47] 
[48] 
[49] static ngx_http_module_t  ngx_http_upstream_ip_hash_module_ctx = {
[50]     NULL,                                  /* preconfiguration */
[51]     NULL,                                  /* postconfiguration */
[52] 
[53]     NULL,                                  /* create main configuration */
[54]     NULL,                                  /* init main configuration */
[55] 
[56]     NULL,                                  /* create server configuration */
[57]     NULL,                                  /* merge server configuration */
[58] 
[59]     NULL,                                  /* create location configuration */
[60]     NULL                                   /* merge location configuration */
[61] };
[62] 
[63] 
[64] ngx_module_t  ngx_http_upstream_ip_hash_module = {
[65]     NGX_MODULE_V1,
[66]     &ngx_http_upstream_ip_hash_module_ctx, /* module context */
[67]     ngx_http_upstream_ip_hash_commands,    /* module directives */
[68]     NGX_HTTP_MODULE,                       /* module type */
[69]     NULL,                                  /* init master */
[70]     NULL,                                  /* init module */
[71]     NULL,                                  /* init process */
[72]     NULL,                                  /* init thread */
[73]     NULL,                                  /* exit thread */
[74]     NULL,                                  /* exit process */
[75]     NULL,                                  /* exit master */
[76]     NGX_MODULE_V1_PADDING
[77] };
[78] 
[79] 
[80] static u_char ngx_http_upstream_ip_hash_pseudo_addr[3];
[81] 
[82] 
[83] static ngx_int_t
[84] ngx_http_upstream_init_ip_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
[85] {
[86]     if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
[87]         return NGX_ERROR;
[88]     }
[89] 
[90]     us->peer.init = ngx_http_upstream_init_ip_hash_peer;
[91] 
[92]     return NGX_OK;
[93] }
[94] 
[95] 
[96] static ngx_int_t
[97] ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
[98]     ngx_http_upstream_srv_conf_t *us)
[99] {
[100]     struct sockaddr_in                     *sin;
[101] #if (NGX_HAVE_INET6)
[102]     struct sockaddr_in6                    *sin6;
[103] #endif
[104]     ngx_http_upstream_ip_hash_peer_data_t  *iphp;
[105] 
[106]     iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ip_hash_peer_data_t));
[107]     if (iphp == NULL) {
[108]         return NGX_ERROR;
[109]     }
[110] 
[111]     r->upstream->peer.data = &iphp->rrp;
[112] 
[113]     if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
[114]         return NGX_ERROR;
[115]     }
[116] 
[117]     r->upstream->peer.get = ngx_http_upstream_get_ip_hash_peer;
[118] 
[119]     switch (r->connection->sockaddr->sa_family) {
[120] 
[121]     case AF_INET:
[122]         sin = (struct sockaddr_in *) r->connection->sockaddr;
[123]         iphp->addr = (u_char *) &sin->sin_addr.s_addr;
[124]         iphp->addrlen = 3;
[125]         break;
[126] 
[127] #if (NGX_HAVE_INET6)
[128]     case AF_INET6:
[129]         sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
[130]         iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
[131]         iphp->addrlen = 16;
[132]         break;
[133] #endif
[134] 
[135]     default:
[136]         iphp->addr = ngx_http_upstream_ip_hash_pseudo_addr;
[137]         iphp->addrlen = 3;
[138]     }
[139] 
[140]     iphp->hash = 89;
[141]     iphp->tries = 0;
[142]     iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
[143] 
[144]     return NGX_OK;
[145] }
[146] 
[147] 
[148] static ngx_int_t
[149] ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
[150] {
[151]     ngx_http_upstream_ip_hash_peer_data_t  *iphp = data;
[152] 
[153]     time_t                        now;
[154]     ngx_int_t                     w;
[155]     uintptr_t                     m;
[156]     ngx_uint_t                    i, n, p, hash;
[157]     ngx_http_upstream_rr_peer_t  *peer;
[158] 
[159]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[160]                    "get ip hash peer, try: %ui", pc->tries);
[161] 
[162]     /* TODO: cached */
[163] 
[164]     ngx_http_upstream_rr_peers_rlock(iphp->rrp.peers);
[165] 
[166]     if (iphp->tries > 20 || iphp->rrp.peers->single) {
[167]         ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
[168]         return iphp->get_rr_peer(pc, &iphp->rrp);
[169]     }
[170] 
[171]     now = ngx_time();
[172] 
[173]     pc->cached = 0;
[174]     pc->connection = NULL;
[175] 
[176]     hash = iphp->hash;
[177] 
[178]     for ( ;; ) {
[179] 
[180]         for (i = 0; i < (ngx_uint_t) iphp->addrlen; i++) {
[181]             hash = (hash * 113 + iphp->addr[i]) % 6271;
[182]         }
[183] 
[184]         w = hash % iphp->rrp.peers->total_weight;
[185]         peer = iphp->rrp.peers->peer;
[186]         p = 0;
[187] 
[188]         while (w >= peer->weight) {
[189]             w -= peer->weight;
[190]             peer = peer->next;
[191]             p++;
[192]         }
[193] 
[194]         n = p / (8 * sizeof(uintptr_t));
[195]         m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
[196] 
[197]         if (iphp->rrp.tried[n] & m) {
[198]             goto next;
[199]         }
[200] 
[201]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[202]                        "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);
[203] 
[204]         ngx_http_upstream_rr_peer_lock(iphp->rrp.peers, peer);
[205] 
[206]         if (peer->down) {
[207]             ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
[208]             goto next;
[209]         }
[210] 
[211]         if (peer->max_fails
[212]             && peer->fails >= peer->max_fails
[213]             && now - peer->checked <= peer->fail_timeout)
[214]         {
[215]             ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
[216]             goto next;
[217]         }
[218] 
[219]         if (peer->max_conns && peer->conns >= peer->max_conns) {
[220]             ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
[221]             goto next;
[222]         }
[223] 
[224]         break;
[225] 
[226]     next:
[227] 
[228]         if (++iphp->tries > 20) {
[229]             ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
[230]             return iphp->get_rr_peer(pc, &iphp->rrp);
[231]         }
[232]     }
[233] 
[234]     iphp->rrp.current = peer;
[235] 
[236]     pc->sockaddr = peer->sockaddr;
[237]     pc->socklen = peer->socklen;
[238]     pc->name = &peer->name;
[239] 
[240]     peer->conns++;
[241] 
[242]     if (now - peer->checked > peer->fail_timeout) {
[243]         peer->checked = now;
[244]     }
[245] 
[246]     ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
[247]     ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
[248] 
[249]     iphp->rrp.tried[n] |= m;
[250]     iphp->hash = hash;
[251] 
[252]     return NGX_OK;
[253] }
[254] 
[255] 
[256] static char *
[257] ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[258] {
[259]     ngx_http_upstream_srv_conf_t  *uscf;
[260] 
[261]     uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
[262] 
[263]     if (uscf->peer.init_upstream) {
[264]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[265]                            "load balancing method redefined");
[266]     }
[267] 
[268]     uscf->peer.init_upstream = ngx_http_upstream_init_ip_hash;
[269] 
[270]     uscf->flags = NGX_HTTP_UPSTREAM_CREATE
[271]                   |NGX_HTTP_UPSTREAM_WEIGHT
[272]                   |NGX_HTTP_UPSTREAM_MAX_CONNS
[273]                   |NGX_HTTP_UPSTREAM_MAX_FAILS
[274]                   |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
[275]                   |NGX_HTTP_UPSTREAM_DOWN;
[276] 
[277]     return NGX_CONF_OK;
[278] }
