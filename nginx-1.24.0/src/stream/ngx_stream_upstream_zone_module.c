[1] 
[2] /*
[3]  * Copyright (C) Ruslan Ermilov
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] static char *ngx_stream_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
[14]     void *conf);
[15] static ngx_int_t ngx_stream_upstream_init_zone(ngx_shm_zone_t *shm_zone,
[16]     void *data);
[17] static ngx_stream_upstream_rr_peers_t *ngx_stream_upstream_zone_copy_peers(
[18]     ngx_slab_pool_t *shpool, ngx_stream_upstream_srv_conf_t *uscf);
[19] static ngx_stream_upstream_rr_peer_t *ngx_stream_upstream_zone_copy_peer(
[20]     ngx_stream_upstream_rr_peers_t *peers, ngx_stream_upstream_rr_peer_t *src);
[21] 
[22] 
[23] static ngx_command_t  ngx_stream_upstream_zone_commands[] = {
[24] 
[25]     { ngx_string("zone"),
[26]       NGX_STREAM_UPS_CONF|NGX_CONF_TAKE12,
[27]       ngx_stream_upstream_zone,
[28]       0,
[29]       0,
[30]       NULL },
[31] 
[32]       ngx_null_command
[33] };
[34] 
[35] 
[36] static ngx_stream_module_t  ngx_stream_upstream_zone_module_ctx = {
[37]     NULL,                                  /* preconfiguration */
[38]     NULL,                                  /* postconfiguration */
[39] 
[40]     NULL,                                  /* create main configuration */
[41]     NULL,                                  /* init main configuration */
[42] 
[43]     NULL,                                  /* create server configuration */
[44]     NULL                                   /* merge server configuration */
[45] };
[46] 
[47] 
[48] ngx_module_t  ngx_stream_upstream_zone_module = {
[49]     NGX_MODULE_V1,
[50]     &ngx_stream_upstream_zone_module_ctx,  /* module context */
[51]     ngx_stream_upstream_zone_commands,     /* module directives */
[52]     NGX_STREAM_MODULE,                     /* module type */
[53]     NULL,                                  /* init master */
[54]     NULL,                                  /* init module */
[55]     NULL,                                  /* init process */
[56]     NULL,                                  /* init thread */
[57]     NULL,                                  /* exit thread */
[58]     NULL,                                  /* exit process */
[59]     NULL,                                  /* exit master */
[60]     NGX_MODULE_V1_PADDING
[61] };
[62] 
[63] 
[64] static char *
[65] ngx_stream_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[66] {
[67]     ssize_t                           size;
[68]     ngx_str_t                        *value;
[69]     ngx_stream_upstream_srv_conf_t   *uscf;
[70]     ngx_stream_upstream_main_conf_t  *umcf;
[71] 
[72]     uscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module);
[73]     umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);
[74] 
[75]     value = cf->args->elts;
[76] 
[77]     if (!value[1].len) {
[78]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[79]                            "invalid zone name \"%V\"", &value[1]);
[80]         return NGX_CONF_ERROR;
[81]     }
[82] 
[83]     if (cf->args->nelts == 3) {
[84]         size = ngx_parse_size(&value[2]);
[85] 
[86]         if (size == NGX_ERROR) {
[87]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[88]                                "invalid zone size \"%V\"", &value[2]);
[89]             return NGX_CONF_ERROR;
[90]         }
[91] 
[92]         if (size < (ssize_t) (8 * ngx_pagesize)) {
[93]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[94]                                "zone \"%V\" is too small", &value[1]);
[95]             return NGX_CONF_ERROR;
[96]         }
[97] 
[98]     } else {
[99]         size = 0;
[100]     }
[101] 
[102]     uscf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
[103]                                            &ngx_stream_upstream_module);
[104]     if (uscf->shm_zone == NULL) {
[105]         return NGX_CONF_ERROR;
[106]     }
[107] 
[108]     uscf->shm_zone->init = ngx_stream_upstream_init_zone;
[109]     uscf->shm_zone->data = umcf;
[110] 
[111]     uscf->shm_zone->noreuse = 1;
[112] 
[113]     return NGX_CONF_OK;
[114] }
[115] 
[116] 
[117] static ngx_int_t
[118] ngx_stream_upstream_init_zone(ngx_shm_zone_t *shm_zone, void *data)
[119] {
[120]     size_t                            len;
[121]     ngx_uint_t                        i;
[122]     ngx_slab_pool_t                  *shpool;
[123]     ngx_stream_upstream_rr_peers_t   *peers, **peersp;
[124]     ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
[125]     ngx_stream_upstream_main_conf_t  *umcf;
[126] 
[127]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[128]     umcf = shm_zone->data;
[129]     uscfp = umcf->upstreams.elts;
[130] 
[131]     if (shm_zone->shm.exists) {
[132]         peers = shpool->data;
[133] 
[134]         for (i = 0; i < umcf->upstreams.nelts; i++) {
[135]             uscf = uscfp[i];
[136] 
[137]             if (uscf->shm_zone != shm_zone) {
[138]                 continue;
[139]             }
[140] 
[141]             uscf->peer.data = peers;
[142]             peers = peers->zone_next;
[143]         }
[144] 
[145]         return NGX_OK;
[146]     }
[147] 
[148]     len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;
[149] 
[150]     shpool->log_ctx = ngx_slab_alloc(shpool, len);
[151]     if (shpool->log_ctx == NULL) {
[152]         return NGX_ERROR;
[153]     }
[154] 
[155]     ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
[156]                 &shm_zone->shm.name);
[157] 
[158] 
[159]     /* copy peers to shared memory */
[160] 
[161]     peersp = (ngx_stream_upstream_rr_peers_t **) (void *) &shpool->data;
[162] 
[163]     for (i = 0; i < umcf->upstreams.nelts; i++) {
[164]         uscf = uscfp[i];
[165] 
[166]         if (uscf->shm_zone != shm_zone) {
[167]             continue;
[168]         }
[169] 
[170]         peers = ngx_stream_upstream_zone_copy_peers(shpool, uscf);
[171]         if (peers == NULL) {
[172]             return NGX_ERROR;
[173]         }
[174] 
[175]         *peersp = peers;
[176]         peersp = &peers->zone_next;
[177]     }
[178] 
[179]     return NGX_OK;
[180] }
[181] 
[182] 
[183] static ngx_stream_upstream_rr_peers_t *
[184] ngx_stream_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
[185]     ngx_stream_upstream_srv_conf_t *uscf)
[186] {
[187]     ngx_str_t                       *name;
[188]     ngx_stream_upstream_rr_peer_t   *peer, **peerp;
[189]     ngx_stream_upstream_rr_peers_t  *peers, *backup;
[190] 
[191]     peers = ngx_slab_alloc(shpool, sizeof(ngx_stream_upstream_rr_peers_t));
[192]     if (peers == NULL) {
[193]         return NULL;
[194]     }
[195] 
[196]     ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_stream_upstream_rr_peers_t));
[197] 
[198]     name = ngx_slab_alloc(shpool, sizeof(ngx_str_t));
[199]     if (name == NULL) {
[200]         return NULL;
[201]     }
[202] 
[203]     name->data = ngx_slab_alloc(shpool, peers->name->len);
[204]     if (name->data == NULL) {
[205]         return NULL;
[206]     }
[207] 
[208]     ngx_memcpy(name->data, peers->name->data, peers->name->len);
[209]     name->len = peers->name->len;
[210] 
[211]     peers->name = name;
[212] 
[213]     peers->shpool = shpool;
[214] 
[215]     for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
[216]         /* pool is unlocked */
[217]         peer = ngx_stream_upstream_zone_copy_peer(peers, *peerp);
[218]         if (peer == NULL) {
[219]             return NULL;
[220]         }
[221] 
[222]         *peerp = peer;
[223]     }
[224] 
[225]     if (peers->next == NULL) {
[226]         goto done;
[227]     }
[228] 
[229]     backup = ngx_slab_alloc(shpool, sizeof(ngx_stream_upstream_rr_peers_t));
[230]     if (backup == NULL) {
[231]         return NULL;
[232]     }
[233] 
[234]     ngx_memcpy(backup, peers->next, sizeof(ngx_stream_upstream_rr_peers_t));
[235] 
[236]     backup->name = name;
[237] 
[238]     backup->shpool = shpool;
[239] 
[240]     for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
[241]         /* pool is unlocked */
[242]         peer = ngx_stream_upstream_zone_copy_peer(backup, *peerp);
[243]         if (peer == NULL) {
[244]             return NULL;
[245]         }
[246] 
[247]         *peerp = peer;
[248]     }
[249] 
[250]     peers->next = backup;
[251] 
[252] done:
[253] 
[254]     uscf->peer.data = peers;
[255] 
[256]     return peers;
[257] }
[258] 
[259] 
[260] static ngx_stream_upstream_rr_peer_t *
[261] ngx_stream_upstream_zone_copy_peer(ngx_stream_upstream_rr_peers_t *peers,
[262]     ngx_stream_upstream_rr_peer_t *src)
[263] {
[264]     ngx_slab_pool_t                *pool;
[265]     ngx_stream_upstream_rr_peer_t  *dst;
[266] 
[267]     pool = peers->shpool;
[268] 
[269]     dst = ngx_slab_calloc_locked(pool, sizeof(ngx_stream_upstream_rr_peer_t));
[270]     if (dst == NULL) {
[271]         return NULL;
[272]     }
[273] 
[274]     if (src) {
[275]         ngx_memcpy(dst, src, sizeof(ngx_stream_upstream_rr_peer_t));
[276]         dst->sockaddr = NULL;
[277]         dst->name.data = NULL;
[278]         dst->server.data = NULL;
[279]     }
[280] 
[281]     dst->sockaddr = ngx_slab_calloc_locked(pool, sizeof(ngx_sockaddr_t));
[282]     if (dst->sockaddr == NULL) {
[283]         goto failed;
[284]     }
[285] 
[286]     dst->name.data = ngx_slab_calloc_locked(pool, NGX_SOCKADDR_STRLEN);
[287]     if (dst->name.data == NULL) {
[288]         goto failed;
[289]     }
[290] 
[291]     if (src) {
[292]         ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
[293]         ngx_memcpy(dst->name.data, src->name.data, src->name.len);
[294] 
[295]         dst->server.data = ngx_slab_alloc_locked(pool, src->server.len);
[296]         if (dst->server.data == NULL) {
[297]             goto failed;
[298]         }
[299] 
[300]         ngx_memcpy(dst->server.data, src->server.data, src->server.len);
[301]     }
[302] 
[303]     return dst;
[304] 
[305] failed:
[306] 
[307]     if (dst->server.data) {
[308]         ngx_slab_free_locked(pool, dst->server.data);
[309]     }
[310] 
[311]     if (dst->name.data) {
[312]         ngx_slab_free_locked(pool, dst->name.data);
[313]     }
[314] 
[315]     if (dst->sockaddr) {
[316]         ngx_slab_free_locked(pool, dst->sockaddr);
[317]     }
[318] 
[319]     ngx_slab_free_locked(pool, dst);
[320] 
[321]     return NULL;
[322] }
