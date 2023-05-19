[1] 
[2] /*
[3]  * Copyright (C) Ruslan Ermilov
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] static char *ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
[14]     void *conf);
[15] static ngx_int_t ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone,
[16]     void *data);
[17] static ngx_http_upstream_rr_peers_t *ngx_http_upstream_zone_copy_peers(
[18]     ngx_slab_pool_t *shpool, ngx_http_upstream_srv_conf_t *uscf);
[19] static ngx_http_upstream_rr_peer_t *ngx_http_upstream_zone_copy_peer(
[20]     ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peer_t *src);
[21] 
[22] 
[23] static ngx_command_t  ngx_http_upstream_zone_commands[] = {
[24] 
[25]     { ngx_string("zone"),
[26]       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
[27]       ngx_http_upstream_zone,
[28]       0,
[29]       0,
[30]       NULL },
[31] 
[32]       ngx_null_command
[33] };
[34] 
[35] 
[36] static ngx_http_module_t  ngx_http_upstream_zone_module_ctx = {
[37]     NULL,                                  /* preconfiguration */
[38]     NULL,                                  /* postconfiguration */
[39] 
[40]     NULL,                                  /* create main configuration */
[41]     NULL,                                  /* init main configuration */
[42] 
[43]     NULL,                                  /* create server configuration */
[44]     NULL,                                  /* merge server configuration */
[45] 
[46]     NULL,                                  /* create location configuration */
[47]     NULL                                   /* merge location configuration */
[48] };
[49] 
[50] 
[51] ngx_module_t  ngx_http_upstream_zone_module = {
[52]     NGX_MODULE_V1,
[53]     &ngx_http_upstream_zone_module_ctx,    /* module context */
[54]     ngx_http_upstream_zone_commands,       /* module directives */
[55]     NGX_HTTP_MODULE,                       /* module type */
[56]     NULL,                                  /* init master */
[57]     NULL,                                  /* init module */
[58]     NULL,                                  /* init process */
[59]     NULL,                                  /* init thread */
[60]     NULL,                                  /* exit thread */
[61]     NULL,                                  /* exit process */
[62]     NULL,                                  /* exit master */
[63]     NGX_MODULE_V1_PADDING
[64] };
[65] 
[66] 
[67] static char *
[68] ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[69] {
[70]     ssize_t                         size;
[71]     ngx_str_t                      *value;
[72]     ngx_http_upstream_srv_conf_t   *uscf;
[73]     ngx_http_upstream_main_conf_t  *umcf;
[74] 
[75]     uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
[76]     umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
[77] 
[78]     value = cf->args->elts;
[79] 
[80]     if (!value[1].len) {
[81]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[82]                            "invalid zone name \"%V\"", &value[1]);
[83]         return NGX_CONF_ERROR;
[84]     }
[85] 
[86]     if (cf->args->nelts == 3) {
[87]         size = ngx_parse_size(&value[2]);
[88] 
[89]         if (size == NGX_ERROR) {
[90]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[91]                                "invalid zone size \"%V\"", &value[2]);
[92]             return NGX_CONF_ERROR;
[93]         }
[94] 
[95]         if (size < (ssize_t) (8 * ngx_pagesize)) {
[96]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[97]                                "zone \"%V\" is too small", &value[1]);
[98]             return NGX_CONF_ERROR;
[99]         }
[100] 
[101]     } else {
[102]         size = 0;
[103]     }
[104] 
[105]     uscf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
[106]                                            &ngx_http_upstream_module);
[107]     if (uscf->shm_zone == NULL) {
[108]         return NGX_CONF_ERROR;
[109]     }
[110] 
[111]     uscf->shm_zone->init = ngx_http_upstream_init_zone;
[112]     uscf->shm_zone->data = umcf;
[113] 
[114]     uscf->shm_zone->noreuse = 1;
[115] 
[116]     return NGX_CONF_OK;
[117] }
[118] 
[119] 
[120] static ngx_int_t
[121] ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone, void *data)
[122] {
[123]     size_t                          len;
[124]     ngx_uint_t                      i;
[125]     ngx_slab_pool_t                *shpool;
[126]     ngx_http_upstream_rr_peers_t   *peers, **peersp;
[127]     ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
[128]     ngx_http_upstream_main_conf_t  *umcf;
[129] 
[130]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[131]     umcf = shm_zone->data;
[132]     uscfp = umcf->upstreams.elts;
[133] 
[134]     if (shm_zone->shm.exists) {
[135]         peers = shpool->data;
[136] 
[137]         for (i = 0; i < umcf->upstreams.nelts; i++) {
[138]             uscf = uscfp[i];
[139] 
[140]             if (uscf->shm_zone != shm_zone) {
[141]                 continue;
[142]             }
[143] 
[144]             uscf->peer.data = peers;
[145]             peers = peers->zone_next;
[146]         }
[147] 
[148]         return NGX_OK;
[149]     }
[150] 
[151]     len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;
[152] 
[153]     shpool->log_ctx = ngx_slab_alloc(shpool, len);
[154]     if (shpool->log_ctx == NULL) {
[155]         return NGX_ERROR;
[156]     }
[157] 
[158]     ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
[159]                 &shm_zone->shm.name);
[160] 
[161] 
[162]     /* copy peers to shared memory */
[163] 
[164]     peersp = (ngx_http_upstream_rr_peers_t **) (void *) &shpool->data;
[165] 
[166]     for (i = 0; i < umcf->upstreams.nelts; i++) {
[167]         uscf = uscfp[i];
[168] 
[169]         if (uscf->shm_zone != shm_zone) {
[170]             continue;
[171]         }
[172] 
[173]         peers = ngx_http_upstream_zone_copy_peers(shpool, uscf);
[174]         if (peers == NULL) {
[175]             return NGX_ERROR;
[176]         }
[177] 
[178]         *peersp = peers;
[179]         peersp = &peers->zone_next;
[180]     }
[181] 
[182]     return NGX_OK;
[183] }
[184] 
[185] 
[186] static ngx_http_upstream_rr_peers_t *
[187] ngx_http_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
[188]     ngx_http_upstream_srv_conf_t *uscf)
[189] {
[190]     ngx_str_t                     *name;
[191]     ngx_http_upstream_rr_peer_t   *peer, **peerp;
[192]     ngx_http_upstream_rr_peers_t  *peers, *backup;
[193] 
[194]     peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
[195]     if (peers == NULL) {
[196]         return NULL;
[197]     }
[198] 
[199]     ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_http_upstream_rr_peers_t));
[200] 
[201]     name = ngx_slab_alloc(shpool, sizeof(ngx_str_t));
[202]     if (name == NULL) {
[203]         return NULL;
[204]     }
[205] 
[206]     name->data = ngx_slab_alloc(shpool, peers->name->len);
[207]     if (name->data == NULL) {
[208]         return NULL;
[209]     }
[210] 
[211]     ngx_memcpy(name->data, peers->name->data, peers->name->len);
[212]     name->len = peers->name->len;
[213] 
[214]     peers->name = name;
[215] 
[216]     peers->shpool = shpool;
[217] 
[218]     for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
[219]         /* pool is unlocked */
[220]         peer = ngx_http_upstream_zone_copy_peer(peers, *peerp);
[221]         if (peer == NULL) {
[222]             return NULL;
[223]         }
[224] 
[225]         *peerp = peer;
[226]     }
[227] 
[228]     if (peers->next == NULL) {
[229]         goto done;
[230]     }
[231] 
[232]     backup = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
[233]     if (backup == NULL) {
[234]         return NULL;
[235]     }
[236] 
[237]     ngx_memcpy(backup, peers->next, sizeof(ngx_http_upstream_rr_peers_t));
[238] 
[239]     backup->name = name;
[240] 
[241]     backup->shpool = shpool;
[242] 
[243]     for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
[244]         /* pool is unlocked */
[245]         peer = ngx_http_upstream_zone_copy_peer(backup, *peerp);
[246]         if (peer == NULL) {
[247]             return NULL;
[248]         }
[249] 
[250]         *peerp = peer;
[251]     }
[252] 
[253]     peers->next = backup;
[254] 
[255] done:
[256] 
[257]     uscf->peer.data = peers;
[258] 
[259]     return peers;
[260] }
[261] 
[262] 
[263] static ngx_http_upstream_rr_peer_t *
[264] ngx_http_upstream_zone_copy_peer(ngx_http_upstream_rr_peers_t *peers,
[265]     ngx_http_upstream_rr_peer_t *src)
[266] {
[267]     ngx_slab_pool_t              *pool;
[268]     ngx_http_upstream_rr_peer_t  *dst;
[269] 
[270]     pool = peers->shpool;
[271] 
[272]     dst = ngx_slab_calloc_locked(pool, sizeof(ngx_http_upstream_rr_peer_t));
[273]     if (dst == NULL) {
[274]         return NULL;
[275]     }
[276] 
[277]     if (src) {
[278]         ngx_memcpy(dst, src, sizeof(ngx_http_upstream_rr_peer_t));
[279]         dst->sockaddr = NULL;
[280]         dst->name.data = NULL;
[281]         dst->server.data = NULL;
[282]     }
[283] 
[284]     dst->sockaddr = ngx_slab_calloc_locked(pool, sizeof(ngx_sockaddr_t));
[285]     if (dst->sockaddr == NULL) {
[286]         goto failed;
[287]     }
[288] 
[289]     dst->name.data = ngx_slab_calloc_locked(pool, NGX_SOCKADDR_STRLEN);
[290]     if (dst->name.data == NULL) {
[291]         goto failed;
[292]     }
[293] 
[294]     if (src) {
[295]         ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
[296]         ngx_memcpy(dst->name.data, src->name.data, src->name.len);
[297] 
[298]         dst->server.data = ngx_slab_alloc_locked(pool, src->server.len);
[299]         if (dst->server.data == NULL) {
[300]             goto failed;
[301]         }
[302] 
[303]         ngx_memcpy(dst->server.data, src->server.data, src->server.len);
[304]     }
[305] 
[306]     return dst;
[307] 
[308] failed:
[309] 
[310]     if (dst->server.data) {
[311]         ngx_slab_free_locked(pool, dst->server.data);
[312]     }
[313] 
[314]     if (dst->name.data) {
[315]         ngx_slab_free_locked(pool, dst->name.data);
[316]     }
[317] 
[318]     if (dst->sockaddr) {
[319]         ngx_slab_free_locked(pool, dst->sockaddr);
[320]     }
[321] 
[322]     ngx_slab_free_locked(pool, dst);
[323] 
[324]     return NULL;
[325] }
