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
[13] typedef struct {
[14]     ngx_uint_t                         max_cached;
[15]     ngx_uint_t                         requests;
[16]     ngx_msec_t                         time;
[17]     ngx_msec_t                         timeout;
[18] 
[19]     ngx_queue_t                        cache;
[20]     ngx_queue_t                        free;
[21] 
[22]     ngx_http_upstream_init_pt          original_init_upstream;
[23]     ngx_http_upstream_init_peer_pt     original_init_peer;
[24] 
[25] } ngx_http_upstream_keepalive_srv_conf_t;
[26] 
[27] 
[28] typedef struct {
[29]     ngx_http_upstream_keepalive_srv_conf_t  *conf;
[30] 
[31]     ngx_queue_t                        queue;
[32]     ngx_connection_t                  *connection;
[33] 
[34]     socklen_t                          socklen;
[35]     ngx_sockaddr_t                     sockaddr;
[36] 
[37] } ngx_http_upstream_keepalive_cache_t;
[38] 
[39] 
[40] typedef struct {
[41]     ngx_http_upstream_keepalive_srv_conf_t  *conf;
[42] 
[43]     ngx_http_upstream_t               *upstream;
[44] 
[45]     void                              *data;
[46] 
[47]     ngx_event_get_peer_pt              original_get_peer;
[48]     ngx_event_free_peer_pt             original_free_peer;
[49] 
[50] #if (NGX_HTTP_SSL)
[51]     ngx_event_set_peer_session_pt      original_set_session;
[52]     ngx_event_save_peer_session_pt     original_save_session;
[53] #endif
[54] 
[55] } ngx_http_upstream_keepalive_peer_data_t;
[56] 
[57] 
[58] static ngx_int_t ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
[59]     ngx_http_upstream_srv_conf_t *us);
[60] static ngx_int_t ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
[61]     void *data);
[62] static void ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
[63]     void *data, ngx_uint_t state);
[64] 
[65] static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
[66] static void ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
[67] static void ngx_http_upstream_keepalive_close(ngx_connection_t *c);
[68] 
[69] #if (NGX_HTTP_SSL)
[70] static ngx_int_t ngx_http_upstream_keepalive_set_session(
[71]     ngx_peer_connection_t *pc, void *data);
[72] static void ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
[73]     void *data);
[74] #endif
[75] 
[76] static void *ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf);
[77] static char *ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
[78]     void *conf);
[79] 
[80] 
[81] static ngx_command_t  ngx_http_upstream_keepalive_commands[] = {
[82] 
[83]     { ngx_string("keepalive"),
[84]       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
[85]       ngx_http_upstream_keepalive,
[86]       NGX_HTTP_SRV_CONF_OFFSET,
[87]       0,
[88]       NULL },
[89] 
[90]     { ngx_string("keepalive_time"),
[91]       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
[92]       ngx_conf_set_msec_slot,
[93]       NGX_HTTP_SRV_CONF_OFFSET,
[94]       offsetof(ngx_http_upstream_keepalive_srv_conf_t, time),
[95]       NULL },
[96] 
[97]     { ngx_string("keepalive_timeout"),
[98]       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
[99]       ngx_conf_set_msec_slot,
[100]       NGX_HTTP_SRV_CONF_OFFSET,
[101]       offsetof(ngx_http_upstream_keepalive_srv_conf_t, timeout),
[102]       NULL },
[103] 
[104]     { ngx_string("keepalive_requests"),
[105]       NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
[106]       ngx_conf_set_num_slot,
[107]       NGX_HTTP_SRV_CONF_OFFSET,
[108]       offsetof(ngx_http_upstream_keepalive_srv_conf_t, requests),
[109]       NULL },
[110] 
[111]       ngx_null_command
[112] };
[113] 
[114] 
[115] static ngx_http_module_t  ngx_http_upstream_keepalive_module_ctx = {
[116]     NULL,                                  /* preconfiguration */
[117]     NULL,                                  /* postconfiguration */
[118] 
[119]     NULL,                                  /* create main configuration */
[120]     NULL,                                  /* init main configuration */
[121] 
[122]     ngx_http_upstream_keepalive_create_conf, /* create server configuration */
[123]     NULL,                                  /* merge server configuration */
[124] 
[125]     NULL,                                  /* create location configuration */
[126]     NULL                                   /* merge location configuration */
[127] };
[128] 
[129] 
[130] ngx_module_t  ngx_http_upstream_keepalive_module = {
[131]     NGX_MODULE_V1,
[132]     &ngx_http_upstream_keepalive_module_ctx, /* module context */
[133]     ngx_http_upstream_keepalive_commands,    /* module directives */
[134]     NGX_HTTP_MODULE,                       /* module type */
[135]     NULL,                                  /* init master */
[136]     NULL,                                  /* init module */
[137]     NULL,                                  /* init process */
[138]     NULL,                                  /* init thread */
[139]     NULL,                                  /* exit thread */
[140]     NULL,                                  /* exit process */
[141]     NULL,                                  /* exit master */
[142]     NGX_MODULE_V1_PADDING
[143] };
[144] 
[145] 
[146] static ngx_int_t
[147] ngx_http_upstream_init_keepalive(ngx_conf_t *cf,
[148]     ngx_http_upstream_srv_conf_t *us)
[149] {
[150]     ngx_uint_t                               i;
[151]     ngx_http_upstream_keepalive_srv_conf_t  *kcf;
[152]     ngx_http_upstream_keepalive_cache_t     *cached;
[153] 
[154]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
[155]                    "init keepalive");
[156] 
[157]     kcf = ngx_http_conf_upstream_srv_conf(us,
[158]                                           ngx_http_upstream_keepalive_module);
[159] 
[160]     ngx_conf_init_msec_value(kcf->time, 3600000);
[161]     ngx_conf_init_msec_value(kcf->timeout, 60000);
[162]     ngx_conf_init_uint_value(kcf->requests, 1000);
[163] 
[164]     if (kcf->original_init_upstream(cf, us) != NGX_OK) {
[165]         return NGX_ERROR;
[166]     }
[167] 
[168]     kcf->original_init_peer = us->peer.init;
[169] 
[170]     us->peer.init = ngx_http_upstream_init_keepalive_peer;
[171] 
[172]     /* allocate cache items and add to free queue */
[173] 
[174]     cached = ngx_pcalloc(cf->pool,
[175]                 sizeof(ngx_http_upstream_keepalive_cache_t) * kcf->max_cached);
[176]     if (cached == NULL) {
[177]         return NGX_ERROR;
[178]     }
[179] 
[180]     ngx_queue_init(&kcf->cache);
[181]     ngx_queue_init(&kcf->free);
[182] 
[183]     for (i = 0; i < kcf->max_cached; i++) {
[184]         ngx_queue_insert_head(&kcf->free, &cached[i].queue);
[185]         cached[i].conf = kcf;
[186]     }
[187] 
[188]     return NGX_OK;
[189] }
[190] 
[191] 
[192] static ngx_int_t
[193] ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
[194]     ngx_http_upstream_srv_conf_t *us)
[195] {
[196]     ngx_http_upstream_keepalive_peer_data_t  *kp;
[197]     ngx_http_upstream_keepalive_srv_conf_t   *kcf;
[198] 
[199]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[200]                    "init keepalive peer");
[201] 
[202]     kcf = ngx_http_conf_upstream_srv_conf(us,
[203]                                           ngx_http_upstream_keepalive_module);
[204] 
[205]     kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_keepalive_peer_data_t));
[206]     if (kp == NULL) {
[207]         return NGX_ERROR;
[208]     }
[209] 
[210]     if (kcf->original_init_peer(r, us) != NGX_OK) {
[211]         return NGX_ERROR;
[212]     }
[213] 
[214]     kp->conf = kcf;
[215]     kp->upstream = r->upstream;
[216]     kp->data = r->upstream->peer.data;
[217]     kp->original_get_peer = r->upstream->peer.get;
[218]     kp->original_free_peer = r->upstream->peer.free;
[219] 
[220]     r->upstream->peer.data = kp;
[221]     r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;
[222]     r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer;
[223] 
[224] #if (NGX_HTTP_SSL)
[225]     kp->original_set_session = r->upstream->peer.set_session;
[226]     kp->original_save_session = r->upstream->peer.save_session;
[227]     r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
[228]     r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
[229] #endif
[230] 
[231]     return NGX_OK;
[232] }
[233] 
[234] 
[235] static ngx_int_t
[236] ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
[237] {
[238]     ngx_http_upstream_keepalive_peer_data_t  *kp = data;
[239]     ngx_http_upstream_keepalive_cache_t      *item;
[240] 
[241]     ngx_int_t          rc;
[242]     ngx_queue_t       *q, *cache;
[243]     ngx_connection_t  *c;
[244] 
[245]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[246]                    "get keepalive peer");
[247] 
[248]     /* ask balancer */
[249] 
[250]     rc = kp->original_get_peer(pc, kp->data);
[251] 
[252]     if (rc != NGX_OK) {
[253]         return rc;
[254]     }
[255] 
[256]     /* search cache for suitable connection */
[257] 
[258]     cache = &kp->conf->cache;
[259] 
[260]     for (q = ngx_queue_head(cache);
[261]          q != ngx_queue_sentinel(cache);
[262]          q = ngx_queue_next(q))
[263]     {
[264]         item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
[265]         c = item->connection;
[266] 
[267]         if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
[268]                          item->socklen, pc->socklen)
[269]             == 0)
[270]         {
[271]             ngx_queue_remove(q);
[272]             ngx_queue_insert_head(&kp->conf->free, q);
[273] 
[274]             goto found;
[275]         }
[276]     }
[277] 
[278]     return NGX_OK;
[279] 
[280] found:
[281] 
[282]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[283]                    "get keepalive peer: using connection %p", c);
[284] 
[285]     c->idle = 0;
[286]     c->sent = 0;
[287]     c->data = NULL;
[288]     c->log = pc->log;
[289]     c->read->log = pc->log;
[290]     c->write->log = pc->log;
[291]     c->pool->log = pc->log;
[292] 
[293]     if (c->read->timer_set) {
[294]         ngx_del_timer(c->read);
[295]     }
[296] 
[297]     pc->connection = c;
[298]     pc->cached = 1;
[299] 
[300]     return NGX_DONE;
[301] }
[302] 
[303] 
[304] static void
[305] ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
[306]     ngx_uint_t state)
[307] {
[308]     ngx_http_upstream_keepalive_peer_data_t  *kp = data;
[309]     ngx_http_upstream_keepalive_cache_t      *item;
[310] 
[311]     ngx_queue_t          *q;
[312]     ngx_connection_t     *c;
[313]     ngx_http_upstream_t  *u;
[314] 
[315]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[316]                    "free keepalive peer");
[317] 
[318]     /* cache valid connections */
[319] 
[320]     u = kp->upstream;
[321]     c = pc->connection;
[322] 
[323]     if (state & NGX_PEER_FAILED
[324]         || c == NULL
[325]         || c->read->eof
[326]         || c->read->error
[327]         || c->read->timedout
[328]         || c->write->error
[329]         || c->write->timedout)
[330]     {
[331]         goto invalid;
[332]     }
[333] 
[334]     if (c->requests >= kp->conf->requests) {
[335]         goto invalid;
[336]     }
[337] 
[338]     if (ngx_current_msec - c->start_time > kp->conf->time) {
[339]         goto invalid;
[340]     }
[341] 
[342]     if (!u->keepalive) {
[343]         goto invalid;
[344]     }
[345] 
[346]     if (!u->request_body_sent) {
[347]         goto invalid;
[348]     }
[349] 
[350]     if (ngx_terminate || ngx_exiting) {
[351]         goto invalid;
[352]     }
[353] 
[354]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[355]         goto invalid;
[356]     }
[357] 
[358]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
[359]                    "free keepalive peer: saving connection %p", c);
[360] 
[361]     if (ngx_queue_empty(&kp->conf->free)) {
[362] 
[363]         q = ngx_queue_last(&kp->conf->cache);
[364]         ngx_queue_remove(q);
[365] 
[366]         item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
[367] 
[368]         ngx_http_upstream_keepalive_close(item->connection);
[369] 
[370]     } else {
[371]         q = ngx_queue_head(&kp->conf->free);
[372]         ngx_queue_remove(q);
[373] 
[374]         item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
[375]     }
[376] 
[377]     ngx_queue_insert_head(&kp->conf->cache, q);
[378] 
[379]     item->connection = c;
[380] 
[381]     pc->connection = NULL;
[382] 
[383]     c->read->delayed = 0;
[384]     ngx_add_timer(c->read, kp->conf->timeout);
[385] 
[386]     if (c->write->timer_set) {
[387]         ngx_del_timer(c->write);
[388]     }
[389] 
[390]     c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
[391]     c->read->handler = ngx_http_upstream_keepalive_close_handler;
[392] 
[393]     c->data = item;
[394]     c->idle = 1;
[395]     c->log = ngx_cycle->log;
[396]     c->read->log = ngx_cycle->log;
[397]     c->write->log = ngx_cycle->log;
[398]     c->pool->log = ngx_cycle->log;
[399] 
[400]     item->socklen = pc->socklen;
[401]     ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);
[402] 
[403]     if (c->read->ready) {
[404]         ngx_http_upstream_keepalive_close_handler(c->read);
[405]     }
[406] 
[407] invalid:
[408] 
[409]     kp->original_free_peer(pc, kp->data, state);
[410] }
[411] 
[412] 
[413] static void
[414] ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
[415] {
[416]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
[417]                    "keepalive dummy handler");
[418] }
[419] 
[420] 
[421] static void
[422] ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
[423] {
[424]     ngx_http_upstream_keepalive_srv_conf_t  *conf;
[425]     ngx_http_upstream_keepalive_cache_t     *item;
[426] 
[427]     int                n;
[428]     char               buf[1];
[429]     ngx_connection_t  *c;
[430] 
[431]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
[432]                    "keepalive close handler");
[433] 
[434]     c = ev->data;
[435] 
[436]     if (c->close || c->read->timedout) {
[437]         goto close;
[438]     }
[439] 
[440]     n = recv(c->fd, buf, 1, MSG_PEEK);
[441] 
[442]     if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
[443]         ev->ready = 0;
[444] 
[445]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[446]             goto close;
[447]         }
[448] 
[449]         return;
[450]     }
[451] 
[452] close:
[453] 
[454]     item = c->data;
[455]     conf = item->conf;
[456] 
[457]     ngx_http_upstream_keepalive_close(c);
[458] 
[459]     ngx_queue_remove(&item->queue);
[460]     ngx_queue_insert_head(&conf->free, &item->queue);
[461] }
[462] 
[463] 
[464] static void
[465] ngx_http_upstream_keepalive_close(ngx_connection_t *c)
[466] {
[467] 
[468] #if (NGX_HTTP_SSL)
[469] 
[470]     if (c->ssl) {
[471]         c->ssl->no_wait_shutdown = 1;
[472]         c->ssl->no_send_shutdown = 1;
[473] 
[474]         if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
[475]             c->ssl->handler = ngx_http_upstream_keepalive_close;
[476]             return;
[477]         }
[478]     }
[479] 
[480] #endif
[481] 
[482]     ngx_destroy_pool(c->pool);
[483]     ngx_close_connection(c);
[484] }
[485] 
[486] 
[487] #if (NGX_HTTP_SSL)
[488] 
[489] static ngx_int_t
[490] ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
[491] {
[492]     ngx_http_upstream_keepalive_peer_data_t  *kp = data;
[493] 
[494]     return kp->original_set_session(pc, kp->data);
[495] }
[496] 
[497] 
[498] static void
[499] ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
[500] {
[501]     ngx_http_upstream_keepalive_peer_data_t  *kp = data;
[502] 
[503]     kp->original_save_session(pc, kp->data);
[504]     return;
[505] }
[506] 
[507] #endif
[508] 
[509] 
[510] static void *
[511] ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf)
[512] {
[513]     ngx_http_upstream_keepalive_srv_conf_t  *conf;
[514] 
[515]     conf = ngx_pcalloc(cf->pool,
[516]                        sizeof(ngx_http_upstream_keepalive_srv_conf_t));
[517]     if (conf == NULL) {
[518]         return NULL;
[519]     }
[520] 
[521]     /*
[522]      * set by ngx_pcalloc():
[523]      *
[524]      *     conf->original_init_upstream = NULL;
[525]      *     conf->original_init_peer = NULL;
[526]      *     conf->max_cached = 0;
[527]      */
[528] 
[529]     conf->time = NGX_CONF_UNSET_MSEC;
[530]     conf->timeout = NGX_CONF_UNSET_MSEC;
[531]     conf->requests = NGX_CONF_UNSET_UINT;
[532] 
[533]     return conf;
[534] }
[535] 
[536] 
[537] static char *
[538] ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[539] {
[540]     ngx_http_upstream_srv_conf_t            *uscf;
[541]     ngx_http_upstream_keepalive_srv_conf_t  *kcf = conf;
[542] 
[543]     ngx_int_t    n;
[544]     ngx_str_t   *value;
[545] 
[546]     if (kcf->max_cached) {
[547]         return "is duplicate";
[548]     }
[549] 
[550]     /* read options */
[551] 
[552]     value = cf->args->elts;
[553] 
[554]     n = ngx_atoi(value[1].data, value[1].len);
[555] 
[556]     if (n == NGX_ERROR || n == 0) {
[557]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[558]                            "invalid value \"%V\" in \"%V\" directive",
[559]                            &value[1], &cmd->name);
[560]         return NGX_CONF_ERROR;
[561]     }
[562] 
[563]     kcf->max_cached = n;
[564] 
[565]     /* init upstream handler */
[566] 
[567]     uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
[568] 
[569]     kcf->original_init_upstream = uscf->peer.init_upstream
[570]                                   ? uscf->peer.init_upstream
[571]                                   : ngx_http_upstream_init_round_robin;
[572] 
[573]     uscf->peer.init_upstream = ngx_http_upstream_init_keepalive;
[574] 
[575]     return NGX_CONF_OK;
[576] }
