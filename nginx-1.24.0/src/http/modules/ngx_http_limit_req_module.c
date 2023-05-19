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
[13] #define NGX_HTTP_LIMIT_REQ_PASSED            1
[14] #define NGX_HTTP_LIMIT_REQ_DELAYED           2
[15] #define NGX_HTTP_LIMIT_REQ_REJECTED          3
[16] #define NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN   4
[17] #define NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN  5
[18] 
[19] 
[20] typedef struct {
[21]     u_char                       color;
[22]     u_char                       dummy;
[23]     u_short                      len;
[24]     ngx_queue_t                  queue;
[25]     ngx_msec_t                   last;
[26]     /* integer value, 1 corresponds to 0.001 r/s */
[27]     ngx_uint_t                   excess;
[28]     ngx_uint_t                   count;
[29]     u_char                       data[1];
[30] } ngx_http_limit_req_node_t;
[31] 
[32] 
[33] typedef struct {
[34]     ngx_rbtree_t                  rbtree;
[35]     ngx_rbtree_node_t             sentinel;
[36]     ngx_queue_t                   queue;
[37] } ngx_http_limit_req_shctx_t;
[38] 
[39] 
[40] typedef struct {
[41]     ngx_http_limit_req_shctx_t  *sh;
[42]     ngx_slab_pool_t             *shpool;
[43]     /* integer value, 1 corresponds to 0.001 r/s */
[44]     ngx_uint_t                   rate;
[45]     ngx_http_complex_value_t     key;
[46]     ngx_http_limit_req_node_t   *node;
[47] } ngx_http_limit_req_ctx_t;
[48] 
[49] 
[50] typedef struct {
[51]     ngx_shm_zone_t              *shm_zone;
[52]     /* integer value, 1 corresponds to 0.001 r/s */
[53]     ngx_uint_t                   burst;
[54]     ngx_uint_t                   delay;
[55] } ngx_http_limit_req_limit_t;
[56] 
[57] 
[58] typedef struct {
[59]     ngx_array_t                  limits;
[60]     ngx_uint_t                   limit_log_level;
[61]     ngx_uint_t                   delay_log_level;
[62]     ngx_uint_t                   status_code;
[63]     ngx_flag_t                   dry_run;
[64] } ngx_http_limit_req_conf_t;
[65] 
[66] 
[67] static void ngx_http_limit_req_delay(ngx_http_request_t *r);
[68] static ngx_int_t ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit,
[69]     ngx_uint_t hash, ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account);
[70] static ngx_msec_t ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits,
[71]     ngx_uint_t n, ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit);
[72] static void ngx_http_limit_req_unlock(ngx_http_limit_req_limit_t *limits,
[73]     ngx_uint_t n);
[74] static void ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx,
[75]     ngx_uint_t n);
[76] 
[77] static ngx_int_t ngx_http_limit_req_status_variable(ngx_http_request_t *r,
[78]     ngx_http_variable_value_t *v, uintptr_t data);
[79] static void *ngx_http_limit_req_create_conf(ngx_conf_t *cf);
[80] static char *ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent,
[81]     void *child);
[82] static char *ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd,
[83]     void *conf);
[84] static char *ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd,
[85]     void *conf);
[86] static ngx_int_t ngx_http_limit_req_add_variables(ngx_conf_t *cf);
[87] static ngx_int_t ngx_http_limit_req_init(ngx_conf_t *cf);
[88] 
[89] 
[90] static ngx_conf_enum_t  ngx_http_limit_req_log_levels[] = {
[91]     { ngx_string("info"), NGX_LOG_INFO },
[92]     { ngx_string("notice"), NGX_LOG_NOTICE },
[93]     { ngx_string("warn"), NGX_LOG_WARN },
[94]     { ngx_string("error"), NGX_LOG_ERR },
[95]     { ngx_null_string, 0 }
[96] };
[97] 
[98] 
[99] static ngx_conf_num_bounds_t  ngx_http_limit_req_status_bounds = {
[100]     ngx_conf_check_num_bounds, 400, 599
[101] };
[102] 
[103] 
[104] static ngx_command_t  ngx_http_limit_req_commands[] = {
[105] 
[106]     { ngx_string("limit_req_zone"),
[107]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
[108]       ngx_http_limit_req_zone,
[109]       0,
[110]       0,
[111]       NULL },
[112] 
[113]     { ngx_string("limit_req"),
[114]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[115]       ngx_http_limit_req,
[116]       NGX_HTTP_LOC_CONF_OFFSET,
[117]       0,
[118]       NULL },
[119] 
[120]     { ngx_string("limit_req_log_level"),
[121]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[122]       ngx_conf_set_enum_slot,
[123]       NGX_HTTP_LOC_CONF_OFFSET,
[124]       offsetof(ngx_http_limit_req_conf_t, limit_log_level),
[125]       &ngx_http_limit_req_log_levels },
[126] 
[127]     { ngx_string("limit_req_status"),
[128]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[129]       ngx_conf_set_num_slot,
[130]       NGX_HTTP_LOC_CONF_OFFSET,
[131]       offsetof(ngx_http_limit_req_conf_t, status_code),
[132]       &ngx_http_limit_req_status_bounds },
[133] 
[134]     { ngx_string("limit_req_dry_run"),
[135]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[136]       ngx_conf_set_flag_slot,
[137]       NGX_HTTP_LOC_CONF_OFFSET,
[138]       offsetof(ngx_http_limit_req_conf_t, dry_run),
[139]       NULL },
[140] 
[141]       ngx_null_command
[142] };
[143] 
[144] 
[145] static ngx_http_module_t  ngx_http_limit_req_module_ctx = {
[146]     ngx_http_limit_req_add_variables,      /* preconfiguration */
[147]     ngx_http_limit_req_init,               /* postconfiguration */
[148] 
[149]     NULL,                                  /* create main configuration */
[150]     NULL,                                  /* init main configuration */
[151] 
[152]     NULL,                                  /* create server configuration */
[153]     NULL,                                  /* merge server configuration */
[154] 
[155]     ngx_http_limit_req_create_conf,        /* create location configuration */
[156]     ngx_http_limit_req_merge_conf          /* merge location configuration */
[157] };
[158] 
[159] 
[160] ngx_module_t  ngx_http_limit_req_module = {
[161]     NGX_MODULE_V1,
[162]     &ngx_http_limit_req_module_ctx,        /* module context */
[163]     ngx_http_limit_req_commands,           /* module directives */
[164]     NGX_HTTP_MODULE,                       /* module type */
[165]     NULL,                                  /* init master */
[166]     NULL,                                  /* init module */
[167]     NULL,                                  /* init process */
[168]     NULL,                                  /* init thread */
[169]     NULL,                                  /* exit thread */
[170]     NULL,                                  /* exit process */
[171]     NULL,                                  /* exit master */
[172]     NGX_MODULE_V1_PADDING
[173] };
[174] 
[175] 
[176] static ngx_http_variable_t  ngx_http_limit_req_vars[] = {
[177] 
[178]     { ngx_string("limit_req_status"), NULL,
[179]       ngx_http_limit_req_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[180] 
[181]       ngx_http_null_variable
[182] };
[183] 
[184] 
[185] static ngx_str_t  ngx_http_limit_req_status[] = {
[186]     ngx_string("PASSED"),
[187]     ngx_string("DELAYED"),
[188]     ngx_string("REJECTED"),
[189]     ngx_string("DELAYED_DRY_RUN"),
[190]     ngx_string("REJECTED_DRY_RUN")
[191] };
[192] 
[193] 
[194] static ngx_int_t
[195] ngx_http_limit_req_handler(ngx_http_request_t *r)
[196] {
[197]     uint32_t                     hash;
[198]     ngx_str_t                    key;
[199]     ngx_int_t                    rc;
[200]     ngx_uint_t                   n, excess;
[201]     ngx_msec_t                   delay;
[202]     ngx_http_limit_req_ctx_t    *ctx;
[203]     ngx_http_limit_req_conf_t   *lrcf;
[204]     ngx_http_limit_req_limit_t  *limit, *limits;
[205] 
[206]     if (r->main->limit_req_status) {
[207]         return NGX_DECLINED;
[208]     }
[209] 
[210]     lrcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_module);
[211]     limits = lrcf->limits.elts;
[212] 
[213]     excess = 0;
[214] 
[215]     rc = NGX_DECLINED;
[216] 
[217] #if (NGX_SUPPRESS_WARN)
[218]     limit = NULL;
[219] #endif
[220] 
[221]     for (n = 0; n < lrcf->limits.nelts; n++) {
[222] 
[223]         limit = &limits[n];
[224] 
[225]         ctx = limit->shm_zone->data;
[226] 
[227]         if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
[228]             ngx_http_limit_req_unlock(limits, n);
[229]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[230]         }
[231] 
[232]         if (key.len == 0) {
[233]             continue;
[234]         }
[235] 
[236]         if (key.len > 65535) {
[237]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[238]                           "the value of the \"%V\" key "
[239]                           "is more than 65535 bytes: \"%V\"",
[240]                           &ctx->key.value, &key);
[241]             continue;
[242]         }
[243] 
[244]         hash = ngx_crc32_short(key.data, key.len);
[245] 
[246]         ngx_shmtx_lock(&ctx->shpool->mutex);
[247] 
[248]         rc = ngx_http_limit_req_lookup(limit, hash, &key, &excess,
[249]                                        (n == lrcf->limits.nelts - 1));
[250] 
[251]         ngx_shmtx_unlock(&ctx->shpool->mutex);
[252] 
[253]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[254]                        "limit_req[%ui]: %i %ui.%03ui",
[255]                        n, rc, excess / 1000, excess % 1000);
[256] 
[257]         if (rc != NGX_AGAIN) {
[258]             break;
[259]         }
[260]     }
[261] 
[262]     if (rc == NGX_DECLINED) {
[263]         return NGX_DECLINED;
[264]     }
[265] 
[266]     if (rc == NGX_BUSY || rc == NGX_ERROR) {
[267] 
[268]         if (rc == NGX_BUSY) {
[269]             ngx_log_error(lrcf->limit_log_level, r->connection->log, 0,
[270]                         "limiting requests%s, excess: %ui.%03ui by zone \"%V\"",
[271]                         lrcf->dry_run ? ", dry run" : "",
[272]                         excess / 1000, excess % 1000,
[273]                         &limit->shm_zone->shm.name);
[274]         }
[275] 
[276]         ngx_http_limit_req_unlock(limits, n);
[277] 
[278]         if (lrcf->dry_run) {
[279]             r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN;
[280]             return NGX_DECLINED;
[281]         }
[282] 
[283]         r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_REJECTED;
[284] 
[285]         return lrcf->status_code;
[286]     }
[287] 
[288]     /* rc == NGX_AGAIN || rc == NGX_OK */
[289] 
[290]     if (rc == NGX_AGAIN) {
[291]         excess = 0;
[292]     }
[293] 
[294]     delay = ngx_http_limit_req_account(limits, n, &excess, &limit);
[295] 
[296]     if (!delay) {
[297]         r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_PASSED;
[298]         return NGX_DECLINED;
[299]     }
[300] 
[301]     ngx_log_error(lrcf->delay_log_level, r->connection->log, 0,
[302]                   "delaying request%s, excess: %ui.%03ui, by zone \"%V\"",
[303]                   lrcf->dry_run ? ", dry run" : "",
[304]                   excess / 1000, excess % 1000, &limit->shm_zone->shm.name);
[305] 
[306]     if (lrcf->dry_run) {
[307]         r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN;
[308]         return NGX_DECLINED;
[309]     }
[310] 
[311]     r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_DELAYED;
[312] 
[313]     if (r->connection->read->ready) {
[314]         ngx_post_event(r->connection->read, &ngx_posted_events);
[315] 
[316]     } else {
[317]         if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
[318]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[319]         }
[320]     }
[321] 
[322]     r->read_event_handler = ngx_http_test_reading;
[323]     r->write_event_handler = ngx_http_limit_req_delay;
[324] 
[325]     r->connection->write->delayed = 1;
[326]     ngx_add_timer(r->connection->write, delay);
[327] 
[328]     return NGX_AGAIN;
[329] }
[330] 
[331] 
[332] static void
[333] ngx_http_limit_req_delay(ngx_http_request_t *r)
[334] {
[335]     ngx_event_t  *wev;
[336] 
[337]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[338]                    "limit_req delay");
[339] 
[340]     wev = r->connection->write;
[341] 
[342]     if (wev->delayed) {
[343] 
[344]         if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[345]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[346]         }
[347] 
[348]         return;
[349]     }
[350] 
[351]     if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
[352]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[353]         return;
[354]     }
[355] 
[356]     r->read_event_handler = ngx_http_block_reading;
[357]     r->write_event_handler = ngx_http_core_run_phases;
[358] 
[359]     ngx_http_core_run_phases(r);
[360] }
[361] 
[362] 
[363] static void
[364] ngx_http_limit_req_rbtree_insert_value(ngx_rbtree_node_t *temp,
[365]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[366] {
[367]     ngx_rbtree_node_t          **p;
[368]     ngx_http_limit_req_node_t   *lrn, *lrnt;
[369] 
[370]     for ( ;; ) {
[371] 
[372]         if (node->key < temp->key) {
[373] 
[374]             p = &temp->left;
[375] 
[376]         } else if (node->key > temp->key) {
[377] 
[378]             p = &temp->right;
[379] 
[380]         } else { /* node->key == temp->key */
[381] 
[382]             lrn = (ngx_http_limit_req_node_t *) &node->color;
[383]             lrnt = (ngx_http_limit_req_node_t *) &temp->color;
[384] 
[385]             p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
[386]                 ? &temp->left : &temp->right;
[387]         }
[388] 
[389]         if (*p == sentinel) {
[390]             break;
[391]         }
[392] 
[393]         temp = *p;
[394]     }
[395] 
[396]     *p = node;
[397]     node->parent = temp;
[398]     node->left = sentinel;
[399]     node->right = sentinel;
[400]     ngx_rbt_red(node);
[401] }
[402] 
[403] 
[404] static ngx_int_t
[405] ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit, ngx_uint_t hash,
[406]     ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account)
[407] {
[408]     size_t                      size;
[409]     ngx_int_t                   rc, excess;
[410]     ngx_msec_t                  now;
[411]     ngx_msec_int_t              ms;
[412]     ngx_rbtree_node_t          *node, *sentinel;
[413]     ngx_http_limit_req_ctx_t   *ctx;
[414]     ngx_http_limit_req_node_t  *lr;
[415] 
[416]     now = ngx_current_msec;
[417] 
[418]     ctx = limit->shm_zone->data;
[419] 
[420]     node = ctx->sh->rbtree.root;
[421]     sentinel = ctx->sh->rbtree.sentinel;
[422] 
[423]     while (node != sentinel) {
[424] 
[425]         if (hash < node->key) {
[426]             node = node->left;
[427]             continue;
[428]         }
[429] 
[430]         if (hash > node->key) {
[431]             node = node->right;
[432]             continue;
[433]         }
[434] 
[435]         /* hash == node->key */
[436] 
[437]         lr = (ngx_http_limit_req_node_t *) &node->color;
[438] 
[439]         rc = ngx_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);
[440] 
[441]         if (rc == 0) {
[442]             ngx_queue_remove(&lr->queue);
[443]             ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);
[444] 
[445]             ms = (ngx_msec_int_t) (now - lr->last);
[446] 
[447]             if (ms < -60000) {
[448]                 ms = 1;
[449] 
[450]             } else if (ms < 0) {
[451]                 ms = 0;
[452]             }
[453] 
[454]             excess = lr->excess - ctx->rate * ms / 1000 + 1000;
[455] 
[456]             if (excess < 0) {
[457]                 excess = 0;
[458]             }
[459] 
[460]             *ep = excess;
[461] 
[462]             if ((ngx_uint_t) excess > limit->burst) {
[463]                 return NGX_BUSY;
[464]             }
[465] 
[466]             if (account) {
[467]                 lr->excess = excess;
[468] 
[469]                 if (ms) {
[470]                     lr->last = now;
[471]                 }
[472] 
[473]                 return NGX_OK;
[474]             }
[475] 
[476]             lr->count++;
[477] 
[478]             ctx->node = lr;
[479] 
[480]             return NGX_AGAIN;
[481]         }
[482] 
[483]         node = (rc < 0) ? node->left : node->right;
[484]     }
[485] 
[486]     *ep = 0;
[487] 
[488]     size = offsetof(ngx_rbtree_node_t, color)
[489]            + offsetof(ngx_http_limit_req_node_t, data)
[490]            + key->len;
[491] 
[492]     ngx_http_limit_req_expire(ctx, 1);
[493] 
[494]     node = ngx_slab_alloc_locked(ctx->shpool, size);
[495] 
[496]     if (node == NULL) {
[497]         ngx_http_limit_req_expire(ctx, 0);
[498] 
[499]         node = ngx_slab_alloc_locked(ctx->shpool, size);
[500]         if (node == NULL) {
[501]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[502]                           "could not allocate node%s", ctx->shpool->log_ctx);
[503]             return NGX_ERROR;
[504]         }
[505]     }
[506] 
[507]     node->key = hash;
[508] 
[509]     lr = (ngx_http_limit_req_node_t *) &node->color;
[510] 
[511]     lr->len = (u_short) key->len;
[512]     lr->excess = 0;
[513] 
[514]     ngx_memcpy(lr->data, key->data, key->len);
[515] 
[516]     ngx_rbtree_insert(&ctx->sh->rbtree, node);
[517] 
[518]     ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);
[519] 
[520]     if (account) {
[521]         lr->last = now;
[522]         lr->count = 0;
[523]         return NGX_OK;
[524]     }
[525] 
[526]     lr->last = 0;
[527]     lr->count = 1;
[528] 
[529]     ctx->node = lr;
[530] 
[531]     return NGX_AGAIN;
[532] }
[533] 
[534] 
[535] static ngx_msec_t
[536] ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits, ngx_uint_t n,
[537]     ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit)
[538] {
[539]     ngx_int_t                   excess;
[540]     ngx_msec_t                  now, delay, max_delay;
[541]     ngx_msec_int_t              ms;
[542]     ngx_http_limit_req_ctx_t   *ctx;
[543]     ngx_http_limit_req_node_t  *lr;
[544] 
[545]     excess = *ep;
[546] 
[547]     if ((ngx_uint_t) excess <= (*limit)->delay) {
[548]         max_delay = 0;
[549] 
[550]     } else {
[551]         ctx = (*limit)->shm_zone->data;
[552]         max_delay = (excess - (*limit)->delay) * 1000 / ctx->rate;
[553]     }
[554] 
[555]     while (n--) {
[556]         ctx = limits[n].shm_zone->data;
[557]         lr = ctx->node;
[558] 
[559]         if (lr == NULL) {
[560]             continue;
[561]         }
[562] 
[563]         ngx_shmtx_lock(&ctx->shpool->mutex);
[564] 
[565]         now = ngx_current_msec;
[566]         ms = (ngx_msec_int_t) (now - lr->last);
[567] 
[568]         if (ms < -60000) {
[569]             ms = 1;
[570] 
[571]         } else if (ms < 0) {
[572]             ms = 0;
[573]         }
[574] 
[575]         excess = lr->excess - ctx->rate * ms / 1000 + 1000;
[576] 
[577]         if (excess < 0) {
[578]             excess = 0;
[579]         }
[580] 
[581]         if (ms) {
[582]             lr->last = now;
[583]         }
[584] 
[585]         lr->excess = excess;
[586]         lr->count--;
[587] 
[588]         ngx_shmtx_unlock(&ctx->shpool->mutex);
[589] 
[590]         ctx->node = NULL;
[591] 
[592]         if ((ngx_uint_t) excess <= limits[n].delay) {
[593]             continue;
[594]         }
[595] 
[596]         delay = (excess - limits[n].delay) * 1000 / ctx->rate;
[597] 
[598]         if (delay > max_delay) {
[599]             max_delay = delay;
[600]             *ep = excess;
[601]             *limit = &limits[n];
[602]         }
[603]     }
[604] 
[605]     return max_delay;
[606] }
[607] 
[608] 
[609] static void
[610] ngx_http_limit_req_unlock(ngx_http_limit_req_limit_t *limits, ngx_uint_t n)
[611] {
[612]     ngx_http_limit_req_ctx_t  *ctx;
[613] 
[614]     while (n--) {
[615]         ctx = limits[n].shm_zone->data;
[616] 
[617]         if (ctx->node == NULL) {
[618]             continue;
[619]         }
[620] 
[621]         ngx_shmtx_lock(&ctx->shpool->mutex);
[622] 
[623]         ctx->node->count--;
[624] 
[625]         ngx_shmtx_unlock(&ctx->shpool->mutex);
[626] 
[627]         ctx->node = NULL;
[628]     }
[629] }
[630] 
[631] 
[632] static void
[633] ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx, ngx_uint_t n)
[634] {
[635]     ngx_int_t                   excess;
[636]     ngx_msec_t                  now;
[637]     ngx_queue_t                *q;
[638]     ngx_msec_int_t              ms;
[639]     ngx_rbtree_node_t          *node;
[640]     ngx_http_limit_req_node_t  *lr;
[641] 
[642]     now = ngx_current_msec;
[643] 
[644]     /*
[645]      * n == 1 deletes one or two zero rate entries
[646]      * n == 0 deletes oldest entry by force
[647]      *        and one or two zero rate entries
[648]      */
[649] 
[650]     while (n < 3) {
[651] 
[652]         if (ngx_queue_empty(&ctx->sh->queue)) {
[653]             return;
[654]         }
[655] 
[656]         q = ngx_queue_last(&ctx->sh->queue);
[657] 
[658]         lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);
[659] 
[660]         if (lr->count) {
[661] 
[662]             /*
[663]              * There is not much sense in looking further,
[664]              * because we bump nodes on the lookup stage.
[665]              */
[666] 
[667]             return;
[668]         }
[669] 
[670]         if (n++ != 0) {
[671] 
[672]             ms = (ngx_msec_int_t) (now - lr->last);
[673]             ms = ngx_abs(ms);
[674] 
[675]             if (ms < 60000) {
[676]                 return;
[677]             }
[678] 
[679]             excess = lr->excess - ctx->rate * ms / 1000;
[680] 
[681]             if (excess > 0) {
[682]                 return;
[683]             }
[684]         }
[685] 
[686]         ngx_queue_remove(q);
[687] 
[688]         node = (ngx_rbtree_node_t *)
[689]                    ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));
[690] 
[691]         ngx_rbtree_delete(&ctx->sh->rbtree, node);
[692] 
[693]         ngx_slab_free_locked(ctx->shpool, node);
[694]     }
[695] }
[696] 
[697] 
[698] static ngx_int_t
[699] ngx_http_limit_req_init_zone(ngx_shm_zone_t *shm_zone, void *data)
[700] {
[701]     ngx_http_limit_req_ctx_t  *octx = data;
[702] 
[703]     size_t                     len;
[704]     ngx_http_limit_req_ctx_t  *ctx;
[705] 
[706]     ctx = shm_zone->data;
[707] 
[708]     if (octx) {
[709]         if (ctx->key.value.len != octx->key.value.len
[710]             || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
[711]                            ctx->key.value.len)
[712]                != 0)
[713]         {
[714]             ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
[715]                           "limit_req \"%V\" uses the \"%V\" key "
[716]                           "while previously it used the \"%V\" key",
[717]                           &shm_zone->shm.name, &ctx->key.value,
[718]                           &octx->key.value);
[719]             return NGX_ERROR;
[720]         }
[721] 
[722]         ctx->sh = octx->sh;
[723]         ctx->shpool = octx->shpool;
[724] 
[725]         return NGX_OK;
[726]     }
[727] 
[728]     ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[729] 
[730]     if (shm_zone->shm.exists) {
[731]         ctx->sh = ctx->shpool->data;
[732] 
[733]         return NGX_OK;
[734]     }
[735] 
[736]     ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_shctx_t));
[737]     if (ctx->sh == NULL) {
[738]         return NGX_ERROR;
[739]     }
[740] 
[741]     ctx->shpool->data = ctx->sh;
[742] 
[743]     ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
[744]                     ngx_http_limit_req_rbtree_insert_value);
[745] 
[746]     ngx_queue_init(&ctx->sh->queue);
[747] 
[748]     len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;
[749] 
[750]     ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
[751]     if (ctx->shpool->log_ctx == NULL) {
[752]         return NGX_ERROR;
[753]     }
[754] 
[755]     ngx_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
[756]                 &shm_zone->shm.name);
[757] 
[758]     ctx->shpool->log_nomem = 0;
[759] 
[760]     return NGX_OK;
[761] }
[762] 
[763] 
[764] static ngx_int_t
[765] ngx_http_limit_req_status_variable(ngx_http_request_t *r,
[766]     ngx_http_variable_value_t *v, uintptr_t data)
[767] {
[768]     if (r->main->limit_req_status == 0) {
[769]         v->not_found = 1;
[770]         return NGX_OK;
[771]     }
[772] 
[773]     v->valid = 1;
[774]     v->no_cacheable = 0;
[775]     v->not_found = 0;
[776]     v->len = ngx_http_limit_req_status[r->main->limit_req_status - 1].len;
[777]     v->data = ngx_http_limit_req_status[r->main->limit_req_status - 1].data;
[778] 
[779]     return NGX_OK;
[780] }
[781] 
[782] 
[783] static void *
[784] ngx_http_limit_req_create_conf(ngx_conf_t *cf)
[785] {
[786]     ngx_http_limit_req_conf_t  *conf;
[787] 
[788]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_conf_t));
[789]     if (conf == NULL) {
[790]         return NULL;
[791]     }
[792] 
[793]     /*
[794]      * set by ngx_pcalloc():
[795]      *
[796]      *     conf->limits.elts = NULL;
[797]      */
[798] 
[799]     conf->limit_log_level = NGX_CONF_UNSET_UINT;
[800]     conf->status_code = NGX_CONF_UNSET_UINT;
[801]     conf->dry_run = NGX_CONF_UNSET;
[802] 
[803]     return conf;
[804] }
[805] 
[806] 
[807] static char *
[808] ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[809] {
[810]     ngx_http_limit_req_conf_t *prev = parent;
[811]     ngx_http_limit_req_conf_t *conf = child;
[812] 
[813]     if (conf->limits.elts == NULL) {
[814]         conf->limits = prev->limits;
[815]     }
[816] 
[817]     ngx_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
[818]                               NGX_LOG_ERR);
[819] 
[820]     conf->delay_log_level = (conf->limit_log_level == NGX_LOG_INFO) ?
[821]                                 NGX_LOG_INFO : conf->limit_log_level + 1;
[822] 
[823]     ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
[824]                               NGX_HTTP_SERVICE_UNAVAILABLE);
[825] 
[826]     ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);
[827] 
[828]     return NGX_CONF_OK;
[829] }
[830] 
[831] 
[832] static char *
[833] ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[834] {
[835]     u_char                            *p;
[836]     size_t                             len;
[837]     ssize_t                            size;
[838]     ngx_str_t                         *value, name, s;
[839]     ngx_int_t                          rate, scale;
[840]     ngx_uint_t                         i;
[841]     ngx_shm_zone_t                    *shm_zone;
[842]     ngx_http_limit_req_ctx_t          *ctx;
[843]     ngx_http_compile_complex_value_t   ccv;
[844] 
[845]     value = cf->args->elts;
[846] 
[847]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_ctx_t));
[848]     if (ctx == NULL) {
[849]         return NGX_CONF_ERROR;
[850]     }
[851] 
[852]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[853] 
[854]     ccv.cf = cf;
[855]     ccv.value = &value[1];
[856]     ccv.complex_value = &ctx->key;
[857] 
[858]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[859]         return NGX_CONF_ERROR;
[860]     }
[861] 
[862]     size = 0;
[863]     rate = 1;
[864]     scale = 1;
[865]     name.len = 0;
[866] 
[867]     for (i = 2; i < cf->args->nelts; i++) {
[868] 
[869]         if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
[870] 
[871]             name.data = value[i].data + 5;
[872] 
[873]             p = (u_char *) ngx_strchr(name.data, ':');
[874] 
[875]             if (p == NULL) {
[876]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[877]                                    "invalid zone size \"%V\"", &value[i]);
[878]                 return NGX_CONF_ERROR;
[879]             }
[880] 
[881]             name.len = p - name.data;
[882] 
[883]             s.data = p + 1;
[884]             s.len = value[i].data + value[i].len - s.data;
[885] 
[886]             size = ngx_parse_size(&s);
[887] 
[888]             if (size == NGX_ERROR) {
[889]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[890]                                    "invalid zone size \"%V\"", &value[i]);
[891]                 return NGX_CONF_ERROR;
[892]             }
[893] 
[894]             if (size < (ssize_t) (8 * ngx_pagesize)) {
[895]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[896]                                    "zone \"%V\" is too small", &value[i]);
[897]                 return NGX_CONF_ERROR;
[898]             }
[899] 
[900]             continue;
[901]         }
[902] 
[903]         if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {
[904] 
[905]             len = value[i].len;
[906]             p = value[i].data + len - 3;
[907] 
[908]             if (ngx_strncmp(p, "r/s", 3) == 0) {
[909]                 scale = 1;
[910]                 len -= 3;
[911] 
[912]             } else if (ngx_strncmp(p, "r/m", 3) == 0) {
[913]                 scale = 60;
[914]                 len -= 3;
[915]             }
[916] 
[917]             rate = ngx_atoi(value[i].data + 5, len - 5);
[918]             if (rate <= 0) {
[919]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[920]                                    "invalid rate \"%V\"", &value[i]);
[921]                 return NGX_CONF_ERROR;
[922]             }
[923] 
[924]             continue;
[925]         }
[926] 
[927]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[928]                            "invalid parameter \"%V\"", &value[i]);
[929]         return NGX_CONF_ERROR;
[930]     }
[931] 
[932]     if (name.len == 0) {
[933]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[934]                            "\"%V\" must have \"zone\" parameter",
[935]                            &cmd->name);
[936]         return NGX_CONF_ERROR;
[937]     }
[938] 
[939]     ctx->rate = rate * 1000 / scale;
[940] 
[941]     shm_zone = ngx_shared_memory_add(cf, &name, size,
[942]                                      &ngx_http_limit_req_module);
[943]     if (shm_zone == NULL) {
[944]         return NGX_CONF_ERROR;
[945]     }
[946] 
[947]     if (shm_zone->data) {
[948]         ctx = shm_zone->data;
[949] 
[950]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[951]                            "%V \"%V\" is already bound to key \"%V\"",
[952]                            &cmd->name, &name, &ctx->key.value);
[953]         return NGX_CONF_ERROR;
[954]     }
[955] 
[956]     shm_zone->init = ngx_http_limit_req_init_zone;
[957]     shm_zone->data = ctx;
[958] 
[959]     return NGX_CONF_OK;
[960] }
[961] 
[962] 
[963] static char *
[964] ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[965] {
[966]     ngx_http_limit_req_conf_t  *lrcf = conf;
[967] 
[968]     ngx_int_t                    burst, delay;
[969]     ngx_str_t                   *value, s;
[970]     ngx_uint_t                   i;
[971]     ngx_shm_zone_t              *shm_zone;
[972]     ngx_http_limit_req_limit_t  *limit, *limits;
[973] 
[974]     value = cf->args->elts;
[975] 
[976]     shm_zone = NULL;
[977]     burst = 0;
[978]     delay = 0;
[979] 
[980]     for (i = 1; i < cf->args->nelts; i++) {
[981] 
[982]         if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
[983] 
[984]             s.len = value[i].len - 5;
[985]             s.data = value[i].data + 5;
[986] 
[987]             shm_zone = ngx_shared_memory_add(cf, &s, 0,
[988]                                              &ngx_http_limit_req_module);
[989]             if (shm_zone == NULL) {
[990]                 return NGX_CONF_ERROR;
[991]             }
[992] 
[993]             continue;
[994]         }
[995] 
[996]         if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {
[997] 
[998]             burst = ngx_atoi(value[i].data + 6, value[i].len - 6);
[999]             if (burst <= 0) {
[1000]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1001]                                    "invalid burst value \"%V\"", &value[i]);
[1002]                 return NGX_CONF_ERROR;
[1003]             }
[1004] 
[1005]             continue;
[1006]         }
[1007] 
[1008]         if (ngx_strncmp(value[i].data, "delay=", 6) == 0) {
[1009] 
[1010]             delay = ngx_atoi(value[i].data + 6, value[i].len - 6);
[1011]             if (delay <= 0) {
[1012]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1013]                                    "invalid delay value \"%V\"", &value[i]);
[1014]                 return NGX_CONF_ERROR;
[1015]             }
[1016] 
[1017]             continue;
[1018]         }
[1019] 
[1020]         if (ngx_strcmp(value[i].data, "nodelay") == 0) {
[1021]             delay = NGX_MAX_INT_T_VALUE / 1000;
[1022]             continue;
[1023]         }
[1024] 
[1025]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1026]                            "invalid parameter \"%V\"", &value[i]);
[1027]         return NGX_CONF_ERROR;
[1028]     }
[1029] 
[1030]     if (shm_zone == NULL) {
[1031]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1032]                            "\"%V\" must have \"zone\" parameter",
[1033]                            &cmd->name);
[1034]         return NGX_CONF_ERROR;
[1035]     }
[1036] 
[1037]     limits = lrcf->limits.elts;
[1038] 
[1039]     if (limits == NULL) {
[1040]         if (ngx_array_init(&lrcf->limits, cf->pool, 1,
[1041]                            sizeof(ngx_http_limit_req_limit_t))
[1042]             != NGX_OK)
[1043]         {
[1044]             return NGX_CONF_ERROR;
[1045]         }
[1046]     }
[1047] 
[1048]     for (i = 0; i < lrcf->limits.nelts; i++) {
[1049]         if (shm_zone == limits[i].shm_zone) {
[1050]             return "is duplicate";
[1051]         }
[1052]     }
[1053] 
[1054]     limit = ngx_array_push(&lrcf->limits);
[1055]     if (limit == NULL) {
[1056]         return NGX_CONF_ERROR;
[1057]     }
[1058] 
[1059]     limit->shm_zone = shm_zone;
[1060]     limit->burst = burst * 1000;
[1061]     limit->delay = delay * 1000;
[1062] 
[1063]     return NGX_CONF_OK;
[1064] }
[1065] 
[1066] 
[1067] static ngx_int_t
[1068] ngx_http_limit_req_add_variables(ngx_conf_t *cf)
[1069] {
[1070]     ngx_http_variable_t  *var, *v;
[1071] 
[1072]     for (v = ngx_http_limit_req_vars; v->name.len; v++) {
[1073]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[1074]         if (var == NULL) {
[1075]             return NGX_ERROR;
[1076]         }
[1077] 
[1078]         var->get_handler = v->get_handler;
[1079]         var->data = v->data;
[1080]     }
[1081] 
[1082]     return NGX_OK;
[1083] }
[1084] 
[1085] 
[1086] static ngx_int_t
[1087] ngx_http_limit_req_init(ngx_conf_t *cf)
[1088] {
[1089]     ngx_http_handler_pt        *h;
[1090]     ngx_http_core_main_conf_t  *cmcf;
[1091] 
[1092]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[1093] 
[1094]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
[1095]     if (h == NULL) {
[1096]         return NGX_ERROR;
[1097]     }
[1098] 
[1099]     *h = ngx_http_limit_req_handler;
[1100] 
[1101]     return NGX_OK;
[1102] }
