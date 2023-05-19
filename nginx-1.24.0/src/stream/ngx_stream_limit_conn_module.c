[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] #define NGX_STREAM_LIMIT_CONN_PASSED            1
[14] #define NGX_STREAM_LIMIT_CONN_REJECTED          2
[15] #define NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN  3
[16] 
[17] 
[18] typedef struct {
[19]     u_char                          color;
[20]     u_char                          len;
[21]     u_short                         conn;
[22]     u_char                          data[1];
[23] } ngx_stream_limit_conn_node_t;
[24] 
[25] 
[26] typedef struct {
[27]     ngx_shm_zone_t                 *shm_zone;
[28]     ngx_rbtree_node_t              *node;
[29] } ngx_stream_limit_conn_cleanup_t;
[30] 
[31] 
[32] typedef struct {
[33]     ngx_rbtree_t                    rbtree;
[34]     ngx_rbtree_node_t               sentinel;
[35] } ngx_stream_limit_conn_shctx_t;
[36] 
[37] 
[38] typedef struct {
[39]     ngx_stream_limit_conn_shctx_t  *sh;
[40]     ngx_slab_pool_t                *shpool;
[41]     ngx_stream_complex_value_t      key;
[42] } ngx_stream_limit_conn_ctx_t;
[43] 
[44] 
[45] typedef struct {
[46]     ngx_shm_zone_t                 *shm_zone;
[47]     ngx_uint_t                      conn;
[48] } ngx_stream_limit_conn_limit_t;
[49] 
[50] 
[51] typedef struct {
[52]     ngx_array_t                     limits;
[53]     ngx_uint_t                      log_level;
[54]     ngx_flag_t                      dry_run;
[55] } ngx_stream_limit_conn_conf_t;
[56] 
[57] 
[58] static ngx_rbtree_node_t *ngx_stream_limit_conn_lookup(ngx_rbtree_t *rbtree,
[59]     ngx_str_t *key, uint32_t hash);
[60] static void ngx_stream_limit_conn_cleanup(void *data);
[61] static ngx_inline void ngx_stream_limit_conn_cleanup_all(ngx_pool_t *pool);
[62] 
[63] static ngx_int_t ngx_stream_limit_conn_status_variable(ngx_stream_session_t *s,
[64]     ngx_stream_variable_value_t *v, uintptr_t data);
[65] static void *ngx_stream_limit_conn_create_conf(ngx_conf_t *cf);
[66] static char *ngx_stream_limit_conn_merge_conf(ngx_conf_t *cf, void *parent,
[67]     void *child);
[68] static char *ngx_stream_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
[69]     void *conf);
[70] static char *ngx_stream_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
[71]     void *conf);
[72] static ngx_int_t ngx_stream_limit_conn_add_variables(ngx_conf_t *cf);
[73] static ngx_int_t ngx_stream_limit_conn_init(ngx_conf_t *cf);
[74] 
[75] 
[76] static ngx_conf_enum_t  ngx_stream_limit_conn_log_levels[] = {
[77]     { ngx_string("info"), NGX_LOG_INFO },
[78]     { ngx_string("notice"), NGX_LOG_NOTICE },
[79]     { ngx_string("warn"), NGX_LOG_WARN },
[80]     { ngx_string("error"), NGX_LOG_ERR },
[81]     { ngx_null_string, 0 }
[82] };
[83] 
[84] 
[85] static ngx_command_t  ngx_stream_limit_conn_commands[] = {
[86] 
[87]     { ngx_string("limit_conn_zone"),
[88]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE2,
[89]       ngx_stream_limit_conn_zone,
[90]       0,
[91]       0,
[92]       NULL },
[93] 
[94]     { ngx_string("limit_conn"),
[95]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
[96]       ngx_stream_limit_conn,
[97]       NGX_STREAM_SRV_CONF_OFFSET,
[98]       0,
[99]       NULL },
[100] 
[101]     { ngx_string("limit_conn_log_level"),
[102]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[103]       ngx_conf_set_enum_slot,
[104]       NGX_STREAM_SRV_CONF_OFFSET,
[105]       offsetof(ngx_stream_limit_conn_conf_t, log_level),
[106]       &ngx_stream_limit_conn_log_levels },
[107] 
[108]     { ngx_string("limit_conn_dry_run"),
[109]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[110]       ngx_conf_set_flag_slot,
[111]       NGX_STREAM_SRV_CONF_OFFSET,
[112]       offsetof(ngx_stream_limit_conn_conf_t, dry_run),
[113]       NULL },
[114] 
[115]       ngx_null_command
[116] };
[117] 
[118] 
[119] static ngx_stream_module_t  ngx_stream_limit_conn_module_ctx = {
[120]     ngx_stream_limit_conn_add_variables,   /* preconfiguration */
[121]     ngx_stream_limit_conn_init,            /* postconfiguration */
[122] 
[123]     NULL,                                  /* create main configuration */
[124]     NULL,                                  /* init main configuration */
[125] 
[126]     ngx_stream_limit_conn_create_conf,     /* create server configuration */
[127]     ngx_stream_limit_conn_merge_conf       /* merge server configuration */
[128] };
[129] 
[130] 
[131] ngx_module_t  ngx_stream_limit_conn_module = {
[132]     NGX_MODULE_V1,
[133]     &ngx_stream_limit_conn_module_ctx,     /* module context */
[134]     ngx_stream_limit_conn_commands,        /* module directives */
[135]     NGX_STREAM_MODULE,                     /* module type */
[136]     NULL,                                  /* init master */
[137]     NULL,                                  /* init module */
[138]     NULL,                                  /* init process */
[139]     NULL,                                  /* init thread */
[140]     NULL,                                  /* exit thread */
[141]     NULL,                                  /* exit process */
[142]     NULL,                                  /* exit master */
[143]     NGX_MODULE_V1_PADDING
[144] };
[145] 
[146] 
[147] static ngx_stream_variable_t  ngx_stream_limit_conn_vars[] = {
[148] 
[149]     { ngx_string("limit_conn_status"), NULL,
[150]       ngx_stream_limit_conn_status_variable, 0, NGX_STREAM_VAR_NOCACHEABLE, 0 },
[151] 
[152]       ngx_stream_null_variable
[153] };
[154] 
[155] 
[156] static ngx_str_t  ngx_stream_limit_conn_status[] = {
[157]     ngx_string("PASSED"),
[158]     ngx_string("REJECTED"),
[159]     ngx_string("REJECTED_DRY_RUN")
[160] };
[161] 
[162] 
[163] static ngx_int_t
[164] ngx_stream_limit_conn_handler(ngx_stream_session_t *s)
[165] {
[166]     size_t                            n;
[167]     uint32_t                          hash;
[168]     ngx_str_t                         key;
[169]     ngx_uint_t                        i;
[170]     ngx_rbtree_node_t                *node;
[171]     ngx_pool_cleanup_t               *cln;
[172]     ngx_stream_limit_conn_ctx_t      *ctx;
[173]     ngx_stream_limit_conn_node_t     *lc;
[174]     ngx_stream_limit_conn_conf_t     *lccf;
[175]     ngx_stream_limit_conn_limit_t    *limits;
[176]     ngx_stream_limit_conn_cleanup_t  *lccln;
[177] 
[178]     lccf = ngx_stream_get_module_srv_conf(s, ngx_stream_limit_conn_module);
[179]     limits = lccf->limits.elts;
[180] 
[181]     for (i = 0; i < lccf->limits.nelts; i++) {
[182]         ctx = limits[i].shm_zone->data;
[183] 
[184]         if (ngx_stream_complex_value(s, &ctx->key, &key) != NGX_OK) {
[185]             return NGX_ERROR;
[186]         }
[187] 
[188]         if (key.len == 0) {
[189]             continue;
[190]         }
[191] 
[192]         if (key.len > 255) {
[193]             ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[194]                           "the value of the \"%V\" key "
[195]                           "is more than 255 bytes: \"%V\"",
[196]                           &ctx->key.value, &key);
[197]             continue;
[198]         }
[199] 
[200]         s->limit_conn_status = NGX_STREAM_LIMIT_CONN_PASSED;
[201] 
[202]         hash = ngx_crc32_short(key.data, key.len);
[203] 
[204]         ngx_shmtx_lock(&ctx->shpool->mutex);
[205] 
[206]         node = ngx_stream_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);
[207] 
[208]         if (node == NULL) {
[209] 
[210]             n = offsetof(ngx_rbtree_node_t, color)
[211]                 + offsetof(ngx_stream_limit_conn_node_t, data)
[212]                 + key.len;
[213] 
[214]             node = ngx_slab_alloc_locked(ctx->shpool, n);
[215] 
[216]             if (node == NULL) {
[217]                 ngx_shmtx_unlock(&ctx->shpool->mutex);
[218]                 ngx_stream_limit_conn_cleanup_all(s->connection->pool);
[219] 
[220]                 if (lccf->dry_run) {
[221]                     s->limit_conn_status =
[222]                                         NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
[223]                     return NGX_DECLINED;
[224]                 }
[225] 
[226]                 s->limit_conn_status = NGX_STREAM_LIMIT_CONN_REJECTED;
[227] 
[228]                 return NGX_STREAM_SERVICE_UNAVAILABLE;
[229]             }
[230] 
[231]             lc = (ngx_stream_limit_conn_node_t *) &node->color;
[232] 
[233]             node->key = hash;
[234]             lc->len = (u_char) key.len;
[235]             lc->conn = 1;
[236]             ngx_memcpy(lc->data, key.data, key.len);
[237] 
[238]             ngx_rbtree_insert(&ctx->sh->rbtree, node);
[239] 
[240]         } else {
[241] 
[242]             lc = (ngx_stream_limit_conn_node_t *) &node->color;
[243] 
[244]             if ((ngx_uint_t) lc->conn >= limits[i].conn) {
[245] 
[246]                 ngx_shmtx_unlock(&ctx->shpool->mutex);
[247] 
[248]                 ngx_log_error(lccf->log_level, s->connection->log, 0,
[249]                               "limiting connections%s by zone \"%V\"",
[250]                               lccf->dry_run ? ", dry run," : "",
[251]                               &limits[i].shm_zone->shm.name);
[252] 
[253]                 ngx_stream_limit_conn_cleanup_all(s->connection->pool);
[254] 
[255]                 if (lccf->dry_run) {
[256]                     s->limit_conn_status =
[257]                                         NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
[258]                     return NGX_DECLINED;
[259]                 }
[260] 
[261]                 s->limit_conn_status = NGX_STREAM_LIMIT_CONN_REJECTED;
[262] 
[263]                 return NGX_STREAM_SERVICE_UNAVAILABLE;
[264]             }
[265] 
[266]             lc->conn++;
[267]         }
[268] 
[269]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[270]                        "limit conn: %08Xi %d", node->key, lc->conn);
[271] 
[272]         ngx_shmtx_unlock(&ctx->shpool->mutex);
[273] 
[274]         cln = ngx_pool_cleanup_add(s->connection->pool,
[275]                                    sizeof(ngx_stream_limit_conn_cleanup_t));
[276]         if (cln == NULL) {
[277]             return NGX_ERROR;
[278]         }
[279] 
[280]         cln->handler = ngx_stream_limit_conn_cleanup;
[281]         lccln = cln->data;
[282] 
[283]         lccln->shm_zone = limits[i].shm_zone;
[284]         lccln->node = node;
[285]     }
[286] 
[287]     return NGX_DECLINED;
[288] }
[289] 
[290] 
[291] static void
[292] ngx_stream_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
[293]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[294] {
[295]     ngx_rbtree_node_t             **p;
[296]     ngx_stream_limit_conn_node_t   *lcn, *lcnt;
[297] 
[298]     for ( ;; ) {
[299] 
[300]         if (node->key < temp->key) {
[301] 
[302]             p = &temp->left;
[303] 
[304]         } else if (node->key > temp->key) {
[305] 
[306]             p = &temp->right;
[307] 
[308]         } else { /* node->key == temp->key */
[309] 
[310]             lcn = (ngx_stream_limit_conn_node_t *) &node->color;
[311]             lcnt = (ngx_stream_limit_conn_node_t *) &temp->color;
[312] 
[313]             p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
[314]                 ? &temp->left : &temp->right;
[315]         }
[316] 
[317]         if (*p == sentinel) {
[318]             break;
[319]         }
[320] 
[321]         temp = *p;
[322]     }
[323] 
[324]     *p = node;
[325]     node->parent = temp;
[326]     node->left = sentinel;
[327]     node->right = sentinel;
[328]     ngx_rbt_red(node);
[329] }
[330] 
[331] 
[332] static ngx_rbtree_node_t *
[333] ngx_stream_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key,
[334]     uint32_t hash)
[335] {
[336]     ngx_int_t                      rc;
[337]     ngx_rbtree_node_t             *node, *sentinel;
[338]     ngx_stream_limit_conn_node_t  *lcn;
[339] 
[340]     node = rbtree->root;
[341]     sentinel = rbtree->sentinel;
[342] 
[343]     while (node != sentinel) {
[344] 
[345]         if (hash < node->key) {
[346]             node = node->left;
[347]             continue;
[348]         }
[349] 
[350]         if (hash > node->key) {
[351]             node = node->right;
[352]             continue;
[353]         }
[354] 
[355]         /* hash == node->key */
[356] 
[357]         lcn = (ngx_stream_limit_conn_node_t *) &node->color;
[358] 
[359]         rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);
[360] 
[361]         if (rc == 0) {
[362]             return node;
[363]         }
[364] 
[365]         node = (rc < 0) ? node->left : node->right;
[366]     }
[367] 
[368]     return NULL;
[369] }
[370] 
[371] 
[372] static void
[373] ngx_stream_limit_conn_cleanup(void *data)
[374] {
[375]     ngx_stream_limit_conn_cleanup_t  *lccln = data;
[376] 
[377]     ngx_rbtree_node_t             *node;
[378]     ngx_stream_limit_conn_ctx_t   *ctx;
[379]     ngx_stream_limit_conn_node_t  *lc;
[380] 
[381]     ctx = lccln->shm_zone->data;
[382]     node = lccln->node;
[383]     lc = (ngx_stream_limit_conn_node_t *) &node->color;
[384] 
[385]     ngx_shmtx_lock(&ctx->shpool->mutex);
[386] 
[387]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, lccln->shm_zone->shm.log, 0,
[388]                    "limit conn cleanup: %08Xi %d", node->key, lc->conn);
[389] 
[390]     lc->conn--;
[391] 
[392]     if (lc->conn == 0) {
[393]         ngx_rbtree_delete(&ctx->sh->rbtree, node);
[394]         ngx_slab_free_locked(ctx->shpool, node);
[395]     }
[396] 
[397]     ngx_shmtx_unlock(&ctx->shpool->mutex);
[398] }
[399] 
[400] 
[401] static ngx_inline void
[402] ngx_stream_limit_conn_cleanup_all(ngx_pool_t *pool)
[403] {
[404]     ngx_pool_cleanup_t  *cln;
[405] 
[406]     cln = pool->cleanup;
[407] 
[408]     while (cln && cln->handler == ngx_stream_limit_conn_cleanup) {
[409]         ngx_stream_limit_conn_cleanup(cln->data);
[410]         cln = cln->next;
[411]     }
[412] 
[413]     pool->cleanup = cln;
[414] }
[415] 
[416] 
[417] static ngx_int_t
[418] ngx_stream_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
[419] {
[420]     ngx_stream_limit_conn_ctx_t  *octx = data;
[421] 
[422]     size_t                        len;
[423]     ngx_stream_limit_conn_ctx_t  *ctx;
[424] 
[425]     ctx = shm_zone->data;
[426] 
[427]     if (octx) {
[428]         if (ctx->key.value.len != octx->key.value.len
[429]             || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
[430]                            ctx->key.value.len)
[431]                != 0)
[432]         {
[433]             ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
[434]                           "limit_conn_zone \"%V\" uses the \"%V\" key "
[435]                           "while previously it used the \"%V\" key",
[436]                           &shm_zone->shm.name, &ctx->key.value,
[437]                           &octx->key.value);
[438]             return NGX_ERROR;
[439]         }
[440] 
[441]         ctx->sh = octx->sh;
[442]         ctx->shpool = octx->shpool;
[443] 
[444]         return NGX_OK;
[445]     }
[446] 
[447]     ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[448] 
[449]     if (shm_zone->shm.exists) {
[450]         ctx->sh = ctx->shpool->data;
[451] 
[452]         return NGX_OK;
[453]     }
[454] 
[455]     ctx->sh = ngx_slab_alloc(ctx->shpool,
[456]                              sizeof(ngx_stream_limit_conn_shctx_t));
[457]     if (ctx->sh == NULL) {
[458]         return NGX_ERROR;
[459]     }
[460] 
[461]     ctx->shpool->data = ctx->sh;
[462] 
[463]     ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
[464]                     ngx_stream_limit_conn_rbtree_insert_value);
[465] 
[466]     len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;
[467] 
[468]     ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
[469]     if (ctx->shpool->log_ctx == NULL) {
[470]         return NGX_ERROR;
[471]     }
[472] 
[473]     ngx_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
[474]                 &shm_zone->shm.name);
[475] 
[476]     return NGX_OK;
[477] }
[478] 
[479] 
[480] static ngx_int_t
[481] ngx_stream_limit_conn_status_variable(ngx_stream_session_t *s,
[482]     ngx_stream_variable_value_t *v, uintptr_t data)
[483] {
[484]     if (s->limit_conn_status == 0) {
[485]         v->not_found = 1;
[486]         return NGX_OK;
[487]     }
[488] 
[489]     v->valid = 1;
[490]     v->no_cacheable = 0;
[491]     v->not_found = 0;
[492]     v->len = ngx_stream_limit_conn_status[s->limit_conn_status - 1].len;
[493]     v->data = ngx_stream_limit_conn_status[s->limit_conn_status - 1].data;
[494] 
[495]     return NGX_OK;
[496] }
[497] 
[498] 
[499] static void *
[500] ngx_stream_limit_conn_create_conf(ngx_conf_t *cf)
[501] {
[502]     ngx_stream_limit_conn_conf_t  *conf;
[503] 
[504]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_limit_conn_conf_t));
[505]     if (conf == NULL) {
[506]         return NULL;
[507]     }
[508] 
[509]     /*
[510]      * set by ngx_pcalloc():
[511]      *
[512]      *     conf->limits.elts = NULL;
[513]      */
[514] 
[515]     conf->log_level = NGX_CONF_UNSET_UINT;
[516]     conf->dry_run = NGX_CONF_UNSET;
[517] 
[518]     return conf;
[519] }
[520] 
[521] 
[522] static char *
[523] ngx_stream_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[524] {
[525]     ngx_stream_limit_conn_conf_t *prev = parent;
[526]     ngx_stream_limit_conn_conf_t *conf = child;
[527] 
[528]     if (conf->limits.elts == NULL) {
[529]         conf->limits = prev->limits;
[530]     }
[531] 
[532]     ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
[533] 
[534]     ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);
[535] 
[536]     return NGX_CONF_OK;
[537] }
[538] 
[539] 
[540] static char *
[541] ngx_stream_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[542] {
[543]     u_char                              *p;
[544]     ssize_t                              size;
[545]     ngx_str_t                           *value, name, s;
[546]     ngx_uint_t                           i;
[547]     ngx_shm_zone_t                      *shm_zone;
[548]     ngx_stream_limit_conn_ctx_t         *ctx;
[549]     ngx_stream_compile_complex_value_t   ccv;
[550] 
[551]     value = cf->args->elts;
[552] 
[553]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_limit_conn_ctx_t));
[554]     if (ctx == NULL) {
[555]         return NGX_CONF_ERROR;
[556]     }
[557] 
[558]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[559] 
[560]     ccv.cf = cf;
[561]     ccv.value = &value[1];
[562]     ccv.complex_value = &ctx->key;
[563] 
[564]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[565]         return NGX_CONF_ERROR;
[566]     }
[567] 
[568]     size = 0;
[569]     name.len = 0;
[570] 
[571]     for (i = 2; i < cf->args->nelts; i++) {
[572] 
[573]         if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
[574] 
[575]             name.data = value[i].data + 5;
[576] 
[577]             p = (u_char *) ngx_strchr(name.data, ':');
[578] 
[579]             if (p == NULL) {
[580]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[581]                                    "invalid zone size \"%V\"", &value[i]);
[582]                 return NGX_CONF_ERROR;
[583]             }
[584] 
[585]             name.len = p - name.data;
[586] 
[587]             s.data = p + 1;
[588]             s.len = value[i].data + value[i].len - s.data;
[589] 
[590]             size = ngx_parse_size(&s);
[591] 
[592]             if (size == NGX_ERROR) {
[593]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[594]                                    "invalid zone size \"%V\"", &value[i]);
[595]                 return NGX_CONF_ERROR;
[596]             }
[597] 
[598]             if (size < (ssize_t) (8 * ngx_pagesize)) {
[599]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[600]                                    "zone \"%V\" is too small", &value[i]);
[601]                 return NGX_CONF_ERROR;
[602]             }
[603] 
[604]             continue;
[605]         }
[606] 
[607]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[608]                            "invalid parameter \"%V\"", &value[i]);
[609]         return NGX_CONF_ERROR;
[610]     }
[611] 
[612]     if (name.len == 0) {
[613]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[614]                            "\"%V\" must have \"zone\" parameter",
[615]                            &cmd->name);
[616]         return NGX_CONF_ERROR;
[617]     }
[618] 
[619]     shm_zone = ngx_shared_memory_add(cf, &name, size,
[620]                                      &ngx_stream_limit_conn_module);
[621]     if (shm_zone == NULL) {
[622]         return NGX_CONF_ERROR;
[623]     }
[624] 
[625]     if (shm_zone->data) {
[626]         ctx = shm_zone->data;
[627] 
[628]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[629]                            "%V \"%V\" is already bound to key \"%V\"",
[630]                            &cmd->name, &name, &ctx->key.value);
[631]         return NGX_CONF_ERROR;
[632]     }
[633] 
[634]     shm_zone->init = ngx_stream_limit_conn_init_zone;
[635]     shm_zone->data = ctx;
[636] 
[637]     return NGX_CONF_OK;
[638] }
[639] 
[640] 
[641] static char *
[642] ngx_stream_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[643] {
[644]     ngx_shm_zone_t                 *shm_zone;
[645]     ngx_stream_limit_conn_conf_t   *lccf = conf;
[646]     ngx_stream_limit_conn_limit_t  *limit, *limits;
[647] 
[648]     ngx_str_t   *value;
[649]     ngx_int_t    n;
[650]     ngx_uint_t   i;
[651] 
[652]     value = cf->args->elts;
[653] 
[654]     shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
[655]                                      &ngx_stream_limit_conn_module);
[656]     if (shm_zone == NULL) {
[657]         return NGX_CONF_ERROR;
[658]     }
[659] 
[660]     limits = lccf->limits.elts;
[661] 
[662]     if (limits == NULL) {
[663]         if (ngx_array_init(&lccf->limits, cf->pool, 1,
[664]                            sizeof(ngx_stream_limit_conn_limit_t))
[665]             != NGX_OK)
[666]         {
[667]             return NGX_CONF_ERROR;
[668]         }
[669]     }
[670] 
[671]     for (i = 0; i < lccf->limits.nelts; i++) {
[672]         if (shm_zone == limits[i].shm_zone) {
[673]             return "is duplicate";
[674]         }
[675]     }
[676] 
[677]     n = ngx_atoi(value[2].data, value[2].len);
[678]     if (n <= 0) {
[679]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[680]                            "invalid number of connections \"%V\"", &value[2]);
[681]         return NGX_CONF_ERROR;
[682]     }
[683] 
[684]     if (n > 65535) {
[685]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[686]                            "connection limit must be less 65536");
[687]         return NGX_CONF_ERROR;
[688]     }
[689] 
[690]     limit = ngx_array_push(&lccf->limits);
[691]     if (limit == NULL) {
[692]         return NGX_CONF_ERROR;
[693]     }
[694] 
[695]     limit->conn = n;
[696]     limit->shm_zone = shm_zone;
[697] 
[698]     return NGX_CONF_OK;
[699] }
[700] 
[701] 
[702] static ngx_int_t
[703] ngx_stream_limit_conn_add_variables(ngx_conf_t *cf)
[704] {
[705]     ngx_stream_variable_t  *var, *v;
[706] 
[707]     for (v = ngx_stream_limit_conn_vars; v->name.len; v++) {
[708]         var = ngx_stream_add_variable(cf, &v->name, v->flags);
[709]         if (var == NULL) {
[710]             return NGX_ERROR;
[711]         }
[712] 
[713]         var->get_handler = v->get_handler;
[714]         var->data = v->data;
[715]     }
[716] 
[717]     return NGX_OK;
[718] }
[719] 
[720] 
[721] static ngx_int_t
[722] ngx_stream_limit_conn_init(ngx_conf_t *cf)
[723] {
[724]     ngx_stream_handler_pt        *h;
[725]     ngx_stream_core_main_conf_t  *cmcf;
[726] 
[727]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[728] 
[729]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREACCESS_PHASE].handlers);
[730]     if (h == NULL) {
[731]         return NGX_ERROR;
[732]     }
[733] 
[734]     *h = ngx_stream_limit_conn_handler;
[735] 
[736]     return NGX_OK;
[737] }
