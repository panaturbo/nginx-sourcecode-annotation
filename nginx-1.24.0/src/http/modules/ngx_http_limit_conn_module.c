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
[13] #define NGX_HTTP_LIMIT_CONN_PASSED            1
[14] #define NGX_HTTP_LIMIT_CONN_REJECTED          2
[15] #define NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN  3
[16] 
[17] 
[18] typedef struct {
[19]     u_char                        color;
[20]     u_char                        len;
[21]     u_short                       conn;
[22]     u_char                        data[1];
[23] } ngx_http_limit_conn_node_t;
[24] 
[25] 
[26] typedef struct {
[27]     ngx_shm_zone_t               *shm_zone;
[28]     ngx_rbtree_node_t            *node;
[29] } ngx_http_limit_conn_cleanup_t;
[30] 
[31] 
[32] typedef struct {
[33]     ngx_rbtree_t                  rbtree;
[34]     ngx_rbtree_node_t             sentinel;
[35] } ngx_http_limit_conn_shctx_t;
[36] 
[37] 
[38] typedef struct {
[39]     ngx_http_limit_conn_shctx_t  *sh;
[40]     ngx_slab_pool_t              *shpool;
[41]     ngx_http_complex_value_t      key;
[42] } ngx_http_limit_conn_ctx_t;
[43] 
[44] 
[45] typedef struct {
[46]     ngx_shm_zone_t               *shm_zone;
[47]     ngx_uint_t                    conn;
[48] } ngx_http_limit_conn_limit_t;
[49] 
[50] 
[51] typedef struct {
[52]     ngx_array_t                   limits;
[53]     ngx_uint_t                    log_level;
[54]     ngx_uint_t                    status_code;
[55]     ngx_flag_t                    dry_run;
[56] } ngx_http_limit_conn_conf_t;
[57] 
[58] 
[59] static ngx_rbtree_node_t *ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree,
[60]     ngx_str_t *key, uint32_t hash);
[61] static void ngx_http_limit_conn_cleanup(void *data);
[62] static ngx_inline void ngx_http_limit_conn_cleanup_all(ngx_pool_t *pool);
[63] 
[64] static ngx_int_t ngx_http_limit_conn_status_variable(ngx_http_request_t *r,
[65]     ngx_http_variable_value_t *v, uintptr_t data);
[66] static void *ngx_http_limit_conn_create_conf(ngx_conf_t *cf);
[67] static char *ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent,
[68]     void *child);
[69] static char *ngx_http_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
[70]     void *conf);
[71] static char *ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
[72]     void *conf);
[73] static ngx_int_t ngx_http_limit_conn_add_variables(ngx_conf_t *cf);
[74] static ngx_int_t ngx_http_limit_conn_init(ngx_conf_t *cf);
[75] 
[76] 
[77] static ngx_conf_enum_t  ngx_http_limit_conn_log_levels[] = {
[78]     { ngx_string("info"), NGX_LOG_INFO },
[79]     { ngx_string("notice"), NGX_LOG_NOTICE },
[80]     { ngx_string("warn"), NGX_LOG_WARN },
[81]     { ngx_string("error"), NGX_LOG_ERR },
[82]     { ngx_null_string, 0 }
[83] };
[84] 
[85] 
[86] static ngx_conf_num_bounds_t  ngx_http_limit_conn_status_bounds = {
[87]     ngx_conf_check_num_bounds, 400, 599
[88] };
[89] 
[90] 
[91] static ngx_command_t  ngx_http_limit_conn_commands[] = {
[92] 
[93]     { ngx_string("limit_conn_zone"),
[94]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
[95]       ngx_http_limit_conn_zone,
[96]       0,
[97]       0,
[98]       NULL },
[99] 
[100]     { ngx_string("limit_conn"),
[101]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[102]       ngx_http_limit_conn,
[103]       NGX_HTTP_LOC_CONF_OFFSET,
[104]       0,
[105]       NULL },
[106] 
[107]     { ngx_string("limit_conn_log_level"),
[108]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[109]       ngx_conf_set_enum_slot,
[110]       NGX_HTTP_LOC_CONF_OFFSET,
[111]       offsetof(ngx_http_limit_conn_conf_t, log_level),
[112]       &ngx_http_limit_conn_log_levels },
[113] 
[114]     { ngx_string("limit_conn_status"),
[115]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[116]       ngx_conf_set_num_slot,
[117]       NGX_HTTP_LOC_CONF_OFFSET,
[118]       offsetof(ngx_http_limit_conn_conf_t, status_code),
[119]       &ngx_http_limit_conn_status_bounds },
[120] 
[121]     { ngx_string("limit_conn_dry_run"),
[122]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[123]       ngx_conf_set_flag_slot,
[124]       NGX_HTTP_LOC_CONF_OFFSET,
[125]       offsetof(ngx_http_limit_conn_conf_t, dry_run),
[126]       NULL },
[127] 
[128]       ngx_null_command
[129] };
[130] 
[131] 
[132] static ngx_http_module_t  ngx_http_limit_conn_module_ctx = {
[133]     ngx_http_limit_conn_add_variables,     /* preconfiguration */
[134]     ngx_http_limit_conn_init,              /* postconfiguration */
[135] 
[136]     NULL,                                  /* create main configuration */
[137]     NULL,                                  /* init main configuration */
[138] 
[139]     NULL,                                  /* create server configuration */
[140]     NULL,                                  /* merge server configuration */
[141] 
[142]     ngx_http_limit_conn_create_conf,       /* create location configuration */
[143]     ngx_http_limit_conn_merge_conf         /* merge location configuration */
[144] };
[145] 
[146] 
[147] ngx_module_t  ngx_http_limit_conn_module = {
[148]     NGX_MODULE_V1,
[149]     &ngx_http_limit_conn_module_ctx,       /* module context */
[150]     ngx_http_limit_conn_commands,          /* module directives */
[151]     NGX_HTTP_MODULE,                       /* module type */
[152]     NULL,                                  /* init master */
[153]     NULL,                                  /* init module */
[154]     NULL,                                  /* init process */
[155]     NULL,                                  /* init thread */
[156]     NULL,                                  /* exit thread */
[157]     NULL,                                  /* exit process */
[158]     NULL,                                  /* exit master */
[159]     NGX_MODULE_V1_PADDING
[160] };
[161] 
[162] 
[163] static ngx_http_variable_t  ngx_http_limit_conn_vars[] = {
[164] 
[165]     { ngx_string("limit_conn_status"), NULL,
[166]       ngx_http_limit_conn_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[167] 
[168]       ngx_http_null_variable
[169] };
[170] 
[171] 
[172] static ngx_str_t  ngx_http_limit_conn_status[] = {
[173]     ngx_string("PASSED"),
[174]     ngx_string("REJECTED"),
[175]     ngx_string("REJECTED_DRY_RUN")
[176] };
[177] 
[178] 
[179] static ngx_int_t
[180] ngx_http_limit_conn_handler(ngx_http_request_t *r)
[181] {
[182]     size_t                          n;
[183]     uint32_t                        hash;
[184]     ngx_str_t                       key;
[185]     ngx_uint_t                      i;
[186]     ngx_rbtree_node_t              *node;
[187]     ngx_pool_cleanup_t             *cln;
[188]     ngx_http_limit_conn_ctx_t      *ctx;
[189]     ngx_http_limit_conn_node_t     *lc;
[190]     ngx_http_limit_conn_conf_t     *lccf;
[191]     ngx_http_limit_conn_limit_t    *limits;
[192]     ngx_http_limit_conn_cleanup_t  *lccln;
[193] 
[194]     if (r->main->limit_conn_status) {
[195]         return NGX_DECLINED;
[196]     }
[197] 
[198]     lccf = ngx_http_get_module_loc_conf(r, ngx_http_limit_conn_module);
[199]     limits = lccf->limits.elts;
[200] 
[201]     for (i = 0; i < lccf->limits.nelts; i++) {
[202]         ctx = limits[i].shm_zone->data;
[203] 
[204]         if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
[205]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[206]         }
[207] 
[208]         if (key.len == 0) {
[209]             continue;
[210]         }
[211] 
[212]         if (key.len > 255) {
[213]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[214]                           "the value of the \"%V\" key "
[215]                           "is more than 255 bytes: \"%V\"",
[216]                           &ctx->key.value, &key);
[217]             continue;
[218]         }
[219] 
[220]         r->main->limit_conn_status = NGX_HTTP_LIMIT_CONN_PASSED;
[221] 
[222]         hash = ngx_crc32_short(key.data, key.len);
[223] 
[224]         ngx_shmtx_lock(&ctx->shpool->mutex);
[225] 
[226]         node = ngx_http_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);
[227] 
[228]         if (node == NULL) {
[229] 
[230]             n = offsetof(ngx_rbtree_node_t, color)
[231]                 + offsetof(ngx_http_limit_conn_node_t, data)
[232]                 + key.len;
[233] 
[234]             node = ngx_slab_alloc_locked(ctx->shpool, n);
[235] 
[236]             if (node == NULL) {
[237]                 ngx_shmtx_unlock(&ctx->shpool->mutex);
[238]                 ngx_http_limit_conn_cleanup_all(r->pool);
[239] 
[240]                 if (lccf->dry_run) {
[241]                     r->main->limit_conn_status =
[242]                                           NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN;
[243]                     return NGX_DECLINED;
[244]                 }
[245] 
[246]                 r->main->limit_conn_status = NGX_HTTP_LIMIT_CONN_REJECTED;
[247] 
[248]                 return lccf->status_code;
[249]             }
[250] 
[251]             lc = (ngx_http_limit_conn_node_t *) &node->color;
[252] 
[253]             node->key = hash;
[254]             lc->len = (u_char) key.len;
[255]             lc->conn = 1;
[256]             ngx_memcpy(lc->data, key.data, key.len);
[257] 
[258]             ngx_rbtree_insert(&ctx->sh->rbtree, node);
[259] 
[260]         } else {
[261] 
[262]             lc = (ngx_http_limit_conn_node_t *) &node->color;
[263] 
[264]             if ((ngx_uint_t) lc->conn >= limits[i].conn) {
[265] 
[266]                 ngx_shmtx_unlock(&ctx->shpool->mutex);
[267] 
[268]                 ngx_log_error(lccf->log_level, r->connection->log, 0,
[269]                               "limiting connections%s by zone \"%V\"",
[270]                               lccf->dry_run ? ", dry run," : "",
[271]                               &limits[i].shm_zone->shm.name);
[272] 
[273]                 ngx_http_limit_conn_cleanup_all(r->pool);
[274] 
[275]                 if (lccf->dry_run) {
[276]                     r->main->limit_conn_status =
[277]                                           NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN;
[278]                     return NGX_DECLINED;
[279]                 }
[280] 
[281]                 r->main->limit_conn_status = NGX_HTTP_LIMIT_CONN_REJECTED;
[282] 
[283]                 return lccf->status_code;
[284]             }
[285] 
[286]             lc->conn++;
[287]         }
[288] 
[289]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[290]                        "limit conn: %08Xi %d", node->key, lc->conn);
[291] 
[292]         ngx_shmtx_unlock(&ctx->shpool->mutex);
[293] 
[294]         cln = ngx_pool_cleanup_add(r->pool,
[295]                                    sizeof(ngx_http_limit_conn_cleanup_t));
[296]         if (cln == NULL) {
[297]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[298]         }
[299] 
[300]         cln->handler = ngx_http_limit_conn_cleanup;
[301]         lccln = cln->data;
[302] 
[303]         lccln->shm_zone = limits[i].shm_zone;
[304]         lccln->node = node;
[305]     }
[306] 
[307]     return NGX_DECLINED;
[308] }
[309] 
[310] 
[311] static void
[312] ngx_http_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
[313]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[314] {
[315]     ngx_rbtree_node_t           **p;
[316]     ngx_http_limit_conn_node_t   *lcn, *lcnt;
[317] 
[318]     for ( ;; ) {
[319] 
[320]         if (node->key < temp->key) {
[321] 
[322]             p = &temp->left;
[323] 
[324]         } else if (node->key > temp->key) {
[325] 
[326]             p = &temp->right;
[327] 
[328]         } else { /* node->key == temp->key */
[329] 
[330]             lcn = (ngx_http_limit_conn_node_t *) &node->color;
[331]             lcnt = (ngx_http_limit_conn_node_t *) &temp->color;
[332] 
[333]             p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
[334]                 ? &temp->left : &temp->right;
[335]         }
[336] 
[337]         if (*p == sentinel) {
[338]             break;
[339]         }
[340] 
[341]         temp = *p;
[342]     }
[343] 
[344]     *p = node;
[345]     node->parent = temp;
[346]     node->left = sentinel;
[347]     node->right = sentinel;
[348]     ngx_rbt_red(node);
[349] }
[350] 
[351] 
[352] static ngx_rbtree_node_t *
[353] ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
[354] {
[355]     ngx_int_t                    rc;
[356]     ngx_rbtree_node_t           *node, *sentinel;
[357]     ngx_http_limit_conn_node_t  *lcn;
[358] 
[359]     node = rbtree->root;
[360]     sentinel = rbtree->sentinel;
[361] 
[362]     while (node != sentinel) {
[363] 
[364]         if (hash < node->key) {
[365]             node = node->left;
[366]             continue;
[367]         }
[368] 
[369]         if (hash > node->key) {
[370]             node = node->right;
[371]             continue;
[372]         }
[373] 
[374]         /* hash == node->key */
[375] 
[376]         lcn = (ngx_http_limit_conn_node_t *) &node->color;
[377] 
[378]         rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);
[379] 
[380]         if (rc == 0) {
[381]             return node;
[382]         }
[383] 
[384]         node = (rc < 0) ? node->left : node->right;
[385]     }
[386] 
[387]     return NULL;
[388] }
[389] 
[390] 
[391] static void
[392] ngx_http_limit_conn_cleanup(void *data)
[393] {
[394]     ngx_http_limit_conn_cleanup_t  *lccln = data;
[395] 
[396]     ngx_rbtree_node_t           *node;
[397]     ngx_http_limit_conn_ctx_t   *ctx;
[398]     ngx_http_limit_conn_node_t  *lc;
[399] 
[400]     ctx = lccln->shm_zone->data;
[401]     node = lccln->node;
[402]     lc = (ngx_http_limit_conn_node_t *) &node->color;
[403] 
[404]     ngx_shmtx_lock(&ctx->shpool->mutex);
[405] 
[406]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
[407]                    "limit conn cleanup: %08Xi %d", node->key, lc->conn);
[408] 
[409]     lc->conn--;
[410] 
[411]     if (lc->conn == 0) {
[412]         ngx_rbtree_delete(&ctx->sh->rbtree, node);
[413]         ngx_slab_free_locked(ctx->shpool, node);
[414]     }
[415] 
[416]     ngx_shmtx_unlock(&ctx->shpool->mutex);
[417] }
[418] 
[419] 
[420] static ngx_inline void
[421] ngx_http_limit_conn_cleanup_all(ngx_pool_t *pool)
[422] {
[423]     ngx_pool_cleanup_t  *cln;
[424] 
[425]     cln = pool->cleanup;
[426] 
[427]     while (cln && cln->handler == ngx_http_limit_conn_cleanup) {
[428]         ngx_http_limit_conn_cleanup(cln->data);
[429]         cln = cln->next;
[430]     }
[431] 
[432]     pool->cleanup = cln;
[433] }
[434] 
[435] 
[436] static ngx_int_t
[437] ngx_http_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
[438] {
[439]     ngx_http_limit_conn_ctx_t  *octx = data;
[440] 
[441]     size_t                      len;
[442]     ngx_http_limit_conn_ctx_t  *ctx;
[443] 
[444]     ctx = shm_zone->data;
[445] 
[446]     if (octx) {
[447]         if (ctx->key.value.len != octx->key.value.len
[448]             || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
[449]                            ctx->key.value.len)
[450]                != 0)
[451]         {
[452]             ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
[453]                           "limit_conn_zone \"%V\" uses the \"%V\" key "
[454]                           "while previously it used the \"%V\" key",
[455]                           &shm_zone->shm.name, &ctx->key.value,
[456]                           &octx->key.value);
[457]             return NGX_ERROR;
[458]         }
[459] 
[460]         ctx->sh = octx->sh;
[461]         ctx->shpool = octx->shpool;
[462] 
[463]         return NGX_OK;
[464]     }
[465] 
[466]     ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[467] 
[468]     if (shm_zone->shm.exists) {
[469]         ctx->sh = ctx->shpool->data;
[470] 
[471]         return NGX_OK;
[472]     }
[473] 
[474]     ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_conn_shctx_t));
[475]     if (ctx->sh == NULL) {
[476]         return NGX_ERROR;
[477]     }
[478] 
[479]     ctx->shpool->data = ctx->sh;
[480] 
[481]     ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
[482]                     ngx_http_limit_conn_rbtree_insert_value);
[483] 
[484]     len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;
[485] 
[486]     ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
[487]     if (ctx->shpool->log_ctx == NULL) {
[488]         return NGX_ERROR;
[489]     }
[490] 
[491]     ngx_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
[492]                 &shm_zone->shm.name);
[493] 
[494]     return NGX_OK;
[495] }
[496] 
[497] 
[498] static ngx_int_t
[499] ngx_http_limit_conn_status_variable(ngx_http_request_t *r,
[500]     ngx_http_variable_value_t *v, uintptr_t data)
[501] {
[502]     if (r->main->limit_conn_status == 0) {
[503]         v->not_found = 1;
[504]         return NGX_OK;
[505]     }
[506] 
[507]     v->valid = 1;
[508]     v->no_cacheable = 0;
[509]     v->not_found = 0;
[510]     v->len = ngx_http_limit_conn_status[r->main->limit_conn_status - 1].len;
[511]     v->data = ngx_http_limit_conn_status[r->main->limit_conn_status - 1].data;
[512] 
[513]     return NGX_OK;
[514] }
[515] 
[516] 
[517] static void *
[518] ngx_http_limit_conn_create_conf(ngx_conf_t *cf)
[519] {
[520]     ngx_http_limit_conn_conf_t  *conf;
[521] 
[522]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_conf_t));
[523]     if (conf == NULL) {
[524]         return NULL;
[525]     }
[526] 
[527]     /*
[528]      * set by ngx_pcalloc():
[529]      *
[530]      *     conf->limits.elts = NULL;
[531]      */
[532] 
[533]     conf->log_level = NGX_CONF_UNSET_UINT;
[534]     conf->status_code = NGX_CONF_UNSET_UINT;
[535]     conf->dry_run = NGX_CONF_UNSET;
[536] 
[537]     return conf;
[538] }
[539] 
[540] 
[541] static char *
[542] ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[543] {
[544]     ngx_http_limit_conn_conf_t *prev = parent;
[545]     ngx_http_limit_conn_conf_t *conf = child;
[546] 
[547]     if (conf->limits.elts == NULL) {
[548]         conf->limits = prev->limits;
[549]     }
[550] 
[551]     ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
[552]     ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
[553]                               NGX_HTTP_SERVICE_UNAVAILABLE);
[554] 
[555]     ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);
[556] 
[557]     return NGX_CONF_OK;
[558] }
[559] 
[560] 
[561] static char *
[562] ngx_http_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[563] {
[564]     u_char                            *p;
[565]     ssize_t                            size;
[566]     ngx_str_t                         *value, name, s;
[567]     ngx_uint_t                         i;
[568]     ngx_shm_zone_t                    *shm_zone;
[569]     ngx_http_limit_conn_ctx_t         *ctx;
[570]     ngx_http_compile_complex_value_t   ccv;
[571] 
[572]     value = cf->args->elts;
[573] 
[574]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_ctx_t));
[575]     if (ctx == NULL) {
[576]         return NGX_CONF_ERROR;
[577]     }
[578] 
[579]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[580] 
[581]     ccv.cf = cf;
[582]     ccv.value = &value[1];
[583]     ccv.complex_value = &ctx->key;
[584] 
[585]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[586]         return NGX_CONF_ERROR;
[587]     }
[588] 
[589]     size = 0;
[590]     name.len = 0;
[591] 
[592]     for (i = 2; i < cf->args->nelts; i++) {
[593] 
[594]         if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
[595] 
[596]             name.data = value[i].data + 5;
[597] 
[598]             p = (u_char *) ngx_strchr(name.data, ':');
[599] 
[600]             if (p == NULL) {
[601]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[602]                                    "invalid zone size \"%V\"", &value[i]);
[603]                 return NGX_CONF_ERROR;
[604]             }
[605] 
[606]             name.len = p - name.data;
[607] 
[608]             s.data = p + 1;
[609]             s.len = value[i].data + value[i].len - s.data;
[610] 
[611]             size = ngx_parse_size(&s);
[612] 
[613]             if (size == NGX_ERROR) {
[614]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[615]                                    "invalid zone size \"%V\"", &value[i]);
[616]                 return NGX_CONF_ERROR;
[617]             }
[618] 
[619]             if (size < (ssize_t) (8 * ngx_pagesize)) {
[620]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[621]                                    "zone \"%V\" is too small", &value[i]);
[622]                 return NGX_CONF_ERROR;
[623]             }
[624] 
[625]             continue;
[626]         }
[627] 
[628]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[629]                            "invalid parameter \"%V\"", &value[i]);
[630]         return NGX_CONF_ERROR;
[631]     }
[632] 
[633]     if (name.len == 0) {
[634]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[635]                            "\"%V\" must have \"zone\" parameter",
[636]                            &cmd->name);
[637]         return NGX_CONF_ERROR;
[638]     }
[639] 
[640]     shm_zone = ngx_shared_memory_add(cf, &name, size,
[641]                                      &ngx_http_limit_conn_module);
[642]     if (shm_zone == NULL) {
[643]         return NGX_CONF_ERROR;
[644]     }
[645] 
[646]     if (shm_zone->data) {
[647]         ctx = shm_zone->data;
[648] 
[649]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[650]                            "%V \"%V\" is already bound to key \"%V\"",
[651]                            &cmd->name, &name, &ctx->key.value);
[652]         return NGX_CONF_ERROR;
[653]     }
[654] 
[655]     shm_zone->init = ngx_http_limit_conn_init_zone;
[656]     shm_zone->data = ctx;
[657] 
[658]     return NGX_CONF_OK;
[659] }
[660] 
[661] 
[662] static char *
[663] ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[664] {
[665]     ngx_shm_zone_t               *shm_zone;
[666]     ngx_http_limit_conn_conf_t   *lccf = conf;
[667]     ngx_http_limit_conn_limit_t  *limit, *limits;
[668] 
[669]     ngx_str_t  *value;
[670]     ngx_int_t   n;
[671]     ngx_uint_t  i;
[672] 
[673]     value = cf->args->elts;
[674] 
[675]     shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
[676]                                      &ngx_http_limit_conn_module);
[677]     if (shm_zone == NULL) {
[678]         return NGX_CONF_ERROR;
[679]     }
[680] 
[681]     limits = lccf->limits.elts;
[682] 
[683]     if (limits == NULL) {
[684]         if (ngx_array_init(&lccf->limits, cf->pool, 1,
[685]                            sizeof(ngx_http_limit_conn_limit_t))
[686]             != NGX_OK)
[687]         {
[688]             return NGX_CONF_ERROR;
[689]         }
[690]     }
[691] 
[692]     for (i = 0; i < lccf->limits.nelts; i++) {
[693]         if (shm_zone == limits[i].shm_zone) {
[694]             return "is duplicate";
[695]         }
[696]     }
[697] 
[698]     n = ngx_atoi(value[2].data, value[2].len);
[699]     if (n <= 0) {
[700]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[701]                            "invalid number of connections \"%V\"", &value[2]);
[702]         return NGX_CONF_ERROR;
[703]     }
[704] 
[705]     if (n > 65535) {
[706]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[707]                            "connection limit must be less 65536");
[708]         return NGX_CONF_ERROR;
[709]     }
[710] 
[711]     limit = ngx_array_push(&lccf->limits);
[712]     if (limit == NULL) {
[713]         return NGX_CONF_ERROR;
[714]     }
[715] 
[716]     limit->conn = n;
[717]     limit->shm_zone = shm_zone;
[718] 
[719]     return NGX_CONF_OK;
[720] }
[721] 
[722] 
[723] static ngx_int_t
[724] ngx_http_limit_conn_add_variables(ngx_conf_t *cf)
[725] {
[726]     ngx_http_variable_t  *var, *v;
[727] 
[728]     for (v = ngx_http_limit_conn_vars; v->name.len; v++) {
[729]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[730]         if (var == NULL) {
[731]             return NGX_ERROR;
[732]         }
[733] 
[734]         var->get_handler = v->get_handler;
[735]         var->data = v->data;
[736]     }
[737] 
[738]     return NGX_OK;
[739] }
[740] 
[741] 
[742] static ngx_int_t
[743] ngx_http_limit_conn_init(ngx_conf_t *cf)
[744] {
[745]     ngx_http_handler_pt        *h;
[746]     ngx_http_core_main_conf_t  *cmcf;
[747] 
[748]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[749] 
[750]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
[751]     if (h == NULL) {
[752]         return NGX_ERROR;
[753]     }
[754] 
[755]     *h = ngx_http_limit_conn_handler;
[756] 
[757]     return NGX_OK;
[758] }
