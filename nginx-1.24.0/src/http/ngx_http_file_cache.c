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
[11] #include <ngx_md5.h>
[12] 
[13] 
[14] static ngx_int_t ngx_http_file_cache_lock(ngx_http_request_t *r,
[15]     ngx_http_cache_t *c);
[16] static void ngx_http_file_cache_lock_wait_handler(ngx_event_t *ev);
[17] static void ngx_http_file_cache_lock_wait(ngx_http_request_t *r,
[18]     ngx_http_cache_t *c);
[19] static ngx_int_t ngx_http_file_cache_read(ngx_http_request_t *r,
[20]     ngx_http_cache_t *c);
[21] static ssize_t ngx_http_file_cache_aio_read(ngx_http_request_t *r,
[22]     ngx_http_cache_t *c);
[23] #if (NGX_HAVE_FILE_AIO)
[24] static void ngx_http_cache_aio_event_handler(ngx_event_t *ev);
[25] #endif
[26] #if (NGX_THREADS)
[27] static ngx_int_t ngx_http_cache_thread_handler(ngx_thread_task_t *task,
[28]     ngx_file_t *file);
[29] static void ngx_http_cache_thread_event_handler(ngx_event_t *ev);
[30] #endif
[31] static ngx_int_t ngx_http_file_cache_exists(ngx_http_file_cache_t *cache,
[32]     ngx_http_cache_t *c);
[33] static ngx_int_t ngx_http_file_cache_name(ngx_http_request_t *r,
[34]     ngx_path_t *path);
[35] static ngx_http_file_cache_node_t *
[36]     ngx_http_file_cache_lookup(ngx_http_file_cache_t *cache, u_char *key);
[37] static void ngx_http_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
[38]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[39] static void ngx_http_file_cache_vary(ngx_http_request_t *r, u_char *vary,
[40]     size_t len, u_char *hash);
[41] static void ngx_http_file_cache_vary_header(ngx_http_request_t *r,
[42]     ngx_md5_t *md5, ngx_str_t *name);
[43] static ngx_int_t ngx_http_file_cache_reopen(ngx_http_request_t *r,
[44]     ngx_http_cache_t *c);
[45] static ngx_int_t ngx_http_file_cache_update_variant(ngx_http_request_t *r,
[46]     ngx_http_cache_t *c);
[47] static void ngx_http_file_cache_cleanup(void *data);
[48] static time_t ngx_http_file_cache_forced_expire(ngx_http_file_cache_t *cache);
[49] static time_t ngx_http_file_cache_expire(ngx_http_file_cache_t *cache);
[50] static void ngx_http_file_cache_delete(ngx_http_file_cache_t *cache,
[51]     ngx_queue_t *q, u_char *name);
[52] static void ngx_http_file_cache_loader_sleep(ngx_http_file_cache_t *cache);
[53] static ngx_int_t ngx_http_file_cache_noop(ngx_tree_ctx_t *ctx,
[54]     ngx_str_t *path);
[55] static ngx_int_t ngx_http_file_cache_manage_file(ngx_tree_ctx_t *ctx,
[56]     ngx_str_t *path);
[57] static ngx_int_t ngx_http_file_cache_manage_directory(ngx_tree_ctx_t *ctx,
[58]     ngx_str_t *path);
[59] static ngx_int_t ngx_http_file_cache_add_file(ngx_tree_ctx_t *ctx,
[60]     ngx_str_t *path);
[61] static ngx_int_t ngx_http_file_cache_add(ngx_http_file_cache_t *cache,
[62]     ngx_http_cache_t *c);
[63] static ngx_int_t ngx_http_file_cache_delete_file(ngx_tree_ctx_t *ctx,
[64]     ngx_str_t *path);
[65] static void ngx_http_file_cache_set_watermark(ngx_http_file_cache_t *cache);
[66] 
[67] 
[68] ngx_str_t  ngx_http_cache_status[] = {
[69]     ngx_string("MISS"),
[70]     ngx_string("BYPASS"),
[71]     ngx_string("EXPIRED"),
[72]     ngx_string("STALE"),
[73]     ngx_string("UPDATING"),
[74]     ngx_string("REVALIDATED"),
[75]     ngx_string("HIT")
[76] };
[77] 
[78] 
[79] static u_char  ngx_http_file_cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };
[80] 
[81] 
[82] static ngx_int_t
[83] ngx_http_file_cache_init(ngx_shm_zone_t *shm_zone, void *data)
[84] {
[85]     ngx_http_file_cache_t  *ocache = data;
[86] 
[87]     size_t                  len;
[88]     ngx_uint_t              n;
[89]     ngx_http_file_cache_t  *cache;
[90] 
[91]     cache = shm_zone->data;
[92] 
[93]     if (ocache) {
[94]         if (ngx_strcmp(cache->path->name.data, ocache->path->name.data) != 0) {
[95]             ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
[96]                           "cache \"%V\" uses the \"%V\" cache path "
[97]                           "while previously it used the \"%V\" cache path",
[98]                           &shm_zone->shm.name, &cache->path->name,
[99]                           &ocache->path->name);
[100] 
[101]             return NGX_ERROR;
[102]         }
[103] 
[104]         for (n = 0; n < NGX_MAX_PATH_LEVEL; n++) {
[105]             if (cache->path->level[n] != ocache->path->level[n]) {
[106]                 ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
[107]                               "cache \"%V\" had previously different levels",
[108]                               &shm_zone->shm.name);
[109]                 return NGX_ERROR;
[110]             }
[111]         }
[112] 
[113]         cache->sh = ocache->sh;
[114] 
[115]         cache->shpool = ocache->shpool;
[116]         cache->bsize = ocache->bsize;
[117] 
[118]         cache->max_size /= cache->bsize;
[119] 
[120]         if (!cache->sh->cold || cache->sh->loading) {
[121]             cache->path->loader = NULL;
[122]         }
[123] 
[124]         return NGX_OK;
[125]     }
[126] 
[127]     cache->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[128] 
[129]     if (shm_zone->shm.exists) {
[130]         cache->sh = cache->shpool->data;
[131]         cache->bsize = ngx_fs_bsize(cache->path->name.data);
[132]         cache->max_size /= cache->bsize;
[133] 
[134]         return NGX_OK;
[135]     }
[136] 
[137]     cache->sh = ngx_slab_alloc(cache->shpool, sizeof(ngx_http_file_cache_sh_t));
[138]     if (cache->sh == NULL) {
[139]         return NGX_ERROR;
[140]     }
[141] 
[142]     cache->shpool->data = cache->sh;
[143] 
[144]     ngx_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel,
[145]                     ngx_http_file_cache_rbtree_insert_value);
[146] 
[147]     ngx_queue_init(&cache->sh->queue);
[148] 
[149]     cache->sh->cold = 1;
[150]     cache->sh->loading = 0;
[151]     cache->sh->size = 0;
[152]     cache->sh->count = 0;
[153]     cache->sh->watermark = (ngx_uint_t) -1;
[154] 
[155]     cache->bsize = ngx_fs_bsize(cache->path->name.data);
[156] 
[157]     cache->max_size /= cache->bsize;
[158] 
[159]     len = sizeof(" in cache keys zone \"\"") + shm_zone->shm.name.len;
[160] 
[161]     cache->shpool->log_ctx = ngx_slab_alloc(cache->shpool, len);
[162]     if (cache->shpool->log_ctx == NULL) {
[163]         return NGX_ERROR;
[164]     }
[165] 
[166]     ngx_sprintf(cache->shpool->log_ctx, " in cache keys zone \"%V\"%Z",
[167]                 &shm_zone->shm.name);
[168] 
[169]     cache->shpool->log_nomem = 0;
[170] 
[171]     return NGX_OK;
[172] }
[173] 
[174] 
[175] ngx_int_t
[176] ngx_http_file_cache_new(ngx_http_request_t *r)
[177] {
[178]     ngx_http_cache_t  *c;
[179] 
[180]     c = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_t));
[181]     if (c == NULL) {
[182]         return NGX_ERROR;
[183]     }
[184] 
[185]     if (ngx_array_init(&c->keys, r->pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
[186]         return NGX_ERROR;
[187]     }
[188] 
[189]     r->cache = c;
[190]     c->file.log = r->connection->log;
[191]     c->file.fd = NGX_INVALID_FILE;
[192] 
[193]     return NGX_OK;
[194] }
[195] 
[196] 
[197] ngx_int_t
[198] ngx_http_file_cache_create(ngx_http_request_t *r)
[199] {
[200]     ngx_http_cache_t       *c;
[201]     ngx_pool_cleanup_t     *cln;
[202]     ngx_http_file_cache_t  *cache;
[203] 
[204]     c = r->cache;
[205]     cache = c->file_cache;
[206] 
[207]     cln = ngx_pool_cleanup_add(r->pool, 0);
[208]     if (cln == NULL) {
[209]         return NGX_ERROR;
[210]     }
[211] 
[212]     cln->handler = ngx_http_file_cache_cleanup;
[213]     cln->data = c;
[214] 
[215]     if (ngx_http_file_cache_exists(cache, c) == NGX_ERROR) {
[216]         return NGX_ERROR;
[217]     }
[218] 
[219]     if (ngx_http_file_cache_name(r, cache->path) != NGX_OK) {
[220]         return NGX_ERROR;
[221]     }
[222] 
[223]     return NGX_OK;
[224] }
[225] 
[226] 
[227] void
[228] ngx_http_file_cache_create_key(ngx_http_request_t *r)
[229] {
[230]     size_t             len;
[231]     ngx_str_t         *key;
[232]     ngx_uint_t         i;
[233]     ngx_md5_t          md5;
[234]     ngx_http_cache_t  *c;
[235] 
[236]     c = r->cache;
[237] 
[238]     len = 0;
[239] 
[240]     ngx_crc32_init(c->crc32);
[241]     ngx_md5_init(&md5);
[242] 
[243]     key = c->keys.elts;
[244]     for (i = 0; i < c->keys.nelts; i++) {
[245]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[246]                        "http cache key: \"%V\"", &key[i]);
[247] 
[248]         len += key[i].len;
[249] 
[250]         ngx_crc32_update(&c->crc32, key[i].data, key[i].len);
[251]         ngx_md5_update(&md5, key[i].data, key[i].len);
[252]     }
[253] 
[254]     c->header_start = sizeof(ngx_http_file_cache_header_t)
[255]                       + sizeof(ngx_http_file_cache_key) + len + 1;
[256] 
[257]     ngx_crc32_final(c->crc32);
[258]     ngx_md5_final(c->key, &md5);
[259] 
[260]     ngx_memcpy(c->main, c->key, NGX_HTTP_CACHE_KEY_LEN);
[261] }
[262] 
[263] 
[264] ngx_int_t
[265] ngx_http_file_cache_open(ngx_http_request_t *r)
[266] {
[267]     ngx_int_t                  rc, rv;
[268]     ngx_uint_t                 test;
[269]     ngx_http_cache_t          *c;
[270]     ngx_pool_cleanup_t        *cln;
[271]     ngx_open_file_info_t       of;
[272]     ngx_http_file_cache_t     *cache;
[273]     ngx_http_core_loc_conf_t  *clcf;
[274] 
[275]     c = r->cache;
[276] 
[277]     if (c->waiting) {
[278]         return NGX_AGAIN;
[279]     }
[280] 
[281]     if (c->reading) {
[282]         return ngx_http_file_cache_read(r, c);
[283]     }
[284] 
[285]     cache = c->file_cache;
[286] 
[287]     if (c->node == NULL) {
[288]         cln = ngx_pool_cleanup_add(r->pool, 0);
[289]         if (cln == NULL) {
[290]             return NGX_ERROR;
[291]         }
[292] 
[293]         cln->handler = ngx_http_file_cache_cleanup;
[294]         cln->data = c;
[295]     }
[296] 
[297]     c->buffer_size = c->body_start;
[298] 
[299]     rc = ngx_http_file_cache_exists(cache, c);
[300] 
[301]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[302]                    "http file cache exists: %i e:%d", rc, c->exists);
[303] 
[304]     if (rc == NGX_ERROR) {
[305]         return rc;
[306]     }
[307] 
[308]     if (rc == NGX_AGAIN) {
[309]         return NGX_HTTP_CACHE_SCARCE;
[310]     }
[311] 
[312]     if (rc == NGX_OK) {
[313] 
[314]         if (c->error) {
[315]             return c->error;
[316]         }
[317] 
[318]         c->temp_file = 1;
[319]         test = c->exists ? 1 : 0;
[320]         rv = NGX_DECLINED;
[321] 
[322]     } else { /* rc == NGX_DECLINED */
[323] 
[324]         test = cache->sh->cold ? 1 : 0;
[325] 
[326]         if (c->min_uses > 1) {
[327] 
[328]             if (!test) {
[329]                 return NGX_HTTP_CACHE_SCARCE;
[330]             }
[331] 
[332]             rv = NGX_HTTP_CACHE_SCARCE;
[333] 
[334]         } else {
[335]             c->temp_file = 1;
[336]             rv = NGX_DECLINED;
[337]         }
[338]     }
[339] 
[340]     if (ngx_http_file_cache_name(r, cache->path) != NGX_OK) {
[341]         return NGX_ERROR;
[342]     }
[343] 
[344]     if (!test) {
[345]         goto done;
[346]     }
[347] 
[348]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[349] 
[350]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[351] 
[352]     of.uniq = c->uniq;
[353]     of.valid = clcf->open_file_cache_valid;
[354]     of.min_uses = clcf->open_file_cache_min_uses;
[355]     of.events = clcf->open_file_cache_events;
[356]     of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;
[357]     of.read_ahead = clcf->read_ahead;
[358] 
[359]     if (ngx_open_cached_file(clcf->open_file_cache, &c->file.name, &of, r->pool)
[360]         != NGX_OK)
[361]     {
[362]         switch (of.err) {
[363] 
[364]         case 0:
[365]             return NGX_ERROR;
[366] 
[367]         case NGX_ENOENT:
[368]         case NGX_ENOTDIR:
[369]             goto done;
[370] 
[371]         default:
[372]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
[373]                           ngx_open_file_n " \"%s\" failed", c->file.name.data);
[374]             return NGX_ERROR;
[375]         }
[376]     }
[377] 
[378]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[379]                    "http file cache fd: %d", of.fd);
[380] 
[381]     c->file.fd = of.fd;
[382]     c->file.log = r->connection->log;
[383]     c->uniq = of.uniq;
[384]     c->length = of.size;
[385]     c->fs_size = (of.fs_size + cache->bsize - 1) / cache->bsize;
[386] 
[387]     c->buf = ngx_create_temp_buf(r->pool, c->body_start);
[388]     if (c->buf == NULL) {
[389]         return NGX_ERROR;
[390]     }
[391] 
[392]     return ngx_http_file_cache_read(r, c);
[393] 
[394] done:
[395] 
[396]     if (rv == NGX_DECLINED) {
[397]         return ngx_http_file_cache_lock(r, c);
[398]     }
[399] 
[400]     return rv;
[401] }
[402] 
[403] 
[404] static ngx_int_t
[405] ngx_http_file_cache_lock(ngx_http_request_t *r, ngx_http_cache_t *c)
[406] {
[407]     ngx_msec_t                 now, timer;
[408]     ngx_http_file_cache_t     *cache;
[409] 
[410]     if (!c->lock) {
[411]         return NGX_DECLINED;
[412]     }
[413] 
[414]     now = ngx_current_msec;
[415] 
[416]     cache = c->file_cache;
[417] 
[418]     ngx_shmtx_lock(&cache->shpool->mutex);
[419] 
[420]     timer = c->node->lock_time - now;
[421] 
[422]     if (!c->node->updating || (ngx_msec_int_t) timer <= 0) {
[423]         c->node->updating = 1;
[424]         c->node->lock_time = now + c->lock_age;
[425]         c->updating = 1;
[426]         c->lock_time = c->node->lock_time;
[427]     }
[428] 
[429]     ngx_shmtx_unlock(&cache->shpool->mutex);
[430] 
[431]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[432]                    "http file cache lock u:%d wt:%M",
[433]                    c->updating, c->wait_time);
[434] 
[435]     if (c->updating) {
[436]         return NGX_DECLINED;
[437]     }
[438] 
[439]     if (c->lock_timeout == 0) {
[440]         return NGX_HTTP_CACHE_SCARCE;
[441]     }
[442] 
[443]     c->waiting = 1;
[444] 
[445]     if (c->wait_time == 0) {
[446]         c->wait_time = now + c->lock_timeout;
[447] 
[448]         c->wait_event.handler = ngx_http_file_cache_lock_wait_handler;
[449]         c->wait_event.data = r;
[450]         c->wait_event.log = r->connection->log;
[451]     }
[452] 
[453]     timer = c->wait_time - now;
[454] 
[455]     ngx_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
[456] 
[457]     r->main->blocked++;
[458] 
[459]     return NGX_AGAIN;
[460] }
[461] 
[462] 
[463] static void
[464] ngx_http_file_cache_lock_wait_handler(ngx_event_t *ev)
[465] {
[466]     ngx_connection_t    *c;
[467]     ngx_http_request_t  *r;
[468] 
[469]     r = ev->data;
[470]     c = r->connection;
[471] 
[472]     ngx_http_set_log_request(c->log, r);
[473] 
[474]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[475]                    "http file cache wait: \"%V?%V\"", &r->uri, &r->args);
[476] 
[477]     ngx_http_file_cache_lock_wait(r, r->cache);
[478] 
[479]     ngx_http_run_posted_requests(c);
[480] }
[481] 
[482] 
[483] static void
[484] ngx_http_file_cache_lock_wait(ngx_http_request_t *r, ngx_http_cache_t *c)
[485] {
[486]     ngx_uint_t              wait;
[487]     ngx_msec_t              now, timer;
[488]     ngx_http_file_cache_t  *cache;
[489] 
[490]     now = ngx_current_msec;
[491] 
[492]     timer = c->wait_time - now;
[493] 
[494]     if ((ngx_msec_int_t) timer <= 0) {
[495]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[496]                       "cache lock timeout");
[497]         c->lock_timeout = 0;
[498]         goto wakeup;
[499]     }
[500] 
[501]     cache = c->file_cache;
[502]     wait = 0;
[503] 
[504]     ngx_shmtx_lock(&cache->shpool->mutex);
[505] 
[506]     timer = c->node->lock_time - now;
[507] 
[508]     if (c->node->updating && (ngx_msec_int_t) timer > 0) {
[509]         wait = 1;
[510]     }
[511] 
[512]     ngx_shmtx_unlock(&cache->shpool->mutex);
[513] 
[514]     if (wait) {
[515]         ngx_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
[516]         return;
[517]     }
[518] 
[519] wakeup:
[520] 
[521]     c->waiting = 0;
[522]     r->main->blocked--;
[523]     r->write_event_handler(r);
[524] }
[525] 
[526] 
[527] static ngx_int_t
[528] ngx_http_file_cache_read(ngx_http_request_t *r, ngx_http_cache_t *c)
[529] {
[530]     u_char                        *p;
[531]     time_t                         now;
[532]     ssize_t                        n;
[533]     ngx_str_t                     *key;
[534]     ngx_int_t                      rc;
[535]     ngx_uint_t                     i;
[536]     ngx_http_file_cache_t         *cache;
[537]     ngx_http_file_cache_header_t  *h;
[538] 
[539]     n = ngx_http_file_cache_aio_read(r, c);
[540] 
[541]     if (n < 0) {
[542]         return n;
[543]     }
[544] 
[545]     if ((size_t) n < c->header_start) {
[546]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[547]                       "cache file \"%s\" is too small", c->file.name.data);
[548]         return NGX_DECLINED;
[549]     }
[550] 
[551]     h = (ngx_http_file_cache_header_t *) c->buf->pos;
[552] 
[553]     if (h->version != NGX_HTTP_CACHE_VERSION) {
[554]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[555]                       "cache file \"%s\" version mismatch", c->file.name.data);
[556]         return NGX_DECLINED;
[557]     }
[558] 
[559]     if (h->crc32 != c->crc32 || (size_t) h->header_start != c->header_start) {
[560]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[561]                       "cache file \"%s\" has md5 collision", c->file.name.data);
[562]         return NGX_DECLINED;
[563]     }
[564] 
[565]     p = c->buf->pos + sizeof(ngx_http_file_cache_header_t)
[566]         + sizeof(ngx_http_file_cache_key);
[567] 
[568]     key = c->keys.elts;
[569]     for (i = 0; i < c->keys.nelts; i++) {
[570]         if (ngx_memcmp(p, key[i].data, key[i].len) != 0) {
[571]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[572]                           "cache file \"%s\" has md5 collision",
[573]                           c->file.name.data);
[574]             return NGX_DECLINED;
[575]         }
[576] 
[577]         p += key[i].len;
[578]     }
[579] 
[580]     if ((size_t) h->body_start > c->body_start) {
[581]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[582]                       "cache file \"%s\" has too long header",
[583]                       c->file.name.data);
[584]         return NGX_DECLINED;
[585]     }
[586] 
[587]     if (h->vary_len > NGX_HTTP_CACHE_VARY_LEN) {
[588]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[589]                       "cache file \"%s\" has incorrect vary length",
[590]                       c->file.name.data);
[591]         return NGX_DECLINED;
[592]     }
[593] 
[594]     if (h->vary_len) {
[595]         ngx_http_file_cache_vary(r, h->vary, h->vary_len, c->variant);
[596] 
[597]         if (ngx_memcmp(c->variant, h->variant, NGX_HTTP_CACHE_KEY_LEN) != 0) {
[598]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[599]                            "http file cache vary mismatch");
[600]             return ngx_http_file_cache_reopen(r, c);
[601]         }
[602]     }
[603] 
[604]     c->buf->last += n;
[605] 
[606]     c->valid_sec = h->valid_sec;
[607]     c->updating_sec = h->updating_sec;
[608]     c->error_sec = h->error_sec;
[609]     c->last_modified = h->last_modified;
[610]     c->date = h->date;
[611]     c->valid_msec = h->valid_msec;
[612]     c->body_start = h->body_start;
[613]     c->etag.len = h->etag_len;
[614]     c->etag.data = h->etag;
[615] 
[616]     r->cached = 1;
[617] 
[618]     cache = c->file_cache;
[619] 
[620]     if (cache->sh->cold) {
[621] 
[622]         ngx_shmtx_lock(&cache->shpool->mutex);
[623] 
[624]         if (!c->node->exists) {
[625]             c->node->uses = 1;
[626]             c->node->body_start = c->body_start;
[627]             c->node->exists = 1;
[628]             c->node->uniq = c->uniq;
[629]             c->node->fs_size = c->fs_size;
[630] 
[631]             cache->sh->size += c->fs_size;
[632]         }
[633] 
[634]         ngx_shmtx_unlock(&cache->shpool->mutex);
[635]     }
[636] 
[637]     now = ngx_time();
[638] 
[639]     if (c->valid_sec < now) {
[640]         c->stale_updating = c->valid_sec + c->updating_sec >= now;
[641]         c->stale_error = c->valid_sec + c->error_sec >= now;
[642] 
[643]         ngx_shmtx_lock(&cache->shpool->mutex);
[644] 
[645]         if (c->node->updating) {
[646]             rc = NGX_HTTP_CACHE_UPDATING;
[647] 
[648]         } else {
[649]             c->node->updating = 1;
[650]             c->updating = 1;
[651]             c->lock_time = c->node->lock_time;
[652]             rc = NGX_HTTP_CACHE_STALE;
[653]         }
[654] 
[655]         ngx_shmtx_unlock(&cache->shpool->mutex);
[656] 
[657]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[658]                        "http file cache expired: %i %T %T",
[659]                        rc, c->valid_sec, now);
[660] 
[661]         return rc;
[662]     }
[663] 
[664]     return NGX_OK;
[665] }
[666] 
[667] 
[668] static ssize_t
[669] ngx_http_file_cache_aio_read(ngx_http_request_t *r, ngx_http_cache_t *c)
[670] {
[671] #if (NGX_HAVE_FILE_AIO || NGX_THREADS)
[672]     ssize_t                    n;
[673]     ngx_http_core_loc_conf_t  *clcf;
[674] 
[675]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[676] #endif
[677] 
[678] #if (NGX_HAVE_FILE_AIO)
[679] 
[680]     if (clcf->aio == NGX_HTTP_AIO_ON && ngx_file_aio) {
[681]         n = ngx_file_aio_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);
[682] 
[683]         if (n != NGX_AGAIN) {
[684]             c->reading = 0;
[685]             return n;
[686]         }
[687] 
[688]         c->reading = 1;
[689] 
[690]         c->file.aio->data = r;
[691]         c->file.aio->handler = ngx_http_cache_aio_event_handler;
[692] 
[693]         r->main->blocked++;
[694]         r->aio = 1;
[695] 
[696]         return NGX_AGAIN;
[697]     }
[698] 
[699] #endif
[700] 
[701] #if (NGX_THREADS)
[702] 
[703]     if (clcf->aio == NGX_HTTP_AIO_THREADS) {
[704]         c->file.thread_task = c->thread_task;
[705]         c->file.thread_handler = ngx_http_cache_thread_handler;
[706]         c->file.thread_ctx = r;
[707] 
[708]         n = ngx_thread_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);
[709] 
[710]         c->thread_task = c->file.thread_task;
[711]         c->reading = (n == NGX_AGAIN);
[712] 
[713]         return n;
[714]     }
[715] 
[716] #endif
[717] 
[718]     return ngx_read_file(&c->file, c->buf->pos, c->body_start, 0);
[719] }
[720] 
[721] 
[722] #if (NGX_HAVE_FILE_AIO)
[723] 
[724] static void
[725] ngx_http_cache_aio_event_handler(ngx_event_t *ev)
[726] {
[727]     ngx_event_aio_t     *aio;
[728]     ngx_connection_t    *c;
[729]     ngx_http_request_t  *r;
[730] 
[731]     aio = ev->data;
[732]     r = aio->data;
[733]     c = r->connection;
[734] 
[735]     ngx_http_set_log_request(c->log, r);
[736] 
[737]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[738]                    "http file cache aio: \"%V?%V\"", &r->uri, &r->args);
[739] 
[740]     r->main->blocked--;
[741]     r->aio = 0;
[742] 
[743]     r->write_event_handler(r);
[744] 
[745]     ngx_http_run_posted_requests(c);
[746] }
[747] 
[748] #endif
[749] 
[750] 
[751] #if (NGX_THREADS)
[752] 
[753] static ngx_int_t
[754] ngx_http_cache_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)
[755] {
[756]     ngx_str_t                  name;
[757]     ngx_thread_pool_t         *tp;
[758]     ngx_http_request_t        *r;
[759]     ngx_http_core_loc_conf_t  *clcf;
[760] 
[761]     r = file->thread_ctx;
[762] 
[763]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[764]     tp = clcf->thread_pool;
[765] 
[766]     if (tp == NULL) {
[767]         if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
[768]             != NGX_OK)
[769]         {
[770]             return NGX_ERROR;
[771]         }
[772] 
[773]         tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);
[774] 
[775]         if (tp == NULL) {
[776]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[777]                           "thread pool \"%V\" not found", &name);
[778]             return NGX_ERROR;
[779]         }
[780]     }
[781] 
[782]     task->event.data = r;
[783]     task->event.handler = ngx_http_cache_thread_event_handler;
[784] 
[785]     if (ngx_thread_task_post(tp, task) != NGX_OK) {
[786]         return NGX_ERROR;
[787]     }
[788] 
[789]     r->main->blocked++;
[790]     r->aio = 1;
[791] 
[792]     return NGX_OK;
[793] }
[794] 
[795] 
[796] static void
[797] ngx_http_cache_thread_event_handler(ngx_event_t *ev)
[798] {
[799]     ngx_connection_t    *c;
[800]     ngx_http_request_t  *r;
[801] 
[802]     r = ev->data;
[803]     c = r->connection;
[804] 
[805]     ngx_http_set_log_request(c->log, r);
[806] 
[807]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[808]                    "http file cache thread: \"%V?%V\"", &r->uri, &r->args);
[809] 
[810]     r->main->blocked--;
[811]     r->aio = 0;
[812] 
[813]     r->write_event_handler(r);
[814] 
[815]     ngx_http_run_posted_requests(c);
[816] }
[817] 
[818] #endif
[819] 
[820] 
[821] static ngx_int_t
[822] ngx_http_file_cache_exists(ngx_http_file_cache_t *cache, ngx_http_cache_t *c)
[823] {
[824]     ngx_int_t                    rc;
[825]     ngx_http_file_cache_node_t  *fcn;
[826] 
[827]     ngx_shmtx_lock(&cache->shpool->mutex);
[828] 
[829]     fcn = c->node;
[830] 
[831]     if (fcn == NULL) {
[832]         fcn = ngx_http_file_cache_lookup(cache, c->key);
[833]     }
[834] 
[835]     if (fcn) {
[836]         ngx_queue_remove(&fcn->queue);
[837] 
[838]         if (c->node == NULL) {
[839]             fcn->uses++;
[840]             fcn->count++;
[841]         }
[842] 
[843]         if (fcn->error) {
[844] 
[845]             if (fcn->valid_sec < ngx_time()) {
[846]                 goto renew;
[847]             }
[848] 
[849]             rc = NGX_OK;
[850] 
[851]             goto done;
[852]         }
[853] 
[854]         if (fcn->exists || fcn->uses >= c->min_uses) {
[855] 
[856]             c->exists = fcn->exists;
[857]             if (fcn->body_start && !c->update_variant) {
[858]                 c->body_start = fcn->body_start;
[859]             }
[860] 
[861]             rc = NGX_OK;
[862] 
[863]             goto done;
[864]         }
[865] 
[866]         rc = NGX_AGAIN;
[867] 
[868]         goto done;
[869]     }
[870] 
[871]     fcn = ngx_slab_calloc_locked(cache->shpool,
[872]                                  sizeof(ngx_http_file_cache_node_t));
[873]     if (fcn == NULL) {
[874]         ngx_http_file_cache_set_watermark(cache);
[875] 
[876]         ngx_shmtx_unlock(&cache->shpool->mutex);
[877] 
[878]         (void) ngx_http_file_cache_forced_expire(cache);
[879] 
[880]         ngx_shmtx_lock(&cache->shpool->mutex);
[881] 
[882]         fcn = ngx_slab_calloc_locked(cache->shpool,
[883]                                      sizeof(ngx_http_file_cache_node_t));
[884]         if (fcn == NULL) {
[885]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[886]                           "could not allocate node%s", cache->shpool->log_ctx);
[887]             rc = NGX_ERROR;
[888]             goto failed;
[889]         }
[890]     }
[891] 
[892]     cache->sh->count++;
[893] 
[894]     ngx_memcpy((u_char *) &fcn->node.key, c->key, sizeof(ngx_rbtree_key_t));
[895] 
[896]     ngx_memcpy(fcn->key, &c->key[sizeof(ngx_rbtree_key_t)],
[897]                NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
[898] 
[899]     ngx_rbtree_insert(&cache->sh->rbtree, &fcn->node);
[900] 
[901]     fcn->uses = 1;
[902]     fcn->count = 1;
[903] 
[904] renew:
[905] 
[906]     rc = NGX_DECLINED;
[907] 
[908]     fcn->valid_msec = 0;
[909]     fcn->error = 0;
[910]     fcn->exists = 0;
[911]     fcn->valid_sec = 0;
[912]     fcn->uniq = 0;
[913]     fcn->body_start = 0;
[914]     fcn->fs_size = 0;
[915] 
[916] done:
[917] 
[918]     fcn->expire = ngx_time() + cache->inactive;
[919] 
[920]     ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);
[921] 
[922]     c->uniq = fcn->uniq;
[923]     c->error = fcn->error;
[924]     c->node = fcn;
[925] 
[926] failed:
[927] 
[928]     ngx_shmtx_unlock(&cache->shpool->mutex);
[929] 
[930]     return rc;
[931] }
[932] 
[933] 
[934] static ngx_int_t
[935] ngx_http_file_cache_name(ngx_http_request_t *r, ngx_path_t *path)
[936] {
[937]     u_char            *p;
[938]     ngx_http_cache_t  *c;
[939] 
[940]     c = r->cache;
[941] 
[942]     if (c->file.name.len) {
[943]         return NGX_OK;
[944]     }
[945] 
[946]     c->file.name.len = path->name.len + 1 + path->len
[947]                        + 2 * NGX_HTTP_CACHE_KEY_LEN;
[948] 
[949]     c->file.name.data = ngx_pnalloc(r->pool, c->file.name.len + 1);
[950]     if (c->file.name.data == NULL) {
[951]         return NGX_ERROR;
[952]     }
[953] 
[954]     ngx_memcpy(c->file.name.data, path->name.data, path->name.len);
[955] 
[956]     p = c->file.name.data + path->name.len + 1 + path->len;
[957]     p = ngx_hex_dump(p, c->key, NGX_HTTP_CACHE_KEY_LEN);
[958]     *p = '\0';
[959] 
[960]     ngx_create_hashed_filename(path, c->file.name.data, c->file.name.len);
[961] 
[962]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[963]                    "cache file: \"%s\"", c->file.name.data);
[964] 
[965]     return NGX_OK;
[966] }
[967] 
[968] 
[969] static ngx_http_file_cache_node_t *
[970] ngx_http_file_cache_lookup(ngx_http_file_cache_t *cache, u_char *key)
[971] {
[972]     ngx_int_t                    rc;
[973]     ngx_rbtree_key_t             node_key;
[974]     ngx_rbtree_node_t           *node, *sentinel;
[975]     ngx_http_file_cache_node_t  *fcn;
[976] 
[977]     ngx_memcpy((u_char *) &node_key, key, sizeof(ngx_rbtree_key_t));
[978] 
[979]     node = cache->sh->rbtree.root;
[980]     sentinel = cache->sh->rbtree.sentinel;
[981] 
[982]     while (node != sentinel) {
[983] 
[984]         if (node_key < node->key) {
[985]             node = node->left;
[986]             continue;
[987]         }
[988] 
[989]         if (node_key > node->key) {
[990]             node = node->right;
[991]             continue;
[992]         }
[993] 
[994]         /* node_key == node->key */
[995] 
[996]         fcn = (ngx_http_file_cache_node_t *) node;
[997] 
[998]         rc = ngx_memcmp(&key[sizeof(ngx_rbtree_key_t)], fcn->key,
[999]                         NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
[1000] 
[1001]         if (rc == 0) {
[1002]             return fcn;
[1003]         }
[1004] 
[1005]         node = (rc < 0) ? node->left : node->right;
[1006]     }
[1007] 
[1008]     /* not found */
[1009] 
[1010]     return NULL;
[1011] }
[1012] 
[1013] 
[1014] static void
[1015] ngx_http_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
[1016]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[1017] {
[1018]     ngx_rbtree_node_t           **p;
[1019]     ngx_http_file_cache_node_t   *cn, *cnt;
[1020] 
[1021]     for ( ;; ) {
[1022] 
[1023]         if (node->key < temp->key) {
[1024] 
[1025]             p = &temp->left;
[1026] 
[1027]         } else if (node->key > temp->key) {
[1028] 
[1029]             p = &temp->right;
[1030] 
[1031]         } else { /* node->key == temp->key */
[1032] 
[1033]             cn = (ngx_http_file_cache_node_t *) node;
[1034]             cnt = (ngx_http_file_cache_node_t *) temp;
[1035] 
[1036]             p = (ngx_memcmp(cn->key, cnt->key,
[1037]                             NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t))
[1038]                  < 0)
[1039]                     ? &temp->left : &temp->right;
[1040]         }
[1041] 
[1042]         if (*p == sentinel) {
[1043]             break;
[1044]         }
[1045] 
[1046]         temp = *p;
[1047]     }
[1048] 
[1049]     *p = node;
[1050]     node->parent = temp;
[1051]     node->left = sentinel;
[1052]     node->right = sentinel;
[1053]     ngx_rbt_red(node);
[1054] }
[1055] 
[1056] 
[1057] static void
[1058] ngx_http_file_cache_vary(ngx_http_request_t *r, u_char *vary, size_t len,
[1059]     u_char *hash)
[1060] {
[1061]     u_char     *p, *last;
[1062]     ngx_str_t   name;
[1063]     ngx_md5_t   md5;
[1064]     u_char      buf[NGX_HTTP_CACHE_VARY_LEN];
[1065] 
[1066]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1067]                    "http file cache vary: \"%*s\"", len, vary);
[1068] 
[1069]     ngx_md5_init(&md5);
[1070]     ngx_md5_update(&md5, r->cache->main, NGX_HTTP_CACHE_KEY_LEN);
[1071] 
[1072]     ngx_strlow(buf, vary, len);
[1073] 
[1074]     p = buf;
[1075]     last = buf + len;
[1076] 
[1077]     while (p < last) {
[1078] 
[1079]         while (p < last && (*p == ' ' || *p == ',')) { p++; }
[1080] 
[1081]         name.data = p;
[1082] 
[1083]         while (p < last && *p != ',' && *p != ' ') { p++; }
[1084] 
[1085]         name.len = p - name.data;
[1086] 
[1087]         if (name.len == 0) {
[1088]             break;
[1089]         }
[1090] 
[1091]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1092]                        "http file cache vary: %V", &name);
[1093] 
[1094]         ngx_md5_update(&md5, name.data, name.len);
[1095]         ngx_md5_update(&md5, (u_char *) ":", sizeof(":") - 1);
[1096] 
[1097]         ngx_http_file_cache_vary_header(r, &md5, &name);
[1098] 
[1099]         ngx_md5_update(&md5, (u_char *) CRLF, sizeof(CRLF) - 1);
[1100]     }
[1101] 
[1102]     ngx_md5_final(hash, &md5);
[1103] }
[1104] 
[1105] 
[1106] static void
[1107] ngx_http_file_cache_vary_header(ngx_http_request_t *r, ngx_md5_t *md5,
[1108]     ngx_str_t *name)
[1109] {
[1110]     size_t            len;
[1111]     u_char           *p, *start, *last;
[1112]     ngx_uint_t        i, multiple, normalize;
[1113]     ngx_list_part_t  *part;
[1114]     ngx_table_elt_t  *header;
[1115] 
[1116]     multiple = 0;
[1117]     normalize = 0;
[1118] 
[1119]     if (name->len == sizeof("Accept-Charset") - 1
[1120]         && ngx_strncasecmp(name->data, (u_char *) "Accept-Charset",
[1121]                            sizeof("Accept-Charset") - 1) == 0)
[1122]     {
[1123]         normalize = 1;
[1124] 
[1125]     } else if (name->len == sizeof("Accept-Encoding") - 1
[1126]         && ngx_strncasecmp(name->data, (u_char *) "Accept-Encoding",
[1127]                            sizeof("Accept-Encoding") - 1) == 0)
[1128]     {
[1129]         normalize = 1;
[1130] 
[1131]     } else if (name->len == sizeof("Accept-Language") - 1
[1132]         && ngx_strncasecmp(name->data, (u_char *) "Accept-Language",
[1133]                            sizeof("Accept-Language") - 1) == 0)
[1134]     {
[1135]         normalize = 1;
[1136]     }
[1137] 
[1138]     part = &r->headers_in.headers.part;
[1139]     header = part->elts;
[1140] 
[1141]     for (i = 0; /* void */ ; i++) {
[1142] 
[1143]         if (i >= part->nelts) {
[1144]             if (part->next == NULL) {
[1145]                 break;
[1146]             }
[1147] 
[1148]             part = part->next;
[1149]             header = part->elts;
[1150]             i = 0;
[1151]         }
[1152] 
[1153]         if (header[i].hash == 0) {
[1154]             continue;
[1155]         }
[1156] 
[1157]         if (header[i].key.len != name->len) {
[1158]             continue;
[1159]         }
[1160] 
[1161]         if (ngx_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
[1162]             continue;
[1163]         }
[1164] 
[1165]         if (!normalize) {
[1166] 
[1167]             if (multiple) {
[1168]                 ngx_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
[1169]             }
[1170] 
[1171]             ngx_md5_update(md5, header[i].value.data, header[i].value.len);
[1172] 
[1173]             multiple = 1;
[1174] 
[1175]             continue;
[1176]         }
[1177] 
[1178]         /* normalize spaces */
[1179] 
[1180]         p = header[i].value.data;
[1181]         last = p + header[i].value.len;
[1182] 
[1183]         while (p < last) {
[1184] 
[1185]             while (p < last && (*p == ' ' || *p == ',')) { p++; }
[1186] 
[1187]             start = p;
[1188] 
[1189]             while (p < last && *p != ',' && *p != ' ') { p++; }
[1190] 
[1191]             len = p - start;
[1192] 
[1193]             if (len == 0) {
[1194]                 break;
[1195]             }
[1196] 
[1197]             if (multiple) {
[1198]                 ngx_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
[1199]             }
[1200] 
[1201]             ngx_md5_update(md5, start, len);
[1202] 
[1203]             multiple = 1;
[1204]         }
[1205]     }
[1206] }
[1207] 
[1208] 
[1209] static ngx_int_t
[1210] ngx_http_file_cache_reopen(ngx_http_request_t *r, ngx_http_cache_t *c)
[1211] {
[1212]     ngx_http_file_cache_t  *cache;
[1213] 
[1214]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
[1215]                    "http file cache reopen");
[1216] 
[1217]     if (c->secondary) {
[1218]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[1219]                       "cache file \"%s\" has incorrect vary hash",
[1220]                       c->file.name.data);
[1221]         return NGX_DECLINED;
[1222]     }
[1223] 
[1224]     cache = c->file_cache;
[1225] 
[1226]     ngx_shmtx_lock(&cache->shpool->mutex);
[1227] 
[1228]     c->node->count--;
[1229]     c->node = NULL;
[1230] 
[1231]     ngx_shmtx_unlock(&cache->shpool->mutex);
[1232] 
[1233]     c->secondary = 1;
[1234]     c->file.name.len = 0;
[1235]     c->body_start = c->buffer_size;
[1236] 
[1237]     ngx_memcpy(c->key, c->variant, NGX_HTTP_CACHE_KEY_LEN);
[1238] 
[1239]     return ngx_http_file_cache_open(r);
[1240] }
[1241] 
[1242] 
[1243] ngx_int_t
[1244] ngx_http_file_cache_set_header(ngx_http_request_t *r, u_char *buf)
[1245] {
[1246]     ngx_http_file_cache_header_t  *h = (ngx_http_file_cache_header_t *) buf;
[1247] 
[1248]     u_char            *p;
[1249]     ngx_str_t         *key;
[1250]     ngx_uint_t         i;
[1251]     ngx_http_cache_t  *c;
[1252] 
[1253]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1254]                    "http file cache set header");
[1255] 
[1256]     c = r->cache;
[1257] 
[1258]     ngx_memzero(h, sizeof(ngx_http_file_cache_header_t));
[1259] 
[1260]     h->version = NGX_HTTP_CACHE_VERSION;
[1261]     h->valid_sec = c->valid_sec;
[1262]     h->updating_sec = c->updating_sec;
[1263]     h->error_sec = c->error_sec;
[1264]     h->last_modified = c->last_modified;
[1265]     h->date = c->date;
[1266]     h->crc32 = c->crc32;
[1267]     h->valid_msec = (u_short) c->valid_msec;
[1268]     h->header_start = (u_short) c->header_start;
[1269]     h->body_start = (u_short) c->body_start;
[1270] 
[1271]     if (c->etag.len <= NGX_HTTP_CACHE_ETAG_LEN) {
[1272]         h->etag_len = (u_char) c->etag.len;
[1273]         ngx_memcpy(h->etag, c->etag.data, c->etag.len);
[1274]     }
[1275] 
[1276]     if (c->vary.len) {
[1277]         if (c->vary.len > NGX_HTTP_CACHE_VARY_LEN) {
[1278]             /* should not happen */
[1279]             c->vary.len = NGX_HTTP_CACHE_VARY_LEN;
[1280]         }
[1281] 
[1282]         h->vary_len = (u_char) c->vary.len;
[1283]         ngx_memcpy(h->vary, c->vary.data, c->vary.len);
[1284] 
[1285]         ngx_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
[1286]         ngx_memcpy(h->variant, c->variant, NGX_HTTP_CACHE_KEY_LEN);
[1287]     }
[1288] 
[1289]     if (ngx_http_file_cache_update_variant(r, c) != NGX_OK) {
[1290]         return NGX_ERROR;
[1291]     }
[1292] 
[1293]     p = buf + sizeof(ngx_http_file_cache_header_t);
[1294] 
[1295]     p = ngx_cpymem(p, ngx_http_file_cache_key, sizeof(ngx_http_file_cache_key));
[1296] 
[1297]     key = c->keys.elts;
[1298]     for (i = 0; i < c->keys.nelts; i++) {
[1299]         p = ngx_copy(p, key[i].data, key[i].len);
[1300]     }
[1301] 
[1302]     *p = LF;
[1303] 
[1304]     return NGX_OK;
[1305] }
[1306] 
[1307] 
[1308] static ngx_int_t
[1309] ngx_http_file_cache_update_variant(ngx_http_request_t *r, ngx_http_cache_t *c)
[1310] {
[1311]     ngx_http_file_cache_t  *cache;
[1312] 
[1313]     if (!c->secondary) {
[1314]         return NGX_OK;
[1315]     }
[1316] 
[1317]     if (c->vary.len
[1318]         && ngx_memcmp(c->variant, c->key, NGX_HTTP_CACHE_KEY_LEN) == 0)
[1319]     {
[1320]         return NGX_OK;
[1321]     }
[1322] 
[1323]     /*
[1324]      * if the variant hash doesn't match one we used as a secondary
[1325]      * cache key, switch back to the original key
[1326]      */
[1327] 
[1328]     cache = c->file_cache;
[1329] 
[1330]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1331]                    "http file cache main key");
[1332] 
[1333]     ngx_shmtx_lock(&cache->shpool->mutex);
[1334] 
[1335]     c->node->count--;
[1336]     c->node->updating = 0;
[1337]     c->node = NULL;
[1338] 
[1339]     ngx_shmtx_unlock(&cache->shpool->mutex);
[1340] 
[1341]     c->file.name.len = 0;
[1342]     c->update_variant = 1;
[1343] 
[1344]     ngx_memcpy(c->key, c->main, NGX_HTTP_CACHE_KEY_LEN);
[1345] 
[1346]     if (ngx_http_file_cache_exists(cache, c) == NGX_ERROR) {
[1347]         return NGX_ERROR;
[1348]     }
[1349] 
[1350]     if (ngx_http_file_cache_name(r, cache->path) != NGX_OK) {
[1351]         return NGX_ERROR;
[1352]     }
[1353] 
[1354]     return NGX_OK;
[1355] }
[1356] 
[1357] 
[1358] void
[1359] ngx_http_file_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf)
[1360] {
[1361]     off_t                   fs_size;
[1362]     ngx_int_t               rc;
[1363]     ngx_file_uniq_t         uniq;
[1364]     ngx_file_info_t         fi;
[1365]     ngx_http_cache_t        *c;
[1366]     ngx_ext_rename_file_t   ext;
[1367]     ngx_http_file_cache_t  *cache;
[1368] 
[1369]     c = r->cache;
[1370] 
[1371]     if (c->updated) {
[1372]         return;
[1373]     }
[1374] 
[1375]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1376]                    "http file cache update");
[1377] 
[1378]     cache = c->file_cache;
[1379] 
[1380]     c->updated = 1;
[1381]     c->updating = 0;
[1382] 
[1383]     uniq = 0;
[1384]     fs_size = 0;
[1385] 
[1386]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1387]                    "http file cache rename: \"%s\" to \"%s\"",
[1388]                    tf->file.name.data, c->file.name.data);
[1389] 
[1390]     ext.access = NGX_FILE_OWNER_ACCESS;
[1391]     ext.path_access = NGX_FILE_OWNER_ACCESS;
[1392]     ext.time = -1;
[1393]     ext.create_path = 1;
[1394]     ext.delete_file = 1;
[1395]     ext.log = r->connection->log;
[1396] 
[1397]     rc = ngx_ext_rename_file(&tf->file.name, &c->file.name, &ext);
[1398] 
[1399]     if (rc == NGX_OK) {
[1400] 
[1401]         if (ngx_fd_info(tf->file.fd, &fi) == NGX_FILE_ERROR) {
[1402]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[1403]                           ngx_fd_info_n " \"%s\" failed", tf->file.name.data);
[1404] 
[1405]             rc = NGX_ERROR;
[1406] 
[1407]         } else {
[1408]             uniq = ngx_file_uniq(&fi);
[1409]             fs_size = (ngx_file_fs_size(&fi) + cache->bsize - 1) / cache->bsize;
[1410]         }
[1411]     }
[1412] 
[1413]     ngx_shmtx_lock(&cache->shpool->mutex);
[1414] 
[1415]     c->node->count--;
[1416]     c->node->error = 0;
[1417]     c->node->uniq = uniq;
[1418]     c->node->body_start = c->body_start;
[1419] 
[1420]     cache->sh->size += fs_size - c->node->fs_size;
[1421]     c->node->fs_size = fs_size;
[1422] 
[1423]     if (rc == NGX_OK) {
[1424]         c->node->exists = 1;
[1425]     }
[1426] 
[1427]     c->node->updating = 0;
[1428] 
[1429]     ngx_shmtx_unlock(&cache->shpool->mutex);
[1430] }
[1431] 
[1432] 
[1433] void
[1434] ngx_http_file_cache_update_header(ngx_http_request_t *r)
[1435] {
[1436]     ssize_t                        n;
[1437]     ngx_err_t                      err;
[1438]     ngx_file_t                     file;
[1439]     ngx_file_info_t                fi;
[1440]     ngx_http_cache_t              *c;
[1441]     ngx_http_file_cache_header_t   h;
[1442] 
[1443]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1444]                    "http file cache update header");
[1445] 
[1446]     c = r->cache;
[1447] 
[1448]     ngx_memzero(&file, sizeof(ngx_file_t));
[1449] 
[1450]     file.name = c->file.name;
[1451]     file.log = r->connection->log;
[1452]     file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);
[1453] 
[1454]     if (file.fd == NGX_INVALID_FILE) {
[1455]         err = ngx_errno;
[1456] 
[1457]         /* cache file may have been deleted */
[1458] 
[1459]         if (err == NGX_ENOENT) {
[1460]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1461]                            "http file cache \"%s\" not found",
[1462]                            file.name.data);
[1463]             return;
[1464]         }
[1465] 
[1466]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
[1467]                       ngx_open_file_n " \"%s\" failed", file.name.data);
[1468]         return;
[1469]     }
[1470] 
[1471]     /*
[1472]      * make sure cache file wasn't replaced;
[1473]      * if it was, do nothing
[1474]      */
[1475] 
[1476]     if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
[1477]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[1478]                       ngx_fd_info_n " \"%s\" failed", file.name.data);
[1479]         goto done;
[1480]     }
[1481] 
[1482]     if (c->uniq != ngx_file_uniq(&fi)
[1483]         || c->length != ngx_file_size(&fi))
[1484]     {
[1485]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1486]                        "http file cache \"%s\" changed",
[1487]                        file.name.data);
[1488]         goto done;
[1489]     }
[1490] 
[1491]     n = ngx_read_file(&file, (u_char *) &h,
[1492]                       sizeof(ngx_http_file_cache_header_t), 0);
[1493] 
[1494]     if (n == NGX_ERROR) {
[1495]         goto done;
[1496]     }
[1497] 
[1498]     if ((size_t) n != sizeof(ngx_http_file_cache_header_t)) {
[1499]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[1500]                       ngx_read_file_n " read only %z of %z from \"%s\"",
[1501]                       n, sizeof(ngx_http_file_cache_header_t), file.name.data);
[1502]         goto done;
[1503]     }
[1504] 
[1505]     if (h.version != NGX_HTTP_CACHE_VERSION
[1506]         || h.last_modified != c->last_modified
[1507]         || h.crc32 != c->crc32
[1508]         || (size_t) h.header_start != c->header_start
[1509]         || (size_t) h.body_start != c->body_start)
[1510]     {
[1511]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1512]                        "http file cache \"%s\" content changed",
[1513]                        file.name.data);
[1514]         goto done;
[1515]     }
[1516] 
[1517]     /*
[1518]      * update cache file header with new data,
[1519]      * notably h.valid_sec and h.date
[1520]      */
[1521] 
[1522]     ngx_memzero(&h, sizeof(ngx_http_file_cache_header_t));
[1523] 
[1524]     h.version = NGX_HTTP_CACHE_VERSION;
[1525]     h.valid_sec = c->valid_sec;
[1526]     h.updating_sec = c->updating_sec;
[1527]     h.error_sec = c->error_sec;
[1528]     h.last_modified = c->last_modified;
[1529]     h.date = c->date;
[1530]     h.crc32 = c->crc32;
[1531]     h.valid_msec = (u_short) c->valid_msec;
[1532]     h.header_start = (u_short) c->header_start;
[1533]     h.body_start = (u_short) c->body_start;
[1534] 
[1535]     if (c->etag.len <= NGX_HTTP_CACHE_ETAG_LEN) {
[1536]         h.etag_len = (u_char) c->etag.len;
[1537]         ngx_memcpy(h.etag, c->etag.data, c->etag.len);
[1538]     }
[1539] 
[1540]     if (c->vary.len) {
[1541]         if (c->vary.len > NGX_HTTP_CACHE_VARY_LEN) {
[1542]             /* should not happen */
[1543]             c->vary.len = NGX_HTTP_CACHE_VARY_LEN;
[1544]         }
[1545] 
[1546]         h.vary_len = (u_char) c->vary.len;
[1547]         ngx_memcpy(h.vary, c->vary.data, c->vary.len);
[1548] 
[1549]         ngx_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
[1550]         ngx_memcpy(h.variant, c->variant, NGX_HTTP_CACHE_KEY_LEN);
[1551]     }
[1552] 
[1553]     (void) ngx_write_file(&file, (u_char *) &h,
[1554]                           sizeof(ngx_http_file_cache_header_t), 0);
[1555] 
[1556] done:
[1557] 
[1558]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[1559]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[1560]                       ngx_close_file_n " \"%s\" failed", file.name.data);
[1561]     }
[1562] }
[1563] 
[1564] 
[1565] ngx_int_t
[1566] ngx_http_cache_send(ngx_http_request_t *r)
[1567] {
[1568]     ngx_int_t          rc;
[1569]     ngx_buf_t         *b;
[1570]     ngx_chain_t        out;
[1571]     ngx_http_cache_t  *c;
[1572] 
[1573]     c = r->cache;
[1574] 
[1575]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1576]                    "http file cache send: %s", c->file.name.data);
[1577] 
[1578]     /* we need to allocate all before the header would be sent */
[1579] 
[1580]     b = ngx_calloc_buf(r->pool);
[1581]     if (b == NULL) {
[1582]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1583]     }
[1584] 
[1585]     b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
[1586]     if (b->file == NULL) {
[1587]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1588]     }
[1589] 
[1590]     rc = ngx_http_send_header(r);
[1591] 
[1592]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[1593]         return rc;
[1594]     }
[1595] 
[1596]     b->file_pos = c->body_start;
[1597]     b->file_last = c->length;
[1598] 
[1599]     b->in_file = (c->length - c->body_start) ? 1 : 0;
[1600]     b->last_buf = (r == r->main) ? 1 : 0;
[1601]     b->last_in_chain = 1;
[1602]     b->sync = (b->last_buf || b->in_file) ? 0 : 1;
[1603] 
[1604]     b->file->fd = c->file.fd;
[1605]     b->file->name = c->file.name;
[1606]     b->file->log = r->connection->log;
[1607] 
[1608]     out.buf = b;
[1609]     out.next = NULL;
[1610] 
[1611]     return ngx_http_output_filter(r, &out);
[1612] }
[1613] 
[1614] 
[1615] void
[1616] ngx_http_file_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf)
[1617] {
[1618]     ngx_http_file_cache_t       *cache;
[1619]     ngx_http_file_cache_node_t  *fcn;
[1620] 
[1621]     if (c->updated || c->node == NULL) {
[1622]         return;
[1623]     }
[1624] 
[1625]     cache = c->file_cache;
[1626] 
[1627]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
[1628]                    "http file cache free, fd: %d", c->file.fd);
[1629] 
[1630]     ngx_shmtx_lock(&cache->shpool->mutex);
[1631] 
[1632]     fcn = c->node;
[1633]     fcn->count--;
[1634] 
[1635]     if (c->updating && fcn->lock_time == c->lock_time) {
[1636]         fcn->updating = 0;
[1637]     }
[1638] 
[1639]     if (c->error) {
[1640]         fcn->error = c->error;
[1641] 
[1642]         if (c->valid_sec) {
[1643]             fcn->valid_sec = c->valid_sec;
[1644]             fcn->valid_msec = c->valid_msec;
[1645]         }
[1646] 
[1647]     } else if (!fcn->exists && fcn->count == 0 && c->min_uses == 1) {
[1648]         ngx_queue_remove(&fcn->queue);
[1649]         ngx_rbtree_delete(&cache->sh->rbtree, &fcn->node);
[1650]         ngx_slab_free_locked(cache->shpool, fcn);
[1651]         cache->sh->count--;
[1652]         c->node = NULL;
[1653]     }
[1654] 
[1655]     ngx_shmtx_unlock(&cache->shpool->mutex);
[1656] 
[1657]     c->updated = 1;
[1658]     c->updating = 0;
[1659] 
[1660]     if (c->temp_file) {
[1661]         if (tf && tf->file.fd != NGX_INVALID_FILE) {
[1662]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
[1663]                            "http file cache incomplete: \"%s\"",
[1664]                            tf->file.name.data);
[1665] 
[1666]             if (ngx_delete_file(tf->file.name.data) == NGX_FILE_ERROR) {
[1667]                 ngx_log_error(NGX_LOG_CRIT, c->file.log, ngx_errno,
[1668]                               ngx_delete_file_n " \"%s\" failed",
[1669]                               tf->file.name.data);
[1670]             }
[1671]         }
[1672]     }
[1673] 
[1674]     if (c->wait_event.timer_set) {
[1675]         ngx_del_timer(&c->wait_event);
[1676]     }
[1677] }
[1678] 
[1679] 
[1680] static void
[1681] ngx_http_file_cache_cleanup(void *data)
[1682] {
[1683]     ngx_http_cache_t  *c = data;
[1684] 
[1685]     if (c->updated) {
[1686]         return;
[1687]     }
[1688] 
[1689]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->file.log, 0,
[1690]                    "http file cache cleanup");
[1691] 
[1692]     if (c->updating && !c->background) {
[1693]         ngx_log_error(NGX_LOG_ALERT, c->file.log, 0,
[1694]                       "stalled cache updating, error:%ui", c->error);
[1695]     }
[1696] 
[1697]     ngx_http_file_cache_free(c, NULL);
[1698] }
[1699] 
[1700] 
[1701] static time_t
[1702] ngx_http_file_cache_forced_expire(ngx_http_file_cache_t *cache)
[1703] {
[1704]     u_char                      *name, *p;
[1705]     size_t                       len;
[1706]     time_t                       wait;
[1707]     ngx_uint_t                   tries;
[1708]     ngx_path_t                  *path;
[1709]     ngx_queue_t                 *q, *sentinel;
[1710]     ngx_http_file_cache_node_t  *fcn;
[1711]     u_char                       key[2 * NGX_HTTP_CACHE_KEY_LEN];
[1712] 
[1713]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[1714]                    "http file cache forced expire");
[1715] 
[1716]     path = cache->path;
[1717]     len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
[1718] 
[1719]     name = ngx_alloc(len + 1, ngx_cycle->log);
[1720]     if (name == NULL) {
[1721]         return 10;
[1722]     }
[1723] 
[1724]     ngx_memcpy(name, path->name.data, path->name.len);
[1725] 
[1726]     wait = 10;
[1727]     tries = 20;
[1728]     sentinel = NULL;
[1729] 
[1730]     ngx_shmtx_lock(&cache->shpool->mutex);
[1731] 
[1732]     for ( ;; ) {
[1733]         if (ngx_queue_empty(&cache->sh->queue)) {
[1734]             break;
[1735]         }
[1736] 
[1737]         q = ngx_queue_last(&cache->sh->queue);
[1738] 
[1739]         if (q == sentinel) {
[1740]             break;
[1741]         }
[1742] 
[1743]         fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);
[1744] 
[1745]         ngx_log_debug6(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[1746]                   "http file cache forced expire: #%d %d %02xd%02xd%02xd%02xd",
[1747]                   fcn->count, fcn->exists,
[1748]                   fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);
[1749] 
[1750]         if (fcn->count == 0) {
[1751]             ngx_http_file_cache_delete(cache, q, name);
[1752]             wait = 0;
[1753]             break;
[1754]         }
[1755] 
[1756]         if (fcn->deleting) {
[1757]             wait = 1;
[1758]             break;
[1759]         }
[1760] 
[1761]         p = ngx_hex_dump(key, (u_char *) &fcn->node.key,
[1762]                          sizeof(ngx_rbtree_key_t));
[1763]         len = NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t);
[1764]         (void) ngx_hex_dump(p, fcn->key, len);
[1765] 
[1766]         /*
[1767]          * abnormally exited workers may leave locked cache entries,
[1768]          * and although it may be safe to remove them completely,
[1769]          * we prefer to just move them to the top of the inactive queue
[1770]          */
[1771] 
[1772]         ngx_queue_remove(q);
[1773]         fcn->expire = ngx_time() + cache->inactive;
[1774]         ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);
[1775] 
[1776]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[1777]                       "ignore long locked inactive cache entry %*s, count:%d",
[1778]                       (size_t) 2 * NGX_HTTP_CACHE_KEY_LEN, key, fcn->count);
[1779] 
[1780]         if (sentinel == NULL) {
[1781]             sentinel = q;
[1782]         }
[1783] 
[1784]         if (--tries) {
[1785]             continue;
[1786]         }
[1787] 
[1788]         wait = 1;
[1789]         break;
[1790]     }
[1791] 
[1792]     ngx_shmtx_unlock(&cache->shpool->mutex);
[1793] 
[1794]     ngx_free(name);
[1795] 
[1796]     return wait;
[1797] }
[1798] 
[1799] 
[1800] static time_t
[1801] ngx_http_file_cache_expire(ngx_http_file_cache_t *cache)
[1802] {
[1803]     u_char                      *name, *p;
[1804]     size_t                       len;
[1805]     time_t                       now, wait;
[1806]     ngx_path_t                  *path;
[1807]     ngx_msec_t                   elapsed;
[1808]     ngx_queue_t                 *q;
[1809]     ngx_http_file_cache_node_t  *fcn;
[1810]     u_char                       key[2 * NGX_HTTP_CACHE_KEY_LEN];
[1811] 
[1812]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[1813]                    "http file cache expire");
[1814] 
[1815]     path = cache->path;
[1816]     len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
[1817] 
[1818]     name = ngx_alloc(len + 1, ngx_cycle->log);
[1819]     if (name == NULL) {
[1820]         return 10;
[1821]     }
[1822] 
[1823]     ngx_memcpy(name, path->name.data, path->name.len);
[1824] 
[1825]     now = ngx_time();
[1826] 
[1827]     ngx_shmtx_lock(&cache->shpool->mutex);
[1828] 
[1829]     for ( ;; ) {
[1830] 
[1831]         if (ngx_quit || ngx_terminate) {
[1832]             wait = 1;
[1833]             break;
[1834]         }
[1835] 
[1836]         if (ngx_queue_empty(&cache->sh->queue)) {
[1837]             wait = 10;
[1838]             break;
[1839]         }
[1840] 
[1841]         q = ngx_queue_last(&cache->sh->queue);
[1842] 
[1843]         fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);
[1844] 
[1845]         wait = fcn->expire - now;
[1846] 
[1847]         if (wait > 0) {
[1848]             wait = wait > 10 ? 10 : wait;
[1849]             break;
[1850]         }
[1851] 
[1852]         ngx_log_debug6(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[1853]                        "http file cache expire: #%d %d %02xd%02xd%02xd%02xd",
[1854]                        fcn->count, fcn->exists,
[1855]                        fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);
[1856] 
[1857]         if (fcn->count == 0) {
[1858]             ngx_http_file_cache_delete(cache, q, name);
[1859]             goto next;
[1860]         }
[1861] 
[1862]         if (fcn->deleting) {
[1863]             wait = 1;
[1864]             break;
[1865]         }
[1866] 
[1867]         p = ngx_hex_dump(key, (u_char *) &fcn->node.key,
[1868]                          sizeof(ngx_rbtree_key_t));
[1869]         len = NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t);
[1870]         (void) ngx_hex_dump(p, fcn->key, len);
[1871] 
[1872]         /*
[1873]          * abnormally exited workers may leave locked cache entries,
[1874]          * and although it may be safe to remove them completely,
[1875]          * we prefer to just move them to the top of the inactive queue
[1876]          */
[1877] 
[1878]         ngx_queue_remove(q);
[1879]         fcn->expire = ngx_time() + cache->inactive;
[1880]         ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);
[1881] 
[1882]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[1883]                       "ignore long locked inactive cache entry %*s, count:%d",
[1884]                       (size_t) 2 * NGX_HTTP_CACHE_KEY_LEN, key, fcn->count);
[1885] 
[1886] next:
[1887] 
[1888]         if (++cache->files >= cache->manager_files) {
[1889]             wait = 0;
[1890]             break;
[1891]         }
[1892] 
[1893]         ngx_time_update();
[1894] 
[1895]         elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));
[1896] 
[1897]         if (elapsed >= cache->manager_threshold) {
[1898]             wait = 0;
[1899]             break;
[1900]         }
[1901]     }
[1902] 
[1903]     ngx_shmtx_unlock(&cache->shpool->mutex);
[1904] 
[1905]     ngx_free(name);
[1906] 
[1907]     return wait;
[1908] }
[1909] 
[1910] 
[1911] static void
[1912] ngx_http_file_cache_delete(ngx_http_file_cache_t *cache, ngx_queue_t *q,
[1913]     u_char *name)
[1914] {
[1915]     u_char                      *p;
[1916]     size_t                       len;
[1917]     ngx_path_t                  *path;
[1918]     ngx_http_file_cache_node_t  *fcn;
[1919] 
[1920]     fcn = ngx_queue_data(q, ngx_http_file_cache_node_t, queue);
[1921] 
[1922]     if (fcn->exists) {
[1923]         cache->sh->size -= fcn->fs_size;
[1924] 
[1925]         path = cache->path;
[1926]         p = name + path->name.len + 1 + path->len;
[1927]         p = ngx_hex_dump(p, (u_char *) &fcn->node.key,
[1928]                          sizeof(ngx_rbtree_key_t));
[1929]         len = NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t);
[1930]         p = ngx_hex_dump(p, fcn->key, len);
[1931]         *p = '\0';
[1932] 
[1933]         fcn->count++;
[1934]         fcn->deleting = 1;
[1935]         ngx_shmtx_unlock(&cache->shpool->mutex);
[1936] 
[1937]         len = path->name.len + 1 + path->len + 2 * NGX_HTTP_CACHE_KEY_LEN;
[1938]         ngx_create_hashed_filename(path, name, len);
[1939] 
[1940]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[1941]                        "http file cache expire: \"%s\"", name);
[1942] 
[1943]         if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[1944]             ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, ngx_errno,
[1945]                           ngx_delete_file_n " \"%s\" failed", name);
[1946]         }
[1947] 
[1948]         ngx_shmtx_lock(&cache->shpool->mutex);
[1949]         fcn->count--;
[1950]         fcn->deleting = 0;
[1951]     }
[1952] 
[1953]     if (fcn->count == 0) {
[1954]         ngx_queue_remove(q);
[1955]         ngx_rbtree_delete(&cache->sh->rbtree, &fcn->node);
[1956]         ngx_slab_free_locked(cache->shpool, fcn);
[1957]         cache->sh->count--;
[1958]     }
[1959] }
[1960] 
[1961] 
[1962] static ngx_msec_t
[1963] ngx_http_file_cache_manager(void *data)
[1964] {
[1965]     ngx_http_file_cache_t  *cache = data;
[1966] 
[1967]     off_t       size, free;
[1968]     time_t      wait;
[1969]     ngx_msec_t  elapsed, next;
[1970]     ngx_uint_t  count, watermark;
[1971] 
[1972]     cache->last = ngx_current_msec;
[1973]     cache->files = 0;
[1974] 
[1975]     next = (ngx_msec_t) ngx_http_file_cache_expire(cache) * 1000;
[1976] 
[1977]     if (next == 0) {
[1978]         next = cache->manager_sleep;
[1979]         goto done;
[1980]     }
[1981] 
[1982]     for ( ;; ) {
[1983]         ngx_shmtx_lock(&cache->shpool->mutex);
[1984] 
[1985]         size = cache->sh->size;
[1986]         count = cache->sh->count;
[1987]         watermark = cache->sh->watermark;
[1988] 
[1989]         ngx_shmtx_unlock(&cache->shpool->mutex);
[1990] 
[1991]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[1992]                        "http file cache size: %O c:%ui w:%i",
[1993]                        size, count, (ngx_int_t) watermark);
[1994] 
[1995]         if (size < cache->max_size && count < watermark) {
[1996] 
[1997]             if (!cache->min_free) {
[1998]                 break;
[1999]             }
[2000] 
[2001]             free = ngx_fs_available(cache->path->name.data);
[2002] 
[2003]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[2004]                            "http file cache free: %O", free);
[2005] 
[2006]             if (free > cache->min_free) {
[2007]                 break;
[2008]             }
[2009]         }
[2010] 
[2011]         wait = ngx_http_file_cache_forced_expire(cache);
[2012] 
[2013]         if (wait > 0) {
[2014]             next = (ngx_msec_t) wait * 1000;
[2015]             break;
[2016]         }
[2017] 
[2018]         if (ngx_quit || ngx_terminate) {
[2019]             break;
[2020]         }
[2021] 
[2022]         if (++cache->files >= cache->manager_files) {
[2023]             next = cache->manager_sleep;
[2024]             break;
[2025]         }
[2026] 
[2027]         ngx_time_update();
[2028] 
[2029]         elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));
[2030] 
[2031]         if (elapsed >= cache->manager_threshold) {
[2032]             next = cache->manager_sleep;
[2033]             break;
[2034]         }
[2035]     }
[2036] 
[2037] done:
[2038] 
[2039]     elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));
[2040] 
[2041]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[2042]                    "http file cache manager: %ui e:%M n:%M",
[2043]                    cache->files, elapsed, next);
[2044] 
[2045]     return next;
[2046] }
[2047] 
[2048] 
[2049] static void
[2050] ngx_http_file_cache_loader(void *data)
[2051] {
[2052]     ngx_http_file_cache_t  *cache = data;
[2053] 
[2054]     ngx_tree_ctx_t  tree;
[2055] 
[2056]     if (!cache->sh->cold || cache->sh->loading) {
[2057]         return;
[2058]     }
[2059] 
[2060]     if (!ngx_atomic_cmp_set(&cache->sh->loading, 0, ngx_pid)) {
[2061]         return;
[2062]     }
[2063] 
[2064]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[2065]                    "http file cache loader");
[2066] 
[2067]     tree.init_handler = NULL;
[2068]     tree.file_handler = ngx_http_file_cache_manage_file;
[2069]     tree.pre_tree_handler = ngx_http_file_cache_manage_directory;
[2070]     tree.post_tree_handler = ngx_http_file_cache_noop;
[2071]     tree.spec_handler = ngx_http_file_cache_delete_file;
[2072]     tree.data = cache;
[2073]     tree.alloc = 0;
[2074]     tree.log = ngx_cycle->log;
[2075] 
[2076]     cache->last = ngx_current_msec;
[2077]     cache->files = 0;
[2078] 
[2079]     if (ngx_walk_tree(&tree, &cache->path->name) == NGX_ABORT) {
[2080]         cache->sh->loading = 0;
[2081]         return;
[2082]     }
[2083] 
[2084]     cache->sh->cold = 0;
[2085]     cache->sh->loading = 0;
[2086] 
[2087]     ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
[2088]                   "http file cache: %V %.3fM, bsize: %uz",
[2089]                   &cache->path->name,
[2090]                   ((double) cache->sh->size * cache->bsize) / (1024 * 1024),
[2091]                   cache->bsize);
[2092] }
[2093] 
[2094] 
[2095] static ngx_int_t
[2096] ngx_http_file_cache_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[2097] {
[2098]     return NGX_OK;
[2099] }
[2100] 
[2101] 
[2102] static ngx_int_t
[2103] ngx_http_file_cache_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[2104] {
[2105]     ngx_msec_t              elapsed;
[2106]     ngx_http_file_cache_t  *cache;
[2107] 
[2108]     cache = ctx->data;
[2109] 
[2110]     if (ngx_http_file_cache_add_file(ctx, path) != NGX_OK) {
[2111]         (void) ngx_http_file_cache_delete_file(ctx, path);
[2112]     }
[2113] 
[2114]     if (++cache->files >= cache->loader_files) {
[2115]         ngx_http_file_cache_loader_sleep(cache);
[2116] 
[2117]     } else {
[2118]         ngx_time_update();
[2119] 
[2120]         elapsed = ngx_abs((ngx_msec_int_t) (ngx_current_msec - cache->last));
[2121] 
[2122]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[2123]                        "http file cache loader time elapsed: %M", elapsed);
[2124] 
[2125]         if (elapsed >= cache->loader_threshold) {
[2126]             ngx_http_file_cache_loader_sleep(cache);
[2127]         }
[2128]     }
[2129] 
[2130]     return (ngx_quit || ngx_terminate) ? NGX_ABORT : NGX_OK;
[2131] }
[2132] 
[2133] 
[2134] static ngx_int_t
[2135] ngx_http_file_cache_manage_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[2136] {
[2137]     if (path->len >= 5
[2138]         && ngx_strncmp(path->data + path->len - 5, "/temp", 5) == 0)
[2139]     {
[2140]         return NGX_DECLINED;
[2141]     }
[2142] 
[2143]     return NGX_OK;
[2144] }
[2145] 
[2146] 
[2147] static void
[2148] ngx_http_file_cache_loader_sleep(ngx_http_file_cache_t *cache)
[2149] {
[2150]     ngx_msleep(cache->loader_sleep);
[2151] 
[2152]     ngx_time_update();
[2153] 
[2154]     cache->last = ngx_current_msec;
[2155]     cache->files = 0;
[2156] }
[2157] 
[2158] 
[2159] static ngx_int_t
[2160] ngx_http_file_cache_add_file(ngx_tree_ctx_t *ctx, ngx_str_t *name)
[2161] {
[2162]     u_char                 *p;
[2163]     ngx_int_t               n;
[2164]     ngx_uint_t              i;
[2165]     ngx_http_cache_t        c;
[2166]     ngx_http_file_cache_t  *cache;
[2167] 
[2168]     if (name->len < 2 * NGX_HTTP_CACHE_KEY_LEN) {
[2169]         return NGX_ERROR;
[2170]     }
[2171] 
[2172]     /*
[2173]      * Temporary files in cache have a suffix consisting of a dot
[2174]      * followed by 10 digits.
[2175]      */
[2176] 
[2177]     if (name->len >= 2 * NGX_HTTP_CACHE_KEY_LEN + 1 + 10
[2178]         && name->data[name->len - 10 - 1] == '.')
[2179]     {
[2180]         return NGX_OK;
[2181]     }
[2182] 
[2183]     if (ctx->size < (off_t) sizeof(ngx_http_file_cache_header_t)) {
[2184]         ngx_log_error(NGX_LOG_CRIT, ctx->log, 0,
[2185]                       "cache file \"%s\" is too small", name->data);
[2186]         return NGX_ERROR;
[2187]     }
[2188] 
[2189]     ngx_memzero(&c, sizeof(ngx_http_cache_t));
[2190]     cache = ctx->data;
[2191] 
[2192]     c.length = ctx->size;
[2193]     c.fs_size = (ctx->fs_size + cache->bsize - 1) / cache->bsize;
[2194] 
[2195]     p = &name->data[name->len - 2 * NGX_HTTP_CACHE_KEY_LEN];
[2196] 
[2197]     for (i = 0; i < NGX_HTTP_CACHE_KEY_LEN; i++) {
[2198]         n = ngx_hextoi(p, 2);
[2199] 
[2200]         if (n == NGX_ERROR) {
[2201]             return NGX_ERROR;
[2202]         }
[2203] 
[2204]         p += 2;
[2205] 
[2206]         c.key[i] = (u_char) n;
[2207]     }
[2208] 
[2209]     return ngx_http_file_cache_add(cache, &c);
[2210] }
[2211] 
[2212] 
[2213] static ngx_int_t
[2214] ngx_http_file_cache_add(ngx_http_file_cache_t *cache, ngx_http_cache_t *c)
[2215] {
[2216]     ngx_http_file_cache_node_t  *fcn;
[2217] 
[2218]     ngx_shmtx_lock(&cache->shpool->mutex);
[2219] 
[2220]     fcn = ngx_http_file_cache_lookup(cache, c->key);
[2221] 
[2222]     if (fcn == NULL) {
[2223] 
[2224]         fcn = ngx_slab_calloc_locked(cache->shpool,
[2225]                                      sizeof(ngx_http_file_cache_node_t));
[2226]         if (fcn == NULL) {
[2227]             ngx_http_file_cache_set_watermark(cache);
[2228] 
[2229]             if (cache->fail_time != ngx_time()) {
[2230]                 cache->fail_time = ngx_time();
[2231]                 ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[2232]                            "could not allocate node%s", cache->shpool->log_ctx);
[2233]             }
[2234] 
[2235]             ngx_shmtx_unlock(&cache->shpool->mutex);
[2236]             return NGX_ERROR;
[2237]         }
[2238] 
[2239]         cache->sh->count++;
[2240] 
[2241]         ngx_memcpy((u_char *) &fcn->node.key, c->key, sizeof(ngx_rbtree_key_t));
[2242] 
[2243]         ngx_memcpy(fcn->key, &c->key[sizeof(ngx_rbtree_key_t)],
[2244]                    NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));
[2245] 
[2246]         ngx_rbtree_insert(&cache->sh->rbtree, &fcn->node);
[2247] 
[2248]         fcn->uses = 1;
[2249]         fcn->exists = 1;
[2250]         fcn->fs_size = c->fs_size;
[2251] 
[2252]         cache->sh->size += c->fs_size;
[2253] 
[2254]     } else {
[2255]         ngx_queue_remove(&fcn->queue);
[2256]     }
[2257] 
[2258]     fcn->expire = ngx_time() + cache->inactive;
[2259] 
[2260]     ngx_queue_insert_head(&cache->sh->queue, &fcn->queue);
[2261] 
[2262]     ngx_shmtx_unlock(&cache->shpool->mutex);
[2263] 
[2264]     return NGX_OK;
[2265] }
[2266] 
[2267] 
[2268] static ngx_int_t
[2269] ngx_http_file_cache_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[2270] {
[2271]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[2272]                    "http file cache delete: \"%s\"", path->data);
[2273] 
[2274]     if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
[2275]         ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
[2276]                       ngx_delete_file_n " \"%s\" failed", path->data);
[2277]     }
[2278] 
[2279]     return NGX_OK;
[2280] }
[2281] 
[2282] 
[2283] static void
[2284] ngx_http_file_cache_set_watermark(ngx_http_file_cache_t *cache)
[2285] {
[2286]     cache->sh->watermark = cache->sh->count - cache->sh->count / 8;
[2287] 
[2288]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
[2289]                    "http file cache watermark: %ui", cache->sh->watermark);
[2290] }
[2291] 
[2292] 
[2293] time_t
[2294] ngx_http_file_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status)
[2295] {
[2296]     ngx_uint_t               i;
[2297]     ngx_http_cache_valid_t  *valid;
[2298] 
[2299]     if (cache_valid == NULL) {
[2300]         return 0;
[2301]     }
[2302] 
[2303]     valid = cache_valid->elts;
[2304]     for (i = 0; i < cache_valid->nelts; i++) {
[2305] 
[2306]         if (valid[i].status == 0) {
[2307]             return valid[i].valid;
[2308]         }
[2309] 
[2310]         if (valid[i].status == status) {
[2311]             return valid[i].valid;
[2312]         }
[2313]     }
[2314] 
[2315]     return 0;
[2316] }
[2317] 
[2318] 
[2319] char *
[2320] ngx_http_file_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2321] {
[2322]     char  *confp = conf;
[2323] 
[2324]     off_t                   max_size, min_free;
[2325]     u_char                 *last, *p;
[2326]     time_t                  inactive;
[2327]     ssize_t                 size;
[2328]     ngx_str_t               s, name, *value;
[2329]     ngx_int_t               loader_files, manager_files;
[2330]     ngx_msec_t              loader_sleep, manager_sleep, loader_threshold,
[2331]                             manager_threshold;
[2332]     ngx_uint_t              i, n, use_temp_path;
[2333]     ngx_array_t            *caches;
[2334]     ngx_http_file_cache_t  *cache, **ce;
[2335] 
[2336]     cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_file_cache_t));
[2337]     if (cache == NULL) {
[2338]         return NGX_CONF_ERROR;
[2339]     }
[2340] 
[2341]     cache->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
[2342]     if (cache->path == NULL) {
[2343]         return NGX_CONF_ERROR;
[2344]     }
[2345] 
[2346]     use_temp_path = 1;
[2347] 
[2348]     inactive = 600;
[2349] 
[2350]     loader_files = 100;
[2351]     loader_sleep = 50;
[2352]     loader_threshold = 200;
[2353] 
[2354]     manager_files = 100;
[2355]     manager_sleep = 50;
[2356]     manager_threshold = 200;
[2357] 
[2358]     name.len = 0;
[2359]     size = 0;
[2360]     max_size = NGX_MAX_OFF_T_VALUE;
[2361]     min_free = 0;
[2362] 
[2363]     value = cf->args->elts;
[2364] 
[2365]     cache->path->name = value[1];
[2366] 
[2367]     if (cache->path->name.data[cache->path->name.len - 1] == '/') {
[2368]         cache->path->name.len--;
[2369]     }
[2370] 
[2371]     if (ngx_conf_full_name(cf->cycle, &cache->path->name, 0) != NGX_OK) {
[2372]         return NGX_CONF_ERROR;
[2373]     }
[2374] 
[2375]     for (i = 2; i < cf->args->nelts; i++) {
[2376] 
[2377]         if (ngx_strncmp(value[i].data, "levels=", 7) == 0) {
[2378] 
[2379]             p = value[i].data + 7;
[2380]             last = value[i].data + value[i].len;
[2381] 
[2382]             for (n = 0; n < NGX_MAX_PATH_LEVEL && p < last; n++) {
[2383] 
[2384]                 if (*p > '0' && *p < '3') {
[2385] 
[2386]                     cache->path->level[n] = *p++ - '0';
[2387]                     cache->path->len += cache->path->level[n] + 1;
[2388] 
[2389]                     if (p == last) {
[2390]                         break;
[2391]                     }
[2392] 
[2393]                     if (*p++ == ':' && n < NGX_MAX_PATH_LEVEL - 1 && p < last) {
[2394]                         continue;
[2395]                     }
[2396] 
[2397]                     goto invalid_levels;
[2398]                 }
[2399] 
[2400]                 goto invalid_levels;
[2401]             }
[2402] 
[2403]             if (cache->path->len < 10 + NGX_MAX_PATH_LEVEL) {
[2404]                 continue;
[2405]             }
[2406] 
[2407]         invalid_levels:
[2408] 
[2409]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2410]                                "invalid \"levels\" \"%V\"", &value[i]);
[2411]             return NGX_CONF_ERROR;
[2412]         }
[2413] 
[2414]         if (ngx_strncmp(value[i].data, "use_temp_path=", 14) == 0) {
[2415] 
[2416]             if (ngx_strcmp(&value[i].data[14], "on") == 0) {
[2417]                 use_temp_path = 1;
[2418] 
[2419]             } else if (ngx_strcmp(&value[i].data[14], "off") == 0) {
[2420]                 use_temp_path = 0;
[2421] 
[2422]             } else {
[2423]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2424]                                    "invalid use_temp_path value \"%V\", "
[2425]                                    "it must be \"on\" or \"off\"",
[2426]                                    &value[i]);
[2427]                 return NGX_CONF_ERROR;
[2428]             }
[2429] 
[2430]             continue;
[2431]         }
[2432] 
[2433]         if (ngx_strncmp(value[i].data, "keys_zone=", 10) == 0) {
[2434] 
[2435]             name.data = value[i].data + 10;
[2436] 
[2437]             p = (u_char *) ngx_strchr(name.data, ':');
[2438] 
[2439]             if (p == NULL) {
[2440]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2441]                                    "invalid keys zone size \"%V\"", &value[i]);
[2442]                 return NGX_CONF_ERROR;
[2443]             }
[2444] 
[2445]             name.len = p - name.data;
[2446] 
[2447]             s.data = p + 1;
[2448]             s.len = value[i].data + value[i].len - s.data;
[2449] 
[2450]             size = ngx_parse_size(&s);
[2451] 
[2452]             if (size == NGX_ERROR) {
[2453]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2454]                                    "invalid keys zone size \"%V\"", &value[i]);
[2455]                 return NGX_CONF_ERROR;
[2456]             }
[2457] 
[2458]             if (size < (ssize_t) (2 * ngx_pagesize)) {
[2459]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2460]                                    "keys zone \"%V\" is too small", &value[i]);
[2461]                 return NGX_CONF_ERROR;
[2462]             }
[2463] 
[2464]             continue;
[2465]         }
[2466] 
[2467]         if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
[2468] 
[2469]             s.len = value[i].len - 9;
[2470]             s.data = value[i].data + 9;
[2471] 
[2472]             inactive = ngx_parse_time(&s, 1);
[2473]             if (inactive == (time_t) NGX_ERROR) {
[2474]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2475]                                    "invalid inactive value \"%V\"", &value[i]);
[2476]                 return NGX_CONF_ERROR;
[2477]             }
[2478] 
[2479]             continue;
[2480]         }
[2481] 
[2482]         if (ngx_strncmp(value[i].data, "max_size=", 9) == 0) {
[2483] 
[2484]             s.len = value[i].len - 9;
[2485]             s.data = value[i].data + 9;
[2486] 
[2487]             max_size = ngx_parse_offset(&s);
[2488]             if (max_size < 0) {
[2489]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2490]                                    "invalid max_size value \"%V\"", &value[i]);
[2491]                 return NGX_CONF_ERROR;
[2492]             }
[2493] 
[2494]             continue;
[2495]         }
[2496] 
[2497]         if (ngx_strncmp(value[i].data, "min_free=", 9) == 0) {
[2498] 
[2499] #if (NGX_WIN32 || NGX_HAVE_STATFS || NGX_HAVE_STATVFS)
[2500] 
[2501]             s.len = value[i].len - 9;
[2502]             s.data = value[i].data + 9;
[2503] 
[2504]             min_free = ngx_parse_offset(&s);
[2505]             if (min_free < 0) {
[2506]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2507]                                    "invalid min_free value \"%V\"", &value[i]);
[2508]                 return NGX_CONF_ERROR;
[2509]             }
[2510] 
[2511] #else
[2512]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[2513]                                "min_free is not supported "
[2514]                                "on this platform, ignored");
[2515] #endif
[2516] 
[2517]             continue;
[2518]         }
[2519] 
[2520]         if (ngx_strncmp(value[i].data, "loader_files=", 13) == 0) {
[2521] 
[2522]             loader_files = ngx_atoi(value[i].data + 13, value[i].len - 13);
[2523]             if (loader_files == NGX_ERROR) {
[2524]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2525]                            "invalid loader_files value \"%V\"", &value[i]);
[2526]                 return NGX_CONF_ERROR;
[2527]             }
[2528] 
[2529]             continue;
[2530]         }
[2531] 
[2532]         if (ngx_strncmp(value[i].data, "loader_sleep=", 13) == 0) {
[2533] 
[2534]             s.len = value[i].len - 13;
[2535]             s.data = value[i].data + 13;
[2536] 
[2537]             loader_sleep = ngx_parse_time(&s, 0);
[2538]             if (loader_sleep == (ngx_msec_t) NGX_ERROR) {
[2539]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2540]                            "invalid loader_sleep value \"%V\"", &value[i]);
[2541]                 return NGX_CONF_ERROR;
[2542]             }
[2543] 
[2544]             continue;
[2545]         }
[2546] 
[2547]         if (ngx_strncmp(value[i].data, "loader_threshold=", 17) == 0) {
[2548] 
[2549]             s.len = value[i].len - 17;
[2550]             s.data = value[i].data + 17;
[2551] 
[2552]             loader_threshold = ngx_parse_time(&s, 0);
[2553]             if (loader_threshold == (ngx_msec_t) NGX_ERROR) {
[2554]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2555]                            "invalid loader_threshold value \"%V\"", &value[i]);
[2556]                 return NGX_CONF_ERROR;
[2557]             }
[2558] 
[2559]             continue;
[2560]         }
[2561] 
[2562]         if (ngx_strncmp(value[i].data, "manager_files=", 14) == 0) {
[2563] 
[2564]             manager_files = ngx_atoi(value[i].data + 14, value[i].len - 14);
[2565]             if (manager_files == NGX_ERROR) {
[2566]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2567]                            "invalid manager_files value \"%V\"", &value[i]);
[2568]                 return NGX_CONF_ERROR;
[2569]             }
[2570] 
[2571]             continue;
[2572]         }
[2573] 
[2574]         if (ngx_strncmp(value[i].data, "manager_sleep=", 14) == 0) {
[2575] 
[2576]             s.len = value[i].len - 14;
[2577]             s.data = value[i].data + 14;
[2578] 
[2579]             manager_sleep = ngx_parse_time(&s, 0);
[2580]             if (manager_sleep == (ngx_msec_t) NGX_ERROR) {
[2581]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2582]                            "invalid manager_sleep value \"%V\"", &value[i]);
[2583]                 return NGX_CONF_ERROR;
[2584]             }
[2585] 
[2586]             continue;
[2587]         }
[2588] 
[2589]         if (ngx_strncmp(value[i].data, "manager_threshold=", 18) == 0) {
[2590] 
[2591]             s.len = value[i].len - 18;
[2592]             s.data = value[i].data + 18;
[2593] 
[2594]             manager_threshold = ngx_parse_time(&s, 0);
[2595]             if (manager_threshold == (ngx_msec_t) NGX_ERROR) {
[2596]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2597]                            "invalid manager_threshold value \"%V\"", &value[i]);
[2598]                 return NGX_CONF_ERROR;
[2599]             }
[2600] 
[2601]             continue;
[2602]         }
[2603] 
[2604]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2605]                            "invalid parameter \"%V\"", &value[i]);
[2606]         return NGX_CONF_ERROR;
[2607]     }
[2608] 
[2609]     if (name.len == 0 || size == 0) {
[2610]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2611]                            "\"%V\" must have \"keys_zone\" parameter",
[2612]                            &cmd->name);
[2613]         return NGX_CONF_ERROR;
[2614]     }
[2615] 
[2616]     cache->path->manager = ngx_http_file_cache_manager;
[2617]     cache->path->loader = ngx_http_file_cache_loader;
[2618]     cache->path->data = cache;
[2619]     cache->path->conf_file = cf->conf_file->file.name.data;
[2620]     cache->path->line = cf->conf_file->line;
[2621]     cache->loader_files = loader_files;
[2622]     cache->loader_sleep = loader_sleep;
[2623]     cache->loader_threshold = loader_threshold;
[2624]     cache->manager_files = manager_files;
[2625]     cache->manager_sleep = manager_sleep;
[2626]     cache->manager_threshold = manager_threshold;
[2627] 
[2628]     if (ngx_add_path(cf, &cache->path) != NGX_OK) {
[2629]         return NGX_CONF_ERROR;
[2630]     }
[2631] 
[2632]     cache->shm_zone = ngx_shared_memory_add(cf, &name, size, cmd->post);
[2633]     if (cache->shm_zone == NULL) {
[2634]         return NGX_CONF_ERROR;
[2635]     }
[2636] 
[2637]     if (cache->shm_zone->data) {
[2638]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2639]                            "duplicate zone \"%V\"", &name);
[2640]         return NGX_CONF_ERROR;
[2641]     }
[2642] 
[2643] 
[2644]     cache->shm_zone->init = ngx_http_file_cache_init;
[2645]     cache->shm_zone->data = cache;
[2646] 
[2647]     cache->use_temp_path = use_temp_path;
[2648] 
[2649]     cache->inactive = inactive;
[2650]     cache->max_size = max_size;
[2651]     cache->min_free = min_free;
[2652] 
[2653]     caches = (ngx_array_t *) (confp + cmd->offset);
[2654] 
[2655]     ce = ngx_array_push(caches);
[2656]     if (ce == NULL) {
[2657]         return NGX_CONF_ERROR;
[2658]     }
[2659] 
[2660]     *ce = cache;
[2661] 
[2662]     return NGX_CONF_OK;
[2663] }
[2664] 
[2665] 
[2666] char *
[2667] ngx_http_file_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[2668]     void *conf)
[2669] {
[2670]     char  *p = conf;
[2671] 
[2672]     time_t                    valid;
[2673]     ngx_str_t                *value;
[2674]     ngx_int_t                 status;
[2675]     ngx_uint_t                i, n;
[2676]     ngx_array_t             **a;
[2677]     ngx_http_cache_valid_t   *v;
[2678]     static ngx_uint_t         statuses[] = { 200, 301, 302 };
[2679] 
[2680]     a = (ngx_array_t **) (p + cmd->offset);
[2681] 
[2682]     if (*a == NGX_CONF_UNSET_PTR) {
[2683]         *a = ngx_array_create(cf->pool, 1, sizeof(ngx_http_cache_valid_t));
[2684]         if (*a == NULL) {
[2685]             return NGX_CONF_ERROR;
[2686]         }
[2687]     }
[2688] 
[2689]     value = cf->args->elts;
[2690]     n = cf->args->nelts - 1;
[2691] 
[2692]     valid = ngx_parse_time(&value[n], 1);
[2693]     if (valid == (time_t) NGX_ERROR) {
[2694]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2695]                            "invalid time value \"%V\"", &value[n]);
[2696]         return NGX_CONF_ERROR;
[2697]     }
[2698] 
[2699]     if (n == 1) {
[2700] 
[2701]         for (i = 0; i < 3; i++) {
[2702]             v = ngx_array_push(*a);
[2703]             if (v == NULL) {
[2704]                 return NGX_CONF_ERROR;
[2705]             }
[2706] 
[2707]             v->status = statuses[i];
[2708]             v->valid = valid;
[2709]         }
[2710] 
[2711]         return NGX_CONF_OK;
[2712]     }
[2713] 
[2714]     for (i = 1; i < n; i++) {
[2715] 
[2716]         if (ngx_strcmp(value[i].data, "any") == 0) {
[2717] 
[2718]             status = 0;
[2719] 
[2720]         } else {
[2721] 
[2722]             status = ngx_atoi(value[i].data, value[i].len);
[2723]             if (status < 100 || status > 599) {
[2724]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2725]                                    "invalid status \"%V\"", &value[i]);
[2726]                 return NGX_CONF_ERROR;
[2727]             }
[2728]         }
[2729] 
[2730]         v = ngx_array_push(*a);
[2731]         if (v == NULL) {
[2732]             return NGX_CONF_ERROR;
[2733]         }
[2734] 
[2735]         v->status = status;
[2736]         v->valid = valid;
[2737]     }
[2738] 
[2739]     return NGX_CONF_OK;
[2740] }
