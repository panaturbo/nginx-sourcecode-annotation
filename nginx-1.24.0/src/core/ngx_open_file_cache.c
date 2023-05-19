[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] 
[12] 
[13] /*
[14]  * open file cache caches
[15]  *    open file handles with stat() info;
[16]  *    directories stat() info;
[17]  *    files and directories errors: not found, access denied, etc.
[18]  */
[19] 
[20] 
[21] #define NGX_MIN_READ_AHEAD  (128 * 1024)
[22] 
[23] 
[24] static void ngx_open_file_cache_cleanup(void *data);
[25] #if (NGX_HAVE_OPENAT)
[26] static ngx_fd_t ngx_openat_file_owner(ngx_fd_t at_fd, const u_char *name,
[27]     ngx_int_t mode, ngx_int_t create, ngx_int_t access, ngx_log_t *log);
[28] #if (NGX_HAVE_O_PATH)
[29] static ngx_int_t ngx_file_o_path_info(ngx_fd_t fd, ngx_file_info_t *fi,
[30]     ngx_log_t *log);
[31] #endif
[32] #endif
[33] static ngx_fd_t ngx_open_file_wrapper(ngx_str_t *name,
[34]     ngx_open_file_info_t *of, ngx_int_t mode, ngx_int_t create,
[35]     ngx_int_t access, ngx_log_t *log);
[36] static ngx_int_t ngx_file_info_wrapper(ngx_str_t *name,
[37]     ngx_open_file_info_t *of, ngx_file_info_t *fi, ngx_log_t *log);
[38] static ngx_int_t ngx_open_and_stat_file(ngx_str_t *name,
[39]     ngx_open_file_info_t *of, ngx_log_t *log);
[40] static void ngx_open_file_add_event(ngx_open_file_cache_t *cache,
[41]     ngx_cached_open_file_t *file, ngx_open_file_info_t *of, ngx_log_t *log);
[42] static void ngx_open_file_cleanup(void *data);
[43] static void ngx_close_cached_file(ngx_open_file_cache_t *cache,
[44]     ngx_cached_open_file_t *file, ngx_uint_t min_uses, ngx_log_t *log);
[45] static void ngx_open_file_del_event(ngx_cached_open_file_t *file);
[46] static void ngx_expire_old_cached_files(ngx_open_file_cache_t *cache,
[47]     ngx_uint_t n, ngx_log_t *log);
[48] static void ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
[49]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[50] static ngx_cached_open_file_t *
[51]     ngx_open_file_lookup(ngx_open_file_cache_t *cache, ngx_str_t *name,
[52]     uint32_t hash);
[53] static void ngx_open_file_cache_remove(ngx_event_t *ev);
[54] 
[55] 
[56] ngx_open_file_cache_t *
[57] ngx_open_file_cache_init(ngx_pool_t *pool, ngx_uint_t max, time_t inactive)
[58] {
[59]     ngx_pool_cleanup_t     *cln;
[60]     ngx_open_file_cache_t  *cache;
[61] 
[62]     cache = ngx_palloc(pool, sizeof(ngx_open_file_cache_t));
[63]     if (cache == NULL) {
[64]         return NULL;
[65]     }
[66] 
[67]     ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
[68]                     ngx_open_file_cache_rbtree_insert_value);
[69] 
[70]     ngx_queue_init(&cache->expire_queue);
[71] 
[72]     cache->current = 0;
[73]     cache->max = max;
[74]     cache->inactive = inactive;
[75] 
[76]     cln = ngx_pool_cleanup_add(pool, 0);
[77]     if (cln == NULL) {
[78]         return NULL;
[79]     }
[80] 
[81]     cln->handler = ngx_open_file_cache_cleanup;
[82]     cln->data = cache;
[83] 
[84]     return cache;
[85] }
[86] 
[87] 
[88] static void
[89] ngx_open_file_cache_cleanup(void *data)
[90] {
[91]     ngx_open_file_cache_t  *cache = data;
[92] 
[93]     ngx_queue_t             *q;
[94]     ngx_cached_open_file_t  *file;
[95] 
[96]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[97]                    "open file cache cleanup");
[98] 
[99]     for ( ;; ) {
[100] 
[101]         if (ngx_queue_empty(&cache->expire_queue)) {
[102]             break;
[103]         }
[104] 
[105]         q = ngx_queue_last(&cache->expire_queue);
[106] 
[107]         file = ngx_queue_data(q, ngx_cached_open_file_t, queue);
[108] 
[109]         ngx_queue_remove(q);
[110] 
[111]         ngx_rbtree_delete(&cache->rbtree, &file->node);
[112] 
[113]         cache->current--;
[114] 
[115]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[116]                        "delete cached open file: %s", file->name);
[117] 
[118]         if (!file->err && !file->is_dir) {
[119]             file->close = 1;
[120]             file->count = 0;
[121]             ngx_close_cached_file(cache, file, 0, ngx_cycle->log);
[122] 
[123]         } else {
[124]             ngx_free(file->name);
[125]             ngx_free(file);
[126]         }
[127]     }
[128] 
[129]     if (cache->current) {
[130]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[131]                       "%ui items still left in open file cache",
[132]                       cache->current);
[133]     }
[134] 
[135]     if (cache->rbtree.root != cache->rbtree.sentinel) {
[136]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[137]                       "rbtree still is not empty in open file cache");
[138] 
[139]     }
[140] }
[141] 
[142] 
[143] ngx_int_t
[144] ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
[145]     ngx_open_file_info_t *of, ngx_pool_t *pool)
[146] {
[147]     time_t                          now;
[148]     uint32_t                        hash;
[149]     ngx_int_t                       rc;
[150]     ngx_file_info_t                 fi;
[151]     ngx_pool_cleanup_t             *cln;
[152]     ngx_cached_open_file_t         *file;
[153]     ngx_pool_cleanup_file_t        *clnf;
[154]     ngx_open_file_cache_cleanup_t  *ofcln;
[155] 
[156]     of->fd = NGX_INVALID_FILE;
[157]     of->err = 0;
[158] 
[159]     if (cache == NULL) {
[160] 
[161]         if (of->test_only) {
[162] 
[163]             if (ngx_file_info_wrapper(name, of, &fi, pool->log)
[164]                 == NGX_FILE_ERROR)
[165]             {
[166]                 return NGX_ERROR;
[167]             }
[168] 
[169]             of->uniq = ngx_file_uniq(&fi);
[170]             of->mtime = ngx_file_mtime(&fi);
[171]             of->size = ngx_file_size(&fi);
[172]             of->fs_size = ngx_file_fs_size(&fi);
[173]             of->is_dir = ngx_is_dir(&fi);
[174]             of->is_file = ngx_is_file(&fi);
[175]             of->is_link = ngx_is_link(&fi);
[176]             of->is_exec = ngx_is_exec(&fi);
[177] 
[178]             return NGX_OK;
[179]         }
[180] 
[181]         cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
[182]         if (cln == NULL) {
[183]             return NGX_ERROR;
[184]         }
[185] 
[186]         rc = ngx_open_and_stat_file(name, of, pool->log);
[187] 
[188]         if (rc == NGX_OK && !of->is_dir) {
[189]             cln->handler = ngx_pool_cleanup_file;
[190]             clnf = cln->data;
[191] 
[192]             clnf->fd = of->fd;
[193]             clnf->name = name->data;
[194]             clnf->log = pool->log;
[195]         }
[196] 
[197]         return rc;
[198]     }
[199] 
[200]     cln = ngx_pool_cleanup_add(pool, sizeof(ngx_open_file_cache_cleanup_t));
[201]     if (cln == NULL) {
[202]         return NGX_ERROR;
[203]     }
[204] 
[205]     now = ngx_time();
[206] 
[207]     hash = ngx_crc32_long(name->data, name->len);
[208] 
[209]     file = ngx_open_file_lookup(cache, name, hash);
[210] 
[211]     if (file) {
[212] 
[213]         file->uses++;
[214] 
[215]         ngx_queue_remove(&file->queue);
[216] 
[217]         if (file->fd == NGX_INVALID_FILE && file->err == 0 && !file->is_dir) {
[218] 
[219]             /* file was not used often enough to keep open */
[220] 
[221]             rc = ngx_open_and_stat_file(name, of, pool->log);
[222] 
[223]             if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
[224]                 goto failed;
[225]             }
[226] 
[227]             goto add_event;
[228]         }
[229] 
[230]         if (file->use_event
[231]             || (file->event == NULL
[232]                 && (of->uniq == 0 || of->uniq == file->uniq)
[233]                 && now - file->created < of->valid
[234] #if (NGX_HAVE_OPENAT)
[235]                 && of->disable_symlinks == file->disable_symlinks
[236]                 && of->disable_symlinks_from == file->disable_symlinks_from
[237] #endif
[238]             ))
[239]         {
[240]             if (file->err == 0) {
[241] 
[242]                 of->fd = file->fd;
[243]                 of->uniq = file->uniq;
[244]                 of->mtime = file->mtime;
[245]                 of->size = file->size;
[246] 
[247]                 of->is_dir = file->is_dir;
[248]                 of->is_file = file->is_file;
[249]                 of->is_link = file->is_link;
[250]                 of->is_exec = file->is_exec;
[251]                 of->is_directio = file->is_directio;
[252] 
[253]                 if (!file->is_dir) {
[254]                     file->count++;
[255]                     ngx_open_file_add_event(cache, file, of, pool->log);
[256]                 }
[257] 
[258]             } else {
[259]                 of->err = file->err;
[260] #if (NGX_HAVE_OPENAT)
[261]                 of->failed = file->disable_symlinks ? ngx_openat_file_n
[262]                                                     : ngx_open_file_n;
[263] #else
[264]                 of->failed = ngx_open_file_n;
[265] #endif
[266]             }
[267] 
[268]             goto found;
[269]         }
[270] 
[271]         ngx_log_debug4(NGX_LOG_DEBUG_CORE, pool->log, 0,
[272]                        "retest open file: %s, fd:%d, c:%d, e:%d",
[273]                        file->name, file->fd, file->count, file->err);
[274] 
[275]         if (file->is_dir) {
[276] 
[277]             /*
[278]              * chances that directory became file are very small
[279]              * so test_dir flag allows to use a single syscall
[280]              * in ngx_file_info() instead of three syscalls
[281]              */
[282] 
[283]             of->test_dir = 1;
[284]         }
[285] 
[286]         of->fd = file->fd;
[287]         of->uniq = file->uniq;
[288] 
[289]         rc = ngx_open_and_stat_file(name, of, pool->log);
[290] 
[291]         if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
[292]             goto failed;
[293]         }
[294] 
[295]         if (of->is_dir) {
[296] 
[297]             if (file->is_dir || file->err) {
[298]                 goto update;
[299]             }
[300] 
[301]             /* file became directory */
[302] 
[303]         } else if (of->err == 0) {  /* file */
[304] 
[305]             if (file->is_dir || file->err) {
[306]                 goto add_event;
[307]             }
[308] 
[309]             if (of->uniq == file->uniq) {
[310] 
[311]                 if (file->event) {
[312]                     file->use_event = 1;
[313]                 }
[314] 
[315]                 of->is_directio = file->is_directio;
[316] 
[317]                 goto update;
[318]             }
[319] 
[320]             /* file was changed */
[321] 
[322]         } else { /* error to cache */
[323] 
[324]             if (file->err || file->is_dir) {
[325]                 goto update;
[326]             }
[327] 
[328]             /* file was removed, etc. */
[329]         }
[330] 
[331]         if (file->count == 0) {
[332] 
[333]             ngx_open_file_del_event(file);
[334] 
[335]             if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
[336]                 ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
[337]                               ngx_close_file_n " \"%V\" failed", name);
[338]             }
[339] 
[340]             goto add_event;
[341]         }
[342] 
[343]         ngx_rbtree_delete(&cache->rbtree, &file->node);
[344] 
[345]         cache->current--;
[346] 
[347]         file->close = 1;
[348] 
[349]         goto create;
[350]     }
[351] 
[352]     /* not found */
[353] 
[354]     rc = ngx_open_and_stat_file(name, of, pool->log);
[355] 
[356]     if (rc != NGX_OK && (of->err == 0 || !of->errors)) {
[357]         goto failed;
[358]     }
[359] 
[360] create:
[361] 
[362]     if (cache->current >= cache->max) {
[363]         ngx_expire_old_cached_files(cache, 0, pool->log);
[364]     }
[365] 
[366]     file = ngx_alloc(sizeof(ngx_cached_open_file_t), pool->log);
[367] 
[368]     if (file == NULL) {
[369]         goto failed;
[370]     }
[371] 
[372]     file->name = ngx_alloc(name->len + 1, pool->log);
[373] 
[374]     if (file->name == NULL) {
[375]         ngx_free(file);
[376]         file = NULL;
[377]         goto failed;
[378]     }
[379] 
[380]     ngx_cpystrn(file->name, name->data, name->len + 1);
[381] 
[382]     file->node.key = hash;
[383] 
[384]     ngx_rbtree_insert(&cache->rbtree, &file->node);
[385] 
[386]     cache->current++;
[387] 
[388]     file->uses = 1;
[389]     file->count = 0;
[390]     file->use_event = 0;
[391]     file->event = NULL;
[392] 
[393] add_event:
[394] 
[395]     ngx_open_file_add_event(cache, file, of, pool->log);
[396] 
[397] update:
[398] 
[399]     file->fd = of->fd;
[400]     file->err = of->err;
[401] #if (NGX_HAVE_OPENAT)
[402]     file->disable_symlinks = of->disable_symlinks;
[403]     file->disable_symlinks_from = of->disable_symlinks_from;
[404] #endif
[405] 
[406]     if (of->err == 0) {
[407]         file->uniq = of->uniq;
[408]         file->mtime = of->mtime;
[409]         file->size = of->size;
[410] 
[411]         file->close = 0;
[412] 
[413]         file->is_dir = of->is_dir;
[414]         file->is_file = of->is_file;
[415]         file->is_link = of->is_link;
[416]         file->is_exec = of->is_exec;
[417]         file->is_directio = of->is_directio;
[418] 
[419]         if (!of->is_dir) {
[420]             file->count++;
[421]         }
[422]     }
[423] 
[424]     file->created = now;
[425] 
[426] found:
[427] 
[428]     file->accessed = now;
[429] 
[430]     ngx_queue_insert_head(&cache->expire_queue, &file->queue);
[431] 
[432]     ngx_log_debug5(NGX_LOG_DEBUG_CORE, pool->log, 0,
[433]                    "cached open file: %s, fd:%d, c:%d, e:%d, u:%d",
[434]                    file->name, file->fd, file->count, file->err, file->uses);
[435] 
[436]     if (of->err == 0) {
[437] 
[438]         if (!of->is_dir) {
[439]             cln->handler = ngx_open_file_cleanup;
[440]             ofcln = cln->data;
[441] 
[442]             ofcln->cache = cache;
[443]             ofcln->file = file;
[444]             ofcln->min_uses = of->min_uses;
[445]             ofcln->log = pool->log;
[446]         }
[447] 
[448]         return NGX_OK;
[449]     }
[450] 
[451]     return NGX_ERROR;
[452] 
[453] failed:
[454] 
[455]     if (file) {
[456]         ngx_rbtree_delete(&cache->rbtree, &file->node);
[457] 
[458]         cache->current--;
[459] 
[460]         if (file->count == 0) {
[461] 
[462]             if (file->fd != NGX_INVALID_FILE) {
[463]                 if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
[464]                     ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
[465]                                   ngx_close_file_n " \"%s\" failed",
[466]                                   file->name);
[467]                 }
[468]             }
[469] 
[470]             ngx_free(file->name);
[471]             ngx_free(file);
[472] 
[473]         } else {
[474]             file->close = 1;
[475]         }
[476]     }
[477] 
[478]     if (of->fd != NGX_INVALID_FILE) {
[479]         if (ngx_close_file(of->fd) == NGX_FILE_ERROR) {
[480]             ngx_log_error(NGX_LOG_ALERT, pool->log, ngx_errno,
[481]                           ngx_close_file_n " \"%V\" failed", name);
[482]         }
[483]     }
[484] 
[485]     return NGX_ERROR;
[486] }
[487] 
[488] 
[489] #if (NGX_HAVE_OPENAT)
[490] 
[491] static ngx_fd_t
[492] ngx_openat_file_owner(ngx_fd_t at_fd, const u_char *name,
[493]     ngx_int_t mode, ngx_int_t create, ngx_int_t access, ngx_log_t *log)
[494] {
[495]     ngx_fd_t         fd;
[496]     ngx_err_t        err;
[497]     ngx_file_info_t  fi, atfi;
[498] 
[499]     /*
[500]      * To allow symlinks with the same owner, use openat() (followed
[501]      * by fstat()) and fstatat(AT_SYMLINK_NOFOLLOW), and then compare
[502]      * uids between fstat() and fstatat().
[503]      *
[504]      * As there is a race between openat() and fstatat() we don't
[505]      * know if openat() in fact opened symlink or not.  Therefore,
[506]      * we have to compare uids even if fstatat() reports the opened
[507]      * component isn't a symlink (as we don't know whether it was
[508]      * symlink during openat() or not).
[509]      */
[510] 
[511]     fd = ngx_openat_file(at_fd, name, mode, create, access);
[512] 
[513]     if (fd == NGX_INVALID_FILE) {
[514]         return NGX_INVALID_FILE;
[515]     }
[516] 
[517]     if (ngx_file_at_info(at_fd, name, &atfi, AT_SYMLINK_NOFOLLOW)
[518]         == NGX_FILE_ERROR)
[519]     {
[520]         err = ngx_errno;
[521]         goto failed;
[522]     }
[523] 
[524] #if (NGX_HAVE_O_PATH)
[525]     if (ngx_file_o_path_info(fd, &fi, log) == NGX_ERROR) {
[526]         err = ngx_errno;
[527]         goto failed;
[528]     }
[529] #else
[530]     if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
[531]         err = ngx_errno;
[532]         goto failed;
[533]     }
[534] #endif
[535] 
[536]     if (fi.st_uid != atfi.st_uid) {
[537]         err = NGX_ELOOP;
[538]         goto failed;
[539]     }
[540] 
[541]     return fd;
[542] 
[543] failed:
[544] 
[545]     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[546]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[547]                       ngx_close_file_n " \"%s\" failed", name);
[548]     }
[549] 
[550]     ngx_set_errno(err);
[551] 
[552]     return NGX_INVALID_FILE;
[553] }
[554] 
[555] 
[556] #if (NGX_HAVE_O_PATH)
[557] 
[558] static ngx_int_t
[559] ngx_file_o_path_info(ngx_fd_t fd, ngx_file_info_t *fi, ngx_log_t *log)
[560] {
[561]     static ngx_uint_t  use_fstat = 1;
[562] 
[563]     /*
[564]      * In Linux 2.6.39 the O_PATH flag was introduced that allows to obtain
[565]      * a descriptor without actually opening file or directory.  It requires
[566]      * less permissions for path components, but till Linux 3.6 fstat() returns
[567]      * EBADF on such descriptors, and fstatat() with the AT_EMPTY_PATH flag
[568]      * should be used instead.
[569]      *
[570]      * Three scenarios are handled in this function:
[571]      *
[572]      * 1) The kernel is newer than 3.6 or fstat() with O_PATH support was
[573]      *    backported by vendor.  Then fstat() is used.
[574]      *
[575]      * 2) The kernel is newer than 2.6.39 but older than 3.6.  In this case
[576]      *    the first call of fstat() returns EBADF and we fallback to fstatat()
[577]      *    with AT_EMPTY_PATH which was introduced at the same time as O_PATH.
[578]      *
[579]      * 3) The kernel is older than 2.6.39 but nginx was build with O_PATH
[580]      *    support.  Since descriptors are opened with O_PATH|O_RDONLY flags
[581]      *    and O_PATH is ignored by the kernel then the O_RDONLY flag is
[582]      *    actually used.  In this case fstat() just works.
[583]      */
[584] 
[585]     if (use_fstat) {
[586]         if (ngx_fd_info(fd, fi) != NGX_FILE_ERROR) {
[587]             return NGX_OK;
[588]         }
[589] 
[590]         if (ngx_errno != NGX_EBADF) {
[591]             return NGX_ERROR;
[592]         }
[593] 
[594]         ngx_log_error(NGX_LOG_NOTICE, log, 0,
[595]                       "fstat(O_PATH) failed with EBADF, "
[596]                       "switching to fstatat(AT_EMPTY_PATH)");
[597] 
[598]         use_fstat = 0;
[599]     }
[600] 
[601]     if (ngx_file_at_info(fd, "", fi, AT_EMPTY_PATH) != NGX_FILE_ERROR) {
[602]         return NGX_OK;
[603]     }
[604] 
[605]     return NGX_ERROR;
[606] }
[607] 
[608] #endif
[609] 
[610] #endif /* NGX_HAVE_OPENAT */
[611] 
[612] 
[613] static ngx_fd_t
[614] ngx_open_file_wrapper(ngx_str_t *name, ngx_open_file_info_t *of,
[615]     ngx_int_t mode, ngx_int_t create, ngx_int_t access, ngx_log_t *log)
[616] {
[617]     ngx_fd_t  fd;
[618] 
[619] #if !(NGX_HAVE_OPENAT)
[620] 
[621]     fd = ngx_open_file(name->data, mode, create, access);
[622] 
[623]     if (fd == NGX_INVALID_FILE) {
[624]         of->err = ngx_errno;
[625]         of->failed = ngx_open_file_n;
[626]         return NGX_INVALID_FILE;
[627]     }
[628] 
[629]     return fd;
[630] 
[631] #else
[632] 
[633]     u_char           *p, *cp, *end;
[634]     ngx_fd_t          at_fd;
[635]     ngx_str_t         at_name;
[636] 
[637]     if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_OFF) {
[638]         fd = ngx_open_file(name->data, mode, create, access);
[639] 
[640]         if (fd == NGX_INVALID_FILE) {
[641]             of->err = ngx_errno;
[642]             of->failed = ngx_open_file_n;
[643]             return NGX_INVALID_FILE;
[644]         }
[645] 
[646]         return fd;
[647]     }
[648] 
[649]     p = name->data;
[650]     end = p + name->len;
[651] 
[652]     at_name = *name;
[653] 
[654]     if (of->disable_symlinks_from) {
[655] 
[656]         cp = p + of->disable_symlinks_from;
[657] 
[658]         *cp = '\0';
[659] 
[660]         at_fd = ngx_open_file(p, NGX_FILE_SEARCH|NGX_FILE_NONBLOCK,
[661]                               NGX_FILE_OPEN, 0);
[662] 
[663]         *cp = '/';
[664] 
[665]         if (at_fd == NGX_INVALID_FILE) {
[666]             of->err = ngx_errno;
[667]             of->failed = ngx_open_file_n;
[668]             return NGX_INVALID_FILE;
[669]         }
[670] 
[671]         at_name.len = of->disable_symlinks_from;
[672]         p = cp + 1;
[673] 
[674]     } else if (*p == '/') {
[675] 
[676]         at_fd = ngx_open_file("/",
[677]                               NGX_FILE_SEARCH|NGX_FILE_NONBLOCK,
[678]                               NGX_FILE_OPEN, 0);
[679] 
[680]         if (at_fd == NGX_INVALID_FILE) {
[681]             of->err = ngx_errno;
[682]             of->failed = ngx_openat_file_n;
[683]             return NGX_INVALID_FILE;
[684]         }
[685] 
[686]         at_name.len = 1;
[687]         p++;
[688] 
[689]     } else {
[690]         at_fd = NGX_AT_FDCWD;
[691]     }
[692] 
[693]     for ( ;; ) {
[694]         cp = ngx_strlchr(p, end, '/');
[695]         if (cp == NULL) {
[696]             break;
[697]         }
[698] 
[699]         if (cp == p) {
[700]             p++;
[701]             continue;
[702]         }
[703] 
[704]         *cp = '\0';
[705] 
[706]         if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_NOTOWNER) {
[707]             fd = ngx_openat_file_owner(at_fd, p,
[708]                                        NGX_FILE_SEARCH|NGX_FILE_NONBLOCK,
[709]                                        NGX_FILE_OPEN, 0, log);
[710] 
[711]         } else {
[712]             fd = ngx_openat_file(at_fd, p,
[713]                            NGX_FILE_SEARCH|NGX_FILE_NONBLOCK|NGX_FILE_NOFOLLOW,
[714]                            NGX_FILE_OPEN, 0);
[715]         }
[716] 
[717]         *cp = '/';
[718] 
[719]         if (fd == NGX_INVALID_FILE) {
[720]             of->err = ngx_errno;
[721]             of->failed = ngx_openat_file_n;
[722]             goto failed;
[723]         }
[724] 
[725]         if (at_fd != NGX_AT_FDCWD && ngx_close_file(at_fd) == NGX_FILE_ERROR) {
[726]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[727]                           ngx_close_file_n " \"%V\" failed", &at_name);
[728]         }
[729] 
[730]         p = cp + 1;
[731]         at_fd = fd;
[732]         at_name.len = cp - at_name.data;
[733]     }
[734] 
[735]     if (p == end) {
[736] 
[737]         /*
[738]          * If pathname ends with a trailing slash, assume the last path
[739]          * component is a directory and reopen it with requested flags;
[740]          * if not, fail with ENOTDIR as per POSIX.
[741]          *
[742]          * We cannot rely on O_DIRECTORY in the loop above to check
[743]          * that the last path component is a directory because
[744]          * O_DIRECTORY doesn't work on FreeBSD 8.  Fortunately, by
[745]          * reopening a directory, we don't depend on it at all.
[746]          */
[747] 
[748]         fd = ngx_openat_file(at_fd, ".", mode, create, access);
[749]         goto done;
[750]     }
[751] 
[752]     if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_NOTOWNER
[753]         && !(create & (NGX_FILE_CREATE_OR_OPEN|NGX_FILE_TRUNCATE)))
[754]     {
[755]         fd = ngx_openat_file_owner(at_fd, p, mode, create, access, log);
[756] 
[757]     } else {
[758]         fd = ngx_openat_file(at_fd, p, mode|NGX_FILE_NOFOLLOW, create, access);
[759]     }
[760] 
[761] done:
[762] 
[763]     if (fd == NGX_INVALID_FILE) {
[764]         of->err = ngx_errno;
[765]         of->failed = ngx_openat_file_n;
[766]     }
[767] 
[768] failed:
[769] 
[770]     if (at_fd != NGX_AT_FDCWD && ngx_close_file(at_fd) == NGX_FILE_ERROR) {
[771]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[772]                       ngx_close_file_n " \"%V\" failed", &at_name);
[773]     }
[774] 
[775]     return fd;
[776] #endif
[777] }
[778] 
[779] 
[780] static ngx_int_t
[781] ngx_file_info_wrapper(ngx_str_t *name, ngx_open_file_info_t *of,
[782]     ngx_file_info_t *fi, ngx_log_t *log)
[783] {
[784]     ngx_int_t  rc;
[785] 
[786] #if !(NGX_HAVE_OPENAT)
[787] 
[788]     rc = ngx_file_info(name->data, fi);
[789] 
[790]     if (rc == NGX_FILE_ERROR) {
[791]         of->err = ngx_errno;
[792]         of->failed = ngx_file_info_n;
[793]         return NGX_FILE_ERROR;
[794]     }
[795] 
[796]     return rc;
[797] 
[798] #else
[799] 
[800]     ngx_fd_t  fd;
[801] 
[802]     if (of->disable_symlinks == NGX_DISABLE_SYMLINKS_OFF) {
[803] 
[804]         rc = ngx_file_info(name->data, fi);
[805] 
[806]         if (rc == NGX_FILE_ERROR) {
[807]             of->err = ngx_errno;
[808]             of->failed = ngx_file_info_n;
[809]             return NGX_FILE_ERROR;
[810]         }
[811] 
[812]         return rc;
[813]     }
[814] 
[815]     fd = ngx_open_file_wrapper(name, of, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
[816]                                NGX_FILE_OPEN, 0, log);
[817] 
[818]     if (fd == NGX_INVALID_FILE) {
[819]         return NGX_FILE_ERROR;
[820]     }
[821] 
[822]     rc = ngx_fd_info(fd, fi);
[823] 
[824]     if (rc == NGX_FILE_ERROR) {
[825]         of->err = ngx_errno;
[826]         of->failed = ngx_fd_info_n;
[827]     }
[828] 
[829]     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[830]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[831]                       ngx_close_file_n " \"%V\" failed", name);
[832]     }
[833] 
[834]     return rc;
[835] #endif
[836] }
[837] 
[838] 
[839] static ngx_int_t
[840] ngx_open_and_stat_file(ngx_str_t *name, ngx_open_file_info_t *of,
[841]     ngx_log_t *log)
[842] {
[843]     ngx_fd_t         fd;
[844]     ngx_file_info_t  fi;
[845] 
[846]     if (of->fd != NGX_INVALID_FILE) {
[847] 
[848]         if (ngx_file_info_wrapper(name, of, &fi, log) == NGX_FILE_ERROR) {
[849]             of->fd = NGX_INVALID_FILE;
[850]             return NGX_ERROR;
[851]         }
[852] 
[853]         if (of->uniq == ngx_file_uniq(&fi)) {
[854]             goto done;
[855]         }
[856] 
[857]     } else if (of->test_dir) {
[858] 
[859]         if (ngx_file_info_wrapper(name, of, &fi, log) == NGX_FILE_ERROR) {
[860]             of->fd = NGX_INVALID_FILE;
[861]             return NGX_ERROR;
[862]         }
[863] 
[864]         if (ngx_is_dir(&fi)) {
[865]             goto done;
[866]         }
[867]     }
[868] 
[869]     if (!of->log) {
[870] 
[871]         /*
[872]          * Use non-blocking open() not to hang on FIFO files, etc.
[873]          * This flag has no effect on a regular files.
[874]          */
[875] 
[876]         fd = ngx_open_file_wrapper(name, of, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
[877]                                    NGX_FILE_OPEN, 0, log);
[878] 
[879]     } else {
[880]         fd = ngx_open_file_wrapper(name, of, NGX_FILE_APPEND,
[881]                                    NGX_FILE_CREATE_OR_OPEN,
[882]                                    NGX_FILE_DEFAULT_ACCESS, log);
[883]     }
[884] 
[885]     if (fd == NGX_INVALID_FILE) {
[886]         of->fd = NGX_INVALID_FILE;
[887]         return NGX_ERROR;
[888]     }
[889] 
[890]     if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
[891]         ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
[892]                       ngx_fd_info_n " \"%V\" failed", name);
[893] 
[894]         if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[895]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[896]                           ngx_close_file_n " \"%V\" failed", name);
[897]         }
[898] 
[899]         of->fd = NGX_INVALID_FILE;
[900] 
[901]         return NGX_ERROR;
[902]     }
[903] 
[904]     if (ngx_is_dir(&fi)) {
[905]         if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[906]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[907]                           ngx_close_file_n " \"%V\" failed", name);
[908]         }
[909] 
[910]         of->fd = NGX_INVALID_FILE;
[911] 
[912]     } else {
[913]         of->fd = fd;
[914] 
[915]         if (of->read_ahead && ngx_file_size(&fi) > NGX_MIN_READ_AHEAD) {
[916]             if (ngx_read_ahead(fd, of->read_ahead) == NGX_ERROR) {
[917]                 ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[918]                               ngx_read_ahead_n " \"%V\" failed", name);
[919]             }
[920]         }
[921] 
[922]         if (of->directio <= ngx_file_size(&fi)) {
[923]             if (ngx_directio_on(fd) == NGX_FILE_ERROR) {
[924]                 ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[925]                               ngx_directio_on_n " \"%V\" failed", name);
[926] 
[927]             } else {
[928]                 of->is_directio = 1;
[929]             }
[930]         }
[931]     }
[932] 
[933] done:
[934] 
[935]     of->uniq = ngx_file_uniq(&fi);
[936]     of->mtime = ngx_file_mtime(&fi);
[937]     of->size = ngx_file_size(&fi);
[938]     of->fs_size = ngx_file_fs_size(&fi);
[939]     of->is_dir = ngx_is_dir(&fi);
[940]     of->is_file = ngx_is_file(&fi);
[941]     of->is_link = ngx_is_link(&fi);
[942]     of->is_exec = ngx_is_exec(&fi);
[943] 
[944]     return NGX_OK;
[945] }
[946] 
[947] 
[948] /*
[949]  * we ignore any possible event setting error and
[950]  * fallback to usual periodic file retests
[951]  */
[952] 
[953] static void
[954] ngx_open_file_add_event(ngx_open_file_cache_t *cache,
[955]     ngx_cached_open_file_t *file, ngx_open_file_info_t *of, ngx_log_t *log)
[956] {
[957]     ngx_open_file_cache_event_t  *fev;
[958] 
[959]     if (!(ngx_event_flags & NGX_USE_VNODE_EVENT)
[960]         || !of->events
[961]         || file->event
[962]         || of->fd == NGX_INVALID_FILE
[963]         || file->uses < of->min_uses)
[964]     {
[965]         return;
[966]     }
[967] 
[968]     file->use_event = 0;
[969] 
[970]     file->event = ngx_calloc(sizeof(ngx_event_t), log);
[971]     if (file->event== NULL) {
[972]         return;
[973]     }
[974] 
[975]     fev = ngx_alloc(sizeof(ngx_open_file_cache_event_t), log);
[976]     if (fev == NULL) {
[977]         ngx_free(file->event);
[978]         file->event = NULL;
[979]         return;
[980]     }
[981] 
[982]     fev->fd = of->fd;
[983]     fev->file = file;
[984]     fev->cache = cache;
[985] 
[986]     file->event->handler = ngx_open_file_cache_remove;
[987]     file->event->data = fev;
[988] 
[989]     /*
[990]      * although vnode event may be called while ngx_cycle->poll
[991]      * destruction, however, cleanup procedures are run before any
[992]      * memory freeing and events will be canceled.
[993]      */
[994] 
[995]     file->event->log = ngx_cycle->log;
[996] 
[997]     if (ngx_add_event(file->event, NGX_VNODE_EVENT, NGX_ONESHOT_EVENT)
[998]         != NGX_OK)
[999]     {
[1000]         ngx_free(file->event->data);
[1001]         ngx_free(file->event);
[1002]         file->event = NULL;
[1003]         return;
[1004]     }
[1005] 
[1006]     /*
[1007]      * we do not set file->use_event here because there may be a race
[1008]      * condition: a file may be deleted between opening the file and
[1009]      * adding event, so we rely upon event notification only after
[1010]      * one file revalidation on next file access
[1011]      */
[1012] 
[1013]     return;
[1014] }
[1015] 
[1016] 
[1017] static void
[1018] ngx_open_file_cleanup(void *data)
[1019] {
[1020]     ngx_open_file_cache_cleanup_t  *c = data;
[1021] 
[1022]     c->file->count--;
[1023] 
[1024]     ngx_close_cached_file(c->cache, c->file, c->min_uses, c->log);
[1025] 
[1026]     /* drop one or two expired open files */
[1027]     ngx_expire_old_cached_files(c->cache, 1, c->log);
[1028] }
[1029] 
[1030] 
[1031] static void
[1032] ngx_close_cached_file(ngx_open_file_cache_t *cache,
[1033]     ngx_cached_open_file_t *file, ngx_uint_t min_uses, ngx_log_t *log)
[1034] {
[1035]     ngx_log_debug5(NGX_LOG_DEBUG_CORE, log, 0,
[1036]                    "close cached open file: %s, fd:%d, c:%d, u:%d, %d",
[1037]                    file->name, file->fd, file->count, file->uses, file->close);
[1038] 
[1039]     if (!file->close) {
[1040] 
[1041]         file->accessed = ngx_time();
[1042] 
[1043]         ngx_queue_remove(&file->queue);
[1044] 
[1045]         ngx_queue_insert_head(&cache->expire_queue, &file->queue);
[1046] 
[1047]         if (file->uses >= min_uses || file->count) {
[1048]             return;
[1049]         }
[1050]     }
[1051] 
[1052]     ngx_open_file_del_event(file);
[1053] 
[1054]     if (file->count) {
[1055]         return;
[1056]     }
[1057] 
[1058]     if (file->fd != NGX_INVALID_FILE) {
[1059] 
[1060]         if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
[1061]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[1062]                           ngx_close_file_n " \"%s\" failed", file->name);
[1063]         }
[1064] 
[1065]         file->fd = NGX_INVALID_FILE;
[1066]     }
[1067] 
[1068]     if (!file->close) {
[1069]         return;
[1070]     }
[1071] 
[1072]     ngx_free(file->name);
[1073]     ngx_free(file);
[1074] }
[1075] 
[1076] 
[1077] static void
[1078] ngx_open_file_del_event(ngx_cached_open_file_t *file)
[1079] {
[1080]     if (file->event == NULL) {
[1081]         return;
[1082]     }
[1083] 
[1084]     (void) ngx_del_event(file->event, NGX_VNODE_EVENT,
[1085]                          file->count ? NGX_FLUSH_EVENT : NGX_CLOSE_EVENT);
[1086] 
[1087]     ngx_free(file->event->data);
[1088]     ngx_free(file->event);
[1089]     file->event = NULL;
[1090]     file->use_event = 0;
[1091] }
[1092] 
[1093] 
[1094] static void
[1095] ngx_expire_old_cached_files(ngx_open_file_cache_t *cache, ngx_uint_t n,
[1096]     ngx_log_t *log)
[1097] {
[1098]     time_t                   now;
[1099]     ngx_queue_t             *q;
[1100]     ngx_cached_open_file_t  *file;
[1101] 
[1102]     now = ngx_time();
[1103] 
[1104]     /*
[1105]      * n == 1 deletes one or two inactive files
[1106]      * n == 0 deletes least recently used file by force
[1107]      *        and one or two inactive files
[1108]      */
[1109] 
[1110]     while (n < 3) {
[1111] 
[1112]         if (ngx_queue_empty(&cache->expire_queue)) {
[1113]             return;
[1114]         }
[1115] 
[1116]         q = ngx_queue_last(&cache->expire_queue);
[1117] 
[1118]         file = ngx_queue_data(q, ngx_cached_open_file_t, queue);
[1119] 
[1120]         if (n++ != 0 && now - file->accessed <= cache->inactive) {
[1121]             return;
[1122]         }
[1123] 
[1124]         ngx_queue_remove(q);
[1125] 
[1126]         ngx_rbtree_delete(&cache->rbtree, &file->node);
[1127] 
[1128]         cache->current--;
[1129] 
[1130]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
[1131]                        "expire cached open file: %s", file->name);
[1132] 
[1133]         if (!file->err && !file->is_dir) {
[1134]             file->close = 1;
[1135]             ngx_close_cached_file(cache, file, 0, log);
[1136] 
[1137]         } else {
[1138]             ngx_free(file->name);
[1139]             ngx_free(file);
[1140]         }
[1141]     }
[1142] }
[1143] 
[1144] 
[1145] static void
[1146] ngx_open_file_cache_rbtree_insert_value(ngx_rbtree_node_t *temp,
[1147]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[1148] {
[1149]     ngx_rbtree_node_t       **p;
[1150]     ngx_cached_open_file_t    *file, *file_temp;
[1151] 
[1152]     for ( ;; ) {
[1153] 
[1154]         if (node->key < temp->key) {
[1155] 
[1156]             p = &temp->left;
[1157] 
[1158]         } else if (node->key > temp->key) {
[1159] 
[1160]             p = &temp->right;
[1161] 
[1162]         } else { /* node->key == temp->key */
[1163] 
[1164]             file = (ngx_cached_open_file_t *) node;
[1165]             file_temp = (ngx_cached_open_file_t *) temp;
[1166] 
[1167]             p = (ngx_strcmp(file->name, file_temp->name) < 0)
[1168]                     ? &temp->left : &temp->right;
[1169]         }
[1170] 
[1171]         if (*p == sentinel) {
[1172]             break;
[1173]         }
[1174] 
[1175]         temp = *p;
[1176]     }
[1177] 
[1178]     *p = node;
[1179]     node->parent = temp;
[1180]     node->left = sentinel;
[1181]     node->right = sentinel;
[1182]     ngx_rbt_red(node);
[1183] }
[1184] 
[1185] 
[1186] static ngx_cached_open_file_t *
[1187] ngx_open_file_lookup(ngx_open_file_cache_t *cache, ngx_str_t *name,
[1188]     uint32_t hash)
[1189] {
[1190]     ngx_int_t                rc;
[1191]     ngx_rbtree_node_t       *node, *sentinel;
[1192]     ngx_cached_open_file_t  *file;
[1193] 
[1194]     node = cache->rbtree.root;
[1195]     sentinel = cache->rbtree.sentinel;
[1196] 
[1197]     while (node != sentinel) {
[1198] 
[1199]         if (hash < node->key) {
[1200]             node = node->left;
[1201]             continue;
[1202]         }
[1203] 
[1204]         if (hash > node->key) {
[1205]             node = node->right;
[1206]             continue;
[1207]         }
[1208] 
[1209]         /* hash == node->key */
[1210] 
[1211]         file = (ngx_cached_open_file_t *) node;
[1212] 
[1213]         rc = ngx_strcmp(name->data, file->name);
[1214] 
[1215]         if (rc == 0) {
[1216]             return file;
[1217]         }
[1218] 
[1219]         node = (rc < 0) ? node->left : node->right;
[1220]     }
[1221] 
[1222]     return NULL;
[1223] }
[1224] 
[1225] 
[1226] static void
[1227] ngx_open_file_cache_remove(ngx_event_t *ev)
[1228] {
[1229]     ngx_cached_open_file_t       *file;
[1230]     ngx_open_file_cache_event_t  *fev;
[1231] 
[1232]     fev = ev->data;
[1233]     file = fev->file;
[1234] 
[1235]     ngx_queue_remove(&file->queue);
[1236] 
[1237]     ngx_rbtree_delete(&fev->cache->rbtree, &file->node);
[1238] 
[1239]     fev->cache->current--;
[1240] 
[1241]     /* NGX_ONESHOT_EVENT was already deleted */
[1242]     file->event = NULL;
[1243]     file->use_event = 0;
[1244] 
[1245]     file->close = 1;
[1246] 
[1247]     ngx_close_cached_file(fev->cache, file, 0, ev->log);
[1248] 
[1249]     /* free memory only when fev->cache and fev->file are already not needed */
[1250] 
[1251]     ngx_free(ev->data);
[1252]     ngx_free(ev);
[1253] }
