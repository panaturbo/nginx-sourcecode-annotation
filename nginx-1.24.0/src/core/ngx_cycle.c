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
[13] static void ngx_destroy_cycle_pools(ngx_conf_t *conf);
[14] static ngx_int_t ngx_init_zone_pool(ngx_cycle_t *cycle,
[15]     ngx_shm_zone_t *shm_zone);
[16] static ngx_int_t ngx_test_lockfile(u_char *file, ngx_log_t *log);
[17] static void ngx_clean_old_cycles(ngx_event_t *ev);
[18] static void ngx_shutdown_timer_handler(ngx_event_t *ev);
[19] 
[20] 
[21] volatile ngx_cycle_t  *ngx_cycle;
[22] ngx_array_t            ngx_old_cycles;
[23] 
[24] static ngx_pool_t     *ngx_temp_pool;
[25] static ngx_event_t     ngx_cleaner_event;
[26] static ngx_event_t     ngx_shutdown_event;
[27] 
[28] ngx_uint_t             ngx_test_config;
[29] ngx_uint_t             ngx_dump_config;
[30] ngx_uint_t             ngx_quiet_mode;
[31] 
[32] 
[33] /* STUB NAME */
[34] static ngx_connection_t  dumb;
[35] /* STUB */
[36] 
[37] 
[38] ngx_cycle_t *
[39] ngx_init_cycle(ngx_cycle_t *old_cycle)
[40] {
[41]     void                *rv;
[42]     char               **senv;
[43]     ngx_uint_t           i, n;
[44]     ngx_log_t           *log;
[45]     ngx_time_t          *tp;
[46]     ngx_conf_t           conf;
[47]     ngx_pool_t          *pool;
[48]     ngx_cycle_t         *cycle, **old;
[49]     ngx_shm_zone_t      *shm_zone, *oshm_zone;
[50]     ngx_list_part_t     *part, *opart;
[51]     ngx_open_file_t     *file;
[52]     ngx_listening_t     *ls, *nls;
[53]     ngx_core_conf_t     *ccf, *old_ccf;
[54]     ngx_core_module_t   *module;
[55]     char                 hostname[NGX_MAXHOSTNAMELEN];
[56] 
[57]     ngx_timezone_update();
[58] 
[59]     /* force localtime update with a new timezone */
[60] 
[61]     tp = ngx_timeofday();
[62]     tp->sec = 0;
[63] 
[64]     ngx_time_update();
[65] 
[66] 
[67]     log = old_cycle->log;
[68] 
[69]     pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, log);
[70]     if (pool == NULL) {
[71]         return NULL;
[72]     }
[73]     pool->log = log;
[74] 
[75]     cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
[76]     if (cycle == NULL) {
[77]         ngx_destroy_pool(pool);
[78]         return NULL;
[79]     }
[80] 
[81]     cycle->pool = pool;
[82]     cycle->log = log;
[83]     cycle->old_cycle = old_cycle;
[84] 
[85]     cycle->conf_prefix.len = old_cycle->conf_prefix.len;
[86]     cycle->conf_prefix.data = ngx_pstrdup(pool, &old_cycle->conf_prefix);
[87]     if (cycle->conf_prefix.data == NULL) {
[88]         ngx_destroy_pool(pool);
[89]         return NULL;
[90]     }
[91] 
[92]     cycle->prefix.len = old_cycle->prefix.len;
[93]     cycle->prefix.data = ngx_pstrdup(pool, &old_cycle->prefix);
[94]     if (cycle->prefix.data == NULL) {
[95]         ngx_destroy_pool(pool);
[96]         return NULL;
[97]     }
[98] 
[99]     cycle->error_log.len = old_cycle->error_log.len;
[100]     cycle->error_log.data = ngx_pnalloc(pool, old_cycle->error_log.len + 1);
[101]     if (cycle->error_log.data == NULL) {
[102]         ngx_destroy_pool(pool);
[103]         return NULL;
[104]     }
[105]     ngx_cpystrn(cycle->error_log.data, old_cycle->error_log.data,
[106]                 old_cycle->error_log.len + 1);
[107] 
[108]     cycle->conf_file.len = old_cycle->conf_file.len;
[109]     cycle->conf_file.data = ngx_pnalloc(pool, old_cycle->conf_file.len + 1);
[110]     if (cycle->conf_file.data == NULL) {
[111]         ngx_destroy_pool(pool);
[112]         return NULL;
[113]     }
[114]     ngx_cpystrn(cycle->conf_file.data, old_cycle->conf_file.data,
[115]                 old_cycle->conf_file.len + 1);
[116] 
[117]     cycle->conf_param.len = old_cycle->conf_param.len;
[118]     cycle->conf_param.data = ngx_pstrdup(pool, &old_cycle->conf_param);
[119]     if (cycle->conf_param.data == NULL) {
[120]         ngx_destroy_pool(pool);
[121]         return NULL;
[122]     }
[123] 
[124] 
[125]     n = old_cycle->paths.nelts ? old_cycle->paths.nelts : 10;
[126] 
[127]     if (ngx_array_init(&cycle->paths, pool, n, sizeof(ngx_path_t *))
[128]         != NGX_OK)
[129]     {
[130]         ngx_destroy_pool(pool);
[131]         return NULL;
[132]     }
[133] 
[134]     ngx_memzero(cycle->paths.elts, n * sizeof(ngx_path_t *));
[135] 
[136] 
[137]     if (ngx_array_init(&cycle->config_dump, pool, 1, sizeof(ngx_conf_dump_t))
[138]         != NGX_OK)
[139]     {
[140]         ngx_destroy_pool(pool);
[141]         return NULL;
[142]     }
[143] 
[144]     ngx_rbtree_init(&cycle->config_dump_rbtree, &cycle->config_dump_sentinel,
[145]                     ngx_str_rbtree_insert_value);
[146] 
[147]     if (old_cycle->open_files.part.nelts) {
[148]         n = old_cycle->open_files.part.nelts;
[149]         for (part = old_cycle->open_files.part.next; part; part = part->next) {
[150]             n += part->nelts;
[151]         }
[152] 
[153]     } else {
[154]         n = 20;
[155]     }
[156] 
[157]     if (ngx_list_init(&cycle->open_files, pool, n, sizeof(ngx_open_file_t))
[158]         != NGX_OK)
[159]     {
[160]         ngx_destroy_pool(pool);
[161]         return NULL;
[162]     }
[163] 
[164] 
[165]     if (old_cycle->shared_memory.part.nelts) {
[166]         n = old_cycle->shared_memory.part.nelts;
[167]         for (part = old_cycle->shared_memory.part.next; part; part = part->next)
[168]         {
[169]             n += part->nelts;
[170]         }
[171] 
[172]     } else {
[173]         n = 1;
[174]     }
[175] 
[176]     if (ngx_list_init(&cycle->shared_memory, pool, n, sizeof(ngx_shm_zone_t))
[177]         != NGX_OK)
[178]     {
[179]         ngx_destroy_pool(pool);
[180]         return NULL;
[181]     }
[182] 
[183]     n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;
[184] 
[185]     if (ngx_array_init(&cycle->listening, pool, n, sizeof(ngx_listening_t))
[186]         != NGX_OK)
[187]     {
[188]         ngx_destroy_pool(pool);
[189]         return NULL;
[190]     }
[191] 
[192]     ngx_memzero(cycle->listening.elts, n * sizeof(ngx_listening_t));
[193] 
[194] 
[195]     ngx_queue_init(&cycle->reusable_connections_queue);
[196] 
[197] 
[198]     cycle->conf_ctx = ngx_pcalloc(pool, ngx_max_module * sizeof(void *));
[199]     if (cycle->conf_ctx == NULL) {
[200]         ngx_destroy_pool(pool);
[201]         return NULL;
[202]     }
[203] 
[204] 
[205]     if (gethostname(hostname, NGX_MAXHOSTNAMELEN) == -1) {
[206]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "gethostname() failed");
[207]         ngx_destroy_pool(pool);
[208]         return NULL;
[209]     }
[210] 
[211]     /* on Linux gethostname() silently truncates name that does not fit */
[212] 
[213]     hostname[NGX_MAXHOSTNAMELEN - 1] = '\0';
[214]     cycle->hostname.len = ngx_strlen(hostname);
[215] 
[216]     cycle->hostname.data = ngx_pnalloc(pool, cycle->hostname.len);
[217]     if (cycle->hostname.data == NULL) {
[218]         ngx_destroy_pool(pool);
[219]         return NULL;
[220]     }
[221] 
[222]     ngx_strlow(cycle->hostname.data, (u_char *) hostname, cycle->hostname.len);
[223] 
[224] 
[225]     if (ngx_cycle_modules(cycle) != NGX_OK) {
[226]         ngx_destroy_pool(pool);
[227]         return NULL;
[228]     }
[229] 
[230] 
[231]     for (i = 0; cycle->modules[i]; i++) {
[232]         if (cycle->modules[i]->type != NGX_CORE_MODULE) {
[233]             continue;
[234]         }
[235] 
[236]         module = cycle->modules[i]->ctx;
[237] 
[238]         if (module->create_conf) {
[239]             rv = module->create_conf(cycle);
[240]             if (rv == NULL) {
[241]                 ngx_destroy_pool(pool);
[242]                 return NULL;
[243]             }
[244]             cycle->conf_ctx[cycle->modules[i]->index] = rv;
[245]         }
[246]     }
[247] 
[248] 
[249]     senv = environ;
[250] 
[251] 
[252]     ngx_memzero(&conf, sizeof(ngx_conf_t));
[253]     /* STUB: init array ? */
[254]     conf.args = ngx_array_create(pool, 10, sizeof(ngx_str_t));
[255]     if (conf.args == NULL) {
[256]         ngx_destroy_pool(pool);
[257]         return NULL;
[258]     }
[259] 
[260]     conf.temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, log);
[261]     if (conf.temp_pool == NULL) {
[262]         ngx_destroy_pool(pool);
[263]         return NULL;
[264]     }
[265] 
[266] 
[267]     conf.ctx = cycle->conf_ctx;
[268]     conf.cycle = cycle;
[269]     conf.pool = pool;
[270]     conf.log = log;
[271]     conf.module_type = NGX_CORE_MODULE;
[272]     conf.cmd_type = NGX_MAIN_CONF;
[273] 
[274] #if 0
[275]     log->log_level = NGX_LOG_DEBUG_ALL;
[276] #endif
[277] 
[278]     if (ngx_conf_param(&conf) != NGX_CONF_OK) {
[279]         environ = senv;
[280]         ngx_destroy_cycle_pools(&conf);
[281]         return NULL;
[282]     }
[283] 
[284]     if (ngx_conf_parse(&conf, &cycle->conf_file) != NGX_CONF_OK) {
[285]         environ = senv;
[286]         ngx_destroy_cycle_pools(&conf);
[287]         return NULL;
[288]     }
[289] 
[290]     if (ngx_test_config && !ngx_quiet_mode) {
[291]         ngx_log_stderr(0, "the configuration file %s syntax is ok",
[292]                        cycle->conf_file.data);
[293]     }
[294] 
[295]     for (i = 0; cycle->modules[i]; i++) {
[296]         if (cycle->modules[i]->type != NGX_CORE_MODULE) {
[297]             continue;
[298]         }
[299] 
[300]         module = cycle->modules[i]->ctx;
[301] 
[302]         if (module->init_conf) {
[303]             if (module->init_conf(cycle,
[304]                                   cycle->conf_ctx[cycle->modules[i]->index])
[305]                 == NGX_CONF_ERROR)
[306]             {
[307]                 environ = senv;
[308]                 ngx_destroy_cycle_pools(&conf);
[309]                 return NULL;
[310]             }
[311]         }
[312]     }
[313] 
[314]     if (ngx_process == NGX_PROCESS_SIGNALLER) {
[315]         return cycle;
[316]     }
[317] 
[318]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[319] 
[320]     if (ngx_test_config) {
[321] 
[322]         if (ngx_create_pidfile(&ccf->pid, log) != NGX_OK) {
[323]             goto failed;
[324]         }
[325] 
[326]     } else if (!ngx_is_init_cycle(old_cycle)) {
[327] 
[328]         /*
[329]          * we do not create the pid file in the first ngx_init_cycle() call
[330]          * because we need to write the demonized process pid
[331]          */
[332] 
[333]         old_ccf = (ngx_core_conf_t *) ngx_get_conf(old_cycle->conf_ctx,
[334]                                                    ngx_core_module);
[335]         if (ccf->pid.len != old_ccf->pid.len
[336]             || ngx_strcmp(ccf->pid.data, old_ccf->pid.data) != 0)
[337]         {
[338]             /* new pid file name */
[339] 
[340]             if (ngx_create_pidfile(&ccf->pid, log) != NGX_OK) {
[341]                 goto failed;
[342]             }
[343] 
[344]             ngx_delete_pidfile(old_cycle);
[345]         }
[346]     }
[347] 
[348] 
[349]     if (ngx_test_lockfile(cycle->lock_file.data, log) != NGX_OK) {
[350]         goto failed;
[351]     }
[352] 
[353] 
[354]     if (ngx_create_paths(cycle, ccf->user) != NGX_OK) {
[355]         goto failed;
[356]     }
[357] 
[358] 
[359]     if (ngx_log_open_default(cycle) != NGX_OK) {
[360]         goto failed;
[361]     }
[362] 
[363]     /* open the new files */
[364] 
[365]     part = &cycle->open_files.part;
[366]     file = part->elts;
[367] 
[368]     for (i = 0; /* void */ ; i++) {
[369] 
[370]         if (i >= part->nelts) {
[371]             if (part->next == NULL) {
[372]                 break;
[373]             }
[374]             part = part->next;
[375]             file = part->elts;
[376]             i = 0;
[377]         }
[378] 
[379]         if (file[i].name.len == 0) {
[380]             continue;
[381]         }
[382] 
[383]         file[i].fd = ngx_open_file(file[i].name.data,
[384]                                    NGX_FILE_APPEND,
[385]                                    NGX_FILE_CREATE_OR_OPEN,
[386]                                    NGX_FILE_DEFAULT_ACCESS);
[387] 
[388]         ngx_log_debug3(NGX_LOG_DEBUG_CORE, log, 0,
[389]                        "log: %p %d \"%s\"",
[390]                        &file[i], file[i].fd, file[i].name.data);
[391] 
[392]         if (file[i].fd == NGX_INVALID_FILE) {
[393]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[394]                           ngx_open_file_n " \"%s\" failed",
[395]                           file[i].name.data);
[396]             goto failed;
[397]         }
[398] 
[399] #if !(NGX_WIN32)
[400]         if (fcntl(file[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
[401]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[402]                           "fcntl(FD_CLOEXEC) \"%s\" failed",
[403]                           file[i].name.data);
[404]             goto failed;
[405]         }
[406] #endif
[407]     }
[408] 
[409]     cycle->log = &cycle->new_log;
[410]     pool->log = &cycle->new_log;
[411] 
[412] 
[413]     /* create shared memory */
[414] 
[415]     part = &cycle->shared_memory.part;
[416]     shm_zone = part->elts;
[417] 
[418]     for (i = 0; /* void */ ; i++) {
[419] 
[420]         if (i >= part->nelts) {
[421]             if (part->next == NULL) {
[422]                 break;
[423]             }
[424]             part = part->next;
[425]             shm_zone = part->elts;
[426]             i = 0;
[427]         }
[428] 
[429]         if (shm_zone[i].shm.size == 0) {
[430]             ngx_log_error(NGX_LOG_EMERG, log, 0,
[431]                           "zero size shared memory zone \"%V\"",
[432]                           &shm_zone[i].shm.name);
[433]             goto failed;
[434]         }
[435] 
[436]         shm_zone[i].shm.log = cycle->log;
[437] 
[438]         opart = &old_cycle->shared_memory.part;
[439]         oshm_zone = opart->elts;
[440] 
[441]         for (n = 0; /* void */ ; n++) {
[442] 
[443]             if (n >= opart->nelts) {
[444]                 if (opart->next == NULL) {
[445]                     break;
[446]                 }
[447]                 opart = opart->next;
[448]                 oshm_zone = opart->elts;
[449]                 n = 0;
[450]             }
[451] 
[452]             if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
[453]                 continue;
[454]             }
[455] 
[456]             if (ngx_strncmp(shm_zone[i].shm.name.data,
[457]                             oshm_zone[n].shm.name.data,
[458]                             shm_zone[i].shm.name.len)
[459]                 != 0)
[460]             {
[461]                 continue;
[462]             }
[463] 
[464]             if (shm_zone[i].tag == oshm_zone[n].tag
[465]                 && shm_zone[i].shm.size == oshm_zone[n].shm.size
[466]                 && !shm_zone[i].noreuse)
[467]             {
[468]                 shm_zone[i].shm.addr = oshm_zone[n].shm.addr;
[469] #if (NGX_WIN32)
[470]                 shm_zone[i].shm.handle = oshm_zone[n].shm.handle;
[471] #endif
[472] 
[473]                 if (shm_zone[i].init(&shm_zone[i], oshm_zone[n].data)
[474]                     != NGX_OK)
[475]                 {
[476]                     goto failed;
[477]                 }
[478] 
[479]                 goto shm_zone_found;
[480]             }
[481] 
[482]             break;
[483]         }
[484] 
[485]         if (ngx_shm_alloc(&shm_zone[i].shm) != NGX_OK) {
[486]             goto failed;
[487]         }
[488] 
[489]         if (ngx_init_zone_pool(cycle, &shm_zone[i]) != NGX_OK) {
[490]             goto failed;
[491]         }
[492] 
[493]         if (shm_zone[i].init(&shm_zone[i], NULL) != NGX_OK) {
[494]             goto failed;
[495]         }
[496] 
[497]     shm_zone_found:
[498] 
[499]         continue;
[500]     }
[501] 
[502] 
[503]     /* handle the listening sockets */
[504] 
[505]     if (old_cycle->listening.nelts) {
[506]         ls = old_cycle->listening.elts;
[507]         for (i = 0; i < old_cycle->listening.nelts; i++) {
[508]             ls[i].remain = 0;
[509]         }
[510] 
[511]         nls = cycle->listening.elts;
[512]         for (n = 0; n < cycle->listening.nelts; n++) {
[513] 
[514]             for (i = 0; i < old_cycle->listening.nelts; i++) {
[515]                 if (ls[i].ignore) {
[516]                     continue;
[517]                 }
[518] 
[519]                 if (ls[i].remain) {
[520]                     continue;
[521]                 }
[522] 
[523]                 if (ls[i].type != nls[n].type) {
[524]                     continue;
[525]                 }
[526] 
[527]                 if (ngx_cmp_sockaddr(nls[n].sockaddr, nls[n].socklen,
[528]                                      ls[i].sockaddr, ls[i].socklen, 1)
[529]                     == NGX_OK)
[530]                 {
[531]                     nls[n].fd = ls[i].fd;
[532]                     nls[n].inherited = ls[i].inherited;
[533]                     nls[n].previous = &ls[i];
[534]                     ls[i].remain = 1;
[535] 
[536]                     if (ls[i].backlog != nls[n].backlog) {
[537]                         nls[n].listen = 1;
[538]                     }
[539] 
[540] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[541] 
[542]                     /*
[543]                      * FreeBSD, except the most recent versions,
[544]                      * could not remove accept filter
[545]                      */
[546]                     nls[n].deferred_accept = ls[i].deferred_accept;
[547] 
[548]                     if (ls[i].accept_filter && nls[n].accept_filter) {
[549]                         if (ngx_strcmp(ls[i].accept_filter,
[550]                                        nls[n].accept_filter)
[551]                             != 0)
[552]                         {
[553]                             nls[n].delete_deferred = 1;
[554]                             nls[n].add_deferred = 1;
[555]                         }
[556] 
[557]                     } else if (ls[i].accept_filter) {
[558]                         nls[n].delete_deferred = 1;
[559] 
[560]                     } else if (nls[n].accept_filter) {
[561]                         nls[n].add_deferred = 1;
[562]                     }
[563] #endif
[564] 
[565] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[566] 
[567]                     if (ls[i].deferred_accept && !nls[n].deferred_accept) {
[568]                         nls[n].delete_deferred = 1;
[569] 
[570]                     } else if (ls[i].deferred_accept != nls[n].deferred_accept)
[571]                     {
[572]                         nls[n].add_deferred = 1;
[573]                     }
[574] #endif
[575] 
[576] #if (NGX_HAVE_REUSEPORT)
[577]                     if (nls[n].reuseport && !ls[i].reuseport) {
[578]                         nls[n].add_reuseport = 1;
[579]                     }
[580] #endif
[581] 
[582]                     break;
[583]                 }
[584]             }
[585] 
[586]             if (nls[n].fd == (ngx_socket_t) -1) {
[587]                 nls[n].open = 1;
[588] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[589]                 if (nls[n].accept_filter) {
[590]                     nls[n].add_deferred = 1;
[591]                 }
[592] #endif
[593] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[594]                 if (nls[n].deferred_accept) {
[595]                     nls[n].add_deferred = 1;
[596]                 }
[597] #endif
[598]             }
[599]         }
[600] 
[601]     } else {
[602]         ls = cycle->listening.elts;
[603]         for (i = 0; i < cycle->listening.nelts; i++) {
[604]             ls[i].open = 1;
[605] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[606]             if (ls[i].accept_filter) {
[607]                 ls[i].add_deferred = 1;
[608]             }
[609] #endif
[610] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[611]             if (ls[i].deferred_accept) {
[612]                 ls[i].add_deferred = 1;
[613]             }
[614] #endif
[615]         }
[616]     }
[617] 
[618]     if (ngx_open_listening_sockets(cycle) != NGX_OK) {
[619]         goto failed;
[620]     }
[621] 
[622]     if (!ngx_test_config) {
[623]         ngx_configure_listening_sockets(cycle);
[624]     }
[625] 
[626] 
[627]     /* commit the new cycle configuration */
[628] 
[629]     if (!ngx_use_stderr) {
[630]         (void) ngx_log_redirect_stderr(cycle);
[631]     }
[632] 
[633]     pool->log = cycle->log;
[634] 
[635]     if (ngx_init_modules(cycle) != NGX_OK) {
[636]         /* fatal */
[637]         exit(1);
[638]     }
[639] 
[640] 
[641]     /* close and delete stuff that lefts from an old cycle */
[642] 
[643]     /* free the unnecessary shared memory */
[644] 
[645]     opart = &old_cycle->shared_memory.part;
[646]     oshm_zone = opart->elts;
[647] 
[648]     for (i = 0; /* void */ ; i++) {
[649] 
[650]         if (i >= opart->nelts) {
[651]             if (opart->next == NULL) {
[652]                 goto old_shm_zone_done;
[653]             }
[654]             opart = opart->next;
[655]             oshm_zone = opart->elts;
[656]             i = 0;
[657]         }
[658] 
[659]         part = &cycle->shared_memory.part;
[660]         shm_zone = part->elts;
[661] 
[662]         for (n = 0; /* void */ ; n++) {
[663] 
[664]             if (n >= part->nelts) {
[665]                 if (part->next == NULL) {
[666]                     break;
[667]                 }
[668]                 part = part->next;
[669]                 shm_zone = part->elts;
[670]                 n = 0;
[671]             }
[672] 
[673]             if (oshm_zone[i].shm.name.len != shm_zone[n].shm.name.len) {
[674]                 continue;
[675]             }
[676] 
[677]             if (ngx_strncmp(oshm_zone[i].shm.name.data,
[678]                             shm_zone[n].shm.name.data,
[679]                             oshm_zone[i].shm.name.len)
[680]                 != 0)
[681]             {
[682]                 continue;
[683]             }
[684] 
[685]             if (oshm_zone[i].tag == shm_zone[n].tag
[686]                 && oshm_zone[i].shm.size == shm_zone[n].shm.size
[687]                 && !oshm_zone[i].noreuse)
[688]             {
[689]                 goto live_shm_zone;
[690]             }
[691] 
[692]             break;
[693]         }
[694] 
[695]         ngx_shm_free(&oshm_zone[i].shm);
[696] 
[697]     live_shm_zone:
[698] 
[699]         continue;
[700]     }
[701] 
[702] old_shm_zone_done:
[703] 
[704] 
[705]     /* close the unnecessary listening sockets */
[706] 
[707]     ls = old_cycle->listening.elts;
[708]     for (i = 0; i < old_cycle->listening.nelts; i++) {
[709] 
[710]         if (ls[i].remain || ls[i].fd == (ngx_socket_t) -1) {
[711]             continue;
[712]         }
[713] 
[714]         if (ngx_close_socket(ls[i].fd) == -1) {
[715]             ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[716]                           ngx_close_socket_n " listening socket on %V failed",
[717]                           &ls[i].addr_text);
[718]         }
[719] 
[720] #if (NGX_HAVE_UNIX_DOMAIN)
[721] 
[722]         if (ls[i].sockaddr->sa_family == AF_UNIX) {
[723]             u_char  *name;
[724] 
[725]             name = ls[i].addr_text.data + sizeof("unix:") - 1;
[726] 
[727]             ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
[728]                           "deleting socket %s", name);
[729] 
[730]             if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[731]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
[732]                               ngx_delete_file_n " %s failed", name);
[733]             }
[734]         }
[735] 
[736] #endif
[737]     }
[738] 
[739] 
[740]     /* close the unnecessary open files */
[741] 
[742]     part = &old_cycle->open_files.part;
[743]     file = part->elts;
[744] 
[745]     for (i = 0; /* void */ ; i++) {
[746] 
[747]         if (i >= part->nelts) {
[748]             if (part->next == NULL) {
[749]                 break;
[750]             }
[751]             part = part->next;
[752]             file = part->elts;
[753]             i = 0;
[754]         }
[755] 
[756]         if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr) {
[757]             continue;
[758]         }
[759] 
[760]         if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
[761]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[762]                           ngx_close_file_n " \"%s\" failed",
[763]                           file[i].name.data);
[764]         }
[765]     }
[766] 
[767]     ngx_destroy_pool(conf.temp_pool);
[768] 
[769]     if (ngx_process == NGX_PROCESS_MASTER || ngx_is_init_cycle(old_cycle)) {
[770] 
[771]         ngx_destroy_pool(old_cycle->pool);
[772]         cycle->old_cycle = NULL;
[773] 
[774]         return cycle;
[775]     }
[776] 
[777] 
[778]     if (ngx_temp_pool == NULL) {
[779]         ngx_temp_pool = ngx_create_pool(128, cycle->log);
[780]         if (ngx_temp_pool == NULL) {
[781]             ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[782]                           "could not create ngx_temp_pool");
[783]             exit(1);
[784]         }
[785] 
[786]         n = 10;
[787] 
[788]         if (ngx_array_init(&ngx_old_cycles, ngx_temp_pool, n,
[789]                            sizeof(ngx_cycle_t *))
[790]             != NGX_OK)
[791]         {
[792]             exit(1);
[793]         }
[794] 
[795]         ngx_memzero(ngx_old_cycles.elts, n * sizeof(ngx_cycle_t *));
[796] 
[797]         ngx_cleaner_event.handler = ngx_clean_old_cycles;
[798]         ngx_cleaner_event.log = cycle->log;
[799]         ngx_cleaner_event.data = &dumb;
[800]         dumb.fd = (ngx_socket_t) -1;
[801]     }
[802] 
[803]     ngx_temp_pool->log = cycle->log;
[804] 
[805]     old = ngx_array_push(&ngx_old_cycles);
[806]     if (old == NULL) {
[807]         exit(1);
[808]     }
[809]     *old = old_cycle;
[810] 
[811]     if (!ngx_cleaner_event.timer_set) {
[812]         ngx_add_timer(&ngx_cleaner_event, 30000);
[813]         ngx_cleaner_event.timer_set = 1;
[814]     }
[815] 
[816]     return cycle;
[817] 
[818] 
[819] failed:
[820] 
[821]     if (!ngx_is_init_cycle(old_cycle)) {
[822]         old_ccf = (ngx_core_conf_t *) ngx_get_conf(old_cycle->conf_ctx,
[823]                                                    ngx_core_module);
[824]         if (old_ccf->environment) {
[825]             environ = old_ccf->environment;
[826]         }
[827]     }
[828] 
[829]     /* rollback the new cycle configuration */
[830] 
[831]     part = &cycle->open_files.part;
[832]     file = part->elts;
[833] 
[834]     for (i = 0; /* void */ ; i++) {
[835] 
[836]         if (i >= part->nelts) {
[837]             if (part->next == NULL) {
[838]                 break;
[839]             }
[840]             part = part->next;
[841]             file = part->elts;
[842]             i = 0;
[843]         }
[844] 
[845]         if (file[i].fd == NGX_INVALID_FILE || file[i].fd == ngx_stderr) {
[846]             continue;
[847]         }
[848] 
[849]         if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
[850]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[851]                           ngx_close_file_n " \"%s\" failed",
[852]                           file[i].name.data);
[853]         }
[854]     }
[855] 
[856]     /* free the newly created shared memory */
[857] 
[858]     part = &cycle->shared_memory.part;
[859]     shm_zone = part->elts;
[860] 
[861]     for (i = 0; /* void */ ; i++) {
[862] 
[863]         if (i >= part->nelts) {
[864]             if (part->next == NULL) {
[865]                 break;
[866]             }
[867]             part = part->next;
[868]             shm_zone = part->elts;
[869]             i = 0;
[870]         }
[871] 
[872]         if (shm_zone[i].shm.addr == NULL) {
[873]             continue;
[874]         }
[875] 
[876]         opart = &old_cycle->shared_memory.part;
[877]         oshm_zone = opart->elts;
[878] 
[879]         for (n = 0; /* void */ ; n++) {
[880] 
[881]             if (n >= opart->nelts) {
[882]                 if (opart->next == NULL) {
[883]                     break;
[884]                 }
[885]                 opart = opart->next;
[886]                 oshm_zone = opart->elts;
[887]                 n = 0;
[888]             }
[889] 
[890]             if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
[891]                 continue;
[892]             }
[893] 
[894]             if (ngx_strncmp(shm_zone[i].shm.name.data,
[895]                             oshm_zone[n].shm.name.data,
[896]                             shm_zone[i].shm.name.len)
[897]                 != 0)
[898]             {
[899]                 continue;
[900]             }
[901] 
[902]             if (shm_zone[i].tag == oshm_zone[n].tag
[903]                 && shm_zone[i].shm.size == oshm_zone[n].shm.size
[904]                 && !shm_zone[i].noreuse)
[905]             {
[906]                 goto old_shm_zone_found;
[907]             }
[908] 
[909]             break;
[910]         }
[911] 
[912]         ngx_shm_free(&shm_zone[i].shm);
[913] 
[914]     old_shm_zone_found:
[915] 
[916]         continue;
[917]     }
[918] 
[919]     if (ngx_test_config) {
[920]         ngx_destroy_cycle_pools(&conf);
[921]         return NULL;
[922]     }
[923] 
[924]     ls = cycle->listening.elts;
[925]     for (i = 0; i < cycle->listening.nelts; i++) {
[926]         if (ls[i].fd == (ngx_socket_t) -1 || !ls[i].open) {
[927]             continue;
[928]         }
[929] 
[930]         if (ngx_close_socket(ls[i].fd) == -1) {
[931]             ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[932]                           ngx_close_socket_n " %V failed",
[933]                           &ls[i].addr_text);
[934]         }
[935]     }
[936] 
[937]     ngx_destroy_cycle_pools(&conf);
[938] 
[939]     return NULL;
[940] }
[941] 
[942] 
[943] static void
[944] ngx_destroy_cycle_pools(ngx_conf_t *conf)
[945] {
[946]     ngx_destroy_pool(conf->temp_pool);
[947]     ngx_destroy_pool(conf->pool);
[948] }
[949] 
[950] 
[951] static ngx_int_t
[952] ngx_init_zone_pool(ngx_cycle_t *cycle, ngx_shm_zone_t *zn)
[953] {
[954]     u_char           *file;
[955]     ngx_slab_pool_t  *sp;
[956] 
[957]     sp = (ngx_slab_pool_t *) zn->shm.addr;
[958] 
[959]     if (zn->shm.exists) {
[960] 
[961]         if (sp == sp->addr) {
[962]             return NGX_OK;
[963]         }
[964] 
[965] #if (NGX_WIN32)
[966] 
[967]         /* remap at the required address */
[968] 
[969]         if (ngx_shm_remap(&zn->shm, sp->addr) != NGX_OK) {
[970]             return NGX_ERROR;
[971]         }
[972] 
[973]         sp = (ngx_slab_pool_t *) zn->shm.addr;
[974] 
[975]         if (sp == sp->addr) {
[976]             return NGX_OK;
[977]         }
[978] 
[979] #endif
[980] 
[981]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[982]                       "shared zone \"%V\" has no equal addresses: %p vs %p",
[983]                       &zn->shm.name, sp->addr, sp);
[984]         return NGX_ERROR;
[985]     }
[986] 
[987]     sp->end = zn->shm.addr + zn->shm.size;
[988]     sp->min_shift = 3;
[989]     sp->addr = zn->shm.addr;
[990] 
[991] #if (NGX_HAVE_ATOMIC_OPS)
[992] 
[993]     file = NULL;
[994] 
[995] #else
[996] 
[997]     file = ngx_pnalloc(cycle->pool,
[998]                        cycle->lock_file.len + zn->shm.name.len + 1);
[999]     if (file == NULL) {
[1000]         return NGX_ERROR;
[1001]     }
[1002] 
[1003]     (void) ngx_sprintf(file, "%V%V%Z", &cycle->lock_file, &zn->shm.name);
[1004] 
[1005] #endif
[1006] 
[1007]     if (ngx_shmtx_create(&sp->mutex, &sp->lock, file) != NGX_OK) {
[1008]         return NGX_ERROR;
[1009]     }
[1010] 
[1011]     ngx_slab_init(sp);
[1012] 
[1013]     return NGX_OK;
[1014] }
[1015] 
[1016] 
[1017] ngx_int_t
[1018] ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log)
[1019] {
[1020]     size_t      len;
[1021]     ngx_int_t   rc;
[1022]     ngx_uint_t  create;
[1023]     ngx_file_t  file;
[1024]     u_char      pid[NGX_INT64_LEN + 2];
[1025] 
[1026]     if (ngx_process > NGX_PROCESS_MASTER) {
[1027]         return NGX_OK;
[1028]     }
[1029] 
[1030]     ngx_memzero(&file, sizeof(ngx_file_t));
[1031] 
[1032]     file.name = *name;
[1033]     file.log = log;
[1034] 
[1035]     create = ngx_test_config ? NGX_FILE_CREATE_OR_OPEN : NGX_FILE_TRUNCATE;
[1036] 
[1037]     file.fd = ngx_open_file(file.name.data, NGX_FILE_RDWR,
[1038]                             create, NGX_FILE_DEFAULT_ACCESS);
[1039] 
[1040]     if (file.fd == NGX_INVALID_FILE) {
[1041]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[1042]                       ngx_open_file_n " \"%s\" failed", file.name.data);
[1043]         return NGX_ERROR;
[1044]     }
[1045] 
[1046]     rc = NGX_OK;
[1047] 
[1048]     if (!ngx_test_config) {
[1049]         len = ngx_snprintf(pid, NGX_INT64_LEN + 2, "%P%N", ngx_pid) - pid;
[1050] 
[1051]         if (ngx_write_file(&file, pid, len, 0) == NGX_ERROR) {
[1052]             rc = NGX_ERROR;
[1053]         }
[1054]     }
[1055] 
[1056]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[1057]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[1058]                       ngx_close_file_n " \"%s\" failed", file.name.data);
[1059]     }
[1060] 
[1061]     return rc;
[1062] }
[1063] 
[1064] 
[1065] void
[1066] ngx_delete_pidfile(ngx_cycle_t *cycle)
[1067] {
[1068]     u_char           *name;
[1069]     ngx_core_conf_t  *ccf;
[1070] 
[1071]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[1072] 
[1073]     name = ngx_new_binary ? ccf->oldpid.data : ccf->pid.data;
[1074] 
[1075]     if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[1076]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[1077]                       ngx_delete_file_n " \"%s\" failed", name);
[1078]     }
[1079] }
[1080] 
[1081] 
[1082] ngx_int_t
[1083] ngx_signal_process(ngx_cycle_t *cycle, char *sig)
[1084] {
[1085]     ssize_t           n;
[1086]     ngx_pid_t         pid;
[1087]     ngx_file_t        file;
[1088]     ngx_core_conf_t  *ccf;
[1089]     u_char            buf[NGX_INT64_LEN + 2];
[1090] 
[1091]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "signal process started");
[1092] 
[1093]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[1094] 
[1095]     ngx_memzero(&file, sizeof(ngx_file_t));
[1096] 
[1097]     file.name = ccf->pid;
[1098]     file.log = cycle->log;
[1099] 
[1100]     file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
[1101]                             NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
[1102] 
[1103]     if (file.fd == NGX_INVALID_FILE) {
[1104]         ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
[1105]                       ngx_open_file_n " \"%s\" failed", file.name.data);
[1106]         return 1;
[1107]     }
[1108] 
[1109]     n = ngx_read_file(&file, buf, NGX_INT64_LEN + 2, 0);
[1110] 
[1111]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[1112]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[1113]                       ngx_close_file_n " \"%s\" failed", file.name.data);
[1114]     }
[1115] 
[1116]     if (n == NGX_ERROR) {
[1117]         return 1;
[1118]     }
[1119] 
[1120]     while (n-- && (buf[n] == CR || buf[n] == LF)) { /* void */ }
[1121] 
[1122]     pid = ngx_atoi(buf, ++n);
[1123] 
[1124]     if (pid == (ngx_pid_t) NGX_ERROR) {
[1125]         ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
[1126]                       "invalid PID number \"%*s\" in \"%s\"",
[1127]                       n, buf, file.name.data);
[1128]         return 1;
[1129]     }
[1130] 
[1131]     return ngx_os_signal_process(cycle, sig, pid);
[1132] 
[1133] }
[1134] 
[1135] 
[1136] static ngx_int_t
[1137] ngx_test_lockfile(u_char *file, ngx_log_t *log)
[1138] {
[1139] #if !(NGX_HAVE_ATOMIC_OPS)
[1140]     ngx_fd_t  fd;
[1141] 
[1142]     fd = ngx_open_file(file, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
[1143]                        NGX_FILE_DEFAULT_ACCESS);
[1144] 
[1145]     if (fd == NGX_INVALID_FILE) {
[1146]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[1147]                       ngx_open_file_n " \"%s\" failed", file);
[1148]         return NGX_ERROR;
[1149]     }
[1150] 
[1151]     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[1152]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[1153]                       ngx_close_file_n " \"%s\" failed", file);
[1154]     }
[1155] 
[1156]     if (ngx_delete_file(file) == NGX_FILE_ERROR) {
[1157]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[1158]                       ngx_delete_file_n " \"%s\" failed", file);
[1159]     }
[1160] 
[1161] #endif
[1162] 
[1163]     return NGX_OK;
[1164] }
[1165] 
[1166] 
[1167] void
[1168] ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user)
[1169] {
[1170]     ngx_fd_t          fd;
[1171]     ngx_uint_t        i;
[1172]     ngx_list_part_t  *part;
[1173]     ngx_open_file_t  *file;
[1174] 
[1175]     part = &cycle->open_files.part;
[1176]     file = part->elts;
[1177] 
[1178]     for (i = 0; /* void */ ; i++) {
[1179] 
[1180]         if (i >= part->nelts) {
[1181]             if (part->next == NULL) {
[1182]                 break;
[1183]             }
[1184]             part = part->next;
[1185]             file = part->elts;
[1186]             i = 0;
[1187]         }
[1188] 
[1189]         if (file[i].name.len == 0) {
[1190]             continue;
[1191]         }
[1192] 
[1193]         if (file[i].flush) {
[1194]             file[i].flush(&file[i], cycle->log);
[1195]         }
[1196] 
[1197]         fd = ngx_open_file(file[i].name.data, NGX_FILE_APPEND,
[1198]                            NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
[1199] 
[1200]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[1201]                        "reopen file \"%s\", old:%d new:%d",
[1202]                        file[i].name.data, file[i].fd, fd);
[1203] 
[1204]         if (fd == NGX_INVALID_FILE) {
[1205]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1206]                           ngx_open_file_n " \"%s\" failed", file[i].name.data);
[1207]             continue;
[1208]         }
[1209] 
[1210] #if !(NGX_WIN32)
[1211]         if (user != (ngx_uid_t) NGX_CONF_UNSET_UINT) {
[1212]             ngx_file_info_t  fi;
[1213] 
[1214]             if (ngx_file_info(file[i].name.data, &fi) == NGX_FILE_ERROR) {
[1215]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1216]                               ngx_file_info_n " \"%s\" failed",
[1217]                               file[i].name.data);
[1218] 
[1219]                 if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[1220]                     ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1221]                                   ngx_close_file_n " \"%s\" failed",
[1222]                                   file[i].name.data);
[1223]                 }
[1224] 
[1225]                 continue;
[1226]             }
[1227] 
[1228]             if (fi.st_uid != user) {
[1229]                 if (chown((const char *) file[i].name.data, user, -1) == -1) {
[1230]                     ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1231]                                   "chown(\"%s\", %d) failed",
[1232]                                   file[i].name.data, user);
[1233] 
[1234]                     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[1235]                         ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1236]                                       ngx_close_file_n " \"%s\" failed",
[1237]                                       file[i].name.data);
[1238]                     }
[1239] 
[1240]                     continue;
[1241]                 }
[1242]             }
[1243] 
[1244]             if ((fi.st_mode & (S_IRUSR|S_IWUSR)) != (S_IRUSR|S_IWUSR)) {
[1245] 
[1246]                 fi.st_mode |= (S_IRUSR|S_IWUSR);
[1247] 
[1248]                 if (chmod((const char *) file[i].name.data, fi.st_mode) == -1) {
[1249]                     ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1250]                                   "chmod() \"%s\" failed", file[i].name.data);
[1251] 
[1252]                     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[1253]                         ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1254]                                       ngx_close_file_n " \"%s\" failed",
[1255]                                       file[i].name.data);
[1256]                     }
[1257] 
[1258]                     continue;
[1259]                 }
[1260]             }
[1261]         }
[1262] 
[1263]         if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
[1264]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1265]                           "fcntl(FD_CLOEXEC) \"%s\" failed",
[1266]                           file[i].name.data);
[1267] 
[1268]             if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[1269]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1270]                               ngx_close_file_n " \"%s\" failed",
[1271]                               file[i].name.data);
[1272]             }
[1273] 
[1274]             continue;
[1275]         }
[1276] #endif
[1277] 
[1278]         if (ngx_close_file(file[i].fd) == NGX_FILE_ERROR) {
[1279]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1280]                           ngx_close_file_n " \"%s\" failed",
[1281]                           file[i].name.data);
[1282]         }
[1283] 
[1284]         file[i].fd = fd;
[1285]     }
[1286] 
[1287]     (void) ngx_log_redirect_stderr(cycle);
[1288] }
[1289] 
[1290] 
[1291] ngx_shm_zone_t *
[1292] ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size, void *tag)
[1293] {
[1294]     ngx_uint_t        i;
[1295]     ngx_shm_zone_t   *shm_zone;
[1296]     ngx_list_part_t  *part;
[1297] 
[1298]     part = &cf->cycle->shared_memory.part;
[1299]     shm_zone = part->elts;
[1300] 
[1301]     for (i = 0; /* void */ ; i++) {
[1302] 
[1303]         if (i >= part->nelts) {
[1304]             if (part->next == NULL) {
[1305]                 break;
[1306]             }
[1307]             part = part->next;
[1308]             shm_zone = part->elts;
[1309]             i = 0;
[1310]         }
[1311] 
[1312]         if (name->len != shm_zone[i].shm.name.len) {
[1313]             continue;
[1314]         }
[1315] 
[1316]         if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
[1317]             != 0)
[1318]         {
[1319]             continue;
[1320]         }
[1321] 
[1322]         if (tag != shm_zone[i].tag) {
[1323]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1324]                             "the shared memory zone \"%V\" is "
[1325]                             "already declared for a different use",
[1326]                             &shm_zone[i].shm.name);
[1327]             return NULL;
[1328]         }
[1329] 
[1330]         if (shm_zone[i].shm.size == 0) {
[1331]             shm_zone[i].shm.size = size;
[1332]         }
[1333] 
[1334]         if (size && size != shm_zone[i].shm.size) {
[1335]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1336]                             "the size %uz of shared memory zone \"%V\" "
[1337]                             "conflicts with already declared size %uz",
[1338]                             size, &shm_zone[i].shm.name, shm_zone[i].shm.size);
[1339]             return NULL;
[1340]         }
[1341] 
[1342]         return &shm_zone[i];
[1343]     }
[1344] 
[1345]     shm_zone = ngx_list_push(&cf->cycle->shared_memory);
[1346] 
[1347]     if (shm_zone == NULL) {
[1348]         return NULL;
[1349]     }
[1350] 
[1351]     shm_zone->data = NULL;
[1352]     shm_zone->shm.log = cf->cycle->log;
[1353]     shm_zone->shm.addr = NULL;
[1354]     shm_zone->shm.size = size;
[1355]     shm_zone->shm.name = *name;
[1356]     shm_zone->shm.exists = 0;
[1357]     shm_zone->init = NULL;
[1358]     shm_zone->tag = tag;
[1359]     shm_zone->noreuse = 0;
[1360] 
[1361]     return shm_zone;
[1362] }
[1363] 
[1364] 
[1365] static void
[1366] ngx_clean_old_cycles(ngx_event_t *ev)
[1367] {
[1368]     ngx_uint_t     i, n, found, live;
[1369]     ngx_log_t     *log;
[1370]     ngx_cycle_t  **cycle;
[1371] 
[1372]     log = ngx_cycle->log;
[1373]     ngx_temp_pool->log = log;
[1374] 
[1375]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "clean old cycles");
[1376] 
[1377]     live = 0;
[1378] 
[1379]     cycle = ngx_old_cycles.elts;
[1380]     for (i = 0; i < ngx_old_cycles.nelts; i++) {
[1381] 
[1382]         if (cycle[i] == NULL) {
[1383]             continue;
[1384]         }
[1385] 
[1386]         found = 0;
[1387] 
[1388]         for (n = 0; n < cycle[i]->connection_n; n++) {
[1389]             if (cycle[i]->connections[n].fd != (ngx_socket_t) -1) {
[1390]                 found = 1;
[1391] 
[1392]                 ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "live fd:%ui", n);
[1393] 
[1394]                 break;
[1395]             }
[1396]         }
[1397] 
[1398]         if (found) {
[1399]             live = 1;
[1400]             continue;
[1401]         }
[1402] 
[1403]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "clean old cycle: %ui", i);
[1404] 
[1405]         ngx_destroy_pool(cycle[i]->pool);
[1406]         cycle[i] = NULL;
[1407]     }
[1408] 
[1409]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0, "old cycles status: %ui", live);
[1410] 
[1411]     if (live) {
[1412]         ngx_add_timer(ev, 30000);
[1413] 
[1414]     } else {
[1415]         ngx_destroy_pool(ngx_temp_pool);
[1416]         ngx_temp_pool = NULL;
[1417]         ngx_old_cycles.nelts = 0;
[1418]     }
[1419] }
[1420] 
[1421] 
[1422] void
[1423] ngx_set_shutdown_timer(ngx_cycle_t *cycle)
[1424] {
[1425]     ngx_core_conf_t  *ccf;
[1426] 
[1427]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[1428] 
[1429]     if (ccf->shutdown_timeout) {
[1430]         ngx_shutdown_event.handler = ngx_shutdown_timer_handler;
[1431]         ngx_shutdown_event.data = cycle;
[1432]         ngx_shutdown_event.log = cycle->log;
[1433]         ngx_shutdown_event.cancelable = 1;
[1434] 
[1435]         ngx_add_timer(&ngx_shutdown_event, ccf->shutdown_timeout);
[1436]     }
[1437] }
[1438] 
[1439] 
[1440] static void
[1441] ngx_shutdown_timer_handler(ngx_event_t *ev)
[1442] {
[1443]     ngx_uint_t         i;
[1444]     ngx_cycle_t       *cycle;
[1445]     ngx_connection_t  *c;
[1446] 
[1447]     cycle = ev->data;
[1448] 
[1449]     c = cycle->connections;
[1450] 
[1451]     for (i = 0; i < cycle->connection_n; i++) {
[1452] 
[1453]         if (c[i].fd == (ngx_socket_t) -1
[1454]             || c[i].read == NULL
[1455]             || c[i].read->accept
[1456]             || c[i].read->channel
[1457]             || c[i].read->resolver)
[1458]         {
[1459]             continue;
[1460]         }
[1461] 
[1462]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
[1463]                        "*%uA shutdown timeout", c[i].number);
[1464] 
[1465]         c[i].close = 1;
[1466]         c[i].error = 1;
[1467] 
[1468]         c[i].read->handler(c[i].read);
[1469]     }
[1470] }
