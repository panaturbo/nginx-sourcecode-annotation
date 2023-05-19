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
[13] #define DEFAULT_CONNECTIONS  512
[14] 
[15] 
[16] extern ngx_module_t ngx_kqueue_module;
[17] extern ngx_module_t ngx_eventport_module;
[18] extern ngx_module_t ngx_devpoll_module;
[19] extern ngx_module_t ngx_epoll_module;
[20] extern ngx_module_t ngx_select_module;
[21] 
[22] 
[23] static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);
[24] static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);
[25] static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);
[26] static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[27] 
[28] static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
[29]     void *conf);
[30] static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[31] static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
[32]     void *conf);
[33] 
[34] static void *ngx_event_core_create_conf(ngx_cycle_t *cycle);
[35] static char *ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf);
[36] 
[37] 
[38] static ngx_uint_t     ngx_timer_resolution;
[39] sig_atomic_t          ngx_event_timer_alarm;
[40] 
[41] static ngx_uint_t     ngx_event_max_module;
[42] 
[43] ngx_uint_t            ngx_event_flags;
[44] ngx_event_actions_t   ngx_event_actions;
[45] 
[46] 
[47] static ngx_atomic_t   connection_counter = 1;
[48] ngx_atomic_t         *ngx_connection_counter = &connection_counter;
[49] 
[50] 
[51] ngx_atomic_t         *ngx_accept_mutex_ptr;
[52] ngx_shmtx_t           ngx_accept_mutex;
[53] ngx_uint_t            ngx_use_accept_mutex;
[54] ngx_uint_t            ngx_accept_events;
[55] ngx_uint_t            ngx_accept_mutex_held;
[56] ngx_msec_t            ngx_accept_mutex_delay;
[57] ngx_int_t             ngx_accept_disabled;
[58] ngx_uint_t            ngx_use_exclusive_accept;
[59] 
[60] 
[61] #if (NGX_STAT_STUB)
[62] 
[63] static ngx_atomic_t   ngx_stat_accepted0;
[64] ngx_atomic_t         *ngx_stat_accepted = &ngx_stat_accepted0;
[65] static ngx_atomic_t   ngx_stat_handled0;
[66] ngx_atomic_t         *ngx_stat_handled = &ngx_stat_handled0;
[67] static ngx_atomic_t   ngx_stat_requests0;
[68] ngx_atomic_t         *ngx_stat_requests = &ngx_stat_requests0;
[69] static ngx_atomic_t   ngx_stat_active0;
[70] ngx_atomic_t         *ngx_stat_active = &ngx_stat_active0;
[71] static ngx_atomic_t   ngx_stat_reading0;
[72] ngx_atomic_t         *ngx_stat_reading = &ngx_stat_reading0;
[73] static ngx_atomic_t   ngx_stat_writing0;
[74] ngx_atomic_t         *ngx_stat_writing = &ngx_stat_writing0;
[75] static ngx_atomic_t   ngx_stat_waiting0;
[76] ngx_atomic_t         *ngx_stat_waiting = &ngx_stat_waiting0;
[77] 
[78] #endif
[79] 
[80] 
[81] 
[82] static ngx_command_t  ngx_events_commands[] = {
[83] 
[84]     { ngx_string("events"),
[85]       NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[86]       ngx_events_block,
[87]       0,
[88]       0,
[89]       NULL },
[90] 
[91]       ngx_null_command
[92] };
[93] 
[94] 
[95] static ngx_core_module_t  ngx_events_module_ctx = {
[96]     ngx_string("events"),
[97]     NULL,
[98]     ngx_event_init_conf
[99] };
[100] 
[101] 
[102] ngx_module_t  ngx_events_module = {
[103]     NGX_MODULE_V1,
[104]     &ngx_events_module_ctx,                /* module context */
[105]     ngx_events_commands,                   /* module directives */
[106]     NGX_CORE_MODULE,                       /* module type */
[107]     NULL,                                  /* init master */
[108]     NULL,                                  /* init module */
[109]     NULL,                                  /* init process */
[110]     NULL,                                  /* init thread */
[111]     NULL,                                  /* exit thread */
[112]     NULL,                                  /* exit process */
[113]     NULL,                                  /* exit master */
[114]     NGX_MODULE_V1_PADDING
[115] };
[116] 
[117] 
[118] static ngx_str_t  event_core_name = ngx_string("event_core");
[119] 
[120] 
[121] static ngx_command_t  ngx_event_core_commands[] = {
[122] 
[123]     { ngx_string("worker_connections"),
[124]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[125]       ngx_event_connections,
[126]       0,
[127]       0,
[128]       NULL },
[129] 
[130]     { ngx_string("use"),
[131]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[132]       ngx_event_use,
[133]       0,
[134]       0,
[135]       NULL },
[136] 
[137]     { ngx_string("multi_accept"),
[138]       NGX_EVENT_CONF|NGX_CONF_FLAG,
[139]       ngx_conf_set_flag_slot,
[140]       0,
[141]       offsetof(ngx_event_conf_t, multi_accept),
[142]       NULL },
[143] 
[144]     { ngx_string("accept_mutex"),
[145]       NGX_EVENT_CONF|NGX_CONF_FLAG,
[146]       ngx_conf_set_flag_slot,
[147]       0,
[148]       offsetof(ngx_event_conf_t, accept_mutex),
[149]       NULL },
[150] 
[151]     { ngx_string("accept_mutex_delay"),
[152]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[153]       ngx_conf_set_msec_slot,
[154]       0,
[155]       offsetof(ngx_event_conf_t, accept_mutex_delay),
[156]       NULL },
[157] 
[158]     { ngx_string("debug_connection"),
[159]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[160]       ngx_event_debug_connection,
[161]       0,
[162]       0,
[163]       NULL },
[164] 
[165]       ngx_null_command
[166] };
[167] 
[168] 
[169] static ngx_event_module_t  ngx_event_core_module_ctx = {
[170]     &event_core_name,
[171]     ngx_event_core_create_conf,            /* create configuration */
[172]     ngx_event_core_init_conf,              /* init configuration */
[173] 
[174]     { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
[175] };
[176] 
[177] 
[178] ngx_module_t  ngx_event_core_module = {
[179]     NGX_MODULE_V1,
[180]     &ngx_event_core_module_ctx,            /* module context */
[181]     ngx_event_core_commands,               /* module directives */
[182]     NGX_EVENT_MODULE,                      /* module type */
[183]     NULL,                                  /* init master */
[184]     ngx_event_module_init,                 /* init module */
[185]     ngx_event_process_init,                /* init process */
[186]     NULL,                                  /* init thread */
[187]     NULL,                                  /* exit thread */
[188]     NULL,                                  /* exit process */
[189]     NULL,                                  /* exit master */
[190]     NGX_MODULE_V1_PADDING
[191] };
[192] 
[193] 
[194] void
[195] ngx_process_events_and_timers(ngx_cycle_t *cycle)
[196] {
[197]     ngx_uint_t  flags;
[198]     ngx_msec_t  timer, delta;
[199] 
[200]     if (ngx_timer_resolution) {
[201]         timer = NGX_TIMER_INFINITE;
[202]         flags = 0;
[203] 
[204]     } else {
[205]         timer = ngx_event_find_timer();
[206]         flags = NGX_UPDATE_TIME;
[207] 
[208] #if (NGX_WIN32)
[209] 
[210]         /* handle signals from master in case of network inactivity */
[211] 
[212]         if (timer == NGX_TIMER_INFINITE || timer > 500) {
[213]             timer = 500;
[214]         }
[215] 
[216] #endif
[217]     }
[218] 
[219]     if (ngx_use_accept_mutex) {
[220]         if (ngx_accept_disabled > 0) {
[221]             ngx_accept_disabled--;
[222] 
[223]         } else {
[224]             if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
[225]                 return;
[226]             }
[227] 
[228]             if (ngx_accept_mutex_held) {
[229]                 flags |= NGX_POST_EVENTS;
[230] 
[231]             } else {
[232]                 if (timer == NGX_TIMER_INFINITE
[233]                     || timer > ngx_accept_mutex_delay)
[234]                 {
[235]                     timer = ngx_accept_mutex_delay;
[236]                 }
[237]             }
[238]         }
[239]     }
[240] 
[241]     if (!ngx_queue_empty(&ngx_posted_next_events)) {
[242]         ngx_event_move_posted_next(cycle);
[243]         timer = 0;
[244]     }
[245] 
[246]     delta = ngx_current_msec;
[247] 
[248]     (void) ngx_process_events(cycle, timer, flags);
[249] 
[250]     delta = ngx_current_msec - delta;
[251] 
[252]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[253]                    "timer delta: %M", delta);
[254] 
[255]     ngx_event_process_posted(cycle, &ngx_posted_accept_events);
[256] 
[257]     if (ngx_accept_mutex_held) {
[258]         ngx_shmtx_unlock(&ngx_accept_mutex);
[259]     }
[260] 
[261]     ngx_event_expire_timers();
[262] 
[263]     ngx_event_process_posted(cycle, &ngx_posted_events);
[264] }
[265] 
[266] 
[267] ngx_int_t
[268] ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
[269] {
[270]     if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
[271] 
[272]         /* kqueue, epoll */
[273] 
[274]         if (!rev->active && !rev->ready) {
[275]             if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT)
[276]                 == NGX_ERROR)
[277]             {
[278]                 return NGX_ERROR;
[279]             }
[280]         }
[281] 
[282]         return NGX_OK;
[283] 
[284]     } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
[285] 
[286]         /* select, poll, /dev/poll */
[287] 
[288]         if (!rev->active && !rev->ready) {
[289]             if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
[290]                 == NGX_ERROR)
[291]             {
[292]                 return NGX_ERROR;
[293]             }
[294] 
[295]             return NGX_OK;
[296]         }
[297] 
[298]         if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
[299]             if (ngx_del_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT | flags)
[300]                 == NGX_ERROR)
[301]             {
[302]                 return NGX_ERROR;
[303]             }
[304] 
[305]             return NGX_OK;
[306]         }
[307] 
[308]     } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
[309] 
[310]         /* event ports */
[311] 
[312]         if (!rev->active && !rev->ready) {
[313]             if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
[314]                 return NGX_ERROR;
[315]             }
[316] 
[317]             return NGX_OK;
[318]         }
[319] 
[320]         if (rev->oneshot && rev->ready) {
[321]             if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
[322]                 return NGX_ERROR;
[323]             }
[324] 
[325]             return NGX_OK;
[326]         }
[327]     }
[328] 
[329]     /* iocp */
[330] 
[331]     return NGX_OK;
[332] }
[333] 
[334] 
[335] ngx_int_t
[336] ngx_handle_write_event(ngx_event_t *wev, size_t lowat)
[337] {
[338]     ngx_connection_t  *c;
[339] 
[340]     if (lowat) {
[341]         c = wev->data;
[342] 
[343]         if (ngx_send_lowat(c, lowat) == NGX_ERROR) {
[344]             return NGX_ERROR;
[345]         }
[346]     }
[347] 
[348]     if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
[349] 
[350]         /* kqueue, epoll */
[351] 
[352]         if (!wev->active && !wev->ready) {
[353]             if (ngx_add_event(wev, NGX_WRITE_EVENT,
[354]                               NGX_CLEAR_EVENT | (lowat ? NGX_LOWAT_EVENT : 0))
[355]                 == NGX_ERROR)
[356]             {
[357]                 return NGX_ERROR;
[358]             }
[359]         }
[360] 
[361]         return NGX_OK;
[362] 
[363]     } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
[364] 
[365]         /* select, poll, /dev/poll */
[366] 
[367]         if (!wev->active && !wev->ready) {
[368]             if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
[369]                 == NGX_ERROR)
[370]             {
[371]                 return NGX_ERROR;
[372]             }
[373] 
[374]             return NGX_OK;
[375]         }
[376] 
[377]         if (wev->active && wev->ready) {
[378]             if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
[379]                 == NGX_ERROR)
[380]             {
[381]                 return NGX_ERROR;
[382]             }
[383] 
[384]             return NGX_OK;
[385]         }
[386] 
[387]     } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
[388] 
[389]         /* event ports */
[390] 
[391]         if (!wev->active && !wev->ready) {
[392]             if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
[393]                 return NGX_ERROR;
[394]             }
[395] 
[396]             return NGX_OK;
[397]         }
[398] 
[399]         if (wev->oneshot && wev->ready) {
[400]             if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
[401]                 return NGX_ERROR;
[402]             }
[403] 
[404]             return NGX_OK;
[405]         }
[406]     }
[407] 
[408]     /* iocp */
[409] 
[410]     return NGX_OK;
[411] }
[412] 
[413] 
[414] static char *
[415] ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
[416] {
[417] #if (NGX_HAVE_REUSEPORT)
[418]     ngx_uint_t        i;
[419]     ngx_core_conf_t  *ccf;
[420]     ngx_listening_t  *ls;
[421] #endif
[422] 
[423]     if (ngx_get_conf(cycle->conf_ctx, ngx_events_module) == NULL) {
[424]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[425]                       "no \"events\" section in configuration");
[426]         return NGX_CONF_ERROR;
[427]     }
[428] 
[429]     if (cycle->connection_n < cycle->listening.nelts + 1) {
[430] 
[431]         /*
[432]          * there should be at least one connection for each listening
[433]          * socket, plus an additional connection for channel
[434]          */
[435] 
[436]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[437]                       "%ui worker_connections are not enough "
[438]                       "for %ui listening sockets",
[439]                       cycle->connection_n, cycle->listening.nelts);
[440] 
[441]         return NGX_CONF_ERROR;
[442]     }
[443] 
[444] #if (NGX_HAVE_REUSEPORT)
[445] 
[446]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[447] 
[448]     if (!ngx_test_config && ccf->master) {
[449] 
[450]         ls = cycle->listening.elts;
[451]         for (i = 0; i < cycle->listening.nelts; i++) {
[452] 
[453]             if (!ls[i].reuseport || ls[i].worker != 0) {
[454]                 continue;
[455]             }
[456] 
[457]             if (ngx_clone_listening(cycle, &ls[i]) != NGX_OK) {
[458]                 return NGX_CONF_ERROR;
[459]             }
[460] 
[461]             /* cloning may change cycle->listening.elts */
[462] 
[463]             ls = cycle->listening.elts;
[464]         }
[465]     }
[466] 
[467] #endif
[468] 
[469]     return NGX_CONF_OK;
[470] }
[471] 
[472] 
[473] static ngx_int_t
[474] ngx_event_module_init(ngx_cycle_t *cycle)
[475] {
[476]     void              ***cf;
[477]     u_char              *shared;
[478]     size_t               size, cl;
[479]     ngx_shm_t            shm;
[480]     ngx_time_t          *tp;
[481]     ngx_core_conf_t     *ccf;
[482]     ngx_event_conf_t    *ecf;
[483] 
[484]     cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);
[485]     ecf = (*cf)[ngx_event_core_module.ctx_index];
[486] 
[487]     if (!ngx_test_config && ngx_process <= NGX_PROCESS_MASTER) {
[488]         ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
[489]                       "using the \"%s\" event method", ecf->name);
[490]     }
[491] 
[492]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[493] 
[494]     ngx_timer_resolution = ccf->timer_resolution;
[495] 
[496] #if !(NGX_WIN32)
[497]     {
[498]     ngx_int_t      limit;
[499]     struct rlimit  rlmt;
[500] 
[501]     if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
[502]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[503]                       "getrlimit(RLIMIT_NOFILE) failed, ignored");
[504] 
[505]     } else {
[506]         if (ecf->connections > (ngx_uint_t) rlmt.rlim_cur
[507]             && (ccf->rlimit_nofile == NGX_CONF_UNSET
[508]                 || ecf->connections > (ngx_uint_t) ccf->rlimit_nofile))
[509]         {
[510]             limit = (ccf->rlimit_nofile == NGX_CONF_UNSET) ?
[511]                          (ngx_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;
[512] 
[513]             ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
[514]                           "%ui worker_connections exceed "
[515]                           "open file resource limit: %i",
[516]                           ecf->connections, limit);
[517]         }
[518]     }
[519]     }
[520] #endif /* !(NGX_WIN32) */
[521] 
[522] 
[523]     if (ccf->master == 0) {
[524]         return NGX_OK;
[525]     }
[526] 
[527]     if (ngx_accept_mutex_ptr) {
[528]         return NGX_OK;
[529]     }
[530] 
[531] 
[532]     /* cl should be equal to or greater than cache line size */
[533] 
[534]     cl = 128;
[535] 
[536]     size = cl            /* ngx_accept_mutex */
[537]            + cl          /* ngx_connection_counter */
[538]            + cl;         /* ngx_temp_number */
[539] 
[540] #if (NGX_STAT_STUB)
[541] 
[542]     size += cl           /* ngx_stat_accepted */
[543]            + cl          /* ngx_stat_handled */
[544]            + cl          /* ngx_stat_requests */
[545]            + cl          /* ngx_stat_active */
[546]            + cl          /* ngx_stat_reading */
[547]            + cl          /* ngx_stat_writing */
[548]            + cl;         /* ngx_stat_waiting */
[549] 
[550] #endif
[551] 
[552]     shm.size = size;
[553]     ngx_str_set(&shm.name, "nginx_shared_zone");
[554]     shm.log = cycle->log;
[555] 
[556]     if (ngx_shm_alloc(&shm) != NGX_OK) {
[557]         return NGX_ERROR;
[558]     }
[559] 
[560]     shared = shm.addr;
[561] 
[562]     ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;
[563]     ngx_accept_mutex.spin = (ngx_uint_t) -1;
[564] 
[565]     if (ngx_shmtx_create(&ngx_accept_mutex, (ngx_shmtx_sh_t *) shared,
[566]                          cycle->lock_file.data)
[567]         != NGX_OK)
[568]     {
[569]         return NGX_ERROR;
[570]     }
[571] 
[572]     ngx_connection_counter = (ngx_atomic_t *) (shared + 1 * cl);
[573] 
[574]     (void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);
[575] 
[576]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[577]                    "counter: %p, %uA",
[578]                    ngx_connection_counter, *ngx_connection_counter);
[579] 
[580]     ngx_temp_number = (ngx_atomic_t *) (shared + 2 * cl);
[581] 
[582]     tp = ngx_timeofday();
[583] 
[584]     ngx_random_number = (tp->msec << 16) + ngx_pid;
[585] 
[586] #if (NGX_STAT_STUB)
[587] 
[588]     ngx_stat_accepted = (ngx_atomic_t *) (shared + 3 * cl);
[589]     ngx_stat_handled = (ngx_atomic_t *) (shared + 4 * cl);
[590]     ngx_stat_requests = (ngx_atomic_t *) (shared + 5 * cl);
[591]     ngx_stat_active = (ngx_atomic_t *) (shared + 6 * cl);
[592]     ngx_stat_reading = (ngx_atomic_t *) (shared + 7 * cl);
[593]     ngx_stat_writing = (ngx_atomic_t *) (shared + 8 * cl);
[594]     ngx_stat_waiting = (ngx_atomic_t *) (shared + 9 * cl);
[595] 
[596] #endif
[597] 
[598]     return NGX_OK;
[599] }
[600] 
[601] 
[602] #if !(NGX_WIN32)
[603] 
[604] static void
[605] ngx_timer_signal_handler(int signo)
[606] {
[607]     ngx_event_timer_alarm = 1;
[608] 
[609] #if 1
[610]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
[611] #endif
[612] }
[613] 
[614] #endif
[615] 
[616] 
[617] static ngx_int_t
[618] ngx_event_process_init(ngx_cycle_t *cycle)
[619] {
[620]     ngx_uint_t           m, i;
[621]     ngx_event_t         *rev, *wev;
[622]     ngx_listening_t     *ls;
[623]     ngx_connection_t    *c, *next, *old;
[624]     ngx_core_conf_t     *ccf;
[625]     ngx_event_conf_t    *ecf;
[626]     ngx_event_module_t  *module;
[627] 
[628]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[629]     ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
[630] 
[631]     if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
[632]         ngx_use_accept_mutex = 1;
[633]         ngx_accept_mutex_held = 0;
[634]         ngx_accept_mutex_delay = ecf->accept_mutex_delay;
[635] 
[636]     } else {
[637]         ngx_use_accept_mutex = 0;
[638]     }
[639] 
[640] #if (NGX_WIN32)
[641] 
[642]     /*
[643]      * disable accept mutex on win32 as it may cause deadlock if
[644]      * grabbed by a process which can't accept connections
[645]      */
[646] 
[647]     ngx_use_accept_mutex = 0;
[648] 
[649] #endif
[650] 
[651]     ngx_use_exclusive_accept = 0;
[652] 
[653]     ngx_queue_init(&ngx_posted_accept_events);
[654]     ngx_queue_init(&ngx_posted_next_events);
[655]     ngx_queue_init(&ngx_posted_events);
[656] 
[657]     if (ngx_event_timer_init(cycle->log) == NGX_ERROR) {
[658]         return NGX_ERROR;
[659]     }
[660] 
[661]     for (m = 0; cycle->modules[m]; m++) {
[662]         if (cycle->modules[m]->type != NGX_EVENT_MODULE) {
[663]             continue;
[664]         }
[665] 
[666]         if (cycle->modules[m]->ctx_index != ecf->use) {
[667]             continue;
[668]         }
[669] 
[670]         module = cycle->modules[m]->ctx;
[671] 
[672]         if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) {
[673]             /* fatal */
[674]             exit(2);
[675]         }
[676] 
[677]         break;
[678]     }
[679] 
[680] #if !(NGX_WIN32)
[681] 
[682]     if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
[683]         struct sigaction  sa;
[684]         struct itimerval  itv;
[685] 
[686]         ngx_memzero(&sa, sizeof(struct sigaction));
[687]         sa.sa_handler = ngx_timer_signal_handler;
[688]         sigemptyset(&sa.sa_mask);
[689] 
[690]         if (sigaction(SIGALRM, &sa, NULL) == -1) {
[691]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[692]                           "sigaction(SIGALRM) failed");
[693]             return NGX_ERROR;
[694]         }
[695] 
[696]         itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
[697]         itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
[698]         itv.it_value.tv_sec = ngx_timer_resolution / 1000;
[699]         itv.it_value.tv_usec = (ngx_timer_resolution % 1000 ) * 1000;
[700] 
[701]         if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
[702]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[703]                           "setitimer() failed");
[704]         }
[705]     }
[706] 
[707]     if (ngx_event_flags & NGX_USE_FD_EVENT) {
[708]         struct rlimit  rlmt;
[709] 
[710]         if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
[711]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[712]                           "getrlimit(RLIMIT_NOFILE) failed");
[713]             return NGX_ERROR;
[714]         }
[715] 
[716]         cycle->files_n = (ngx_uint_t) rlmt.rlim_cur;
[717] 
[718]         cycle->files = ngx_calloc(sizeof(ngx_connection_t *) * cycle->files_n,
[719]                                   cycle->log);
[720]         if (cycle->files == NULL) {
[721]             return NGX_ERROR;
[722]         }
[723]     }
[724] 
[725] #else
[726] 
[727]     if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
[728]         ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
[729]                       "the \"timer_resolution\" directive is not supported "
[730]                       "with the configured event method, ignored");
[731]         ngx_timer_resolution = 0;
[732]     }
[733] 
[734] #endif
[735] 
[736]     cycle->connections =
[737]         ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
[738]     if (cycle->connections == NULL) {
[739]         return NGX_ERROR;
[740]     }
[741] 
[742]     c = cycle->connections;
[743] 
[744]     cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
[745]                                    cycle->log);
[746]     if (cycle->read_events == NULL) {
[747]         return NGX_ERROR;
[748]     }
[749] 
[750]     rev = cycle->read_events;
[751]     for (i = 0; i < cycle->connection_n; i++) {
[752]         rev[i].closed = 1;
[753]         rev[i].instance = 1;
[754]     }
[755] 
[756]     cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
[757]                                     cycle->log);
[758]     if (cycle->write_events == NULL) {
[759]         return NGX_ERROR;
[760]     }
[761] 
[762]     wev = cycle->write_events;
[763]     for (i = 0; i < cycle->connection_n; i++) {
[764]         wev[i].closed = 1;
[765]     }
[766] 
[767]     i = cycle->connection_n;
[768]     next = NULL;
[769] 
[770]     do {
[771]         i--;
[772] 
[773]         c[i].data = next;
[774]         c[i].read = &cycle->read_events[i];
[775]         c[i].write = &cycle->write_events[i];
[776]         c[i].fd = (ngx_socket_t) -1;
[777] 
[778]         next = &c[i];
[779]     } while (i);
[780] 
[781]     cycle->free_connections = next;
[782]     cycle->free_connection_n = cycle->connection_n;
[783] 
[784]     /* for each listening socket */
[785] 
[786]     ls = cycle->listening.elts;
[787]     for (i = 0; i < cycle->listening.nelts; i++) {
[788] 
[789] #if (NGX_HAVE_REUSEPORT)
[790]         if (ls[i].reuseport && ls[i].worker != ngx_worker) {
[791]             continue;
[792]         }
[793] #endif
[794] 
[795]         c = ngx_get_connection(ls[i].fd, cycle->log);
[796] 
[797]         if (c == NULL) {
[798]             return NGX_ERROR;
[799]         }
[800] 
[801]         c->type = ls[i].type;
[802]         c->log = &ls[i].log;
[803] 
[804]         c->listening = &ls[i];
[805]         ls[i].connection = c;
[806] 
[807]         rev = c->read;
[808] 
[809]         rev->log = c->log;
[810]         rev->accept = 1;
[811] 
[812] #if (NGX_HAVE_DEFERRED_ACCEPT)
[813]         rev->deferred_accept = ls[i].deferred_accept;
[814] #endif
[815] 
[816]         if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)
[817]             && cycle->old_cycle)
[818]         {
[819]             if (ls[i].previous) {
[820] 
[821]                 /*
[822]                  * delete the old accept events that were bound to
[823]                  * the old cycle read events array
[824]                  */
[825] 
[826]                 old = ls[i].previous->connection;
[827] 
[828]                 if (ngx_del_event(old->read, NGX_READ_EVENT, NGX_CLOSE_EVENT)
[829]                     == NGX_ERROR)
[830]                 {
[831]                     return NGX_ERROR;
[832]                 }
[833] 
[834]                 old->fd = (ngx_socket_t) -1;
[835]             }
[836]         }
[837] 
[838] #if (NGX_WIN32)
[839] 
[840]         if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[841]             ngx_iocp_conf_t  *iocpcf;
[842] 
[843]             rev->handler = ngx_event_acceptex;
[844] 
[845]             if (ngx_use_accept_mutex) {
[846]                 continue;
[847]             }
[848] 
[849]             if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
[850]                 return NGX_ERROR;
[851]             }
[852] 
[853]             ls[i].log.handler = ngx_acceptex_log_error;
[854] 
[855]             iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
[856]             if (ngx_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
[857]                 == NGX_ERROR)
[858]             {
[859]                 return NGX_ERROR;
[860]             }
[861] 
[862]         } else {
[863]             rev->handler = ngx_event_accept;
[864] 
[865]             if (ngx_use_accept_mutex) {
[866]                 continue;
[867]             }
[868] 
[869]             if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
[870]                 return NGX_ERROR;
[871]             }
[872]         }
[873] 
[874] #else
[875] 
[876]         rev->handler = (c->type == SOCK_STREAM) ? ngx_event_accept
[877]                                                 : ngx_event_recvmsg;
[878] 
[879] #if (NGX_HAVE_REUSEPORT)
[880] 
[881]         if (ls[i].reuseport) {
[882]             if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
[883]                 return NGX_ERROR;
[884]             }
[885] 
[886]             continue;
[887]         }
[888] 
[889] #endif
[890] 
[891]         if (ngx_use_accept_mutex) {
[892]             continue;
[893]         }
[894] 
[895] #if (NGX_HAVE_EPOLLEXCLUSIVE)
[896] 
[897]         if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
[898]             && ccf->worker_processes > 1)
[899]         {
[900]             ngx_use_exclusive_accept = 1;
[901] 
[902]             if (ngx_add_event(rev, NGX_READ_EVENT, NGX_EXCLUSIVE_EVENT)
[903]                 == NGX_ERROR)
[904]             {
[905]                 return NGX_ERROR;
[906]             }
[907] 
[908]             continue;
[909]         }
[910] 
[911] #endif
[912] 
[913]         if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
[914]             return NGX_ERROR;
[915]         }
[916] 
[917] #endif
[918] 
[919]     }
[920] 
[921]     return NGX_OK;
[922] }
[923] 
[924] 
[925] ngx_int_t
[926] ngx_send_lowat(ngx_connection_t *c, size_t lowat)
[927] {
[928]     int  sndlowat;
[929] 
[930] #if (NGX_HAVE_LOWAT_EVENT)
[931] 
[932]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[933]         c->write->available = lowat;
[934]         return NGX_OK;
[935]     }
[936] 
[937] #endif
[938] 
[939]     if (lowat == 0 || c->sndlowat) {
[940]         return NGX_OK;
[941]     }
[942] 
[943]     sndlowat = (int) lowat;
[944] 
[945]     if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
[946]                    (const void *) &sndlowat, sizeof(int))
[947]         == -1)
[948]     {
[949]         ngx_connection_error(c, ngx_socket_errno,
[950]                              "setsockopt(SO_SNDLOWAT) failed");
[951]         return NGX_ERROR;
[952]     }
[953] 
[954]     c->sndlowat = 1;
[955] 
[956]     return NGX_OK;
[957] }
[958] 
[959] 
[960] static char *
[961] ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[962] {
[963]     char                 *rv;
[964]     void               ***ctx;
[965]     ngx_uint_t            i;
[966]     ngx_conf_t            pcf;
[967]     ngx_event_module_t   *m;
[968] 
[969]     if (*(void **) conf) {
[970]         return "is duplicate";
[971]     }
[972] 
[973]     /* count the number of the event modules and set up their indices */
[974] 
[975]     ngx_event_max_module = ngx_count_modules(cf->cycle, NGX_EVENT_MODULE);
[976] 
[977]     ctx = ngx_pcalloc(cf->pool, sizeof(void *));
[978]     if (ctx == NULL) {
[979]         return NGX_CONF_ERROR;
[980]     }
[981] 
[982]     *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
[983]     if (*ctx == NULL) {
[984]         return NGX_CONF_ERROR;
[985]     }
[986] 
[987]     *(void **) conf = ctx;
[988] 
[989]     for (i = 0; cf->cycle->modules[i]; i++) {
[990]         if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
[991]             continue;
[992]         }
[993] 
[994]         m = cf->cycle->modules[i]->ctx;
[995] 
[996]         if (m->create_conf) {
[997]             (*ctx)[cf->cycle->modules[i]->ctx_index] =
[998]                                                      m->create_conf(cf->cycle);
[999]             if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
[1000]                 return NGX_CONF_ERROR;
[1001]             }
[1002]         }
[1003]     }
[1004] 
[1005]     pcf = *cf;
[1006]     cf->ctx = ctx;
[1007]     cf->module_type = NGX_EVENT_MODULE;
[1008]     cf->cmd_type = NGX_EVENT_CONF;
[1009] 
[1010]     rv = ngx_conf_parse(cf, NULL);
[1011] 
[1012]     *cf = pcf;
[1013] 
[1014]     if (rv != NGX_CONF_OK) {
[1015]         return rv;
[1016]     }
[1017] 
[1018]     for (i = 0; cf->cycle->modules[i]; i++) {
[1019]         if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
[1020]             continue;
[1021]         }
[1022] 
[1023]         m = cf->cycle->modules[i]->ctx;
[1024] 
[1025]         if (m->init_conf) {
[1026]             rv = m->init_conf(cf->cycle,
[1027]                               (*ctx)[cf->cycle->modules[i]->ctx_index]);
[1028]             if (rv != NGX_CONF_OK) {
[1029]                 return rv;
[1030]             }
[1031]         }
[1032]     }
[1033] 
[1034]     return NGX_CONF_OK;
[1035] }
[1036] 
[1037] 
[1038] static char *
[1039] ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1040] {
[1041]     ngx_event_conf_t  *ecf = conf;
[1042] 
[1043]     ngx_str_t  *value;
[1044] 
[1045]     if (ecf->connections != NGX_CONF_UNSET_UINT) {
[1046]         return "is duplicate";
[1047]     }
[1048] 
[1049]     value = cf->args->elts;
[1050]     ecf->connections = ngx_atoi(value[1].data, value[1].len);
[1051]     if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
[1052]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1053]                            "invalid number \"%V\"", &value[1]);
[1054] 
[1055]         return NGX_CONF_ERROR;
[1056]     }
[1057] 
[1058]     cf->cycle->connection_n = ecf->connections;
[1059] 
[1060]     return NGX_CONF_OK;
[1061] }
[1062] 
[1063] 
[1064] static char *
[1065] ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1066] {
[1067]     ngx_event_conf_t  *ecf = conf;
[1068] 
[1069]     ngx_int_t             m;
[1070]     ngx_str_t            *value;
[1071]     ngx_event_conf_t     *old_ecf;
[1072]     ngx_event_module_t   *module;
[1073] 
[1074]     if (ecf->use != NGX_CONF_UNSET_UINT) {
[1075]         return "is duplicate";
[1076]     }
[1077] 
[1078]     value = cf->args->elts;
[1079] 
[1080]     if (cf->cycle->old_cycle->conf_ctx) {
[1081]         old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
[1082]                                      ngx_event_core_module);
[1083]     } else {
[1084]         old_ecf = NULL;
[1085]     }
[1086] 
[1087] 
[1088]     for (m = 0; cf->cycle->modules[m]; m++) {
[1089]         if (cf->cycle->modules[m]->type != NGX_EVENT_MODULE) {
[1090]             continue;
[1091]         }
[1092] 
[1093]         module = cf->cycle->modules[m]->ctx;
[1094]         if (module->name->len == value[1].len) {
[1095]             if (ngx_strcmp(module->name->data, value[1].data) == 0) {
[1096]                 ecf->use = cf->cycle->modules[m]->ctx_index;
[1097]                 ecf->name = module->name->data;
[1098] 
[1099]                 if (ngx_process == NGX_PROCESS_SINGLE
[1100]                     && old_ecf
[1101]                     && old_ecf->use != ecf->use)
[1102]                 {
[1103]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1104]                                "when the server runs without a master process "
[1105]                                "the \"%V\" event type must be the same as "
[1106]                                "in previous configuration - \"%s\" "
[1107]                                "and it cannot be changed on the fly, "
[1108]                                "to change it you need to stop server "
[1109]                                "and start it again",
[1110]                                &value[1], old_ecf->name);
[1111] 
[1112]                     return NGX_CONF_ERROR;
[1113]                 }
[1114] 
[1115]                 return NGX_CONF_OK;
[1116]             }
[1117]         }
[1118]     }
[1119] 
[1120]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1121]                        "invalid event type \"%V\"", &value[1]);
[1122] 
[1123]     return NGX_CONF_ERROR;
[1124] }
[1125] 
[1126] 
[1127] static char *
[1128] ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1129] {
[1130] #if (NGX_DEBUG)
[1131]     ngx_event_conf_t  *ecf = conf;
[1132] 
[1133]     ngx_int_t             rc;
[1134]     ngx_str_t            *value;
[1135]     ngx_url_t             u;
[1136]     ngx_cidr_t            c, *cidr;
[1137]     ngx_uint_t            i;
[1138]     struct sockaddr_in   *sin;
[1139] #if (NGX_HAVE_INET6)
[1140]     struct sockaddr_in6  *sin6;
[1141] #endif
[1142] 
[1143]     value = cf->args->elts;
[1144] 
[1145] #if (NGX_HAVE_UNIX_DOMAIN)
[1146] 
[1147]     if (ngx_strcmp(value[1].data, "unix:") == 0) {
[1148]         cidr = ngx_array_push(&ecf->debug_connection);
[1149]         if (cidr == NULL) {
[1150]             return NGX_CONF_ERROR;
[1151]         }
[1152] 
[1153]         cidr->family = AF_UNIX;
[1154]         return NGX_CONF_OK;
[1155]     }
[1156] 
[1157] #endif
[1158] 
[1159]     rc = ngx_ptocidr(&value[1], &c);
[1160] 
[1161]     if (rc != NGX_ERROR) {
[1162]         if (rc == NGX_DONE) {
[1163]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1164]                                "low address bits of %V are meaningless",
[1165]                                &value[1]);
[1166]         }
[1167] 
[1168]         cidr = ngx_array_push(&ecf->debug_connection);
[1169]         if (cidr == NULL) {
[1170]             return NGX_CONF_ERROR;
[1171]         }
[1172] 
[1173]         *cidr = c;
[1174] 
[1175]         return NGX_CONF_OK;
[1176]     }
[1177] 
[1178]     ngx_memzero(&u, sizeof(ngx_url_t));
[1179]     u.host = value[1];
[1180] 
[1181]     if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
[1182]         if (u.err) {
[1183]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1184]                                "%s in debug_connection \"%V\"",
[1185]                                u.err, &u.host);
[1186]         }
[1187] 
[1188]         return NGX_CONF_ERROR;
[1189]     }
[1190] 
[1191]     cidr = ngx_array_push_n(&ecf->debug_connection, u.naddrs);
[1192]     if (cidr == NULL) {
[1193]         return NGX_CONF_ERROR;
[1194]     }
[1195] 
[1196]     ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));
[1197] 
[1198]     for (i = 0; i < u.naddrs; i++) {
[1199]         cidr[i].family = u.addrs[i].sockaddr->sa_family;
[1200] 
[1201]         switch (cidr[i].family) {
[1202] 
[1203] #if (NGX_HAVE_INET6)
[1204]         case AF_INET6:
[1205]             sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
[1206]             cidr[i].u.in6.addr = sin6->sin6_addr;
[1207]             ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
[1208]             break;
[1209] #endif
[1210] 
[1211]         default: /* AF_INET */
[1212]             sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
[1213]             cidr[i].u.in.addr = sin->sin_addr.s_addr;
[1214]             cidr[i].u.in.mask = 0xffffffff;
[1215]             break;
[1216]         }
[1217]     }
[1218] 
[1219] #else
[1220] 
[1221]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1222]                        "\"debug_connection\" is ignored, you need to rebuild "
[1223]                        "nginx using --with-debug option to enable it");
[1224] 
[1225] #endif
[1226] 
[1227]     return NGX_CONF_OK;
[1228] }
[1229] 
[1230] 
[1231] static void *
[1232] ngx_event_core_create_conf(ngx_cycle_t *cycle)
[1233] {
[1234]     ngx_event_conf_t  *ecf;
[1235] 
[1236]     ecf = ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t));
[1237]     if (ecf == NULL) {
[1238]         return NULL;
[1239]     }
[1240] 
[1241]     ecf->connections = NGX_CONF_UNSET_UINT;
[1242]     ecf->use = NGX_CONF_UNSET_UINT;
[1243]     ecf->multi_accept = NGX_CONF_UNSET;
[1244]     ecf->accept_mutex = NGX_CONF_UNSET;
[1245]     ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
[1246]     ecf->name = (void *) NGX_CONF_UNSET;
[1247] 
[1248] #if (NGX_DEBUG)
[1249] 
[1250]     if (ngx_array_init(&ecf->debug_connection, cycle->pool, 4,
[1251]                        sizeof(ngx_cidr_t)) == NGX_ERROR)
[1252]     {
[1253]         return NULL;
[1254]     }
[1255] 
[1256] #endif
[1257] 
[1258]     return ecf;
[1259] }
[1260] 
[1261] 
[1262] static char *
[1263] ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf)
[1264] {
[1265]     ngx_event_conf_t  *ecf = conf;
[1266] 
[1267] #if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
[1268]     int                  fd;
[1269] #endif
[1270]     ngx_int_t            i;
[1271]     ngx_module_t        *module;
[1272]     ngx_event_module_t  *event_module;
[1273] 
[1274]     module = NULL;
[1275] 
[1276] #if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
[1277] 
[1278]     fd = epoll_create(100);
[1279] 
[1280]     if (fd != -1) {
[1281]         (void) close(fd);
[1282]         module = &ngx_epoll_module;
[1283] 
[1284]     } else if (ngx_errno != NGX_ENOSYS) {
[1285]         module = &ngx_epoll_module;
[1286]     }
[1287] 
[1288] #endif
[1289] 
[1290] #if (NGX_HAVE_DEVPOLL) && !(NGX_TEST_BUILD_DEVPOLL)
[1291] 
[1292]     module = &ngx_devpoll_module;
[1293] 
[1294] #endif
[1295] 
[1296] #if (NGX_HAVE_KQUEUE)
[1297] 
[1298]     module = &ngx_kqueue_module;
[1299] 
[1300] #endif
[1301] 
[1302] #if (NGX_HAVE_SELECT)
[1303] 
[1304]     if (module == NULL) {
[1305]         module = &ngx_select_module;
[1306]     }
[1307] 
[1308] #endif
[1309] 
[1310]     if (module == NULL) {
[1311]         for (i = 0; cycle->modules[i]; i++) {
[1312] 
[1313]             if (cycle->modules[i]->type != NGX_EVENT_MODULE) {
[1314]                 continue;
[1315]             }
[1316] 
[1317]             event_module = cycle->modules[i]->ctx;
[1318] 
[1319]             if (ngx_strcmp(event_module->name->data, event_core_name.data) == 0)
[1320]             {
[1321]                 continue;
[1322]             }
[1323] 
[1324]             module = cycle->modules[i];
[1325]             break;
[1326]         }
[1327]     }
[1328] 
[1329]     if (module == NULL) {
[1330]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
[1331]         return NGX_CONF_ERROR;
[1332]     }
[1333] 
[1334]     ngx_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
[1335]     cycle->connection_n = ecf->connections;
[1336] 
[1337]     ngx_conf_init_uint_value(ecf->use, module->ctx_index);
[1338] 
[1339]     event_module = module->ctx;
[1340]     ngx_conf_init_ptr_value(ecf->name, event_module->name->data);
[1341] 
[1342]     ngx_conf_init_value(ecf->multi_accept, 0);
[1343]     ngx_conf_init_value(ecf->accept_mutex, 0);
[1344]     ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);
[1345] 
[1346]     return NGX_CONF_OK;
[1347] }
