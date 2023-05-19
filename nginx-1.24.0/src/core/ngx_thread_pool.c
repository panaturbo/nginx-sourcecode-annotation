[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  * Copyright (C) Ruslan Ermilov
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_thread_pool.h>
[12] 
[13] 
[14] typedef struct {
[15]     ngx_array_t               pools;
[16] } ngx_thread_pool_conf_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_thread_task_t        *first;
[21]     ngx_thread_task_t       **last;
[22] } ngx_thread_pool_queue_t;
[23] 
[24] #define ngx_thread_pool_queue_init(q)                                         \
[25]     (q)->first = NULL;                                                        \
[26]     (q)->last = &(q)->first
[27] 
[28] 
[29] struct ngx_thread_pool_s {
[30]     ngx_thread_mutex_t        mtx;
[31]     ngx_thread_pool_queue_t   queue;
[32]     ngx_int_t                 waiting;
[33]     ngx_thread_cond_t         cond;
[34] 
[35]     ngx_log_t                *log;
[36] 
[37]     ngx_str_t                 name;
[38]     ngx_uint_t                threads;
[39]     ngx_int_t                 max_queue;
[40] 
[41]     u_char                   *file;
[42]     ngx_uint_t                line;
[43] };
[44] 
[45] 
[46] static ngx_int_t ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log,
[47]     ngx_pool_t *pool);
[48] static void ngx_thread_pool_destroy(ngx_thread_pool_t *tp);
[49] static void ngx_thread_pool_exit_handler(void *data, ngx_log_t *log);
[50] 
[51] static void *ngx_thread_pool_cycle(void *data);
[52] static void ngx_thread_pool_handler(ngx_event_t *ev);
[53] 
[54] static char *ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[55] 
[56] static void *ngx_thread_pool_create_conf(ngx_cycle_t *cycle);
[57] static char *ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf);
[58] 
[59] static ngx_int_t ngx_thread_pool_init_worker(ngx_cycle_t *cycle);
[60] static void ngx_thread_pool_exit_worker(ngx_cycle_t *cycle);
[61] 
[62] 
[63] static ngx_command_t  ngx_thread_pool_commands[] = {
[64] 
[65]     { ngx_string("thread_pool"),
[66]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE23,
[67]       ngx_thread_pool,
[68]       0,
[69]       0,
[70]       NULL },
[71] 
[72]       ngx_null_command
[73] };
[74] 
[75] 
[76] static ngx_core_module_t  ngx_thread_pool_module_ctx = {
[77]     ngx_string("thread_pool"),
[78]     ngx_thread_pool_create_conf,
[79]     ngx_thread_pool_init_conf
[80] };
[81] 
[82] 
[83] ngx_module_t  ngx_thread_pool_module = {
[84]     NGX_MODULE_V1,
[85]     &ngx_thread_pool_module_ctx,           /* module context */
[86]     ngx_thread_pool_commands,              /* module directives */
[87]     NGX_CORE_MODULE,                       /* module type */
[88]     NULL,                                  /* init master */
[89]     NULL,                                  /* init module */
[90]     ngx_thread_pool_init_worker,           /* init process */
[91]     NULL,                                  /* init thread */
[92]     NULL,                                  /* exit thread */
[93]     ngx_thread_pool_exit_worker,           /* exit process */
[94]     NULL,                                  /* exit master */
[95]     NGX_MODULE_V1_PADDING
[96] };
[97] 
[98] 
[99] static ngx_str_t  ngx_thread_pool_default = ngx_string("default");
[100] 
[101] static ngx_uint_t               ngx_thread_pool_task_id;
[102] static ngx_atomic_t             ngx_thread_pool_done_lock;
[103] static ngx_thread_pool_queue_t  ngx_thread_pool_done;
[104] 
[105] 
[106] static ngx_int_t
[107] ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log, ngx_pool_t *pool)
[108] {
[109]     int             err;
[110]     pthread_t       tid;
[111]     ngx_uint_t      n;
[112]     pthread_attr_t  attr;
[113] 
[114]     if (ngx_notify == NULL) {
[115]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[116]                "the configured event method cannot be used with thread pools");
[117]         return NGX_ERROR;
[118]     }
[119] 
[120]     ngx_thread_pool_queue_init(&tp->queue);
[121] 
[122]     if (ngx_thread_mutex_create(&tp->mtx, log) != NGX_OK) {
[123]         return NGX_ERROR;
[124]     }
[125] 
[126]     if (ngx_thread_cond_create(&tp->cond, log) != NGX_OK) {
[127]         (void) ngx_thread_mutex_destroy(&tp->mtx, log);
[128]         return NGX_ERROR;
[129]     }
[130] 
[131]     tp->log = log;
[132] 
[133]     err = pthread_attr_init(&attr);
[134]     if (err) {
[135]         ngx_log_error(NGX_LOG_ALERT, log, err,
[136]                       "pthread_attr_init() failed");
[137]         return NGX_ERROR;
[138]     }
[139] 
[140]     err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
[141]     if (err) {
[142]         ngx_log_error(NGX_LOG_ALERT, log, err,
[143]                       "pthread_attr_setdetachstate() failed");
[144]         return NGX_ERROR;
[145]     }
[146] 
[147] #if 0
[148]     err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
[149]     if (err) {
[150]         ngx_log_error(NGX_LOG_ALERT, log, err,
[151]                       "pthread_attr_setstacksize() failed");
[152]         return NGX_ERROR;
[153]     }
[154] #endif
[155] 
[156]     for (n = 0; n < tp->threads; n++) {
[157]         err = pthread_create(&tid, &attr, ngx_thread_pool_cycle, tp);
[158]         if (err) {
[159]             ngx_log_error(NGX_LOG_ALERT, log, err,
[160]                           "pthread_create() failed");
[161]             return NGX_ERROR;
[162]         }
[163]     }
[164] 
[165]     (void) pthread_attr_destroy(&attr);
[166] 
[167]     return NGX_OK;
[168] }
[169] 
[170] 
[171] static void
[172] ngx_thread_pool_destroy(ngx_thread_pool_t *tp)
[173] {
[174]     ngx_uint_t           n;
[175]     ngx_thread_task_t    task;
[176]     volatile ngx_uint_t  lock;
[177] 
[178]     ngx_memzero(&task, sizeof(ngx_thread_task_t));
[179] 
[180]     task.handler = ngx_thread_pool_exit_handler;
[181]     task.ctx = (void *) &lock;
[182] 
[183]     for (n = 0; n < tp->threads; n++) {
[184]         lock = 1;
[185] 
[186]         if (ngx_thread_task_post(tp, &task) != NGX_OK) {
[187]             return;
[188]         }
[189] 
[190]         while (lock) {
[191]             ngx_sched_yield();
[192]         }
[193] 
[194]         task.event.active = 0;
[195]     }
[196] 
[197]     (void) ngx_thread_cond_destroy(&tp->cond, tp->log);
[198] 
[199]     (void) ngx_thread_mutex_destroy(&tp->mtx, tp->log);
[200] }
[201] 
[202] 
[203] static void
[204] ngx_thread_pool_exit_handler(void *data, ngx_log_t *log)
[205] {
[206]     ngx_uint_t *lock = data;
[207] 
[208]     *lock = 0;
[209] 
[210]     pthread_exit(0);
[211] }
[212] 
[213] 
[214] ngx_thread_task_t *
[215] ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
[216] {
[217]     ngx_thread_task_t  *task;
[218] 
[219]     task = ngx_pcalloc(pool, sizeof(ngx_thread_task_t) + size);
[220]     if (task == NULL) {
[221]         return NULL;
[222]     }
[223] 
[224]     task->ctx = task + 1;
[225] 
[226]     return task;
[227] }
[228] 
[229] 
[230] ngx_int_t
[231] ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
[232] {
[233]     if (task->event.active) {
[234]         ngx_log_error(NGX_LOG_ALERT, tp->log, 0,
[235]                       "task #%ui already active", task->id);
[236]         return NGX_ERROR;
[237]     }
[238] 
[239]     if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
[240]         return NGX_ERROR;
[241]     }
[242] 
[243]     if (tp->waiting >= tp->max_queue) {
[244]         (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
[245] 
[246]         ngx_log_error(NGX_LOG_ERR, tp->log, 0,
[247]                       "thread pool \"%V\" queue overflow: %i tasks waiting",
[248]                       &tp->name, tp->waiting);
[249]         return NGX_ERROR;
[250]     }
[251] 
[252]     task->event.active = 1;
[253] 
[254]     task->id = ngx_thread_pool_task_id++;
[255]     task->next = NULL;
[256] 
[257]     if (ngx_thread_cond_signal(&tp->cond, tp->log) != NGX_OK) {
[258]         (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
[259]         return NGX_ERROR;
[260]     }
[261] 
[262]     *tp->queue.last = task;
[263]     tp->queue.last = &task->next;
[264] 
[265]     tp->waiting++;
[266] 
[267]     (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
[268] 
[269]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
[270]                    "task #%ui added to thread pool \"%V\"",
[271]                    task->id, &tp->name);
[272] 
[273]     return NGX_OK;
[274] }
[275] 
[276] 
[277] static void *
[278] ngx_thread_pool_cycle(void *data)
[279] {
[280]     ngx_thread_pool_t *tp = data;
[281] 
[282]     int                 err;
[283]     sigset_t            set;
[284]     ngx_thread_task_t  *task;
[285] 
[286] #if 0
[287]     ngx_time_update();
[288] #endif
[289] 
[290]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, tp->log, 0,
[291]                    "thread in pool \"%V\" started", &tp->name);
[292] 
[293]     sigfillset(&set);
[294] 
[295]     sigdelset(&set, SIGILL);
[296]     sigdelset(&set, SIGFPE);
[297]     sigdelset(&set, SIGSEGV);
[298]     sigdelset(&set, SIGBUS);
[299] 
[300]     err = pthread_sigmask(SIG_BLOCK, &set, NULL);
[301]     if (err) {
[302]         ngx_log_error(NGX_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
[303]         return NULL;
[304]     }
[305] 
[306]     for ( ;; ) {
[307]         if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
[308]             return NULL;
[309]         }
[310] 
[311]         /* the number may become negative */
[312]         tp->waiting--;
[313] 
[314]         while (tp->queue.first == NULL) {
[315]             if (ngx_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
[316]                 != NGX_OK)
[317]             {
[318]                 (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
[319]                 return NULL;
[320]             }
[321]         }
[322] 
[323]         task = tp->queue.first;
[324]         tp->queue.first = task->next;
[325] 
[326]         if (tp->queue.first == NULL) {
[327]             tp->queue.last = &tp->queue.first;
[328]         }
[329] 
[330]         if (ngx_thread_mutex_unlock(&tp->mtx, tp->log) != NGX_OK) {
[331]             return NULL;
[332]         }
[333] 
[334] #if 0
[335]         ngx_time_update();
[336] #endif
[337] 
[338]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
[339]                        "run task #%ui in thread pool \"%V\"",
[340]                        task->id, &tp->name);
[341] 
[342]         task->handler(task->ctx, tp->log);
[343] 
[344]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
[345]                        "complete task #%ui in thread pool \"%V\"",
[346]                        task->id, &tp->name);
[347] 
[348]         task->next = NULL;
[349] 
[350]         ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);
[351] 
[352]         *ngx_thread_pool_done.last = task;
[353]         ngx_thread_pool_done.last = &task->next;
[354] 
[355]         ngx_memory_barrier();
[356] 
[357]         ngx_unlock(&ngx_thread_pool_done_lock);
[358] 
[359]         (void) ngx_notify(ngx_thread_pool_handler);
[360]     }
[361] }
[362] 
[363] 
[364] static void
[365] ngx_thread_pool_handler(ngx_event_t *ev)
[366] {
[367]     ngx_event_t        *event;
[368]     ngx_thread_task_t  *task;
[369] 
[370]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");
[371] 
[372]     ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);
[373] 
[374]     task = ngx_thread_pool_done.first;
[375]     ngx_thread_pool_done.first = NULL;
[376]     ngx_thread_pool_done.last = &ngx_thread_pool_done.first;
[377] 
[378]     ngx_memory_barrier();
[379] 
[380]     ngx_unlock(&ngx_thread_pool_done_lock);
[381] 
[382]     while (task) {
[383]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
[384]                        "run completion handler for task #%ui", task->id);
[385] 
[386]         event = &task->event;
[387]         task = task->next;
[388] 
[389]         event->complete = 1;
[390]         event->active = 0;
[391] 
[392]         event->handler(event);
[393]     }
[394] }
[395] 
[396] 
[397] static void *
[398] ngx_thread_pool_create_conf(ngx_cycle_t *cycle)
[399] {
[400]     ngx_thread_pool_conf_t  *tcf;
[401] 
[402]     tcf = ngx_pcalloc(cycle->pool, sizeof(ngx_thread_pool_conf_t));
[403]     if (tcf == NULL) {
[404]         return NULL;
[405]     }
[406] 
[407]     if (ngx_array_init(&tcf->pools, cycle->pool, 4,
[408]                        sizeof(ngx_thread_pool_t *))
[409]         != NGX_OK)
[410]     {
[411]         return NULL;
[412]     }
[413] 
[414]     return tcf;
[415] }
[416] 
[417] 
[418] static char *
[419] ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf)
[420] {
[421]     ngx_thread_pool_conf_t *tcf = conf;
[422] 
[423]     ngx_uint_t           i;
[424]     ngx_thread_pool_t  **tpp;
[425] 
[426]     tpp = tcf->pools.elts;
[427] 
[428]     for (i = 0; i < tcf->pools.nelts; i++) {
[429] 
[430]         if (tpp[i]->threads) {
[431]             continue;
[432]         }
[433] 
[434]         if (tpp[i]->name.len == ngx_thread_pool_default.len
[435]             && ngx_strncmp(tpp[i]->name.data, ngx_thread_pool_default.data,
[436]                            ngx_thread_pool_default.len)
[437]                == 0)
[438]         {
[439]             tpp[i]->threads = 32;
[440]             tpp[i]->max_queue = 65536;
[441]             continue;
[442]         }
[443] 
[444]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[445]                       "unknown thread pool \"%V\" in %s:%ui",
[446]                       &tpp[i]->name, tpp[i]->file, tpp[i]->line);
[447] 
[448]         return NGX_CONF_ERROR;
[449]     }
[450] 
[451]     return NGX_CONF_OK;
[452] }
[453] 
[454] 
[455] static char *
[456] ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[457] {
[458]     ngx_str_t          *value;
[459]     ngx_uint_t          i;
[460]     ngx_thread_pool_t  *tp;
[461] 
[462]     value = cf->args->elts;
[463] 
[464]     tp = ngx_thread_pool_add(cf, &value[1]);
[465] 
[466]     if (tp == NULL) {
[467]         return NGX_CONF_ERROR;
[468]     }
[469] 
[470]     if (tp->threads) {
[471]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[472]                            "duplicate thread pool \"%V\"", &tp->name);
[473]         return NGX_CONF_ERROR;
[474]     }
[475] 
[476]     tp->max_queue = 65536;
[477] 
[478]     for (i = 2; i < cf->args->nelts; i++) {
[479] 
[480]         if (ngx_strncmp(value[i].data, "threads=", 8) == 0) {
[481] 
[482]             tp->threads = ngx_atoi(value[i].data + 8, value[i].len - 8);
[483] 
[484]             if (tp->threads == (ngx_uint_t) NGX_ERROR || tp->threads == 0) {
[485]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[486]                                    "invalid threads value \"%V\"", &value[i]);
[487]                 return NGX_CONF_ERROR;
[488]             }
[489] 
[490]             continue;
[491]         }
[492] 
[493]         if (ngx_strncmp(value[i].data, "max_queue=", 10) == 0) {
[494] 
[495]             tp->max_queue = ngx_atoi(value[i].data + 10, value[i].len - 10);
[496] 
[497]             if (tp->max_queue == NGX_ERROR) {
[498]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[499]                                    "invalid max_queue value \"%V\"", &value[i]);
[500]                 return NGX_CONF_ERROR;
[501]             }
[502] 
[503]             continue;
[504]         }
[505]     }
[506] 
[507]     if (tp->threads == 0) {
[508]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[509]                            "\"%V\" must have \"threads\" parameter",
[510]                            &cmd->name);
[511]         return NGX_CONF_ERROR;
[512]     }
[513] 
[514]     return NGX_CONF_OK;
[515] }
[516] 
[517] 
[518] ngx_thread_pool_t *
[519] ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name)
[520] {
[521]     ngx_thread_pool_t       *tp, **tpp;
[522]     ngx_thread_pool_conf_t  *tcf;
[523] 
[524]     if (name == NULL) {
[525]         name = &ngx_thread_pool_default;
[526]     }
[527] 
[528]     tp = ngx_thread_pool_get(cf->cycle, name);
[529] 
[530]     if (tp) {
[531]         return tp;
[532]     }
[533] 
[534]     tp = ngx_pcalloc(cf->pool, sizeof(ngx_thread_pool_t));
[535]     if (tp == NULL) {
[536]         return NULL;
[537]     }
[538] 
[539]     tp->name = *name;
[540]     tp->file = cf->conf_file->file.name.data;
[541]     tp->line = cf->conf_file->line;
[542] 
[543]     tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
[544]                                                   ngx_thread_pool_module);
[545] 
[546]     tpp = ngx_array_push(&tcf->pools);
[547]     if (tpp == NULL) {
[548]         return NULL;
[549]     }
[550] 
[551]     *tpp = tp;
[552] 
[553]     return tp;
[554] }
[555] 
[556] 
[557] ngx_thread_pool_t *
[558] ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
[559] {
[560]     ngx_uint_t                i;
[561]     ngx_thread_pool_t       **tpp;
[562]     ngx_thread_pool_conf_t   *tcf;
[563] 
[564]     tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
[565]                                                   ngx_thread_pool_module);
[566] 
[567]     tpp = tcf->pools.elts;
[568] 
[569]     for (i = 0; i < tcf->pools.nelts; i++) {
[570] 
[571]         if (tpp[i]->name.len == name->len
[572]             && ngx_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
[573]         {
[574]             return tpp[i];
[575]         }
[576]     }
[577] 
[578]     return NULL;
[579] }
[580] 
[581] 
[582] static ngx_int_t
[583] ngx_thread_pool_init_worker(ngx_cycle_t *cycle)
[584] {
[585]     ngx_uint_t                i;
[586]     ngx_thread_pool_t       **tpp;
[587]     ngx_thread_pool_conf_t   *tcf;
[588] 
[589]     if (ngx_process != NGX_PROCESS_WORKER
[590]         && ngx_process != NGX_PROCESS_SINGLE)
[591]     {
[592]         return NGX_OK;
[593]     }
[594] 
[595]     tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
[596]                                                   ngx_thread_pool_module);
[597] 
[598]     if (tcf == NULL) {
[599]         return NGX_OK;
[600]     }
[601] 
[602]     ngx_thread_pool_queue_init(&ngx_thread_pool_done);
[603] 
[604]     tpp = tcf->pools.elts;
[605] 
[606]     for (i = 0; i < tcf->pools.nelts; i++) {
[607]         if (ngx_thread_pool_init(tpp[i], cycle->log, cycle->pool) != NGX_OK) {
[608]             return NGX_ERROR;
[609]         }
[610]     }
[611] 
[612]     return NGX_OK;
[613] }
[614] 
[615] 
[616] static void
[617] ngx_thread_pool_exit_worker(ngx_cycle_t *cycle)
[618] {
[619]     ngx_uint_t                i;
[620]     ngx_thread_pool_t       **tpp;
[621]     ngx_thread_pool_conf_t   *tcf;
[622] 
[623]     if (ngx_process != NGX_PROCESS_WORKER
[624]         && ngx_process != NGX_PROCESS_SINGLE)
[625]     {
[626]         return;
[627]     }
[628] 
[629]     tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
[630]                                                   ngx_thread_pool_module);
[631] 
[632]     if (tcf == NULL) {
[633]         return;
[634]     }
[635] 
[636]     tpp = tcf->pools.elts;
[637] 
[638]     for (i = 0; i < tcf->pools.nelts; i++) {
[639]         ngx_thread_pool_destroy(tpp[i]);
[640]     }
[641] }
