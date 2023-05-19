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
[11] #include <ngx_channel.h>
[12] 
[13] 
[14] static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
[15]     ngx_int_t type);
[16] static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle,
[17]     ngx_uint_t respawn);
[18] static void ngx_pass_open_channel(ngx_cycle_t *cycle);
[19] static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
[20] static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);
[21] static void ngx_master_process_exit(ngx_cycle_t *cycle);
[22] static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
[23] static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker);
[24] static void ngx_worker_process_exit(ngx_cycle_t *cycle);
[25] static void ngx_channel_handler(ngx_event_t *ev);
[26] static void ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data);
[27] static void ngx_cache_manager_process_handler(ngx_event_t *ev);
[28] static void ngx_cache_loader_process_handler(ngx_event_t *ev);
[29] 
[30] 
[31] ngx_uint_t    ngx_process;
[32] ngx_uint_t    ngx_worker;
[33] ngx_pid_t     ngx_pid;
[34] ngx_pid_t     ngx_parent;
[35] 
[36] sig_atomic_t  ngx_reap;
[37] sig_atomic_t  ngx_sigio;
[38] sig_atomic_t  ngx_sigalrm;
[39] sig_atomic_t  ngx_terminate;
[40] sig_atomic_t  ngx_quit;
[41] sig_atomic_t  ngx_debug_quit;
[42] ngx_uint_t    ngx_exiting;
[43] sig_atomic_t  ngx_reconfigure;
[44] sig_atomic_t  ngx_reopen;
[45] 
[46] sig_atomic_t  ngx_change_binary;
[47] ngx_pid_t     ngx_new_binary;
[48] ngx_uint_t    ngx_inherited;
[49] ngx_uint_t    ngx_daemonized;
[50] 
[51] sig_atomic_t  ngx_noaccept;
[52] ngx_uint_t    ngx_noaccepting;
[53] ngx_uint_t    ngx_restart;
[54] 
[55] 
[56] static u_char  master_process[] = "master process";
[57] 
[58] 
[59] static ngx_cache_manager_ctx_t  ngx_cache_manager_ctx = {
[60]     ngx_cache_manager_process_handler, "cache manager process", 0
[61] };
[62] 
[63] static ngx_cache_manager_ctx_t  ngx_cache_loader_ctx = {
[64]     ngx_cache_loader_process_handler, "cache loader process", 60000
[65] };
[66] 
[67] 
[68] static ngx_cycle_t      ngx_exit_cycle;
[69] static ngx_log_t        ngx_exit_log;
[70] static ngx_open_file_t  ngx_exit_log_file;
[71] 
[72] 
[73] void
[74] ngx_master_process_cycle(ngx_cycle_t *cycle)
[75] {
[76]     char              *title;
[77]     u_char            *p;
[78]     size_t             size;
[79]     ngx_int_t          i;
[80]     ngx_uint_t         sigio;
[81]     sigset_t           set;
[82]     struct itimerval   itv;
[83]     ngx_uint_t         live;
[84]     ngx_msec_t         delay;
[85]     ngx_core_conf_t   *ccf;
[86] 
[87]     sigemptyset(&set);
[88]     sigaddset(&set, SIGCHLD);
[89]     sigaddset(&set, SIGALRM);
[90]     sigaddset(&set, SIGIO);
[91]     sigaddset(&set, SIGINT);
[92]     sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
[93]     sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
[94]     sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
[95]     sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
[96]     sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
[97]     sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));
[98] 
[99]     if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
[100]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[101]                       "sigprocmask() failed");
[102]     }
[103] 
[104]     sigemptyset(&set);
[105] 
[106] 
[107]     size = sizeof(master_process);
[108] 
[109]     for (i = 0; i < ngx_argc; i++) {
[110]         size += ngx_strlen(ngx_argv[i]) + 1;
[111]     }
[112] 
[113]     title = ngx_pnalloc(cycle->pool, size);
[114]     if (title == NULL) {
[115]         /* fatal */
[116]         exit(2);
[117]     }
[118] 
[119]     p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
[120]     for (i = 0; i < ngx_argc; i++) {
[121]         *p++ = ' ';
[122]         p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
[123]     }
[124] 
[125]     ngx_setproctitle(title);
[126] 
[127] 
[128]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[129] 
[130]     ngx_start_worker_processes(cycle, ccf->worker_processes,
[131]                                NGX_PROCESS_RESPAWN);
[132]     ngx_start_cache_manager_processes(cycle, 0);
[133] 
[134]     ngx_new_binary = 0;
[135]     delay = 0;
[136]     sigio = 0;
[137]     live = 1;
[138] 
[139]     for ( ;; ) {
[140]         if (delay) {
[141]             if (ngx_sigalrm) {
[142]                 sigio = 0;
[143]                 delay *= 2;
[144]                 ngx_sigalrm = 0;
[145]             }
[146] 
[147]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[148]                            "termination cycle: %M", delay);
[149] 
[150]             itv.it_interval.tv_sec = 0;
[151]             itv.it_interval.tv_usec = 0;
[152]             itv.it_value.tv_sec = delay / 1000;
[153]             itv.it_value.tv_usec = (delay % 1000 ) * 1000;
[154] 
[155]             if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
[156]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[157]                               "setitimer() failed");
[158]             }
[159]         }
[160] 
[161]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");
[162] 
[163]         sigsuspend(&set);
[164] 
[165]         ngx_time_update();
[166] 
[167]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[168]                        "wake up, sigio %i", sigio);
[169] 
[170]         if (ngx_reap) {
[171]             ngx_reap = 0;
[172]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");
[173] 
[174]             live = ngx_reap_children(cycle);
[175]         }
[176] 
[177]         if (!live && (ngx_terminate || ngx_quit)) {
[178]             ngx_master_process_exit(cycle);
[179]         }
[180] 
[181]         if (ngx_terminate) {
[182]             if (delay == 0) {
[183]                 delay = 50;
[184]             }
[185] 
[186]             if (sigio) {
[187]                 sigio--;
[188]                 continue;
[189]             }
[190] 
[191]             sigio = ccf->worker_processes + 2 /* cache processes */;
[192] 
[193]             if (delay > 1000) {
[194]                 ngx_signal_worker_processes(cycle, SIGKILL);
[195]             } else {
[196]                 ngx_signal_worker_processes(cycle,
[197]                                        ngx_signal_value(NGX_TERMINATE_SIGNAL));
[198]             }
[199] 
[200]             continue;
[201]         }
[202] 
[203]         if (ngx_quit) {
[204]             ngx_signal_worker_processes(cycle,
[205]                                         ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
[206]             ngx_close_listening_sockets(cycle);
[207] 
[208]             continue;
[209]         }
[210] 
[211]         if (ngx_reconfigure) {
[212]             ngx_reconfigure = 0;
[213] 
[214]             if (ngx_new_binary) {
[215]                 ngx_start_worker_processes(cycle, ccf->worker_processes,
[216]                                            NGX_PROCESS_RESPAWN);
[217]                 ngx_start_cache_manager_processes(cycle, 0);
[218]                 ngx_noaccepting = 0;
[219] 
[220]                 continue;
[221]             }
[222] 
[223]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");
[224] 
[225]             cycle = ngx_init_cycle(cycle);
[226]             if (cycle == NULL) {
[227]                 cycle = (ngx_cycle_t *) ngx_cycle;
[228]                 continue;
[229]             }
[230] 
[231]             ngx_cycle = cycle;
[232]             ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
[233]                                                    ngx_core_module);
[234]             ngx_start_worker_processes(cycle, ccf->worker_processes,
[235]                                        NGX_PROCESS_JUST_RESPAWN);
[236]             ngx_start_cache_manager_processes(cycle, 1);
[237] 
[238]             /* allow new processes to start */
[239]             ngx_msleep(100);
[240] 
[241]             live = 1;
[242]             ngx_signal_worker_processes(cycle,
[243]                                         ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
[244]         }
[245] 
[246]         if (ngx_restart) {
[247]             ngx_restart = 0;
[248]             ngx_start_worker_processes(cycle, ccf->worker_processes,
[249]                                        NGX_PROCESS_RESPAWN);
[250]             ngx_start_cache_manager_processes(cycle, 0);
[251]             live = 1;
[252]         }
[253] 
[254]         if (ngx_reopen) {
[255]             ngx_reopen = 0;
[256]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
[257]             ngx_reopen_files(cycle, ccf->user);
[258]             ngx_signal_worker_processes(cycle,
[259]                                         ngx_signal_value(NGX_REOPEN_SIGNAL));
[260]         }
[261] 
[262]         if (ngx_change_binary) {
[263]             ngx_change_binary = 0;
[264]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");
[265]             ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
[266]         }
[267] 
[268]         if (ngx_noaccept) {
[269]             ngx_noaccept = 0;
[270]             ngx_noaccepting = 1;
[271]             ngx_signal_worker_processes(cycle,
[272]                                         ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
[273]         }
[274]     }
[275] }
[276] 
[277] 
[278] void
[279] ngx_single_process_cycle(ngx_cycle_t *cycle)
[280] {
[281]     ngx_uint_t  i;
[282] 
[283]     if (ngx_set_environment(cycle, NULL) == NULL) {
[284]         /* fatal */
[285]         exit(2);
[286]     }
[287] 
[288]     for (i = 0; cycle->modules[i]; i++) {
[289]         if (cycle->modules[i]->init_process) {
[290]             if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
[291]                 /* fatal */
[292]                 exit(2);
[293]             }
[294]         }
[295]     }
[296] 
[297]     for ( ;; ) {
[298]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");
[299] 
[300]         ngx_process_events_and_timers(cycle);
[301] 
[302]         if (ngx_terminate || ngx_quit) {
[303] 
[304]             for (i = 0; cycle->modules[i]; i++) {
[305]                 if (cycle->modules[i]->exit_process) {
[306]                     cycle->modules[i]->exit_process(cycle);
[307]                 }
[308]             }
[309] 
[310]             ngx_master_process_exit(cycle);
[311]         }
[312] 
[313]         if (ngx_reconfigure) {
[314]             ngx_reconfigure = 0;
[315]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");
[316] 
[317]             cycle = ngx_init_cycle(cycle);
[318]             if (cycle == NULL) {
[319]                 cycle = (ngx_cycle_t *) ngx_cycle;
[320]                 continue;
[321]             }
[322] 
[323]             ngx_cycle = cycle;
[324]         }
[325] 
[326]         if (ngx_reopen) {
[327]             ngx_reopen = 0;
[328]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
[329]             ngx_reopen_files(cycle, (ngx_uid_t) -1);
[330]         }
[331]     }
[332] }
[333] 
[334] 
[335] static void
[336] ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
[337] {
[338]     ngx_int_t  i;
[339] 
[340]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");
[341] 
[342]     for (i = 0; i < n; i++) {
[343] 
[344]         ngx_spawn_process(cycle, ngx_worker_process_cycle,
[345]                           (void *) (intptr_t) i, "worker process", type);
[346] 
[347]         ngx_pass_open_channel(cycle);
[348]     }
[349] }
[350] 
[351] 
[352] static void
[353] ngx_start_cache_manager_processes(ngx_cycle_t *cycle, ngx_uint_t respawn)
[354] {
[355]     ngx_uint_t    i, manager, loader;
[356]     ngx_path_t  **path;
[357] 
[358]     manager = 0;
[359]     loader = 0;
[360] 
[361]     path = ngx_cycle->paths.elts;
[362]     for (i = 0; i < ngx_cycle->paths.nelts; i++) {
[363] 
[364]         if (path[i]->manager) {
[365]             manager = 1;
[366]         }
[367] 
[368]         if (path[i]->loader) {
[369]             loader = 1;
[370]         }
[371]     }
[372] 
[373]     if (manager == 0) {
[374]         return;
[375]     }
[376] 
[377]     ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
[378]                       &ngx_cache_manager_ctx, "cache manager process",
[379]                       respawn ? NGX_PROCESS_JUST_RESPAWN : NGX_PROCESS_RESPAWN);
[380] 
[381]     ngx_pass_open_channel(cycle);
[382] 
[383]     if (loader == 0) {
[384]         return;
[385]     }
[386] 
[387]     ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
[388]                       &ngx_cache_loader_ctx, "cache loader process",
[389]                       respawn ? NGX_PROCESS_JUST_SPAWN : NGX_PROCESS_NORESPAWN);
[390] 
[391]     ngx_pass_open_channel(cycle);
[392] }
[393] 
[394] 
[395] static void
[396] ngx_pass_open_channel(ngx_cycle_t *cycle)
[397] {
[398]     ngx_int_t      i;
[399]     ngx_channel_t  ch;
[400] 
[401]     ngx_memzero(&ch, sizeof(ngx_channel_t));
[402] 
[403]     ch.command = NGX_CMD_OPEN_CHANNEL;
[404]     ch.pid = ngx_processes[ngx_process_slot].pid;
[405]     ch.slot = ngx_process_slot;
[406]     ch.fd = ngx_processes[ngx_process_slot].channel[0];
[407] 
[408]     for (i = 0; i < ngx_last_process; i++) {
[409] 
[410]         if (i == ngx_process_slot
[411]             || ngx_processes[i].pid == -1
[412]             || ngx_processes[i].channel[0] == -1)
[413]         {
[414]             continue;
[415]         }
[416] 
[417]         ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[418]                       "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
[419]                       ch.slot, ch.pid, ch.fd,
[420]                       i, ngx_processes[i].pid,
[421]                       ngx_processes[i].channel[0]);
[422] 
[423]         /* TODO: NGX_AGAIN */
[424] 
[425]         ngx_write_channel(ngx_processes[i].channel[0],
[426]                           &ch, sizeof(ngx_channel_t), cycle->log);
[427]     }
[428] }
[429] 
[430] 
[431] static void
[432] ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
[433] {
[434]     ngx_int_t      i;
[435]     ngx_err_t      err;
[436]     ngx_channel_t  ch;
[437] 
[438]     ngx_memzero(&ch, sizeof(ngx_channel_t));
[439] 
[440] #if (NGX_BROKEN_SCM_RIGHTS)
[441] 
[442]     ch.command = 0;
[443] 
[444] #else
[445] 
[446]     switch (signo) {
[447] 
[448]     case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
[449]         ch.command = NGX_CMD_QUIT;
[450]         break;
[451] 
[452]     case ngx_signal_value(NGX_TERMINATE_SIGNAL):
[453]         ch.command = NGX_CMD_TERMINATE;
[454]         break;
[455] 
[456]     case ngx_signal_value(NGX_REOPEN_SIGNAL):
[457]         ch.command = NGX_CMD_REOPEN;
[458]         break;
[459] 
[460]     default:
[461]         ch.command = 0;
[462]     }
[463] 
[464] #endif
[465] 
[466]     ch.fd = -1;
[467] 
[468] 
[469]     for (i = 0; i < ngx_last_process; i++) {
[470] 
[471]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[472]                        "child: %i %P e:%d t:%d d:%d r:%d j:%d",
[473]                        i,
[474]                        ngx_processes[i].pid,
[475]                        ngx_processes[i].exiting,
[476]                        ngx_processes[i].exited,
[477]                        ngx_processes[i].detached,
[478]                        ngx_processes[i].respawn,
[479]                        ngx_processes[i].just_spawn);
[480] 
[481]         if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
[482]             continue;
[483]         }
[484] 
[485]         if (ngx_processes[i].just_spawn) {
[486]             ngx_processes[i].just_spawn = 0;
[487]             continue;
[488]         }
[489] 
[490]         if (ngx_processes[i].exiting
[491]             && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
[492]         {
[493]             continue;
[494]         }
[495] 
[496]         if (ch.command) {
[497]             if (ngx_write_channel(ngx_processes[i].channel[0],
[498]                                   &ch, sizeof(ngx_channel_t), cycle->log)
[499]                 == NGX_OK)
[500]             {
[501]                 if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
[502]                     ngx_processes[i].exiting = 1;
[503]                 }
[504] 
[505]                 continue;
[506]             }
[507]         }
[508] 
[509]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[510]                        "kill (%P, %d)", ngx_processes[i].pid, signo);
[511] 
[512]         if (kill(ngx_processes[i].pid, signo) == -1) {
[513]             err = ngx_errno;
[514]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[515]                           "kill(%P, %d) failed", ngx_processes[i].pid, signo);
[516] 
[517]             if (err == NGX_ESRCH) {
[518]                 ngx_processes[i].exited = 1;
[519]                 ngx_processes[i].exiting = 0;
[520]                 ngx_reap = 1;
[521]             }
[522] 
[523]             continue;
[524]         }
[525] 
[526]         if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
[527]             ngx_processes[i].exiting = 1;
[528]         }
[529]     }
[530] }
[531] 
[532] 
[533] static ngx_uint_t
[534] ngx_reap_children(ngx_cycle_t *cycle)
[535] {
[536]     ngx_int_t         i, n;
[537]     ngx_uint_t        live;
[538]     ngx_channel_t     ch;
[539]     ngx_core_conf_t  *ccf;
[540] 
[541]     ngx_memzero(&ch, sizeof(ngx_channel_t));
[542] 
[543]     ch.command = NGX_CMD_CLOSE_CHANNEL;
[544]     ch.fd = -1;
[545] 
[546]     live = 0;
[547]     for (i = 0; i < ngx_last_process; i++) {
[548] 
[549]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[550]                        "child: %i %P e:%d t:%d d:%d r:%d j:%d",
[551]                        i,
[552]                        ngx_processes[i].pid,
[553]                        ngx_processes[i].exiting,
[554]                        ngx_processes[i].exited,
[555]                        ngx_processes[i].detached,
[556]                        ngx_processes[i].respawn,
[557]                        ngx_processes[i].just_spawn);
[558] 
[559]         if (ngx_processes[i].pid == -1) {
[560]             continue;
[561]         }
[562] 
[563]         if (ngx_processes[i].exited) {
[564] 
[565]             if (!ngx_processes[i].detached) {
[566]                 ngx_close_channel(ngx_processes[i].channel, cycle->log);
[567] 
[568]                 ngx_processes[i].channel[0] = -1;
[569]                 ngx_processes[i].channel[1] = -1;
[570] 
[571]                 ch.pid = ngx_processes[i].pid;
[572]                 ch.slot = i;
[573] 
[574]                 for (n = 0; n < ngx_last_process; n++) {
[575]                     if (ngx_processes[n].exited
[576]                         || ngx_processes[n].pid == -1
[577]                         || ngx_processes[n].channel[0] == -1)
[578]                     {
[579]                         continue;
[580]                     }
[581] 
[582]                     ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[583]                                    "pass close channel s:%i pid:%P to:%P",
[584]                                    ch.slot, ch.pid, ngx_processes[n].pid);
[585] 
[586]                     /* TODO: NGX_AGAIN */
[587] 
[588]                     ngx_write_channel(ngx_processes[n].channel[0],
[589]                                       &ch, sizeof(ngx_channel_t), cycle->log);
[590]                 }
[591]             }
[592] 
[593]             if (ngx_processes[i].respawn
[594]                 && !ngx_processes[i].exiting
[595]                 && !ngx_terminate
[596]                 && !ngx_quit)
[597]             {
[598]                 if (ngx_spawn_process(cycle, ngx_processes[i].proc,
[599]                                       ngx_processes[i].data,
[600]                                       ngx_processes[i].name, i)
[601]                     == NGX_INVALID_PID)
[602]                 {
[603]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[604]                                   "could not respawn %s",
[605]                                   ngx_processes[i].name);
[606]                     continue;
[607]                 }
[608] 
[609] 
[610]                 ngx_pass_open_channel(cycle);
[611] 
[612]                 live = 1;
[613] 
[614]                 continue;
[615]             }
[616] 
[617]             if (ngx_processes[i].pid == ngx_new_binary) {
[618] 
[619]                 ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
[620]                                                        ngx_core_module);
[621] 
[622]                 if (ngx_rename_file((char *) ccf->oldpid.data,
[623]                                     (char *) ccf->pid.data)
[624]                     == NGX_FILE_ERROR)
[625]                 {
[626]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[627]                                   ngx_rename_file_n " %s back to %s failed "
[628]                                   "after the new binary process \"%s\" exited",
[629]                                   ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
[630]                 }
[631] 
[632]                 ngx_new_binary = 0;
[633]                 if (ngx_noaccepting) {
[634]                     ngx_restart = 1;
[635]                     ngx_noaccepting = 0;
[636]                 }
[637]             }
[638] 
[639]             if (i == ngx_last_process - 1) {
[640]                 ngx_last_process--;
[641] 
[642]             } else {
[643]                 ngx_processes[i].pid = -1;
[644]             }
[645] 
[646]         } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
[647]             live = 1;
[648]         }
[649]     }
[650] 
[651]     return live;
[652] }
[653] 
[654] 
[655] static void
[656] ngx_master_process_exit(ngx_cycle_t *cycle)
[657] {
[658]     ngx_uint_t  i;
[659] 
[660]     ngx_delete_pidfile(cycle);
[661] 
[662]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");
[663] 
[664]     for (i = 0; cycle->modules[i]; i++) {
[665]         if (cycle->modules[i]->exit_master) {
[666]             cycle->modules[i]->exit_master(cycle);
[667]         }
[668]     }
[669] 
[670]     ngx_close_listening_sockets(cycle);
[671] 
[672]     /*
[673]      * Copy ngx_cycle->log related data to the special static exit cycle,
[674]      * log, and log file structures enough to allow a signal handler to log.
[675]      * The handler may be called when standard ngx_cycle->log allocated from
[676]      * ngx_cycle->pool is already destroyed.
[677]      */
[678] 
[679] 
[680]     ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);
[681] 
[682]     ngx_exit_log_file.fd = ngx_exit_log.file->fd;
[683]     ngx_exit_log.file = &ngx_exit_log_file;
[684]     ngx_exit_log.next = NULL;
[685]     ngx_exit_log.writer = NULL;
[686] 
[687]     ngx_exit_cycle.log = &ngx_exit_log;
[688]     ngx_exit_cycle.files = ngx_cycle->files;
[689]     ngx_exit_cycle.files_n = ngx_cycle->files_n;
[690]     ngx_cycle = &ngx_exit_cycle;
[691] 
[692]     ngx_destroy_pool(cycle->pool);
[693] 
[694]     exit(0);
[695] }
[696] 
[697] 
[698] static void
[699] ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
[700] {
[701]     ngx_int_t worker = (intptr_t) data;
[702] 
[703]     ngx_process = NGX_PROCESS_WORKER;
[704]     ngx_worker = worker;
[705] 
[706]     ngx_worker_process_init(cycle, worker);
[707] 
[708]     ngx_setproctitle("worker process");
[709] 
[710]     for ( ;; ) {
[711] 
[712]         if (ngx_exiting) {
[713]             if (ngx_event_no_timers_left() == NGX_OK) {
[714]                 ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[715]                 ngx_worker_process_exit(cycle);
[716]             }
[717]         }
[718] 
[719]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");
[720] 
[721]         ngx_process_events_and_timers(cycle);
[722] 
[723]         if (ngx_terminate) {
[724]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[725]             ngx_worker_process_exit(cycle);
[726]         }
[727] 
[728]         if (ngx_quit) {
[729]             ngx_quit = 0;
[730]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
[731]                           "gracefully shutting down");
[732]             ngx_setproctitle("worker process is shutting down");
[733] 
[734]             if (!ngx_exiting) {
[735]                 ngx_exiting = 1;
[736]                 ngx_set_shutdown_timer(cycle);
[737]                 ngx_close_listening_sockets(cycle);
[738]                 ngx_close_idle_connections(cycle);
[739]                 ngx_event_process_posted(cycle, &ngx_posted_events);
[740]             }
[741]         }
[742] 
[743]         if (ngx_reopen) {
[744]             ngx_reopen = 0;
[745]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
[746]             ngx_reopen_files(cycle, -1);
[747]         }
[748]     }
[749] }
[750] 
[751] 
[752] static void
[753] ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker)
[754] {
[755]     sigset_t          set;
[756]     ngx_int_t         n;
[757]     ngx_time_t       *tp;
[758]     ngx_uint_t        i;
[759]     ngx_cpuset_t     *cpu_affinity;
[760]     struct rlimit     rlmt;
[761]     ngx_core_conf_t  *ccf;
[762] 
[763]     if (ngx_set_environment(cycle, NULL) == NULL) {
[764]         /* fatal */
[765]         exit(2);
[766]     }
[767] 
[768]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[769] 
[770]     if (worker >= 0 && ccf->priority != 0) {
[771]         if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
[772]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[773]                           "setpriority(%d) failed", ccf->priority);
[774]         }
[775]     }
[776] 
[777]     if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
[778]         rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
[779]         rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;
[780] 
[781]         if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
[782]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[783]                           "setrlimit(RLIMIT_NOFILE, %i) failed",
[784]                           ccf->rlimit_nofile);
[785]         }
[786]     }
[787] 
[788]     if (ccf->rlimit_core != NGX_CONF_UNSET) {
[789]         rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
[790]         rlmt.rlim_max = (rlim_t) ccf->rlimit_core;
[791] 
[792]         if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
[793]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[794]                           "setrlimit(RLIMIT_CORE, %O) failed",
[795]                           ccf->rlimit_core);
[796]         }
[797]     }
[798] 
[799]     if (geteuid() == 0) {
[800]         if (setgid(ccf->group) == -1) {
[801]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[802]                           "setgid(%d) failed", ccf->group);
[803]             /* fatal */
[804]             exit(2);
[805]         }
[806] 
[807]         if (initgroups(ccf->username, ccf->group) == -1) {
[808]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[809]                           "initgroups(%s, %d) failed",
[810]                           ccf->username, ccf->group);
[811]         }
[812] 
[813] #if (NGX_HAVE_PR_SET_KEEPCAPS && NGX_HAVE_CAPABILITIES)
[814]         if (ccf->transparent && ccf->user) {
[815]             if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
[816]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[817]                               "prctl(PR_SET_KEEPCAPS, 1) failed");
[818]                 /* fatal */
[819]                 exit(2);
[820]             }
[821]         }
[822] #endif
[823] 
[824]         if (setuid(ccf->user) == -1) {
[825]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[826]                           "setuid(%d) failed", ccf->user);
[827]             /* fatal */
[828]             exit(2);
[829]         }
[830] 
[831] #if (NGX_HAVE_CAPABILITIES)
[832]         if (ccf->transparent && ccf->user) {
[833]             struct __user_cap_data_struct    data;
[834]             struct __user_cap_header_struct  header;
[835] 
[836]             ngx_memzero(&header, sizeof(struct __user_cap_header_struct));
[837]             ngx_memzero(&data, sizeof(struct __user_cap_data_struct));
[838] 
[839]             header.version = _LINUX_CAPABILITY_VERSION_1;
[840]             data.effective = CAP_TO_MASK(CAP_NET_RAW);
[841]             data.permitted = data.effective;
[842] 
[843]             if (syscall(SYS_capset, &header, &data) == -1) {
[844]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[845]                               "capset() failed");
[846]                 /* fatal */
[847]                 exit(2);
[848]             }
[849]         }
[850] #endif
[851]     }
[852] 
[853]     if (worker >= 0) {
[854]         cpu_affinity = ngx_get_cpu_affinity(worker);
[855] 
[856]         if (cpu_affinity) {
[857]             ngx_setaffinity(cpu_affinity, cycle->log);
[858]         }
[859]     }
[860] 
[861] #if (NGX_HAVE_PR_SET_DUMPABLE)
[862] 
[863]     /* allow coredump after setuid() in Linux 2.4.x */
[864] 
[865]     if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
[866]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[867]                       "prctl(PR_SET_DUMPABLE) failed");
[868]     }
[869] 
[870] #endif
[871] 
[872]     if (ccf->working_directory.len) {
[873]         if (chdir((char *) ccf->working_directory.data) == -1) {
[874]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[875]                           "chdir(\"%s\") failed", ccf->working_directory.data);
[876]             /* fatal */
[877]             exit(2);
[878]         }
[879]     }
[880] 
[881]     sigemptyset(&set);
[882] 
[883]     if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
[884]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[885]                       "sigprocmask() failed");
[886]     }
[887] 
[888]     tp = ngx_timeofday();
[889]     srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);
[890] 
[891]     for (i = 0; cycle->modules[i]; i++) {
[892]         if (cycle->modules[i]->init_process) {
[893]             if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
[894]                 /* fatal */
[895]                 exit(2);
[896]             }
[897]         }
[898]     }
[899] 
[900]     for (n = 0; n < ngx_last_process; n++) {
[901] 
[902]         if (ngx_processes[n].pid == -1) {
[903]             continue;
[904]         }
[905] 
[906]         if (n == ngx_process_slot) {
[907]             continue;
[908]         }
[909] 
[910]         if (ngx_processes[n].channel[1] == -1) {
[911]             continue;
[912]         }
[913] 
[914]         if (close(ngx_processes[n].channel[1]) == -1) {
[915]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[916]                           "close() channel failed");
[917]         }
[918]     }
[919] 
[920]     if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
[921]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[922]                       "close() channel failed");
[923]     }
[924] 
[925] #if 0
[926]     ngx_last_process = 0;
[927] #endif
[928] 
[929]     if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
[930]                               ngx_channel_handler)
[931]         == NGX_ERROR)
[932]     {
[933]         /* fatal */
[934]         exit(2);
[935]     }
[936] }
[937] 
[938] 
[939] static void
[940] ngx_worker_process_exit(ngx_cycle_t *cycle)
[941] {
[942]     ngx_uint_t         i;
[943]     ngx_connection_t  *c;
[944] 
[945]     for (i = 0; cycle->modules[i]; i++) {
[946]         if (cycle->modules[i]->exit_process) {
[947]             cycle->modules[i]->exit_process(cycle);
[948]         }
[949]     }
[950] 
[951]     if (ngx_exiting) {
[952]         c = cycle->connections;
[953]         for (i = 0; i < cycle->connection_n; i++) {
[954]             if (c[i].fd != -1
[955]                 && c[i].read
[956]                 && !c[i].read->accept
[957]                 && !c[i].read->channel
[958]                 && !c[i].read->resolver)
[959]             {
[960]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[961]                               "*%uA open socket #%d left in connection %ui",
[962]                               c[i].number, c[i].fd, i);
[963]                 ngx_debug_quit = 1;
[964]             }
[965]         }
[966] 
[967]         if (ngx_debug_quit) {
[968]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "aborting");
[969]             ngx_debug_point();
[970]         }
[971]     }
[972] 
[973]     /*
[974]      * Copy ngx_cycle->log related data to the special static exit cycle,
[975]      * log, and log file structures enough to allow a signal handler to log.
[976]      * The handler may be called when standard ngx_cycle->log allocated from
[977]      * ngx_cycle->pool is already destroyed.
[978]      */
[979] 
[980]     ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);
[981] 
[982]     ngx_exit_log_file.fd = ngx_exit_log.file->fd;
[983]     ngx_exit_log.file = &ngx_exit_log_file;
[984]     ngx_exit_log.next = NULL;
[985]     ngx_exit_log.writer = NULL;
[986] 
[987]     ngx_exit_cycle.log = &ngx_exit_log;
[988]     ngx_exit_cycle.files = ngx_cycle->files;
[989]     ngx_exit_cycle.files_n = ngx_cycle->files_n;
[990]     ngx_cycle = &ngx_exit_cycle;
[991] 
[992]     ngx_destroy_pool(cycle->pool);
[993] 
[994]     ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "exit");
[995] 
[996]     exit(0);
[997] }
[998] 
[999] 
[1000] static void
[1001] ngx_channel_handler(ngx_event_t *ev)
[1002] {
[1003]     ngx_int_t          n;
[1004]     ngx_channel_t      ch;
[1005]     ngx_connection_t  *c;
[1006] 
[1007]     if (ev->timedout) {
[1008]         ev->timedout = 0;
[1009]         return;
[1010]     }
[1011] 
[1012]     c = ev->data;
[1013] 
[1014]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");
[1015] 
[1016]     for ( ;; ) {
[1017] 
[1018]         n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);
[1019] 
[1020]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);
[1021] 
[1022]         if (n == NGX_ERROR) {
[1023] 
[1024]             if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
[1025]                 ngx_del_conn(c, 0);
[1026]             }
[1027] 
[1028]             ngx_close_connection(c);
[1029]             return;
[1030]         }
[1031] 
[1032]         if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
[1033]             if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
[1034]                 return;
[1035]             }
[1036]         }
[1037] 
[1038]         if (n == NGX_AGAIN) {
[1039]             return;
[1040]         }
[1041] 
[1042]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
[1043]                        "channel command: %ui", ch.command);
[1044] 
[1045]         switch (ch.command) {
[1046] 
[1047]         case NGX_CMD_QUIT:
[1048]             ngx_quit = 1;
[1049]             break;
[1050] 
[1051]         case NGX_CMD_TERMINATE:
[1052]             ngx_terminate = 1;
[1053]             break;
[1054] 
[1055]         case NGX_CMD_REOPEN:
[1056]             ngx_reopen = 1;
[1057]             break;
[1058] 
[1059]         case NGX_CMD_OPEN_CHANNEL:
[1060] 
[1061]             ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
[1062]                            "get channel s:%i pid:%P fd:%d",
[1063]                            ch.slot, ch.pid, ch.fd);
[1064] 
[1065]             ngx_processes[ch.slot].pid = ch.pid;
[1066]             ngx_processes[ch.slot].channel[0] = ch.fd;
[1067]             break;
[1068] 
[1069]         case NGX_CMD_CLOSE_CHANNEL:
[1070] 
[1071]             ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
[1072]                            "close channel s:%i pid:%P our:%P fd:%d",
[1073]                            ch.slot, ch.pid, ngx_processes[ch.slot].pid,
[1074]                            ngx_processes[ch.slot].channel[0]);
[1075] 
[1076]             if (close(ngx_processes[ch.slot].channel[0]) == -1) {
[1077]                 ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[1078]                               "close() channel failed");
[1079]             }
[1080] 
[1081]             ngx_processes[ch.slot].channel[0] = -1;
[1082]             break;
[1083]         }
[1084]     }
[1085] }
[1086] 
[1087] 
[1088] static void
[1089] ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data)
[1090] {
[1091]     ngx_cache_manager_ctx_t *ctx = data;
[1092] 
[1093]     void         *ident[4];
[1094]     ngx_event_t   ev;
[1095] 
[1096]     /*
[1097]      * Set correct process type since closing listening Unix domain socket
[1098]      * in a master process also removes the Unix domain socket file.
[1099]      */
[1100]     ngx_process = NGX_PROCESS_HELPER;
[1101] 
[1102]     ngx_close_listening_sockets(cycle);
[1103] 
[1104]     /* Set a moderate number of connections for a helper process. */
[1105]     cycle->connection_n = 512;
[1106] 
[1107]     ngx_worker_process_init(cycle, -1);
[1108] 
[1109]     ngx_memzero(&ev, sizeof(ngx_event_t));
[1110]     ev.handler = ctx->handler;
[1111]     ev.data = ident;
[1112]     ev.log = cycle->log;
[1113]     ident[3] = (void *) -1;
[1114] 
[1115]     ngx_use_accept_mutex = 0;
[1116] 
[1117]     ngx_setproctitle(ctx->name);
[1118] 
[1119]     ngx_add_timer(&ev, ctx->delay);
[1120] 
[1121]     for ( ;; ) {
[1122] 
[1123]         if (ngx_terminate || ngx_quit) {
[1124]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[1125]             exit(0);
[1126]         }
[1127] 
[1128]         if (ngx_reopen) {
[1129]             ngx_reopen = 0;
[1130]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
[1131]             ngx_reopen_files(cycle, -1);
[1132]         }
[1133] 
[1134]         ngx_process_events_and_timers(cycle);
[1135]     }
[1136] }
[1137] 
[1138] 
[1139] static void
[1140] ngx_cache_manager_process_handler(ngx_event_t *ev)
[1141] {
[1142]     ngx_uint_t    i;
[1143]     ngx_msec_t    next, n;
[1144]     ngx_path_t  **path;
[1145] 
[1146]     next = 60 * 60 * 1000;
[1147] 
[1148]     path = ngx_cycle->paths.elts;
[1149]     for (i = 0; i < ngx_cycle->paths.nelts; i++) {
[1150] 
[1151]         if (path[i]->manager) {
[1152]             n = path[i]->manager(path[i]->data);
[1153] 
[1154]             next = (n <= next) ? n : next;
[1155] 
[1156]             ngx_time_update();
[1157]         }
[1158]     }
[1159] 
[1160]     if (next == 0) {
[1161]         next = 1;
[1162]     }
[1163] 
[1164]     ngx_add_timer(ev, next);
[1165] }
[1166] 
[1167] 
[1168] static void
[1169] ngx_cache_loader_process_handler(ngx_event_t *ev)
[1170] {
[1171]     ngx_uint_t     i;
[1172]     ngx_path_t   **path;
[1173]     ngx_cycle_t   *cycle;
[1174] 
[1175]     cycle = (ngx_cycle_t *) ngx_cycle;
[1176] 
[1177]     path = cycle->paths.elts;
[1178]     for (i = 0; i < cycle->paths.nelts; i++) {
[1179] 
[1180]         if (ngx_terminate || ngx_quit) {
[1181]             break;
[1182]         }
[1183] 
[1184]         if (path[i]->loader) {
[1185]             path[i]->loader(path[i]->data);
[1186]             ngx_time_update();
[1187]         }
[1188]     }
[1189] 
[1190]     exit(0);
[1191] }
