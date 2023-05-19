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
[11] #include <nginx.h>
[12] 
[13] 
[14] static void ngx_console_init(ngx_cycle_t *cycle);
[15] static int __stdcall ngx_console_handler(u_long type);
[16] static ngx_int_t ngx_create_signal_events(ngx_cycle_t *cycle);
[17] static ngx_int_t ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t type);
[18] static void ngx_reopen_worker_processes(ngx_cycle_t *cycle);
[19] static void ngx_quit_worker_processes(ngx_cycle_t *cycle, ngx_uint_t old);
[20] static void ngx_terminate_worker_processes(ngx_cycle_t *cycle);
[21] static ngx_uint_t ngx_reap_worker(ngx_cycle_t *cycle, HANDLE h);
[22] static void ngx_master_process_exit(ngx_cycle_t *cycle);
[23] static void ngx_worker_process_cycle(ngx_cycle_t *cycle, char *mevn);
[24] static void ngx_worker_process_exit(ngx_cycle_t *cycle);
[25] static ngx_thread_value_t __stdcall ngx_worker_thread(void *data);
[26] static ngx_thread_value_t __stdcall ngx_cache_manager_thread(void *data);
[27] static void ngx_cache_manager_process_handler(void);
[28] static ngx_thread_value_t __stdcall ngx_cache_loader_thread(void *data);
[29] 
[30] 
[31] ngx_uint_t     ngx_process;
[32] ngx_uint_t     ngx_worker;
[33] ngx_pid_t      ngx_pid;
[34] ngx_pid_t      ngx_parent;
[35] 
[36] ngx_uint_t     ngx_inherited;
[37] ngx_pid_t      ngx_new_binary;
[38] 
[39] sig_atomic_t   ngx_terminate;
[40] sig_atomic_t   ngx_quit;
[41] sig_atomic_t   ngx_reopen;
[42] sig_atomic_t   ngx_reconfigure;
[43] ngx_uint_t     ngx_exiting;
[44] 
[45] 
[46] HANDLE         ngx_master_process_event;
[47] char           ngx_master_process_event_name[NGX_PROCESS_SYNC_NAME];
[48] 
[49] static HANDLE  ngx_stop_event;
[50] static char    ngx_stop_event_name[NGX_PROCESS_SYNC_NAME];
[51] static HANDLE  ngx_quit_event;
[52] static char    ngx_quit_event_name[NGX_PROCESS_SYNC_NAME];
[53] static HANDLE  ngx_reopen_event;
[54] static char    ngx_reopen_event_name[NGX_PROCESS_SYNC_NAME];
[55] static HANDLE  ngx_reload_event;
[56] static char    ngx_reload_event_name[NGX_PROCESS_SYNC_NAME];
[57] 
[58] HANDLE         ngx_cache_manager_mutex;
[59] char           ngx_cache_manager_mutex_name[NGX_PROCESS_SYNC_NAME];
[60] HANDLE         ngx_cache_manager_event;
[61] 
[62] 
[63] void
[64] ngx_master_process_cycle(ngx_cycle_t *cycle)
[65] {
[66]     u_long      nev, ev, timeout;
[67]     ngx_err_t   err;
[68]     ngx_int_t   n;
[69]     ngx_msec_t  timer;
[70]     ngx_uint_t  live;
[71]     HANDLE      events[MAXIMUM_WAIT_OBJECTS];
[72] 
[73]     ngx_sprintf((u_char *) ngx_master_process_event_name,
[74]                 "ngx_master_%s%Z", ngx_unique);
[75] 
[76]     if (ngx_process == NGX_PROCESS_WORKER) {
[77]         ngx_worker_process_cycle(cycle, ngx_master_process_event_name);
[78]         return;
[79]     }
[80] 
[81]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "master started");
[82] 
[83]     ngx_console_init(cycle);
[84] 
[85]     SetEnvironmentVariable("ngx_unique", ngx_unique);
[86] 
[87]     ngx_master_process_event = CreateEvent(NULL, 1, 0,
[88]                                            ngx_master_process_event_name);
[89]     if (ngx_master_process_event == NULL) {
[90]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[91]                       "CreateEvent(\"%s\") failed",
[92]                       ngx_master_process_event_name);
[93]         exit(2);
[94]     }
[95] 
[96]     if (ngx_create_signal_events(cycle) != NGX_OK) {
[97]         exit(2);
[98]     }
[99] 
[100]     ngx_sprintf((u_char *) ngx_cache_manager_mutex_name,
[101]                 "ngx_cache_manager_mutex_%s%Z", ngx_unique);
[102] 
[103]     ngx_cache_manager_mutex = CreateMutex(NULL, 0,
[104]                                           ngx_cache_manager_mutex_name);
[105]     if (ngx_cache_manager_mutex == NULL) {
[106]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[107]                    "CreateMutex(\"%s\") failed", ngx_cache_manager_mutex_name);
[108]         exit(2);
[109]     }
[110] 
[111] 
[112]     events[0] = ngx_stop_event;
[113]     events[1] = ngx_quit_event;
[114]     events[2] = ngx_reopen_event;
[115]     events[3] = ngx_reload_event;
[116] 
[117]     ngx_close_listening_sockets(cycle);
[118] 
[119]     if (ngx_start_worker_processes(cycle, NGX_PROCESS_RESPAWN) == 0) {
[120]         exit(2);
[121]     }
[122] 
[123]     timer = 0;
[124]     timeout = INFINITE;
[125] 
[126]     for ( ;; ) {
[127] 
[128]         nev = 4;
[129]         for (n = 0; n < ngx_last_process; n++) {
[130]             if (ngx_processes[n].handle) {
[131]                 events[nev++] = ngx_processes[n].handle;
[132]             }
[133]         }
[134] 
[135]         if (timer) {
[136]             timeout = timer > ngx_current_msec ? timer - ngx_current_msec : 0;
[137]         }
[138] 
[139]         ev = WaitForMultipleObjects(nev, events, 0, timeout);
[140] 
[141]         err = ngx_errno;
[142]         ngx_time_update();
[143] 
[144]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[145]                        "master WaitForMultipleObjects: %ul", ev);
[146] 
[147]         if (ev == WAIT_OBJECT_0) {
[148]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[149] 
[150]             if (ResetEvent(ngx_stop_event) == 0) {
[151]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[152]                               "ResetEvent(\"%s\") failed", ngx_stop_event_name);
[153]             }
[154] 
[155]             if (timer == 0) {
[156]                 timer = ngx_current_msec + 5000;
[157]             }
[158] 
[159]             ngx_terminate = 1;
[160]             ngx_quit_worker_processes(cycle, 0);
[161] 
[162]             continue;
[163]         }
[164] 
[165]         if (ev == WAIT_OBJECT_0 + 1) {
[166]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "shutting down");
[167] 
[168]             if (ResetEvent(ngx_quit_event) == 0) {
[169]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[170]                               "ResetEvent(\"%s\") failed", ngx_quit_event_name);
[171]             }
[172] 
[173]             ngx_quit = 1;
[174]             ngx_quit_worker_processes(cycle, 0);
[175] 
[176]             continue;
[177]         }
[178] 
[179]         if (ev == WAIT_OBJECT_0 + 2) {
[180]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
[181] 
[182]             if (ResetEvent(ngx_reopen_event) == 0) {
[183]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[184]                               "ResetEvent(\"%s\") failed",
[185]                               ngx_reopen_event_name);
[186]             }
[187] 
[188]             ngx_reopen_files(cycle, -1);
[189]             ngx_reopen_worker_processes(cycle);
[190] 
[191]             continue;
[192]         }
[193] 
[194]         if (ev == WAIT_OBJECT_0 + 3) {
[195]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");
[196] 
[197]             if (ResetEvent(ngx_reload_event) == 0) {
[198]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[199]                               "ResetEvent(\"%s\") failed",
[200]                               ngx_reload_event_name);
[201]             }
[202] 
[203]             cycle = ngx_init_cycle(cycle);
[204]             if (cycle == NULL) {
[205]                 cycle = (ngx_cycle_t *) ngx_cycle;
[206]                 continue;
[207]             }
[208] 
[209]             ngx_cycle = cycle;
[210] 
[211]             ngx_close_listening_sockets(cycle);
[212] 
[213]             if (ngx_start_worker_processes(cycle, NGX_PROCESS_JUST_RESPAWN)) {
[214]                 ngx_quit_worker_processes(cycle, 1);
[215]             }
[216] 
[217]             continue;
[218]         }
[219] 
[220]         if (ev > WAIT_OBJECT_0 + 3 && ev < WAIT_OBJECT_0 + nev) {
[221] 
[222]             ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "reap worker");
[223] 
[224]             live = ngx_reap_worker(cycle, events[ev]);
[225] 
[226]             if (!live && (ngx_terminate || ngx_quit)) {
[227]                 ngx_master_process_exit(cycle);
[228]             }
[229] 
[230]             continue;
[231]         }
[232] 
[233]         if (ev == WAIT_TIMEOUT) {
[234]             ngx_terminate_worker_processes(cycle);
[235] 
[236]             ngx_master_process_exit(cycle);
[237]         }
[238] 
[239]         if (ev == WAIT_FAILED) {
[240]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[241]                           "WaitForMultipleObjects() failed");
[242] 
[243]             continue;
[244]         }
[245] 
[246]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[247]             "WaitForMultipleObjects() returned unexpected value %ul", ev);
[248]     }
[249] }
[250] 
[251] 
[252] static void
[253] ngx_console_init(ngx_cycle_t *cycle)
[254] {
[255]     ngx_core_conf_t  *ccf;
[256] 
[257]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[258] 
[259]     if (ccf->daemon) {
[260]         if (FreeConsole() == 0) {
[261]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[262]                           "FreeConsole() failed");
[263]         }
[264] 
[265]         return;
[266]     }
[267] 
[268]     if (SetConsoleCtrlHandler(ngx_console_handler, 1) == 0) {
[269]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[270]                       "SetConsoleCtrlHandler() failed");
[271]     }
[272] }
[273] 
[274] 
[275] static int __stdcall
[276] ngx_console_handler(u_long type)
[277] {
[278]     char  *msg;
[279] 
[280]     switch (type) {
[281] 
[282]     case CTRL_C_EVENT:
[283]         msg = "Ctrl-C pressed, exiting";
[284]         break;
[285] 
[286]     case CTRL_BREAK_EVENT:
[287]         msg = "Ctrl-Break pressed, exiting";
[288]         break;
[289] 
[290]     case CTRL_CLOSE_EVENT:
[291]         msg = "console closing, exiting";
[292]         break;
[293] 
[294]     case CTRL_LOGOFF_EVENT:
[295]         msg = "user logs off, exiting";
[296]         break;
[297] 
[298]     default:
[299]         return 0;
[300]     }
[301] 
[302]     ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, msg);
[303] 
[304]     if (ngx_stop_event == NULL) {
[305]         return 1;
[306]     }
[307] 
[308]     if (SetEvent(ngx_stop_event) == 0) {
[309]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[310]                       "SetEvent(\"%s\") failed", ngx_stop_event_name);
[311]     }
[312] 
[313]     return 1;
[314] }
[315] 
[316] 
[317] static ngx_int_t
[318] ngx_create_signal_events(ngx_cycle_t *cycle)
[319] {
[320]     ngx_sprintf((u_char *) ngx_stop_event_name,
[321]                 "Global\\ngx_stop_%s%Z", ngx_unique);
[322] 
[323]     ngx_stop_event = CreateEvent(NULL, 1, 0, ngx_stop_event_name);
[324]     if (ngx_stop_event == NULL) {
[325]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[326]                       "CreateEvent(\"%s\") failed", ngx_stop_event_name);
[327]         return NGX_ERROR;
[328]     }
[329] 
[330] 
[331]     ngx_sprintf((u_char *) ngx_quit_event_name,
[332]                 "Global\\ngx_quit_%s%Z", ngx_unique);
[333] 
[334]     ngx_quit_event = CreateEvent(NULL, 1, 0, ngx_quit_event_name);
[335]     if (ngx_quit_event == NULL) {
[336]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[337]                       "CreateEvent(\"%s\") failed", ngx_quit_event_name);
[338]         return NGX_ERROR;
[339]     }
[340] 
[341] 
[342]     ngx_sprintf((u_char *) ngx_reopen_event_name,
[343]                 "Global\\ngx_reopen_%s%Z", ngx_unique);
[344] 
[345]     ngx_reopen_event = CreateEvent(NULL, 1, 0, ngx_reopen_event_name);
[346]     if (ngx_reopen_event == NULL) {
[347]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[348]                       "CreateEvent(\"%s\") failed", ngx_reopen_event_name);
[349]         return NGX_ERROR;
[350]     }
[351] 
[352] 
[353]     ngx_sprintf((u_char *) ngx_reload_event_name,
[354]                 "Global\\ngx_reload_%s%Z", ngx_unique);
[355] 
[356]     ngx_reload_event = CreateEvent(NULL, 1, 0, ngx_reload_event_name);
[357]     if (ngx_reload_event == NULL) {
[358]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[359]                       "CreateEvent(\"%s\") failed", ngx_reload_event_name);
[360]         return NGX_ERROR;
[361]     }
[362] 
[363]     return NGX_OK;
[364] }
[365] 
[366] 
[367] static ngx_int_t
[368] ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t type)
[369] {
[370]     ngx_int_t         n;
[371]     ngx_core_conf_t  *ccf;
[372] 
[373]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");
[374] 
[375]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[376] 
[377]     for (n = 0; n < ccf->worker_processes; n++) {
[378]         if (ngx_spawn_process(cycle, "worker", type) == NGX_INVALID_PID) {
[379]             break;
[380]         }
[381]     }
[382] 
[383]     return n;
[384] }
[385] 
[386] 
[387] static void
[388] ngx_reopen_worker_processes(ngx_cycle_t *cycle)
[389] {
[390]     ngx_int_t  n;
[391] 
[392]     for (n = 0; n < ngx_last_process; n++) {
[393] 
[394]         if (ngx_processes[n].handle == NULL) {
[395]             continue;
[396]         }
[397] 
[398]         if (SetEvent(ngx_processes[n].reopen) == 0) {
[399]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[400]                           "SetEvent(\"%s\") failed",
[401]                           ngx_processes[n].reopen_event);
[402]         }
[403]     }
[404] }
[405] 
[406] 
[407] static void
[408] ngx_quit_worker_processes(ngx_cycle_t *cycle, ngx_uint_t old)
[409] {
[410]     ngx_int_t  n;
[411] 
[412]     for (n = 0; n < ngx_last_process; n++) {
[413] 
[414]         ngx_log_debug5(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[415]                        "process: %d %P %p e:%d j:%d",
[416]                        n,
[417]                        ngx_processes[n].pid,
[418]                        ngx_processes[n].handle,
[419]                        ngx_processes[n].exiting,
[420]                        ngx_processes[n].just_spawn);
[421] 
[422]         if (old && ngx_processes[n].just_spawn) {
[423]             ngx_processes[n].just_spawn = 0;
[424]             continue;
[425]         }
[426] 
[427]         if (ngx_processes[n].handle == NULL) {
[428]             continue;
[429]         }
[430] 
[431]         if (SetEvent(ngx_processes[n].quit) == 0) {
[432]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[433]                           "SetEvent(\"%s\") failed",
[434]                           ngx_processes[n].quit_event);
[435]         }
[436] 
[437]         ngx_processes[n].exiting = 1;
[438]     }
[439] }
[440] 
[441] 
[442] static void
[443] ngx_terminate_worker_processes(ngx_cycle_t *cycle)
[444] {
[445]     ngx_int_t  n;
[446] 
[447]     for (n = 0; n < ngx_last_process; n++) {
[448] 
[449]         if (ngx_processes[n].handle == NULL) {
[450]             continue;
[451]         }
[452] 
[453]         if (TerminateProcess(ngx_processes[n].handle, 0) == 0) {
[454]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[455]                           "TerminateProcess(\"%p\") failed",
[456]                           ngx_processes[n].handle);
[457]         }
[458] 
[459]         ngx_processes[n].exiting = 1;
[460] 
[461]         ngx_close_handle(ngx_processes[n].reopen);
[462]         ngx_close_handle(ngx_processes[n].quit);
[463]         ngx_close_handle(ngx_processes[n].term);
[464]         ngx_close_handle(ngx_processes[n].handle);
[465]     }
[466] }
[467] 
[468] 
[469] static ngx_uint_t
[470] ngx_reap_worker(ngx_cycle_t *cycle, HANDLE h)
[471] {
[472]     u_long     code;
[473]     ngx_int_t  n;
[474] 
[475]     for (n = 0; n < ngx_last_process; n++) {
[476] 
[477]         if (ngx_processes[n].handle != h) {
[478]             continue;
[479]         }
[480] 
[481]         if (GetExitCodeProcess(h, &code) == 0) {
[482]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[483]                           "GetExitCodeProcess(%P) failed",
[484]                           ngx_processes[n].pid);
[485]         }
[486] 
[487]         ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
[488]                       "%s process %P exited with code %Xl",
[489]                       ngx_processes[n].name, ngx_processes[n].pid, code);
[490] 
[491]         ngx_close_handle(ngx_processes[n].reopen);
[492]         ngx_close_handle(ngx_processes[n].quit);
[493]         ngx_close_handle(ngx_processes[n].term);
[494]         ngx_close_handle(h);
[495] 
[496]         ngx_processes[n].handle = NULL;
[497]         ngx_processes[n].term = NULL;
[498]         ngx_processes[n].quit = NULL;
[499]         ngx_processes[n].reopen = NULL;
[500] 
[501]         if (!ngx_processes[n].exiting && !ngx_terminate && !ngx_quit) {
[502] 
[503]             if (ngx_spawn_process(cycle, ngx_processes[n].name, n)
[504]                 == NGX_INVALID_PID)
[505]             {
[506]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[507]                               "could not respawn %s", ngx_processes[n].name);
[508] 
[509]                 if (n == ngx_last_process - 1) {
[510]                     ngx_last_process--;
[511]                 }
[512]             }
[513]         }
[514] 
[515]         goto found;
[516]     }
[517] 
[518]     ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "unknown process handle %p", h);
[519] 
[520] found:
[521] 
[522]     for (n = 0; n < ngx_last_process; n++) {
[523] 
[524]         ngx_log_debug5(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[525]                        "process: %d %P %p e:%d j:%d",
[526]                        n,
[527]                        ngx_processes[n].pid,
[528]                        ngx_processes[n].handle,
[529]                        ngx_processes[n].exiting,
[530]                        ngx_processes[n].just_spawn);
[531] 
[532]         if (ngx_processes[n].handle) {
[533]             return 1;
[534]         }
[535]     }
[536] 
[537]     return 0;
[538] }
[539] 
[540] 
[541] static void
[542] ngx_master_process_exit(ngx_cycle_t *cycle)
[543] {
[544]     ngx_uint_t  i;
[545] 
[546]     ngx_delete_pidfile(cycle);
[547] 
[548]     ngx_close_handle(ngx_cache_manager_mutex);
[549]     ngx_close_handle(ngx_stop_event);
[550]     ngx_close_handle(ngx_quit_event);
[551]     ngx_close_handle(ngx_reopen_event);
[552]     ngx_close_handle(ngx_reload_event);
[553]     ngx_close_handle(ngx_master_process_event);
[554] 
[555]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");
[556] 
[557]     for (i = 0; cycle->modules[i]; i++) {
[558]         if (cycle->modules[i]->exit_master) {
[559]             cycle->modules[i]->exit_master(cycle);
[560]         }
[561]     }
[562] 
[563]     ngx_destroy_pool(cycle->pool);
[564] 
[565]     exit(0);
[566] }
[567] 
[568] 
[569] static void
[570] ngx_worker_process_cycle(ngx_cycle_t *cycle, char *mevn)
[571] {
[572]     char        wtevn[NGX_PROCESS_SYNC_NAME];
[573]     char        wqevn[NGX_PROCESS_SYNC_NAME];
[574]     char        wroevn[NGX_PROCESS_SYNC_NAME];
[575]     HANDLE      mev, events[3];
[576]     u_long      nev, ev;
[577]     ngx_err_t   err;
[578]     ngx_tid_t   wtid, cmtid, cltid;
[579]     ngx_log_t  *log;
[580] 
[581]     log = cycle->log;
[582] 
[583]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "worker started");
[584] 
[585]     ngx_sprintf((u_char *) wtevn, "ngx_worker_term_%P%Z", ngx_pid);
[586]     events[0] = CreateEvent(NULL, 1, 0, wtevn);
[587]     if (events[0] == NULL) {
[588]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[589]                       "CreateEvent(\"%s\") failed", wtevn);
[590]         goto failed;
[591]     }
[592] 
[593]     ngx_sprintf((u_char *) wqevn, "ngx_worker_quit_%P%Z", ngx_pid);
[594]     events[1] = CreateEvent(NULL, 1, 0, wqevn);
[595]     if (events[1] == NULL) {
[596]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[597]                       "CreateEvent(\"%s\") failed", wqevn);
[598]         goto failed;
[599]     }
[600] 
[601]     ngx_sprintf((u_char *) wroevn, "ngx_worker_reopen_%P%Z", ngx_pid);
[602]     events[2] = CreateEvent(NULL, 1, 0, wroevn);
[603]     if (events[2] == NULL) {
[604]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[605]                       "CreateEvent(\"%s\") failed", wroevn);
[606]         goto failed;
[607]     }
[608] 
[609]     mev = OpenEvent(EVENT_MODIFY_STATE, 0, mevn);
[610]     if (mev == NULL) {
[611]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[612]                       "OpenEvent(\"%s\") failed", mevn);
[613]         goto failed;
[614]     }
[615] 
[616]     if (SetEvent(mev) == 0) {
[617]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[618]                       "SetEvent(\"%s\") failed", mevn);
[619]         goto failed;
[620]     }
[621] 
[622] 
[623]     ngx_sprintf((u_char *) ngx_cache_manager_mutex_name,
[624]                 "ngx_cache_manager_mutex_%s%Z", ngx_unique);
[625] 
[626]     ngx_cache_manager_mutex = OpenMutex(SYNCHRONIZE, 0,
[627]                                         ngx_cache_manager_mutex_name);
[628]     if (ngx_cache_manager_mutex == NULL) {
[629]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[630]                       "OpenMutex(\"%s\") failed", ngx_cache_manager_mutex_name);
[631]         goto failed;
[632]     }
[633] 
[634]     ngx_cache_manager_event = CreateEvent(NULL, 1, 0, NULL);
[635]     if (ngx_cache_manager_event == NULL) {
[636]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[637]                       "CreateEvent(\"ngx_cache_manager_event\") failed");
[638]         goto failed;
[639]     }
[640] 
[641] 
[642]     if (ngx_create_thread(&wtid, ngx_worker_thread, NULL, log) != 0) {
[643]         goto failed;
[644]     }
[645] 
[646]     if (ngx_create_thread(&cmtid, ngx_cache_manager_thread, NULL, log) != 0) {
[647]         goto failed;
[648]     }
[649] 
[650]     if (ngx_create_thread(&cltid, ngx_cache_loader_thread, NULL, log) != 0) {
[651]         goto failed;
[652]     }
[653] 
[654]     for ( ;; ) {
[655]         ev = WaitForMultipleObjects(3, events, 0, INFINITE);
[656] 
[657]         err = ngx_errno;
[658]         ngx_time_update();
[659] 
[660]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
[661]                        "worker WaitForMultipleObjects: %ul", ev);
[662] 
[663]         if (ev == WAIT_OBJECT_0) {
[664]             ngx_terminate = 1;
[665]             ngx_log_error(NGX_LOG_NOTICE, log, 0, "exiting");
[666] 
[667]             if (ResetEvent(events[0]) == 0) {
[668]                 ngx_log_error(NGX_LOG_ALERT, log, 0,
[669]                               "ResetEvent(\"%s\") failed", wtevn);
[670]             }
[671] 
[672]             break;
[673]         }
[674] 
[675]         if (ev == WAIT_OBJECT_0 + 1) {
[676]             ngx_quit = 1;
[677]             ngx_log_error(NGX_LOG_NOTICE, log, 0, "gracefully shutting down");
[678]             break;
[679]         }
[680] 
[681]         if (ev == WAIT_OBJECT_0 + 2) {
[682]             ngx_reopen = 1;
[683]             ngx_log_error(NGX_LOG_NOTICE, log, 0, "reopening logs");
[684] 
[685]             if (ResetEvent(events[2]) == 0) {
[686]                 ngx_log_error(NGX_LOG_ALERT, log, 0,
[687]                               "ResetEvent(\"%s\") failed", wroevn);
[688]             }
[689] 
[690]             continue;
[691]         }
[692] 
[693]         if (ev == WAIT_FAILED) {
[694]             ngx_log_error(NGX_LOG_ALERT, log, err,
[695]                           "WaitForMultipleObjects() failed");
[696] 
[697]             goto failed;
[698]         }
[699]     }
[700] 
[701]     /* wait threads */
[702] 
[703]     if (SetEvent(ngx_cache_manager_event) == 0) {
[704]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[705]                       "SetEvent(\"ngx_cache_manager_event\") failed");
[706]     }
[707] 
[708]     events[1] = wtid;
[709]     events[2] = cmtid;
[710] 
[711]     nev = 3;
[712] 
[713]     for ( ;; ) {
[714]         ev = WaitForMultipleObjects(nev, events, 0, INFINITE);
[715] 
[716]         err = ngx_errno;
[717]         ngx_time_update();
[718] 
[719]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
[720]                        "worker exit WaitForMultipleObjects: %ul", ev);
[721] 
[722]         if (ev == WAIT_OBJECT_0) {
[723]             break;
[724]         }
[725] 
[726]         if (ev == WAIT_OBJECT_0 + 1) {
[727]             if (nev == 2) {
[728]                 break;
[729]             }
[730] 
[731]             events[1] = events[2];
[732]             nev = 2;
[733]             continue;
[734]         }
[735] 
[736]         if (ev == WAIT_OBJECT_0 + 2) {
[737]             nev = 2;
[738]             continue;
[739]         }
[740] 
[741]         if (ev == WAIT_FAILED) {
[742]             ngx_log_error(NGX_LOG_ALERT, log, err,
[743]                           "WaitForMultipleObjects() failed");
[744]             break;
[745]         }
[746]     }
[747] 
[748]     ngx_close_handle(ngx_cache_manager_event);
[749]     ngx_close_handle(events[0]);
[750]     ngx_close_handle(events[1]);
[751]     ngx_close_handle(events[2]);
[752]     ngx_close_handle(mev);
[753] 
[754]     ngx_worker_process_exit(cycle);
[755] 
[756] failed:
[757] 
[758]     exit(2);
[759] }
[760] 
[761] 
[762] static ngx_thread_value_t __stdcall
[763] ngx_worker_thread(void *data)
[764] {
[765]     ngx_int_t     n;
[766]     ngx_time_t   *tp;
[767]     ngx_cycle_t  *cycle;
[768] 
[769]     tp = ngx_timeofday();
[770]     srand((ngx_pid << 16) ^ (unsigned) tp->sec ^ tp->msec);
[771] 
[772]     cycle = (ngx_cycle_t *) ngx_cycle;
[773] 
[774]     for (n = 0; cycle->modules[n]; n++) {
[775]         if (cycle->modules[n]->init_process) {
[776]             if (cycle->modules[n]->init_process(cycle) == NGX_ERROR) {
[777]                 /* fatal */
[778]                 exit(2);
[779]             }
[780]         }
[781]     }
[782] 
[783]     while (!ngx_quit) {
[784] 
[785]         if (ngx_exiting) {
[786]             if (ngx_event_no_timers_left() == NGX_OK) {
[787]                 break;
[788]             }
[789]         }
[790] 
[791]         ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "worker cycle");
[792] 
[793]         ngx_process_events_and_timers(cycle);
[794] 
[795]         if (ngx_terminate) {
[796]             return 0;
[797]         }
[798] 
[799]         if (ngx_quit) {
[800]             ngx_quit = 0;
[801] 
[802]             if (!ngx_exiting) {
[803]                 ngx_exiting = 1;
[804]                 ngx_set_shutdown_timer(cycle);
[805]                 ngx_close_listening_sockets(cycle);
[806]                 ngx_close_idle_connections(cycle);
[807]                 ngx_event_process_posted(cycle, &ngx_posted_events);
[808]             }
[809]         }
[810] 
[811]         if (ngx_reopen) {
[812]             ngx_reopen = 0;
[813]             ngx_reopen_files(cycle, -1);
[814]         }
[815]     }
[816] 
[817]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[818] 
[819]     return 0;
[820] }
[821] 
[822] 
[823] static void
[824] ngx_worker_process_exit(ngx_cycle_t *cycle)
[825] {
[826]     ngx_uint_t         i;
[827]     ngx_connection_t  *c;
[828] 
[829]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");
[830] 
[831]     for (i = 0; cycle->modules[i]; i++) {
[832]         if (cycle->modules[i]->exit_process) {
[833]             cycle->modules[i]->exit_process(cycle);
[834]         }
[835]     }
[836] 
[837]     if (ngx_exiting) {
[838]         c = cycle->connections;
[839]         for (i = 0; i < cycle->connection_n; i++) {
[840]             if (c[i].fd != (ngx_socket_t) -1
[841]                 && c[i].read
[842]                 && !c[i].read->accept
[843]                 && !c[i].read->channel
[844]                 && !c[i].read->resolver)
[845]             {
[846]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[847]                               "*%uA open socket #%d left in connection %ui",
[848]                               c[i].number, c[i].fd, i);
[849]             }
[850]         }
[851]     }
[852] 
[853]     ngx_destroy_pool(cycle->pool);
[854] 
[855]     exit(0);
[856] }
[857] 
[858] 
[859] static ngx_thread_value_t __stdcall
[860] ngx_cache_manager_thread(void *data)
[861] {
[862]     u_long        ev;
[863]     HANDLE        events[2];
[864]     ngx_err_t     err;
[865]     ngx_cycle_t  *cycle;
[866] 
[867]     cycle = (ngx_cycle_t *) ngx_cycle;
[868] 
[869]     events[0] = ngx_cache_manager_event;
[870]     events[1] = ngx_cache_manager_mutex;
[871] 
[872]     for ( ;; ) {
[873]         ev = WaitForMultipleObjects(2, events, 0, INFINITE);
[874] 
[875]         err = ngx_errno;
[876]         ngx_time_update();
[877] 
[878]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[879]                        "cache manager WaitForMultipleObjects: %ul", ev);
[880] 
[881]         if (ev == WAIT_FAILED) {
[882]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[883]                           "WaitForMultipleObjects() failed");
[884]         }
[885] 
[886]         /*
[887]          * ev == WAIT_OBJECT_0
[888]          * ev == WAIT_OBJECT_0 + 1
[889]          * ev == WAIT_ABANDONED_0 + 1
[890]          */
[891] 
[892]         if (ngx_terminate || ngx_quit || ngx_exiting) {
[893]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[894]             return 0;
[895]         }
[896] 
[897]         break;
[898]     }
[899] 
[900]     for ( ;; ) {
[901] 
[902]         if (ngx_terminate || ngx_quit || ngx_exiting) {
[903]             ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
[904]             break;
[905]         }
[906] 
[907]         ngx_cache_manager_process_handler();
[908]     }
[909] 
[910]     if (ReleaseMutex(ngx_cache_manager_mutex) == 0) {
[911]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[912]                       "ReleaseMutex() failed");
[913]     }
[914] 
[915]     return 0;
[916] }
[917] 
[918] 
[919] static void
[920] ngx_cache_manager_process_handler(void)
[921] {
[922]     u_long        ev;
[923]     ngx_uint_t    i;
[924]     ngx_msec_t    next, n;
[925]     ngx_path_t  **path;
[926] 
[927]     next = 60 * 60 * 1000;
[928] 
[929]     path = ngx_cycle->paths.elts;
[930]     for (i = 0; i < ngx_cycle->paths.nelts; i++) {
[931] 
[932]         if (path[i]->manager) {
[933]             n = path[i]->manager(path[i]->data);
[934] 
[935]             next = (n <= next) ? n : next;
[936] 
[937]             ngx_time_update();
[938]         }
[939]     }
[940] 
[941]     if (next == 0) {
[942]         next = 1;
[943]     }
[944] 
[945]     ev = WaitForSingleObject(ngx_cache_manager_event, (u_long) next);
[946] 
[947]     if (ev != WAIT_TIMEOUT) {
[948] 
[949]         ngx_time_update();
[950] 
[951]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[952]                        "cache manager WaitForSingleObject: %ul", ev);
[953]     }
[954] }
[955] 
[956] 
[957] static ngx_thread_value_t __stdcall
[958] ngx_cache_loader_thread(void *data)
[959] {
[960]     ngx_uint_t     i;
[961]     ngx_path_t   **path;
[962]     ngx_cycle_t   *cycle;
[963] 
[964]     ngx_msleep(60000);
[965] 
[966]     cycle = (ngx_cycle_t *) ngx_cycle;
[967] 
[968]     path = cycle->paths.elts;
[969]     for (i = 0; i < cycle->paths.nelts; i++) {
[970] 
[971]         if (ngx_terminate || ngx_quit || ngx_exiting) {
[972]             break;
[973]         }
[974] 
[975]         if (path[i]->loader) {
[976]             path[i]->loader(path[i]->data);
[977]             ngx_time_update();
[978]         }
[979]     }
[980] 
[981]     return 0;
[982] }
[983] 
[984] 
[985] void
[986] ngx_single_process_cycle(ngx_cycle_t *cycle)
[987] {
[988]     ngx_tid_t  tid;
[989] 
[990]     ngx_console_init(cycle);
[991] 
[992]     if (ngx_create_signal_events(cycle) != NGX_OK) {
[993]         exit(2);
[994]     }
[995] 
[996]     if (ngx_create_thread(&tid, ngx_worker_thread, NULL, cycle->log) != 0) {
[997]         /* fatal */
[998]         exit(2);
[999]     }
[1000] 
[1001]     /* STUB */
[1002]     WaitForSingleObject(ngx_stop_event, INFINITE);
[1003] }
[1004] 
[1005] 
[1006] ngx_int_t
[1007] ngx_os_signal_process(ngx_cycle_t *cycle, char *sig, ngx_pid_t pid)
[1008] {
[1009]     HANDLE     ev;
[1010]     ngx_int_t  rc;
[1011]     char       evn[NGX_PROCESS_SYNC_NAME];
[1012] 
[1013]     ngx_sprintf((u_char *) evn, "Global\\ngx_%s_%P%Z", sig, pid);
[1014] 
[1015]     ev = OpenEvent(EVENT_MODIFY_STATE, 0, evn);
[1016]     if (ev == NULL) {
[1017]         ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
[1018]                       "OpenEvent(\"%s\") failed", evn);
[1019]         return 1;
[1020]     }
[1021] 
[1022]     if (SetEvent(ev) == 0) {
[1023]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[1024]                       "SetEvent(\"%s\") failed", evn);
[1025]         rc = 1;
[1026] 
[1027]     } else {
[1028]         rc = 0;
[1029]     }
[1030] 
[1031]     ngx_close_handle(ev);
[1032] 
[1033]     return rc;
[1034] }
[1035] 
[1036] 
[1037] void
[1038] ngx_close_handle(HANDLE h)
[1039] {
[1040]     if (CloseHandle(h) == 0) {
[1041]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
[1042]                       "CloseHandle(%p) failed", h);
[1043]     }
[1044] }
