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
[14] typedef struct {
[15]     int     signo;
[16]     char   *signame;
[17]     char   *name;
[18]     void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
[19] } ngx_signal_t;
[20] 
[21] 
[22] 
[23] static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
[24] static void ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);
[25] static void ngx_process_get_status(void);
[26] static void ngx_unlock_mutexes(ngx_pid_t pid);
[27] 
[28] 
[29] int              ngx_argc;
[30] char           **ngx_argv;
[31] char           **ngx_os_argv;
[32] 
[33] ngx_int_t        ngx_process_slot;
[34] ngx_socket_t     ngx_channel;
[35] ngx_int_t        ngx_last_process;
[36] ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];
[37] 
[38] 
[39] ngx_signal_t  signals[] = {
[40]     { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),
[41]       "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
[42]       "reload",
[43]       ngx_signal_handler },
[44] 
[45]     { ngx_signal_value(NGX_REOPEN_SIGNAL),
[46]       "SIG" ngx_value(NGX_REOPEN_SIGNAL),
[47]       "reopen",
[48]       ngx_signal_handler },
[49] 
[50]     { ngx_signal_value(NGX_NOACCEPT_SIGNAL),
[51]       "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
[52]       "",
[53]       ngx_signal_handler },
[54] 
[55]     { ngx_signal_value(NGX_TERMINATE_SIGNAL),
[56]       "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
[57]       "stop",
[58]       ngx_signal_handler },
[59] 
[60]     { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
[61]       "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
[62]       "quit",
[63]       ngx_signal_handler },
[64] 
[65]     { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
[66]       "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
[67]       "",
[68]       ngx_signal_handler },
[69] 
[70]     { SIGALRM, "SIGALRM", "", ngx_signal_handler },
[71] 
[72]     { SIGINT, "SIGINT", "", ngx_signal_handler },
[73] 
[74]     { SIGIO, "SIGIO", "", ngx_signal_handler },
[75] 
[76]     { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },
[77] 
[78]     { SIGSYS, "SIGSYS, SIG_IGN", "", NULL },
[79] 
[80]     { SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },
[81] 
[82]     { 0, NULL, "", NULL }
[83] };
[84] 
[85] 
[86] ngx_pid_t
[87] ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
[88]     char *name, ngx_int_t respawn)
[89] {
[90]     u_long     on;
[91]     ngx_pid_t  pid;
[92]     ngx_int_t  s;
[93] 
[94]     if (respawn >= 0) {
[95]         s = respawn;
[96] 
[97]     } else {
[98]         for (s = 0; s < ngx_last_process; s++) {
[99]             if (ngx_processes[s].pid == -1) {
[100]                 break;
[101]             }
[102]         }
[103] 
[104]         if (s == NGX_MAX_PROCESSES) {
[105]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[106]                           "no more than %d processes can be spawned",
[107]                           NGX_MAX_PROCESSES);
[108]             return NGX_INVALID_PID;
[109]         }
[110]     }
[111] 
[112] 
[113]     if (respawn != NGX_PROCESS_DETACHED) {
[114] 
[115]         /* Solaris 9 still has no AF_LOCAL */
[116] 
[117]         if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
[118]         {
[119]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[120]                           "socketpair() failed while spawning \"%s\"", name);
[121]             return NGX_INVALID_PID;
[122]         }
[123] 
[124]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[125]                        "channel %d:%d",
[126]                        ngx_processes[s].channel[0],
[127]                        ngx_processes[s].channel[1]);
[128] 
[129]         if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
[130]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[131]                           ngx_nonblocking_n " failed while spawning \"%s\"",
[132]                           name);
[133]             ngx_close_channel(ngx_processes[s].channel, cycle->log);
[134]             return NGX_INVALID_PID;
[135]         }
[136] 
[137]         if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
[138]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[139]                           ngx_nonblocking_n " failed while spawning \"%s\"",
[140]                           name);
[141]             ngx_close_channel(ngx_processes[s].channel, cycle->log);
[142]             return NGX_INVALID_PID;
[143]         }
[144] 
[145]         on = 1;
[146]         if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
[147]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[148]                           "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
[149]             ngx_close_channel(ngx_processes[s].channel, cycle->log);
[150]             return NGX_INVALID_PID;
[151]         }
[152] 
[153]         if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
[154]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[155]                           "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
[156]             ngx_close_channel(ngx_processes[s].channel, cycle->log);
[157]             return NGX_INVALID_PID;
[158]         }
[159] 
[160]         if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
[161]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[162]                           "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
[163]                            name);
[164]             ngx_close_channel(ngx_processes[s].channel, cycle->log);
[165]             return NGX_INVALID_PID;
[166]         }
[167] 
[168]         if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
[169]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[170]                           "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
[171]                            name);
[172]             ngx_close_channel(ngx_processes[s].channel, cycle->log);
[173]             return NGX_INVALID_PID;
[174]         }
[175] 
[176]         ngx_channel = ngx_processes[s].channel[1];
[177] 
[178]     } else {
[179]         ngx_processes[s].channel[0] = -1;
[180]         ngx_processes[s].channel[1] = -1;
[181]     }
[182] 
[183]     ngx_process_slot = s;
[184] 
[185] 
[186]     pid = fork();
[187] 
[188]     switch (pid) {
[189] 
[190]     case -1:
[191]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[192]                       "fork() failed while spawning \"%s\"", name);
[193]         ngx_close_channel(ngx_processes[s].channel, cycle->log);
[194]         return NGX_INVALID_PID;
[195] 
[196]     case 0:
[197]         ngx_parent = ngx_pid;
[198]         ngx_pid = ngx_getpid();
[199]         proc(cycle, data);
[200]         break;
[201] 
[202]     default:
[203]         break;
[204]     }
[205] 
[206]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);
[207] 
[208]     ngx_processes[s].pid = pid;
[209]     ngx_processes[s].exited = 0;
[210] 
[211]     if (respawn >= 0) {
[212]         return pid;
[213]     }
[214] 
[215]     ngx_processes[s].proc = proc;
[216]     ngx_processes[s].data = data;
[217]     ngx_processes[s].name = name;
[218]     ngx_processes[s].exiting = 0;
[219] 
[220]     switch (respawn) {
[221] 
[222]     case NGX_PROCESS_NORESPAWN:
[223]         ngx_processes[s].respawn = 0;
[224]         ngx_processes[s].just_spawn = 0;
[225]         ngx_processes[s].detached = 0;
[226]         break;
[227] 
[228]     case NGX_PROCESS_JUST_SPAWN:
[229]         ngx_processes[s].respawn = 0;
[230]         ngx_processes[s].just_spawn = 1;
[231]         ngx_processes[s].detached = 0;
[232]         break;
[233] 
[234]     case NGX_PROCESS_RESPAWN:
[235]         ngx_processes[s].respawn = 1;
[236]         ngx_processes[s].just_spawn = 0;
[237]         ngx_processes[s].detached = 0;
[238]         break;
[239] 
[240]     case NGX_PROCESS_JUST_RESPAWN:
[241]         ngx_processes[s].respawn = 1;
[242]         ngx_processes[s].just_spawn = 1;
[243]         ngx_processes[s].detached = 0;
[244]         break;
[245] 
[246]     case NGX_PROCESS_DETACHED:
[247]         ngx_processes[s].respawn = 0;
[248]         ngx_processes[s].just_spawn = 0;
[249]         ngx_processes[s].detached = 1;
[250]         break;
[251]     }
[252] 
[253]     if (s == ngx_last_process) {
[254]         ngx_last_process++;
[255]     }
[256] 
[257]     return pid;
[258] }
[259] 
[260] 
[261] ngx_pid_t
[262] ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
[263] {
[264]     return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
[265]                              NGX_PROCESS_DETACHED);
[266] }
[267] 
[268] 
[269] static void
[270] ngx_execute_proc(ngx_cycle_t *cycle, void *data)
[271] {
[272]     ngx_exec_ctx_t  *ctx = data;
[273] 
[274]     if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
[275]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[276]                       "execve() failed while executing %s \"%s\"",
[277]                       ctx->name, ctx->path);
[278]     }
[279] 
[280]     exit(1);
[281] }
[282] 
[283] 
[284] ngx_int_t
[285] ngx_init_signals(ngx_log_t *log)
[286] {
[287]     ngx_signal_t      *sig;
[288]     struct sigaction   sa;
[289] 
[290]     for (sig = signals; sig->signo != 0; sig++) {
[291]         ngx_memzero(&sa, sizeof(struct sigaction));
[292] 
[293]         if (sig->handler) {
[294]             sa.sa_sigaction = sig->handler;
[295]             sa.sa_flags = SA_SIGINFO;
[296] 
[297]         } else {
[298]             sa.sa_handler = SIG_IGN;
[299]         }
[300] 
[301]         sigemptyset(&sa.sa_mask);
[302]         if (sigaction(sig->signo, &sa, NULL) == -1) {
[303] #if (NGX_VALGRIND)
[304]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[305]                           "sigaction(%s) failed, ignored", sig->signame);
[306] #else
[307]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[308]                           "sigaction(%s) failed", sig->signame);
[309]             return NGX_ERROR;
[310] #endif
[311]         }
[312]     }
[313] 
[314]     return NGX_OK;
[315] }
[316] 
[317] 
[318] static void
[319] ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext)
[320] {
[321]     char            *action;
[322]     ngx_int_t        ignore;
[323]     ngx_err_t        err;
[324]     ngx_signal_t    *sig;
[325] 
[326]     ignore = 0;
[327] 
[328]     err = ngx_errno;
[329] 
[330]     for (sig = signals; sig->signo != 0; sig++) {
[331]         if (sig->signo == signo) {
[332]             break;
[333]         }
[334]     }
[335] 
[336]     ngx_time_sigsafe_update();
[337] 
[338]     action = "";
[339] 
[340]     switch (ngx_process) {
[341] 
[342]     case NGX_PROCESS_MASTER:
[343]     case NGX_PROCESS_SINGLE:
[344]         switch (signo) {
[345] 
[346]         case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
[347]             ngx_quit = 1;
[348]             action = ", shutting down";
[349]             break;
[350] 
[351]         case ngx_signal_value(NGX_TERMINATE_SIGNAL):
[352]         case SIGINT:
[353]             ngx_terminate = 1;
[354]             action = ", exiting";
[355]             break;
[356] 
[357]         case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
[358]             if (ngx_daemonized) {
[359]                 ngx_noaccept = 1;
[360]                 action = ", stop accepting connections";
[361]             }
[362]             break;
[363] 
[364]         case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
[365]             ngx_reconfigure = 1;
[366]             action = ", reconfiguring";
[367]             break;
[368] 
[369]         case ngx_signal_value(NGX_REOPEN_SIGNAL):
[370]             ngx_reopen = 1;
[371]             action = ", reopening logs";
[372]             break;
[373] 
[374]         case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
[375]             if (ngx_getppid() == ngx_parent || ngx_new_binary > 0) {
[376] 
[377]                 /*
[378]                  * Ignore the signal in the new binary if its parent is
[379]                  * not changed, i.e. the old binary's process is still
[380]                  * running.  Or ignore the signal in the old binary's
[381]                  * process if the new binary's process is already running.
[382]                  */
[383] 
[384]                 action = ", ignoring";
[385]                 ignore = 1;
[386]                 break;
[387]             }
[388] 
[389]             ngx_change_binary = 1;
[390]             action = ", changing binary";
[391]             break;
[392] 
[393]         case SIGALRM:
[394]             ngx_sigalrm = 1;
[395]             break;
[396] 
[397]         case SIGIO:
[398]             ngx_sigio = 1;
[399]             break;
[400] 
[401]         case SIGCHLD:
[402]             ngx_reap = 1;
[403]             break;
[404]         }
[405] 
[406]         break;
[407] 
[408]     case NGX_PROCESS_WORKER:
[409]     case NGX_PROCESS_HELPER:
[410]         switch (signo) {
[411] 
[412]         case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
[413]             if (!ngx_daemonized) {
[414]                 break;
[415]             }
[416]             ngx_debug_quit = 1;
[417]             /* fall through */
[418]         case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
[419]             ngx_quit = 1;
[420]             action = ", shutting down";
[421]             break;
[422] 
[423]         case ngx_signal_value(NGX_TERMINATE_SIGNAL):
[424]         case SIGINT:
[425]             ngx_terminate = 1;
[426]             action = ", exiting";
[427]             break;
[428] 
[429]         case ngx_signal_value(NGX_REOPEN_SIGNAL):
[430]             ngx_reopen = 1;
[431]             action = ", reopening logs";
[432]             break;
[433] 
[434]         case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
[435]         case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
[436]         case SIGIO:
[437]             action = ", ignoring";
[438]             break;
[439]         }
[440] 
[441]         break;
[442]     }
[443] 
[444]     if (siginfo && siginfo->si_pid) {
[445]         ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
[446]                       "signal %d (%s) received from %P%s",
[447]                       signo, sig->signame, siginfo->si_pid, action);
[448] 
[449]     } else {
[450]         ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
[451]                       "signal %d (%s) received%s",
[452]                       signo, sig->signame, action);
[453]     }
[454] 
[455]     if (ignore) {
[456]         ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
[457]                       "the changing binary signal is ignored: "
[458]                       "you should shutdown or terminate "
[459]                       "before either old or new binary's process");
[460]     }
[461] 
[462]     if (signo == SIGCHLD) {
[463]         ngx_process_get_status();
[464]     }
[465] 
[466]     ngx_set_errno(err);
[467] }
[468] 
[469] 
[470] static void
[471] ngx_process_get_status(void)
[472] {
[473]     int              status;
[474]     char            *process;
[475]     ngx_pid_t        pid;
[476]     ngx_err_t        err;
[477]     ngx_int_t        i;
[478]     ngx_uint_t       one;
[479] 
[480]     one = 0;
[481] 
[482]     for ( ;; ) {
[483]         pid = waitpid(-1, &status, WNOHANG);
[484] 
[485]         if (pid == 0) {
[486]             return;
[487]         }
[488] 
[489]         if (pid == -1) {
[490]             err = ngx_errno;
[491] 
[492]             if (err == NGX_EINTR) {
[493]                 continue;
[494]             }
[495] 
[496]             if (err == NGX_ECHILD && one) {
[497]                 return;
[498]             }
[499] 
[500]             /*
[501]              * Solaris always calls the signal handler for each exited process
[502]              * despite waitpid() may be already called for this process.
[503]              *
[504]              * When several processes exit at the same time FreeBSD may
[505]              * erroneously call the signal handler for exited process
[506]              * despite waitpid() may be already called for this process.
[507]              */
[508] 
[509]             if (err == NGX_ECHILD) {
[510]                 ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
[511]                               "waitpid() failed");
[512]                 return;
[513]             }
[514] 
[515]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
[516]                           "waitpid() failed");
[517]             return;
[518]         }
[519] 
[520] 
[521]         one = 1;
[522]         process = "unknown process";
[523] 
[524]         for (i = 0; i < ngx_last_process; i++) {
[525]             if (ngx_processes[i].pid == pid) {
[526]                 ngx_processes[i].status = status;
[527]                 ngx_processes[i].exited = 1;
[528]                 process = ngx_processes[i].name;
[529]                 break;
[530]             }
[531]         }
[532] 
[533]         if (WTERMSIG(status)) {
[534] #ifdef WCOREDUMP
[535]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[536]                           "%s %P exited on signal %d%s",
[537]                           process, pid, WTERMSIG(status),
[538]                           WCOREDUMP(status) ? " (core dumped)" : "");
[539] #else
[540]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[541]                           "%s %P exited on signal %d",
[542]                           process, pid, WTERMSIG(status));
[543] #endif
[544] 
[545]         } else {
[546]             ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
[547]                           "%s %P exited with code %d",
[548]                           process, pid, WEXITSTATUS(status));
[549]         }
[550] 
[551]         if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
[552]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[553]                           "%s %P exited with fatal code %d "
[554]                           "and cannot be respawned",
[555]                           process, pid, WEXITSTATUS(status));
[556]             ngx_processes[i].respawn = 0;
[557]         }
[558] 
[559]         ngx_unlock_mutexes(pid);
[560]     }
[561] }
[562] 
[563] 
[564] static void
[565] ngx_unlock_mutexes(ngx_pid_t pid)
[566] {
[567]     ngx_uint_t        i;
[568]     ngx_shm_zone_t   *shm_zone;
[569]     ngx_list_part_t  *part;
[570]     ngx_slab_pool_t  *sp;
[571] 
[572]     /*
[573]      * unlock the accept mutex if the abnormally exited process
[574]      * held it
[575]      */
[576] 
[577]     if (ngx_accept_mutex_ptr) {
[578]         (void) ngx_shmtx_force_unlock(&ngx_accept_mutex, pid);
[579]     }
[580] 
[581]     /*
[582]      * unlock shared memory mutexes if held by the abnormally exited
[583]      * process
[584]      */
[585] 
[586]     part = (ngx_list_part_t *) &ngx_cycle->shared_memory.part;
[587]     shm_zone = part->elts;
[588] 
[589]     for (i = 0; /* void */ ; i++) {
[590] 
[591]         if (i >= part->nelts) {
[592]             if (part->next == NULL) {
[593]                 break;
[594]             }
[595]             part = part->next;
[596]             shm_zone = part->elts;
[597]             i = 0;
[598]         }
[599] 
[600]         sp = (ngx_slab_pool_t *) shm_zone[i].shm.addr;
[601] 
[602]         if (ngx_shmtx_force_unlock(&sp->mutex, pid)) {
[603]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[604]                           "shared memory zone \"%V\" was locked by %P",
[605]                           &shm_zone[i].shm.name, pid);
[606]         }
[607]     }
[608] }
[609] 
[610] 
[611] void
[612] ngx_debug_point(void)
[613] {
[614]     ngx_core_conf_t  *ccf;
[615] 
[616]     ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
[617]                                            ngx_core_module);
[618] 
[619]     switch (ccf->debug_points) {
[620] 
[621]     case NGX_DEBUG_POINTS_STOP:
[622]         raise(SIGSTOP);
[623]         break;
[624] 
[625]     case NGX_DEBUG_POINTS_ABORT:
[626]         ngx_abort();
[627]     }
[628] }
[629] 
[630] 
[631] ngx_int_t
[632] ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_pid_t pid)
[633] {
[634]     ngx_signal_t  *sig;
[635] 
[636]     for (sig = signals; sig->signo != 0; sig++) {
[637]         if (ngx_strcmp(name, sig->name) == 0) {
[638]             if (kill(pid, sig->signo) != -1) {
[639]                 return 0;
[640]             }
[641] 
[642]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[643]                           "kill(%P, %d) failed", pid, sig->signo);
[644]         }
[645]     }
[646] 
[647]     return 1;
[648] }
