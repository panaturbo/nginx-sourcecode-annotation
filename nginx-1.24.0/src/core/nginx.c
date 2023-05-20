[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <nginx.h>
[11] 
[12] 
[13] static void ngx_show_version_info(void);
[14] static ngx_int_t ngx_add_inherited_sockets(ngx_cycle_t *cycle);
[15] static void ngx_cleanup_environment(void *data);
[16] static ngx_int_t ngx_get_options(int argc, char *const *argv);
[17] static ngx_int_t ngx_process_options(ngx_cycle_t *cycle);
[18] static ngx_int_t ngx_save_argv(ngx_cycle_t *cycle, int argc, char *const *argv);
[19] static void *ngx_core_module_create_conf(ngx_cycle_t *cycle);
[20] static char *ngx_core_module_init_conf(ngx_cycle_t *cycle, void *conf);
[21] static char *ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[22] static char *ngx_set_env(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[23] static char *ngx_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[24] static char *ngx_set_cpu_affinity(ngx_conf_t *cf, ngx_command_t *cmd,
[25]     void *conf);
[26] static char *ngx_set_worker_processes(ngx_conf_t *cf, ngx_command_t *cmd,
[27]     void *conf);
[28] static char *ngx_load_module(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[29] #if (NGX_HAVE_DLOPEN)
[30] static void ngx_unload_module(void *data);
[31] #endif
[32] 
[33] 
[34] static ngx_conf_enum_t  ngx_debug_points[] = {
[35]     { ngx_string("stop"), NGX_DEBUG_POINTS_STOP },
[36]     { ngx_string("abort"), NGX_DEBUG_POINTS_ABORT },
[37]     { ngx_null_string, 0 }
[38] };
[39] 
[40] 
[41] static ngx_command_t  ngx_core_commands[] = {
[42] 
[43]     { ngx_string("daemon"),
[44]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
[45]       ngx_conf_set_flag_slot,
[46]       0,
[47]       offsetof(ngx_core_conf_t, daemon),
[48]       NULL },
[49] 
[50]     { ngx_string("master_process"),
[51]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
[52]       ngx_conf_set_flag_slot,
[53]       0,
[54]       offsetof(ngx_core_conf_t, master),
[55]       NULL },
[56] 
[57]     { ngx_string("timer_resolution"),
[58]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[59]       ngx_conf_set_msec_slot,
[60]       0,
[61]       offsetof(ngx_core_conf_t, timer_resolution),
[62]       NULL },
[63] 
[64]     { ngx_string("pid"),
[65]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[66]       ngx_conf_set_str_slot,
[67]       0,
[68]       offsetof(ngx_core_conf_t, pid),
[69]       NULL },
[70] 
[71]     { ngx_string("lock_file"),
[72]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[73]       ngx_conf_set_str_slot,
[74]       0,
[75]       offsetof(ngx_core_conf_t, lock_file),
[76]       NULL },
[77] 
[78]     { ngx_string("worker_processes"),
[79]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[80]       ngx_set_worker_processes,
[81]       0,
[82]       0,
[83]       NULL },
[84] 
[85]     { ngx_string("debug_points"),
[86]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[87]       ngx_conf_set_enum_slot,
[88]       0,
[89]       offsetof(ngx_core_conf_t, debug_points),
[90]       &ngx_debug_points },
[91] 
[92]     { ngx_string("user"),
[93]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE12,
[94]       ngx_set_user,
[95]       0,
[96]       0,
[97]       NULL },
[98] 
[99]     { ngx_string("worker_priority"),
[100]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[101]       ngx_set_priority,
[102]       0,
[103]       0,
[104]       NULL },
[105] 
[106]     { ngx_string("worker_cpu_affinity"),
[107]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
[108]       ngx_set_cpu_affinity,
[109]       0,
[110]       0,
[111]       NULL },
[112] 
[113]     { ngx_string("worker_rlimit_nofile"),
[114]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[115]       ngx_conf_set_num_slot,
[116]       0,
[117]       offsetof(ngx_core_conf_t, rlimit_nofile),
[118]       NULL },
[119] 
[120]     { ngx_string("worker_rlimit_core"),
[121]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[122]       ngx_conf_set_off_slot,
[123]       0,
[124]       offsetof(ngx_core_conf_t, rlimit_core),
[125]       NULL },
[126] 
[127]     { ngx_string("worker_shutdown_timeout"),
[128]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[129]       ngx_conf_set_msec_slot,
[130]       0,
[131]       offsetof(ngx_core_conf_t, shutdown_timeout),
[132]       NULL },
[133] 
[134]     { ngx_string("working_directory"),
[135]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[136]       ngx_conf_set_str_slot,
[137]       0,
[138]       offsetof(ngx_core_conf_t, working_directory),
[139]       NULL },
[140] 
[141]     { ngx_string("env"),
[142]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[143]       ngx_set_env,
[144]       0,
[145]       0,
[146]       NULL },
[147] 
[148]     { ngx_string("load_module"),
[149]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[150]       ngx_load_module,
[151]       0,
[152]       0,
[153]       NULL },
[154] 
[155]       ngx_null_command
[156] };
[157] 
[158] 
[159] static ngx_core_module_t  ngx_core_module_ctx = {
[160]     ngx_string("core"),
[161]     ngx_core_module_create_conf,
[162]     ngx_core_module_init_conf
[163] };
[164] 
[165] 
[166] ngx_module_t  ngx_core_module = {
[167]     NGX_MODULE_V1,
[168]     &ngx_core_module_ctx,                  /* module context */
[169]     ngx_core_commands,                     /* module directives */
[170]     NGX_CORE_MODULE,                       /* module type */
[171]     NULL,                                  /* init master */
[172]     NULL,                                  /* init module */
[173]     NULL,                                  /* init process */
[174]     NULL,                                  /* init thread */
[175]     NULL,                                  /* exit thread */
[176]     NULL,                                  /* exit process */
[177]     NULL,                                  /* exit master */
[178]     NGX_MODULE_V1_PADDING
[179] };
[180] 
[181] 
[182] static ngx_uint_t   ngx_show_help;
[183] static ngx_uint_t   ngx_show_version;
[184] static ngx_uint_t   ngx_show_configure;
[185] static u_char      *ngx_prefix;
[186] static u_char      *ngx_error_log;
[187] static u_char      *ngx_conf_file;
[188] static u_char      *ngx_conf_params;
[189] static char        *ngx_signal;
[190] 
[191] 
[192] static char **ngx_os_environ;
[193] 
[194] 

第195-387行为nginx程序main入口函数，无论是通过手动还是系统服务方式启动nginx，皆是从此main函数开始执行。
main函数有两个参数变量，int argc和char *const * argv。argc保存nginx启动时使用的命令行参数数量；
argv变量指向命令行参数数组,系统启动nginx时所有启动参数的地址均保存在此数组中，通过argv可以访问nginx所有启动参数；
[195] int ngx_cdecl
[196] main(int argc, char *const *argv)
[197] {
[198]     ngx_buf_t        *b;
[199]     ngx_log_t        *log;
[200]     ngx_uint_t        i;
[201]     ngx_cycle_t      *cycle, init_cycle;
[202]     ngx_conf_dump_t  *cd;
[203]     ngx_core_conf_t  *ccf;
[204] 
[205]     ngx_debug_init();
[206] 
[207]     if (ngx_strerror_init() != NGX_OK) {
[208]         return 1;
[209]     }
[210] 
[211]     if (ngx_get_options(argc, argv) != NGX_OK) {
[212]         return 1;
[213]     }
[214] 
[215]     if (ngx_show_version) {
[216]         ngx_show_version_info();
[217] 
[218]         if (!ngx_test_config) {
[219]             return 0;
[220]         }
[221]     }
[222] 
[223]     /* TODO */ ngx_max_sockets = -1;
[224] 
[225]     ngx_time_init();
[226] 
[227] #if (NGX_PCRE)
[228]     ngx_regex_init();
[229] #endif
[230] 
[231]     ngx_pid = ngx_getpid();
[232]     ngx_parent = ngx_getppid();
[233] 
[234]     log = ngx_log_init(ngx_prefix, ngx_error_log);
[235]     if (log == NULL) {
[236]         return 1;
[237]     }
[238] 
[239]     /* STUB */
[240] #if (NGX_OPENSSL)
[241]     ngx_ssl_init(log);
[242] #endif
[243] 
[244]     /*
[245]      * init_cycle->log is required for signal handlers and
[246]      * ngx_process_options()
[247]      */
[248] 
[249]     ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
[250]     init_cycle.log = log;
[251]     ngx_cycle = &init_cycle;
[252] 
[253]     init_cycle.pool = ngx_create_pool(1024, log);
[254]     if (init_cycle.pool == NULL) {
[255]         return 1;
[256]     }
[257] 
[258]     if (ngx_save_argv(&init_cycle, argc, argv) != NGX_OK) {
[259]         return 1;
[260]     }
[261] 
[262]     if (ngx_process_options(&init_cycle) != NGX_OK) {
[263]         return 1;
[264]     }
[265] 
[266]     if (ngx_os_init(log) != NGX_OK) {
[267]         return 1;
[268]     }
[269] 
[270]     /*
[271]      * ngx_crc32_table_init() requires ngx_cacheline_size set in ngx_os_init()
[272]      */
[273] 
[274]     if (ngx_crc32_table_init() != NGX_OK) {
[275]         return 1;
[276]     }
[277] 
[278]     /*
[279]      * ngx_slab_sizes_init() requires ngx_pagesize set in ngx_os_init()
[280]      */
[281] 
[282]     ngx_slab_sizes_init();
[283] 
[284]     if (ngx_add_inherited_sockets(&init_cycle) != NGX_OK) {
[285]         return 1;
[286]     }
[287] 
[288]     if (ngx_preinit_modules() != NGX_OK) {
[289]         return 1;
[290]     }
[291] 
[292]     cycle = ngx_init_cycle(&init_cycle);
[293]     if (cycle == NULL) {
[294]         if (ngx_test_config) {
[295]             ngx_log_stderr(0, "configuration file %s test failed",
[296]                            init_cycle.conf_file.data);
[297]         }
[298] 
[299]         return 1;
[300]     }
[301] 
[302]     if (ngx_test_config) {
[303]         if (!ngx_quiet_mode) {
[304]             ngx_log_stderr(0, "configuration file %s test is successful",
[305]                            cycle->conf_file.data);
[306]         }
[307] 
[308]         if (ngx_dump_config) {
[309]             cd = cycle->config_dump.elts;
[310] 
[311]             for (i = 0; i < cycle->config_dump.nelts; i++) {
[312] 
[313]                 ngx_write_stdout("# configuration file ");
[314]                 (void) ngx_write_fd(ngx_stdout, cd[i].name.data,
[315]                                     cd[i].name.len);
[316]                 ngx_write_stdout(":" NGX_LINEFEED);
[317] 
[318]                 b = cd[i].buffer;
[319] 
[320]                 (void) ngx_write_fd(ngx_stdout, b->pos, b->last - b->pos);
[321]                 ngx_write_stdout(NGX_LINEFEED);
[322]             }
[323]         }
[324] 
[325]         return 0;
[326]     }
[327] 
[328]     if (ngx_signal) {
[329]         return ngx_signal_process(cycle, ngx_signal);
[330]     }
[331] 
[332]     ngx_os_status(cycle->log);
[333] 
[334]     ngx_cycle = cycle;
[335] 
[336]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[337] 
[338]     if (ccf->master && ngx_process == NGX_PROCESS_SINGLE) {
[339]         ngx_process = NGX_PROCESS_MASTER;
[340]     }
[341] 
[342] #if !(NGX_WIN32)
[343] 
[344]     if (ngx_init_signals(cycle->log) != NGX_OK) {
[345]         return 1;
[346]     }
[347] 
[348]     if (!ngx_inherited && ccf->daemon) {
[349]         if (ngx_daemon(cycle->log) != NGX_OK) {
[350]             return 1;
[351]         }
[352] 
[353]         ngx_daemonized = 1;
[354]     }
[355] 
[356]     if (ngx_inherited) {
[357]         ngx_daemonized = 1;
[358]     }
[359] 
[360] #endif
[361] 
[362]     if (ngx_create_pidfile(&ccf->pid, cycle->log) != NGX_OK) {
[363]         return 1;
[364]     }
[365] 
[366]     if (ngx_log_redirect_stderr(cycle) != NGX_OK) {
[367]         return 1;
[368]     }
[369] 
[370]     if (log->file->fd != ngx_stderr) {
[371]         if (ngx_close_file(log->file->fd) == NGX_FILE_ERROR) {
[372]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[373]                           ngx_close_file_n " built-in log failed");
[374]         }
[375]     }
[376] 
[377]     ngx_use_stderr = 0;
[378] 
[379]     if (ngx_process == NGX_PROCESS_SINGLE) {
[380]         ngx_single_process_cycle(cycle);
[381] 
[382]     } else {
[383]         ngx_master_process_cycle(cycle);
[384]     }
[385] 
[386]     return 0;
[387] }
[388] 
[389] 
[390] static void
[391] ngx_show_version_info(void)
[392] {
[393]     ngx_write_stderr("nginx version: " NGINX_VER_BUILD NGX_LINEFEED);
[394] 
[395]     if (ngx_show_help) {
[396]         ngx_write_stderr(
[397]             "Usage: nginx [-?hvVtTq] [-s signal] [-p prefix]" NGX_LINEFEED
[398]             "             [-e filename] [-c filename] [-g directives]"
[399]                           NGX_LINEFEED NGX_LINEFEED
[400]             "Options:" NGX_LINEFEED
[401]             "  -?,-h         : this help" NGX_LINEFEED
[402]             "  -v            : show version and exit" NGX_LINEFEED
[403]             "  -V            : show version and configure options then exit"
[404]                                NGX_LINEFEED
[405]             "  -t            : test configuration and exit" NGX_LINEFEED
[406]             "  -T            : test configuration, dump it and exit"
[407]                                NGX_LINEFEED
[408]             "  -q            : suppress non-error messages "
[409]                                "during configuration testing" NGX_LINEFEED
[410]             "  -s signal     : send signal to a master process: "
[411]                                "stop, quit, reopen, reload" NGX_LINEFEED
[412] #ifdef NGX_PREFIX
[413]             "  -p prefix     : set prefix path (default: " NGX_PREFIX ")"
[414]                                NGX_LINEFEED
[415] #else
[416]             "  -p prefix     : set prefix path (default: NONE)" NGX_LINEFEED
[417] #endif
[418]             "  -e filename   : set error log file (default: "
[419] #ifdef NGX_ERROR_LOG_STDERR
[420]                                "stderr)" NGX_LINEFEED
[421] #else
[422]                                NGX_ERROR_LOG_PATH ")" NGX_LINEFEED
[423] #endif
[424]             "  -c filename   : set configuration file (default: " NGX_CONF_PATH
[425]                                ")" NGX_LINEFEED
[426]             "  -g directives : set global directives out of configuration "
[427]                                "file" NGX_LINEFEED NGX_LINEFEED
[428]         );
[429]     }
[430] 
[431]     if (ngx_show_configure) {
[432] 
[433] #ifdef NGX_COMPILER
[434]         ngx_write_stderr("built by " NGX_COMPILER NGX_LINEFEED);
[435] #endif
[436] 
[437] #if (NGX_SSL)
[438]         if (ngx_strcmp(ngx_ssl_version(), OPENSSL_VERSION_TEXT) == 0) {
[439]             ngx_write_stderr("built with " OPENSSL_VERSION_TEXT NGX_LINEFEED);
[440]         } else {
[441]             ngx_write_stderr("built with " OPENSSL_VERSION_TEXT
[442]                              " (running with ");
[443]             ngx_write_stderr((char *) (uintptr_t) ngx_ssl_version());
[444]             ngx_write_stderr(")" NGX_LINEFEED);
[445]         }
[446] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[447]         ngx_write_stderr("TLS SNI support enabled" NGX_LINEFEED);
[448] #else
[449]         ngx_write_stderr("TLS SNI support disabled" NGX_LINEFEED);
[450] #endif
[451] #endif
[452] 
[453]         ngx_write_stderr("configure arguments:" NGX_CONFIGURE NGX_LINEFEED);
[454]     }
[455] }
[456] 
[457] 
[458] static ngx_int_t
[459] ngx_add_inherited_sockets(ngx_cycle_t *cycle)
[460] {
[461]     u_char           *p, *v, *inherited;
[462]     ngx_int_t         s;
[463]     ngx_listening_t  *ls;
[464] 
[465]     inherited = (u_char *) getenv(NGINX_VAR);
[466] 
[467]     if (inherited == NULL) {
[468]         return NGX_OK;
[469]     }
[470] 
[471]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
[472]                   "using inherited sockets from \"%s\"", inherited);
[473] 
[474]     if (ngx_array_init(&cycle->listening, cycle->pool, 10,
[475]                        sizeof(ngx_listening_t))
[476]         != NGX_OK)
[477]     {
[478]         return NGX_ERROR;
[479]     }
[480] 
[481]     for (p = inherited, v = p; *p; p++) {
[482]         if (*p == ':' || *p == ';') {
[483]             s = ngx_atoi(v, p - v);
[484]             if (s == NGX_ERROR) {
[485]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[486]                               "invalid socket number \"%s\" in " NGINX_VAR
[487]                               " environment variable, ignoring the rest"
[488]                               " of the variable", v);
[489]                 break;
[490]             }
[491] 
[492]             v = p + 1;
[493] 
[494]             ls = ngx_array_push(&cycle->listening);
[495]             if (ls == NULL) {
[496]                 return NGX_ERROR;
[497]             }
[498] 
[499]             ngx_memzero(ls, sizeof(ngx_listening_t));
[500] 
[501]             ls->fd = (ngx_socket_t) s;
[502]             ls->inherited = 1;
[503]         }
[504]     }
[505] 
[506]     if (v != p) {
[507]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[508]                       "invalid socket number \"%s\" in " NGINX_VAR
[509]                       " environment variable, ignoring", v);
[510]     }
[511] 
[512]     ngx_inherited = 1;
[513] 
[514]     return ngx_set_inherited_sockets(cycle);
[515] }
[516] 
[517] 
[518] char **
[519] ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last)
[520] {
[521]     char                **p, **env;
[522]     ngx_str_t            *var;
[523]     ngx_uint_t            i, n;
[524]     ngx_core_conf_t      *ccf;
[525]     ngx_pool_cleanup_t   *cln;
[526] 
[527]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[528] 
[529]     if (last == NULL && ccf->environment) {
[530]         return ccf->environment;
[531]     }
[532] 
[533]     var = ccf->env.elts;
[534] 
[535]     for (i = 0; i < ccf->env.nelts; i++) {
[536]         if (ngx_strcmp(var[i].data, "TZ") == 0
[537]             || ngx_strncmp(var[i].data, "TZ=", 3) == 0)
[538]         {
[539]             goto tz_found;
[540]         }
[541]     }
[542] 
[543]     var = ngx_array_push(&ccf->env);
[544]     if (var == NULL) {
[545]         return NULL;
[546]     }
[547] 
[548]     var->len = 2;
[549]     var->data = (u_char *) "TZ";
[550] 
[551]     var = ccf->env.elts;
[552] 
[553] tz_found:
[554] 
[555]     n = 0;
[556] 
[557]     for (i = 0; i < ccf->env.nelts; i++) {
[558] 
[559]         if (var[i].data[var[i].len] == '=') {
[560]             n++;
[561]             continue;
[562]         }
[563] 
[564]         for (p = ngx_os_environ; *p; p++) {
[565] 
[566]             if (ngx_strncmp(*p, var[i].data, var[i].len) == 0
[567]                 && (*p)[var[i].len] == '=')
[568]             {
[569]                 n++;
[570]                 break;
[571]             }
[572]         }
[573]     }
[574] 
[575]     if (last) {
[576]         env = ngx_alloc((*last + n + 1) * sizeof(char *), cycle->log);
[577]         if (env == NULL) {
[578]             return NULL;
[579]         }
[580] 
[581]         *last = n;
[582] 
[583]     } else {
[584]         cln = ngx_pool_cleanup_add(cycle->pool, 0);
[585]         if (cln == NULL) {
[586]             return NULL;
[587]         }
[588] 
[589]         env = ngx_alloc((n + 1) * sizeof(char *), cycle->log);
[590]         if (env == NULL) {
[591]             return NULL;
[592]         }
[593] 
[594]         cln->handler = ngx_cleanup_environment;
[595]         cln->data = env;
[596]     }
[597] 
[598]     n = 0;
[599] 
[600]     for (i = 0; i < ccf->env.nelts; i++) {
[601] 
[602]         if (var[i].data[var[i].len] == '=') {
[603]             env[n++] = (char *) var[i].data;
[604]             continue;
[605]         }
[606] 
[607]         for (p = ngx_os_environ; *p; p++) {
[608] 
[609]             if (ngx_strncmp(*p, var[i].data, var[i].len) == 0
[610]                 && (*p)[var[i].len] == '=')
[611]             {
[612]                 env[n++] = *p;
[613]                 break;
[614]             }
[615]         }
[616]     }
[617] 
[618]     env[n] = NULL;
[619] 
[620]     if (last == NULL) {
[621]         ccf->environment = env;
[622]         environ = env;
[623]     }
[624] 
[625]     return env;
[626] }
[627] 
[628] 
[629] static void
[630] ngx_cleanup_environment(void *data)
[631] {
[632]     char  **env = data;
[633] 
[634]     if (environ == env) {
[635] 
[636]         /*
[637]          * if the environment is still used, as it happens on exit,
[638]          * the only option is to leak it
[639]          */
[640] 
[641]         return;
[642]     }
[643] 
[644]     ngx_free(env);
[645] }
[646] 
[647] 
[648] ngx_pid_t
[649] ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv)
[650] {
[651]     char             **env, *var;
[652]     u_char            *p;
[653]     ngx_uint_t         i, n;
[654]     ngx_pid_t          pid;
[655]     ngx_exec_ctx_t     ctx;
[656]     ngx_core_conf_t   *ccf;
[657]     ngx_listening_t   *ls;
[658] 
[659]     ngx_memzero(&ctx, sizeof(ngx_exec_ctx_t));
[660] 
[661]     ctx.path = argv[0];
[662]     ctx.name = "new binary process";
[663]     ctx.argv = argv;
[664] 
[665]     n = 2;
[666]     env = ngx_set_environment(cycle, &n);
[667]     if (env == NULL) {
[668]         return NGX_INVALID_PID;
[669]     }
[670] 
[671]     var = ngx_alloc(sizeof(NGINX_VAR)
[672]                     + cycle->listening.nelts * (NGX_INT32_LEN + 1) + 2,
[673]                     cycle->log);
[674]     if (var == NULL) {
[675]         ngx_free(env);
[676]         return NGX_INVALID_PID;
[677]     }
[678] 
[679]     p = ngx_cpymem(var, NGINX_VAR "=", sizeof(NGINX_VAR));
[680] 
[681]     ls = cycle->listening.elts;
[682]     for (i = 0; i < cycle->listening.nelts; i++) {
[683]         p = ngx_sprintf(p, "%ud;", ls[i].fd);
[684]     }
[685] 
[686]     *p = '\0';
[687] 
[688]     env[n++] = var;
[689] 
[690] #if (NGX_SETPROCTITLE_USES_ENV)
[691] 
[692]     /* allocate the spare 300 bytes for the new binary process title */
[693] 
[694]     env[n++] = "SPARE=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
[695]                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
[696]                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
[697]                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
[698]                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
[699] 
[700] #endif
[701] 
[702]     env[n] = NULL;
[703] 
[704] #if (NGX_DEBUG)
[705]     {
[706]     char  **e;
[707]     for (e = env; *e; e++) {
[708]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0, "env: %s", *e);
[709]     }
[710]     }
[711] #endif
[712] 
[713]     ctx.envp = (char *const *) env;
[714] 
[715]     ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
[716] 
[717]     if (ngx_rename_file(ccf->pid.data, ccf->oldpid.data) == NGX_FILE_ERROR) {
[718]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[719]                       ngx_rename_file_n " %s to %s failed "
[720]                       "before executing new binary process \"%s\"",
[721]                       ccf->pid.data, ccf->oldpid.data, argv[0]);
[722] 
[723]         ngx_free(env);
[724]         ngx_free(var);
[725] 
[726]         return NGX_INVALID_PID;
[727]     }
[728] 
[729]     pid = ngx_execute(cycle, &ctx);
[730] 
[731]     if (pid == NGX_INVALID_PID) {
[732]         if (ngx_rename_file(ccf->oldpid.data, ccf->pid.data)
[733]             == NGX_FILE_ERROR)
[734]         {
[735]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[736]                           ngx_rename_file_n " %s back to %s failed after "
[737]                           "an attempt to execute new binary process \"%s\"",
[738]                           ccf->oldpid.data, ccf->pid.data, argv[0]);
[739]         }
[740]     }
[741] 
[742]     ngx_free(env);
[743]     ngx_free(var);
[744] 
[745]     return pid;
[746] }
[747] 
[748] 
[749] static ngx_int_t
[750] ngx_get_options(int argc, char *const *argv)
[751] {
[752]     u_char     *p;
[753]     ngx_int_t   i;
[754] 
[755]     for (i = 1; i < argc; i++) {
[756] 
[757]         p = (u_char *) argv[i];
[758] 
[759]         if (*p++ != '-') {
[760]             ngx_log_stderr(0, "invalid option: \"%s\"", argv[i]);
[761]             return NGX_ERROR;
[762]         }
[763] 
[764]         while (*p) {
[765] 
[766]             switch (*p++) {
[767] 
[768]             case '?':
[769]             case 'h':
[770]                 ngx_show_version = 1;
[771]                 ngx_show_help = 1;
[772]                 break;
[773] 
[774]             case 'v':
[775]                 ngx_show_version = 1;
[776]                 break;
[777] 
[778]             case 'V':
[779]                 ngx_show_version = 1;
[780]                 ngx_show_configure = 1;
[781]                 break;
[782] 
[783]             case 't':
[784]                 ngx_test_config = 1;
[785]                 break;
[786] 
[787]             case 'T':
[788]                 ngx_test_config = 1;
[789]                 ngx_dump_config = 1;
[790]                 break;
[791] 
[792]             case 'q':
[793]                 ngx_quiet_mode = 1;
[794]                 break;
[795] 
[796]             case 'p':
[797]                 if (*p) {
[798]                     ngx_prefix = p;
[799]                     goto next;
[800]                 }
[801] 
[802]                 if (argv[++i]) {
[803]                     ngx_prefix = (u_char *) argv[i];
[804]                     goto next;
[805]                 }
[806] 
[807]                 ngx_log_stderr(0, "option \"-p\" requires directory name");
[808]                 return NGX_ERROR;
[809] 
[810]             case 'e':
[811]                 if (*p) {
[812]                     ngx_error_log = p;
[813] 
[814]                 } else if (argv[++i]) {
[815]                     ngx_error_log = (u_char *) argv[i];
[816] 
[817]                 } else {
[818]                     ngx_log_stderr(0, "option \"-e\" requires file name");
[819]                     return NGX_ERROR;
[820]                 }
[821] 
[822]                 if (ngx_strcmp(ngx_error_log, "stderr") == 0) {
[823]                     ngx_error_log = (u_char *) "";
[824]                 }
[825] 
[826]                 goto next;
[827] 
[828]             case 'c':
[829]                 if (*p) {
[830]                     ngx_conf_file = p;
[831]                     goto next;
[832]                 }
[833] 
[834]                 if (argv[++i]) {
[835]                     ngx_conf_file = (u_char *) argv[i];
[836]                     goto next;
[837]                 }
[838] 
[839]                 ngx_log_stderr(0, "option \"-c\" requires file name");
[840]                 return NGX_ERROR;
[841] 
[842]             case 'g':
[843]                 if (*p) {
[844]                     ngx_conf_params = p;
[845]                     goto next;
[846]                 }
[847] 
[848]                 if (argv[++i]) {
[849]                     ngx_conf_params = (u_char *) argv[i];
[850]                     goto next;
[851]                 }
[852] 
[853]                 ngx_log_stderr(0, "option \"-g\" requires parameter");
[854]                 return NGX_ERROR;
[855] 
[856]             case 's':
[857]                 if (*p) {
[858]                     ngx_signal = (char *) p;
[859] 
[860]                 } else if (argv[++i]) {
[861]                     ngx_signal = argv[i];
[862] 
[863]                 } else {
[864]                     ngx_log_stderr(0, "option \"-s\" requires parameter");
[865]                     return NGX_ERROR;
[866]                 }
[867] 
[868]                 if (ngx_strcmp(ngx_signal, "stop") == 0
[869]                     || ngx_strcmp(ngx_signal, "quit") == 0
[870]                     || ngx_strcmp(ngx_signal, "reopen") == 0
[871]                     || ngx_strcmp(ngx_signal, "reload") == 0)
[872]                 {
[873]                     ngx_process = NGX_PROCESS_SIGNALLER;
[874]                     goto next;
[875]                 }
[876] 
[877]                 ngx_log_stderr(0, "invalid option: \"-s %s\"", ngx_signal);
[878]                 return NGX_ERROR;
[879] 
[880]             default:
[881]                 ngx_log_stderr(0, "invalid option: \"%c\"", *(p - 1));
[882]                 return NGX_ERROR;
[883]             }
[884]         }
[885] 
[886]     next:
[887] 
[888]         continue;
[889]     }
[890] 
[891]     return NGX_OK;
[892] }
[893] 
[894] 
[895] static ngx_int_t
[896] ngx_save_argv(ngx_cycle_t *cycle, int argc, char *const *argv)
[897] {
[898] #if (NGX_FREEBSD)
[899] 
[900]     ngx_os_argv = (char **) argv;
[901]     ngx_argc = argc;
[902]     ngx_argv = (char **) argv;
[903] 
[904] #else
[905]     size_t     len;
[906]     ngx_int_t  i;
[907] 
[908]     ngx_os_argv = (char **) argv;
[909]     ngx_argc = argc;
[910] 
[911]     ngx_argv = ngx_alloc((argc + 1) * sizeof(char *), cycle->log);
[912]     if (ngx_argv == NULL) {
[913]         return NGX_ERROR;
[914]     }
[915] 
[916]     for (i = 0; i < argc; i++) {
[917]         len = ngx_strlen(argv[i]) + 1;
[918] 
[919]         ngx_argv[i] = ngx_alloc(len, cycle->log);
[920]         if (ngx_argv[i] == NULL) {
[921]             return NGX_ERROR;
[922]         }
[923] 
[924]         (void) ngx_cpystrn((u_char *) ngx_argv[i], (u_char *) argv[i], len);
[925]     }
[926] 
[927]     ngx_argv[i] = NULL;
[928] 
[929] #endif
[930] 
[931]     ngx_os_environ = environ;
[932] 
[933]     return NGX_OK;
[934] }
[935] 
[936] 
[937] static ngx_int_t
[938] ngx_process_options(ngx_cycle_t *cycle)
[939] {
[940]     u_char  *p;
[941]     size_t   len;
[942] 
[943]     if (ngx_prefix) {
[944]         len = ngx_strlen(ngx_prefix);
[945]         p = ngx_prefix;
[946] 
[947]         if (len && !ngx_path_separator(p[len - 1])) {
[948]             p = ngx_pnalloc(cycle->pool, len + 1);
[949]             if (p == NULL) {
[950]                 return NGX_ERROR;
[951]             }
[952] 
[953]             ngx_memcpy(p, ngx_prefix, len);
[954]             p[len++] = '/';
[955]         }
[956] 
[957]         cycle->conf_prefix.len = len;
[958]         cycle->conf_prefix.data = p;
[959]         cycle->prefix.len = len;
[960]         cycle->prefix.data = p;
[961] 
[962]     } else {
[963] 
[964] #ifndef NGX_PREFIX
[965] 
[966]         p = ngx_pnalloc(cycle->pool, NGX_MAX_PATH);
[967]         if (p == NULL) {
[968]             return NGX_ERROR;
[969]         }
[970] 
[971]         if (ngx_getcwd(p, NGX_MAX_PATH) == 0) {
[972]             ngx_log_stderr(ngx_errno, "[emerg]: " ngx_getcwd_n " failed");
[973]             return NGX_ERROR;
[974]         }
[975] 
[976]         len = ngx_strlen(p);
[977] 
[978]         p[len++] = '/';
[979] 
[980]         cycle->conf_prefix.len = len;
[981]         cycle->conf_prefix.data = p;
[982]         cycle->prefix.len = len;
[983]         cycle->prefix.data = p;
[984] 
[985] #else
[986] 
[987] #ifdef NGX_CONF_PREFIX
[988]         ngx_str_set(&cycle->conf_prefix, NGX_CONF_PREFIX);
[989] #else
[990]         ngx_str_set(&cycle->conf_prefix, NGX_PREFIX);
[991] #endif
[992]         ngx_str_set(&cycle->prefix, NGX_PREFIX);
[993] 
[994] #endif
[995]     }
[996] 
[997]     if (ngx_conf_file) {
[998]         cycle->conf_file.len = ngx_strlen(ngx_conf_file);
[999]         cycle->conf_file.data = ngx_conf_file;
[1000] 
[1001]     } else {
[1002]         ngx_str_set(&cycle->conf_file, NGX_CONF_PATH);
[1003]     }
[1004] 
[1005]     if (ngx_conf_full_name(cycle, &cycle->conf_file, 0) != NGX_OK) {
[1006]         return NGX_ERROR;
[1007]     }
[1008] 
[1009]     for (p = cycle->conf_file.data + cycle->conf_file.len - 1;
[1010]          p > cycle->conf_file.data;
[1011]          p--)
[1012]     {
[1013]         if (ngx_path_separator(*p)) {
[1014]             cycle->conf_prefix.len = p - cycle->conf_file.data + 1;
[1015]             cycle->conf_prefix.data = cycle->conf_file.data;
[1016]             break;
[1017]         }
[1018]     }
[1019] 
[1020]     if (ngx_error_log) {
[1021]         cycle->error_log.len = ngx_strlen(ngx_error_log);
[1022]         cycle->error_log.data = ngx_error_log;
[1023] 
[1024]     } else {
[1025]         ngx_str_set(&cycle->error_log, NGX_ERROR_LOG_PATH);
[1026]     }
[1027] 
[1028]     if (ngx_conf_params) {
[1029]         cycle->conf_param.len = ngx_strlen(ngx_conf_params);
[1030]         cycle->conf_param.data = ngx_conf_params;
[1031]     }
[1032] 
[1033]     if (ngx_test_config) {
[1034]         cycle->log->log_level = NGX_LOG_INFO;
[1035]     }
[1036] 
[1037]     return NGX_OK;
[1038] }
[1039] 
[1040] 
[1041] static void *
[1042] ngx_core_module_create_conf(ngx_cycle_t *cycle)
[1043] {
[1044]     ngx_core_conf_t  *ccf;
[1045] 
[1046]     ccf = ngx_pcalloc(cycle->pool, sizeof(ngx_core_conf_t));
[1047]     if (ccf == NULL) {
[1048]         return NULL;
[1049]     }
[1050] 
[1051]     /*
[1052]      * set by ngx_pcalloc()
[1053]      *
[1054]      *     ccf->pid = NULL;
[1055]      *     ccf->oldpid = NULL;
[1056]      *     ccf->priority = 0;
[1057]      *     ccf->cpu_affinity_auto = 0;
[1058]      *     ccf->cpu_affinity_n = 0;
[1059]      *     ccf->cpu_affinity = NULL;
[1060]      */
[1061] 
[1062]     ccf->daemon = NGX_CONF_UNSET;
[1063]     ccf->master = NGX_CONF_UNSET;
[1064]     ccf->timer_resolution = NGX_CONF_UNSET_MSEC;
[1065]     ccf->shutdown_timeout = NGX_CONF_UNSET_MSEC;
[1066] 
[1067]     ccf->worker_processes = NGX_CONF_UNSET;
[1068]     ccf->debug_points = NGX_CONF_UNSET;
[1069] 
[1070]     ccf->rlimit_nofile = NGX_CONF_UNSET;
[1071]     ccf->rlimit_core = NGX_CONF_UNSET;
[1072] 
[1073]     ccf->user = (ngx_uid_t) NGX_CONF_UNSET_UINT;
[1074]     ccf->group = (ngx_gid_t) NGX_CONF_UNSET_UINT;
[1075] 
[1076]     if (ngx_array_init(&ccf->env, cycle->pool, 1, sizeof(ngx_str_t))
[1077]         != NGX_OK)
[1078]     {
[1079]         return NULL;
[1080]     }
[1081] 
[1082]     return ccf;
[1083] }
[1084] 
[1085] 
[1086] static char *
[1087] ngx_core_module_init_conf(ngx_cycle_t *cycle, void *conf)
[1088] {
[1089]     ngx_core_conf_t  *ccf = conf;
[1090] 
[1091]     ngx_conf_init_value(ccf->daemon, 1);
[1092]     ngx_conf_init_value(ccf->master, 1);
[1093]     ngx_conf_init_msec_value(ccf->timer_resolution, 0);
[1094]     ngx_conf_init_msec_value(ccf->shutdown_timeout, 0);
[1095] 
[1096]     ngx_conf_init_value(ccf->worker_processes, 1);
[1097]     ngx_conf_init_value(ccf->debug_points, 0);
[1098] 
[1099] #if (NGX_HAVE_CPU_AFFINITY)
[1100] 
[1101]     if (!ccf->cpu_affinity_auto
[1102]         && ccf->cpu_affinity_n
[1103]         && ccf->cpu_affinity_n != 1
[1104]         && ccf->cpu_affinity_n != (ngx_uint_t) ccf->worker_processes)
[1105]     {
[1106]         ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
[1107]                       "the number of \"worker_processes\" is not equal to "
[1108]                       "the number of \"worker_cpu_affinity\" masks, "
[1109]                       "using last mask for remaining worker processes");
[1110]     }
[1111] 
[1112] #endif
[1113] 
[1114] 
[1115]     if (ccf->pid.len == 0) {
[1116]         ngx_str_set(&ccf->pid, NGX_PID_PATH);
[1117]     }
[1118] 
[1119]     if (ngx_conf_full_name(cycle, &ccf->pid, 0) != NGX_OK) {
[1120]         return NGX_CONF_ERROR;
[1121]     }
[1122] 
[1123]     ccf->oldpid.len = ccf->pid.len + sizeof(NGX_OLDPID_EXT);
[1124] 
[1125]     ccf->oldpid.data = ngx_pnalloc(cycle->pool, ccf->oldpid.len);
[1126]     if (ccf->oldpid.data == NULL) {
[1127]         return NGX_CONF_ERROR;
[1128]     }
[1129] 
[1130]     ngx_memcpy(ngx_cpymem(ccf->oldpid.data, ccf->pid.data, ccf->pid.len),
[1131]                NGX_OLDPID_EXT, sizeof(NGX_OLDPID_EXT));
[1132] 
[1133] 
[1134] #if !(NGX_WIN32)
[1135] 
[1136]     if (ccf->user == (uid_t) NGX_CONF_UNSET_UINT && geteuid() == 0) {
[1137]         struct group   *grp;
[1138]         struct passwd  *pwd;
[1139] 
[1140]         ngx_set_errno(0);
[1141]         pwd = getpwnam(NGX_USER);
[1142]         if (pwd == NULL) {
[1143]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1144]                           "getpwnam(\"" NGX_USER "\") failed");
[1145]             return NGX_CONF_ERROR;
[1146]         }
[1147] 
[1148]         ccf->username = NGX_USER;
[1149]         ccf->user = pwd->pw_uid;
[1150] 
[1151]         ngx_set_errno(0);
[1152]         grp = getgrnam(NGX_GROUP);
[1153]         if (grp == NULL) {
[1154]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[1155]                           "getgrnam(\"" NGX_GROUP "\") failed");
[1156]             return NGX_CONF_ERROR;
[1157]         }
[1158] 
[1159]         ccf->group = grp->gr_gid;
[1160]     }
[1161] 
[1162] 
[1163]     if (ccf->lock_file.len == 0) {
[1164]         ngx_str_set(&ccf->lock_file, NGX_LOCK_PATH);
[1165]     }
[1166] 
[1167]     if (ngx_conf_full_name(cycle, &ccf->lock_file, 0) != NGX_OK) {
[1168]         return NGX_CONF_ERROR;
[1169]     }
[1170] 
[1171]     {
[1172]     ngx_str_t  lock_file;
[1173] 
[1174]     lock_file = cycle->old_cycle->lock_file;
[1175] 
[1176]     if (lock_file.len) {
[1177]         lock_file.len--;
[1178] 
[1179]         if (ccf->lock_file.len != lock_file.len
[1180]             || ngx_strncmp(ccf->lock_file.data, lock_file.data, lock_file.len)
[1181]                != 0)
[1182]         {
[1183]             ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[1184]                           "\"lock_file\" could not be changed, ignored");
[1185]         }
[1186] 
[1187]         cycle->lock_file.len = lock_file.len + 1;
[1188]         lock_file.len += sizeof(".accept");
[1189] 
[1190]         cycle->lock_file.data = ngx_pstrdup(cycle->pool, &lock_file);
[1191]         if (cycle->lock_file.data == NULL) {
[1192]             return NGX_CONF_ERROR;
[1193]         }
[1194] 
[1195]     } else {
[1196]         cycle->lock_file.len = ccf->lock_file.len + 1;
[1197]         cycle->lock_file.data = ngx_pnalloc(cycle->pool,
[1198]                                       ccf->lock_file.len + sizeof(".accept"));
[1199]         if (cycle->lock_file.data == NULL) {
[1200]             return NGX_CONF_ERROR;
[1201]         }
[1202] 
[1203]         ngx_memcpy(ngx_cpymem(cycle->lock_file.data, ccf->lock_file.data,
[1204]                               ccf->lock_file.len),
[1205]                    ".accept", sizeof(".accept"));
[1206]     }
[1207]     }
[1208] 
[1209] #endif
[1210] 
[1211]     return NGX_CONF_OK;
[1212] }
[1213] 
[1214] 
[1215] static char *
[1216] ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1217] {
[1218] #if (NGX_WIN32)
[1219] 
[1220]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1221]                        "\"user\" is not supported, ignored");
[1222] 
[1223]     return NGX_CONF_OK;
[1224] 
[1225] #else
[1226] 
[1227]     ngx_core_conf_t  *ccf = conf;
[1228] 
[1229]     char             *group;
[1230]     struct passwd    *pwd;
[1231]     struct group     *grp;
[1232]     ngx_str_t        *value;
[1233] 
[1234]     if (ccf->user != (uid_t) NGX_CONF_UNSET_UINT) {
[1235]         return "is duplicate";
[1236]     }
[1237] 
[1238]     if (geteuid() != 0) {
[1239]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1240]                            "the \"user\" directive makes sense only "
[1241]                            "if the master process runs "
[1242]                            "with super-user privileges, ignored");
[1243]         return NGX_CONF_OK;
[1244]     }
[1245] 
[1246]     value = cf->args->elts;
[1247] 
[1248]     ccf->username = (char *) value[1].data;
[1249] 
[1250]     ngx_set_errno(0);
[1251]     pwd = getpwnam((const char *) value[1].data);
[1252]     if (pwd == NULL) {
[1253]         ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[1254]                            "getpwnam(\"%s\") failed", value[1].data);
[1255]         return NGX_CONF_ERROR;
[1256]     }
[1257] 
[1258]     ccf->user = pwd->pw_uid;
[1259] 
[1260]     group = (char *) ((cf->args->nelts == 2) ? value[1].data : value[2].data);
[1261] 
[1262]     ngx_set_errno(0);
[1263]     grp = getgrnam(group);
[1264]     if (grp == NULL) {
[1265]         ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[1266]                            "getgrnam(\"%s\") failed", group);
[1267]         return NGX_CONF_ERROR;
[1268]     }
[1269] 
[1270]     ccf->group = grp->gr_gid;
[1271] 
[1272]     return NGX_CONF_OK;
[1273] 
[1274] #endif
[1275] }
[1276] 
[1277] 
[1278] static char *
[1279] ngx_set_env(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1280] {
[1281]     ngx_core_conf_t  *ccf = conf;
[1282] 
[1283]     ngx_str_t   *value, *var;
[1284]     ngx_uint_t   i;
[1285] 
[1286]     var = ngx_array_push(&ccf->env);
[1287]     if (var == NULL) {
[1288]         return NGX_CONF_ERROR;
[1289]     }
[1290] 
[1291]     value = cf->args->elts;
[1292]     *var = value[1];
[1293] 
[1294]     for (i = 0; i < value[1].len; i++) {
[1295] 
[1296]         if (value[1].data[i] == '=') {
[1297] 
[1298]             var->len = i;
[1299] 
[1300]             return NGX_CONF_OK;
[1301]         }
[1302]     }
[1303] 
[1304]     return NGX_CONF_OK;
[1305] }
[1306] 
[1307] 
[1308] static char *
[1309] ngx_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1310] {
[1311]     ngx_core_conf_t  *ccf = conf;
[1312] 
[1313]     ngx_str_t        *value;
[1314]     ngx_uint_t        n, minus;
[1315] 
[1316]     if (ccf->priority != 0) {
[1317]         return "is duplicate";
[1318]     }
[1319] 
[1320]     value = cf->args->elts;
[1321] 
[1322]     if (value[1].data[0] == '-') {
[1323]         n = 1;
[1324]         minus = 1;
[1325] 
[1326]     } else if (value[1].data[0] == '+') {
[1327]         n = 1;
[1328]         minus = 0;
[1329] 
[1330]     } else {
[1331]         n = 0;
[1332]         minus = 0;
[1333]     }
[1334] 
[1335]     ccf->priority = ngx_atoi(&value[1].data[n], value[1].len - n);
[1336]     if (ccf->priority == NGX_ERROR) {
[1337]         return "invalid number";
[1338]     }
[1339] 
[1340]     if (minus) {
[1341]         ccf->priority = -ccf->priority;
[1342]     }
[1343] 
[1344]     return NGX_CONF_OK;
[1345] }
[1346] 
[1347] 
[1348] static char *
[1349] ngx_set_cpu_affinity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1350] {
[1351] #if (NGX_HAVE_CPU_AFFINITY)
[1352]     ngx_core_conf_t  *ccf = conf;
[1353] 
[1354]     u_char            ch, *p;
[1355]     ngx_str_t        *value;
[1356]     ngx_uint_t        i, n;
[1357]     ngx_cpuset_t     *mask;
[1358] 
[1359]     if (ccf->cpu_affinity) {
[1360]         return "is duplicate";
[1361]     }
[1362] 
[1363]     mask = ngx_palloc(cf->pool, (cf->args->nelts - 1) * sizeof(ngx_cpuset_t));
[1364]     if (mask == NULL) {
[1365]         return NGX_CONF_ERROR;
[1366]     }
[1367] 
[1368]     ccf->cpu_affinity_n = cf->args->nelts - 1;
[1369]     ccf->cpu_affinity = mask;
[1370] 
[1371]     value = cf->args->elts;
[1372] 
[1373]     if (ngx_strcmp(value[1].data, "auto") == 0) {
[1374] 
[1375]         if (cf->args->nelts > 3) {
[1376]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1377]                                "invalid number of arguments in "
[1378]                                "\"worker_cpu_affinity\" directive");
[1379]             return NGX_CONF_ERROR;
[1380]         }
[1381] 
[1382]         ccf->cpu_affinity_auto = 1;
[1383] 
[1384]         CPU_ZERO(&mask[0]);
[1385]         for (i = 0; i < (ngx_uint_t) ngx_min(ngx_ncpu, CPU_SETSIZE); i++) {
[1386]             CPU_SET(i, &mask[0]);
[1387]         }
[1388] 
[1389]         n = 2;
[1390] 
[1391]     } else {
[1392]         n = 1;
[1393]     }
[1394] 
[1395]     for ( /* void */ ; n < cf->args->nelts; n++) {
[1396] 
[1397]         if (value[n].len > CPU_SETSIZE) {
[1398]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1399]                          "\"worker_cpu_affinity\" supports up to %d CPUs only",
[1400]                          CPU_SETSIZE);
[1401]             return NGX_CONF_ERROR;
[1402]         }
[1403] 
[1404]         i = 0;
[1405]         CPU_ZERO(&mask[n - 1]);
[1406] 
[1407]         for (p = value[n].data + value[n].len - 1;
[1408]              p >= value[n].data;
[1409]              p--)
[1410]         {
[1411]             ch = *p;
[1412] 
[1413]             if (ch == ' ') {
[1414]                 continue;
[1415]             }
[1416] 
[1417]             i++;
[1418] 
[1419]             if (ch == '0') {
[1420]                 continue;
[1421]             }
[1422] 
[1423]             if (ch == '1') {
[1424]                 CPU_SET(i - 1, &mask[n - 1]);
[1425]                 continue;
[1426]             }
[1427] 
[1428]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1429]                           "invalid character \"%c\" in \"worker_cpu_affinity\"",
[1430]                           ch);
[1431]             return NGX_CONF_ERROR;
[1432]         }
[1433]     }
[1434] 
[1435] #else
[1436] 
[1437]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1438]                        "\"worker_cpu_affinity\" is not supported "
[1439]                        "on this platform, ignored");
[1440] #endif
[1441] 
[1442]     return NGX_CONF_OK;
[1443] }
[1444] 
[1445] 
[1446] ngx_cpuset_t *
[1447] ngx_get_cpu_affinity(ngx_uint_t n)
[1448] {
[1449] #if (NGX_HAVE_CPU_AFFINITY)
[1450]     ngx_uint_t        i, j;
[1451]     ngx_cpuset_t     *mask;
[1452]     ngx_core_conf_t  *ccf;
[1453] 
[1454]     static ngx_cpuset_t  result;
[1455] 
[1456]     ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
[1457]                                            ngx_core_module);
[1458] 
[1459]     if (ccf->cpu_affinity == NULL) {
[1460]         return NULL;
[1461]     }
[1462] 
[1463]     if (ccf->cpu_affinity_auto) {
[1464]         mask = &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];
[1465] 
[1466]         for (i = 0, j = n; /* void */ ; i++) {
[1467] 
[1468]             if (CPU_ISSET(i % CPU_SETSIZE, mask) && j-- == 0) {
[1469]                 break;
[1470]             }
[1471] 
[1472]             if (i == CPU_SETSIZE && j == n) {
[1473]                 /* empty mask */
[1474]                 return NULL;
[1475]             }
[1476] 
[1477]             /* void */
[1478]         }
[1479] 
[1480]         CPU_ZERO(&result);
[1481]         CPU_SET(i % CPU_SETSIZE, &result);
[1482] 
[1483]         return &result;
[1484]     }
[1485] 
[1486]     if (ccf->cpu_affinity_n > n) {
[1487]         return &ccf->cpu_affinity[n];
[1488]     }
[1489] 
[1490]     return &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];
[1491] 
[1492] #else
[1493] 
[1494]     return NULL;
[1495] 
[1496] #endif
[1497] }
[1498] 
[1499] 
[1500] static char *
[1501] ngx_set_worker_processes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1502] {
[1503]     ngx_str_t        *value;
[1504]     ngx_core_conf_t  *ccf;
[1505] 
[1506]     ccf = (ngx_core_conf_t *) conf;
[1507] 
[1508]     if (ccf->worker_processes != NGX_CONF_UNSET) {
[1509]         return "is duplicate";
[1510]     }
[1511] 
[1512]     value = cf->args->elts;
[1513] 
[1514]     if (ngx_strcmp(value[1].data, "auto") == 0) {
[1515]         ccf->worker_processes = ngx_ncpu;
[1516]         return NGX_CONF_OK;
[1517]     }
[1518] 
[1519]     ccf->worker_processes = ngx_atoi(value[1].data, value[1].len);
[1520] 
[1521]     if (ccf->worker_processes == NGX_ERROR) {
[1522]         return "invalid value";
[1523]     }
[1524] 
[1525]     return NGX_CONF_OK;
[1526] }
[1527] 
[1528] 
[1529] static char *
[1530] ngx_load_module(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1531] {
[1532] #if (NGX_HAVE_DLOPEN)
[1533]     void                *handle;
[1534]     char               **names, **order;
[1535]     ngx_str_t           *value, file;
[1536]     ngx_uint_t           i;
[1537]     ngx_module_t        *module, **modules;
[1538]     ngx_pool_cleanup_t  *cln;
[1539] 
[1540]     if (cf->cycle->modules_used) {
[1541]         return "is specified too late";
[1542]     }
[1543] 
[1544]     value = cf->args->elts;
[1545] 
[1546]     file = value[1];
[1547] 
[1548]     if (ngx_conf_full_name(cf->cycle, &file, 0) != NGX_OK) {
[1549]         return NGX_CONF_ERROR;
[1550]     }
[1551] 
[1552]     cln = ngx_pool_cleanup_add(cf->cycle->pool, 0);
[1553]     if (cln == NULL) {
[1554]         return NGX_CONF_ERROR;
[1555]     }
[1556] 
[1557]     handle = ngx_dlopen(file.data);
[1558]     if (handle == NULL) {
[1559]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1560]                            ngx_dlopen_n " \"%s\" failed (%s)",
[1561]                            file.data, ngx_dlerror());
[1562]         return NGX_CONF_ERROR;
[1563]     }
[1564] 
[1565]     cln->handler = ngx_unload_module;
[1566]     cln->data = handle;
[1567] 
[1568]     modules = ngx_dlsym(handle, "ngx_modules");
[1569]     if (modules == NULL) {
[1570]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1571]                            ngx_dlsym_n " \"%V\", \"%s\" failed (%s)",
[1572]                            &value[1], "ngx_modules", ngx_dlerror());
[1573]         return NGX_CONF_ERROR;
[1574]     }
[1575] 
[1576]     names = ngx_dlsym(handle, "ngx_module_names");
[1577]     if (names == NULL) {
[1578]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1579]                            ngx_dlsym_n " \"%V\", \"%s\" failed (%s)",
[1580]                            &value[1], "ngx_module_names", ngx_dlerror());
[1581]         return NGX_CONF_ERROR;
[1582]     }
[1583] 
[1584]     order = ngx_dlsym(handle, "ngx_module_order");
[1585] 
[1586]     for (i = 0; modules[i]; i++) {
[1587]         module = modules[i];
[1588]         module->name = names[i];
[1589] 
[1590]         if (ngx_add_module(cf, &file, module, order) != NGX_OK) {
[1591]             return NGX_CONF_ERROR;
[1592]         }
[1593] 
[1594]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, cf->log, 0, "module: %s i:%ui",
[1595]                        module->name, module->index);
[1596]     }
[1597] 
[1598]     return NGX_CONF_OK;
[1599] 
[1600] #else
[1601] 
[1602]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1603]                        "\"load_module\" is not supported "
[1604]                        "on this platform");
[1605]     return NGX_CONF_ERROR;
[1606] 
[1607] #endif
[1608] }
[1609] 
[1610] 
[1611] #if (NGX_HAVE_DLOPEN)
[1612] 
[1613] static void
[1614] ngx_unload_module(void *data)
[1615] {
[1616]     void  *handle = data;
[1617] 
[1618]     if (ngx_dlclose(handle) != 0) {
[1619]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[1620]                       ngx_dlclose_n " failed (%s)", ngx_dlerror());
[1621]     }
[1622] }
[1623] 
[1624] #endif
