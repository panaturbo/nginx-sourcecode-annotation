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
[13] ngx_int_t   ngx_ncpu;
[14] ngx_int_t   ngx_max_sockets;
[15] ngx_uint_t  ngx_inherited_nonblocking;
[16] ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;
[17] 
[18] 
[19] struct rlimit  rlmt;
[20] 
[21] 
[22] ngx_os_io_t ngx_os_io = {
[23]     ngx_unix_recv,
[24]     ngx_readv_chain,
[25]     ngx_udp_unix_recv,
[26]     ngx_unix_send,
[27]     ngx_udp_unix_send,
[28]     ngx_udp_unix_sendmsg_chain,
[29]     ngx_writev_chain,
[30]     0
[31] };
[32] 
[33] 
[34] ngx_int_t
[35] ngx_os_init(ngx_log_t *log)
[36] {
[37]     ngx_time_t  *tp;
[38]     ngx_uint_t   n;
[39] #if (NGX_HAVE_LEVEL1_DCACHE_LINESIZE)
[40]     long         size;
[41] #endif
[42] 
[43] #if (NGX_HAVE_OS_SPECIFIC_INIT)
[44]     if (ngx_os_specific_init(log) != NGX_OK) {
[45]         return NGX_ERROR;
[46]     }
[47] #endif
[48] 
[49]     if (ngx_init_setproctitle(log) != NGX_OK) {
[50]         return NGX_ERROR;
[51]     }
[52] 
[53]     ngx_pagesize = getpagesize();
[54]     ngx_cacheline_size = NGX_CPU_CACHE_LINE;
[55] 
[56]     for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }
[57] 
[58] #if (NGX_HAVE_SC_NPROCESSORS_ONLN)
[59]     if (ngx_ncpu == 0) {
[60]         ngx_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
[61]     }
[62] #endif
[63] 
[64]     if (ngx_ncpu < 1) {
[65]         ngx_ncpu = 1;
[66]     }
[67] 
[68] #if (NGX_HAVE_LEVEL1_DCACHE_LINESIZE)
[69]     size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
[70]     if (size > 0) {
[71]         ngx_cacheline_size = size;
[72]     }
[73] #endif
[74] 
[75]     ngx_cpuinfo();
[76] 
[77]     if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
[78]         ngx_log_error(NGX_LOG_ALERT, log, errno,
[79]                       "getrlimit(RLIMIT_NOFILE) failed");
[80]         return NGX_ERROR;
[81]     }
[82] 
[83]     ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur;
[84] 
[85] #if (NGX_HAVE_INHERITED_NONBLOCK || NGX_HAVE_ACCEPT4)
[86]     ngx_inherited_nonblocking = 1;
[87] #else
[88]     ngx_inherited_nonblocking = 0;
[89] #endif
[90] 
[91]     tp = ngx_timeofday();
[92]     srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);
[93] 
[94]     return NGX_OK;
[95] }
[96] 
[97] 
[98] void
[99] ngx_os_status(ngx_log_t *log)
[100] {
[101]     ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER_BUILD);
[102] 
[103] #ifdef NGX_COMPILER
[104]     ngx_log_error(NGX_LOG_NOTICE, log, 0, "built by " NGX_COMPILER);
[105] #endif
[106] 
[107] #if (NGX_HAVE_OS_SPECIFIC_INIT)
[108]     ngx_os_specific_status(log);
[109] #endif
[110] 
[111]     ngx_log_error(NGX_LOG_NOTICE, log, 0,
[112]                   "getrlimit(RLIMIT_NOFILE): %r:%r",
[113]                   rlmt.rlim_cur, rlmt.rlim_max);
[114] }
[115] 
[116] 
[117] #if 0
[118] 
[119] ngx_int_t
[120] ngx_posix_post_conf_init(ngx_log_t *log)
[121] {
[122]     ngx_fd_t  pp[2];
[123] 
[124]     if (pipe(pp) == -1) {
[125]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
[126]         return NGX_ERROR;
[127]     }
[128] 
[129]     if (dup2(pp[1], STDERR_FILENO) == -1) {
[130]         ngx_log_error(NGX_LOG_EMERG, log, errno, "dup2(STDERR) failed");
[131]         return NGX_ERROR;
[132]     }
[133] 
[134]     if (pp[1] > STDERR_FILENO) {
[135]         if (close(pp[1]) == -1) {
[136]             ngx_log_error(NGX_LOG_EMERG, log, errno, "close() failed");
[137]             return NGX_ERROR;
[138]         }
[139]     }
[140] 
[141]     return NGX_OK;
[142] }
[143] 
[144] #endif
