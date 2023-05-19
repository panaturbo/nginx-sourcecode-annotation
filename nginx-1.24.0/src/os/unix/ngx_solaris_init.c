[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] char ngx_solaris_sysname[20];
[13] char ngx_solaris_release[10];
[14] char ngx_solaris_version[50];
[15] 
[16] 
[17] static ngx_os_io_t ngx_solaris_io = {
[18]     ngx_unix_recv,
[19]     ngx_readv_chain,
[20]     ngx_udp_unix_recv,
[21]     ngx_unix_send,
[22]     ngx_udp_unix_send,
[23]     ngx_udp_unix_sendmsg_chain,
[24] #if (NGX_HAVE_SENDFILE)
[25]     ngx_solaris_sendfilev_chain,
[26]     NGX_IO_SENDFILE
[27] #else
[28]     ngx_writev_chain,
[29]     0
[30] #endif
[31] };
[32] 
[33] 
[34] ngx_int_t
[35] ngx_os_specific_init(ngx_log_t *log)
[36] {
[37]     if (sysinfo(SI_SYSNAME, ngx_solaris_sysname, sizeof(ngx_solaris_sysname))
[38]         == -1)
[39]     {
[40]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[41]                       "sysinfo(SI_SYSNAME) failed");
[42]         return NGX_ERROR;
[43]     }
[44] 
[45]     if (sysinfo(SI_RELEASE, ngx_solaris_release, sizeof(ngx_solaris_release))
[46]         == -1)
[47]     {
[48]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[49]                       "sysinfo(SI_RELEASE) failed");
[50]         return NGX_ERROR;
[51]     }
[52] 
[53]     if (sysinfo(SI_VERSION, ngx_solaris_version, sizeof(ngx_solaris_version))
[54]         == -1)
[55]     {
[56]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[57]                       "sysinfo(SI_SYSNAME) failed");
[58]         return NGX_ERROR;
[59]     }
[60] 
[61] 
[62]     ngx_os_io = ngx_solaris_io;
[63] 
[64]     return NGX_OK;
[65] }
[66] 
[67] 
[68] void
[69] ngx_os_specific_status(ngx_log_t *log)
[70] {
[71] 
[72]     ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
[73]                   ngx_solaris_sysname, ngx_solaris_release);
[74] 
[75]     ngx_log_error(NGX_LOG_NOTICE, log, 0, "version: %s",
[76]                   ngx_solaris_version);
[77] }
