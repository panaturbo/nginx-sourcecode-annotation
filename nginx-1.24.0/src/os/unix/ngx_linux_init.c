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
[12] u_char  ngx_linux_kern_ostype[50];
[13] u_char  ngx_linux_kern_osrelease[50];
[14] 
[15] 
[16] static ngx_os_io_t ngx_linux_io = {
[17]     ngx_unix_recv,
[18]     ngx_readv_chain,
[19]     ngx_udp_unix_recv,
[20]     ngx_unix_send,
[21]     ngx_udp_unix_send,
[22]     ngx_udp_unix_sendmsg_chain,
[23] #if (NGX_HAVE_SENDFILE)
[24]     ngx_linux_sendfile_chain,
[25]     NGX_IO_SENDFILE
[26] #else
[27]     ngx_writev_chain,
[28]     0
[29] #endif
[30] };
[31] 
[32] 
[33] ngx_int_t
[34] ngx_os_specific_init(ngx_log_t *log)
[35] {
[36]     struct utsname  u;
[37] 
[38]     if (uname(&u) == -1) {
[39]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "uname() failed");
[40]         return NGX_ERROR;
[41]     }
[42] 
[43]     (void) ngx_cpystrn(ngx_linux_kern_ostype, (u_char *) u.sysname,
[44]                        sizeof(ngx_linux_kern_ostype));
[45] 
[46]     (void) ngx_cpystrn(ngx_linux_kern_osrelease, (u_char *) u.release,
[47]                        sizeof(ngx_linux_kern_osrelease));
[48] 
[49]     ngx_os_io = ngx_linux_io;
[50] 
[51]     return NGX_OK;
[52] }
[53] 
[54] 
[55] void
[56] ngx_os_specific_status(ngx_log_t *log)
[57] {
[58]     ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
[59]                   ngx_linux_kern_ostype, ngx_linux_kern_osrelease);
[60] }
