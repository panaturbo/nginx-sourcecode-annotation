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
[12] ngx_int_t
[13] ngx_daemon(ngx_log_t *log)
[14] {
[15]     int  fd;
[16] 
[17]     switch (fork()) {
[18]     case -1:
[19]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "fork() failed");
[20]         return NGX_ERROR;
[21] 
[22]     case 0:
[23]         break;
[24] 
[25]     default:
[26]         exit(0);
[27]     }
[28] 
[29]     ngx_parent = ngx_pid;
[30]     ngx_pid = ngx_getpid();
[31] 
[32]     if (setsid() == -1) {
[33]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "setsid() failed");
[34]         return NGX_ERROR;
[35]     }
[36] 
[37]     umask(0);
[38] 
[39]     fd = open("/dev/null", O_RDWR);
[40]     if (fd == -1) {
[41]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[42]                       "open(\"/dev/null\") failed");
[43]         return NGX_ERROR;
[44]     }
[45] 
[46]     if (dup2(fd, STDIN_FILENO) == -1) {
[47]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDIN) failed");
[48]         return NGX_ERROR;
[49]     }
[50] 
[51]     if (dup2(fd, STDOUT_FILENO) == -1) {
[52]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDOUT) failed");
[53]         return NGX_ERROR;
[54]     }
[55] 
[56] #if 0
[57]     if (dup2(fd, STDERR_FILENO) == -1) {
[58]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDERR) failed");
[59]         return NGX_ERROR;
[60]     }
[61] #endif
[62] 
[63]     if (fd > STDERR_FILENO) {
[64]         if (close(fd) == -1) {
[65]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "close() failed");
[66]             return NGX_ERROR;
[67]         }
[68]     }
[69] 
[70]     return NGX_OK;
[71] }
