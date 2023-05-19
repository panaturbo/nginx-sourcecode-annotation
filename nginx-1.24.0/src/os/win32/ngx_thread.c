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
[12] ngx_err_t
[13] ngx_create_thread(ngx_tid_t *tid,
[14]     ngx_thread_value_t (__stdcall *func)(void *arg), void *arg, ngx_log_t *log)
[15] {
[16]     u_long     id;
[17]     ngx_err_t  err;
[18] 
[19]     *tid = CreateThread(NULL, 0, func, arg, 0, &id);
[20] 
[21]     if (*tid != NULL) {
[22]         ngx_log_error(NGX_LOG_NOTICE, log, 0,
[23]                       "create thread " NGX_TID_T_FMT, id);
[24]         return 0;
[25]     }
[26] 
[27]     err = ngx_errno;
[28]     ngx_log_error(NGX_LOG_ALERT, log, err, "CreateThread() failed");
[29]     return err;
[30] }
