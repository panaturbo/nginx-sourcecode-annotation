[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_THREAD_H_INCLUDED_
[9] #define _NGX_THREAD_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef HANDLE  ngx_tid_t;
[17] typedef DWORD   ngx_thread_value_t;
[18] 
[19] 
[20] ngx_err_t ngx_create_thread(ngx_tid_t *tid,
[21]     ngx_thread_value_t (__stdcall *func)(void *arg), void *arg, ngx_log_t *log);
[22] 
[23] #define ngx_log_tid                 GetCurrentThreadId()
[24] #define NGX_TID_T_FMT               "%ud"
[25] 
[26] 
[27] #endif /* _NGX_THREAD_H_INCLUDED_ */
