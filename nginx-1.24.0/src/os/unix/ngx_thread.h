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
[15] #if (NGX_THREADS)
[16] 
[17] #include <pthread.h>
[18] 
[19] 
[20] typedef pthread_mutex_t  ngx_thread_mutex_t;
[21] 
[22] ngx_int_t ngx_thread_mutex_create(ngx_thread_mutex_t *mtx, ngx_log_t *log);
[23] ngx_int_t ngx_thread_mutex_destroy(ngx_thread_mutex_t *mtx, ngx_log_t *log);
[24] ngx_int_t ngx_thread_mutex_lock(ngx_thread_mutex_t *mtx, ngx_log_t *log);
[25] ngx_int_t ngx_thread_mutex_unlock(ngx_thread_mutex_t *mtx, ngx_log_t *log);
[26] 
[27] 
[28] typedef pthread_cond_t  ngx_thread_cond_t;
[29] 
[30] ngx_int_t ngx_thread_cond_create(ngx_thread_cond_t *cond, ngx_log_t *log);
[31] ngx_int_t ngx_thread_cond_destroy(ngx_thread_cond_t *cond, ngx_log_t *log);
[32] ngx_int_t ngx_thread_cond_signal(ngx_thread_cond_t *cond, ngx_log_t *log);
[33] ngx_int_t ngx_thread_cond_wait(ngx_thread_cond_t *cond, ngx_thread_mutex_t *mtx,
[34]     ngx_log_t *log);
[35] 
[36] 
[37] #if (NGX_LINUX)
[38] 
[39] typedef pid_t      ngx_tid_t;
[40] #define NGX_TID_T_FMT         "%P"
[41] 
[42] #elif (NGX_FREEBSD)
[43] 
[44] typedef uint32_t   ngx_tid_t;
[45] #define NGX_TID_T_FMT         "%uD"
[46] 
[47] #elif (NGX_DARWIN)
[48] 
[49] typedef uint64_t   ngx_tid_t;
[50] #define NGX_TID_T_FMT         "%uL"
[51] 
[52] #else
[53] 
[54] typedef uint64_t   ngx_tid_t;
[55] #define NGX_TID_T_FMT         "%uL"
[56] 
[57] #endif
[58] 
[59] ngx_tid_t ngx_thread_tid(void);
[60] 
[61] #define ngx_log_tid           ngx_thread_tid()
[62] 
[63] #else
[64] 
[65] #define ngx_log_tid           0
[66] #define NGX_TID_T_FMT         "%d"
[67] 
[68] #endif
[69] 
[70] 
[71] #endif /* _NGX_THREAD_H_INCLUDED_ */
