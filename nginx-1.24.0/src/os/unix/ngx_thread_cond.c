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
[13] ngx_thread_cond_create(ngx_thread_cond_t *cond, ngx_log_t *log)
[14] {
[15]     ngx_err_t  err;
[16] 
[17]     err = pthread_cond_init(cond, NULL);
[18]     if (err == 0) {
[19]         return NGX_OK;
[20]     }
[21] 
[22]     ngx_log_error(NGX_LOG_EMERG, log, err, "pthread_cond_init() failed");
[23]     return NGX_ERROR;
[24] }
[25] 
[26] 
[27] ngx_int_t
[28] ngx_thread_cond_destroy(ngx_thread_cond_t *cond, ngx_log_t *log)
[29] {
[30]     ngx_err_t  err;
[31] 
[32]     err = pthread_cond_destroy(cond);
[33]     if (err == 0) {
[34]         return NGX_OK;
[35]     }
[36] 
[37]     ngx_log_error(NGX_LOG_EMERG, log, err, "pthread_cond_destroy() failed");
[38]     return NGX_ERROR;
[39] }
[40] 
[41] 
[42] ngx_int_t
[43] ngx_thread_cond_signal(ngx_thread_cond_t *cond, ngx_log_t *log)
[44] {
[45]     ngx_err_t  err;
[46] 
[47]     err = pthread_cond_signal(cond);
[48]     if (err == 0) {
[49]         return NGX_OK;
[50]     }
[51] 
[52]     ngx_log_error(NGX_LOG_EMERG, log, err, "pthread_cond_signal() failed");
[53]     return NGX_ERROR;
[54] }
[55] 
[56] 
[57] ngx_int_t
[58] ngx_thread_cond_wait(ngx_thread_cond_t *cond, ngx_thread_mutex_t *mtx,
[59]     ngx_log_t *log)
[60] {
[61]     ngx_err_t  err;
[62] 
[63]     err = pthread_cond_wait(cond, mtx);
[64] 
[65] #if 0
[66]     ngx_time_update();
[67] #endif
[68] 
[69]     if (err == 0) {
[70]         return NGX_OK;
[71]     }
[72] 
[73]     ngx_log_error(NGX_LOG_ALERT, log, err, "pthread_cond_wait() failed");
[74] 
[75]     return NGX_ERROR;
[76] }
