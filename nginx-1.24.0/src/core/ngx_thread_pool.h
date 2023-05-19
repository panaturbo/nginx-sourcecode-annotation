[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_THREAD_POOL_H_INCLUDED_
[9] #define _NGX_THREAD_POOL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] 
[16] 
[17] struct ngx_thread_task_s {
[18]     ngx_thread_task_t   *next;
[19]     ngx_uint_t           id;
[20]     void                *ctx;
[21]     void               (*handler)(void *data, ngx_log_t *log);
[22]     ngx_event_t          event;
[23] };
[24] 
[25] 
[26] typedef struct ngx_thread_pool_s  ngx_thread_pool_t;
[27] 
[28] 
[29] ngx_thread_pool_t *ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);
[30] ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);
[31] 
[32] ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size);
[33] ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task);
[34] 
[35] 
[36] #endif /* _NGX_THREAD_POOL_H_INCLUDED_ */
