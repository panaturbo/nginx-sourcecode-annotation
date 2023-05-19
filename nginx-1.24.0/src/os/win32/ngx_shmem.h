[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SHMEM_H_INCLUDED_
[9] #define _NGX_SHMEM_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     u_char      *addr;
[18]     size_t       size;
[19]     ngx_str_t    name;
[20]     HANDLE       handle;
[21]     ngx_log_t   *log;
[22]     ngx_uint_t   exists;   /* unsigned  exists:1;  */
[23] } ngx_shm_t;
[24] 
[25] 
[26] ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
[27] ngx_int_t ngx_shm_remap(ngx_shm_t *shm, u_char *addr);
[28] void ngx_shm_free(ngx_shm_t *shm);
[29] 
[30] extern ngx_uint_t  ngx_allocation_granularity;
[31] 
[32] 
[33] #endif /* _NGX_SHMEM_H_INCLUDED_ */
