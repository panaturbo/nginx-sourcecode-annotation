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
[20]     ngx_log_t   *log;
[21]     ngx_uint_t   exists;   /* unsigned  exists:1;  */
[22] } ngx_shm_t;
[23] 
[24] 
[25] ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
[26] void ngx_shm_free(ngx_shm_t *shm);
[27] 
[28] 
[29] #endif /* _NGX_SHMEM_H_INCLUDED_ */
