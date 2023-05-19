[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SHMTX_H_INCLUDED_
[9] #define _NGX_SHMTX_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     ngx_atomic_t   lock;
[18] #if (NGX_HAVE_POSIX_SEM)
[19]     ngx_atomic_t   wait;
[20] #endif
[21] } ngx_shmtx_sh_t;
[22] 
[23] 
[24] typedef struct {
[25] #if (NGX_HAVE_ATOMIC_OPS)
[26]     ngx_atomic_t  *lock;
[27] #if (NGX_HAVE_POSIX_SEM)
[28]     ngx_atomic_t  *wait;
[29]     ngx_uint_t     semaphore;
[30]     sem_t          sem;
[31] #endif
[32] #else
[33]     ngx_fd_t       fd;
[34]     u_char        *name;
[35] #endif
[36]     ngx_uint_t     spin;
[37] } ngx_shmtx_t;
[38] 
[39] 
[40] ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
[41]     u_char *name);
[42] void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
[43] ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
[44] void ngx_shmtx_lock(ngx_shmtx_t *mtx);
[45] void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
[46] ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);
[47] 
[48] 
[49] #endif /* _NGX_SHMTX_H_INCLUDED_ */
