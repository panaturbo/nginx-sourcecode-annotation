[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SLAB_H_INCLUDED_
[9] #define _NGX_SLAB_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct ngx_slab_page_s  ngx_slab_page_t;
[17] 
[18] struct ngx_slab_page_s {
[19]     uintptr_t         slab;
[20]     ngx_slab_page_t  *next;
[21]     uintptr_t         prev;
[22] };
[23] 
[24] 
[25] typedef struct {
[26]     ngx_uint_t        total;
[27]     ngx_uint_t        used;
[28] 
[29]     ngx_uint_t        reqs;
[30]     ngx_uint_t        fails;
[31] } ngx_slab_stat_t;
[32] 
[33] 
[34] typedef struct {
[35]     ngx_shmtx_sh_t    lock;
[36] 
[37]     size_t            min_size;
[38]     size_t            min_shift;
[39] 
[40]     ngx_slab_page_t  *pages;
[41]     ngx_slab_page_t  *last;
[42]     ngx_slab_page_t   free;
[43] 
[44]     ngx_slab_stat_t  *stats;
[45]     ngx_uint_t        pfree;
[46] 
[47]     u_char           *start;
[48]     u_char           *end;
[49] 
[50]     ngx_shmtx_t       mutex;
[51] 
[52]     u_char           *log_ctx;
[53]     u_char            zero;
[54] 
[55]     unsigned          log_nomem:1;
[56] 
[57]     void             *data;
[58]     void             *addr;
[59] } ngx_slab_pool_t;
[60] 
[61] 
[62] void ngx_slab_sizes_init(void);
[63] void ngx_slab_init(ngx_slab_pool_t *pool);
[64] void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
[65] void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
[66] void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
[67] void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
[68] void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
[69] void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);
[70] 
[71] 
[72] #endif /* _NGX_SLAB_H_INCLUDED_ */
