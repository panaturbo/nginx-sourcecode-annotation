[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_PALLOC_H_INCLUDED_
[9] #define _NGX_PALLOC_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] /*
[17]  * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
[18]  * On Windows NT it decreases a number of locked pages in a kernel.
[19]  */
[20] #define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)
[21] 
[22] #define NGX_DEFAULT_POOL_SIZE    (16 * 1024)
[23] 
[24] #define NGX_POOL_ALIGNMENT       16
[25] #define NGX_MIN_POOL_SIZE                                                     \
[26]     ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
[27]               NGX_POOL_ALIGNMENT)
[28] 
[29] 
[30] typedef void (*ngx_pool_cleanup_pt)(void *data);
[31] 
[32] typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;
[33] 
[34] struct ngx_pool_cleanup_s {
[35]     ngx_pool_cleanup_pt   handler;
[36]     void                 *data;
[37]     ngx_pool_cleanup_t   *next;
[38] };
[39] 
[40] 
[41] typedef struct ngx_pool_large_s  ngx_pool_large_t;
[42] 
[43] struct ngx_pool_large_s {
[44]     ngx_pool_large_t     *next;
[45]     void                 *alloc;
[46] };
[47] 
[48] 
[49] typedef struct {
[50]     u_char               *last;
[51]     u_char               *end;
[52]     ngx_pool_t           *next;
[53]     ngx_uint_t            failed;
[54] } ngx_pool_data_t;
[55] 
[56] 
[57] struct ngx_pool_s {
[58]     ngx_pool_data_t       d;
[59]     size_t                max;
[60]     ngx_pool_t           *current;
[61]     ngx_chain_t          *chain;
[62]     ngx_pool_large_t     *large;
[63]     ngx_pool_cleanup_t   *cleanup;
[64]     ngx_log_t            *log;
[65] };
[66] 
[67] 
[68] typedef struct {
[69]     ngx_fd_t              fd;
[70]     u_char               *name;
[71]     ngx_log_t            *log;
[72] } ngx_pool_cleanup_file_t;
[73] 
[74] 
[75] ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
[76] void ngx_destroy_pool(ngx_pool_t *pool);
[77] void ngx_reset_pool(ngx_pool_t *pool);
[78] 
[79] void *ngx_palloc(ngx_pool_t *pool, size_t size);
[80] void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
[81] void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
[82] void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
[83] ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);
[84] 
[85] 
[86] ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
[87] void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
[88] void ngx_pool_cleanup_file(void *data);
[89] void ngx_pool_delete_file(void *data);
[90] 
[91] 
[92] #endif /* _NGX_PALLOC_H_INCLUDED_ */
