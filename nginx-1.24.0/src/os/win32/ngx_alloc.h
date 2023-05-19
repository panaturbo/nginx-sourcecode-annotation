[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_ALLOC_H_INCLUDED_
[9] #define _NGX_ALLOC_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] void *ngx_alloc(size_t size, ngx_log_t *log);
[17] void *ngx_calloc(size_t size, ngx_log_t *log);
[18] 
[19] #define ngx_free          free
[20] #define ngx_memalign(alignment, size, log)  ngx_alloc(size, log)
[21] 
[22] extern ngx_uint_t  ngx_pagesize;
[23] extern ngx_uint_t  ngx_pagesize_shift;
[24] extern ngx_uint_t  ngx_cacheline_size;
[25] 
[26] 
[27] #endif /* _NGX_ALLOC_H_INCLUDED_ */
