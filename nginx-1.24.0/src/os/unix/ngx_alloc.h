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
[20] 
[21] 
[22] /*
[23]  * Linux has memalign() or posix_memalign()
[24]  * Solaris has memalign()
[25]  * FreeBSD 7.0 has posix_memalign(), besides, early version's malloc()
[26]  * aligns allocations bigger than page size at the page boundary
[27]  */
[28] 
[29] #if (NGX_HAVE_POSIX_MEMALIGN || NGX_HAVE_MEMALIGN)
[30] 
[31] void *ngx_memalign(size_t alignment, size_t size, ngx_log_t *log);
[32] 
[33] #else
[34] 
[35] #define ngx_memalign(alignment, size, log)  ngx_alloc(size, log)
[36] 
[37] #endif
[38] 
[39] 
[40] extern ngx_uint_t  ngx_pagesize;
[41] extern ngx_uint_t  ngx_pagesize_shift;
[42] extern ngx_uint_t  ngx_cacheline_size;
[43] 
[44] 
[45] #endif /* _NGX_ALLOC_H_INCLUDED_ */
