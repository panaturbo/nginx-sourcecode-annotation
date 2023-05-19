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
[12] ngx_uint_t  ngx_pagesize;
[13] ngx_uint_t  ngx_pagesize_shift;
[14] ngx_uint_t  ngx_cacheline_size;
[15] 
[16] 
[17] void *ngx_alloc(size_t size, ngx_log_t *log)
[18] {
[19]     void  *p;
[20] 
[21]     p = malloc(size);
[22]     if (p == NULL) {
[23]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[24]                       "malloc(%uz) failed", size);
[25]     }
[26] 
[27]     ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);
[28] 
[29]     return p;
[30] }
[31] 
[32] 
[33] void *ngx_calloc(size_t size, ngx_log_t *log)
[34] {
[35]     void  *p;
[36] 
[37]     p = ngx_alloc(size, log);
[38] 
[39]     if (p) {
[40]         ngx_memzero(p, size);
[41]     }
[42] 
[43]     return p;
[44] }
