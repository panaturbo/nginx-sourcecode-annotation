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
[17] void *
[18] ngx_alloc(size_t size, ngx_log_t *log)
[19] {
[20]     void  *p;
[21] 
[22]     p = malloc(size);
[23]     if (p == NULL) {
[24]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[25]                       "malloc(%uz) failed", size);
[26]     }
[27] 
[28]     ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);
[29] 
[30]     return p;
[31] }
[32] 
[33] 
[34] void *
[35] ngx_calloc(size_t size, ngx_log_t *log)
[36] {
[37]     void  *p;
[38] 
[39]     p = ngx_alloc(size, log);
[40] 
[41]     if (p) {
[42]         ngx_memzero(p, size);
[43]     }
[44] 
[45]     return p;
[46] }
[47] 
[48] 
[49] #if (NGX_HAVE_POSIX_MEMALIGN)
[50] 
[51] void *
[52] ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
[53] {
[54]     void  *p;
[55]     int    err;
[56] 
[57]     err = posix_memalign(&p, alignment, size);
[58] 
[59]     if (err) {
[60]         ngx_log_error(NGX_LOG_EMERG, log, err,
[61]                       "posix_memalign(%uz, %uz) failed", alignment, size);
[62]         p = NULL;
[63]     }
[64] 
[65]     ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, log, 0,
[66]                    "posix_memalign: %p:%uz @%uz", p, size, alignment);
[67] 
[68]     return p;
[69] }
[70] 
[71] #elif (NGX_HAVE_MEMALIGN)
[72] 
[73] void *
[74] ngx_memalign(size_t alignment, size_t size, ngx_log_t *log)
[75] {
[76]     void  *p;
[77] 
[78]     p = memalign(alignment, size);
[79]     if (p == NULL) {
[80]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[81]                       "memalign(%uz, %uz) failed", alignment, size);
[82]     }
[83] 
[84]     ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, log, 0,
[85]                    "memalign: %p:%uz @%uz", p, size, alignment);
[86] 
[87]     return p;
[88] }
[89] 
[90] #endif
