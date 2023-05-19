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
[12] void
[13] ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
[14] {
[15] 
[16] #if (NGX_HAVE_ATOMIC_OPS)
[17] 
[18]     ngx_uint_t  i, n;
[19] 
[20]     for ( ;; ) {
[21] 
[22]         if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
[23]             return;
[24]         }
[25] 
[26]         if (ngx_ncpu > 1) {
[27] 
[28]             for (n = 1; n < spin; n <<= 1) {
[29] 
[30]                 for (i = 0; i < n; i++) {
[31]                     ngx_cpu_pause();
[32]                 }
[33] 
[34]                 if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
[35]                     return;
[36]                 }
[37]             }
[38]         }
[39] 
[40]         ngx_sched_yield();
[41]     }
[42] 
[43] #else
[44] 
[45] #if (NGX_THREADS)
[46] 
[47] #error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !
[48] 
[49] #endif
[50] 
[51] #endif
[52] 
[53] }
