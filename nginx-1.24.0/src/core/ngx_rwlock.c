[1] 
[2] /*
[3]  * Copyright (C) Ruslan Ermilov
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] #if (NGX_HAVE_ATOMIC_OPS)
[13] 
[14] 
[15] #define NGX_RWLOCK_SPIN   2048
[16] #define NGX_RWLOCK_WLOCK  ((ngx_atomic_uint_t) -1)
[17] 
[18] 
[19] void
[20] ngx_rwlock_wlock(ngx_atomic_t *lock)
[21] {
[22]     ngx_uint_t  i, n;
[23] 
[24]     for ( ;; ) {
[25] 
[26]         if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK)) {
[27]             return;
[28]         }
[29] 
[30]         if (ngx_ncpu > 1) {
[31] 
[32]             for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1) {
[33] 
[34]                 for (i = 0; i < n; i++) {
[35]                     ngx_cpu_pause();
[36]                 }
[37] 
[38]                 if (*lock == 0
[39]                     && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK))
[40]                 {
[41]                     return;
[42]                 }
[43]             }
[44]         }
[45] 
[46]         ngx_sched_yield();
[47]     }
[48] }
[49] 
[50] 
[51] void
[52] ngx_rwlock_rlock(ngx_atomic_t *lock)
[53] {
[54]     ngx_uint_t         i, n;
[55]     ngx_atomic_uint_t  readers;
[56] 
[57]     for ( ;; ) {
[58]         readers = *lock;
[59] 
[60]         if (readers != NGX_RWLOCK_WLOCK
[61]             && ngx_atomic_cmp_set(lock, readers, readers + 1))
[62]         {
[63]             return;
[64]         }
[65] 
[66]         if (ngx_ncpu > 1) {
[67] 
[68]             for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1) {
[69] 
[70]                 for (i = 0; i < n; i++) {
[71]                     ngx_cpu_pause();
[72]                 }
[73] 
[74]                 readers = *lock;
[75] 
[76]                 if (readers != NGX_RWLOCK_WLOCK
[77]                     && ngx_atomic_cmp_set(lock, readers, readers + 1))
[78]                 {
[79]                     return;
[80]                 }
[81]             }
[82]         }
[83] 
[84]         ngx_sched_yield();
[85]     }
[86] }
[87] 
[88] 
[89] void
[90] ngx_rwlock_unlock(ngx_atomic_t *lock)
[91] {
[92]     if (*lock == NGX_RWLOCK_WLOCK) {
[93]         (void) ngx_atomic_cmp_set(lock, NGX_RWLOCK_WLOCK, 0);
[94]     } else {
[95]         (void) ngx_atomic_fetch_add(lock, -1);
[96]     }
[97] }
[98] 
[99] 
[100] void
[101] ngx_rwlock_downgrade(ngx_atomic_t *lock)
[102] {
[103]     if (*lock == NGX_RWLOCK_WLOCK) {
[104]         *lock = 1;
[105]     }
[106] }
[107] 
[108] 
[109] #else
[110] 
[111] #if (NGX_HTTP_UPSTREAM_ZONE || NGX_STREAM_UPSTREAM_ZONE)
[112] 
[113] #error ngx_atomic_cmp_set() is not defined!
[114] 
[115] #endif
[116] 
[117] #endif
