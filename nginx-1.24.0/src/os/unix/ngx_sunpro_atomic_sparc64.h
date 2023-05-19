[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #if (NGX_PTR_SIZE == 4)
[9] #define NGX_CASA  ngx_casa
[10] #else
[11] #define NGX_CASA  ngx_casxa
[12] #endif
[13] 
[14] 
[15] ngx_atomic_uint_t
[16] ngx_casa(ngx_atomic_uint_t set, ngx_atomic_uint_t old, ngx_atomic_t *lock);
[17] 
[18] ngx_atomic_uint_t
[19] ngx_casxa(ngx_atomic_uint_t set, ngx_atomic_uint_t old, ngx_atomic_t *lock);
[20] 
[21] /* the code in src/os/unix/ngx_sunpro_sparc64.il */
[22] 
[23] 
[24] static ngx_inline ngx_atomic_uint_t
[25] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[26]     ngx_atomic_uint_t set)
[27] {
[28]     set = NGX_CASA(set, old, lock);
[29] 
[30]     return (set == old);
[31] }
[32] 
[33] 
[34] static ngx_inline ngx_atomic_int_t
[35] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[36] {
[37]     ngx_atomic_uint_t  old, res;
[38] 
[39]     old = *value;
[40] 
[41]     for ( ;; ) {
[42] 
[43]         res = old + add;
[44] 
[45]         res = NGX_CASA(res, old, value);
[46] 
[47]         if (res == old) {
[48]             return res;
[49]         }
[50] 
[51]         old = res;
[52]     }
[53] }
[54] 
[55] 
[56] #define ngx_memory_barrier()                                                  \
[57]         __asm (".volatile");                                                  \
[58]         __asm ("membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad");   \
[59]         __asm (".nonvolatile")
[60] 
[61] #define ngx_cpu_pause()
