[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] /*
[9]  * "casa   [r1] 0x80, r2, r0"  and
[10]  * "casxa  [r1] 0x80, r2, r0"  do the following:
[11]  *
[12]  *     if ([r1] == r2) {
[13]  *         swap(r0, [r1]);
[14]  *     } else {
[15]  *         r0 = [r1];
[16]  *     }
[17]  *
[18]  * so "r0 == r2" means that the operation was successful.
[19]  *
[20]  *
[21]  * The "r" means the general register.
[22]  * The "+r" means the general register used for both input and output.
[23]  */
[24] 
[25] 
[26] #if (NGX_PTR_SIZE == 4)
[27] #define NGX_CASA  "casa"
[28] #else
[29] #define NGX_CASA  "casxa"
[30] #endif
[31] 
[32] 
[33] static ngx_inline ngx_atomic_uint_t
[34] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[35]     ngx_atomic_uint_t set)
[36] {
[37]     __asm__ volatile (
[38] 
[39]     NGX_CASA " [%1] 0x80, %2, %0"
[40] 
[41]     : "+r" (set) : "r" (lock), "r" (old) : "memory");
[42] 
[43]     return (set == old);
[44] }
[45] 
[46] 
[47] static ngx_inline ngx_atomic_int_t
[48] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[49] {
[50]     ngx_atomic_uint_t  old, res;
[51] 
[52]     old = *value;
[53] 
[54]     for ( ;; ) {
[55] 
[56]         res = old + add;
[57] 
[58]         __asm__ volatile (
[59] 
[60]         NGX_CASA " [%1] 0x80, %2, %0"
[61] 
[62]         : "+r" (res) : "r" (value), "r" (old) : "memory");
[63] 
[64]         if (res == old) {
[65]             return res;
[66]         }
[67] 
[68]         old = res;
[69]     }
[70] }
[71] 
[72] 
[73] #if (NGX_SMP)
[74] #define ngx_memory_barrier()                                                  \
[75]             __asm__ volatile (                                                \
[76]             "membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad"        \
[77]             ::: "memory")
[78] #else
[79] #define ngx_memory_barrier()   __asm__ volatile ("" ::: "memory")
[80] #endif
[81] 
[82] #define ngx_cpu_pause()
