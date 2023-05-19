[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #if (NGX_SMP)
[9] #define NGX_SMP_LOCK  "lock;"
[10] #else
[11] #define NGX_SMP_LOCK
[12] #endif
[13] 
[14] 
[15] /*
[16]  * "cmpxchgq  r, [m]":
[17]  *
[18]  *     if (rax == [m]) {
[19]  *         zf = 1;
[20]  *         [m] = r;
[21]  *     } else {
[22]  *         zf = 0;
[23]  *         rax = [m];
[24]  *     }
[25]  *
[26]  *
[27]  * The "r" is any register, %rax (%r0) - %r16.
[28]  * The "=a" and "a" are the %rax register.
[29]  * Although we can return result in any register, we use "a" because it is
[30]  * used in cmpxchgq anyway.  The result is actually in %al but not in $rax,
[31]  * however as the code is inlined gcc can test %al as well as %rax.
[32]  *
[33]  * The "cc" means that flags were changed.
[34]  */
[35] 
[36] static ngx_inline ngx_atomic_uint_t
[37] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[38]     ngx_atomic_uint_t set)
[39] {
[40]     u_char  res;
[41] 
[42]     __asm__ volatile (
[43] 
[44]          NGX_SMP_LOCK
[45]     "    cmpxchgq  %3, %1;   "
[46]     "    sete      %0;       "
[47] 
[48]     : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");
[49] 
[50]     return res;
[51] }
[52] 
[53] 
[54] /*
[55]  * "xaddq  r, [m]":
[56]  *
[57]  *     temp = [m];
[58]  *     [m] += r;
[59]  *     r = temp;
[60]  *
[61]  *
[62]  * The "+r" is any register, %rax (%r0) - %r16.
[63]  * The "cc" means that flags were changed.
[64]  */
[65] 
[66] static ngx_inline ngx_atomic_int_t
[67] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[68] {
[69]     __asm__ volatile (
[70] 
[71]          NGX_SMP_LOCK
[72]     "    xaddq  %0, %1;   "
[73] 
[74]     : "+r" (add) : "m" (*value) : "cc", "memory");
[75] 
[76]     return add;
[77] }
[78] 
[79] 
[80] #define ngx_memory_barrier()    __asm__ volatile ("" ::: "memory")
[81] 
[82] #define ngx_cpu_pause()         __asm__ ("pause")
