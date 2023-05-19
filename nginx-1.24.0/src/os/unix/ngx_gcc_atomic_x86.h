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
[16]  * "cmpxchgl  r, [m]":
[17]  *
[18]  *     if (eax == [m]) {
[19]  *         zf = 1;
[20]  *         [m] = r;
[21]  *     } else {
[22]  *         zf = 0;
[23]  *         eax = [m];
[24]  *     }
[25]  *
[26]  *
[27]  * The "r" means the general register.
[28]  * The "=a" and "a" are the %eax register.
[29]  * Although we can return result in any register, we use "a" because it is
[30]  * used in cmpxchgl anyway.  The result is actually in %al but not in %eax,
[31]  * however, as the code is inlined gcc can test %al as well as %eax,
[32]  * and icc adds "movzbl %al, %eax" by itself.
[33]  *
[34]  * The "cc" means that flags were changed.
[35]  */
[36] 
[37] static ngx_inline ngx_atomic_uint_t
[38] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[39]     ngx_atomic_uint_t set)
[40] {
[41]     u_char  res;
[42] 
[43]     __asm__ volatile (
[44] 
[45]          NGX_SMP_LOCK
[46]     "    cmpxchgl  %3, %1;   "
[47]     "    sete      %0;       "
[48] 
[49]     : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");
[50] 
[51]     return res;
[52] }
[53] 
[54] 
[55] /*
[56]  * "xaddl  r, [m]":
[57]  *
[58]  *     temp = [m];
[59]  *     [m] += r;
[60]  *     r = temp;
[61]  *
[62]  *
[63]  * The "+r" means the general register.
[64]  * The "cc" means that flags were changed.
[65]  */
[66] 
[67] 
[68] #if !(( __GNUC__ == 2 && __GNUC_MINOR__ <= 7 ) || ( __INTEL_COMPILER >= 800 ))
[69] 
[70] /*
[71]  * icc 8.1 and 9.0 compile broken code with -march=pentium4 option:
[72]  * ngx_atomic_fetch_add() always return the input "add" value,
[73]  * so we use the gcc 2.7 version.
[74]  *
[75]  * icc 8.1 and 9.0 with -march=pentiumpro option or icc 7.1 compile
[76]  * correct code.
[77]  */
[78] 
[79] static ngx_inline ngx_atomic_int_t
[80] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[81] {
[82]     __asm__ volatile (
[83] 
[84]          NGX_SMP_LOCK
[85]     "    xaddl  %0, %1;   "
[86] 
[87]     : "+r" (add) : "m" (*value) : "cc", "memory");
[88] 
[89]     return add;
[90] }
[91] 
[92] 
[93] #else
[94] 
[95] /*
[96]  * gcc 2.7 does not support "+r", so we have to use the fixed
[97]  * %eax ("=a" and "a") and this adds two superfluous instructions in the end
[98]  * of code, something like this: "mov %eax, %edx / mov %edx, %eax".
[99]  */
[100] 
[101] static ngx_inline ngx_atomic_int_t
[102] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[103] {
[104]     ngx_atomic_uint_t  old;
[105] 
[106]     __asm__ volatile (
[107] 
[108]          NGX_SMP_LOCK
[109]     "    xaddl  %2, %1;   "
[110] 
[111]     : "=a" (old) : "m" (*value), "a" (add) : "cc", "memory");
[112] 
[113]     return old;
[114] }
[115] 
[116] #endif
[117] 
[118] 
[119] /*
[120]  * on x86 the write operations go in a program order, so we need only
[121]  * to disable the gcc reorder optimizations
[122]  */
[123] 
[124] #define ngx_memory_barrier()    __asm__ volatile ("" ::: "memory")
[125] 
[126] /* old "as" does not support "pause" opcode */
[127] #define ngx_cpu_pause()         __asm__ (".byte 0xf3, 0x90")
