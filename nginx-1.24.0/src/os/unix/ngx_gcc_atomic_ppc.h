[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] /*
[9]  * The ppc assembler treats ";" as comment, so we have to use "\n".
[10]  * The minus in "bne-" is a hint for the branch prediction unit that
[11]  * this branch is unlikely to be taken.
[12]  * The "1b" means the nearest backward label "1" and the "1f" means
[13]  * the nearest forward label "1".
[14]  *
[15]  * The "b" means that the base registers can be used only, i.e.
[16]  * any register except r0.  The r0 register always has a zero value and
[17]  * could not be used in "addi  r0, r0, 1".
[18]  * The "=&b" means that no input registers can be used.
[19]  *
[20]  * "sync"    read and write barriers
[21]  * "isync"   read barrier, is faster than "sync"
[22]  * "eieio"   write barrier, is faster than "sync"
[23]  * "lwsync"  write barrier, is faster than "eieio" on ppc64
[24]  */
[25] 
[26] #if (NGX_PTR_SIZE == 8)
[27] 
[28] static ngx_inline ngx_atomic_uint_t
[29] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[30]     ngx_atomic_uint_t set)
[31] {
[32]     ngx_atomic_uint_t  res, temp;
[33] 
[34]     __asm__ volatile (
[35] 
[36]     "    li      %0, 0       \n" /* preset "0" to "res"                      */
[37]     "    lwsync              \n" /* write barrier                            */
[38]     "1:                      \n"
[39]     "    ldarx   %1, 0, %2   \n" /* load from [lock] into "temp"             */
[40]                                  /*   and store reservation                  */
[41]     "    cmpd    %1, %3      \n" /* compare "temp" and "old"                 */
[42]     "    bne-    2f          \n" /* not equal                                */
[43]     "    stdcx.  %4, 0, %2   \n" /* store "set" into [lock] if reservation   */
[44]                                  /*   is not cleared                         */
[45]     "    bne-    1b          \n" /* the reservation was cleared              */
[46]     "    isync               \n" /* read barrier                             */
[47]     "    li      %0, 1       \n" /* set "1" to "res"                         */
[48]     "2:                      \n"
[49] 
[50]     : "=&b" (res), "=&b" (temp)
[51]     : "b" (lock), "b" (old), "b" (set)
[52]     : "cc", "memory");
[53] 
[54]     return res;
[55] }
[56] 
[57] 
[58] static ngx_inline ngx_atomic_int_t
[59] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[60] {
[61]     ngx_atomic_uint_t  res, temp;
[62] 
[63]     __asm__ volatile (
[64] 
[65]     "    lwsync              \n" /* write barrier                            */
[66]     "1:  ldarx   %0, 0, %2   \n" /* load from [value] into "res"             */
[67]                                  /*   and store reservation                  */
[68]     "    add     %1, %0, %3  \n" /* "res" + "add" store in "temp"            */
[69]     "    stdcx.  %1, 0, %2   \n" /* store "temp" into [value] if reservation */
[70]                                  /*   is not cleared                         */
[71]     "    bne-    1b          \n" /* try again if reservation was cleared     */
[72]     "    isync               \n" /* read barrier                             */
[73] 
[74]     : "=&b" (res), "=&b" (temp)
[75]     : "b" (value), "b" (add)
[76]     : "cc", "memory");
[77] 
[78]     return res;
[79] }
[80] 
[81] 
[82] #if (NGX_SMP)
[83] #define ngx_memory_barrier()                                                  \
[84]     __asm__ volatile ("isync  \n  lwsync  \n" ::: "memory")
[85] #else
[86] #define ngx_memory_barrier()   __asm__ volatile ("" ::: "memory")
[87] #endif
[88] 
[89] #else
[90] 
[91] static ngx_inline ngx_atomic_uint_t
[92] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[93]     ngx_atomic_uint_t set)
[94] {
[95]     ngx_atomic_uint_t  res, temp;
[96] 
[97]     __asm__ volatile (
[98] 
[99]     "    li      %0, 0       \n" /* preset "0" to "res"                      */
[100]     "    eieio               \n" /* write barrier                            */
[101]     "1:                      \n"
[102]     "    lwarx   %1, 0, %2   \n" /* load from [lock] into "temp"             */
[103]                                  /*   and store reservation                  */
[104]     "    cmpw    %1, %3      \n" /* compare "temp" and "old"                 */
[105]     "    bne-    2f          \n" /* not equal                                */
[106]     "    stwcx.  %4, 0, %2   \n" /* store "set" into [lock] if reservation   */
[107]                                  /*   is not cleared                         */
[108]     "    bne-    1b          \n" /* the reservation was cleared              */
[109]     "    isync               \n" /* read barrier                             */
[110]     "    li      %0, 1       \n" /* set "1" to "res"                         */
[111]     "2:                      \n"
[112] 
[113]     : "=&b" (res), "=&b" (temp)
[114]     : "b" (lock), "b" (old), "b" (set)
[115]     : "cc", "memory");
[116] 
[117]     return res;
[118] }
[119] 
[120] 
[121] static ngx_inline ngx_atomic_int_t
[122] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[123] {
[124]     ngx_atomic_uint_t  res, temp;
[125] 
[126]     __asm__ volatile (
[127] 
[128]     "    eieio               \n" /* write barrier                            */
[129]     "1:  lwarx   %0, 0, %2   \n" /* load from [value] into "res"             */
[130]                                  /*   and store reservation                  */
[131]     "    add     %1, %0, %3  \n" /* "res" + "add" store in "temp"            */
[132]     "    stwcx.  %1, 0, %2   \n" /* store "temp" into [value] if reservation */
[133]                                  /*   is not cleared                         */
[134]     "    bne-    1b          \n" /* try again if reservation was cleared     */
[135]     "    isync               \n" /* read barrier                             */
[136] 
[137]     : "=&b" (res), "=&b" (temp)
[138]     : "b" (value), "b" (add)
[139]     : "cc", "memory");
[140] 
[141]     return res;
[142] }
[143] 
[144] 
[145] #if (NGX_SMP)
[146] #define ngx_memory_barrier()                                                  \
[147]     __asm__ volatile ("isync  \n  eieio  \n" ::: "memory")
[148] #else
[149] #define ngx_memory_barrier()   __asm__ volatile ("" ::: "memory")
[150] #endif
[151] 
[152] #endif
[153] 
[154] 
[155] #define ngx_cpu_pause()
