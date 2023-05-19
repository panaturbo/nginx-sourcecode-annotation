[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_ATOMIC_H_INCLUDED_
[9] #define _NGX_ATOMIC_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #if (NGX_HAVE_LIBATOMIC)
[17] 
[18] #define AO_REQUIRE_CAS
[19] #include <atomic_ops.h>
[20] 
[21] #define NGX_HAVE_ATOMIC_OPS  1
[22] 
[23] typedef long                        ngx_atomic_int_t;
[24] typedef AO_t                        ngx_atomic_uint_t;
[25] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[26] 
[27] #if (NGX_PTR_SIZE == 8)
[28] #define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
[29] #else
[30] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[31] #endif
[32] 
[33] #define ngx_atomic_cmp_set(lock, old, new)                                    \
[34]     AO_compare_and_swap(lock, old, new)
[35] #define ngx_atomic_fetch_add(value, add)                                      \
[36]     AO_fetch_and_add(value, add)
[37] #define ngx_memory_barrier()        AO_nop()
[38] #define ngx_cpu_pause()
[39] 
[40] 
[41] #elif (NGX_HAVE_GCC_ATOMIC)
[42] 
[43] /* GCC 4.1 builtin atomic operations */
[44] 
[45] #define NGX_HAVE_ATOMIC_OPS  1
[46] 
[47] typedef long                        ngx_atomic_int_t;
[48] typedef unsigned long               ngx_atomic_uint_t;
[49] 
[50] #if (NGX_PTR_SIZE == 8)
[51] #define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
[52] #else
[53] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[54] #endif
[55] 
[56] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[57] 
[58] 
[59] #define ngx_atomic_cmp_set(lock, old, set)                                    \
[60]     __sync_bool_compare_and_swap(lock, old, set)
[61] 
[62] #define ngx_atomic_fetch_add(value, add)                                      \
[63]     __sync_fetch_and_add(value, add)
[64] 
[65] #define ngx_memory_barrier()        __sync_synchronize()
[66] 
[67] #if ( __i386__ || __i386 || __amd64__ || __amd64 )
[68] #define ngx_cpu_pause()             __asm__ ("pause")
[69] #else
[70] #define ngx_cpu_pause()
[71] #endif
[72] 
[73] 
[74] #elif (NGX_DARWIN_ATOMIC)
[75] 
[76] /*
[77]  * use Darwin 8 atomic(3) and barrier(3) operations
[78]  * optimized at run-time for UP and SMP
[79]  */
[80] 
[81] #include <libkern/OSAtomic.h>
[82] 
[83] /* "bool" conflicts with perl's CORE/handy.h */
[84] #if 0
[85] #undef bool
[86] #endif
[87] 
[88] 
[89] #define NGX_HAVE_ATOMIC_OPS  1
[90] 
[91] #if (NGX_PTR_SIZE == 8)
[92] 
[93] typedef int64_t                     ngx_atomic_int_t;
[94] typedef uint64_t                    ngx_atomic_uint_t;
[95] #define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
[96] 
[97] #define ngx_atomic_cmp_set(lock, old, new)                                    \
[98]     OSAtomicCompareAndSwap64Barrier(old, new, (int64_t *) lock)
[99] 
[100] #define ngx_atomic_fetch_add(value, add)                                      \
[101]     (OSAtomicAdd64(add, (int64_t *) value) - add)
[102] 
[103] #else
[104] 
[105] typedef int32_t                     ngx_atomic_int_t;
[106] typedef uint32_t                    ngx_atomic_uint_t;
[107] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[108] 
[109] #define ngx_atomic_cmp_set(lock, old, new)                                    \
[110]     OSAtomicCompareAndSwap32Barrier(old, new, (int32_t *) lock)
[111] 
[112] #define ngx_atomic_fetch_add(value, add)                                      \
[113]     (OSAtomicAdd32(add, (int32_t *) value) - add)
[114] 
[115] #endif
[116] 
[117] #define ngx_memory_barrier()        OSMemoryBarrier()
[118] 
[119] #define ngx_cpu_pause()
[120] 
[121] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[122] 
[123] 
[124] #elif ( __i386__ || __i386 )
[125] 
[126] typedef int32_t                     ngx_atomic_int_t;
[127] typedef uint32_t                    ngx_atomic_uint_t;
[128] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[129] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[130] 
[131] 
[132] #if ( __SUNPRO_C )
[133] 
[134] #define NGX_HAVE_ATOMIC_OPS  1
[135] 
[136] ngx_atomic_uint_t
[137] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[138]     ngx_atomic_uint_t set);
[139] 
[140] ngx_atomic_int_t
[141] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add);
[142] 
[143] /*
[144]  * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
[145]  * so ngx_cpu_pause is declared in src/os/unix/ngx_sunpro_x86.il
[146]  */
[147] 
[148] void
[149] ngx_cpu_pause(void);
[150] 
[151] /* the code in src/os/unix/ngx_sunpro_x86.il */
[152] 
[153] #define ngx_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")
[154] 
[155] 
[156] #else /* ( __GNUC__ || __INTEL_COMPILER ) */
[157] 
[158] #define NGX_HAVE_ATOMIC_OPS  1
[159] 
[160] #include "ngx_gcc_atomic_x86.h"
[161] 
[162] #endif
[163] 
[164] 
[165] #elif ( __amd64__ || __amd64 )
[166] 
[167] typedef int64_t                     ngx_atomic_int_t;
[168] typedef uint64_t                    ngx_atomic_uint_t;
[169] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[170] #define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
[171] 
[172] 
[173] #if ( __SUNPRO_C )
[174] 
[175] #define NGX_HAVE_ATOMIC_OPS  1
[176] 
[177] ngx_atomic_uint_t
[178] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[179]     ngx_atomic_uint_t set);
[180] 
[181] ngx_atomic_int_t
[182] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add);
[183] 
[184] /*
[185]  * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
[186]  * so ngx_cpu_pause is declared in src/os/unix/ngx_sunpro_amd64.il
[187]  */
[188] 
[189] void
[190] ngx_cpu_pause(void);
[191] 
[192] /* the code in src/os/unix/ngx_sunpro_amd64.il */
[193] 
[194] #define ngx_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")
[195] 
[196] 
[197] #else /* ( __GNUC__ || __INTEL_COMPILER ) */
[198] 
[199] #define NGX_HAVE_ATOMIC_OPS  1
[200] 
[201] #include "ngx_gcc_atomic_amd64.h"
[202] 
[203] #endif
[204] 
[205] 
[206] #elif ( __sparc__ || __sparc || __sparcv9 )
[207] 
[208] #if (NGX_PTR_SIZE == 8)
[209] 
[210] typedef int64_t                     ngx_atomic_int_t;
[211] typedef uint64_t                    ngx_atomic_uint_t;
[212] #define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
[213] 
[214] #else
[215] 
[216] typedef int32_t                     ngx_atomic_int_t;
[217] typedef uint32_t                    ngx_atomic_uint_t;
[218] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[219] 
[220] #endif
[221] 
[222] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[223] 
[224] 
[225] #if ( __SUNPRO_C )
[226] 
[227] #define NGX_HAVE_ATOMIC_OPS  1
[228] 
[229] #include "ngx_sunpro_atomic_sparc64.h"
[230] 
[231] 
[232] #else /* ( __GNUC__ || __INTEL_COMPILER ) */
[233] 
[234] #define NGX_HAVE_ATOMIC_OPS  1
[235] 
[236] #include "ngx_gcc_atomic_sparc64.h"
[237] 
[238] #endif
[239] 
[240] 
[241] #elif ( __powerpc__ || __POWERPC__ )
[242] 
[243] #define NGX_HAVE_ATOMIC_OPS  1
[244] 
[245] #if (NGX_PTR_SIZE == 8)
[246] 
[247] typedef int64_t                     ngx_atomic_int_t;
[248] typedef uint64_t                    ngx_atomic_uint_t;
[249] #define NGX_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
[250] 
[251] #else
[252] 
[253] typedef int32_t                     ngx_atomic_int_t;
[254] typedef uint32_t                    ngx_atomic_uint_t;
[255] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[256] 
[257] #endif
[258] 
[259] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[260] 
[261] 
[262] #include "ngx_gcc_atomic_ppc.h"
[263] 
[264] #endif
[265] 
[266] 
[267] #if !(NGX_HAVE_ATOMIC_OPS)
[268] 
[269] #define NGX_HAVE_ATOMIC_OPS  0
[270] 
[271] typedef int32_t                     ngx_atomic_int_t;
[272] typedef uint32_t                    ngx_atomic_uint_t;
[273] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[274] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[275] 
[276] 
[277] static ngx_inline ngx_atomic_uint_t
[278] ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
[279]     ngx_atomic_uint_t set)
[280] {
[281]     if (*lock == old) {
[282]         *lock = set;
[283]         return 1;
[284]     }
[285] 
[286]     return 0;
[287] }
[288] 
[289] 
[290] static ngx_inline ngx_atomic_int_t
[291] ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
[292] {
[293]     ngx_atomic_int_t  old;
[294] 
[295]     old = *value;
[296]     *value += add;
[297] 
[298]     return old;
[299] }
[300] 
[301] #define ngx_memory_barrier()
[302] #define ngx_cpu_pause()
[303] 
[304] #endif
[305] 
[306] 
[307] void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin);
[308] 
[309] #define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
[310] #define ngx_unlock(lock)    *(lock) = 0
[311] 
[312] 
[313] #endif /* _NGX_ATOMIC_H_INCLUDED_ */
