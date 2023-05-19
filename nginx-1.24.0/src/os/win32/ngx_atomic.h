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
[16] #define NGX_HAVE_ATOMIC_OPS   1
[17] 
[18] typedef int32_t                     ngx_atomic_int_t;
[19] typedef uint32_t                    ngx_atomic_uint_t;
[20] typedef volatile ngx_atomic_uint_t  ngx_atomic_t;
[21] #define NGX_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
[22] 
[23] 
[24] #if defined( __WATCOMC__ ) || defined( __BORLANDC__ ) || defined(__GNUC__)    \
[25]     || ( _MSC_VER >= 1300 )
[26] 
[27] /* the new SDK headers */
[28] 
[29] #define ngx_atomic_cmp_set(lock, old, set)                                    \
[30]     ((ngx_atomic_uint_t) InterlockedCompareExchange((long *) lock, set, old)  \
[31]                          == old)
[32] 
[33] #else
[34] 
[35] /* the old MS VC6.0SP2 SDK headers */
[36] 
[37] #define ngx_atomic_cmp_set(lock, old, set)                                    \
[38]     (InterlockedCompareExchange((void **) lock, (void *) set, (void *) old)   \
[39]      == (void *) old)
[40] 
[41] #endif
[42] 
[43] 
[44] #define ngx_atomic_fetch_add(p, add) InterlockedExchangeAdd((long *) p, add)
[45] 
[46] 
[47] #define ngx_memory_barrier()
[48] 
[49] 
[50] #if defined( __BORLANDC__ ) || ( __WATCOMC__ < 1230 )
[51] 
[52] /*
[53]  * Borland C++ 5.5 (tasm32) and Open Watcom C prior to 1.3
[54]  * do not understand the "pause" instruction
[55]  */
[56] 
[57] #define ngx_cpu_pause()
[58] #else
[59] #define ngx_cpu_pause()       __asm { pause }
[60] #endif
[61] 
[62] 
[63] void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin);
[64] 
[65] #define ngx_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, 1))
[66] #define ngx_unlock(lock)    *(lock) = 0
[67] 
[68] 
[69] #endif /* _NGX_ATOMIC_H_INCLUDED_ */
