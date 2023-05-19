[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CONFIG_H_INCLUDED_
[9] #define _NGX_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_auto_headers.h>
[13] 
[14] 
[15] #if defined __DragonFly__ && !defined __FreeBSD__
[16] #define __FreeBSD__        4
[17] #define __FreeBSD_version  480101
[18] #endif
[19] 
[20] 
[21] #if (NGX_FREEBSD)
[22] #include <ngx_freebsd_config.h>
[23] 
[24] 
[25] #elif (NGX_LINUX)
[26] #include <ngx_linux_config.h>
[27] 
[28] 
[29] #elif (NGX_SOLARIS)
[30] #include <ngx_solaris_config.h>
[31] 
[32] 
[33] #elif (NGX_DARWIN)
[34] #include <ngx_darwin_config.h>
[35] 
[36] 
[37] #elif (NGX_WIN32)
[38] #include <ngx_win32_config.h>
[39] 
[40] 
[41] #else /* POSIX */
[42] #include <ngx_posix_config.h>
[43] 
[44] #endif
[45] 
[46] 
[47] #ifndef NGX_HAVE_SO_SNDLOWAT
[48] #define NGX_HAVE_SO_SNDLOWAT     1
[49] #endif
[50] 
[51] 
[52] #if !(NGX_WIN32)
[53] 
[54] #define ngx_signal_helper(n)     SIG##n
[55] #define ngx_signal_value(n)      ngx_signal_helper(n)
[56] 
[57] #define ngx_random               random
[58] 
[59] /* TODO: #ifndef */
[60] #define NGX_SHUTDOWN_SIGNAL      QUIT
[61] #define NGX_TERMINATE_SIGNAL     TERM
[62] #define NGX_NOACCEPT_SIGNAL      WINCH
[63] #define NGX_RECONFIGURE_SIGNAL   HUP
[64] 
[65] #if (NGX_LINUXTHREADS)
[66] #define NGX_REOPEN_SIGNAL        INFO
[67] #define NGX_CHANGEBIN_SIGNAL     XCPU
[68] #else
[69] #define NGX_REOPEN_SIGNAL        USR1
[70] #define NGX_CHANGEBIN_SIGNAL     USR2
[71] #endif
[72] 
[73] #define ngx_cdecl
[74] #define ngx_libc_cdecl
[75] 
[76] #endif
[77] 
[78] typedef intptr_t        ngx_int_t;
[79] typedef uintptr_t       ngx_uint_t;
[80] typedef intptr_t        ngx_flag_t;
[81] 
[82] 
[83] #define NGX_INT32_LEN   (sizeof("-2147483648") - 1)
[84] #define NGX_INT64_LEN   (sizeof("-9223372036854775808") - 1)
[85] 
[86] #if (NGX_PTR_SIZE == 4)
[87] #define NGX_INT_T_LEN   NGX_INT32_LEN
[88] #define NGX_MAX_INT_T_VALUE  2147483647
[89] 
[90] #else
[91] #define NGX_INT_T_LEN   NGX_INT64_LEN
[92] #define NGX_MAX_INT_T_VALUE  9223372036854775807
[93] #endif
[94] 
[95] 
[96] #ifndef NGX_ALIGNMENT
[97] #define NGX_ALIGNMENT   sizeof(unsigned long)    /* platform word */
[98] #endif
[99] 
[100] #define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
[101] #define ngx_align_ptr(p, a)                                                   \
[102]     (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))
[103] 
[104] 
[105] #define ngx_abort       abort
[106] 
[107] 
[108] /* TODO: platform specific: array[NGX_INVALID_ARRAY_INDEX] must cause SIGSEGV */
[109] #define NGX_INVALID_ARRAY_INDEX 0x80000000
[110] 
[111] 
[112] /* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
[113] #ifndef ngx_inline
[114] #define ngx_inline      inline
[115] #endif
[116] 
[117] #ifndef INADDR_NONE  /* Solaris */
[118] #define INADDR_NONE  ((unsigned int) -1)
[119] #endif
[120] 
[121] #ifdef MAXHOSTNAMELEN
[122] #define NGX_MAXHOSTNAMELEN  MAXHOSTNAMELEN
[123] #else
[124] #define NGX_MAXHOSTNAMELEN  256
[125] #endif
[126] 
[127] 
[128] #define NGX_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
[129] #define NGX_MAX_INT32_VALUE   (uint32_t) 0x7fffffff
[130] 
[131] 
[132] #if (NGX_COMPAT)
[133] 
[134] #define NGX_COMPAT_BEGIN(slots)  uint64_t spare[slots];
[135] #define NGX_COMPAT_END
[136] 
[137] #else
[138] 
[139] #define NGX_COMPAT_BEGIN(slots)
[140] #define NGX_COMPAT_END
[141] 
[142] #endif
[143] 
[144] 
[145] #endif /* _NGX_CONFIG_H_INCLUDED_ */
