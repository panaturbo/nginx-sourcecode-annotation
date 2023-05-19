[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_WIN32_CONFIG_H_INCLUDED_
[9] #define _NGX_WIN32_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #undef  WIN32
[13] #define WIN32         0x0400
[14] #define _WIN32_WINNT  0x0501
[15] 
[16] 
[17] #define STRICT
[18] #define WIN32_LEAN_AND_MEAN
[19] 
[20] /* enable getenv() and gmtime() in msvc8 */
[21] #define _CRT_SECURE_NO_WARNINGS
[22] #define _CRT_SECURE_NO_DEPRECATE
[23] 
[24] /* enable gethostbyname() in msvc2015 */
[25] #if !(NGX_HAVE_INET6)
[26] #define _WINSOCK_DEPRECATED_NO_WARNINGS
[27] #endif
[28] 
[29] /*
[30]  * we need to include <windows.h> explicitly before <winsock2.h> because
[31]  * the warning 4201 is enabled in <windows.h>
[32]  */
[33] #include <windows.h>
[34] 
[35] #ifdef _MSC_VER
[36] #pragma warning(disable:4201)
[37] #endif
[38] 
[39] #include <winsock2.h>
[40] #include <ws2tcpip.h>  /* ipv6 */
[41] #include <mswsock.h>
[42] #include <shellapi.h>
[43] #include <stddef.h>    /* offsetof() */
[44] 
[45] #ifdef __MINGW64_VERSION_MAJOR
[46] 
[47] /* GCC MinGW-w64 supports _FILE_OFFSET_BITS */
[48] #define _FILE_OFFSET_BITS 64
[49] 
[50] #elif defined __GNUC__
[51] 
[52] /* GCC MinGW's stdio.h includes sys/types.h */
[53] #define _OFF_T_
[54] #define __have_typedef_off_t
[55] 
[56] #endif
[57] 
[58] #include <stdio.h>
[59] #include <stdlib.h>
[60] #include <stdarg.h>
[61] #ifdef __GNUC__
[62] #include <stdint.h>
[63] #endif
[64] #include <ctype.h>
[65] #include <locale.h>
[66] 
[67] #ifdef __WATCOMC__
[68] #define _TIME_T_DEFINED
[69] typedef long  time_t;
[70] /* OpenWatcom defines time_t as "unsigned long" */
[71] #endif
[72] 
[73] #include <time.h>      /* localtime(), strftime() */
[74] 
[75] 
[76] #ifdef _MSC_VER
[77] 
[78] /* the end of the precompiled headers */
[79] #pragma hdrstop
[80] 
[81] #pragma warning(default:4201)
[82] 
[83] /* 'type cast': from function pointer to data pointer */
[84] #pragma warning(disable:4054)
[85] 
[86] /* 'type cast': from data pointer to function pointer */
[87] #pragma warning(disable:4055)
[88] 
[89] /* 'function' : different 'const' qualifiers */
[90] #pragma warning(disable:4090)
[91] 
[92] /* unreferenced formal parameter */
[93] #pragma warning(disable:4100)
[94] 
[95] /* FD_SET() and FD_CLR(): conditional expression is constant */
[96] #pragma warning(disable:4127)
[97] 
[98] /* conversion from 'type1' to 'type2', possible loss of data */
[99] #pragma warning(disable:4244)
[100] 
[101] /* conversion from 'size_t' to 'type', possible loss of data */
[102] #pragma warning(disable:4267)
[103] 
[104] /* array is too small to include a terminating null character */
[105] #pragma warning(disable:4295)
[106] 
[107] /* conversion from 'type1' to 'type2' of greater size */
[108] #pragma warning(disable:4306)
[109] 
[110] #endif
[111] 
[112] 
[113] #ifdef __WATCOMC__
[114] 
[115] /* symbol 'ngx_rbtree_min' has been defined, but not referenced */
[116] #pragma disable_message(202)
[117] 
[118] #endif
[119] 
[120] 
[121] #ifdef __BORLANDC__
[122] 
[123] /* the end of the precompiled headers */
[124] #pragma hdrstop
[125] 
[126] /* functions containing (for|while|some if) are not expanded inline */
[127] #pragma warn -8027
[128] 
[129] /* unreferenced formal parameter */
[130] #pragma warn -8057
[131] 
[132] /* suspicious pointer arithmetic */
[133] #pragma warn -8072
[134] 
[135] #endif
[136] 
[137] 
[138] #include <ngx_auto_config.h>
[139] 
[140] 
[141] #define ngx_inline          __inline
[142] #define ngx_cdecl           __cdecl
[143] 
[144] 
[145] #ifdef _MSC_VER
[146] typedef unsigned __int32    uint32_t;
[147] typedef __int32             int32_t;
[148] typedef unsigned __int16    uint16_t;
[149] #define ngx_libc_cdecl      __cdecl
[150] 
[151] #elif defined __BORLANDC__
[152] typedef unsigned __int32    uint32_t;
[153] typedef __int32             int32_t;
[154] typedef unsigned __int16    uint16_t;
[155] #define ngx_libc_cdecl      __cdecl
[156] 
[157] #else /* __WATCOMC__ */
[158] typedef unsigned int        uint32_t;
[159] typedef int                 int32_t;
[160] typedef unsigned short int  uint16_t;
[161] #define ngx_libc_cdecl
[162] 
[163] #endif
[164] 
[165] typedef __int64             int64_t;
[166] typedef unsigned __int64    uint64_t;
[167] 
[168] #if __BORLANDC__
[169] typedef int                 intptr_t;
[170] typedef u_int               uintptr_t;
[171] #endif
[172] 
[173] 
[174] #ifndef __MINGW64_VERSION_MAJOR
[175] 
[176] /* Windows defines off_t as long, which is 32-bit */
[177] typedef __int64             off_t;
[178] #define _OFF_T_DEFINED
[179] 
[180] #endif
[181] 
[182] 
[183] #ifdef __WATCOMC__
[184] 
[185] /* off_t is redefined by sys/types.h used by zlib.h */
[186] #define __TYPES_H_INCLUDED
[187] typedef int                 dev_t;
[188] typedef unsigned int        ino_t;
[189] 
[190] #elif __BORLANDC__
[191] 
[192] /* off_t is redefined by sys/types.h used by zlib.h */
[193] #define __TYPES_H
[194] 
[195] typedef int                 dev_t;
[196] typedef unsigned int        ino_t;
[197] 
[198] #endif
[199] 
[200] 
[201] #ifndef __GNUC__
[202] #ifdef _WIN64
[203] typedef __int64             ssize_t;
[204] #else
[205] typedef int                 ssize_t;
[206] #endif
[207] #endif
[208] 
[209] 
[210] typedef uint32_t            in_addr_t;
[211] typedef u_short             in_port_t;
[212] typedef int                 sig_atomic_t;
[213] 
[214] 
[215] #ifdef _WIN64
[216] 
[217] #define NGX_PTR_SIZE            8
[218] #define NGX_SIZE_T_LEN          (sizeof("-9223372036854775808") - 1)
[219] #define NGX_MAX_SIZE_T_VALUE    9223372036854775807
[220] #define NGX_TIME_T_LEN          (sizeof("-9223372036854775808") - 1)
[221] #define NGX_TIME_T_SIZE         8
[222] #define NGX_MAX_TIME_T_VALUE    9223372036854775807
[223] 
[224] #else
[225] 
[226] #define NGX_PTR_SIZE            4
[227] #define NGX_SIZE_T_LEN          (sizeof("-2147483648") - 1)
[228] #define NGX_MAX_SIZE_T_VALUE    2147483647
[229] #define NGX_TIME_T_LEN          (sizeof("-2147483648") - 1)
[230] #define NGX_TIME_T_SIZE         4
[231] #define NGX_MAX_TIME_T_VALUE    2147483647
[232] 
[233] #endif
[234] 
[235] 
[236] #define NGX_OFF_T_LEN           (sizeof("-9223372036854775807") - 1)
[237] #define NGX_MAX_OFF_T_VALUE     9223372036854775807
[238] #define NGX_SIG_ATOMIC_T_SIZE   4
[239] 
[240] 
[241] #define NGX_HAVE_LITTLE_ENDIAN  1
[242] #define NGX_HAVE_NONALIGNED     1
[243] 
[244] 
[245] #define NGX_WIN_NT        200000
[246] 
[247] 
[248] #define NGX_LISTEN_BACKLOG           511
[249] 
[250] 
[251] #ifndef NGX_HAVE_INHERITED_NONBLOCK
[252] #define NGX_HAVE_INHERITED_NONBLOCK  1
[253] #endif
[254] 
[255] #ifndef NGX_HAVE_CASELESS_FILESYSTEM
[256] #define NGX_HAVE_CASELESS_FILESYSTEM  1
[257] #endif
[258] 
[259] #ifndef NGX_HAVE_WIN32_TRANSMITPACKETS
[260] #define NGX_HAVE_WIN32_TRANSMITPACKETS  1
[261] #define NGX_HAVE_WIN32_TRANSMITFILE     0
[262] #endif
[263] 
[264] #ifndef NGX_HAVE_WIN32_TRANSMITFILE
[265] #define NGX_HAVE_WIN32_TRANSMITFILE  1
[266] #endif
[267] 
[268] #if (NGX_HAVE_WIN32_TRANSMITPACKETS) || (NGX_HAVE_WIN32_TRANSMITFILE)
[269] #define NGX_HAVE_SENDFILE  1
[270] #endif
[271] 
[272] #ifndef NGX_HAVE_SO_SNDLOWAT
[273] /* setsockopt(SO_SNDLOWAT) returns error WSAENOPROTOOPT */
[274] #define NGX_HAVE_SO_SNDLOWAT         0
[275] #endif
[276] 
[277] #ifndef NGX_HAVE_FIONREAD
[278] #define NGX_HAVE_FIONREAD            1
[279] #endif
[280] 
[281] #define NGX_HAVE_GETADDRINFO         1
[282] 
[283] #define ngx_random               rand
[284] #define ngx_debug_init()
[285] 
[286] 
[287] #endif /* _NGX_WIN32_CONFIG_H_INCLUDED_ */
