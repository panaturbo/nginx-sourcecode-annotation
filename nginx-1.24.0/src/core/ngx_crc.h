[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CRC_H_INCLUDED_
[9] #define _NGX_CRC_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] /* 32-bit crc16 */
[17] 
[18] static ngx_inline uint32_t
[19] ngx_crc(u_char *data, size_t len)
[20] {
[21]     uint32_t  sum;
[22] 
[23]     for (sum = 0; len; len--) {
[24] 
[25]         /*
[26]          * gcc 2.95.2 x86 and icc 7.1.006 compile
[27]          * that operator into the single "rol" opcode,
[28]          * msvc 6.0sp2 compiles it into four opcodes.
[29]          */
[30]         sum = sum >> 1 | sum << 31;
[31] 
[32]         sum += *data++;
[33]     }
[34] 
[35]     return sum;
[36] }
[37] 
[38] 
[39] #endif /* _NGX_CRC_H_INCLUDED_ */
