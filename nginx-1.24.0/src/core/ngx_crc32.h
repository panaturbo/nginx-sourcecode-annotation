[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CRC32_H_INCLUDED_
[9] #define _NGX_CRC32_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] extern uint32_t  *ngx_crc32_table_short;
[17] extern uint32_t   ngx_crc32_table256[];
[18] 
[19] 
[20] static ngx_inline uint32_t
[21] ngx_crc32_short(u_char *p, size_t len)
[22] {
[23]     u_char    c;
[24]     uint32_t  crc;
[25] 
[26]     crc = 0xffffffff;
[27] 
[28]     while (len--) {
[29]         c = *p++;
[30]         crc = ngx_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
[31]         crc = ngx_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
[32]     }
[33] 
[34]     return crc ^ 0xffffffff;
[35] }
[36] 
[37] 
[38] static ngx_inline uint32_t
[39] ngx_crc32_long(u_char *p, size_t len)
[40] {
[41]     uint32_t  crc;
[42] 
[43]     crc = 0xffffffff;
[44] 
[45]     while (len--) {
[46]         crc = ngx_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
[47]     }
[48] 
[49]     return crc ^ 0xffffffff;
[50] }
[51] 
[52] 
[53] #define ngx_crc32_init(crc)                                                   \
[54]     crc = 0xffffffff
[55] 
[56] 
[57] static ngx_inline void
[58] ngx_crc32_update(uint32_t *crc, u_char *p, size_t len)
[59] {
[60]     uint32_t  c;
[61] 
[62]     c = *crc;
[63] 
[64]     while (len--) {
[65]         c = ngx_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
[66]     }
[67] 
[68]     *crc = c;
[69] }
[70] 
[71] 
[72] #define ngx_crc32_final(crc)                                                  \
[73]     crc ^= 0xffffffff
[74] 
[75] 
[76] ngx_int_t ngx_crc32_table_init(void);
[77] 
[78] 
[79] #endif /* _NGX_CRC32_H_INCLUDED_ */
