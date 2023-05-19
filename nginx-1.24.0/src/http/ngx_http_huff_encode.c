[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  * Copyright (C) 2015 Vlad Krasnov
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_http.h>
[12] 
[13] 
[14] typedef struct {
[15]     uint32_t  code;
[16]     uint32_t  len;
[17] } ngx_http_huff_encode_code_t;
[18] 
[19] 
[20] static ngx_http_huff_encode_code_t  ngx_http_huff_encode_table[256] =
[21] {
[22]     {0x00001ff8, 13}, {0x007fffd8, 23}, {0x0fffffe2, 28}, {0x0fffffe3, 28},
[23]     {0x0fffffe4, 28}, {0x0fffffe5, 28}, {0x0fffffe6, 28}, {0x0fffffe7, 28},
[24]     {0x0fffffe8, 28}, {0x00ffffea, 24}, {0x3ffffffc, 30}, {0x0fffffe9, 28},
[25]     {0x0fffffea, 28}, {0x3ffffffd, 30}, {0x0fffffeb, 28}, {0x0fffffec, 28},
[26]     {0x0fffffed, 28}, {0x0fffffee, 28}, {0x0fffffef, 28}, {0x0ffffff0, 28},
[27]     {0x0ffffff1, 28}, {0x0ffffff2, 28}, {0x3ffffffe, 30}, {0x0ffffff3, 28},
[28]     {0x0ffffff4, 28}, {0x0ffffff5, 28}, {0x0ffffff6, 28}, {0x0ffffff7, 28},
[29]     {0x0ffffff8, 28}, {0x0ffffff9, 28}, {0x0ffffffa, 28}, {0x0ffffffb, 28},
[30]     {0x00000014,  6}, {0x000003f8, 10}, {0x000003f9, 10}, {0x00000ffa, 12},
[31]     {0x00001ff9, 13}, {0x00000015,  6}, {0x000000f8,  8}, {0x000007fa, 11},
[32]     {0x000003fa, 10}, {0x000003fb, 10}, {0x000000f9,  8}, {0x000007fb, 11},
[33]     {0x000000fa,  8}, {0x00000016,  6}, {0x00000017,  6}, {0x00000018,  6},
[34]     {0x00000000,  5}, {0x00000001,  5}, {0x00000002,  5}, {0x00000019,  6},
[35]     {0x0000001a,  6}, {0x0000001b,  6}, {0x0000001c,  6}, {0x0000001d,  6},
[36]     {0x0000001e,  6}, {0x0000001f,  6}, {0x0000005c,  7}, {0x000000fb,  8},
[37]     {0x00007ffc, 15}, {0x00000020,  6}, {0x00000ffb, 12}, {0x000003fc, 10},
[38]     {0x00001ffa, 13}, {0x00000021,  6}, {0x0000005d,  7}, {0x0000005e,  7},
[39]     {0x0000005f,  7}, {0x00000060,  7}, {0x00000061,  7}, {0x00000062,  7},
[40]     {0x00000063,  7}, {0x00000064,  7}, {0x00000065,  7}, {0x00000066,  7},
[41]     {0x00000067,  7}, {0x00000068,  7}, {0x00000069,  7}, {0x0000006a,  7},
[42]     {0x0000006b,  7}, {0x0000006c,  7}, {0x0000006d,  7}, {0x0000006e,  7},
[43]     {0x0000006f,  7}, {0x00000070,  7}, {0x00000071,  7}, {0x00000072,  7},
[44]     {0x000000fc,  8}, {0x00000073,  7}, {0x000000fd,  8}, {0x00001ffb, 13},
[45]     {0x0007fff0, 19}, {0x00001ffc, 13}, {0x00003ffc, 14}, {0x00000022,  6},
[46]     {0x00007ffd, 15}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
[47]     {0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
[48]     {0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
[49]     {0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
[50]     {0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
[51]     {0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
[52]     {0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00007ffe, 15},
[53]     {0x000007fc, 11}, {0x00003ffd, 14}, {0x00001ffd, 13}, {0x0ffffffc, 28},
[54]     {0x000fffe6, 20}, {0x003fffd2, 22}, {0x000fffe7, 20}, {0x000fffe8, 20},
[55]     {0x003fffd3, 22}, {0x003fffd4, 22}, {0x003fffd5, 22}, {0x007fffd9, 23},
[56]     {0x003fffd6, 22}, {0x007fffda, 23}, {0x007fffdb, 23}, {0x007fffdc, 23},
[57]     {0x007fffdd, 23}, {0x007fffde, 23}, {0x00ffffeb, 24}, {0x007fffdf, 23},
[58]     {0x00ffffec, 24}, {0x00ffffed, 24}, {0x003fffd7, 22}, {0x007fffe0, 23},
[59]     {0x00ffffee, 24}, {0x007fffe1, 23}, {0x007fffe2, 23}, {0x007fffe3, 23},
[60]     {0x007fffe4, 23}, {0x001fffdc, 21}, {0x003fffd8, 22}, {0x007fffe5, 23},
[61]     {0x003fffd9, 22}, {0x007fffe6, 23}, {0x007fffe7, 23}, {0x00ffffef, 24},
[62]     {0x003fffda, 22}, {0x001fffdd, 21}, {0x000fffe9, 20}, {0x003fffdb, 22},
[63]     {0x003fffdc, 22}, {0x007fffe8, 23}, {0x007fffe9, 23}, {0x001fffde, 21},
[64]     {0x007fffea, 23}, {0x003fffdd, 22}, {0x003fffde, 22}, {0x00fffff0, 24},
[65]     {0x001fffdf, 21}, {0x003fffdf, 22}, {0x007fffeb, 23}, {0x007fffec, 23},
[66]     {0x001fffe0, 21}, {0x001fffe1, 21}, {0x003fffe0, 22}, {0x001fffe2, 21},
[67]     {0x007fffed, 23}, {0x003fffe1, 22}, {0x007fffee, 23}, {0x007fffef, 23},
[68]     {0x000fffea, 20}, {0x003fffe2, 22}, {0x003fffe3, 22}, {0x003fffe4, 22},
[69]     {0x007ffff0, 23}, {0x003fffe5, 22}, {0x003fffe6, 22}, {0x007ffff1, 23},
[70]     {0x03ffffe0, 26}, {0x03ffffe1, 26}, {0x000fffeb, 20}, {0x0007fff1, 19},
[71]     {0x003fffe7, 22}, {0x007ffff2, 23}, {0x003fffe8, 22}, {0x01ffffec, 25},
[72]     {0x03ffffe2, 26}, {0x03ffffe3, 26}, {0x03ffffe4, 26}, {0x07ffffde, 27},
[73]     {0x07ffffdf, 27}, {0x03ffffe5, 26}, {0x00fffff1, 24}, {0x01ffffed, 25},
[74]     {0x0007fff2, 19}, {0x001fffe3, 21}, {0x03ffffe6, 26}, {0x07ffffe0, 27},
[75]     {0x07ffffe1, 27}, {0x03ffffe7, 26}, {0x07ffffe2, 27}, {0x00fffff2, 24},
[76]     {0x001fffe4, 21}, {0x001fffe5, 21}, {0x03ffffe8, 26}, {0x03ffffe9, 26},
[77]     {0x0ffffffd, 28}, {0x07ffffe3, 27}, {0x07ffffe4, 27}, {0x07ffffe5, 27},
[78]     {0x000fffec, 20}, {0x00fffff3, 24}, {0x000fffed, 20}, {0x001fffe6, 21},
[79]     {0x003fffe9, 22}, {0x001fffe7, 21}, {0x001fffe8, 21}, {0x007ffff3, 23},
[80]     {0x003fffea, 22}, {0x003fffeb, 22}, {0x01ffffee, 25}, {0x01ffffef, 25},
[81]     {0x00fffff4, 24}, {0x00fffff5, 24}, {0x03ffffea, 26}, {0x007ffff4, 23},
[82]     {0x03ffffeb, 26}, {0x07ffffe6, 27}, {0x03ffffec, 26}, {0x03ffffed, 26},
[83]     {0x07ffffe7, 27}, {0x07ffffe8, 27}, {0x07ffffe9, 27}, {0x07ffffea, 27},
[84]     {0x07ffffeb, 27}, {0x0ffffffe, 28}, {0x07ffffec, 27}, {0x07ffffed, 27},
[85]     {0x07ffffee, 27}, {0x07ffffef, 27}, {0x07fffff0, 27}, {0x03ffffee, 26}
[86] };
[87] 
[88] 
[89] /* same as above, but embeds lowercase transformation */
[90] static ngx_http_huff_encode_code_t  ngx_http_huff_encode_table_lc[256] =
[91] {
[92]     {0x00001ff8, 13}, {0x007fffd8, 23}, {0x0fffffe2, 28}, {0x0fffffe3, 28},
[93]     {0x0fffffe4, 28}, {0x0fffffe5, 28}, {0x0fffffe6, 28}, {0x0fffffe7, 28},
[94]     {0x0fffffe8, 28}, {0x00ffffea, 24}, {0x3ffffffc, 30}, {0x0fffffe9, 28},
[95]     {0x0fffffea, 28}, {0x3ffffffd, 30}, {0x0fffffeb, 28}, {0x0fffffec, 28},
[96]     {0x0fffffed, 28}, {0x0fffffee, 28}, {0x0fffffef, 28}, {0x0ffffff0, 28},
[97]     {0x0ffffff1, 28}, {0x0ffffff2, 28}, {0x3ffffffe, 30}, {0x0ffffff3, 28},
[98]     {0x0ffffff4, 28}, {0x0ffffff5, 28}, {0x0ffffff6, 28}, {0x0ffffff7, 28},
[99]     {0x0ffffff8, 28}, {0x0ffffff9, 28}, {0x0ffffffa, 28}, {0x0ffffffb, 28},
[100]     {0x00000014,  6}, {0x000003f8, 10}, {0x000003f9, 10}, {0x00000ffa, 12},
[101]     {0x00001ff9, 13}, {0x00000015,  6}, {0x000000f8,  8}, {0x000007fa, 11},
[102]     {0x000003fa, 10}, {0x000003fb, 10}, {0x000000f9,  8}, {0x000007fb, 11},
[103]     {0x000000fa,  8}, {0x00000016,  6}, {0x00000017,  6}, {0x00000018,  6},
[104]     {0x00000000,  5}, {0x00000001,  5}, {0x00000002,  5}, {0x00000019,  6},
[105]     {0x0000001a,  6}, {0x0000001b,  6}, {0x0000001c,  6}, {0x0000001d,  6},
[106]     {0x0000001e,  6}, {0x0000001f,  6}, {0x0000005c,  7}, {0x000000fb,  8},
[107]     {0x00007ffc, 15}, {0x00000020,  6}, {0x00000ffb, 12}, {0x000003fc, 10},
[108]     {0x00001ffa, 13}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
[109]     {0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
[110]     {0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
[111]     {0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
[112]     {0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
[113]     {0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
[114]     {0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00001ffb, 13},
[115]     {0x0007fff0, 19}, {0x00001ffc, 13}, {0x00003ffc, 14}, {0x00000022,  6},
[116]     {0x00007ffd, 15}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
[117]     {0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
[118]     {0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
[119]     {0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
[120]     {0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
[121]     {0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
[122]     {0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00007ffe, 15},
[123]     {0x000007fc, 11}, {0x00003ffd, 14}, {0x00001ffd, 13}, {0x0ffffffc, 28},
[124]     {0x000fffe6, 20}, {0x003fffd2, 22}, {0x000fffe7, 20}, {0x000fffe8, 20},
[125]     {0x003fffd3, 22}, {0x003fffd4, 22}, {0x003fffd5, 22}, {0x007fffd9, 23},
[126]     {0x003fffd6, 22}, {0x007fffda, 23}, {0x007fffdb, 23}, {0x007fffdc, 23},
[127]     {0x007fffdd, 23}, {0x007fffde, 23}, {0x00ffffeb, 24}, {0x007fffdf, 23},
[128]     {0x00ffffec, 24}, {0x00ffffed, 24}, {0x003fffd7, 22}, {0x007fffe0, 23},
[129]     {0x00ffffee, 24}, {0x007fffe1, 23}, {0x007fffe2, 23}, {0x007fffe3, 23},
[130]     {0x007fffe4, 23}, {0x001fffdc, 21}, {0x003fffd8, 22}, {0x007fffe5, 23},
[131]     {0x003fffd9, 22}, {0x007fffe6, 23}, {0x007fffe7, 23}, {0x00ffffef, 24},
[132]     {0x003fffda, 22}, {0x001fffdd, 21}, {0x000fffe9, 20}, {0x003fffdb, 22},
[133]     {0x003fffdc, 22}, {0x007fffe8, 23}, {0x007fffe9, 23}, {0x001fffde, 21},
[134]     {0x007fffea, 23}, {0x003fffdd, 22}, {0x003fffde, 22}, {0x00fffff0, 24},
[135]     {0x001fffdf, 21}, {0x003fffdf, 22}, {0x007fffeb, 23}, {0x007fffec, 23},
[136]     {0x001fffe0, 21}, {0x001fffe1, 21}, {0x003fffe0, 22}, {0x001fffe2, 21},
[137]     {0x007fffed, 23}, {0x003fffe1, 22}, {0x007fffee, 23}, {0x007fffef, 23},
[138]     {0x000fffea, 20}, {0x003fffe2, 22}, {0x003fffe3, 22}, {0x003fffe4, 22},
[139]     {0x007ffff0, 23}, {0x003fffe5, 22}, {0x003fffe6, 22}, {0x007ffff1, 23},
[140]     {0x03ffffe0, 26}, {0x03ffffe1, 26}, {0x000fffeb, 20}, {0x0007fff1, 19},
[141]     {0x003fffe7, 22}, {0x007ffff2, 23}, {0x003fffe8, 22}, {0x01ffffec, 25},
[142]     {0x03ffffe2, 26}, {0x03ffffe3, 26}, {0x03ffffe4, 26}, {0x07ffffde, 27},
[143]     {0x07ffffdf, 27}, {0x03ffffe5, 26}, {0x00fffff1, 24}, {0x01ffffed, 25},
[144]     {0x0007fff2, 19}, {0x001fffe3, 21}, {0x03ffffe6, 26}, {0x07ffffe0, 27},
[145]     {0x07ffffe1, 27}, {0x03ffffe7, 26}, {0x07ffffe2, 27}, {0x00fffff2, 24},
[146]     {0x001fffe4, 21}, {0x001fffe5, 21}, {0x03ffffe8, 26}, {0x03ffffe9, 26},
[147]     {0x0ffffffd, 28}, {0x07ffffe3, 27}, {0x07ffffe4, 27}, {0x07ffffe5, 27},
[148]     {0x000fffec, 20}, {0x00fffff3, 24}, {0x000fffed, 20}, {0x001fffe6, 21},
[149]     {0x003fffe9, 22}, {0x001fffe7, 21}, {0x001fffe8, 21}, {0x007ffff3, 23},
[150]     {0x003fffea, 22}, {0x003fffeb, 22}, {0x01ffffee, 25}, {0x01ffffef, 25},
[151]     {0x00fffff4, 24}, {0x00fffff5, 24}, {0x03ffffea, 26}, {0x007ffff4, 23},
[152]     {0x03ffffeb, 26}, {0x07ffffe6, 27}, {0x03ffffec, 26}, {0x03ffffed, 26},
[153]     {0x07ffffe7, 27}, {0x07ffffe8, 27}, {0x07ffffe9, 27}, {0x07ffffea, 27},
[154]     {0x07ffffeb, 27}, {0x0ffffffe, 28}, {0x07ffffec, 27}, {0x07ffffed, 27},
[155]     {0x07ffffee, 27}, {0x07ffffef, 27}, {0x07fffff0, 27}, {0x03ffffee, 26}
[156] };
[157] 
[158] 
[159] #if (NGX_PTR_SIZE == 8)
[160] 
[161] #if (NGX_HAVE_LITTLE_ENDIAN)
[162] 
[163] #if (NGX_HAVE_GCC_BSWAP64)
[164] #define ngx_http_huff_encode_buf(dst, buf)                                    \
[165]     (*(uint64_t *) (dst) = __builtin_bswap64(buf))
[166] #else
[167] #define ngx_http_huff_encode_buf(dst, buf)                                    \
[168]     ((dst)[0] = (u_char) ((buf) >> 56),                                       \
[169]      (dst)[1] = (u_char) ((buf) >> 48),                                       \
[170]      (dst)[2] = (u_char) ((buf) >> 40),                                       \
[171]      (dst)[3] = (u_char) ((buf) >> 32),                                       \
[172]      (dst)[4] = (u_char) ((buf) >> 24),                                       \
[173]      (dst)[5] = (u_char) ((buf) >> 16),                                       \
[174]      (dst)[6] = (u_char) ((buf) >> 8),                                        \
[175]      (dst)[7] = (u_char)  (buf))
[176] #endif
[177] 
[178] #else /* !NGX_HAVE_LITTLE_ENDIAN */
[179] #define ngx_http_huff_encode_buf(dst, buf)                                    \
[180]     (*(uint64_t *) (dst) = (buf))
[181] #endif
[182] 
[183] #else /* NGX_PTR_SIZE == 4 */
[184] 
[185] #define ngx_http_huff_encode_buf(dst, buf)                                    \
[186]     (*(uint32_t *) (dst) = htonl(buf))
[187] 
[188] #endif
[189] 
[190] 
[191] size_t
[192] ngx_http_huff_encode(u_char *src, size_t len, u_char *dst, ngx_uint_t lower)
[193] {
[194]     u_char                       *end;
[195]     size_t                        hlen;
[196]     ngx_uint_t                    buf, pending, code;
[197]     ngx_http_huff_encode_code_t  *table, *next;
[198] 
[199]     table = lower ? ngx_http_huff_encode_table_lc
[200]                   : ngx_http_huff_encode_table;
[201]     hlen = 0;
[202]     buf = 0;
[203]     pending = 0;
[204] 
[205]     end = src + len;
[206] 
[207]     while (src != end) {
[208]         next = &table[*src++];
[209] 
[210]         code = next->code;
[211]         pending += next->len;
[212] 
[213]         /* accumulate bits */
[214]         if (pending < sizeof(buf) * 8) {
[215]             buf |= code << (sizeof(buf) * 8 - pending);
[216]             continue;
[217]         }
[218] 
[219]         if (hlen + sizeof(buf) >= len) {
[220]             return 0;
[221]         }
[222] 
[223]         pending -= sizeof(buf) * 8;
[224] 
[225]         buf |= code >> pending;
[226] 
[227]         ngx_http_huff_encode_buf(&dst[hlen], buf);
[228] 
[229]         hlen += sizeof(buf);
[230] 
[231]         buf = pending ? code << (sizeof(buf) * 8 - pending) : 0;
[232]     }
[233] 
[234]     if (pending == 0) {
[235]         return hlen;
[236]     }
[237] 
[238]     buf |= (ngx_uint_t) -1 >> pending;
[239] 
[240]     pending = ngx_align(pending, 8);
[241] 
[242]     if (hlen + pending / 8 >= len) {
[243]         return 0;
[244]     }
[245] 
[246]     buf >>= sizeof(buf) * 8 - pending;
[247] 
[248]     do {
[249]         pending -= 8;
[250]         dst[hlen++] = (u_char) (buf >> pending);
[251]     } while (pending);
[252] 
[253]     return hlen;
[254] }
