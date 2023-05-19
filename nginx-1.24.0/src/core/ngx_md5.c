[1] 
[2] /*
[3]  * An internal implementation, based on Alexander Peslyak's
[4]  * public domain implementation:
[5]  * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_md5.h>
[12] 
[13] 
[14] static const u_char *ngx_md5_body(ngx_md5_t *ctx, const u_char *data,
[15]     size_t size);
[16] 
[17] 
[18] void
[19] ngx_md5_init(ngx_md5_t *ctx)
[20] {
[21]     ctx->a = 0x67452301;
[22]     ctx->b = 0xefcdab89;
[23]     ctx->c = 0x98badcfe;
[24]     ctx->d = 0x10325476;
[25] 
[26]     ctx->bytes = 0;
[27] }
[28] 
[29] 
[30] void
[31] ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t size)
[32] {
[33]     size_t  used, free;
[34] 
[35]     used = (size_t) (ctx->bytes & 0x3f);
[36]     ctx->bytes += size;
[37] 
[38]     if (used) {
[39]         free = 64 - used;
[40] 
[41]         if (size < free) {
[42]             ngx_memcpy(&ctx->buffer[used], data, size);
[43]             return;
[44]         }
[45] 
[46]         ngx_memcpy(&ctx->buffer[used], data, free);
[47]         data = (u_char *) data + free;
[48]         size -= free;
[49]         (void) ngx_md5_body(ctx, ctx->buffer, 64);
[50]     }
[51] 
[52]     if (size >= 64) {
[53]         data = ngx_md5_body(ctx, data, size & ~(size_t) 0x3f);
[54]         size &= 0x3f;
[55]     }
[56] 
[57]     ngx_memcpy(ctx->buffer, data, size);
[58] }
[59] 
[60] 
[61] void
[62] ngx_md5_final(u_char result[16], ngx_md5_t *ctx)
[63] {
[64]     size_t  used, free;
[65] 
[66]     used = (size_t) (ctx->bytes & 0x3f);
[67] 
[68]     ctx->buffer[used++] = 0x80;
[69] 
[70]     free = 64 - used;
[71] 
[72]     if (free < 8) {
[73]         ngx_memzero(&ctx->buffer[used], free);
[74]         (void) ngx_md5_body(ctx, ctx->buffer, 64);
[75]         used = 0;
[76]         free = 64;
[77]     }
[78] 
[79]     ngx_memzero(&ctx->buffer[used], free - 8);
[80] 
[81]     ctx->bytes <<= 3;
[82]     ctx->buffer[56] = (u_char) ctx->bytes;
[83]     ctx->buffer[57] = (u_char) (ctx->bytes >> 8);
[84]     ctx->buffer[58] = (u_char) (ctx->bytes >> 16);
[85]     ctx->buffer[59] = (u_char) (ctx->bytes >> 24);
[86]     ctx->buffer[60] = (u_char) (ctx->bytes >> 32);
[87]     ctx->buffer[61] = (u_char) (ctx->bytes >> 40);
[88]     ctx->buffer[62] = (u_char) (ctx->bytes >> 48);
[89]     ctx->buffer[63] = (u_char) (ctx->bytes >> 56);
[90] 
[91]     (void) ngx_md5_body(ctx, ctx->buffer, 64);
[92] 
[93]     result[0] = (u_char) ctx->a;
[94]     result[1] = (u_char) (ctx->a >> 8);
[95]     result[2] = (u_char) (ctx->a >> 16);
[96]     result[3] = (u_char) (ctx->a >> 24);
[97]     result[4] = (u_char) ctx->b;
[98]     result[5] = (u_char) (ctx->b >> 8);
[99]     result[6] = (u_char) (ctx->b >> 16);
[100]     result[7] = (u_char) (ctx->b >> 24);
[101]     result[8] = (u_char) ctx->c;
[102]     result[9] = (u_char) (ctx->c >> 8);
[103]     result[10] = (u_char) (ctx->c >> 16);
[104]     result[11] = (u_char) (ctx->c >> 24);
[105]     result[12] = (u_char) ctx->d;
[106]     result[13] = (u_char) (ctx->d >> 8);
[107]     result[14] = (u_char) (ctx->d >> 16);
[108]     result[15] = (u_char) (ctx->d >> 24);
[109] 
[110]     ngx_memzero(ctx, sizeof(*ctx));
[111] }
[112] 
[113] 
[114] /*
[115]  * The basic MD5 functions.
[116]  *
[117]  * F and G are optimized compared to their RFC 1321 definitions for
[118]  * architectures that lack an AND-NOT instruction, just like in
[119]  * Colin Plumb's implementation.
[120]  */
[121] 
[122] #define F(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
[123] #define G(x, y, z)  ((y) ^ ((z) & ((x) ^ (y))))
[124] #define H(x, y, z)  ((x) ^ (y) ^ (z))
[125] #define I(x, y, z)  ((y) ^ ((x) | ~(z)))
[126] 
[127] /*
[128]  * The MD5 transformation for all four rounds.
[129]  */
[130] 
[131] #define STEP(f, a, b, c, d, x, t, s)                                          \
[132]     (a) += f((b), (c), (d)) + (x) + (t);                                      \
[133]     (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));                \
[134]     (a) += (b)
[135] 
[136] /*
[137]  * SET() reads 4 input bytes in little-endian byte order and stores them
[138]  * in a properly aligned word in host byte order.
[139]  *
[140]  * The check for little-endian architectures that tolerate unaligned
[141]  * memory accesses is just an optimization.  Nothing will break if it
[142]  * does not work.
[143]  */
[144] 
[145] #if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)
[146] 
[147] #define SET(n)      (*(uint32_t *) &p[n * 4])
[148] #define GET(n)      (*(uint32_t *) &p[n * 4])
[149] 
[150] #else
[151] 
[152] #define SET(n)                                                                \
[153]     (block[n] =                                                               \
[154]     (uint32_t) p[n * 4] |                                                     \
[155]     ((uint32_t) p[n * 4 + 1] << 8) |                                          \
[156]     ((uint32_t) p[n * 4 + 2] << 16) |                                         \
[157]     ((uint32_t) p[n * 4 + 3] << 24))
[158] 
[159] #define GET(n)      block[n]
[160] 
[161] #endif
[162] 
[163] 
[164] /*
[165]  * This processes one or more 64-byte data blocks, but does not update
[166]  * the bit counters.  There are no alignment requirements.
[167]  */
[168] 
[169] static const u_char *
[170] ngx_md5_body(ngx_md5_t *ctx, const u_char *data, size_t size)
[171] {
[172]     uint32_t       a, b, c, d;
[173]     uint32_t       saved_a, saved_b, saved_c, saved_d;
[174]     const u_char  *p;
[175] #if !(NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)
[176]     uint32_t       block[16];
[177] #endif
[178] 
[179]     p = data;
[180] 
[181]     a = ctx->a;
[182]     b = ctx->b;
[183]     c = ctx->c;
[184]     d = ctx->d;
[185] 
[186]     do {
[187]         saved_a = a;
[188]         saved_b = b;
[189]         saved_c = c;
[190]         saved_d = d;
[191] 
[192]         /* Round 1 */
[193] 
[194]         STEP(F, a, b, c, d, SET(0),  0xd76aa478, 7);
[195]         STEP(F, d, a, b, c, SET(1),  0xe8c7b756, 12);
[196]         STEP(F, c, d, a, b, SET(2),  0x242070db, 17);
[197]         STEP(F, b, c, d, a, SET(3),  0xc1bdceee, 22);
[198]         STEP(F, a, b, c, d, SET(4),  0xf57c0faf, 7);
[199]         STEP(F, d, a, b, c, SET(5),  0x4787c62a, 12);
[200]         STEP(F, c, d, a, b, SET(6),  0xa8304613, 17);
[201]         STEP(F, b, c, d, a, SET(7),  0xfd469501, 22);
[202]         STEP(F, a, b, c, d, SET(8),  0x698098d8, 7);
[203]         STEP(F, d, a, b, c, SET(9),  0x8b44f7af, 12);
[204]         STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17);
[205]         STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22);
[206]         STEP(F, a, b, c, d, SET(12), 0x6b901122, 7);
[207]         STEP(F, d, a, b, c, SET(13), 0xfd987193, 12);
[208]         STEP(F, c, d, a, b, SET(14), 0xa679438e, 17);
[209]         STEP(F, b, c, d, a, SET(15), 0x49b40821, 22);
[210] 
[211]         /* Round 2 */
[212] 
[213]         STEP(G, a, b, c, d, GET(1),  0xf61e2562, 5);
[214]         STEP(G, d, a, b, c, GET(6),  0xc040b340, 9);
[215]         STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14);
[216]         STEP(G, b, c, d, a, GET(0),  0xe9b6c7aa, 20);
[217]         STEP(G, a, b, c, d, GET(5),  0xd62f105d, 5);
[218]         STEP(G, d, a, b, c, GET(10), 0x02441453, 9);
[219]         STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14);
[220]         STEP(G, b, c, d, a, GET(4),  0xe7d3fbc8, 20);
[221]         STEP(G, a, b, c, d, GET(9),  0x21e1cde6, 5);
[222]         STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9);
[223]         STEP(G, c, d, a, b, GET(3),  0xf4d50d87, 14);
[224]         STEP(G, b, c, d, a, GET(8),  0x455a14ed, 20);
[225]         STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5);
[226]         STEP(G, d, a, b, c, GET(2),  0xfcefa3f8, 9);
[227]         STEP(G, c, d, a, b, GET(7),  0x676f02d9, 14);
[228]         STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20);
[229] 
[230]         /* Round 3 */
[231] 
[232]         STEP(H, a, b, c, d, GET(5),  0xfffa3942, 4);
[233]         STEP(H, d, a, b, c, GET(8),  0x8771f681, 11);
[234]         STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16);
[235]         STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23);
[236]         STEP(H, a, b, c, d, GET(1),  0xa4beea44, 4);
[237]         STEP(H, d, a, b, c, GET(4),  0x4bdecfa9, 11);
[238]         STEP(H, c, d, a, b, GET(7),  0xf6bb4b60, 16);
[239]         STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23);
[240]         STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4);
[241]         STEP(H, d, a, b, c, GET(0),  0xeaa127fa, 11);
[242]         STEP(H, c, d, a, b, GET(3),  0xd4ef3085, 16);
[243]         STEP(H, b, c, d, a, GET(6),  0x04881d05, 23);
[244]         STEP(H, a, b, c, d, GET(9),  0xd9d4d039, 4);
[245]         STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11);
[246]         STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16);
[247]         STEP(H, b, c, d, a, GET(2),  0xc4ac5665, 23);
[248] 
[249]         /* Round 4 */
[250] 
[251]         STEP(I, a, b, c, d, GET(0),  0xf4292244, 6);
[252]         STEP(I, d, a, b, c, GET(7),  0x432aff97, 10);
[253]         STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15);
[254]         STEP(I, b, c, d, a, GET(5),  0xfc93a039, 21);
[255]         STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6);
[256]         STEP(I, d, a, b, c, GET(3),  0x8f0ccc92, 10);
[257]         STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15);
[258]         STEP(I, b, c, d, a, GET(1),  0x85845dd1, 21);
[259]         STEP(I, a, b, c, d, GET(8),  0x6fa87e4f, 6);
[260]         STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10);
[261]         STEP(I, c, d, a, b, GET(6),  0xa3014314, 15);
[262]         STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21);
[263]         STEP(I, a, b, c, d, GET(4),  0xf7537e82, 6);
[264]         STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10);
[265]         STEP(I, c, d, a, b, GET(2),  0x2ad7d2bb, 15);
[266]         STEP(I, b, c, d, a, GET(9),  0xeb86d391, 21);
[267] 
[268]         a += saved_a;
[269]         b += saved_b;
[270]         c += saved_c;
[271]         d += saved_d;
[272] 
[273]         p += 64;
[274] 
[275]     } while (size -= 64);
[276] 
[277]     ctx->a = a;
[278]     ctx->b = b;
[279]     ctx->c = c;
[280]     ctx->d = d;
[281] 
[282]     return p;
[283] }
