[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  *
[6]  * An internal SHA1 implementation.
[7]  */
[8] 
[9] 
[10] #include <ngx_config.h>
[11] #include <ngx_core.h>
[12] #include <ngx_sha1.h>
[13] 
[14] 
[15] static const u_char *ngx_sha1_body(ngx_sha1_t *ctx, const u_char *data,
[16]     size_t size);
[17] 
[18] 
[19] void
[20] ngx_sha1_init(ngx_sha1_t *ctx)
[21] {
[22]     ctx->a = 0x67452301;
[23]     ctx->b = 0xefcdab89;
[24]     ctx->c = 0x98badcfe;
[25]     ctx->d = 0x10325476;
[26]     ctx->e = 0xc3d2e1f0;
[27] 
[28]     ctx->bytes = 0;
[29] }
[30] 
[31] 
[32] void
[33] ngx_sha1_update(ngx_sha1_t *ctx, const void *data, size_t size)
[34] {
[35]     size_t  used, free;
[36] 
[37]     used = (size_t) (ctx->bytes & 0x3f);
[38]     ctx->bytes += size;
[39] 
[40]     if (used) {
[41]         free = 64 - used;
[42] 
[43]         if (size < free) {
[44]             ngx_memcpy(&ctx->buffer[used], data, size);
[45]             return;
[46]         }
[47] 
[48]         ngx_memcpy(&ctx->buffer[used], data, free);
[49]         data = (u_char *) data + free;
[50]         size -= free;
[51]         (void) ngx_sha1_body(ctx, ctx->buffer, 64);
[52]     }
[53] 
[54]     if (size >= 64) {
[55]         data = ngx_sha1_body(ctx, data, size & ~(size_t) 0x3f);
[56]         size &= 0x3f;
[57]     }
[58] 
[59]     ngx_memcpy(ctx->buffer, data, size);
[60] }
[61] 
[62] 
[63] void
[64] ngx_sha1_final(u_char result[20], ngx_sha1_t *ctx)
[65] {
[66]     size_t  used, free;
[67] 
[68]     used = (size_t) (ctx->bytes & 0x3f);
[69] 
[70]     ctx->buffer[used++] = 0x80;
[71] 
[72]     free = 64 - used;
[73] 
[74]     if (free < 8) {
[75]         ngx_memzero(&ctx->buffer[used], free);
[76]         (void) ngx_sha1_body(ctx, ctx->buffer, 64);
[77]         used = 0;
[78]         free = 64;
[79]     }
[80] 
[81]     ngx_memzero(&ctx->buffer[used], free - 8);
[82] 
[83]     ctx->bytes <<= 3;
[84]     ctx->buffer[56] = (u_char) (ctx->bytes >> 56);
[85]     ctx->buffer[57] = (u_char) (ctx->bytes >> 48);
[86]     ctx->buffer[58] = (u_char) (ctx->bytes >> 40);
[87]     ctx->buffer[59] = (u_char) (ctx->bytes >> 32);
[88]     ctx->buffer[60] = (u_char) (ctx->bytes >> 24);
[89]     ctx->buffer[61] = (u_char) (ctx->bytes >> 16);
[90]     ctx->buffer[62] = (u_char) (ctx->bytes >> 8);
[91]     ctx->buffer[63] = (u_char) ctx->bytes;
[92] 
[93]     (void) ngx_sha1_body(ctx, ctx->buffer, 64);
[94] 
[95]     result[0] = (u_char) (ctx->a >> 24);
[96]     result[1] = (u_char) (ctx->a >> 16);
[97]     result[2] = (u_char) (ctx->a >> 8);
[98]     result[3] = (u_char) ctx->a;
[99]     result[4] = (u_char) (ctx->b >> 24);
[100]     result[5] = (u_char) (ctx->b >> 16);
[101]     result[6] = (u_char) (ctx->b >> 8);
[102]     result[7] = (u_char) ctx->b;
[103]     result[8] = (u_char) (ctx->c >> 24);
[104]     result[9] = (u_char) (ctx->c >> 16);
[105]     result[10] = (u_char) (ctx->c >> 8);
[106]     result[11] = (u_char) ctx->c;
[107]     result[12] = (u_char) (ctx->d >> 24);
[108]     result[13] = (u_char) (ctx->d >> 16);
[109]     result[14] = (u_char) (ctx->d >> 8);
[110]     result[15] = (u_char) ctx->d;
[111]     result[16] = (u_char) (ctx->e >> 24);
[112]     result[17] = (u_char) (ctx->e >> 16);
[113]     result[18] = (u_char) (ctx->e >> 8);
[114]     result[19] = (u_char) ctx->e;
[115] 
[116]     ngx_memzero(ctx, sizeof(*ctx));
[117] }
[118] 
[119] 
[120] /*
[121]  * Helper functions.
[122]  */
[123] 
[124] #define ROTATE(bits, word)  (((word) << (bits)) | ((word) >> (32 - (bits))))
[125] 
[126] #define F1(b, c, d)  (((b) & (c)) | ((~(b)) & (d)))
[127] #define F2(b, c, d)  ((b) ^ (c) ^ (d))
[128] #define F3(b, c, d)  (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
[129] 
[130] #define STEP(f, a, b, c, d, e, w, t)                                          \
[131]     temp = ROTATE(5, (a)) + f((b), (c), (d)) + (e) + (w) + (t);               \
[132]     (e) = (d);                                                                \
[133]     (d) = (c);                                                                \
[134]     (c) = ROTATE(30, (b));                                                    \
[135]     (b) = (a);                                                                \
[136]     (a) = temp;
[137] 
[138] 
[139] /*
[140]  * GET() reads 4 input bytes in big-endian byte order and returns
[141]  * them as uint32_t.
[142]  */
[143] 
[144] #define GET(n)                                                                \
[145]     ((uint32_t) p[n * 4 + 3] |                                                \
[146]     ((uint32_t) p[n * 4 + 2] << 8) |                                          \
[147]     ((uint32_t) p[n * 4 + 1] << 16) |                                         \
[148]     ((uint32_t) p[n * 4] << 24))
[149] 
[150] 
[151] /*
[152]  * This processes one or more 64-byte data blocks, but does not update
[153]  * the bit counters.  There are no alignment requirements.
[154]  */
[155] 
[156] static const u_char *
[157] ngx_sha1_body(ngx_sha1_t *ctx, const u_char *data, size_t size)
[158] {
[159]     uint32_t       a, b, c, d, e, temp;
[160]     uint32_t       saved_a, saved_b, saved_c, saved_d, saved_e;
[161]     uint32_t       words[80];
[162]     ngx_uint_t     i;
[163]     const u_char  *p;
[164] 
[165]     p = data;
[166] 
[167]     a = ctx->a;
[168]     b = ctx->b;
[169]     c = ctx->c;
[170]     d = ctx->d;
[171]     e = ctx->e;
[172] 
[173]     do {
[174]         saved_a = a;
[175]         saved_b = b;
[176]         saved_c = c;
[177]         saved_d = d;
[178]         saved_e = e;
[179] 
[180]         /* Load data block into the words array */
[181] 
[182]         for (i = 0; i < 16; i++) {
[183]             words[i] = GET(i);
[184]         }
[185] 
[186]         for (i = 16; i < 80; i++) {
[187]             words[i] = ROTATE(1, words[i - 3] ^ words[i - 8] ^ words[i - 14]
[188]                                  ^ words[i - 16]);
[189]         }
[190] 
[191]         /* Transformations */
[192] 
[193]         STEP(F1, a, b, c, d, e, words[0],  0x5a827999);
[194]         STEP(F1, a, b, c, d, e, words[1],  0x5a827999);
[195]         STEP(F1, a, b, c, d, e, words[2],  0x5a827999);
[196]         STEP(F1, a, b, c, d, e, words[3],  0x5a827999);
[197]         STEP(F1, a, b, c, d, e, words[4],  0x5a827999);
[198]         STEP(F1, a, b, c, d, e, words[5],  0x5a827999);
[199]         STEP(F1, a, b, c, d, e, words[6],  0x5a827999);
[200]         STEP(F1, a, b, c, d, e, words[7],  0x5a827999);
[201]         STEP(F1, a, b, c, d, e, words[8],  0x5a827999);
[202]         STEP(F1, a, b, c, d, e, words[9],  0x5a827999);
[203]         STEP(F1, a, b, c, d, e, words[10], 0x5a827999);
[204]         STEP(F1, a, b, c, d, e, words[11], 0x5a827999);
[205]         STEP(F1, a, b, c, d, e, words[12], 0x5a827999);
[206]         STEP(F1, a, b, c, d, e, words[13], 0x5a827999);
[207]         STEP(F1, a, b, c, d, e, words[14], 0x5a827999);
[208]         STEP(F1, a, b, c, d, e, words[15], 0x5a827999);
[209]         STEP(F1, a, b, c, d, e, words[16], 0x5a827999);
[210]         STEP(F1, a, b, c, d, e, words[17], 0x5a827999);
[211]         STEP(F1, a, b, c, d, e, words[18], 0x5a827999);
[212]         STEP(F1, a, b, c, d, e, words[19], 0x5a827999);
[213] 
[214]         STEP(F2, a, b, c, d, e, words[20], 0x6ed9eba1);
[215]         STEP(F2, a, b, c, d, e, words[21], 0x6ed9eba1);
[216]         STEP(F2, a, b, c, d, e, words[22], 0x6ed9eba1);
[217]         STEP(F2, a, b, c, d, e, words[23], 0x6ed9eba1);
[218]         STEP(F2, a, b, c, d, e, words[24], 0x6ed9eba1);
[219]         STEP(F2, a, b, c, d, e, words[25], 0x6ed9eba1);
[220]         STEP(F2, a, b, c, d, e, words[26], 0x6ed9eba1);
[221]         STEP(F2, a, b, c, d, e, words[27], 0x6ed9eba1);
[222]         STEP(F2, a, b, c, d, e, words[28], 0x6ed9eba1);
[223]         STEP(F2, a, b, c, d, e, words[29], 0x6ed9eba1);
[224]         STEP(F2, a, b, c, d, e, words[30], 0x6ed9eba1);
[225]         STEP(F2, a, b, c, d, e, words[31], 0x6ed9eba1);
[226]         STEP(F2, a, b, c, d, e, words[32], 0x6ed9eba1);
[227]         STEP(F2, a, b, c, d, e, words[33], 0x6ed9eba1);
[228]         STEP(F2, a, b, c, d, e, words[34], 0x6ed9eba1);
[229]         STEP(F2, a, b, c, d, e, words[35], 0x6ed9eba1);
[230]         STEP(F2, a, b, c, d, e, words[36], 0x6ed9eba1);
[231]         STEP(F2, a, b, c, d, e, words[37], 0x6ed9eba1);
[232]         STEP(F2, a, b, c, d, e, words[38], 0x6ed9eba1);
[233]         STEP(F2, a, b, c, d, e, words[39], 0x6ed9eba1);
[234] 
[235]         STEP(F3, a, b, c, d, e, words[40], 0x8f1bbcdc);
[236]         STEP(F3, a, b, c, d, e, words[41], 0x8f1bbcdc);
[237]         STEP(F3, a, b, c, d, e, words[42], 0x8f1bbcdc);
[238]         STEP(F3, a, b, c, d, e, words[43], 0x8f1bbcdc);
[239]         STEP(F3, a, b, c, d, e, words[44], 0x8f1bbcdc);
[240]         STEP(F3, a, b, c, d, e, words[45], 0x8f1bbcdc);
[241]         STEP(F3, a, b, c, d, e, words[46], 0x8f1bbcdc);
[242]         STEP(F3, a, b, c, d, e, words[47], 0x8f1bbcdc);
[243]         STEP(F3, a, b, c, d, e, words[48], 0x8f1bbcdc);
[244]         STEP(F3, a, b, c, d, e, words[49], 0x8f1bbcdc);
[245]         STEP(F3, a, b, c, d, e, words[50], 0x8f1bbcdc);
[246]         STEP(F3, a, b, c, d, e, words[51], 0x8f1bbcdc);
[247]         STEP(F3, a, b, c, d, e, words[52], 0x8f1bbcdc);
[248]         STEP(F3, a, b, c, d, e, words[53], 0x8f1bbcdc);
[249]         STEP(F3, a, b, c, d, e, words[54], 0x8f1bbcdc);
[250]         STEP(F3, a, b, c, d, e, words[55], 0x8f1bbcdc);
[251]         STEP(F3, a, b, c, d, e, words[56], 0x8f1bbcdc);
[252]         STEP(F3, a, b, c, d, e, words[57], 0x8f1bbcdc);
[253]         STEP(F3, a, b, c, d, e, words[58], 0x8f1bbcdc);
[254]         STEP(F3, a, b, c, d, e, words[59], 0x8f1bbcdc);
[255] 
[256]         STEP(F2, a, b, c, d, e, words[60], 0xca62c1d6);
[257]         STEP(F2, a, b, c, d, e, words[61], 0xca62c1d6);
[258]         STEP(F2, a, b, c, d, e, words[62], 0xca62c1d6);
[259]         STEP(F2, a, b, c, d, e, words[63], 0xca62c1d6);
[260]         STEP(F2, a, b, c, d, e, words[64], 0xca62c1d6);
[261]         STEP(F2, a, b, c, d, e, words[65], 0xca62c1d6);
[262]         STEP(F2, a, b, c, d, e, words[66], 0xca62c1d6);
[263]         STEP(F2, a, b, c, d, e, words[67], 0xca62c1d6);
[264]         STEP(F2, a, b, c, d, e, words[68], 0xca62c1d6);
[265]         STEP(F2, a, b, c, d, e, words[69], 0xca62c1d6);
[266]         STEP(F2, a, b, c, d, e, words[70], 0xca62c1d6);
[267]         STEP(F2, a, b, c, d, e, words[71], 0xca62c1d6);
[268]         STEP(F2, a, b, c, d, e, words[72], 0xca62c1d6);
[269]         STEP(F2, a, b, c, d, e, words[73], 0xca62c1d6);
[270]         STEP(F2, a, b, c, d, e, words[74], 0xca62c1d6);
[271]         STEP(F2, a, b, c, d, e, words[75], 0xca62c1d6);
[272]         STEP(F2, a, b, c, d, e, words[76], 0xca62c1d6);
[273]         STEP(F2, a, b, c, d, e, words[77], 0xca62c1d6);
[274]         STEP(F2, a, b, c, d, e, words[78], 0xca62c1d6);
[275]         STEP(F2, a, b, c, d, e, words[79], 0xca62c1d6);
[276] 
[277]         a += saved_a;
[278]         b += saved_b;
[279]         c += saved_c;
[280]         d += saved_d;
[281]         e += saved_e;
[282] 
[283]         p += 64;
[284] 
[285]     } while (size -= 64);
[286] 
[287]     ctx->a = a;
[288]     ctx->b = b;
[289]     ctx->c = c;
[290]     ctx->d = d;
[291]     ctx->e = e;
[292] 
[293]     return p;
[294] }
