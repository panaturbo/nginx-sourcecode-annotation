[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_crypt.h>
[10] #include <ngx_md5.h>
[11] #include <ngx_sha1.h>
[12] 
[13] 
[14] #if (NGX_CRYPT)
[15] 
[16] static ngx_int_t ngx_crypt_apr1(ngx_pool_t *pool, u_char *key, u_char *salt,
[17]     u_char **encrypted);
[18] static ngx_int_t ngx_crypt_plain(ngx_pool_t *pool, u_char *key, u_char *salt,
[19]     u_char **encrypted);
[20] static ngx_int_t ngx_crypt_ssha(ngx_pool_t *pool, u_char *key, u_char *salt,
[21]     u_char **encrypted);
[22] static ngx_int_t ngx_crypt_sha(ngx_pool_t *pool, u_char *key, u_char *salt,
[23]     u_char **encrypted);
[24] 
[25] 
[26] static u_char *ngx_crypt_to64(u_char *p, uint32_t v, size_t n);
[27] 
[28] 
[29] ngx_int_t
[30] ngx_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[31] {
[32]     if (ngx_strncmp(salt, "$apr1$", sizeof("$apr1$") - 1) == 0) {
[33]         return ngx_crypt_apr1(pool, key, salt, encrypted);
[34] 
[35]     } else if (ngx_strncmp(salt, "{PLAIN}", sizeof("{PLAIN}") - 1) == 0) {
[36]         return ngx_crypt_plain(pool, key, salt, encrypted);
[37] 
[38]     } else if (ngx_strncmp(salt, "{SSHA}", sizeof("{SSHA}") - 1) == 0) {
[39]         return ngx_crypt_ssha(pool, key, salt, encrypted);
[40] 
[41]     } else if (ngx_strncmp(salt, "{SHA}", sizeof("{SHA}") - 1) == 0) {
[42]         return ngx_crypt_sha(pool, key, salt, encrypted);
[43]     }
[44] 
[45]     /* fallback to libc crypt() */
[46] 
[47]     return ngx_libc_crypt(pool, key, salt, encrypted);
[48] }
[49] 
[50] 
[51] static ngx_int_t
[52] ngx_crypt_apr1(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[53] {
[54]     ngx_int_t          n;
[55]     ngx_uint_t         i;
[56]     u_char            *p, *last, final[16];
[57]     size_t             saltlen, keylen;
[58]     ngx_md5_t          md5, ctx1;
[59] 
[60]     /* Apache's apr1 crypt is Poul-Henning Kamp's md5 crypt with $apr1$ magic */
[61] 
[62]     keylen = ngx_strlen(key);
[63] 
[64]     /* true salt: no magic, max 8 chars, stop at first $ */
[65] 
[66]     salt += sizeof("$apr1$") - 1;
[67]     last = salt + 8;
[68]     for (p = salt; *p && *p != '$' && p < last; p++) { /* void */ }
[69]     saltlen = p - salt;
[70] 
[71]     /* hash key and salt */
[72] 
[73]     ngx_md5_init(&md5);
[74]     ngx_md5_update(&md5, key, keylen);
[75]     ngx_md5_update(&md5, (u_char *) "$apr1$", sizeof("$apr1$") - 1);
[76]     ngx_md5_update(&md5, salt, saltlen);
[77] 
[78]     ngx_md5_init(&ctx1);
[79]     ngx_md5_update(&ctx1, key, keylen);
[80]     ngx_md5_update(&ctx1, salt, saltlen);
[81]     ngx_md5_update(&ctx1, key, keylen);
[82]     ngx_md5_final(final, &ctx1);
[83] 
[84]     for (n = keylen; n > 0; n -= 16) {
[85]         ngx_md5_update(&md5, final, n > 16 ? 16 : n);
[86]     }
[87] 
[88]     ngx_memzero(final, sizeof(final));
[89] 
[90]     for (i = keylen; i; i >>= 1) {
[91]         if (i & 1) {
[92]             ngx_md5_update(&md5, final, 1);
[93] 
[94]         } else {
[95]             ngx_md5_update(&md5, key, 1);
[96]         }
[97]     }
[98] 
[99]     ngx_md5_final(final, &md5);
[100] 
[101]     for (i = 0; i < 1000; i++) {
[102]         ngx_md5_init(&ctx1);
[103] 
[104]         if (i & 1) {
[105]             ngx_md5_update(&ctx1, key, keylen);
[106] 
[107]         } else {
[108]             ngx_md5_update(&ctx1, final, 16);
[109]         }
[110] 
[111]         if (i % 3) {
[112]             ngx_md5_update(&ctx1, salt, saltlen);
[113]         }
[114] 
[115]         if (i % 7) {
[116]             ngx_md5_update(&ctx1, key, keylen);
[117]         }
[118] 
[119]         if (i & 1) {
[120]             ngx_md5_update(&ctx1, final, 16);
[121] 
[122]         } else {
[123]             ngx_md5_update(&ctx1, key, keylen);
[124]         }
[125] 
[126]         ngx_md5_final(final, &ctx1);
[127]     }
[128] 
[129]     /* output */
[130] 
[131]     *encrypted = ngx_pnalloc(pool, sizeof("$apr1$") - 1 + saltlen + 1 + 22 + 1);
[132]     if (*encrypted == NULL) {
[133]         return NGX_ERROR;
[134]     }
[135] 
[136]     p = ngx_cpymem(*encrypted, "$apr1$", sizeof("$apr1$") - 1);
[137]     p = ngx_copy(p, salt, saltlen);
[138]     *p++ = '$';
[139] 
[140]     p = ngx_crypt_to64(p, (final[ 0]<<16) | (final[ 6]<<8) | final[12], 4);
[141]     p = ngx_crypt_to64(p, (final[ 1]<<16) | (final[ 7]<<8) | final[13], 4);
[142]     p = ngx_crypt_to64(p, (final[ 2]<<16) | (final[ 8]<<8) | final[14], 4);
[143]     p = ngx_crypt_to64(p, (final[ 3]<<16) | (final[ 9]<<8) | final[15], 4);
[144]     p = ngx_crypt_to64(p, (final[ 4]<<16) | (final[10]<<8) | final[ 5], 4);
[145]     p = ngx_crypt_to64(p, final[11], 2);
[146]     *p = '\0';
[147] 
[148]     return NGX_OK;
[149] }
[150] 
[151] 
[152] static u_char *
[153] ngx_crypt_to64(u_char *p, uint32_t v, size_t n)
[154] {
[155]     static u_char   itoa64[] =
[156]         "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
[157] 
[158]     while (n--) {
[159]         *p++ = itoa64[v & 0x3f];
[160]         v >>= 6;
[161]     }
[162] 
[163]     return p;
[164] }
[165] 
[166] 
[167] static ngx_int_t
[168] ngx_crypt_plain(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[169] {
[170]     size_t   len;
[171]     u_char  *p;
[172] 
[173]     len = ngx_strlen(key);
[174] 
[175]     *encrypted = ngx_pnalloc(pool, sizeof("{PLAIN}") - 1 + len + 1);
[176]     if (*encrypted == NULL) {
[177]         return NGX_ERROR;
[178]     }
[179] 
[180]     p = ngx_cpymem(*encrypted, "{PLAIN}", sizeof("{PLAIN}") - 1);
[181]     ngx_memcpy(p, key, len + 1);
[182] 
[183]     return NGX_OK;
[184] }
[185] 
[186] 
[187] static ngx_int_t
[188] ngx_crypt_ssha(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[189] {
[190]     size_t       len;
[191]     ngx_int_t    rc;
[192]     ngx_str_t    encoded, decoded;
[193]     ngx_sha1_t   sha1;
[194] 
[195]     /* "{SSHA}" base64(SHA1(key salt) salt) */
[196] 
[197]     /* decode base64 salt to find out true salt */
[198] 
[199]     encoded.data = salt + sizeof("{SSHA}") - 1;
[200]     encoded.len = ngx_strlen(encoded.data);
[201] 
[202]     len = ngx_max(ngx_base64_decoded_length(encoded.len), 20);
[203] 
[204]     decoded.data = ngx_pnalloc(pool, len);
[205]     if (decoded.data == NULL) {
[206]         return NGX_ERROR;
[207]     }
[208] 
[209]     rc = ngx_decode_base64(&decoded, &encoded);
[210] 
[211]     if (rc != NGX_OK || decoded.len < 20) {
[212]         decoded.len = 20;
[213]     }
[214] 
[215]     /* update SHA1 from key and salt */
[216] 
[217]     ngx_sha1_init(&sha1);
[218]     ngx_sha1_update(&sha1, key, ngx_strlen(key));
[219]     ngx_sha1_update(&sha1, decoded.data + 20, decoded.len - 20);
[220]     ngx_sha1_final(decoded.data, &sha1);
[221] 
[222]     /* encode it back to base64 */
[223] 
[224]     len = sizeof("{SSHA}") - 1 + ngx_base64_encoded_length(decoded.len) + 1;
[225] 
[226]     *encrypted = ngx_pnalloc(pool, len);
[227]     if (*encrypted == NULL) {
[228]         return NGX_ERROR;
[229]     }
[230] 
[231]     encoded.data = ngx_cpymem(*encrypted, "{SSHA}", sizeof("{SSHA}") - 1);
[232]     ngx_encode_base64(&encoded, &decoded);
[233]     encoded.data[encoded.len] = '\0';
[234] 
[235]     return NGX_OK;
[236] }
[237] 
[238] 
[239] static ngx_int_t
[240] ngx_crypt_sha(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[241] {
[242]     size_t      len;
[243]     ngx_str_t   encoded, decoded;
[244]     ngx_sha1_t  sha1;
[245]     u_char      digest[20];
[246] 
[247]     /* "{SHA}" base64(SHA1(key)) */
[248] 
[249]     decoded.len = sizeof(digest);
[250]     decoded.data = digest;
[251] 
[252]     ngx_sha1_init(&sha1);
[253]     ngx_sha1_update(&sha1, key, ngx_strlen(key));
[254]     ngx_sha1_final(digest, &sha1);
[255] 
[256]     len = sizeof("{SHA}") - 1 + ngx_base64_encoded_length(decoded.len) + 1;
[257] 
[258]     *encrypted = ngx_pnalloc(pool, len);
[259]     if (*encrypted == NULL) {
[260]         return NGX_ERROR;
[261]     }
[262] 
[263]     encoded.data = ngx_cpymem(*encrypted, "{SHA}", sizeof("{SHA}") - 1);
[264]     ngx_encode_base64(&encoded, &decoded);
[265]     encoded.data[encoded.len] = '\0';
[266] 
[267]     return NGX_OK;
[268] }
[269] 
[270] #endif /* NGX_CRYPT */
