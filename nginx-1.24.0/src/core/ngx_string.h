[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STRING_H_INCLUDED_
[9] #define _NGX_STRING_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     size_t      len;
[18]     u_char     *data;
[19] } ngx_str_t;
[20] 
[21] 
[22] typedef struct {
[23]     ngx_str_t   key;
[24]     ngx_str_t   value;
[25] } ngx_keyval_t;
[26] 
[27] 
[28] typedef struct {
[29]     unsigned    len:28;
[30] 
[31]     unsigned    valid:1;
[32]     unsigned    no_cacheable:1;
[33]     unsigned    not_found:1;
[34]     unsigned    escape:1;
[35] 
[36]     u_char     *data;
[37] } ngx_variable_value_t;
[38] 
[39] 
[40] #define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
[41] #define ngx_null_string     { 0, NULL }
[42] #define ngx_str_set(str, text)                                               \
[43]     (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
[44] #define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL
[45] 
[46] 
[47] #define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
[48] #define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)
[49] 
[50] void ngx_strlow(u_char *dst, u_char *src, size_t n);
[51] 
[52] 
[53] #define ngx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)
[54] 
[55] 
[56] /* msvc and icc7 compile strcmp() to inline loop */
[57] #define ngx_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)
[58] 
[59] 
[60] #define ngx_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
[61] #define ngx_strlen(s)       strlen((const char *) s)
[62] 
[63] size_t ngx_strnlen(u_char *p, size_t n);
[64] 
[65] #define ngx_strchr(s1, c)   strchr((const char *) s1, (int) c)
[66] 
[67] static ngx_inline u_char *
[68] ngx_strlchr(u_char *p, u_char *last, u_char c)
[69] {
[70]     while (p < last) {
[71] 
[72]         if (*p == c) {
[73]             return p;
[74]         }
[75] 
[76]         p++;
[77]     }
[78] 
[79]     return NULL;
[80] }
[81] 
[82] 
[83] /*
[84]  * msvc and icc7 compile memset() to the inline "rep stos"
[85]  * while ZeroMemory() and bzero() are the calls.
[86]  * icc7 may also inline several mov's of a zeroed register for small blocks.
[87]  */
[88] #define ngx_memzero(buf, n)       (void) memset(buf, 0, n)
[89] #define ngx_memset(buf, c, n)     (void) memset(buf, c, n)
[90] 
[91] void ngx_explicit_memzero(void *buf, size_t n);
[92] 
[93] 
[94] #if (NGX_MEMCPY_LIMIT)
[95] 
[96] void *ngx_memcpy(void *dst, const void *src, size_t n);
[97] #define ngx_cpymem(dst, src, n)   (((u_char *) ngx_memcpy(dst, src, n)) + (n))
[98] 
[99] #else
[100] 
[101] /*
[102]  * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
[103]  * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
[104]  * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
[105]  */
[106] #define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
[107] #define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))
[108] 
[109] #endif
[110] 
[111] 
[112] #if ( __INTEL_COMPILER >= 800 )
[113] 
[114] /*
[115]  * the simple inline cycle copies the variable length strings up to 16
[116]  * bytes faster than icc8 autodetecting _intel_fast_memcpy()
[117]  */
[118] 
[119] static ngx_inline u_char *
[120] ngx_copy(u_char *dst, u_char *src, size_t len)
[121] {
[122]     if (len < 17) {
[123] 
[124]         while (len) {
[125]             *dst++ = *src++;
[126]             len--;
[127]         }
[128] 
[129]         return dst;
[130] 
[131]     } else {
[132]         return ngx_cpymem(dst, src, len);
[133]     }
[134] }
[135] 
[136] #else
[137] 
[138] #define ngx_copy                  ngx_cpymem
[139] 
[140] #endif
[141] 
[142] 
[143] #define ngx_memmove(dst, src, n)  (void) memmove(dst, src, n)
[144] #define ngx_movemem(dst, src, n)  (((u_char *) memmove(dst, src, n)) + (n))
[145] 
[146] 
[147] /* msvc and icc7 compile memcmp() to the inline loop */
[148] #define ngx_memcmp(s1, s2, n)     memcmp(s1, s2, n)
[149] 
[150] 
[151] u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n);
[152] u_char *ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src);
[153] u_char * ngx_cdecl ngx_sprintf(u_char *buf, const char *fmt, ...);
[154] u_char * ngx_cdecl ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...);
[155] u_char * ngx_cdecl ngx_slprintf(u_char *buf, u_char *last, const char *fmt,
[156]     ...);
[157] u_char *ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
[158] #define ngx_vsnprintf(buf, max, fmt, args)                                   \
[159]     ngx_vslprintf(buf, buf + (max), fmt, args)
[160] 
[161] ngx_int_t ngx_strcasecmp(u_char *s1, u_char *s2);
[162] ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);
[163] 
[164] u_char *ngx_strnstr(u_char *s1, char *s2, size_t n);
[165] 
[166] u_char *ngx_strstrn(u_char *s1, char *s2, size_t n);
[167] u_char *ngx_strcasestrn(u_char *s1, char *s2, size_t n);
[168] u_char *ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);
[169] 
[170] ngx_int_t ngx_rstrncmp(u_char *s1, u_char *s2, size_t n);
[171] ngx_int_t ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
[172] ngx_int_t ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
[173] ngx_int_t ngx_dns_strcmp(u_char *s1, u_char *s2);
[174] ngx_int_t ngx_filename_cmp(u_char *s1, u_char *s2, size_t n);
[175] 
[176] ngx_int_t ngx_atoi(u_char *line, size_t n);
[177] ngx_int_t ngx_atofp(u_char *line, size_t n, size_t point);
[178] ssize_t ngx_atosz(u_char *line, size_t n);
[179] off_t ngx_atoof(u_char *line, size_t n);
[180] time_t ngx_atotm(u_char *line, size_t n);
[181] ngx_int_t ngx_hextoi(u_char *line, size_t n);
[182] 
[183] u_char *ngx_hex_dump(u_char *dst, u_char *src, size_t len);
[184] 
[185] 
[186] #define ngx_base64_encoded_length(len)  (((len + 2) / 3) * 4)
[187] #define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)
[188] 
[189] void ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src);
[190] void ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src);
[191] ngx_int_t ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src);
[192] ngx_int_t ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src);
[193] 
[194] uint32_t ngx_utf8_decode(u_char **p, size_t n);
[195] size_t ngx_utf8_length(u_char *p, size_t n);
[196] u_char *ngx_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);
[197] 
[198] 
[199] #define NGX_ESCAPE_URI            0
[200] #define NGX_ESCAPE_ARGS           1
[201] #define NGX_ESCAPE_URI_COMPONENT  2
[202] #define NGX_ESCAPE_HTML           3
[203] #define NGX_ESCAPE_REFRESH        4
[204] #define NGX_ESCAPE_MEMCACHED      5
[205] #define NGX_ESCAPE_MAIL_AUTH      6
[206] 
[207] #define NGX_UNESCAPE_URI       1
[208] #define NGX_UNESCAPE_REDIRECT  2
[209] 
[210] uintptr_t ngx_escape_uri(u_char *dst, u_char *src, size_t size,
[211]     ngx_uint_t type);
[212] void ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type);
[213] uintptr_t ngx_escape_html(u_char *dst, u_char *src, size_t size);
[214] uintptr_t ngx_escape_json(u_char *dst, u_char *src, size_t size);
[215] 
[216] 
[217] typedef struct {
[218]     ngx_rbtree_node_t         node;
[219]     ngx_str_t                 str;
[220] } ngx_str_node_t;
[221] 
[222] 
[223] void ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
[224]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[225] ngx_str_node_t *ngx_str_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *name,
[226]     uint32_t hash);
[227] 
[228] 
[229] void ngx_sort(void *base, size_t n, size_t size,
[230]     ngx_int_t (*cmp)(const void *, const void *));
[231] #define ngx_qsort             qsort
[232] 
[233] 
[234] #define ngx_value_helper(n)   #n
[235] #define ngx_value(n)          ngx_value_helper(n)
[236] 
[237] 
[238] #endif /* _NGX_STRING_H_INCLUDED_ */
