[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] static u_char *ngx_http_v2_write_int(u_char *pos, ngx_uint_t prefix,
[14]     ngx_uint_t value);
[15] 
[16] 
[17] u_char *
[18] ngx_http_v2_string_encode(u_char *dst, u_char *src, size_t len, u_char *tmp,
[19]     ngx_uint_t lower)
[20] {
[21]     size_t  hlen;
[22] 
[23]     hlen = ngx_http_huff_encode(src, len, tmp, lower);
[24] 
[25]     if (hlen > 0) {
[26]         *dst = NGX_HTTP_V2_ENCODE_HUFF;
[27]         dst = ngx_http_v2_write_int(dst, ngx_http_v2_prefix(7), hlen);
[28]         return ngx_cpymem(dst, tmp, hlen);
[29]     }
[30] 
[31]     *dst = NGX_HTTP_V2_ENCODE_RAW;
[32]     dst = ngx_http_v2_write_int(dst, ngx_http_v2_prefix(7), len);
[33] 
[34]     if (lower) {
[35]         ngx_strlow(dst, src, len);
[36]         return dst + len;
[37]     }
[38] 
[39]     return ngx_cpymem(dst, src, len);
[40] }
[41] 
[42] 
[43] static u_char *
[44] ngx_http_v2_write_int(u_char *pos, ngx_uint_t prefix, ngx_uint_t value)
[45] {
[46]     if (value < prefix) {
[47]         *pos++ |= value;
[48]         return pos;
[49]     }
[50] 
[51]     *pos++ |= prefix;
[52]     value -= prefix;
[53] 
[54]     while (value >= 128) {
[55]         *pos++ = value % 128 + 128;
[56]         value /= 128;
[57]     }
[58] 
[59]     *pos++ = (u_char) value;
[60] 
[61]     return pos;
[62] }
