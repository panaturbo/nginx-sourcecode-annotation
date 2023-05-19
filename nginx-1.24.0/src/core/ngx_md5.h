[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MD5_H_INCLUDED_
[9] #define _NGX_MD5_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     uint64_t  bytes;
[18]     uint32_t  a, b, c, d;
[19]     u_char    buffer[64];
[20] } ngx_md5_t;
[21] 
[22] 
[23] void ngx_md5_init(ngx_md5_t *ctx);
[24] void ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t size);
[25] void ngx_md5_final(u_char result[16], ngx_md5_t *ctx);
[26] 
[27] 
[28] #endif /* _NGX_MD5_H_INCLUDED_ */
