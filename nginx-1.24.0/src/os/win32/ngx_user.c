[1] /*
[2]  * Copyright (C) Igor Sysoev
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] 
[10] 
[11] #if (NGX_CRYPT)
[12] 
[13] ngx_int_t
[14] ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[15] {
[16]     /* STUB: a plain text password */
[17] 
[18]     *encrypted = key;
[19] 
[20]     return NGX_OK;
[21] }
[22] 
[23] #endif /* NGX_CRYPT */
