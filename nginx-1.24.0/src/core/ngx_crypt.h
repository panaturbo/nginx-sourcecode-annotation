[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CRYPT_H_INCLUDED_
[9] #define _NGX_CRYPT_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] ngx_int_t ngx_crypt(ngx_pool_t *pool, u_char *key, u_char *salt,
[17]     u_char **encrypted);
[18] 
[19] 
[20] #endif /* _NGX_CRYPT_H_INCLUDED_ */
