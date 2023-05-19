[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_USER_H_INCLUDED_
[9] #define _NGX_USER_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] /* STUB */
[17] #define ngx_uid_t  ngx_int_t
[18] #define ngx_gid_t  ngx_int_t
[19] 
[20] 
[21] ngx_int_t ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt,
[22]     u_char **encrypted);
[23] 
[24] 
[25] #endif /* _NGX_USER_H_INCLUDED_ */
