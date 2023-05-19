[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MURMURHASH_H_INCLUDED_
[9] #define _NGX_MURMURHASH_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] uint32_t ngx_murmur_hash2(u_char *data, size_t len);
[17] 
[18] 
[19] #endif /* _NGX_MURMURHASH_H_INCLUDED_ */
