[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SOLARIS_H_INCLUDED_
[9] #define _NGX_SOLARIS_H_INCLUDED_
[10] 
[11] 
[12] ngx_chain_t *ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in,
[13]     off_t limit);
[14] 
[15] 
[16] #endif /* _NGX_SOLARIS_H_INCLUDED_ */
