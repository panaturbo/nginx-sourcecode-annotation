[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_DARWIN_H_INCLUDED_
[9] #define _NGX_DARWIN_H_INCLUDED_
[10] 
[11] 
[12] void ngx_debug_init(void);
[13] ngx_chain_t *ngx_darwin_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in,
[14]     off_t limit);
[15] 
[16] extern int       ngx_darwin_kern_osreldate;
[17] extern int       ngx_darwin_hw_ncpu;
[18] extern u_long    ngx_darwin_net_inet_tcp_sendspace;
[19] 
[20] extern ngx_uint_t  ngx_debug_malloc;
[21] 
[22] 
[23] #endif /* _NGX_DARWIN_H_INCLUDED_ */
