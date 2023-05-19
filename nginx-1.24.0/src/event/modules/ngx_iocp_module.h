[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_IOCP_MODULE_H_INCLUDED_
[9] #define _NGX_IOCP_MODULE_H_INCLUDED_
[10] 
[11] 
[12] typedef struct {
[13]     int  threads;
[14]     int  post_acceptex;
[15]     int  acceptex_read;
[16] } ngx_iocp_conf_t;
[17] 
[18] 
[19] extern ngx_module_t  ngx_iocp_module;
[20] 
[21] 
[22] #endif /* _NGX_IOCP_MODULE_H_INCLUDED_ */
