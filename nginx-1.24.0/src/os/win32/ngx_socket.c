[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] int
[13] ngx_nonblocking(ngx_socket_t s)
[14] {
[15]     unsigned long  nb = 1;
[16] 
[17]     return ioctlsocket(s, FIONBIO, &nb);
[18] }
[19] 
[20] 
[21] int
[22] ngx_blocking(ngx_socket_t s)
[23] {
[24]     unsigned long  nb = 0;
[25] 
[26]     return ioctlsocket(s, FIONBIO, &nb);
[27] }
[28] 
[29] 
[30] int
[31] ngx_socket_nread(ngx_socket_t s, int *n)
[32] {
[33]     unsigned long  nread;
[34] 
[35]     if (ioctlsocket(s, FIONREAD, &nread) == -1) {
[36]         return -1;
[37]     }
[38] 
[39]     *n = nread;
[40] 
[41]     return 0;
[42] }
[43] 
[44] 
[45] int
[46] ngx_tcp_push(ngx_socket_t s)
[47] {
[48]     return 0;
[49] }
