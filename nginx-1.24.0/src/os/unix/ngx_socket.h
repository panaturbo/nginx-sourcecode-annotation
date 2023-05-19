[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SOCKET_H_INCLUDED_
[9] #define _NGX_SOCKET_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] 
[14] 
[15] #define NGX_WRITE_SHUTDOWN SHUT_WR
[16] 
[17] typedef int  ngx_socket_t;
[18] 
[19] #define ngx_socket          socket
[20] #define ngx_socket_n        "socket()"
[21] 
[22] 
[23] #if (NGX_HAVE_FIONBIO)
[24] 
[25] int ngx_nonblocking(ngx_socket_t s);
[26] int ngx_blocking(ngx_socket_t s);
[27] 
[28] #define ngx_nonblocking_n   "ioctl(FIONBIO)"
[29] #define ngx_blocking_n      "ioctl(!FIONBIO)"
[30] 
[31] #else
[32] 
[33] #define ngx_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
[34] #define ngx_nonblocking_n   "fcntl(O_NONBLOCK)"
[35] 
[36] #define ngx_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
[37] #define ngx_blocking_n      "fcntl(!O_NONBLOCK)"
[38] 
[39] #endif
[40] 
[41] #if (NGX_HAVE_FIONREAD)
[42] 
[43] #define ngx_socket_nread(s, n)  ioctl(s, FIONREAD, n)
[44] #define ngx_socket_nread_n      "ioctl(FIONREAD)"
[45] 
[46] #endif
[47] 
[48] int ngx_tcp_nopush(ngx_socket_t s);
[49] int ngx_tcp_push(ngx_socket_t s);
[50] 
[51] #if (NGX_LINUX)
[52] 
[53] #define ngx_tcp_nopush_n   "setsockopt(TCP_CORK)"
[54] #define ngx_tcp_push_n     "setsockopt(!TCP_CORK)"
[55] 
[56] #else
[57] 
[58] #define ngx_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
[59] #define ngx_tcp_push_n     "setsockopt(!TCP_NOPUSH)"
[60] 
[61] #endif
[62] 
[63] 
[64] #define ngx_shutdown_socket    shutdown
[65] #define ngx_shutdown_socket_n  "shutdown()"
[66] 
[67] #define ngx_close_socket    close
[68] #define ngx_close_socket_n  "close() socket"
[69] 
[70] 
[71] #endif /* _NGX_SOCKET_H_INCLUDED_ */
