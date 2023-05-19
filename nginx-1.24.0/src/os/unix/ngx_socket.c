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
[12] /*
[13]  * ioctl(FIONBIO) sets a non-blocking mode with the single syscall
[14]  * while fcntl(F_SETFL, O_NONBLOCK) needs to learn the current state
[15]  * using fcntl(F_GETFL).
[16]  *
[17]  * ioctl() and fcntl() are syscalls at least in FreeBSD 2.x, Linux 2.2
[18]  * and Solaris 7.
[19]  *
[20]  * ioctl() in Linux 2.4 and 2.6 uses BKL, however, fcntl(F_SETFL) uses it too.
[21]  */
[22] 
[23] 
[24] #if (NGX_HAVE_FIONBIO)
[25] 
[26] int
[27] ngx_nonblocking(ngx_socket_t s)
[28] {
[29]     int  nb;
[30] 
[31]     nb = 1;
[32] 
[33]     return ioctl(s, FIONBIO, &nb);
[34] }
[35] 
[36] 
[37] int
[38] ngx_blocking(ngx_socket_t s)
[39] {
[40]     int  nb;
[41] 
[42]     nb = 0;
[43] 
[44]     return ioctl(s, FIONBIO, &nb);
[45] }
[46] 
[47] #endif
[48] 
[49] 
[50] #if (NGX_FREEBSD)
[51] 
[52] int
[53] ngx_tcp_nopush(ngx_socket_t s)
[54] {
[55]     int  tcp_nopush;
[56] 
[57]     tcp_nopush = 1;
[58] 
[59]     return setsockopt(s, IPPROTO_TCP, TCP_NOPUSH,
[60]                       (const void *) &tcp_nopush, sizeof(int));
[61] }
[62] 
[63] 
[64] int
[65] ngx_tcp_push(ngx_socket_t s)
[66] {
[67]     int  tcp_nopush;
[68] 
[69]     tcp_nopush = 0;
[70] 
[71]     return setsockopt(s, IPPROTO_TCP, TCP_NOPUSH,
[72]                       (const void *) &tcp_nopush, sizeof(int));
[73] }
[74] 
[75] #elif (NGX_LINUX)
[76] 
[77] 
[78] int
[79] ngx_tcp_nopush(ngx_socket_t s)
[80] {
[81]     int  cork;
[82] 
[83]     cork = 1;
[84] 
[85]     return setsockopt(s, IPPROTO_TCP, TCP_CORK,
[86]                       (const void *) &cork, sizeof(int));
[87] }
[88] 
[89] 
[90] int
[91] ngx_tcp_push(ngx_socket_t s)
[92] {
[93]     int  cork;
[94] 
[95]     cork = 0;
[96] 
[97]     return setsockopt(s, IPPROTO_TCP, TCP_CORK,
[98]                       (const void *) &cork, sizeof(int));
[99] }
[100] 
[101] #else
[102] 
[103] int
[104] ngx_tcp_nopush(ngx_socket_t s)
[105] {
[106]     return 0;
[107] }
[108] 
[109] 
[110] int
[111] ngx_tcp_push(ngx_socket_t s)
[112] {
[113]     return 0;
[114] }
[115] 
[116] #endif
