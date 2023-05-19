[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_OS_H_INCLUDED_
[9] #define _NGX_OS_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_IO_SENDFILE    1
[17] 
[18] 
[19] typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
[20] typedef ssize_t (*ngx_recv_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
[21]     off_t limit);
[22] typedef ssize_t (*ngx_send_pt)(ngx_connection_t *c, u_char *buf, size_t size);
[23] typedef ngx_chain_t *(*ngx_send_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
[24]     off_t limit);
[25] 
[26] typedef struct {
[27]     ngx_recv_pt        recv;
[28]     ngx_recv_chain_pt  recv_chain;
[29]     ngx_recv_pt        udp_recv;
[30]     ngx_send_pt        send;
[31]     ngx_send_pt        udp_send;
[32]     ngx_send_chain_pt  udp_send_chain;
[33]     ngx_send_chain_pt  send_chain;
[34]     ngx_uint_t         flags;
[35] } ngx_os_io_t;
[36] 
[37] 
[38] ngx_int_t ngx_os_init(ngx_log_t *log);
[39] void ngx_os_status(ngx_log_t *log);
[40] ngx_int_t ngx_os_signal_process(ngx_cycle_t *cycle, char *sig, ngx_pid_t pid);
[41] 
[42] ssize_t ngx_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
[43] ssize_t ngx_overlapped_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
[44] ssize_t ngx_udp_wsarecv(ngx_connection_t *c, u_char *buf, size_t size);
[45] ssize_t ngx_udp_overlapped_wsarecv(ngx_connection_t *c, u_char *buf,
[46]     size_t size);
[47] ssize_t ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain, off_t limit);
[48] ssize_t ngx_wsasend(ngx_connection_t *c, u_char *buf, size_t size);
[49] ssize_t ngx_overlapped_wsasend(ngx_connection_t *c, u_char *buf, size_t size);
[50] ngx_chain_t *ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
[51]     off_t limit);
[52] ngx_chain_t *ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in,
[53]     off_t limit);
[54] 
[55] void ngx_cdecl ngx_event_log(ngx_err_t err, const char *fmt, ...);
[56] 
[57] 
[58] extern ngx_os_io_t  ngx_os_io;
[59] extern ngx_uint_t   ngx_ncpu;
[60] extern ngx_uint_t   ngx_max_wsabufs;
[61] extern ngx_int_t    ngx_max_sockets;
[62] extern ngx_uint_t   ngx_inherited_nonblocking;
[63] extern ngx_uint_t   ngx_tcp_nodelay_and_tcp_nopush;
[64] extern ngx_uint_t   ngx_win32_version;
[65] extern char         ngx_unique[];
[66] 
[67] 
[68] #endif /* _NGX_OS_H_INCLUDED_ */
