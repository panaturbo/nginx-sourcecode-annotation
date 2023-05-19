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
[40] ngx_int_t ngx_os_specific_init(ngx_log_t *log);
[41] void ngx_os_specific_status(ngx_log_t *log);
[42] ngx_int_t ngx_daemon(ngx_log_t *log);
[43] ngx_int_t ngx_os_signal_process(ngx_cycle_t *cycle, char *sig, ngx_pid_t pid);
[44] 
[45] 
[46] ssize_t ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size);
[47] ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *entry, off_t limit);
[48] ssize_t ngx_udp_unix_recv(ngx_connection_t *c, u_char *buf, size_t size);
[49] ssize_t ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size);
[50] ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in,
[51]     off_t limit);
[52] ssize_t ngx_udp_unix_send(ngx_connection_t *c, u_char *buf, size_t size);
[53] ngx_chain_t *ngx_udp_unix_sendmsg_chain(ngx_connection_t *c, ngx_chain_t *in,
[54]     off_t limit);
[55] 
[56] 
[57] #if (IOV_MAX > 64)
[58] #define NGX_IOVS_PREALLOCATE  64
[59] #else
[60] #define NGX_IOVS_PREALLOCATE  IOV_MAX
[61] #endif
[62] 
[63] 
[64] typedef struct {
[65]     struct iovec  *iovs;
[66]     ngx_uint_t     count;
[67]     size_t         size;
[68]     ngx_uint_t     nalloc;
[69] } ngx_iovec_t;
[70] 
[71] ngx_chain_t *ngx_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in,
[72]     size_t limit, ngx_log_t *log);
[73] 
[74] 
[75] ssize_t ngx_writev(ngx_connection_t *c, ngx_iovec_t *vec);
[76] 
[77] 
[78] extern ngx_os_io_t  ngx_os_io;
[79] extern ngx_int_t    ngx_ncpu;
[80] extern ngx_int_t    ngx_max_sockets;
[81] extern ngx_uint_t   ngx_inherited_nonblocking;
[82] extern ngx_uint_t   ngx_tcp_nodelay_and_tcp_nopush;
[83] 
[84] 
[85] #if (NGX_FREEBSD)
[86] #include <ngx_freebsd.h>
[87] 
[88] 
[89] #elif (NGX_LINUX)
[90] #include <ngx_linux.h>
[91] 
[92] 
[93] #elif (NGX_SOLARIS)
[94] #include <ngx_solaris.h>
[95] 
[96] 
[97] #elif (NGX_DARWIN)
[98] #include <ngx_darwin.h>
[99] #endif
[100] 
[101] 
[102] #endif /* _NGX_OS_H_INCLUDED_ */
