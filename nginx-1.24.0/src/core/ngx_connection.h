[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CONNECTION_H_INCLUDED_
[9] #define _NGX_CONNECTION_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct ngx_listening_s  ngx_listening_t;
[17] 
[18] struct ngx_listening_s {
[19]     ngx_socket_t        fd;
[20] 
[21]     struct sockaddr    *sockaddr;
[22]     socklen_t           socklen;    /* size of sockaddr */
[23]     size_t              addr_text_max_len;
[24]     ngx_str_t           addr_text;
[25] 
[26]     int                 type;
[27] 
[28]     int                 backlog;
[29]     int                 rcvbuf;
[30]     int                 sndbuf;
[31] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[32]     int                 keepidle;
[33]     int                 keepintvl;
[34]     int                 keepcnt;
[35] #endif
[36] 
[37]     /* handler of accepted connection */
[38]     ngx_connection_handler_pt   handler;
[39] 
[40]     void               *servers;  /* array of ngx_http_in_addr_t, for example */
[41] 
[42]     ngx_log_t           log;
[43]     ngx_log_t          *logp;
[44] 
[45]     size_t              pool_size;
[46]     /* should be here because of the AcceptEx() preread */
[47]     size_t              post_accept_buffer_size;
[48] 
[49]     ngx_listening_t    *previous;
[50]     ngx_connection_t   *connection;
[51] 
[52]     ngx_rbtree_t        rbtree;
[53]     ngx_rbtree_node_t   sentinel;
[54] 
[55]     ngx_uint_t          worker;
[56] 
[57]     unsigned            open:1;
[58]     unsigned            remain:1;
[59]     unsigned            ignore:1;
[60] 
[61]     unsigned            bound:1;       /* already bound */
[62]     unsigned            inherited:1;   /* inherited from previous process */
[63]     unsigned            nonblocking_accept:1;
[64]     unsigned            listen:1;
[65]     unsigned            nonblocking:1;
[66]     unsigned            shared:1;    /* shared between threads or processes */
[67]     unsigned            addr_ntop:1;
[68]     unsigned            wildcard:1;
[69] 
[70] #if (NGX_HAVE_INET6)
[71]     unsigned            ipv6only:1;
[72] #endif
[73]     unsigned            reuseport:1;
[74]     unsigned            add_reuseport:1;
[75]     unsigned            keepalive:2;
[76] 
[77]     unsigned            deferred_accept:1;
[78]     unsigned            delete_deferred:1;
[79]     unsigned            add_deferred:1;
[80] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[81]     char               *accept_filter;
[82] #endif
[83] #if (NGX_HAVE_SETFIB)
[84]     int                 setfib;
[85] #endif
[86] 
[87] #if (NGX_HAVE_TCP_FASTOPEN)
[88]     int                 fastopen;
[89] #endif
[90] 
[91] };
[92] 
[93] 
[94] typedef enum {
[95]     NGX_ERROR_ALERT = 0,
[96]     NGX_ERROR_ERR,
[97]     NGX_ERROR_INFO,
[98]     NGX_ERROR_IGNORE_ECONNRESET,
[99]     NGX_ERROR_IGNORE_EINVAL
[100] } ngx_connection_log_error_e;
[101] 
[102] 
[103] typedef enum {
[104]     NGX_TCP_NODELAY_UNSET = 0,
[105]     NGX_TCP_NODELAY_SET,
[106]     NGX_TCP_NODELAY_DISABLED
[107] } ngx_connection_tcp_nodelay_e;
[108] 
[109] 
[110] typedef enum {
[111]     NGX_TCP_NOPUSH_UNSET = 0,
[112]     NGX_TCP_NOPUSH_SET,
[113]     NGX_TCP_NOPUSH_DISABLED
[114] } ngx_connection_tcp_nopush_e;
[115] 
[116] 
[117] #define NGX_LOWLEVEL_BUFFERED  0x0f
[118] #define NGX_SSL_BUFFERED       0x01
[119] #define NGX_HTTP_V2_BUFFERED   0x02
[120] 
[121] 
[122] struct ngx_connection_s {
[123]     void               *data;
[124]     ngx_event_t        *read;
[125]     ngx_event_t        *write;
[126] 
[127]     ngx_socket_t        fd;
[128] 
[129]     ngx_recv_pt         recv;
[130]     ngx_send_pt         send;
[131]     ngx_recv_chain_pt   recv_chain;
[132]     ngx_send_chain_pt   send_chain;
[133] 
[134]     ngx_listening_t    *listening;
[135] 
[136]     off_t               sent;
[137] 
[138]     ngx_log_t          *log;
[139] 
[140]     ngx_pool_t         *pool;
[141] 
[142]     int                 type;
[143] 
[144]     struct sockaddr    *sockaddr;
[145]     socklen_t           socklen;
[146]     ngx_str_t           addr_text;
[147] 
[148]     ngx_proxy_protocol_t  *proxy_protocol;
[149] 
[150] #if (NGX_SSL || NGX_COMPAT)
[151]     ngx_ssl_connection_t  *ssl;
[152] #endif
[153] 
[154]     ngx_udp_connection_t  *udp;
[155] 
[156]     struct sockaddr    *local_sockaddr;
[157]     socklen_t           local_socklen;
[158] 
[159]     ngx_buf_t          *buffer;
[160] 
[161]     ngx_queue_t         queue;
[162] 
[163]     ngx_atomic_uint_t   number;
[164] 
[165]     ngx_msec_t          start_time;
[166]     ngx_uint_t          requests;
[167] 
[168]     unsigned            buffered:8;
[169] 
[170]     unsigned            log_error:3;     /* ngx_connection_log_error_e */
[171] 
[172]     unsigned            timedout:1;
[173]     unsigned            error:1;
[174]     unsigned            destroyed:1;
[175]     unsigned            pipeline:1;
[176] 
[177]     unsigned            idle:1;
[178]     unsigned            reusable:1;
[179]     unsigned            close:1;
[180]     unsigned            shared:1;
[181] 
[182]     unsigned            sendfile:1;
[183]     unsigned            sndlowat:1;
[184]     unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
[185]     unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */
[186] 
[187]     unsigned            need_last_buf:1;
[188]     unsigned            need_flush_buf:1;
[189] 
[190] #if (NGX_HAVE_SENDFILE_NODISKIO || NGX_COMPAT)
[191]     unsigned            busy_count:2;
[192] #endif
[193] 
[194] #if (NGX_THREADS || NGX_COMPAT)
[195]     ngx_thread_task_t  *sendfile_task;
[196] #endif
[197] };
[198] 
[199] 
[200] #define ngx_set_connection_log(c, l)                                         \
[201]                                                                              \
[202]     c->log->file = l->file;                                                  \
[203]     c->log->next = l->next;                                                  \
[204]     c->log->writer = l->writer;                                              \
[205]     c->log->wdata = l->wdata;                                                \
[206]     if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
[207]         c->log->log_level = l->log_level;                                    \
[208]     }
[209] 
[210] 
[211] ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
[212]     socklen_t socklen);
[213] ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
[214] ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
[215] ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
[216] void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
[217] void ngx_close_listening_sockets(ngx_cycle_t *cycle);
[218] void ngx_close_connection(ngx_connection_t *c);
[219] void ngx_close_idle_connections(ngx_cycle_t *cycle);
[220] ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
[221]     ngx_uint_t port);
[222] ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
[223] ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);
[224] 
[225] ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
[226] void ngx_free_connection(ngx_connection_t *c);
[227] 
[228] void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);
[229] 
[230] #endif /* _NGX_CONNECTION_H_INCLUDED_ */
