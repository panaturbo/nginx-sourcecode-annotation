[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
[9] #define _NGX_EVENT_CONNECT_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] 
[16] 
[17] #define NGX_PEER_KEEPALIVE           1
[18] #define NGX_PEER_NEXT                2
[19] #define NGX_PEER_FAILED              4
[20] 
[21] 
[22] typedef struct ngx_peer_connection_s  ngx_peer_connection_t;
[23] 
[24] typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
[25]     void *data);
[26] typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
[27]     ngx_uint_t state);
[28] typedef void (*ngx_event_notify_peer_pt)(ngx_peer_connection_t *pc,
[29]     void *data, ngx_uint_t type);
[30] typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
[31]     void *data);
[32] typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
[33]     void *data);
[34] 
[35] 
[36] struct ngx_peer_connection_s {
[37]     ngx_connection_t                *connection;
[38] 
[39]     struct sockaddr                 *sockaddr;
[40]     socklen_t                        socklen;
[41]     ngx_str_t                       *name;
[42] 
[43]     ngx_uint_t                       tries;
[44]     ngx_msec_t                       start_time;
[45] 
[46]     ngx_event_get_peer_pt            get;
[47]     ngx_event_free_peer_pt           free;
[48]     ngx_event_notify_peer_pt         notify;
[49]     void                            *data;
[50] 
[51] #if (NGX_SSL || NGX_COMPAT)
[52]     ngx_event_set_peer_session_pt    set_session;
[53]     ngx_event_save_peer_session_pt   save_session;
[54] #endif
[55] 
[56]     ngx_addr_t                      *local;
[57] 
[58]     int                              type;
[59]     int                              rcvbuf;
[60] 
[61]     ngx_log_t                       *log;
[62] 
[63]     unsigned                         cached:1;
[64]     unsigned                         transparent:1;
[65]     unsigned                         so_keepalive:1;
[66]     unsigned                         down:1;
[67] 
[68]                                      /* ngx_connection_log_error_e */
[69]     unsigned                         log_error:2;
[70] 
[71]     NGX_COMPAT_BEGIN(2)
[72]     NGX_COMPAT_END
[73] };
[74] 
[75] 
[76] ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
[77] ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);
[78] 
[79] 
[80] #endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
