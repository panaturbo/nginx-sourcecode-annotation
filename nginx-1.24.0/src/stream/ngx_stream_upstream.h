[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STREAM_UPSTREAM_H_INCLUDED_
[9] #define _NGX_STREAM_UPSTREAM_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_stream.h>
[15] #include <ngx_event_connect.h>
[16] 
[17] 
[18] #define NGX_STREAM_UPSTREAM_CREATE        0x0001
[19] #define NGX_STREAM_UPSTREAM_WEIGHT        0x0002
[20] #define NGX_STREAM_UPSTREAM_MAX_FAILS     0x0004
[21] #define NGX_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
[22] #define NGX_STREAM_UPSTREAM_DOWN          0x0010
[23] #define NGX_STREAM_UPSTREAM_BACKUP        0x0020
[24] #define NGX_STREAM_UPSTREAM_MAX_CONNS     0x0100
[25] 
[26] 
[27] #define NGX_STREAM_UPSTREAM_NOTIFY_CONNECT     0x1
[28] 
[29] 
[30] typedef struct {
[31]     ngx_array_t                        upstreams;
[32]                                            /* ngx_stream_upstream_srv_conf_t */
[33] } ngx_stream_upstream_main_conf_t;
[34] 
[35] 
[36] typedef struct ngx_stream_upstream_srv_conf_s  ngx_stream_upstream_srv_conf_t;
[37] 
[38] 
[39] typedef ngx_int_t (*ngx_stream_upstream_init_pt)(ngx_conf_t *cf,
[40]     ngx_stream_upstream_srv_conf_t *us);
[41] typedef ngx_int_t (*ngx_stream_upstream_init_peer_pt)(ngx_stream_session_t *s,
[42]     ngx_stream_upstream_srv_conf_t *us);
[43] 
[44] 
[45] typedef struct {
[46]     ngx_stream_upstream_init_pt        init_upstream;
[47]     ngx_stream_upstream_init_peer_pt   init;
[48]     void                              *data;
[49] } ngx_stream_upstream_peer_t;
[50] 
[51] 
[52] typedef struct {
[53]     ngx_str_t                          name;
[54]     ngx_addr_t                        *addrs;
[55]     ngx_uint_t                         naddrs;
[56]     ngx_uint_t                         weight;
[57]     ngx_uint_t                         max_conns;
[58]     ngx_uint_t                         max_fails;
[59]     time_t                             fail_timeout;
[60]     ngx_msec_t                         slow_start;
[61]     ngx_uint_t                         down;
[62] 
[63]     unsigned                           backup:1;
[64] 
[65]     NGX_COMPAT_BEGIN(4)
[66]     NGX_COMPAT_END
[67] } ngx_stream_upstream_server_t;
[68] 
[69] 
[70] struct ngx_stream_upstream_srv_conf_s {
[71]     ngx_stream_upstream_peer_t         peer;
[72]     void                             **srv_conf;
[73] 
[74]     ngx_array_t                       *servers;
[75]                                               /* ngx_stream_upstream_server_t */
[76] 
[77]     ngx_uint_t                         flags;
[78]     ngx_str_t                          host;
[79]     u_char                            *file_name;
[80]     ngx_uint_t                         line;
[81]     in_port_t                          port;
[82]     ngx_uint_t                         no_port;  /* unsigned no_port:1 */
[83] 
[84] #if (NGX_STREAM_UPSTREAM_ZONE)
[85]     ngx_shm_zone_t                    *shm_zone;
[86] #endif
[87] };
[88] 
[89] 
[90] typedef struct {
[91]     ngx_msec_t                         response_time;
[92]     ngx_msec_t                         connect_time;
[93]     ngx_msec_t                         first_byte_time;
[94]     off_t                              bytes_sent;
[95]     off_t                              bytes_received;
[96] 
[97]     ngx_str_t                         *peer;
[98] } ngx_stream_upstream_state_t;
[99] 
[100] 
[101] typedef struct {
[102]     ngx_str_t                          host;
[103]     in_port_t                          port;
[104]     ngx_uint_t                         no_port; /* unsigned no_port:1 */
[105] 
[106]     ngx_uint_t                         naddrs;
[107]     ngx_resolver_addr_t               *addrs;
[108] 
[109]     struct sockaddr                   *sockaddr;
[110]     socklen_t                          socklen;
[111]     ngx_str_t                          name;
[112] 
[113]     ngx_resolver_ctx_t                *ctx;
[114] } ngx_stream_upstream_resolved_t;
[115] 
[116] 
[117] typedef struct {
[118]     ngx_peer_connection_t              peer;
[119] 
[120]     ngx_buf_t                          downstream_buf;
[121]     ngx_buf_t                          upstream_buf;
[122] 
[123]     ngx_chain_t                       *free;
[124]     ngx_chain_t                       *upstream_out;
[125]     ngx_chain_t                       *upstream_busy;
[126]     ngx_chain_t                       *downstream_out;
[127]     ngx_chain_t                       *downstream_busy;
[128] 
[129]     off_t                              received;
[130]     time_t                             start_sec;
[131]     ngx_uint_t                         requests;
[132]     ngx_uint_t                         responses;
[133]     ngx_msec_t                         start_time;
[134] 
[135]     size_t                             upload_rate;
[136]     size_t                             download_rate;
[137] 
[138]     ngx_str_t                          ssl_name;
[139] 
[140]     ngx_stream_upstream_srv_conf_t    *upstream;
[141]     ngx_stream_upstream_resolved_t    *resolved;
[142]     ngx_stream_upstream_state_t       *state;
[143]     unsigned                           connected:1;
[144]     unsigned                           proxy_protocol:1;
[145]     unsigned                           half_closed:1;
[146] } ngx_stream_upstream_t;
[147] 
[148] 
[149] ngx_stream_upstream_srv_conf_t *ngx_stream_upstream_add(ngx_conf_t *cf,
[150]     ngx_url_t *u, ngx_uint_t flags);
[151] 
[152] 
[153] #define ngx_stream_conf_upstream_srv_conf(uscf, module)                       \
[154]     uscf->srv_conf[module.ctx_index]
[155] 
[156] 
[157] extern ngx_module_t  ngx_stream_upstream_module;
[158] 
[159] 
[160] #endif /* _NGX_STREAM_UPSTREAM_H_INCLUDED_ */
