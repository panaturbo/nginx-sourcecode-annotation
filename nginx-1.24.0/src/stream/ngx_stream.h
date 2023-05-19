[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STREAM_H_INCLUDED_
[9] #define _NGX_STREAM_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] #if (NGX_STREAM_SSL)
[16] #include <ngx_stream_ssl_module.h>
[17] #endif
[18] 
[19] 
[20] typedef struct ngx_stream_session_s  ngx_stream_session_t;
[21] 
[22] 
[23] #include <ngx_stream_variables.h>
[24] #include <ngx_stream_script.h>
[25] #include <ngx_stream_upstream.h>
[26] #include <ngx_stream_upstream_round_robin.h>
[27] 
[28] 
[29] #define NGX_STREAM_OK                        200
[30] #define NGX_STREAM_BAD_REQUEST               400
[31] #define NGX_STREAM_FORBIDDEN                 403
[32] #define NGX_STREAM_INTERNAL_SERVER_ERROR     500
[33] #define NGX_STREAM_BAD_GATEWAY               502
[34] #define NGX_STREAM_SERVICE_UNAVAILABLE       503
[35] 
[36] 
[37] typedef struct {
[38]     void                         **main_conf;
[39]     void                         **srv_conf;
[40] } ngx_stream_conf_ctx_t;
[41] 
[42] 
[43] typedef struct {
[44]     struct sockaddr               *sockaddr;
[45]     socklen_t                      socklen;
[46]     ngx_str_t                      addr_text;
[47] 
[48]     /* server ctx */
[49]     ngx_stream_conf_ctx_t         *ctx;
[50] 
[51]     unsigned                       bind:1;
[52]     unsigned                       wildcard:1;
[53]     unsigned                       ssl:1;
[54] #if (NGX_HAVE_INET6)
[55]     unsigned                       ipv6only:1;
[56] #endif
[57]     unsigned                       reuseport:1;
[58]     unsigned                       so_keepalive:2;
[59]     unsigned                       proxy_protocol:1;
[60] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[61]     int                            tcp_keepidle;
[62]     int                            tcp_keepintvl;
[63]     int                            tcp_keepcnt;
[64] #endif
[65]     int                            backlog;
[66]     int                            rcvbuf;
[67]     int                            sndbuf;
[68] #if (NGX_HAVE_TCP_FASTOPEN)
[69]     int                            fastopen;
[70] #endif
[71]     int                            type;
[72] } ngx_stream_listen_t;
[73] 
[74] 
[75] typedef struct {
[76]     ngx_stream_conf_ctx_t         *ctx;
[77]     ngx_str_t                      addr_text;
[78]     unsigned                       ssl:1;
[79]     unsigned                       proxy_protocol:1;
[80] } ngx_stream_addr_conf_t;
[81] 
[82] typedef struct {
[83]     in_addr_t                      addr;
[84]     ngx_stream_addr_conf_t         conf;
[85] } ngx_stream_in_addr_t;
[86] 
[87] 
[88] #if (NGX_HAVE_INET6)
[89] 
[90] typedef struct {
[91]     struct in6_addr                addr6;
[92]     ngx_stream_addr_conf_t         conf;
[93] } ngx_stream_in6_addr_t;
[94] 
[95] #endif
[96] 
[97] 
[98] typedef struct {
[99]     /* ngx_stream_in_addr_t or ngx_stream_in6_addr_t */
[100]     void                          *addrs;
[101]     ngx_uint_t                     naddrs;
[102] } ngx_stream_port_t;
[103] 
[104] 
[105] typedef struct {
[106]     int                            family;
[107]     int                            type;
[108]     in_port_t                      port;
[109]     ngx_array_t                    addrs; /* array of ngx_stream_conf_addr_t */
[110] } ngx_stream_conf_port_t;
[111] 
[112] 
[113] typedef struct {
[114]     ngx_stream_listen_t            opt;
[115] } ngx_stream_conf_addr_t;
[116] 
[117] 
[118] typedef enum {
[119]     NGX_STREAM_POST_ACCEPT_PHASE = 0,
[120]     NGX_STREAM_PREACCESS_PHASE,
[121]     NGX_STREAM_ACCESS_PHASE,
[122]     NGX_STREAM_SSL_PHASE,
[123]     NGX_STREAM_PREREAD_PHASE,
[124]     NGX_STREAM_CONTENT_PHASE,
[125]     NGX_STREAM_LOG_PHASE
[126] } ngx_stream_phases;
[127] 
[128] 
[129] typedef struct ngx_stream_phase_handler_s  ngx_stream_phase_handler_t;
[130] 
[131] typedef ngx_int_t (*ngx_stream_phase_handler_pt)(ngx_stream_session_t *s,
[132]     ngx_stream_phase_handler_t *ph);
[133] typedef ngx_int_t (*ngx_stream_handler_pt)(ngx_stream_session_t *s);
[134] typedef void (*ngx_stream_content_handler_pt)(ngx_stream_session_t *s);
[135] 
[136] 
[137] struct ngx_stream_phase_handler_s {
[138]     ngx_stream_phase_handler_pt    checker;
[139]     ngx_stream_handler_pt          handler;
[140]     ngx_uint_t                     next;
[141] };
[142] 
[143] 
[144] typedef struct {
[145]     ngx_stream_phase_handler_t    *handlers;
[146] } ngx_stream_phase_engine_t;
[147] 
[148] 
[149] typedef struct {
[150]     ngx_array_t                    handlers;
[151] } ngx_stream_phase_t;
[152] 
[153] 
[154] typedef struct {
[155]     ngx_array_t                    servers;     /* ngx_stream_core_srv_conf_t */
[156]     ngx_array_t                    listen;      /* ngx_stream_listen_t */
[157] 
[158]     ngx_stream_phase_engine_t      phase_engine;
[159] 
[160]     ngx_hash_t                     variables_hash;
[161] 
[162]     ngx_array_t                    variables;        /* ngx_stream_variable_t */
[163]     ngx_array_t                    prefix_variables; /* ngx_stream_variable_t */
[164]     ngx_uint_t                     ncaptures;
[165] 
[166]     ngx_uint_t                     variables_hash_max_size;
[167]     ngx_uint_t                     variables_hash_bucket_size;
[168] 
[169]     ngx_hash_keys_arrays_t        *variables_keys;
[170] 
[171]     ngx_stream_phase_t             phases[NGX_STREAM_LOG_PHASE + 1];
[172] } ngx_stream_core_main_conf_t;
[173] 
[174] 
[175] typedef struct {
[176]     ngx_stream_content_handler_pt  handler;
[177] 
[178]     ngx_stream_conf_ctx_t         *ctx;
[179] 
[180]     u_char                        *file_name;
[181]     ngx_uint_t                     line;
[182] 
[183]     ngx_flag_t                     tcp_nodelay;
[184]     size_t                         preread_buffer_size;
[185]     ngx_msec_t                     preread_timeout;
[186] 
[187]     ngx_log_t                     *error_log;
[188] 
[189]     ngx_msec_t                     resolver_timeout;
[190]     ngx_resolver_t                *resolver;
[191] 
[192]     ngx_msec_t                     proxy_protocol_timeout;
[193] 
[194]     ngx_uint_t                     listen;  /* unsigned  listen:1; */
[195] } ngx_stream_core_srv_conf_t;
[196] 
[197] 
[198] struct ngx_stream_session_s {
[199]     uint32_t                       signature;         /* "STRM" */
[200] 
[201]     ngx_connection_t              *connection;
[202] 
[203]     off_t                          received;
[204]     time_t                         start_sec;
[205]     ngx_msec_t                     start_msec;
[206] 
[207]     ngx_log_handler_pt             log_handler;
[208] 
[209]     void                         **ctx;
[210]     void                         **main_conf;
[211]     void                         **srv_conf;
[212] 
[213]     ngx_stream_upstream_t         *upstream;
[214]     ngx_array_t                   *upstream_states;
[215]                                            /* of ngx_stream_upstream_state_t */
[216]     ngx_stream_variable_value_t   *variables;
[217] 
[218] #if (NGX_PCRE)
[219]     ngx_uint_t                     ncaptures;
[220]     int                           *captures;
[221]     u_char                        *captures_data;
[222] #endif
[223] 
[224]     ngx_int_t                      phase_handler;
[225]     ngx_uint_t                     status;
[226] 
[227]     unsigned                       ssl:1;
[228] 
[229]     unsigned                       stat_processing:1;
[230] 
[231]     unsigned                       health_check:1;
[232] 
[233]     unsigned                       limit_conn_status:2;
[234] };
[235] 
[236] 
[237] typedef struct {
[238]     ngx_int_t                    (*preconfiguration)(ngx_conf_t *cf);
[239]     ngx_int_t                    (*postconfiguration)(ngx_conf_t *cf);
[240] 
[241]     void                        *(*create_main_conf)(ngx_conf_t *cf);
[242]     char                        *(*init_main_conf)(ngx_conf_t *cf, void *conf);
[243] 
[244]     void                        *(*create_srv_conf)(ngx_conf_t *cf);
[245]     char                        *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
[246]                                                    void *conf);
[247] } ngx_stream_module_t;
[248] 
[249] 
[250] #define NGX_STREAM_MODULE       0x4d525453     /* "STRM" */
[251] 
[252] #define NGX_STREAM_MAIN_CONF    0x02000000
[253] #define NGX_STREAM_SRV_CONF     0x04000000
[254] #define NGX_STREAM_UPS_CONF     0x08000000
[255] 
[256] 
[257] #define NGX_STREAM_MAIN_CONF_OFFSET  offsetof(ngx_stream_conf_ctx_t, main_conf)
[258] #define NGX_STREAM_SRV_CONF_OFFSET   offsetof(ngx_stream_conf_ctx_t, srv_conf)
[259] 
[260] 
[261] #define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
[262] #define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
[263] #define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;
[264] 
[265] 
[266] #define ngx_stream_get_module_main_conf(s, module)                             \
[267]     (s)->main_conf[module.ctx_index]
[268] #define ngx_stream_get_module_srv_conf(s, module)                              \
[269]     (s)->srv_conf[module.ctx_index]
[270] 
[271] #define ngx_stream_conf_get_module_main_conf(cf, module)                       \
[272]     ((ngx_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
[273] #define ngx_stream_conf_get_module_srv_conf(cf, module)                        \
[274]     ((ngx_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
[275] 
[276] #define ngx_stream_cycle_get_module_main_conf(cycle, module)                   \
[277]     (cycle->conf_ctx[ngx_stream_module.index] ?                                \
[278]         ((ngx_stream_conf_ctx_t *) cycle->conf_ctx[ngx_stream_module.index])   \
[279]             ->main_conf[module.ctx_index]:                                     \
[280]         NULL)
[281] 
[282] 
[283] #define NGX_STREAM_WRITE_BUFFERED  0x10
[284] 
[285] 
[286] void ngx_stream_core_run_phases(ngx_stream_session_t *s);
[287] ngx_int_t ngx_stream_core_generic_phase(ngx_stream_session_t *s,
[288]     ngx_stream_phase_handler_t *ph);
[289] ngx_int_t ngx_stream_core_preread_phase(ngx_stream_session_t *s,
[290]     ngx_stream_phase_handler_t *ph);
[291] ngx_int_t ngx_stream_core_content_phase(ngx_stream_session_t *s,
[292]     ngx_stream_phase_handler_t *ph);
[293] 
[294] 
[295] void ngx_stream_init_connection(ngx_connection_t *c);
[296] void ngx_stream_session_handler(ngx_event_t *rev);
[297] void ngx_stream_finalize_session(ngx_stream_session_t *s, ngx_uint_t rc);
[298] 
[299] 
[300] extern ngx_module_t  ngx_stream_module;
[301] extern ngx_uint_t    ngx_stream_max_module;
[302] extern ngx_module_t  ngx_stream_core_module;
[303] 
[304] 
[305] typedef ngx_int_t (*ngx_stream_filter_pt)(ngx_stream_session_t *s,
[306]     ngx_chain_t *chain, ngx_uint_t from_upstream);
[307] 
[308] 
[309] extern ngx_stream_filter_pt  ngx_stream_top_filter;
[310] 
[311] 
[312] #endif /* _NGX_STREAM_H_INCLUDED_ */
