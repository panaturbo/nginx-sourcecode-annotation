[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
[9] #define _NGX_HTTP_UPSTREAM_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] #include <ngx_event_connect.h>
[16] #include <ngx_event_pipe.h>
[17] #include <ngx_http.h>
[18] 
[19] 
[20] #define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
[21] #define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
[22] #define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
[23] #define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
[24] #define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
[25] #define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
[26] #define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
[27] #define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
[28] #define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
[29] #define NGX_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
[30] #define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000800
[31] #define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
[32] #define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
[33] #define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
[34] #define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
[35] #define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000
[36] 
[37] #define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
[38]                                              |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
[39]                                              |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
[40]                                              |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
[41]                                              |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
[42]                                              |NGX_HTTP_UPSTREAM_FT_HTTP_404  \
[43]                                              |NGX_HTTP_UPSTREAM_FT_HTTP_429)
[44] 
[45] #define NGX_HTTP_UPSTREAM_INVALID_HEADER     40
[46] 
[47] 
[48] #define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
[49] #define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
[50] #define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
[51] #define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
[52] #define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
[53] #define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
[54] #define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
[55] #define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
[56] #define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200
[57] 
[58] 
[59] typedef struct {
[60]     ngx_uint_t                       status;
[61]     ngx_msec_t                       response_time;
[62]     ngx_msec_t                       connect_time;
[63]     ngx_msec_t                       header_time;
[64]     ngx_msec_t                       queue_time;
[65]     off_t                            response_length;
[66]     off_t                            bytes_received;
[67]     off_t                            bytes_sent;
[68] 
[69]     ngx_str_t                       *peer;
[70] } ngx_http_upstream_state_t;
[71] 
[72] 
[73] typedef struct {
[74]     ngx_hash_t                       headers_in_hash;
[75]     ngx_array_t                      upstreams;
[76]                                              /* ngx_http_upstream_srv_conf_t */
[77] } ngx_http_upstream_main_conf_t;
[78] 
[79] typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;
[80] 
[81] typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
[82]     ngx_http_upstream_srv_conf_t *us);
[83] typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
[84]     ngx_http_upstream_srv_conf_t *us);
[85] 
[86] 
[87] typedef struct {
[88]     ngx_http_upstream_init_pt        init_upstream;
[89]     ngx_http_upstream_init_peer_pt   init;
[90]     void                            *data;
[91] } ngx_http_upstream_peer_t;
[92] 
[93] 
[94] typedef struct {
[95]     ngx_str_t                        name;
[96]     ngx_addr_t                      *addrs;
[97]     ngx_uint_t                       naddrs;
[98]     ngx_uint_t                       weight;
[99]     ngx_uint_t                       max_conns;
[100]     ngx_uint_t                       max_fails;
[101]     time_t                           fail_timeout;
[102]     ngx_msec_t                       slow_start;
[103]     ngx_uint_t                       down;
[104] 
[105]     unsigned                         backup:1;
[106] 
[107]     NGX_COMPAT_BEGIN(6)
[108]     NGX_COMPAT_END
[109] } ngx_http_upstream_server_t;
[110] 
[111] 
[112] #define NGX_HTTP_UPSTREAM_CREATE        0x0001
[113] #define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
[114] #define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
[115] #define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
[116] #define NGX_HTTP_UPSTREAM_DOWN          0x0010
[117] #define NGX_HTTP_UPSTREAM_BACKUP        0x0020
[118] #define NGX_HTTP_UPSTREAM_MAX_CONNS     0x0100
[119] 
[120] 
[121] struct ngx_http_upstream_srv_conf_s {
[122]     ngx_http_upstream_peer_t         peer;
[123]     void                           **srv_conf;
[124] 
[125]     ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */
[126] 
[127]     ngx_uint_t                       flags;
[128]     ngx_str_t                        host;
[129]     u_char                          *file_name;
[130]     ngx_uint_t                       line;
[131]     in_port_t                        port;
[132]     ngx_uint_t                       no_port;  /* unsigned no_port:1 */
[133] 
[134] #if (NGX_HTTP_UPSTREAM_ZONE)
[135]     ngx_shm_zone_t                  *shm_zone;
[136] #endif
[137] };
[138] 
[139] 
[140] typedef struct {
[141]     ngx_addr_t                      *addr;
[142]     ngx_http_complex_value_t        *value;
[143] #if (NGX_HAVE_TRANSPARENT_PROXY)
[144]     ngx_uint_t                       transparent; /* unsigned  transparent:1; */
[145] #endif
[146] } ngx_http_upstream_local_t;
[147] 
[148] 
[149] typedef struct {
[150]     ngx_http_upstream_srv_conf_t    *upstream;
[151] 
[152]     ngx_msec_t                       connect_timeout;
[153]     ngx_msec_t                       send_timeout;
[154]     ngx_msec_t                       read_timeout;
[155]     ngx_msec_t                       next_upstream_timeout;
[156] 
[157]     size_t                           send_lowat;
[158]     size_t                           buffer_size;
[159]     size_t                           limit_rate;
[160] 
[161]     size_t                           busy_buffers_size;
[162]     size_t                           max_temp_file_size;
[163]     size_t                           temp_file_write_size;
[164] 
[165]     size_t                           busy_buffers_size_conf;
[166]     size_t                           max_temp_file_size_conf;
[167]     size_t                           temp_file_write_size_conf;
[168] 
[169]     ngx_bufs_t                       bufs;
[170] 
[171]     ngx_uint_t                       ignore_headers;
[172]     ngx_uint_t                       next_upstream;
[173]     ngx_uint_t                       store_access;
[174]     ngx_uint_t                       next_upstream_tries;
[175]     ngx_flag_t                       buffering;
[176]     ngx_flag_t                       request_buffering;
[177]     ngx_flag_t                       pass_request_headers;
[178]     ngx_flag_t                       pass_request_body;
[179] 
[180]     ngx_flag_t                       ignore_client_abort;
[181]     ngx_flag_t                       intercept_errors;
[182]     ngx_flag_t                       cyclic_temp_file;
[183]     ngx_flag_t                       force_ranges;
[184] 
[185]     ngx_path_t                      *temp_path;
[186] 
[187]     ngx_hash_t                       hide_headers_hash;
[188]     ngx_array_t                     *hide_headers;
[189]     ngx_array_t                     *pass_headers;
[190] 
[191]     ngx_http_upstream_local_t       *local;
[192]     ngx_flag_t                       socket_keepalive;
[193] 
[194] #if (NGX_HTTP_CACHE)
[195]     ngx_shm_zone_t                  *cache_zone;
[196]     ngx_http_complex_value_t        *cache_value;
[197] 
[198]     ngx_uint_t                       cache_min_uses;
[199]     ngx_uint_t                       cache_use_stale;
[200]     ngx_uint_t                       cache_methods;
[201] 
[202]     off_t                            cache_max_range_offset;
[203] 
[204]     ngx_flag_t                       cache_lock;
[205]     ngx_msec_t                       cache_lock_timeout;
[206]     ngx_msec_t                       cache_lock_age;
[207] 
[208]     ngx_flag_t                       cache_revalidate;
[209]     ngx_flag_t                       cache_convert_head;
[210]     ngx_flag_t                       cache_background_update;
[211] 
[212]     ngx_array_t                     *cache_valid;
[213]     ngx_array_t                     *cache_bypass;
[214]     ngx_array_t                     *cache_purge;
[215]     ngx_array_t                     *no_cache;
[216] #endif
[217] 
[218]     ngx_array_t                     *store_lengths;
[219]     ngx_array_t                     *store_values;
[220] 
[221] #if (NGX_HTTP_CACHE)
[222]     signed                           cache:2;
[223] #endif
[224]     signed                           store:2;
[225]     unsigned                         intercept_404:1;
[226]     unsigned                         change_buffering:1;
[227]     unsigned                         pass_trailers:1;
[228]     unsigned                         preserve_output:1;
[229] 
[230] #if (NGX_HTTP_SSL || NGX_COMPAT)
[231]     ngx_ssl_t                       *ssl;
[232]     ngx_flag_t                       ssl_session_reuse;
[233] 
[234]     ngx_http_complex_value_t        *ssl_name;
[235]     ngx_flag_t                       ssl_server_name;
[236]     ngx_flag_t                       ssl_verify;
[237] 
[238]     ngx_http_complex_value_t        *ssl_certificate;
[239]     ngx_http_complex_value_t        *ssl_certificate_key;
[240]     ngx_array_t                     *ssl_passwords;
[241] #endif
[242] 
[243]     ngx_str_t                        module;
[244] 
[245]     NGX_COMPAT_BEGIN(2)
[246]     NGX_COMPAT_END
[247] } ngx_http_upstream_conf_t;
[248] 
[249] 
[250] typedef struct {
[251]     ngx_str_t                        name;
[252]     ngx_http_header_handler_pt       handler;
[253]     ngx_uint_t                       offset;
[254]     ngx_http_header_handler_pt       copy_handler;
[255]     ngx_uint_t                       conf;
[256]     ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
[257] } ngx_http_upstream_header_t;
[258] 
[259] 
[260] typedef struct {
[261]     ngx_list_t                       headers;
[262]     ngx_list_t                       trailers;
[263] 
[264]     ngx_uint_t                       status_n;
[265]     ngx_str_t                        status_line;
[266] 
[267]     ngx_table_elt_t                 *status;
[268]     ngx_table_elt_t                 *date;
[269]     ngx_table_elt_t                 *server;
[270]     ngx_table_elt_t                 *connection;
[271] 
[272]     ngx_table_elt_t                 *expires;
[273]     ngx_table_elt_t                 *etag;
[274]     ngx_table_elt_t                 *x_accel_expires;
[275]     ngx_table_elt_t                 *x_accel_redirect;
[276]     ngx_table_elt_t                 *x_accel_limit_rate;
[277] 
[278]     ngx_table_elt_t                 *content_type;
[279]     ngx_table_elt_t                 *content_length;
[280] 
[281]     ngx_table_elt_t                 *last_modified;
[282]     ngx_table_elt_t                 *location;
[283]     ngx_table_elt_t                 *refresh;
[284]     ngx_table_elt_t                 *www_authenticate;
[285]     ngx_table_elt_t                 *transfer_encoding;
[286]     ngx_table_elt_t                 *vary;
[287] 
[288]     ngx_table_elt_t                 *cache_control;
[289]     ngx_table_elt_t                 *set_cookie;
[290] 
[291]     off_t                            content_length_n;
[292]     time_t                           last_modified_time;
[293] 
[294]     unsigned                         connection_close:1;
[295]     unsigned                         chunked:1;
[296]     unsigned                         no_cache:1;
[297]     unsigned                         expired:1;
[298] } ngx_http_upstream_headers_in_t;
[299] 
[300] 
[301] typedef struct {
[302]     ngx_str_t                        host;
[303]     in_port_t                        port;
[304]     ngx_uint_t                       no_port; /* unsigned no_port:1 */
[305] 
[306]     ngx_uint_t                       naddrs;
[307]     ngx_resolver_addr_t             *addrs;
[308] 
[309]     struct sockaddr                 *sockaddr;
[310]     socklen_t                        socklen;
[311]     ngx_str_t                        name;
[312] 
[313]     ngx_resolver_ctx_t              *ctx;
[314] } ngx_http_upstream_resolved_t;
[315] 
[316] 
[317] typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
[318]     ngx_http_upstream_t *u);
[319] 
[320] 
[321] struct ngx_http_upstream_s {
[322]     ngx_http_upstream_handler_pt     read_event_handler;
[323]     ngx_http_upstream_handler_pt     write_event_handler;
[324] 
[325]     ngx_peer_connection_t            peer;
[326] 
[327]     ngx_event_pipe_t                *pipe;
[328] 
[329]     ngx_chain_t                     *request_bufs;
[330] 
[331]     ngx_output_chain_ctx_t           output;
[332]     ngx_chain_writer_ctx_t           writer;
[333] 
[334]     ngx_http_upstream_conf_t        *conf;
[335]     ngx_http_upstream_srv_conf_t    *upstream;
[336] #if (NGX_HTTP_CACHE)
[337]     ngx_array_t                     *caches;
[338] #endif
[339] 
[340]     ngx_http_upstream_headers_in_t   headers_in;
[341] 
[342]     ngx_http_upstream_resolved_t    *resolved;
[343] 
[344]     ngx_buf_t                        from_client;
[345] 
[346]     ngx_buf_t                        buffer;
[347]     off_t                            length;
[348] 
[349]     ngx_chain_t                     *out_bufs;
[350]     ngx_chain_t                     *busy_bufs;
[351]     ngx_chain_t                     *free_bufs;
[352] 
[353]     ngx_int_t                      (*input_filter_init)(void *data);
[354]     ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
[355]     void                            *input_filter_ctx;
[356] 
[357] #if (NGX_HTTP_CACHE)
[358]     ngx_int_t                      (*create_key)(ngx_http_request_t *r);
[359] #endif
[360]     ngx_int_t                      (*create_request)(ngx_http_request_t *r);
[361]     ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
[362]     ngx_int_t                      (*process_header)(ngx_http_request_t *r);
[363]     void                           (*abort_request)(ngx_http_request_t *r);
[364]     void                           (*finalize_request)(ngx_http_request_t *r,
[365]                                          ngx_int_t rc);
[366]     ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
[367]                                          ngx_table_elt_t *h, size_t prefix);
[368]     ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
[369]                                          ngx_table_elt_t *h);
[370] 
[371]     ngx_msec_t                       start_time;
[372] 
[373]     ngx_http_upstream_state_t       *state;
[374] 
[375]     ngx_str_t                        method;
[376]     ngx_str_t                        schema;
[377]     ngx_str_t                        uri;
[378] 
[379] #if (NGX_HTTP_SSL || NGX_COMPAT)
[380]     ngx_str_t                        ssl_name;
[381] #endif
[382] 
[383]     ngx_http_cleanup_pt             *cleanup;
[384] 
[385]     unsigned                         store:1;
[386]     unsigned                         cacheable:1;
[387]     unsigned                         accel:1;
[388]     unsigned                         ssl:1;
[389] #if (NGX_HTTP_CACHE)
[390]     unsigned                         cache_status:3;
[391] #endif
[392] 
[393]     unsigned                         buffering:1;
[394]     unsigned                         keepalive:1;
[395]     unsigned                         upgrade:1;
[396]     unsigned                         error:1;
[397] 
[398]     unsigned                         request_sent:1;
[399]     unsigned                         request_body_sent:1;
[400]     unsigned                         request_body_blocked:1;
[401]     unsigned                         header_sent:1;
[402] };
[403] 
[404] 
[405] typedef struct {
[406]     ngx_uint_t                      status;
[407]     ngx_uint_t                      mask;
[408] } ngx_http_upstream_next_t;
[409] 
[410] 
[411] typedef struct {
[412]     ngx_str_t   key;
[413]     ngx_str_t   value;
[414]     ngx_uint_t  skip_empty;
[415] } ngx_http_upstream_param_t;
[416] 
[417] 
[418] ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
[419] void ngx_http_upstream_init(ngx_http_request_t *r);
[420] ngx_int_t ngx_http_upstream_non_buffered_filter_init(void *data);
[421] ngx_int_t ngx_http_upstream_non_buffered_filter(void *data, ssize_t bytes);
[422] ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
[423]     ngx_url_t *u, ngx_uint_t flags);
[424] char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[425]     void *conf);
[426] char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[427]     void *conf);
[428] ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
[429]     ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
[430]     ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);
[431] 
[432] 
[433] #define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
[434]     uscf->srv_conf[module.ctx_index]
[435] 
[436] 
[437] extern ngx_module_t        ngx_http_upstream_module;
[438] extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
[439] extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];
[440] 
[441] 
[442] #endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
