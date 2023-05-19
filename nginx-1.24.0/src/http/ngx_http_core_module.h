[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_CORE_H_INCLUDED_
[9] #define _NGX_HTTP_CORE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] #if (NGX_THREADS)
[17] #include <ngx_thread_pool.h>
[18] #elif (NGX_COMPAT)
[19] typedef struct ngx_thread_pool_s  ngx_thread_pool_t;
[20] #endif
[21] 
[22] 
[23] #define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
[24] #define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
[25] #define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
[26] #define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
[27] #define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
[28] #define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
[29] #define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
[30] #define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
[31] #define NGX_HTTP_GZIP_PROXIED_ANY       0x0200
[32] 
[33] 
[34] #define NGX_HTTP_AIO_OFF                0
[35] #define NGX_HTTP_AIO_ON                 1
[36] #define NGX_HTTP_AIO_THREADS            2
[37] 
[38] 
[39] #define NGX_HTTP_SATISFY_ALL            0
[40] #define NGX_HTTP_SATISFY_ANY            1
[41] 
[42] 
[43] #define NGX_HTTP_LINGERING_OFF          0
[44] #define NGX_HTTP_LINGERING_ON           1
[45] #define NGX_HTTP_LINGERING_ALWAYS       2
[46] 
[47] 
[48] #define NGX_HTTP_IMS_OFF                0
[49] #define NGX_HTTP_IMS_EXACT              1
[50] #define NGX_HTTP_IMS_BEFORE             2
[51] 
[52] 
[53] #define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
[54] #define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
[55] #define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008
[56] 
[57] 
[58] #define NGX_HTTP_SERVER_TOKENS_OFF      0
[59] #define NGX_HTTP_SERVER_TOKENS_ON       1
[60] #define NGX_HTTP_SERVER_TOKENS_BUILD    2
[61] 
[62] 
[63] typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
[64] typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;
[65] 
[66] 
[67] typedef struct {
[68]     struct sockaddr           *sockaddr;
[69]     socklen_t                  socklen;
[70]     ngx_str_t                  addr_text;
[71] 
[72]     unsigned                   set:1;
[73]     unsigned                   default_server:1;
[74]     unsigned                   bind:1;
[75]     unsigned                   wildcard:1;
[76]     unsigned                   ssl:1;
[77]     unsigned                   http2:1;
[78] #if (NGX_HAVE_INET6)
[79]     unsigned                   ipv6only:1;
[80] #endif
[81]     unsigned                   deferred_accept:1;
[82]     unsigned                   reuseport:1;
[83]     unsigned                   so_keepalive:2;
[84]     unsigned                   proxy_protocol:1;
[85] 
[86]     int                        backlog;
[87]     int                        rcvbuf;
[88]     int                        sndbuf;
[89] #if (NGX_HAVE_SETFIB)
[90]     int                        setfib;
[91] #endif
[92] #if (NGX_HAVE_TCP_FASTOPEN)
[93]     int                        fastopen;
[94] #endif
[95] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[96]     int                        tcp_keepidle;
[97]     int                        tcp_keepintvl;
[98]     int                        tcp_keepcnt;
[99] #endif
[100] 
[101] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[102]     char                      *accept_filter;
[103] #endif
[104] } ngx_http_listen_opt_t;
[105] 
[106] 
[107] typedef enum {
[108]     NGX_HTTP_POST_READ_PHASE = 0,
[109] 
[110]     NGX_HTTP_SERVER_REWRITE_PHASE,
[111] 
[112]     NGX_HTTP_FIND_CONFIG_PHASE,
[113]     NGX_HTTP_REWRITE_PHASE,
[114]     NGX_HTTP_POST_REWRITE_PHASE,
[115] 
[116]     NGX_HTTP_PREACCESS_PHASE,
[117] 
[118]     NGX_HTTP_ACCESS_PHASE,
[119]     NGX_HTTP_POST_ACCESS_PHASE,
[120] 
[121]     NGX_HTTP_PRECONTENT_PHASE,
[122] 
[123]     NGX_HTTP_CONTENT_PHASE,
[124] 
[125]     NGX_HTTP_LOG_PHASE
[126] } ngx_http_phases;
[127] 
[128] typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;
[129] 
[130] typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
[131]     ngx_http_phase_handler_t *ph);
[132] 
[133] struct ngx_http_phase_handler_s {
[134]     ngx_http_phase_handler_pt  checker;
[135]     ngx_http_handler_pt        handler;
[136]     ngx_uint_t                 next;
[137] };
[138] 
[139] 
[140] typedef struct {
[141]     ngx_http_phase_handler_t  *handlers;
[142]     ngx_uint_t                 server_rewrite_index;
[143]     ngx_uint_t                 location_rewrite_index;
[144] } ngx_http_phase_engine_t;
[145] 
[146] 
[147] typedef struct {
[148]     ngx_array_t                handlers;
[149] } ngx_http_phase_t;
[150] 
[151] 
[152] typedef struct {
[153]     ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */
[154] 
[155]     ngx_http_phase_engine_t    phase_engine;
[156] 
[157]     ngx_hash_t                 headers_in_hash;
[158] 
[159]     ngx_hash_t                 variables_hash;
[160] 
[161]     ngx_array_t                variables;         /* ngx_http_variable_t */
[162]     ngx_array_t                prefix_variables;  /* ngx_http_variable_t */
[163]     ngx_uint_t                 ncaptures;
[164] 
[165]     ngx_uint_t                 server_names_hash_max_size;
[166]     ngx_uint_t                 server_names_hash_bucket_size;
[167] 
[168]     ngx_uint_t                 variables_hash_max_size;
[169]     ngx_uint_t                 variables_hash_bucket_size;
[170] 
[171]     ngx_hash_keys_arrays_t    *variables_keys;
[172] 
[173]     ngx_array_t               *ports;
[174] 
[175]     ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
[176] } ngx_http_core_main_conf_t;
[177] 
[178] 
[179] typedef struct {
[180]     /* array of the ngx_http_server_name_t, "server_name" directive */
[181]     ngx_array_t                 server_names;
[182] 
[183]     /* server ctx */
[184]     ngx_http_conf_ctx_t        *ctx;
[185] 
[186]     u_char                     *file_name;
[187]     ngx_uint_t                  line;
[188] 
[189]     ngx_str_t                   server_name;
[190] 
[191]     size_t                      connection_pool_size;
[192]     size_t                      request_pool_size;
[193]     size_t                      client_header_buffer_size;
[194] 
[195]     ngx_bufs_t                  large_client_header_buffers;
[196] 
[197]     ngx_msec_t                  client_header_timeout;
[198] 
[199]     ngx_flag_t                  ignore_invalid_headers;
[200]     ngx_flag_t                  merge_slashes;
[201]     ngx_flag_t                  underscores_in_headers;
[202] 
[203]     unsigned                    listen:1;
[204] #if (NGX_PCRE)
[205]     unsigned                    captures:1;
[206] #endif
[207] 
[208]     ngx_http_core_loc_conf_t  **named_locations;
[209] } ngx_http_core_srv_conf_t;
[210] 
[211] 
[212] /* list of structures to find core_srv_conf quickly at run time */
[213] 
[214] 
[215] typedef struct {
[216] #if (NGX_PCRE)
[217]     ngx_http_regex_t          *regex;
[218] #endif
[219]     ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
[220]     ngx_str_t                  name;
[221] } ngx_http_server_name_t;
[222] 
[223] 
[224] typedef struct {
[225]     ngx_hash_combined_t        names;
[226] 
[227]     ngx_uint_t                 nregex;
[228]     ngx_http_server_name_t    *regex;
[229] } ngx_http_virtual_names_t;
[230] 
[231] 
[232] struct ngx_http_addr_conf_s {
[233]     /* the default server configuration for this address:port */
[234]     ngx_http_core_srv_conf_t  *default_server;
[235] 
[236]     ngx_http_virtual_names_t  *virtual_names;
[237] 
[238]     unsigned                   ssl:1;
[239]     unsigned                   http2:1;
[240]     unsigned                   proxy_protocol:1;
[241] };
[242] 
[243] 
[244] typedef struct {
[245]     in_addr_t                  addr;
[246]     ngx_http_addr_conf_t       conf;
[247] } ngx_http_in_addr_t;
[248] 
[249] 
[250] #if (NGX_HAVE_INET6)
[251] 
[252] typedef struct {
[253]     struct in6_addr            addr6;
[254]     ngx_http_addr_conf_t       conf;
[255] } ngx_http_in6_addr_t;
[256] 
[257] #endif
[258] 
[259] 
[260] typedef struct {
[261]     /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
[262]     void                      *addrs;
[263]     ngx_uint_t                 naddrs;
[264] } ngx_http_port_t;
[265] 
[266] 
[267] typedef struct {
[268]     ngx_int_t                  family;
[269]     in_port_t                  port;
[270]     ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
[271] } ngx_http_conf_port_t;
[272] 
[273] 
[274] typedef struct {
[275]     ngx_http_listen_opt_t      opt;
[276] 
[277]     unsigned                   protocols:3;
[278]     unsigned                   protocols_set:1;
[279]     unsigned                   protocols_changed:1;
[280] 
[281]     ngx_hash_t                 hash;
[282]     ngx_hash_wildcard_t       *wc_head;
[283]     ngx_hash_wildcard_t       *wc_tail;
[284] 
[285] #if (NGX_PCRE)
[286]     ngx_uint_t                 nregex;
[287]     ngx_http_server_name_t    *regex;
[288] #endif
[289] 
[290]     /* the default server configuration for this address:port */
[291]     ngx_http_core_srv_conf_t  *default_server;
[292]     ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
[293] } ngx_http_conf_addr_t;
[294] 
[295] 
[296] typedef struct {
[297]     ngx_int_t                  status;
[298]     ngx_int_t                  overwrite;
[299]     ngx_http_complex_value_t   value;
[300]     ngx_str_t                  args;
[301] } ngx_http_err_page_t;
[302] 
[303] 
[304] struct ngx_http_core_loc_conf_s {
[305]     ngx_str_t     name;          /* location name */
[306]     ngx_str_t     escaped_name;
[307] 
[308] #if (NGX_PCRE)
[309]     ngx_http_regex_t  *regex;
[310] #endif
[311] 
[312]     unsigned      noname:1;   /* "if () {}" block or limit_except */
[313]     unsigned      lmt_excpt:1;
[314]     unsigned      named:1;
[315] 
[316]     unsigned      exact_match:1;
[317]     unsigned      noregex:1;
[318] 
[319]     unsigned      auto_redirect:1;
[320] #if (NGX_HTTP_GZIP)
[321]     unsigned      gzip_disable_msie6:2;
[322]     unsigned      gzip_disable_degradation:2;
[323] #endif
[324] 
[325]     ngx_http_location_tree_node_t   *static_locations;
[326] #if (NGX_PCRE)
[327]     ngx_http_core_loc_conf_t       **regex_locations;
[328] #endif
[329] 
[330]     /* pointer to the modules' loc_conf */
[331]     void        **loc_conf;
[332] 
[333]     uint32_t      limit_except;
[334]     void        **limit_except_loc_conf;
[335] 
[336]     ngx_http_handler_pt  handler;
[337] 
[338]     /* location name length for inclusive location with inherited alias */
[339]     size_t        alias;
[340]     ngx_str_t     root;                    /* root, alias */
[341]     ngx_str_t     post_action;
[342] 
[343]     ngx_array_t  *root_lengths;
[344]     ngx_array_t  *root_values;
[345] 
[346]     ngx_array_t  *types;
[347]     ngx_hash_t    types_hash;
[348]     ngx_str_t     default_type;
[349] 
[350]     off_t         client_max_body_size;    /* client_max_body_size */
[351]     off_t         directio;                /* directio */
[352]     off_t         directio_alignment;      /* directio_alignment */
[353] 
[354]     size_t        client_body_buffer_size; /* client_body_buffer_size */
[355]     size_t        send_lowat;              /* send_lowat */
[356]     size_t        postpone_output;         /* postpone_output */
[357]     size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
[358]     size_t        read_ahead;              /* read_ahead */
[359]     size_t        subrequest_output_buffer_size;
[360]                                            /* subrequest_output_buffer_size */
[361] 
[362]     ngx_http_complex_value_t  *limit_rate; /* limit_rate */
[363]     ngx_http_complex_value_t  *limit_rate_after; /* limit_rate_after */
[364] 
[365]     ngx_msec_t    client_body_timeout;     /* client_body_timeout */
[366]     ngx_msec_t    send_timeout;            /* send_timeout */
[367]     ngx_msec_t    keepalive_time;          /* keepalive_time */
[368]     ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
[369]     ngx_msec_t    lingering_time;          /* lingering_time */
[370]     ngx_msec_t    lingering_timeout;       /* lingering_timeout */
[371]     ngx_msec_t    resolver_timeout;        /* resolver_timeout */
[372]     ngx_msec_t    auth_delay;              /* auth_delay */
[373] 
[374]     ngx_resolver_t  *resolver;             /* resolver */
[375] 
[376]     time_t        keepalive_header;        /* keepalive_timeout */
[377] 
[378]     ngx_uint_t    keepalive_requests;      /* keepalive_requests */
[379]     ngx_uint_t    keepalive_disable;       /* keepalive_disable */
[380]     ngx_uint_t    satisfy;                 /* satisfy */
[381]     ngx_uint_t    lingering_close;         /* lingering_close */
[382]     ngx_uint_t    if_modified_since;       /* if_modified_since */
[383]     ngx_uint_t    max_ranges;              /* max_ranges */
[384]     ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */
[385] 
[386]     ngx_flag_t    client_body_in_single_buffer;
[387]                                            /* client_body_in_singe_buffer */
[388]     ngx_flag_t    internal;                /* internal */
[389]     ngx_flag_t    sendfile;                /* sendfile */
[390]     ngx_flag_t    aio;                     /* aio */
[391]     ngx_flag_t    aio_write;               /* aio_write */
[392]     ngx_flag_t    tcp_nopush;              /* tcp_nopush */
[393]     ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
[394]     ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
[395]     ngx_flag_t    absolute_redirect;       /* absolute_redirect */
[396]     ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
[397]     ngx_flag_t    port_in_redirect;        /* port_in_redirect */
[398]     ngx_flag_t    msie_padding;            /* msie_padding */
[399]     ngx_flag_t    msie_refresh;            /* msie_refresh */
[400]     ngx_flag_t    log_not_found;           /* log_not_found */
[401]     ngx_flag_t    log_subrequest;          /* log_subrequest */
[402]     ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
[403]     ngx_uint_t    server_tokens;           /* server_tokens */
[404]     ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
[405]     ngx_flag_t    etag;                    /* etag */
[406] 
[407] #if (NGX_HTTP_GZIP)
[408]     ngx_flag_t    gzip_vary;               /* gzip_vary */
[409] 
[410]     ngx_uint_t    gzip_http_version;       /* gzip_http_version */
[411]     ngx_uint_t    gzip_proxied;            /* gzip_proxied */
[412] 
[413] #if (NGX_PCRE)
[414]     ngx_array_t  *gzip_disable;            /* gzip_disable */
[415] #endif
[416] #endif
[417] 
[418] #if (NGX_THREADS || NGX_COMPAT)
[419]     ngx_thread_pool_t         *thread_pool;
[420]     ngx_http_complex_value_t  *thread_pool_value;
[421] #endif
[422] 
[423] #if (NGX_HAVE_OPENAT)
[424]     ngx_uint_t    disable_symlinks;        /* disable_symlinks */
[425]     ngx_http_complex_value_t  *disable_symlinks_from;
[426] #endif
[427] 
[428]     ngx_array_t  *error_pages;             /* error_page */
[429] 
[430]     ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */
[431] 
[432]     ngx_open_file_cache_t  *open_file_cache;
[433]     time_t        open_file_cache_valid;
[434]     ngx_uint_t    open_file_cache_min_uses;
[435]     ngx_flag_t    open_file_cache_errors;
[436]     ngx_flag_t    open_file_cache_events;
[437] 
[438]     ngx_log_t    *error_log;
[439] 
[440]     ngx_uint_t    types_hash_max_size;
[441]     ngx_uint_t    types_hash_bucket_size;
[442] 
[443]     ngx_queue_t  *locations;
[444] 
[445] #if 0
[446]     ngx_http_core_loc_conf_t  *prev_location;
[447] #endif
[448] };
[449] 
[450] 
[451] typedef struct {
[452]     ngx_queue_t                      queue;
[453]     ngx_http_core_loc_conf_t        *exact;
[454]     ngx_http_core_loc_conf_t        *inclusive;
[455]     ngx_str_t                       *name;
[456]     u_char                          *file_name;
[457]     ngx_uint_t                       line;
[458]     ngx_queue_t                      list;
[459] } ngx_http_location_queue_t;
[460] 
[461] 
[462] struct ngx_http_location_tree_node_s {
[463]     ngx_http_location_tree_node_t   *left;
[464]     ngx_http_location_tree_node_t   *right;
[465]     ngx_http_location_tree_node_t   *tree;
[466] 
[467]     ngx_http_core_loc_conf_t        *exact;
[468]     ngx_http_core_loc_conf_t        *inclusive;
[469] 
[470]     u_short                          len;
[471]     u_char                           auto_redirect;
[472]     u_char                           name[1];
[473] };
[474] 
[475] 
[476] void ngx_http_core_run_phases(ngx_http_request_t *r);
[477] ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
[478]     ngx_http_phase_handler_t *ph);
[479] ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
[480]     ngx_http_phase_handler_t *ph);
[481] ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
[482]     ngx_http_phase_handler_t *ph);
[483] ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
[484]     ngx_http_phase_handler_t *ph);
[485] ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
[486]     ngx_http_phase_handler_t *ph);
[487] ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
[488]     ngx_http_phase_handler_t *ph);
[489] ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
[490]     ngx_http_phase_handler_t *ph);
[491] 
[492] 
[493] void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
[494] ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
[495] void ngx_http_set_exten(ngx_http_request_t *r);
[496] ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
[497] void ngx_http_weak_etag(ngx_http_request_t *r);
[498] ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
[499]     ngx_str_t *ct, ngx_http_complex_value_t *cv);
[500] u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
[501]     size_t *root_length, size_t reserved);
[502] ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
[503] #if (NGX_HTTP_GZIP)
[504] ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
[505] #endif
[506] 
[507] 
[508] ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
[509]     ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
[510]     ngx_http_post_subrequest_t *ps, ngx_uint_t flags);
[511] ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
[512]     ngx_str_t *uri, ngx_str_t *args);
[513] ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);
[514] 
[515] 
[516] ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);
[517] 
[518] 
[519] typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
[520] typedef ngx_int_t (*ngx_http_output_body_filter_pt)
[521]     (ngx_http_request_t *r, ngx_chain_t *chain);
[522] typedef ngx_int_t (*ngx_http_request_body_filter_pt)
[523]     (ngx_http_request_t *r, ngx_chain_t *chain);
[524] 
[525] 
[526] ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
[527] ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);
[528] ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
[529]     ngx_chain_t *chain);
[530] 
[531] 
[532] ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
[533]     ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);
[534] 
[535] ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
[536]     ngx_table_elt_t *headers, ngx_str_t *value, ngx_array_t *proxies,
[537]     int recursive);
[538] 
[539] ngx_int_t ngx_http_link_multi_headers(ngx_http_request_t *r);
[540] 
[541] 
[542] extern ngx_module_t  ngx_http_core_module;
[543] 
[544] extern ngx_uint_t ngx_http_max_module;
[545] 
[546] extern ngx_str_t  ngx_http_core_get_method;
[547] 
[548] 
[549] #define ngx_http_clear_content_length(r)                                      \
[550]                                                                               \
[551]     r->headers_out.content_length_n = -1;                                     \
[552]     if (r->headers_out.content_length) {                                      \
[553]         r->headers_out.content_length->hash = 0;                              \
[554]         r->headers_out.content_length = NULL;                                 \
[555]     }
[556] 
[557] #define ngx_http_clear_accept_ranges(r)                                       \
[558]                                                                               \
[559]     r->allow_ranges = 0;                                                      \
[560]     if (r->headers_out.accept_ranges) {                                       \
[561]         r->headers_out.accept_ranges->hash = 0;                               \
[562]         r->headers_out.accept_ranges = NULL;                                  \
[563]     }
[564] 
[565] #define ngx_http_clear_last_modified(r)                                       \
[566]                                                                               \
[567]     r->headers_out.last_modified_time = -1;                                   \
[568]     if (r->headers_out.last_modified) {                                       \
[569]         r->headers_out.last_modified->hash = 0;                               \
[570]         r->headers_out.last_modified = NULL;                                  \
[571]     }
[572] 
[573] #define ngx_http_clear_location(r)                                            \
[574]                                                                               \
[575]     if (r->headers_out.location) {                                            \
[576]         r->headers_out.location->hash = 0;                                    \
[577]         r->headers_out.location = NULL;                                       \
[578]     }
[579] 
[580] #define ngx_http_clear_etag(r)                                                \
[581]                                                                               \
[582]     if (r->headers_out.etag) {                                                \
[583]         r->headers_out.etag->hash = 0;                                        \
[584]         r->headers_out.etag = NULL;                                           \
[585]     }
[586] 
[587] 
[588] #endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
