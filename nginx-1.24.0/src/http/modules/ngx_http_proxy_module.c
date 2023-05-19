[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] #define  NGX_HTTP_PROXY_COOKIE_SECURE           0x0001
[14] #define  NGX_HTTP_PROXY_COOKIE_SECURE_ON        0x0002
[15] #define  NGX_HTTP_PROXY_COOKIE_SECURE_OFF       0x0004
[16] #define  NGX_HTTP_PROXY_COOKIE_HTTPONLY         0x0008
[17] #define  NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON      0x0010
[18] #define  NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF     0x0020
[19] #define  NGX_HTTP_PROXY_COOKIE_SAMESITE         0x0040
[20] #define  NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT  0x0080
[21] #define  NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX     0x0100
[22] #define  NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE    0x0200
[23] #define  NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF     0x0400
[24] 
[25] 
[26] typedef struct {
[27]     ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
[28] } ngx_http_proxy_main_conf_t;
[29] 
[30] 
[31] typedef struct ngx_http_proxy_rewrite_s  ngx_http_proxy_rewrite_t;
[32] 
[33] typedef ngx_int_t (*ngx_http_proxy_rewrite_pt)(ngx_http_request_t *r,
[34]     ngx_str_t *value, size_t prefix, size_t len,
[35]     ngx_http_proxy_rewrite_t *pr);
[36] 
[37] struct ngx_http_proxy_rewrite_s {
[38]     ngx_http_proxy_rewrite_pt      handler;
[39] 
[40]     union {
[41]         ngx_http_complex_value_t   complex;
[42] #if (NGX_PCRE)
[43]         ngx_http_regex_t          *regex;
[44] #endif
[45]     } pattern;
[46] 
[47]     ngx_http_complex_value_t       replacement;
[48] };
[49] 
[50] 
[51] typedef struct {
[52]     union {
[53]         ngx_http_complex_value_t   complex;
[54] #if (NGX_PCRE)
[55]         ngx_http_regex_t          *regex;
[56] #endif
[57]     } cookie;
[58] 
[59]     ngx_array_t                    flags_values;
[60]     ngx_uint_t                     regex;
[61] } ngx_http_proxy_cookie_flags_t;
[62] 
[63] 
[64] typedef struct {
[65]     ngx_str_t                      key_start;
[66]     ngx_str_t                      schema;
[67]     ngx_str_t                      host_header;
[68]     ngx_str_t                      port;
[69]     ngx_str_t                      uri;
[70] } ngx_http_proxy_vars_t;
[71] 
[72] 
[73] typedef struct {
[74]     ngx_array_t                   *flushes;
[75]     ngx_array_t                   *lengths;
[76]     ngx_array_t                   *values;
[77]     ngx_hash_t                     hash;
[78] } ngx_http_proxy_headers_t;
[79] 
[80] 
[81] typedef struct {
[82]     ngx_http_upstream_conf_t       upstream;
[83] 
[84]     ngx_array_t                   *body_flushes;
[85]     ngx_array_t                   *body_lengths;
[86]     ngx_array_t                   *body_values;
[87]     ngx_str_t                      body_source;
[88] 
[89]     ngx_http_proxy_headers_t       headers;
[90] #if (NGX_HTTP_CACHE)
[91]     ngx_http_proxy_headers_t       headers_cache;
[92] #endif
[93]     ngx_array_t                   *headers_source;
[94] 
[95]     ngx_array_t                   *proxy_lengths;
[96]     ngx_array_t                   *proxy_values;
[97] 
[98]     ngx_array_t                   *redirects;
[99]     ngx_array_t                   *cookie_domains;
[100]     ngx_array_t                   *cookie_paths;
[101]     ngx_array_t                   *cookie_flags;
[102] 
[103]     ngx_http_complex_value_t      *method;
[104]     ngx_str_t                      location;
[105]     ngx_str_t                      url;
[106] 
[107] #if (NGX_HTTP_CACHE)
[108]     ngx_http_complex_value_t       cache_key;
[109] #endif
[110] 
[111]     ngx_http_proxy_vars_t          vars;
[112] 
[113]     ngx_flag_t                     redirect;
[114] 
[115]     ngx_uint_t                     http_version;
[116] 
[117]     ngx_uint_t                     headers_hash_max_size;
[118]     ngx_uint_t                     headers_hash_bucket_size;
[119] 
[120] #if (NGX_HTTP_SSL)
[121]     ngx_uint_t                     ssl;
[122]     ngx_uint_t                     ssl_protocols;
[123]     ngx_str_t                      ssl_ciphers;
[124]     ngx_uint_t                     ssl_verify_depth;
[125]     ngx_str_t                      ssl_trusted_certificate;
[126]     ngx_str_t                      ssl_crl;
[127]     ngx_array_t                   *ssl_conf_commands;
[128] #endif
[129] } ngx_http_proxy_loc_conf_t;
[130] 
[131] 
[132] typedef struct {
[133]     ngx_http_status_t              status;
[134]     ngx_http_chunked_t             chunked;
[135]     ngx_http_proxy_vars_t          vars;
[136]     off_t                          internal_body_length;
[137] 
[138]     ngx_chain_t                   *free;
[139]     ngx_chain_t                   *busy;
[140] 
[141]     unsigned                       head:1;
[142]     unsigned                       internal_chunked:1;
[143]     unsigned                       header_sent:1;
[144] } ngx_http_proxy_ctx_t;
[145] 
[146] 
[147] static ngx_int_t ngx_http_proxy_eval(ngx_http_request_t *r,
[148]     ngx_http_proxy_ctx_t *ctx, ngx_http_proxy_loc_conf_t *plcf);
[149] #if (NGX_HTTP_CACHE)
[150] static ngx_int_t ngx_http_proxy_create_key(ngx_http_request_t *r);
[151] #endif
[152] static ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
[153] static ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
[154] static ngx_int_t ngx_http_proxy_body_output_filter(void *data, ngx_chain_t *in);
[155] static ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
[156] static ngx_int_t ngx_http_proxy_process_header(ngx_http_request_t *r);
[157] static ngx_int_t ngx_http_proxy_input_filter_init(void *data);
[158] static ngx_int_t ngx_http_proxy_copy_filter(ngx_event_pipe_t *p,
[159]     ngx_buf_t *buf);
[160] static ngx_int_t ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p,
[161]     ngx_buf_t *buf);
[162] static ngx_int_t ngx_http_proxy_non_buffered_copy_filter(void *data,
[163]     ssize_t bytes);
[164] static ngx_int_t ngx_http_proxy_non_buffered_chunked_filter(void *data,
[165]     ssize_t bytes);
[166] static void ngx_http_proxy_abort_request(ngx_http_request_t *r);
[167] static void ngx_http_proxy_finalize_request(ngx_http_request_t *r,
[168]     ngx_int_t rc);
[169] 
[170] static ngx_int_t ngx_http_proxy_host_variable(ngx_http_request_t *r,
[171]     ngx_http_variable_value_t *v, uintptr_t data);
[172] static ngx_int_t ngx_http_proxy_port_variable(ngx_http_request_t *r,
[173]     ngx_http_variable_value_t *v, uintptr_t data);
[174] static ngx_int_t
[175]     ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
[176]     ngx_http_variable_value_t *v, uintptr_t data);
[177] static ngx_int_t
[178]     ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
[179]     ngx_http_variable_value_t *v, uintptr_t data);
[180] static ngx_int_t ngx_http_proxy_internal_chunked_variable(ngx_http_request_t *r,
[181]     ngx_http_variable_value_t *v, uintptr_t data);
[182] static ngx_int_t ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r,
[183]     ngx_table_elt_t *h, size_t prefix);
[184] static ngx_int_t ngx_http_proxy_rewrite_cookie(ngx_http_request_t *r,
[185]     ngx_table_elt_t *h);
[186] static ngx_int_t ngx_http_proxy_parse_cookie(ngx_str_t *value,
[187]     ngx_array_t *attrs);
[188] static ngx_int_t ngx_http_proxy_rewrite_cookie_value(ngx_http_request_t *r,
[189]     ngx_str_t *value, ngx_array_t *rewrites);
[190] static ngx_int_t ngx_http_proxy_rewrite_cookie_flags(ngx_http_request_t *r,
[191]     ngx_array_t *attrs, ngx_array_t *flags);
[192] static ngx_int_t ngx_http_proxy_edit_cookie_flags(ngx_http_request_t *r,
[193]     ngx_array_t *attrs, ngx_uint_t flags);
[194] static ngx_int_t ngx_http_proxy_rewrite(ngx_http_request_t *r,
[195]     ngx_str_t *value, size_t prefix, size_t len, ngx_str_t *replacement);
[196] 
[197] static ngx_int_t ngx_http_proxy_add_variables(ngx_conf_t *cf);
[198] static void *ngx_http_proxy_create_main_conf(ngx_conf_t *cf);
[199] static void *ngx_http_proxy_create_loc_conf(ngx_conf_t *cf);
[200] static char *ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf,
[201]     void *parent, void *child);
[202] static ngx_int_t ngx_http_proxy_init_headers(ngx_conf_t *cf,
[203]     ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_headers_t *headers,
[204]     ngx_keyval_t *default_headers);
[205] 
[206] static char *ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
[207]     void *conf);
[208] static char *ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
[209]     void *conf);
[210] static char *ngx_http_proxy_cookie_domain(ngx_conf_t *cf, ngx_command_t *cmd,
[211]     void *conf);
[212] static char *ngx_http_proxy_cookie_path(ngx_conf_t *cf, ngx_command_t *cmd,
[213]     void *conf);
[214] static char *ngx_http_proxy_cookie_flags(ngx_conf_t *cf, ngx_command_t *cmd,
[215]     void *conf);
[216] static char *ngx_http_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd,
[217]     void *conf);
[218] #if (NGX_HTTP_CACHE)
[219] static char *ngx_http_proxy_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[220]     void *conf);
[221] static char *ngx_http_proxy_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
[222]     void *conf);
[223] #endif
[224] #if (NGX_HTTP_SSL)
[225] static char *ngx_http_proxy_ssl_password_file(ngx_conf_t *cf,
[226]     ngx_command_t *cmd, void *conf);
[227] #endif
[228] 
[229] static char *ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);
[230] #if (NGX_HTTP_SSL)
[231] static char *ngx_http_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[232]     void *data);
[233] #endif
[234] 
[235] static ngx_int_t ngx_http_proxy_rewrite_regex(ngx_conf_t *cf,
[236]     ngx_http_proxy_rewrite_t *pr, ngx_str_t *regex, ngx_uint_t caseless);
[237] 
[238] #if (NGX_HTTP_SSL)
[239] static ngx_int_t ngx_http_proxy_merge_ssl(ngx_conf_t *cf,
[240]     ngx_http_proxy_loc_conf_t *conf, ngx_http_proxy_loc_conf_t *prev);
[241] static ngx_int_t ngx_http_proxy_set_ssl(ngx_conf_t *cf,
[242]     ngx_http_proxy_loc_conf_t *plcf);
[243] #endif
[244] static void ngx_http_proxy_set_vars(ngx_url_t *u, ngx_http_proxy_vars_t *v);
[245] 
[246] 
[247] static ngx_conf_post_t  ngx_http_proxy_lowat_post =
[248]     { ngx_http_proxy_lowat_check };
[249] 
[250] 
[251] static ngx_conf_bitmask_t  ngx_http_proxy_next_upstream_masks[] = {
[252]     { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
[253]     { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
[254]     { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
[255]     { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
[256]     { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
[257]     { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
[258]     { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
[259]     { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
[260]     { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
[261]     { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[262]     { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
[263]     { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
[264]     { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
[265]     { ngx_null_string, 0 }
[266] };
[267] 
[268] 
[269] #if (NGX_HTTP_SSL)
[270] 
[271] static ngx_conf_bitmask_t  ngx_http_proxy_ssl_protocols[] = {
[272]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[273]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[274]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[275]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[276]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[277]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[278]     { ngx_null_string, 0 }
[279] };
[280] 
[281] static ngx_conf_post_t  ngx_http_proxy_ssl_conf_command_post =
[282]     { ngx_http_proxy_ssl_conf_command_check };
[283] 
[284] #endif
[285] 
[286] 
[287] static ngx_conf_enum_t  ngx_http_proxy_http_version[] = {
[288]     { ngx_string("1.0"), NGX_HTTP_VERSION_10 },
[289]     { ngx_string("1.1"), NGX_HTTP_VERSION_11 },
[290]     { ngx_null_string, 0 }
[291] };
[292] 
[293] 
[294] ngx_module_t  ngx_http_proxy_module;
[295] 
[296] 
[297] static ngx_command_t  ngx_http_proxy_commands[] = {
[298] 
[299]     { ngx_string("proxy_pass"),
[300]       NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
[301]       ngx_http_proxy_pass,
[302]       NGX_HTTP_LOC_CONF_OFFSET,
[303]       0,
[304]       NULL },
[305] 
[306]     { ngx_string("proxy_redirect"),
[307]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[308]       ngx_http_proxy_redirect,
[309]       NGX_HTTP_LOC_CONF_OFFSET,
[310]       0,
[311]       NULL },
[312] 
[313]     { ngx_string("proxy_cookie_domain"),
[314]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[315]       ngx_http_proxy_cookie_domain,
[316]       NGX_HTTP_LOC_CONF_OFFSET,
[317]       0,
[318]       NULL },
[319] 
[320]     { ngx_string("proxy_cookie_path"),
[321]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[322]       ngx_http_proxy_cookie_path,
[323]       NGX_HTTP_LOC_CONF_OFFSET,
[324]       0,
[325]       NULL },
[326] 
[327]     { ngx_string("proxy_cookie_flags"),
[328]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[329]       ngx_http_proxy_cookie_flags,
[330]       NGX_HTTP_LOC_CONF_OFFSET,
[331]       0,
[332]       NULL },
[333] 
[334]     { ngx_string("proxy_store"),
[335]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[336]       ngx_http_proxy_store,
[337]       NGX_HTTP_LOC_CONF_OFFSET,
[338]       0,
[339]       NULL },
[340] 
[341]     { ngx_string("proxy_store_access"),
[342]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[343]       ngx_conf_set_access_slot,
[344]       NGX_HTTP_LOC_CONF_OFFSET,
[345]       offsetof(ngx_http_proxy_loc_conf_t, upstream.store_access),
[346]       NULL },
[347] 
[348]     { ngx_string("proxy_buffering"),
[349]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[350]       ngx_conf_set_flag_slot,
[351]       NGX_HTTP_LOC_CONF_OFFSET,
[352]       offsetof(ngx_http_proxy_loc_conf_t, upstream.buffering),
[353]       NULL },
[354] 
[355]     { ngx_string("proxy_request_buffering"),
[356]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[357]       ngx_conf_set_flag_slot,
[358]       NGX_HTTP_LOC_CONF_OFFSET,
[359]       offsetof(ngx_http_proxy_loc_conf_t, upstream.request_buffering),
[360]       NULL },
[361] 
[362]     { ngx_string("proxy_ignore_client_abort"),
[363]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[364]       ngx_conf_set_flag_slot,
[365]       NGX_HTTP_LOC_CONF_OFFSET,
[366]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ignore_client_abort),
[367]       NULL },
[368] 
[369]     { ngx_string("proxy_bind"),
[370]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[371]       ngx_http_upstream_bind_set_slot,
[372]       NGX_HTTP_LOC_CONF_OFFSET,
[373]       offsetof(ngx_http_proxy_loc_conf_t, upstream.local),
[374]       NULL },
[375] 
[376]     { ngx_string("proxy_socket_keepalive"),
[377]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[378]       ngx_conf_set_flag_slot,
[379]       NGX_HTTP_LOC_CONF_OFFSET,
[380]       offsetof(ngx_http_proxy_loc_conf_t, upstream.socket_keepalive),
[381]       NULL },
[382] 
[383]     { ngx_string("proxy_connect_timeout"),
[384]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[385]       ngx_conf_set_msec_slot,
[386]       NGX_HTTP_LOC_CONF_OFFSET,
[387]       offsetof(ngx_http_proxy_loc_conf_t, upstream.connect_timeout),
[388]       NULL },
[389] 
[390]     { ngx_string("proxy_send_timeout"),
[391]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[392]       ngx_conf_set_msec_slot,
[393]       NGX_HTTP_LOC_CONF_OFFSET,
[394]       offsetof(ngx_http_proxy_loc_conf_t, upstream.send_timeout),
[395]       NULL },
[396] 
[397]     { ngx_string("proxy_send_lowat"),
[398]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[399]       ngx_conf_set_size_slot,
[400]       NGX_HTTP_LOC_CONF_OFFSET,
[401]       offsetof(ngx_http_proxy_loc_conf_t, upstream.send_lowat),
[402]       &ngx_http_proxy_lowat_post },
[403] 
[404]     { ngx_string("proxy_intercept_errors"),
[405]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[406]       ngx_conf_set_flag_slot,
[407]       NGX_HTTP_LOC_CONF_OFFSET,
[408]       offsetof(ngx_http_proxy_loc_conf_t, upstream.intercept_errors),
[409]       NULL },
[410] 
[411]     { ngx_string("proxy_set_header"),
[412]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[413]       ngx_conf_set_keyval_slot,
[414]       NGX_HTTP_LOC_CONF_OFFSET,
[415]       offsetof(ngx_http_proxy_loc_conf_t, headers_source),
[416]       NULL },
[417] 
[418]     { ngx_string("proxy_headers_hash_max_size"),
[419]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[420]       ngx_conf_set_num_slot,
[421]       NGX_HTTP_LOC_CONF_OFFSET,
[422]       offsetof(ngx_http_proxy_loc_conf_t, headers_hash_max_size),
[423]       NULL },
[424] 
[425]     { ngx_string("proxy_headers_hash_bucket_size"),
[426]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[427]       ngx_conf_set_num_slot,
[428]       NGX_HTTP_LOC_CONF_OFFSET,
[429]       offsetof(ngx_http_proxy_loc_conf_t, headers_hash_bucket_size),
[430]       NULL },
[431] 
[432]     { ngx_string("proxy_set_body"),
[433]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[434]       ngx_conf_set_str_slot,
[435]       NGX_HTTP_LOC_CONF_OFFSET,
[436]       offsetof(ngx_http_proxy_loc_conf_t, body_source),
[437]       NULL },
[438] 
[439]     { ngx_string("proxy_method"),
[440]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[441]       ngx_http_set_complex_value_slot,
[442]       NGX_HTTP_LOC_CONF_OFFSET,
[443]       offsetof(ngx_http_proxy_loc_conf_t, method),
[444]       NULL },
[445] 
[446]     { ngx_string("proxy_pass_request_headers"),
[447]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[448]       ngx_conf_set_flag_slot,
[449]       NGX_HTTP_LOC_CONF_OFFSET,
[450]       offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_headers),
[451]       NULL },
[452] 
[453]     { ngx_string("proxy_pass_request_body"),
[454]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[455]       ngx_conf_set_flag_slot,
[456]       NGX_HTTP_LOC_CONF_OFFSET,
[457]       offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_request_body),
[458]       NULL },
[459] 
[460]     { ngx_string("proxy_buffer_size"),
[461]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[462]       ngx_conf_set_size_slot,
[463]       NGX_HTTP_LOC_CONF_OFFSET,
[464]       offsetof(ngx_http_proxy_loc_conf_t, upstream.buffer_size),
[465]       NULL },
[466] 
[467]     { ngx_string("proxy_read_timeout"),
[468]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[469]       ngx_conf_set_msec_slot,
[470]       NGX_HTTP_LOC_CONF_OFFSET,
[471]       offsetof(ngx_http_proxy_loc_conf_t, upstream.read_timeout),
[472]       NULL },
[473] 
[474]     { ngx_string("proxy_buffers"),
[475]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[476]       ngx_conf_set_bufs_slot,
[477]       NGX_HTTP_LOC_CONF_OFFSET,
[478]       offsetof(ngx_http_proxy_loc_conf_t, upstream.bufs),
[479]       NULL },
[480] 
[481]     { ngx_string("proxy_busy_buffers_size"),
[482]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[483]       ngx_conf_set_size_slot,
[484]       NGX_HTTP_LOC_CONF_OFFSET,
[485]       offsetof(ngx_http_proxy_loc_conf_t, upstream.busy_buffers_size_conf),
[486]       NULL },
[487] 
[488]     { ngx_string("proxy_force_ranges"),
[489]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[490]       ngx_conf_set_flag_slot,
[491]       NGX_HTTP_LOC_CONF_OFFSET,
[492]       offsetof(ngx_http_proxy_loc_conf_t, upstream.force_ranges),
[493]       NULL },
[494] 
[495]     { ngx_string("proxy_limit_rate"),
[496]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[497]       ngx_conf_set_size_slot,
[498]       NGX_HTTP_LOC_CONF_OFFSET,
[499]       offsetof(ngx_http_proxy_loc_conf_t, upstream.limit_rate),
[500]       NULL },
[501] 
[502] #if (NGX_HTTP_CACHE)
[503] 
[504]     { ngx_string("proxy_cache"),
[505]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[506]       ngx_http_proxy_cache,
[507]       NGX_HTTP_LOC_CONF_OFFSET,
[508]       0,
[509]       NULL },
[510] 
[511]     { ngx_string("proxy_cache_key"),
[512]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[513]       ngx_http_proxy_cache_key,
[514]       NGX_HTTP_LOC_CONF_OFFSET,
[515]       0,
[516]       NULL },
[517] 
[518]     { ngx_string("proxy_cache_path"),
[519]       NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
[520]       ngx_http_file_cache_set_slot,
[521]       NGX_HTTP_MAIN_CONF_OFFSET,
[522]       offsetof(ngx_http_proxy_main_conf_t, caches),
[523]       &ngx_http_proxy_module },
[524] 
[525]     { ngx_string("proxy_cache_bypass"),
[526]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[527]       ngx_http_set_predicate_slot,
[528]       NGX_HTTP_LOC_CONF_OFFSET,
[529]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_bypass),
[530]       NULL },
[531] 
[532]     { ngx_string("proxy_no_cache"),
[533]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[534]       ngx_http_set_predicate_slot,
[535]       NGX_HTTP_LOC_CONF_OFFSET,
[536]       offsetof(ngx_http_proxy_loc_conf_t, upstream.no_cache),
[537]       NULL },
[538] 
[539]     { ngx_string("proxy_cache_valid"),
[540]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[541]       ngx_http_file_cache_valid_set_slot,
[542]       NGX_HTTP_LOC_CONF_OFFSET,
[543]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_valid),
[544]       NULL },
[545] 
[546]     { ngx_string("proxy_cache_min_uses"),
[547]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[548]       ngx_conf_set_num_slot,
[549]       NGX_HTTP_LOC_CONF_OFFSET,
[550]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_min_uses),
[551]       NULL },
[552] 
[553]     { ngx_string("proxy_cache_max_range_offset"),
[554]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[555]       ngx_conf_set_off_slot,
[556]       NGX_HTTP_LOC_CONF_OFFSET,
[557]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_max_range_offset),
[558]       NULL },
[559] 
[560]     { ngx_string("proxy_cache_use_stale"),
[561]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[562]       ngx_conf_set_bitmask_slot,
[563]       NGX_HTTP_LOC_CONF_OFFSET,
[564]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_use_stale),
[565]       &ngx_http_proxy_next_upstream_masks },
[566] 
[567]     { ngx_string("proxy_cache_methods"),
[568]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[569]       ngx_conf_set_bitmask_slot,
[570]       NGX_HTTP_LOC_CONF_OFFSET,
[571]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_methods),
[572]       &ngx_http_upstream_cache_method_mask },
[573] 
[574]     { ngx_string("proxy_cache_lock"),
[575]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[576]       ngx_conf_set_flag_slot,
[577]       NGX_HTTP_LOC_CONF_OFFSET,
[578]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_lock),
[579]       NULL },
[580] 
[581]     { ngx_string("proxy_cache_lock_timeout"),
[582]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[583]       ngx_conf_set_msec_slot,
[584]       NGX_HTTP_LOC_CONF_OFFSET,
[585]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_lock_timeout),
[586]       NULL },
[587] 
[588]     { ngx_string("proxy_cache_lock_age"),
[589]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[590]       ngx_conf_set_msec_slot,
[591]       NGX_HTTP_LOC_CONF_OFFSET,
[592]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_lock_age),
[593]       NULL },
[594] 
[595]     { ngx_string("proxy_cache_revalidate"),
[596]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[597]       ngx_conf_set_flag_slot,
[598]       NGX_HTTP_LOC_CONF_OFFSET,
[599]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_revalidate),
[600]       NULL },
[601] 
[602]     { ngx_string("proxy_cache_convert_head"),
[603]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[604]       ngx_conf_set_flag_slot,
[605]       NGX_HTTP_LOC_CONF_OFFSET,
[606]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_convert_head),
[607]       NULL },
[608] 
[609]     { ngx_string("proxy_cache_background_update"),
[610]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[611]       ngx_conf_set_flag_slot,
[612]       NGX_HTTP_LOC_CONF_OFFSET,
[613]       offsetof(ngx_http_proxy_loc_conf_t, upstream.cache_background_update),
[614]       NULL },
[615] 
[616] #endif
[617] 
[618]     { ngx_string("proxy_temp_path"),
[619]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[620]       ngx_conf_set_path_slot,
[621]       NGX_HTTP_LOC_CONF_OFFSET,
[622]       offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_path),
[623]       NULL },
[624] 
[625]     { ngx_string("proxy_max_temp_file_size"),
[626]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[627]       ngx_conf_set_size_slot,
[628]       NGX_HTTP_LOC_CONF_OFFSET,
[629]       offsetof(ngx_http_proxy_loc_conf_t, upstream.max_temp_file_size_conf),
[630]       NULL },
[631] 
[632]     { ngx_string("proxy_temp_file_write_size"),
[633]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[634]       ngx_conf_set_size_slot,
[635]       NGX_HTTP_LOC_CONF_OFFSET,
[636]       offsetof(ngx_http_proxy_loc_conf_t, upstream.temp_file_write_size_conf),
[637]       NULL },
[638] 
[639]     { ngx_string("proxy_next_upstream"),
[640]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[641]       ngx_conf_set_bitmask_slot,
[642]       NGX_HTTP_LOC_CONF_OFFSET,
[643]       offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream),
[644]       &ngx_http_proxy_next_upstream_masks },
[645] 
[646]     { ngx_string("proxy_next_upstream_tries"),
[647]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[648]       ngx_conf_set_num_slot,
[649]       NGX_HTTP_LOC_CONF_OFFSET,
[650]       offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream_tries),
[651]       NULL },
[652] 
[653]     { ngx_string("proxy_next_upstream_timeout"),
[654]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[655]       ngx_conf_set_msec_slot,
[656]       NGX_HTTP_LOC_CONF_OFFSET,
[657]       offsetof(ngx_http_proxy_loc_conf_t, upstream.next_upstream_timeout),
[658]       NULL },
[659] 
[660]     { ngx_string("proxy_pass_header"),
[661]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[662]       ngx_conf_set_str_array_slot,
[663]       NGX_HTTP_LOC_CONF_OFFSET,
[664]       offsetof(ngx_http_proxy_loc_conf_t, upstream.pass_headers),
[665]       NULL },
[666] 
[667]     { ngx_string("proxy_hide_header"),
[668]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[669]       ngx_conf_set_str_array_slot,
[670]       NGX_HTTP_LOC_CONF_OFFSET,
[671]       offsetof(ngx_http_proxy_loc_conf_t, upstream.hide_headers),
[672]       NULL },
[673] 
[674]     { ngx_string("proxy_ignore_headers"),
[675]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[676]       ngx_conf_set_bitmask_slot,
[677]       NGX_HTTP_LOC_CONF_OFFSET,
[678]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ignore_headers),
[679]       &ngx_http_upstream_ignore_headers_masks },
[680] 
[681]     { ngx_string("proxy_http_version"),
[682]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[683]       ngx_conf_set_enum_slot,
[684]       NGX_HTTP_LOC_CONF_OFFSET,
[685]       offsetof(ngx_http_proxy_loc_conf_t, http_version),
[686]       &ngx_http_proxy_http_version },
[687] 
[688] #if (NGX_HTTP_SSL)
[689] 
[690]     { ngx_string("proxy_ssl_session_reuse"),
[691]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[692]       ngx_conf_set_flag_slot,
[693]       NGX_HTTP_LOC_CONF_OFFSET,
[694]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_session_reuse),
[695]       NULL },
[696] 
[697]     { ngx_string("proxy_ssl_protocols"),
[698]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[699]       ngx_conf_set_bitmask_slot,
[700]       NGX_HTTP_LOC_CONF_OFFSET,
[701]       offsetof(ngx_http_proxy_loc_conf_t, ssl_protocols),
[702]       &ngx_http_proxy_ssl_protocols },
[703] 
[704]     { ngx_string("proxy_ssl_ciphers"),
[705]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[706]       ngx_conf_set_str_slot,
[707]       NGX_HTTP_LOC_CONF_OFFSET,
[708]       offsetof(ngx_http_proxy_loc_conf_t, ssl_ciphers),
[709]       NULL },
[710] 
[711]     { ngx_string("proxy_ssl_name"),
[712]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[713]       ngx_http_set_complex_value_slot,
[714]       NGX_HTTP_LOC_CONF_OFFSET,
[715]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_name),
[716]       NULL },
[717] 
[718]     { ngx_string("proxy_ssl_server_name"),
[719]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[720]       ngx_conf_set_flag_slot,
[721]       NGX_HTTP_LOC_CONF_OFFSET,
[722]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_server_name),
[723]       NULL },
[724] 
[725]     { ngx_string("proxy_ssl_verify"),
[726]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[727]       ngx_conf_set_flag_slot,
[728]       NGX_HTTP_LOC_CONF_OFFSET,
[729]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_verify),
[730]       NULL },
[731] 
[732]     { ngx_string("proxy_ssl_verify_depth"),
[733]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[734]       ngx_conf_set_num_slot,
[735]       NGX_HTTP_LOC_CONF_OFFSET,
[736]       offsetof(ngx_http_proxy_loc_conf_t, ssl_verify_depth),
[737]       NULL },
[738] 
[739]     { ngx_string("proxy_ssl_trusted_certificate"),
[740]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[741]       ngx_conf_set_str_slot,
[742]       NGX_HTTP_LOC_CONF_OFFSET,
[743]       offsetof(ngx_http_proxy_loc_conf_t, ssl_trusted_certificate),
[744]       NULL },
[745] 
[746]     { ngx_string("proxy_ssl_crl"),
[747]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[748]       ngx_conf_set_str_slot,
[749]       NGX_HTTP_LOC_CONF_OFFSET,
[750]       offsetof(ngx_http_proxy_loc_conf_t, ssl_crl),
[751]       NULL },
[752] 
[753]     { ngx_string("proxy_ssl_certificate"),
[754]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[755]       ngx_http_set_complex_value_zero_slot,
[756]       NGX_HTTP_LOC_CONF_OFFSET,
[757]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_certificate),
[758]       NULL },
[759] 
[760]     { ngx_string("proxy_ssl_certificate_key"),
[761]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[762]       ngx_http_set_complex_value_zero_slot,
[763]       NGX_HTTP_LOC_CONF_OFFSET,
[764]       offsetof(ngx_http_proxy_loc_conf_t, upstream.ssl_certificate_key),
[765]       NULL },
[766] 
[767]     { ngx_string("proxy_ssl_password_file"),
[768]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[769]       ngx_http_proxy_ssl_password_file,
[770]       NGX_HTTP_LOC_CONF_OFFSET,
[771]       0,
[772]       NULL },
[773] 
[774]     { ngx_string("proxy_ssl_conf_command"),
[775]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[776]       ngx_conf_set_keyval_slot,
[777]       NGX_HTTP_LOC_CONF_OFFSET,
[778]       offsetof(ngx_http_proxy_loc_conf_t, ssl_conf_commands),
[779]       &ngx_http_proxy_ssl_conf_command_post },
[780] 
[781] #endif
[782] 
[783]       ngx_null_command
[784] };
[785] 
[786] 
[787] static ngx_http_module_t  ngx_http_proxy_module_ctx = {
[788]     ngx_http_proxy_add_variables,          /* preconfiguration */
[789]     NULL,                                  /* postconfiguration */
[790] 
[791]     ngx_http_proxy_create_main_conf,       /* create main configuration */
[792]     NULL,                                  /* init main configuration */
[793] 
[794]     NULL,                                  /* create server configuration */
[795]     NULL,                                  /* merge server configuration */
[796] 
[797]     ngx_http_proxy_create_loc_conf,        /* create location configuration */
[798]     ngx_http_proxy_merge_loc_conf          /* merge location configuration */
[799] };
[800] 
[801] 
[802] ngx_module_t  ngx_http_proxy_module = {
[803]     NGX_MODULE_V1,
[804]     &ngx_http_proxy_module_ctx,            /* module context */
[805]     ngx_http_proxy_commands,               /* module directives */
[806]     NGX_HTTP_MODULE,                       /* module type */
[807]     NULL,                                  /* init master */
[808]     NULL,                                  /* init module */
[809]     NULL,                                  /* init process */
[810]     NULL,                                  /* init thread */
[811]     NULL,                                  /* exit thread */
[812]     NULL,                                  /* exit process */
[813]     NULL,                                  /* exit master */
[814]     NGX_MODULE_V1_PADDING
[815] };
[816] 
[817] 
[818] static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;
[819] static char  ngx_http_proxy_version_11[] = " HTTP/1.1" CRLF;
[820] 
[821] 
[822] static ngx_keyval_t  ngx_http_proxy_headers[] = {
[823]     { ngx_string("Host"), ngx_string("$proxy_host") },
[824]     { ngx_string("Connection"), ngx_string("close") },
[825]     { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
[826]     { ngx_string("Transfer-Encoding"), ngx_string("$proxy_internal_chunked") },
[827]     { ngx_string("TE"), ngx_string("") },
[828]     { ngx_string("Keep-Alive"), ngx_string("") },
[829]     { ngx_string("Expect"), ngx_string("") },
[830]     { ngx_string("Upgrade"), ngx_string("") },
[831]     { ngx_null_string, ngx_null_string }
[832] };
[833] 
[834] 
[835] static ngx_str_t  ngx_http_proxy_hide_headers[] = {
[836]     ngx_string("Date"),
[837]     ngx_string("Server"),
[838]     ngx_string("X-Pad"),
[839]     ngx_string("X-Accel-Expires"),
[840]     ngx_string("X-Accel-Redirect"),
[841]     ngx_string("X-Accel-Limit-Rate"),
[842]     ngx_string("X-Accel-Buffering"),
[843]     ngx_string("X-Accel-Charset"),
[844]     ngx_null_string
[845] };
[846] 
[847] 
[848] #if (NGX_HTTP_CACHE)
[849] 
[850] static ngx_keyval_t  ngx_http_proxy_cache_headers[] = {
[851]     { ngx_string("Host"), ngx_string("$proxy_host") },
[852]     { ngx_string("Connection"), ngx_string("close") },
[853]     { ngx_string("Content-Length"), ngx_string("$proxy_internal_body_length") },
[854]     { ngx_string("Transfer-Encoding"), ngx_string("$proxy_internal_chunked") },
[855]     { ngx_string("TE"), ngx_string("") },
[856]     { ngx_string("Keep-Alive"), ngx_string("") },
[857]     { ngx_string("Expect"), ngx_string("") },
[858]     { ngx_string("Upgrade"), ngx_string("") },
[859]     { ngx_string("If-Modified-Since"),
[860]       ngx_string("$upstream_cache_last_modified") },
[861]     { ngx_string("If-Unmodified-Since"), ngx_string("") },
[862]     { ngx_string("If-None-Match"), ngx_string("$upstream_cache_etag") },
[863]     { ngx_string("If-Match"), ngx_string("") },
[864]     { ngx_string("Range"), ngx_string("") },
[865]     { ngx_string("If-Range"), ngx_string("") },
[866]     { ngx_null_string, ngx_null_string }
[867] };
[868] 
[869] #endif
[870] 
[871] 
[872] static ngx_http_variable_t  ngx_http_proxy_vars[] = {
[873] 
[874]     { ngx_string("proxy_host"), NULL, ngx_http_proxy_host_variable, 0,
[875]       NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[876] 
[877]     { ngx_string("proxy_port"), NULL, ngx_http_proxy_port_variable, 0,
[878]       NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[879] 
[880]     { ngx_string("proxy_add_x_forwarded_for"), NULL,
[881]       ngx_http_proxy_add_x_forwarded_for_variable, 0, NGX_HTTP_VAR_NOHASH, 0 },
[882] 
[883] #if 0
[884]     { ngx_string("proxy_add_via"), NULL, NULL, 0, NGX_HTTP_VAR_NOHASH, 0 },
[885] #endif
[886] 
[887]     { ngx_string("proxy_internal_body_length"), NULL,
[888]       ngx_http_proxy_internal_body_length_variable, 0,
[889]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[890] 
[891]     { ngx_string("proxy_internal_chunked"), NULL,
[892]       ngx_http_proxy_internal_chunked_variable, 0,
[893]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[894] 
[895]       ngx_http_null_variable
[896] };
[897] 
[898] 
[899] static ngx_path_init_t  ngx_http_proxy_temp_path = {
[900]     ngx_string(NGX_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
[901] };
[902] 
[903] 
[904] static ngx_conf_bitmask_t  ngx_http_proxy_cookie_flags_masks[] = {
[905] 
[906]     { ngx_string("secure"),
[907]       NGX_HTTP_PROXY_COOKIE_SECURE|NGX_HTTP_PROXY_COOKIE_SECURE_ON },
[908] 
[909]     { ngx_string("nosecure"),
[910]       NGX_HTTP_PROXY_COOKIE_SECURE|NGX_HTTP_PROXY_COOKIE_SECURE_OFF },
[911] 
[912]     { ngx_string("httponly"),
[913]       NGX_HTTP_PROXY_COOKIE_HTTPONLY|NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON },
[914] 
[915]     { ngx_string("nohttponly"),
[916]       NGX_HTTP_PROXY_COOKIE_HTTPONLY|NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF },
[917] 
[918]     { ngx_string("samesite=strict"),
[919]       NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT },
[920] 
[921]     { ngx_string("samesite=lax"),
[922]       NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX },
[923] 
[924]     { ngx_string("samesite=none"),
[925]       NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE },
[926] 
[927]     { ngx_string("nosamesite"),
[928]       NGX_HTTP_PROXY_COOKIE_SAMESITE|NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF },
[929] 
[930]     { ngx_null_string, 0 }
[931] };
[932] 
[933] 
[934] static ngx_int_t
[935] ngx_http_proxy_handler(ngx_http_request_t *r)
[936] {
[937]     ngx_int_t                    rc;
[938]     ngx_http_upstream_t         *u;
[939]     ngx_http_proxy_ctx_t        *ctx;
[940]     ngx_http_proxy_loc_conf_t   *plcf;
[941] #if (NGX_HTTP_CACHE)
[942]     ngx_http_proxy_main_conf_t  *pmcf;
[943] #endif
[944] 
[945]     if (ngx_http_upstream_create(r) != NGX_OK) {
[946]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[947]     }
[948] 
[949]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_ctx_t));
[950]     if (ctx == NULL) {
[951]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[952]     }
[953] 
[954]     ngx_http_set_ctx(r, ctx, ngx_http_proxy_module);
[955] 
[956]     plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
[957] 
[958]     u = r->upstream;
[959] 
[960]     if (plcf->proxy_lengths == NULL) {
[961]         ctx->vars = plcf->vars;
[962]         u->schema = plcf->vars.schema;
[963] #if (NGX_HTTP_SSL)
[964]         u->ssl = plcf->ssl;
[965] #endif
[966] 
[967]     } else {
[968]         if (ngx_http_proxy_eval(r, ctx, plcf) != NGX_OK) {
[969]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[970]         }
[971]     }
[972] 
[973]     u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_module;
[974] 
[975]     u->conf = &plcf->upstream;
[976] 
[977] #if (NGX_HTTP_CACHE)
[978]     pmcf = ngx_http_get_module_main_conf(r, ngx_http_proxy_module);
[979] 
[980]     u->caches = &pmcf->caches;
[981]     u->create_key = ngx_http_proxy_create_key;
[982] #endif
[983] 
[984]     u->create_request = ngx_http_proxy_create_request;
[985]     u->reinit_request = ngx_http_proxy_reinit_request;
[986]     u->process_header = ngx_http_proxy_process_status_line;
[987]     u->abort_request = ngx_http_proxy_abort_request;
[988]     u->finalize_request = ngx_http_proxy_finalize_request;
[989]     r->state = 0;
[990] 
[991]     if (plcf->redirects) {
[992]         u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
[993]     }
[994] 
[995]     if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
[996]         u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
[997]     }
[998] 
[999]     u->buffering = plcf->upstream.buffering;
[1000] 
[1001]     u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
[1002]     if (u->pipe == NULL) {
[1003]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1004]     }
[1005] 
[1006]     u->pipe->input_filter = ngx_http_proxy_copy_filter;
[1007]     u->pipe->input_ctx = r;
[1008] 
[1009]     u->input_filter_init = ngx_http_proxy_input_filter_init;
[1010]     u->input_filter = ngx_http_proxy_non_buffered_copy_filter;
[1011]     u->input_filter_ctx = r;
[1012] 
[1013]     u->accel = 1;
[1014] 
[1015]     if (!plcf->upstream.request_buffering
[1016]         && plcf->body_values == NULL && plcf->upstream.pass_request_body
[1017]         && (!r->headers_in.chunked
[1018]             || plcf->http_version == NGX_HTTP_VERSION_11))
[1019]     {
[1020]         r->request_body_no_buffering = 1;
[1021]     }
[1022] 
[1023]     rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
[1024] 
[1025]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[1026]         return rc;
[1027]     }
[1028] 
[1029]     return NGX_DONE;
[1030] }
[1031] 
[1032] 
[1033] static ngx_int_t
[1034] ngx_http_proxy_eval(ngx_http_request_t *r, ngx_http_proxy_ctx_t *ctx,
[1035]     ngx_http_proxy_loc_conf_t *plcf)
[1036] {
[1037]     u_char               *p;
[1038]     size_t                add;
[1039]     u_short               port;
[1040]     ngx_str_t             proxy;
[1041]     ngx_url_t             url;
[1042]     ngx_http_upstream_t  *u;
[1043] 
[1044]     if (ngx_http_script_run(r, &proxy, plcf->proxy_lengths->elts, 0,
[1045]                             plcf->proxy_values->elts)
[1046]         == NULL)
[1047]     {
[1048]         return NGX_ERROR;
[1049]     }
[1050] 
[1051]     if (proxy.len > 7
[1052]         && ngx_strncasecmp(proxy.data, (u_char *) "http://", 7) == 0)
[1053]     {
[1054]         add = 7;
[1055]         port = 80;
[1056] 
[1057] #if (NGX_HTTP_SSL)
[1058] 
[1059]     } else if (proxy.len > 8
[1060]                && ngx_strncasecmp(proxy.data, (u_char *) "https://", 8) == 0)
[1061]     {
[1062]         add = 8;
[1063]         port = 443;
[1064]         r->upstream->ssl = 1;
[1065] 
[1066] #endif
[1067] 
[1068]     } else {
[1069]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1070]                       "invalid URL prefix in \"%V\"", &proxy);
[1071]         return NGX_ERROR;
[1072]     }
[1073] 
[1074]     u = r->upstream;
[1075] 
[1076]     u->schema.len = add;
[1077]     u->schema.data = proxy.data;
[1078] 
[1079]     ngx_memzero(&url, sizeof(ngx_url_t));
[1080] 
[1081]     url.url.len = proxy.len - add;
[1082]     url.url.data = proxy.data + add;
[1083]     url.default_port = port;
[1084]     url.uri_part = 1;
[1085]     url.no_resolve = 1;
[1086] 
[1087]     if (ngx_parse_url(r->pool, &url) != NGX_OK) {
[1088]         if (url.err) {
[1089]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1090]                           "%s in upstream \"%V\"", url.err, &url.url);
[1091]         }
[1092] 
[1093]         return NGX_ERROR;
[1094]     }
[1095] 
[1096]     if (url.uri.len) {
[1097]         if (url.uri.data[0] == '?') {
[1098]             p = ngx_pnalloc(r->pool, url.uri.len + 1);
[1099]             if (p == NULL) {
[1100]                 return NGX_ERROR;
[1101]             }
[1102] 
[1103]             *p++ = '/';
[1104]             ngx_memcpy(p, url.uri.data, url.uri.len);
[1105] 
[1106]             url.uri.len++;
[1107]             url.uri.data = p - 1;
[1108]         }
[1109]     }
[1110] 
[1111]     ctx->vars.key_start = u->schema;
[1112] 
[1113]     ngx_http_proxy_set_vars(&url, &ctx->vars);
[1114] 
[1115]     u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
[1116]     if (u->resolved == NULL) {
[1117]         return NGX_ERROR;
[1118]     }
[1119] 
[1120]     if (url.addrs) {
[1121]         u->resolved->sockaddr = url.addrs[0].sockaddr;
[1122]         u->resolved->socklen = url.addrs[0].socklen;
[1123]         u->resolved->name = url.addrs[0].name;
[1124]         u->resolved->naddrs = 1;
[1125]     }
[1126] 
[1127]     u->resolved->host = url.host;
[1128]     u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
[1129]     u->resolved->no_port = url.no_port;
[1130] 
[1131]     return NGX_OK;
[1132] }
[1133] 
[1134] 
[1135] #if (NGX_HTTP_CACHE)
[1136] 
[1137] static ngx_int_t
[1138] ngx_http_proxy_create_key(ngx_http_request_t *r)
[1139] {
[1140]     size_t                      len, loc_len;
[1141]     u_char                     *p;
[1142]     uintptr_t                   escape;
[1143]     ngx_str_t                  *key;
[1144]     ngx_http_upstream_t        *u;
[1145]     ngx_http_proxy_ctx_t       *ctx;
[1146]     ngx_http_proxy_loc_conf_t  *plcf;
[1147] 
[1148]     u = r->upstream;
[1149] 
[1150]     plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
[1151] 
[1152]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[1153] 
[1154]     key = ngx_array_push(&r->cache->keys);
[1155]     if (key == NULL) {
[1156]         return NGX_ERROR;
[1157]     }
[1158] 
[1159]     if (plcf->cache_key.value.data) {
[1160] 
[1161]         if (ngx_http_complex_value(r, &plcf->cache_key, key) != NGX_OK) {
[1162]             return NGX_ERROR;
[1163]         }
[1164] 
[1165]         return NGX_OK;
[1166]     }
[1167] 
[1168]     *key = ctx->vars.key_start;
[1169] 
[1170]     key = ngx_array_push(&r->cache->keys);
[1171]     if (key == NULL) {
[1172]         return NGX_ERROR;
[1173]     }
[1174] 
[1175]     if (plcf->proxy_lengths && ctx->vars.uri.len) {
[1176] 
[1177]         *key = ctx->vars.uri;
[1178]         u->uri = ctx->vars.uri;
[1179] 
[1180]         return NGX_OK;
[1181] 
[1182]     } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
[1183]         *key = r->unparsed_uri;
[1184]         u->uri = r->unparsed_uri;
[1185] 
[1186]         return NGX_OK;
[1187]     }
[1188] 
[1189]     loc_len = (r->valid_location && ctx->vars.uri.len) ? plcf->location.len : 0;
[1190] 
[1191]     if (r->quoted_uri || r->internal) {
[1192]         escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
[1193]                                     r->uri.len - loc_len, NGX_ESCAPE_URI);
[1194]     } else {
[1195]         escape = 0;
[1196]     }
[1197] 
[1198]     len = ctx->vars.uri.len + r->uri.len - loc_len + escape
[1199]           + sizeof("?") - 1 + r->args.len;
[1200] 
[1201]     p = ngx_pnalloc(r->pool, len);
[1202]     if (p == NULL) {
[1203]         return NGX_ERROR;
[1204]     }
[1205] 
[1206]     key->data = p;
[1207] 
[1208]     if (r->valid_location) {
[1209]         p = ngx_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
[1210]     }
[1211] 
[1212]     if (escape) {
[1213]         ngx_escape_uri(p, r->uri.data + loc_len,
[1214]                        r->uri.len - loc_len, NGX_ESCAPE_URI);
[1215]         p += r->uri.len - loc_len + escape;
[1216] 
[1217]     } else {
[1218]         p = ngx_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
[1219]     }
[1220] 
[1221]     if (r->args.len > 0) {
[1222]         *p++ = '?';
[1223]         p = ngx_copy(p, r->args.data, r->args.len);
[1224]     }
[1225] 
[1226]     key->len = p - key->data;
[1227]     u->uri = *key;
[1228] 
[1229]     return NGX_OK;
[1230] }
[1231] 
[1232] #endif
[1233] 
[1234] 
[1235] static ngx_int_t
[1236] ngx_http_proxy_create_request(ngx_http_request_t *r)
[1237] {
[1238]     size_t                        len, uri_len, loc_len, body_len,
[1239]                                   key_len, val_len;
[1240]     uintptr_t                     escape;
[1241]     ngx_buf_t                    *b;
[1242]     ngx_str_t                     method;
[1243]     ngx_uint_t                    i, unparsed_uri;
[1244]     ngx_chain_t                  *cl, *body;
[1245]     ngx_list_part_t              *part;
[1246]     ngx_table_elt_t              *header;
[1247]     ngx_http_upstream_t          *u;
[1248]     ngx_http_proxy_ctx_t         *ctx;
[1249]     ngx_http_script_code_pt       code;
[1250]     ngx_http_proxy_headers_t     *headers;
[1251]     ngx_http_script_engine_t      e, le;
[1252]     ngx_http_proxy_loc_conf_t    *plcf;
[1253]     ngx_http_script_len_code_pt   lcode;
[1254] 
[1255]     u = r->upstream;
[1256] 
[1257]     plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
[1258] 
[1259] #if (NGX_HTTP_CACHE)
[1260]     headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
[1261] #else
[1262]     headers = &plcf->headers;
[1263] #endif
[1264] 
[1265]     if (u->method.len) {
[1266]         /* HEAD was changed to GET to cache response */
[1267]         method = u->method;
[1268] 
[1269]     } else if (plcf->method) {
[1270]         if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
[1271]             return NGX_ERROR;
[1272]         }
[1273] 
[1274]     } else {
[1275]         method = r->method_name;
[1276]     }
[1277] 
[1278]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[1279] 
[1280]     if (method.len == 4
[1281]         && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
[1282]     {
[1283]         ctx->head = 1;
[1284]     }
[1285] 
[1286]     len = method.len + 1 + sizeof(ngx_http_proxy_version) - 1
[1287]           + sizeof(CRLF) - 1;
[1288] 
[1289]     escape = 0;
[1290]     loc_len = 0;
[1291]     unparsed_uri = 0;
[1292] 
[1293]     if (plcf->proxy_lengths && ctx->vars.uri.len) {
[1294]         uri_len = ctx->vars.uri.len;
[1295] 
[1296]     } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
[1297]         unparsed_uri = 1;
[1298]         uri_len = r->unparsed_uri.len;
[1299] 
[1300]     } else {
[1301]         loc_len = (r->valid_location && ctx->vars.uri.len) ?
[1302]                       plcf->location.len : 0;
[1303] 
[1304]         if (r->quoted_uri || r->internal) {
[1305]             escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
[1306]                                         r->uri.len - loc_len, NGX_ESCAPE_URI);
[1307]         }
[1308] 
[1309]         uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
[1310]                   + sizeof("?") - 1 + r->args.len;
[1311]     }
[1312] 
[1313]     if (uri_len == 0) {
[1314]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1315]                       "zero length URI to proxy");
[1316]         return NGX_ERROR;
[1317]     }
[1318] 
[1319]     len += uri_len;
[1320] 
[1321]     ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[1322] 
[1323]     ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
[1324]     ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);
[1325] 
[1326]     if (plcf->body_lengths) {
[1327]         le.ip = plcf->body_lengths->elts;
[1328]         le.request = r;
[1329]         le.flushed = 1;
[1330]         body_len = 0;
[1331] 
[1332]         while (*(uintptr_t *) le.ip) {
[1333]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1334]             body_len += lcode(&le);
[1335]         }
[1336] 
[1337]         ctx->internal_body_length = body_len;
[1338]         len += body_len;
[1339] 
[1340]     } else if (r->headers_in.chunked && r->reading_body) {
[1341]         ctx->internal_body_length = -1;
[1342]         ctx->internal_chunked = 1;
[1343] 
[1344]     } else {
[1345]         ctx->internal_body_length = r->headers_in.content_length_n;
[1346]     }
[1347] 
[1348]     le.ip = headers->lengths->elts;
[1349]     le.request = r;
[1350]     le.flushed = 1;
[1351] 
[1352]     while (*(uintptr_t *) le.ip) {
[1353] 
[1354]         lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1355]         key_len = lcode(&le);
[1356] 
[1357]         for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[1358]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1359]         }
[1360]         le.ip += sizeof(uintptr_t);
[1361] 
[1362]         if (val_len == 0) {
[1363]             continue;
[1364]         }
[1365] 
[1366]         len += key_len + sizeof(": ") - 1 + val_len + sizeof(CRLF) - 1;
[1367]     }
[1368] 
[1369] 
[1370]     if (plcf->upstream.pass_request_headers) {
[1371]         part = &r->headers_in.headers.part;
[1372]         header = part->elts;
[1373] 
[1374]         for (i = 0; /* void */; i++) {
[1375] 
[1376]             if (i >= part->nelts) {
[1377]                 if (part->next == NULL) {
[1378]                     break;
[1379]                 }
[1380] 
[1381]                 part = part->next;
[1382]                 header = part->elts;
[1383]                 i = 0;
[1384]             }
[1385] 
[1386]             if (ngx_hash_find(&headers->hash, header[i].hash,
[1387]                               header[i].lowcase_key, header[i].key.len))
[1388]             {
[1389]                 continue;
[1390]             }
[1391] 
[1392]             len += header[i].key.len + sizeof(": ") - 1
[1393]                 + header[i].value.len + sizeof(CRLF) - 1;
[1394]         }
[1395]     }
[1396] 
[1397] 
[1398]     b = ngx_create_temp_buf(r->pool, len);
[1399]     if (b == NULL) {
[1400]         return NGX_ERROR;
[1401]     }
[1402] 
[1403]     cl = ngx_alloc_chain_link(r->pool);
[1404]     if (cl == NULL) {
[1405]         return NGX_ERROR;
[1406]     }
[1407] 
[1408]     cl->buf = b;
[1409] 
[1410] 
[1411]     /* the request line */
[1412] 
[1413]     b->last = ngx_copy(b->last, method.data, method.len);
[1414]     *b->last++ = ' ';
[1415] 
[1416]     u->uri.data = b->last;
[1417] 
[1418]     if (plcf->proxy_lengths && ctx->vars.uri.len) {
[1419]         b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
[1420] 
[1421]     } else if (unparsed_uri) {
[1422]         b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);
[1423] 
[1424]     } else {
[1425]         if (r->valid_location) {
[1426]             b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
[1427]         }
[1428] 
[1429]         if (escape) {
[1430]             ngx_escape_uri(b->last, r->uri.data + loc_len,
[1431]                            r->uri.len - loc_len, NGX_ESCAPE_URI);
[1432]             b->last += r->uri.len - loc_len + escape;
[1433] 
[1434]         } else {
[1435]             b->last = ngx_copy(b->last, r->uri.data + loc_len,
[1436]                                r->uri.len - loc_len);
[1437]         }
[1438] 
[1439]         if (r->args.len > 0) {
[1440]             *b->last++ = '?';
[1441]             b->last = ngx_copy(b->last, r->args.data, r->args.len);
[1442]         }
[1443]     }
[1444] 
[1445]     u->uri.len = b->last - u->uri.data;
[1446] 
[1447]     if (plcf->http_version == NGX_HTTP_VERSION_11) {
[1448]         b->last = ngx_cpymem(b->last, ngx_http_proxy_version_11,
[1449]                              sizeof(ngx_http_proxy_version_11) - 1);
[1450] 
[1451]     } else {
[1452]         b->last = ngx_cpymem(b->last, ngx_http_proxy_version,
[1453]                              sizeof(ngx_http_proxy_version) - 1);
[1454]     }
[1455] 
[1456]     ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[1457] 
[1458]     e.ip = headers->values->elts;
[1459]     e.pos = b->last;
[1460]     e.request = r;
[1461]     e.flushed = 1;
[1462] 
[1463]     le.ip = headers->lengths->elts;
[1464] 
[1465]     while (*(uintptr_t *) le.ip) {
[1466] 
[1467]         lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1468]         (void) lcode(&le);
[1469] 
[1470]         for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[1471]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1472]         }
[1473]         le.ip += sizeof(uintptr_t);
[1474] 
[1475]         if (val_len == 0) {
[1476]             e.skip = 1;
[1477] 
[1478]             while (*(uintptr_t *) e.ip) {
[1479]                 code = *(ngx_http_script_code_pt *) e.ip;
[1480]                 code((ngx_http_script_engine_t *) &e);
[1481]             }
[1482]             e.ip += sizeof(uintptr_t);
[1483] 
[1484]             e.skip = 0;
[1485] 
[1486]             continue;
[1487]         }
[1488] 
[1489]         code = *(ngx_http_script_code_pt *) e.ip;
[1490]         code((ngx_http_script_engine_t *) &e);
[1491] 
[1492]         *e.pos++ = ':'; *e.pos++ = ' ';
[1493] 
[1494]         while (*(uintptr_t *) e.ip) {
[1495]             code = *(ngx_http_script_code_pt *) e.ip;
[1496]             code((ngx_http_script_engine_t *) &e);
[1497]         }
[1498]         e.ip += sizeof(uintptr_t);
[1499] 
[1500]         *e.pos++ = CR; *e.pos++ = LF;
[1501]     }
[1502] 
[1503]     b->last = e.pos;
[1504] 
[1505] 
[1506]     if (plcf->upstream.pass_request_headers) {
[1507]         part = &r->headers_in.headers.part;
[1508]         header = part->elts;
[1509] 
[1510]         for (i = 0; /* void */; i++) {
[1511] 
[1512]             if (i >= part->nelts) {
[1513]                 if (part->next == NULL) {
[1514]                     break;
[1515]                 }
[1516] 
[1517]                 part = part->next;
[1518]                 header = part->elts;
[1519]                 i = 0;
[1520]             }
[1521] 
[1522]             if (ngx_hash_find(&headers->hash, header[i].hash,
[1523]                               header[i].lowcase_key, header[i].key.len))
[1524]             {
[1525]                 continue;
[1526]             }
[1527] 
[1528]             b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
[1529] 
[1530]             *b->last++ = ':'; *b->last++ = ' ';
[1531] 
[1532]             b->last = ngx_copy(b->last, header[i].value.data,
[1533]                                header[i].value.len);
[1534] 
[1535]             *b->last++ = CR; *b->last++ = LF;
[1536] 
[1537]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1538]                            "http proxy header: \"%V: %V\"",
[1539]                            &header[i].key, &header[i].value);
[1540]         }
[1541]     }
[1542] 
[1543] 
[1544]     /* add "\r\n" at the header end */
[1545]     *b->last++ = CR; *b->last++ = LF;
[1546] 
[1547]     if (plcf->body_values) {
[1548]         e.ip = plcf->body_values->elts;
[1549]         e.pos = b->last;
[1550]         e.skip = 0;
[1551] 
[1552]         while (*(uintptr_t *) e.ip) {
[1553]             code = *(ngx_http_script_code_pt *) e.ip;
[1554]             code((ngx_http_script_engine_t *) &e);
[1555]         }
[1556] 
[1557]         b->last = e.pos;
[1558]     }
[1559] 
[1560]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1561]                    "http proxy header:%N\"%*s\"",
[1562]                    (size_t) (b->last - b->pos), b->pos);
[1563] 
[1564]     if (r->request_body_no_buffering) {
[1565] 
[1566]         u->request_bufs = cl;
[1567] 
[1568]         if (ctx->internal_chunked) {
[1569]             u->output.output_filter = ngx_http_proxy_body_output_filter;
[1570]             u->output.filter_ctx = r;
[1571]         }
[1572] 
[1573]     } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {
[1574] 
[1575]         body = u->request_bufs;
[1576]         u->request_bufs = cl;
[1577] 
[1578]         while (body) {
[1579]             b = ngx_alloc_buf(r->pool);
[1580]             if (b == NULL) {
[1581]                 return NGX_ERROR;
[1582]             }
[1583] 
[1584]             ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
[1585] 
[1586]             cl->next = ngx_alloc_chain_link(r->pool);
[1587]             if (cl->next == NULL) {
[1588]                 return NGX_ERROR;
[1589]             }
[1590] 
[1591]             cl = cl->next;
[1592]             cl->buf = b;
[1593] 
[1594]             body = body->next;
[1595]         }
[1596] 
[1597]     } else {
[1598]         u->request_bufs = cl;
[1599]     }
[1600] 
[1601]     b->flush = 1;
[1602]     cl->next = NULL;
[1603] 
[1604]     return NGX_OK;
[1605] }
[1606] 
[1607] 
[1608] static ngx_int_t
[1609] ngx_http_proxy_reinit_request(ngx_http_request_t *r)
[1610] {
[1611]     ngx_http_proxy_ctx_t  *ctx;
[1612] 
[1613]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[1614] 
[1615]     if (ctx == NULL) {
[1616]         return NGX_OK;
[1617]     }
[1618] 
[1619]     ctx->status.code = 0;
[1620]     ctx->status.count = 0;
[1621]     ctx->status.start = NULL;
[1622]     ctx->status.end = NULL;
[1623]     ctx->chunked.state = 0;
[1624] 
[1625]     r->upstream->process_header = ngx_http_proxy_process_status_line;
[1626]     r->upstream->pipe->input_filter = ngx_http_proxy_copy_filter;
[1627]     r->upstream->input_filter = ngx_http_proxy_non_buffered_copy_filter;
[1628]     r->state = 0;
[1629] 
[1630]     return NGX_OK;
[1631] }
[1632] 
[1633] 
[1634] static ngx_int_t
[1635] ngx_http_proxy_body_output_filter(void *data, ngx_chain_t *in)
[1636] {
[1637]     ngx_http_request_t  *r = data;
[1638] 
[1639]     off_t                  size;
[1640]     u_char                *chunk;
[1641]     ngx_int_t              rc;
[1642]     ngx_buf_t             *b;
[1643]     ngx_chain_t           *out, *cl, *tl, **ll, **fl;
[1644]     ngx_http_proxy_ctx_t  *ctx;
[1645] 
[1646]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1647]                    "proxy output filter");
[1648] 
[1649]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[1650] 
[1651]     if (in == NULL) {
[1652]         out = in;
[1653]         goto out;
[1654]     }
[1655] 
[1656]     out = NULL;
[1657]     ll = &out;
[1658] 
[1659]     if (!ctx->header_sent) {
[1660]         /* first buffer contains headers, pass it unmodified */
[1661] 
[1662]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1663]                        "proxy output header");
[1664] 
[1665]         ctx->header_sent = 1;
[1666] 
[1667]         tl = ngx_alloc_chain_link(r->pool);
[1668]         if (tl == NULL) {
[1669]             return NGX_ERROR;
[1670]         }
[1671] 
[1672]         tl->buf = in->buf;
[1673]         *ll = tl;
[1674]         ll = &tl->next;
[1675] 
[1676]         in = in->next;
[1677] 
[1678]         if (in == NULL) {
[1679]             tl->next = NULL;
[1680]             goto out;
[1681]         }
[1682]     }
[1683] 
[1684]     size = 0;
[1685]     cl = in;
[1686]     fl = ll;
[1687] 
[1688]     for ( ;; ) {
[1689]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1690]                        "proxy output chunk: %O", ngx_buf_size(cl->buf));
[1691] 
[1692]         size += ngx_buf_size(cl->buf);
[1693] 
[1694]         if (cl->buf->flush
[1695]             || cl->buf->sync
[1696]             || ngx_buf_in_memory(cl->buf)
[1697]             || cl->buf->in_file)
[1698]         {
[1699]             tl = ngx_alloc_chain_link(r->pool);
[1700]             if (tl == NULL) {
[1701]                 return NGX_ERROR;
[1702]             }
[1703] 
[1704]             tl->buf = cl->buf;
[1705]             *ll = tl;
[1706]             ll = &tl->next;
[1707]         }
[1708] 
[1709]         if (cl->next == NULL) {
[1710]             break;
[1711]         }
[1712] 
[1713]         cl = cl->next;
[1714]     }
[1715] 
[1716]     if (size) {
[1717]         tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[1718]         if (tl == NULL) {
[1719]             return NGX_ERROR;
[1720]         }
[1721] 
[1722]         b = tl->buf;
[1723]         chunk = b->start;
[1724] 
[1725]         if (chunk == NULL) {
[1726]             /* the "0000000000000000" is 64-bit hexadecimal string */
[1727] 
[1728]             chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
[1729]             if (chunk == NULL) {
[1730]                 return NGX_ERROR;
[1731]             }
[1732] 
[1733]             b->start = chunk;
[1734]             b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
[1735]         }
[1736] 
[1737]         b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
[1738]         b->memory = 0;
[1739]         b->temporary = 1;
[1740]         b->pos = chunk;
[1741]         b->last = ngx_sprintf(chunk, "%xO" CRLF, size);
[1742] 
[1743]         tl->next = *fl;
[1744]         *fl = tl;
[1745]     }
[1746] 
[1747]     if (cl->buf->last_buf) {
[1748]         tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[1749]         if (tl == NULL) {
[1750]             return NGX_ERROR;
[1751]         }
[1752] 
[1753]         b = tl->buf;
[1754] 
[1755]         b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
[1756]         b->temporary = 0;
[1757]         b->memory = 1;
[1758]         b->last_buf = 1;
[1759]         b->pos = (u_char *) CRLF "0" CRLF CRLF;
[1760]         b->last = b->pos + 7;
[1761] 
[1762]         cl->buf->last_buf = 0;
[1763] 
[1764]         *ll = tl;
[1765] 
[1766]         if (size == 0) {
[1767]             b->pos += 2;
[1768]         }
[1769] 
[1770]     } else if (size > 0) {
[1771]         tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[1772]         if (tl == NULL) {
[1773]             return NGX_ERROR;
[1774]         }
[1775] 
[1776]         b = tl->buf;
[1777] 
[1778]         b->tag = (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter;
[1779]         b->temporary = 0;
[1780]         b->memory = 1;
[1781]         b->pos = (u_char *) CRLF;
[1782]         b->last = b->pos + 2;
[1783] 
[1784]         *ll = tl;
[1785] 
[1786]     } else {
[1787]         *ll = NULL;
[1788]     }
[1789] 
[1790] out:
[1791] 
[1792]     rc = ngx_chain_writer(&r->upstream->writer, out);
[1793] 
[1794]     ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
[1795]                             (ngx_buf_tag_t) &ngx_http_proxy_body_output_filter);
[1796] 
[1797]     return rc;
[1798] }
[1799] 
[1800] 
[1801] static ngx_int_t
[1802] ngx_http_proxy_process_status_line(ngx_http_request_t *r)
[1803] {
[1804]     size_t                 len;
[1805]     ngx_int_t              rc;
[1806]     ngx_http_upstream_t   *u;
[1807]     ngx_http_proxy_ctx_t  *ctx;
[1808] 
[1809]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[1810] 
[1811]     if (ctx == NULL) {
[1812]         return NGX_ERROR;
[1813]     }
[1814] 
[1815]     u = r->upstream;
[1816] 
[1817]     rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
[1818] 
[1819]     if (rc == NGX_AGAIN) {
[1820]         return rc;
[1821]     }
[1822] 
[1823]     if (rc == NGX_ERROR) {
[1824] 
[1825] #if (NGX_HTTP_CACHE)
[1826] 
[1827]         if (r->cache) {
[1828]             r->http_version = NGX_HTTP_VERSION_9;
[1829]             return NGX_OK;
[1830]         }
[1831] 
[1832] #endif
[1833] 
[1834]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1835]                       "upstream sent no valid HTTP/1.0 header");
[1836] 
[1837] #if 0
[1838]         if (u->accel) {
[1839]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1840]         }
[1841] #endif
[1842] 
[1843]         r->http_version = NGX_HTTP_VERSION_9;
[1844]         u->state->status = NGX_HTTP_OK;
[1845]         u->headers_in.connection_close = 1;
[1846] 
[1847]         return NGX_OK;
[1848]     }
[1849] 
[1850]     if (u->state && u->state->status == 0) {
[1851]         u->state->status = ctx->status.code;
[1852]     }
[1853] 
[1854]     u->headers_in.status_n = ctx->status.code;
[1855] 
[1856]     len = ctx->status.end - ctx->status.start;
[1857]     u->headers_in.status_line.len = len;
[1858] 
[1859]     u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
[1860]     if (u->headers_in.status_line.data == NULL) {
[1861]         return NGX_ERROR;
[1862]     }
[1863] 
[1864]     ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
[1865] 
[1866]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1867]                    "http proxy status %ui \"%V\"",
[1868]                    u->headers_in.status_n, &u->headers_in.status_line);
[1869] 
[1870]     if (ctx->status.http_version < NGX_HTTP_VERSION_11) {
[1871]         u->headers_in.connection_close = 1;
[1872]     }
[1873] 
[1874]     u->process_header = ngx_http_proxy_process_header;
[1875] 
[1876]     return ngx_http_proxy_process_header(r);
[1877] }
[1878] 
[1879] 
[1880] static ngx_int_t
[1881] ngx_http_proxy_process_header(ngx_http_request_t *r)
[1882] {
[1883]     ngx_int_t                       rc;
[1884]     ngx_table_elt_t                *h;
[1885]     ngx_http_upstream_t            *u;
[1886]     ngx_http_proxy_ctx_t           *ctx;
[1887]     ngx_http_upstream_header_t     *hh;
[1888]     ngx_http_upstream_main_conf_t  *umcf;
[1889] 
[1890]     umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[1891] 
[1892]     for ( ;; ) {
[1893] 
[1894]         rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
[1895] 
[1896]         if (rc == NGX_OK) {
[1897] 
[1898]             /* a header line has been parsed successfully */
[1899] 
[1900]             h = ngx_list_push(&r->upstream->headers_in.headers);
[1901]             if (h == NULL) {
[1902]                 return NGX_ERROR;
[1903]             }
[1904] 
[1905]             h->hash = r->header_hash;
[1906] 
[1907]             h->key.len = r->header_name_end - r->header_name_start;
[1908]             h->value.len = r->header_end - r->header_start;
[1909] 
[1910]             h->key.data = ngx_pnalloc(r->pool,
[1911]                                h->key.len + 1 + h->value.len + 1 + h->key.len);
[1912]             if (h->key.data == NULL) {
[1913]                 h->hash = 0;
[1914]                 return NGX_ERROR;
[1915]             }
[1916] 
[1917]             h->value.data = h->key.data + h->key.len + 1;
[1918]             h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
[1919] 
[1920]             ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
[1921]             h->key.data[h->key.len] = '\0';
[1922]             ngx_memcpy(h->value.data, r->header_start, h->value.len);
[1923]             h->value.data[h->value.len] = '\0';
[1924] 
[1925]             if (h->key.len == r->lowcase_index) {
[1926]                 ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
[1927] 
[1928]             } else {
[1929]                 ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
[1930]             }
[1931] 
[1932]             hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
[1933]                                h->lowcase_key, h->key.len);
[1934] 
[1935]             if (hh) {
[1936]                 rc = hh->handler(r, h, hh->offset);
[1937] 
[1938]                 if (rc != NGX_OK) {
[1939]                     return rc;
[1940]                 }
[1941]             }
[1942] 
[1943]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1944]                            "http proxy header: \"%V: %V\"",
[1945]                            &h->key, &h->value);
[1946] 
[1947]             continue;
[1948]         }
[1949] 
[1950]         if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[1951] 
[1952]             /* a whole header has been parsed successfully */
[1953] 
[1954]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1955]                            "http proxy header done");
[1956] 
[1957]             /*
[1958]              * if no "Server" and "Date" in header line,
[1959]              * then add the special empty headers
[1960]              */
[1961] 
[1962]             if (r->upstream->headers_in.server == NULL) {
[1963]                 h = ngx_list_push(&r->upstream->headers_in.headers);
[1964]                 if (h == NULL) {
[1965]                     return NGX_ERROR;
[1966]                 }
[1967] 
[1968]                 h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
[1969]                                     ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
[1970] 
[1971]                 ngx_str_set(&h->key, "Server");
[1972]                 ngx_str_null(&h->value);
[1973]                 h->lowcase_key = (u_char *) "server";
[1974]                 h->next = NULL;
[1975]             }
[1976] 
[1977]             if (r->upstream->headers_in.date == NULL) {
[1978]                 h = ngx_list_push(&r->upstream->headers_in.headers);
[1979]                 if (h == NULL) {
[1980]                     return NGX_ERROR;
[1981]                 }
[1982] 
[1983]                 h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
[1984] 
[1985]                 ngx_str_set(&h->key, "Date");
[1986]                 ngx_str_null(&h->value);
[1987]                 h->lowcase_key = (u_char *) "date";
[1988]                 h->next = NULL;
[1989]             }
[1990] 
[1991]             /* clear content length if response is chunked */
[1992] 
[1993]             u = r->upstream;
[1994] 
[1995]             if (u->headers_in.chunked) {
[1996]                 u->headers_in.content_length_n = -1;
[1997]             }
[1998] 
[1999]             /*
[2000]              * set u->keepalive if response has no body; this allows to keep
[2001]              * connections alive in case of r->header_only or X-Accel-Redirect
[2002]              */
[2003] 
[2004]             ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2005] 
[2006]             if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
[2007]                 || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
[2008]                 || ctx->head
[2009]                 || (!u->headers_in.chunked
[2010]                     && u->headers_in.content_length_n == 0))
[2011]             {
[2012]                 u->keepalive = !u->headers_in.connection_close;
[2013]             }
[2014] 
[2015]             if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS) {
[2016]                 u->keepalive = 0;
[2017] 
[2018]                 if (r->headers_in.upgrade) {
[2019]                     u->upgrade = 1;
[2020]                 }
[2021]             }
[2022] 
[2023]             return NGX_OK;
[2024]         }
[2025] 
[2026]         if (rc == NGX_AGAIN) {
[2027]             return NGX_AGAIN;
[2028]         }
[2029] 
[2030]         /* rc == NGX_HTTP_PARSE_INVALID_HEADER */
[2031] 
[2032]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2033]                       "upstream sent invalid header: \"%*s\\x%02xd...\"",
[2034]                       r->header_end - r->header_name_start,
[2035]                       r->header_name_start, *r->header_end);
[2036] 
[2037]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[2038]     }
[2039] }
[2040] 
[2041] 
[2042] static ngx_int_t
[2043] ngx_http_proxy_input_filter_init(void *data)
[2044] {
[2045]     ngx_http_request_t    *r = data;
[2046]     ngx_http_upstream_t   *u;
[2047]     ngx_http_proxy_ctx_t  *ctx;
[2048] 
[2049]     u = r->upstream;
[2050]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2051] 
[2052]     if (ctx == NULL) {
[2053]         return NGX_ERROR;
[2054]     }
[2055] 
[2056]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2057]                    "http proxy filter init s:%ui h:%d c:%d l:%O",
[2058]                    u->headers_in.status_n, ctx->head, u->headers_in.chunked,
[2059]                    u->headers_in.content_length_n);
[2060] 
[2061]     /* as per RFC2616, 4.4 Message Length */
[2062] 
[2063]     if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
[2064]         || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
[2065]         || ctx->head)
[2066]     {
[2067]         /* 1xx, 204, and 304 and replies to HEAD requests */
[2068]         /* no 1xx since we don't send Expect and Upgrade */
[2069] 
[2070]         u->pipe->length = 0;
[2071]         u->length = 0;
[2072]         u->keepalive = !u->headers_in.connection_close;
[2073] 
[2074]     } else if (u->headers_in.chunked) {
[2075]         /* chunked */
[2076] 
[2077]         u->pipe->input_filter = ngx_http_proxy_chunked_filter;
[2078]         u->pipe->length = 3; /* "0" LF LF */
[2079] 
[2080]         u->input_filter = ngx_http_proxy_non_buffered_chunked_filter;
[2081]         u->length = 1;
[2082] 
[2083]     } else if (u->headers_in.content_length_n == 0) {
[2084]         /* empty body: special case as filter won't be called */
[2085] 
[2086]         u->pipe->length = 0;
[2087]         u->length = 0;
[2088]         u->keepalive = !u->headers_in.connection_close;
[2089] 
[2090]     } else {
[2091]         /* content length or connection close */
[2092] 
[2093]         u->pipe->length = u->headers_in.content_length_n;
[2094]         u->length = u->headers_in.content_length_n;
[2095]     }
[2096] 
[2097]     return NGX_OK;
[2098] }
[2099] 
[2100] 
[2101] static ngx_int_t
[2102] ngx_http_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
[2103] {
[2104]     ngx_buf_t           *b;
[2105]     ngx_chain_t         *cl;
[2106]     ngx_http_request_t  *r;
[2107] 
[2108]     if (buf->pos == buf->last) {
[2109]         return NGX_OK;
[2110]     }
[2111] 
[2112]     if (p->upstream_done) {
[2113]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
[2114]                        "http proxy data after close");
[2115]         return NGX_OK;
[2116]     }
[2117] 
[2118]     if (p->length == 0) {
[2119] 
[2120]         ngx_log_error(NGX_LOG_WARN, p->log, 0,
[2121]                       "upstream sent more data than specified in "
[2122]                       "\"Content-Length\" header");
[2123] 
[2124]         r = p->input_ctx;
[2125]         r->upstream->keepalive = 0;
[2126]         p->upstream_done = 1;
[2127] 
[2128]         return NGX_OK;
[2129]     }
[2130] 
[2131]     cl = ngx_chain_get_free_buf(p->pool, &p->free);
[2132]     if (cl == NULL) {
[2133]         return NGX_ERROR;
[2134]     }
[2135] 
[2136]     b = cl->buf;
[2137] 
[2138]     ngx_memcpy(b, buf, sizeof(ngx_buf_t));
[2139]     b->shadow = buf;
[2140]     b->tag = p->tag;
[2141]     b->last_shadow = 1;
[2142]     b->recycled = 1;
[2143]     buf->shadow = b;
[2144] 
[2145]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);
[2146] 
[2147]     if (p->in) {
[2148]         *p->last_in = cl;
[2149]     } else {
[2150]         p->in = cl;
[2151]     }
[2152]     p->last_in = &cl->next;
[2153] 
[2154]     if (p->length == -1) {
[2155]         return NGX_OK;
[2156]     }
[2157] 
[2158]     if (b->last - b->pos > p->length) {
[2159] 
[2160]         ngx_log_error(NGX_LOG_WARN, p->log, 0,
[2161]                       "upstream sent more data than specified in "
[2162]                       "\"Content-Length\" header");
[2163] 
[2164]         b->last = b->pos + p->length;
[2165]         p->upstream_done = 1;
[2166] 
[2167]         return NGX_OK;
[2168]     }
[2169] 
[2170]     p->length -= b->last - b->pos;
[2171] 
[2172]     if (p->length == 0) {
[2173]         r = p->input_ctx;
[2174]         r->upstream->keepalive = !r->upstream->headers_in.connection_close;
[2175]     }
[2176] 
[2177]     return NGX_OK;
[2178] }
[2179] 
[2180] 
[2181] static ngx_int_t
[2182] ngx_http_proxy_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
[2183] {
[2184]     ngx_int_t              rc;
[2185]     ngx_buf_t             *b, **prev;
[2186]     ngx_chain_t           *cl;
[2187]     ngx_http_request_t    *r;
[2188]     ngx_http_proxy_ctx_t  *ctx;
[2189] 
[2190]     if (buf->pos == buf->last) {
[2191]         return NGX_OK;
[2192]     }
[2193] 
[2194]     r = p->input_ctx;
[2195]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2196] 
[2197]     if (ctx == NULL) {
[2198]         return NGX_ERROR;
[2199]     }
[2200] 
[2201]     if (p->upstream_done) {
[2202]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
[2203]                        "http proxy data after close");
[2204]         return NGX_OK;
[2205]     }
[2206] 
[2207]     if (p->length == 0) {
[2208] 
[2209]         ngx_log_error(NGX_LOG_WARN, p->log, 0,
[2210]                       "upstream sent data after final chunk");
[2211] 
[2212]         r->upstream->keepalive = 0;
[2213]         p->upstream_done = 1;
[2214] 
[2215]         return NGX_OK;
[2216]     }
[2217] 
[2218]     b = NULL;
[2219]     prev = &buf->shadow;
[2220] 
[2221]     for ( ;; ) {
[2222] 
[2223]         rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);
[2224] 
[2225]         if (rc == NGX_OK) {
[2226] 
[2227]             /* a chunk has been parsed successfully */
[2228] 
[2229]             cl = ngx_chain_get_free_buf(p->pool, &p->free);
[2230]             if (cl == NULL) {
[2231]                 return NGX_ERROR;
[2232]             }
[2233] 
[2234]             b = cl->buf;
[2235] 
[2236]             ngx_memzero(b, sizeof(ngx_buf_t));
[2237] 
[2238]             b->pos = buf->pos;
[2239]             b->start = buf->start;
[2240]             b->end = buf->end;
[2241]             b->tag = p->tag;
[2242]             b->temporary = 1;
[2243]             b->recycled = 1;
[2244] 
[2245]             *prev = b;
[2246]             prev = &b->shadow;
[2247] 
[2248]             if (p->in) {
[2249]                 *p->last_in = cl;
[2250]             } else {
[2251]                 p->in = cl;
[2252]             }
[2253]             p->last_in = &cl->next;
[2254] 
[2255]             /* STUB */ b->num = buf->num;
[2256] 
[2257]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
[2258]                            "input buf #%d %p", b->num, b->pos);
[2259] 
[2260]             if (buf->last - buf->pos >= ctx->chunked.size) {
[2261] 
[2262]                 buf->pos += (size_t) ctx->chunked.size;
[2263]                 b->last = buf->pos;
[2264]                 ctx->chunked.size = 0;
[2265] 
[2266]                 continue;
[2267]             }
[2268] 
[2269]             ctx->chunked.size -= buf->last - buf->pos;
[2270]             buf->pos = buf->last;
[2271]             b->last = buf->last;
[2272] 
[2273]             continue;
[2274]         }
[2275] 
[2276]         if (rc == NGX_DONE) {
[2277] 
[2278]             /* a whole response has been parsed successfully */
[2279] 
[2280]             p->length = 0;
[2281]             r->upstream->keepalive = !r->upstream->headers_in.connection_close;
[2282] 
[2283]             if (buf->pos != buf->last) {
[2284]                 ngx_log_error(NGX_LOG_WARN, p->log, 0,
[2285]                               "upstream sent data after final chunk");
[2286]                 r->upstream->keepalive = 0;
[2287]             }
[2288] 
[2289]             break;
[2290]         }
[2291] 
[2292]         if (rc == NGX_AGAIN) {
[2293] 
[2294]             /* set p->length, minimal amount of data we want to see */
[2295] 
[2296]             p->length = ctx->chunked.length;
[2297] 
[2298]             break;
[2299]         }
[2300] 
[2301]         /* invalid response */
[2302] 
[2303]         ngx_log_error(NGX_LOG_ERR, p->log, 0,
[2304]                       "upstream sent invalid chunked response");
[2305] 
[2306]         return NGX_ERROR;
[2307]     }
[2308] 
[2309]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
[2310]                    "http proxy chunked state %ui, length %O",
[2311]                    ctx->chunked.state, p->length);
[2312] 
[2313]     if (b) {
[2314]         b->shadow = buf;
[2315]         b->last_shadow = 1;
[2316] 
[2317]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
[2318]                        "input buf %p %z", b->pos, b->last - b->pos);
[2319] 
[2320]         return NGX_OK;
[2321]     }
[2322] 
[2323]     /* there is no data record in the buf, add it to free chain */
[2324] 
[2325]     if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
[2326]         return NGX_ERROR;
[2327]     }
[2328] 
[2329]     return NGX_OK;
[2330] }
[2331] 
[2332] 
[2333] static ngx_int_t
[2334] ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
[2335] {
[2336]     ngx_http_request_t   *r = data;
[2337] 
[2338]     ngx_buf_t            *b;
[2339]     ngx_chain_t          *cl, **ll;
[2340]     ngx_http_upstream_t  *u;
[2341] 
[2342]     u = r->upstream;
[2343] 
[2344]     if (u->length == 0) {
[2345]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[2346]                       "upstream sent more data than specified in "
[2347]                       "\"Content-Length\" header");
[2348]         u->keepalive = 0;
[2349]         return NGX_OK;
[2350]     }
[2351] 
[2352]     for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
[2353]         ll = &cl->next;
[2354]     }
[2355] 
[2356]     cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
[2357]     if (cl == NULL) {
[2358]         return NGX_ERROR;
[2359]     }
[2360] 
[2361]     *ll = cl;
[2362] 
[2363]     cl->buf->flush = 1;
[2364]     cl->buf->memory = 1;
[2365] 
[2366]     b = &u->buffer;
[2367] 
[2368]     cl->buf->pos = b->last;
[2369]     b->last += bytes;
[2370]     cl->buf->last = b->last;
[2371]     cl->buf->tag = u->output.tag;
[2372] 
[2373]     if (u->length == -1) {
[2374]         return NGX_OK;
[2375]     }
[2376] 
[2377]     if (bytes > u->length) {
[2378] 
[2379]         ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[2380]                       "upstream sent more data than specified in "
[2381]                       "\"Content-Length\" header");
[2382] 
[2383]         cl->buf->last = cl->buf->pos + u->length;
[2384]         u->length = 0;
[2385] 
[2386]         return NGX_OK;
[2387]     }
[2388] 
[2389]     u->length -= bytes;
[2390] 
[2391]     if (u->length == 0) {
[2392]         u->keepalive = !u->headers_in.connection_close;
[2393]     }
[2394] 
[2395]     return NGX_OK;
[2396] }
[2397] 
[2398] 
[2399] static ngx_int_t
[2400] ngx_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)
[2401] {
[2402]     ngx_http_request_t   *r = data;
[2403] 
[2404]     ngx_int_t              rc;
[2405]     ngx_buf_t             *b, *buf;
[2406]     ngx_chain_t           *cl, **ll;
[2407]     ngx_http_upstream_t   *u;
[2408]     ngx_http_proxy_ctx_t  *ctx;
[2409] 
[2410]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2411] 
[2412]     if (ctx == NULL) {
[2413]         return NGX_ERROR;
[2414]     }
[2415] 
[2416]     u = r->upstream;
[2417]     buf = &u->buffer;
[2418] 
[2419]     buf->pos = buf->last;
[2420]     buf->last += bytes;
[2421] 
[2422]     for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
[2423]         ll = &cl->next;
[2424]     }
[2425] 
[2426]     for ( ;; ) {
[2427] 
[2428]         rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);
[2429] 
[2430]         if (rc == NGX_OK) {
[2431] 
[2432]             /* a chunk has been parsed successfully */
[2433] 
[2434]             cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
[2435]             if (cl == NULL) {
[2436]                 return NGX_ERROR;
[2437]             }
[2438] 
[2439]             *ll = cl;
[2440]             ll = &cl->next;
[2441] 
[2442]             b = cl->buf;
[2443] 
[2444]             b->flush = 1;
[2445]             b->memory = 1;
[2446] 
[2447]             b->pos = buf->pos;
[2448]             b->tag = u->output.tag;
[2449] 
[2450]             if (buf->last - buf->pos >= ctx->chunked.size) {
[2451]                 buf->pos += (size_t) ctx->chunked.size;
[2452]                 b->last = buf->pos;
[2453]                 ctx->chunked.size = 0;
[2454] 
[2455]             } else {
[2456]                 ctx->chunked.size -= buf->last - buf->pos;
[2457]                 buf->pos = buf->last;
[2458]                 b->last = buf->last;
[2459]             }
[2460] 
[2461]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2462]                            "http proxy out buf %p %z",
[2463]                            b->pos, b->last - b->pos);
[2464] 
[2465]             continue;
[2466]         }
[2467] 
[2468]         if (rc == NGX_DONE) {
[2469] 
[2470]             /* a whole response has been parsed successfully */
[2471] 
[2472]             u->keepalive = !u->headers_in.connection_close;
[2473]             u->length = 0;
[2474] 
[2475]             if (buf->pos != buf->last) {
[2476]                 ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[2477]                               "upstream sent data after final chunk");
[2478]                 u->keepalive = 0;
[2479]             }
[2480] 
[2481]             break;
[2482]         }
[2483] 
[2484]         if (rc == NGX_AGAIN) {
[2485]             break;
[2486]         }
[2487] 
[2488]         /* invalid response */
[2489] 
[2490]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2491]                       "upstream sent invalid chunked response");
[2492] 
[2493]         return NGX_ERROR;
[2494]     }
[2495] 
[2496]     return NGX_OK;
[2497] }
[2498] 
[2499] 
[2500] static void
[2501] ngx_http_proxy_abort_request(ngx_http_request_t *r)
[2502] {
[2503]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2504]                    "abort http proxy request");
[2505] 
[2506]     return;
[2507] }
[2508] 
[2509] 
[2510] static void
[2511] ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[2512] {
[2513]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2514]                    "finalize http proxy request");
[2515] 
[2516]     return;
[2517] }
[2518] 
[2519] 
[2520] static ngx_int_t
[2521] ngx_http_proxy_host_variable(ngx_http_request_t *r,
[2522]     ngx_http_variable_value_t *v, uintptr_t data)
[2523] {
[2524]     ngx_http_proxy_ctx_t  *ctx;
[2525] 
[2526]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2527] 
[2528]     if (ctx == NULL) {
[2529]         v->not_found = 1;
[2530]         return NGX_OK;
[2531]     }
[2532] 
[2533]     v->len = ctx->vars.host_header.len;
[2534]     v->valid = 1;
[2535]     v->no_cacheable = 0;
[2536]     v->not_found = 0;
[2537]     v->data = ctx->vars.host_header.data;
[2538] 
[2539]     return NGX_OK;
[2540] }
[2541] 
[2542] 
[2543] static ngx_int_t
[2544] ngx_http_proxy_port_variable(ngx_http_request_t *r,
[2545]     ngx_http_variable_value_t *v, uintptr_t data)
[2546] {
[2547]     ngx_http_proxy_ctx_t  *ctx;
[2548] 
[2549]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2550] 
[2551]     if (ctx == NULL) {
[2552]         v->not_found = 1;
[2553]         return NGX_OK;
[2554]     }
[2555] 
[2556]     v->len = ctx->vars.port.len;
[2557]     v->valid = 1;
[2558]     v->no_cacheable = 0;
[2559]     v->not_found = 0;
[2560]     v->data = ctx->vars.port.data;
[2561] 
[2562]     return NGX_OK;
[2563] }
[2564] 
[2565] 
[2566] static ngx_int_t
[2567] ngx_http_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r,
[2568]     ngx_http_variable_value_t *v, uintptr_t data)
[2569] {
[2570]     size_t            len;
[2571]     u_char           *p;
[2572]     ngx_table_elt_t  *h, *xfwd;
[2573] 
[2574]     v->valid = 1;
[2575]     v->no_cacheable = 0;
[2576]     v->not_found = 0;
[2577] 
[2578]     xfwd = r->headers_in.x_forwarded_for;
[2579] 
[2580]     len = 0;
[2581] 
[2582]     for (h = xfwd; h; h = h->next) {
[2583]         len += h->value.len + sizeof(", ") - 1;
[2584]     }
[2585] 
[2586]     if (len == 0) {
[2587]         v->len = r->connection->addr_text.len;
[2588]         v->data = r->connection->addr_text.data;
[2589]         return NGX_OK;
[2590]     }
[2591] 
[2592]     len += r->connection->addr_text.len;
[2593] 
[2594]     p = ngx_pnalloc(r->pool, len);
[2595]     if (p == NULL) {
[2596]         return NGX_ERROR;
[2597]     }
[2598] 
[2599]     v->len = len;
[2600]     v->data = p;
[2601] 
[2602]     for (h = xfwd; h; h = h->next) {
[2603]         p = ngx_copy(p, h->value.data, h->value.len);
[2604]         *p++ = ','; *p++ = ' ';
[2605]     }
[2606] 
[2607]     ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);
[2608] 
[2609]     return NGX_OK;
[2610] }
[2611] 
[2612] 
[2613] static ngx_int_t
[2614] ngx_http_proxy_internal_body_length_variable(ngx_http_request_t *r,
[2615]     ngx_http_variable_value_t *v, uintptr_t data)
[2616] {
[2617]     ngx_http_proxy_ctx_t  *ctx;
[2618] 
[2619]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2620] 
[2621]     if (ctx == NULL || ctx->internal_body_length < 0) {
[2622]         v->not_found = 1;
[2623]         return NGX_OK;
[2624]     }
[2625] 
[2626]     v->valid = 1;
[2627]     v->no_cacheable = 0;
[2628]     v->not_found = 0;
[2629] 
[2630]     v->data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
[2631] 
[2632]     if (v->data == NULL) {
[2633]         return NGX_ERROR;
[2634]     }
[2635] 
[2636]     v->len = ngx_sprintf(v->data, "%O", ctx->internal_body_length) - v->data;
[2637] 
[2638]     return NGX_OK;
[2639] }
[2640] 
[2641] 
[2642] static ngx_int_t
[2643] ngx_http_proxy_internal_chunked_variable(ngx_http_request_t *r,
[2644]     ngx_http_variable_value_t *v, uintptr_t data)
[2645] {
[2646]     ngx_http_proxy_ctx_t  *ctx;
[2647] 
[2648]     ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_module);
[2649] 
[2650]     if (ctx == NULL || !ctx->internal_chunked) {
[2651]         v->not_found = 1;
[2652]         return NGX_OK;
[2653]     }
[2654] 
[2655]     v->valid = 1;
[2656]     v->no_cacheable = 0;
[2657]     v->not_found = 0;
[2658] 
[2659]     v->data = (u_char *) "chunked";
[2660]     v->len = sizeof("chunked") - 1;
[2661] 
[2662]     return NGX_OK;
[2663] }
[2664] 
[2665] 
[2666] static ngx_int_t
[2667] ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r, ngx_table_elt_t *h,
[2668]     size_t prefix)
[2669] {
[2670]     size_t                      len;
[2671]     ngx_int_t                   rc;
[2672]     ngx_uint_t                  i;
[2673]     ngx_http_proxy_rewrite_t   *pr;
[2674]     ngx_http_proxy_loc_conf_t  *plcf;
[2675] 
[2676]     plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
[2677] 
[2678]     pr = plcf->redirects->elts;
[2679] 
[2680]     if (pr == NULL) {
[2681]         return NGX_DECLINED;
[2682]     }
[2683] 
[2684]     len = h->value.len - prefix;
[2685] 
[2686]     for (i = 0; i < plcf->redirects->nelts; i++) {
[2687]         rc = pr[i].handler(r, &h->value, prefix, len, &pr[i]);
[2688] 
[2689]         if (rc != NGX_DECLINED) {
[2690]             return rc;
[2691]         }
[2692]     }
[2693] 
[2694]     return NGX_DECLINED;
[2695] }
[2696] 
[2697] 
[2698] static ngx_int_t
[2699] ngx_http_proxy_rewrite_cookie(ngx_http_request_t *r, ngx_table_elt_t *h)
[2700] {
[2701]     u_char                     *p;
[2702]     size_t                      len;
[2703]     ngx_int_t                   rc, rv;
[2704]     ngx_str_t                  *key, *value;
[2705]     ngx_uint_t                  i;
[2706]     ngx_array_t                 attrs;
[2707]     ngx_keyval_t               *attr;
[2708]     ngx_http_proxy_loc_conf_t  *plcf;
[2709] 
[2710]     if (ngx_array_init(&attrs, r->pool, 2, sizeof(ngx_keyval_t)) != NGX_OK) {
[2711]         return NGX_ERROR;
[2712]     }
[2713] 
[2714]     if (ngx_http_proxy_parse_cookie(&h->value, &attrs) != NGX_OK) {
[2715]         return NGX_ERROR;
[2716]     }
[2717] 
[2718]     attr = attrs.elts;
[2719] 
[2720]     if (attr[0].value.data == NULL) {
[2721]         return NGX_DECLINED;
[2722]     }
[2723] 
[2724]     rv = NGX_DECLINED;
[2725] 
[2726]     plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
[2727] 
[2728]     for (i = 1; i < attrs.nelts; i++) {
[2729] 
[2730]         key = &attr[i].key;
[2731]         value = &attr[i].value;
[2732] 
[2733]         if (plcf->cookie_domains && key->len == 6
[2734]             && ngx_strncasecmp(key->data, (u_char *) "domain", 6) == 0
[2735]             && value->data)
[2736]         {
[2737]             rc = ngx_http_proxy_rewrite_cookie_value(r, value,
[2738]                                                      plcf->cookie_domains);
[2739]             if (rc == NGX_ERROR) {
[2740]                 return NGX_ERROR;
[2741]             }
[2742] 
[2743]             if (rc != NGX_DECLINED) {
[2744]                 rv = rc;
[2745]             }
[2746]         }
[2747] 
[2748]         if (plcf->cookie_paths && key->len == 4
[2749]             && ngx_strncasecmp(key->data, (u_char *) "path", 4) == 0
[2750]             && value->data)
[2751]         {
[2752]             rc = ngx_http_proxy_rewrite_cookie_value(r, value,
[2753]                                                      plcf->cookie_paths);
[2754]             if (rc == NGX_ERROR) {
[2755]                 return NGX_ERROR;
[2756]             }
[2757] 
[2758]             if (rc != NGX_DECLINED) {
[2759]                 rv = rc;
[2760]             }
[2761]         }
[2762]     }
[2763] 
[2764]     if (plcf->cookie_flags) {
[2765]         rc = ngx_http_proxy_rewrite_cookie_flags(r, &attrs,
[2766]                                                  plcf->cookie_flags);
[2767]         if (rc == NGX_ERROR) {
[2768]             return NGX_ERROR;
[2769]         }
[2770] 
[2771]         if (rc != NGX_DECLINED) {
[2772]             rv = rc;
[2773]         }
[2774] 
[2775]         attr = attrs.elts;
[2776]     }
[2777] 
[2778]     if (rv != NGX_OK) {
[2779]         return rv;
[2780]     }
[2781] 
[2782]     len = 0;
[2783] 
[2784]     for (i = 0; i < attrs.nelts; i++) {
[2785] 
[2786]         if (attr[i].key.data == NULL) {
[2787]             continue;
[2788]         }
[2789] 
[2790]         if (i > 0) {
[2791]             len += 2;
[2792]         }
[2793] 
[2794]         len += attr[i].key.len;
[2795] 
[2796]         if (attr[i].value.data) {
[2797]             len += 1 + attr[i].value.len;
[2798]         }
[2799]     }
[2800] 
[2801]     p = ngx_pnalloc(r->pool, len + 1);
[2802]     if (p == NULL) {
[2803]         return NGX_ERROR;
[2804]     }
[2805] 
[2806]     h->value.data = p;
[2807]     h->value.len = len;
[2808] 
[2809]     for (i = 0; i < attrs.nelts; i++) {
[2810] 
[2811]         if (attr[i].key.data == NULL) {
[2812]             continue;
[2813]         }
[2814] 
[2815]         if (i > 0) {
[2816]             *p++ = ';';
[2817]             *p++ = ' ';
[2818]         }
[2819] 
[2820]         p = ngx_cpymem(p, attr[i].key.data, attr[i].key.len);
[2821] 
[2822]         if (attr[i].value.data) {
[2823]             *p++ = '=';
[2824]             p = ngx_cpymem(p, attr[i].value.data, attr[i].value.len);
[2825]         }
[2826]     }
[2827] 
[2828]     *p = '\0';
[2829] 
[2830]     return NGX_OK;
[2831] }
[2832] 
[2833] 
[2834] static ngx_int_t
[2835] ngx_http_proxy_parse_cookie(ngx_str_t *value, ngx_array_t *attrs)
[2836] {
[2837]     u_char        *start, *end, *p, *last;
[2838]     ngx_str_t      name, val;
[2839]     ngx_keyval_t  *attr;
[2840] 
[2841]     start = value->data;
[2842]     end = value->data + value->len;
[2843] 
[2844]     for ( ;; ) {
[2845] 
[2846]         last = (u_char *) ngx_strchr(start, ';');
[2847] 
[2848]         if (last == NULL) {
[2849]             last = end;
[2850]         }
[2851] 
[2852]         while (start < last && *start == ' ') { start++; }
[2853] 
[2854]         for (p = start; p < last && *p != '='; p++) { /* void */ }
[2855] 
[2856]         name.data = start;
[2857]         name.len = p - start;
[2858] 
[2859]         while (name.len && name.data[name.len - 1] == ' ') {
[2860]             name.len--;
[2861]         }
[2862] 
[2863]         if (p < last) {
[2864] 
[2865]             p++;
[2866] 
[2867]             while (p < last && *p == ' ') { p++; }
[2868] 
[2869]             val.data = p;
[2870]             val.len = last - val.data;
[2871] 
[2872]             while (val.len && val.data[val.len - 1] == ' ') {
[2873]                 val.len--;
[2874]             }
[2875] 
[2876]         } else {
[2877]             ngx_str_null(&val);
[2878]         }
[2879] 
[2880]         attr = ngx_array_push(attrs);
[2881]         if (attr == NULL) {
[2882]             return NGX_ERROR;
[2883]         }
[2884] 
[2885]         attr->key = name;
[2886]         attr->value = val;
[2887] 
[2888]         if (last == end) {
[2889]             break;
[2890]         }
[2891] 
[2892]         start = last + 1;
[2893]     }
[2894] 
[2895]     return NGX_OK;
[2896] }
[2897] 
[2898] 
[2899] static ngx_int_t
[2900] ngx_http_proxy_rewrite_cookie_value(ngx_http_request_t *r, ngx_str_t *value,
[2901]     ngx_array_t *rewrites)
[2902] {
[2903]     ngx_int_t                  rc;
[2904]     ngx_uint_t                 i;
[2905]     ngx_http_proxy_rewrite_t  *pr;
[2906] 
[2907]     pr = rewrites->elts;
[2908] 
[2909]     for (i = 0; i < rewrites->nelts; i++) {
[2910]         rc = pr[i].handler(r, value, 0, value->len, &pr[i]);
[2911] 
[2912]         if (rc != NGX_DECLINED) {
[2913]             return rc;
[2914]         }
[2915]     }
[2916] 
[2917]     return NGX_DECLINED;
[2918] }
[2919] 
[2920] 
[2921] static ngx_int_t
[2922] ngx_http_proxy_rewrite_cookie_flags(ngx_http_request_t *r, ngx_array_t *attrs,
[2923]     ngx_array_t *flags)
[2924] {
[2925]     ngx_str_t                       pattern, value;
[2926] #if (NGX_PCRE)
[2927]     ngx_int_t                       rc;
[2928] #endif
[2929]     ngx_uint_t                      i, m, f, nelts;
[2930]     ngx_keyval_t                   *attr;
[2931]     ngx_conf_bitmask_t             *mask;
[2932]     ngx_http_complex_value_t       *flags_values;
[2933]     ngx_http_proxy_cookie_flags_t  *pcf;
[2934] 
[2935]     attr = attrs->elts;
[2936]     pcf = flags->elts;
[2937] 
[2938]     for (i = 0; i < flags->nelts; i++) {
[2939] 
[2940] #if (NGX_PCRE)
[2941]         if (pcf[i].regex) {
[2942]             rc = ngx_http_regex_exec(r, pcf[i].cookie.regex, &attr[0].key);
[2943] 
[2944]             if (rc == NGX_ERROR) {
[2945]                 return NGX_ERROR;
[2946]             }
[2947] 
[2948]             if (rc == NGX_OK) {
[2949]                 break;
[2950]             }
[2951] 
[2952]             /* NGX_DECLINED */
[2953] 
[2954]             continue;
[2955]         }
[2956] #endif
[2957] 
[2958]         if (ngx_http_complex_value(r, &pcf[i].cookie.complex, &pattern)
[2959]             != NGX_OK)
[2960]         {
[2961]             return NGX_ERROR;
[2962]         }
[2963] 
[2964]         if (pattern.len == attr[0].key.len
[2965]             && ngx_strncasecmp(attr[0].key.data, pattern.data, pattern.len)
[2966]                == 0)
[2967]         {
[2968]             break;
[2969]         }
[2970]     }
[2971] 
[2972]     if (i == flags->nelts) {
[2973]         return NGX_DECLINED;
[2974]     }
[2975] 
[2976]     nelts = pcf[i].flags_values.nelts;
[2977]     flags_values = pcf[i].flags_values.elts;
[2978] 
[2979]     mask = ngx_http_proxy_cookie_flags_masks;
[2980]     f = 0;
[2981] 
[2982]     for (i = 0; i < nelts; i++) {
[2983] 
[2984]         if (ngx_http_complex_value(r, &flags_values[i], &value) != NGX_OK) {
[2985]             return NGX_ERROR;
[2986]         }
[2987] 
[2988]         if (value.len == 0) {
[2989]             continue;
[2990]         }
[2991] 
[2992]         for (m = 0; mask[m].name.len != 0; m++) {
[2993] 
[2994]             if (mask[m].name.len != value.len
[2995]                 || ngx_strncasecmp(mask[m].name.data, value.data, value.len)
[2996]                    != 0)
[2997]             {
[2998]                 continue;
[2999]             }
[3000] 
[3001]             f |= mask[m].mask;
[3002] 
[3003]             break;
[3004]         }
[3005] 
[3006]         if (mask[m].name.len == 0) {
[3007]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3008]                            "invalid proxy_cookie_flags flag \"%V\"", &value);
[3009]         }
[3010]     }
[3011] 
[3012]     if (f == 0) {
[3013]         return NGX_DECLINED;
[3014]     }
[3015] 
[3016]     return ngx_http_proxy_edit_cookie_flags(r, attrs, f);
[3017] }
[3018] 
[3019] 
[3020] static ngx_int_t
[3021] ngx_http_proxy_edit_cookie_flags(ngx_http_request_t *r, ngx_array_t *attrs,
[3022]     ngx_uint_t flags)
[3023] {
[3024]     ngx_str_t     *key, *value;
[3025]     ngx_uint_t     i;
[3026]     ngx_keyval_t  *attr;
[3027] 
[3028]     attr = attrs->elts;
[3029] 
[3030]     for (i = 1; i < attrs->nelts; i++) {
[3031]         key = &attr[i].key;
[3032] 
[3033]         if (key->len == 6
[3034]             && ngx_strncasecmp(key->data, (u_char *) "secure", 6) == 0)
[3035]         {
[3036]             if (flags & NGX_HTTP_PROXY_COOKIE_SECURE_ON) {
[3037]                 flags &= ~NGX_HTTP_PROXY_COOKIE_SECURE_ON;
[3038] 
[3039]             } else if (flags & NGX_HTTP_PROXY_COOKIE_SECURE_OFF) {
[3040]                 key->data = NULL;
[3041]             }
[3042] 
[3043]             continue;
[3044]         }
[3045] 
[3046]         if (key->len == 8
[3047]             && ngx_strncasecmp(key->data, (u_char *) "httponly", 8) == 0)
[3048]         {
[3049]             if (flags & NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON) {
[3050]                 flags &= ~NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON;
[3051] 
[3052]             } else if (flags & NGX_HTTP_PROXY_COOKIE_HTTPONLY_OFF) {
[3053]                 key->data = NULL;
[3054]             }
[3055] 
[3056]             continue;
[3057]         }
[3058] 
[3059]         if (key->len == 8
[3060]             && ngx_strncasecmp(key->data, (u_char *) "samesite", 8) == 0)
[3061]         {
[3062]             value = &attr[i].value;
[3063] 
[3064]             if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT) {
[3065]                 flags &= ~NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT;
[3066] 
[3067]                 if (value->len != 6
[3068]                     || ngx_strncasecmp(value->data, (u_char *) "strict", 6)
[3069]                        != 0)
[3070]                 {
[3071]                     ngx_str_set(key, "SameSite");
[3072]                     ngx_str_set(value, "Strict");
[3073]                 }
[3074] 
[3075]             } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX) {
[3076]                 flags &= ~NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX;
[3077] 
[3078]                 if (value->len != 3
[3079]                     || ngx_strncasecmp(value->data, (u_char *) "lax", 3) != 0)
[3080]                 {
[3081]                     ngx_str_set(key, "SameSite");
[3082]                     ngx_str_set(value, "Lax");
[3083]                 }
[3084] 
[3085]             } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE) {
[3086]                 flags &= ~NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE;
[3087] 
[3088]                 if (value->len != 4
[3089]                     || ngx_strncasecmp(value->data, (u_char *) "none", 4) != 0)
[3090]                 {
[3091]                     ngx_str_set(key, "SameSite");
[3092]                     ngx_str_set(value, "None");
[3093]                 }
[3094] 
[3095]             } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_OFF) {
[3096]                 key->data = NULL;
[3097]             }
[3098] 
[3099]             continue;
[3100]         }
[3101]     }
[3102] 
[3103]     if (flags & NGX_HTTP_PROXY_COOKIE_SECURE_ON) {
[3104]         attr = ngx_array_push(attrs);
[3105]         if (attr == NULL) {
[3106]             return NGX_ERROR;
[3107]         }
[3108] 
[3109]         ngx_str_set(&attr->key, "Secure");
[3110]         ngx_str_null(&attr->value);
[3111]     }
[3112] 
[3113]     if (flags & NGX_HTTP_PROXY_COOKIE_HTTPONLY_ON) {
[3114]         attr = ngx_array_push(attrs);
[3115]         if (attr == NULL) {
[3116]             return NGX_ERROR;
[3117]         }
[3118] 
[3119]         ngx_str_set(&attr->key, "HttpOnly");
[3120]         ngx_str_null(&attr->value);
[3121]     }
[3122] 
[3123]     if (flags & (NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT
[3124]                  |NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX
[3125]                  |NGX_HTTP_PROXY_COOKIE_SAMESITE_NONE))
[3126]     {
[3127]         attr = ngx_array_push(attrs);
[3128]         if (attr == NULL) {
[3129]             return NGX_ERROR;
[3130]         }
[3131] 
[3132]         ngx_str_set(&attr->key, "SameSite");
[3133] 
[3134]         if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_STRICT) {
[3135]             ngx_str_set(&attr->value, "Strict");
[3136] 
[3137]         } else if (flags & NGX_HTTP_PROXY_COOKIE_SAMESITE_LAX) {
[3138]             ngx_str_set(&attr->value, "Lax");
[3139] 
[3140]         } else {
[3141]             ngx_str_set(&attr->value, "None");
[3142]         }
[3143]     }
[3144] 
[3145]     return NGX_OK;
[3146] }
[3147] 
[3148] 
[3149] static ngx_int_t
[3150] ngx_http_proxy_rewrite_complex_handler(ngx_http_request_t *r, ngx_str_t *value,
[3151]     size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
[3152] {
[3153]     ngx_str_t  pattern, replacement;
[3154] 
[3155]     if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
[3156]         return NGX_ERROR;
[3157]     }
[3158] 
[3159]     if (pattern.len > len
[3160]         || ngx_rstrncmp(value->data + prefix, pattern.data, pattern.len) != 0)
[3161]     {
[3162]         return NGX_DECLINED;
[3163]     }
[3164] 
[3165]     if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
[3166]         return NGX_ERROR;
[3167]     }
[3168] 
[3169]     return ngx_http_proxy_rewrite(r, value, prefix, pattern.len, &replacement);
[3170] }
[3171] 
[3172] 
[3173] #if (NGX_PCRE)
[3174] 
[3175] static ngx_int_t
[3176] ngx_http_proxy_rewrite_regex_handler(ngx_http_request_t *r, ngx_str_t *value,
[3177]     size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
[3178] {
[3179]     ngx_str_t  pattern, replacement;
[3180] 
[3181]     pattern.len = len;
[3182]     pattern.data = value->data + prefix;
[3183] 
[3184]     if (ngx_http_regex_exec(r, pr->pattern.regex, &pattern) != NGX_OK) {
[3185]         return NGX_DECLINED;
[3186]     }
[3187] 
[3188]     if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
[3189]         return NGX_ERROR;
[3190]     }
[3191] 
[3192]     return ngx_http_proxy_rewrite(r, value, prefix, len, &replacement);
[3193] }
[3194] 
[3195] #endif
[3196] 
[3197] 
[3198] static ngx_int_t
[3199] ngx_http_proxy_rewrite_domain_handler(ngx_http_request_t *r, ngx_str_t *value,
[3200]     size_t prefix, size_t len, ngx_http_proxy_rewrite_t *pr)
[3201] {
[3202]     u_char     *p;
[3203]     ngx_str_t   pattern, replacement;
[3204] 
[3205]     if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
[3206]         return NGX_ERROR;
[3207]     }
[3208] 
[3209]     p = value->data + prefix;
[3210] 
[3211]     if (len && p[0] == '.') {
[3212]         p++;
[3213]         prefix++;
[3214]         len--;
[3215]     }
[3216] 
[3217]     if (pattern.len != len || ngx_rstrncasecmp(pattern.data, p, len) != 0) {
[3218]         return NGX_DECLINED;
[3219]     }
[3220] 
[3221]     if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
[3222]         return NGX_ERROR;
[3223]     }
[3224] 
[3225]     return ngx_http_proxy_rewrite(r, value, prefix, len, &replacement);
[3226] }
[3227] 
[3228] 
[3229] static ngx_int_t
[3230] ngx_http_proxy_rewrite(ngx_http_request_t *r, ngx_str_t *value, size_t prefix,
[3231]     size_t len, ngx_str_t *replacement)
[3232] {
[3233]     u_char  *p, *data;
[3234]     size_t   new_len;
[3235] 
[3236]     if (len == value->len) {
[3237]         *value = *replacement;
[3238]         return NGX_OK;
[3239]     }
[3240] 
[3241]     new_len = replacement->len + value->len - len;
[3242] 
[3243]     if (replacement->len > len) {
[3244] 
[3245]         data = ngx_pnalloc(r->pool, new_len + 1);
[3246]         if (data == NULL) {
[3247]             return NGX_ERROR;
[3248]         }
[3249] 
[3250]         p = ngx_copy(data, value->data, prefix);
[3251]         p = ngx_copy(p, replacement->data, replacement->len);
[3252] 
[3253]         ngx_memcpy(p, value->data + prefix + len,
[3254]                    value->len - len - prefix + 1);
[3255] 
[3256]         value->data = data;
[3257] 
[3258]     } else {
[3259]         p = ngx_copy(value->data + prefix, replacement->data, replacement->len);
[3260] 
[3261]         ngx_memmove(p, value->data + prefix + len,
[3262]                     value->len - len - prefix + 1);
[3263]     }
[3264] 
[3265]     value->len = new_len;
[3266] 
[3267]     return NGX_OK;
[3268] }
[3269] 
[3270] 
[3271] static ngx_int_t
[3272] ngx_http_proxy_add_variables(ngx_conf_t *cf)
[3273] {
[3274]     ngx_http_variable_t  *var, *v;
[3275] 
[3276]     for (v = ngx_http_proxy_vars; v->name.len; v++) {
[3277]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[3278]         if (var == NULL) {
[3279]             return NGX_ERROR;
[3280]         }
[3281] 
[3282]         var->get_handler = v->get_handler;
[3283]         var->data = v->data;
[3284]     }
[3285] 
[3286]     return NGX_OK;
[3287] }
[3288] 
[3289] 
[3290] static void *
[3291] ngx_http_proxy_create_main_conf(ngx_conf_t *cf)
[3292] {
[3293]     ngx_http_proxy_main_conf_t  *conf;
[3294] 
[3295]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_main_conf_t));
[3296]     if (conf == NULL) {
[3297]         return NULL;
[3298]     }
[3299] 
[3300] #if (NGX_HTTP_CACHE)
[3301]     if (ngx_array_init(&conf->caches, cf->pool, 4,
[3302]                        sizeof(ngx_http_file_cache_t *))
[3303]         != NGX_OK)
[3304]     {
[3305]         return NULL;
[3306]     }
[3307] #endif
[3308] 
[3309]     return conf;
[3310] }
[3311] 
[3312] 
[3313] static void *
[3314] ngx_http_proxy_create_loc_conf(ngx_conf_t *cf)
[3315] {
[3316]     ngx_http_proxy_loc_conf_t  *conf;
[3317] 
[3318]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_loc_conf_t));
[3319]     if (conf == NULL) {
[3320]         return NULL;
[3321]     }
[3322] 
[3323]     /*
[3324]      * set by ngx_pcalloc():
[3325]      *
[3326]      *     conf->upstream.bufs.num = 0;
[3327]      *     conf->upstream.ignore_headers = 0;
[3328]      *     conf->upstream.next_upstream = 0;
[3329]      *     conf->upstream.cache_zone = NULL;
[3330]      *     conf->upstream.cache_use_stale = 0;
[3331]      *     conf->upstream.cache_methods = 0;
[3332]      *     conf->upstream.temp_path = NULL;
[3333]      *     conf->upstream.hide_headers_hash = { NULL, 0 };
[3334]      *     conf->upstream.store_lengths = NULL;
[3335]      *     conf->upstream.store_values = NULL;
[3336]      *
[3337]      *     conf->location = NULL;
[3338]      *     conf->url = { 0, NULL };
[3339]      *     conf->headers.lengths = NULL;
[3340]      *     conf->headers.values = NULL;
[3341]      *     conf->headers.hash = { NULL, 0 };
[3342]      *     conf->headers_cache.lengths = NULL;
[3343]      *     conf->headers_cache.values = NULL;
[3344]      *     conf->headers_cache.hash = { NULL, 0 };
[3345]      *     conf->body_lengths = NULL;
[3346]      *     conf->body_values = NULL;
[3347]      *     conf->body_source = { 0, NULL };
[3348]      *     conf->redirects = NULL;
[3349]      *     conf->ssl = 0;
[3350]      *     conf->ssl_protocols = 0;
[3351]      *     conf->ssl_ciphers = { 0, NULL };
[3352]      *     conf->ssl_trusted_certificate = { 0, NULL };
[3353]      *     conf->ssl_crl = { 0, NULL };
[3354]      */
[3355] 
[3356]     conf->upstream.store = NGX_CONF_UNSET;
[3357]     conf->upstream.store_access = NGX_CONF_UNSET_UINT;
[3358]     conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
[3359]     conf->upstream.buffering = NGX_CONF_UNSET;
[3360]     conf->upstream.request_buffering = NGX_CONF_UNSET;
[3361]     conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
[3362]     conf->upstream.force_ranges = NGX_CONF_UNSET;
[3363] 
[3364]     conf->upstream.local = NGX_CONF_UNSET_PTR;
[3365]     conf->upstream.socket_keepalive = NGX_CONF_UNSET;
[3366] 
[3367]     conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
[3368]     conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
[3369]     conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
[3370]     conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[3371] 
[3372]     conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
[3373]     conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
[3374]     conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
[3375] 
[3376]     conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
[3377]     conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
[3378]     conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
[3379] 
[3380]     conf->upstream.pass_request_headers = NGX_CONF_UNSET;
[3381]     conf->upstream.pass_request_body = NGX_CONF_UNSET;
[3382] 
[3383] #if (NGX_HTTP_CACHE)
[3384]     conf->upstream.cache = NGX_CONF_UNSET;
[3385]     conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
[3386]     conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
[3387]     conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
[3388]     conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
[3389]     conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
[3390]     conf->upstream.cache_lock = NGX_CONF_UNSET;
[3391]     conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
[3392]     conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
[3393]     conf->upstream.cache_revalidate = NGX_CONF_UNSET;
[3394]     conf->upstream.cache_convert_head = NGX_CONF_UNSET;
[3395]     conf->upstream.cache_background_update = NGX_CONF_UNSET;
[3396] #endif
[3397] 
[3398]     conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
[3399]     conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
[3400] 
[3401]     conf->upstream.intercept_errors = NGX_CONF_UNSET;
[3402] 
[3403] #if (NGX_HTTP_SSL)
[3404]     conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
[3405]     conf->upstream.ssl_name = NGX_CONF_UNSET_PTR;
[3406]     conf->upstream.ssl_server_name = NGX_CONF_UNSET;
[3407]     conf->upstream.ssl_verify = NGX_CONF_UNSET;
[3408]     conf->upstream.ssl_certificate = NGX_CONF_UNSET_PTR;
[3409]     conf->upstream.ssl_certificate_key = NGX_CONF_UNSET_PTR;
[3410]     conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
[3411]     conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
[3412]     conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
[3413] #endif
[3414] 
[3415]     /* "proxy_cyclic_temp_file" is disabled */
[3416]     conf->upstream.cyclic_temp_file = 0;
[3417] 
[3418]     conf->upstream.change_buffering = 1;
[3419] 
[3420]     conf->headers_source = NGX_CONF_UNSET_PTR;
[3421] 
[3422]     conf->method = NGX_CONF_UNSET_PTR;
[3423] 
[3424]     conf->redirect = NGX_CONF_UNSET;
[3425] 
[3426]     conf->cookie_domains = NGX_CONF_UNSET_PTR;
[3427]     conf->cookie_paths = NGX_CONF_UNSET_PTR;
[3428]     conf->cookie_flags = NGX_CONF_UNSET_PTR;
[3429] 
[3430]     conf->http_version = NGX_CONF_UNSET_UINT;
[3431] 
[3432]     conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
[3433]     conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;
[3434] 
[3435]     ngx_str_set(&conf->upstream.module, "proxy");
[3436] 
[3437]     return conf;
[3438] }
[3439] 
[3440] 
[3441] static char *
[3442] ngx_http_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[3443] {
[3444]     ngx_http_proxy_loc_conf_t *prev = parent;
[3445]     ngx_http_proxy_loc_conf_t *conf = child;
[3446] 
[3447]     u_char                     *p;
[3448]     size_t                      size;
[3449]     ngx_int_t                   rc;
[3450]     ngx_hash_init_t             hash;
[3451]     ngx_http_core_loc_conf_t   *clcf;
[3452]     ngx_http_proxy_rewrite_t   *pr;
[3453]     ngx_http_script_compile_t   sc;
[3454] 
[3455] #if (NGX_HTTP_CACHE)
[3456] 
[3457]     if (conf->upstream.store > 0) {
[3458]         conf->upstream.cache = 0;
[3459]     }
[3460] 
[3461]     if (conf->upstream.cache > 0) {
[3462]         conf->upstream.store = 0;
[3463]     }
[3464] 
[3465] #endif
[3466] 
[3467]     if (conf->upstream.store == NGX_CONF_UNSET) {
[3468]         ngx_conf_merge_value(conf->upstream.store,
[3469]                               prev->upstream.store, 0);
[3470] 
[3471]         conf->upstream.store_lengths = prev->upstream.store_lengths;
[3472]         conf->upstream.store_values = prev->upstream.store_values;
[3473]     }
[3474] 
[3475]     ngx_conf_merge_uint_value(conf->upstream.store_access,
[3476]                               prev->upstream.store_access, 0600);
[3477] 
[3478]     ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
[3479]                               prev->upstream.next_upstream_tries, 0);
[3480] 
[3481]     ngx_conf_merge_value(conf->upstream.buffering,
[3482]                               prev->upstream.buffering, 1);
[3483] 
[3484]     ngx_conf_merge_value(conf->upstream.request_buffering,
[3485]                               prev->upstream.request_buffering, 1);
[3486] 
[3487]     ngx_conf_merge_value(conf->upstream.ignore_client_abort,
[3488]                               prev->upstream.ignore_client_abort, 0);
[3489] 
[3490]     ngx_conf_merge_value(conf->upstream.force_ranges,
[3491]                               prev->upstream.force_ranges, 0);
[3492] 
[3493]     ngx_conf_merge_ptr_value(conf->upstream.local,
[3494]                               prev->upstream.local, NULL);
[3495] 
[3496]     ngx_conf_merge_value(conf->upstream.socket_keepalive,
[3497]                               prev->upstream.socket_keepalive, 0);
[3498] 
[3499]     ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
[3500]                               prev->upstream.connect_timeout, 60000);
[3501] 
[3502]     ngx_conf_merge_msec_value(conf->upstream.send_timeout,
[3503]                               prev->upstream.send_timeout, 60000);
[3504] 
[3505]     ngx_conf_merge_msec_value(conf->upstream.read_timeout,
[3506]                               prev->upstream.read_timeout, 60000);
[3507] 
[3508]     ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
[3509]                               prev->upstream.next_upstream_timeout, 0);
[3510] 
[3511]     ngx_conf_merge_size_value(conf->upstream.send_lowat,
[3512]                               prev->upstream.send_lowat, 0);
[3513] 
[3514]     ngx_conf_merge_size_value(conf->upstream.buffer_size,
[3515]                               prev->upstream.buffer_size,
[3516]                               (size_t) ngx_pagesize);
[3517] 
[3518]     ngx_conf_merge_size_value(conf->upstream.limit_rate,
[3519]                               prev->upstream.limit_rate, 0);
[3520] 
[3521]     ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
[3522]                               8, ngx_pagesize);
[3523] 
[3524]     if (conf->upstream.bufs.num < 2) {
[3525]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3526]                            "there must be at least 2 \"proxy_buffers\"");
[3527]         return NGX_CONF_ERROR;
[3528]     }
[3529] 
[3530] 
[3531]     size = conf->upstream.buffer_size;
[3532]     if (size < conf->upstream.bufs.size) {
[3533]         size = conf->upstream.bufs.size;
[3534]     }
[3535] 
[3536] 
[3537]     ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
[3538]                               prev->upstream.busy_buffers_size_conf,
[3539]                               NGX_CONF_UNSET_SIZE);
[3540] 
[3541]     if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
[3542]         conf->upstream.busy_buffers_size = 2 * size;
[3543]     } else {
[3544]         conf->upstream.busy_buffers_size =
[3545]                                          conf->upstream.busy_buffers_size_conf;
[3546]     }
[3547] 
[3548]     if (conf->upstream.busy_buffers_size < size) {
[3549]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3550]              "\"proxy_busy_buffers_size\" must be equal to or greater than "
[3551]              "the maximum of the value of \"proxy_buffer_size\" and "
[3552]              "one of the \"proxy_buffers\"");
[3553] 
[3554]         return NGX_CONF_ERROR;
[3555]     }
[3556] 
[3557]     if (conf->upstream.busy_buffers_size
[3558]         > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
[3559]     {
[3560]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3561]              "\"proxy_busy_buffers_size\" must be less than "
[3562]              "the size of all \"proxy_buffers\" minus one buffer");
[3563] 
[3564]         return NGX_CONF_ERROR;
[3565]     }
[3566] 
[3567] 
[3568]     ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
[3569]                               prev->upstream.temp_file_write_size_conf,
[3570]                               NGX_CONF_UNSET_SIZE);
[3571] 
[3572]     if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
[3573]         conf->upstream.temp_file_write_size = 2 * size;
[3574]     } else {
[3575]         conf->upstream.temp_file_write_size =
[3576]                                       conf->upstream.temp_file_write_size_conf;
[3577]     }
[3578] 
[3579]     if (conf->upstream.temp_file_write_size < size) {
[3580]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3581]              "\"proxy_temp_file_write_size\" must be equal to or greater "
[3582]              "than the maximum of the value of \"proxy_buffer_size\" and "
[3583]              "one of the \"proxy_buffers\"");
[3584] 
[3585]         return NGX_CONF_ERROR;
[3586]     }
[3587] 
[3588]     ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
[3589]                               prev->upstream.max_temp_file_size_conf,
[3590]                               NGX_CONF_UNSET_SIZE);
[3591] 
[3592]     if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
[3593]         conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
[3594]     } else {
[3595]         conf->upstream.max_temp_file_size =
[3596]                                         conf->upstream.max_temp_file_size_conf;
[3597]     }
[3598] 
[3599]     if (conf->upstream.max_temp_file_size != 0
[3600]         && conf->upstream.max_temp_file_size < size)
[3601]     {
[3602]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3603]              "\"proxy_max_temp_file_size\" must be equal to zero to disable "
[3604]              "temporary files usage or must be equal to or greater than "
[3605]              "the maximum of the value of \"proxy_buffer_size\" and "
[3606]              "one of the \"proxy_buffers\"");
[3607] 
[3608]         return NGX_CONF_ERROR;
[3609]     }
[3610] 
[3611] 
[3612]     ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
[3613]                               prev->upstream.ignore_headers,
[3614]                               NGX_CONF_BITMASK_SET);
[3615] 
[3616] 
[3617]     ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
[3618]                               prev->upstream.next_upstream,
[3619]                               (NGX_CONF_BITMASK_SET
[3620]                                |NGX_HTTP_UPSTREAM_FT_ERROR
[3621]                                |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
[3622] 
[3623]     if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
[3624]         conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
[3625]                                        |NGX_HTTP_UPSTREAM_FT_OFF;
[3626]     }
[3627] 
[3628]     if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
[3629]                               prev->upstream.temp_path,
[3630]                               &ngx_http_proxy_temp_path)
[3631]         != NGX_OK)
[3632]     {
[3633]         return NGX_CONF_ERROR;
[3634]     }
[3635] 
[3636] 
[3637] #if (NGX_HTTP_CACHE)
[3638] 
[3639]     if (conf->upstream.cache == NGX_CONF_UNSET) {
[3640]         ngx_conf_merge_value(conf->upstream.cache,
[3641]                               prev->upstream.cache, 0);
[3642] 
[3643]         conf->upstream.cache_zone = prev->upstream.cache_zone;
[3644]         conf->upstream.cache_value = prev->upstream.cache_value;
[3645]     }
[3646] 
[3647]     if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
[3648]         ngx_shm_zone_t  *shm_zone;
[3649] 
[3650]         shm_zone = conf->upstream.cache_zone;
[3651] 
[3652]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3653]                            "\"proxy_cache\" zone \"%V\" is unknown",
[3654]                            &shm_zone->shm.name);
[3655] 
[3656]         return NGX_CONF_ERROR;
[3657]     }
[3658] 
[3659]     ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
[3660]                               prev->upstream.cache_min_uses, 1);
[3661] 
[3662]     ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
[3663]                               prev->upstream.cache_max_range_offset,
[3664]                               NGX_MAX_OFF_T_VALUE);
[3665] 
[3666]     ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
[3667]                               prev->upstream.cache_use_stale,
[3668]                               (NGX_CONF_BITMASK_SET
[3669]                                |NGX_HTTP_UPSTREAM_FT_OFF));
[3670] 
[3671]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
[3672]         conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
[3673]                                          |NGX_HTTP_UPSTREAM_FT_OFF;
[3674]     }
[3675] 
[3676]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
[3677]         conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
[3678]     }
[3679] 
[3680]     if (conf->upstream.cache_methods == 0) {
[3681]         conf->upstream.cache_methods = prev->upstream.cache_methods;
[3682]     }
[3683] 
[3684]     conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;
[3685] 
[3686]     ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
[3687]                              prev->upstream.cache_bypass, NULL);
[3688] 
[3689]     ngx_conf_merge_ptr_value(conf->upstream.no_cache,
[3690]                              prev->upstream.no_cache, NULL);
[3691] 
[3692]     ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
[3693]                              prev->upstream.cache_valid, NULL);
[3694] 
[3695]     if (conf->cache_key.value.data == NULL) {
[3696]         conf->cache_key = prev->cache_key;
[3697]     }
[3698] 
[3699]     ngx_conf_merge_value(conf->upstream.cache_lock,
[3700]                               prev->upstream.cache_lock, 0);
[3701] 
[3702]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
[3703]                               prev->upstream.cache_lock_timeout, 5000);
[3704] 
[3705]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
[3706]                               prev->upstream.cache_lock_age, 5000);
[3707] 
[3708]     ngx_conf_merge_value(conf->upstream.cache_revalidate,
[3709]                               prev->upstream.cache_revalidate, 0);
[3710] 
[3711]     ngx_conf_merge_value(conf->upstream.cache_convert_head,
[3712]                               prev->upstream.cache_convert_head, 1);
[3713] 
[3714]     ngx_conf_merge_value(conf->upstream.cache_background_update,
[3715]                               prev->upstream.cache_background_update, 0);
[3716] 
[3717] #endif
[3718] 
[3719]     ngx_conf_merge_value(conf->upstream.pass_request_headers,
[3720]                               prev->upstream.pass_request_headers, 1);
[3721]     ngx_conf_merge_value(conf->upstream.pass_request_body,
[3722]                               prev->upstream.pass_request_body, 1);
[3723] 
[3724]     ngx_conf_merge_value(conf->upstream.intercept_errors,
[3725]                               prev->upstream.intercept_errors, 0);
[3726] 
[3727] #if (NGX_HTTP_SSL)
[3728] 
[3729]     if (ngx_http_proxy_merge_ssl(cf, conf, prev) != NGX_OK) {
[3730]         return NGX_CONF_ERROR;
[3731]     }
[3732] 
[3733]     ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
[3734]                               prev->upstream.ssl_session_reuse, 1);
[3735] 
[3736]     ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
[3737]                                  (NGX_CONF_BITMASK_SET
[3738]                                   |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[3739]                                   |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[3740] 
[3741]     ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
[3742]                              "DEFAULT");
[3743] 
[3744]     ngx_conf_merge_ptr_value(conf->upstream.ssl_name,
[3745]                               prev->upstream.ssl_name, NULL);
[3746]     ngx_conf_merge_value(conf->upstream.ssl_server_name,
[3747]                               prev->upstream.ssl_server_name, 0);
[3748]     ngx_conf_merge_value(conf->upstream.ssl_verify,
[3749]                               prev->upstream.ssl_verify, 0);
[3750]     ngx_conf_merge_uint_value(conf->ssl_verify_depth,
[3751]                               prev->ssl_verify_depth, 1);
[3752]     ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
[3753]                               prev->ssl_trusted_certificate, "");
[3754]     ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
[3755] 
[3756]     ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate,
[3757]                               prev->upstream.ssl_certificate, NULL);
[3758]     ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
[3759]                               prev->upstream.ssl_certificate_key, NULL);
[3760]     ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords,
[3761]                               prev->upstream.ssl_passwords, NULL);
[3762] 
[3763]     ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
[3764]                               prev->ssl_conf_commands, NULL);
[3765] 
[3766]     if (conf->ssl && ngx_http_proxy_set_ssl(cf, conf) != NGX_OK) {
[3767]         return NGX_CONF_ERROR;
[3768]     }
[3769] 
[3770] #endif
[3771] 
[3772]     ngx_conf_merge_ptr_value(conf->method, prev->method, NULL);
[3773] 
[3774]     ngx_conf_merge_value(conf->redirect, prev->redirect, 1);
[3775] 
[3776]     if (conf->redirect) {
[3777] 
[3778]         if (conf->redirects == NULL) {
[3779]             conf->redirects = prev->redirects;
[3780]         }
[3781] 
[3782]         if (conf->redirects == NULL && conf->url.data) {
[3783] 
[3784]             conf->redirects = ngx_array_create(cf->pool, 1,
[3785]                                              sizeof(ngx_http_proxy_rewrite_t));
[3786]             if (conf->redirects == NULL) {
[3787]                 return NGX_CONF_ERROR;
[3788]             }
[3789] 
[3790]             pr = ngx_array_push(conf->redirects);
[3791]             if (pr == NULL) {
[3792]                 return NGX_CONF_ERROR;
[3793]             }
[3794] 
[3795]             ngx_memzero(&pr->pattern.complex,
[3796]                         sizeof(ngx_http_complex_value_t));
[3797] 
[3798]             ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));
[3799] 
[3800]             pr->handler = ngx_http_proxy_rewrite_complex_handler;
[3801] 
[3802]             if (conf->vars.uri.len) {
[3803]                 pr->pattern.complex.value = conf->url;
[3804]                 pr->replacement.value = conf->location;
[3805] 
[3806]             } else {
[3807]                 pr->pattern.complex.value.len = conf->url.len
[3808]                                                 + sizeof("/") - 1;
[3809] 
[3810]                 p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
[3811]                 if (p == NULL) {
[3812]                     return NGX_CONF_ERROR;
[3813]                 }
[3814] 
[3815]                 pr->pattern.complex.value.data = p;
[3816] 
[3817]                 p = ngx_cpymem(p, conf->url.data, conf->url.len);
[3818]                 *p = '/';
[3819] 
[3820]                 ngx_str_set(&pr->replacement.value, "/");
[3821]             }
[3822]         }
[3823]     }
[3824] 
[3825]     ngx_conf_merge_ptr_value(conf->cookie_domains, prev->cookie_domains, NULL);
[3826] 
[3827]     ngx_conf_merge_ptr_value(conf->cookie_paths, prev->cookie_paths, NULL);
[3828] 
[3829]     ngx_conf_merge_ptr_value(conf->cookie_flags, prev->cookie_flags, NULL);
[3830] 
[3831]     ngx_conf_merge_uint_value(conf->http_version, prev->http_version,
[3832]                               NGX_HTTP_VERSION_10);
[3833] 
[3834]     ngx_conf_merge_uint_value(conf->headers_hash_max_size,
[3835]                               prev->headers_hash_max_size, 512);
[3836] 
[3837]     ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
[3838]                               prev->headers_hash_bucket_size, 64);
[3839] 
[3840]     conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
[3841]                                                ngx_cacheline_size);
[3842] 
[3843]     hash.max_size = conf->headers_hash_max_size;
[3844]     hash.bucket_size = conf->headers_hash_bucket_size;
[3845]     hash.name = "proxy_headers_hash";
[3846] 
[3847]     if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
[3848]             &prev->upstream, ngx_http_proxy_hide_headers, &hash)
[3849]         != NGX_OK)
[3850]     {
[3851]         return NGX_CONF_ERROR;
[3852]     }
[3853] 
[3854]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[3855] 
[3856]     if (clcf->noname
[3857]         && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL)
[3858]     {
[3859]         conf->upstream.upstream = prev->upstream.upstream;
[3860]         conf->location = prev->location;
[3861]         conf->vars = prev->vars;
[3862] 
[3863]         conf->proxy_lengths = prev->proxy_lengths;
[3864]         conf->proxy_values = prev->proxy_values;
[3865] 
[3866] #if (NGX_HTTP_SSL)
[3867]         conf->ssl = prev->ssl;
[3868] #endif
[3869]     }
[3870] 
[3871]     if (clcf->lmt_excpt && clcf->handler == NULL
[3872]         && (conf->upstream.upstream || conf->proxy_lengths))
[3873]     {
[3874]         clcf->handler = ngx_http_proxy_handler;
[3875]     }
[3876] 
[3877]     if (conf->body_source.data == NULL) {
[3878]         conf->body_flushes = prev->body_flushes;
[3879]         conf->body_source = prev->body_source;
[3880]         conf->body_lengths = prev->body_lengths;
[3881]         conf->body_values = prev->body_values;
[3882]     }
[3883] 
[3884]     if (conf->body_source.data && conf->body_lengths == NULL) {
[3885] 
[3886]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[3887] 
[3888]         sc.cf = cf;
[3889]         sc.source = &conf->body_source;
[3890]         sc.flushes = &conf->body_flushes;
[3891]         sc.lengths = &conf->body_lengths;
[3892]         sc.values = &conf->body_values;
[3893]         sc.complete_lengths = 1;
[3894]         sc.complete_values = 1;
[3895] 
[3896]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[3897]             return NGX_CONF_ERROR;
[3898]         }
[3899]     }
[3900] 
[3901]     ngx_conf_merge_ptr_value(conf->headers_source, prev->headers_source, NULL);
[3902] 
[3903]     if (conf->headers_source == prev->headers_source) {
[3904]         conf->headers = prev->headers;
[3905] #if (NGX_HTTP_CACHE)
[3906]         conf->headers_cache = prev->headers_cache;
[3907] #endif
[3908]     }
[3909] 
[3910]     rc = ngx_http_proxy_init_headers(cf, conf, &conf->headers,
[3911]                                      ngx_http_proxy_headers);
[3912]     if (rc != NGX_OK) {
[3913]         return NGX_CONF_ERROR;
[3914]     }
[3915] 
[3916] #if (NGX_HTTP_CACHE)
[3917] 
[3918]     if (conf->upstream.cache) {
[3919]         rc = ngx_http_proxy_init_headers(cf, conf, &conf->headers_cache,
[3920]                                          ngx_http_proxy_cache_headers);
[3921]         if (rc != NGX_OK) {
[3922]             return NGX_CONF_ERROR;
[3923]         }
[3924]     }
[3925] 
[3926] #endif
[3927] 
[3928]     /*
[3929]      * special handling to preserve conf->headers in the "http" section
[3930]      * to inherit it to all servers
[3931]      */
[3932] 
[3933]     if (prev->headers.hash.buckets == NULL
[3934]         && conf->headers_source == prev->headers_source)
[3935]     {
[3936]         prev->headers = conf->headers;
[3937] #if (NGX_HTTP_CACHE)
[3938]         prev->headers_cache = conf->headers_cache;
[3939] #endif
[3940]     }
[3941] 
[3942]     return NGX_CONF_OK;
[3943] }
[3944] 
[3945] 
[3946] static ngx_int_t
[3947] ngx_http_proxy_init_headers(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
[3948]     ngx_http_proxy_headers_t *headers, ngx_keyval_t *default_headers)
[3949] {
[3950]     u_char                       *p;
[3951]     size_t                        size;
[3952]     uintptr_t                    *code;
[3953]     ngx_uint_t                    i;
[3954]     ngx_array_t                   headers_names, headers_merged;
[3955]     ngx_keyval_t                 *src, *s, *h;
[3956]     ngx_hash_key_t               *hk;
[3957]     ngx_hash_init_t               hash;
[3958]     ngx_http_script_compile_t     sc;
[3959]     ngx_http_script_copy_code_t  *copy;
[3960] 
[3961]     if (headers->hash.buckets) {
[3962]         return NGX_OK;
[3963]     }
[3964] 
[3965]     if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
[3966]         != NGX_OK)
[3967]     {
[3968]         return NGX_ERROR;
[3969]     }
[3970] 
[3971]     if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
[3972]         != NGX_OK)
[3973]     {
[3974]         return NGX_ERROR;
[3975]     }
[3976] 
[3977]     headers->lengths = ngx_array_create(cf->pool, 64, 1);
[3978]     if (headers->lengths == NULL) {
[3979]         return NGX_ERROR;
[3980]     }
[3981] 
[3982]     headers->values = ngx_array_create(cf->pool, 512, 1);
[3983]     if (headers->values == NULL) {
[3984]         return NGX_ERROR;
[3985]     }
[3986] 
[3987]     if (conf->headers_source) {
[3988] 
[3989]         src = conf->headers_source->elts;
[3990]         for (i = 0; i < conf->headers_source->nelts; i++) {
[3991] 
[3992]             s = ngx_array_push(&headers_merged);
[3993]             if (s == NULL) {
[3994]                 return NGX_ERROR;
[3995]             }
[3996] 
[3997]             *s = src[i];
[3998]         }
[3999]     }
[4000] 
[4001]     h = default_headers;
[4002] 
[4003]     while (h->key.len) {
[4004] 
[4005]         src = headers_merged.elts;
[4006]         for (i = 0; i < headers_merged.nelts; i++) {
[4007]             if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
[4008]                 goto next;
[4009]             }
[4010]         }
[4011] 
[4012]         s = ngx_array_push(&headers_merged);
[4013]         if (s == NULL) {
[4014]             return NGX_ERROR;
[4015]         }
[4016] 
[4017]         *s = *h;
[4018] 
[4019]     next:
[4020] 
[4021]         h++;
[4022]     }
[4023] 
[4024] 
[4025]     src = headers_merged.elts;
[4026]     for (i = 0; i < headers_merged.nelts; i++) {
[4027] 
[4028]         hk = ngx_array_push(&headers_names);
[4029]         if (hk == NULL) {
[4030]             return NGX_ERROR;
[4031]         }
[4032] 
[4033]         hk->key = src[i].key;
[4034]         hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
[4035]         hk->value = (void *) 1;
[4036] 
[4037]         if (src[i].value.len == 0) {
[4038]             continue;
[4039]         }
[4040] 
[4041]         copy = ngx_array_push_n(headers->lengths,
[4042]                                 sizeof(ngx_http_script_copy_code_t));
[4043]         if (copy == NULL) {
[4044]             return NGX_ERROR;
[4045]         }
[4046] 
[4047]         copy->code = (ngx_http_script_code_pt) (void *)
[4048]                                                  ngx_http_script_copy_len_code;
[4049]         copy->len = src[i].key.len;
[4050] 
[4051]         size = (sizeof(ngx_http_script_copy_code_t)
[4052]                 + src[i].key.len + sizeof(uintptr_t) - 1)
[4053]                & ~(sizeof(uintptr_t) - 1);
[4054] 
[4055]         copy = ngx_array_push_n(headers->values, size);
[4056]         if (copy == NULL) {
[4057]             return NGX_ERROR;
[4058]         }
[4059] 
[4060]         copy->code = ngx_http_script_copy_code;
[4061]         copy->len = src[i].key.len;
[4062] 
[4063]         p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
[4064]         ngx_memcpy(p, src[i].key.data, src[i].key.len);
[4065] 
[4066]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[4067] 
[4068]         sc.cf = cf;
[4069]         sc.source = &src[i].value;
[4070]         sc.flushes = &headers->flushes;
[4071]         sc.lengths = &headers->lengths;
[4072]         sc.values = &headers->values;
[4073] 
[4074]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[4075]             return NGX_ERROR;
[4076]         }
[4077] 
[4078]         code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
[4079]         if (code == NULL) {
[4080]             return NGX_ERROR;
[4081]         }
[4082] 
[4083]         *code = (uintptr_t) NULL;
[4084] 
[4085]         code = ngx_array_push_n(headers->values, sizeof(uintptr_t));
[4086]         if (code == NULL) {
[4087]             return NGX_ERROR;
[4088]         }
[4089] 
[4090]         *code = (uintptr_t) NULL;
[4091]     }
[4092] 
[4093]     code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
[4094]     if (code == NULL) {
[4095]         return NGX_ERROR;
[4096]     }
[4097] 
[4098]     *code = (uintptr_t) NULL;
[4099] 
[4100] 
[4101]     hash.hash = &headers->hash;
[4102]     hash.key = ngx_hash_key_lc;
[4103]     hash.max_size = conf->headers_hash_max_size;
[4104]     hash.bucket_size = conf->headers_hash_bucket_size;
[4105]     hash.name = "proxy_headers_hash";
[4106]     hash.pool = cf->pool;
[4107]     hash.temp_pool = NULL;
[4108] 
[4109]     return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
[4110] }
[4111] 
[4112] 
[4113] static char *
[4114] ngx_http_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4115] {
[4116]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4117] 
[4118]     size_t                      add;
[4119]     u_short                     port;
[4120]     ngx_str_t                  *value, *url;
[4121]     ngx_url_t                   u;
[4122]     ngx_uint_t                  n;
[4123]     ngx_http_core_loc_conf_t   *clcf;
[4124]     ngx_http_script_compile_t   sc;
[4125] 
[4126]     if (plcf->upstream.upstream || plcf->proxy_lengths) {
[4127]         return "is duplicate";
[4128]     }
[4129] 
[4130]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[4131] 
[4132]     clcf->handler = ngx_http_proxy_handler;
[4133] 
[4134]     if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
[4135]         clcf->auto_redirect = 1;
[4136]     }
[4137] 
[4138]     value = cf->args->elts;
[4139] 
[4140]     url = &value[1];
[4141] 
[4142]     n = ngx_http_script_variables_count(url);
[4143] 
[4144]     if (n) {
[4145] 
[4146]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[4147] 
[4148]         sc.cf = cf;
[4149]         sc.source = url;
[4150]         sc.lengths = &plcf->proxy_lengths;
[4151]         sc.values = &plcf->proxy_values;
[4152]         sc.variables = n;
[4153]         sc.complete_lengths = 1;
[4154]         sc.complete_values = 1;
[4155] 
[4156]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[4157]             return NGX_CONF_ERROR;
[4158]         }
[4159] 
[4160] #if (NGX_HTTP_SSL)
[4161]         plcf->ssl = 1;
[4162] #endif
[4163] 
[4164]         return NGX_CONF_OK;
[4165]     }
[4166] 
[4167]     if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
[4168]         add = 7;
[4169]         port = 80;
[4170] 
[4171]     } else if (ngx_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {
[4172] 
[4173] #if (NGX_HTTP_SSL)
[4174]         plcf->ssl = 1;
[4175] 
[4176]         add = 8;
[4177]         port = 443;
[4178] #else
[4179]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4180]                            "https protocol requires SSL support");
[4181]         return NGX_CONF_ERROR;
[4182] #endif
[4183] 
[4184]     } else {
[4185]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL prefix");
[4186]         return NGX_CONF_ERROR;
[4187]     }
[4188] 
[4189]     ngx_memzero(&u, sizeof(ngx_url_t));
[4190] 
[4191]     u.url.len = url->len - add;
[4192]     u.url.data = url->data + add;
[4193]     u.default_port = port;
[4194]     u.uri_part = 1;
[4195]     u.no_resolve = 1;
[4196] 
[4197]     plcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
[4198]     if (plcf->upstream.upstream == NULL) {
[4199]         return NGX_CONF_ERROR;
[4200]     }
[4201] 
[4202]     plcf->vars.schema.len = add;
[4203]     plcf->vars.schema.data = url->data;
[4204]     plcf->vars.key_start = plcf->vars.schema;
[4205] 
[4206]     ngx_http_proxy_set_vars(&u, &plcf->vars);
[4207] 
[4208]     plcf->location = clcf->name;
[4209] 
[4210]     if (clcf->named
[4211] #if (NGX_PCRE)
[4212]         || clcf->regex
[4213] #endif
[4214]         || clcf->noname)
[4215]     {
[4216]         if (plcf->vars.uri.len) {
[4217]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4218]                                "\"proxy_pass\" cannot have URI part in "
[4219]                                "location given by regular expression, "
[4220]                                "or inside named location, "
[4221]                                "or inside \"if\" statement, "
[4222]                                "or inside \"limit_except\" block");
[4223]             return NGX_CONF_ERROR;
[4224]         }
[4225] 
[4226]         plcf->location.len = 0;
[4227]     }
[4228] 
[4229]     plcf->url = *url;
[4230] 
[4231]     return NGX_CONF_OK;
[4232] }
[4233] 
[4234] 
[4235] static char *
[4236] ngx_http_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4237] {
[4238]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4239] 
[4240]     u_char                            *p;
[4241]     ngx_str_t                         *value;
[4242]     ngx_http_proxy_rewrite_t          *pr;
[4243]     ngx_http_compile_complex_value_t   ccv;
[4244] 
[4245]     if (plcf->redirect == 0) {
[4246]         return "is duplicate";
[4247]     }
[4248] 
[4249]     plcf->redirect = 1;
[4250] 
[4251]     value = cf->args->elts;
[4252] 
[4253]     if (cf->args->nelts == 2) {
[4254]         if (ngx_strcmp(value[1].data, "off") == 0) {
[4255] 
[4256]             if (plcf->redirects) {
[4257]                 return "is duplicate";
[4258]             }
[4259] 
[4260]             plcf->redirect = 0;
[4261]             return NGX_CONF_OK;
[4262]         }
[4263] 
[4264]         if (ngx_strcmp(value[1].data, "default") != 0) {
[4265]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4266]                                "invalid parameter \"%V\"", &value[1]);
[4267]             return NGX_CONF_ERROR;
[4268]         }
[4269]     }
[4270] 
[4271]     if (plcf->redirects == NULL) {
[4272]         plcf->redirects = ngx_array_create(cf->pool, 1,
[4273]                                            sizeof(ngx_http_proxy_rewrite_t));
[4274]         if (plcf->redirects == NULL) {
[4275]             return NGX_CONF_ERROR;
[4276]         }
[4277]     }
[4278] 
[4279]     pr = ngx_array_push(plcf->redirects);
[4280]     if (pr == NULL) {
[4281]         return NGX_CONF_ERROR;
[4282]     }
[4283] 
[4284]     if (cf->args->nelts == 2
[4285]         && ngx_strcmp(value[1].data, "default") == 0)
[4286]     {
[4287]         if (plcf->proxy_lengths) {
[4288]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4289]                                "\"proxy_redirect default\" cannot be used "
[4290]                                "with \"proxy_pass\" directive with variables");
[4291]             return NGX_CONF_ERROR;
[4292]         }
[4293] 
[4294]         if (plcf->url.data == NULL) {
[4295]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4296]                                "\"proxy_redirect default\" should be placed "
[4297]                                "after the \"proxy_pass\" directive");
[4298]             return NGX_CONF_ERROR;
[4299]         }
[4300] 
[4301]         pr->handler = ngx_http_proxy_rewrite_complex_handler;
[4302] 
[4303]         ngx_memzero(&pr->pattern.complex, sizeof(ngx_http_complex_value_t));
[4304] 
[4305]         ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));
[4306] 
[4307]         if (plcf->vars.uri.len) {
[4308]             pr->pattern.complex.value = plcf->url;
[4309]             pr->replacement.value = plcf->location;
[4310] 
[4311]         } else {
[4312]             pr->pattern.complex.value.len = plcf->url.len + sizeof("/") - 1;
[4313] 
[4314]             p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
[4315]             if (p == NULL) {
[4316]                 return NGX_CONF_ERROR;
[4317]             }
[4318] 
[4319]             pr->pattern.complex.value.data = p;
[4320] 
[4321]             p = ngx_cpymem(p, plcf->url.data, plcf->url.len);
[4322]             *p = '/';
[4323] 
[4324]             ngx_str_set(&pr->replacement.value, "/");
[4325]         }
[4326] 
[4327]         return NGX_CONF_OK;
[4328]     }
[4329] 
[4330] 
[4331]     if (value[1].data[0] == '~') {
[4332]         value[1].len--;
[4333]         value[1].data++;
[4334] 
[4335]         if (value[1].data[0] == '*') {
[4336]             value[1].len--;
[4337]             value[1].data++;
[4338] 
[4339]             if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
[4340]                 return NGX_CONF_ERROR;
[4341]             }
[4342] 
[4343]         } else {
[4344]             if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != NGX_OK) {
[4345]                 return NGX_CONF_ERROR;
[4346]             }
[4347]         }
[4348] 
[4349]     } else {
[4350] 
[4351]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4352] 
[4353]         ccv.cf = cf;
[4354]         ccv.value = &value[1];
[4355]         ccv.complex_value = &pr->pattern.complex;
[4356] 
[4357]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4358]             return NGX_CONF_ERROR;
[4359]         }
[4360] 
[4361]         pr->handler = ngx_http_proxy_rewrite_complex_handler;
[4362]     }
[4363] 
[4364] 
[4365]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4366] 
[4367]     ccv.cf = cf;
[4368]     ccv.value = &value[2];
[4369]     ccv.complex_value = &pr->replacement;
[4370] 
[4371]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4372]         return NGX_CONF_ERROR;
[4373]     }
[4374] 
[4375]     return NGX_CONF_OK;
[4376] }
[4377] 
[4378] 
[4379] static char *
[4380] ngx_http_proxy_cookie_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4381] {
[4382]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4383] 
[4384]     ngx_str_t                         *value;
[4385]     ngx_http_proxy_rewrite_t          *pr;
[4386]     ngx_http_compile_complex_value_t   ccv;
[4387] 
[4388]     if (plcf->cookie_domains == NULL) {
[4389]         return "is duplicate";
[4390]     }
[4391] 
[4392]     value = cf->args->elts;
[4393] 
[4394]     if (cf->args->nelts == 2) {
[4395] 
[4396]         if (ngx_strcmp(value[1].data, "off") == 0) {
[4397] 
[4398]             if (plcf->cookie_domains != NGX_CONF_UNSET_PTR) {
[4399]                 return "is duplicate";
[4400]             }
[4401] 
[4402]             plcf->cookie_domains = NULL;
[4403]             return NGX_CONF_OK;
[4404]         }
[4405] 
[4406]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4407]                            "invalid parameter \"%V\"", &value[1]);
[4408]         return NGX_CONF_ERROR;
[4409]     }
[4410] 
[4411]     if (plcf->cookie_domains == NGX_CONF_UNSET_PTR) {
[4412]         plcf->cookie_domains = ngx_array_create(cf->pool, 1,
[4413]                                      sizeof(ngx_http_proxy_rewrite_t));
[4414]         if (plcf->cookie_domains == NULL) {
[4415]             return NGX_CONF_ERROR;
[4416]         }
[4417]     }
[4418] 
[4419]     pr = ngx_array_push(plcf->cookie_domains);
[4420]     if (pr == NULL) {
[4421]         return NGX_CONF_ERROR;
[4422]     }
[4423] 
[4424]     if (value[1].data[0] == '~') {
[4425]         value[1].len--;
[4426]         value[1].data++;
[4427] 
[4428]         if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
[4429]             return NGX_CONF_ERROR;
[4430]         }
[4431] 
[4432]     } else {
[4433] 
[4434]         if (value[1].data[0] == '.') {
[4435]             value[1].len--;
[4436]             value[1].data++;
[4437]         }
[4438] 
[4439]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4440] 
[4441]         ccv.cf = cf;
[4442]         ccv.value = &value[1];
[4443]         ccv.complex_value = &pr->pattern.complex;
[4444] 
[4445]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4446]             return NGX_CONF_ERROR;
[4447]         }
[4448] 
[4449]         pr->handler = ngx_http_proxy_rewrite_domain_handler;
[4450] 
[4451]         if (value[2].data[0] == '.') {
[4452]             value[2].len--;
[4453]             value[2].data++;
[4454]         }
[4455]     }
[4456] 
[4457]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4458] 
[4459]     ccv.cf = cf;
[4460]     ccv.value = &value[2];
[4461]     ccv.complex_value = &pr->replacement;
[4462] 
[4463]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4464]         return NGX_CONF_ERROR;
[4465]     }
[4466] 
[4467]     return NGX_CONF_OK;
[4468] }
[4469] 
[4470] 
[4471] static char *
[4472] ngx_http_proxy_cookie_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4473] {
[4474]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4475] 
[4476]     ngx_str_t                         *value;
[4477]     ngx_http_proxy_rewrite_t          *pr;
[4478]     ngx_http_compile_complex_value_t   ccv;
[4479] 
[4480]     if (plcf->cookie_paths == NULL) {
[4481]         return "is duplicate";
[4482]     }
[4483] 
[4484]     value = cf->args->elts;
[4485] 
[4486]     if (cf->args->nelts == 2) {
[4487] 
[4488]         if (ngx_strcmp(value[1].data, "off") == 0) {
[4489] 
[4490]             if (plcf->cookie_paths != NGX_CONF_UNSET_PTR) {
[4491]                 return "is duplicate";
[4492]             }
[4493] 
[4494]             plcf->cookie_paths = NULL;
[4495]             return NGX_CONF_OK;
[4496]         }
[4497] 
[4498]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4499]                            "invalid parameter \"%V\"", &value[1]);
[4500]         return NGX_CONF_ERROR;
[4501]     }
[4502] 
[4503]     if (plcf->cookie_paths == NGX_CONF_UNSET_PTR) {
[4504]         plcf->cookie_paths = ngx_array_create(cf->pool, 1,
[4505]                                      sizeof(ngx_http_proxy_rewrite_t));
[4506]         if (plcf->cookie_paths == NULL) {
[4507]             return NGX_CONF_ERROR;
[4508]         }
[4509]     }
[4510] 
[4511]     pr = ngx_array_push(plcf->cookie_paths);
[4512]     if (pr == NULL) {
[4513]         return NGX_CONF_ERROR;
[4514]     }
[4515] 
[4516]     if (value[1].data[0] == '~') {
[4517]         value[1].len--;
[4518]         value[1].data++;
[4519] 
[4520]         if (value[1].data[0] == '*') {
[4521]             value[1].len--;
[4522]             value[1].data++;
[4523] 
[4524]             if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
[4525]                 return NGX_CONF_ERROR;
[4526]             }
[4527] 
[4528]         } else {
[4529]             if (ngx_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != NGX_OK) {
[4530]                 return NGX_CONF_ERROR;
[4531]             }
[4532]         }
[4533] 
[4534]     } else {
[4535] 
[4536]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4537] 
[4538]         ccv.cf = cf;
[4539]         ccv.value = &value[1];
[4540]         ccv.complex_value = &pr->pattern.complex;
[4541] 
[4542]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4543]             return NGX_CONF_ERROR;
[4544]         }
[4545] 
[4546]         pr->handler = ngx_http_proxy_rewrite_complex_handler;
[4547]     }
[4548] 
[4549]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4550] 
[4551]     ccv.cf = cf;
[4552]     ccv.value = &value[2];
[4553]     ccv.complex_value = &pr->replacement;
[4554] 
[4555]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4556]         return NGX_CONF_ERROR;
[4557]     }
[4558] 
[4559]     return NGX_CONF_OK;
[4560] }
[4561] 
[4562] 
[4563] static char *
[4564] ngx_http_proxy_cookie_flags(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4565] {
[4566]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4567] 
[4568]     ngx_str_t                         *value;
[4569]     ngx_uint_t                         i;
[4570]     ngx_http_complex_value_t          *cv;
[4571]     ngx_http_proxy_cookie_flags_t     *pcf;
[4572]     ngx_http_compile_complex_value_t   ccv;
[4573] #if (NGX_PCRE)
[4574]     ngx_regex_compile_t                rc;
[4575]     u_char                             errstr[NGX_MAX_CONF_ERRSTR];
[4576] #endif
[4577] 
[4578]     if (plcf->cookie_flags == NULL) {
[4579]         return "is duplicate";
[4580]     }
[4581] 
[4582]     value = cf->args->elts;
[4583] 
[4584]     if (cf->args->nelts == 2) {
[4585] 
[4586]         if (ngx_strcmp(value[1].data, "off") == 0) {
[4587] 
[4588]             if (plcf->cookie_flags != NGX_CONF_UNSET_PTR) {
[4589]                 return "is duplicate";
[4590]             }
[4591] 
[4592]             plcf->cookie_flags = NULL;
[4593]             return NGX_CONF_OK;
[4594]         }
[4595] 
[4596]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4597]                            "invalid parameter \"%V\"", &value[1]);
[4598]         return NGX_CONF_ERROR;
[4599]     }
[4600] 
[4601]     if (plcf->cookie_flags == NGX_CONF_UNSET_PTR) {
[4602]         plcf->cookie_flags = ngx_array_create(cf->pool, 1,
[4603]                                         sizeof(ngx_http_proxy_cookie_flags_t));
[4604]         if (plcf->cookie_flags == NULL) {
[4605]             return NGX_CONF_ERROR;
[4606]         }
[4607]     }
[4608] 
[4609]     pcf = ngx_array_push(plcf->cookie_flags);
[4610]     if (pcf == NULL) {
[4611]         return NGX_CONF_ERROR;
[4612]     }
[4613] 
[4614]     pcf->regex = 0;
[4615] 
[4616]     if (value[1].data[0] == '~') {
[4617]         value[1].len--;
[4618]         value[1].data++;
[4619] 
[4620] #if (NGX_PCRE)
[4621]         ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[4622] 
[4623]         rc.pattern = value[1];
[4624]         rc.err.len = NGX_MAX_CONF_ERRSTR;
[4625]         rc.err.data = errstr;
[4626]         rc.options = NGX_REGEX_CASELESS;
[4627] 
[4628]         pcf->cookie.regex = ngx_http_regex_compile(cf, &rc);
[4629]         if (pcf->cookie.regex == NULL) {
[4630]             return NGX_CONF_ERROR;
[4631]         }
[4632] 
[4633]         pcf->regex = 1;
[4634] #else
[4635]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4636]                            "using regex \"%V\" requires PCRE library",
[4637]                            &value[1]);
[4638]         return NGX_CONF_ERROR;
[4639] #endif
[4640] 
[4641]     } else {
[4642] 
[4643]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4644] 
[4645]         ccv.cf = cf;
[4646]         ccv.value = &value[1];
[4647]         ccv.complex_value = &pcf->cookie.complex;
[4648] 
[4649]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4650]             return NGX_CONF_ERROR;
[4651]         }
[4652]     }
[4653] 
[4654]     if (ngx_array_init(&pcf->flags_values, cf->pool, cf->args->nelts - 2,
[4655]                        sizeof(ngx_http_complex_value_t))
[4656]         != NGX_OK)
[4657]     {
[4658]         return NGX_CONF_ERROR;
[4659]     }
[4660] 
[4661]     for (i = 2; i < cf->args->nelts; i++) {
[4662] 
[4663]         cv = ngx_array_push(&pcf->flags_values);
[4664]         if (cv == NULL) {
[4665]             return NGX_CONF_ERROR;
[4666]         }
[4667] 
[4668]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4669] 
[4670]         ccv.cf = cf;
[4671]         ccv.value = &value[i];
[4672]         ccv.complex_value = cv;
[4673] 
[4674]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4675]             return NGX_CONF_ERROR;
[4676]         }
[4677]     }
[4678] 
[4679]     return NGX_CONF_OK;
[4680] }
[4681] 
[4682] 
[4683] static ngx_int_t
[4684] ngx_http_proxy_rewrite_regex(ngx_conf_t *cf, ngx_http_proxy_rewrite_t *pr,
[4685]     ngx_str_t *regex, ngx_uint_t caseless)
[4686] {
[4687] #if (NGX_PCRE)
[4688]     u_char               errstr[NGX_MAX_CONF_ERRSTR];
[4689]     ngx_regex_compile_t  rc;
[4690] 
[4691]     ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[4692] 
[4693]     rc.pattern = *regex;
[4694]     rc.err.len = NGX_MAX_CONF_ERRSTR;
[4695]     rc.err.data = errstr;
[4696] 
[4697]     if (caseless) {
[4698]         rc.options = NGX_REGEX_CASELESS;
[4699]     }
[4700] 
[4701]     pr->pattern.regex = ngx_http_regex_compile(cf, &rc);
[4702]     if (pr->pattern.regex == NULL) {
[4703]         return NGX_ERROR;
[4704]     }
[4705] 
[4706]     pr->handler = ngx_http_proxy_rewrite_regex_handler;
[4707] 
[4708]     return NGX_OK;
[4709] 
[4710] #else
[4711] 
[4712]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4713]                        "using regex \"%V\" requires PCRE library", regex);
[4714]     return NGX_ERROR;
[4715] 
[4716] #endif
[4717] }
[4718] 
[4719] 
[4720] static char *
[4721] ngx_http_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4722] {
[4723]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4724] 
[4725]     ngx_str_t                  *value;
[4726]     ngx_http_script_compile_t   sc;
[4727] 
[4728]     if (plcf->upstream.store != NGX_CONF_UNSET) {
[4729]         return "is duplicate";
[4730]     }
[4731] 
[4732]     value = cf->args->elts;
[4733] 
[4734]     if (ngx_strcmp(value[1].data, "off") == 0) {
[4735]         plcf->upstream.store = 0;
[4736]         return NGX_CONF_OK;
[4737]     }
[4738] 
[4739] #if (NGX_HTTP_CACHE)
[4740]     if (plcf->upstream.cache > 0) {
[4741]         return "is incompatible with \"proxy_cache\"";
[4742]     }
[4743] #endif
[4744] 
[4745]     plcf->upstream.store = 1;
[4746] 
[4747]     if (ngx_strcmp(value[1].data, "on") == 0) {
[4748]         return NGX_CONF_OK;
[4749]     }
[4750] 
[4751]     /* include the terminating '\0' into script */
[4752]     value[1].len++;
[4753] 
[4754]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[4755] 
[4756]     sc.cf = cf;
[4757]     sc.source = &value[1];
[4758]     sc.lengths = &plcf->upstream.store_lengths;
[4759]     sc.values = &plcf->upstream.store_values;
[4760]     sc.variables = ngx_http_script_variables_count(&value[1]);
[4761]     sc.complete_lengths = 1;
[4762]     sc.complete_values = 1;
[4763] 
[4764]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[4765]         return NGX_CONF_ERROR;
[4766]     }
[4767] 
[4768]     return NGX_CONF_OK;
[4769] }
[4770] 
[4771] 
[4772] #if (NGX_HTTP_CACHE)
[4773] 
[4774] static char *
[4775] ngx_http_proxy_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4776] {
[4777]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4778] 
[4779]     ngx_str_t                         *value;
[4780]     ngx_http_complex_value_t           cv;
[4781]     ngx_http_compile_complex_value_t   ccv;
[4782] 
[4783]     value = cf->args->elts;
[4784] 
[4785]     if (plcf->upstream.cache != NGX_CONF_UNSET) {
[4786]         return "is duplicate";
[4787]     }
[4788] 
[4789]     if (ngx_strcmp(value[1].data, "off") == 0) {
[4790]         plcf->upstream.cache = 0;
[4791]         return NGX_CONF_OK;
[4792]     }
[4793] 
[4794]     if (plcf->upstream.store > 0) {
[4795]         return "is incompatible with \"proxy_store\"";
[4796]     }
[4797] 
[4798]     plcf->upstream.cache = 1;
[4799] 
[4800]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4801] 
[4802]     ccv.cf = cf;
[4803]     ccv.value = &value[1];
[4804]     ccv.complex_value = &cv;
[4805] 
[4806]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4807]         return NGX_CONF_ERROR;
[4808]     }
[4809] 
[4810]     if (cv.lengths != NULL) {
[4811] 
[4812]         plcf->upstream.cache_value = ngx_palloc(cf->pool,
[4813]                                              sizeof(ngx_http_complex_value_t));
[4814]         if (plcf->upstream.cache_value == NULL) {
[4815]             return NGX_CONF_ERROR;
[4816]         }
[4817] 
[4818]         *plcf->upstream.cache_value = cv;
[4819] 
[4820]         return NGX_CONF_OK;
[4821]     }
[4822] 
[4823]     plcf->upstream.cache_zone = ngx_shared_memory_add(cf, &value[1], 0,
[4824]                                                       &ngx_http_proxy_module);
[4825]     if (plcf->upstream.cache_zone == NULL) {
[4826]         return NGX_CONF_ERROR;
[4827]     }
[4828] 
[4829]     return NGX_CONF_OK;
[4830] }
[4831] 
[4832] 
[4833] static char *
[4834] ngx_http_proxy_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4835] {
[4836]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4837] 
[4838]     ngx_str_t                         *value;
[4839]     ngx_http_compile_complex_value_t   ccv;
[4840] 
[4841]     value = cf->args->elts;
[4842] 
[4843]     if (plcf->cache_key.value.data) {
[4844]         return "is duplicate";
[4845]     }
[4846] 
[4847]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4848] 
[4849]     ccv.cf = cf;
[4850]     ccv.value = &value[1];
[4851]     ccv.complex_value = &plcf->cache_key;
[4852] 
[4853]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4854]         return NGX_CONF_ERROR;
[4855]     }
[4856] 
[4857]     return NGX_CONF_OK;
[4858] }
[4859] 
[4860] #endif
[4861] 
[4862] 
[4863] #if (NGX_HTTP_SSL)
[4864] 
[4865] static char *
[4866] ngx_http_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4867] {
[4868]     ngx_http_proxy_loc_conf_t *plcf = conf;
[4869] 
[4870]     ngx_str_t  *value;
[4871] 
[4872]     if (plcf->upstream.ssl_passwords != NGX_CONF_UNSET_PTR) {
[4873]         return "is duplicate";
[4874]     }
[4875] 
[4876]     value = cf->args->elts;
[4877] 
[4878]     plcf->upstream.ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);
[4879] 
[4880]     if (plcf->upstream.ssl_passwords == NULL) {
[4881]         return NGX_CONF_ERROR;
[4882]     }
[4883] 
[4884]     return NGX_CONF_OK;
[4885] }
[4886] 
[4887] #endif
[4888] 
[4889] 
[4890] static char *
[4891] ngx_http_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data)
[4892] {
[4893] #if (NGX_FREEBSD)
[4894]     ssize_t *np = data;
[4895] 
[4896]     if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
[4897]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4898]                            "\"proxy_send_lowat\" must be less than %d "
[4899]                            "(sysctl net.inet.tcp.sendspace)",
[4900]                            ngx_freebsd_net_inet_tcp_sendspace);
[4901] 
[4902]         return NGX_CONF_ERROR;
[4903]     }
[4904] 
[4905] #elif !(NGX_HAVE_SO_SNDLOWAT)
[4906]     ssize_t *np = data;
[4907] 
[4908]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[4909]                        "\"proxy_send_lowat\" is not supported, ignored");
[4910] 
[4911]     *np = 0;
[4912] 
[4913] #endif
[4914] 
[4915]     return NGX_CONF_OK;
[4916] }
[4917] 
[4918] 
[4919] #if (NGX_HTTP_SSL)
[4920] 
[4921] static char *
[4922] ngx_http_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[4923] {
[4924] #ifndef SSL_CONF_FLAG_FILE
[4925]     return "is not supported on this platform";
[4926] #else
[4927]     return NGX_CONF_OK;
[4928] #endif
[4929] }
[4930] 
[4931] 
[4932] static ngx_int_t
[4933] ngx_http_proxy_merge_ssl(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *conf,
[4934]     ngx_http_proxy_loc_conf_t *prev)
[4935] {
[4936]     ngx_uint_t  preserve;
[4937] 
[4938]     if (conf->ssl_protocols == 0
[4939]         && conf->ssl_ciphers.data == NULL
[4940]         && conf->upstream.ssl_certificate == NGX_CONF_UNSET_PTR
[4941]         && conf->upstream.ssl_certificate_key == NGX_CONF_UNSET_PTR
[4942]         && conf->upstream.ssl_passwords == NGX_CONF_UNSET_PTR
[4943]         && conf->upstream.ssl_verify == NGX_CONF_UNSET
[4944]         && conf->ssl_verify_depth == NGX_CONF_UNSET_UINT
[4945]         && conf->ssl_trusted_certificate.data == NULL
[4946]         && conf->ssl_crl.data == NULL
[4947]         && conf->upstream.ssl_session_reuse == NGX_CONF_UNSET
[4948]         && conf->ssl_conf_commands == NGX_CONF_UNSET_PTR)
[4949]     {
[4950]         if (prev->upstream.ssl) {
[4951]             conf->upstream.ssl = prev->upstream.ssl;
[4952]             return NGX_OK;
[4953]         }
[4954] 
[4955]         preserve = 1;
[4956] 
[4957]     } else {
[4958]         preserve = 0;
[4959]     }
[4960] 
[4961]     conf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
[4962]     if (conf->upstream.ssl == NULL) {
[4963]         return NGX_ERROR;
[4964]     }
[4965] 
[4966]     conf->upstream.ssl->log = cf->log;
[4967] 
[4968]     /*
[4969]      * special handling to preserve conf->upstream.ssl
[4970]      * in the "http" section to inherit it to all servers
[4971]      */
[4972] 
[4973]     if (preserve) {
[4974]         prev->upstream.ssl = conf->upstream.ssl;
[4975]     }
[4976] 
[4977]     return NGX_OK;
[4978] }
[4979] 
[4980] 
[4981] static ngx_int_t
[4982] ngx_http_proxy_set_ssl(ngx_conf_t *cf, ngx_http_proxy_loc_conf_t *plcf)
[4983] {
[4984]     ngx_pool_cleanup_t  *cln;
[4985] 
[4986]     if (plcf->upstream.ssl->ctx) {
[4987]         return NGX_OK;
[4988]     }
[4989] 
[4990]     if (ngx_ssl_create(plcf->upstream.ssl, plcf->ssl_protocols, NULL)
[4991]         != NGX_OK)
[4992]     {
[4993]         return NGX_ERROR;
[4994]     }
[4995] 
[4996]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[4997]     if (cln == NULL) {
[4998]         ngx_ssl_cleanup_ctx(plcf->upstream.ssl);
[4999]         return NGX_ERROR;
[5000]     }
[5001] 
[5002]     cln->handler = ngx_ssl_cleanup_ctx;
[5003]     cln->data = plcf->upstream.ssl;
[5004] 
[5005]     if (ngx_ssl_ciphers(cf, plcf->upstream.ssl, &plcf->ssl_ciphers, 0)
[5006]         != NGX_OK)
[5007]     {
[5008]         return NGX_ERROR;
[5009]     }
[5010] 
[5011]     if (plcf->upstream.ssl_certificate
[5012]         && plcf->upstream.ssl_certificate->value.len)
[5013]     {
[5014]         if (plcf->upstream.ssl_certificate_key == NULL) {
[5015]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[5016]                           "no \"proxy_ssl_certificate_key\" is defined "
[5017]                           "for certificate \"%V\"",
[5018]                           &plcf->upstream.ssl_certificate->value);
[5019]             return NGX_ERROR;
[5020]         }
[5021] 
[5022]         if (plcf->upstream.ssl_certificate->lengths
[5023]             || plcf->upstream.ssl_certificate_key->lengths)
[5024]         {
[5025]             plcf->upstream.ssl_passwords =
[5026]                   ngx_ssl_preserve_passwords(cf, plcf->upstream.ssl_passwords);
[5027]             if (plcf->upstream.ssl_passwords == NULL) {
[5028]                 return NGX_ERROR;
[5029]             }
[5030] 
[5031]         } else {
[5032]             if (ngx_ssl_certificate(cf, plcf->upstream.ssl,
[5033]                                     &plcf->upstream.ssl_certificate->value,
[5034]                                     &plcf->upstream.ssl_certificate_key->value,
[5035]                                     plcf->upstream.ssl_passwords)
[5036]                 != NGX_OK)
[5037]             {
[5038]                 return NGX_ERROR;
[5039]             }
[5040]         }
[5041]     }
[5042] 
[5043]     if (plcf->upstream.ssl_verify) {
[5044]         if (plcf->ssl_trusted_certificate.len == 0) {
[5045]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[5046]                       "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
[5047]             return NGX_ERROR;
[5048]         }
[5049] 
[5050]         if (ngx_ssl_trusted_certificate(cf, plcf->upstream.ssl,
[5051]                                         &plcf->ssl_trusted_certificate,
[5052]                                         plcf->ssl_verify_depth)
[5053]             != NGX_OK)
[5054]         {
[5055]             return NGX_ERROR;
[5056]         }
[5057] 
[5058]         if (ngx_ssl_crl(cf, plcf->upstream.ssl, &plcf->ssl_crl) != NGX_OK) {
[5059]             return NGX_ERROR;
[5060]         }
[5061]     }
[5062] 
[5063]     if (ngx_ssl_client_session_cache(cf, plcf->upstream.ssl,
[5064]                                      plcf->upstream.ssl_session_reuse)
[5065]         != NGX_OK)
[5066]     {
[5067]         return NGX_ERROR;
[5068]     }
[5069] 
[5070]     if (ngx_ssl_conf_commands(cf, plcf->upstream.ssl, plcf->ssl_conf_commands)
[5071]         != NGX_OK)
[5072]     {
[5073]         return NGX_ERROR;
[5074]     }
[5075] 
[5076]     return NGX_OK;
[5077] }
[5078] 
[5079] #endif
[5080] 
[5081] 
[5082] static void
[5083] ngx_http_proxy_set_vars(ngx_url_t *u, ngx_http_proxy_vars_t *v)
[5084] {
[5085]     if (u->family != AF_UNIX) {
[5086] 
[5087]         if (u->no_port || u->port == u->default_port) {
[5088] 
[5089]             v->host_header = u->host;
[5090] 
[5091]             if (u->default_port == 80) {
[5092]                 ngx_str_set(&v->port, "80");
[5093] 
[5094]             } else {
[5095]                 ngx_str_set(&v->port, "443");
[5096]             }
[5097] 
[5098]         } else {
[5099]             v->host_header.len = u->host.len + 1 + u->port_text.len;
[5100]             v->host_header.data = u->host.data;
[5101]             v->port = u->port_text;
[5102]         }
[5103] 
[5104]         v->key_start.len += v->host_header.len;
[5105] 
[5106]     } else {
[5107]         ngx_str_set(&v->host_header, "localhost");
[5108]         ngx_str_null(&v->port);
[5109]         v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
[5110]     }
[5111] 
[5112]     v->uri = u->uri;
[5113] }
