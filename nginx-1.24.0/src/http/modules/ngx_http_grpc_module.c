[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] typedef struct {
[14]     ngx_array_t               *flushes;
[15]     ngx_array_t               *lengths;
[16]     ngx_array_t               *values;
[17]     ngx_hash_t                 hash;
[18] } ngx_http_grpc_headers_t;
[19] 
[20] 
[21] typedef struct {
[22]     ngx_http_upstream_conf_t   upstream;
[23] 
[24]     ngx_http_grpc_headers_t    headers;
[25]     ngx_array_t               *headers_source;
[26] 
[27]     ngx_str_t                  host;
[28]     ngx_uint_t                 host_set;
[29] 
[30]     ngx_array_t               *grpc_lengths;
[31]     ngx_array_t               *grpc_values;
[32] 
[33] #if (NGX_HTTP_SSL)
[34]     ngx_uint_t                 ssl;
[35]     ngx_uint_t                 ssl_protocols;
[36]     ngx_str_t                  ssl_ciphers;
[37]     ngx_uint_t                 ssl_verify_depth;
[38]     ngx_str_t                  ssl_trusted_certificate;
[39]     ngx_str_t                  ssl_crl;
[40]     ngx_array_t               *ssl_conf_commands;
[41] #endif
[42] } ngx_http_grpc_loc_conf_t;
[43] 
[44] 
[45] typedef enum {
[46]     ngx_http_grpc_st_start = 0,
[47]     ngx_http_grpc_st_length_2,
[48]     ngx_http_grpc_st_length_3,
[49]     ngx_http_grpc_st_type,
[50]     ngx_http_grpc_st_flags,
[51]     ngx_http_grpc_st_stream_id,
[52]     ngx_http_grpc_st_stream_id_2,
[53]     ngx_http_grpc_st_stream_id_3,
[54]     ngx_http_grpc_st_stream_id_4,
[55]     ngx_http_grpc_st_payload,
[56]     ngx_http_grpc_st_padding
[57] } ngx_http_grpc_state_e;
[58] 
[59] 
[60] typedef struct {
[61]     size_t                     init_window;
[62]     size_t                     send_window;
[63]     size_t                     recv_window;
[64]     ngx_uint_t                 last_stream_id;
[65] } ngx_http_grpc_conn_t;
[66] 
[67] 
[68] typedef struct {
[69]     ngx_http_grpc_state_e      state;
[70]     ngx_uint_t                 frame_state;
[71]     ngx_uint_t                 fragment_state;
[72] 
[73]     ngx_chain_t               *in;
[74]     ngx_chain_t               *out;
[75]     ngx_chain_t               *free;
[76]     ngx_chain_t               *busy;
[77] 
[78]     ngx_http_grpc_conn_t      *connection;
[79] 
[80]     ngx_uint_t                 id;
[81] 
[82]     ngx_uint_t                 pings;
[83]     ngx_uint_t                 settings;
[84] 
[85]     off_t                      length;
[86] 
[87]     ssize_t                    send_window;
[88]     size_t                     recv_window;
[89] 
[90]     size_t                     rest;
[91]     ngx_uint_t                 stream_id;
[92]     u_char                     type;
[93]     u_char                     flags;
[94]     u_char                     padding;
[95] 
[96]     ngx_uint_t                 error;
[97]     ngx_uint_t                 window_update;
[98] 
[99]     ngx_uint_t                 setting_id;
[100]     ngx_uint_t                 setting_value;
[101] 
[102]     u_char                     ping_data[8];
[103] 
[104]     ngx_uint_t                 index;
[105]     ngx_str_t                  name;
[106]     ngx_str_t                  value;
[107] 
[108]     u_char                    *field_end;
[109]     size_t                     field_length;
[110]     size_t                     field_rest;
[111]     u_char                     field_state;
[112] 
[113]     unsigned                   literal:1;
[114]     unsigned                   field_huffman:1;
[115] 
[116]     unsigned                   header_sent:1;
[117]     unsigned                   output_closed:1;
[118]     unsigned                   output_blocked:1;
[119]     unsigned                   parsing_headers:1;
[120]     unsigned                   end_stream:1;
[121]     unsigned                   done:1;
[122]     unsigned                   status:1;
[123]     unsigned                   rst:1;
[124]     unsigned                   goaway:1;
[125] 
[126]     ngx_http_request_t        *request;
[127] 
[128]     ngx_str_t                  host;
[129] } ngx_http_grpc_ctx_t;
[130] 
[131] 
[132] typedef struct {
[133]     u_char                     length_0;
[134]     u_char                     length_1;
[135]     u_char                     length_2;
[136]     u_char                     type;
[137]     u_char                     flags;
[138]     u_char                     stream_id_0;
[139]     u_char                     stream_id_1;
[140]     u_char                     stream_id_2;
[141]     u_char                     stream_id_3;
[142] } ngx_http_grpc_frame_t;
[143] 
[144] 
[145] static ngx_int_t ngx_http_grpc_eval(ngx_http_request_t *r,
[146]     ngx_http_grpc_ctx_t *ctx, ngx_http_grpc_loc_conf_t *glcf);
[147] static ngx_int_t ngx_http_grpc_create_request(ngx_http_request_t *r);
[148] static ngx_int_t ngx_http_grpc_reinit_request(ngx_http_request_t *r);
[149] static ngx_int_t ngx_http_grpc_body_output_filter(void *data, ngx_chain_t *in);
[150] static ngx_int_t ngx_http_grpc_process_header(ngx_http_request_t *r);
[151] static ngx_int_t ngx_http_grpc_filter_init(void *data);
[152] static ngx_int_t ngx_http_grpc_filter(void *data, ssize_t bytes);
[153] 
[154] static ngx_int_t ngx_http_grpc_parse_frame(ngx_http_request_t *r,
[155]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[156] static ngx_int_t ngx_http_grpc_parse_header(ngx_http_request_t *r,
[157]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[158] static ngx_int_t ngx_http_grpc_parse_fragment(ngx_http_request_t *r,
[159]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[160] static ngx_int_t ngx_http_grpc_validate_header_name(ngx_http_request_t *r,
[161]     ngx_str_t *s);
[162] static ngx_int_t ngx_http_grpc_validate_header_value(ngx_http_request_t *r,
[163]     ngx_str_t *s);
[164] static ngx_int_t ngx_http_grpc_parse_rst_stream(ngx_http_request_t *r,
[165]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[166] static ngx_int_t ngx_http_grpc_parse_goaway(ngx_http_request_t *r,
[167]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[168] static ngx_int_t ngx_http_grpc_parse_window_update(ngx_http_request_t *r,
[169]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[170] static ngx_int_t ngx_http_grpc_parse_settings(ngx_http_request_t *r,
[171]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[172] static ngx_int_t ngx_http_grpc_parse_ping(ngx_http_request_t *r,
[173]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b);
[174] 
[175] static ngx_int_t ngx_http_grpc_send_settings_ack(ngx_http_request_t *r,
[176]     ngx_http_grpc_ctx_t *ctx);
[177] static ngx_int_t ngx_http_grpc_send_ping_ack(ngx_http_request_t *r,
[178]     ngx_http_grpc_ctx_t *ctx);
[179] static ngx_int_t ngx_http_grpc_send_window_update(ngx_http_request_t *r,
[180]     ngx_http_grpc_ctx_t *ctx);
[181] 
[182] static ngx_chain_t *ngx_http_grpc_get_buf(ngx_http_request_t *r,
[183]     ngx_http_grpc_ctx_t *ctx);
[184] static ngx_http_grpc_ctx_t *ngx_http_grpc_get_ctx(ngx_http_request_t *r);
[185] static ngx_int_t ngx_http_grpc_get_connection_data(ngx_http_request_t *r,
[186]     ngx_http_grpc_ctx_t *ctx, ngx_peer_connection_t *pc);
[187] static void ngx_http_grpc_cleanup(void *data);
[188] 
[189] static void ngx_http_grpc_abort_request(ngx_http_request_t *r);
[190] static void ngx_http_grpc_finalize_request(ngx_http_request_t *r,
[191]     ngx_int_t rc);
[192] 
[193] static ngx_int_t ngx_http_grpc_internal_trailers_variable(
[194]     ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
[195] 
[196] static ngx_int_t ngx_http_grpc_add_variables(ngx_conf_t *cf);
[197] static void *ngx_http_grpc_create_loc_conf(ngx_conf_t *cf);
[198] static char *ngx_http_grpc_merge_loc_conf(ngx_conf_t *cf,
[199]     void *parent, void *child);
[200] static ngx_int_t ngx_http_grpc_init_headers(ngx_conf_t *cf,
[201]     ngx_http_grpc_loc_conf_t *conf, ngx_http_grpc_headers_t *headers,
[202]     ngx_keyval_t *default_headers);
[203] 
[204] static char *ngx_http_grpc_pass(ngx_conf_t *cf, ngx_command_t *cmd,
[205]     void *conf);
[206] 
[207] #if (NGX_HTTP_SSL)
[208] static char *ngx_http_grpc_ssl_password_file(ngx_conf_t *cf,
[209]     ngx_command_t *cmd, void *conf);
[210] static char *ngx_http_grpc_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[211]     void *data);
[212] static ngx_int_t ngx_http_grpc_merge_ssl(ngx_conf_t *cf,
[213]     ngx_http_grpc_loc_conf_t *conf, ngx_http_grpc_loc_conf_t *prev);
[214] static ngx_int_t ngx_http_grpc_set_ssl(ngx_conf_t *cf,
[215]     ngx_http_grpc_loc_conf_t *glcf);
[216] #endif
[217] 
[218] 
[219] static ngx_conf_bitmask_t  ngx_http_grpc_next_upstream_masks[] = {
[220]     { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
[221]     { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
[222]     { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
[223]     { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
[224]     { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
[225]     { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
[226]     { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
[227]     { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
[228]     { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
[229]     { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[230]     { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
[231]     { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
[232]     { ngx_null_string, 0 }
[233] };
[234] 
[235] 
[236] #if (NGX_HTTP_SSL)
[237] 
[238] static ngx_conf_bitmask_t  ngx_http_grpc_ssl_protocols[] = {
[239]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[240]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[241]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[242]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[243]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[244]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[245]     { ngx_null_string, 0 }
[246] };
[247] 
[248] static ngx_conf_post_t  ngx_http_grpc_ssl_conf_command_post =
[249]     { ngx_http_grpc_ssl_conf_command_check };
[250] 
[251] #endif
[252] 
[253] 
[254] static ngx_command_t  ngx_http_grpc_commands[] = {
[255] 
[256]     { ngx_string("grpc_pass"),
[257]       NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[258]       ngx_http_grpc_pass,
[259]       NGX_HTTP_LOC_CONF_OFFSET,
[260]       0,
[261]       NULL },
[262] 
[263]     { ngx_string("grpc_bind"),
[264]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[265]       ngx_http_upstream_bind_set_slot,
[266]       NGX_HTTP_LOC_CONF_OFFSET,
[267]       offsetof(ngx_http_grpc_loc_conf_t, upstream.local),
[268]       NULL },
[269] 
[270]     { ngx_string("grpc_socket_keepalive"),
[271]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[272]       ngx_conf_set_flag_slot,
[273]       NGX_HTTP_LOC_CONF_OFFSET,
[274]       offsetof(ngx_http_grpc_loc_conf_t, upstream.socket_keepalive),
[275]       NULL },
[276] 
[277]     { ngx_string("grpc_connect_timeout"),
[278]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[279]       ngx_conf_set_msec_slot,
[280]       NGX_HTTP_LOC_CONF_OFFSET,
[281]       offsetof(ngx_http_grpc_loc_conf_t, upstream.connect_timeout),
[282]       NULL },
[283] 
[284]     { ngx_string("grpc_send_timeout"),
[285]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[286]       ngx_conf_set_msec_slot,
[287]       NGX_HTTP_LOC_CONF_OFFSET,
[288]       offsetof(ngx_http_grpc_loc_conf_t, upstream.send_timeout),
[289]       NULL },
[290] 
[291]     { ngx_string("grpc_intercept_errors"),
[292]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[293]       ngx_conf_set_flag_slot,
[294]       NGX_HTTP_LOC_CONF_OFFSET,
[295]       offsetof(ngx_http_grpc_loc_conf_t, upstream.intercept_errors),
[296]       NULL },
[297] 
[298]     { ngx_string("grpc_buffer_size"),
[299]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[300]       ngx_conf_set_size_slot,
[301]       NGX_HTTP_LOC_CONF_OFFSET,
[302]       offsetof(ngx_http_grpc_loc_conf_t, upstream.buffer_size),
[303]       NULL },
[304] 
[305]     { ngx_string("grpc_read_timeout"),
[306]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[307]       ngx_conf_set_msec_slot,
[308]       NGX_HTTP_LOC_CONF_OFFSET,
[309]       offsetof(ngx_http_grpc_loc_conf_t, upstream.read_timeout),
[310]       NULL },
[311] 
[312]     { ngx_string("grpc_next_upstream"),
[313]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[314]       ngx_conf_set_bitmask_slot,
[315]       NGX_HTTP_LOC_CONF_OFFSET,
[316]       offsetof(ngx_http_grpc_loc_conf_t, upstream.next_upstream),
[317]       &ngx_http_grpc_next_upstream_masks },
[318] 
[319]     { ngx_string("grpc_next_upstream_tries"),
[320]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[321]       ngx_conf_set_num_slot,
[322]       NGX_HTTP_LOC_CONF_OFFSET,
[323]       offsetof(ngx_http_grpc_loc_conf_t, upstream.next_upstream_tries),
[324]       NULL },
[325] 
[326]     { ngx_string("grpc_next_upstream_timeout"),
[327]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[328]       ngx_conf_set_msec_slot,
[329]       NGX_HTTP_LOC_CONF_OFFSET,
[330]       offsetof(ngx_http_grpc_loc_conf_t, upstream.next_upstream_timeout),
[331]       NULL },
[332] 
[333]     { ngx_string("grpc_set_header"),
[334]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[335]       ngx_conf_set_keyval_slot,
[336]       NGX_HTTP_LOC_CONF_OFFSET,
[337]       offsetof(ngx_http_grpc_loc_conf_t, headers_source),
[338]       NULL },
[339] 
[340]     { ngx_string("grpc_pass_header"),
[341]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[342]       ngx_conf_set_str_array_slot,
[343]       NGX_HTTP_LOC_CONF_OFFSET,
[344]       offsetof(ngx_http_grpc_loc_conf_t, upstream.pass_headers),
[345]       NULL },
[346] 
[347]     { ngx_string("grpc_hide_header"),
[348]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[349]       ngx_conf_set_str_array_slot,
[350]       NGX_HTTP_LOC_CONF_OFFSET,
[351]       offsetof(ngx_http_grpc_loc_conf_t, upstream.hide_headers),
[352]       NULL },
[353] 
[354]     { ngx_string("grpc_ignore_headers"),
[355]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[356]       ngx_conf_set_bitmask_slot,
[357]       NGX_HTTP_LOC_CONF_OFFSET,
[358]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ignore_headers),
[359]       &ngx_http_upstream_ignore_headers_masks },
[360] 
[361] #if (NGX_HTTP_SSL)
[362] 
[363]     { ngx_string("grpc_ssl_session_reuse"),
[364]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[365]       ngx_conf_set_flag_slot,
[366]       NGX_HTTP_LOC_CONF_OFFSET,
[367]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_session_reuse),
[368]       NULL },
[369] 
[370]     { ngx_string("grpc_ssl_protocols"),
[371]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[372]       ngx_conf_set_bitmask_slot,
[373]       NGX_HTTP_LOC_CONF_OFFSET,
[374]       offsetof(ngx_http_grpc_loc_conf_t, ssl_protocols),
[375]       &ngx_http_grpc_ssl_protocols },
[376] 
[377]     { ngx_string("grpc_ssl_ciphers"),
[378]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[379]       ngx_conf_set_str_slot,
[380]       NGX_HTTP_LOC_CONF_OFFSET,
[381]       offsetof(ngx_http_grpc_loc_conf_t, ssl_ciphers),
[382]       NULL },
[383] 
[384]     { ngx_string("grpc_ssl_name"),
[385]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[386]       ngx_http_set_complex_value_slot,
[387]       NGX_HTTP_LOC_CONF_OFFSET,
[388]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_name),
[389]       NULL },
[390] 
[391]     { ngx_string("grpc_ssl_server_name"),
[392]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[393]       ngx_conf_set_flag_slot,
[394]       NGX_HTTP_LOC_CONF_OFFSET,
[395]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_server_name),
[396]       NULL },
[397] 
[398]     { ngx_string("grpc_ssl_verify"),
[399]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[400]       ngx_conf_set_flag_slot,
[401]       NGX_HTTP_LOC_CONF_OFFSET,
[402]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_verify),
[403]       NULL },
[404] 
[405]     { ngx_string("grpc_ssl_verify_depth"),
[406]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[407]       ngx_conf_set_num_slot,
[408]       NGX_HTTP_LOC_CONF_OFFSET,
[409]       offsetof(ngx_http_grpc_loc_conf_t, ssl_verify_depth),
[410]       NULL },
[411] 
[412]     { ngx_string("grpc_ssl_trusted_certificate"),
[413]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[414]       ngx_conf_set_str_slot,
[415]       NGX_HTTP_LOC_CONF_OFFSET,
[416]       offsetof(ngx_http_grpc_loc_conf_t, ssl_trusted_certificate),
[417]       NULL },
[418] 
[419]     { ngx_string("grpc_ssl_crl"),
[420]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[421]       ngx_conf_set_str_slot,
[422]       NGX_HTTP_LOC_CONF_OFFSET,
[423]       offsetof(ngx_http_grpc_loc_conf_t, ssl_crl),
[424]       NULL },
[425] 
[426]     { ngx_string("grpc_ssl_certificate"),
[427]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[428]       ngx_http_set_complex_value_zero_slot,
[429]       NGX_HTTP_LOC_CONF_OFFSET,
[430]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_certificate),
[431]       NULL },
[432] 
[433]     { ngx_string("grpc_ssl_certificate_key"),
[434]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[435]       ngx_http_set_complex_value_zero_slot,
[436]       NGX_HTTP_LOC_CONF_OFFSET,
[437]       offsetof(ngx_http_grpc_loc_conf_t, upstream.ssl_certificate_key),
[438]       NULL },
[439] 
[440]     { ngx_string("grpc_ssl_password_file"),
[441]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[442]       ngx_http_grpc_ssl_password_file,
[443]       NGX_HTTP_LOC_CONF_OFFSET,
[444]       0,
[445]       NULL },
[446] 
[447]     { ngx_string("grpc_ssl_conf_command"),
[448]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[449]       ngx_conf_set_keyval_slot,
[450]       NGX_HTTP_LOC_CONF_OFFSET,
[451]       offsetof(ngx_http_grpc_loc_conf_t, ssl_conf_commands),
[452]       &ngx_http_grpc_ssl_conf_command_post },
[453] 
[454] #endif
[455] 
[456]       ngx_null_command
[457] };
[458] 
[459] 
[460] static ngx_http_module_t  ngx_http_grpc_module_ctx = {
[461]     ngx_http_grpc_add_variables,           /* preconfiguration */
[462]     NULL,                                  /* postconfiguration */
[463] 
[464]     NULL,                                  /* create main configuration */
[465]     NULL,                                  /* init main configuration */
[466] 
[467]     NULL,                                  /* create server configuration */
[468]     NULL,                                  /* merge server configuration */
[469] 
[470]     ngx_http_grpc_create_loc_conf,         /* create location configuration */
[471]     ngx_http_grpc_merge_loc_conf           /* merge location configuration */
[472] };
[473] 
[474] 
[475] ngx_module_t  ngx_http_grpc_module = {
[476]     NGX_MODULE_V1,
[477]     &ngx_http_grpc_module_ctx,             /* module context */
[478]     ngx_http_grpc_commands,                /* module directives */
[479]     NGX_HTTP_MODULE,                       /* module type */
[480]     NULL,                                  /* init master */
[481]     NULL,                                  /* init module */
[482]     NULL,                                  /* init process */
[483]     NULL,                                  /* init thread */
[484]     NULL,                                  /* exit thread */
[485]     NULL,                                  /* exit process */
[486]     NULL,                                  /* exit master */
[487]     NGX_MODULE_V1_PADDING
[488] };
[489] 
[490] 
[491] static u_char  ngx_http_grpc_connection_start[] =
[492]     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */
[493] 
[494]     "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
[495]     "\x00\x01\x00\x00\x00\x00"                 /* header table size */
[496]     "\x00\x02\x00\x00\x00\x00"                 /* disable push */
[497]     "\x00\x04\x7f\xff\xff\xff"                 /* initial window */
[498] 
[499]     "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
[500]     "\x7f\xff\x00\x00";
[501] 
[502] 
[503] static ngx_keyval_t  ngx_http_grpc_headers[] = {
[504]     { ngx_string("Content-Length"), ngx_string("$content_length") },
[505]     { ngx_string("TE"), ngx_string("$grpc_internal_trailers") },
[506]     { ngx_string("Host"), ngx_string("") },
[507]     { ngx_string("Connection"), ngx_string("") },
[508]     { ngx_string("Transfer-Encoding"), ngx_string("") },
[509]     { ngx_string("Keep-Alive"), ngx_string("") },
[510]     { ngx_string("Expect"), ngx_string("") },
[511]     { ngx_string("Upgrade"), ngx_string("") },
[512]     { ngx_null_string, ngx_null_string }
[513] };
[514] 
[515] 
[516] static ngx_str_t  ngx_http_grpc_hide_headers[] = {
[517]     ngx_string("Date"),
[518]     ngx_string("Server"),
[519]     ngx_string("X-Accel-Expires"),
[520]     ngx_string("X-Accel-Redirect"),
[521]     ngx_string("X-Accel-Limit-Rate"),
[522]     ngx_string("X-Accel-Buffering"),
[523]     ngx_string("X-Accel-Charset"),
[524]     ngx_null_string
[525] };
[526] 
[527] 
[528] static ngx_http_variable_t  ngx_http_grpc_vars[] = {
[529] 
[530]     { ngx_string("grpc_internal_trailers"), NULL,
[531]       ngx_http_grpc_internal_trailers_variable, 0,
[532]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[533] 
[534]       ngx_http_null_variable
[535] };
[536] 
[537] 
[538] static ngx_int_t
[539] ngx_http_grpc_handler(ngx_http_request_t *r)
[540] {
[541]     ngx_int_t                  rc;
[542]     ngx_http_upstream_t       *u;
[543]     ngx_http_grpc_ctx_t       *ctx;
[544]     ngx_http_grpc_loc_conf_t  *glcf;
[545] 
[546]     if (ngx_http_upstream_create(r) != NGX_OK) {
[547]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[548]     }
[549] 
[550]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_grpc_ctx_t));
[551]     if (ctx == NULL) {
[552]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[553]     }
[554] 
[555]     ctx->request = r;
[556] 
[557]     ngx_http_set_ctx(r, ctx, ngx_http_grpc_module);
[558] 
[559]     glcf = ngx_http_get_module_loc_conf(r, ngx_http_grpc_module);
[560] 
[561]     u = r->upstream;
[562] 
[563]     if (glcf->grpc_lengths == NULL) {
[564]         ctx->host = glcf->host;
[565] 
[566] #if (NGX_HTTP_SSL)
[567]         u->ssl = glcf->ssl;
[568] 
[569]         if (u->ssl) {
[570]             ngx_str_set(&u->schema, "grpcs://");
[571] 
[572]         } else {
[573]             ngx_str_set(&u->schema, "grpc://");
[574]         }
[575] #else
[576]         ngx_str_set(&u->schema, "grpc://");
[577] #endif
[578] 
[579]     } else {
[580]         if (ngx_http_grpc_eval(r, ctx, glcf) != NGX_OK) {
[581]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[582]         }
[583]     }
[584] 
[585]     u->output.tag = (ngx_buf_tag_t) &ngx_http_grpc_module;
[586] 
[587]     u->conf = &glcf->upstream;
[588] 
[589]     u->create_request = ngx_http_grpc_create_request;
[590]     u->reinit_request = ngx_http_grpc_reinit_request;
[591]     u->process_header = ngx_http_grpc_process_header;
[592]     u->abort_request = ngx_http_grpc_abort_request;
[593]     u->finalize_request = ngx_http_grpc_finalize_request;
[594] 
[595]     u->input_filter_init = ngx_http_grpc_filter_init;
[596]     u->input_filter = ngx_http_grpc_filter;
[597]     u->input_filter_ctx = ctx;
[598] 
[599]     r->request_body_no_buffering = 1;
[600] 
[601]     rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
[602] 
[603]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[604]         return rc;
[605]     }
[606] 
[607]     return NGX_DONE;
[608] }
[609] 
[610] 
[611] static ngx_int_t
[612] ngx_http_grpc_eval(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[613]     ngx_http_grpc_loc_conf_t *glcf)
[614] {
[615]     size_t                add;
[616]     ngx_url_t             url;
[617]     ngx_http_upstream_t  *u;
[618] 
[619]     ngx_memzero(&url, sizeof(ngx_url_t));
[620] 
[621]     if (ngx_http_script_run(r, &url.url, glcf->grpc_lengths->elts, 0,
[622]                             glcf->grpc_values->elts)
[623]         == NULL)
[624]     {
[625]         return NGX_ERROR;
[626]     }
[627] 
[628]     if (url.url.len > 7
[629]         && ngx_strncasecmp(url.url.data, (u_char *) "grpc://", 7) == 0)
[630]     {
[631]         add = 7;
[632] 
[633]     } else if (url.url.len > 8
[634]                && ngx_strncasecmp(url.url.data, (u_char *) "grpcs://", 8) == 0)
[635]     {
[636] 
[637] #if (NGX_HTTP_SSL)
[638]         add = 8;
[639]         r->upstream->ssl = 1;
[640] #else
[641]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[642]                       "grpcs protocol requires SSL support");
[643]         return NGX_ERROR;
[644] #endif
[645] 
[646]     } else {
[647]         add = 0;
[648]     }
[649] 
[650]     u = r->upstream;
[651] 
[652]     if (add) {
[653]         u->schema.len = add;
[654]         u->schema.data = url.url.data;
[655] 
[656]         url.url.data += add;
[657]         url.url.len -= add;
[658] 
[659]     } else {
[660]         ngx_str_set(&u->schema, "grpc://");
[661]     }
[662] 
[663]     url.no_resolve = 1;
[664] 
[665]     if (ngx_parse_url(r->pool, &url) != NGX_OK) {
[666]         if (url.err) {
[667]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[668]                           "%s in upstream \"%V\"", url.err, &url.url);
[669]         }
[670] 
[671]         return NGX_ERROR;
[672]     }
[673] 
[674]     u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
[675]     if (u->resolved == NULL) {
[676]         return NGX_ERROR;
[677]     }
[678] 
[679]     if (url.addrs) {
[680]         u->resolved->sockaddr = url.addrs[0].sockaddr;
[681]         u->resolved->socklen = url.addrs[0].socklen;
[682]         u->resolved->name = url.addrs[0].name;
[683]         u->resolved->naddrs = 1;
[684]     }
[685] 
[686]     u->resolved->host = url.host;
[687]     u->resolved->port = url.port;
[688]     u->resolved->no_port = url.no_port;
[689] 
[690]     if (url.family != AF_UNIX) {
[691] 
[692]         if (url.no_port) {
[693]             ctx->host = url.host;
[694] 
[695]         } else {
[696]             ctx->host.len = url.host.len + 1 + url.port_text.len;
[697]             ctx->host.data = url.host.data;
[698]         }
[699] 
[700]     } else {
[701]         ngx_str_set(&ctx->host, "localhost");
[702]     }
[703] 
[704]     return NGX_OK;
[705] }
[706] 
[707] 
[708] static ngx_int_t
[709] ngx_http_grpc_create_request(ngx_http_request_t *r)
[710] {
[711]     u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame;
[712]     size_t                        len, tmp_len, key_len, val_len, uri_len;
[713]     uintptr_t                     escape;
[714]     ngx_buf_t                    *b;
[715]     ngx_uint_t                    i, next;
[716]     ngx_chain_t                  *cl, *body;
[717]     ngx_list_part_t              *part;
[718]     ngx_table_elt_t              *header;
[719]     ngx_http_grpc_ctx_t          *ctx;
[720]     ngx_http_upstream_t          *u;
[721]     ngx_http_grpc_frame_t        *f;
[722]     ngx_http_script_code_pt       code;
[723]     ngx_http_grpc_loc_conf_t     *glcf;
[724]     ngx_http_script_engine_t      e, le;
[725]     ngx_http_script_len_code_pt   lcode;
[726] 
[727]     u = r->upstream;
[728] 
[729]     glcf = ngx_http_get_module_loc_conf(r, ngx_http_grpc_module);
[730] 
[731]     ctx = ngx_http_get_module_ctx(r, ngx_http_grpc_module);
[732] 
[733]     len = sizeof(ngx_http_grpc_connection_start) - 1
[734]           + sizeof(ngx_http_grpc_frame_t);             /* headers frame */
[735] 
[736]     /* :method header */
[737] 
[738]     if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_POST) {
[739]         len += 1;
[740]         tmp_len = 0;
[741] 
[742]     } else {
[743]         len += 1 + NGX_HTTP_V2_INT_OCTETS + r->method_name.len;
[744]         tmp_len = r->method_name.len;
[745]     }
[746] 
[747]     /* :scheme header */
[748] 
[749]     len += 1;
[750] 
[751]     /* :path header */
[752] 
[753]     if (r->valid_unparsed_uri) {
[754]         escape = 0;
[755]         uri_len = r->unparsed_uri.len;
[756] 
[757]     } else {
[758]         escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
[759]                                     NGX_ESCAPE_URI);
[760]         uri_len = r->uri.len + escape + sizeof("?") - 1 + r->args.len;
[761]     }
[762] 
[763]     len += 1 + NGX_HTTP_V2_INT_OCTETS + uri_len;
[764] 
[765]     if (tmp_len < uri_len) {
[766]         tmp_len = uri_len;
[767]     }
[768] 
[769]     /* :authority header */
[770] 
[771]     if (!glcf->host_set) {
[772]         len += 1 + NGX_HTTP_V2_INT_OCTETS + ctx->host.len;
[773] 
[774]         if (tmp_len < ctx->host.len) {
[775]             tmp_len = ctx->host.len;
[776]         }
[777]     }
[778] 
[779]     /* other headers */
[780] 
[781]     ngx_http_script_flush_no_cacheable_variables(r, glcf->headers.flushes);
[782]     ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[783] 
[784]     le.ip = glcf->headers.lengths->elts;
[785]     le.request = r;
[786]     le.flushed = 1;
[787] 
[788]     while (*(uintptr_t *) le.ip) {
[789] 
[790]         lcode = *(ngx_http_script_len_code_pt *) le.ip;
[791]         key_len = lcode(&le);
[792] 
[793]         for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[794]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[795]         }
[796]         le.ip += sizeof(uintptr_t);
[797] 
[798]         if (val_len == 0) {
[799]             continue;
[800]         }
[801] 
[802]         len += 1 + NGX_HTTP_V2_INT_OCTETS + key_len
[803]                  + NGX_HTTP_V2_INT_OCTETS + val_len;
[804] 
[805]         if (tmp_len < key_len) {
[806]             tmp_len = key_len;
[807]         }
[808] 
[809]         if (tmp_len < val_len) {
[810]             tmp_len = val_len;
[811]         }
[812]     }
[813] 
[814]     if (glcf->upstream.pass_request_headers) {
[815]         part = &r->headers_in.headers.part;
[816]         header = part->elts;
[817] 
[818]         for (i = 0; /* void */; i++) {
[819] 
[820]             if (i >= part->nelts) {
[821]                 if (part->next == NULL) {
[822]                     break;
[823]                 }
[824] 
[825]                 part = part->next;
[826]                 header = part->elts;
[827]                 i = 0;
[828]             }
[829] 
[830]             if (ngx_hash_find(&glcf->headers.hash, header[i].hash,
[831]                               header[i].lowcase_key, header[i].key.len))
[832]             {
[833]                 continue;
[834]             }
[835] 
[836]             len += 1 + NGX_HTTP_V2_INT_OCTETS + header[i].key.len
[837]                      + NGX_HTTP_V2_INT_OCTETS + header[i].value.len;
[838] 
[839]             if (tmp_len < header[i].key.len) {
[840]                 tmp_len = header[i].key.len;
[841]             }
[842] 
[843]             if (tmp_len < header[i].value.len) {
[844]                 tmp_len = header[i].value.len;
[845]             }
[846]         }
[847]     }
[848] 
[849]     /* continuation frames */
[850] 
[851]     len += sizeof(ngx_http_grpc_frame_t)
[852]            * (len / NGX_HTTP_V2_DEFAULT_FRAME_SIZE);
[853] 
[854] 
[855]     b = ngx_create_temp_buf(r->pool, len);
[856]     if (b == NULL) {
[857]         return NGX_ERROR;
[858]     }
[859] 
[860]     cl = ngx_alloc_chain_link(r->pool);
[861]     if (cl == NULL) {
[862]         return NGX_ERROR;
[863]     }
[864] 
[865]     cl->buf = b;
[866]     cl->next = NULL;
[867] 
[868]     tmp = ngx_palloc(r->pool, tmp_len * 3);
[869]     if (tmp == NULL) {
[870]         return NGX_ERROR;
[871]     }
[872] 
[873]     key_tmp = tmp + tmp_len;
[874]     val_tmp = tmp + 2 * tmp_len;
[875] 
[876]     /* connection preface */
[877] 
[878]     b->last = ngx_copy(b->last, ngx_http_grpc_connection_start,
[879]                        sizeof(ngx_http_grpc_connection_start) - 1);
[880] 
[881]     /* headers frame */
[882] 
[883]     headers_frame = b->last;
[884] 
[885]     f = (ngx_http_grpc_frame_t *) b->last;
[886]     b->last += sizeof(ngx_http_grpc_frame_t);
[887] 
[888]     f->length_0 = 0;
[889]     f->length_1 = 0;
[890]     f->length_2 = 0;
[891]     f->type = NGX_HTTP_V2_HEADERS_FRAME;
[892]     f->flags = 0;
[893]     f->stream_id_0 = 0;
[894]     f->stream_id_1 = 0;
[895]     f->stream_id_2 = 0;
[896]     f->stream_id_3 = 1;
[897] 
[898]     if (r->method == NGX_HTTP_GET) {
[899]         *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_GET_INDEX);
[900] 
[901]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[902]                        "grpc header: \":method: GET\"");
[903] 
[904]     } else if (r->method == NGX_HTTP_POST) {
[905]         *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_POST_INDEX);
[906] 
[907]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[908]                        "grpc header: \":method: POST\"");
[909] 
[910]     } else {
[911]         *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_METHOD_INDEX);
[912]         b->last = ngx_http_v2_write_value(b->last, r->method_name.data,
[913]                                           r->method_name.len, tmp);
[914] 
[915]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[916]                        "grpc header: \":method: %V\"", &r->method_name);
[917]     }
[918] 
[919] #if (NGX_HTTP_SSL)
[920]     if (u->ssl) {
[921]         *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX);
[922] 
[923]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[924]                        "grpc header: \":scheme: https\"");
[925]     } else
[926] #endif
[927]     {
[928]         *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX);
[929] 
[930]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[931]                        "grpc header: \":scheme: http\"");
[932]     }
[933] 
[934]     if (r->valid_unparsed_uri) {
[935] 
[936]         if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
[937]             *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_PATH_ROOT_INDEX);
[938] 
[939]         } else {
[940]             *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
[941]             b->last = ngx_http_v2_write_value(b->last, r->unparsed_uri.data,
[942]                                               r->unparsed_uri.len, tmp);
[943]         }
[944] 
[945]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[946]                        "grpc header: \":path: %V\"", &r->unparsed_uri);
[947] 
[948]     } else if (escape || r->args.len > 0) {
[949]         p = val_tmp;
[950] 
[951]         if (escape) {
[952]             p = (u_char *) ngx_escape_uri(p, r->uri.data, r->uri.len,
[953]                                           NGX_ESCAPE_URI);
[954] 
[955]         } else {
[956]             p = ngx_copy(p, r->uri.data, r->uri.len);
[957]         }
[958] 
[959]         if (r->args.len > 0) {
[960]             *p++ = '?';
[961]             p = ngx_copy(p, r->args.data, r->args.len);
[962]         }
[963] 
[964]         *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
[965]         b->last = ngx_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);
[966] 
[967]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[968]                        "grpc header: \":path: %*s\"", p - val_tmp, val_tmp);
[969] 
[970]     } else {
[971]         *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
[972]         b->last = ngx_http_v2_write_value(b->last, r->uri.data,
[973]                                           r->uri.len, tmp);
[974] 
[975]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[976]                        "grpc header: \":path: %V\"", &r->uri);
[977]     }
[978] 
[979]     if (!glcf->host_set) {
[980]         *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX);
[981]         b->last = ngx_http_v2_write_value(b->last, ctx->host.data,
[982]                                           ctx->host.len, tmp);
[983] 
[984]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[985]                        "grpc header: \":authority: %V\"", &ctx->host);
[986]     }
[987] 
[988]     ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[989] 
[990]     e.ip = glcf->headers.values->elts;
[991]     e.request = r;
[992]     e.flushed = 1;
[993] 
[994]     le.ip = glcf->headers.lengths->elts;
[995] 
[996]     while (*(uintptr_t *) le.ip) {
[997] 
[998]         lcode = *(ngx_http_script_len_code_pt *) le.ip;
[999]         key_len = lcode(&le);
[1000] 
[1001]         for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[1002]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1003]         }
[1004]         le.ip += sizeof(uintptr_t);
[1005] 
[1006]         if (val_len == 0) {
[1007]             e.skip = 1;
[1008] 
[1009]             while (*(uintptr_t *) e.ip) {
[1010]                 code = *(ngx_http_script_code_pt *) e.ip;
[1011]                 code((ngx_http_script_engine_t *) &e);
[1012]             }
[1013]             e.ip += sizeof(uintptr_t);
[1014] 
[1015]             e.skip = 0;
[1016] 
[1017]             continue;
[1018]         }
[1019] 
[1020]         *b->last++ = 0;
[1021] 
[1022]         e.pos = key_tmp;
[1023] 
[1024]         code = *(ngx_http_script_code_pt *) e.ip;
[1025]         code((ngx_http_script_engine_t *) &e);
[1026] 
[1027]         b->last = ngx_http_v2_write_name(b->last, key_tmp, key_len, tmp);
[1028] 
[1029]         e.pos = val_tmp;
[1030] 
[1031]         while (*(uintptr_t *) e.ip) {
[1032]             code = *(ngx_http_script_code_pt *) e.ip;
[1033]             code((ngx_http_script_engine_t *) &e);
[1034]         }
[1035]         e.ip += sizeof(uintptr_t);
[1036] 
[1037]         b->last = ngx_http_v2_write_value(b->last, val_tmp, val_len, tmp);
[1038] 
[1039] #if (NGX_DEBUG)
[1040]         if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
[1041]             ngx_strlow(key_tmp, key_tmp, key_len);
[1042] 
[1043]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1044]                            "grpc header: \"%*s: %*s\"",
[1045]                            key_len, key_tmp, val_len, val_tmp);
[1046]         }
[1047] #endif
[1048]     }
[1049] 
[1050]     if (glcf->upstream.pass_request_headers) {
[1051]         part = &r->headers_in.headers.part;
[1052]         header = part->elts;
[1053] 
[1054]         for (i = 0; /* void */; i++) {
[1055] 
[1056]             if (i >= part->nelts) {
[1057]                 if (part->next == NULL) {
[1058]                     break;
[1059]                 }
[1060] 
[1061]                 part = part->next;
[1062]                 header = part->elts;
[1063]                 i = 0;
[1064]             }
[1065] 
[1066]             if (ngx_hash_find(&glcf->headers.hash, header[i].hash,
[1067]                               header[i].lowcase_key, header[i].key.len))
[1068]             {
[1069]                 continue;
[1070]             }
[1071] 
[1072]             *b->last++ = 0;
[1073] 
[1074]             b->last = ngx_http_v2_write_name(b->last, header[i].key.data,
[1075]                                              header[i].key.len, tmp);
[1076] 
[1077]             b->last = ngx_http_v2_write_value(b->last, header[i].value.data,
[1078]                                               header[i].value.len, tmp);
[1079] 
[1080] #if (NGX_DEBUG)
[1081]             if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
[1082]                 ngx_strlow(tmp, header[i].key.data, header[i].key.len);
[1083] 
[1084]                 ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1085]                                "grpc header: \"%*s: %V\"",
[1086]                                header[i].key.len, tmp, &header[i].value);
[1087]             }
[1088] #endif
[1089]         }
[1090]     }
[1091] 
[1092]     /* update headers frame length */
[1093] 
[1094]     len = b->last - headers_frame - sizeof(ngx_http_grpc_frame_t);
[1095] 
[1096]     if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
[1097]         len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
[1098]         next = 1;
[1099] 
[1100]     } else {
[1101]         next = 0;
[1102]     }
[1103] 
[1104]     f = (ngx_http_grpc_frame_t *) headers_frame;
[1105] 
[1106]     f->length_0 = (u_char) ((len >> 16) & 0xff);
[1107]     f->length_1 = (u_char) ((len >> 8) & 0xff);
[1108]     f->length_2 = (u_char) (len & 0xff);
[1109] 
[1110]     /* create additional continuation frames */
[1111] 
[1112]     p = headers_frame;
[1113] 
[1114]     while (next) {
[1115]         p += sizeof(ngx_http_grpc_frame_t) + NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
[1116]         len = b->last - p;
[1117] 
[1118]         ngx_memmove(p + sizeof(ngx_http_grpc_frame_t), p, len);
[1119]         b->last += sizeof(ngx_http_grpc_frame_t);
[1120] 
[1121]         if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
[1122]             len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
[1123]             next = 1;
[1124] 
[1125]         } else {
[1126]             next = 0;
[1127]         }
[1128] 
[1129]         f = (ngx_http_grpc_frame_t *) p;
[1130] 
[1131]         f->length_0 = (u_char) ((len >> 16) & 0xff);
[1132]         f->length_1 = (u_char) ((len >> 8) & 0xff);
[1133]         f->length_2 = (u_char) (len & 0xff);
[1134]         f->type = NGX_HTTP_V2_CONTINUATION_FRAME;
[1135]         f->flags = 0;
[1136]         f->stream_id_0 = 0;
[1137]         f->stream_id_1 = 0;
[1138]         f->stream_id_2 = 0;
[1139]         f->stream_id_3 = 1;
[1140]     }
[1141] 
[1142]     f->flags |= NGX_HTTP_V2_END_HEADERS_FLAG;
[1143] 
[1144]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1145]                    "grpc header: %*xs%s, len: %uz",
[1146]                    (size_t) ngx_min(b->last - b->pos, 256), b->pos,
[1147]                    b->last - b->pos > 256 ? "..." : "",
[1148]                    b->last - b->pos);
[1149] 
[1150]     if (r->request_body_no_buffering) {
[1151] 
[1152]         u->request_bufs = cl;
[1153] 
[1154]     } else {
[1155] 
[1156]         body = u->request_bufs;
[1157]         u->request_bufs = cl;
[1158] 
[1159]         if (body == NULL) {
[1160]             f = (ngx_http_grpc_frame_t *) headers_frame;
[1161]             f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;
[1162]         }
[1163] 
[1164]         while (body) {
[1165]             b = ngx_alloc_buf(r->pool);
[1166]             if (b == NULL) {
[1167]                 return NGX_ERROR;
[1168]             }
[1169] 
[1170]             ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
[1171] 
[1172]             cl->next = ngx_alloc_chain_link(r->pool);
[1173]             if (cl->next == NULL) {
[1174]                 return NGX_ERROR;
[1175]             }
[1176] 
[1177]             cl = cl->next;
[1178]             cl->buf = b;
[1179] 
[1180]             body = body->next;
[1181]         }
[1182] 
[1183]         b->last_buf = 1;
[1184]     }
[1185] 
[1186]     u->output.output_filter = ngx_http_grpc_body_output_filter;
[1187]     u->output.filter_ctx = r;
[1188] 
[1189]     b->flush = 1;
[1190]     cl->next = NULL;
[1191] 
[1192]     return NGX_OK;
[1193] }
[1194] 
[1195] 
[1196] static ngx_int_t
[1197] ngx_http_grpc_reinit_request(ngx_http_request_t *r)
[1198] {
[1199]     ngx_http_grpc_ctx_t  *ctx;
[1200] 
[1201]     ctx = ngx_http_get_module_ctx(r, ngx_http_grpc_module);
[1202] 
[1203]     if (ctx == NULL) {
[1204]         return NGX_OK;
[1205]     }
[1206] 
[1207]     ctx->state = 0;
[1208]     ctx->header_sent = 0;
[1209]     ctx->output_closed = 0;
[1210]     ctx->output_blocked = 0;
[1211]     ctx->parsing_headers = 0;
[1212]     ctx->end_stream = 0;
[1213]     ctx->done = 0;
[1214]     ctx->status = 0;
[1215]     ctx->rst = 0;
[1216]     ctx->goaway = 0;
[1217]     ctx->connection = NULL;
[1218] 
[1219]     return NGX_OK;
[1220] }
[1221] 
[1222] 
[1223] static ngx_int_t
[1224] ngx_http_grpc_body_output_filter(void *data, ngx_chain_t *in)
[1225] {
[1226]     ngx_http_request_t  *r = data;
[1227] 
[1228]     off_t                   file_pos;
[1229]     u_char                 *p, *pos, *start;
[1230]     size_t                  len, limit;
[1231]     ngx_buf_t              *b;
[1232]     ngx_int_t               rc;
[1233]     ngx_uint_t              next, last;
[1234]     ngx_chain_t            *cl, *out, **ll;
[1235]     ngx_http_upstream_t    *u;
[1236]     ngx_http_grpc_ctx_t    *ctx;
[1237]     ngx_http_grpc_frame_t  *f;
[1238] 
[1239]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1240]                    "grpc output filter");
[1241] 
[1242]     ctx = ngx_http_grpc_get_ctx(r);
[1243] 
[1244]     if (ctx == NULL) {
[1245]         return NGX_ERROR;
[1246]     }
[1247] 
[1248]     if (in) {
[1249]         if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
[1250]             return NGX_ERROR;
[1251]         }
[1252]     }
[1253] 
[1254]     out = NULL;
[1255]     ll = &out;
[1256] 
[1257]     if (!ctx->header_sent) {
[1258]         /* first buffer contains headers */
[1259] 
[1260]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1261]                        "grpc output header");
[1262] 
[1263]         ctx->header_sent = 1;
[1264] 
[1265]         if (ctx->id != 1) {
[1266]             /*
[1267]              * keepalive connection: skip connection preface,
[1268]              * update stream identifiers
[1269]              */
[1270] 
[1271]             b = ctx->in->buf;
[1272]             b->pos += sizeof(ngx_http_grpc_connection_start) - 1;
[1273] 
[1274]             p = b->pos;
[1275] 
[1276]             while (p < b->last) {
[1277]                 f = (ngx_http_grpc_frame_t *) p;
[1278]                 p += sizeof(ngx_http_grpc_frame_t);
[1279] 
[1280]                 f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
[1281]                 f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
[1282]                 f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
[1283]                 f->stream_id_3 = (u_char) (ctx->id & 0xff);
[1284] 
[1285]                 p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
[1286]             }
[1287]         }
[1288] 
[1289]         if (ctx->in->buf->last_buf) {
[1290]             ctx->output_closed = 1;
[1291]         }
[1292] 
[1293]         *ll = ctx->in;
[1294]         ll = &ctx->in->next;
[1295] 
[1296]         ctx->in = ctx->in->next;
[1297]     }
[1298] 
[1299]     if (ctx->out) {
[1300]         /* queued control frames */
[1301] 
[1302]         *ll = ctx->out;
[1303] 
[1304]         for (cl = ctx->out, ll = &cl->next; cl; cl = cl->next) {
[1305]             ll = &cl->next;
[1306]         }
[1307] 
[1308]         ctx->out = NULL;
[1309]     }
[1310] 
[1311]     f = NULL;
[1312]     last = 0;
[1313] 
[1314]     limit = ngx_max(0, ctx->send_window);
[1315] 
[1316]     if (limit > ctx->connection->send_window) {
[1317]         limit = ctx->connection->send_window;
[1318]     }
[1319] 
[1320]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1321]                    "grpc output limit: %uz w:%z:%uz",
[1322]                    limit, ctx->send_window, ctx->connection->send_window);
[1323] 
[1324] #if (NGX_SUPPRESS_WARN)
[1325]     file_pos = 0;
[1326]     pos = NULL;
[1327]     cl = NULL;
[1328] #endif
[1329] 
[1330]     in = ctx->in;
[1331] 
[1332]     while (in && limit > 0) {
[1333] 
[1334]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1335]                        "grpc output in  l:%d f:%d %p, pos %p, size: %z "
[1336]                        "file: %O, size: %O",
[1337]                        in->buf->last_buf,
[1338]                        in->buf->in_file,
[1339]                        in->buf->start, in->buf->pos,
[1340]                        in->buf->last - in->buf->pos,
[1341]                        in->buf->file_pos,
[1342]                        in->buf->file_last - in->buf->file_pos);
[1343] 
[1344]         if (ngx_buf_special(in->buf)) {
[1345]             goto next;
[1346]         }
[1347] 
[1348]         if (in->buf->in_file) {
[1349]             file_pos = in->buf->file_pos;
[1350] 
[1351]         } else {
[1352]             pos = in->buf->pos;
[1353]         }
[1354] 
[1355]         next = 0;
[1356] 
[1357]         do {
[1358] 
[1359]             cl = ngx_http_grpc_get_buf(r, ctx);
[1360]             if (cl == NULL) {
[1361]                 return NGX_ERROR;
[1362]             }
[1363] 
[1364]             b = cl->buf;
[1365] 
[1366]             f = (ngx_http_grpc_frame_t *) b->last;
[1367]             b->last += sizeof(ngx_http_grpc_frame_t);
[1368] 
[1369]             *ll = cl;
[1370]             ll = &cl->next;
[1371] 
[1372]             cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[1373]             if (cl == NULL) {
[1374]                 return NGX_ERROR;
[1375]             }
[1376] 
[1377]             b = cl->buf;
[1378]             start = b->start;
[1379] 
[1380]             ngx_memcpy(b, in->buf, sizeof(ngx_buf_t));
[1381] 
[1382]             /*
[1383]              * restore b->start to preserve memory allocated in the buffer,
[1384]              * to reuse it later for headers and control frames
[1385]              */
[1386] 
[1387]             b->start = start;
[1388] 
[1389]             if (in->buf->in_file) {
[1390]                 b->file_pos = file_pos;
[1391]                 file_pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);
[1392] 
[1393]                 if (file_pos >= in->buf->file_last) {
[1394]                     file_pos = in->buf->file_last;
[1395]                     next = 1;
[1396]                 }
[1397] 
[1398]                 b->file_last = file_pos;
[1399]                 len = (ngx_uint_t) (file_pos - b->file_pos);
[1400] 
[1401]             } else {
[1402]                 b->pos = pos;
[1403]                 pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);
[1404] 
[1405]                 if (pos >= in->buf->last) {
[1406]                     pos = in->buf->last;
[1407]                     next = 1;
[1408]                 }
[1409] 
[1410]                 b->last = pos;
[1411]                 len = (ngx_uint_t) (pos - b->pos);
[1412]             }
[1413] 
[1414]             b->tag = (ngx_buf_tag_t) &ngx_http_grpc_body_output_filter;
[1415]             b->shadow = in->buf;
[1416]             b->last_shadow = next;
[1417] 
[1418]             b->last_buf = 0;
[1419]             b->last_in_chain = 0;
[1420] 
[1421]             *ll = cl;
[1422]             ll = &cl->next;
[1423] 
[1424]             f->length_0 = (u_char) ((len >> 16) & 0xff);
[1425]             f->length_1 = (u_char) ((len >> 8) & 0xff);
[1426]             f->length_2 = (u_char) (len & 0xff);
[1427]             f->type = NGX_HTTP_V2_DATA_FRAME;
[1428]             f->flags = 0;
[1429]             f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
[1430]             f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
[1431]             f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
[1432]             f->stream_id_3 = (u_char) (ctx->id & 0xff);
[1433] 
[1434]             limit -= len;
[1435]             ctx->send_window -= len;
[1436]             ctx->connection->send_window -= len;
[1437] 
[1438]         } while (!next && limit > 0);
[1439] 
[1440]         if (!next) {
[1441]             /*
[1442]              * if the buffer wasn't fully sent due to flow control limits,
[1443]              * preserve position for future use
[1444]              */
[1445] 
[1446]             if (in->buf->in_file) {
[1447]                 in->buf->file_pos = file_pos;
[1448] 
[1449]             } else {
[1450]                 in->buf->pos = pos;
[1451]             }
[1452] 
[1453]             break;
[1454]         }
[1455] 
[1456]     next:
[1457] 
[1458]         if (in->buf->last_buf) {
[1459]             last = 1;
[1460]         }
[1461] 
[1462]         in = in->next;
[1463]     }
[1464] 
[1465]     ctx->in = in;
[1466] 
[1467]     if (last) {
[1468] 
[1469]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1470]                        "grpc output last");
[1471] 
[1472]         ctx->output_closed = 1;
[1473] 
[1474]         if (f) {
[1475]             f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;
[1476] 
[1477]         } else {
[1478]             cl = ngx_http_grpc_get_buf(r, ctx);
[1479]             if (cl == NULL) {
[1480]                 return NGX_ERROR;
[1481]             }
[1482] 
[1483]             b = cl->buf;
[1484] 
[1485]             f = (ngx_http_grpc_frame_t *) b->last;
[1486]             b->last += sizeof(ngx_http_grpc_frame_t);
[1487] 
[1488]             f->length_0 = 0;
[1489]             f->length_1 = 0;
[1490]             f->length_2 = 0;
[1491]             f->type = NGX_HTTP_V2_DATA_FRAME;
[1492]             f->flags = NGX_HTTP_V2_END_STREAM_FLAG;
[1493]             f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
[1494]             f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
[1495]             f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
[1496]             f->stream_id_3 = (u_char) (ctx->id & 0xff);
[1497] 
[1498]             *ll = cl;
[1499]             ll = &cl->next;
[1500]         }
[1501] 
[1502]         cl->buf->last_buf = 1;
[1503]     }
[1504] 
[1505]     *ll = NULL;
[1506] 
[1507] #if (NGX_DEBUG)
[1508] 
[1509]     for (cl = out; cl; cl = cl->next) {
[1510]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1511]                        "grpc output out l:%d f:%d %p, pos %p, size: %z "
[1512]                        "file: %O, size: %O",
[1513]                        cl->buf->last_buf,
[1514]                        cl->buf->in_file,
[1515]                        cl->buf->start, cl->buf->pos,
[1516]                        cl->buf->last - cl->buf->pos,
[1517]                        cl->buf->file_pos,
[1518]                        cl->buf->file_last - cl->buf->file_pos);
[1519]     }
[1520] 
[1521]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1522]                    "grpc output limit: %uz w:%z:%uz",
[1523]                    limit, ctx->send_window, ctx->connection->send_window);
[1524] 
[1525] #endif
[1526] 
[1527]     rc = ngx_chain_writer(&r->upstream->writer, out);
[1528] 
[1529]     ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
[1530]                             (ngx_buf_tag_t) &ngx_http_grpc_body_output_filter);
[1531] 
[1532]     for (cl = ctx->free; cl; cl = cl->next) {
[1533] 
[1534]         /* mark original buffers as sent */
[1535] 
[1536]         if (cl->buf->shadow) {
[1537]             if (cl->buf->last_shadow) {
[1538]                 b = cl->buf->shadow;
[1539]                 b->pos = b->last;
[1540]             }
[1541] 
[1542]             cl->buf->shadow = NULL;
[1543]         }
[1544]     }
[1545] 
[1546]     if (rc == NGX_OK && ctx->in) {
[1547]         rc = NGX_AGAIN;
[1548]     }
[1549] 
[1550]     if (rc == NGX_AGAIN) {
[1551]         ctx->output_blocked = 1;
[1552] 
[1553]     } else {
[1554]         ctx->output_blocked = 0;
[1555]     }
[1556] 
[1557]     if (ctx->done) {
[1558] 
[1559]         /*
[1560]          * We have already got the response and were sending some additional
[1561]          * control frames.  Even if there is still something unsent, stop
[1562]          * here anyway.
[1563]          */
[1564] 
[1565]         u = r->upstream;
[1566]         u->length = 0;
[1567] 
[1568]         if (ctx->in == NULL
[1569]             && ctx->out == NULL
[1570]             && ctx->output_closed
[1571]             && !ctx->output_blocked
[1572]             && !ctx->goaway
[1573]             && ctx->state == ngx_http_grpc_st_start)
[1574]         {
[1575]             u->keepalive = 1;
[1576]         }
[1577] 
[1578]         ngx_post_event(u->peer.connection->read, &ngx_posted_events);
[1579]     }
[1580] 
[1581]     return rc;
[1582] }
[1583] 
[1584] 
[1585] static ngx_int_t
[1586] ngx_http_grpc_process_header(ngx_http_request_t *r)
[1587] {
[1588]     ngx_str_t                      *status_line;
[1589]     ngx_int_t                       rc, status;
[1590]     ngx_buf_t                      *b;
[1591]     ngx_table_elt_t                *h;
[1592]     ngx_http_upstream_t            *u;
[1593]     ngx_http_grpc_ctx_t            *ctx;
[1594]     ngx_http_upstream_header_t     *hh;
[1595]     ngx_http_upstream_main_conf_t  *umcf;
[1596] 
[1597]     u = r->upstream;
[1598]     b = &u->buffer;
[1599] 
[1600]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1601]                    "grpc response: %*xs%s, len: %uz",
[1602]                    (size_t) ngx_min(b->last - b->pos, 256),
[1603]                    b->pos, b->last - b->pos > 256 ? "..." : "",
[1604]                    b->last - b->pos);
[1605] 
[1606]     ctx = ngx_http_grpc_get_ctx(r);
[1607] 
[1608]     if (ctx == NULL) {
[1609]         return NGX_ERROR;
[1610]     }
[1611] 
[1612]     umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[1613] 
[1614]     for ( ;; ) {
[1615] 
[1616]         if (ctx->state < ngx_http_grpc_st_payload) {
[1617] 
[1618]             rc = ngx_http_grpc_parse_frame(r, ctx, b);
[1619] 
[1620]             if (rc == NGX_AGAIN) {
[1621] 
[1622]                 /*
[1623]                  * there can be a lot of window update frames,
[1624]                  * so we reset buffer if it is empty and we haven't
[1625]                  * started parsing headers yet
[1626]                  */
[1627] 
[1628]                 if (!ctx->parsing_headers) {
[1629]                     b->pos = b->start;
[1630]                     b->last = b->pos;
[1631]                 }
[1632] 
[1633]                 return NGX_AGAIN;
[1634]             }
[1635] 
[1636]             if (rc == NGX_ERROR) {
[1637]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1638]             }
[1639] 
[1640]             /*
[1641]              * RFC 7540 says that implementations MUST discard frames
[1642]              * that have unknown or unsupported types.  However, extension
[1643]              * frames that appear in the middle of a header block are
[1644]              * not permitted.  Also, for obvious reasons CONTINUATION frames
[1645]              * cannot appear before headers, and DATA frames are not expected
[1646]              * to appear before all headers are parsed.
[1647]              */
[1648] 
[1649]             if (ctx->type == NGX_HTTP_V2_DATA_FRAME
[1650]                 || (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME
[1651]                     && !ctx->parsing_headers)
[1652]                 || (ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME
[1653]                     && ctx->parsing_headers))
[1654]             {
[1655]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1656]                               "upstream sent unexpected http2 frame: %d",
[1657]                               ctx->type);
[1658]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1659]             }
[1660] 
[1661]             if (ctx->stream_id && ctx->stream_id != ctx->id) {
[1662]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1663]                               "upstream sent frame for unknown stream %ui",
[1664]                               ctx->stream_id);
[1665]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1666]             }
[1667]         }
[1668] 
[1669]         /* frame payload */
[1670] 
[1671]         if (ctx->type == NGX_HTTP_V2_RST_STREAM_FRAME) {
[1672] 
[1673]             rc = ngx_http_grpc_parse_rst_stream(r, ctx, b);
[1674] 
[1675]             if (rc == NGX_AGAIN) {
[1676]                 return NGX_AGAIN;
[1677]             }
[1678] 
[1679]             if (rc == NGX_ERROR) {
[1680]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1681]             }
[1682] 
[1683]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1684]                           "upstream rejected request with error %ui",
[1685]                           ctx->error);
[1686] 
[1687]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1688]         }
[1689] 
[1690]         if (ctx->type == NGX_HTTP_V2_GOAWAY_FRAME) {
[1691] 
[1692]             rc = ngx_http_grpc_parse_goaway(r, ctx, b);
[1693] 
[1694]             if (rc == NGX_AGAIN) {
[1695]                 return NGX_AGAIN;
[1696]             }
[1697] 
[1698]             if (rc == NGX_ERROR) {
[1699]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1700]             }
[1701] 
[1702]             /*
[1703]              * If stream_id is lower than one we use, our
[1704]              * request won't be processed and needs to be retried.
[1705]              * If stream_id is greater or equal to the one we use,
[1706]              * we can continue normally (except we can't use this
[1707]              * connection for additional requests).  If there is
[1708]              * a real error, the connection will be closed.
[1709]              */
[1710] 
[1711]             if (ctx->stream_id < ctx->id) {
[1712] 
[1713]                 /* TODO: we can retry non-idempotent requests */
[1714] 
[1715]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1716]                               "upstream sent goaway with error %ui",
[1717]                               ctx->error);
[1718] 
[1719]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1720]             }
[1721] 
[1722]             ctx->goaway = 1;
[1723] 
[1724]             continue;
[1725]         }
[1726] 
[1727]         if (ctx->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {
[1728] 
[1729]             rc = ngx_http_grpc_parse_window_update(r, ctx, b);
[1730] 
[1731]             if (rc == NGX_AGAIN) {
[1732]                 return NGX_AGAIN;
[1733]             }
[1734] 
[1735]             if (rc == NGX_ERROR) {
[1736]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1737]             }
[1738] 
[1739]             if (ctx->in) {
[1740]                 ngx_post_event(u->peer.connection->write, &ngx_posted_events);
[1741]             }
[1742] 
[1743]             continue;
[1744]         }
[1745] 
[1746]         if (ctx->type == NGX_HTTP_V2_SETTINGS_FRAME) {
[1747] 
[1748]             rc = ngx_http_grpc_parse_settings(r, ctx, b);
[1749] 
[1750]             if (rc == NGX_AGAIN) {
[1751]                 return NGX_AGAIN;
[1752]             }
[1753] 
[1754]             if (rc == NGX_ERROR) {
[1755]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1756]             }
[1757] 
[1758]             if (ctx->in) {
[1759]                 ngx_post_event(u->peer.connection->write, &ngx_posted_events);
[1760]             }
[1761] 
[1762]             continue;
[1763]         }
[1764] 
[1765]         if (ctx->type == NGX_HTTP_V2_PING_FRAME) {
[1766] 
[1767]             rc = ngx_http_grpc_parse_ping(r, ctx, b);
[1768] 
[1769]             if (rc == NGX_AGAIN) {
[1770]                 return NGX_AGAIN;
[1771]             }
[1772] 
[1773]             if (rc == NGX_ERROR) {
[1774]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1775]             }
[1776] 
[1777]             ngx_post_event(u->peer.connection->write, &ngx_posted_events);
[1778]             continue;
[1779]         }
[1780] 
[1781]         if (ctx->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
[1782]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1783]                           "upstream sent unexpected push promise frame");
[1784]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1785]         }
[1786] 
[1787]         if (ctx->type != NGX_HTTP_V2_HEADERS_FRAME
[1788]             && ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME)
[1789]         {
[1790]             /* priority, unknown frames */
[1791] 
[1792]             if (b->last - b->pos < (ssize_t) ctx->rest) {
[1793]                 ctx->rest -= b->last - b->pos;
[1794]                 b->pos = b->last;
[1795]                 return NGX_AGAIN;
[1796]             }
[1797] 
[1798]             b->pos += ctx->rest;
[1799]             ctx->rest = 0;
[1800]             ctx->state = ngx_http_grpc_st_start;
[1801] 
[1802]             continue;
[1803]         }
[1804] 
[1805]         /* headers */
[1806] 
[1807]         for ( ;; ) {
[1808] 
[1809]             rc = ngx_http_grpc_parse_header(r, ctx, b);
[1810] 
[1811]             if (rc == NGX_AGAIN) {
[1812]                 break;
[1813]             }
[1814] 
[1815]             if (rc == NGX_OK) {
[1816] 
[1817]                 /* a header line has been parsed successfully */
[1818] 
[1819]                 ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1820]                                "grpc header: \"%V: %V\"",
[1821]                                &ctx->name, &ctx->value);
[1822] 
[1823]                 if (ctx->name.len && ctx->name.data[0] == ':') {
[1824] 
[1825]                     if (ctx->name.len != sizeof(":status") - 1
[1826]                         || ngx_strncmp(ctx->name.data, ":status",
[1827]                                        sizeof(":status") - 1)
[1828]                            != 0)
[1829]                     {
[1830]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1831]                                       "upstream sent invalid header \"%V: %V\"",
[1832]                                       &ctx->name, &ctx->value);
[1833]                         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1834]                     }
[1835] 
[1836]                     if (ctx->status) {
[1837]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1838]                                       "upstream sent duplicate :status header");
[1839]                         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1840]                     }
[1841] 
[1842]                     status_line = &ctx->value;
[1843] 
[1844]                     if (status_line->len != 3) {
[1845]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1846]                                       "upstream sent invalid :status \"%V\"",
[1847]                                       status_line);
[1848]                         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1849]                     }
[1850] 
[1851]                     status = ngx_atoi(status_line->data, 3);
[1852] 
[1853]                     if (status == NGX_ERROR) {
[1854]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1855]                                       "upstream sent invalid :status \"%V\"",
[1856]                                       status_line);
[1857]                         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1858]                     }
[1859] 
[1860]                     if (status < NGX_HTTP_OK) {
[1861]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1862]                                       "upstream sent unexpected :status \"%V\"",
[1863]                                       status_line);
[1864]                         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1865]                     }
[1866] 
[1867]                     u->headers_in.status_n = status;
[1868] 
[1869]                     if (u->state && u->state->status == 0) {
[1870]                         u->state->status = status;
[1871]                     }
[1872] 
[1873]                     ctx->status = 1;
[1874] 
[1875]                     continue;
[1876] 
[1877]                 } else if (!ctx->status) {
[1878]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1879]                                   "upstream sent no :status header");
[1880]                     return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1881]                 }
[1882] 
[1883]                 h = ngx_list_push(&u->headers_in.headers);
[1884]                 if (h == NULL) {
[1885]                     return NGX_ERROR;
[1886]                 }
[1887] 
[1888]                 h->key = ctx->name;
[1889]                 h->value = ctx->value;
[1890]                 h->lowcase_key = h->key.data;
[1891]                 h->hash = ngx_hash_key(h->key.data, h->key.len);
[1892] 
[1893]                 hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
[1894]                                    h->lowcase_key, h->key.len);
[1895] 
[1896]                 if (hh) {
[1897]                     rc = hh->handler(r, h, hh->offset);
[1898] 
[1899]                     if (rc != NGX_OK) {
[1900]                         return rc;
[1901]                     }
[1902]                 }
[1903] 
[1904]                 continue;
[1905]             }
[1906] 
[1907]             if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[1908] 
[1909]                 /* a whole header has been parsed successfully */
[1910] 
[1911]                 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1912]                                "grpc header done");
[1913] 
[1914]                 if (ctx->end_stream) {
[1915]                     u->headers_in.content_length_n = 0;
[1916] 
[1917]                     if (ctx->in == NULL
[1918]                         && ctx->out == NULL
[1919]                         && ctx->output_closed
[1920]                         && !ctx->output_blocked
[1921]                         && !ctx->goaway
[1922]                         && b->last == b->pos)
[1923]                     {
[1924]                         u->keepalive = 1;
[1925]                     }
[1926]                 }
[1927] 
[1928]                 return NGX_OK;
[1929]             }
[1930] 
[1931]             /* there was error while a header line parsing */
[1932] 
[1933]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1934]                           "upstream sent invalid header");
[1935] 
[1936]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1937]         }
[1938] 
[1939]         /* rc == NGX_AGAIN */
[1940] 
[1941]         if (ctx->rest == 0) {
[1942]             ctx->state = ngx_http_grpc_st_start;
[1943]             continue;
[1944]         }
[1945] 
[1946]         return NGX_AGAIN;
[1947]     }
[1948] }
[1949] 
[1950] 
[1951] static ngx_int_t
[1952] ngx_http_grpc_filter_init(void *data)
[1953] {
[1954]     ngx_http_grpc_ctx_t  *ctx = data;
[1955] 
[1956]     ngx_http_request_t   *r;
[1957]     ngx_http_upstream_t  *u;
[1958] 
[1959]     r = ctx->request;
[1960]     u = r->upstream;
[1961] 
[1962]     if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
[1963]         || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
[1964]         || r->method == NGX_HTTP_HEAD)
[1965]     {
[1966]         ctx->length = 0;
[1967] 
[1968]     } else {
[1969]         ctx->length = u->headers_in.content_length_n;
[1970]     }
[1971] 
[1972]     if (ctx->end_stream) {
[1973] 
[1974]         if (ctx->length > 0) {
[1975]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1976]                           "upstream prematurely closed stream");
[1977]             return NGX_ERROR;
[1978]         }
[1979] 
[1980]         u->length = 0;
[1981]         ctx->done = 1;
[1982] 
[1983]     } else {
[1984]         u->length = 1;
[1985]     }
[1986] 
[1987]     return NGX_OK;
[1988] }
[1989] 
[1990] 
[1991] static ngx_int_t
[1992] ngx_http_grpc_filter(void *data, ssize_t bytes)
[1993] {
[1994]     ngx_http_grpc_ctx_t  *ctx = data;
[1995] 
[1996]     ngx_int_t             rc;
[1997]     ngx_buf_t            *b, *buf;
[1998]     ngx_chain_t          *cl, **ll;
[1999]     ngx_table_elt_t      *h;
[2000]     ngx_http_request_t   *r;
[2001]     ngx_http_upstream_t  *u;
[2002] 
[2003]     r = ctx->request;
[2004]     u = r->upstream;
[2005]     b = &u->buffer;
[2006] 
[2007]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2008]                    "grpc filter bytes:%z", bytes);
[2009] 
[2010]     b->pos = b->last;
[2011]     b->last += bytes;
[2012] 
[2013]     for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
[2014]         ll = &cl->next;
[2015]     }
[2016] 
[2017]     for ( ;; ) {
[2018] 
[2019]         if (ctx->state < ngx_http_grpc_st_payload) {
[2020] 
[2021]             rc = ngx_http_grpc_parse_frame(r, ctx, b);
[2022] 
[2023]             if (rc == NGX_AGAIN) {
[2024] 
[2025]                 if (ctx->done) {
[2026] 
[2027]                     if (ctx->length > 0) {
[2028]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2029]                                       "upstream prematurely closed stream");
[2030]                         return NGX_ERROR;
[2031]                     }
[2032] 
[2033]                     /*
[2034]                      * We have finished parsing the response and the
[2035]                      * remaining control frames.  If there are unsent
[2036]                      * control frames, post a write event to send them.
[2037]                      */
[2038] 
[2039]                     if (ctx->out) {
[2040]                         ngx_post_event(u->peer.connection->write,
[2041]                                        &ngx_posted_events);
[2042]                         return NGX_AGAIN;
[2043]                     }
[2044] 
[2045]                     u->length = 0;
[2046] 
[2047]                     if (ctx->in == NULL
[2048]                         && ctx->output_closed
[2049]                         && !ctx->output_blocked
[2050]                         && !ctx->goaway
[2051]                         && ctx->state == ngx_http_grpc_st_start)
[2052]                     {
[2053]                         u->keepalive = 1;
[2054]                     }
[2055] 
[2056]                     break;
[2057]                 }
[2058] 
[2059]                 return NGX_AGAIN;
[2060]             }
[2061] 
[2062]             if (rc == NGX_ERROR) {
[2063]                 return NGX_ERROR;
[2064]             }
[2065] 
[2066]             if ((ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME
[2067]                  && !ctx->parsing_headers)
[2068]                 || (ctx->type != NGX_HTTP_V2_CONTINUATION_FRAME
[2069]                     && ctx->parsing_headers))
[2070]             {
[2071]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2072]                               "upstream sent unexpected http2 frame: %d",
[2073]                               ctx->type);
[2074]                 return NGX_ERROR;
[2075]             }
[2076] 
[2077]             if (ctx->type == NGX_HTTP_V2_DATA_FRAME) {
[2078] 
[2079]                 if (ctx->stream_id != ctx->id) {
[2080]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2081]                                   "upstream sent data frame "
[2082]                                   "for unknown stream %ui",
[2083]                                   ctx->stream_id);
[2084]                     return NGX_ERROR;
[2085]                 }
[2086] 
[2087]                 if (ctx->rest > ctx->recv_window) {
[2088]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2089]                                   "upstream violated stream flow control, "
[2090]                                   "received %uz data frame with window %uz",
[2091]                                   ctx->rest, ctx->recv_window);
[2092]                     return NGX_ERROR;
[2093]                 }
[2094] 
[2095]                 if (ctx->rest > ctx->connection->recv_window) {
[2096]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2097]                                   "upstream violated connection flow control, "
[2098]                                   "received %uz data frame with window %uz",
[2099]                                   ctx->rest, ctx->connection->recv_window);
[2100]                     return NGX_ERROR;
[2101]                 }
[2102] 
[2103]                 ctx->recv_window -= ctx->rest;
[2104]                 ctx->connection->recv_window -= ctx->rest;
[2105] 
[2106]                 if (ctx->connection->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4
[2107]                     || ctx->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
[2108]                 {
[2109]                     if (ngx_http_grpc_send_window_update(r, ctx) != NGX_OK) {
[2110]                         return NGX_ERROR;
[2111]                     }
[2112] 
[2113]                     ngx_post_event(u->peer.connection->write,
[2114]                                    &ngx_posted_events);
[2115]                 }
[2116]             }
[2117] 
[2118]             if (ctx->stream_id && ctx->stream_id != ctx->id) {
[2119]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2120]                               "upstream sent frame for unknown stream %ui",
[2121]                               ctx->stream_id);
[2122]                 return NGX_ERROR;
[2123]             }
[2124] 
[2125]             if (ctx->stream_id && ctx->done
[2126]                 && ctx->type != NGX_HTTP_V2_RST_STREAM_FRAME
[2127]                 && ctx->type != NGX_HTTP_V2_WINDOW_UPDATE_FRAME)
[2128]             {
[2129]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2130]                               "upstream sent frame for closed stream %ui",
[2131]                               ctx->stream_id);
[2132]                 return NGX_ERROR;
[2133]             }
[2134] 
[2135]             ctx->padding = 0;
[2136]         }
[2137] 
[2138]         if (ctx->state == ngx_http_grpc_st_padding) {
[2139] 
[2140]             if (b->last - b->pos < (ssize_t) ctx->rest) {
[2141]                 ctx->rest -= b->last - b->pos;
[2142]                 b->pos = b->last;
[2143]                 return NGX_AGAIN;
[2144]             }
[2145] 
[2146]             b->pos += ctx->rest;
[2147]             ctx->rest = 0;
[2148]             ctx->state = ngx_http_grpc_st_start;
[2149] 
[2150]             if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
[2151]                 ctx->done = 1;
[2152]             }
[2153] 
[2154]             continue;
[2155]         }
[2156] 
[2157]         /* frame payload */
[2158] 
[2159]         if (ctx->type == NGX_HTTP_V2_RST_STREAM_FRAME) {
[2160] 
[2161]             rc = ngx_http_grpc_parse_rst_stream(r, ctx, b);
[2162] 
[2163]             if (rc == NGX_AGAIN) {
[2164]                 return NGX_AGAIN;
[2165]             }
[2166] 
[2167]             if (rc == NGX_ERROR) {
[2168]                 return NGX_ERROR;
[2169]             }
[2170] 
[2171]             if (ctx->error || !ctx->done) {
[2172]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2173]                               "upstream rejected request with error %ui",
[2174]                               ctx->error);
[2175]                 return NGX_ERROR;
[2176]             }
[2177] 
[2178]             if (ctx->rst) {
[2179]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2180]                               "upstream sent frame for closed stream %ui",
[2181]                               ctx->stream_id);
[2182]                 return NGX_ERROR;
[2183]             }
[2184] 
[2185]             ctx->rst = 1;
[2186] 
[2187]             continue;
[2188]         }
[2189] 
[2190]         if (ctx->type == NGX_HTTP_V2_GOAWAY_FRAME) {
[2191] 
[2192]             rc = ngx_http_grpc_parse_goaway(r, ctx, b);
[2193] 
[2194]             if (rc == NGX_AGAIN) {
[2195]                 return NGX_AGAIN;
[2196]             }
[2197] 
[2198]             if (rc == NGX_ERROR) {
[2199]                 return NGX_ERROR;
[2200]             }
[2201] 
[2202]             /*
[2203]              * If stream_id is lower than one we use, our
[2204]              * request won't be processed and needs to be retried.
[2205]              * If stream_id is greater or equal to the one we use,
[2206]              * we can continue normally (except we can't use this
[2207]              * connection for additional requests).  If there is
[2208]              * a real error, the connection will be closed.
[2209]              */
[2210] 
[2211]             if (ctx->stream_id < ctx->id) {
[2212] 
[2213]                 /* TODO: we can retry non-idempotent requests */
[2214] 
[2215]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2216]                               "upstream sent goaway with error %ui",
[2217]                               ctx->error);
[2218] 
[2219]                 return NGX_ERROR;
[2220]             }
[2221] 
[2222]             ctx->goaway = 1;
[2223] 
[2224]             continue;
[2225]         }
[2226] 
[2227]         if (ctx->type == NGX_HTTP_V2_WINDOW_UPDATE_FRAME) {
[2228] 
[2229]             rc = ngx_http_grpc_parse_window_update(r, ctx, b);
[2230] 
[2231]             if (rc == NGX_AGAIN) {
[2232]                 return NGX_AGAIN;
[2233]             }
[2234] 
[2235]             if (rc == NGX_ERROR) {
[2236]                 return NGX_ERROR;
[2237]             }
[2238] 
[2239]             if (ctx->in) {
[2240]                 ngx_post_event(u->peer.connection->write, &ngx_posted_events);
[2241]             }
[2242] 
[2243]             continue;
[2244]         }
[2245] 
[2246]         if (ctx->type == NGX_HTTP_V2_SETTINGS_FRAME) {
[2247] 
[2248]             rc = ngx_http_grpc_parse_settings(r, ctx, b);
[2249] 
[2250]             if (rc == NGX_AGAIN) {
[2251]                 return NGX_AGAIN;
[2252]             }
[2253] 
[2254]             if (rc == NGX_ERROR) {
[2255]                 return NGX_ERROR;
[2256]             }
[2257] 
[2258]             if (ctx->in) {
[2259]                 ngx_post_event(u->peer.connection->write, &ngx_posted_events);
[2260]             }
[2261] 
[2262]             continue;
[2263]         }
[2264] 
[2265]         if (ctx->type == NGX_HTTP_V2_PING_FRAME) {
[2266] 
[2267]             rc = ngx_http_grpc_parse_ping(r, ctx, b);
[2268] 
[2269]             if (rc == NGX_AGAIN) {
[2270]                 return NGX_AGAIN;
[2271]             }
[2272] 
[2273]             if (rc == NGX_ERROR) {
[2274]                 return NGX_ERROR;
[2275]             }
[2276] 
[2277]             ngx_post_event(u->peer.connection->write, &ngx_posted_events);
[2278]             continue;
[2279]         }
[2280] 
[2281]         if (ctx->type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
[2282]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2283]                           "upstream sent unexpected push promise frame");
[2284]             return NGX_ERROR;
[2285]         }
[2286] 
[2287]         if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME
[2288]             || ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME)
[2289]         {
[2290]             for ( ;; ) {
[2291] 
[2292]                 rc = ngx_http_grpc_parse_header(r, ctx, b);
[2293] 
[2294]                 if (rc == NGX_AGAIN) {
[2295]                     break;
[2296]                 }
[2297] 
[2298]                 if (rc == NGX_OK) {
[2299] 
[2300]                     /* a header line has been parsed successfully */
[2301] 
[2302]                     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2303]                                    "grpc trailer: \"%V: %V\"",
[2304]                                    &ctx->name, &ctx->value);
[2305] 
[2306]                     if (ctx->name.len && ctx->name.data[0] == ':') {
[2307]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2308]                                       "upstream sent invalid "
[2309]                                       "trailer \"%V: %V\"",
[2310]                                       &ctx->name, &ctx->value);
[2311]                         return NGX_ERROR;
[2312]                     }
[2313] 
[2314]                     h = ngx_list_push(&u->headers_in.trailers);
[2315]                     if (h == NULL) {
[2316]                         return NGX_ERROR;
[2317]                     }
[2318] 
[2319]                     h->key = ctx->name;
[2320]                     h->value = ctx->value;
[2321]                     h->lowcase_key = h->key.data;
[2322]                     h->hash = ngx_hash_key(h->key.data, h->key.len);
[2323] 
[2324]                     continue;
[2325]                 }
[2326] 
[2327]                 if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[2328] 
[2329]                     /* a whole header has been parsed successfully */
[2330] 
[2331]                     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2332]                                    "grpc trailer done");
[2333] 
[2334]                     if (ctx->end_stream) {
[2335]                         ctx->done = 1;
[2336]                         break;
[2337]                     }
[2338] 
[2339]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2340]                                   "upstream sent trailer without "
[2341]                                   "end stream flag");
[2342]                     return NGX_ERROR;
[2343]                 }
[2344] 
[2345]                 /* there was error while a header line parsing */
[2346] 
[2347]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2348]                               "upstream sent invalid trailer");
[2349] 
[2350]                 return NGX_ERROR;
[2351]             }
[2352] 
[2353]             if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[2354]                 continue;
[2355]             }
[2356] 
[2357]             /* rc == NGX_AGAIN */
[2358] 
[2359]             if (ctx->rest == 0) {
[2360]                 ctx->state = ngx_http_grpc_st_start;
[2361]                 continue;
[2362]             }
[2363] 
[2364]             return NGX_AGAIN;
[2365]         }
[2366] 
[2367]         if (ctx->type != NGX_HTTP_V2_DATA_FRAME) {
[2368] 
[2369]             /* priority, unknown frames */
[2370] 
[2371]             if (b->last - b->pos < (ssize_t) ctx->rest) {
[2372]                 ctx->rest -= b->last - b->pos;
[2373]                 b->pos = b->last;
[2374]                 return NGX_AGAIN;
[2375]             }
[2376] 
[2377]             b->pos += ctx->rest;
[2378]             ctx->rest = 0;
[2379]             ctx->state = ngx_http_grpc_st_start;
[2380] 
[2381]             continue;
[2382]         }
[2383] 
[2384]         /*
[2385]          * data frame:
[2386]          *
[2387]          * +---------------+
[2388]          * |Pad Length? (8)|
[2389]          * +---------------+-----------------------------------------------+
[2390]          * |                            Data (*)                         ...
[2391]          * +---------------------------------------------------------------+
[2392]          * |                           Padding (*)                       ...
[2393]          * +---------------------------------------------------------------+
[2394]          */
[2395] 
[2396]         if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {
[2397] 
[2398]             if (ctx->rest == 0) {
[2399]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2400]                               "upstream sent too short http2 frame");
[2401]                 return NGX_ERROR;
[2402]             }
[2403] 
[2404]             if (b->pos == b->last) {
[2405]                 return NGX_AGAIN;
[2406]             }
[2407] 
[2408]             ctx->flags &= ~NGX_HTTP_V2_PADDED_FLAG;
[2409]             ctx->padding = *b->pos++;
[2410]             ctx->rest -= 1;
[2411] 
[2412]             if (ctx->padding > ctx->rest) {
[2413]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2414]                               "upstream sent http2 frame with too long "
[2415]                               "padding: %d in frame %uz",
[2416]                               ctx->padding, ctx->rest);
[2417]                 return NGX_ERROR;
[2418]             }
[2419] 
[2420]             continue;
[2421]         }
[2422] 
[2423]         if (ctx->rest == ctx->padding) {
[2424]             goto done;
[2425]         }
[2426] 
[2427]         if (b->pos == b->last) {
[2428]             return NGX_AGAIN;
[2429]         }
[2430] 
[2431]         cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
[2432]         if (cl == NULL) {
[2433]             return NGX_ERROR;
[2434]         }
[2435] 
[2436]         *ll = cl;
[2437]         ll = &cl->next;
[2438] 
[2439]         buf = cl->buf;
[2440] 
[2441]         buf->flush = 1;
[2442]         buf->memory = 1;
[2443] 
[2444]         buf->pos = b->pos;
[2445]         buf->tag = u->output.tag;
[2446] 
[2447]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2448]                        "grpc output buf %p", buf->pos);
[2449] 
[2450]         if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
[2451] 
[2452]             ctx->rest -= b->last - b->pos;
[2453]             b->pos = b->last;
[2454]             buf->last = b->pos;
[2455] 
[2456]             if (ctx->length != -1) {
[2457] 
[2458]                 if (buf->last - buf->pos > ctx->length) {
[2459]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2460]                                   "upstream sent response body larger "
[2461]                                   "than indicated content length");
[2462]                     return NGX_ERROR;
[2463]                 }
[2464] 
[2465]                 ctx->length -= buf->last - buf->pos;
[2466]             }
[2467] 
[2468]             return NGX_AGAIN;
[2469]         }
[2470] 
[2471]         b->pos += ctx->rest - ctx->padding;
[2472]         buf->last = b->pos;
[2473]         ctx->rest = ctx->padding;
[2474] 
[2475]         if (ctx->length != -1) {
[2476] 
[2477]             if (buf->last - buf->pos > ctx->length) {
[2478]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2479]                               "upstream sent response body larger "
[2480]                               "than indicated content length");
[2481]                 return NGX_ERROR;
[2482]             }
[2483] 
[2484]             ctx->length -= buf->last - buf->pos;
[2485]         }
[2486] 
[2487]     done:
[2488] 
[2489]         if (ctx->padding) {
[2490]             ctx->state = ngx_http_grpc_st_padding;
[2491]             continue;
[2492]         }
[2493] 
[2494]         ctx->state = ngx_http_grpc_st_start;
[2495] 
[2496]         if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
[2497]             ctx->done = 1;
[2498]         }
[2499]     }
[2500] 
[2501]     return NGX_OK;
[2502] }
[2503] 
[2504] 
[2505] static ngx_int_t
[2506] ngx_http_grpc_parse_frame(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[2507]     ngx_buf_t *b)
[2508] {
[2509]     u_char                 ch, *p;
[2510]     ngx_http_grpc_state_e  state;
[2511] 
[2512]     state = ctx->state;
[2513] 
[2514]     for (p = b->pos; p < b->last; p++) {
[2515]         ch = *p;
[2516] 
[2517] #if 0
[2518]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2519]                        "grpc frame byte: %02Xd, s:%d", ch, state);
[2520] #endif
[2521] 
[2522]         switch (state) {
[2523] 
[2524]         case ngx_http_grpc_st_start:
[2525]             ctx->rest = ch << 16;
[2526]             state = ngx_http_grpc_st_length_2;
[2527]             break;
[2528] 
[2529]         case ngx_http_grpc_st_length_2:
[2530]             ctx->rest |= ch << 8;
[2531]             state = ngx_http_grpc_st_length_3;
[2532]             break;
[2533] 
[2534]         case ngx_http_grpc_st_length_3:
[2535]             ctx->rest |= ch;
[2536] 
[2537]             if (ctx->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
[2538]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2539]                               "upstream sent too large http2 frame: %uz",
[2540]                               ctx->rest);
[2541]                 return NGX_ERROR;
[2542]             }
[2543] 
[2544]             state = ngx_http_grpc_st_type;
[2545]             break;
[2546] 
[2547]         case ngx_http_grpc_st_type:
[2548]             ctx->type = ch;
[2549]             state = ngx_http_grpc_st_flags;
[2550]             break;
[2551] 
[2552]         case ngx_http_grpc_st_flags:
[2553]             ctx->flags = ch;
[2554]             state = ngx_http_grpc_st_stream_id;
[2555]             break;
[2556] 
[2557]         case ngx_http_grpc_st_stream_id:
[2558]             ctx->stream_id = (ch & 0x7f) << 24;
[2559]             state = ngx_http_grpc_st_stream_id_2;
[2560]             break;
[2561] 
[2562]         case ngx_http_grpc_st_stream_id_2:
[2563]             ctx->stream_id |= ch << 16;
[2564]             state = ngx_http_grpc_st_stream_id_3;
[2565]             break;
[2566] 
[2567]         case ngx_http_grpc_st_stream_id_3:
[2568]             ctx->stream_id |= ch << 8;
[2569]             state = ngx_http_grpc_st_stream_id_4;
[2570]             break;
[2571] 
[2572]         case ngx_http_grpc_st_stream_id_4:
[2573]             ctx->stream_id |= ch;
[2574] 
[2575]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2576]                            "grpc frame: %d, len: %uz, f:%d, i:%ui",
[2577]                            ctx->type, ctx->rest, ctx->flags, ctx->stream_id);
[2578] 
[2579]             b->pos = p + 1;
[2580] 
[2581]             ctx->state = ngx_http_grpc_st_payload;
[2582]             ctx->frame_state = 0;
[2583] 
[2584]             return NGX_OK;
[2585] 
[2586]         /* suppress warning */
[2587]         case ngx_http_grpc_st_payload:
[2588]         case ngx_http_grpc_st_padding:
[2589]             break;
[2590]         }
[2591]     }
[2592] 
[2593]     b->pos = p;
[2594]     ctx->state = state;
[2595] 
[2596]     return NGX_AGAIN;
[2597] }
[2598] 
[2599] 
[2600] static ngx_int_t
[2601] ngx_http_grpc_parse_header(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[2602]     ngx_buf_t *b)
[2603] {
[2604]     u_char     ch, *p, *last;
[2605]     size_t     min;
[2606]     ngx_int_t  rc;
[2607]     enum {
[2608]         sw_start = 0,
[2609]         sw_padding_length,
[2610]         sw_dependency,
[2611]         sw_dependency_2,
[2612]         sw_dependency_3,
[2613]         sw_dependency_4,
[2614]         sw_weight,
[2615]         sw_fragment,
[2616]         sw_padding
[2617]     } state;
[2618] 
[2619]     state = ctx->frame_state;
[2620] 
[2621]     if (state == sw_start) {
[2622] 
[2623]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2624]                        "grpc parse header: start");
[2625] 
[2626]         if (ctx->type == NGX_HTTP_V2_HEADERS_FRAME) {
[2627]             ctx->parsing_headers = 1;
[2628]             ctx->fragment_state = 0;
[2629] 
[2630]             min = (ctx->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
[2631]                   + (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);
[2632] 
[2633]             if (ctx->rest < min) {
[2634]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2635]                               "upstream sent headers frame "
[2636]                               "with invalid length: %uz",
[2637]                               ctx->rest);
[2638]                 return NGX_ERROR;
[2639]             }
[2640] 
[2641]             if (ctx->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
[2642]                 ctx->end_stream = 1;
[2643]             }
[2644] 
[2645]             if (ctx->flags & NGX_HTTP_V2_PADDED_FLAG) {
[2646]                 state = sw_padding_length;
[2647] 
[2648]             } else if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
[2649]                 state = sw_dependency;
[2650] 
[2651]             } else {
[2652]                 state = sw_fragment;
[2653]             }
[2654] 
[2655]         } else if (ctx->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
[2656]             state = sw_fragment;
[2657]         }
[2658] 
[2659]         ctx->padding = 0;
[2660]         ctx->frame_state = state;
[2661]     }
[2662] 
[2663]     if (state < sw_fragment) {
[2664] 
[2665]         if (b->last - b->pos < (ssize_t) ctx->rest) {
[2666]             last = b->last;
[2667] 
[2668]         } else {
[2669]             last = b->pos + ctx->rest;
[2670]         }
[2671] 
[2672]         for (p = b->pos; p < last; p++) {
[2673]             ch = *p;
[2674] 
[2675] #if 0
[2676]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2677]                            "grpc header byte: %02Xd s:%d", ch, state);
[2678] #endif
[2679] 
[2680]             /*
[2681]              * headers frame:
[2682]              *
[2683]              * +---------------+
[2684]              * |Pad Length? (8)|
[2685]              * +-+-------------+----------------------------------------------+
[2686]              * |E|                 Stream Dependency? (31)                    |
[2687]              * +-+-------------+----------------------------------------------+
[2688]              * |  Weight? (8)  |
[2689]              * +-+-------------+----------------------------------------------+
[2690]              * |                   Header Block Fragment (*)                ...
[2691]              * +--------------------------------------------------------------+
[2692]              * |                           Padding (*)                      ...
[2693]              * +--------------------------------------------------------------+
[2694]              */
[2695] 
[2696]             switch (state) {
[2697] 
[2698]             case sw_padding_length:
[2699] 
[2700]                 ctx->padding = ch;
[2701] 
[2702]                 if (ctx->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
[2703]                     state = sw_dependency;
[2704]                     break;
[2705]                 }
[2706] 
[2707]                 goto fragment;
[2708] 
[2709]             case sw_dependency:
[2710]                 state = sw_dependency_2;
[2711]                 break;
[2712] 
[2713]             case sw_dependency_2:
[2714]                 state = sw_dependency_3;
[2715]                 break;
[2716] 
[2717]             case sw_dependency_3:
[2718]                 state = sw_dependency_4;
[2719]                 break;
[2720] 
[2721]             case sw_dependency_4:
[2722]                 state = sw_weight;
[2723]                 break;
[2724] 
[2725]             case sw_weight:
[2726]                 goto fragment;
[2727] 
[2728]             /* suppress warning */
[2729]             case sw_start:
[2730]             case sw_fragment:
[2731]             case sw_padding:
[2732]                 break;
[2733]             }
[2734]         }
[2735] 
[2736]         ctx->rest -= p - b->pos;
[2737]         b->pos = p;
[2738] 
[2739]         ctx->frame_state = state;
[2740]         return NGX_AGAIN;
[2741] 
[2742]     fragment:
[2743] 
[2744]         p++;
[2745]         ctx->rest -= p - b->pos;
[2746]         b->pos = p;
[2747] 
[2748]         if (ctx->padding > ctx->rest) {
[2749]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2750]                           "upstream sent http2 frame with too long "
[2751]                           "padding: %d in frame %uz",
[2752]                           ctx->padding, ctx->rest);
[2753]             return NGX_ERROR;
[2754]         }
[2755] 
[2756]         state = sw_fragment;
[2757]         ctx->frame_state = state;
[2758]     }
[2759] 
[2760]     if (state == sw_fragment) {
[2761] 
[2762]         rc = ngx_http_grpc_parse_fragment(r, ctx, b);
[2763] 
[2764]         if (rc == NGX_AGAIN) {
[2765]             return NGX_AGAIN;
[2766]         }
[2767] 
[2768]         if (rc == NGX_ERROR) {
[2769]             return NGX_ERROR;
[2770]         }
[2771] 
[2772]         if (rc == NGX_OK) {
[2773]             return NGX_OK;
[2774]         }
[2775] 
[2776]         /* rc == NGX_DONE */
[2777] 
[2778]         state = sw_padding;
[2779]         ctx->frame_state = state;
[2780]     }
[2781] 
[2782]     if (state == sw_padding) {
[2783] 
[2784]         if (b->last - b->pos < (ssize_t) ctx->rest) {
[2785] 
[2786]             ctx->rest -= b->last - b->pos;
[2787]             b->pos = b->last;
[2788] 
[2789]             return NGX_AGAIN;
[2790]         }
[2791] 
[2792]         b->pos += ctx->rest;
[2793]         ctx->rest = 0;
[2794] 
[2795]         ctx->state = ngx_http_grpc_st_start;
[2796] 
[2797]         if (ctx->flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
[2798] 
[2799]             if (ctx->fragment_state) {
[2800]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2801]                               "upstream sent truncated http2 header");
[2802]                 return NGX_ERROR;
[2803]             }
[2804] 
[2805]             ctx->parsing_headers = 0;
[2806] 
[2807]             return NGX_HTTP_PARSE_HEADER_DONE;
[2808]         }
[2809] 
[2810]         return NGX_AGAIN;
[2811]     }
[2812] 
[2813]     /* unreachable */
[2814] 
[2815]     return NGX_ERROR;
[2816] }
[2817] 
[2818] 
[2819] static ngx_int_t
[2820] ngx_http_grpc_parse_fragment(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[2821]     ngx_buf_t *b)
[2822] {
[2823]     u_char      ch, *p, *last;
[2824]     size_t      size;
[2825]     ngx_uint_t  index, size_update;
[2826]     enum {
[2827]         sw_start = 0,
[2828]         sw_index,
[2829]         sw_name_length,
[2830]         sw_name_length_2,
[2831]         sw_name_length_3,
[2832]         sw_name_length_4,
[2833]         sw_name,
[2834]         sw_name_bytes,
[2835]         sw_value_length,
[2836]         sw_value_length_2,
[2837]         sw_value_length_3,
[2838]         sw_value_length_4,
[2839]         sw_value,
[2840]         sw_value_bytes
[2841]     } state;
[2842] 
[2843]     /* header block fragment */
[2844] 
[2845] #if 0
[2846]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2847]                    "grpc header fragment %p:%p rest:%uz",
[2848]                    b->pos, b->last, ctx->rest);
[2849] #endif
[2850] 
[2851]     if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
[2852]         last = b->last;
[2853] 
[2854]     } else {
[2855]         last = b->pos + ctx->rest - ctx->padding;
[2856]     }
[2857] 
[2858]     state = ctx->fragment_state;
[2859] 
[2860]     for (p = b->pos; p < last; p++) {
[2861]         ch = *p;
[2862] 
[2863] #if 0
[2864]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2865]                        "grpc header byte: %02Xd s:%d", ch, state);
[2866] #endif
[2867] 
[2868]         switch (state) {
[2869] 
[2870]         case sw_start:
[2871]             ctx->index = 0;
[2872] 
[2873]             if ((ch & 0x80) == 0x80) {
[2874]                 /*
[2875]                  * indexed header:
[2876]                  *
[2877]                  *   0   1   2   3   4   5   6   7
[2878]                  * +---+---+---+---+---+---+---+---+
[2879]                  * | 1 |        Index (7+)         |
[2880]                  * +---+---------------------------+
[2881]                  */
[2882] 
[2883]                 index = ch & ~0x80;
[2884] 
[2885]                 if (index == 0 || index > 61) {
[2886]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2887]                                   "upstream sent invalid http2 "
[2888]                                   "table index: %ui", index);
[2889]                     return NGX_ERROR;
[2890]                 }
[2891] 
[2892]                 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2893]                                "grpc indexed header: %ui", index);
[2894] 
[2895]                 ctx->index = index;
[2896]                 ctx->literal = 0;
[2897] 
[2898]                 goto done;
[2899] 
[2900]             } else if ((ch & 0xc0) == 0x40) {
[2901]                 /*
[2902]                  * literal header with incremental indexing:
[2903]                  *
[2904]                  *   0   1   2   3   4   5   6   7
[2905]                  * +---+---+---+---+---+---+---+---+
[2906]                  * | 0 | 1 |      Index (6+)       |
[2907]                  * +---+---+-----------------------+
[2908]                  * | H |     Value Length (7+)     |
[2909]                  * +---+---------------------------+
[2910]                  * | Value String (Length octets)  |
[2911]                  * +-------------------------------+
[2912]                  *
[2913]                  *   0   1   2   3   4   5   6   7
[2914]                  * +---+---+---+---+---+---+---+---+
[2915]                  * | 0 | 1 |           0           |
[2916]                  * +---+---+-----------------------+
[2917]                  * | H |     Name Length (7+)      |
[2918]                  * +---+---------------------------+
[2919]                  * |  Name String (Length octets)  |
[2920]                  * +---+---------------------------+
[2921]                  * | H |     Value Length (7+)     |
[2922]                  * +---+---------------------------+
[2923]                  * | Value String (Length octets)  |
[2924]                  * +-------------------------------+
[2925]                  */
[2926] 
[2927]                 index = ch & ~0xc0;
[2928] 
[2929]                 if (index > 61) {
[2930]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2931]                                   "upstream sent invalid http2 "
[2932]                                   "table index: %ui", index);
[2933]                     return NGX_ERROR;
[2934]                 }
[2935] 
[2936]                 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2937]                                "grpc literal header: %ui", index);
[2938] 
[2939]                 if (index == 0) {
[2940]                     state = sw_name_length;
[2941]                     break;
[2942]                 }
[2943] 
[2944]                 ctx->index = index;
[2945]                 ctx->literal = 1;
[2946] 
[2947]                 state = sw_value_length;
[2948]                 break;
[2949] 
[2950]             } else if ((ch & 0xe0) == 0x20) {
[2951]                 /*
[2952]                  * dynamic table size update:
[2953]                  *
[2954]                  *   0   1   2   3   4   5   6   7
[2955]                  * +---+---+---+---+---+---+---+---+
[2956]                  * | 0 | 0 | 1 |   Max size (5+)   |
[2957]                  * +---+---------------------------+
[2958]                  */
[2959] 
[2960]                 size_update = ch & ~0xe0;
[2961] 
[2962]                 if (size_update > 0) {
[2963]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2964]                                   "upstream sent invalid http2 "
[2965]                                   "dynamic table size update: %ui",
[2966]                                   size_update);
[2967]                     return NGX_ERROR;
[2968]                 }
[2969] 
[2970]                 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2971]                                "grpc table size update: %ui", size_update);
[2972] 
[2973]                 break;
[2974] 
[2975]             } else if ((ch & 0xf0) == 0x10) {
[2976]                 /*
[2977]                  *  literal header field never indexed:
[2978]                  *
[2979]                  *   0   1   2   3   4   5   6   7
[2980]                  * +---+---+---+---+---+---+---+---+
[2981]                  * | 0 | 0 | 0 | 1 |  Index (4+)   |
[2982]                  * +---+---+-----------------------+
[2983]                  * | H |     Value Length (7+)     |
[2984]                  * +---+---------------------------+
[2985]                  * | Value String (Length octets)  |
[2986]                  * +-------------------------------+
[2987]                  *
[2988]                  *   0   1   2   3   4   5   6   7
[2989]                  * +---+---+---+---+---+---+---+---+
[2990]                  * | 0 | 0 | 0 | 1 |       0       |
[2991]                  * +---+---+-----------------------+
[2992]                  * | H |     Name Length (7+)      |
[2993]                  * +---+---------------------------+
[2994]                  * |  Name String (Length octets)  |
[2995]                  * +---+---------------------------+
[2996]                  * | H |     Value Length (7+)     |
[2997]                  * +---+---------------------------+
[2998]                  * | Value String (Length octets)  |
[2999]                  * +-------------------------------+
[3000]                  */
[3001] 
[3002]                 index = ch & ~0xf0;
[3003] 
[3004]                 if (index == 0x0f) {
[3005]                     ctx->index = index;
[3006]                     ctx->literal = 1;
[3007]                     state = sw_index;
[3008]                     break;
[3009]                 }
[3010] 
[3011]                 if (index == 0) {
[3012]                     state = sw_name_length;
[3013]                     break;
[3014]                 }
[3015] 
[3016]                 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3017]                                "grpc literal header never indexed: %ui",
[3018]                                index);
[3019] 
[3020]                 ctx->index = index;
[3021]                 ctx->literal = 1;
[3022] 
[3023]                 state = sw_value_length;
[3024]                 break;
[3025] 
[3026]             } else if ((ch & 0xf0) == 0x00) {
[3027]                 /*
[3028]                  * literal header field without indexing:
[3029]                  *
[3030]                  *   0   1   2   3   4   5   6   7
[3031]                  * +---+---+---+---+---+---+---+---+
[3032]                  * | 0 | 0 | 0 | 0 |  Index (4+)   |
[3033]                  * +---+---+-----------------------+
[3034]                  * | H |     Value Length (7+)     |
[3035]                  * +---+---------------------------+
[3036]                  * | Value String (Length octets)  |
[3037]                  * +-------------------------------+
[3038]                  *
[3039]                  *   0   1   2   3   4   5   6   7
[3040]                  * +---+---+---+---+---+---+---+---+
[3041]                  * | 0 | 0 | 0 | 0 |       0       |
[3042]                  * +---+---+-----------------------+
[3043]                  * | H |     Name Length (7+)      |
[3044]                  * +---+---------------------------+
[3045]                  * |  Name String (Length octets)  |
[3046]                  * +---+---------------------------+
[3047]                  * | H |     Value Length (7+)     |
[3048]                  * +---+---------------------------+
[3049]                  * | Value String (Length octets)  |
[3050]                  * +-------------------------------+
[3051]                  */
[3052] 
[3053]                 index = ch & ~0xf0;
[3054] 
[3055]                 if (index == 0x0f) {
[3056]                     ctx->index = index;
[3057]                     ctx->literal = 1;
[3058]                     state = sw_index;
[3059]                     break;
[3060]                 }
[3061] 
[3062]                 if (index == 0) {
[3063]                     state = sw_name_length;
[3064]                     break;
[3065]                 }
[3066] 
[3067]                 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3068]                                "grpc literal header without indexing: %ui",
[3069]                                index);
[3070] 
[3071]                 ctx->index = index;
[3072]                 ctx->literal = 1;
[3073] 
[3074]                 state = sw_value_length;
[3075]                 break;
[3076]             }
[3077] 
[3078]             /* not reached */
[3079] 
[3080]             return NGX_ERROR;
[3081] 
[3082]         case sw_index:
[3083]             ctx->index = ctx->index + (ch & ~0x80);
[3084] 
[3085]             if (ch & 0x80) {
[3086]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3087]                               "upstream sent http2 table index "
[3088]                               "with continuation flag");
[3089]                 return NGX_ERROR;
[3090]             }
[3091] 
[3092]             if (ctx->index > 61) {
[3093]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3094]                               "upstream sent invalid http2 "
[3095]                               "table index: %ui", ctx->index);
[3096]                 return NGX_ERROR;
[3097]             }
[3098] 
[3099]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3100]                            "grpc header index: %ui", ctx->index);
[3101] 
[3102]             state = sw_value_length;
[3103]             break;
[3104] 
[3105]         case sw_name_length:
[3106]             ctx->field_huffman = ch & 0x80 ? 1 : 0;
[3107]             ctx->field_length = ch & ~0x80;
[3108] 
[3109]             if (ctx->field_length == 0x7f) {
[3110]                 state = sw_name_length_2;
[3111]                 break;
[3112]             }
[3113] 
[3114]             if (ctx->field_length == 0) {
[3115]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3116]                               "upstream sent zero http2 "
[3117]                               "header name length");
[3118]                 return NGX_ERROR;
[3119]             }
[3120] 
[3121]             state = sw_name;
[3122]             break;
[3123] 
[3124]         case sw_name_length_2:
[3125]             ctx->field_length += ch & ~0x80;
[3126] 
[3127]             if (ch & 0x80) {
[3128]                 state = sw_name_length_3;
[3129]                 break;
[3130]             }
[3131] 
[3132]             state = sw_name;
[3133]             break;
[3134] 
[3135]         case sw_name_length_3:
[3136]             ctx->field_length += (ch & ~0x80) << 7;
[3137] 
[3138]             if (ch & 0x80) {
[3139]                 state = sw_name_length_4;
[3140]                 break;
[3141]             }
[3142] 
[3143]             state = sw_name;
[3144]             break;
[3145] 
[3146]         case sw_name_length_4:
[3147]             ctx->field_length += (ch & ~0x80) << 14;
[3148] 
[3149]             if (ch & 0x80) {
[3150]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3151]                               "upstream sent too large http2 "
[3152]                               "header name length");
[3153]                 return NGX_ERROR;
[3154]             }
[3155] 
[3156]             state = sw_name;
[3157]             break;
[3158] 
[3159]         case sw_name:
[3160]             ctx->name.len = ctx->field_huffman ?
[3161]                             ctx->field_length * 8 / 5 : ctx->field_length;
[3162] 
[3163]             ctx->name.data = ngx_pnalloc(r->pool, ctx->name.len + 1);
[3164]             if (ctx->name.data == NULL) {
[3165]                 return NGX_ERROR;
[3166]             }
[3167] 
[3168]             ctx->field_end = ctx->name.data;
[3169]             ctx->field_rest = ctx->field_length;
[3170]             ctx->field_state = 0;
[3171] 
[3172]             state = sw_name_bytes;
[3173] 
[3174]             /* fall through */
[3175] 
[3176]         case sw_name_bytes:
[3177] 
[3178]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3179]                            "grpc name: len:%uz h:%d last:%uz, rest:%uz",
[3180]                            ctx->field_length,
[3181]                            ctx->field_huffman,
[3182]                            last - p,
[3183]                            ctx->rest - (p - b->pos));
[3184] 
[3185]             size = ngx_min(last - p, (ssize_t) ctx->field_rest);
[3186]             ctx->field_rest -= size;
[3187] 
[3188]             if (ctx->field_huffman) {
[3189]                 if (ngx_http_huff_decode(&ctx->field_state, p, size,
[3190]                                          &ctx->field_end,
[3191]                                          ctx->field_rest == 0,
[3192]                                          r->connection->log)
[3193]                     != NGX_OK)
[3194]                 {
[3195]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3196]                                   "upstream sent invalid encoded header");
[3197]                     return NGX_ERROR;
[3198]                 }
[3199] 
[3200]                 ctx->name.len = ctx->field_end - ctx->name.data;
[3201]                 ctx->name.data[ctx->name.len] = '\0';
[3202] 
[3203]             } else {
[3204]                 ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
[3205]                 ctx->name.data[ctx->name.len] = '\0';
[3206]             }
[3207] 
[3208]             p += size - 1;
[3209] 
[3210]             if (ctx->field_rest == 0) {
[3211]                 state = sw_value_length;
[3212]             }
[3213] 
[3214]             break;
[3215] 
[3216]         case sw_value_length:
[3217]             ctx->field_huffman = ch & 0x80 ? 1 : 0;
[3218]             ctx->field_length = ch & ~0x80;
[3219] 
[3220]             if (ctx->field_length == 0x7f) {
[3221]                 state = sw_value_length_2;
[3222]                 break;
[3223]             }
[3224] 
[3225]             if (ctx->field_length == 0) {
[3226]                 ngx_str_set(&ctx->value, "");
[3227]                 goto done;
[3228]             }
[3229] 
[3230]             state = sw_value;
[3231]             break;
[3232] 
[3233]         case sw_value_length_2:
[3234]             ctx->field_length += ch & ~0x80;
[3235] 
[3236]             if (ch & 0x80) {
[3237]                 state = sw_value_length_3;
[3238]                 break;
[3239]             }
[3240] 
[3241]             state = sw_value;
[3242]             break;
[3243] 
[3244]         case sw_value_length_3:
[3245]             ctx->field_length += (ch & ~0x80) << 7;
[3246] 
[3247]             if (ch & 0x80) {
[3248]                 state = sw_value_length_4;
[3249]                 break;
[3250]             }
[3251] 
[3252]             state = sw_value;
[3253]             break;
[3254] 
[3255]         case sw_value_length_4:
[3256]             ctx->field_length += (ch & ~0x80) << 14;
[3257] 
[3258]             if (ch & 0x80) {
[3259]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3260]                               "upstream sent too large http2 "
[3261]                               "header value length");
[3262]                 return NGX_ERROR;
[3263]             }
[3264] 
[3265]             state = sw_value;
[3266]             break;
[3267] 
[3268]         case sw_value:
[3269]             ctx->value.len = ctx->field_huffman ?
[3270]                              ctx->field_length * 8 / 5 : ctx->field_length;
[3271] 
[3272]             ctx->value.data = ngx_pnalloc(r->pool, ctx->value.len + 1);
[3273]             if (ctx->value.data == NULL) {
[3274]                 return NGX_ERROR;
[3275]             }
[3276] 
[3277]             ctx->field_end = ctx->value.data;
[3278]             ctx->field_rest = ctx->field_length;
[3279]             ctx->field_state = 0;
[3280] 
[3281]             state = sw_value_bytes;
[3282] 
[3283]             /* fall through */
[3284] 
[3285]         case sw_value_bytes:
[3286] 
[3287]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3288]                            "grpc value: len:%uz h:%d last:%uz, rest:%uz",
[3289]                            ctx->field_length,
[3290]                            ctx->field_huffman,
[3291]                            last - p,
[3292]                            ctx->rest - (p - b->pos));
[3293] 
[3294]             size = ngx_min(last - p, (ssize_t) ctx->field_rest);
[3295]             ctx->field_rest -= size;
[3296] 
[3297]             if (ctx->field_huffman) {
[3298]                 if (ngx_http_huff_decode(&ctx->field_state, p, size,
[3299]                                          &ctx->field_end,
[3300]                                          ctx->field_rest == 0,
[3301]                                          r->connection->log)
[3302]                     != NGX_OK)
[3303]                 {
[3304]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3305]                                   "upstream sent invalid encoded header");
[3306]                     return NGX_ERROR;
[3307]                 }
[3308] 
[3309]                 ctx->value.len = ctx->field_end - ctx->value.data;
[3310]                 ctx->value.data[ctx->value.len] = '\0';
[3311] 
[3312]             } else {
[3313]                 ctx->field_end = ngx_cpymem(ctx->field_end, p, size);
[3314]                 ctx->value.data[ctx->value.len] = '\0';
[3315]             }
[3316] 
[3317]             p += size - 1;
[3318] 
[3319]             if (ctx->field_rest == 0) {
[3320]                 goto done;
[3321]             }
[3322] 
[3323]             break;
[3324]         }
[3325] 
[3326]         continue;
[3327] 
[3328]     done:
[3329] 
[3330]         p++;
[3331]         ctx->rest -= p - b->pos;
[3332]         ctx->fragment_state = sw_start;
[3333]         b->pos = p;
[3334] 
[3335]         if (ctx->index) {
[3336]             ctx->name = *ngx_http_v2_get_static_name(ctx->index);
[3337]         }
[3338] 
[3339]         if (ctx->index && !ctx->literal) {
[3340]             ctx->value = *ngx_http_v2_get_static_value(ctx->index);
[3341]         }
[3342] 
[3343]         if (!ctx->index) {
[3344]             if (ngx_http_grpc_validate_header_name(r, &ctx->name) != NGX_OK) {
[3345]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3346]                               "upstream sent invalid header: \"%V: %V\"",
[3347]                               &ctx->name, &ctx->value);
[3348]                 return NGX_ERROR;
[3349]             }
[3350]         }
[3351] 
[3352]         if (!ctx->index || ctx->literal) {
[3353]             if (ngx_http_grpc_validate_header_value(r, &ctx->value) != NGX_OK) {
[3354]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3355]                               "upstream sent invalid header: \"%V: %V\"",
[3356]                               &ctx->name, &ctx->value);
[3357]                 return NGX_ERROR;
[3358]             }
[3359]         }
[3360] 
[3361]         return NGX_OK;
[3362]     }
[3363] 
[3364]     ctx->rest -= p - b->pos;
[3365]     ctx->fragment_state = state;
[3366]     b->pos = p;
[3367] 
[3368]     if (ctx->rest > ctx->padding) {
[3369]         return NGX_AGAIN;
[3370]     }
[3371] 
[3372]     return NGX_DONE;
[3373] }
[3374] 
[3375] 
[3376] static ngx_int_t
[3377] ngx_http_grpc_validate_header_name(ngx_http_request_t *r, ngx_str_t *s)
[3378] {
[3379]     u_char      ch;
[3380]     ngx_uint_t  i;
[3381] 
[3382]     for (i = 0; i < s->len; i++) {
[3383]         ch = s->data[i];
[3384] 
[3385]         if (ch == ':' && i > 0) {
[3386]             return NGX_ERROR;
[3387]         }
[3388] 
[3389]         if (ch >= 'A' && ch <= 'Z') {
[3390]             return NGX_ERROR;
[3391]         }
[3392] 
[3393]         if (ch <= 0x20 || ch == 0x7f) {
[3394]             return NGX_ERROR;
[3395]         }
[3396]     }
[3397] 
[3398]     return NGX_OK;
[3399] }
[3400] 
[3401] 
[3402] static ngx_int_t
[3403] ngx_http_grpc_validate_header_value(ngx_http_request_t *r, ngx_str_t *s)
[3404] {
[3405]     u_char      ch;
[3406]     ngx_uint_t  i;
[3407] 
[3408]     for (i = 0; i < s->len; i++) {
[3409]         ch = s->data[i];
[3410] 
[3411]         if (ch == '\0' || ch == CR || ch == LF) {
[3412]             return NGX_ERROR;
[3413]         }
[3414]     }
[3415] 
[3416]     return NGX_OK;
[3417] }
[3418] 
[3419] 
[3420] static ngx_int_t
[3421] ngx_http_grpc_parse_rst_stream(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[3422]     ngx_buf_t *b)
[3423] {
[3424]     u_char  ch, *p, *last;
[3425]     enum {
[3426]         sw_start = 0,
[3427]         sw_error_2,
[3428]         sw_error_3,
[3429]         sw_error_4
[3430]     } state;
[3431] 
[3432]     if (b->last - b->pos < (ssize_t) ctx->rest) {
[3433]         last = b->last;
[3434] 
[3435]     } else {
[3436]         last = b->pos + ctx->rest;
[3437]     }
[3438] 
[3439]     state = ctx->frame_state;
[3440] 
[3441]     if (state == sw_start) {
[3442]         if (ctx->rest != 4) {
[3443]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3444]                           "upstream sent rst stream frame "
[3445]                           "with invalid length: %uz",
[3446]                           ctx->rest);
[3447]             return NGX_ERROR;
[3448]         }
[3449]     }
[3450] 
[3451]     for (p = b->pos; p < last; p++) {
[3452]         ch = *p;
[3453] 
[3454] #if 0
[3455]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3456]                        "grpc rst byte: %02Xd s:%d", ch, state);
[3457] #endif
[3458] 
[3459]         switch (state) {
[3460] 
[3461]         case sw_start:
[3462]             ctx->error = (ngx_uint_t) ch << 24;
[3463]             state = sw_error_2;
[3464]             break;
[3465] 
[3466]         case sw_error_2:
[3467]             ctx->error |= ch << 16;
[3468]             state = sw_error_3;
[3469]             break;
[3470] 
[3471]         case sw_error_3:
[3472]             ctx->error |= ch << 8;
[3473]             state = sw_error_4;
[3474]             break;
[3475] 
[3476]         case sw_error_4:
[3477]             ctx->error |= ch;
[3478]             state = sw_start;
[3479] 
[3480]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3481]                            "grpc error: %ui", ctx->error);
[3482] 
[3483]             break;
[3484]         }
[3485]     }
[3486] 
[3487]     ctx->rest -= p - b->pos;
[3488]     ctx->frame_state = state;
[3489]     b->pos = p;
[3490] 
[3491]     if (ctx->rest > 0) {
[3492]         return NGX_AGAIN;
[3493]     }
[3494] 
[3495]     ctx->state = ngx_http_grpc_st_start;
[3496] 
[3497]     return NGX_OK;
[3498] }
[3499] 
[3500] 
[3501] static ngx_int_t
[3502] ngx_http_grpc_parse_goaway(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[3503]     ngx_buf_t *b)
[3504] {
[3505]     u_char  ch, *p, *last;
[3506]     enum {
[3507]         sw_start = 0,
[3508]         sw_last_stream_id_2,
[3509]         sw_last_stream_id_3,
[3510]         sw_last_stream_id_4,
[3511]         sw_error,
[3512]         sw_error_2,
[3513]         sw_error_3,
[3514]         sw_error_4,
[3515]         sw_debug
[3516]     } state;
[3517] 
[3518]     if (b->last - b->pos < (ssize_t) ctx->rest) {
[3519]         last = b->last;
[3520] 
[3521]     } else {
[3522]         last = b->pos + ctx->rest;
[3523]     }
[3524] 
[3525]     state = ctx->frame_state;
[3526] 
[3527]     if (state == sw_start) {
[3528] 
[3529]         if (ctx->stream_id) {
[3530]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3531]                           "upstream sent goaway frame "
[3532]                           "with non-zero stream id: %ui",
[3533]                           ctx->stream_id);
[3534]             return NGX_ERROR;
[3535]         }
[3536] 
[3537]         if (ctx->rest < 8) {
[3538]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3539]                           "upstream sent goaway frame "
[3540]                           "with invalid length: %uz",
[3541]                           ctx->rest);
[3542]             return NGX_ERROR;
[3543]         }
[3544]     }
[3545] 
[3546]     for (p = b->pos; p < last; p++) {
[3547]         ch = *p;
[3548] 
[3549] #if 0
[3550]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3551]                        "grpc goaway byte: %02Xd s:%d", ch, state);
[3552] #endif
[3553] 
[3554]         switch (state) {
[3555] 
[3556]         case sw_start:
[3557]             ctx->stream_id = (ch & 0x7f) << 24;
[3558]             state = sw_last_stream_id_2;
[3559]             break;
[3560] 
[3561]         case sw_last_stream_id_2:
[3562]             ctx->stream_id |= ch << 16;
[3563]             state = sw_last_stream_id_3;
[3564]             break;
[3565] 
[3566]         case sw_last_stream_id_3:
[3567]             ctx->stream_id |= ch << 8;
[3568]             state = sw_last_stream_id_4;
[3569]             break;
[3570] 
[3571]         case sw_last_stream_id_4:
[3572]             ctx->stream_id |= ch;
[3573]             state = sw_error;
[3574]             break;
[3575] 
[3576]         case sw_error:
[3577]             ctx->error = (ngx_uint_t) ch << 24;
[3578]             state = sw_error_2;
[3579]             break;
[3580] 
[3581]         case sw_error_2:
[3582]             ctx->error |= ch << 16;
[3583]             state = sw_error_3;
[3584]             break;
[3585] 
[3586]         case sw_error_3:
[3587]             ctx->error |= ch << 8;
[3588]             state = sw_error_4;
[3589]             break;
[3590] 
[3591]         case sw_error_4:
[3592]             ctx->error |= ch;
[3593]             state = sw_debug;
[3594]             break;
[3595] 
[3596]         case sw_debug:
[3597]             break;
[3598]         }
[3599]     }
[3600] 
[3601]     ctx->rest -= p - b->pos;
[3602]     ctx->frame_state = state;
[3603]     b->pos = p;
[3604] 
[3605]     if (ctx->rest > 0) {
[3606]         return NGX_AGAIN;
[3607]     }
[3608] 
[3609]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3610]                    "grpc goaway: %ui, stream %ui",
[3611]                    ctx->error, ctx->stream_id);
[3612] 
[3613]     ctx->state = ngx_http_grpc_st_start;
[3614] 
[3615]     return NGX_OK;
[3616] }
[3617] 
[3618] 
[3619] static ngx_int_t
[3620] ngx_http_grpc_parse_window_update(ngx_http_request_t *r,
[3621]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b)
[3622] {
[3623]     u_char  ch, *p, *last;
[3624]     enum {
[3625]         sw_start = 0,
[3626]         sw_size_2,
[3627]         sw_size_3,
[3628]         sw_size_4
[3629]     } state;
[3630] 
[3631]     if (b->last - b->pos < (ssize_t) ctx->rest) {
[3632]         last = b->last;
[3633] 
[3634]     } else {
[3635]         last = b->pos + ctx->rest;
[3636]     }
[3637] 
[3638]     state = ctx->frame_state;
[3639] 
[3640]     if (state == sw_start) {
[3641]         if (ctx->rest != 4) {
[3642]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3643]                           "upstream sent window update frame "
[3644]                           "with invalid length: %uz",
[3645]                           ctx->rest);
[3646]             return NGX_ERROR;
[3647]         }
[3648]     }
[3649] 
[3650]     for (p = b->pos; p < last; p++) {
[3651]         ch = *p;
[3652] 
[3653] #if 0
[3654]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3655]                        "grpc window update byte: %02Xd s:%d", ch, state);
[3656] #endif
[3657] 
[3658]         switch (state) {
[3659] 
[3660]         case sw_start:
[3661]             ctx->window_update = (ch & 0x7f) << 24;
[3662]             state = sw_size_2;
[3663]             break;
[3664] 
[3665]         case sw_size_2:
[3666]             ctx->window_update |= ch << 16;
[3667]             state = sw_size_3;
[3668]             break;
[3669] 
[3670]         case sw_size_3:
[3671]             ctx->window_update |= ch << 8;
[3672]             state = sw_size_4;
[3673]             break;
[3674] 
[3675]         case sw_size_4:
[3676]             ctx->window_update |= ch;
[3677]             state = sw_start;
[3678]             break;
[3679]         }
[3680]     }
[3681] 
[3682]     ctx->rest -= p - b->pos;
[3683]     ctx->frame_state = state;
[3684]     b->pos = p;
[3685] 
[3686]     if (ctx->rest > 0) {
[3687]         return NGX_AGAIN;
[3688]     }
[3689] 
[3690]     ctx->state = ngx_http_grpc_st_start;
[3691] 
[3692]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3693]                    "grpc window update: %ui", ctx->window_update);
[3694] 
[3695]     if (ctx->stream_id) {
[3696] 
[3697]         if (ctx->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
[3698]                                  - ctx->send_window)
[3699]         {
[3700]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3701]                           "upstream sent too large window update");
[3702]             return NGX_ERROR;
[3703]         }
[3704] 
[3705]         ctx->send_window += ctx->window_update;
[3706] 
[3707]     } else {
[3708] 
[3709]         if (ctx->window_update > NGX_HTTP_V2_MAX_WINDOW
[3710]                                  - ctx->connection->send_window)
[3711]         {
[3712]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3713]                           "upstream sent too large window update");
[3714]             return NGX_ERROR;
[3715]         }
[3716] 
[3717]         ctx->connection->send_window += ctx->window_update;
[3718]     }
[3719] 
[3720]     return NGX_OK;
[3721] }
[3722] 
[3723] 
[3724] static ngx_int_t
[3725] ngx_http_grpc_parse_settings(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx,
[3726]     ngx_buf_t *b)
[3727] {
[3728]     u_char   ch, *p, *last;
[3729]     ssize_t  window_update;
[3730]     enum {
[3731]         sw_start = 0,
[3732]         sw_id,
[3733]         sw_id_2,
[3734]         sw_value,
[3735]         sw_value_2,
[3736]         sw_value_3,
[3737]         sw_value_4
[3738]     } state;
[3739] 
[3740]     if (b->last - b->pos < (ssize_t) ctx->rest) {
[3741]         last = b->last;
[3742] 
[3743]     } else {
[3744]         last = b->pos + ctx->rest;
[3745]     }
[3746] 
[3747]     state = ctx->frame_state;
[3748] 
[3749]     if (state == sw_start) {
[3750] 
[3751]         if (ctx->stream_id) {
[3752]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3753]                           "upstream sent settings frame "
[3754]                           "with non-zero stream id: %ui",
[3755]                           ctx->stream_id);
[3756]             return NGX_ERROR;
[3757]         }
[3758] 
[3759]         if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
[3760]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3761]                            "grpc settings ack");
[3762] 
[3763]             if (ctx->rest != 0) {
[3764]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3765]                               "upstream sent settings frame "
[3766]                               "with ack flag and non-zero length: %uz",
[3767]                               ctx->rest);
[3768]                 return NGX_ERROR;
[3769]             }
[3770] 
[3771]             ctx->state = ngx_http_grpc_st_start;
[3772] 
[3773]             return NGX_OK;
[3774]         }
[3775] 
[3776]         if (ctx->rest % 6 != 0) {
[3777]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3778]                           "upstream sent settings frame "
[3779]                           "with invalid length: %uz",
[3780]                           ctx->rest);
[3781]             return NGX_ERROR;
[3782]         }
[3783] 
[3784]         if (ctx->free == NULL && ctx->settings++ > 1000) {
[3785]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3786]                           "upstream sent too many settings frames");
[3787]             return NGX_ERROR;
[3788]         }
[3789]     }
[3790] 
[3791]     for (p = b->pos; p < last; p++) {
[3792]         ch = *p;
[3793] 
[3794] #if 0
[3795]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3796]                        "grpc settings byte: %02Xd s:%d", ch, state);
[3797] #endif
[3798] 
[3799]         switch (state) {
[3800] 
[3801]         case sw_start:
[3802]         case sw_id:
[3803]             ctx->setting_id = ch << 8;
[3804]             state = sw_id_2;
[3805]             break;
[3806] 
[3807]         case sw_id_2:
[3808]             ctx->setting_id |= ch;
[3809]             state = sw_value;
[3810]             break;
[3811] 
[3812]         case sw_value:
[3813]             ctx->setting_value = (ngx_uint_t) ch << 24;
[3814]             state = sw_value_2;
[3815]             break;
[3816] 
[3817]         case sw_value_2:
[3818]             ctx->setting_value |= ch << 16;
[3819]             state = sw_value_3;
[3820]             break;
[3821] 
[3822]         case sw_value_3:
[3823]             ctx->setting_value |= ch << 8;
[3824]             state = sw_value_4;
[3825]             break;
[3826] 
[3827]         case sw_value_4:
[3828]             ctx->setting_value |= ch;
[3829]             state = sw_id;
[3830] 
[3831]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3832]                            "grpc setting: %ui %ui",
[3833]                            ctx->setting_id, ctx->setting_value);
[3834] 
[3835]             /*
[3836]              * The following settings are defined by the protocol:
[3837]              *
[3838]              * SETTINGS_HEADER_TABLE_SIZE, SETTINGS_ENABLE_PUSH,
[3839]              * SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
[3840]              * SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE
[3841]              *
[3842]              * Only SETTINGS_INITIAL_WINDOW_SIZE seems to be needed in
[3843]              * a simple client.
[3844]              */
[3845] 
[3846]             if (ctx->setting_id == 0x04) {
[3847]                 /* SETTINGS_INITIAL_WINDOW_SIZE */
[3848] 
[3849]                 if (ctx->setting_value > NGX_HTTP_V2_MAX_WINDOW) {
[3850]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3851]                                   "upstream sent settings frame "
[3852]                                   "with too large initial window size: %ui",
[3853]                                   ctx->setting_value);
[3854]                     return NGX_ERROR;
[3855]                 }
[3856] 
[3857]                 window_update = ctx->setting_value
[3858]                                 - ctx->connection->init_window;
[3859]                 ctx->connection->init_window = ctx->setting_value;
[3860] 
[3861]                 if (ctx->send_window > 0
[3862]                     && window_update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW
[3863]                                        - ctx->send_window)
[3864]                 {
[3865]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3866]                                   "upstream sent settings frame "
[3867]                                   "with too large initial window size: %ui",
[3868]                                   ctx->setting_value);
[3869]                     return NGX_ERROR;
[3870]                 }
[3871] 
[3872]                 ctx->send_window += window_update;
[3873]             }
[3874] 
[3875]             break;
[3876]         }
[3877]     }
[3878] 
[3879]     ctx->rest -= p - b->pos;
[3880]     ctx->frame_state = state;
[3881]     b->pos = p;
[3882] 
[3883]     if (ctx->rest > 0) {
[3884]         return NGX_AGAIN;
[3885]     }
[3886] 
[3887]     ctx->state = ngx_http_grpc_st_start;
[3888] 
[3889]     return ngx_http_grpc_send_settings_ack(r, ctx);
[3890] }
[3891] 
[3892] 
[3893] static ngx_int_t
[3894] ngx_http_grpc_parse_ping(ngx_http_request_t *r,
[3895]     ngx_http_grpc_ctx_t *ctx, ngx_buf_t *b)
[3896] {
[3897]     u_char  ch, *p, *last;
[3898]     enum {
[3899]         sw_start = 0,
[3900]         sw_data_2,
[3901]         sw_data_3,
[3902]         sw_data_4,
[3903]         sw_data_5,
[3904]         sw_data_6,
[3905]         sw_data_7,
[3906]         sw_data_8
[3907]     } state;
[3908] 
[3909]     if (b->last - b->pos < (ssize_t) ctx->rest) {
[3910]         last = b->last;
[3911] 
[3912]     } else {
[3913]         last = b->pos + ctx->rest;
[3914]     }
[3915] 
[3916]     state = ctx->frame_state;
[3917] 
[3918]     if (state == sw_start) {
[3919] 
[3920]         if (ctx->stream_id) {
[3921]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3922]                           "upstream sent ping frame "
[3923]                           "with non-zero stream id: %ui",
[3924]                           ctx->stream_id);
[3925]             return NGX_ERROR;
[3926]         }
[3927] 
[3928]         if (ctx->rest != 8) {
[3929]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3930]                           "upstream sent ping frame "
[3931]                           "with invalid length: %uz",
[3932]                           ctx->rest);
[3933]             return NGX_ERROR;
[3934]         }
[3935] 
[3936]         if (ctx->flags & NGX_HTTP_V2_ACK_FLAG) {
[3937]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3938]                           "upstream sent ping frame with ack flag");
[3939]             return NGX_ERROR;
[3940]         }
[3941] 
[3942]         if (ctx->free == NULL && ctx->pings++ > 1000) {
[3943]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[3944]                           "upstream sent too many ping frames");
[3945]             return NGX_ERROR;
[3946]         }
[3947]     }
[3948] 
[3949]     for (p = b->pos; p < last; p++) {
[3950]         ch = *p;
[3951] 
[3952] #if 0
[3953]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3954]                        "grpc ping byte: %02Xd s:%d", ch, state);
[3955] #endif
[3956] 
[3957]         if (state < sw_data_8) {
[3958]             ctx->ping_data[state] = ch;
[3959]             state++;
[3960] 
[3961]         } else {
[3962]             ctx->ping_data[7] = ch;
[3963]             state = sw_start;
[3964] 
[3965]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3966]                            "grpc ping");
[3967]         }
[3968]     }
[3969] 
[3970]     ctx->rest -= p - b->pos;
[3971]     ctx->frame_state = state;
[3972]     b->pos = p;
[3973] 
[3974]     if (ctx->rest > 0) {
[3975]         return NGX_AGAIN;
[3976]     }
[3977] 
[3978]     ctx->state = ngx_http_grpc_st_start;
[3979] 
[3980]     return ngx_http_grpc_send_ping_ack(r, ctx);
[3981] }
[3982] 
[3983] 
[3984] static ngx_int_t
[3985] ngx_http_grpc_send_settings_ack(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx)
[3986] {
[3987]     ngx_chain_t            *cl, **ll;
[3988]     ngx_http_grpc_frame_t  *f;
[3989] 
[3990]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3991]                    "grpc send settings ack");
[3992] 
[3993]     for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
[3994]         ll = &cl->next;
[3995]     }
[3996] 
[3997]     cl = ngx_http_grpc_get_buf(r, ctx);
[3998]     if (cl == NULL) {
[3999]         return NGX_ERROR;
[4000]     }
[4001] 
[4002]     f = (ngx_http_grpc_frame_t *) cl->buf->last;
[4003]     cl->buf->last += sizeof(ngx_http_grpc_frame_t);
[4004] 
[4005]     f->length_0 = 0;
[4006]     f->length_1 = 0;
[4007]     f->length_2 = 0;
[4008]     f->type = NGX_HTTP_V2_SETTINGS_FRAME;
[4009]     f->flags = NGX_HTTP_V2_ACK_FLAG;
[4010]     f->stream_id_0 = 0;
[4011]     f->stream_id_1 = 0;
[4012]     f->stream_id_2 = 0;
[4013]     f->stream_id_3 = 0;
[4014] 
[4015]     *ll = cl;
[4016] 
[4017]     return NGX_OK;
[4018] }
[4019] 
[4020] 
[4021] static ngx_int_t
[4022] ngx_http_grpc_send_ping_ack(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx)
[4023] {
[4024]     ngx_chain_t            *cl, **ll;
[4025]     ngx_http_grpc_frame_t  *f;
[4026] 
[4027]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4028]                    "grpc send ping ack");
[4029] 
[4030]     for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
[4031]         ll = &cl->next;
[4032]     }
[4033] 
[4034]     cl = ngx_http_grpc_get_buf(r, ctx);
[4035]     if (cl == NULL) {
[4036]         return NGX_ERROR;
[4037]     }
[4038] 
[4039]     f = (ngx_http_grpc_frame_t *) cl->buf->last;
[4040]     cl->buf->last += sizeof(ngx_http_grpc_frame_t);
[4041] 
[4042]     f->length_0 = 0;
[4043]     f->length_1 = 0;
[4044]     f->length_2 = 8;
[4045]     f->type = NGX_HTTP_V2_PING_FRAME;
[4046]     f->flags = NGX_HTTP_V2_ACK_FLAG;
[4047]     f->stream_id_0 = 0;
[4048]     f->stream_id_1 = 0;
[4049]     f->stream_id_2 = 0;
[4050]     f->stream_id_3 = 0;
[4051] 
[4052]     cl->buf->last = ngx_copy(cl->buf->last, ctx->ping_data, 8);
[4053] 
[4054]     *ll = cl;
[4055] 
[4056]     return NGX_OK;
[4057] }
[4058] 
[4059] 
[4060] static ngx_int_t
[4061] ngx_http_grpc_send_window_update(ngx_http_request_t *r,
[4062]     ngx_http_grpc_ctx_t *ctx)
[4063] {
[4064]     size_t                  n;
[4065]     ngx_chain_t            *cl, **ll;
[4066]     ngx_http_grpc_frame_t  *f;
[4067] 
[4068]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4069]                    "grpc send window update: %uz %uz",
[4070]                    ctx->connection->recv_window, ctx->recv_window);
[4071] 
[4072]     for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
[4073]         ll = &cl->next;
[4074]     }
[4075] 
[4076]     cl = ngx_http_grpc_get_buf(r, ctx);
[4077]     if (cl == NULL) {
[4078]         return NGX_ERROR;
[4079]     }
[4080] 
[4081]     f = (ngx_http_grpc_frame_t *) cl->buf->last;
[4082]     cl->buf->last += sizeof(ngx_http_grpc_frame_t);
[4083] 
[4084]     f->length_0 = 0;
[4085]     f->length_1 = 0;
[4086]     f->length_2 = 4;
[4087]     f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
[4088]     f->flags = 0;
[4089]     f->stream_id_0 = 0;
[4090]     f->stream_id_1 = 0;
[4091]     f->stream_id_2 = 0;
[4092]     f->stream_id_3 = 0;
[4093] 
[4094]     n = NGX_HTTP_V2_MAX_WINDOW - ctx->connection->recv_window;
[4095]     ctx->connection->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[4096] 
[4097]     *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
[4098]     *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
[4099]     *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
[4100]     *cl->buf->last++ = (u_char) (n & 0xff);
[4101] 
[4102]     f = (ngx_http_grpc_frame_t *) cl->buf->last;
[4103]     cl->buf->last += sizeof(ngx_http_grpc_frame_t);
[4104] 
[4105]     f->length_0 = 0;
[4106]     f->length_1 = 0;
[4107]     f->length_2 = 4;
[4108]     f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
[4109]     f->flags = 0;
[4110]     f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
[4111]     f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
[4112]     f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
[4113]     f->stream_id_3 = (u_char) (ctx->id & 0xff);
[4114] 
[4115]     n = NGX_HTTP_V2_MAX_WINDOW - ctx->recv_window;
[4116]     ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[4117] 
[4118]     *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
[4119]     *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
[4120]     *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
[4121]     *cl->buf->last++ = (u_char) (n & 0xff);
[4122] 
[4123]     *ll = cl;
[4124] 
[4125]     return NGX_OK;
[4126] }
[4127] 
[4128] 
[4129] static ngx_chain_t *
[4130] ngx_http_grpc_get_buf(ngx_http_request_t *r, ngx_http_grpc_ctx_t *ctx)
[4131] {
[4132]     u_char       *start;
[4133]     ngx_buf_t    *b;
[4134]     ngx_chain_t  *cl;
[4135] 
[4136]     cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[4137]     if (cl == NULL) {
[4138]         return NULL;
[4139]     }
[4140] 
[4141]     b = cl->buf;
[4142]     start = b->start;
[4143] 
[4144]     if (start == NULL) {
[4145] 
[4146]         /*
[4147]          * each buffer is large enough to hold two window update
[4148]          * frames in a row
[4149]          */
[4150] 
[4151]         start = ngx_palloc(r->pool, 2 * sizeof(ngx_http_grpc_frame_t) + 8);
[4152]         if (start == NULL) {
[4153]             return NULL;
[4154]         }
[4155] 
[4156]     }
[4157] 
[4158]     ngx_memzero(b, sizeof(ngx_buf_t));
[4159] 
[4160]     b->start = start;
[4161]     b->pos = start;
[4162]     b->last = start;
[4163]     b->end = start + 2 * sizeof(ngx_http_grpc_frame_t) + 8;
[4164] 
[4165]     b->tag = (ngx_buf_tag_t) &ngx_http_grpc_body_output_filter;
[4166]     b->temporary = 1;
[4167]     b->flush = 1;
[4168] 
[4169]     return cl;
[4170] }
[4171] 
[4172] 
[4173] static ngx_http_grpc_ctx_t *
[4174] ngx_http_grpc_get_ctx(ngx_http_request_t *r)
[4175] {
[4176]     ngx_http_grpc_ctx_t  *ctx;
[4177]     ngx_http_upstream_t  *u;
[4178] 
[4179]     ctx = ngx_http_get_module_ctx(r, ngx_http_grpc_module);
[4180] 
[4181]     if (ctx->connection == NULL) {
[4182]         u = r->upstream;
[4183] 
[4184]         if (ngx_http_grpc_get_connection_data(r, ctx, &u->peer) != NGX_OK) {
[4185]             return NULL;
[4186]         }
[4187]     }
[4188] 
[4189]     return ctx;
[4190] }
[4191] 
[4192] 
[4193] static ngx_int_t
[4194] ngx_http_grpc_get_connection_data(ngx_http_request_t *r,
[4195]     ngx_http_grpc_ctx_t *ctx, ngx_peer_connection_t *pc)
[4196] {
[4197]     ngx_connection_t    *c;
[4198]     ngx_pool_cleanup_t  *cln;
[4199] 
[4200]     c = pc->connection;
[4201] 
[4202]     if (pc->cached) {
[4203] 
[4204]         /*
[4205]          * for cached connections, connection data can be found
[4206]          * in the cleanup handler
[4207]          */
[4208] 
[4209]         for (cln = c->pool->cleanup; cln; cln = cln->next) {
[4210]             if (cln->handler == ngx_http_grpc_cleanup) {
[4211]                 ctx->connection = cln->data;
[4212]                 break;
[4213]             }
[4214]         }
[4215] 
[4216]         if (ctx->connection == NULL) {
[4217]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[4218]                           "no connection data found for "
[4219]                           "keepalive http2 connection");
[4220]             return NGX_ERROR;
[4221]         }
[4222] 
[4223]         ctx->send_window = ctx->connection->init_window;
[4224]         ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[4225] 
[4226]         ctx->connection->last_stream_id += 2;
[4227]         ctx->id = ctx->connection->last_stream_id;
[4228] 
[4229]         return NGX_OK;
[4230]     }
[4231] 
[4232]     cln = ngx_pool_cleanup_add(c->pool, sizeof(ngx_http_grpc_conn_t));
[4233]     if (cln == NULL) {
[4234]         return NGX_ERROR;
[4235]     }
[4236] 
[4237]     cln->handler = ngx_http_grpc_cleanup;
[4238]     ctx->connection = cln->data;
[4239] 
[4240]     ctx->connection->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
[4241]     ctx->connection->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
[4242]     ctx->connection->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[4243] 
[4244]     ctx->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
[4245]     ctx->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[4246] 
[4247]     ctx->id = 1;
[4248]     ctx->connection->last_stream_id = 1;
[4249] 
[4250]     return NGX_OK;
[4251] }
[4252] 
[4253] 
[4254] static void
[4255] ngx_http_grpc_cleanup(void *data)
[4256] {
[4257] #if 0
[4258]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[4259]                    "grpc cleanup");
[4260] #endif
[4261]     return;
[4262] }
[4263] 
[4264] 
[4265] static void
[4266] ngx_http_grpc_abort_request(ngx_http_request_t *r)
[4267] {
[4268]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4269]                    "abort grpc request");
[4270]     return;
[4271] }
[4272] 
[4273] 
[4274] static void
[4275] ngx_http_grpc_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[4276] {
[4277]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[4278]                    "finalize grpc request");
[4279]     return;
[4280] }
[4281] 
[4282] 
[4283] static ngx_int_t
[4284] ngx_http_grpc_internal_trailers_variable(ngx_http_request_t *r,
[4285]     ngx_http_variable_value_t *v, uintptr_t data)
[4286] {
[4287]     ngx_table_elt_t  *te;
[4288] 
[4289]     te = r->headers_in.te;
[4290] 
[4291]     if (te == NULL) {
[4292]         v->not_found = 1;
[4293]         return NGX_OK;
[4294]     }
[4295] 
[4296]     if (ngx_strlcasestrn(te->value.data, te->value.data + te->value.len,
[4297]                          (u_char *) "trailers", 8 - 1)
[4298]         == NULL)
[4299]     {
[4300]         v->not_found = 1;
[4301]         return NGX_OK;
[4302]     }
[4303] 
[4304]     v->valid = 1;
[4305]     v->no_cacheable = 0;
[4306]     v->not_found = 0;
[4307] 
[4308]     v->data = (u_char *) "trailers";
[4309]     v->len = sizeof("trailers") - 1;
[4310] 
[4311]     return NGX_OK;
[4312] }
[4313] 
[4314] 
[4315] static ngx_int_t
[4316] ngx_http_grpc_add_variables(ngx_conf_t *cf)
[4317] {
[4318]     ngx_http_variable_t  *var, *v;
[4319] 
[4320]     for (v = ngx_http_grpc_vars; v->name.len; v++) {
[4321]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[4322]         if (var == NULL) {
[4323]             return NGX_ERROR;
[4324]         }
[4325] 
[4326]         var->get_handler = v->get_handler;
[4327]         var->data = v->data;
[4328]     }
[4329] 
[4330]     return NGX_OK;
[4331] }
[4332] 
[4333] 
[4334] static void *
[4335] ngx_http_grpc_create_loc_conf(ngx_conf_t *cf)
[4336] {
[4337]     ngx_http_grpc_loc_conf_t  *conf;
[4338] 
[4339]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_grpc_loc_conf_t));
[4340]     if (conf == NULL) {
[4341]         return NULL;
[4342]     }
[4343] 
[4344]     /*
[4345]      * set by ngx_pcalloc():
[4346]      *
[4347]      *     conf->upstream.ignore_headers = 0;
[4348]      *     conf->upstream.next_upstream = 0;
[4349]      *     conf->upstream.hide_headers_hash = { NULL, 0 };
[4350]      *
[4351]      *     conf->headers.lengths = NULL;
[4352]      *     conf->headers.values = NULL;
[4353]      *     conf->headers.hash = { NULL, 0 };
[4354]      *     conf->host = { 0, NULL };
[4355]      *     conf->host_set = 0;
[4356]      *     conf->ssl = 0;
[4357]      *     conf->ssl_protocols = 0;
[4358]      *     conf->ssl_ciphers = { 0, NULL };
[4359]      *     conf->ssl_trusted_certificate = { 0, NULL };
[4360]      *     conf->ssl_crl = { 0, NULL };
[4361]      */
[4362] 
[4363]     conf->upstream.local = NGX_CONF_UNSET_PTR;
[4364]     conf->upstream.socket_keepalive = NGX_CONF_UNSET;
[4365]     conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
[4366]     conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
[4367]     conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
[4368]     conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
[4369]     conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[4370] 
[4371]     conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
[4372] 
[4373]     conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
[4374]     conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
[4375] 
[4376]     conf->upstream.intercept_errors = NGX_CONF_UNSET;
[4377] 
[4378] #if (NGX_HTTP_SSL)
[4379]     conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
[4380]     conf->upstream.ssl_name = NGX_CONF_UNSET_PTR;
[4381]     conf->upstream.ssl_server_name = NGX_CONF_UNSET;
[4382]     conf->upstream.ssl_verify = NGX_CONF_UNSET;
[4383]     conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
[4384]     conf->upstream.ssl_certificate = NGX_CONF_UNSET_PTR;
[4385]     conf->upstream.ssl_certificate_key = NGX_CONF_UNSET_PTR;
[4386]     conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
[4387]     conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
[4388] #endif
[4389] 
[4390]     /* the hardcoded values */
[4391]     conf->upstream.cyclic_temp_file = 0;
[4392]     conf->upstream.buffering = 0;
[4393]     conf->upstream.ignore_client_abort = 0;
[4394]     conf->upstream.send_lowat = 0;
[4395]     conf->upstream.bufs.num = 0;
[4396]     conf->upstream.busy_buffers_size = 0;
[4397]     conf->upstream.max_temp_file_size = 0;
[4398]     conf->upstream.temp_file_write_size = 0;
[4399]     conf->upstream.pass_request_headers = 1;
[4400]     conf->upstream.pass_request_body = 1;
[4401]     conf->upstream.force_ranges = 0;
[4402]     conf->upstream.pass_trailers = 1;
[4403]     conf->upstream.preserve_output = 1;
[4404] 
[4405]     conf->headers_source = NGX_CONF_UNSET_PTR;
[4406] 
[4407]     ngx_str_set(&conf->upstream.module, "grpc");
[4408] 
[4409]     return conf;
[4410] }
[4411] 
[4412] 
[4413] static char *
[4414] ngx_http_grpc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[4415] {
[4416]     ngx_http_grpc_loc_conf_t *prev = parent;
[4417]     ngx_http_grpc_loc_conf_t *conf = child;
[4418] 
[4419]     ngx_int_t                  rc;
[4420]     ngx_hash_init_t            hash;
[4421]     ngx_http_core_loc_conf_t  *clcf;
[4422] 
[4423]     ngx_conf_merge_ptr_value(conf->upstream.local,
[4424]                               prev->upstream.local, NULL);
[4425] 
[4426]     ngx_conf_merge_value(conf->upstream.socket_keepalive,
[4427]                               prev->upstream.socket_keepalive, 0);
[4428] 
[4429]     ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
[4430]                               prev->upstream.next_upstream_tries, 0);
[4431] 
[4432]     ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
[4433]                               prev->upstream.connect_timeout, 60000);
[4434] 
[4435]     ngx_conf_merge_msec_value(conf->upstream.send_timeout,
[4436]                               prev->upstream.send_timeout, 60000);
[4437] 
[4438]     ngx_conf_merge_msec_value(conf->upstream.read_timeout,
[4439]                               prev->upstream.read_timeout, 60000);
[4440] 
[4441]     ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
[4442]                               prev->upstream.next_upstream_timeout, 0);
[4443] 
[4444]     ngx_conf_merge_size_value(conf->upstream.buffer_size,
[4445]                               prev->upstream.buffer_size,
[4446]                               (size_t) ngx_pagesize);
[4447] 
[4448]     ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
[4449]                               prev->upstream.ignore_headers,
[4450]                               NGX_CONF_BITMASK_SET);
[4451] 
[4452]     ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
[4453]                               prev->upstream.next_upstream,
[4454]                               (NGX_CONF_BITMASK_SET
[4455]                                |NGX_HTTP_UPSTREAM_FT_ERROR
[4456]                                |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
[4457] 
[4458]     if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
[4459]         conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
[4460]                                        |NGX_HTTP_UPSTREAM_FT_OFF;
[4461]     }
[4462] 
[4463]     ngx_conf_merge_value(conf->upstream.intercept_errors,
[4464]                               prev->upstream.intercept_errors, 0);
[4465] 
[4466] #if (NGX_HTTP_SSL)
[4467] 
[4468]     if (ngx_http_grpc_merge_ssl(cf, conf, prev) != NGX_OK) {
[4469]         return NGX_CONF_ERROR;
[4470]     }
[4471] 
[4472]     ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
[4473]                               prev->upstream.ssl_session_reuse, 1);
[4474] 
[4475]     ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
[4476]                                  (NGX_CONF_BITMASK_SET
[4477]                                   |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[4478]                                   |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[4479] 
[4480]     ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
[4481]                              "DEFAULT");
[4482] 
[4483]     ngx_conf_merge_ptr_value(conf->upstream.ssl_name,
[4484]                               prev->upstream.ssl_name, NULL);
[4485]     ngx_conf_merge_value(conf->upstream.ssl_server_name,
[4486]                               prev->upstream.ssl_server_name, 0);
[4487]     ngx_conf_merge_value(conf->upstream.ssl_verify,
[4488]                               prev->upstream.ssl_verify, 0);
[4489]     ngx_conf_merge_uint_value(conf->ssl_verify_depth,
[4490]                               prev->ssl_verify_depth, 1);
[4491]     ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
[4492]                               prev->ssl_trusted_certificate, "");
[4493]     ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
[4494] 
[4495]     ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate,
[4496]                               prev->upstream.ssl_certificate, NULL);
[4497]     ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
[4498]                               prev->upstream.ssl_certificate_key, NULL);
[4499]     ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords,
[4500]                               prev->upstream.ssl_passwords, NULL);
[4501] 
[4502]     ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
[4503]                               prev->ssl_conf_commands, NULL);
[4504] 
[4505]     if (conf->ssl && ngx_http_grpc_set_ssl(cf, conf) != NGX_OK) {
[4506]         return NGX_CONF_ERROR;
[4507]     }
[4508] 
[4509] #endif
[4510] 
[4511]     hash.max_size = 512;
[4512]     hash.bucket_size = ngx_align(64, ngx_cacheline_size);
[4513]     hash.name = "grpc_headers_hash";
[4514] 
[4515]     if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
[4516]             &prev->upstream, ngx_http_grpc_hide_headers, &hash)
[4517]         != NGX_OK)
[4518]     {
[4519]         return NGX_CONF_ERROR;
[4520]     }
[4521] 
[4522]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[4523] 
[4524]     if (clcf->noname
[4525]         && conf->upstream.upstream == NULL && conf->grpc_lengths == NULL)
[4526]     {
[4527]         conf->upstream.upstream = prev->upstream.upstream;
[4528]         conf->host = prev->host;
[4529] 
[4530]         conf->grpc_lengths = prev->grpc_lengths;
[4531]         conf->grpc_values = prev->grpc_values;
[4532] 
[4533] #if (NGX_HTTP_SSL)
[4534]         conf->ssl = prev->ssl;
[4535] #endif
[4536]     }
[4537] 
[4538]     if (clcf->lmt_excpt && clcf->handler == NULL
[4539]         && (conf->upstream.upstream || conf->grpc_lengths))
[4540]     {
[4541]         clcf->handler = ngx_http_grpc_handler;
[4542]     }
[4543] 
[4544]     ngx_conf_merge_ptr_value(conf->headers_source, prev->headers_source, NULL);
[4545] 
[4546]     if (conf->headers_source == prev->headers_source) {
[4547]         conf->headers = prev->headers;
[4548]         conf->host_set = prev->host_set;
[4549]     }
[4550] 
[4551]     rc = ngx_http_grpc_init_headers(cf, conf, &conf->headers,
[4552]                                     ngx_http_grpc_headers);
[4553]     if (rc != NGX_OK) {
[4554]         return NGX_CONF_ERROR;
[4555]     }
[4556] 
[4557]     /*
[4558]      * special handling to preserve conf->headers in the "http" section
[4559]      * to inherit it to all servers
[4560]      */
[4561] 
[4562]     if (prev->headers.hash.buckets == NULL
[4563]         && conf->headers_source == prev->headers_source)
[4564]     {
[4565]         prev->headers = conf->headers;
[4566]         prev->host_set = conf->host_set;
[4567]     }
[4568] 
[4569]     return NGX_CONF_OK;
[4570] }
[4571] 
[4572] 
[4573] static ngx_int_t
[4574] ngx_http_grpc_init_headers(ngx_conf_t *cf, ngx_http_grpc_loc_conf_t *conf,
[4575]     ngx_http_grpc_headers_t *headers, ngx_keyval_t *default_headers)
[4576] {
[4577]     u_char                       *p;
[4578]     size_t                        size;
[4579]     uintptr_t                    *code;
[4580]     ngx_uint_t                    i;
[4581]     ngx_array_t                   headers_names, headers_merged;
[4582]     ngx_keyval_t                 *src, *s, *h;
[4583]     ngx_hash_key_t               *hk;
[4584]     ngx_hash_init_t               hash;
[4585]     ngx_http_script_compile_t     sc;
[4586]     ngx_http_script_copy_code_t  *copy;
[4587] 
[4588]     if (headers->hash.buckets) {
[4589]         return NGX_OK;
[4590]     }
[4591] 
[4592]     if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
[4593]         != NGX_OK)
[4594]     {
[4595]         return NGX_ERROR;
[4596]     }
[4597] 
[4598]     if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
[4599]         != NGX_OK)
[4600]     {
[4601]         return NGX_ERROR;
[4602]     }
[4603] 
[4604]     headers->lengths = ngx_array_create(cf->pool, 64, 1);
[4605]     if (headers->lengths == NULL) {
[4606]         return NGX_ERROR;
[4607]     }
[4608] 
[4609]     headers->values = ngx_array_create(cf->pool, 512, 1);
[4610]     if (headers->values == NULL) {
[4611]         return NGX_ERROR;
[4612]     }
[4613] 
[4614]     if (conf->headers_source) {
[4615] 
[4616]         src = conf->headers_source->elts;
[4617]         for (i = 0; i < conf->headers_source->nelts; i++) {
[4618] 
[4619]             if (src[i].key.len == 4
[4620]                 && ngx_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
[4621]             {
[4622]                 conf->host_set = 1;
[4623]             }
[4624] 
[4625]             s = ngx_array_push(&headers_merged);
[4626]             if (s == NULL) {
[4627]                 return NGX_ERROR;
[4628]             }
[4629] 
[4630]             *s = src[i];
[4631]         }
[4632]     }
[4633] 
[4634]     h = default_headers;
[4635] 
[4636]     while (h->key.len) {
[4637] 
[4638]         src = headers_merged.elts;
[4639]         for (i = 0; i < headers_merged.nelts; i++) {
[4640]             if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
[4641]                 goto next;
[4642]             }
[4643]         }
[4644] 
[4645]         s = ngx_array_push(&headers_merged);
[4646]         if (s == NULL) {
[4647]             return NGX_ERROR;
[4648]         }
[4649] 
[4650]         *s = *h;
[4651] 
[4652]     next:
[4653] 
[4654]         h++;
[4655]     }
[4656] 
[4657] 
[4658]     src = headers_merged.elts;
[4659]     for (i = 0; i < headers_merged.nelts; i++) {
[4660] 
[4661]         hk = ngx_array_push(&headers_names);
[4662]         if (hk == NULL) {
[4663]             return NGX_ERROR;
[4664]         }
[4665] 
[4666]         hk->key = src[i].key;
[4667]         hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
[4668]         hk->value = (void *) 1;
[4669] 
[4670]         if (src[i].value.len == 0) {
[4671]             continue;
[4672]         }
[4673] 
[4674]         copy = ngx_array_push_n(headers->lengths,
[4675]                                 sizeof(ngx_http_script_copy_code_t));
[4676]         if (copy == NULL) {
[4677]             return NGX_ERROR;
[4678]         }
[4679] 
[4680]         copy->code = (ngx_http_script_code_pt) (void *)
[4681]                                                  ngx_http_script_copy_len_code;
[4682]         copy->len = src[i].key.len;
[4683] 
[4684]         size = (sizeof(ngx_http_script_copy_code_t)
[4685]                 + src[i].key.len + sizeof(uintptr_t) - 1)
[4686]                & ~(sizeof(uintptr_t) - 1);
[4687] 
[4688]         copy = ngx_array_push_n(headers->values, size);
[4689]         if (copy == NULL) {
[4690]             return NGX_ERROR;
[4691]         }
[4692] 
[4693]         copy->code = ngx_http_script_copy_code;
[4694]         copy->len = src[i].key.len;
[4695] 
[4696]         p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
[4697]         ngx_memcpy(p, src[i].key.data, src[i].key.len);
[4698] 
[4699]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[4700] 
[4701]         sc.cf = cf;
[4702]         sc.source = &src[i].value;
[4703]         sc.flushes = &headers->flushes;
[4704]         sc.lengths = &headers->lengths;
[4705]         sc.values = &headers->values;
[4706] 
[4707]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[4708]             return NGX_ERROR;
[4709]         }
[4710] 
[4711]         code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
[4712]         if (code == NULL) {
[4713]             return NGX_ERROR;
[4714]         }
[4715] 
[4716]         *code = (uintptr_t) NULL;
[4717] 
[4718]         code = ngx_array_push_n(headers->values, sizeof(uintptr_t));
[4719]         if (code == NULL) {
[4720]             return NGX_ERROR;
[4721]         }
[4722] 
[4723]         *code = (uintptr_t) NULL;
[4724]     }
[4725] 
[4726]     code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
[4727]     if (code == NULL) {
[4728]         return NGX_ERROR;
[4729]     }
[4730] 
[4731]     *code = (uintptr_t) NULL;
[4732] 
[4733] 
[4734]     hash.hash = &headers->hash;
[4735]     hash.key = ngx_hash_key_lc;
[4736]     hash.max_size = 512;
[4737]     hash.bucket_size = 64;
[4738]     hash.name = "grpc_headers_hash";
[4739]     hash.pool = cf->pool;
[4740]     hash.temp_pool = NULL;
[4741] 
[4742]     return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
[4743] }
[4744] 
[4745] 
[4746] static char *
[4747] ngx_http_grpc_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4748] {
[4749]     ngx_http_grpc_loc_conf_t *glcf = conf;
[4750] 
[4751]     size_t                      add;
[4752]     ngx_str_t                  *value, *url;
[4753]     ngx_url_t                   u;
[4754]     ngx_uint_t                  n;
[4755]     ngx_http_core_loc_conf_t   *clcf;
[4756]     ngx_http_script_compile_t   sc;
[4757] 
[4758]     if (glcf->upstream.upstream || glcf->grpc_lengths) {
[4759]         return "is duplicate";
[4760]     }
[4761] 
[4762]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[4763] 
[4764]     clcf->handler = ngx_http_grpc_handler;
[4765] 
[4766]     if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
[4767]         clcf->auto_redirect = 1;
[4768]     }
[4769] 
[4770]     value = cf->args->elts;
[4771] 
[4772]     url = &value[1];
[4773] 
[4774]     n = ngx_http_script_variables_count(url);
[4775] 
[4776]     if (n) {
[4777] 
[4778]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[4779] 
[4780]         sc.cf = cf;
[4781]         sc.source = url;
[4782]         sc.lengths = &glcf->grpc_lengths;
[4783]         sc.values = &glcf->grpc_values;
[4784]         sc.variables = n;
[4785]         sc.complete_lengths = 1;
[4786]         sc.complete_values = 1;
[4787] 
[4788]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[4789]             return NGX_CONF_ERROR;
[4790]         }
[4791] 
[4792] #if (NGX_HTTP_SSL)
[4793]         glcf->ssl = 1;
[4794] #endif
[4795] 
[4796]         return NGX_CONF_OK;
[4797]     }
[4798] 
[4799]     if (ngx_strncasecmp(url->data, (u_char *) "grpc://", 7) == 0) {
[4800]         add = 7;
[4801] 
[4802]     } else if (ngx_strncasecmp(url->data, (u_char *) "grpcs://", 8) == 0) {
[4803] 
[4804] #if (NGX_HTTP_SSL)
[4805]         glcf->ssl = 1;
[4806] 
[4807]         add = 8;
[4808] #else
[4809]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4810]                            "grpcs protocol requires SSL support");
[4811]         return NGX_CONF_ERROR;
[4812] #endif
[4813] 
[4814]     } else {
[4815]         add = 0;
[4816]     }
[4817] 
[4818]     ngx_memzero(&u, sizeof(ngx_url_t));
[4819] 
[4820]     u.url.len = url->len - add;
[4821]     u.url.data = url->data + add;
[4822]     u.no_resolve = 1;
[4823] 
[4824]     glcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
[4825]     if (glcf->upstream.upstream == NULL) {
[4826]         return NGX_CONF_ERROR;
[4827]     }
[4828] 
[4829]     if (u.family != AF_UNIX) {
[4830] 
[4831]         if (u.no_port) {
[4832]             glcf->host = u.host;
[4833] 
[4834]         } else {
[4835]             glcf->host.len = u.host.len + 1 + u.port_text.len;
[4836]             glcf->host.data = u.host.data;
[4837]         }
[4838] 
[4839]     } else {
[4840]         ngx_str_set(&glcf->host, "localhost");
[4841]     }
[4842] 
[4843]     return NGX_CONF_OK;
[4844] }
[4845] 
[4846] 
[4847] #if (NGX_HTTP_SSL)
[4848] 
[4849] static char *
[4850] ngx_http_grpc_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4851] {
[4852]     ngx_http_grpc_loc_conf_t *glcf = conf;
[4853] 
[4854]     ngx_str_t  *value;
[4855] 
[4856]     if (glcf->upstream.ssl_passwords != NGX_CONF_UNSET_PTR) {
[4857]         return "is duplicate";
[4858]     }
[4859] 
[4860]     value = cf->args->elts;
[4861] 
[4862]     glcf->upstream.ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);
[4863] 
[4864]     if (glcf->upstream.ssl_passwords == NULL) {
[4865]         return NGX_CONF_ERROR;
[4866]     }
[4867] 
[4868]     return NGX_CONF_OK;
[4869] }
[4870] 
[4871] 
[4872] static char *
[4873] ngx_http_grpc_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[4874] {
[4875] #ifndef SSL_CONF_FLAG_FILE
[4876]     return "is not supported on this platform";
[4877] #else
[4878]     return NGX_CONF_OK;
[4879] #endif
[4880] }
[4881] 
[4882] 
[4883] static ngx_int_t
[4884] ngx_http_grpc_merge_ssl(ngx_conf_t *cf, ngx_http_grpc_loc_conf_t *conf,
[4885]     ngx_http_grpc_loc_conf_t *prev)
[4886] {
[4887]     ngx_uint_t  preserve;
[4888] 
[4889]     if (conf->ssl_protocols == 0
[4890]         && conf->ssl_ciphers.data == NULL
[4891]         && conf->upstream.ssl_certificate == NGX_CONF_UNSET_PTR
[4892]         && conf->upstream.ssl_certificate_key == NGX_CONF_UNSET_PTR
[4893]         && conf->upstream.ssl_passwords == NGX_CONF_UNSET_PTR
[4894]         && conf->upstream.ssl_verify == NGX_CONF_UNSET
[4895]         && conf->ssl_verify_depth == NGX_CONF_UNSET_UINT
[4896]         && conf->ssl_trusted_certificate.data == NULL
[4897]         && conf->ssl_crl.data == NULL
[4898]         && conf->upstream.ssl_session_reuse == NGX_CONF_UNSET
[4899]         && conf->ssl_conf_commands == NGX_CONF_UNSET_PTR)
[4900]     {
[4901]         if (prev->upstream.ssl) {
[4902]             conf->upstream.ssl = prev->upstream.ssl;
[4903]             return NGX_OK;
[4904]         }
[4905] 
[4906]         preserve = 1;
[4907] 
[4908]     } else {
[4909]         preserve = 0;
[4910]     }
[4911] 
[4912]     conf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
[4913]     if (conf->upstream.ssl == NULL) {
[4914]         return NGX_ERROR;
[4915]     }
[4916] 
[4917]     conf->upstream.ssl->log = cf->log;
[4918] 
[4919]     /*
[4920]      * special handling to preserve conf->upstream.ssl
[4921]      * in the "http" section to inherit it to all servers
[4922]      */
[4923] 
[4924]     if (preserve) {
[4925]         prev->upstream.ssl = conf->upstream.ssl;
[4926]     }
[4927] 
[4928]     return NGX_OK;
[4929] }
[4930] 
[4931] 
[4932] static ngx_int_t
[4933] ngx_http_grpc_set_ssl(ngx_conf_t *cf, ngx_http_grpc_loc_conf_t *glcf)
[4934] {
[4935]     ngx_pool_cleanup_t  *cln;
[4936] 
[4937]     if (glcf->upstream.ssl->ctx) {
[4938]         return NGX_OK;
[4939]     }
[4940] 
[4941]     if (ngx_ssl_create(glcf->upstream.ssl, glcf->ssl_protocols, NULL)
[4942]         != NGX_OK)
[4943]     {
[4944]         return NGX_ERROR;
[4945]     }
[4946] 
[4947]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[4948]     if (cln == NULL) {
[4949]         ngx_ssl_cleanup_ctx(glcf->upstream.ssl);
[4950]         return NGX_ERROR;
[4951]     }
[4952] 
[4953]     cln->handler = ngx_ssl_cleanup_ctx;
[4954]     cln->data = glcf->upstream.ssl;
[4955] 
[4956]     if (ngx_ssl_ciphers(cf, glcf->upstream.ssl, &glcf->ssl_ciphers, 0)
[4957]         != NGX_OK)
[4958]     {
[4959]         return NGX_ERROR;
[4960]     }
[4961] 
[4962]     if (glcf->upstream.ssl_certificate
[4963]         && glcf->upstream.ssl_certificate->value.len)
[4964]     {
[4965]         if (glcf->upstream.ssl_certificate_key == NULL) {
[4966]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[4967]                           "no \"grpc_ssl_certificate_key\" is defined "
[4968]                           "for certificate \"%V\"",
[4969]                           &glcf->upstream.ssl_certificate->value);
[4970]             return NGX_ERROR;
[4971]         }
[4972] 
[4973]         if (glcf->upstream.ssl_certificate->lengths
[4974]             || glcf->upstream.ssl_certificate_key->lengths)
[4975]         {
[4976]             glcf->upstream.ssl_passwords =
[4977]                   ngx_ssl_preserve_passwords(cf, glcf->upstream.ssl_passwords);
[4978]             if (glcf->upstream.ssl_passwords == NULL) {
[4979]                 return NGX_ERROR;
[4980]             }
[4981] 
[4982]         } else {
[4983]             if (ngx_ssl_certificate(cf, glcf->upstream.ssl,
[4984]                                     &glcf->upstream.ssl_certificate->value,
[4985]                                     &glcf->upstream.ssl_certificate_key->value,
[4986]                                     glcf->upstream.ssl_passwords)
[4987]                 != NGX_OK)
[4988]             {
[4989]                 return NGX_ERROR;
[4990]             }
[4991]         }
[4992]     }
[4993] 
[4994]     if (glcf->upstream.ssl_verify) {
[4995]         if (glcf->ssl_trusted_certificate.len == 0) {
[4996]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[4997]                       "no grpc_ssl_trusted_certificate for grpc_ssl_verify");
[4998]             return NGX_ERROR;
[4999]         }
[5000] 
[5001]         if (ngx_ssl_trusted_certificate(cf, glcf->upstream.ssl,
[5002]                                         &glcf->ssl_trusted_certificate,
[5003]                                         glcf->ssl_verify_depth)
[5004]             != NGX_OK)
[5005]         {
[5006]             return NGX_ERROR;
[5007]         }
[5008] 
[5009]         if (ngx_ssl_crl(cf, glcf->upstream.ssl, &glcf->ssl_crl) != NGX_OK) {
[5010]             return NGX_ERROR;
[5011]         }
[5012]     }
[5013] 
[5014]     if (ngx_ssl_client_session_cache(cf, glcf->upstream.ssl,
[5015]                                      glcf->upstream.ssl_session_reuse)
[5016]         != NGX_OK)
[5017]     {
[5018]         return NGX_ERROR;
[5019]     }
[5020] 
[5021] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[5022] 
[5023]     if (SSL_CTX_set_alpn_protos(glcf->upstream.ssl->ctx,
[5024]                                 (u_char *) "\x02h2", 3)
[5025]         != 0)
[5026]     {
[5027]         ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
[5028]                       "SSL_CTX_set_alpn_protos() failed");
[5029]         return NGX_ERROR;
[5030]     }
[5031] 
[5032] #endif
[5033] 
[5034]     if (ngx_ssl_conf_commands(cf, glcf->upstream.ssl, glcf->ssl_conf_commands)
[5035]         != NGX_OK)
[5036]     {
[5037]         return NGX_ERROR;
[5038]     }
[5039] 
[5040]     return NGX_OK;
[5041] }
[5042] 
[5043] #endif
