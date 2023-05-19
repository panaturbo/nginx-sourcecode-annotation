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
[13] typedef struct {
[14]     ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
[15] } ngx_http_fastcgi_main_conf_t;
[16] 
[17] 
[18] typedef struct {
[19]     ngx_array_t                   *flushes;
[20]     ngx_array_t                   *lengths;
[21]     ngx_array_t                   *values;
[22]     ngx_uint_t                     number;
[23]     ngx_hash_t                     hash;
[24] } ngx_http_fastcgi_params_t;
[25] 
[26] 
[27] typedef struct {
[28]     ngx_http_upstream_conf_t       upstream;
[29] 
[30]     ngx_str_t                      index;
[31] 
[32]     ngx_http_fastcgi_params_t      params;
[33] #if (NGX_HTTP_CACHE)
[34]     ngx_http_fastcgi_params_t      params_cache;
[35] #endif
[36] 
[37]     ngx_array_t                   *params_source;
[38]     ngx_array_t                   *catch_stderr;
[39] 
[40]     ngx_array_t                   *fastcgi_lengths;
[41]     ngx_array_t                   *fastcgi_values;
[42] 
[43]     ngx_flag_t                     keep_conn;
[44] 
[45] #if (NGX_HTTP_CACHE)
[46]     ngx_http_complex_value_t       cache_key;
[47] #endif
[48] 
[49] #if (NGX_PCRE)
[50]     ngx_regex_t                   *split_regex;
[51]     ngx_str_t                      split_name;
[52] #endif
[53] } ngx_http_fastcgi_loc_conf_t;
[54] 
[55] 
[56] typedef enum {
[57]     ngx_http_fastcgi_st_version = 0,
[58]     ngx_http_fastcgi_st_type,
[59]     ngx_http_fastcgi_st_request_id_hi,
[60]     ngx_http_fastcgi_st_request_id_lo,
[61]     ngx_http_fastcgi_st_content_length_hi,
[62]     ngx_http_fastcgi_st_content_length_lo,
[63]     ngx_http_fastcgi_st_padding_length,
[64]     ngx_http_fastcgi_st_reserved,
[65]     ngx_http_fastcgi_st_data,
[66]     ngx_http_fastcgi_st_padding
[67] } ngx_http_fastcgi_state_e;
[68] 
[69] 
[70] typedef struct {
[71]     u_char                        *start;
[72]     u_char                        *end;
[73] } ngx_http_fastcgi_split_part_t;
[74] 
[75] 
[76] typedef struct {
[77]     ngx_http_fastcgi_state_e       state;
[78]     u_char                        *pos;
[79]     u_char                        *last;
[80]     ngx_uint_t                     type;
[81]     size_t                         length;
[82]     size_t                         padding;
[83] 
[84]     off_t                          rest;
[85] 
[86]     ngx_chain_t                   *free;
[87]     ngx_chain_t                   *busy;
[88] 
[89]     unsigned                       fastcgi_stdout:1;
[90]     unsigned                       large_stderr:1;
[91]     unsigned                       header_sent:1;
[92]     unsigned                       closed:1;
[93] 
[94]     ngx_array_t                   *split_parts;
[95] 
[96]     ngx_str_t                      script_name;
[97]     ngx_str_t                      path_info;
[98] } ngx_http_fastcgi_ctx_t;
[99] 
[100] 
[101] #define NGX_HTTP_FASTCGI_RESPONDER      1
[102] 
[103] #define NGX_HTTP_FASTCGI_KEEP_CONN      1
[104] 
[105] #define NGX_HTTP_FASTCGI_BEGIN_REQUEST  1
[106] #define NGX_HTTP_FASTCGI_ABORT_REQUEST  2
[107] #define NGX_HTTP_FASTCGI_END_REQUEST    3
[108] #define NGX_HTTP_FASTCGI_PARAMS         4
[109] #define NGX_HTTP_FASTCGI_STDIN          5
[110] #define NGX_HTTP_FASTCGI_STDOUT         6
[111] #define NGX_HTTP_FASTCGI_STDERR         7
[112] #define NGX_HTTP_FASTCGI_DATA           8
[113] 
[114] 
[115] typedef struct {
[116]     u_char  version;
[117]     u_char  type;
[118]     u_char  request_id_hi;
[119]     u_char  request_id_lo;
[120]     u_char  content_length_hi;
[121]     u_char  content_length_lo;
[122]     u_char  padding_length;
[123]     u_char  reserved;
[124] } ngx_http_fastcgi_header_t;
[125] 
[126] 
[127] typedef struct {
[128]     u_char  role_hi;
[129]     u_char  role_lo;
[130]     u_char  flags;
[131]     u_char  reserved[5];
[132] } ngx_http_fastcgi_begin_request_t;
[133] 
[134] 
[135] typedef struct {
[136]     u_char  version;
[137]     u_char  type;
[138]     u_char  request_id_hi;
[139]     u_char  request_id_lo;
[140] } ngx_http_fastcgi_header_small_t;
[141] 
[142] 
[143] typedef struct {
[144]     ngx_http_fastcgi_header_t         h0;
[145]     ngx_http_fastcgi_begin_request_t  br;
[146]     ngx_http_fastcgi_header_small_t   h1;
[147] } ngx_http_fastcgi_request_start_t;
[148] 
[149] 
[150] static ngx_int_t ngx_http_fastcgi_eval(ngx_http_request_t *r,
[151]     ngx_http_fastcgi_loc_conf_t *flcf);
[152] #if (NGX_HTTP_CACHE)
[153] static ngx_int_t ngx_http_fastcgi_create_key(ngx_http_request_t *r);
[154] #endif
[155] static ngx_int_t ngx_http_fastcgi_create_request(ngx_http_request_t *r);
[156] static ngx_int_t ngx_http_fastcgi_reinit_request(ngx_http_request_t *r);
[157] static ngx_int_t ngx_http_fastcgi_body_output_filter(void *data,
[158]     ngx_chain_t *in);
[159] static ngx_int_t ngx_http_fastcgi_process_header(ngx_http_request_t *r);
[160] static ngx_int_t ngx_http_fastcgi_input_filter_init(void *data);
[161] static ngx_int_t ngx_http_fastcgi_input_filter(ngx_event_pipe_t *p,
[162]     ngx_buf_t *buf);
[163] static ngx_int_t ngx_http_fastcgi_non_buffered_filter(void *data,
[164]     ssize_t bytes);
[165] static ngx_int_t ngx_http_fastcgi_process_record(ngx_http_request_t *r,
[166]     ngx_http_fastcgi_ctx_t *f);
[167] static void ngx_http_fastcgi_abort_request(ngx_http_request_t *r);
[168] static void ngx_http_fastcgi_finalize_request(ngx_http_request_t *r,
[169]     ngx_int_t rc);
[170] 
[171] static ngx_int_t ngx_http_fastcgi_add_variables(ngx_conf_t *cf);
[172] static void *ngx_http_fastcgi_create_main_conf(ngx_conf_t *cf);
[173] static void *ngx_http_fastcgi_create_loc_conf(ngx_conf_t *cf);
[174] static char *ngx_http_fastcgi_merge_loc_conf(ngx_conf_t *cf,
[175]     void *parent, void *child);
[176] static ngx_int_t ngx_http_fastcgi_init_params(ngx_conf_t *cf,
[177]     ngx_http_fastcgi_loc_conf_t *conf, ngx_http_fastcgi_params_t *params,
[178]     ngx_keyval_t *default_params);
[179] 
[180] static ngx_int_t ngx_http_fastcgi_script_name_variable(ngx_http_request_t *r,
[181]     ngx_http_variable_value_t *v, uintptr_t data);
[182] static ngx_int_t ngx_http_fastcgi_path_info_variable(ngx_http_request_t *r,
[183]     ngx_http_variable_value_t *v, uintptr_t data);
[184] static ngx_http_fastcgi_ctx_t *ngx_http_fastcgi_split(ngx_http_request_t *r,
[185]     ngx_http_fastcgi_loc_conf_t *flcf);
[186] 
[187] static char *ngx_http_fastcgi_pass(ngx_conf_t *cf, ngx_command_t *cmd,
[188]     void *conf);
[189] static char *ngx_http_fastcgi_split_path_info(ngx_conf_t *cf,
[190]     ngx_command_t *cmd, void *conf);
[191] static char *ngx_http_fastcgi_store(ngx_conf_t *cf, ngx_command_t *cmd,
[192]     void *conf);
[193] #if (NGX_HTTP_CACHE)
[194] static char *ngx_http_fastcgi_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[195]     void *conf);
[196] static char *ngx_http_fastcgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
[197]     void *conf);
[198] #endif
[199] 
[200] static char *ngx_http_fastcgi_lowat_check(ngx_conf_t *cf, void *post,
[201]     void *data);
[202] 
[203] 
[204] static ngx_conf_post_t  ngx_http_fastcgi_lowat_post =
[205]     { ngx_http_fastcgi_lowat_check };
[206] 
[207] 
[208] static ngx_conf_bitmask_t  ngx_http_fastcgi_next_upstream_masks[] = {
[209]     { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
[210]     { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
[211]     { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
[212]     { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
[213]     { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
[214]     { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
[215]     { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
[216]     { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[217]     { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
[218]     { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
[219]     { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
[220]     { ngx_null_string, 0 }
[221] };
[222] 
[223] 
[224] ngx_module_t  ngx_http_fastcgi_module;
[225] 
[226] 
[227] static ngx_command_t  ngx_http_fastcgi_commands[] = {
[228] 
[229]     { ngx_string("fastcgi_pass"),
[230]       NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[231]       ngx_http_fastcgi_pass,
[232]       NGX_HTTP_LOC_CONF_OFFSET,
[233]       0,
[234]       NULL },
[235] 
[236]     { ngx_string("fastcgi_index"),
[237]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[238]       ngx_conf_set_str_slot,
[239]       NGX_HTTP_LOC_CONF_OFFSET,
[240]       offsetof(ngx_http_fastcgi_loc_conf_t, index),
[241]       NULL },
[242] 
[243]     { ngx_string("fastcgi_split_path_info"),
[244]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[245]       ngx_http_fastcgi_split_path_info,
[246]       NGX_HTTP_LOC_CONF_OFFSET,
[247]       0,
[248]       NULL },
[249] 
[250]     { ngx_string("fastcgi_store"),
[251]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[252]       ngx_http_fastcgi_store,
[253]       NGX_HTTP_LOC_CONF_OFFSET,
[254]       0,
[255]       NULL },
[256] 
[257]     { ngx_string("fastcgi_store_access"),
[258]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[259]       ngx_conf_set_access_slot,
[260]       NGX_HTTP_LOC_CONF_OFFSET,
[261]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.store_access),
[262]       NULL },
[263] 
[264]     { ngx_string("fastcgi_buffering"),
[265]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[266]       ngx_conf_set_flag_slot,
[267]       NGX_HTTP_LOC_CONF_OFFSET,
[268]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.buffering),
[269]       NULL },
[270] 
[271]     { ngx_string("fastcgi_request_buffering"),
[272]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[273]       ngx_conf_set_flag_slot,
[274]       NGX_HTTP_LOC_CONF_OFFSET,
[275]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.request_buffering),
[276]       NULL },
[277] 
[278]     { ngx_string("fastcgi_ignore_client_abort"),
[279]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[280]       ngx_conf_set_flag_slot,
[281]       NGX_HTTP_LOC_CONF_OFFSET,
[282]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.ignore_client_abort),
[283]       NULL },
[284] 
[285]     { ngx_string("fastcgi_bind"),
[286]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[287]       ngx_http_upstream_bind_set_slot,
[288]       NGX_HTTP_LOC_CONF_OFFSET,
[289]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.local),
[290]       NULL },
[291] 
[292]     { ngx_string("fastcgi_socket_keepalive"),
[293]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[294]       ngx_conf_set_flag_slot,
[295]       NGX_HTTP_LOC_CONF_OFFSET,
[296]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.socket_keepalive),
[297]       NULL },
[298] 
[299]     { ngx_string("fastcgi_connect_timeout"),
[300]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[301]       ngx_conf_set_msec_slot,
[302]       NGX_HTTP_LOC_CONF_OFFSET,
[303]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.connect_timeout),
[304]       NULL },
[305] 
[306]     { ngx_string("fastcgi_send_timeout"),
[307]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[308]       ngx_conf_set_msec_slot,
[309]       NGX_HTTP_LOC_CONF_OFFSET,
[310]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.send_timeout),
[311]       NULL },
[312] 
[313]     { ngx_string("fastcgi_send_lowat"),
[314]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[315]       ngx_conf_set_size_slot,
[316]       NGX_HTTP_LOC_CONF_OFFSET,
[317]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.send_lowat),
[318]       &ngx_http_fastcgi_lowat_post },
[319] 
[320]     { ngx_string("fastcgi_buffer_size"),
[321]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[322]       ngx_conf_set_size_slot,
[323]       NGX_HTTP_LOC_CONF_OFFSET,
[324]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.buffer_size),
[325]       NULL },
[326] 
[327]     { ngx_string("fastcgi_pass_request_headers"),
[328]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[329]       ngx_conf_set_flag_slot,
[330]       NGX_HTTP_LOC_CONF_OFFSET,
[331]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.pass_request_headers),
[332]       NULL },
[333] 
[334]     { ngx_string("fastcgi_pass_request_body"),
[335]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[336]       ngx_conf_set_flag_slot,
[337]       NGX_HTTP_LOC_CONF_OFFSET,
[338]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.pass_request_body),
[339]       NULL },
[340] 
[341]     { ngx_string("fastcgi_intercept_errors"),
[342]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[343]       ngx_conf_set_flag_slot,
[344]       NGX_HTTP_LOC_CONF_OFFSET,
[345]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.intercept_errors),
[346]       NULL },
[347] 
[348]     { ngx_string("fastcgi_read_timeout"),
[349]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[350]       ngx_conf_set_msec_slot,
[351]       NGX_HTTP_LOC_CONF_OFFSET,
[352]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.read_timeout),
[353]       NULL },
[354] 
[355]     { ngx_string("fastcgi_buffers"),
[356]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[357]       ngx_conf_set_bufs_slot,
[358]       NGX_HTTP_LOC_CONF_OFFSET,
[359]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.bufs),
[360]       NULL },
[361] 
[362]     { ngx_string("fastcgi_busy_buffers_size"),
[363]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[364]       ngx_conf_set_size_slot,
[365]       NGX_HTTP_LOC_CONF_OFFSET,
[366]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.busy_buffers_size_conf),
[367]       NULL },
[368] 
[369]     { ngx_string("fastcgi_force_ranges"),
[370]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[371]       ngx_conf_set_flag_slot,
[372]       NGX_HTTP_LOC_CONF_OFFSET,
[373]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.force_ranges),
[374]       NULL },
[375] 
[376]     { ngx_string("fastcgi_limit_rate"),
[377]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[378]       ngx_conf_set_size_slot,
[379]       NGX_HTTP_LOC_CONF_OFFSET,
[380]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.limit_rate),
[381]       NULL },
[382] 
[383] #if (NGX_HTTP_CACHE)
[384] 
[385]     { ngx_string("fastcgi_cache"),
[386]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[387]       ngx_http_fastcgi_cache,
[388]       NGX_HTTP_LOC_CONF_OFFSET,
[389]       0,
[390]       NULL },
[391] 
[392]     { ngx_string("fastcgi_cache_key"),
[393]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[394]       ngx_http_fastcgi_cache_key,
[395]       NGX_HTTP_LOC_CONF_OFFSET,
[396]       0,
[397]       NULL },
[398] 
[399]     { ngx_string("fastcgi_cache_path"),
[400]       NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
[401]       ngx_http_file_cache_set_slot,
[402]       NGX_HTTP_MAIN_CONF_OFFSET,
[403]       offsetof(ngx_http_fastcgi_main_conf_t, caches),
[404]       &ngx_http_fastcgi_module },
[405] 
[406]     { ngx_string("fastcgi_cache_bypass"),
[407]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[408]       ngx_http_set_predicate_slot,
[409]       NGX_HTTP_LOC_CONF_OFFSET,
[410]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_bypass),
[411]       NULL },
[412] 
[413]     { ngx_string("fastcgi_no_cache"),
[414]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[415]       ngx_http_set_predicate_slot,
[416]       NGX_HTTP_LOC_CONF_OFFSET,
[417]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.no_cache),
[418]       NULL },
[419] 
[420]     { ngx_string("fastcgi_cache_valid"),
[421]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[422]       ngx_http_file_cache_valid_set_slot,
[423]       NGX_HTTP_LOC_CONF_OFFSET,
[424]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_valid),
[425]       NULL },
[426] 
[427]     { ngx_string("fastcgi_cache_min_uses"),
[428]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[429]       ngx_conf_set_num_slot,
[430]       NGX_HTTP_LOC_CONF_OFFSET,
[431]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_min_uses),
[432]       NULL },
[433] 
[434]     { ngx_string("fastcgi_cache_max_range_offset"),
[435]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[436]       ngx_conf_set_off_slot,
[437]       NGX_HTTP_LOC_CONF_OFFSET,
[438]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_max_range_offset),
[439]       NULL },
[440] 
[441]     { ngx_string("fastcgi_cache_use_stale"),
[442]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[443]       ngx_conf_set_bitmask_slot,
[444]       NGX_HTTP_LOC_CONF_OFFSET,
[445]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_use_stale),
[446]       &ngx_http_fastcgi_next_upstream_masks },
[447] 
[448]     { ngx_string("fastcgi_cache_methods"),
[449]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[450]       ngx_conf_set_bitmask_slot,
[451]       NGX_HTTP_LOC_CONF_OFFSET,
[452]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_methods),
[453]       &ngx_http_upstream_cache_method_mask },
[454] 
[455]     { ngx_string("fastcgi_cache_lock"),
[456]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[457]       ngx_conf_set_flag_slot,
[458]       NGX_HTTP_LOC_CONF_OFFSET,
[459]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_lock),
[460]       NULL },
[461] 
[462]     { ngx_string("fastcgi_cache_lock_timeout"),
[463]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[464]       ngx_conf_set_msec_slot,
[465]       NGX_HTTP_LOC_CONF_OFFSET,
[466]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_lock_timeout),
[467]       NULL },
[468] 
[469]     { ngx_string("fastcgi_cache_lock_age"),
[470]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[471]       ngx_conf_set_msec_slot,
[472]       NGX_HTTP_LOC_CONF_OFFSET,
[473]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_lock_age),
[474]       NULL },
[475] 
[476]     { ngx_string("fastcgi_cache_revalidate"),
[477]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[478]       ngx_conf_set_flag_slot,
[479]       NGX_HTTP_LOC_CONF_OFFSET,
[480]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_revalidate),
[481]       NULL },
[482] 
[483]     { ngx_string("fastcgi_cache_background_update"),
[484]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[485]       ngx_conf_set_flag_slot,
[486]       NGX_HTTP_LOC_CONF_OFFSET,
[487]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.cache_background_update),
[488]       NULL },
[489] 
[490] #endif
[491] 
[492]     { ngx_string("fastcgi_temp_path"),
[493]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[494]       ngx_conf_set_path_slot,
[495]       NGX_HTTP_LOC_CONF_OFFSET,
[496]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.temp_path),
[497]       NULL },
[498] 
[499]     { ngx_string("fastcgi_max_temp_file_size"),
[500]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[501]       ngx_conf_set_size_slot,
[502]       NGX_HTTP_LOC_CONF_OFFSET,
[503]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.max_temp_file_size_conf),
[504]       NULL },
[505] 
[506]     { ngx_string("fastcgi_temp_file_write_size"),
[507]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[508]       ngx_conf_set_size_slot,
[509]       NGX_HTTP_LOC_CONF_OFFSET,
[510]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.temp_file_write_size_conf),
[511]       NULL },
[512] 
[513]     { ngx_string("fastcgi_next_upstream"),
[514]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[515]       ngx_conf_set_bitmask_slot,
[516]       NGX_HTTP_LOC_CONF_OFFSET,
[517]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream),
[518]       &ngx_http_fastcgi_next_upstream_masks },
[519] 
[520]     { ngx_string("fastcgi_next_upstream_tries"),
[521]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[522]       ngx_conf_set_num_slot,
[523]       NGX_HTTP_LOC_CONF_OFFSET,
[524]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream_tries),
[525]       NULL },
[526] 
[527]     { ngx_string("fastcgi_next_upstream_timeout"),
[528]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[529]       ngx_conf_set_msec_slot,
[530]       NGX_HTTP_LOC_CONF_OFFSET,
[531]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.next_upstream_timeout),
[532]       NULL },
[533] 
[534]     { ngx_string("fastcgi_param"),
[535]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
[536]       ngx_http_upstream_param_set_slot,
[537]       NGX_HTTP_LOC_CONF_OFFSET,
[538]       offsetof(ngx_http_fastcgi_loc_conf_t, params_source),
[539]       NULL },
[540] 
[541]     { ngx_string("fastcgi_pass_header"),
[542]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[543]       ngx_conf_set_str_array_slot,
[544]       NGX_HTTP_LOC_CONF_OFFSET,
[545]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.pass_headers),
[546]       NULL },
[547] 
[548]     { ngx_string("fastcgi_hide_header"),
[549]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[550]       ngx_conf_set_str_array_slot,
[551]       NGX_HTTP_LOC_CONF_OFFSET,
[552]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.hide_headers),
[553]       NULL },
[554] 
[555]     { ngx_string("fastcgi_ignore_headers"),
[556]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[557]       ngx_conf_set_bitmask_slot,
[558]       NGX_HTTP_LOC_CONF_OFFSET,
[559]       offsetof(ngx_http_fastcgi_loc_conf_t, upstream.ignore_headers),
[560]       &ngx_http_upstream_ignore_headers_masks },
[561] 
[562]     { ngx_string("fastcgi_catch_stderr"),
[563]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[564]       ngx_conf_set_str_array_slot,
[565]       NGX_HTTP_LOC_CONF_OFFSET,
[566]       offsetof(ngx_http_fastcgi_loc_conf_t, catch_stderr),
[567]       NULL },
[568] 
[569]     { ngx_string("fastcgi_keep_conn"),
[570]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[571]       ngx_conf_set_flag_slot,
[572]       NGX_HTTP_LOC_CONF_OFFSET,
[573]       offsetof(ngx_http_fastcgi_loc_conf_t, keep_conn),
[574]       NULL },
[575] 
[576]       ngx_null_command
[577] };
[578] 
[579] 
[580] static ngx_http_module_t  ngx_http_fastcgi_module_ctx = {
[581]     ngx_http_fastcgi_add_variables,        /* preconfiguration */
[582]     NULL,                                  /* postconfiguration */
[583] 
[584]     ngx_http_fastcgi_create_main_conf,     /* create main configuration */
[585]     NULL,                                  /* init main configuration */
[586] 
[587]     NULL,                                  /* create server configuration */
[588]     NULL,                                  /* merge server configuration */
[589] 
[590]     ngx_http_fastcgi_create_loc_conf,      /* create location configuration */
[591]     ngx_http_fastcgi_merge_loc_conf        /* merge location configuration */
[592] };
[593] 
[594] 
[595] ngx_module_t  ngx_http_fastcgi_module = {
[596]     NGX_MODULE_V1,
[597]     &ngx_http_fastcgi_module_ctx,          /* module context */
[598]     ngx_http_fastcgi_commands,             /* module directives */
[599]     NGX_HTTP_MODULE,                       /* module type */
[600]     NULL,                                  /* init master */
[601]     NULL,                                  /* init module */
[602]     NULL,                                  /* init process */
[603]     NULL,                                  /* init thread */
[604]     NULL,                                  /* exit thread */
[605]     NULL,                                  /* exit process */
[606]     NULL,                                  /* exit master */
[607]     NGX_MODULE_V1_PADDING
[608] };
[609] 
[610] 
[611] static ngx_http_fastcgi_request_start_t  ngx_http_fastcgi_request_start = {
[612]     { 1,                                               /* version */
[613]       NGX_HTTP_FASTCGI_BEGIN_REQUEST,                  /* type */
[614]       0,                                               /* request_id_hi */
[615]       1,                                               /* request_id_lo */
[616]       0,                                               /* content_length_hi */
[617]       sizeof(ngx_http_fastcgi_begin_request_t),        /* content_length_lo */
[618]       0,                                               /* padding_length */
[619]       0 },                                             /* reserved */
[620] 
[621]     { 0,                                               /* role_hi */
[622]       NGX_HTTP_FASTCGI_RESPONDER,                      /* role_lo */
[623]       0, /* NGX_HTTP_FASTCGI_KEEP_CONN */              /* flags */
[624]       { 0, 0, 0, 0, 0 } },                             /* reserved[5] */
[625] 
[626]     { 1,                                               /* version */
[627]       NGX_HTTP_FASTCGI_PARAMS,                         /* type */
[628]       0,                                               /* request_id_hi */
[629]       1 },                                             /* request_id_lo */
[630] 
[631] };
[632] 
[633] 
[634] static ngx_http_variable_t  ngx_http_fastcgi_vars[] = {
[635] 
[636]     { ngx_string("fastcgi_script_name"), NULL,
[637]       ngx_http_fastcgi_script_name_variable, 0,
[638]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[639] 
[640]     { ngx_string("fastcgi_path_info"), NULL,
[641]       ngx_http_fastcgi_path_info_variable, 0,
[642]       NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },
[643] 
[644]       ngx_http_null_variable
[645] };
[646] 
[647] 
[648] static ngx_str_t  ngx_http_fastcgi_hide_headers[] = {
[649]     ngx_string("Status"),
[650]     ngx_string("X-Accel-Expires"),
[651]     ngx_string("X-Accel-Redirect"),
[652]     ngx_string("X-Accel-Limit-Rate"),
[653]     ngx_string("X-Accel-Buffering"),
[654]     ngx_string("X-Accel-Charset"),
[655]     ngx_null_string
[656] };
[657] 
[658] 
[659] #if (NGX_HTTP_CACHE)
[660] 
[661] static ngx_keyval_t  ngx_http_fastcgi_cache_headers[] = {
[662]     { ngx_string("HTTP_IF_MODIFIED_SINCE"),
[663]       ngx_string("$upstream_cache_last_modified") },
[664]     { ngx_string("HTTP_IF_UNMODIFIED_SINCE"), ngx_string("") },
[665]     { ngx_string("HTTP_IF_NONE_MATCH"), ngx_string("$upstream_cache_etag") },
[666]     { ngx_string("HTTP_IF_MATCH"), ngx_string("") },
[667]     { ngx_string("HTTP_RANGE"), ngx_string("") },
[668]     { ngx_string("HTTP_IF_RANGE"), ngx_string("") },
[669]     { ngx_null_string, ngx_null_string }
[670] };
[671] 
[672] #endif
[673] 
[674] 
[675] static ngx_path_init_t  ngx_http_fastcgi_temp_path = {
[676]     ngx_string(NGX_HTTP_FASTCGI_TEMP_PATH), { 1, 2, 0 }
[677] };
[678] 
[679] 
[680] static ngx_int_t
[681] ngx_http_fastcgi_handler(ngx_http_request_t *r)
[682] {
[683]     ngx_int_t                      rc;
[684]     ngx_http_upstream_t           *u;
[685]     ngx_http_fastcgi_ctx_t        *f;
[686]     ngx_http_fastcgi_loc_conf_t   *flcf;
[687] #if (NGX_HTTP_CACHE)
[688]     ngx_http_fastcgi_main_conf_t  *fmcf;
[689] #endif
[690] 
[691]     if (ngx_http_upstream_create(r) != NGX_OK) {
[692]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[693]     }
[694] 
[695]     f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t));
[696]     if (f == NULL) {
[697]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[698]     }
[699] 
[700]     ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);
[701] 
[702]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[703] 
[704]     if (flcf->fastcgi_lengths) {
[705]         if (ngx_http_fastcgi_eval(r, flcf) != NGX_OK) {
[706]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[707]         }
[708]     }
[709] 
[710]     u = r->upstream;
[711] 
[712]     ngx_str_set(&u->schema, "fastcgi://");
[713]     u->output.tag = (ngx_buf_tag_t) &ngx_http_fastcgi_module;
[714] 
[715]     u->conf = &flcf->upstream;
[716] 
[717] #if (NGX_HTTP_CACHE)
[718]     fmcf = ngx_http_get_module_main_conf(r, ngx_http_fastcgi_module);
[719] 
[720]     u->caches = &fmcf->caches;
[721]     u->create_key = ngx_http_fastcgi_create_key;
[722] #endif
[723] 
[724]     u->create_request = ngx_http_fastcgi_create_request;
[725]     u->reinit_request = ngx_http_fastcgi_reinit_request;
[726]     u->process_header = ngx_http_fastcgi_process_header;
[727]     u->abort_request = ngx_http_fastcgi_abort_request;
[728]     u->finalize_request = ngx_http_fastcgi_finalize_request;
[729]     r->state = 0;
[730] 
[731]     u->buffering = flcf->upstream.buffering;
[732] 
[733]     u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
[734]     if (u->pipe == NULL) {
[735]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[736]     }
[737] 
[738]     u->pipe->input_filter = ngx_http_fastcgi_input_filter;
[739]     u->pipe->input_ctx = r;
[740] 
[741]     u->input_filter_init = ngx_http_fastcgi_input_filter_init;
[742]     u->input_filter = ngx_http_fastcgi_non_buffered_filter;
[743]     u->input_filter_ctx = r;
[744] 
[745]     if (!flcf->upstream.request_buffering
[746]         && flcf->upstream.pass_request_body)
[747]     {
[748]         r->request_body_no_buffering = 1;
[749]     }
[750] 
[751]     rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
[752] 
[753]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[754]         return rc;
[755]     }
[756] 
[757]     return NGX_DONE;
[758] }
[759] 
[760] 
[761] static ngx_int_t
[762] ngx_http_fastcgi_eval(ngx_http_request_t *r, ngx_http_fastcgi_loc_conf_t *flcf)
[763] {
[764]     ngx_url_t             url;
[765]     ngx_http_upstream_t  *u;
[766] 
[767]     ngx_memzero(&url, sizeof(ngx_url_t));
[768] 
[769]     if (ngx_http_script_run(r, &url.url, flcf->fastcgi_lengths->elts, 0,
[770]                             flcf->fastcgi_values->elts)
[771]         == NULL)
[772]     {
[773]         return NGX_ERROR;
[774]     }
[775] 
[776]     url.no_resolve = 1;
[777] 
[778]     if (ngx_parse_url(r->pool, &url) != NGX_OK) {
[779]         if (url.err) {
[780]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[781]                           "%s in upstream \"%V\"", url.err, &url.url);
[782]         }
[783] 
[784]         return NGX_ERROR;
[785]     }
[786] 
[787]     u = r->upstream;
[788] 
[789]     u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
[790]     if (u->resolved == NULL) {
[791]         return NGX_ERROR;
[792]     }
[793] 
[794]     if (url.addrs) {
[795]         u->resolved->sockaddr = url.addrs[0].sockaddr;
[796]         u->resolved->socklen = url.addrs[0].socklen;
[797]         u->resolved->name = url.addrs[0].name;
[798]         u->resolved->naddrs = 1;
[799]     }
[800] 
[801]     u->resolved->host = url.host;
[802]     u->resolved->port = url.port;
[803]     u->resolved->no_port = url.no_port;
[804] 
[805]     return NGX_OK;
[806] }
[807] 
[808] 
[809] #if (NGX_HTTP_CACHE)
[810] 
[811] static ngx_int_t
[812] ngx_http_fastcgi_create_key(ngx_http_request_t *r)
[813] {
[814]     ngx_str_t                    *key;
[815]     ngx_http_fastcgi_loc_conf_t  *flcf;
[816] 
[817]     key = ngx_array_push(&r->cache->keys);
[818]     if (key == NULL) {
[819]         return NGX_ERROR;
[820]     }
[821] 
[822]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[823] 
[824]     if (ngx_http_complex_value(r, &flcf->cache_key, key) != NGX_OK) {
[825]         return NGX_ERROR;
[826]     }
[827] 
[828]     return NGX_OK;
[829] }
[830] 
[831] #endif
[832] 
[833] 
[834] static ngx_int_t
[835] ngx_http_fastcgi_create_request(ngx_http_request_t *r)
[836] {
[837]     off_t                         file_pos;
[838]     u_char                        ch, sep, *pos, *lowcase_key;
[839]     size_t                        size, len, key_len, val_len, padding,
[840]                                   allocated;
[841]     ngx_uint_t                    i, n, next, hash, skip_empty, header_params;
[842]     ngx_buf_t                    *b;
[843]     ngx_chain_t                  *cl, *body;
[844]     ngx_list_part_t              *part;
[845]     ngx_table_elt_t              *header, *hn, **ignored;
[846]     ngx_http_upstream_t          *u;
[847]     ngx_http_script_code_pt       code;
[848]     ngx_http_script_engine_t      e, le;
[849]     ngx_http_fastcgi_header_t    *h;
[850]     ngx_http_fastcgi_params_t    *params;
[851]     ngx_http_fastcgi_loc_conf_t  *flcf;
[852]     ngx_http_script_len_code_pt   lcode;
[853] 
[854]     len = 0;
[855]     header_params = 0;
[856]     ignored = NULL;
[857] 
[858]     u = r->upstream;
[859] 
[860]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[861] 
[862] #if (NGX_HTTP_CACHE)
[863]     params = u->cacheable ? &flcf->params_cache : &flcf->params;
[864] #else
[865]     params = &flcf->params;
[866] #endif
[867] 
[868]     if (params->lengths) {
[869]         ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[870] 
[871]         ngx_http_script_flush_no_cacheable_variables(r, params->flushes);
[872]         le.flushed = 1;
[873] 
[874]         le.ip = params->lengths->elts;
[875]         le.request = r;
[876] 
[877]         while (*(uintptr_t *) le.ip) {
[878] 
[879]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[880]             key_len = lcode(&le);
[881] 
[882]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[883]             skip_empty = lcode(&le);
[884] 
[885]             for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[886]                 lcode = *(ngx_http_script_len_code_pt *) le.ip;
[887]             }
[888]             le.ip += sizeof(uintptr_t);
[889] 
[890]             if (skip_empty && val_len == 0) {
[891]                 continue;
[892]             }
[893] 
[894]             len += 1 + key_len + ((val_len > 127) ? 4 : 1) + val_len;
[895]         }
[896]     }
[897] 
[898]     if (flcf->upstream.pass_request_headers) {
[899] 
[900]         allocated = 0;
[901]         lowcase_key = NULL;
[902] 
[903]         if (ngx_http_link_multi_headers(r) != NGX_OK) {
[904]             return NGX_ERROR;
[905]         }
[906] 
[907]         if (params->number || r->headers_in.multi) {
[908]             n = 0;
[909]             part = &r->headers_in.headers.part;
[910] 
[911]             while (part) {
[912]                 n += part->nelts;
[913]                 part = part->next;
[914]             }
[915] 
[916]             ignored = ngx_palloc(r->pool, n * sizeof(void *));
[917]             if (ignored == NULL) {
[918]                 return NGX_ERROR;
[919]             }
[920]         }
[921] 
[922]         part = &r->headers_in.headers.part;
[923]         header = part->elts;
[924] 
[925]         for (i = 0; /* void */; i++) {
[926] 
[927]             if (i >= part->nelts) {
[928]                 if (part->next == NULL) {
[929]                     break;
[930]                 }
[931] 
[932]                 part = part->next;
[933]                 header = part->elts;
[934]                 i = 0;
[935]             }
[936] 
[937]             for (n = 0; n < header_params; n++) {
[938]                 if (&header[i] == ignored[n]) {
[939]                     goto next_length;
[940]                 }
[941]             }
[942] 
[943]             if (params->number) {
[944]                 if (allocated < header[i].key.len) {
[945]                     allocated = header[i].key.len + 16;
[946]                     lowcase_key = ngx_pnalloc(r->pool, allocated);
[947]                     if (lowcase_key == NULL) {
[948]                         return NGX_ERROR;
[949]                     }
[950]                 }
[951] 
[952]                 hash = 0;
[953] 
[954]                 for (n = 0; n < header[i].key.len; n++) {
[955]                     ch = header[i].key.data[n];
[956] 
[957]                     if (ch >= 'A' && ch <= 'Z') {
[958]                         ch |= 0x20;
[959] 
[960]                     } else if (ch == '-') {
[961]                         ch = '_';
[962]                     }
[963] 
[964]                     hash = ngx_hash(hash, ch);
[965]                     lowcase_key[n] = ch;
[966]                 }
[967] 
[968]                 if (ngx_hash_find(&params->hash, hash, lowcase_key, n)) {
[969]                     ignored[header_params++] = &header[i];
[970]                     continue;
[971]                 }
[972]             }
[973] 
[974]             key_len = sizeof("HTTP_") - 1 + header[i].key.len;
[975] 
[976]             val_len = header[i].value.len;
[977] 
[978]             for (hn = header[i].next; hn; hn = hn->next) {
[979]                 val_len += hn->value.len + 2;
[980]                 ignored[header_params++] = hn;
[981]             }
[982] 
[983]             len += ((key_len > 127) ? 4 : 1) + key_len
[984]                    + ((val_len > 127) ? 4 : 1) + val_len;
[985] 
[986]         next_length:
[987] 
[988]             continue;
[989]         }
[990]     }
[991] 
[992] 
[993]     if (len > 65535) {
[994]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[995]                       "fastcgi request record is too big: %uz", len);
[996]         return NGX_ERROR;
[997]     }
[998] 
[999] 
[1000]     padding = 8 - len % 8;
[1001]     padding = (padding == 8) ? 0 : padding;
[1002] 
[1003] 
[1004]     size = sizeof(ngx_http_fastcgi_header_t)
[1005]            + sizeof(ngx_http_fastcgi_begin_request_t)
[1006] 
[1007]            + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */
[1008]            + len + padding
[1009]            + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */
[1010] 
[1011]            + sizeof(ngx_http_fastcgi_header_t); /* NGX_HTTP_FASTCGI_STDIN */
[1012] 
[1013] 
[1014]     b = ngx_create_temp_buf(r->pool, size);
[1015]     if (b == NULL) {
[1016]         return NGX_ERROR;
[1017]     }
[1018] 
[1019]     cl = ngx_alloc_chain_link(r->pool);
[1020]     if (cl == NULL) {
[1021]         return NGX_ERROR;
[1022]     }
[1023] 
[1024]     cl->buf = b;
[1025] 
[1026]     ngx_http_fastcgi_request_start.br.flags =
[1027]         flcf->keep_conn ? NGX_HTTP_FASTCGI_KEEP_CONN : 0;
[1028] 
[1029]     ngx_memcpy(b->pos, &ngx_http_fastcgi_request_start,
[1030]                sizeof(ngx_http_fastcgi_request_start_t));
[1031] 
[1032]     h = (ngx_http_fastcgi_header_t *)
[1033]              (b->pos + sizeof(ngx_http_fastcgi_header_t)
[1034]                      + sizeof(ngx_http_fastcgi_begin_request_t));
[1035] 
[1036]     h->content_length_hi = (u_char) ((len >> 8) & 0xff);
[1037]     h->content_length_lo = (u_char) (len & 0xff);
[1038]     h->padding_length = (u_char) padding;
[1039]     h->reserved = 0;
[1040] 
[1041]     b->last = b->pos + sizeof(ngx_http_fastcgi_header_t)
[1042]                      + sizeof(ngx_http_fastcgi_begin_request_t)
[1043]                      + sizeof(ngx_http_fastcgi_header_t);
[1044] 
[1045] 
[1046]     if (params->lengths) {
[1047]         ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[1048] 
[1049]         e.ip = params->values->elts;
[1050]         e.pos = b->last;
[1051]         e.request = r;
[1052]         e.flushed = 1;
[1053] 
[1054]         le.ip = params->lengths->elts;
[1055] 
[1056]         while (*(uintptr_t *) le.ip) {
[1057] 
[1058]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1059]             key_len = (u_char) lcode(&le);
[1060] 
[1061]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1062]             skip_empty = lcode(&le);
[1063] 
[1064]             for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[1065]                 lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1066]             }
[1067]             le.ip += sizeof(uintptr_t);
[1068] 
[1069]             if (skip_empty && val_len == 0) {
[1070]                 e.skip = 1;
[1071] 
[1072]                 while (*(uintptr_t *) e.ip) {
[1073]                     code = *(ngx_http_script_code_pt *) e.ip;
[1074]                     code((ngx_http_script_engine_t *) &e);
[1075]                 }
[1076]                 e.ip += sizeof(uintptr_t);
[1077] 
[1078]                 e.skip = 0;
[1079] 
[1080]                 continue;
[1081]             }
[1082] 
[1083]             *e.pos++ = (u_char) key_len;
[1084] 
[1085]             if (val_len > 127) {
[1086]                 *e.pos++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
[1087]                 *e.pos++ = (u_char) ((val_len >> 16) & 0xff);
[1088]                 *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
[1089]                 *e.pos++ = (u_char) (val_len & 0xff);
[1090] 
[1091]             } else {
[1092]                 *e.pos++ = (u_char) val_len;
[1093]             }
[1094] 
[1095]             while (*(uintptr_t *) e.ip) {
[1096]                 code = *(ngx_http_script_code_pt *) e.ip;
[1097]                 code((ngx_http_script_engine_t *) &e);
[1098]             }
[1099]             e.ip += sizeof(uintptr_t);
[1100] 
[1101]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1102]                            "fastcgi param: \"%*s: %*s\"",
[1103]                            key_len, e.pos - (key_len + val_len),
[1104]                            val_len, e.pos - val_len);
[1105]         }
[1106] 
[1107]         b->last = e.pos;
[1108]     }
[1109] 
[1110] 
[1111]     if (flcf->upstream.pass_request_headers) {
[1112] 
[1113]         part = &r->headers_in.headers.part;
[1114]         header = part->elts;
[1115] 
[1116]         for (i = 0; /* void */; i++) {
[1117] 
[1118]             if (i >= part->nelts) {
[1119]                 if (part->next == NULL) {
[1120]                     break;
[1121]                 }
[1122] 
[1123]                 part = part->next;
[1124]                 header = part->elts;
[1125]                 i = 0;
[1126]             }
[1127] 
[1128]             for (n = 0; n < header_params; n++) {
[1129]                 if (&header[i] == ignored[n]) {
[1130]                     goto next_value;
[1131]                 }
[1132]             }
[1133] 
[1134]             key_len = sizeof("HTTP_") - 1 + header[i].key.len;
[1135]             if (key_len > 127) {
[1136]                 *b->last++ = (u_char) (((key_len >> 24) & 0x7f) | 0x80);
[1137]                 *b->last++ = (u_char) ((key_len >> 16) & 0xff);
[1138]                 *b->last++ = (u_char) ((key_len >> 8) & 0xff);
[1139]                 *b->last++ = (u_char) (key_len & 0xff);
[1140] 
[1141]             } else {
[1142]                 *b->last++ = (u_char) key_len;
[1143]             }
[1144] 
[1145]             val_len = header[i].value.len;
[1146] 
[1147]             for (hn = header[i].next; hn; hn = hn->next) {
[1148]                 val_len += hn->value.len + 2;
[1149]             }
[1150] 
[1151]             if (val_len > 127) {
[1152]                 *b->last++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
[1153]                 *b->last++ = (u_char) ((val_len >> 16) & 0xff);
[1154]                 *b->last++ = (u_char) ((val_len >> 8) & 0xff);
[1155]                 *b->last++ = (u_char) (val_len & 0xff);
[1156] 
[1157]             } else {
[1158]                 *b->last++ = (u_char) val_len;
[1159]             }
[1160] 
[1161]             b->last = ngx_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);
[1162] 
[1163]             for (n = 0; n < header[i].key.len; n++) {
[1164]                 ch = header[i].key.data[n];
[1165] 
[1166]                 if (ch >= 'a' && ch <= 'z') {
[1167]                     ch &= ~0x20;
[1168] 
[1169]                 } else if (ch == '-') {
[1170]                     ch = '_';
[1171]                 }
[1172] 
[1173]                 *b->last++ = ch;
[1174]             }
[1175] 
[1176]             b->last = ngx_copy(b->last, header[i].value.data,
[1177]                                header[i].value.len);
[1178] 
[1179]             if (header[i].next) {
[1180] 
[1181]                 if (header[i].key.len == sizeof("Cookie") - 1
[1182]                     && ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie",
[1183]                                        sizeof("Cookie") - 1)
[1184]                        == 0)
[1185]                 {
[1186]                     sep = ';';
[1187] 
[1188]                 } else {
[1189]                     sep = ',';
[1190]                 }
[1191] 
[1192]                 for (hn = header[i].next; hn; hn = hn->next) {
[1193]                     *b->last++ = sep;
[1194]                     *b->last++ = ' ';
[1195]                     b->last = ngx_copy(b->last, hn->value.data, hn->value.len);
[1196]                 }
[1197]             }
[1198] 
[1199]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1200]                            "fastcgi param: \"%*s: %*s\"",
[1201]                            key_len, b->last - (key_len + val_len),
[1202]                            val_len, b->last - val_len);
[1203]         next_value:
[1204] 
[1205]             continue;
[1206]         }
[1207]     }
[1208] 
[1209] 
[1210]     if (padding) {
[1211]         ngx_memzero(b->last, padding);
[1212]         b->last += padding;
[1213]     }
[1214] 
[1215] 
[1216]     h = (ngx_http_fastcgi_header_t *) b->last;
[1217]     b->last += sizeof(ngx_http_fastcgi_header_t);
[1218] 
[1219]     h->version = 1;
[1220]     h->type = NGX_HTTP_FASTCGI_PARAMS;
[1221]     h->request_id_hi = 0;
[1222]     h->request_id_lo = 1;
[1223]     h->content_length_hi = 0;
[1224]     h->content_length_lo = 0;
[1225]     h->padding_length = 0;
[1226]     h->reserved = 0;
[1227] 
[1228]     if (r->request_body_no_buffering) {
[1229] 
[1230]         u->request_bufs = cl;
[1231] 
[1232]         u->output.output_filter = ngx_http_fastcgi_body_output_filter;
[1233]         u->output.filter_ctx = r;
[1234] 
[1235]     } else if (flcf->upstream.pass_request_body) {
[1236] 
[1237]         body = u->request_bufs;
[1238]         u->request_bufs = cl;
[1239] 
[1240] #if (NGX_SUPPRESS_WARN)
[1241]         file_pos = 0;
[1242]         pos = NULL;
[1243] #endif
[1244] 
[1245]         while (body) {
[1246] 
[1247]             if (ngx_buf_special(body->buf)) {
[1248]                 body = body->next;
[1249]                 continue;
[1250]             }
[1251] 
[1252]             if (body->buf->in_file) {
[1253]                 file_pos = body->buf->file_pos;
[1254] 
[1255]             } else {
[1256]                 pos = body->buf->pos;
[1257]             }
[1258] 
[1259]             next = 0;
[1260] 
[1261]             do {
[1262]                 b = ngx_alloc_buf(r->pool);
[1263]                 if (b == NULL) {
[1264]                     return NGX_ERROR;
[1265]                 }
[1266] 
[1267]                 ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
[1268] 
[1269]                 if (body->buf->in_file) {
[1270]                     b->file_pos = file_pos;
[1271]                     file_pos += 32 * 1024;
[1272] 
[1273]                     if (file_pos >= body->buf->file_last) {
[1274]                         file_pos = body->buf->file_last;
[1275]                         next = 1;
[1276]                     }
[1277] 
[1278]                     b->file_last = file_pos;
[1279]                     len = (ngx_uint_t) (file_pos - b->file_pos);
[1280] 
[1281]                 } else {
[1282]                     b->pos = pos;
[1283]                     b->start = pos;
[1284]                     pos += 32 * 1024;
[1285] 
[1286]                     if (pos >= body->buf->last) {
[1287]                         pos = body->buf->last;
[1288]                         next = 1;
[1289]                     }
[1290] 
[1291]                     b->last = pos;
[1292]                     len = (ngx_uint_t) (pos - b->pos);
[1293]                 }
[1294] 
[1295]                 padding = 8 - len % 8;
[1296]                 padding = (padding == 8) ? 0 : padding;
[1297] 
[1298]                 h = (ngx_http_fastcgi_header_t *) cl->buf->last;
[1299]                 cl->buf->last += sizeof(ngx_http_fastcgi_header_t);
[1300] 
[1301]                 h->version = 1;
[1302]                 h->type = NGX_HTTP_FASTCGI_STDIN;
[1303]                 h->request_id_hi = 0;
[1304]                 h->request_id_lo = 1;
[1305]                 h->content_length_hi = (u_char) ((len >> 8) & 0xff);
[1306]                 h->content_length_lo = (u_char) (len & 0xff);
[1307]                 h->padding_length = (u_char) padding;
[1308]                 h->reserved = 0;
[1309] 
[1310]                 cl->next = ngx_alloc_chain_link(r->pool);
[1311]                 if (cl->next == NULL) {
[1312]                     return NGX_ERROR;
[1313]                 }
[1314] 
[1315]                 cl = cl->next;
[1316]                 cl->buf = b;
[1317] 
[1318]                 b = ngx_create_temp_buf(r->pool,
[1319]                                         sizeof(ngx_http_fastcgi_header_t)
[1320]                                         + padding);
[1321]                 if (b == NULL) {
[1322]                     return NGX_ERROR;
[1323]                 }
[1324] 
[1325]                 if (padding) {
[1326]                     ngx_memzero(b->last, padding);
[1327]                     b->last += padding;
[1328]                 }
[1329] 
[1330]                 cl->next = ngx_alloc_chain_link(r->pool);
[1331]                 if (cl->next == NULL) {
[1332]                     return NGX_ERROR;
[1333]                 }
[1334] 
[1335]                 cl = cl->next;
[1336]                 cl->buf = b;
[1337] 
[1338]             } while (!next);
[1339] 
[1340]             body = body->next;
[1341]         }
[1342] 
[1343]     } else {
[1344]         u->request_bufs = cl;
[1345]     }
[1346] 
[1347]     if (!r->request_body_no_buffering) {
[1348]         h = (ngx_http_fastcgi_header_t *) cl->buf->last;
[1349]         cl->buf->last += sizeof(ngx_http_fastcgi_header_t);
[1350] 
[1351]         h->version = 1;
[1352]         h->type = NGX_HTTP_FASTCGI_STDIN;
[1353]         h->request_id_hi = 0;
[1354]         h->request_id_lo = 1;
[1355]         h->content_length_hi = 0;
[1356]         h->content_length_lo = 0;
[1357]         h->padding_length = 0;
[1358]         h->reserved = 0;
[1359]     }
[1360] 
[1361]     cl->next = NULL;
[1362] 
[1363]     return NGX_OK;
[1364] }
[1365] 
[1366] 
[1367] static ngx_int_t
[1368] ngx_http_fastcgi_reinit_request(ngx_http_request_t *r)
[1369] {
[1370]     ngx_http_fastcgi_ctx_t  *f;
[1371] 
[1372]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[1373] 
[1374]     if (f == NULL) {
[1375]         return NGX_OK;
[1376]     }
[1377] 
[1378]     f->state = ngx_http_fastcgi_st_version;
[1379]     f->fastcgi_stdout = 0;
[1380]     f->large_stderr = 0;
[1381] 
[1382]     if (f->split_parts) {
[1383]         f->split_parts->nelts = 0;
[1384]     }
[1385] 
[1386]     r->state = 0;
[1387] 
[1388]     return NGX_OK;
[1389] }
[1390] 
[1391] 
[1392] static ngx_int_t
[1393] ngx_http_fastcgi_body_output_filter(void *data, ngx_chain_t *in)
[1394] {
[1395]     ngx_http_request_t  *r = data;
[1396] 
[1397]     off_t                       file_pos;
[1398]     u_char                     *pos, *start;
[1399]     size_t                      len, padding;
[1400]     ngx_buf_t                  *b;
[1401]     ngx_int_t                   rc;
[1402]     ngx_uint_t                  next, last;
[1403]     ngx_chain_t                *cl, *tl, *out, **ll;
[1404]     ngx_http_fastcgi_ctx_t     *f;
[1405]     ngx_http_fastcgi_header_t  *h;
[1406] 
[1407]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1408]                    "fastcgi output filter");
[1409] 
[1410]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[1411] 
[1412]     if (in == NULL) {
[1413]         out = in;
[1414]         goto out;
[1415]     }
[1416] 
[1417]     out = NULL;
[1418]     ll = &out;
[1419] 
[1420]     if (!f->header_sent) {
[1421]         /* first buffer contains headers, pass it unmodified */
[1422] 
[1423]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1424]                        "fastcgi output header");
[1425] 
[1426]         f->header_sent = 1;
[1427] 
[1428]         tl = ngx_alloc_chain_link(r->pool);
[1429]         if (tl == NULL) {
[1430]             return NGX_ERROR;
[1431]         }
[1432] 
[1433]         tl->buf = in->buf;
[1434]         *ll = tl;
[1435]         ll = &tl->next;
[1436] 
[1437]         in = in->next;
[1438] 
[1439]         if (in == NULL) {
[1440]             tl->next = NULL;
[1441]             goto out;
[1442]         }
[1443]     }
[1444] 
[1445]     cl = ngx_chain_get_free_buf(r->pool, &f->free);
[1446]     if (cl == NULL) {
[1447]         return NGX_ERROR;
[1448]     }
[1449] 
[1450]     b = cl->buf;
[1451] 
[1452]     b->tag = (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter;
[1453]     b->temporary = 1;
[1454] 
[1455]     if (b->start == NULL) {
[1456]         /* reserve space for maximum possible padding, 7 bytes */
[1457] 
[1458]         b->start = ngx_palloc(r->pool,
[1459]                               sizeof(ngx_http_fastcgi_header_t) + 7);
[1460]         if (b->start == NULL) {
[1461]             return NGX_ERROR;
[1462]         }
[1463] 
[1464]         b->pos = b->start;
[1465]         b->last = b->start;
[1466] 
[1467]         b->end = b->start + sizeof(ngx_http_fastcgi_header_t) + 7;
[1468]     }
[1469] 
[1470]     *ll = cl;
[1471] 
[1472]     last = 0;
[1473]     padding = 0;
[1474] 
[1475] #if (NGX_SUPPRESS_WARN)
[1476]     file_pos = 0;
[1477]     pos = NULL;
[1478] #endif
[1479] 
[1480]     while (in) {
[1481] 
[1482]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1483]                        "fastcgi output in  l:%d f:%d %p, pos %p, size: %z "
[1484]                        "file: %O, size: %O",
[1485]                        in->buf->last_buf,
[1486]                        in->buf->in_file,
[1487]                        in->buf->start, in->buf->pos,
[1488]                        in->buf->last - in->buf->pos,
[1489]                        in->buf->file_pos,
[1490]                        in->buf->file_last - in->buf->file_pos);
[1491] 
[1492]         if (in->buf->last_buf) {
[1493]             last = 1;
[1494]         }
[1495] 
[1496]         if (ngx_buf_special(in->buf)) {
[1497]             in = in->next;
[1498]             continue;
[1499]         }
[1500] 
[1501]         if (in->buf->in_file) {
[1502]             file_pos = in->buf->file_pos;
[1503] 
[1504]         } else {
[1505]             pos = in->buf->pos;
[1506]         }
[1507] 
[1508]         next = 0;
[1509] 
[1510]         do {
[1511]             tl = ngx_chain_get_free_buf(r->pool, &f->free);
[1512]             if (tl == NULL) {
[1513]                 return NGX_ERROR;
[1514]             }
[1515] 
[1516]             b = tl->buf;
[1517]             start = b->start;
[1518] 
[1519]             ngx_memcpy(b, in->buf, sizeof(ngx_buf_t));
[1520] 
[1521]             /*
[1522]              * restore b->start to preserve memory allocated in the buffer,
[1523]              * to reuse it later for headers and padding
[1524]              */
[1525] 
[1526]             b->start = start;
[1527] 
[1528]             if (in->buf->in_file) {
[1529]                 b->file_pos = file_pos;
[1530]                 file_pos += 32 * 1024;
[1531] 
[1532]                 if (file_pos >= in->buf->file_last) {
[1533]                     file_pos = in->buf->file_last;
[1534]                     next = 1;
[1535]                 }
[1536] 
[1537]                 b->file_last = file_pos;
[1538]                 len = (ngx_uint_t) (file_pos - b->file_pos);
[1539] 
[1540]             } else {
[1541]                 b->pos = pos;
[1542]                 pos += 32 * 1024;
[1543] 
[1544]                 if (pos >= in->buf->last) {
[1545]                     pos = in->buf->last;
[1546]                     next = 1;
[1547]                 }
[1548] 
[1549]                 b->last = pos;
[1550]                 len = (ngx_uint_t) (pos - b->pos);
[1551]             }
[1552] 
[1553]             b->tag = (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter;
[1554]             b->shadow = in->buf;
[1555]             b->last_shadow = next;
[1556] 
[1557]             b->last_buf = 0;
[1558]             b->last_in_chain = 0;
[1559] 
[1560]             padding = 8 - len % 8;
[1561]             padding = (padding == 8) ? 0 : padding;
[1562] 
[1563]             h = (ngx_http_fastcgi_header_t *) cl->buf->last;
[1564]             cl->buf->last += sizeof(ngx_http_fastcgi_header_t);
[1565] 
[1566]             h->version = 1;
[1567]             h->type = NGX_HTTP_FASTCGI_STDIN;
[1568]             h->request_id_hi = 0;
[1569]             h->request_id_lo = 1;
[1570]             h->content_length_hi = (u_char) ((len >> 8) & 0xff);
[1571]             h->content_length_lo = (u_char) (len & 0xff);
[1572]             h->padding_length = (u_char) padding;
[1573]             h->reserved = 0;
[1574] 
[1575]             cl->next = tl;
[1576]             cl = tl;
[1577] 
[1578]             tl = ngx_chain_get_free_buf(r->pool, &f->free);
[1579]             if (tl == NULL) {
[1580]                 return NGX_ERROR;
[1581]             }
[1582] 
[1583]             b = tl->buf;
[1584] 
[1585]             b->tag = (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter;
[1586]             b->temporary = 1;
[1587] 
[1588]             if (b->start == NULL) {
[1589]                 /* reserve space for maximum possible padding, 7 bytes */
[1590] 
[1591]                 b->start = ngx_palloc(r->pool,
[1592]                                       sizeof(ngx_http_fastcgi_header_t) + 7);
[1593]                 if (b->start == NULL) {
[1594]                     return NGX_ERROR;
[1595]                 }
[1596] 
[1597]                 b->pos = b->start;
[1598]                 b->last = b->start;
[1599] 
[1600]                 b->end = b->start + sizeof(ngx_http_fastcgi_header_t) + 7;
[1601]             }
[1602] 
[1603]             if (padding) {
[1604]                 ngx_memzero(b->last, padding);
[1605]                 b->last += padding;
[1606]             }
[1607] 
[1608]             cl->next = tl;
[1609]             cl = tl;
[1610] 
[1611]         } while (!next);
[1612] 
[1613]         in = in->next;
[1614]     }
[1615] 
[1616]     if (last) {
[1617]         h = (ngx_http_fastcgi_header_t *) cl->buf->last;
[1618]         cl->buf->last += sizeof(ngx_http_fastcgi_header_t);
[1619] 
[1620]         h->version = 1;
[1621]         h->type = NGX_HTTP_FASTCGI_STDIN;
[1622]         h->request_id_hi = 0;
[1623]         h->request_id_lo = 1;
[1624]         h->content_length_hi = 0;
[1625]         h->content_length_lo = 0;
[1626]         h->padding_length = 0;
[1627]         h->reserved = 0;
[1628] 
[1629]         cl->buf->last_buf = 1;
[1630] 
[1631]     } else if (padding == 0) {
[1632]         /* TODO: do not allocate buffers instead */
[1633]         cl->buf->temporary = 0;
[1634]         cl->buf->sync = 1;
[1635]     }
[1636] 
[1637]     cl->next = NULL;
[1638] 
[1639] out:
[1640] 
[1641] #if (NGX_DEBUG)
[1642] 
[1643]     for (cl = out; cl; cl = cl->next) {
[1644]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1645]                        "fastcgi output out l:%d f:%d %p, pos %p, size: %z "
[1646]                        "file: %O, size: %O",
[1647]                        cl->buf->last_buf,
[1648]                        cl->buf->in_file,
[1649]                        cl->buf->start, cl->buf->pos,
[1650]                        cl->buf->last - cl->buf->pos,
[1651]                        cl->buf->file_pos,
[1652]                        cl->buf->file_last - cl->buf->file_pos);
[1653]     }
[1654] 
[1655] #endif
[1656] 
[1657]     rc = ngx_chain_writer(&r->upstream->writer, out);
[1658] 
[1659]     ngx_chain_update_chains(r->pool, &f->free, &f->busy, &out,
[1660]                          (ngx_buf_tag_t) &ngx_http_fastcgi_body_output_filter);
[1661] 
[1662]     for (cl = f->free; cl; cl = cl->next) {
[1663] 
[1664]         /* mark original buffers as sent */
[1665] 
[1666]         if (cl->buf->shadow) {
[1667]             if (cl->buf->last_shadow) {
[1668]                 b = cl->buf->shadow;
[1669]                 b->pos = b->last;
[1670]             }
[1671] 
[1672]             cl->buf->shadow = NULL;
[1673]         }
[1674]     }
[1675] 
[1676]     return rc;
[1677] }
[1678] 
[1679] 
[1680] static ngx_int_t
[1681] ngx_http_fastcgi_process_header(ngx_http_request_t *r)
[1682] {
[1683]     u_char                         *p, *msg, *start, *last,
[1684]                                    *part_start, *part_end;
[1685]     size_t                          size;
[1686]     ngx_str_t                      *status_line, *pattern;
[1687]     ngx_int_t                       rc, status;
[1688]     ngx_buf_t                       buf;
[1689]     ngx_uint_t                      i;
[1690]     ngx_table_elt_t                *h;
[1691]     ngx_http_upstream_t            *u;
[1692]     ngx_http_fastcgi_ctx_t         *f;
[1693]     ngx_http_upstream_header_t     *hh;
[1694]     ngx_http_fastcgi_loc_conf_t    *flcf;
[1695]     ngx_http_fastcgi_split_part_t  *part;
[1696]     ngx_http_upstream_main_conf_t  *umcf;
[1697] 
[1698]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[1699] 
[1700]     umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[1701] 
[1702]     u = r->upstream;
[1703] 
[1704]     for ( ;; ) {
[1705] 
[1706]         if (f->state < ngx_http_fastcgi_st_data) {
[1707] 
[1708]             f->pos = u->buffer.pos;
[1709]             f->last = u->buffer.last;
[1710] 
[1711]             rc = ngx_http_fastcgi_process_record(r, f);
[1712] 
[1713]             u->buffer.pos = f->pos;
[1714]             u->buffer.last = f->last;
[1715] 
[1716]             if (rc == NGX_AGAIN) {
[1717]                 return NGX_AGAIN;
[1718]             }
[1719] 
[1720]             if (rc == NGX_ERROR) {
[1721]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1722]             }
[1723] 
[1724]             if (f->type != NGX_HTTP_FASTCGI_STDOUT
[1725]                 && f->type != NGX_HTTP_FASTCGI_STDERR)
[1726]             {
[1727]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1728]                               "upstream sent unexpected FastCGI record: %ui",
[1729]                               f->type);
[1730] 
[1731]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1732]             }
[1733] 
[1734]             if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
[1735]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1736]                               "upstream prematurely closed FastCGI stdout");
[1737] 
[1738]                 return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1739]             }
[1740]         }
[1741] 
[1742]         if (f->state == ngx_http_fastcgi_st_padding) {
[1743] 
[1744]             if (u->buffer.pos + f->padding < u->buffer.last) {
[1745]                 f->state = ngx_http_fastcgi_st_version;
[1746]                 u->buffer.pos += f->padding;
[1747] 
[1748]                 continue;
[1749]             }
[1750] 
[1751]             if (u->buffer.pos + f->padding == u->buffer.last) {
[1752]                 f->state = ngx_http_fastcgi_st_version;
[1753]                 u->buffer.pos = u->buffer.last;
[1754] 
[1755]                 return NGX_AGAIN;
[1756]             }
[1757] 
[1758]             f->padding -= u->buffer.last - u->buffer.pos;
[1759]             u->buffer.pos = u->buffer.last;
[1760] 
[1761]             return NGX_AGAIN;
[1762]         }
[1763] 
[1764] 
[1765]         /* f->state == ngx_http_fastcgi_st_data */
[1766] 
[1767]         if (f->type == NGX_HTTP_FASTCGI_STDERR) {
[1768] 
[1769]             if (f->length) {
[1770]                 msg = u->buffer.pos;
[1771] 
[1772]                 if (u->buffer.pos + f->length <= u->buffer.last) {
[1773]                     u->buffer.pos += f->length;
[1774]                     f->length = 0;
[1775]                     f->state = ngx_http_fastcgi_st_padding;
[1776] 
[1777]                 } else {
[1778]                     f->length -= u->buffer.last - u->buffer.pos;
[1779]                     u->buffer.pos = u->buffer.last;
[1780]                 }
[1781] 
[1782]                 for (p = u->buffer.pos - 1; msg < p; p--) {
[1783]                     if (*p != LF && *p != CR && *p != '.' && *p != ' ') {
[1784]                         break;
[1785]                     }
[1786]                 }
[1787] 
[1788]                 p++;
[1789] 
[1790]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1791]                               "FastCGI sent in stderr: \"%*s\"", p - msg, msg);
[1792] 
[1793]                 flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[1794] 
[1795]                 if (flcf->catch_stderr) {
[1796]                     pattern = flcf->catch_stderr->elts;
[1797] 
[1798]                     for (i = 0; i < flcf->catch_stderr->nelts; i++) {
[1799]                         if (ngx_strnstr(msg, (char *) pattern[i].data,
[1800]                                         p - msg)
[1801]                             != NULL)
[1802]                         {
[1803]                             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1804]                         }
[1805]                     }
[1806]                 }
[1807] 
[1808]                 if (u->buffer.pos == u->buffer.last) {
[1809] 
[1810]                     if (!f->fastcgi_stdout) {
[1811] 
[1812]                         /*
[1813]                          * the special handling the large number
[1814]                          * of the PHP warnings to not allocate memory
[1815]                          */
[1816] 
[1817] #if (NGX_HTTP_CACHE)
[1818]                         if (r->cache) {
[1819]                             u->buffer.pos = u->buffer.start
[1820]                                                      + r->cache->header_start;
[1821]                         } else {
[1822]                             u->buffer.pos = u->buffer.start;
[1823]                         }
[1824] #else
[1825]                         u->buffer.pos = u->buffer.start;
[1826] #endif
[1827]                         u->buffer.last = u->buffer.pos;
[1828]                         f->large_stderr = 1;
[1829]                     }
[1830] 
[1831]                     return NGX_AGAIN;
[1832]                 }
[1833] 
[1834]             } else {
[1835]                 f->state = ngx_http_fastcgi_st_padding;
[1836]             }
[1837] 
[1838]             continue;
[1839]         }
[1840] 
[1841] 
[1842]         /* f->type == NGX_HTTP_FASTCGI_STDOUT */
[1843] 
[1844] #if (NGX_HTTP_CACHE)
[1845] 
[1846]         if (f->large_stderr && r->cache) {
[1847]             ssize_t                     len;
[1848]             ngx_http_fastcgi_header_t  *fh;
[1849] 
[1850]             start = u->buffer.start + r->cache->header_start;
[1851] 
[1852]             len = u->buffer.pos - start - 2 * sizeof(ngx_http_fastcgi_header_t);
[1853] 
[1854]             /*
[1855]              * A tail of large stderr output before HTTP header is placed
[1856]              * in a cache file without a FastCGI record header.
[1857]              * To workaround it we put a dummy FastCGI record header at the
[1858]              * start of the stderr output or update r->cache_header_start,
[1859]              * if there is no enough place for the record header.
[1860]              */
[1861] 
[1862]             if (len >= 0) {
[1863]                 fh = (ngx_http_fastcgi_header_t *) start;
[1864]                 fh->version = 1;
[1865]                 fh->type = NGX_HTTP_FASTCGI_STDERR;
[1866]                 fh->request_id_hi = 0;
[1867]                 fh->request_id_lo = 1;
[1868]                 fh->content_length_hi = (u_char) ((len >> 8) & 0xff);
[1869]                 fh->content_length_lo = (u_char) (len & 0xff);
[1870]                 fh->padding_length = 0;
[1871]                 fh->reserved = 0;
[1872] 
[1873]             } else {
[1874]                 r->cache->header_start += u->buffer.pos - start
[1875]                                           - sizeof(ngx_http_fastcgi_header_t);
[1876]             }
[1877] 
[1878]             f->large_stderr = 0;
[1879]         }
[1880] 
[1881] #endif
[1882] 
[1883]         f->fastcgi_stdout = 1;
[1884] 
[1885]         start = u->buffer.pos;
[1886] 
[1887]         if (u->buffer.pos + f->length < u->buffer.last) {
[1888] 
[1889]             /*
[1890]              * set u->buffer.last to the end of the FastCGI record data
[1891]              * for ngx_http_parse_header_line()
[1892]              */
[1893] 
[1894]             last = u->buffer.last;
[1895]             u->buffer.last = u->buffer.pos + f->length;
[1896] 
[1897]         } else {
[1898]             last = NULL;
[1899]         }
[1900] 
[1901]         for ( ;; ) {
[1902] 
[1903]             part_start = u->buffer.pos;
[1904]             part_end = u->buffer.last;
[1905] 
[1906]             rc = ngx_http_parse_header_line(r, &u->buffer, 1);
[1907] 
[1908]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1909]                            "http fastcgi parser: %i", rc);
[1910] 
[1911]             if (rc == NGX_AGAIN) {
[1912]                 break;
[1913]             }
[1914] 
[1915]             if (rc == NGX_OK) {
[1916] 
[1917]                 /* a header line has been parsed successfully */
[1918] 
[1919]                 h = ngx_list_push(&u->headers_in.headers);
[1920]                 if (h == NULL) {
[1921]                     return NGX_ERROR;
[1922]                 }
[1923] 
[1924]                 if (f->split_parts && f->split_parts->nelts) {
[1925] 
[1926]                     part = f->split_parts->elts;
[1927]                     size = u->buffer.pos - part_start;
[1928] 
[1929]                     for (i = 0; i < f->split_parts->nelts; i++) {
[1930]                         size += part[i].end - part[i].start;
[1931]                     }
[1932] 
[1933]                     p = ngx_pnalloc(r->pool, size);
[1934]                     if (p == NULL) {
[1935]                         h->hash = 0;
[1936]                         return NGX_ERROR;
[1937]                     }
[1938] 
[1939]                     buf.pos = p;
[1940] 
[1941]                     for (i = 0; i < f->split_parts->nelts; i++) {
[1942]                         p = ngx_cpymem(p, part[i].start,
[1943]                                        part[i].end - part[i].start);
[1944]                     }
[1945] 
[1946]                     p = ngx_cpymem(p, part_start, u->buffer.pos - part_start);
[1947] 
[1948]                     buf.last = p;
[1949] 
[1950]                     f->split_parts->nelts = 0;
[1951] 
[1952]                     rc = ngx_http_parse_header_line(r, &buf, 1);
[1953] 
[1954]                     if (rc != NGX_OK) {
[1955]                         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1956]                                       "invalid header after joining "
[1957]                                       "FastCGI records");
[1958]                         h->hash = 0;
[1959]                         return NGX_ERROR;
[1960]                     }
[1961] 
[1962]                     h->key.len = r->header_name_end - r->header_name_start;
[1963]                     h->key.data = r->header_name_start;
[1964]                     h->key.data[h->key.len] = '\0';
[1965] 
[1966]                     h->value.len = r->header_end - r->header_start;
[1967]                     h->value.data = r->header_start;
[1968]                     h->value.data[h->value.len] = '\0';
[1969] 
[1970]                     h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
[1971]                     if (h->lowcase_key == NULL) {
[1972]                         return NGX_ERROR;
[1973]                     }
[1974] 
[1975]                 } else {
[1976] 
[1977]                     h->key.len = r->header_name_end - r->header_name_start;
[1978]                     h->value.len = r->header_end - r->header_start;
[1979] 
[1980]                     h->key.data = ngx_pnalloc(r->pool,
[1981]                                               h->key.len + 1 + h->value.len + 1
[1982]                                               + h->key.len);
[1983]                     if (h->key.data == NULL) {
[1984]                         h->hash = 0;
[1985]                         return NGX_ERROR;
[1986]                     }
[1987] 
[1988]                     h->value.data = h->key.data + h->key.len + 1;
[1989]                     h->lowcase_key = h->key.data + h->key.len + 1
[1990]                                      + h->value.len + 1;
[1991] 
[1992]                     ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
[1993]                     h->key.data[h->key.len] = '\0';
[1994]                     ngx_memcpy(h->value.data, r->header_start, h->value.len);
[1995]                     h->value.data[h->value.len] = '\0';
[1996]                 }
[1997] 
[1998]                 h->hash = r->header_hash;
[1999] 
[2000]                 if (h->key.len == r->lowcase_index) {
[2001]                     ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
[2002] 
[2003]                 } else {
[2004]                     ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
[2005]                 }
[2006] 
[2007]                 hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
[2008]                                    h->lowcase_key, h->key.len);
[2009] 
[2010]                 if (hh) {
[2011]                     rc = hh->handler(r, h, hh->offset);
[2012] 
[2013]                     if (rc != NGX_OK) {
[2014]                         return rc;
[2015]                     }
[2016]                 }
[2017] 
[2018]                 ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2019]                                "http fastcgi header: \"%V: %V\"",
[2020]                                &h->key, &h->value);
[2021] 
[2022]                 if (u->buffer.pos < u->buffer.last) {
[2023]                     continue;
[2024]                 }
[2025] 
[2026]                 /* the end of the FastCGI record */
[2027] 
[2028]                 break;
[2029]             }
[2030] 
[2031]             if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[2032] 
[2033]                 /* a whole header has been parsed successfully */
[2034] 
[2035]                 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2036]                                "http fastcgi header done");
[2037] 
[2038]                 if (u->headers_in.status) {
[2039]                     status_line = &u->headers_in.status->value;
[2040] 
[2041]                     status = ngx_atoi(status_line->data, 3);
[2042] 
[2043]                     if (status == NGX_ERROR) {
[2044]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2045]                                       "upstream sent invalid status \"%V\"",
[2046]                                       status_line);
[2047]                         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[2048]                     }
[2049] 
[2050]                     u->headers_in.status_n = status;
[2051]                     u->headers_in.status_line = *status_line;
[2052] 
[2053]                 } else if (u->headers_in.location) {
[2054]                     u->headers_in.status_n = 302;
[2055]                     ngx_str_set(&u->headers_in.status_line,
[2056]                                 "302 Moved Temporarily");
[2057] 
[2058]                 } else {
[2059]                     u->headers_in.status_n = 200;
[2060]                     ngx_str_set(&u->headers_in.status_line, "200 OK");
[2061]                 }
[2062] 
[2063]                 if (u->state && u->state->status == 0) {
[2064]                     u->state->status = u->headers_in.status_n;
[2065]                 }
[2066] 
[2067]                 break;
[2068]             }
[2069] 
[2070]             /* rc == NGX_HTTP_PARSE_INVALID_HEADER */
[2071] 
[2072]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2073]                           "upstream sent invalid header: \"%*s\\x%02xd...\"",
[2074]                           r->header_end - r->header_name_start,
[2075]                           r->header_name_start, *r->header_end);
[2076] 
[2077]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[2078]         }
[2079] 
[2080]         if (last) {
[2081]             u->buffer.last = last;
[2082]         }
[2083] 
[2084]         f->length -= u->buffer.pos - start;
[2085] 
[2086]         if (f->length == 0) {
[2087]             f->state = ngx_http_fastcgi_st_padding;
[2088]         }
[2089] 
[2090]         if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[2091]             return NGX_OK;
[2092]         }
[2093] 
[2094]         if (rc == NGX_OK) {
[2095]             continue;
[2096]         }
[2097] 
[2098]         /* rc == NGX_AGAIN */
[2099] 
[2100]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2101]                        "upstream split a header line in FastCGI records");
[2102] 
[2103]         if (f->split_parts == NULL) {
[2104]             f->split_parts = ngx_array_create(r->pool, 1,
[2105]                                         sizeof(ngx_http_fastcgi_split_part_t));
[2106]             if (f->split_parts == NULL) {
[2107]                 return NGX_ERROR;
[2108]             }
[2109]         }
[2110] 
[2111]         part = ngx_array_push(f->split_parts);
[2112]         if (part == NULL) {
[2113]             return NGX_ERROR;
[2114]         }
[2115] 
[2116]         part->start = part_start;
[2117]         part->end = part_end;
[2118] 
[2119]         if (u->buffer.pos < u->buffer.last) {
[2120]             continue;
[2121]         }
[2122] 
[2123]         return NGX_AGAIN;
[2124]     }
[2125] }
[2126] 
[2127] 
[2128] static ngx_int_t
[2129] ngx_http_fastcgi_input_filter_init(void *data)
[2130] {
[2131]     ngx_http_request_t  *r = data;
[2132] 
[2133]     ngx_http_upstream_t          *u;
[2134]     ngx_http_fastcgi_ctx_t       *f;
[2135]     ngx_http_fastcgi_loc_conf_t  *flcf;
[2136] 
[2137]     u = r->upstream;
[2138] 
[2139]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[2140]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[2141] 
[2142]     u->pipe->length = flcf->keep_conn ?
[2143]                       (off_t) sizeof(ngx_http_fastcgi_header_t) : -1;
[2144] 
[2145]     if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
[2146]         || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED)
[2147]     {
[2148]         f->rest = 0;
[2149] 
[2150]     } else if (r->method == NGX_HTTP_HEAD) {
[2151]         f->rest = -2;
[2152] 
[2153]     } else {
[2154]         f->rest = u->headers_in.content_length_n;
[2155]     }
[2156] 
[2157]     return NGX_OK;
[2158] }
[2159] 
[2160] 
[2161] static ngx_int_t
[2162] ngx_http_fastcgi_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
[2163] {
[2164]     u_char                       *m, *msg;
[2165]     ngx_int_t                     rc;
[2166]     ngx_buf_t                    *b, **prev;
[2167]     ngx_chain_t                  *cl;
[2168]     ngx_http_request_t           *r;
[2169]     ngx_http_fastcgi_ctx_t       *f;
[2170]     ngx_http_fastcgi_loc_conf_t  *flcf;
[2171] 
[2172]     if (buf->pos == buf->last) {
[2173]         return NGX_OK;
[2174]     }
[2175] 
[2176]     r = p->input_ctx;
[2177]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[2178]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[2179] 
[2180]     if (p->upstream_done || f->closed) {
[2181]         r->upstream->keepalive = 0;
[2182] 
[2183]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
[2184]                        "http fastcgi data after close");
[2185] 
[2186]         return NGX_OK;
[2187]     }
[2188] 
[2189]     b = NULL;
[2190]     prev = &buf->shadow;
[2191] 
[2192]     f->pos = buf->pos;
[2193]     f->last = buf->last;
[2194] 
[2195]     for ( ;; ) {
[2196]         if (f->state < ngx_http_fastcgi_st_data) {
[2197] 
[2198]             rc = ngx_http_fastcgi_process_record(r, f);
[2199] 
[2200]             if (rc == NGX_AGAIN) {
[2201]                 break;
[2202]             }
[2203] 
[2204]             if (rc == NGX_ERROR) {
[2205]                 return NGX_ERROR;
[2206]             }
[2207] 
[2208]             if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
[2209]                 f->state = ngx_http_fastcgi_st_padding;
[2210] 
[2211]                 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
[2212]                                "http fastcgi closed stdout");
[2213] 
[2214]                 if (f->rest > 0) {
[2215]                     ngx_log_error(NGX_LOG_ERR, p->log, 0,
[2216]                                   "upstream prematurely closed "
[2217]                                   "FastCGI stdout");
[2218] 
[2219]                     p->upstream_error = 1;
[2220]                     p->upstream_eof = 0;
[2221]                     f->closed = 1;
[2222] 
[2223]                     break;
[2224]                 }
[2225] 
[2226]                 if (!flcf->keep_conn) {
[2227]                     p->upstream_done = 1;
[2228]                 }
[2229] 
[2230]                 continue;
[2231]             }
[2232] 
[2233]             if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {
[2234] 
[2235]                 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, p->log, 0,
[2236]                                "http fastcgi sent end request");
[2237] 
[2238]                 if (f->rest > 0) {
[2239]                     ngx_log_error(NGX_LOG_ERR, p->log, 0,
[2240]                                   "upstream prematurely closed "
[2241]                                   "FastCGI request");
[2242] 
[2243]                     p->upstream_error = 1;
[2244]                     p->upstream_eof = 0;
[2245]                     f->closed = 1;
[2246] 
[2247]                     break;
[2248]                 }
[2249] 
[2250]                 if (!flcf->keep_conn) {
[2251]                     p->upstream_done = 1;
[2252]                     break;
[2253]                 }
[2254] 
[2255]                 continue;
[2256]             }
[2257]         }
[2258] 
[2259] 
[2260]         if (f->state == ngx_http_fastcgi_st_padding) {
[2261] 
[2262]             if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {
[2263] 
[2264]                 if (f->pos + f->padding < f->last) {
[2265]                     p->upstream_done = 1;
[2266]                     break;
[2267]                 }
[2268] 
[2269]                 if (f->pos + f->padding == f->last) {
[2270]                     p->upstream_done = 1;
[2271]                     r->upstream->keepalive = 1;
[2272]                     break;
[2273]                 }
[2274] 
[2275]                 f->padding -= f->last - f->pos;
[2276] 
[2277]                 break;
[2278]             }
[2279] 
[2280]             if (f->pos + f->padding < f->last) {
[2281]                 f->state = ngx_http_fastcgi_st_version;
[2282]                 f->pos += f->padding;
[2283] 
[2284]                 continue;
[2285]             }
[2286] 
[2287]             if (f->pos + f->padding == f->last) {
[2288]                 f->state = ngx_http_fastcgi_st_version;
[2289] 
[2290]                 break;
[2291]             }
[2292] 
[2293]             f->padding -= f->last - f->pos;
[2294] 
[2295]             break;
[2296]         }
[2297] 
[2298] 
[2299]         /* f->state == ngx_http_fastcgi_st_data */
[2300] 
[2301]         if (f->type == NGX_HTTP_FASTCGI_STDERR) {
[2302] 
[2303]             if (f->length) {
[2304] 
[2305]                 if (f->pos == f->last) {
[2306]                     break;
[2307]                 }
[2308] 
[2309]                 msg = f->pos;
[2310] 
[2311]                 if (f->pos + f->length <= f->last) {
[2312]                     f->pos += f->length;
[2313]                     f->length = 0;
[2314]                     f->state = ngx_http_fastcgi_st_padding;
[2315] 
[2316]                 } else {
[2317]                     f->length -= f->last - f->pos;
[2318]                     f->pos = f->last;
[2319]                 }
[2320] 
[2321]                 for (m = f->pos - 1; msg < m; m--) {
[2322]                     if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
[2323]                         break;
[2324]                     }
[2325]                 }
[2326] 
[2327]                 ngx_log_error(NGX_LOG_ERR, p->log, 0,
[2328]                               "FastCGI sent in stderr: \"%*s\"",
[2329]                               m + 1 - msg, msg);
[2330] 
[2331]             } else {
[2332]                 f->state = ngx_http_fastcgi_st_padding;
[2333]             }
[2334] 
[2335]             continue;
[2336]         }
[2337] 
[2338]         if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {
[2339] 
[2340]             if (f->pos + f->length <= f->last) {
[2341]                 f->state = ngx_http_fastcgi_st_padding;
[2342]                 f->pos += f->length;
[2343] 
[2344]                 continue;
[2345]             }
[2346] 
[2347]             f->length -= f->last - f->pos;
[2348] 
[2349]             break;
[2350]         }
[2351] 
[2352] 
[2353]         /* f->type == NGX_HTTP_FASTCGI_STDOUT */
[2354] 
[2355]         if (f->pos == f->last) {
[2356]             break;
[2357]         }
[2358] 
[2359]         if (f->rest == -2) {
[2360]             f->rest = r->upstream->headers_in.content_length_n;
[2361]         }
[2362] 
[2363]         if (f->rest == 0) {
[2364]             ngx_log_error(NGX_LOG_WARN, p->log, 0,
[2365]                           "upstream sent more data than specified in "
[2366]                           "\"Content-Length\" header");
[2367]             p->upstream_done = 1;
[2368]             break;
[2369]         }
[2370] 
[2371]         cl = ngx_chain_get_free_buf(p->pool, &p->free);
[2372]         if (cl == NULL) {
[2373]             return NGX_ERROR;
[2374]         }
[2375] 
[2376]         b = cl->buf;
[2377] 
[2378]         ngx_memzero(b, sizeof(ngx_buf_t));
[2379] 
[2380]         b->pos = f->pos;
[2381]         b->start = buf->start;
[2382]         b->end = buf->end;
[2383]         b->tag = p->tag;
[2384]         b->temporary = 1;
[2385]         b->recycled = 1;
[2386] 
[2387]         *prev = b;
[2388]         prev = &b->shadow;
[2389] 
[2390]         if (p->in) {
[2391]             *p->last_in = cl;
[2392]         } else {
[2393]             p->in = cl;
[2394]         }
[2395]         p->last_in = &cl->next;
[2396] 
[2397] 
[2398]         /* STUB */ b->num = buf->num;
[2399] 
[2400]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
[2401]                        "input buf #%d %p", b->num, b->pos);
[2402] 
[2403]         if (f->pos + f->length <= f->last) {
[2404]             f->state = ngx_http_fastcgi_st_padding;
[2405]             f->pos += f->length;
[2406]             b->last = f->pos;
[2407] 
[2408]         } else {
[2409]             f->length -= f->last - f->pos;
[2410]             f->pos = f->last;
[2411]             b->last = f->last;
[2412]         }
[2413] 
[2414]         if (f->rest > 0) {
[2415] 
[2416]             if (b->last - b->pos > f->rest) {
[2417]                 ngx_log_error(NGX_LOG_WARN, p->log, 0,
[2418]                               "upstream sent more data than specified in "
[2419]                               "\"Content-Length\" header");
[2420] 
[2421]                 b->last = b->pos + f->rest;
[2422]                 p->upstream_done = 1;
[2423] 
[2424]                 break;
[2425]             }
[2426] 
[2427]             f->rest -= b->last - b->pos;
[2428]         }
[2429]     }
[2430] 
[2431]     if (flcf->keep_conn) {
[2432] 
[2433]         /* set p->length, minimal amount of data we want to see */
[2434] 
[2435]         if (f->state < ngx_http_fastcgi_st_data) {
[2436]             p->length = 1;
[2437] 
[2438]         } else if (f->state == ngx_http_fastcgi_st_padding) {
[2439]             p->length = f->padding;
[2440] 
[2441]         } else {
[2442]             /* ngx_http_fastcgi_st_data */
[2443] 
[2444]             p->length = f->length;
[2445]         }
[2446]     }
[2447] 
[2448]     if (b) {
[2449]         b->shadow = buf;
[2450]         b->last_shadow = 1;
[2451] 
[2452]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
[2453]                        "input buf %p %z", b->pos, b->last - b->pos);
[2454] 
[2455]         return NGX_OK;
[2456]     }
[2457] 
[2458]     /* there is no data record in the buf, add it to free chain */
[2459] 
[2460]     if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
[2461]         return NGX_ERROR;
[2462]     }
[2463] 
[2464]     return NGX_OK;
[2465] }
[2466] 
[2467] 
[2468] static ngx_int_t
[2469] ngx_http_fastcgi_non_buffered_filter(void *data, ssize_t bytes)
[2470] {
[2471]     u_char                  *m, *msg;
[2472]     ngx_int_t                rc;
[2473]     ngx_buf_t               *b, *buf;
[2474]     ngx_chain_t             *cl, **ll;
[2475]     ngx_http_request_t      *r;
[2476]     ngx_http_upstream_t     *u;
[2477]     ngx_http_fastcgi_ctx_t  *f;
[2478] 
[2479]     r = data;
[2480]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[2481] 
[2482]     u = r->upstream;
[2483]     buf = &u->buffer;
[2484] 
[2485]     buf->pos = buf->last;
[2486]     buf->last += bytes;
[2487] 
[2488]     for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
[2489]         ll = &cl->next;
[2490]     }
[2491] 
[2492]     f->pos = buf->pos;
[2493]     f->last = buf->last;
[2494] 
[2495]     for ( ;; ) {
[2496]         if (f->state < ngx_http_fastcgi_st_data) {
[2497] 
[2498]             rc = ngx_http_fastcgi_process_record(r, f);
[2499] 
[2500]             if (rc == NGX_AGAIN) {
[2501]                 break;
[2502]             }
[2503] 
[2504]             if (rc == NGX_ERROR) {
[2505]                 return NGX_ERROR;
[2506]             }
[2507] 
[2508]             if (f->type == NGX_HTTP_FASTCGI_STDOUT && f->length == 0) {
[2509]                 f->state = ngx_http_fastcgi_st_padding;
[2510] 
[2511]                 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2512]                                "http fastcgi closed stdout");
[2513] 
[2514]                 continue;
[2515]             }
[2516]         }
[2517] 
[2518]         if (f->state == ngx_http_fastcgi_st_padding) {
[2519] 
[2520]             if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {
[2521] 
[2522]                 if (f->rest > 0) {
[2523]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2524]                                   "upstream prematurely closed "
[2525]                                   "FastCGI request");
[2526]                     u->error = 1;
[2527]                     break;
[2528]                 }
[2529] 
[2530]                 if (f->pos + f->padding < f->last) {
[2531]                     u->length = 0;
[2532]                     break;
[2533]                 }
[2534] 
[2535]                 if (f->pos + f->padding == f->last) {
[2536]                     u->length = 0;
[2537]                     u->keepalive = 1;
[2538]                     break;
[2539]                 }
[2540] 
[2541]                 f->padding -= f->last - f->pos;
[2542] 
[2543]                 break;
[2544]             }
[2545] 
[2546]             if (f->pos + f->padding < f->last) {
[2547]                 f->state = ngx_http_fastcgi_st_version;
[2548]                 f->pos += f->padding;
[2549] 
[2550]                 continue;
[2551]             }
[2552] 
[2553]             if (f->pos + f->padding == f->last) {
[2554]                 f->state = ngx_http_fastcgi_st_version;
[2555] 
[2556]                 break;
[2557]             }
[2558] 
[2559]             f->padding -= f->last - f->pos;
[2560] 
[2561]             break;
[2562]         }
[2563] 
[2564] 
[2565]         /* f->state == ngx_http_fastcgi_st_data */
[2566] 
[2567]         if (f->type == NGX_HTTP_FASTCGI_STDERR) {
[2568] 
[2569]             if (f->length) {
[2570] 
[2571]                 if (f->pos == f->last) {
[2572]                     break;
[2573]                 }
[2574] 
[2575]                 msg = f->pos;
[2576] 
[2577]                 if (f->pos + f->length <= f->last) {
[2578]                     f->pos += f->length;
[2579]                     f->length = 0;
[2580]                     f->state = ngx_http_fastcgi_st_padding;
[2581] 
[2582]                 } else {
[2583]                     f->length -= f->last - f->pos;
[2584]                     f->pos = f->last;
[2585]                 }
[2586] 
[2587]                 for (m = f->pos - 1; msg < m; m--) {
[2588]                     if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
[2589]                         break;
[2590]                     }
[2591]                 }
[2592] 
[2593]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2594]                               "FastCGI sent in stderr: \"%*s\"",
[2595]                               m + 1 - msg, msg);
[2596] 
[2597]             } else {
[2598]                 f->state = ngx_http_fastcgi_st_padding;
[2599]             }
[2600] 
[2601]             continue;
[2602]         }
[2603] 
[2604]         if (f->type == NGX_HTTP_FASTCGI_END_REQUEST) {
[2605] 
[2606]             if (f->pos + f->length <= f->last) {
[2607]                 f->state = ngx_http_fastcgi_st_padding;
[2608]                 f->pos += f->length;
[2609] 
[2610]                 continue;
[2611]             }
[2612] 
[2613]             f->length -= f->last - f->pos;
[2614] 
[2615]             break;
[2616]         }
[2617] 
[2618] 
[2619]         /* f->type == NGX_HTTP_FASTCGI_STDOUT */
[2620] 
[2621]         if (f->pos == f->last) {
[2622]             break;
[2623]         }
[2624] 
[2625]         if (f->rest == 0) {
[2626]             ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[2627]                           "upstream sent more data than specified in "
[2628]                           "\"Content-Length\" header");
[2629]             u->length = 0;
[2630]             break;
[2631]         }
[2632] 
[2633]         cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
[2634]         if (cl == NULL) {
[2635]             return NGX_ERROR;
[2636]         }
[2637] 
[2638]         *ll = cl;
[2639]         ll = &cl->next;
[2640] 
[2641]         b = cl->buf;
[2642] 
[2643]         b->flush = 1;
[2644]         b->memory = 1;
[2645] 
[2646]         b->pos = f->pos;
[2647]         b->tag = u->output.tag;
[2648] 
[2649]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2650]                        "http fastcgi output buf %p", b->pos);
[2651] 
[2652]         if (f->pos + f->length <= f->last) {
[2653]             f->state = ngx_http_fastcgi_st_padding;
[2654]             f->pos += f->length;
[2655]             b->last = f->pos;
[2656] 
[2657]         } else {
[2658]             f->length -= f->last - f->pos;
[2659]             f->pos = f->last;
[2660]             b->last = f->last;
[2661]         }
[2662] 
[2663]         if (f->rest > 0) {
[2664] 
[2665]             if (b->last - b->pos > f->rest) {
[2666]                 ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[2667]                               "upstream sent more data than specified in "
[2668]                               "\"Content-Length\" header");
[2669] 
[2670]                 b->last = b->pos + f->rest;
[2671]                 u->length = 0;
[2672] 
[2673]                 break;
[2674]             }
[2675] 
[2676]             f->rest -= b->last - b->pos;
[2677]         }
[2678]     }
[2679] 
[2680]     return NGX_OK;
[2681] }
[2682] 
[2683] 
[2684] static ngx_int_t
[2685] ngx_http_fastcgi_process_record(ngx_http_request_t *r,
[2686]     ngx_http_fastcgi_ctx_t *f)
[2687] {
[2688]     u_char                     ch, *p;
[2689]     ngx_http_fastcgi_state_e   state;
[2690] 
[2691]     state = f->state;
[2692] 
[2693]     for (p = f->pos; p < f->last; p++) {
[2694] 
[2695]         ch = *p;
[2696] 
[2697]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2698]                        "http fastcgi record byte: %02Xd", ch);
[2699] 
[2700]         switch (state) {
[2701] 
[2702]         case ngx_http_fastcgi_st_version:
[2703]             if (ch != 1) {
[2704]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2705]                               "upstream sent unsupported FastCGI "
[2706]                               "protocol version: %d", ch);
[2707]                 return NGX_ERROR;
[2708]             }
[2709]             state = ngx_http_fastcgi_st_type;
[2710]             break;
[2711] 
[2712]         case ngx_http_fastcgi_st_type:
[2713]             switch (ch) {
[2714]             case NGX_HTTP_FASTCGI_STDOUT:
[2715]             case NGX_HTTP_FASTCGI_STDERR:
[2716]             case NGX_HTTP_FASTCGI_END_REQUEST:
[2717]                 f->type = (ngx_uint_t) ch;
[2718]                 break;
[2719]             default:
[2720]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2721]                               "upstream sent invalid FastCGI "
[2722]                               "record type: %d", ch);
[2723]                 return NGX_ERROR;
[2724] 
[2725]             }
[2726]             state = ngx_http_fastcgi_st_request_id_hi;
[2727]             break;
[2728] 
[2729]         /* we support the single request per connection */
[2730] 
[2731]         case ngx_http_fastcgi_st_request_id_hi:
[2732]             if (ch != 0) {
[2733]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2734]                               "upstream sent unexpected FastCGI "
[2735]                               "request id high byte: %d", ch);
[2736]                 return NGX_ERROR;
[2737]             }
[2738]             state = ngx_http_fastcgi_st_request_id_lo;
[2739]             break;
[2740] 
[2741]         case ngx_http_fastcgi_st_request_id_lo:
[2742]             if (ch != 1) {
[2743]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2744]                               "upstream sent unexpected FastCGI "
[2745]                               "request id low byte: %d", ch);
[2746]                 return NGX_ERROR;
[2747]             }
[2748]             state = ngx_http_fastcgi_st_content_length_hi;
[2749]             break;
[2750] 
[2751]         case ngx_http_fastcgi_st_content_length_hi:
[2752]             f->length = ch << 8;
[2753]             state = ngx_http_fastcgi_st_content_length_lo;
[2754]             break;
[2755] 
[2756]         case ngx_http_fastcgi_st_content_length_lo:
[2757]             f->length |= (size_t) ch;
[2758]             state = ngx_http_fastcgi_st_padding_length;
[2759]             break;
[2760] 
[2761]         case ngx_http_fastcgi_st_padding_length:
[2762]             f->padding = (size_t) ch;
[2763]             state = ngx_http_fastcgi_st_reserved;
[2764]             break;
[2765] 
[2766]         case ngx_http_fastcgi_st_reserved:
[2767]             state = ngx_http_fastcgi_st_data;
[2768] 
[2769]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2770]                            "http fastcgi record length: %z", f->length);
[2771] 
[2772]             f->pos = p + 1;
[2773]             f->state = state;
[2774] 
[2775]             return NGX_OK;
[2776] 
[2777]         /* suppress warning */
[2778]         case ngx_http_fastcgi_st_data:
[2779]         case ngx_http_fastcgi_st_padding:
[2780]             break;
[2781]         }
[2782]     }
[2783] 
[2784]     f->pos = p;
[2785]     f->state = state;
[2786] 
[2787]     return NGX_AGAIN;
[2788] }
[2789] 
[2790] 
[2791] static void
[2792] ngx_http_fastcgi_abort_request(ngx_http_request_t *r)
[2793] {
[2794]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2795]                    "abort http fastcgi request");
[2796] 
[2797]     return;
[2798] }
[2799] 
[2800] 
[2801] static void
[2802] ngx_http_fastcgi_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[2803] {
[2804]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2805]                    "finalize http fastcgi request");
[2806] 
[2807]     return;
[2808] }
[2809] 
[2810] 
[2811] static ngx_int_t
[2812] ngx_http_fastcgi_add_variables(ngx_conf_t *cf)
[2813] {
[2814]     ngx_http_variable_t  *var, *v;
[2815] 
[2816]     for (v = ngx_http_fastcgi_vars; v->name.len; v++) {
[2817]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[2818]         if (var == NULL) {
[2819]             return NGX_ERROR;
[2820]         }
[2821] 
[2822]         var->get_handler = v->get_handler;
[2823]         var->data = v->data;
[2824]     }
[2825] 
[2826]     return NGX_OK;
[2827] }
[2828] 
[2829] 
[2830] static void *
[2831] ngx_http_fastcgi_create_main_conf(ngx_conf_t *cf)
[2832] {
[2833]     ngx_http_fastcgi_main_conf_t  *conf;
[2834] 
[2835]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastcgi_main_conf_t));
[2836]     if (conf == NULL) {
[2837]         return NULL;
[2838]     }
[2839] 
[2840] #if (NGX_HTTP_CACHE)
[2841]     if (ngx_array_init(&conf->caches, cf->pool, 4,
[2842]                        sizeof(ngx_http_file_cache_t *))
[2843]         != NGX_OK)
[2844]     {
[2845]         return NULL;
[2846]     }
[2847] #endif
[2848] 
[2849]     return conf;
[2850] }
[2851] 
[2852] 
[2853] static void *
[2854] ngx_http_fastcgi_create_loc_conf(ngx_conf_t *cf)
[2855] {
[2856]     ngx_http_fastcgi_loc_conf_t  *conf;
[2857] 
[2858]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fastcgi_loc_conf_t));
[2859]     if (conf == NULL) {
[2860]         return NULL;
[2861]     }
[2862] 
[2863]     /*
[2864]      * set by ngx_pcalloc():
[2865]      *
[2866]      *     conf->upstream.bufs.num = 0;
[2867]      *     conf->upstream.ignore_headers = 0;
[2868]      *     conf->upstream.next_upstream = 0;
[2869]      *     conf->upstream.cache_zone = NULL;
[2870]      *     conf->upstream.cache_use_stale = 0;
[2871]      *     conf->upstream.cache_methods = 0;
[2872]      *     conf->upstream.temp_path = NULL;
[2873]      *     conf->upstream.hide_headers_hash = { NULL, 0 };
[2874]      *     conf->upstream.store_lengths = NULL;
[2875]      *     conf->upstream.store_values = NULL;
[2876]      *
[2877]      *     conf->index.len = { 0, NULL };
[2878]      */
[2879] 
[2880]     conf->upstream.store = NGX_CONF_UNSET;
[2881]     conf->upstream.store_access = NGX_CONF_UNSET_UINT;
[2882]     conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
[2883]     conf->upstream.buffering = NGX_CONF_UNSET;
[2884]     conf->upstream.request_buffering = NGX_CONF_UNSET;
[2885]     conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
[2886]     conf->upstream.force_ranges = NGX_CONF_UNSET;
[2887] 
[2888]     conf->upstream.local = NGX_CONF_UNSET_PTR;
[2889]     conf->upstream.socket_keepalive = NGX_CONF_UNSET;
[2890] 
[2891]     conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
[2892]     conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
[2893]     conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
[2894]     conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[2895] 
[2896]     conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
[2897]     conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
[2898]     conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
[2899] 
[2900]     conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
[2901]     conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
[2902]     conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
[2903] 
[2904]     conf->upstream.pass_request_headers = NGX_CONF_UNSET;
[2905]     conf->upstream.pass_request_body = NGX_CONF_UNSET;
[2906] 
[2907] #if (NGX_HTTP_CACHE)
[2908]     conf->upstream.cache = NGX_CONF_UNSET;
[2909]     conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
[2910]     conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
[2911]     conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
[2912]     conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
[2913]     conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
[2914]     conf->upstream.cache_lock = NGX_CONF_UNSET;
[2915]     conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
[2916]     conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
[2917]     conf->upstream.cache_revalidate = NGX_CONF_UNSET;
[2918]     conf->upstream.cache_background_update = NGX_CONF_UNSET;
[2919] #endif
[2920] 
[2921]     conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
[2922]     conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
[2923] 
[2924]     conf->upstream.intercept_errors = NGX_CONF_UNSET;
[2925] 
[2926]     /* "fastcgi_cyclic_temp_file" is disabled */
[2927]     conf->upstream.cyclic_temp_file = 0;
[2928] 
[2929]     conf->upstream.change_buffering = 1;
[2930] 
[2931]     conf->catch_stderr = NGX_CONF_UNSET_PTR;
[2932] 
[2933]     conf->keep_conn = NGX_CONF_UNSET;
[2934] 
[2935]     ngx_str_set(&conf->upstream.module, "fastcgi");
[2936] 
[2937]     return conf;
[2938] }
[2939] 
[2940] 
[2941] static char *
[2942] ngx_http_fastcgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[2943] {
[2944]     ngx_http_fastcgi_loc_conf_t *prev = parent;
[2945]     ngx_http_fastcgi_loc_conf_t *conf = child;
[2946] 
[2947]     size_t                        size;
[2948]     ngx_int_t                     rc;
[2949]     ngx_hash_init_t               hash;
[2950]     ngx_http_core_loc_conf_t     *clcf;
[2951] 
[2952] #if (NGX_HTTP_CACHE)
[2953] 
[2954]     if (conf->upstream.store > 0) {
[2955]         conf->upstream.cache = 0;
[2956]     }
[2957] 
[2958]     if (conf->upstream.cache > 0) {
[2959]         conf->upstream.store = 0;
[2960]     }
[2961] 
[2962] #endif
[2963] 
[2964]     if (conf->upstream.store == NGX_CONF_UNSET) {
[2965]         ngx_conf_merge_value(conf->upstream.store,
[2966]                               prev->upstream.store, 0);
[2967] 
[2968]         conf->upstream.store_lengths = prev->upstream.store_lengths;
[2969]         conf->upstream.store_values = prev->upstream.store_values;
[2970]     }
[2971] 
[2972]     ngx_conf_merge_uint_value(conf->upstream.store_access,
[2973]                               prev->upstream.store_access, 0600);
[2974] 
[2975]     ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
[2976]                               prev->upstream.next_upstream_tries, 0);
[2977] 
[2978]     ngx_conf_merge_value(conf->upstream.buffering,
[2979]                               prev->upstream.buffering, 1);
[2980] 
[2981]     ngx_conf_merge_value(conf->upstream.request_buffering,
[2982]                               prev->upstream.request_buffering, 1);
[2983] 
[2984]     ngx_conf_merge_value(conf->upstream.ignore_client_abort,
[2985]                               prev->upstream.ignore_client_abort, 0);
[2986] 
[2987]     ngx_conf_merge_value(conf->upstream.force_ranges,
[2988]                               prev->upstream.force_ranges, 0);
[2989] 
[2990]     ngx_conf_merge_ptr_value(conf->upstream.local,
[2991]                               prev->upstream.local, NULL);
[2992] 
[2993]     ngx_conf_merge_value(conf->upstream.socket_keepalive,
[2994]                               prev->upstream.socket_keepalive, 0);
[2995] 
[2996]     ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
[2997]                               prev->upstream.connect_timeout, 60000);
[2998] 
[2999]     ngx_conf_merge_msec_value(conf->upstream.send_timeout,
[3000]                               prev->upstream.send_timeout, 60000);
[3001] 
[3002]     ngx_conf_merge_msec_value(conf->upstream.read_timeout,
[3003]                               prev->upstream.read_timeout, 60000);
[3004] 
[3005]     ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
[3006]                               prev->upstream.next_upstream_timeout, 0);
[3007] 
[3008]     ngx_conf_merge_size_value(conf->upstream.send_lowat,
[3009]                               prev->upstream.send_lowat, 0);
[3010] 
[3011]     ngx_conf_merge_size_value(conf->upstream.buffer_size,
[3012]                               prev->upstream.buffer_size,
[3013]                               (size_t) ngx_pagesize);
[3014] 
[3015]     ngx_conf_merge_size_value(conf->upstream.limit_rate,
[3016]                               prev->upstream.limit_rate, 0);
[3017] 
[3018] 
[3019]     ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
[3020]                               8, ngx_pagesize);
[3021] 
[3022]     if (conf->upstream.bufs.num < 2) {
[3023]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3024]                            "there must be at least 2 \"fastcgi_buffers\"");
[3025]         return NGX_CONF_ERROR;
[3026]     }
[3027] 
[3028] 
[3029]     size = conf->upstream.buffer_size;
[3030]     if (size < conf->upstream.bufs.size) {
[3031]         size = conf->upstream.bufs.size;
[3032]     }
[3033] 
[3034] 
[3035]     ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
[3036]                               prev->upstream.busy_buffers_size_conf,
[3037]                               NGX_CONF_UNSET_SIZE);
[3038] 
[3039]     if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
[3040]         conf->upstream.busy_buffers_size = 2 * size;
[3041]     } else {
[3042]         conf->upstream.busy_buffers_size =
[3043]                                          conf->upstream.busy_buffers_size_conf;
[3044]     }
[3045] 
[3046]     if (conf->upstream.busy_buffers_size < size) {
[3047]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3048]              "\"fastcgi_busy_buffers_size\" must be equal to or greater than "
[3049]              "the maximum of the value of \"fastcgi_buffer_size\" and "
[3050]              "one of the \"fastcgi_buffers\"");
[3051] 
[3052]         return NGX_CONF_ERROR;
[3053]     }
[3054] 
[3055]     if (conf->upstream.busy_buffers_size
[3056]         > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
[3057]     {
[3058]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3059]              "\"fastcgi_busy_buffers_size\" must be less than "
[3060]              "the size of all \"fastcgi_buffers\" minus one buffer");
[3061] 
[3062]         return NGX_CONF_ERROR;
[3063]     }
[3064] 
[3065] 
[3066]     ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
[3067]                               prev->upstream.temp_file_write_size_conf,
[3068]                               NGX_CONF_UNSET_SIZE);
[3069] 
[3070]     if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
[3071]         conf->upstream.temp_file_write_size = 2 * size;
[3072]     } else {
[3073]         conf->upstream.temp_file_write_size =
[3074]                                       conf->upstream.temp_file_write_size_conf;
[3075]     }
[3076] 
[3077]     if (conf->upstream.temp_file_write_size < size) {
[3078]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3079]              "\"fastcgi_temp_file_write_size\" must be equal to or greater "
[3080]              "than the maximum of the value of \"fastcgi_buffer_size\" and "
[3081]              "one of the \"fastcgi_buffers\"");
[3082] 
[3083]         return NGX_CONF_ERROR;
[3084]     }
[3085] 
[3086] 
[3087]     ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
[3088]                               prev->upstream.max_temp_file_size_conf,
[3089]                               NGX_CONF_UNSET_SIZE);
[3090] 
[3091]     if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
[3092]         conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
[3093]     } else {
[3094]         conf->upstream.max_temp_file_size =
[3095]                                         conf->upstream.max_temp_file_size_conf;
[3096]     }
[3097] 
[3098]     if (conf->upstream.max_temp_file_size != 0
[3099]         && conf->upstream.max_temp_file_size < size)
[3100]     {
[3101]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3102]              "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
[3103]              "temporary files usage or must be equal to or greater than "
[3104]              "the maximum of the value of \"fastcgi_buffer_size\" and "
[3105]              "one of the \"fastcgi_buffers\"");
[3106] 
[3107]         return NGX_CONF_ERROR;
[3108]     }
[3109] 
[3110] 
[3111]     ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
[3112]                               prev->upstream.ignore_headers,
[3113]                               NGX_CONF_BITMASK_SET);
[3114] 
[3115] 
[3116]     ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
[3117]                               prev->upstream.next_upstream,
[3118]                               (NGX_CONF_BITMASK_SET
[3119]                                |NGX_HTTP_UPSTREAM_FT_ERROR
[3120]                                |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
[3121] 
[3122]     if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
[3123]         conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
[3124]                                        |NGX_HTTP_UPSTREAM_FT_OFF;
[3125]     }
[3126] 
[3127]     if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
[3128]                               prev->upstream.temp_path,
[3129]                               &ngx_http_fastcgi_temp_path)
[3130]         != NGX_OK)
[3131]     {
[3132]         return NGX_CONF_ERROR;
[3133]     }
[3134] 
[3135] #if (NGX_HTTP_CACHE)
[3136] 
[3137]     if (conf->upstream.cache == NGX_CONF_UNSET) {
[3138]         ngx_conf_merge_value(conf->upstream.cache,
[3139]                               prev->upstream.cache, 0);
[3140] 
[3141]         conf->upstream.cache_zone = prev->upstream.cache_zone;
[3142]         conf->upstream.cache_value = prev->upstream.cache_value;
[3143]     }
[3144] 
[3145]     if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
[3146]         ngx_shm_zone_t  *shm_zone;
[3147] 
[3148]         shm_zone = conf->upstream.cache_zone;
[3149] 
[3150]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3151]                            "\"fastcgi_cache\" zone \"%V\" is unknown",
[3152]                            &shm_zone->shm.name);
[3153] 
[3154]         return NGX_CONF_ERROR;
[3155]     }
[3156] 
[3157]     ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
[3158]                               prev->upstream.cache_min_uses, 1);
[3159] 
[3160]     ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
[3161]                               prev->upstream.cache_max_range_offset,
[3162]                               NGX_MAX_OFF_T_VALUE);
[3163] 
[3164]     ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
[3165]                               prev->upstream.cache_use_stale,
[3166]                               (NGX_CONF_BITMASK_SET
[3167]                                |NGX_HTTP_UPSTREAM_FT_OFF));
[3168] 
[3169]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
[3170]         conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
[3171]                                          |NGX_HTTP_UPSTREAM_FT_OFF;
[3172]     }
[3173] 
[3174]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
[3175]         conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
[3176]     }
[3177] 
[3178]     if (conf->upstream.cache_methods == 0) {
[3179]         conf->upstream.cache_methods = prev->upstream.cache_methods;
[3180]     }
[3181] 
[3182]     conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;
[3183] 
[3184]     ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
[3185]                              prev->upstream.cache_bypass, NULL);
[3186] 
[3187]     ngx_conf_merge_ptr_value(conf->upstream.no_cache,
[3188]                              prev->upstream.no_cache, NULL);
[3189] 
[3190]     ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
[3191]                              prev->upstream.cache_valid, NULL);
[3192] 
[3193]     if (conf->cache_key.value.data == NULL) {
[3194]         conf->cache_key = prev->cache_key;
[3195]     }
[3196] 
[3197]     if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
[3198]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[3199]                            "no \"fastcgi_cache_key\" for \"fastcgi_cache\"");
[3200]     }
[3201] 
[3202]     ngx_conf_merge_value(conf->upstream.cache_lock,
[3203]                               prev->upstream.cache_lock, 0);
[3204] 
[3205]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
[3206]                               prev->upstream.cache_lock_timeout, 5000);
[3207] 
[3208]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
[3209]                               prev->upstream.cache_lock_age, 5000);
[3210] 
[3211]     ngx_conf_merge_value(conf->upstream.cache_revalidate,
[3212]                               prev->upstream.cache_revalidate, 0);
[3213] 
[3214]     ngx_conf_merge_value(conf->upstream.cache_background_update,
[3215]                               prev->upstream.cache_background_update, 0);
[3216] 
[3217] #endif
[3218] 
[3219]     ngx_conf_merge_value(conf->upstream.pass_request_headers,
[3220]                               prev->upstream.pass_request_headers, 1);
[3221]     ngx_conf_merge_value(conf->upstream.pass_request_body,
[3222]                               prev->upstream.pass_request_body, 1);
[3223] 
[3224]     ngx_conf_merge_value(conf->upstream.intercept_errors,
[3225]                               prev->upstream.intercept_errors, 0);
[3226] 
[3227]     ngx_conf_merge_ptr_value(conf->catch_stderr, prev->catch_stderr, NULL);
[3228] 
[3229]     ngx_conf_merge_value(conf->keep_conn, prev->keep_conn, 0);
[3230] 
[3231] 
[3232]     ngx_conf_merge_str_value(conf->index, prev->index, "");
[3233] 
[3234]     hash.max_size = 512;
[3235]     hash.bucket_size = ngx_align(64, ngx_cacheline_size);
[3236]     hash.name = "fastcgi_hide_headers_hash";
[3237] 
[3238]     if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
[3239]              &prev->upstream, ngx_http_fastcgi_hide_headers, &hash)
[3240]         != NGX_OK)
[3241]     {
[3242]         return NGX_CONF_ERROR;
[3243]     }
[3244] 
[3245]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[3246] 
[3247]     if (clcf->noname
[3248]         && conf->upstream.upstream == NULL && conf->fastcgi_lengths == NULL)
[3249]     {
[3250]         conf->upstream.upstream = prev->upstream.upstream;
[3251]         conf->fastcgi_lengths = prev->fastcgi_lengths;
[3252]         conf->fastcgi_values = prev->fastcgi_values;
[3253]     }
[3254] 
[3255]     if (clcf->lmt_excpt && clcf->handler == NULL
[3256]         && (conf->upstream.upstream || conf->fastcgi_lengths))
[3257]     {
[3258]         clcf->handler = ngx_http_fastcgi_handler;
[3259]     }
[3260] 
[3261] #if (NGX_PCRE)
[3262]     if (conf->split_regex == NULL) {
[3263]         conf->split_regex = prev->split_regex;
[3264]         conf->split_name = prev->split_name;
[3265]     }
[3266] #endif
[3267] 
[3268]     if (conf->params_source == NULL) {
[3269]         conf->params = prev->params;
[3270] #if (NGX_HTTP_CACHE)
[3271]         conf->params_cache = prev->params_cache;
[3272] #endif
[3273]         conf->params_source = prev->params_source;
[3274]     }
[3275] 
[3276]     rc = ngx_http_fastcgi_init_params(cf, conf, &conf->params, NULL);
[3277]     if (rc != NGX_OK) {
[3278]         return NGX_CONF_ERROR;
[3279]     }
[3280] 
[3281] #if (NGX_HTTP_CACHE)
[3282] 
[3283]     if (conf->upstream.cache) {
[3284]         rc = ngx_http_fastcgi_init_params(cf, conf, &conf->params_cache,
[3285]                                           ngx_http_fastcgi_cache_headers);
[3286]         if (rc != NGX_OK) {
[3287]             return NGX_CONF_ERROR;
[3288]         }
[3289]     }
[3290] 
[3291] #endif
[3292] 
[3293]     /*
[3294]      * special handling to preserve conf->params in the "http" section
[3295]      * to inherit it to all servers
[3296]      */
[3297] 
[3298]     if (prev->params.hash.buckets == NULL
[3299]         && conf->params_source == prev->params_source)
[3300]     {
[3301]         prev->params = conf->params;
[3302] #if (NGX_HTTP_CACHE)
[3303]         prev->params_cache = conf->params_cache;
[3304] #endif
[3305]     }
[3306] 
[3307]     return NGX_CONF_OK;
[3308] }
[3309] 
[3310] 
[3311] static ngx_int_t
[3312] ngx_http_fastcgi_init_params(ngx_conf_t *cf, ngx_http_fastcgi_loc_conf_t *conf,
[3313]     ngx_http_fastcgi_params_t *params, ngx_keyval_t *default_params)
[3314] {
[3315]     u_char                       *p;
[3316]     size_t                        size;
[3317]     uintptr_t                    *code;
[3318]     ngx_uint_t                    i, nsrc;
[3319]     ngx_array_t                   headers_names, params_merged;
[3320]     ngx_keyval_t                 *h;
[3321]     ngx_hash_key_t               *hk;
[3322]     ngx_hash_init_t               hash;
[3323]     ngx_http_upstream_param_t    *src, *s;
[3324]     ngx_http_script_compile_t     sc;
[3325]     ngx_http_script_copy_code_t  *copy;
[3326] 
[3327]     if (params->hash.buckets) {
[3328]         return NGX_OK;
[3329]     }
[3330] 
[3331]     if (conf->params_source == NULL && default_params == NULL) {
[3332]         params->hash.buckets = (void *) 1;
[3333]         return NGX_OK;
[3334]     }
[3335] 
[3336]     params->lengths = ngx_array_create(cf->pool, 64, 1);
[3337]     if (params->lengths == NULL) {
[3338]         return NGX_ERROR;
[3339]     }
[3340] 
[3341]     params->values = ngx_array_create(cf->pool, 512, 1);
[3342]     if (params->values == NULL) {
[3343]         return NGX_ERROR;
[3344]     }
[3345] 
[3346]     if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
[3347]         != NGX_OK)
[3348]     {
[3349]         return NGX_ERROR;
[3350]     }
[3351] 
[3352]     if (conf->params_source) {
[3353]         src = conf->params_source->elts;
[3354]         nsrc = conf->params_source->nelts;
[3355] 
[3356]     } else {
[3357]         src = NULL;
[3358]         nsrc = 0;
[3359]     }
[3360] 
[3361]     if (default_params) {
[3362]         if (ngx_array_init(&params_merged, cf->temp_pool, 4,
[3363]                            sizeof(ngx_http_upstream_param_t))
[3364]             != NGX_OK)
[3365]         {
[3366]             return NGX_ERROR;
[3367]         }
[3368] 
[3369]         for (i = 0; i < nsrc; i++) {
[3370] 
[3371]             s = ngx_array_push(&params_merged);
[3372]             if (s == NULL) {
[3373]                 return NGX_ERROR;
[3374]             }
[3375] 
[3376]             *s = src[i];
[3377]         }
[3378] 
[3379]         h = default_params;
[3380] 
[3381]         while (h->key.len) {
[3382] 
[3383]             src = params_merged.elts;
[3384]             nsrc = params_merged.nelts;
[3385] 
[3386]             for (i = 0; i < nsrc; i++) {
[3387]                 if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
[3388]                     goto next;
[3389]                 }
[3390]             }
[3391] 
[3392]             s = ngx_array_push(&params_merged);
[3393]             if (s == NULL) {
[3394]                 return NGX_ERROR;
[3395]             }
[3396] 
[3397]             s->key = h->key;
[3398]             s->value = h->value;
[3399]             s->skip_empty = 1;
[3400] 
[3401]         next:
[3402] 
[3403]             h++;
[3404]         }
[3405] 
[3406]         src = params_merged.elts;
[3407]         nsrc = params_merged.nelts;
[3408]     }
[3409] 
[3410]     for (i = 0; i < nsrc; i++) {
[3411] 
[3412]         if (src[i].key.len > sizeof("HTTP_") - 1
[3413]             && ngx_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
[3414]         {
[3415]             hk = ngx_array_push(&headers_names);
[3416]             if (hk == NULL) {
[3417]                 return NGX_ERROR;
[3418]             }
[3419] 
[3420]             hk->key.len = src[i].key.len - 5;
[3421]             hk->key.data = src[i].key.data + 5;
[3422]             hk->key_hash = ngx_hash_key_lc(hk->key.data, hk->key.len);
[3423]             hk->value = (void *) 1;
[3424] 
[3425]             if (src[i].value.len == 0) {
[3426]                 continue;
[3427]             }
[3428]         }
[3429] 
[3430]         copy = ngx_array_push_n(params->lengths,
[3431]                                 sizeof(ngx_http_script_copy_code_t));
[3432]         if (copy == NULL) {
[3433]             return NGX_ERROR;
[3434]         }
[3435] 
[3436]         copy->code = (ngx_http_script_code_pt) (void *)
[3437]                                                  ngx_http_script_copy_len_code;
[3438]         copy->len = src[i].key.len;
[3439] 
[3440]         copy = ngx_array_push_n(params->lengths,
[3441]                                 sizeof(ngx_http_script_copy_code_t));
[3442]         if (copy == NULL) {
[3443]             return NGX_ERROR;
[3444]         }
[3445] 
[3446]         copy->code = (ngx_http_script_code_pt) (void *)
[3447]                                                  ngx_http_script_copy_len_code;
[3448]         copy->len = src[i].skip_empty;
[3449] 
[3450] 
[3451]         size = (sizeof(ngx_http_script_copy_code_t)
[3452]                 + src[i].key.len + sizeof(uintptr_t) - 1)
[3453]                & ~(sizeof(uintptr_t) - 1);
[3454] 
[3455]         copy = ngx_array_push_n(params->values, size);
[3456]         if (copy == NULL) {
[3457]             return NGX_ERROR;
[3458]         }
[3459] 
[3460]         copy->code = ngx_http_script_copy_code;
[3461]         copy->len = src[i].key.len;
[3462] 
[3463]         p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
[3464]         ngx_memcpy(p, src[i].key.data, src[i].key.len);
[3465] 
[3466] 
[3467]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[3468] 
[3469]         sc.cf = cf;
[3470]         sc.source = &src[i].value;
[3471]         sc.flushes = &params->flushes;
[3472]         sc.lengths = &params->lengths;
[3473]         sc.values = &params->values;
[3474] 
[3475]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[3476]             return NGX_ERROR;
[3477]         }
[3478] 
[3479]         code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
[3480]         if (code == NULL) {
[3481]             return NGX_ERROR;
[3482]         }
[3483] 
[3484]         *code = (uintptr_t) NULL;
[3485] 
[3486] 
[3487]         code = ngx_array_push_n(params->values, sizeof(uintptr_t));
[3488]         if (code == NULL) {
[3489]             return NGX_ERROR;
[3490]         }
[3491] 
[3492]         *code = (uintptr_t) NULL;
[3493]     }
[3494] 
[3495]     code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
[3496]     if (code == NULL) {
[3497]         return NGX_ERROR;
[3498]     }
[3499] 
[3500]     *code = (uintptr_t) NULL;
[3501] 
[3502]     params->number = headers_names.nelts;
[3503] 
[3504]     hash.hash = &params->hash;
[3505]     hash.key = ngx_hash_key_lc;
[3506]     hash.max_size = 512;
[3507]     hash.bucket_size = 64;
[3508]     hash.name = "fastcgi_params_hash";
[3509]     hash.pool = cf->pool;
[3510]     hash.temp_pool = NULL;
[3511] 
[3512]     return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
[3513] }
[3514] 
[3515] 
[3516] static ngx_int_t
[3517] ngx_http_fastcgi_script_name_variable(ngx_http_request_t *r,
[3518]     ngx_http_variable_value_t *v, uintptr_t data)
[3519] {
[3520]     u_char                       *p;
[3521]     ngx_http_fastcgi_ctx_t       *f;
[3522]     ngx_http_fastcgi_loc_conf_t  *flcf;
[3523] 
[3524]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[3525] 
[3526]     f = ngx_http_fastcgi_split(r, flcf);
[3527] 
[3528]     if (f == NULL) {
[3529]         return NGX_ERROR;
[3530]     }
[3531] 
[3532]     if (f->script_name.len == 0
[3533]         || f->script_name.data[f->script_name.len - 1] != '/')
[3534]     {
[3535]         v->len = f->script_name.len;
[3536]         v->valid = 1;
[3537]         v->no_cacheable = 0;
[3538]         v->not_found = 0;
[3539]         v->data = f->script_name.data;
[3540] 
[3541]         return NGX_OK;
[3542]     }
[3543] 
[3544]     v->len = f->script_name.len + flcf->index.len;
[3545] 
[3546]     v->data = ngx_pnalloc(r->pool, v->len);
[3547]     if (v->data == NULL) {
[3548]         return NGX_ERROR;
[3549]     }
[3550] 
[3551]     p = ngx_copy(v->data, f->script_name.data, f->script_name.len);
[3552]     ngx_memcpy(p, flcf->index.data, flcf->index.len);
[3553] 
[3554]     return NGX_OK;
[3555] }
[3556] 
[3557] 
[3558] static ngx_int_t
[3559] ngx_http_fastcgi_path_info_variable(ngx_http_request_t *r,
[3560]     ngx_http_variable_value_t *v, uintptr_t data)
[3561] {
[3562]     ngx_http_fastcgi_ctx_t       *f;
[3563]     ngx_http_fastcgi_loc_conf_t  *flcf;
[3564] 
[3565]     flcf = ngx_http_get_module_loc_conf(r, ngx_http_fastcgi_module);
[3566] 
[3567]     f = ngx_http_fastcgi_split(r, flcf);
[3568] 
[3569]     if (f == NULL) {
[3570]         return NGX_ERROR;
[3571]     }
[3572] 
[3573]     v->len = f->path_info.len;
[3574]     v->valid = 1;
[3575]     v->no_cacheable = 0;
[3576]     v->not_found = 0;
[3577]     v->data = f->path_info.data;
[3578] 
[3579]     return NGX_OK;
[3580] }
[3581] 
[3582] 
[3583] static ngx_http_fastcgi_ctx_t *
[3584] ngx_http_fastcgi_split(ngx_http_request_t *r, ngx_http_fastcgi_loc_conf_t *flcf)
[3585] {
[3586]     ngx_http_fastcgi_ctx_t       *f;
[3587] #if (NGX_PCRE)
[3588]     ngx_int_t                     n;
[3589]     int                           captures[(1 + 2) * 3];
[3590] 
[3591]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[3592] 
[3593]     if (f == NULL) {
[3594]         f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t));
[3595]         if (f == NULL) {
[3596]             return NULL;
[3597]         }
[3598] 
[3599]         ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);
[3600]     }
[3601] 
[3602]     if (f->script_name.len) {
[3603]         return f;
[3604]     }
[3605] 
[3606]     if (flcf->split_regex == NULL) {
[3607]         f->script_name = r->uri;
[3608]         return f;
[3609]     }
[3610] 
[3611]     n = ngx_regex_exec(flcf->split_regex, &r->uri, captures, (1 + 2) * 3);
[3612] 
[3613]     if (n >= 0) { /* match */
[3614]         f->script_name.len = captures[3] - captures[2];
[3615]         f->script_name.data = r->uri.data + captures[2];
[3616] 
[3617]         f->path_info.len = captures[5] - captures[4];
[3618]         f->path_info.data = r->uri.data + captures[4];
[3619] 
[3620]         return f;
[3621]     }
[3622] 
[3623]     if (n == NGX_REGEX_NO_MATCHED) {
[3624]         f->script_name = r->uri;
[3625]         return f;
[3626]     }
[3627] 
[3628]     ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[3629]                   ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
[3630]                   n, &r->uri, &flcf->split_name);
[3631]     return NULL;
[3632] 
[3633] #else
[3634] 
[3635]     f = ngx_http_get_module_ctx(r, ngx_http_fastcgi_module);
[3636] 
[3637]     if (f == NULL) {
[3638]         f = ngx_pcalloc(r->pool, sizeof(ngx_http_fastcgi_ctx_t));
[3639]         if (f == NULL) {
[3640]             return NULL;
[3641]         }
[3642] 
[3643]         ngx_http_set_ctx(r, f, ngx_http_fastcgi_module);
[3644]     }
[3645] 
[3646]     f->script_name = r->uri;
[3647] 
[3648]     return f;
[3649] 
[3650] #endif
[3651] }
[3652] 
[3653] 
[3654] static char *
[3655] ngx_http_fastcgi_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3656] {
[3657]     ngx_http_fastcgi_loc_conf_t *flcf = conf;
[3658] 
[3659]     ngx_url_t                   u;
[3660]     ngx_str_t                  *value, *url;
[3661]     ngx_uint_t                  n;
[3662]     ngx_http_core_loc_conf_t   *clcf;
[3663]     ngx_http_script_compile_t   sc;
[3664] 
[3665]     if (flcf->upstream.upstream || flcf->fastcgi_lengths) {
[3666]         return "is duplicate";
[3667]     }
[3668] 
[3669]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[3670] 
[3671]     clcf->handler = ngx_http_fastcgi_handler;
[3672] 
[3673]     if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
[3674]         clcf->auto_redirect = 1;
[3675]     }
[3676] 
[3677]     value = cf->args->elts;
[3678] 
[3679]     url = &value[1];
[3680] 
[3681]     n = ngx_http_script_variables_count(url);
[3682] 
[3683]     if (n) {
[3684] 
[3685]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[3686] 
[3687]         sc.cf = cf;
[3688]         sc.source = url;
[3689]         sc.lengths = &flcf->fastcgi_lengths;
[3690]         sc.values = &flcf->fastcgi_values;
[3691]         sc.variables = n;
[3692]         sc.complete_lengths = 1;
[3693]         sc.complete_values = 1;
[3694] 
[3695]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[3696]             return NGX_CONF_ERROR;
[3697]         }
[3698] 
[3699]         return NGX_CONF_OK;
[3700]     }
[3701] 
[3702]     ngx_memzero(&u, sizeof(ngx_url_t));
[3703] 
[3704]     u.url = value[1];
[3705]     u.no_resolve = 1;
[3706] 
[3707]     flcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
[3708]     if (flcf->upstream.upstream == NULL) {
[3709]         return NGX_CONF_ERROR;
[3710]     }
[3711] 
[3712]     return NGX_CONF_OK;
[3713] }
[3714] 
[3715] 
[3716] static char *
[3717] ngx_http_fastcgi_split_path_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3718] {
[3719] #if (NGX_PCRE)
[3720]     ngx_http_fastcgi_loc_conf_t *flcf = conf;
[3721] 
[3722]     ngx_str_t            *value;
[3723]     ngx_regex_compile_t   rc;
[3724]     u_char                errstr[NGX_MAX_CONF_ERRSTR];
[3725] 
[3726]     value = cf->args->elts;
[3727] 
[3728]     flcf->split_name = value[1];
[3729] 
[3730]     ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[3731] 
[3732]     rc.pattern = value[1];
[3733]     rc.pool = cf->pool;
[3734]     rc.err.len = NGX_MAX_CONF_ERRSTR;
[3735]     rc.err.data = errstr;
[3736] 
[3737]     if (ngx_regex_compile(&rc) != NGX_OK) {
[3738]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
[3739]         return NGX_CONF_ERROR;
[3740]     }
[3741] 
[3742]     if (rc.captures != 2) {
[3743]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3744]                            "pattern \"%V\" must have 2 captures", &value[1]);
[3745]         return NGX_CONF_ERROR;
[3746]     }
[3747] 
[3748]     flcf->split_regex = rc.regex;
[3749] 
[3750]     return NGX_CONF_OK;
[3751] 
[3752] #else
[3753] 
[3754]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3755]                        "\"%V\" requires PCRE library", &cmd->name);
[3756]     return NGX_CONF_ERROR;
[3757] 
[3758] #endif
[3759] }
[3760] 
[3761] 
[3762] static char *
[3763] ngx_http_fastcgi_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3764] {
[3765]     ngx_http_fastcgi_loc_conf_t *flcf = conf;
[3766] 
[3767]     ngx_str_t                  *value;
[3768]     ngx_http_script_compile_t   sc;
[3769] 
[3770]     if (flcf->upstream.store != NGX_CONF_UNSET) {
[3771]         return "is duplicate";
[3772]     }
[3773] 
[3774]     value = cf->args->elts;
[3775] 
[3776]     if (ngx_strcmp(value[1].data, "off") == 0) {
[3777]         flcf->upstream.store = 0;
[3778]         return NGX_CONF_OK;
[3779]     }
[3780] 
[3781] #if (NGX_HTTP_CACHE)
[3782]     if (flcf->upstream.cache > 0) {
[3783]         return "is incompatible with \"fastcgi_cache\"";
[3784]     }
[3785] #endif
[3786] 
[3787]     flcf->upstream.store = 1;
[3788] 
[3789]     if (ngx_strcmp(value[1].data, "on") == 0) {
[3790]         return NGX_CONF_OK;
[3791]     }
[3792] 
[3793]     /* include the terminating '\0' into script */
[3794]     value[1].len++;
[3795] 
[3796]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[3797] 
[3798]     sc.cf = cf;
[3799]     sc.source = &value[1];
[3800]     sc.lengths = &flcf->upstream.store_lengths;
[3801]     sc.values = &flcf->upstream.store_values;
[3802]     sc.variables = ngx_http_script_variables_count(&value[1]);
[3803]     sc.complete_lengths = 1;
[3804]     sc.complete_values = 1;
[3805] 
[3806]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[3807]         return NGX_CONF_ERROR;
[3808]     }
[3809] 
[3810]     return NGX_CONF_OK;
[3811] }
[3812] 
[3813] 
[3814] #if (NGX_HTTP_CACHE)
[3815] 
[3816] static char *
[3817] ngx_http_fastcgi_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3818] {
[3819]     ngx_http_fastcgi_loc_conf_t *flcf = conf;
[3820] 
[3821]     ngx_str_t                         *value;
[3822]     ngx_http_complex_value_t           cv;
[3823]     ngx_http_compile_complex_value_t   ccv;
[3824] 
[3825]     value = cf->args->elts;
[3826] 
[3827]     if (flcf->upstream.cache != NGX_CONF_UNSET) {
[3828]         return "is duplicate";
[3829]     }
[3830] 
[3831]     if (ngx_strcmp(value[1].data, "off") == 0) {
[3832]         flcf->upstream.cache = 0;
[3833]         return NGX_CONF_OK;
[3834]     }
[3835] 
[3836]     if (flcf->upstream.store > 0) {
[3837]         return "is incompatible with \"fastcgi_store\"";
[3838]     }
[3839] 
[3840]     flcf->upstream.cache = 1;
[3841] 
[3842]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[3843] 
[3844]     ccv.cf = cf;
[3845]     ccv.value = &value[1];
[3846]     ccv.complex_value = &cv;
[3847] 
[3848]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[3849]         return NGX_CONF_ERROR;
[3850]     }
[3851] 
[3852]     if (cv.lengths != NULL) {
[3853] 
[3854]         flcf->upstream.cache_value = ngx_palloc(cf->pool,
[3855]                                              sizeof(ngx_http_complex_value_t));
[3856]         if (flcf->upstream.cache_value == NULL) {
[3857]             return NGX_CONF_ERROR;
[3858]         }
[3859] 
[3860]         *flcf->upstream.cache_value = cv;
[3861] 
[3862]         return NGX_CONF_OK;
[3863]     }
[3864] 
[3865]     flcf->upstream.cache_zone = ngx_shared_memory_add(cf, &value[1], 0,
[3866]                                                       &ngx_http_fastcgi_module);
[3867]     if (flcf->upstream.cache_zone == NULL) {
[3868]         return NGX_CONF_ERROR;
[3869]     }
[3870] 
[3871]     return NGX_CONF_OK;
[3872] }
[3873] 
[3874] 
[3875] static char *
[3876] ngx_http_fastcgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3877] {
[3878]     ngx_http_fastcgi_loc_conf_t *flcf = conf;
[3879] 
[3880]     ngx_str_t                         *value;
[3881]     ngx_http_compile_complex_value_t   ccv;
[3882] 
[3883]     value = cf->args->elts;
[3884] 
[3885]     if (flcf->cache_key.value.data) {
[3886]         return "is duplicate";
[3887]     }
[3888] 
[3889]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[3890] 
[3891]     ccv.cf = cf;
[3892]     ccv.value = &value[1];
[3893]     ccv.complex_value = &flcf->cache_key;
[3894] 
[3895]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[3896]         return NGX_CONF_ERROR;
[3897]     }
[3898] 
[3899]     return NGX_CONF_OK;
[3900] }
[3901] 
[3902] #endif
[3903] 
[3904] 
[3905] static char *
[3906] ngx_http_fastcgi_lowat_check(ngx_conf_t *cf, void *post, void *data)
[3907] {
[3908] #if (NGX_FREEBSD)
[3909]     ssize_t *np = data;
[3910] 
[3911]     if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
[3912]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3913]                            "\"fastcgi_send_lowat\" must be less than %d "
[3914]                            "(sysctl net.inet.tcp.sendspace)",
[3915]                            ngx_freebsd_net_inet_tcp_sendspace);
[3916] 
[3917]         return NGX_CONF_ERROR;
[3918]     }
[3919] 
[3920] #elif !(NGX_HAVE_SO_SNDLOWAT)
[3921]     ssize_t *np = data;
[3922] 
[3923]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[3924]                        "\"fastcgi_send_lowat\" is not supported, ignored");
[3925] 
[3926]     *np = 0;
[3927] 
[3928] #endif
[3929] 
[3930]     return NGX_CONF_OK;
[3931] }
