[1] 
[2] /*
[3]  * Copyright (C) Unbit S.a.s. 2009-2010
[4]  * Copyright (C) 2008 Manlio Perillo (manlio.perillo@gmail.com)
[5]  * Copyright (C) Igor Sysoev
[6]  * Copyright (C) Nginx, Inc.
[7]  */
[8] 
[9] 
[10] #include <ngx_config.h>
[11] #include <ngx_core.h>
[12] #include <ngx_http.h>
[13] 
[14] 
[15] typedef struct {
[16]     ngx_array_t                caches;  /* ngx_http_file_cache_t * */
[17] } ngx_http_uwsgi_main_conf_t;
[18] 
[19] 
[20] typedef struct {
[21]     ngx_array_t               *flushes;
[22]     ngx_array_t               *lengths;
[23]     ngx_array_t               *values;
[24]     ngx_uint_t                 number;
[25]     ngx_hash_t                 hash;
[26] } ngx_http_uwsgi_params_t;
[27] 
[28] 
[29] typedef struct {
[30]     ngx_http_upstream_conf_t   upstream;
[31] 
[32]     ngx_http_uwsgi_params_t    params;
[33] #if (NGX_HTTP_CACHE)
[34]     ngx_http_uwsgi_params_t    params_cache;
[35] #endif
[36]     ngx_array_t               *params_source;
[37] 
[38]     ngx_array_t               *uwsgi_lengths;
[39]     ngx_array_t               *uwsgi_values;
[40] 
[41] #if (NGX_HTTP_CACHE)
[42]     ngx_http_complex_value_t   cache_key;
[43] #endif
[44] 
[45]     ngx_str_t                  uwsgi_string;
[46] 
[47]     ngx_uint_t                 modifier1;
[48]     ngx_uint_t                 modifier2;
[49] 
[50] #if (NGX_HTTP_SSL)
[51]     ngx_uint_t                 ssl;
[52]     ngx_uint_t                 ssl_protocols;
[53]     ngx_str_t                  ssl_ciphers;
[54]     ngx_uint_t                 ssl_verify_depth;
[55]     ngx_str_t                  ssl_trusted_certificate;
[56]     ngx_str_t                  ssl_crl;
[57]     ngx_array_t               *ssl_conf_commands;
[58] #endif
[59] } ngx_http_uwsgi_loc_conf_t;
[60] 
[61] 
[62] static ngx_int_t ngx_http_uwsgi_eval(ngx_http_request_t *r,
[63]     ngx_http_uwsgi_loc_conf_t *uwcf);
[64] static ngx_int_t ngx_http_uwsgi_create_request(ngx_http_request_t *r);
[65] static ngx_int_t ngx_http_uwsgi_reinit_request(ngx_http_request_t *r);
[66] static ngx_int_t ngx_http_uwsgi_process_status_line(ngx_http_request_t *r);
[67] static ngx_int_t ngx_http_uwsgi_process_header(ngx_http_request_t *r);
[68] static ngx_int_t ngx_http_uwsgi_input_filter_init(void *data);
[69] static void ngx_http_uwsgi_abort_request(ngx_http_request_t *r);
[70] static void ngx_http_uwsgi_finalize_request(ngx_http_request_t *r,
[71]     ngx_int_t rc);
[72] 
[73] static void *ngx_http_uwsgi_create_main_conf(ngx_conf_t *cf);
[74] static void *ngx_http_uwsgi_create_loc_conf(ngx_conf_t *cf);
[75] static char *ngx_http_uwsgi_merge_loc_conf(ngx_conf_t *cf, void *parent,
[76]     void *child);
[77] static ngx_int_t ngx_http_uwsgi_init_params(ngx_conf_t *cf,
[78]     ngx_http_uwsgi_loc_conf_t *conf, ngx_http_uwsgi_params_t *params,
[79]     ngx_keyval_t *default_params);
[80] 
[81] static char *ngx_http_uwsgi_pass(ngx_conf_t *cf, ngx_command_t *cmd,
[82]     void *conf);
[83] static char *ngx_http_uwsgi_store(ngx_conf_t *cf, ngx_command_t *cmd,
[84]     void *conf);
[85] 
[86] #if (NGX_HTTP_CACHE)
[87] static ngx_int_t ngx_http_uwsgi_create_key(ngx_http_request_t *r);
[88] static char *ngx_http_uwsgi_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[89]     void *conf);
[90] static char *ngx_http_uwsgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
[91]     void *conf);
[92] #endif
[93] 
[94] #if (NGX_HTTP_SSL)
[95] static char *ngx_http_uwsgi_ssl_password_file(ngx_conf_t *cf,
[96]     ngx_command_t *cmd, void *conf);
[97] static char *ngx_http_uwsgi_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[98]     void *data);
[99] static ngx_int_t ngx_http_uwsgi_merge_ssl(ngx_conf_t *cf,
[100]     ngx_http_uwsgi_loc_conf_t *conf, ngx_http_uwsgi_loc_conf_t *prev);
[101] static ngx_int_t ngx_http_uwsgi_set_ssl(ngx_conf_t *cf,
[102]     ngx_http_uwsgi_loc_conf_t *uwcf);
[103] #endif
[104] 
[105] 
[106] static ngx_conf_num_bounds_t  ngx_http_uwsgi_modifier_bounds = {
[107]     ngx_conf_check_num_bounds, 0, 255
[108] };
[109] 
[110] 
[111] static ngx_conf_bitmask_t ngx_http_uwsgi_next_upstream_masks[] = {
[112]     { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
[113]     { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
[114]     { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
[115]     { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
[116]     { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
[117]     { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
[118]     { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
[119]     { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[120]     { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
[121]     { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
[122]     { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
[123]     { ngx_null_string, 0 }
[124] };
[125] 
[126] 
[127] #if (NGX_HTTP_SSL)
[128] 
[129] static ngx_conf_bitmask_t  ngx_http_uwsgi_ssl_protocols[] = {
[130]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[131]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[132]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[133]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[134]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[135]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[136]     { ngx_null_string, 0 }
[137] };
[138] 
[139] static ngx_conf_post_t  ngx_http_uwsgi_ssl_conf_command_post =
[140]     { ngx_http_uwsgi_ssl_conf_command_check };
[141] 
[142] #endif
[143] 
[144] 
[145] ngx_module_t  ngx_http_uwsgi_module;
[146] 
[147] 
[148] static ngx_command_t ngx_http_uwsgi_commands[] = {
[149] 
[150]     { ngx_string("uwsgi_pass"),
[151]       NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[152]       ngx_http_uwsgi_pass,
[153]       NGX_HTTP_LOC_CONF_OFFSET,
[154]       0,
[155]       NULL },
[156] 
[157]     { ngx_string("uwsgi_modifier1"),
[158]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[159]       ngx_conf_set_num_slot,
[160]       NGX_HTTP_LOC_CONF_OFFSET,
[161]       offsetof(ngx_http_uwsgi_loc_conf_t, modifier1),
[162]       &ngx_http_uwsgi_modifier_bounds },
[163] 
[164]     { ngx_string("uwsgi_modifier2"),
[165]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[166]       ngx_conf_set_num_slot,
[167]       NGX_HTTP_LOC_CONF_OFFSET,
[168]       offsetof(ngx_http_uwsgi_loc_conf_t, modifier2),
[169]       &ngx_http_uwsgi_modifier_bounds },
[170] 
[171]     { ngx_string("uwsgi_store"),
[172]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[173]       ngx_http_uwsgi_store,
[174]       NGX_HTTP_LOC_CONF_OFFSET,
[175]       0,
[176]       NULL },
[177] 
[178]     { ngx_string("uwsgi_store_access"),
[179]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[180]       ngx_conf_set_access_slot,
[181]       NGX_HTTP_LOC_CONF_OFFSET,
[182]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.store_access),
[183]       NULL },
[184] 
[185]     { ngx_string("uwsgi_buffering"),
[186]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[187]       ngx_conf_set_flag_slot,
[188]       NGX_HTTP_LOC_CONF_OFFSET,
[189]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.buffering),
[190]       NULL },
[191] 
[192]     { ngx_string("uwsgi_request_buffering"),
[193]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[194]       ngx_conf_set_flag_slot,
[195]       NGX_HTTP_LOC_CONF_OFFSET,
[196]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.request_buffering),
[197]       NULL },
[198] 
[199]     { ngx_string("uwsgi_ignore_client_abort"),
[200]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[201]       ngx_conf_set_flag_slot,
[202]       NGX_HTTP_LOC_CONF_OFFSET,
[203]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ignore_client_abort),
[204]       NULL },
[205] 
[206]     { ngx_string("uwsgi_bind"),
[207]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[208]       ngx_http_upstream_bind_set_slot,
[209]       NGX_HTTP_LOC_CONF_OFFSET,
[210]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.local),
[211]       NULL },
[212] 
[213]     { ngx_string("uwsgi_socket_keepalive"),
[214]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[215]       ngx_conf_set_flag_slot,
[216]       NGX_HTTP_LOC_CONF_OFFSET,
[217]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.socket_keepalive),
[218]       NULL },
[219] 
[220]     { ngx_string("uwsgi_connect_timeout"),
[221]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[222]       ngx_conf_set_msec_slot,
[223]       NGX_HTTP_LOC_CONF_OFFSET,
[224]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.connect_timeout),
[225]       NULL },
[226] 
[227]     { ngx_string("uwsgi_send_timeout"),
[228]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[229]       ngx_conf_set_msec_slot,
[230]       NGX_HTTP_LOC_CONF_OFFSET,
[231]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.send_timeout),
[232]       NULL },
[233] 
[234]     { ngx_string("uwsgi_buffer_size"),
[235]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[236]       ngx_conf_set_size_slot,
[237]       NGX_HTTP_LOC_CONF_OFFSET,
[238]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.buffer_size),
[239]       NULL },
[240] 
[241]     { ngx_string("uwsgi_pass_request_headers"),
[242]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[243]       ngx_conf_set_flag_slot,
[244]       NGX_HTTP_LOC_CONF_OFFSET,
[245]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.pass_request_headers),
[246]       NULL },
[247] 
[248]     { ngx_string("uwsgi_pass_request_body"),
[249]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[250]       ngx_conf_set_flag_slot,
[251]       NGX_HTTP_LOC_CONF_OFFSET,
[252]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.pass_request_body),
[253]       NULL },
[254] 
[255]     { ngx_string("uwsgi_intercept_errors"),
[256]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[257]       ngx_conf_set_flag_slot,
[258]       NGX_HTTP_LOC_CONF_OFFSET,
[259]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.intercept_errors),
[260]       NULL },
[261] 
[262]     { ngx_string("uwsgi_read_timeout"),
[263]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[264]       ngx_conf_set_msec_slot,
[265]       NGX_HTTP_LOC_CONF_OFFSET,
[266]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.read_timeout),
[267]       NULL },
[268] 
[269]     { ngx_string("uwsgi_buffers"),
[270]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[271]       ngx_conf_set_bufs_slot,
[272]       NGX_HTTP_LOC_CONF_OFFSET,
[273]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.bufs),
[274]       NULL },
[275] 
[276]     { ngx_string("uwsgi_busy_buffers_size"),
[277]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[278]       ngx_conf_set_size_slot,
[279]       NGX_HTTP_LOC_CONF_OFFSET,
[280]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.busy_buffers_size_conf),
[281]       NULL },
[282] 
[283]     { ngx_string("uwsgi_force_ranges"),
[284]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[285]       ngx_conf_set_flag_slot,
[286]       NGX_HTTP_LOC_CONF_OFFSET,
[287]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.force_ranges),
[288]       NULL },
[289] 
[290]     { ngx_string("uwsgi_limit_rate"),
[291]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[292]       ngx_conf_set_size_slot,
[293]       NGX_HTTP_LOC_CONF_OFFSET,
[294]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.limit_rate),
[295]       NULL },
[296] 
[297] #if (NGX_HTTP_CACHE)
[298] 
[299]     { ngx_string("uwsgi_cache"),
[300]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[301]       ngx_http_uwsgi_cache,
[302]       NGX_HTTP_LOC_CONF_OFFSET,
[303]       0,
[304]       NULL },
[305] 
[306]     { ngx_string("uwsgi_cache_key"),
[307]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[308]       ngx_http_uwsgi_cache_key,
[309]       NGX_HTTP_LOC_CONF_OFFSET,
[310]       0,
[311]       NULL },
[312] 
[313]     { ngx_string("uwsgi_cache_path"),
[314]       NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
[315]       ngx_http_file_cache_set_slot,
[316]       NGX_HTTP_MAIN_CONF_OFFSET,
[317]       offsetof(ngx_http_uwsgi_main_conf_t, caches),
[318]       &ngx_http_uwsgi_module },
[319] 
[320]     { ngx_string("uwsgi_cache_bypass"),
[321]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[322]       ngx_http_set_predicate_slot,
[323]       NGX_HTTP_LOC_CONF_OFFSET,
[324]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_bypass),
[325]       NULL },
[326] 
[327]     { ngx_string("uwsgi_no_cache"),
[328]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[329]       ngx_http_set_predicate_slot,
[330]       NGX_HTTP_LOC_CONF_OFFSET,
[331]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.no_cache),
[332]       NULL },
[333] 
[334]     { ngx_string("uwsgi_cache_valid"),
[335]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[336]       ngx_http_file_cache_valid_set_slot,
[337]       NGX_HTTP_LOC_CONF_OFFSET,
[338]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_valid),
[339]       NULL },
[340] 
[341]     { ngx_string("uwsgi_cache_min_uses"),
[342]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[343]       ngx_conf_set_num_slot,
[344]       NGX_HTTP_LOC_CONF_OFFSET,
[345]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_min_uses),
[346]       NULL },
[347] 
[348]     { ngx_string("uwsgi_cache_max_range_offset"),
[349]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[350]       ngx_conf_set_off_slot,
[351]       NGX_HTTP_LOC_CONF_OFFSET,
[352]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_max_range_offset),
[353]       NULL },
[354] 
[355]     { ngx_string("uwsgi_cache_use_stale"),
[356]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[357]       ngx_conf_set_bitmask_slot,
[358]       NGX_HTTP_LOC_CONF_OFFSET,
[359]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_use_stale),
[360]       &ngx_http_uwsgi_next_upstream_masks },
[361] 
[362]     { ngx_string("uwsgi_cache_methods"),
[363]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[364]       ngx_conf_set_bitmask_slot,
[365]       NGX_HTTP_LOC_CONF_OFFSET,
[366]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_methods),
[367]       &ngx_http_upstream_cache_method_mask },
[368] 
[369]     { ngx_string("uwsgi_cache_lock"),
[370]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[371]       ngx_conf_set_flag_slot,
[372]       NGX_HTTP_LOC_CONF_OFFSET,
[373]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_lock),
[374]       NULL },
[375] 
[376]     { ngx_string("uwsgi_cache_lock_timeout"),
[377]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[378]       ngx_conf_set_msec_slot,
[379]       NGX_HTTP_LOC_CONF_OFFSET,
[380]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_lock_timeout),
[381]       NULL },
[382] 
[383]     { ngx_string("uwsgi_cache_lock_age"),
[384]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[385]       ngx_conf_set_msec_slot,
[386]       NGX_HTTP_LOC_CONF_OFFSET,
[387]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_lock_age),
[388]       NULL },
[389] 
[390]     { ngx_string("uwsgi_cache_revalidate"),
[391]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[392]       ngx_conf_set_flag_slot,
[393]       NGX_HTTP_LOC_CONF_OFFSET,
[394]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_revalidate),
[395]       NULL },
[396] 
[397]     { ngx_string("uwsgi_cache_background_update"),
[398]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[399]       ngx_conf_set_flag_slot,
[400]       NGX_HTTP_LOC_CONF_OFFSET,
[401]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.cache_background_update),
[402]       NULL },
[403] 
[404] #endif
[405] 
[406]     { ngx_string("uwsgi_temp_path"),
[407]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[408]       ngx_conf_set_path_slot,
[409]       NGX_HTTP_LOC_CONF_OFFSET,
[410]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.temp_path),
[411]       NULL },
[412] 
[413]     { ngx_string("uwsgi_max_temp_file_size"),
[414]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[415]       ngx_conf_set_size_slot,
[416]       NGX_HTTP_LOC_CONF_OFFSET,
[417]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.max_temp_file_size_conf),
[418]       NULL },
[419] 
[420]     { ngx_string("uwsgi_temp_file_write_size"),
[421]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[422]       ngx_conf_set_size_slot,
[423]       NGX_HTTP_LOC_CONF_OFFSET,
[424]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.temp_file_write_size_conf),
[425]       NULL },
[426] 
[427]     { ngx_string("uwsgi_next_upstream"),
[428]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[429]       ngx_conf_set_bitmask_slot,
[430]       NGX_HTTP_LOC_CONF_OFFSET,
[431]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.next_upstream),
[432]       &ngx_http_uwsgi_next_upstream_masks },
[433] 
[434]     { ngx_string("uwsgi_next_upstream_tries"),
[435]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[436]       ngx_conf_set_num_slot,
[437]       NGX_HTTP_LOC_CONF_OFFSET,
[438]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.next_upstream_tries),
[439]       NULL },
[440] 
[441]     { ngx_string("uwsgi_next_upstream_timeout"),
[442]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[443]       ngx_conf_set_msec_slot,
[444]       NGX_HTTP_LOC_CONF_OFFSET,
[445]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.next_upstream_timeout),
[446]       NULL },
[447] 
[448]     { ngx_string("uwsgi_param"),
[449]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
[450]       ngx_http_upstream_param_set_slot,
[451]       NGX_HTTP_LOC_CONF_OFFSET,
[452]       offsetof(ngx_http_uwsgi_loc_conf_t, params_source),
[453]       NULL },
[454] 
[455]     { ngx_string("uwsgi_string"),
[456]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[457]       ngx_conf_set_str_slot,
[458]       NGX_HTTP_LOC_CONF_OFFSET,
[459]       offsetof(ngx_http_uwsgi_loc_conf_t, uwsgi_string),
[460]       NULL },
[461] 
[462]     { ngx_string("uwsgi_pass_header"),
[463]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[464]       ngx_conf_set_str_array_slot,
[465]       NGX_HTTP_LOC_CONF_OFFSET,
[466]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.pass_headers),
[467]       NULL },
[468] 
[469]     { ngx_string("uwsgi_hide_header"),
[470]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[471]       ngx_conf_set_str_array_slot,
[472]       NGX_HTTP_LOC_CONF_OFFSET,
[473]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.hide_headers),
[474]       NULL },
[475] 
[476]     { ngx_string("uwsgi_ignore_headers"),
[477]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[478]       ngx_conf_set_bitmask_slot,
[479]       NGX_HTTP_LOC_CONF_OFFSET,
[480]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ignore_headers),
[481]       &ngx_http_upstream_ignore_headers_masks },
[482] 
[483] #if (NGX_HTTP_SSL)
[484] 
[485]     { ngx_string("uwsgi_ssl_session_reuse"),
[486]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[487]       ngx_conf_set_flag_slot,
[488]       NGX_HTTP_LOC_CONF_OFFSET,
[489]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ssl_session_reuse),
[490]       NULL },
[491] 
[492]     { ngx_string("uwsgi_ssl_protocols"),
[493]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[494]       ngx_conf_set_bitmask_slot,
[495]       NGX_HTTP_LOC_CONF_OFFSET,
[496]       offsetof(ngx_http_uwsgi_loc_conf_t, ssl_protocols),
[497]       &ngx_http_uwsgi_ssl_protocols },
[498] 
[499]     { ngx_string("uwsgi_ssl_ciphers"),
[500]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[501]       ngx_conf_set_str_slot,
[502]       NGX_HTTP_LOC_CONF_OFFSET,
[503]       offsetof(ngx_http_uwsgi_loc_conf_t, ssl_ciphers),
[504]       NULL },
[505] 
[506]     { ngx_string("uwsgi_ssl_name"),
[507]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[508]       ngx_http_set_complex_value_slot,
[509]       NGX_HTTP_LOC_CONF_OFFSET,
[510]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ssl_name),
[511]       NULL },
[512] 
[513]     { ngx_string("uwsgi_ssl_server_name"),
[514]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[515]       ngx_conf_set_flag_slot,
[516]       NGX_HTTP_LOC_CONF_OFFSET,
[517]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ssl_server_name),
[518]       NULL },
[519] 
[520]     { ngx_string("uwsgi_ssl_verify"),
[521]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[522]       ngx_conf_set_flag_slot,
[523]       NGX_HTTP_LOC_CONF_OFFSET,
[524]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ssl_verify),
[525]       NULL },
[526] 
[527]     { ngx_string("uwsgi_ssl_verify_depth"),
[528]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[529]       ngx_conf_set_num_slot,
[530]       NGX_HTTP_LOC_CONF_OFFSET,
[531]       offsetof(ngx_http_uwsgi_loc_conf_t, ssl_verify_depth),
[532]       NULL },
[533] 
[534]     { ngx_string("uwsgi_ssl_trusted_certificate"),
[535]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[536]       ngx_conf_set_str_slot,
[537]       NGX_HTTP_LOC_CONF_OFFSET,
[538]       offsetof(ngx_http_uwsgi_loc_conf_t, ssl_trusted_certificate),
[539]       NULL },
[540] 
[541]     { ngx_string("uwsgi_ssl_crl"),
[542]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[543]       ngx_conf_set_str_slot,
[544]       NGX_HTTP_LOC_CONF_OFFSET,
[545]       offsetof(ngx_http_uwsgi_loc_conf_t, ssl_crl),
[546]       NULL },
[547] 
[548]     { ngx_string("uwsgi_ssl_certificate"),
[549]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[550]       ngx_http_set_complex_value_zero_slot,
[551]       NGX_HTTP_LOC_CONF_OFFSET,
[552]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ssl_certificate),
[553]       NULL },
[554] 
[555]     { ngx_string("uwsgi_ssl_certificate_key"),
[556]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[557]       ngx_http_set_complex_value_zero_slot,
[558]       NGX_HTTP_LOC_CONF_OFFSET,
[559]       offsetof(ngx_http_uwsgi_loc_conf_t, upstream.ssl_certificate_key),
[560]       NULL },
[561] 
[562]     { ngx_string("uwsgi_ssl_password_file"),
[563]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[564]       ngx_http_uwsgi_ssl_password_file,
[565]       NGX_HTTP_LOC_CONF_OFFSET,
[566]       0,
[567]       NULL },
[568] 
[569]     { ngx_string("uwsgi_ssl_conf_command"),
[570]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[571]       ngx_conf_set_keyval_slot,
[572]       NGX_HTTP_LOC_CONF_OFFSET,
[573]       offsetof(ngx_http_uwsgi_loc_conf_t, ssl_conf_commands),
[574]       &ngx_http_uwsgi_ssl_conf_command_post },
[575] 
[576] #endif
[577] 
[578]       ngx_null_command
[579] };
[580] 
[581] 
[582] static ngx_http_module_t ngx_http_uwsgi_module_ctx = {
[583]     NULL,                                  /* preconfiguration */
[584]     NULL,                                  /* postconfiguration */
[585] 
[586]     ngx_http_uwsgi_create_main_conf,       /* create main configuration */
[587]     NULL,                                  /* init main configuration */
[588] 
[589]     NULL,                                  /* create server configuration */
[590]     NULL,                                  /* merge server configuration */
[591] 
[592]     ngx_http_uwsgi_create_loc_conf,        /* create location configuration */
[593]     ngx_http_uwsgi_merge_loc_conf          /* merge location configuration */
[594] };
[595] 
[596] 
[597] ngx_module_t ngx_http_uwsgi_module = {
[598]     NGX_MODULE_V1,
[599]     &ngx_http_uwsgi_module_ctx,            /* module context */
[600]     ngx_http_uwsgi_commands,               /* module directives */
[601]     NGX_HTTP_MODULE,                       /* module type */
[602]     NULL,                                  /* init master */
[603]     NULL,                                  /* init module */
[604]     NULL,                                  /* init process */
[605]     NULL,                                  /* init thread */
[606]     NULL,                                  /* exit thread */
[607]     NULL,                                  /* exit process */
[608]     NULL,                                  /* exit master */
[609]     NGX_MODULE_V1_PADDING
[610] };
[611] 
[612] 
[613] static ngx_str_t ngx_http_uwsgi_hide_headers[] = {
[614]     ngx_string("X-Accel-Expires"),
[615]     ngx_string("X-Accel-Redirect"),
[616]     ngx_string("X-Accel-Limit-Rate"),
[617]     ngx_string("X-Accel-Buffering"),
[618]     ngx_string("X-Accel-Charset"),
[619]     ngx_null_string
[620] };
[621] 
[622] 
[623] #if (NGX_HTTP_CACHE)
[624] 
[625] static ngx_keyval_t  ngx_http_uwsgi_cache_headers[] = {
[626]     { ngx_string("HTTP_IF_MODIFIED_SINCE"),
[627]       ngx_string("$upstream_cache_last_modified") },
[628]     { ngx_string("HTTP_IF_UNMODIFIED_SINCE"), ngx_string("") },
[629]     { ngx_string("HTTP_IF_NONE_MATCH"), ngx_string("$upstream_cache_etag") },
[630]     { ngx_string("HTTP_IF_MATCH"), ngx_string("") },
[631]     { ngx_string("HTTP_RANGE"), ngx_string("") },
[632]     { ngx_string("HTTP_IF_RANGE"), ngx_string("") },
[633]     { ngx_null_string, ngx_null_string }
[634] };
[635] 
[636] #endif
[637] 
[638] 
[639] static ngx_path_init_t ngx_http_uwsgi_temp_path = {
[640]     ngx_string(NGX_HTTP_UWSGI_TEMP_PATH), { 1, 2, 0 }
[641] };
[642] 
[643] 
[644] static ngx_int_t
[645] ngx_http_uwsgi_handler(ngx_http_request_t *r)
[646] {
[647]     ngx_int_t                    rc;
[648]     ngx_http_status_t           *status;
[649]     ngx_http_upstream_t         *u;
[650]     ngx_http_uwsgi_loc_conf_t   *uwcf;
[651] #if (NGX_HTTP_CACHE)
[652]     ngx_http_uwsgi_main_conf_t  *uwmcf;
[653] #endif
[654] 
[655]     if (ngx_http_upstream_create(r) != NGX_OK) {
[656]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[657]     }
[658] 
[659]     status = ngx_pcalloc(r->pool, sizeof(ngx_http_status_t));
[660]     if (status == NULL) {
[661]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[662]     }
[663] 
[664]     ngx_http_set_ctx(r, status, ngx_http_uwsgi_module);
[665] 
[666]     uwcf = ngx_http_get_module_loc_conf(r, ngx_http_uwsgi_module);
[667] 
[668]     u = r->upstream;
[669] 
[670]     if (uwcf->uwsgi_lengths == NULL) {
[671] 
[672] #if (NGX_HTTP_SSL)
[673]         u->ssl = uwcf->ssl;
[674] 
[675]         if (u->ssl) {
[676]             ngx_str_set(&u->schema, "suwsgi://");
[677] 
[678]         } else {
[679]             ngx_str_set(&u->schema, "uwsgi://");
[680]         }
[681] #else
[682]         ngx_str_set(&u->schema, "uwsgi://");
[683] #endif
[684] 
[685]     } else {
[686]         if (ngx_http_uwsgi_eval(r, uwcf) != NGX_OK) {
[687]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[688]         }
[689]     }
[690] 
[691]     u->output.tag = (ngx_buf_tag_t) &ngx_http_uwsgi_module;
[692] 
[693]     u->conf = &uwcf->upstream;
[694] 
[695] #if (NGX_HTTP_CACHE)
[696]     uwmcf = ngx_http_get_module_main_conf(r, ngx_http_uwsgi_module);
[697] 
[698]     u->caches = &uwmcf->caches;
[699]     u->create_key = ngx_http_uwsgi_create_key;
[700] #endif
[701] 
[702]     u->create_request = ngx_http_uwsgi_create_request;
[703]     u->reinit_request = ngx_http_uwsgi_reinit_request;
[704]     u->process_header = ngx_http_uwsgi_process_status_line;
[705]     u->abort_request = ngx_http_uwsgi_abort_request;
[706]     u->finalize_request = ngx_http_uwsgi_finalize_request;
[707]     r->state = 0;
[708] 
[709]     u->buffering = uwcf->upstream.buffering;
[710] 
[711]     u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
[712]     if (u->pipe == NULL) {
[713]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[714]     }
[715] 
[716]     u->pipe->input_filter = ngx_event_pipe_copy_input_filter;
[717]     u->pipe->input_ctx = r;
[718] 
[719]     u->input_filter_init = ngx_http_uwsgi_input_filter_init;
[720]     u->input_filter = ngx_http_upstream_non_buffered_filter;
[721]     u->input_filter_ctx = r;
[722] 
[723]     if (!uwcf->upstream.request_buffering
[724]         && uwcf->upstream.pass_request_body
[725]         && !r->headers_in.chunked)
[726]     {
[727]         r->request_body_no_buffering = 1;
[728]     }
[729] 
[730]     rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
[731] 
[732]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[733]         return rc;
[734]     }
[735] 
[736]     return NGX_DONE;
[737] }
[738] 
[739] 
[740] static ngx_int_t
[741] ngx_http_uwsgi_eval(ngx_http_request_t *r, ngx_http_uwsgi_loc_conf_t * uwcf)
[742] {
[743]     size_t                add;
[744]     ngx_url_t             url;
[745]     ngx_http_upstream_t  *u;
[746] 
[747]     ngx_memzero(&url, sizeof(ngx_url_t));
[748] 
[749]     if (ngx_http_script_run(r, &url.url, uwcf->uwsgi_lengths->elts, 0,
[750]                             uwcf->uwsgi_values->elts)
[751]         == NULL)
[752]     {
[753]         return NGX_ERROR;
[754]     }
[755] 
[756]     if (url.url.len > 8
[757]         && ngx_strncasecmp(url.url.data, (u_char *) "uwsgi://", 8) == 0)
[758]     {
[759]         add = 8;
[760] 
[761]     } else if (url.url.len > 9
[762]                && ngx_strncasecmp(url.url.data, (u_char *) "suwsgi://", 9) == 0)
[763]     {
[764] 
[765] #if (NGX_HTTP_SSL)
[766]         add = 9;
[767]         r->upstream->ssl = 1;
[768] #else
[769]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[770]                       "suwsgi protocol requires SSL support");
[771]         return NGX_ERROR;
[772] #endif
[773] 
[774]     } else {
[775]         add = 0;
[776]     }
[777] 
[778]     u = r->upstream;
[779] 
[780]     if (add) {
[781]         u->schema.len = add;
[782]         u->schema.data = url.url.data;
[783] 
[784]         url.url.data += add;
[785]         url.url.len -= add;
[786] 
[787]     } else {
[788]         ngx_str_set(&u->schema, "uwsgi://");
[789]     }
[790] 
[791]     url.no_resolve = 1;
[792] 
[793]     if (ngx_parse_url(r->pool, &url) != NGX_OK) {
[794]         if (url.err) {
[795]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[796]                           "%s in upstream \"%V\"", url.err, &url.url);
[797]         }
[798] 
[799]         return NGX_ERROR;
[800]     }
[801] 
[802]     u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
[803]     if (u->resolved == NULL) {
[804]         return NGX_ERROR;
[805]     }
[806] 
[807]     if (url.addrs) {
[808]         u->resolved->sockaddr = url.addrs[0].sockaddr;
[809]         u->resolved->socklen = url.addrs[0].socklen;
[810]         u->resolved->name = url.addrs[0].name;
[811]         u->resolved->naddrs = 1;
[812]     }
[813] 
[814]     u->resolved->host = url.host;
[815]     u->resolved->port = url.port;
[816]     u->resolved->no_port = url.no_port;
[817] 
[818]     return NGX_OK;
[819] }
[820] 
[821] 
[822] #if (NGX_HTTP_CACHE)
[823] 
[824] static ngx_int_t
[825] ngx_http_uwsgi_create_key(ngx_http_request_t *r)
[826] {
[827]     ngx_str_t                  *key;
[828]     ngx_http_uwsgi_loc_conf_t  *uwcf;
[829] 
[830]     key = ngx_array_push(&r->cache->keys);
[831]     if (key == NULL) {
[832]         return NGX_ERROR;
[833]     }
[834] 
[835]     uwcf = ngx_http_get_module_loc_conf(r, ngx_http_uwsgi_module);
[836] 
[837]     if (ngx_http_complex_value(r, &uwcf->cache_key, key) != NGX_OK) {
[838]         return NGX_ERROR;
[839]     }
[840] 
[841]     return NGX_OK;
[842] }
[843] 
[844] #endif
[845] 
[846] 
[847] static ngx_int_t
[848] ngx_http_uwsgi_create_request(ngx_http_request_t *r)
[849] {
[850]     u_char                        ch, sep, *lowcase_key;
[851]     size_t                        key_len, val_len, len, allocated;
[852]     ngx_uint_t                    i, n, hash, skip_empty, header_params;
[853]     ngx_buf_t                    *b;
[854]     ngx_chain_t                  *cl, *body;
[855]     ngx_list_part_t              *part;
[856]     ngx_table_elt_t              *header, *hn, **ignored;
[857]     ngx_http_uwsgi_params_t      *params;
[858]     ngx_http_script_code_pt       code;
[859]     ngx_http_script_engine_t      e, le;
[860]     ngx_http_uwsgi_loc_conf_t    *uwcf;
[861]     ngx_http_script_len_code_pt   lcode;
[862] 
[863]     len = 0;
[864]     header_params = 0;
[865]     ignored = NULL;
[866] 
[867]     uwcf = ngx_http_get_module_loc_conf(r, ngx_http_uwsgi_module);
[868] 
[869] #if (NGX_HTTP_CACHE)
[870]     params = r->upstream->cacheable ? &uwcf->params_cache : &uwcf->params;
[871] #else
[872]     params = &uwcf->params;
[873] #endif
[874] 
[875]     if (params->lengths) {
[876]         ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[877] 
[878]         ngx_http_script_flush_no_cacheable_variables(r, params->flushes);
[879]         le.flushed = 1;
[880] 
[881]         le.ip = params->lengths->elts;
[882]         le.request = r;
[883] 
[884]         while (*(uintptr_t *) le.ip) {
[885] 
[886]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[887]             key_len = lcode(&le);
[888] 
[889]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[890]             skip_empty = lcode(&le);
[891] 
[892]             for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[893]                 lcode = *(ngx_http_script_len_code_pt *) le.ip;
[894]             }
[895]             le.ip += sizeof(uintptr_t);
[896] 
[897]             if (skip_empty && val_len == 0) {
[898]                 continue;
[899]             }
[900] 
[901]             len += 2 + key_len + 2 + val_len;
[902]         }
[903]     }
[904] 
[905]     if (uwcf->upstream.pass_request_headers) {
[906] 
[907]         allocated = 0;
[908]         lowcase_key = NULL;
[909] 
[910]         if (ngx_http_link_multi_headers(r) != NGX_OK) {
[911]             return NGX_ERROR;
[912]         }
[913] 
[914]         if (params->number || r->headers_in.multi) {
[915]             n = 0;
[916]             part = &r->headers_in.headers.part;
[917] 
[918]             while (part) {
[919]                 n += part->nelts;
[920]                 part = part->next;
[921]             }
[922] 
[923]             ignored = ngx_palloc(r->pool, n * sizeof(void *));
[924]             if (ignored == NULL) {
[925]                 return NGX_ERROR;
[926]             }
[927]         }
[928] 
[929]         part = &r->headers_in.headers.part;
[930]         header = part->elts;
[931] 
[932]         for (i = 0; /* void */ ; i++) {
[933] 
[934]             if (i >= part->nelts) {
[935]                 if (part->next == NULL) {
[936]                     break;
[937]                 }
[938] 
[939]                 part = part->next;
[940]                 header = part->elts;
[941]                 i = 0;
[942]             }
[943] 
[944]             for (n = 0; n < header_params; n++) {
[945]                 if (&header[i] == ignored[n]) {
[946]                     goto next_length;
[947]                 }
[948]             }
[949] 
[950]             if (params->number) {
[951]                 if (allocated < header[i].key.len) {
[952]                     allocated = header[i].key.len + 16;
[953]                     lowcase_key = ngx_pnalloc(r->pool, allocated);
[954]                     if (lowcase_key == NULL) {
[955]                         return NGX_ERROR;
[956]                     }
[957]                 }
[958] 
[959]                 hash = 0;
[960] 
[961]                 for (n = 0; n < header[i].key.len; n++) {
[962]                     ch = header[i].key.data[n];
[963] 
[964]                     if (ch >= 'A' && ch <= 'Z') {
[965]                         ch |= 0x20;
[966] 
[967]                     } else if (ch == '-') {
[968]                         ch = '_';
[969]                     }
[970] 
[971]                     hash = ngx_hash(hash, ch);
[972]                     lowcase_key[n] = ch;
[973]                 }
[974] 
[975]                 if (ngx_hash_find(&params->hash, hash, lowcase_key, n)) {
[976]                     ignored[header_params++] = &header[i];
[977]                     continue;
[978]                 }
[979]             }
[980] 
[981]             len += 2 + sizeof("HTTP_") - 1 + header[i].key.len
[982]                  + 2 + header[i].value.len;
[983] 
[984]             for (hn = header[i].next; hn; hn = hn->next) {
[985]                 len += hn->value.len + 2;
[986]                 ignored[header_params++] = hn;
[987]             }
[988] 
[989]         next_length:
[990] 
[991]             continue;
[992]         }
[993]     }
[994] 
[995]     len += uwcf->uwsgi_string.len;
[996] 
[997] #if 0
[998]     /* allow custom uwsgi packet */
[999]     if (len > 0 && len < 2) {
[1000]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1001]                       "uwsgi request is too little: %uz", len);
[1002]         return NGX_ERROR;
[1003]     }
[1004] #endif
[1005] 
[1006]     if (len > 65535) {
[1007]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1008]                       "uwsgi request is too big: %uz", len);
[1009]         return NGX_ERROR;
[1010]     }
[1011] 
[1012]     b = ngx_create_temp_buf(r->pool, len + 4);
[1013]     if (b == NULL) {
[1014]         return NGX_ERROR;
[1015]     }
[1016] 
[1017]     cl = ngx_alloc_chain_link(r->pool);
[1018]     if (cl == NULL) {
[1019]         return NGX_ERROR;
[1020]     }
[1021] 
[1022]     cl->buf = b;
[1023] 
[1024]     *b->last++ = (u_char) uwcf->modifier1;
[1025]     *b->last++ = (u_char) (len & 0xff);
[1026]     *b->last++ = (u_char) ((len >> 8) & 0xff);
[1027]     *b->last++ = (u_char) uwcf->modifier2;
[1028] 
[1029]     if (params->lengths) {
[1030]         ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[1031] 
[1032]         e.ip = params->values->elts;
[1033]         e.pos = b->last;
[1034]         e.request = r;
[1035]         e.flushed = 1;
[1036] 
[1037]         le.ip = params->lengths->elts;
[1038] 
[1039]         while (*(uintptr_t *) le.ip) {
[1040] 
[1041]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1042]             key_len = (u_char) lcode(&le);
[1043] 
[1044]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1045]             skip_empty = lcode(&le);
[1046] 
[1047]             for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[1048]                 lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1049]             }
[1050]             le.ip += sizeof(uintptr_t);
[1051] 
[1052]             if (skip_empty && val_len == 0) {
[1053]                 e.skip = 1;
[1054] 
[1055]                 while (*(uintptr_t *) e.ip) {
[1056]                     code = *(ngx_http_script_code_pt *) e.ip;
[1057]                     code((ngx_http_script_engine_t *) &e);
[1058]                 }
[1059]                 e.ip += sizeof(uintptr_t);
[1060] 
[1061]                 e.skip = 0;
[1062] 
[1063]                 continue;
[1064]             }
[1065] 
[1066]             *e.pos++ = (u_char) (key_len & 0xff);
[1067]             *e.pos++ = (u_char) ((key_len >> 8) & 0xff);
[1068] 
[1069]             code = *(ngx_http_script_code_pt *) e.ip;
[1070]             code((ngx_http_script_engine_t *) &e);
[1071] 
[1072]             *e.pos++ = (u_char) (val_len & 0xff);
[1073]             *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
[1074] 
[1075]             while (*(uintptr_t *) e.ip) {
[1076]                 code = *(ngx_http_script_code_pt *) e.ip;
[1077]                 code((ngx_http_script_engine_t *) &e);
[1078]             }
[1079] 
[1080]             e.ip += sizeof(uintptr_t);
[1081] 
[1082]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1083]                            "uwsgi param: \"%*s: %*s\"",
[1084]                            key_len, e.pos - (key_len + 2 + val_len),
[1085]                            val_len, e.pos - val_len);
[1086]         }
[1087] 
[1088]         b->last = e.pos;
[1089]     }
[1090] 
[1091]     if (uwcf->upstream.pass_request_headers) {
[1092] 
[1093]         part = &r->headers_in.headers.part;
[1094]         header = part->elts;
[1095] 
[1096]         for (i = 0; /* void */ ; i++) {
[1097] 
[1098]             if (i >= part->nelts) {
[1099]                 if (part->next == NULL) {
[1100]                     break;
[1101]                 }
[1102] 
[1103]                 part = part->next;
[1104]                 header = part->elts;
[1105]                 i = 0;
[1106]             }
[1107] 
[1108]             for (n = 0; n < header_params; n++) {
[1109]                 if (&header[i] == ignored[n]) {
[1110]                     goto next_value;
[1111]                 }
[1112]             }
[1113] 
[1114]             key_len = sizeof("HTTP_") - 1 + header[i].key.len;
[1115]             *b->last++ = (u_char) (key_len & 0xff);
[1116]             *b->last++ = (u_char) ((key_len >> 8) & 0xff);
[1117] 
[1118]             b->last = ngx_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);
[1119]             for (n = 0; n < header[i].key.len; n++) {
[1120]                 ch = header[i].key.data[n];
[1121] 
[1122]                 if (ch >= 'a' && ch <= 'z') {
[1123]                     ch &= ~0x20;
[1124] 
[1125]                 } else if (ch == '-') {
[1126]                     ch = '_';
[1127]                 }
[1128] 
[1129]                 *b->last++ = ch;
[1130]             }
[1131] 
[1132]             val_len = header[i].value.len;
[1133] 
[1134]             for (hn = header[i].next; hn; hn = hn->next) {
[1135]                 val_len += hn->value.len + 2;
[1136]             }
[1137] 
[1138]             *b->last++ = (u_char) (val_len & 0xff);
[1139]             *b->last++ = (u_char) ((val_len >> 8) & 0xff);
[1140]             b->last = ngx_copy(b->last, header[i].value.data,
[1141]                                header[i].value.len);
[1142] 
[1143]             if (header[i].next) {
[1144] 
[1145]                 if (header[i].key.len == sizeof("Cookie") - 1
[1146]                     && ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie",
[1147]                                        sizeof("Cookie") - 1)
[1148]                        == 0)
[1149]                 {
[1150]                     sep = ';';
[1151] 
[1152]                 } else {
[1153]                     sep = ',';
[1154]                 }
[1155] 
[1156]                 for (hn = header[i].next; hn; hn = hn->next) {
[1157]                     *b->last++ = sep;
[1158]                     *b->last++ = ' ';
[1159]                     b->last = ngx_copy(b->last, hn->value.data, hn->value.len);
[1160]                 }
[1161]             }
[1162] 
[1163]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1164]                            "uwsgi param: \"%*s: %*s\"",
[1165]                            key_len, b->last - (key_len + 2 + val_len),
[1166]                            val_len, b->last - val_len);
[1167]         next_value:
[1168] 
[1169]             continue;
[1170]         }
[1171]     }
[1172] 
[1173]     b->last = ngx_copy(b->last, uwcf->uwsgi_string.data,
[1174]                        uwcf->uwsgi_string.len);
[1175] 
[1176]     if (r->request_body_no_buffering) {
[1177]         r->upstream->request_bufs = cl;
[1178] 
[1179]     } else if (uwcf->upstream.pass_request_body) {
[1180]         body = r->upstream->request_bufs;
[1181]         r->upstream->request_bufs = cl;
[1182] 
[1183]         while (body) {
[1184]             b = ngx_alloc_buf(r->pool);
[1185]             if (b == NULL) {
[1186]                 return NGX_ERROR;
[1187]             }
[1188] 
[1189]             ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
[1190] 
[1191]             cl->next = ngx_alloc_chain_link(r->pool);
[1192]             if (cl->next == NULL) {
[1193]                 return NGX_ERROR;
[1194]             }
[1195] 
[1196]             cl = cl->next;
[1197]             cl->buf = b;
[1198] 
[1199]             body = body->next;
[1200]         }
[1201] 
[1202]     } else {
[1203]         r->upstream->request_bufs = cl;
[1204]     }
[1205] 
[1206]     b->flush = 1;
[1207]     cl->next = NULL;
[1208] 
[1209]     return NGX_OK;
[1210] }
[1211] 
[1212] 
[1213] static ngx_int_t
[1214] ngx_http_uwsgi_reinit_request(ngx_http_request_t *r)
[1215] {
[1216]     ngx_http_status_t  *status;
[1217] 
[1218]     status = ngx_http_get_module_ctx(r, ngx_http_uwsgi_module);
[1219] 
[1220]     if (status == NULL) {
[1221]         return NGX_OK;
[1222]     }
[1223] 
[1224]     status->code = 0;
[1225]     status->count = 0;
[1226]     status->start = NULL;
[1227]     status->end = NULL;
[1228] 
[1229]     r->upstream->process_header = ngx_http_uwsgi_process_status_line;
[1230]     r->state = 0;
[1231] 
[1232]     return NGX_OK;
[1233] }
[1234] 
[1235] 
[1236] static ngx_int_t
[1237] ngx_http_uwsgi_process_status_line(ngx_http_request_t *r)
[1238] {
[1239]     size_t                 len;
[1240]     ngx_int_t              rc;
[1241]     ngx_http_status_t     *status;
[1242]     ngx_http_upstream_t   *u;
[1243] 
[1244]     status = ngx_http_get_module_ctx(r, ngx_http_uwsgi_module);
[1245] 
[1246]     if (status == NULL) {
[1247]         return NGX_ERROR;
[1248]     }
[1249] 
[1250]     u = r->upstream;
[1251] 
[1252]     rc = ngx_http_parse_status_line(r, &u->buffer, status);
[1253] 
[1254]     if (rc == NGX_AGAIN) {
[1255]         return rc;
[1256]     }
[1257] 
[1258]     if (rc == NGX_ERROR) {
[1259]         u->process_header = ngx_http_uwsgi_process_header;
[1260]         return ngx_http_uwsgi_process_header(r);
[1261]     }
[1262] 
[1263]     if (u->state && u->state->status == 0) {
[1264]         u->state->status = status->code;
[1265]     }
[1266] 
[1267]     u->headers_in.status_n = status->code;
[1268] 
[1269]     len = status->end - status->start;
[1270]     u->headers_in.status_line.len = len;
[1271] 
[1272]     u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
[1273]     if (u->headers_in.status_line.data == NULL) {
[1274]         return NGX_ERROR;
[1275]     }
[1276] 
[1277]     ngx_memcpy(u->headers_in.status_line.data, status->start, len);
[1278] 
[1279]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1280]                    "http uwsgi status %ui \"%V\"",
[1281]                    u->headers_in.status_n, &u->headers_in.status_line);
[1282] 
[1283]     u->process_header = ngx_http_uwsgi_process_header;
[1284] 
[1285]     return ngx_http_uwsgi_process_header(r);
[1286] }
[1287] 
[1288] 
[1289] static ngx_int_t
[1290] ngx_http_uwsgi_process_header(ngx_http_request_t *r)
[1291] {
[1292]     ngx_str_t                      *status_line;
[1293]     ngx_int_t                       rc, status;
[1294]     ngx_table_elt_t                *h;
[1295]     ngx_http_upstream_t            *u;
[1296]     ngx_http_upstream_header_t     *hh;
[1297]     ngx_http_upstream_main_conf_t  *umcf;
[1298] 
[1299]     umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[1300] 
[1301]     for ( ;; ) {
[1302] 
[1303]         rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
[1304] 
[1305]         if (rc == NGX_OK) {
[1306] 
[1307]             /* a header line has been parsed successfully */
[1308] 
[1309]             h = ngx_list_push(&r->upstream->headers_in.headers);
[1310]             if (h == NULL) {
[1311]                 return NGX_ERROR;
[1312]             }
[1313] 
[1314]             h->hash = r->header_hash;
[1315] 
[1316]             h->key.len = r->header_name_end - r->header_name_start;
[1317]             h->value.len = r->header_end - r->header_start;
[1318] 
[1319]             h->key.data = ngx_pnalloc(r->pool,
[1320]                                       h->key.len + 1 + h->value.len + 1
[1321]                                       + h->key.len);
[1322]             if (h->key.data == NULL) {
[1323]                 h->hash = 0;
[1324]                 return NGX_ERROR;
[1325]             }
[1326] 
[1327]             h->value.data = h->key.data + h->key.len + 1;
[1328]             h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
[1329] 
[1330]             ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
[1331]             h->key.data[h->key.len] = '\0';
[1332]             ngx_memcpy(h->value.data, r->header_start, h->value.len);
[1333]             h->value.data[h->value.len] = '\0';
[1334] 
[1335]             if (h->key.len == r->lowcase_index) {
[1336]                 ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
[1337] 
[1338]             } else {
[1339]                 ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
[1340]             }
[1341] 
[1342]             hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
[1343]                                h->lowcase_key, h->key.len);
[1344] 
[1345]             if (hh) {
[1346]                 rc = hh->handler(r, h, hh->offset);
[1347] 
[1348]                 if (rc != NGX_OK) {
[1349]                     return rc;
[1350]                 }
[1351]             }
[1352] 
[1353]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1354]                            "http uwsgi header: \"%V: %V\"", &h->key, &h->value);
[1355] 
[1356]             continue;
[1357]         }
[1358] 
[1359]         if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[1360] 
[1361]             /* a whole header has been parsed successfully */
[1362] 
[1363]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1364]                            "http uwsgi header done");
[1365] 
[1366]             u = r->upstream;
[1367] 
[1368]             if (u->headers_in.status_n) {
[1369]                 goto done;
[1370]             }
[1371] 
[1372]             if (u->headers_in.status) {
[1373]                 status_line = &u->headers_in.status->value;
[1374] 
[1375]                 status = ngx_atoi(status_line->data, 3);
[1376]                 if (status == NGX_ERROR) {
[1377]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1378]                                   "upstream sent invalid status \"%V\"",
[1379]                                   status_line);
[1380]                     return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1381]                 }
[1382] 
[1383]                 u->headers_in.status_n = status;
[1384]                 u->headers_in.status_line = *status_line;
[1385] 
[1386]             } else if (u->headers_in.location) {
[1387]                 u->headers_in.status_n = 302;
[1388]                 ngx_str_set(&u->headers_in.status_line,
[1389]                             "302 Moved Temporarily");
[1390] 
[1391]             } else {
[1392]                 u->headers_in.status_n = 200;
[1393]                 ngx_str_set(&u->headers_in.status_line, "200 OK");
[1394]             }
[1395] 
[1396]             if (u->state && u->state->status == 0) {
[1397]                 u->state->status = u->headers_in.status_n;
[1398]             }
[1399] 
[1400]         done:
[1401] 
[1402]             if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS
[1403]                 && r->headers_in.upgrade)
[1404]             {
[1405]                 u->upgrade = 1;
[1406]             }
[1407] 
[1408]             return NGX_OK;
[1409]         }
[1410] 
[1411]         if (rc == NGX_AGAIN) {
[1412]             return NGX_AGAIN;
[1413]         }
[1414] 
[1415]         /* rc == NGX_HTTP_PARSE_INVALID_HEADER */
[1416] 
[1417]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1418]                       "upstream sent invalid header: \"%*s\\x%02xd...\"",
[1419]                       r->header_end - r->header_name_start,
[1420]                       r->header_name_start, *r->header_end);
[1421] 
[1422]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1423]     }
[1424] }
[1425] 
[1426] 
[1427] static ngx_int_t
[1428] ngx_http_uwsgi_input_filter_init(void *data)
[1429] {
[1430]     ngx_http_request_t   *r = data;
[1431]     ngx_http_upstream_t  *u;
[1432] 
[1433]     u = r->upstream;
[1434] 
[1435]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1436]                    "http uwsgi filter init s:%ui l:%O",
[1437]                    u->headers_in.status_n, u->headers_in.content_length_n);
[1438] 
[1439]     if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
[1440]         || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED)
[1441]     {
[1442]         u->pipe->length = 0;
[1443]         u->length = 0;
[1444] 
[1445]     } else if (r->method == NGX_HTTP_HEAD) {
[1446]         u->pipe->length = -1;
[1447]         u->length = -1;
[1448] 
[1449]     } else {
[1450]         u->pipe->length = u->headers_in.content_length_n;
[1451]         u->length = u->headers_in.content_length_n;
[1452]     }
[1453] 
[1454]     return NGX_OK;
[1455] }
[1456] 
[1457] 
[1458] static void
[1459] ngx_http_uwsgi_abort_request(ngx_http_request_t *r)
[1460] {
[1461]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1462]                    "abort http uwsgi request");
[1463] 
[1464]     return;
[1465] }
[1466] 
[1467] 
[1468] static void
[1469] ngx_http_uwsgi_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[1470] {
[1471]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1472]                    "finalize http uwsgi request");
[1473] 
[1474]     return;
[1475] }
[1476] 
[1477] 
[1478] static void *
[1479] ngx_http_uwsgi_create_main_conf(ngx_conf_t *cf)
[1480] {
[1481]     ngx_http_uwsgi_main_conf_t  *conf;
[1482] 
[1483]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uwsgi_main_conf_t));
[1484]     if (conf == NULL) {
[1485]         return NULL;
[1486]     }
[1487] 
[1488] #if (NGX_HTTP_CACHE)
[1489]     if (ngx_array_init(&conf->caches, cf->pool, 4,
[1490]                        sizeof(ngx_http_file_cache_t *))
[1491]         != NGX_OK)
[1492]     {
[1493]         return NULL;
[1494]     }
[1495] #endif
[1496] 
[1497]     return conf;
[1498] }
[1499] 
[1500] 
[1501] static void *
[1502] ngx_http_uwsgi_create_loc_conf(ngx_conf_t *cf)
[1503] {
[1504]     ngx_http_uwsgi_loc_conf_t  *conf;
[1505] 
[1506]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uwsgi_loc_conf_t));
[1507]     if (conf == NULL) {
[1508]         return NULL;
[1509]     }
[1510] 
[1511]     conf->modifier1 = NGX_CONF_UNSET_UINT;
[1512]     conf->modifier2 = NGX_CONF_UNSET_UINT;
[1513] 
[1514]     conf->upstream.store = NGX_CONF_UNSET;
[1515]     conf->upstream.store_access = NGX_CONF_UNSET_UINT;
[1516]     conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
[1517]     conf->upstream.buffering = NGX_CONF_UNSET;
[1518]     conf->upstream.request_buffering = NGX_CONF_UNSET;
[1519]     conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
[1520]     conf->upstream.force_ranges = NGX_CONF_UNSET;
[1521] 
[1522]     conf->upstream.local = NGX_CONF_UNSET_PTR;
[1523]     conf->upstream.socket_keepalive = NGX_CONF_UNSET;
[1524] 
[1525]     conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
[1526]     conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
[1527]     conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
[1528]     conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[1529] 
[1530]     conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
[1531]     conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
[1532]     conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
[1533] 
[1534]     conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
[1535]     conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
[1536]     conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
[1537] 
[1538]     conf->upstream.pass_request_headers = NGX_CONF_UNSET;
[1539]     conf->upstream.pass_request_body = NGX_CONF_UNSET;
[1540] 
[1541] #if (NGX_HTTP_CACHE)
[1542]     conf->upstream.cache = NGX_CONF_UNSET;
[1543]     conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
[1544]     conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
[1545]     conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
[1546]     conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
[1547]     conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
[1548]     conf->upstream.cache_lock = NGX_CONF_UNSET;
[1549]     conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
[1550]     conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
[1551]     conf->upstream.cache_revalidate = NGX_CONF_UNSET;
[1552]     conf->upstream.cache_background_update = NGX_CONF_UNSET;
[1553] #endif
[1554] 
[1555]     conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
[1556]     conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
[1557] 
[1558]     conf->upstream.intercept_errors = NGX_CONF_UNSET;
[1559] 
[1560] #if (NGX_HTTP_SSL)
[1561]     conf->upstream.ssl_session_reuse = NGX_CONF_UNSET;
[1562]     conf->upstream.ssl_name = NGX_CONF_UNSET_PTR;
[1563]     conf->upstream.ssl_server_name = NGX_CONF_UNSET;
[1564]     conf->upstream.ssl_verify = NGX_CONF_UNSET;
[1565]     conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
[1566]     conf->upstream.ssl_certificate = NGX_CONF_UNSET_PTR;
[1567]     conf->upstream.ssl_certificate_key = NGX_CONF_UNSET_PTR;
[1568]     conf->upstream.ssl_passwords = NGX_CONF_UNSET_PTR;
[1569]     conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
[1570] #endif
[1571] 
[1572]     /* "uwsgi_cyclic_temp_file" is disabled */
[1573]     conf->upstream.cyclic_temp_file = 0;
[1574] 
[1575]     conf->upstream.change_buffering = 1;
[1576] 
[1577]     ngx_str_set(&conf->upstream.module, "uwsgi");
[1578] 
[1579]     return conf;
[1580] }
[1581] 
[1582] 
[1583] static char *
[1584] ngx_http_uwsgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[1585] {
[1586]     ngx_http_uwsgi_loc_conf_t *prev = parent;
[1587]     ngx_http_uwsgi_loc_conf_t *conf = child;
[1588] 
[1589]     size_t                        size;
[1590]     ngx_int_t                     rc;
[1591]     ngx_hash_init_t               hash;
[1592]     ngx_http_core_loc_conf_t     *clcf;
[1593] 
[1594] #if (NGX_HTTP_CACHE)
[1595] 
[1596]     if (conf->upstream.store > 0) {
[1597]         conf->upstream.cache = 0;
[1598]     }
[1599] 
[1600]     if (conf->upstream.cache > 0) {
[1601]         conf->upstream.store = 0;
[1602]     }
[1603] 
[1604] #endif
[1605] 
[1606]     if (conf->upstream.store == NGX_CONF_UNSET) {
[1607]         ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
[1608] 
[1609]         conf->upstream.store_lengths = prev->upstream.store_lengths;
[1610]         conf->upstream.store_values = prev->upstream.store_values;
[1611]     }
[1612] 
[1613]     ngx_conf_merge_uint_value(conf->upstream.store_access,
[1614]                               prev->upstream.store_access, 0600);
[1615] 
[1616]     ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
[1617]                               prev->upstream.next_upstream_tries, 0);
[1618] 
[1619]     ngx_conf_merge_value(conf->upstream.buffering,
[1620]                               prev->upstream.buffering, 1);
[1621] 
[1622]     ngx_conf_merge_value(conf->upstream.request_buffering,
[1623]                               prev->upstream.request_buffering, 1);
[1624] 
[1625]     ngx_conf_merge_value(conf->upstream.ignore_client_abort,
[1626]                               prev->upstream.ignore_client_abort, 0);
[1627] 
[1628]     ngx_conf_merge_value(conf->upstream.force_ranges,
[1629]                               prev->upstream.force_ranges, 0);
[1630] 
[1631]     ngx_conf_merge_ptr_value(conf->upstream.local,
[1632]                               prev->upstream.local, NULL);
[1633] 
[1634]     ngx_conf_merge_value(conf->upstream.socket_keepalive,
[1635]                               prev->upstream.socket_keepalive, 0);
[1636] 
[1637]     ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
[1638]                               prev->upstream.connect_timeout, 60000);
[1639] 
[1640]     ngx_conf_merge_msec_value(conf->upstream.send_timeout,
[1641]                               prev->upstream.send_timeout, 60000);
[1642] 
[1643]     ngx_conf_merge_msec_value(conf->upstream.read_timeout,
[1644]                               prev->upstream.read_timeout, 60000);
[1645] 
[1646]     ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
[1647]                               prev->upstream.next_upstream_timeout, 0);
[1648] 
[1649]     ngx_conf_merge_size_value(conf->upstream.send_lowat,
[1650]                               prev->upstream.send_lowat, 0);
[1651] 
[1652]     ngx_conf_merge_size_value(conf->upstream.buffer_size,
[1653]                               prev->upstream.buffer_size,
[1654]                               (size_t) ngx_pagesize);
[1655] 
[1656]     ngx_conf_merge_size_value(conf->upstream.limit_rate,
[1657]                               prev->upstream.limit_rate, 0);
[1658] 
[1659] 
[1660]     ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
[1661]                               8, ngx_pagesize);
[1662] 
[1663]     if (conf->upstream.bufs.num < 2) {
[1664]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1665]                            "there must be at least 2 \"uwsgi_buffers\"");
[1666]         return NGX_CONF_ERROR;
[1667]     }
[1668] 
[1669] 
[1670]     size = conf->upstream.buffer_size;
[1671]     if (size < conf->upstream.bufs.size) {
[1672]         size = conf->upstream.bufs.size;
[1673]     }
[1674] 
[1675] 
[1676]     ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
[1677]                               prev->upstream.busy_buffers_size_conf,
[1678]                               NGX_CONF_UNSET_SIZE);
[1679] 
[1680]     if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
[1681]         conf->upstream.busy_buffers_size = 2 * size;
[1682]     } else {
[1683]         conf->upstream.busy_buffers_size =
[1684]             conf->upstream.busy_buffers_size_conf;
[1685]     }
[1686] 
[1687]     if (conf->upstream.busy_buffers_size < size) {
[1688]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1689]             "\"uwsgi_busy_buffers_size\" must be equal to or greater "
[1690]             "than the maximum of the value of \"uwsgi_buffer_size\" and "
[1691]             "one of the \"uwsgi_buffers\"");
[1692] 
[1693]         return NGX_CONF_ERROR;
[1694]     }
[1695] 
[1696]     if (conf->upstream.busy_buffers_size
[1697]         > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
[1698]     {
[1699]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1700]             "\"uwsgi_busy_buffers_size\" must be less than "
[1701]             "the size of all \"uwsgi_buffers\" minus one buffer");
[1702] 
[1703]         return NGX_CONF_ERROR;
[1704]     }
[1705] 
[1706] 
[1707]     ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
[1708]                               prev->upstream.temp_file_write_size_conf,
[1709]                               NGX_CONF_UNSET_SIZE);
[1710] 
[1711]     if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
[1712]         conf->upstream.temp_file_write_size = 2 * size;
[1713]     } else {
[1714]         conf->upstream.temp_file_write_size =
[1715]             conf->upstream.temp_file_write_size_conf;
[1716]     }
[1717] 
[1718]     if (conf->upstream.temp_file_write_size < size) {
[1719]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1720]             "\"uwsgi_temp_file_write_size\" must be equal to or greater than "
[1721]             "the maximum of the value of \"uwsgi_buffer_size\" and "
[1722]             "one of the \"uwsgi_buffers\"");
[1723] 
[1724]         return NGX_CONF_ERROR;
[1725]     }
[1726] 
[1727] 
[1728]     ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
[1729]                               prev->upstream.max_temp_file_size_conf,
[1730]                               NGX_CONF_UNSET_SIZE);
[1731] 
[1732]     if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
[1733]         conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
[1734]     } else {
[1735]         conf->upstream.max_temp_file_size =
[1736]             conf->upstream.max_temp_file_size_conf;
[1737]     }
[1738] 
[1739]     if (conf->upstream.max_temp_file_size != 0
[1740]         && conf->upstream.max_temp_file_size < size)
[1741]     {
[1742]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1743]             "\"uwsgi_max_temp_file_size\" must be equal to zero to disable "
[1744]             "temporary files usage or must be equal to or greater than "
[1745]             "the maximum of the value of \"uwsgi_buffer_size\" and "
[1746]             "one of the \"uwsgi_buffers\"");
[1747] 
[1748]         return NGX_CONF_ERROR;
[1749]     }
[1750] 
[1751] 
[1752]     ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
[1753]                                  prev->upstream.ignore_headers,
[1754]                                  NGX_CONF_BITMASK_SET);
[1755] 
[1756] 
[1757]     ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
[1758]                                  prev->upstream.next_upstream,
[1759]                                  (NGX_CONF_BITMASK_SET
[1760]                                   |NGX_HTTP_UPSTREAM_FT_ERROR
[1761]                                   |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
[1762] 
[1763]     if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
[1764]         conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
[1765]                                        |NGX_HTTP_UPSTREAM_FT_OFF;
[1766]     }
[1767] 
[1768]     if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
[1769]                                   prev->upstream.temp_path,
[1770]                                   &ngx_http_uwsgi_temp_path)
[1771]         != NGX_OK)
[1772]     {
[1773]         return NGX_CONF_ERROR;
[1774]     }
[1775] 
[1776] #if (NGX_HTTP_CACHE)
[1777] 
[1778]     if (conf->upstream.cache == NGX_CONF_UNSET) {
[1779]         ngx_conf_merge_value(conf->upstream.cache,
[1780]                               prev->upstream.cache, 0);
[1781] 
[1782]         conf->upstream.cache_zone = prev->upstream.cache_zone;
[1783]         conf->upstream.cache_value = prev->upstream.cache_value;
[1784]     }
[1785] 
[1786]     if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
[1787]         ngx_shm_zone_t  *shm_zone;
[1788] 
[1789]         shm_zone = conf->upstream.cache_zone;
[1790] 
[1791]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1792]                            "\"uwsgi_cache\" zone \"%V\" is unknown",
[1793]                            &shm_zone->shm.name);
[1794] 
[1795]         return NGX_CONF_ERROR;
[1796]     }
[1797] 
[1798]     ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
[1799]                               prev->upstream.cache_min_uses, 1);
[1800] 
[1801]     ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
[1802]                               prev->upstream.cache_max_range_offset,
[1803]                               NGX_MAX_OFF_T_VALUE);
[1804] 
[1805]     ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
[1806]                               prev->upstream.cache_use_stale,
[1807]                               (NGX_CONF_BITMASK_SET
[1808]                                |NGX_HTTP_UPSTREAM_FT_OFF));
[1809] 
[1810]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
[1811]         conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
[1812]                                          |NGX_HTTP_UPSTREAM_FT_OFF;
[1813]     }
[1814] 
[1815]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
[1816]         conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
[1817]     }
[1818] 
[1819]     if (conf->upstream.cache_methods == 0) {
[1820]         conf->upstream.cache_methods = prev->upstream.cache_methods;
[1821]     }
[1822] 
[1823]     conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;
[1824] 
[1825]     ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
[1826]                              prev->upstream.cache_bypass, NULL);
[1827] 
[1828]     ngx_conf_merge_ptr_value(conf->upstream.no_cache,
[1829]                              prev->upstream.no_cache, NULL);
[1830] 
[1831]     ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
[1832]                              prev->upstream.cache_valid, NULL);
[1833] 
[1834]     if (conf->cache_key.value.data == NULL) {
[1835]         conf->cache_key = prev->cache_key;
[1836]     }
[1837] 
[1838]     if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
[1839]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1840]                            "no \"uwsgi_cache_key\" for \"uwsgi_cache\"");
[1841]     }
[1842] 
[1843]     ngx_conf_merge_value(conf->upstream.cache_lock,
[1844]                               prev->upstream.cache_lock, 0);
[1845] 
[1846]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
[1847]                               prev->upstream.cache_lock_timeout, 5000);
[1848] 
[1849]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
[1850]                               prev->upstream.cache_lock_age, 5000);
[1851] 
[1852]     ngx_conf_merge_value(conf->upstream.cache_revalidate,
[1853]                               prev->upstream.cache_revalidate, 0);
[1854] 
[1855]     ngx_conf_merge_value(conf->upstream.cache_background_update,
[1856]                               prev->upstream.cache_background_update, 0);
[1857] 
[1858] #endif
[1859] 
[1860]     ngx_conf_merge_value(conf->upstream.pass_request_headers,
[1861]                          prev->upstream.pass_request_headers, 1);
[1862]     ngx_conf_merge_value(conf->upstream.pass_request_body,
[1863]                          prev->upstream.pass_request_body, 1);
[1864] 
[1865]     ngx_conf_merge_value(conf->upstream.intercept_errors,
[1866]                          prev->upstream.intercept_errors, 0);
[1867] 
[1868] #if (NGX_HTTP_SSL)
[1869] 
[1870]     if (ngx_http_uwsgi_merge_ssl(cf, conf, prev) != NGX_OK) {
[1871]         return NGX_CONF_ERROR;
[1872]     }
[1873] 
[1874]     ngx_conf_merge_value(conf->upstream.ssl_session_reuse,
[1875]                               prev->upstream.ssl_session_reuse, 1);
[1876] 
[1877]     ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
[1878]                                  (NGX_CONF_BITMASK_SET
[1879]                                   |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[1880]                                   |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[1881] 
[1882]     ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
[1883]                              "DEFAULT");
[1884] 
[1885]     ngx_conf_merge_ptr_value(conf->upstream.ssl_name,
[1886]                               prev->upstream.ssl_name, NULL);
[1887]     ngx_conf_merge_value(conf->upstream.ssl_server_name,
[1888]                               prev->upstream.ssl_server_name, 0);
[1889]     ngx_conf_merge_value(conf->upstream.ssl_verify,
[1890]                               prev->upstream.ssl_verify, 0);
[1891]     ngx_conf_merge_uint_value(conf->ssl_verify_depth,
[1892]                               prev->ssl_verify_depth, 1);
[1893]     ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
[1894]                               prev->ssl_trusted_certificate, "");
[1895]     ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
[1896] 
[1897]     ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate,
[1898]                               prev->upstream.ssl_certificate, NULL);
[1899]     ngx_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
[1900]                               prev->upstream.ssl_certificate_key, NULL);
[1901]     ngx_conf_merge_ptr_value(conf->upstream.ssl_passwords,
[1902]                               prev->upstream.ssl_passwords, NULL);
[1903] 
[1904]     ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
[1905]                               prev->ssl_conf_commands, NULL);
[1906] 
[1907]     if (conf->ssl && ngx_http_uwsgi_set_ssl(cf, conf) != NGX_OK) {
[1908]         return NGX_CONF_ERROR;
[1909]     }
[1910] 
[1911] #endif
[1912] 
[1913]     ngx_conf_merge_str_value(conf->uwsgi_string, prev->uwsgi_string, "");
[1914] 
[1915]     hash.max_size = 512;
[1916]     hash.bucket_size = ngx_align(64, ngx_cacheline_size);
[1917]     hash.name = "uwsgi_hide_headers_hash";
[1918] 
[1919]     if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
[1920]             &prev->upstream, ngx_http_uwsgi_hide_headers, &hash)
[1921]         != NGX_OK)
[1922]     {
[1923]         return NGX_CONF_ERROR;
[1924]     }
[1925] 
[1926]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[1927] 
[1928]     if (clcf->noname
[1929]         && conf->upstream.upstream == NULL && conf->uwsgi_lengths == NULL)
[1930]     {
[1931]         conf->upstream.upstream = prev->upstream.upstream;
[1932] 
[1933]         conf->uwsgi_lengths = prev->uwsgi_lengths;
[1934]         conf->uwsgi_values = prev->uwsgi_values;
[1935] 
[1936] #if (NGX_HTTP_SSL)
[1937]         conf->ssl = prev->ssl;
[1938] #endif
[1939]     }
[1940] 
[1941]     if (clcf->lmt_excpt && clcf->handler == NULL
[1942]         && (conf->upstream.upstream || conf->uwsgi_lengths))
[1943]     {
[1944]         clcf->handler = ngx_http_uwsgi_handler;
[1945]     }
[1946] 
[1947]     ngx_conf_merge_uint_value(conf->modifier1, prev->modifier1, 0);
[1948]     ngx_conf_merge_uint_value(conf->modifier2, prev->modifier2, 0);
[1949] 
[1950]     if (conf->params_source == NULL) {
[1951]         conf->params = prev->params;
[1952] #if (NGX_HTTP_CACHE)
[1953]         conf->params_cache = prev->params_cache;
[1954] #endif
[1955]         conf->params_source = prev->params_source;
[1956]     }
[1957] 
[1958]     rc = ngx_http_uwsgi_init_params(cf, conf, &conf->params, NULL);
[1959]     if (rc != NGX_OK) {
[1960]         return NGX_CONF_ERROR;
[1961]     }
[1962] 
[1963] #if (NGX_HTTP_CACHE)
[1964] 
[1965]     if (conf->upstream.cache) {
[1966]         rc = ngx_http_uwsgi_init_params(cf, conf, &conf->params_cache,
[1967]                                         ngx_http_uwsgi_cache_headers);
[1968]         if (rc != NGX_OK) {
[1969]             return NGX_CONF_ERROR;
[1970]         }
[1971]     }
[1972] 
[1973] #endif
[1974] 
[1975]     /*
[1976]      * special handling to preserve conf->params in the "http" section
[1977]      * to inherit it to all servers
[1978]      */
[1979] 
[1980]     if (prev->params.hash.buckets == NULL
[1981]         && conf->params_source == prev->params_source)
[1982]     {
[1983]         prev->params = conf->params;
[1984] #if (NGX_HTTP_CACHE)
[1985]         prev->params_cache = conf->params_cache;
[1986] #endif
[1987]     }
[1988] 
[1989]     return NGX_CONF_OK;
[1990] }
[1991] 
[1992] 
[1993] static ngx_int_t
[1994] ngx_http_uwsgi_init_params(ngx_conf_t *cf, ngx_http_uwsgi_loc_conf_t *conf,
[1995]     ngx_http_uwsgi_params_t *params, ngx_keyval_t *default_params)
[1996] {
[1997]     u_char                       *p;
[1998]     size_t                        size;
[1999]     uintptr_t                    *code;
[2000]     ngx_uint_t                    i, nsrc;
[2001]     ngx_array_t                   headers_names, params_merged;
[2002]     ngx_keyval_t                 *h;
[2003]     ngx_hash_key_t               *hk;
[2004]     ngx_hash_init_t               hash;
[2005]     ngx_http_upstream_param_t    *src, *s;
[2006]     ngx_http_script_compile_t     sc;
[2007]     ngx_http_script_copy_code_t  *copy;
[2008] 
[2009]     if (params->hash.buckets) {
[2010]         return NGX_OK;
[2011]     }
[2012] 
[2013]     if (conf->params_source == NULL && default_params == NULL) {
[2014]         params->hash.buckets = (void *) 1;
[2015]         return NGX_OK;
[2016]     }
[2017] 
[2018]     params->lengths = ngx_array_create(cf->pool, 64, 1);
[2019]     if (params->lengths == NULL) {
[2020]         return NGX_ERROR;
[2021]     }
[2022] 
[2023]     params->values = ngx_array_create(cf->pool, 512, 1);
[2024]     if (params->values == NULL) {
[2025]         return NGX_ERROR;
[2026]     }
[2027] 
[2028]     if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
[2029]         != NGX_OK)
[2030]     {
[2031]         return NGX_ERROR;
[2032]     }
[2033] 
[2034]     if (conf->params_source) {
[2035]         src = conf->params_source->elts;
[2036]         nsrc = conf->params_source->nelts;
[2037] 
[2038]     } else {
[2039]         src = NULL;
[2040]         nsrc = 0;
[2041]     }
[2042] 
[2043]     if (default_params) {
[2044]         if (ngx_array_init(&params_merged, cf->temp_pool, 4,
[2045]                            sizeof(ngx_http_upstream_param_t))
[2046]             != NGX_OK)
[2047]         {
[2048]             return NGX_ERROR;
[2049]         }
[2050] 
[2051]         for (i = 0; i < nsrc; i++) {
[2052] 
[2053]             s = ngx_array_push(&params_merged);
[2054]             if (s == NULL) {
[2055]                 return NGX_ERROR;
[2056]             }
[2057] 
[2058]             *s = src[i];
[2059]         }
[2060] 
[2061]         h = default_params;
[2062] 
[2063]         while (h->key.len) {
[2064] 
[2065]             src = params_merged.elts;
[2066]             nsrc = params_merged.nelts;
[2067] 
[2068]             for (i = 0; i < nsrc; i++) {
[2069]                 if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
[2070]                     goto next;
[2071]                 }
[2072]             }
[2073] 
[2074]             s = ngx_array_push(&params_merged);
[2075]             if (s == NULL) {
[2076]                 return NGX_ERROR;
[2077]             }
[2078] 
[2079]             s->key = h->key;
[2080]             s->value = h->value;
[2081]             s->skip_empty = 1;
[2082] 
[2083]         next:
[2084] 
[2085]             h++;
[2086]         }
[2087] 
[2088]         src = params_merged.elts;
[2089]         nsrc = params_merged.nelts;
[2090]     }
[2091] 
[2092]     for (i = 0; i < nsrc; i++) {
[2093] 
[2094]         if (src[i].key.len > sizeof("HTTP_") - 1
[2095]             && ngx_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
[2096]         {
[2097]             hk = ngx_array_push(&headers_names);
[2098]             if (hk == NULL) {
[2099]                 return NGX_ERROR;
[2100]             }
[2101] 
[2102]             hk->key.len = src[i].key.len - 5;
[2103]             hk->key.data = src[i].key.data + 5;
[2104]             hk->key_hash = ngx_hash_key_lc(hk->key.data, hk->key.len);
[2105]             hk->value = (void *) 1;
[2106] 
[2107]             if (src[i].value.len == 0) {
[2108]                 continue;
[2109]             }
[2110]         }
[2111] 
[2112]         copy = ngx_array_push_n(params->lengths,
[2113]                                 sizeof(ngx_http_script_copy_code_t));
[2114]         if (copy == NULL) {
[2115]             return NGX_ERROR;
[2116]         }
[2117] 
[2118]         copy->code = (ngx_http_script_code_pt) (void *)
[2119]                                                  ngx_http_script_copy_len_code;
[2120]         copy->len = src[i].key.len;
[2121] 
[2122]         copy = ngx_array_push_n(params->lengths,
[2123]                                 sizeof(ngx_http_script_copy_code_t));
[2124]         if (copy == NULL) {
[2125]             return NGX_ERROR;
[2126]         }
[2127] 
[2128]         copy->code = (ngx_http_script_code_pt) (void *)
[2129]                                                  ngx_http_script_copy_len_code;
[2130]         copy->len = src[i].skip_empty;
[2131] 
[2132] 
[2133]         size = (sizeof(ngx_http_script_copy_code_t)
[2134]                 + src[i].key.len + sizeof(uintptr_t) - 1)
[2135]                & ~(sizeof(uintptr_t) - 1);
[2136] 
[2137]         copy = ngx_array_push_n(params->values, size);
[2138]         if (copy == NULL) {
[2139]             return NGX_ERROR;
[2140]         }
[2141] 
[2142]         copy->code = ngx_http_script_copy_code;
[2143]         copy->len = src[i].key.len;
[2144] 
[2145]         p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
[2146]         ngx_memcpy(p, src[i].key.data, src[i].key.len);
[2147] 
[2148] 
[2149]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[2150] 
[2151]         sc.cf = cf;
[2152]         sc.source = &src[i].value;
[2153]         sc.flushes = &params->flushes;
[2154]         sc.lengths = &params->lengths;
[2155]         sc.values = &params->values;
[2156] 
[2157]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[2158]             return NGX_ERROR;
[2159]         }
[2160] 
[2161]         code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
[2162]         if (code == NULL) {
[2163]             return NGX_ERROR;
[2164]         }
[2165] 
[2166]         *code = (uintptr_t) NULL;
[2167] 
[2168] 
[2169]         code = ngx_array_push_n(params->values, sizeof(uintptr_t));
[2170]         if (code == NULL) {
[2171]             return NGX_ERROR;
[2172]         }
[2173] 
[2174]         *code = (uintptr_t) NULL;
[2175]     }
[2176] 
[2177]     code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
[2178]     if (code == NULL) {
[2179]         return NGX_ERROR;
[2180]     }
[2181] 
[2182]     *code = (uintptr_t) NULL;
[2183] 
[2184]     params->number = headers_names.nelts;
[2185] 
[2186]     hash.hash = &params->hash;
[2187]     hash.key = ngx_hash_key_lc;
[2188]     hash.max_size = 512;
[2189]     hash.bucket_size = 64;
[2190]     hash.name = "uwsgi_params_hash";
[2191]     hash.pool = cf->pool;
[2192]     hash.temp_pool = NULL;
[2193] 
[2194]     return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
[2195] }
[2196] 
[2197] 
[2198] static char *
[2199] ngx_http_uwsgi_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2200] {
[2201]     ngx_http_uwsgi_loc_conf_t *uwcf = conf;
[2202] 
[2203]     size_t                      add;
[2204]     ngx_url_t                   u;
[2205]     ngx_str_t                  *value, *url;
[2206]     ngx_uint_t                  n;
[2207]     ngx_http_core_loc_conf_t   *clcf;
[2208]     ngx_http_script_compile_t   sc;
[2209] 
[2210]     if (uwcf->upstream.upstream || uwcf->uwsgi_lengths) {
[2211]         return "is duplicate";
[2212]     }
[2213] 
[2214]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[2215]     clcf->handler = ngx_http_uwsgi_handler;
[2216] 
[2217]     value = cf->args->elts;
[2218] 
[2219]     url = &value[1];
[2220] 
[2221]     n = ngx_http_script_variables_count(url);
[2222] 
[2223]     if (n) {
[2224] 
[2225]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[2226] 
[2227]         sc.cf = cf;
[2228]         sc.source = url;
[2229]         sc.lengths = &uwcf->uwsgi_lengths;
[2230]         sc.values = &uwcf->uwsgi_values;
[2231]         sc.variables = n;
[2232]         sc.complete_lengths = 1;
[2233]         sc.complete_values = 1;
[2234] 
[2235]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[2236]             return NGX_CONF_ERROR;
[2237]         }
[2238] 
[2239] #if (NGX_HTTP_SSL)
[2240]         uwcf->ssl = 1;
[2241] #endif
[2242] 
[2243]         return NGX_CONF_OK;
[2244]     }
[2245] 
[2246]     if (ngx_strncasecmp(url->data, (u_char *) "uwsgi://", 8) == 0) {
[2247]         add = 8;
[2248] 
[2249]     } else if (ngx_strncasecmp(url->data, (u_char *) "suwsgi://", 9) == 0) {
[2250] 
[2251] #if (NGX_HTTP_SSL)
[2252]         add = 9;
[2253]         uwcf->ssl = 1;
[2254] #else
[2255]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2256]                            "suwsgi protocol requires SSL support");
[2257]         return NGX_CONF_ERROR;
[2258] #endif
[2259] 
[2260]     } else {
[2261]         add = 0;
[2262]     }
[2263] 
[2264]     ngx_memzero(&u, sizeof(ngx_url_t));
[2265] 
[2266]     u.url.len = url->len - add;
[2267]     u.url.data = url->data + add;
[2268]     u.no_resolve = 1;
[2269] 
[2270]     uwcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
[2271]     if (uwcf->upstream.upstream == NULL) {
[2272]         return NGX_CONF_ERROR;
[2273]     }
[2274] 
[2275]     if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
[2276]         clcf->auto_redirect = 1;
[2277]     }
[2278] 
[2279]     return NGX_CONF_OK;
[2280] }
[2281] 
[2282] 
[2283] static char *
[2284] ngx_http_uwsgi_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2285] {
[2286]     ngx_http_uwsgi_loc_conf_t *uwcf = conf;
[2287] 
[2288]     ngx_str_t                  *value;
[2289]     ngx_http_script_compile_t   sc;
[2290] 
[2291]     if (uwcf->upstream.store != NGX_CONF_UNSET) {
[2292]         return "is duplicate";
[2293]     }
[2294] 
[2295]     value = cf->args->elts;
[2296] 
[2297]     if (ngx_strcmp(value[1].data, "off") == 0) {
[2298]         uwcf->upstream.store = 0;
[2299]         return NGX_CONF_OK;
[2300]     }
[2301] 
[2302] #if (NGX_HTTP_CACHE)
[2303] 
[2304]     if (uwcf->upstream.cache > 0) {
[2305]         return "is incompatible with \"uwsgi_cache\"";
[2306]     }
[2307] 
[2308] #endif
[2309] 
[2310]     uwcf->upstream.store = 1;
[2311] 
[2312]     if (ngx_strcmp(value[1].data, "on") == 0) {
[2313]         return NGX_CONF_OK;
[2314]     }
[2315] 
[2316]     /* include the terminating '\0' into script */
[2317]     value[1].len++;
[2318] 
[2319]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[2320] 
[2321]     sc.cf = cf;
[2322]     sc.source = &value[1];
[2323]     sc.lengths = &uwcf->upstream.store_lengths;
[2324]     sc.values = &uwcf->upstream.store_values;
[2325]     sc.variables = ngx_http_script_variables_count(&value[1]);
[2326]     sc.complete_lengths = 1;
[2327]     sc.complete_values = 1;
[2328] 
[2329]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[2330]         return NGX_CONF_ERROR;
[2331]     }
[2332] 
[2333]     return NGX_CONF_OK;
[2334] }
[2335] 
[2336] 
[2337] #if (NGX_HTTP_CACHE)
[2338] 
[2339] static char *
[2340] ngx_http_uwsgi_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2341] {
[2342]     ngx_http_uwsgi_loc_conf_t *uwcf = conf;
[2343] 
[2344]     ngx_str_t                         *value;
[2345]     ngx_http_complex_value_t           cv;
[2346]     ngx_http_compile_complex_value_t   ccv;
[2347] 
[2348]     value = cf->args->elts;
[2349] 
[2350]     if (uwcf->upstream.cache != NGX_CONF_UNSET) {
[2351]         return "is duplicate";
[2352]     }
[2353] 
[2354]     if (ngx_strcmp(value[1].data, "off") == 0) {
[2355]         uwcf->upstream.cache = 0;
[2356]         return NGX_CONF_OK;
[2357]     }
[2358] 
[2359]     if (uwcf->upstream.store > 0) {
[2360]         return "is incompatible with \"uwsgi_store\"";
[2361]     }
[2362] 
[2363]     uwcf->upstream.cache = 1;
[2364] 
[2365]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[2366] 
[2367]     ccv.cf = cf;
[2368]     ccv.value = &value[1];
[2369]     ccv.complex_value = &cv;
[2370] 
[2371]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[2372]         return NGX_CONF_ERROR;
[2373]     }
[2374] 
[2375]     if (cv.lengths != NULL) {
[2376] 
[2377]         uwcf->upstream.cache_value = ngx_palloc(cf->pool,
[2378]                                              sizeof(ngx_http_complex_value_t));
[2379]         if (uwcf->upstream.cache_value == NULL) {
[2380]             return NGX_CONF_ERROR;
[2381]         }
[2382] 
[2383]         *uwcf->upstream.cache_value = cv;
[2384] 
[2385]         return NGX_CONF_OK;
[2386]     }
[2387] 
[2388]     uwcf->upstream.cache_zone = ngx_shared_memory_add(cf, &value[1], 0,
[2389]                                                       &ngx_http_uwsgi_module);
[2390]     if (uwcf->upstream.cache_zone == NULL) {
[2391]         return NGX_CONF_ERROR;
[2392]     }
[2393] 
[2394]     return NGX_CONF_OK;
[2395] }
[2396] 
[2397] 
[2398] static char *
[2399] ngx_http_uwsgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2400] {
[2401]     ngx_http_uwsgi_loc_conf_t *uwcf = conf;
[2402] 
[2403]     ngx_str_t                         *value;
[2404]     ngx_http_compile_complex_value_t   ccv;
[2405] 
[2406]     value = cf->args->elts;
[2407] 
[2408]     if (uwcf->cache_key.value.data) {
[2409]         return "is duplicate";
[2410]     }
[2411] 
[2412]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[2413] 
[2414]     ccv.cf = cf;
[2415]     ccv.value = &value[1];
[2416]     ccv.complex_value = &uwcf->cache_key;
[2417] 
[2418]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[2419]         return NGX_CONF_ERROR;
[2420]     }
[2421] 
[2422]     return NGX_CONF_OK;
[2423] }
[2424] 
[2425] #endif
[2426] 
[2427] 
[2428] #if (NGX_HTTP_SSL)
[2429] 
[2430] static char *
[2431] ngx_http_uwsgi_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2432] {
[2433]     ngx_http_uwsgi_loc_conf_t *uwcf = conf;
[2434] 
[2435]     ngx_str_t  *value;
[2436] 
[2437]     if (uwcf->upstream.ssl_passwords != NGX_CONF_UNSET_PTR) {
[2438]         return "is duplicate";
[2439]     }
[2440] 
[2441]     value = cf->args->elts;
[2442] 
[2443]     uwcf->upstream.ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);
[2444] 
[2445]     if (uwcf->upstream.ssl_passwords == NULL) {
[2446]         return NGX_CONF_ERROR;
[2447]     }
[2448] 
[2449]     return NGX_CONF_OK;
[2450] }
[2451] 
[2452] 
[2453] static char *
[2454] ngx_http_uwsgi_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[2455] {
[2456] #ifndef SSL_CONF_FLAG_FILE
[2457]     return "is not supported on this platform";
[2458] #else
[2459]     return NGX_CONF_OK;
[2460] #endif
[2461] }
[2462] 
[2463] 
[2464] static ngx_int_t
[2465] ngx_http_uwsgi_merge_ssl(ngx_conf_t *cf, ngx_http_uwsgi_loc_conf_t *conf,
[2466]     ngx_http_uwsgi_loc_conf_t *prev)
[2467] {
[2468]     ngx_uint_t  preserve;
[2469] 
[2470]     if (conf->ssl_protocols == 0
[2471]         && conf->ssl_ciphers.data == NULL
[2472]         && conf->upstream.ssl_certificate == NGX_CONF_UNSET_PTR
[2473]         && conf->upstream.ssl_certificate_key == NGX_CONF_UNSET_PTR
[2474]         && conf->upstream.ssl_passwords == NGX_CONF_UNSET_PTR
[2475]         && conf->upstream.ssl_verify == NGX_CONF_UNSET
[2476]         && conf->ssl_verify_depth == NGX_CONF_UNSET_UINT
[2477]         && conf->ssl_trusted_certificate.data == NULL
[2478]         && conf->ssl_crl.data == NULL
[2479]         && conf->upstream.ssl_session_reuse == NGX_CONF_UNSET
[2480]         && conf->ssl_conf_commands == NGX_CONF_UNSET_PTR)
[2481]     {
[2482]         if (prev->upstream.ssl) {
[2483]             conf->upstream.ssl = prev->upstream.ssl;
[2484]             return NGX_OK;
[2485]         }
[2486] 
[2487]         preserve = 1;
[2488] 
[2489]     } else {
[2490]         preserve = 0;
[2491]     }
[2492] 
[2493]     conf->upstream.ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
[2494]     if (conf->upstream.ssl == NULL) {
[2495]         return NGX_ERROR;
[2496]     }
[2497] 
[2498]     conf->upstream.ssl->log = cf->log;
[2499] 
[2500]     /*
[2501]      * special handling to preserve conf->upstream.ssl
[2502]      * in the "http" section to inherit it to all servers
[2503]      */
[2504] 
[2505]     if (preserve) {
[2506]         prev->upstream.ssl = conf->upstream.ssl;
[2507]     }
[2508] 
[2509]     return NGX_OK;
[2510] }
[2511] 
[2512] 
[2513] static ngx_int_t
[2514] ngx_http_uwsgi_set_ssl(ngx_conf_t *cf, ngx_http_uwsgi_loc_conf_t *uwcf)
[2515] {
[2516]     ngx_pool_cleanup_t  *cln;
[2517] 
[2518]     if (uwcf->upstream.ssl->ctx) {
[2519]         return NGX_OK;
[2520]     }
[2521] 
[2522]     if (ngx_ssl_create(uwcf->upstream.ssl, uwcf->ssl_protocols, NULL)
[2523]         != NGX_OK)
[2524]     {
[2525]         return NGX_ERROR;
[2526]     }
[2527] 
[2528]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[2529]     if (cln == NULL) {
[2530]         ngx_ssl_cleanup_ctx(uwcf->upstream.ssl);
[2531]         return NGX_ERROR;
[2532]     }
[2533] 
[2534]     cln->handler = ngx_ssl_cleanup_ctx;
[2535]     cln->data = uwcf->upstream.ssl;
[2536] 
[2537]     if (ngx_ssl_ciphers(cf, uwcf->upstream.ssl, &uwcf->ssl_ciphers, 0)
[2538]         != NGX_OK)
[2539]     {
[2540]         return NGX_ERROR;
[2541]     }
[2542] 
[2543]     if (uwcf->upstream.ssl_certificate
[2544]         && uwcf->upstream.ssl_certificate->value.len)
[2545]     {
[2546]         if (uwcf->upstream.ssl_certificate_key == NULL) {
[2547]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[2548]                           "no \"uwsgi_ssl_certificate_key\" is defined "
[2549]                           "for certificate \"%V\"",
[2550]                           &uwcf->upstream.ssl_certificate->value);
[2551]             return NGX_ERROR;
[2552]         }
[2553] 
[2554]         if (uwcf->upstream.ssl_certificate->lengths
[2555]             || uwcf->upstream.ssl_certificate_key->lengths)
[2556]         {
[2557]             uwcf->upstream.ssl_passwords =
[2558]                   ngx_ssl_preserve_passwords(cf, uwcf->upstream.ssl_passwords);
[2559]             if (uwcf->upstream.ssl_passwords == NULL) {
[2560]                 return NGX_ERROR;
[2561]             }
[2562] 
[2563]         } else {
[2564]             if (ngx_ssl_certificate(cf, uwcf->upstream.ssl,
[2565]                                     &uwcf->upstream.ssl_certificate->value,
[2566]                                     &uwcf->upstream.ssl_certificate_key->value,
[2567]                                     uwcf->upstream.ssl_passwords)
[2568]                 != NGX_OK)
[2569]             {
[2570]                 return NGX_ERROR;
[2571]             }
[2572]         }
[2573]     }
[2574] 
[2575]     if (uwcf->upstream.ssl_verify) {
[2576]         if (uwcf->ssl_trusted_certificate.len == 0) {
[2577]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[2578]                       "no uwsgi_ssl_trusted_certificate for uwsgi_ssl_verify");
[2579]             return NGX_ERROR;
[2580]         }
[2581] 
[2582]         if (ngx_ssl_trusted_certificate(cf, uwcf->upstream.ssl,
[2583]                                         &uwcf->ssl_trusted_certificate,
[2584]                                         uwcf->ssl_verify_depth)
[2585]             != NGX_OK)
[2586]         {
[2587]             return NGX_ERROR;
[2588]         }
[2589] 
[2590]         if (ngx_ssl_crl(cf, uwcf->upstream.ssl, &uwcf->ssl_crl) != NGX_OK) {
[2591]             return NGX_ERROR;
[2592]         }
[2593]     }
[2594] 
[2595]     if (ngx_ssl_client_session_cache(cf, uwcf->upstream.ssl,
[2596]                                      uwcf->upstream.ssl_session_reuse)
[2597]         != NGX_OK)
[2598]     {
[2599]         return NGX_ERROR;
[2600]     }
[2601] 
[2602]     if (ngx_ssl_conf_commands(cf, uwcf->upstream.ssl, uwcf->ssl_conf_commands)
[2603]         != NGX_OK)
[2604]     {
[2605]         return NGX_ERROR;
[2606]     }
[2607] 
[2608]     return NGX_OK;
[2609] }
[2610] 
[2611] #endif
