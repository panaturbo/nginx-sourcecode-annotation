[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  * Copyright (C) Manlio Perillo (manlio.perillo@gmail.com)
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_http.h>
[12] 
[13] 
[14] typedef struct {
[15]     ngx_array_t                caches;  /* ngx_http_file_cache_t * */
[16] } ngx_http_scgi_main_conf_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_array_t               *flushes;
[21]     ngx_array_t               *lengths;
[22]     ngx_array_t               *values;
[23]     ngx_uint_t                 number;
[24]     ngx_hash_t                 hash;
[25] } ngx_http_scgi_params_t;
[26] 
[27] 
[28] typedef struct {
[29]     ngx_http_upstream_conf_t   upstream;
[30] 
[31]     ngx_http_scgi_params_t     params;
[32] #if (NGX_HTTP_CACHE)
[33]     ngx_http_scgi_params_t     params_cache;
[34] #endif
[35]     ngx_array_t               *params_source;
[36] 
[37]     ngx_array_t               *scgi_lengths;
[38]     ngx_array_t               *scgi_values;
[39] 
[40] #if (NGX_HTTP_CACHE)
[41]     ngx_http_complex_value_t   cache_key;
[42] #endif
[43] } ngx_http_scgi_loc_conf_t;
[44] 
[45] 
[46] static ngx_int_t ngx_http_scgi_eval(ngx_http_request_t *r,
[47]     ngx_http_scgi_loc_conf_t *scf);
[48] static ngx_int_t ngx_http_scgi_create_request(ngx_http_request_t *r);
[49] static ngx_int_t ngx_http_scgi_reinit_request(ngx_http_request_t *r);
[50] static ngx_int_t ngx_http_scgi_process_status_line(ngx_http_request_t *r);
[51] static ngx_int_t ngx_http_scgi_process_header(ngx_http_request_t *r);
[52] static ngx_int_t ngx_http_scgi_input_filter_init(void *data);
[53] static void ngx_http_scgi_abort_request(ngx_http_request_t *r);
[54] static void ngx_http_scgi_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
[55] 
[56] static void *ngx_http_scgi_create_main_conf(ngx_conf_t *cf);
[57] static void *ngx_http_scgi_create_loc_conf(ngx_conf_t *cf);
[58] static char *ngx_http_scgi_merge_loc_conf(ngx_conf_t *cf, void *parent,
[59]     void *child);
[60] static ngx_int_t ngx_http_scgi_init_params(ngx_conf_t *cf,
[61]     ngx_http_scgi_loc_conf_t *conf, ngx_http_scgi_params_t *params,
[62]     ngx_keyval_t *default_params);
[63] 
[64] static char *ngx_http_scgi_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[65] static char *ngx_http_scgi_store(ngx_conf_t *cf, ngx_command_t *cmd,
[66]     void *conf);
[67] 
[68] #if (NGX_HTTP_CACHE)
[69] static ngx_int_t ngx_http_scgi_create_key(ngx_http_request_t *r);
[70] static char *ngx_http_scgi_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[71]     void *conf);
[72] static char *ngx_http_scgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
[73]     void *conf);
[74] #endif
[75] 
[76] 
[77] static ngx_conf_bitmask_t ngx_http_scgi_next_upstream_masks[] = {
[78]     { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
[79]     { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
[80]     { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
[81]     { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
[82]     { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
[83]     { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
[84]     { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
[85]     { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[86]     { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
[87]     { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
[88]     { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
[89]     { ngx_null_string, 0 }
[90] };
[91] 
[92] 
[93] ngx_module_t  ngx_http_scgi_module;
[94] 
[95] 
[96] static ngx_command_t ngx_http_scgi_commands[] = {
[97] 
[98]     { ngx_string("scgi_pass"),
[99]       NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[100]       ngx_http_scgi_pass,
[101]       NGX_HTTP_LOC_CONF_OFFSET,
[102]       0,
[103]       NULL },
[104] 
[105]     { ngx_string("scgi_store"),
[106]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[107]       ngx_http_scgi_store,
[108]       NGX_HTTP_LOC_CONF_OFFSET,
[109]       0,
[110]       NULL },
[111] 
[112]     { ngx_string("scgi_store_access"),
[113]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[114]       ngx_conf_set_access_slot,
[115]       NGX_HTTP_LOC_CONF_OFFSET,
[116]       offsetof(ngx_http_scgi_loc_conf_t, upstream.store_access),
[117]       NULL },
[118] 
[119]     { ngx_string("scgi_buffering"),
[120]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[121]       ngx_conf_set_flag_slot,
[122]       NGX_HTTP_LOC_CONF_OFFSET,
[123]       offsetof(ngx_http_scgi_loc_conf_t, upstream.buffering),
[124]       NULL },
[125] 
[126]     { ngx_string("scgi_request_buffering"),
[127]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[128]       ngx_conf_set_flag_slot,
[129]       NGX_HTTP_LOC_CONF_OFFSET,
[130]       offsetof(ngx_http_scgi_loc_conf_t, upstream.request_buffering),
[131]       NULL },
[132] 
[133]     { ngx_string("scgi_ignore_client_abort"),
[134]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[135]       ngx_conf_set_flag_slot,
[136]       NGX_HTTP_LOC_CONF_OFFSET,
[137]       offsetof(ngx_http_scgi_loc_conf_t, upstream.ignore_client_abort),
[138]       NULL },
[139] 
[140]     { ngx_string("scgi_bind"),
[141]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[142]       ngx_http_upstream_bind_set_slot,
[143]       NGX_HTTP_LOC_CONF_OFFSET,
[144]       offsetof(ngx_http_scgi_loc_conf_t, upstream.local),
[145]       NULL },
[146] 
[147]     { ngx_string("scgi_socket_keepalive"),
[148]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[149]       ngx_conf_set_flag_slot,
[150]       NGX_HTTP_LOC_CONF_OFFSET,
[151]       offsetof(ngx_http_scgi_loc_conf_t, upstream.socket_keepalive),
[152]       NULL },
[153] 
[154]     { ngx_string("scgi_connect_timeout"),
[155]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[156]       ngx_conf_set_msec_slot,
[157]       NGX_HTTP_LOC_CONF_OFFSET,
[158]       offsetof(ngx_http_scgi_loc_conf_t, upstream.connect_timeout),
[159]       NULL },
[160] 
[161]     { ngx_string("scgi_send_timeout"),
[162]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[163]       ngx_conf_set_msec_slot,
[164]       NGX_HTTP_LOC_CONF_OFFSET,
[165]       offsetof(ngx_http_scgi_loc_conf_t, upstream.send_timeout),
[166]       NULL },
[167] 
[168]     { ngx_string("scgi_buffer_size"),
[169]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[170]       ngx_conf_set_size_slot,
[171]       NGX_HTTP_LOC_CONF_OFFSET,
[172]       offsetof(ngx_http_scgi_loc_conf_t, upstream.buffer_size),
[173]       NULL },
[174] 
[175]     { ngx_string("scgi_pass_request_headers"),
[176]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[177]       ngx_conf_set_flag_slot,
[178]       NGX_HTTP_LOC_CONF_OFFSET,
[179]       offsetof(ngx_http_scgi_loc_conf_t, upstream.pass_request_headers),
[180]       NULL },
[181] 
[182]     { ngx_string("scgi_pass_request_body"),
[183]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[184]       ngx_conf_set_flag_slot,
[185]       NGX_HTTP_LOC_CONF_OFFSET,
[186]       offsetof(ngx_http_scgi_loc_conf_t, upstream.pass_request_body),
[187]       NULL },
[188] 
[189]     { ngx_string("scgi_intercept_errors"),
[190]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[191]       ngx_conf_set_flag_slot,
[192]       NGX_HTTP_LOC_CONF_OFFSET,
[193]       offsetof(ngx_http_scgi_loc_conf_t, upstream.intercept_errors),
[194]       NULL },
[195] 
[196]     { ngx_string("scgi_read_timeout"),
[197]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[198]       ngx_conf_set_msec_slot,
[199]       NGX_HTTP_LOC_CONF_OFFSET,
[200]       offsetof(ngx_http_scgi_loc_conf_t, upstream.read_timeout),
[201]       NULL },
[202] 
[203]     { ngx_string("scgi_buffers"),
[204]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[205]       ngx_conf_set_bufs_slot,
[206]       NGX_HTTP_LOC_CONF_OFFSET,
[207]       offsetof(ngx_http_scgi_loc_conf_t, upstream.bufs),
[208]       NULL },
[209] 
[210]     { ngx_string("scgi_busy_buffers_size"),
[211]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[212]       ngx_conf_set_size_slot,
[213]       NGX_HTTP_LOC_CONF_OFFSET,
[214]       offsetof(ngx_http_scgi_loc_conf_t, upstream.busy_buffers_size_conf),
[215]       NULL },
[216] 
[217]     { ngx_string("scgi_force_ranges"),
[218]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[219]       ngx_conf_set_flag_slot,
[220]       NGX_HTTP_LOC_CONF_OFFSET,
[221]       offsetof(ngx_http_scgi_loc_conf_t, upstream.force_ranges),
[222]       NULL },
[223] 
[224]     { ngx_string("scgi_limit_rate"),
[225]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[226]       ngx_conf_set_size_slot,
[227]       NGX_HTTP_LOC_CONF_OFFSET,
[228]       offsetof(ngx_http_scgi_loc_conf_t, upstream.limit_rate),
[229]       NULL },
[230] 
[231] #if (NGX_HTTP_CACHE)
[232] 
[233]     { ngx_string("scgi_cache"),
[234]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[235]       ngx_http_scgi_cache,
[236]       NGX_HTTP_LOC_CONF_OFFSET,
[237]       0,
[238]       NULL },
[239] 
[240]     { ngx_string("scgi_cache_key"),
[241]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[242]       ngx_http_scgi_cache_key,
[243]       NGX_HTTP_LOC_CONF_OFFSET,
[244]       0,
[245]       NULL },
[246] 
[247]     { ngx_string("scgi_cache_path"),
[248]       NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
[249]       ngx_http_file_cache_set_slot,
[250]       NGX_HTTP_MAIN_CONF_OFFSET,
[251]       offsetof(ngx_http_scgi_main_conf_t, caches),
[252]       &ngx_http_scgi_module },
[253] 
[254]     { ngx_string("scgi_cache_bypass"),
[255]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[256]       ngx_http_set_predicate_slot,
[257]       NGX_HTTP_LOC_CONF_OFFSET,
[258]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_bypass),
[259]       NULL },
[260] 
[261]     { ngx_string("scgi_no_cache"),
[262]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[263]       ngx_http_set_predicate_slot,
[264]       NGX_HTTP_LOC_CONF_OFFSET,
[265]       offsetof(ngx_http_scgi_loc_conf_t, upstream.no_cache),
[266]       NULL },
[267] 
[268]     { ngx_string("scgi_cache_valid"),
[269]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[270]       ngx_http_file_cache_valid_set_slot,
[271]       NGX_HTTP_LOC_CONF_OFFSET,
[272]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_valid),
[273]       NULL },
[274] 
[275]     { ngx_string("scgi_cache_min_uses"),
[276]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[277]       ngx_conf_set_num_slot,
[278]       NGX_HTTP_LOC_CONF_OFFSET,
[279]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_min_uses),
[280]       NULL },
[281] 
[282]     { ngx_string("scgi_cache_max_range_offset"),
[283]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[284]       ngx_conf_set_off_slot,
[285]       NGX_HTTP_LOC_CONF_OFFSET,
[286]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_max_range_offset),
[287]       NULL },
[288] 
[289]     { ngx_string("scgi_cache_use_stale"),
[290]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[291]       ngx_conf_set_bitmask_slot,
[292]       NGX_HTTP_LOC_CONF_OFFSET,
[293]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_use_stale),
[294]       &ngx_http_scgi_next_upstream_masks },
[295] 
[296]     { ngx_string("scgi_cache_methods"),
[297]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[298]       ngx_conf_set_bitmask_slot,
[299]       NGX_HTTP_LOC_CONF_OFFSET,
[300]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_methods),
[301]       &ngx_http_upstream_cache_method_mask },
[302] 
[303]     { ngx_string("scgi_cache_lock"),
[304]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[305]       ngx_conf_set_flag_slot,
[306]       NGX_HTTP_LOC_CONF_OFFSET,
[307]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_lock),
[308]       NULL },
[309] 
[310]     { ngx_string("scgi_cache_lock_timeout"),
[311]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[312]       ngx_conf_set_msec_slot,
[313]       NGX_HTTP_LOC_CONF_OFFSET,
[314]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_lock_timeout),
[315]       NULL },
[316] 
[317]     { ngx_string("scgi_cache_lock_age"),
[318]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[319]       ngx_conf_set_msec_slot,
[320]       NGX_HTTP_LOC_CONF_OFFSET,
[321]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_lock_age),
[322]       NULL },
[323] 
[324]     { ngx_string("scgi_cache_revalidate"),
[325]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[326]       ngx_conf_set_flag_slot,
[327]       NGX_HTTP_LOC_CONF_OFFSET,
[328]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_revalidate),
[329]       NULL },
[330] 
[331]     { ngx_string("scgi_cache_background_update"),
[332]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[333]       ngx_conf_set_flag_slot,
[334]       NGX_HTTP_LOC_CONF_OFFSET,
[335]       offsetof(ngx_http_scgi_loc_conf_t, upstream.cache_background_update),
[336]       NULL },
[337] 
[338] #endif
[339] 
[340]     { ngx_string("scgi_temp_path"),
[341]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[342]       ngx_conf_set_path_slot,
[343]       NGX_HTTP_LOC_CONF_OFFSET,
[344]       offsetof(ngx_http_scgi_loc_conf_t, upstream.temp_path),
[345]       NULL },
[346] 
[347]     { ngx_string("scgi_max_temp_file_size"),
[348]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[349]       ngx_conf_set_size_slot,
[350]       NGX_HTTP_LOC_CONF_OFFSET,
[351]       offsetof(ngx_http_scgi_loc_conf_t, upstream.max_temp_file_size_conf),
[352]       NULL },
[353] 
[354]     { ngx_string("scgi_temp_file_write_size"),
[355]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[356]       ngx_conf_set_size_slot,
[357]       NGX_HTTP_LOC_CONF_OFFSET,
[358]       offsetof(ngx_http_scgi_loc_conf_t, upstream.temp_file_write_size_conf),
[359]       NULL },
[360] 
[361]     { ngx_string("scgi_next_upstream"),
[362]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[363]       ngx_conf_set_bitmask_slot,
[364]       NGX_HTTP_LOC_CONF_OFFSET,
[365]       offsetof(ngx_http_scgi_loc_conf_t, upstream.next_upstream),
[366]       &ngx_http_scgi_next_upstream_masks },
[367] 
[368]     { ngx_string("scgi_next_upstream_tries"),
[369]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[370]       ngx_conf_set_num_slot,
[371]       NGX_HTTP_LOC_CONF_OFFSET,
[372]       offsetof(ngx_http_scgi_loc_conf_t, upstream.next_upstream_tries),
[373]       NULL },
[374] 
[375]     { ngx_string("scgi_next_upstream_timeout"),
[376]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[377]       ngx_conf_set_msec_slot,
[378]       NGX_HTTP_LOC_CONF_OFFSET,
[379]       offsetof(ngx_http_scgi_loc_conf_t, upstream.next_upstream_timeout),
[380]       NULL },
[381] 
[382]     { ngx_string("scgi_param"),
[383]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
[384]       ngx_http_upstream_param_set_slot,
[385]       NGX_HTTP_LOC_CONF_OFFSET,
[386]       offsetof(ngx_http_scgi_loc_conf_t, params_source),
[387]       NULL },
[388] 
[389]     { ngx_string("scgi_pass_header"),
[390]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[391]       ngx_conf_set_str_array_slot,
[392]       NGX_HTTP_LOC_CONF_OFFSET,
[393]       offsetof(ngx_http_scgi_loc_conf_t, upstream.pass_headers),
[394]       NULL },
[395] 
[396]     { ngx_string("scgi_hide_header"),
[397]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[398]       ngx_conf_set_str_array_slot,
[399]       NGX_HTTP_LOC_CONF_OFFSET,
[400]       offsetof(ngx_http_scgi_loc_conf_t, upstream.hide_headers),
[401]       NULL },
[402] 
[403]     { ngx_string("scgi_ignore_headers"),
[404]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[405]       ngx_conf_set_bitmask_slot,
[406]       NGX_HTTP_LOC_CONF_OFFSET,
[407]       offsetof(ngx_http_scgi_loc_conf_t, upstream.ignore_headers),
[408]       &ngx_http_upstream_ignore_headers_masks },
[409] 
[410]       ngx_null_command
[411] };
[412] 
[413] 
[414] static ngx_http_module_t ngx_http_scgi_module_ctx = {
[415]     NULL,                                  /* preconfiguration */
[416]     NULL,                                  /* postconfiguration */
[417] 
[418]     ngx_http_scgi_create_main_conf,        /* create main configuration */
[419]     NULL,                                  /* init main configuration */
[420] 
[421]     NULL,                                  /* create server configuration */
[422]     NULL,                                  /* merge server configuration */
[423] 
[424]     ngx_http_scgi_create_loc_conf,         /* create location configuration */
[425]     ngx_http_scgi_merge_loc_conf           /* merge location configuration */
[426] };
[427] 
[428] 
[429] ngx_module_t ngx_http_scgi_module = {
[430]     NGX_MODULE_V1,
[431]     &ngx_http_scgi_module_ctx,             /* module context */
[432]     ngx_http_scgi_commands,                /* module directives */
[433]     NGX_HTTP_MODULE,                       /* module type */
[434]     NULL,                                  /* init master */
[435]     NULL,                                  /* init module */
[436]     NULL,                                  /* init process */
[437]     NULL,                                  /* init thread */
[438]     NULL,                                  /* exit thread */
[439]     NULL,                                  /* exit process */
[440]     NULL,                                  /* exit master */
[441]     NGX_MODULE_V1_PADDING
[442] };
[443] 
[444] 
[445] static ngx_str_t ngx_http_scgi_hide_headers[] = {
[446]     ngx_string("Status"),
[447]     ngx_string("X-Accel-Expires"),
[448]     ngx_string("X-Accel-Redirect"),
[449]     ngx_string("X-Accel-Limit-Rate"),
[450]     ngx_string("X-Accel-Buffering"),
[451]     ngx_string("X-Accel-Charset"),
[452]     ngx_null_string
[453] };
[454] 
[455] 
[456] #if (NGX_HTTP_CACHE)
[457] 
[458] static ngx_keyval_t  ngx_http_scgi_cache_headers[] = {
[459]     { ngx_string("HTTP_IF_MODIFIED_SINCE"),
[460]       ngx_string("$upstream_cache_last_modified") },
[461]     { ngx_string("HTTP_IF_UNMODIFIED_SINCE"), ngx_string("") },
[462]     { ngx_string("HTTP_IF_NONE_MATCH"), ngx_string("$upstream_cache_etag") },
[463]     { ngx_string("HTTP_IF_MATCH"), ngx_string("") },
[464]     { ngx_string("HTTP_RANGE"), ngx_string("") },
[465]     { ngx_string("HTTP_IF_RANGE"), ngx_string("") },
[466]     { ngx_null_string, ngx_null_string }
[467] };
[468] 
[469] #endif
[470] 
[471] 
[472] static ngx_path_init_t ngx_http_scgi_temp_path = {
[473]     ngx_string(NGX_HTTP_SCGI_TEMP_PATH), { 1, 2, 0 }
[474] };
[475] 
[476] 
[477] static ngx_int_t
[478] ngx_http_scgi_handler(ngx_http_request_t *r)
[479] {
[480]     ngx_int_t                   rc;
[481]     ngx_http_status_t          *status;
[482]     ngx_http_upstream_t        *u;
[483]     ngx_http_scgi_loc_conf_t   *scf;
[484] #if (NGX_HTTP_CACHE)
[485]     ngx_http_scgi_main_conf_t  *smcf;
[486] #endif
[487] 
[488]     if (ngx_http_upstream_create(r) != NGX_OK) {
[489]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[490]     }
[491] 
[492]     status = ngx_pcalloc(r->pool, sizeof(ngx_http_status_t));
[493]     if (status == NULL) {
[494]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[495]     }
[496] 
[497]     ngx_http_set_ctx(r, status, ngx_http_scgi_module);
[498] 
[499]     scf = ngx_http_get_module_loc_conf(r, ngx_http_scgi_module);
[500] 
[501]     if (scf->scgi_lengths) {
[502]         if (ngx_http_scgi_eval(r, scf) != NGX_OK) {
[503]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[504]         }
[505]     }
[506] 
[507]     u = r->upstream;
[508] 
[509]     ngx_str_set(&u->schema, "scgi://");
[510]     u->output.tag = (ngx_buf_tag_t) &ngx_http_scgi_module;
[511] 
[512]     u->conf = &scf->upstream;
[513] 
[514] #if (NGX_HTTP_CACHE)
[515]     smcf = ngx_http_get_module_main_conf(r, ngx_http_scgi_module);
[516] 
[517]     u->caches = &smcf->caches;
[518]     u->create_key = ngx_http_scgi_create_key;
[519] #endif
[520] 
[521]     u->create_request = ngx_http_scgi_create_request;
[522]     u->reinit_request = ngx_http_scgi_reinit_request;
[523]     u->process_header = ngx_http_scgi_process_status_line;
[524]     u->abort_request = ngx_http_scgi_abort_request;
[525]     u->finalize_request = ngx_http_scgi_finalize_request;
[526]     r->state = 0;
[527] 
[528]     u->buffering = scf->upstream.buffering;
[529] 
[530]     u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
[531]     if (u->pipe == NULL) {
[532]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[533]     }
[534] 
[535]     u->pipe->input_filter = ngx_event_pipe_copy_input_filter;
[536]     u->pipe->input_ctx = r;
[537] 
[538]     u->input_filter_init = ngx_http_scgi_input_filter_init;
[539]     u->input_filter = ngx_http_upstream_non_buffered_filter;
[540]     u->input_filter_ctx = r;
[541] 
[542]     if (!scf->upstream.request_buffering
[543]         && scf->upstream.pass_request_body
[544]         && !r->headers_in.chunked)
[545]     {
[546]         r->request_body_no_buffering = 1;
[547]     }
[548] 
[549]     rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
[550] 
[551]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[552]         return rc;
[553]     }
[554] 
[555]     return NGX_DONE;
[556] }
[557] 
[558] 
[559] static ngx_int_t
[560] ngx_http_scgi_eval(ngx_http_request_t *r, ngx_http_scgi_loc_conf_t * scf)
[561] {
[562]     ngx_url_t             url;
[563]     ngx_http_upstream_t  *u;
[564] 
[565]     ngx_memzero(&url, sizeof(ngx_url_t));
[566] 
[567]     if (ngx_http_script_run(r, &url.url, scf->scgi_lengths->elts, 0,
[568]                             scf->scgi_values->elts)
[569]         == NULL)
[570]     {
[571]         return NGX_ERROR;
[572]     }
[573] 
[574]     url.no_resolve = 1;
[575] 
[576]     if (ngx_parse_url(r->pool, &url) != NGX_OK) {
[577]         if (url.err) {
[578]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[579]                           "%s in upstream \"%V\"", url.err, &url.url);
[580]         }
[581] 
[582]         return NGX_ERROR;
[583]     }
[584] 
[585]     u = r->upstream;
[586] 
[587]     u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
[588]     if (u->resolved == NULL) {
[589]         return NGX_ERROR;
[590]     }
[591] 
[592]     if (url.addrs) {
[593]         u->resolved->sockaddr = url.addrs[0].sockaddr;
[594]         u->resolved->socklen = url.addrs[0].socklen;
[595]         u->resolved->name = url.addrs[0].name;
[596]         u->resolved->naddrs = 1;
[597]     }
[598] 
[599]     u->resolved->host = url.host;
[600]     u->resolved->port = url.port;
[601]     u->resolved->no_port = url.no_port;
[602] 
[603]     return NGX_OK;
[604] }
[605] 
[606] 
[607] #if (NGX_HTTP_CACHE)
[608] 
[609] static ngx_int_t
[610] ngx_http_scgi_create_key(ngx_http_request_t *r)
[611] {
[612]     ngx_str_t                 *key;
[613]     ngx_http_scgi_loc_conf_t  *scf;
[614] 
[615]     key = ngx_array_push(&r->cache->keys);
[616]     if (key == NULL) {
[617]         return NGX_ERROR;
[618]     }
[619] 
[620]     scf = ngx_http_get_module_loc_conf(r, ngx_http_scgi_module);
[621] 
[622]     if (ngx_http_complex_value(r, &scf->cache_key, key) != NGX_OK) {
[623]         return NGX_ERROR;
[624]     }
[625] 
[626]     return NGX_OK;
[627] }
[628] 
[629] #endif
[630] 
[631] 
[632] static ngx_int_t
[633] ngx_http_scgi_create_request(ngx_http_request_t *r)
[634] {
[635]     off_t                         content_length_n;
[636]     u_char                        ch, sep, *key, *val, *lowcase_key;
[637]     size_t                        len, key_len, val_len, allocated;
[638]     ngx_buf_t                    *b;
[639]     ngx_str_t                     content_length;
[640]     ngx_uint_t                    i, n, hash, skip_empty, header_params;
[641]     ngx_chain_t                  *cl, *body;
[642]     ngx_list_part_t              *part;
[643]     ngx_table_elt_t              *header, *hn, **ignored;
[644]     ngx_http_scgi_params_t       *params;
[645]     ngx_http_script_code_pt       code;
[646]     ngx_http_script_engine_t      e, le;
[647]     ngx_http_scgi_loc_conf_t     *scf;
[648]     ngx_http_script_len_code_pt   lcode;
[649]     u_char                        buffer[NGX_OFF_T_LEN];
[650] 
[651]     content_length_n = 0;
[652]     body = r->upstream->request_bufs;
[653] 
[654]     while (body) {
[655]         content_length_n += ngx_buf_size(body->buf);
[656]         body = body->next;
[657]     }
[658] 
[659]     content_length.data = buffer;
[660]     content_length.len = ngx_sprintf(buffer, "%O", content_length_n) - buffer;
[661] 
[662]     len = sizeof("CONTENT_LENGTH") + content_length.len + 1;
[663] 
[664]     header_params = 0;
[665]     ignored = NULL;
[666] 
[667]     scf = ngx_http_get_module_loc_conf(r, ngx_http_scgi_module);
[668] 
[669] #if (NGX_HTTP_CACHE)
[670]     params = r->upstream->cacheable ? &scf->params_cache : &scf->params;
[671] #else
[672]     params = &scf->params;
[673] #endif
[674] 
[675]     if (params->lengths) {
[676]         ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[677] 
[678]         ngx_http_script_flush_no_cacheable_variables(r, params->flushes);
[679]         le.flushed = 1;
[680] 
[681]         le.ip = params->lengths->elts;
[682]         le.request = r;
[683] 
[684]         while (*(uintptr_t *) le.ip) {
[685] 
[686]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[687]             key_len = lcode(&le);
[688] 
[689]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[690]             skip_empty = lcode(&le);
[691] 
[692]             for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[693]                 lcode = *(ngx_http_script_len_code_pt *) le.ip;
[694]             }
[695]             le.ip += sizeof(uintptr_t);
[696] 
[697]             if (skip_empty && val_len == 0) {
[698]                 continue;
[699]             }
[700] 
[701]             len += key_len + val_len + 1;
[702]         }
[703]     }
[704] 
[705]     if (scf->upstream.pass_request_headers) {
[706] 
[707]         allocated = 0;
[708]         lowcase_key = NULL;
[709] 
[710]         if (ngx_http_link_multi_headers(r) != NGX_OK) {
[711]             return NGX_ERROR;
[712]         }
[713] 
[714]         if (params->number || r->headers_in.multi) {
[715]             n = 0;
[716]             part = &r->headers_in.headers.part;
[717] 
[718]             while (part) {
[719]                 n += part->nelts;
[720]                 part = part->next;
[721]             }
[722] 
[723]             ignored = ngx_palloc(r->pool, n * sizeof(void *));
[724]             if (ignored == NULL) {
[725]                 return NGX_ERROR;
[726]             }
[727]         }
[728] 
[729]         part = &r->headers_in.headers.part;
[730]         header = part->elts;
[731] 
[732]         for (i = 0; /* void */; i++) {
[733] 
[734]             if (i >= part->nelts) {
[735]                 if (part->next == NULL) {
[736]                     break;
[737]                 }
[738] 
[739]                 part = part->next;
[740]                 header = part->elts;
[741]                 i = 0;
[742]             }
[743] 
[744]             for (n = 0; n < header_params; n++) {
[745]                 if (&header[i] == ignored[n]) {
[746]                     goto next_length;
[747]                 }
[748]             }
[749] 
[750]             if (params->number) {
[751]                 if (allocated < header[i].key.len) {
[752]                     allocated = header[i].key.len + 16;
[753]                     lowcase_key = ngx_pnalloc(r->pool, allocated);
[754]                     if (lowcase_key == NULL) {
[755]                         return NGX_ERROR;
[756]                     }
[757]                 }
[758] 
[759]                 hash = 0;
[760] 
[761]                 for (n = 0; n < header[i].key.len; n++) {
[762]                     ch = header[i].key.data[n];
[763] 
[764]                     if (ch >= 'A' && ch <= 'Z') {
[765]                         ch |= 0x20;
[766] 
[767]                     } else if (ch == '-') {
[768]                         ch = '_';
[769]                     }
[770] 
[771]                     hash = ngx_hash(hash, ch);
[772]                     lowcase_key[n] = ch;
[773]                 }
[774] 
[775]                 if (ngx_hash_find(&params->hash, hash, lowcase_key, n)) {
[776]                     ignored[header_params++] = &header[i];
[777]                     continue;
[778]                 }
[779]             }
[780] 
[781]             len += sizeof("HTTP_") - 1 + header[i].key.len + 1
[782]                 + header[i].value.len + 1;
[783] 
[784]             for (hn = header[i].next; hn; hn = hn->next) {
[785]                 len += hn->value.len + 2;
[786]                 ignored[header_params++] = hn;
[787]             }
[788] 
[789]         next_length:
[790] 
[791]             continue;
[792]         }
[793]     }
[794] 
[795]     /* netstring: "length:" + packet + "," */
[796] 
[797]     b = ngx_create_temp_buf(r->pool, NGX_SIZE_T_LEN + 1 + len + 1);
[798]     if (b == NULL) {
[799]         return NGX_ERROR;
[800]     }
[801] 
[802]     cl = ngx_alloc_chain_link(r->pool);
[803]     if (cl == NULL) {
[804]         return NGX_ERROR;
[805]     }
[806] 
[807]     cl->buf = b;
[808] 
[809]     b->last = ngx_sprintf(b->last, "%ui:CONTENT_LENGTH%Z%V%Z",
[810]                           len, &content_length);
[811] 
[812]     if (params->lengths) {
[813]         ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[814] 
[815]         e.ip = params->values->elts;
[816]         e.pos = b->last;
[817]         e.request = r;
[818]         e.flushed = 1;
[819] 
[820]         le.ip = params->lengths->elts;
[821] 
[822]         while (*(uintptr_t *) le.ip) {
[823] 
[824]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[825]             lcode(&le); /* key length */
[826] 
[827]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[828]             skip_empty = lcode(&le);
[829] 
[830]             for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
[831]                 lcode = *(ngx_http_script_len_code_pt *) le.ip;
[832]             }
[833]             le.ip += sizeof(uintptr_t);
[834] 
[835]             if (skip_empty && val_len == 0) {
[836]                 e.skip = 1;
[837] 
[838]                 while (*(uintptr_t *) e.ip) {
[839]                     code = *(ngx_http_script_code_pt *) e.ip;
[840]                     code((ngx_http_script_engine_t *) &e);
[841]                 }
[842]                 e.ip += sizeof(uintptr_t);
[843] 
[844]                 e.skip = 0;
[845] 
[846]                 continue;
[847]             }
[848] 
[849] #if (NGX_DEBUG)
[850]             key = e.pos;
[851] #endif
[852]             code = *(ngx_http_script_code_pt *) e.ip;
[853]             code((ngx_http_script_engine_t *) &e);
[854] 
[855] #if (NGX_DEBUG)
[856]             val = e.pos;
[857] #endif
[858]             while (*(uintptr_t *) e.ip) {
[859]                 code = *(ngx_http_script_code_pt *) e.ip;
[860]                 code((ngx_http_script_engine_t *) &e);
[861]             }
[862]             *e.pos++ = '\0';
[863]             e.ip += sizeof(uintptr_t);
[864] 
[865]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[866]                            "scgi param: \"%s: %s\"", key, val);
[867]         }
[868] 
[869]         b->last = e.pos;
[870]     }
[871] 
[872]     if (scf->upstream.pass_request_headers) {
[873] 
[874]         part = &r->headers_in.headers.part;
[875]         header = part->elts;
[876] 
[877]         for (i = 0; /* void */; i++) {
[878] 
[879]             if (i >= part->nelts) {
[880]                 if (part->next == NULL) {
[881]                     break;
[882]                 }
[883] 
[884]                 part = part->next;
[885]                 header = part->elts;
[886]                 i = 0;
[887]             }
[888] 
[889]             for (n = 0; n < header_params; n++) {
[890]                 if (&header[i] == ignored[n]) {
[891]                     goto next_value;
[892]                 }
[893]             }
[894] 
[895]             key = b->last;
[896]             b->last = ngx_cpymem(key, "HTTP_", sizeof("HTTP_") - 1);
[897] 
[898]             for (n = 0; n < header[i].key.len; n++) {
[899]                 ch = header[i].key.data[n];
[900] 
[901]                 if (ch >= 'a' && ch <= 'z') {
[902]                     ch &= ~0x20;
[903] 
[904]                 } else if (ch == '-') {
[905]                     ch = '_';
[906]                 }
[907] 
[908]                 *b->last++ = ch;
[909]             }
[910] 
[911]             *b->last++ = (u_char) 0;
[912] 
[913]             val = b->last;
[914]             b->last = ngx_copy(val, header[i].value.data, header[i].value.len);
[915] 
[916]             if (header[i].next) {
[917] 
[918]                 if (header[i].key.len == sizeof("Cookie") - 1
[919]                     && ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie",
[920]                                        sizeof("Cookie") - 1)
[921]                        == 0)
[922]                 {
[923]                     sep = ';';
[924] 
[925]                 } else {
[926]                     sep = ',';
[927]                 }
[928] 
[929]                 for (hn = header[i].next; hn; hn = hn->next) {
[930]                     *b->last++ = sep;
[931]                     *b->last++ = ' ';
[932]                     b->last = ngx_copy(b->last, hn->value.data, hn->value.len);
[933]                 }
[934]             }
[935] 
[936]             *b->last++ = (u_char) 0;
[937] 
[938]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[939]                            "scgi param: \"%s: %s\"", key, val);
[940] 
[941]         next_value:
[942] 
[943]             continue;
[944]         }
[945]     }
[946] 
[947]     *b->last++ = (u_char) ',';
[948] 
[949]     if (r->request_body_no_buffering) {
[950]         r->upstream->request_bufs = cl;
[951] 
[952]     } else if (scf->upstream.pass_request_body) {
[953]         body = r->upstream->request_bufs;
[954]         r->upstream->request_bufs = cl;
[955] 
[956]         while (body) {
[957]             b = ngx_alloc_buf(r->pool);
[958]             if (b == NULL) {
[959]                 return NGX_ERROR;
[960]             }
[961] 
[962]             ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
[963] 
[964]             cl->next = ngx_alloc_chain_link(r->pool);
[965]             if (cl->next == NULL) {
[966]                 return NGX_ERROR;
[967]             }
[968] 
[969]             cl = cl->next;
[970]             cl->buf = b;
[971] 
[972]             body = body->next;
[973]         }
[974] 
[975]     } else {
[976]         r->upstream->request_bufs = cl;
[977]     }
[978] 
[979]     cl->next = NULL;
[980] 
[981]     return NGX_OK;
[982] }
[983] 
[984] 
[985] static ngx_int_t
[986] ngx_http_scgi_reinit_request(ngx_http_request_t *r)
[987] {
[988]     ngx_http_status_t  *status;
[989] 
[990]     status = ngx_http_get_module_ctx(r, ngx_http_scgi_module);
[991] 
[992]     if (status == NULL) {
[993]         return NGX_OK;
[994]     }
[995] 
[996]     status->code = 0;
[997]     status->count = 0;
[998]     status->start = NULL;
[999]     status->end = NULL;
[1000] 
[1001]     r->upstream->process_header = ngx_http_scgi_process_status_line;
[1002]     r->state = 0;
[1003] 
[1004]     return NGX_OK;
[1005] }
[1006] 
[1007] 
[1008] static ngx_int_t
[1009] ngx_http_scgi_process_status_line(ngx_http_request_t *r)
[1010] {
[1011]     size_t                len;
[1012]     ngx_int_t             rc;
[1013]     ngx_http_status_t    *status;
[1014]     ngx_http_upstream_t  *u;
[1015] 
[1016]     status = ngx_http_get_module_ctx(r, ngx_http_scgi_module);
[1017] 
[1018]     if (status == NULL) {
[1019]         return NGX_ERROR;
[1020]     }
[1021] 
[1022]     u = r->upstream;
[1023] 
[1024]     rc = ngx_http_parse_status_line(r, &u->buffer, status);
[1025] 
[1026]     if (rc == NGX_AGAIN) {
[1027]         return rc;
[1028]     }
[1029] 
[1030]     if (rc == NGX_ERROR) {
[1031]         u->process_header = ngx_http_scgi_process_header;
[1032]         return ngx_http_scgi_process_header(r);
[1033]     }
[1034] 
[1035]     if (u->state && u->state->status == 0) {
[1036]         u->state->status = status->code;
[1037]     }
[1038] 
[1039]     u->headers_in.status_n = status->code;
[1040] 
[1041]     len = status->end - status->start;
[1042]     u->headers_in.status_line.len = len;
[1043] 
[1044]     u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
[1045]     if (u->headers_in.status_line.data == NULL) {
[1046]         return NGX_ERROR;
[1047]     }
[1048] 
[1049]     ngx_memcpy(u->headers_in.status_line.data, status->start, len);
[1050] 
[1051]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1052]                    "http scgi status %ui \"%V\"",
[1053]                    u->headers_in.status_n, &u->headers_in.status_line);
[1054] 
[1055]     u->process_header = ngx_http_scgi_process_header;
[1056] 
[1057]     return ngx_http_scgi_process_header(r);
[1058] }
[1059] 
[1060] 
[1061] static ngx_int_t
[1062] ngx_http_scgi_process_header(ngx_http_request_t *r)
[1063] {
[1064]     ngx_str_t                      *status_line;
[1065]     ngx_int_t                       rc, status;
[1066]     ngx_table_elt_t                *h;
[1067]     ngx_http_upstream_t            *u;
[1068]     ngx_http_upstream_header_t     *hh;
[1069]     ngx_http_upstream_main_conf_t  *umcf;
[1070] 
[1071]     umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
[1072] 
[1073]     for ( ;; ) {
[1074] 
[1075]         rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
[1076] 
[1077]         if (rc == NGX_OK) {
[1078] 
[1079]             /* a header line has been parsed successfully */
[1080] 
[1081]             h = ngx_list_push(&r->upstream->headers_in.headers);
[1082]             if (h == NULL) {
[1083]                 return NGX_ERROR;
[1084]             }
[1085] 
[1086]             h->hash = r->header_hash;
[1087] 
[1088]             h->key.len = r->header_name_end - r->header_name_start;
[1089]             h->value.len = r->header_end - r->header_start;
[1090] 
[1091]             h->key.data = ngx_pnalloc(r->pool,
[1092]                                       h->key.len + 1 + h->value.len + 1
[1093]                                       + h->key.len);
[1094]             if (h->key.data == NULL) {
[1095]                 h->hash = 0;
[1096]                 return NGX_ERROR;
[1097]             }
[1098] 
[1099]             h->value.data = h->key.data + h->key.len + 1;
[1100]             h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
[1101] 
[1102]             ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
[1103]             h->key.data[h->key.len] = '\0';
[1104]             ngx_memcpy(h->value.data, r->header_start, h->value.len);
[1105]             h->value.data[h->value.len] = '\0';
[1106] 
[1107]             if (h->key.len == r->lowcase_index) {
[1108]                 ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
[1109] 
[1110]             } else {
[1111]                 ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
[1112]             }
[1113] 
[1114]             hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
[1115]                                h->lowcase_key, h->key.len);
[1116] 
[1117]             if (hh) {
[1118]                 rc = hh->handler(r, h, hh->offset);
[1119] 
[1120]                 if (rc != NGX_OK) {
[1121]                     return rc;
[1122]                 }
[1123]             }
[1124] 
[1125]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1126]                            "http scgi header: \"%V: %V\"", &h->key, &h->value);
[1127] 
[1128]             continue;
[1129]         }
[1130] 
[1131]         if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
[1132] 
[1133]             /* a whole header has been parsed successfully */
[1134] 
[1135]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1136]                            "http scgi header done");
[1137] 
[1138]             u = r->upstream;
[1139] 
[1140]             if (u->headers_in.status_n) {
[1141]                 goto done;
[1142]             }
[1143] 
[1144]             if (u->headers_in.status) {
[1145]                 status_line = &u->headers_in.status->value;
[1146] 
[1147]                 status = ngx_atoi(status_line->data, 3);
[1148]                 if (status == NGX_ERROR) {
[1149]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1150]                                   "upstream sent invalid status \"%V\"",
[1151]                                   status_line);
[1152]                     return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1153]                 }
[1154] 
[1155]                 u->headers_in.status_n = status;
[1156]                 u->headers_in.status_line = *status_line;
[1157] 
[1158]             } else if (u->headers_in.location) {
[1159]                 u->headers_in.status_n = 302;
[1160]                 ngx_str_set(&u->headers_in.status_line,
[1161]                             "302 Moved Temporarily");
[1162] 
[1163]             } else {
[1164]                 u->headers_in.status_n = 200;
[1165]                 ngx_str_set(&u->headers_in.status_line, "200 OK");
[1166]             }
[1167] 
[1168]             if (u->state && u->state->status == 0) {
[1169]                 u->state->status = u->headers_in.status_n;
[1170]             }
[1171] 
[1172]         done:
[1173] 
[1174]             if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS
[1175]                 && r->headers_in.upgrade)
[1176]             {
[1177]                 u->upgrade = 1;
[1178]             }
[1179] 
[1180]             return NGX_OK;
[1181]         }
[1182] 
[1183]         if (rc == NGX_AGAIN) {
[1184]             return NGX_AGAIN;
[1185]         }
[1186] 
[1187]         /* rc == NGX_HTTP_PARSE_INVALID_HEADER */
[1188] 
[1189]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1190]                       "upstream sent invalid header: \"%*s\\x%02xd...\"",
[1191]                       r->header_end - r->header_name_start,
[1192]                       r->header_name_start, *r->header_end);
[1193] 
[1194]         return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[1195]     }
[1196] }
[1197] 
[1198] 
[1199] static ngx_int_t
[1200] ngx_http_scgi_input_filter_init(void *data)
[1201] {
[1202]     ngx_http_request_t   *r = data;
[1203]     ngx_http_upstream_t  *u;
[1204] 
[1205]     u = r->upstream;
[1206] 
[1207]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1208]                    "http scgi filter init s:%ui l:%O",
[1209]                    u->headers_in.status_n, u->headers_in.content_length_n);
[1210] 
[1211]     if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
[1212]         || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED)
[1213]     {
[1214]         u->pipe->length = 0;
[1215]         u->length = 0;
[1216] 
[1217]     } else if (r->method == NGX_HTTP_HEAD) {
[1218]         u->pipe->length = -1;
[1219]         u->length = -1;
[1220] 
[1221]     } else {
[1222]         u->pipe->length = u->headers_in.content_length_n;
[1223]         u->length = u->headers_in.content_length_n;
[1224]     }
[1225] 
[1226]     return NGX_OK;
[1227] }
[1228] 
[1229] 
[1230] static void
[1231] ngx_http_scgi_abort_request(ngx_http_request_t *r)
[1232] {
[1233]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1234]                    "abort http scgi request");
[1235] 
[1236]     return;
[1237] }
[1238] 
[1239] 
[1240] static void
[1241] ngx_http_scgi_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[1242] {
[1243]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1244]                    "finalize http scgi request");
[1245] 
[1246]     return;
[1247] }
[1248] 
[1249] 
[1250] static void *
[1251] ngx_http_scgi_create_main_conf(ngx_conf_t *cf)
[1252] {
[1253]     ngx_http_scgi_main_conf_t  *conf;
[1254] 
[1255]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_scgi_main_conf_t));
[1256]     if (conf == NULL) {
[1257]         return NULL;
[1258]     }
[1259] 
[1260] #if (NGX_HTTP_CACHE)
[1261]     if (ngx_array_init(&conf->caches, cf->pool, 4,
[1262]                        sizeof(ngx_http_file_cache_t *))
[1263]         != NGX_OK)
[1264]     {
[1265]         return NULL;
[1266]     }
[1267] #endif
[1268] 
[1269]     return conf;
[1270] }
[1271] 
[1272] 
[1273] static void *
[1274] ngx_http_scgi_create_loc_conf(ngx_conf_t *cf)
[1275] {
[1276]     ngx_http_scgi_loc_conf_t  *conf;
[1277] 
[1278]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_scgi_loc_conf_t));
[1279]     if (conf == NULL) {
[1280]         return NULL;
[1281]     }
[1282] 
[1283]     conf->upstream.store = NGX_CONF_UNSET;
[1284]     conf->upstream.store_access = NGX_CONF_UNSET_UINT;
[1285]     conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
[1286]     conf->upstream.buffering = NGX_CONF_UNSET;
[1287]     conf->upstream.request_buffering = NGX_CONF_UNSET;
[1288]     conf->upstream.ignore_client_abort = NGX_CONF_UNSET;
[1289]     conf->upstream.force_ranges = NGX_CONF_UNSET;
[1290] 
[1291]     conf->upstream.local = NGX_CONF_UNSET_PTR;
[1292]     conf->upstream.socket_keepalive = NGX_CONF_UNSET;
[1293] 
[1294]     conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
[1295]     conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
[1296]     conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
[1297]     conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[1298] 
[1299]     conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
[1300]     conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
[1301]     conf->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
[1302] 
[1303]     conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
[1304]     conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
[1305]     conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
[1306] 
[1307]     conf->upstream.pass_request_headers = NGX_CONF_UNSET;
[1308]     conf->upstream.pass_request_body = NGX_CONF_UNSET;
[1309] 
[1310] #if (NGX_HTTP_CACHE)
[1311]     conf->upstream.cache = NGX_CONF_UNSET;
[1312]     conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
[1313]     conf->upstream.cache_max_range_offset = NGX_CONF_UNSET;
[1314]     conf->upstream.cache_bypass = NGX_CONF_UNSET_PTR;
[1315]     conf->upstream.no_cache = NGX_CONF_UNSET_PTR;
[1316]     conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
[1317]     conf->upstream.cache_lock = NGX_CONF_UNSET;
[1318]     conf->upstream.cache_lock_timeout = NGX_CONF_UNSET_MSEC;
[1319]     conf->upstream.cache_lock_age = NGX_CONF_UNSET_MSEC;
[1320]     conf->upstream.cache_revalidate = NGX_CONF_UNSET;
[1321]     conf->upstream.cache_background_update = NGX_CONF_UNSET;
[1322] #endif
[1323] 
[1324]     conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
[1325]     conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
[1326] 
[1327]     conf->upstream.intercept_errors = NGX_CONF_UNSET;
[1328] 
[1329]     /* "scgi_cyclic_temp_file" is disabled */
[1330]     conf->upstream.cyclic_temp_file = 0;
[1331] 
[1332]     conf->upstream.change_buffering = 1;
[1333] 
[1334]     ngx_str_set(&conf->upstream.module, "scgi");
[1335] 
[1336]     return conf;
[1337] }
[1338] 
[1339] 
[1340] static char *
[1341] ngx_http_scgi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[1342] {
[1343]     ngx_http_scgi_loc_conf_t *prev = parent;
[1344]     ngx_http_scgi_loc_conf_t *conf = child;
[1345] 
[1346]     size_t                        size;
[1347]     ngx_int_t                     rc;
[1348]     ngx_hash_init_t               hash;
[1349]     ngx_http_core_loc_conf_t     *clcf;
[1350] 
[1351] #if (NGX_HTTP_CACHE)
[1352] 
[1353]     if (conf->upstream.store > 0) {
[1354]         conf->upstream.cache = 0;
[1355]     }
[1356] 
[1357]     if (conf->upstream.cache > 0) {
[1358]         conf->upstream.store = 0;
[1359]     }
[1360] 
[1361] #endif
[1362] 
[1363]     if (conf->upstream.store == NGX_CONF_UNSET) {
[1364]         ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
[1365] 
[1366]         conf->upstream.store_lengths = prev->upstream.store_lengths;
[1367]         conf->upstream.store_values = prev->upstream.store_values;
[1368]     }
[1369] 
[1370]     ngx_conf_merge_uint_value(conf->upstream.store_access,
[1371]                               prev->upstream.store_access, 0600);
[1372] 
[1373]     ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
[1374]                               prev->upstream.next_upstream_tries, 0);
[1375] 
[1376]     ngx_conf_merge_value(conf->upstream.buffering,
[1377]                               prev->upstream.buffering, 1);
[1378] 
[1379]     ngx_conf_merge_value(conf->upstream.request_buffering,
[1380]                               prev->upstream.request_buffering, 1);
[1381] 
[1382]     ngx_conf_merge_value(conf->upstream.ignore_client_abort,
[1383]                               prev->upstream.ignore_client_abort, 0);
[1384] 
[1385]     ngx_conf_merge_value(conf->upstream.force_ranges,
[1386]                               prev->upstream.force_ranges, 0);
[1387] 
[1388]     ngx_conf_merge_ptr_value(conf->upstream.local,
[1389]                               prev->upstream.local, NULL);
[1390] 
[1391]     ngx_conf_merge_value(conf->upstream.socket_keepalive,
[1392]                               prev->upstream.socket_keepalive, 0);
[1393] 
[1394]     ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
[1395]                               prev->upstream.connect_timeout, 60000);
[1396] 
[1397]     ngx_conf_merge_msec_value(conf->upstream.send_timeout,
[1398]                               prev->upstream.send_timeout, 60000);
[1399] 
[1400]     ngx_conf_merge_msec_value(conf->upstream.read_timeout,
[1401]                               prev->upstream.read_timeout, 60000);
[1402] 
[1403]     ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
[1404]                               prev->upstream.next_upstream_timeout, 0);
[1405] 
[1406]     ngx_conf_merge_size_value(conf->upstream.send_lowat,
[1407]                               prev->upstream.send_lowat, 0);
[1408] 
[1409]     ngx_conf_merge_size_value(conf->upstream.buffer_size,
[1410]                               prev->upstream.buffer_size,
[1411]                               (size_t) ngx_pagesize);
[1412] 
[1413]     ngx_conf_merge_size_value(conf->upstream.limit_rate,
[1414]                               prev->upstream.limit_rate, 0);
[1415] 
[1416] 
[1417]     ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
[1418]                               8, ngx_pagesize);
[1419] 
[1420]     if (conf->upstream.bufs.num < 2) {
[1421]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1422]                            "there must be at least 2 \"scgi_buffers\"");
[1423]         return NGX_CONF_ERROR;
[1424]     }
[1425] 
[1426] 
[1427]     size = conf->upstream.buffer_size;
[1428]     if (size < conf->upstream.bufs.size) {
[1429]         size = conf->upstream.bufs.size;
[1430]     }
[1431] 
[1432] 
[1433]     ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
[1434]                               prev->upstream.busy_buffers_size_conf,
[1435]                               NGX_CONF_UNSET_SIZE);
[1436] 
[1437]     if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
[1438]         conf->upstream.busy_buffers_size = 2 * size;
[1439]     } else {
[1440]         conf->upstream.busy_buffers_size =
[1441]             conf->upstream.busy_buffers_size_conf;
[1442]     }
[1443] 
[1444]     if (conf->upstream.busy_buffers_size < size) {
[1445]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1446]             "\"scgi_busy_buffers_size\" must be equal to or greater "
[1447]             "than the maximum of the value of \"scgi_buffer_size\" and "
[1448]             "one of the \"scgi_buffers\"");
[1449] 
[1450]         return NGX_CONF_ERROR;
[1451]     }
[1452] 
[1453]     if (conf->upstream.busy_buffers_size
[1454]         > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
[1455]     {
[1456]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1457]             "\"scgi_busy_buffers_size\" must be less than "
[1458]             "the size of all \"scgi_buffers\" minus one buffer");
[1459] 
[1460]         return NGX_CONF_ERROR;
[1461]     }
[1462] 
[1463] 
[1464]     ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
[1465]                               prev->upstream.temp_file_write_size_conf,
[1466]                               NGX_CONF_UNSET_SIZE);
[1467] 
[1468]     if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
[1469]         conf->upstream.temp_file_write_size = 2 * size;
[1470]     } else {
[1471]         conf->upstream.temp_file_write_size =
[1472]             conf->upstream.temp_file_write_size_conf;
[1473]     }
[1474] 
[1475]     if (conf->upstream.temp_file_write_size < size) {
[1476]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1477]             "\"scgi_temp_file_write_size\" must be equal to or greater than "
[1478]             "the maximum of the value of \"scgi_buffer_size\" and "
[1479]             "one of the \"scgi_buffers\"");
[1480] 
[1481]         return NGX_CONF_ERROR;
[1482]     }
[1483] 
[1484] 
[1485]     ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
[1486]                               prev->upstream.max_temp_file_size_conf,
[1487]                               NGX_CONF_UNSET_SIZE);
[1488] 
[1489]     if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
[1490]         conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
[1491]     } else {
[1492]         conf->upstream.max_temp_file_size =
[1493]             conf->upstream.max_temp_file_size_conf;
[1494]     }
[1495] 
[1496]     if (conf->upstream.max_temp_file_size != 0
[1497]         && conf->upstream.max_temp_file_size < size)
[1498]     {
[1499]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1500]             "\"scgi_max_temp_file_size\" must be equal to zero to disable "
[1501]             "temporary files usage or must be equal to or greater than "
[1502]             "the maximum of the value of \"scgi_buffer_size\" and "
[1503]             "one of the \"scgi_buffers\"");
[1504] 
[1505]         return NGX_CONF_ERROR;
[1506]     }
[1507] 
[1508] 
[1509]     ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
[1510]                                  prev->upstream.ignore_headers,
[1511]                                  NGX_CONF_BITMASK_SET);
[1512] 
[1513] 
[1514]     ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
[1515]                                  prev->upstream.next_upstream,
[1516]                                  (NGX_CONF_BITMASK_SET
[1517]                                   |NGX_HTTP_UPSTREAM_FT_ERROR
[1518]                                   |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
[1519] 
[1520]     if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
[1521]         conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
[1522]                                        |NGX_HTTP_UPSTREAM_FT_OFF;
[1523]     }
[1524] 
[1525]     if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
[1526]                                   prev->upstream.temp_path,
[1527]                                   &ngx_http_scgi_temp_path)
[1528]         != NGX_OK)
[1529]     {
[1530]         return NGX_CONF_ERROR;
[1531]     }
[1532] 
[1533] #if (NGX_HTTP_CACHE)
[1534] 
[1535]     if (conf->upstream.cache == NGX_CONF_UNSET) {
[1536]         ngx_conf_merge_value(conf->upstream.cache,
[1537]                               prev->upstream.cache, 0);
[1538] 
[1539]         conf->upstream.cache_zone = prev->upstream.cache_zone;
[1540]         conf->upstream.cache_value = prev->upstream.cache_value;
[1541]     }
[1542] 
[1543]     if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
[1544]         ngx_shm_zone_t  *shm_zone;
[1545] 
[1546]         shm_zone = conf->upstream.cache_zone;
[1547] 
[1548]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1549]                            "\"scgi_cache\" zone \"%V\" is unknown",
[1550]                            &shm_zone->shm.name);
[1551] 
[1552]         return NGX_CONF_ERROR;
[1553]     }
[1554] 
[1555]     ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
[1556]                               prev->upstream.cache_min_uses, 1);
[1557] 
[1558]     ngx_conf_merge_off_value(conf->upstream.cache_max_range_offset,
[1559]                               prev->upstream.cache_max_range_offset,
[1560]                               NGX_MAX_OFF_T_VALUE);
[1561] 
[1562]     ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
[1563]                               prev->upstream.cache_use_stale,
[1564]                               (NGX_CONF_BITMASK_SET
[1565]                                |NGX_HTTP_UPSTREAM_FT_OFF));
[1566] 
[1567]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
[1568]         conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
[1569]                                          |NGX_HTTP_UPSTREAM_FT_OFF;
[1570]     }
[1571] 
[1572]     if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_ERROR) {
[1573]         conf->upstream.cache_use_stale |= NGX_HTTP_UPSTREAM_FT_NOLIVE;
[1574]     }
[1575] 
[1576]     if (conf->upstream.cache_methods == 0) {
[1577]         conf->upstream.cache_methods = prev->upstream.cache_methods;
[1578]     }
[1579] 
[1580]     conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;
[1581] 
[1582]     ngx_conf_merge_ptr_value(conf->upstream.cache_bypass,
[1583]                              prev->upstream.cache_bypass, NULL);
[1584] 
[1585]     ngx_conf_merge_ptr_value(conf->upstream.no_cache,
[1586]                              prev->upstream.no_cache, NULL);
[1587] 
[1588]     ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
[1589]                              prev->upstream.cache_valid, NULL);
[1590] 
[1591]     if (conf->cache_key.value.data == NULL) {
[1592]         conf->cache_key = prev->cache_key;
[1593]     }
[1594] 
[1595]     if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
[1596]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1597]                            "no \"scgi_cache_key\" for \"scgi_cache\"");
[1598]     }
[1599] 
[1600]     ngx_conf_merge_value(conf->upstream.cache_lock,
[1601]                               prev->upstream.cache_lock, 0);
[1602] 
[1603]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
[1604]                               prev->upstream.cache_lock_timeout, 5000);
[1605] 
[1606]     ngx_conf_merge_msec_value(conf->upstream.cache_lock_age,
[1607]                               prev->upstream.cache_lock_age, 5000);
[1608] 
[1609]     ngx_conf_merge_value(conf->upstream.cache_revalidate,
[1610]                               prev->upstream.cache_revalidate, 0);
[1611] 
[1612]     ngx_conf_merge_value(conf->upstream.cache_background_update,
[1613]                               prev->upstream.cache_background_update, 0);
[1614] 
[1615] #endif
[1616] 
[1617]     ngx_conf_merge_value(conf->upstream.pass_request_headers,
[1618]                          prev->upstream.pass_request_headers, 1);
[1619]     ngx_conf_merge_value(conf->upstream.pass_request_body,
[1620]                          prev->upstream.pass_request_body, 1);
[1621] 
[1622]     ngx_conf_merge_value(conf->upstream.intercept_errors,
[1623]                          prev->upstream.intercept_errors, 0);
[1624] 
[1625]     hash.max_size = 512;
[1626]     hash.bucket_size = ngx_align(64, ngx_cacheline_size);
[1627]     hash.name = "scgi_hide_headers_hash";
[1628] 
[1629]     if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
[1630]             &prev->upstream, ngx_http_scgi_hide_headers, &hash)
[1631]         != NGX_OK)
[1632]     {
[1633]         return NGX_CONF_ERROR;
[1634]     }
[1635] 
[1636]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[1637] 
[1638]     if (clcf->noname
[1639]         && conf->upstream.upstream == NULL && conf->scgi_lengths == NULL)
[1640]     {
[1641]         conf->upstream.upstream = prev->upstream.upstream;
[1642]         conf->scgi_lengths = prev->scgi_lengths;
[1643]         conf->scgi_values = prev->scgi_values;
[1644]     }
[1645] 
[1646]     if (clcf->lmt_excpt && clcf->handler == NULL
[1647]         && (conf->upstream.upstream || conf->scgi_lengths))
[1648]     {
[1649]         clcf->handler = ngx_http_scgi_handler;
[1650]     }
[1651] 
[1652]     if (conf->params_source == NULL) {
[1653]         conf->params = prev->params;
[1654] #if (NGX_HTTP_CACHE)
[1655]         conf->params_cache = prev->params_cache;
[1656] #endif
[1657]         conf->params_source = prev->params_source;
[1658]     }
[1659] 
[1660]     rc = ngx_http_scgi_init_params(cf, conf, &conf->params, NULL);
[1661]     if (rc != NGX_OK) {
[1662]         return NGX_CONF_ERROR;
[1663]     }
[1664] 
[1665] #if (NGX_HTTP_CACHE)
[1666] 
[1667]     if (conf->upstream.cache) {
[1668]         rc = ngx_http_scgi_init_params(cf, conf, &conf->params_cache,
[1669]                                        ngx_http_scgi_cache_headers);
[1670]         if (rc != NGX_OK) {
[1671]             return NGX_CONF_ERROR;
[1672]         }
[1673]     }
[1674] 
[1675] #endif
[1676] 
[1677]     /*
[1678]      * special handling to preserve conf->params in the "http" section
[1679]      * to inherit it to all servers
[1680]      */
[1681] 
[1682]     if (prev->params.hash.buckets == NULL
[1683]         && conf->params_source == prev->params_source)
[1684]     {
[1685]         prev->params = conf->params;
[1686] #if (NGX_HTTP_CACHE)
[1687]         prev->params_cache = conf->params_cache;
[1688] #endif
[1689]     }
[1690] 
[1691]     return NGX_CONF_OK;
[1692] }
[1693] 
[1694] 
[1695] static ngx_int_t
[1696] ngx_http_scgi_init_params(ngx_conf_t *cf, ngx_http_scgi_loc_conf_t *conf,
[1697]     ngx_http_scgi_params_t *params, ngx_keyval_t *default_params)
[1698] {
[1699]     u_char                       *p;
[1700]     size_t                        size;
[1701]     uintptr_t                    *code;
[1702]     ngx_uint_t                    i, nsrc;
[1703]     ngx_array_t                   headers_names, params_merged;
[1704]     ngx_keyval_t                 *h;
[1705]     ngx_hash_key_t               *hk;
[1706]     ngx_hash_init_t               hash;
[1707]     ngx_http_upstream_param_t    *src, *s;
[1708]     ngx_http_script_compile_t     sc;
[1709]     ngx_http_script_copy_code_t  *copy;
[1710] 
[1711]     if (params->hash.buckets) {
[1712]         return NGX_OK;
[1713]     }
[1714] 
[1715]     if (conf->params_source == NULL && default_params == NULL) {
[1716]         params->hash.buckets = (void *) 1;
[1717]         return NGX_OK;
[1718]     }
[1719] 
[1720]     params->lengths = ngx_array_create(cf->pool, 64, 1);
[1721]     if (params->lengths == NULL) {
[1722]         return NGX_ERROR;
[1723]     }
[1724] 
[1725]     params->values = ngx_array_create(cf->pool, 512, 1);
[1726]     if (params->values == NULL) {
[1727]         return NGX_ERROR;
[1728]     }
[1729] 
[1730]     if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
[1731]         != NGX_OK)
[1732]     {
[1733]         return NGX_ERROR;
[1734]     }
[1735] 
[1736]     if (conf->params_source) {
[1737]         src = conf->params_source->elts;
[1738]         nsrc = conf->params_source->nelts;
[1739] 
[1740]     } else {
[1741]         src = NULL;
[1742]         nsrc = 0;
[1743]     }
[1744] 
[1745]     if (default_params) {
[1746]         if (ngx_array_init(&params_merged, cf->temp_pool, 4,
[1747]                            sizeof(ngx_http_upstream_param_t))
[1748]             != NGX_OK)
[1749]         {
[1750]             return NGX_ERROR;
[1751]         }
[1752] 
[1753]         for (i = 0; i < nsrc; i++) {
[1754] 
[1755]             s = ngx_array_push(&params_merged);
[1756]             if (s == NULL) {
[1757]                 return NGX_ERROR;
[1758]             }
[1759] 
[1760]             *s = src[i];
[1761]         }
[1762] 
[1763]         h = default_params;
[1764] 
[1765]         while (h->key.len) {
[1766] 
[1767]             src = params_merged.elts;
[1768]             nsrc = params_merged.nelts;
[1769] 
[1770]             for (i = 0; i < nsrc; i++) {
[1771]                 if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
[1772]                     goto next;
[1773]                 }
[1774]             }
[1775] 
[1776]             s = ngx_array_push(&params_merged);
[1777]             if (s == NULL) {
[1778]                 return NGX_ERROR;
[1779]             }
[1780] 
[1781]             s->key = h->key;
[1782]             s->value = h->value;
[1783]             s->skip_empty = 1;
[1784] 
[1785]         next:
[1786] 
[1787]             h++;
[1788]         }
[1789] 
[1790]         src = params_merged.elts;
[1791]         nsrc = params_merged.nelts;
[1792]     }
[1793] 
[1794]     for (i = 0; i < nsrc; i++) {
[1795] 
[1796]         if (src[i].key.len > sizeof("HTTP_") - 1
[1797]             && ngx_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
[1798]         {
[1799]             hk = ngx_array_push(&headers_names);
[1800]             if (hk == NULL) {
[1801]                 return NGX_ERROR;
[1802]             }
[1803] 
[1804]             hk->key.len = src[i].key.len - 5;
[1805]             hk->key.data = src[i].key.data + 5;
[1806]             hk->key_hash = ngx_hash_key_lc(hk->key.data, hk->key.len);
[1807]             hk->value = (void *) 1;
[1808] 
[1809]             if (src[i].value.len == 0) {
[1810]                 continue;
[1811]             }
[1812]         }
[1813] 
[1814]         copy = ngx_array_push_n(params->lengths,
[1815]                                 sizeof(ngx_http_script_copy_code_t));
[1816]         if (copy == NULL) {
[1817]             return NGX_ERROR;
[1818]         }
[1819] 
[1820]         copy->code = (ngx_http_script_code_pt) (void *)
[1821]                                                  ngx_http_script_copy_len_code;
[1822]         copy->len = src[i].key.len + 1;
[1823] 
[1824]         copy = ngx_array_push_n(params->lengths,
[1825]                                 sizeof(ngx_http_script_copy_code_t));
[1826]         if (copy == NULL) {
[1827]             return NGX_ERROR;
[1828]         }
[1829] 
[1830]         copy->code = (ngx_http_script_code_pt) (void *)
[1831]                                                  ngx_http_script_copy_len_code;
[1832]         copy->len = src[i].skip_empty;
[1833] 
[1834] 
[1835]         size = (sizeof(ngx_http_script_copy_code_t)
[1836]                 + src[i].key.len + 1 + sizeof(uintptr_t) - 1)
[1837]                & ~(sizeof(uintptr_t) - 1);
[1838] 
[1839]         copy = ngx_array_push_n(params->values, size);
[1840]         if (copy == NULL) {
[1841]             return NGX_ERROR;
[1842]         }
[1843] 
[1844]         copy->code = ngx_http_script_copy_code;
[1845]         copy->len = src[i].key.len + 1;
[1846] 
[1847]         p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
[1848]         (void) ngx_cpystrn(p, src[i].key.data, src[i].key.len + 1);
[1849] 
[1850] 
[1851]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[1852] 
[1853]         sc.cf = cf;
[1854]         sc.source = &src[i].value;
[1855]         sc.flushes = &params->flushes;
[1856]         sc.lengths = &params->lengths;
[1857]         sc.values = &params->values;
[1858] 
[1859]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[1860]             return NGX_ERROR;
[1861]         }
[1862] 
[1863]         code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
[1864]         if (code == NULL) {
[1865]             return NGX_ERROR;
[1866]         }
[1867] 
[1868]         *code = (uintptr_t) NULL;
[1869] 
[1870] 
[1871]         code = ngx_array_push_n(params->values, sizeof(uintptr_t));
[1872]         if (code == NULL) {
[1873]             return NGX_ERROR;
[1874]         }
[1875] 
[1876]         *code = (uintptr_t) NULL;
[1877]     }
[1878] 
[1879]     code = ngx_array_push_n(params->lengths, sizeof(uintptr_t));
[1880]     if (code == NULL) {
[1881]         return NGX_ERROR;
[1882]     }
[1883] 
[1884]     *code = (uintptr_t) NULL;
[1885] 
[1886]     params->number = headers_names.nelts;
[1887] 
[1888]     hash.hash = &params->hash;
[1889]     hash.key = ngx_hash_key_lc;
[1890]     hash.max_size = 512;
[1891]     hash.bucket_size = 64;
[1892]     hash.name = "scgi_params_hash";
[1893]     hash.pool = cf->pool;
[1894]     hash.temp_pool = NULL;
[1895] 
[1896]     return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
[1897] }
[1898] 
[1899] 
[1900] static char *
[1901] ngx_http_scgi_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1902] {
[1903]     ngx_http_scgi_loc_conf_t *scf = conf;
[1904] 
[1905]     ngx_url_t                   u;
[1906]     ngx_str_t                  *value, *url;
[1907]     ngx_uint_t                  n;
[1908]     ngx_http_core_loc_conf_t   *clcf;
[1909]     ngx_http_script_compile_t   sc;
[1910] 
[1911]     if (scf->upstream.upstream || scf->scgi_lengths) {
[1912]         return "is duplicate";
[1913]     }
[1914] 
[1915]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[1916]     clcf->handler = ngx_http_scgi_handler;
[1917] 
[1918]     value = cf->args->elts;
[1919] 
[1920]     url = &value[1];
[1921] 
[1922]     n = ngx_http_script_variables_count(url);
[1923] 
[1924]     if (n) {
[1925] 
[1926]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[1927] 
[1928]         sc.cf = cf;
[1929]         sc.source = url;
[1930]         sc.lengths = &scf->scgi_lengths;
[1931]         sc.values = &scf->scgi_values;
[1932]         sc.variables = n;
[1933]         sc.complete_lengths = 1;
[1934]         sc.complete_values = 1;
[1935] 
[1936]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[1937]             return NGX_CONF_ERROR;
[1938]         }
[1939] 
[1940]         return NGX_CONF_OK;
[1941]     }
[1942] 
[1943]     ngx_memzero(&u, sizeof(ngx_url_t));
[1944] 
[1945]     u.url = value[1];
[1946]     u.no_resolve = 1;
[1947] 
[1948]     scf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
[1949]     if (scf->upstream.upstream == NULL) {
[1950]         return NGX_CONF_ERROR;
[1951]     }
[1952] 
[1953]     if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
[1954]         clcf->auto_redirect = 1;
[1955]     }
[1956] 
[1957]     return NGX_CONF_OK;
[1958] }
[1959] 
[1960] 
[1961] static char *
[1962] ngx_http_scgi_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1963] {
[1964]     ngx_http_scgi_loc_conf_t *scf = conf;
[1965] 
[1966]     ngx_str_t                  *value;
[1967]     ngx_http_script_compile_t   sc;
[1968] 
[1969]     if (scf->upstream.store != NGX_CONF_UNSET) {
[1970]         return "is duplicate";
[1971]     }
[1972] 
[1973]     value = cf->args->elts;
[1974] 
[1975]     if (ngx_strcmp(value[1].data, "off") == 0) {
[1976]         scf->upstream.store = 0;
[1977]         return NGX_CONF_OK;
[1978]     }
[1979] 
[1980] #if (NGX_HTTP_CACHE)
[1981]     if (scf->upstream.cache > 0) {
[1982]         return "is incompatible with \"scgi_cache\"";
[1983]     }
[1984] #endif
[1985] 
[1986]     scf->upstream.store = 1;
[1987] 
[1988]     if (ngx_strcmp(value[1].data, "on") == 0) {
[1989]         return NGX_CONF_OK;
[1990]     }
[1991] 
[1992]     /* include the terminating '\0' into script */
[1993]     value[1].len++;
[1994] 
[1995]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[1996] 
[1997]     sc.cf = cf;
[1998]     sc.source = &value[1];
[1999]     sc.lengths = &scf->upstream.store_lengths;
[2000]     sc.values = &scf->upstream.store_values;
[2001]     sc.variables = ngx_http_script_variables_count(&value[1]);
[2002]     sc.complete_lengths = 1;
[2003]     sc.complete_values = 1;
[2004] 
[2005]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[2006]         return NGX_CONF_ERROR;
[2007]     }
[2008] 
[2009]     return NGX_CONF_OK;
[2010] }
[2011] 
[2012] 
[2013] #if (NGX_HTTP_CACHE)
[2014] 
[2015] static char *
[2016] ngx_http_scgi_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2017] {
[2018]     ngx_http_scgi_loc_conf_t *scf = conf;
[2019] 
[2020]     ngx_str_t                         *value;
[2021]     ngx_http_complex_value_t           cv;
[2022]     ngx_http_compile_complex_value_t   ccv;
[2023] 
[2024]     value = cf->args->elts;
[2025] 
[2026]     if (scf->upstream.cache != NGX_CONF_UNSET) {
[2027]         return "is duplicate";
[2028]     }
[2029] 
[2030]     if (ngx_strcmp(value[1].data, "off") == 0) {
[2031]         scf->upstream.cache = 0;
[2032]         return NGX_CONF_OK;
[2033]     }
[2034] 
[2035]     if (scf->upstream.store > 0) {
[2036]         return "is incompatible with \"scgi_store\"";
[2037]     }
[2038] 
[2039]     scf->upstream.cache = 1;
[2040] 
[2041]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[2042] 
[2043]     ccv.cf = cf;
[2044]     ccv.value = &value[1];
[2045]     ccv.complex_value = &cv;
[2046] 
[2047]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[2048]         return NGX_CONF_ERROR;
[2049]     }
[2050] 
[2051]     if (cv.lengths != NULL) {
[2052] 
[2053]         scf->upstream.cache_value = ngx_palloc(cf->pool,
[2054]                                              sizeof(ngx_http_complex_value_t));
[2055]         if (scf->upstream.cache_value == NULL) {
[2056]             return NGX_CONF_ERROR;
[2057]         }
[2058] 
[2059]         *scf->upstream.cache_value = cv;
[2060] 
[2061]         return NGX_CONF_OK;
[2062]     }
[2063] 
[2064]     scf->upstream.cache_zone = ngx_shared_memory_add(cf, &value[1], 0,
[2065]                                                      &ngx_http_scgi_module);
[2066]     if (scf->upstream.cache_zone == NULL) {
[2067]         return NGX_CONF_ERROR;
[2068]     }
[2069] 
[2070]     return NGX_CONF_OK;
[2071] }
[2072] 
[2073] 
[2074] static char *
[2075] ngx_http_scgi_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2076] {
[2077]     ngx_http_scgi_loc_conf_t *scf = conf;
[2078] 
[2079]     ngx_str_t                         *value;
[2080]     ngx_http_compile_complex_value_t   ccv;
[2081] 
[2082]     value = cf->args->elts;
[2083] 
[2084]     if (scf->cache_key.value.data) {
[2085]         return "is duplicate";
[2086]     }
[2087] 
[2088]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[2089] 
[2090]     ccv.cf = cf;
[2091]     ccv.value = &value[1];
[2092]     ccv.complex_value = &scf->cache_key;
[2093] 
[2094]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[2095]         return NGX_CONF_ERROR;
[2096]     }
[2097] 
[2098]     return NGX_CONF_OK;
[2099] }
[2100] 
[2101] #endif
