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
[14]     u_char    *name;
[15]     uint32_t   method;
[16] } ngx_http_method_name_t;
[17] 
[18] 
[19] #define NGX_HTTP_REQUEST_BODY_FILE_OFF    0
[20] #define NGX_HTTP_REQUEST_BODY_FILE_ON     1
[21] #define NGX_HTTP_REQUEST_BODY_FILE_CLEAN  2
[22] 
[23] 
[24] static ngx_int_t ngx_http_core_auth_delay(ngx_http_request_t *r);
[25] static void ngx_http_core_auth_delay_handler(ngx_http_request_t *r);
[26] 
[27] static ngx_int_t ngx_http_core_find_location(ngx_http_request_t *r);
[28] static ngx_int_t ngx_http_core_find_static_location(ngx_http_request_t *r,
[29]     ngx_http_location_tree_node_t *node);
[30] 
[31] static ngx_int_t ngx_http_core_preconfiguration(ngx_conf_t *cf);
[32] static ngx_int_t ngx_http_core_postconfiguration(ngx_conf_t *cf);
[33] static void *ngx_http_core_create_main_conf(ngx_conf_t *cf);
[34] static char *ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf);
[35] static void *ngx_http_core_create_srv_conf(ngx_conf_t *cf);
[36] static char *ngx_http_core_merge_srv_conf(ngx_conf_t *cf,
[37]     void *parent, void *child);
[38] static void *ngx_http_core_create_loc_conf(ngx_conf_t *cf);
[39] static char *ngx_http_core_merge_loc_conf(ngx_conf_t *cf,
[40]     void *parent, void *child);
[41] 
[42] static char *ngx_http_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
[43]     void *dummy);
[44] static char *ngx_http_core_location(ngx_conf_t *cf, ngx_command_t *cmd,
[45]     void *dummy);
[46] static ngx_int_t ngx_http_core_regex_location(ngx_conf_t *cf,
[47]     ngx_http_core_loc_conf_t *clcf, ngx_str_t *regex, ngx_uint_t caseless);
[48] 
[49] static char *ngx_http_core_types(ngx_conf_t *cf, ngx_command_t *cmd,
[50]     void *conf);
[51] static char *ngx_http_core_type(ngx_conf_t *cf, ngx_command_t *dummy,
[52]     void *conf);
[53] 
[54] static char *ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
[55]     void *conf);
[56] static char *ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd,
[57]     void *conf);
[58] static char *ngx_http_core_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[59] static char *ngx_http_core_limit_except(ngx_conf_t *cf, ngx_command_t *cmd,
[60]     void *conf);
[61] static char *ngx_http_core_set_aio(ngx_conf_t *cf, ngx_command_t *cmd,
[62]     void *conf);
[63] static char *ngx_http_core_directio(ngx_conf_t *cf, ngx_command_t *cmd,
[64]     void *conf);
[65] static char *ngx_http_core_error_page(ngx_conf_t *cf, ngx_command_t *cmd,
[66]     void *conf);
[67] static char *ngx_http_core_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[68]     void *conf);
[69] static char *ngx_http_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
[70]     void *conf);
[71] static char *ngx_http_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
[72]     void *conf);
[73] static char *ngx_http_core_internal(ngx_conf_t *cf, ngx_command_t *cmd,
[74]     void *conf);
[75] static char *ngx_http_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
[76]     void *conf);
[77] #if (NGX_HTTP_GZIP)
[78] static ngx_int_t ngx_http_gzip_accept_encoding(ngx_str_t *ae);
[79] static ngx_uint_t ngx_http_gzip_quantity(u_char *p, u_char *last);
[80] static char *ngx_http_gzip_disable(ngx_conf_t *cf, ngx_command_t *cmd,
[81]     void *conf);
[82] #endif
[83] static ngx_int_t ngx_http_get_forwarded_addr_internal(ngx_http_request_t *r,
[84]     ngx_addr_t *addr, u_char *xff, size_t xfflen, ngx_array_t *proxies,
[85]     int recursive);
[86] #if (NGX_HAVE_OPENAT)
[87] static char *ngx_http_disable_symlinks(ngx_conf_t *cf, ngx_command_t *cmd,
[88]     void *conf);
[89] #endif
[90] 
[91] static char *ngx_http_core_lowat_check(ngx_conf_t *cf, void *post, void *data);
[92] static char *ngx_http_core_pool_size(ngx_conf_t *cf, void *post, void *data);
[93] 
[94] static ngx_conf_post_t  ngx_http_core_lowat_post =
[95]     { ngx_http_core_lowat_check };
[96] 
[97] static ngx_conf_post_handler_pt  ngx_http_core_pool_size_p =
[98]     ngx_http_core_pool_size;
[99] 
[100] 
[101] static ngx_conf_enum_t  ngx_http_core_request_body_in_file[] = {
[102]     { ngx_string("off"), NGX_HTTP_REQUEST_BODY_FILE_OFF },
[103]     { ngx_string("on"), NGX_HTTP_REQUEST_BODY_FILE_ON },
[104]     { ngx_string("clean"), NGX_HTTP_REQUEST_BODY_FILE_CLEAN },
[105]     { ngx_null_string, 0 }
[106] };
[107] 
[108] 
[109] static ngx_conf_enum_t  ngx_http_core_satisfy[] = {
[110]     { ngx_string("all"), NGX_HTTP_SATISFY_ALL },
[111]     { ngx_string("any"), NGX_HTTP_SATISFY_ANY },
[112]     { ngx_null_string, 0 }
[113] };
[114] 
[115] 
[116] static ngx_conf_enum_t  ngx_http_core_lingering_close[] = {
[117]     { ngx_string("off"), NGX_HTTP_LINGERING_OFF },
[118]     { ngx_string("on"), NGX_HTTP_LINGERING_ON },
[119]     { ngx_string("always"), NGX_HTTP_LINGERING_ALWAYS },
[120]     { ngx_null_string, 0 }
[121] };
[122] 
[123] 
[124] static ngx_conf_enum_t  ngx_http_core_server_tokens[] = {
[125]     { ngx_string("off"), NGX_HTTP_SERVER_TOKENS_OFF },
[126]     { ngx_string("on"), NGX_HTTP_SERVER_TOKENS_ON },
[127]     { ngx_string("build"), NGX_HTTP_SERVER_TOKENS_BUILD },
[128]     { ngx_null_string, 0 }
[129] };
[130] 
[131] 
[132] static ngx_conf_enum_t  ngx_http_core_if_modified_since[] = {
[133]     { ngx_string("off"), NGX_HTTP_IMS_OFF },
[134]     { ngx_string("exact"), NGX_HTTP_IMS_EXACT },
[135]     { ngx_string("before"), NGX_HTTP_IMS_BEFORE },
[136]     { ngx_null_string, 0 }
[137] };
[138] 
[139] 
[140] static ngx_conf_bitmask_t  ngx_http_core_keepalive_disable[] = {
[141]     { ngx_string("none"), NGX_HTTP_KEEPALIVE_DISABLE_NONE },
[142]     { ngx_string("msie6"), NGX_HTTP_KEEPALIVE_DISABLE_MSIE6 },
[143]     { ngx_string("safari"), NGX_HTTP_KEEPALIVE_DISABLE_SAFARI },
[144]     { ngx_null_string, 0 }
[145] };
[146] 
[147] 
[148] static ngx_path_init_t  ngx_http_client_temp_path = {
[149]     ngx_string(NGX_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
[150] };
[151] 
[152] 
[153] #if (NGX_HTTP_GZIP)
[154] 
[155] static ngx_conf_enum_t  ngx_http_gzip_http_version[] = {
[156]     { ngx_string("1.0"), NGX_HTTP_VERSION_10 },
[157]     { ngx_string("1.1"), NGX_HTTP_VERSION_11 },
[158]     { ngx_null_string, 0 }
[159] };
[160] 
[161] 
[162] static ngx_conf_bitmask_t  ngx_http_gzip_proxied_mask[] = {
[163]     { ngx_string("off"), NGX_HTTP_GZIP_PROXIED_OFF },
[164]     { ngx_string("expired"), NGX_HTTP_GZIP_PROXIED_EXPIRED },
[165]     { ngx_string("no-cache"), NGX_HTTP_GZIP_PROXIED_NO_CACHE },
[166]     { ngx_string("no-store"), NGX_HTTP_GZIP_PROXIED_NO_STORE },
[167]     { ngx_string("private"), NGX_HTTP_GZIP_PROXIED_PRIVATE },
[168]     { ngx_string("no_last_modified"), NGX_HTTP_GZIP_PROXIED_NO_LM },
[169]     { ngx_string("no_etag"), NGX_HTTP_GZIP_PROXIED_NO_ETAG },
[170]     { ngx_string("auth"), NGX_HTTP_GZIP_PROXIED_AUTH },
[171]     { ngx_string("any"), NGX_HTTP_GZIP_PROXIED_ANY },
[172]     { ngx_null_string, 0 }
[173] };
[174] 
[175] 
[176] static ngx_str_t  ngx_http_gzip_no_cache = ngx_string("no-cache");
[177] static ngx_str_t  ngx_http_gzip_no_store = ngx_string("no-store");
[178] static ngx_str_t  ngx_http_gzip_private = ngx_string("private");
[179] 
[180] #endif
[181] 
[182] 
[183] static ngx_command_t  ngx_http_core_commands[] = {
[184] 
[185]     { ngx_string("variables_hash_max_size"),
[186]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[187]       ngx_conf_set_num_slot,
[188]       NGX_HTTP_MAIN_CONF_OFFSET,
[189]       offsetof(ngx_http_core_main_conf_t, variables_hash_max_size),
[190]       NULL },
[191] 
[192]     { ngx_string("variables_hash_bucket_size"),
[193]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[194]       ngx_conf_set_num_slot,
[195]       NGX_HTTP_MAIN_CONF_OFFSET,
[196]       offsetof(ngx_http_core_main_conf_t, variables_hash_bucket_size),
[197]       NULL },
[198] 
[199]     { ngx_string("server_names_hash_max_size"),
[200]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[201]       ngx_conf_set_num_slot,
[202]       NGX_HTTP_MAIN_CONF_OFFSET,
[203]       offsetof(ngx_http_core_main_conf_t, server_names_hash_max_size),
[204]       NULL },
[205] 
[206]     { ngx_string("server_names_hash_bucket_size"),
[207]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[208]       ngx_conf_set_num_slot,
[209]       NGX_HTTP_MAIN_CONF_OFFSET,
[210]       offsetof(ngx_http_core_main_conf_t, server_names_hash_bucket_size),
[211]       NULL },
[212] 
[213]     { ngx_string("server"),
[214]       NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[215]       ngx_http_core_server,
[216]       0,
[217]       0,
[218]       NULL },
[219] 
[220]     { ngx_string("connection_pool_size"),
[221]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[222]       ngx_conf_set_size_slot,
[223]       NGX_HTTP_SRV_CONF_OFFSET,
[224]       offsetof(ngx_http_core_srv_conf_t, connection_pool_size),
[225]       &ngx_http_core_pool_size_p },
[226] 
[227]     { ngx_string("request_pool_size"),
[228]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[229]       ngx_conf_set_size_slot,
[230]       NGX_HTTP_SRV_CONF_OFFSET,
[231]       offsetof(ngx_http_core_srv_conf_t, request_pool_size),
[232]       &ngx_http_core_pool_size_p },
[233] 
[234]     { ngx_string("client_header_timeout"),
[235]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[236]       ngx_conf_set_msec_slot,
[237]       NGX_HTTP_SRV_CONF_OFFSET,
[238]       offsetof(ngx_http_core_srv_conf_t, client_header_timeout),
[239]       NULL },
[240] 
[241]     { ngx_string("client_header_buffer_size"),
[242]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[243]       ngx_conf_set_size_slot,
[244]       NGX_HTTP_SRV_CONF_OFFSET,
[245]       offsetof(ngx_http_core_srv_conf_t, client_header_buffer_size),
[246]       NULL },
[247] 
[248]     { ngx_string("large_client_header_buffers"),
[249]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
[250]       ngx_conf_set_bufs_slot,
[251]       NGX_HTTP_SRV_CONF_OFFSET,
[252]       offsetof(ngx_http_core_srv_conf_t, large_client_header_buffers),
[253]       NULL },
[254] 
[255]     { ngx_string("ignore_invalid_headers"),
[256]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[257]       ngx_conf_set_flag_slot,
[258]       NGX_HTTP_SRV_CONF_OFFSET,
[259]       offsetof(ngx_http_core_srv_conf_t, ignore_invalid_headers),
[260]       NULL },
[261] 
[262]     { ngx_string("merge_slashes"),
[263]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[264]       ngx_conf_set_flag_slot,
[265]       NGX_HTTP_SRV_CONF_OFFSET,
[266]       offsetof(ngx_http_core_srv_conf_t, merge_slashes),
[267]       NULL },
[268] 
[269]     { ngx_string("underscores_in_headers"),
[270]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[271]       ngx_conf_set_flag_slot,
[272]       NGX_HTTP_SRV_CONF_OFFSET,
[273]       offsetof(ngx_http_core_srv_conf_t, underscores_in_headers),
[274]       NULL },
[275] 
[276]     { ngx_string("location"),
[277]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
[278]       ngx_http_core_location,
[279]       NGX_HTTP_SRV_CONF_OFFSET,
[280]       0,
[281]       NULL },
[282] 
[283]     { ngx_string("listen"),
[284]       NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
[285]       ngx_http_core_listen,
[286]       NGX_HTTP_SRV_CONF_OFFSET,
[287]       0,
[288]       NULL },
[289] 
[290]     { ngx_string("server_name"),
[291]       NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
[292]       ngx_http_core_server_name,
[293]       NGX_HTTP_SRV_CONF_OFFSET,
[294]       0,
[295]       NULL },
[296] 
[297]     { ngx_string("types_hash_max_size"),
[298]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[299]       ngx_conf_set_num_slot,
[300]       NGX_HTTP_LOC_CONF_OFFSET,
[301]       offsetof(ngx_http_core_loc_conf_t, types_hash_max_size),
[302]       NULL },
[303] 
[304]     { ngx_string("types_hash_bucket_size"),
[305]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[306]       ngx_conf_set_num_slot,
[307]       NGX_HTTP_LOC_CONF_OFFSET,
[308]       offsetof(ngx_http_core_loc_conf_t, types_hash_bucket_size),
[309]       NULL },
[310] 
[311]     { ngx_string("types"),
[312]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
[313]                                           |NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[314]       ngx_http_core_types,
[315]       NGX_HTTP_LOC_CONF_OFFSET,
[316]       0,
[317]       NULL },
[318] 
[319]     { ngx_string("default_type"),
[320]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[321]       ngx_conf_set_str_slot,
[322]       NGX_HTTP_LOC_CONF_OFFSET,
[323]       offsetof(ngx_http_core_loc_conf_t, default_type),
[324]       NULL },
[325] 
[326]     { ngx_string("root"),
[327]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[328]                         |NGX_CONF_TAKE1,
[329]       ngx_http_core_root,
[330]       NGX_HTTP_LOC_CONF_OFFSET,
[331]       0,
[332]       NULL },
[333] 
[334]     { ngx_string("alias"),
[335]       NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[336]       ngx_http_core_root,
[337]       NGX_HTTP_LOC_CONF_OFFSET,
[338]       0,
[339]       NULL },
[340] 
[341]     { ngx_string("limit_except"),
[342]       NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_1MORE,
[343]       ngx_http_core_limit_except,
[344]       NGX_HTTP_LOC_CONF_OFFSET,
[345]       0,
[346]       NULL },
[347] 
[348]     { ngx_string("client_max_body_size"),
[349]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[350]       ngx_conf_set_off_slot,
[351]       NGX_HTTP_LOC_CONF_OFFSET,
[352]       offsetof(ngx_http_core_loc_conf_t, client_max_body_size),
[353]       NULL },
[354] 
[355]     { ngx_string("client_body_buffer_size"),
[356]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[357]       ngx_conf_set_size_slot,
[358]       NGX_HTTP_LOC_CONF_OFFSET,
[359]       offsetof(ngx_http_core_loc_conf_t, client_body_buffer_size),
[360]       NULL },
[361] 
[362]     { ngx_string("client_body_timeout"),
[363]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[364]       ngx_conf_set_msec_slot,
[365]       NGX_HTTP_LOC_CONF_OFFSET,
[366]       offsetof(ngx_http_core_loc_conf_t, client_body_timeout),
[367]       NULL },
[368] 
[369]     { ngx_string("client_body_temp_path"),
[370]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[371]       ngx_conf_set_path_slot,
[372]       NGX_HTTP_LOC_CONF_OFFSET,
[373]       offsetof(ngx_http_core_loc_conf_t, client_body_temp_path),
[374]       NULL },
[375] 
[376]     { ngx_string("client_body_in_file_only"),
[377]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[378]       ngx_conf_set_enum_slot,
[379]       NGX_HTTP_LOC_CONF_OFFSET,
[380]       offsetof(ngx_http_core_loc_conf_t, client_body_in_file_only),
[381]       &ngx_http_core_request_body_in_file },
[382] 
[383]     { ngx_string("client_body_in_single_buffer"),
[384]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[385]       ngx_conf_set_flag_slot,
[386]       NGX_HTTP_LOC_CONF_OFFSET,
[387]       offsetof(ngx_http_core_loc_conf_t, client_body_in_single_buffer),
[388]       NULL },
[389] 
[390]     { ngx_string("sendfile"),
[391]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[392]                         |NGX_CONF_FLAG,
[393]       ngx_conf_set_flag_slot,
[394]       NGX_HTTP_LOC_CONF_OFFSET,
[395]       offsetof(ngx_http_core_loc_conf_t, sendfile),
[396]       NULL },
[397] 
[398]     { ngx_string("sendfile_max_chunk"),
[399]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[400]       ngx_conf_set_size_slot,
[401]       NGX_HTTP_LOC_CONF_OFFSET,
[402]       offsetof(ngx_http_core_loc_conf_t, sendfile_max_chunk),
[403]       NULL },
[404] 
[405]     { ngx_string("subrequest_output_buffer_size"),
[406]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[407]       ngx_conf_set_size_slot,
[408]       NGX_HTTP_LOC_CONF_OFFSET,
[409]       offsetof(ngx_http_core_loc_conf_t, subrequest_output_buffer_size),
[410]       NULL },
[411] 
[412]     { ngx_string("aio"),
[413]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[414]       ngx_http_core_set_aio,
[415]       NGX_HTTP_LOC_CONF_OFFSET,
[416]       0,
[417]       NULL },
[418] 
[419]     { ngx_string("aio_write"),
[420]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[421]       ngx_conf_set_flag_slot,
[422]       NGX_HTTP_LOC_CONF_OFFSET,
[423]       offsetof(ngx_http_core_loc_conf_t, aio_write),
[424]       NULL },
[425] 
[426]     { ngx_string("read_ahead"),
[427]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[428]       ngx_conf_set_size_slot,
[429]       NGX_HTTP_LOC_CONF_OFFSET,
[430]       offsetof(ngx_http_core_loc_conf_t, read_ahead),
[431]       NULL },
[432] 
[433]     { ngx_string("directio"),
[434]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[435]       ngx_http_core_directio,
[436]       NGX_HTTP_LOC_CONF_OFFSET,
[437]       0,
[438]       NULL },
[439] 
[440]     { ngx_string("directio_alignment"),
[441]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[442]       ngx_conf_set_off_slot,
[443]       NGX_HTTP_LOC_CONF_OFFSET,
[444]       offsetof(ngx_http_core_loc_conf_t, directio_alignment),
[445]       NULL },
[446] 
[447]     { ngx_string("tcp_nopush"),
[448]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[449]       ngx_conf_set_flag_slot,
[450]       NGX_HTTP_LOC_CONF_OFFSET,
[451]       offsetof(ngx_http_core_loc_conf_t, tcp_nopush),
[452]       NULL },
[453] 
[454]     { ngx_string("tcp_nodelay"),
[455]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[456]       ngx_conf_set_flag_slot,
[457]       NGX_HTTP_LOC_CONF_OFFSET,
[458]       offsetof(ngx_http_core_loc_conf_t, tcp_nodelay),
[459]       NULL },
[460] 
[461]     { ngx_string("send_timeout"),
[462]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[463]       ngx_conf_set_msec_slot,
[464]       NGX_HTTP_LOC_CONF_OFFSET,
[465]       offsetof(ngx_http_core_loc_conf_t, send_timeout),
[466]       NULL },
[467] 
[468]     { ngx_string("send_lowat"),
[469]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[470]       ngx_conf_set_size_slot,
[471]       NGX_HTTP_LOC_CONF_OFFSET,
[472]       offsetof(ngx_http_core_loc_conf_t, send_lowat),
[473]       &ngx_http_core_lowat_post },
[474] 
[475]     { ngx_string("postpone_output"),
[476]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[477]       ngx_conf_set_size_slot,
[478]       NGX_HTTP_LOC_CONF_OFFSET,
[479]       offsetof(ngx_http_core_loc_conf_t, postpone_output),
[480]       NULL },
[481] 
[482]     { ngx_string("limit_rate"),
[483]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[484]                         |NGX_CONF_TAKE1,
[485]       ngx_http_set_complex_value_size_slot,
[486]       NGX_HTTP_LOC_CONF_OFFSET,
[487]       offsetof(ngx_http_core_loc_conf_t, limit_rate),
[488]       NULL },
[489] 
[490]     { ngx_string("limit_rate_after"),
[491]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[492]                         |NGX_CONF_TAKE1,
[493]       ngx_http_set_complex_value_size_slot,
[494]       NGX_HTTP_LOC_CONF_OFFSET,
[495]       offsetof(ngx_http_core_loc_conf_t, limit_rate_after),
[496]       NULL },
[497] 
[498]     { ngx_string("keepalive_time"),
[499]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[500]       ngx_conf_set_msec_slot,
[501]       NGX_HTTP_LOC_CONF_OFFSET,
[502]       offsetof(ngx_http_core_loc_conf_t, keepalive_time),
[503]       NULL },
[504] 
[505]     { ngx_string("keepalive_timeout"),
[506]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[507]       ngx_http_core_keepalive,
[508]       NGX_HTTP_LOC_CONF_OFFSET,
[509]       0,
[510]       NULL },
[511] 
[512]     { ngx_string("keepalive_requests"),
[513]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[514]       ngx_conf_set_num_slot,
[515]       NGX_HTTP_LOC_CONF_OFFSET,
[516]       offsetof(ngx_http_core_loc_conf_t, keepalive_requests),
[517]       NULL },
[518] 
[519]     { ngx_string("keepalive_disable"),
[520]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[521]       ngx_conf_set_bitmask_slot,
[522]       NGX_HTTP_LOC_CONF_OFFSET,
[523]       offsetof(ngx_http_core_loc_conf_t, keepalive_disable),
[524]       &ngx_http_core_keepalive_disable },
[525] 
[526]     { ngx_string("satisfy"),
[527]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[528]       ngx_conf_set_enum_slot,
[529]       NGX_HTTP_LOC_CONF_OFFSET,
[530]       offsetof(ngx_http_core_loc_conf_t, satisfy),
[531]       &ngx_http_core_satisfy },
[532] 
[533]     { ngx_string("auth_delay"),
[534]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[535]       ngx_conf_set_msec_slot,
[536]       NGX_HTTP_LOC_CONF_OFFSET,
[537]       offsetof(ngx_http_core_loc_conf_t, auth_delay),
[538]       NULL },
[539] 
[540]     { ngx_string("internal"),
[541]       NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
[542]       ngx_http_core_internal,
[543]       NGX_HTTP_LOC_CONF_OFFSET,
[544]       0,
[545]       NULL },
[546] 
[547]     { ngx_string("lingering_close"),
[548]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[549]       ngx_conf_set_enum_slot,
[550]       NGX_HTTP_LOC_CONF_OFFSET,
[551]       offsetof(ngx_http_core_loc_conf_t, lingering_close),
[552]       &ngx_http_core_lingering_close },
[553] 
[554]     { ngx_string("lingering_time"),
[555]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[556]       ngx_conf_set_msec_slot,
[557]       NGX_HTTP_LOC_CONF_OFFSET,
[558]       offsetof(ngx_http_core_loc_conf_t, lingering_time),
[559]       NULL },
[560] 
[561]     { ngx_string("lingering_timeout"),
[562]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[563]       ngx_conf_set_msec_slot,
[564]       NGX_HTTP_LOC_CONF_OFFSET,
[565]       offsetof(ngx_http_core_loc_conf_t, lingering_timeout),
[566]       NULL },
[567] 
[568]     { ngx_string("reset_timedout_connection"),
[569]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[570]       ngx_conf_set_flag_slot,
[571]       NGX_HTTP_LOC_CONF_OFFSET,
[572]       offsetof(ngx_http_core_loc_conf_t, reset_timedout_connection),
[573]       NULL },
[574] 
[575]     { ngx_string("absolute_redirect"),
[576]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[577]       ngx_conf_set_flag_slot,
[578]       NGX_HTTP_LOC_CONF_OFFSET,
[579]       offsetof(ngx_http_core_loc_conf_t, absolute_redirect),
[580]       NULL },
[581] 
[582]     { ngx_string("server_name_in_redirect"),
[583]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[584]       ngx_conf_set_flag_slot,
[585]       NGX_HTTP_LOC_CONF_OFFSET,
[586]       offsetof(ngx_http_core_loc_conf_t, server_name_in_redirect),
[587]       NULL },
[588] 
[589]     { ngx_string("port_in_redirect"),
[590]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[591]       ngx_conf_set_flag_slot,
[592]       NGX_HTTP_LOC_CONF_OFFSET,
[593]       offsetof(ngx_http_core_loc_conf_t, port_in_redirect),
[594]       NULL },
[595] 
[596]     { ngx_string("msie_padding"),
[597]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[598]       ngx_conf_set_flag_slot,
[599]       NGX_HTTP_LOC_CONF_OFFSET,
[600]       offsetof(ngx_http_core_loc_conf_t, msie_padding),
[601]       NULL },
[602] 
[603]     { ngx_string("msie_refresh"),
[604]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[605]       ngx_conf_set_flag_slot,
[606]       NGX_HTTP_LOC_CONF_OFFSET,
[607]       offsetof(ngx_http_core_loc_conf_t, msie_refresh),
[608]       NULL },
[609] 
[610]     { ngx_string("log_not_found"),
[611]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[612]       ngx_conf_set_flag_slot,
[613]       NGX_HTTP_LOC_CONF_OFFSET,
[614]       offsetof(ngx_http_core_loc_conf_t, log_not_found),
[615]       NULL },
[616] 
[617]     { ngx_string("log_subrequest"),
[618]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[619]       ngx_conf_set_flag_slot,
[620]       NGX_HTTP_LOC_CONF_OFFSET,
[621]       offsetof(ngx_http_core_loc_conf_t, log_subrequest),
[622]       NULL },
[623] 
[624]     { ngx_string("recursive_error_pages"),
[625]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[626]       ngx_conf_set_flag_slot,
[627]       NGX_HTTP_LOC_CONF_OFFSET,
[628]       offsetof(ngx_http_core_loc_conf_t, recursive_error_pages),
[629]       NULL },
[630] 
[631]     { ngx_string("server_tokens"),
[632]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[633]       ngx_conf_set_enum_slot,
[634]       NGX_HTTP_LOC_CONF_OFFSET,
[635]       offsetof(ngx_http_core_loc_conf_t, server_tokens),
[636]       &ngx_http_core_server_tokens },
[637] 
[638]     { ngx_string("if_modified_since"),
[639]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[640]       ngx_conf_set_enum_slot,
[641]       NGX_HTTP_LOC_CONF_OFFSET,
[642]       offsetof(ngx_http_core_loc_conf_t, if_modified_since),
[643]       &ngx_http_core_if_modified_since },
[644] 
[645]     { ngx_string("max_ranges"),
[646]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[647]       ngx_conf_set_num_slot,
[648]       NGX_HTTP_LOC_CONF_OFFSET,
[649]       offsetof(ngx_http_core_loc_conf_t, max_ranges),
[650]       NULL },
[651] 
[652]     { ngx_string("chunked_transfer_encoding"),
[653]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[654]       ngx_conf_set_flag_slot,
[655]       NGX_HTTP_LOC_CONF_OFFSET,
[656]       offsetof(ngx_http_core_loc_conf_t, chunked_transfer_encoding),
[657]       NULL },
[658] 
[659]     { ngx_string("etag"),
[660]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[661]       ngx_conf_set_flag_slot,
[662]       NGX_HTTP_LOC_CONF_OFFSET,
[663]       offsetof(ngx_http_core_loc_conf_t, etag),
[664]       NULL },
[665] 
[666]     { ngx_string("error_page"),
[667]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[668]                         |NGX_CONF_2MORE,
[669]       ngx_http_core_error_page,
[670]       NGX_HTTP_LOC_CONF_OFFSET,
[671]       0,
[672]       NULL },
[673] 
[674]     { ngx_string("post_action"),
[675]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[676]                         |NGX_CONF_TAKE1,
[677]       ngx_conf_set_str_slot,
[678]       NGX_HTTP_LOC_CONF_OFFSET,
[679]       offsetof(ngx_http_core_loc_conf_t, post_action),
[680]       NULL },
[681] 
[682]     { ngx_string("error_log"),
[683]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[684]       ngx_http_core_error_log,
[685]       NGX_HTTP_LOC_CONF_OFFSET,
[686]       0,
[687]       NULL },
[688] 
[689]     { ngx_string("open_file_cache"),
[690]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[691]       ngx_http_core_open_file_cache,
[692]       NGX_HTTP_LOC_CONF_OFFSET,
[693]       offsetof(ngx_http_core_loc_conf_t, open_file_cache),
[694]       NULL },
[695] 
[696]     { ngx_string("open_file_cache_valid"),
[697]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[698]       ngx_conf_set_sec_slot,
[699]       NGX_HTTP_LOC_CONF_OFFSET,
[700]       offsetof(ngx_http_core_loc_conf_t, open_file_cache_valid),
[701]       NULL },
[702] 
[703]     { ngx_string("open_file_cache_min_uses"),
[704]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[705]       ngx_conf_set_num_slot,
[706]       NGX_HTTP_LOC_CONF_OFFSET,
[707]       offsetof(ngx_http_core_loc_conf_t, open_file_cache_min_uses),
[708]       NULL },
[709] 
[710]     { ngx_string("open_file_cache_errors"),
[711]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[712]       ngx_conf_set_flag_slot,
[713]       NGX_HTTP_LOC_CONF_OFFSET,
[714]       offsetof(ngx_http_core_loc_conf_t, open_file_cache_errors),
[715]       NULL },
[716] 
[717]     { ngx_string("open_file_cache_events"),
[718]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[719]       ngx_conf_set_flag_slot,
[720]       NGX_HTTP_LOC_CONF_OFFSET,
[721]       offsetof(ngx_http_core_loc_conf_t, open_file_cache_events),
[722]       NULL },
[723] 
[724]     { ngx_string("resolver"),
[725]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[726]       ngx_http_core_resolver,
[727]       NGX_HTTP_LOC_CONF_OFFSET,
[728]       0,
[729]       NULL },
[730] 
[731]     { ngx_string("resolver_timeout"),
[732]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[733]       ngx_conf_set_msec_slot,
[734]       NGX_HTTP_LOC_CONF_OFFSET,
[735]       offsetof(ngx_http_core_loc_conf_t, resolver_timeout),
[736]       NULL },
[737] 
[738] #if (NGX_HTTP_GZIP)
[739] 
[740]     { ngx_string("gzip_vary"),
[741]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[742]       ngx_conf_set_flag_slot,
[743]       NGX_HTTP_LOC_CONF_OFFSET,
[744]       offsetof(ngx_http_core_loc_conf_t, gzip_vary),
[745]       NULL },
[746] 
[747]     { ngx_string("gzip_http_version"),
[748]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[749]       ngx_conf_set_enum_slot,
[750]       NGX_HTTP_LOC_CONF_OFFSET,
[751]       offsetof(ngx_http_core_loc_conf_t, gzip_http_version),
[752]       &ngx_http_gzip_http_version },
[753] 
[754]     { ngx_string("gzip_proxied"),
[755]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[756]       ngx_conf_set_bitmask_slot,
[757]       NGX_HTTP_LOC_CONF_OFFSET,
[758]       offsetof(ngx_http_core_loc_conf_t, gzip_proxied),
[759]       &ngx_http_gzip_proxied_mask },
[760] 
[761]     { ngx_string("gzip_disable"),
[762]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[763]       ngx_http_gzip_disable,
[764]       NGX_HTTP_LOC_CONF_OFFSET,
[765]       0,
[766]       NULL },
[767] 
[768] #endif
[769] 
[770] #if (NGX_HAVE_OPENAT)
[771] 
[772]     { ngx_string("disable_symlinks"),
[773]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[774]       ngx_http_disable_symlinks,
[775]       NGX_HTTP_LOC_CONF_OFFSET,
[776]       0,
[777]       NULL },
[778] 
[779] #endif
[780] 
[781]       ngx_null_command
[782] };
[783] 
[784] 
[785] static ngx_http_module_t  ngx_http_core_module_ctx = {
[786]     ngx_http_core_preconfiguration,        /* preconfiguration */
[787]     ngx_http_core_postconfiguration,       /* postconfiguration */
[788] 
[789]     ngx_http_core_create_main_conf,        /* create main configuration */
[790]     ngx_http_core_init_main_conf,          /* init main configuration */
[791] 
[792]     ngx_http_core_create_srv_conf,         /* create server configuration */
[793]     ngx_http_core_merge_srv_conf,          /* merge server configuration */
[794] 
[795]     ngx_http_core_create_loc_conf,         /* create location configuration */
[796]     ngx_http_core_merge_loc_conf           /* merge location configuration */
[797] };
[798] 
[799] 
[800] ngx_module_t  ngx_http_core_module = {
[801]     NGX_MODULE_V1,
[802]     &ngx_http_core_module_ctx,             /* module context */
[803]     ngx_http_core_commands,                /* module directives */
[804]     NGX_HTTP_MODULE,                       /* module type */
[805]     NULL,                                  /* init master */
[806]     NULL,                                  /* init module */
[807]     NULL,                                  /* init process */
[808]     NULL,                                  /* init thread */
[809]     NULL,                                  /* exit thread */
[810]     NULL,                                  /* exit process */
[811]     NULL,                                  /* exit master */
[812]     NGX_MODULE_V1_PADDING
[813] };
[814] 
[815] 
[816] ngx_str_t  ngx_http_core_get_method = { 3, (u_char *) "GET" };
[817] 
[818] 
[819] void
[820] ngx_http_handler(ngx_http_request_t *r)
[821] {
[822]     ngx_http_core_main_conf_t  *cmcf;
[823] 
[824]     r->connection->log->action = NULL;
[825] 
[826]     if (!r->internal) {
[827]         switch (r->headers_in.connection_type) {
[828]         case 0:
[829]             r->keepalive = (r->http_version > NGX_HTTP_VERSION_10);
[830]             break;
[831] 
[832]         case NGX_HTTP_CONNECTION_CLOSE:
[833]             r->keepalive = 0;
[834]             break;
[835] 
[836]         case NGX_HTTP_CONNECTION_KEEP_ALIVE:
[837]             r->keepalive = 1;
[838]             break;
[839]         }
[840] 
[841]         r->lingering_close = (r->headers_in.content_length_n > 0
[842]                               || r->headers_in.chunked);
[843]         r->phase_handler = 0;
[844] 
[845]     } else {
[846]         cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[847]         r->phase_handler = cmcf->phase_engine.server_rewrite_index;
[848]     }
[849] 
[850]     r->valid_location = 1;
[851] #if (NGX_HTTP_GZIP)
[852]     r->gzip_tested = 0;
[853]     r->gzip_ok = 0;
[854]     r->gzip_vary = 0;
[855] #endif
[856] 
[857]     r->write_event_handler = ngx_http_core_run_phases;
[858]     ngx_http_core_run_phases(r);
[859] }
[860] 
[861] 
[862] void
[863] ngx_http_core_run_phases(ngx_http_request_t *r)
[864] {
[865]     ngx_int_t                   rc;
[866]     ngx_http_phase_handler_t   *ph;
[867]     ngx_http_core_main_conf_t  *cmcf;
[868] 
[869]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[870] 
[871]     ph = cmcf->phase_engine.handlers;
[872] 
[873]     while (ph[r->phase_handler].checker) {
[874] 
[875]         rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);
[876] 
[877]         if (rc == NGX_OK) {
[878]             return;
[879]         }
[880]     }
[881] }
[882] 
[883] 
[884] ngx_int_t
[885] ngx_http_core_generic_phase(ngx_http_request_t *r, ngx_http_phase_handler_t *ph)
[886] {
[887]     ngx_int_t  rc;
[888] 
[889]     /*
[890]      * generic phase checker,
[891]      * used by the post read and pre-access phases
[892]      */
[893] 
[894]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[895]                    "generic phase: %ui", r->phase_handler);
[896] 
[897]     rc = ph->handler(r);
[898] 
[899]     if (rc == NGX_OK) {
[900]         r->phase_handler = ph->next;
[901]         return NGX_AGAIN;
[902]     }
[903] 
[904]     if (rc == NGX_DECLINED) {
[905]         r->phase_handler++;
[906]         return NGX_AGAIN;
[907]     }
[908] 
[909]     if (rc == NGX_AGAIN || rc == NGX_DONE) {
[910]         return NGX_OK;
[911]     }
[912] 
[913]     /* rc == NGX_ERROR || rc == NGX_HTTP_...  */
[914] 
[915]     ngx_http_finalize_request(r, rc);
[916] 
[917]     return NGX_OK;
[918] }
[919] 
[920] 
[921] ngx_int_t
[922] ngx_http_core_rewrite_phase(ngx_http_request_t *r, ngx_http_phase_handler_t *ph)
[923] {
[924]     ngx_int_t  rc;
[925] 
[926]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[927]                    "rewrite phase: %ui", r->phase_handler);
[928] 
[929]     rc = ph->handler(r);
[930] 
[931]     if (rc == NGX_DECLINED) {
[932]         r->phase_handler++;
[933]         return NGX_AGAIN;
[934]     }
[935] 
[936]     if (rc == NGX_DONE) {
[937]         return NGX_OK;
[938]     }
[939] 
[940]     /* NGX_OK, NGX_AGAIN, NGX_ERROR, NGX_HTTP_...  */
[941] 
[942]     ngx_http_finalize_request(r, rc);
[943] 
[944]     return NGX_OK;
[945] }
[946] 
[947] 
[948] ngx_int_t
[949] ngx_http_core_find_config_phase(ngx_http_request_t *r,
[950]     ngx_http_phase_handler_t *ph)
[951] {
[952]     u_char                    *p;
[953]     size_t                     len;
[954]     ngx_int_t                  rc;
[955]     ngx_http_core_loc_conf_t  *clcf;
[956] 
[957]     r->content_handler = NULL;
[958]     r->uri_changed = 0;
[959] 
[960]     rc = ngx_http_core_find_location(r);
[961] 
[962]     if (rc == NGX_ERROR) {
[963]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[964]         return NGX_OK;
[965]     }
[966] 
[967]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[968] 
[969]     if (!r->internal && clcf->internal) {
[970]         ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
[971]         return NGX_OK;
[972]     }
[973] 
[974]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[975]                    "using configuration \"%s%V\"",
[976]                    (clcf->noname ? "*" : (clcf->exact_match ? "=" : "")),
[977]                    &clcf->name);
[978] 
[979]     ngx_http_update_location_config(r);
[980] 
[981]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[982]                    "http cl:%O max:%O",
[983]                    r->headers_in.content_length_n, clcf->client_max_body_size);
[984] 
[985]     if (r->headers_in.content_length_n != -1
[986]         && !r->discard_body
[987]         && clcf->client_max_body_size
[988]         && clcf->client_max_body_size < r->headers_in.content_length_n)
[989]     {
[990]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[991]                       "client intended to send too large body: %O bytes",
[992]                       r->headers_in.content_length_n);
[993] 
[994]         r->expect_tested = 1;
[995]         (void) ngx_http_discard_request_body(r);
[996]         ngx_http_finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
[997]         return NGX_OK;
[998]     }
[999] 
[1000]     if (rc == NGX_DONE) {
[1001]         ngx_http_clear_location(r);
[1002] 
[1003]         r->headers_out.location = ngx_list_push(&r->headers_out.headers);
[1004]         if (r->headers_out.location == NULL) {
[1005]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1006]             return NGX_OK;
[1007]         }
[1008] 
[1009]         r->headers_out.location->hash = 1;
[1010]         r->headers_out.location->next = NULL;
[1011]         ngx_str_set(&r->headers_out.location->key, "Location");
[1012] 
[1013]         if (r->args.len == 0) {
[1014]             r->headers_out.location->value = clcf->escaped_name;
[1015] 
[1016]         } else {
[1017]             len = clcf->escaped_name.len + 1 + r->args.len;
[1018]             p = ngx_pnalloc(r->pool, len);
[1019] 
[1020]             if (p == NULL) {
[1021]                 ngx_http_clear_location(r);
[1022]                 ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1023]                 return NGX_OK;
[1024]             }
[1025] 
[1026]             r->headers_out.location->value.len = len;
[1027]             r->headers_out.location->value.data = p;
[1028] 
[1029]             p = ngx_cpymem(p, clcf->escaped_name.data, clcf->escaped_name.len);
[1030]             *p++ = '?';
[1031]             ngx_memcpy(p, r->args.data, r->args.len);
[1032]         }
[1033] 
[1034]         ngx_http_finalize_request(r, NGX_HTTP_MOVED_PERMANENTLY);
[1035]         return NGX_OK;
[1036]     }
[1037] 
[1038]     r->phase_handler++;
[1039]     return NGX_AGAIN;
[1040] }
[1041] 
[1042] 
[1043] ngx_int_t
[1044] ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
[1045]     ngx_http_phase_handler_t *ph)
[1046] {
[1047]     ngx_http_core_srv_conf_t  *cscf;
[1048] 
[1049]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1050]                    "post rewrite phase: %ui", r->phase_handler);
[1051] 
[1052]     if (!r->uri_changed) {
[1053]         r->phase_handler++;
[1054]         return NGX_AGAIN;
[1055]     }
[1056] 
[1057]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1058]                    "uri changes: %d", r->uri_changes);
[1059] 
[1060]     /*
[1061]      * gcc before 3.3 compiles the broken code for
[1062]      *     if (r->uri_changes-- == 0)
[1063]      * if the r->uri_changes is defined as
[1064]      *     unsigned  uri_changes:4
[1065]      */
[1066] 
[1067]     r->uri_changes--;
[1068] 
[1069]     if (r->uri_changes == 0) {
[1070]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1071]                       "rewrite or internal redirection cycle "
[1072]                       "while processing \"%V\"", &r->uri);
[1073] 
[1074]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1075]         return NGX_OK;
[1076]     }
[1077] 
[1078]     r->phase_handler = ph->next;
[1079] 
[1080]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1081]     r->loc_conf = cscf->ctx->loc_conf;
[1082] 
[1083]     return NGX_AGAIN;
[1084] }
[1085] 
[1086] 
[1087] ngx_int_t
[1088] ngx_http_core_access_phase(ngx_http_request_t *r, ngx_http_phase_handler_t *ph)
[1089] {
[1090]     ngx_int_t                  rc;
[1091]     ngx_table_elt_t           *h;
[1092]     ngx_http_core_loc_conf_t  *clcf;
[1093] 
[1094]     if (r != r->main) {
[1095]         r->phase_handler = ph->next;
[1096]         return NGX_AGAIN;
[1097]     }
[1098] 
[1099]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1100]                    "access phase: %ui", r->phase_handler);
[1101] 
[1102]     rc = ph->handler(r);
[1103] 
[1104]     if (rc == NGX_DECLINED) {
[1105]         r->phase_handler++;
[1106]         return NGX_AGAIN;
[1107]     }
[1108] 
[1109]     if (rc == NGX_AGAIN || rc == NGX_DONE) {
[1110]         return NGX_OK;
[1111]     }
[1112] 
[1113]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1114] 
[1115]     if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
[1116] 
[1117]         if (rc == NGX_OK) {
[1118]             r->phase_handler++;
[1119]             return NGX_AGAIN;
[1120]         }
[1121] 
[1122]     } else {
[1123]         if (rc == NGX_OK) {
[1124]             r->access_code = 0;
[1125] 
[1126]             for (h = r->headers_out.www_authenticate; h; h = h->next) {
[1127]                 h->hash = 0;
[1128]             }
[1129] 
[1130]             r->phase_handler = ph->next;
[1131]             return NGX_AGAIN;
[1132]         }
[1133] 
[1134]         if (rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_UNAUTHORIZED) {
[1135]             if (r->access_code != NGX_HTTP_UNAUTHORIZED) {
[1136]                 r->access_code = rc;
[1137]             }
[1138] 
[1139]             r->phase_handler++;
[1140]             return NGX_AGAIN;
[1141]         }
[1142]     }
[1143] 
[1144]     /* rc == NGX_ERROR || rc == NGX_HTTP_...  */
[1145] 
[1146]     if (rc == NGX_HTTP_UNAUTHORIZED) {
[1147]         return ngx_http_core_auth_delay(r);
[1148]     }
[1149] 
[1150]     ngx_http_finalize_request(r, rc);
[1151]     return NGX_OK;
[1152] }
[1153] 
[1154] 
[1155] ngx_int_t
[1156] ngx_http_core_post_access_phase(ngx_http_request_t *r,
[1157]     ngx_http_phase_handler_t *ph)
[1158] {
[1159]     ngx_int_t  access_code;
[1160] 
[1161]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1162]                    "post access phase: %ui", r->phase_handler);
[1163] 
[1164]     access_code = r->access_code;
[1165] 
[1166]     if (access_code) {
[1167]         r->access_code = 0;
[1168] 
[1169]         if (access_code == NGX_HTTP_FORBIDDEN) {
[1170]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1171]                           "access forbidden by rule");
[1172]         }
[1173] 
[1174]         if (access_code == NGX_HTTP_UNAUTHORIZED) {
[1175]             return ngx_http_core_auth_delay(r);
[1176]         }
[1177] 
[1178]         ngx_http_finalize_request(r, access_code);
[1179]         return NGX_OK;
[1180]     }
[1181] 
[1182]     r->phase_handler++;
[1183]     return NGX_AGAIN;
[1184] }
[1185] 
[1186] 
[1187] static ngx_int_t
[1188] ngx_http_core_auth_delay(ngx_http_request_t *r)
[1189] {
[1190]     ngx_http_core_loc_conf_t  *clcf;
[1191] 
[1192]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1193] 
[1194]     if (clcf->auth_delay == 0) {
[1195]         ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
[1196]         return NGX_OK;
[1197]     }
[1198] 
[1199]     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1200]                   "delaying unauthorized request");
[1201] 
[1202]     if (r->connection->read->ready) {
[1203]         ngx_post_event(r->connection->read, &ngx_posted_events);
[1204] 
[1205]     } else {
[1206]         if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
[1207]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1208]         }
[1209]     }
[1210] 
[1211]     r->read_event_handler = ngx_http_test_reading;
[1212]     r->write_event_handler = ngx_http_core_auth_delay_handler;
[1213] 
[1214]     r->connection->write->delayed = 1;
[1215]     ngx_add_timer(r->connection->write, clcf->auth_delay);
[1216] 
[1217]     /*
[1218]      * trigger an additional event loop iteration
[1219]      * to ensure constant-time processing
[1220]      */
[1221] 
[1222]     ngx_post_event(r->connection->write, &ngx_posted_next_events);
[1223] 
[1224]     return NGX_OK;
[1225] }
[1226] 
[1227] 
[1228] static void
[1229] ngx_http_core_auth_delay_handler(ngx_http_request_t *r)
[1230] {
[1231]     ngx_event_t  *wev;
[1232] 
[1233]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1234]                    "auth delay handler");
[1235] 
[1236]     wev = r->connection->write;
[1237] 
[1238]     if (wev->delayed) {
[1239] 
[1240]         if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[1241]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[1242]         }
[1243] 
[1244]         return;
[1245]     }
[1246] 
[1247]     ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
[1248] }
[1249] 
[1250] 
[1251] ngx_int_t
[1252] ngx_http_core_content_phase(ngx_http_request_t *r,
[1253]     ngx_http_phase_handler_t *ph)
[1254] {
[1255]     size_t     root;
[1256]     ngx_int_t  rc;
[1257]     ngx_str_t  path;
[1258] 
[1259]     if (r->content_handler) {
[1260]         r->write_event_handler = ngx_http_request_empty_handler;
[1261]         ngx_http_finalize_request(r, r->content_handler(r));
[1262]         return NGX_OK;
[1263]     }
[1264] 
[1265]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1266]                    "content phase: %ui", r->phase_handler);
[1267] 
[1268]     rc = ph->handler(r);
[1269] 
[1270]     if (rc != NGX_DECLINED) {
[1271]         ngx_http_finalize_request(r, rc);
[1272]         return NGX_OK;
[1273]     }
[1274] 
[1275]     /* rc == NGX_DECLINED */
[1276] 
[1277]     ph++;
[1278] 
[1279]     if (ph->checker) {
[1280]         r->phase_handler++;
[1281]         return NGX_AGAIN;
[1282]     }
[1283] 
[1284]     /* no content handler was found */
[1285] 
[1286]     if (r->uri.data[r->uri.len - 1] == '/') {
[1287] 
[1288]         if (ngx_http_map_uri_to_path(r, &path, &root, 0) != NULL) {
[1289]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1290]                           "directory index of \"%s\" is forbidden", path.data);
[1291]         }
[1292] 
[1293]         ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
[1294]         return NGX_OK;
[1295]     }
[1296] 
[1297]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no handler found");
[1298] 
[1299]     ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
[1300]     return NGX_OK;
[1301] }
[1302] 
[1303] 
[1304] void
[1305] ngx_http_update_location_config(ngx_http_request_t *r)
[1306] {
[1307]     ngx_http_core_loc_conf_t  *clcf;
[1308] 
[1309]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1310] 
[1311]     if (r->method & clcf->limit_except) {
[1312]         r->loc_conf = clcf->limit_except_loc_conf;
[1313]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1314]     }
[1315] 
[1316]     if (r == r->main) {
[1317]         ngx_set_connection_log(r->connection, clcf->error_log);
[1318]     }
[1319] 
[1320]     if ((ngx_io.flags & NGX_IO_SENDFILE) && clcf->sendfile) {
[1321]         r->connection->sendfile = 1;
[1322] 
[1323]     } else {
[1324]         r->connection->sendfile = 0;
[1325]     }
[1326] 
[1327]     if (clcf->client_body_in_file_only) {
[1328]         r->request_body_in_file_only = 1;
[1329]         r->request_body_in_persistent_file = 1;
[1330]         r->request_body_in_clean_file =
[1331]             clcf->client_body_in_file_only == NGX_HTTP_REQUEST_BODY_FILE_CLEAN;
[1332]         r->request_body_file_log_level = NGX_LOG_NOTICE;
[1333] 
[1334]     } else {
[1335]         r->request_body_file_log_level = NGX_LOG_WARN;
[1336]     }
[1337] 
[1338]     r->request_body_in_single_buf = clcf->client_body_in_single_buffer;
[1339] 
[1340]     if (r->keepalive) {
[1341]         if (clcf->keepalive_timeout == 0) {
[1342]             r->keepalive = 0;
[1343] 
[1344]         } else if (r->connection->requests >= clcf->keepalive_requests) {
[1345]             r->keepalive = 0;
[1346] 
[1347]         } else if (ngx_current_msec - r->connection->start_time
[1348]                    > clcf->keepalive_time)
[1349]         {
[1350]             r->keepalive = 0;
[1351] 
[1352]         } else if (r->headers_in.msie6
[1353]                    && r->method == NGX_HTTP_POST
[1354]                    && (clcf->keepalive_disable
[1355]                        & NGX_HTTP_KEEPALIVE_DISABLE_MSIE6))
[1356]         {
[1357]             /*
[1358]              * MSIE may wait for some time if an response for
[1359]              * a POST request was sent over a keepalive connection
[1360]              */
[1361]             r->keepalive = 0;
[1362] 
[1363]         } else if (r->headers_in.safari
[1364]                    && (clcf->keepalive_disable
[1365]                        & NGX_HTTP_KEEPALIVE_DISABLE_SAFARI))
[1366]         {
[1367]             /*
[1368]              * Safari may send a POST request to a closed keepalive
[1369]              * connection and may stall for some time, see
[1370]              *     https://bugs.webkit.org/show_bug.cgi?id=5760
[1371]              */
[1372]             r->keepalive = 0;
[1373]         }
[1374]     }
[1375] 
[1376]     if (!clcf->tcp_nopush) {
[1377]         /* disable TCP_NOPUSH/TCP_CORK use */
[1378]         r->connection->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
[1379]     }
[1380] 
[1381]     if (clcf->handler) {
[1382]         r->content_handler = clcf->handler;
[1383]     }
[1384] }
[1385] 
[1386] 
[1387] /*
[1388]  * NGX_OK       - exact or regex match
[1389]  * NGX_DONE     - auto redirect
[1390]  * NGX_AGAIN    - inclusive match
[1391]  * NGX_ERROR    - regex error
[1392]  * NGX_DECLINED - no match
[1393]  */
[1394] 
[1395] static ngx_int_t
[1396] ngx_http_core_find_location(ngx_http_request_t *r)
[1397] {
[1398]     ngx_int_t                  rc;
[1399]     ngx_http_core_loc_conf_t  *pclcf;
[1400] #if (NGX_PCRE)
[1401]     ngx_int_t                  n;
[1402]     ngx_uint_t                 noregex;
[1403]     ngx_http_core_loc_conf_t  *clcf, **clcfp;
[1404] 
[1405]     noregex = 0;
[1406] #endif
[1407] 
[1408]     pclcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1409] 
[1410]     rc = ngx_http_core_find_static_location(r, pclcf->static_locations);
[1411] 
[1412]     if (rc == NGX_AGAIN) {
[1413] 
[1414] #if (NGX_PCRE)
[1415]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1416] 
[1417]         noregex = clcf->noregex;
[1418] #endif
[1419] 
[1420]         /* look up nested locations */
[1421] 
[1422]         rc = ngx_http_core_find_location(r);
[1423]     }
[1424] 
[1425]     if (rc == NGX_OK || rc == NGX_DONE) {
[1426]         return rc;
[1427]     }
[1428] 
[1429]     /* rc == NGX_DECLINED or rc == NGX_AGAIN in nested location */
[1430] 
[1431] #if (NGX_PCRE)
[1432] 
[1433]     if (noregex == 0 && pclcf->regex_locations) {
[1434] 
[1435]         for (clcfp = pclcf->regex_locations; *clcfp; clcfp++) {
[1436] 
[1437]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1438]                            "test location: ~ \"%V\"", &(*clcfp)->name);
[1439] 
[1440]             n = ngx_http_regex_exec(r, (*clcfp)->regex, &r->uri);
[1441] 
[1442]             if (n == NGX_OK) {
[1443]                 r->loc_conf = (*clcfp)->loc_conf;
[1444] 
[1445]                 /* look up nested locations */
[1446] 
[1447]                 rc = ngx_http_core_find_location(r);
[1448] 
[1449]                 return (rc == NGX_ERROR) ? rc : NGX_OK;
[1450]             }
[1451] 
[1452]             if (n == NGX_DECLINED) {
[1453]                 continue;
[1454]             }
[1455] 
[1456]             return NGX_ERROR;
[1457]         }
[1458]     }
[1459] #endif
[1460] 
[1461]     return rc;
[1462] }
[1463] 
[1464] 
[1465] /*
[1466]  * NGX_OK       - exact match
[1467]  * NGX_DONE     - auto redirect
[1468]  * NGX_AGAIN    - inclusive match
[1469]  * NGX_DECLINED - no match
[1470]  */
[1471] 
[1472] static ngx_int_t
[1473] ngx_http_core_find_static_location(ngx_http_request_t *r,
[1474]     ngx_http_location_tree_node_t *node)
[1475] {
[1476]     u_char     *uri;
[1477]     size_t      len, n;
[1478]     ngx_int_t   rc, rv;
[1479] 
[1480]     len = r->uri.len;
[1481]     uri = r->uri.data;
[1482] 
[1483]     rv = NGX_DECLINED;
[1484] 
[1485]     for ( ;; ) {
[1486] 
[1487]         if (node == NULL) {
[1488]             return rv;
[1489]         }
[1490] 
[1491]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1492]                        "test location: \"%*s\"",
[1493]                        (size_t) node->len, node->name);
[1494] 
[1495]         n = (len <= (size_t) node->len) ? len : node->len;
[1496] 
[1497]         rc = ngx_filename_cmp(uri, node->name, n);
[1498] 
[1499]         if (rc != 0) {
[1500]             node = (rc < 0) ? node->left : node->right;
[1501] 
[1502]             continue;
[1503]         }
[1504] 
[1505]         if (len > (size_t) node->len) {
[1506] 
[1507]             if (node->inclusive) {
[1508] 
[1509]                 r->loc_conf = node->inclusive->loc_conf;
[1510]                 rv = NGX_AGAIN;
[1511] 
[1512]                 node = node->tree;
[1513]                 uri += n;
[1514]                 len -= n;
[1515] 
[1516]                 continue;
[1517]             }
[1518] 
[1519]             /* exact only */
[1520] 
[1521]             node = node->right;
[1522] 
[1523]             continue;
[1524]         }
[1525] 
[1526]         if (len == (size_t) node->len) {
[1527] 
[1528]             if (node->exact) {
[1529]                 r->loc_conf = node->exact->loc_conf;
[1530]                 return NGX_OK;
[1531] 
[1532]             } else {
[1533]                 r->loc_conf = node->inclusive->loc_conf;
[1534]                 return NGX_AGAIN;
[1535]             }
[1536]         }
[1537] 
[1538]         /* len < node->len */
[1539] 
[1540]         if (len + 1 == (size_t) node->len && node->auto_redirect) {
[1541] 
[1542]             r->loc_conf = (node->exact) ? node->exact->loc_conf:
[1543]                                           node->inclusive->loc_conf;
[1544]             rv = NGX_DONE;
[1545]         }
[1546] 
[1547]         node = node->left;
[1548]     }
[1549] }
[1550] 
[1551] 
[1552] void *
[1553] ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash)
[1554] {
[1555]     u_char      c, *lowcase;
[1556]     size_t      len;
[1557]     ngx_uint_t  i, hash;
[1558] 
[1559]     if (types_hash->size == 0) {
[1560]         return (void *) 4;
[1561]     }
[1562] 
[1563]     if (r->headers_out.content_type.len == 0) {
[1564]         return NULL;
[1565]     }
[1566] 
[1567]     len = r->headers_out.content_type_len;
[1568] 
[1569]     if (r->headers_out.content_type_lowcase == NULL) {
[1570] 
[1571]         lowcase = ngx_pnalloc(r->pool, len);
[1572]         if (lowcase == NULL) {
[1573]             return NULL;
[1574]         }
[1575] 
[1576]         r->headers_out.content_type_lowcase = lowcase;
[1577] 
[1578]         hash = 0;
[1579] 
[1580]         for (i = 0; i < len; i++) {
[1581]             c = ngx_tolower(r->headers_out.content_type.data[i]);
[1582]             hash = ngx_hash(hash, c);
[1583]             lowcase[i] = c;
[1584]         }
[1585] 
[1586]         r->headers_out.content_type_hash = hash;
[1587]     }
[1588] 
[1589]     return ngx_hash_find(types_hash, r->headers_out.content_type_hash,
[1590]                          r->headers_out.content_type_lowcase, len);
[1591] }
[1592] 
[1593] 
[1594] ngx_int_t
[1595] ngx_http_set_content_type(ngx_http_request_t *r)
[1596] {
[1597]     u_char                     c, *exten;
[1598]     ngx_str_t                 *type;
[1599]     ngx_uint_t                 i, hash;
[1600]     ngx_http_core_loc_conf_t  *clcf;
[1601] 
[1602]     if (r->headers_out.content_type.len) {
[1603]         return NGX_OK;
[1604]     }
[1605] 
[1606]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1607] 
[1608]     if (r->exten.len) {
[1609] 
[1610]         hash = 0;
[1611] 
[1612]         for (i = 0; i < r->exten.len; i++) {
[1613]             c = r->exten.data[i];
[1614] 
[1615]             if (c >= 'A' && c <= 'Z') {
[1616] 
[1617]                 exten = ngx_pnalloc(r->pool, r->exten.len);
[1618]                 if (exten == NULL) {
[1619]                     return NGX_ERROR;
[1620]                 }
[1621] 
[1622]                 hash = ngx_hash_strlow(exten, r->exten.data, r->exten.len);
[1623] 
[1624]                 r->exten.data = exten;
[1625] 
[1626]                 break;
[1627]             }
[1628] 
[1629]             hash = ngx_hash(hash, c);
[1630]         }
[1631] 
[1632]         type = ngx_hash_find(&clcf->types_hash, hash,
[1633]                              r->exten.data, r->exten.len);
[1634] 
[1635]         if (type) {
[1636]             r->headers_out.content_type_len = type->len;
[1637]             r->headers_out.content_type = *type;
[1638] 
[1639]             return NGX_OK;
[1640]         }
[1641]     }
[1642] 
[1643]     r->headers_out.content_type_len = clcf->default_type.len;
[1644]     r->headers_out.content_type = clcf->default_type;
[1645] 
[1646]     return NGX_OK;
[1647] }
[1648] 
[1649] 
[1650] void
[1651] ngx_http_set_exten(ngx_http_request_t *r)
[1652] {
[1653]     ngx_int_t  i;
[1654] 
[1655]     ngx_str_null(&r->exten);
[1656] 
[1657]     for (i = r->uri.len - 1; i > 1; i--) {
[1658]         if (r->uri.data[i] == '.' && r->uri.data[i - 1] != '/') {
[1659] 
[1660]             r->exten.len = r->uri.len - i - 1;
[1661]             r->exten.data = &r->uri.data[i + 1];
[1662] 
[1663]             return;
[1664] 
[1665]         } else if (r->uri.data[i] == '/') {
[1666]             return;
[1667]         }
[1668]     }
[1669] 
[1670]     return;
[1671] }
[1672] 
[1673] 
[1674] ngx_int_t
[1675] ngx_http_set_etag(ngx_http_request_t *r)
[1676] {
[1677]     ngx_table_elt_t           *etag;
[1678]     ngx_http_core_loc_conf_t  *clcf;
[1679] 
[1680]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1681] 
[1682]     if (!clcf->etag) {
[1683]         return NGX_OK;
[1684]     }
[1685] 
[1686]     etag = ngx_list_push(&r->headers_out.headers);
[1687]     if (etag == NULL) {
[1688]         return NGX_ERROR;
[1689]     }
[1690] 
[1691]     etag->hash = 1;
[1692]     etag->next = NULL;
[1693]     ngx_str_set(&etag->key, "ETag");
[1694] 
[1695]     etag->value.data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN + NGX_TIME_T_LEN + 3);
[1696]     if (etag->value.data == NULL) {
[1697]         etag->hash = 0;
[1698]         return NGX_ERROR;
[1699]     }
[1700] 
[1701]     etag->value.len = ngx_sprintf(etag->value.data, "\"%xT-%xO\"",
[1702]                                   r->headers_out.last_modified_time,
[1703]                                   r->headers_out.content_length_n)
[1704]                       - etag->value.data;
[1705] 
[1706]     r->headers_out.etag = etag;
[1707] 
[1708]     return NGX_OK;
[1709] }
[1710] 
[1711] 
[1712] void
[1713] ngx_http_weak_etag(ngx_http_request_t *r)
[1714] {
[1715]     size_t            len;
[1716]     u_char           *p;
[1717]     ngx_table_elt_t  *etag;
[1718] 
[1719]     etag = r->headers_out.etag;
[1720] 
[1721]     if (etag == NULL) {
[1722]         return;
[1723]     }
[1724] 
[1725]     if (etag->value.len > 2
[1726]         && etag->value.data[0] == 'W'
[1727]         && etag->value.data[1] == '/')
[1728]     {
[1729]         return;
[1730]     }
[1731] 
[1732]     if (etag->value.len < 1 || etag->value.data[0] != '"') {
[1733]         r->headers_out.etag->hash = 0;
[1734]         r->headers_out.etag = NULL;
[1735]         return;
[1736]     }
[1737] 
[1738]     p = ngx_pnalloc(r->pool, etag->value.len + 2);
[1739]     if (p == NULL) {
[1740]         r->headers_out.etag->hash = 0;
[1741]         r->headers_out.etag = NULL;
[1742]         return;
[1743]     }
[1744] 
[1745]     len = ngx_sprintf(p, "W/%V", &etag->value) - p;
[1746] 
[1747]     etag->value.data = p;
[1748]     etag->value.len = len;
[1749] }
[1750] 
[1751] 
[1752] ngx_int_t
[1753] ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
[1754]     ngx_str_t *ct, ngx_http_complex_value_t *cv)
[1755] {
[1756]     ngx_int_t     rc;
[1757]     ngx_str_t     val;
[1758]     ngx_buf_t    *b;
[1759]     ngx_chain_t   out;
[1760] 
[1761]     rc = ngx_http_discard_request_body(r);
[1762] 
[1763]     if (rc != NGX_OK) {
[1764]         return rc;
[1765]     }
[1766] 
[1767]     r->headers_out.status = status;
[1768] 
[1769]     if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
[1770]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1771]     }
[1772] 
[1773]     if (status == NGX_HTTP_MOVED_PERMANENTLY
[1774]         || status == NGX_HTTP_MOVED_TEMPORARILY
[1775]         || status == NGX_HTTP_SEE_OTHER
[1776]         || status == NGX_HTTP_TEMPORARY_REDIRECT
[1777]         || status == NGX_HTTP_PERMANENT_REDIRECT)
[1778]     {
[1779]         ngx_http_clear_location(r);
[1780] 
[1781]         r->headers_out.location = ngx_list_push(&r->headers_out.headers);
[1782]         if (r->headers_out.location == NULL) {
[1783]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1784]         }
[1785] 
[1786]         r->headers_out.location->hash = 1;
[1787]         r->headers_out.location->next = NULL;
[1788]         ngx_str_set(&r->headers_out.location->key, "Location");
[1789]         r->headers_out.location->value = val;
[1790] 
[1791]         return status;
[1792]     }
[1793] 
[1794]     r->headers_out.content_length_n = val.len;
[1795] 
[1796]     if (ct) {
[1797]         r->headers_out.content_type_len = ct->len;
[1798]         r->headers_out.content_type = *ct;
[1799] 
[1800]     } else {
[1801]         if (ngx_http_set_content_type(r) != NGX_OK) {
[1802]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1803]         }
[1804]     }
[1805] 
[1806]     b = ngx_calloc_buf(r->pool);
[1807]     if (b == NULL) {
[1808]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1809]     }
[1810] 
[1811]     b->pos = val.data;
[1812]     b->last = val.data + val.len;
[1813]     b->memory = val.len ? 1 : 0;
[1814]     b->last_buf = (r == r->main) ? 1 : 0;
[1815]     b->last_in_chain = 1;
[1816]     b->sync = (b->last_buf || b->memory) ? 0 : 1;
[1817] 
[1818]     out.buf = b;
[1819]     out.next = NULL;
[1820] 
[1821]     rc = ngx_http_send_header(r);
[1822] 
[1823]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[1824]         return rc;
[1825]     }
[1826] 
[1827]     return ngx_http_output_filter(r, &out);
[1828] }
[1829] 
[1830] 
[1831] ngx_int_t
[1832] ngx_http_send_header(ngx_http_request_t *r)
[1833] {
[1834]     if (r->post_action) {
[1835]         return NGX_OK;
[1836]     }
[1837] 
[1838]     if (r->header_sent) {
[1839]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1840]                       "header already sent");
[1841]         return NGX_ERROR;
[1842]     }
[1843] 
[1844]     if (r->err_status) {
[1845]         r->headers_out.status = r->err_status;
[1846]         r->headers_out.status_line.len = 0;
[1847]     }
[1848] 
[1849]     return ngx_http_top_header_filter(r);
[1850] }
[1851] 
[1852] 
[1853] ngx_int_t
[1854] ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
[1855] {
[1856]     ngx_int_t          rc;
[1857]     ngx_connection_t  *c;
[1858] 
[1859]     c = r->connection;
[1860] 
[1861]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[1862]                    "http output filter \"%V?%V\"", &r->uri, &r->args);
[1863] 
[1864]     rc = ngx_http_top_body_filter(r, in);
[1865] 
[1866]     if (rc == NGX_ERROR) {
[1867]         /* NGX_ERROR may be returned by any filter */
[1868]         c->error = 1;
[1869]     }
[1870] 
[1871]     return rc;
[1872] }
[1873] 
[1874] 
[1875] u_char *
[1876] ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *path,
[1877]     size_t *root_length, size_t reserved)
[1878] {
[1879]     u_char                    *last;
[1880]     size_t                     alias;
[1881]     ngx_http_core_loc_conf_t  *clcf;
[1882] 
[1883]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1884] 
[1885]     alias = clcf->alias;
[1886] 
[1887]     if (alias && !r->valid_location) {
[1888]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1889]                       "\"alias\" cannot be used in location \"%V\" "
[1890]                       "where URI was rewritten", &clcf->name);
[1891]         return NULL;
[1892]     }
[1893] 
[1894]     if (clcf->root_lengths == NULL) {
[1895] 
[1896]         *root_length = clcf->root.len;
[1897] 
[1898]         path->len = clcf->root.len + reserved + r->uri.len - alias + 1;
[1899] 
[1900]         path->data = ngx_pnalloc(r->pool, path->len);
[1901]         if (path->data == NULL) {
[1902]             return NULL;
[1903]         }
[1904] 
[1905]         last = ngx_copy(path->data, clcf->root.data, clcf->root.len);
[1906] 
[1907]     } else {
[1908] 
[1909]         if (alias == NGX_MAX_SIZE_T_VALUE) {
[1910]             reserved += r->add_uri_to_alias ? r->uri.len + 1 : 1;
[1911] 
[1912]         } else {
[1913]             reserved += r->uri.len - alias + 1;
[1914]         }
[1915] 
[1916]         if (ngx_http_script_run(r, path, clcf->root_lengths->elts, reserved,
[1917]                                 clcf->root_values->elts)
[1918]             == NULL)
[1919]         {
[1920]             return NULL;
[1921]         }
[1922] 
[1923]         if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, path)
[1924]             != NGX_OK)
[1925]         {
[1926]             return NULL;
[1927]         }
[1928] 
[1929]         *root_length = path->len - reserved;
[1930]         last = path->data + *root_length;
[1931] 
[1932]         if (alias == NGX_MAX_SIZE_T_VALUE) {
[1933]             if (!r->add_uri_to_alias) {
[1934]                 *last = '\0';
[1935]                 return last;
[1936]             }
[1937] 
[1938]             alias = 0;
[1939]         }
[1940]     }
[1941] 
[1942]     last = ngx_copy(last, r->uri.data + alias, r->uri.len - alias);
[1943]     *last = '\0';
[1944] 
[1945]     return last;
[1946] }
[1947] 
[1948] 
[1949] ngx_int_t
[1950] ngx_http_auth_basic_user(ngx_http_request_t *r)
[1951] {
[1952]     ngx_str_t   auth, encoded;
[1953]     ngx_uint_t  len;
[1954] 
[1955]     if (r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
[1956]         return NGX_DECLINED;
[1957]     }
[1958] 
[1959]     if (r->headers_in.authorization == NULL) {
[1960]         r->headers_in.user.data = (u_char *) "";
[1961]         return NGX_DECLINED;
[1962]     }
[1963] 
[1964]     encoded = r->headers_in.authorization->value;
[1965] 
[1966]     if (encoded.len < sizeof("Basic ") - 1
[1967]         || ngx_strncasecmp(encoded.data, (u_char *) "Basic ",
[1968]                            sizeof("Basic ") - 1)
[1969]            != 0)
[1970]     {
[1971]         r->headers_in.user.data = (u_char *) "";
[1972]         return NGX_DECLINED;
[1973]     }
[1974] 
[1975]     encoded.len -= sizeof("Basic ") - 1;
[1976]     encoded.data += sizeof("Basic ") - 1;
[1977] 
[1978]     while (encoded.len && encoded.data[0] == ' ') {
[1979]         encoded.len--;
[1980]         encoded.data++;
[1981]     }
[1982] 
[1983]     if (encoded.len == 0) {
[1984]         r->headers_in.user.data = (u_char *) "";
[1985]         return NGX_DECLINED;
[1986]     }
[1987] 
[1988]     auth.len = ngx_base64_decoded_length(encoded.len);
[1989]     auth.data = ngx_pnalloc(r->pool, auth.len + 1);
[1990]     if (auth.data == NULL) {
[1991]         return NGX_ERROR;
[1992]     }
[1993] 
[1994]     if (ngx_decode_base64(&auth, &encoded) != NGX_OK) {
[1995]         r->headers_in.user.data = (u_char *) "";
[1996]         return NGX_DECLINED;
[1997]     }
[1998] 
[1999]     auth.data[auth.len] = '\0';
[2000] 
[2001]     for (len = 0; len < auth.len; len++) {
[2002]         if (auth.data[len] == ':') {
[2003]             break;
[2004]         }
[2005]     }
[2006] 
[2007]     if (len == 0 || len == auth.len) {
[2008]         r->headers_in.user.data = (u_char *) "";
[2009]         return NGX_DECLINED;
[2010]     }
[2011] 
[2012]     r->headers_in.user.len = len;
[2013]     r->headers_in.user.data = auth.data;
[2014]     r->headers_in.passwd.len = auth.len - len - 1;
[2015]     r->headers_in.passwd.data = &auth.data[len + 1];
[2016] 
[2017]     return NGX_OK;
[2018] }
[2019] 
[2020] 
[2021] #if (NGX_HTTP_GZIP)
[2022] 
[2023] ngx_int_t
[2024] ngx_http_gzip_ok(ngx_http_request_t *r)
[2025] {
[2026]     time_t                     date, expires;
[2027]     ngx_uint_t                 p;
[2028]     ngx_table_elt_t           *e, *d, *ae, *cc;
[2029]     ngx_http_core_loc_conf_t  *clcf;
[2030] 
[2031]     r->gzip_tested = 1;
[2032] 
[2033]     if (r != r->main) {
[2034]         return NGX_DECLINED;
[2035]     }
[2036] 
[2037]     ae = r->headers_in.accept_encoding;
[2038]     if (ae == NULL) {
[2039]         return NGX_DECLINED;
[2040]     }
[2041] 
[2042]     if (ae->value.len < sizeof("gzip") - 1) {
[2043]         return NGX_DECLINED;
[2044]     }
[2045] 
[2046]     /*
[2047]      * test first for the most common case "gzip,...":
[2048]      *   MSIE:    "gzip, deflate"
[2049]      *   Firefox: "gzip,deflate"
[2050]      *   Chrome:  "gzip,deflate,sdch"
[2051]      *   Safari:  "gzip, deflate"
[2052]      *   Opera:   "gzip, deflate"
[2053]      */
[2054] 
[2055]     if (ngx_memcmp(ae->value.data, "gzip,", 5) != 0
[2056]         && ngx_http_gzip_accept_encoding(&ae->value) != NGX_OK)
[2057]     {
[2058]         return NGX_DECLINED;
[2059]     }
[2060] 
[2061]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2062] 
[2063]     if (r->headers_in.msie6 && clcf->gzip_disable_msie6) {
[2064]         return NGX_DECLINED;
[2065]     }
[2066] 
[2067]     if (r->http_version < clcf->gzip_http_version) {
[2068]         return NGX_DECLINED;
[2069]     }
[2070] 
[2071]     if (r->headers_in.via == NULL) {
[2072]         goto ok;
[2073]     }
[2074] 
[2075]     p = clcf->gzip_proxied;
[2076] 
[2077]     if (p & NGX_HTTP_GZIP_PROXIED_OFF) {
[2078]         return NGX_DECLINED;
[2079]     }
[2080] 
[2081]     if (p & NGX_HTTP_GZIP_PROXIED_ANY) {
[2082]         goto ok;
[2083]     }
[2084] 
[2085]     if (r->headers_in.authorization && (p & NGX_HTTP_GZIP_PROXIED_AUTH)) {
[2086]         goto ok;
[2087]     }
[2088] 
[2089]     e = r->headers_out.expires;
[2090] 
[2091]     if (e) {
[2092] 
[2093]         if (!(p & NGX_HTTP_GZIP_PROXIED_EXPIRED)) {
[2094]             return NGX_DECLINED;
[2095]         }
[2096] 
[2097]         expires = ngx_parse_http_time(e->value.data, e->value.len);
[2098]         if (expires == NGX_ERROR) {
[2099]             return NGX_DECLINED;
[2100]         }
[2101] 
[2102]         d = r->headers_out.date;
[2103] 
[2104]         if (d) {
[2105]             date = ngx_parse_http_time(d->value.data, d->value.len);
[2106]             if (date == NGX_ERROR) {
[2107]                 return NGX_DECLINED;
[2108]             }
[2109] 
[2110]         } else {
[2111]             date = ngx_time();
[2112]         }
[2113] 
[2114]         if (expires < date) {
[2115]             goto ok;
[2116]         }
[2117] 
[2118]         return NGX_DECLINED;
[2119]     }
[2120] 
[2121]     cc = r->headers_out.cache_control;
[2122] 
[2123]     if (cc) {
[2124] 
[2125]         if ((p & NGX_HTTP_GZIP_PROXIED_NO_CACHE)
[2126]             && ngx_http_parse_multi_header_lines(r, cc, &ngx_http_gzip_no_cache,
[2127]                                                  NULL)
[2128]                != NULL)
[2129]         {
[2130]             goto ok;
[2131]         }
[2132] 
[2133]         if ((p & NGX_HTTP_GZIP_PROXIED_NO_STORE)
[2134]             && ngx_http_parse_multi_header_lines(r, cc, &ngx_http_gzip_no_store,
[2135]                                                  NULL)
[2136]                != NULL)
[2137]         {
[2138]             goto ok;
[2139]         }
[2140] 
[2141]         if ((p & NGX_HTTP_GZIP_PROXIED_PRIVATE)
[2142]             && ngx_http_parse_multi_header_lines(r, cc, &ngx_http_gzip_private,
[2143]                                                  NULL)
[2144]                != NULL)
[2145]         {
[2146]             goto ok;
[2147]         }
[2148] 
[2149]         return NGX_DECLINED;
[2150]     }
[2151] 
[2152]     if ((p & NGX_HTTP_GZIP_PROXIED_NO_LM) && r->headers_out.last_modified) {
[2153]         return NGX_DECLINED;
[2154]     }
[2155] 
[2156]     if ((p & NGX_HTTP_GZIP_PROXIED_NO_ETAG) && r->headers_out.etag) {
[2157]         return NGX_DECLINED;
[2158]     }
[2159] 
[2160] ok:
[2161] 
[2162] #if (NGX_PCRE)
[2163] 
[2164]     if (clcf->gzip_disable && r->headers_in.user_agent) {
[2165] 
[2166]         if (ngx_regex_exec_array(clcf->gzip_disable,
[2167]                                  &r->headers_in.user_agent->value,
[2168]                                  r->connection->log)
[2169]             != NGX_DECLINED)
[2170]         {
[2171]             return NGX_DECLINED;
[2172]         }
[2173]     }
[2174] 
[2175] #endif
[2176] 
[2177]     r->gzip_ok = 1;
[2178] 
[2179]     return NGX_OK;
[2180] }
[2181] 
[2182] 
[2183] /*
[2184]  * gzip is enabled for the following quantities:
[2185]  *     "gzip; q=0.001" ... "gzip; q=1.000"
[2186]  * gzip is disabled for the following quantities:
[2187]  *     "gzip; q=0" ... "gzip; q=0.000", and for any invalid cases
[2188]  */
[2189] 
[2190] static ngx_int_t
[2191] ngx_http_gzip_accept_encoding(ngx_str_t *ae)
[2192] {
[2193]     u_char  *p, *start, *last;
[2194] 
[2195]     start = ae->data;
[2196]     last = start + ae->len;
[2197] 
[2198]     for ( ;; ) {
[2199]         p = ngx_strcasestrn(start, "gzip", 4 - 1);
[2200]         if (p == NULL) {
[2201]             return NGX_DECLINED;
[2202]         }
[2203] 
[2204]         if (p == start || (*(p - 1) == ',' || *(p - 1) == ' ')) {
[2205]             break;
[2206]         }
[2207] 
[2208]         start = p + 4;
[2209]     }
[2210] 
[2211]     p += 4;
[2212] 
[2213]     while (p < last) {
[2214]         switch (*p++) {
[2215]         case ',':
[2216]             return NGX_OK;
[2217]         case ';':
[2218]             goto quantity;
[2219]         case ' ':
[2220]             continue;
[2221]         default:
[2222]             return NGX_DECLINED;
[2223]         }
[2224]     }
[2225] 
[2226]     return NGX_OK;
[2227] 
[2228] quantity:
[2229] 
[2230]     while (p < last) {
[2231]         switch (*p++) {
[2232]         case 'q':
[2233]         case 'Q':
[2234]             goto equal;
[2235]         case ' ':
[2236]             continue;
[2237]         default:
[2238]             return NGX_DECLINED;
[2239]         }
[2240]     }
[2241] 
[2242]     return NGX_OK;
[2243] 
[2244] equal:
[2245] 
[2246]     if (p + 2 > last || *p++ != '=') {
[2247]         return NGX_DECLINED;
[2248]     }
[2249] 
[2250]     if (ngx_http_gzip_quantity(p, last) == 0) {
[2251]         return NGX_DECLINED;
[2252]     }
[2253] 
[2254]     return NGX_OK;
[2255] }
[2256] 
[2257] 
[2258] static ngx_uint_t
[2259] ngx_http_gzip_quantity(u_char *p, u_char *last)
[2260] {
[2261]     u_char      c;
[2262]     ngx_uint_t  n, q;
[2263] 
[2264]     c = *p++;
[2265] 
[2266]     if (c != '0' && c != '1') {
[2267]         return 0;
[2268]     }
[2269] 
[2270]     q = (c - '0') * 100;
[2271] 
[2272]     if (p == last) {
[2273]         return q;
[2274]     }
[2275] 
[2276]     c = *p++;
[2277] 
[2278]     if (c == ',' || c == ' ') {
[2279]         return q;
[2280]     }
[2281] 
[2282]     if (c != '.') {
[2283]         return 0;
[2284]     }
[2285] 
[2286]     n = 0;
[2287] 
[2288]     while (p < last) {
[2289]         c = *p++;
[2290] 
[2291]         if (c == ',' || c == ' ') {
[2292]             break;
[2293]         }
[2294] 
[2295]         if (c >= '0' && c <= '9') {
[2296]             q += c - '0';
[2297]             n++;
[2298]             continue;
[2299]         }
[2300] 
[2301]         return 0;
[2302]     }
[2303] 
[2304]     if (q > 100 || n > 3) {
[2305]         return 0;
[2306]     }
[2307] 
[2308]     return q;
[2309] }
[2310] 
[2311] #endif
[2312] 
[2313] 
[2314] ngx_int_t
[2315] ngx_http_subrequest(ngx_http_request_t *r,
[2316]     ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
[2317]     ngx_http_post_subrequest_t *ps, ngx_uint_t flags)
[2318] {
[2319]     ngx_time_t                    *tp;
[2320]     ngx_connection_t              *c;
[2321]     ngx_http_request_t            *sr;
[2322]     ngx_http_core_srv_conf_t      *cscf;
[2323]     ngx_http_postponed_request_t  *pr, *p;
[2324] 
[2325]     if (r->subrequests == 0) {
[2326]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2327]                       "subrequests cycle while processing \"%V\"", uri);
[2328]         return NGX_ERROR;
[2329]     }
[2330] 
[2331]     /*
[2332]      * 1000 is reserved for other purposes.
[2333]      */
[2334]     if (r->main->count >= 65535 - 1000) {
[2335]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
[2336]                       "request reference counter overflow "
[2337]                       "while processing \"%V\"", uri);
[2338]         return NGX_ERROR;
[2339]     }
[2340] 
[2341]     if (r->subrequest_in_memory) {
[2342]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2343]                       "nested in-memory subrequest \"%V\"", uri);
[2344]         return NGX_ERROR;
[2345]     }
[2346] 
[2347]     sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));
[2348]     if (sr == NULL) {
[2349]         return NGX_ERROR;
[2350]     }
[2351] 
[2352]     sr->signature = NGX_HTTP_MODULE;
[2353] 
[2354]     c = r->connection;
[2355]     sr->connection = c;
[2356] 
[2357]     sr->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
[2358]     if (sr->ctx == NULL) {
[2359]         return NGX_ERROR;
[2360]     }
[2361] 
[2362]     if (ngx_list_init(&sr->headers_out.headers, r->pool, 20,
[2363]                       sizeof(ngx_table_elt_t))
[2364]         != NGX_OK)
[2365]     {
[2366]         return NGX_ERROR;
[2367]     }
[2368] 
[2369]     if (ngx_list_init(&sr->headers_out.trailers, r->pool, 4,
[2370]                       sizeof(ngx_table_elt_t))
[2371]         != NGX_OK)
[2372]     {
[2373]         return NGX_ERROR;
[2374]     }
[2375] 
[2376]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[2377]     sr->main_conf = cscf->ctx->main_conf;
[2378]     sr->srv_conf = cscf->ctx->srv_conf;
[2379]     sr->loc_conf = cscf->ctx->loc_conf;
[2380] 
[2381]     sr->pool = r->pool;
[2382] 
[2383]     sr->headers_in = r->headers_in;
[2384] 
[2385]     ngx_http_clear_content_length(sr);
[2386]     ngx_http_clear_accept_ranges(sr);
[2387]     ngx_http_clear_last_modified(sr);
[2388] 
[2389]     sr->request_body = r->request_body;
[2390] 
[2391] #if (NGX_HTTP_V2)
[2392]     sr->stream = r->stream;
[2393] #endif
[2394] 
[2395]     sr->method = NGX_HTTP_GET;
[2396]     sr->http_version = r->http_version;
[2397] 
[2398]     sr->request_line = r->request_line;
[2399]     sr->uri = *uri;
[2400] 
[2401]     if (args) {
[2402]         sr->args = *args;
[2403]     }
[2404] 
[2405]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[2406]                    "http subrequest \"%V?%V\"", uri, &sr->args);
[2407] 
[2408]     sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;
[2409]     sr->waited = (flags & NGX_HTTP_SUBREQUEST_WAITED) != 0;
[2410]     sr->background = (flags & NGX_HTTP_SUBREQUEST_BACKGROUND) != 0;
[2411] 
[2412]     sr->unparsed_uri = r->unparsed_uri;
[2413]     sr->method_name = ngx_http_core_get_method;
[2414]     sr->http_protocol = r->http_protocol;
[2415]     sr->schema = r->schema;
[2416] 
[2417]     ngx_http_set_exten(sr);
[2418] 
[2419]     sr->main = r->main;
[2420]     sr->parent = r;
[2421]     sr->post_subrequest = ps;
[2422]     sr->read_event_handler = ngx_http_request_empty_handler;
[2423]     sr->write_event_handler = ngx_http_handler;
[2424] 
[2425]     sr->variables = r->variables;
[2426] 
[2427]     sr->log_handler = r->log_handler;
[2428] 
[2429]     if (sr->subrequest_in_memory) {
[2430]         sr->filter_need_in_memory = 1;
[2431]     }
[2432] 
[2433]     if (!sr->background) {
[2434]         if (c->data == r && r->postponed == NULL) {
[2435]             c->data = sr;
[2436]         }
[2437] 
[2438]         pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
[2439]         if (pr == NULL) {
[2440]             return NGX_ERROR;
[2441]         }
[2442] 
[2443]         pr->request = sr;
[2444]         pr->out = NULL;
[2445]         pr->next = NULL;
[2446] 
[2447]         if (r->postponed) {
[2448]             for (p = r->postponed; p->next; p = p->next) { /* void */ }
[2449]             p->next = pr;
[2450] 
[2451]         } else {
[2452]             r->postponed = pr;
[2453]         }
[2454]     }
[2455] 
[2456]     sr->internal = 1;
[2457] 
[2458]     sr->discard_body = r->discard_body;
[2459]     sr->expect_tested = 1;
[2460]     sr->main_filter_need_in_memory = r->main_filter_need_in_memory;
[2461] 
[2462]     sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
[2463]     sr->subrequests = r->subrequests - 1;
[2464] 
[2465]     tp = ngx_timeofday();
[2466]     sr->start_sec = tp->sec;
[2467]     sr->start_msec = tp->msec;
[2468] 
[2469]     r->main->count++;
[2470] 
[2471]     *psr = sr;
[2472] 
[2473]     if (flags & NGX_HTTP_SUBREQUEST_CLONE) {
[2474]         sr->method = r->method;
[2475]         sr->method_name = r->method_name;
[2476]         sr->loc_conf = r->loc_conf;
[2477]         sr->valid_location = r->valid_location;
[2478]         sr->valid_unparsed_uri = r->valid_unparsed_uri;
[2479]         sr->content_handler = r->content_handler;
[2480]         sr->phase_handler = r->phase_handler;
[2481]         sr->write_event_handler = ngx_http_core_run_phases;
[2482] 
[2483] #if (NGX_PCRE)
[2484]         sr->ncaptures = r->ncaptures;
[2485]         sr->captures = r->captures;
[2486]         sr->captures_data = r->captures_data;
[2487]         sr->realloc_captures = 1;
[2488]         r->realloc_captures = 1;
[2489] #endif
[2490] 
[2491]         ngx_http_update_location_config(sr);
[2492]     }
[2493] 
[2494]     return ngx_http_post_request(sr, NULL);
[2495] }
[2496] 
[2497] 
[2498] ngx_int_t
[2499] ngx_http_internal_redirect(ngx_http_request_t *r,
[2500]     ngx_str_t *uri, ngx_str_t *args)
[2501] {
[2502]     ngx_http_core_srv_conf_t  *cscf;
[2503] 
[2504]     r->uri_changes--;
[2505] 
[2506]     if (r->uri_changes == 0) {
[2507]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2508]                       "rewrite or internal redirection cycle "
[2509]                       "while internally redirecting to \"%V\"", uri);
[2510] 
[2511]         r->main->count++;
[2512]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2513]         return NGX_DONE;
[2514]     }
[2515] 
[2516]     r->uri = *uri;
[2517] 
[2518]     if (args) {
[2519]         r->args = *args;
[2520] 
[2521]     } else {
[2522]         ngx_str_null(&r->args);
[2523]     }
[2524] 
[2525]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2526]                    "internal redirect: \"%V?%V\"", uri, &r->args);
[2527] 
[2528]     ngx_http_set_exten(r);
[2529] 
[2530]     /* clear the modules contexts */
[2531]     ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
[2532] 
[2533]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[2534]     r->loc_conf = cscf->ctx->loc_conf;
[2535] 
[2536]     ngx_http_update_location_config(r);
[2537] 
[2538] #if (NGX_HTTP_CACHE)
[2539]     r->cache = NULL;
[2540] #endif
[2541] 
[2542]     r->internal = 1;
[2543]     r->valid_unparsed_uri = 0;
[2544]     r->add_uri_to_alias = 0;
[2545]     r->main->count++;
[2546] 
[2547]     ngx_http_handler(r);
[2548] 
[2549]     return NGX_DONE;
[2550] }
[2551] 
[2552] 
[2553] ngx_int_t
[2554] ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name)
[2555] {
[2556]     ngx_http_core_srv_conf_t    *cscf;
[2557]     ngx_http_core_loc_conf_t   **clcfp;
[2558]     ngx_http_core_main_conf_t   *cmcf;
[2559] 
[2560]     r->main->count++;
[2561]     r->uri_changes--;
[2562] 
[2563]     if (r->uri_changes == 0) {
[2564]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2565]                       "rewrite or internal redirection cycle "
[2566]                       "while redirect to named location \"%V\"", name);
[2567] 
[2568]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2569]         return NGX_DONE;
[2570]     }
[2571] 
[2572]     if (r->uri.len == 0) {
[2573]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2574]                       "empty URI in redirect to named location \"%V\"", name);
[2575] 
[2576]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2577]         return NGX_DONE;
[2578]     }
[2579] 
[2580]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[2581] 
[2582]     if (cscf->named_locations) {
[2583] 
[2584]         for (clcfp = cscf->named_locations; *clcfp; clcfp++) {
[2585] 
[2586]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2587]                            "test location: \"%V\"", &(*clcfp)->name);
[2588] 
[2589]             if (name->len != (*clcfp)->name.len
[2590]                 || ngx_strncmp(name->data, (*clcfp)->name.data, name->len) != 0)
[2591]             {
[2592]                 continue;
[2593]             }
[2594] 
[2595]             ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2596]                            "using location: %V \"%V?%V\"",
[2597]                            name, &r->uri, &r->args);
[2598] 
[2599]             r->internal = 1;
[2600]             r->content_handler = NULL;
[2601]             r->uri_changed = 0;
[2602]             r->loc_conf = (*clcfp)->loc_conf;
[2603] 
[2604]             /* clear the modules contexts */
[2605]             ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
[2606] 
[2607]             ngx_http_update_location_config(r);
[2608] 
[2609]             cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[2610] 
[2611]             r->phase_handler = cmcf->phase_engine.location_rewrite_index;
[2612] 
[2613]             r->write_event_handler = ngx_http_core_run_phases;
[2614]             ngx_http_core_run_phases(r);
[2615] 
[2616]             return NGX_DONE;
[2617]         }
[2618]     }
[2619] 
[2620]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2621]                   "could not find named location \"%V\"", name);
[2622] 
[2623]     ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2624] 
[2625]     return NGX_DONE;
[2626] }
[2627] 
[2628] 
[2629] ngx_http_cleanup_t *
[2630] ngx_http_cleanup_add(ngx_http_request_t *r, size_t size)
[2631] {
[2632]     ngx_http_cleanup_t  *cln;
[2633] 
[2634]     r = r->main;
[2635] 
[2636]     cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
[2637]     if (cln == NULL) {
[2638]         return NULL;
[2639]     }
[2640] 
[2641]     if (size) {
[2642]         cln->data = ngx_palloc(r->pool, size);
[2643]         if (cln->data == NULL) {
[2644]             return NULL;
[2645]         }
[2646] 
[2647]     } else {
[2648]         cln->data = NULL;
[2649]     }
[2650] 
[2651]     cln->handler = NULL;
[2652]     cln->next = r->cleanup;
[2653] 
[2654]     r->cleanup = cln;
[2655] 
[2656]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2657]                    "http cleanup add: %p", cln);
[2658] 
[2659]     return cln;
[2660] }
[2661] 
[2662] 
[2663] ngx_int_t
[2664] ngx_http_set_disable_symlinks(ngx_http_request_t *r,
[2665]     ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of)
[2666] {
[2667] #if (NGX_HAVE_OPENAT)
[2668]     u_char     *p;
[2669]     ngx_str_t   from;
[2670] 
[2671]     of->disable_symlinks = clcf->disable_symlinks;
[2672] 
[2673]     if (clcf->disable_symlinks_from == NULL) {
[2674]         return NGX_OK;
[2675]     }
[2676] 
[2677]     if (ngx_http_complex_value(r, clcf->disable_symlinks_from, &from)
[2678]         != NGX_OK)
[2679]     {
[2680]         return NGX_ERROR;
[2681]     }
[2682] 
[2683]     if (from.len == 0
[2684]         || from.len > path->len
[2685]         || ngx_memcmp(path->data, from.data, from.len) != 0)
[2686]     {
[2687]         return NGX_OK;
[2688]     }
[2689] 
[2690]     if (from.len == path->len) {
[2691]         of->disable_symlinks = NGX_DISABLE_SYMLINKS_OFF;
[2692]         return NGX_OK;
[2693]     }
[2694] 
[2695]     p = path->data + from.len;
[2696] 
[2697]     if (*p == '/') {
[2698]         of->disable_symlinks_from = from.len;
[2699]         return NGX_OK;
[2700]     }
[2701] 
[2702]     p--;
[2703] 
[2704]     if (*p == '/') {
[2705]         of->disable_symlinks_from = from.len - 1;
[2706]     }
[2707] #endif
[2708] 
[2709]     return NGX_OK;
[2710] }
[2711] 
[2712] 
[2713] ngx_int_t
[2714] ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
[2715]     ngx_table_elt_t *headers, ngx_str_t *value, ngx_array_t *proxies,
[2716]     int recursive)
[2717] {
[2718]     ngx_int_t         rc;
[2719]     ngx_uint_t        found;
[2720]     ngx_table_elt_t  *h, *next;
[2721] 
[2722]     if (headers == NULL) {
[2723]         return ngx_http_get_forwarded_addr_internal(r, addr, value->data,
[2724]                                                     value->len, proxies,
[2725]                                                     recursive);
[2726]     }
[2727] 
[2728]     /* revert headers order */
[2729] 
[2730]     for (h = headers, headers = NULL; h; h = next) {
[2731]         next = h->next;
[2732]         h->next = headers;
[2733]         headers = h;
[2734]     }
[2735] 
[2736]     /* iterate over all headers in reverse order */
[2737] 
[2738]     rc = NGX_DECLINED;
[2739] 
[2740]     found = 0;
[2741] 
[2742]     for (h = headers; h; h = h->next) {
[2743]         rc = ngx_http_get_forwarded_addr_internal(r, addr, h->value.data,
[2744]                                                   h->value.len, proxies,
[2745]                                                   recursive);
[2746] 
[2747]         if (!recursive) {
[2748]             break;
[2749]         }
[2750] 
[2751]         if (rc == NGX_DECLINED && found) {
[2752]             rc = NGX_DONE;
[2753]             break;
[2754]         }
[2755] 
[2756]         if (rc != NGX_OK) {
[2757]             break;
[2758]         }
[2759] 
[2760]         found = 1;
[2761]     }
[2762] 
[2763]     /* restore headers order */
[2764] 
[2765]     for (h = headers, headers = NULL; h; h = next) {
[2766]         next = h->next;
[2767]         h->next = headers;
[2768]         headers = h;
[2769]     }
[2770] 
[2771]     return rc;
[2772] }
[2773] 
[2774] 
[2775] static ngx_int_t
[2776] ngx_http_get_forwarded_addr_internal(ngx_http_request_t *r, ngx_addr_t *addr,
[2777]     u_char *xff, size_t xfflen, ngx_array_t *proxies, int recursive)
[2778] {
[2779]     u_char      *p;
[2780]     ngx_addr_t   paddr;
[2781]     ngx_uint_t   found;
[2782] 
[2783]     found = 0;
[2784] 
[2785]     do {
[2786] 
[2787]         if (ngx_cidr_match(addr->sockaddr, proxies) != NGX_OK) {
[2788]             return found ? NGX_DONE : NGX_DECLINED;
[2789]         }
[2790] 
[2791]         for (p = xff + xfflen - 1; p > xff; p--, xfflen--) {
[2792]             if (*p != ' ' && *p != ',') {
[2793]                 break;
[2794]             }
[2795]         }
[2796] 
[2797]         for ( /* void */ ; p > xff; p--) {
[2798]             if (*p == ' ' || *p == ',') {
[2799]                 p++;
[2800]                 break;
[2801]             }
[2802]         }
[2803] 
[2804]         if (ngx_parse_addr_port(r->pool, &paddr, p, xfflen - (p - xff))
[2805]             != NGX_OK)
[2806]         {
[2807]             return found ? NGX_DONE : NGX_DECLINED;
[2808]         }
[2809] 
[2810]         *addr = paddr;
[2811]         found = 1;
[2812]         xfflen = p - 1 - xff;
[2813] 
[2814]     } while (recursive && p > xff);
[2815] 
[2816]     return NGX_OK;
[2817] }
[2818] 
[2819] 
[2820] ngx_int_t
[2821] ngx_http_link_multi_headers(ngx_http_request_t *r)
[2822] {
[2823]     ngx_uint_t        i, j;
[2824]     ngx_list_part_t  *part, *ppart;
[2825]     ngx_table_elt_t  *header, *pheader, **ph;
[2826] 
[2827]     if (r->headers_in.multi_linked) {
[2828]         return NGX_OK;
[2829]     }
[2830] 
[2831]     r->headers_in.multi_linked = 1;
[2832] 
[2833]     part = &r->headers_in.headers.part;
[2834]     header = part->elts;
[2835] 
[2836]     for (i = 0; /* void */; i++) {
[2837] 
[2838]         if (i >= part->nelts) {
[2839]             if (part->next == NULL) {
[2840]                 break;
[2841]             }
[2842] 
[2843]             part = part->next;
[2844]             header = part->elts;
[2845]             i = 0;
[2846]         }
[2847] 
[2848]         header[i].next = NULL;
[2849] 
[2850]         /*
[2851]          * search for previous headers with the same name;
[2852]          * if there are any, link to them
[2853]          */
[2854] 
[2855]         ppart = &r->headers_in.headers.part;
[2856]         pheader = ppart->elts;
[2857] 
[2858]         for (j = 0; /* void */; j++) {
[2859] 
[2860]             if (j >= ppart->nelts) {
[2861]                 if (ppart->next == NULL) {
[2862]                     break;
[2863]                 }
[2864] 
[2865]                 ppart = ppart->next;
[2866]                 pheader = ppart->elts;
[2867]                 j = 0;
[2868]             }
[2869] 
[2870]             if (part == ppart && i == j) {
[2871]                 break;
[2872]             }
[2873] 
[2874]             if (header[i].key.len == pheader[j].key.len
[2875]                 && ngx_strncasecmp(header[i].key.data, pheader[j].key.data,
[2876]                                    header[i].key.len)
[2877]                    == 0)
[2878]             {
[2879]                 ph = &pheader[j].next;
[2880]                 while (*ph) { ph = &(*ph)->next; }
[2881]                 *ph = &header[i];
[2882] 
[2883]                 r->headers_in.multi = 1;
[2884] 
[2885]                 break;
[2886]             }
[2887]         }
[2888]     }
[2889] 
[2890]     return NGX_OK;
[2891] }
[2892] 
[2893] 
[2894] static char *
[2895] ngx_http_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
[2896] {
[2897]     char                        *rv;
[2898]     void                        *mconf;
[2899]     size_t                       len;
[2900]     u_char                      *p;
[2901]     ngx_uint_t                   i;
[2902]     ngx_conf_t                   pcf;
[2903]     ngx_http_module_t           *module;
[2904]     struct sockaddr_in          *sin;
[2905]     ngx_http_conf_ctx_t         *ctx, *http_ctx;
[2906]     ngx_http_listen_opt_t        lsopt;
[2907]     ngx_http_core_srv_conf_t    *cscf, **cscfp;
[2908]     ngx_http_core_main_conf_t   *cmcf;
[2909] 
[2910]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
[2911]     if (ctx == NULL) {
[2912]         return NGX_CONF_ERROR;
[2913]     }
[2914] 
[2915]     http_ctx = cf->ctx;
[2916]     ctx->main_conf = http_ctx->main_conf;
[2917] 
[2918]     /* the server{}'s srv_conf */
[2919] 
[2920]     ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[2921]     if (ctx->srv_conf == NULL) {
[2922]         return NGX_CONF_ERROR;
[2923]     }
[2924] 
[2925]     /* the server{}'s loc_conf */
[2926] 
[2927]     ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[2928]     if (ctx->loc_conf == NULL) {
[2929]         return NGX_CONF_ERROR;
[2930]     }
[2931] 
[2932]     for (i = 0; cf->cycle->modules[i]; i++) {
[2933]         if (cf->cycle->modules[i]->type != NGX_HTTP_MODULE) {
[2934]             continue;
[2935]         }
[2936] 
[2937]         module = cf->cycle->modules[i]->ctx;
[2938] 
[2939]         if (module->create_srv_conf) {
[2940]             mconf = module->create_srv_conf(cf);
[2941]             if (mconf == NULL) {
[2942]                 return NGX_CONF_ERROR;
[2943]             }
[2944] 
[2945]             ctx->srv_conf[cf->cycle->modules[i]->ctx_index] = mconf;
[2946]         }
[2947] 
[2948]         if (module->create_loc_conf) {
[2949]             mconf = module->create_loc_conf(cf);
[2950]             if (mconf == NULL) {
[2951]                 return NGX_CONF_ERROR;
[2952]             }
[2953] 
[2954]             ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
[2955]         }
[2956]     }
[2957] 
[2958] 
[2959]     /* the server configuration context */
[2960] 
[2961]     cscf = ctx->srv_conf[ngx_http_core_module.ctx_index];
[2962]     cscf->ctx = ctx;
[2963] 
[2964] 
[2965]     cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
[2966] 
[2967]     cscfp = ngx_array_push(&cmcf->servers);
[2968]     if (cscfp == NULL) {
[2969]         return NGX_CONF_ERROR;
[2970]     }
[2971] 
[2972]     *cscfp = cscf;
[2973] 
[2974] 
[2975]     /* parse inside server{} */
[2976] 
[2977]     pcf = *cf;
[2978]     cf->ctx = ctx;
[2979]     cf->cmd_type = NGX_HTTP_SRV_CONF;
[2980] 
[2981]     rv = ngx_conf_parse(cf, NULL);
[2982] 
[2983]     *cf = pcf;
[2984] 
[2985]     if (rv == NGX_CONF_OK && !cscf->listen) {
[2986]         ngx_memzero(&lsopt, sizeof(ngx_http_listen_opt_t));
[2987] 
[2988]         p = ngx_pcalloc(cf->pool, sizeof(struct sockaddr_in));
[2989]         if (p == NULL) {
[2990]             return NGX_CONF_ERROR;
[2991]         }
[2992] 
[2993]         lsopt.sockaddr = (struct sockaddr *) p;
[2994] 
[2995]         sin = (struct sockaddr_in *) p;
[2996] 
[2997]         sin->sin_family = AF_INET;
[2998] #if (NGX_WIN32)
[2999]         sin->sin_port = htons(80);
[3000] #else
[3001]         sin->sin_port = htons((getuid() == 0) ? 80 : 8000);
[3002] #endif
[3003]         sin->sin_addr.s_addr = INADDR_ANY;
[3004] 
[3005]         lsopt.socklen = sizeof(struct sockaddr_in);
[3006] 
[3007]         lsopt.backlog = NGX_LISTEN_BACKLOG;
[3008]         lsopt.rcvbuf = -1;
[3009]         lsopt.sndbuf = -1;
[3010] #if (NGX_HAVE_SETFIB)
[3011]         lsopt.setfib = -1;
[3012] #endif
[3013] #if (NGX_HAVE_TCP_FASTOPEN)
[3014]         lsopt.fastopen = -1;
[3015] #endif
[3016]         lsopt.wildcard = 1;
[3017] 
[3018]         len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
[3019] 
[3020]         p = ngx_pnalloc(cf->pool, len);
[3021]         if (p == NULL) {
[3022]             return NGX_CONF_ERROR;
[3023]         }
[3024] 
[3025]         lsopt.addr_text.data = p;
[3026]         lsopt.addr_text.len = ngx_sock_ntop(lsopt.sockaddr, lsopt.socklen, p,
[3027]                                             len, 1);
[3028] 
[3029]         if (ngx_http_add_listen(cf, cscf, &lsopt) != NGX_OK) {
[3030]             return NGX_CONF_ERROR;
[3031]         }
[3032]     }
[3033] 
[3034]     return rv;
[3035] }
[3036] 
[3037] 
[3038] static char *
[3039] ngx_http_core_location(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
[3040] {
[3041]     char                      *rv;
[3042]     u_char                    *mod;
[3043]     size_t                     len;
[3044]     ngx_str_t                 *value, *name;
[3045]     ngx_uint_t                 i;
[3046]     ngx_conf_t                 save;
[3047]     ngx_http_module_t         *module;
[3048]     ngx_http_conf_ctx_t       *ctx, *pctx;
[3049]     ngx_http_core_loc_conf_t  *clcf, *pclcf;
[3050] 
[3051]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
[3052]     if (ctx == NULL) {
[3053]         return NGX_CONF_ERROR;
[3054]     }
[3055] 
[3056]     pctx = cf->ctx;
[3057]     ctx->main_conf = pctx->main_conf;
[3058]     ctx->srv_conf = pctx->srv_conf;
[3059] 
[3060]     ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[3061]     if (ctx->loc_conf == NULL) {
[3062]         return NGX_CONF_ERROR;
[3063]     }
[3064] 
[3065]     for (i = 0; cf->cycle->modules[i]; i++) {
[3066]         if (cf->cycle->modules[i]->type != NGX_HTTP_MODULE) {
[3067]             continue;
[3068]         }
[3069] 
[3070]         module = cf->cycle->modules[i]->ctx;
[3071] 
[3072]         if (module->create_loc_conf) {
[3073]             ctx->loc_conf[cf->cycle->modules[i]->ctx_index] =
[3074]                                                    module->create_loc_conf(cf);
[3075]             if (ctx->loc_conf[cf->cycle->modules[i]->ctx_index] == NULL) {
[3076]                 return NGX_CONF_ERROR;
[3077]             }
[3078]         }
[3079]     }
[3080] 
[3081]     clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
[3082]     clcf->loc_conf = ctx->loc_conf;
[3083] 
[3084]     value = cf->args->elts;
[3085] 
[3086]     if (cf->args->nelts == 3) {
[3087] 
[3088]         len = value[1].len;
[3089]         mod = value[1].data;
[3090]         name = &value[2];
[3091] 
[3092]         if (len == 1 && mod[0] == '=') {
[3093] 
[3094]             clcf->name = *name;
[3095]             clcf->exact_match = 1;
[3096] 
[3097]         } else if (len == 2 && mod[0] == '^' && mod[1] == '~') {
[3098] 
[3099]             clcf->name = *name;
[3100]             clcf->noregex = 1;
[3101] 
[3102]         } else if (len == 1 && mod[0] == '~') {
[3103] 
[3104]             if (ngx_http_core_regex_location(cf, clcf, name, 0) != NGX_OK) {
[3105]                 return NGX_CONF_ERROR;
[3106]             }
[3107] 
[3108]         } else if (len == 2 && mod[0] == '~' && mod[1] == '*') {
[3109] 
[3110]             if (ngx_http_core_regex_location(cf, clcf, name, 1) != NGX_OK) {
[3111]                 return NGX_CONF_ERROR;
[3112]             }
[3113] 
[3114]         } else {
[3115]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3116]                                "invalid location modifier \"%V\"", &value[1]);
[3117]             return NGX_CONF_ERROR;
[3118]         }
[3119] 
[3120]     } else {
[3121] 
[3122]         name = &value[1];
[3123] 
[3124]         if (name->data[0] == '=') {
[3125] 
[3126]             clcf->name.len = name->len - 1;
[3127]             clcf->name.data = name->data + 1;
[3128]             clcf->exact_match = 1;
[3129] 
[3130]         } else if (name->data[0] == '^' && name->data[1] == '~') {
[3131] 
[3132]             clcf->name.len = name->len - 2;
[3133]             clcf->name.data = name->data + 2;
[3134]             clcf->noregex = 1;
[3135] 
[3136]         } else if (name->data[0] == '~') {
[3137] 
[3138]             name->len--;
[3139]             name->data++;
[3140] 
[3141]             if (name->data[0] == '*') {
[3142] 
[3143]                 name->len--;
[3144]                 name->data++;
[3145] 
[3146]                 if (ngx_http_core_regex_location(cf, clcf, name, 1) != NGX_OK) {
[3147]                     return NGX_CONF_ERROR;
[3148]                 }
[3149] 
[3150]             } else {
[3151]                 if (ngx_http_core_regex_location(cf, clcf, name, 0) != NGX_OK) {
[3152]                     return NGX_CONF_ERROR;
[3153]                 }
[3154]             }
[3155] 
[3156]         } else {
[3157] 
[3158]             clcf->name = *name;
[3159] 
[3160]             if (name->data[0] == '@') {
[3161]                 clcf->named = 1;
[3162]             }
[3163]         }
[3164]     }
[3165] 
[3166]     pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];
[3167] 
[3168]     if (cf->cmd_type == NGX_HTTP_LOC_CONF) {
[3169] 
[3170]         /* nested location */
[3171] 
[3172] #if 0
[3173]         clcf->prev_location = pclcf;
[3174] #endif
[3175] 
[3176]         if (pclcf->exact_match) {
[3177]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3178]                                "location \"%V\" cannot be inside "
[3179]                                "the exact location \"%V\"",
[3180]                                &clcf->name, &pclcf->name);
[3181]             return NGX_CONF_ERROR;
[3182]         }
[3183] 
[3184]         if (pclcf->named) {
[3185]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3186]                                "location \"%V\" cannot be inside "
[3187]                                "the named location \"%V\"",
[3188]                                &clcf->name, &pclcf->name);
[3189]             return NGX_CONF_ERROR;
[3190]         }
[3191] 
[3192]         if (clcf->named) {
[3193]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3194]                                "named location \"%V\" can be "
[3195]                                "on the server level only",
[3196]                                &clcf->name);
[3197]             return NGX_CONF_ERROR;
[3198]         }
[3199] 
[3200]         len = pclcf->name.len;
[3201] 
[3202] #if (NGX_PCRE)
[3203]         if (clcf->regex == NULL
[3204]             && ngx_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0)
[3205] #else
[3206]         if (ngx_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0)
[3207] #endif
[3208]         {
[3209]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3210]                                "location \"%V\" is outside location \"%V\"",
[3211]                                &clcf->name, &pclcf->name);
[3212]             return NGX_CONF_ERROR;
[3213]         }
[3214]     }
[3215] 
[3216]     if (ngx_http_add_location(cf, &pclcf->locations, clcf) != NGX_OK) {
[3217]         return NGX_CONF_ERROR;
[3218]     }
[3219] 
[3220]     save = *cf;
[3221]     cf->ctx = ctx;
[3222]     cf->cmd_type = NGX_HTTP_LOC_CONF;
[3223] 
[3224]     rv = ngx_conf_parse(cf, NULL);
[3225] 
[3226]     *cf = save;
[3227] 
[3228]     return rv;
[3229] }
[3230] 
[3231] 
[3232] static ngx_int_t
[3233] ngx_http_core_regex_location(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf,
[3234]     ngx_str_t *regex, ngx_uint_t caseless)
[3235] {
[3236] #if (NGX_PCRE)
[3237]     ngx_regex_compile_t  rc;
[3238]     u_char               errstr[NGX_MAX_CONF_ERRSTR];
[3239] 
[3240]     ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[3241] 
[3242]     rc.pattern = *regex;
[3243]     rc.err.len = NGX_MAX_CONF_ERRSTR;
[3244]     rc.err.data = errstr;
[3245] 
[3246] #if (NGX_HAVE_CASELESS_FILESYSTEM)
[3247]     rc.options = NGX_REGEX_CASELESS;
[3248] #else
[3249]     rc.options = caseless ? NGX_REGEX_CASELESS : 0;
[3250] #endif
[3251] 
[3252]     clcf->regex = ngx_http_regex_compile(cf, &rc);
[3253]     if (clcf->regex == NULL) {
[3254]         return NGX_ERROR;
[3255]     }
[3256] 
[3257]     clcf->name = *regex;
[3258] 
[3259]     return NGX_OK;
[3260] 
[3261] #else
[3262] 
[3263]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3264]                        "using regex \"%V\" requires PCRE library",
[3265]                        regex);
[3266]     return NGX_ERROR;
[3267] 
[3268] #endif
[3269] }
[3270] 
[3271] 
[3272] static char *
[3273] ngx_http_core_types(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3274] {
[3275]     ngx_http_core_loc_conf_t *clcf = conf;
[3276] 
[3277]     char        *rv;
[3278]     ngx_conf_t   save;
[3279] 
[3280]     if (clcf->types == NULL) {
[3281]         clcf->types = ngx_array_create(cf->pool, 64, sizeof(ngx_hash_key_t));
[3282]         if (clcf->types == NULL) {
[3283]             return NGX_CONF_ERROR;
[3284]         }
[3285]     }
[3286] 
[3287]     save = *cf;
[3288]     cf->handler = ngx_http_core_type;
[3289]     cf->handler_conf = conf;
[3290] 
[3291]     rv = ngx_conf_parse(cf, NULL);
[3292] 
[3293]     *cf = save;
[3294] 
[3295]     return rv;
[3296] }
[3297] 
[3298] 
[3299] static char *
[3300] ngx_http_core_type(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[3301] {
[3302]     ngx_http_core_loc_conf_t *clcf = conf;
[3303] 
[3304]     ngx_str_t       *value, *content_type, *old;
[3305]     ngx_uint_t       i, n, hash;
[3306]     ngx_hash_key_t  *type;
[3307] 
[3308]     value = cf->args->elts;
[3309] 
[3310]     if (ngx_strcmp(value[0].data, "include") == 0) {
[3311]         if (cf->args->nelts != 2) {
[3312]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3313]                                "invalid number of arguments"
[3314]                                " in \"include\" directive");
[3315]             return NGX_CONF_ERROR;
[3316]         }
[3317] 
[3318]         return ngx_conf_include(cf, dummy, conf);
[3319]     }
[3320] 
[3321]     content_type = ngx_palloc(cf->pool, sizeof(ngx_str_t));
[3322]     if (content_type == NULL) {
[3323]         return NGX_CONF_ERROR;
[3324]     }
[3325] 
[3326]     *content_type = value[0];
[3327] 
[3328]     for (i = 1; i < cf->args->nelts; i++) {
[3329] 
[3330]         hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);
[3331] 
[3332]         type = clcf->types->elts;
[3333]         for (n = 0; n < clcf->types->nelts; n++) {
[3334]             if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
[3335]                 old = type[n].value;
[3336]                 type[n].value = content_type;
[3337] 
[3338]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[3339]                                    "duplicate extension \"%V\", "
[3340]                                    "content type: \"%V\", "
[3341]                                    "previous content type: \"%V\"",
[3342]                                    &value[i], content_type, old);
[3343]                 goto next;
[3344]             }
[3345]         }
[3346] 
[3347] 
[3348]         type = ngx_array_push(clcf->types);
[3349]         if (type == NULL) {
[3350]             return NGX_CONF_ERROR;
[3351]         }
[3352] 
[3353]         type->key = value[i];
[3354]         type->key_hash = hash;
[3355]         type->value = content_type;
[3356] 
[3357]     next:
[3358]         continue;
[3359]     }
[3360] 
[3361]     return NGX_CONF_OK;
[3362] }
[3363] 
[3364] 
[3365] static ngx_int_t
[3366] ngx_http_core_preconfiguration(ngx_conf_t *cf)
[3367] {
[3368]     return ngx_http_variables_add_core_vars(cf);
[3369] }
[3370] 
[3371] 
[3372] static ngx_int_t
[3373] ngx_http_core_postconfiguration(ngx_conf_t *cf)
[3374] {
[3375]     ngx_http_top_request_body_filter = ngx_http_request_body_save_filter;
[3376] 
[3377]     return NGX_OK;
[3378] }
[3379] 
[3380] 
[3381] static void *
[3382] ngx_http_core_create_main_conf(ngx_conf_t *cf)
[3383] {
[3384]     ngx_http_core_main_conf_t  *cmcf;
[3385] 
[3386]     cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_main_conf_t));
[3387]     if (cmcf == NULL) {
[3388]         return NULL;
[3389]     }
[3390] 
[3391]     if (ngx_array_init(&cmcf->servers, cf->pool, 4,
[3392]                        sizeof(ngx_http_core_srv_conf_t *))
[3393]         != NGX_OK)
[3394]     {
[3395]         return NULL;
[3396]     }
[3397] 
[3398]     cmcf->server_names_hash_max_size = NGX_CONF_UNSET_UINT;
[3399]     cmcf->server_names_hash_bucket_size = NGX_CONF_UNSET_UINT;
[3400] 
[3401]     cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
[3402]     cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;
[3403] 
[3404]     return cmcf;
[3405] }
[3406] 
[3407] 
[3408] static char *
[3409] ngx_http_core_init_main_conf(ngx_conf_t *cf, void *conf)
[3410] {
[3411]     ngx_http_core_main_conf_t *cmcf = conf;
[3412] 
[3413]     ngx_conf_init_uint_value(cmcf->server_names_hash_max_size, 512);
[3414]     ngx_conf_init_uint_value(cmcf->server_names_hash_bucket_size,
[3415]                              ngx_cacheline_size);
[3416] 
[3417]     cmcf->server_names_hash_bucket_size =
[3418]             ngx_align(cmcf->server_names_hash_bucket_size, ngx_cacheline_size);
[3419] 
[3420] 
[3421]     ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
[3422]     ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);
[3423] 
[3424]     cmcf->variables_hash_bucket_size =
[3425]                ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);
[3426] 
[3427]     if (cmcf->ncaptures) {
[3428]         cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
[3429]     }
[3430] 
[3431]     return NGX_CONF_OK;
[3432] }
[3433] 
[3434] 
[3435] static void *
[3436] ngx_http_core_create_srv_conf(ngx_conf_t *cf)
[3437] {
[3438]     ngx_http_core_srv_conf_t  *cscf;
[3439] 
[3440]     cscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_srv_conf_t));
[3441]     if (cscf == NULL) {
[3442]         return NULL;
[3443]     }
[3444] 
[3445]     /*
[3446]      * set by ngx_pcalloc():
[3447]      *
[3448]      *     conf->client_large_buffers.num = 0;
[3449]      */
[3450] 
[3451]     if (ngx_array_init(&cscf->server_names, cf->temp_pool, 4,
[3452]                        sizeof(ngx_http_server_name_t))
[3453]         != NGX_OK)
[3454]     {
[3455]         return NULL;
[3456]     }
[3457] 
[3458]     cscf->connection_pool_size = NGX_CONF_UNSET_SIZE;
[3459]     cscf->request_pool_size = NGX_CONF_UNSET_SIZE;
[3460]     cscf->client_header_timeout = NGX_CONF_UNSET_MSEC;
[3461]     cscf->client_header_buffer_size = NGX_CONF_UNSET_SIZE;
[3462]     cscf->ignore_invalid_headers = NGX_CONF_UNSET;
[3463]     cscf->merge_slashes = NGX_CONF_UNSET;
[3464]     cscf->underscores_in_headers = NGX_CONF_UNSET;
[3465] 
[3466]     cscf->file_name = cf->conf_file->file.name.data;
[3467]     cscf->line = cf->conf_file->line;
[3468] 
[3469]     return cscf;
[3470] }
[3471] 
[3472] 
[3473] static char *
[3474] ngx_http_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[3475] {
[3476]     ngx_http_core_srv_conf_t *prev = parent;
[3477]     ngx_http_core_srv_conf_t *conf = child;
[3478] 
[3479]     ngx_str_t                name;
[3480]     ngx_http_server_name_t  *sn;
[3481] 
[3482]     /* TODO: it does not merge, it inits only */
[3483] 
[3484]     ngx_conf_merge_size_value(conf->connection_pool_size,
[3485]                               prev->connection_pool_size, 64 * sizeof(void *));
[3486]     ngx_conf_merge_size_value(conf->request_pool_size,
[3487]                               prev->request_pool_size, 4096);
[3488]     ngx_conf_merge_msec_value(conf->client_header_timeout,
[3489]                               prev->client_header_timeout, 60000);
[3490]     ngx_conf_merge_size_value(conf->client_header_buffer_size,
[3491]                               prev->client_header_buffer_size, 1024);
[3492]     ngx_conf_merge_bufs_value(conf->large_client_header_buffers,
[3493]                               prev->large_client_header_buffers,
[3494]                               4, 8192);
[3495] 
[3496]     if (conf->large_client_header_buffers.size < conf->connection_pool_size) {
[3497]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3498]                            "the \"large_client_header_buffers\" size must be "
[3499]                            "equal to or greater than \"connection_pool_size\"");
[3500]         return NGX_CONF_ERROR;
[3501]     }
[3502] 
[3503]     ngx_conf_merge_value(conf->ignore_invalid_headers,
[3504]                               prev->ignore_invalid_headers, 1);
[3505] 
[3506]     ngx_conf_merge_value(conf->merge_slashes, prev->merge_slashes, 1);
[3507] 
[3508]     ngx_conf_merge_value(conf->underscores_in_headers,
[3509]                               prev->underscores_in_headers, 0);
[3510] 
[3511]     if (conf->server_names.nelts == 0) {
[3512]         /* the array has 4 empty preallocated elements, so push cannot fail */
[3513]         sn = ngx_array_push(&conf->server_names);
[3514] #if (NGX_PCRE)
[3515]         sn->regex = NULL;
[3516] #endif
[3517]         sn->server = conf;
[3518]         ngx_str_set(&sn->name, "");
[3519]     }
[3520] 
[3521]     sn = conf->server_names.elts;
[3522]     name = sn[0].name;
[3523] 
[3524] #if (NGX_PCRE)
[3525]     if (sn->regex) {
[3526]         name.len++;
[3527]         name.data--;
[3528]     } else
[3529] #endif
[3530] 
[3531]     if (name.data[0] == '.') {
[3532]         name.len--;
[3533]         name.data++;
[3534]     }
[3535] 
[3536]     conf->server_name.len = name.len;
[3537]     conf->server_name.data = ngx_pstrdup(cf->pool, &name);
[3538]     if (conf->server_name.data == NULL) {
[3539]         return NGX_CONF_ERROR;
[3540]     }
[3541] 
[3542]     return NGX_CONF_OK;
[3543] }
[3544] 
[3545] 
[3546] static void *
[3547] ngx_http_core_create_loc_conf(ngx_conf_t *cf)
[3548] {
[3549]     ngx_http_core_loc_conf_t  *clcf;
[3550] 
[3551]     clcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_core_loc_conf_t));
[3552]     if (clcf == NULL) {
[3553]         return NULL;
[3554]     }
[3555] 
[3556]     /*
[3557]      * set by ngx_pcalloc():
[3558]      *
[3559]      *     clcf->escaped_name = { 0, NULL };
[3560]      *     clcf->root = { 0, NULL };
[3561]      *     clcf->limit_except = 0;
[3562]      *     clcf->post_action = { 0, NULL };
[3563]      *     clcf->types = NULL;
[3564]      *     clcf->default_type = { 0, NULL };
[3565]      *     clcf->error_log = NULL;
[3566]      *     clcf->error_pages = NULL;
[3567]      *     clcf->client_body_path = NULL;
[3568]      *     clcf->regex = NULL;
[3569]      *     clcf->exact_match = 0;
[3570]      *     clcf->auto_redirect = 0;
[3571]      *     clcf->alias = 0;
[3572]      *     clcf->gzip_proxied = 0;
[3573]      *     clcf->keepalive_disable = 0;
[3574]      */
[3575] 
[3576]     clcf->client_max_body_size = NGX_CONF_UNSET;
[3577]     clcf->client_body_buffer_size = NGX_CONF_UNSET_SIZE;
[3578]     clcf->client_body_timeout = NGX_CONF_UNSET_MSEC;
[3579]     clcf->satisfy = NGX_CONF_UNSET_UINT;
[3580]     clcf->auth_delay = NGX_CONF_UNSET_MSEC;
[3581]     clcf->if_modified_since = NGX_CONF_UNSET_UINT;
[3582]     clcf->max_ranges = NGX_CONF_UNSET_UINT;
[3583]     clcf->client_body_in_file_only = NGX_CONF_UNSET_UINT;
[3584]     clcf->client_body_in_single_buffer = NGX_CONF_UNSET;
[3585]     clcf->internal = NGX_CONF_UNSET;
[3586]     clcf->sendfile = NGX_CONF_UNSET;
[3587]     clcf->sendfile_max_chunk = NGX_CONF_UNSET_SIZE;
[3588]     clcf->subrequest_output_buffer_size = NGX_CONF_UNSET_SIZE;
[3589]     clcf->aio = NGX_CONF_UNSET;
[3590]     clcf->aio_write = NGX_CONF_UNSET;
[3591] #if (NGX_THREADS)
[3592]     clcf->thread_pool = NGX_CONF_UNSET_PTR;
[3593]     clcf->thread_pool_value = NGX_CONF_UNSET_PTR;
[3594] #endif
[3595]     clcf->read_ahead = NGX_CONF_UNSET_SIZE;
[3596]     clcf->directio = NGX_CONF_UNSET;
[3597]     clcf->directio_alignment = NGX_CONF_UNSET;
[3598]     clcf->tcp_nopush = NGX_CONF_UNSET;
[3599]     clcf->tcp_nodelay = NGX_CONF_UNSET;
[3600]     clcf->send_timeout = NGX_CONF_UNSET_MSEC;
[3601]     clcf->send_lowat = NGX_CONF_UNSET_SIZE;
[3602]     clcf->postpone_output = NGX_CONF_UNSET_SIZE;
[3603]     clcf->limit_rate = NGX_CONF_UNSET_PTR;
[3604]     clcf->limit_rate_after = NGX_CONF_UNSET_PTR;
[3605]     clcf->keepalive_time = NGX_CONF_UNSET_MSEC;
[3606]     clcf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
[3607]     clcf->keepalive_header = NGX_CONF_UNSET;
[3608]     clcf->keepalive_requests = NGX_CONF_UNSET_UINT;
[3609]     clcf->lingering_close = NGX_CONF_UNSET_UINT;
[3610]     clcf->lingering_time = NGX_CONF_UNSET_MSEC;
[3611]     clcf->lingering_timeout = NGX_CONF_UNSET_MSEC;
[3612]     clcf->resolver_timeout = NGX_CONF_UNSET_MSEC;
[3613]     clcf->reset_timedout_connection = NGX_CONF_UNSET;
[3614]     clcf->absolute_redirect = NGX_CONF_UNSET;
[3615]     clcf->server_name_in_redirect = NGX_CONF_UNSET;
[3616]     clcf->port_in_redirect = NGX_CONF_UNSET;
[3617]     clcf->msie_padding = NGX_CONF_UNSET;
[3618]     clcf->msie_refresh = NGX_CONF_UNSET;
[3619]     clcf->log_not_found = NGX_CONF_UNSET;
[3620]     clcf->log_subrequest = NGX_CONF_UNSET;
[3621]     clcf->recursive_error_pages = NGX_CONF_UNSET;
[3622]     clcf->chunked_transfer_encoding = NGX_CONF_UNSET;
[3623]     clcf->etag = NGX_CONF_UNSET;
[3624]     clcf->server_tokens = NGX_CONF_UNSET_UINT;
[3625]     clcf->types_hash_max_size = NGX_CONF_UNSET_UINT;
[3626]     clcf->types_hash_bucket_size = NGX_CONF_UNSET_UINT;
[3627] 
[3628]     clcf->open_file_cache = NGX_CONF_UNSET_PTR;
[3629]     clcf->open_file_cache_valid = NGX_CONF_UNSET;
[3630]     clcf->open_file_cache_min_uses = NGX_CONF_UNSET_UINT;
[3631]     clcf->open_file_cache_errors = NGX_CONF_UNSET;
[3632]     clcf->open_file_cache_events = NGX_CONF_UNSET;
[3633] 
[3634] #if (NGX_HTTP_GZIP)
[3635]     clcf->gzip_vary = NGX_CONF_UNSET;
[3636]     clcf->gzip_http_version = NGX_CONF_UNSET_UINT;
[3637] #if (NGX_PCRE)
[3638]     clcf->gzip_disable = NGX_CONF_UNSET_PTR;
[3639] #endif
[3640]     clcf->gzip_disable_msie6 = 3;
[3641] #if (NGX_HTTP_DEGRADATION)
[3642]     clcf->gzip_disable_degradation = 3;
[3643] #endif
[3644] #endif
[3645] 
[3646] #if (NGX_HAVE_OPENAT)
[3647]     clcf->disable_symlinks = NGX_CONF_UNSET_UINT;
[3648]     clcf->disable_symlinks_from = NGX_CONF_UNSET_PTR;
[3649] #endif
[3650] 
[3651]     return clcf;
[3652] }
[3653] 
[3654] 
[3655] static ngx_str_t  ngx_http_core_text_html_type = ngx_string("text/html");
[3656] static ngx_str_t  ngx_http_core_image_gif_type = ngx_string("image/gif");
[3657] static ngx_str_t  ngx_http_core_image_jpeg_type = ngx_string("image/jpeg");
[3658] 
[3659] static ngx_hash_key_t  ngx_http_core_default_types[] = {
[3660]     { ngx_string("html"), 0, &ngx_http_core_text_html_type },
[3661]     { ngx_string("gif"), 0, &ngx_http_core_image_gif_type },
[3662]     { ngx_string("jpg"), 0, &ngx_http_core_image_jpeg_type },
[3663]     { ngx_null_string, 0, NULL }
[3664] };
[3665] 
[3666] 
[3667] static char *
[3668] ngx_http_core_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[3669] {
[3670]     ngx_http_core_loc_conf_t *prev = parent;
[3671]     ngx_http_core_loc_conf_t *conf = child;
[3672] 
[3673]     ngx_uint_t        i;
[3674]     ngx_hash_key_t   *type;
[3675]     ngx_hash_init_t   types_hash;
[3676] 
[3677]     if (conf->root.data == NULL) {
[3678] 
[3679]         conf->alias = prev->alias;
[3680]         conf->root = prev->root;
[3681]         conf->root_lengths = prev->root_lengths;
[3682]         conf->root_values = prev->root_values;
[3683] 
[3684]         if (prev->root.data == NULL) {
[3685]             ngx_str_set(&conf->root, "html");
[3686] 
[3687]             if (ngx_conf_full_name(cf->cycle, &conf->root, 0) != NGX_OK) {
[3688]                 return NGX_CONF_ERROR;
[3689]             }
[3690]         }
[3691]     }
[3692] 
[3693]     if (conf->post_action.data == NULL) {
[3694]         conf->post_action = prev->post_action;
[3695]     }
[3696] 
[3697]     ngx_conf_merge_uint_value(conf->types_hash_max_size,
[3698]                               prev->types_hash_max_size, 1024);
[3699] 
[3700]     ngx_conf_merge_uint_value(conf->types_hash_bucket_size,
[3701]                               prev->types_hash_bucket_size, 64);
[3702] 
[3703]     conf->types_hash_bucket_size = ngx_align(conf->types_hash_bucket_size,
[3704]                                              ngx_cacheline_size);
[3705] 
[3706]     /*
[3707]      * the special handling of the "types" directive in the "http" section
[3708]      * to inherit the http's conf->types_hash to all servers
[3709]      */
[3710] 
[3711]     if (prev->types && prev->types_hash.buckets == NULL) {
[3712] 
[3713]         types_hash.hash = &prev->types_hash;
[3714]         types_hash.key = ngx_hash_key_lc;
[3715]         types_hash.max_size = conf->types_hash_max_size;
[3716]         types_hash.bucket_size = conf->types_hash_bucket_size;
[3717]         types_hash.name = "types_hash";
[3718]         types_hash.pool = cf->pool;
[3719]         types_hash.temp_pool = NULL;
[3720] 
[3721]         if (ngx_hash_init(&types_hash, prev->types->elts, prev->types->nelts)
[3722]             != NGX_OK)
[3723]         {
[3724]             return NGX_CONF_ERROR;
[3725]         }
[3726]     }
[3727] 
[3728]     if (conf->types == NULL) {
[3729]         conf->types = prev->types;
[3730]         conf->types_hash = prev->types_hash;
[3731]     }
[3732] 
[3733]     if (conf->types == NULL) {
[3734]         conf->types = ngx_array_create(cf->pool, 3, sizeof(ngx_hash_key_t));
[3735]         if (conf->types == NULL) {
[3736]             return NGX_CONF_ERROR;
[3737]         }
[3738] 
[3739]         for (i = 0; ngx_http_core_default_types[i].key.len; i++) {
[3740]             type = ngx_array_push(conf->types);
[3741]             if (type == NULL) {
[3742]                 return NGX_CONF_ERROR;
[3743]             }
[3744] 
[3745]             type->key = ngx_http_core_default_types[i].key;
[3746]             type->key_hash =
[3747]                        ngx_hash_key_lc(ngx_http_core_default_types[i].key.data,
[3748]                                        ngx_http_core_default_types[i].key.len);
[3749]             type->value = ngx_http_core_default_types[i].value;
[3750]         }
[3751]     }
[3752] 
[3753]     if (conf->types_hash.buckets == NULL) {
[3754] 
[3755]         types_hash.hash = &conf->types_hash;
[3756]         types_hash.key = ngx_hash_key_lc;
[3757]         types_hash.max_size = conf->types_hash_max_size;
[3758]         types_hash.bucket_size = conf->types_hash_bucket_size;
[3759]         types_hash.name = "types_hash";
[3760]         types_hash.pool = cf->pool;
[3761]         types_hash.temp_pool = NULL;
[3762] 
[3763]         if (ngx_hash_init(&types_hash, conf->types->elts, conf->types->nelts)
[3764]             != NGX_OK)
[3765]         {
[3766]             return NGX_CONF_ERROR;
[3767]         }
[3768]     }
[3769] 
[3770]     if (conf->error_log == NULL) {
[3771]         if (prev->error_log) {
[3772]             conf->error_log = prev->error_log;
[3773]         } else {
[3774]             conf->error_log = &cf->cycle->new_log;
[3775]         }
[3776]     }
[3777] 
[3778]     if (conf->error_pages == NULL && prev->error_pages) {
[3779]         conf->error_pages = prev->error_pages;
[3780]     }
[3781] 
[3782]     ngx_conf_merge_str_value(conf->default_type,
[3783]                               prev->default_type, "text/plain");
[3784] 
[3785]     ngx_conf_merge_off_value(conf->client_max_body_size,
[3786]                               prev->client_max_body_size, 1 * 1024 * 1024);
[3787]     ngx_conf_merge_size_value(conf->client_body_buffer_size,
[3788]                               prev->client_body_buffer_size,
[3789]                               (size_t) 2 * ngx_pagesize);
[3790]     ngx_conf_merge_msec_value(conf->client_body_timeout,
[3791]                               prev->client_body_timeout, 60000);
[3792] 
[3793]     ngx_conf_merge_bitmask_value(conf->keepalive_disable,
[3794]                               prev->keepalive_disable,
[3795]                               (NGX_CONF_BITMASK_SET
[3796]                                |NGX_HTTP_KEEPALIVE_DISABLE_MSIE6));
[3797]     ngx_conf_merge_uint_value(conf->satisfy, prev->satisfy,
[3798]                               NGX_HTTP_SATISFY_ALL);
[3799]     ngx_conf_merge_msec_value(conf->auth_delay, prev->auth_delay, 0);
[3800]     ngx_conf_merge_uint_value(conf->if_modified_since, prev->if_modified_since,
[3801]                               NGX_HTTP_IMS_EXACT);
[3802]     ngx_conf_merge_uint_value(conf->max_ranges, prev->max_ranges,
[3803]                               NGX_MAX_INT32_VALUE);
[3804]     ngx_conf_merge_uint_value(conf->client_body_in_file_only,
[3805]                               prev->client_body_in_file_only,
[3806]                               NGX_HTTP_REQUEST_BODY_FILE_OFF);
[3807]     ngx_conf_merge_value(conf->client_body_in_single_buffer,
[3808]                               prev->client_body_in_single_buffer, 0);
[3809]     ngx_conf_merge_value(conf->internal, prev->internal, 0);
[3810]     ngx_conf_merge_value(conf->sendfile, prev->sendfile, 0);
[3811]     ngx_conf_merge_size_value(conf->sendfile_max_chunk,
[3812]                               prev->sendfile_max_chunk, 2 * 1024 * 1024);
[3813]     ngx_conf_merge_size_value(conf->subrequest_output_buffer_size,
[3814]                               prev->subrequest_output_buffer_size,
[3815]                               (size_t) ngx_pagesize);
[3816]     ngx_conf_merge_value(conf->aio, prev->aio, NGX_HTTP_AIO_OFF);
[3817]     ngx_conf_merge_value(conf->aio_write, prev->aio_write, 0);
[3818] #if (NGX_THREADS)
[3819]     ngx_conf_merge_ptr_value(conf->thread_pool, prev->thread_pool, NULL);
[3820]     ngx_conf_merge_ptr_value(conf->thread_pool_value, prev->thread_pool_value,
[3821]                              NULL);
[3822] #endif
[3823]     ngx_conf_merge_size_value(conf->read_ahead, prev->read_ahead, 0);
[3824]     ngx_conf_merge_off_value(conf->directio, prev->directio,
[3825]                               NGX_OPEN_FILE_DIRECTIO_OFF);
[3826]     ngx_conf_merge_off_value(conf->directio_alignment, prev->directio_alignment,
[3827]                               512);
[3828]     ngx_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
[3829]     ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);
[3830] 
[3831]     ngx_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
[3832]     ngx_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);
[3833]     ngx_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
[3834]                               1460);
[3835] 
[3836]     ngx_conf_merge_ptr_value(conf->limit_rate, prev->limit_rate, NULL);
[3837]     ngx_conf_merge_ptr_value(conf->limit_rate_after,
[3838]                               prev->limit_rate_after, NULL);
[3839] 
[3840]     ngx_conf_merge_msec_value(conf->keepalive_time,
[3841]                               prev->keepalive_time, 3600000);
[3842]     ngx_conf_merge_msec_value(conf->keepalive_timeout,
[3843]                               prev->keepalive_timeout, 75000);
[3844]     ngx_conf_merge_sec_value(conf->keepalive_header,
[3845]                               prev->keepalive_header, 0);
[3846]     ngx_conf_merge_uint_value(conf->keepalive_requests,
[3847]                               prev->keepalive_requests, 1000);
[3848]     ngx_conf_merge_uint_value(conf->lingering_close,
[3849]                               prev->lingering_close, NGX_HTTP_LINGERING_ON);
[3850]     ngx_conf_merge_msec_value(conf->lingering_time,
[3851]                               prev->lingering_time, 30000);
[3852]     ngx_conf_merge_msec_value(conf->lingering_timeout,
[3853]                               prev->lingering_timeout, 5000);
[3854]     ngx_conf_merge_msec_value(conf->resolver_timeout,
[3855]                               prev->resolver_timeout, 30000);
[3856] 
[3857]     if (conf->resolver == NULL) {
[3858] 
[3859]         if (prev->resolver == NULL) {
[3860] 
[3861]             /*
[3862]              * create dummy resolver in http {} context
[3863]              * to inherit it in all servers
[3864]              */
[3865] 
[3866]             prev->resolver = ngx_resolver_create(cf, NULL, 0);
[3867]             if (prev->resolver == NULL) {
[3868]                 return NGX_CONF_ERROR;
[3869]             }
[3870]         }
[3871] 
[3872]         conf->resolver = prev->resolver;
[3873]     }
[3874] 
[3875]     if (ngx_conf_merge_path_value(cf, &conf->client_body_temp_path,
[3876]                               prev->client_body_temp_path,
[3877]                               &ngx_http_client_temp_path)
[3878]         != NGX_OK)
[3879]     {
[3880]         return NGX_CONF_ERROR;
[3881]     }
[3882] 
[3883]     ngx_conf_merge_value(conf->reset_timedout_connection,
[3884]                               prev->reset_timedout_connection, 0);
[3885]     ngx_conf_merge_value(conf->absolute_redirect,
[3886]                               prev->absolute_redirect, 1);
[3887]     ngx_conf_merge_value(conf->server_name_in_redirect,
[3888]                               prev->server_name_in_redirect, 0);
[3889]     ngx_conf_merge_value(conf->port_in_redirect, prev->port_in_redirect, 1);
[3890]     ngx_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);
[3891]     ngx_conf_merge_value(conf->msie_refresh, prev->msie_refresh, 0);
[3892]     ngx_conf_merge_value(conf->log_not_found, prev->log_not_found, 1);
[3893]     ngx_conf_merge_value(conf->log_subrequest, prev->log_subrequest, 0);
[3894]     ngx_conf_merge_value(conf->recursive_error_pages,
[3895]                               prev->recursive_error_pages, 0);
[3896]     ngx_conf_merge_value(conf->chunked_transfer_encoding,
[3897]                               prev->chunked_transfer_encoding, 1);
[3898]     ngx_conf_merge_value(conf->etag, prev->etag, 1);
[3899] 
[3900]     ngx_conf_merge_uint_value(conf->server_tokens, prev->server_tokens,
[3901]                               NGX_HTTP_SERVER_TOKENS_ON);
[3902] 
[3903]     ngx_conf_merge_ptr_value(conf->open_file_cache,
[3904]                               prev->open_file_cache, NULL);
[3905] 
[3906]     ngx_conf_merge_sec_value(conf->open_file_cache_valid,
[3907]                               prev->open_file_cache_valid, 60);
[3908] 
[3909]     ngx_conf_merge_uint_value(conf->open_file_cache_min_uses,
[3910]                               prev->open_file_cache_min_uses, 1);
[3911] 
[3912]     ngx_conf_merge_sec_value(conf->open_file_cache_errors,
[3913]                               prev->open_file_cache_errors, 0);
[3914] 
[3915]     ngx_conf_merge_sec_value(conf->open_file_cache_events,
[3916]                               prev->open_file_cache_events, 0);
[3917] #if (NGX_HTTP_GZIP)
[3918] 
[3919]     ngx_conf_merge_value(conf->gzip_vary, prev->gzip_vary, 0);
[3920]     ngx_conf_merge_uint_value(conf->gzip_http_version, prev->gzip_http_version,
[3921]                               NGX_HTTP_VERSION_11);
[3922]     ngx_conf_merge_bitmask_value(conf->gzip_proxied, prev->gzip_proxied,
[3923]                               (NGX_CONF_BITMASK_SET|NGX_HTTP_GZIP_PROXIED_OFF));
[3924] 
[3925] #if (NGX_PCRE)
[3926]     ngx_conf_merge_ptr_value(conf->gzip_disable, prev->gzip_disable, NULL);
[3927] #endif
[3928] 
[3929]     if (conf->gzip_disable_msie6 == 3) {
[3930]         conf->gzip_disable_msie6 =
[3931]             (prev->gzip_disable_msie6 == 3) ? 0 : prev->gzip_disable_msie6;
[3932]     }
[3933] 
[3934] #if (NGX_HTTP_DEGRADATION)
[3935] 
[3936]     if (conf->gzip_disable_degradation == 3) {
[3937]         conf->gzip_disable_degradation =
[3938]             (prev->gzip_disable_degradation == 3) ?
[3939]                  0 : prev->gzip_disable_degradation;
[3940]     }
[3941] 
[3942] #endif
[3943] #endif
[3944] 
[3945] #if (NGX_HAVE_OPENAT)
[3946]     ngx_conf_merge_uint_value(conf->disable_symlinks, prev->disable_symlinks,
[3947]                               NGX_DISABLE_SYMLINKS_OFF);
[3948]     ngx_conf_merge_ptr_value(conf->disable_symlinks_from,
[3949]                              prev->disable_symlinks_from, NULL);
[3950] #endif
[3951] 
[3952]     return NGX_CONF_OK;
[3953] }
[3954] 
[3955] 
[3956] static char *
[3957] ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3958] {
[3959]     ngx_http_core_srv_conf_t *cscf = conf;
[3960] 
[3961]     ngx_str_t              *value, size;
[3962]     ngx_url_t               u;
[3963]     ngx_uint_t              n, i;
[3964]     ngx_http_listen_opt_t   lsopt;
[3965] 
[3966]     cscf->listen = 1;
[3967] 
[3968]     value = cf->args->elts;
[3969] 
[3970]     ngx_memzero(&u, sizeof(ngx_url_t));
[3971] 
[3972]     u.url = value[1];
[3973]     u.listen = 1;
[3974]     u.default_port = 80;
[3975] 
[3976]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[3977]         if (u.err) {
[3978]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[3979]                                "%s in \"%V\" of the \"listen\" directive",
[3980]                                u.err, &u.url);
[3981]         }
[3982] 
[3983]         return NGX_CONF_ERROR;
[3984]     }
[3985] 
[3986]     ngx_memzero(&lsopt, sizeof(ngx_http_listen_opt_t));
[3987] 
[3988]     lsopt.backlog = NGX_LISTEN_BACKLOG;
[3989]     lsopt.rcvbuf = -1;
[3990]     lsopt.sndbuf = -1;
[3991] #if (NGX_HAVE_SETFIB)
[3992]     lsopt.setfib = -1;
[3993] #endif
[3994] #if (NGX_HAVE_TCP_FASTOPEN)
[3995]     lsopt.fastopen = -1;
[3996] #endif
[3997] #if (NGX_HAVE_INET6)
[3998]     lsopt.ipv6only = 1;
[3999] #endif
[4000] 
[4001]     for (n = 2; n < cf->args->nelts; n++) {
[4002] 
[4003]         if (ngx_strcmp(value[n].data, "default_server") == 0
[4004]             || ngx_strcmp(value[n].data, "default") == 0)
[4005]         {
[4006]             lsopt.default_server = 1;
[4007]             continue;
[4008]         }
[4009] 
[4010]         if (ngx_strcmp(value[n].data, "bind") == 0) {
[4011]             lsopt.set = 1;
[4012]             lsopt.bind = 1;
[4013]             continue;
[4014]         }
[4015] 
[4016] #if (NGX_HAVE_SETFIB)
[4017]         if (ngx_strncmp(value[n].data, "setfib=", 7) == 0) {
[4018]             lsopt.setfib = ngx_atoi(value[n].data + 7, value[n].len - 7);
[4019]             lsopt.set = 1;
[4020]             lsopt.bind = 1;
[4021] 
[4022]             if (lsopt.setfib == NGX_ERROR) {
[4023]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4024]                                    "invalid setfib \"%V\"", &value[n]);
[4025]                 return NGX_CONF_ERROR;
[4026]             }
[4027] 
[4028]             continue;
[4029]         }
[4030] #endif
[4031] 
[4032] #if (NGX_HAVE_TCP_FASTOPEN)
[4033]         if (ngx_strncmp(value[n].data, "fastopen=", 9) == 0) {
[4034]             lsopt.fastopen = ngx_atoi(value[n].data + 9, value[n].len - 9);
[4035]             lsopt.set = 1;
[4036]             lsopt.bind = 1;
[4037] 
[4038]             if (lsopt.fastopen == NGX_ERROR) {
[4039]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4040]                                    "invalid fastopen \"%V\"", &value[n]);
[4041]                 return NGX_CONF_ERROR;
[4042]             }
[4043] 
[4044]             continue;
[4045]         }
[4046] #endif
[4047] 
[4048]         if (ngx_strncmp(value[n].data, "backlog=", 8) == 0) {
[4049]             lsopt.backlog = ngx_atoi(value[n].data + 8, value[n].len - 8);
[4050]             lsopt.set = 1;
[4051]             lsopt.bind = 1;
[4052] 
[4053]             if (lsopt.backlog == NGX_ERROR || lsopt.backlog == 0) {
[4054]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4055]                                    "invalid backlog \"%V\"", &value[n]);
[4056]                 return NGX_CONF_ERROR;
[4057]             }
[4058] 
[4059]             continue;
[4060]         }
[4061] 
[4062]         if (ngx_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
[4063]             size.len = value[n].len - 7;
[4064]             size.data = value[n].data + 7;
[4065] 
[4066]             lsopt.rcvbuf = ngx_parse_size(&size);
[4067]             lsopt.set = 1;
[4068]             lsopt.bind = 1;
[4069] 
[4070]             if (lsopt.rcvbuf == NGX_ERROR) {
[4071]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4072]                                    "invalid rcvbuf \"%V\"", &value[n]);
[4073]                 return NGX_CONF_ERROR;
[4074]             }
[4075] 
[4076]             continue;
[4077]         }
[4078] 
[4079]         if (ngx_strncmp(value[n].data, "sndbuf=", 7) == 0) {
[4080]             size.len = value[n].len - 7;
[4081]             size.data = value[n].data + 7;
[4082] 
[4083]             lsopt.sndbuf = ngx_parse_size(&size);
[4084]             lsopt.set = 1;
[4085]             lsopt.bind = 1;
[4086] 
[4087]             if (lsopt.sndbuf == NGX_ERROR) {
[4088]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4089]                                    "invalid sndbuf \"%V\"", &value[n]);
[4090]                 return NGX_CONF_ERROR;
[4091]             }
[4092] 
[4093]             continue;
[4094]         }
[4095] 
[4096]         if (ngx_strncmp(value[n].data, "accept_filter=", 14) == 0) {
[4097] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[4098]             lsopt.accept_filter = (char *) &value[n].data[14];
[4099]             lsopt.set = 1;
[4100]             lsopt.bind = 1;
[4101] #else
[4102]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4103]                                "accept filters \"%V\" are not supported "
[4104]                                "on this platform, ignored",
[4105]                                &value[n]);
[4106] #endif
[4107]             continue;
[4108]         }
[4109] 
[4110]         if (ngx_strcmp(value[n].data, "deferred") == 0) {
[4111] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[4112]             lsopt.deferred_accept = 1;
[4113]             lsopt.set = 1;
[4114]             lsopt.bind = 1;
[4115] #else
[4116]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4117]                                "the deferred accept is not supported "
[4118]                                "on this platform, ignored");
[4119] #endif
[4120]             continue;
[4121]         }
[4122] 
[4123]         if (ngx_strncmp(value[n].data, "ipv6only=o", 10) == 0) {
[4124] #if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
[4125]             if (ngx_strcmp(&value[n].data[10], "n") == 0) {
[4126]                 lsopt.ipv6only = 1;
[4127] 
[4128]             } else if (ngx_strcmp(&value[n].data[10], "ff") == 0) {
[4129]                 lsopt.ipv6only = 0;
[4130] 
[4131]             } else {
[4132]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4133]                                    "invalid ipv6only flags \"%s\"",
[4134]                                    &value[n].data[9]);
[4135]                 return NGX_CONF_ERROR;
[4136]             }
[4137] 
[4138]             lsopt.set = 1;
[4139]             lsopt.bind = 1;
[4140] 
[4141]             continue;
[4142] #else
[4143]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4144]                                "ipv6only is not supported "
[4145]                                "on this platform");
[4146]             return NGX_CONF_ERROR;
[4147] #endif
[4148]         }
[4149] 
[4150]         if (ngx_strcmp(value[n].data, "reuseport") == 0) {
[4151] #if (NGX_HAVE_REUSEPORT)
[4152]             lsopt.reuseport = 1;
[4153]             lsopt.set = 1;
[4154]             lsopt.bind = 1;
[4155] #else
[4156]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4157]                                "reuseport is not supported "
[4158]                                "on this platform, ignored");
[4159] #endif
[4160]             continue;
[4161]         }
[4162] 
[4163]         if (ngx_strcmp(value[n].data, "ssl") == 0) {
[4164] #if (NGX_HTTP_SSL)
[4165]             lsopt.ssl = 1;
[4166]             continue;
[4167] #else
[4168]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4169]                                "the \"ssl\" parameter requires "
[4170]                                "ngx_http_ssl_module");
[4171]             return NGX_CONF_ERROR;
[4172] #endif
[4173]         }
[4174] 
[4175]         if (ngx_strcmp(value[n].data, "http2") == 0) {
[4176] #if (NGX_HTTP_V2)
[4177]             lsopt.http2 = 1;
[4178]             continue;
[4179] #else
[4180]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4181]                                "the \"http2\" parameter requires "
[4182]                                "ngx_http_v2_module");
[4183]             return NGX_CONF_ERROR;
[4184] #endif
[4185]         }
[4186] 
[4187]         if (ngx_strncmp(value[n].data, "so_keepalive=", 13) == 0) {
[4188] 
[4189]             if (ngx_strcmp(&value[n].data[13], "on") == 0) {
[4190]                 lsopt.so_keepalive = 1;
[4191] 
[4192]             } else if (ngx_strcmp(&value[n].data[13], "off") == 0) {
[4193]                 lsopt.so_keepalive = 2;
[4194] 
[4195]             } else {
[4196] 
[4197] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[4198]                 u_char     *p, *end;
[4199]                 ngx_str_t   s;
[4200] 
[4201]                 end = value[n].data + value[n].len;
[4202]                 s.data = value[n].data + 13;
[4203] 
[4204]                 p = ngx_strlchr(s.data, end, ':');
[4205]                 if (p == NULL) {
[4206]                     p = end;
[4207]                 }
[4208] 
[4209]                 if (p > s.data) {
[4210]                     s.len = p - s.data;
[4211] 
[4212]                     lsopt.tcp_keepidle = ngx_parse_time(&s, 1);
[4213]                     if (lsopt.tcp_keepidle == (time_t) NGX_ERROR) {
[4214]                         goto invalid_so_keepalive;
[4215]                     }
[4216]                 }
[4217] 
[4218]                 s.data = (p < end) ? (p + 1) : end;
[4219] 
[4220]                 p = ngx_strlchr(s.data, end, ':');
[4221]                 if (p == NULL) {
[4222]                     p = end;
[4223]                 }
[4224] 
[4225]                 if (p > s.data) {
[4226]                     s.len = p - s.data;
[4227] 
[4228]                     lsopt.tcp_keepintvl = ngx_parse_time(&s, 1);
[4229]                     if (lsopt.tcp_keepintvl == (time_t) NGX_ERROR) {
[4230]                         goto invalid_so_keepalive;
[4231]                     }
[4232]                 }
[4233] 
[4234]                 s.data = (p < end) ? (p + 1) : end;
[4235] 
[4236]                 if (s.data < end) {
[4237]                     s.len = end - s.data;
[4238] 
[4239]                     lsopt.tcp_keepcnt = ngx_atoi(s.data, s.len);
[4240]                     if (lsopt.tcp_keepcnt == NGX_ERROR) {
[4241]                         goto invalid_so_keepalive;
[4242]                     }
[4243]                 }
[4244] 
[4245]                 if (lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0
[4246]                     && lsopt.tcp_keepcnt == 0)
[4247]                 {
[4248]                     goto invalid_so_keepalive;
[4249]                 }
[4250] 
[4251]                 lsopt.so_keepalive = 1;
[4252] 
[4253] #else
[4254] 
[4255]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4256]                                    "the \"so_keepalive\" parameter accepts "
[4257]                                    "only \"on\" or \"off\" on this platform");
[4258]                 return NGX_CONF_ERROR;
[4259] 
[4260] #endif
[4261]             }
[4262] 
[4263]             lsopt.set = 1;
[4264]             lsopt.bind = 1;
[4265] 
[4266]             continue;
[4267] 
[4268] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[4269]         invalid_so_keepalive:
[4270] 
[4271]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4272]                                "invalid so_keepalive value: \"%s\"",
[4273]                                &value[n].data[13]);
[4274]             return NGX_CONF_ERROR;
[4275] #endif
[4276]         }
[4277] 
[4278]         if (ngx_strcmp(value[n].data, "proxy_protocol") == 0) {
[4279]             lsopt.proxy_protocol = 1;
[4280]             continue;
[4281]         }
[4282] 
[4283]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4284]                            "invalid parameter \"%V\"", &value[n]);
[4285]         return NGX_CONF_ERROR;
[4286]     }
[4287] 
[4288]     for (n = 0; n < u.naddrs; n++) {
[4289] 
[4290]         for (i = 0; i < n; i++) {
[4291]             if (ngx_cmp_sockaddr(u.addrs[n].sockaddr, u.addrs[n].socklen,
[4292]                                  u.addrs[i].sockaddr, u.addrs[i].socklen, 1)
[4293]                 == NGX_OK)
[4294]             {
[4295]                 goto next;
[4296]             }
[4297]         }
[4298] 
[4299]         lsopt.sockaddr = u.addrs[n].sockaddr;
[4300]         lsopt.socklen = u.addrs[n].socklen;
[4301]         lsopt.addr_text = u.addrs[n].name;
[4302]         lsopt.wildcard = ngx_inet_wildcard(lsopt.sockaddr);
[4303] 
[4304]         if (ngx_http_add_listen(cf, cscf, &lsopt) != NGX_OK) {
[4305]             return NGX_CONF_ERROR;
[4306]         }
[4307] 
[4308]     next:
[4309]         continue;
[4310]     }
[4311] 
[4312]     return NGX_CONF_OK;
[4313] }
[4314] 
[4315] 
[4316] static char *
[4317] ngx_http_core_server_name(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4318] {
[4319]     ngx_http_core_srv_conf_t *cscf = conf;
[4320] 
[4321]     u_char                   ch;
[4322]     ngx_str_t               *value;
[4323]     ngx_uint_t               i;
[4324]     ngx_http_server_name_t  *sn;
[4325] 
[4326]     value = cf->args->elts;
[4327] 
[4328]     for (i = 1; i < cf->args->nelts; i++) {
[4329] 
[4330]         ch = value[i].data[0];
[4331] 
[4332]         if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
[4333]             || (ch == '.' && value[i].len < 2))
[4334]         {
[4335]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4336]                                "server name \"%V\" is invalid", &value[i]);
[4337]             return NGX_CONF_ERROR;
[4338]         }
[4339] 
[4340]         if (ngx_strchr(value[i].data, '/')) {
[4341]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[4342]                                "server name \"%V\" has suspicious symbols",
[4343]                                &value[i]);
[4344]         }
[4345] 
[4346]         sn = ngx_array_push(&cscf->server_names);
[4347]         if (sn == NULL) {
[4348]             return NGX_CONF_ERROR;
[4349]         }
[4350] 
[4351] #if (NGX_PCRE)
[4352]         sn->regex = NULL;
[4353] #endif
[4354]         sn->server = cscf;
[4355] 
[4356]         if (ngx_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
[4357]             sn->name = cf->cycle->hostname;
[4358] 
[4359]         } else {
[4360]             sn->name = value[i];
[4361]         }
[4362] 
[4363]         if (value[i].data[0] != '~') {
[4364]             ngx_strlow(sn->name.data, sn->name.data, sn->name.len);
[4365]             continue;
[4366]         }
[4367] 
[4368] #if (NGX_PCRE)
[4369]         {
[4370]         u_char               *p;
[4371]         ngx_regex_compile_t   rc;
[4372]         u_char                errstr[NGX_MAX_CONF_ERRSTR];
[4373] 
[4374]         if (value[i].len == 1) {
[4375]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4376]                                "empty regex in server name \"%V\"", &value[i]);
[4377]             return NGX_CONF_ERROR;
[4378]         }
[4379] 
[4380]         value[i].len--;
[4381]         value[i].data++;
[4382] 
[4383]         ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[4384] 
[4385]         rc.pattern = value[i];
[4386]         rc.err.len = NGX_MAX_CONF_ERRSTR;
[4387]         rc.err.data = errstr;
[4388] 
[4389]         for (p = value[i].data; p < value[i].data + value[i].len; p++) {
[4390]             if (*p >= 'A' && *p <= 'Z') {
[4391]                 rc.options = NGX_REGEX_CASELESS;
[4392]                 break;
[4393]             }
[4394]         }
[4395] 
[4396]         sn->regex = ngx_http_regex_compile(cf, &rc);
[4397]         if (sn->regex == NULL) {
[4398]             return NGX_CONF_ERROR;
[4399]         }
[4400] 
[4401]         sn->name = value[i];
[4402]         cscf->captures = (rc.captures > 0);
[4403]         }
[4404] #else
[4405]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4406]                            "using regex \"%V\" "
[4407]                            "requires PCRE library", &value[i]);
[4408] 
[4409]         return NGX_CONF_ERROR;
[4410] #endif
[4411]     }
[4412] 
[4413]     return NGX_CONF_OK;
[4414] }
[4415] 
[4416] 
[4417] static char *
[4418] ngx_http_core_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4419] {
[4420]     ngx_http_core_loc_conf_t *clcf = conf;
[4421] 
[4422]     ngx_str_t                  *value;
[4423]     ngx_int_t                   alias;
[4424]     ngx_uint_t                  n;
[4425]     ngx_http_script_compile_t   sc;
[4426] 
[4427]     alias = (cmd->name.len == sizeof("alias") - 1) ? 1 : 0;
[4428] 
[4429]     if (clcf->root.data) {
[4430] 
[4431]         if ((clcf->alias != 0) == alias) {
[4432]             return "is duplicate";
[4433]         }
[4434] 
[4435]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4436]                            "\"%V\" directive is duplicate, "
[4437]                            "\"%s\" directive was specified earlier",
[4438]                            &cmd->name, clcf->alias ? "alias" : "root");
[4439] 
[4440]         return NGX_CONF_ERROR;
[4441]     }
[4442] 
[4443]     if (clcf->named && alias) {
[4444]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4445]                            "the \"alias\" directive cannot be used "
[4446]                            "inside the named location");
[4447] 
[4448]         return NGX_CONF_ERROR;
[4449]     }
[4450] 
[4451]     value = cf->args->elts;
[4452] 
[4453]     if (ngx_strstr(value[1].data, "$document_root")
[4454]         || ngx_strstr(value[1].data, "${document_root}"))
[4455]     {
[4456]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4457]                            "the $document_root variable cannot be used "
[4458]                            "in the \"%V\" directive",
[4459]                            &cmd->name);
[4460] 
[4461]         return NGX_CONF_ERROR;
[4462]     }
[4463] 
[4464]     if (ngx_strstr(value[1].data, "$realpath_root")
[4465]         || ngx_strstr(value[1].data, "${realpath_root}"))
[4466]     {
[4467]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4468]                            "the $realpath_root variable cannot be used "
[4469]                            "in the \"%V\" directive",
[4470]                            &cmd->name);
[4471] 
[4472]         return NGX_CONF_ERROR;
[4473]     }
[4474] 
[4475]     clcf->alias = alias ? clcf->name.len : 0;
[4476]     clcf->root = value[1];
[4477] 
[4478]     if (!alias && clcf->root.len > 0
[4479]         && clcf->root.data[clcf->root.len - 1] == '/')
[4480]     {
[4481]         clcf->root.len--;
[4482]     }
[4483] 
[4484]     if (clcf->root.data[0] != '$') {
[4485]         if (ngx_conf_full_name(cf->cycle, &clcf->root, 0) != NGX_OK) {
[4486]             return NGX_CONF_ERROR;
[4487]         }
[4488]     }
[4489] 
[4490]     n = ngx_http_script_variables_count(&clcf->root);
[4491] 
[4492]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[4493]     sc.variables = n;
[4494] 
[4495] #if (NGX_PCRE)
[4496]     if (alias && clcf->regex) {
[4497]         clcf->alias = NGX_MAX_SIZE_T_VALUE;
[4498]         n = 1;
[4499]     }
[4500] #endif
[4501] 
[4502]     if (n) {
[4503]         sc.cf = cf;
[4504]         sc.source = &clcf->root;
[4505]         sc.lengths = &clcf->root_lengths;
[4506]         sc.values = &clcf->root_values;
[4507]         sc.complete_lengths = 1;
[4508]         sc.complete_values = 1;
[4509] 
[4510]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[4511]             return NGX_CONF_ERROR;
[4512]         }
[4513]     }
[4514] 
[4515]     return NGX_CONF_OK;
[4516] }
[4517] 
[4518] 
[4519] static ngx_http_method_name_t  ngx_methods_names[] = {
[4520]     { (u_char *) "GET",       (uint32_t) ~NGX_HTTP_GET },
[4521]     { (u_char *) "HEAD",      (uint32_t) ~NGX_HTTP_HEAD },
[4522]     { (u_char *) "POST",      (uint32_t) ~NGX_HTTP_POST },
[4523]     { (u_char *) "PUT",       (uint32_t) ~NGX_HTTP_PUT },
[4524]     { (u_char *) "DELETE",    (uint32_t) ~NGX_HTTP_DELETE },
[4525]     { (u_char *) "MKCOL",     (uint32_t) ~NGX_HTTP_MKCOL },
[4526]     { (u_char *) "COPY",      (uint32_t) ~NGX_HTTP_COPY },
[4527]     { (u_char *) "MOVE",      (uint32_t) ~NGX_HTTP_MOVE },
[4528]     { (u_char *) "OPTIONS",   (uint32_t) ~NGX_HTTP_OPTIONS },
[4529]     { (u_char *) "PROPFIND",  (uint32_t) ~NGX_HTTP_PROPFIND },
[4530]     { (u_char *) "PROPPATCH", (uint32_t) ~NGX_HTTP_PROPPATCH },
[4531]     { (u_char *) "LOCK",      (uint32_t) ~NGX_HTTP_LOCK },
[4532]     { (u_char *) "UNLOCK",    (uint32_t) ~NGX_HTTP_UNLOCK },
[4533]     { (u_char *) "PATCH",     (uint32_t) ~NGX_HTTP_PATCH },
[4534]     { NULL, 0 }
[4535] };
[4536] 
[4537] 
[4538] static char *
[4539] ngx_http_core_limit_except(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4540] {
[4541]     ngx_http_core_loc_conf_t *pclcf = conf;
[4542] 
[4543]     char                      *rv;
[4544]     void                      *mconf;
[4545]     ngx_str_t                 *value;
[4546]     ngx_uint_t                 i;
[4547]     ngx_conf_t                 save;
[4548]     ngx_http_module_t         *module;
[4549]     ngx_http_conf_ctx_t       *ctx, *pctx;
[4550]     ngx_http_method_name_t    *name;
[4551]     ngx_http_core_loc_conf_t  *clcf;
[4552] 
[4553]     if (pclcf->limit_except) {
[4554]         return "is duplicate";
[4555]     }
[4556] 
[4557]     pclcf->limit_except = 0xffffffff;
[4558] 
[4559]     value = cf->args->elts;
[4560] 
[4561]     for (i = 1; i < cf->args->nelts; i++) {
[4562]         for (name = ngx_methods_names; name->name; name++) {
[4563] 
[4564]             if (ngx_strcasecmp(value[i].data, name->name) == 0) {
[4565]                 pclcf->limit_except &= name->method;
[4566]                 goto next;
[4567]             }
[4568]         }
[4569] 
[4570]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4571]                            "invalid method \"%V\"", &value[i]);
[4572]         return NGX_CONF_ERROR;
[4573] 
[4574]     next:
[4575]         continue;
[4576]     }
[4577] 
[4578]     if (!(pclcf->limit_except & NGX_HTTP_GET)) {
[4579]         pclcf->limit_except &= (uint32_t) ~NGX_HTTP_HEAD;
[4580]     }
[4581] 
[4582]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
[4583]     if (ctx == NULL) {
[4584]         return NGX_CONF_ERROR;
[4585]     }
[4586] 
[4587]     pctx = cf->ctx;
[4588]     ctx->main_conf = pctx->main_conf;
[4589]     ctx->srv_conf = pctx->srv_conf;
[4590] 
[4591]     ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[4592]     if (ctx->loc_conf == NULL) {
[4593]         return NGX_CONF_ERROR;
[4594]     }
[4595] 
[4596]     for (i = 0; cf->cycle->modules[i]; i++) {
[4597]         if (cf->cycle->modules[i]->type != NGX_HTTP_MODULE) {
[4598]             continue;
[4599]         }
[4600] 
[4601]         module = cf->cycle->modules[i]->ctx;
[4602] 
[4603]         if (module->create_loc_conf) {
[4604] 
[4605]             mconf = module->create_loc_conf(cf);
[4606]             if (mconf == NULL) {
[4607]                 return NGX_CONF_ERROR;
[4608]             }
[4609] 
[4610]             ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
[4611]         }
[4612]     }
[4613] 
[4614] 
[4615]     clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
[4616]     pclcf->limit_except_loc_conf = ctx->loc_conf;
[4617]     clcf->loc_conf = ctx->loc_conf;
[4618]     clcf->name = pclcf->name;
[4619]     clcf->noname = 1;
[4620]     clcf->lmt_excpt = 1;
[4621] 
[4622]     if (ngx_http_add_location(cf, &pclcf->locations, clcf) != NGX_OK) {
[4623]         return NGX_CONF_ERROR;
[4624]     }
[4625] 
[4626]     save = *cf;
[4627]     cf->ctx = ctx;
[4628]     cf->cmd_type = NGX_HTTP_LMT_CONF;
[4629] 
[4630]     rv = ngx_conf_parse(cf, NULL);
[4631] 
[4632]     *cf = save;
[4633] 
[4634]     return rv;
[4635] }
[4636] 
[4637] 
[4638] static char *
[4639] ngx_http_core_set_aio(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4640] {
[4641]     ngx_http_core_loc_conf_t *clcf = conf;
[4642] 
[4643]     ngx_str_t  *value;
[4644] 
[4645]     if (clcf->aio != NGX_CONF_UNSET) {
[4646]         return "is duplicate";
[4647]     }
[4648] 
[4649] #if (NGX_THREADS)
[4650]     clcf->thread_pool = NULL;
[4651]     clcf->thread_pool_value = NULL;
[4652] #endif
[4653] 
[4654]     value = cf->args->elts;
[4655] 
[4656]     if (ngx_strcmp(value[1].data, "off") == 0) {
[4657]         clcf->aio = NGX_HTTP_AIO_OFF;
[4658]         return NGX_CONF_OK;
[4659]     }
[4660] 
[4661]     if (ngx_strcmp(value[1].data, "on") == 0) {
[4662] #if (NGX_HAVE_FILE_AIO)
[4663]         clcf->aio = NGX_HTTP_AIO_ON;
[4664]         return NGX_CONF_OK;
[4665] #else
[4666]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4667]                            "\"aio on\" "
[4668]                            "is unsupported on this platform");
[4669]         return NGX_CONF_ERROR;
[4670] #endif
[4671]     }
[4672] 
[4673]     if (ngx_strncmp(value[1].data, "threads", 7) == 0
[4674]         && (value[1].len == 7 || value[1].data[7] == '='))
[4675]     {
[4676] #if (NGX_THREADS)
[4677]         ngx_str_t                          name;
[4678]         ngx_thread_pool_t                 *tp;
[4679]         ngx_http_complex_value_t           cv;
[4680]         ngx_http_compile_complex_value_t   ccv;
[4681] 
[4682]         clcf->aio = NGX_HTTP_AIO_THREADS;
[4683] 
[4684]         if (value[1].len >= 8) {
[4685]             name.len = value[1].len - 8;
[4686]             name.data = value[1].data + 8;
[4687] 
[4688]             ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4689] 
[4690]             ccv.cf = cf;
[4691]             ccv.value = &name;
[4692]             ccv.complex_value = &cv;
[4693] 
[4694]             if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4695]                 return NGX_CONF_ERROR;
[4696]             }
[4697] 
[4698]             if (cv.lengths != NULL) {
[4699]                 clcf->thread_pool_value = ngx_palloc(cf->pool,
[4700]                                     sizeof(ngx_http_complex_value_t));
[4701]                 if (clcf->thread_pool_value == NULL) {
[4702]                     return NGX_CONF_ERROR;
[4703]                 }
[4704] 
[4705]                 *clcf->thread_pool_value = cv;
[4706] 
[4707]                 return NGX_CONF_OK;
[4708]             }
[4709] 
[4710]             tp = ngx_thread_pool_add(cf, &name);
[4711] 
[4712]         } else {
[4713]             tp = ngx_thread_pool_add(cf, NULL);
[4714]         }
[4715] 
[4716]         if (tp == NULL) {
[4717]             return NGX_CONF_ERROR;
[4718]         }
[4719] 
[4720]         clcf->thread_pool = tp;
[4721] 
[4722]         return NGX_CONF_OK;
[4723] #else
[4724]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4725]                            "\"aio threads\" "
[4726]                            "is unsupported on this platform");
[4727]         return NGX_CONF_ERROR;
[4728] #endif
[4729]     }
[4730] 
[4731]     return "invalid value";
[4732] }
[4733] 
[4734] 
[4735] static char *
[4736] ngx_http_core_directio(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4737] {
[4738]     ngx_http_core_loc_conf_t *clcf = conf;
[4739] 
[4740]     ngx_str_t  *value;
[4741] 
[4742]     if (clcf->directio != NGX_CONF_UNSET) {
[4743]         return "is duplicate";
[4744]     }
[4745] 
[4746]     value = cf->args->elts;
[4747] 
[4748]     if (ngx_strcmp(value[1].data, "off") == 0) {
[4749]         clcf->directio = NGX_OPEN_FILE_DIRECTIO_OFF;
[4750]         return NGX_CONF_OK;
[4751]     }
[4752] 
[4753]     clcf->directio = ngx_parse_offset(&value[1]);
[4754]     if (clcf->directio == (off_t) NGX_ERROR) {
[4755]         return "invalid value";
[4756]     }
[4757] 
[4758]     return NGX_CONF_OK;
[4759] }
[4760] 
[4761] 
[4762] static char *
[4763] ngx_http_core_error_page(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4764] {
[4765]     ngx_http_core_loc_conf_t *clcf = conf;
[4766] 
[4767]     u_char                            *p;
[4768]     ngx_int_t                          overwrite;
[4769]     ngx_str_t                         *value, uri, args;
[4770]     ngx_uint_t                         i, n;
[4771]     ngx_http_err_page_t               *err;
[4772]     ngx_http_complex_value_t           cv;
[4773]     ngx_http_compile_complex_value_t   ccv;
[4774] 
[4775]     if (clcf->error_pages == NULL) {
[4776]         clcf->error_pages = ngx_array_create(cf->pool, 4,
[4777]                                              sizeof(ngx_http_err_page_t));
[4778]         if (clcf->error_pages == NULL) {
[4779]             return NGX_CONF_ERROR;
[4780]         }
[4781]     }
[4782] 
[4783]     value = cf->args->elts;
[4784] 
[4785]     i = cf->args->nelts - 2;
[4786] 
[4787]     if (value[i].data[0] == '=') {
[4788]         if (i == 1) {
[4789]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4790]                                "invalid value \"%V\"", &value[i]);
[4791]             return NGX_CONF_ERROR;
[4792]         }
[4793] 
[4794]         if (value[i].len > 1) {
[4795]             overwrite = ngx_atoi(&value[i].data[1], value[i].len - 1);
[4796] 
[4797]             if (overwrite == NGX_ERROR) {
[4798]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4799]                                    "invalid value \"%V\"", &value[i]);
[4800]                 return NGX_CONF_ERROR;
[4801]             }
[4802] 
[4803]         } else {
[4804]             overwrite = 0;
[4805]         }
[4806] 
[4807]         n = 2;
[4808] 
[4809]     } else {
[4810]         overwrite = -1;
[4811]         n = 1;
[4812]     }
[4813] 
[4814]     uri = value[cf->args->nelts - 1];
[4815] 
[4816]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[4817] 
[4818]     ccv.cf = cf;
[4819]     ccv.value = &uri;
[4820]     ccv.complex_value = &cv;
[4821] 
[4822]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[4823]         return NGX_CONF_ERROR;
[4824]     }
[4825] 
[4826]     ngx_str_null(&args);
[4827] 
[4828]     if (cv.lengths == NULL && uri.len && uri.data[0] == '/') {
[4829]         p = (u_char *) ngx_strchr(uri.data, '?');
[4830] 
[4831]         if (p) {
[4832]             cv.value.len = p - uri.data;
[4833]             cv.value.data = uri.data;
[4834]             p++;
[4835]             args.len = (uri.data + uri.len) - p;
[4836]             args.data = p;
[4837]         }
[4838]     }
[4839] 
[4840]     for (i = 1; i < cf->args->nelts - n; i++) {
[4841]         err = ngx_array_push(clcf->error_pages);
[4842]         if (err == NULL) {
[4843]             return NGX_CONF_ERROR;
[4844]         }
[4845] 
[4846]         err->status = ngx_atoi(value[i].data, value[i].len);
[4847] 
[4848]         if (err->status == NGX_ERROR || err->status == 499) {
[4849]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4850]                                "invalid value \"%V\"", &value[i]);
[4851]             return NGX_CONF_ERROR;
[4852]         }
[4853] 
[4854]         if (err->status < 300 || err->status > 599) {
[4855]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4856]                                "value \"%V\" must be between 300 and 599",
[4857]                                &value[i]);
[4858]             return NGX_CONF_ERROR;
[4859]         }
[4860] 
[4861]         err->overwrite = overwrite;
[4862] 
[4863]         if (overwrite == -1) {
[4864]             switch (err->status) {
[4865]                 case NGX_HTTP_TO_HTTPS:
[4866]                 case NGX_HTTPS_CERT_ERROR:
[4867]                 case NGX_HTTPS_NO_CERT:
[4868]                 case NGX_HTTP_REQUEST_HEADER_TOO_LARGE:
[4869]                     err->overwrite = NGX_HTTP_BAD_REQUEST;
[4870]             }
[4871]         }
[4872] 
[4873]         err->value = cv;
[4874]         err->args = args;
[4875]     }
[4876] 
[4877]     return NGX_CONF_OK;
[4878] }
[4879] 
[4880] 
[4881] static char *
[4882] ngx_http_core_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4883] {
[4884]     ngx_http_core_loc_conf_t *clcf = conf;
[4885] 
[4886]     time_t       inactive;
[4887]     ngx_str_t   *value, s;
[4888]     ngx_int_t    max;
[4889]     ngx_uint_t   i;
[4890] 
[4891]     if (clcf->open_file_cache != NGX_CONF_UNSET_PTR) {
[4892]         return "is duplicate";
[4893]     }
[4894] 
[4895]     value = cf->args->elts;
[4896] 
[4897]     max = 0;
[4898]     inactive = 60;
[4899] 
[4900]     for (i = 1; i < cf->args->nelts; i++) {
[4901] 
[4902]         if (ngx_strncmp(value[i].data, "max=", 4) == 0) {
[4903] 
[4904]             max = ngx_atoi(value[i].data + 4, value[i].len - 4);
[4905]             if (max <= 0) {
[4906]                 goto failed;
[4907]             }
[4908] 
[4909]             continue;
[4910]         }
[4911] 
[4912]         if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
[4913] 
[4914]             s.len = value[i].len - 9;
[4915]             s.data = value[i].data + 9;
[4916] 
[4917]             inactive = ngx_parse_time(&s, 1);
[4918]             if (inactive == (time_t) NGX_ERROR) {
[4919]                 goto failed;
[4920]             }
[4921] 
[4922]             continue;
[4923]         }
[4924] 
[4925]         if (ngx_strcmp(value[i].data, "off") == 0) {
[4926] 
[4927]             clcf->open_file_cache = NULL;
[4928] 
[4929]             continue;
[4930]         }
[4931] 
[4932]     failed:
[4933] 
[4934]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4935]                            "invalid \"open_file_cache\" parameter \"%V\"",
[4936]                            &value[i]);
[4937]         return NGX_CONF_ERROR;
[4938]     }
[4939] 
[4940]     if (clcf->open_file_cache == NULL) {
[4941]         return NGX_CONF_OK;
[4942]     }
[4943] 
[4944]     if (max == 0) {
[4945]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4946]                         "\"open_file_cache\" must have the \"max\" parameter");
[4947]         return NGX_CONF_ERROR;
[4948]     }
[4949] 
[4950]     clcf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);
[4951]     if (clcf->open_file_cache) {
[4952]         return NGX_CONF_OK;
[4953]     }
[4954] 
[4955]     return NGX_CONF_ERROR;
[4956] }
[4957] 
[4958] 
[4959] static char *
[4960] ngx_http_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4961] {
[4962]     ngx_http_core_loc_conf_t *clcf = conf;
[4963] 
[4964]     return ngx_log_set_log(cf, &clcf->error_log);
[4965] }
[4966] 
[4967] 
[4968] static char *
[4969] ngx_http_core_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[4970] {
[4971]     ngx_http_core_loc_conf_t *clcf = conf;
[4972] 
[4973]     ngx_str_t  *value;
[4974] 
[4975]     if (clcf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
[4976]         return "is duplicate";
[4977]     }
[4978] 
[4979]     value = cf->args->elts;
[4980] 
[4981]     clcf->keepalive_timeout = ngx_parse_time(&value[1], 0);
[4982] 
[4983]     if (clcf->keepalive_timeout == (ngx_msec_t) NGX_ERROR) {
[4984]         return "invalid value";
[4985]     }
[4986] 
[4987]     if (cf->args->nelts == 2) {
[4988]         return NGX_CONF_OK;
[4989]     }
[4990] 
[4991]     clcf->keepalive_header = ngx_parse_time(&value[2], 1);
[4992] 
[4993]     if (clcf->keepalive_header == (time_t) NGX_ERROR) {
[4994]         return "invalid value";
[4995]     }
[4996] 
[4997]     return NGX_CONF_OK;
[4998] }
[4999] 
[5000] 
[5001] static char *
[5002] ngx_http_core_internal(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[5003] {
[5004]     ngx_http_core_loc_conf_t *clcf = conf;
[5005] 
[5006]     if (clcf->internal != NGX_CONF_UNSET) {
[5007]         return "is duplicate";
[5008]     }
[5009] 
[5010]     clcf->internal = 1;
[5011] 
[5012]     return NGX_CONF_OK;
[5013] }
[5014] 
[5015] 
[5016] static char *
[5017] ngx_http_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[5018] {
[5019]     ngx_http_core_loc_conf_t  *clcf = conf;
[5020] 
[5021]     ngx_str_t  *value;
[5022] 
[5023]     if (clcf->resolver) {
[5024]         return "is duplicate";
[5025]     }
[5026] 
[5027]     value = cf->args->elts;
[5028] 
[5029]     clcf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
[5030]     if (clcf->resolver == NULL) {
[5031]         return NGX_CONF_ERROR;
[5032]     }
[5033] 
[5034]     return NGX_CONF_OK;
[5035] }
[5036] 
[5037] 
[5038] #if (NGX_HTTP_GZIP)
[5039] 
[5040] static char *
[5041] ngx_http_gzip_disable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[5042] {
[5043]     ngx_http_core_loc_conf_t  *clcf = conf;
[5044] 
[5045] #if (NGX_PCRE)
[5046] 
[5047]     ngx_str_t            *value;
[5048]     ngx_uint_t            i;
[5049]     ngx_regex_elt_t      *re;
[5050]     ngx_regex_compile_t   rc;
[5051]     u_char                errstr[NGX_MAX_CONF_ERRSTR];
[5052] 
[5053]     if (clcf->gzip_disable == NGX_CONF_UNSET_PTR) {
[5054]         clcf->gzip_disable = ngx_array_create(cf->pool, 2,
[5055]                                               sizeof(ngx_regex_elt_t));
[5056]         if (clcf->gzip_disable == NULL) {
[5057]             return NGX_CONF_ERROR;
[5058]         }
[5059]     }
[5060] 
[5061]     value = cf->args->elts;
[5062] 
[5063]     ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[5064] 
[5065]     rc.pool = cf->pool;
[5066]     rc.err.len = NGX_MAX_CONF_ERRSTR;
[5067]     rc.err.data = errstr;
[5068] 
[5069]     for (i = 1; i < cf->args->nelts; i++) {
[5070] 
[5071]         if (ngx_strcmp(value[i].data, "msie6") == 0) {
[5072]             clcf->gzip_disable_msie6 = 1;
[5073]             continue;
[5074]         }
[5075] 
[5076] #if (NGX_HTTP_DEGRADATION)
[5077] 
[5078]         if (ngx_strcmp(value[i].data, "degradation") == 0) {
[5079]             clcf->gzip_disable_degradation = 1;
[5080]             continue;
[5081]         }
[5082] 
[5083] #endif
[5084] 
[5085]         re = ngx_array_push(clcf->gzip_disable);
[5086]         if (re == NULL) {
[5087]             return NGX_CONF_ERROR;
[5088]         }
[5089] 
[5090]         rc.pattern = value[i];
[5091]         rc.options = NGX_REGEX_CASELESS;
[5092] 
[5093]         if (ngx_regex_compile(&rc) != NGX_OK) {
[5094]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
[5095]             return NGX_CONF_ERROR;
[5096]         }
[5097] 
[5098]         re->regex = rc.regex;
[5099]         re->name = value[i].data;
[5100]     }
[5101] 
[5102]     return NGX_CONF_OK;
[5103] 
[5104] #else
[5105]     ngx_str_t   *value;
[5106]     ngx_uint_t   i;
[5107] 
[5108]     value = cf->args->elts;
[5109] 
[5110]     for (i = 1; i < cf->args->nelts; i++) {
[5111]         if (ngx_strcmp(value[i].data, "msie6") == 0) {
[5112]             clcf->gzip_disable_msie6 = 1;
[5113]             continue;
[5114]         }
[5115] 
[5116] #if (NGX_HTTP_DEGRADATION)
[5117] 
[5118]         if (ngx_strcmp(value[i].data, "degradation") == 0) {
[5119]             clcf->gzip_disable_degradation = 1;
[5120]             continue;
[5121]         }
[5122] 
[5123] #endif
[5124] 
[5125]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5126]                            "without PCRE library \"gzip_disable\" supports "
[5127]                            "builtin \"msie6\" and \"degradation\" mask only");
[5128] 
[5129]         return NGX_CONF_ERROR;
[5130]     }
[5131] 
[5132]     return NGX_CONF_OK;
[5133] 
[5134] #endif
[5135] }
[5136] 
[5137] #endif
[5138] 
[5139] 
[5140] #if (NGX_HAVE_OPENAT)
[5141] 
[5142] static char *
[5143] ngx_http_disable_symlinks(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[5144] {
[5145]     ngx_http_core_loc_conf_t *clcf = conf;
[5146] 
[5147]     ngx_str_t                         *value;
[5148]     ngx_uint_t                         i;
[5149]     ngx_http_compile_complex_value_t   ccv;
[5150] 
[5151]     if (clcf->disable_symlinks != NGX_CONF_UNSET_UINT) {
[5152]         return "is duplicate";
[5153]     }
[5154] 
[5155]     value = cf->args->elts;
[5156] 
[5157]     for (i = 1; i < cf->args->nelts; i++) {
[5158] 
[5159]         if (ngx_strcmp(value[i].data, "off") == 0) {
[5160]             clcf->disable_symlinks = NGX_DISABLE_SYMLINKS_OFF;
[5161]             continue;
[5162]         }
[5163] 
[5164]         if (ngx_strcmp(value[i].data, "if_not_owner") == 0) {
[5165]             clcf->disable_symlinks = NGX_DISABLE_SYMLINKS_NOTOWNER;
[5166]             continue;
[5167]         }
[5168] 
[5169]         if (ngx_strcmp(value[i].data, "on") == 0) {
[5170]             clcf->disable_symlinks = NGX_DISABLE_SYMLINKS_ON;
[5171]             continue;
[5172]         }
[5173] 
[5174]         if (ngx_strncmp(value[i].data, "from=", 5) == 0) {
[5175]             value[i].len -= 5;
[5176]             value[i].data += 5;
[5177] 
[5178]             ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[5179] 
[5180]             ccv.cf = cf;
[5181]             ccv.value = &value[i];
[5182]             ccv.complex_value = ngx_palloc(cf->pool,
[5183]                                            sizeof(ngx_http_complex_value_t));
[5184]             if (ccv.complex_value == NULL) {
[5185]                 return NGX_CONF_ERROR;
[5186]             }
[5187] 
[5188]             if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[5189]                 return NGX_CONF_ERROR;
[5190]             }
[5191] 
[5192]             clcf->disable_symlinks_from = ccv.complex_value;
[5193] 
[5194]             continue;
[5195]         }
[5196] 
[5197]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5198]                            "invalid parameter \"%V\"", &value[i]);
[5199]         return NGX_CONF_ERROR;
[5200]     }
[5201] 
[5202]     if (clcf->disable_symlinks == NGX_CONF_UNSET_UINT) {
[5203]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5204]                            "\"%V\" must have \"off\", \"on\" "
[5205]                            "or \"if_not_owner\" parameter",
[5206]                            &cmd->name);
[5207]         return NGX_CONF_ERROR;
[5208]     }
[5209] 
[5210]     if (cf->args->nelts == 2) {
[5211]         clcf->disable_symlinks_from = NULL;
[5212]         return NGX_CONF_OK;
[5213]     }
[5214] 
[5215]     if (clcf->disable_symlinks_from == NGX_CONF_UNSET_PTR) {
[5216]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5217]                            "duplicate parameters \"%V %V\"",
[5218]                            &value[1], &value[2]);
[5219]         return NGX_CONF_ERROR;
[5220]     }
[5221] 
[5222]     if (clcf->disable_symlinks == NGX_DISABLE_SYMLINKS_OFF) {
[5223]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5224]                            "\"from=\" cannot be used with \"off\" parameter");
[5225]         return NGX_CONF_ERROR;
[5226]     }
[5227] 
[5228]     return NGX_CONF_OK;
[5229] }
[5230] 
[5231] #endif
[5232] 
[5233] 
[5234] static char *
[5235] ngx_http_core_lowat_check(ngx_conf_t *cf, void *post, void *data)
[5236] {
[5237] #if (NGX_FREEBSD)
[5238]     ssize_t *np = data;
[5239] 
[5240]     if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
[5241]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5242]                            "\"send_lowat\" must be less than %d "
[5243]                            "(sysctl net.inet.tcp.sendspace)",
[5244]                            ngx_freebsd_net_inet_tcp_sendspace);
[5245] 
[5246]         return NGX_CONF_ERROR;
[5247]     }
[5248] 
[5249] #elif !(NGX_HAVE_SO_SNDLOWAT)
[5250]     ssize_t *np = data;
[5251] 
[5252]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[5253]                        "\"send_lowat\" is not supported, ignored");
[5254] 
[5255]     *np = 0;
[5256] 
[5257] #endif
[5258] 
[5259]     return NGX_CONF_OK;
[5260] }
[5261] 
[5262] 
[5263] static char *
[5264] ngx_http_core_pool_size(ngx_conf_t *cf, void *post, void *data)
[5265] {
[5266]     size_t *sp = data;
[5267] 
[5268]     if (*sp < NGX_MIN_POOL_SIZE) {
[5269]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5270]                            "the pool size must be no less than %uz",
[5271]                            NGX_MIN_POOL_SIZE);
[5272]         return NGX_CONF_ERROR;
[5273]     }
[5274] 
[5275]     if (*sp % NGX_POOL_ALIGNMENT) {
[5276]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[5277]                            "the pool size must be a multiple of %uz",
[5278]                            NGX_POOL_ALIGNMENT);
[5279]         return NGX_CONF_ERROR;
[5280]     }
[5281] 
[5282]     return NGX_CONF_OK;
[5283] }
