[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] #include <ngx_http_v2_module.h>
[12] 
[13] 
[14] static ngx_int_t ngx_http_v2_add_variables(ngx_conf_t *cf);
[15] 
[16] static ngx_int_t ngx_http_v2_variable(ngx_http_request_t *r,
[17]     ngx_http_variable_value_t *v, uintptr_t data);
[18] 
[19] static ngx_int_t ngx_http_v2_module_init(ngx_cycle_t *cycle);
[20] 
[21] static void *ngx_http_v2_create_main_conf(ngx_conf_t *cf);
[22] static char *ngx_http_v2_init_main_conf(ngx_conf_t *cf, void *conf);
[23] static void *ngx_http_v2_create_srv_conf(ngx_conf_t *cf);
[24] static char *ngx_http_v2_merge_srv_conf(ngx_conf_t *cf, void *parent,
[25]     void *child);
[26] static void *ngx_http_v2_create_loc_conf(ngx_conf_t *cf);
[27] static char *ngx_http_v2_merge_loc_conf(ngx_conf_t *cf, void *parent,
[28]     void *child);
[29] 
[30] static char *ngx_http_v2_push(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[31] 
[32] static char *ngx_http_v2_recv_buffer_size(ngx_conf_t *cf, void *post,
[33]     void *data);
[34] static char *ngx_http_v2_pool_size(ngx_conf_t *cf, void *post, void *data);
[35] static char *ngx_http_v2_preread_size(ngx_conf_t *cf, void *post, void *data);
[36] static char *ngx_http_v2_streams_index_mask(ngx_conf_t *cf, void *post,
[37]     void *data);
[38] static char *ngx_http_v2_chunk_size(ngx_conf_t *cf, void *post, void *data);
[39] static char *ngx_http_v2_obsolete(ngx_conf_t *cf, ngx_command_t *cmd,
[40]     void *conf);
[41] 
[42] 
[43] static ngx_conf_deprecated_t  ngx_http_v2_recv_timeout_deprecated = {
[44]     ngx_conf_deprecated, "http2_recv_timeout", "client_header_timeout"
[45] };
[46] 
[47] static ngx_conf_deprecated_t  ngx_http_v2_idle_timeout_deprecated = {
[48]     ngx_conf_deprecated, "http2_idle_timeout", "keepalive_timeout"
[49] };
[50] 
[51] static ngx_conf_deprecated_t  ngx_http_v2_max_requests_deprecated = {
[52]     ngx_conf_deprecated, "http2_max_requests", "keepalive_requests"
[53] };
[54] 
[55] static ngx_conf_deprecated_t  ngx_http_v2_max_field_size_deprecated = {
[56]     ngx_conf_deprecated, "http2_max_field_size", "large_client_header_buffers"
[57] };
[58] 
[59] static ngx_conf_deprecated_t  ngx_http_v2_max_header_size_deprecated = {
[60]     ngx_conf_deprecated, "http2_max_header_size", "large_client_header_buffers"
[61] };
[62] 
[63] 
[64] static ngx_conf_post_t  ngx_http_v2_recv_buffer_size_post =
[65]     { ngx_http_v2_recv_buffer_size };
[66] static ngx_conf_post_t  ngx_http_v2_pool_size_post =
[67]     { ngx_http_v2_pool_size };
[68] static ngx_conf_post_t  ngx_http_v2_preread_size_post =
[69]     { ngx_http_v2_preread_size };
[70] static ngx_conf_post_t  ngx_http_v2_streams_index_mask_post =
[71]     { ngx_http_v2_streams_index_mask };
[72] static ngx_conf_post_t  ngx_http_v2_chunk_size_post =
[73]     { ngx_http_v2_chunk_size };
[74] 
[75] 
[76] static ngx_command_t  ngx_http_v2_commands[] = {
[77] 
[78]     { ngx_string("http2_recv_buffer_size"),
[79]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[80]       ngx_conf_set_size_slot,
[81]       NGX_HTTP_MAIN_CONF_OFFSET,
[82]       offsetof(ngx_http_v2_main_conf_t, recv_buffer_size),
[83]       &ngx_http_v2_recv_buffer_size_post },
[84] 
[85]     { ngx_string("http2_pool_size"),
[86]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[87]       ngx_conf_set_size_slot,
[88]       NGX_HTTP_SRV_CONF_OFFSET,
[89]       offsetof(ngx_http_v2_srv_conf_t, pool_size),
[90]       &ngx_http_v2_pool_size_post },
[91] 
[92]     { ngx_string("http2_max_concurrent_streams"),
[93]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[94]       ngx_conf_set_num_slot,
[95]       NGX_HTTP_SRV_CONF_OFFSET,
[96]       offsetof(ngx_http_v2_srv_conf_t, concurrent_streams),
[97]       NULL },
[98] 
[99]     { ngx_string("http2_max_concurrent_pushes"),
[100]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[101]       ngx_conf_set_num_slot,
[102]       NGX_HTTP_SRV_CONF_OFFSET,
[103]       offsetof(ngx_http_v2_srv_conf_t, concurrent_pushes),
[104]       NULL },
[105] 
[106]     { ngx_string("http2_max_requests"),
[107]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[108]       ngx_http_v2_obsolete,
[109]       0,
[110]       0,
[111]       &ngx_http_v2_max_requests_deprecated },
[112] 
[113]     { ngx_string("http2_max_field_size"),
[114]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[115]       ngx_http_v2_obsolete,
[116]       0,
[117]       0,
[118]       &ngx_http_v2_max_field_size_deprecated },
[119] 
[120]     { ngx_string("http2_max_header_size"),
[121]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[122]       ngx_http_v2_obsolete,
[123]       0,
[124]       0,
[125]       &ngx_http_v2_max_header_size_deprecated },
[126] 
[127]     { ngx_string("http2_body_preread_size"),
[128]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[129]       ngx_conf_set_size_slot,
[130]       NGX_HTTP_SRV_CONF_OFFSET,
[131]       offsetof(ngx_http_v2_srv_conf_t, preread_size),
[132]       &ngx_http_v2_preread_size_post },
[133] 
[134]     { ngx_string("http2_streams_index_size"),
[135]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[136]       ngx_conf_set_num_slot,
[137]       NGX_HTTP_SRV_CONF_OFFSET,
[138]       offsetof(ngx_http_v2_srv_conf_t, streams_index_mask),
[139]       &ngx_http_v2_streams_index_mask_post },
[140] 
[141]     { ngx_string("http2_recv_timeout"),
[142]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[143]       ngx_http_v2_obsolete,
[144]       0,
[145]       0,
[146]       &ngx_http_v2_recv_timeout_deprecated },
[147] 
[148]     { ngx_string("http2_idle_timeout"),
[149]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[150]       ngx_http_v2_obsolete,
[151]       0,
[152]       0,
[153]       &ngx_http_v2_idle_timeout_deprecated },
[154] 
[155]     { ngx_string("http2_chunk_size"),
[156]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[157]       ngx_conf_set_size_slot,
[158]       NGX_HTTP_LOC_CONF_OFFSET,
[159]       offsetof(ngx_http_v2_loc_conf_t, chunk_size),
[160]       &ngx_http_v2_chunk_size_post },
[161] 
[162]     { ngx_string("http2_push_preload"),
[163]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[164]       ngx_conf_set_flag_slot,
[165]       NGX_HTTP_LOC_CONF_OFFSET,
[166]       offsetof(ngx_http_v2_loc_conf_t, push_preload),
[167]       NULL },
[168] 
[169]     { ngx_string("http2_push"),
[170]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[171]       ngx_http_v2_push,
[172]       NGX_HTTP_LOC_CONF_OFFSET,
[173]       0,
[174]       NULL },
[175] 
[176]       ngx_null_command
[177] };
[178] 
[179] 
[180] static ngx_http_module_t  ngx_http_v2_module_ctx = {
[181]     ngx_http_v2_add_variables,             /* preconfiguration */
[182]     NULL,                                  /* postconfiguration */
[183] 
[184]     ngx_http_v2_create_main_conf,          /* create main configuration */
[185]     ngx_http_v2_init_main_conf,            /* init main configuration */
[186] 
[187]     ngx_http_v2_create_srv_conf,           /* create server configuration */
[188]     ngx_http_v2_merge_srv_conf,            /* merge server configuration */
[189] 
[190]     ngx_http_v2_create_loc_conf,           /* create location configuration */
[191]     ngx_http_v2_merge_loc_conf             /* merge location configuration */
[192] };
[193] 
[194] 
[195] ngx_module_t  ngx_http_v2_module = {
[196]     NGX_MODULE_V1,
[197]     &ngx_http_v2_module_ctx,               /* module context */
[198]     ngx_http_v2_commands,                  /* module directives */
[199]     NGX_HTTP_MODULE,                       /* module type */
[200]     NULL,                                  /* init master */
[201]     ngx_http_v2_module_init,               /* init module */
[202]     NULL,                                  /* init process */
[203]     NULL,                                  /* init thread */
[204]     NULL,                                  /* exit thread */
[205]     NULL,                                  /* exit process */
[206]     NULL,                                  /* exit master */
[207]     NGX_MODULE_V1_PADDING
[208] };
[209] 
[210] 
[211] static ngx_http_variable_t  ngx_http_v2_vars[] = {
[212] 
[213]     { ngx_string("http2"), NULL,
[214]       ngx_http_v2_variable, 0, 0, 0 },
[215] 
[216]       ngx_http_null_variable
[217] };
[218] 
[219] 
[220] static ngx_int_t
[221] ngx_http_v2_add_variables(ngx_conf_t *cf)
[222] {
[223]     ngx_http_variable_t  *var, *v;
[224] 
[225]     for (v = ngx_http_v2_vars; v->name.len; v++) {
[226]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[227]         if (var == NULL) {
[228]             return NGX_ERROR;
[229]         }
[230] 
[231]         var->get_handler = v->get_handler;
[232]         var->data = v->data;
[233]     }
[234] 
[235]     return NGX_OK;
[236] }
[237] 
[238] 
[239] static ngx_int_t
[240] ngx_http_v2_variable(ngx_http_request_t *r,
[241]     ngx_http_variable_value_t *v, uintptr_t data)
[242] {
[243] 
[244]     if (r->stream) {
[245] #if (NGX_HTTP_SSL)
[246] 
[247]         if (r->connection->ssl) {
[248]             v->len = sizeof("h2") - 1;
[249]             v->valid = 1;
[250]             v->no_cacheable = 0;
[251]             v->not_found = 0;
[252]             v->data = (u_char *) "h2";
[253] 
[254]             return NGX_OK;
[255]         }
[256] 
[257] #endif
[258]         v->len = sizeof("h2c") - 1;
[259]         v->valid = 1;
[260]         v->no_cacheable = 0;
[261]         v->not_found = 0;
[262]         v->data = (u_char *) "h2c";
[263] 
[264]         return NGX_OK;
[265]     }
[266] 
[267]     *v = ngx_http_variable_null_value;
[268] 
[269]     return NGX_OK;
[270] }
[271] 
[272] 
[273] static ngx_int_t
[274] ngx_http_v2_module_init(ngx_cycle_t *cycle)
[275] {
[276]     return NGX_OK;
[277] }
[278] 
[279] 
[280] static void *
[281] ngx_http_v2_create_main_conf(ngx_conf_t *cf)
[282] {
[283]     ngx_http_v2_main_conf_t  *h2mcf;
[284] 
[285]     h2mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v2_main_conf_t));
[286]     if (h2mcf == NULL) {
[287]         return NULL;
[288]     }
[289] 
[290]     h2mcf->recv_buffer_size = NGX_CONF_UNSET_SIZE;
[291] 
[292]     return h2mcf;
[293] }
[294] 
[295] 
[296] static char *
[297] ngx_http_v2_init_main_conf(ngx_conf_t *cf, void *conf)
[298] {
[299]     ngx_http_v2_main_conf_t *h2mcf = conf;
[300] 
[301]     ngx_conf_init_size_value(h2mcf->recv_buffer_size, 256 * 1024);
[302] 
[303]     return NGX_CONF_OK;
[304] }
[305] 
[306] 
[307] static void *
[308] ngx_http_v2_create_srv_conf(ngx_conf_t *cf)
[309] {
[310]     ngx_http_v2_srv_conf_t  *h2scf;
[311] 
[312]     h2scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v2_srv_conf_t));
[313]     if (h2scf == NULL) {
[314]         return NULL;
[315]     }
[316] 
[317]     h2scf->pool_size = NGX_CONF_UNSET_SIZE;
[318] 
[319]     h2scf->concurrent_streams = NGX_CONF_UNSET_UINT;
[320]     h2scf->concurrent_pushes = NGX_CONF_UNSET_UINT;
[321] 
[322]     h2scf->preread_size = NGX_CONF_UNSET_SIZE;
[323] 
[324]     h2scf->streams_index_mask = NGX_CONF_UNSET_UINT;
[325] 
[326]     return h2scf;
[327] }
[328] 
[329] 
[330] static char *
[331] ngx_http_v2_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[332] {
[333]     ngx_http_v2_srv_conf_t *prev = parent;
[334]     ngx_http_v2_srv_conf_t *conf = child;
[335] 
[336]     ngx_conf_merge_size_value(conf->pool_size, prev->pool_size, 4096);
[337] 
[338]     ngx_conf_merge_uint_value(conf->concurrent_streams,
[339]                               prev->concurrent_streams, 128);
[340]     ngx_conf_merge_uint_value(conf->concurrent_pushes,
[341]                               prev->concurrent_pushes, 10);
[342] 
[343]     ngx_conf_merge_size_value(conf->preread_size, prev->preread_size, 65536);
[344] 
[345]     ngx_conf_merge_uint_value(conf->streams_index_mask,
[346]                               prev->streams_index_mask, 32 - 1);
[347] 
[348]     return NGX_CONF_OK;
[349] }
[350] 
[351] 
[352] static void *
[353] ngx_http_v2_create_loc_conf(ngx_conf_t *cf)
[354] {
[355]     ngx_http_v2_loc_conf_t  *h2lcf;
[356] 
[357]     h2lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v2_loc_conf_t));
[358]     if (h2lcf == NULL) {
[359]         return NULL;
[360]     }
[361] 
[362]     /*
[363]      * set by ngx_pcalloc():
[364]      *
[365]      *     h2lcf->pushes = NULL;
[366]      */
[367] 
[368]     h2lcf->chunk_size = NGX_CONF_UNSET_SIZE;
[369] 
[370]     h2lcf->push_preload = NGX_CONF_UNSET;
[371]     h2lcf->push = NGX_CONF_UNSET;
[372] 
[373]     return h2lcf;
[374] }
[375] 
[376] 
[377] static char *
[378] ngx_http_v2_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[379] {
[380]     ngx_http_v2_loc_conf_t *prev = parent;
[381]     ngx_http_v2_loc_conf_t *conf = child;
[382] 
[383]     ngx_conf_merge_size_value(conf->chunk_size, prev->chunk_size, 8 * 1024);
[384] 
[385]     ngx_conf_merge_value(conf->push, prev->push, 1);
[386] 
[387]     if (conf->push && conf->pushes == NULL) {
[388]         conf->pushes = prev->pushes;
[389]     }
[390] 
[391]     ngx_conf_merge_value(conf->push_preload, prev->push_preload, 0);
[392] 
[393]     return NGX_CONF_OK;
[394] }
[395] 
[396] 
[397] static char *
[398] ngx_http_v2_push(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[399] {
[400]     ngx_http_v2_loc_conf_t *h2lcf = conf;
[401] 
[402]     ngx_str_t                         *value;
[403]     ngx_http_complex_value_t          *cv;
[404]     ngx_http_compile_complex_value_t   ccv;
[405] 
[406]     value = cf->args->elts;
[407] 
[408]     if (ngx_strcmp(value[1].data, "off") == 0) {
[409] 
[410]         if (h2lcf->pushes) {
[411]             return "\"off\" parameter cannot be used with URI";
[412]         }
[413] 
[414]         if (h2lcf->push == 0) {
[415]             return "is duplicate";
[416]         }
[417] 
[418]         h2lcf->push = 0;
[419]         return NGX_CONF_OK;
[420]     }
[421] 
[422]     if (h2lcf->push == 0) {
[423]         return "URI cannot be used with \"off\" parameter";
[424]     }
[425] 
[426]     h2lcf->push = 1;
[427] 
[428]     if (h2lcf->pushes == NULL) {
[429]         h2lcf->pushes = ngx_array_create(cf->pool, 1,
[430]                                          sizeof(ngx_http_complex_value_t));
[431]         if (h2lcf->pushes == NULL) {
[432]             return NGX_CONF_ERROR;
[433]         }
[434]     }
[435] 
[436]     cv = ngx_array_push(h2lcf->pushes);
[437]     if (cv == NULL) {
[438]         return NGX_CONF_ERROR;
[439]     }
[440] 
[441]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[442] 
[443]     ccv.cf = cf;
[444]     ccv.value = &value[1];
[445]     ccv.complex_value = cv;
[446] 
[447]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[448]         return NGX_CONF_ERROR;
[449]     }
[450] 
[451]     return NGX_CONF_OK;
[452] }
[453] 
[454] 
[455] static char *
[456] ngx_http_v2_recv_buffer_size(ngx_conf_t *cf, void *post, void *data)
[457] {
[458]     size_t *sp = data;
[459] 
[460]     if (*sp <= 2 * NGX_HTTP_V2_STATE_BUFFER_SIZE) {
[461]         return "value is too small";
[462]     }
[463] 
[464]     return NGX_CONF_OK;
[465] }
[466] 
[467] 
[468] static char *
[469] ngx_http_v2_pool_size(ngx_conf_t *cf, void *post, void *data)
[470] {
[471]     size_t *sp = data;
[472] 
[473]     if (*sp < NGX_MIN_POOL_SIZE) {
[474]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[475]                            "the pool size must be no less than %uz",
[476]                            NGX_MIN_POOL_SIZE);
[477] 
[478]         return NGX_CONF_ERROR;
[479]     }
[480] 
[481]     if (*sp % NGX_POOL_ALIGNMENT) {
[482]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[483]                            "the pool size must be a multiple of %uz",
[484]                            NGX_POOL_ALIGNMENT);
[485] 
[486]         return NGX_CONF_ERROR;
[487]     }
[488] 
[489]     return NGX_CONF_OK;
[490] }
[491] 
[492] 
[493] static char *
[494] ngx_http_v2_preread_size(ngx_conf_t *cf, void *post, void *data)
[495] {
[496]     size_t *sp = data;
[497] 
[498]     if (*sp > NGX_HTTP_V2_MAX_WINDOW) {
[499]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[500]                            "the maximum body preread buffer size is %uz",
[501]                            NGX_HTTP_V2_MAX_WINDOW);
[502] 
[503]         return NGX_CONF_ERROR;
[504]     }
[505] 
[506]     return NGX_CONF_OK;
[507] }
[508] 
[509] 
[510] static char *
[511] ngx_http_v2_streams_index_mask(ngx_conf_t *cf, void *post, void *data)
[512] {
[513]     ngx_uint_t *np = data;
[514] 
[515]     ngx_uint_t  mask;
[516] 
[517]     mask = *np - 1;
[518] 
[519]     if (*np == 0 || (*np & mask)) {
[520]         return "must be a power of two";
[521]     }
[522] 
[523]     *np = mask;
[524] 
[525]     return NGX_CONF_OK;
[526] }
[527] 
[528] 
[529] static char *
[530] ngx_http_v2_chunk_size(ngx_conf_t *cf, void *post, void *data)
[531] {
[532]     size_t *sp = data;
[533] 
[534]     if (*sp == 0) {
[535]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[536]                            "the http2 chunk size cannot be zero");
[537] 
[538]         return NGX_CONF_ERROR;
[539]     }
[540] 
[541]     if (*sp > NGX_HTTP_V2_MAX_FRAME_SIZE) {
[542]         *sp = NGX_HTTP_V2_MAX_FRAME_SIZE;
[543]     }
[544] 
[545]     return NGX_CONF_OK;
[546] }
[547] 
[548] 
[549] static char *
[550] ngx_http_v2_obsolete(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[551] {
[552]     ngx_conf_deprecated_t  *d = cmd->post;
[553] 
[554]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[555]                        "the \"%s\" directive is obsolete, "
[556]                        "use the \"%s\" directive instead",
[557]                        d->old_name, d->new_name);
[558] 
[559]     return NGX_CONF_OK;
[560] }
