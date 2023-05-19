[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] typedef struct {
[14]     ngx_addr_t                      *addr;
[15]     ngx_stream_complex_value_t      *value;
[16] #if (NGX_HAVE_TRANSPARENT_PROXY)
[17]     ngx_uint_t                       transparent; /* unsigned  transparent:1; */
[18] #endif
[19] } ngx_stream_upstream_local_t;
[20] 
[21] 
[22] typedef struct {
[23]     ngx_msec_t                       connect_timeout;
[24]     ngx_msec_t                       timeout;
[25]     ngx_msec_t                       next_upstream_timeout;
[26]     size_t                           buffer_size;
[27]     ngx_stream_complex_value_t      *upload_rate;
[28]     ngx_stream_complex_value_t      *download_rate;
[29]     ngx_uint_t                       requests;
[30]     ngx_uint_t                       responses;
[31]     ngx_uint_t                       next_upstream_tries;
[32]     ngx_flag_t                       next_upstream;
[33]     ngx_flag_t                       proxy_protocol;
[34]     ngx_flag_t                       half_close;
[35]     ngx_stream_upstream_local_t     *local;
[36]     ngx_flag_t                       socket_keepalive;
[37] 
[38] #if (NGX_STREAM_SSL)
[39]     ngx_flag_t                       ssl_enable;
[40]     ngx_flag_t                       ssl_session_reuse;
[41]     ngx_uint_t                       ssl_protocols;
[42]     ngx_str_t                        ssl_ciphers;
[43]     ngx_stream_complex_value_t      *ssl_name;
[44]     ngx_flag_t                       ssl_server_name;
[45] 
[46]     ngx_flag_t                       ssl_verify;
[47]     ngx_uint_t                       ssl_verify_depth;
[48]     ngx_str_t                        ssl_trusted_certificate;
[49]     ngx_str_t                        ssl_crl;
[50]     ngx_stream_complex_value_t      *ssl_certificate;
[51]     ngx_stream_complex_value_t      *ssl_certificate_key;
[52]     ngx_array_t                     *ssl_passwords;
[53]     ngx_array_t                     *ssl_conf_commands;
[54] 
[55]     ngx_ssl_t                       *ssl;
[56] #endif
[57] 
[58]     ngx_stream_upstream_srv_conf_t  *upstream;
[59]     ngx_stream_complex_value_t      *upstream_value;
[60] } ngx_stream_proxy_srv_conf_t;
[61] 
[62] 
[63] static void ngx_stream_proxy_handler(ngx_stream_session_t *s);
[64] static ngx_int_t ngx_stream_proxy_eval(ngx_stream_session_t *s,
[65]     ngx_stream_proxy_srv_conf_t *pscf);
[66] static ngx_int_t ngx_stream_proxy_set_local(ngx_stream_session_t *s,
[67]     ngx_stream_upstream_t *u, ngx_stream_upstream_local_t *local);
[68] static void ngx_stream_proxy_connect(ngx_stream_session_t *s);
[69] static void ngx_stream_proxy_init_upstream(ngx_stream_session_t *s);
[70] static void ngx_stream_proxy_resolve_handler(ngx_resolver_ctx_t *ctx);
[71] static void ngx_stream_proxy_upstream_handler(ngx_event_t *ev);
[72] static void ngx_stream_proxy_downstream_handler(ngx_event_t *ev);
[73] static void ngx_stream_proxy_process_connection(ngx_event_t *ev,
[74]     ngx_uint_t from_upstream);
[75] static void ngx_stream_proxy_connect_handler(ngx_event_t *ev);
[76] static ngx_int_t ngx_stream_proxy_test_connect(ngx_connection_t *c);
[77] static void ngx_stream_proxy_process(ngx_stream_session_t *s,
[78]     ngx_uint_t from_upstream, ngx_uint_t do_write);
[79] static ngx_int_t ngx_stream_proxy_test_finalize(ngx_stream_session_t *s,
[80]     ngx_uint_t from_upstream);
[81] static void ngx_stream_proxy_next_upstream(ngx_stream_session_t *s);
[82] static void ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);
[83] static u_char *ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf,
[84]     size_t len);
[85] 
[86] static void *ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf);
[87] static char *ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
[88]     void *child);
[89] static char *ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
[90]     void *conf);
[91] static char *ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd,
[92]     void *conf);
[93] 
[94] #if (NGX_STREAM_SSL)
[95] 
[96] static ngx_int_t ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s);
[97] static char *ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf,
[98]     ngx_command_t *cmd, void *conf);
[99] static char *ngx_stream_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[100]     void *data);
[101] static void ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s);
[102] static void ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc);
[103] static void ngx_stream_proxy_ssl_save_session(ngx_connection_t *c);
[104] static ngx_int_t ngx_stream_proxy_ssl_name(ngx_stream_session_t *s);
[105] static ngx_int_t ngx_stream_proxy_ssl_certificate(ngx_stream_session_t *s);
[106] static ngx_int_t ngx_stream_proxy_merge_ssl(ngx_conf_t *cf,
[107]     ngx_stream_proxy_srv_conf_t *conf, ngx_stream_proxy_srv_conf_t *prev);
[108] static ngx_int_t ngx_stream_proxy_set_ssl(ngx_conf_t *cf,
[109]     ngx_stream_proxy_srv_conf_t *pscf);
[110] 
[111] 
[112] static ngx_conf_bitmask_t  ngx_stream_proxy_ssl_protocols[] = {
[113]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[114]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[115]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[116]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[117]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[118]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[119]     { ngx_null_string, 0 }
[120] };
[121] 
[122] static ngx_conf_post_t  ngx_stream_proxy_ssl_conf_command_post =
[123]     { ngx_stream_proxy_ssl_conf_command_check };
[124] 
[125] #endif
[126] 
[127] 
[128] static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_downstream_buffer = {
[129]     ngx_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
[130] };
[131] 
[132] static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_upstream_buffer = {
[133]     ngx_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
[134] };
[135] 
[136] 
[137] static ngx_command_t  ngx_stream_proxy_commands[] = {
[138] 
[139]     { ngx_string("proxy_pass"),
[140]       NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[141]       ngx_stream_proxy_pass,
[142]       NGX_STREAM_SRV_CONF_OFFSET,
[143]       0,
[144]       NULL },
[145] 
[146]     { ngx_string("proxy_bind"),
[147]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE12,
[148]       ngx_stream_proxy_bind,
[149]       NGX_STREAM_SRV_CONF_OFFSET,
[150]       0,
[151]       NULL },
[152] 
[153]     { ngx_string("proxy_socket_keepalive"),
[154]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[155]       ngx_conf_set_flag_slot,
[156]       NGX_STREAM_SRV_CONF_OFFSET,
[157]       offsetof(ngx_stream_proxy_srv_conf_t, socket_keepalive),
[158]       NULL },
[159] 
[160]     { ngx_string("proxy_connect_timeout"),
[161]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[162]       ngx_conf_set_msec_slot,
[163]       NGX_STREAM_SRV_CONF_OFFSET,
[164]       offsetof(ngx_stream_proxy_srv_conf_t, connect_timeout),
[165]       NULL },
[166] 
[167]     { ngx_string("proxy_timeout"),
[168]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[169]       ngx_conf_set_msec_slot,
[170]       NGX_STREAM_SRV_CONF_OFFSET,
[171]       offsetof(ngx_stream_proxy_srv_conf_t, timeout),
[172]       NULL },
[173] 
[174]     { ngx_string("proxy_buffer_size"),
[175]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[176]       ngx_conf_set_size_slot,
[177]       NGX_STREAM_SRV_CONF_OFFSET,
[178]       offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
[179]       NULL },
[180] 
[181]     { ngx_string("proxy_downstream_buffer"),
[182]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[183]       ngx_conf_set_size_slot,
[184]       NGX_STREAM_SRV_CONF_OFFSET,
[185]       offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
[186]       &ngx_conf_deprecated_proxy_downstream_buffer },
[187] 
[188]     { ngx_string("proxy_upstream_buffer"),
[189]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[190]       ngx_conf_set_size_slot,
[191]       NGX_STREAM_SRV_CONF_OFFSET,
[192]       offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
[193]       &ngx_conf_deprecated_proxy_upstream_buffer },
[194] 
[195]     { ngx_string("proxy_upload_rate"),
[196]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[197]       ngx_stream_set_complex_value_size_slot,
[198]       NGX_STREAM_SRV_CONF_OFFSET,
[199]       offsetof(ngx_stream_proxy_srv_conf_t, upload_rate),
[200]       NULL },
[201] 
[202]     { ngx_string("proxy_download_rate"),
[203]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[204]       ngx_stream_set_complex_value_size_slot,
[205]       NGX_STREAM_SRV_CONF_OFFSET,
[206]       offsetof(ngx_stream_proxy_srv_conf_t, download_rate),
[207]       NULL },
[208] 
[209]     { ngx_string("proxy_requests"),
[210]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[211]       ngx_conf_set_num_slot,
[212]       NGX_STREAM_SRV_CONF_OFFSET,
[213]       offsetof(ngx_stream_proxy_srv_conf_t, requests),
[214]       NULL },
[215] 
[216]     { ngx_string("proxy_responses"),
[217]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[218]       ngx_conf_set_num_slot,
[219]       NGX_STREAM_SRV_CONF_OFFSET,
[220]       offsetof(ngx_stream_proxy_srv_conf_t, responses),
[221]       NULL },
[222] 
[223]     { ngx_string("proxy_next_upstream"),
[224]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[225]       ngx_conf_set_flag_slot,
[226]       NGX_STREAM_SRV_CONF_OFFSET,
[227]       offsetof(ngx_stream_proxy_srv_conf_t, next_upstream),
[228]       NULL },
[229] 
[230]     { ngx_string("proxy_next_upstream_tries"),
[231]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[232]       ngx_conf_set_num_slot,
[233]       NGX_STREAM_SRV_CONF_OFFSET,
[234]       offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_tries),
[235]       NULL },
[236] 
[237]     { ngx_string("proxy_next_upstream_timeout"),
[238]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[239]       ngx_conf_set_msec_slot,
[240]       NGX_STREAM_SRV_CONF_OFFSET,
[241]       offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_timeout),
[242]       NULL },
[243] 
[244]     { ngx_string("proxy_protocol"),
[245]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[246]       ngx_conf_set_flag_slot,
[247]       NGX_STREAM_SRV_CONF_OFFSET,
[248]       offsetof(ngx_stream_proxy_srv_conf_t, proxy_protocol),
[249]       NULL },
[250] 
[251]     { ngx_string("proxy_half_close"),
[252]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[253]       ngx_conf_set_flag_slot,
[254]       NGX_STREAM_SRV_CONF_OFFSET,
[255]       offsetof(ngx_stream_proxy_srv_conf_t, half_close),
[256]       NULL },
[257] 
[258] #if (NGX_STREAM_SSL)
[259] 
[260]     { ngx_string("proxy_ssl"),
[261]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[262]       ngx_conf_set_flag_slot,
[263]       NGX_STREAM_SRV_CONF_OFFSET,
[264]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_enable),
[265]       NULL },
[266] 
[267]     { ngx_string("proxy_ssl_session_reuse"),
[268]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[269]       ngx_conf_set_flag_slot,
[270]       NGX_STREAM_SRV_CONF_OFFSET,
[271]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_session_reuse),
[272]       NULL },
[273] 
[274]     { ngx_string("proxy_ssl_protocols"),
[275]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[276]       ngx_conf_set_bitmask_slot,
[277]       NGX_STREAM_SRV_CONF_OFFSET,
[278]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_protocols),
[279]       &ngx_stream_proxy_ssl_protocols },
[280] 
[281]     { ngx_string("proxy_ssl_ciphers"),
[282]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[283]       ngx_conf_set_str_slot,
[284]       NGX_STREAM_SRV_CONF_OFFSET,
[285]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_ciphers),
[286]       NULL },
[287] 
[288]     { ngx_string("proxy_ssl_name"),
[289]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[290]       ngx_stream_set_complex_value_slot,
[291]       NGX_STREAM_SRV_CONF_OFFSET,
[292]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_name),
[293]       NULL },
[294] 
[295]     { ngx_string("proxy_ssl_server_name"),
[296]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[297]       ngx_conf_set_flag_slot,
[298]       NGX_STREAM_SRV_CONF_OFFSET,
[299]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_server_name),
[300]       NULL },
[301] 
[302]     { ngx_string("proxy_ssl_verify"),
[303]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[304]       ngx_conf_set_flag_slot,
[305]       NGX_STREAM_SRV_CONF_OFFSET,
[306]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify),
[307]       NULL },
[308] 
[309]     { ngx_string("proxy_ssl_verify_depth"),
[310]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[311]       ngx_conf_set_num_slot,
[312]       NGX_STREAM_SRV_CONF_OFFSET,
[313]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify_depth),
[314]       NULL },
[315] 
[316]     { ngx_string("proxy_ssl_trusted_certificate"),
[317]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[318]       ngx_conf_set_str_slot,
[319]       NGX_STREAM_SRV_CONF_OFFSET,
[320]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_trusted_certificate),
[321]       NULL },
[322] 
[323]     { ngx_string("proxy_ssl_crl"),
[324]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[325]       ngx_conf_set_str_slot,
[326]       NGX_STREAM_SRV_CONF_OFFSET,
[327]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_crl),
[328]       NULL },
[329] 
[330]     { ngx_string("proxy_ssl_certificate"),
[331]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[332]       ngx_stream_set_complex_value_zero_slot,
[333]       NGX_STREAM_SRV_CONF_OFFSET,
[334]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate),
[335]       NULL },
[336] 
[337]     { ngx_string("proxy_ssl_certificate_key"),
[338]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[339]       ngx_stream_set_complex_value_zero_slot,
[340]       NGX_STREAM_SRV_CONF_OFFSET,
[341]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate_key),
[342]       NULL },
[343] 
[344]     { ngx_string("proxy_ssl_password_file"),
[345]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[346]       ngx_stream_proxy_ssl_password_file,
[347]       NGX_STREAM_SRV_CONF_OFFSET,
[348]       0,
[349]       NULL },
[350] 
[351]     { ngx_string("proxy_ssl_conf_command"),
[352]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
[353]       ngx_conf_set_keyval_slot,
[354]       NGX_STREAM_SRV_CONF_OFFSET,
[355]       offsetof(ngx_stream_proxy_srv_conf_t, ssl_conf_commands),
[356]       &ngx_stream_proxy_ssl_conf_command_post },
[357] 
[358] #endif
[359] 
[360]       ngx_null_command
[361] };
[362] 
[363] 
[364] static ngx_stream_module_t  ngx_stream_proxy_module_ctx = {
[365]     NULL,                                  /* preconfiguration */
[366]     NULL,                                  /* postconfiguration */
[367] 
[368]     NULL,                                  /* create main configuration */
[369]     NULL,                                  /* init main configuration */
[370] 
[371]     ngx_stream_proxy_create_srv_conf,      /* create server configuration */
[372]     ngx_stream_proxy_merge_srv_conf        /* merge server configuration */
[373] };
[374] 
[375] 
[376] ngx_module_t  ngx_stream_proxy_module = {
[377]     NGX_MODULE_V1,
[378]     &ngx_stream_proxy_module_ctx,          /* module context */
[379]     ngx_stream_proxy_commands,             /* module directives */
[380]     NGX_STREAM_MODULE,                     /* module type */
[381]     NULL,                                  /* init master */
[382]     NULL,                                  /* init module */
[383]     NULL,                                  /* init process */
[384]     NULL,                                  /* init thread */
[385]     NULL,                                  /* exit thread */
[386]     NULL,                                  /* exit process */
[387]     NULL,                                  /* exit master */
[388]     NGX_MODULE_V1_PADDING
[389] };
[390] 
[391] 
[392] static void
[393] ngx_stream_proxy_handler(ngx_stream_session_t *s)
[394] {
[395]     u_char                           *p;
[396]     ngx_str_t                        *host;
[397]     ngx_uint_t                        i;
[398]     ngx_connection_t                 *c;
[399]     ngx_resolver_ctx_t               *ctx, temp;
[400]     ngx_stream_upstream_t            *u;
[401]     ngx_stream_core_srv_conf_t       *cscf;
[402]     ngx_stream_proxy_srv_conf_t      *pscf;
[403]     ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
[404]     ngx_stream_upstream_main_conf_t  *umcf;
[405] 
[406]     c = s->connection;
[407] 
[408]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[409] 
[410]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[411]                    "proxy connection handler");
[412] 
[413]     u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
[414]     if (u == NULL) {
[415]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[416]         return;
[417]     }
[418] 
[419]     s->upstream = u;
[420] 
[421]     s->log_handler = ngx_stream_proxy_log_error;
[422] 
[423]     u->requests = 1;
[424] 
[425]     u->peer.log = c->log;
[426]     u->peer.log_error = NGX_ERROR_ERR;
[427] 
[428]     if (ngx_stream_proxy_set_local(s, u, pscf->local) != NGX_OK) {
[429]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[430]         return;
[431]     }
[432] 
[433]     if (pscf->socket_keepalive) {
[434]         u->peer.so_keepalive = 1;
[435]     }
[436] 
[437]     u->peer.type = c->type;
[438]     u->start_sec = ngx_time();
[439] 
[440]     c->write->handler = ngx_stream_proxy_downstream_handler;
[441]     c->read->handler = ngx_stream_proxy_downstream_handler;
[442] 
[443]     s->upstream_states = ngx_array_create(c->pool, 1,
[444]                                           sizeof(ngx_stream_upstream_state_t));
[445]     if (s->upstream_states == NULL) {
[446]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[447]         return;
[448]     }
[449] 
[450]     p = ngx_pnalloc(c->pool, pscf->buffer_size);
[451]     if (p == NULL) {
[452]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[453]         return;
[454]     }
[455] 
[456]     u->downstream_buf.start = p;
[457]     u->downstream_buf.end = p + pscf->buffer_size;
[458]     u->downstream_buf.pos = p;
[459]     u->downstream_buf.last = p;
[460] 
[461]     if (c->read->ready) {
[462]         ngx_post_event(c->read, &ngx_posted_events);
[463]     }
[464] 
[465]     if (pscf->upstream_value) {
[466]         if (ngx_stream_proxy_eval(s, pscf) != NGX_OK) {
[467]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[468]             return;
[469]         }
[470]     }
[471] 
[472]     if (u->resolved == NULL) {
[473] 
[474]         uscf = pscf->upstream;
[475] 
[476]     } else {
[477] 
[478] #if (NGX_STREAM_SSL)
[479]         u->ssl_name = u->resolved->host;
[480] #endif
[481] 
[482]         host = &u->resolved->host;
[483] 
[484]         umcf = ngx_stream_get_module_main_conf(s, ngx_stream_upstream_module);
[485] 
[486]         uscfp = umcf->upstreams.elts;
[487] 
[488]         for (i = 0; i < umcf->upstreams.nelts; i++) {
[489] 
[490]             uscf = uscfp[i];
[491] 
[492]             if (uscf->host.len == host->len
[493]                 && ((uscf->port == 0 && u->resolved->no_port)
[494]                      || uscf->port == u->resolved->port)
[495]                 && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
[496]             {
[497]                 goto found;
[498]             }
[499]         }
[500] 
[501]         if (u->resolved->sockaddr) {
[502] 
[503]             if (u->resolved->port == 0
[504]                 && u->resolved->sockaddr->sa_family != AF_UNIX)
[505]             {
[506]                 ngx_log_error(NGX_LOG_ERR, c->log, 0,
[507]                               "no port in upstream \"%V\"", host);
[508]                 ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[509]                 return;
[510]             }
[511] 
[512]             if (ngx_stream_upstream_create_round_robin_peer(s, u->resolved)
[513]                 != NGX_OK)
[514]             {
[515]                 ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[516]                 return;
[517]             }
[518] 
[519]             ngx_stream_proxy_connect(s);
[520] 
[521]             return;
[522]         }
[523] 
[524]         if (u->resolved->port == 0) {
[525]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[526]                           "no port in upstream \"%V\"", host);
[527]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[528]             return;
[529]         }
[530] 
[531]         temp.name = *host;
[532] 
[533]         cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
[534] 
[535]         ctx = ngx_resolve_start(cscf->resolver, &temp);
[536]         if (ctx == NULL) {
[537]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[538]             return;
[539]         }
[540] 
[541]         if (ctx == NGX_NO_RESOLVER) {
[542]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[543]                           "no resolver defined to resolve %V", host);
[544]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[545]             return;
[546]         }
[547] 
[548]         ctx->name = *host;
[549]         ctx->handler = ngx_stream_proxy_resolve_handler;
[550]         ctx->data = s;
[551]         ctx->timeout = cscf->resolver_timeout;
[552] 
[553]         u->resolved->ctx = ctx;
[554] 
[555]         if (ngx_resolve_name(ctx) != NGX_OK) {
[556]             u->resolved->ctx = NULL;
[557]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[558]             return;
[559]         }
[560] 
[561]         return;
[562]     }
[563] 
[564] found:
[565] 
[566]     if (uscf == NULL) {
[567]         ngx_log_error(NGX_LOG_ALERT, c->log, 0, "no upstream configuration");
[568]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[569]         return;
[570]     }
[571] 
[572]     u->upstream = uscf;
[573] 
[574] #if (NGX_STREAM_SSL)
[575]     u->ssl_name = uscf->host;
[576] #endif
[577] 
[578]     if (uscf->peer.init(s, uscf) != NGX_OK) {
[579]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[580]         return;
[581]     }
[582] 
[583]     u->peer.start_time = ngx_current_msec;
[584] 
[585]     if (pscf->next_upstream_tries
[586]         && u->peer.tries > pscf->next_upstream_tries)
[587]     {
[588]         u->peer.tries = pscf->next_upstream_tries;
[589]     }
[590] 
[591]     ngx_stream_proxy_connect(s);
[592] }
[593] 
[594] 
[595] static ngx_int_t
[596] ngx_stream_proxy_eval(ngx_stream_session_t *s,
[597]     ngx_stream_proxy_srv_conf_t *pscf)
[598] {
[599]     ngx_str_t               host;
[600]     ngx_url_t               url;
[601]     ngx_stream_upstream_t  *u;
[602] 
[603]     if (ngx_stream_complex_value(s, pscf->upstream_value, &host) != NGX_OK) {
[604]         return NGX_ERROR;
[605]     }
[606] 
[607]     ngx_memzero(&url, sizeof(ngx_url_t));
[608] 
[609]     url.url = host;
[610]     url.no_resolve = 1;
[611] 
[612]     if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
[613]         if (url.err) {
[614]             ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[615]                           "%s in upstream \"%V\"", url.err, &url.url);
[616]         }
[617] 
[618]         return NGX_ERROR;
[619]     }
[620] 
[621]     u = s->upstream;
[622] 
[623]     u->resolved = ngx_pcalloc(s->connection->pool,
[624]                               sizeof(ngx_stream_upstream_resolved_t));
[625]     if (u->resolved == NULL) {
[626]         return NGX_ERROR;
[627]     }
[628] 
[629]     if (url.addrs) {
[630]         u->resolved->sockaddr = url.addrs[0].sockaddr;
[631]         u->resolved->socklen = url.addrs[0].socklen;
[632]         u->resolved->name = url.addrs[0].name;
[633]         u->resolved->naddrs = 1;
[634]     }
[635] 
[636]     u->resolved->host = url.host;
[637]     u->resolved->port = url.port;
[638]     u->resolved->no_port = url.no_port;
[639] 
[640]     return NGX_OK;
[641] }
[642] 
[643] 
[644] static ngx_int_t
[645] ngx_stream_proxy_set_local(ngx_stream_session_t *s, ngx_stream_upstream_t *u,
[646]     ngx_stream_upstream_local_t *local)
[647] {
[648]     ngx_int_t    rc;
[649]     ngx_str_t    val;
[650]     ngx_addr_t  *addr;
[651] 
[652]     if (local == NULL) {
[653]         u->peer.local = NULL;
[654]         return NGX_OK;
[655]     }
[656] 
[657] #if (NGX_HAVE_TRANSPARENT_PROXY)
[658]     u->peer.transparent = local->transparent;
[659] #endif
[660] 
[661]     if (local->value == NULL) {
[662]         u->peer.local = local->addr;
[663]         return NGX_OK;
[664]     }
[665] 
[666]     if (ngx_stream_complex_value(s, local->value, &val) != NGX_OK) {
[667]         return NGX_ERROR;
[668]     }
[669] 
[670]     if (val.len == 0) {
[671]         return NGX_OK;
[672]     }
[673] 
[674]     addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
[675]     if (addr == NULL) {
[676]         return NGX_ERROR;
[677]     }
[678] 
[679]     rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
[680]     if (rc == NGX_ERROR) {
[681]         return NGX_ERROR;
[682]     }
[683] 
[684]     if (rc != NGX_OK) {
[685]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[686]                       "invalid local address \"%V\"", &val);
[687]         return NGX_OK;
[688]     }
[689] 
[690]     addr->name = val;
[691]     u->peer.local = addr;
[692] 
[693]     return NGX_OK;
[694] }
[695] 
[696] 
[697] static void
[698] ngx_stream_proxy_connect(ngx_stream_session_t *s)
[699] {
[700]     ngx_int_t                     rc;
[701]     ngx_connection_t             *c, *pc;
[702]     ngx_stream_upstream_t        *u;
[703]     ngx_stream_proxy_srv_conf_t  *pscf;
[704] 
[705]     c = s->connection;
[706] 
[707]     c->log->action = "connecting to upstream";
[708] 
[709]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[710] 
[711]     u = s->upstream;
[712] 
[713]     u->connected = 0;
[714]     u->proxy_protocol = pscf->proxy_protocol;
[715] 
[716]     if (u->state) {
[717]         u->state->response_time = ngx_current_msec - u->start_time;
[718]     }
[719] 
[720]     u->state = ngx_array_push(s->upstream_states);
[721]     if (u->state == NULL) {
[722]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[723]         return;
[724]     }
[725] 
[726]     ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));
[727] 
[728]     u->start_time = ngx_current_msec;
[729] 
[730]     u->state->connect_time = (ngx_msec_t) -1;
[731]     u->state->first_byte_time = (ngx_msec_t) -1;
[732]     u->state->response_time = (ngx_msec_t) -1;
[733] 
[734]     rc = ngx_event_connect_peer(&u->peer);
[735] 
[736]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);
[737] 
[738]     if (rc == NGX_ERROR) {
[739]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[740]         return;
[741]     }
[742] 
[743]     u->state->peer = u->peer.name;
[744] 
[745]     if (rc == NGX_BUSY) {
[746]         ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
[747]         ngx_stream_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
[748]         return;
[749]     }
[750] 
[751]     if (rc == NGX_DECLINED) {
[752]         ngx_stream_proxy_next_upstream(s);
[753]         return;
[754]     }
[755] 
[756]     /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */
[757] 
[758]     pc = u->peer.connection;
[759] 
[760]     pc->data = s;
[761]     pc->log = c->log;
[762]     pc->pool = c->pool;
[763]     pc->read->log = c->log;
[764]     pc->write->log = c->log;
[765] 
[766]     if (rc != NGX_AGAIN) {
[767]         ngx_stream_proxy_init_upstream(s);
[768]         return;
[769]     }
[770] 
[771]     pc->read->handler = ngx_stream_proxy_connect_handler;
[772]     pc->write->handler = ngx_stream_proxy_connect_handler;
[773] 
[774]     ngx_add_timer(pc->write, pscf->connect_timeout);
[775] }
[776] 
[777] 
[778] static void
[779] ngx_stream_proxy_init_upstream(ngx_stream_session_t *s)
[780] {
[781]     u_char                       *p;
[782]     ngx_chain_t                  *cl;
[783]     ngx_connection_t             *c, *pc;
[784]     ngx_log_handler_pt            handler;
[785]     ngx_stream_upstream_t        *u;
[786]     ngx_stream_core_srv_conf_t   *cscf;
[787]     ngx_stream_proxy_srv_conf_t  *pscf;
[788] 
[789]     u = s->upstream;
[790]     pc = u->peer.connection;
[791] 
[792]     cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
[793] 
[794]     if (pc->type == SOCK_STREAM
[795]         && cscf->tcp_nodelay
[796]         && ngx_tcp_nodelay(pc) != NGX_OK)
[797]     {
[798]         ngx_stream_proxy_next_upstream(s);
[799]         return;
[800]     }
[801] 
[802]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[803] 
[804] #if (NGX_STREAM_SSL)
[805] 
[806]     if (pc->type == SOCK_STREAM && pscf->ssl_enable) {
[807] 
[808]         if (u->proxy_protocol) {
[809]             if (ngx_stream_proxy_send_proxy_protocol(s) != NGX_OK) {
[810]                 return;
[811]             }
[812] 
[813]             u->proxy_protocol = 0;
[814]         }
[815] 
[816]         if (pc->ssl == NULL) {
[817]             ngx_stream_proxy_ssl_init_connection(s);
[818]             return;
[819]         }
[820]     }
[821] 
[822] #endif
[823] 
[824]     c = s->connection;
[825] 
[826]     if (c->log->log_level >= NGX_LOG_INFO) {
[827]         ngx_str_t  str;
[828]         u_char     addr[NGX_SOCKADDR_STRLEN];
[829] 
[830]         str.len = NGX_SOCKADDR_STRLEN;
[831]         str.data = addr;
[832] 
[833]         if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
[834]             handler = c->log->handler;
[835]             c->log->handler = NULL;
[836] 
[837]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[838]                           "%sproxy %V connected to %V",
[839]                           pc->type == SOCK_DGRAM ? "udp " : "",
[840]                           &str, u->peer.name);
[841] 
[842]             c->log->handler = handler;
[843]         }
[844]     }
[845] 
[846]     u->state->connect_time = ngx_current_msec - u->start_time;
[847] 
[848]     if (u->peer.notify) {
[849]         u->peer.notify(&u->peer, u->peer.data,
[850]                        NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
[851]     }
[852] 
[853]     if (u->upstream_buf.start == NULL) {
[854]         p = ngx_pnalloc(c->pool, pscf->buffer_size);
[855]         if (p == NULL) {
[856]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[857]             return;
[858]         }
[859] 
[860]         u->upstream_buf.start = p;
[861]         u->upstream_buf.end = p + pscf->buffer_size;
[862]         u->upstream_buf.pos = p;
[863]         u->upstream_buf.last = p;
[864]     }
[865] 
[866]     if (c->buffer && c->buffer->pos <= c->buffer->last) {
[867]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[868]                        "stream proxy add preread buffer: %uz",
[869]                        c->buffer->last - c->buffer->pos);
[870] 
[871]         cl = ngx_chain_get_free_buf(c->pool, &u->free);
[872]         if (cl == NULL) {
[873]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[874]             return;
[875]         }
[876] 
[877]         *cl->buf = *c->buffer;
[878] 
[879]         cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;
[880]         cl->buf->temporary = (cl->buf->pos == cl->buf->last) ? 0 : 1;
[881]         cl->buf->flush = 1;
[882] 
[883]         cl->next = u->upstream_out;
[884]         u->upstream_out = cl;
[885]     }
[886] 
[887]     if (u->proxy_protocol) {
[888]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[889]                        "stream proxy add PROXY protocol header");
[890] 
[891]         cl = ngx_chain_get_free_buf(c->pool, &u->free);
[892]         if (cl == NULL) {
[893]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[894]             return;
[895]         }
[896] 
[897]         p = ngx_pnalloc(c->pool, NGX_PROXY_PROTOCOL_V1_MAX_HEADER);
[898]         if (p == NULL) {
[899]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[900]             return;
[901]         }
[902] 
[903]         cl->buf->pos = p;
[904] 
[905]         p = ngx_proxy_protocol_write(c, p,
[906]                                      p + NGX_PROXY_PROTOCOL_V1_MAX_HEADER);
[907]         if (p == NULL) {
[908]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[909]             return;
[910]         }
[911] 
[912]         cl->buf->last = p;
[913]         cl->buf->temporary = 1;
[914]         cl->buf->flush = 0;
[915]         cl->buf->last_buf = 0;
[916]         cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;
[917] 
[918]         cl->next = u->upstream_out;
[919]         u->upstream_out = cl;
[920] 
[921]         u->proxy_protocol = 0;
[922]     }
[923] 
[924]     u->upload_rate = ngx_stream_complex_value_size(s, pscf->upload_rate, 0);
[925]     u->download_rate = ngx_stream_complex_value_size(s, pscf->download_rate, 0);
[926] 
[927]     u->connected = 1;
[928] 
[929]     pc->read->handler = ngx_stream_proxy_upstream_handler;
[930]     pc->write->handler = ngx_stream_proxy_upstream_handler;
[931] 
[932]     if (pc->read->ready) {
[933]         ngx_post_event(pc->read, &ngx_posted_events);
[934]     }
[935] 
[936]     ngx_stream_proxy_process(s, 0, 1);
[937] }
[938] 
[939] 
[940] #if (NGX_STREAM_SSL)
[941] 
[942] static ngx_int_t
[943] ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s)
[944] {
[945]     u_char                       *p;
[946]     ssize_t                       n, size;
[947]     ngx_connection_t             *c, *pc;
[948]     ngx_stream_upstream_t        *u;
[949]     ngx_stream_proxy_srv_conf_t  *pscf;
[950]     u_char                        buf[NGX_PROXY_PROTOCOL_V1_MAX_HEADER];
[951] 
[952]     c = s->connection;
[953] 
[954]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[955]                    "stream proxy send PROXY protocol header");
[956] 
[957]     p = ngx_proxy_protocol_write(c, buf,
[958]                                  buf + NGX_PROXY_PROTOCOL_V1_MAX_HEADER);
[959]     if (p == NULL) {
[960]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[961]         return NGX_ERROR;
[962]     }
[963] 
[964]     u = s->upstream;
[965] 
[966]     pc = u->peer.connection;
[967] 
[968]     size = p - buf;
[969] 
[970]     n = pc->send(pc, buf, size);
[971] 
[972]     if (n == NGX_AGAIN) {
[973]         if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
[974]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[975]             return NGX_ERROR;
[976]         }
[977] 
[978]         pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[979] 
[980]         ngx_add_timer(pc->write, pscf->timeout);
[981] 
[982]         pc->write->handler = ngx_stream_proxy_connect_handler;
[983] 
[984]         return NGX_AGAIN;
[985]     }
[986] 
[987]     if (n == NGX_ERROR) {
[988]         ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[989]         return NGX_ERROR;
[990]     }
[991] 
[992]     if (n != size) {
[993] 
[994]         /*
[995]          * PROXY protocol specification:
[996]          * The sender must always ensure that the header
[997]          * is sent at once, so that the transport layer
[998]          * maintains atomicity along the path to the receiver.
[999]          */
[1000] 
[1001]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1002]                       "could not send PROXY protocol header at once");
[1003] 
[1004]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1005] 
[1006]         return NGX_ERROR;
[1007]     }
[1008] 
[1009]     return NGX_OK;
[1010] }
[1011] 
[1012] 
[1013] static char *
[1014] ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
[1015]     void *conf)
[1016] {
[1017]     ngx_stream_proxy_srv_conf_t *pscf = conf;
[1018] 
[1019]     ngx_str_t  *value;
[1020] 
[1021]     if (pscf->ssl_passwords != NGX_CONF_UNSET_PTR) {
[1022]         return "is duplicate";
[1023]     }
[1024] 
[1025]     value = cf->args->elts;
[1026] 
[1027]     pscf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);
[1028] 
[1029]     if (pscf->ssl_passwords == NULL) {
[1030]         return NGX_CONF_ERROR;
[1031]     }
[1032] 
[1033]     return NGX_CONF_OK;
[1034] }
[1035] 
[1036] 
[1037] static char *
[1038] ngx_stream_proxy_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[1039] {
[1040] #ifndef SSL_CONF_FLAG_FILE
[1041]     return "is not supported on this platform";
[1042] #else
[1043]     return NGX_CONF_OK;
[1044] #endif
[1045] }
[1046] 
[1047] 
[1048] static void
[1049] ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s)
[1050] {
[1051]     ngx_int_t                     rc;
[1052]     ngx_connection_t             *pc;
[1053]     ngx_stream_upstream_t        *u;
[1054]     ngx_stream_proxy_srv_conf_t  *pscf;
[1055] 
[1056]     u = s->upstream;
[1057] 
[1058]     pc = u->peer.connection;
[1059] 
[1060]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1061] 
[1062]     if (ngx_ssl_create_connection(pscf->ssl, pc, NGX_SSL_BUFFER|NGX_SSL_CLIENT)
[1063]         != NGX_OK)
[1064]     {
[1065]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1066]         return;
[1067]     }
[1068] 
[1069]     if (pscf->ssl_server_name || pscf->ssl_verify) {
[1070]         if (ngx_stream_proxy_ssl_name(s) != NGX_OK) {
[1071]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1072]             return;
[1073]         }
[1074]     }
[1075] 
[1076]     if (pscf->ssl_certificate
[1077]         && pscf->ssl_certificate->value.len
[1078]         && (pscf->ssl_certificate->lengths
[1079]             || pscf->ssl_certificate_key->lengths))
[1080]     {
[1081]         if (ngx_stream_proxy_ssl_certificate(s) != NGX_OK) {
[1082]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1083]             return;
[1084]         }
[1085]     }
[1086] 
[1087]     if (pscf->ssl_session_reuse) {
[1088]         pc->ssl->save_session = ngx_stream_proxy_ssl_save_session;
[1089] 
[1090]         if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
[1091]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1092]             return;
[1093]         }
[1094]     }
[1095] 
[1096]     s->connection->log->action = "SSL handshaking to upstream";
[1097] 
[1098]     rc = ngx_ssl_handshake(pc);
[1099] 
[1100]     if (rc == NGX_AGAIN) {
[1101] 
[1102]         if (!pc->write->timer_set) {
[1103]             ngx_add_timer(pc->write, pscf->connect_timeout);
[1104]         }
[1105] 
[1106]         pc->ssl->handler = ngx_stream_proxy_ssl_handshake;
[1107]         return;
[1108]     }
[1109] 
[1110]     ngx_stream_proxy_ssl_handshake(pc);
[1111] }
[1112] 
[1113] 
[1114] static void
[1115] ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc)
[1116] {
[1117]     long                          rc;
[1118]     ngx_stream_session_t         *s;
[1119]     ngx_stream_upstream_t        *u;
[1120]     ngx_stream_proxy_srv_conf_t  *pscf;
[1121] 
[1122]     s = pc->data;
[1123] 
[1124]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1125] 
[1126]     if (pc->ssl->handshaked) {
[1127] 
[1128]         if (pscf->ssl_verify) {
[1129]             rc = SSL_get_verify_result(pc->ssl->connection);
[1130] 
[1131]             if (rc != X509_V_OK) {
[1132]                 ngx_log_error(NGX_LOG_ERR, pc->log, 0,
[1133]                               "upstream SSL certificate verify error: (%l:%s)",
[1134]                               rc, X509_verify_cert_error_string(rc));
[1135]                 goto failed;
[1136]             }
[1137] 
[1138]             u = s->upstream;
[1139] 
[1140]             if (ngx_ssl_check_host(pc, &u->ssl_name) != NGX_OK) {
[1141]                 ngx_log_error(NGX_LOG_ERR, pc->log, 0,
[1142]                               "upstream SSL certificate does not match \"%V\"",
[1143]                               &u->ssl_name);
[1144]                 goto failed;
[1145]             }
[1146]         }
[1147] 
[1148]         if (pc->write->timer_set) {
[1149]             ngx_del_timer(pc->write);
[1150]         }
[1151] 
[1152]         ngx_stream_proxy_init_upstream(s);
[1153] 
[1154]         return;
[1155]     }
[1156] 
[1157] failed:
[1158] 
[1159]     ngx_stream_proxy_next_upstream(s);
[1160] }
[1161] 
[1162] 
[1163] static void
[1164] ngx_stream_proxy_ssl_save_session(ngx_connection_t *c)
[1165] {
[1166]     ngx_stream_session_t   *s;
[1167]     ngx_stream_upstream_t  *u;
[1168] 
[1169]     s = c->data;
[1170]     u = s->upstream;
[1171] 
[1172]     u->peer.save_session(&u->peer, u->peer.data);
[1173] }
[1174] 
[1175] 
[1176] static ngx_int_t
[1177] ngx_stream_proxy_ssl_name(ngx_stream_session_t *s)
[1178] {
[1179]     u_char                       *p, *last;
[1180]     ngx_str_t                     name;
[1181]     ngx_stream_upstream_t        *u;
[1182]     ngx_stream_proxy_srv_conf_t  *pscf;
[1183] 
[1184]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1185] 
[1186]     u = s->upstream;
[1187] 
[1188]     if (pscf->ssl_name) {
[1189]         if (ngx_stream_complex_value(s, pscf->ssl_name, &name) != NGX_OK) {
[1190]             return NGX_ERROR;
[1191]         }
[1192] 
[1193]     } else {
[1194]         name = u->ssl_name;
[1195]     }
[1196] 
[1197]     if (name.len == 0) {
[1198]         goto done;
[1199]     }
[1200] 
[1201]     /*
[1202]      * ssl name here may contain port, strip it for compatibility
[1203]      * with the http module
[1204]      */
[1205] 
[1206]     p = name.data;
[1207]     last = name.data + name.len;
[1208] 
[1209]     if (*p == '[') {
[1210]         p = ngx_strlchr(p, last, ']');
[1211] 
[1212]         if (p == NULL) {
[1213]             p = name.data;
[1214]         }
[1215]     }
[1216] 
[1217]     p = ngx_strlchr(p, last, ':');
[1218] 
[1219]     if (p != NULL) {
[1220]         name.len = p - name.data;
[1221]     }
[1222] 
[1223]     if (!pscf->ssl_server_name) {
[1224]         goto done;
[1225]     }
[1226] 
[1227] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[1228] 
[1229]     /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */
[1230] 
[1231]     if (name.len == 0 || *name.data == '[') {
[1232]         goto done;
[1233]     }
[1234] 
[1235]     if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
[1236]         goto done;
[1237]     }
[1238] 
[1239]     /*
[1240]      * SSL_set_tlsext_host_name() needs a null-terminated string,
[1241]      * hence we explicitly null-terminate name here
[1242]      */
[1243] 
[1244]     p = ngx_pnalloc(s->connection->pool, name.len + 1);
[1245]     if (p == NULL) {
[1246]         return NGX_ERROR;
[1247]     }
[1248] 
[1249]     (void) ngx_cpystrn(p, name.data, name.len + 1);
[1250] 
[1251]     name.data = p;
[1252] 
[1253]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1254]                    "upstream SSL server name: \"%s\"", name.data);
[1255] 
[1256]     if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
[1257]                                  (char *) name.data)
[1258]         == 0)
[1259]     {
[1260]         ngx_ssl_error(NGX_LOG_ERR, s->connection->log, 0,
[1261]                       "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
[1262]         return NGX_ERROR;
[1263]     }
[1264] 
[1265] #endif
[1266] 
[1267] done:
[1268] 
[1269]     u->ssl_name = name;
[1270] 
[1271]     return NGX_OK;
[1272] }
[1273] 
[1274] 
[1275] static ngx_int_t
[1276] ngx_stream_proxy_ssl_certificate(ngx_stream_session_t *s)
[1277] {
[1278]     ngx_str_t                     cert, key;
[1279]     ngx_connection_t             *c;
[1280]     ngx_stream_proxy_srv_conf_t  *pscf;
[1281] 
[1282]     c = s->upstream->peer.connection;
[1283] 
[1284]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1285] 
[1286]     if (ngx_stream_complex_value(s, pscf->ssl_certificate, &cert)
[1287]         != NGX_OK)
[1288]     {
[1289]         return NGX_ERROR;
[1290]     }
[1291] 
[1292]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[1293]                    "stream upstream ssl cert: \"%s\"", cert.data);
[1294] 
[1295]     if (*cert.data == '\0') {
[1296]         return NGX_OK;
[1297]     }
[1298] 
[1299]     if (ngx_stream_complex_value(s, pscf->ssl_certificate_key, &key)
[1300]         != NGX_OK)
[1301]     {
[1302]         return NGX_ERROR;
[1303]     }
[1304] 
[1305]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[1306]                    "stream upstream ssl key: \"%s\"", key.data);
[1307] 
[1308]     if (ngx_ssl_connection_certificate(c, c->pool, &cert, &key,
[1309]                                        pscf->ssl_passwords)
[1310]         != NGX_OK)
[1311]     {
[1312]         return NGX_ERROR;
[1313]     }
[1314] 
[1315]     return NGX_OK;
[1316] }
[1317] 
[1318] #endif
[1319] 
[1320] 
[1321] static void
[1322] ngx_stream_proxy_downstream_handler(ngx_event_t *ev)
[1323] {
[1324]     ngx_stream_proxy_process_connection(ev, ev->write);
[1325] }
[1326] 
[1327] 
[1328] static void
[1329] ngx_stream_proxy_resolve_handler(ngx_resolver_ctx_t *ctx)
[1330] {
[1331]     ngx_stream_session_t            *s;
[1332]     ngx_stream_upstream_t           *u;
[1333]     ngx_stream_proxy_srv_conf_t     *pscf;
[1334]     ngx_stream_upstream_resolved_t  *ur;
[1335] 
[1336]     s = ctx->data;
[1337] 
[1338]     u = s->upstream;
[1339]     ur = u->resolved;
[1340] 
[1341]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1342]                    "stream upstream resolve");
[1343] 
[1344]     if (ctx->state) {
[1345]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[1346]                       "%V could not be resolved (%i: %s)",
[1347]                       &ctx->name, ctx->state,
[1348]                       ngx_resolver_strerror(ctx->state));
[1349] 
[1350]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1351]         return;
[1352]     }
[1353] 
[1354]     ur->naddrs = ctx->naddrs;
[1355]     ur->addrs = ctx->addrs;
[1356] 
[1357] #if (NGX_DEBUG)
[1358]     {
[1359]     u_char      text[NGX_SOCKADDR_STRLEN];
[1360]     ngx_str_t   addr;
[1361]     ngx_uint_t  i;
[1362] 
[1363]     addr.data = text;
[1364] 
[1365]     for (i = 0; i < ctx->naddrs; i++) {
[1366]         addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
[1367]                                  text, NGX_SOCKADDR_STRLEN, 0);
[1368] 
[1369]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1370]                        "name was resolved to %V", &addr);
[1371]     }
[1372]     }
[1373] #endif
[1374] 
[1375]     if (ngx_stream_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
[1376]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1377]         return;
[1378]     }
[1379] 
[1380]     ngx_resolve_name_done(ctx);
[1381]     ur->ctx = NULL;
[1382] 
[1383]     u->peer.start_time = ngx_current_msec;
[1384] 
[1385]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1386] 
[1387]     if (pscf->next_upstream_tries
[1388]         && u->peer.tries > pscf->next_upstream_tries)
[1389]     {
[1390]         u->peer.tries = pscf->next_upstream_tries;
[1391]     }
[1392] 
[1393]     ngx_stream_proxy_connect(s);
[1394] }
[1395] 
[1396] 
[1397] static void
[1398] ngx_stream_proxy_upstream_handler(ngx_event_t *ev)
[1399] {
[1400]     ngx_stream_proxy_process_connection(ev, !ev->write);
[1401] }
[1402] 
[1403] 
[1404] static void
[1405] ngx_stream_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
[1406] {
[1407]     ngx_connection_t             *c, *pc;
[1408]     ngx_log_handler_pt            handler;
[1409]     ngx_stream_session_t         *s;
[1410]     ngx_stream_upstream_t        *u;
[1411]     ngx_stream_proxy_srv_conf_t  *pscf;
[1412] 
[1413]     c = ev->data;
[1414]     s = c->data;
[1415]     u = s->upstream;
[1416] 
[1417]     if (c->close) {
[1418]         ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
[1419]         ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1420]         return;
[1421]     }
[1422] 
[1423]     c = s->connection;
[1424]     pc = u->peer.connection;
[1425] 
[1426]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1427] 
[1428]     if (ev->timedout) {
[1429]         ev->timedout = 0;
[1430] 
[1431]         if (ev->delayed) {
[1432]             ev->delayed = 0;
[1433] 
[1434]             if (!ev->ready) {
[1435]                 if (ngx_handle_read_event(ev, 0) != NGX_OK) {
[1436]                     ngx_stream_proxy_finalize(s,
[1437]                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
[1438]                     return;
[1439]                 }
[1440] 
[1441]                 if (u->connected && !c->read->delayed && !pc->read->delayed) {
[1442]                     ngx_add_timer(c->write, pscf->timeout);
[1443]                 }
[1444] 
[1445]                 return;
[1446]             }
[1447] 
[1448]         } else {
[1449]             if (s->connection->type == SOCK_DGRAM) {
[1450] 
[1451]                 if (pscf->responses == NGX_MAX_INT32_VALUE
[1452]                     || (u->responses >= pscf->responses * u->requests))
[1453]                 {
[1454] 
[1455]                     /*
[1456]                      * successfully terminate timed out UDP session
[1457]                      * if expected number of responses was received
[1458]                      */
[1459] 
[1460]                     handler = c->log->handler;
[1461]                     c->log->handler = NULL;
[1462] 
[1463]                     ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1464]                                   "udp timed out"
[1465]                                   ", packets from/to client:%ui/%ui"
[1466]                                   ", bytes from/to client:%O/%O"
[1467]                                   ", bytes from/to upstream:%O/%O",
[1468]                                   u->requests, u->responses,
[1469]                                   s->received, c->sent, u->received,
[1470]                                   pc ? pc->sent : 0);
[1471] 
[1472]                     c->log->handler = handler;
[1473] 
[1474]                     ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1475]                     return;
[1476]                 }
[1477] 
[1478]                 ngx_connection_error(pc, NGX_ETIMEDOUT, "upstream timed out");
[1479] 
[1480]                 pc->read->error = 1;
[1481] 
[1482]                 ngx_stream_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
[1483] 
[1484]                 return;
[1485]             }
[1486] 
[1487]             ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
[1488] 
[1489]             ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1490] 
[1491]             return;
[1492]         }
[1493] 
[1494]     } else if (ev->delayed) {
[1495] 
[1496]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[1497]                        "stream connection delayed");
[1498] 
[1499]         if (ngx_handle_read_event(ev, 0) != NGX_OK) {
[1500]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1501]         }
[1502] 
[1503]         return;
[1504]     }
[1505] 
[1506]     if (from_upstream && !u->connected) {
[1507]         return;
[1508]     }
[1509] 
[1510]     ngx_stream_proxy_process(s, from_upstream, ev->write);
[1511] }
[1512] 
[1513] 
[1514] static void
[1515] ngx_stream_proxy_connect_handler(ngx_event_t *ev)
[1516] {
[1517]     ngx_connection_t      *c;
[1518]     ngx_stream_session_t  *s;
[1519] 
[1520]     c = ev->data;
[1521]     s = c->data;
[1522] 
[1523]     if (ev->timedout) {
[1524]         ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
[1525]         ngx_stream_proxy_next_upstream(s);
[1526]         return;
[1527]     }
[1528] 
[1529]     ngx_del_timer(c->write);
[1530] 
[1531]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[1532]                    "stream proxy connect upstream");
[1533] 
[1534]     if (ngx_stream_proxy_test_connect(c) != NGX_OK) {
[1535]         ngx_stream_proxy_next_upstream(s);
[1536]         return;
[1537]     }
[1538] 
[1539]     ngx_stream_proxy_init_upstream(s);
[1540] }
[1541] 
[1542] 
[1543] static ngx_int_t
[1544] ngx_stream_proxy_test_connect(ngx_connection_t *c)
[1545] {
[1546]     int        err;
[1547]     socklen_t  len;
[1548] 
[1549] #if (NGX_HAVE_KQUEUE)
[1550] 
[1551]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
[1552]         err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;
[1553] 
[1554]         if (err) {
[1555]             (void) ngx_connection_error(c, err,
[1556]                                     "kevent() reported that connect() failed");
[1557]             return NGX_ERROR;
[1558]         }
[1559] 
[1560]     } else
[1561] #endif
[1562]     {
[1563]         err = 0;
[1564]         len = sizeof(int);
[1565] 
[1566]         /*
[1567]          * BSDs and Linux return 0 and set a pending error in err
[1568]          * Solaris returns -1 and sets errno
[1569]          */
[1570] 
[1571]         if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
[1572]             == -1)
[1573]         {
[1574]             err = ngx_socket_errno;
[1575]         }
[1576] 
[1577]         if (err) {
[1578]             (void) ngx_connection_error(c, err, "connect() failed");
[1579]             return NGX_ERROR;
[1580]         }
[1581]     }
[1582] 
[1583]     return NGX_OK;
[1584] }
[1585] 
[1586] 
[1587] static void
[1588] ngx_stream_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
[1589]     ngx_uint_t do_write)
[1590] {
[1591]     char                         *recv_action, *send_action;
[1592]     off_t                        *received, limit;
[1593]     size_t                        size, limit_rate;
[1594]     ssize_t                       n;
[1595]     ngx_buf_t                    *b;
[1596]     ngx_int_t                     rc;
[1597]     ngx_uint_t                    flags, *packets;
[1598]     ngx_msec_t                    delay;
[1599]     ngx_chain_t                  *cl, **ll, **out, **busy;
[1600]     ngx_connection_t             *c, *pc, *src, *dst;
[1601]     ngx_log_handler_pt            handler;
[1602]     ngx_stream_upstream_t        *u;
[1603]     ngx_stream_proxy_srv_conf_t  *pscf;
[1604] 
[1605]     u = s->upstream;
[1606] 
[1607]     c = s->connection;
[1608]     pc = u->connected ? u->peer.connection : NULL;
[1609] 
[1610]     if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {
[1611] 
[1612]         /* socket is already closed on worker shutdown */
[1613] 
[1614]         handler = c->log->handler;
[1615]         c->log->handler = NULL;
[1616] 
[1617]         ngx_log_error(NGX_LOG_INFO, c->log, 0, "disconnected on shutdown");
[1618] 
[1619]         c->log->handler = handler;
[1620] 
[1621]         ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1622]         return;
[1623]     }
[1624] 
[1625]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1626] 
[1627]     if (from_upstream) {
[1628]         src = pc;
[1629]         dst = c;
[1630]         b = &u->upstream_buf;
[1631]         limit_rate = u->download_rate;
[1632]         received = &u->received;
[1633]         packets = &u->responses;
[1634]         out = &u->downstream_out;
[1635]         busy = &u->downstream_busy;
[1636]         recv_action = "proxying and reading from upstream";
[1637]         send_action = "proxying and sending to client";
[1638] 
[1639]     } else {
[1640]         src = c;
[1641]         dst = pc;
[1642]         b = &u->downstream_buf;
[1643]         limit_rate = u->upload_rate;
[1644]         received = &s->received;
[1645]         packets = &u->requests;
[1646]         out = &u->upstream_out;
[1647]         busy = &u->upstream_busy;
[1648]         recv_action = "proxying and reading from client";
[1649]         send_action = "proxying and sending to upstream";
[1650]     }
[1651] 
[1652]     for ( ;; ) {
[1653] 
[1654]         if (do_write && dst) {
[1655] 
[1656]             if (*out || *busy || dst->buffered) {
[1657]                 c->log->action = send_action;
[1658] 
[1659]                 rc = ngx_stream_top_filter(s, *out, from_upstream);
[1660] 
[1661]                 if (rc == NGX_ERROR) {
[1662]                     ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1663]                     return;
[1664]                 }
[1665] 
[1666]                 ngx_chain_update_chains(c->pool, &u->free, busy, out,
[1667]                                       (ngx_buf_tag_t) &ngx_stream_proxy_module);
[1668] 
[1669]                 if (*busy == NULL) {
[1670]                     b->pos = b->start;
[1671]                     b->last = b->start;
[1672]                 }
[1673]             }
[1674]         }
[1675] 
[1676]         size = b->end - b->last;
[1677] 
[1678]         if (size && src->read->ready && !src->read->delayed) {
[1679] 
[1680]             if (limit_rate) {
[1681]                 limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
[1682]                         - *received;
[1683] 
[1684]                 if (limit <= 0) {
[1685]                     src->read->delayed = 1;
[1686]                     delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
[1687]                     ngx_add_timer(src->read, delay);
[1688]                     break;
[1689]                 }
[1690] 
[1691]                 if (c->type == SOCK_STREAM && (off_t) size > limit) {
[1692]                     size = (size_t) limit;
[1693]                 }
[1694]             }
[1695] 
[1696]             c->log->action = recv_action;
[1697] 
[1698]             n = src->recv(src, b->last, size);
[1699] 
[1700]             if (n == NGX_AGAIN) {
[1701]                 break;
[1702]             }
[1703] 
[1704]             if (n == NGX_ERROR) {
[1705]                 src->read->eof = 1;
[1706]                 n = 0;
[1707]             }
[1708] 
[1709]             if (n >= 0) {
[1710]                 if (limit_rate) {
[1711]                     delay = (ngx_msec_t) (n * 1000 / limit_rate);
[1712] 
[1713]                     if (delay > 0) {
[1714]                         src->read->delayed = 1;
[1715]                         ngx_add_timer(src->read, delay);
[1716]                     }
[1717]                 }
[1718] 
[1719]                 if (from_upstream) {
[1720]                     if (u->state->first_byte_time == (ngx_msec_t) -1) {
[1721]                         u->state->first_byte_time = ngx_current_msec
[1722]                                                     - u->start_time;
[1723]                     }
[1724]                 }
[1725] 
[1726]                 for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }
[1727] 
[1728]                 cl = ngx_chain_get_free_buf(c->pool, &u->free);
[1729]                 if (cl == NULL) {
[1730]                     ngx_stream_proxy_finalize(s,
[1731]                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
[1732]                     return;
[1733]                 }
[1734] 
[1735]                 *ll = cl;
[1736] 
[1737]                 cl->buf->pos = b->last;
[1738]                 cl->buf->last = b->last + n;
[1739]                 cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;
[1740] 
[1741]                 cl->buf->temporary = (n ? 1 : 0);
[1742]                 cl->buf->last_buf = src->read->eof;
[1743]                 cl->buf->flush = !src->read->eof;
[1744] 
[1745]                 (*packets)++;
[1746]                 *received += n;
[1747]                 b->last += n;
[1748]                 do_write = 1;
[1749] 
[1750]                 continue;
[1751]             }
[1752]         }
[1753] 
[1754]         break;
[1755]     }
[1756] 
[1757]     c->log->action = "proxying connection";
[1758] 
[1759]     if (ngx_stream_proxy_test_finalize(s, from_upstream) == NGX_OK) {
[1760]         return;
[1761]     }
[1762] 
[1763]     flags = src->read->eof ? NGX_CLOSE_EVENT : 0;
[1764] 
[1765]     if (ngx_handle_read_event(src->read, flags) != NGX_OK) {
[1766]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1767]         return;
[1768]     }
[1769] 
[1770]     if (dst) {
[1771] 
[1772]         if (dst->type == SOCK_STREAM && pscf->half_close
[1773]             && src->read->eof && !u->half_closed && !dst->buffered)
[1774]         {
[1775]             if (ngx_shutdown_socket(dst->fd, NGX_WRITE_SHUTDOWN) == -1) {
[1776]                 ngx_connection_error(c, ngx_socket_errno,
[1777]                                      ngx_shutdown_socket_n " failed");
[1778] 
[1779]                 ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1780]                 return;
[1781]             }
[1782] 
[1783]             u->half_closed = 1;
[1784]             ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1785]                            "stream proxy %s socket shutdown",
[1786]                            from_upstream ? "client" : "upstream");
[1787]         }
[1788] 
[1789]         if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
[1790]             ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1791]             return;
[1792]         }
[1793] 
[1794]         if (!c->read->delayed && !pc->read->delayed) {
[1795]             ngx_add_timer(c->write, pscf->timeout);
[1796] 
[1797]         } else if (c->write->timer_set) {
[1798]             ngx_del_timer(c->write);
[1799]         }
[1800]     }
[1801] }
[1802] 
[1803] 
[1804] static ngx_int_t
[1805] ngx_stream_proxy_test_finalize(ngx_stream_session_t *s,
[1806]     ngx_uint_t from_upstream)
[1807] {
[1808]     ngx_connection_t             *c, *pc;
[1809]     ngx_log_handler_pt            handler;
[1810]     ngx_stream_upstream_t        *u;
[1811]     ngx_stream_proxy_srv_conf_t  *pscf;
[1812] 
[1813]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1814] 
[1815]     c = s->connection;
[1816]     u = s->upstream;
[1817]     pc = u->connected ? u->peer.connection : NULL;
[1818] 
[1819]     if (c->type == SOCK_DGRAM) {
[1820] 
[1821]         if (pscf->requests && u->requests < pscf->requests) {
[1822]             return NGX_DECLINED;
[1823]         }
[1824] 
[1825]         if (pscf->requests) {
[1826]             ngx_delete_udp_connection(c);
[1827]         }
[1828] 
[1829]         if (pscf->responses == NGX_MAX_INT32_VALUE
[1830]             || u->responses < pscf->responses * u->requests)
[1831]         {
[1832]             return NGX_DECLINED;
[1833]         }
[1834] 
[1835]         if (pc == NULL || c->buffered || pc->buffered) {
[1836]             return NGX_DECLINED;
[1837]         }
[1838] 
[1839]         handler = c->log->handler;
[1840]         c->log->handler = NULL;
[1841] 
[1842]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1843]                       "udp done"
[1844]                       ", packets from/to client:%ui/%ui"
[1845]                       ", bytes from/to client:%O/%O"
[1846]                       ", bytes from/to upstream:%O/%O",
[1847]                       u->requests, u->responses,
[1848]                       s->received, c->sent, u->received, pc ? pc->sent : 0);
[1849] 
[1850]         c->log->handler = handler;
[1851] 
[1852]         ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1853] 
[1854]         return NGX_OK;
[1855]     }
[1856] 
[1857]     /* c->type == SOCK_STREAM */
[1858] 
[1859]     if (pc == NULL
[1860]         || (!c->read->eof && !pc->read->eof)
[1861]         || (!c->read->eof && c->buffered)
[1862]         || (!pc->read->eof && pc->buffered))
[1863]     {
[1864]         return NGX_DECLINED;
[1865]     }
[1866] 
[1867]     if (pscf->half_close) {
[1868]         /* avoid closing live connections until both read ends get EOF */
[1869]         if (!(c->read->eof && pc->read->eof && !c->buffered && !pc->buffered)) {
[1870]              return NGX_DECLINED;
[1871]         }
[1872]     }
[1873] 
[1874]     handler = c->log->handler;
[1875]     c->log->handler = NULL;
[1876] 
[1877]     ngx_log_error(NGX_LOG_INFO, c->log, 0,
[1878]                   "%s disconnected"
[1879]                   ", bytes from/to client:%O/%O"
[1880]                   ", bytes from/to upstream:%O/%O",
[1881]                   from_upstream ? "upstream" : "client",
[1882]                   s->received, c->sent, u->received, pc ? pc->sent : 0);
[1883] 
[1884]     c->log->handler = handler;
[1885] 
[1886]     ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
[1887] 
[1888]     return NGX_OK;
[1889] }
[1890] 
[1891] 
[1892] static void
[1893] ngx_stream_proxy_next_upstream(ngx_stream_session_t *s)
[1894] {
[1895]     ngx_msec_t                    timeout;
[1896]     ngx_connection_t             *pc;
[1897]     ngx_stream_upstream_t        *u;
[1898]     ngx_stream_proxy_srv_conf_t  *pscf;
[1899] 
[1900]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1901]                    "stream proxy next upstream");
[1902] 
[1903]     u = s->upstream;
[1904]     pc = u->peer.connection;
[1905] 
[1906]     if (pc && pc->buffered) {
[1907]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[1908]                       "buffered data on next upstream");
[1909]         ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[1910]         return;
[1911]     }
[1912] 
[1913]     if (s->connection->type == SOCK_DGRAM) {
[1914]         u->upstream_out = NULL;
[1915]     }
[1916] 
[1917]     if (u->peer.sockaddr) {
[1918]         u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
[1919]         u->peer.sockaddr = NULL;
[1920]     }
[1921] 
[1922]     pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);
[1923] 
[1924]     timeout = pscf->next_upstream_timeout;
[1925] 
[1926]     if (u->peer.tries == 0
[1927]         || !pscf->next_upstream
[1928]         || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
[1929]     {
[1930]         ngx_stream_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
[1931]         return;
[1932]     }
[1933] 
[1934]     if (pc) {
[1935]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1936]                        "close proxy upstream connection: %d", pc->fd);
[1937] 
[1938] #if (NGX_STREAM_SSL)
[1939]         if (pc->ssl) {
[1940]             pc->ssl->no_wait_shutdown = 1;
[1941]             pc->ssl->no_send_shutdown = 1;
[1942] 
[1943]             (void) ngx_ssl_shutdown(pc);
[1944]         }
[1945] #endif
[1946] 
[1947]         u->state->bytes_received = u->received;
[1948]         u->state->bytes_sent = pc->sent;
[1949] 
[1950]         ngx_close_connection(pc);
[1951]         u->peer.connection = NULL;
[1952]     }
[1953] 
[1954]     ngx_stream_proxy_connect(s);
[1955] }
[1956] 
[1957] 
[1958] static void
[1959] ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
[1960] {
[1961]     ngx_uint_t              state;
[1962]     ngx_connection_t       *pc;
[1963]     ngx_stream_upstream_t  *u;
[1964] 
[1965]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1966]                    "finalize stream proxy: %i", rc);
[1967] 
[1968]     u = s->upstream;
[1969] 
[1970]     if (u == NULL) {
[1971]         goto noupstream;
[1972]     }
[1973] 
[1974]     if (u->resolved && u->resolved->ctx) {
[1975]         ngx_resolve_name_done(u->resolved->ctx);
[1976]         u->resolved->ctx = NULL;
[1977]     }
[1978] 
[1979]     pc = u->peer.connection;
[1980] 
[1981]     if (u->state) {
[1982]         if (u->state->response_time == (ngx_msec_t) -1) {
[1983]             u->state->response_time = ngx_current_msec - u->start_time;
[1984]         }
[1985] 
[1986]         if (pc) {
[1987]             u->state->bytes_received = u->received;
[1988]             u->state->bytes_sent = pc->sent;
[1989]         }
[1990]     }
[1991] 
[1992]     if (u->peer.free && u->peer.sockaddr) {
[1993]         state = 0;
[1994] 
[1995]         if (pc && pc->type == SOCK_DGRAM
[1996]             && (pc->read->error || pc->write->error))
[1997]         {
[1998]             state = NGX_PEER_FAILED;
[1999]         }
[2000] 
[2001]         u->peer.free(&u->peer, u->peer.data, state);
[2002]         u->peer.sockaddr = NULL;
[2003]     }
[2004] 
[2005]     if (pc) {
[2006]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[2007]                        "close stream proxy upstream connection: %d", pc->fd);
[2008] 
[2009] #if (NGX_STREAM_SSL)
[2010]         if (pc->ssl) {
[2011]             pc->ssl->no_wait_shutdown = 1;
[2012]             (void) ngx_ssl_shutdown(pc);
[2013]         }
[2014] #endif
[2015] 
[2016]         ngx_close_connection(pc);
[2017]         u->peer.connection = NULL;
[2018]     }
[2019] 
[2020] noupstream:
[2021] 
[2022]     ngx_stream_finalize_session(s, rc);
[2023] }
[2024] 
[2025] 
[2026] static u_char *
[2027] ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
[2028] {
[2029]     u_char                 *p;
[2030]     ngx_connection_t       *pc;
[2031]     ngx_stream_session_t   *s;
[2032]     ngx_stream_upstream_t  *u;
[2033] 
[2034]     s = log->data;
[2035] 
[2036]     u = s->upstream;
[2037] 
[2038]     p = buf;
[2039] 
[2040]     if (u->peer.name) {
[2041]         p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
[2042]         len -= p - buf;
[2043]     }
[2044] 
[2045]     pc = u->peer.connection;
[2046] 
[2047]     p = ngx_snprintf(p, len,
[2048]                      ", bytes from/to client:%O/%O"
[2049]                      ", bytes from/to upstream:%O/%O",
[2050]                      s->received, s->connection->sent,
[2051]                      u->received, pc ? pc->sent : 0);
[2052] 
[2053]     return p;
[2054] }
[2055] 
[2056] 
[2057] static void *
[2058] ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf)
[2059] {
[2060]     ngx_stream_proxy_srv_conf_t  *conf;
[2061] 
[2062]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_proxy_srv_conf_t));
[2063]     if (conf == NULL) {
[2064]         return NULL;
[2065]     }
[2066] 
[2067]     /*
[2068]      * set by ngx_pcalloc():
[2069]      *
[2070]      *     conf->ssl_protocols = 0;
[2071]      *     conf->ssl_ciphers = { 0, NULL };
[2072]      *     conf->ssl_trusted_certificate = { 0, NULL };
[2073]      *     conf->ssl_crl = { 0, NULL };
[2074]      *
[2075]      *     conf->ssl = NULL;
[2076]      *     conf->upstream = NULL;
[2077]      *     conf->upstream_value = NULL;
[2078]      */
[2079] 
[2080]     conf->connect_timeout = NGX_CONF_UNSET_MSEC;
[2081]     conf->timeout = NGX_CONF_UNSET_MSEC;
[2082]     conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[2083]     conf->buffer_size = NGX_CONF_UNSET_SIZE;
[2084]     conf->upload_rate = NGX_CONF_UNSET_PTR;
[2085]     conf->download_rate = NGX_CONF_UNSET_PTR;
[2086]     conf->requests = NGX_CONF_UNSET_UINT;
[2087]     conf->responses = NGX_CONF_UNSET_UINT;
[2088]     conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
[2089]     conf->next_upstream = NGX_CONF_UNSET;
[2090]     conf->proxy_protocol = NGX_CONF_UNSET;
[2091]     conf->local = NGX_CONF_UNSET_PTR;
[2092]     conf->socket_keepalive = NGX_CONF_UNSET;
[2093]     conf->half_close = NGX_CONF_UNSET;
[2094] 
[2095] #if (NGX_STREAM_SSL)
[2096]     conf->ssl_enable = NGX_CONF_UNSET;
[2097]     conf->ssl_session_reuse = NGX_CONF_UNSET;
[2098]     conf->ssl_name = NGX_CONF_UNSET_PTR;
[2099]     conf->ssl_server_name = NGX_CONF_UNSET;
[2100]     conf->ssl_verify = NGX_CONF_UNSET;
[2101]     conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
[2102]     conf->ssl_certificate = NGX_CONF_UNSET_PTR;
[2103]     conf->ssl_certificate_key = NGX_CONF_UNSET_PTR;
[2104]     conf->ssl_passwords = NGX_CONF_UNSET_PTR;
[2105]     conf->ssl_conf_commands = NGX_CONF_UNSET_PTR;
[2106] #endif
[2107] 
[2108]     return conf;
[2109] }
[2110] 
[2111] 
[2112] static char *
[2113] ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[2114] {
[2115]     ngx_stream_proxy_srv_conf_t *prev = parent;
[2116]     ngx_stream_proxy_srv_conf_t *conf = child;
[2117] 
[2118]     ngx_conf_merge_msec_value(conf->connect_timeout,
[2119]                               prev->connect_timeout, 60000);
[2120] 
[2121]     ngx_conf_merge_msec_value(conf->timeout,
[2122]                               prev->timeout, 10 * 60000);
[2123] 
[2124]     ngx_conf_merge_msec_value(conf->next_upstream_timeout,
[2125]                               prev->next_upstream_timeout, 0);
[2126] 
[2127]     ngx_conf_merge_size_value(conf->buffer_size,
[2128]                               prev->buffer_size, 16384);
[2129] 
[2130]     ngx_conf_merge_ptr_value(conf->upload_rate, prev->upload_rate, NULL);
[2131] 
[2132]     ngx_conf_merge_ptr_value(conf->download_rate, prev->download_rate, NULL);
[2133] 
[2134]     ngx_conf_merge_uint_value(conf->requests,
[2135]                               prev->requests, 0);
[2136] 
[2137]     ngx_conf_merge_uint_value(conf->responses,
[2138]                               prev->responses, NGX_MAX_INT32_VALUE);
[2139] 
[2140]     ngx_conf_merge_uint_value(conf->next_upstream_tries,
[2141]                               prev->next_upstream_tries, 0);
[2142] 
[2143]     ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);
[2144] 
[2145]     ngx_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);
[2146] 
[2147]     ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);
[2148] 
[2149]     ngx_conf_merge_value(conf->socket_keepalive,
[2150]                               prev->socket_keepalive, 0);
[2151] 
[2152]     ngx_conf_merge_value(conf->half_close, prev->half_close, 0);
[2153] 
[2154] #if (NGX_STREAM_SSL)
[2155] 
[2156]     if (ngx_stream_proxy_merge_ssl(cf, conf, prev) != NGX_OK) {
[2157]         return NGX_CONF_ERROR;
[2158]     }
[2159] 
[2160]     ngx_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);
[2161] 
[2162]     ngx_conf_merge_value(conf->ssl_session_reuse,
[2163]                               prev->ssl_session_reuse, 1);
[2164] 
[2165]     ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
[2166]                               (NGX_CONF_BITMASK_SET
[2167]                                |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[2168]                                |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[2169] 
[2170]     ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");
[2171] 
[2172]     ngx_conf_merge_ptr_value(conf->ssl_name, prev->ssl_name, NULL);
[2173] 
[2174]     ngx_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);
[2175] 
[2176]     ngx_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);
[2177] 
[2178]     ngx_conf_merge_uint_value(conf->ssl_verify_depth,
[2179]                               prev->ssl_verify_depth, 1);
[2180] 
[2181]     ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
[2182]                               prev->ssl_trusted_certificate, "");
[2183] 
[2184]     ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
[2185] 
[2186]     ngx_conf_merge_ptr_value(conf->ssl_certificate,
[2187]                               prev->ssl_certificate, NULL);
[2188] 
[2189]     ngx_conf_merge_ptr_value(conf->ssl_certificate_key,
[2190]                               prev->ssl_certificate_key, NULL);
[2191] 
[2192]     ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);
[2193] 
[2194]     ngx_conf_merge_ptr_value(conf->ssl_conf_commands,
[2195]                               prev->ssl_conf_commands, NULL);
[2196] 
[2197]     if (conf->ssl_enable && ngx_stream_proxy_set_ssl(cf, conf) != NGX_OK) {
[2198]         return NGX_CONF_ERROR;
[2199]     }
[2200] 
[2201] #endif
[2202] 
[2203]     return NGX_CONF_OK;
[2204] }
[2205] 
[2206] 
[2207] #if (NGX_STREAM_SSL)
[2208] 
[2209] static ngx_int_t
[2210] ngx_stream_proxy_merge_ssl(ngx_conf_t *cf, ngx_stream_proxy_srv_conf_t *conf,
[2211]     ngx_stream_proxy_srv_conf_t *prev)
[2212] {
[2213]     ngx_uint_t  preserve;
[2214] 
[2215]     if (conf->ssl_protocols == 0
[2216]         && conf->ssl_ciphers.data == NULL
[2217]         && conf->ssl_certificate == NGX_CONF_UNSET_PTR
[2218]         && conf->ssl_certificate_key == NGX_CONF_UNSET_PTR
[2219]         && conf->ssl_passwords == NGX_CONF_UNSET_PTR
[2220]         && conf->ssl_verify == NGX_CONF_UNSET
[2221]         && conf->ssl_verify_depth == NGX_CONF_UNSET_UINT
[2222]         && conf->ssl_trusted_certificate.data == NULL
[2223]         && conf->ssl_crl.data == NULL
[2224]         && conf->ssl_session_reuse == NGX_CONF_UNSET
[2225]         && conf->ssl_conf_commands == NGX_CONF_UNSET_PTR)
[2226]     {
[2227]         if (prev->ssl) {
[2228]             conf->ssl = prev->ssl;
[2229]             return NGX_OK;
[2230]         }
[2231] 
[2232]         preserve = 1;
[2233] 
[2234]     } else {
[2235]         preserve = 0;
[2236]     }
[2237] 
[2238]     conf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
[2239]     if (conf->ssl == NULL) {
[2240]         return NGX_ERROR;
[2241]     }
[2242] 
[2243]     conf->ssl->log = cf->log;
[2244] 
[2245]     /*
[2246]      * special handling to preserve conf->ssl
[2247]      * in the "stream" section to inherit it to all servers
[2248]      */
[2249] 
[2250]     if (preserve) {
[2251]         prev->ssl = conf->ssl;
[2252]     }
[2253] 
[2254]     return NGX_OK;
[2255] }
[2256] 
[2257] 
[2258] static ngx_int_t
[2259] ngx_stream_proxy_set_ssl(ngx_conf_t *cf, ngx_stream_proxy_srv_conf_t *pscf)
[2260] {
[2261]     ngx_pool_cleanup_t  *cln;
[2262] 
[2263]     if (pscf->ssl->ctx) {
[2264]         return NGX_OK;
[2265]     }
[2266] 
[2267]     if (ngx_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != NGX_OK) {
[2268]         return NGX_ERROR;
[2269]     }
[2270] 
[2271]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[2272]     if (cln == NULL) {
[2273]         ngx_ssl_cleanup_ctx(pscf->ssl);
[2274]         return NGX_ERROR;
[2275]     }
[2276] 
[2277]     cln->handler = ngx_ssl_cleanup_ctx;
[2278]     cln->data = pscf->ssl;
[2279] 
[2280]     if (ngx_ssl_ciphers(cf, pscf->ssl, &pscf->ssl_ciphers, 0) != NGX_OK) {
[2281]         return NGX_ERROR;
[2282]     }
[2283] 
[2284]     if (pscf->ssl_certificate
[2285]         && pscf->ssl_certificate->value.len)
[2286]     {
[2287]         if (pscf->ssl_certificate_key == NULL) {
[2288]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[2289]                           "no \"proxy_ssl_certificate_key\" is defined "
[2290]                           "for certificate \"%V\"",
[2291]                           &pscf->ssl_certificate->value);
[2292]             return NGX_ERROR;
[2293]         }
[2294] 
[2295]         if (pscf->ssl_certificate->lengths
[2296]             || pscf->ssl_certificate_key->lengths)
[2297]         {
[2298]             pscf->ssl_passwords =
[2299]                            ngx_ssl_preserve_passwords(cf, pscf->ssl_passwords);
[2300]             if (pscf->ssl_passwords == NULL) {
[2301]                 return NGX_ERROR;
[2302]             }
[2303] 
[2304]         } else {
[2305]             if (ngx_ssl_certificate(cf, pscf->ssl,
[2306]                                     &pscf->ssl_certificate->value,
[2307]                                     &pscf->ssl_certificate_key->value,
[2308]                                     pscf->ssl_passwords)
[2309]                 != NGX_OK)
[2310]             {
[2311]                 return NGX_ERROR;
[2312]             }
[2313]         }
[2314]     }
[2315] 
[2316]     if (pscf->ssl_verify) {
[2317]         if (pscf->ssl_trusted_certificate.len == 0) {
[2318]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[2319]                       "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
[2320]             return NGX_ERROR;
[2321]         }
[2322] 
[2323]         if (ngx_ssl_trusted_certificate(cf, pscf->ssl,
[2324]                                         &pscf->ssl_trusted_certificate,
[2325]                                         pscf->ssl_verify_depth)
[2326]             != NGX_OK)
[2327]         {
[2328]             return NGX_ERROR;
[2329]         }
[2330] 
[2331]         if (ngx_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != NGX_OK) {
[2332]             return NGX_ERROR;
[2333]         }
[2334]     }
[2335] 
[2336]     if (ngx_ssl_client_session_cache(cf, pscf->ssl, pscf->ssl_session_reuse)
[2337]         != NGX_OK)
[2338]     {
[2339]         return NGX_ERROR;
[2340]     }
[2341] 
[2342]     if (ngx_ssl_conf_commands(cf, pscf->ssl, pscf->ssl_conf_commands)
[2343]         != NGX_OK)
[2344]     {
[2345]         return NGX_ERROR;
[2346]     }
[2347] 
[2348]     return NGX_OK;
[2349] }
[2350] 
[2351] #endif
[2352] 
[2353] 
[2354] static char *
[2355] ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2356] {
[2357]     ngx_stream_proxy_srv_conf_t *pscf = conf;
[2358] 
[2359]     ngx_url_t                            u;
[2360]     ngx_str_t                           *value, *url;
[2361]     ngx_stream_complex_value_t           cv;
[2362]     ngx_stream_core_srv_conf_t          *cscf;
[2363]     ngx_stream_compile_complex_value_t   ccv;
[2364] 
[2365]     if (pscf->upstream || pscf->upstream_value) {
[2366]         return "is duplicate";
[2367]     }
[2368] 
[2369]     cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
[2370] 
[2371]     cscf->handler = ngx_stream_proxy_handler;
[2372] 
[2373]     value = cf->args->elts;
[2374] 
[2375]     url = &value[1];
[2376] 
[2377]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[2378] 
[2379]     ccv.cf = cf;
[2380]     ccv.value = url;
[2381]     ccv.complex_value = &cv;
[2382] 
[2383]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[2384]         return NGX_CONF_ERROR;
[2385]     }
[2386] 
[2387]     if (cv.lengths) {
[2388]         pscf->upstream_value = ngx_palloc(cf->pool,
[2389]                                           sizeof(ngx_stream_complex_value_t));
[2390]         if (pscf->upstream_value == NULL) {
[2391]             return NGX_CONF_ERROR;
[2392]         }
[2393] 
[2394]         *pscf->upstream_value = cv;
[2395] 
[2396]         return NGX_CONF_OK;
[2397]     }
[2398] 
[2399]     ngx_memzero(&u, sizeof(ngx_url_t));
[2400] 
[2401]     u.url = *url;
[2402]     u.no_resolve = 1;
[2403] 
[2404]     pscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
[2405]     if (pscf->upstream == NULL) {
[2406]         return NGX_CONF_ERROR;
[2407]     }
[2408] 
[2409]     return NGX_CONF_OK;
[2410] }
[2411] 
[2412] 
[2413] static char *
[2414] ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2415] {
[2416]     ngx_stream_proxy_srv_conf_t *pscf = conf;
[2417] 
[2418]     ngx_int_t                            rc;
[2419]     ngx_str_t                           *value;
[2420]     ngx_stream_complex_value_t           cv;
[2421]     ngx_stream_upstream_local_t         *local;
[2422]     ngx_stream_compile_complex_value_t   ccv;
[2423] 
[2424]     if (pscf->local != NGX_CONF_UNSET_PTR) {
[2425]         return "is duplicate";
[2426]     }
[2427] 
[2428]     value = cf->args->elts;
[2429] 
[2430]     if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
[2431]         pscf->local = NULL;
[2432]         return NGX_CONF_OK;
[2433]     }
[2434] 
[2435]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[2436] 
[2437]     ccv.cf = cf;
[2438]     ccv.value = &value[1];
[2439]     ccv.complex_value = &cv;
[2440] 
[2441]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[2442]         return NGX_CONF_ERROR;
[2443]     }
[2444] 
[2445]     local = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_local_t));
[2446]     if (local == NULL) {
[2447]         return NGX_CONF_ERROR;
[2448]     }
[2449] 
[2450]     pscf->local = local;
[2451] 
[2452]     if (cv.lengths) {
[2453]         local->value = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
[2454]         if (local->value == NULL) {
[2455]             return NGX_CONF_ERROR;
[2456]         }
[2457] 
[2458]         *local->value = cv;
[2459] 
[2460]     } else {
[2461]         local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
[2462]         if (local->addr == NULL) {
[2463]             return NGX_CONF_ERROR;
[2464]         }
[2465] 
[2466]         rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
[2467]                                  value[1].len);
[2468] 
[2469]         switch (rc) {
[2470]         case NGX_OK:
[2471]             local->addr->name = value[1];
[2472]             break;
[2473] 
[2474]         case NGX_DECLINED:
[2475]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2476]                                "invalid address \"%V\"", &value[1]);
[2477]             /* fall through */
[2478] 
[2479]         default:
[2480]             return NGX_CONF_ERROR;
[2481]         }
[2482]     }
[2483] 
[2484]     if (cf->args->nelts > 2) {
[2485]         if (ngx_strcmp(value[2].data, "transparent") == 0) {
[2486] #if (NGX_HAVE_TRANSPARENT_PROXY)
[2487]             ngx_core_conf_t  *ccf;
[2488] 
[2489]             ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
[2490]                                                    ngx_core_module);
[2491] 
[2492]             ccf->transparent = 1;
[2493]             local->transparent = 1;
[2494] #else
[2495]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2496]                                "transparent proxying is not supported "
[2497]                                "on this platform, ignored");
[2498] #endif
[2499]         } else {
[2500]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2501]                                "invalid parameter \"%V\"", &value[2]);
[2502]             return NGX_CONF_ERROR;
[2503]         }
[2504]     }
[2505] 
[2506]     return NGX_CONF_OK;
[2507] }
