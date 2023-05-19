[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] typedef ngx_int_t (*ngx_ssl_variable_handler_pt)(ngx_connection_t *c,
[14]     ngx_pool_t *pool, ngx_str_t *s);
[15] 
[16] 
[17] #define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
[18] #define NGX_DEFAULT_ECDH_CURVE  "auto"
[19] 
[20] 
[21] static ngx_int_t ngx_stream_ssl_handler(ngx_stream_session_t *s);
[22] static ngx_int_t ngx_stream_ssl_init_connection(ngx_ssl_t *ssl,
[23]     ngx_connection_t *c);
[24] static void ngx_stream_ssl_handshake_handler(ngx_connection_t *c);
[25] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[26] static int ngx_stream_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad,
[27]     void *arg);
[28] #endif
[29] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[30] static int ngx_stream_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn,
[31]     const unsigned char **out, unsigned char *outlen,
[32]     const unsigned char *in, unsigned int inlen, void *arg);
[33] #endif
[34] #ifdef SSL_R_CERT_CB_ERROR
[35] static int ngx_stream_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg);
[36] #endif
[37] static ngx_int_t ngx_stream_ssl_static_variable(ngx_stream_session_t *s,
[38]     ngx_stream_variable_value_t *v, uintptr_t data);
[39] static ngx_int_t ngx_stream_ssl_variable(ngx_stream_session_t *s,
[40]     ngx_stream_variable_value_t *v, uintptr_t data);
[41] 
[42] static ngx_int_t ngx_stream_ssl_add_variables(ngx_conf_t *cf);
[43] static void *ngx_stream_ssl_create_conf(ngx_conf_t *cf);
[44] static char *ngx_stream_ssl_merge_conf(ngx_conf_t *cf, void *parent,
[45]     void *child);
[46] 
[47] static ngx_int_t ngx_stream_ssl_compile_certificates(ngx_conf_t *cf,
[48]     ngx_stream_ssl_conf_t *conf);
[49] 
[50] static char *ngx_stream_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
[51]     void *conf);
[52] static char *ngx_stream_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[53]     void *conf);
[54] static char *ngx_stream_ssl_alpn(ngx_conf_t *cf, ngx_command_t *cmd,
[55]     void *conf);
[56] 
[57] static char *ngx_stream_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[58]     void *data);
[59] 
[60] static ngx_int_t ngx_stream_ssl_init(ngx_conf_t *cf);
[61] 
[62] 
[63] static ngx_conf_bitmask_t  ngx_stream_ssl_protocols[] = {
[64]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[65]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[66]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[67]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[68]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[69]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[70]     { ngx_null_string, 0 }
[71] };
[72] 
[73] 
[74] static ngx_conf_enum_t  ngx_stream_ssl_verify[] = {
[75]     { ngx_string("off"), 0 },
[76]     { ngx_string("on"), 1 },
[77]     { ngx_string("optional"), 2 },
[78]     { ngx_string("optional_no_ca"), 3 },
[79]     { ngx_null_string, 0 }
[80] };
[81] 
[82] 
[83] static ngx_conf_post_t  ngx_stream_ssl_conf_command_post =
[84]     { ngx_stream_ssl_conf_command_check };
[85] 
[86] 
[87] static ngx_command_t  ngx_stream_ssl_commands[] = {
[88] 
[89]     { ngx_string("ssl_handshake_timeout"),
[90]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[91]       ngx_conf_set_msec_slot,
[92]       NGX_STREAM_SRV_CONF_OFFSET,
[93]       offsetof(ngx_stream_ssl_conf_t, handshake_timeout),
[94]       NULL },
[95] 
[96]     { ngx_string("ssl_certificate"),
[97]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[98]       ngx_conf_set_str_array_slot,
[99]       NGX_STREAM_SRV_CONF_OFFSET,
[100]       offsetof(ngx_stream_ssl_conf_t, certificates),
[101]       NULL },
[102] 
[103]     { ngx_string("ssl_certificate_key"),
[104]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[105]       ngx_conf_set_str_array_slot,
[106]       NGX_STREAM_SRV_CONF_OFFSET,
[107]       offsetof(ngx_stream_ssl_conf_t, certificate_keys),
[108]       NULL },
[109] 
[110]     { ngx_string("ssl_password_file"),
[111]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[112]       ngx_stream_ssl_password_file,
[113]       NGX_STREAM_SRV_CONF_OFFSET,
[114]       0,
[115]       NULL },
[116] 
[117]     { ngx_string("ssl_dhparam"),
[118]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[119]       ngx_conf_set_str_slot,
[120]       NGX_STREAM_SRV_CONF_OFFSET,
[121]       offsetof(ngx_stream_ssl_conf_t, dhparam),
[122]       NULL },
[123] 
[124]     { ngx_string("ssl_ecdh_curve"),
[125]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[126]       ngx_conf_set_str_slot,
[127]       NGX_STREAM_SRV_CONF_OFFSET,
[128]       offsetof(ngx_stream_ssl_conf_t, ecdh_curve),
[129]       NULL },
[130] 
[131]     { ngx_string("ssl_protocols"),
[132]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[133]       ngx_conf_set_bitmask_slot,
[134]       NGX_STREAM_SRV_CONF_OFFSET,
[135]       offsetof(ngx_stream_ssl_conf_t, protocols),
[136]       &ngx_stream_ssl_protocols },
[137] 
[138]     { ngx_string("ssl_ciphers"),
[139]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[140]       ngx_conf_set_str_slot,
[141]       NGX_STREAM_SRV_CONF_OFFSET,
[142]       offsetof(ngx_stream_ssl_conf_t, ciphers),
[143]       NULL },
[144] 
[145]     { ngx_string("ssl_verify_client"),
[146]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[147]       ngx_conf_set_enum_slot,
[148]       NGX_STREAM_SRV_CONF_OFFSET,
[149]       offsetof(ngx_stream_ssl_conf_t, verify),
[150]       &ngx_stream_ssl_verify },
[151] 
[152]     { ngx_string("ssl_verify_depth"),
[153]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[154]       ngx_conf_set_num_slot,
[155]       NGX_STREAM_SRV_CONF_OFFSET,
[156]       offsetof(ngx_stream_ssl_conf_t, verify_depth),
[157]       NULL },
[158] 
[159]     { ngx_string("ssl_client_certificate"),
[160]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[161]       ngx_conf_set_str_slot,
[162]       NGX_STREAM_SRV_CONF_OFFSET,
[163]       offsetof(ngx_stream_ssl_conf_t, client_certificate),
[164]       NULL },
[165] 
[166]     { ngx_string("ssl_trusted_certificate"),
[167]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[168]       ngx_conf_set_str_slot,
[169]       NGX_STREAM_SRV_CONF_OFFSET,
[170]       offsetof(ngx_stream_ssl_conf_t, trusted_certificate),
[171]       NULL },
[172] 
[173]     { ngx_string("ssl_prefer_server_ciphers"),
[174]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[175]       ngx_conf_set_flag_slot,
[176]       NGX_STREAM_SRV_CONF_OFFSET,
[177]       offsetof(ngx_stream_ssl_conf_t, prefer_server_ciphers),
[178]       NULL },
[179] 
[180]     { ngx_string("ssl_session_cache"),
[181]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE12,
[182]       ngx_stream_ssl_session_cache,
[183]       NGX_STREAM_SRV_CONF_OFFSET,
[184]       0,
[185]       NULL },
[186] 
[187]     { ngx_string("ssl_session_tickets"),
[188]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[189]       ngx_conf_set_flag_slot,
[190]       NGX_STREAM_SRV_CONF_OFFSET,
[191]       offsetof(ngx_stream_ssl_conf_t, session_tickets),
[192]       NULL },
[193] 
[194]     { ngx_string("ssl_session_ticket_key"),
[195]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[196]       ngx_conf_set_str_array_slot,
[197]       NGX_STREAM_SRV_CONF_OFFSET,
[198]       offsetof(ngx_stream_ssl_conf_t, session_ticket_keys),
[199]       NULL },
[200] 
[201]     { ngx_string("ssl_session_timeout"),
[202]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[203]       ngx_conf_set_sec_slot,
[204]       NGX_STREAM_SRV_CONF_OFFSET,
[205]       offsetof(ngx_stream_ssl_conf_t, session_timeout),
[206]       NULL },
[207] 
[208]     { ngx_string("ssl_crl"),
[209]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[210]       ngx_conf_set_str_slot,
[211]       NGX_STREAM_SRV_CONF_OFFSET,
[212]       offsetof(ngx_stream_ssl_conf_t, crl),
[213]       NULL },
[214] 
[215]     { ngx_string("ssl_conf_command"),
[216]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
[217]       ngx_conf_set_keyval_slot,
[218]       NGX_STREAM_SRV_CONF_OFFSET,
[219]       offsetof(ngx_stream_ssl_conf_t, conf_commands),
[220]       &ngx_stream_ssl_conf_command_post },
[221] 
[222]     { ngx_string("ssl_alpn"),
[223]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[224]       ngx_stream_ssl_alpn,
[225]       NGX_STREAM_SRV_CONF_OFFSET,
[226]       0,
[227]       NULL },
[228] 
[229]       ngx_null_command
[230] };
[231] 
[232] 
[233] static ngx_stream_module_t  ngx_stream_ssl_module_ctx = {
[234]     ngx_stream_ssl_add_variables,          /* preconfiguration */
[235]     ngx_stream_ssl_init,                   /* postconfiguration */
[236] 
[237]     NULL,                                  /* create main configuration */
[238]     NULL,                                  /* init main configuration */
[239] 
[240]     ngx_stream_ssl_create_conf,            /* create server configuration */
[241]     ngx_stream_ssl_merge_conf              /* merge server configuration */
[242] };
[243] 
[244] 
[245] ngx_module_t  ngx_stream_ssl_module = {
[246]     NGX_MODULE_V1,
[247]     &ngx_stream_ssl_module_ctx,            /* module context */
[248]     ngx_stream_ssl_commands,               /* module directives */
[249]     NGX_STREAM_MODULE,                     /* module type */
[250]     NULL,                                  /* init master */
[251]     NULL,                                  /* init module */
[252]     NULL,                                  /* init process */
[253]     NULL,                                  /* init thread */
[254]     NULL,                                  /* exit thread */
[255]     NULL,                                  /* exit process */
[256]     NULL,                                  /* exit master */
[257]     NGX_MODULE_V1_PADDING
[258] };
[259] 
[260] 
[261] static ngx_stream_variable_t  ngx_stream_ssl_vars[] = {
[262] 
[263]     { ngx_string("ssl_protocol"), NULL, ngx_stream_ssl_static_variable,
[264]       (uintptr_t) ngx_ssl_get_protocol, NGX_STREAM_VAR_CHANGEABLE, 0 },
[265] 
[266]     { ngx_string("ssl_cipher"), NULL, ngx_stream_ssl_static_variable,
[267]       (uintptr_t) ngx_ssl_get_cipher_name, NGX_STREAM_VAR_CHANGEABLE, 0 },
[268] 
[269]     { ngx_string("ssl_ciphers"), NULL, ngx_stream_ssl_variable,
[270]       (uintptr_t) ngx_ssl_get_ciphers, NGX_STREAM_VAR_CHANGEABLE, 0 },
[271] 
[272]     { ngx_string("ssl_curve"), NULL, ngx_stream_ssl_variable,
[273]       (uintptr_t) ngx_ssl_get_curve, NGX_STREAM_VAR_CHANGEABLE, 0 },
[274] 
[275]     { ngx_string("ssl_curves"), NULL, ngx_stream_ssl_variable,
[276]       (uintptr_t) ngx_ssl_get_curves, NGX_STREAM_VAR_CHANGEABLE, 0 },
[277] 
[278]     { ngx_string("ssl_session_id"), NULL, ngx_stream_ssl_variable,
[279]       (uintptr_t) ngx_ssl_get_session_id, NGX_STREAM_VAR_CHANGEABLE, 0 },
[280] 
[281]     { ngx_string("ssl_session_reused"), NULL, ngx_stream_ssl_variable,
[282]       (uintptr_t) ngx_ssl_get_session_reused, NGX_STREAM_VAR_CHANGEABLE, 0 },
[283] 
[284]     { ngx_string("ssl_server_name"), NULL, ngx_stream_ssl_variable,
[285]       (uintptr_t) ngx_ssl_get_server_name, NGX_STREAM_VAR_CHANGEABLE, 0 },
[286] 
[287]     { ngx_string("ssl_alpn_protocol"), NULL, ngx_stream_ssl_variable,
[288]       (uintptr_t) ngx_ssl_get_alpn_protocol, NGX_STREAM_VAR_CHANGEABLE, 0 },
[289] 
[290]     { ngx_string("ssl_client_cert"), NULL, ngx_stream_ssl_variable,
[291]       (uintptr_t) ngx_ssl_get_certificate, NGX_STREAM_VAR_CHANGEABLE, 0 },
[292] 
[293]     { ngx_string("ssl_client_raw_cert"), NULL, ngx_stream_ssl_variable,
[294]       (uintptr_t) ngx_ssl_get_raw_certificate,
[295]       NGX_STREAM_VAR_CHANGEABLE, 0 },
[296] 
[297]     { ngx_string("ssl_client_escaped_cert"), NULL, ngx_stream_ssl_variable,
[298]       (uintptr_t) ngx_ssl_get_escaped_certificate,
[299]       NGX_STREAM_VAR_CHANGEABLE, 0 },
[300] 
[301]     { ngx_string("ssl_client_s_dn"), NULL, ngx_stream_ssl_variable,
[302]       (uintptr_t) ngx_ssl_get_subject_dn, NGX_STREAM_VAR_CHANGEABLE, 0 },
[303] 
[304]     { ngx_string("ssl_client_i_dn"), NULL, ngx_stream_ssl_variable,
[305]       (uintptr_t) ngx_ssl_get_issuer_dn, NGX_STREAM_VAR_CHANGEABLE, 0 },
[306] 
[307]     { ngx_string("ssl_client_serial"), NULL, ngx_stream_ssl_variable,
[308]       (uintptr_t) ngx_ssl_get_serial_number, NGX_STREAM_VAR_CHANGEABLE, 0 },
[309] 
[310]     { ngx_string("ssl_client_fingerprint"), NULL, ngx_stream_ssl_variable,
[311]       (uintptr_t) ngx_ssl_get_fingerprint, NGX_STREAM_VAR_CHANGEABLE, 0 },
[312] 
[313]     { ngx_string("ssl_client_verify"), NULL, ngx_stream_ssl_variable,
[314]       (uintptr_t) ngx_ssl_get_client_verify, NGX_STREAM_VAR_CHANGEABLE, 0 },
[315] 
[316]     { ngx_string("ssl_client_v_start"), NULL, ngx_stream_ssl_variable,
[317]       (uintptr_t) ngx_ssl_get_client_v_start, NGX_STREAM_VAR_CHANGEABLE, 0 },
[318] 
[319]     { ngx_string("ssl_client_v_end"), NULL, ngx_stream_ssl_variable,
[320]       (uintptr_t) ngx_ssl_get_client_v_end, NGX_STREAM_VAR_CHANGEABLE, 0 },
[321] 
[322]     { ngx_string("ssl_client_v_remain"), NULL, ngx_stream_ssl_variable,
[323]       (uintptr_t) ngx_ssl_get_client_v_remain, NGX_STREAM_VAR_CHANGEABLE, 0 },
[324] 
[325]       ngx_stream_null_variable
[326] };
[327] 
[328] 
[329] static ngx_str_t ngx_stream_ssl_sess_id_ctx = ngx_string("STREAM");
[330] 
[331] 
[332] static ngx_int_t
[333] ngx_stream_ssl_handler(ngx_stream_session_t *s)
[334] {
[335]     long                    rc;
[336]     X509                   *cert;
[337]     ngx_int_t               rv;
[338]     ngx_connection_t       *c;
[339]     ngx_stream_ssl_conf_t  *sslcf;
[340] 
[341]     if (!s->ssl) {
[342]         return NGX_OK;
[343]     }
[344] 
[345]     c = s->connection;
[346] 
[347]     sslcf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_module);
[348] 
[349]     if (c->ssl == NULL) {
[350]         c->log->action = "SSL handshaking";
[351] 
[352]         rv = ngx_stream_ssl_init_connection(&sslcf->ssl, c);
[353] 
[354]         if (rv != NGX_OK) {
[355]             return rv;
[356]         }
[357]     }
[358] 
[359]     if (sslcf->verify) {
[360]         rc = SSL_get_verify_result(c->ssl->connection);
[361] 
[362]         if (rc != X509_V_OK
[363]             && (sslcf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
[364]         {
[365]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[366]                           "client SSL certificate verify error: (%l:%s)",
[367]                           rc, X509_verify_cert_error_string(rc));
[368] 
[369]             ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[370]                                        (SSL_get0_session(c->ssl->connection)));
[371]             return NGX_ERROR;
[372]         }
[373] 
[374]         if (sslcf->verify == 1) {
[375]             cert = SSL_get_peer_certificate(c->ssl->connection);
[376] 
[377]             if (cert == NULL) {
[378]                 ngx_log_error(NGX_LOG_INFO, c->log, 0,
[379]                               "client sent no required SSL certificate");
[380] 
[381]                 ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[382]                                        (SSL_get0_session(c->ssl->connection)));
[383]                 return NGX_ERROR;
[384]             }
[385] 
[386]             X509_free(cert);
[387]         }
[388]     }
[389] 
[390]     return NGX_OK;
[391] }
[392] 
[393] 
[394] static ngx_int_t
[395] ngx_stream_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c)
[396] {
[397]     ngx_int_t                    rc;
[398]     ngx_stream_session_t        *s;
[399]     ngx_stream_ssl_conf_t       *sslcf;
[400]     ngx_stream_core_srv_conf_t  *cscf;
[401] 
[402]     s = c->data;
[403] 
[404]     cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
[405] 
[406]     if (cscf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[407]         return NGX_ERROR;
[408]     }
[409] 
[410]     if (ngx_ssl_create_connection(ssl, c, 0) != NGX_OK) {
[411]         return NGX_ERROR;
[412]     }
[413] 
[414]     rc = ngx_ssl_handshake(c);
[415] 
[416]     if (rc == NGX_ERROR) {
[417]         return NGX_ERROR;
[418]     }
[419] 
[420]     if (rc == NGX_AGAIN) {
[421]         sslcf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_module);
[422] 
[423]         ngx_add_timer(c->read, sslcf->handshake_timeout);
[424] 
[425]         c->ssl->handler = ngx_stream_ssl_handshake_handler;
[426] 
[427]         return NGX_AGAIN;
[428]     }
[429] 
[430]     /* rc == NGX_OK */
[431] 
[432]     return NGX_OK;
[433] }
[434] 
[435] 
[436] static void
[437] ngx_stream_ssl_handshake_handler(ngx_connection_t *c)
[438] {
[439]     ngx_stream_session_t  *s;
[440] 
[441]     s = c->data;
[442] 
[443]     if (!c->ssl->handshaked) {
[444]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[445]         return;
[446]     }
[447] 
[448]     if (c->read->timer_set) {
[449]         ngx_del_timer(c->read);
[450]     }
[451] 
[452]     ngx_stream_core_run_phases(s);
[453] }
[454] 
[455] 
[456] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[457] 
[458] static int
[459] ngx_stream_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
[460] {
[461]     return SSL_TLSEXT_ERR_OK;
[462] }
[463] 
[464] #endif
[465] 
[466] 
[467] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[468] 
[469] static int
[470] ngx_stream_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn, const unsigned char **out,
[471]     unsigned char *outlen, const unsigned char *in, unsigned int inlen,
[472]     void *arg)
[473] {
[474]     ngx_str_t         *alpn;
[475] #if (NGX_DEBUG)
[476]     unsigned int       i;
[477]     ngx_connection_t  *c;
[478] 
[479]     c = ngx_ssl_get_connection(ssl_conn);
[480] 
[481]     for (i = 0; i < inlen; i += in[i] + 1) {
[482]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
[483]                        "SSL ALPN supported by client: %*s",
[484]                        (size_t) in[i], &in[i + 1]);
[485]     }
[486] 
[487] #endif
[488] 
[489]     alpn = arg;
[490] 
[491]     if (SSL_select_next_proto((unsigned char **) out, outlen, alpn->data,
[492]                               alpn->len, in, inlen)
[493]         != OPENSSL_NPN_NEGOTIATED)
[494]     {
[495]         return SSL_TLSEXT_ERR_ALERT_FATAL;
[496]     }
[497] 
[498]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
[499]                    "SSL ALPN selected: %*s", (size_t) *outlen, *out);
[500] 
[501]     return SSL_TLSEXT_ERR_OK;
[502] }
[503] 
[504] #endif
[505] 
[506] 
[507] #ifdef SSL_R_CERT_CB_ERROR
[508] 
[509] static int
[510] ngx_stream_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg)
[511] {
[512]     ngx_str_t                    cert, key;
[513]     ngx_uint_t                   i, nelts;
[514]     ngx_connection_t            *c;
[515]     ngx_stream_session_t        *s;
[516]     ngx_stream_ssl_conf_t       *sslcf;
[517]     ngx_stream_complex_value_t  *certs, *keys;
[518] 
[519]     c = ngx_ssl_get_connection(ssl_conn);
[520] 
[521]     if (c->ssl->handshaked) {
[522]         return 0;
[523]     }
[524] 
[525]     s = c->data;
[526] 
[527]     sslcf = arg;
[528] 
[529]     nelts = sslcf->certificate_values->nelts;
[530]     certs = sslcf->certificate_values->elts;
[531]     keys = sslcf->certificate_key_values->elts;
[532] 
[533]     for (i = 0; i < nelts; i++) {
[534] 
[535]         if (ngx_stream_complex_value(s, &certs[i], &cert) != NGX_OK) {
[536]             return 0;
[537]         }
[538] 
[539]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[540]                        "ssl cert: \"%s\"", cert.data);
[541] 
[542]         if (ngx_stream_complex_value(s, &keys[i], &key) != NGX_OK) {
[543]             return 0;
[544]         }
[545] 
[546]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[547]                        "ssl key: \"%s\"", key.data);
[548] 
[549]         if (ngx_ssl_connection_certificate(c, c->pool, &cert, &key,
[550]                                            sslcf->passwords)
[551]             != NGX_OK)
[552]         {
[553]             return 0;
[554]         }
[555]     }
[556] 
[557]     return 1;
[558] }
[559] 
[560] #endif
[561] 
[562] 
[563] static ngx_int_t
[564] ngx_stream_ssl_static_variable(ngx_stream_session_t *s,
[565]     ngx_stream_variable_value_t *v, uintptr_t data)
[566] {
[567]     ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;
[568] 
[569]     size_t     len;
[570]     ngx_str_t  str;
[571] 
[572]     if (s->connection->ssl) {
[573] 
[574]         (void) handler(s->connection, NULL, &str);
[575] 
[576]         v->data = str.data;
[577] 
[578]         for (len = 0; v->data[len]; len++) { /* void */ }
[579] 
[580]         v->len = len;
[581]         v->valid = 1;
[582]         v->no_cacheable = 0;
[583]         v->not_found = 0;
[584] 
[585]         return NGX_OK;
[586]     }
[587] 
[588]     v->not_found = 1;
[589] 
[590]     return NGX_OK;
[591] }
[592] 
[593] 
[594] static ngx_int_t
[595] ngx_stream_ssl_variable(ngx_stream_session_t *s,
[596]     ngx_stream_variable_value_t *v, uintptr_t data)
[597] {
[598]     ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;
[599] 
[600]     ngx_str_t  str;
[601] 
[602]     if (s->connection->ssl) {
[603] 
[604]         if (handler(s->connection, s->connection->pool, &str) != NGX_OK) {
[605]             return NGX_ERROR;
[606]         }
[607] 
[608]         v->len = str.len;
[609]         v->data = str.data;
[610] 
[611]         if (v->len) {
[612]             v->valid = 1;
[613]             v->no_cacheable = 0;
[614]             v->not_found = 0;
[615] 
[616]             return NGX_OK;
[617]         }
[618]     }
[619] 
[620]     v->not_found = 1;
[621] 
[622]     return NGX_OK;
[623] }
[624] 
[625] 
[626] static ngx_int_t
[627] ngx_stream_ssl_add_variables(ngx_conf_t *cf)
[628] {
[629]     ngx_stream_variable_t  *var, *v;
[630] 
[631]     for (v = ngx_stream_ssl_vars; v->name.len; v++) {
[632]         var = ngx_stream_add_variable(cf, &v->name, v->flags);
[633]         if (var == NULL) {
[634]             return NGX_ERROR;
[635]         }
[636] 
[637]         var->get_handler = v->get_handler;
[638]         var->data = v->data;
[639]     }
[640] 
[641]     return NGX_OK;
[642] }
[643] 
[644] 
[645] static void *
[646] ngx_stream_ssl_create_conf(ngx_conf_t *cf)
[647] {
[648]     ngx_stream_ssl_conf_t  *scf;
[649] 
[650]     scf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ssl_conf_t));
[651]     if (scf == NULL) {
[652]         return NULL;
[653]     }
[654] 
[655]     /*
[656]      * set by ngx_pcalloc():
[657]      *
[658]      *     scf->listen = 0;
[659]      *     scf->protocols = 0;
[660]      *     scf->certificate_values = NULL;
[661]      *     scf->dhparam = { 0, NULL };
[662]      *     scf->ecdh_curve = { 0, NULL };
[663]      *     scf->client_certificate = { 0, NULL };
[664]      *     scf->trusted_certificate = { 0, NULL };
[665]      *     scf->crl = { 0, NULL };
[666]      *     scf->alpn = { 0, NULL };
[667]      *     scf->ciphers = { 0, NULL };
[668]      *     scf->shm_zone = NULL;
[669]      */
[670] 
[671]     scf->handshake_timeout = NGX_CONF_UNSET_MSEC;
[672]     scf->certificates = NGX_CONF_UNSET_PTR;
[673]     scf->certificate_keys = NGX_CONF_UNSET_PTR;
[674]     scf->passwords = NGX_CONF_UNSET_PTR;
[675]     scf->conf_commands = NGX_CONF_UNSET_PTR;
[676]     scf->prefer_server_ciphers = NGX_CONF_UNSET;
[677]     scf->verify = NGX_CONF_UNSET_UINT;
[678]     scf->verify_depth = NGX_CONF_UNSET_UINT;
[679]     scf->builtin_session_cache = NGX_CONF_UNSET;
[680]     scf->session_timeout = NGX_CONF_UNSET;
[681]     scf->session_tickets = NGX_CONF_UNSET;
[682]     scf->session_ticket_keys = NGX_CONF_UNSET_PTR;
[683] 
[684]     return scf;
[685] }
[686] 
[687] 
[688] static char *
[689] ngx_stream_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[690] {
[691]     ngx_stream_ssl_conf_t *prev = parent;
[692]     ngx_stream_ssl_conf_t *conf = child;
[693] 
[694]     ngx_pool_cleanup_t  *cln;
[695] 
[696]     ngx_conf_merge_msec_value(conf->handshake_timeout,
[697]                          prev->handshake_timeout, 60000);
[698] 
[699]     ngx_conf_merge_value(conf->session_timeout,
[700]                          prev->session_timeout, 300);
[701] 
[702]     ngx_conf_merge_value(conf->prefer_server_ciphers,
[703]                          prev->prefer_server_ciphers, 0);
[704] 
[705]     ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
[706]                          (NGX_CONF_BITMASK_SET
[707]                           |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[708]                           |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[709] 
[710]     ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
[711]     ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);
[712] 
[713]     ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
[714]     ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
[715]                          NULL);
[716] 
[717]     ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);
[718] 
[719]     ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");
[720] 
[721]     ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
[722]                          "");
[723]     ngx_conf_merge_str_value(conf->trusted_certificate,
[724]                          prev->trusted_certificate, "");
[725]     ngx_conf_merge_str_value(conf->crl, prev->crl, "");
[726]     ngx_conf_merge_str_value(conf->alpn, prev->alpn, "");
[727] 
[728]     ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
[729]                          NGX_DEFAULT_ECDH_CURVE);
[730] 
[731]     ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);
[732] 
[733]     ngx_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);
[734] 
[735] 
[736]     conf->ssl.log = cf->log;
[737] 
[738]     if (!conf->listen) {
[739]         return NGX_CONF_OK;
[740]     }
[741] 
[742]     if (conf->certificates == NULL) {
[743]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[744]                       "no \"ssl_certificate\" is defined for "
[745]                       "the \"listen ... ssl\" directive in %s:%ui",
[746]                       conf->file, conf->line);
[747]         return NGX_CONF_ERROR;
[748]     }
[749] 
[750]     if (conf->certificate_keys == NULL) {
[751]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[752]                       "no \"ssl_certificate_key\" is defined for "
[753]                       "the \"listen ... ssl\" directive in %s:%ui",
[754]                       conf->file, conf->line);
[755]         return NGX_CONF_ERROR;
[756]     }
[757] 
[758]     if (conf->certificate_keys->nelts < conf->certificates->nelts) {
[759]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[760]                       "no \"ssl_certificate_key\" is defined "
[761]                       "for certificate \"%V\" and "
[762]                       "the \"listen ... ssl\" directive in %s:%ui",
[763]                       ((ngx_str_t *) conf->certificates->elts)
[764]                       + conf->certificates->nelts - 1,
[765]                       conf->file, conf->line);
[766]         return NGX_CONF_ERROR;
[767]     }
[768] 
[769]     if (ngx_ssl_create(&conf->ssl, conf->protocols, NULL) != NGX_OK) {
[770]         return NGX_CONF_ERROR;
[771]     }
[772] 
[773]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[774]     if (cln == NULL) {
[775]         ngx_ssl_cleanup_ctx(&conf->ssl);
[776]         return NGX_CONF_ERROR;
[777]     }
[778] 
[779]     cln->handler = ngx_ssl_cleanup_ctx;
[780]     cln->data = &conf->ssl;
[781] 
[782] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[783]     SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
[784]                                            ngx_stream_ssl_servername);
[785] #endif
[786] 
[787] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[788]     if (conf->alpn.len) {
[789]         SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, ngx_stream_ssl_alpn_select,
[790]                                    &conf->alpn);
[791]     }
[792] #endif
[793] 
[794]     if (ngx_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
[795]                         conf->prefer_server_ciphers)
[796]         != NGX_OK)
[797]     {
[798]         return NGX_CONF_ERROR;
[799]     }
[800] 
[801]     if (ngx_stream_ssl_compile_certificates(cf, conf) != NGX_OK) {
[802]         return NGX_CONF_ERROR;
[803]     }
[804] 
[805]     if (conf->certificate_values) {
[806] 
[807] #ifdef SSL_R_CERT_CB_ERROR
[808] 
[809]         /* install callback to lookup certificates */
[810] 
[811]         SSL_CTX_set_cert_cb(conf->ssl.ctx, ngx_stream_ssl_certificate, conf);
[812] 
[813] #else
[814]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[815]                       "variables in "
[816]                       "\"ssl_certificate\" and \"ssl_certificate_key\" "
[817]                       "directives are not supported on this platform");
[818]         return NGX_CONF_ERROR;
[819] #endif
[820] 
[821]     } else {
[822] 
[823]         /* configure certificates */
[824] 
[825]         if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
[826]                                  conf->certificate_keys, conf->passwords)
[827]             != NGX_OK)
[828]         {
[829]             return NGX_CONF_ERROR;
[830]         }
[831]     }
[832] 
[833]     if (conf->verify) {
[834] 
[835]         if (conf->client_certificate.len == 0 && conf->verify != 3) {
[836]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[837]                           "no ssl_client_certificate for ssl_verify_client");
[838]             return NGX_CONF_ERROR;
[839]         }
[840] 
[841]         if (ngx_ssl_client_certificate(cf, &conf->ssl,
[842]                                        &conf->client_certificate,
[843]                                        conf->verify_depth)
[844]             != NGX_OK)
[845]         {
[846]             return NGX_CONF_ERROR;
[847]         }
[848] 
[849]         if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
[850]                                         &conf->trusted_certificate,
[851]                                         conf->verify_depth)
[852]             != NGX_OK)
[853]         {
[854]             return NGX_CONF_ERROR;
[855]         }
[856] 
[857]         if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
[858]             return NGX_CONF_ERROR;
[859]         }
[860]     }
[861] 
[862]     if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
[863]         return NGX_CONF_ERROR;
[864]     }
[865] 
[866]     if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
[867]         return NGX_CONF_ERROR;
[868]     }
[869] 
[870]     ngx_conf_merge_value(conf->builtin_session_cache,
[871]                          prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);
[872] 
[873]     if (conf->shm_zone == NULL) {
[874]         conf->shm_zone = prev->shm_zone;
[875]     }
[876] 
[877]     if (ngx_ssl_session_cache(&conf->ssl, &ngx_stream_ssl_sess_id_ctx,
[878]                               conf->certificates, conf->builtin_session_cache,
[879]                               conf->shm_zone, conf->session_timeout)
[880]         != NGX_OK)
[881]     {
[882]         return NGX_CONF_ERROR;
[883]     }
[884] 
[885]     ngx_conf_merge_value(conf->session_tickets,
[886]                          prev->session_tickets, 1);
[887] 
[888] #ifdef SSL_OP_NO_TICKET
[889]     if (!conf->session_tickets) {
[890]         SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
[891]     }
[892] #endif
[893] 
[894]     ngx_conf_merge_ptr_value(conf->session_ticket_keys,
[895]                          prev->session_ticket_keys, NULL);
[896] 
[897]     if (ngx_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
[898]         != NGX_OK)
[899]     {
[900]         return NGX_CONF_ERROR;
[901]     }
[902] 
[903]     if (ngx_ssl_conf_commands(cf, &conf->ssl, conf->conf_commands) != NGX_OK) {
[904]         return NGX_CONF_ERROR;
[905]     }
[906] 
[907]     return NGX_CONF_OK;
[908] }
[909] 
[910] 
[911] static ngx_int_t
[912] ngx_stream_ssl_compile_certificates(ngx_conf_t *cf,
[913]     ngx_stream_ssl_conf_t *conf)
[914] {
[915]     ngx_str_t                           *cert, *key;
[916]     ngx_uint_t                           i, nelts;
[917]     ngx_stream_complex_value_t          *cv;
[918]     ngx_stream_compile_complex_value_t   ccv;
[919] 
[920]     cert = conf->certificates->elts;
[921]     key = conf->certificate_keys->elts;
[922]     nelts = conf->certificates->nelts;
[923] 
[924]     for (i = 0; i < nelts; i++) {
[925] 
[926]         if (ngx_stream_script_variables_count(&cert[i])) {
[927]             goto found;
[928]         }
[929] 
[930]         if (ngx_stream_script_variables_count(&key[i])) {
[931]             goto found;
[932]         }
[933]     }
[934] 
[935]     return NGX_OK;
[936] 
[937] found:
[938] 
[939]     conf->certificate_values = ngx_array_create(cf->pool, nelts,
[940]                                            sizeof(ngx_stream_complex_value_t));
[941]     if (conf->certificate_values == NULL) {
[942]         return NGX_ERROR;
[943]     }
[944] 
[945]     conf->certificate_key_values = ngx_array_create(cf->pool, nelts,
[946]                                            sizeof(ngx_stream_complex_value_t));
[947]     if (conf->certificate_key_values == NULL) {
[948]         return NGX_ERROR;
[949]     }
[950] 
[951]     for (i = 0; i < nelts; i++) {
[952] 
[953]         cv = ngx_array_push(conf->certificate_values);
[954]         if (cv == NULL) {
[955]             return NGX_ERROR;
[956]         }
[957] 
[958]         ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[959] 
[960]         ccv.cf = cf;
[961]         ccv.value = &cert[i];
[962]         ccv.complex_value = cv;
[963]         ccv.zero = 1;
[964] 
[965]         if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[966]             return NGX_ERROR;
[967]         }
[968] 
[969]         cv = ngx_array_push(conf->certificate_key_values);
[970]         if (cv == NULL) {
[971]             return NGX_ERROR;
[972]         }
[973] 
[974]         ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[975] 
[976]         ccv.cf = cf;
[977]         ccv.value = &key[i];
[978]         ccv.complex_value = cv;
[979]         ccv.zero = 1;
[980] 
[981]         if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[982]             return NGX_ERROR;
[983]         }
[984]     }
[985] 
[986]     conf->passwords = ngx_ssl_preserve_passwords(cf, conf->passwords);
[987]     if (conf->passwords == NULL) {
[988]         return NGX_ERROR;
[989]     }
[990] 
[991]     return NGX_OK;
[992] }
[993] 
[994] 
[995] static char *
[996] ngx_stream_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[997] {
[998]     ngx_stream_ssl_conf_t  *scf = conf;
[999] 
[1000]     ngx_str_t  *value;
[1001] 
[1002]     if (scf->passwords != NGX_CONF_UNSET_PTR) {
[1003]         return "is duplicate";
[1004]     }
[1005] 
[1006]     value = cf->args->elts;
[1007] 
[1008]     scf->passwords = ngx_ssl_read_password_file(cf, &value[1]);
[1009] 
[1010]     if (scf->passwords == NULL) {
[1011]         return NGX_CONF_ERROR;
[1012]     }
[1013] 
[1014]     return NGX_CONF_OK;
[1015] }
[1016] 
[1017] 
[1018] static char *
[1019] ngx_stream_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1020] {
[1021]     ngx_stream_ssl_conf_t  *scf = conf;
[1022] 
[1023]     size_t       len;
[1024]     ngx_str_t   *value, name, size;
[1025]     ngx_int_t    n;
[1026]     ngx_uint_t   i, j;
[1027] 
[1028]     value = cf->args->elts;
[1029] 
[1030]     for (i = 1; i < cf->args->nelts; i++) {
[1031] 
[1032]         if (ngx_strcmp(value[i].data, "off") == 0) {
[1033]             scf->builtin_session_cache = NGX_SSL_NO_SCACHE;
[1034]             continue;
[1035]         }
[1036] 
[1037]         if (ngx_strcmp(value[i].data, "none") == 0) {
[1038]             scf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
[1039]             continue;
[1040]         }
[1041] 
[1042]         if (ngx_strcmp(value[i].data, "builtin") == 0) {
[1043]             scf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
[1044]             continue;
[1045]         }
[1046] 
[1047]         if (value[i].len > sizeof("builtin:") - 1
[1048]             && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
[1049]                == 0)
[1050]         {
[1051]             n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
[1052]                          value[i].len - (sizeof("builtin:") - 1));
[1053] 
[1054]             if (n == NGX_ERROR) {
[1055]                 goto invalid;
[1056]             }
[1057] 
[1058]             scf->builtin_session_cache = n;
[1059] 
[1060]             continue;
[1061]         }
[1062] 
[1063]         if (value[i].len > sizeof("shared:") - 1
[1064]             && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
[1065]                == 0)
[1066]         {
[1067]             len = 0;
[1068] 
[1069]             for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
[1070]                 if (value[i].data[j] == ':') {
[1071]                     break;
[1072]                 }
[1073] 
[1074]                 len++;
[1075]             }
[1076] 
[1077]             if (len == 0 || j == value[i].len) {
[1078]                 goto invalid;
[1079]             }
[1080] 
[1081]             name.len = len;
[1082]             name.data = value[i].data + sizeof("shared:") - 1;
[1083] 
[1084]             size.len = value[i].len - j - 1;
[1085]             size.data = name.data + len + 1;
[1086] 
[1087]             n = ngx_parse_size(&size);
[1088] 
[1089]             if (n == NGX_ERROR) {
[1090]                 goto invalid;
[1091]             }
[1092] 
[1093]             if (n < (ngx_int_t) (8 * ngx_pagesize)) {
[1094]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1095]                                    "session cache \"%V\" is too small",
[1096]                                    &value[i]);
[1097] 
[1098]                 return NGX_CONF_ERROR;
[1099]             }
[1100] 
[1101]             scf->shm_zone = ngx_shared_memory_add(cf, &name, n,
[1102]                                                    &ngx_stream_ssl_module);
[1103]             if (scf->shm_zone == NULL) {
[1104]                 return NGX_CONF_ERROR;
[1105]             }
[1106] 
[1107]             scf->shm_zone->init = ngx_ssl_session_cache_init;
[1108] 
[1109]             continue;
[1110]         }
[1111] 
[1112]         goto invalid;
[1113]     }
[1114] 
[1115]     if (scf->shm_zone && scf->builtin_session_cache == NGX_CONF_UNSET) {
[1116]         scf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
[1117]     }
[1118] 
[1119]     return NGX_CONF_OK;
[1120] 
[1121] invalid:
[1122] 
[1123]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1124]                        "invalid session cache \"%V\"", &value[i]);
[1125] 
[1126]     return NGX_CONF_ERROR;
[1127] }
[1128] 
[1129] 
[1130] static char *
[1131] ngx_stream_ssl_alpn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1132] {
[1133] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[1134] 
[1135]     ngx_stream_ssl_conf_t  *scf = conf;
[1136] 
[1137]     u_char      *p;
[1138]     size_t       len;
[1139]     ngx_str_t   *value;
[1140]     ngx_uint_t   i;
[1141] 
[1142]     if (scf->alpn.len) {
[1143]         return "is duplicate";
[1144]     }
[1145] 
[1146]     value = cf->args->elts;
[1147] 
[1148]     len = 0;
[1149] 
[1150]     for (i = 1; i < cf->args->nelts; i++) {
[1151] 
[1152]         if (value[i].len > 255) {
[1153]             return "protocol too long";
[1154]         }
[1155] 
[1156]         len += value[i].len + 1;
[1157]     }
[1158] 
[1159]     scf->alpn.data = ngx_pnalloc(cf->pool, len);
[1160]     if (scf->alpn.data == NULL) {
[1161]         return NGX_CONF_ERROR;
[1162]     }
[1163] 
[1164]     p = scf->alpn.data;
[1165] 
[1166]     for (i = 1; i < cf->args->nelts; i++) {
[1167]         *p++ = value[i].len;
[1168]         p = ngx_cpymem(p, value[i].data, value[i].len);
[1169]     }
[1170] 
[1171]     scf->alpn.len = len;
[1172] 
[1173]     return NGX_CONF_OK;
[1174] 
[1175] #else
[1176]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1177]                        "the \"ssl_alpn\" directive requires OpenSSL "
[1178]                        "with ALPN support");
[1179]     return NGX_CONF_ERROR;
[1180] #endif
[1181] }
[1182] 
[1183] 
[1184] static char *
[1185] ngx_stream_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[1186] {
[1187] #ifndef SSL_CONF_FLAG_FILE
[1188]     return "is not supported on this platform";
[1189] #else
[1190]     return NGX_CONF_OK;
[1191] #endif
[1192] }
[1193] 
[1194] 
[1195] static ngx_int_t
[1196] ngx_stream_ssl_init(ngx_conf_t *cf)
[1197] {
[1198]     ngx_stream_handler_pt        *h;
[1199]     ngx_stream_core_main_conf_t  *cmcf;
[1200] 
[1201]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[1202] 
[1203]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);
[1204]     if (h == NULL) {
[1205]         return NGX_ERROR;
[1206]     }
[1207] 
[1208]     *h = ngx_stream_ssl_handler;
[1209] 
[1210]     return NGX_OK;
[1211] }
