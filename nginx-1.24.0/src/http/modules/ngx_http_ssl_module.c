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
[13] typedef ngx_int_t (*ngx_ssl_variable_handler_pt)(ngx_connection_t *c,
[14]     ngx_pool_t *pool, ngx_str_t *s);
[15] 
[16] 
[17] #define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
[18] #define NGX_DEFAULT_ECDH_CURVE  "auto"
[19] 
[20] #define NGX_HTTP_ALPN_PROTOS    "\x08http/1.1\x08http/1.0\x08http/0.9"
[21] 
[22] 
[23] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[24] static int ngx_http_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn,
[25]     const unsigned char **out, unsigned char *outlen,
[26]     const unsigned char *in, unsigned int inlen, void *arg);
[27] #endif
[28] 
[29] static ngx_int_t ngx_http_ssl_static_variable(ngx_http_request_t *r,
[30]     ngx_http_variable_value_t *v, uintptr_t data);
[31] static ngx_int_t ngx_http_ssl_variable(ngx_http_request_t *r,
[32]     ngx_http_variable_value_t *v, uintptr_t data);
[33] 
[34] static ngx_int_t ngx_http_ssl_add_variables(ngx_conf_t *cf);
[35] static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
[36] static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
[37]     void *parent, void *child);
[38] 
[39] static ngx_int_t ngx_http_ssl_compile_certificates(ngx_conf_t *cf,
[40]     ngx_http_ssl_srv_conf_t *conf);
[41] 
[42] static char *ngx_http_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd,
[43]     void *conf);
[44] static char *ngx_http_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
[45]     void *conf);
[46] static char *ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[47]     void *conf);
[48] static char *ngx_http_ssl_ocsp_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[49]     void *conf);
[50] 
[51] static char *ngx_http_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[52]     void *data);
[53] 
[54] static ngx_int_t ngx_http_ssl_init(ngx_conf_t *cf);
[55] 
[56] 
[57] static ngx_conf_bitmask_t  ngx_http_ssl_protocols[] = {
[58]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[59]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[60]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[61]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[62]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[63]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[64]     { ngx_null_string, 0 }
[65] };
[66] 
[67] 
[68] static ngx_conf_enum_t  ngx_http_ssl_verify[] = {
[69]     { ngx_string("off"), 0 },
[70]     { ngx_string("on"), 1 },
[71]     { ngx_string("optional"), 2 },
[72]     { ngx_string("optional_no_ca"), 3 },
[73]     { ngx_null_string, 0 }
[74] };
[75] 
[76] 
[77] static ngx_conf_enum_t  ngx_http_ssl_ocsp[] = {
[78]     { ngx_string("off"), 0 },
[79]     { ngx_string("on"), 1 },
[80]     { ngx_string("leaf"), 2 },
[81]     { ngx_null_string, 0 }
[82] };
[83] 
[84] 
[85] static ngx_conf_deprecated_t  ngx_http_ssl_deprecated = {
[86]     ngx_conf_deprecated, "ssl", "listen ... ssl"
[87] };
[88] 
[89] 
[90] static ngx_conf_post_t  ngx_http_ssl_conf_command_post =
[91]     { ngx_http_ssl_conf_command_check };
[92] 
[93] 
[94] static ngx_command_t  ngx_http_ssl_commands[] = {
[95] 
[96]     { ngx_string("ssl"),
[97]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[98]       ngx_http_ssl_enable,
[99]       NGX_HTTP_SRV_CONF_OFFSET,
[100]       offsetof(ngx_http_ssl_srv_conf_t, enable),
[101]       &ngx_http_ssl_deprecated },
[102] 
[103]     { ngx_string("ssl_certificate"),
[104]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[105]       ngx_conf_set_str_array_slot,
[106]       NGX_HTTP_SRV_CONF_OFFSET,
[107]       offsetof(ngx_http_ssl_srv_conf_t, certificates),
[108]       NULL },
[109] 
[110]     { ngx_string("ssl_certificate_key"),
[111]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[112]       ngx_conf_set_str_array_slot,
[113]       NGX_HTTP_SRV_CONF_OFFSET,
[114]       offsetof(ngx_http_ssl_srv_conf_t, certificate_keys),
[115]       NULL },
[116] 
[117]     { ngx_string("ssl_password_file"),
[118]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[119]       ngx_http_ssl_password_file,
[120]       NGX_HTTP_SRV_CONF_OFFSET,
[121]       0,
[122]       NULL },
[123] 
[124]     { ngx_string("ssl_dhparam"),
[125]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[126]       ngx_conf_set_str_slot,
[127]       NGX_HTTP_SRV_CONF_OFFSET,
[128]       offsetof(ngx_http_ssl_srv_conf_t, dhparam),
[129]       NULL },
[130] 
[131]     { ngx_string("ssl_ecdh_curve"),
[132]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[133]       ngx_conf_set_str_slot,
[134]       NGX_HTTP_SRV_CONF_OFFSET,
[135]       offsetof(ngx_http_ssl_srv_conf_t, ecdh_curve),
[136]       NULL },
[137] 
[138]     { ngx_string("ssl_protocols"),
[139]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
[140]       ngx_conf_set_bitmask_slot,
[141]       NGX_HTTP_SRV_CONF_OFFSET,
[142]       offsetof(ngx_http_ssl_srv_conf_t, protocols),
[143]       &ngx_http_ssl_protocols },
[144] 
[145]     { ngx_string("ssl_ciphers"),
[146]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[147]       ngx_conf_set_str_slot,
[148]       NGX_HTTP_SRV_CONF_OFFSET,
[149]       offsetof(ngx_http_ssl_srv_conf_t, ciphers),
[150]       NULL },
[151] 
[152]     { ngx_string("ssl_buffer_size"),
[153]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[154]       ngx_conf_set_size_slot,
[155]       NGX_HTTP_SRV_CONF_OFFSET,
[156]       offsetof(ngx_http_ssl_srv_conf_t, buffer_size),
[157]       NULL },
[158] 
[159]     { ngx_string("ssl_verify_client"),
[160]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[161]       ngx_conf_set_enum_slot,
[162]       NGX_HTTP_SRV_CONF_OFFSET,
[163]       offsetof(ngx_http_ssl_srv_conf_t, verify),
[164]       &ngx_http_ssl_verify },
[165] 
[166]     { ngx_string("ssl_verify_depth"),
[167]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[168]       ngx_conf_set_num_slot,
[169]       NGX_HTTP_SRV_CONF_OFFSET,
[170]       offsetof(ngx_http_ssl_srv_conf_t, verify_depth),
[171]       NULL },
[172] 
[173]     { ngx_string("ssl_client_certificate"),
[174]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[175]       ngx_conf_set_str_slot,
[176]       NGX_HTTP_SRV_CONF_OFFSET,
[177]       offsetof(ngx_http_ssl_srv_conf_t, client_certificate),
[178]       NULL },
[179] 
[180]     { ngx_string("ssl_trusted_certificate"),
[181]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[182]       ngx_conf_set_str_slot,
[183]       NGX_HTTP_SRV_CONF_OFFSET,
[184]       offsetof(ngx_http_ssl_srv_conf_t, trusted_certificate),
[185]       NULL },
[186] 
[187]     { ngx_string("ssl_prefer_server_ciphers"),
[188]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[189]       ngx_conf_set_flag_slot,
[190]       NGX_HTTP_SRV_CONF_OFFSET,
[191]       offsetof(ngx_http_ssl_srv_conf_t, prefer_server_ciphers),
[192]       NULL },
[193] 
[194]     { ngx_string("ssl_session_cache"),
[195]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
[196]       ngx_http_ssl_session_cache,
[197]       NGX_HTTP_SRV_CONF_OFFSET,
[198]       0,
[199]       NULL },
[200] 
[201]     { ngx_string("ssl_session_tickets"),
[202]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[203]       ngx_conf_set_flag_slot,
[204]       NGX_HTTP_SRV_CONF_OFFSET,
[205]       offsetof(ngx_http_ssl_srv_conf_t, session_tickets),
[206]       NULL },
[207] 
[208]     { ngx_string("ssl_session_ticket_key"),
[209]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[210]       ngx_conf_set_str_array_slot,
[211]       NGX_HTTP_SRV_CONF_OFFSET,
[212]       offsetof(ngx_http_ssl_srv_conf_t, session_ticket_keys),
[213]       NULL },
[214] 
[215]     { ngx_string("ssl_session_timeout"),
[216]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[217]       ngx_conf_set_sec_slot,
[218]       NGX_HTTP_SRV_CONF_OFFSET,
[219]       offsetof(ngx_http_ssl_srv_conf_t, session_timeout),
[220]       NULL },
[221] 
[222]     { ngx_string("ssl_crl"),
[223]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[224]       ngx_conf_set_str_slot,
[225]       NGX_HTTP_SRV_CONF_OFFSET,
[226]       offsetof(ngx_http_ssl_srv_conf_t, crl),
[227]       NULL },
[228] 
[229]     { ngx_string("ssl_ocsp"),
[230]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[231]       ngx_conf_set_enum_slot,
[232]       NGX_HTTP_SRV_CONF_OFFSET,
[233]       offsetof(ngx_http_ssl_srv_conf_t, ocsp),
[234]       &ngx_http_ssl_ocsp },
[235] 
[236]     { ngx_string("ssl_ocsp_responder"),
[237]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[238]       ngx_conf_set_str_slot,
[239]       NGX_HTTP_SRV_CONF_OFFSET,
[240]       offsetof(ngx_http_ssl_srv_conf_t, ocsp_responder),
[241]       NULL },
[242] 
[243]     { ngx_string("ssl_ocsp_cache"),
[244]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[245]       ngx_http_ssl_ocsp_cache,
[246]       NGX_HTTP_SRV_CONF_OFFSET,
[247]       0,
[248]       NULL },
[249] 
[250]     { ngx_string("ssl_stapling"),
[251]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[252]       ngx_conf_set_flag_slot,
[253]       NGX_HTTP_SRV_CONF_OFFSET,
[254]       offsetof(ngx_http_ssl_srv_conf_t, stapling),
[255]       NULL },
[256] 
[257]     { ngx_string("ssl_stapling_file"),
[258]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[259]       ngx_conf_set_str_slot,
[260]       NGX_HTTP_SRV_CONF_OFFSET,
[261]       offsetof(ngx_http_ssl_srv_conf_t, stapling_file),
[262]       NULL },
[263] 
[264]     { ngx_string("ssl_stapling_responder"),
[265]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
[266]       ngx_conf_set_str_slot,
[267]       NGX_HTTP_SRV_CONF_OFFSET,
[268]       offsetof(ngx_http_ssl_srv_conf_t, stapling_responder),
[269]       NULL },
[270] 
[271]     { ngx_string("ssl_stapling_verify"),
[272]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[273]       ngx_conf_set_flag_slot,
[274]       NGX_HTTP_SRV_CONF_OFFSET,
[275]       offsetof(ngx_http_ssl_srv_conf_t, stapling_verify),
[276]       NULL },
[277] 
[278]     { ngx_string("ssl_early_data"),
[279]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[280]       ngx_conf_set_flag_slot,
[281]       NGX_HTTP_SRV_CONF_OFFSET,
[282]       offsetof(ngx_http_ssl_srv_conf_t, early_data),
[283]       NULL },
[284] 
[285]     { ngx_string("ssl_conf_command"),
[286]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
[287]       ngx_conf_set_keyval_slot,
[288]       NGX_HTTP_SRV_CONF_OFFSET,
[289]       offsetof(ngx_http_ssl_srv_conf_t, conf_commands),
[290]       &ngx_http_ssl_conf_command_post },
[291] 
[292]     { ngx_string("ssl_reject_handshake"),
[293]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
[294]       ngx_conf_set_flag_slot,
[295]       NGX_HTTP_SRV_CONF_OFFSET,
[296]       offsetof(ngx_http_ssl_srv_conf_t, reject_handshake),
[297]       NULL },
[298] 
[299]       ngx_null_command
[300] };
[301] 
[302] 
[303] static ngx_http_module_t  ngx_http_ssl_module_ctx = {
[304]     ngx_http_ssl_add_variables,            /* preconfiguration */
[305]     ngx_http_ssl_init,                     /* postconfiguration */
[306] 
[307]     NULL,                                  /* create main configuration */
[308]     NULL,                                  /* init main configuration */
[309] 
[310]     ngx_http_ssl_create_srv_conf,          /* create server configuration */
[311]     ngx_http_ssl_merge_srv_conf,           /* merge server configuration */
[312] 
[313]     NULL,                                  /* create location configuration */
[314]     NULL                                   /* merge location configuration */
[315] };
[316] 
[317] 
[318] ngx_module_t  ngx_http_ssl_module = {
[319]     NGX_MODULE_V1,
[320]     &ngx_http_ssl_module_ctx,              /* module context */
[321]     ngx_http_ssl_commands,                 /* module directives */
[322]     NGX_HTTP_MODULE,                       /* module type */
[323]     NULL,                                  /* init master */
[324]     NULL,                                  /* init module */
[325]     NULL,                                  /* init process */
[326]     NULL,                                  /* init thread */
[327]     NULL,                                  /* exit thread */
[328]     NULL,                                  /* exit process */
[329]     NULL,                                  /* exit master */
[330]     NGX_MODULE_V1_PADDING
[331] };
[332] 
[333] 
[334] static ngx_http_variable_t  ngx_http_ssl_vars[] = {
[335] 
[336]     { ngx_string("ssl_protocol"), NULL, ngx_http_ssl_static_variable,
[337]       (uintptr_t) ngx_ssl_get_protocol, NGX_HTTP_VAR_CHANGEABLE, 0 },
[338] 
[339]     { ngx_string("ssl_cipher"), NULL, ngx_http_ssl_static_variable,
[340]       (uintptr_t) ngx_ssl_get_cipher_name, NGX_HTTP_VAR_CHANGEABLE, 0 },
[341] 
[342]     { ngx_string("ssl_ciphers"), NULL, ngx_http_ssl_variable,
[343]       (uintptr_t) ngx_ssl_get_ciphers, NGX_HTTP_VAR_CHANGEABLE, 0 },
[344] 
[345]     { ngx_string("ssl_curve"), NULL, ngx_http_ssl_variable,
[346]       (uintptr_t) ngx_ssl_get_curve, NGX_HTTP_VAR_CHANGEABLE, 0 },
[347] 
[348]     { ngx_string("ssl_curves"), NULL, ngx_http_ssl_variable,
[349]       (uintptr_t) ngx_ssl_get_curves, NGX_HTTP_VAR_CHANGEABLE, 0 },
[350] 
[351]     { ngx_string("ssl_session_id"), NULL, ngx_http_ssl_variable,
[352]       (uintptr_t) ngx_ssl_get_session_id, NGX_HTTP_VAR_CHANGEABLE, 0 },
[353] 
[354]     { ngx_string("ssl_session_reused"), NULL, ngx_http_ssl_variable,
[355]       (uintptr_t) ngx_ssl_get_session_reused, NGX_HTTP_VAR_CHANGEABLE, 0 },
[356] 
[357]     { ngx_string("ssl_early_data"), NULL, ngx_http_ssl_variable,
[358]       (uintptr_t) ngx_ssl_get_early_data,
[359]       NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },
[360] 
[361]     { ngx_string("ssl_server_name"), NULL, ngx_http_ssl_variable,
[362]       (uintptr_t) ngx_ssl_get_server_name, NGX_HTTP_VAR_CHANGEABLE, 0 },
[363] 
[364]     { ngx_string("ssl_alpn_protocol"), NULL, ngx_http_ssl_variable,
[365]       (uintptr_t) ngx_ssl_get_alpn_protocol, NGX_HTTP_VAR_CHANGEABLE, 0 },
[366] 
[367]     { ngx_string("ssl_client_cert"), NULL, ngx_http_ssl_variable,
[368]       (uintptr_t) ngx_ssl_get_certificate, NGX_HTTP_VAR_CHANGEABLE, 0 },
[369] 
[370]     { ngx_string("ssl_client_raw_cert"), NULL, ngx_http_ssl_variable,
[371]       (uintptr_t) ngx_ssl_get_raw_certificate,
[372]       NGX_HTTP_VAR_CHANGEABLE, 0 },
[373] 
[374]     { ngx_string("ssl_client_escaped_cert"), NULL, ngx_http_ssl_variable,
[375]       (uintptr_t) ngx_ssl_get_escaped_certificate,
[376]       NGX_HTTP_VAR_CHANGEABLE, 0 },
[377] 
[378]     { ngx_string("ssl_client_s_dn"), NULL, ngx_http_ssl_variable,
[379]       (uintptr_t) ngx_ssl_get_subject_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },
[380] 
[381]     { ngx_string("ssl_client_i_dn"), NULL, ngx_http_ssl_variable,
[382]       (uintptr_t) ngx_ssl_get_issuer_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },
[383] 
[384]     { ngx_string("ssl_client_s_dn_legacy"), NULL, ngx_http_ssl_variable,
[385]       (uintptr_t) ngx_ssl_get_subject_dn_legacy, NGX_HTTP_VAR_CHANGEABLE, 0 },
[386] 
[387]     { ngx_string("ssl_client_i_dn_legacy"), NULL, ngx_http_ssl_variable,
[388]       (uintptr_t) ngx_ssl_get_issuer_dn_legacy, NGX_HTTP_VAR_CHANGEABLE, 0 },
[389] 
[390]     { ngx_string("ssl_client_serial"), NULL, ngx_http_ssl_variable,
[391]       (uintptr_t) ngx_ssl_get_serial_number, NGX_HTTP_VAR_CHANGEABLE, 0 },
[392] 
[393]     { ngx_string("ssl_client_fingerprint"), NULL, ngx_http_ssl_variable,
[394]       (uintptr_t) ngx_ssl_get_fingerprint, NGX_HTTP_VAR_CHANGEABLE, 0 },
[395] 
[396]     { ngx_string("ssl_client_verify"), NULL, ngx_http_ssl_variable,
[397]       (uintptr_t) ngx_ssl_get_client_verify, NGX_HTTP_VAR_CHANGEABLE, 0 },
[398] 
[399]     { ngx_string("ssl_client_v_start"), NULL, ngx_http_ssl_variable,
[400]       (uintptr_t) ngx_ssl_get_client_v_start, NGX_HTTP_VAR_CHANGEABLE, 0 },
[401] 
[402]     { ngx_string("ssl_client_v_end"), NULL, ngx_http_ssl_variable,
[403]       (uintptr_t) ngx_ssl_get_client_v_end, NGX_HTTP_VAR_CHANGEABLE, 0 },
[404] 
[405]     { ngx_string("ssl_client_v_remain"), NULL, ngx_http_ssl_variable,
[406]       (uintptr_t) ngx_ssl_get_client_v_remain, NGX_HTTP_VAR_CHANGEABLE, 0 },
[407] 
[408]       ngx_http_null_variable
[409] };
[410] 
[411] 
[412] static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");
[413] 
[414] 
[415] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[416] 
[417] static int
[418] ngx_http_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn, const unsigned char **out,
[419]     unsigned char *outlen, const unsigned char *in, unsigned int inlen,
[420]     void *arg)
[421] {
[422]     unsigned int            srvlen;
[423]     unsigned char          *srv;
[424] #if (NGX_DEBUG)
[425]     unsigned int            i;
[426] #endif
[427] #if (NGX_HTTP_V2)
[428]     ngx_http_connection_t  *hc;
[429] #endif
[430] #if (NGX_HTTP_V2 || NGX_DEBUG)
[431]     ngx_connection_t       *c;
[432] 
[433]     c = ngx_ssl_get_connection(ssl_conn);
[434] #endif
[435] 
[436] #if (NGX_DEBUG)
[437]     for (i = 0; i < inlen; i += in[i] + 1) {
[438]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[439]                        "SSL ALPN supported by client: %*s",
[440]                        (size_t) in[i], &in[i + 1]);
[441]     }
[442] #endif
[443] 
[444] #if (NGX_HTTP_V2)
[445]     hc = c->data;
[446] 
[447]     if (hc->addr_conf->http2) {
[448]         srv = (unsigned char *) NGX_HTTP_V2_ALPN_PROTO NGX_HTTP_ALPN_PROTOS;
[449]         srvlen = sizeof(NGX_HTTP_V2_ALPN_PROTO NGX_HTTP_ALPN_PROTOS) - 1;
[450]     } else
[451] #endif
[452]     {
[453]         srv = (unsigned char *) NGX_HTTP_ALPN_PROTOS;
[454]         srvlen = sizeof(NGX_HTTP_ALPN_PROTOS) - 1;
[455]     }
[456] 
[457]     if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
[458]                               in, inlen)
[459]         != OPENSSL_NPN_NEGOTIATED)
[460]     {
[461]         return SSL_TLSEXT_ERR_ALERT_FATAL;
[462]     }
[463] 
[464]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[465]                    "SSL ALPN selected: %*s", (size_t) *outlen, *out);
[466] 
[467]     return SSL_TLSEXT_ERR_OK;
[468] }
[469] 
[470] #endif
[471] 
[472] 
[473] static ngx_int_t
[474] ngx_http_ssl_static_variable(ngx_http_request_t *r,
[475]     ngx_http_variable_value_t *v, uintptr_t data)
[476] {
[477]     ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;
[478] 
[479]     size_t     len;
[480]     ngx_str_t  s;
[481] 
[482]     if (r->connection->ssl) {
[483] 
[484]         (void) handler(r->connection, NULL, &s);
[485] 
[486]         v->data = s.data;
[487] 
[488]         for (len = 0; v->data[len]; len++) { /* void */ }
[489] 
[490]         v->len = len;
[491]         v->valid = 1;
[492]         v->no_cacheable = 0;
[493]         v->not_found = 0;
[494] 
[495]         return NGX_OK;
[496]     }
[497] 
[498]     v->not_found = 1;
[499] 
[500]     return NGX_OK;
[501] }
[502] 
[503] 
[504] static ngx_int_t
[505] ngx_http_ssl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[506]     uintptr_t data)
[507] {
[508]     ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;
[509] 
[510]     ngx_str_t  s;
[511] 
[512]     if (r->connection->ssl) {
[513] 
[514]         if (handler(r->connection, r->pool, &s) != NGX_OK) {
[515]             return NGX_ERROR;
[516]         }
[517] 
[518]         v->len = s.len;
[519]         v->data = s.data;
[520] 
[521]         if (v->len) {
[522]             v->valid = 1;
[523]             v->no_cacheable = 0;
[524]             v->not_found = 0;
[525] 
[526]             return NGX_OK;
[527]         }
[528]     }
[529] 
[530]     v->not_found = 1;
[531] 
[532]     return NGX_OK;
[533] }
[534] 
[535] 
[536] static ngx_int_t
[537] ngx_http_ssl_add_variables(ngx_conf_t *cf)
[538] {
[539]     ngx_http_variable_t  *var, *v;
[540] 
[541]     for (v = ngx_http_ssl_vars; v->name.len; v++) {
[542]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[543]         if (var == NULL) {
[544]             return NGX_ERROR;
[545]         }
[546] 
[547]         var->get_handler = v->get_handler;
[548]         var->data = v->data;
[549]     }
[550] 
[551]     return NGX_OK;
[552] }
[553] 
[554] 
[555] static void *
[556] ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
[557] {
[558]     ngx_http_ssl_srv_conf_t  *sscf;
[559] 
[560]     sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t));
[561]     if (sscf == NULL) {
[562]         return NULL;
[563]     }
[564] 
[565]     /*
[566]      * set by ngx_pcalloc():
[567]      *
[568]      *     sscf->protocols = 0;
[569]      *     sscf->certificate_values = NULL;
[570]      *     sscf->dhparam = { 0, NULL };
[571]      *     sscf->ecdh_curve = { 0, NULL };
[572]      *     sscf->client_certificate = { 0, NULL };
[573]      *     sscf->trusted_certificate = { 0, NULL };
[574]      *     sscf->crl = { 0, NULL };
[575]      *     sscf->ciphers = { 0, NULL };
[576]      *     sscf->shm_zone = NULL;
[577]      *     sscf->ocsp_responder = { 0, NULL };
[578]      *     sscf->stapling_file = { 0, NULL };
[579]      *     sscf->stapling_responder = { 0, NULL };
[580]      */
[581] 
[582]     sscf->enable = NGX_CONF_UNSET;
[583]     sscf->prefer_server_ciphers = NGX_CONF_UNSET;
[584]     sscf->early_data = NGX_CONF_UNSET;
[585]     sscf->reject_handshake = NGX_CONF_UNSET;
[586]     sscf->buffer_size = NGX_CONF_UNSET_SIZE;
[587]     sscf->verify = NGX_CONF_UNSET_UINT;
[588]     sscf->verify_depth = NGX_CONF_UNSET_UINT;
[589]     sscf->certificates = NGX_CONF_UNSET_PTR;
[590]     sscf->certificate_keys = NGX_CONF_UNSET_PTR;
[591]     sscf->passwords = NGX_CONF_UNSET_PTR;
[592]     sscf->conf_commands = NGX_CONF_UNSET_PTR;
[593]     sscf->builtin_session_cache = NGX_CONF_UNSET;
[594]     sscf->session_timeout = NGX_CONF_UNSET;
[595]     sscf->session_tickets = NGX_CONF_UNSET;
[596]     sscf->session_ticket_keys = NGX_CONF_UNSET_PTR;
[597]     sscf->ocsp = NGX_CONF_UNSET_UINT;
[598]     sscf->ocsp_cache_zone = NGX_CONF_UNSET_PTR;
[599]     sscf->stapling = NGX_CONF_UNSET;
[600]     sscf->stapling_verify = NGX_CONF_UNSET;
[601] 
[602]     return sscf;
[603] }
[604] 
[605] 
[606] static char *
[607] ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[608] {
[609]     ngx_http_ssl_srv_conf_t *prev = parent;
[610]     ngx_http_ssl_srv_conf_t *conf = child;
[611] 
[612]     ngx_pool_cleanup_t  *cln;
[613] 
[614]     if (conf->enable == NGX_CONF_UNSET) {
[615]         if (prev->enable == NGX_CONF_UNSET) {
[616]             conf->enable = 0;
[617] 
[618]         } else {
[619]             conf->enable = prev->enable;
[620]             conf->file = prev->file;
[621]             conf->line = prev->line;
[622]         }
[623]     }
[624] 
[625]     ngx_conf_merge_value(conf->session_timeout,
[626]                          prev->session_timeout, 300);
[627] 
[628]     ngx_conf_merge_value(conf->prefer_server_ciphers,
[629]                          prev->prefer_server_ciphers, 0);
[630] 
[631]     ngx_conf_merge_value(conf->early_data, prev->early_data, 0);
[632]     ngx_conf_merge_value(conf->reject_handshake, prev->reject_handshake, 0);
[633] 
[634]     ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
[635]                          (NGX_CONF_BITMASK_SET
[636]                           |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[637]                           |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[638] 
[639]     ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
[640]                          NGX_SSL_BUFSIZE);
[641] 
[642]     ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
[643]     ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);
[644] 
[645]     ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
[646]     ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
[647]                          NULL);
[648] 
[649]     ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);
[650] 
[651]     ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");
[652] 
[653]     ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
[654]                          "");
[655]     ngx_conf_merge_str_value(conf->trusted_certificate,
[656]                          prev->trusted_certificate, "");
[657]     ngx_conf_merge_str_value(conf->crl, prev->crl, "");
[658] 
[659]     ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
[660]                          NGX_DEFAULT_ECDH_CURVE);
[661] 
[662]     ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);
[663] 
[664]     ngx_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);
[665] 
[666]     ngx_conf_merge_uint_value(conf->ocsp, prev->ocsp, 0);
[667]     ngx_conf_merge_str_value(conf->ocsp_responder, prev->ocsp_responder, "");
[668]     ngx_conf_merge_ptr_value(conf->ocsp_cache_zone,
[669]                          prev->ocsp_cache_zone, NULL);
[670] 
[671]     ngx_conf_merge_value(conf->stapling, prev->stapling, 0);
[672]     ngx_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
[673]     ngx_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
[674]     ngx_conf_merge_str_value(conf->stapling_responder,
[675]                          prev->stapling_responder, "");
[676] 
[677]     conf->ssl.log = cf->log;
[678] 
[679]     if (conf->enable) {
[680] 
[681]         if (conf->certificates) {
[682]             if (conf->certificate_keys == NULL) {
[683]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[684]                               "no \"ssl_certificate_key\" is defined for "
[685]                               "the \"ssl\" directive in %s:%ui",
[686]                               conf->file, conf->line);
[687]                 return NGX_CONF_ERROR;
[688]             }
[689] 
[690]             if (conf->certificate_keys->nelts < conf->certificates->nelts) {
[691]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[692]                               "no \"ssl_certificate_key\" is defined "
[693]                               "for certificate \"%V\" and "
[694]                               "the \"ssl\" directive in %s:%ui",
[695]                               ((ngx_str_t *) conf->certificates->elts)
[696]                               + conf->certificates->nelts - 1,
[697]                               conf->file, conf->line);
[698]                 return NGX_CONF_ERROR;
[699]             }
[700] 
[701]         } else if (!conf->reject_handshake) {
[702]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[703]                           "no \"ssl_certificate\" is defined for "
[704]                           "the \"ssl\" directive in %s:%ui",
[705]                           conf->file, conf->line);
[706]             return NGX_CONF_ERROR;
[707]         }
[708] 
[709]     } else if (conf->certificates) {
[710] 
[711]         if (conf->certificate_keys == NULL
[712]             || conf->certificate_keys->nelts < conf->certificates->nelts)
[713]         {
[714]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[715]                           "no \"ssl_certificate_key\" is defined "
[716]                           "for certificate \"%V\"",
[717]                           ((ngx_str_t *) conf->certificates->elts)
[718]                           + conf->certificates->nelts - 1);
[719]             return NGX_CONF_ERROR;
[720]         }
[721] 
[722]     } else if (!conf->reject_handshake) {
[723]         return NGX_CONF_OK;
[724]     }
[725] 
[726]     if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
[727]         return NGX_CONF_ERROR;
[728]     }
[729] 
[730]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[731]     if (cln == NULL) {
[732]         ngx_ssl_cleanup_ctx(&conf->ssl);
[733]         return NGX_CONF_ERROR;
[734]     }
[735] 
[736]     cln->handler = ngx_ssl_cleanup_ctx;
[737]     cln->data = &conf->ssl;
[738] 
[739] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[740] 
[741]     if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
[742]                                                ngx_http_ssl_servername)
[743]         == 0)
[744]     {
[745]         ngx_log_error(NGX_LOG_WARN, cf->log, 0,
[746]             "nginx was built with SNI support, however, now it is linked "
[747]             "dynamically to an OpenSSL library which has no tlsext support, "
[748]             "therefore SNI is not available");
[749]     }
[750] 
[751] #endif
[752] 
[753] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[754]     SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, ngx_http_ssl_alpn_select, NULL);
[755] #endif
[756] 
[757]     if (ngx_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
[758]                         conf->prefer_server_ciphers)
[759]         != NGX_OK)
[760]     {
[761]         return NGX_CONF_ERROR;
[762]     }
[763] 
[764]     if (ngx_http_ssl_compile_certificates(cf, conf) != NGX_OK) {
[765]         return NGX_CONF_ERROR;
[766]     }
[767] 
[768]     if (conf->certificate_values) {
[769] 
[770] #ifdef SSL_R_CERT_CB_ERROR
[771] 
[772]         /* install callback to lookup certificates */
[773] 
[774]         SSL_CTX_set_cert_cb(conf->ssl.ctx, ngx_http_ssl_certificate, conf);
[775] 
[776] #else
[777]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[778]                       "variables in "
[779]                       "\"ssl_certificate\" and \"ssl_certificate_key\" "
[780]                       "directives are not supported on this platform");
[781]         return NGX_CONF_ERROR;
[782] #endif
[783] 
[784]     } else if (conf->certificates) {
[785] 
[786]         /* configure certificates */
[787] 
[788]         if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
[789]                                  conf->certificate_keys, conf->passwords)
[790]             != NGX_OK)
[791]         {
[792]             return NGX_CONF_ERROR;
[793]         }
[794]     }
[795] 
[796]     conf->ssl.buffer_size = conf->buffer_size;
[797] 
[798]     if (conf->verify) {
[799] 
[800]         if (conf->client_certificate.len == 0 && conf->verify != 3) {
[801]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[802]                           "no ssl_client_certificate for ssl_verify_client");
[803]             return NGX_CONF_ERROR;
[804]         }
[805] 
[806]         if (ngx_ssl_client_certificate(cf, &conf->ssl,
[807]                                        &conf->client_certificate,
[808]                                        conf->verify_depth)
[809]             != NGX_OK)
[810]         {
[811]             return NGX_CONF_ERROR;
[812]         }
[813]     }
[814] 
[815]     if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
[816]                                     &conf->trusted_certificate,
[817]                                     conf->verify_depth)
[818]         != NGX_OK)
[819]     {
[820]         return NGX_CONF_ERROR;
[821]     }
[822] 
[823]     if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
[824]         return NGX_CONF_ERROR;
[825]     }
[826] 
[827]     if (conf->ocsp) {
[828] 
[829]         if (conf->verify == 3) {
[830]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[831]                           "\"ssl_ocsp\" is incompatible with "
[832]                           "\"ssl_verify_client optional_no_ca\"");
[833]             return NGX_CONF_ERROR;
[834]         }
[835] 
[836]         if (ngx_ssl_ocsp(cf, &conf->ssl, &conf->ocsp_responder, conf->ocsp,
[837]                          conf->ocsp_cache_zone)
[838]             != NGX_OK)
[839]         {
[840]             return NGX_CONF_ERROR;
[841]         }
[842]     }
[843] 
[844]     if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
[845]         return NGX_CONF_ERROR;
[846]     }
[847] 
[848]     if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
[849]         return NGX_CONF_ERROR;
[850]     }
[851] 
[852]     ngx_conf_merge_value(conf->builtin_session_cache,
[853]                          prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);
[854] 
[855]     if (conf->shm_zone == NULL) {
[856]         conf->shm_zone = prev->shm_zone;
[857]     }
[858] 
[859]     if (ngx_ssl_session_cache(&conf->ssl, &ngx_http_ssl_sess_id_ctx,
[860]                               conf->certificates, conf->builtin_session_cache,
[861]                               conf->shm_zone, conf->session_timeout)
[862]         != NGX_OK)
[863]     {
[864]         return NGX_CONF_ERROR;
[865]     }
[866] 
[867]     ngx_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);
[868] 
[869] #ifdef SSL_OP_NO_TICKET
[870]     if (!conf->session_tickets) {
[871]         SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
[872]     }
[873] #endif
[874] 
[875]     ngx_conf_merge_ptr_value(conf->session_ticket_keys,
[876]                          prev->session_ticket_keys, NULL);
[877] 
[878]     if (ngx_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
[879]         != NGX_OK)
[880]     {
[881]         return NGX_CONF_ERROR;
[882]     }
[883] 
[884]     if (conf->stapling) {
[885] 
[886]         if (ngx_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
[887]                              &conf->stapling_responder, conf->stapling_verify)
[888]             != NGX_OK)
[889]         {
[890]             return NGX_CONF_ERROR;
[891]         }
[892] 
[893]     }
[894] 
[895]     if (ngx_ssl_early_data(cf, &conf->ssl, conf->early_data) != NGX_OK) {
[896]         return NGX_CONF_ERROR;
[897]     }
[898] 
[899]     if (ngx_ssl_conf_commands(cf, &conf->ssl, conf->conf_commands) != NGX_OK) {
[900]         return NGX_CONF_ERROR;
[901]     }
[902] 
[903]     return NGX_CONF_OK;
[904] }
[905] 
[906] 
[907] static ngx_int_t
[908] ngx_http_ssl_compile_certificates(ngx_conf_t *cf,
[909]     ngx_http_ssl_srv_conf_t *conf)
[910] {
[911]     ngx_str_t                         *cert, *key;
[912]     ngx_uint_t                         i, nelts;
[913]     ngx_http_complex_value_t          *cv;
[914]     ngx_http_compile_complex_value_t   ccv;
[915] 
[916]     if (conf->certificates == NULL) {
[917]         return NGX_OK;
[918]     }
[919] 
[920]     cert = conf->certificates->elts;
[921]     key = conf->certificate_keys->elts;
[922]     nelts = conf->certificates->nelts;
[923] 
[924]     for (i = 0; i < nelts; i++) {
[925] 
[926]         if (ngx_http_script_variables_count(&cert[i])) {
[927]             goto found;
[928]         }
[929] 
[930]         if (ngx_http_script_variables_count(&key[i])) {
[931]             goto found;
[932]         }
[933]     }
[934] 
[935]     return NGX_OK;
[936] 
[937] found:
[938] 
[939]     conf->certificate_values = ngx_array_create(cf->pool, nelts,
[940]                                              sizeof(ngx_http_complex_value_t));
[941]     if (conf->certificate_values == NULL) {
[942]         return NGX_ERROR;
[943]     }
[944] 
[945]     conf->certificate_key_values = ngx_array_create(cf->pool, nelts,
[946]                                              sizeof(ngx_http_complex_value_t));
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
[958]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[959] 
[960]         ccv.cf = cf;
[961]         ccv.value = &cert[i];
[962]         ccv.complex_value = cv;
[963]         ccv.zero = 1;
[964] 
[965]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[966]             return NGX_ERROR;
[967]         }
[968] 
[969]         cv = ngx_array_push(conf->certificate_key_values);
[970]         if (cv == NULL) {
[971]             return NGX_ERROR;
[972]         }
[973] 
[974]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[975] 
[976]         ccv.cf = cf;
[977]         ccv.value = &key[i];
[978]         ccv.complex_value = cv;
[979]         ccv.zero = 1;
[980] 
[981]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
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
[996] ngx_http_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[997] {
[998]     ngx_http_ssl_srv_conf_t *sscf = conf;
[999] 
[1000]     char  *rv;
[1001] 
[1002]     rv = ngx_conf_set_flag_slot(cf, cmd, conf);
[1003] 
[1004]     if (rv != NGX_CONF_OK) {
[1005]         return rv;
[1006]     }
[1007] 
[1008]     sscf->file = cf->conf_file->file.name.data;
[1009]     sscf->line = cf->conf_file->line;
[1010] 
[1011]     return NGX_CONF_OK;
[1012] }
[1013] 
[1014] 
[1015] static char *
[1016] ngx_http_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1017] {
[1018]     ngx_http_ssl_srv_conf_t *sscf = conf;
[1019] 
[1020]     ngx_str_t  *value;
[1021] 
[1022]     if (sscf->passwords != NGX_CONF_UNSET_PTR) {
[1023]         return "is duplicate";
[1024]     }
[1025] 
[1026]     value = cf->args->elts;
[1027] 
[1028]     sscf->passwords = ngx_ssl_read_password_file(cf, &value[1]);
[1029] 
[1030]     if (sscf->passwords == NULL) {
[1031]         return NGX_CONF_ERROR;
[1032]     }
[1033] 
[1034]     return NGX_CONF_OK;
[1035] }
[1036] 
[1037] 
[1038] static char *
[1039] ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1040] {
[1041]     ngx_http_ssl_srv_conf_t *sscf = conf;
[1042] 
[1043]     size_t       len;
[1044]     ngx_str_t   *value, name, size;
[1045]     ngx_int_t    n;
[1046]     ngx_uint_t   i, j;
[1047] 
[1048]     value = cf->args->elts;
[1049] 
[1050]     for (i = 1; i < cf->args->nelts; i++) {
[1051] 
[1052]         if (ngx_strcmp(value[i].data, "off") == 0) {
[1053]             sscf->builtin_session_cache = NGX_SSL_NO_SCACHE;
[1054]             continue;
[1055]         }
[1056] 
[1057]         if (ngx_strcmp(value[i].data, "none") == 0) {
[1058]             sscf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
[1059]             continue;
[1060]         }
[1061] 
[1062]         if (ngx_strcmp(value[i].data, "builtin") == 0) {
[1063]             sscf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
[1064]             continue;
[1065]         }
[1066] 
[1067]         if (value[i].len > sizeof("builtin:") - 1
[1068]             && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
[1069]                == 0)
[1070]         {
[1071]             n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
[1072]                          value[i].len - (sizeof("builtin:") - 1));
[1073] 
[1074]             if (n == NGX_ERROR) {
[1075]                 goto invalid;
[1076]             }
[1077] 
[1078]             sscf->builtin_session_cache = n;
[1079] 
[1080]             continue;
[1081]         }
[1082] 
[1083]         if (value[i].len > sizeof("shared:") - 1
[1084]             && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
[1085]                == 0)
[1086]         {
[1087]             len = 0;
[1088] 
[1089]             for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
[1090]                 if (value[i].data[j] == ':') {
[1091]                     break;
[1092]                 }
[1093] 
[1094]                 len++;
[1095]             }
[1096] 
[1097]             if (len == 0 || j == value[i].len) {
[1098]                 goto invalid;
[1099]             }
[1100] 
[1101]             name.len = len;
[1102]             name.data = value[i].data + sizeof("shared:") - 1;
[1103] 
[1104]             size.len = value[i].len - j - 1;
[1105]             size.data = name.data + len + 1;
[1106] 
[1107]             n = ngx_parse_size(&size);
[1108] 
[1109]             if (n == NGX_ERROR) {
[1110]                 goto invalid;
[1111]             }
[1112] 
[1113]             if (n < (ngx_int_t) (8 * ngx_pagesize)) {
[1114]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1115]                                    "session cache \"%V\" is too small",
[1116]                                    &value[i]);
[1117] 
[1118]                 return NGX_CONF_ERROR;
[1119]             }
[1120] 
[1121]             sscf->shm_zone = ngx_shared_memory_add(cf, &name, n,
[1122]                                                    &ngx_http_ssl_module);
[1123]             if (sscf->shm_zone == NULL) {
[1124]                 return NGX_CONF_ERROR;
[1125]             }
[1126] 
[1127]             sscf->shm_zone->init = ngx_ssl_session_cache_init;
[1128] 
[1129]             continue;
[1130]         }
[1131] 
[1132]         goto invalid;
[1133]     }
[1134] 
[1135]     if (sscf->shm_zone && sscf->builtin_session_cache == NGX_CONF_UNSET) {
[1136]         sscf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
[1137]     }
[1138] 
[1139]     return NGX_CONF_OK;
[1140] 
[1141] invalid:
[1142] 
[1143]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1144]                        "invalid session cache \"%V\"", &value[i]);
[1145] 
[1146]     return NGX_CONF_ERROR;
[1147] }
[1148] 
[1149] 
[1150] static char *
[1151] ngx_http_ssl_ocsp_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1152] {
[1153]     ngx_http_ssl_srv_conf_t *sscf = conf;
[1154] 
[1155]     size_t       len;
[1156]     ngx_int_t    n;
[1157]     ngx_str_t   *value, name, size;
[1158]     ngx_uint_t   j;
[1159] 
[1160]     if (sscf->ocsp_cache_zone != NGX_CONF_UNSET_PTR) {
[1161]         return "is duplicate";
[1162]     }
[1163] 
[1164]     value = cf->args->elts;
[1165] 
[1166]     if (ngx_strcmp(value[1].data, "off") == 0) {
[1167]         sscf->ocsp_cache_zone = NULL;
[1168]         return NGX_CONF_OK;
[1169]     }
[1170] 
[1171]     if (value[1].len <= sizeof("shared:") - 1
[1172]         || ngx_strncmp(value[1].data, "shared:", sizeof("shared:") - 1) != 0)
[1173]     {
[1174]         goto invalid;
[1175]     }
[1176] 
[1177]     len = 0;
[1178] 
[1179]     for (j = sizeof("shared:") - 1; j < value[1].len; j++) {
[1180]         if (value[1].data[j] == ':') {
[1181]             break;
[1182]         }
[1183] 
[1184]         len++;
[1185]     }
[1186] 
[1187]     if (len == 0 || j == value[1].len) {
[1188]         goto invalid;
[1189]     }
[1190] 
[1191]     name.len = len;
[1192]     name.data = value[1].data + sizeof("shared:") - 1;
[1193] 
[1194]     size.len = value[1].len - j - 1;
[1195]     size.data = name.data + len + 1;
[1196] 
[1197]     n = ngx_parse_size(&size);
[1198] 
[1199]     if (n == NGX_ERROR) {
[1200]         goto invalid;
[1201]     }
[1202] 
[1203]     if (n < (ngx_int_t) (8 * ngx_pagesize)) {
[1204]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1205]                            "OCSP cache \"%V\" is too small", &value[1]);
[1206] 
[1207]         return NGX_CONF_ERROR;
[1208]     }
[1209] 
[1210]     sscf->ocsp_cache_zone = ngx_shared_memory_add(cf, &name, n,
[1211]                                                   &ngx_http_ssl_module_ctx);
[1212]     if (sscf->ocsp_cache_zone == NULL) {
[1213]         return NGX_CONF_ERROR;
[1214]     }
[1215] 
[1216]     sscf->ocsp_cache_zone->init = ngx_ssl_ocsp_cache_init;
[1217] 
[1218]     return NGX_CONF_OK;
[1219] 
[1220] invalid:
[1221] 
[1222]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1223]                        "invalid OCSP cache \"%V\"", &value[1]);
[1224] 
[1225]     return NGX_CONF_ERROR;
[1226] }
[1227] 
[1228] 
[1229] static char *
[1230] ngx_http_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[1231] {
[1232] #ifndef SSL_CONF_FLAG_FILE
[1233]     return "is not supported on this platform";
[1234] #else
[1235]     return NGX_CONF_OK;
[1236] #endif
[1237] }
[1238] 
[1239] 
[1240] static ngx_int_t
[1241] ngx_http_ssl_init(ngx_conf_t *cf)
[1242] {
[1243]     ngx_uint_t                   a, p, s;
[1244]     ngx_http_conf_addr_t        *addr;
[1245]     ngx_http_conf_port_t        *port;
[1246]     ngx_http_ssl_srv_conf_t     *sscf;
[1247]     ngx_http_core_loc_conf_t    *clcf;
[1248]     ngx_http_core_srv_conf_t   **cscfp, *cscf;
[1249]     ngx_http_core_main_conf_t   *cmcf;
[1250] 
[1251]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[1252]     cscfp = cmcf->servers.elts;
[1253] 
[1254]     for (s = 0; s < cmcf->servers.nelts; s++) {
[1255] 
[1256]         sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
[1257] 
[1258]         if (sscf->ssl.ctx == NULL) {
[1259]             continue;
[1260]         }
[1261] 
[1262]         clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
[1263] 
[1264]         if (sscf->stapling) {
[1265]             if (ngx_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
[1266]                                           clcf->resolver_timeout)
[1267]                 != NGX_OK)
[1268]             {
[1269]                 return NGX_ERROR;
[1270]             }
[1271]         }
[1272] 
[1273]         if (sscf->ocsp) {
[1274]             if (ngx_ssl_ocsp_resolver(cf, &sscf->ssl, clcf->resolver,
[1275]                                       clcf->resolver_timeout)
[1276]                 != NGX_OK)
[1277]             {
[1278]                 return NGX_ERROR;
[1279]             }
[1280]         }
[1281]     }
[1282] 
[1283]     if (cmcf->ports == NULL) {
[1284]         return NGX_OK;
[1285]     }
[1286] 
[1287]     port = cmcf->ports->elts;
[1288]     for (p = 0; p < cmcf->ports->nelts; p++) {
[1289] 
[1290]         addr = port[p].addrs.elts;
[1291]         for (a = 0; a < port[p].addrs.nelts; a++) {
[1292] 
[1293]             if (!addr[a].opt.ssl) {
[1294]                 continue;
[1295]             }
[1296] 
[1297]             cscf = addr[a].default_server;
[1298]             sscf = cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
[1299] 
[1300]             if (sscf->certificates) {
[1301]                 continue;
[1302]             }
[1303] 
[1304]             if (!sscf->reject_handshake) {
[1305]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1306]                               "no \"ssl_certificate\" is defined for "
[1307]                               "the \"listen ... ssl\" directive in %s:%ui",
[1308]                               cscf->file_name, cscf->line);
[1309]                 return NGX_ERROR;
[1310]             }
[1311] 
[1312]             /*
[1313]              * if no certificates are defined in the default server,
[1314]              * check all non-default server blocks
[1315]              */
[1316] 
[1317]             cscfp = addr[a].servers.elts;
[1318]             for (s = 0; s < addr[a].servers.nelts; s++) {
[1319] 
[1320]                 cscf = cscfp[s];
[1321]                 sscf = cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
[1322] 
[1323]                 if (sscf->certificates || sscf->reject_handshake) {
[1324]                     continue;
[1325]                 }
[1326] 
[1327]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1328]                               "no \"ssl_certificate\" is defined for "
[1329]                               "the \"listen ... ssl\" directive in %s:%ui",
[1330]                               cscf->file_name, cscf->line);
[1331]                 return NGX_ERROR;
[1332]             }
[1333]         }
[1334]     }
[1335] 
[1336]     return NGX_OK;
[1337] }
