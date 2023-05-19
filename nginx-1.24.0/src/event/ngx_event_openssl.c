[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] 
[12] 
[13] #define NGX_SSL_PASSWORD_BUFFER_SIZE  4096
[14] 
[15] 
[16] typedef struct {
[17]     ngx_uint_t  engine;   /* unsigned  engine:1; */
[18] } ngx_openssl_conf_t;
[19] 
[20] 
[21] static X509 *ngx_ssl_load_certificate(ngx_pool_t *pool, char **err,
[22]     ngx_str_t *cert, STACK_OF(X509) **chain);
[23] static EVP_PKEY *ngx_ssl_load_certificate_key(ngx_pool_t *pool, char **err,
[24]     ngx_str_t *key, ngx_array_t *passwords);
[25] static int ngx_ssl_password_callback(char *buf, int size, int rwflag,
[26]     void *userdata);
[27] static int ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
[28] static void ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where,
[29]     int ret);
[30] static void ngx_ssl_passwords_cleanup(void *data);
[31] static int ngx_ssl_new_client_session(ngx_ssl_conn_t *ssl_conn,
[32]     ngx_ssl_session_t *sess);
[33] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[34] static ngx_int_t ngx_ssl_try_early_data(ngx_connection_t *c);
[35] #endif
[36] #if (NGX_DEBUG)
[37] static void ngx_ssl_handshake_log(ngx_connection_t *c);
[38] #endif
[39] static void ngx_ssl_handshake_handler(ngx_event_t *ev);
[40] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[41] static ssize_t ngx_ssl_recv_early(ngx_connection_t *c, u_char *buf,
[42]     size_t size);
[43] #endif
[44] static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n);
[45] static void ngx_ssl_write_handler(ngx_event_t *wev);
[46] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[47] static ssize_t ngx_ssl_write_early(ngx_connection_t *c, u_char *data,
[48]     size_t size);
[49] #endif
[50] static ssize_t ngx_ssl_sendfile(ngx_connection_t *c, ngx_buf_t *file,
[51]     size_t size);
[52] static void ngx_ssl_read_handler(ngx_event_t *rev);
[53] static void ngx_ssl_shutdown_handler(ngx_event_t *ev);
[54] static void ngx_ssl_connection_error(ngx_connection_t *c, int sslerr,
[55]     ngx_err_t err, char *text);
[56] static void ngx_ssl_clear_error(ngx_log_t *log);
[57] 
[58] static ngx_int_t ngx_ssl_session_id_context(ngx_ssl_t *ssl,
[59]     ngx_str_t *sess_ctx, ngx_array_t *certificates);
[60] static int ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn,
[61]     ngx_ssl_session_t *sess);
[62] static ngx_ssl_session_t *ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn,
[63] #if OPENSSL_VERSION_NUMBER >= 0x10100003L
[64]     const
[65] #endif
[66]     u_char *id, int len, int *copy);
[67] static void ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
[68] static void ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
[69]     ngx_slab_pool_t *shpool, ngx_uint_t n);
[70] static void ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
[71]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[72] 
[73] #ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB
[74] static int ngx_ssl_ticket_key_callback(ngx_ssl_conn_t *ssl_conn,
[75]     unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
[76]     HMAC_CTX *hctx, int enc);
[77] static ngx_int_t ngx_ssl_rotate_ticket_keys(SSL_CTX *ssl_ctx, ngx_log_t *log);
[78] static void ngx_ssl_ticket_keys_cleanup(void *data);
[79] #endif
[80] 
[81] #ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
[82] static ngx_int_t ngx_ssl_check_name(ngx_str_t *name, ASN1_STRING *str);
[83] #endif
[84] 
[85] static time_t ngx_ssl_parse_time(
[86] #if OPENSSL_VERSION_NUMBER > 0x10100000L
[87]     const
[88] #endif
[89]     ASN1_TIME *asn1time, ngx_log_t *log);
[90] 
[91] static void *ngx_openssl_create_conf(ngx_cycle_t *cycle);
[92] static char *ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[93] static void ngx_openssl_exit(ngx_cycle_t *cycle);
[94] 
[95] 
[96] static ngx_command_t  ngx_openssl_commands[] = {
[97] 
[98]     { ngx_string("ssl_engine"),
[99]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[100]       ngx_openssl_engine,
[101]       0,
[102]       0,
[103]       NULL },
[104] 
[105]       ngx_null_command
[106] };
[107] 
[108] 
[109] static ngx_core_module_t  ngx_openssl_module_ctx = {
[110]     ngx_string("openssl"),
[111]     ngx_openssl_create_conf,
[112]     NULL
[113] };
[114] 
[115] 
[116] ngx_module_t  ngx_openssl_module = {
[117]     NGX_MODULE_V1,
[118]     &ngx_openssl_module_ctx,               /* module context */
[119]     ngx_openssl_commands,                  /* module directives */
[120]     NGX_CORE_MODULE,                       /* module type */
[121]     NULL,                                  /* init master */
[122]     NULL,                                  /* init module */
[123]     NULL,                                  /* init process */
[124]     NULL,                                  /* init thread */
[125]     NULL,                                  /* exit thread */
[126]     NULL,                                  /* exit process */
[127]     ngx_openssl_exit,                      /* exit master */
[128]     NGX_MODULE_V1_PADDING
[129] };
[130] 
[131] 
[132] int  ngx_ssl_connection_index;
[133] int  ngx_ssl_server_conf_index;
[134] int  ngx_ssl_session_cache_index;
[135] int  ngx_ssl_ticket_keys_index;
[136] int  ngx_ssl_ocsp_index;
[137] int  ngx_ssl_certificate_index;
[138] int  ngx_ssl_next_certificate_index;
[139] int  ngx_ssl_certificate_name_index;
[140] int  ngx_ssl_stapling_index;
[141] 
[142] 
[143] ngx_int_t
[144] ngx_ssl_init(ngx_log_t *log)
[145] {
[146] #if OPENSSL_VERSION_NUMBER >= 0x10100003L
[147] 
[148]     if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
[149]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "OPENSSL_init_ssl() failed");
[150]         return NGX_ERROR;
[151]     }
[152] 
[153]     /*
[154]      * OPENSSL_init_ssl() may leave errors in the error queue
[155]      * while returning success
[156]      */
[157] 
[158]     ERR_clear_error();
[159] 
[160] #else
[161] 
[162]     OPENSSL_config(NULL);
[163] 
[164]     SSL_library_init();
[165]     SSL_load_error_strings();
[166] 
[167]     OpenSSL_add_all_algorithms();
[168] 
[169] #endif
[170] 
[171] #ifndef SSL_OP_NO_COMPRESSION
[172]     {
[173]     /*
[174]      * Disable gzip compression in OpenSSL prior to 1.0.0 version,
[175]      * this saves about 522K per connection.
[176]      */
[177]     int                  n;
[178]     STACK_OF(SSL_COMP)  *ssl_comp_methods;
[179] 
[180]     ssl_comp_methods = SSL_COMP_get_compression_methods();
[181]     n = sk_SSL_COMP_num(ssl_comp_methods);
[182] 
[183]     while (n--) {
[184]         (void) sk_SSL_COMP_pop(ssl_comp_methods);
[185]     }
[186]     }
[187] #endif
[188] 
[189]     ngx_ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
[190] 
[191]     if (ngx_ssl_connection_index == -1) {
[192]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "SSL_get_ex_new_index() failed");
[193]         return NGX_ERROR;
[194]     }
[195] 
[196]     ngx_ssl_server_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
[197]                                                          NULL);
[198]     if (ngx_ssl_server_conf_index == -1) {
[199]         ngx_ssl_error(NGX_LOG_ALERT, log, 0,
[200]                       "SSL_CTX_get_ex_new_index() failed");
[201]         return NGX_ERROR;
[202]     }
[203] 
[204]     ngx_ssl_session_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
[205]                                                            NULL);
[206]     if (ngx_ssl_session_cache_index == -1) {
[207]         ngx_ssl_error(NGX_LOG_ALERT, log, 0,
[208]                       "SSL_CTX_get_ex_new_index() failed");
[209]         return NGX_ERROR;
[210]     }
[211] 
[212]     ngx_ssl_ticket_keys_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
[213]                                                          NULL);
[214]     if (ngx_ssl_ticket_keys_index == -1) {
[215]         ngx_ssl_error(NGX_LOG_ALERT, log, 0,
[216]                       "SSL_CTX_get_ex_new_index() failed");
[217]         return NGX_ERROR;
[218]     }
[219] 
[220]     ngx_ssl_ocsp_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
[221]     if (ngx_ssl_ocsp_index == -1) {
[222]         ngx_ssl_error(NGX_LOG_ALERT, log, 0,
[223]                       "SSL_CTX_get_ex_new_index() failed");
[224]         return NGX_ERROR;
[225]     }
[226] 
[227]     ngx_ssl_certificate_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
[228]                                                          NULL);
[229]     if (ngx_ssl_certificate_index == -1) {
[230]         ngx_ssl_error(NGX_LOG_ALERT, log, 0,
[231]                       "SSL_CTX_get_ex_new_index() failed");
[232]         return NGX_ERROR;
[233]     }
[234] 
[235]     ngx_ssl_next_certificate_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
[236]                                                            NULL);
[237]     if (ngx_ssl_next_certificate_index == -1) {
[238]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
[239]         return NGX_ERROR;
[240]     }
[241] 
[242]     ngx_ssl_certificate_name_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
[243]                                                            NULL);
[244] 
[245]     if (ngx_ssl_certificate_name_index == -1) {
[246]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
[247]         return NGX_ERROR;
[248]     }
[249] 
[250]     ngx_ssl_stapling_index = X509_get_ex_new_index(0, NULL, NULL, NULL, NULL);
[251] 
[252]     if (ngx_ssl_stapling_index == -1) {
[253]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
[254]         return NGX_ERROR;
[255]     }
[256] 
[257]     return NGX_OK;
[258] }
[259] 
[260] 
[261] ngx_int_t
[262] ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
[263] {
[264]     ssl->ctx = SSL_CTX_new(SSLv23_method());
[265] 
[266]     if (ssl->ctx == NULL) {
[267]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "SSL_CTX_new() failed");
[268]         return NGX_ERROR;
[269]     }
[270] 
[271]     if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_server_conf_index, data) == 0) {
[272]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[273]                       "SSL_CTX_set_ex_data() failed");
[274]         return NGX_ERROR;
[275]     }
[276] 
[277]     if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_certificate_index, NULL) == 0) {
[278]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[279]                       "SSL_CTX_set_ex_data() failed");
[280]         return NGX_ERROR;
[281]     }
[282] 
[283]     ssl->buffer_size = NGX_SSL_BUFSIZE;
[284] 
[285]     /* client side options */
[286] 
[287] #ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
[288]     SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
[289] #endif
[290] 
[291] #ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
[292]     SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
[293] #endif
[294] 
[295]     /* server side options */
[296] 
[297] #ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
[298]     SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
[299] #endif
[300] 
[301] #ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
[302]     SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
[303] #endif
[304] 
[305] #ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
[306]     SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
[307] #endif
[308] 
[309] #ifdef SSL_OP_TLS_D5_BUG
[310]     SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
[311] #endif
[312] 
[313] #ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
[314]     SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
[315] #endif
[316] 
[317] #ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
[318]     SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
[319] #endif
[320] 
[321]     SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);
[322] 
[323] #if OPENSSL_VERSION_NUMBER >= 0x009080dfL
[324]     /* only in 0.9.8m+ */
[325]     SSL_CTX_clear_options(ssl->ctx,
[326]                           SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
[327] #endif
[328] 
[329]     if (!(protocols & NGX_SSL_SSLv2)) {
[330]         SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv2);
[331]     }
[332]     if (!(protocols & NGX_SSL_SSLv3)) {
[333]         SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv3);
[334]     }
[335]     if (!(protocols & NGX_SSL_TLSv1)) {
[336]         SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1);
[337]     }
[338] #ifdef SSL_OP_NO_TLSv1_1
[339]     SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
[340]     if (!(protocols & NGX_SSL_TLSv1_1)) {
[341]         SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
[342]     }
[343] #endif
[344] #ifdef SSL_OP_NO_TLSv1_2
[345]     SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
[346]     if (!(protocols & NGX_SSL_TLSv1_2)) {
[347]         SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
[348]     }
[349] #endif
[350] #ifdef SSL_OP_NO_TLSv1_3
[351]     SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
[352]     if (!(protocols & NGX_SSL_TLSv1_3)) {
[353]         SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
[354]     }
[355] #endif
[356] 
[357] #ifdef SSL_CTX_set_min_proto_version
[358]     SSL_CTX_set_min_proto_version(ssl->ctx, 0);
[359]     SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_2_VERSION);
[360] #endif
[361] 
[362] #ifdef TLS1_3_VERSION
[363]     SSL_CTX_set_min_proto_version(ssl->ctx, 0);
[364]     SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_3_VERSION);
[365] #endif
[366] 
[367] #ifdef SSL_OP_NO_COMPRESSION
[368]     SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_COMPRESSION);
[369] #endif
[370] 
[371] #ifdef SSL_OP_NO_ANTI_REPLAY
[372]     SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_ANTI_REPLAY);
[373] #endif
[374] 
[375] #ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
[376]     SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
[377] #endif
[378] 
[379] #ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
[380]     SSL_CTX_set_options(ssl->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
[381] #endif
[382] 
[383] #ifdef SSL_MODE_RELEASE_BUFFERS
[384]     SSL_CTX_set_mode(ssl->ctx, SSL_MODE_RELEASE_BUFFERS);
[385] #endif
[386] 
[387] #ifdef SSL_MODE_NO_AUTO_CHAIN
[388]     SSL_CTX_set_mode(ssl->ctx, SSL_MODE_NO_AUTO_CHAIN);
[389] #endif
[390] 
[391]     SSL_CTX_set_read_ahead(ssl->ctx, 1);
[392] 
[393]     SSL_CTX_set_info_callback(ssl->ctx, ngx_ssl_info_callback);
[394] 
[395]     return NGX_OK;
[396] }
[397] 
[398] 
[399] ngx_int_t
[400] ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *certs,
[401]     ngx_array_t *keys, ngx_array_t *passwords)
[402] {
[403]     ngx_str_t   *cert, *key;
[404]     ngx_uint_t   i;
[405] 
[406]     cert = certs->elts;
[407]     key = keys->elts;
[408] 
[409]     for (i = 0; i < certs->nelts; i++) {
[410] 
[411]         if (ngx_ssl_certificate(cf, ssl, &cert[i], &key[i], passwords)
[412]             != NGX_OK)
[413]         {
[414]             return NGX_ERROR;
[415]         }
[416]     }
[417] 
[418]     return NGX_OK;
[419] }
[420] 
[421] 
[422] ngx_int_t
[423] ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
[424]     ngx_str_t *key, ngx_array_t *passwords)
[425] {
[426]     char            *err;
[427]     X509            *x509;
[428]     EVP_PKEY        *pkey;
[429]     STACK_OF(X509)  *chain;
[430] 
[431]     x509 = ngx_ssl_load_certificate(cf->pool, &err, cert, &chain);
[432]     if (x509 == NULL) {
[433]         if (err != NULL) {
[434]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[435]                           "cannot load certificate \"%s\": %s",
[436]                           cert->data, err);
[437]         }
[438] 
[439]         return NGX_ERROR;
[440]     }
[441] 
[442]     if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {
[443]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[444]                       "SSL_CTX_use_certificate(\"%s\") failed", cert->data);
[445]         X509_free(x509);
[446]         sk_X509_pop_free(chain, X509_free);
[447]         return NGX_ERROR;
[448]     }
[449] 
[450]     if (X509_set_ex_data(x509, ngx_ssl_certificate_name_index, cert->data)
[451]         == 0)
[452]     {
[453]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
[454]         X509_free(x509);
[455]         sk_X509_pop_free(chain, X509_free);
[456]         return NGX_ERROR;
[457]     }
[458] 
[459]     if (X509_set_ex_data(x509, ngx_ssl_next_certificate_index,
[460]                       SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index))
[461]         == 0)
[462]     {
[463]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
[464]         X509_free(x509);
[465]         sk_X509_pop_free(chain, X509_free);
[466]         return NGX_ERROR;
[467]     }
[468] 
[469]     if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_certificate_index, x509) == 0) {
[470]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[471]                       "SSL_CTX_set_ex_data() failed");
[472]         X509_free(x509);
[473]         sk_X509_pop_free(chain, X509_free);
[474]         return NGX_ERROR;
[475]     }
[476] 
[477]     /*
[478]      * Note that x509 is not freed here, but will be instead freed in
[479]      * ngx_ssl_cleanup_ctx().  This is because we need to preserve all
[480]      * certificates to be able to iterate all of them through exdata
[481]      * (ngx_ssl_certificate_index, ngx_ssl_next_certificate_index),
[482]      * while OpenSSL can free a certificate if it is replaced with another
[483]      * certificate of the same type.
[484]      */
[485] 
[486] #ifdef SSL_CTX_set0_chain
[487] 
[488]     if (SSL_CTX_set0_chain(ssl->ctx, chain) == 0) {
[489]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[490]                       "SSL_CTX_set0_chain(\"%s\") failed", cert->data);
[491]         sk_X509_pop_free(chain, X509_free);
[492]         return NGX_ERROR;
[493]     }
[494] 
[495] #else
[496]     {
[497]     int  n;
[498] 
[499]     /* SSL_CTX_set0_chain() is only available in OpenSSL 1.0.2+ */
[500] 
[501]     n = sk_X509_num(chain);
[502] 
[503]     while (n--) {
[504]         x509 = sk_X509_shift(chain);
[505] 
[506]         if (SSL_CTX_add_extra_chain_cert(ssl->ctx, x509) == 0) {
[507]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[508]                           "SSL_CTX_add_extra_chain_cert(\"%s\") failed",
[509]                           cert->data);
[510]             sk_X509_pop_free(chain, X509_free);
[511]             return NGX_ERROR;
[512]         }
[513]     }
[514] 
[515]     sk_X509_free(chain);
[516]     }
[517] #endif
[518] 
[519]     pkey = ngx_ssl_load_certificate_key(cf->pool, &err, key, passwords);
[520]     if (pkey == NULL) {
[521]         if (err != NULL) {
[522]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[523]                           "cannot load certificate key \"%s\": %s",
[524]                           key->data, err);
[525]         }
[526] 
[527]         return NGX_ERROR;
[528]     }
[529] 
[530]     if (SSL_CTX_use_PrivateKey(ssl->ctx, pkey) == 0) {
[531]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[532]                       "SSL_CTX_use_PrivateKey(\"%s\") failed", key->data);
[533]         EVP_PKEY_free(pkey);
[534]         return NGX_ERROR;
[535]     }
[536] 
[537]     EVP_PKEY_free(pkey);
[538] 
[539]     return NGX_OK;
[540] }
[541] 
[542] 
[543] ngx_int_t
[544] ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
[545]     ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords)
[546] {
[547]     char            *err;
[548]     X509            *x509;
[549]     EVP_PKEY        *pkey;
[550]     STACK_OF(X509)  *chain;
[551] 
[552]     x509 = ngx_ssl_load_certificate(pool, &err, cert, &chain);
[553]     if (x509 == NULL) {
[554]         if (err != NULL) {
[555]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[556]                           "cannot load certificate \"%s\": %s",
[557]                           cert->data, err);
[558]         }
[559] 
[560]         return NGX_ERROR;
[561]     }
[562] 
[563]     if (SSL_use_certificate(c->ssl->connection, x509) == 0) {
[564]         ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[565]                       "SSL_use_certificate(\"%s\") failed", cert->data);
[566]         X509_free(x509);
[567]         sk_X509_pop_free(chain, X509_free);
[568]         return NGX_ERROR;
[569]     }
[570] 
[571]     X509_free(x509);
[572] 
[573] #ifdef SSL_set0_chain
[574] 
[575]     /*
[576]      * SSL_set0_chain() is only available in OpenSSL 1.0.2+,
[577]      * but this function is only called via certificate callback,
[578]      * which is only available in OpenSSL 1.0.2+ as well
[579]      */
[580] 
[581]     if (SSL_set0_chain(c->ssl->connection, chain) == 0) {
[582]         ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[583]                       "SSL_set0_chain(\"%s\") failed", cert->data);
[584]         sk_X509_pop_free(chain, X509_free);
[585]         return NGX_ERROR;
[586]     }
[587] 
[588] #endif
[589] 
[590]     pkey = ngx_ssl_load_certificate_key(pool, &err, key, passwords);
[591]     if (pkey == NULL) {
[592]         if (err != NULL) {
[593]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[594]                           "cannot load certificate key \"%s\": %s",
[595]                           key->data, err);
[596]         }
[597] 
[598]         return NGX_ERROR;
[599]     }
[600] 
[601]     if (SSL_use_PrivateKey(c->ssl->connection, pkey) == 0) {
[602]         ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[603]                       "SSL_use_PrivateKey(\"%s\") failed", key->data);
[604]         EVP_PKEY_free(pkey);
[605]         return NGX_ERROR;
[606]     }
[607] 
[608]     EVP_PKEY_free(pkey);
[609] 
[610]     return NGX_OK;
[611] }
[612] 
[613] 
[614] static X509 *
[615] ngx_ssl_load_certificate(ngx_pool_t *pool, char **err, ngx_str_t *cert,
[616]     STACK_OF(X509) **chain)
[617] {
[618]     BIO     *bio;
[619]     X509    *x509, *temp;
[620]     u_long   n;
[621] 
[622]     if (ngx_strncmp(cert->data, "data:", sizeof("data:") - 1) == 0) {
[623] 
[624]         bio = BIO_new_mem_buf(cert->data + sizeof("data:") - 1,
[625]                               cert->len - (sizeof("data:") - 1));
[626]         if (bio == NULL) {
[627]             *err = "BIO_new_mem_buf() failed";
[628]             return NULL;
[629]         }
[630] 
[631]     } else {
[632] 
[633]         if (ngx_get_full_name(pool, (ngx_str_t *) &ngx_cycle->conf_prefix, cert)
[634]             != NGX_OK)
[635]         {
[636]             *err = NULL;
[637]             return NULL;
[638]         }
[639] 
[640]         bio = BIO_new_file((char *) cert->data, "r");
[641]         if (bio == NULL) {
[642]             *err = "BIO_new_file() failed";
[643]             return NULL;
[644]         }
[645]     }
[646] 
[647]     /* certificate itself */
[648] 
[649]     x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
[650]     if (x509 == NULL) {
[651]         *err = "PEM_read_bio_X509_AUX() failed";
[652]         BIO_free(bio);
[653]         return NULL;
[654]     }
[655] 
[656]     /* rest of the chain */
[657] 
[658]     *chain = sk_X509_new_null();
[659]     if (*chain == NULL) {
[660]         *err = "sk_X509_new_null() failed";
[661]         BIO_free(bio);
[662]         X509_free(x509);
[663]         return NULL;
[664]     }
[665] 
[666]     for ( ;; ) {
[667] 
[668]         temp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
[669]         if (temp == NULL) {
[670]             n = ERR_peek_last_error();
[671] 
[672]             if (ERR_GET_LIB(n) == ERR_LIB_PEM
[673]                 && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
[674]             {
[675]                 /* end of file */
[676]                 ERR_clear_error();
[677]                 break;
[678]             }
[679] 
[680]             /* some real error */
[681] 
[682]             *err = "PEM_read_bio_X509() failed";
[683]             BIO_free(bio);
[684]             X509_free(x509);
[685]             sk_X509_pop_free(*chain, X509_free);
[686]             return NULL;
[687]         }
[688] 
[689]         if (sk_X509_push(*chain, temp) == 0) {
[690]             *err = "sk_X509_push() failed";
[691]             BIO_free(bio);
[692]             X509_free(x509);
[693]             sk_X509_pop_free(*chain, X509_free);
[694]             return NULL;
[695]         }
[696]     }
[697] 
[698]     BIO_free(bio);
[699] 
[700]     return x509;
[701] }
[702] 
[703] 
[704] static EVP_PKEY *
[705] ngx_ssl_load_certificate_key(ngx_pool_t *pool, char **err,
[706]     ngx_str_t *key, ngx_array_t *passwords)
[707] {
[708]     BIO              *bio;
[709]     EVP_PKEY         *pkey;
[710]     ngx_str_t        *pwd;
[711]     ngx_uint_t        tries;
[712]     pem_password_cb  *cb;
[713] 
[714]     if (ngx_strncmp(key->data, "engine:", sizeof("engine:") - 1) == 0) {
[715] 
[716] #ifndef OPENSSL_NO_ENGINE
[717] 
[718]         u_char  *p, *last;
[719]         ENGINE  *engine;
[720] 
[721]         p = key->data + sizeof("engine:") - 1;
[722]         last = (u_char *) ngx_strchr(p, ':');
[723] 
[724]         if (last == NULL) {
[725]             *err = "invalid syntax";
[726]             return NULL;
[727]         }
[728] 
[729]         *last = '\0';
[730] 
[731]         engine = ENGINE_by_id((char *) p);
[732] 
[733]         if (engine == NULL) {
[734]             *err = "ENGINE_by_id() failed";
[735]             return NULL;
[736]         }
[737] 
[738]         *last++ = ':';
[739] 
[740]         pkey = ENGINE_load_private_key(engine, (char *) last, 0, 0);
[741] 
[742]         if (pkey == NULL) {
[743]             *err = "ENGINE_load_private_key() failed";
[744]             ENGINE_free(engine);
[745]             return NULL;
[746]         }
[747] 
[748]         ENGINE_free(engine);
[749] 
[750]         return pkey;
[751] 
[752] #else
[753] 
[754]         *err = "loading \"engine:...\" certificate keys is not supported";
[755]         return NULL;
[756] 
[757] #endif
[758]     }
[759] 
[760]     if (ngx_strncmp(key->data, "data:", sizeof("data:") - 1) == 0) {
[761] 
[762]         bio = BIO_new_mem_buf(key->data + sizeof("data:") - 1,
[763]                               key->len - (sizeof("data:") - 1));
[764]         if (bio == NULL) {
[765]             *err = "BIO_new_mem_buf() failed";
[766]             return NULL;
[767]         }
[768] 
[769]     } else {
[770] 
[771]         if (ngx_get_full_name(pool, (ngx_str_t *) &ngx_cycle->conf_prefix, key)
[772]             != NGX_OK)
[773]         {
[774]             *err = NULL;
[775]             return NULL;
[776]         }
[777] 
[778]         bio = BIO_new_file((char *) key->data, "r");
[779]         if (bio == NULL) {
[780]             *err = "BIO_new_file() failed";
[781]             return NULL;
[782]         }
[783]     }
[784] 
[785]     if (passwords) {
[786]         tries = passwords->nelts;
[787]         pwd = passwords->elts;
[788]         cb = ngx_ssl_password_callback;
[789] 
[790]     } else {
[791]         tries = 1;
[792]         pwd = NULL;
[793]         cb = NULL;
[794]     }
[795] 
[796]     for ( ;; ) {
[797] 
[798]         pkey = PEM_read_bio_PrivateKey(bio, NULL, cb, pwd);
[799]         if (pkey != NULL) {
[800]             break;
[801]         }
[802] 
[803]         if (tries-- > 1) {
[804]             ERR_clear_error();
[805]             (void) BIO_reset(bio);
[806]             pwd++;
[807]             continue;
[808]         }
[809] 
[810]         *err = "PEM_read_bio_PrivateKey() failed";
[811]         BIO_free(bio);
[812]         return NULL;
[813]     }
[814] 
[815]     BIO_free(bio);
[816] 
[817]     return pkey;
[818] }
[819] 
[820] 
[821] static int
[822] ngx_ssl_password_callback(char *buf, int size, int rwflag, void *userdata)
[823] {
[824]     ngx_str_t *pwd = userdata;
[825] 
[826]     if (rwflag) {
[827]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
[828]                       "ngx_ssl_password_callback() is called for encryption");
[829]         return 0;
[830]     }
[831] 
[832]     if (pwd == NULL) {
[833]         return 0;
[834]     }
[835] 
[836]     if (pwd->len > (size_t) size) {
[837]         ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
[838]                       "password is truncated to %d bytes", size);
[839]     } else {
[840]         size = pwd->len;
[841]     }
[842] 
[843]     ngx_memcpy(buf, pwd->data, size);
[844] 
[845]     return size;
[846] }
[847] 
[848] 
[849] ngx_int_t
[850] ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
[851]     ngx_uint_t prefer_server_ciphers)
[852] {
[853]     if (SSL_CTX_set_cipher_list(ssl->ctx, (char *) ciphers->data) == 0) {
[854]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[855]                       "SSL_CTX_set_cipher_list(\"%V\") failed",
[856]                       ciphers);
[857]         return NGX_ERROR;
[858]     }
[859] 
[860]     if (prefer_server_ciphers) {
[861]         SSL_CTX_set_options(ssl->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
[862]     }
[863] 
[864]     return NGX_OK;
[865] }
[866] 
[867] 
[868] ngx_int_t
[869] ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
[870]     ngx_int_t depth)
[871] {
[872]     STACK_OF(X509_NAME)  *list;
[873] 
[874]     SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
[875] 
[876]     SSL_CTX_set_verify_depth(ssl->ctx, depth);
[877] 
[878]     if (cert->len == 0) {
[879]         return NGX_OK;
[880]     }
[881] 
[882]     if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
[883]         return NGX_ERROR;
[884]     }
[885] 
[886]     if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
[887]         == 0)
[888]     {
[889]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[890]                       "SSL_CTX_load_verify_locations(\"%s\") failed",
[891]                       cert->data);
[892]         return NGX_ERROR;
[893]     }
[894] 
[895]     /*
[896]      * SSL_CTX_load_verify_locations() may leave errors in the error queue
[897]      * while returning success
[898]      */
[899] 
[900]     ERR_clear_error();
[901] 
[902]     list = SSL_load_client_CA_file((char *) cert->data);
[903] 
[904]     if (list == NULL) {
[905]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[906]                       "SSL_load_client_CA_file(\"%s\") failed", cert->data);
[907]         return NGX_ERROR;
[908]     }
[909] 
[910]     SSL_CTX_set_client_CA_list(ssl->ctx, list);
[911] 
[912]     return NGX_OK;
[913] }
[914] 
[915] 
[916] ngx_int_t
[917] ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
[918]     ngx_int_t depth)
[919] {
[920]     SSL_CTX_set_verify(ssl->ctx, SSL_CTX_get_verify_mode(ssl->ctx),
[921]                        ngx_ssl_verify_callback);
[922] 
[923]     SSL_CTX_set_verify_depth(ssl->ctx, depth);
[924] 
[925]     if (cert->len == 0) {
[926]         return NGX_OK;
[927]     }
[928] 
[929]     if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
[930]         return NGX_ERROR;
[931]     }
[932] 
[933]     if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
[934]         == 0)
[935]     {
[936]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[937]                       "SSL_CTX_load_verify_locations(\"%s\") failed",
[938]                       cert->data);
[939]         return NGX_ERROR;
[940]     }
[941] 
[942]     /*
[943]      * SSL_CTX_load_verify_locations() may leave errors in the error queue
[944]      * while returning success
[945]      */
[946] 
[947]     ERR_clear_error();
[948] 
[949]     return NGX_OK;
[950] }
[951] 
[952] 
[953] ngx_int_t
[954] ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
[955] {
[956]     X509_STORE   *store;
[957]     X509_LOOKUP  *lookup;
[958] 
[959]     if (crl->len == 0) {
[960]         return NGX_OK;
[961]     }
[962] 
[963]     if (ngx_conf_full_name(cf->cycle, crl, 1) != NGX_OK) {
[964]         return NGX_ERROR;
[965]     }
[966] 
[967]     store = SSL_CTX_get_cert_store(ssl->ctx);
[968] 
[969]     if (store == NULL) {
[970]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[971]                       "SSL_CTX_get_cert_store() failed");
[972]         return NGX_ERROR;
[973]     }
[974] 
[975]     lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
[976] 
[977]     if (lookup == NULL) {
[978]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[979]                       "X509_STORE_add_lookup() failed");
[980]         return NGX_ERROR;
[981]     }
[982] 
[983]     if (X509_LOOKUP_load_file(lookup, (char *) crl->data, X509_FILETYPE_PEM)
[984]         == 0)
[985]     {
[986]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[987]                       "X509_LOOKUP_load_file(\"%s\") failed", crl->data);
[988]         return NGX_ERROR;
[989]     }
[990] 
[991]     X509_STORE_set_flags(store,
[992]                          X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
[993] 
[994]     return NGX_OK;
[995] }
[996] 
[997] 
[998] static int
[999] ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
[1000] {
[1001] #if (NGX_DEBUG)
[1002]     char              *subject, *issuer;
[1003]     int                err, depth;
[1004]     X509              *cert;
[1005]     X509_NAME         *sname, *iname;
[1006]     ngx_connection_t  *c;
[1007]     ngx_ssl_conn_t    *ssl_conn;
[1008] 
[1009]     ssl_conn = X509_STORE_CTX_get_ex_data(x509_store,
[1010]                                           SSL_get_ex_data_X509_STORE_CTX_idx());
[1011] 
[1012]     c = ngx_ssl_get_connection(ssl_conn);
[1013] 
[1014]     if (!(c->log->log_level & NGX_LOG_DEBUG_EVENT)) {
[1015]         return 1;
[1016]     }
[1017] 
[1018]     cert = X509_STORE_CTX_get_current_cert(x509_store);
[1019]     err = X509_STORE_CTX_get_error(x509_store);
[1020]     depth = X509_STORE_CTX_get_error_depth(x509_store);
[1021] 
[1022]     sname = X509_get_subject_name(cert);
[1023] 
[1024]     if (sname) {
[1025]         subject = X509_NAME_oneline(sname, NULL, 0);
[1026]         if (subject == NULL) {
[1027]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
[1028]                           "X509_NAME_oneline() failed");
[1029]         }
[1030] 
[1031]     } else {
[1032]         subject = NULL;
[1033]     }
[1034] 
[1035]     iname = X509_get_issuer_name(cert);
[1036] 
[1037]     if (iname) {
[1038]         issuer = X509_NAME_oneline(iname, NULL, 0);
[1039]         if (issuer == NULL) {
[1040]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
[1041]                           "X509_NAME_oneline() failed");
[1042]         }
[1043] 
[1044]     } else {
[1045]         issuer = NULL;
[1046]     }
[1047] 
[1048]     ngx_log_debug5(NGX_LOG_DEBUG_EVENT, c->log, 0,
[1049]                    "verify:%d, error:%d, depth:%d, "
[1050]                    "subject:\"%s\", issuer:\"%s\"",
[1051]                    ok, err, depth,
[1052]                    subject ? subject : "(none)",
[1053]                    issuer ? issuer : "(none)");
[1054] 
[1055]     if (subject) {
[1056]         OPENSSL_free(subject);
[1057]     }
[1058] 
[1059]     if (issuer) {
[1060]         OPENSSL_free(issuer);
[1061]     }
[1062] #endif
[1063] 
[1064]     return 1;
[1065] }
[1066] 
[1067] 
[1068] static void
[1069] ngx_ssl_info_callback(const ngx_ssl_conn_t *ssl_conn, int where, int ret)
[1070] {
[1071]     BIO               *rbio, *wbio;
[1072]     ngx_connection_t  *c;
[1073] 
[1074] #ifndef SSL_OP_NO_RENEGOTIATION
[1075] 
[1076]     if ((where & SSL_CB_HANDSHAKE_START)
[1077]         && SSL_is_server((ngx_ssl_conn_t *) ssl_conn))
[1078]     {
[1079]         c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
[1080] 
[1081]         if (c->ssl->handshaked) {
[1082]             c->ssl->renegotiation = 1;
[1083]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
[1084]         }
[1085]     }
[1086] 
[1087] #endif
[1088] 
[1089] #ifdef TLS1_3_VERSION
[1090] 
[1091]     if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP
[1092]         && SSL_version(ssl_conn) == TLS1_3_VERSION)
[1093]     {
[1094]         time_t        now, time, timeout, conf_timeout;
[1095]         SSL_SESSION  *sess;
[1096] 
[1097]         /*
[1098]          * OpenSSL with TLSv1.3 updates the session creation time on
[1099]          * session resumption and keeps the session timeout unmodified,
[1100]          * making it possible to maintain the session forever, bypassing
[1101]          * client certificate expiration and revocation.  To make sure
[1102]          * session timeouts are actually used, we now update the session
[1103]          * creation time and reduce the session timeout accordingly.
[1104]          *
[1105]          * BoringSSL with TLSv1.3 ignores configured session timeouts
[1106]          * and uses a hardcoded timeout instead, 7 days.  So we update
[1107]          * session timeout to the configured value as soon as a session
[1108]          * is created.
[1109]          */
[1110] 
[1111]         c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
[1112]         sess = SSL_get0_session(ssl_conn);
[1113] 
[1114]         if (!c->ssl->session_timeout_set && sess) {
[1115]             c->ssl->session_timeout_set = 1;
[1116] 
[1117]             now = ngx_time();
[1118]             time = SSL_SESSION_get_time(sess);
[1119]             timeout = SSL_SESSION_get_timeout(sess);
[1120]             conf_timeout = SSL_CTX_get_timeout(c->ssl->session_ctx);
[1121] 
[1122]             timeout = ngx_min(timeout, conf_timeout);
[1123] 
[1124]             if (now - time >= timeout) {
[1125]                 SSL_SESSION_set1_id_context(sess, (unsigned char *) "", 0);
[1126] 
[1127]             } else {
[1128]                 SSL_SESSION_set_time(sess, now);
[1129]                 SSL_SESSION_set_timeout(sess, timeout - (now - time));
[1130]             }
[1131]         }
[1132]     }
[1133] 
[1134] #endif
[1135] 
[1136]     if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
[1137]         c = ngx_ssl_get_connection((ngx_ssl_conn_t *) ssl_conn);
[1138] 
[1139]         if (!c->ssl->handshake_buffer_set) {
[1140]             /*
[1141]              * By default OpenSSL uses 4k buffer during a handshake,
[1142]              * which is too low for long certificate chains and might
[1143]              * result in extra round-trips.
[1144]              *
[1145]              * To adjust a buffer size we detect that buffering was added
[1146]              * to write side of the connection by comparing rbio and wbio.
[1147]              * If they are different, we assume that it's due to buffering
[1148]              * added to wbio, and set buffer size.
[1149]              */
[1150] 
[1151]             rbio = SSL_get_rbio(ssl_conn);
[1152]             wbio = SSL_get_wbio(ssl_conn);
[1153] 
[1154]             if (rbio != wbio) {
[1155]                 (void) BIO_set_write_buffer_size(wbio, NGX_SSL_BUFSIZE);
[1156]                 c->ssl->handshake_buffer_set = 1;
[1157]             }
[1158]         }
[1159]     }
[1160] }
[1161] 
[1162] 
[1163] ngx_array_t *
[1164] ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file)
[1165] {
[1166]     u_char              *p, *last, *end;
[1167]     size_t               len;
[1168]     ssize_t              n;
[1169]     ngx_fd_t             fd;
[1170]     ngx_str_t           *pwd;
[1171]     ngx_array_t         *passwords;
[1172]     ngx_pool_cleanup_t  *cln;
[1173]     u_char               buf[NGX_SSL_PASSWORD_BUFFER_SIZE];
[1174] 
[1175]     if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
[1176]         return NULL;
[1177]     }
[1178] 
[1179]     passwords = ngx_array_create(cf->temp_pool, 4, sizeof(ngx_str_t));
[1180]     if (passwords == NULL) {
[1181]         return NULL;
[1182]     }
[1183] 
[1184]     cln = ngx_pool_cleanup_add(cf->temp_pool, 0);
[1185]     if (cln == NULL) {
[1186]         return NULL;
[1187]     }
[1188] 
[1189]     cln->handler = ngx_ssl_passwords_cleanup;
[1190]     cln->data = passwords;
[1191] 
[1192]     fd = ngx_open_file(file->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
[1193] 
[1194]     if (fd == NGX_INVALID_FILE) {
[1195]         ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[1196]                            ngx_open_file_n " \"%s\" failed", file->data);
[1197]         return NULL;
[1198]     }
[1199] 
[1200]     len = 0;
[1201]     last = buf;
[1202] 
[1203]     do {
[1204]         n = ngx_read_fd(fd, last, NGX_SSL_PASSWORD_BUFFER_SIZE - len);
[1205] 
[1206]         if (n == -1) {
[1207]             ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[1208]                                ngx_read_fd_n " \"%s\" failed", file->data);
[1209]             passwords = NULL;
[1210]             goto cleanup;
[1211]         }
[1212] 
[1213]         end = last + n;
[1214] 
[1215]         if (len && n == 0) {
[1216]             *end++ = LF;
[1217]         }
[1218] 
[1219]         p = buf;
[1220] 
[1221]         for ( ;; ) {
[1222]             last = ngx_strlchr(last, end, LF);
[1223] 
[1224]             if (last == NULL) {
[1225]                 break;
[1226]             }
[1227] 
[1228]             len = last++ - p;
[1229] 
[1230]             if (len && p[len - 1] == CR) {
[1231]                 len--;
[1232]             }
[1233] 
[1234]             if (len) {
[1235]                 pwd = ngx_array_push(passwords);
[1236]                 if (pwd == NULL) {
[1237]                     passwords = NULL;
[1238]                     goto cleanup;
[1239]                 }
[1240] 
[1241]                 pwd->len = len;
[1242]                 pwd->data = ngx_pnalloc(cf->temp_pool, len);
[1243] 
[1244]                 if (pwd->data == NULL) {
[1245]                     passwords->nelts--;
[1246]                     passwords = NULL;
[1247]                     goto cleanup;
[1248]                 }
[1249] 
[1250]                 ngx_memcpy(pwd->data, p, len);
[1251]             }
[1252] 
[1253]             p = last;
[1254]         }
[1255] 
[1256]         len = end - p;
[1257] 
[1258]         if (len == NGX_SSL_PASSWORD_BUFFER_SIZE) {
[1259]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1260]                                "too long line in \"%s\"", file->data);
[1261]             passwords = NULL;
[1262]             goto cleanup;
[1263]         }
[1264] 
[1265]         ngx_memmove(buf, p, len);
[1266]         last = buf + len;
[1267] 
[1268]     } while (n != 0);
[1269] 
[1270]     if (passwords->nelts == 0) {
[1271]         pwd = ngx_array_push(passwords);
[1272]         if (pwd == NULL) {
[1273]             passwords = NULL;
[1274]             goto cleanup;
[1275]         }
[1276] 
[1277]         ngx_memzero(pwd, sizeof(ngx_str_t));
[1278]     }
[1279] 
[1280] cleanup:
[1281] 
[1282]     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[1283]         ngx_conf_log_error(NGX_LOG_ALERT, cf, ngx_errno,
[1284]                            ngx_close_file_n " \"%s\" failed", file->data);
[1285]     }
[1286] 
[1287]     ngx_explicit_memzero(buf, NGX_SSL_PASSWORD_BUFFER_SIZE);
[1288] 
[1289]     return passwords;
[1290] }
[1291] 
[1292] 
[1293] ngx_array_t *
[1294] ngx_ssl_preserve_passwords(ngx_conf_t *cf, ngx_array_t *passwords)
[1295] {
[1296]     ngx_str_t           *opwd, *pwd;
[1297]     ngx_uint_t           i;
[1298]     ngx_array_t         *pwds;
[1299]     ngx_pool_cleanup_t  *cln;
[1300]     static ngx_array_t   empty_passwords;
[1301] 
[1302]     if (passwords == NULL) {
[1303] 
[1304]         /*
[1305]          * If there are no passwords, an empty array is used
[1306]          * to make sure OpenSSL's default password callback
[1307]          * won't block on reading from stdin.
[1308]          */
[1309] 
[1310]         return &empty_passwords;
[1311]     }
[1312] 
[1313]     /*
[1314]      * Passwords are normally allocated from the temporary pool
[1315]      * and cleared after parsing configuration.  To be used at
[1316]      * runtime they have to be copied to the configuration pool.
[1317]      */
[1318] 
[1319]     pwds = ngx_array_create(cf->pool, passwords->nelts, sizeof(ngx_str_t));
[1320]     if (pwds == NULL) {
[1321]         return NULL;
[1322]     }
[1323] 
[1324]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[1325]     if (cln == NULL) {
[1326]         return NULL;
[1327]     }
[1328] 
[1329]     cln->handler = ngx_ssl_passwords_cleanup;
[1330]     cln->data = pwds;
[1331] 
[1332]     opwd = passwords->elts;
[1333] 
[1334]     for (i = 0; i < passwords->nelts; i++) {
[1335] 
[1336]         pwd = ngx_array_push(pwds);
[1337]         if (pwd == NULL) {
[1338]             return NULL;
[1339]         }
[1340] 
[1341]         pwd->len = opwd[i].len;
[1342]         pwd->data = ngx_pnalloc(cf->pool, pwd->len);
[1343] 
[1344]         if (pwd->data == NULL) {
[1345]             pwds->nelts--;
[1346]             return NULL;
[1347]         }
[1348] 
[1349]         ngx_memcpy(pwd->data, opwd[i].data, opwd[i].len);
[1350]     }
[1351] 
[1352]     return pwds;
[1353] }
[1354] 
[1355] 
[1356] static void
[1357] ngx_ssl_passwords_cleanup(void *data)
[1358] {
[1359]     ngx_array_t *passwords = data;
[1360] 
[1361]     ngx_str_t   *pwd;
[1362]     ngx_uint_t   i;
[1363] 
[1364]     pwd = passwords->elts;
[1365] 
[1366]     for (i = 0; i < passwords->nelts; i++) {
[1367]         ngx_explicit_memzero(pwd[i].data, pwd[i].len);
[1368]     }
[1369] }
[1370] 
[1371] 
[1372] ngx_int_t
[1373] ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
[1374] {
[1375]     BIO  *bio;
[1376] 
[1377]     if (file->len == 0) {
[1378]         return NGX_OK;
[1379]     }
[1380] 
[1381]     if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
[1382]         return NGX_ERROR;
[1383]     }
[1384] 
[1385]     bio = BIO_new_file((char *) file->data, "r");
[1386]     if (bio == NULL) {
[1387]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1388]                       "BIO_new_file(\"%s\") failed", file->data);
[1389]         return NGX_ERROR;
[1390]     }
[1391] 
[1392] #ifdef SSL_CTX_set_tmp_dh
[1393]     {
[1394]     DH  *dh;
[1395] 
[1396]     dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
[1397]     if (dh == NULL) {
[1398]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1399]                       "PEM_read_bio_DHparams(\"%s\") failed", file->data);
[1400]         BIO_free(bio);
[1401]         return NGX_ERROR;
[1402]     }
[1403] 
[1404]     if (SSL_CTX_set_tmp_dh(ssl->ctx, dh) != 1) {
[1405]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1406]                       "SSL_CTX_set_tmp_dh(\"%s\") failed", file->data);
[1407]         DH_free(dh);
[1408]         BIO_free(bio);
[1409]         return NGX_ERROR;
[1410]     }
[1411] 
[1412]     DH_free(dh);
[1413]     }
[1414] #else
[1415]     {
[1416]     EVP_PKEY  *dh;
[1417] 
[1418]     /*
[1419]      * PEM_read_bio_DHparams() and SSL_CTX_set_tmp_dh()
[1420]      * are deprecated in OpenSSL 3.0
[1421]      */
[1422] 
[1423]     dh = PEM_read_bio_Parameters(bio, NULL);
[1424]     if (dh == NULL) {
[1425]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1426]                       "PEM_read_bio_Parameters(\"%s\") failed", file->data);
[1427]         BIO_free(bio);
[1428]         return NGX_ERROR;
[1429]     }
[1430] 
[1431]     if (SSL_CTX_set0_tmp_dh_pkey(ssl->ctx, dh) != 1) {
[1432]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1433]                       "SSL_CTX_set0_tmp_dh_pkey(\%s\") failed", file->data);
[1434] #if (OPENSSL_VERSION_NUMBER >= 0x3000001fL)
[1435]         EVP_PKEY_free(dh);
[1436] #endif
[1437]         BIO_free(bio);
[1438]         return NGX_ERROR;
[1439]     }
[1440]     }
[1441] #endif
[1442] 
[1443]     BIO_free(bio);
[1444] 
[1445]     return NGX_OK;
[1446] }
[1447] 
[1448] 
[1449] ngx_int_t
[1450] ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
[1451] {
[1452] #ifndef OPENSSL_NO_ECDH
[1453] 
[1454]     /*
[1455]      * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
[1456]      * from RFC 4492 section 5.1.1, or explicitly described curves over
[1457]      * binary fields.  OpenSSL only supports the "named curves", which provide
[1458]      * maximum interoperability.
[1459]      */
[1460] 
[1461] #if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)
[1462] 
[1463]     /*
[1464]      * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
[1465]      * curve previously supported.  By default an internal list is used,
[1466]      * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
[1467]      * and X25519 in OpenSSL 1.1.0+.
[1468]      *
[1469]      * By default a curve preferred by the client will be used for
[1470]      * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
[1471]      * be used to prefer server curves instead, similar to what it
[1472]      * does for ciphers.
[1473]      */
[1474] 
[1475]     SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);
[1476] 
[1477] #ifdef SSL_CTRL_SET_ECDH_AUTO
[1478]     /* not needed in OpenSSL 1.1.0+ */
[1479]     (void) SSL_CTX_set_ecdh_auto(ssl->ctx, 1);
[1480] #endif
[1481] 
[1482]     if (ngx_strcmp(name->data, "auto") == 0) {
[1483]         return NGX_OK;
[1484]     }
[1485] 
[1486]     if (SSL_CTX_set1_curves_list(ssl->ctx, (char *) name->data) == 0) {
[1487]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1488]                       "SSL_CTX_set1_curves_list(\"%s\") failed", name->data);
[1489]         return NGX_ERROR;
[1490]     }
[1491] 
[1492] #else
[1493] 
[1494]     int      nid;
[1495]     char    *curve;
[1496]     EC_KEY  *ecdh;
[1497] 
[1498]     if (ngx_strcmp(name->data, "auto") == 0) {
[1499]         curve = "prime256v1";
[1500] 
[1501]     } else {
[1502]         curve = (char *) name->data;
[1503]     }
[1504] 
[1505]     nid = OBJ_sn2nid(curve);
[1506]     if (nid == 0) {
[1507]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1508]                       "OBJ_sn2nid(\"%s\") failed: unknown curve", curve);
[1509]         return NGX_ERROR;
[1510]     }
[1511] 
[1512]     ecdh = EC_KEY_new_by_curve_name(nid);
[1513]     if (ecdh == NULL) {
[1514]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1515]                       "EC_KEY_new_by_curve_name(\"%s\") failed", curve);
[1516]         return NGX_ERROR;
[1517]     }
[1518] 
[1519]     SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);
[1520] 
[1521]     SSL_CTX_set_tmp_ecdh(ssl->ctx, ecdh);
[1522] 
[1523]     EC_KEY_free(ecdh);
[1524] #endif
[1525] #endif
[1526] 
[1527]     return NGX_OK;
[1528] }
[1529] 
[1530] 
[1531] ngx_int_t
[1532] ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
[1533] {
[1534]     if (!enable) {
[1535]         return NGX_OK;
[1536]     }
[1537] 
[1538] #ifdef SSL_ERROR_EARLY_DATA_REJECTED
[1539] 
[1540]     /* BoringSSL */
[1541] 
[1542]     SSL_CTX_set_early_data_enabled(ssl->ctx, 1);
[1543] 
[1544] #elif defined SSL_READ_EARLY_DATA_SUCCESS
[1545] 
[1546]     /* OpenSSL */
[1547] 
[1548]     SSL_CTX_set_max_early_data(ssl->ctx, NGX_SSL_BUFSIZE);
[1549] 
[1550] #else
[1551]     ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[1552]                   "\"ssl_early_data\" is not supported on this platform, "
[1553]                   "ignored");
[1554] #endif
[1555] 
[1556]     return NGX_OK;
[1557] }
[1558] 
[1559] 
[1560] ngx_int_t
[1561] ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *commands)
[1562] {
[1563]     if (commands == NULL) {
[1564]         return NGX_OK;
[1565]     }
[1566] 
[1567] #ifdef SSL_CONF_FLAG_FILE
[1568]     {
[1569]     int            type;
[1570]     u_char        *key, *value;
[1571]     ngx_uint_t     i;
[1572]     ngx_keyval_t  *cmd;
[1573]     SSL_CONF_CTX  *cctx;
[1574] 
[1575]     cctx = SSL_CONF_CTX_new();
[1576]     if (cctx == NULL) {
[1577]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1578]                       "SSL_CONF_CTX_new() failed");
[1579]         return NGX_ERROR;
[1580]     }
[1581] 
[1582]     SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
[1583]     SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
[1584]     SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
[1585]     SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
[1586]     SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SHOW_ERRORS);
[1587] 
[1588]     SSL_CONF_CTX_set_ssl_ctx(cctx, ssl->ctx);
[1589] 
[1590]     cmd = commands->elts;
[1591]     for (i = 0; i < commands->nelts; i++) {
[1592] 
[1593]         key = cmd[i].key.data;
[1594]         type = SSL_CONF_cmd_value_type(cctx, (char *) key);
[1595] 
[1596]         if (type == SSL_CONF_TYPE_FILE || type == SSL_CONF_TYPE_DIR) {
[1597]             if (ngx_conf_full_name(cf->cycle, &cmd[i].value, 1) != NGX_OK) {
[1598]                 SSL_CONF_CTX_free(cctx);
[1599]                 return NGX_ERROR;
[1600]             }
[1601]         }
[1602] 
[1603]         value = cmd[i].value.data;
[1604] 
[1605]         if (SSL_CONF_cmd(cctx, (char *) key, (char *) value) <= 0) {
[1606]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1607]                           "SSL_CONF_cmd(\"%s\", \"%s\") failed", key, value);
[1608]             SSL_CONF_CTX_free(cctx);
[1609]             return NGX_ERROR;
[1610]         }
[1611]     }
[1612] 
[1613]     if (SSL_CONF_CTX_finish(cctx) != 1) {
[1614]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[1615]                       "SSL_CONF_finish() failed");
[1616]         SSL_CONF_CTX_free(cctx);
[1617]         return NGX_ERROR;
[1618]     }
[1619] 
[1620]     SSL_CONF_CTX_free(cctx);
[1621] 
[1622]     return NGX_OK;
[1623]     }
[1624] #else
[1625]     ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
[1626]                   "SSL_CONF_cmd() is not available on this platform");
[1627]     return NGX_ERROR;
[1628] #endif
[1629] }
[1630] 
[1631] 
[1632] ngx_int_t
[1633] ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_uint_t enable)
[1634] {
[1635]     if (!enable) {
[1636]         return NGX_OK;
[1637]     }
[1638] 
[1639]     SSL_CTX_set_session_cache_mode(ssl->ctx,
[1640]                                    SSL_SESS_CACHE_CLIENT
[1641]                                    |SSL_SESS_CACHE_NO_INTERNAL);
[1642] 
[1643]     SSL_CTX_sess_set_new_cb(ssl->ctx, ngx_ssl_new_client_session);
[1644] 
[1645]     return NGX_OK;
[1646] }
[1647] 
[1648] 
[1649] static int
[1650] ngx_ssl_new_client_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
[1651] {
[1652]     ngx_connection_t  *c;
[1653] 
[1654]     c = ngx_ssl_get_connection(ssl_conn);
[1655] 
[1656]     if (c->ssl->save_session) {
[1657]         c->ssl->session = sess;
[1658] 
[1659]         c->ssl->save_session(c);
[1660] 
[1661]         c->ssl->session = NULL;
[1662]     }
[1663] 
[1664]     return 0;
[1665] }
[1666] 
[1667] 
[1668] ngx_int_t
[1669] ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
[1670] {
[1671]     ngx_ssl_connection_t  *sc;
[1672] 
[1673]     sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
[1674]     if (sc == NULL) {
[1675]         return NGX_ERROR;
[1676]     }
[1677] 
[1678]     sc->buffer = ((flags & NGX_SSL_BUFFER) != 0);
[1679]     sc->buffer_size = ssl->buffer_size;
[1680] 
[1681]     sc->session_ctx = ssl->ctx;
[1682] 
[1683] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[1684]     if (SSL_CTX_get_max_early_data(ssl->ctx)) {
[1685]         sc->try_early_data = 1;
[1686]     }
[1687] #endif
[1688] 
[1689]     sc->connection = SSL_new(ssl->ctx);
[1690] 
[1691]     if (sc->connection == NULL) {
[1692]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_new() failed");
[1693]         return NGX_ERROR;
[1694]     }
[1695] 
[1696]     if (SSL_set_fd(sc->connection, c->fd) == 0) {
[1697]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
[1698]         return NGX_ERROR;
[1699]     }
[1700] 
[1701]     if (flags & NGX_SSL_CLIENT) {
[1702]         SSL_set_connect_state(sc->connection);
[1703] 
[1704]     } else {
[1705]         SSL_set_accept_state(sc->connection);
[1706] 
[1707] #ifdef SSL_OP_NO_RENEGOTIATION
[1708]         SSL_set_options(sc->connection, SSL_OP_NO_RENEGOTIATION);
[1709] #endif
[1710]     }
[1711] 
[1712]     if (SSL_set_ex_data(sc->connection, ngx_ssl_connection_index, c) == 0) {
[1713]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
[1714]         return NGX_ERROR;
[1715]     }
[1716] 
[1717]     c->ssl = sc;
[1718] 
[1719]     return NGX_OK;
[1720] }
[1721] 
[1722] 
[1723] ngx_ssl_session_t *
[1724] ngx_ssl_get_session(ngx_connection_t *c)
[1725] {
[1726] #ifdef TLS1_3_VERSION
[1727]     if (c->ssl->session) {
[1728]         SSL_SESSION_up_ref(c->ssl->session);
[1729]         return c->ssl->session;
[1730]     }
[1731] #endif
[1732] 
[1733]     return SSL_get1_session(c->ssl->connection);
[1734] }
[1735] 
[1736] 
[1737] ngx_ssl_session_t *
[1738] ngx_ssl_get0_session(ngx_connection_t *c)
[1739] {
[1740]     if (c->ssl->session) {
[1741]         return c->ssl->session;
[1742]     }
[1743] 
[1744]     return SSL_get0_session(c->ssl->connection);
[1745] }
[1746] 
[1747] 
[1748] ngx_int_t
[1749] ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
[1750] {
[1751]     if (session) {
[1752]         if (SSL_set_session(c->ssl->connection, session) == 0) {
[1753]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_session() failed");
[1754]             return NGX_ERROR;
[1755]         }
[1756]     }
[1757] 
[1758]     return NGX_OK;
[1759] }
[1760] 
[1761] 
[1762] ngx_int_t
[1763] ngx_ssl_handshake(ngx_connection_t *c)
[1764] {
[1765]     int        n, sslerr;
[1766]     ngx_err_t  err;
[1767]     ngx_int_t  rc;
[1768] 
[1769] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[1770]     if (c->ssl->try_early_data) {
[1771]         return ngx_ssl_try_early_data(c);
[1772]     }
[1773] #endif
[1774] 
[1775]     if (c->ssl->in_ocsp) {
[1776]         return ngx_ssl_ocsp_validate(c);
[1777]     }
[1778] 
[1779]     ngx_ssl_clear_error(c->log);
[1780] 
[1781]     n = SSL_do_handshake(c->ssl->connection);
[1782] 
[1783]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);
[1784] 
[1785]     if (n == 1) {
[1786] 
[1787]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[1788]             return NGX_ERROR;
[1789]         }
[1790] 
[1791]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[1792]             return NGX_ERROR;
[1793]         }
[1794] 
[1795] #if (NGX_DEBUG)
[1796]         ngx_ssl_handshake_log(c);
[1797] #endif
[1798] 
[1799]         c->recv = ngx_ssl_recv;
[1800]         c->send = ngx_ssl_write;
[1801]         c->recv_chain = ngx_ssl_recv_chain;
[1802]         c->send_chain = ngx_ssl_send_chain;
[1803] 
[1804]         c->read->ready = 1;
[1805]         c->write->ready = 1;
[1806] 
[1807] #ifndef SSL_OP_NO_RENEGOTIATION
[1808] #if OPENSSL_VERSION_NUMBER < 0x10100000L
[1809] #ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
[1810] 
[1811]         /* initial handshake done, disable renegotiation (CVE-2009-3555) */
[1812]         if (c->ssl->connection->s3 && SSL_is_server(c->ssl->connection)) {
[1813]             c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
[1814]         }
[1815] 
[1816] #endif
[1817] #endif
[1818] #endif
[1819] 
[1820] #if (defined BIO_get_ktls_send && !NGX_WIN32)
[1821] 
[1822]         if (BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) == 1) {
[1823]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[1824]                            "BIO_get_ktls_send(): 1");
[1825]             c->ssl->sendfile = 1;
[1826]         }
[1827] 
[1828] #endif
[1829] 
[1830]         rc = ngx_ssl_ocsp_validate(c);
[1831] 
[1832]         if (rc == NGX_ERROR) {
[1833]             return NGX_ERROR;
[1834]         }
[1835] 
[1836]         if (rc == NGX_AGAIN) {
[1837]             c->read->handler = ngx_ssl_handshake_handler;
[1838]             c->write->handler = ngx_ssl_handshake_handler;
[1839]             return NGX_AGAIN;
[1840]         }
[1841] 
[1842]         c->ssl->handshaked = 1;
[1843] 
[1844]         return NGX_OK;
[1845]     }
[1846] 
[1847]     sslerr = SSL_get_error(c->ssl->connection, n);
[1848] 
[1849]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
[1850] 
[1851]     if (sslerr == SSL_ERROR_WANT_READ) {
[1852]         c->read->ready = 0;
[1853]         c->read->handler = ngx_ssl_handshake_handler;
[1854]         c->write->handler = ngx_ssl_handshake_handler;
[1855] 
[1856]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[1857]             return NGX_ERROR;
[1858]         }
[1859] 
[1860]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[1861]             return NGX_ERROR;
[1862]         }
[1863] 
[1864]         return NGX_AGAIN;
[1865]     }
[1866] 
[1867]     if (sslerr == SSL_ERROR_WANT_WRITE) {
[1868]         c->write->ready = 0;
[1869]         c->read->handler = ngx_ssl_handshake_handler;
[1870]         c->write->handler = ngx_ssl_handshake_handler;
[1871] 
[1872]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[1873]             return NGX_ERROR;
[1874]         }
[1875] 
[1876]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[1877]             return NGX_ERROR;
[1878]         }
[1879] 
[1880]         return NGX_AGAIN;
[1881]     }
[1882] 
[1883]     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[1884] 
[1885]     c->ssl->no_wait_shutdown = 1;
[1886]     c->ssl->no_send_shutdown = 1;
[1887]     c->read->eof = 1;
[1888] 
[1889]     if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
[1890]         ngx_connection_error(c, err,
[1891]                              "peer closed connection in SSL handshake");
[1892] 
[1893]         return NGX_ERROR;
[1894]     }
[1895] 
[1896]     if (c->ssl->handshake_rejected) {
[1897]         ngx_connection_error(c, err, "handshake rejected");
[1898]         ERR_clear_error();
[1899] 
[1900]         return NGX_ERROR;
[1901]     }
[1902] 
[1903]     c->read->error = 1;
[1904] 
[1905]     ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");
[1906] 
[1907]     return NGX_ERROR;
[1908] }
[1909] 
[1910] 
[1911] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[1912] 
[1913] static ngx_int_t
[1914] ngx_ssl_try_early_data(ngx_connection_t *c)
[1915] {
[1916]     int        n, sslerr;
[1917]     u_char     buf;
[1918]     size_t     readbytes;
[1919]     ngx_err_t  err;
[1920]     ngx_int_t  rc;
[1921] 
[1922]     ngx_ssl_clear_error(c->log);
[1923] 
[1924]     readbytes = 0;
[1925] 
[1926]     n = SSL_read_early_data(c->ssl->connection, &buf, 1, &readbytes);
[1927] 
[1928]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[1929]                    "SSL_read_early_data: %d, %uz", n, readbytes);
[1930] 
[1931]     if (n == SSL_READ_EARLY_DATA_FINISH) {
[1932]         c->ssl->try_early_data = 0;
[1933]         return ngx_ssl_handshake(c);
[1934]     }
[1935] 
[1936]     if (n == SSL_READ_EARLY_DATA_SUCCESS) {
[1937] 
[1938]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[1939]             return NGX_ERROR;
[1940]         }
[1941] 
[1942]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[1943]             return NGX_ERROR;
[1944]         }
[1945] 
[1946] #if (NGX_DEBUG)
[1947]         ngx_ssl_handshake_log(c);
[1948] #endif
[1949] 
[1950]         c->ssl->try_early_data = 0;
[1951] 
[1952]         c->ssl->early_buf = buf;
[1953]         c->ssl->early_preread = 1;
[1954] 
[1955]         c->ssl->in_early = 1;
[1956] 
[1957]         c->recv = ngx_ssl_recv;
[1958]         c->send = ngx_ssl_write;
[1959]         c->recv_chain = ngx_ssl_recv_chain;
[1960]         c->send_chain = ngx_ssl_send_chain;
[1961] 
[1962]         c->read->ready = 1;
[1963]         c->write->ready = 1;
[1964] 
[1965] #if (defined BIO_get_ktls_send && !NGX_WIN32)
[1966] 
[1967]         if (BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) == 1) {
[1968]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[1969]                            "BIO_get_ktls_send(): 1");
[1970]             c->ssl->sendfile = 1;
[1971]         }
[1972] 
[1973] #endif
[1974] 
[1975]         rc = ngx_ssl_ocsp_validate(c);
[1976] 
[1977]         if (rc == NGX_ERROR) {
[1978]             return NGX_ERROR;
[1979]         }
[1980] 
[1981]         if (rc == NGX_AGAIN) {
[1982]             c->read->handler = ngx_ssl_handshake_handler;
[1983]             c->write->handler = ngx_ssl_handshake_handler;
[1984]             return NGX_AGAIN;
[1985]         }
[1986] 
[1987]         c->ssl->handshaked = 1;
[1988] 
[1989]         return NGX_OK;
[1990]     }
[1991] 
[1992]     /* SSL_READ_EARLY_DATA_ERROR */
[1993] 
[1994]     sslerr = SSL_get_error(c->ssl->connection, n);
[1995] 
[1996]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
[1997] 
[1998]     if (sslerr == SSL_ERROR_WANT_READ) {
[1999]         c->read->ready = 0;
[2000]         c->read->handler = ngx_ssl_handshake_handler;
[2001]         c->write->handler = ngx_ssl_handshake_handler;
[2002] 
[2003]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2004]             return NGX_ERROR;
[2005]         }
[2006] 
[2007]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[2008]             return NGX_ERROR;
[2009]         }
[2010] 
[2011]         return NGX_AGAIN;
[2012]     }
[2013] 
[2014]     if (sslerr == SSL_ERROR_WANT_WRITE) {
[2015]         c->write->ready = 0;
[2016]         c->read->handler = ngx_ssl_handshake_handler;
[2017]         c->write->handler = ngx_ssl_handshake_handler;
[2018] 
[2019]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2020]             return NGX_ERROR;
[2021]         }
[2022] 
[2023]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[2024]             return NGX_ERROR;
[2025]         }
[2026] 
[2027]         return NGX_AGAIN;
[2028]     }
[2029] 
[2030]     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[2031] 
[2032]     c->ssl->no_wait_shutdown = 1;
[2033]     c->ssl->no_send_shutdown = 1;
[2034]     c->read->eof = 1;
[2035] 
[2036]     if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
[2037]         ngx_connection_error(c, err,
[2038]                              "peer closed connection in SSL handshake");
[2039] 
[2040]         return NGX_ERROR;
[2041]     }
[2042] 
[2043]     c->read->error = 1;
[2044] 
[2045]     ngx_ssl_connection_error(c, sslerr, err, "SSL_read_early_data() failed");
[2046] 
[2047]     return NGX_ERROR;
[2048] }
[2049] 
[2050] #endif
[2051] 
[2052] 
[2053] #if (NGX_DEBUG)
[2054] 
[2055] static void
[2056] ngx_ssl_handshake_log(ngx_connection_t *c)
[2057] {
[2058]     char         buf[129], *s, *d;
[2059] #if OPENSSL_VERSION_NUMBER >= 0x10000000L
[2060]     const
[2061] #endif
[2062]     SSL_CIPHER  *cipher;
[2063] 
[2064]     if (!(c->log->log_level & NGX_LOG_DEBUG_EVENT)) {
[2065]         return;
[2066]     }
[2067] 
[2068]     cipher = SSL_get_current_cipher(c->ssl->connection);
[2069] 
[2070]     if (cipher) {
[2071]         SSL_CIPHER_description(cipher, &buf[1], 128);
[2072] 
[2073]         for (s = &buf[1], d = buf; *s; s++) {
[2074]             if (*s == ' ' && *d == ' ') {
[2075]                 continue;
[2076]             }
[2077] 
[2078]             if (*s == LF || *s == CR) {
[2079]                 continue;
[2080]             }
[2081] 
[2082]             *++d = *s;
[2083]         }
[2084] 
[2085]         if (*d != ' ') {
[2086]             d++;
[2087]         }
[2088] 
[2089]         *d = '\0';
[2090] 
[2091]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2092]                        "SSL: %s, cipher: \"%s\"",
[2093]                        SSL_get_version(c->ssl->connection), &buf[1]);
[2094] 
[2095]         if (SSL_session_reused(c->ssl->connection)) {
[2096]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2097]                            "SSL reused session");
[2098]         }
[2099] 
[2100]     } else {
[2101]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2102]                        "SSL no shared ciphers");
[2103]     }
[2104] }
[2105] 
[2106] #endif
[2107] 
[2108] 
[2109] static void
[2110] ngx_ssl_handshake_handler(ngx_event_t *ev)
[2111] {
[2112]     ngx_connection_t  *c;
[2113] 
[2114]     c = ev->data;
[2115] 
[2116]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2117]                    "SSL handshake handler: %d", ev->write);
[2118] 
[2119]     if (ev->timedout) {
[2120]         c->ssl->handler(c);
[2121]         return;
[2122]     }
[2123] 
[2124]     if (ngx_ssl_handshake(c) == NGX_AGAIN) {
[2125]         return;
[2126]     }
[2127] 
[2128]     c->ssl->handler(c);
[2129] }
[2130] 
[2131] 
[2132] ssize_t
[2133] ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
[2134] {
[2135]     u_char     *last;
[2136]     ssize_t     n, bytes, size;
[2137]     ngx_buf_t  *b;
[2138] 
[2139]     bytes = 0;
[2140] 
[2141]     b = cl->buf;
[2142]     last = b->last;
[2143] 
[2144]     for ( ;; ) {
[2145]         size = b->end - last;
[2146] 
[2147]         if (limit) {
[2148]             if (bytes >= limit) {
[2149]                 return bytes;
[2150]             }
[2151] 
[2152]             if (bytes + size > limit) {
[2153]                 size = (ssize_t) (limit - bytes);
[2154]             }
[2155]         }
[2156] 
[2157]         n = ngx_ssl_recv(c, last, size);
[2158] 
[2159]         if (n > 0) {
[2160]             last += n;
[2161]             bytes += n;
[2162] 
[2163]             if (!c->read->ready) {
[2164]                 return bytes;
[2165]             }
[2166] 
[2167]             if (last == b->end) {
[2168]                 cl = cl->next;
[2169] 
[2170]                 if (cl == NULL) {
[2171]                     return bytes;
[2172]                 }
[2173] 
[2174]                 b = cl->buf;
[2175]                 last = b->last;
[2176]             }
[2177] 
[2178]             continue;
[2179]         }
[2180] 
[2181]         if (bytes) {
[2182] 
[2183]             if (n == 0 || n == NGX_ERROR) {
[2184]                 c->read->ready = 1;
[2185]             }
[2186] 
[2187]             return bytes;
[2188]         }
[2189] 
[2190]         return n;
[2191]     }
[2192] }
[2193] 
[2194] 
[2195] ssize_t
[2196] ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
[2197] {
[2198]     int  n, bytes;
[2199] 
[2200] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[2201]     if (c->ssl->in_early) {
[2202]         return ngx_ssl_recv_early(c, buf, size);
[2203]     }
[2204] #endif
[2205] 
[2206]     if (c->ssl->last == NGX_ERROR) {
[2207]         c->read->ready = 0;
[2208]         c->read->error = 1;
[2209]         return NGX_ERROR;
[2210]     }
[2211] 
[2212]     if (c->ssl->last == NGX_DONE) {
[2213]         c->read->ready = 0;
[2214]         c->read->eof = 1;
[2215]         return 0;
[2216]     }
[2217] 
[2218]     bytes = 0;
[2219] 
[2220]     ngx_ssl_clear_error(c->log);
[2221] 
[2222]     /*
[2223]      * SSL_read() may return data in parts, so try to read
[2224]      * until SSL_read() would return no data
[2225]      */
[2226] 
[2227]     for ( ;; ) {
[2228] 
[2229]         n = SSL_read(c->ssl->connection, buf, size);
[2230] 
[2231]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);
[2232] 
[2233]         if (n > 0) {
[2234]             bytes += n;
[2235]         }
[2236] 
[2237]         c->ssl->last = ngx_ssl_handle_recv(c, n);
[2238] 
[2239]         if (c->ssl->last == NGX_OK) {
[2240] 
[2241]             size -= n;
[2242] 
[2243]             if (size == 0) {
[2244]                 c->read->ready = 1;
[2245] 
[2246]                 if (c->read->available >= 0) {
[2247]                     c->read->available -= bytes;
[2248] 
[2249]                     /*
[2250]                      * there can be data buffered at SSL layer,
[2251]                      * so we post an event to continue reading on the next
[2252]                      * iteration of the event loop
[2253]                      */
[2254] 
[2255]                     if (c->read->available < 0) {
[2256]                         c->read->available = 0;
[2257]                         c->read->ready = 0;
[2258] 
[2259]                         if (c->read->posted) {
[2260]                             ngx_delete_posted_event(c->read);
[2261]                         }
[2262] 
[2263]                         ngx_post_event(c->read, &ngx_posted_next_events);
[2264]                     }
[2265] 
[2266]                     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2267]                                    "SSL_read: avail:%d", c->read->available);
[2268] 
[2269]                 } else {
[2270] 
[2271] #if (NGX_HAVE_FIONREAD)
[2272] 
[2273]                     if (ngx_socket_nread(c->fd, &c->read->available) == -1) {
[2274]                         c->read->ready = 0;
[2275]                         c->read->error = 1;
[2276]                         ngx_connection_error(c, ngx_socket_errno,
[2277]                                              ngx_socket_nread_n " failed");
[2278]                         return NGX_ERROR;
[2279]                     }
[2280] 
[2281]                     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2282]                                    "SSL_read: avail:%d", c->read->available);
[2283] 
[2284] #endif
[2285]                 }
[2286] 
[2287]                 return bytes;
[2288]             }
[2289] 
[2290]             buf += n;
[2291] 
[2292]             continue;
[2293]         }
[2294] 
[2295]         if (bytes) {
[2296]             if (c->ssl->last != NGX_AGAIN) {
[2297]                 c->read->ready = 1;
[2298]             }
[2299] 
[2300]             return bytes;
[2301]         }
[2302] 
[2303]         switch (c->ssl->last) {
[2304] 
[2305]         case NGX_DONE:
[2306]             c->read->ready = 0;
[2307]             c->read->eof = 1;
[2308]             return 0;
[2309] 
[2310]         case NGX_ERROR:
[2311]             c->read->ready = 0;
[2312]             c->read->error = 1;
[2313] 
[2314]             /* fall through */
[2315] 
[2316]         case NGX_AGAIN:
[2317]             return c->ssl->last;
[2318]         }
[2319]     }
[2320] }
[2321] 
[2322] 
[2323] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[2324] 
[2325] static ssize_t
[2326] ngx_ssl_recv_early(ngx_connection_t *c, u_char *buf, size_t size)
[2327] {
[2328]     int        n, bytes;
[2329]     size_t     readbytes;
[2330] 
[2331]     if (c->ssl->last == NGX_ERROR) {
[2332]         c->read->ready = 0;
[2333]         c->read->error = 1;
[2334]         return NGX_ERROR;
[2335]     }
[2336] 
[2337]     if (c->ssl->last == NGX_DONE) {
[2338]         c->read->ready = 0;
[2339]         c->read->eof = 1;
[2340]         return 0;
[2341]     }
[2342] 
[2343]     bytes = 0;
[2344] 
[2345]     ngx_ssl_clear_error(c->log);
[2346] 
[2347]     if (c->ssl->early_preread) {
[2348] 
[2349]         if (size == 0) {
[2350]             c->read->ready = 0;
[2351]             c->read->eof = 1;
[2352]             return 0;
[2353]         }
[2354] 
[2355]         *buf = c->ssl->early_buf;
[2356] 
[2357]         c->ssl->early_preread = 0;
[2358] 
[2359]         bytes = 1;
[2360]         size -= 1;
[2361]         buf += 1;
[2362]     }
[2363] 
[2364]     if (c->ssl->write_blocked) {
[2365]         return NGX_AGAIN;
[2366]     }
[2367] 
[2368]     /*
[2369]      * SSL_read_early_data() may return data in parts, so try to read
[2370]      * until SSL_read_early_data() would return no data
[2371]      */
[2372] 
[2373]     for ( ;; ) {
[2374] 
[2375]         readbytes = 0;
[2376] 
[2377]         n = SSL_read_early_data(c->ssl->connection, buf, size, &readbytes);
[2378] 
[2379]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2380]                        "SSL_read_early_data: %d, %uz", n, readbytes);
[2381] 
[2382]         if (n == SSL_READ_EARLY_DATA_SUCCESS) {
[2383] 
[2384]             c->ssl->last = ngx_ssl_handle_recv(c, 1);
[2385] 
[2386]             bytes += readbytes;
[2387]             size -= readbytes;
[2388] 
[2389]             if (size == 0) {
[2390]                 c->read->ready = 1;
[2391]                 return bytes;
[2392]             }
[2393] 
[2394]             buf += readbytes;
[2395] 
[2396]             continue;
[2397]         }
[2398] 
[2399]         if (n == SSL_READ_EARLY_DATA_FINISH) {
[2400] 
[2401]             c->ssl->last = ngx_ssl_handle_recv(c, 1);
[2402]             c->ssl->in_early = 0;
[2403] 
[2404]             if (bytes) {
[2405]                 c->read->ready = 1;
[2406]                 return bytes;
[2407]             }
[2408] 
[2409]             return ngx_ssl_recv(c, buf, size);
[2410]         }
[2411] 
[2412]         /* SSL_READ_EARLY_DATA_ERROR */
[2413] 
[2414]         c->ssl->last = ngx_ssl_handle_recv(c, 0);
[2415] 
[2416]         if (bytes) {
[2417]             if (c->ssl->last != NGX_AGAIN) {
[2418]                 c->read->ready = 1;
[2419]             }
[2420] 
[2421]             return bytes;
[2422]         }
[2423] 
[2424]         switch (c->ssl->last) {
[2425] 
[2426]         case NGX_DONE:
[2427]             c->read->ready = 0;
[2428]             c->read->eof = 1;
[2429]             return 0;
[2430] 
[2431]         case NGX_ERROR:
[2432]             c->read->ready = 0;
[2433]             c->read->error = 1;
[2434] 
[2435]             /* fall through */
[2436] 
[2437]         case NGX_AGAIN:
[2438]             return c->ssl->last;
[2439]         }
[2440]     }
[2441] }
[2442] 
[2443] #endif
[2444] 
[2445] 
[2446] static ngx_int_t
[2447] ngx_ssl_handle_recv(ngx_connection_t *c, int n)
[2448] {
[2449]     int        sslerr;
[2450]     ngx_err_t  err;
[2451] 
[2452] #ifndef SSL_OP_NO_RENEGOTIATION
[2453] 
[2454]     if (c->ssl->renegotiation) {
[2455]         /*
[2456]          * disable renegotiation (CVE-2009-3555):
[2457]          * OpenSSL (at least up to 0.9.8l) does not handle disabled
[2458]          * renegotiation gracefully, so drop connection here
[2459]          */
[2460] 
[2461]         ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "SSL renegotiation disabled");
[2462] 
[2463]         while (ERR_peek_error()) {
[2464]             ngx_ssl_error(NGX_LOG_DEBUG, c->log, 0,
[2465]                           "ignoring stale global SSL error");
[2466]         }
[2467] 
[2468]         ERR_clear_error();
[2469] 
[2470]         c->ssl->no_wait_shutdown = 1;
[2471]         c->ssl->no_send_shutdown = 1;
[2472] 
[2473]         return NGX_ERROR;
[2474]     }
[2475] 
[2476] #endif
[2477] 
[2478]     if (n > 0) {
[2479] 
[2480]         if (c->ssl->saved_write_handler) {
[2481] 
[2482]             c->write->handler = c->ssl->saved_write_handler;
[2483]             c->ssl->saved_write_handler = NULL;
[2484]             c->write->ready = 1;
[2485] 
[2486]             if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[2487]                 return NGX_ERROR;
[2488]             }
[2489] 
[2490]             ngx_post_event(c->write, &ngx_posted_events);
[2491]         }
[2492] 
[2493]         return NGX_OK;
[2494]     }
[2495] 
[2496]     sslerr = SSL_get_error(c->ssl->connection, n);
[2497] 
[2498]     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[2499] 
[2500]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
[2501] 
[2502]     if (sslerr == SSL_ERROR_WANT_READ) {
[2503] 
[2504]         if (c->ssl->saved_write_handler) {
[2505] 
[2506]             c->write->handler = c->ssl->saved_write_handler;
[2507]             c->ssl->saved_write_handler = NULL;
[2508]             c->write->ready = 1;
[2509] 
[2510]             if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[2511]                 return NGX_ERROR;
[2512]             }
[2513] 
[2514]             ngx_post_event(c->write, &ngx_posted_events);
[2515]         }
[2516] 
[2517]         c->read->ready = 0;
[2518]         return NGX_AGAIN;
[2519]     }
[2520] 
[2521]     if (sslerr == SSL_ERROR_WANT_WRITE) {
[2522] 
[2523]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2524]                        "SSL_read: want write");
[2525] 
[2526]         c->write->ready = 0;
[2527] 
[2528]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[2529]             return NGX_ERROR;
[2530]         }
[2531] 
[2532]         /*
[2533]          * we do not set the timer because there is already the read event timer
[2534]          */
[2535] 
[2536]         if (c->ssl->saved_write_handler == NULL) {
[2537]             c->ssl->saved_write_handler = c->write->handler;
[2538]             c->write->handler = ngx_ssl_write_handler;
[2539]         }
[2540] 
[2541]         return NGX_AGAIN;
[2542]     }
[2543] 
[2544]     c->ssl->no_wait_shutdown = 1;
[2545]     c->ssl->no_send_shutdown = 1;
[2546] 
[2547]     if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
[2548]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2549]                        "peer shutdown SSL cleanly");
[2550]         return NGX_DONE;
[2551]     }
[2552] 
[2553]     ngx_ssl_connection_error(c, sslerr, err, "SSL_read() failed");
[2554] 
[2555]     return NGX_ERROR;
[2556] }
[2557] 
[2558] 
[2559] static void
[2560] ngx_ssl_write_handler(ngx_event_t *wev)
[2561] {
[2562]     ngx_connection_t  *c;
[2563] 
[2564]     c = wev->data;
[2565] 
[2566]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL write handler");
[2567] 
[2568]     c->read->handler(c->read);
[2569] }
[2570] 
[2571] 
[2572] /*
[2573]  * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
[2574]  * before the SSL_write() call to decrease a SSL overhead.
[2575]  *
[2576]  * Besides for protocols such as HTTP it is possible to always buffer
[2577]  * the output to decrease a SSL overhead some more.
[2578]  */
[2579] 
[2580] ngx_chain_t *
[2581] ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[2582] {
[2583]     int           n;
[2584]     ngx_uint_t    flush;
[2585]     ssize_t       send, size, file_size;
[2586]     ngx_buf_t    *buf;
[2587]     ngx_chain_t  *cl;
[2588] 
[2589]     if (!c->ssl->buffer) {
[2590] 
[2591]         while (in) {
[2592]             if (ngx_buf_special(in->buf)) {
[2593]                 in = in->next;
[2594]                 continue;
[2595]             }
[2596] 
[2597]             n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);
[2598] 
[2599]             if (n == NGX_ERROR) {
[2600]                 return NGX_CHAIN_ERROR;
[2601]             }
[2602] 
[2603]             if (n == NGX_AGAIN) {
[2604]                 return in;
[2605]             }
[2606] 
[2607]             in->buf->pos += n;
[2608] 
[2609]             if (in->buf->pos == in->buf->last) {
[2610]                 in = in->next;
[2611]             }
[2612]         }
[2613] 
[2614]         return in;
[2615]     }
[2616] 
[2617] 
[2618]     /* the maximum limit size is the maximum int32_t value - the page size */
[2619] 
[2620]     if (limit == 0 || limit > (off_t) (NGX_MAX_INT32_VALUE - ngx_pagesize)) {
[2621]         limit = NGX_MAX_INT32_VALUE - ngx_pagesize;
[2622]     }
[2623] 
[2624]     buf = c->ssl->buf;
[2625] 
[2626]     if (buf == NULL) {
[2627]         buf = ngx_create_temp_buf(c->pool, c->ssl->buffer_size);
[2628]         if (buf == NULL) {
[2629]             return NGX_CHAIN_ERROR;
[2630]         }
[2631] 
[2632]         c->ssl->buf = buf;
[2633]     }
[2634] 
[2635]     if (buf->start == NULL) {
[2636]         buf->start = ngx_palloc(c->pool, c->ssl->buffer_size);
[2637]         if (buf->start == NULL) {
[2638]             return NGX_CHAIN_ERROR;
[2639]         }
[2640] 
[2641]         buf->pos = buf->start;
[2642]         buf->last = buf->start;
[2643]         buf->end = buf->start + c->ssl->buffer_size;
[2644]     }
[2645] 
[2646]     send = buf->last - buf->pos;
[2647]     flush = (in == NULL) ? 1 : buf->flush;
[2648] 
[2649]     for ( ;; ) {
[2650] 
[2651]         while (in && buf->last < buf->end && send < limit) {
[2652]             if (in->buf->last_buf || in->buf->flush) {
[2653]                 flush = 1;
[2654]             }
[2655] 
[2656]             if (ngx_buf_special(in->buf)) {
[2657]                 in = in->next;
[2658]                 continue;
[2659]             }
[2660] 
[2661]             if (in->buf->in_file && c->ssl->sendfile) {
[2662]                 flush = 1;
[2663]                 break;
[2664]             }
[2665] 
[2666]             size = in->buf->last - in->buf->pos;
[2667] 
[2668]             if (size > buf->end - buf->last) {
[2669]                 size = buf->end - buf->last;
[2670]             }
[2671] 
[2672]             if (send + size > limit) {
[2673]                 size = (ssize_t) (limit - send);
[2674]             }
[2675] 
[2676]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2677]                            "SSL buf copy: %z", size);
[2678] 
[2679]             ngx_memcpy(buf->last, in->buf->pos, size);
[2680] 
[2681]             buf->last += size;
[2682]             in->buf->pos += size;
[2683]             send += size;
[2684] 
[2685]             if (in->buf->pos == in->buf->last) {
[2686]                 in = in->next;
[2687]             }
[2688]         }
[2689] 
[2690]         if (!flush && send < limit && buf->last < buf->end) {
[2691]             break;
[2692]         }
[2693] 
[2694]         size = buf->last - buf->pos;
[2695] 
[2696]         if (size == 0) {
[2697] 
[2698]             if (in && in->buf->in_file && send < limit) {
[2699] 
[2700]                 /* coalesce the neighbouring file bufs */
[2701] 
[2702]                 cl = in;
[2703]                 file_size = (size_t) ngx_chain_coalesce_file(&cl, limit - send);
[2704] 
[2705]                 n = ngx_ssl_sendfile(c, in->buf, file_size);
[2706] 
[2707]                 if (n == NGX_ERROR) {
[2708]                     return NGX_CHAIN_ERROR;
[2709]                 }
[2710] 
[2711]                 if (n == NGX_AGAIN) {
[2712]                     break;
[2713]                 }
[2714] 
[2715]                 in = ngx_chain_update_sent(in, n);
[2716] 
[2717]                 send += n;
[2718]                 flush = 0;
[2719] 
[2720]                 continue;
[2721]             }
[2722] 
[2723]             buf->flush = 0;
[2724]             c->buffered &= ~NGX_SSL_BUFFERED;
[2725] 
[2726]             return in;
[2727]         }
[2728] 
[2729]         n = ngx_ssl_write(c, buf->pos, size);
[2730] 
[2731]         if (n == NGX_ERROR) {
[2732]             return NGX_CHAIN_ERROR;
[2733]         }
[2734] 
[2735]         if (n == NGX_AGAIN) {
[2736]             break;
[2737]         }
[2738] 
[2739]         buf->pos += n;
[2740] 
[2741]         if (n < size) {
[2742]             break;
[2743]         }
[2744] 
[2745]         flush = 0;
[2746] 
[2747]         buf->pos = buf->start;
[2748]         buf->last = buf->start;
[2749] 
[2750]         if (in == NULL || send >= limit) {
[2751]             break;
[2752]         }
[2753]     }
[2754] 
[2755]     buf->flush = flush;
[2756] 
[2757]     if (buf->pos < buf->last) {
[2758]         c->buffered |= NGX_SSL_BUFFERED;
[2759] 
[2760]     } else {
[2761]         c->buffered &= ~NGX_SSL_BUFFERED;
[2762]     }
[2763] 
[2764]     return in;
[2765] }
[2766] 
[2767] 
[2768] ssize_t
[2769] ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
[2770] {
[2771]     int        n, sslerr;
[2772]     ngx_err_t  err;
[2773] 
[2774] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[2775]     if (c->ssl->in_early) {
[2776]         return ngx_ssl_write_early(c, data, size);
[2777]     }
[2778] #endif
[2779] 
[2780]     ngx_ssl_clear_error(c->log);
[2781] 
[2782]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);
[2783] 
[2784]     n = SSL_write(c->ssl->connection, data, size);
[2785] 
[2786]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);
[2787] 
[2788]     if (n > 0) {
[2789] 
[2790]         if (c->ssl->saved_read_handler) {
[2791] 
[2792]             c->read->handler = c->ssl->saved_read_handler;
[2793]             c->ssl->saved_read_handler = NULL;
[2794]             c->read->ready = 1;
[2795] 
[2796]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2797]                 return NGX_ERROR;
[2798]             }
[2799] 
[2800]             ngx_post_event(c->read, &ngx_posted_events);
[2801]         }
[2802] 
[2803]         c->sent += n;
[2804] 
[2805]         return n;
[2806]     }
[2807] 
[2808]     sslerr = SSL_get_error(c->ssl->connection, n);
[2809] 
[2810]     if (sslerr == SSL_ERROR_ZERO_RETURN) {
[2811] 
[2812]         /*
[2813]          * OpenSSL 1.1.1 fails to return SSL_ERROR_SYSCALL if an error
[2814]          * happens during SSL_write() after close_notify alert from the
[2815]          * peer, and returns SSL_ERROR_ZERO_RETURN instead,
[2816]          * https://git.openssl.org/?p=openssl.git;a=commitdiff;h=8051ab2
[2817]          */
[2818] 
[2819]         sslerr = SSL_ERROR_SYSCALL;
[2820]     }
[2821] 
[2822]     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[2823] 
[2824]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
[2825] 
[2826]     if (sslerr == SSL_ERROR_WANT_WRITE) {
[2827] 
[2828]         if (c->ssl->saved_read_handler) {
[2829] 
[2830]             c->read->handler = c->ssl->saved_read_handler;
[2831]             c->ssl->saved_read_handler = NULL;
[2832]             c->read->ready = 1;
[2833] 
[2834]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2835]                 return NGX_ERROR;
[2836]             }
[2837] 
[2838]             ngx_post_event(c->read, &ngx_posted_events);
[2839]         }
[2840] 
[2841]         c->write->ready = 0;
[2842]         return NGX_AGAIN;
[2843]     }
[2844] 
[2845]     if (sslerr == SSL_ERROR_WANT_READ) {
[2846] 
[2847]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2848]                        "SSL_write: want read");
[2849] 
[2850]         c->read->ready = 0;
[2851] 
[2852]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2853]             return NGX_ERROR;
[2854]         }
[2855] 
[2856]         /*
[2857]          * we do not set the timer because there is already
[2858]          * the write event timer
[2859]          */
[2860] 
[2861]         if (c->ssl->saved_read_handler == NULL) {
[2862]             c->ssl->saved_read_handler = c->read->handler;
[2863]             c->read->handler = ngx_ssl_read_handler;
[2864]         }
[2865] 
[2866]         return NGX_AGAIN;
[2867]     }
[2868] 
[2869]     c->ssl->no_wait_shutdown = 1;
[2870]     c->ssl->no_send_shutdown = 1;
[2871]     c->write->error = 1;
[2872] 
[2873]     ngx_ssl_connection_error(c, sslerr, err, "SSL_write() failed");
[2874] 
[2875]     return NGX_ERROR;
[2876] }
[2877] 
[2878] 
[2879] #ifdef SSL_READ_EARLY_DATA_SUCCESS
[2880] 
[2881] static ssize_t
[2882] ngx_ssl_write_early(ngx_connection_t *c, u_char *data, size_t size)
[2883] {
[2884]     int        n, sslerr;
[2885]     size_t     written;
[2886]     ngx_err_t  err;
[2887] 
[2888]     ngx_ssl_clear_error(c->log);
[2889] 
[2890]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);
[2891] 
[2892]     written = 0;
[2893] 
[2894]     n = SSL_write_early_data(c->ssl->connection, data, size, &written);
[2895] 
[2896]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2897]                    "SSL_write_early_data: %d, %uz", n, written);
[2898] 
[2899]     if (n > 0) {
[2900] 
[2901]         if (c->ssl->saved_read_handler) {
[2902] 
[2903]             c->read->handler = c->ssl->saved_read_handler;
[2904]             c->ssl->saved_read_handler = NULL;
[2905]             c->read->ready = 1;
[2906] 
[2907]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2908]                 return NGX_ERROR;
[2909]             }
[2910] 
[2911]             ngx_post_event(c->read, &ngx_posted_events);
[2912]         }
[2913] 
[2914]         if (c->ssl->write_blocked) {
[2915]             c->ssl->write_blocked = 0;
[2916]             ngx_post_event(c->read, &ngx_posted_events);
[2917]         }
[2918] 
[2919]         c->sent += written;
[2920] 
[2921]         return written;
[2922]     }
[2923] 
[2924]     sslerr = SSL_get_error(c->ssl->connection, n);
[2925] 
[2926]     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[2927] 
[2928]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
[2929] 
[2930]     if (sslerr == SSL_ERROR_WANT_WRITE) {
[2931] 
[2932]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2933]                        "SSL_write_early_data: want write");
[2934] 
[2935]         if (c->ssl->saved_read_handler) {
[2936] 
[2937]             c->read->handler = c->ssl->saved_read_handler;
[2938]             c->ssl->saved_read_handler = NULL;
[2939]             c->read->ready = 1;
[2940] 
[2941]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2942]                 return NGX_ERROR;
[2943]             }
[2944] 
[2945]             ngx_post_event(c->read, &ngx_posted_events);
[2946]         }
[2947] 
[2948]         /*
[2949]          * OpenSSL 1.1.1a fails to handle SSL_read_early_data()
[2950]          * if an SSL_write_early_data() call blocked on writing,
[2951]          * see https://github.com/openssl/openssl/issues/7757
[2952]          */
[2953] 
[2954]         c->ssl->write_blocked = 1;
[2955] 
[2956]         c->write->ready = 0;
[2957]         return NGX_AGAIN;
[2958]     }
[2959] 
[2960]     if (sslerr == SSL_ERROR_WANT_READ) {
[2961] 
[2962]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[2963]                        "SSL_write_early_data: want read");
[2964] 
[2965]         c->read->ready = 0;
[2966] 
[2967]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[2968]             return NGX_ERROR;
[2969]         }
[2970] 
[2971]         /*
[2972]          * we do not set the timer because there is already
[2973]          * the write event timer
[2974]          */
[2975] 
[2976]         if (c->ssl->saved_read_handler == NULL) {
[2977]             c->ssl->saved_read_handler = c->read->handler;
[2978]             c->read->handler = ngx_ssl_read_handler;
[2979]         }
[2980] 
[2981]         return NGX_AGAIN;
[2982]     }
[2983] 
[2984]     c->ssl->no_wait_shutdown = 1;
[2985]     c->ssl->no_send_shutdown = 1;
[2986]     c->write->error = 1;
[2987] 
[2988]     ngx_ssl_connection_error(c, sslerr, err, "SSL_write_early_data() failed");
[2989] 
[2990]     return NGX_ERROR;
[2991] }
[2992] 
[2993] #endif
[2994] 
[2995] 
[2996] static ssize_t
[2997] ngx_ssl_sendfile(ngx_connection_t *c, ngx_buf_t *file, size_t size)
[2998] {
[2999] #if (defined BIO_get_ktls_send && !NGX_WIN32)
[3000] 
[3001]     int        sslerr, flags;
[3002]     ssize_t    n;
[3003]     ngx_err_t  err;
[3004] 
[3005]     ngx_ssl_clear_error(c->log);
[3006] 
[3007]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[3008]                    "SSL to sendfile: @%O %uz",
[3009]                    file->file_pos, size);
[3010] 
[3011]     ngx_set_errno(0);
[3012] 
[3013] #if (NGX_HAVE_SENDFILE_NODISKIO)
[3014] 
[3015]     flags = (c->busy_count <= 2) ? SF_NODISKIO : 0;
[3016] 
[3017]     if (file->file->directio) {
[3018]         flags |= SF_NOCACHE;
[3019]     }
[3020] 
[3021] #else
[3022]     flags = 0;
[3023] #endif
[3024] 
[3025]     n = SSL_sendfile(c->ssl->connection, file->file->fd, file->file_pos,
[3026]                      size, flags);
[3027] 
[3028]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_sendfile: %z", n);
[3029] 
[3030]     if (n > 0) {
[3031] 
[3032]         if (c->ssl->saved_read_handler) {
[3033] 
[3034]             c->read->handler = c->ssl->saved_read_handler;
[3035]             c->ssl->saved_read_handler = NULL;
[3036]             c->read->ready = 1;
[3037] 
[3038]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[3039]                 return NGX_ERROR;
[3040]             }
[3041] 
[3042]             ngx_post_event(c->read, &ngx_posted_events);
[3043]         }
[3044] 
[3045] #if (NGX_HAVE_SENDFILE_NODISKIO)
[3046]         c->busy_count = 0;
[3047] #endif
[3048] 
[3049]         c->sent += n;
[3050] 
[3051]         return n;
[3052]     }
[3053] 
[3054]     if (n == 0) {
[3055] 
[3056]         /*
[3057]          * if sendfile returns zero, then someone has truncated the file,
[3058]          * so the offset became beyond the end of the file
[3059]          */
[3060] 
[3061]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[3062]                       "SSL_sendfile() reported that \"%s\" was truncated at %O",
[3063]                       file->file->name.data, file->file_pos);
[3064] 
[3065]         return NGX_ERROR;
[3066]     }
[3067] 
[3068]     sslerr = SSL_get_error(c->ssl->connection, n);
[3069] 
[3070]     if (sslerr == SSL_ERROR_ZERO_RETURN) {
[3071] 
[3072]         /*
[3073]          * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
[3074]          * happens during writing after close_notify alert from the
[3075]          * peer, and returns SSL_ERROR_ZERO_RETURN instead
[3076]          */
[3077] 
[3078]         sslerr = SSL_ERROR_SYSCALL;
[3079]     }
[3080] 
[3081]     if (sslerr == SSL_ERROR_SSL
[3082]         && ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNINITIALIZED
[3083]         && ngx_errno != 0)
[3084]     {
[3085]         /*
[3086]          * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
[3087]          * happens in sendfile(), and returns SSL_ERROR_SSL with
[3088]          * SSL_R_UNINITIALIZED reason instead
[3089]          */
[3090] 
[3091]         sslerr = SSL_ERROR_SYSCALL;
[3092]     }
[3093] 
[3094]     err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[3095] 
[3096]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);
[3097] 
[3098]     if (sslerr == SSL_ERROR_WANT_WRITE) {
[3099] 
[3100]         if (c->ssl->saved_read_handler) {
[3101] 
[3102]             c->read->handler = c->ssl->saved_read_handler;
[3103]             c->ssl->saved_read_handler = NULL;
[3104]             c->read->ready = 1;
[3105] 
[3106]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[3107]                 return NGX_ERROR;
[3108]             }
[3109] 
[3110]             ngx_post_event(c->read, &ngx_posted_events);
[3111]         }
[3112] 
[3113] #if (NGX_HAVE_SENDFILE_NODISKIO)
[3114] 
[3115]         if (ngx_errno == EBUSY) {
[3116]             c->busy_count++;
[3117] 
[3118]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[3119]                            "SSL_sendfile() busy, count:%d", c->busy_count);
[3120] 
[3121]             if (c->write->posted) {
[3122]                 ngx_delete_posted_event(c->write);
[3123]             }
[3124] 
[3125]             ngx_post_event(c->write, &ngx_posted_next_events);
[3126]         }
[3127] 
[3128] #endif
[3129] 
[3130]         c->write->ready = 0;
[3131]         return NGX_AGAIN;
[3132]     }
[3133] 
[3134]     if (sslerr == SSL_ERROR_WANT_READ) {
[3135] 
[3136]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[3137]                        "SSL_sendfile: want read");
[3138] 
[3139]         c->read->ready = 0;
[3140] 
[3141]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[3142]             return NGX_ERROR;
[3143]         }
[3144] 
[3145]         /*
[3146]          * we do not set the timer because there is already
[3147]          * the write event timer
[3148]          */
[3149] 
[3150]         if (c->ssl->saved_read_handler == NULL) {
[3151]             c->ssl->saved_read_handler = c->read->handler;
[3152]             c->read->handler = ngx_ssl_read_handler;
[3153]         }
[3154] 
[3155]         return NGX_AGAIN;
[3156]     }
[3157] 
[3158]     c->ssl->no_wait_shutdown = 1;
[3159]     c->ssl->no_send_shutdown = 1;
[3160]     c->write->error = 1;
[3161] 
[3162]     ngx_ssl_connection_error(c, sslerr, err, "SSL_sendfile() failed");
[3163] 
[3164] #else
[3165]     ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[3166]                   "SSL_sendfile() not available");
[3167] #endif
[3168] 
[3169]     return NGX_ERROR;
[3170] }
[3171] 
[3172] 
[3173] static void
[3174] ngx_ssl_read_handler(ngx_event_t *rev)
[3175] {
[3176]     ngx_connection_t  *c;
[3177] 
[3178]     c = rev->data;
[3179] 
[3180]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL read handler");
[3181] 
[3182]     c->write->handler(c->write);
[3183] }
[3184] 
[3185] 
[3186] void
[3187] ngx_ssl_free_buffer(ngx_connection_t *c)
[3188] {
[3189]     if (c->ssl->buf && c->ssl->buf->start) {
[3190]         if (ngx_pfree(c->pool, c->ssl->buf->start) == NGX_OK) {
[3191]             c->ssl->buf->start = NULL;
[3192]         }
[3193]     }
[3194] }
[3195] 
[3196] 
[3197] ngx_int_t
[3198] ngx_ssl_shutdown(ngx_connection_t *c)
[3199] {
[3200]     int         n, sslerr, mode;
[3201]     ngx_int_t   rc;
[3202]     ngx_err_t   err;
[3203]     ngx_uint_t  tries;
[3204] 
[3205]     rc = NGX_OK;
[3206] 
[3207]     ngx_ssl_ocsp_cleanup(c);
[3208] 
[3209]     if (SSL_in_init(c->ssl->connection)) {
[3210]         /*
[3211]          * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
[3212]          * an SSL handshake, while previous versions always return 0.
[3213]          * Avoid calling SSL_shutdown() if handshake wasn't completed.
[3214]          */
[3215] 
[3216]         goto done;
[3217]     }
[3218] 
[3219]     if (c->timedout || c->error || c->buffered) {
[3220]         mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;
[3221]         SSL_set_quiet_shutdown(c->ssl->connection, 1);
[3222] 
[3223]     } else {
[3224]         mode = SSL_get_shutdown(c->ssl->connection);
[3225] 
[3226]         if (c->ssl->no_wait_shutdown) {
[3227]             mode |= SSL_RECEIVED_SHUTDOWN;
[3228]         }
[3229] 
[3230]         if (c->ssl->no_send_shutdown) {
[3231]             mode |= SSL_SENT_SHUTDOWN;
[3232]         }
[3233] 
[3234]         if (c->ssl->no_wait_shutdown && c->ssl->no_send_shutdown) {
[3235]             SSL_set_quiet_shutdown(c->ssl->connection, 1);
[3236]         }
[3237]     }
[3238] 
[3239]     SSL_set_shutdown(c->ssl->connection, mode);
[3240] 
[3241]     ngx_ssl_clear_error(c->log);
[3242] 
[3243]     tries = 2;
[3244] 
[3245]     for ( ;; ) {
[3246] 
[3247]         /*
[3248]          * For bidirectional shutdown, SSL_shutdown() needs to be called
[3249]          * twice: first call sends the "close notify" alert and returns 0,
[3250]          * second call waits for the peer's "close notify" alert.
[3251]          */
[3252] 
[3253]         n = SSL_shutdown(c->ssl->connection);
[3254] 
[3255]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);
[3256] 
[3257]         if (n == 1) {
[3258]             goto done;
[3259]         }
[3260] 
[3261]         if (n == 0 && tries-- > 1) {
[3262]             continue;
[3263]         }
[3264] 
[3265]         /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */
[3266] 
[3267]         sslerr = SSL_get_error(c->ssl->connection, n);
[3268] 
[3269]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[3270]                        "SSL_get_error: %d", sslerr);
[3271] 
[3272]         if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
[3273]             c->read->handler = ngx_ssl_shutdown_handler;
[3274]             c->write->handler = ngx_ssl_shutdown_handler;
[3275] 
[3276]             if (sslerr == SSL_ERROR_WANT_READ) {
[3277]                 c->read->ready = 0;
[3278] 
[3279]             } else {
[3280]                 c->write->ready = 0;
[3281]             }
[3282] 
[3283]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[3284]                 goto failed;
[3285]             }
[3286] 
[3287]             if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[3288]                 goto failed;
[3289]             }
[3290] 
[3291]             ngx_add_timer(c->read, 3000);
[3292] 
[3293]             return NGX_AGAIN;
[3294]         }
[3295] 
[3296]         if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
[3297]             goto done;
[3298]         }
[3299] 
[3300]         err = (sslerr == SSL_ERROR_SYSCALL) ? ngx_errno : 0;
[3301] 
[3302]         ngx_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");
[3303] 
[3304]         break;
[3305]     }
[3306] 
[3307] failed:
[3308] 
[3309]     rc = NGX_ERROR;
[3310] 
[3311] done:
[3312] 
[3313]     if (c->ssl->shutdown_without_free) {
[3314]         c->ssl->shutdown_without_free = 0;
[3315]         c->recv = ngx_recv;
[3316]         return rc;
[3317]     }
[3318] 
[3319]     SSL_free(c->ssl->connection);
[3320]     c->ssl = NULL;
[3321]     c->recv = ngx_recv;
[3322] 
[3323]     return rc;
[3324] }
[3325] 
[3326] 
[3327] static void
[3328] ngx_ssl_shutdown_handler(ngx_event_t *ev)
[3329] {
[3330]     ngx_connection_t           *c;
[3331]     ngx_connection_handler_pt   handler;
[3332] 
[3333]     c = ev->data;
[3334]     handler = c->ssl->handler;
[3335] 
[3336]     if (ev->timedout) {
[3337]         c->timedout = 1;
[3338]     }
[3339] 
[3340]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "SSL shutdown handler");
[3341] 
[3342]     if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
[3343]         return;
[3344]     }
[3345] 
[3346]     handler(c);
[3347] }
[3348] 
[3349] 
[3350] static void
[3351] ngx_ssl_connection_error(ngx_connection_t *c, int sslerr, ngx_err_t err,
[3352]     char *text)
[3353] {
[3354]     int         n;
[3355]     ngx_uint_t  level;
[3356] 
[3357]     level = NGX_LOG_CRIT;
[3358] 
[3359]     if (sslerr == SSL_ERROR_SYSCALL) {
[3360] 
[3361]         if (err == NGX_ECONNRESET
[3362] #if (NGX_WIN32)
[3363]             || err == NGX_ECONNABORTED
[3364] #endif
[3365]             || err == NGX_EPIPE
[3366]             || err == NGX_ENOTCONN
[3367]             || err == NGX_ETIMEDOUT
[3368]             || err == NGX_ECONNREFUSED
[3369]             || err == NGX_ENETDOWN
[3370]             || err == NGX_ENETUNREACH
[3371]             || err == NGX_EHOSTDOWN
[3372]             || err == NGX_EHOSTUNREACH)
[3373]         {
[3374]             switch (c->log_error) {
[3375] 
[3376]             case NGX_ERROR_IGNORE_ECONNRESET:
[3377]             case NGX_ERROR_INFO:
[3378]                 level = NGX_LOG_INFO;
[3379]                 break;
[3380] 
[3381]             case NGX_ERROR_ERR:
[3382]                 level = NGX_LOG_ERR;
[3383]                 break;
[3384] 
[3385]             default:
[3386]                 break;
[3387]             }
[3388]         }
[3389] 
[3390]     } else if (sslerr == SSL_ERROR_SSL) {
[3391] 
[3392]         n = ERR_GET_REASON(ERR_peek_last_error());
[3393] 
[3394]             /* handshake failures */
[3395]         if (n == SSL_R_BAD_CHANGE_CIPHER_SPEC                        /*  103 */
[3396] #ifdef SSL_R_NO_SUITABLE_KEY_SHARE
[3397]             || n == SSL_R_NO_SUITABLE_KEY_SHARE                      /*  101 */
[3398] #endif
[3399] #ifdef SSL_R_BAD_ALERT
[3400]             || n == SSL_R_BAD_ALERT                                  /*  102 */
[3401] #endif
[3402] #ifdef SSL_R_BAD_KEY_SHARE
[3403]             || n == SSL_R_BAD_KEY_SHARE                              /*  108 */
[3404] #endif
[3405] #ifdef SSL_R_BAD_EXTENSION
[3406]             || n == SSL_R_BAD_EXTENSION                              /*  110 */
[3407] #endif
[3408]             || n == SSL_R_BAD_DIGEST_LENGTH                          /*  111 */
[3409] #ifdef SSL_R_MISSING_SIGALGS_EXTENSION
[3410]             || n == SSL_R_MISSING_SIGALGS_EXTENSION                  /*  112 */
[3411] #endif
[3412]             || n == SSL_R_BAD_PACKET_LENGTH                          /*  115 */
[3413] #ifdef SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM
[3414]             || n == SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            /*  118 */
[3415] #endif
[3416] #ifdef SSL_R_BAD_KEY_UPDATE
[3417]             || n == SSL_R_BAD_KEY_UPDATE                             /*  122 */
[3418] #endif
[3419]             || n == SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  /*  129 */
[3420]             || n == SSL_R_CCS_RECEIVED_EARLY                         /*  133 */
[3421] #ifdef SSL_R_DECODE_ERROR
[3422]             || n == SSL_R_DECODE_ERROR                               /*  137 */
[3423] #endif
[3424] #ifdef SSL_R_DATA_BETWEEN_CCS_AND_FINISHED
[3425]             || n == SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              /*  145 */
[3426] #endif
[3427]             || n == SSL_R_DATA_LENGTH_TOO_LONG                       /*  146 */
[3428]             || n == SSL_R_DIGEST_CHECK_FAILED                        /*  149 */
[3429]             || n == SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  /*  150 */
[3430]             || n == SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              /*  151 */
[3431]             || n == SSL_R_EXCESSIVE_MESSAGE_SIZE                     /*  152 */
[3432] #ifdef SSL_R_GOT_A_FIN_BEFORE_A_CCS
[3433]             || n == SSL_R_GOT_A_FIN_BEFORE_A_CCS                     /*  154 */
[3434] #endif
[3435]             || n == SSL_R_HTTPS_PROXY_REQUEST                        /*  155 */
[3436]             || n == SSL_R_HTTP_REQUEST                               /*  156 */
[3437]             || n == SSL_R_LENGTH_MISMATCH                            /*  159 */
[3438] #ifdef SSL_R_LENGTH_TOO_SHORT
[3439]             || n == SSL_R_LENGTH_TOO_SHORT                           /*  160 */
[3440] #endif
[3441] #ifdef SSL_R_NO_RENEGOTIATION
[3442]             || n == SSL_R_NO_RENEGOTIATION                           /*  182 */
[3443] #endif
[3444] #ifdef SSL_R_NO_CIPHERS_PASSED
[3445]             || n == SSL_R_NO_CIPHERS_PASSED                          /*  182 */
[3446] #endif
[3447]             || n == SSL_R_NO_CIPHERS_SPECIFIED                       /*  183 */
[3448] #ifdef SSL_R_BAD_CIPHER
[3449]             || n == SSL_R_BAD_CIPHER                                 /*  186 */
[3450] #endif
[3451]             || n == SSL_R_NO_COMPRESSION_SPECIFIED                   /*  187 */
[3452]             || n == SSL_R_NO_SHARED_CIPHER                           /*  193 */
[3453] #ifdef SSL_R_PACKET_LENGTH_TOO_LONG
[3454]             || n == SSL_R_PACKET_LENGTH_TOO_LONG                     /*  198 */
[3455] #endif
[3456]             || n == SSL_R_RECORD_LENGTH_MISMATCH                     /*  213 */
[3457] #ifdef SSL_R_TOO_MANY_WARNING_ALERTS
[3458]             || n == SSL_R_TOO_MANY_WARNING_ALERTS                    /*  220 */
[3459] #endif
[3460] #ifdef SSL_R_CLIENTHELLO_TLSEXT
[3461]             || n == SSL_R_CLIENTHELLO_TLSEXT                         /*  226 */
[3462] #endif
[3463] #ifdef SSL_R_PARSE_TLSEXT
[3464]             || n == SSL_R_PARSE_TLSEXT                               /*  227 */
[3465] #endif
[3466] #ifdef SSL_R_CALLBACK_FAILED
[3467]             || n == SSL_R_CALLBACK_FAILED                            /*  234 */
[3468] #endif
[3469] #ifdef SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG
[3470]             || n == SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG    /*  234 */
[3471] #endif
[3472] #ifdef SSL_R_NO_APPLICATION_PROTOCOL
[3473]             || n == SSL_R_NO_APPLICATION_PROTOCOL                    /*  235 */
[3474] #endif
[3475]             || n == SSL_R_UNEXPECTED_MESSAGE                         /*  244 */
[3476]             || n == SSL_R_UNEXPECTED_RECORD                          /*  245 */
[3477]             || n == SSL_R_UNKNOWN_ALERT_TYPE                         /*  246 */
[3478]             || n == SSL_R_UNKNOWN_PROTOCOL                           /*  252 */
[3479] #ifdef SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS
[3480]             || n == SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS             /*  253 */
[3481] #endif
[3482] #ifdef SSL_R_INVALID_COMPRESSION_LIST
[3483]             || n == SSL_R_INVALID_COMPRESSION_LIST                   /*  256 */
[3484] #endif
[3485] #ifdef SSL_R_MISSING_KEY_SHARE
[3486]             || n == SSL_R_MISSING_KEY_SHARE                          /*  258 */
[3487] #endif
[3488]             || n == SSL_R_UNSUPPORTED_PROTOCOL                       /*  258 */
[3489] #ifdef SSL_R_NO_SHARED_GROUP
[3490]             || n == SSL_R_NO_SHARED_GROUP                            /*  266 */
[3491] #endif
[3492]             || n == SSL_R_WRONG_VERSION_NUMBER                       /*  267 */
[3493] #ifdef SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA
[3494]             || n == SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA                /*  270 */
[3495] #endif
[3496]             || n == SSL_R_BAD_LENGTH                                 /*  271 */
[3497]             || n == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        /*  281 */
[3498] #ifdef SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY
[3499]             || n == SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY        /*  291 */
[3500] #endif
[3501] #ifdef SSL_R_APPLICATION_DATA_ON_SHUTDOWN
[3502]             || n == SSL_R_APPLICATION_DATA_ON_SHUTDOWN               /*  291 */
[3503] #endif
[3504] #ifdef SSL_R_BAD_LEGACY_VERSION
[3505]             || n == SSL_R_BAD_LEGACY_VERSION                         /*  292 */
[3506] #endif
[3507] #ifdef SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA
[3508]             || n == SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA     /*  293 */
[3509] #endif
[3510] #ifdef SSL_R_RECORD_TOO_SMALL
[3511]             || n == SSL_R_RECORD_TOO_SMALL                           /*  298 */
[3512] #endif
[3513] #ifdef SSL_R_SSL3_SESSION_ID_TOO_LONG
[3514]             || n == SSL_R_SSL3_SESSION_ID_TOO_LONG                   /*  300 */
[3515] #endif
[3516] #ifdef SSL_R_BAD_ECPOINT
[3517]             || n == SSL_R_BAD_ECPOINT                                /*  306 */
[3518] #endif
[3519] #ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
[3520]             || n == SSL_R_RENEGOTIATE_EXT_TOO_LONG                   /*  335 */
[3521]             || n == SSL_R_RENEGOTIATION_ENCODING_ERR                 /*  336 */
[3522]             || n == SSL_R_RENEGOTIATION_MISMATCH                     /*  337 */
[3523] #endif
[3524] #ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
[3525]             || n == SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       /*  338 */
[3526] #endif
[3527] #ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
[3528]             || n == SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           /*  345 */
[3529] #endif
[3530] #ifdef SSL_R_INAPPROPRIATE_FALLBACK
[3531]             || n == SSL_R_INAPPROPRIATE_FALLBACK                     /*  373 */
[3532] #endif
[3533] #ifdef SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS
[3534]             || n == SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             /*  376 */
[3535] #endif
[3536] #ifdef SSL_R_NO_SHARED_SIGATURE_ALGORITHMS
[3537]             || n == SSL_R_NO_SHARED_SIGATURE_ALGORITHMS              /*  376 */
[3538] #endif
[3539] #ifdef SSL_R_CERT_CB_ERROR
[3540]             || n == SSL_R_CERT_CB_ERROR                              /*  377 */
[3541] #endif
[3542] #ifdef SSL_R_VERSION_TOO_LOW
[3543]             || n == SSL_R_VERSION_TOO_LOW                            /*  396 */
[3544] #endif
[3545] #ifdef SSL_R_TOO_MANY_WARN_ALERTS
[3546]             || n == SSL_R_TOO_MANY_WARN_ALERTS                       /*  409 */
[3547] #endif
[3548] #ifdef SSL_R_BAD_RECORD_TYPE
[3549]             || n == SSL_R_BAD_RECORD_TYPE                            /*  443 */
[3550] #endif
[3551]             || n == 1000 /* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
[3552] #ifdef SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE
[3553]             || n == SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             /* 1010 */
[3554]             || n == SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 /* 1020 */
[3555]             || n == SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              /* 1021 */
[3556]             || n == SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                /* 1022 */
[3557]             || n == SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          /* 1030 */
[3558]             || n == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              /* 1040 */
[3559]             || n == SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 /* 1041 */
[3560]             || n == SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                /* 1042 */
[3561]             || n == SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        /* 1043 */
[3562]             || n == SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            /* 1044 */
[3563]             || n == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            /* 1045 */
[3564]             || n == SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            /* 1046 */
[3565]             || n == SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              /* 1047 */
[3566]             || n == SSL_R_TLSV1_ALERT_UNKNOWN_CA                     /* 1048 */
[3567]             || n == SSL_R_TLSV1_ALERT_ACCESS_DENIED                  /* 1049 */
[3568]             || n == SSL_R_TLSV1_ALERT_DECODE_ERROR                   /* 1050 */
[3569]             || n == SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  /* 1051 */
[3570]             || n == SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             /* 1060 */
[3571]             || n == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               /* 1070 */
[3572]             || n == SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          /* 1071 */
[3573]             || n == SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 /* 1080 */
[3574]             || n == SSL_R_TLSV1_ALERT_USER_CANCELLED                 /* 1090 */
[3575]             || n == SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               /* 1100 */
[3576] #endif
[3577]             )
[3578]         {
[3579]             switch (c->log_error) {
[3580] 
[3581]             case NGX_ERROR_IGNORE_ECONNRESET:
[3582]             case NGX_ERROR_INFO:
[3583]                 level = NGX_LOG_INFO;
[3584]                 break;
[3585] 
[3586]             case NGX_ERROR_ERR:
[3587]                 level = NGX_LOG_ERR;
[3588]                 break;
[3589] 
[3590]             default:
[3591]                 break;
[3592]             }
[3593]         }
[3594]     }
[3595] 
[3596]     ngx_ssl_error(level, c->log, err, text);
[3597] }
[3598] 
[3599] 
[3600] static void
[3601] ngx_ssl_clear_error(ngx_log_t *log)
[3602] {
[3603]     while (ERR_peek_error()) {
[3604]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "ignoring stale global SSL error");
[3605]     }
[3606] 
[3607]     ERR_clear_error();
[3608] }
[3609] 
[3610] 
[3611] void ngx_cdecl
[3612] ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
[3613] {
[3614]     int          flags;
[3615]     u_long       n;
[3616]     va_list      args;
[3617]     u_char      *p, *last;
[3618]     u_char       errstr[NGX_MAX_CONF_ERRSTR];
[3619]     const char  *data;
[3620] 
[3621]     last = errstr + NGX_MAX_CONF_ERRSTR;
[3622] 
[3623]     va_start(args, fmt);
[3624]     p = ngx_vslprintf(errstr, last - 1, fmt, args);
[3625]     va_end(args);
[3626] 
[3627]     if (ERR_peek_error()) {
[3628]         p = ngx_cpystrn(p, (u_char *) " (SSL:", last - p);
[3629] 
[3630]         for ( ;; ) {
[3631] 
[3632]             n = ERR_peek_error_data(&data, &flags);
[3633] 
[3634]             if (n == 0) {
[3635]                 break;
[3636]             }
[3637] 
[3638]             /* ERR_error_string_n() requires at least one byte */
[3639] 
[3640]             if (p >= last - 1) {
[3641]                 goto next;
[3642]             }
[3643] 
[3644]             *p++ = ' ';
[3645] 
[3646]             ERR_error_string_n(n, (char *) p, last - p);
[3647] 
[3648]             while (p < last && *p) {
[3649]                 p++;
[3650]             }
[3651] 
[3652]             if (p < last && *data && (flags & ERR_TXT_STRING)) {
[3653]                 *p++ = ':';
[3654]                 p = ngx_cpystrn(p, (u_char *) data, last - p);
[3655]             }
[3656] 
[3657]         next:
[3658] 
[3659]             (void) ERR_get_error();
[3660]         }
[3661] 
[3662]         if (p < last) {
[3663]             *p++ = ')';
[3664]         }
[3665]     }
[3666] 
[3667]     ngx_log_error(level, log, err, "%*s", p - errstr, errstr);
[3668] }
[3669] 
[3670] 
[3671] ngx_int_t
[3672] ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
[3673]     ngx_array_t *certificates, ssize_t builtin_session_cache,
[3674]     ngx_shm_zone_t *shm_zone, time_t timeout)
[3675] {
[3676]     long  cache_mode;
[3677] 
[3678]     SSL_CTX_set_timeout(ssl->ctx, (long) timeout);
[3679] 
[3680]     if (ngx_ssl_session_id_context(ssl, sess_ctx, certificates) != NGX_OK) {
[3681]         return NGX_ERROR;
[3682]     }
[3683] 
[3684]     if (builtin_session_cache == NGX_SSL_NO_SCACHE) {
[3685]         SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);
[3686]         return NGX_OK;
[3687]     }
[3688] 
[3689]     if (builtin_session_cache == NGX_SSL_NONE_SCACHE) {
[3690] 
[3691]         /*
[3692]          * If the server explicitly says that it does not support
[3693]          * session reuse (see SSL_SESS_CACHE_OFF above), then
[3694]          * Outlook Express fails to upload a sent email to
[3695]          * the Sent Items folder on the IMAP server via a separate IMAP
[3696]          * connection in the background.  Therefore we have a special
[3697]          * mode (SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_STORE)
[3698]          * where the server pretends that it supports session reuse,
[3699]          * but it does not actually store any session.
[3700]          */
[3701] 
[3702]         SSL_CTX_set_session_cache_mode(ssl->ctx,
[3703]                                        SSL_SESS_CACHE_SERVER
[3704]                                        |SSL_SESS_CACHE_NO_AUTO_CLEAR
[3705]                                        |SSL_SESS_CACHE_NO_INTERNAL_STORE);
[3706] 
[3707]         SSL_CTX_sess_set_cache_size(ssl->ctx, 1);
[3708] 
[3709]         return NGX_OK;
[3710]     }
[3711] 
[3712]     cache_mode = SSL_SESS_CACHE_SERVER;
[3713] 
[3714]     if (shm_zone && builtin_session_cache == NGX_SSL_NO_BUILTIN_SCACHE) {
[3715]         cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
[3716]     }
[3717] 
[3718]     SSL_CTX_set_session_cache_mode(ssl->ctx, cache_mode);
[3719] 
[3720]     if (builtin_session_cache != NGX_SSL_NO_BUILTIN_SCACHE) {
[3721] 
[3722]         if (builtin_session_cache != NGX_SSL_DFLT_BUILTIN_SCACHE) {
[3723]             SSL_CTX_sess_set_cache_size(ssl->ctx, builtin_session_cache);
[3724]         }
[3725]     }
[3726] 
[3727]     if (shm_zone) {
[3728]         SSL_CTX_sess_set_new_cb(ssl->ctx, ngx_ssl_new_session);
[3729]         SSL_CTX_sess_set_get_cb(ssl->ctx, ngx_ssl_get_cached_session);
[3730]         SSL_CTX_sess_set_remove_cb(ssl->ctx, ngx_ssl_remove_session);
[3731] 
[3732]         if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_session_cache_index, shm_zone)
[3733]             == 0)
[3734]         {
[3735]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3736]                           "SSL_CTX_set_ex_data() failed");
[3737]             return NGX_ERROR;
[3738]         }
[3739]     }
[3740] 
[3741]     return NGX_OK;
[3742] }
[3743] 
[3744] 
[3745] static ngx_int_t
[3746] ngx_ssl_session_id_context(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
[3747]     ngx_array_t *certificates)
[3748] {
[3749]     int                   n, i;
[3750]     X509                 *cert;
[3751]     X509_NAME            *name;
[3752]     ngx_str_t            *certs;
[3753]     ngx_uint_t            k;
[3754]     EVP_MD_CTX           *md;
[3755]     unsigned int          len;
[3756]     STACK_OF(X509_NAME)  *list;
[3757]     u_char                buf[EVP_MAX_MD_SIZE];
[3758] 
[3759]     /*
[3760]      * Session ID context is set based on the string provided,
[3761]      * the server certificates, and the client CA list.
[3762]      */
[3763] 
[3764]     md = EVP_MD_CTX_create();
[3765]     if (md == NULL) {
[3766]         return NGX_ERROR;
[3767]     }
[3768] 
[3769]     if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
[3770]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3771]                       "EVP_DigestInit_ex() failed");
[3772]         goto failed;
[3773]     }
[3774] 
[3775]     if (EVP_DigestUpdate(md, sess_ctx->data, sess_ctx->len) == 0) {
[3776]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3777]                       "EVP_DigestUpdate() failed");
[3778]         goto failed;
[3779]     }
[3780] 
[3781]     for (cert = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index);
[3782]          cert;
[3783]          cert = X509_get_ex_data(cert, ngx_ssl_next_certificate_index))
[3784]     {
[3785]         if (X509_digest(cert, EVP_sha1(), buf, &len) == 0) {
[3786]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3787]                           "X509_digest() failed");
[3788]             goto failed;
[3789]         }
[3790] 
[3791]         if (EVP_DigestUpdate(md, buf, len) == 0) {
[3792]             ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3793]                           "EVP_DigestUpdate() failed");
[3794]             goto failed;
[3795]         }
[3796]     }
[3797] 
[3798]     if (SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index) == NULL
[3799]         && certificates != NULL)
[3800]     {
[3801]         /*
[3802]          * If certificates are loaded dynamically, we use certificate
[3803]          * names as specified in the configuration (with variables).
[3804]          */
[3805] 
[3806]         certs = certificates->elts;
[3807]         for (k = 0; k < certificates->nelts; k++) {
[3808] 
[3809]             if (EVP_DigestUpdate(md, certs[k].data, certs[k].len) == 0) {
[3810]                 ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3811]                               "EVP_DigestUpdate() failed");
[3812]                 goto failed;
[3813]             }
[3814]         }
[3815]     }
[3816] 
[3817]     list = SSL_CTX_get_client_CA_list(ssl->ctx);
[3818] 
[3819]     if (list != NULL) {
[3820]         n = sk_X509_NAME_num(list);
[3821] 
[3822]         for (i = 0; i < n; i++) {
[3823]             name = sk_X509_NAME_value(list, i);
[3824] 
[3825]             if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
[3826]                 ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3827]                               "X509_NAME_digest() failed");
[3828]                 goto failed;
[3829]             }
[3830] 
[3831]             if (EVP_DigestUpdate(md, buf, len) == 0) {
[3832]                 ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3833]                               "EVP_DigestUpdate() failed");
[3834]                 goto failed;
[3835]             }
[3836]         }
[3837]     }
[3838] 
[3839]     if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
[3840]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3841]                       "EVP_DigestFinal_ex() failed");
[3842]         goto failed;
[3843]     }
[3844] 
[3845]     EVP_MD_CTX_destroy(md);
[3846] 
[3847]     if (SSL_CTX_set_session_id_context(ssl->ctx, buf, len) == 0) {
[3848]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[3849]                       "SSL_CTX_set_session_id_context() failed");
[3850]         return NGX_ERROR;
[3851]     }
[3852] 
[3853]     return NGX_OK;
[3854] 
[3855] failed:
[3856] 
[3857]     EVP_MD_CTX_destroy(md);
[3858] 
[3859]     return NGX_ERROR;
[3860] }
[3861] 
[3862] 
[3863] ngx_int_t
[3864] ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
[3865] {
[3866]     size_t                    len;
[3867]     ngx_slab_pool_t          *shpool;
[3868]     ngx_ssl_session_cache_t  *cache;
[3869] 
[3870]     if (data) {
[3871]         shm_zone->data = data;
[3872]         return NGX_OK;
[3873]     }
[3874] 
[3875]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[3876] 
[3877]     if (shm_zone->shm.exists) {
[3878]         shm_zone->data = shpool->data;
[3879]         return NGX_OK;
[3880]     }
[3881] 
[3882]     cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_session_cache_t));
[3883]     if (cache == NULL) {
[3884]         return NGX_ERROR;
[3885]     }
[3886] 
[3887]     shpool->data = cache;
[3888]     shm_zone->data = cache;
[3889] 
[3890]     ngx_rbtree_init(&cache->session_rbtree, &cache->sentinel,
[3891]                     ngx_ssl_session_rbtree_insert_value);
[3892] 
[3893]     ngx_queue_init(&cache->expire_queue);
[3894] 
[3895]     cache->ticket_keys[0].expire = 0;
[3896]     cache->ticket_keys[1].expire = 0;
[3897]     cache->ticket_keys[2].expire = 0;
[3898] 
[3899]     cache->fail_time = 0;
[3900] 
[3901]     len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;
[3902] 
[3903]     shpool->log_ctx = ngx_slab_alloc(shpool, len);
[3904]     if (shpool->log_ctx == NULL) {
[3905]         return NGX_ERROR;
[3906]     }
[3907] 
[3908]     ngx_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
[3909]                 &shm_zone->shm.name);
[3910] 
[3911]     shpool->log_nomem = 0;
[3912] 
[3913]     return NGX_OK;
[3914] }
[3915] 
[3916] 
[3917] /*
[3918]  * The length of the session id is 16 bytes for SSLv2 sessions and
[3919]  * between 1 and 32 bytes for SSLv3 and TLS, typically 32 bytes.
[3920]  * Typical length of the external ASN1 representation of a session
[3921]  * is about 150 bytes plus SNI server name.
[3922]  *
[3923]  * On 32-bit platforms we allocate an rbtree node, a session id, and
[3924]  * an ASN1 representation in a single allocation, it typically takes
[3925]  * 256 bytes.
[3926]  *
[3927]  * On 64-bit platforms we allocate separately an rbtree node + session_id,
[3928]  * and an ASN1 representation, they take accordingly 128 and 256 bytes.
[3929]  *
[3930]  * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
[3931]  * so they are outside the code locked by shared pool mutex
[3932]  */
[3933] 
[3934] static int
[3935] ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
[3936] {
[3937]     int                       len;
[3938]     u_char                   *p, *session_id;
[3939]     size_t                    n;
[3940]     uint32_t                  hash;
[3941]     SSL_CTX                  *ssl_ctx;
[3942]     unsigned int              session_id_length;
[3943]     ngx_shm_zone_t           *shm_zone;
[3944]     ngx_connection_t         *c;
[3945]     ngx_slab_pool_t          *shpool;
[3946]     ngx_ssl_sess_id_t        *sess_id;
[3947]     ngx_ssl_session_cache_t  *cache;
[3948]     u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];
[3949] 
[3950] #ifdef TLS1_3_VERSION
[3951] 
[3952]     /*
[3953]      * OpenSSL tries to save TLSv1.3 sessions into session cache
[3954]      * even when using tickets for stateless session resumption,
[3955]      * "because some applications just want to know about the creation
[3956]      * of a session"; do not cache such sessions
[3957]      */
[3958] 
[3959]     if (SSL_version(ssl_conn) == TLS1_3_VERSION
[3960]         && (SSL_get_options(ssl_conn) & SSL_OP_NO_TICKET) == 0)
[3961]     {
[3962]         return 0;
[3963]     }
[3964] 
[3965] #endif
[3966] 
[3967]     len = i2d_SSL_SESSION(sess, NULL);
[3968] 
[3969]     /* do not cache too big session */
[3970] 
[3971]     if (len > NGX_SSL_MAX_SESSION_SIZE) {
[3972]         return 0;
[3973]     }
[3974] 
[3975]     p = buf;
[3976]     i2d_SSL_SESSION(sess, &p);
[3977] 
[3978]     session_id = (u_char *) SSL_SESSION_get_id(sess, &session_id_length);
[3979] 
[3980]     /* do not cache sessions with too long session id */
[3981] 
[3982]     if (session_id_length > 32) {
[3983]         return 0;
[3984]     }
[3985] 
[3986]     c = ngx_ssl_get_connection(ssl_conn);
[3987] 
[3988]     ssl_ctx = c->ssl->session_ctx;
[3989]     shm_zone = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index);
[3990] 
[3991]     cache = shm_zone->data;
[3992]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[3993] 
[3994]     ngx_shmtx_lock(&shpool->mutex);
[3995] 
[3996]     /* drop one or two expired sessions */
[3997]     ngx_ssl_expire_sessions(cache, shpool, 1);
[3998] 
[3999] #if (NGX_PTR_SIZE == 8)
[4000]     n = sizeof(ngx_ssl_sess_id_t);
[4001] #else
[4002]     n = offsetof(ngx_ssl_sess_id_t, session) + len;
[4003] #endif
[4004] 
[4005]     sess_id = ngx_slab_alloc_locked(shpool, n);
[4006] 
[4007]     if (sess_id == NULL) {
[4008] 
[4009]         /* drop the oldest non-expired session and try once more */
[4010] 
[4011]         ngx_ssl_expire_sessions(cache, shpool, 0);
[4012] 
[4013]         sess_id = ngx_slab_alloc_locked(shpool, n);
[4014] 
[4015]         if (sess_id == NULL) {
[4016]             goto failed;
[4017]         }
[4018]     }
[4019] 
[4020] #if (NGX_PTR_SIZE == 8)
[4021] 
[4022]     sess_id->session = ngx_slab_alloc_locked(shpool, len);
[4023] 
[4024]     if (sess_id->session == NULL) {
[4025] 
[4026]         /* drop the oldest non-expired session and try once more */
[4027] 
[4028]         ngx_ssl_expire_sessions(cache, shpool, 0);
[4029] 
[4030]         sess_id->session = ngx_slab_alloc_locked(shpool, len);
[4031] 
[4032]         if (sess_id->session == NULL) {
[4033]             goto failed;
[4034]         }
[4035]     }
[4036] 
[4037] #endif
[4038] 
[4039]     ngx_memcpy(sess_id->session, buf, len);
[4040]     ngx_memcpy(sess_id->id, session_id, session_id_length);
[4041] 
[4042]     hash = ngx_crc32_short(session_id, session_id_length);
[4043] 
[4044]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4045]                    "ssl new session: %08XD:%ud:%d",
[4046]                    hash, session_id_length, len);
[4047] 
[4048]     sess_id->node.key = hash;
[4049]     sess_id->node.data = (u_char) session_id_length;
[4050]     sess_id->len = len;
[4051] 
[4052]     sess_id->expire = ngx_time() + SSL_CTX_get_timeout(ssl_ctx);
[4053] 
[4054]     ngx_queue_insert_head(&cache->expire_queue, &sess_id->queue);
[4055] 
[4056]     ngx_rbtree_insert(&cache->session_rbtree, &sess_id->node);
[4057] 
[4058]     ngx_shmtx_unlock(&shpool->mutex);
[4059] 
[4060]     return 0;
[4061] 
[4062] failed:
[4063] 
[4064]     if (sess_id) {
[4065]         ngx_slab_free_locked(shpool, sess_id);
[4066]     }
[4067] 
[4068]     ngx_shmtx_unlock(&shpool->mutex);
[4069] 
[4070]     if (cache->fail_time != ngx_time()) {
[4071]         cache->fail_time = ngx_time();
[4072]         ngx_log_error(NGX_LOG_WARN, c->log, 0,
[4073]                       "could not allocate new session%s", shpool->log_ctx);
[4074]     }
[4075] 
[4076]     return 0;
[4077] }
[4078] 
[4079] 
[4080] static ngx_ssl_session_t *
[4081] ngx_ssl_get_cached_session(ngx_ssl_conn_t *ssl_conn,
[4082] #if OPENSSL_VERSION_NUMBER >= 0x10100003L
[4083]     const
[4084] #endif
[4085]     u_char *id, int len, int *copy)
[4086] {
[4087]     size_t                    slen;
[4088]     uint32_t                  hash;
[4089]     ngx_int_t                 rc;
[4090]     const u_char             *p;
[4091]     ngx_shm_zone_t           *shm_zone;
[4092]     ngx_slab_pool_t          *shpool;
[4093]     ngx_rbtree_node_t        *node, *sentinel;
[4094]     ngx_ssl_session_t        *sess;
[4095]     ngx_ssl_sess_id_t        *sess_id;
[4096]     ngx_ssl_session_cache_t  *cache;
[4097]     u_char                    buf[NGX_SSL_MAX_SESSION_SIZE];
[4098]     ngx_connection_t         *c;
[4099] 
[4100]     hash = ngx_crc32_short((u_char *) (uintptr_t) id, (size_t) len);
[4101]     *copy = 0;
[4102] 
[4103]     c = ngx_ssl_get_connection(ssl_conn);
[4104] 
[4105]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4106]                    "ssl get session: %08XD:%d", hash, len);
[4107] 
[4108]     shm_zone = SSL_CTX_get_ex_data(c->ssl->session_ctx,
[4109]                                    ngx_ssl_session_cache_index);
[4110] 
[4111]     cache = shm_zone->data;
[4112] 
[4113]     sess = NULL;
[4114] 
[4115]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[4116] 
[4117]     ngx_shmtx_lock(&shpool->mutex);
[4118] 
[4119]     node = cache->session_rbtree.root;
[4120]     sentinel = cache->session_rbtree.sentinel;
[4121] 
[4122]     while (node != sentinel) {
[4123] 
[4124]         if (hash < node->key) {
[4125]             node = node->left;
[4126]             continue;
[4127]         }
[4128] 
[4129]         if (hash > node->key) {
[4130]             node = node->right;
[4131]             continue;
[4132]         }
[4133] 
[4134]         /* hash == node->key */
[4135] 
[4136]         sess_id = (ngx_ssl_sess_id_t *) node;
[4137] 
[4138]         rc = ngx_memn2cmp((u_char *) (uintptr_t) id, sess_id->id,
[4139]                           (size_t) len, (size_t) node->data);
[4140] 
[4141]         if (rc == 0) {
[4142] 
[4143]             if (sess_id->expire > ngx_time()) {
[4144]                 slen = sess_id->len;
[4145] 
[4146]                 ngx_memcpy(buf, sess_id->session, slen);
[4147] 
[4148]                 ngx_shmtx_unlock(&shpool->mutex);
[4149] 
[4150]                 p = buf;
[4151]                 sess = d2i_SSL_SESSION(NULL, &p, slen);
[4152] 
[4153]                 return sess;
[4154]             }
[4155] 
[4156]             ngx_queue_remove(&sess_id->queue);
[4157] 
[4158]             ngx_rbtree_delete(&cache->session_rbtree, node);
[4159] 
[4160]             ngx_explicit_memzero(sess_id->session, sess_id->len);
[4161] 
[4162] #if (NGX_PTR_SIZE == 8)
[4163]             ngx_slab_free_locked(shpool, sess_id->session);
[4164] #endif
[4165]             ngx_slab_free_locked(shpool, sess_id);
[4166] 
[4167]             sess = NULL;
[4168] 
[4169]             goto done;
[4170]         }
[4171] 
[4172]         node = (rc < 0) ? node->left : node->right;
[4173]     }
[4174] 
[4175] done:
[4176] 
[4177]     ngx_shmtx_unlock(&shpool->mutex);
[4178] 
[4179]     return sess;
[4180] }
[4181] 
[4182] 
[4183] void
[4184] ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
[4185] {
[4186]     SSL_CTX_remove_session(ssl, sess);
[4187] 
[4188]     ngx_ssl_remove_session(ssl, sess);
[4189] }
[4190] 
[4191] 
[4192] static void
[4193] ngx_ssl_remove_session(SSL_CTX *ssl, ngx_ssl_session_t *sess)
[4194] {
[4195]     u_char                   *id;
[4196]     uint32_t                  hash;
[4197]     ngx_int_t                 rc;
[4198]     unsigned int              len;
[4199]     ngx_shm_zone_t           *shm_zone;
[4200]     ngx_slab_pool_t          *shpool;
[4201]     ngx_rbtree_node_t        *node, *sentinel;
[4202]     ngx_ssl_sess_id_t        *sess_id;
[4203]     ngx_ssl_session_cache_t  *cache;
[4204] 
[4205]     shm_zone = SSL_CTX_get_ex_data(ssl, ngx_ssl_session_cache_index);
[4206] 
[4207]     if (shm_zone == NULL) {
[4208]         return;
[4209]     }
[4210] 
[4211]     cache = shm_zone->data;
[4212] 
[4213]     id = (u_char *) SSL_SESSION_get_id(sess, &len);
[4214] 
[4215]     hash = ngx_crc32_short(id, len);
[4216] 
[4217]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
[4218]                    "ssl remove session: %08XD:%ud", hash, len);
[4219] 
[4220]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[4221] 
[4222]     ngx_shmtx_lock(&shpool->mutex);
[4223] 
[4224]     node = cache->session_rbtree.root;
[4225]     sentinel = cache->session_rbtree.sentinel;
[4226] 
[4227]     while (node != sentinel) {
[4228] 
[4229]         if (hash < node->key) {
[4230]             node = node->left;
[4231]             continue;
[4232]         }
[4233] 
[4234]         if (hash > node->key) {
[4235]             node = node->right;
[4236]             continue;
[4237]         }
[4238] 
[4239]         /* hash == node->key */
[4240] 
[4241]         sess_id = (ngx_ssl_sess_id_t *) node;
[4242] 
[4243]         rc = ngx_memn2cmp(id, sess_id->id, len, (size_t) node->data);
[4244] 
[4245]         if (rc == 0) {
[4246] 
[4247]             ngx_queue_remove(&sess_id->queue);
[4248] 
[4249]             ngx_rbtree_delete(&cache->session_rbtree, node);
[4250] 
[4251]             ngx_explicit_memzero(sess_id->session, sess_id->len);
[4252] 
[4253] #if (NGX_PTR_SIZE == 8)
[4254]             ngx_slab_free_locked(shpool, sess_id->session);
[4255] #endif
[4256]             ngx_slab_free_locked(shpool, sess_id);
[4257] 
[4258]             goto done;
[4259]         }
[4260] 
[4261]         node = (rc < 0) ? node->left : node->right;
[4262]     }
[4263] 
[4264] done:
[4265] 
[4266]     ngx_shmtx_unlock(&shpool->mutex);
[4267] }
[4268] 
[4269] 
[4270] static void
[4271] ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
[4272]     ngx_slab_pool_t *shpool, ngx_uint_t n)
[4273] {
[4274]     time_t              now;
[4275]     ngx_queue_t        *q;
[4276]     ngx_ssl_sess_id_t  *sess_id;
[4277] 
[4278]     now = ngx_time();
[4279] 
[4280]     while (n < 3) {
[4281] 
[4282]         if (ngx_queue_empty(&cache->expire_queue)) {
[4283]             return;
[4284]         }
[4285] 
[4286]         q = ngx_queue_last(&cache->expire_queue);
[4287] 
[4288]         sess_id = ngx_queue_data(q, ngx_ssl_sess_id_t, queue);
[4289] 
[4290]         if (n++ != 0 && sess_id->expire > now) {
[4291]             return;
[4292]         }
[4293] 
[4294]         ngx_queue_remove(q);
[4295] 
[4296]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
[4297]                        "expire session: %08Xi", sess_id->node.key);
[4298] 
[4299]         ngx_rbtree_delete(&cache->session_rbtree, &sess_id->node);
[4300] 
[4301]         ngx_explicit_memzero(sess_id->session, sess_id->len);
[4302] 
[4303] #if (NGX_PTR_SIZE == 8)
[4304]         ngx_slab_free_locked(shpool, sess_id->session);
[4305] #endif
[4306]         ngx_slab_free_locked(shpool, sess_id);
[4307]     }
[4308] }
[4309] 
[4310] 
[4311] static void
[4312] ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
[4313]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[4314] {
[4315]     ngx_rbtree_node_t  **p;
[4316]     ngx_ssl_sess_id_t   *sess_id, *sess_id_temp;
[4317] 
[4318]     for ( ;; ) {
[4319] 
[4320]         if (node->key < temp->key) {
[4321] 
[4322]             p = &temp->left;
[4323] 
[4324]         } else if (node->key > temp->key) {
[4325] 
[4326]             p = &temp->right;
[4327] 
[4328]         } else { /* node->key == temp->key */
[4329] 
[4330]             sess_id = (ngx_ssl_sess_id_t *) node;
[4331]             sess_id_temp = (ngx_ssl_sess_id_t *) temp;
[4332] 
[4333]             p = (ngx_memn2cmp(sess_id->id, sess_id_temp->id,
[4334]                               (size_t) node->data, (size_t) temp->data)
[4335]                  < 0) ? &temp->left : &temp->right;
[4336]         }
[4337] 
[4338]         if (*p == sentinel) {
[4339]             break;
[4340]         }
[4341] 
[4342]         temp = *p;
[4343]     }
[4344] 
[4345]     *p = node;
[4346]     node->parent = temp;
[4347]     node->left = sentinel;
[4348]     node->right = sentinel;
[4349]     ngx_rbt_red(node);
[4350] }
[4351] 
[4352] 
[4353] #ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB
[4354] 
[4355] ngx_int_t
[4356] ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
[4357] {
[4358]     u_char                 buf[80];
[4359]     size_t                 size;
[4360]     ssize_t                n;
[4361]     ngx_str_t             *path;
[4362]     ngx_file_t             file;
[4363]     ngx_uint_t             i;
[4364]     ngx_array_t           *keys;
[4365]     ngx_file_info_t        fi;
[4366]     ngx_pool_cleanup_t    *cln;
[4367]     ngx_ssl_ticket_key_t  *key;
[4368] 
[4369]     if (paths == NULL
[4370]         && SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_session_cache_index) == NULL)
[4371]     {
[4372]         return NGX_OK;
[4373]     }
[4374] 
[4375]     keys = ngx_array_create(cf->pool, paths ? paths->nelts : 3,
[4376]                             sizeof(ngx_ssl_ticket_key_t));
[4377]     if (keys == NULL) {
[4378]         return NGX_ERROR;
[4379]     }
[4380] 
[4381]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[4382]     if (cln == NULL) {
[4383]         return NGX_ERROR;
[4384]     }
[4385] 
[4386]     cln->handler = ngx_ssl_ticket_keys_cleanup;
[4387]     cln->data = keys;
[4388] 
[4389]     if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_ticket_keys_index, keys) == 0) {
[4390]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[4391]                       "SSL_CTX_set_ex_data() failed");
[4392]         return NGX_ERROR;
[4393]     }
[4394] 
[4395]     if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx, ngx_ssl_ticket_key_callback)
[4396]         == 0)
[4397]     {
[4398]         ngx_log_error(NGX_LOG_WARN, cf->log, 0,
[4399]                       "nginx was built with Session Tickets support, however, "
[4400]                       "now it is linked dynamically to an OpenSSL library "
[4401]                       "which has no tlsext support, therefore Session Tickets "
[4402]                       "are not available");
[4403]         return NGX_OK;
[4404]     }
[4405] 
[4406]     if (paths == NULL) {
[4407] 
[4408]         /* placeholder for keys in shared memory */
[4409] 
[4410]         key = ngx_array_push_n(keys, 3);
[4411]         key[0].shared = 1;
[4412]         key[0].expire = 0;
[4413]         key[1].shared = 1;
[4414]         key[1].expire = 0;
[4415]         key[2].shared = 1;
[4416]         key[2].expire = 0;
[4417] 
[4418]         return NGX_OK;
[4419]     }
[4420] 
[4421]     path = paths->elts;
[4422]     for (i = 0; i < paths->nelts; i++) {
[4423] 
[4424]         if (ngx_conf_full_name(cf->cycle, &path[i], 1) != NGX_OK) {
[4425]             return NGX_ERROR;
[4426]         }
[4427] 
[4428]         ngx_memzero(&file, sizeof(ngx_file_t));
[4429]         file.name = path[i];
[4430]         file.log = cf->log;
[4431] 
[4432]         file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY,
[4433]                                 NGX_FILE_OPEN, 0);
[4434] 
[4435]         if (file.fd == NGX_INVALID_FILE) {
[4436]             ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[4437]                                ngx_open_file_n " \"%V\" failed", &file.name);
[4438]             return NGX_ERROR;
[4439]         }
[4440] 
[4441]         if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
[4442]             ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[4443]                                ngx_fd_info_n " \"%V\" failed", &file.name);
[4444]             goto failed;
[4445]         }
[4446] 
[4447]         size = ngx_file_size(&fi);
[4448] 
[4449]         if (size != 48 && size != 80) {
[4450]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[4451]                                "\"%V\" must be 48 or 80 bytes", &file.name);
[4452]             goto failed;
[4453]         }
[4454] 
[4455]         n = ngx_read_file(&file, buf, size, 0);
[4456] 
[4457]         if (n == NGX_ERROR) {
[4458]             ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[4459]                                ngx_read_file_n " \"%V\" failed", &file.name);
[4460]             goto failed;
[4461]         }
[4462] 
[4463]         if ((size_t) n != size) {
[4464]             ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
[4465]                                ngx_read_file_n " \"%V\" returned only "
[4466]                                "%z bytes instead of %uz", &file.name, n, size);
[4467]             goto failed;
[4468]         }
[4469] 
[4470]         key = ngx_array_push(keys);
[4471]         if (key == NULL) {
[4472]             goto failed;
[4473]         }
[4474] 
[4475]         key->shared = 0;
[4476]         key->expire = 1;
[4477] 
[4478]         if (size == 48) {
[4479]             key->size = 48;
[4480]             ngx_memcpy(key->name, buf, 16);
[4481]             ngx_memcpy(key->aes_key, buf + 16, 16);
[4482]             ngx_memcpy(key->hmac_key, buf + 32, 16);
[4483] 
[4484]         } else {
[4485]             key->size = 80;
[4486]             ngx_memcpy(key->name, buf, 16);
[4487]             ngx_memcpy(key->hmac_key, buf + 16, 32);
[4488]             ngx_memcpy(key->aes_key, buf + 48, 32);
[4489]         }
[4490] 
[4491]         if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[4492]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[4493]                           ngx_close_file_n " \"%V\" failed", &file.name);
[4494]         }
[4495] 
[4496]         ngx_explicit_memzero(&buf, 80);
[4497]     }
[4498] 
[4499]     return NGX_OK;
[4500] 
[4501] failed:
[4502] 
[4503]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[4504]         ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[4505]                       ngx_close_file_n " \"%V\" failed", &file.name);
[4506]     }
[4507] 
[4508]     ngx_explicit_memzero(&buf, 80);
[4509] 
[4510]     return NGX_ERROR;
[4511] }
[4512] 
[4513] 
[4514] static int
[4515] ngx_ssl_ticket_key_callback(ngx_ssl_conn_t *ssl_conn,
[4516]     unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
[4517]     HMAC_CTX *hctx, int enc)
[4518] {
[4519]     size_t                 size;
[4520]     SSL_CTX               *ssl_ctx;
[4521]     ngx_uint_t             i;
[4522]     ngx_array_t           *keys;
[4523]     ngx_connection_t      *c;
[4524]     ngx_ssl_ticket_key_t  *key;
[4525]     const EVP_MD          *digest;
[4526]     const EVP_CIPHER      *cipher;
[4527] 
[4528]     c = ngx_ssl_get_connection(ssl_conn);
[4529]     ssl_ctx = c->ssl->session_ctx;
[4530] 
[4531]     if (ngx_ssl_rotate_ticket_keys(ssl_ctx, c->log) != NGX_OK) {
[4532]         return -1;
[4533]     }
[4534] 
[4535] #ifdef OPENSSL_NO_SHA256
[4536]     digest = EVP_sha1();
[4537] #else
[4538]     digest = EVP_sha256();
[4539] #endif
[4540] 
[4541]     keys = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index);
[4542]     if (keys == NULL) {
[4543]         return -1;
[4544]     }
[4545] 
[4546]     key = keys->elts;
[4547] 
[4548]     if (enc == 1) {
[4549]         /* encrypt session ticket */
[4550] 
[4551]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4552]                        "ssl ticket encrypt, key: \"%*xs\" (%s session)",
[4553]                        (size_t) 16, key[0].name,
[4554]                        SSL_session_reused(ssl_conn) ? "reused" : "new");
[4555] 
[4556]         if (key[0].size == 48) {
[4557]             cipher = EVP_aes_128_cbc();
[4558]             size = 16;
[4559] 
[4560]         } else {
[4561]             cipher = EVP_aes_256_cbc();
[4562]             size = 32;
[4563]         }
[4564] 
[4565]         if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
[4566]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "RAND_bytes() failed");
[4567]             return -1;
[4568]         }
[4569] 
[4570]         if (EVP_EncryptInit_ex(ectx, cipher, NULL, key[0].aes_key, iv) != 1) {
[4571]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
[4572]                           "EVP_EncryptInit_ex() failed");
[4573]             return -1;
[4574]         }
[4575] 
[4576] #if OPENSSL_VERSION_NUMBER >= 0x10000000L
[4577]         if (HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL) != 1) {
[4578]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
[4579]             return -1;
[4580]         }
[4581] #else
[4582]         HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL);
[4583] #endif
[4584] 
[4585]         ngx_memcpy(name, key[0].name, 16);
[4586] 
[4587]         return 1;
[4588] 
[4589]     } else {
[4590]         /* decrypt session ticket */
[4591] 
[4592]         for (i = 0; i < keys->nelts; i++) {
[4593]             if (ngx_memcmp(name, key[i].name, 16) == 0) {
[4594]                 goto found;
[4595]             }
[4596]         }
[4597] 
[4598]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4599]                        "ssl ticket decrypt, key: \"%*xs\" not found",
[4600]                        (size_t) 16, name);
[4601] 
[4602]         return 0;
[4603] 
[4604]     found:
[4605] 
[4606]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4607]                        "ssl ticket decrypt, key: \"%*xs\"%s",
[4608]                        (size_t) 16, key[i].name, (i == 0) ? " (default)" : "");
[4609] 
[4610]         if (key[i].size == 48) {
[4611]             cipher = EVP_aes_128_cbc();
[4612]             size = 16;
[4613] 
[4614]         } else {
[4615]             cipher = EVP_aes_256_cbc();
[4616]             size = 32;
[4617]         }
[4618] 
[4619] #if OPENSSL_VERSION_NUMBER >= 0x10000000L
[4620]         if (HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL) != 1) {
[4621]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
[4622]             return -1;
[4623]         }
[4624] #else
[4625]         HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL);
[4626] #endif
[4627] 
[4628]         if (EVP_DecryptInit_ex(ectx, cipher, NULL, key[i].aes_key, iv) != 1) {
[4629]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0,
[4630]                           "EVP_DecryptInit_ex() failed");
[4631]             return -1;
[4632]         }
[4633] 
[4634]         /* renew if TLSv1.3 */
[4635] 
[4636] #ifdef TLS1_3_VERSION
[4637]         if (SSL_version(ssl_conn) == TLS1_3_VERSION) {
[4638]             return 2;
[4639]         }
[4640] #endif
[4641] 
[4642]         /* renew if non-default key */
[4643] 
[4644]         if (i != 0 && key[i].expire) {
[4645]             return 2;
[4646]         }
[4647] 
[4648]         return 1;
[4649]     }
[4650] }
[4651] 
[4652] 
[4653] static ngx_int_t
[4654] ngx_ssl_rotate_ticket_keys(SSL_CTX *ssl_ctx, ngx_log_t *log)
[4655] {
[4656]     time_t                    now, expire;
[4657]     ngx_array_t              *keys;
[4658]     ngx_shm_zone_t           *shm_zone;
[4659]     ngx_slab_pool_t          *shpool;
[4660]     ngx_ssl_ticket_key_t     *key;
[4661]     ngx_ssl_session_cache_t  *cache;
[4662]     u_char                    buf[80];
[4663] 
[4664]     keys = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index);
[4665]     if (keys == NULL) {
[4666]         return NGX_OK;
[4667]     }
[4668] 
[4669]     key = keys->elts;
[4670] 
[4671]     if (!key[0].shared) {
[4672]         return NGX_OK;
[4673]     }
[4674] 
[4675]     /*
[4676]      * if we don't need to update expiration of the current key
[4677]      * and the previous key is still needed, don't sync with shared
[4678]      * memory to save some work; in the worst case other worker process
[4679]      * will switch to the next key, but this process will still be able
[4680]      * to decrypt tickets encrypted with it
[4681]      */
[4682] 
[4683]     now = ngx_time();
[4684]     expire = now + SSL_CTX_get_timeout(ssl_ctx);
[4685] 
[4686]     if (key[0].expire >= expire && key[1].expire >= now) {
[4687]         return NGX_OK;
[4688]     }
[4689] 
[4690]     shm_zone = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index);
[4691] 
[4692]     cache = shm_zone->data;
[4693]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[4694] 
[4695]     ngx_shmtx_lock(&shpool->mutex);
[4696] 
[4697]     key = cache->ticket_keys;
[4698] 
[4699]     if (key[0].expire == 0) {
[4700] 
[4701]         /* initialize the current key */
[4702] 
[4703]         if (RAND_bytes(buf, 80) != 1) {
[4704]             ngx_ssl_error(NGX_LOG_ALERT, log, 0, "RAND_bytes() failed");
[4705]             ngx_shmtx_unlock(&shpool->mutex);
[4706]             return NGX_ERROR;
[4707]         }
[4708] 
[4709]         key[0].shared = 1;
[4710]         key[0].expire = expire;
[4711]         key[0].size = 80;
[4712]         ngx_memcpy(key[0].name, buf, 16);
[4713]         ngx_memcpy(key[0].hmac_key, buf + 16, 32);
[4714]         ngx_memcpy(key[0].aes_key, buf + 48, 32);
[4715] 
[4716]         ngx_explicit_memzero(&buf, 80);
[4717] 
[4718]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
[4719]                        "ssl ticket key: \"%*xs\"",
[4720]                        (size_t) 16, key[0].name);
[4721] 
[4722]         /*
[4723]          * copy the current key to the next key, as initialization of
[4724]          * the previous key will replace the current key with the next
[4725]          * key
[4726]          */
[4727] 
[4728]         key[2] = key[0];
[4729]     }
[4730] 
[4731]     if (key[1].expire < now) {
[4732] 
[4733]         /*
[4734]          * if the previous key is no longer needed (or not initialized),
[4735]          * replace it with the current key, replace the current key with
[4736]          * the next key, and generate new next key
[4737]          */
[4738] 
[4739]         key[1] = key[0];
[4740]         key[0] = key[2];
[4741] 
[4742]         if (RAND_bytes(buf, 80) != 1) {
[4743]             ngx_ssl_error(NGX_LOG_ALERT, log, 0, "RAND_bytes() failed");
[4744]             ngx_shmtx_unlock(&shpool->mutex);
[4745]             return NGX_ERROR;
[4746]         }
[4747] 
[4748]         key[2].shared = 1;
[4749]         key[2].expire = 0;
[4750]         key[2].size = 80;
[4751]         ngx_memcpy(key[2].name, buf, 16);
[4752]         ngx_memcpy(key[2].hmac_key, buf + 16, 32);
[4753]         ngx_memcpy(key[2].aes_key, buf + 48, 32);
[4754] 
[4755]         ngx_explicit_memzero(&buf, 80);
[4756] 
[4757]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0,
[4758]                        "ssl ticket key: \"%*xs\"",
[4759]                        (size_t) 16, key[2].name);
[4760]     }
[4761] 
[4762]     /*
[4763]      * update expiration of the current key: it is going to be needed
[4764]      * at least till the session being created expires
[4765]      */
[4766] 
[4767]     if (expire > key[0].expire) {
[4768]         key[0].expire = expire;
[4769]     }
[4770] 
[4771]     /* sync keys to the worker process memory */
[4772] 
[4773]     ngx_memcpy(keys->elts, cache->ticket_keys,
[4774]                2 * sizeof(ngx_ssl_ticket_key_t));
[4775] 
[4776]     ngx_shmtx_unlock(&shpool->mutex);
[4777] 
[4778]     return NGX_OK;
[4779] }
[4780] 
[4781] 
[4782] static void
[4783] ngx_ssl_ticket_keys_cleanup(void *data)
[4784] {
[4785]     ngx_array_t  *keys = data;
[4786] 
[4787]     ngx_explicit_memzero(keys->elts,
[4788]                          keys->nelts * sizeof(ngx_ssl_ticket_key_t));
[4789] }
[4790] 
[4791] #else
[4792] 
[4793] ngx_int_t
[4794] ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
[4795] {
[4796]     if (paths) {
[4797]         ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[4798]                       "\"ssl_session_ticket_key\" ignored, not supported");
[4799]     }
[4800] 
[4801]     return NGX_OK;
[4802] }
[4803] 
[4804] #endif
[4805] 
[4806] 
[4807] void
[4808] ngx_ssl_cleanup_ctx(void *data)
[4809] {
[4810]     ngx_ssl_t  *ssl = data;
[4811] 
[4812]     X509  *cert, *next;
[4813] 
[4814]     cert = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index);
[4815] 
[4816]     while (cert) {
[4817]         next = X509_get_ex_data(cert, ngx_ssl_next_certificate_index);
[4818]         X509_free(cert);
[4819]         cert = next;
[4820]     }
[4821] 
[4822]     SSL_CTX_free(ssl->ctx);
[4823] }
[4824] 
[4825] 
[4826] ngx_int_t
[4827] ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name)
[4828] {
[4829]     X509   *cert;
[4830] 
[4831]     cert = SSL_get_peer_certificate(c->ssl->connection);
[4832]     if (cert == NULL) {
[4833]         return NGX_ERROR;
[4834]     }
[4835] 
[4836] #ifdef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
[4837] 
[4838]     /* X509_check_host() is only available in OpenSSL 1.0.2+ */
[4839] 
[4840]     if (name->len == 0) {
[4841]         goto failed;
[4842]     }
[4843] 
[4844]     if (X509_check_host(cert, (char *) name->data, name->len, 0, NULL) != 1) {
[4845]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4846]                        "X509_check_host(): no match");
[4847]         goto failed;
[4848]     }
[4849] 
[4850]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4851]                    "X509_check_host(): match");
[4852] 
[4853]     goto found;
[4854] 
[4855] #else
[4856]     {
[4857]     int                      n, i;
[4858]     X509_NAME               *sname;
[4859]     ASN1_STRING             *str;
[4860]     X509_NAME_ENTRY         *entry;
[4861]     GENERAL_NAME            *altname;
[4862]     STACK_OF(GENERAL_NAME)  *altnames;
[4863] 
[4864]     /*
[4865]      * As per RFC6125 and RFC2818, we check subjectAltName extension,
[4866]      * and if it's not present - commonName in Subject is checked.
[4867]      */
[4868] 
[4869]     altnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
[4870] 
[4871]     if (altnames) {
[4872]         n = sk_GENERAL_NAME_num(altnames);
[4873] 
[4874]         for (i = 0; i < n; i++) {
[4875]             altname = sk_GENERAL_NAME_value(altnames, i);
[4876] 
[4877]             if (altname->type != GEN_DNS) {
[4878]                 continue;
[4879]             }
[4880] 
[4881]             str = altname->d.dNSName;
[4882] 
[4883]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4884]                            "SSL subjectAltName: \"%*s\"",
[4885]                            ASN1_STRING_length(str), ASN1_STRING_data(str));
[4886] 
[4887]             if (ngx_ssl_check_name(name, str) == NGX_OK) {
[4888]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4889]                                "SSL subjectAltName: match");
[4890]                 GENERAL_NAMES_free(altnames);
[4891]                 goto found;
[4892]             }
[4893]         }
[4894] 
[4895]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4896]                        "SSL subjectAltName: no match");
[4897] 
[4898]         GENERAL_NAMES_free(altnames);
[4899]         goto failed;
[4900]     }
[4901] 
[4902]     /*
[4903]      * If there is no subjectAltName extension, check commonName
[4904]      * in Subject.  While RFC2818 requires to only check "most specific"
[4905]      * CN, both Apache and OpenSSL check all CNs, and so do we.
[4906]      */
[4907] 
[4908]     sname = X509_get_subject_name(cert);
[4909] 
[4910]     if (sname == NULL) {
[4911]         goto failed;
[4912]     }
[4913] 
[4914]     i = -1;
[4915]     for ( ;; ) {
[4916]         i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);
[4917] 
[4918]         if (i < 0) {
[4919]             break;
[4920]         }
[4921] 
[4922]         entry = X509_NAME_get_entry(sname, i);
[4923]         str = X509_NAME_ENTRY_get_data(entry);
[4924] 
[4925]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4926]                        "SSL commonName: \"%*s\"",
[4927]                        ASN1_STRING_length(str), ASN1_STRING_data(str));
[4928] 
[4929]         if (ngx_ssl_check_name(name, str) == NGX_OK) {
[4930]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4931]                            "SSL commonName: match");
[4932]             goto found;
[4933]         }
[4934]     }
[4935] 
[4936]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[4937]                    "SSL commonName: no match");
[4938]     }
[4939] #endif
[4940] 
[4941] failed:
[4942] 
[4943]     X509_free(cert);
[4944]     return NGX_ERROR;
[4945] 
[4946] found:
[4947] 
[4948]     X509_free(cert);
[4949]     return NGX_OK;
[4950] }
[4951] 
[4952] 
[4953] #ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
[4954] 
[4955] static ngx_int_t
[4956] ngx_ssl_check_name(ngx_str_t *name, ASN1_STRING *pattern)
[4957] {
[4958]     u_char  *s, *p, *end;
[4959]     size_t   slen, plen;
[4960] 
[4961]     s = name->data;
[4962]     slen = name->len;
[4963] 
[4964]     p = ASN1_STRING_data(pattern);
[4965]     plen = ASN1_STRING_length(pattern);
[4966] 
[4967]     if (slen == plen && ngx_strncasecmp(s, p, plen) == 0) {
[4968]         return NGX_OK;
[4969]     }
[4970] 
[4971]     if (plen > 2 && p[0] == '*' && p[1] == '.') {
[4972]         plen -= 1;
[4973]         p += 1;
[4974] 
[4975]         end = s + slen;
[4976]         s = ngx_strlchr(s, end, '.');
[4977] 
[4978]         if (s == NULL) {
[4979]             return NGX_ERROR;
[4980]         }
[4981] 
[4982]         slen = end - s;
[4983] 
[4984]         if (plen == slen && ngx_strncasecmp(s, p, plen) == 0) {
[4985]             return NGX_OK;
[4986]         }
[4987]     }
[4988] 
[4989]     return NGX_ERROR;
[4990] }
[4991] 
[4992] #endif
[4993] 
[4994] 
[4995] ngx_int_t
[4996] ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[4997] {
[4998]     s->data = (u_char *) SSL_get_version(c->ssl->connection);
[4999]     return NGX_OK;
[5000] }
[5001] 
[5002] 
[5003] ngx_int_t
[5004] ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5005] {
[5006]     s->data = (u_char *) SSL_get_cipher_name(c->ssl->connection);
[5007]     return NGX_OK;
[5008] }
[5009] 
[5010] 
[5011] ngx_int_t
[5012] ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5013] {
[5014] #ifdef SSL_CTRL_GET_RAW_CIPHERLIST
[5015] 
[5016]     int                n, i, bytes;
[5017]     size_t             len;
[5018]     u_char            *ciphers, *p;
[5019]     const SSL_CIPHER  *cipher;
[5020] 
[5021]     bytes = SSL_get0_raw_cipherlist(c->ssl->connection, NULL);
[5022]     n = SSL_get0_raw_cipherlist(c->ssl->connection, &ciphers);
[5023] 
[5024]     if (n <= 0) {
[5025]         s->len = 0;
[5026]         return NGX_OK;
[5027]     }
[5028] 
[5029]     len = 0;
[5030]     n /= bytes;
[5031] 
[5032]     for (i = 0; i < n; i++) {
[5033]         cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);
[5034] 
[5035]         if (cipher) {
[5036]             len += ngx_strlen(SSL_CIPHER_get_name(cipher));
[5037] 
[5038]         } else {
[5039]             len += sizeof("0x") - 1 + bytes * (sizeof("00") - 1);
[5040]         }
[5041] 
[5042]         len += sizeof(":") - 1;
[5043]     }
[5044] 
[5045]     s->data = ngx_pnalloc(pool, len);
[5046]     if (s->data == NULL) {
[5047]         return NGX_ERROR;
[5048]     }
[5049] 
[5050]     p = s->data;
[5051] 
[5052]     for (i = 0; i < n; i++) {
[5053]         cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);
[5054] 
[5055]         if (cipher) {
[5056]             p = ngx_sprintf(p, "%s", SSL_CIPHER_get_name(cipher));
[5057] 
[5058]         } else {
[5059]             p = ngx_sprintf(p, "0x");
[5060]             p = ngx_hex_dump(p, ciphers + i * bytes, bytes);
[5061]         }
[5062] 
[5063]         *p++ = ':';
[5064]     }
[5065] 
[5066]     p--;
[5067] 
[5068]     s->len = p - s->data;
[5069] 
[5070] #else
[5071] 
[5072]     u_char  buf[4096];
[5073] 
[5074]     if (SSL_get_shared_ciphers(c->ssl->connection, (char *) buf, 4096)
[5075]         == NULL)
[5076]     {
[5077]         s->len = 0;
[5078]         return NGX_OK;
[5079]     }
[5080] 
[5081]     s->len = ngx_strlen(buf);
[5082]     s->data = ngx_pnalloc(pool, s->len);
[5083]     if (s->data == NULL) {
[5084]         return NGX_ERROR;
[5085]     }
[5086] 
[5087]     ngx_memcpy(s->data, buf, s->len);
[5088] 
[5089] #endif
[5090] 
[5091]     return NGX_OK;
[5092] }
[5093] 
[5094] 
[5095] ngx_int_t
[5096] ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5097] {
[5098] #ifdef SSL_get_negotiated_group
[5099] 
[5100]     int  nid;
[5101] 
[5102]     nid = SSL_get_negotiated_group(c->ssl->connection);
[5103] 
[5104]     if (nid != NID_undef) {
[5105] 
[5106]         if ((nid & TLSEXT_nid_unknown) == 0) {
[5107]             s->len = ngx_strlen(OBJ_nid2sn(nid));
[5108]             s->data = (u_char *) OBJ_nid2sn(nid);
[5109]             return NGX_OK;
[5110]         }
[5111] 
[5112]         s->len = sizeof("0x0000") - 1;
[5113] 
[5114]         s->data = ngx_pnalloc(pool, s->len);
[5115]         if (s->data == NULL) {
[5116]             return NGX_ERROR;
[5117]         }
[5118] 
[5119]         ngx_sprintf(s->data, "0x%04xd", nid & 0xffff);
[5120] 
[5121]         return NGX_OK;
[5122]     }
[5123] 
[5124] #endif
[5125] 
[5126]     s->len = 0;
[5127]     return NGX_OK;
[5128] }
[5129] 
[5130] 
[5131] ngx_int_t
[5132] ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5133] {
[5134] #ifdef SSL_CTRL_GET_CURVES
[5135] 
[5136]     int         *curves, n, i, nid;
[5137]     u_char      *p;
[5138]     size_t       len;
[5139] 
[5140]     n = SSL_get1_curves(c->ssl->connection, NULL);
[5141] 
[5142]     if (n <= 0) {
[5143]         s->len = 0;
[5144]         return NGX_OK;
[5145]     }
[5146] 
[5147]     curves = ngx_palloc(pool, n * sizeof(int));
[5148] 
[5149]     n = SSL_get1_curves(c->ssl->connection, curves);
[5150]     len = 0;
[5151] 
[5152]     for (i = 0; i < n; i++) {
[5153]         nid = curves[i];
[5154] 
[5155]         if (nid & TLSEXT_nid_unknown) {
[5156]             len += sizeof("0x0000") - 1;
[5157] 
[5158]         } else {
[5159]             len += ngx_strlen(OBJ_nid2sn(nid));
[5160]         }
[5161] 
[5162]         len += sizeof(":") - 1;
[5163]     }
[5164] 
[5165]     s->data = ngx_pnalloc(pool, len);
[5166]     if (s->data == NULL) {
[5167]         return NGX_ERROR;
[5168]     }
[5169] 
[5170]     p = s->data;
[5171] 
[5172]     for (i = 0; i < n; i++) {
[5173]         nid = curves[i];
[5174] 
[5175]         if (nid & TLSEXT_nid_unknown) {
[5176]             p = ngx_sprintf(p, "0x%04xd", nid & 0xffff);
[5177] 
[5178]         } else {
[5179]             p = ngx_sprintf(p, "%s", OBJ_nid2sn(nid));
[5180]         }
[5181] 
[5182]         *p++ = ':';
[5183]     }
[5184] 
[5185]     p--;
[5186] 
[5187]     s->len = p - s->data;
[5188] 
[5189] #else
[5190] 
[5191]     s->len = 0;
[5192] 
[5193] #endif
[5194] 
[5195]     return NGX_OK;
[5196] }
[5197] 
[5198] 
[5199] ngx_int_t
[5200] ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5201] {
[5202]     u_char        *buf;
[5203]     SSL_SESSION   *sess;
[5204]     unsigned int   len;
[5205] 
[5206]     sess = SSL_get0_session(c->ssl->connection);
[5207]     if (sess == NULL) {
[5208]         s->len = 0;
[5209]         return NGX_OK;
[5210]     }
[5211] 
[5212]     buf = (u_char *) SSL_SESSION_get_id(sess, &len);
[5213] 
[5214]     s->len = 2 * len;
[5215]     s->data = ngx_pnalloc(pool, 2 * len);
[5216]     if (s->data == NULL) {
[5217]         return NGX_ERROR;
[5218]     }
[5219] 
[5220]     ngx_hex_dump(s->data, buf, len);
[5221] 
[5222]     return NGX_OK;
[5223] }
[5224] 
[5225] 
[5226] ngx_int_t
[5227] ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5228] {
[5229]     if (SSL_session_reused(c->ssl->connection)) {
[5230]         ngx_str_set(s, "r");
[5231] 
[5232]     } else {
[5233]         ngx_str_set(s, ".");
[5234]     }
[5235] 
[5236]     return NGX_OK;
[5237] }
[5238] 
[5239] 
[5240] ngx_int_t
[5241] ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5242] {
[5243]     s->len = 0;
[5244] 
[5245] #ifdef SSL_ERROR_EARLY_DATA_REJECTED
[5246] 
[5247]     /* BoringSSL */
[5248] 
[5249]     if (SSL_in_early_data(c->ssl->connection)) {
[5250]         ngx_str_set(s, "1");
[5251]     }
[5252] 
[5253] #elif defined SSL_READ_EARLY_DATA_SUCCESS
[5254] 
[5255]     /* OpenSSL */
[5256] 
[5257]     if (!SSL_is_init_finished(c->ssl->connection)) {
[5258]         ngx_str_set(s, "1");
[5259]     }
[5260] 
[5261] #endif
[5262] 
[5263]     return NGX_OK;
[5264] }
[5265] 
[5266] 
[5267] ngx_int_t
[5268] ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5269] {
[5270] #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
[5271] 
[5272]     size_t       len;
[5273]     const char  *name;
[5274] 
[5275]     name = SSL_get_servername(c->ssl->connection, TLSEXT_NAMETYPE_host_name);
[5276] 
[5277]     if (name) {
[5278]         len = ngx_strlen(name);
[5279] 
[5280]         s->len = len;
[5281]         s->data = ngx_pnalloc(pool, len);
[5282]         if (s->data == NULL) {
[5283]             return NGX_ERROR;
[5284]         }
[5285] 
[5286]         ngx_memcpy(s->data, name, len);
[5287] 
[5288]         return NGX_OK;
[5289]     }
[5290] 
[5291] #endif
[5292] 
[5293]     s->len = 0;
[5294]     return NGX_OK;
[5295] }
[5296] 
[5297] 
[5298] ngx_int_t
[5299] ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5300] {
[5301] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[5302] 
[5303]     unsigned int          len;
[5304]     const unsigned char  *data;
[5305] 
[5306]     SSL_get0_alpn_selected(c->ssl->connection, &data, &len);
[5307] 
[5308]     if (len > 0) {
[5309] 
[5310]         s->data = ngx_pnalloc(pool, len);
[5311]         if (s->data == NULL) {
[5312]             return NGX_ERROR;
[5313]         }
[5314] 
[5315]         ngx_memcpy(s->data, data, len);
[5316]         s->len = len;
[5317] 
[5318]         return NGX_OK;
[5319]     }
[5320] 
[5321] #endif
[5322] 
[5323]     s->len = 0;
[5324]     return NGX_OK;
[5325] }
[5326] 
[5327] 
[5328] ngx_int_t
[5329] ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5330] {
[5331]     size_t   len;
[5332]     BIO     *bio;
[5333]     X509    *cert;
[5334] 
[5335]     s->len = 0;
[5336] 
[5337]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5338]     if (cert == NULL) {
[5339]         return NGX_OK;
[5340]     }
[5341] 
[5342]     bio = BIO_new(BIO_s_mem());
[5343]     if (bio == NULL) {
[5344]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
[5345]         X509_free(cert);
[5346]         return NGX_ERROR;
[5347]     }
[5348] 
[5349]     if (PEM_write_bio_X509(bio, cert) == 0) {
[5350]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");
[5351]         goto failed;
[5352]     }
[5353] 
[5354]     len = BIO_pending(bio);
[5355]     s->len = len;
[5356] 
[5357]     s->data = ngx_pnalloc(pool, len);
[5358]     if (s->data == NULL) {
[5359]         goto failed;
[5360]     }
[5361] 
[5362]     BIO_read(bio, s->data, len);
[5363] 
[5364]     BIO_free(bio);
[5365]     X509_free(cert);
[5366] 
[5367]     return NGX_OK;
[5368] 
[5369] failed:
[5370] 
[5371]     BIO_free(bio);
[5372]     X509_free(cert);
[5373] 
[5374]     return NGX_ERROR;
[5375] }
[5376] 
[5377] 
[5378] ngx_int_t
[5379] ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5380] {
[5381]     u_char      *p;
[5382]     size_t       len;
[5383]     ngx_uint_t   i;
[5384]     ngx_str_t    cert;
[5385] 
[5386]     if (ngx_ssl_get_raw_certificate(c, pool, &cert) != NGX_OK) {
[5387]         return NGX_ERROR;
[5388]     }
[5389] 
[5390]     if (cert.len == 0) {
[5391]         s->len = 0;
[5392]         return NGX_OK;
[5393]     }
[5394] 
[5395]     len = cert.len - 1;
[5396] 
[5397]     for (i = 0; i < cert.len - 1; i++) {
[5398]         if (cert.data[i] == LF) {
[5399]             len++;
[5400]         }
[5401]     }
[5402] 
[5403]     s->len = len;
[5404]     s->data = ngx_pnalloc(pool, len);
[5405]     if (s->data == NULL) {
[5406]         return NGX_ERROR;
[5407]     }
[5408] 
[5409]     p = s->data;
[5410] 
[5411]     for (i = 0; i < cert.len - 1; i++) {
[5412]         *p++ = cert.data[i];
[5413]         if (cert.data[i] == LF) {
[5414]             *p++ = '\t';
[5415]         }
[5416]     }
[5417] 
[5418]     return NGX_OK;
[5419] }
[5420] 
[5421] 
[5422] ngx_int_t
[5423] ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool,
[5424]     ngx_str_t *s)
[5425] {
[5426]     ngx_str_t  cert;
[5427]     uintptr_t  n;
[5428] 
[5429]     if (ngx_ssl_get_raw_certificate(c, pool, &cert) != NGX_OK) {
[5430]         return NGX_ERROR;
[5431]     }
[5432] 
[5433]     if (cert.len == 0) {
[5434]         s->len = 0;
[5435]         return NGX_OK;
[5436]     }
[5437] 
[5438]     n = ngx_escape_uri(NULL, cert.data, cert.len, NGX_ESCAPE_URI_COMPONENT);
[5439] 
[5440]     s->len = cert.len + n * 2;
[5441]     s->data = ngx_pnalloc(pool, s->len);
[5442]     if (s->data == NULL) {
[5443]         return NGX_ERROR;
[5444]     }
[5445] 
[5446]     ngx_escape_uri(s->data, cert.data, cert.len, NGX_ESCAPE_URI_COMPONENT);
[5447] 
[5448]     return NGX_OK;
[5449] }
[5450] 
[5451] 
[5452] ngx_int_t
[5453] ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5454] {
[5455]     BIO        *bio;
[5456]     X509       *cert;
[5457]     X509_NAME  *name;
[5458] 
[5459]     s->len = 0;
[5460] 
[5461]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5462]     if (cert == NULL) {
[5463]         return NGX_OK;
[5464]     }
[5465] 
[5466]     name = X509_get_subject_name(cert);
[5467]     if (name == NULL) {
[5468]         X509_free(cert);
[5469]         return NGX_ERROR;
[5470]     }
[5471] 
[5472]     bio = BIO_new(BIO_s_mem());
[5473]     if (bio == NULL) {
[5474]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
[5475]         X509_free(cert);
[5476]         return NGX_ERROR;
[5477]     }
[5478] 
[5479]     if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
[5480]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_print_ex() failed");
[5481]         goto failed;
[5482]     }
[5483] 
[5484]     s->len = BIO_pending(bio);
[5485]     s->data = ngx_pnalloc(pool, s->len);
[5486]     if (s->data == NULL) {
[5487]         goto failed;
[5488]     }
[5489] 
[5490]     BIO_read(bio, s->data, s->len);
[5491] 
[5492]     BIO_free(bio);
[5493]     X509_free(cert);
[5494] 
[5495]     return NGX_OK;
[5496] 
[5497] failed:
[5498] 
[5499]     BIO_free(bio);
[5500]     X509_free(cert);
[5501] 
[5502]     return NGX_ERROR;
[5503] }
[5504] 
[5505] 
[5506] ngx_int_t
[5507] ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5508] {
[5509]     BIO        *bio;
[5510]     X509       *cert;
[5511]     X509_NAME  *name;
[5512] 
[5513]     s->len = 0;
[5514] 
[5515]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5516]     if (cert == NULL) {
[5517]         return NGX_OK;
[5518]     }
[5519] 
[5520]     name = X509_get_issuer_name(cert);
[5521]     if (name == NULL) {
[5522]         X509_free(cert);
[5523]         return NGX_ERROR;
[5524]     }
[5525] 
[5526]     bio = BIO_new(BIO_s_mem());
[5527]     if (bio == NULL) {
[5528]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
[5529]         X509_free(cert);
[5530]         return NGX_ERROR;
[5531]     }
[5532] 
[5533]     if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
[5534]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_print_ex() failed");
[5535]         goto failed;
[5536]     }
[5537] 
[5538]     s->len = BIO_pending(bio);
[5539]     s->data = ngx_pnalloc(pool, s->len);
[5540]     if (s->data == NULL) {
[5541]         goto failed;
[5542]     }
[5543] 
[5544]     BIO_read(bio, s->data, s->len);
[5545] 
[5546]     BIO_free(bio);
[5547]     X509_free(cert);
[5548] 
[5549]     return NGX_OK;
[5550] 
[5551] failed:
[5552] 
[5553]     BIO_free(bio);
[5554]     X509_free(cert);
[5555] 
[5556]     return NGX_ERROR;
[5557] }
[5558] 
[5559] 
[5560] ngx_int_t
[5561] ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
[5562]     ngx_str_t *s)
[5563] {
[5564]     char       *p;
[5565]     size_t      len;
[5566]     X509       *cert;
[5567]     X509_NAME  *name;
[5568] 
[5569]     s->len = 0;
[5570] 
[5571]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5572]     if (cert == NULL) {
[5573]         return NGX_OK;
[5574]     }
[5575] 
[5576]     name = X509_get_subject_name(cert);
[5577]     if (name == NULL) {
[5578]         X509_free(cert);
[5579]         return NGX_ERROR;
[5580]     }
[5581] 
[5582]     p = X509_NAME_oneline(name, NULL, 0);
[5583]     if (p == NULL) {
[5584]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_oneline() failed");
[5585]         X509_free(cert);
[5586]         return NGX_ERROR;
[5587]     }
[5588] 
[5589]     for (len = 0; p[len]; len++) { /* void */ }
[5590] 
[5591]     s->len = len;
[5592]     s->data = ngx_pnalloc(pool, len);
[5593]     if (s->data == NULL) {
[5594]         OPENSSL_free(p);
[5595]         X509_free(cert);
[5596]         return NGX_ERROR;
[5597]     }
[5598] 
[5599]     ngx_memcpy(s->data, p, len);
[5600] 
[5601]     OPENSSL_free(p);
[5602]     X509_free(cert);
[5603] 
[5604]     return NGX_OK;
[5605] }
[5606] 
[5607] 
[5608] ngx_int_t
[5609] ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
[5610]     ngx_str_t *s)
[5611] {
[5612]     char       *p;
[5613]     size_t      len;
[5614]     X509       *cert;
[5615]     X509_NAME  *name;
[5616] 
[5617]     s->len = 0;
[5618] 
[5619]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5620]     if (cert == NULL) {
[5621]         return NGX_OK;
[5622]     }
[5623] 
[5624]     name = X509_get_issuer_name(cert);
[5625]     if (name == NULL) {
[5626]         X509_free(cert);
[5627]         return NGX_ERROR;
[5628]     }
[5629] 
[5630]     p = X509_NAME_oneline(name, NULL, 0);
[5631]     if (p == NULL) {
[5632]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_NAME_oneline() failed");
[5633]         X509_free(cert);
[5634]         return NGX_ERROR;
[5635]     }
[5636] 
[5637]     for (len = 0; p[len]; len++) { /* void */ }
[5638] 
[5639]     s->len = len;
[5640]     s->data = ngx_pnalloc(pool, len);
[5641]     if (s->data == NULL) {
[5642]         OPENSSL_free(p);
[5643]         X509_free(cert);
[5644]         return NGX_ERROR;
[5645]     }
[5646] 
[5647]     ngx_memcpy(s->data, p, len);
[5648] 
[5649]     OPENSSL_free(p);
[5650]     X509_free(cert);
[5651] 
[5652]     return NGX_OK;
[5653] }
[5654] 
[5655] 
[5656] ngx_int_t
[5657] ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5658] {
[5659]     size_t   len;
[5660]     X509    *cert;
[5661]     BIO     *bio;
[5662] 
[5663]     s->len = 0;
[5664] 
[5665]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5666]     if (cert == NULL) {
[5667]         return NGX_OK;
[5668]     }
[5669] 
[5670]     bio = BIO_new(BIO_s_mem());
[5671]     if (bio == NULL) {
[5672]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
[5673]         X509_free(cert);
[5674]         return NGX_ERROR;
[5675]     }
[5676] 
[5677]     i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));
[5678]     len = BIO_pending(bio);
[5679] 
[5680]     s->len = len;
[5681]     s->data = ngx_pnalloc(pool, len);
[5682]     if (s->data == NULL) {
[5683]         BIO_free(bio);
[5684]         X509_free(cert);
[5685]         return NGX_ERROR;
[5686]     }
[5687] 
[5688]     BIO_read(bio, s->data, len);
[5689]     BIO_free(bio);
[5690]     X509_free(cert);
[5691] 
[5692]     return NGX_OK;
[5693] }
[5694] 
[5695] 
[5696] ngx_int_t
[5697] ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5698] {
[5699]     X509          *cert;
[5700]     unsigned int   len;
[5701]     u_char         buf[EVP_MAX_MD_SIZE];
[5702] 
[5703]     s->len = 0;
[5704] 
[5705]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5706]     if (cert == NULL) {
[5707]         return NGX_OK;
[5708]     }
[5709] 
[5710]     if (!X509_digest(cert, EVP_sha1(), buf, &len)) {
[5711]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "X509_digest() failed");
[5712]         X509_free(cert);
[5713]         return NGX_ERROR;
[5714]     }
[5715] 
[5716]     s->len = 2 * len;
[5717]     s->data = ngx_pnalloc(pool, 2 * len);
[5718]     if (s->data == NULL) {
[5719]         X509_free(cert);
[5720]         return NGX_ERROR;
[5721]     }
[5722] 
[5723]     ngx_hex_dump(s->data, buf, len);
[5724] 
[5725]     X509_free(cert);
[5726] 
[5727]     return NGX_OK;
[5728] }
[5729] 
[5730] 
[5731] ngx_int_t
[5732] ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5733] {
[5734]     X509        *cert;
[5735]     long         rc;
[5736]     const char  *str;
[5737] 
[5738]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5739]     if (cert == NULL) {
[5740]         ngx_str_set(s, "NONE");
[5741]         return NGX_OK;
[5742]     }
[5743] 
[5744]     X509_free(cert);
[5745] 
[5746]     rc = SSL_get_verify_result(c->ssl->connection);
[5747] 
[5748]     if (rc == X509_V_OK) {
[5749]         if (ngx_ssl_ocsp_get_status(c, &str) == NGX_OK) {
[5750]             ngx_str_set(s, "SUCCESS");
[5751]             return NGX_OK;
[5752]         }
[5753] 
[5754]     } else {
[5755]         str = X509_verify_cert_error_string(rc);
[5756]     }
[5757] 
[5758]     s->data = ngx_pnalloc(pool, sizeof("FAILED:") - 1 + ngx_strlen(str));
[5759]     if (s->data == NULL) {
[5760]         return NGX_ERROR;
[5761]     }
[5762] 
[5763]     s->len = ngx_sprintf(s->data, "FAILED:%s", str) - s->data;
[5764] 
[5765]     return NGX_OK;
[5766] }
[5767] 
[5768] 
[5769] ngx_int_t
[5770] ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5771] {
[5772]     BIO     *bio;
[5773]     X509    *cert;
[5774]     size_t   len;
[5775] 
[5776]     s->len = 0;
[5777] 
[5778]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5779]     if (cert == NULL) {
[5780]         return NGX_OK;
[5781]     }
[5782] 
[5783]     bio = BIO_new(BIO_s_mem());
[5784]     if (bio == NULL) {
[5785]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
[5786]         X509_free(cert);
[5787]         return NGX_ERROR;
[5788]     }
[5789] 
[5790] #if OPENSSL_VERSION_NUMBER > 0x10100000L
[5791]     ASN1_TIME_print(bio, X509_get0_notBefore(cert));
[5792] #else
[5793]     ASN1_TIME_print(bio, X509_get_notBefore(cert));
[5794] #endif
[5795] 
[5796]     len = BIO_pending(bio);
[5797] 
[5798]     s->len = len;
[5799]     s->data = ngx_pnalloc(pool, len);
[5800]     if (s->data == NULL) {
[5801]         BIO_free(bio);
[5802]         X509_free(cert);
[5803]         return NGX_ERROR;
[5804]     }
[5805] 
[5806]     BIO_read(bio, s->data, len);
[5807]     BIO_free(bio);
[5808]     X509_free(cert);
[5809] 
[5810]     return NGX_OK;
[5811] }
[5812] 
[5813] 
[5814] ngx_int_t
[5815] ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5816] {
[5817]     BIO     *bio;
[5818]     X509    *cert;
[5819]     size_t   len;
[5820] 
[5821]     s->len = 0;
[5822] 
[5823]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5824]     if (cert == NULL) {
[5825]         return NGX_OK;
[5826]     }
[5827] 
[5828]     bio = BIO_new(BIO_s_mem());
[5829]     if (bio == NULL) {
[5830]         ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "BIO_new() failed");
[5831]         X509_free(cert);
[5832]         return NGX_ERROR;
[5833]     }
[5834] 
[5835] #if OPENSSL_VERSION_NUMBER > 0x10100000L
[5836]     ASN1_TIME_print(bio, X509_get0_notAfter(cert));
[5837] #else
[5838]     ASN1_TIME_print(bio, X509_get_notAfter(cert));
[5839] #endif
[5840] 
[5841]     len = BIO_pending(bio);
[5842] 
[5843]     s->len = len;
[5844]     s->data = ngx_pnalloc(pool, len);
[5845]     if (s->data == NULL) {
[5846]         BIO_free(bio);
[5847]         X509_free(cert);
[5848]         return NGX_ERROR;
[5849]     }
[5850] 
[5851]     BIO_read(bio, s->data, len);
[5852]     BIO_free(bio);
[5853]     X509_free(cert);
[5854] 
[5855]     return NGX_OK;
[5856] }
[5857] 
[5858] 
[5859] ngx_int_t
[5860] ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
[5861] {
[5862]     X509    *cert;
[5863]     time_t   now, end;
[5864] 
[5865]     s->len = 0;
[5866] 
[5867]     cert = SSL_get_peer_certificate(c->ssl->connection);
[5868]     if (cert == NULL) {
[5869]         return NGX_OK;
[5870]     }
[5871] 
[5872] #if OPENSSL_VERSION_NUMBER > 0x10100000L
[5873]     end = ngx_ssl_parse_time(X509_get0_notAfter(cert), c->log);
[5874] #else
[5875]     end = ngx_ssl_parse_time(X509_get_notAfter(cert), c->log);
[5876] #endif
[5877] 
[5878]     if (end == (time_t) NGX_ERROR) {
[5879]         X509_free(cert);
[5880]         return NGX_OK;
[5881]     }
[5882] 
[5883]     now = ngx_time();
[5884] 
[5885]     if (end < now + 86400) {
[5886]         ngx_str_set(s, "0");
[5887]         X509_free(cert);
[5888]         return NGX_OK;
[5889]     }
[5890] 
[5891]     s->data = ngx_pnalloc(pool, NGX_TIME_T_LEN);
[5892]     if (s->data == NULL) {
[5893]         X509_free(cert);
[5894]         return NGX_ERROR;
[5895]     }
[5896] 
[5897]     s->len = ngx_sprintf(s->data, "%T", (end - now) / 86400) - s->data;
[5898] 
[5899]     X509_free(cert);
[5900] 
[5901]     return NGX_OK;
[5902] }
[5903] 
[5904] 
[5905] static time_t
[5906] ngx_ssl_parse_time(
[5907] #if OPENSSL_VERSION_NUMBER > 0x10100000L
[5908]     const
[5909] #endif
[5910]     ASN1_TIME *asn1time, ngx_log_t *log)
[5911] {
[5912]     BIO     *bio;
[5913]     char    *value;
[5914]     size_t   len;
[5915]     time_t   time;
[5916] 
[5917]     /*
[5918]      * OpenSSL doesn't provide a way to convert ASN1_TIME
[5919]      * into time_t.  To do this, we use ASN1_TIME_print(),
[5920]      * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
[5921]      * "Feb  3 00:55:52 2015 GMT"), and parse the result.
[5922]      */
[5923] 
[5924]     bio = BIO_new(BIO_s_mem());
[5925]     if (bio == NULL) {
[5926]         ngx_ssl_error(NGX_LOG_ALERT, log, 0, "BIO_new() failed");
[5927]         return NGX_ERROR;
[5928]     }
[5929] 
[5930]     /* fake weekday prepended to match C asctime() format */
[5931] 
[5932]     BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
[5933]     ASN1_TIME_print(bio, asn1time);
[5934]     len = BIO_get_mem_data(bio, &value);
[5935] 
[5936]     time = ngx_parse_http_time((u_char *) value, len);
[5937] 
[5938]     BIO_free(bio);
[5939] 
[5940]     return time;
[5941] }
[5942] 
[5943] 
[5944] static void *
[5945] ngx_openssl_create_conf(ngx_cycle_t *cycle)
[5946] {
[5947]     ngx_openssl_conf_t  *oscf;
[5948] 
[5949]     oscf = ngx_pcalloc(cycle->pool, sizeof(ngx_openssl_conf_t));
[5950]     if (oscf == NULL) {
[5951]         return NULL;
[5952]     }
[5953] 
[5954]     /*
[5955]      * set by ngx_pcalloc():
[5956]      *
[5957]      *     oscf->engine = 0;
[5958]      */
[5959] 
[5960]     return oscf;
[5961] }
[5962] 
[5963] 
[5964] static char *
[5965] ngx_openssl_engine(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[5966] {
[5967] #ifndef OPENSSL_NO_ENGINE
[5968] 
[5969]     ngx_openssl_conf_t *oscf = conf;
[5970] 
[5971]     ENGINE     *engine;
[5972]     ngx_str_t  *value;
[5973] 
[5974]     if (oscf->engine) {
[5975]         return "is duplicate";
[5976]     }
[5977] 
[5978]     oscf->engine = 1;
[5979] 
[5980]     value = cf->args->elts;
[5981] 
[5982]     engine = ENGINE_by_id((char *) value[1].data);
[5983] 
[5984]     if (engine == NULL) {
[5985]         ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
[5986]                       "ENGINE_by_id(\"%V\") failed", &value[1]);
[5987]         return NGX_CONF_ERROR;
[5988]     }
[5989] 
[5990]     if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
[5991]         ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
[5992]                       "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
[5993]                       &value[1]);
[5994] 
[5995]         ENGINE_free(engine);
[5996] 
[5997]         return NGX_CONF_ERROR;
[5998]     }
[5999] 
[6000]     ENGINE_free(engine);
[6001] 
[6002]     return NGX_CONF_OK;
[6003] 
[6004] #else
[6005] 
[6006]     return "is not supported";
[6007] 
[6008] #endif
[6009] }
[6010] 
[6011] 
[6012] static void
[6013] ngx_openssl_exit(ngx_cycle_t *cycle)
[6014] {
[6015] #if OPENSSL_VERSION_NUMBER < 0x10100003L
[6016] 
[6017]     EVP_cleanup();
[6018] #ifndef OPENSSL_NO_ENGINE
[6019]     ENGINE_cleanup();
[6020] #endif
[6021] 
[6022] #endif
[6023] }
