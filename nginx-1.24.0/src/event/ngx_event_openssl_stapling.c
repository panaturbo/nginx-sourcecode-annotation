[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] #include <ngx_event_connect.h>
[12] 
[13] 
[14] #if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)
[15] 
[16] 
[17] typedef struct {
[18]     ngx_str_t                    staple;
[19]     ngx_msec_t                   timeout;
[20] 
[21]     ngx_resolver_t              *resolver;
[22]     ngx_msec_t                   resolver_timeout;
[23] 
[24]     ngx_addr_t                  *addrs;
[25]     ngx_uint_t                   naddrs;
[26]     ngx_str_t                    host;
[27]     ngx_str_t                    uri;
[28]     in_port_t                    port;
[29] 
[30]     SSL_CTX                     *ssl_ctx;
[31] 
[32]     X509                        *cert;
[33]     X509                        *issuer;
[34]     STACK_OF(X509)              *chain;
[35] 
[36]     u_char                      *name;
[37] 
[38]     time_t                       valid;
[39]     time_t                       refresh;
[40] 
[41]     unsigned                     verify:1;
[42]     unsigned                     loading:1;
[43] } ngx_ssl_stapling_t;
[44] 
[45] 
[46] typedef struct {
[47]     ngx_addr_t                  *addrs;
[48]     ngx_uint_t                   naddrs;
[49] 
[50]     ngx_str_t                    host;
[51]     ngx_str_t                    uri;
[52]     in_port_t                    port;
[53]     ngx_uint_t                   depth;
[54] 
[55]     ngx_shm_zone_t              *shm_zone;
[56] 
[57]     ngx_resolver_t              *resolver;
[58]     ngx_msec_t                   resolver_timeout;
[59] } ngx_ssl_ocsp_conf_t;
[60] 
[61] 
[62] typedef struct {
[63]     ngx_rbtree_t                 rbtree;
[64]     ngx_rbtree_node_t            sentinel;
[65]     ngx_queue_t                  expire_queue;
[66] } ngx_ssl_ocsp_cache_t;
[67] 
[68] 
[69] typedef struct {
[70]     ngx_str_node_t               node;
[71]     ngx_queue_t                  queue;
[72]     int                          status;
[73]     time_t                       valid;
[74] } ngx_ssl_ocsp_cache_node_t;
[75] 
[76] 
[77] typedef struct ngx_ssl_ocsp_ctx_s  ngx_ssl_ocsp_ctx_t;
[78] 
[79] 
[80] struct ngx_ssl_ocsp_s {
[81]     STACK_OF(X509)              *certs;
[82]     ngx_uint_t                   ncert;
[83] 
[84]     int                          cert_status;
[85]     ngx_int_t                    status;
[86] 
[87]     ngx_ssl_ocsp_conf_t         *conf;
[88]     ngx_ssl_ocsp_ctx_t          *ctx;
[89] };
[90] 
[91] 
[92] struct ngx_ssl_ocsp_ctx_s {
[93]     SSL_CTX                     *ssl_ctx;
[94] 
[95]     X509                        *cert;
[96]     X509                        *issuer;
[97]     STACK_OF(X509)              *chain;
[98] 
[99]     int                          status;
[100]     time_t                       valid;
[101] 
[102]     u_char                      *name;
[103] 
[104]     ngx_uint_t                   naddrs;
[105]     ngx_uint_t                   naddr;
[106] 
[107]     ngx_addr_t                  *addrs;
[108]     ngx_str_t                    host;
[109]     ngx_str_t                    uri;
[110]     in_port_t                    port;
[111] 
[112]     ngx_resolver_t              *resolver;
[113]     ngx_msec_t                   resolver_timeout;
[114] 
[115]     ngx_msec_t                   timeout;
[116] 
[117]     void                       (*handler)(ngx_ssl_ocsp_ctx_t *ctx);
[118]     void                        *data;
[119] 
[120]     ngx_str_t                    key;
[121]     ngx_buf_t                   *request;
[122]     ngx_buf_t                   *response;
[123]     ngx_peer_connection_t        peer;
[124] 
[125]     ngx_shm_zone_t              *shm_zone;
[126] 
[127]     ngx_int_t                  (*process)(ngx_ssl_ocsp_ctx_t *ctx);
[128] 
[129]     ngx_uint_t                   state;
[130] 
[131]     ngx_uint_t                   code;
[132]     ngx_uint_t                   count;
[133]     ngx_uint_t                   flags;
[134]     ngx_uint_t                   done;
[135] 
[136]     u_char                      *header_name_start;
[137]     u_char                      *header_name_end;
[138]     u_char                      *header_start;
[139]     u_char                      *header_end;
[140] 
[141]     ngx_pool_t                  *pool;
[142]     ngx_log_t                   *log;
[143] };
[144] 
[145] 
[146] static ngx_int_t ngx_ssl_stapling_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
[147]     X509 *cert, ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
[148] static ngx_int_t ngx_ssl_stapling_file(ngx_conf_t *cf, ngx_ssl_t *ssl,
[149]     ngx_ssl_stapling_t *staple, ngx_str_t *file);
[150] static ngx_int_t ngx_ssl_stapling_issuer(ngx_conf_t *cf, ngx_ssl_t *ssl,
[151]     ngx_ssl_stapling_t *staple);
[152] static ngx_int_t ngx_ssl_stapling_responder(ngx_conf_t *cf, ngx_ssl_t *ssl,
[153]     ngx_ssl_stapling_t *staple, ngx_str_t *responder);
[154] 
[155] static int ngx_ssl_certificate_status_callback(ngx_ssl_conn_t *ssl_conn,
[156]     void *data);
[157] static void ngx_ssl_stapling_update(ngx_ssl_stapling_t *staple);
[158] static void ngx_ssl_stapling_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx);
[159] 
[160] static time_t ngx_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time);
[161] 
[162] static void ngx_ssl_stapling_cleanup(void *data);
[163] 
[164] static void ngx_ssl_ocsp_validate_next(ngx_connection_t *c);
[165] static void ngx_ssl_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx);
[166] static ngx_int_t ngx_ssl_ocsp_responder(ngx_connection_t *c,
[167]     ngx_ssl_ocsp_ctx_t *ctx);
[168] 
[169] static ngx_ssl_ocsp_ctx_t *ngx_ssl_ocsp_start(ngx_log_t *log);
[170] static void ngx_ssl_ocsp_done(ngx_ssl_ocsp_ctx_t *ctx);
[171] static void ngx_ssl_ocsp_next(ngx_ssl_ocsp_ctx_t *ctx);
[172] static void ngx_ssl_ocsp_request(ngx_ssl_ocsp_ctx_t *ctx);
[173] static void ngx_ssl_ocsp_resolve_handler(ngx_resolver_ctx_t *resolve);
[174] static void ngx_ssl_ocsp_connect(ngx_ssl_ocsp_ctx_t *ctx);
[175] static void ngx_ssl_ocsp_write_handler(ngx_event_t *wev);
[176] static void ngx_ssl_ocsp_read_handler(ngx_event_t *rev);
[177] static void ngx_ssl_ocsp_dummy_handler(ngx_event_t *ev);
[178] 
[179] static ngx_int_t ngx_ssl_ocsp_create_request(ngx_ssl_ocsp_ctx_t *ctx);
[180] static ngx_int_t ngx_ssl_ocsp_process_status_line(ngx_ssl_ocsp_ctx_t *ctx);
[181] static ngx_int_t ngx_ssl_ocsp_parse_status_line(ngx_ssl_ocsp_ctx_t *ctx);
[182] static ngx_int_t ngx_ssl_ocsp_process_headers(ngx_ssl_ocsp_ctx_t *ctx);
[183] static ngx_int_t ngx_ssl_ocsp_parse_header_line(ngx_ssl_ocsp_ctx_t *ctx);
[184] static ngx_int_t ngx_ssl_ocsp_process_body(ngx_ssl_ocsp_ctx_t *ctx);
[185] static ngx_int_t ngx_ssl_ocsp_verify(ngx_ssl_ocsp_ctx_t *ctx);
[186] 
[187] static ngx_int_t ngx_ssl_ocsp_cache_lookup(ngx_ssl_ocsp_ctx_t *ctx);
[188] static ngx_int_t ngx_ssl_ocsp_cache_store(ngx_ssl_ocsp_ctx_t *ctx);
[189] static ngx_int_t ngx_ssl_ocsp_create_key(ngx_ssl_ocsp_ctx_t *ctx);
[190] 
[191] static u_char *ngx_ssl_ocsp_log_error(ngx_log_t *log, u_char *buf, size_t len);
[192] 
[193] 
[194] ngx_int_t
[195] ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
[196]     ngx_str_t *responder, ngx_uint_t verify)
[197] {
[198]     X509  *cert;
[199] 
[200]     for (cert = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index);
[201]          cert;
[202]          cert = X509_get_ex_data(cert, ngx_ssl_next_certificate_index))
[203]     {
[204]         if (ngx_ssl_stapling_certificate(cf, ssl, cert, file, responder, verify)
[205]             != NGX_OK)
[206]         {
[207]             return NGX_ERROR;
[208]         }
[209]     }
[210] 
[211]     SSL_CTX_set_tlsext_status_cb(ssl->ctx, ngx_ssl_certificate_status_callback);
[212] 
[213]     return NGX_OK;
[214] }
[215] 
[216] 
[217] static ngx_int_t
[218] ngx_ssl_stapling_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, X509 *cert,
[219]     ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify)
[220] {
[221]     ngx_int_t            rc;
[222]     ngx_pool_cleanup_t  *cln;
[223]     ngx_ssl_stapling_t  *staple;
[224] 
[225]     staple = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_stapling_t));
[226]     if (staple == NULL) {
[227]         return NGX_ERROR;
[228]     }
[229] 
[230]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[231]     if (cln == NULL) {
[232]         return NGX_ERROR;
[233]     }
[234] 
[235]     cln->handler = ngx_ssl_stapling_cleanup;
[236]     cln->data = staple;
[237] 
[238]     if (X509_set_ex_data(cert, ngx_ssl_stapling_index, staple) == 0) {
[239]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
[240]         return NGX_ERROR;
[241]     }
[242] 
[243] #ifdef SSL_CTRL_SELECT_CURRENT_CERT
[244]     /* OpenSSL 1.0.2+ */
[245]     SSL_CTX_select_current_cert(ssl->ctx, cert);
[246] #endif
[247] 
[248] #ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
[249]     /* OpenSSL 1.0.1+ */
[250]     SSL_CTX_get_extra_chain_certs(ssl->ctx, &staple->chain);
[251] #else
[252]     staple->chain = ssl->ctx->extra_certs;
[253] #endif
[254] 
[255]     staple->ssl_ctx = ssl->ctx;
[256]     staple->timeout = 60000;
[257]     staple->verify = verify;
[258]     staple->cert = cert;
[259]     staple->name = X509_get_ex_data(staple->cert,
[260]                                     ngx_ssl_certificate_name_index);
[261] 
[262]     if (file->len) {
[263]         /* use OCSP response from the file */
[264] 
[265]         if (ngx_ssl_stapling_file(cf, ssl, staple, file) != NGX_OK) {
[266]             return NGX_ERROR;
[267]         }
[268] 
[269]         return NGX_OK;
[270]     }
[271] 
[272]     rc = ngx_ssl_stapling_issuer(cf, ssl, staple);
[273] 
[274]     if (rc == NGX_DECLINED) {
[275]         return NGX_OK;
[276]     }
[277] 
[278]     if (rc != NGX_OK) {
[279]         return NGX_ERROR;
[280]     }
[281] 
[282]     rc = ngx_ssl_stapling_responder(cf, ssl, staple, responder);
[283] 
[284]     if (rc == NGX_DECLINED) {
[285]         return NGX_OK;
[286]     }
[287] 
[288]     if (rc != NGX_OK) {
[289]         return NGX_ERROR;
[290]     }
[291] 
[292]     return NGX_OK;
[293] }
[294] 
[295] 
[296] static ngx_int_t
[297] ngx_ssl_stapling_file(ngx_conf_t *cf, ngx_ssl_t *ssl,
[298]     ngx_ssl_stapling_t *staple, ngx_str_t *file)
[299] {
[300]     BIO            *bio;
[301]     int             len;
[302]     u_char         *p, *buf;
[303]     OCSP_RESPONSE  *response;
[304] 
[305]     if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
[306]         return NGX_ERROR;
[307]     }
[308] 
[309]     bio = BIO_new_file((char *) file->data, "rb");
[310]     if (bio == NULL) {
[311]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[312]                       "BIO_new_file(\"%s\") failed", file->data);
[313]         return NGX_ERROR;
[314]     }
[315] 
[316]     response = d2i_OCSP_RESPONSE_bio(bio, NULL);
[317]     if (response == NULL) {
[318]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[319]                       "d2i_OCSP_RESPONSE_bio(\"%s\") failed", file->data);
[320]         BIO_free(bio);
[321]         return NGX_ERROR;
[322]     }
[323] 
[324]     len = i2d_OCSP_RESPONSE(response, NULL);
[325]     if (len <= 0) {
[326]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[327]                       "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
[328]         goto failed;
[329]     }
[330] 
[331]     buf = ngx_alloc(len, ssl->log);
[332]     if (buf == NULL) {
[333]         goto failed;
[334]     }
[335] 
[336]     p = buf;
[337]     len = i2d_OCSP_RESPONSE(response, &p);
[338]     if (len <= 0) {
[339]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[340]                       "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
[341]         ngx_free(buf);
[342]         goto failed;
[343]     }
[344] 
[345]     OCSP_RESPONSE_free(response);
[346]     BIO_free(bio);
[347] 
[348]     staple->staple.data = buf;
[349]     staple->staple.len = len;
[350]     staple->valid = NGX_MAX_TIME_T_VALUE;
[351] 
[352]     return NGX_OK;
[353] 
[354] failed:
[355] 
[356]     OCSP_RESPONSE_free(response);
[357]     BIO_free(bio);
[358] 
[359]     return NGX_ERROR;
[360] }
[361] 
[362] 
[363] static ngx_int_t
[364] ngx_ssl_stapling_issuer(ngx_conf_t *cf, ngx_ssl_t *ssl,
[365]     ngx_ssl_stapling_t *staple)
[366] {
[367]     int              i, n, rc;
[368]     X509            *cert, *issuer;
[369]     X509_STORE      *store;
[370]     X509_STORE_CTX  *store_ctx;
[371] 
[372]     cert = staple->cert;
[373] 
[374]     n = sk_X509_num(staple->chain);
[375] 
[376]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
[377]                    "SSL get issuer: %d extra certs", n);
[378] 
[379]     for (i = 0; i < n; i++) {
[380]         issuer = sk_X509_value(staple->chain, i);
[381]         if (X509_check_issued(issuer, cert) == X509_V_OK) {
[382] #if OPENSSL_VERSION_NUMBER >= 0x10100001L
[383]             X509_up_ref(issuer);
[384] #else
[385]             CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
[386] #endif
[387] 
[388]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
[389]                            "SSL get issuer: found %p in extra certs", issuer);
[390] 
[391]             staple->issuer = issuer;
[392] 
[393]             return NGX_OK;
[394]         }
[395]     }
[396] 
[397]     store = SSL_CTX_get_cert_store(ssl->ctx);
[398]     if (store == NULL) {
[399]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[400]                       "SSL_CTX_get_cert_store() failed");
[401]         return NGX_ERROR;
[402]     }
[403] 
[404]     store_ctx = X509_STORE_CTX_new();
[405]     if (store_ctx == NULL) {
[406]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[407]                       "X509_STORE_CTX_new() failed");
[408]         return NGX_ERROR;
[409]     }
[410] 
[411]     if (X509_STORE_CTX_init(store_ctx, store, NULL, NULL) == 0) {
[412]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[413]                       "X509_STORE_CTX_init() failed");
[414]         X509_STORE_CTX_free(store_ctx);
[415]         return NGX_ERROR;
[416]     }
[417] 
[418]     rc = X509_STORE_CTX_get1_issuer(&issuer, store_ctx, cert);
[419] 
[420]     if (rc == -1) {
[421]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[422]                       "X509_STORE_CTX_get1_issuer() failed");
[423]         X509_STORE_CTX_free(store_ctx);
[424]         return NGX_ERROR;
[425]     }
[426] 
[427]     if (rc == 0) {
[428]         ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[429]                       "\"ssl_stapling\" ignored, "
[430]                       "issuer certificate not found for certificate \"%s\"",
[431]                       staple->name);
[432]         X509_STORE_CTX_free(store_ctx);
[433]         return NGX_DECLINED;
[434]     }
[435] 
[436]     X509_STORE_CTX_free(store_ctx);
[437] 
[438]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ssl->log, 0,
[439]                    "SSL get issuer: found %p in cert store", issuer);
[440] 
[441]     staple->issuer = issuer;
[442] 
[443]     return NGX_OK;
[444] }
[445] 
[446] 
[447] static ngx_int_t
[448] ngx_ssl_stapling_responder(ngx_conf_t *cf, ngx_ssl_t *ssl,
[449]     ngx_ssl_stapling_t *staple, ngx_str_t *responder)
[450] {
[451]     char                      *s;
[452]     ngx_str_t                  rsp;
[453]     ngx_url_t                  u;
[454]     STACK_OF(OPENSSL_STRING)  *aia;
[455] 
[456]     if (responder->len == 0) {
[457] 
[458]         /* extract OCSP responder URL from certificate */
[459] 
[460]         aia = X509_get1_ocsp(staple->cert);
[461]         if (aia == NULL) {
[462]             ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[463]                           "\"ssl_stapling\" ignored, "
[464]                           "no OCSP responder URL in the certificate \"%s\"",
[465]                           staple->name);
[466]             return NGX_DECLINED;
[467]         }
[468] 
[469] #if OPENSSL_VERSION_NUMBER >= 0x10000000L
[470]         s = sk_OPENSSL_STRING_value(aia, 0);
[471] #else
[472]         s = sk_value(aia, 0);
[473] #endif
[474]         if (s == NULL) {
[475]             ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[476]                           "\"ssl_stapling\" ignored, "
[477]                           "no OCSP responder URL in the certificate \"%s\"",
[478]                           staple->name);
[479]             X509_email_free(aia);
[480]             return NGX_DECLINED;
[481]         }
[482] 
[483]         responder = &rsp;
[484] 
[485]         responder->len = ngx_strlen(s);
[486]         responder->data = ngx_palloc(cf->pool, responder->len);
[487]         if (responder->data == NULL) {
[488]             X509_email_free(aia);
[489]             return NGX_ERROR;
[490]         }
[491] 
[492]         ngx_memcpy(responder->data, s, responder->len);
[493]         X509_email_free(aia);
[494]     }
[495] 
[496]     ngx_memzero(&u, sizeof(ngx_url_t));
[497] 
[498]     u.url = *responder;
[499]     u.default_port = 80;
[500]     u.uri_part = 1;
[501] 
[502]     if (u.url.len > 7
[503]         && ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
[504]     {
[505]         u.url.len -= 7;
[506]         u.url.data += 7;
[507] 
[508]     } else {
[509]         ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[510]                       "\"ssl_stapling\" ignored, "
[511]                       "invalid URL prefix in OCSP responder \"%V\" "
[512]                       "in the certificate \"%s\"",
[513]                       &u.url, staple->name);
[514]         return NGX_DECLINED;
[515]     }
[516] 
[517]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[518]         if (u.err) {
[519]             ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[520]                           "\"ssl_stapling\" ignored, "
[521]                           "%s in OCSP responder \"%V\" "
[522]                           "in the certificate \"%s\"",
[523]                           u.err, &u.url, staple->name);
[524]             return NGX_DECLINED;
[525]         }
[526] 
[527]         return NGX_ERROR;
[528]     }
[529] 
[530]     staple->addrs = u.addrs;
[531]     staple->naddrs = u.naddrs;
[532]     staple->host = u.host;
[533]     staple->uri = u.uri;
[534]     staple->port = u.port;
[535] 
[536]     if (staple->uri.len == 0) {
[537]         ngx_str_set(&staple->uri, "/");
[538]     }
[539] 
[540]     return NGX_OK;
[541] }
[542] 
[543] 
[544] ngx_int_t
[545] ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
[546]     ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
[547] {
[548]     X509                *cert;
[549]     ngx_ssl_stapling_t  *staple;
[550] 
[551]     for (cert = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index);
[552]          cert;
[553]          cert = X509_get_ex_data(cert, ngx_ssl_next_certificate_index))
[554]     {
[555]         staple = X509_get_ex_data(cert, ngx_ssl_stapling_index);
[556]         staple->resolver = resolver;
[557]         staple->resolver_timeout = resolver_timeout;
[558]     }
[559] 
[560]     return NGX_OK;
[561] }
[562] 
[563] 
[564] static int
[565] ngx_ssl_certificate_status_callback(ngx_ssl_conn_t *ssl_conn, void *data)
[566] {
[567]     int                  rc;
[568]     X509                *cert;
[569]     u_char              *p;
[570]     ngx_connection_t    *c;
[571]     ngx_ssl_stapling_t  *staple;
[572] 
[573]     c = ngx_ssl_get_connection(ssl_conn);
[574] 
[575]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[576]                    "SSL certificate status callback");
[577] 
[578]     rc = SSL_TLSEXT_ERR_NOACK;
[579] 
[580]     cert = SSL_get_certificate(ssl_conn);
[581] 
[582]     if (cert == NULL) {
[583]         return rc;
[584]     }
[585] 
[586]     staple = X509_get_ex_data(cert, ngx_ssl_stapling_index);
[587] 
[588]     if (staple == NULL) {
[589]         return rc;
[590]     }
[591] 
[592]     if (staple->staple.len
[593]         && staple->valid >= ngx_time())
[594]     {
[595]         /* we have to copy ocsp response as OpenSSL will free it by itself */
[596] 
[597]         p = OPENSSL_malloc(staple->staple.len);
[598]         if (p == NULL) {
[599]             ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "OPENSSL_malloc() failed");
[600]             return SSL_TLSEXT_ERR_NOACK;
[601]         }
[602] 
[603]         ngx_memcpy(p, staple->staple.data, staple->staple.len);
[604] 
[605]         SSL_set_tlsext_status_ocsp_resp(ssl_conn, p, staple->staple.len);
[606] 
[607]         rc = SSL_TLSEXT_ERR_OK;
[608]     }
[609] 
[610]     ngx_ssl_stapling_update(staple);
[611] 
[612]     return rc;
[613] }
[614] 
[615] 
[616] static void
[617] ngx_ssl_stapling_update(ngx_ssl_stapling_t *staple)
[618] {
[619]     ngx_ssl_ocsp_ctx_t  *ctx;
[620] 
[621]     if (staple->host.len == 0
[622]         || staple->loading || staple->refresh >= ngx_time())
[623]     {
[624]         return;
[625]     }
[626] 
[627]     staple->loading = 1;
[628] 
[629]     ctx = ngx_ssl_ocsp_start(ngx_cycle->log);
[630]     if (ctx == NULL) {
[631]         return;
[632]     }
[633] 
[634]     ctx->ssl_ctx = staple->ssl_ctx;
[635]     ctx->cert = staple->cert;
[636]     ctx->issuer = staple->issuer;
[637]     ctx->chain = staple->chain;
[638]     ctx->name = staple->name;
[639]     ctx->flags = (staple->verify ? OCSP_TRUSTOTHER : OCSP_NOVERIFY);
[640] 
[641]     ctx->addrs = staple->addrs;
[642]     ctx->naddrs = staple->naddrs;
[643]     ctx->host = staple->host;
[644]     ctx->uri = staple->uri;
[645]     ctx->port = staple->port;
[646]     ctx->timeout = staple->timeout;
[647] 
[648]     ctx->resolver = staple->resolver;
[649]     ctx->resolver_timeout = staple->resolver_timeout;
[650] 
[651]     ctx->handler = ngx_ssl_stapling_ocsp_handler;
[652]     ctx->data = staple;
[653] 
[654]     ngx_ssl_ocsp_request(ctx);
[655] 
[656]     return;
[657] }
[658] 
[659] 
[660] static void
[661] ngx_ssl_stapling_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx)
[662] {
[663]     time_t               now;
[664]     ngx_str_t            response;
[665]     ngx_ssl_stapling_t  *staple;
[666] 
[667]     staple = ctx->data;
[668]     now = ngx_time();
[669] 
[670]     if (ngx_ssl_ocsp_verify(ctx) != NGX_OK) {
[671]         goto error;
[672]     }
[673] 
[674]     if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
[675]         ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[676]                       "certificate status \"%s\" in the OCSP response",
[677]                       OCSP_cert_status_str(ctx->status));
[678]         goto error;
[679]     }
[680] 
[681]     /* copy the response to memory not in ctx->pool */
[682] 
[683]     response.len = ctx->response->last - ctx->response->pos;
[684]     response.data = ngx_alloc(response.len, ctx->log);
[685] 
[686]     if (response.data == NULL) {
[687]         goto error;
[688]     }
[689] 
[690]     ngx_memcpy(response.data, ctx->response->pos, response.len);
[691] 
[692]     if (staple->staple.data) {
[693]         ngx_free(staple->staple.data);
[694]     }
[695] 
[696]     staple->staple = response;
[697]     staple->valid = ctx->valid;
[698] 
[699]     /*
[700]      * refresh before the response expires,
[701]      * but not earlier than in 5 minutes, and at least in an hour
[702]      */
[703] 
[704]     staple->loading = 0;
[705]     staple->refresh = ngx_max(ngx_min(ctx->valid - 300, now + 3600), now + 300);
[706] 
[707]     ngx_ssl_ocsp_done(ctx);
[708]     return;
[709] 
[710] error:
[711] 
[712]     staple->loading = 0;
[713]     staple->refresh = now + 300;
[714] 
[715]     ngx_ssl_ocsp_done(ctx);
[716] }
[717] 
[718] 
[719] static time_t
[720] ngx_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time)
[721] {
[722]     BIO     *bio;
[723]     char    *value;
[724]     size_t   len;
[725]     time_t   time;
[726] 
[727]     /*
[728]      * OpenSSL doesn't provide a way to convert ASN1_GENERALIZEDTIME
[729]      * into time_t.  To do this, we use ASN1_GENERALIZEDTIME_print(),
[730]      * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
[731]      * "Feb  3 00:55:52 2015 GMT"), and parse the result.
[732]      */
[733] 
[734]     bio = BIO_new(BIO_s_mem());
[735]     if (bio == NULL) {
[736]         return NGX_ERROR;
[737]     }
[738] 
[739]     /* fake weekday prepended to match C asctime() format */
[740] 
[741]     BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
[742]     ASN1_GENERALIZEDTIME_print(bio, asn1time);
[743]     len = BIO_get_mem_data(bio, &value);
[744] 
[745]     time = ngx_parse_http_time((u_char *) value, len);
[746] 
[747]     BIO_free(bio);
[748] 
[749]     return time;
[750] }
[751] 
[752] 
[753] static void
[754] ngx_ssl_stapling_cleanup(void *data)
[755] {
[756]     ngx_ssl_stapling_t  *staple = data;
[757] 
[758]     if (staple->issuer) {
[759]         X509_free(staple->issuer);
[760]     }
[761] 
[762]     if (staple->staple.data) {
[763]         ngx_free(staple->staple.data);
[764]     }
[765] }
[766] 
[767] 
[768] ngx_int_t
[769] ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
[770]     ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
[771] {
[772]     ngx_url_t             u;
[773]     ngx_ssl_ocsp_conf_t  *ocf;
[774] 
[775]     ocf = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_ocsp_conf_t));
[776]     if (ocf == NULL) {
[777]         return NGX_ERROR;
[778]     }
[779] 
[780]     ocf->depth = depth;
[781]     ocf->shm_zone = shm_zone;
[782] 
[783]     if (responder->len) {
[784]         ngx_memzero(&u, sizeof(ngx_url_t));
[785] 
[786]         u.url = *responder;
[787]         u.default_port = 80;
[788]         u.uri_part = 1;
[789] 
[790]         if (u.url.len > 7
[791]             && ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
[792]         {
[793]             u.url.len -= 7;
[794]             u.url.data += 7;
[795] 
[796]         } else {
[797]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[798]                           "invalid URL prefix in OCSP responder \"%V\" "
[799]                           "in \"ssl_ocsp_responder\"", &u.url);
[800]             return NGX_ERROR;
[801]         }
[802] 
[803]         if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[804]             if (u.err) {
[805]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[806]                               "%s in OCSP responder \"%V\" "
[807]                               "in \"ssl_ocsp_responder\"", u.err, &u.url);
[808]             }
[809] 
[810]             return NGX_ERROR;
[811]         }
[812] 
[813]         ocf->addrs = u.addrs;
[814]         ocf->naddrs = u.naddrs;
[815]         ocf->host = u.host;
[816]         ocf->uri = u.uri;
[817]         ocf->port = u.port;
[818]     }
[819] 
[820]     if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_ocsp_index, ocf) == 0) {
[821]         ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
[822]                       "SSL_CTX_set_ex_data() failed");
[823]         return NGX_ERROR;
[824]     }
[825] 
[826]     return NGX_OK;
[827] }
[828] 
[829] 
[830] ngx_int_t
[831] ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
[832]     ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
[833] {
[834]     ngx_ssl_ocsp_conf_t  *ocf;
[835] 
[836]     ocf = SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_ocsp_index);
[837]     ocf->resolver = resolver;
[838]     ocf->resolver_timeout = resolver_timeout;
[839] 
[840]     return NGX_OK;
[841] }
[842] 
[843] 
[844] ngx_int_t
[845] ngx_ssl_ocsp_validate(ngx_connection_t *c)
[846] {
[847]     X509                 *cert;
[848]     SSL_CTX              *ssl_ctx;
[849]     ngx_int_t             rc;
[850]     X509_STORE           *store;
[851]     X509_STORE_CTX       *store_ctx;
[852]     STACK_OF(X509)       *chain;
[853]     ngx_ssl_ocsp_t       *ocsp;
[854]     ngx_ssl_ocsp_conf_t  *ocf;
[855] 
[856]     if (c->ssl->in_ocsp) {
[857]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[858]             return NGX_ERROR;
[859]         }
[860] 
[861]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[862]             return NGX_ERROR;
[863]         }
[864] 
[865]         return NGX_AGAIN;
[866]     }
[867] 
[868]     ssl_ctx = SSL_get_SSL_CTX(c->ssl->connection);
[869] 
[870]     ocf = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ocsp_index);
[871]     if (ocf == NULL) {
[872]         return NGX_OK;
[873]     }
[874] 
[875]     if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
[876]         return NGX_OK;
[877]     }
[878] 
[879]     cert = SSL_get_peer_certificate(c->ssl->connection);
[880]     if (cert == NULL) {
[881]         return NGX_OK;
[882]     }
[883] 
[884]     ocsp = ngx_pcalloc(c->pool, sizeof(ngx_ssl_ocsp_t));
[885]     if (ocsp == NULL) {
[886]         X509_free(cert);
[887]         return NGX_ERROR;
[888]     }
[889] 
[890]     c->ssl->ocsp = ocsp;
[891] 
[892]     ocsp->status = NGX_AGAIN;
[893]     ocsp->cert_status = V_OCSP_CERTSTATUS_GOOD;
[894]     ocsp->conf = ocf;
[895] 
[896] #if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)
[897] 
[898]     ocsp->certs = SSL_get0_verified_chain(c->ssl->connection);
[899] 
[900]     if (ocsp->certs) {
[901]         ocsp->certs = X509_chain_up_ref(ocsp->certs);
[902]         if (ocsp->certs == NULL) {
[903]             X509_free(cert);
[904]             return NGX_ERROR;
[905]         }
[906]     }
[907] 
[908] #endif
[909] 
[910]     if (ocsp->certs == NULL) {
[911]         store = SSL_CTX_get_cert_store(ssl_ctx);
[912]         if (store == NULL) {
[913]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[914]                           "SSL_CTX_get_cert_store() failed");
[915]             X509_free(cert);
[916]             return NGX_ERROR;
[917]         }
[918] 
[919]         store_ctx = X509_STORE_CTX_new();
[920]         if (store_ctx == NULL) {
[921]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[922]                           "X509_STORE_CTX_new() failed");
[923]             X509_free(cert);
[924]             return NGX_ERROR;
[925]         }
[926] 
[927]         chain = SSL_get_peer_cert_chain(c->ssl->connection);
[928] 
[929]         if (X509_STORE_CTX_init(store_ctx, store, cert, chain) == 0) {
[930]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[931]                           "X509_STORE_CTX_init() failed");
[932]             X509_STORE_CTX_free(store_ctx);
[933]             X509_free(cert);
[934]             return NGX_ERROR;
[935]         }
[936] 
[937]         rc = X509_verify_cert(store_ctx);
[938]         if (rc <= 0) {
[939]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "X509_verify_cert() failed");
[940]             X509_STORE_CTX_free(store_ctx);
[941]             X509_free(cert);
[942]             return NGX_ERROR;
[943]         }
[944] 
[945]         ocsp->certs = X509_STORE_CTX_get1_chain(store_ctx);
[946]         if (ocsp->certs == NULL) {
[947]             ngx_ssl_error(NGX_LOG_ERR, c->log, 0,
[948]                           "X509_STORE_CTX_get1_chain() failed");
[949]             X509_STORE_CTX_free(store_ctx);
[950]             X509_free(cert);
[951]             return NGX_ERROR;
[952]         }
[953] 
[954]         X509_STORE_CTX_free(store_ctx);
[955]     }
[956] 
[957]     X509_free(cert);
[958] 
[959]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[960]                    "ssl ocsp validate, certs:%d", sk_X509_num(ocsp->certs));
[961] 
[962]     ngx_ssl_ocsp_validate_next(c);
[963] 
[964]     if (ocsp->status == NGX_AGAIN) {
[965]         c->ssl->in_ocsp = 1;
[966]         return NGX_AGAIN;
[967]     }
[968] 
[969]     return NGX_OK;
[970] }
[971] 
[972] 
[973] static void
[974] ngx_ssl_ocsp_validate_next(ngx_connection_t *c)
[975] {
[976]     ngx_int_t             rc;
[977]     ngx_uint_t            n;
[978]     ngx_ssl_ocsp_t       *ocsp;
[979]     ngx_ssl_ocsp_ctx_t   *ctx;
[980]     ngx_ssl_ocsp_conf_t  *ocf;
[981] 
[982]     ocsp = c->ssl->ocsp;
[983]     ocf = ocsp->conf;
[984] 
[985]     n = sk_X509_num(ocsp->certs);
[986] 
[987]     for ( ;; ) {
[988] 
[989]         if (ocsp->ncert == n - 1 || (ocf->depth == 2 && ocsp->ncert == 1)) {
[990]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[991]                            "ssl ocsp validated, certs:%ui", ocsp->ncert);
[992]             rc = NGX_OK;
[993]             goto done;
[994]         }
[995] 
[996]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[997]                        "ssl ocsp validate cert:%ui", ocsp->ncert);
[998] 
[999]         ctx = ngx_ssl_ocsp_start(c->log);
[1000]         if (ctx == NULL) {
[1001]             rc = NGX_ERROR;
[1002]             goto done;
[1003]         }
[1004] 
[1005]         ocsp->ctx = ctx;
[1006] 
[1007]         ctx->ssl_ctx = SSL_get_SSL_CTX(c->ssl->connection);
[1008]         ctx->cert = sk_X509_value(ocsp->certs, ocsp->ncert);
[1009]         ctx->issuer = sk_X509_value(ocsp->certs, ocsp->ncert + 1);
[1010]         ctx->chain = ocsp->certs;
[1011] 
[1012]         ctx->resolver = ocf->resolver;
[1013]         ctx->resolver_timeout = ocf->resolver_timeout;
[1014] 
[1015]         ctx->handler = ngx_ssl_ocsp_handler;
[1016]         ctx->data = c;
[1017] 
[1018]         ctx->shm_zone = ocf->shm_zone;
[1019] 
[1020]         ctx->addrs = ocf->addrs;
[1021]         ctx->naddrs = ocf->naddrs;
[1022]         ctx->host = ocf->host;
[1023]         ctx->uri = ocf->uri;
[1024]         ctx->port = ocf->port;
[1025] 
[1026]         rc = ngx_ssl_ocsp_responder(c, ctx);
[1027]         if (rc != NGX_OK) {
[1028]             goto done;
[1029]         }
[1030] 
[1031]         if (ctx->uri.len == 0) {
[1032]             ngx_str_set(&ctx->uri, "/");
[1033]         }
[1034] 
[1035]         ocsp->ncert++;
[1036] 
[1037]         rc = ngx_ssl_ocsp_cache_lookup(ctx);
[1038] 
[1039]         if (rc == NGX_ERROR) {
[1040]             goto done;
[1041]         }
[1042] 
[1043]         if (rc == NGX_DECLINED) {
[1044]             break;
[1045]         }
[1046] 
[1047]         /* rc == NGX_OK */
[1048] 
[1049]         if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
[1050]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1051]                            "ssl ocsp cached status \"%s\"",
[1052]                            OCSP_cert_status_str(ctx->status));
[1053]             ocsp->cert_status = ctx->status;
[1054]             goto done;
[1055]         }
[1056] 
[1057]         ocsp->ctx = NULL;
[1058]         ngx_ssl_ocsp_done(ctx);
[1059]     }
[1060] 
[1061]     ngx_ssl_ocsp_request(ctx);
[1062]     return;
[1063] 
[1064] done:
[1065] 
[1066]     ocsp->status = rc;
[1067] 
[1068]     if (c->ssl->in_ocsp) {
[1069]         c->ssl->handshaked = 1;
[1070]         c->ssl->handler(c);
[1071]     }
[1072] }
[1073] 
[1074] 
[1075] static void
[1076] ngx_ssl_ocsp_handler(ngx_ssl_ocsp_ctx_t *ctx)
[1077] {
[1078]     ngx_int_t          rc;
[1079]     ngx_ssl_ocsp_t    *ocsp;
[1080]     ngx_connection_t  *c;
[1081] 
[1082]     c = ctx->data;
[1083]     ocsp = c->ssl->ocsp;
[1084]     ocsp->ctx = NULL;
[1085] 
[1086]     rc = ngx_ssl_ocsp_verify(ctx);
[1087]     if (rc != NGX_OK) {
[1088]         goto done;
[1089]     }
[1090] 
[1091]     rc = ngx_ssl_ocsp_cache_store(ctx);
[1092]     if (rc != NGX_OK) {
[1093]         goto done;
[1094]     }
[1095] 
[1096]     if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
[1097]         ocsp->cert_status = ctx->status;
[1098]         goto done;
[1099]     }
[1100] 
[1101]     ngx_ssl_ocsp_done(ctx);
[1102] 
[1103]     ngx_ssl_ocsp_validate_next(c);
[1104] 
[1105]     return;
[1106] 
[1107] done:
[1108] 
[1109]     ocsp->status = rc;
[1110]     ngx_ssl_ocsp_done(ctx);
[1111] 
[1112]     if (c->ssl->in_ocsp) {
[1113]         c->ssl->handshaked = 1;
[1114]         c->ssl->handler(c);
[1115]     }
[1116] }
[1117] 
[1118] 
[1119] static ngx_int_t
[1120] ngx_ssl_ocsp_responder(ngx_connection_t *c, ngx_ssl_ocsp_ctx_t *ctx)
[1121] {
[1122]     char                      *s;
[1123]     ngx_str_t                  responder;
[1124]     ngx_url_t                  u;
[1125]     STACK_OF(OPENSSL_STRING)  *aia;
[1126] 
[1127]     if (ctx->host.len) {
[1128]         return NGX_OK;
[1129]     }
[1130] 
[1131]     /* extract OCSP responder URL from certificate */
[1132] 
[1133]     aia = X509_get1_ocsp(ctx->cert);
[1134]     if (aia == NULL) {
[1135]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1136]                       "no OCSP responder URL in certificate");
[1137]         return NGX_ERROR;
[1138]     }
[1139] 
[1140] #if OPENSSL_VERSION_NUMBER >= 0x10000000L
[1141]     s = sk_OPENSSL_STRING_value(aia, 0);
[1142] #else
[1143]     s = sk_value(aia, 0);
[1144] #endif
[1145]     if (s == NULL) {
[1146]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1147]                       "no OCSP responder URL in certificate");
[1148]         X509_email_free(aia);
[1149]         return NGX_ERROR;
[1150]     }
[1151] 
[1152]     responder.len = ngx_strlen(s);
[1153]     responder.data = ngx_palloc(ctx->pool, responder.len);
[1154]     if (responder.data == NULL) {
[1155]         X509_email_free(aia);
[1156]         return NGX_ERROR;
[1157]     }
[1158] 
[1159]     ngx_memcpy(responder.data, s, responder.len);
[1160]     X509_email_free(aia);
[1161] 
[1162]     ngx_memzero(&u, sizeof(ngx_url_t));
[1163] 
[1164]     u.url = responder;
[1165]     u.default_port = 80;
[1166]     u.uri_part = 1;
[1167]     u.no_resolve = 1;
[1168] 
[1169]     if (u.url.len > 7
[1170]         && ngx_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
[1171]     {
[1172]         u.url.len -= 7;
[1173]         u.url.data += 7;
[1174] 
[1175]     } else {
[1176]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1177]                       "invalid URL prefix in OCSP responder \"%V\" "
[1178]                       "in certificate", &u.url);
[1179]         return NGX_ERROR;
[1180]     }
[1181] 
[1182]     if (ngx_parse_url(ctx->pool, &u) != NGX_OK) {
[1183]         if (u.err) {
[1184]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1185]                           "%s in OCSP responder \"%V\" in certificate",
[1186]                           u.err, &u.url);
[1187]         }
[1188] 
[1189]         return NGX_ERROR;
[1190]     }
[1191] 
[1192]     if (u.host.len == 0) {
[1193]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[1194]                       "empty host in OCSP responder in certificate");
[1195]         return NGX_ERROR;
[1196]     }
[1197] 
[1198]     ctx->addrs = u.addrs;
[1199]     ctx->naddrs = u.naddrs;
[1200]     ctx->host = u.host;
[1201]     ctx->uri = u.uri;
[1202]     ctx->port = u.port;
[1203] 
[1204]     return NGX_OK;
[1205] }
[1206] 
[1207] 
[1208] ngx_int_t
[1209] ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s)
[1210] {
[1211]     ngx_ssl_ocsp_t  *ocsp;
[1212] 
[1213]     ocsp = c->ssl->ocsp;
[1214]     if (ocsp == NULL) {
[1215]         return NGX_OK;
[1216]     }
[1217] 
[1218]     if (ocsp->status == NGX_ERROR) {
[1219]         *s = "certificate status request failed";
[1220]         return NGX_DECLINED;
[1221]     }
[1222] 
[1223]     switch (ocsp->cert_status) {
[1224] 
[1225]     case V_OCSP_CERTSTATUS_GOOD:
[1226]         return NGX_OK;
[1227] 
[1228]     case V_OCSP_CERTSTATUS_REVOKED:
[1229]         *s = "certificate revoked";
[1230]         break;
[1231] 
[1232]     default: /* V_OCSP_CERTSTATUS_UNKNOWN */
[1233]         *s = "certificate status unknown";
[1234]     }
[1235] 
[1236]     return NGX_DECLINED;
[1237] }
[1238] 
[1239] 
[1240] void
[1241] ngx_ssl_ocsp_cleanup(ngx_connection_t *c)
[1242] {
[1243]     ngx_ssl_ocsp_t  *ocsp;
[1244] 
[1245]     ocsp = c->ssl->ocsp;
[1246]     if (ocsp == NULL) {
[1247]         return;
[1248]     }
[1249] 
[1250]     if (ocsp->ctx) {
[1251]         ngx_ssl_ocsp_done(ocsp->ctx);
[1252]         ocsp->ctx = NULL;
[1253]     }
[1254] 
[1255]     if (ocsp->certs) {
[1256]         sk_X509_pop_free(ocsp->certs, X509_free);
[1257]         ocsp->certs = NULL;
[1258]     }
[1259] }
[1260] 
[1261] 
[1262] static ngx_ssl_ocsp_ctx_t *
[1263] ngx_ssl_ocsp_start(ngx_log_t *log)
[1264] {
[1265]     ngx_pool_t          *pool;
[1266]     ngx_ssl_ocsp_ctx_t  *ctx;
[1267] 
[1268]     pool = ngx_create_pool(2048, log);
[1269]     if (pool == NULL) {
[1270]         return NULL;
[1271]     }
[1272] 
[1273]     ctx = ngx_pcalloc(pool, sizeof(ngx_ssl_ocsp_ctx_t));
[1274]     if (ctx == NULL) {
[1275]         ngx_destroy_pool(pool);
[1276]         return NULL;
[1277]     }
[1278] 
[1279]     log = ngx_palloc(pool, sizeof(ngx_log_t));
[1280]     if (log == NULL) {
[1281]         ngx_destroy_pool(pool);
[1282]         return NULL;
[1283]     }
[1284] 
[1285]     ctx->pool = pool;
[1286] 
[1287]     *log = *ctx->pool->log;
[1288] 
[1289]     ctx->pool->log = log;
[1290]     ctx->log = log;
[1291] 
[1292]     log->handler = ngx_ssl_ocsp_log_error;
[1293]     log->data = ctx;
[1294]     log->action = "requesting certificate status";
[1295] 
[1296]     return ctx;
[1297] }
[1298] 
[1299] 
[1300] static void
[1301] ngx_ssl_ocsp_done(ngx_ssl_ocsp_ctx_t *ctx)
[1302] {
[1303]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1304]                    "ssl ocsp done");
[1305] 
[1306]     if (ctx->peer.connection) {
[1307]         ngx_close_connection(ctx->peer.connection);
[1308]     }
[1309] 
[1310]     ngx_destroy_pool(ctx->pool);
[1311] }
[1312] 
[1313] 
[1314] static void
[1315] ngx_ssl_ocsp_error(ngx_ssl_ocsp_ctx_t *ctx)
[1316] {
[1317]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1318]                    "ssl ocsp error");
[1319] 
[1320]     ctx->code = 0;
[1321]     ctx->handler(ctx);
[1322] }
[1323] 
[1324] 
[1325] static void
[1326] ngx_ssl_ocsp_next(ngx_ssl_ocsp_ctx_t *ctx)
[1327] {
[1328]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1329]                    "ssl ocsp next");
[1330] 
[1331]     if (++ctx->naddr >= ctx->naddrs) {
[1332]         ngx_ssl_ocsp_error(ctx);
[1333]         return;
[1334]     }
[1335] 
[1336]     ctx->request->pos = ctx->request->start;
[1337] 
[1338]     if (ctx->response) {
[1339]         ctx->response->last = ctx->response->pos;
[1340]     }
[1341] 
[1342]     if (ctx->peer.connection) {
[1343]         ngx_close_connection(ctx->peer.connection);
[1344]         ctx->peer.connection = NULL;
[1345]     }
[1346] 
[1347]     ctx->state = 0;
[1348]     ctx->count = 0;
[1349]     ctx->done = 0;
[1350] 
[1351]     ngx_ssl_ocsp_connect(ctx);
[1352] }
[1353] 
[1354] 
[1355] static void
[1356] ngx_ssl_ocsp_request(ngx_ssl_ocsp_ctx_t *ctx)
[1357] {
[1358]     ngx_resolver_ctx_t  *resolve, temp;
[1359] 
[1360]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1361]                    "ssl ocsp request");
[1362] 
[1363]     if (ngx_ssl_ocsp_create_request(ctx) != NGX_OK) {
[1364]         ngx_ssl_ocsp_error(ctx);
[1365]         return;
[1366]     }
[1367] 
[1368]     if (ctx->resolver) {
[1369]         /* resolve OCSP responder hostname */
[1370] 
[1371]         temp.name = ctx->host;
[1372] 
[1373]         resolve = ngx_resolve_start(ctx->resolver, &temp);
[1374]         if (resolve == NULL) {
[1375]             ngx_ssl_ocsp_error(ctx);
[1376]             return;
[1377]         }
[1378] 
[1379]         if (resolve == NGX_NO_RESOLVER) {
[1380]             if (ctx->naddrs == 0) {
[1381]                 ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[1382]                               "no resolver defined to resolve %V", &ctx->host);
[1383] 
[1384]                 ngx_ssl_ocsp_error(ctx);
[1385]                 return;
[1386]             }
[1387] 
[1388]             ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
[1389]                           "no resolver defined to resolve %V", &ctx->host);
[1390]             goto connect;
[1391]         }
[1392] 
[1393]         resolve->name = ctx->host;
[1394]         resolve->handler = ngx_ssl_ocsp_resolve_handler;
[1395]         resolve->data = ctx;
[1396]         resolve->timeout = ctx->resolver_timeout;
[1397] 
[1398]         if (ngx_resolve_name(resolve) != NGX_OK) {
[1399]             ngx_ssl_ocsp_error(ctx);
[1400]             return;
[1401]         }
[1402] 
[1403]         return;
[1404]     }
[1405] 
[1406] connect:
[1407] 
[1408]     ngx_ssl_ocsp_connect(ctx);
[1409] }
[1410] 
[1411] 
[1412] static void
[1413] ngx_ssl_ocsp_resolve_handler(ngx_resolver_ctx_t *resolve)
[1414] {
[1415]     ngx_ssl_ocsp_ctx_t *ctx = resolve->data;
[1416] 
[1417]     u_char           *p;
[1418]     size_t            len;
[1419]     socklen_t         socklen;
[1420]     ngx_uint_t        i;
[1421]     struct sockaddr  *sockaddr;
[1422] 
[1423]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1424]                    "ssl ocsp resolve handler");
[1425] 
[1426]     if (resolve->state) {
[1427]         ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[1428]                       "%V could not be resolved (%i: %s)",
[1429]                       &resolve->name, resolve->state,
[1430]                       ngx_resolver_strerror(resolve->state));
[1431]         goto failed;
[1432]     }
[1433] 
[1434] #if (NGX_DEBUG)
[1435]     {
[1436]     u_char     text[NGX_SOCKADDR_STRLEN];
[1437]     ngx_str_t  addr;
[1438] 
[1439]     addr.data = text;
[1440] 
[1441]     for (i = 0; i < resolve->naddrs; i++) {
[1442]         addr.len = ngx_sock_ntop(resolve->addrs[i].sockaddr,
[1443]                                  resolve->addrs[i].socklen,
[1444]                                  text, NGX_SOCKADDR_STRLEN, 0);
[1445] 
[1446]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1447]                        "name was resolved to %V", &addr);
[1448] 
[1449]     }
[1450]     }
[1451] #endif
[1452] 
[1453]     ctx->naddrs = resolve->naddrs;
[1454]     ctx->addrs = ngx_pcalloc(ctx->pool, ctx->naddrs * sizeof(ngx_addr_t));
[1455] 
[1456]     if (ctx->addrs == NULL) {
[1457]         goto failed;
[1458]     }
[1459] 
[1460]     for (i = 0; i < resolve->naddrs; i++) {
[1461] 
[1462]         socklen = resolve->addrs[i].socklen;
[1463] 
[1464]         sockaddr = ngx_palloc(ctx->pool, socklen);
[1465]         if (sockaddr == NULL) {
[1466]             goto failed;
[1467]         }
[1468] 
[1469]         ngx_memcpy(sockaddr, resolve->addrs[i].sockaddr, socklen);
[1470]         ngx_inet_set_port(sockaddr, ctx->port);
[1471] 
[1472]         ctx->addrs[i].sockaddr = sockaddr;
[1473]         ctx->addrs[i].socklen = socklen;
[1474] 
[1475]         p = ngx_pnalloc(ctx->pool, NGX_SOCKADDR_STRLEN);
[1476]         if (p == NULL) {
[1477]             goto failed;
[1478]         }
[1479] 
[1480]         len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);
[1481] 
[1482]         ctx->addrs[i].name.len = len;
[1483]         ctx->addrs[i].name.data = p;
[1484]     }
[1485] 
[1486]     ngx_resolve_name_done(resolve);
[1487] 
[1488]     ngx_ssl_ocsp_connect(ctx);
[1489]     return;
[1490] 
[1491] failed:
[1492] 
[1493]     ngx_resolve_name_done(resolve);
[1494]     ngx_ssl_ocsp_error(ctx);
[1495] }
[1496] 
[1497] 
[1498] static void
[1499] ngx_ssl_ocsp_connect(ngx_ssl_ocsp_ctx_t *ctx)
[1500] {
[1501]     ngx_int_t    rc;
[1502]     ngx_addr_t  *addr;
[1503] 
[1504]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1505]                    "ssl ocsp connect %ui/%ui", ctx->naddr, ctx->naddrs);
[1506] 
[1507]     addr = &ctx->addrs[ctx->naddr];
[1508] 
[1509]     ctx->peer.sockaddr = addr->sockaddr;
[1510]     ctx->peer.socklen = addr->socklen;
[1511]     ctx->peer.name = &addr->name;
[1512]     ctx->peer.get = ngx_event_get_peer;
[1513]     ctx->peer.log = ctx->log;
[1514]     ctx->peer.log_error = NGX_ERROR_ERR;
[1515] 
[1516]     rc = ngx_event_connect_peer(&ctx->peer);
[1517] 
[1518]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1519]                    "ssl ocsp connect peer done");
[1520] 
[1521]     if (rc == NGX_ERROR) {
[1522]         ngx_ssl_ocsp_error(ctx);
[1523]         return;
[1524]     }
[1525] 
[1526]     if (rc == NGX_BUSY || rc == NGX_DECLINED) {
[1527]         ngx_ssl_ocsp_next(ctx);
[1528]         return;
[1529]     }
[1530] 
[1531]     ctx->peer.connection->data = ctx;
[1532]     ctx->peer.connection->pool = ctx->pool;
[1533] 
[1534]     ctx->peer.connection->read->handler = ngx_ssl_ocsp_read_handler;
[1535]     ctx->peer.connection->write->handler = ngx_ssl_ocsp_write_handler;
[1536] 
[1537]     ctx->process = ngx_ssl_ocsp_process_status_line;
[1538] 
[1539]     if (ctx->timeout) {
[1540]         ngx_add_timer(ctx->peer.connection->read, ctx->timeout);
[1541]         ngx_add_timer(ctx->peer.connection->write, ctx->timeout);
[1542]     }
[1543] 
[1544]     if (rc == NGX_OK) {
[1545]         ngx_ssl_ocsp_write_handler(ctx->peer.connection->write);
[1546]         return;
[1547]     }
[1548] }
[1549] 
[1550] 
[1551] static void
[1552] ngx_ssl_ocsp_write_handler(ngx_event_t *wev)
[1553] {
[1554]     ssize_t              n, size;
[1555]     ngx_connection_t    *c;
[1556]     ngx_ssl_ocsp_ctx_t  *ctx;
[1557] 
[1558]     c = wev->data;
[1559]     ctx = c->data;
[1560] 
[1561]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, wev->log, 0,
[1562]                    "ssl ocsp write handler");
[1563] 
[1564]     if (wev->timedout) {
[1565]         ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
[1566]                       "OCSP responder timed out");
[1567]         ngx_ssl_ocsp_next(ctx);
[1568]         return;
[1569]     }
[1570] 
[1571]     size = ctx->request->last - ctx->request->pos;
[1572] 
[1573]     n = ngx_send(c, ctx->request->pos, size);
[1574] 
[1575]     if (n == NGX_ERROR) {
[1576]         ngx_ssl_ocsp_next(ctx);
[1577]         return;
[1578]     }
[1579] 
[1580]     if (n > 0) {
[1581]         ctx->request->pos += n;
[1582] 
[1583]         if (n == size) {
[1584]             wev->handler = ngx_ssl_ocsp_dummy_handler;
[1585] 
[1586]             if (wev->timer_set) {
[1587]                 ngx_del_timer(wev);
[1588]             }
[1589] 
[1590]             if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[1591]                 ngx_ssl_ocsp_error(ctx);
[1592]             }
[1593] 
[1594]             return;
[1595]         }
[1596]     }
[1597] 
[1598]     if (!wev->timer_set && ctx->timeout) {
[1599]         ngx_add_timer(wev, ctx->timeout);
[1600]     }
[1601] }
[1602] 
[1603] 
[1604] static void
[1605] ngx_ssl_ocsp_read_handler(ngx_event_t *rev)
[1606] {
[1607]     ssize_t              n, size;
[1608]     ngx_int_t            rc;
[1609]     ngx_connection_t    *c;
[1610]     ngx_ssl_ocsp_ctx_t  *ctx;
[1611] 
[1612]     c = rev->data;
[1613]     ctx = c->data;
[1614] 
[1615]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, rev->log, 0,
[1616]                    "ssl ocsp read handler");
[1617] 
[1618]     if (rev->timedout) {
[1619]         ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
[1620]                       "OCSP responder timed out");
[1621]         ngx_ssl_ocsp_next(ctx);
[1622]         return;
[1623]     }
[1624] 
[1625]     if (ctx->response == NULL) {
[1626]         ctx->response = ngx_create_temp_buf(ctx->pool, 16384);
[1627]         if (ctx->response == NULL) {
[1628]             ngx_ssl_ocsp_error(ctx);
[1629]             return;
[1630]         }
[1631]     }
[1632] 
[1633]     for ( ;; ) {
[1634] 
[1635]         size = ctx->response->end - ctx->response->last;
[1636] 
[1637]         n = ngx_recv(c, ctx->response->last, size);
[1638] 
[1639]         if (n > 0) {
[1640]             ctx->response->last += n;
[1641] 
[1642]             rc = ctx->process(ctx);
[1643] 
[1644]             if (rc == NGX_ERROR) {
[1645]                 ngx_ssl_ocsp_next(ctx);
[1646]                 return;
[1647]             }
[1648] 
[1649]             continue;
[1650]         }
[1651] 
[1652]         if (n == NGX_AGAIN) {
[1653] 
[1654]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[1655]                 ngx_ssl_ocsp_error(ctx);
[1656]             }
[1657] 
[1658]             return;
[1659]         }
[1660] 
[1661]         break;
[1662]     }
[1663] 
[1664]     ctx->done = 1;
[1665] 
[1666]     rc = ctx->process(ctx);
[1667] 
[1668]     if (rc == NGX_DONE) {
[1669]         /* ctx->handler() was called */
[1670]         return;
[1671]     }
[1672] 
[1673]     ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[1674]                   "OCSP responder prematurely closed connection");
[1675] 
[1676]     ngx_ssl_ocsp_next(ctx);
[1677] }
[1678] 
[1679] 
[1680] static void
[1681] ngx_ssl_ocsp_dummy_handler(ngx_event_t *ev)
[1682] {
[1683]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[1684]                    "ssl ocsp dummy handler");
[1685] }
[1686] 
[1687] 
[1688] static ngx_int_t
[1689] ngx_ssl_ocsp_create_request(ngx_ssl_ocsp_ctx_t *ctx)
[1690] {
[1691]     int            len;
[1692]     u_char        *p;
[1693]     uintptr_t      escape;
[1694]     ngx_str_t      binary, base64;
[1695]     ngx_buf_t     *b;
[1696]     OCSP_CERTID   *id;
[1697]     OCSP_REQUEST  *ocsp;
[1698] 
[1699]     ocsp = OCSP_REQUEST_new();
[1700]     if (ocsp == NULL) {
[1701]         ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
[1702]                       "OCSP_REQUEST_new() failed");
[1703]         return NGX_ERROR;
[1704]     }
[1705] 
[1706]     id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
[1707]     if (id == NULL) {
[1708]         ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
[1709]                       "OCSP_cert_to_id() failed");
[1710]         goto failed;
[1711]     }
[1712] 
[1713]     if (OCSP_request_add0_id(ocsp, id) == NULL) {
[1714]         ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
[1715]                       "OCSP_request_add0_id() failed");
[1716]         OCSP_CERTID_free(id);
[1717]         goto failed;
[1718]     }
[1719] 
[1720]     len = i2d_OCSP_REQUEST(ocsp, NULL);
[1721]     if (len <= 0) {
[1722]         ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
[1723]                       "i2d_OCSP_REQUEST() failed");
[1724]         goto failed;
[1725]     }
[1726] 
[1727]     binary.len = len;
[1728]     binary.data = ngx_palloc(ctx->pool, len);
[1729]     if (binary.data == NULL) {
[1730]         goto failed;
[1731]     }
[1732] 
[1733]     p = binary.data;
[1734]     len = i2d_OCSP_REQUEST(ocsp, &p);
[1735]     if (len <= 0) {
[1736]         ngx_ssl_error(NGX_LOG_EMERG, ctx->log, 0,
[1737]                       "i2d_OCSP_REQUEST() failed");
[1738]         goto failed;
[1739]     }
[1740] 
[1741]     base64.len = ngx_base64_encoded_length(binary.len);
[1742]     base64.data = ngx_palloc(ctx->pool, base64.len);
[1743]     if (base64.data == NULL) {
[1744]         goto failed;
[1745]     }
[1746] 
[1747]     ngx_encode_base64(&base64, &binary);
[1748] 
[1749]     escape = ngx_escape_uri(NULL, base64.data, base64.len,
[1750]                             NGX_ESCAPE_URI_COMPONENT);
[1751] 
[1752]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1753]                    "ssl ocsp request length %z, escape %d",
[1754]                    base64.len, (int) escape);
[1755] 
[1756]     len = sizeof("GET ") - 1 + ctx->uri.len + sizeof("/") - 1
[1757]           + base64.len + 2 * escape + sizeof(" HTTP/1.0" CRLF) - 1
[1758]           + sizeof("Host: ") - 1 + ctx->host.len + sizeof(CRLF) - 1
[1759]           + sizeof(CRLF) - 1;
[1760] 
[1761]     b = ngx_create_temp_buf(ctx->pool, len);
[1762]     if (b == NULL) {
[1763]         goto failed;
[1764]     }
[1765] 
[1766]     p = b->last;
[1767] 
[1768]     p = ngx_cpymem(p, "GET ", sizeof("GET ") - 1);
[1769]     p = ngx_cpymem(p, ctx->uri.data, ctx->uri.len);
[1770] 
[1771]     if (ctx->uri.data[ctx->uri.len - 1] != '/') {
[1772]         *p++ = '/';
[1773]     }
[1774] 
[1775]     if (escape == 0) {
[1776]         p = ngx_cpymem(p, base64.data, base64.len);
[1777] 
[1778]     } else {
[1779]         p = (u_char *) ngx_escape_uri(p, base64.data, base64.len,
[1780]                                       NGX_ESCAPE_URI_COMPONENT);
[1781]     }
[1782] 
[1783]     p = ngx_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
[1784]     p = ngx_cpymem(p, "Host: ", sizeof("Host: ") - 1);
[1785]     p = ngx_cpymem(p, ctx->host.data, ctx->host.len);
[1786]     *p++ = CR; *p++ = LF;
[1787] 
[1788]     /* add "\r\n" at the header end */
[1789]     *p++ = CR; *p++ = LF;
[1790] 
[1791]     b->last = p;
[1792]     ctx->request = b;
[1793] 
[1794]     OCSP_REQUEST_free(ocsp);
[1795] 
[1796]     return NGX_OK;
[1797] 
[1798] failed:
[1799] 
[1800]     OCSP_REQUEST_free(ocsp);
[1801] 
[1802]     return NGX_ERROR;
[1803] }
[1804] 
[1805] 
[1806] static ngx_int_t
[1807] ngx_ssl_ocsp_process_status_line(ngx_ssl_ocsp_ctx_t *ctx)
[1808] {
[1809]     ngx_int_t  rc;
[1810] 
[1811]     rc = ngx_ssl_ocsp_parse_status_line(ctx);
[1812] 
[1813]     if (rc == NGX_OK) {
[1814]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1815]                        "ssl ocsp status %ui \"%*s\"",
[1816]                        ctx->code,
[1817]                        ctx->header_end - ctx->header_start,
[1818]                        ctx->header_start);
[1819] 
[1820]         ctx->process = ngx_ssl_ocsp_process_headers;
[1821]         return ctx->process(ctx);
[1822]     }
[1823] 
[1824]     if (rc == NGX_AGAIN) {
[1825]         return NGX_AGAIN;
[1826]     }
[1827] 
[1828]     /* rc == NGX_ERROR */
[1829] 
[1830]     ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[1831]                   "OCSP responder sent invalid response");
[1832] 
[1833]     return NGX_ERROR;
[1834] }
[1835] 
[1836] 
[1837] static ngx_int_t
[1838] ngx_ssl_ocsp_parse_status_line(ngx_ssl_ocsp_ctx_t *ctx)
[1839] {
[1840]     u_char      ch;
[1841]     u_char     *p;
[1842]     ngx_buf_t  *b;
[1843]     enum {
[1844]         sw_start = 0,
[1845]         sw_H,
[1846]         sw_HT,
[1847]         sw_HTT,
[1848]         sw_HTTP,
[1849]         sw_first_major_digit,
[1850]         sw_major_digit,
[1851]         sw_first_minor_digit,
[1852]         sw_minor_digit,
[1853]         sw_status,
[1854]         sw_space_after_status,
[1855]         sw_status_text,
[1856]         sw_almost_done
[1857]     } state;
[1858] 
[1859]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[1860]                    "ssl ocsp process status line");
[1861] 
[1862]     state = ctx->state;
[1863]     b = ctx->response;
[1864] 
[1865]     for (p = b->pos; p < b->last; p++) {
[1866]         ch = *p;
[1867] 
[1868]         switch (state) {
[1869] 
[1870]         /* "HTTP/" */
[1871]         case sw_start:
[1872]             switch (ch) {
[1873]             case 'H':
[1874]                 state = sw_H;
[1875]                 break;
[1876]             default:
[1877]                 return NGX_ERROR;
[1878]             }
[1879]             break;
[1880] 
[1881]         case sw_H:
[1882]             switch (ch) {
[1883]             case 'T':
[1884]                 state = sw_HT;
[1885]                 break;
[1886]             default:
[1887]                 return NGX_ERROR;
[1888]             }
[1889]             break;
[1890] 
[1891]         case sw_HT:
[1892]             switch (ch) {
[1893]             case 'T':
[1894]                 state = sw_HTT;
[1895]                 break;
[1896]             default:
[1897]                 return NGX_ERROR;
[1898]             }
[1899]             break;
[1900] 
[1901]         case sw_HTT:
[1902]             switch (ch) {
[1903]             case 'P':
[1904]                 state = sw_HTTP;
[1905]                 break;
[1906]             default:
[1907]                 return NGX_ERROR;
[1908]             }
[1909]             break;
[1910] 
[1911]         case sw_HTTP:
[1912]             switch (ch) {
[1913]             case '/':
[1914]                 state = sw_first_major_digit;
[1915]                 break;
[1916]             default:
[1917]                 return NGX_ERROR;
[1918]             }
[1919]             break;
[1920] 
[1921]         /* the first digit of major HTTP version */
[1922]         case sw_first_major_digit:
[1923]             if (ch < '1' || ch > '9') {
[1924]                 return NGX_ERROR;
[1925]             }
[1926] 
[1927]             state = sw_major_digit;
[1928]             break;
[1929] 
[1930]         /* the major HTTP version or dot */
[1931]         case sw_major_digit:
[1932]             if (ch == '.') {
[1933]                 state = sw_first_minor_digit;
[1934]                 break;
[1935]             }
[1936] 
[1937]             if (ch < '0' || ch > '9') {
[1938]                 return NGX_ERROR;
[1939]             }
[1940] 
[1941]             break;
[1942] 
[1943]         /* the first digit of minor HTTP version */
[1944]         case sw_first_minor_digit:
[1945]             if (ch < '0' || ch > '9') {
[1946]                 return NGX_ERROR;
[1947]             }
[1948] 
[1949]             state = sw_minor_digit;
[1950]             break;
[1951] 
[1952]         /* the minor HTTP version or the end of the request line */
[1953]         case sw_minor_digit:
[1954]             if (ch == ' ') {
[1955]                 state = sw_status;
[1956]                 break;
[1957]             }
[1958] 
[1959]             if (ch < '0' || ch > '9') {
[1960]                 return NGX_ERROR;
[1961]             }
[1962] 
[1963]             break;
[1964] 
[1965]         /* HTTP status code */
[1966]         case sw_status:
[1967]             if (ch == ' ') {
[1968]                 break;
[1969]             }
[1970] 
[1971]             if (ch < '0' || ch > '9') {
[1972]                 return NGX_ERROR;
[1973]             }
[1974] 
[1975]             ctx->code = ctx->code * 10 + (ch - '0');
[1976] 
[1977]             if (++ctx->count == 3) {
[1978]                 state = sw_space_after_status;
[1979]                 ctx->header_start = p - 2;
[1980]             }
[1981] 
[1982]             break;
[1983] 
[1984]         /* space or end of line */
[1985]         case sw_space_after_status:
[1986]             switch (ch) {
[1987]             case ' ':
[1988]                 state = sw_status_text;
[1989]                 break;
[1990]             case '.':                    /* IIS may send 403.1, 403.2, etc */
[1991]                 state = sw_status_text;
[1992]                 break;
[1993]             case CR:
[1994]                 state = sw_almost_done;
[1995]                 break;
[1996]             case LF:
[1997]                 ctx->header_end = p;
[1998]                 goto done;
[1999]             default:
[2000]                 return NGX_ERROR;
[2001]             }
[2002]             break;
[2003] 
[2004]         /* any text until end of line */
[2005]         case sw_status_text:
[2006]             switch (ch) {
[2007]             case CR:
[2008]                 state = sw_almost_done;
[2009]                 break;
[2010]             case LF:
[2011]                 ctx->header_end = p;
[2012]                 goto done;
[2013]             }
[2014]             break;
[2015] 
[2016]         /* end of status line */
[2017]         case sw_almost_done:
[2018]             switch (ch) {
[2019]             case LF:
[2020]                 ctx->header_end = p - 1;
[2021]                 goto done;
[2022]             default:
[2023]                 return NGX_ERROR;
[2024]             }
[2025]         }
[2026]     }
[2027] 
[2028]     b->pos = p;
[2029]     ctx->state = state;
[2030] 
[2031]     return NGX_AGAIN;
[2032] 
[2033] done:
[2034] 
[2035]     b->pos = p + 1;
[2036]     ctx->state = sw_start;
[2037] 
[2038]     return NGX_OK;
[2039] }
[2040] 
[2041] 
[2042] static ngx_int_t
[2043] ngx_ssl_ocsp_process_headers(ngx_ssl_ocsp_ctx_t *ctx)
[2044] {
[2045]     size_t     len;
[2046]     ngx_int_t  rc;
[2047] 
[2048]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2049]                    "ssl ocsp process headers");
[2050] 
[2051]     for ( ;; ) {
[2052]         rc = ngx_ssl_ocsp_parse_header_line(ctx);
[2053] 
[2054]         if (rc == NGX_OK) {
[2055] 
[2056]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2057]                            "ssl ocsp header \"%*s: %*s\"",
[2058]                            ctx->header_name_end - ctx->header_name_start,
[2059]                            ctx->header_name_start,
[2060]                            ctx->header_end - ctx->header_start,
[2061]                            ctx->header_start);
[2062] 
[2063]             len = ctx->header_name_end - ctx->header_name_start;
[2064] 
[2065]             if (len == sizeof("Content-Type") - 1
[2066]                 && ngx_strncasecmp(ctx->header_name_start,
[2067]                                    (u_char *) "Content-Type",
[2068]                                    sizeof("Content-Type") - 1)
[2069]                    == 0)
[2070]             {
[2071]                 len = ctx->header_end - ctx->header_start;
[2072] 
[2073]                 if (len != sizeof("application/ocsp-response") - 1
[2074]                     || ngx_strncasecmp(ctx->header_start,
[2075]                                        (u_char *) "application/ocsp-response",
[2076]                                        sizeof("application/ocsp-response") - 1)
[2077]                        != 0)
[2078]                 {
[2079]                     ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[2080]                                   "OCSP responder sent invalid "
[2081]                                   "\"Content-Type\" header: \"%*s\"",
[2082]                                   ctx->header_end - ctx->header_start,
[2083]                                   ctx->header_start);
[2084]                     return NGX_ERROR;
[2085]                 }
[2086] 
[2087]                 continue;
[2088]             }
[2089] 
[2090]             /* TODO: honor Content-Length */
[2091] 
[2092]             continue;
[2093]         }
[2094] 
[2095]         if (rc == NGX_DONE) {
[2096]             break;
[2097]         }
[2098] 
[2099]         if (rc == NGX_AGAIN) {
[2100]             return NGX_AGAIN;
[2101]         }
[2102] 
[2103]         /* rc == NGX_ERROR */
[2104] 
[2105]         ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[2106]                       "OCSP responder sent invalid response");
[2107] 
[2108]         return NGX_ERROR;
[2109]     }
[2110] 
[2111]     ctx->process = ngx_ssl_ocsp_process_body;
[2112]     return ctx->process(ctx);
[2113] }
[2114] 
[2115] 
[2116] static ngx_int_t
[2117] ngx_ssl_ocsp_parse_header_line(ngx_ssl_ocsp_ctx_t *ctx)
[2118] {
[2119]     u_char  c, ch, *p;
[2120]     enum {
[2121]         sw_start = 0,
[2122]         sw_name,
[2123]         sw_space_before_value,
[2124]         sw_value,
[2125]         sw_space_after_value,
[2126]         sw_almost_done,
[2127]         sw_header_almost_done
[2128]     } state;
[2129] 
[2130]     state = ctx->state;
[2131] 
[2132]     for (p = ctx->response->pos; p < ctx->response->last; p++) {
[2133]         ch = *p;
[2134] 
[2135] #if 0
[2136]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2137]                        "s:%d in:'%02Xd:%c'", state, ch, ch);
[2138] #endif
[2139] 
[2140]         switch (state) {
[2141] 
[2142]         /* first char */
[2143]         case sw_start:
[2144] 
[2145]             switch (ch) {
[2146]             case CR:
[2147]                 ctx->header_end = p;
[2148]                 state = sw_header_almost_done;
[2149]                 break;
[2150]             case LF:
[2151]                 ctx->header_end = p;
[2152]                 goto header_done;
[2153]             default:
[2154]                 state = sw_name;
[2155]                 ctx->header_name_start = p;
[2156] 
[2157]                 c = (u_char) (ch | 0x20);
[2158]                 if (c >= 'a' && c <= 'z') {
[2159]                     break;
[2160]                 }
[2161] 
[2162]                 if (ch >= '0' && ch <= '9') {
[2163]                     break;
[2164]                 }
[2165] 
[2166]                 return NGX_ERROR;
[2167]             }
[2168]             break;
[2169] 
[2170]         /* header name */
[2171]         case sw_name:
[2172]             c = (u_char) (ch | 0x20);
[2173]             if (c >= 'a' && c <= 'z') {
[2174]                 break;
[2175]             }
[2176] 
[2177]             if (ch == ':') {
[2178]                 ctx->header_name_end = p;
[2179]                 state = sw_space_before_value;
[2180]                 break;
[2181]             }
[2182] 
[2183]             if (ch == '-') {
[2184]                 break;
[2185]             }
[2186] 
[2187]             if (ch >= '0' && ch <= '9') {
[2188]                 break;
[2189]             }
[2190] 
[2191]             if (ch == CR) {
[2192]                 ctx->header_name_end = p;
[2193]                 ctx->header_start = p;
[2194]                 ctx->header_end = p;
[2195]                 state = sw_almost_done;
[2196]                 break;
[2197]             }
[2198] 
[2199]             if (ch == LF) {
[2200]                 ctx->header_name_end = p;
[2201]                 ctx->header_start = p;
[2202]                 ctx->header_end = p;
[2203]                 goto done;
[2204]             }
[2205] 
[2206]             return NGX_ERROR;
[2207] 
[2208]         /* space* before header value */
[2209]         case sw_space_before_value:
[2210]             switch (ch) {
[2211]             case ' ':
[2212]                 break;
[2213]             case CR:
[2214]                 ctx->header_start = p;
[2215]                 ctx->header_end = p;
[2216]                 state = sw_almost_done;
[2217]                 break;
[2218]             case LF:
[2219]                 ctx->header_start = p;
[2220]                 ctx->header_end = p;
[2221]                 goto done;
[2222]             default:
[2223]                 ctx->header_start = p;
[2224]                 state = sw_value;
[2225]                 break;
[2226]             }
[2227]             break;
[2228] 
[2229]         /* header value */
[2230]         case sw_value:
[2231]             switch (ch) {
[2232]             case ' ':
[2233]                 ctx->header_end = p;
[2234]                 state = sw_space_after_value;
[2235]                 break;
[2236]             case CR:
[2237]                 ctx->header_end = p;
[2238]                 state = sw_almost_done;
[2239]                 break;
[2240]             case LF:
[2241]                 ctx->header_end = p;
[2242]                 goto done;
[2243]             }
[2244]             break;
[2245] 
[2246]         /* space* before end of header line */
[2247]         case sw_space_after_value:
[2248]             switch (ch) {
[2249]             case ' ':
[2250]                 break;
[2251]             case CR:
[2252]                 state = sw_almost_done;
[2253]                 break;
[2254]             case LF:
[2255]                 goto done;
[2256]             default:
[2257]                 state = sw_value;
[2258]                 break;
[2259]             }
[2260]             break;
[2261] 
[2262]         /* end of header line */
[2263]         case sw_almost_done:
[2264]             switch (ch) {
[2265]             case LF:
[2266]                 goto done;
[2267]             default:
[2268]                 return NGX_ERROR;
[2269]             }
[2270] 
[2271]         /* end of header */
[2272]         case sw_header_almost_done:
[2273]             switch (ch) {
[2274]             case LF:
[2275]                 goto header_done;
[2276]             default:
[2277]                 return NGX_ERROR;
[2278]             }
[2279]         }
[2280]     }
[2281] 
[2282]     ctx->response->pos = p;
[2283]     ctx->state = state;
[2284] 
[2285]     return NGX_AGAIN;
[2286] 
[2287] done:
[2288] 
[2289]     ctx->response->pos = p + 1;
[2290]     ctx->state = sw_start;
[2291] 
[2292]     return NGX_OK;
[2293] 
[2294] header_done:
[2295] 
[2296]     ctx->response->pos = p + 1;
[2297]     ctx->state = sw_start;
[2298] 
[2299]     return NGX_DONE;
[2300] }
[2301] 
[2302] 
[2303] static ngx_int_t
[2304] ngx_ssl_ocsp_process_body(ngx_ssl_ocsp_ctx_t *ctx)
[2305] {
[2306]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2307]                    "ssl ocsp process body");
[2308] 
[2309]     if (ctx->done) {
[2310]         ctx->handler(ctx);
[2311]         return NGX_DONE;
[2312]     }
[2313] 
[2314]     return NGX_AGAIN;
[2315] }
[2316] 
[2317] 
[2318] static ngx_int_t
[2319] ngx_ssl_ocsp_verify(ngx_ssl_ocsp_ctx_t *ctx)
[2320] {
[2321]     int                    n;
[2322]     size_t                 len;
[2323]     X509_STORE            *store;
[2324]     const u_char          *p;
[2325]     OCSP_CERTID           *id;
[2326]     OCSP_RESPONSE         *ocsp;
[2327]     OCSP_BASICRESP        *basic;
[2328]     ASN1_GENERALIZEDTIME  *thisupdate, *nextupdate;
[2329] 
[2330]     ocsp = NULL;
[2331]     basic = NULL;
[2332]     id = NULL;
[2333] 
[2334]     if (ctx->code != 200) {
[2335]         goto error;
[2336]     }
[2337] 
[2338]     /* check the response */
[2339] 
[2340]     len = ctx->response->last - ctx->response->pos;
[2341]     p = ctx->response->pos;
[2342] 
[2343]     ocsp = d2i_OCSP_RESPONSE(NULL, &p, len);
[2344]     if (ocsp == NULL) {
[2345]         ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
[2346]                       "d2i_OCSP_RESPONSE() failed");
[2347]         goto error;
[2348]     }
[2349] 
[2350]     n = OCSP_response_status(ocsp);
[2351] 
[2352]     if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
[2353]         ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[2354]                       "OCSP response not successful (%d: %s)",
[2355]                       n, OCSP_response_status_str(n));
[2356]         goto error;
[2357]     }
[2358] 
[2359]     basic = OCSP_response_get1_basic(ocsp);
[2360]     if (basic == NULL) {
[2361]         ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
[2362]                       "OCSP_response_get1_basic() failed");
[2363]         goto error;
[2364]     }
[2365] 
[2366]     store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
[2367]     if (store == NULL) {
[2368]         ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
[2369]                       "SSL_CTX_get_cert_store() failed");
[2370]         goto error;
[2371]     }
[2372] 
[2373]     if (OCSP_basic_verify(basic, ctx->chain, store, ctx->flags) != 1) {
[2374]         ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
[2375]                       "OCSP_basic_verify() failed");
[2376]         goto error;
[2377]     }
[2378] 
[2379]     id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
[2380]     if (id == NULL) {
[2381]         ngx_ssl_error(NGX_LOG_CRIT, ctx->log, 0,
[2382]                       "OCSP_cert_to_id() failed");
[2383]         goto error;
[2384]     }
[2385] 
[2386]     if (OCSP_resp_find_status(basic, id, &ctx->status, NULL, NULL,
[2387]                               &thisupdate, &nextupdate)
[2388]         != 1)
[2389]     {
[2390]         ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[2391]                       "certificate status not found in the OCSP response");
[2392]         goto error;
[2393]     }
[2394] 
[2395]     if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) {
[2396]         ngx_ssl_error(NGX_LOG_ERR, ctx->log, 0,
[2397]                       "OCSP_check_validity() failed");
[2398]         goto error;
[2399]     }
[2400] 
[2401]     if (nextupdate) {
[2402]         ctx->valid = ngx_ssl_stapling_time(nextupdate);
[2403]         if (ctx->valid == (time_t) NGX_ERROR) {
[2404]             ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
[2405]                           "invalid nextUpdate time in certificate status");
[2406]             goto error;
[2407]         }
[2408] 
[2409]     } else {
[2410]         ctx->valid = NGX_MAX_TIME_T_VALUE;
[2411]     }
[2412] 
[2413]     OCSP_CERTID_free(id);
[2414]     OCSP_BASICRESP_free(basic);
[2415]     OCSP_RESPONSE_free(ocsp);
[2416] 
[2417]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2418]                    "ssl ocsp response, %s, %uz",
[2419]                    OCSP_cert_status_str(ctx->status), len);
[2420] 
[2421]     return NGX_OK;
[2422] 
[2423] error:
[2424] 
[2425]     if (id) {
[2426]         OCSP_CERTID_free(id);
[2427]     }
[2428] 
[2429]     if (basic) {
[2430]         OCSP_BASICRESP_free(basic);
[2431]     }
[2432] 
[2433]     if (ocsp) {
[2434]         OCSP_RESPONSE_free(ocsp);
[2435]     }
[2436] 
[2437]     return NGX_ERROR;
[2438] }
[2439] 
[2440] 
[2441] ngx_int_t
[2442] ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
[2443] {
[2444]     size_t                 len;
[2445]     ngx_slab_pool_t       *shpool;
[2446]     ngx_ssl_ocsp_cache_t  *cache;
[2447] 
[2448]     if (data) {
[2449]         shm_zone->data = data;
[2450]         return NGX_OK;
[2451]     }
[2452] 
[2453]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[2454] 
[2455]     if (shm_zone->shm.exists) {
[2456]         shm_zone->data = shpool->data;
[2457]         return NGX_OK;
[2458]     }
[2459] 
[2460]     cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_ocsp_cache_t));
[2461]     if (cache == NULL) {
[2462]         return NGX_ERROR;
[2463]     }
[2464] 
[2465]     shpool->data = cache;
[2466]     shm_zone->data = cache;
[2467] 
[2468]     ngx_rbtree_init(&cache->rbtree, &cache->sentinel,
[2469]                     ngx_str_rbtree_insert_value);
[2470] 
[2471]     ngx_queue_init(&cache->expire_queue);
[2472] 
[2473]     len = sizeof(" in OCSP cache \"\"") + shm_zone->shm.name.len;
[2474] 
[2475]     shpool->log_ctx = ngx_slab_alloc(shpool, len);
[2476]     if (shpool->log_ctx == NULL) {
[2477]         return NGX_ERROR;
[2478]     }
[2479] 
[2480]     ngx_sprintf(shpool->log_ctx, " in OCSP cache \"%V\"%Z",
[2481]                 &shm_zone->shm.name);
[2482] 
[2483]     shpool->log_nomem = 0;
[2484] 
[2485]     return NGX_OK;
[2486] }
[2487] 
[2488] 
[2489] static ngx_int_t
[2490] ngx_ssl_ocsp_cache_lookup(ngx_ssl_ocsp_ctx_t *ctx)
[2491] {
[2492]     uint32_t                    hash;
[2493]     ngx_shm_zone_t             *shm_zone;
[2494]     ngx_slab_pool_t            *shpool;
[2495]     ngx_ssl_ocsp_cache_t       *cache;
[2496]     ngx_ssl_ocsp_cache_node_t  *node;
[2497] 
[2498]     shm_zone = ctx->shm_zone;
[2499] 
[2500]     if (shm_zone == NULL) {
[2501]         return NGX_DECLINED;
[2502]     }
[2503] 
[2504]     if (ngx_ssl_ocsp_create_key(ctx) != NGX_OK) {
[2505]         return NGX_ERROR;
[2506]     }
[2507] 
[2508]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0, "ssl ocsp cache lookup");
[2509] 
[2510]     cache = shm_zone->data;
[2511]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[2512]     hash = ngx_hash_key(ctx->key.data, ctx->key.len);
[2513] 
[2514]     ngx_shmtx_lock(&shpool->mutex);
[2515] 
[2516]     node = (ngx_ssl_ocsp_cache_node_t *)
[2517]                ngx_str_rbtree_lookup(&cache->rbtree, &ctx->key, hash);
[2518] 
[2519]     if (node) {
[2520]         if (node->valid > ngx_time()) {
[2521]             ctx->status = node->status;
[2522]             ngx_shmtx_unlock(&shpool->mutex);
[2523] 
[2524]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2525]                            "ssl ocsp cache hit, %s",
[2526]                            OCSP_cert_status_str(ctx->status));
[2527] 
[2528]             return NGX_OK;
[2529]         }
[2530] 
[2531]         ngx_queue_remove(&node->queue);
[2532]         ngx_rbtree_delete(&cache->rbtree, &node->node.node);
[2533]         ngx_slab_free_locked(shpool, node);
[2534] 
[2535]         ngx_shmtx_unlock(&shpool->mutex);
[2536] 
[2537]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2538]                        "ssl ocsp cache expired");
[2539] 
[2540]         return NGX_DECLINED;
[2541]     }
[2542] 
[2543]     ngx_shmtx_unlock(&shpool->mutex);
[2544] 
[2545]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->log, 0, "ssl ocsp cache miss");
[2546] 
[2547]     return NGX_DECLINED;
[2548] }
[2549] 
[2550] 
[2551] static ngx_int_t
[2552] ngx_ssl_ocsp_cache_store(ngx_ssl_ocsp_ctx_t *ctx)
[2553] {
[2554]     time_t                      now, valid;
[2555]     uint32_t                    hash;
[2556]     ngx_queue_t                *q;
[2557]     ngx_shm_zone_t             *shm_zone;
[2558]     ngx_slab_pool_t            *shpool;
[2559]     ngx_ssl_ocsp_cache_t       *cache;
[2560]     ngx_ssl_ocsp_cache_node_t  *node;
[2561] 
[2562]     shm_zone = ctx->shm_zone;
[2563] 
[2564]     if (shm_zone == NULL) {
[2565]         return NGX_OK;
[2566]     }
[2567] 
[2568]     valid = ctx->valid;
[2569] 
[2570]     now = ngx_time();
[2571] 
[2572]     if (valid < now) {
[2573]         return NGX_OK;
[2574]     }
[2575] 
[2576]     if (valid == NGX_MAX_TIME_T_VALUE) {
[2577]         valid = now + 3600;
[2578]     }
[2579] 
[2580]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2581]                    "ssl ocsp cache store, valid:%T", valid - now);
[2582] 
[2583]     cache = shm_zone->data;
[2584]     shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
[2585]     hash = ngx_hash_key(ctx->key.data, ctx->key.len);
[2586] 
[2587]     ngx_shmtx_lock(&shpool->mutex);
[2588] 
[2589]     node = ngx_slab_calloc_locked(shpool,
[2590]                              sizeof(ngx_ssl_ocsp_cache_node_t) + ctx->key.len);
[2591]     if (node == NULL) {
[2592] 
[2593]         if (!ngx_queue_empty(&cache->expire_queue)) {
[2594]             q = ngx_queue_last(&cache->expire_queue);
[2595]             node = ngx_queue_data(q, ngx_ssl_ocsp_cache_node_t, queue);
[2596] 
[2597]             ngx_rbtree_delete(&cache->rbtree, &node->node.node);
[2598]             ngx_queue_remove(q);
[2599]             ngx_slab_free_locked(shpool, node);
[2600] 
[2601]             node = ngx_slab_alloc_locked(shpool,
[2602]                              sizeof(ngx_ssl_ocsp_cache_node_t) + ctx->key.len);
[2603]         }
[2604] 
[2605]         if (node == NULL) {
[2606]             ngx_shmtx_unlock(&shpool->mutex);
[2607]             ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
[2608]                           "could not allocate new entry%s", shpool->log_ctx);
[2609]             return NGX_ERROR;
[2610]         }
[2611]     }
[2612] 
[2613]     node->node.str.len = ctx->key.len;
[2614]     node->node.str.data = (u_char *) node + sizeof(ngx_ssl_ocsp_cache_node_t);
[2615]     ngx_memcpy(node->node.str.data, ctx->key.data, ctx->key.len);
[2616]     node->node.node.key = hash;
[2617]     node->status = ctx->status;
[2618]     node->valid = valid;
[2619] 
[2620]     ngx_rbtree_insert(&cache->rbtree, &node->node.node);
[2621]     ngx_queue_insert_head(&cache->expire_queue, &node->queue);
[2622] 
[2623]     ngx_shmtx_unlock(&shpool->mutex);
[2624] 
[2625]     return NGX_OK;
[2626] }
[2627] 
[2628] 
[2629] static ngx_int_t
[2630] ngx_ssl_ocsp_create_key(ngx_ssl_ocsp_ctx_t *ctx)
[2631] {
[2632]     u_char        *p;
[2633]     X509_NAME     *name;
[2634]     ASN1_INTEGER  *serial;
[2635] 
[2636]     p = ngx_pnalloc(ctx->pool, 60);
[2637]     if (p == NULL) {
[2638]         return NGX_ERROR;
[2639]     }
[2640] 
[2641]     ctx->key.data = p;
[2642]     ctx->key.len = 60;
[2643] 
[2644]     name = X509_get_subject_name(ctx->issuer);
[2645]     if (X509_NAME_digest(name, EVP_sha1(), p, NULL) == 0) {
[2646]         return NGX_ERROR;
[2647]     }
[2648] 
[2649]     p += 20;
[2650] 
[2651]     if (X509_pubkey_digest(ctx->issuer, EVP_sha1(), p, NULL) == 0) {
[2652]         return NGX_ERROR;
[2653]     }
[2654] 
[2655]     p += 20;
[2656] 
[2657]     serial = X509_get_serialNumber(ctx->cert);
[2658]     if (serial->length > 20) {
[2659]         return NGX_ERROR;
[2660]     }
[2661] 
[2662]     p = ngx_cpymem(p, serial->data, serial->length);
[2663]     ngx_memzero(p, 20 - serial->length);
[2664] 
[2665]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0,
[2666]                    "ssl ocsp key %xV", &ctx->key);
[2667] 
[2668]     return NGX_OK;
[2669] }
[2670] 
[2671] 
[2672] static u_char *
[2673] ngx_ssl_ocsp_log_error(ngx_log_t *log, u_char *buf, size_t len)
[2674] {
[2675]     u_char              *p;
[2676]     ngx_ssl_ocsp_ctx_t  *ctx;
[2677] 
[2678]     p = buf;
[2679] 
[2680]     if (log->action) {
[2681]         p = ngx_snprintf(buf, len, " while %s", log->action);
[2682]         len -= p - buf;
[2683]         buf = p;
[2684]     }
[2685] 
[2686]     ctx = log->data;
[2687] 
[2688]     if (ctx) {
[2689]         p = ngx_snprintf(buf, len, ", responder: %V", &ctx->host);
[2690]         len -= p - buf;
[2691]         buf = p;
[2692]     }
[2693] 
[2694]     if (ctx && ctx->peer.name) {
[2695]         p = ngx_snprintf(buf, len, ", peer: %V", ctx->peer.name);
[2696]         len -= p - buf;
[2697]         buf = p;
[2698]     }
[2699] 
[2700]     if (ctx && ctx->name) {
[2701]         p = ngx_snprintf(buf, len, ", certificate: \"%s\"", ctx->name);
[2702]         len -= p - buf;
[2703]         buf = p;
[2704]     }
[2705] 
[2706]     return p;
[2707] }
[2708] 
[2709] 
[2710] #else
[2711] 
[2712] 
[2713] ngx_int_t
[2714] ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
[2715]     ngx_str_t *responder, ngx_uint_t verify)
[2716] {
[2717]     ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
[2718]                   "\"ssl_stapling\" ignored, not supported");
[2719] 
[2720]     return NGX_OK;
[2721] }
[2722] 
[2723] 
[2724] ngx_int_t
[2725] ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
[2726]     ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
[2727] {
[2728]     return NGX_OK;
[2729] }
[2730] 
[2731] 
[2732] ngx_int_t
[2733] ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
[2734]     ngx_uint_t depth, ngx_shm_zone_t *shm_zone)
[2735] {
[2736]     ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
[2737]                   "\"ssl_ocsp\" is not supported on this platform");
[2738] 
[2739]     return NGX_ERROR;
[2740] }
[2741] 
[2742] 
[2743] ngx_int_t
[2744] ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
[2745]     ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
[2746] {
[2747]     return NGX_OK;
[2748] }
[2749] 
[2750] 
[2751] ngx_int_t
[2752] ngx_ssl_ocsp_validate(ngx_connection_t *c)
[2753] {
[2754]     return NGX_OK;
[2755] }
[2756] 
[2757] 
[2758] ngx_int_t
[2759] ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s)
[2760] {
[2761]     return NGX_OK;
[2762] }
[2763] 
[2764] 
[2765] void
[2766] ngx_ssl_ocsp_cleanup(ngx_connection_t *c)
[2767] {
[2768] }
[2769] 
[2770] 
[2771] ngx_int_t
[2772] ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data)
[2773] {
[2774]     return NGX_OK;
[2775] }
[2776] 
[2777] 
[2778] #endif
