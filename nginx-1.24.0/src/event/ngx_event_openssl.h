[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_EVENT_OPENSSL_H_INCLUDED_
[9] #define _NGX_EVENT_OPENSSL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] #define OPENSSL_SUPPRESS_DEPRECATED
[16] 
[17] #include <openssl/ssl.h>
[18] #include <openssl/err.h>
[19] #include <openssl/bn.h>
[20] #include <openssl/conf.h>
[21] #include <openssl/crypto.h>
[22] #include <openssl/dh.h>
[23] #ifndef OPENSSL_NO_ENGINE
[24] #include <openssl/engine.h>
[25] #endif
[26] #include <openssl/evp.h>
[27] #include <openssl/hmac.h>
[28] #ifndef OPENSSL_NO_OCSP
[29] #include <openssl/ocsp.h>
[30] #endif
[31] #include <openssl/rand.h>
[32] #include <openssl/x509.h>
[33] #include <openssl/x509v3.h>
[34] 
[35] #define NGX_SSL_NAME     "OpenSSL"
[36] 
[37] 
[38] #if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
[39] #undef OPENSSL_VERSION_NUMBER
[40] #if (LIBRESSL_VERSION_NUMBER >= 0x2080000fL)
[41] #define OPENSSL_VERSION_NUMBER  0x1010000fL
[42] #else
[43] #define OPENSSL_VERSION_NUMBER  0x1000107fL
[44] #endif
[45] #endif
[46] 
[47] 
[48] #if (OPENSSL_VERSION_NUMBER >= 0x10100001L)
[49] 
[50] #define ngx_ssl_version()       OpenSSL_version(OPENSSL_VERSION)
[51] 
[52] #else
[53] 
[54] #define ngx_ssl_version()       SSLeay_version(SSLEAY_VERSION)
[55] 
[56] #endif
[57] 
[58] 
[59] #define ngx_ssl_session_t       SSL_SESSION
[60] #define ngx_ssl_conn_t          SSL
[61] 
[62] 
[63] #if (OPENSSL_VERSION_NUMBER < 0x10002000L)
[64] #define SSL_is_server(s)        (s)->server
[65] #endif
[66] 
[67] 
[68] #if (OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined SSL_get_peer_certificate)
[69] #define SSL_get_peer_certificate(s)  SSL_get1_peer_certificate(s)
[70] #endif
[71] 
[72] 
[73] #if (OPENSSL_VERSION_NUMBER < 0x30000000L && !defined ERR_peek_error_data)
[74] #define ERR_peek_error_data(d, f)    ERR_peek_error_line_data(NULL, NULL, d, f)
[75] #endif
[76] 
[77] 
[78] typedef struct ngx_ssl_ocsp_s  ngx_ssl_ocsp_t;
[79] 
[80] 
[81] struct ngx_ssl_s {
[82]     SSL_CTX                    *ctx;
[83]     ngx_log_t                  *log;
[84]     size_t                      buffer_size;
[85] };
[86] 
[87] 
[88] struct ngx_ssl_connection_s {
[89]     ngx_ssl_conn_t             *connection;
[90]     SSL_CTX                    *session_ctx;
[91] 
[92]     ngx_int_t                   last;
[93]     ngx_buf_t                  *buf;
[94]     size_t                      buffer_size;
[95] 
[96]     ngx_connection_handler_pt   handler;
[97] 
[98]     ngx_ssl_session_t          *session;
[99]     ngx_connection_handler_pt   save_session;
[100] 
[101]     ngx_event_handler_pt        saved_read_handler;
[102]     ngx_event_handler_pt        saved_write_handler;
[103] 
[104]     ngx_ssl_ocsp_t             *ocsp;
[105] 
[106]     u_char                      early_buf;
[107] 
[108]     unsigned                    handshaked:1;
[109]     unsigned                    handshake_rejected:1;
[110]     unsigned                    renegotiation:1;
[111]     unsigned                    buffer:1;
[112]     unsigned                    sendfile:1;
[113]     unsigned                    no_wait_shutdown:1;
[114]     unsigned                    no_send_shutdown:1;
[115]     unsigned                    shutdown_without_free:1;
[116]     unsigned                    handshake_buffer_set:1;
[117]     unsigned                    session_timeout_set:1;
[118]     unsigned                    try_early_data:1;
[119]     unsigned                    in_early:1;
[120]     unsigned                    in_ocsp:1;
[121]     unsigned                    early_preread:1;
[122]     unsigned                    write_blocked:1;
[123] };
[124] 
[125] 
[126] #define NGX_SSL_NO_SCACHE            -2
[127] #define NGX_SSL_NONE_SCACHE          -3
[128] #define NGX_SSL_NO_BUILTIN_SCACHE    -4
[129] #define NGX_SSL_DFLT_BUILTIN_SCACHE  -5
[130] 
[131] 
[132] #define NGX_SSL_MAX_SESSION_SIZE  4096
[133] 
[134] typedef struct ngx_ssl_sess_id_s  ngx_ssl_sess_id_t;
[135] 
[136] struct ngx_ssl_sess_id_s {
[137]     ngx_rbtree_node_t           node;
[138]     size_t                      len;
[139]     ngx_queue_t                 queue;
[140]     time_t                      expire;
[141]     u_char                      id[32];
[142] #if (NGX_PTR_SIZE == 8)
[143]     u_char                     *session;
[144] #else
[145]     u_char                      session[1];
[146] #endif
[147] };
[148] 
[149] 
[150] typedef struct {
[151]     u_char                      name[16];
[152]     u_char                      hmac_key[32];
[153]     u_char                      aes_key[32];
[154]     time_t                      expire;
[155]     unsigned                    size:8;
[156]     unsigned                    shared:1;
[157] } ngx_ssl_ticket_key_t;
[158] 
[159] 
[160] typedef struct {
[161]     ngx_rbtree_t                session_rbtree;
[162]     ngx_rbtree_node_t           sentinel;
[163]     ngx_queue_t                 expire_queue;
[164]     ngx_ssl_ticket_key_t        ticket_keys[3];
[165]     time_t                      fail_time;
[166] } ngx_ssl_session_cache_t;
[167] 
[168] 
[169] #define NGX_SSL_SSLv2    0x0002
[170] #define NGX_SSL_SSLv3    0x0004
[171] #define NGX_SSL_TLSv1    0x0008
[172] #define NGX_SSL_TLSv1_1  0x0010
[173] #define NGX_SSL_TLSv1_2  0x0020
[174] #define NGX_SSL_TLSv1_3  0x0040
[175] 
[176] 
[177] #define NGX_SSL_BUFFER   1
[178] #define NGX_SSL_CLIENT   2
[179] 
[180] #define NGX_SSL_BUFSIZE  16384
[181] 
[182] 
[183] ngx_int_t ngx_ssl_init(ngx_log_t *log);
[184] ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);
[185] 
[186] ngx_int_t ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl,
[187]     ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords);
[188] ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
[189]     ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
[190] ngx_int_t ngx_ssl_connection_certificate(ngx_connection_t *c, ngx_pool_t *pool,
[191]     ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
[192] 
[193] ngx_int_t ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers,
[194]     ngx_uint_t prefer_server_ciphers);
[195] ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
[196]     ngx_str_t *cert, ngx_int_t depth);
[197] ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
[198]     ngx_str_t *cert, ngx_int_t depth);
[199] ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
[200] ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
[201]     ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
[202] ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
[203]     ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
[204] ngx_int_t ngx_ssl_ocsp(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *responder,
[205]     ngx_uint_t depth, ngx_shm_zone_t *shm_zone);
[206] ngx_int_t ngx_ssl_ocsp_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
[207]     ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
[208] 
[209] ngx_int_t ngx_ssl_ocsp_validate(ngx_connection_t *c);
[210] ngx_int_t ngx_ssl_ocsp_get_status(ngx_connection_t *c, const char **s);
[211] void ngx_ssl_ocsp_cleanup(ngx_connection_t *c);
[212] ngx_int_t ngx_ssl_ocsp_cache_init(ngx_shm_zone_t *shm_zone, void *data);
[213] 
[214] ngx_array_t *ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file);
[215] ngx_array_t *ngx_ssl_preserve_passwords(ngx_conf_t *cf,
[216]     ngx_array_t *passwords);
[217] ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
[218] ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);
[219] ngx_int_t ngx_ssl_early_data(ngx_conf_t *cf, ngx_ssl_t *ssl,
[220]     ngx_uint_t enable);
[221] ngx_int_t ngx_ssl_conf_commands(ngx_conf_t *cf, ngx_ssl_t *ssl,
[222]     ngx_array_t *commands);
[223] 
[224] ngx_int_t ngx_ssl_client_session_cache(ngx_conf_t *cf, ngx_ssl_t *ssl,
[225]     ngx_uint_t enable);
[226] ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
[227]     ngx_array_t *certificates, ssize_t builtin_session_cache,
[228]     ngx_shm_zone_t *shm_zone, time_t timeout);
[229] ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
[230]     ngx_array_t *paths);
[231] ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);
[232] 
[233] ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
[234]     ngx_uint_t flags);
[235] 
[236] void ngx_ssl_remove_cached_session(SSL_CTX *ssl, ngx_ssl_session_t *sess);
[237] ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
[238] ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
[239] ngx_ssl_session_t *ngx_ssl_get0_session(ngx_connection_t *c);
[240] #define ngx_ssl_free_session        SSL_SESSION_free
[241] #define ngx_ssl_get_connection(ssl_conn)                                      \
[242]     SSL_get_ex_data(ssl_conn, ngx_ssl_connection_index)
[243] #define ngx_ssl_get_server_conf(ssl_ctx)                                      \
[244]     SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_server_conf_index)
[245] 
[246] #define ngx_ssl_verify_error_optional(n)                                      \
[247]     (n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT                              \
[248]      || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN                             \
[249]      || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY                     \
[250]      || n == X509_V_ERR_CERT_UNTRUSTED                                        \
[251]      || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)
[252] 
[253] ngx_int_t ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name);
[254] 
[255] 
[256] ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
[257]     ngx_str_t *s);
[258] ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
[259]     ngx_str_t *s);
[260] ngx_int_t ngx_ssl_get_ciphers(ngx_connection_t *c, ngx_pool_t *pool,
[261]     ngx_str_t *s);
[262] ngx_int_t ngx_ssl_get_curve(ngx_connection_t *c, ngx_pool_t *pool,
[263]     ngx_str_t *s);
[264] ngx_int_t ngx_ssl_get_curves(ngx_connection_t *c, ngx_pool_t *pool,
[265]     ngx_str_t *s);
[266] ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
[267]     ngx_str_t *s);
[268] ngx_int_t ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool,
[269]     ngx_str_t *s);
[270] ngx_int_t ngx_ssl_get_early_data(ngx_connection_t *c, ngx_pool_t *pool,
[271]     ngx_str_t *s);
[272] ngx_int_t ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool,
[273]     ngx_str_t *s);
[274] ngx_int_t ngx_ssl_get_alpn_protocol(ngx_connection_t *c, ngx_pool_t *pool,
[275]     ngx_str_t *s);
[276] ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
[277]     ngx_str_t *s);
[278] ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
[279]     ngx_str_t *s);
[280] ngx_int_t ngx_ssl_get_escaped_certificate(ngx_connection_t *c, ngx_pool_t *pool,
[281]     ngx_str_t *s);
[282] ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
[283]     ngx_str_t *s);
[284] ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
[285]     ngx_str_t *s);
[286] ngx_int_t ngx_ssl_get_subject_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
[287]     ngx_str_t *s);
[288] ngx_int_t ngx_ssl_get_issuer_dn_legacy(ngx_connection_t *c, ngx_pool_t *pool,
[289]     ngx_str_t *s);
[290] ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
[291]     ngx_str_t *s);
[292] ngx_int_t ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool,
[293]     ngx_str_t *s);
[294] ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
[295]     ngx_str_t *s);
[296] ngx_int_t ngx_ssl_get_client_v_start(ngx_connection_t *c, ngx_pool_t *pool,
[297]     ngx_str_t *s);
[298] ngx_int_t ngx_ssl_get_client_v_end(ngx_connection_t *c, ngx_pool_t *pool,
[299]     ngx_str_t *s);
[300] ngx_int_t ngx_ssl_get_client_v_remain(ngx_connection_t *c, ngx_pool_t *pool,
[301]     ngx_str_t *s);
[302] 
[303] 
[304] ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
[305] ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
[306] ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
[307] ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit);
[308] ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
[309]     off_t limit);
[310] void ngx_ssl_free_buffer(ngx_connection_t *c);
[311] ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
[312] void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[313]     char *fmt, ...);
[314] void ngx_ssl_cleanup_ctx(void *data);
[315] 
[316] 
[317] extern int  ngx_ssl_connection_index;
[318] extern int  ngx_ssl_server_conf_index;
[319] extern int  ngx_ssl_session_cache_index;
[320] extern int  ngx_ssl_ticket_keys_index;
[321] extern int  ngx_ssl_ocsp_index;
[322] extern int  ngx_ssl_certificate_index;
[323] extern int  ngx_ssl_next_certificate_index;
[324] extern int  ngx_ssl_certificate_name_index;
[325] extern int  ngx_ssl_stapling_index;
[326] 
[327] 
[328] #endif /* _NGX_EVENT_OPENSSL_H_INCLUDED_ */
