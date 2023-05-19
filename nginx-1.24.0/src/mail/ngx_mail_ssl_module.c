[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_mail.h>
[11] 
[12] 
[13] #define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
[14] #define NGX_DEFAULT_ECDH_CURVE  "auto"
[15] 
[16] 
[17] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[18] static int ngx_mail_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn,
[19]     const unsigned char **out, unsigned char *outlen,
[20]     const unsigned char *in, unsigned int inlen, void *arg);
[21] #endif
[22] 
[23] static void *ngx_mail_ssl_create_conf(ngx_conf_t *cf);
[24] static char *ngx_mail_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child);
[25] 
[26] static char *ngx_mail_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd,
[27]     void *conf);
[28] static char *ngx_mail_ssl_starttls(ngx_conf_t *cf, ngx_command_t *cmd,
[29]     void *conf);
[30] static char *ngx_mail_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
[31]     void *conf);
[32] static char *ngx_mail_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[33]     void *conf);
[34] 
[35] static char *ngx_mail_ssl_conf_command_check(ngx_conf_t *cf, void *post,
[36]     void *data);
[37] 
[38] 
[39] static ngx_conf_enum_t  ngx_mail_starttls_state[] = {
[40]     { ngx_string("off"), NGX_MAIL_STARTTLS_OFF },
[41]     { ngx_string("on"), NGX_MAIL_STARTTLS_ON },
[42]     { ngx_string("only"), NGX_MAIL_STARTTLS_ONLY },
[43]     { ngx_null_string, 0 }
[44] };
[45] 
[46] 
[47] 
[48] static ngx_conf_bitmask_t  ngx_mail_ssl_protocols[] = {
[49]     { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
[50]     { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
[51]     { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
[52]     { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
[53]     { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
[54]     { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
[55]     { ngx_null_string, 0 }
[56] };
[57] 
[58] 
[59] static ngx_conf_enum_t  ngx_mail_ssl_verify[] = {
[60]     { ngx_string("off"), 0 },
[61]     { ngx_string("on"), 1 },
[62]     { ngx_string("optional"), 2 },
[63]     { ngx_string("optional_no_ca"), 3 },
[64]     { ngx_null_string, 0 }
[65] };
[66] 
[67] 
[68] static ngx_conf_deprecated_t  ngx_mail_ssl_deprecated = {
[69]     ngx_conf_deprecated, "ssl", "listen ... ssl"
[70] };
[71] 
[72] 
[73] static ngx_conf_post_t  ngx_mail_ssl_conf_command_post =
[74]     { ngx_mail_ssl_conf_command_check };
[75] 
[76] 
[77] static ngx_command_t  ngx_mail_ssl_commands[] = {
[78] 
[79]     { ngx_string("ssl"),
[80]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[81]       ngx_mail_ssl_enable,
[82]       NGX_MAIL_SRV_CONF_OFFSET,
[83]       offsetof(ngx_mail_ssl_conf_t, enable),
[84]       &ngx_mail_ssl_deprecated },
[85] 
[86]     { ngx_string("starttls"),
[87]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[88]       ngx_mail_ssl_starttls,
[89]       NGX_MAIL_SRV_CONF_OFFSET,
[90]       offsetof(ngx_mail_ssl_conf_t, starttls),
[91]       ngx_mail_starttls_state },
[92] 
[93]     { ngx_string("ssl_certificate"),
[94]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[95]       ngx_conf_set_str_array_slot,
[96]       NGX_MAIL_SRV_CONF_OFFSET,
[97]       offsetof(ngx_mail_ssl_conf_t, certificates),
[98]       NULL },
[99] 
[100]     { ngx_string("ssl_certificate_key"),
[101]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[102]       ngx_conf_set_str_array_slot,
[103]       NGX_MAIL_SRV_CONF_OFFSET,
[104]       offsetof(ngx_mail_ssl_conf_t, certificate_keys),
[105]       NULL },
[106] 
[107]     { ngx_string("ssl_password_file"),
[108]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[109]       ngx_mail_ssl_password_file,
[110]       NGX_MAIL_SRV_CONF_OFFSET,
[111]       0,
[112]       NULL },
[113] 
[114]     { ngx_string("ssl_dhparam"),
[115]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[116]       ngx_conf_set_str_slot,
[117]       NGX_MAIL_SRV_CONF_OFFSET,
[118]       offsetof(ngx_mail_ssl_conf_t, dhparam),
[119]       NULL },
[120] 
[121]     { ngx_string("ssl_ecdh_curve"),
[122]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[123]       ngx_conf_set_str_slot,
[124]       NGX_MAIL_SRV_CONF_OFFSET,
[125]       offsetof(ngx_mail_ssl_conf_t, ecdh_curve),
[126]       NULL },
[127] 
[128]     { ngx_string("ssl_protocols"),
[129]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[130]       ngx_conf_set_bitmask_slot,
[131]       NGX_MAIL_SRV_CONF_OFFSET,
[132]       offsetof(ngx_mail_ssl_conf_t, protocols),
[133]       &ngx_mail_ssl_protocols },
[134] 
[135]     { ngx_string("ssl_ciphers"),
[136]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[137]       ngx_conf_set_str_slot,
[138]       NGX_MAIL_SRV_CONF_OFFSET,
[139]       offsetof(ngx_mail_ssl_conf_t, ciphers),
[140]       NULL },
[141] 
[142]     { ngx_string("ssl_prefer_server_ciphers"),
[143]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[144]       ngx_conf_set_flag_slot,
[145]       NGX_MAIL_SRV_CONF_OFFSET,
[146]       offsetof(ngx_mail_ssl_conf_t, prefer_server_ciphers),
[147]       NULL },
[148] 
[149]     { ngx_string("ssl_session_cache"),
[150]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE12,
[151]       ngx_mail_ssl_session_cache,
[152]       NGX_MAIL_SRV_CONF_OFFSET,
[153]       0,
[154]       NULL },
[155] 
[156]     { ngx_string("ssl_session_tickets"),
[157]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[158]       ngx_conf_set_flag_slot,
[159]       NGX_MAIL_SRV_CONF_OFFSET,
[160]       offsetof(ngx_mail_ssl_conf_t, session_tickets),
[161]       NULL },
[162] 
[163]     { ngx_string("ssl_session_ticket_key"),
[164]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[165]       ngx_conf_set_str_array_slot,
[166]       NGX_MAIL_SRV_CONF_OFFSET,
[167]       offsetof(ngx_mail_ssl_conf_t, session_ticket_keys),
[168]       NULL },
[169] 
[170]     { ngx_string("ssl_session_timeout"),
[171]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[172]       ngx_conf_set_sec_slot,
[173]       NGX_MAIL_SRV_CONF_OFFSET,
[174]       offsetof(ngx_mail_ssl_conf_t, session_timeout),
[175]       NULL },
[176] 
[177]     { ngx_string("ssl_verify_client"),
[178]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[179]       ngx_conf_set_enum_slot,
[180]       NGX_MAIL_SRV_CONF_OFFSET,
[181]       offsetof(ngx_mail_ssl_conf_t, verify),
[182]       &ngx_mail_ssl_verify },
[183] 
[184]     { ngx_string("ssl_verify_depth"),
[185]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[186]       ngx_conf_set_num_slot,
[187]       NGX_MAIL_SRV_CONF_OFFSET,
[188]       offsetof(ngx_mail_ssl_conf_t, verify_depth),
[189]       NULL },
[190] 
[191]     { ngx_string("ssl_client_certificate"),
[192]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[193]       ngx_conf_set_str_slot,
[194]       NGX_MAIL_SRV_CONF_OFFSET,
[195]       offsetof(ngx_mail_ssl_conf_t, client_certificate),
[196]       NULL },
[197] 
[198]     { ngx_string("ssl_trusted_certificate"),
[199]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[200]       ngx_conf_set_str_slot,
[201]       NGX_MAIL_SRV_CONF_OFFSET,
[202]       offsetof(ngx_mail_ssl_conf_t, trusted_certificate),
[203]       NULL },
[204] 
[205]     { ngx_string("ssl_crl"),
[206]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[207]       ngx_conf_set_str_slot,
[208]       NGX_MAIL_SRV_CONF_OFFSET,
[209]       offsetof(ngx_mail_ssl_conf_t, crl),
[210]       NULL },
[211] 
[212]     { ngx_string("ssl_conf_command"),
[213]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE2,
[214]       ngx_conf_set_keyval_slot,
[215]       NGX_MAIL_SRV_CONF_OFFSET,
[216]       offsetof(ngx_mail_ssl_conf_t, conf_commands),
[217]       &ngx_mail_ssl_conf_command_post },
[218] 
[219]       ngx_null_command
[220] };
[221] 
[222] 
[223] static ngx_mail_module_t  ngx_mail_ssl_module_ctx = {
[224]     NULL,                                  /* protocol */
[225] 
[226]     NULL,                                  /* create main configuration */
[227]     NULL,                                  /* init main configuration */
[228] 
[229]     ngx_mail_ssl_create_conf,              /* create server configuration */
[230]     ngx_mail_ssl_merge_conf                /* merge server configuration */
[231] };
[232] 
[233] 
[234] ngx_module_t  ngx_mail_ssl_module = {
[235]     NGX_MODULE_V1,
[236]     &ngx_mail_ssl_module_ctx,              /* module context */
[237]     ngx_mail_ssl_commands,                 /* module directives */
[238]     NGX_MAIL_MODULE,                       /* module type */
[239]     NULL,                                  /* init master */
[240]     NULL,                                  /* init module */
[241]     NULL,                                  /* init process */
[242]     NULL,                                  /* init thread */
[243]     NULL,                                  /* exit thread */
[244]     NULL,                                  /* exit process */
[245]     NULL,                                  /* exit master */
[246]     NGX_MODULE_V1_PADDING
[247] };
[248] 
[249] 
[250] static ngx_str_t ngx_mail_ssl_sess_id_ctx = ngx_string("MAIL");
[251] 
[252] 
[253] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[254] 
[255] static int
[256] ngx_mail_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn, const unsigned char **out,
[257]     unsigned char *outlen, const unsigned char *in, unsigned int inlen,
[258]     void *arg)
[259] {
[260]     unsigned int               srvlen;
[261]     unsigned char             *srv;
[262]     ngx_connection_t          *c;
[263]     ngx_mail_session_t        *s;
[264]     ngx_mail_core_srv_conf_t  *cscf;
[265] #if (NGX_DEBUG)
[266]     unsigned int               i;
[267] #endif
[268] 
[269]     c = ngx_ssl_get_connection(ssl_conn);
[270]     s = c->data;
[271] 
[272] #if (NGX_DEBUG)
[273]     for (i = 0; i < inlen; i += in[i] + 1) {
[274]         ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
[275]                        "SSL ALPN supported by client: %*s",
[276]                        (size_t) in[i], &in[i + 1]);
[277]     }
[278] #endif
[279] 
[280]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[281] 
[282]     srv = cscf->protocol->alpn.data;
[283]     srvlen = cscf->protocol->alpn.len;
[284] 
[285]     if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
[286]                               in, inlen)
[287]         != OPENSSL_NPN_NEGOTIATED)
[288]     {
[289]         return SSL_TLSEXT_ERR_ALERT_FATAL;
[290]     }
[291] 
[292]     ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
[293]                    "SSL ALPN selected: %*s", (size_t) *outlen, *out);
[294] 
[295]     return SSL_TLSEXT_ERR_OK;
[296] }
[297] 
[298] #endif
[299] 
[300] 
[301] static void *
[302] ngx_mail_ssl_create_conf(ngx_conf_t *cf)
[303] {
[304]     ngx_mail_ssl_conf_t  *scf;
[305] 
[306]     scf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_ssl_conf_t));
[307]     if (scf == NULL) {
[308]         return NULL;
[309]     }
[310] 
[311]     /*
[312]      * set by ngx_pcalloc():
[313]      *
[314]      *     scf->listen = 0;
[315]      *     scf->protocols = 0;
[316]      *     scf->dhparam = { 0, NULL };
[317]      *     scf->ecdh_curve = { 0, NULL };
[318]      *     scf->client_certificate = { 0, NULL };
[319]      *     scf->trusted_certificate = { 0, NULL };
[320]      *     scf->crl = { 0, NULL };
[321]      *     scf->ciphers = { 0, NULL };
[322]      *     scf->shm_zone = NULL;
[323]      */
[324] 
[325]     scf->enable = NGX_CONF_UNSET;
[326]     scf->starttls = NGX_CONF_UNSET_UINT;
[327]     scf->certificates = NGX_CONF_UNSET_PTR;
[328]     scf->certificate_keys = NGX_CONF_UNSET_PTR;
[329]     scf->passwords = NGX_CONF_UNSET_PTR;
[330]     scf->conf_commands = NGX_CONF_UNSET_PTR;
[331]     scf->prefer_server_ciphers = NGX_CONF_UNSET;
[332]     scf->verify = NGX_CONF_UNSET_UINT;
[333]     scf->verify_depth = NGX_CONF_UNSET_UINT;
[334]     scf->builtin_session_cache = NGX_CONF_UNSET;
[335]     scf->session_timeout = NGX_CONF_UNSET;
[336]     scf->session_tickets = NGX_CONF_UNSET;
[337]     scf->session_ticket_keys = NGX_CONF_UNSET_PTR;
[338] 
[339]     return scf;
[340] }
[341] 
[342] 
[343] static char *
[344] ngx_mail_ssl_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[345] {
[346]     ngx_mail_ssl_conf_t *prev = parent;
[347]     ngx_mail_ssl_conf_t *conf = child;
[348] 
[349]     char                *mode;
[350]     ngx_pool_cleanup_t  *cln;
[351] 
[352]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[353]     ngx_conf_merge_uint_value(conf->starttls, prev->starttls,
[354]                          NGX_MAIL_STARTTLS_OFF);
[355] 
[356]     ngx_conf_merge_value(conf->session_timeout,
[357]                          prev->session_timeout, 300);
[358] 
[359]     ngx_conf_merge_value(conf->prefer_server_ciphers,
[360]                          prev->prefer_server_ciphers, 0);
[361] 
[362]     ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
[363]                          (NGX_CONF_BITMASK_SET
[364]                           |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
[365]                           |NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3));
[366] 
[367]     ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
[368]     ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);
[369] 
[370]     ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
[371]     ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
[372]                          NULL);
[373] 
[374]     ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);
[375] 
[376]     ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");
[377] 
[378]     ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
[379]                          NGX_DEFAULT_ECDH_CURVE);
[380] 
[381]     ngx_conf_merge_str_value(conf->client_certificate,
[382]                          prev->client_certificate, "");
[383]     ngx_conf_merge_str_value(conf->trusted_certificate,
[384]                          prev->trusted_certificate, "");
[385]     ngx_conf_merge_str_value(conf->crl, prev->crl, "");
[386] 
[387]     ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);
[388] 
[389]     ngx_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);
[390] 
[391] 
[392]     conf->ssl.log = cf->log;
[393] 
[394]     if (conf->listen) {
[395]         mode = "listen ... ssl";
[396] 
[397]     } else if (conf->enable) {
[398]         mode = "ssl";
[399] 
[400]     } else if (conf->starttls != NGX_MAIL_STARTTLS_OFF) {
[401]         mode = "starttls";
[402] 
[403]     } else {
[404]         return NGX_CONF_OK;
[405]     }
[406] 
[407]     if (conf->file == NULL) {
[408]         conf->file = prev->file;
[409]         conf->line = prev->line;
[410]     }
[411] 
[412]     if (conf->certificates == NULL) {
[413]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[414]                       "no \"ssl_certificate\" is defined for "
[415]                       "the \"%s\" directive in %s:%ui",
[416]                       mode, conf->file, conf->line);
[417]         return NGX_CONF_ERROR;
[418]     }
[419] 
[420]     if (conf->certificate_keys == NULL) {
[421]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[422]                       "no \"ssl_certificate_key\" is defined for "
[423]                       "the \"%s\" directive in %s:%ui",
[424]                       mode, conf->file, conf->line);
[425]         return NGX_CONF_ERROR;
[426]     }
[427] 
[428]     if (conf->certificate_keys->nelts < conf->certificates->nelts) {
[429]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[430]                       "no \"ssl_certificate_key\" is defined "
[431]                       "for certificate \"%V\" and "
[432]                       "the \"%s\" directive in %s:%ui",
[433]                       ((ngx_str_t *) conf->certificates->elts)
[434]                       + conf->certificates->nelts - 1,
[435]                       mode, conf->file, conf->line);
[436]         return NGX_CONF_ERROR;
[437]     }
[438] 
[439]     if (ngx_ssl_create(&conf->ssl, conf->protocols, NULL) != NGX_OK) {
[440]         return NGX_CONF_ERROR;
[441]     }
[442] 
[443]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[444]     if (cln == NULL) {
[445]         ngx_ssl_cleanup_ctx(&conf->ssl);
[446]         return NGX_CONF_ERROR;
[447]     }
[448] 
[449]     cln->handler = ngx_ssl_cleanup_ctx;
[450]     cln->data = &conf->ssl;
[451] 
[452] #ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
[453]     SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, ngx_mail_ssl_alpn_select, NULL);
[454] #endif
[455] 
[456]     if (ngx_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
[457]                         conf->prefer_server_ciphers)
[458]         != NGX_OK)
[459]     {
[460]         return NGX_CONF_ERROR;
[461]     }
[462] 
[463]     if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
[464]                              conf->certificate_keys, conf->passwords)
[465]         != NGX_OK)
[466]     {
[467]         return NGX_CONF_ERROR;
[468]     }
[469] 
[470]     if (conf->verify) {
[471] 
[472]         if (conf->client_certificate.len == 0 && conf->verify != 3) {
[473]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[474]                           "no ssl_client_certificate for ssl_verify_client");
[475]             return NGX_CONF_ERROR;
[476]         }
[477] 
[478]         if (ngx_ssl_client_certificate(cf, &conf->ssl,
[479]                                        &conf->client_certificate,
[480]                                        conf->verify_depth)
[481]             != NGX_OK)
[482]         {
[483]             return NGX_CONF_ERROR;
[484]         }
[485] 
[486]         if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
[487]                                         &conf->trusted_certificate,
[488]                                         conf->verify_depth)
[489]             != NGX_OK)
[490]         {
[491]             return NGX_CONF_ERROR;
[492]         }
[493] 
[494]         if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
[495]             return NGX_CONF_ERROR;
[496]         }
[497]     }
[498] 
[499]     if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
[500]         return NGX_CONF_ERROR;
[501]     }
[502] 
[503]     if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
[504]         return NGX_CONF_ERROR;
[505]     }
[506] 
[507]     ngx_conf_merge_value(conf->builtin_session_cache,
[508]                          prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);
[509] 
[510]     if (conf->shm_zone == NULL) {
[511]         conf->shm_zone = prev->shm_zone;
[512]     }
[513] 
[514]     if (ngx_ssl_session_cache(&conf->ssl, &ngx_mail_ssl_sess_id_ctx,
[515]                               conf->certificates, conf->builtin_session_cache,
[516]                               conf->shm_zone, conf->session_timeout)
[517]         != NGX_OK)
[518]     {
[519]         return NGX_CONF_ERROR;
[520]     }
[521] 
[522]     ngx_conf_merge_value(conf->session_tickets,
[523]                          prev->session_tickets, 1);
[524] 
[525] #ifdef SSL_OP_NO_TICKET
[526]     if (!conf->session_tickets) {
[527]         SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
[528]     }
[529] #endif
[530] 
[531]     ngx_conf_merge_ptr_value(conf->session_ticket_keys,
[532]                          prev->session_ticket_keys, NULL);
[533] 
[534]     if (ngx_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
[535]         != NGX_OK)
[536]     {
[537]         return NGX_CONF_ERROR;
[538]     }
[539] 
[540]     if (ngx_ssl_conf_commands(cf, &conf->ssl, conf->conf_commands) != NGX_OK) {
[541]         return NGX_CONF_ERROR;
[542]     }
[543] 
[544]     return NGX_CONF_OK;
[545] }
[546] 
[547] 
[548] static char *
[549] ngx_mail_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[550] {
[551]     ngx_mail_ssl_conf_t  *scf = conf;
[552] 
[553]     char  *rv;
[554] 
[555]     rv = ngx_conf_set_flag_slot(cf, cmd, conf);
[556] 
[557]     if (rv != NGX_CONF_OK) {
[558]         return rv;
[559]     }
[560] 
[561]     if (scf->enable && (ngx_int_t) scf->starttls > NGX_MAIL_STARTTLS_OFF) {
[562]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[563]                            "\"starttls\" directive conflicts with \"ssl on\"");
[564]         return NGX_CONF_ERROR;
[565]     }
[566] 
[567]     if (!scf->listen) {
[568]         scf->file = cf->conf_file->file.name.data;
[569]         scf->line = cf->conf_file->line;
[570]     }
[571] 
[572]     return NGX_CONF_OK;
[573] }
[574] 
[575] 
[576] static char *
[577] ngx_mail_ssl_starttls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[578] {
[579]     ngx_mail_ssl_conf_t  *scf = conf;
[580] 
[581]     char  *rv;
[582] 
[583]     rv = ngx_conf_set_enum_slot(cf, cmd, conf);
[584] 
[585]     if (rv != NGX_CONF_OK) {
[586]         return rv;
[587]     }
[588] 
[589]     if (scf->enable == 1 && (ngx_int_t) scf->starttls > NGX_MAIL_STARTTLS_OFF) {
[590]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[591]                            "\"ssl\" directive conflicts with \"starttls\"");
[592]         return NGX_CONF_ERROR;
[593]     }
[594] 
[595]     if (!scf->listen) {
[596]         scf->file = cf->conf_file->file.name.data;
[597]         scf->line = cf->conf_file->line;
[598]     }
[599] 
[600]     return NGX_CONF_OK;
[601] }
[602] 
[603] 
[604] static char *
[605] ngx_mail_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[606] {
[607]     ngx_mail_ssl_conf_t  *scf = conf;
[608] 
[609]     ngx_str_t  *value;
[610] 
[611]     if (scf->passwords != NGX_CONF_UNSET_PTR) {
[612]         return "is duplicate";
[613]     }
[614] 
[615]     value = cf->args->elts;
[616] 
[617]     scf->passwords = ngx_ssl_read_password_file(cf, &value[1]);
[618] 
[619]     if (scf->passwords == NULL) {
[620]         return NGX_CONF_ERROR;
[621]     }
[622] 
[623]     return NGX_CONF_OK;
[624] }
[625] 
[626] 
[627] static char *
[628] ngx_mail_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[629] {
[630]     ngx_mail_ssl_conf_t  *scf = conf;
[631] 
[632]     size_t       len;
[633]     ngx_str_t   *value, name, size;
[634]     ngx_int_t    n;
[635]     ngx_uint_t   i, j;
[636] 
[637]     value = cf->args->elts;
[638] 
[639]     for (i = 1; i < cf->args->nelts; i++) {
[640] 
[641]         if (ngx_strcmp(value[i].data, "off") == 0) {
[642]             scf->builtin_session_cache = NGX_SSL_NO_SCACHE;
[643]             continue;
[644]         }
[645] 
[646]         if (ngx_strcmp(value[i].data, "none") == 0) {
[647]             scf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
[648]             continue;
[649]         }
[650] 
[651]         if (ngx_strcmp(value[i].data, "builtin") == 0) {
[652]             scf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
[653]             continue;
[654]         }
[655] 
[656]         if (value[i].len > sizeof("builtin:") - 1
[657]             && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
[658]                == 0)
[659]         {
[660]             n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
[661]                          value[i].len - (sizeof("builtin:") - 1));
[662] 
[663]             if (n == NGX_ERROR) {
[664]                 goto invalid;
[665]             }
[666] 
[667]             scf->builtin_session_cache = n;
[668] 
[669]             continue;
[670]         }
[671] 
[672]         if (value[i].len > sizeof("shared:") - 1
[673]             && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
[674]                == 0)
[675]         {
[676]             len = 0;
[677] 
[678]             for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
[679]                 if (value[i].data[j] == ':') {
[680]                     break;
[681]                 }
[682] 
[683]                 len++;
[684]             }
[685] 
[686]             if (len == 0 || j == value[i].len) {
[687]                 goto invalid;
[688]             }
[689] 
[690]             name.len = len;
[691]             name.data = value[i].data + sizeof("shared:") - 1;
[692] 
[693]             size.len = value[i].len - j - 1;
[694]             size.data = name.data + len + 1;
[695] 
[696]             n = ngx_parse_size(&size);
[697] 
[698]             if (n == NGX_ERROR) {
[699]                 goto invalid;
[700]             }
[701] 
[702]             if (n < (ngx_int_t) (8 * ngx_pagesize)) {
[703]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[704]                                    "session cache \"%V\" is too small",
[705]                                    &value[i]);
[706] 
[707]                 return NGX_CONF_ERROR;
[708]             }
[709] 
[710]             scf->shm_zone = ngx_shared_memory_add(cf, &name, n,
[711]                                                    &ngx_mail_ssl_module);
[712]             if (scf->shm_zone == NULL) {
[713]                 return NGX_CONF_ERROR;
[714]             }
[715] 
[716]             scf->shm_zone->init = ngx_ssl_session_cache_init;
[717] 
[718]             continue;
[719]         }
[720] 
[721]         goto invalid;
[722]     }
[723] 
[724]     if (scf->shm_zone && scf->builtin_session_cache == NGX_CONF_UNSET) {
[725]         scf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
[726]     }
[727] 
[728]     return NGX_CONF_OK;
[729] 
[730] invalid:
[731] 
[732]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[733]                        "invalid session cache \"%V\"", &value[i]);
[734] 
[735]     return NGX_CONF_ERROR;
[736] }
[737] 
[738] 
[739] static char *
[740] ngx_mail_ssl_conf_command_check(ngx_conf_t *cf, void *post, void *data)
[741] {
[742] #ifndef SSL_CONF_FLAG_FILE
[743]     return "is not supported on this platform";
[744] #else
[745]     return NGX_CONF_OK;
[746] #endif
[747] }
