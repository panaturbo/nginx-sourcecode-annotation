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
[11] #include <ngx_mail.h>
[12] 
[13] 
[14] static void ngx_mail_proxy_protocol_handler(ngx_event_t *rev);
[15] static void ngx_mail_init_session_handler(ngx_event_t *rev);
[16] static void ngx_mail_init_session(ngx_connection_t *c);
[17] 
[18] #if (NGX_MAIL_SSL)
[19] static void ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
[20] static void ngx_mail_ssl_handshake_handler(ngx_connection_t *c);
[21] static ngx_int_t ngx_mail_verify_cert(ngx_mail_session_t *s,
[22]     ngx_connection_t *c);
[23] #endif
[24] 
[25] 
[26] void
[27] ngx_mail_init_connection(ngx_connection_t *c)
[28] {
[29]     size_t                     len;
[30]     ngx_uint_t                 i;
[31]     ngx_event_t               *rev;
[32]     ngx_mail_port_t           *port;
[33]     struct sockaddr           *sa;
[34]     struct sockaddr_in        *sin;
[35]     ngx_mail_log_ctx_t        *ctx;
[36]     ngx_mail_in_addr_t        *addr;
[37]     ngx_mail_session_t        *s;
[38]     ngx_mail_addr_conf_t      *addr_conf;
[39]     ngx_mail_core_srv_conf_t  *cscf;
[40]     u_char                     text[NGX_SOCKADDR_STRLEN];
[41] #if (NGX_HAVE_INET6)
[42]     struct sockaddr_in6       *sin6;
[43]     ngx_mail_in6_addr_t       *addr6;
[44] #endif
[45] 
[46] 
[47]     /* find the server configuration for the address:port */
[48] 
[49]     port = c->listening->servers;
[50] 
[51]     if (port->naddrs > 1) {
[52] 
[53]         /*
[54]          * There are several addresses on this port and one of them
[55]          * is the "*:port" wildcard so getsockname() is needed to determine
[56]          * the server address.
[57]          *
[58]          * AcceptEx() already gave this address.
[59]          */
[60] 
[61]         if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
[62]             ngx_mail_close_connection(c);
[63]             return;
[64]         }
[65] 
[66]         sa = c->local_sockaddr;
[67] 
[68]         switch (sa->sa_family) {
[69] 
[70] #if (NGX_HAVE_INET6)
[71]         case AF_INET6:
[72]             sin6 = (struct sockaddr_in6 *) sa;
[73] 
[74]             addr6 = port->addrs;
[75] 
[76]             /* the last address is "*" */
[77] 
[78]             for (i = 0; i < port->naddrs - 1; i++) {
[79]                 if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
[80]                     break;
[81]                 }
[82]             }
[83] 
[84]             addr_conf = &addr6[i].conf;
[85] 
[86]             break;
[87] #endif
[88] 
[89]         default: /* AF_INET */
[90]             sin = (struct sockaddr_in *) sa;
[91] 
[92]             addr = port->addrs;
[93] 
[94]             /* the last address is "*" */
[95] 
[96]             for (i = 0; i < port->naddrs - 1; i++) {
[97]                 if (addr[i].addr == sin->sin_addr.s_addr) {
[98]                     break;
[99]                 }
[100]             }
[101] 
[102]             addr_conf = &addr[i].conf;
[103] 
[104]             break;
[105]         }
[106] 
[107]     } else {
[108]         switch (c->local_sockaddr->sa_family) {
[109] 
[110] #if (NGX_HAVE_INET6)
[111]         case AF_INET6:
[112]             addr6 = port->addrs;
[113]             addr_conf = &addr6[0].conf;
[114]             break;
[115] #endif
[116] 
[117]         default: /* AF_INET */
[118]             addr = port->addrs;
[119]             addr_conf = &addr[0].conf;
[120]             break;
[121]         }
[122]     }
[123] 
[124]     s = ngx_pcalloc(c->pool, sizeof(ngx_mail_session_t));
[125]     if (s == NULL) {
[126]         ngx_mail_close_connection(c);
[127]         return;
[128]     }
[129] 
[130]     s->signature = NGX_MAIL_MODULE;
[131] 
[132]     s->main_conf = addr_conf->ctx->main_conf;
[133]     s->srv_conf = addr_conf->ctx->srv_conf;
[134] 
[135] #if (NGX_MAIL_SSL)
[136]     s->ssl = addr_conf->ssl;
[137] #endif
[138] 
[139]     s->addr_text = &addr_conf->addr_text;
[140] 
[141]     c->data = s;
[142]     s->connection = c;
[143] 
[144]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[145] 
[146]     ngx_set_connection_log(c, cscf->error_log);
[147] 
[148]     len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);
[149] 
[150]     ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%uA client %*s connected to %V",
[151]                   c->number, len, text, s->addr_text);
[152] 
[153]     ctx = ngx_palloc(c->pool, sizeof(ngx_mail_log_ctx_t));
[154]     if (ctx == NULL) {
[155]         ngx_mail_close_connection(c);
[156]         return;
[157]     }
[158] 
[159]     ctx->client = &c->addr_text;
[160]     ctx->session = s;
[161] 
[162]     c->log->connection = c->number;
[163]     c->log->handler = ngx_mail_log_error;
[164]     c->log->data = ctx;
[165]     c->log->action = "sending client greeting line";
[166] 
[167]     c->log_error = NGX_ERROR_INFO;
[168] 
[169]     rev = c->read;
[170]     rev->handler = ngx_mail_init_session_handler;
[171] 
[172]     if (addr_conf->proxy_protocol) {
[173]         c->log->action = "reading PROXY protocol";
[174] 
[175]         rev->handler = ngx_mail_proxy_protocol_handler;
[176] 
[177]         if (!rev->ready) {
[178]             ngx_add_timer(rev, cscf->timeout);
[179] 
[180]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[181]                 ngx_mail_close_connection(c);
[182]             }
[183] 
[184]             return;
[185]         }
[186]     }
[187] 
[188]     if (ngx_use_accept_mutex) {
[189]         ngx_post_event(rev, &ngx_posted_events);
[190]         return;
[191]     }
[192] 
[193]     rev->handler(rev);
[194] }
[195] 
[196] 
[197] static void
[198] ngx_mail_proxy_protocol_handler(ngx_event_t *rev)
[199] {
[200]     u_char                    *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER];
[201]     size_t                     size;
[202]     ssize_t                    n;
[203]     ngx_err_t                  err;
[204]     ngx_connection_t          *c;
[205]     ngx_mail_session_t        *s;
[206]     ngx_mail_core_srv_conf_t  *cscf;
[207] 
[208]     c = rev->data;
[209]     s = c->data;
[210] 
[211]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0,
[212]                    "mail PROXY protocol handler");
[213] 
[214]     if (rev->timedout) {
[215]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[216]         c->timedout = 1;
[217]         ngx_mail_close_connection(c);
[218]         return;
[219]     }
[220] 
[221]     n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);
[222] 
[223]     err = ngx_socket_errno;
[224] 
[225]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "recv(): %z", n);
[226] 
[227]     if (n == -1) {
[228]         if (err == NGX_EAGAIN) {
[229]             rev->ready = 0;
[230] 
[231]             if (!rev->timer_set) {
[232]                 cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[233]                 ngx_add_timer(rev, cscf->timeout);
[234]             }
[235] 
[236]             if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[237]                 ngx_mail_close_connection(c);
[238]             }
[239] 
[240]             return;
[241]         }
[242] 
[243]         ngx_connection_error(c, err, "recv() failed");
[244] 
[245]         ngx_mail_close_connection(c);
[246]         return;
[247]     }
[248] 
[249]     p = ngx_proxy_protocol_read(c, buf, buf + n);
[250] 
[251]     if (p == NULL) {
[252]         ngx_mail_close_connection(c);
[253]         return;
[254]     }
[255] 
[256]     size = p - buf;
[257] 
[258]     if (c->recv(c, buf, size) != (ssize_t) size) {
[259]         ngx_mail_close_connection(c);
[260]         return;
[261]     }
[262] 
[263]     if (ngx_mail_realip_handler(s) != NGX_OK) {
[264]         ngx_mail_close_connection(c);
[265]         return;
[266]     }
[267] 
[268]     ngx_mail_init_session_handler(rev);
[269] }
[270] 
[271] 
[272] static void
[273] ngx_mail_init_session_handler(ngx_event_t *rev)
[274] {
[275]     ngx_connection_t  *c;
[276] 
[277]     c = rev->data;
[278] 
[279] #if (NGX_MAIL_SSL)
[280]     {
[281]     ngx_mail_session_t   *s;
[282]     ngx_mail_ssl_conf_t  *sslcf;
[283] 
[284]     s = c->data;
[285] 
[286]     sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[287] 
[288]     if (sslcf->enable || s->ssl) {
[289]         c->log->action = "SSL handshaking";
[290] 
[291]         ngx_mail_ssl_init_connection(&sslcf->ssl, c);
[292]         return;
[293]     }
[294] 
[295]     }
[296] #endif
[297] 
[298]     ngx_mail_init_session(c);
[299] }
[300] 
[301] 
[302] #if (NGX_MAIL_SSL)
[303] 
[304] void
[305] ngx_mail_starttls_handler(ngx_event_t *rev)
[306] {
[307]     ngx_connection_t     *c;
[308]     ngx_mail_session_t   *s;
[309]     ngx_mail_ssl_conf_t  *sslcf;
[310] 
[311]     c = rev->data;
[312]     s = c->data;
[313]     s->starttls = 1;
[314] 
[315]     c->log->action = "in starttls state";
[316] 
[317]     sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[318] 
[319]     ngx_mail_ssl_init_connection(&sslcf->ssl, c);
[320] }
[321] 
[322] 
[323] static void
[324] ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c)
[325] {
[326]     ngx_mail_session_t        *s;
[327]     ngx_mail_core_srv_conf_t  *cscf;
[328] 
[329]     if (ngx_ssl_create_connection(ssl, c, 0) != NGX_OK) {
[330]         ngx_mail_close_connection(c);
[331]         return;
[332]     }
[333] 
[334]     if (ngx_ssl_handshake(c) == NGX_AGAIN) {
[335] 
[336]         s = c->data;
[337] 
[338]         if (!c->read->timer_set) {
[339]             cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[340]             ngx_add_timer(c->read, cscf->timeout);
[341]         }
[342] 
[343]         c->ssl->handler = ngx_mail_ssl_handshake_handler;
[344] 
[345]         return;
[346]     }
[347] 
[348]     ngx_mail_ssl_handshake_handler(c);
[349] }
[350] 
[351] 
[352] static void
[353] ngx_mail_ssl_handshake_handler(ngx_connection_t *c)
[354] {
[355]     ngx_mail_session_t        *s;
[356]     ngx_mail_core_srv_conf_t  *cscf;
[357] 
[358]     if (c->ssl->handshaked) {
[359] 
[360]         s = c->data;
[361] 
[362]         if (ngx_mail_verify_cert(s, c) != NGX_OK) {
[363]             return;
[364]         }
[365] 
[366]         if (s->starttls) {
[367]             cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[368] 
[369]             c->read->handler = cscf->protocol->init_protocol;
[370]             c->write->handler = ngx_mail_send;
[371] 
[372]             cscf->protocol->init_protocol(c->read);
[373] 
[374]             return;
[375]         }
[376] 
[377]         c->read->ready = 0;
[378] 
[379]         ngx_mail_init_session(c);
[380]         return;
[381]     }
[382] 
[383]     ngx_mail_close_connection(c);
[384] }
[385] 
[386] 
[387] static ngx_int_t
[388] ngx_mail_verify_cert(ngx_mail_session_t *s, ngx_connection_t *c)
[389] {
[390]     long                       rc;
[391]     X509                      *cert;
[392]     ngx_mail_ssl_conf_t       *sslcf;
[393]     ngx_mail_core_srv_conf_t  *cscf;
[394] 
[395]     sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[396] 
[397]     if (!sslcf->verify) {
[398]         return NGX_OK;
[399]     }
[400] 
[401]     rc = SSL_get_verify_result(c->ssl->connection);
[402] 
[403]     if (rc != X509_V_OK
[404]         && (sslcf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
[405]     {
[406]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[407]                       "client SSL certificate verify error: (%l:%s)",
[408]                       rc, X509_verify_cert_error_string(rc));
[409] 
[410]         ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[411]                                       (SSL_get0_session(c->ssl->connection)));
[412] 
[413]         cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[414] 
[415]         s->out = cscf->protocol->cert_error;
[416]         s->quit = 1;
[417] 
[418]         c->write->handler = ngx_mail_send;
[419] 
[420]         ngx_mail_send(s->connection->write);
[421]         return NGX_ERROR;
[422]     }
[423] 
[424]     if (sslcf->verify == 1) {
[425]         cert = SSL_get_peer_certificate(c->ssl->connection);
[426] 
[427]         if (cert == NULL) {
[428]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[429]                           "client sent no required SSL certificate");
[430] 
[431]             ngx_ssl_remove_cached_session(c->ssl->session_ctx,
[432]                                        (SSL_get0_session(c->ssl->connection)));
[433] 
[434]             cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[435] 
[436]             s->out = cscf->protocol->no_cert;
[437]             s->quit = 1;
[438] 
[439]             c->write->handler = ngx_mail_send;
[440] 
[441]             ngx_mail_send(s->connection->write);
[442]             return NGX_ERROR;
[443]         }
[444] 
[445]         X509_free(cert);
[446]     }
[447] 
[448]     return NGX_OK;
[449] }
[450] 
[451] #endif
[452] 
[453] 
[454] static void
[455] ngx_mail_init_session(ngx_connection_t *c)
[456] {
[457]     ngx_mail_session_t        *s;
[458]     ngx_mail_core_srv_conf_t  *cscf;
[459] 
[460]     s = c->data;
[461] 
[462]     c->log->action = "sending client greeting line";
[463] 
[464]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[465] 
[466]     s->protocol = cscf->protocol->type;
[467] 
[468]     s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_mail_max_module);
[469]     if (s->ctx == NULL) {
[470]         ngx_mail_session_internal_server_error(s);
[471]         return;
[472]     }
[473] 
[474]     c->write->handler = ngx_mail_send;
[475] 
[476]     cscf->protocol->init_session(s, c);
[477] }
[478] 
[479] 
[480] ngx_int_t
[481] ngx_mail_salt(ngx_mail_session_t *s, ngx_connection_t *c,
[482]     ngx_mail_core_srv_conf_t *cscf)
[483] {
[484]     s->salt.data = ngx_pnalloc(c->pool,
[485]                                sizeof(" <18446744073709551616.@>" CRLF) - 1
[486]                                + NGX_TIME_T_LEN
[487]                                + cscf->server_name.len);
[488]     if (s->salt.data == NULL) {
[489]         return NGX_ERROR;
[490]     }
[491] 
[492]     s->salt.len = ngx_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
[493]                               ngx_random(), ngx_time(), &cscf->server_name)
[494]                   - s->salt.data;
[495] 
[496]     return NGX_OK;
[497] }
[498] 
[499] 
[500] #if (NGX_MAIL_SSL)
[501] 
[502] ngx_int_t
[503] ngx_mail_starttls_only(ngx_mail_session_t *s, ngx_connection_t *c)
[504] {
[505]     ngx_mail_ssl_conf_t  *sslcf;
[506] 
[507]     if (c->ssl) {
[508]         return 0;
[509]     }
[510] 
[511]     sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[512] 
[513]     if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
[514]         return 1;
[515]     }
[516] 
[517]     return 0;
[518] }
[519] 
[520] #endif
[521] 
[522] 
[523] ngx_int_t
[524] ngx_mail_auth_plain(ngx_mail_session_t *s, ngx_connection_t *c, ngx_uint_t n)
[525] {
[526]     u_char     *p, *last;
[527]     ngx_str_t  *arg, plain;
[528] 
[529]     arg = s->args.elts;
[530] 
[531] #if (NGX_DEBUG_MAIL_PASSWD)
[532]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[533]                    "mail auth plain: \"%V\"", &arg[n]);
[534] #endif
[535] 
[536]     plain.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
[537]     if (plain.data == NULL) {
[538]         return NGX_ERROR;
[539]     }
[540] 
[541]     if (ngx_decode_base64(&plain, &arg[n]) != NGX_OK) {
[542]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[543]             "client sent invalid base64 encoding in AUTH PLAIN command");
[544]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[545]     }
[546] 
[547]     p = plain.data;
[548]     last = p + plain.len;
[549] 
[550]     while (p < last && *p++) { /* void */ }
[551] 
[552]     if (p == last) {
[553]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[554]                       "client sent invalid login in AUTH PLAIN command");
[555]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[556]     }
[557] 
[558]     s->login.data = p;
[559] 
[560]     while (p < last && *p) { p++; }
[561] 
[562]     if (p == last) {
[563]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[564]                       "client sent invalid password in AUTH PLAIN command");
[565]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[566]     }
[567] 
[568]     s->login.len = p++ - s->login.data;
[569] 
[570]     s->passwd.len = last - p;
[571]     s->passwd.data = p;
[572] 
[573] #if (NGX_DEBUG_MAIL_PASSWD)
[574]     ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
[575]                    "mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
[576] #endif
[577] 
[578]     return NGX_DONE;
[579] }
[580] 
[581] 
[582] ngx_int_t
[583] ngx_mail_auth_login_username(ngx_mail_session_t *s, ngx_connection_t *c,
[584]     ngx_uint_t n)
[585] {
[586]     ngx_str_t  *arg;
[587] 
[588]     arg = s->args.elts;
[589] 
[590]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[591]                    "mail auth login username: \"%V\"", &arg[n]);
[592] 
[593]     s->login.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
[594]     if (s->login.data == NULL) {
[595]         return NGX_ERROR;
[596]     }
[597] 
[598]     if (ngx_decode_base64(&s->login, &arg[n]) != NGX_OK) {
[599]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[600]             "client sent invalid base64 encoding in AUTH LOGIN command");
[601]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[602]     }
[603] 
[604]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[605]                    "mail auth login username: \"%V\"", &s->login);
[606] 
[607]     return NGX_OK;
[608] }
[609] 
[610] 
[611] ngx_int_t
[612] ngx_mail_auth_login_password(ngx_mail_session_t *s, ngx_connection_t *c)
[613] {
[614]     ngx_str_t  *arg;
[615] 
[616]     arg = s->args.elts;
[617] 
[618] #if (NGX_DEBUG_MAIL_PASSWD)
[619]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[620]                    "mail auth login password: \"%V\"", &arg[0]);
[621] #endif
[622] 
[623]     s->passwd.data = ngx_pnalloc(c->pool,
[624]                                  ngx_base64_decoded_length(arg[0].len));
[625]     if (s->passwd.data == NULL) {
[626]         return NGX_ERROR;
[627]     }
[628] 
[629]     if (ngx_decode_base64(&s->passwd, &arg[0]) != NGX_OK) {
[630]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[631]             "client sent invalid base64 encoding in AUTH LOGIN command");
[632]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[633]     }
[634] 
[635] #if (NGX_DEBUG_MAIL_PASSWD)
[636]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[637]                    "mail auth login password: \"%V\"", &s->passwd);
[638] #endif
[639] 
[640]     return NGX_DONE;
[641] }
[642] 
[643] 
[644] ngx_int_t
[645] ngx_mail_auth_cram_md5_salt(ngx_mail_session_t *s, ngx_connection_t *c,
[646]     char *prefix, size_t len)
[647] {
[648]     u_char      *p;
[649]     ngx_str_t    salt;
[650]     ngx_uint_t   n;
[651] 
[652]     p = ngx_pnalloc(c->pool, len + ngx_base64_encoded_length(s->salt.len) + 2);
[653]     if (p == NULL) {
[654]         return NGX_ERROR;
[655]     }
[656] 
[657]     salt.data = ngx_cpymem(p, prefix, len);
[658]     s->salt.len -= 2;
[659] 
[660]     ngx_encode_base64(&salt, &s->salt);
[661] 
[662]     s->salt.len += 2;
[663]     n = len + salt.len;
[664]     p[n++] = CR; p[n++] = LF;
[665] 
[666]     s->out.len = n;
[667]     s->out.data = p;
[668] 
[669]     return NGX_OK;
[670] }
[671] 
[672] 
[673] ngx_int_t
[674] ngx_mail_auth_cram_md5(ngx_mail_session_t *s, ngx_connection_t *c)
[675] {
[676]     u_char     *p, *last;
[677]     ngx_str_t  *arg;
[678] 
[679]     arg = s->args.elts;
[680] 
[681]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[682]                    "mail auth cram-md5: \"%V\"", &arg[0]);
[683] 
[684]     s->login.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[0].len));
[685]     if (s->login.data == NULL) {
[686]         return NGX_ERROR;
[687]     }
[688] 
[689]     if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
[690]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[691]             "client sent invalid base64 encoding in AUTH CRAM-MD5 command");
[692]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[693]     }
[694] 
[695]     p = s->login.data;
[696]     last = p + s->login.len;
[697] 
[698]     while (p < last) {
[699]         if (*p++ == ' ') {
[700]             s->login.len = p - s->login.data - 1;
[701]             s->passwd.len = last - p;
[702]             s->passwd.data = p;
[703]             break;
[704]         }
[705]     }
[706] 
[707]     if (s->passwd.len != 32) {
[708]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[709]             "client sent invalid CRAM-MD5 hash in AUTH CRAM-MD5 command");
[710]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[711]     }
[712] 
[713]     ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
[714]                    "mail auth cram-md5: \"%V\" \"%V\"", &s->login, &s->passwd);
[715] 
[716]     s->auth_method = NGX_MAIL_AUTH_CRAM_MD5;
[717] 
[718]     return NGX_DONE;
[719] }
[720] 
[721] 
[722] ngx_int_t
[723] ngx_mail_auth_external(ngx_mail_session_t *s, ngx_connection_t *c,
[724]     ngx_uint_t n)
[725] {
[726]     ngx_str_t  *arg, external;
[727] 
[728]     arg = s->args.elts;
[729] 
[730]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[731]                    "mail auth external: \"%V\"", &arg[n]);
[732] 
[733]     external.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
[734]     if (external.data == NULL) {
[735]         return NGX_ERROR;
[736]     }
[737] 
[738]     if (ngx_decode_base64(&external, &arg[n]) != NGX_OK) {
[739]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[740]             "client sent invalid base64 encoding in AUTH EXTERNAL command");
[741]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[742]     }
[743] 
[744]     s->login.len = external.len;
[745]     s->login.data = external.data;
[746] 
[747]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[748]                    "mail auth external: \"%V\"", &s->login);
[749] 
[750]     s->auth_method = NGX_MAIL_AUTH_EXTERNAL;
[751] 
[752]     return NGX_DONE;
[753] }
[754] 
[755] 
[756] void
[757] ngx_mail_send(ngx_event_t *wev)
[758] {
[759]     ngx_int_t                  n;
[760]     ngx_connection_t          *c;
[761]     ngx_mail_session_t        *s;
[762]     ngx_mail_core_srv_conf_t  *cscf;
[763] 
[764]     c = wev->data;
[765]     s = c->data;
[766] 
[767]     if (wev->timedout) {
[768]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[769]         c->timedout = 1;
[770]         ngx_mail_close_connection(c);
[771]         return;
[772]     }
[773] 
[774]     if (s->out.len == 0) {
[775]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[776]             ngx_mail_close_connection(c);
[777]         }
[778] 
[779]         return;
[780]     }
[781] 
[782]     n = c->send(c, s->out.data, s->out.len);
[783] 
[784]     if (n > 0) {
[785]         s->out.data += n;
[786]         s->out.len -= n;
[787] 
[788]         if (s->out.len != 0) {
[789]             goto again;
[790]         }
[791] 
[792]         if (wev->timer_set) {
[793]             ngx_del_timer(wev);
[794]         }
[795] 
[796]         if (s->quit) {
[797]             ngx_mail_close_connection(c);
[798]             return;
[799]         }
[800] 
[801]         if (s->blocked) {
[802]             c->read->handler(c->read);
[803]         }
[804] 
[805]         return;
[806]     }
[807] 
[808]     if (n == NGX_ERROR) {
[809]         ngx_mail_close_connection(c);
[810]         return;
[811]     }
[812] 
[813]     /* n == NGX_AGAIN */
[814] 
[815] again:
[816] 
[817]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[818] 
[819]     ngx_add_timer(c->write, cscf->timeout);
[820] 
[821]     if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[822]         ngx_mail_close_connection(c);
[823]         return;
[824]     }
[825] }
[826] 
[827] 
[828] ngx_int_t
[829] ngx_mail_read_command(ngx_mail_session_t *s, ngx_connection_t *c)
[830] {
[831]     ssize_t                    n;
[832]     ngx_int_t                  rc;
[833]     ngx_str_t                  l;
[834]     ngx_mail_core_srv_conf_t  *cscf;
[835] 
[836]     if (s->buffer->last < s->buffer->end) {
[837] 
[838]         n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);
[839] 
[840]         if (n == NGX_ERROR || n == 0) {
[841]             ngx_mail_close_connection(c);
[842]             return NGX_ERROR;
[843]         }
[844] 
[845]         if (n > 0) {
[846]             s->buffer->last += n;
[847]         }
[848] 
[849]         if (n == NGX_AGAIN) {
[850]             if (s->buffer->pos == s->buffer->last) {
[851]                 return NGX_AGAIN;
[852]             }
[853]         }
[854]     }
[855] 
[856]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[857] 
[858]     rc = cscf->protocol->parse_command(s);
[859] 
[860]     if (rc == NGX_AGAIN) {
[861] 
[862]         if (s->buffer->last < s->buffer->end) {
[863]             return rc;
[864]         }
[865] 
[866]         l.len = s->buffer->last - s->buffer->start;
[867]         l.data = s->buffer->start;
[868] 
[869]         ngx_log_error(NGX_LOG_INFO, c->log, 0,
[870]                       "client sent too long command \"%V\"", &l);
[871] 
[872]         s->quit = 1;
[873] 
[874]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[875]     }
[876] 
[877]     if (rc == NGX_MAIL_PARSE_INVALID_COMMAND) {
[878] 
[879]         s->errors++;
[880] 
[881]         if (s->errors >= cscf->max_errors) {
[882]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[883]                           "client sent too many invalid commands");
[884]             s->quit = 1;
[885]         }
[886] 
[887]         return rc;
[888]     }
[889] 
[890]     if (rc == NGX_IMAP_NEXT) {
[891]         return rc;
[892]     }
[893] 
[894]     if (rc == NGX_ERROR) {
[895]         ngx_mail_close_connection(c);
[896]         return NGX_ERROR;
[897]     }
[898] 
[899]     return NGX_OK;
[900] }
[901] 
[902] 
[903] void
[904] ngx_mail_auth(ngx_mail_session_t *s, ngx_connection_t *c)
[905] {
[906]     s->args.nelts = 0;
[907] 
[908]     if (s->buffer->pos == s->buffer->last) {
[909]         s->buffer->pos = s->buffer->start;
[910]         s->buffer->last = s->buffer->start;
[911]     }
[912] 
[913]     s->state = 0;
[914] 
[915]     if (c->read->timer_set) {
[916]         ngx_del_timer(c->read);
[917]     }
[918] 
[919]     s->login_attempt++;
[920] 
[921]     ngx_mail_auth_http_init(s);
[922] }
[923] 
[924] 
[925] void
[926] ngx_mail_session_internal_server_error(ngx_mail_session_t *s)
[927] {
[928]     ngx_mail_core_srv_conf_t  *cscf;
[929] 
[930]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[931] 
[932]     s->out = cscf->protocol->internal_server_error;
[933]     s->quit = 1;
[934] 
[935]     ngx_mail_send(s->connection->write);
[936] }
[937] 
[938] 
[939] void
[940] ngx_mail_close_connection(ngx_connection_t *c)
[941] {
[942]     ngx_pool_t  *pool;
[943] 
[944]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[945]                    "close mail connection: %d", c->fd);
[946] 
[947] #if (NGX_MAIL_SSL)
[948] 
[949]     if (c->ssl) {
[950]         if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
[951]             c->ssl->handler = ngx_mail_close_connection;
[952]             return;
[953]         }
[954]     }
[955] 
[956] #endif
[957] 
[958] #if (NGX_STAT_STUB)
[959]     (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
[960] #endif
[961] 
[962]     c->destroyed = 1;
[963] 
[964]     pool = c->pool;
[965] 
[966]     ngx_close_connection(c);
[967] 
[968]     ngx_destroy_pool(pool);
[969] }
[970] 
[971] 
[972] u_char *
[973] ngx_mail_log_error(ngx_log_t *log, u_char *buf, size_t len)
[974] {
[975]     u_char              *p;
[976]     ngx_mail_session_t  *s;
[977]     ngx_mail_log_ctx_t  *ctx;
[978] 
[979]     if (log->action) {
[980]         p = ngx_snprintf(buf, len, " while %s", log->action);
[981]         len -= p - buf;
[982]         buf = p;
[983]     }
[984] 
[985]     ctx = log->data;
[986] 
[987]     p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
[988]     len -= p - buf;
[989]     buf = p;
[990] 
[991]     s = ctx->session;
[992] 
[993]     if (s == NULL) {
[994]         return p;
[995]     }
[996] 
[997]     p = ngx_snprintf(buf, len, "%s, server: %V",
[998]                      s->starttls ? " using starttls" : "",
[999]                      s->addr_text);
[1000]     len -= p - buf;
[1001]     buf = p;
[1002] 
[1003]     if (s->login.len == 0) {
[1004]         return p;
[1005]     }
[1006] 
[1007]     p = ngx_snprintf(buf, len, ", login: \"%V\"", &s->login);
[1008]     len -= p - buf;
[1009]     buf = p;
[1010] 
[1011]     if (s->proxy == NULL) {
[1012]         return p;
[1013]     }
[1014] 
[1015]     p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);
[1016] 
[1017]     return p;
[1018] }
