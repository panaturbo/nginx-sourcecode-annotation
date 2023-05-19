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
[12] #include <ngx_mail_smtp_module.h>
[13] 
[14] 
[15] static void ngx_mail_smtp_resolve_addr_handler(ngx_resolver_ctx_t *ctx);
[16] static void ngx_mail_smtp_resolve_name(ngx_event_t *rev);
[17] static void ngx_mail_smtp_resolve_name_handler(ngx_resolver_ctx_t *ctx);
[18] static void ngx_mail_smtp_block_reading(ngx_event_t *rev);
[19] static void ngx_mail_smtp_greeting(ngx_mail_session_t *s, ngx_connection_t *c);
[20] static void ngx_mail_smtp_invalid_pipelining(ngx_event_t *rev);
[21] static ngx_int_t ngx_mail_smtp_create_buffer(ngx_mail_session_t *s,
[22]     ngx_connection_t *c);
[23] 
[24] static ngx_int_t ngx_mail_smtp_helo(ngx_mail_session_t *s, ngx_connection_t *c);
[25] static ngx_int_t ngx_mail_smtp_auth(ngx_mail_session_t *s, ngx_connection_t *c);
[26] static ngx_int_t ngx_mail_smtp_mail(ngx_mail_session_t *s, ngx_connection_t *c);
[27] static ngx_int_t ngx_mail_smtp_starttls(ngx_mail_session_t *s,
[28]     ngx_connection_t *c);
[29] static ngx_int_t ngx_mail_smtp_rset(ngx_mail_session_t *s, ngx_connection_t *c);
[30] static ngx_int_t ngx_mail_smtp_rcpt(ngx_mail_session_t *s, ngx_connection_t *c);
[31] 
[32] static ngx_int_t ngx_mail_smtp_discard_command(ngx_mail_session_t *s,
[33]     ngx_connection_t *c, char *err);
[34] static void ngx_mail_smtp_log_rejected_command(ngx_mail_session_t *s,
[35]     ngx_connection_t *c, char *err);
[36] 
[37] 
[38] static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
[39] static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
[40] static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
[41] static u_char  smtp_next[] = "334 " CRLF;
[42] static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
[43] static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
[44] static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
[45] static u_char  smtp_invalid_pipelining[] =
[46]     "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
[47] static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
[48] static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
[49] static u_char  smtp_bad_sequence[] = "503 5.5.1 Bad sequence of commands" CRLF;
[50] 
[51] 
[52] static ngx_str_t  smtp_unavailable = ngx_string("[UNAVAILABLE]");
[53] static ngx_str_t  smtp_tempunavail = ngx_string("[TEMPUNAVAIL]");
[54] 
[55] 
[56] void
[57] ngx_mail_smtp_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
[58] {
[59]     ngx_resolver_ctx_t        *ctx;
[60]     ngx_mail_core_srv_conf_t  *cscf;
[61] 
[62]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[63] 
[64]     if (cscf->resolver == NULL) {
[65]         s->host = smtp_unavailable;
[66]         ngx_mail_smtp_greeting(s, c);
[67]         return;
[68]     }
[69] 
[70] #if (NGX_HAVE_UNIX_DOMAIN)
[71]     if (c->sockaddr->sa_family == AF_UNIX) {
[72]         s->host = smtp_tempunavail;
[73]         ngx_mail_smtp_greeting(s, c);
[74]         return;
[75]     }
[76] #endif
[77] 
[78]     c->log->action = "in resolving client address";
[79] 
[80]     ctx = ngx_resolve_start(cscf->resolver, NULL);
[81]     if (ctx == NULL) {
[82]         ngx_mail_close_connection(c);
[83]         return;
[84]     }
[85] 
[86]     ctx->addr.sockaddr = c->sockaddr;
[87]     ctx->addr.socklen = c->socklen;
[88]     ctx->handler = ngx_mail_smtp_resolve_addr_handler;
[89]     ctx->data = s;
[90]     ctx->timeout = cscf->resolver_timeout;
[91] 
[92]     s->resolver_ctx = ctx;
[93]     c->read->handler = ngx_mail_smtp_block_reading;
[94] 
[95]     if (ngx_resolve_addr(ctx) != NGX_OK) {
[96]         ngx_mail_close_connection(c);
[97]     }
[98] }
[99] 
[100] 
[101] static void
[102] ngx_mail_smtp_resolve_addr_handler(ngx_resolver_ctx_t *ctx)
[103] {
[104]     ngx_connection_t    *c;
[105]     ngx_mail_session_t  *s;
[106] 
[107]     s = ctx->data;
[108]     c = s->connection;
[109] 
[110]     if (ctx->state) {
[111]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[112]                       "%V could not be resolved (%i: %s)",
[113]                       &c->addr_text, ctx->state,
[114]                       ngx_resolver_strerror(ctx->state));
[115] 
[116]         if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
[117]             s->host = smtp_unavailable;
[118] 
[119]         } else {
[120]             s->host = smtp_tempunavail;
[121]         }
[122] 
[123]         ngx_resolve_addr_done(ctx);
[124] 
[125]         ngx_mail_smtp_greeting(s, s->connection);
[126] 
[127]         return;
[128]     }
[129] 
[130]     c->log->action = "in resolving client hostname";
[131] 
[132]     s->host.data = ngx_pstrdup(c->pool, &ctx->name);
[133]     if (s->host.data == NULL) {
[134]         ngx_resolve_addr_done(ctx);
[135]         ngx_mail_close_connection(c);
[136]         return;
[137]     }
[138] 
[139]     s->host.len = ctx->name.len;
[140] 
[141]     ngx_resolve_addr_done(ctx);
[142] 
[143]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[144]                    "address resolved: %V", &s->host);
[145] 
[146]     c->read->handler = ngx_mail_smtp_resolve_name;
[147] 
[148]     ngx_post_event(c->read, &ngx_posted_events);
[149] }
[150] 
[151] 
[152] static void
[153] ngx_mail_smtp_resolve_name(ngx_event_t *rev)
[154] {
[155]     ngx_connection_t          *c;
[156]     ngx_mail_session_t        *s;
[157]     ngx_resolver_ctx_t        *ctx;
[158]     ngx_mail_core_srv_conf_t  *cscf;
[159] 
[160]     c = rev->data;
[161]     s = c->data;
[162] 
[163]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[164] 
[165]     ctx = ngx_resolve_start(cscf->resolver, NULL);
[166]     if (ctx == NULL) {
[167]         ngx_mail_close_connection(c);
[168]         return;
[169]     }
[170] 
[171]     ctx->name = s->host;
[172]     ctx->handler = ngx_mail_smtp_resolve_name_handler;
[173]     ctx->data = s;
[174]     ctx->timeout = cscf->resolver_timeout;
[175] 
[176]     s->resolver_ctx = ctx;
[177]     c->read->handler = ngx_mail_smtp_block_reading;
[178] 
[179]     if (ngx_resolve_name(ctx) != NGX_OK) {
[180]         ngx_mail_close_connection(c);
[181]     }
[182] }
[183] 
[184] 
[185] static void
[186] ngx_mail_smtp_resolve_name_handler(ngx_resolver_ctx_t *ctx)
[187] {
[188]     ngx_uint_t           i;
[189]     ngx_connection_t    *c;
[190]     ngx_mail_session_t  *s;
[191] 
[192]     s = ctx->data;
[193]     c = s->connection;
[194] 
[195]     if (ctx->state) {
[196]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[197]                       "\"%V\" could not be resolved (%i: %s)",
[198]                       &ctx->name, ctx->state,
[199]                       ngx_resolver_strerror(ctx->state));
[200] 
[201]         if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
[202]             s->host = smtp_unavailable;
[203] 
[204]         } else {
[205]             s->host = smtp_tempunavail;
[206]         }
[207] 
[208]     } else {
[209] 
[210] #if (NGX_DEBUG)
[211]         {
[212]         u_char     text[NGX_SOCKADDR_STRLEN];
[213]         ngx_str_t  addr;
[214] 
[215]         addr.data = text;
[216] 
[217]         for (i = 0; i < ctx->naddrs; i++) {
[218]             addr.len = ngx_sock_ntop(ctx->addrs[i].sockaddr,
[219]                                      ctx->addrs[i].socklen,
[220]                                      text, NGX_SOCKADDR_STRLEN, 0);
[221] 
[222]             ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[223]                            "name was resolved to %V", &addr);
[224]         }
[225]         }
[226] #endif
[227] 
[228]         for (i = 0; i < ctx->naddrs; i++) {
[229]             if (ngx_cmp_sockaddr(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
[230]                                  c->sockaddr, c->socklen, 0)
[231]                 == NGX_OK)
[232]             {
[233]                 goto found;
[234]             }
[235]         }
[236] 
[237]         s->host = smtp_unavailable;
[238]     }
[239] 
[240] found:
[241] 
[242]     ngx_resolve_name_done(ctx);
[243] 
[244]     ngx_mail_smtp_greeting(s, c);
[245] }
[246] 
[247] 
[248] static void
[249] ngx_mail_smtp_block_reading(ngx_event_t *rev)
[250] {
[251]     ngx_connection_t    *c;
[252]     ngx_mail_session_t  *s;
[253]     ngx_resolver_ctx_t  *ctx;
[254] 
[255]     c = rev->data;
[256]     s = c->data;
[257] 
[258]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp reading blocked");
[259] 
[260]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[261] 
[262]         if (s->resolver_ctx) {
[263]             ctx = s->resolver_ctx;
[264] 
[265]             if (ctx->handler == ngx_mail_smtp_resolve_addr_handler) {
[266]                 ngx_resolve_addr_done(ctx);
[267] 
[268]             } else if (ctx->handler == ngx_mail_smtp_resolve_name_handler) {
[269]                 ngx_resolve_name_done(ctx);
[270]             }
[271] 
[272]             s->resolver_ctx = NULL;
[273]         }
[274] 
[275]         ngx_mail_close_connection(c);
[276]     }
[277] }
[278] 
[279] 
[280] static void
[281] ngx_mail_smtp_greeting(ngx_mail_session_t *s, ngx_connection_t *c)
[282] {
[283]     ngx_msec_t                 timeout;
[284]     ngx_mail_core_srv_conf_t  *cscf;
[285]     ngx_mail_smtp_srv_conf_t  *sscf;
[286] 
[287]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[288]                    "smtp greeting for \"%V\"", &s->host);
[289] 
[290]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[291]     sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);
[292] 
[293]     timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
[294]     ngx_add_timer(c->read, timeout);
[295] 
[296]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[297]         ngx_mail_close_connection(c);
[298]     }
[299] 
[300]     if (c->read->ready) {
[301]         ngx_post_event(c->read, &ngx_posted_events);
[302]     }
[303] 
[304]     if (sscf->greeting_delay) {
[305]          c->read->handler = ngx_mail_smtp_invalid_pipelining;
[306]          return;
[307]     }
[308] 
[309]     c->read->handler = ngx_mail_smtp_init_protocol;
[310] 
[311]     s->out = sscf->greeting;
[312] 
[313]     ngx_mail_send(c->write);
[314] }
[315] 
[316] 
[317] static void
[318] ngx_mail_smtp_invalid_pipelining(ngx_event_t *rev)
[319] {
[320]     ngx_connection_t          *c;
[321]     ngx_mail_session_t        *s;
[322]     ngx_mail_core_srv_conf_t  *cscf;
[323]     ngx_mail_smtp_srv_conf_t  *sscf;
[324] 
[325]     c = rev->data;
[326]     s = c->data;
[327] 
[328]     c->log->action = "in delay pipelining state";
[329] 
[330]     if (rev->timedout) {
[331] 
[332]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "delay greeting");
[333] 
[334]         rev->timedout = 0;
[335] 
[336]         cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[337] 
[338]         c->read->handler = ngx_mail_smtp_init_protocol;
[339] 
[340]         ngx_add_timer(c->read, cscf->timeout);
[341] 
[342]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[343]             ngx_mail_close_connection(c);
[344]             return;
[345]         }
[346] 
[347]         sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);
[348] 
[349]         s->out = sscf->greeting;
[350] 
[351]     } else {
[352] 
[353]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "invalid pipelining");
[354] 
[355]         if (s->buffer == NULL) {
[356]             if (ngx_mail_smtp_create_buffer(s, c) != NGX_OK) {
[357]                 return;
[358]             }
[359]         }
[360] 
[361]         if (ngx_mail_smtp_discard_command(s, c,
[362]                                 "client was rejected before greeting: \"%V\"")
[363]             != NGX_OK)
[364]         {
[365]             return;
[366]         }
[367] 
[368]         ngx_str_set(&s->out, smtp_invalid_pipelining);
[369]         s->quit = 1;
[370]     }
[371] 
[372]     ngx_mail_send(c->write);
[373] }
[374] 
[375] 
[376] void
[377] ngx_mail_smtp_init_protocol(ngx_event_t *rev)
[378] {
[379]     ngx_connection_t    *c;
[380]     ngx_mail_session_t  *s;
[381] 
[382]     c = rev->data;
[383] 
[384]     c->log->action = "in auth state";
[385] 
[386]     if (rev->timedout) {
[387]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[388]         c->timedout = 1;
[389]         ngx_mail_close_connection(c);
[390]         return;
[391]     }
[392] 
[393]     s = c->data;
[394] 
[395]     if (s->buffer == NULL) {
[396]         if (ngx_mail_smtp_create_buffer(s, c) != NGX_OK) {
[397]             return;
[398]         }
[399]     }
[400] 
[401]     s->mail_state = ngx_smtp_start;
[402]     c->read->handler = ngx_mail_smtp_auth_state;
[403] 
[404]     ngx_mail_smtp_auth_state(rev);
[405] }
[406] 
[407] 
[408] static ngx_int_t
[409] ngx_mail_smtp_create_buffer(ngx_mail_session_t *s, ngx_connection_t *c)
[410] {
[411]     ngx_mail_smtp_srv_conf_t  *sscf;
[412] 
[413]     if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
[414]         ngx_mail_session_internal_server_error(s);
[415]         return NGX_ERROR;
[416]     }
[417] 
[418]     sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);
[419] 
[420]     s->buffer = ngx_create_temp_buf(c->pool, sscf->client_buffer_size);
[421]     if (s->buffer == NULL) {
[422]         ngx_mail_session_internal_server_error(s);
[423]         return NGX_ERROR;
[424]     }
[425] 
[426]     return NGX_OK;
[427] }
[428] 
[429] 
[430] void
[431] ngx_mail_smtp_auth_state(ngx_event_t *rev)
[432] {
[433]     ngx_int_t            rc;
[434]     ngx_connection_t    *c;
[435]     ngx_mail_session_t  *s;
[436] 
[437]     c = rev->data;
[438]     s = c->data;
[439] 
[440]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");
[441] 
[442]     if (rev->timedout) {
[443]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[444]         c->timedout = 1;
[445]         ngx_mail_close_connection(c);
[446]         return;
[447]     }
[448] 
[449]     if (s->out.len) {
[450]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
[451]         s->blocked = 1;
[452] 
[453]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[454]             ngx_mail_close_connection(c);
[455]             return;
[456]         }
[457] 
[458]         return;
[459]     }
[460] 
[461]     s->blocked = 0;
[462] 
[463]     rc = ngx_mail_read_command(s, c);
[464] 
[465]     if (rc == NGX_AGAIN) {
[466]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[467]             ngx_mail_session_internal_server_error(s);
[468]             return;
[469]         }
[470] 
[471]         return;
[472]     }
[473] 
[474]     if (rc == NGX_ERROR) {
[475]         return;
[476]     }
[477] 
[478]     ngx_str_set(&s->out, smtp_ok);
[479] 
[480]     if (rc == NGX_OK) {
[481]         switch (s->mail_state) {
[482] 
[483]         case ngx_smtp_start:
[484] 
[485]             switch (s->command) {
[486] 
[487]             case NGX_SMTP_HELO:
[488]             case NGX_SMTP_EHLO:
[489]                 rc = ngx_mail_smtp_helo(s, c);
[490]                 break;
[491] 
[492]             case NGX_SMTP_AUTH:
[493]                 rc = ngx_mail_smtp_auth(s, c);
[494]                 break;
[495] 
[496]             case NGX_SMTP_QUIT:
[497]                 s->quit = 1;
[498]                 ngx_str_set(&s->out, smtp_bye);
[499]                 break;
[500] 
[501]             case NGX_SMTP_MAIL:
[502]                 rc = ngx_mail_smtp_mail(s, c);
[503]                 break;
[504] 
[505]             case NGX_SMTP_RCPT:
[506]                 rc = ngx_mail_smtp_rcpt(s, c);
[507]                 break;
[508] 
[509]             case NGX_SMTP_RSET:
[510]                 rc = ngx_mail_smtp_rset(s, c);
[511]                 break;
[512] 
[513]             case NGX_SMTP_NOOP:
[514]                 break;
[515] 
[516]             case NGX_SMTP_STARTTLS:
[517]                 rc = ngx_mail_smtp_starttls(s, c);
[518]                 ngx_str_set(&s->out, smtp_starttls);
[519]                 break;
[520] 
[521]             default:
[522]                 rc = NGX_MAIL_PARSE_INVALID_COMMAND;
[523]                 break;
[524]             }
[525] 
[526]             break;
[527] 
[528]         case ngx_smtp_auth_login_username:
[529]             rc = ngx_mail_auth_login_username(s, c, 0);
[530] 
[531]             ngx_str_set(&s->out, smtp_password);
[532]             s->mail_state = ngx_smtp_auth_login_password;
[533]             break;
[534] 
[535]         case ngx_smtp_auth_login_password:
[536]             rc = ngx_mail_auth_login_password(s, c);
[537]             break;
[538] 
[539]         case ngx_smtp_auth_plain:
[540]             rc = ngx_mail_auth_plain(s, c, 0);
[541]             break;
[542] 
[543]         case ngx_smtp_auth_cram_md5:
[544]             rc = ngx_mail_auth_cram_md5(s, c);
[545]             break;
[546] 
[547]         case ngx_smtp_auth_external:
[548]             rc = ngx_mail_auth_external(s, c, 0);
[549]             break;
[550]         }
[551]     }
[552] 
[553]     if (s->buffer->pos < s->buffer->last) {
[554]         s->blocked = 1;
[555]     }
[556] 
[557]     switch (rc) {
[558] 
[559]     case NGX_DONE:
[560]         ngx_mail_auth(s, c);
[561]         return;
[562] 
[563]     case NGX_ERROR:
[564]         ngx_mail_session_internal_server_error(s);
[565]         return;
[566] 
[567]     case NGX_MAIL_PARSE_INVALID_COMMAND:
[568]         s->mail_state = ngx_smtp_start;
[569]         s->state = 0;
[570]         ngx_str_set(&s->out, smtp_invalid_command);
[571] 
[572]         /* fall through */
[573] 
[574]     case NGX_OK:
[575]         s->args.nelts = 0;
[576] 
[577]         if (s->buffer->pos == s->buffer->last) {
[578]             s->buffer->pos = s->buffer->start;
[579]             s->buffer->last = s->buffer->start;
[580]         }
[581] 
[582]         if (s->state) {
[583]             s->arg_start = s->buffer->pos;
[584]         }
[585] 
[586]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[587]             ngx_mail_session_internal_server_error(s);
[588]             return;
[589]         }
[590] 
[591]         ngx_mail_send(c->write);
[592]     }
[593] }
[594] 
[595] 
[596] static ngx_int_t
[597] ngx_mail_smtp_helo(ngx_mail_session_t *s, ngx_connection_t *c)
[598] {
[599]     ngx_str_t                 *arg;
[600]     ngx_mail_smtp_srv_conf_t  *sscf;
[601] 
[602]     if (s->args.nelts != 1) {
[603]         ngx_str_set(&s->out, smtp_invalid_argument);
[604]         s->state = 0;
[605]         return NGX_OK;
[606]     }
[607] 
[608]     arg = s->args.elts;
[609] 
[610]     s->smtp_helo.len = arg[0].len;
[611] 
[612]     s->smtp_helo.data = ngx_pnalloc(c->pool, arg[0].len);
[613]     if (s->smtp_helo.data == NULL) {
[614]         return NGX_ERROR;
[615]     }
[616] 
[617]     ngx_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);
[618] 
[619]     ngx_str_null(&s->smtp_from);
[620]     ngx_str_null(&s->smtp_to);
[621] 
[622]     sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);
[623] 
[624]     if (s->command == NGX_SMTP_HELO) {
[625]         s->out = sscf->server_name;
[626] 
[627]     } else {
[628]         s->esmtp = 1;
[629] 
[630] #if (NGX_MAIL_SSL)
[631] 
[632]         if (c->ssl == NULL) {
[633]             ngx_mail_ssl_conf_t  *sslcf;
[634] 
[635]             sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[636] 
[637]             if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
[638]                 s->out = sscf->starttls_capability;
[639]                 return NGX_OK;
[640]             }
[641] 
[642]             if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
[643]                 s->out = sscf->starttls_only_capability;
[644]                 return NGX_OK;
[645]             }
[646]         }
[647] #endif
[648] 
[649]         s->out = sscf->capability;
[650]     }
[651] 
[652]     return NGX_OK;
[653] }
[654] 
[655] 
[656] static ngx_int_t
[657] ngx_mail_smtp_auth(ngx_mail_session_t *s, ngx_connection_t *c)
[658] {
[659]     ngx_int_t                  rc;
[660]     ngx_mail_core_srv_conf_t  *cscf;
[661]     ngx_mail_smtp_srv_conf_t  *sscf;
[662] 
[663] #if (NGX_MAIL_SSL)
[664]     if (ngx_mail_starttls_only(s, c)) {
[665]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[666]     }
[667] #endif
[668] 
[669]     if (s->args.nelts == 0) {
[670]         ngx_str_set(&s->out, smtp_invalid_argument);
[671]         s->state = 0;
[672]         return NGX_OK;
[673]     }
[674] 
[675]     sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);
[676] 
[677]     rc = ngx_mail_auth_parse(s, c);
[678] 
[679]     switch (rc) {
[680] 
[681]     case NGX_MAIL_AUTH_LOGIN:
[682] 
[683]         ngx_str_set(&s->out, smtp_username);
[684]         s->mail_state = ngx_smtp_auth_login_username;
[685] 
[686]         return NGX_OK;
[687] 
[688]     case NGX_MAIL_AUTH_LOGIN_USERNAME:
[689] 
[690]         ngx_str_set(&s->out, smtp_password);
[691]         s->mail_state = ngx_smtp_auth_login_password;
[692] 
[693]         return ngx_mail_auth_login_username(s, c, 1);
[694] 
[695]     case NGX_MAIL_AUTH_PLAIN:
[696] 
[697]         ngx_str_set(&s->out, smtp_next);
[698]         s->mail_state = ngx_smtp_auth_plain;
[699] 
[700]         return NGX_OK;
[701] 
[702]     case NGX_MAIL_AUTH_CRAM_MD5:
[703] 
[704]         if (!(sscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
[705]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[706]         }
[707] 
[708]         if (s->salt.data == NULL) {
[709]             cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[710] 
[711]             if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
[712]                 return NGX_ERROR;
[713]             }
[714]         }
[715] 
[716]         if (ngx_mail_auth_cram_md5_salt(s, c, "334 ", 4) == NGX_OK) {
[717]             s->mail_state = ngx_smtp_auth_cram_md5;
[718]             return NGX_OK;
[719]         }
[720] 
[721]         return NGX_ERROR;
[722] 
[723]     case NGX_MAIL_AUTH_EXTERNAL:
[724] 
[725]         if (!(sscf->auth_methods & NGX_MAIL_AUTH_EXTERNAL_ENABLED)) {
[726]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[727]         }
[728] 
[729]         ngx_str_set(&s->out, smtp_username);
[730]         s->mail_state = ngx_smtp_auth_external;
[731] 
[732]         return NGX_OK;
[733]     }
[734] 
[735]     return rc;
[736] }
[737] 
[738] 
[739] static ngx_int_t
[740] ngx_mail_smtp_mail(ngx_mail_session_t *s, ngx_connection_t *c)
[741] {
[742]     ngx_str_t                 *arg, cmd;
[743]     ngx_mail_smtp_srv_conf_t  *sscf;
[744] 
[745]     sscf = ngx_mail_get_module_srv_conf(s, ngx_mail_smtp_module);
[746] 
[747]     if (!(sscf->auth_methods & NGX_MAIL_AUTH_NONE_ENABLED)) {
[748]         ngx_mail_smtp_log_rejected_command(s, c, "client was rejected: \"%V\"");
[749]         ngx_str_set(&s->out, smtp_auth_required);
[750]         return NGX_OK;
[751]     }
[752] 
[753]     /* auth none */
[754] 
[755]     if (s->smtp_from.len) {
[756]         ngx_str_set(&s->out, smtp_bad_sequence);
[757]         return NGX_OK;
[758]     }
[759] 
[760]     if (s->args.nelts == 0) {
[761]         ngx_str_set(&s->out, smtp_invalid_argument);
[762]         return NGX_OK;
[763]     }
[764] 
[765]     arg = s->args.elts;
[766]     arg += s->args.nelts - 1;
[767] 
[768]     cmd.len = arg->data + arg->len - s->cmd.data;
[769]     cmd.data = s->cmd.data;
[770] 
[771]     s->smtp_from.len = cmd.len;
[772] 
[773]     s->smtp_from.data = ngx_pnalloc(c->pool, cmd.len);
[774]     if (s->smtp_from.data == NULL) {
[775]         return NGX_ERROR;
[776]     }
[777] 
[778]     ngx_memcpy(s->smtp_from.data, cmd.data, cmd.len);
[779] 
[780]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[781]                    "smtp mail from:\"%V\"", &s->smtp_from);
[782] 
[783]     ngx_str_set(&s->out, smtp_ok);
[784] 
[785]     return NGX_OK;
[786] }
[787] 
[788] 
[789] static ngx_int_t
[790] ngx_mail_smtp_rcpt(ngx_mail_session_t *s, ngx_connection_t *c)
[791] {
[792]     ngx_str_t  *arg, cmd;
[793] 
[794]     if (s->smtp_from.len == 0) {
[795]         ngx_str_set(&s->out, smtp_bad_sequence);
[796]         return NGX_OK;
[797]     }
[798] 
[799]     if (s->args.nelts == 0) {
[800]         ngx_str_set(&s->out, smtp_invalid_argument);
[801]         return NGX_OK;
[802]     }
[803] 
[804]     arg = s->args.elts;
[805]     arg += s->args.nelts - 1;
[806] 
[807]     cmd.len = arg->data + arg->len - s->cmd.data;
[808]     cmd.data = s->cmd.data;
[809] 
[810]     s->smtp_to.len = cmd.len;
[811] 
[812]     s->smtp_to.data = ngx_pnalloc(c->pool, cmd.len);
[813]     if (s->smtp_to.data == NULL) {
[814]         return NGX_ERROR;
[815]     }
[816] 
[817]     ngx_memcpy(s->smtp_to.data, cmd.data, cmd.len);
[818] 
[819]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[820]                    "smtp rcpt to:\"%V\"", &s->smtp_to);
[821] 
[822]     s->auth_method = NGX_MAIL_AUTH_NONE;
[823] 
[824]     return NGX_DONE;
[825] }
[826] 
[827] 
[828] static ngx_int_t
[829] ngx_mail_smtp_rset(ngx_mail_session_t *s, ngx_connection_t *c)
[830] {
[831]     ngx_str_null(&s->smtp_from);
[832]     ngx_str_null(&s->smtp_to);
[833]     ngx_str_set(&s->out, smtp_ok);
[834] 
[835]     return NGX_OK;
[836] }
[837] 
[838] 
[839] static ngx_int_t
[840] ngx_mail_smtp_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
[841] {
[842] #if (NGX_MAIL_SSL)
[843]     ngx_mail_ssl_conf_t  *sslcf;
[844] 
[845]     if (c->ssl == NULL) {
[846]         sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[847]         if (sslcf->starttls) {
[848] 
[849]             /*
[850]              * RFC3207 requires us to discard any knowledge
[851]              * obtained from client before STARTTLS.
[852]              */
[853] 
[854]             ngx_str_null(&s->smtp_helo);
[855]             ngx_str_null(&s->smtp_from);
[856]             ngx_str_null(&s->smtp_to);
[857] 
[858]             s->buffer->pos = s->buffer->start;
[859]             s->buffer->last = s->buffer->start;
[860] 
[861]             c->read->handler = ngx_mail_starttls_handler;
[862]             return NGX_OK;
[863]         }
[864]     }
[865] 
[866] #endif
[867] 
[868]     return NGX_MAIL_PARSE_INVALID_COMMAND;
[869] }
[870] 
[871] 
[872] static ngx_int_t
[873] ngx_mail_smtp_discard_command(ngx_mail_session_t *s, ngx_connection_t *c,
[874]     char *err)
[875] {
[876]     ssize_t    n;
[877] 
[878]     n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);
[879] 
[880]     if (n == NGX_ERROR || n == 0) {
[881]         ngx_mail_close_connection(c);
[882]         return NGX_ERROR;
[883]     }
[884] 
[885]     if (n > 0) {
[886]         s->buffer->last += n;
[887]     }
[888] 
[889]     if (n == NGX_AGAIN) {
[890]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[891]             ngx_mail_session_internal_server_error(s);
[892]             return NGX_ERROR;
[893]         }
[894] 
[895]         return NGX_AGAIN;
[896]     }
[897] 
[898]     ngx_mail_smtp_log_rejected_command(s, c, err);
[899] 
[900]     s->buffer->pos = s->buffer->start;
[901]     s->buffer->last = s->buffer->start;
[902] 
[903]     return NGX_OK;
[904] }
[905] 
[906] 
[907] static void
[908] ngx_mail_smtp_log_rejected_command(ngx_mail_session_t *s, ngx_connection_t *c,
[909]     char *err)
[910] {
[911]     u_char      ch;
[912]     ngx_str_t   cmd;
[913]     ngx_uint_t  i;
[914] 
[915]     if (c->log->log_level < NGX_LOG_INFO) {
[916]         return;
[917]     }
[918] 
[919]     cmd.len = s->buffer->last - s->buffer->start;
[920]     cmd.data = s->buffer->start;
[921] 
[922]     for (i = 0; i < cmd.len; i++) {
[923]         ch = cmd.data[i];
[924] 
[925]         if (ch != CR && ch != LF) {
[926]             continue;
[927]         }
[928] 
[929]         cmd.data[i] = '_';
[930]     }
[931] 
[932]     cmd.len = i;
[933] 
[934]     ngx_log_error(NGX_LOG_INFO, c->log, 0, err, &cmd);
[935] }
