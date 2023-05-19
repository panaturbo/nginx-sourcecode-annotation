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
[11] #include <ngx_event_connect.h>
[12] #include <ngx_mail.h>
[13] 
[14] 
[15] typedef struct {
[16]     ngx_flag_t  enable;
[17]     ngx_flag_t  pass_error_message;
[18]     ngx_flag_t  xclient;
[19]     ngx_flag_t  smtp_auth;
[20]     ngx_flag_t  proxy_protocol;
[21]     size_t      buffer_size;
[22]     ngx_msec_t  timeout;
[23] } ngx_mail_proxy_conf_t;
[24] 
[25] 
[26] static void ngx_mail_proxy_block_read(ngx_event_t *rev);
[27] static void ngx_mail_proxy_pop3_handler(ngx_event_t *rev);
[28] static void ngx_mail_proxy_imap_handler(ngx_event_t *rev);
[29] static void ngx_mail_proxy_smtp_handler(ngx_event_t *rev);
[30] static void ngx_mail_proxy_write_handler(ngx_event_t *wev);
[31] static ngx_int_t ngx_mail_proxy_send_proxy_protocol(ngx_mail_session_t *s);
[32] static ngx_int_t ngx_mail_proxy_read_response(ngx_mail_session_t *s,
[33]     ngx_uint_t state);
[34] static void ngx_mail_proxy_handler(ngx_event_t *ev);
[35] static void ngx_mail_proxy_upstream_error(ngx_mail_session_t *s);
[36] static void ngx_mail_proxy_internal_server_error(ngx_mail_session_t *s);
[37] static void ngx_mail_proxy_close_session(ngx_mail_session_t *s);
[38] static void *ngx_mail_proxy_create_conf(ngx_conf_t *cf);
[39] static char *ngx_mail_proxy_merge_conf(ngx_conf_t *cf, void *parent,
[40]     void *child);
[41] 
[42] 
[43] static ngx_command_t  ngx_mail_proxy_commands[] = {
[44] 
[45]     { ngx_string("proxy"),
[46]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[47]       ngx_conf_set_flag_slot,
[48]       NGX_MAIL_SRV_CONF_OFFSET,
[49]       offsetof(ngx_mail_proxy_conf_t, enable),
[50]       NULL },
[51] 
[52]     { ngx_string("proxy_buffer"),
[53]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[54]       ngx_conf_set_size_slot,
[55]       NGX_MAIL_SRV_CONF_OFFSET,
[56]       offsetof(ngx_mail_proxy_conf_t, buffer_size),
[57]       NULL },
[58] 
[59]     { ngx_string("proxy_timeout"),
[60]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[61]       ngx_conf_set_msec_slot,
[62]       NGX_MAIL_SRV_CONF_OFFSET,
[63]       offsetof(ngx_mail_proxy_conf_t, timeout),
[64]       NULL },
[65] 
[66]     { ngx_string("proxy_pass_error_message"),
[67]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[68]       ngx_conf_set_flag_slot,
[69]       NGX_MAIL_SRV_CONF_OFFSET,
[70]       offsetof(ngx_mail_proxy_conf_t, pass_error_message),
[71]       NULL },
[72] 
[73]     { ngx_string("xclient"),
[74]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[75]       ngx_conf_set_flag_slot,
[76]       NGX_MAIL_SRV_CONF_OFFSET,
[77]       offsetof(ngx_mail_proxy_conf_t, xclient),
[78]       NULL },
[79] 
[80]     { ngx_string("proxy_smtp_auth"),
[81]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[82]       ngx_conf_set_flag_slot,
[83]       NGX_MAIL_SRV_CONF_OFFSET,
[84]       offsetof(ngx_mail_proxy_conf_t, smtp_auth),
[85]       NULL },
[86] 
[87]     { ngx_string("proxy_protocol"),
[88]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[89]       ngx_conf_set_flag_slot,
[90]       NGX_MAIL_SRV_CONF_OFFSET,
[91]       offsetof(ngx_mail_proxy_conf_t, proxy_protocol),
[92]       NULL },
[93] 
[94]       ngx_null_command
[95] };
[96] 
[97] 
[98] static ngx_mail_module_t  ngx_mail_proxy_module_ctx = {
[99]     NULL,                                  /* protocol */
[100] 
[101]     NULL,                                  /* create main configuration */
[102]     NULL,                                  /* init main configuration */
[103] 
[104]     ngx_mail_proxy_create_conf,            /* create server configuration */
[105]     ngx_mail_proxy_merge_conf              /* merge server configuration */
[106] };
[107] 
[108] 
[109] ngx_module_t  ngx_mail_proxy_module = {
[110]     NGX_MODULE_V1,
[111]     &ngx_mail_proxy_module_ctx,            /* module context */
[112]     ngx_mail_proxy_commands,               /* module directives */
[113]     NGX_MAIL_MODULE,                       /* module type */
[114]     NULL,                                  /* init master */
[115]     NULL,                                  /* init module */
[116]     NULL,                                  /* init process */
[117]     NULL,                                  /* init thread */
[118]     NULL,                                  /* exit thread */
[119]     NULL,                                  /* exit process */
[120]     NULL,                                  /* exit master */
[121]     NGX_MODULE_V1_PADDING
[122] };
[123] 
[124] 
[125] static u_char  smtp_auth_ok[] = "235 2.0.0 OK" CRLF;
[126] 
[127] 
[128] void
[129] ngx_mail_proxy_init(ngx_mail_session_t *s, ngx_addr_t *peer)
[130] {
[131]     ngx_int_t                  rc;
[132]     ngx_mail_proxy_ctx_t      *p;
[133]     ngx_mail_proxy_conf_t     *pcf;
[134]     ngx_mail_core_srv_conf_t  *cscf;
[135] 
[136]     s->connection->log->action = "connecting to upstream";
[137] 
[138]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[139] 
[140]     p = ngx_pcalloc(s->connection->pool, sizeof(ngx_mail_proxy_ctx_t));
[141]     if (p == NULL) {
[142]         ngx_mail_session_internal_server_error(s);
[143]         return;
[144]     }
[145] 
[146]     s->proxy = p;
[147] 
[148]     p->upstream.sockaddr = peer->sockaddr;
[149]     p->upstream.socklen = peer->socklen;
[150]     p->upstream.name = &peer->name;
[151]     p->upstream.get = ngx_event_get_peer;
[152]     p->upstream.log = s->connection->log;
[153]     p->upstream.log_error = NGX_ERROR_ERR;
[154] 
[155]     rc = ngx_event_connect_peer(&p->upstream);
[156] 
[157]     if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
[158]         ngx_mail_proxy_internal_server_error(s);
[159]         return;
[160]     }
[161] 
[162]     ngx_add_timer(p->upstream.connection->read, cscf->timeout);
[163] 
[164]     p->upstream.connection->data = s;
[165]     p->upstream.connection->pool = s->connection->pool;
[166] 
[167]     s->connection->read->handler = ngx_mail_proxy_block_read;
[168]     p->upstream.connection->write->handler = ngx_mail_proxy_write_handler;
[169] 
[170]     pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[171] 
[172]     s->proxy->buffer = ngx_create_temp_buf(s->connection->pool,
[173]                                            pcf->buffer_size);
[174]     if (s->proxy->buffer == NULL) {
[175]         ngx_mail_proxy_internal_server_error(s);
[176]         return;
[177]     }
[178] 
[179]     s->proxy->proxy_protocol = pcf->proxy_protocol;
[180] 
[181]     s->out.len = 0;
[182] 
[183]     switch (s->protocol) {
[184] 
[185]     case NGX_MAIL_POP3_PROTOCOL:
[186]         p->upstream.connection->read->handler = ngx_mail_proxy_pop3_handler;
[187]         s->mail_state = ngx_pop3_start;
[188]         break;
[189] 
[190]     case NGX_MAIL_IMAP_PROTOCOL:
[191]         p->upstream.connection->read->handler = ngx_mail_proxy_imap_handler;
[192]         s->mail_state = ngx_imap_start;
[193]         break;
[194] 
[195]     default: /* NGX_MAIL_SMTP_PROTOCOL */
[196]         p->upstream.connection->read->handler = ngx_mail_proxy_smtp_handler;
[197]         s->mail_state = ngx_smtp_start;
[198]         break;
[199]     }
[200] 
[201]     if (rc == NGX_AGAIN) {
[202]         return;
[203]     }
[204] 
[205]     ngx_mail_proxy_write_handler(p->upstream.connection->write);
[206] }
[207] 
[208] 
[209] static void
[210] ngx_mail_proxy_block_read(ngx_event_t *rev)
[211] {
[212]     ngx_connection_t    *c;
[213]     ngx_mail_session_t  *s;
[214] 
[215]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");
[216] 
[217]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[218]         c = rev->data;
[219]         s = c->data;
[220] 
[221]         ngx_mail_proxy_close_session(s);
[222]     }
[223] }
[224] 
[225] 
[226] static void
[227] ngx_mail_proxy_pop3_handler(ngx_event_t *rev)
[228] {
[229]     u_char                 *p;
[230]     ngx_int_t               rc;
[231]     ngx_str_t               line;
[232]     ngx_connection_t       *c;
[233]     ngx_mail_session_t     *s;
[234]     ngx_mail_proxy_conf_t  *pcf;
[235] 
[236]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[237]                    "mail proxy pop3 auth handler");
[238] 
[239]     c = rev->data;
[240]     s = c->data;
[241] 
[242]     if (rev->timedout) {
[243]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
[244]                       "upstream timed out");
[245]         c->timedout = 1;
[246]         ngx_mail_proxy_internal_server_error(s);
[247]         return;
[248]     }
[249] 
[250]     if (s->proxy->proxy_protocol) {
[251]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "mail proxy pop3 busy");
[252] 
[253]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[254]             ngx_mail_proxy_internal_server_error(s);
[255]             return;
[256]         }
[257] 
[258]         return;
[259]     }
[260] 
[261]     rc = ngx_mail_proxy_read_response(s, 0);
[262] 
[263]     if (rc == NGX_AGAIN) {
[264]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[265]             ngx_mail_proxy_internal_server_error(s);
[266]             return;
[267]         }
[268] 
[269]         return;
[270]     }
[271] 
[272]     if (rc == NGX_ERROR) {
[273]         ngx_mail_proxy_upstream_error(s);
[274]         return;
[275]     }
[276] 
[277]     switch (s->mail_state) {
[278] 
[279]     case ngx_pop3_start:
[280]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");
[281] 
[282]         s->connection->log->action = "sending user name to upstream";
[283] 
[284]         line.len = sizeof("USER ")  - 1 + s->login.len + 2;
[285]         line.data = ngx_pnalloc(c->pool, line.len);
[286]         if (line.data == NULL) {
[287]             ngx_mail_proxy_internal_server_error(s);
[288]             return;
[289]         }
[290] 
[291]         p = ngx_cpymem(line.data, "USER ", sizeof("USER ") - 1);
[292]         p = ngx_cpymem(p, s->login.data, s->login.len);
[293]         *p++ = CR; *p = LF;
[294] 
[295]         s->mail_state = ngx_pop3_user;
[296]         break;
[297] 
[298]     case ngx_pop3_user:
[299]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send pass");
[300] 
[301]         s->connection->log->action = "sending password to upstream";
[302] 
[303]         line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
[304]         line.data = ngx_pnalloc(c->pool, line.len);
[305]         if (line.data == NULL) {
[306]             ngx_mail_proxy_internal_server_error(s);
[307]             return;
[308]         }
[309] 
[310]         p = ngx_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
[311]         p = ngx_cpymem(p, s->passwd.data, s->passwd.len);
[312]         *p++ = CR; *p = LF;
[313] 
[314]         s->mail_state = ngx_pop3_passwd;
[315]         break;
[316] 
[317]     case ngx_pop3_passwd:
[318]         s->connection->read->handler = ngx_mail_proxy_handler;
[319]         s->connection->write->handler = ngx_mail_proxy_handler;
[320]         rev->handler = ngx_mail_proxy_handler;
[321]         c->write->handler = ngx_mail_proxy_handler;
[322] 
[323]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[324]         ngx_add_timer(s->connection->read, pcf->timeout);
[325]         ngx_del_timer(c->read);
[326] 
[327]         c->log->action = NULL;
[328]         ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");
[329] 
[330]         if (s->buffer->pos < s->buffer->last
[331]             || s->connection->read->ready)
[332]         {
[333]             ngx_post_event(c->write, &ngx_posted_events);
[334]         }
[335] 
[336]         ngx_mail_proxy_handler(s->connection->write);
[337] 
[338]         return;
[339] 
[340]     default:
[341] #if (NGX_SUPPRESS_WARN)
[342]         ngx_str_null(&line);
[343] #endif
[344]         break;
[345]     }
[346] 
[347]     if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
[348]         /*
[349]          * we treat the incomplete sending as NGX_ERROR
[350]          * because it is very strange here
[351]          */
[352]         ngx_mail_proxy_internal_server_error(s);
[353]         return;
[354]     }
[355] 
[356]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[357]         ngx_mail_proxy_internal_server_error(s);
[358]         return;
[359]     }
[360] 
[361]     s->proxy->buffer->pos = s->proxy->buffer->start;
[362]     s->proxy->buffer->last = s->proxy->buffer->start;
[363] }
[364] 
[365] 
[366] static void
[367] ngx_mail_proxy_imap_handler(ngx_event_t *rev)
[368] {
[369]     u_char                 *p;
[370]     ngx_int_t               rc;
[371]     ngx_str_t               line;
[372]     ngx_connection_t       *c;
[373]     ngx_mail_session_t     *s;
[374]     ngx_mail_proxy_conf_t  *pcf;
[375] 
[376]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[377]                    "mail proxy imap auth handler");
[378] 
[379]     c = rev->data;
[380]     s = c->data;
[381] 
[382]     if (rev->timedout) {
[383]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
[384]                       "upstream timed out");
[385]         c->timedout = 1;
[386]         ngx_mail_proxy_internal_server_error(s);
[387]         return;
[388]     }
[389] 
[390]     if (s->proxy->proxy_protocol) {
[391]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "mail proxy imap busy");
[392] 
[393]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[394]             ngx_mail_proxy_internal_server_error(s);
[395]             return;
[396]         }
[397] 
[398]         return;
[399]     }
[400] 
[401]     rc = ngx_mail_proxy_read_response(s, s->mail_state);
[402] 
[403]     if (rc == NGX_AGAIN) {
[404]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[405]             ngx_mail_proxy_internal_server_error(s);
[406]             return;
[407]         }
[408] 
[409]         return;
[410]     }
[411] 
[412]     if (rc == NGX_ERROR) {
[413]         ngx_mail_proxy_upstream_error(s);
[414]         return;
[415]     }
[416] 
[417]     switch (s->mail_state) {
[418] 
[419]     case ngx_imap_start:
[420]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[421]                        "mail proxy send login");
[422] 
[423]         s->connection->log->action = "sending LOGIN command to upstream";
[424] 
[425]         line.len = s->tag.len + sizeof("LOGIN ") - 1
[426]                    + 1 + NGX_SIZE_T_LEN + 1 + 2;
[427]         line.data = ngx_pnalloc(c->pool, line.len);
[428]         if (line.data == NULL) {
[429]             ngx_mail_proxy_internal_server_error(s);
[430]             return;
[431]         }
[432] 
[433]         line.len = ngx_sprintf(line.data, "%VLOGIN {%uz}" CRLF,
[434]                                &s->tag, s->login.len)
[435]                    - line.data;
[436] 
[437]         s->mail_state = ngx_imap_login;
[438]         break;
[439] 
[440]     case ngx_imap_login:
[441]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");
[442] 
[443]         s->connection->log->action = "sending user name to upstream";
[444] 
[445]         line.len = s->login.len + 1 + 1 + NGX_SIZE_T_LEN + 1 + 2;
[446]         line.data = ngx_pnalloc(c->pool, line.len);
[447]         if (line.data == NULL) {
[448]             ngx_mail_proxy_internal_server_error(s);
[449]             return;
[450]         }
[451] 
[452]         line.len = ngx_sprintf(line.data, "%V {%uz}" CRLF,
[453]                                &s->login, s->passwd.len)
[454]                    - line.data;
[455] 
[456]         s->mail_state = ngx_imap_user;
[457]         break;
[458] 
[459]     case ngx_imap_user:
[460]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[461]                        "mail proxy send passwd");
[462] 
[463]         s->connection->log->action = "sending password to upstream";
[464] 
[465]         line.len = s->passwd.len + 2;
[466]         line.data = ngx_pnalloc(c->pool, line.len);
[467]         if (line.data == NULL) {
[468]             ngx_mail_proxy_internal_server_error(s);
[469]             return;
[470]         }
[471] 
[472]         p = ngx_cpymem(line.data, s->passwd.data, s->passwd.len);
[473]         *p++ = CR; *p = LF;
[474] 
[475]         s->mail_state = ngx_imap_passwd;
[476]         break;
[477] 
[478]     case ngx_imap_passwd:
[479]         s->connection->read->handler = ngx_mail_proxy_handler;
[480]         s->connection->write->handler = ngx_mail_proxy_handler;
[481]         rev->handler = ngx_mail_proxy_handler;
[482]         c->write->handler = ngx_mail_proxy_handler;
[483] 
[484]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[485]         ngx_add_timer(s->connection->read, pcf->timeout);
[486]         ngx_del_timer(c->read);
[487] 
[488]         c->log->action = NULL;
[489]         ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");
[490] 
[491]         if (s->buffer->pos < s->buffer->last
[492]             || s->connection->read->ready)
[493]         {
[494]             ngx_post_event(c->write, &ngx_posted_events);
[495]         }
[496] 
[497]         ngx_mail_proxy_handler(s->connection->write);
[498] 
[499]         return;
[500] 
[501]     default:
[502] #if (NGX_SUPPRESS_WARN)
[503]         ngx_str_null(&line);
[504] #endif
[505]         break;
[506]     }
[507] 
[508]     if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
[509]         /*
[510]          * we treat the incomplete sending as NGX_ERROR
[511]          * because it is very strange here
[512]          */
[513]         ngx_mail_proxy_internal_server_error(s);
[514]         return;
[515]     }
[516] 
[517]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[518]         ngx_mail_proxy_internal_server_error(s);
[519]         return;
[520]     }
[521] 
[522]     s->proxy->buffer->pos = s->proxy->buffer->start;
[523]     s->proxy->buffer->last = s->proxy->buffer->start;
[524] }
[525] 
[526] 
[527] static void
[528] ngx_mail_proxy_smtp_handler(ngx_event_t *rev)
[529] {
[530]     u_char                    *p;
[531]     ngx_int_t                  rc;
[532]     ngx_str_t                  line, auth, encoded;
[533]     ngx_buf_t                 *b;
[534]     ngx_connection_t          *c;
[535]     ngx_mail_session_t        *s;
[536]     ngx_mail_proxy_conf_t     *pcf;
[537]     ngx_mail_core_srv_conf_t  *cscf;
[538] 
[539]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[540]                    "mail proxy smtp auth handler");
[541] 
[542]     c = rev->data;
[543]     s = c->data;
[544] 
[545]     if (rev->timedout) {
[546]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
[547]                       "upstream timed out");
[548]         c->timedout = 1;
[549]         ngx_mail_proxy_internal_server_error(s);
[550]         return;
[551]     }
[552] 
[553]     if (s->proxy->proxy_protocol) {
[554]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "mail proxy smtp busy");
[555] 
[556]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[557]             ngx_mail_proxy_internal_server_error(s);
[558]             return;
[559]         }
[560] 
[561]         return;
[562]     }
[563] 
[564]     rc = ngx_mail_proxy_read_response(s, s->mail_state);
[565] 
[566]     if (rc == NGX_AGAIN) {
[567]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[568]             ngx_mail_proxy_internal_server_error(s);
[569]             return;
[570]         }
[571] 
[572]         return;
[573]     }
[574] 
[575]     if (rc == NGX_ERROR) {
[576]         ngx_mail_proxy_upstream_error(s);
[577]         return;
[578]     }
[579] 
[580]     switch (s->mail_state) {
[581] 
[582]     case ngx_smtp_start:
[583]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send ehlo");
[584] 
[585]         s->connection->log->action = "sending HELO/EHLO to upstream";
[586] 
[587]         cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[588] 
[589]         line.len = sizeof("HELO ")  - 1 + cscf->server_name.len + 2;
[590]         line.data = ngx_pnalloc(c->pool, line.len);
[591]         if (line.data == NULL) {
[592]             ngx_mail_proxy_internal_server_error(s);
[593]             return;
[594]         }
[595] 
[596]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[597] 
[598]         p = ngx_cpymem(line.data,
[599]                        ((s->esmtp || pcf->xclient) ? "EHLO " : "HELO "),
[600]                        sizeof("HELO ") - 1);
[601] 
[602]         p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
[603]         *p++ = CR; *p = LF;
[604] 
[605]         if (pcf->xclient) {
[606]             s->mail_state = ngx_smtp_helo_xclient;
[607] 
[608]         } else if (s->auth_method == NGX_MAIL_AUTH_NONE) {
[609]             s->mail_state = ngx_smtp_helo_from;
[610] 
[611]         } else if (pcf->smtp_auth) {
[612]             s->mail_state = ngx_smtp_helo_auth;
[613] 
[614]         } else {
[615]             s->mail_state = ngx_smtp_helo;
[616]         }
[617] 
[618]         break;
[619] 
[620]     case ngx_smtp_helo_xclient:
[621]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[622]                        "mail proxy send xclient");
[623] 
[624]         s->connection->log->action = "sending XCLIENT to upstream";
[625] 
[626]         line.len = sizeof("XCLIENT ADDR= LOGIN= NAME="
[627]                           CRLF) - 1
[628]                    + s->connection->addr_text.len + s->login.len + s->host.len;
[629] 
[630] #if (NGX_HAVE_INET6)
[631]         if (s->connection->sockaddr->sa_family == AF_INET6) {
[632]             line.len += sizeof("IPV6:") - 1;
[633]         }
[634] #endif
[635] 
[636]         line.data = ngx_pnalloc(c->pool, line.len);
[637]         if (line.data == NULL) {
[638]             ngx_mail_proxy_internal_server_error(s);
[639]             return;
[640]         }
[641] 
[642]         p = ngx_cpymem(line.data, "XCLIENT ADDR=", sizeof("XCLIENT ADDR=") - 1);
[643] 
[644] #if (NGX_HAVE_INET6)
[645]         if (s->connection->sockaddr->sa_family == AF_INET6) {
[646]             p = ngx_cpymem(p, "IPV6:", sizeof("IPV6:") - 1);
[647]         }
[648] #endif
[649] 
[650]         p = ngx_copy(p, s->connection->addr_text.data,
[651]                      s->connection->addr_text.len);
[652] 
[653]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[654] 
[655]         if (s->login.len && !pcf->smtp_auth) {
[656]             p = ngx_cpymem(p, " LOGIN=", sizeof(" LOGIN=") - 1);
[657]             p = ngx_copy(p, s->login.data, s->login.len);
[658]         }
[659] 
[660]         p = ngx_cpymem(p, " NAME=", sizeof(" NAME=") - 1);
[661]         p = ngx_copy(p, s->host.data, s->host.len);
[662] 
[663]         *p++ = CR; *p++ = LF;
[664] 
[665]         line.len = p - line.data;
[666] 
[667]         if (s->smtp_helo.len) {
[668]             s->mail_state = ngx_smtp_xclient_helo;
[669] 
[670]         } else if (s->auth_method == NGX_MAIL_AUTH_NONE) {
[671]             s->mail_state = ngx_smtp_xclient_from;
[672] 
[673]         } else if (pcf->smtp_auth) {
[674]             s->mail_state = ngx_smtp_xclient_auth;
[675] 
[676]         } else {
[677]             s->mail_state = ngx_smtp_xclient;
[678]         }
[679] 
[680]         break;
[681] 
[682]     case ngx_smtp_xclient_helo:
[683]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[684]                        "mail proxy send client ehlo");
[685] 
[686]         s->connection->log->action = "sending client HELO/EHLO to upstream";
[687] 
[688]         line.len = sizeof("HELO " CRLF) - 1 + s->smtp_helo.len;
[689] 
[690]         line.data = ngx_pnalloc(c->pool, line.len);
[691]         if (line.data == NULL) {
[692]             ngx_mail_proxy_internal_server_error(s);
[693]             return;
[694]         }
[695] 
[696]         line.len = ngx_sprintf(line.data,
[697]                        ((s->esmtp) ? "EHLO %V" CRLF : "HELO %V" CRLF),
[698]                        &s->smtp_helo)
[699]                    - line.data;
[700] 
[701]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[702] 
[703]         if (s->auth_method == NGX_MAIL_AUTH_NONE) {
[704]             s->mail_state = ngx_smtp_helo_from;
[705] 
[706]         } else if (pcf->smtp_auth) {
[707]             s->mail_state = ngx_smtp_helo_auth;
[708] 
[709]         } else {
[710]             s->mail_state = ngx_smtp_helo;
[711]         }
[712] 
[713]         break;
[714] 
[715]     case ngx_smtp_helo_auth:
[716]     case ngx_smtp_xclient_auth:
[717]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[718]                        "mail proxy send auth");
[719] 
[720]         s->connection->log->action = "sending AUTH to upstream";
[721] 
[722]         if (s->passwd.data == NULL) {
[723]             ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[724]                           "no password available");
[725]             ngx_mail_proxy_internal_server_error(s);
[726]             return;
[727]         }
[728] 
[729]         auth.len = 1 + s->login.len + 1 + s->passwd.len;
[730]         auth.data = ngx_pnalloc(c->pool, auth.len);
[731]         if (auth.data == NULL) {
[732]             ngx_mail_proxy_internal_server_error(s);
[733]             return;
[734]         }
[735] 
[736]         auth.len = ngx_sprintf(auth.data, "%Z%V%Z%V", &s->login, &s->passwd)
[737]                    - auth.data;
[738] 
[739]         line.len = sizeof("AUTH PLAIN " CRLF) - 1
[740]                    + ngx_base64_encoded_length(auth.len);
[741] 
[742]         line.data = ngx_pnalloc(c->pool, line.len);
[743]         if (line.data == NULL) {
[744]             ngx_mail_proxy_internal_server_error(s);
[745]             return;
[746]         }
[747] 
[748]         encoded.data = ngx_cpymem(line.data, "AUTH PLAIN ",
[749]                                   sizeof("AUTH PLAIN ") - 1);
[750] 
[751]         ngx_encode_base64(&encoded, &auth);
[752] 
[753]         p = encoded.data + encoded.len;
[754]         *p++ = CR; *p = LF;
[755] 
[756]         s->mail_state = ngx_smtp_auth_plain;
[757] 
[758]         break;
[759] 
[760]     case ngx_smtp_helo_from:
[761]     case ngx_smtp_xclient_from:
[762]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[763]                        "mail proxy send mail from");
[764] 
[765]         s->connection->log->action = "sending MAIL FROM to upstream";
[766] 
[767]         line.len = s->smtp_from.len + sizeof(CRLF) - 1;
[768]         line.data = ngx_pnalloc(c->pool, line.len);
[769]         if (line.data == NULL) {
[770]             ngx_mail_proxy_internal_server_error(s);
[771]             return;
[772]         }
[773] 
[774]         p = ngx_cpymem(line.data, s->smtp_from.data, s->smtp_from.len);
[775]         *p++ = CR; *p = LF;
[776] 
[777]         s->mail_state = ngx_smtp_from;
[778] 
[779]         break;
[780] 
[781]     case ngx_smtp_from:
[782]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[783]                        "mail proxy send rcpt to");
[784] 
[785]         s->connection->log->action = "sending RCPT TO to upstream";
[786] 
[787]         line.len = s->smtp_to.len + sizeof(CRLF) - 1;
[788]         line.data = ngx_pnalloc(c->pool, line.len);
[789]         if (line.data == NULL) {
[790]             ngx_mail_proxy_internal_server_error(s);
[791]             return;
[792]         }
[793] 
[794]         p = ngx_cpymem(line.data, s->smtp_to.data, s->smtp_to.len);
[795]         *p++ = CR; *p = LF;
[796] 
[797]         s->mail_state = ngx_smtp_to;
[798] 
[799]         break;
[800] 
[801]     case ngx_smtp_helo:
[802]     case ngx_smtp_xclient:
[803]     case ngx_smtp_auth_plain:
[804]     case ngx_smtp_to:
[805] 
[806]         b = s->proxy->buffer;
[807] 
[808]         if (s->auth_method == NGX_MAIL_AUTH_NONE) {
[809]             b->pos = b->start;
[810] 
[811]         } else {
[812]             ngx_memcpy(b->start, smtp_auth_ok, sizeof(smtp_auth_ok) - 1);
[813]             b->last = b->start + sizeof(smtp_auth_ok) - 1;
[814]         }
[815] 
[816]         s->connection->read->handler = ngx_mail_proxy_handler;
[817]         s->connection->write->handler = ngx_mail_proxy_handler;
[818]         rev->handler = ngx_mail_proxy_handler;
[819]         c->write->handler = ngx_mail_proxy_handler;
[820] 
[821]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[822]         ngx_add_timer(s->connection->read, pcf->timeout);
[823]         ngx_del_timer(c->read);
[824] 
[825]         c->log->action = NULL;
[826]         ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");
[827] 
[828]         if (s->buffer->pos < s->buffer->last
[829]             || s->connection->read->ready)
[830]         {
[831]             ngx_post_event(c->write, &ngx_posted_events);
[832]         }
[833] 
[834]         ngx_mail_proxy_handler(s->connection->write);
[835] 
[836]         return;
[837] 
[838]     default:
[839] #if (NGX_SUPPRESS_WARN)
[840]         ngx_str_null(&line);
[841] #endif
[842]         break;
[843]     }
[844] 
[845]     if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
[846]         /*
[847]          * we treat the incomplete sending as NGX_ERROR
[848]          * because it is very strange here
[849]          */
[850]         ngx_mail_proxy_internal_server_error(s);
[851]         return;
[852]     }
[853] 
[854]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[855]         ngx_mail_proxy_internal_server_error(s);
[856]         return;
[857]     }
[858] 
[859]     s->proxy->buffer->pos = s->proxy->buffer->start;
[860]     s->proxy->buffer->last = s->proxy->buffer->start;
[861] }
[862] 
[863] 
[864] static void
[865] ngx_mail_proxy_write_handler(ngx_event_t *wev)
[866] {
[867]     ngx_connection_t    *c;
[868]     ngx_mail_session_t  *s;
[869] 
[870]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy write handler");
[871] 
[872]     c = wev->data;
[873]     s = c->data;
[874] 
[875]     if (s->proxy->proxy_protocol) {
[876]         if (ngx_mail_proxy_send_proxy_protocol(s) != NGX_OK) {
[877]             return;
[878]         }
[879] 
[880]         s->proxy->proxy_protocol = 0;
[881]     }
[882] 
[883]     if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[884]         ngx_mail_proxy_internal_server_error(s);
[885]     }
[886] 
[887]     if (c->read->ready) {
[888]         ngx_post_event(c->read, &ngx_posted_events);
[889]     }
[890] }
[891] 
[892] 
[893] static ngx_int_t
[894] ngx_mail_proxy_send_proxy_protocol(ngx_mail_session_t *s)
[895] {
[896]     u_char            *p;
[897]     ssize_t            n, size;
[898]     ngx_connection_t  *c;
[899]     u_char             buf[NGX_PROXY_PROTOCOL_V1_MAX_HEADER];
[900] 
[901]     s->connection->log->action = "sending PROXY protocol header to upstream";
[902] 
[903]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[904]                    "mail proxy send PROXY protocol header");
[905] 
[906]     p = ngx_proxy_protocol_write(s->connection, buf,
[907]                                  buf + NGX_PROXY_PROTOCOL_V1_MAX_HEADER);
[908]     if (p == NULL) {
[909]         ngx_mail_proxy_internal_server_error(s);
[910]         return NGX_ERROR;
[911]     }
[912] 
[913]     c = s->proxy->upstream.connection;
[914] 
[915]     size = p - buf;
[916] 
[917]     n = c->send(c, buf, size);
[918] 
[919]     if (n == NGX_AGAIN) {
[920]         if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
[921]             ngx_mail_proxy_internal_server_error(s);
[922]             return NGX_ERROR;
[923]         }
[924] 
[925]         return NGX_AGAIN;
[926]     }
[927] 
[928]     if (n == NGX_ERROR) {
[929]         ngx_mail_proxy_internal_server_error(s);
[930]         return NGX_ERROR;
[931]     }
[932] 
[933]     if (n != size) {
[934] 
[935]         /*
[936]          * PROXY protocol specification:
[937]          * The sender must always ensure that the header
[938]          * is sent at once, so that the transport layer
[939]          * maintains atomicity along the path to the receiver.
[940]          */
[941] 
[942]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[943]                       "could not send PROXY protocol header at once");
[944] 
[945]         ngx_mail_proxy_internal_server_error(s);
[946] 
[947]         return NGX_ERROR;
[948]     }
[949] 
[950]     return NGX_OK;
[951] }
[952] 
[953] 
[954] static ngx_int_t
[955] ngx_mail_proxy_read_response(ngx_mail_session_t *s, ngx_uint_t state)
[956] {
[957]     u_char                 *p, *m;
[958]     ssize_t                 n;
[959]     ngx_buf_t              *b;
[960]     ngx_mail_proxy_conf_t  *pcf;
[961] 
[962]     s->connection->log->action = "reading response from upstream";
[963] 
[964]     b = s->proxy->buffer;
[965] 
[966]     n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
[967]                                             b->last, b->end - b->last);
[968] 
[969]     if (n == NGX_ERROR || n == 0) {
[970]         return NGX_ERROR;
[971]     }
[972] 
[973]     if (n == NGX_AGAIN) {
[974]         return NGX_AGAIN;
[975]     }
[976] 
[977]     b->last += n;
[978] 
[979]     if (b->last - b->pos < 4) {
[980]         return NGX_AGAIN;
[981]     }
[982] 
[983]     if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
[984]         if (b->last == b->end) {
[985]             *(b->last - 1) = '\0';
[986]             ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[987]                           "upstream sent too long response line: \"%s\"",
[988]                           b->pos);
[989]             return NGX_ERROR;
[990]         }
[991] 
[992]         return NGX_AGAIN;
[993]     }
[994] 
[995]     p = b->pos;
[996] 
[997]     switch (s->protocol) {
[998] 
[999]     case NGX_MAIL_POP3_PROTOCOL:
[1000]         if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
[1001]             return NGX_OK;
[1002]         }
[1003]         break;
[1004] 
[1005]     case NGX_MAIL_IMAP_PROTOCOL:
[1006]         switch (state) {
[1007] 
[1008]         case ngx_imap_start:
[1009]             if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
[1010]                 return NGX_OK;
[1011]             }
[1012]             break;
[1013] 
[1014]         case ngx_imap_login:
[1015]         case ngx_imap_user:
[1016]             if (p[0] == '+') {
[1017]                 return NGX_OK;
[1018]             }
[1019]             break;
[1020] 
[1021]         case ngx_imap_passwd:
[1022]             if (ngx_strncmp(p, s->tag.data, s->tag.len) == 0) {
[1023]                 p += s->tag.len;
[1024]                 if (p[0] == 'O' && p[1] == 'K') {
[1025]                     return NGX_OK;
[1026]                 }
[1027]             }
[1028]             break;
[1029]         }
[1030] 
[1031]         break;
[1032] 
[1033]     default: /* NGX_MAIL_SMTP_PROTOCOL */
[1034] 
[1035]         if (p[3] == '-') {
[1036]             /* multiline reply, check if we got last line */
[1037] 
[1038]             m = b->last - (sizeof(CRLF "200" CRLF) - 1);
[1039] 
[1040]             while (m > p) {
[1041]                 if (m[0] == CR && m[1] == LF) {
[1042]                     break;
[1043]                 }
[1044] 
[1045]                 m--;
[1046]             }
[1047] 
[1048]             if (m <= p || m[5] == '-') {
[1049]                 return NGX_AGAIN;
[1050]             }
[1051]         }
[1052] 
[1053]         switch (state) {
[1054] 
[1055]         case ngx_smtp_start:
[1056]             if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
[1057]                 return NGX_OK;
[1058]             }
[1059]             break;
[1060] 
[1061]         case ngx_smtp_helo:
[1062]         case ngx_smtp_helo_xclient:
[1063]         case ngx_smtp_helo_from:
[1064]         case ngx_smtp_helo_auth:
[1065]         case ngx_smtp_from:
[1066]             if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
[1067]                 return NGX_OK;
[1068]             }
[1069]             break;
[1070] 
[1071]         case ngx_smtp_xclient:
[1072]         case ngx_smtp_xclient_from:
[1073]         case ngx_smtp_xclient_helo:
[1074]         case ngx_smtp_xclient_auth:
[1075]             if (p[0] == '2' && (p[1] == '2' || p[1] == '5') && p[2] == '0') {
[1076]                 return NGX_OK;
[1077]             }
[1078]             break;
[1079] 
[1080]         case ngx_smtp_auth_plain:
[1081]             if (p[0] == '2' && p[1] == '3' && p[2] == '5') {
[1082]                 return NGX_OK;
[1083]             }
[1084]             break;
[1085] 
[1086]         case ngx_smtp_to:
[1087]             return NGX_OK;
[1088]         }
[1089] 
[1090]         break;
[1091]     }
[1092] 
[1093]     pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[1094] 
[1095]     if (pcf->pass_error_message == 0) {
[1096]         *(b->last - 2) = '\0';
[1097]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[1098]                       "upstream sent invalid response: \"%s\"", p);
[1099]         return NGX_ERROR;
[1100]     }
[1101] 
[1102]     s->out.len = b->last - p - 2;
[1103]     s->out.data = p;
[1104] 
[1105]     ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
[1106]                   "upstream sent invalid response: \"%V\"", &s->out);
[1107] 
[1108]     s->out.len = b->last - b->pos;
[1109]     s->out.data = b->pos;
[1110] 
[1111]     return NGX_ERROR;
[1112] }
[1113] 
[1114] 
[1115] static void
[1116] ngx_mail_proxy_handler(ngx_event_t *ev)
[1117] {
[1118]     char                   *action, *recv_action, *send_action;
[1119]     size_t                  size;
[1120]     ssize_t                 n;
[1121]     ngx_buf_t              *b;
[1122]     ngx_uint_t              do_write;
[1123]     ngx_connection_t       *c, *src, *dst;
[1124]     ngx_mail_session_t     *s;
[1125]     ngx_mail_proxy_conf_t  *pcf;
[1126] 
[1127]     c = ev->data;
[1128]     s = c->data;
[1129] 
[1130]     if (ev->timedout || c->close) {
[1131]         c->log->action = "proxying";
[1132] 
[1133]         if (c->close) {
[1134]             ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
[1135] 
[1136]         } else if (c == s->connection) {
[1137]             ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
[1138]                           "client timed out");
[1139]             c->timedout = 1;
[1140] 
[1141]         } else {
[1142]             ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
[1143]                           "upstream timed out");
[1144]         }
[1145] 
[1146]         ngx_mail_proxy_close_session(s);
[1147]         return;
[1148]     }
[1149] 
[1150]     if (c == s->connection) {
[1151]         if (ev->write) {
[1152]             recv_action = "proxying and reading from upstream";
[1153]             send_action = "proxying and sending to client";
[1154]             src = s->proxy->upstream.connection;
[1155]             dst = c;
[1156]             b = s->proxy->buffer;
[1157] 
[1158]         } else {
[1159]             recv_action = "proxying and reading from client";
[1160]             send_action = "proxying and sending to upstream";
[1161]             src = c;
[1162]             dst = s->proxy->upstream.connection;
[1163]             b = s->buffer;
[1164]         }
[1165] 
[1166]     } else {
[1167]         if (ev->write) {
[1168]             recv_action = "proxying and reading from client";
[1169]             send_action = "proxying and sending to upstream";
[1170]             src = s->connection;
[1171]             dst = c;
[1172]             b = s->buffer;
[1173] 
[1174]         } else {
[1175]             recv_action = "proxying and reading from upstream";
[1176]             send_action = "proxying and sending to client";
[1177]             src = c;
[1178]             dst = s->connection;
[1179]             b = s->proxy->buffer;
[1180]         }
[1181]     }
[1182] 
[1183]     do_write = ev->write ? 1 : 0;
[1184] 
[1185]     ngx_log_debug3(NGX_LOG_DEBUG_MAIL, ev->log, 0,
[1186]                    "mail proxy handler: %ui, #%d > #%d",
[1187]                    do_write, src->fd, dst->fd);
[1188] 
[1189]     for ( ;; ) {
[1190] 
[1191]         if (do_write) {
[1192] 
[1193]             size = b->last - b->pos;
[1194] 
[1195]             if (size && dst->write->ready) {
[1196]                 c->log->action = send_action;
[1197] 
[1198]                 n = dst->send(dst, b->pos, size);
[1199] 
[1200]                 if (n == NGX_ERROR) {
[1201]                     ngx_mail_proxy_close_session(s);
[1202]                     return;
[1203]                 }
[1204] 
[1205]                 if (n > 0) {
[1206]                     b->pos += n;
[1207] 
[1208]                     if (b->pos == b->last) {
[1209]                         b->pos = b->start;
[1210]                         b->last = b->start;
[1211]                     }
[1212]                 }
[1213]             }
[1214]         }
[1215] 
[1216]         size = b->end - b->last;
[1217] 
[1218]         if (size && src->read->ready) {
[1219]             c->log->action = recv_action;
[1220] 
[1221]             n = src->recv(src, b->last, size);
[1222] 
[1223]             if (n == NGX_AGAIN || n == 0) {
[1224]                 break;
[1225]             }
[1226] 
[1227]             if (n > 0) {
[1228]                 do_write = 1;
[1229]                 b->last += n;
[1230] 
[1231]                 continue;
[1232]             }
[1233] 
[1234]             if (n == NGX_ERROR) {
[1235]                 src->read->eof = 1;
[1236]             }
[1237]         }
[1238] 
[1239]         break;
[1240]     }
[1241] 
[1242]     c->log->action = "proxying";
[1243] 
[1244]     if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
[1245]         || (s->proxy->upstream.connection->read->eof
[1246]             && s->proxy->buffer->pos == s->proxy->buffer->last)
[1247]         || (s->connection->read->eof
[1248]             && s->proxy->upstream.connection->read->eof))
[1249]     {
[1250]         action = c->log->action;
[1251]         c->log->action = NULL;
[1252]         ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
[1253]         c->log->action = action;
[1254] 
[1255]         ngx_mail_proxy_close_session(s);
[1256]         return;
[1257]     }
[1258] 
[1259]     if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
[1260]         ngx_mail_proxy_close_session(s);
[1261]         return;
[1262]     }
[1263] 
[1264]     if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
[1265]         ngx_mail_proxy_close_session(s);
[1266]         return;
[1267]     }
[1268] 
[1269]     if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
[1270]         ngx_mail_proxy_close_session(s);
[1271]         return;
[1272]     }
[1273] 
[1274]     if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
[1275]         ngx_mail_proxy_close_session(s);
[1276]         return;
[1277]     }
[1278] 
[1279]     if (c == s->connection) {
[1280]         pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
[1281]         ngx_add_timer(c->read, pcf->timeout);
[1282]     }
[1283] }
[1284] 
[1285] 
[1286] static void
[1287] ngx_mail_proxy_upstream_error(ngx_mail_session_t *s)
[1288] {
[1289]     if (s->proxy->upstream.connection) {
[1290]         ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[1291]                        "close mail proxy connection: %d",
[1292]                        s->proxy->upstream.connection->fd);
[1293] 
[1294]         ngx_close_connection(s->proxy->upstream.connection);
[1295]     }
[1296] 
[1297]     if (s->out.len == 0) {
[1298]         ngx_mail_session_internal_server_error(s);
[1299]         return;
[1300]     }
[1301] 
[1302]     s->quit = 1;
[1303]     ngx_mail_send(s->connection->write);
[1304] }
[1305] 
[1306] 
[1307] static void
[1308] ngx_mail_proxy_internal_server_error(ngx_mail_session_t *s)
[1309] {
[1310]     if (s->proxy->upstream.connection) {
[1311]         ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[1312]                        "close mail proxy connection: %d",
[1313]                        s->proxy->upstream.connection->fd);
[1314] 
[1315]         ngx_close_connection(s->proxy->upstream.connection);
[1316]     }
[1317] 
[1318]     ngx_mail_session_internal_server_error(s);
[1319] }
[1320] 
[1321] 
[1322] static void
[1323] ngx_mail_proxy_close_session(ngx_mail_session_t *s)
[1324] {
[1325]     if (s->proxy->upstream.connection) {
[1326]         ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[1327]                        "close mail proxy connection: %d",
[1328]                        s->proxy->upstream.connection->fd);
[1329] 
[1330]         ngx_close_connection(s->proxy->upstream.connection);
[1331]     }
[1332] 
[1333]     ngx_mail_close_connection(s->connection);
[1334] }
[1335] 
[1336] 
[1337] static void *
[1338] ngx_mail_proxy_create_conf(ngx_conf_t *cf)
[1339] {
[1340]     ngx_mail_proxy_conf_t  *pcf;
[1341] 
[1342]     pcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_proxy_conf_t));
[1343]     if (pcf == NULL) {
[1344]         return NULL;
[1345]     }
[1346] 
[1347]     pcf->enable = NGX_CONF_UNSET;
[1348]     pcf->pass_error_message = NGX_CONF_UNSET;
[1349]     pcf->xclient = NGX_CONF_UNSET;
[1350]     pcf->smtp_auth = NGX_CONF_UNSET;
[1351]     pcf->proxy_protocol = NGX_CONF_UNSET;
[1352]     pcf->buffer_size = NGX_CONF_UNSET_SIZE;
[1353]     pcf->timeout = NGX_CONF_UNSET_MSEC;
[1354] 
[1355]     return pcf;
[1356] }
[1357] 
[1358] 
[1359] static char *
[1360] ngx_mail_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[1361] {
[1362]     ngx_mail_proxy_conf_t *prev = parent;
[1363]     ngx_mail_proxy_conf_t *conf = child;
[1364] 
[1365]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[1366]     ngx_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
[1367]     ngx_conf_merge_value(conf->xclient, prev->xclient, 1);
[1368]     ngx_conf_merge_value(conf->smtp_auth, prev->smtp_auth, 0);
[1369]     ngx_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);
[1370]     ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
[1371]                               (size_t) ngx_pagesize);
[1372]     ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);
[1373] 
[1374]     return NGX_CONF_OK;
[1375] }
