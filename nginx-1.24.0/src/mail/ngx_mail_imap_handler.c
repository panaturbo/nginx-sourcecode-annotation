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
[12] #include <ngx_mail_imap_module.h>
[13] 
[14] 
[15] static ngx_int_t ngx_mail_imap_login(ngx_mail_session_t *s,
[16]     ngx_connection_t *c);
[17] static ngx_int_t ngx_mail_imap_authenticate(ngx_mail_session_t *s,
[18]     ngx_connection_t *c);
[19] static ngx_int_t ngx_mail_imap_capability(ngx_mail_session_t *s,
[20]     ngx_connection_t *c);
[21] static ngx_int_t ngx_mail_imap_starttls(ngx_mail_session_t *s,
[22]     ngx_connection_t *c);
[23] 
[24] 
[25] static u_char  imap_greeting[] = "* OK IMAP4 ready" CRLF;
[26] static u_char  imap_star[] = "* ";
[27] static u_char  imap_ok[] = "OK completed" CRLF;
[28] static u_char  imap_next[] = "+ OK" CRLF;
[29] static u_char  imap_plain_next[] = "+ " CRLF;
[30] static u_char  imap_username[] = "+ VXNlcm5hbWU6" CRLF;
[31] static u_char  imap_password[] = "+ UGFzc3dvcmQ6" CRLF;
[32] static u_char  imap_bye[] = "* BYE" CRLF;
[33] static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;
[34] 
[35] 
[36] void
[37] ngx_mail_imap_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
[38] {
[39]     ngx_mail_core_srv_conf_t  *cscf;
[40] 
[41]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[42] 
[43]     ngx_str_set(&s->out, imap_greeting);
[44] 
[45]     c->read->handler = ngx_mail_imap_init_protocol;
[46] 
[47]     ngx_add_timer(c->read, cscf->timeout);
[48] 
[49]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[50]         ngx_mail_close_connection(c);
[51]     }
[52] 
[53]     ngx_mail_send(c->write);
[54] }
[55] 
[56] 
[57] void
[58] ngx_mail_imap_init_protocol(ngx_event_t *rev)
[59] {
[60]     ngx_connection_t          *c;
[61]     ngx_mail_session_t        *s;
[62]     ngx_mail_imap_srv_conf_t  *iscf;
[63] 
[64]     c = rev->data;
[65] 
[66]     c->log->action = "in auth state";
[67] 
[68]     if (rev->timedout) {
[69]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[70]         c->timedout = 1;
[71]         ngx_mail_close_connection(c);
[72]         return;
[73]     }
[74] 
[75]     s = c->data;
[76] 
[77]     if (s->buffer == NULL) {
[78]         if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
[79]             == NGX_ERROR)
[80]         {
[81]             ngx_mail_session_internal_server_error(s);
[82]             return;
[83]         }
[84] 
[85]         iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);
[86] 
[87]         s->buffer = ngx_create_temp_buf(c->pool, iscf->client_buffer_size);
[88]         if (s->buffer == NULL) {
[89]             ngx_mail_session_internal_server_error(s);
[90]             return;
[91]         }
[92]     }
[93] 
[94]     s->mail_state = ngx_imap_start;
[95]     c->read->handler = ngx_mail_imap_auth_state;
[96] 
[97]     ngx_mail_imap_auth_state(rev);
[98] }
[99] 
[100] 
[101] void
[102] ngx_mail_imap_auth_state(ngx_event_t *rev)
[103] {
[104]     u_char              *p;
[105]     ngx_int_t            rc;
[106]     ngx_uint_t           tag;
[107]     ngx_connection_t    *c;
[108]     ngx_mail_session_t  *s;
[109] 
[110]     c = rev->data;
[111]     s = c->data;
[112] 
[113]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap auth state");
[114] 
[115]     if (rev->timedout) {
[116]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[117]         c->timedout = 1;
[118]         ngx_mail_close_connection(c);
[119]         return;
[120]     }
[121] 
[122]     if (s->out.len) {
[123]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap send handler busy");
[124]         s->blocked = 1;
[125] 
[126]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[127]             ngx_mail_close_connection(c);
[128]             return;
[129]         }
[130] 
[131]         return;
[132]     }
[133] 
[134]     s->blocked = 0;
[135] 
[136]     rc = ngx_mail_read_command(s, c);
[137] 
[138]     if (rc == NGX_AGAIN) {
[139]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[140]             ngx_mail_session_internal_server_error(s);
[141]             return;
[142]         }
[143] 
[144]         return;
[145]     }
[146] 
[147]     if (rc == NGX_ERROR) {
[148]         return;
[149]     }
[150] 
[151]     tag = 1;
[152]     s->text.len = 0;
[153]     ngx_str_set(&s->out, imap_ok);
[154] 
[155]     if (rc == NGX_OK) {
[156] 
[157]         ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap auth command: %i",
[158]                        s->command);
[159] 
[160]         switch (s->mail_state) {
[161] 
[162]         case ngx_imap_start:
[163] 
[164]             switch (s->command) {
[165] 
[166]             case NGX_IMAP_LOGIN:
[167]                 rc = ngx_mail_imap_login(s, c);
[168]                 break;
[169] 
[170]             case NGX_IMAP_AUTHENTICATE:
[171]                 rc = ngx_mail_imap_authenticate(s, c);
[172]                 tag = (rc != NGX_OK);
[173]                 break;
[174] 
[175]             case NGX_IMAP_CAPABILITY:
[176]                 rc = ngx_mail_imap_capability(s, c);
[177]                 break;
[178] 
[179]             case NGX_IMAP_LOGOUT:
[180]                 s->quit = 1;
[181]                 ngx_str_set(&s->text, imap_bye);
[182]                 break;
[183] 
[184]             case NGX_IMAP_NOOP:
[185]                 break;
[186] 
[187]             case NGX_IMAP_STARTTLS:
[188]                 rc = ngx_mail_imap_starttls(s, c);
[189]                 break;
[190] 
[191]             default:
[192]                 rc = NGX_MAIL_PARSE_INVALID_COMMAND;
[193]                 break;
[194]             }
[195] 
[196]             break;
[197] 
[198]         case ngx_imap_auth_login_username:
[199]             rc = ngx_mail_auth_login_username(s, c, 0);
[200] 
[201]             tag = 0;
[202]             ngx_str_set(&s->out, imap_password);
[203]             s->mail_state = ngx_imap_auth_login_password;
[204] 
[205]             break;
[206] 
[207]         case ngx_imap_auth_login_password:
[208]             rc = ngx_mail_auth_login_password(s, c);
[209]             break;
[210] 
[211]         case ngx_imap_auth_plain:
[212]             rc = ngx_mail_auth_plain(s, c, 0);
[213]             break;
[214] 
[215]         case ngx_imap_auth_cram_md5:
[216]             rc = ngx_mail_auth_cram_md5(s, c);
[217]             break;
[218] 
[219]         case ngx_imap_auth_external:
[220]             rc = ngx_mail_auth_external(s, c, 0);
[221]             break;
[222]         }
[223] 
[224]     } else if (rc == NGX_IMAP_NEXT) {
[225]         tag = 0;
[226]         ngx_str_set(&s->out, imap_next);
[227]     }
[228] 
[229]     if (s->buffer->pos < s->buffer->last) {
[230]         s->blocked = 1;
[231]     }
[232] 
[233]     switch (rc) {
[234] 
[235]     case NGX_DONE:
[236]         ngx_mail_auth(s, c);
[237]         return;
[238] 
[239]     case NGX_ERROR:
[240]         ngx_mail_session_internal_server_error(s);
[241]         return;
[242] 
[243]     case NGX_MAIL_PARSE_INVALID_COMMAND:
[244]         s->state = 0;
[245]         ngx_str_set(&s->out, imap_invalid_command);
[246]         s->mail_state = ngx_imap_start;
[247]         break;
[248]     }
[249] 
[250]     if (tag) {
[251]         if (s->tag.len == 0) {
[252]             ngx_str_set(&s->tag, imap_star);
[253]         }
[254] 
[255]         if (s->tagged_line.len < s->tag.len + s->text.len + s->out.len) {
[256]             s->tagged_line.len = s->tag.len + s->text.len + s->out.len;
[257]             s->tagged_line.data = ngx_pnalloc(c->pool, s->tagged_line.len);
[258]             if (s->tagged_line.data == NULL) {
[259]                 ngx_mail_close_connection(c);
[260]                 return;
[261]             }
[262]         }
[263] 
[264]         p = s->tagged_line.data;
[265] 
[266]         if (s->text.len) {
[267]             p = ngx_cpymem(p, s->text.data, s->text.len);
[268]         }
[269] 
[270]         p = ngx_cpymem(p, s->tag.data, s->tag.len);
[271]         ngx_memcpy(p, s->out.data, s->out.len);
[272] 
[273]         s->out.len = s->text.len + s->tag.len + s->out.len;
[274]         s->out.data = s->tagged_line.data;
[275]     }
[276] 
[277]     if (rc != NGX_IMAP_NEXT) {
[278]         s->args.nelts = 0;
[279] 
[280]         if (s->state) {
[281]             /* preserve tag */
[282]             s->arg_start = s->buffer->pos;
[283] 
[284]         } else {
[285]             if (s->buffer->pos == s->buffer->last) {
[286]                 s->buffer->pos = s->buffer->start;
[287]                 s->buffer->last = s->buffer->start;
[288]             }
[289] 
[290]             s->tag.len = 0;
[291]         }
[292]     }
[293] 
[294]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[295]         ngx_mail_session_internal_server_error(s);
[296]         return;
[297]     }
[298] 
[299]     ngx_mail_send(c->write);
[300] }
[301] 
[302] 
[303] static ngx_int_t
[304] ngx_mail_imap_login(ngx_mail_session_t *s, ngx_connection_t *c)
[305] {
[306]     ngx_str_t  *arg;
[307] 
[308] #if (NGX_MAIL_SSL)
[309]     if (ngx_mail_starttls_only(s, c)) {
[310]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[311]     }
[312] #endif
[313] 
[314]     arg = s->args.elts;
[315] 
[316]     if (s->args.nelts != 2 || arg[0].len == 0) {
[317]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[318]     }
[319] 
[320]     s->login.len = arg[0].len;
[321]     s->login.data = ngx_pnalloc(c->pool, s->login.len);
[322]     if (s->login.data == NULL) {
[323]         return NGX_ERROR;
[324]     }
[325] 
[326]     ngx_memcpy(s->login.data, arg[0].data, s->login.len);
[327] 
[328]     s->passwd.len = arg[1].len;
[329]     s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
[330]     if (s->passwd.data == NULL) {
[331]         return NGX_ERROR;
[332]     }
[333] 
[334]     ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);
[335] 
[336] #if (NGX_DEBUG_MAIL_PASSWD)
[337]     ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
[338]                    "imap login:\"%V\" passwd:\"%V\"",
[339]                    &s->login, &s->passwd);
[340] #else
[341]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[342]                    "imap login:\"%V\"", &s->login);
[343] #endif
[344] 
[345]     return NGX_DONE;
[346] }
[347] 
[348] 
[349] static ngx_int_t
[350] ngx_mail_imap_authenticate(ngx_mail_session_t *s, ngx_connection_t *c)
[351] {
[352]     ngx_int_t                  rc;
[353]     ngx_mail_core_srv_conf_t  *cscf;
[354]     ngx_mail_imap_srv_conf_t  *iscf;
[355] 
[356] #if (NGX_MAIL_SSL)
[357]     if (ngx_mail_starttls_only(s, c)) {
[358]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[359]     }
[360] #endif
[361] 
[362]     iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);
[363] 
[364]     rc = ngx_mail_auth_parse(s, c);
[365] 
[366]     switch (rc) {
[367] 
[368]     case NGX_MAIL_AUTH_LOGIN:
[369] 
[370]         ngx_str_set(&s->out, imap_username);
[371]         s->mail_state = ngx_imap_auth_login_username;
[372] 
[373]         return NGX_OK;
[374] 
[375]     case NGX_MAIL_AUTH_LOGIN_USERNAME:
[376] 
[377]         ngx_str_set(&s->out, imap_password);
[378]         s->mail_state = ngx_imap_auth_login_password;
[379] 
[380]         return ngx_mail_auth_login_username(s, c, 1);
[381] 
[382]     case NGX_MAIL_AUTH_PLAIN:
[383] 
[384]         ngx_str_set(&s->out, imap_plain_next);
[385]         s->mail_state = ngx_imap_auth_plain;
[386] 
[387]         return NGX_OK;
[388] 
[389]     case NGX_MAIL_AUTH_CRAM_MD5:
[390] 
[391]         if (!(iscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
[392]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[393]         }
[394] 
[395]         if (s->salt.data == NULL) {
[396]             cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[397] 
[398]             if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
[399]                 return NGX_ERROR;
[400]             }
[401]         }
[402] 
[403]         if (ngx_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NGX_OK) {
[404]             s->mail_state = ngx_imap_auth_cram_md5;
[405]             return NGX_OK;
[406]         }
[407] 
[408]         return NGX_ERROR;
[409] 
[410]     case NGX_MAIL_AUTH_EXTERNAL:
[411] 
[412]         if (!(iscf->auth_methods & NGX_MAIL_AUTH_EXTERNAL_ENABLED)) {
[413]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[414]         }
[415] 
[416]         ngx_str_set(&s->out, imap_username);
[417]         s->mail_state = ngx_imap_auth_external;
[418] 
[419]         return NGX_OK;
[420]     }
[421] 
[422]     return rc;
[423] }
[424] 
[425] 
[426] static ngx_int_t
[427] ngx_mail_imap_capability(ngx_mail_session_t *s, ngx_connection_t *c)
[428] {
[429]     ngx_mail_imap_srv_conf_t  *iscf;
[430] 
[431]     iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_imap_module);
[432] 
[433] #if (NGX_MAIL_SSL)
[434] 
[435]     if (c->ssl == NULL) {
[436]         ngx_mail_ssl_conf_t  *sslcf;
[437] 
[438]         sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[439] 
[440]         if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
[441]             s->text = iscf->starttls_capability;
[442]             return NGX_OK;
[443]         }
[444] 
[445]         if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
[446]             s->text = iscf->starttls_only_capability;
[447]             return NGX_OK;
[448]         }
[449]     }
[450] #endif
[451] 
[452]     s->text = iscf->capability;
[453] 
[454]     return NGX_OK;
[455] }
[456] 
[457] 
[458] static ngx_int_t
[459] ngx_mail_imap_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
[460] {
[461] #if (NGX_MAIL_SSL)
[462]     ngx_mail_ssl_conf_t  *sslcf;
[463] 
[464]     if (c->ssl == NULL) {
[465]         sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[466]         if (sslcf->starttls) {
[467]             s->buffer->pos = s->buffer->start;
[468]             s->buffer->last = s->buffer->start;
[469]             c->read->handler = ngx_mail_starttls_handler;
[470]             return NGX_OK;
[471]         }
[472]     }
[473] 
[474] #endif
[475] 
[476]     return NGX_MAIL_PARSE_INVALID_COMMAND;
[477] }
