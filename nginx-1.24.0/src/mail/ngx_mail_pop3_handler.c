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
[12] #include <ngx_mail_pop3_module.h>
[13] 
[14] 
[15] static ngx_int_t ngx_mail_pop3_user(ngx_mail_session_t *s, ngx_connection_t *c);
[16] static ngx_int_t ngx_mail_pop3_pass(ngx_mail_session_t *s, ngx_connection_t *c);
[17] static ngx_int_t ngx_mail_pop3_capa(ngx_mail_session_t *s, ngx_connection_t *c,
[18]     ngx_int_t stls);
[19] static ngx_int_t ngx_mail_pop3_stls(ngx_mail_session_t *s, ngx_connection_t *c);
[20] static ngx_int_t ngx_mail_pop3_apop(ngx_mail_session_t *s, ngx_connection_t *c);
[21] static ngx_int_t ngx_mail_pop3_auth(ngx_mail_session_t *s, ngx_connection_t *c);
[22] 
[23] 
[24] static u_char  pop3_greeting[] = "+OK POP3 ready" CRLF;
[25] static u_char  pop3_ok[] = "+OK" CRLF;
[26] static u_char  pop3_next[] = "+ " CRLF;
[27] static u_char  pop3_username[] = "+ VXNlcm5hbWU6" CRLF;
[28] static u_char  pop3_password[] = "+ UGFzc3dvcmQ6" CRLF;
[29] static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;
[30] 
[31] 
[32] void
[33] ngx_mail_pop3_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
[34] {
[35]     u_char                    *p;
[36]     ngx_mail_core_srv_conf_t  *cscf;
[37]     ngx_mail_pop3_srv_conf_t  *pscf;
[38] 
[39]     pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);
[40]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[41] 
[42]     if (pscf->auth_methods
[43]         & (NGX_MAIL_AUTH_APOP_ENABLED|NGX_MAIL_AUTH_CRAM_MD5_ENABLED))
[44]     {
[45]         if (ngx_mail_salt(s, c, cscf) != NGX_OK) {
[46]             ngx_mail_session_internal_server_error(s);
[47]             return;
[48]         }
[49] 
[50]         s->out.data = ngx_pnalloc(c->pool, sizeof(pop3_greeting) + s->salt.len);
[51]         if (s->out.data == NULL) {
[52]             ngx_mail_session_internal_server_error(s);
[53]             return;
[54]         }
[55] 
[56]         p = ngx_cpymem(s->out.data, pop3_greeting, sizeof(pop3_greeting) - 3);
[57]         *p++ = ' ';
[58]         p = ngx_cpymem(p, s->salt.data, s->salt.len);
[59] 
[60]         s->out.len = p - s->out.data;
[61] 
[62]     } else {
[63]         ngx_str_set(&s->out, pop3_greeting);
[64]     }
[65] 
[66]     c->read->handler = ngx_mail_pop3_init_protocol;
[67] 
[68]     ngx_add_timer(c->read, cscf->timeout);
[69] 
[70]     if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[71]         ngx_mail_close_connection(c);
[72]     }
[73] 
[74]     ngx_mail_send(c->write);
[75] }
[76] 
[77] 
[78] void
[79] ngx_mail_pop3_init_protocol(ngx_event_t *rev)
[80] {
[81]     ngx_connection_t    *c;
[82]     ngx_mail_session_t  *s;
[83] 
[84]     c = rev->data;
[85] 
[86]     c->log->action = "in auth state";
[87] 
[88]     if (rev->timedout) {
[89]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[90]         c->timedout = 1;
[91]         ngx_mail_close_connection(c);
[92]         return;
[93]     }
[94] 
[95]     s = c->data;
[96] 
[97]     if (s->buffer == NULL) {
[98]         if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
[99]             == NGX_ERROR)
[100]         {
[101]             ngx_mail_session_internal_server_error(s);
[102]             return;
[103]         }
[104] 
[105]         s->buffer = ngx_create_temp_buf(c->pool, 128);
[106]         if (s->buffer == NULL) {
[107]             ngx_mail_session_internal_server_error(s);
[108]             return;
[109]         }
[110]     }
[111] 
[112]     s->mail_state = ngx_pop3_start;
[113]     c->read->handler = ngx_mail_pop3_auth_state;
[114] 
[115]     ngx_mail_pop3_auth_state(rev);
[116] }
[117] 
[118] 
[119] void
[120] ngx_mail_pop3_auth_state(ngx_event_t *rev)
[121] {
[122]     ngx_int_t            rc;
[123]     ngx_connection_t    *c;
[124]     ngx_mail_session_t  *s;
[125] 
[126]     c = rev->data;
[127]     s = c->data;
[128] 
[129]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "pop3 auth state");
[130] 
[131]     if (rev->timedout) {
[132]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[133]         c->timedout = 1;
[134]         ngx_mail_close_connection(c);
[135]         return;
[136]     }
[137] 
[138]     if (s->out.len) {
[139]         ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "pop3 send handler busy");
[140]         s->blocked = 1;
[141] 
[142]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[143]             ngx_mail_close_connection(c);
[144]             return;
[145]         }
[146] 
[147]         return;
[148]     }
[149] 
[150]     s->blocked = 0;
[151] 
[152]     rc = ngx_mail_read_command(s, c);
[153] 
[154]     if (rc == NGX_AGAIN) {
[155]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[156]             ngx_mail_session_internal_server_error(s);
[157]             return;
[158]         }
[159] 
[160]         return;
[161]     }
[162] 
[163]     if (rc == NGX_ERROR) {
[164]         return;
[165]     }
[166] 
[167]     ngx_str_set(&s->out, pop3_ok);
[168] 
[169]     if (rc == NGX_OK) {
[170]         switch (s->mail_state) {
[171] 
[172]         case ngx_pop3_start:
[173] 
[174]             switch (s->command) {
[175] 
[176]             case NGX_POP3_USER:
[177]                 rc = ngx_mail_pop3_user(s, c);
[178]                 break;
[179] 
[180]             case NGX_POP3_CAPA:
[181]                 rc = ngx_mail_pop3_capa(s, c, 1);
[182]                 break;
[183] 
[184]             case NGX_POP3_APOP:
[185]                 rc = ngx_mail_pop3_apop(s, c);
[186]                 break;
[187] 
[188]             case NGX_POP3_AUTH:
[189]                 rc = ngx_mail_pop3_auth(s, c);
[190]                 break;
[191] 
[192]             case NGX_POP3_QUIT:
[193]                 s->quit = 1;
[194]                 break;
[195] 
[196]             case NGX_POP3_NOOP:
[197]                 break;
[198] 
[199]             case NGX_POP3_STLS:
[200]                 rc = ngx_mail_pop3_stls(s, c);
[201]                 break;
[202] 
[203]             default:
[204]                 rc = NGX_MAIL_PARSE_INVALID_COMMAND;
[205]                 break;
[206]             }
[207] 
[208]             break;
[209] 
[210]         case ngx_pop3_user:
[211] 
[212]             switch (s->command) {
[213] 
[214]             case NGX_POP3_PASS:
[215]                 rc = ngx_mail_pop3_pass(s, c);
[216]                 break;
[217] 
[218]             case NGX_POP3_CAPA:
[219]                 rc = ngx_mail_pop3_capa(s, c, 0);
[220]                 break;
[221] 
[222]             case NGX_POP3_QUIT:
[223]                 s->quit = 1;
[224]                 break;
[225] 
[226]             case NGX_POP3_NOOP:
[227]                 break;
[228] 
[229]             default:
[230]                 rc = NGX_MAIL_PARSE_INVALID_COMMAND;
[231]                 break;
[232]             }
[233] 
[234]             break;
[235] 
[236]         /* suppress warnings */
[237]         case ngx_pop3_passwd:
[238]             break;
[239] 
[240]         case ngx_pop3_auth_login_username:
[241]             rc = ngx_mail_auth_login_username(s, c, 0);
[242] 
[243]             ngx_str_set(&s->out, pop3_password);
[244]             s->mail_state = ngx_pop3_auth_login_password;
[245]             break;
[246] 
[247]         case ngx_pop3_auth_login_password:
[248]             rc = ngx_mail_auth_login_password(s, c);
[249]             break;
[250] 
[251]         case ngx_pop3_auth_plain:
[252]             rc = ngx_mail_auth_plain(s, c, 0);
[253]             break;
[254] 
[255]         case ngx_pop3_auth_cram_md5:
[256]             rc = ngx_mail_auth_cram_md5(s, c);
[257]             break;
[258] 
[259]         case ngx_pop3_auth_external:
[260]             rc = ngx_mail_auth_external(s, c, 0);
[261]             break;
[262]         }
[263]     }
[264] 
[265]     if (s->buffer->pos < s->buffer->last) {
[266]         s->blocked = 1;
[267]     }
[268] 
[269]     switch (rc) {
[270] 
[271]     case NGX_DONE:
[272]         ngx_mail_auth(s, c);
[273]         return;
[274] 
[275]     case NGX_ERROR:
[276]         ngx_mail_session_internal_server_error(s);
[277]         return;
[278] 
[279]     case NGX_MAIL_PARSE_INVALID_COMMAND:
[280]         s->mail_state = ngx_pop3_start;
[281]         s->state = 0;
[282] 
[283]         ngx_str_set(&s->out, pop3_invalid_command);
[284] 
[285]         /* fall through */
[286] 
[287]     case NGX_OK:
[288] 
[289]         s->args.nelts = 0;
[290] 
[291]         if (s->buffer->pos == s->buffer->last) {
[292]             s->buffer->pos = s->buffer->start;
[293]             s->buffer->last = s->buffer->start;
[294]         }
[295] 
[296]         if (s->state) {
[297]             s->arg_start = s->buffer->pos;
[298]         }
[299] 
[300]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[301]             ngx_mail_session_internal_server_error(s);
[302]             return;
[303]         }
[304] 
[305]         ngx_mail_send(c->write);
[306]     }
[307] }
[308] 
[309] static ngx_int_t
[310] ngx_mail_pop3_user(ngx_mail_session_t *s, ngx_connection_t *c)
[311] {
[312]     ngx_str_t  *arg;
[313] 
[314] #if (NGX_MAIL_SSL)
[315]     if (ngx_mail_starttls_only(s, c)) {
[316]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[317]     }
[318] #endif
[319] 
[320]     if (s->args.nelts != 1) {
[321]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[322]     }
[323] 
[324]     arg = s->args.elts;
[325]     s->login.len = arg[0].len;
[326]     s->login.data = ngx_pnalloc(c->pool, s->login.len);
[327]     if (s->login.data == NULL) {
[328]         return NGX_ERROR;
[329]     }
[330] 
[331]     ngx_memcpy(s->login.data, arg[0].data, s->login.len);
[332] 
[333]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[334]                    "pop3 login: \"%V\"", &s->login);
[335] 
[336]     s->mail_state = ngx_pop3_user;
[337] 
[338]     return NGX_OK;
[339] }
[340] 
[341] 
[342] static ngx_int_t
[343] ngx_mail_pop3_pass(ngx_mail_session_t *s, ngx_connection_t *c)
[344] {
[345]     ngx_str_t  *arg;
[346] 
[347]     if (s->args.nelts != 1) {
[348]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[349]     }
[350] 
[351]     arg = s->args.elts;
[352]     s->passwd.len = arg[0].len;
[353]     s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
[354]     if (s->passwd.data == NULL) {
[355]         return NGX_ERROR;
[356]     }
[357] 
[358]     ngx_memcpy(s->passwd.data, arg[0].data, s->passwd.len);
[359] 
[360] #if (NGX_DEBUG_MAIL_PASSWD)
[361]     ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
[362]                    "pop3 passwd: \"%V\"", &s->passwd);
[363] #endif
[364] 
[365]     return NGX_DONE;
[366] }
[367] 
[368] 
[369] static ngx_int_t
[370] ngx_mail_pop3_capa(ngx_mail_session_t *s, ngx_connection_t *c, ngx_int_t stls)
[371] {
[372]     ngx_mail_pop3_srv_conf_t  *pscf;
[373] 
[374]     pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);
[375] 
[376] #if (NGX_MAIL_SSL)
[377] 
[378]     if (stls && c->ssl == NULL) {
[379]         ngx_mail_ssl_conf_t  *sslcf;
[380] 
[381]         sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[382] 
[383]         if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
[384]             s->out = pscf->starttls_capability;
[385]             return NGX_OK;
[386]         }
[387] 
[388]         if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
[389]             s->out = pscf->starttls_only_capability;
[390]             return NGX_OK;
[391]         }
[392]     }
[393] 
[394] #endif
[395] 
[396]     s->out = pscf->capability;
[397]     return NGX_OK;
[398] }
[399] 
[400] 
[401] static ngx_int_t
[402] ngx_mail_pop3_stls(ngx_mail_session_t *s, ngx_connection_t *c)
[403] {
[404] #if (NGX_MAIL_SSL)
[405]     ngx_mail_ssl_conf_t  *sslcf;
[406] 
[407]     if (c->ssl == NULL) {
[408]         sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[409]         if (sslcf->starttls) {
[410]             s->buffer->pos = s->buffer->start;
[411]             s->buffer->last = s->buffer->start;
[412]             c->read->handler = ngx_mail_starttls_handler;
[413]             return NGX_OK;
[414]         }
[415]     }
[416] 
[417] #endif
[418] 
[419]     return NGX_MAIL_PARSE_INVALID_COMMAND;
[420] }
[421] 
[422] 
[423] static ngx_int_t
[424] ngx_mail_pop3_apop(ngx_mail_session_t *s, ngx_connection_t *c)
[425] {
[426]     ngx_str_t                 *arg;
[427]     ngx_mail_pop3_srv_conf_t  *pscf;
[428] 
[429] #if (NGX_MAIL_SSL)
[430]     if (ngx_mail_starttls_only(s, c)) {
[431]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[432]     }
[433] #endif
[434] 
[435]     if (s->args.nelts != 2) {
[436]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[437]     }
[438] 
[439]     pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);
[440] 
[441]     if (!(pscf->auth_methods & NGX_MAIL_AUTH_APOP_ENABLED)) {
[442]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[443]     }
[444] 
[445]     arg = s->args.elts;
[446] 
[447]     s->login.len = arg[0].len;
[448]     s->login.data = ngx_pnalloc(c->pool, s->login.len);
[449]     if (s->login.data == NULL) {
[450]         return NGX_ERROR;
[451]     }
[452] 
[453]     ngx_memcpy(s->login.data, arg[0].data, s->login.len);
[454] 
[455]     s->passwd.len = arg[1].len;
[456]     s->passwd.data = ngx_pnalloc(c->pool, s->passwd.len);
[457]     if (s->passwd.data == NULL) {
[458]         return NGX_ERROR;
[459]     }
[460] 
[461]     ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);
[462] 
[463]     ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
[464]                    "pop3 apop: \"%V\" \"%V\"", &s->login, &s->passwd);
[465] 
[466]     s->auth_method = NGX_MAIL_AUTH_APOP;
[467] 
[468]     return NGX_DONE;
[469] }
[470] 
[471] 
[472] static ngx_int_t
[473] ngx_mail_pop3_auth(ngx_mail_session_t *s, ngx_connection_t *c)
[474] {
[475]     ngx_int_t                  rc;
[476]     ngx_mail_pop3_srv_conf_t  *pscf;
[477] 
[478] #if (NGX_MAIL_SSL)
[479]     if (ngx_mail_starttls_only(s, c)) {
[480]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[481]     }
[482] #endif
[483] 
[484]     pscf = ngx_mail_get_module_srv_conf(s, ngx_mail_pop3_module);
[485] 
[486]     if (s->args.nelts == 0) {
[487]         s->out = pscf->auth_capability;
[488]         s->state = 0;
[489] 
[490]         return NGX_OK;
[491]     }
[492] 
[493]     rc = ngx_mail_auth_parse(s, c);
[494] 
[495]     switch (rc) {
[496] 
[497]     case NGX_MAIL_AUTH_LOGIN:
[498] 
[499]         ngx_str_set(&s->out, pop3_username);
[500]         s->mail_state = ngx_pop3_auth_login_username;
[501] 
[502]         return NGX_OK;
[503] 
[504]     case NGX_MAIL_AUTH_LOGIN_USERNAME:
[505] 
[506]         ngx_str_set(&s->out, pop3_password);
[507]         s->mail_state = ngx_pop3_auth_login_password;
[508] 
[509]         return ngx_mail_auth_login_username(s, c, 1);
[510] 
[511]     case NGX_MAIL_AUTH_PLAIN:
[512] 
[513]         ngx_str_set(&s->out, pop3_next);
[514]         s->mail_state = ngx_pop3_auth_plain;
[515] 
[516]         return NGX_OK;
[517] 
[518]     case NGX_MAIL_AUTH_CRAM_MD5:
[519] 
[520]         if (!(pscf->auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)) {
[521]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[522]         }
[523] 
[524]         if (ngx_mail_auth_cram_md5_salt(s, c, "+ ", 2) == NGX_OK) {
[525]             s->mail_state = ngx_pop3_auth_cram_md5;
[526]             return NGX_OK;
[527]         }
[528] 
[529]         return NGX_ERROR;
[530] 
[531]     case NGX_MAIL_AUTH_EXTERNAL:
[532] 
[533]         if (!(pscf->auth_methods & NGX_MAIL_AUTH_EXTERNAL_ENABLED)) {
[534]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[535]         }
[536] 
[537]         ngx_str_set(&s->out, pop3_username);
[538]         s->mail_state = ngx_pop3_auth_external;
[539] 
[540]         return NGX_OK;
[541]     }
[542] 
[543]     return rc;
[544] }
