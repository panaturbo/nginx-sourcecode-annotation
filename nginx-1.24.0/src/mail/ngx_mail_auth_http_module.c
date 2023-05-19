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
[16]     ngx_addr_t                     *peer;
[17] 
[18]     ngx_msec_t                      timeout;
[19]     ngx_flag_t                      pass_client_cert;
[20] 
[21]     ngx_str_t                       host_header;
[22]     ngx_str_t                       uri;
[23]     ngx_str_t                       header;
[24] 
[25]     ngx_array_t                    *headers;
[26] 
[27]     u_char                         *file;
[28]     ngx_uint_t                      line;
[29] } ngx_mail_auth_http_conf_t;
[30] 
[31] 
[32] typedef struct ngx_mail_auth_http_ctx_s  ngx_mail_auth_http_ctx_t;
[33] 
[34] typedef void (*ngx_mail_auth_http_handler_pt)(ngx_mail_session_t *s,
[35]     ngx_mail_auth_http_ctx_t *ctx);
[36] 
[37] struct ngx_mail_auth_http_ctx_s {
[38]     ngx_buf_t                      *request;
[39]     ngx_buf_t                      *response;
[40]     ngx_peer_connection_t           peer;
[41] 
[42]     ngx_mail_auth_http_handler_pt   handler;
[43] 
[44]     ngx_uint_t                      state;
[45] 
[46]     u_char                         *header_name_start;
[47]     u_char                         *header_name_end;
[48]     u_char                         *header_start;
[49]     u_char                         *header_end;
[50] 
[51]     ngx_str_t                       addr;
[52]     ngx_str_t                       port;
[53]     ngx_str_t                       err;
[54]     ngx_str_t                       errmsg;
[55]     ngx_str_t                       errcode;
[56] 
[57]     time_t                          sleep;
[58] 
[59]     ngx_pool_t                     *pool;
[60] };
[61] 
[62] 
[63] static void ngx_mail_auth_http_write_handler(ngx_event_t *wev);
[64] static void ngx_mail_auth_http_read_handler(ngx_event_t *rev);
[65] static void ngx_mail_auth_http_ignore_status_line(ngx_mail_session_t *s,
[66]     ngx_mail_auth_http_ctx_t *ctx);
[67] static void ngx_mail_auth_http_process_headers(ngx_mail_session_t *s,
[68]     ngx_mail_auth_http_ctx_t *ctx);
[69] static void ngx_mail_auth_sleep_handler(ngx_event_t *rev);
[70] static ngx_int_t ngx_mail_auth_http_parse_header_line(ngx_mail_session_t *s,
[71]     ngx_mail_auth_http_ctx_t *ctx);
[72] static void ngx_mail_auth_http_block_read(ngx_event_t *rev);
[73] static void ngx_mail_auth_http_dummy_handler(ngx_event_t *ev);
[74] static ngx_buf_t *ngx_mail_auth_http_create_request(ngx_mail_session_t *s,
[75]     ngx_pool_t *pool, ngx_mail_auth_http_conf_t *ahcf);
[76] static ngx_int_t ngx_mail_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text,
[77]     ngx_str_t *escaped);
[78] 
[79] static void *ngx_mail_auth_http_create_conf(ngx_conf_t *cf);
[80] static char *ngx_mail_auth_http_merge_conf(ngx_conf_t *cf, void *parent,
[81]     void *child);
[82] static char *ngx_mail_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[83] static char *ngx_mail_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd,
[84]     void *conf);
[85] 
[86] 
[87] static ngx_command_t  ngx_mail_auth_http_commands[] = {
[88] 
[89]     { ngx_string("auth_http"),
[90]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[91]       ngx_mail_auth_http,
[92]       NGX_MAIL_SRV_CONF_OFFSET,
[93]       0,
[94]       NULL },
[95] 
[96]     { ngx_string("auth_http_timeout"),
[97]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[98]       ngx_conf_set_msec_slot,
[99]       NGX_MAIL_SRV_CONF_OFFSET,
[100]       offsetof(ngx_mail_auth_http_conf_t, timeout),
[101]       NULL },
[102] 
[103]     { ngx_string("auth_http_header"),
[104]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE2,
[105]       ngx_mail_auth_http_header,
[106]       NGX_MAIL_SRV_CONF_OFFSET,
[107]       0,
[108]       NULL },
[109] 
[110]     { ngx_string("auth_http_pass_client_cert"),
[111]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
[112]       ngx_conf_set_flag_slot,
[113]       NGX_MAIL_SRV_CONF_OFFSET,
[114]       offsetof(ngx_mail_auth_http_conf_t, pass_client_cert),
[115]       NULL },
[116] 
[117]       ngx_null_command
[118] };
[119] 
[120] 
[121] static ngx_mail_module_t  ngx_mail_auth_http_module_ctx = {
[122]     NULL,                                  /* protocol */
[123] 
[124]     NULL,                                  /* create main configuration */
[125]     NULL,                                  /* init main configuration */
[126] 
[127]     ngx_mail_auth_http_create_conf,        /* create server configuration */
[128]     ngx_mail_auth_http_merge_conf          /* merge server configuration */
[129] };
[130] 
[131] 
[132] ngx_module_t  ngx_mail_auth_http_module = {
[133]     NGX_MODULE_V1,
[134]     &ngx_mail_auth_http_module_ctx,        /* module context */
[135]     ngx_mail_auth_http_commands,           /* module directives */
[136]     NGX_MAIL_MODULE,                       /* module type */
[137]     NULL,                                  /* init master */
[138]     NULL,                                  /* init module */
[139]     NULL,                                  /* init process */
[140]     NULL,                                  /* init thread */
[141]     NULL,                                  /* exit thread */
[142]     NULL,                                  /* exit process */
[143]     NULL,                                  /* exit master */
[144]     NGX_MODULE_V1_PADDING
[145] };
[146] 
[147] 
[148] static ngx_str_t   ngx_mail_auth_http_method[] = {
[149]     ngx_string("plain"),
[150]     ngx_string("plain"),
[151]     ngx_string("plain"),
[152]     ngx_string("apop"),
[153]     ngx_string("cram-md5"),
[154]     ngx_string("external"),
[155]     ngx_string("none")
[156] };
[157] 
[158] static ngx_str_t   ngx_mail_smtp_errcode = ngx_string("535 5.7.0");
[159] 
[160] 
[161] void
[162] ngx_mail_auth_http_init(ngx_mail_session_t *s)
[163] {
[164]     ngx_int_t                   rc;
[165]     ngx_pool_t                 *pool;
[166]     ngx_mail_auth_http_ctx_t   *ctx;
[167]     ngx_mail_auth_http_conf_t  *ahcf;
[168] 
[169]     s->connection->log->action = "in http auth state";
[170] 
[171]     pool = ngx_create_pool(2048, s->connection->log);
[172]     if (pool == NULL) {
[173]         ngx_mail_session_internal_server_error(s);
[174]         return;
[175]     }
[176] 
[177]     ctx = ngx_pcalloc(pool, sizeof(ngx_mail_auth_http_ctx_t));
[178]     if (ctx == NULL) {
[179]         ngx_destroy_pool(pool);
[180]         ngx_mail_session_internal_server_error(s);
[181]         return;
[182]     }
[183] 
[184]     ctx->pool = pool;
[185] 
[186]     ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);
[187] 
[188]     ctx->request = ngx_mail_auth_http_create_request(s, pool, ahcf);
[189]     if (ctx->request == NULL) {
[190]         ngx_destroy_pool(ctx->pool);
[191]         ngx_mail_session_internal_server_error(s);
[192]         return;
[193]     }
[194] 
[195]     ngx_mail_set_ctx(s, ctx, ngx_mail_auth_http_module);
[196] 
[197]     ctx->peer.sockaddr = ahcf->peer->sockaddr;
[198]     ctx->peer.socklen = ahcf->peer->socklen;
[199]     ctx->peer.name = &ahcf->peer->name;
[200]     ctx->peer.get = ngx_event_get_peer;
[201]     ctx->peer.log = s->connection->log;
[202]     ctx->peer.log_error = NGX_ERROR_ERR;
[203] 
[204]     rc = ngx_event_connect_peer(&ctx->peer);
[205] 
[206]     if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
[207]         if (ctx->peer.connection) {
[208]             ngx_close_connection(ctx->peer.connection);
[209]         }
[210] 
[211]         ngx_destroy_pool(ctx->pool);
[212]         ngx_mail_session_internal_server_error(s);
[213]         return;
[214]     }
[215] 
[216]     ctx->peer.connection->data = s;
[217]     ctx->peer.connection->pool = s->connection->pool;
[218] 
[219]     s->connection->read->handler = ngx_mail_auth_http_block_read;
[220]     ctx->peer.connection->read->handler = ngx_mail_auth_http_read_handler;
[221]     ctx->peer.connection->write->handler = ngx_mail_auth_http_write_handler;
[222] 
[223]     ctx->handler = ngx_mail_auth_http_ignore_status_line;
[224] 
[225]     ngx_add_timer(ctx->peer.connection->read, ahcf->timeout);
[226]     ngx_add_timer(ctx->peer.connection->write, ahcf->timeout);
[227] 
[228]     if (rc == NGX_OK) {
[229]         ngx_mail_auth_http_write_handler(ctx->peer.connection->write);
[230]         return;
[231]     }
[232] }
[233] 
[234] 
[235] static void
[236] ngx_mail_auth_http_write_handler(ngx_event_t *wev)
[237] {
[238]     ssize_t                     n, size;
[239]     ngx_connection_t           *c;
[240]     ngx_mail_session_t         *s;
[241]     ngx_mail_auth_http_ctx_t   *ctx;
[242]     ngx_mail_auth_http_conf_t  *ahcf;
[243] 
[244]     c = wev->data;
[245]     s = c->data;
[246] 
[247]     ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);
[248] 
[249]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0,
[250]                    "mail auth http write handler");
[251] 
[252]     if (wev->timedout) {
[253]         ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
[254]                       "auth http server %V timed out", ctx->peer.name);
[255]         ngx_close_connection(c);
[256]         ngx_destroy_pool(ctx->pool);
[257]         ngx_mail_session_internal_server_error(s);
[258]         return;
[259]     }
[260] 
[261]     size = ctx->request->last - ctx->request->pos;
[262] 
[263]     n = ngx_send(c, ctx->request->pos, size);
[264] 
[265]     if (n == NGX_ERROR) {
[266]         ngx_close_connection(c);
[267]         ngx_destroy_pool(ctx->pool);
[268]         ngx_mail_session_internal_server_error(s);
[269]         return;
[270]     }
[271] 
[272]     if (n > 0) {
[273]         ctx->request->pos += n;
[274] 
[275]         if (n == size) {
[276]             wev->handler = ngx_mail_auth_http_dummy_handler;
[277] 
[278]             if (wev->timer_set) {
[279]                 ngx_del_timer(wev);
[280]             }
[281] 
[282]             if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[283]                 ngx_close_connection(c);
[284]                 ngx_destroy_pool(ctx->pool);
[285]                 ngx_mail_session_internal_server_error(s);
[286]             }
[287] 
[288]             return;
[289]         }
[290]     }
[291] 
[292]     if (!wev->timer_set) {
[293]         ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);
[294]         ngx_add_timer(wev, ahcf->timeout);
[295]     }
[296] }
[297] 
[298] 
[299] static void
[300] ngx_mail_auth_http_read_handler(ngx_event_t *rev)
[301] {
[302]     ssize_t                     n, size;
[303]     ngx_connection_t          *c;
[304]     ngx_mail_session_t        *s;
[305]     ngx_mail_auth_http_ctx_t  *ctx;
[306] 
[307]     c = rev->data;
[308]     s = c->data;
[309] 
[310]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[311]                    "mail auth http read handler");
[312] 
[313]     ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);
[314] 
[315]     if (rev->timedout) {
[316]         ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
[317]                       "auth http server %V timed out", ctx->peer.name);
[318]         ngx_close_connection(c);
[319]         ngx_destroy_pool(ctx->pool);
[320]         ngx_mail_session_internal_server_error(s);
[321]         return;
[322]     }
[323] 
[324]     if (ctx->response == NULL) {
[325]         ctx->response = ngx_create_temp_buf(ctx->pool, 1024);
[326]         if (ctx->response == NULL) {
[327]             ngx_close_connection(c);
[328]             ngx_destroy_pool(ctx->pool);
[329]             ngx_mail_session_internal_server_error(s);
[330]             return;
[331]         }
[332]     }
[333] 
[334]     size = ctx->response->end - ctx->response->last;
[335] 
[336]     n = ngx_recv(c, ctx->response->pos, size);
[337] 
[338]     if (n > 0) {
[339]         ctx->response->last += n;
[340] 
[341]         ctx->handler(s, ctx);
[342]         return;
[343]     }
[344] 
[345]     if (n == NGX_AGAIN) {
[346]         return;
[347]     }
[348] 
[349]     ngx_close_connection(c);
[350]     ngx_destroy_pool(ctx->pool);
[351]     ngx_mail_session_internal_server_error(s);
[352] }
[353] 
[354] 
[355] static void
[356] ngx_mail_auth_http_ignore_status_line(ngx_mail_session_t *s,
[357]     ngx_mail_auth_http_ctx_t *ctx)
[358] {
[359]     u_char  *p, ch;
[360]     enum  {
[361]         sw_start = 0,
[362]         sw_H,
[363]         sw_HT,
[364]         sw_HTT,
[365]         sw_HTTP,
[366]         sw_skip,
[367]         sw_almost_done
[368]     } state;
[369] 
[370]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[371]                    "mail auth http process status line");
[372] 
[373]     state = ctx->state;
[374] 
[375]     for (p = ctx->response->pos; p < ctx->response->last; p++) {
[376]         ch = *p;
[377] 
[378]         switch (state) {
[379] 
[380]         /* "HTTP/" */
[381]         case sw_start:
[382]             if (ch == 'H') {
[383]                 state = sw_H;
[384]                 break;
[385]             }
[386]             goto next;
[387] 
[388]         case sw_H:
[389]             if (ch == 'T') {
[390]                 state = sw_HT;
[391]                 break;
[392]             }
[393]             goto next;
[394] 
[395]         case sw_HT:
[396]             if (ch == 'T') {
[397]                 state = sw_HTT;
[398]                 break;
[399]             }
[400]             goto next;
[401] 
[402]         case sw_HTT:
[403]             if (ch == 'P') {
[404]                 state = sw_HTTP;
[405]                 break;
[406]             }
[407]             goto next;
[408] 
[409]         case sw_HTTP:
[410]             if (ch == '/') {
[411]                 state = sw_skip;
[412]                 break;
[413]             }
[414]             goto next;
[415] 
[416]         /* any text until end of line */
[417]         case sw_skip:
[418]             switch (ch) {
[419]             case CR:
[420]                 state = sw_almost_done;
[421] 
[422]                 break;
[423]             case LF:
[424]                 goto done;
[425]             }
[426]             break;
[427] 
[428]         /* end of status line */
[429]         case sw_almost_done:
[430]             if (ch == LF) {
[431]                 goto done;
[432]             }
[433] 
[434]             ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[435]                           "auth http server %V sent invalid response",
[436]                           ctx->peer.name);
[437]             ngx_close_connection(ctx->peer.connection);
[438]             ngx_destroy_pool(ctx->pool);
[439]             ngx_mail_session_internal_server_error(s);
[440]             return;
[441]         }
[442]     }
[443] 
[444]     ctx->response->pos = p;
[445]     ctx->state = state;
[446] 
[447]     return;
[448] 
[449] next:
[450] 
[451]     p = ctx->response->start - 1;
[452] 
[453] done:
[454] 
[455]     ctx->response->pos = p + 1;
[456]     ctx->state = 0;
[457]     ctx->handler = ngx_mail_auth_http_process_headers;
[458]     ctx->handler(s, ctx);
[459] }
[460] 
[461] 
[462] static void
[463] ngx_mail_auth_http_process_headers(ngx_mail_session_t *s,
[464]     ngx_mail_auth_http_ctx_t *ctx)
[465] {
[466]     u_char      *p;
[467]     time_t       timer;
[468]     size_t       len, size;
[469]     ngx_int_t    rc, port, n;
[470]     ngx_addr_t  *peer;
[471] 
[472]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[473]                    "mail auth http process headers");
[474] 
[475]     for ( ;; ) {
[476]         rc = ngx_mail_auth_http_parse_header_line(s, ctx);
[477] 
[478]         if (rc == NGX_OK) {
[479] 
[480] #if (NGX_DEBUG)
[481]             {
[482]             ngx_str_t  key, value;
[483] 
[484]             key.len = ctx->header_name_end - ctx->header_name_start;
[485]             key.data = ctx->header_name_start;
[486]             value.len = ctx->header_end - ctx->header_start;
[487]             value.data = ctx->header_start;
[488] 
[489]             ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[490]                            "mail auth http header: \"%V: %V\"",
[491]                            &key, &value);
[492]             }
[493] #endif
[494] 
[495]             len = ctx->header_name_end - ctx->header_name_start;
[496] 
[497]             if (len == sizeof("Auth-Status") - 1
[498]                 && ngx_strncasecmp(ctx->header_name_start,
[499]                                    (u_char *) "Auth-Status",
[500]                                    sizeof("Auth-Status") - 1)
[501]                    == 0)
[502]             {
[503]                 len = ctx->header_end - ctx->header_start;
[504] 
[505]                 if (len == 2
[506]                     && ctx->header_start[0] == 'O'
[507]                     && ctx->header_start[1] == 'K')
[508]                 {
[509]                     continue;
[510]                 }
[511] 
[512]                 if (len == 4
[513]                     && ctx->header_start[0] == 'W'
[514]                     && ctx->header_start[1] == 'A'
[515]                     && ctx->header_start[2] == 'I'
[516]                     && ctx->header_start[3] == 'T')
[517]                 {
[518]                     s->auth_wait = 1;
[519]                     continue;
[520]                 }
[521] 
[522]                 ctx->errmsg.len = len;
[523]                 ctx->errmsg.data = ctx->header_start;
[524] 
[525]                 switch (s->protocol) {
[526] 
[527]                 case NGX_MAIL_POP3_PROTOCOL:
[528]                     size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;
[529]                     break;
[530] 
[531]                 case NGX_MAIL_IMAP_PROTOCOL:
[532]                     size = s->tag.len + sizeof("NO ") - 1 + len
[533]                            + sizeof(CRLF) - 1;
[534]                     break;
[535] 
[536]                 default: /* NGX_MAIL_SMTP_PROTOCOL */
[537]                     ctx->err = ctx->errmsg;
[538]                     continue;
[539]                 }
[540] 
[541]                 p = ngx_pnalloc(s->connection->pool, size);
[542]                 if (p == NULL) {
[543]                     ngx_close_connection(ctx->peer.connection);
[544]                     ngx_destroy_pool(ctx->pool);
[545]                     ngx_mail_session_internal_server_error(s);
[546]                     return;
[547]                 }
[548] 
[549]                 ctx->err.data = p;
[550] 
[551]                 switch (s->protocol) {
[552] 
[553]                 case NGX_MAIL_POP3_PROTOCOL:
[554]                     *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R'; *p++ = ' ';
[555]                     break;
[556] 
[557]                 case NGX_MAIL_IMAP_PROTOCOL:
[558]                     p = ngx_cpymem(p, s->tag.data, s->tag.len);
[559]                     *p++ = 'N'; *p++ = 'O'; *p++ = ' ';
[560]                     break;
[561] 
[562]                 default: /* NGX_MAIL_SMTP_PROTOCOL */
[563]                     break;
[564]                 }
[565] 
[566]                 p = ngx_cpymem(p, ctx->header_start, len);
[567]                 *p++ = CR; *p++ = LF;
[568] 
[569]                 ctx->err.len = p - ctx->err.data;
[570] 
[571]                 continue;
[572]             }
[573] 
[574]             if (len == sizeof("Auth-Server") - 1
[575]                 && ngx_strncasecmp(ctx->header_name_start,
[576]                                    (u_char *) "Auth-Server",
[577]                                    sizeof("Auth-Server") - 1)
[578]                     == 0)
[579]             {
[580]                 ctx->addr.len = ctx->header_end - ctx->header_start;
[581]                 ctx->addr.data = ctx->header_start;
[582] 
[583]                 continue;
[584]             }
[585] 
[586]             if (len == sizeof("Auth-Port") - 1
[587]                 && ngx_strncasecmp(ctx->header_name_start,
[588]                                    (u_char *) "Auth-Port",
[589]                                    sizeof("Auth-Port") - 1)
[590]                    == 0)
[591]             {
[592]                 ctx->port.len = ctx->header_end - ctx->header_start;
[593]                 ctx->port.data = ctx->header_start;
[594] 
[595]                 continue;
[596]             }
[597] 
[598]             if (len == sizeof("Auth-User") - 1
[599]                 && ngx_strncasecmp(ctx->header_name_start,
[600]                                    (u_char *) "Auth-User",
[601]                                    sizeof("Auth-User") - 1)
[602]                    == 0)
[603]             {
[604]                 s->login.len = ctx->header_end - ctx->header_start;
[605] 
[606]                 s->login.data = ngx_pnalloc(s->connection->pool, s->login.len);
[607]                 if (s->login.data == NULL) {
[608]                     ngx_close_connection(ctx->peer.connection);
[609]                     ngx_destroy_pool(ctx->pool);
[610]                     ngx_mail_session_internal_server_error(s);
[611]                     return;
[612]                 }
[613] 
[614]                 ngx_memcpy(s->login.data, ctx->header_start, s->login.len);
[615] 
[616]                 continue;
[617]             }
[618] 
[619]             if (len == sizeof("Auth-Pass") - 1
[620]                 && ngx_strncasecmp(ctx->header_name_start,
[621]                                    (u_char *) "Auth-Pass",
[622]                                    sizeof("Auth-Pass") - 1)
[623]                    == 0)
[624]             {
[625]                 s->passwd.len = ctx->header_end - ctx->header_start;
[626] 
[627]                 s->passwd.data = ngx_pnalloc(s->connection->pool,
[628]                                              s->passwd.len);
[629]                 if (s->passwd.data == NULL) {
[630]                     ngx_close_connection(ctx->peer.connection);
[631]                     ngx_destroy_pool(ctx->pool);
[632]                     ngx_mail_session_internal_server_error(s);
[633]                     return;
[634]                 }
[635] 
[636]                 ngx_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);
[637] 
[638]                 continue;
[639]             }
[640] 
[641]             if (len == sizeof("Auth-Wait") - 1
[642]                 && ngx_strncasecmp(ctx->header_name_start,
[643]                                    (u_char *) "Auth-Wait",
[644]                                    sizeof("Auth-Wait") - 1)
[645]                    == 0)
[646]             {
[647]                 n = ngx_atoi(ctx->header_start,
[648]                              ctx->header_end - ctx->header_start);
[649] 
[650]                 if (n != NGX_ERROR) {
[651]                     ctx->sleep = n;
[652]                 }
[653] 
[654]                 continue;
[655]             }
[656] 
[657]             if (len == sizeof("Auth-Error-Code") - 1
[658]                 && ngx_strncasecmp(ctx->header_name_start,
[659]                                    (u_char *) "Auth-Error-Code",
[660]                                    sizeof("Auth-Error-Code") - 1)
[661]                    == 0)
[662]             {
[663]                 ctx->errcode.len = ctx->header_end - ctx->header_start;
[664] 
[665]                 ctx->errcode.data = ngx_pnalloc(s->connection->pool,
[666]                                                 ctx->errcode.len);
[667]                 if (ctx->errcode.data == NULL) {
[668]                     ngx_close_connection(ctx->peer.connection);
[669]                     ngx_destroy_pool(ctx->pool);
[670]                     ngx_mail_session_internal_server_error(s);
[671]                     return;
[672]                 }
[673] 
[674]                 ngx_memcpy(ctx->errcode.data, ctx->header_start,
[675]                            ctx->errcode.len);
[676] 
[677]                 continue;
[678]             }
[679] 
[680]             /* ignore other headers */
[681] 
[682]             continue;
[683]         }
[684] 
[685]         if (rc == NGX_DONE) {
[686]             ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[687]                            "mail auth http header done");
[688] 
[689]             ngx_close_connection(ctx->peer.connection);
[690] 
[691]             if (ctx->err.len) {
[692] 
[693]                 ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
[694]                               "client login failed: \"%V\"", &ctx->errmsg);
[695] 
[696]                 if (s->protocol == NGX_MAIL_SMTP_PROTOCOL) {
[697] 
[698]                     if (ctx->errcode.len == 0) {
[699]                         ctx->errcode = ngx_mail_smtp_errcode;
[700]                     }
[701] 
[702]                     ctx->err.len = ctx->errcode.len + ctx->errmsg.len
[703]                                    + sizeof(" " CRLF) - 1;
[704] 
[705]                     p = ngx_pnalloc(s->connection->pool, ctx->err.len);
[706]                     if (p == NULL) {
[707]                         ngx_destroy_pool(ctx->pool);
[708]                         ngx_mail_session_internal_server_error(s);
[709]                         return;
[710]                     }
[711] 
[712]                     ctx->err.data = p;
[713] 
[714]                     p = ngx_cpymem(p, ctx->errcode.data, ctx->errcode.len);
[715]                     *p++ = ' ';
[716]                     p = ngx_cpymem(p, ctx->errmsg.data, ctx->errmsg.len);
[717]                     *p++ = CR; *p = LF;
[718]                 }
[719] 
[720]                 s->out = ctx->err;
[721]                 timer = ctx->sleep;
[722] 
[723]                 ngx_destroy_pool(ctx->pool);
[724] 
[725]                 if (timer == 0) {
[726]                     s->quit = 1;
[727]                     ngx_mail_send(s->connection->write);
[728]                     return;
[729]                 }
[730] 
[731]                 ngx_add_timer(s->connection->read, (ngx_msec_t) (timer * 1000));
[732] 
[733]                 s->connection->read->handler = ngx_mail_auth_sleep_handler;
[734] 
[735]                 return;
[736]             }
[737] 
[738]             if (s->auth_wait) {
[739]                 timer = ctx->sleep;
[740] 
[741]                 ngx_destroy_pool(ctx->pool);
[742] 
[743]                 if (timer == 0) {
[744]                     ngx_mail_auth_http_init(s);
[745]                     return;
[746]                 }
[747] 
[748]                 ngx_add_timer(s->connection->read, (ngx_msec_t) (timer * 1000));
[749] 
[750]                 s->connection->read->handler = ngx_mail_auth_sleep_handler;
[751] 
[752]                 return;
[753]             }
[754] 
[755]             if (ctx->addr.len == 0 || ctx->port.len == 0) {
[756]                 ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[757]                               "auth http server %V did not send server or port",
[758]                               ctx->peer.name);
[759]                 ngx_destroy_pool(ctx->pool);
[760]                 ngx_mail_session_internal_server_error(s);
[761]                 return;
[762]             }
[763] 
[764]             if (s->passwd.data == NULL
[765]                 && s->protocol != NGX_MAIL_SMTP_PROTOCOL)
[766]             {
[767]                 ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[768]                               "auth http server %V did not send password",
[769]                               ctx->peer.name);
[770]                 ngx_destroy_pool(ctx->pool);
[771]                 ngx_mail_session_internal_server_error(s);
[772]                 return;
[773]             }
[774] 
[775]             peer = ngx_pcalloc(s->connection->pool, sizeof(ngx_addr_t));
[776]             if (peer == NULL) {
[777]                 ngx_destroy_pool(ctx->pool);
[778]                 ngx_mail_session_internal_server_error(s);
[779]                 return;
[780]             }
[781] 
[782]             rc = ngx_parse_addr(s->connection->pool, peer,
[783]                                 ctx->addr.data, ctx->addr.len);
[784] 
[785]             switch (rc) {
[786]             case NGX_OK:
[787]                 break;
[788] 
[789]             case NGX_DECLINED:
[790]                 ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[791]                               "auth http server %V sent invalid server "
[792]                               "address:\"%V\"",
[793]                               ctx->peer.name, &ctx->addr);
[794]                 /* fall through */
[795] 
[796]             default:
[797]                 ngx_destroy_pool(ctx->pool);
[798]                 ngx_mail_session_internal_server_error(s);
[799]                 return;
[800]             }
[801] 
[802]             port = ngx_atoi(ctx->port.data, ctx->port.len);
[803]             if (port == NGX_ERROR || port < 1 || port > 65535) {
[804]                 ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[805]                               "auth http server %V sent invalid server "
[806]                               "port:\"%V\"",
[807]                               ctx->peer.name, &ctx->port);
[808]                 ngx_destroy_pool(ctx->pool);
[809]                 ngx_mail_session_internal_server_error(s);
[810]                 return;
[811]             }
[812] 
[813]             ngx_inet_set_port(peer->sockaddr, (in_port_t) port);
[814] 
[815]             len = ctx->addr.len + 1 + ctx->port.len;
[816] 
[817]             peer->name.len = len;
[818] 
[819]             peer->name.data = ngx_pnalloc(s->connection->pool, len);
[820]             if (peer->name.data == NULL) {
[821]                 ngx_destroy_pool(ctx->pool);
[822]                 ngx_mail_session_internal_server_error(s);
[823]                 return;
[824]             }
[825] 
[826]             len = ctx->addr.len;
[827] 
[828]             ngx_memcpy(peer->name.data, ctx->addr.data, len);
[829] 
[830]             peer->name.data[len++] = ':';
[831] 
[832]             ngx_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);
[833] 
[834]             ngx_destroy_pool(ctx->pool);
[835]             ngx_mail_proxy_init(s, peer);
[836] 
[837]             return;
[838]         }
[839] 
[840]         if (rc == NGX_AGAIN ) {
[841]             return;
[842]         }
[843] 
[844]         /* rc == NGX_ERROR */
[845] 
[846]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[847]                       "auth http server %V sent invalid header in response",
[848]                       ctx->peer.name);
[849]         ngx_close_connection(ctx->peer.connection);
[850]         ngx_destroy_pool(ctx->pool);
[851]         ngx_mail_session_internal_server_error(s);
[852] 
[853]         return;
[854]     }
[855] }
[856] 
[857] 
[858] static void
[859] ngx_mail_auth_sleep_handler(ngx_event_t *rev)
[860] {
[861]     ngx_connection_t          *c;
[862]     ngx_mail_session_t        *s;
[863]     ngx_mail_core_srv_conf_t  *cscf;
[864] 
[865]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail auth sleep handler");
[866] 
[867]     c = rev->data;
[868]     s = c->data;
[869] 
[870]     if (rev->timedout) {
[871] 
[872]         rev->timedout = 0;
[873] 
[874]         if (s->auth_wait) {
[875]             s->auth_wait = 0;
[876]             ngx_mail_auth_http_init(s);
[877]             return;
[878]         }
[879] 
[880]         cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[881] 
[882]         rev->handler = cscf->protocol->auth_state;
[883] 
[884]         s->mail_state = 0;
[885]         s->auth_method = NGX_MAIL_AUTH_PLAIN;
[886] 
[887]         c->log->action = "in auth state";
[888] 
[889]         ngx_mail_send(c->write);
[890] 
[891]         if (c->destroyed) {
[892]             return;
[893]         }
[894] 
[895]         ngx_add_timer(rev, cscf->timeout);
[896] 
[897]         if (rev->ready) {
[898]             rev->handler(rev);
[899]             return;
[900]         }
[901] 
[902]         if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[903]             ngx_mail_close_connection(c);
[904]         }
[905] 
[906]         return;
[907]     }
[908] 
[909]     if (rev->active) {
[910]         if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[911]             ngx_mail_close_connection(c);
[912]         }
[913]     }
[914] }
[915] 
[916] 
[917] static ngx_int_t
[918] ngx_mail_auth_http_parse_header_line(ngx_mail_session_t *s,
[919]     ngx_mail_auth_http_ctx_t *ctx)
[920] {
[921]     u_char      c, ch, *p;
[922]     enum {
[923]         sw_start = 0,
[924]         sw_name,
[925]         sw_space_before_value,
[926]         sw_value,
[927]         sw_space_after_value,
[928]         sw_almost_done,
[929]         sw_header_almost_done
[930]     } state;
[931] 
[932]     state = ctx->state;
[933] 
[934]     for (p = ctx->response->pos; p < ctx->response->last; p++) {
[935]         ch = *p;
[936] 
[937]         switch (state) {
[938] 
[939]         /* first char */
[940]         case sw_start:
[941] 
[942]             switch (ch) {
[943]             case CR:
[944]                 ctx->header_end = p;
[945]                 state = sw_header_almost_done;
[946]                 break;
[947]             case LF:
[948]                 ctx->header_end = p;
[949]                 goto header_done;
[950]             default:
[951]                 state = sw_name;
[952]                 ctx->header_name_start = p;
[953] 
[954]                 c = (u_char) (ch | 0x20);
[955]                 if (c >= 'a' && c <= 'z') {
[956]                     break;
[957]                 }
[958] 
[959]                 if (ch >= '0' && ch <= '9') {
[960]                     break;
[961]                 }
[962] 
[963]                 return NGX_ERROR;
[964]             }
[965]             break;
[966] 
[967]         /* header name */
[968]         case sw_name:
[969]             c = (u_char) (ch | 0x20);
[970]             if (c >= 'a' && c <= 'z') {
[971]                 break;
[972]             }
[973] 
[974]             if (ch == ':') {
[975]                 ctx->header_name_end = p;
[976]                 state = sw_space_before_value;
[977]                 break;
[978]             }
[979] 
[980]             if (ch == '-') {
[981]                 break;
[982]             }
[983] 
[984]             if (ch >= '0' && ch <= '9') {
[985]                 break;
[986]             }
[987] 
[988]             if (ch == CR) {
[989]                 ctx->header_name_end = p;
[990]                 ctx->header_start = p;
[991]                 ctx->header_end = p;
[992]                 state = sw_almost_done;
[993]                 break;
[994]             }
[995] 
[996]             if (ch == LF) {
[997]                 ctx->header_name_end = p;
[998]                 ctx->header_start = p;
[999]                 ctx->header_end = p;
[1000]                 goto done;
[1001]             }
[1002] 
[1003]             return NGX_ERROR;
[1004] 
[1005]         /* space* before header value */
[1006]         case sw_space_before_value:
[1007]             switch (ch) {
[1008]             case ' ':
[1009]                 break;
[1010]             case CR:
[1011]                 ctx->header_start = p;
[1012]                 ctx->header_end = p;
[1013]                 state = sw_almost_done;
[1014]                 break;
[1015]             case LF:
[1016]                 ctx->header_start = p;
[1017]                 ctx->header_end = p;
[1018]                 goto done;
[1019]             default:
[1020]                 ctx->header_start = p;
[1021]                 state = sw_value;
[1022]                 break;
[1023]             }
[1024]             break;
[1025] 
[1026]         /* header value */
[1027]         case sw_value:
[1028]             switch (ch) {
[1029]             case ' ':
[1030]                 ctx->header_end = p;
[1031]                 state = sw_space_after_value;
[1032]                 break;
[1033]             case CR:
[1034]                 ctx->header_end = p;
[1035]                 state = sw_almost_done;
[1036]                 break;
[1037]             case LF:
[1038]                 ctx->header_end = p;
[1039]                 goto done;
[1040]             }
[1041]             break;
[1042] 
[1043]         /* space* before end of header line */
[1044]         case sw_space_after_value:
[1045]             switch (ch) {
[1046]             case ' ':
[1047]                 break;
[1048]             case CR:
[1049]                 state = sw_almost_done;
[1050]                 break;
[1051]             case LF:
[1052]                 goto done;
[1053]             default:
[1054]                 state = sw_value;
[1055]                 break;
[1056]             }
[1057]             break;
[1058] 
[1059]         /* end of header line */
[1060]         case sw_almost_done:
[1061]             switch (ch) {
[1062]             case LF:
[1063]                 goto done;
[1064]             default:
[1065]                 return NGX_ERROR;
[1066]             }
[1067] 
[1068]         /* end of header */
[1069]         case sw_header_almost_done:
[1070]             switch (ch) {
[1071]             case LF:
[1072]                 goto header_done;
[1073]             default:
[1074]                 return NGX_ERROR;
[1075]             }
[1076]         }
[1077]     }
[1078] 
[1079]     ctx->response->pos = p;
[1080]     ctx->state = state;
[1081] 
[1082]     return NGX_AGAIN;
[1083] 
[1084] done:
[1085] 
[1086]     ctx->response->pos = p + 1;
[1087]     ctx->state = sw_start;
[1088] 
[1089]     return NGX_OK;
[1090] 
[1091] header_done:
[1092] 
[1093]     ctx->response->pos = p + 1;
[1094]     ctx->state = sw_start;
[1095] 
[1096]     return NGX_DONE;
[1097] }
[1098] 
[1099] 
[1100] static void
[1101] ngx_mail_auth_http_block_read(ngx_event_t *rev)
[1102] {
[1103]     ngx_connection_t          *c;
[1104]     ngx_mail_session_t        *s;
[1105]     ngx_mail_auth_http_ctx_t  *ctx;
[1106] 
[1107]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
[1108]                    "mail auth http block read");
[1109] 
[1110]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[1111]         c = rev->data;
[1112]         s = c->data;
[1113] 
[1114]         ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);
[1115] 
[1116]         ngx_close_connection(ctx->peer.connection);
[1117]         ngx_destroy_pool(ctx->pool);
[1118]         ngx_mail_session_internal_server_error(s);
[1119]     }
[1120] }
[1121] 
[1122] 
[1123] static void
[1124] ngx_mail_auth_http_dummy_handler(ngx_event_t *ev)
[1125] {
[1126]     ngx_log_debug0(NGX_LOG_DEBUG_MAIL, ev->log, 0,
[1127]                    "mail auth http dummy handler");
[1128] }
[1129] 
[1130] 
[1131] static ngx_buf_t *
[1132] ngx_mail_auth_http_create_request(ngx_mail_session_t *s, ngx_pool_t *pool,
[1133]     ngx_mail_auth_http_conf_t *ahcf)
[1134] {
[1135]     size_t                     len;
[1136]     ngx_buf_t                 *b;
[1137]     ngx_str_t                  login, passwd;
[1138]     ngx_connection_t          *c;
[1139] #if (NGX_MAIL_SSL)
[1140]     ngx_str_t                  protocol, cipher, verify, subject, issuer,
[1141]                                serial, fingerprint, raw_cert, cert;
[1142]     ngx_mail_ssl_conf_t       *sslcf;
[1143] #endif
[1144]     ngx_mail_core_srv_conf_t  *cscf;
[1145] 
[1146]     if (ngx_mail_auth_http_escape(pool, &s->login, &login) != NGX_OK) {
[1147]         return NULL;
[1148]     }
[1149] 
[1150]     if (ngx_mail_auth_http_escape(pool, &s->passwd, &passwd) != NGX_OK) {
[1151]         return NULL;
[1152]     }
[1153] 
[1154]     c = s->connection;
[1155] 
[1156] #if (NGX_MAIL_SSL)
[1157] 
[1158]     if (c->ssl) {
[1159] 
[1160]         if (ngx_ssl_get_protocol(c, pool, &protocol) != NGX_OK) {
[1161]             return NULL;
[1162]         }
[1163] 
[1164]         protocol.len = ngx_strlen(protocol.data);
[1165] 
[1166]         if (ngx_ssl_get_cipher_name(c, pool, &cipher) != NGX_OK) {
[1167]             return NULL;
[1168]         }
[1169] 
[1170]         cipher.len = ngx_strlen(cipher.data);
[1171] 
[1172]     } else {
[1173]         ngx_str_null(&protocol);
[1174]         ngx_str_null(&cipher);
[1175]     }
[1176] 
[1177]     sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
[1178] 
[1179]     if (c->ssl && sslcf->verify) {
[1180] 
[1181]         /* certificate details */
[1182] 
[1183]         if (ngx_ssl_get_client_verify(c, pool, &verify) != NGX_OK) {
[1184]             return NULL;
[1185]         }
[1186] 
[1187]         if (ngx_ssl_get_subject_dn(c, pool, &subject) != NGX_OK) {
[1188]             return NULL;
[1189]         }
[1190] 
[1191]         if (ngx_ssl_get_issuer_dn(c, pool, &issuer) != NGX_OK) {
[1192]             return NULL;
[1193]         }
[1194] 
[1195]         if (ngx_ssl_get_serial_number(c, pool, &serial) != NGX_OK) {
[1196]             return NULL;
[1197]         }
[1198] 
[1199]         if (ngx_ssl_get_fingerprint(c, pool, &fingerprint) != NGX_OK) {
[1200]             return NULL;
[1201]         }
[1202] 
[1203]         if (ahcf->pass_client_cert) {
[1204] 
[1205]             /* certificate itself, if configured */
[1206] 
[1207]             if (ngx_ssl_get_raw_certificate(c, pool, &raw_cert) != NGX_OK) {
[1208]                 return NULL;
[1209]             }
[1210] 
[1211]             if (ngx_mail_auth_http_escape(pool, &raw_cert, &cert) != NGX_OK) {
[1212]                 return NULL;
[1213]             }
[1214] 
[1215]         } else {
[1216]             ngx_str_null(&cert);
[1217]         }
[1218] 
[1219]     } else {
[1220]         ngx_str_null(&verify);
[1221]         ngx_str_null(&subject);
[1222]         ngx_str_null(&issuer);
[1223]         ngx_str_null(&serial);
[1224]         ngx_str_null(&fingerprint);
[1225]         ngx_str_null(&cert);
[1226]     }
[1227] 
[1228] #endif
[1229] 
[1230]     cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
[1231] 
[1232]     len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
[1233]           + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
[1234]           + sizeof("Auth-Method: ") - 1
[1235]                 + ngx_mail_auth_http_method[s->auth_method].len
[1236]                 + sizeof(CRLF) - 1
[1237]           + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
[1238]           + sizeof("Auth-Pass: ") - 1 + passwd.len + sizeof(CRLF) - 1
[1239]           + sizeof("Auth-Salt: ") - 1 + s->salt.len
[1240]           + sizeof("Auth-Protocol: ") - 1 + cscf->protocol->name.len
[1241]                 + sizeof(CRLF) - 1
[1242]           + sizeof("Auth-Login-Attempt: ") - 1 + NGX_INT_T_LEN
[1243]                 + sizeof(CRLF) - 1
[1244]           + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
[1245]                 + sizeof(CRLF) - 1
[1246]           + sizeof("Client-Host: ") - 1 + s->host.len + sizeof(CRLF) - 1
[1247]           + ahcf->header.len
[1248]           + sizeof(CRLF) - 1;
[1249] 
[1250]     if (c->proxy_protocol) {
[1251]         len += sizeof("Proxy-Protocol-Addr: ") - 1
[1252]                      + c->proxy_protocol->src_addr.len + sizeof(CRLF) - 1
[1253]                + sizeof("Proxy-Protocol-Port: ") - 1
[1254]                      + sizeof("65535") - 1 + sizeof(CRLF) - 1
[1255]                + sizeof("Proxy-Protocol-Server-Addr: ") - 1
[1256]                      + c->proxy_protocol->dst_addr.len + sizeof(CRLF) - 1
[1257]                + sizeof("Proxy-Protocol-Server-Port: ") - 1
[1258]                      + sizeof("65535") - 1 + sizeof(CRLF) - 1;
[1259]     }
[1260] 
[1261]     if (s->auth_method == NGX_MAIL_AUTH_NONE) {
[1262]         len += sizeof("Auth-SMTP-Helo: ") - 1 + s->smtp_helo.len
[1263]                      + sizeof(CRLF) - 1
[1264]                + sizeof("Auth-SMTP-From: ") - 1 + s->smtp_from.len
[1265]                      + sizeof(CRLF) - 1
[1266]                + sizeof("Auth-SMTP-To: ") - 1 + s->smtp_to.len
[1267]                      + sizeof(CRLF) - 1;
[1268]     }
[1269] 
[1270] #if (NGX_MAIL_SSL)
[1271] 
[1272]     if (c->ssl) {
[1273]         len += sizeof("Auth-SSL: on" CRLF) - 1
[1274]                + sizeof("Auth-SSL-Protocol: ") - 1 + protocol.len
[1275]                      + sizeof(CRLF) - 1
[1276]                + sizeof("Auth-SSL-Cipher: ") - 1 + cipher.len
[1277]                      + sizeof(CRLF) - 1
[1278]                + sizeof("Auth-SSL-Verify: ") - 1 + verify.len
[1279]                      + sizeof(CRLF) - 1
[1280]                + sizeof("Auth-SSL-Subject: ") - 1 + subject.len
[1281]                      + sizeof(CRLF) - 1
[1282]                + sizeof("Auth-SSL-Issuer: ") - 1 + issuer.len
[1283]                      + sizeof(CRLF) - 1
[1284]                + sizeof("Auth-SSL-Serial: ") - 1 + serial.len
[1285]                      + sizeof(CRLF) - 1
[1286]                + sizeof("Auth-SSL-Fingerprint: ") - 1 + fingerprint.len
[1287]                      + sizeof(CRLF) - 1
[1288]                + sizeof("Auth-SSL-Cert: ") - 1 + cert.len
[1289]                      + sizeof(CRLF) - 1;
[1290]     }
[1291] 
[1292] #endif
[1293] 
[1294]     b = ngx_create_temp_buf(pool, len);
[1295]     if (b == NULL) {
[1296]         return NULL;
[1297]     }
[1298] 
[1299]     b->last = ngx_cpymem(b->last, "GET ", sizeof("GET ") - 1);
[1300]     b->last = ngx_copy(b->last, ahcf->uri.data, ahcf->uri.len);
[1301]     b->last = ngx_cpymem(b->last, " HTTP/1.0" CRLF,
[1302]                          sizeof(" HTTP/1.0" CRLF) - 1);
[1303] 
[1304]     b->last = ngx_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
[1305]     b->last = ngx_copy(b->last, ahcf->host_header.data,
[1306]                          ahcf->host_header.len);
[1307]     *b->last++ = CR; *b->last++ = LF;
[1308] 
[1309]     b->last = ngx_cpymem(b->last, "Auth-Method: ",
[1310]                          sizeof("Auth-Method: ") - 1);
[1311]     b->last = ngx_cpymem(b->last,
[1312]                          ngx_mail_auth_http_method[s->auth_method].data,
[1313]                          ngx_mail_auth_http_method[s->auth_method].len);
[1314]     *b->last++ = CR; *b->last++ = LF;
[1315] 
[1316]     b->last = ngx_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
[1317]     b->last = ngx_copy(b->last, login.data, login.len);
[1318]     *b->last++ = CR; *b->last++ = LF;
[1319] 
[1320]     b->last = ngx_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
[1321]     b->last = ngx_copy(b->last, passwd.data, passwd.len);
[1322]     *b->last++ = CR; *b->last++ = LF;
[1323] 
[1324]     if (s->auth_method != NGX_MAIL_AUTH_PLAIN && s->salt.len) {
[1325]         b->last = ngx_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
[1326]         b->last = ngx_copy(b->last, s->salt.data, s->salt.len);
[1327] 
[1328]         s->passwd.data = NULL;
[1329]     }
[1330] 
[1331]     b->last = ngx_cpymem(b->last, "Auth-Protocol: ",
[1332]                          sizeof("Auth-Protocol: ") - 1);
[1333]     b->last = ngx_cpymem(b->last, cscf->protocol->name.data,
[1334]                          cscf->protocol->name.len);
[1335]     *b->last++ = CR; *b->last++ = LF;
[1336] 
[1337]     b->last = ngx_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
[1338]                           s->login_attempt);
[1339] 
[1340]     b->last = ngx_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
[1341]     b->last = ngx_copy(b->last, s->connection->addr_text.data,
[1342]                        s->connection->addr_text.len);
[1343]     *b->last++ = CR; *b->last++ = LF;
[1344] 
[1345]     if (s->host.len) {
[1346]         b->last = ngx_cpymem(b->last, "Client-Host: ",
[1347]                              sizeof("Client-Host: ") - 1);
[1348]         b->last = ngx_copy(b->last, s->host.data, s->host.len);
[1349]         *b->last++ = CR; *b->last++ = LF;
[1350]     }
[1351] 
[1352]     if (c->proxy_protocol) {
[1353]         b->last = ngx_cpymem(b->last, "Proxy-Protocol-Addr: ",
[1354]                              sizeof("Proxy-Protocol-Addr: ") - 1);
[1355]         b->last = ngx_copy(b->last, c->proxy_protocol->src_addr.data,
[1356]                            c->proxy_protocol->src_addr.len);
[1357]         *b->last++ = CR; *b->last++ = LF;
[1358] 
[1359]         b->last = ngx_sprintf(b->last, "Proxy-Protocol-Port: %d" CRLF,
[1360]                               c->proxy_protocol->src_port);
[1361] 
[1362]         b->last = ngx_cpymem(b->last, "Proxy-Protocol-Server-Addr: ",
[1363]                              sizeof("Proxy-Protocol-Server-Addr: ") - 1);
[1364]         b->last = ngx_copy(b->last, c->proxy_protocol->dst_addr.data,
[1365]                            c->proxy_protocol->dst_addr.len);
[1366]         *b->last++ = CR; *b->last++ = LF;
[1367] 
[1368]         b->last = ngx_sprintf(b->last, "Proxy-Protocol-Server-Port: %d" CRLF,
[1369]                               c->proxy_protocol->dst_port);
[1370]     }
[1371] 
[1372]     if (s->auth_method == NGX_MAIL_AUTH_NONE) {
[1373] 
[1374]         /* HELO, MAIL FROM, and RCPT TO can't contain CRLF, no need to escape */
[1375] 
[1376]         b->last = ngx_cpymem(b->last, "Auth-SMTP-Helo: ",
[1377]                              sizeof("Auth-SMTP-Helo: ") - 1);
[1378]         b->last = ngx_copy(b->last, s->smtp_helo.data, s->smtp_helo.len);
[1379]         *b->last++ = CR; *b->last++ = LF;
[1380] 
[1381]         b->last = ngx_cpymem(b->last, "Auth-SMTP-From: ",
[1382]                              sizeof("Auth-SMTP-From: ") - 1);
[1383]         b->last = ngx_copy(b->last, s->smtp_from.data, s->smtp_from.len);
[1384]         *b->last++ = CR; *b->last++ = LF;
[1385] 
[1386]         b->last = ngx_cpymem(b->last, "Auth-SMTP-To: ",
[1387]                              sizeof("Auth-SMTP-To: ") - 1);
[1388]         b->last = ngx_copy(b->last, s->smtp_to.data, s->smtp_to.len);
[1389]         *b->last++ = CR; *b->last++ = LF;
[1390] 
[1391]     }
[1392] 
[1393] #if (NGX_MAIL_SSL)
[1394] 
[1395]     if (c->ssl) {
[1396]         b->last = ngx_cpymem(b->last, "Auth-SSL: on" CRLF,
[1397]                              sizeof("Auth-SSL: on" CRLF) - 1);
[1398] 
[1399]         if (protocol.len) {
[1400]             b->last = ngx_cpymem(b->last, "Auth-SSL-Protocol: ",
[1401]                                  sizeof("Auth-SSL-Protocol: ") - 1);
[1402]             b->last = ngx_copy(b->last, protocol.data, protocol.len);
[1403]             *b->last++ = CR; *b->last++ = LF;
[1404]         }
[1405] 
[1406]         if (cipher.len) {
[1407]             b->last = ngx_cpymem(b->last, "Auth-SSL-Cipher: ",
[1408]                                  sizeof("Auth-SSL-Cipher: ") - 1);
[1409]             b->last = ngx_copy(b->last, cipher.data, cipher.len);
[1410]             *b->last++ = CR; *b->last++ = LF;
[1411]         }
[1412] 
[1413]         if (verify.len) {
[1414]             b->last = ngx_cpymem(b->last, "Auth-SSL-Verify: ",
[1415]                                  sizeof("Auth-SSL-Verify: ") - 1);
[1416]             b->last = ngx_copy(b->last, verify.data, verify.len);
[1417]             *b->last++ = CR; *b->last++ = LF;
[1418]         }
[1419] 
[1420]         if (subject.len) {
[1421]             b->last = ngx_cpymem(b->last, "Auth-SSL-Subject: ",
[1422]                                  sizeof("Auth-SSL-Subject: ") - 1);
[1423]             b->last = ngx_copy(b->last, subject.data, subject.len);
[1424]             *b->last++ = CR; *b->last++ = LF;
[1425]         }
[1426] 
[1427]         if (issuer.len) {
[1428]             b->last = ngx_cpymem(b->last, "Auth-SSL-Issuer: ",
[1429]                                  sizeof("Auth-SSL-Issuer: ") - 1);
[1430]             b->last = ngx_copy(b->last, issuer.data, issuer.len);
[1431]             *b->last++ = CR; *b->last++ = LF;
[1432]         }
[1433] 
[1434]         if (serial.len) {
[1435]             b->last = ngx_cpymem(b->last, "Auth-SSL-Serial: ",
[1436]                                  sizeof("Auth-SSL-Serial: ") - 1);
[1437]             b->last = ngx_copy(b->last, serial.data, serial.len);
[1438]             *b->last++ = CR; *b->last++ = LF;
[1439]         }
[1440] 
[1441]         if (fingerprint.len) {
[1442]             b->last = ngx_cpymem(b->last, "Auth-SSL-Fingerprint: ",
[1443]                                  sizeof("Auth-SSL-Fingerprint: ") - 1);
[1444]             b->last = ngx_copy(b->last, fingerprint.data, fingerprint.len);
[1445]             *b->last++ = CR; *b->last++ = LF;
[1446]         }
[1447] 
[1448]         if (cert.len) {
[1449]             b->last = ngx_cpymem(b->last, "Auth-SSL-Cert: ",
[1450]                                  sizeof("Auth-SSL-Cert: ") - 1);
[1451]             b->last = ngx_copy(b->last, cert.data, cert.len);
[1452]             *b->last++ = CR; *b->last++ = LF;
[1453]         }
[1454]     }
[1455] 
[1456] #endif
[1457] 
[1458]     if (ahcf->header.len) {
[1459]         b->last = ngx_copy(b->last, ahcf->header.data, ahcf->header.len);
[1460]     }
[1461] 
[1462]     /* add "\r\n" at the header end */
[1463]     *b->last++ = CR; *b->last++ = LF;
[1464] 
[1465] #if (NGX_DEBUG_MAIL_PASSWD)
[1466]     ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
[1467]                    "mail auth http header:%N\"%*s\"",
[1468]                    (size_t) (b->last - b->pos), b->pos);
[1469] #endif
[1470] 
[1471]     return b;
[1472] }
[1473] 
[1474] 
[1475] static ngx_int_t
[1476] ngx_mail_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text, ngx_str_t *escaped)
[1477] {
[1478]     u_char     *p;
[1479]     uintptr_t   n;
[1480] 
[1481]     n = ngx_escape_uri(NULL, text->data, text->len, NGX_ESCAPE_MAIL_AUTH);
[1482] 
[1483]     if (n == 0) {
[1484]         *escaped = *text;
[1485]         return NGX_OK;
[1486]     }
[1487] 
[1488]     escaped->len = text->len + n * 2;
[1489] 
[1490]     p = ngx_pnalloc(pool, escaped->len);
[1491]     if (p == NULL) {
[1492]         return NGX_ERROR;
[1493]     }
[1494] 
[1495]     (void) ngx_escape_uri(p, text->data, text->len, NGX_ESCAPE_MAIL_AUTH);
[1496] 
[1497]     escaped->data = p;
[1498] 
[1499]     return NGX_OK;
[1500] }
[1501] 
[1502] 
[1503] static void *
[1504] ngx_mail_auth_http_create_conf(ngx_conf_t *cf)
[1505] {
[1506]     ngx_mail_auth_http_conf_t  *ahcf;
[1507] 
[1508]     ahcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_auth_http_conf_t));
[1509]     if (ahcf == NULL) {
[1510]         return NULL;
[1511]     }
[1512] 
[1513]     ahcf->timeout = NGX_CONF_UNSET_MSEC;
[1514]     ahcf->pass_client_cert = NGX_CONF_UNSET;
[1515] 
[1516]     ahcf->file = cf->conf_file->file.name.data;
[1517]     ahcf->line = cf->conf_file->line;
[1518] 
[1519]     return ahcf;
[1520] }
[1521] 
[1522] 
[1523] static char *
[1524] ngx_mail_auth_http_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[1525] {
[1526]     ngx_mail_auth_http_conf_t *prev = parent;
[1527]     ngx_mail_auth_http_conf_t *conf = child;
[1528] 
[1529]     u_char           *p;
[1530]     size_t            len;
[1531]     ngx_uint_t        i;
[1532]     ngx_table_elt_t  *header;
[1533] 
[1534]     if (conf->peer == NULL) {
[1535]         conf->peer = prev->peer;
[1536]         conf->host_header = prev->host_header;
[1537]         conf->uri = prev->uri;
[1538] 
[1539]         if (conf->peer == NULL) {
[1540]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1541]                           "no \"auth_http\" is defined for server in %s:%ui",
[1542]                           conf->file, conf->line);
[1543] 
[1544]             return NGX_CONF_ERROR;
[1545]         }
[1546]     }
[1547] 
[1548]     ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
[1549] 
[1550]     ngx_conf_merge_value(conf->pass_client_cert, prev->pass_client_cert, 0);
[1551] 
[1552]     if (conf->headers == NULL) {
[1553]         conf->headers = prev->headers;
[1554]         conf->header = prev->header;
[1555]     }
[1556] 
[1557]     if (conf->headers && conf->header.len == 0) {
[1558]         len = 0;
[1559]         header = conf->headers->elts;
[1560]         for (i = 0; i < conf->headers->nelts; i++) {
[1561]             len += header[i].key.len + 2 + header[i].value.len + 2;
[1562]         }
[1563] 
[1564]         p = ngx_pnalloc(cf->pool, len);
[1565]         if (p == NULL) {
[1566]             return NGX_CONF_ERROR;
[1567]         }
[1568] 
[1569]         conf->header.len = len;
[1570]         conf->header.data = p;
[1571] 
[1572]         for (i = 0; i < conf->headers->nelts; i++) {
[1573]             p = ngx_cpymem(p, header[i].key.data, header[i].key.len);
[1574]             *p++ = ':'; *p++ = ' ';
[1575]             p = ngx_cpymem(p, header[i].value.data, header[i].value.len);
[1576]             *p++ = CR; *p++ = LF;
[1577]         }
[1578]     }
[1579] 
[1580]     return NGX_CONF_OK;
[1581] }
[1582] 
[1583] 
[1584] static char *
[1585] ngx_mail_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1586] {
[1587]     ngx_mail_auth_http_conf_t *ahcf = conf;
[1588] 
[1589]     ngx_str_t  *value;
[1590]     ngx_url_t   u;
[1591] 
[1592]     value = cf->args->elts;
[1593] 
[1594]     ngx_memzero(&u, sizeof(ngx_url_t));
[1595] 
[1596]     u.url = value[1];
[1597]     u.default_port = 80;
[1598]     u.uri_part = 1;
[1599] 
[1600]     if (ngx_strncmp(u.url.data, "http://", 7) == 0) {
[1601]         u.url.len -= 7;
[1602]         u.url.data += 7;
[1603]     }
[1604] 
[1605]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[1606]         if (u.err) {
[1607]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1608]                                "%s in auth_http \"%V\"", u.err, &u.url);
[1609]         }
[1610] 
[1611]         return NGX_CONF_ERROR;
[1612]     }
[1613] 
[1614]     ahcf->peer = u.addrs;
[1615] 
[1616]     if (u.family != AF_UNIX) {
[1617]         ahcf->host_header = u.host;
[1618] 
[1619]     } else {
[1620]         ngx_str_set(&ahcf->host_header, "localhost");
[1621]     }
[1622] 
[1623]     ahcf->uri = u.uri;
[1624] 
[1625]     if (ahcf->uri.len == 0) {
[1626]         ngx_str_set(&ahcf->uri, "/");
[1627]     }
[1628] 
[1629]     return NGX_CONF_OK;
[1630] }
[1631] 
[1632] 
[1633] static char *
[1634] ngx_mail_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1635] {
[1636]     ngx_mail_auth_http_conf_t *ahcf = conf;
[1637] 
[1638]     ngx_str_t        *value;
[1639]     ngx_table_elt_t  *header;
[1640] 
[1641]     if (ahcf->headers == NULL) {
[1642]         ahcf->headers = ngx_array_create(cf->pool, 1, sizeof(ngx_table_elt_t));
[1643]         if (ahcf->headers == NULL) {
[1644]             return NGX_CONF_ERROR;
[1645]         }
[1646]     }
[1647] 
[1648]     header = ngx_array_push(ahcf->headers);
[1649]     if (header == NULL) {
[1650]         return NGX_CONF_ERROR;
[1651]     }
[1652] 
[1653]     value = cf->args->elts;
[1654] 
[1655]     header->key = value[1];
[1656]     header->value = value[2];
[1657] 
[1658]     return NGX_CONF_OK;
[1659] }
