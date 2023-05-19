[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MAIL_H_INCLUDED_
[9] #define _NGX_MAIL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] #include <ngx_event_connect.h>
[16] 
[17] #if (NGX_MAIL_SSL)
[18] #include <ngx_mail_ssl_module.h>
[19] #endif
[20] 
[21] 
[22] 
[23] typedef struct {
[24]     void                  **main_conf;
[25]     void                  **srv_conf;
[26] } ngx_mail_conf_ctx_t;
[27] 
[28] 
[29] typedef struct {
[30]     struct sockaddr        *sockaddr;
[31]     socklen_t               socklen;
[32]     ngx_str_t               addr_text;
[33] 
[34]     /* server ctx */
[35]     ngx_mail_conf_ctx_t    *ctx;
[36] 
[37]     unsigned                bind:1;
[38]     unsigned                wildcard:1;
[39]     unsigned                ssl:1;
[40] #if (NGX_HAVE_INET6)
[41]     unsigned                ipv6only:1;
[42] #endif
[43]     unsigned                so_keepalive:2;
[44]     unsigned                proxy_protocol:1;
[45] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[46]     int                     tcp_keepidle;
[47]     int                     tcp_keepintvl;
[48]     int                     tcp_keepcnt;
[49] #endif
[50]     int                     backlog;
[51]     int                     rcvbuf;
[52]     int                     sndbuf;
[53] } ngx_mail_listen_t;
[54] 
[55] 
[56] typedef struct {
[57]     ngx_mail_conf_ctx_t    *ctx;
[58]     ngx_str_t               addr_text;
[59]     unsigned                ssl:1;
[60]     unsigned                proxy_protocol:1;
[61] } ngx_mail_addr_conf_t;
[62] 
[63] typedef struct {
[64]     in_addr_t               addr;
[65]     ngx_mail_addr_conf_t    conf;
[66] } ngx_mail_in_addr_t;
[67] 
[68] 
[69] #if (NGX_HAVE_INET6)
[70] 
[71] typedef struct {
[72]     struct in6_addr         addr6;
[73]     ngx_mail_addr_conf_t    conf;
[74] } ngx_mail_in6_addr_t;
[75] 
[76] #endif
[77] 
[78] 
[79] typedef struct {
[80]     /* ngx_mail_in_addr_t or ngx_mail_in6_addr_t */
[81]     void                   *addrs;
[82]     ngx_uint_t              naddrs;
[83] } ngx_mail_port_t;
[84] 
[85] 
[86] typedef struct {
[87]     int                     family;
[88]     in_port_t               port;
[89]     ngx_array_t             addrs;       /* array of ngx_mail_conf_addr_t */
[90] } ngx_mail_conf_port_t;
[91] 
[92] 
[93] typedef struct {
[94]     ngx_mail_listen_t       opt;
[95] } ngx_mail_conf_addr_t;
[96] 
[97] 
[98] typedef struct {
[99]     ngx_array_t             servers;     /* ngx_mail_core_srv_conf_t */
[100]     ngx_array_t             listen;      /* ngx_mail_listen_t */
[101] } ngx_mail_core_main_conf_t;
[102] 
[103] 
[104] #define NGX_MAIL_POP3_PROTOCOL  0
[105] #define NGX_MAIL_IMAP_PROTOCOL  1
[106] #define NGX_MAIL_SMTP_PROTOCOL  2
[107] 
[108] 
[109] typedef struct ngx_mail_protocol_s  ngx_mail_protocol_t;
[110] 
[111] 
[112] typedef struct {
[113]     ngx_mail_protocol_t    *protocol;
[114] 
[115]     ngx_msec_t              timeout;
[116]     ngx_msec_t              resolver_timeout;
[117] 
[118]     ngx_uint_t              max_errors;
[119] 
[120]     ngx_str_t               server_name;
[121] 
[122]     u_char                 *file_name;
[123]     ngx_uint_t              line;
[124] 
[125]     ngx_resolver_t         *resolver;
[126]     ngx_log_t              *error_log;
[127] 
[128]     /* server ctx */
[129]     ngx_mail_conf_ctx_t    *ctx;
[130] 
[131]     ngx_uint_t              listen;  /* unsigned  listen:1; */
[132] } ngx_mail_core_srv_conf_t;
[133] 
[134] 
[135] typedef enum {
[136]     ngx_pop3_start = 0,
[137]     ngx_pop3_user,
[138]     ngx_pop3_passwd,
[139]     ngx_pop3_auth_login_username,
[140]     ngx_pop3_auth_login_password,
[141]     ngx_pop3_auth_plain,
[142]     ngx_pop3_auth_cram_md5,
[143]     ngx_pop3_auth_external
[144] } ngx_pop3_state_e;
[145] 
[146] 
[147] typedef enum {
[148]     ngx_imap_start = 0,
[149]     ngx_imap_auth_login_username,
[150]     ngx_imap_auth_login_password,
[151]     ngx_imap_auth_plain,
[152]     ngx_imap_auth_cram_md5,
[153]     ngx_imap_auth_external,
[154]     ngx_imap_login,
[155]     ngx_imap_user,
[156]     ngx_imap_passwd
[157] } ngx_imap_state_e;
[158] 
[159] 
[160] typedef enum {
[161]     ngx_smtp_start = 0,
[162]     ngx_smtp_auth_login_username,
[163]     ngx_smtp_auth_login_password,
[164]     ngx_smtp_auth_plain,
[165]     ngx_smtp_auth_cram_md5,
[166]     ngx_smtp_auth_external,
[167]     ngx_smtp_helo,
[168]     ngx_smtp_helo_xclient,
[169]     ngx_smtp_helo_auth,
[170]     ngx_smtp_helo_from,
[171]     ngx_smtp_xclient,
[172]     ngx_smtp_xclient_from,
[173]     ngx_smtp_xclient_helo,
[174]     ngx_smtp_xclient_auth,
[175]     ngx_smtp_from,
[176]     ngx_smtp_to
[177] } ngx_smtp_state_e;
[178] 
[179] 
[180] typedef struct {
[181]     ngx_peer_connection_t   upstream;
[182]     ngx_buf_t              *buffer;
[183]     ngx_uint_t              proxy_protocol;  /* unsigned  proxy_protocol:1; */
[184] } ngx_mail_proxy_ctx_t;
[185] 
[186] 
[187] typedef struct {
[188]     uint32_t                signature;         /* "MAIL" */
[189] 
[190]     ngx_connection_t       *connection;
[191] 
[192]     ngx_str_t               out;
[193]     ngx_buf_t              *buffer;
[194] 
[195]     void                  **ctx;
[196]     void                  **main_conf;
[197]     void                  **srv_conf;
[198] 
[199]     ngx_resolver_ctx_t     *resolver_ctx;
[200] 
[201]     ngx_mail_proxy_ctx_t   *proxy;
[202] 
[203]     ngx_uint_t              mail_state;
[204] 
[205]     unsigned                ssl:1;
[206]     unsigned                protocol:3;
[207]     unsigned                blocked:1;
[208]     unsigned                quit:1;
[209]     unsigned                quoted:1;
[210]     unsigned                backslash:1;
[211]     unsigned                no_sync_literal:1;
[212]     unsigned                starttls:1;
[213]     unsigned                esmtp:1;
[214]     unsigned                auth_method:3;
[215]     unsigned                auth_wait:1;
[216] 
[217]     ngx_str_t               login;
[218]     ngx_str_t               passwd;
[219] 
[220]     ngx_str_t               salt;
[221]     ngx_str_t               tag;
[222]     ngx_str_t               tagged_line;
[223]     ngx_str_t               text;
[224] 
[225]     ngx_str_t              *addr_text;
[226]     ngx_str_t               host;
[227]     ngx_str_t               smtp_helo;
[228]     ngx_str_t               smtp_from;
[229]     ngx_str_t               smtp_to;
[230] 
[231]     ngx_str_t               cmd;
[232] 
[233]     ngx_uint_t              command;
[234]     ngx_array_t             args;
[235] 
[236]     ngx_uint_t              errors;
[237]     ngx_uint_t              login_attempt;
[238] 
[239]     /* used to parse POP3/IMAP/SMTP command */
[240] 
[241]     ngx_uint_t              state;
[242]     u_char                 *tag_start;
[243]     u_char                 *cmd_start;
[244]     u_char                 *arg_start;
[245]     ngx_uint_t              literal_len;
[246] } ngx_mail_session_t;
[247] 
[248] 
[249] typedef struct {
[250]     ngx_str_t              *client;
[251]     ngx_mail_session_t     *session;
[252] } ngx_mail_log_ctx_t;
[253] 
[254] 
[255] #define NGX_POP3_USER          1
[256] #define NGX_POP3_PASS          2
[257] #define NGX_POP3_CAPA          3
[258] #define NGX_POP3_QUIT          4
[259] #define NGX_POP3_NOOP          5
[260] #define NGX_POP3_STLS          6
[261] #define NGX_POP3_APOP          7
[262] #define NGX_POP3_AUTH          8
[263] #define NGX_POP3_STAT          9
[264] #define NGX_POP3_LIST          10
[265] #define NGX_POP3_RETR          11
[266] #define NGX_POP3_DELE          12
[267] #define NGX_POP3_RSET          13
[268] #define NGX_POP3_TOP           14
[269] #define NGX_POP3_UIDL          15
[270] 
[271] 
[272] #define NGX_IMAP_LOGIN         1
[273] #define NGX_IMAP_LOGOUT        2
[274] #define NGX_IMAP_CAPABILITY    3
[275] #define NGX_IMAP_NOOP          4
[276] #define NGX_IMAP_STARTTLS      5
[277] 
[278] #define NGX_IMAP_NEXT          6
[279] 
[280] #define NGX_IMAP_AUTHENTICATE  7
[281] 
[282] 
[283] #define NGX_SMTP_HELO          1
[284] #define NGX_SMTP_EHLO          2
[285] #define NGX_SMTP_AUTH          3
[286] #define NGX_SMTP_QUIT          4
[287] #define NGX_SMTP_NOOP          5
[288] #define NGX_SMTP_MAIL          6
[289] #define NGX_SMTP_RSET          7
[290] #define NGX_SMTP_RCPT          8
[291] #define NGX_SMTP_DATA          9
[292] #define NGX_SMTP_VRFY          10
[293] #define NGX_SMTP_EXPN          11
[294] #define NGX_SMTP_HELP          12
[295] #define NGX_SMTP_STARTTLS      13
[296] 
[297] 
[298] #define NGX_MAIL_AUTH_PLAIN             0
[299] #define NGX_MAIL_AUTH_LOGIN             1
[300] #define NGX_MAIL_AUTH_LOGIN_USERNAME    2
[301] #define NGX_MAIL_AUTH_APOP              3
[302] #define NGX_MAIL_AUTH_CRAM_MD5          4
[303] #define NGX_MAIL_AUTH_EXTERNAL          5
[304] #define NGX_MAIL_AUTH_NONE              6
[305] 
[306] 
[307] #define NGX_MAIL_AUTH_PLAIN_ENABLED     0x0002
[308] #define NGX_MAIL_AUTH_LOGIN_ENABLED     0x0004
[309] #define NGX_MAIL_AUTH_APOP_ENABLED      0x0008
[310] #define NGX_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
[311] #define NGX_MAIL_AUTH_EXTERNAL_ENABLED  0x0020
[312] #define NGX_MAIL_AUTH_NONE_ENABLED      0x0040
[313] 
[314] 
[315] #define NGX_MAIL_PARSE_INVALID_COMMAND  20
[316] 
[317] 
[318] typedef void (*ngx_mail_init_session_pt)(ngx_mail_session_t *s,
[319]     ngx_connection_t *c);
[320] typedef void (*ngx_mail_init_protocol_pt)(ngx_event_t *rev);
[321] typedef void (*ngx_mail_auth_state_pt)(ngx_event_t *rev);
[322] typedef ngx_int_t (*ngx_mail_parse_command_pt)(ngx_mail_session_t *s);
[323] 
[324] 
[325] struct ngx_mail_protocol_s {
[326]     ngx_str_t                   name;
[327]     ngx_str_t                   alpn;
[328]     in_port_t                   port[4];
[329]     ngx_uint_t                  type;
[330] 
[331]     ngx_mail_init_session_pt    init_session;
[332]     ngx_mail_init_protocol_pt   init_protocol;
[333]     ngx_mail_parse_command_pt   parse_command;
[334]     ngx_mail_auth_state_pt      auth_state;
[335] 
[336]     ngx_str_t                   internal_server_error;
[337]     ngx_str_t                   cert_error;
[338]     ngx_str_t                   no_cert;
[339] };
[340] 
[341] 
[342] typedef struct {
[343]     ngx_mail_protocol_t        *protocol;
[344] 
[345]     void                       *(*create_main_conf)(ngx_conf_t *cf);
[346]     char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);
[347] 
[348]     void                       *(*create_srv_conf)(ngx_conf_t *cf);
[349]     char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
[350]                                                   void *conf);
[351] } ngx_mail_module_t;
[352] 
[353] 
[354] #define NGX_MAIL_MODULE         0x4C49414D     /* "MAIL" */
[355] 
[356] #define NGX_MAIL_MAIN_CONF      0x02000000
[357] #define NGX_MAIL_SRV_CONF       0x04000000
[358] 
[359] 
[360] #define NGX_MAIL_MAIN_CONF_OFFSET  offsetof(ngx_mail_conf_ctx_t, main_conf)
[361] #define NGX_MAIL_SRV_CONF_OFFSET   offsetof(ngx_mail_conf_ctx_t, srv_conf)
[362] 
[363] 
[364] #define ngx_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
[365] #define ngx_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
[366] #define ngx_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;
[367] 
[368] 
[369] #define ngx_mail_get_module_main_conf(s, module)                             \
[370]     (s)->main_conf[module.ctx_index]
[371] #define ngx_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]
[372] 
[373] #define ngx_mail_conf_get_module_main_conf(cf, module)                       \
[374]     ((ngx_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
[375] #define ngx_mail_conf_get_module_srv_conf(cf, module)                        \
[376]     ((ngx_mail_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
[377] 
[378] 
[379] #if (NGX_MAIL_SSL)
[380] void ngx_mail_starttls_handler(ngx_event_t *rev);
[381] ngx_int_t ngx_mail_starttls_only(ngx_mail_session_t *s, ngx_connection_t *c);
[382] #endif
[383] 
[384] 
[385] void ngx_mail_init_connection(ngx_connection_t *c);
[386] 
[387] ngx_int_t ngx_mail_salt(ngx_mail_session_t *s, ngx_connection_t *c,
[388]     ngx_mail_core_srv_conf_t *cscf);
[389] ngx_int_t ngx_mail_auth_plain(ngx_mail_session_t *s, ngx_connection_t *c,
[390]     ngx_uint_t n);
[391] ngx_int_t ngx_mail_auth_login_username(ngx_mail_session_t *s,
[392]     ngx_connection_t *c, ngx_uint_t n);
[393] ngx_int_t ngx_mail_auth_login_password(ngx_mail_session_t *s,
[394]     ngx_connection_t *c);
[395] ngx_int_t ngx_mail_auth_cram_md5_salt(ngx_mail_session_t *s,
[396]     ngx_connection_t *c, char *prefix, size_t len);
[397] ngx_int_t ngx_mail_auth_cram_md5(ngx_mail_session_t *s, ngx_connection_t *c);
[398] ngx_int_t ngx_mail_auth_external(ngx_mail_session_t *s, ngx_connection_t *c,
[399]     ngx_uint_t n);
[400] ngx_int_t ngx_mail_auth_parse(ngx_mail_session_t *s, ngx_connection_t *c);
[401] 
[402] void ngx_mail_send(ngx_event_t *wev);
[403] ngx_int_t ngx_mail_read_command(ngx_mail_session_t *s, ngx_connection_t *c);
[404] void ngx_mail_auth(ngx_mail_session_t *s, ngx_connection_t *c);
[405] void ngx_mail_close_connection(ngx_connection_t *c);
[406] void ngx_mail_session_internal_server_error(ngx_mail_session_t *s);
[407] u_char *ngx_mail_log_error(ngx_log_t *log, u_char *buf, size_t len);
[408] 
[409] 
[410] char *ngx_mail_capabilities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[411] 
[412] 
[413] /* STUB */
[414] void ngx_mail_proxy_init(ngx_mail_session_t *s, ngx_addr_t *peer);
[415] void ngx_mail_auth_http_init(ngx_mail_session_t *s);
[416] ngx_int_t ngx_mail_realip_handler(ngx_mail_session_t *s);
[417] /**/
[418] 
[419] 
[420] extern ngx_uint_t    ngx_mail_max_module;
[421] extern ngx_module_t  ngx_mail_core_module;
[422] 
[423] 
[424] #endif /* _NGX_MAIL_H_INCLUDED_ */
