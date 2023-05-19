[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_event.h>
[10] 
[11] 
[12] #define NGX_SYSLOG_MAX_STR                                                    \
[13]     NGX_MAX_ERROR_STR + sizeof("<255>Jan 01 00:00:00 ") - 1                   \
[14]     + (NGX_MAXHOSTNAMELEN - 1) + 1 /* space */                                \
[15]     + 32 /* tag */ + 2 /* colon, space */
[16] 
[17] 
[18] static char *ngx_syslog_parse_args(ngx_conf_t *cf, ngx_syslog_peer_t *peer);
[19] static ngx_int_t ngx_syslog_init_peer(ngx_syslog_peer_t *peer);
[20] static void ngx_syslog_cleanup(void *data);
[21] static u_char *ngx_syslog_log_error(ngx_log_t *log, u_char *buf, size_t len);
[22] 
[23] 
[24] static char  *facilities[] = {
[25]     "kern", "user", "mail", "daemon", "auth", "intern", "lpr", "news", "uucp",
[26]     "clock", "authpriv", "ftp", "ntp", "audit", "alert", "cron", "local0",
[27]     "local1", "local2", "local3", "local4", "local5", "local6", "local7",
[28]     NULL
[29] };
[30] 
[31] /* note 'error/warn' like in nginx.conf, not 'err/warning' */
[32] static char  *severities[] = {
[33]     "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug", NULL
[34] };
[35] 
[36] static ngx_log_t    ngx_syslog_dummy_log;
[37] static ngx_event_t  ngx_syslog_dummy_event;
[38] 
[39] 
[40] char *
[41] ngx_syslog_process_conf(ngx_conf_t *cf, ngx_syslog_peer_t *peer)
[42] {
[43]     ngx_pool_cleanup_t  *cln;
[44] 
[45]     peer->facility = NGX_CONF_UNSET_UINT;
[46]     peer->severity = NGX_CONF_UNSET_UINT;
[47] 
[48]     if (ngx_syslog_parse_args(cf, peer) != NGX_CONF_OK) {
[49]         return NGX_CONF_ERROR;
[50]     }
[51] 
[52]     if (peer->server.sockaddr == NULL) {
[53]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[54]                            "no syslog server specified");
[55]         return NGX_CONF_ERROR;
[56]     }
[57] 
[58]     if (peer->facility == NGX_CONF_UNSET_UINT) {
[59]         peer->facility = 23; /* local7 */
[60]     }
[61] 
[62]     if (peer->severity == NGX_CONF_UNSET_UINT) {
[63]         peer->severity = 6; /* info */
[64]     }
[65] 
[66]     if (peer->tag.data == NULL) {
[67]         ngx_str_set(&peer->tag, "nginx");
[68]     }
[69] 
[70]     peer->hostname = &cf->cycle->hostname;
[71]     peer->logp = &cf->cycle->new_log;
[72] 
[73]     peer->conn.fd = (ngx_socket_t) -1;
[74] 
[75]     peer->conn.read = &ngx_syslog_dummy_event;
[76]     peer->conn.write = &ngx_syslog_dummy_event;
[77] 
[78]     ngx_syslog_dummy_event.log = &ngx_syslog_dummy_log;
[79] 
[80]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[81]     if (cln == NULL) {
[82]         return NGX_CONF_ERROR;
[83]     }
[84] 
[85]     cln->data = peer;
[86]     cln->handler = ngx_syslog_cleanup;
[87] 
[88]     return NGX_CONF_OK;
[89] }
[90] 
[91] 
[92] static char *
[93] ngx_syslog_parse_args(ngx_conf_t *cf, ngx_syslog_peer_t *peer)
[94] {
[95]     u_char      *p, *comma, c;
[96]     size_t       len;
[97]     ngx_str_t   *value;
[98]     ngx_url_t    u;
[99]     ngx_uint_t   i;
[100] 
[101]     value = cf->args->elts;
[102] 
[103]     p = value[1].data + sizeof("syslog:") - 1;
[104] 
[105]     for ( ;; ) {
[106]         comma = (u_char *) ngx_strchr(p, ',');
[107] 
[108]         if (comma != NULL) {
[109]             len = comma - p;
[110]             *comma = '\0';
[111] 
[112]         } else {
[113]             len = value[1].data + value[1].len - p;
[114]         }
[115] 
[116]         if (ngx_strncmp(p, "server=", 7) == 0) {
[117] 
[118]             if (peer->server.sockaddr != NULL) {
[119]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[120]                                    "duplicate syslog \"server\"");
[121]                 return NGX_CONF_ERROR;
[122]             }
[123] 
[124]             ngx_memzero(&u, sizeof(ngx_url_t));
[125] 
[126]             u.url.data = p + 7;
[127]             u.url.len = len - 7;
[128]             u.default_port = 514;
[129] 
[130]             if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[131]                 if (u.err) {
[132]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[133]                                        "%s in syslog server \"%V\"",
[134]                                        u.err, &u.url);
[135]                 }
[136] 
[137]                 return NGX_CONF_ERROR;
[138]             }
[139] 
[140]             peer->server = u.addrs[0];
[141] 
[142]         } else if (ngx_strncmp(p, "facility=", 9) == 0) {
[143] 
[144]             if (peer->facility != NGX_CONF_UNSET_UINT) {
[145]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[146]                                    "duplicate syslog \"facility\"");
[147]                 return NGX_CONF_ERROR;
[148]             }
[149] 
[150]             for (i = 0; facilities[i] != NULL; i++) {
[151] 
[152]                 if (ngx_strcmp(p + 9, facilities[i]) == 0) {
[153]                     peer->facility = i;
[154]                     goto next;
[155]                 }
[156]             }
[157] 
[158]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[159]                                "unknown syslog facility \"%s\"", p + 9);
[160]             return NGX_CONF_ERROR;
[161] 
[162]         } else if (ngx_strncmp(p, "severity=", 9) == 0) {
[163] 
[164]             if (peer->severity != NGX_CONF_UNSET_UINT) {
[165]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[166]                                    "duplicate syslog \"severity\"");
[167]                 return NGX_CONF_ERROR;
[168]             }
[169] 
[170]             for (i = 0; severities[i] != NULL; i++) {
[171] 
[172]                 if (ngx_strcmp(p + 9, severities[i]) == 0) {
[173]                     peer->severity = i;
[174]                     goto next;
[175]                 }
[176]             }
[177] 
[178]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[179]                                "unknown syslog severity \"%s\"", p + 9);
[180]             return NGX_CONF_ERROR;
[181] 
[182]         } else if (ngx_strncmp(p, "tag=", 4) == 0) {
[183] 
[184]             if (peer->tag.data != NULL) {
[185]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[186]                                    "duplicate syslog \"tag\"");
[187]                 return NGX_CONF_ERROR;
[188]             }
[189] 
[190]             /*
[191]              * RFC 3164: the TAG is a string of ABNF alphanumeric characters
[192]              * that MUST NOT exceed 32 characters.
[193]              */
[194]             if (len - 4 > 32) {
[195]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[196]                                    "syslog tag length exceeds 32");
[197]                 return NGX_CONF_ERROR;
[198]             }
[199] 
[200]             for (i = 4; i < len; i++) {
[201]                 c = ngx_tolower(p[i]);
[202] 
[203]                 if (c < '0' || (c > '9' && c < 'a' && c != '_') || c > 'z') {
[204]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[205]                                        "syslog \"tag\" only allows "
[206]                                        "alphanumeric characters "
[207]                                        "and underscore");
[208]                     return NGX_CONF_ERROR;
[209]                 }
[210]             }
[211] 
[212]             peer->tag.data = p + 4;
[213]             peer->tag.len = len - 4;
[214] 
[215]         } else if (len == 10 && ngx_strncmp(p, "nohostname", 10) == 0) {
[216]             peer->nohostname = 1;
[217] 
[218]         } else {
[219]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[220]                                "unknown syslog parameter \"%s\"", p);
[221]             return NGX_CONF_ERROR;
[222]         }
[223] 
[224]     next:
[225] 
[226]         if (comma == NULL) {
[227]             break;
[228]         }
[229] 
[230]         p = comma + 1;
[231]     }
[232] 
[233]     return NGX_CONF_OK;
[234] }
[235] 
[236] 
[237] u_char *
[238] ngx_syslog_add_header(ngx_syslog_peer_t *peer, u_char *buf)
[239] {
[240]     ngx_uint_t  pri;
[241] 
[242]     pri = peer->facility * 8 + peer->severity;
[243] 
[244]     if (peer->nohostname) {
[245]         return ngx_sprintf(buf, "<%ui>%V %V: ", pri, &ngx_cached_syslog_time,
[246]                            &peer->tag);
[247]     }
[248] 
[249]     return ngx_sprintf(buf, "<%ui>%V %V %V: ", pri, &ngx_cached_syslog_time,
[250]                        peer->hostname, &peer->tag);
[251] }
[252] 
[253] 
[254] void
[255] ngx_syslog_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
[256]     size_t len)
[257] {
[258]     u_char             *p, msg[NGX_SYSLOG_MAX_STR];
[259]     ngx_uint_t          head_len;
[260]     ngx_syslog_peer_t  *peer;
[261] 
[262]     peer = log->wdata;
[263] 
[264]     if (peer->busy) {
[265]         return;
[266]     }
[267] 
[268]     peer->busy = 1;
[269]     peer->severity = level - 1;
[270] 
[271]     p = ngx_syslog_add_header(peer, msg);
[272]     head_len = p - msg;
[273] 
[274]     len -= NGX_LINEFEED_SIZE;
[275] 
[276]     if (len > NGX_SYSLOG_MAX_STR - head_len) {
[277]         len = NGX_SYSLOG_MAX_STR - head_len;
[278]     }
[279] 
[280]     p = ngx_snprintf(p, len, "%s", buf);
[281] 
[282]     (void) ngx_syslog_send(peer, msg, p - msg);
[283] 
[284]     peer->busy = 0;
[285] }
[286] 
[287] 
[288] ssize_t
[289] ngx_syslog_send(ngx_syslog_peer_t *peer, u_char *buf, size_t len)
[290] {
[291]     ssize_t  n;
[292] 
[293]     if (peer->log.handler == NULL) {
[294]         peer->log = *peer->logp;
[295]         peer->log.handler = ngx_syslog_log_error;
[296]         peer->log.data = peer;
[297]         peer->log.action = "logging to syslog";
[298]     }
[299] 
[300]     if (peer->conn.fd == (ngx_socket_t) -1) {
[301]         if (ngx_syslog_init_peer(peer) != NGX_OK) {
[302]             return NGX_ERROR;
[303]         }
[304]     }
[305] 
[306]     if (ngx_send) {
[307]         n = ngx_send(&peer->conn, buf, len);
[308] 
[309]     } else {
[310]         /* event module has not yet set ngx_io */
[311]         n = ngx_os_io.send(&peer->conn, buf, len);
[312]     }
[313] 
[314]     if (n == NGX_ERROR) {
[315] 
[316]         if (ngx_close_socket(peer->conn.fd) == -1) {
[317]             ngx_log_error(NGX_LOG_ALERT, &peer->log, ngx_socket_errno,
[318]                           ngx_close_socket_n " failed");
[319]         }
[320] 
[321]         peer->conn.fd = (ngx_socket_t) -1;
[322]     }
[323] 
[324]     return n;
[325] }
[326] 
[327] 
[328] static ngx_int_t
[329] ngx_syslog_init_peer(ngx_syslog_peer_t *peer)
[330] {
[331]     ngx_socket_t  fd;
[332] 
[333]     fd = ngx_socket(peer->server.sockaddr->sa_family, SOCK_DGRAM, 0);
[334]     if (fd == (ngx_socket_t) -1) {
[335]         ngx_log_error(NGX_LOG_ALERT, &peer->log, ngx_socket_errno,
[336]                       ngx_socket_n " failed");
[337]         return NGX_ERROR;
[338]     }
[339] 
[340]     if (ngx_nonblocking(fd) == -1) {
[341]         ngx_log_error(NGX_LOG_ALERT, &peer->log, ngx_socket_errno,
[342]                       ngx_nonblocking_n " failed");
[343]         goto failed;
[344]     }
[345] 
[346]     if (connect(fd, peer->server.sockaddr, peer->server.socklen) == -1) {
[347]         ngx_log_error(NGX_LOG_ALERT, &peer->log, ngx_socket_errno,
[348]                       "connect() failed");
[349]         goto failed;
[350]     }
[351] 
[352]     peer->conn.fd = fd;
[353]     peer->conn.log = &peer->log;
[354] 
[355]     /* UDP sockets are always ready to write */
[356]     peer->conn.write->ready = 1;
[357] 
[358]     return NGX_OK;
[359] 
[360] failed:
[361] 
[362]     if (ngx_close_socket(fd) == -1) {
[363]         ngx_log_error(NGX_LOG_ALERT, &peer->log, ngx_socket_errno,
[364]                       ngx_close_socket_n " failed");
[365]     }
[366] 
[367]     return NGX_ERROR;
[368] }
[369] 
[370] 
[371] static void
[372] ngx_syslog_cleanup(void *data)
[373] {
[374]     ngx_syslog_peer_t  *peer = data;
[375] 
[376]     /* prevents further use of this peer */
[377]     peer->busy = 1;
[378] 
[379]     if (peer->conn.fd == (ngx_socket_t) -1) {
[380]         return;
[381]     }
[382] 
[383]     if (ngx_close_socket(peer->conn.fd) == -1) {
[384]         ngx_log_error(NGX_LOG_ALERT, &peer->log, ngx_socket_errno,
[385]                       ngx_close_socket_n " failed");
[386]     }
[387] }
[388] 
[389] 
[390] static u_char *
[391] ngx_syslog_log_error(ngx_log_t *log, u_char *buf, size_t len)
[392] {
[393]     u_char             *p;
[394]     ngx_syslog_peer_t  *peer;
[395] 
[396]     p = buf;
[397] 
[398]     if (log->action) {
[399]         p = ngx_snprintf(buf, len, " while %s", log->action);
[400]         len -= p - buf;
[401]     }
[402] 
[403]     peer = log->data;
[404] 
[405]     if (peer) {
[406]         p = ngx_snprintf(p, len, ", server: %V", &peer->server.name);
[407]     }
[408] 
[409]     return p;
[410] }
