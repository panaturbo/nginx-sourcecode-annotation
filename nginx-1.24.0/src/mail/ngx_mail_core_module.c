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
[14] static void *ngx_mail_core_create_main_conf(ngx_conf_t *cf);
[15] static void *ngx_mail_core_create_srv_conf(ngx_conf_t *cf);
[16] static char *ngx_mail_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
[17]     void *child);
[18] static char *ngx_mail_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
[19]     void *conf);
[20] static char *ngx_mail_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
[21]     void *conf);
[22] static char *ngx_mail_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd,
[23]     void *conf);
[24] static char *ngx_mail_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
[25]     void *conf);
[26] static char *ngx_mail_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
[27]     void *conf);
[28] 
[29] 
[30] static ngx_command_t  ngx_mail_core_commands[] = {
[31] 
[32]     { ngx_string("server"),
[33]       NGX_MAIL_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[34]       ngx_mail_core_server,
[35]       0,
[36]       0,
[37]       NULL },
[38] 
[39]     { ngx_string("listen"),
[40]       NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[41]       ngx_mail_core_listen,
[42]       NGX_MAIL_SRV_CONF_OFFSET,
[43]       0,
[44]       NULL },
[45] 
[46]     { ngx_string("protocol"),
[47]       NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[48]       ngx_mail_core_protocol,
[49]       NGX_MAIL_SRV_CONF_OFFSET,
[50]       0,
[51]       NULL },
[52] 
[53]     { ngx_string("timeout"),
[54]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[55]       ngx_conf_set_msec_slot,
[56]       NGX_MAIL_SRV_CONF_OFFSET,
[57]       offsetof(ngx_mail_core_srv_conf_t, timeout),
[58]       NULL },
[59] 
[60]     { ngx_string("server_name"),
[61]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[62]       ngx_conf_set_str_slot,
[63]       NGX_MAIL_SRV_CONF_OFFSET,
[64]       offsetof(ngx_mail_core_srv_conf_t, server_name),
[65]       NULL },
[66] 
[67]     { ngx_string("error_log"),
[68]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[69]       ngx_mail_core_error_log,
[70]       NGX_MAIL_SRV_CONF_OFFSET,
[71]       0,
[72]       NULL },
[73] 
[74]     { ngx_string("resolver"),
[75]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[76]       ngx_mail_core_resolver,
[77]       NGX_MAIL_SRV_CONF_OFFSET,
[78]       0,
[79]       NULL },
[80] 
[81]     { ngx_string("resolver_timeout"),
[82]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[83]       ngx_conf_set_msec_slot,
[84]       NGX_MAIL_SRV_CONF_OFFSET,
[85]       offsetof(ngx_mail_core_srv_conf_t, resolver_timeout),
[86]       NULL },
[87] 
[88]     { ngx_string("max_errors"),
[89]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[90]       ngx_conf_set_num_slot,
[91]       NGX_MAIL_SRV_CONF_OFFSET,
[92]       offsetof(ngx_mail_core_srv_conf_t, max_errors),
[93]       NULL },
[94] 
[95]       ngx_null_command
[96] };
[97] 
[98] 
[99] static ngx_mail_module_t  ngx_mail_core_module_ctx = {
[100]     NULL,                                  /* protocol */
[101] 
[102]     ngx_mail_core_create_main_conf,        /* create main configuration */
[103]     NULL,                                  /* init main configuration */
[104] 
[105]     ngx_mail_core_create_srv_conf,         /* create server configuration */
[106]     ngx_mail_core_merge_srv_conf           /* merge server configuration */
[107] };
[108] 
[109] 
[110] ngx_module_t  ngx_mail_core_module = {
[111]     NGX_MODULE_V1,
[112]     &ngx_mail_core_module_ctx,             /* module context */
[113]     ngx_mail_core_commands,                /* module directives */
[114]     NGX_MAIL_MODULE,                       /* module type */
[115]     NULL,                                  /* init master */
[116]     NULL,                                  /* init module */
[117]     NULL,                                  /* init process */
[118]     NULL,                                  /* init thread */
[119]     NULL,                                  /* exit thread */
[120]     NULL,                                  /* exit process */
[121]     NULL,                                  /* exit master */
[122]     NGX_MODULE_V1_PADDING
[123] };
[124] 
[125] 
[126] static void *
[127] ngx_mail_core_create_main_conf(ngx_conf_t *cf)
[128] {
[129]     ngx_mail_core_main_conf_t  *cmcf;
[130] 
[131]     cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_core_main_conf_t));
[132]     if (cmcf == NULL) {
[133]         return NULL;
[134]     }
[135] 
[136]     if (ngx_array_init(&cmcf->servers, cf->pool, 4,
[137]                        sizeof(ngx_mail_core_srv_conf_t *))
[138]         != NGX_OK)
[139]     {
[140]         return NULL;
[141]     }
[142] 
[143]     if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_mail_listen_t))
[144]         != NGX_OK)
[145]     {
[146]         return NULL;
[147]     }
[148] 
[149]     return cmcf;
[150] }
[151] 
[152] 
[153] static void *
[154] ngx_mail_core_create_srv_conf(ngx_conf_t *cf)
[155] {
[156]     ngx_mail_core_srv_conf_t  *cscf;
[157] 
[158]     cscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_core_srv_conf_t));
[159]     if (cscf == NULL) {
[160]         return NULL;
[161]     }
[162] 
[163]     /*
[164]      * set by ngx_pcalloc():
[165]      *
[166]      *     cscf->protocol = NULL;
[167]      *     cscf->error_log = NULL;
[168]      */
[169] 
[170]     cscf->timeout = NGX_CONF_UNSET_MSEC;
[171]     cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
[172] 
[173]     cscf->max_errors = NGX_CONF_UNSET_UINT;
[174] 
[175]     cscf->resolver = NGX_CONF_UNSET_PTR;
[176] 
[177]     cscf->file_name = cf->conf_file->file.name.data;
[178]     cscf->line = cf->conf_file->line;
[179] 
[180]     return cscf;
[181] }
[182] 
[183] 
[184] static char *
[185] ngx_mail_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[186] {
[187]     ngx_mail_core_srv_conf_t *prev = parent;
[188]     ngx_mail_core_srv_conf_t *conf = child;
[189] 
[190]     ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
[191]     ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
[192]                               30000);
[193] 
[194]     ngx_conf_merge_uint_value(conf->max_errors, prev->max_errors, 5);
[195] 
[196]     ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");
[197] 
[198]     if (conf->server_name.len == 0) {
[199]         conf->server_name = cf->cycle->hostname;
[200]     }
[201] 
[202]     if (conf->protocol == NULL) {
[203]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[204]                       "unknown mail protocol for server in %s:%ui",
[205]                       conf->file_name, conf->line);
[206]         return NGX_CONF_ERROR;
[207]     }
[208] 
[209]     if (conf->error_log == NULL) {
[210]         if (prev->error_log) {
[211]             conf->error_log = prev->error_log;
[212]         } else {
[213]             conf->error_log = &cf->cycle->new_log;
[214]         }
[215]     }
[216] 
[217]     ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);
[218] 
[219]     return NGX_CONF_OK;
[220] }
[221] 
[222] 
[223] static char *
[224] ngx_mail_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[225] {
[226]     char                       *rv;
[227]     void                       *mconf;
[228]     ngx_uint_t                  m;
[229]     ngx_conf_t                  pcf;
[230]     ngx_mail_module_t          *module;
[231]     ngx_mail_conf_ctx_t        *ctx, *mail_ctx;
[232]     ngx_mail_core_srv_conf_t   *cscf, **cscfp;
[233]     ngx_mail_core_main_conf_t  *cmcf;
[234] 
[235]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_mail_conf_ctx_t));
[236]     if (ctx == NULL) {
[237]         return NGX_CONF_ERROR;
[238]     }
[239] 
[240]     mail_ctx = cf->ctx;
[241]     ctx->main_conf = mail_ctx->main_conf;
[242] 
[243]     /* the server{}'s srv_conf */
[244] 
[245]     ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_mail_max_module);
[246]     if (ctx->srv_conf == NULL) {
[247]         return NGX_CONF_ERROR;
[248]     }
[249] 
[250]     for (m = 0; cf->cycle->modules[m]; m++) {
[251]         if (cf->cycle->modules[m]->type != NGX_MAIL_MODULE) {
[252]             continue;
[253]         }
[254] 
[255]         module = cf->cycle->modules[m]->ctx;
[256] 
[257]         if (module->create_srv_conf) {
[258]             mconf = module->create_srv_conf(cf);
[259]             if (mconf == NULL) {
[260]                 return NGX_CONF_ERROR;
[261]             }
[262] 
[263]             ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
[264]         }
[265]     }
[266] 
[267]     /* the server configuration context */
[268] 
[269]     cscf = ctx->srv_conf[ngx_mail_core_module.ctx_index];
[270]     cscf->ctx = ctx;
[271] 
[272]     cmcf = ctx->main_conf[ngx_mail_core_module.ctx_index];
[273] 
[274]     cscfp = ngx_array_push(&cmcf->servers);
[275]     if (cscfp == NULL) {
[276]         return NGX_CONF_ERROR;
[277]     }
[278] 
[279]     *cscfp = cscf;
[280] 
[281] 
[282]     /* parse inside server{} */
[283] 
[284]     pcf = *cf;
[285]     cf->ctx = ctx;
[286]     cf->cmd_type = NGX_MAIL_SRV_CONF;
[287] 
[288]     rv = ngx_conf_parse(cf, NULL);
[289] 
[290]     *cf = pcf;
[291] 
[292]     if (rv == NGX_CONF_OK && !cscf->listen) {
[293]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[294]                       "no \"listen\" is defined for server in %s:%ui",
[295]                       cscf->file_name, cscf->line);
[296]         return NGX_CONF_ERROR;
[297]     }
[298] 
[299]     return rv;
[300] }
[301] 
[302] 
[303] static char *
[304] ngx_mail_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[305] {
[306]     ngx_mail_core_srv_conf_t  *cscf = conf;
[307] 
[308]     ngx_str_t                  *value, size;
[309]     ngx_url_t                   u;
[310]     ngx_uint_t                  i, n, m;
[311]     ngx_mail_listen_t          *ls, *als, *nls;
[312]     ngx_mail_module_t          *module;
[313]     ngx_mail_core_main_conf_t  *cmcf;
[314] 
[315]     cscf->listen = 1;
[316] 
[317]     value = cf->args->elts;
[318] 
[319]     ngx_memzero(&u, sizeof(ngx_url_t));
[320] 
[321]     u.url = value[1];
[322]     u.listen = 1;
[323] 
[324]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[325]         if (u.err) {
[326]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[327]                                "%s in \"%V\" of the \"listen\" directive",
[328]                                u.err, &u.url);
[329]         }
[330] 
[331]         return NGX_CONF_ERROR;
[332]     }
[333] 
[334]     cmcf = ngx_mail_conf_get_module_main_conf(cf, ngx_mail_core_module);
[335] 
[336]     ls = ngx_array_push(&cmcf->listen);
[337]     if (ls == NULL) {
[338]         return NGX_CONF_ERROR;
[339]     }
[340] 
[341]     ngx_memzero(ls, sizeof(ngx_mail_listen_t));
[342] 
[343]     ls->backlog = NGX_LISTEN_BACKLOG;
[344]     ls->rcvbuf = -1;
[345]     ls->sndbuf = -1;
[346]     ls->ctx = cf->ctx;
[347] 
[348] #if (NGX_HAVE_INET6)
[349]     ls->ipv6only = 1;
[350] #endif
[351] 
[352]     if (cscf->protocol == NULL) {
[353]         for (m = 0; cf->cycle->modules[m]; m++) {
[354]             if (cf->cycle->modules[m]->type != NGX_MAIL_MODULE) {
[355]                 continue;
[356]             }
[357] 
[358]             module = cf->cycle->modules[m]->ctx;
[359] 
[360]             if (module->protocol == NULL) {
[361]                 continue;
[362]             }
[363] 
[364]             for (i = 0; module->protocol->port[i]; i++) {
[365]                 if (module->protocol->port[i] == u.port) {
[366]                     cscf->protocol = module->protocol;
[367]                     break;
[368]                 }
[369]             }
[370]         }
[371]     }
[372] 
[373]     for (i = 2; i < cf->args->nelts; i++) {
[374] 
[375]         if (ngx_strcmp(value[i].data, "bind") == 0) {
[376]             ls->bind = 1;
[377]             continue;
[378]         }
[379] 
[380]         if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
[381]             ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
[382]             ls->bind = 1;
[383] 
[384]             if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
[385]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[386]                                    "invalid backlog \"%V\"", &value[i]);
[387]                 return NGX_CONF_ERROR;
[388]             }
[389] 
[390]             continue;
[391]         }
[392] 
[393]         if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
[394]             size.len = value[i].len - 7;
[395]             size.data = value[i].data + 7;
[396] 
[397]             ls->rcvbuf = ngx_parse_size(&size);
[398]             ls->bind = 1;
[399] 
[400]             if (ls->rcvbuf == NGX_ERROR) {
[401]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[402]                                    "invalid rcvbuf \"%V\"", &value[i]);
[403]                 return NGX_CONF_ERROR;
[404]             }
[405] 
[406]             continue;
[407]         }
[408] 
[409]         if (ngx_strncmp(value[i].data, "sndbuf=", 7) == 0) {
[410]             size.len = value[i].len - 7;
[411]             size.data = value[i].data + 7;
[412] 
[413]             ls->sndbuf = ngx_parse_size(&size);
[414]             ls->bind = 1;
[415] 
[416]             if (ls->sndbuf == NGX_ERROR) {
[417]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[418]                                    "invalid sndbuf \"%V\"", &value[i]);
[419]                 return NGX_CONF_ERROR;
[420]             }
[421] 
[422]             continue;
[423]         }
[424] 
[425]         if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
[426] #if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
[427]             if (ngx_strcmp(&value[i].data[10], "n") == 0) {
[428]                 ls->ipv6only = 1;
[429] 
[430]             } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
[431]                 ls->ipv6only = 0;
[432] 
[433]             } else {
[434]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[435]                                    "invalid ipv6only flags \"%s\"",
[436]                                    &value[i].data[9]);
[437]                 return NGX_CONF_ERROR;
[438]             }
[439] 
[440]             ls->bind = 1;
[441]             continue;
[442] #else
[443]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[444]                                "bind ipv6only is not supported "
[445]                                "on this platform");
[446]             return NGX_CONF_ERROR;
[447] #endif
[448]         }
[449] 
[450]         if (ngx_strcmp(value[i].data, "ssl") == 0) {
[451] #if (NGX_MAIL_SSL)
[452]             ngx_mail_ssl_conf_t  *sslcf;
[453] 
[454]             sslcf = ngx_mail_conf_get_module_srv_conf(cf, ngx_mail_ssl_module);
[455] 
[456]             sslcf->listen = 1;
[457]             sslcf->file = cf->conf_file->file.name.data;
[458]             sslcf->line = cf->conf_file->line;
[459] 
[460]             ls->ssl = 1;
[461] 
[462]             continue;
[463] #else
[464]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[465]                                "the \"ssl\" parameter requires "
[466]                                "ngx_mail_ssl_module");
[467]             return NGX_CONF_ERROR;
[468] #endif
[469]         }
[470] 
[471]         if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {
[472] 
[473]             if (ngx_strcmp(&value[i].data[13], "on") == 0) {
[474]                 ls->so_keepalive = 1;
[475] 
[476]             } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
[477]                 ls->so_keepalive = 2;
[478] 
[479]             } else {
[480] 
[481] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[482]                 u_char     *p, *end;
[483]                 ngx_str_t   s;
[484] 
[485]                 end = value[i].data + value[i].len;
[486]                 s.data = value[i].data + 13;
[487] 
[488]                 p = ngx_strlchr(s.data, end, ':');
[489]                 if (p == NULL) {
[490]                     p = end;
[491]                 }
[492] 
[493]                 if (p > s.data) {
[494]                     s.len = p - s.data;
[495] 
[496]                     ls->tcp_keepidle = ngx_parse_time(&s, 1);
[497]                     if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
[498]                         goto invalid_so_keepalive;
[499]                     }
[500]                 }
[501] 
[502]                 s.data = (p < end) ? (p + 1) : end;
[503] 
[504]                 p = ngx_strlchr(s.data, end, ':');
[505]                 if (p == NULL) {
[506]                     p = end;
[507]                 }
[508] 
[509]                 if (p > s.data) {
[510]                     s.len = p - s.data;
[511] 
[512]                     ls->tcp_keepintvl = ngx_parse_time(&s, 1);
[513]                     if (ls->tcp_keepintvl == (time_t) NGX_ERROR) {
[514]                         goto invalid_so_keepalive;
[515]                     }
[516]                 }
[517] 
[518]                 s.data = (p < end) ? (p + 1) : end;
[519] 
[520]                 if (s.data < end) {
[521]                     s.len = end - s.data;
[522] 
[523]                     ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
[524]                     if (ls->tcp_keepcnt == NGX_ERROR) {
[525]                         goto invalid_so_keepalive;
[526]                     }
[527]                 }
[528] 
[529]                 if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
[530]                     && ls->tcp_keepcnt == 0)
[531]                 {
[532]                     goto invalid_so_keepalive;
[533]                 }
[534] 
[535]                 ls->so_keepalive = 1;
[536] 
[537] #else
[538] 
[539]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[540]                                    "the \"so_keepalive\" parameter accepts "
[541]                                    "only \"on\" or \"off\" on this platform");
[542]                 return NGX_CONF_ERROR;
[543] 
[544] #endif
[545]             }
[546] 
[547]             ls->bind = 1;
[548] 
[549]             continue;
[550] 
[551] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[552]         invalid_so_keepalive:
[553] 
[554]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[555]                                "invalid so_keepalive value: \"%s\"",
[556]                                &value[i].data[13]);
[557]             return NGX_CONF_ERROR;
[558] #endif
[559]         }
[560] 
[561]         if (ngx_strcmp(value[i].data, "proxy_protocol") == 0) {
[562]             ls->proxy_protocol = 1;
[563]             continue;
[564]         }
[565] 
[566]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[567]                            "the invalid \"%V\" parameter", &value[i]);
[568]         return NGX_CONF_ERROR;
[569]     }
[570] 
[571]     for (n = 0; n < u.naddrs; n++) {
[572] 
[573]         for (i = 0; i < n; i++) {
[574]             if (ngx_cmp_sockaddr(u.addrs[n].sockaddr, u.addrs[n].socklen,
[575]                                  u.addrs[i].sockaddr, u.addrs[i].socklen, 1)
[576]                 == NGX_OK)
[577]             {
[578]                 goto next;
[579]             }
[580]         }
[581] 
[582]         if (n != 0) {
[583]             nls = ngx_array_push(&cmcf->listen);
[584]             if (nls == NULL) {
[585]                 return NGX_CONF_ERROR;
[586]             }
[587] 
[588]             *nls = *ls;
[589] 
[590]         } else {
[591]             nls = ls;
[592]         }
[593] 
[594]         nls->sockaddr = u.addrs[n].sockaddr;
[595]         nls->socklen = u.addrs[n].socklen;
[596]         nls->addr_text = u.addrs[n].name;
[597]         nls->wildcard = ngx_inet_wildcard(nls->sockaddr);
[598] 
[599]         als = cmcf->listen.elts;
[600] 
[601]         for (i = 0; i < cmcf->listen.nelts - 1; i++) {
[602] 
[603]             if (ngx_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
[604]                                  nls->sockaddr, nls->socklen, 1)
[605]                 != NGX_OK)
[606]             {
[607]                 continue;
[608]             }
[609] 
[610]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[611]                                "duplicate \"%V\" address and port pair",
[612]                                &nls->addr_text);
[613]             return NGX_CONF_ERROR;
[614]         }
[615] 
[616]     next:
[617]         continue;
[618]     }
[619] 
[620]     return NGX_CONF_OK;
[621] }
[622] 
[623] 
[624] static char *
[625] ngx_mail_core_protocol(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[626] {
[627]     ngx_mail_core_srv_conf_t  *cscf = conf;
[628] 
[629]     ngx_str_t          *value;
[630]     ngx_uint_t          m;
[631]     ngx_mail_module_t  *module;
[632] 
[633]     value = cf->args->elts;
[634] 
[635]     for (m = 0; cf->cycle->modules[m]; m++) {
[636]         if (cf->cycle->modules[m]->type != NGX_MAIL_MODULE) {
[637]             continue;
[638]         }
[639] 
[640]         module = cf->cycle->modules[m]->ctx;
[641] 
[642]         if (module->protocol
[643]             && ngx_strcmp(module->protocol->name.data, value[1].data) == 0)
[644]         {
[645]             cscf->protocol = module->protocol;
[646] 
[647]             return NGX_CONF_OK;
[648]         }
[649]     }
[650] 
[651]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[652]                        "unknown protocol \"%V\"", &value[1]);
[653]     return NGX_CONF_ERROR;
[654] }
[655] 
[656] 
[657] static char *
[658] ngx_mail_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[659] {
[660]     ngx_mail_core_srv_conf_t  *cscf = conf;
[661] 
[662]     return ngx_log_set_log(cf, &cscf->error_log);
[663] }
[664] 
[665] 
[666] static char *
[667] ngx_mail_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[668] {
[669]     ngx_mail_core_srv_conf_t  *cscf = conf;
[670] 
[671]     ngx_str_t  *value;
[672] 
[673]     value = cf->args->elts;
[674] 
[675]     if (cscf->resolver != NGX_CONF_UNSET_PTR) {
[676]         return "is duplicate";
[677]     }
[678] 
[679]     if (ngx_strcmp(value[1].data, "off") == 0) {
[680]         cscf->resolver = NULL;
[681]         return NGX_CONF_OK;
[682]     }
[683] 
[684]     cscf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
[685]     if (cscf->resolver == NULL) {
[686]         return NGX_CONF_ERROR;
[687]     }
[688] 
[689]     return NGX_CONF_OK;
[690] }
[691] 
[692] 
[693] char *
[694] ngx_mail_capabilities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[695] {
[696]     char  *p = conf;
[697] 
[698]     ngx_str_t    *c, *value;
[699]     ngx_uint_t    i;
[700]     ngx_array_t  *a;
[701] 
[702]     a = (ngx_array_t *) (p + cmd->offset);
[703] 
[704]     value = cf->args->elts;
[705] 
[706]     for (i = 1; i < cf->args->nelts; i++) {
[707]         c = ngx_array_push(a);
[708]         if (c == NULL) {
[709]             return NGX_CONF_ERROR;
[710]         }
[711] 
[712]         *c = value[i];
[713]     }
[714] 
[715]     return NGX_CONF_OK;
[716] }
