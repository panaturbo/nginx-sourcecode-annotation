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
[14] static char *ngx_mail_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[15] static ngx_int_t ngx_mail_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
[16]     ngx_mail_listen_t *listen);
[17] static char *ngx_mail_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
[18] static ngx_int_t ngx_mail_add_addrs(ngx_conf_t *cf, ngx_mail_port_t *mport,
[19]     ngx_mail_conf_addr_t *addr);
[20] #if (NGX_HAVE_INET6)
[21] static ngx_int_t ngx_mail_add_addrs6(ngx_conf_t *cf, ngx_mail_port_t *mport,
[22]     ngx_mail_conf_addr_t *addr);
[23] #endif
[24] static ngx_int_t ngx_mail_cmp_conf_addrs(const void *one, const void *two);
[25] 
[26] 
[27] ngx_uint_t  ngx_mail_max_module;
[28] 
[29] 
[30] static ngx_command_t  ngx_mail_commands[] = {
[31] 
[32]     { ngx_string("mail"),
[33]       NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[34]       ngx_mail_block,
[35]       0,
[36]       0,
[37]       NULL },
[38] 
[39]       ngx_null_command
[40] };
[41] 
[42] 
[43] static ngx_core_module_t  ngx_mail_module_ctx = {
[44]     ngx_string("mail"),
[45]     NULL,
[46]     NULL
[47] };
[48] 
[49] 
[50] ngx_module_t  ngx_mail_module = {
[51]     NGX_MODULE_V1,
[52]     &ngx_mail_module_ctx,                  /* module context */
[53]     ngx_mail_commands,                     /* module directives */
[54]     NGX_CORE_MODULE,                       /* module type */
[55]     NULL,                                  /* init master */
[56]     NULL,                                  /* init module */
[57]     NULL,                                  /* init process */
[58]     NULL,                                  /* init thread */
[59]     NULL,                                  /* exit thread */
[60]     NULL,                                  /* exit process */
[61]     NULL,                                  /* exit master */
[62]     NGX_MODULE_V1_PADDING
[63] };
[64] 
[65] 
[66] static char *
[67] ngx_mail_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[68] {
[69]     char                        *rv;
[70]     ngx_uint_t                   i, m, mi, s;
[71]     ngx_conf_t                   pcf;
[72]     ngx_array_t                  ports;
[73]     ngx_mail_listen_t           *listen;
[74]     ngx_mail_module_t           *module;
[75]     ngx_mail_conf_ctx_t         *ctx;
[76]     ngx_mail_core_srv_conf_t   **cscfp;
[77]     ngx_mail_core_main_conf_t   *cmcf;
[78] 
[79]     if (*(ngx_mail_conf_ctx_t **) conf) {
[80]         return "is duplicate";
[81]     }
[82] 
[83]     /* the main mail context */
[84] 
[85]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_mail_conf_ctx_t));
[86]     if (ctx == NULL) {
[87]         return NGX_CONF_ERROR;
[88]     }
[89] 
[90]     *(ngx_mail_conf_ctx_t **) conf = ctx;
[91] 
[92]     /* count the number of the mail modules and set up their indices */
[93] 
[94]     ngx_mail_max_module = ngx_count_modules(cf->cycle, NGX_MAIL_MODULE);
[95] 
[96] 
[97]     /* the mail main_conf context, it is the same in the all mail contexts */
[98] 
[99]     ctx->main_conf = ngx_pcalloc(cf->pool,
[100]                                  sizeof(void *) * ngx_mail_max_module);
[101]     if (ctx->main_conf == NULL) {
[102]         return NGX_CONF_ERROR;
[103]     }
[104] 
[105] 
[106]     /*
[107]      * the mail null srv_conf context, it is used to merge
[108]      * the server{}s' srv_conf's
[109]      */
[110] 
[111]     ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_mail_max_module);
[112]     if (ctx->srv_conf == NULL) {
[113]         return NGX_CONF_ERROR;
[114]     }
[115] 
[116] 
[117]     /*
[118]      * create the main_conf's and the null srv_conf's of the all mail modules
[119]      */
[120] 
[121]     for (m = 0; cf->cycle->modules[m]; m++) {
[122]         if (cf->cycle->modules[m]->type != NGX_MAIL_MODULE) {
[123]             continue;
[124]         }
[125] 
[126]         module = cf->cycle->modules[m]->ctx;
[127]         mi = cf->cycle->modules[m]->ctx_index;
[128] 
[129]         if (module->create_main_conf) {
[130]             ctx->main_conf[mi] = module->create_main_conf(cf);
[131]             if (ctx->main_conf[mi] == NULL) {
[132]                 return NGX_CONF_ERROR;
[133]             }
[134]         }
[135] 
[136]         if (module->create_srv_conf) {
[137]             ctx->srv_conf[mi] = module->create_srv_conf(cf);
[138]             if (ctx->srv_conf[mi] == NULL) {
[139]                 return NGX_CONF_ERROR;
[140]             }
[141]         }
[142]     }
[143] 
[144] 
[145]     /* parse inside the mail{} block */
[146] 
[147]     pcf = *cf;
[148]     cf->ctx = ctx;
[149] 
[150]     cf->module_type = NGX_MAIL_MODULE;
[151]     cf->cmd_type = NGX_MAIL_MAIN_CONF;
[152]     rv = ngx_conf_parse(cf, NULL);
[153] 
[154]     if (rv != NGX_CONF_OK) {
[155]         *cf = pcf;
[156]         return rv;
[157]     }
[158] 
[159] 
[160]     /* init mail{} main_conf's, merge the server{}s' srv_conf's */
[161] 
[162]     cmcf = ctx->main_conf[ngx_mail_core_module.ctx_index];
[163]     cscfp = cmcf->servers.elts;
[164] 
[165]     for (m = 0; cf->cycle->modules[m]; m++) {
[166]         if (cf->cycle->modules[m]->type != NGX_MAIL_MODULE) {
[167]             continue;
[168]         }
[169] 
[170]         module = cf->cycle->modules[m]->ctx;
[171]         mi = cf->cycle->modules[m]->ctx_index;
[172] 
[173]         /* init mail{} main_conf's */
[174] 
[175]         cf->ctx = ctx;
[176] 
[177]         if (module->init_main_conf) {
[178]             rv = module->init_main_conf(cf, ctx->main_conf[mi]);
[179]             if (rv != NGX_CONF_OK) {
[180]                 *cf = pcf;
[181]                 return rv;
[182]             }
[183]         }
[184] 
[185]         for (s = 0; s < cmcf->servers.nelts; s++) {
[186] 
[187]             /* merge the server{}s' srv_conf's */
[188] 
[189]             cf->ctx = cscfp[s]->ctx;
[190] 
[191]             if (module->merge_srv_conf) {
[192]                 rv = module->merge_srv_conf(cf,
[193]                                             ctx->srv_conf[mi],
[194]                                             cscfp[s]->ctx->srv_conf[mi]);
[195]                 if (rv != NGX_CONF_OK) {
[196]                     *cf = pcf;
[197]                     return rv;
[198]                 }
[199]             }
[200]         }
[201]     }
[202] 
[203]     *cf = pcf;
[204] 
[205] 
[206]     if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_mail_conf_port_t))
[207]         != NGX_OK)
[208]     {
[209]         return NGX_CONF_ERROR;
[210]     }
[211] 
[212]     listen = cmcf->listen.elts;
[213] 
[214]     for (i = 0; i < cmcf->listen.nelts; i++) {
[215]         if (ngx_mail_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
[216]             return NGX_CONF_ERROR;
[217]         }
[218]     }
[219] 
[220]     return ngx_mail_optimize_servers(cf, &ports);
[221] }
[222] 
[223] 
[224] static ngx_int_t
[225] ngx_mail_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
[226]     ngx_mail_listen_t *listen)
[227] {
[228]     in_port_t              p;
[229]     ngx_uint_t             i;
[230]     struct sockaddr       *sa;
[231]     ngx_mail_conf_port_t  *port;
[232]     ngx_mail_conf_addr_t  *addr;
[233] 
[234]     sa = listen->sockaddr;
[235]     p = ngx_inet_get_port(sa);
[236] 
[237]     port = ports->elts;
[238]     for (i = 0; i < ports->nelts; i++) {
[239]         if (p == port[i].port && sa->sa_family == port[i].family) {
[240] 
[241]             /* a port is already in the port list */
[242] 
[243]             port = &port[i];
[244]             goto found;
[245]         }
[246]     }
[247] 
[248]     /* add a port to the port list */
[249] 
[250]     port = ngx_array_push(ports);
[251]     if (port == NULL) {
[252]         return NGX_ERROR;
[253]     }
[254] 
[255]     port->family = sa->sa_family;
[256]     port->port = p;
[257] 
[258]     if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
[259]                        sizeof(ngx_mail_conf_addr_t))
[260]         != NGX_OK)
[261]     {
[262]         return NGX_ERROR;
[263]     }
[264] 
[265] found:
[266] 
[267]     addr = ngx_array_push(&port->addrs);
[268]     if (addr == NULL) {
[269]         return NGX_ERROR;
[270]     }
[271] 
[272]     addr->opt = *listen;
[273] 
[274]     return NGX_OK;
[275] }
[276] 
[277] 
[278] static char *
[279] ngx_mail_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
[280] {
[281]     ngx_uint_t                 i, p, last, bind_wildcard;
[282]     ngx_listening_t           *ls;
[283]     ngx_mail_port_t           *mport;
[284]     ngx_mail_conf_port_t      *port;
[285]     ngx_mail_conf_addr_t      *addr;
[286]     ngx_mail_core_srv_conf_t  *cscf;
[287] 
[288]     port = ports->elts;
[289]     for (p = 0; p < ports->nelts; p++) {
[290] 
[291]         ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
[292]                  sizeof(ngx_mail_conf_addr_t), ngx_mail_cmp_conf_addrs);
[293] 
[294]         addr = port[p].addrs.elts;
[295]         last = port[p].addrs.nelts;
[296] 
[297]         /*
[298]          * if there is the binding to the "*:port" then we need to bind()
[299]          * to the "*:port" only and ignore the other bindings
[300]          */
[301] 
[302]         if (addr[last - 1].opt.wildcard) {
[303]             addr[last - 1].opt.bind = 1;
[304]             bind_wildcard = 1;
[305] 
[306]         } else {
[307]             bind_wildcard = 0;
[308]         }
[309] 
[310]         i = 0;
[311] 
[312]         while (i < last) {
[313] 
[314]             if (bind_wildcard && !addr[i].opt.bind) {
[315]                 i++;
[316]                 continue;
[317]             }
[318] 
[319]             ls = ngx_create_listening(cf, addr[i].opt.sockaddr,
[320]                                       addr[i].opt.socklen);
[321]             if (ls == NULL) {
[322]                 return NGX_CONF_ERROR;
[323]             }
[324] 
[325]             ls->addr_ntop = 1;
[326]             ls->handler = ngx_mail_init_connection;
[327]             ls->pool_size = 256;
[328] 
[329]             cscf = addr->opt.ctx->srv_conf[ngx_mail_core_module.ctx_index];
[330] 
[331]             ls->logp = cscf->error_log;
[332]             ls->log.data = &ls->addr_text;
[333]             ls->log.handler = ngx_accept_log_error;
[334] 
[335]             ls->backlog = addr[i].opt.backlog;
[336]             ls->rcvbuf = addr[i].opt.rcvbuf;
[337]             ls->sndbuf = addr[i].opt.sndbuf;
[338] 
[339]             ls->keepalive = addr[i].opt.so_keepalive;
[340] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[341]             ls->keepidle = addr[i].opt.tcp_keepidle;
[342]             ls->keepintvl = addr[i].opt.tcp_keepintvl;
[343]             ls->keepcnt = addr[i].opt.tcp_keepcnt;
[344] #endif
[345] 
[346] #if (NGX_HAVE_INET6)
[347]             ls->ipv6only = addr[i].opt.ipv6only;
[348] #endif
[349] 
[350]             mport = ngx_palloc(cf->pool, sizeof(ngx_mail_port_t));
[351]             if (mport == NULL) {
[352]                 return NGX_CONF_ERROR;
[353]             }
[354] 
[355]             ls->servers = mport;
[356] 
[357]             mport->naddrs = i + 1;
[358] 
[359]             switch (ls->sockaddr->sa_family) {
[360] #if (NGX_HAVE_INET6)
[361]             case AF_INET6:
[362]                 if (ngx_mail_add_addrs6(cf, mport, addr) != NGX_OK) {
[363]                     return NGX_CONF_ERROR;
[364]                 }
[365]                 break;
[366] #endif
[367]             default: /* AF_INET */
[368]                 if (ngx_mail_add_addrs(cf, mport, addr) != NGX_OK) {
[369]                     return NGX_CONF_ERROR;
[370]                 }
[371]                 break;
[372]             }
[373] 
[374]             addr++;
[375]             last--;
[376]         }
[377]     }
[378] 
[379]     return NGX_CONF_OK;
[380] }
[381] 
[382] 
[383] static ngx_int_t
[384] ngx_mail_add_addrs(ngx_conf_t *cf, ngx_mail_port_t *mport,
[385]     ngx_mail_conf_addr_t *addr)
[386] {
[387]     ngx_uint_t           i;
[388]     ngx_mail_in_addr_t  *addrs;
[389]     struct sockaddr_in  *sin;
[390] 
[391]     mport->addrs = ngx_pcalloc(cf->pool,
[392]                                mport->naddrs * sizeof(ngx_mail_in_addr_t));
[393]     if (mport->addrs == NULL) {
[394]         return NGX_ERROR;
[395]     }
[396] 
[397]     addrs = mport->addrs;
[398] 
[399]     for (i = 0; i < mport->naddrs; i++) {
[400] 
[401]         sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
[402]         addrs[i].addr = sin->sin_addr.s_addr;
[403] 
[404]         addrs[i].conf.ctx = addr[i].opt.ctx;
[405] #if (NGX_MAIL_SSL)
[406]         addrs[i].conf.ssl = addr[i].opt.ssl;
[407] #endif
[408]         addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
[409]         addrs[i].conf.addr_text = addr[i].opt.addr_text;
[410]     }
[411] 
[412]     return NGX_OK;
[413] }
[414] 
[415] 
[416] #if (NGX_HAVE_INET6)
[417] 
[418] static ngx_int_t
[419] ngx_mail_add_addrs6(ngx_conf_t *cf, ngx_mail_port_t *mport,
[420]     ngx_mail_conf_addr_t *addr)
[421] {
[422]     ngx_uint_t            i;
[423]     ngx_mail_in6_addr_t  *addrs6;
[424]     struct sockaddr_in6  *sin6;
[425] 
[426]     mport->addrs = ngx_pcalloc(cf->pool,
[427]                                mport->naddrs * sizeof(ngx_mail_in6_addr_t));
[428]     if (mport->addrs == NULL) {
[429]         return NGX_ERROR;
[430]     }
[431] 
[432]     addrs6 = mport->addrs;
[433] 
[434]     for (i = 0; i < mport->naddrs; i++) {
[435] 
[436]         sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
[437]         addrs6[i].addr6 = sin6->sin6_addr;
[438] 
[439]         addrs6[i].conf.ctx = addr[i].opt.ctx;
[440] #if (NGX_MAIL_SSL)
[441]         addrs6[i].conf.ssl = addr[i].opt.ssl;
[442] #endif
[443]         addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
[444]         addrs6[i].conf.addr_text = addr[i].opt.addr_text;
[445]     }
[446] 
[447]     return NGX_OK;
[448] }
[449] 
[450] #endif
[451] 
[452] 
[453] static ngx_int_t
[454] ngx_mail_cmp_conf_addrs(const void *one, const void *two)
[455] {
[456]     ngx_mail_conf_addr_t  *first, *second;
[457] 
[458]     first = (ngx_mail_conf_addr_t *) one;
[459]     second = (ngx_mail_conf_addr_t *) two;
[460] 
[461]     if (first->opt.wildcard) {
[462]         /* a wildcard must be the last resort, shift it to the end */
[463]         return 1;
[464]     }
[465] 
[466]     if (second->opt.wildcard) {
[467]         /* a wildcard must be the last resort, shift it to the end */
[468]         return -1;
[469]     }
[470] 
[471]     if (first->opt.bind && !second->opt.bind) {
[472]         /* shift explicit bind()ed addresses to the start */
[473]         return -1;
[474]     }
[475] 
[476]     if (!first->opt.bind && second->opt.bind) {
[477]         /* shift explicit bind()ed addresses to the start */
[478]         return 1;
[479]     }
[480] 
[481]     /* do not sort by default */
[482] 
[483]     return 0;
[484] }
