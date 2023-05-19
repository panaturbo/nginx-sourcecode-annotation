[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] #include <ngx_stream.h>
[12] 
[13] 
[14] static char *ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[15] static ngx_int_t ngx_stream_init_phases(ngx_conf_t *cf,
[16]     ngx_stream_core_main_conf_t *cmcf);
[17] static ngx_int_t ngx_stream_init_phase_handlers(ngx_conf_t *cf,
[18]     ngx_stream_core_main_conf_t *cmcf);
[19] static ngx_int_t ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
[20]     ngx_stream_listen_t *listen);
[21] static char *ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);
[22] static ngx_int_t ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
[23]     ngx_stream_conf_addr_t *addr);
[24] #if (NGX_HAVE_INET6)
[25] static ngx_int_t ngx_stream_add_addrs6(ngx_conf_t *cf,
[26]     ngx_stream_port_t *stport, ngx_stream_conf_addr_t *addr);
[27] #endif
[28] static ngx_int_t ngx_stream_cmp_conf_addrs(const void *one, const void *two);
[29] 
[30] 
[31] ngx_uint_t  ngx_stream_max_module;
[32] 
[33] 
[34] ngx_stream_filter_pt  ngx_stream_top_filter;
[35] 
[36] 
[37] static ngx_command_t  ngx_stream_commands[] = {
[38] 
[39]     { ngx_string("stream"),
[40]       NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[41]       ngx_stream_block,
[42]       0,
[43]       0,
[44]       NULL },
[45] 
[46]       ngx_null_command
[47] };
[48] 
[49] 
[50] static ngx_core_module_t  ngx_stream_module_ctx = {
[51]     ngx_string("stream"),
[52]     NULL,
[53]     NULL
[54] };
[55] 
[56] 
[57] ngx_module_t  ngx_stream_module = {
[58]     NGX_MODULE_V1,
[59]     &ngx_stream_module_ctx,                /* module context */
[60]     ngx_stream_commands,                   /* module directives */
[61]     NGX_CORE_MODULE,                       /* module type */
[62]     NULL,                                  /* init master */
[63]     NULL,                                  /* init module */
[64]     NULL,                                  /* init process */
[65]     NULL,                                  /* init thread */
[66]     NULL,                                  /* exit thread */
[67]     NULL,                                  /* exit process */
[68]     NULL,                                  /* exit master */
[69]     NGX_MODULE_V1_PADDING
[70] };
[71] 
[72] 
[73] static char *
[74] ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[75] {
[76]     char                          *rv;
[77]     ngx_uint_t                     i, m, mi, s;
[78]     ngx_conf_t                     pcf;
[79]     ngx_array_t                    ports;
[80]     ngx_stream_listen_t           *listen;
[81]     ngx_stream_module_t           *module;
[82]     ngx_stream_conf_ctx_t         *ctx;
[83]     ngx_stream_core_srv_conf_t   **cscfp;
[84]     ngx_stream_core_main_conf_t   *cmcf;
[85] 
[86]     if (*(ngx_stream_conf_ctx_t **) conf) {
[87]         return "is duplicate";
[88]     }
[89] 
[90]     /* the main stream context */
[91] 
[92]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
[93]     if (ctx == NULL) {
[94]         return NGX_CONF_ERROR;
[95]     }
[96] 
[97]     *(ngx_stream_conf_ctx_t **) conf = ctx;
[98] 
[99]     /* count the number of the stream modules and set up their indices */
[100] 
[101]     ngx_stream_max_module = ngx_count_modules(cf->cycle, NGX_STREAM_MODULE);
[102] 
[103] 
[104]     /* the stream main_conf context, it's the same in the all stream contexts */
[105] 
[106]     ctx->main_conf = ngx_pcalloc(cf->pool,
[107]                                  sizeof(void *) * ngx_stream_max_module);
[108]     if (ctx->main_conf == NULL) {
[109]         return NGX_CONF_ERROR;
[110]     }
[111] 
[112] 
[113]     /*
[114]      * the stream null srv_conf context, it is used to merge
[115]      * the server{}s' srv_conf's
[116]      */
[117] 
[118]     ctx->srv_conf = ngx_pcalloc(cf->pool,
[119]                                 sizeof(void *) * ngx_stream_max_module);
[120]     if (ctx->srv_conf == NULL) {
[121]         return NGX_CONF_ERROR;
[122]     }
[123] 
[124] 
[125]     /*
[126]      * create the main_conf's and the null srv_conf's of the all stream modules
[127]      */
[128] 
[129]     for (m = 0; cf->cycle->modules[m]; m++) {
[130]         if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
[131]             continue;
[132]         }
[133] 
[134]         module = cf->cycle->modules[m]->ctx;
[135]         mi = cf->cycle->modules[m]->ctx_index;
[136] 
[137]         if (module->create_main_conf) {
[138]             ctx->main_conf[mi] = module->create_main_conf(cf);
[139]             if (ctx->main_conf[mi] == NULL) {
[140]                 return NGX_CONF_ERROR;
[141]             }
[142]         }
[143] 
[144]         if (module->create_srv_conf) {
[145]             ctx->srv_conf[mi] = module->create_srv_conf(cf);
[146]             if (ctx->srv_conf[mi] == NULL) {
[147]                 return NGX_CONF_ERROR;
[148]             }
[149]         }
[150]     }
[151] 
[152] 
[153]     pcf = *cf;
[154]     cf->ctx = ctx;
[155] 
[156]     for (m = 0; cf->cycle->modules[m]; m++) {
[157]         if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
[158]             continue;
[159]         }
[160] 
[161]         module = cf->cycle->modules[m]->ctx;
[162] 
[163]         if (module->preconfiguration) {
[164]             if (module->preconfiguration(cf) != NGX_OK) {
[165]                 return NGX_CONF_ERROR;
[166]             }
[167]         }
[168]     }
[169] 
[170] 
[171]     /* parse inside the stream{} block */
[172] 
[173]     cf->module_type = NGX_STREAM_MODULE;
[174]     cf->cmd_type = NGX_STREAM_MAIN_CONF;
[175]     rv = ngx_conf_parse(cf, NULL);
[176] 
[177]     if (rv != NGX_CONF_OK) {
[178]         *cf = pcf;
[179]         return rv;
[180]     }
[181] 
[182] 
[183]     /* init stream{} main_conf's, merge the server{}s' srv_conf's */
[184] 
[185]     cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];
[186]     cscfp = cmcf->servers.elts;
[187] 
[188]     for (m = 0; cf->cycle->modules[m]; m++) {
[189]         if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
[190]             continue;
[191]         }
[192] 
[193]         module = cf->cycle->modules[m]->ctx;
[194]         mi = cf->cycle->modules[m]->ctx_index;
[195] 
[196]         /* init stream{} main_conf's */
[197] 
[198]         cf->ctx = ctx;
[199] 
[200]         if (module->init_main_conf) {
[201]             rv = module->init_main_conf(cf, ctx->main_conf[mi]);
[202]             if (rv != NGX_CONF_OK) {
[203]                 *cf = pcf;
[204]                 return rv;
[205]             }
[206]         }
[207] 
[208]         for (s = 0; s < cmcf->servers.nelts; s++) {
[209] 
[210]             /* merge the server{}s' srv_conf's */
[211] 
[212]             cf->ctx = cscfp[s]->ctx;
[213] 
[214]             if (module->merge_srv_conf) {
[215]                 rv = module->merge_srv_conf(cf,
[216]                                             ctx->srv_conf[mi],
[217]                                             cscfp[s]->ctx->srv_conf[mi]);
[218]                 if (rv != NGX_CONF_OK) {
[219]                     *cf = pcf;
[220]                     return rv;
[221]                 }
[222]             }
[223]         }
[224]     }
[225] 
[226]     if (ngx_stream_init_phases(cf, cmcf) != NGX_OK) {
[227]         return NGX_CONF_ERROR;
[228]     }
[229] 
[230]     for (m = 0; cf->cycle->modules[m]; m++) {
[231]         if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
[232]             continue;
[233]         }
[234] 
[235]         module = cf->cycle->modules[m]->ctx;
[236] 
[237]         if (module->postconfiguration) {
[238]             if (module->postconfiguration(cf) != NGX_OK) {
[239]                 return NGX_CONF_ERROR;
[240]             }
[241]         }
[242]     }
[243] 
[244]     if (ngx_stream_variables_init_vars(cf) != NGX_OK) {
[245]         return NGX_CONF_ERROR;
[246]     }
[247] 
[248]     *cf = pcf;
[249] 
[250]     if (ngx_stream_init_phase_handlers(cf, cmcf) != NGX_OK) {
[251]         return NGX_CONF_ERROR;
[252]     }
[253] 
[254]     if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_stream_conf_port_t))
[255]         != NGX_OK)
[256]     {
[257]         return NGX_CONF_ERROR;
[258]     }
[259] 
[260]     listen = cmcf->listen.elts;
[261] 
[262]     for (i = 0; i < cmcf->listen.nelts; i++) {
[263]         if (ngx_stream_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
[264]             return NGX_CONF_ERROR;
[265]         }
[266]     }
[267] 
[268]     return ngx_stream_optimize_servers(cf, &ports);
[269] }
[270] 
[271] 
[272] static ngx_int_t
[273] ngx_stream_init_phases(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf)
[274] {
[275]     if (ngx_array_init(&cmcf->phases[NGX_STREAM_POST_ACCEPT_PHASE].handlers,
[276]                        cf->pool, 1, sizeof(ngx_stream_handler_pt))
[277]         != NGX_OK)
[278]     {
[279]         return NGX_ERROR;
[280]     }
[281] 
[282]     if (ngx_array_init(&cmcf->phases[NGX_STREAM_PREACCESS_PHASE].handlers,
[283]                        cf->pool, 1, sizeof(ngx_stream_handler_pt))
[284]         != NGX_OK)
[285]     {
[286]         return NGX_ERROR;
[287]     }
[288] 
[289]     if (ngx_array_init(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers,
[290]                        cf->pool, 1, sizeof(ngx_stream_handler_pt))
[291]         != NGX_OK)
[292]     {
[293]         return NGX_ERROR;
[294]     }
[295] 
[296]     if (ngx_array_init(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers,
[297]                        cf->pool, 1, sizeof(ngx_stream_handler_pt))
[298]         != NGX_OK)
[299]     {
[300]         return NGX_ERROR;
[301]     }
[302] 
[303]     if (ngx_array_init(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers,
[304]                        cf->pool, 1, sizeof(ngx_stream_handler_pt))
[305]         != NGX_OK)
[306]     {
[307]         return NGX_ERROR;
[308]     }
[309] 
[310]     if (ngx_array_init(&cmcf->phases[NGX_STREAM_LOG_PHASE].handlers,
[311]                        cf->pool, 1, sizeof(ngx_stream_handler_pt))
[312]         != NGX_OK)
[313]     {
[314]         return NGX_ERROR;
[315]     }
[316] 
[317]     return NGX_OK;
[318] }
[319] 
[320] 
[321] static ngx_int_t
[322] ngx_stream_init_phase_handlers(ngx_conf_t *cf,
[323]     ngx_stream_core_main_conf_t *cmcf)
[324] {
[325]     ngx_int_t                     j;
[326]     ngx_uint_t                    i, n;
[327]     ngx_stream_handler_pt        *h;
[328]     ngx_stream_phase_handler_t   *ph;
[329]     ngx_stream_phase_handler_pt   checker;
[330] 
[331]     n = 1 /* content phase */;
[332] 
[333]     for (i = 0; i < NGX_STREAM_LOG_PHASE; i++) {
[334]         n += cmcf->phases[i].handlers.nelts;
[335]     }
[336] 
[337]     ph = ngx_pcalloc(cf->pool,
[338]                      n * sizeof(ngx_stream_phase_handler_t) + sizeof(void *));
[339]     if (ph == NULL) {
[340]         return NGX_ERROR;
[341]     }
[342] 
[343]     cmcf->phase_engine.handlers = ph;
[344]     n = 0;
[345] 
[346]     for (i = 0; i < NGX_STREAM_LOG_PHASE; i++) {
[347]         h = cmcf->phases[i].handlers.elts;
[348] 
[349]         switch (i) {
[350] 
[351]         case NGX_STREAM_PREREAD_PHASE:
[352]             checker = ngx_stream_core_preread_phase;
[353]             break;
[354] 
[355]         case NGX_STREAM_CONTENT_PHASE:
[356]             ph->checker = ngx_stream_core_content_phase;
[357]             n++;
[358]             ph++;
[359] 
[360]             continue;
[361] 
[362]         default:
[363]             checker = ngx_stream_core_generic_phase;
[364]         }
[365] 
[366]         n += cmcf->phases[i].handlers.nelts;
[367] 
[368]         for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
[369]             ph->checker = checker;
[370]             ph->handler = h[j];
[371]             ph->next = n;
[372]             ph++;
[373]         }
[374]     }
[375] 
[376]     return NGX_OK;
[377] }
[378] 
[379] 
[380] static ngx_int_t
[381] ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
[382]     ngx_stream_listen_t *listen)
[383] {
[384]     in_port_t                p;
[385]     ngx_uint_t               i;
[386]     struct sockaddr         *sa;
[387]     ngx_stream_conf_port_t  *port;
[388]     ngx_stream_conf_addr_t  *addr;
[389] 
[390]     sa = listen->sockaddr;
[391]     p = ngx_inet_get_port(sa);
[392] 
[393]     port = ports->elts;
[394]     for (i = 0; i < ports->nelts; i++) {
[395] 
[396]         if (p == port[i].port
[397]             && listen->type == port[i].type
[398]             && sa->sa_family == port[i].family)
[399]         {
[400]             /* a port is already in the port list */
[401] 
[402]             port = &port[i];
[403]             goto found;
[404]         }
[405]     }
[406] 
[407]     /* add a port to the port list */
[408] 
[409]     port = ngx_array_push(ports);
[410]     if (port == NULL) {
[411]         return NGX_ERROR;
[412]     }
[413] 
[414]     port->family = sa->sa_family;
[415]     port->type = listen->type;
[416]     port->port = p;
[417] 
[418]     if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
[419]                        sizeof(ngx_stream_conf_addr_t))
[420]         != NGX_OK)
[421]     {
[422]         return NGX_ERROR;
[423]     }
[424] 
[425] found:
[426] 
[427]     addr = ngx_array_push(&port->addrs);
[428]     if (addr == NULL) {
[429]         return NGX_ERROR;
[430]     }
[431] 
[432]     addr->opt = *listen;
[433] 
[434]     return NGX_OK;
[435] }
[436] 
[437] 
[438] static char *
[439] ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
[440] {
[441]     ngx_uint_t                   i, p, last, bind_wildcard;
[442]     ngx_listening_t             *ls;
[443]     ngx_stream_port_t           *stport;
[444]     ngx_stream_conf_port_t      *port;
[445]     ngx_stream_conf_addr_t      *addr;
[446]     ngx_stream_core_srv_conf_t  *cscf;
[447] 
[448]     port = ports->elts;
[449]     for (p = 0; p < ports->nelts; p++) {
[450] 
[451]         ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
[452]                  sizeof(ngx_stream_conf_addr_t), ngx_stream_cmp_conf_addrs);
[453] 
[454]         addr = port[p].addrs.elts;
[455]         last = port[p].addrs.nelts;
[456] 
[457]         /*
[458]          * if there is the binding to the "*:port" then we need to bind()
[459]          * to the "*:port" only and ignore the other bindings
[460]          */
[461] 
[462]         if (addr[last - 1].opt.wildcard) {
[463]             addr[last - 1].opt.bind = 1;
[464]             bind_wildcard = 1;
[465] 
[466]         } else {
[467]             bind_wildcard = 0;
[468]         }
[469] 
[470]         i = 0;
[471] 
[472]         while (i < last) {
[473] 
[474]             if (bind_wildcard && !addr[i].opt.bind) {
[475]                 i++;
[476]                 continue;
[477]             }
[478] 
[479]             ls = ngx_create_listening(cf, addr[i].opt.sockaddr,
[480]                                       addr[i].opt.socklen);
[481]             if (ls == NULL) {
[482]                 return NGX_CONF_ERROR;
[483]             }
[484] 
[485]             ls->addr_ntop = 1;
[486]             ls->handler = ngx_stream_init_connection;
[487]             ls->pool_size = 256;
[488]             ls->type = addr[i].opt.type;
[489] 
[490]             cscf = addr->opt.ctx->srv_conf[ngx_stream_core_module.ctx_index];
[491] 
[492]             ls->logp = cscf->error_log;
[493]             ls->log.data = &ls->addr_text;
[494]             ls->log.handler = ngx_accept_log_error;
[495] 
[496]             ls->backlog = addr[i].opt.backlog;
[497]             ls->rcvbuf = addr[i].opt.rcvbuf;
[498]             ls->sndbuf = addr[i].opt.sndbuf;
[499] 
[500]             ls->wildcard = addr[i].opt.wildcard;
[501] 
[502]             ls->keepalive = addr[i].opt.so_keepalive;
[503] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[504]             ls->keepidle = addr[i].opt.tcp_keepidle;
[505]             ls->keepintvl = addr[i].opt.tcp_keepintvl;
[506]             ls->keepcnt = addr[i].opt.tcp_keepcnt;
[507] #endif
[508] 
[509] #if (NGX_HAVE_INET6)
[510]             ls->ipv6only = addr[i].opt.ipv6only;
[511] #endif
[512] 
[513] #if (NGX_HAVE_TCP_FASTOPEN)
[514]             ls->fastopen = addr[i].opt.fastopen;
[515] #endif
[516] 
[517] #if (NGX_HAVE_REUSEPORT)
[518]             ls->reuseport = addr[i].opt.reuseport;
[519] #endif
[520] 
[521]             stport = ngx_palloc(cf->pool, sizeof(ngx_stream_port_t));
[522]             if (stport == NULL) {
[523]                 return NGX_CONF_ERROR;
[524]             }
[525] 
[526]             ls->servers = stport;
[527] 
[528]             stport->naddrs = i + 1;
[529] 
[530]             switch (ls->sockaddr->sa_family) {
[531] #if (NGX_HAVE_INET6)
[532]             case AF_INET6:
[533]                 if (ngx_stream_add_addrs6(cf, stport, addr) != NGX_OK) {
[534]                     return NGX_CONF_ERROR;
[535]                 }
[536]                 break;
[537] #endif
[538]             default: /* AF_INET */
[539]                 if (ngx_stream_add_addrs(cf, stport, addr) != NGX_OK) {
[540]                     return NGX_CONF_ERROR;
[541]                 }
[542]                 break;
[543]             }
[544] 
[545]             addr++;
[546]             last--;
[547]         }
[548]     }
[549] 
[550]     return NGX_CONF_OK;
[551] }
[552] 
[553] 
[554] static ngx_int_t
[555] ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
[556]     ngx_stream_conf_addr_t *addr)
[557] {
[558]     ngx_uint_t             i;
[559]     struct sockaddr_in    *sin;
[560]     ngx_stream_in_addr_t  *addrs;
[561] 
[562]     stport->addrs = ngx_pcalloc(cf->pool,
[563]                                 stport->naddrs * sizeof(ngx_stream_in_addr_t));
[564]     if (stport->addrs == NULL) {
[565]         return NGX_ERROR;
[566]     }
[567] 
[568]     addrs = stport->addrs;
[569] 
[570]     for (i = 0; i < stport->naddrs; i++) {
[571] 
[572]         sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
[573]         addrs[i].addr = sin->sin_addr.s_addr;
[574] 
[575]         addrs[i].conf.ctx = addr[i].opt.ctx;
[576] #if (NGX_STREAM_SSL)
[577]         addrs[i].conf.ssl = addr[i].opt.ssl;
[578] #endif
[579]         addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
[580]         addrs[i].conf.addr_text = addr[i].opt.addr_text;
[581]     }
[582] 
[583]     return NGX_OK;
[584] }
[585] 
[586] 
[587] #if (NGX_HAVE_INET6)
[588] 
[589] static ngx_int_t
[590] ngx_stream_add_addrs6(ngx_conf_t *cf, ngx_stream_port_t *stport,
[591]     ngx_stream_conf_addr_t *addr)
[592] {
[593]     ngx_uint_t              i;
[594]     struct sockaddr_in6    *sin6;
[595]     ngx_stream_in6_addr_t  *addrs6;
[596] 
[597]     stport->addrs = ngx_pcalloc(cf->pool,
[598]                                 stport->naddrs * sizeof(ngx_stream_in6_addr_t));
[599]     if (stport->addrs == NULL) {
[600]         return NGX_ERROR;
[601]     }
[602] 
[603]     addrs6 = stport->addrs;
[604] 
[605]     for (i = 0; i < stport->naddrs; i++) {
[606] 
[607]         sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
[608]         addrs6[i].addr6 = sin6->sin6_addr;
[609] 
[610]         addrs6[i].conf.ctx = addr[i].opt.ctx;
[611] #if (NGX_STREAM_SSL)
[612]         addrs6[i].conf.ssl = addr[i].opt.ssl;
[613] #endif
[614]         addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
[615]         addrs6[i].conf.addr_text = addr[i].opt.addr_text;
[616]     }
[617] 
[618]     return NGX_OK;
[619] }
[620] 
[621] #endif
[622] 
[623] 
[624] static ngx_int_t
[625] ngx_stream_cmp_conf_addrs(const void *one, const void *two)
[626] {
[627]     ngx_stream_conf_addr_t  *first, *second;
[628] 
[629]     first = (ngx_stream_conf_addr_t *) one;
[630]     second = (ngx_stream_conf_addr_t *) two;
[631] 
[632]     if (first->opt.wildcard) {
[633]         /* a wildcard must be the last resort, shift it to the end */
[634]         return 1;
[635]     }
[636] 
[637]     if (second->opt.wildcard) {
[638]         /* a wildcard must be the last resort, shift it to the end */
[639]         return -1;
[640]     }
[641] 
[642]     if (first->opt.bind && !second->opt.bind) {
[643]         /* shift explicit bind()ed addresses to the start */
[644]         return -1;
[645]     }
[646] 
[647]     if (!first->opt.bind && second->opt.bind) {
[648]         /* shift explicit bind()ed addresses to the start */
[649]         return 1;
[650]     }
[651] 
[652]     /* do not sort by default */
[653] 
[654]     return 0;
[655] }
