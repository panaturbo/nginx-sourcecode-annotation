[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[14] static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
[15]     ngx_http_core_main_conf_t *cmcf);
[16] static ngx_int_t ngx_http_init_headers_in_hash(ngx_conf_t *cf,
[17]     ngx_http_core_main_conf_t *cmcf);
[18] static ngx_int_t ngx_http_init_phase_handlers(ngx_conf_t *cf,
[19]     ngx_http_core_main_conf_t *cmcf);
[20] 
[21] static ngx_int_t ngx_http_add_addresses(ngx_conf_t *cf,
[22]     ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
[23]     ngx_http_listen_opt_t *lsopt);
[24] static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
[25]     ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
[26]     ngx_http_listen_opt_t *lsopt);
[27] static ngx_int_t ngx_http_add_server(ngx_conf_t *cf,
[28]     ngx_http_core_srv_conf_t *cscf, ngx_http_conf_addr_t *addr);
[29] 
[30] static char *ngx_http_merge_servers(ngx_conf_t *cf,
[31]     ngx_http_core_main_conf_t *cmcf, ngx_http_module_t *module,
[32]     ngx_uint_t ctx_index);
[33] static char *ngx_http_merge_locations(ngx_conf_t *cf,
[34]     ngx_queue_t *locations, void **loc_conf, ngx_http_module_t *module,
[35]     ngx_uint_t ctx_index);
[36] static ngx_int_t ngx_http_init_locations(ngx_conf_t *cf,
[37]     ngx_http_core_srv_conf_t *cscf, ngx_http_core_loc_conf_t *pclcf);
[38] static ngx_int_t ngx_http_init_static_location_trees(ngx_conf_t *cf,
[39]     ngx_http_core_loc_conf_t *pclcf);
[40] static ngx_int_t ngx_http_escape_location_name(ngx_conf_t *cf,
[41]     ngx_http_core_loc_conf_t *clcf);
[42] static ngx_int_t ngx_http_cmp_locations(const ngx_queue_t *one,
[43]     const ngx_queue_t *two);
[44] static ngx_int_t ngx_http_join_exact_locations(ngx_conf_t *cf,
[45]     ngx_queue_t *locations);
[46] static void ngx_http_create_locations_list(ngx_queue_t *locations,
[47]     ngx_queue_t *q);
[48] static ngx_http_location_tree_node_t *
[49]     ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
[50]     size_t prefix);
[51] 
[52] static ngx_int_t ngx_http_optimize_servers(ngx_conf_t *cf,
[53]     ngx_http_core_main_conf_t *cmcf, ngx_array_t *ports);
[54] static ngx_int_t ngx_http_server_names(ngx_conf_t *cf,
[55]     ngx_http_core_main_conf_t *cmcf, ngx_http_conf_addr_t *addr);
[56] static ngx_int_t ngx_http_cmp_conf_addrs(const void *one, const void *two);
[57] static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
[58]     const void *two);
[59] 
[60] static ngx_int_t ngx_http_init_listening(ngx_conf_t *cf,
[61]     ngx_http_conf_port_t *port);
[62] static ngx_listening_t *ngx_http_add_listening(ngx_conf_t *cf,
[63]     ngx_http_conf_addr_t *addr);
[64] static ngx_int_t ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
[65]     ngx_http_conf_addr_t *addr);
[66] #if (NGX_HAVE_INET6)
[67] static ngx_int_t ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
[68]     ngx_http_conf_addr_t *addr);
[69] #endif
[70] 
[71] ngx_uint_t   ngx_http_max_module;
[72] 
[73] 
[74] ngx_http_output_header_filter_pt  ngx_http_top_header_filter;
[75] ngx_http_output_body_filter_pt    ngx_http_top_body_filter;
[76] ngx_http_request_body_filter_pt   ngx_http_top_request_body_filter;
[77] 
[78] 
[79] ngx_str_t  ngx_http_html_default_types[] = {
[80]     ngx_string("text/html"),
[81]     ngx_null_string
[82] };
[83] 
[84] 
[85] static ngx_command_t  ngx_http_commands[] = {
[86] 
[87]     { ngx_string("http"),
[88]       NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[89]       ngx_http_block,
[90]       0,
[91]       0,
[92]       NULL },
[93] 
[94]       ngx_null_command
[95] };
[96] 
[97] 
[98] static ngx_core_module_t  ngx_http_module_ctx = {
[99]     ngx_string("http"),
[100]     NULL,
[101]     NULL
[102] };
[103] 
[104] 
[105] ngx_module_t  ngx_http_module = {
[106]     NGX_MODULE_V1,
[107]     &ngx_http_module_ctx,                  /* module context */
[108]     ngx_http_commands,                     /* module directives */
[109]     NGX_CORE_MODULE,                       /* module type */
[110]     NULL,                                  /* init master */
[111]     NULL,                                  /* init module */
[112]     NULL,                                  /* init process */
[113]     NULL,                                  /* init thread */
[114]     NULL,                                  /* exit thread */
[115]     NULL,                                  /* exit process */
[116]     NULL,                                  /* exit master */
[117]     NGX_MODULE_V1_PADDING
[118] };
[119] 
[120] 
[121] static char *
[122] ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[123] {
[124]     char                        *rv;
[125]     ngx_uint_t                   mi, m, s;
[126]     ngx_conf_t                   pcf;
[127]     ngx_http_module_t           *module;
[128]     ngx_http_conf_ctx_t         *ctx;
[129]     ngx_http_core_loc_conf_t    *clcf;
[130]     ngx_http_core_srv_conf_t   **cscfp;
[131]     ngx_http_core_main_conf_t   *cmcf;
[132] 
[133]     if (*(ngx_http_conf_ctx_t **) conf) {
[134]         return "is duplicate";
[135]     }
[136] 
[137]     /* the main http context */
[138] 
[139]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
[140]     if (ctx == NULL) {
[141]         return NGX_CONF_ERROR;
[142]     }
[143] 
[144]     *(ngx_http_conf_ctx_t **) conf = ctx;
[145] 
[146] 
[147]     /* count the number of the http modules and set up their indices */
[148] 
[149]     ngx_http_max_module = ngx_count_modules(cf->cycle, NGX_HTTP_MODULE);
[150] 
[151] 
[152]     /* the http main_conf context, it is the same in the all http contexts */
[153] 
[154]     ctx->main_conf = ngx_pcalloc(cf->pool,
[155]                                  sizeof(void *) * ngx_http_max_module);
[156]     if (ctx->main_conf == NULL) {
[157]         return NGX_CONF_ERROR;
[158]     }
[159] 
[160] 
[161]     /*
[162]      * the http null srv_conf context, it is used to merge
[163]      * the server{}s' srv_conf's
[164]      */
[165] 
[166]     ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[167]     if (ctx->srv_conf == NULL) {
[168]         return NGX_CONF_ERROR;
[169]     }
[170] 
[171] 
[172]     /*
[173]      * the http null loc_conf context, it is used to merge
[174]      * the server{}s' loc_conf's
[175]      */
[176] 
[177]     ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[178]     if (ctx->loc_conf == NULL) {
[179]         return NGX_CONF_ERROR;
[180]     }
[181] 
[182] 
[183]     /*
[184]      * create the main_conf's, the null srv_conf's, and the null loc_conf's
[185]      * of the all http modules
[186]      */
[187] 
[188]     for (m = 0; cf->cycle->modules[m]; m++) {
[189]         if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
[190]             continue;
[191]         }
[192] 
[193]         module = cf->cycle->modules[m]->ctx;
[194]         mi = cf->cycle->modules[m]->ctx_index;
[195] 
[196]         if (module->create_main_conf) {
[197]             ctx->main_conf[mi] = module->create_main_conf(cf);
[198]             if (ctx->main_conf[mi] == NULL) {
[199]                 return NGX_CONF_ERROR;
[200]             }
[201]         }
[202] 
[203]         if (module->create_srv_conf) {
[204]             ctx->srv_conf[mi] = module->create_srv_conf(cf);
[205]             if (ctx->srv_conf[mi] == NULL) {
[206]                 return NGX_CONF_ERROR;
[207]             }
[208]         }
[209] 
[210]         if (module->create_loc_conf) {
[211]             ctx->loc_conf[mi] = module->create_loc_conf(cf);
[212]             if (ctx->loc_conf[mi] == NULL) {
[213]                 return NGX_CONF_ERROR;
[214]             }
[215]         }
[216]     }
[217] 
[218]     pcf = *cf;
[219]     cf->ctx = ctx;
[220] 
[221]     for (m = 0; cf->cycle->modules[m]; m++) {
[222]         if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
[223]             continue;
[224]         }
[225] 
[226]         module = cf->cycle->modules[m]->ctx;
[227] 
[228]         if (module->preconfiguration) {
[229]             if (module->preconfiguration(cf) != NGX_OK) {
[230]                 return NGX_CONF_ERROR;
[231]             }
[232]         }
[233]     }
[234] 
[235]     /* parse inside the http{} block */
[236] 
[237]     cf->module_type = NGX_HTTP_MODULE;
[238]     cf->cmd_type = NGX_HTTP_MAIN_CONF;
[239]     rv = ngx_conf_parse(cf, NULL);
[240] 
[241]     if (rv != NGX_CONF_OK) {
[242]         goto failed;
[243]     }
[244] 
[245]     /*
[246]      * init http{} main_conf's, merge the server{}s' srv_conf's
[247]      * and its location{}s' loc_conf's
[248]      */
[249] 
[250]     cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
[251]     cscfp = cmcf->servers.elts;
[252] 
[253]     for (m = 0; cf->cycle->modules[m]; m++) {
[254]         if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
[255]             continue;
[256]         }
[257] 
[258]         module = cf->cycle->modules[m]->ctx;
[259]         mi = cf->cycle->modules[m]->ctx_index;
[260] 
[261]         /* init http{} main_conf's */
[262] 
[263]         if (module->init_main_conf) {
[264]             rv = module->init_main_conf(cf, ctx->main_conf[mi]);
[265]             if (rv != NGX_CONF_OK) {
[266]                 goto failed;
[267]             }
[268]         }
[269] 
[270]         rv = ngx_http_merge_servers(cf, cmcf, module, mi);
[271]         if (rv != NGX_CONF_OK) {
[272]             goto failed;
[273]         }
[274]     }
[275] 
[276] 
[277]     /* create location trees */
[278] 
[279]     for (s = 0; s < cmcf->servers.nelts; s++) {
[280] 
[281]         clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
[282] 
[283]         if (ngx_http_init_locations(cf, cscfp[s], clcf) != NGX_OK) {
[284]             return NGX_CONF_ERROR;
[285]         }
[286] 
[287]         if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
[288]             return NGX_CONF_ERROR;
[289]         }
[290]     }
[291] 
[292] 
[293]     if (ngx_http_init_phases(cf, cmcf) != NGX_OK) {
[294]         return NGX_CONF_ERROR;
[295]     }
[296] 
[297]     if (ngx_http_init_headers_in_hash(cf, cmcf) != NGX_OK) {
[298]         return NGX_CONF_ERROR;
[299]     }
[300] 
[301] 
[302]     for (m = 0; cf->cycle->modules[m]; m++) {
[303]         if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
[304]             continue;
[305]         }
[306] 
[307]         module = cf->cycle->modules[m]->ctx;
[308] 
[309]         if (module->postconfiguration) {
[310]             if (module->postconfiguration(cf) != NGX_OK) {
[311]                 return NGX_CONF_ERROR;
[312]             }
[313]         }
[314]     }
[315] 
[316]     if (ngx_http_variables_init_vars(cf) != NGX_OK) {
[317]         return NGX_CONF_ERROR;
[318]     }
[319] 
[320]     /*
[321]      * http{}'s cf->ctx was needed while the configuration merging
[322]      * and in postconfiguration process
[323]      */
[324] 
[325]     *cf = pcf;
[326] 
[327] 
[328]     if (ngx_http_init_phase_handlers(cf, cmcf) != NGX_OK) {
[329]         return NGX_CONF_ERROR;
[330]     }
[331] 
[332] 
[333]     /* optimize the lists of ports, addresses and server names */
[334] 
[335]     if (ngx_http_optimize_servers(cf, cmcf, cmcf->ports) != NGX_OK) {
[336]         return NGX_CONF_ERROR;
[337]     }
[338] 
[339]     return NGX_CONF_OK;
[340] 
[341] failed:
[342] 
[343]     *cf = pcf;
[344] 
[345]     return rv;
[346] }
[347] 
[348] 
[349] static ngx_int_t
[350] ngx_http_init_phases(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
[351] {
[352]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers,
[353]                        cf->pool, 1, sizeof(ngx_http_handler_pt))
[354]         != NGX_OK)
[355]     {
[356]         return NGX_ERROR;
[357]     }
[358] 
[359]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers,
[360]                        cf->pool, 1, sizeof(ngx_http_handler_pt))
[361]         != NGX_OK)
[362]     {
[363]         return NGX_ERROR;
[364]     }
[365] 
[366]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
[367]                        cf->pool, 1, sizeof(ngx_http_handler_pt))
[368]         != NGX_OK)
[369]     {
[370]         return NGX_ERROR;
[371]     }
[372] 
[373]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers,
[374]                        cf->pool, 1, sizeof(ngx_http_handler_pt))
[375]         != NGX_OK)
[376]     {
[377]         return NGX_ERROR;
[378]     }
[379] 
[380]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,
[381]                        cf->pool, 2, sizeof(ngx_http_handler_pt))
[382]         != NGX_OK)
[383]     {
[384]         return NGX_ERROR;
[385]     }
[386] 
[387]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers,
[388]                        cf->pool, 2, sizeof(ngx_http_handler_pt))
[389]         != NGX_OK)
[390]     {
[391]         return NGX_ERROR;
[392]     }
[393] 
[394]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers,
[395]                        cf->pool, 4, sizeof(ngx_http_handler_pt))
[396]         != NGX_OK)
[397]     {
[398]         return NGX_ERROR;
[399]     }
[400] 
[401]     if (ngx_array_init(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers,
[402]                        cf->pool, 1, sizeof(ngx_http_handler_pt))
[403]         != NGX_OK)
[404]     {
[405]         return NGX_ERROR;
[406]     }
[407] 
[408]     return NGX_OK;
[409] }
[410] 
[411] 
[412] static ngx_int_t
[413] ngx_http_init_headers_in_hash(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
[414] {
[415]     ngx_array_t         headers_in;
[416]     ngx_hash_key_t     *hk;
[417]     ngx_hash_init_t     hash;
[418]     ngx_http_header_t  *header;
[419] 
[420]     if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
[421]         != NGX_OK)
[422]     {
[423]         return NGX_ERROR;
[424]     }
[425] 
[426]     for (header = ngx_http_headers_in; header->name.len; header++) {
[427]         hk = ngx_array_push(&headers_in);
[428]         if (hk == NULL) {
[429]             return NGX_ERROR;
[430]         }
[431] 
[432]         hk->key = header->name;
[433]         hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
[434]         hk->value = header;
[435]     }
[436] 
[437]     hash.hash = &cmcf->headers_in_hash;
[438]     hash.key = ngx_hash_key_lc;
[439]     hash.max_size = 512;
[440]     hash.bucket_size = ngx_align(64, ngx_cacheline_size);
[441]     hash.name = "headers_in_hash";
[442]     hash.pool = cf->pool;
[443]     hash.temp_pool = NULL;
[444] 
[445]     if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
[446]         return NGX_ERROR;
[447]     }
[448] 
[449]     return NGX_OK;
[450] }
[451] 
[452] 
[453] static ngx_int_t
[454] ngx_http_init_phase_handlers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
[455] {
[456]     ngx_int_t                   j;
[457]     ngx_uint_t                  i, n;
[458]     ngx_uint_t                  find_config_index, use_rewrite, use_access;
[459]     ngx_http_handler_pt        *h;
[460]     ngx_http_phase_handler_t   *ph;
[461]     ngx_http_phase_handler_pt   checker;
[462] 
[463]     cmcf->phase_engine.server_rewrite_index = (ngx_uint_t) -1;
[464]     cmcf->phase_engine.location_rewrite_index = (ngx_uint_t) -1;
[465]     find_config_index = 0;
[466]     use_rewrite = cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
[467]     use_access = cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;
[468] 
[469]     n = 1                  /* find config phase */
[470]         + use_rewrite      /* post rewrite phase */
[471]         + use_access;      /* post access phase */
[472] 
[473]     for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
[474]         n += cmcf->phases[i].handlers.nelts;
[475]     }
[476] 
[477]     ph = ngx_pcalloc(cf->pool,
[478]                      n * sizeof(ngx_http_phase_handler_t) + sizeof(void *));
[479]     if (ph == NULL) {
[480]         return NGX_ERROR;
[481]     }
[482] 
[483]     cmcf->phase_engine.handlers = ph;
[484]     n = 0;
[485] 
[486]     for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
[487]         h = cmcf->phases[i].handlers.elts;
[488] 
[489]         switch (i) {
[490] 
[491]         case NGX_HTTP_SERVER_REWRITE_PHASE:
[492]             if (cmcf->phase_engine.server_rewrite_index == (ngx_uint_t) -1) {
[493]                 cmcf->phase_engine.server_rewrite_index = n;
[494]             }
[495]             checker = ngx_http_core_rewrite_phase;
[496] 
[497]             break;
[498] 
[499]         case NGX_HTTP_FIND_CONFIG_PHASE:
[500]             find_config_index = n;
[501] 
[502]             ph->checker = ngx_http_core_find_config_phase;
[503]             n++;
[504]             ph++;
[505] 
[506]             continue;
[507] 
[508]         case NGX_HTTP_REWRITE_PHASE:
[509]             if (cmcf->phase_engine.location_rewrite_index == (ngx_uint_t) -1) {
[510]                 cmcf->phase_engine.location_rewrite_index = n;
[511]             }
[512]             checker = ngx_http_core_rewrite_phase;
[513] 
[514]             break;
[515] 
[516]         case NGX_HTTP_POST_REWRITE_PHASE:
[517]             if (use_rewrite) {
[518]                 ph->checker = ngx_http_core_post_rewrite_phase;
[519]                 ph->next = find_config_index;
[520]                 n++;
[521]                 ph++;
[522]             }
[523] 
[524]             continue;
[525] 
[526]         case NGX_HTTP_ACCESS_PHASE:
[527]             checker = ngx_http_core_access_phase;
[528]             n++;
[529]             break;
[530] 
[531]         case NGX_HTTP_POST_ACCESS_PHASE:
[532]             if (use_access) {
[533]                 ph->checker = ngx_http_core_post_access_phase;
[534]                 ph->next = n;
[535]                 ph++;
[536]             }
[537] 
[538]             continue;
[539] 
[540]         case NGX_HTTP_CONTENT_PHASE:
[541]             checker = ngx_http_core_content_phase;
[542]             break;
[543] 
[544]         default:
[545]             checker = ngx_http_core_generic_phase;
[546]         }
[547] 
[548]         n += cmcf->phases[i].handlers.nelts;
[549] 
[550]         for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
[551]             ph->checker = checker;
[552]             ph->handler = h[j];
[553]             ph->next = n;
[554]             ph++;
[555]         }
[556]     }
[557] 
[558]     return NGX_OK;
[559] }
[560] 
[561] 
[562] static char *
[563] ngx_http_merge_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
[564]     ngx_http_module_t *module, ngx_uint_t ctx_index)
[565] {
[566]     char                        *rv;
[567]     ngx_uint_t                   s;
[568]     ngx_http_conf_ctx_t         *ctx, saved;
[569]     ngx_http_core_loc_conf_t    *clcf;
[570]     ngx_http_core_srv_conf_t   **cscfp;
[571] 
[572]     cscfp = cmcf->servers.elts;
[573]     ctx = (ngx_http_conf_ctx_t *) cf->ctx;
[574]     saved = *ctx;
[575]     rv = NGX_CONF_OK;
[576] 
[577]     for (s = 0; s < cmcf->servers.nelts; s++) {
[578] 
[579]         /* merge the server{}s' srv_conf's */
[580] 
[581]         ctx->srv_conf = cscfp[s]->ctx->srv_conf;
[582] 
[583]         if (module->merge_srv_conf) {
[584]             rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
[585]                                         cscfp[s]->ctx->srv_conf[ctx_index]);
[586]             if (rv != NGX_CONF_OK) {
[587]                 goto failed;
[588]             }
[589]         }
[590] 
[591]         if (module->merge_loc_conf) {
[592] 
[593]             /* merge the server{}'s loc_conf */
[594] 
[595]             ctx->loc_conf = cscfp[s]->ctx->loc_conf;
[596] 
[597]             rv = module->merge_loc_conf(cf, saved.loc_conf[ctx_index],
[598]                                         cscfp[s]->ctx->loc_conf[ctx_index]);
[599]             if (rv != NGX_CONF_OK) {
[600]                 goto failed;
[601]             }
[602] 
[603]             /* merge the locations{}' loc_conf's */
[604] 
[605]             clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
[606] 
[607]             rv = ngx_http_merge_locations(cf, clcf->locations,
[608]                                           cscfp[s]->ctx->loc_conf,
[609]                                           module, ctx_index);
[610]             if (rv != NGX_CONF_OK) {
[611]                 goto failed;
[612]             }
[613]         }
[614]     }
[615] 
[616] failed:
[617] 
[618]     *ctx = saved;
[619] 
[620]     return rv;
[621] }
[622] 
[623] 
[624] static char *
[625] ngx_http_merge_locations(ngx_conf_t *cf, ngx_queue_t *locations,
[626]     void **loc_conf, ngx_http_module_t *module, ngx_uint_t ctx_index)
[627] {
[628]     char                       *rv;
[629]     ngx_queue_t                *q;
[630]     ngx_http_conf_ctx_t        *ctx, saved;
[631]     ngx_http_core_loc_conf_t   *clcf;
[632]     ngx_http_location_queue_t  *lq;
[633] 
[634]     if (locations == NULL) {
[635]         return NGX_CONF_OK;
[636]     }
[637] 
[638]     ctx = (ngx_http_conf_ctx_t *) cf->ctx;
[639]     saved = *ctx;
[640] 
[641]     for (q = ngx_queue_head(locations);
[642]          q != ngx_queue_sentinel(locations);
[643]          q = ngx_queue_next(q))
[644]     {
[645]         lq = (ngx_http_location_queue_t *) q;
[646] 
[647]         clcf = lq->exact ? lq->exact : lq->inclusive;
[648]         ctx->loc_conf = clcf->loc_conf;
[649] 
[650]         rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
[651]                                     clcf->loc_conf[ctx_index]);
[652]         if (rv != NGX_CONF_OK) {
[653]             return rv;
[654]         }
[655] 
[656]         rv = ngx_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
[657]                                       module, ctx_index);
[658]         if (rv != NGX_CONF_OK) {
[659]             return rv;
[660]         }
[661]     }
[662] 
[663]     *ctx = saved;
[664] 
[665]     return NGX_CONF_OK;
[666] }
[667] 
[668] 
[669] static ngx_int_t
[670] ngx_http_init_locations(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
[671]     ngx_http_core_loc_conf_t *pclcf)
[672] {
[673]     ngx_uint_t                   n;
[674]     ngx_queue_t                 *q, *locations, *named, tail;
[675]     ngx_http_core_loc_conf_t    *clcf;
[676]     ngx_http_location_queue_t   *lq;
[677]     ngx_http_core_loc_conf_t   **clcfp;
[678] #if (NGX_PCRE)
[679]     ngx_uint_t                   r;
[680]     ngx_queue_t                 *regex;
[681] #endif
[682] 
[683]     locations = pclcf->locations;
[684] 
[685]     if (locations == NULL) {
[686]         return NGX_OK;
[687]     }
[688] 
[689]     ngx_queue_sort(locations, ngx_http_cmp_locations);
[690] 
[691]     named = NULL;
[692]     n = 0;
[693] #if (NGX_PCRE)
[694]     regex = NULL;
[695]     r = 0;
[696] #endif
[697] 
[698]     for (q = ngx_queue_head(locations);
[699]          q != ngx_queue_sentinel(locations);
[700]          q = ngx_queue_next(q))
[701]     {
[702]         lq = (ngx_http_location_queue_t *) q;
[703] 
[704]         clcf = lq->exact ? lq->exact : lq->inclusive;
[705] 
[706]         if (ngx_http_init_locations(cf, NULL, clcf) != NGX_OK) {
[707]             return NGX_ERROR;
[708]         }
[709] 
[710] #if (NGX_PCRE)
[711] 
[712]         if (clcf->regex) {
[713]             r++;
[714] 
[715]             if (regex == NULL) {
[716]                 regex = q;
[717]             }
[718] 
[719]             continue;
[720]         }
[721] 
[722] #endif
[723] 
[724]         if (clcf->named) {
[725]             n++;
[726] 
[727]             if (named == NULL) {
[728]                 named = q;
[729]             }
[730] 
[731]             continue;
[732]         }
[733] 
[734]         if (clcf->noname) {
[735]             break;
[736]         }
[737]     }
[738] 
[739]     if (q != ngx_queue_sentinel(locations)) {
[740]         ngx_queue_split(locations, q, &tail);
[741]     }
[742] 
[743]     if (named) {
[744]         clcfp = ngx_palloc(cf->pool,
[745]                            (n + 1) * sizeof(ngx_http_core_loc_conf_t *));
[746]         if (clcfp == NULL) {
[747]             return NGX_ERROR;
[748]         }
[749] 
[750]         cscf->named_locations = clcfp;
[751] 
[752]         for (q = named;
[753]              q != ngx_queue_sentinel(locations);
[754]              q = ngx_queue_next(q))
[755]         {
[756]             lq = (ngx_http_location_queue_t *) q;
[757] 
[758]             *(clcfp++) = lq->exact;
[759]         }
[760] 
[761]         *clcfp = NULL;
[762] 
[763]         ngx_queue_split(locations, named, &tail);
[764]     }
[765] 
[766] #if (NGX_PCRE)
[767] 
[768]     if (regex) {
[769] 
[770]         clcfp = ngx_palloc(cf->pool,
[771]                            (r + 1) * sizeof(ngx_http_core_loc_conf_t *));
[772]         if (clcfp == NULL) {
[773]             return NGX_ERROR;
[774]         }
[775] 
[776]         pclcf->regex_locations = clcfp;
[777] 
[778]         for (q = regex;
[779]              q != ngx_queue_sentinel(locations);
[780]              q = ngx_queue_next(q))
[781]         {
[782]             lq = (ngx_http_location_queue_t *) q;
[783] 
[784]             *(clcfp++) = lq->exact;
[785]         }
[786] 
[787]         *clcfp = NULL;
[788] 
[789]         ngx_queue_split(locations, regex, &tail);
[790]     }
[791] 
[792] #endif
[793] 
[794]     return NGX_OK;
[795] }
[796] 
[797] 
[798] static ngx_int_t
[799] ngx_http_init_static_location_trees(ngx_conf_t *cf,
[800]     ngx_http_core_loc_conf_t *pclcf)
[801] {
[802]     ngx_queue_t                *q, *locations;
[803]     ngx_http_core_loc_conf_t   *clcf;
[804]     ngx_http_location_queue_t  *lq;
[805] 
[806]     locations = pclcf->locations;
[807] 
[808]     if (locations == NULL) {
[809]         return NGX_OK;
[810]     }
[811] 
[812]     if (ngx_queue_empty(locations)) {
[813]         return NGX_OK;
[814]     }
[815] 
[816]     for (q = ngx_queue_head(locations);
[817]          q != ngx_queue_sentinel(locations);
[818]          q = ngx_queue_next(q))
[819]     {
[820]         lq = (ngx_http_location_queue_t *) q;
[821] 
[822]         clcf = lq->exact ? lq->exact : lq->inclusive;
[823] 
[824]         if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
[825]             return NGX_ERROR;
[826]         }
[827]     }
[828] 
[829]     if (ngx_http_join_exact_locations(cf, locations) != NGX_OK) {
[830]         return NGX_ERROR;
[831]     }
[832] 
[833]     ngx_http_create_locations_list(locations, ngx_queue_head(locations));
[834] 
[835]     pclcf->static_locations = ngx_http_create_locations_tree(cf, locations, 0);
[836]     if (pclcf->static_locations == NULL) {
[837]         return NGX_ERROR;
[838]     }
[839] 
[840]     return NGX_OK;
[841] }
[842] 
[843] 
[844] ngx_int_t
[845] ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
[846]     ngx_http_core_loc_conf_t *clcf)
[847] {
[848]     ngx_http_location_queue_t  *lq;
[849] 
[850]     if (*locations == NULL) {
[851]         *locations = ngx_palloc(cf->temp_pool,
[852]                                 sizeof(ngx_http_location_queue_t));
[853]         if (*locations == NULL) {
[854]             return NGX_ERROR;
[855]         }
[856] 
[857]         ngx_queue_init(*locations);
[858]     }
[859] 
[860]     lq = ngx_palloc(cf->temp_pool, sizeof(ngx_http_location_queue_t));
[861]     if (lq == NULL) {
[862]         return NGX_ERROR;
[863]     }
[864] 
[865]     if (clcf->exact_match
[866] #if (NGX_PCRE)
[867]         || clcf->regex
[868] #endif
[869]         || clcf->named || clcf->noname)
[870]     {
[871]         lq->exact = clcf;
[872]         lq->inclusive = NULL;
[873] 
[874]     } else {
[875]         lq->exact = NULL;
[876]         lq->inclusive = clcf;
[877]     }
[878] 
[879]     lq->name = &clcf->name;
[880]     lq->file_name = cf->conf_file->file.name.data;
[881]     lq->line = cf->conf_file->line;
[882] 
[883]     ngx_queue_init(&lq->list);
[884] 
[885]     ngx_queue_insert_tail(*locations, &lq->queue);
[886] 
[887]     if (ngx_http_escape_location_name(cf, clcf) != NGX_OK) {
[888]         return NGX_ERROR;
[889]     }
[890] 
[891]     return NGX_OK;
[892] }
[893] 
[894] 
[895] static ngx_int_t
[896] ngx_http_escape_location_name(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf)
[897] {
[898]     u_char     *p;
[899]     size_t      len;
[900]     uintptr_t   escape;
[901] 
[902]     escape = 2 * ngx_escape_uri(NULL, clcf->name.data, clcf->name.len,
[903]                                 NGX_ESCAPE_URI);
[904] 
[905]     if (escape) {
[906]         len = clcf->name.len + escape;
[907] 
[908]         p = ngx_pnalloc(cf->pool, len);
[909]         if (p == NULL) {
[910]             return NGX_ERROR;
[911]         }
[912] 
[913]         clcf->escaped_name.len = len;
[914]         clcf->escaped_name.data = p;
[915] 
[916]         ngx_escape_uri(p, clcf->name.data, clcf->name.len, NGX_ESCAPE_URI);
[917] 
[918]     } else {
[919]         clcf->escaped_name = clcf->name;
[920]     }
[921] 
[922]     return NGX_OK;
[923] }
[924] 
[925] 
[926] static ngx_int_t
[927] ngx_http_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
[928] {
[929]     ngx_int_t                   rc;
[930]     ngx_http_core_loc_conf_t   *first, *second;
[931]     ngx_http_location_queue_t  *lq1, *lq2;
[932] 
[933]     lq1 = (ngx_http_location_queue_t *) one;
[934]     lq2 = (ngx_http_location_queue_t *) two;
[935] 
[936]     first = lq1->exact ? lq1->exact : lq1->inclusive;
[937]     second = lq2->exact ? lq2->exact : lq2->inclusive;
[938] 
[939]     if (first->noname && !second->noname) {
[940]         /* shift no named locations to the end */
[941]         return 1;
[942]     }
[943] 
[944]     if (!first->noname && second->noname) {
[945]         /* shift no named locations to the end */
[946]         return -1;
[947]     }
[948] 
[949]     if (first->noname || second->noname) {
[950]         /* do not sort no named locations */
[951]         return 0;
[952]     }
[953] 
[954]     if (first->named && !second->named) {
[955]         /* shift named locations to the end */
[956]         return 1;
[957]     }
[958] 
[959]     if (!first->named && second->named) {
[960]         /* shift named locations to the end */
[961]         return -1;
[962]     }
[963] 
[964]     if (first->named && second->named) {
[965]         return ngx_strcmp(first->name.data, second->name.data);
[966]     }
[967] 
[968] #if (NGX_PCRE)
[969] 
[970]     if (first->regex && !second->regex) {
[971]         /* shift the regex matches to the end */
[972]         return 1;
[973]     }
[974] 
[975]     if (!first->regex && second->regex) {
[976]         /* shift the regex matches to the end */
[977]         return -1;
[978]     }
[979] 
[980]     if (first->regex || second->regex) {
[981]         /* do not sort the regex matches */
[982]         return 0;
[983]     }
[984] 
[985] #endif
[986] 
[987]     rc = ngx_filename_cmp(first->name.data, second->name.data,
[988]                           ngx_min(first->name.len, second->name.len) + 1);
[989] 
[990]     if (rc == 0 && !first->exact_match && second->exact_match) {
[991]         /* an exact match must be before the same inclusive one */
[992]         return 1;
[993]     }
[994] 
[995]     return rc;
[996] }
[997] 
[998] 
[999] static ngx_int_t
[1000] ngx_http_join_exact_locations(ngx_conf_t *cf, ngx_queue_t *locations)
[1001] {
[1002]     ngx_queue_t                *q, *x;
[1003]     ngx_http_location_queue_t  *lq, *lx;
[1004] 
[1005]     q = ngx_queue_head(locations);
[1006] 
[1007]     while (q != ngx_queue_last(locations)) {
[1008] 
[1009]         x = ngx_queue_next(q);
[1010] 
[1011]         lq = (ngx_http_location_queue_t *) q;
[1012]         lx = (ngx_http_location_queue_t *) x;
[1013] 
[1014]         if (lq->name->len == lx->name->len
[1015]             && ngx_filename_cmp(lq->name->data, lx->name->data, lx->name->len)
[1016]                == 0)
[1017]         {
[1018]             if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
[1019]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1020]                               "duplicate location \"%V\" in %s:%ui",
[1021]                               lx->name, lx->file_name, lx->line);
[1022] 
[1023]                 return NGX_ERROR;
[1024]             }
[1025] 
[1026]             lq->inclusive = lx->inclusive;
[1027] 
[1028]             ngx_queue_remove(x);
[1029] 
[1030]             continue;
[1031]         }
[1032] 
[1033]         q = ngx_queue_next(q);
[1034]     }
[1035] 
[1036]     return NGX_OK;
[1037] }
[1038] 
[1039] 
[1040] static void
[1041] ngx_http_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
[1042] {
[1043]     u_char                     *name;
[1044]     size_t                      len;
[1045]     ngx_queue_t                *x, tail;
[1046]     ngx_http_location_queue_t  *lq, *lx;
[1047] 
[1048]     if (q == ngx_queue_last(locations)) {
[1049]         return;
[1050]     }
[1051] 
[1052]     lq = (ngx_http_location_queue_t *) q;
[1053] 
[1054]     if (lq->inclusive == NULL) {
[1055]         ngx_http_create_locations_list(locations, ngx_queue_next(q));
[1056]         return;
[1057]     }
[1058] 
[1059]     len = lq->name->len;
[1060]     name = lq->name->data;
[1061] 
[1062]     for (x = ngx_queue_next(q);
[1063]          x != ngx_queue_sentinel(locations);
[1064]          x = ngx_queue_next(x))
[1065]     {
[1066]         lx = (ngx_http_location_queue_t *) x;
[1067] 
[1068]         if (len > lx->name->len
[1069]             || ngx_filename_cmp(name, lx->name->data, len) != 0)
[1070]         {
[1071]             break;
[1072]         }
[1073]     }
[1074] 
[1075]     q = ngx_queue_next(q);
[1076] 
[1077]     if (q == x) {
[1078]         ngx_http_create_locations_list(locations, x);
[1079]         return;
[1080]     }
[1081] 
[1082]     ngx_queue_split(locations, q, &tail);
[1083]     ngx_queue_add(&lq->list, &tail);
[1084] 
[1085]     if (x == ngx_queue_sentinel(locations)) {
[1086]         ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
[1087]         return;
[1088]     }
[1089] 
[1090]     ngx_queue_split(&lq->list, x, &tail);
[1091]     ngx_queue_add(locations, &tail);
[1092] 
[1093]     ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
[1094] 
[1095]     ngx_http_create_locations_list(locations, x);
[1096] }
[1097] 
[1098] 
[1099] /*
[1100]  * to keep cache locality for left leaf nodes, allocate nodes in following
[1101]  * order: node, left subtree, right subtree, inclusive subtree
[1102]  */
[1103] 
[1104] static ngx_http_location_tree_node_t *
[1105] ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
[1106]     size_t prefix)
[1107] {
[1108]     size_t                          len;
[1109]     ngx_queue_t                    *q, tail;
[1110]     ngx_http_location_queue_t      *lq;
[1111]     ngx_http_location_tree_node_t  *node;
[1112] 
[1113]     q = ngx_queue_middle(locations);
[1114] 
[1115]     lq = (ngx_http_location_queue_t *) q;
[1116]     len = lq->name->len - prefix;
[1117] 
[1118]     node = ngx_palloc(cf->pool,
[1119]                       offsetof(ngx_http_location_tree_node_t, name) + len);
[1120]     if (node == NULL) {
[1121]         return NULL;
[1122]     }
[1123] 
[1124]     node->left = NULL;
[1125]     node->right = NULL;
[1126]     node->tree = NULL;
[1127]     node->exact = lq->exact;
[1128]     node->inclusive = lq->inclusive;
[1129] 
[1130]     node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
[1131]                            || (lq->inclusive && lq->inclusive->auto_redirect));
[1132] 
[1133]     node->len = (u_short) len;
[1134]     ngx_memcpy(node->name, &lq->name->data[prefix], len);
[1135] 
[1136]     ngx_queue_split(locations, q, &tail);
[1137] 
[1138]     if (ngx_queue_empty(locations)) {
[1139]         /*
[1140]          * ngx_queue_split() insures that if left part is empty,
[1141]          * then right one is empty too
[1142]          */
[1143]         goto inclusive;
[1144]     }
[1145] 
[1146]     node->left = ngx_http_create_locations_tree(cf, locations, prefix);
[1147]     if (node->left == NULL) {
[1148]         return NULL;
[1149]     }
[1150] 
[1151]     ngx_queue_remove(q);
[1152] 
[1153]     if (ngx_queue_empty(&tail)) {
[1154]         goto inclusive;
[1155]     }
[1156] 
[1157]     node->right = ngx_http_create_locations_tree(cf, &tail, prefix);
[1158]     if (node->right == NULL) {
[1159]         return NULL;
[1160]     }
[1161] 
[1162] inclusive:
[1163] 
[1164]     if (ngx_queue_empty(&lq->list)) {
[1165]         return node;
[1166]     }
[1167] 
[1168]     node->tree = ngx_http_create_locations_tree(cf, &lq->list, prefix + len);
[1169]     if (node->tree == NULL) {
[1170]         return NULL;
[1171]     }
[1172] 
[1173]     return node;
[1174] }
[1175] 
[1176] 
[1177] ngx_int_t
[1178] ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
[1179]     ngx_http_listen_opt_t *lsopt)
[1180] {
[1181]     in_port_t                   p;
[1182]     ngx_uint_t                  i;
[1183]     struct sockaddr            *sa;
[1184]     ngx_http_conf_port_t       *port;
[1185]     ngx_http_core_main_conf_t  *cmcf;
[1186] 
[1187]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[1188] 
[1189]     if (cmcf->ports == NULL) {
[1190]         cmcf->ports = ngx_array_create(cf->temp_pool, 2,
[1191]                                        sizeof(ngx_http_conf_port_t));
[1192]         if (cmcf->ports == NULL) {
[1193]             return NGX_ERROR;
[1194]         }
[1195]     }
[1196] 
[1197]     sa = lsopt->sockaddr;
[1198]     p = ngx_inet_get_port(sa);
[1199] 
[1200]     port = cmcf->ports->elts;
[1201]     for (i = 0; i < cmcf->ports->nelts; i++) {
[1202] 
[1203]         if (p != port[i].port || sa->sa_family != port[i].family) {
[1204]             continue;
[1205]         }
[1206] 
[1207]         /* a port is already in the port list */
[1208] 
[1209]         return ngx_http_add_addresses(cf, cscf, &port[i], lsopt);
[1210]     }
[1211] 
[1212]     /* add a port to the port list */
[1213] 
[1214]     port = ngx_array_push(cmcf->ports);
[1215]     if (port == NULL) {
[1216]         return NGX_ERROR;
[1217]     }
[1218] 
[1219]     port->family = sa->sa_family;
[1220]     port->port = p;
[1221]     port->addrs.elts = NULL;
[1222] 
[1223]     return ngx_http_add_address(cf, cscf, port, lsopt);
[1224] }
[1225] 
[1226] 
[1227] static ngx_int_t
[1228] ngx_http_add_addresses(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
[1229]     ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
[1230] {
[1231]     ngx_uint_t             i, default_server, proxy_protocol,
[1232]                            protocols, protocols_prev;
[1233]     ngx_http_conf_addr_t  *addr;
[1234] #if (NGX_HTTP_SSL)
[1235]     ngx_uint_t             ssl;
[1236] #endif
[1237] #if (NGX_HTTP_V2)
[1238]     ngx_uint_t             http2;
[1239] #endif
[1240] 
[1241]     /*
[1242]      * we cannot compare whole sockaddr struct's as kernel
[1243]      * may fill some fields in inherited sockaddr struct's
[1244]      */
[1245] 
[1246]     addr = port->addrs.elts;
[1247] 
[1248]     for (i = 0; i < port->addrs.nelts; i++) {
[1249] 
[1250]         if (ngx_cmp_sockaddr(lsopt->sockaddr, lsopt->socklen,
[1251]                              addr[i].opt.sockaddr,
[1252]                              addr[i].opt.socklen, 0)
[1253]             != NGX_OK)
[1254]         {
[1255]             continue;
[1256]         }
[1257] 
[1258]         /* the address is already in the address list */
[1259] 
[1260]         if (ngx_http_add_server(cf, cscf, &addr[i]) != NGX_OK) {
[1261]             return NGX_ERROR;
[1262]         }
[1263] 
[1264]         /* preserve default_server bit during listen options overwriting */
[1265]         default_server = addr[i].opt.default_server;
[1266] 
[1267]         proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;
[1268]         protocols = lsopt->proxy_protocol;
[1269]         protocols_prev = addr[i].opt.proxy_protocol;
[1270] 
[1271] #if (NGX_HTTP_SSL)
[1272]         ssl = lsopt->ssl || addr[i].opt.ssl;
[1273]         protocols |= lsopt->ssl << 1;
[1274]         protocols_prev |= addr[i].opt.ssl << 1;
[1275] #endif
[1276] #if (NGX_HTTP_V2)
[1277]         http2 = lsopt->http2 || addr[i].opt.http2;
[1278]         protocols |= lsopt->http2 << 2;
[1279]         protocols_prev |= addr[i].opt.http2 << 2;
[1280] #endif
[1281] 
[1282]         if (lsopt->set) {
[1283] 
[1284]             if (addr[i].opt.set) {
[1285]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1286]                                    "duplicate listen options for %V",
[1287]                                    &addr[i].opt.addr_text);
[1288]                 return NGX_ERROR;
[1289]             }
[1290] 
[1291]             addr[i].opt = *lsopt;
[1292]         }
[1293] 
[1294]         /* check the duplicate "default" server for this address:port */
[1295] 
[1296]         if (lsopt->default_server) {
[1297] 
[1298]             if (default_server) {
[1299]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1300]                                    "a duplicate default server for %V",
[1301]                                    &addr[i].opt.addr_text);
[1302]                 return NGX_ERROR;
[1303]             }
[1304] 
[1305]             default_server = 1;
[1306]             addr[i].default_server = cscf;
[1307]         }
[1308] 
[1309]         /* check for conflicting protocol options */
[1310] 
[1311]         if ((protocols | protocols_prev) != protocols_prev) {
[1312] 
[1313]             /* options added */
[1314] 
[1315]             if ((addr[i].opt.set && !lsopt->set)
[1316]                 || addr[i].protocols_changed
[1317]                 || (protocols | protocols_prev) != protocols)
[1318]             {
[1319]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1320]                                    "protocol options redefined for %V",
[1321]                                    &addr[i].opt.addr_text);
[1322]             }
[1323] 
[1324]             addr[i].protocols = protocols_prev;
[1325]             addr[i].protocols_set = 1;
[1326]             addr[i].protocols_changed = 1;
[1327] 
[1328]         } else if ((protocols_prev | protocols) != protocols) {
[1329] 
[1330]             /* options removed */
[1331] 
[1332]             if (lsopt->set
[1333]                 || (addr[i].protocols_set && protocols != addr[i].protocols))
[1334]             {
[1335]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1336]                                    "protocol options redefined for %V",
[1337]                                    &addr[i].opt.addr_text);
[1338]             }
[1339] 
[1340]             addr[i].protocols = protocols;
[1341]             addr[i].protocols_set = 1;
[1342]             addr[i].protocols_changed = 1;
[1343] 
[1344]         } else {
[1345] 
[1346]             /* the same options */
[1347] 
[1348]             if ((lsopt->set && addr[i].protocols_changed)
[1349]                 || (addr[i].protocols_set && protocols != addr[i].protocols))
[1350]             {
[1351]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1352]                                    "protocol options redefined for %V",
[1353]                                    &addr[i].opt.addr_text);
[1354]             }
[1355] 
[1356]             addr[i].protocols = protocols;
[1357]             addr[i].protocols_set = 1;
[1358]         }
[1359] 
[1360]         addr[i].opt.default_server = default_server;
[1361]         addr[i].opt.proxy_protocol = proxy_protocol;
[1362] #if (NGX_HTTP_SSL)
[1363]         addr[i].opt.ssl = ssl;
[1364] #endif
[1365] #if (NGX_HTTP_V2)
[1366]         addr[i].opt.http2 = http2;
[1367] #endif
[1368] 
[1369]         return NGX_OK;
[1370]     }
[1371] 
[1372]     /* add the address to the addresses list that bound to this port */
[1373] 
[1374]     return ngx_http_add_address(cf, cscf, port, lsopt);
[1375] }
[1376] 
[1377] 
[1378] /*
[1379]  * add the server address, the server names and the server core module
[1380]  * configurations to the port list
[1381]  */
[1382] 
[1383] static ngx_int_t
[1384] ngx_http_add_address(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
[1385]     ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
[1386] {
[1387]     ngx_http_conf_addr_t  *addr;
[1388] 
[1389]     if (port->addrs.elts == NULL) {
[1390]         if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
[1391]                            sizeof(ngx_http_conf_addr_t))
[1392]             != NGX_OK)
[1393]         {
[1394]             return NGX_ERROR;
[1395]         }
[1396]     }
[1397] 
[1398] #if (NGX_HTTP_V2 && NGX_HTTP_SSL                                              \
[1399]      && !defined TLSEXT_TYPE_application_layer_protocol_negotiation)
[1400] 
[1401]     if (lsopt->http2 && lsopt->ssl) {
[1402]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1403]                            "nginx was built with OpenSSL that lacks ALPN "
[1404]                            "support, HTTP/2 is not enabled for %V",
[1405]                            &lsopt->addr_text);
[1406]     }
[1407] 
[1408] #endif
[1409] 
[1410]     addr = ngx_array_push(&port->addrs);
[1411]     if (addr == NULL) {
[1412]         return NGX_ERROR;
[1413]     }
[1414] 
[1415]     addr->opt = *lsopt;
[1416]     addr->protocols = 0;
[1417]     addr->protocols_set = 0;
[1418]     addr->protocols_changed = 0;
[1419]     addr->hash.buckets = NULL;
[1420]     addr->hash.size = 0;
[1421]     addr->wc_head = NULL;
[1422]     addr->wc_tail = NULL;
[1423] #if (NGX_PCRE)
[1424]     addr->nregex = 0;
[1425]     addr->regex = NULL;
[1426] #endif
[1427]     addr->default_server = cscf;
[1428]     addr->servers.elts = NULL;
[1429] 
[1430]     return ngx_http_add_server(cf, cscf, addr);
[1431] }
[1432] 
[1433] 
[1434] /* add the server core module configuration to the address:port */
[1435] 
[1436] static ngx_int_t
[1437] ngx_http_add_server(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
[1438]     ngx_http_conf_addr_t *addr)
[1439] {
[1440]     ngx_uint_t                  i;
[1441]     ngx_http_core_srv_conf_t  **server;
[1442] 
[1443]     if (addr->servers.elts == NULL) {
[1444]         if (ngx_array_init(&addr->servers, cf->temp_pool, 4,
[1445]                            sizeof(ngx_http_core_srv_conf_t *))
[1446]             != NGX_OK)
[1447]         {
[1448]             return NGX_ERROR;
[1449]         }
[1450] 
[1451]     } else {
[1452]         server = addr->servers.elts;
[1453]         for (i = 0; i < addr->servers.nelts; i++) {
[1454]             if (server[i] == cscf) {
[1455]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1456]                                    "a duplicate listen %V",
[1457]                                    &addr->opt.addr_text);
[1458]                 return NGX_ERROR;
[1459]             }
[1460]         }
[1461]     }
[1462] 
[1463]     server = ngx_array_push(&addr->servers);
[1464]     if (server == NULL) {
[1465]         return NGX_ERROR;
[1466]     }
[1467] 
[1468]     *server = cscf;
[1469] 
[1470]     return NGX_OK;
[1471] }
[1472] 
[1473] 
[1474] static ngx_int_t
[1475] ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
[1476]     ngx_array_t *ports)
[1477] {
[1478]     ngx_uint_t             p, a;
[1479]     ngx_http_conf_port_t  *port;
[1480]     ngx_http_conf_addr_t  *addr;
[1481] 
[1482]     if (ports == NULL) {
[1483]         return NGX_OK;
[1484]     }
[1485] 
[1486]     port = ports->elts;
[1487]     for (p = 0; p < ports->nelts; p++) {
[1488] 
[1489]         ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
[1490]                  sizeof(ngx_http_conf_addr_t), ngx_http_cmp_conf_addrs);
[1491] 
[1492]         /*
[1493]          * check whether all name-based servers have the same
[1494]          * configuration as a default server for given address:port
[1495]          */
[1496] 
[1497]         addr = port[p].addrs.elts;
[1498]         for (a = 0; a < port[p].addrs.nelts; a++) {
[1499] 
[1500]             if (addr[a].servers.nelts > 1
[1501] #if (NGX_PCRE)
[1502]                 || addr[a].default_server->captures
[1503] #endif
[1504]                )
[1505]             {
[1506]                 if (ngx_http_server_names(cf, cmcf, &addr[a]) != NGX_OK) {
[1507]                     return NGX_ERROR;
[1508]                 }
[1509]             }
[1510]         }
[1511] 
[1512]         if (ngx_http_init_listening(cf, &port[p]) != NGX_OK) {
[1513]             return NGX_ERROR;
[1514]         }
[1515]     }
[1516] 
[1517]     return NGX_OK;
[1518] }
[1519] 
[1520] 
[1521] static ngx_int_t
[1522] ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
[1523]     ngx_http_conf_addr_t *addr)
[1524] {
[1525]     ngx_int_t                   rc;
[1526]     ngx_uint_t                  n, s;
[1527]     ngx_hash_init_t             hash;
[1528]     ngx_hash_keys_arrays_t      ha;
[1529]     ngx_http_server_name_t     *name;
[1530]     ngx_http_core_srv_conf_t  **cscfp;
[1531] #if (NGX_PCRE)
[1532]     ngx_uint_t                  regex, i;
[1533] 
[1534]     regex = 0;
[1535] #endif
[1536] 
[1537]     ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));
[1538] 
[1539]     ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[1540]     if (ha.temp_pool == NULL) {
[1541]         return NGX_ERROR;
[1542]     }
[1543] 
[1544]     ha.pool = cf->pool;
[1545] 
[1546]     if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
[1547]         goto failed;
[1548]     }
[1549] 
[1550]     cscfp = addr->servers.elts;
[1551] 
[1552]     for (s = 0; s < addr->servers.nelts; s++) {
[1553] 
[1554]         name = cscfp[s]->server_names.elts;
[1555] 
[1556]         for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
[1557] 
[1558] #if (NGX_PCRE)
[1559]             if (name[n].regex) {
[1560]                 regex++;
[1561]                 continue;
[1562]             }
[1563] #endif
[1564] 
[1565]             rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
[1566]                                   NGX_HASH_WILDCARD_KEY);
[1567] 
[1568]             if (rc == NGX_ERROR) {
[1569]                 goto failed;
[1570]             }
[1571] 
[1572]             if (rc == NGX_DECLINED) {
[1573]                 ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1574]                               "invalid server name or wildcard \"%V\" on %V",
[1575]                               &name[n].name, &addr->opt.addr_text);
[1576]                 goto failed;
[1577]             }
[1578] 
[1579]             if (rc == NGX_BUSY) {
[1580]                 ngx_log_error(NGX_LOG_WARN, cf->log, 0,
[1581]                               "conflicting server name \"%V\" on %V, ignored",
[1582]                               &name[n].name, &addr->opt.addr_text);
[1583]             }
[1584]         }
[1585]     }
[1586] 
[1587]     hash.key = ngx_hash_key_lc;
[1588]     hash.max_size = cmcf->server_names_hash_max_size;
[1589]     hash.bucket_size = cmcf->server_names_hash_bucket_size;
[1590]     hash.name = "server_names_hash";
[1591]     hash.pool = cf->pool;
[1592] 
[1593]     if (ha.keys.nelts) {
[1594]         hash.hash = &addr->hash;
[1595]         hash.temp_pool = NULL;
[1596] 
[1597]         if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
[1598]             goto failed;
[1599]         }
[1600]     }
[1601] 
[1602]     if (ha.dns_wc_head.nelts) {
[1603] 
[1604]         ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
[1605]                   sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);
[1606] 
[1607]         hash.hash = NULL;
[1608]         hash.temp_pool = ha.temp_pool;
[1609] 
[1610]         if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
[1611]                                    ha.dns_wc_head.nelts)
[1612]             != NGX_OK)
[1613]         {
[1614]             goto failed;
[1615]         }
[1616] 
[1617]         addr->wc_head = (ngx_hash_wildcard_t *) hash.hash;
[1618]     }
[1619] 
[1620]     if (ha.dns_wc_tail.nelts) {
[1621] 
[1622]         ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
[1623]                   sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);
[1624] 
[1625]         hash.hash = NULL;
[1626]         hash.temp_pool = ha.temp_pool;
[1627] 
[1628]         if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
[1629]                                    ha.dns_wc_tail.nelts)
[1630]             != NGX_OK)
[1631]         {
[1632]             goto failed;
[1633]         }
[1634] 
[1635]         addr->wc_tail = (ngx_hash_wildcard_t *) hash.hash;
[1636]     }
[1637] 
[1638]     ngx_destroy_pool(ha.temp_pool);
[1639] 
[1640] #if (NGX_PCRE)
[1641] 
[1642]     if (regex == 0) {
[1643]         return NGX_OK;
[1644]     }
[1645] 
[1646]     addr->nregex = regex;
[1647]     addr->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_server_name_t));
[1648]     if (addr->regex == NULL) {
[1649]         return NGX_ERROR;
[1650]     }
[1651] 
[1652]     i = 0;
[1653] 
[1654]     for (s = 0; s < addr->servers.nelts; s++) {
[1655] 
[1656]         name = cscfp[s]->server_names.elts;
[1657] 
[1658]         for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
[1659]             if (name[n].regex) {
[1660]                 addr->regex[i++] = name[n];
[1661]             }
[1662]         }
[1663]     }
[1664] 
[1665] #endif
[1666] 
[1667]     return NGX_OK;
[1668] 
[1669] failed:
[1670] 
[1671]     ngx_destroy_pool(ha.temp_pool);
[1672] 
[1673]     return NGX_ERROR;
[1674] }
[1675] 
[1676] 
[1677] static ngx_int_t
[1678] ngx_http_cmp_conf_addrs(const void *one, const void *two)
[1679] {
[1680]     ngx_http_conf_addr_t  *first, *second;
[1681] 
[1682]     first = (ngx_http_conf_addr_t *) one;
[1683]     second = (ngx_http_conf_addr_t *) two;
[1684] 
[1685]     if (first->opt.wildcard) {
[1686]         /* a wildcard address must be the last resort, shift it to the end */
[1687]         return 1;
[1688]     }
[1689] 
[1690]     if (second->opt.wildcard) {
[1691]         /* a wildcard address must be the last resort, shift it to the end */
[1692]         return -1;
[1693]     }
[1694] 
[1695]     if (first->opt.bind && !second->opt.bind) {
[1696]         /* shift explicit bind()ed addresses to the start */
[1697]         return -1;
[1698]     }
[1699] 
[1700]     if (!first->opt.bind && second->opt.bind) {
[1701]         /* shift explicit bind()ed addresses to the start */
[1702]         return 1;
[1703]     }
[1704] 
[1705]     /* do not sort by default */
[1706] 
[1707]     return 0;
[1708] }
[1709] 
[1710] 
[1711] static int ngx_libc_cdecl
[1712] ngx_http_cmp_dns_wildcards(const void *one, const void *two)
[1713] {
[1714]     ngx_hash_key_t  *first, *second;
[1715] 
[1716]     first = (ngx_hash_key_t *) one;
[1717]     second = (ngx_hash_key_t *) two;
[1718] 
[1719]     return ngx_dns_strcmp(first->key.data, second->key.data);
[1720] }
[1721] 
[1722] 
[1723] static ngx_int_t
[1724] ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_port_t *port)
[1725] {
[1726]     ngx_uint_t                 i, last, bind_wildcard;
[1727]     ngx_listening_t           *ls;
[1728]     ngx_http_port_t           *hport;
[1729]     ngx_http_conf_addr_t      *addr;
[1730] 
[1731]     addr = port->addrs.elts;
[1732]     last = port->addrs.nelts;
[1733] 
[1734]     /*
[1735]      * If there is a binding to an "*:port" then we need to bind() to
[1736]      * the "*:port" only and ignore other implicit bindings.  The bindings
[1737]      * have been already sorted: explicit bindings are on the start, then
[1738]      * implicit bindings go, and wildcard binding is in the end.
[1739]      */
[1740] 
[1741]     if (addr[last - 1].opt.wildcard) {
[1742]         addr[last - 1].opt.bind = 1;
[1743]         bind_wildcard = 1;
[1744] 
[1745]     } else {
[1746]         bind_wildcard = 0;
[1747]     }
[1748] 
[1749]     i = 0;
[1750] 
[1751]     while (i < last) {
[1752] 
[1753]         if (bind_wildcard && !addr[i].opt.bind) {
[1754]             i++;
[1755]             continue;
[1756]         }
[1757] 
[1758]         ls = ngx_http_add_listening(cf, &addr[i]);
[1759]         if (ls == NULL) {
[1760]             return NGX_ERROR;
[1761]         }
[1762] 
[1763]         hport = ngx_pcalloc(cf->pool, sizeof(ngx_http_port_t));
[1764]         if (hport == NULL) {
[1765]             return NGX_ERROR;
[1766]         }
[1767] 
[1768]         ls->servers = hport;
[1769] 
[1770]         hport->naddrs = i + 1;
[1771] 
[1772]         switch (ls->sockaddr->sa_family) {
[1773] 
[1774] #if (NGX_HAVE_INET6)
[1775]         case AF_INET6:
[1776]             if (ngx_http_add_addrs6(cf, hport, addr) != NGX_OK) {
[1777]                 return NGX_ERROR;
[1778]             }
[1779]             break;
[1780] #endif
[1781]         default: /* AF_INET */
[1782]             if (ngx_http_add_addrs(cf, hport, addr) != NGX_OK) {
[1783]                 return NGX_ERROR;
[1784]             }
[1785]             break;
[1786]         }
[1787] 
[1788]         addr++;
[1789]         last--;
[1790]     }
[1791] 
[1792]     return NGX_OK;
[1793] }
[1794] 
[1795] 
[1796] static ngx_listening_t *
[1797] ngx_http_add_listening(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
[1798] {
[1799]     ngx_listening_t           *ls;
[1800]     ngx_http_core_loc_conf_t  *clcf;
[1801]     ngx_http_core_srv_conf_t  *cscf;
[1802] 
[1803]     ls = ngx_create_listening(cf, addr->opt.sockaddr, addr->opt.socklen);
[1804]     if (ls == NULL) {
[1805]         return NULL;
[1806]     }
[1807] 
[1808]     ls->addr_ntop = 1;
[1809] 
[1810]     ls->handler = ngx_http_init_connection;
[1811] 
[1812]     cscf = addr->default_server;
[1813]     ls->pool_size = cscf->connection_pool_size;
[1814] 
[1815]     clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];
[1816] 
[1817]     ls->logp = clcf->error_log;
[1818]     ls->log.data = &ls->addr_text;
[1819]     ls->log.handler = ngx_accept_log_error;
[1820] 
[1821] #if (NGX_WIN32)
[1822]     {
[1823]     ngx_iocp_conf_t  *iocpcf = NULL;
[1824] 
[1825]     if (ngx_get_conf(cf->cycle->conf_ctx, ngx_events_module)) {
[1826]         iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
[1827]     }
[1828]     if (iocpcf && iocpcf->acceptex_read) {
[1829]         ls->post_accept_buffer_size = cscf->client_header_buffer_size;
[1830]     }
[1831]     }
[1832] #endif
[1833] 
[1834]     ls->backlog = addr->opt.backlog;
[1835]     ls->rcvbuf = addr->opt.rcvbuf;
[1836]     ls->sndbuf = addr->opt.sndbuf;
[1837] 
[1838]     ls->keepalive = addr->opt.so_keepalive;
[1839] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[1840]     ls->keepidle = addr->opt.tcp_keepidle;
[1841]     ls->keepintvl = addr->opt.tcp_keepintvl;
[1842]     ls->keepcnt = addr->opt.tcp_keepcnt;
[1843] #endif
[1844] 
[1845] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[1846]     ls->accept_filter = addr->opt.accept_filter;
[1847] #endif
[1848] 
[1849] #if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
[1850]     ls->deferred_accept = addr->opt.deferred_accept;
[1851] #endif
[1852] 
[1853] #if (NGX_HAVE_INET6)
[1854]     ls->ipv6only = addr->opt.ipv6only;
[1855] #endif
[1856] 
[1857] #if (NGX_HAVE_SETFIB)
[1858]     ls->setfib = addr->opt.setfib;
[1859] #endif
[1860] 
[1861] #if (NGX_HAVE_TCP_FASTOPEN)
[1862]     ls->fastopen = addr->opt.fastopen;
[1863] #endif
[1864] 
[1865] #if (NGX_HAVE_REUSEPORT)
[1866]     ls->reuseport = addr->opt.reuseport;
[1867] #endif
[1868] 
[1869]     return ls;
[1870] }
[1871] 
[1872] 
[1873] static ngx_int_t
[1874] ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
[1875]     ngx_http_conf_addr_t *addr)
[1876] {
[1877]     ngx_uint_t                 i;
[1878]     ngx_http_in_addr_t        *addrs;
[1879]     struct sockaddr_in        *sin;
[1880]     ngx_http_virtual_names_t  *vn;
[1881] 
[1882]     hport->addrs = ngx_pcalloc(cf->pool,
[1883]                                hport->naddrs * sizeof(ngx_http_in_addr_t));
[1884]     if (hport->addrs == NULL) {
[1885]         return NGX_ERROR;
[1886]     }
[1887] 
[1888]     addrs = hport->addrs;
[1889] 
[1890]     for (i = 0; i < hport->naddrs; i++) {
[1891] 
[1892]         sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
[1893]         addrs[i].addr = sin->sin_addr.s_addr;
[1894]         addrs[i].conf.default_server = addr[i].default_server;
[1895] #if (NGX_HTTP_SSL)
[1896]         addrs[i].conf.ssl = addr[i].opt.ssl;
[1897] #endif
[1898] #if (NGX_HTTP_V2)
[1899]         addrs[i].conf.http2 = addr[i].opt.http2;
[1900] #endif
[1901]         addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
[1902] 
[1903]         if (addr[i].hash.buckets == NULL
[1904]             && (addr[i].wc_head == NULL
[1905]                 || addr[i].wc_head->hash.buckets == NULL)
[1906]             && (addr[i].wc_tail == NULL
[1907]                 || addr[i].wc_tail->hash.buckets == NULL)
[1908] #if (NGX_PCRE)
[1909]             && addr[i].nregex == 0
[1910] #endif
[1911]             )
[1912]         {
[1913]             continue;
[1914]         }
[1915] 
[1916]         vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
[1917]         if (vn == NULL) {
[1918]             return NGX_ERROR;
[1919]         }
[1920] 
[1921]         addrs[i].conf.virtual_names = vn;
[1922] 
[1923]         vn->names.hash = addr[i].hash;
[1924]         vn->names.wc_head = addr[i].wc_head;
[1925]         vn->names.wc_tail = addr[i].wc_tail;
[1926] #if (NGX_PCRE)
[1927]         vn->nregex = addr[i].nregex;
[1928]         vn->regex = addr[i].regex;
[1929] #endif
[1930]     }
[1931] 
[1932]     return NGX_OK;
[1933] }
[1934] 
[1935] 
[1936] #if (NGX_HAVE_INET6)
[1937] 
[1938] static ngx_int_t
[1939] ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
[1940]     ngx_http_conf_addr_t *addr)
[1941] {
[1942]     ngx_uint_t                 i;
[1943]     ngx_http_in6_addr_t       *addrs6;
[1944]     struct sockaddr_in6       *sin6;
[1945]     ngx_http_virtual_names_t  *vn;
[1946] 
[1947]     hport->addrs = ngx_pcalloc(cf->pool,
[1948]                                hport->naddrs * sizeof(ngx_http_in6_addr_t));
[1949]     if (hport->addrs == NULL) {
[1950]         return NGX_ERROR;
[1951]     }
[1952] 
[1953]     addrs6 = hport->addrs;
[1954] 
[1955]     for (i = 0; i < hport->naddrs; i++) {
[1956] 
[1957]         sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
[1958]         addrs6[i].addr6 = sin6->sin6_addr;
[1959]         addrs6[i].conf.default_server = addr[i].default_server;
[1960] #if (NGX_HTTP_SSL)
[1961]         addrs6[i].conf.ssl = addr[i].opt.ssl;
[1962] #endif
[1963] #if (NGX_HTTP_V2)
[1964]         addrs6[i].conf.http2 = addr[i].opt.http2;
[1965] #endif
[1966]         addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
[1967] 
[1968]         if (addr[i].hash.buckets == NULL
[1969]             && (addr[i].wc_head == NULL
[1970]                 || addr[i].wc_head->hash.buckets == NULL)
[1971]             && (addr[i].wc_tail == NULL
[1972]                 || addr[i].wc_tail->hash.buckets == NULL)
[1973] #if (NGX_PCRE)
[1974]             && addr[i].nregex == 0
[1975] #endif
[1976]             )
[1977]         {
[1978]             continue;
[1979]         }
[1980] 
[1981]         vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
[1982]         if (vn == NULL) {
[1983]             return NGX_ERROR;
[1984]         }
[1985] 
[1986]         addrs6[i].conf.virtual_names = vn;
[1987] 
[1988]         vn->names.hash = addr[i].hash;
[1989]         vn->names.wc_head = addr[i].wc_head;
[1990]         vn->names.wc_tail = addr[i].wc_tail;
[1991] #if (NGX_PCRE)
[1992]         vn->nregex = addr[i].nregex;
[1993]         vn->regex = addr[i].regex;
[1994] #endif
[1995]     }
[1996] 
[1997]     return NGX_OK;
[1998] }
[1999] 
[2000] #endif
[2001] 
[2002] 
[2003] char *
[2004] ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[2005] {
[2006]     char  *p = conf;
[2007] 
[2008]     ngx_array_t     **types;
[2009]     ngx_str_t        *value, *default_type;
[2010]     ngx_uint_t        i, n, hash;
[2011]     ngx_hash_key_t   *type;
[2012] 
[2013]     types = (ngx_array_t **) (p + cmd->offset);
[2014] 
[2015]     if (*types == (void *) -1) {
[2016]         return NGX_CONF_OK;
[2017]     }
[2018] 
[2019]     default_type = cmd->post;
[2020] 
[2021]     if (*types == NULL) {
[2022]         *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
[2023]         if (*types == NULL) {
[2024]             return NGX_CONF_ERROR;
[2025]         }
[2026] 
[2027]         if (default_type) {
[2028]             type = ngx_array_push(*types);
[2029]             if (type == NULL) {
[2030]                 return NGX_CONF_ERROR;
[2031]             }
[2032] 
[2033]             type->key = *default_type;
[2034]             type->key_hash = ngx_hash_key(default_type->data,
[2035]                                           default_type->len);
[2036]             type->value = (void *) 4;
[2037]         }
[2038]     }
[2039] 
[2040]     value = cf->args->elts;
[2041] 
[2042]     for (i = 1; i < cf->args->nelts; i++) {
[2043] 
[2044]         if (value[i].len == 1 && value[i].data[0] == '*') {
[2045]             *types = (void *) -1;
[2046]             return NGX_CONF_OK;
[2047]         }
[2048] 
[2049]         hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);
[2050]         value[i].data[value[i].len] = '\0';
[2051] 
[2052]         type = (*types)->elts;
[2053]         for (n = 0; n < (*types)->nelts; n++) {
[2054] 
[2055]             if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
[2056]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[2057]                                    "duplicate MIME type \"%V\"", &value[i]);
[2058]                 goto next;
[2059]             }
[2060]         }
[2061] 
[2062]         type = ngx_array_push(*types);
[2063]         if (type == NULL) {
[2064]             return NGX_CONF_ERROR;
[2065]         }
[2066] 
[2067]         type->key = value[i];
[2068]         type->key_hash = hash;
[2069]         type->value = (void *) 4;
[2070] 
[2071]     next:
[2072] 
[2073]         continue;
[2074]     }
[2075] 
[2076]     return NGX_CONF_OK;
[2077] }
[2078] 
[2079] 
[2080] char *
[2081] ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t **keys, ngx_hash_t *types_hash,
[2082]     ngx_array_t **prev_keys, ngx_hash_t *prev_types_hash,
[2083]     ngx_str_t *default_types)
[2084] {
[2085]     ngx_hash_init_t  hash;
[2086] 
[2087]     if (*keys) {
[2088] 
[2089]         if (*keys == (void *) -1) {
[2090]             return NGX_CONF_OK;
[2091]         }
[2092] 
[2093]         hash.hash = types_hash;
[2094]         hash.key = NULL;
[2095]         hash.max_size = 2048;
[2096]         hash.bucket_size = 64;
[2097]         hash.name = "test_types_hash";
[2098]         hash.pool = cf->pool;
[2099]         hash.temp_pool = NULL;
[2100] 
[2101]         if (ngx_hash_init(&hash, (*keys)->elts, (*keys)->nelts) != NGX_OK) {
[2102]             return NGX_CONF_ERROR;
[2103]         }
[2104] 
[2105]         return NGX_CONF_OK;
[2106]     }
[2107] 
[2108]     if (prev_types_hash->buckets == NULL) {
[2109] 
[2110]         if (*prev_keys == NULL) {
[2111] 
[2112]             if (ngx_http_set_default_types(cf, prev_keys, default_types)
[2113]                 != NGX_OK)
[2114]             {
[2115]                 return NGX_CONF_ERROR;
[2116]             }
[2117] 
[2118]         } else if (*prev_keys == (void *) -1) {
[2119]             *keys = *prev_keys;
[2120]             return NGX_CONF_OK;
[2121]         }
[2122] 
[2123]         hash.hash = prev_types_hash;
[2124]         hash.key = NULL;
[2125]         hash.max_size = 2048;
[2126]         hash.bucket_size = 64;
[2127]         hash.name = "test_types_hash";
[2128]         hash.pool = cf->pool;
[2129]         hash.temp_pool = NULL;
[2130] 
[2131]         if (ngx_hash_init(&hash, (*prev_keys)->elts, (*prev_keys)->nelts)
[2132]             != NGX_OK)
[2133]         {
[2134]             return NGX_CONF_ERROR;
[2135]         }
[2136]     }
[2137] 
[2138]     *types_hash = *prev_types_hash;
[2139] 
[2140]     return NGX_CONF_OK;
[2141] 
[2142] }
[2143] 
[2144] 
[2145] ngx_int_t
[2146] ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
[2147]     ngx_str_t *default_type)
[2148] {
[2149]     ngx_hash_key_t  *type;
[2150] 
[2151]     *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
[2152]     if (*types == NULL) {
[2153]         return NGX_ERROR;
[2154]     }
[2155] 
[2156]     while (default_type->len) {
[2157] 
[2158]         type = ngx_array_push(*types);
[2159]         if (type == NULL) {
[2160]             return NGX_ERROR;
[2161]         }
[2162] 
[2163]         type->key = *default_type;
[2164]         type->key_hash = ngx_hash_key(default_type->data,
[2165]                                       default_type->len);
[2166]         type->value = (void *) 4;
[2167] 
[2168]         default_type++;
[2169]     }
[2170] 
[2171]     return NGX_OK;
[2172] }
