[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] static ngx_int_t ngx_stream_upstream_add_variables(ngx_conf_t *cf);
[14] static ngx_int_t ngx_stream_upstream_addr_variable(ngx_stream_session_t *s,
[15]     ngx_stream_variable_value_t *v, uintptr_t data);
[16] static ngx_int_t ngx_stream_upstream_response_time_variable(
[17]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[18] static ngx_int_t ngx_stream_upstream_bytes_variable(ngx_stream_session_t *s,
[19]     ngx_stream_variable_value_t *v, uintptr_t data);
[20] 
[21] static char *ngx_stream_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
[22]     void *dummy);
[23] static char *ngx_stream_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
[24]     void *conf);
[25] static void *ngx_stream_upstream_create_main_conf(ngx_conf_t *cf);
[26] static char *ngx_stream_upstream_init_main_conf(ngx_conf_t *cf, void *conf);
[27] 
[28] 
[29] static ngx_command_t  ngx_stream_upstream_commands[] = {
[30] 
[31]     { ngx_string("upstream"),
[32]       NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
[33]       ngx_stream_upstream,
[34]       0,
[35]       0,
[36]       NULL },
[37] 
[38]     { ngx_string("server"),
[39]       NGX_STREAM_UPS_CONF|NGX_CONF_1MORE,
[40]       ngx_stream_upstream_server,
[41]       NGX_STREAM_SRV_CONF_OFFSET,
[42]       0,
[43]       NULL },
[44] 
[45]       ngx_null_command
[46] };
[47] 
[48] 
[49] static ngx_stream_module_t  ngx_stream_upstream_module_ctx = {
[50]     ngx_stream_upstream_add_variables,     /* preconfiguration */
[51]     NULL,                                  /* postconfiguration */
[52] 
[53]     ngx_stream_upstream_create_main_conf,  /* create main configuration */
[54]     ngx_stream_upstream_init_main_conf,    /* init main configuration */
[55] 
[56]     NULL,                                  /* create server configuration */
[57]     NULL                                   /* merge server configuration */
[58] };
[59] 
[60] 
[61] ngx_module_t  ngx_stream_upstream_module = {
[62]     NGX_MODULE_V1,
[63]     &ngx_stream_upstream_module_ctx,       /* module context */
[64]     ngx_stream_upstream_commands,          /* module directives */
[65]     NGX_STREAM_MODULE,                     /* module type */
[66]     NULL,                                  /* init master */
[67]     NULL,                                  /* init module */
[68]     NULL,                                  /* init process */
[69]     NULL,                                  /* init thread */
[70]     NULL,                                  /* exit thread */
[71]     NULL,                                  /* exit process */
[72]     NULL,                                  /* exit master */
[73]     NGX_MODULE_V1_PADDING
[74] };
[75] 
[76] 
[77] static ngx_stream_variable_t  ngx_stream_upstream_vars[] = {
[78] 
[79]     { ngx_string("upstream_addr"), NULL,
[80]       ngx_stream_upstream_addr_variable, 0,
[81]       NGX_STREAM_VAR_NOCACHEABLE, 0 },
[82] 
[83]     { ngx_string("upstream_bytes_sent"), NULL,
[84]       ngx_stream_upstream_bytes_variable, 0,
[85]       NGX_STREAM_VAR_NOCACHEABLE, 0 },
[86] 
[87]     { ngx_string("upstream_connect_time"), NULL,
[88]       ngx_stream_upstream_response_time_variable, 2,
[89]       NGX_STREAM_VAR_NOCACHEABLE, 0 },
[90] 
[91]     { ngx_string("upstream_first_byte_time"), NULL,
[92]       ngx_stream_upstream_response_time_variable, 1,
[93]       NGX_STREAM_VAR_NOCACHEABLE, 0 },
[94] 
[95]     { ngx_string("upstream_session_time"), NULL,
[96]       ngx_stream_upstream_response_time_variable, 0,
[97]       NGX_STREAM_VAR_NOCACHEABLE, 0 },
[98] 
[99]     { ngx_string("upstream_bytes_received"), NULL,
[100]       ngx_stream_upstream_bytes_variable, 1,
[101]       NGX_STREAM_VAR_NOCACHEABLE, 0 },
[102] 
[103]       ngx_stream_null_variable
[104] };
[105] 
[106] 
[107] static ngx_int_t
[108] ngx_stream_upstream_add_variables(ngx_conf_t *cf)
[109] {
[110]     ngx_stream_variable_t  *var, *v;
[111] 
[112]     for (v = ngx_stream_upstream_vars; v->name.len; v++) {
[113]         var = ngx_stream_add_variable(cf, &v->name, v->flags);
[114]         if (var == NULL) {
[115]             return NGX_ERROR;
[116]         }
[117] 
[118]         var->get_handler = v->get_handler;
[119]         var->data = v->data;
[120]     }
[121] 
[122]     return NGX_OK;
[123] }
[124] 
[125] 
[126] static ngx_int_t
[127] ngx_stream_upstream_addr_variable(ngx_stream_session_t *s,
[128]     ngx_stream_variable_value_t *v, uintptr_t data)
[129] {
[130]     u_char                       *p;
[131]     size_t                        len;
[132]     ngx_uint_t                    i;
[133]     ngx_stream_upstream_state_t  *state;
[134] 
[135]     v->valid = 1;
[136]     v->no_cacheable = 0;
[137]     v->not_found = 0;
[138] 
[139]     if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
[140]         v->not_found = 1;
[141]         return NGX_OK;
[142]     }
[143] 
[144]     len = 0;
[145]     state = s->upstream_states->elts;
[146] 
[147]     for (i = 0; i < s->upstream_states->nelts; i++) {
[148]         if (state[i].peer) {
[149]             len += state[i].peer->len;
[150]         }
[151] 
[152]         len += 2;
[153]     }
[154] 
[155]     p = ngx_pnalloc(s->connection->pool, len);
[156]     if (p == NULL) {
[157]         return NGX_ERROR;
[158]     }
[159] 
[160]     v->data = p;
[161] 
[162]     i = 0;
[163] 
[164]     for ( ;; ) {
[165]         if (state[i].peer) {
[166]             p = ngx_cpymem(p, state[i].peer->data, state[i].peer->len);
[167]         }
[168] 
[169]         if (++i == s->upstream_states->nelts) {
[170]             break;
[171]         }
[172] 
[173]         *p++ = ',';
[174]         *p++ = ' ';
[175]     }
[176] 
[177]     v->len = p - v->data;
[178] 
[179]     return NGX_OK;
[180] }
[181] 
[182] 
[183] static ngx_int_t
[184] ngx_stream_upstream_bytes_variable(ngx_stream_session_t *s,
[185]     ngx_stream_variable_value_t *v, uintptr_t data)
[186] {
[187]     u_char                       *p;
[188]     size_t                        len;
[189]     ngx_uint_t                    i;
[190]     ngx_stream_upstream_state_t  *state;
[191] 
[192]     v->valid = 1;
[193]     v->no_cacheable = 0;
[194]     v->not_found = 0;
[195] 
[196]     if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
[197]         v->not_found = 1;
[198]         return NGX_OK;
[199]     }
[200] 
[201]     len = s->upstream_states->nelts * (NGX_OFF_T_LEN + 2);
[202] 
[203]     p = ngx_pnalloc(s->connection->pool, len);
[204]     if (p == NULL) {
[205]         return NGX_ERROR;
[206]     }
[207] 
[208]     v->data = p;
[209] 
[210]     i = 0;
[211]     state = s->upstream_states->elts;
[212] 
[213]     for ( ;; ) {
[214] 
[215]         if (data == 1) {
[216]             p = ngx_sprintf(p, "%O", state[i].bytes_received);
[217] 
[218]         } else {
[219]             p = ngx_sprintf(p, "%O", state[i].bytes_sent);
[220]         }
[221] 
[222]         if (++i == s->upstream_states->nelts) {
[223]             break;
[224]         }
[225] 
[226]         *p++ = ',';
[227]         *p++ = ' ';
[228]     }
[229] 
[230]     v->len = p - v->data;
[231] 
[232]     return NGX_OK;
[233] }
[234] 
[235] 
[236] static ngx_int_t
[237] ngx_stream_upstream_response_time_variable(ngx_stream_session_t *s,
[238]     ngx_stream_variable_value_t *v, uintptr_t data)
[239] {
[240]     u_char                       *p;
[241]     size_t                        len;
[242]     ngx_uint_t                    i;
[243]     ngx_msec_int_t                ms;
[244]     ngx_stream_upstream_state_t  *state;
[245] 
[246]     v->valid = 1;
[247]     v->no_cacheable = 0;
[248]     v->not_found = 0;
[249] 
[250]     if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
[251]         v->not_found = 1;
[252]         return NGX_OK;
[253]     }
[254] 
[255]     len = s->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);
[256] 
[257]     p = ngx_pnalloc(s->connection->pool, len);
[258]     if (p == NULL) {
[259]         return NGX_ERROR;
[260]     }
[261] 
[262]     v->data = p;
[263] 
[264]     i = 0;
[265]     state = s->upstream_states->elts;
[266] 
[267]     for ( ;; ) {
[268] 
[269]         if (data == 1) {
[270]             ms = state[i].first_byte_time;
[271] 
[272]         } else if (data == 2) {
[273]             ms = state[i].connect_time;
[274] 
[275]         } else {
[276]             ms = state[i].response_time;
[277]         }
[278] 
[279]         if (ms != -1) {
[280]             ms = ngx_max(ms, 0);
[281]             p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);
[282] 
[283]         } else {
[284]             *p++ = '-';
[285]         }
[286] 
[287]         if (++i == s->upstream_states->nelts) {
[288]             break;
[289]         }
[290] 
[291]         *p++ = ',';
[292]         *p++ = ' ';
[293]     }
[294] 
[295]     v->len = p - v->data;
[296] 
[297]     return NGX_OK;
[298] }
[299] 
[300] 
[301] static char *
[302] ngx_stream_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
[303] {
[304]     char                            *rv;
[305]     void                            *mconf;
[306]     ngx_str_t                       *value;
[307]     ngx_url_t                        u;
[308]     ngx_uint_t                       m;
[309]     ngx_conf_t                       pcf;
[310]     ngx_stream_module_t             *module;
[311]     ngx_stream_conf_ctx_t           *ctx, *stream_ctx;
[312]     ngx_stream_upstream_srv_conf_t  *uscf;
[313] 
[314]     ngx_memzero(&u, sizeof(ngx_url_t));
[315] 
[316]     value = cf->args->elts;
[317]     u.host = value[1];
[318]     u.no_resolve = 1;
[319]     u.no_port = 1;
[320] 
[321]     uscf = ngx_stream_upstream_add(cf, &u, NGX_STREAM_UPSTREAM_CREATE
[322]                                            |NGX_STREAM_UPSTREAM_WEIGHT
[323]                                            |NGX_STREAM_UPSTREAM_MAX_CONNS
[324]                                            |NGX_STREAM_UPSTREAM_MAX_FAILS
[325]                                            |NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
[326]                                            |NGX_STREAM_UPSTREAM_DOWN
[327]                                            |NGX_STREAM_UPSTREAM_BACKUP);
[328]     if (uscf == NULL) {
[329]         return NGX_CONF_ERROR;
[330]     }
[331] 
[332] 
[333]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
[334]     if (ctx == NULL) {
[335]         return NGX_CONF_ERROR;
[336]     }
[337] 
[338]     stream_ctx = cf->ctx;
[339]     ctx->main_conf = stream_ctx->main_conf;
[340] 
[341]     /* the upstream{}'s srv_conf */
[342] 
[343]     ctx->srv_conf = ngx_pcalloc(cf->pool,
[344]                                 sizeof(void *) * ngx_stream_max_module);
[345]     if (ctx->srv_conf == NULL) {
[346]         return NGX_CONF_ERROR;
[347]     }
[348] 
[349]     ctx->srv_conf[ngx_stream_upstream_module.ctx_index] = uscf;
[350] 
[351]     uscf->srv_conf = ctx->srv_conf;
[352] 
[353]     for (m = 0; cf->cycle->modules[m]; m++) {
[354]         if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
[355]             continue;
[356]         }
[357] 
[358]         module = cf->cycle->modules[m]->ctx;
[359] 
[360]         if (module->create_srv_conf) {
[361]             mconf = module->create_srv_conf(cf);
[362]             if (mconf == NULL) {
[363]                 return NGX_CONF_ERROR;
[364]             }
[365] 
[366]             ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
[367]         }
[368]     }
[369] 
[370]     uscf->servers = ngx_array_create(cf->pool, 4,
[371]                                      sizeof(ngx_stream_upstream_server_t));
[372]     if (uscf->servers == NULL) {
[373]         return NGX_CONF_ERROR;
[374]     }
[375] 
[376] 
[377]     /* parse inside upstream{} */
[378] 
[379]     pcf = *cf;
[380]     cf->ctx = ctx;
[381]     cf->cmd_type = NGX_STREAM_UPS_CONF;
[382] 
[383]     rv = ngx_conf_parse(cf, NULL);
[384] 
[385]     *cf = pcf;
[386] 
[387]     if (rv != NGX_CONF_OK) {
[388]         return rv;
[389]     }
[390] 
[391]     if (uscf->servers->nelts == 0) {
[392]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[393]                            "no servers are inside upstream");
[394]         return NGX_CONF_ERROR;
[395]     }
[396] 
[397]     return rv;
[398] }
[399] 
[400] 
[401] static char *
[402] ngx_stream_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[403] {
[404]     ngx_stream_upstream_srv_conf_t  *uscf = conf;
[405] 
[406]     time_t                         fail_timeout;
[407]     ngx_str_t                     *value, s;
[408]     ngx_url_t                      u;
[409]     ngx_int_t                      weight, max_conns, max_fails;
[410]     ngx_uint_t                     i;
[411]     ngx_stream_upstream_server_t  *us;
[412] 
[413]     us = ngx_array_push(uscf->servers);
[414]     if (us == NULL) {
[415]         return NGX_CONF_ERROR;
[416]     }
[417] 
[418]     ngx_memzero(us, sizeof(ngx_stream_upstream_server_t));
[419] 
[420]     value = cf->args->elts;
[421] 
[422]     weight = 1;
[423]     max_conns = 0;
[424]     max_fails = 1;
[425]     fail_timeout = 10;
[426] 
[427]     for (i = 2; i < cf->args->nelts; i++) {
[428] 
[429]         if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
[430] 
[431]             if (!(uscf->flags & NGX_STREAM_UPSTREAM_WEIGHT)) {
[432]                 goto not_supported;
[433]             }
[434] 
[435]             weight = ngx_atoi(&value[i].data[7], value[i].len - 7);
[436] 
[437]             if (weight == NGX_ERROR || weight == 0) {
[438]                 goto invalid;
[439]             }
[440] 
[441]             continue;
[442]         }
[443] 
[444]         if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {
[445] 
[446]             if (!(uscf->flags & NGX_STREAM_UPSTREAM_MAX_CONNS)) {
[447]                 goto not_supported;
[448]             }
[449] 
[450]             max_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);
[451] 
[452]             if (max_conns == NGX_ERROR) {
[453]                 goto invalid;
[454]             }
[455] 
[456]             continue;
[457]         }
[458] 
[459]         if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
[460] 
[461]             if (!(uscf->flags & NGX_STREAM_UPSTREAM_MAX_FAILS)) {
[462]                 goto not_supported;
[463]             }
[464] 
[465]             max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);
[466] 
[467]             if (max_fails == NGX_ERROR) {
[468]                 goto invalid;
[469]             }
[470] 
[471]             continue;
[472]         }
[473] 
[474]         if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {
[475] 
[476]             if (!(uscf->flags & NGX_STREAM_UPSTREAM_FAIL_TIMEOUT)) {
[477]                 goto not_supported;
[478]             }
[479] 
[480]             s.len = value[i].len - 13;
[481]             s.data = &value[i].data[13];
[482] 
[483]             fail_timeout = ngx_parse_time(&s, 1);
[484] 
[485]             if (fail_timeout == (time_t) NGX_ERROR) {
[486]                 goto invalid;
[487]             }
[488] 
[489]             continue;
[490]         }
[491] 
[492]         if (ngx_strcmp(value[i].data, "backup") == 0) {
[493] 
[494]             if (!(uscf->flags & NGX_STREAM_UPSTREAM_BACKUP)) {
[495]                 goto not_supported;
[496]             }
[497] 
[498]             us->backup = 1;
[499] 
[500]             continue;
[501]         }
[502] 
[503]         if (ngx_strcmp(value[i].data, "down") == 0) {
[504] 
[505]             if (!(uscf->flags & NGX_STREAM_UPSTREAM_DOWN)) {
[506]                 goto not_supported;
[507]             }
[508] 
[509]             us->down = 1;
[510] 
[511]             continue;
[512]         }
[513] 
[514]         goto invalid;
[515]     }
[516] 
[517]     ngx_memzero(&u, sizeof(ngx_url_t));
[518] 
[519]     u.url = value[1];
[520] 
[521]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[522]         if (u.err) {
[523]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[524]                                "%s in upstream \"%V\"", u.err, &u.url);
[525]         }
[526] 
[527]         return NGX_CONF_ERROR;
[528]     }
[529] 
[530]     if (u.no_port) {
[531]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[532]                            "no port in upstream \"%V\"", &u.url);
[533]         return NGX_CONF_ERROR;
[534]     }
[535] 
[536]     us->name = u.url;
[537]     us->addrs = u.addrs;
[538]     us->naddrs = u.naddrs;
[539]     us->weight = weight;
[540]     us->max_conns = max_conns;
[541]     us->max_fails = max_fails;
[542]     us->fail_timeout = fail_timeout;
[543] 
[544]     return NGX_CONF_OK;
[545] 
[546] invalid:
[547] 
[548]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[549]                        "invalid parameter \"%V\"", &value[i]);
[550] 
[551]     return NGX_CONF_ERROR;
[552] 
[553] not_supported:
[554] 
[555]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[556]                        "balancing method does not support parameter \"%V\"",
[557]                        &value[i]);
[558] 
[559]     return NGX_CONF_ERROR;
[560] }
[561] 
[562] 
[563] ngx_stream_upstream_srv_conf_t *
[564] ngx_stream_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
[565] {
[566]     ngx_uint_t                        i;
[567]     ngx_stream_upstream_server_t     *us;
[568]     ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
[569]     ngx_stream_upstream_main_conf_t  *umcf;
[570] 
[571]     if (!(flags & NGX_STREAM_UPSTREAM_CREATE)) {
[572] 
[573]         if (ngx_parse_url(cf->pool, u) != NGX_OK) {
[574]             if (u->err) {
[575]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[576]                                    "%s in upstream \"%V\"", u->err, &u->url);
[577]             }
[578] 
[579]             return NULL;
[580]         }
[581]     }
[582] 
[583]     umcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_upstream_module);
[584] 
[585]     uscfp = umcf->upstreams.elts;
[586] 
[587]     for (i = 0; i < umcf->upstreams.nelts; i++) {
[588] 
[589]         if (uscfp[i]->host.len != u->host.len
[590]             || ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
[591]                != 0)
[592]         {
[593]             continue;
[594]         }
[595] 
[596]         if ((flags & NGX_STREAM_UPSTREAM_CREATE)
[597]              && (uscfp[i]->flags & NGX_STREAM_UPSTREAM_CREATE))
[598]         {
[599]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[600]                                "duplicate upstream \"%V\"", &u->host);
[601]             return NULL;
[602]         }
[603] 
[604]         if ((uscfp[i]->flags & NGX_STREAM_UPSTREAM_CREATE) && !u->no_port) {
[605]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[606]                                "upstream \"%V\" may not have port %d",
[607]                                &u->host, u->port);
[608]             return NULL;
[609]         }
[610] 
[611]         if ((flags & NGX_STREAM_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
[612]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[613]                           "upstream \"%V\" may not have port %d in %s:%ui",
[614]                           &u->host, uscfp[i]->port,
[615]                           uscfp[i]->file_name, uscfp[i]->line);
[616]             return NULL;
[617]         }
[618] 
[619]         if (uscfp[i]->port != u->port) {
[620]             continue;
[621]         }
[622] 
[623]         if (flags & NGX_STREAM_UPSTREAM_CREATE) {
[624]             uscfp[i]->flags = flags;
[625]         }
[626] 
[627]         return uscfp[i];
[628]     }
[629] 
[630]     uscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_srv_conf_t));
[631]     if (uscf == NULL) {
[632]         return NULL;
[633]     }
[634] 
[635]     uscf->flags = flags;
[636]     uscf->host = u->host;
[637]     uscf->file_name = cf->conf_file->file.name.data;
[638]     uscf->line = cf->conf_file->line;
[639]     uscf->port = u->port;
[640]     uscf->no_port = u->no_port;
[641] 
[642]     if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
[643]         uscf->servers = ngx_array_create(cf->pool, 1,
[644]                                          sizeof(ngx_stream_upstream_server_t));
[645]         if (uscf->servers == NULL) {
[646]             return NULL;
[647]         }
[648] 
[649]         us = ngx_array_push(uscf->servers);
[650]         if (us == NULL) {
[651]             return NULL;
[652]         }
[653] 
[654]         ngx_memzero(us, sizeof(ngx_stream_upstream_server_t));
[655] 
[656]         us->addrs = u->addrs;
[657]         us->naddrs = 1;
[658]     }
[659] 
[660]     uscfp = ngx_array_push(&umcf->upstreams);
[661]     if (uscfp == NULL) {
[662]         return NULL;
[663]     }
[664] 
[665]     *uscfp = uscf;
[666] 
[667]     return uscf;
[668] }
[669] 
[670] 
[671] static void *
[672] ngx_stream_upstream_create_main_conf(ngx_conf_t *cf)
[673] {
[674]     ngx_stream_upstream_main_conf_t  *umcf;
[675] 
[676]     umcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_main_conf_t));
[677]     if (umcf == NULL) {
[678]         return NULL;
[679]     }
[680] 
[681]     if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
[682]                        sizeof(ngx_stream_upstream_srv_conf_t *))
[683]         != NGX_OK)
[684]     {
[685]         return NULL;
[686]     }
[687] 
[688]     return umcf;
[689] }
[690] 
[691] 
[692] static char *
[693] ngx_stream_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
[694] {
[695]     ngx_stream_upstream_main_conf_t *umcf = conf;
[696] 
[697]     ngx_uint_t                        i;
[698]     ngx_stream_upstream_init_pt       init;
[699]     ngx_stream_upstream_srv_conf_t  **uscfp;
[700] 
[701]     uscfp = umcf->upstreams.elts;
[702] 
[703]     for (i = 0; i < umcf->upstreams.nelts; i++) {
[704] 
[705]         init = uscfp[i]->peer.init_upstream
[706]                                          ? uscfp[i]->peer.init_upstream
[707]                                          : ngx_stream_upstream_init_round_robin;
[708] 
[709]         if (init(cf, uscfp[i]) != NGX_OK) {
[710]             return NGX_CONF_ERROR;
[711]         }
[712]     }
[713] 
[714]     return NGX_CONF_OK;
[715] }
