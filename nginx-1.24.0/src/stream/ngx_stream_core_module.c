[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] static ngx_int_t ngx_stream_core_preconfiguration(ngx_conf_t *cf);
[14] static void *ngx_stream_core_create_main_conf(ngx_conf_t *cf);
[15] static char *ngx_stream_core_init_main_conf(ngx_conf_t *cf, void *conf);
[16] static void *ngx_stream_core_create_srv_conf(ngx_conf_t *cf);
[17] static char *ngx_stream_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
[18]     void *child);
[19] static char *ngx_stream_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
[20]     void *conf);
[21] static char *ngx_stream_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
[22]     void *conf);
[23] static char *ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
[24]     void *conf);
[25] static char *ngx_stream_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
[26]     void *conf);
[27] 
[28] 
[29] static ngx_command_t  ngx_stream_core_commands[] = {
[30] 
[31]     { ngx_string("variables_hash_max_size"),
[32]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
[33]       ngx_conf_set_num_slot,
[34]       NGX_STREAM_MAIN_CONF_OFFSET,
[35]       offsetof(ngx_stream_core_main_conf_t, variables_hash_max_size),
[36]       NULL },
[37] 
[38]     { ngx_string("variables_hash_bucket_size"),
[39]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
[40]       ngx_conf_set_num_slot,
[41]       NGX_STREAM_MAIN_CONF_OFFSET,
[42]       offsetof(ngx_stream_core_main_conf_t, variables_hash_bucket_size),
[43]       NULL },
[44] 
[45]     { ngx_string("server"),
[46]       NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
[47]       ngx_stream_core_server,
[48]       0,
[49]       0,
[50]       NULL },
[51] 
[52]     { ngx_string("listen"),
[53]       NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[54]       ngx_stream_core_listen,
[55]       NGX_STREAM_SRV_CONF_OFFSET,
[56]       0,
[57]       NULL },
[58] 
[59]     { ngx_string("error_log"),
[60]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[61]       ngx_stream_core_error_log,
[62]       NGX_STREAM_SRV_CONF_OFFSET,
[63]       0,
[64]       NULL },
[65] 
[66]     { ngx_string("resolver"),
[67]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[68]       ngx_stream_core_resolver,
[69]       NGX_STREAM_SRV_CONF_OFFSET,
[70]       0,
[71]       NULL },
[72] 
[73]     { ngx_string("resolver_timeout"),
[74]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[75]       ngx_conf_set_msec_slot,
[76]       NGX_STREAM_SRV_CONF_OFFSET,
[77]       offsetof(ngx_stream_core_srv_conf_t, resolver_timeout),
[78]       NULL },
[79] 
[80]     { ngx_string("proxy_protocol_timeout"),
[81]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[82]       ngx_conf_set_msec_slot,
[83]       NGX_STREAM_SRV_CONF_OFFSET,
[84]       offsetof(ngx_stream_core_srv_conf_t, proxy_protocol_timeout),
[85]       NULL },
[86] 
[87]     { ngx_string("tcp_nodelay"),
[88]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[89]       ngx_conf_set_flag_slot,
[90]       NGX_STREAM_SRV_CONF_OFFSET,
[91]       offsetof(ngx_stream_core_srv_conf_t, tcp_nodelay),
[92]       NULL },
[93] 
[94]     { ngx_string("preread_buffer_size"),
[95]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[96]       ngx_conf_set_size_slot,
[97]       NGX_STREAM_SRV_CONF_OFFSET,
[98]       offsetof(ngx_stream_core_srv_conf_t, preread_buffer_size),
[99]       NULL },
[100] 
[101]     { ngx_string("preread_timeout"),
[102]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[103]       ngx_conf_set_msec_slot,
[104]       NGX_STREAM_SRV_CONF_OFFSET,
[105]       offsetof(ngx_stream_core_srv_conf_t, preread_timeout),
[106]       NULL },
[107] 
[108]       ngx_null_command
[109] };
[110] 
[111] 
[112] static ngx_stream_module_t  ngx_stream_core_module_ctx = {
[113]     ngx_stream_core_preconfiguration,      /* preconfiguration */
[114]     NULL,                                  /* postconfiguration */
[115] 
[116]     ngx_stream_core_create_main_conf,      /* create main configuration */
[117]     ngx_stream_core_init_main_conf,        /* init main configuration */
[118] 
[119]     ngx_stream_core_create_srv_conf,       /* create server configuration */
[120]     ngx_stream_core_merge_srv_conf         /* merge server configuration */
[121] };
[122] 
[123] 
[124] ngx_module_t  ngx_stream_core_module = {
[125]     NGX_MODULE_V1,
[126]     &ngx_stream_core_module_ctx,           /* module context */
[127]     ngx_stream_core_commands,              /* module directives */
[128]     NGX_STREAM_MODULE,                     /* module type */
[129]     NULL,                                  /* init master */
[130]     NULL,                                  /* init module */
[131]     NULL,                                  /* init process */
[132]     NULL,                                  /* init thread */
[133]     NULL,                                  /* exit thread */
[134]     NULL,                                  /* exit process */
[135]     NULL,                                  /* exit master */
[136]     NGX_MODULE_V1_PADDING
[137] };
[138] 
[139] 
[140] void
[141] ngx_stream_core_run_phases(ngx_stream_session_t *s)
[142] {
[143]     ngx_int_t                     rc;
[144]     ngx_stream_phase_handler_t   *ph;
[145]     ngx_stream_core_main_conf_t  *cmcf;
[146] 
[147]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[148] 
[149]     ph = cmcf->phase_engine.handlers;
[150] 
[151]     while (ph[s->phase_handler].checker) {
[152] 
[153]         rc = ph[s->phase_handler].checker(s, &ph[s->phase_handler]);
[154] 
[155]         if (rc == NGX_OK) {
[156]             return;
[157]         }
[158]     }
[159] }
[160] 
[161] 
[162] ngx_int_t
[163] ngx_stream_core_generic_phase(ngx_stream_session_t *s,
[164]     ngx_stream_phase_handler_t *ph)
[165] {
[166]     ngx_int_t  rc;
[167] 
[168]     /*
[169]      * generic phase checker,
[170]      * used by all phases, except for preread and content
[171]      */
[172] 
[173]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[174]                    "generic phase: %ui", s->phase_handler);
[175] 
[176]     rc = ph->handler(s);
[177] 
[178]     if (rc == NGX_OK) {
[179]         s->phase_handler = ph->next;
[180]         return NGX_AGAIN;
[181]     }
[182] 
[183]     if (rc == NGX_DECLINED) {
[184]         s->phase_handler++;
[185]         return NGX_AGAIN;
[186]     }
[187] 
[188]     if (rc == NGX_AGAIN || rc == NGX_DONE) {
[189]         return NGX_OK;
[190]     }
[191] 
[192]     if (rc == NGX_ERROR) {
[193]         rc = NGX_STREAM_INTERNAL_SERVER_ERROR;
[194]     }
[195] 
[196]     ngx_stream_finalize_session(s, rc);
[197] 
[198]     return NGX_OK;
[199] }
[200] 
[201] 
[202] ngx_int_t
[203] ngx_stream_core_preread_phase(ngx_stream_session_t *s,
[204]     ngx_stream_phase_handler_t *ph)
[205] {
[206]     size_t                       size;
[207]     ssize_t                      n;
[208]     ngx_int_t                    rc;
[209]     ngx_connection_t            *c;
[210]     ngx_stream_core_srv_conf_t  *cscf;
[211] 
[212]     c = s->connection;
[213] 
[214]     c->log->action = "prereading client data";
[215] 
[216]     cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
[217] 
[218]     if (c->read->timedout) {
[219]         rc = NGX_STREAM_OK;
[220] 
[221]     } else if (c->read->timer_set) {
[222]         rc = NGX_AGAIN;
[223] 
[224]     } else {
[225]         rc = ph->handler(s);
[226]     }
[227] 
[228]     while (rc == NGX_AGAIN) {
[229] 
[230]         if (c->buffer == NULL) {
[231]             c->buffer = ngx_create_temp_buf(c->pool, cscf->preread_buffer_size);
[232]             if (c->buffer == NULL) {
[233]                 rc = NGX_ERROR;
[234]                 break;
[235]             }
[236]         }
[237] 
[238]         size = c->buffer->end - c->buffer->last;
[239] 
[240]         if (size == 0) {
[241]             ngx_log_error(NGX_LOG_ERR, c->log, 0, "preread buffer full");
[242]             rc = NGX_STREAM_BAD_REQUEST;
[243]             break;
[244]         }
[245] 
[246]         if (c->read->eof) {
[247]             rc = NGX_STREAM_OK;
[248]             break;
[249]         }
[250] 
[251]         if (!c->read->ready) {
[252]             break;
[253]         }
[254] 
[255]         n = c->recv(c, c->buffer->last, size);
[256] 
[257]         if (n == NGX_ERROR || n == 0) {
[258]             rc = NGX_STREAM_OK;
[259]             break;
[260]         }
[261] 
[262]         if (n == NGX_AGAIN) {
[263]             break;
[264]         }
[265] 
[266]         c->buffer->last += n;
[267] 
[268]         rc = ph->handler(s);
[269]     }
[270] 
[271]     if (rc == NGX_AGAIN) {
[272]         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[273]             ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[274]             return NGX_OK;
[275]         }
[276] 
[277]         if (!c->read->timer_set) {
[278]             ngx_add_timer(c->read, cscf->preread_timeout);
[279]         }
[280] 
[281]         c->read->handler = ngx_stream_session_handler;
[282] 
[283]         return NGX_OK;
[284]     }
[285] 
[286]     if (c->read->timer_set) {
[287]         ngx_del_timer(c->read);
[288]     }
[289] 
[290]     if (rc == NGX_OK) {
[291]         s->phase_handler = ph->next;
[292]         return NGX_AGAIN;
[293]     }
[294] 
[295]     if (rc == NGX_DECLINED) {
[296]         s->phase_handler++;
[297]         return NGX_AGAIN;
[298]     }
[299] 
[300]     if (rc == NGX_DONE) {
[301]         return NGX_OK;
[302]     }
[303] 
[304]     if (rc == NGX_ERROR) {
[305]         rc = NGX_STREAM_INTERNAL_SERVER_ERROR;
[306]     }
[307] 
[308]     ngx_stream_finalize_session(s, rc);
[309] 
[310]     return NGX_OK;
[311] }
[312] 
[313] 
[314] ngx_int_t
[315] ngx_stream_core_content_phase(ngx_stream_session_t *s,
[316]     ngx_stream_phase_handler_t *ph)
[317] {
[318]     ngx_connection_t            *c;
[319]     ngx_stream_core_srv_conf_t  *cscf;
[320] 
[321]     c = s->connection;
[322] 
[323]     c->log->action = NULL;
[324] 
[325]     cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
[326] 
[327]     if (c->type == SOCK_STREAM
[328]         && cscf->tcp_nodelay
[329]         && ngx_tcp_nodelay(c) != NGX_OK)
[330]     {
[331]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[332]         return NGX_OK;
[333]     }
[334] 
[335]     cscf->handler(s);
[336] 
[337]     return NGX_OK;
[338] }
[339] 
[340] 
[341] static ngx_int_t
[342] ngx_stream_core_preconfiguration(ngx_conf_t *cf)
[343] {
[344]     return ngx_stream_variables_add_core_vars(cf);
[345] }
[346] 
[347] 
[348] static void *
[349] ngx_stream_core_create_main_conf(ngx_conf_t *cf)
[350] {
[351]     ngx_stream_core_main_conf_t  *cmcf;
[352] 
[353]     cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_core_main_conf_t));
[354]     if (cmcf == NULL) {
[355]         return NULL;
[356]     }
[357] 
[358]     if (ngx_array_init(&cmcf->servers, cf->pool, 4,
[359]                        sizeof(ngx_stream_core_srv_conf_t *))
[360]         != NGX_OK)
[361]     {
[362]         return NULL;
[363]     }
[364] 
[365]     if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_stream_listen_t))
[366]         != NGX_OK)
[367]     {
[368]         return NULL;
[369]     }
[370] 
[371]     cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
[372]     cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;
[373] 
[374]     return cmcf;
[375] }
[376] 
[377] 
[378] static char *
[379] ngx_stream_core_init_main_conf(ngx_conf_t *cf, void *conf)
[380] {
[381]     ngx_stream_core_main_conf_t *cmcf = conf;
[382] 
[383]     ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
[384]     ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);
[385] 
[386]     cmcf->variables_hash_bucket_size =
[387]                ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);
[388] 
[389]     if (cmcf->ncaptures) {
[390]         cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
[391]     }
[392] 
[393]     return NGX_CONF_OK;
[394] }
[395] 
[396] 
[397] static void *
[398] ngx_stream_core_create_srv_conf(ngx_conf_t *cf)
[399] {
[400]     ngx_stream_core_srv_conf_t  *cscf;
[401] 
[402]     cscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_core_srv_conf_t));
[403]     if (cscf == NULL) {
[404]         return NULL;
[405]     }
[406] 
[407]     /*
[408]      * set by ngx_pcalloc():
[409]      *
[410]      *     cscf->handler = NULL;
[411]      *     cscf->error_log = NULL;
[412]      */
[413] 
[414]     cscf->file_name = cf->conf_file->file.name.data;
[415]     cscf->line = cf->conf_file->line;
[416]     cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
[417]     cscf->proxy_protocol_timeout = NGX_CONF_UNSET_MSEC;
[418]     cscf->tcp_nodelay = NGX_CONF_UNSET;
[419]     cscf->preread_buffer_size = NGX_CONF_UNSET_SIZE;
[420]     cscf->preread_timeout = NGX_CONF_UNSET_MSEC;
[421] 
[422]     return cscf;
[423] }
[424] 
[425] 
[426] static char *
[427] ngx_stream_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[428] {
[429]     ngx_stream_core_srv_conf_t *prev = parent;
[430]     ngx_stream_core_srv_conf_t *conf = child;
[431] 
[432]     ngx_conf_merge_msec_value(conf->resolver_timeout,
[433]                               prev->resolver_timeout, 30000);
[434] 
[435]     if (conf->resolver == NULL) {
[436] 
[437]         if (prev->resolver == NULL) {
[438] 
[439]             /*
[440]              * create dummy resolver in stream {} context
[441]              * to inherit it in all servers
[442]              */
[443] 
[444]             prev->resolver = ngx_resolver_create(cf, NULL, 0);
[445]             if (prev->resolver == NULL) {
[446]                 return NGX_CONF_ERROR;
[447]             }
[448]         }
[449] 
[450]         conf->resolver = prev->resolver;
[451]     }
[452] 
[453]     if (conf->handler == NULL) {
[454]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[455]                       "no handler for server in %s:%ui",
[456]                       conf->file_name, conf->line);
[457]         return NGX_CONF_ERROR;
[458]     }
[459] 
[460]     if (conf->error_log == NULL) {
[461]         if (prev->error_log) {
[462]             conf->error_log = prev->error_log;
[463]         } else {
[464]             conf->error_log = &cf->cycle->new_log;
[465]         }
[466]     }
[467] 
[468]     ngx_conf_merge_msec_value(conf->proxy_protocol_timeout,
[469]                               prev->proxy_protocol_timeout, 30000);
[470] 
[471]     ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);
[472] 
[473]     ngx_conf_merge_size_value(conf->preread_buffer_size,
[474]                               prev->preread_buffer_size, 16384);
[475] 
[476]     ngx_conf_merge_msec_value(conf->preread_timeout,
[477]                               prev->preread_timeout, 30000);
[478] 
[479]     return NGX_CONF_OK;
[480] }
[481] 
[482] 
[483] static char *
[484] ngx_stream_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[485] {
[486]     ngx_stream_core_srv_conf_t  *cscf = conf;
[487] 
[488]     return ngx_log_set_log(cf, &cscf->error_log);
[489] }
[490] 
[491] 
[492] static char *
[493] ngx_stream_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[494] {
[495]     char                         *rv;
[496]     void                         *mconf;
[497]     ngx_uint_t                    m;
[498]     ngx_conf_t                    pcf;
[499]     ngx_stream_module_t          *module;
[500]     ngx_stream_conf_ctx_t        *ctx, *stream_ctx;
[501]     ngx_stream_core_srv_conf_t   *cscf, **cscfp;
[502]     ngx_stream_core_main_conf_t  *cmcf;
[503] 
[504]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
[505]     if (ctx == NULL) {
[506]         return NGX_CONF_ERROR;
[507]     }
[508] 
[509]     stream_ctx = cf->ctx;
[510]     ctx->main_conf = stream_ctx->main_conf;
[511] 
[512]     /* the server{}'s srv_conf */
[513] 
[514]     ctx->srv_conf = ngx_pcalloc(cf->pool,
[515]                                 sizeof(void *) * ngx_stream_max_module);
[516]     if (ctx->srv_conf == NULL) {
[517]         return NGX_CONF_ERROR;
[518]     }
[519] 
[520]     for (m = 0; cf->cycle->modules[m]; m++) {
[521]         if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
[522]             continue;
[523]         }
[524] 
[525]         module = cf->cycle->modules[m]->ctx;
[526] 
[527]         if (module->create_srv_conf) {
[528]             mconf = module->create_srv_conf(cf);
[529]             if (mconf == NULL) {
[530]                 return NGX_CONF_ERROR;
[531]             }
[532] 
[533]             ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
[534]         }
[535]     }
[536] 
[537]     /* the server configuration context */
[538] 
[539]     cscf = ctx->srv_conf[ngx_stream_core_module.ctx_index];
[540]     cscf->ctx = ctx;
[541] 
[542]     cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];
[543] 
[544]     cscfp = ngx_array_push(&cmcf->servers);
[545]     if (cscfp == NULL) {
[546]         return NGX_CONF_ERROR;
[547]     }
[548] 
[549]     *cscfp = cscf;
[550] 
[551] 
[552]     /* parse inside server{} */
[553] 
[554]     pcf = *cf;
[555]     cf->ctx = ctx;
[556]     cf->cmd_type = NGX_STREAM_SRV_CONF;
[557] 
[558]     rv = ngx_conf_parse(cf, NULL);
[559] 
[560]     *cf = pcf;
[561] 
[562]     if (rv == NGX_CONF_OK && !cscf->listen) {
[563]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[564]                       "no \"listen\" is defined for server in %s:%ui",
[565]                       cscf->file_name, cscf->line);
[566]         return NGX_CONF_ERROR;
[567]     }
[568] 
[569]     return rv;
[570] }
[571] 
[572] 
[573] static char *
[574] ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[575] {
[576]     ngx_stream_core_srv_conf_t  *cscf = conf;
[577] 
[578]     ngx_str_t                    *value, size;
[579]     ngx_url_t                     u;
[580]     ngx_uint_t                    i, n, backlog;
[581]     ngx_stream_listen_t          *ls, *als, *nls;
[582]     ngx_stream_core_main_conf_t  *cmcf;
[583] 
[584]     cscf->listen = 1;
[585] 
[586]     value = cf->args->elts;
[587] 
[588]     ngx_memzero(&u, sizeof(ngx_url_t));
[589] 
[590]     u.url = value[1];
[591]     u.listen = 1;
[592] 
[593]     if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[594]         if (u.err) {
[595]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[596]                                "%s in \"%V\" of the \"listen\" directive",
[597]                                u.err, &u.url);
[598]         }
[599] 
[600]         return NGX_CONF_ERROR;
[601]     }
[602] 
[603]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[604] 
[605]     ls = ngx_array_push(&cmcf->listen);
[606]     if (ls == NULL) {
[607]         return NGX_CONF_ERROR;
[608]     }
[609] 
[610]     ngx_memzero(ls, sizeof(ngx_stream_listen_t));
[611] 
[612]     ls->backlog = NGX_LISTEN_BACKLOG;
[613]     ls->rcvbuf = -1;
[614]     ls->sndbuf = -1;
[615]     ls->type = SOCK_STREAM;
[616]     ls->ctx = cf->ctx;
[617] 
[618] #if (NGX_HAVE_TCP_FASTOPEN)
[619]     ls->fastopen = -1;
[620] #endif
[621] 
[622] #if (NGX_HAVE_INET6)
[623]     ls->ipv6only = 1;
[624] #endif
[625] 
[626]     backlog = 0;
[627] 
[628]     for (i = 2; i < cf->args->nelts; i++) {
[629] 
[630] #if !(NGX_WIN32)
[631]         if (ngx_strcmp(value[i].data, "udp") == 0) {
[632]             ls->type = SOCK_DGRAM;
[633]             continue;
[634]         }
[635] #endif
[636] 
[637]         if (ngx_strcmp(value[i].data, "bind") == 0) {
[638]             ls->bind = 1;
[639]             continue;
[640]         }
[641] 
[642] #if (NGX_HAVE_TCP_FASTOPEN)
[643]         if (ngx_strncmp(value[i].data, "fastopen=", 9) == 0) {
[644]             ls->fastopen = ngx_atoi(value[i].data + 9, value[i].len - 9);
[645]             ls->bind = 1;
[646] 
[647]             if (ls->fastopen == NGX_ERROR) {
[648]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[649]                                    "invalid fastopen \"%V\"", &value[i]);
[650]                 return NGX_CONF_ERROR;
[651]             }
[652] 
[653]             continue;
[654]         }
[655] #endif
[656] 
[657]         if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
[658]             ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
[659]             ls->bind = 1;
[660] 
[661]             if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
[662]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[663]                                    "invalid backlog \"%V\"", &value[i]);
[664]                 return NGX_CONF_ERROR;
[665]             }
[666] 
[667]             backlog = 1;
[668] 
[669]             continue;
[670]         }
[671] 
[672]         if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
[673]             size.len = value[i].len - 7;
[674]             size.data = value[i].data + 7;
[675] 
[676]             ls->rcvbuf = ngx_parse_size(&size);
[677]             ls->bind = 1;
[678] 
[679]             if (ls->rcvbuf == NGX_ERROR) {
[680]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[681]                                    "invalid rcvbuf \"%V\"", &value[i]);
[682]                 return NGX_CONF_ERROR;
[683]             }
[684] 
[685]             continue;
[686]         }
[687] 
[688]         if (ngx_strncmp(value[i].data, "sndbuf=", 7) == 0) {
[689]             size.len = value[i].len - 7;
[690]             size.data = value[i].data + 7;
[691] 
[692]             ls->sndbuf = ngx_parse_size(&size);
[693]             ls->bind = 1;
[694] 
[695]             if (ls->sndbuf == NGX_ERROR) {
[696]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[697]                                    "invalid sndbuf \"%V\"", &value[i]);
[698]                 return NGX_CONF_ERROR;
[699]             }
[700] 
[701]             continue;
[702]         }
[703] 
[704]         if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
[705] #if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
[706]             if (ngx_strcmp(&value[i].data[10], "n") == 0) {
[707]                 ls->ipv6only = 1;
[708] 
[709]             } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
[710]                 ls->ipv6only = 0;
[711] 
[712]             } else {
[713]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[714]                                    "invalid ipv6only flags \"%s\"",
[715]                                    &value[i].data[9]);
[716]                 return NGX_CONF_ERROR;
[717]             }
[718] 
[719]             ls->bind = 1;
[720]             continue;
[721] #else
[722]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[723]                                "bind ipv6only is not supported "
[724]                                "on this platform");
[725]             return NGX_CONF_ERROR;
[726] #endif
[727]         }
[728] 
[729]         if (ngx_strcmp(value[i].data, "reuseport") == 0) {
[730] #if (NGX_HAVE_REUSEPORT)
[731]             ls->reuseport = 1;
[732]             ls->bind = 1;
[733] #else
[734]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[735]                                "reuseport is not supported "
[736]                                "on this platform, ignored");
[737] #endif
[738]             continue;
[739]         }
[740] 
[741]         if (ngx_strcmp(value[i].data, "ssl") == 0) {
[742] #if (NGX_STREAM_SSL)
[743]             ngx_stream_ssl_conf_t  *sslcf;
[744] 
[745]             sslcf = ngx_stream_conf_get_module_srv_conf(cf,
[746]                                                         ngx_stream_ssl_module);
[747] 
[748]             sslcf->listen = 1;
[749]             sslcf->file = cf->conf_file->file.name.data;
[750]             sslcf->line = cf->conf_file->line;
[751] 
[752]             ls->ssl = 1;
[753] 
[754]             continue;
[755] #else
[756]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[757]                                "the \"ssl\" parameter requires "
[758]                                "ngx_stream_ssl_module");
[759]             return NGX_CONF_ERROR;
[760] #endif
[761]         }
[762] 
[763]         if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {
[764] 
[765]             if (ngx_strcmp(&value[i].data[13], "on") == 0) {
[766]                 ls->so_keepalive = 1;
[767] 
[768]             } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
[769]                 ls->so_keepalive = 2;
[770] 
[771]             } else {
[772] 
[773] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[774]                 u_char     *p, *end;
[775]                 ngx_str_t   s;
[776] 
[777]                 end = value[i].data + value[i].len;
[778]                 s.data = value[i].data + 13;
[779] 
[780]                 p = ngx_strlchr(s.data, end, ':');
[781]                 if (p == NULL) {
[782]                     p = end;
[783]                 }
[784] 
[785]                 if (p > s.data) {
[786]                     s.len = p - s.data;
[787] 
[788]                     ls->tcp_keepidle = ngx_parse_time(&s, 1);
[789]                     if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
[790]                         goto invalid_so_keepalive;
[791]                     }
[792]                 }
[793] 
[794]                 s.data = (p < end) ? (p + 1) : end;
[795] 
[796]                 p = ngx_strlchr(s.data, end, ':');
[797]                 if (p == NULL) {
[798]                     p = end;
[799]                 }
[800] 
[801]                 if (p > s.data) {
[802]                     s.len = p - s.data;
[803] 
[804]                     ls->tcp_keepintvl = ngx_parse_time(&s, 1);
[805]                     if (ls->tcp_keepintvl == (time_t) NGX_ERROR) {
[806]                         goto invalid_so_keepalive;
[807]                     }
[808]                 }
[809] 
[810]                 s.data = (p < end) ? (p + 1) : end;
[811] 
[812]                 if (s.data < end) {
[813]                     s.len = end - s.data;
[814] 
[815]                     ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
[816]                     if (ls->tcp_keepcnt == NGX_ERROR) {
[817]                         goto invalid_so_keepalive;
[818]                     }
[819]                 }
[820] 
[821]                 if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
[822]                     && ls->tcp_keepcnt == 0)
[823]                 {
[824]                     goto invalid_so_keepalive;
[825]                 }
[826] 
[827]                 ls->so_keepalive = 1;
[828] 
[829] #else
[830] 
[831]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[832]                                    "the \"so_keepalive\" parameter accepts "
[833]                                    "only \"on\" or \"off\" on this platform");
[834]                 return NGX_CONF_ERROR;
[835] 
[836] #endif
[837]             }
[838] 
[839]             ls->bind = 1;
[840] 
[841]             continue;
[842] 
[843] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[844]         invalid_so_keepalive:
[845] 
[846]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[847]                                "invalid so_keepalive value: \"%s\"",
[848]                                &value[i].data[13]);
[849]             return NGX_CONF_ERROR;
[850] #endif
[851]         }
[852] 
[853]         if (ngx_strcmp(value[i].data, "proxy_protocol") == 0) {
[854]             ls->proxy_protocol = 1;
[855]             continue;
[856]         }
[857] 
[858]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[859]                            "the invalid \"%V\" parameter", &value[i]);
[860]         return NGX_CONF_ERROR;
[861]     }
[862] 
[863]     if (ls->type == SOCK_DGRAM) {
[864]         if (backlog) {
[865]             return "\"backlog\" parameter is incompatible with \"udp\"";
[866]         }
[867] 
[868] #if (NGX_STREAM_SSL)
[869]         if (ls->ssl) {
[870]             return "\"ssl\" parameter is incompatible with \"udp\"";
[871]         }
[872] #endif
[873] 
[874]         if (ls->so_keepalive) {
[875]             return "\"so_keepalive\" parameter is incompatible with \"udp\"";
[876]         }
[877] 
[878]         if (ls->proxy_protocol) {
[879]             return "\"proxy_protocol\" parameter is incompatible with \"udp\"";
[880]         }
[881] 
[882] #if (NGX_HAVE_TCP_FASTOPEN)
[883]         if (ls->fastopen != -1) {
[884]             return "\"fastopen\" parameter is incompatible with \"udp\"";
[885]         }
[886] #endif
[887]     }
[888] 
[889]     for (n = 0; n < u.naddrs; n++) {
[890] 
[891]         for (i = 0; i < n; i++) {
[892]             if (ngx_cmp_sockaddr(u.addrs[n].sockaddr, u.addrs[n].socklen,
[893]                                  u.addrs[i].sockaddr, u.addrs[i].socklen, 1)
[894]                 == NGX_OK)
[895]             {
[896]                 goto next;
[897]             }
[898]         }
[899] 
[900]         if (n != 0) {
[901]             nls = ngx_array_push(&cmcf->listen);
[902]             if (nls == NULL) {
[903]                 return NGX_CONF_ERROR;
[904]             }
[905] 
[906]             *nls = *ls;
[907] 
[908]         } else {
[909]             nls = ls;
[910]         }
[911] 
[912]         nls->sockaddr = u.addrs[n].sockaddr;
[913]         nls->socklen = u.addrs[n].socklen;
[914]         nls->addr_text = u.addrs[n].name;
[915]         nls->wildcard = ngx_inet_wildcard(nls->sockaddr);
[916] 
[917]         als = cmcf->listen.elts;
[918] 
[919]         for (i = 0; i < cmcf->listen.nelts - 1; i++) {
[920]             if (nls->type != als[i].type) {
[921]                 continue;
[922]             }
[923] 
[924]             if (ngx_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
[925]                                  nls->sockaddr, nls->socklen, 1)
[926]                 != NGX_OK)
[927]             {
[928]                 continue;
[929]             }
[930] 
[931]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[932]                                "duplicate \"%V\" address and port pair",
[933]                                &nls->addr_text);
[934]             return NGX_CONF_ERROR;
[935]         }
[936] 
[937]     next:
[938]         continue;
[939]     }
[940] 
[941]     return NGX_CONF_OK;
[942] }
[943] 
[944] 
[945] static char *
[946] ngx_stream_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[947] {
[948]     ngx_stream_core_srv_conf_t  *cscf = conf;
[949] 
[950]     ngx_str_t  *value;
[951] 
[952]     if (cscf->resolver) {
[953]         return "is duplicate";
[954]     }
[955] 
[956]     value = cf->args->elts;
[957] 
[958]     cscf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
[959]     if (cscf->resolver == NULL) {
[960]         return NGX_CONF_ERROR;
[961]     }
[962] 
[963]     return NGX_CONF_OK;
[964] }
