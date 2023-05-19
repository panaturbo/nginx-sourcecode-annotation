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
[11] #include <ngx_http_perl_module.h>
[12] 
[13] 
[14] typedef struct {
[15]     PerlInterpreter   *perl;
[16]     HV                *nginx;
[17]     ngx_array_t       *modules;
[18]     ngx_array_t       *requires;
[19] } ngx_http_perl_main_conf_t;
[20] 
[21] 
[22] typedef struct {
[23]     SV                *sub;
[24]     ngx_str_t          handler;
[25] } ngx_http_perl_loc_conf_t;
[26] 
[27] 
[28] typedef struct {
[29]     SV                *sub;
[30]     ngx_str_t          handler;
[31] } ngx_http_perl_variable_t;
[32] 
[33] 
[34] #if (NGX_HTTP_SSI)
[35] static ngx_int_t ngx_http_perl_ssi(ngx_http_request_t *r,
[36]     ngx_http_ssi_ctx_t *ssi_ctx, ngx_str_t **params);
[37] #endif
[38] 
[39] static char *ngx_http_perl_init_interpreter(ngx_conf_t *cf,
[40]     ngx_http_perl_main_conf_t *pmcf);
[41] static PerlInterpreter *ngx_http_perl_create_interpreter(ngx_conf_t *cf,
[42]     ngx_http_perl_main_conf_t *pmcf);
[43] static ngx_int_t ngx_http_perl_run_requires(pTHX_ ngx_array_t *requires,
[44]     ngx_log_t *log);
[45] static ngx_int_t ngx_http_perl_call_handler(pTHX_ ngx_http_request_t *r,
[46]     ngx_http_perl_ctx_t *ctx, HV *nginx, SV *sub, SV **args,
[47]     ngx_str_t *handler, ngx_str_t *rv);
[48] static void ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv);
[49] 
[50] static ngx_int_t ngx_http_perl_preconfiguration(ngx_conf_t *cf);
[51] static void *ngx_http_perl_create_main_conf(ngx_conf_t *cf);
[52] static char *ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf);
[53] static void *ngx_http_perl_create_loc_conf(ngx_conf_t *cf);
[54] static char *ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent,
[55]     void *child);
[56] static char *ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[57] static char *ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[58] 
[59] #if (NGX_HAVE_PERL_MULTIPLICITY)
[60] static void ngx_http_perl_cleanup_perl(void *data);
[61] #endif
[62] 
[63] static ngx_int_t ngx_http_perl_init_worker(ngx_cycle_t *cycle);
[64] static void ngx_http_perl_exit(ngx_cycle_t *cycle);
[65] 
[66] 
[67] static ngx_command_t  ngx_http_perl_commands[] = {
[68] 
[69]     { ngx_string("perl_modules"),
[70]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[71]       ngx_conf_set_str_array_slot,
[72]       NGX_HTTP_MAIN_CONF_OFFSET,
[73]       offsetof(ngx_http_perl_main_conf_t, modules),
[74]       NULL },
[75] 
[76]     { ngx_string("perl_require"),
[77]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[78]       ngx_conf_set_str_array_slot,
[79]       NGX_HTTP_MAIN_CONF_OFFSET,
[80]       offsetof(ngx_http_perl_main_conf_t, requires),
[81]       NULL },
[82] 
[83]     { ngx_string("perl"),
[84]       NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
[85]       ngx_http_perl,
[86]       NGX_HTTP_LOC_CONF_OFFSET,
[87]       0,
[88]       NULL },
[89] 
[90]     { ngx_string("perl_set"),
[91]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
[92]       ngx_http_perl_set,
[93]       NGX_HTTP_LOC_CONF_OFFSET,
[94]       0,
[95]       NULL },
[96] 
[97]       ngx_null_command
[98] };
[99] 
[100] 
[101] static ngx_http_module_t  ngx_http_perl_module_ctx = {
[102]     ngx_http_perl_preconfiguration,        /* preconfiguration */
[103]     NULL,                                  /* postconfiguration */
[104] 
[105]     ngx_http_perl_create_main_conf,        /* create main configuration */
[106]     ngx_http_perl_init_main_conf,          /* init main configuration */
[107] 
[108]     NULL,                                  /* create server configuration */
[109]     NULL,                                  /* merge server configuration */
[110] 
[111]     ngx_http_perl_create_loc_conf,         /* create location configuration */
[112]     ngx_http_perl_merge_loc_conf           /* merge location configuration */
[113] };
[114] 
[115] 
[116] ngx_module_t  ngx_http_perl_module = {
[117]     NGX_MODULE_V1,
[118]     &ngx_http_perl_module_ctx,             /* module context */
[119]     ngx_http_perl_commands,                /* module directives */
[120]     NGX_HTTP_MODULE,                       /* module type */
[121]     NULL,                                  /* init master */
[122]     NULL,                                  /* init module */
[123]     ngx_http_perl_init_worker,             /* init process */
[124]     NULL,                                  /* init thread */
[125]     NULL,                                  /* exit thread */
[126]     NULL,                                  /* exit process */
[127]     ngx_http_perl_exit,                    /* exit master */
[128]     NGX_MODULE_V1_PADDING
[129] };
[130] 
[131] 
[132] #if (NGX_HTTP_SSI)
[133] 
[134] #define NGX_HTTP_PERL_SSI_SUB  0
[135] #define NGX_HTTP_PERL_SSI_ARG  1
[136] 
[137] 
[138] static ngx_http_ssi_param_t  ngx_http_perl_ssi_params[] = {
[139]     { ngx_string("sub"), NGX_HTTP_PERL_SSI_SUB, 1, 0 },
[140]     { ngx_string("arg"), NGX_HTTP_PERL_SSI_ARG, 0, 1 },
[141]     { ngx_null_string, 0, 0, 0 }
[142] };
[143] 
[144] static ngx_http_ssi_command_t  ngx_http_perl_ssi_command = {
[145]     ngx_string("perl"), ngx_http_perl_ssi, ngx_http_perl_ssi_params, 0, 0, 1
[146] };
[147] 
[148] #endif
[149] 
[150] 
[151] static ngx_str_t         ngx_null_name = ngx_null_string;
[152] static HV               *nginx_stash;
[153] 
[154] #if (NGX_HAVE_PERL_MULTIPLICITY)
[155] static ngx_uint_t        ngx_perl_term;
[156] #else
[157] static PerlInterpreter  *perl;
[158] #endif
[159] 
[160] 
[161] static void
[162] ngx_http_perl_xs_init(pTHX)
[163] {
[164]     newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);
[165] 
[166]     nginx_stash = gv_stashpv("nginx", TRUE);
[167] }
[168] 
[169] 
[170] static ngx_int_t
[171] ngx_http_perl_handler(ngx_http_request_t *r)
[172] {
[173]     r->main->count++;
[174] 
[175]     ngx_http_perl_handle_request(r);
[176] 
[177]     return NGX_DONE;
[178] }
[179] 
[180] 
[181] void
[182] ngx_http_perl_handle_request(ngx_http_request_t *r)
[183] {
[184]     SV                         *sub;
[185]     ngx_int_t                   rc;
[186]     ngx_str_t                   uri, args, *handler;
[187]     ngx_uint_t                  flags;
[188]     ngx_http_perl_ctx_t        *ctx;
[189]     ngx_http_perl_loc_conf_t   *plcf;
[190]     ngx_http_perl_main_conf_t  *pmcf;
[191] 
[192]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");
[193] 
[194]     ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);
[195] 
[196]     if (ctx == NULL) {
[197]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
[198]         if (ctx == NULL) {
[199]             ngx_http_finalize_request(r, NGX_ERROR);
[200]             return;
[201]         }
[202] 
[203]         ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
[204] 
[205]         ctx->request = r;
[206]     }
[207] 
[208]     pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);
[209] 
[210]     {
[211] 
[212]     dTHXa(pmcf->perl);
[213]     PERL_SET_CONTEXT(pmcf->perl);
[214]     PERL_SET_INTERP(pmcf->perl);
[215] 
[216]     if (ctx->next == NULL) {
[217]         plcf = ngx_http_get_module_loc_conf(r, ngx_http_perl_module);
[218]         sub = plcf->sub;
[219]         handler = &plcf->handler;
[220] 
[221]     } else {
[222]         sub = ctx->next;
[223]         handler = &ngx_null_name;
[224]         ctx->next = NULL;
[225]     }
[226] 
[227]     rc = ngx_http_perl_call_handler(aTHX_ r, ctx, pmcf->nginx, sub, NULL,
[228]                                     handler, NULL);
[229] 
[230]     }
[231] 
[232]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[233]                    "perl handler done: %i", rc);
[234] 
[235]     if (rc > 600) {
[236]         rc = NGX_OK;
[237]     }
[238] 
[239]     if (ctx->redirect_uri.len) {
[240]         uri = ctx->redirect_uri;
[241] 
[242]     } else {
[243]         uri.len = 0;
[244]     }
[245] 
[246]     ctx->filename.data = NULL;
[247]     ctx->redirect_uri.len = 0;
[248] 
[249]     if (rc == NGX_ERROR) {
[250]         ngx_http_finalize_request(r, rc);
[251]         return;
[252]     }
[253] 
[254]     if (ctx->done || ctx->next) {
[255]         ngx_http_finalize_request(r, NGX_DONE);
[256]         return;
[257]     }
[258] 
[259]     if (uri.len) {
[260]         if (uri.data[0] == '@') {
[261]             ngx_http_named_location(r, &uri);
[262] 
[263]         } else {
[264]             ngx_str_null(&args);
[265]             flags = NGX_HTTP_LOG_UNSAFE;
[266] 
[267]             if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
[268]                 ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[269]                 return;
[270]             }
[271] 
[272]             ngx_http_internal_redirect(r, &uri, &args);
[273]         }
[274] 
[275]         ngx_http_finalize_request(r, NGX_DONE);
[276]         return;
[277]     }
[278] 
[279]     if (rc == NGX_OK || rc == NGX_HTTP_OK) {
[280]         ngx_http_send_special(r, NGX_HTTP_LAST);
[281]         ctx->done = 1;
[282]     }
[283] 
[284]     ngx_http_finalize_request(r, rc);
[285] }
[286] 
[287] 
[288] void
[289] ngx_http_perl_sleep_handler(ngx_http_request_t *r)
[290] {
[291]     ngx_event_t  *wev;
[292] 
[293]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[294]                    "perl sleep handler");
[295] 
[296]     wev = r->connection->write;
[297] 
[298]     if (wev->delayed) {
[299] 
[300]         if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[301]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[302]         }
[303] 
[304]         return;
[305]     }
[306] 
[307]     ngx_http_perl_handle_request(r);
[308] }
[309] 
[310] 
[311] static ngx_int_t
[312] ngx_http_perl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[313]     uintptr_t data)
[314] {
[315]     ngx_http_perl_variable_t *pv = (ngx_http_perl_variable_t *) data;
[316] 
[317]     ngx_int_t                   rc;
[318]     ngx_str_t                   value;
[319]     ngx_uint_t                  saved;
[320]     ngx_http_perl_ctx_t        *ctx;
[321]     ngx_http_perl_main_conf_t  *pmcf;
[322] 
[323]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[324]                    "perl variable handler");
[325] 
[326]     ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);
[327] 
[328]     if (ctx == NULL) {
[329]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
[330]         if (ctx == NULL) {
[331]             return NGX_ERROR;
[332]         }
[333] 
[334]         ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
[335] 
[336]         ctx->request = r;
[337]     }
[338] 
[339]     saved = ctx->variable;
[340]     ctx->variable = 1;
[341] 
[342]     pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);
[343] 
[344]     value.data = NULL;
[345] 
[346]     {
[347] 
[348]     dTHXa(pmcf->perl);
[349]     PERL_SET_CONTEXT(pmcf->perl);
[350]     PERL_SET_INTERP(pmcf->perl);
[351] 
[352]     rc = ngx_http_perl_call_handler(aTHX_ r, ctx, pmcf->nginx, pv->sub, NULL,
[353]                                     &pv->handler, &value);
[354] 
[355]     }
[356] 
[357]     if (value.data) {
[358]         v->len = value.len;
[359]         v->valid = 1;
[360]         v->no_cacheable = 0;
[361]         v->not_found = 0;
[362]         v->data = value.data;
[363] 
[364]     } else {
[365]         v->not_found = 1;
[366]     }
[367] 
[368]     ctx->variable = saved;
[369]     ctx->filename.data = NULL;
[370]     ctx->redirect_uri.len = 0;
[371] 
[372]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[373]                    "perl variable done");
[374] 
[375]     return rc;
[376] }
[377] 
[378] 
[379] #if (NGX_HTTP_SSI)
[380] 
[381] static ngx_int_t
[382] ngx_http_perl_ssi(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ssi_ctx,
[383]     ngx_str_t **params)
[384] {
[385]     SV                         *sv, **asv;
[386]     ngx_int_t                   rc;
[387]     ngx_str_t                  *handler, **args;
[388]     ngx_uint_t                  i;
[389]     ngx_http_perl_ctx_t        *ctx;
[390]     ngx_http_perl_main_conf_t  *pmcf;
[391] 
[392]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[393]                    "perl ssi handler");
[394] 
[395]     ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);
[396] 
[397]     if (ctx == NULL) {
[398]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
[399]         if (ctx == NULL) {
[400]             return NGX_ERROR;
[401]         }
[402] 
[403]         ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
[404] 
[405]         ctx->request = r;
[406]     }
[407] 
[408]     pmcf = ngx_http_get_module_main_conf(r, ngx_http_perl_module);
[409] 
[410]     ctx->ssi = ssi_ctx;
[411]     ctx->header_sent = 1;
[412] 
[413]     handler = params[NGX_HTTP_PERL_SSI_SUB];
[414]     handler->data[handler->len] = '\0';
[415] 
[416]     {
[417] 
[418]     dTHXa(pmcf->perl);
[419]     PERL_SET_CONTEXT(pmcf->perl);
[420]     PERL_SET_INTERP(pmcf->perl);
[421] 
[422] #if 0
[423] 
[424]     /* the code is disabled to force the precompiled perl code using only */
[425] 
[426]     ngx_http_perl_eval_anon_sub(aTHX_ handler, &sv);
[427] 
[428]     if (sv == &PL_sv_undef) {
[429]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[430]                       "eval_pv(\"%V\") failed", handler);
[431]         return NGX_ERROR;
[432]     }
[433] 
[434]     if (sv == NULL) {
[435]         sv = newSVpvn((char *) handler->data, handler->len);
[436]     }
[437] 
[438] #endif
[439] 
[440]     sv = newSVpvn((char *) handler->data, handler->len);
[441] 
[442]     args = &params[NGX_HTTP_PERL_SSI_ARG];
[443] 
[444]     if (args[0]) {
[445] 
[446]         for (i = 0; args[i]; i++) { /* void */ }
[447] 
[448]         asv = ngx_pcalloc(r->pool, (i + 1) * sizeof(SV *));
[449] 
[450]         if (asv == NULL) {
[451]             SvREFCNT_dec(sv);
[452]             return NGX_ERROR;
[453]         }
[454] 
[455]         asv[0] = (SV *) (uintptr_t) i;
[456] 
[457]         for (i = 0; args[i]; i++) {
[458]             asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
[459]         }
[460] 
[461]     } else {
[462]         asv = NULL;
[463]     }
[464] 
[465]     rc = ngx_http_perl_call_handler(aTHX_ r, ctx, pmcf->nginx, sv, asv,
[466]                                     handler, NULL);
[467] 
[468]     SvREFCNT_dec(sv);
[469] 
[470]     }
[471] 
[472]     ctx->filename.data = NULL;
[473]     ctx->redirect_uri.len = 0;
[474]     ctx->ssi = NULL;
[475] 
[476]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");
[477] 
[478]     return rc;
[479] }
[480] 
[481] #endif
[482] 
[483] 
[484] static char *
[485] ngx_http_perl_init_interpreter(ngx_conf_t *cf, ngx_http_perl_main_conf_t *pmcf)
[486] {
[487]     ngx_str_t           *m;
[488]     ngx_uint_t           i;
[489] #if (NGX_HAVE_PERL_MULTIPLICITY)
[490]     ngx_pool_cleanup_t  *cln;
[491] 
[492]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[493]     if (cln == NULL) {
[494]         return NGX_CONF_ERROR;
[495]     }
[496] 
[497] #endif
[498] 
[499] #ifdef NGX_PERL_MODULES
[500]     if (pmcf->modules == NGX_CONF_UNSET_PTR) {
[501] 
[502]         pmcf->modules = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
[503]         if (pmcf->modules == NULL) {
[504]             return NGX_CONF_ERROR;
[505]         }
[506] 
[507]         m = ngx_array_push(pmcf->modules);
[508]         if (m == NULL) {
[509]             return NGX_CONF_ERROR;
[510]         }
[511] 
[512]         ngx_str_set(m, NGX_PERL_MODULES);
[513]     }
[514] #endif
[515] 
[516]     if (pmcf->modules != NGX_CONF_UNSET_PTR) {
[517]         m = pmcf->modules->elts;
[518]         for (i = 0; i < pmcf->modules->nelts; i++) {
[519]             if (ngx_conf_full_name(cf->cycle, &m[i], 0) != NGX_OK) {
[520]                 return NGX_CONF_ERROR;
[521]             }
[522]         }
[523]     }
[524] 
[525] #if !(NGX_HAVE_PERL_MULTIPLICITY)
[526] 
[527]     if (perl) {
[528] 
[529]         if (ngx_set_environment(cf->cycle, NULL) == NULL) {
[530]             return NGX_CONF_ERROR;
[531]         }
[532] 
[533]         if (ngx_http_perl_run_requires(aTHX_ pmcf->requires, cf->log)
[534]             != NGX_OK)
[535]         {
[536]             return NGX_CONF_ERROR;
[537]         }
[538] 
[539]         pmcf->perl = perl;
[540]         pmcf->nginx = nginx_stash;
[541] 
[542]         return NGX_CONF_OK;
[543]     }
[544] 
[545] #endif
[546] 
[547]     if (nginx_stash == NULL) {
[548]         PERL_SYS_INIT(&ngx_argc, &ngx_argv);
[549]     }
[550] 
[551]     pmcf->perl = ngx_http_perl_create_interpreter(cf, pmcf);
[552] 
[553]     if (pmcf->perl == NULL) {
[554]         return NGX_CONF_ERROR;
[555]     }
[556] 
[557]     pmcf->nginx = nginx_stash;
[558] 
[559] #if (NGX_HAVE_PERL_MULTIPLICITY)
[560] 
[561]     cln->handler = ngx_http_perl_cleanup_perl;
[562]     cln->data = pmcf->perl;
[563] 
[564] #else
[565] 
[566]     perl = pmcf->perl;
[567] 
[568] #endif
[569] 
[570]     return NGX_CONF_OK;
[571] }
[572] 
[573] 
[574] static PerlInterpreter *
[575] ngx_http_perl_create_interpreter(ngx_conf_t *cf,
[576]     ngx_http_perl_main_conf_t *pmcf)
[577] {
[578]     int                n;
[579]     STRLEN             len;
[580]     SV                *sv;
[581]     char              *ver, **embedding;
[582]     ngx_str_t         *m;
[583]     ngx_uint_t         i;
[584]     PerlInterpreter   *perl;
[585] 
[586]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "create perl interpreter");
[587] 
[588]     if (ngx_set_environment(cf->cycle, NULL) == NULL) {
[589]         return NULL;
[590]     }
[591] 
[592]     perl = perl_alloc();
[593]     if (perl == NULL) {
[594]         ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
[595]         return NULL;
[596]     }
[597] 
[598]     {
[599] 
[600]     dTHXa(perl);
[601]     PERL_SET_CONTEXT(perl);
[602]     PERL_SET_INTERP(perl);
[603] 
[604]     perl_construct(perl);
[605] 
[606] #ifdef PERL_EXIT_DESTRUCT_END
[607]     PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
[608] #endif
[609] 
[610]     n = (pmcf->modules != NGX_CONF_UNSET_PTR) ? pmcf->modules->nelts * 2 : 0;
[611] 
[612]     embedding = ngx_palloc(cf->pool, (5 + n) * sizeof(char *));
[613]     if (embedding == NULL) {
[614]         goto fail;
[615]     }
[616] 
[617]     embedding[0] = "";
[618] 
[619]     if (n++) {
[620]         m = pmcf->modules->elts;
[621]         for (i = 0; i < pmcf->modules->nelts; i++) {
[622]             embedding[2 * i + 1] = "-I";
[623]             embedding[2 * i + 2] = (char *) m[i].data;
[624]         }
[625]     }
[626] 
[627]     embedding[n++] = "-Mnginx";
[628]     embedding[n++] = "-e";
[629]     embedding[n++] = "0";
[630]     embedding[n] = NULL;
[631] 
[632]     n = perl_parse(perl, ngx_http_perl_xs_init, n, embedding, NULL);
[633] 
[634]     if (n != 0) {
[635]         ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_parse() failed: %d", n);
[636]         goto fail;
[637]     }
[638] 
[639]     sv = get_sv("nginx::VERSION", FALSE);
[640]     ver = SvPV(sv, len);
[641] 
[642]     if (ngx_strcmp(ver, NGINX_VERSION) != 0) {
[643]         ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
[644]                       "version " NGINX_VERSION " of nginx.pm is required, "
[645]                       "but %s was found", ver);
[646]         goto fail;
[647]     }
[648] 
[649]     if (ngx_http_perl_run_requires(aTHX_ pmcf->requires, cf->log) != NGX_OK) {
[650]         goto fail;
[651]     }
[652] 
[653]     }
[654] 
[655]     return perl;
[656] 
[657] fail:
[658] 
[659]     (void) perl_destruct(perl);
[660] 
[661]     perl_free(perl);
[662] 
[663]     return NULL;
[664] }
[665] 
[666] 
[667] static ngx_int_t
[668] ngx_http_perl_run_requires(pTHX_ ngx_array_t *requires, ngx_log_t *log)
[669] {
[670]     u_char      *err;
[671]     STRLEN       len;
[672]     ngx_str_t   *script;
[673]     ngx_uint_t   i;
[674] 
[675]     if (requires == NGX_CONF_UNSET_PTR) {
[676]         return NGX_OK;
[677]     }
[678] 
[679]     script = requires->elts;
[680]     for (i = 0; i < requires->nelts; i++) {
[681] 
[682]         require_pv((char *) script[i].data);
[683] 
[684]         if (SvTRUE(ERRSV)) {
[685] 
[686]             err = (u_char *) SvPV(ERRSV, len);
[687]             while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }
[688] 
[689]             ngx_log_error(NGX_LOG_EMERG, log, 0,
[690]                           "require_pv(\"%s\") failed: \"%*s\"",
[691]                           script[i].data, len + 1, err);
[692] 
[693]             return NGX_ERROR;
[694]         }
[695]     }
[696] 
[697]     return NGX_OK;
[698] }
[699] 
[700] 
[701] static ngx_int_t
[702] ngx_http_perl_call_handler(pTHX_ ngx_http_request_t *r,
[703]     ngx_http_perl_ctx_t *ctx, HV *nginx, SV *sub, SV **args,
[704]     ngx_str_t *handler, ngx_str_t *rv)
[705] {
[706]     SV                *sv;
[707]     int                n, status;
[708]     char              *line;
[709]     u_char            *err;
[710]     STRLEN             len, n_a;
[711]     ngx_uint_t         i;
[712]     ngx_connection_t  *c;
[713] 
[714]     dSP;
[715] 
[716]     status = 0;
[717] 
[718]     ctx->error = 0;
[719]     ctx->status = NGX_OK;
[720] 
[721]     ENTER;
[722]     SAVETMPS;
[723] 
[724]     PUSHMARK(sp);
[725] 
[726]     sv = sv_2mortal(sv_bless(newRV_noinc(newSViv(PTR2IV(ctx))), nginx));
[727]     XPUSHs(sv);
[728] 
[729]     if (args) {
[730]         EXTEND(sp, (intptr_t) args[0]);
[731] 
[732]         for (i = 1; i <= (uintptr_t) args[0]; i++) {
[733]             PUSHs(sv_2mortal(args[i]));
[734]         }
[735]     }
[736] 
[737]     PUTBACK;
[738] 
[739]     c = r->connection;
[740] 
[741]     n = call_sv(sub, G_EVAL);
[742] 
[743]     SPAGAIN;
[744] 
[745]     if (n) {
[746]         if (rv == NULL) {
[747]             status = POPi;
[748] 
[749]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[750]                            "call_sv: %d", status);
[751] 
[752]         } else {
[753]             line = SvPVx(POPs, n_a);
[754]             rv->len = n_a;
[755] 
[756]             rv->data = ngx_pnalloc(r->pool, n_a);
[757]             if (rv->data == NULL) {
[758]                 return NGX_ERROR;
[759]             }
[760] 
[761]             ngx_memcpy(rv->data, line, n_a);
[762]         }
[763]     }
[764] 
[765]     PUTBACK;
[766] 
[767]     FREETMPS;
[768]     LEAVE;
[769] 
[770]     if (ctx->error) {
[771] 
[772]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[773]                        "call_sv: error, %d", ctx->status);
[774] 
[775]         if (ctx->status != NGX_OK) {
[776]             return ctx->status;
[777]         }
[778] 
[779]         return NGX_ERROR;
[780]     }
[781] 
[782]     /* check $@ */
[783] 
[784]     if (SvTRUE(ERRSV)) {
[785] 
[786]         err = (u_char *) SvPV(ERRSV, len);
[787]         while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }
[788] 
[789]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[790]                       "call_sv(\"%V\") failed: \"%*s\"", handler, len + 1, err);
[791] 
[792]         if (rv) {
[793]             return NGX_ERROR;
[794]         }
[795] 
[796]         ctx->redirect_uri.len = 0;
[797] 
[798]         if (ctx->header_sent) {
[799]             return NGX_ERROR;
[800]         }
[801] 
[802]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[803]     }
[804] 
[805]     if (n != 1) {
[806]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[807]                       "call_sv(\"%V\") returned %d results", handler, n);
[808]         status = NGX_OK;
[809]     }
[810] 
[811]     if (rv) {
[812]         return NGX_OK;
[813]     }
[814] 
[815]     return (ngx_int_t) status;
[816] }
[817] 
[818] 
[819] static void
[820] ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv)
[821] {
[822]     u_char  *p;
[823] 
[824]     for (p = handler->data; *p; p++) {
[825]         if (*p != ' ' && *p != '\t' && *p != CR && *p != LF) {
[826]             break;
[827]         }
[828]     }
[829] 
[830]     if (ngx_strncmp(p, "sub ", 4) == 0
[831]         || ngx_strncmp(p, "sub{", 4) == 0
[832]         || ngx_strncmp(p, "use ", 4) == 0)
[833]     {
[834]         *sv = eval_pv((char *) p, FALSE);
[835] 
[836]         /* eval_pv() does not set ERRSV on failure */
[837] 
[838]         return;
[839]     }
[840] 
[841]     *sv = NULL;
[842] }
[843] 
[844] 
[845] static void *
[846] ngx_http_perl_create_main_conf(ngx_conf_t *cf)
[847] {
[848]     ngx_http_perl_main_conf_t  *pmcf;
[849] 
[850]     pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_main_conf_t));
[851]     if (pmcf == NULL) {
[852]         return NULL;
[853]     }
[854] 
[855]     pmcf->modules = NGX_CONF_UNSET_PTR;
[856]     pmcf->requires = NGX_CONF_UNSET_PTR;
[857] 
[858]     return pmcf;
[859] }
[860] 
[861] 
[862] static char *
[863] ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf)
[864] {
[865]     ngx_http_perl_main_conf_t *pmcf = conf;
[866] 
[867]     if (pmcf->perl == NULL) {
[868]         if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
[869]             return NGX_CONF_ERROR;
[870]         }
[871]     }
[872] 
[873]     return NGX_CONF_OK;
[874] }
[875] 
[876] 
[877] #if (NGX_HAVE_PERL_MULTIPLICITY)
[878] 
[879] static void
[880] ngx_http_perl_cleanup_perl(void *data)
[881] {
[882]     PerlInterpreter  *perl = data;
[883] 
[884]     PERL_SET_CONTEXT(perl);
[885]     PERL_SET_INTERP(perl);
[886] 
[887]     (void) perl_destruct(perl);
[888] 
[889]     perl_free(perl);
[890] 
[891]     if (ngx_perl_term) {
[892]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "perl term");
[893] 
[894]         PERL_SYS_TERM();
[895]     }
[896] }
[897] 
[898] #endif
[899] 
[900] 
[901] static ngx_int_t
[902] ngx_http_perl_preconfiguration(ngx_conf_t *cf)
[903] {
[904] #if (NGX_HTTP_SSI)
[905]     ngx_int_t                  rc;
[906]     ngx_http_ssi_main_conf_t  *smcf;
[907] 
[908]     smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssi_filter_module);
[909] 
[910]     rc = ngx_hash_add_key(&smcf->commands, &ngx_http_perl_ssi_command.name,
[911]                           &ngx_http_perl_ssi_command, NGX_HASH_READONLY_KEY);
[912] 
[913]     if (rc != NGX_OK) {
[914]         if (rc == NGX_BUSY) {
[915]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[916]                                "conflicting SSI command \"%V\"",
[917]                                &ngx_http_perl_ssi_command.name);
[918]         }
[919] 
[920]         return NGX_ERROR;
[921]     }
[922] #endif
[923] 
[924]     return NGX_OK;
[925] }
[926] 
[927] 
[928] static void *
[929] ngx_http_perl_create_loc_conf(ngx_conf_t *cf)
[930] {
[931]     ngx_http_perl_loc_conf_t *plcf;
[932] 
[933]     plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_loc_conf_t));
[934]     if (plcf == NULL) {
[935]         return NULL;
[936]     }
[937] 
[938]     /*
[939]      * set by ngx_pcalloc():
[940]      *
[941]      *     plcf->handler = { 0, NULL };
[942]      */
[943] 
[944]     return plcf;
[945] }
[946] 
[947] 
[948] static char *
[949] ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[950] {
[951]     ngx_http_perl_loc_conf_t *prev = parent;
[952]     ngx_http_perl_loc_conf_t *conf = child;
[953] 
[954]     if (conf->sub == NULL) {
[955]         conf->sub = prev->sub;
[956]         conf->handler = prev->handler;
[957]     }
[958] 
[959]     return NGX_CONF_OK;
[960] }
[961] 
[962] 
[963] static char *
[964] ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[965] {
[966]     ngx_http_perl_loc_conf_t *plcf = conf;
[967] 
[968]     ngx_str_t                  *value;
[969]     ngx_http_core_loc_conf_t   *clcf;
[970]     ngx_http_perl_main_conf_t  *pmcf;
[971] 
[972]     value = cf->args->elts;
[973] 
[974]     if (plcf->handler.data) {
[975]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[976]                            "duplicate perl handler \"%V\"", &value[1]);
[977]         return NGX_CONF_ERROR;
[978]     }
[979] 
[980]     pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);
[981] 
[982]     if (pmcf->perl == NULL) {
[983]         if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
[984]             return NGX_CONF_ERROR;
[985]         }
[986]     }
[987] 
[988]     plcf->handler = value[1];
[989] 
[990]     {
[991] 
[992]     dTHXa(pmcf->perl);
[993]     PERL_SET_CONTEXT(pmcf->perl);
[994]     PERL_SET_INTERP(pmcf->perl);
[995] 
[996]     ngx_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->sub);
[997] 
[998]     if (plcf->sub == &PL_sv_undef) {
[999]         ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
[1000]                            "eval_pv(\"%V\") failed", &value[1]);
[1001]         return NGX_CONF_ERROR;
[1002]     }
[1003] 
[1004]     if (plcf->sub == NULL) {
[1005]         plcf->sub = newSVpvn((char *) value[1].data, value[1].len);
[1006]     }
[1007] 
[1008]     }
[1009] 
[1010]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[1011]     clcf->handler = ngx_http_perl_handler;
[1012] 
[1013]     return NGX_CONF_OK;
[1014] }
[1015] 
[1016] 
[1017] static char *
[1018] ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1019] {
[1020]     ngx_int_t                   index;
[1021]     ngx_str_t                  *value;
[1022]     ngx_http_variable_t        *v;
[1023]     ngx_http_perl_variable_t   *pv;
[1024]     ngx_http_perl_main_conf_t  *pmcf;
[1025] 
[1026]     value = cf->args->elts;
[1027] 
[1028]     if (value[1].data[0] != '$') {
[1029]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1030]                            "invalid variable name \"%V\"", &value[1]);
[1031]         return NGX_CONF_ERROR;
[1032]     }
[1033] 
[1034]     value[1].len--;
[1035]     value[1].data++;
[1036] 
[1037]     v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
[1038]     if (v == NULL) {
[1039]         return NGX_CONF_ERROR;
[1040]     }
[1041] 
[1042]     pv = ngx_palloc(cf->pool, sizeof(ngx_http_perl_variable_t));
[1043]     if (pv == NULL) {
[1044]         return NGX_CONF_ERROR;
[1045]     }
[1046] 
[1047]     index = ngx_http_get_variable_index(cf, &value[1]);
[1048]     if (index == NGX_ERROR) {
[1049]         return NGX_CONF_ERROR;
[1050]     }
[1051] 
[1052]     pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);
[1053] 
[1054]     if (pmcf->perl == NULL) {
[1055]         if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
[1056]             return NGX_CONF_ERROR;
[1057]         }
[1058]     }
[1059] 
[1060]     pv->handler = value[2];
[1061] 
[1062]     {
[1063] 
[1064]     dTHXa(pmcf->perl);
[1065]     PERL_SET_CONTEXT(pmcf->perl);
[1066]     PERL_SET_INTERP(pmcf->perl);
[1067] 
[1068]     ngx_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);
[1069] 
[1070]     if (pv->sub == &PL_sv_undef) {
[1071]         ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
[1072]                            "eval_pv(\"%V\") failed", &value[2]);
[1073]         return NGX_CONF_ERROR;
[1074]     }
[1075] 
[1076]     if (pv->sub == NULL) {
[1077]         pv->sub = newSVpvn((char *) value[2].data, value[2].len);
[1078]     }
[1079] 
[1080]     }
[1081] 
[1082]     v->get_handler = ngx_http_perl_variable;
[1083]     v->data = (uintptr_t) pv;
[1084] 
[1085]     return NGX_CONF_OK;
[1086] }
[1087] 
[1088] 
[1089] static ngx_int_t
[1090] ngx_http_perl_init_worker(ngx_cycle_t *cycle)
[1091] {
[1092]     ngx_http_perl_main_conf_t  *pmcf;
[1093] 
[1094]     pmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_perl_module);
[1095] 
[1096]     if (pmcf) {
[1097]         dTHXa(pmcf->perl);
[1098]         PERL_SET_CONTEXT(pmcf->perl);
[1099]         PERL_SET_INTERP(pmcf->perl);
[1100] 
[1101]         /* set worker's $$ */
[1102] 
[1103]         sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) ngx_pid);
[1104]     }
[1105] 
[1106]     return NGX_OK;
[1107] }
[1108] 
[1109] 
[1110] static void
[1111] ngx_http_perl_exit(ngx_cycle_t *cycle)
[1112] {
[1113] #if (NGX_HAVE_PERL_MULTIPLICITY)
[1114] 
[1115]     /*
[1116]      * the master exit hook is run before global pool cleanup,
[1117]      * therefore just set flag here
[1118]      */
[1119] 
[1120]     ngx_perl_term = 1;
[1121] 
[1122] #else
[1123] 
[1124]     if (nginx_stash) {
[1125]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");
[1126] 
[1127]         (void) perl_destruct(perl);
[1128] 
[1129]         perl_free(perl);
[1130] 
[1131]         PERL_SYS_TERM();
[1132]     }
[1133] 
[1134] #endif
[1135] }
