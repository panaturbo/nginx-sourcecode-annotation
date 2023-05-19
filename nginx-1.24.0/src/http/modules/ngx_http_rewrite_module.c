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
[13] typedef struct {
[14]     ngx_array_t  *codes;        /* uintptr_t */
[15] 
[16]     ngx_uint_t    stack_size;
[17] 
[18]     ngx_flag_t    log;
[19]     ngx_flag_t    uninitialized_variable_warn;
[20] } ngx_http_rewrite_loc_conf_t;
[21] 
[22] 
[23] static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf);
[24] static char *ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf,
[25]     void *parent, void *child);
[26] static ngx_int_t ngx_http_rewrite_init(ngx_conf_t *cf);
[27] static char *ngx_http_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[28] static char *ngx_http_rewrite_return(ngx_conf_t *cf, ngx_command_t *cmd,
[29]     void *conf);
[30] static char *ngx_http_rewrite_break(ngx_conf_t *cf, ngx_command_t *cmd,
[31]     void *conf);
[32] static char *ngx_http_rewrite_if(ngx_conf_t *cf, ngx_command_t *cmd,
[33]     void *conf);
[34] static char * ngx_http_rewrite_if_condition(ngx_conf_t *cf,
[35]     ngx_http_rewrite_loc_conf_t *lcf);
[36] static char *ngx_http_rewrite_variable(ngx_conf_t *cf,
[37]     ngx_http_rewrite_loc_conf_t *lcf, ngx_str_t *value);
[38] static char *ngx_http_rewrite_set(ngx_conf_t *cf, ngx_command_t *cmd,
[39]     void *conf);
[40] static char * ngx_http_rewrite_value(ngx_conf_t *cf,
[41]     ngx_http_rewrite_loc_conf_t *lcf, ngx_str_t *value);
[42] 
[43] 
[44] static ngx_command_t  ngx_http_rewrite_commands[] = {
[45] 
[46]     { ngx_string("rewrite"),
[47]       NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[48]                        |NGX_CONF_TAKE23,
[49]       ngx_http_rewrite,
[50]       NGX_HTTP_LOC_CONF_OFFSET,
[51]       0,
[52]       NULL },
[53] 
[54]     { ngx_string("return"),
[55]       NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[56]                        |NGX_CONF_TAKE12,
[57]       ngx_http_rewrite_return,
[58]       NGX_HTTP_LOC_CONF_OFFSET,
[59]       0,
[60]       NULL },
[61] 
[62]     { ngx_string("break"),
[63]       NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[64]                        |NGX_CONF_NOARGS,
[65]       ngx_http_rewrite_break,
[66]       NGX_HTTP_LOC_CONF_OFFSET,
[67]       0,
[68]       NULL },
[69] 
[70]     { ngx_string("if"),
[71]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_1MORE,
[72]       ngx_http_rewrite_if,
[73]       NGX_HTTP_LOC_CONF_OFFSET,
[74]       0,
[75]       NULL },
[76] 
[77]     { ngx_string("set"),
[78]       NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[79]                        |NGX_CONF_TAKE2,
[80]       ngx_http_rewrite_set,
[81]       NGX_HTTP_LOC_CONF_OFFSET,
[82]       0,
[83]       NULL },
[84] 
[85]     { ngx_string("rewrite_log"),
[86]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF
[87]                         |NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
[88]       ngx_conf_set_flag_slot,
[89]       NGX_HTTP_LOC_CONF_OFFSET,
[90]       offsetof(ngx_http_rewrite_loc_conf_t, log),
[91]       NULL },
[92] 
[93]     { ngx_string("uninitialized_variable_warn"),
[94]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF
[95]                         |NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
[96]       ngx_conf_set_flag_slot,
[97]       NGX_HTTP_LOC_CONF_OFFSET,
[98]       offsetof(ngx_http_rewrite_loc_conf_t, uninitialized_variable_warn),
[99]       NULL },
[100] 
[101]       ngx_null_command
[102] };
[103] 
[104] 
[105] static ngx_http_module_t  ngx_http_rewrite_module_ctx = {
[106]     NULL,                                  /* preconfiguration */
[107]     ngx_http_rewrite_init,                 /* postconfiguration */
[108] 
[109]     NULL,                                  /* create main configuration */
[110]     NULL,                                  /* init main configuration */
[111] 
[112]     NULL,                                  /* create server configuration */
[113]     NULL,                                  /* merge server configuration */
[114] 
[115]     ngx_http_rewrite_create_loc_conf,      /* create location configuration */
[116]     ngx_http_rewrite_merge_loc_conf        /* merge location configuration */
[117] };
[118] 
[119] 
[120] ngx_module_t  ngx_http_rewrite_module = {
[121]     NGX_MODULE_V1,
[122]     &ngx_http_rewrite_module_ctx,          /* module context */
[123]     ngx_http_rewrite_commands,             /* module directives */
[124]     NGX_HTTP_MODULE,                       /* module type */
[125]     NULL,                                  /* init master */
[126]     NULL,                                  /* init module */
[127]     NULL,                                  /* init process */
[128]     NULL,                                  /* init thread */
[129]     NULL,                                  /* exit thread */
[130]     NULL,                                  /* exit process */
[131]     NULL,                                  /* exit master */
[132]     NGX_MODULE_V1_PADDING
[133] };
[134] 
[135] 
[136] static ngx_int_t
[137] ngx_http_rewrite_handler(ngx_http_request_t *r)
[138] {
[139]     ngx_int_t                     index;
[140]     ngx_http_script_code_pt       code;
[141]     ngx_http_script_engine_t     *e;
[142]     ngx_http_core_srv_conf_t     *cscf;
[143]     ngx_http_core_main_conf_t    *cmcf;
[144]     ngx_http_rewrite_loc_conf_t  *rlcf;
[145] 
[146]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[147]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[148]     index = cmcf->phase_engine.location_rewrite_index;
[149] 
[150]     if (r->phase_handler == index && r->loc_conf == cscf->ctx->loc_conf) {
[151]         /* skipping location rewrite phase for server null location */
[152]         return NGX_DECLINED;
[153]     }
[154] 
[155]     rlcf = ngx_http_get_module_loc_conf(r, ngx_http_rewrite_module);
[156] 
[157]     if (rlcf->codes == NULL) {
[158]         return NGX_DECLINED;
[159]     }
[160] 
[161]     e = ngx_pcalloc(r->pool, sizeof(ngx_http_script_engine_t));
[162]     if (e == NULL) {
[163]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[164]     }
[165] 
[166]     e->sp = ngx_pcalloc(r->pool,
[167]                         rlcf->stack_size * sizeof(ngx_http_variable_value_t));
[168]     if (e->sp == NULL) {
[169]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[170]     }
[171] 
[172]     e->ip = rlcf->codes->elts;
[173]     e->request = r;
[174]     e->quote = 1;
[175]     e->log = rlcf->log;
[176]     e->status = NGX_DECLINED;
[177] 
[178]     while (*(uintptr_t *) e->ip) {
[179]         code = *(ngx_http_script_code_pt *) e->ip;
[180]         code(e);
[181]     }
[182] 
[183]     return e->status;
[184] }
[185] 
[186] 
[187] static ngx_int_t
[188] ngx_http_rewrite_var(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[189]     uintptr_t data)
[190] {
[191]     ngx_http_variable_t          *var;
[192]     ngx_http_core_main_conf_t    *cmcf;
[193]     ngx_http_rewrite_loc_conf_t  *rlcf;
[194] 
[195]     rlcf = ngx_http_get_module_loc_conf(r, ngx_http_rewrite_module);
[196] 
[197]     if (rlcf->uninitialized_variable_warn == 0) {
[198]         *v = ngx_http_variable_null_value;
[199]         return NGX_OK;
[200]     }
[201] 
[202]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[203] 
[204]     var = cmcf->variables.elts;
[205] 
[206]     /*
[207]      * the ngx_http_rewrite_module sets variables directly in r->variables,
[208]      * and they should be handled by ngx_http_get_indexed_variable(),
[209]      * so the handler is called only if the variable is not initialized
[210]      */
[211] 
[212]     ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[213]                   "using uninitialized \"%V\" variable", &var[data].name);
[214] 
[215]     *v = ngx_http_variable_null_value;
[216] 
[217]     return NGX_OK;
[218] }
[219] 
[220] 
[221] static void *
[222] ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf)
[223] {
[224]     ngx_http_rewrite_loc_conf_t  *conf;
[225] 
[226]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rewrite_loc_conf_t));
[227]     if (conf == NULL) {
[228]         return NULL;
[229]     }
[230] 
[231]     conf->stack_size = NGX_CONF_UNSET_UINT;
[232]     conf->log = NGX_CONF_UNSET;
[233]     conf->uninitialized_variable_warn = NGX_CONF_UNSET;
[234] 
[235]     return conf;
[236] }
[237] 
[238] 
[239] static char *
[240] ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[241] {
[242]     ngx_http_rewrite_loc_conf_t *prev = parent;
[243]     ngx_http_rewrite_loc_conf_t *conf = child;
[244] 
[245]     uintptr_t  *code;
[246] 
[247]     ngx_conf_merge_value(conf->log, prev->log, 0);
[248]     ngx_conf_merge_value(conf->uninitialized_variable_warn,
[249]                          prev->uninitialized_variable_warn, 1);
[250]     ngx_conf_merge_uint_value(conf->stack_size, prev->stack_size, 10);
[251] 
[252]     if (conf->codes == NULL) {
[253]         return NGX_CONF_OK;
[254]     }
[255] 
[256]     if (conf->codes == prev->codes) {
[257]         return NGX_CONF_OK;
[258]     }
[259] 
[260]     code = ngx_array_push_n(conf->codes, sizeof(uintptr_t));
[261]     if (code == NULL) {
[262]         return NGX_CONF_ERROR;
[263]     }
[264] 
[265]     *code = (uintptr_t) NULL;
[266] 
[267]     return NGX_CONF_OK;
[268] }
[269] 
[270] 
[271] static ngx_int_t
[272] ngx_http_rewrite_init(ngx_conf_t *cf)
[273] {
[274]     ngx_http_handler_pt        *h;
[275]     ngx_http_core_main_conf_t  *cmcf;
[276] 
[277]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[278] 
[279]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
[280]     if (h == NULL) {
[281]         return NGX_ERROR;
[282]     }
[283] 
[284]     *h = ngx_http_rewrite_handler;
[285] 
[286]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
[287]     if (h == NULL) {
[288]         return NGX_ERROR;
[289]     }
[290] 
[291]     *h = ngx_http_rewrite_handler;
[292] 
[293]     return NGX_OK;
[294] }
[295] 
[296] 
[297] static char *
[298] ngx_http_rewrite(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[299] {
[300]     ngx_http_rewrite_loc_conf_t  *lcf = conf;
[301] 
[302]     ngx_str_t                         *value;
[303]     ngx_uint_t                         last;
[304]     ngx_regex_compile_t                rc;
[305]     ngx_http_script_code_pt           *code;
[306]     ngx_http_script_compile_t          sc;
[307]     ngx_http_script_regex_code_t      *regex;
[308]     ngx_http_script_regex_end_code_t  *regex_end;
[309]     u_char                             errstr[NGX_MAX_CONF_ERRSTR];
[310] 
[311]     regex = ngx_http_script_start_code(cf->pool, &lcf->codes,
[312]                                        sizeof(ngx_http_script_regex_code_t));
[313]     if (regex == NULL) {
[314]         return NGX_CONF_ERROR;
[315]     }
[316] 
[317]     ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));
[318] 
[319]     value = cf->args->elts;
[320] 
[321]     if (value[2].len == 0) {
[322]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty replacement");
[323]         return NGX_CONF_ERROR;
[324]     }
[325] 
[326]     ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[327] 
[328]     rc.pattern = value[1];
[329]     rc.err.len = NGX_MAX_CONF_ERRSTR;
[330]     rc.err.data = errstr;
[331] 
[332]     /* TODO: NGX_REGEX_CASELESS */
[333] 
[334]     regex->regex = ngx_http_regex_compile(cf, &rc);
[335]     if (regex->regex == NULL) {
[336]         return NGX_CONF_ERROR;
[337]     }
[338] 
[339]     regex->code = ngx_http_script_regex_start_code;
[340]     regex->uri = 1;
[341]     regex->name = value[1];
[342] 
[343]     if (value[2].data[value[2].len - 1] == '?') {
[344] 
[345]         /* the last "?" drops the original arguments */
[346]         value[2].len--;
[347] 
[348]     } else {
[349]         regex->add_args = 1;
[350]     }
[351] 
[352]     last = 0;
[353] 
[354]     if (ngx_strncmp(value[2].data, "http://", sizeof("http://") - 1) == 0
[355]         || ngx_strncmp(value[2].data, "https://", sizeof("https://") - 1) == 0
[356]         || ngx_strncmp(value[2].data, "$scheme", sizeof("$scheme") - 1) == 0)
[357]     {
[358]         regex->status = NGX_HTTP_MOVED_TEMPORARILY;
[359]         regex->redirect = 1;
[360]         last = 1;
[361]     }
[362] 
[363]     if (cf->args->nelts == 4) {
[364]         if (ngx_strcmp(value[3].data, "last") == 0) {
[365]             last = 1;
[366] 
[367]         } else if (ngx_strcmp(value[3].data, "break") == 0) {
[368]             regex->break_cycle = 1;
[369]             last = 1;
[370] 
[371]         } else if (ngx_strcmp(value[3].data, "redirect") == 0) {
[372]             regex->status = NGX_HTTP_MOVED_TEMPORARILY;
[373]             regex->redirect = 1;
[374]             last = 1;
[375] 
[376]         } else if (ngx_strcmp(value[3].data, "permanent") == 0) {
[377]             regex->status = NGX_HTTP_MOVED_PERMANENTLY;
[378]             regex->redirect = 1;
[379]             last = 1;
[380] 
[381]         } else {
[382]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[383]                                "invalid parameter \"%V\"", &value[3]);
[384]             return NGX_CONF_ERROR;
[385]         }
[386]     }
[387] 
[388]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[389] 
[390]     sc.cf = cf;
[391]     sc.source = &value[2];
[392]     sc.lengths = &regex->lengths;
[393]     sc.values = &lcf->codes;
[394]     sc.variables = ngx_http_script_variables_count(&value[2]);
[395]     sc.main = regex;
[396]     sc.complete_lengths = 1;
[397]     sc.compile_args = !regex->redirect;
[398] 
[399]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[400]         return NGX_CONF_ERROR;
[401]     }
[402] 
[403]     regex = sc.main;
[404] 
[405]     regex->size = sc.size;
[406]     regex->args = sc.args;
[407] 
[408]     if (sc.variables == 0 && !sc.dup_capture) {
[409]         regex->lengths = NULL;
[410]     }
[411] 
[412]     regex_end = ngx_http_script_add_code(lcf->codes,
[413]                                       sizeof(ngx_http_script_regex_end_code_t),
[414]                                       &regex);
[415]     if (regex_end == NULL) {
[416]         return NGX_CONF_ERROR;
[417]     }
[418] 
[419]     regex_end->code = ngx_http_script_regex_end_code;
[420]     regex_end->uri = regex->uri;
[421]     regex_end->args = regex->args;
[422]     regex_end->add_args = regex->add_args;
[423]     regex_end->redirect = regex->redirect;
[424] 
[425]     if (last) {
[426]         code = ngx_http_script_add_code(lcf->codes, sizeof(uintptr_t), &regex);
[427]         if (code == NULL) {
[428]             return NGX_CONF_ERROR;
[429]         }
[430] 
[431]         *code = NULL;
[432]     }
[433] 
[434]     regex->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
[435]                                               - (u_char *) regex;
[436] 
[437]     return NGX_CONF_OK;
[438] }
[439] 
[440] 
[441] static char *
[442] ngx_http_rewrite_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[443] {
[444]     ngx_http_rewrite_loc_conf_t  *lcf = conf;
[445] 
[446]     u_char                            *p;
[447]     ngx_str_t                         *value, *v;
[448]     ngx_http_script_return_code_t     *ret;
[449]     ngx_http_compile_complex_value_t   ccv;
[450] 
[451]     ret = ngx_http_script_start_code(cf->pool, &lcf->codes,
[452]                                      sizeof(ngx_http_script_return_code_t));
[453]     if (ret == NULL) {
[454]         return NGX_CONF_ERROR;
[455]     }
[456] 
[457]     value = cf->args->elts;
[458] 
[459]     ngx_memzero(ret, sizeof(ngx_http_script_return_code_t));
[460] 
[461]     ret->code = ngx_http_script_return_code;
[462] 
[463]     p = value[1].data;
[464] 
[465]     ret->status = ngx_atoi(p, value[1].len);
[466] 
[467]     if (ret->status == (uintptr_t) NGX_ERROR) {
[468] 
[469]         if (cf->args->nelts == 2
[470]             && (ngx_strncmp(p, "http://", sizeof("http://") - 1) == 0
[471]                 || ngx_strncmp(p, "https://", sizeof("https://") - 1) == 0
[472]                 || ngx_strncmp(p, "$scheme", sizeof("$scheme") - 1) == 0))
[473]         {
[474]             ret->status = NGX_HTTP_MOVED_TEMPORARILY;
[475]             v = &value[1];
[476] 
[477]         } else {
[478]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[479]                                "invalid return code \"%V\"", &value[1]);
[480]             return NGX_CONF_ERROR;
[481]         }
[482] 
[483]     } else {
[484] 
[485]         if (ret->status > 999) {
[486]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[487]                                "invalid return code \"%V\"", &value[1]);
[488]             return NGX_CONF_ERROR;
[489]         }
[490] 
[491]         if (cf->args->nelts == 2) {
[492]             return NGX_CONF_OK;
[493]         }
[494] 
[495]         v = &value[2];
[496]     }
[497] 
[498]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[499] 
[500]     ccv.cf = cf;
[501]     ccv.value = v;
[502]     ccv.complex_value = &ret->text;
[503] 
[504]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[505]         return NGX_CONF_ERROR;
[506]     }
[507] 
[508]     return NGX_CONF_OK;
[509] }
[510] 
[511] 
[512] static char *
[513] ngx_http_rewrite_break(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[514] {
[515]     ngx_http_rewrite_loc_conf_t *lcf = conf;
[516] 
[517]     ngx_http_script_code_pt  *code;
[518] 
[519]     code = ngx_http_script_start_code(cf->pool, &lcf->codes, sizeof(uintptr_t));
[520]     if (code == NULL) {
[521]         return NGX_CONF_ERROR;
[522]     }
[523] 
[524]     *code = ngx_http_script_break_code;
[525] 
[526]     return NGX_CONF_OK;
[527] }
[528] 
[529] 
[530] static char *
[531] ngx_http_rewrite_if(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[532] {
[533]     ngx_http_rewrite_loc_conf_t  *lcf = conf;
[534] 
[535]     void                         *mconf;
[536]     char                         *rv;
[537]     u_char                       *elts;
[538]     ngx_uint_t                    i;
[539]     ngx_conf_t                    save;
[540]     ngx_http_module_t            *module;
[541]     ngx_http_conf_ctx_t          *ctx, *pctx;
[542]     ngx_http_core_loc_conf_t     *clcf, *pclcf;
[543]     ngx_http_script_if_code_t    *if_code;
[544]     ngx_http_rewrite_loc_conf_t  *nlcf;
[545] 
[546]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
[547]     if (ctx == NULL) {
[548]         return NGX_CONF_ERROR;
[549]     }
[550] 
[551]     pctx = cf->ctx;
[552]     ctx->main_conf = pctx->main_conf;
[553]     ctx->srv_conf = pctx->srv_conf;
[554] 
[555]     ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
[556]     if (ctx->loc_conf == NULL) {
[557]         return NGX_CONF_ERROR;
[558]     }
[559] 
[560]     for (i = 0; cf->cycle->modules[i]; i++) {
[561]         if (cf->cycle->modules[i]->type != NGX_HTTP_MODULE) {
[562]             continue;
[563]         }
[564] 
[565]         module = cf->cycle->modules[i]->ctx;
[566] 
[567]         if (module->create_loc_conf) {
[568] 
[569]             mconf = module->create_loc_conf(cf);
[570]             if (mconf == NULL) {
[571]                 return NGX_CONF_ERROR;
[572]             }
[573] 
[574]             ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
[575]         }
[576]     }
[577] 
[578]     pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];
[579] 
[580]     clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
[581]     clcf->loc_conf = ctx->loc_conf;
[582]     clcf->name = pclcf->name;
[583]     clcf->noname = 1;
[584] 
[585]     if (ngx_http_add_location(cf, &pclcf->locations, clcf) != NGX_OK) {
[586]         return NGX_CONF_ERROR;
[587]     }
[588] 
[589]     if (ngx_http_rewrite_if_condition(cf, lcf) != NGX_CONF_OK) {
[590]         return NGX_CONF_ERROR;
[591]     }
[592] 
[593]     if_code = ngx_array_push_n(lcf->codes, sizeof(ngx_http_script_if_code_t));
[594]     if (if_code == NULL) {
[595]         return NGX_CONF_ERROR;
[596]     }
[597] 
[598]     if_code->code = ngx_http_script_if_code;
[599] 
[600]     elts = lcf->codes->elts;
[601] 
[602] 
[603]     /* the inner directives must be compiled to the same code array */
[604] 
[605]     nlcf = ctx->loc_conf[ngx_http_rewrite_module.ctx_index];
[606]     nlcf->codes = lcf->codes;
[607] 
[608] 
[609]     save = *cf;
[610]     cf->ctx = ctx;
[611] 
[612]     if (cf->cmd_type == NGX_HTTP_SRV_CONF) {
[613]         if_code->loc_conf = NULL;
[614]         cf->cmd_type = NGX_HTTP_SIF_CONF;
[615] 
[616]     } else {
[617]         if_code->loc_conf = ctx->loc_conf;
[618]         cf->cmd_type = NGX_HTTP_LIF_CONF;
[619]     }
[620] 
[621]     rv = ngx_conf_parse(cf, NULL);
[622] 
[623]     *cf = save;
[624] 
[625]     if (rv != NGX_CONF_OK) {
[626]         return rv;
[627]     }
[628] 
[629] 
[630]     if (elts != lcf->codes->elts) {
[631]         if_code = (ngx_http_script_if_code_t *)
[632]                    ((u_char *) if_code + ((u_char *) lcf->codes->elts - elts));
[633]     }
[634] 
[635]     if_code->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
[636]                                                 - (u_char *) if_code;
[637] 
[638]     /* the code array belong to parent block */
[639] 
[640]     nlcf->codes = NULL;
[641] 
[642]     return NGX_CONF_OK;
[643] }
[644] 
[645] 
[646] static char *
[647] ngx_http_rewrite_if_condition(ngx_conf_t *cf, ngx_http_rewrite_loc_conf_t *lcf)
[648] {
[649]     u_char                        *p;
[650]     size_t                         len;
[651]     ngx_str_t                     *value;
[652]     ngx_uint_t                     cur, last;
[653]     ngx_regex_compile_t            rc;
[654]     ngx_http_script_code_pt       *code;
[655]     ngx_http_script_file_code_t   *fop;
[656]     ngx_http_script_regex_code_t  *regex;
[657]     u_char                         errstr[NGX_MAX_CONF_ERRSTR];
[658] 
[659]     value = cf->args->elts;
[660]     last = cf->args->nelts - 1;
[661] 
[662]     if (value[1].len < 1 || value[1].data[0] != '(') {
[663]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[664]                            "invalid condition \"%V\"", &value[1]);
[665]         return NGX_CONF_ERROR;
[666]     }
[667] 
[668]     if (value[1].len == 1) {
[669]         cur = 2;
[670] 
[671]     } else {
[672]         cur = 1;
[673]         value[1].len--;
[674]         value[1].data++;
[675]     }
[676] 
[677]     if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
[678]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[679]                            "invalid condition \"%V\"", &value[last]);
[680]         return NGX_CONF_ERROR;
[681]     }
[682] 
[683]     if (value[last].len == 1) {
[684]         last--;
[685] 
[686]     } else {
[687]         value[last].len--;
[688]         value[last].data[value[last].len] = '\0';
[689]     }
[690] 
[691]     len = value[cur].len;
[692]     p = value[cur].data;
[693] 
[694]     if (len > 1 && p[0] == '$') {
[695] 
[696]         if (cur != last && cur + 2 != last) {
[697]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[698]                                "invalid condition \"%V\"", &value[cur]);
[699]             return NGX_CONF_ERROR;
[700]         }
[701] 
[702]         if (ngx_http_rewrite_variable(cf, lcf, &value[cur]) != NGX_CONF_OK) {
[703]             return NGX_CONF_ERROR;
[704]         }
[705] 
[706]         if (cur == last) {
[707]             return NGX_CONF_OK;
[708]         }
[709] 
[710]         cur++;
[711] 
[712]         len = value[cur].len;
[713]         p = value[cur].data;
[714] 
[715]         if (len == 1 && p[0] == '=') {
[716] 
[717]             if (ngx_http_rewrite_value(cf, lcf, &value[last]) != NGX_CONF_OK) {
[718]                 return NGX_CONF_ERROR;
[719]             }
[720] 
[721]             code = ngx_http_script_start_code(cf->pool, &lcf->codes,
[722]                                               sizeof(uintptr_t));
[723]             if (code == NULL) {
[724]                 return NGX_CONF_ERROR;
[725]             }
[726] 
[727]             *code = ngx_http_script_equal_code;
[728] 
[729]             return NGX_CONF_OK;
[730]         }
[731] 
[732]         if (len == 2 && p[0] == '!' && p[1] == '=') {
[733] 
[734]             if (ngx_http_rewrite_value(cf, lcf, &value[last]) != NGX_CONF_OK) {
[735]                 return NGX_CONF_ERROR;
[736]             }
[737] 
[738]             code = ngx_http_script_start_code(cf->pool, &lcf->codes,
[739]                                               sizeof(uintptr_t));
[740]             if (code == NULL) {
[741]                 return NGX_CONF_ERROR;
[742]             }
[743] 
[744]             *code = ngx_http_script_not_equal_code;
[745]             return NGX_CONF_OK;
[746]         }
[747] 
[748]         if ((len == 1 && p[0] == '~')
[749]             || (len == 2 && p[0] == '~' && p[1] == '*')
[750]             || (len == 2 && p[0] == '!' && p[1] == '~')
[751]             || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
[752]         {
[753]             regex = ngx_http_script_start_code(cf->pool, &lcf->codes,
[754]                                          sizeof(ngx_http_script_regex_code_t));
[755]             if (regex == NULL) {
[756]                 return NGX_CONF_ERROR;
[757]             }
[758] 
[759]             ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));
[760] 
[761]             ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
[762] 
[763]             rc.pattern = value[last];
[764]             rc.options = (p[len - 1] == '*') ? NGX_REGEX_CASELESS : 0;
[765]             rc.err.len = NGX_MAX_CONF_ERRSTR;
[766]             rc.err.data = errstr;
[767] 
[768]             regex->regex = ngx_http_regex_compile(cf, &rc);
[769]             if (regex->regex == NULL) {
[770]                 return NGX_CONF_ERROR;
[771]             }
[772] 
[773]             regex->code = ngx_http_script_regex_start_code;
[774]             regex->next = sizeof(ngx_http_script_regex_code_t);
[775]             regex->test = 1;
[776]             if (p[0] == '!') {
[777]                 regex->negative_test = 1;
[778]             }
[779]             regex->name = value[last];
[780] 
[781]             return NGX_CONF_OK;
[782]         }
[783] 
[784]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[785]                            "unexpected \"%V\" in condition", &value[cur]);
[786]         return NGX_CONF_ERROR;
[787] 
[788]     } else if ((len == 2 && p[0] == '-')
[789]                || (len == 3 && p[0] == '!' && p[1] == '-'))
[790]     {
[791]         if (cur + 1 != last) {
[792]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[793]                                "invalid condition \"%V\"", &value[cur]);
[794]             return NGX_CONF_ERROR;
[795]         }
[796] 
[797]         value[last].data[value[last].len] = '\0';
[798]         value[last].len++;
[799] 
[800]         if (ngx_http_rewrite_value(cf, lcf, &value[last]) != NGX_CONF_OK) {
[801]             return NGX_CONF_ERROR;
[802]         }
[803] 
[804]         fop = ngx_http_script_start_code(cf->pool, &lcf->codes,
[805]                                           sizeof(ngx_http_script_file_code_t));
[806]         if (fop == NULL) {
[807]             return NGX_CONF_ERROR;
[808]         }
[809] 
[810]         fop->code = ngx_http_script_file_code;
[811] 
[812]         if (p[1] == 'f') {
[813]             fop->op = ngx_http_script_file_plain;
[814]             return NGX_CONF_OK;
[815]         }
[816] 
[817]         if (p[1] == 'd') {
[818]             fop->op = ngx_http_script_file_dir;
[819]             return NGX_CONF_OK;
[820]         }
[821] 
[822]         if (p[1] == 'e') {
[823]             fop->op = ngx_http_script_file_exists;
[824]             return NGX_CONF_OK;
[825]         }
[826] 
[827]         if (p[1] == 'x') {
[828]             fop->op = ngx_http_script_file_exec;
[829]             return NGX_CONF_OK;
[830]         }
[831] 
[832]         if (p[0] == '!') {
[833]             if (p[2] == 'f') {
[834]                 fop->op = ngx_http_script_file_not_plain;
[835]                 return NGX_CONF_OK;
[836]             }
[837] 
[838]             if (p[2] == 'd') {
[839]                 fop->op = ngx_http_script_file_not_dir;
[840]                 return NGX_CONF_OK;
[841]             }
[842] 
[843]             if (p[2] == 'e') {
[844]                 fop->op = ngx_http_script_file_not_exists;
[845]                 return NGX_CONF_OK;
[846]             }
[847] 
[848]             if (p[2] == 'x') {
[849]                 fop->op = ngx_http_script_file_not_exec;
[850]                 return NGX_CONF_OK;
[851]             }
[852]         }
[853] 
[854]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[855]                            "invalid condition \"%V\"", &value[cur]);
[856]         return NGX_CONF_ERROR;
[857]     }
[858] 
[859]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[860]                        "invalid condition \"%V\"", &value[cur]);
[861] 
[862]     return NGX_CONF_ERROR;
[863] }
[864] 
[865] 
[866] static char *
[867] ngx_http_rewrite_variable(ngx_conf_t *cf, ngx_http_rewrite_loc_conf_t *lcf,
[868]     ngx_str_t *value)
[869] {
[870]     ngx_int_t                    index;
[871]     ngx_http_script_var_code_t  *var_code;
[872] 
[873]     value->len--;
[874]     value->data++;
[875] 
[876]     index = ngx_http_get_variable_index(cf, value);
[877] 
[878]     if (index == NGX_ERROR) {
[879]         return NGX_CONF_ERROR;
[880]     }
[881] 
[882]     var_code = ngx_http_script_start_code(cf->pool, &lcf->codes,
[883]                                           sizeof(ngx_http_script_var_code_t));
[884]     if (var_code == NULL) {
[885]         return NGX_CONF_ERROR;
[886]     }
[887] 
[888]     var_code->code = ngx_http_script_var_code;
[889]     var_code->index = index;
[890] 
[891]     return NGX_CONF_OK;
[892] }
[893] 
[894] 
[895] static char *
[896] ngx_http_rewrite_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[897] {
[898]     ngx_http_rewrite_loc_conf_t  *lcf = conf;
[899] 
[900]     ngx_int_t                            index;
[901]     ngx_str_t                           *value;
[902]     ngx_http_variable_t                 *v;
[903]     ngx_http_script_var_code_t          *vcode;
[904]     ngx_http_script_var_handler_code_t  *vhcode;
[905] 
[906]     value = cf->args->elts;
[907] 
[908]     if (value[1].data[0] != '$') {
[909]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[910]                            "invalid variable name \"%V\"", &value[1]);
[911]         return NGX_CONF_ERROR;
[912]     }
[913] 
[914]     value[1].len--;
[915]     value[1].data++;
[916] 
[917]     v = ngx_http_add_variable(cf, &value[1],
[918]                               NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_WEAK);
[919]     if (v == NULL) {
[920]         return NGX_CONF_ERROR;
[921]     }
[922] 
[923]     index = ngx_http_get_variable_index(cf, &value[1]);
[924]     if (index == NGX_ERROR) {
[925]         return NGX_CONF_ERROR;
[926]     }
[927] 
[928]     if (v->get_handler == NULL) {
[929]         v->get_handler = ngx_http_rewrite_var;
[930]         v->data = index;
[931]     }
[932] 
[933]     if (ngx_http_rewrite_value(cf, lcf, &value[2]) != NGX_CONF_OK) {
[934]         return NGX_CONF_ERROR;
[935]     }
[936] 
[937]     if (v->set_handler) {
[938]         vhcode = ngx_http_script_start_code(cf->pool, &lcf->codes,
[939]                                    sizeof(ngx_http_script_var_handler_code_t));
[940]         if (vhcode == NULL) {
[941]             return NGX_CONF_ERROR;
[942]         }
[943] 
[944]         vhcode->code = ngx_http_script_var_set_handler_code;
[945]         vhcode->handler = v->set_handler;
[946]         vhcode->data = v->data;
[947] 
[948]         return NGX_CONF_OK;
[949]     }
[950] 
[951]     vcode = ngx_http_script_start_code(cf->pool, &lcf->codes,
[952]                                        sizeof(ngx_http_script_var_code_t));
[953]     if (vcode == NULL) {
[954]         return NGX_CONF_ERROR;
[955]     }
[956] 
[957]     vcode->code = ngx_http_script_set_var_code;
[958]     vcode->index = (uintptr_t) index;
[959] 
[960]     return NGX_CONF_OK;
[961] }
[962] 
[963] 
[964] static char *
[965] ngx_http_rewrite_value(ngx_conf_t *cf, ngx_http_rewrite_loc_conf_t *lcf,
[966]     ngx_str_t *value)
[967] {
[968]     ngx_int_t                              n;
[969]     ngx_http_script_compile_t              sc;
[970]     ngx_http_script_value_code_t          *val;
[971]     ngx_http_script_complex_value_code_t  *complex;
[972] 
[973]     n = ngx_http_script_variables_count(value);
[974] 
[975]     if (n == 0) {
[976]         val = ngx_http_script_start_code(cf->pool, &lcf->codes,
[977]                                          sizeof(ngx_http_script_value_code_t));
[978]         if (val == NULL) {
[979]             return NGX_CONF_ERROR;
[980]         }
[981] 
[982]         n = ngx_atoi(value->data, value->len);
[983] 
[984]         if (n == NGX_ERROR) {
[985]             n = 0;
[986]         }
[987] 
[988]         val->code = ngx_http_script_value_code;
[989]         val->value = (uintptr_t) n;
[990]         val->text_len = (uintptr_t) value->len;
[991]         val->text_data = (uintptr_t) value->data;
[992] 
[993]         return NGX_CONF_OK;
[994]     }
[995] 
[996]     complex = ngx_http_script_start_code(cf->pool, &lcf->codes,
[997]                                  sizeof(ngx_http_script_complex_value_code_t));
[998]     if (complex == NULL) {
[999]         return NGX_CONF_ERROR;
[1000]     }
[1001] 
[1002]     complex->code = ngx_http_script_complex_value_code;
[1003]     complex->lengths = NULL;
[1004] 
[1005]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[1006] 
[1007]     sc.cf = cf;
[1008]     sc.source = value;
[1009]     sc.lengths = &complex->lengths;
[1010]     sc.values = &lcf->codes;
[1011]     sc.variables = n;
[1012]     sc.complete_lengths = 1;
[1013] 
[1014]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[1015]         return NGX_CONF_ERROR;
[1016]     }
[1017] 
[1018]     return NGX_CONF_OK;
[1019] }
