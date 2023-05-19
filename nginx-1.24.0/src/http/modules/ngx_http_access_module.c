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
[14]     in_addr_t         mask;
[15]     in_addr_t         addr;
[16]     ngx_uint_t        deny;      /* unsigned  deny:1; */
[17] } ngx_http_access_rule_t;
[18] 
[19] #if (NGX_HAVE_INET6)
[20] 
[21] typedef struct {
[22]     struct in6_addr   addr;
[23]     struct in6_addr   mask;
[24]     ngx_uint_t        deny;      /* unsigned  deny:1; */
[25] } ngx_http_access_rule6_t;
[26] 
[27] #endif
[28] 
[29] #if (NGX_HAVE_UNIX_DOMAIN)
[30] 
[31] typedef struct {
[32]     ngx_uint_t        deny;      /* unsigned  deny:1; */
[33] } ngx_http_access_rule_un_t;
[34] 
[35] #endif
[36] 
[37] typedef struct {
[38]     ngx_array_t      *rules;     /* array of ngx_http_access_rule_t */
[39] #if (NGX_HAVE_INET6)
[40]     ngx_array_t      *rules6;    /* array of ngx_http_access_rule6_t */
[41] #endif
[42] #if (NGX_HAVE_UNIX_DOMAIN)
[43]     ngx_array_t      *rules_un;  /* array of ngx_http_access_rule_un_t */
[44] #endif
[45] } ngx_http_access_loc_conf_t;
[46] 
[47] 
[48] static ngx_int_t ngx_http_access_handler(ngx_http_request_t *r);
[49] static ngx_int_t ngx_http_access_inet(ngx_http_request_t *r,
[50]     ngx_http_access_loc_conf_t *alcf, in_addr_t addr);
[51] #if (NGX_HAVE_INET6)
[52] static ngx_int_t ngx_http_access_inet6(ngx_http_request_t *r,
[53]     ngx_http_access_loc_conf_t *alcf, u_char *p);
[54] #endif
[55] #if (NGX_HAVE_UNIX_DOMAIN)
[56] static ngx_int_t ngx_http_access_unix(ngx_http_request_t *r,
[57]     ngx_http_access_loc_conf_t *alcf);
[58] #endif
[59] static ngx_int_t ngx_http_access_found(ngx_http_request_t *r, ngx_uint_t deny);
[60] static char *ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
[61]     void *conf);
[62] static void *ngx_http_access_create_loc_conf(ngx_conf_t *cf);
[63] static char *ngx_http_access_merge_loc_conf(ngx_conf_t *cf,
[64]     void *parent, void *child);
[65] static ngx_int_t ngx_http_access_init(ngx_conf_t *cf);
[66] 
[67] 
[68] static ngx_command_t  ngx_http_access_commands[] = {
[69] 
[70]     { ngx_string("allow"),
[71]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
[72]                         |NGX_CONF_TAKE1,
[73]       ngx_http_access_rule,
[74]       NGX_HTTP_LOC_CONF_OFFSET,
[75]       0,
[76]       NULL },
[77] 
[78]     { ngx_string("deny"),
[79]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
[80]                         |NGX_CONF_TAKE1,
[81]       ngx_http_access_rule,
[82]       NGX_HTTP_LOC_CONF_OFFSET,
[83]       0,
[84]       NULL },
[85] 
[86]       ngx_null_command
[87] };
[88] 
[89] 
[90] 
[91] static ngx_http_module_t  ngx_http_access_module_ctx = {
[92]     NULL,                                  /* preconfiguration */
[93]     ngx_http_access_init,                  /* postconfiguration */
[94] 
[95]     NULL,                                  /* create main configuration */
[96]     NULL,                                  /* init main configuration */
[97] 
[98]     NULL,                                  /* create server configuration */
[99]     NULL,                                  /* merge server configuration */
[100] 
[101]     ngx_http_access_create_loc_conf,       /* create location configuration */
[102]     ngx_http_access_merge_loc_conf         /* merge location configuration */
[103] };
[104] 
[105] 
[106] ngx_module_t  ngx_http_access_module = {
[107]     NGX_MODULE_V1,
[108]     &ngx_http_access_module_ctx,           /* module context */
[109]     ngx_http_access_commands,              /* module directives */
[110]     NGX_HTTP_MODULE,                       /* module type */
[111]     NULL,                                  /* init master */
[112]     NULL,                                  /* init module */
[113]     NULL,                                  /* init process */
[114]     NULL,                                  /* init thread */
[115]     NULL,                                  /* exit thread */
[116]     NULL,                                  /* exit process */
[117]     NULL,                                  /* exit master */
[118]     NGX_MODULE_V1_PADDING
[119] };
[120] 
[121] 
[122] static ngx_int_t
[123] ngx_http_access_handler(ngx_http_request_t *r)
[124] {
[125]     struct sockaddr_in          *sin;
[126]     ngx_http_access_loc_conf_t  *alcf;
[127] #if (NGX_HAVE_INET6)
[128]     u_char                      *p;
[129]     in_addr_t                    addr;
[130]     struct sockaddr_in6         *sin6;
[131] #endif
[132] 
[133]     alcf = ngx_http_get_module_loc_conf(r, ngx_http_access_module);
[134] 
[135]     switch (r->connection->sockaddr->sa_family) {
[136] 
[137]     case AF_INET:
[138]         if (alcf->rules) {
[139]             sin = (struct sockaddr_in *) r->connection->sockaddr;
[140]             return ngx_http_access_inet(r, alcf, sin->sin_addr.s_addr);
[141]         }
[142]         break;
[143] 
[144] #if (NGX_HAVE_INET6)
[145] 
[146]     case AF_INET6:
[147]         sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
[148]         p = sin6->sin6_addr.s6_addr;
[149] 
[150]         if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
[151]             addr = p[12] << 24;
[152]             addr += p[13] << 16;
[153]             addr += p[14] << 8;
[154]             addr += p[15];
[155]             return ngx_http_access_inet(r, alcf, htonl(addr));
[156]         }
[157] 
[158]         if (alcf->rules6) {
[159]             return ngx_http_access_inet6(r, alcf, p);
[160]         }
[161] 
[162]         break;
[163] 
[164] #endif
[165] 
[166] #if (NGX_HAVE_UNIX_DOMAIN)
[167] 
[168]     case AF_UNIX:
[169]         if (alcf->rules_un) {
[170]             return ngx_http_access_unix(r, alcf);
[171]         }
[172] 
[173]         break;
[174] 
[175] #endif
[176]     }
[177] 
[178]     return NGX_DECLINED;
[179] }
[180] 
[181] 
[182] static ngx_int_t
[183] ngx_http_access_inet(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf,
[184]     in_addr_t addr)
[185] {
[186]     ngx_uint_t               i;
[187]     ngx_http_access_rule_t  *rule;
[188] 
[189]     rule = alcf->rules->elts;
[190]     for (i = 0; i < alcf->rules->nelts; i++) {
[191] 
[192]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[193]                        "access: %08XD %08XD %08XD",
[194]                        addr, rule[i].mask, rule[i].addr);
[195] 
[196]         if ((addr & rule[i].mask) == rule[i].addr) {
[197]             return ngx_http_access_found(r, rule[i].deny);
[198]         }
[199]     }
[200] 
[201]     return NGX_DECLINED;
[202] }
[203] 
[204] 
[205] #if (NGX_HAVE_INET6)
[206] 
[207] static ngx_int_t
[208] ngx_http_access_inet6(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf,
[209]     u_char *p)
[210] {
[211]     ngx_uint_t                n;
[212]     ngx_uint_t                i;
[213]     ngx_http_access_rule6_t  *rule6;
[214] 
[215]     rule6 = alcf->rules6->elts;
[216]     for (i = 0; i < alcf->rules6->nelts; i++) {
[217] 
[218] #if (NGX_DEBUG)
[219]         {
[220]         size_t  cl, ml, al;
[221]         u_char  ct[NGX_INET6_ADDRSTRLEN];
[222]         u_char  mt[NGX_INET6_ADDRSTRLEN];
[223]         u_char  at[NGX_INET6_ADDRSTRLEN];
[224] 
[225]         cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
[226]         ml = ngx_inet6_ntop(rule6[i].mask.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
[227]         al = ngx_inet6_ntop(rule6[i].addr.s6_addr, at, NGX_INET6_ADDRSTRLEN);
[228] 
[229]         ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[230]                        "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
[231]         }
[232] #endif
[233] 
[234]         for (n = 0; n < 16; n++) {
[235]             if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
[236]                 goto next;
[237]             }
[238]         }
[239] 
[240]         return ngx_http_access_found(r, rule6[i].deny);
[241] 
[242]     next:
[243]         continue;
[244]     }
[245] 
[246]     return NGX_DECLINED;
[247] }
[248] 
[249] #endif
[250] 
[251] 
[252] #if (NGX_HAVE_UNIX_DOMAIN)
[253] 
[254] static ngx_int_t
[255] ngx_http_access_unix(ngx_http_request_t *r, ngx_http_access_loc_conf_t *alcf)
[256] {
[257]     ngx_uint_t                  i;
[258]     ngx_http_access_rule_un_t  *rule_un;
[259] 
[260]     rule_un = alcf->rules_un->elts;
[261]     for (i = 0; i < alcf->rules_un->nelts; i++) {
[262] 
[263]         /* TODO: check path */
[264]         if (1) {
[265]             return ngx_http_access_found(r, rule_un[i].deny);
[266]         }
[267]     }
[268] 
[269]     return NGX_DECLINED;
[270] }
[271] 
[272] #endif
[273] 
[274] 
[275] static ngx_int_t
[276] ngx_http_access_found(ngx_http_request_t *r, ngx_uint_t deny)
[277] {
[278]     ngx_http_core_loc_conf_t  *clcf;
[279] 
[280]     if (deny) {
[281]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[282] 
[283]         if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
[284]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[285]                           "access forbidden by rule");
[286]         }
[287] 
[288]         return NGX_HTTP_FORBIDDEN;
[289]     }
[290] 
[291]     return NGX_OK;
[292] }
[293] 
[294] 
[295] static char *
[296] ngx_http_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[297] {
[298]     ngx_http_access_loc_conf_t *alcf = conf;
[299] 
[300]     ngx_int_t                   rc;
[301]     ngx_uint_t                  all;
[302]     ngx_str_t                  *value;
[303]     ngx_cidr_t                  cidr;
[304]     ngx_http_access_rule_t     *rule;
[305] #if (NGX_HAVE_INET6)
[306]     ngx_http_access_rule6_t    *rule6;
[307] #endif
[308] #if (NGX_HAVE_UNIX_DOMAIN)
[309]     ngx_http_access_rule_un_t  *rule_un;
[310] #endif
[311] 
[312]     all = 0;
[313]     ngx_memzero(&cidr, sizeof(ngx_cidr_t));
[314] 
[315]     value = cf->args->elts;
[316] 
[317]     if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
[318]         all = 1;
[319] 
[320] #if (NGX_HAVE_UNIX_DOMAIN)
[321]     } else if (value[1].len == 5 && ngx_strcmp(value[1].data, "unix:") == 0) {
[322]         cidr.family = AF_UNIX;
[323] #endif
[324] 
[325]     } else {
[326]         rc = ngx_ptocidr(&value[1], &cidr);
[327] 
[328]         if (rc == NGX_ERROR) {
[329]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[330]                          "invalid parameter \"%V\"", &value[1]);
[331]             return NGX_CONF_ERROR;
[332]         }
[333] 
[334]         if (rc == NGX_DONE) {
[335]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[336]                          "low address bits of %V are meaningless", &value[1]);
[337]         }
[338]     }
[339] 
[340]     if (cidr.family == AF_INET || all) {
[341] 
[342]         if (alcf->rules == NULL) {
[343]             alcf->rules = ngx_array_create(cf->pool, 4,
[344]                                            sizeof(ngx_http_access_rule_t));
[345]             if (alcf->rules == NULL) {
[346]                 return NGX_CONF_ERROR;
[347]             }
[348]         }
[349] 
[350]         rule = ngx_array_push(alcf->rules);
[351]         if (rule == NULL) {
[352]             return NGX_CONF_ERROR;
[353]         }
[354] 
[355]         rule->mask = cidr.u.in.mask;
[356]         rule->addr = cidr.u.in.addr;
[357]         rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
[358]     }
[359] 
[360] #if (NGX_HAVE_INET6)
[361]     if (cidr.family == AF_INET6 || all) {
[362] 
[363]         if (alcf->rules6 == NULL) {
[364]             alcf->rules6 = ngx_array_create(cf->pool, 4,
[365]                                             sizeof(ngx_http_access_rule6_t));
[366]             if (alcf->rules6 == NULL) {
[367]                 return NGX_CONF_ERROR;
[368]             }
[369]         }
[370] 
[371]         rule6 = ngx_array_push(alcf->rules6);
[372]         if (rule6 == NULL) {
[373]             return NGX_CONF_ERROR;
[374]         }
[375] 
[376]         rule6->mask = cidr.u.in6.mask;
[377]         rule6->addr = cidr.u.in6.addr;
[378]         rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
[379]     }
[380] #endif
[381] 
[382] #if (NGX_HAVE_UNIX_DOMAIN)
[383]     if (cidr.family == AF_UNIX || all) {
[384] 
[385]         if (alcf->rules_un == NULL) {
[386]             alcf->rules_un = ngx_array_create(cf->pool, 1,
[387]                                             sizeof(ngx_http_access_rule_un_t));
[388]             if (alcf->rules_un == NULL) {
[389]                 return NGX_CONF_ERROR;
[390]             }
[391]         }
[392] 
[393]         rule_un = ngx_array_push(alcf->rules_un);
[394]         if (rule_un == NULL) {
[395]             return NGX_CONF_ERROR;
[396]         }
[397] 
[398]         rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
[399]     }
[400] #endif
[401] 
[402]     return NGX_CONF_OK;
[403] }
[404] 
[405] 
[406] static void *
[407] ngx_http_access_create_loc_conf(ngx_conf_t *cf)
[408] {
[409]     ngx_http_access_loc_conf_t  *conf;
[410] 
[411]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_loc_conf_t));
[412]     if (conf == NULL) {
[413]         return NULL;
[414]     }
[415] 
[416]     return conf;
[417] }
[418] 
[419] 
[420] static char *
[421] ngx_http_access_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[422] {
[423]     ngx_http_access_loc_conf_t  *prev = parent;
[424]     ngx_http_access_loc_conf_t  *conf = child;
[425] 
[426]     if (conf->rules == NULL
[427] #if (NGX_HAVE_INET6)
[428]         && conf->rules6 == NULL
[429] #endif
[430] #if (NGX_HAVE_UNIX_DOMAIN)
[431]         && conf->rules_un == NULL
[432] #endif
[433]     ) {
[434]         conf->rules = prev->rules;
[435] #if (NGX_HAVE_INET6)
[436]         conf->rules6 = prev->rules6;
[437] #endif
[438] #if (NGX_HAVE_UNIX_DOMAIN)
[439]         conf->rules_un = prev->rules_un;
[440] #endif
[441]     }
[442] 
[443]     return NGX_CONF_OK;
[444] }
[445] 
[446] 
[447] static ngx_int_t
[448] ngx_http_access_init(ngx_conf_t *cf)
[449] {
[450]     ngx_http_handler_pt        *h;
[451]     ngx_http_core_main_conf_t  *cmcf;
[452] 
[453]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[454] 
[455]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
[456]     if (h == NULL) {
[457]         return NGX_ERROR;
[458]     }
[459] 
[460]     *h = ngx_http_access_handler;
[461] 
[462]     return NGX_OK;
[463] }
