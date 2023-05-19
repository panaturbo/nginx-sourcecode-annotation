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
[13] typedef struct {
[14]     in_addr_t         mask;
[15]     in_addr_t         addr;
[16]     ngx_uint_t        deny;      /* unsigned  deny:1; */
[17] } ngx_stream_access_rule_t;
[18] 
[19] #if (NGX_HAVE_INET6)
[20] 
[21] typedef struct {
[22]     struct in6_addr   addr;
[23]     struct in6_addr   mask;
[24]     ngx_uint_t        deny;      /* unsigned  deny:1; */
[25] } ngx_stream_access_rule6_t;
[26] 
[27] #endif
[28] 
[29] #if (NGX_HAVE_UNIX_DOMAIN)
[30] 
[31] typedef struct {
[32]     ngx_uint_t        deny;      /* unsigned  deny:1; */
[33] } ngx_stream_access_rule_un_t;
[34] 
[35] #endif
[36] 
[37] typedef struct {
[38]     ngx_array_t      *rules;     /* array of ngx_stream_access_rule_t */
[39] #if (NGX_HAVE_INET6)
[40]     ngx_array_t      *rules6;    /* array of ngx_stream_access_rule6_t */
[41] #endif
[42] #if (NGX_HAVE_UNIX_DOMAIN)
[43]     ngx_array_t      *rules_un;  /* array of ngx_stream_access_rule_un_t */
[44] #endif
[45] } ngx_stream_access_srv_conf_t;
[46] 
[47] 
[48] static ngx_int_t ngx_stream_access_handler(ngx_stream_session_t *s);
[49] static ngx_int_t ngx_stream_access_inet(ngx_stream_session_t *s,
[50]     ngx_stream_access_srv_conf_t *ascf, in_addr_t addr);
[51] #if (NGX_HAVE_INET6)
[52] static ngx_int_t ngx_stream_access_inet6(ngx_stream_session_t *s,
[53]     ngx_stream_access_srv_conf_t *ascf, u_char *p);
[54] #endif
[55] #if (NGX_HAVE_UNIX_DOMAIN)
[56] static ngx_int_t ngx_stream_access_unix(ngx_stream_session_t *s,
[57]     ngx_stream_access_srv_conf_t *ascf);
[58] #endif
[59] static ngx_int_t ngx_stream_access_found(ngx_stream_session_t *s,
[60]     ngx_uint_t deny);
[61] static char *ngx_stream_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
[62]     void *conf);
[63] static void *ngx_stream_access_create_srv_conf(ngx_conf_t *cf);
[64] static char *ngx_stream_access_merge_srv_conf(ngx_conf_t *cf,
[65]     void *parent, void *child);
[66] static ngx_int_t ngx_stream_access_init(ngx_conf_t *cf);
[67] 
[68] 
[69] static ngx_command_t  ngx_stream_access_commands[] = {
[70] 
[71]     { ngx_string("allow"),
[72]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[73]       ngx_stream_access_rule,
[74]       NGX_STREAM_SRV_CONF_OFFSET,
[75]       0,
[76]       NULL },
[77] 
[78]     { ngx_string("deny"),
[79]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[80]       ngx_stream_access_rule,
[81]       NGX_STREAM_SRV_CONF_OFFSET,
[82]       0,
[83]       NULL },
[84] 
[85]       ngx_null_command
[86] };
[87] 
[88] 
[89] 
[90] static ngx_stream_module_t  ngx_stream_access_module_ctx = {
[91]     NULL,                                  /* preconfiguration */
[92]     ngx_stream_access_init,                /* postconfiguration */
[93] 
[94]     NULL,                                  /* create main configuration */
[95]     NULL,                                  /* init main configuration */
[96] 
[97]     ngx_stream_access_create_srv_conf,     /* create server configuration */
[98]     ngx_stream_access_merge_srv_conf       /* merge server configuration */
[99] };
[100] 
[101] 
[102] ngx_module_t  ngx_stream_access_module = {
[103]     NGX_MODULE_V1,
[104]     &ngx_stream_access_module_ctx,         /* module context */
[105]     ngx_stream_access_commands,            /* module directives */
[106]     NGX_STREAM_MODULE,                     /* module type */
[107]     NULL,                                  /* init master */
[108]     NULL,                                  /* init module */
[109]     NULL,                                  /* init process */
[110]     NULL,                                  /* init thread */
[111]     NULL,                                  /* exit thread */
[112]     NULL,                                  /* exit process */
[113]     NULL,                                  /* exit master */
[114]     NGX_MODULE_V1_PADDING
[115] };
[116] 
[117] 
[118] static ngx_int_t
[119] ngx_stream_access_handler(ngx_stream_session_t *s)
[120] {
[121]     struct sockaddr_in            *sin;
[122]     ngx_stream_access_srv_conf_t  *ascf;
[123] #if (NGX_HAVE_INET6)
[124]     u_char                        *p;
[125]     in_addr_t                      addr;
[126]     struct sockaddr_in6           *sin6;
[127] #endif
[128] 
[129]     ascf = ngx_stream_get_module_srv_conf(s, ngx_stream_access_module);
[130] 
[131]     switch (s->connection->sockaddr->sa_family) {
[132] 
[133]     case AF_INET:
[134]         if (ascf->rules) {
[135]             sin = (struct sockaddr_in *) s->connection->sockaddr;
[136]             return ngx_stream_access_inet(s, ascf, sin->sin_addr.s_addr);
[137]         }
[138]         break;
[139] 
[140] #if (NGX_HAVE_INET6)
[141] 
[142]     case AF_INET6:
[143]         sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
[144]         p = sin6->sin6_addr.s6_addr;
[145] 
[146]         if (ascf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
[147]             addr = p[12] << 24;
[148]             addr += p[13] << 16;
[149]             addr += p[14] << 8;
[150]             addr += p[15];
[151]             return ngx_stream_access_inet(s, ascf, htonl(addr));
[152]         }
[153] 
[154]         if (ascf->rules6) {
[155]             return ngx_stream_access_inet6(s, ascf, p);
[156]         }
[157] 
[158]         break;
[159] 
[160] #endif
[161] 
[162] #if (NGX_HAVE_UNIX_DOMAIN)
[163] 
[164]     case AF_UNIX:
[165]         if (ascf->rules_un) {
[166]             return ngx_stream_access_unix(s, ascf);
[167]         }
[168] 
[169]         break;
[170] 
[171] #endif
[172]     }
[173] 
[174]     return NGX_DECLINED;
[175] }
[176] 
[177] 
[178] static ngx_int_t
[179] ngx_stream_access_inet(ngx_stream_session_t *s,
[180]     ngx_stream_access_srv_conf_t *ascf, in_addr_t addr)
[181] {
[182]     ngx_uint_t                 i;
[183]     ngx_stream_access_rule_t  *rule;
[184] 
[185]     rule = ascf->rules->elts;
[186]     for (i = 0; i < ascf->rules->nelts; i++) {
[187] 
[188]         ngx_log_debug3(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[189]                        "access: %08XD %08XD %08XD",
[190]                        addr, rule[i].mask, rule[i].addr);
[191] 
[192]         if ((addr & rule[i].mask) == rule[i].addr) {
[193]             return ngx_stream_access_found(s, rule[i].deny);
[194]         }
[195]     }
[196] 
[197]     return NGX_DECLINED;
[198] }
[199] 
[200] 
[201] #if (NGX_HAVE_INET6)
[202] 
[203] static ngx_int_t
[204] ngx_stream_access_inet6(ngx_stream_session_t *s,
[205]     ngx_stream_access_srv_conf_t *ascf, u_char *p)
[206] {
[207]     ngx_uint_t                  n;
[208]     ngx_uint_t                  i;
[209]     ngx_stream_access_rule6_t  *rule6;
[210] 
[211]     rule6 = ascf->rules6->elts;
[212]     for (i = 0; i < ascf->rules6->nelts; i++) {
[213] 
[214] #if (NGX_DEBUG)
[215]         {
[216]         size_t  cl, ml, al;
[217]         u_char  ct[NGX_INET6_ADDRSTRLEN];
[218]         u_char  mt[NGX_INET6_ADDRSTRLEN];
[219]         u_char  at[NGX_INET6_ADDRSTRLEN];
[220] 
[221]         cl = ngx_inet6_ntop(p, ct, NGX_INET6_ADDRSTRLEN);
[222]         ml = ngx_inet6_ntop(rule6[i].mask.s6_addr, mt, NGX_INET6_ADDRSTRLEN);
[223]         al = ngx_inet6_ntop(rule6[i].addr.s6_addr, at, NGX_INET6_ADDRSTRLEN);
[224] 
[225]         ngx_log_debug6(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[226]                        "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
[227]         }
[228] #endif
[229] 
[230]         for (n = 0; n < 16; n++) {
[231]             if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
[232]                 goto next;
[233]             }
[234]         }
[235] 
[236]         return ngx_stream_access_found(s, rule6[i].deny);
[237] 
[238]     next:
[239]         continue;
[240]     }
[241] 
[242]     return NGX_DECLINED;
[243] }
[244] 
[245] #endif
[246] 
[247] 
[248] #if (NGX_HAVE_UNIX_DOMAIN)
[249] 
[250] static ngx_int_t
[251] ngx_stream_access_unix(ngx_stream_session_t *s,
[252]     ngx_stream_access_srv_conf_t *ascf)
[253] {
[254]     ngx_uint_t                    i;
[255]     ngx_stream_access_rule_un_t  *rule_un;
[256] 
[257]     rule_un = ascf->rules_un->elts;
[258]     for (i = 0; i < ascf->rules_un->nelts; i++) {
[259] 
[260]         /* TODO: check path */
[261]         if (1) {
[262]             return ngx_stream_access_found(s, rule_un[i].deny);
[263]         }
[264]     }
[265] 
[266]     return NGX_DECLINED;
[267] }
[268] 
[269] #endif
[270] 
[271] 
[272] static ngx_int_t
[273] ngx_stream_access_found(ngx_stream_session_t *s, ngx_uint_t deny)
[274] {
[275]     if (deny) {
[276]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[277]                       "access forbidden by rule");
[278]         return NGX_STREAM_FORBIDDEN;
[279]     }
[280] 
[281]     return NGX_OK;
[282] }
[283] 
[284] 
[285] static char *
[286] ngx_stream_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[287] {
[288]     ngx_stream_access_srv_conf_t *ascf = conf;
[289] 
[290]     ngx_int_t                     rc;
[291]     ngx_uint_t                    all;
[292]     ngx_str_t                    *value;
[293]     ngx_cidr_t                    cidr;
[294]     ngx_stream_access_rule_t     *rule;
[295] #if (NGX_HAVE_INET6)
[296]     ngx_stream_access_rule6_t    *rule6;
[297] #endif
[298] #if (NGX_HAVE_UNIX_DOMAIN)
[299]     ngx_stream_access_rule_un_t  *rule_un;
[300] #endif
[301] 
[302]     all = 0;
[303]     ngx_memzero(&cidr, sizeof(ngx_cidr_t));
[304] 
[305]     value = cf->args->elts;
[306] 
[307]     if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
[308]         all = 1;
[309] 
[310] #if (NGX_HAVE_UNIX_DOMAIN)
[311]     } else if (value[1].len == 5 && ngx_strcmp(value[1].data, "unix:") == 0) {
[312]         cidr.family = AF_UNIX;
[313] #endif
[314] 
[315]     } else {
[316]         rc = ngx_ptocidr(&value[1], &cidr);
[317] 
[318]         if (rc == NGX_ERROR) {
[319]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[320]                          "invalid parameter \"%V\"", &value[1]);
[321]             return NGX_CONF_ERROR;
[322]         }
[323] 
[324]         if (rc == NGX_DONE) {
[325]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[326]                          "low address bits of %V are meaningless", &value[1]);
[327]         }
[328]     }
[329] 
[330]     if (cidr.family == AF_INET || all) {
[331] 
[332]         if (ascf->rules == NULL) {
[333]             ascf->rules = ngx_array_create(cf->pool, 4,
[334]                                            sizeof(ngx_stream_access_rule_t));
[335]             if (ascf->rules == NULL) {
[336]                 return NGX_CONF_ERROR;
[337]             }
[338]         }
[339] 
[340]         rule = ngx_array_push(ascf->rules);
[341]         if (rule == NULL) {
[342]             return NGX_CONF_ERROR;
[343]         }
[344] 
[345]         rule->mask = cidr.u.in.mask;
[346]         rule->addr = cidr.u.in.addr;
[347]         rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
[348]     }
[349] 
[350] #if (NGX_HAVE_INET6)
[351]     if (cidr.family == AF_INET6 || all) {
[352] 
[353]         if (ascf->rules6 == NULL) {
[354]             ascf->rules6 = ngx_array_create(cf->pool, 4,
[355]                                             sizeof(ngx_stream_access_rule6_t));
[356]             if (ascf->rules6 == NULL) {
[357]                 return NGX_CONF_ERROR;
[358]             }
[359]         }
[360] 
[361]         rule6 = ngx_array_push(ascf->rules6);
[362]         if (rule6 == NULL) {
[363]             return NGX_CONF_ERROR;
[364]         }
[365] 
[366]         rule6->mask = cidr.u.in6.mask;
[367]         rule6->addr = cidr.u.in6.addr;
[368]         rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
[369]     }
[370] #endif
[371] 
[372] #if (NGX_HAVE_UNIX_DOMAIN)
[373]     if (cidr.family == AF_UNIX || all) {
[374] 
[375]         if (ascf->rules_un == NULL) {
[376]             ascf->rules_un = ngx_array_create(cf->pool, 1,
[377]                                           sizeof(ngx_stream_access_rule_un_t));
[378]             if (ascf->rules_un == NULL) {
[379]                 return NGX_CONF_ERROR;
[380]             }
[381]         }
[382] 
[383]         rule_un = ngx_array_push(ascf->rules_un);
[384]         if (rule_un == NULL) {
[385]             return NGX_CONF_ERROR;
[386]         }
[387] 
[388]         rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
[389]     }
[390] #endif
[391] 
[392]     return NGX_CONF_OK;
[393] }
[394] 
[395] 
[396] static void *
[397] ngx_stream_access_create_srv_conf(ngx_conf_t *cf)
[398] {
[399]     ngx_stream_access_srv_conf_t  *conf;
[400] 
[401]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_access_srv_conf_t));
[402]     if (conf == NULL) {
[403]         return NULL;
[404]     }
[405] 
[406]     return conf;
[407] }
[408] 
[409] 
[410] static char *
[411] ngx_stream_access_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[412] {
[413]     ngx_stream_access_srv_conf_t  *prev = parent;
[414]     ngx_stream_access_srv_conf_t  *conf = child;
[415] 
[416]     if (conf->rules == NULL
[417] #if (NGX_HAVE_INET6)
[418]         && conf->rules6 == NULL
[419] #endif
[420] #if (NGX_HAVE_UNIX_DOMAIN)
[421]         && conf->rules_un == NULL
[422] #endif
[423]     ) {
[424]         conf->rules = prev->rules;
[425] #if (NGX_HAVE_INET6)
[426]         conf->rules6 = prev->rules6;
[427] #endif
[428] #if (NGX_HAVE_UNIX_DOMAIN)
[429]         conf->rules_un = prev->rules_un;
[430] #endif
[431]     }
[432] 
[433]     return NGX_CONF_OK;
[434] }
[435] 
[436] 
[437] static ngx_int_t
[438] ngx_stream_access_init(ngx_conf_t *cf)
[439] {
[440]     ngx_stream_handler_pt        *h;
[441]     ngx_stream_core_main_conf_t  *cmcf;
[442] 
[443]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[444] 
[445]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers);
[446]     if (h == NULL) {
[447]         return NGX_ERROR;
[448]     }
[449] 
[450]     *h = ngx_stream_access_handler;
[451] 
[452]     return NGX_OK;
[453] }
