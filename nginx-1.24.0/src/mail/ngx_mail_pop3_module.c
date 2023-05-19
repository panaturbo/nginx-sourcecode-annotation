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
[12] #include <ngx_mail_pop3_module.h>
[13] 
[14] 
[15] static void *ngx_mail_pop3_create_srv_conf(ngx_conf_t *cf);
[16] static char *ngx_mail_pop3_merge_srv_conf(ngx_conf_t *cf, void *parent,
[17]     void *child);
[18] 
[19] 
[20] static ngx_str_t  ngx_mail_pop3_default_capabilities[] = {
[21]     ngx_string("TOP"),
[22]     ngx_string("USER"),
[23]     ngx_string("UIDL"),
[24]     ngx_null_string
[25] };
[26] 
[27] 
[28] static ngx_conf_bitmask_t  ngx_mail_pop3_auth_methods[] = {
[29]     { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
[30]     { ngx_string("apop"), NGX_MAIL_AUTH_APOP_ENABLED },
[31]     { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
[32]     { ngx_string("external"), NGX_MAIL_AUTH_EXTERNAL_ENABLED },
[33]     { ngx_null_string, 0 }
[34] };
[35] 
[36] 
[37] static ngx_str_t  ngx_mail_pop3_auth_methods_names[] = {
[38]     ngx_string("PLAIN"),
[39]     ngx_string("LOGIN"),
[40]     ngx_null_string,  /* APOP */
[41]     ngx_string("CRAM-MD5"),
[42]     ngx_string("EXTERNAL"),
[43]     ngx_null_string   /* NONE */
[44] };
[45] 
[46] 
[47] static ngx_mail_protocol_t  ngx_mail_pop3_protocol = {
[48]     ngx_string("pop3"),
[49]     ngx_string("\x04pop3"),
[50]     { 110, 995, 0, 0 },
[51]     NGX_MAIL_POP3_PROTOCOL,
[52] 
[53]     ngx_mail_pop3_init_session,
[54]     ngx_mail_pop3_init_protocol,
[55]     ngx_mail_pop3_parse_command,
[56]     ngx_mail_pop3_auth_state,
[57] 
[58]     ngx_string("-ERR internal server error" CRLF),
[59]     ngx_string("-ERR SSL certificate error" CRLF),
[60]     ngx_string("-ERR No required SSL certificate" CRLF)
[61] };
[62] 
[63] 
[64] static ngx_command_t  ngx_mail_pop3_commands[] = {
[65] 
[66]     { ngx_string("pop3_capabilities"),
[67]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[68]       ngx_mail_capabilities,
[69]       NGX_MAIL_SRV_CONF_OFFSET,
[70]       offsetof(ngx_mail_pop3_srv_conf_t, capabilities),
[71]       NULL },
[72] 
[73]     { ngx_string("pop3_auth"),
[74]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[75]       ngx_conf_set_bitmask_slot,
[76]       NGX_MAIL_SRV_CONF_OFFSET,
[77]       offsetof(ngx_mail_pop3_srv_conf_t, auth_methods),
[78]       &ngx_mail_pop3_auth_methods },
[79] 
[80]       ngx_null_command
[81] };
[82] 
[83] 
[84] static ngx_mail_module_t  ngx_mail_pop3_module_ctx = {
[85]     &ngx_mail_pop3_protocol,               /* protocol */
[86] 
[87]     NULL,                                  /* create main configuration */
[88]     NULL,                                  /* init main configuration */
[89] 
[90]     ngx_mail_pop3_create_srv_conf,         /* create server configuration */
[91]     ngx_mail_pop3_merge_srv_conf           /* merge server configuration */
[92] };
[93] 
[94] 
[95] ngx_module_t  ngx_mail_pop3_module = {
[96]     NGX_MODULE_V1,
[97]     &ngx_mail_pop3_module_ctx,             /* module context */
[98]     ngx_mail_pop3_commands,                /* module directives */
[99]     NGX_MAIL_MODULE,                       /* module type */
[100]     NULL,                                  /* init master */
[101]     NULL,                                  /* init module */
[102]     NULL,                                  /* init process */
[103]     NULL,                                  /* init thread */
[104]     NULL,                                  /* exit thread */
[105]     NULL,                                  /* exit process */
[106]     NULL,                                  /* exit master */
[107]     NGX_MODULE_V1_PADDING
[108] };
[109] 
[110] 
[111] static void *
[112] ngx_mail_pop3_create_srv_conf(ngx_conf_t *cf)
[113] {
[114]     ngx_mail_pop3_srv_conf_t  *pscf;
[115] 
[116]     pscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_pop3_srv_conf_t));
[117]     if (pscf == NULL) {
[118]         return NULL;
[119]     }
[120] 
[121]     if (ngx_array_init(&pscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
[122]         != NGX_OK)
[123]     {
[124]         return NULL;
[125]     }
[126] 
[127]     return pscf;
[128] }
[129] 
[130] 
[131] static char *
[132] ngx_mail_pop3_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[133] {
[134]     ngx_mail_pop3_srv_conf_t *prev = parent;
[135]     ngx_mail_pop3_srv_conf_t *conf = child;
[136] 
[137]     u_char      *p;
[138]     size_t       size, stls_only_size;
[139]     ngx_str_t   *c, *d;
[140]     ngx_uint_t   i, m;
[141] 
[142]     ngx_conf_merge_bitmask_value(conf->auth_methods,
[143]                                  prev->auth_methods,
[144]                                  (NGX_CONF_BITMASK_SET
[145]                                   |NGX_MAIL_AUTH_PLAIN_ENABLED));
[146] 
[147]     if (conf->auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED) {
[148]         conf->auth_methods |= NGX_MAIL_AUTH_LOGIN_ENABLED;
[149]     }
[150] 
[151]     if (conf->capabilities.nelts == 0) {
[152]         conf->capabilities = prev->capabilities;
[153]     }
[154] 
[155]     if (conf->capabilities.nelts == 0) {
[156] 
[157]         for (d = ngx_mail_pop3_default_capabilities; d->len; d++) {
[158]             c = ngx_array_push(&conf->capabilities);
[159]             if (c == NULL) {
[160]                 return NGX_CONF_ERROR;
[161]             }
[162] 
[163]             *c = *d;
[164]         }
[165]     }
[166] 
[167]     size = sizeof("+OK Capability list follows" CRLF) - 1
[168]            + sizeof("." CRLF) - 1;
[169] 
[170]     stls_only_size = size + sizeof("STLS" CRLF) - 1;
[171] 
[172]     c = conf->capabilities.elts;
[173]     for (i = 0; i < conf->capabilities.nelts; i++) {
[174]         size += c[i].len + sizeof(CRLF) - 1;
[175] 
[176]         if (ngx_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
[177]             continue;
[178]         }
[179] 
[180]         stls_only_size += c[i].len + sizeof(CRLF) - 1;
[181]     }
[182] 
[183]     size += sizeof("SASL") - 1 + sizeof(CRLF) - 1;
[184] 
[185]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[186]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[187]          m <<= 1, i++)
[188]     {
[189]         if (ngx_mail_pop3_auth_methods_names[i].len == 0) {
[190]             continue;
[191]         }
[192] 
[193]         if (m & conf->auth_methods) {
[194]             size += 1 + ngx_mail_pop3_auth_methods_names[i].len;
[195]         }
[196]     }
[197] 
[198]     p = ngx_pnalloc(cf->pool, size);
[199]     if (p == NULL) {
[200]         return NGX_CONF_ERROR;
[201]     }
[202] 
[203]     conf->capability.len = size;
[204]     conf->capability.data = p;
[205] 
[206]     p = ngx_cpymem(p, "+OK Capability list follows" CRLF,
[207]                    sizeof("+OK Capability list follows" CRLF) - 1);
[208] 
[209]     for (i = 0; i < conf->capabilities.nelts; i++) {
[210]         p = ngx_cpymem(p, c[i].data, c[i].len);
[211]         *p++ = CR; *p++ = LF;
[212]     }
[213] 
[214]     p = ngx_cpymem(p, "SASL", sizeof("SASL") - 1);
[215] 
[216]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[217]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[218]          m <<= 1, i++)
[219]     {
[220]         if (ngx_mail_pop3_auth_methods_names[i].len == 0) {
[221]             continue;
[222]         }
[223] 
[224]         if (m & conf->auth_methods) {
[225]             *p++ = ' ';
[226]             p = ngx_cpymem(p, ngx_mail_pop3_auth_methods_names[i].data,
[227]                            ngx_mail_pop3_auth_methods_names[i].len);
[228]         }
[229]     }
[230] 
[231]     *p++ = CR; *p++ = LF;
[232] 
[233]     *p++ = '.'; *p++ = CR; *p = LF;
[234] 
[235] 
[236]     size += sizeof("STLS" CRLF) - 1;
[237] 
[238]     p = ngx_pnalloc(cf->pool, size);
[239]     if (p == NULL) {
[240]         return NGX_CONF_ERROR;
[241]     }
[242] 
[243]     conf->starttls_capability.len = size;
[244]     conf->starttls_capability.data = p;
[245] 
[246]     p = ngx_cpymem(p, conf->capability.data,
[247]                    conf->capability.len - (sizeof("." CRLF) - 1));
[248] 
[249]     p = ngx_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
[250]     *p++ = '.'; *p++ = CR; *p = LF;
[251] 
[252] 
[253]     size = sizeof("+OK methods supported:" CRLF) - 1
[254]            + sizeof("." CRLF) - 1;
[255] 
[256]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[257]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[258]          m <<= 1, i++)
[259]     {
[260]         if (ngx_mail_pop3_auth_methods_names[i].len == 0) {
[261]             continue;
[262]         }
[263] 
[264]         if (m & conf->auth_methods) {
[265]             size += ngx_mail_pop3_auth_methods_names[i].len
[266]                     + sizeof(CRLF) - 1;
[267]         }
[268]     }
[269] 
[270]     p = ngx_pnalloc(cf->pool, size);
[271]     if (p == NULL) {
[272]         return NGX_CONF_ERROR;
[273]     }
[274] 
[275]     conf->auth_capability.data = p;
[276]     conf->auth_capability.len = size;
[277] 
[278]     p = ngx_cpymem(p, "+OK methods supported:" CRLF,
[279]                    sizeof("+OK methods supported:" CRLF) - 1);
[280] 
[281]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[282]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[283]          m <<= 1, i++)
[284]     {
[285]         if (ngx_mail_pop3_auth_methods_names[i].len == 0) {
[286]             continue;
[287]         }
[288] 
[289]         if (m & conf->auth_methods) {
[290]             p = ngx_cpymem(p, ngx_mail_pop3_auth_methods_names[i].data,
[291]                            ngx_mail_pop3_auth_methods_names[i].len);
[292]             *p++ = CR; *p++ = LF;
[293]         }
[294]     }
[295] 
[296]     *p++ = '.'; *p++ = CR; *p = LF;
[297] 
[298] 
[299]     p = ngx_pnalloc(cf->pool, stls_only_size);
[300]     if (p == NULL) {
[301]         return NGX_CONF_ERROR;
[302]     }
[303] 
[304]     conf->starttls_only_capability.len = stls_only_size;
[305]     conf->starttls_only_capability.data = p;
[306] 
[307]     p = ngx_cpymem(p, "+OK Capability list follows" CRLF,
[308]                    sizeof("+OK Capability list follows" CRLF) - 1);
[309] 
[310]     for (i = 0; i < conf->capabilities.nelts; i++) {
[311]         if (ngx_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
[312]             continue;
[313]         }
[314] 
[315]         p = ngx_cpymem(p, c[i].data, c[i].len);
[316]         *p++ = CR; *p++ = LF;
[317]     }
[318] 
[319]     p = ngx_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
[320]     *p++ = '.'; *p++ = CR; *p = LF;
[321] 
[322]     return NGX_CONF_OK;
[323] }
