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
[12] #include <ngx_mail_smtp_module.h>
[13] 
[14] 
[15] static void *ngx_mail_smtp_create_srv_conf(ngx_conf_t *cf);
[16] static char *ngx_mail_smtp_merge_srv_conf(ngx_conf_t *cf, void *parent,
[17]     void *child);
[18] 
[19] 
[20] static ngx_conf_bitmask_t  ngx_mail_smtp_auth_methods[] = {
[21]     { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
[22]     { ngx_string("login"), NGX_MAIL_AUTH_LOGIN_ENABLED },
[23]     { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
[24]     { ngx_string("external"), NGX_MAIL_AUTH_EXTERNAL_ENABLED },
[25]     { ngx_string("none"), NGX_MAIL_AUTH_NONE_ENABLED },
[26]     { ngx_null_string, 0 }
[27] };
[28] 
[29] 
[30] static ngx_str_t  ngx_mail_smtp_auth_methods_names[] = {
[31]     ngx_string("PLAIN"),
[32]     ngx_string("LOGIN"),
[33]     ngx_null_string,  /* APOP */
[34]     ngx_string("CRAM-MD5"),
[35]     ngx_string("EXTERNAL"),
[36]     ngx_null_string   /* NONE */
[37] };
[38] 
[39] 
[40] static ngx_mail_protocol_t  ngx_mail_smtp_protocol = {
[41]     ngx_string("smtp"),
[42]     ngx_string("\x04smtp"),
[43]     { 25, 465, 587, 0 },
[44]     NGX_MAIL_SMTP_PROTOCOL,
[45] 
[46]     ngx_mail_smtp_init_session,
[47]     ngx_mail_smtp_init_protocol,
[48]     ngx_mail_smtp_parse_command,
[49]     ngx_mail_smtp_auth_state,
[50] 
[51]     ngx_string("451 4.3.2 Internal server error" CRLF),
[52]     ngx_string("421 4.7.1 SSL certificate error" CRLF),
[53]     ngx_string("421 4.7.1 No required SSL certificate" CRLF)
[54] };
[55] 
[56] 
[57] static ngx_command_t  ngx_mail_smtp_commands[] = {
[58] 
[59]     { ngx_string("smtp_client_buffer"),
[60]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[61]       ngx_conf_set_size_slot,
[62]       NGX_MAIL_SRV_CONF_OFFSET,
[63]       offsetof(ngx_mail_smtp_srv_conf_t, client_buffer_size),
[64]       NULL },
[65] 
[66]     { ngx_string("smtp_greeting_delay"),
[67]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[68]       ngx_conf_set_msec_slot,
[69]       NGX_MAIL_SRV_CONF_OFFSET,
[70]       offsetof(ngx_mail_smtp_srv_conf_t, greeting_delay),
[71]       NULL },
[72] 
[73]     { ngx_string("smtp_capabilities"),
[74]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[75]       ngx_mail_capabilities,
[76]       NGX_MAIL_SRV_CONF_OFFSET,
[77]       offsetof(ngx_mail_smtp_srv_conf_t, capabilities),
[78]       NULL },
[79] 
[80]     { ngx_string("smtp_auth"),
[81]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[82]       ngx_conf_set_bitmask_slot,
[83]       NGX_MAIL_SRV_CONF_OFFSET,
[84]       offsetof(ngx_mail_smtp_srv_conf_t, auth_methods),
[85]       &ngx_mail_smtp_auth_methods },
[86] 
[87]       ngx_null_command
[88] };
[89] 
[90] 
[91] static ngx_mail_module_t  ngx_mail_smtp_module_ctx = {
[92]     &ngx_mail_smtp_protocol,               /* protocol */
[93] 
[94]     NULL,                                  /* create main configuration */
[95]     NULL,                                  /* init main configuration */
[96] 
[97]     ngx_mail_smtp_create_srv_conf,         /* create server configuration */
[98]     ngx_mail_smtp_merge_srv_conf           /* merge server configuration */
[99] };
[100] 
[101] 
[102] ngx_module_t  ngx_mail_smtp_module = {
[103]     NGX_MODULE_V1,
[104]     &ngx_mail_smtp_module_ctx,             /* module context */
[105]     ngx_mail_smtp_commands,                /* module directives */
[106]     NGX_MAIL_MODULE,                       /* module type */
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
[118] static void *
[119] ngx_mail_smtp_create_srv_conf(ngx_conf_t *cf)
[120] {
[121]     ngx_mail_smtp_srv_conf_t  *sscf;
[122] 
[123]     sscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_smtp_srv_conf_t));
[124]     if (sscf == NULL) {
[125]         return NULL;
[126]     }
[127] 
[128]     sscf->client_buffer_size = NGX_CONF_UNSET_SIZE;
[129]     sscf->greeting_delay = NGX_CONF_UNSET_MSEC;
[130] 
[131]     if (ngx_array_init(&sscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
[132]         != NGX_OK)
[133]     {
[134]         return NULL;
[135]     }
[136] 
[137]     return sscf;
[138] }
[139] 
[140] 
[141] static char *
[142] ngx_mail_smtp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[143] {
[144]     ngx_mail_smtp_srv_conf_t *prev = parent;
[145]     ngx_mail_smtp_srv_conf_t *conf = child;
[146] 
[147]     u_char                    *p, *auth, *last;
[148]     size_t                     size;
[149]     ngx_str_t                 *c;
[150]     ngx_uint_t                 i, m, auth_enabled;
[151]     ngx_mail_core_srv_conf_t  *cscf;
[152] 
[153]     ngx_conf_merge_size_value(conf->client_buffer_size,
[154]                               prev->client_buffer_size,
[155]                               (size_t) ngx_pagesize);
[156] 
[157]     ngx_conf_merge_msec_value(conf->greeting_delay,
[158]                               prev->greeting_delay, 0);
[159] 
[160]     ngx_conf_merge_bitmask_value(conf->auth_methods,
[161]                               prev->auth_methods,
[162]                               (NGX_CONF_BITMASK_SET
[163]                                |NGX_MAIL_AUTH_PLAIN_ENABLED
[164]                                |NGX_MAIL_AUTH_LOGIN_ENABLED));
[165] 
[166] 
[167]     cscf = ngx_mail_conf_get_module_srv_conf(cf, ngx_mail_core_module);
[168] 
[169]     size = sizeof("220  ESMTP ready" CRLF) - 1 + cscf->server_name.len;
[170] 
[171]     p = ngx_pnalloc(cf->pool, size);
[172]     if (p == NULL) {
[173]         return NGX_CONF_ERROR;
[174]     }
[175] 
[176]     conf->greeting.len = size;
[177]     conf->greeting.data = p;
[178] 
[179]     *p++ = '2'; *p++ = '2'; *p++ = '0'; *p++ = ' ';
[180]     p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
[181]     ngx_memcpy(p, " ESMTP ready" CRLF, sizeof(" ESMTP ready" CRLF) - 1);
[182] 
[183] 
[184]     size = sizeof("250 " CRLF) - 1 + cscf->server_name.len;
[185] 
[186]     p = ngx_pnalloc(cf->pool, size);
[187]     if (p == NULL) {
[188]         return NGX_CONF_ERROR;
[189]     }
[190] 
[191]     conf->server_name.len = size;
[192]     conf->server_name.data = p;
[193] 
[194]     *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
[195]     p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
[196]     *p++ = CR; *p = LF;
[197] 
[198] 
[199]     if (conf->capabilities.nelts == 0) {
[200]         conf->capabilities = prev->capabilities;
[201]     }
[202] 
[203]     size = sizeof("250-") - 1 + cscf->server_name.len + sizeof(CRLF) - 1;
[204] 
[205]     c = conf->capabilities.elts;
[206]     for (i = 0; i < conf->capabilities.nelts; i++) {
[207]         size += sizeof("250 ") - 1 + c[i].len + sizeof(CRLF) - 1;
[208]     }
[209] 
[210]     auth_enabled = 0;
[211] 
[212]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[213]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[214]          m <<= 1, i++)
[215]     {
[216]         if (m & conf->auth_methods) {
[217]             size += 1 + ngx_mail_smtp_auth_methods_names[i].len;
[218]             auth_enabled = 1;
[219]         }
[220]     }
[221] 
[222]     if (auth_enabled) {
[223]         size += sizeof("250 AUTH") - 1 + sizeof(CRLF) - 1;
[224]     }
[225] 
[226]     p = ngx_pnalloc(cf->pool, size);
[227]     if (p == NULL) {
[228]         return NGX_CONF_ERROR;
[229]     }
[230] 
[231]     conf->capability.len = size;
[232]     conf->capability.data = p;
[233] 
[234]     last = p;
[235] 
[236]     *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
[237]     p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
[238]     *p++ = CR; *p++ = LF;
[239] 
[240]     for (i = 0; i < conf->capabilities.nelts; i++) {
[241]         last = p;
[242]         *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
[243]         p = ngx_cpymem(p, c[i].data, c[i].len);
[244]         *p++ = CR; *p++ = LF;
[245]     }
[246] 
[247]     auth = p;
[248] 
[249]     if (auth_enabled) {
[250]         last = p;
[251] 
[252]         *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
[253]         *p++ = 'A'; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';
[254] 
[255]         for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[256]              m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[257]              m <<= 1, i++)
[258]         {
[259]             if (m & conf->auth_methods) {
[260]                 *p++ = ' ';
[261]                 p = ngx_cpymem(p, ngx_mail_smtp_auth_methods_names[i].data,
[262]                                ngx_mail_smtp_auth_methods_names[i].len);
[263]             }
[264]         }
[265] 
[266]         *p++ = CR; *p = LF;
[267] 
[268]     } else {
[269]         last[3] = ' ';
[270]     }
[271] 
[272]     size += sizeof("250 STARTTLS" CRLF) - 1;
[273] 
[274]     p = ngx_pnalloc(cf->pool, size);
[275]     if (p == NULL) {
[276]         return NGX_CONF_ERROR;
[277]     }
[278] 
[279]     conf->starttls_capability.len = size;
[280]     conf->starttls_capability.data = p;
[281] 
[282]     p = ngx_cpymem(p, conf->capability.data, conf->capability.len);
[283] 
[284]     ngx_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);
[285] 
[286]     p = conf->starttls_capability.data
[287]         + (last - conf->capability.data) + 3;
[288]     *p = '-';
[289] 
[290]     size = (auth - conf->capability.data)
[291]             + sizeof("250 STARTTLS" CRLF) - 1;
[292] 
[293]     p = ngx_pnalloc(cf->pool, size);
[294]     if (p == NULL) {
[295]         return NGX_CONF_ERROR;
[296]     }
[297] 
[298]     conf->starttls_only_capability.len = size;
[299]     conf->starttls_only_capability.data = p;
[300] 
[301]     p = ngx_cpymem(p, conf->capability.data, auth - conf->capability.data);
[302] 
[303]     ngx_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);
[304] 
[305]     if (last < auth) {
[306]         p = conf->starttls_only_capability.data
[307]             + (last - conf->capability.data) + 3;
[308]         *p = '-';
[309]     }
[310] 
[311]     return NGX_CONF_OK;
[312] }
