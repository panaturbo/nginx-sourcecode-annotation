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
[12] #include <ngx_mail_imap_module.h>
[13] 
[14] 
[15] static void *ngx_mail_imap_create_srv_conf(ngx_conf_t *cf);
[16] static char *ngx_mail_imap_merge_srv_conf(ngx_conf_t *cf, void *parent,
[17]     void *child);
[18] 
[19] 
[20] static ngx_str_t  ngx_mail_imap_default_capabilities[] = {
[21]     ngx_string("IMAP4"),
[22]     ngx_string("IMAP4rev1"),
[23]     ngx_string("UIDPLUS"),
[24]     ngx_null_string
[25] };
[26] 
[27] 
[28] static ngx_conf_bitmask_t  ngx_mail_imap_auth_methods[] = {
[29]     { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
[30]     { ngx_string("login"), NGX_MAIL_AUTH_LOGIN_ENABLED },
[31]     { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
[32]     { ngx_string("external"), NGX_MAIL_AUTH_EXTERNAL_ENABLED },
[33]     { ngx_null_string, 0 }
[34] };
[35] 
[36] 
[37] static ngx_str_t  ngx_mail_imap_auth_methods_names[] = {
[38]     ngx_string("AUTH=PLAIN"),
[39]     ngx_string("AUTH=LOGIN"),
[40]     ngx_null_string,  /* APOP */
[41]     ngx_string("AUTH=CRAM-MD5"),
[42]     ngx_string("AUTH=EXTERNAL"),
[43]     ngx_null_string   /* NONE */
[44] };
[45] 
[46] 
[47] static ngx_mail_protocol_t  ngx_mail_imap_protocol = {
[48]     ngx_string("imap"),
[49]     ngx_string("\x04imap"),
[50]     { 143, 993, 0, 0 },
[51]     NGX_MAIL_IMAP_PROTOCOL,
[52] 
[53]     ngx_mail_imap_init_session,
[54]     ngx_mail_imap_init_protocol,
[55]     ngx_mail_imap_parse_command,
[56]     ngx_mail_imap_auth_state,
[57] 
[58]     ngx_string("* BAD internal server error" CRLF),
[59]     ngx_string("* BYE SSL certificate error" CRLF),
[60]     ngx_string("* BYE No required SSL certificate" CRLF)
[61] };
[62] 
[63] 
[64] static ngx_command_t  ngx_mail_imap_commands[] = {
[65] 
[66]     { ngx_string("imap_client_buffer"),
[67]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[68]       ngx_conf_set_size_slot,
[69]       NGX_MAIL_SRV_CONF_OFFSET,
[70]       offsetof(ngx_mail_imap_srv_conf_t, client_buffer_size),
[71]       NULL },
[72] 
[73]     { ngx_string("imap_capabilities"),
[74]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[75]       ngx_mail_capabilities,
[76]       NGX_MAIL_SRV_CONF_OFFSET,
[77]       offsetof(ngx_mail_imap_srv_conf_t, capabilities),
[78]       NULL },
[79] 
[80]     { ngx_string("imap_auth"),
[81]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
[82]       ngx_conf_set_bitmask_slot,
[83]       NGX_MAIL_SRV_CONF_OFFSET,
[84]       offsetof(ngx_mail_imap_srv_conf_t, auth_methods),
[85]       &ngx_mail_imap_auth_methods },
[86] 
[87]       ngx_null_command
[88] };
[89] 
[90] 
[91] static ngx_mail_module_t  ngx_mail_imap_module_ctx = {
[92]     &ngx_mail_imap_protocol,               /* protocol */
[93] 
[94]     NULL,                                  /* create main configuration */
[95]     NULL,                                  /* init main configuration */
[96] 
[97]     ngx_mail_imap_create_srv_conf,         /* create server configuration */
[98]     ngx_mail_imap_merge_srv_conf           /* merge server configuration */
[99] };
[100] 
[101] 
[102] ngx_module_t  ngx_mail_imap_module = {
[103]     NGX_MODULE_V1,
[104]     &ngx_mail_imap_module_ctx,             /* module context */
[105]     ngx_mail_imap_commands,                /* module directives */
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
[119] ngx_mail_imap_create_srv_conf(ngx_conf_t *cf)
[120] {
[121]     ngx_mail_imap_srv_conf_t  *iscf;
[122] 
[123]     iscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_imap_srv_conf_t));
[124]     if (iscf == NULL) {
[125]         return NULL;
[126]     }
[127] 
[128]     iscf->client_buffer_size = NGX_CONF_UNSET_SIZE;
[129] 
[130]     if (ngx_array_init(&iscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
[131]         != NGX_OK)
[132]     {
[133]         return NULL;
[134]     }
[135] 
[136]     return iscf;
[137] }
[138] 
[139] 
[140] static char *
[141] ngx_mail_imap_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[142] {
[143]     ngx_mail_imap_srv_conf_t *prev = parent;
[144]     ngx_mail_imap_srv_conf_t *conf = child;
[145] 
[146]     u_char      *p, *auth;
[147]     size_t       size;
[148]     ngx_str_t   *c, *d;
[149]     ngx_uint_t   i, m;
[150] 
[151]     ngx_conf_merge_size_value(conf->client_buffer_size,
[152]                               prev->client_buffer_size,
[153]                               (size_t) ngx_pagesize);
[154] 
[155]     ngx_conf_merge_bitmask_value(conf->auth_methods,
[156]                               prev->auth_methods,
[157]                               (NGX_CONF_BITMASK_SET
[158]                                |NGX_MAIL_AUTH_PLAIN_ENABLED));
[159] 
[160] 
[161]     if (conf->capabilities.nelts == 0) {
[162]         conf->capabilities = prev->capabilities;
[163]     }
[164] 
[165]     if (conf->capabilities.nelts == 0) {
[166] 
[167]         for (d = ngx_mail_imap_default_capabilities; d->len; d++) {
[168]             c = ngx_array_push(&conf->capabilities);
[169]             if (c == NULL) {
[170]                 return NGX_CONF_ERROR;
[171]             }
[172] 
[173]             *c = *d;
[174]         }
[175]     }
[176] 
[177]     size = sizeof("* CAPABILITY" CRLF) - 1;
[178] 
[179]     c = conf->capabilities.elts;
[180]     for (i = 0; i < conf->capabilities.nelts; i++) {
[181]         size += 1 + c[i].len;
[182]     }
[183] 
[184]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[185]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[186]          m <<= 1, i++)
[187]     {
[188]         if (m & conf->auth_methods) {
[189]             size += 1 + ngx_mail_imap_auth_methods_names[i].len;
[190]         }
[191]     }
[192] 
[193]     p = ngx_pnalloc(cf->pool, size);
[194]     if (p == NULL) {
[195]         return NGX_CONF_ERROR;
[196]     }
[197] 
[198]     conf->capability.len = size;
[199]     conf->capability.data = p;
[200] 
[201]     p = ngx_cpymem(p, "* CAPABILITY", sizeof("* CAPABILITY") - 1);
[202] 
[203]     for (i = 0; i < conf->capabilities.nelts; i++) {
[204]         *p++ = ' ';
[205]         p = ngx_cpymem(p, c[i].data, c[i].len);
[206]     }
[207] 
[208]     auth = p;
[209] 
[210]     for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
[211]          m <= NGX_MAIL_AUTH_EXTERNAL_ENABLED;
[212]          m <<= 1, i++)
[213]     {
[214]         if (m & conf->auth_methods) {
[215]             *p++ = ' ';
[216]             p = ngx_cpymem(p, ngx_mail_imap_auth_methods_names[i].data,
[217]                            ngx_mail_imap_auth_methods_names[i].len);
[218]         }
[219]     }
[220] 
[221]     *p++ = CR; *p = LF;
[222] 
[223] 
[224]     size += sizeof(" STARTTLS") - 1;
[225] 
[226]     p = ngx_pnalloc(cf->pool, size);
[227]     if (p == NULL) {
[228]         return NGX_CONF_ERROR;
[229]     }
[230] 
[231]     conf->starttls_capability.len = size;
[232]     conf->starttls_capability.data = p;
[233] 
[234]     p = ngx_cpymem(p, conf->capability.data,
[235]                    conf->capability.len - (sizeof(CRLF) - 1));
[236]     p = ngx_cpymem(p, " STARTTLS", sizeof(" STARTTLS") - 1);
[237]     *p++ = CR; *p = LF;
[238] 
[239] 
[240]     size = (auth - conf->capability.data) + sizeof(CRLF) - 1
[241]             + sizeof(" STARTTLS LOGINDISABLED") - 1;
[242] 
[243]     p = ngx_pnalloc(cf->pool, size);
[244]     if (p == NULL) {
[245]         return NGX_CONF_ERROR;
[246]     }
[247] 
[248]     conf->starttls_only_capability.len = size;
[249]     conf->starttls_only_capability.data = p;
[250] 
[251]     p = ngx_cpymem(p, conf->capability.data,
[252]                    auth - conf->capability.data);
[253]     p = ngx_cpymem(p, " STARTTLS LOGINDISABLED",
[254]                    sizeof(" STARTTLS LOGINDISABLED") - 1);
[255]     *p++ = CR; *p = LF;
[256] 
[257]     return NGX_CONF_OK;
[258] }
