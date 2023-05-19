[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_mail.h>
[11] 
[12] 
[13] typedef struct {
[14]     ngx_array_t       *from;     /* array of ngx_cidr_t */
[15] } ngx_mail_realip_srv_conf_t;
[16] 
[17] 
[18] static ngx_int_t ngx_mail_realip_set_addr(ngx_mail_session_t *s,
[19]     ngx_addr_t *addr);
[20] static char *ngx_mail_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
[21]     void *conf);
[22] static void *ngx_mail_realip_create_srv_conf(ngx_conf_t *cf);
[23] static char *ngx_mail_realip_merge_srv_conf(ngx_conf_t *cf, void *parent,
[24]     void *child);
[25] 
[26] 
[27] static ngx_command_t  ngx_mail_realip_commands[] = {
[28] 
[29]     { ngx_string("set_real_ip_from"),
[30]       NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
[31]       ngx_mail_realip_from,
[32]       NGX_MAIL_SRV_CONF_OFFSET,
[33]       0,
[34]       NULL },
[35] 
[36]       ngx_null_command
[37] };
[38] 
[39] 
[40] static ngx_mail_module_t  ngx_mail_realip_module_ctx = {
[41]     NULL,                                  /* protocol */
[42] 
[43]     NULL,                                  /* create main configuration */
[44]     NULL,                                  /* init main configuration */
[45] 
[46]     ngx_mail_realip_create_srv_conf,       /* create server configuration */
[47]     ngx_mail_realip_merge_srv_conf         /* merge server configuration */
[48] };
[49] 
[50] 
[51] ngx_module_t  ngx_mail_realip_module = {
[52]     NGX_MODULE_V1,
[53]     &ngx_mail_realip_module_ctx,           /* module context */
[54]     ngx_mail_realip_commands,              /* module directives */
[55]     NGX_MAIL_MODULE,                       /* module type */
[56]     NULL,                                  /* init master */
[57]     NULL,                                  /* init module */
[58]     NULL,                                  /* init process */
[59]     NULL,                                  /* init thread */
[60]     NULL,                                  /* exit thread */
[61]     NULL,                                  /* exit process */
[62]     NULL,                                  /* exit master */
[63]     NGX_MODULE_V1_PADDING
[64] };
[65] 
[66] 
[67] ngx_int_t
[68] ngx_mail_realip_handler(ngx_mail_session_t *s)
[69] {
[70]     ngx_addr_t                   addr;
[71]     ngx_connection_t            *c;
[72]     ngx_mail_realip_srv_conf_t  *rscf;
[73] 
[74]     rscf = ngx_mail_get_module_srv_conf(s, ngx_mail_realip_module);
[75] 
[76]     if (rscf->from == NULL) {
[77]         return NGX_OK;
[78]     }
[79] 
[80]     c = s->connection;
[81] 
[82]     if (c->proxy_protocol == NULL) {
[83]         return NGX_OK;
[84]     }
[85] 
[86]     if (ngx_cidr_match(c->sockaddr, rscf->from) != NGX_OK) {
[87]         return NGX_OK;
[88]     }
[89] 
[90]     if (ngx_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
[91]                        c->proxy_protocol->src_addr.len)
[92]         != NGX_OK)
[93]     {
[94]         return NGX_OK;
[95]     }
[96] 
[97]     ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
[98] 
[99]     return ngx_mail_realip_set_addr(s, &addr);
[100] }
[101] 
[102] 
[103] static ngx_int_t
[104] ngx_mail_realip_set_addr(ngx_mail_session_t *s, ngx_addr_t *addr)
[105] {
[106]     size_t             len;
[107]     u_char            *p;
[108]     u_char             text[NGX_SOCKADDR_STRLEN];
[109]     ngx_connection_t  *c;
[110] 
[111]     c = s->connection;
[112] 
[113]     len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
[114]                         NGX_SOCKADDR_STRLEN, 0);
[115]     if (len == 0) {
[116]         return NGX_ERROR;
[117]     }
[118] 
[119]     p = ngx_pnalloc(c->pool, len);
[120]     if (p == NULL) {
[121]         return NGX_ERROR;
[122]     }
[123] 
[124]     ngx_memcpy(p, text, len);
[125] 
[126]     c->sockaddr = addr->sockaddr;
[127]     c->socklen = addr->socklen;
[128]     c->addr_text.len = len;
[129]     c->addr_text.data = p;
[130] 
[131]     return NGX_OK;
[132] }
[133] 
[134] 
[135] static char *
[136] ngx_mail_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[137] {
[138]     ngx_mail_realip_srv_conf_t *rscf = conf;
[139] 
[140]     ngx_int_t             rc;
[141]     ngx_str_t            *value;
[142]     ngx_url_t             u;
[143]     ngx_cidr_t            c, *cidr;
[144]     ngx_uint_t            i;
[145]     struct sockaddr_in   *sin;
[146] #if (NGX_HAVE_INET6)
[147]     struct sockaddr_in6  *sin6;
[148] #endif
[149] 
[150]     value = cf->args->elts;
[151] 
[152]     if (rscf->from == NULL) {
[153]         rscf->from = ngx_array_create(cf->pool, 2,
[154]                                       sizeof(ngx_cidr_t));
[155]         if (rscf->from == NULL) {
[156]             return NGX_CONF_ERROR;
[157]         }
[158]     }
[159] 
[160] #if (NGX_HAVE_UNIX_DOMAIN)
[161] 
[162]     if (ngx_strcmp(value[1].data, "unix:") == 0) {
[163]         cidr = ngx_array_push(rscf->from);
[164]         if (cidr == NULL) {
[165]             return NGX_CONF_ERROR;
[166]         }
[167] 
[168]         cidr->family = AF_UNIX;
[169]         return NGX_CONF_OK;
[170]     }
[171] 
[172] #endif
[173] 
[174]     rc = ngx_ptocidr(&value[1], &c);
[175] 
[176]     if (rc != NGX_ERROR) {
[177]         if (rc == NGX_DONE) {
[178]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[179]                                "low address bits of %V are meaningless",
[180]                                &value[1]);
[181]         }
[182] 
[183]         cidr = ngx_array_push(rscf->from);
[184]         if (cidr == NULL) {
[185]             return NGX_CONF_ERROR;
[186]         }
[187] 
[188]         *cidr = c;
[189] 
[190]         return NGX_CONF_OK;
[191]     }
[192] 
[193]     ngx_memzero(&u, sizeof(ngx_url_t));
[194]     u.host = value[1];
[195] 
[196]     if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
[197]         if (u.err) {
[198]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[199]                                "%s in set_real_ip_from \"%V\"",
[200]                                u.err, &u.host);
[201]         }
[202] 
[203]         return NGX_CONF_ERROR;
[204]     }
[205] 
[206]     cidr = ngx_array_push_n(rscf->from, u.naddrs);
[207]     if (cidr == NULL) {
[208]         return NGX_CONF_ERROR;
[209]     }
[210] 
[211]     ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));
[212] 
[213]     for (i = 0; i < u.naddrs; i++) {
[214]         cidr[i].family = u.addrs[i].sockaddr->sa_family;
[215] 
[216]         switch (cidr[i].family) {
[217] 
[218] #if (NGX_HAVE_INET6)
[219]         case AF_INET6:
[220]             sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
[221]             cidr[i].u.in6.addr = sin6->sin6_addr;
[222]             ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
[223]             break;
[224] #endif
[225] 
[226]         default: /* AF_INET */
[227]             sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
[228]             cidr[i].u.in.addr = sin->sin_addr.s_addr;
[229]             cidr[i].u.in.mask = 0xffffffff;
[230]             break;
[231]         }
[232]     }
[233] 
[234]     return NGX_CONF_OK;
[235] }
[236] 
[237] 
[238] static void *
[239] ngx_mail_realip_create_srv_conf(ngx_conf_t *cf)
[240] {
[241]     ngx_mail_realip_srv_conf_t  *conf;
[242] 
[243]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_realip_srv_conf_t));
[244]     if (conf == NULL) {
[245]         return NULL;
[246]     }
[247] 
[248]     /*
[249]      * set by ngx_pcalloc():
[250]      *
[251]      *     conf->from = NULL;
[252]      */
[253] 
[254]     return conf;
[255] }
[256] 
[257] 
[258] static char *
[259] ngx_mail_realip_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[260] {
[261]     ngx_mail_realip_srv_conf_t *prev = parent;
[262]     ngx_mail_realip_srv_conf_t *conf = child;
[263] 
[264]     if (conf->from == NULL) {
[265]         conf->from = prev->from;
[266]     }
[267] 
[268]     return NGX_CONF_OK;
[269] }
