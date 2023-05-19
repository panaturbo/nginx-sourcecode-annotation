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
[14]     ngx_array_t       *from;     /* array of ngx_cidr_t */
[15] } ngx_stream_realip_srv_conf_t;
[16] 
[17] 
[18] typedef struct {
[19]     struct sockaddr   *sockaddr;
[20]     socklen_t          socklen;
[21]     ngx_str_t          addr_text;
[22] } ngx_stream_realip_ctx_t;
[23] 
[24] 
[25] static ngx_int_t ngx_stream_realip_handler(ngx_stream_session_t *s);
[26] static ngx_int_t ngx_stream_realip_set_addr(ngx_stream_session_t *s,
[27]     ngx_addr_t *addr);
[28] static char *ngx_stream_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
[29]     void *conf);
[30] static void *ngx_stream_realip_create_srv_conf(ngx_conf_t *cf);
[31] static char *ngx_stream_realip_merge_srv_conf(ngx_conf_t *cf, void *parent,
[32]     void *child);
[33] static ngx_int_t ngx_stream_realip_add_variables(ngx_conf_t *cf);
[34] static ngx_int_t ngx_stream_realip_init(ngx_conf_t *cf);
[35] 
[36] 
[37] static ngx_int_t ngx_stream_realip_remote_addr_variable(ngx_stream_session_t *s,
[38]     ngx_stream_variable_value_t *v, uintptr_t data);
[39] static ngx_int_t ngx_stream_realip_remote_port_variable(ngx_stream_session_t *s,
[40]     ngx_stream_variable_value_t *v, uintptr_t data);
[41] 
[42] 
[43] static ngx_command_t  ngx_stream_realip_commands[] = {
[44] 
[45]     { ngx_string("set_real_ip_from"),
[46]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[47]       ngx_stream_realip_from,
[48]       NGX_STREAM_SRV_CONF_OFFSET,
[49]       0,
[50]       NULL },
[51] 
[52]       ngx_null_command
[53] };
[54] 
[55] 
[56] static ngx_stream_module_t  ngx_stream_realip_module_ctx = {
[57]     ngx_stream_realip_add_variables,       /* preconfiguration */
[58]     ngx_stream_realip_init,                /* postconfiguration */
[59] 
[60]     NULL,                                  /* create main configuration */
[61]     NULL,                                  /* init main configuration */
[62] 
[63]     ngx_stream_realip_create_srv_conf,     /* create server configuration */
[64]     ngx_stream_realip_merge_srv_conf       /* merge server configuration */
[65] };
[66] 
[67] 
[68] ngx_module_t  ngx_stream_realip_module = {
[69]     NGX_MODULE_V1,
[70]     &ngx_stream_realip_module_ctx,         /* module context */
[71]     ngx_stream_realip_commands,            /* module directives */
[72]     NGX_STREAM_MODULE,                     /* module type */
[73]     NULL,                                  /* init master */
[74]     NULL,                                  /* init module */
[75]     NULL,                                  /* init process */
[76]     NULL,                                  /* init thread */
[77]     NULL,                                  /* exit thread */
[78]     NULL,                                  /* exit process */
[79]     NULL,                                  /* exit master */
[80]     NGX_MODULE_V1_PADDING
[81] };
[82] 
[83] 
[84] static ngx_stream_variable_t  ngx_stream_realip_vars[] = {
[85] 
[86]     { ngx_string("realip_remote_addr"), NULL,
[87]       ngx_stream_realip_remote_addr_variable, 0, 0, 0 },
[88] 
[89]     { ngx_string("realip_remote_port"), NULL,
[90]       ngx_stream_realip_remote_port_variable, 0, 0, 0 },
[91] 
[92]       ngx_stream_null_variable
[93] };
[94] 
[95] 
[96] static ngx_int_t
[97] ngx_stream_realip_handler(ngx_stream_session_t *s)
[98] {
[99]     ngx_addr_t                     addr;
[100]     ngx_connection_t              *c;
[101]     ngx_stream_realip_srv_conf_t  *rscf;
[102] 
[103]     rscf = ngx_stream_get_module_srv_conf(s, ngx_stream_realip_module);
[104] 
[105]     if (rscf->from == NULL) {
[106]         return NGX_DECLINED;
[107]     }
[108] 
[109]     c = s->connection;
[110] 
[111]     if (c->proxy_protocol == NULL) {
[112]         return NGX_DECLINED;
[113]     }
[114] 
[115]     if (ngx_cidr_match(c->sockaddr, rscf->from) != NGX_OK) {
[116]         return NGX_DECLINED;
[117]     }
[118] 
[119]     if (ngx_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
[120]                        c->proxy_protocol->src_addr.len)
[121]         != NGX_OK)
[122]     {
[123]         return NGX_DECLINED;
[124]     }
[125] 
[126]     ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
[127] 
[128]     return ngx_stream_realip_set_addr(s, &addr);
[129] }
[130] 
[131] 
[132] static ngx_int_t
[133] ngx_stream_realip_set_addr(ngx_stream_session_t *s, ngx_addr_t *addr)
[134] {
[135]     size_t                    len;
[136]     u_char                   *p;
[137]     u_char                    text[NGX_SOCKADDR_STRLEN];
[138]     ngx_connection_t         *c;
[139]     ngx_stream_realip_ctx_t  *ctx;
[140] 
[141]     c = s->connection;
[142] 
[143]     ctx = ngx_palloc(c->pool, sizeof(ngx_stream_realip_ctx_t));
[144]     if (ctx == NULL) {
[145]         return NGX_ERROR;
[146]     }
[147] 
[148]     len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
[149]                         NGX_SOCKADDR_STRLEN, 0);
[150]     if (len == 0) {
[151]         return NGX_ERROR;
[152]     }
[153] 
[154]     p = ngx_pnalloc(c->pool, len);
[155]     if (p == NULL) {
[156]         return NGX_ERROR;
[157]     }
[158] 
[159]     ngx_memcpy(p, text, len);
[160] 
[161]     ngx_stream_set_ctx(s, ctx, ngx_stream_realip_module);
[162] 
[163]     ctx->sockaddr = c->sockaddr;
[164]     ctx->socklen = c->socklen;
[165]     ctx->addr_text = c->addr_text;
[166] 
[167]     c->sockaddr = addr->sockaddr;
[168]     c->socklen = addr->socklen;
[169]     c->addr_text.len = len;
[170]     c->addr_text.data = p;
[171] 
[172]     return NGX_DECLINED;
[173] }
[174] 
[175] 
[176] static char *
[177] ngx_stream_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[178] {
[179]     ngx_stream_realip_srv_conf_t *rscf = conf;
[180] 
[181]     ngx_int_t             rc;
[182]     ngx_str_t            *value;
[183]     ngx_url_t             u;
[184]     ngx_cidr_t            c, *cidr;
[185]     ngx_uint_t            i;
[186]     struct sockaddr_in   *sin;
[187] #if (NGX_HAVE_INET6)
[188]     struct sockaddr_in6  *sin6;
[189] #endif
[190] 
[191]     value = cf->args->elts;
[192] 
[193]     if (rscf->from == NULL) {
[194]         rscf->from = ngx_array_create(cf->pool, 2,
[195]                                       sizeof(ngx_cidr_t));
[196]         if (rscf->from == NULL) {
[197]             return NGX_CONF_ERROR;
[198]         }
[199]     }
[200] 
[201] #if (NGX_HAVE_UNIX_DOMAIN)
[202] 
[203]     if (ngx_strcmp(value[1].data, "unix:") == 0) {
[204]         cidr = ngx_array_push(rscf->from);
[205]         if (cidr == NULL) {
[206]             return NGX_CONF_ERROR;
[207]         }
[208] 
[209]         cidr->family = AF_UNIX;
[210]         return NGX_CONF_OK;
[211]     }
[212] 
[213] #endif
[214] 
[215]     rc = ngx_ptocidr(&value[1], &c);
[216] 
[217]     if (rc != NGX_ERROR) {
[218]         if (rc == NGX_DONE) {
[219]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[220]                                "low address bits of %V are meaningless",
[221]                                &value[1]);
[222]         }
[223] 
[224]         cidr = ngx_array_push(rscf->from);
[225]         if (cidr == NULL) {
[226]             return NGX_CONF_ERROR;
[227]         }
[228] 
[229]         *cidr = c;
[230] 
[231]         return NGX_CONF_OK;
[232]     }
[233] 
[234]     ngx_memzero(&u, sizeof(ngx_url_t));
[235]     u.host = value[1];
[236] 
[237]     if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
[238]         if (u.err) {
[239]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[240]                                "%s in set_real_ip_from \"%V\"",
[241]                                u.err, &u.host);
[242]         }
[243] 
[244]         return NGX_CONF_ERROR;
[245]     }
[246] 
[247]     cidr = ngx_array_push_n(rscf->from, u.naddrs);
[248]     if (cidr == NULL) {
[249]         return NGX_CONF_ERROR;
[250]     }
[251] 
[252]     ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));
[253] 
[254]     for (i = 0; i < u.naddrs; i++) {
[255]         cidr[i].family = u.addrs[i].sockaddr->sa_family;
[256] 
[257]         switch (cidr[i].family) {
[258] 
[259] #if (NGX_HAVE_INET6)
[260]         case AF_INET6:
[261]             sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
[262]             cidr[i].u.in6.addr = sin6->sin6_addr;
[263]             ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
[264]             break;
[265] #endif
[266] 
[267]         default: /* AF_INET */
[268]             sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
[269]             cidr[i].u.in.addr = sin->sin_addr.s_addr;
[270]             cidr[i].u.in.mask = 0xffffffff;
[271]             break;
[272]         }
[273]     }
[274] 
[275]     return NGX_CONF_OK;
[276] }
[277] 
[278] 
[279] static void *
[280] ngx_stream_realip_create_srv_conf(ngx_conf_t *cf)
[281] {
[282]     ngx_stream_realip_srv_conf_t  *conf;
[283] 
[284]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_realip_srv_conf_t));
[285]     if (conf == NULL) {
[286]         return NULL;
[287]     }
[288] 
[289]     /*
[290]      * set by ngx_pcalloc():
[291]      *
[292]      *     conf->from = NULL;
[293]      */
[294] 
[295]     return conf;
[296] }
[297] 
[298] 
[299] static char *
[300] ngx_stream_realip_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[301] {
[302]     ngx_stream_realip_srv_conf_t *prev = parent;
[303]     ngx_stream_realip_srv_conf_t *conf = child;
[304] 
[305]     if (conf->from == NULL) {
[306]         conf->from = prev->from;
[307]     }
[308] 
[309]     return NGX_CONF_OK;
[310] }
[311] 
[312] 
[313] static ngx_int_t
[314] ngx_stream_realip_add_variables(ngx_conf_t *cf)
[315] {
[316]     ngx_stream_variable_t  *var, *v;
[317] 
[318]     for (v = ngx_stream_realip_vars; v->name.len; v++) {
[319]         var = ngx_stream_add_variable(cf, &v->name, v->flags);
[320]         if (var == NULL) {
[321]             return NGX_ERROR;
[322]         }
[323] 
[324]         var->get_handler = v->get_handler;
[325]         var->data = v->data;
[326]     }
[327] 
[328]     return NGX_OK;
[329] }
[330] 
[331] 
[332] static ngx_int_t
[333] ngx_stream_realip_init(ngx_conf_t *cf)
[334] {
[335]     ngx_stream_handler_pt        *h;
[336]     ngx_stream_core_main_conf_t  *cmcf;
[337] 
[338]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[339] 
[340]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_POST_ACCEPT_PHASE].handlers);
[341]     if (h == NULL) {
[342]         return NGX_ERROR;
[343]     }
[344] 
[345]     *h = ngx_stream_realip_handler;
[346] 
[347]     return NGX_OK;
[348] }
[349] 
[350] 
[351] static ngx_int_t
[352] ngx_stream_realip_remote_addr_variable(ngx_stream_session_t *s,
[353]     ngx_stream_variable_value_t *v, uintptr_t data)
[354] {
[355]     ngx_str_t                *addr_text;
[356]     ngx_stream_realip_ctx_t  *ctx;
[357] 
[358]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_realip_module);
[359] 
[360]     addr_text = ctx ? &ctx->addr_text : &s->connection->addr_text;
[361] 
[362]     v->len = addr_text->len;
[363]     v->valid = 1;
[364]     v->no_cacheable = 0;
[365]     v->not_found = 0;
[366]     v->data = addr_text->data;
[367] 
[368]     return NGX_OK;
[369] }
[370] 
[371] 
[372] static ngx_int_t
[373] ngx_stream_realip_remote_port_variable(ngx_stream_session_t *s,
[374]     ngx_stream_variable_value_t *v, uintptr_t data)
[375] {
[376]     ngx_uint_t                port;
[377]     struct sockaddr          *sa;
[378]     ngx_stream_realip_ctx_t  *ctx;
[379] 
[380]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_realip_module);
[381] 
[382]     sa = ctx ? ctx->sockaddr : s->connection->sockaddr;
[383] 
[384]     v->len = 0;
[385]     v->valid = 1;
[386]     v->no_cacheable = 0;
[387]     v->not_found = 0;
[388] 
[389]     v->data = ngx_pnalloc(s->connection->pool, sizeof("65535") - 1);
[390]     if (v->data == NULL) {
[391]         return NGX_ERROR;
[392]     }
[393] 
[394]     port = ngx_inet_get_port(sa);
[395] 
[396]     if (port > 0 && port < 65536) {
[397]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[398]     }
[399] 
[400]     return NGX_OK;
[401] }
