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
[13] #define NGX_HTTP_REALIP_XREALIP  0
[14] #define NGX_HTTP_REALIP_XFWD     1
[15] #define NGX_HTTP_REALIP_HEADER   2
[16] #define NGX_HTTP_REALIP_PROXY    3
[17] 
[18] 
[19] typedef struct {
[20]     ngx_array_t       *from;     /* array of ngx_cidr_t */
[21]     ngx_uint_t         type;
[22]     ngx_uint_t         hash;
[23]     ngx_str_t          header;
[24]     ngx_flag_t         recursive;
[25] } ngx_http_realip_loc_conf_t;
[26] 
[27] 
[28] typedef struct {
[29]     ngx_connection_t  *connection;
[30]     struct sockaddr   *sockaddr;
[31]     socklen_t          socklen;
[32]     ngx_str_t          addr_text;
[33] } ngx_http_realip_ctx_t;
[34] 
[35] 
[36] static ngx_int_t ngx_http_realip_handler(ngx_http_request_t *r);
[37] static ngx_int_t ngx_http_realip_set_addr(ngx_http_request_t *r,
[38]     ngx_addr_t *addr);
[39] static void ngx_http_realip_cleanup(void *data);
[40] static char *ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd,
[41]     void *conf);
[42] static char *ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[43] static void *ngx_http_realip_create_loc_conf(ngx_conf_t *cf);
[44] static char *ngx_http_realip_merge_loc_conf(ngx_conf_t *cf,
[45]     void *parent, void *child);
[46] static ngx_int_t ngx_http_realip_add_variables(ngx_conf_t *cf);
[47] static ngx_int_t ngx_http_realip_init(ngx_conf_t *cf);
[48] static ngx_http_realip_ctx_t *ngx_http_realip_get_module_ctx(
[49]     ngx_http_request_t *r);
[50] 
[51] 
[52] static ngx_int_t ngx_http_realip_remote_addr_variable(ngx_http_request_t *r,
[53]     ngx_http_variable_value_t *v, uintptr_t data);
[54] static ngx_int_t ngx_http_realip_remote_port_variable(ngx_http_request_t *r,
[55]     ngx_http_variable_value_t *v, uintptr_t data);
[56] 
[57] 
[58] static ngx_command_t  ngx_http_realip_commands[] = {
[59] 
[60]     { ngx_string("set_real_ip_from"),
[61]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[62]       ngx_http_realip_from,
[63]       NGX_HTTP_LOC_CONF_OFFSET,
[64]       0,
[65]       NULL },
[66] 
[67]     { ngx_string("real_ip_header"),
[68]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[69]       ngx_http_realip,
[70]       NGX_HTTP_LOC_CONF_OFFSET,
[71]       0,
[72]       NULL },
[73] 
[74]     { ngx_string("real_ip_recursive"),
[75]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[76]       ngx_conf_set_flag_slot,
[77]       NGX_HTTP_LOC_CONF_OFFSET,
[78]       offsetof(ngx_http_realip_loc_conf_t, recursive),
[79]       NULL },
[80] 
[81]       ngx_null_command
[82] };
[83] 
[84] 
[85] 
[86] static ngx_http_module_t  ngx_http_realip_module_ctx = {
[87]     ngx_http_realip_add_variables,         /* preconfiguration */
[88]     ngx_http_realip_init,                  /* postconfiguration */
[89] 
[90]     NULL,                                  /* create main configuration */
[91]     NULL,                                  /* init main configuration */
[92] 
[93]     NULL,                                  /* create server configuration */
[94]     NULL,                                  /* merge server configuration */
[95] 
[96]     ngx_http_realip_create_loc_conf,       /* create location configuration */
[97]     ngx_http_realip_merge_loc_conf         /* merge location configuration */
[98] };
[99] 
[100] 
[101] ngx_module_t  ngx_http_realip_module = {
[102]     NGX_MODULE_V1,
[103]     &ngx_http_realip_module_ctx,           /* module context */
[104]     ngx_http_realip_commands,              /* module directives */
[105]     NGX_HTTP_MODULE,                       /* module type */
[106]     NULL,                                  /* init master */
[107]     NULL,                                  /* init module */
[108]     NULL,                                  /* init process */
[109]     NULL,                                  /* init thread */
[110]     NULL,                                  /* exit thread */
[111]     NULL,                                  /* exit process */
[112]     NULL,                                  /* exit master */
[113]     NGX_MODULE_V1_PADDING
[114] };
[115] 
[116] 
[117] static ngx_http_variable_t  ngx_http_realip_vars[] = {
[118] 
[119]     { ngx_string("realip_remote_addr"), NULL,
[120]       ngx_http_realip_remote_addr_variable, 0, 0, 0 },
[121] 
[122]     { ngx_string("realip_remote_port"), NULL,
[123]       ngx_http_realip_remote_port_variable, 0, 0, 0 },
[124] 
[125]       ngx_http_null_variable
[126] };
[127] 
[128] 
[129] static ngx_int_t
[130] ngx_http_realip_handler(ngx_http_request_t *r)
[131] {
[132]     u_char                      *p;
[133]     size_t                       len;
[134]     ngx_str_t                   *value;
[135]     ngx_uint_t                   i, hash;
[136]     ngx_addr_t                   addr;
[137]     ngx_list_part_t             *part;
[138]     ngx_table_elt_t             *header, *xfwd;
[139]     ngx_connection_t            *c;
[140]     ngx_http_realip_ctx_t       *ctx;
[141]     ngx_http_realip_loc_conf_t  *rlcf;
[142] 
[143]     rlcf = ngx_http_get_module_loc_conf(r, ngx_http_realip_module);
[144] 
[145]     if (rlcf->from == NULL) {
[146]         return NGX_DECLINED;
[147]     }
[148] 
[149]     ctx = ngx_http_realip_get_module_ctx(r);
[150] 
[151]     if (ctx) {
[152]         return NGX_DECLINED;
[153]     }
[154] 
[155]     switch (rlcf->type) {
[156] 
[157]     case NGX_HTTP_REALIP_XREALIP:
[158] 
[159]         if (r->headers_in.x_real_ip == NULL) {
[160]             return NGX_DECLINED;
[161]         }
[162] 
[163]         value = &r->headers_in.x_real_ip->value;
[164]         xfwd = NULL;
[165] 
[166]         break;
[167] 
[168]     case NGX_HTTP_REALIP_XFWD:
[169] 
[170]         xfwd = r->headers_in.x_forwarded_for;
[171] 
[172]         if (xfwd == NULL) {
[173]             return NGX_DECLINED;
[174]         }
[175] 
[176]         value = NULL;
[177] 
[178]         break;
[179] 
[180]     case NGX_HTTP_REALIP_PROXY:
[181] 
[182]         if (r->connection->proxy_protocol == NULL) {
[183]             return NGX_DECLINED;
[184]         }
[185] 
[186]         value = &r->connection->proxy_protocol->src_addr;
[187]         xfwd = NULL;
[188] 
[189]         break;
[190] 
[191]     default: /* NGX_HTTP_REALIP_HEADER */
[192] 
[193]         part = &r->headers_in.headers.part;
[194]         header = part->elts;
[195] 
[196]         hash = rlcf->hash;
[197]         len = rlcf->header.len;
[198]         p = rlcf->header.data;
[199] 
[200]         for (i = 0; /* void */ ; i++) {
[201] 
[202]             if (i >= part->nelts) {
[203]                 if (part->next == NULL) {
[204]                     break;
[205]                 }
[206] 
[207]                 part = part->next;
[208]                 header = part->elts;
[209]                 i = 0;
[210]             }
[211] 
[212]             if (hash == header[i].hash
[213]                 && len == header[i].key.len
[214]                 && ngx_strncmp(p, header[i].lowcase_key, len) == 0)
[215]             {
[216]                 value = &header[i].value;
[217]                 xfwd = NULL;
[218] 
[219]                 goto found;
[220]             }
[221]         }
[222] 
[223]         return NGX_DECLINED;
[224]     }
[225] 
[226] found:
[227] 
[228]     c = r->connection;
[229] 
[230]     addr.sockaddr = c->sockaddr;
[231]     addr.socklen = c->socklen;
[232]     /* addr.name = c->addr_text; */
[233] 
[234]     if (ngx_http_get_forwarded_addr(r, &addr, xfwd, value, rlcf->from,
[235]                                     rlcf->recursive)
[236]         != NGX_DECLINED)
[237]     {
[238]         if (rlcf->type == NGX_HTTP_REALIP_PROXY) {
[239]             ngx_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
[240]         }
[241] 
[242]         return ngx_http_realip_set_addr(r, &addr);
[243]     }
[244] 
[245]     return NGX_DECLINED;
[246] }
[247] 
[248] 
[249] static ngx_int_t
[250] ngx_http_realip_set_addr(ngx_http_request_t *r, ngx_addr_t *addr)
[251] {
[252]     size_t                  len;
[253]     u_char                 *p;
[254]     u_char                  text[NGX_SOCKADDR_STRLEN];
[255]     ngx_connection_t       *c;
[256]     ngx_pool_cleanup_t     *cln;
[257]     ngx_http_realip_ctx_t  *ctx;
[258] 
[259]     cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_realip_ctx_t));
[260]     if (cln == NULL) {
[261]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[262]     }
[263] 
[264]     ctx = cln->data;
[265] 
[266]     c = r->connection;
[267] 
[268]     len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text,
[269]                         NGX_SOCKADDR_STRLEN, 0);
[270]     if (len == 0) {
[271]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[272]     }
[273] 
[274]     p = ngx_pnalloc(c->pool, len);
[275]     if (p == NULL) {
[276]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[277]     }
[278] 
[279]     ngx_memcpy(p, text, len);
[280] 
[281]     cln->handler = ngx_http_realip_cleanup;
[282]     ngx_http_set_ctx(r, ctx, ngx_http_realip_module);
[283] 
[284]     ctx->connection = c;
[285]     ctx->sockaddr = c->sockaddr;
[286]     ctx->socklen = c->socklen;
[287]     ctx->addr_text = c->addr_text;
[288] 
[289]     c->sockaddr = addr->sockaddr;
[290]     c->socklen = addr->socklen;
[291]     c->addr_text.len = len;
[292]     c->addr_text.data = p;
[293] 
[294]     return NGX_DECLINED;
[295] }
[296] 
[297] 
[298] static void
[299] ngx_http_realip_cleanup(void *data)
[300] {
[301]     ngx_http_realip_ctx_t *ctx = data;
[302] 
[303]     ngx_connection_t  *c;
[304] 
[305]     c = ctx->connection;
[306] 
[307]     c->sockaddr = ctx->sockaddr;
[308]     c->socklen = ctx->socklen;
[309]     c->addr_text = ctx->addr_text;
[310] }
[311] 
[312] 
[313] static char *
[314] ngx_http_realip_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[315] {
[316]     ngx_http_realip_loc_conf_t *rlcf = conf;
[317] 
[318]     ngx_int_t             rc;
[319]     ngx_str_t            *value;
[320]     ngx_url_t             u;
[321]     ngx_cidr_t            c, *cidr;
[322]     ngx_uint_t            i;
[323]     struct sockaddr_in   *sin;
[324] #if (NGX_HAVE_INET6)
[325]     struct sockaddr_in6  *sin6;
[326] #endif
[327] 
[328]     value = cf->args->elts;
[329] 
[330]     if (rlcf->from == NULL) {
[331]         rlcf->from = ngx_array_create(cf->pool, 2,
[332]                                       sizeof(ngx_cidr_t));
[333]         if (rlcf->from == NULL) {
[334]             return NGX_CONF_ERROR;
[335]         }
[336]     }
[337] 
[338] #if (NGX_HAVE_UNIX_DOMAIN)
[339] 
[340]     if (ngx_strcmp(value[1].data, "unix:") == 0) {
[341]         cidr = ngx_array_push(rlcf->from);
[342]         if (cidr == NULL) {
[343]             return NGX_CONF_ERROR;
[344]         }
[345] 
[346]         cidr->family = AF_UNIX;
[347]         return NGX_CONF_OK;
[348]     }
[349] 
[350] #endif
[351] 
[352]     rc = ngx_ptocidr(&value[1], &c);
[353] 
[354]     if (rc != NGX_ERROR) {
[355]         if (rc == NGX_DONE) {
[356]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[357]                                "low address bits of %V are meaningless",
[358]                                &value[1]);
[359]         }
[360] 
[361]         cidr = ngx_array_push(rlcf->from);
[362]         if (cidr == NULL) {
[363]             return NGX_CONF_ERROR;
[364]         }
[365] 
[366]         *cidr = c;
[367] 
[368]         return NGX_CONF_OK;
[369]     }
[370] 
[371]     ngx_memzero(&u, sizeof(ngx_url_t));
[372]     u.host = value[1];
[373] 
[374]     if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
[375]         if (u.err) {
[376]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[377]                                "%s in set_real_ip_from \"%V\"",
[378]                                u.err, &u.host);
[379]         }
[380] 
[381]         return NGX_CONF_ERROR;
[382]     }
[383] 
[384]     cidr = ngx_array_push_n(rlcf->from, u.naddrs);
[385]     if (cidr == NULL) {
[386]         return NGX_CONF_ERROR;
[387]     }
[388] 
[389]     ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));
[390] 
[391]     for (i = 0; i < u.naddrs; i++) {
[392]         cidr[i].family = u.addrs[i].sockaddr->sa_family;
[393] 
[394]         switch (cidr[i].family) {
[395] 
[396] #if (NGX_HAVE_INET6)
[397]         case AF_INET6:
[398]             sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
[399]             cidr[i].u.in6.addr = sin6->sin6_addr;
[400]             ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
[401]             break;
[402] #endif
[403] 
[404]         default: /* AF_INET */
[405]             sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
[406]             cidr[i].u.in.addr = sin->sin_addr.s_addr;
[407]             cidr[i].u.in.mask = 0xffffffff;
[408]             break;
[409]         }
[410]     }
[411] 
[412]     return NGX_CONF_OK;
[413] }
[414] 
[415] 
[416] static char *
[417] ngx_http_realip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[418] {
[419]     ngx_http_realip_loc_conf_t *rlcf = conf;
[420] 
[421]     ngx_str_t  *value;
[422] 
[423]     if (rlcf->type != NGX_CONF_UNSET_UINT) {
[424]         return "is duplicate";
[425]     }
[426] 
[427]     value = cf->args->elts;
[428] 
[429]     if (ngx_strcmp(value[1].data, "X-Real-IP") == 0) {
[430]         rlcf->type = NGX_HTTP_REALIP_XREALIP;
[431]         return NGX_CONF_OK;
[432]     }
[433] 
[434]     if (ngx_strcmp(value[1].data, "X-Forwarded-For") == 0) {
[435]         rlcf->type = NGX_HTTP_REALIP_XFWD;
[436]         return NGX_CONF_OK;
[437]     }
[438] 
[439]     if (ngx_strcmp(value[1].data, "proxy_protocol") == 0) {
[440]         rlcf->type = NGX_HTTP_REALIP_PROXY;
[441]         return NGX_CONF_OK;
[442]     }
[443] 
[444]     rlcf->type = NGX_HTTP_REALIP_HEADER;
[445]     rlcf->hash = ngx_hash_strlow(value[1].data, value[1].data, value[1].len);
[446]     rlcf->header = value[1];
[447] 
[448]     return NGX_CONF_OK;
[449] }
[450] 
[451] 
[452] static void *
[453] ngx_http_realip_create_loc_conf(ngx_conf_t *cf)
[454] {
[455]     ngx_http_realip_loc_conf_t  *conf;
[456] 
[457]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_realip_loc_conf_t));
[458]     if (conf == NULL) {
[459]         return NULL;
[460]     }
[461] 
[462]     /*
[463]      * set by ngx_pcalloc():
[464]      *
[465]      *     conf->from = NULL;
[466]      *     conf->hash = 0;
[467]      *     conf->header = { 0, NULL };
[468]      */
[469] 
[470]     conf->type = NGX_CONF_UNSET_UINT;
[471]     conf->recursive = NGX_CONF_UNSET;
[472] 
[473]     return conf;
[474] }
[475] 
[476] 
[477] static char *
[478] ngx_http_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[479] {
[480]     ngx_http_realip_loc_conf_t  *prev = parent;
[481]     ngx_http_realip_loc_conf_t  *conf = child;
[482] 
[483]     if (conf->from == NULL) {
[484]         conf->from = prev->from;
[485]     }
[486] 
[487]     ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_REALIP_XREALIP);
[488]     ngx_conf_merge_value(conf->recursive, prev->recursive, 0);
[489] 
[490]     if (conf->header.len == 0) {
[491]         conf->hash = prev->hash;
[492]         conf->header = prev->header;
[493]     }
[494] 
[495]     return NGX_CONF_OK;
[496] }
[497] 
[498] 
[499] static ngx_int_t
[500] ngx_http_realip_add_variables(ngx_conf_t *cf)
[501] {
[502]     ngx_http_variable_t  *var, *v;
[503] 
[504]     for (v = ngx_http_realip_vars; v->name.len; v++) {
[505]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[506]         if (var == NULL) {
[507]             return NGX_ERROR;
[508]         }
[509] 
[510]         var->get_handler = v->get_handler;
[511]         var->data = v->data;
[512]     }
[513] 
[514]     return NGX_OK;
[515] }
[516] 
[517] 
[518] static ngx_int_t
[519] ngx_http_realip_init(ngx_conf_t *cf)
[520] {
[521]     ngx_http_handler_pt        *h;
[522]     ngx_http_core_main_conf_t  *cmcf;
[523] 
[524]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[525] 
[526]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
[527]     if (h == NULL) {
[528]         return NGX_ERROR;
[529]     }
[530] 
[531]     *h = ngx_http_realip_handler;
[532] 
[533]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
[534]     if (h == NULL) {
[535]         return NGX_ERROR;
[536]     }
[537] 
[538]     *h = ngx_http_realip_handler;
[539] 
[540]     return NGX_OK;
[541] }
[542] 
[543] 
[544] static ngx_http_realip_ctx_t *
[545] ngx_http_realip_get_module_ctx(ngx_http_request_t *r)
[546] {
[547]     ngx_pool_cleanup_t     *cln;
[548]     ngx_http_realip_ctx_t  *ctx;
[549] 
[550]     ctx = ngx_http_get_module_ctx(r, ngx_http_realip_module);
[551] 
[552]     if (ctx == NULL && (r->internal || r->filter_finalize)) {
[553] 
[554]         /*
[555]          * if module context was reset, the original address
[556]          * can still be found in the cleanup handler
[557]          */
[558] 
[559]         for (cln = r->pool->cleanup; cln; cln = cln->next) {
[560]             if (cln->handler == ngx_http_realip_cleanup) {
[561]                 ctx = cln->data;
[562]                 break;
[563]             }
[564]         }
[565]     }
[566] 
[567]     return ctx;
[568] }
[569] 
[570] 
[571] static ngx_int_t
[572] ngx_http_realip_remote_addr_variable(ngx_http_request_t *r,
[573]     ngx_http_variable_value_t *v, uintptr_t data)
[574] {
[575]     ngx_str_t              *addr_text;
[576]     ngx_http_realip_ctx_t  *ctx;
[577] 
[578]     ctx = ngx_http_realip_get_module_ctx(r);
[579] 
[580]     addr_text = ctx ? &ctx->addr_text : &r->connection->addr_text;
[581] 
[582]     v->len = addr_text->len;
[583]     v->valid = 1;
[584]     v->no_cacheable = 0;
[585]     v->not_found = 0;
[586]     v->data = addr_text->data;
[587] 
[588]     return NGX_OK;
[589] }
[590] 
[591] 
[592] static ngx_int_t
[593] ngx_http_realip_remote_port_variable(ngx_http_request_t *r,
[594]     ngx_http_variable_value_t *v, uintptr_t data)
[595] {
[596]     ngx_uint_t              port;
[597]     struct sockaddr        *sa;
[598]     ngx_http_realip_ctx_t  *ctx;
[599] 
[600]     ctx = ngx_http_realip_get_module_ctx(r);
[601] 
[602]     sa = ctx ? ctx->sockaddr : r->connection->sockaddr;
[603] 
[604]     v->len = 0;
[605]     v->valid = 1;
[606]     v->no_cacheable = 0;
[607]     v->not_found = 0;
[608] 
[609]     v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
[610]     if (v->data == NULL) {
[611]         return NGX_ERROR;
[612]     }
[613] 
[614]     port = ngx_inet_get_port(sa);
[615] 
[616]     if (port > 0 && port < 65536) {
[617]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[618]     }
[619] 
[620]     return NGX_OK;
[621] }
