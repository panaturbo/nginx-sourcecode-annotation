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
[14]     ngx_http_variable_value_t       *value;
[15]     u_short                          start;
[16]     u_short                          end;
[17] } ngx_http_geo_range_t;
[18] 
[19] 
[20] typedef struct {
[21]     ngx_radix_tree_t                *tree;
[22] #if (NGX_HAVE_INET6)
[23]     ngx_radix_tree_t                *tree6;
[24] #endif
[25] } ngx_http_geo_trees_t;
[26] 
[27] 
[28] typedef struct {
[29]     ngx_http_geo_range_t           **low;
[30]     ngx_http_variable_value_t       *default_value;
[31] } ngx_http_geo_high_ranges_t;
[32] 
[33] 
[34] typedef struct {
[35]     ngx_str_node_t                   sn;
[36]     ngx_http_variable_value_t       *value;
[37]     size_t                           offset;
[38] } ngx_http_geo_variable_value_node_t;
[39] 
[40] 
[41] typedef struct {
[42]     ngx_http_variable_value_t       *value;
[43]     ngx_str_t                       *net;
[44]     ngx_http_geo_high_ranges_t       high;
[45]     ngx_radix_tree_t                *tree;
[46] #if (NGX_HAVE_INET6)
[47]     ngx_radix_tree_t                *tree6;
[48] #endif
[49]     ngx_rbtree_t                     rbtree;
[50]     ngx_rbtree_node_t                sentinel;
[51]     ngx_array_t                     *proxies;
[52]     ngx_pool_t                      *pool;
[53]     ngx_pool_t                      *temp_pool;
[54] 
[55]     size_t                           data_size;
[56] 
[57]     ngx_str_t                        include_name;
[58]     ngx_uint_t                       includes;
[59]     ngx_uint_t                       entries;
[60] 
[61]     unsigned                         ranges:1;
[62]     unsigned                         outside_entries:1;
[63]     unsigned                         allow_binary_include:1;
[64]     unsigned                         binary_include:1;
[65]     unsigned                         proxy_recursive:1;
[66] } ngx_http_geo_conf_ctx_t;
[67] 
[68] 
[69] typedef struct {
[70]     union {
[71]         ngx_http_geo_trees_t         trees;
[72]         ngx_http_geo_high_ranges_t   high;
[73]     } u;
[74] 
[75]     ngx_array_t                     *proxies;
[76]     unsigned                         proxy_recursive:1;
[77] 
[78]     ngx_int_t                        index;
[79] } ngx_http_geo_ctx_t;
[80] 
[81] 
[82] static ngx_int_t ngx_http_geo_addr(ngx_http_request_t *r,
[83]     ngx_http_geo_ctx_t *ctx, ngx_addr_t *addr);
[84] static ngx_int_t ngx_http_geo_real_addr(ngx_http_request_t *r,
[85]     ngx_http_geo_ctx_t *ctx, ngx_addr_t *addr);
[86] static char *ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[87] static char *ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
[88] static char *ngx_http_geo_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[89]     ngx_str_t *value);
[90] static char *ngx_http_geo_add_range(ngx_conf_t *cf,
[91]     ngx_http_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
[92] static ngx_uint_t ngx_http_geo_delete_range(ngx_conf_t *cf,
[93]     ngx_http_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
[94] static char *ngx_http_geo_cidr(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[95]     ngx_str_t *value);
[96] static char *ngx_http_geo_cidr_add(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[97]     ngx_cidr_t *cidr, ngx_str_t *value, ngx_str_t *net);
[98] static ngx_http_variable_value_t *ngx_http_geo_value(ngx_conf_t *cf,
[99]     ngx_http_geo_conf_ctx_t *ctx, ngx_str_t *value);
[100] static char *ngx_http_geo_add_proxy(ngx_conf_t *cf,
[101]     ngx_http_geo_conf_ctx_t *ctx, ngx_cidr_t *cidr);
[102] static ngx_int_t ngx_http_geo_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
[103]     ngx_cidr_t *cidr);
[104] static char *ngx_http_geo_include(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[105]     ngx_str_t *name);
[106] static ngx_int_t ngx_http_geo_include_binary_base(ngx_conf_t *cf,
[107]     ngx_http_geo_conf_ctx_t *ctx, ngx_str_t *name);
[108] static void ngx_http_geo_create_binary_base(ngx_http_geo_conf_ctx_t *ctx);
[109] static u_char *ngx_http_geo_copy_values(u_char *base, u_char *p,
[110]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[111] 
[112] 
[113] static ngx_command_t  ngx_http_geo_commands[] = {
[114] 
[115]     { ngx_string("geo"),
[116]       NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
[117]       ngx_http_geo_block,
[118]       NGX_HTTP_MAIN_CONF_OFFSET,
[119]       0,
[120]       NULL },
[121] 
[122]       ngx_null_command
[123] };
[124] 
[125] 
[126] static ngx_http_module_t  ngx_http_geo_module_ctx = {
[127]     NULL,                                  /* preconfiguration */
[128]     NULL,                                  /* postconfiguration */
[129] 
[130]     NULL,                                  /* create main configuration */
[131]     NULL,                                  /* init main configuration */
[132] 
[133]     NULL,                                  /* create server configuration */
[134]     NULL,                                  /* merge server configuration */
[135] 
[136]     NULL,                                  /* create location configuration */
[137]     NULL                                   /* merge location configuration */
[138] };
[139] 
[140] 
[141] ngx_module_t  ngx_http_geo_module = {
[142]     NGX_MODULE_V1,
[143]     &ngx_http_geo_module_ctx,              /* module context */
[144]     ngx_http_geo_commands,                 /* module directives */
[145]     NGX_HTTP_MODULE,                       /* module type */
[146]     NULL,                                  /* init master */
[147]     NULL,                                  /* init module */
[148]     NULL,                                  /* init process */
[149]     NULL,                                  /* init thread */
[150]     NULL,                                  /* exit thread */
[151]     NULL,                                  /* exit process */
[152]     NULL,                                  /* exit master */
[153]     NGX_MODULE_V1_PADDING
[154] };
[155] 
[156] 
[157] typedef struct {
[158]     u_char    GEORNG[6];
[159]     u_char    version;
[160]     u_char    ptr_size;
[161]     uint32_t  endianness;
[162]     uint32_t  crc32;
[163] } ngx_http_geo_header_t;
[164] 
[165] 
[166] static ngx_http_geo_header_t  ngx_http_geo_header = {
[167]     { 'G', 'E', 'O', 'R', 'N', 'G' }, 0, sizeof(void *), 0x12345678, 0
[168] };
[169] 
[170] 
[171] /* geo range is AF_INET only */
[172] 
[173] static ngx_int_t
[174] ngx_http_geo_cidr_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[175]     uintptr_t data)
[176] {
[177]     ngx_http_geo_ctx_t *ctx = (ngx_http_geo_ctx_t *) data;
[178] 
[179]     in_addr_t                   inaddr;
[180]     ngx_addr_t                  addr;
[181]     struct sockaddr_in         *sin;
[182]     ngx_http_variable_value_t  *vv;
[183] #if (NGX_HAVE_INET6)
[184]     u_char                     *p;
[185]     struct in6_addr            *inaddr6;
[186] #endif
[187] 
[188]     if (ngx_http_geo_addr(r, ctx, &addr) != NGX_OK) {
[189]         vv = (ngx_http_variable_value_t *)
[190]                   ngx_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
[191]         goto done;
[192]     }
[193] 
[194]     switch (addr.sockaddr->sa_family) {
[195] 
[196] #if (NGX_HAVE_INET6)
[197]     case AF_INET6:
[198]         inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
[199]         p = inaddr6->s6_addr;
[200] 
[201]         if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[202]             inaddr = p[12] << 24;
[203]             inaddr += p[13] << 16;
[204]             inaddr += p[14] << 8;
[205]             inaddr += p[15];
[206] 
[207]             vv = (ngx_http_variable_value_t *)
[208]                       ngx_radix32tree_find(ctx->u.trees.tree, inaddr);
[209] 
[210]         } else {
[211]             vv = (ngx_http_variable_value_t *)
[212]                       ngx_radix128tree_find(ctx->u.trees.tree6, p);
[213]         }
[214] 
[215]         break;
[216] #endif
[217] 
[218] #if (NGX_HAVE_UNIX_DOMAIN)
[219]     case AF_UNIX:
[220]         vv = (ngx_http_variable_value_t *)
[221]                   ngx_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
[222]         break;
[223] #endif
[224] 
[225]     default: /* AF_INET */
[226]         sin = (struct sockaddr_in *) addr.sockaddr;
[227]         inaddr = ntohl(sin->sin_addr.s_addr);
[228] 
[229]         vv = (ngx_http_variable_value_t *)
[230]                   ngx_radix32tree_find(ctx->u.trees.tree, inaddr);
[231] 
[232]         break;
[233]     }
[234] 
[235] done:
[236] 
[237]     *v = *vv;
[238] 
[239]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[240]                    "http geo: %v", v);
[241] 
[242]     return NGX_OK;
[243] }
[244] 
[245] 
[246] static ngx_int_t
[247] ngx_http_geo_range_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[248]     uintptr_t data)
[249] {
[250]     ngx_http_geo_ctx_t *ctx = (ngx_http_geo_ctx_t *) data;
[251] 
[252]     in_addr_t              inaddr;
[253]     ngx_addr_t             addr;
[254]     ngx_uint_t             n;
[255]     struct sockaddr_in    *sin;
[256]     ngx_http_geo_range_t  *range;
[257] #if (NGX_HAVE_INET6)
[258]     u_char                *p;
[259]     struct in6_addr       *inaddr6;
[260] #endif
[261] 
[262]     *v = *ctx->u.high.default_value;
[263] 
[264]     if (ngx_http_geo_addr(r, ctx, &addr) == NGX_OK) {
[265] 
[266]         switch (addr.sockaddr->sa_family) {
[267] 
[268] #if (NGX_HAVE_INET6)
[269]         case AF_INET6:
[270]             inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
[271] 
[272]             if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[273]                 p = inaddr6->s6_addr;
[274] 
[275]                 inaddr = p[12] << 24;
[276]                 inaddr += p[13] << 16;
[277]                 inaddr += p[14] << 8;
[278]                 inaddr += p[15];
[279] 
[280]             } else {
[281]                 inaddr = INADDR_NONE;
[282]             }
[283] 
[284]             break;
[285] #endif
[286] 
[287] #if (NGX_HAVE_UNIX_DOMAIN)
[288]         case AF_UNIX:
[289]             inaddr = INADDR_NONE;
[290]             break;
[291] #endif
[292] 
[293]         default: /* AF_INET */
[294]             sin = (struct sockaddr_in *) addr.sockaddr;
[295]             inaddr = ntohl(sin->sin_addr.s_addr);
[296]             break;
[297]         }
[298] 
[299]     } else {
[300]         inaddr = INADDR_NONE;
[301]     }
[302] 
[303]     if (ctx->u.high.low) {
[304]         range = ctx->u.high.low[inaddr >> 16];
[305] 
[306]         if (range) {
[307]             n = inaddr & 0xffff;
[308]             do {
[309]                 if (n >= (ngx_uint_t) range->start
[310]                     && n <= (ngx_uint_t) range->end)
[311]                 {
[312]                     *v = *range->value;
[313]                     break;
[314]                 }
[315]             } while ((++range)->value);
[316]         }
[317]     }
[318] 
[319]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[320]                    "http geo: %v", v);
[321] 
[322]     return NGX_OK;
[323] }
[324] 
[325] 
[326] static ngx_int_t
[327] ngx_http_geo_addr(ngx_http_request_t *r, ngx_http_geo_ctx_t *ctx,
[328]     ngx_addr_t *addr)
[329] {
[330]     ngx_table_elt_t  *xfwd;
[331] 
[332]     if (ngx_http_geo_real_addr(r, ctx, addr) != NGX_OK) {
[333]         return NGX_ERROR;
[334]     }
[335] 
[336]     xfwd = r->headers_in.x_forwarded_for;
[337] 
[338]     if (xfwd != NULL && ctx->proxies != NULL) {
[339]         (void) ngx_http_get_forwarded_addr(r, addr, xfwd, NULL,
[340]                                            ctx->proxies, ctx->proxy_recursive);
[341]     }
[342] 
[343]     return NGX_OK;
[344] }
[345] 
[346] 
[347] static ngx_int_t
[348] ngx_http_geo_real_addr(ngx_http_request_t *r, ngx_http_geo_ctx_t *ctx,
[349]     ngx_addr_t *addr)
[350] {
[351]     ngx_http_variable_value_t  *v;
[352] 
[353]     if (ctx->index == -1) {
[354]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[355]                        "http geo started: %V", &r->connection->addr_text);
[356] 
[357]         addr->sockaddr = r->connection->sockaddr;
[358]         addr->socklen = r->connection->socklen;
[359]         /* addr->name = r->connection->addr_text; */
[360] 
[361]         return NGX_OK;
[362]     }
[363] 
[364]     v = ngx_http_get_flushed_variable(r, ctx->index);
[365] 
[366]     if (v == NULL || v->not_found) {
[367]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[368]                        "http geo not found");
[369] 
[370]         return NGX_ERROR;
[371]     }
[372] 
[373]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[374]                    "http geo started: %v", v);
[375] 
[376]     if (ngx_parse_addr(r->pool, addr, v->data, v->len) == NGX_OK) {
[377]         return NGX_OK;
[378]     }
[379] 
[380]     return NGX_ERROR;
[381] }
[382] 
[383] 
[384] static char *
[385] ngx_http_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[386] {
[387]     char                     *rv;
[388]     size_t                    len;
[389]     ngx_str_t                *value, name;
[390]     ngx_uint_t                i;
[391]     ngx_conf_t                save;
[392]     ngx_pool_t               *pool;
[393]     ngx_array_t              *a;
[394]     ngx_http_variable_t      *var;
[395]     ngx_http_geo_ctx_t       *geo;
[396]     ngx_http_geo_conf_ctx_t   ctx;
[397] #if (NGX_HAVE_INET6)
[398]     static struct in6_addr    zero;
[399] #endif
[400] 
[401]     value = cf->args->elts;
[402] 
[403]     geo = ngx_palloc(cf->pool, sizeof(ngx_http_geo_ctx_t));
[404]     if (geo == NULL) {
[405]         return NGX_CONF_ERROR;
[406]     }
[407] 
[408]     name = value[1];
[409] 
[410]     if (name.data[0] != '$') {
[411]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[412]                            "invalid variable name \"%V\"", &name);
[413]         return NGX_CONF_ERROR;
[414]     }
[415] 
[416]     name.len--;
[417]     name.data++;
[418] 
[419]     if (cf->args->nelts == 3) {
[420] 
[421]         geo->index = ngx_http_get_variable_index(cf, &name);
[422]         if (geo->index == NGX_ERROR) {
[423]             return NGX_CONF_ERROR;
[424]         }
[425] 
[426]         name = value[2];
[427] 
[428]         if (name.data[0] != '$') {
[429]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[430]                                "invalid variable name \"%V\"", &name);
[431]             return NGX_CONF_ERROR;
[432]         }
[433] 
[434]         name.len--;
[435]         name.data++;
[436] 
[437]     } else {
[438]         geo->index = -1;
[439]     }
[440] 
[441]     var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
[442]     if (var == NULL) {
[443]         return NGX_CONF_ERROR;
[444]     }
[445] 
[446]     pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[447]     if (pool == NULL) {
[448]         return NGX_CONF_ERROR;
[449]     }
[450] 
[451]     ngx_memzero(&ctx, sizeof(ngx_http_geo_conf_ctx_t));
[452] 
[453]     ctx.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[454]     if (ctx.temp_pool == NULL) {
[455]         ngx_destroy_pool(pool);
[456]         return NGX_CONF_ERROR;
[457]     }
[458] 
[459]     ngx_rbtree_init(&ctx.rbtree, &ctx.sentinel, ngx_str_rbtree_insert_value);
[460] 
[461]     ctx.pool = cf->pool;
[462]     ctx.data_size = sizeof(ngx_http_geo_header_t)
[463]                   + sizeof(ngx_http_variable_value_t)
[464]                   + 0x10000 * sizeof(ngx_http_geo_range_t *);
[465]     ctx.allow_binary_include = 1;
[466] 
[467]     save = *cf;
[468]     cf->pool = pool;
[469]     cf->ctx = &ctx;
[470]     cf->handler = ngx_http_geo;
[471]     cf->handler_conf = conf;
[472] 
[473]     rv = ngx_conf_parse(cf, NULL);
[474] 
[475]     *cf = save;
[476] 
[477]     if (rv != NGX_CONF_OK) {
[478]         goto failed;
[479]     }
[480] 
[481]     geo->proxies = ctx.proxies;
[482]     geo->proxy_recursive = ctx.proxy_recursive;
[483] 
[484]     if (ctx.ranges) {
[485] 
[486]         if (ctx.high.low && !ctx.binary_include) {
[487]             for (i = 0; i < 0x10000; i++) {
[488]                 a = (ngx_array_t *) ctx.high.low[i];
[489] 
[490]                 if (a == NULL) {
[491]                     continue;
[492]                 }
[493] 
[494]                 if (a->nelts == 0) {
[495]                     ctx.high.low[i] = NULL;
[496]                     continue;
[497]                 }
[498] 
[499]                 len = a->nelts * sizeof(ngx_http_geo_range_t);
[500] 
[501]                 ctx.high.low[i] = ngx_palloc(cf->pool, len + sizeof(void *));
[502]                 if (ctx.high.low[i] == NULL) {
[503]                     goto failed;
[504]                 }
[505] 
[506]                 ngx_memcpy(ctx.high.low[i], a->elts, len);
[507]                 ctx.high.low[i][a->nelts].value = NULL;
[508]                 ctx.data_size += len + sizeof(void *);
[509]             }
[510] 
[511]             if (ctx.allow_binary_include
[512]                 && !ctx.outside_entries
[513]                 && ctx.entries > 100000
[514]                 && ctx.includes == 1)
[515]             {
[516]                 ngx_http_geo_create_binary_base(&ctx);
[517]             }
[518]         }
[519] 
[520]         if (ctx.high.default_value == NULL) {
[521]             ctx.high.default_value = &ngx_http_variable_null_value;
[522]         }
[523] 
[524]         geo->u.high = ctx.high;
[525] 
[526]         var->get_handler = ngx_http_geo_range_variable;
[527]         var->data = (uintptr_t) geo;
[528] 
[529]     } else {
[530]         if (ctx.tree == NULL) {
[531]             ctx.tree = ngx_radix_tree_create(cf->pool, -1);
[532]             if (ctx.tree == NULL) {
[533]                 goto failed;
[534]             }
[535]         }
[536] 
[537]         geo->u.trees.tree = ctx.tree;
[538] 
[539] #if (NGX_HAVE_INET6)
[540]         if (ctx.tree6 == NULL) {
[541]             ctx.tree6 = ngx_radix_tree_create(cf->pool, -1);
[542]             if (ctx.tree6 == NULL) {
[543]                 goto failed;
[544]             }
[545]         }
[546] 
[547]         geo->u.trees.tree6 = ctx.tree6;
[548] #endif
[549] 
[550]         var->get_handler = ngx_http_geo_cidr_variable;
[551]         var->data = (uintptr_t) geo;
[552] 
[553]         if (ngx_radix32tree_insert(ctx.tree, 0, 0,
[554]                                    (uintptr_t) &ngx_http_variable_null_value)
[555]             == NGX_ERROR)
[556]         {
[557]             goto failed;
[558]         }
[559] 
[560]         /* NGX_BUSY is okay (default was set explicitly) */
[561] 
[562] #if (NGX_HAVE_INET6)
[563]         if (ngx_radix128tree_insert(ctx.tree6, zero.s6_addr, zero.s6_addr,
[564]                                     (uintptr_t) &ngx_http_variable_null_value)
[565]             == NGX_ERROR)
[566]         {
[567]             goto failed;
[568]         }
[569] #endif
[570]     }
[571] 
[572]     ngx_destroy_pool(ctx.temp_pool);
[573]     ngx_destroy_pool(pool);
[574] 
[575]     return NGX_CONF_OK;
[576] 
[577] failed:
[578] 
[579]     ngx_destroy_pool(ctx.temp_pool);
[580]     ngx_destroy_pool(pool);
[581] 
[582]     return NGX_CONF_ERROR;
[583] }
[584] 
[585] 
[586] static char *
[587] ngx_http_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[588] {
[589]     char                     *rv;
[590]     ngx_str_t                *value;
[591]     ngx_cidr_t                cidr;
[592]     ngx_http_geo_conf_ctx_t  *ctx;
[593] 
[594]     ctx = cf->ctx;
[595] 
[596]     value = cf->args->elts;
[597] 
[598]     if (cf->args->nelts == 1) {
[599] 
[600]         if (ngx_strcmp(value[0].data, "ranges") == 0) {
[601] 
[602]             if (ctx->tree
[603] #if (NGX_HAVE_INET6)
[604]                 || ctx->tree6
[605] #endif
[606]                )
[607]             {
[608]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[609]                                    "the \"ranges\" directive must be "
[610]                                    "the first directive inside \"geo\" block");
[611]                 goto failed;
[612]             }
[613] 
[614]             ctx->ranges = 1;
[615] 
[616]             rv = NGX_CONF_OK;
[617] 
[618]             goto done;
[619]         }
[620] 
[621]         else if (ngx_strcmp(value[0].data, "proxy_recursive") == 0) {
[622]             ctx->proxy_recursive = 1;
[623]             rv = NGX_CONF_OK;
[624]             goto done;
[625]         }
[626]     }
[627] 
[628]     if (cf->args->nelts != 2) {
[629]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[630]                            "invalid number of the geo parameters");
[631]         goto failed;
[632]     }
[633] 
[634]     if (ngx_strcmp(value[0].data, "include") == 0) {
[635] 
[636]         rv = ngx_http_geo_include(cf, ctx, &value[1]);
[637] 
[638]         goto done;
[639] 
[640]     } else if (ngx_strcmp(value[0].data, "proxy") == 0) {
[641] 
[642]         if (ngx_http_geo_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
[643]             goto failed;
[644]         }
[645] 
[646]         rv = ngx_http_geo_add_proxy(cf, ctx, &cidr);
[647] 
[648]         goto done;
[649]     }
[650] 
[651]     if (ctx->ranges) {
[652]         rv = ngx_http_geo_range(cf, ctx, value);
[653] 
[654]     } else {
[655]         rv = ngx_http_geo_cidr(cf, ctx, value);
[656]     }
[657] 
[658] done:
[659] 
[660]     ngx_reset_pool(cf->pool);
[661] 
[662]     return rv;
[663] 
[664] failed:
[665] 
[666]     ngx_reset_pool(cf->pool);
[667] 
[668]     return NGX_CONF_ERROR;
[669] }
[670] 
[671] 
[672] static char *
[673] ngx_http_geo_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[674]     ngx_str_t *value)
[675] {
[676]     u_char      *p, *last;
[677]     in_addr_t    start, end;
[678]     ngx_str_t   *net;
[679]     ngx_uint_t   del;
[680] 
[681]     if (ngx_strcmp(value[0].data, "default") == 0) {
[682] 
[683]         if (ctx->high.default_value) {
[684]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[685]                 "duplicate default geo range value: \"%V\", old value: \"%v\"",
[686]                 &value[1], ctx->high.default_value);
[687]         }
[688] 
[689]         ctx->high.default_value = ngx_http_geo_value(cf, ctx, &value[1]);
[690]         if (ctx->high.default_value == NULL) {
[691]             return NGX_CONF_ERROR;
[692]         }
[693] 
[694]         return NGX_CONF_OK;
[695]     }
[696] 
[697]     if (ctx->binary_include) {
[698]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[699]             "binary geo range base \"%s\" cannot be mixed with usual entries",
[700]             ctx->include_name.data);
[701]         return NGX_CONF_ERROR;
[702]     }
[703] 
[704]     if (ctx->high.low == NULL) {
[705]         ctx->high.low = ngx_pcalloc(ctx->pool,
[706]                                     0x10000 * sizeof(ngx_http_geo_range_t *));
[707]         if (ctx->high.low == NULL) {
[708]             return NGX_CONF_ERROR;
[709]         }
[710]     }
[711] 
[712]     ctx->entries++;
[713]     ctx->outside_entries = 1;
[714] 
[715]     if (ngx_strcmp(value[0].data, "delete") == 0) {
[716]         net = &value[1];
[717]         del = 1;
[718] 
[719]     } else {
[720]         net = &value[0];
[721]         del = 0;
[722]     }
[723] 
[724]     last = net->data + net->len;
[725] 
[726]     p = ngx_strlchr(net->data, last, '-');
[727] 
[728]     if (p == NULL) {
[729]         goto invalid;
[730]     }
[731] 
[732]     start = ngx_inet_addr(net->data, p - net->data);
[733] 
[734]     if (start == INADDR_NONE) {
[735]         goto invalid;
[736]     }
[737] 
[738]     start = ntohl(start);
[739] 
[740]     p++;
[741] 
[742]     end = ngx_inet_addr(p, last - p);
[743] 
[744]     if (end == INADDR_NONE) {
[745]         goto invalid;
[746]     }
[747] 
[748]     end = ntohl(end);
[749] 
[750]     if (start > end) {
[751]         goto invalid;
[752]     }
[753] 
[754]     if (del) {
[755]         if (ngx_http_geo_delete_range(cf, ctx, start, end)) {
[756]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[757]                                "no address range \"%V\" to delete", net);
[758]         }
[759] 
[760]         return NGX_CONF_OK;
[761]     }
[762] 
[763]     ctx->value = ngx_http_geo_value(cf, ctx, &value[1]);
[764] 
[765]     if (ctx->value == NULL) {
[766]         return NGX_CONF_ERROR;
[767]     }
[768] 
[769]     ctx->net = net;
[770] 
[771]     return ngx_http_geo_add_range(cf, ctx, start, end);
[772] 
[773] invalid:
[774] 
[775]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);
[776] 
[777]     return NGX_CONF_ERROR;
[778] }
[779] 
[780] 
[781] /* the add procedure is optimized to add a growing up sequence */
[782] 
[783] static char *
[784] ngx_http_geo_add_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[785]     in_addr_t start, in_addr_t end)
[786] {
[787]     in_addr_t              n;
[788]     ngx_uint_t             h, i, s, e;
[789]     ngx_array_t           *a;
[790]     ngx_http_geo_range_t  *range;
[791] 
[792]     for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {
[793] 
[794]         h = n >> 16;
[795] 
[796]         if (n == start) {
[797]             s = n & 0xffff;
[798]         } else {
[799]             s = 0;
[800]         }
[801] 
[802]         if ((n | 0xffff) > end) {
[803]             e = end & 0xffff;
[804] 
[805]         } else {
[806]             e = 0xffff;
[807]         }
[808] 
[809]         a = (ngx_array_t *) ctx->high.low[h];
[810] 
[811]         if (a == NULL) {
[812]             a = ngx_array_create(ctx->temp_pool, 64,
[813]                                  sizeof(ngx_http_geo_range_t));
[814]             if (a == NULL) {
[815]                 return NGX_CONF_ERROR;
[816]             }
[817] 
[818]             ctx->high.low[h] = (ngx_http_geo_range_t *) a;
[819]         }
[820] 
[821]         i = a->nelts;
[822]         range = a->elts;
[823] 
[824]         while (i) {
[825] 
[826]             i--;
[827] 
[828]             if (e < (ngx_uint_t) range[i].start) {
[829]                 continue;
[830]             }
[831] 
[832]             if (s > (ngx_uint_t) range[i].end) {
[833] 
[834]                 /* add after the range */
[835] 
[836]                 range = ngx_array_push(a);
[837]                 if (range == NULL) {
[838]                     return NGX_CONF_ERROR;
[839]                 }
[840] 
[841]                 range = a->elts;
[842] 
[843]                 ngx_memmove(&range[i + 2], &range[i + 1],
[844]                             (a->nelts - 2 - i) * sizeof(ngx_http_geo_range_t));
[845] 
[846]                 range[i + 1].start = (u_short) s;
[847]                 range[i + 1].end = (u_short) e;
[848]                 range[i + 1].value = ctx->value;
[849] 
[850]                 goto next;
[851]             }
[852] 
[853]             if (s == (ngx_uint_t) range[i].start
[854]                 && e == (ngx_uint_t) range[i].end)
[855]             {
[856]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[857]                     "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
[858]                     ctx->net, ctx->value, range[i].value);
[859] 
[860]                 range[i].value = ctx->value;
[861] 
[862]                 goto next;
[863]             }
[864] 
[865]             if (s > (ngx_uint_t) range[i].start
[866]                 && e < (ngx_uint_t) range[i].end)
[867]             {
[868]                 /* split the range and insert the new one */
[869] 
[870]                 range = ngx_array_push(a);
[871]                 if (range == NULL) {
[872]                     return NGX_CONF_ERROR;
[873]                 }
[874] 
[875]                 range = ngx_array_push(a);
[876]                 if (range == NULL) {
[877]                     return NGX_CONF_ERROR;
[878]                 }
[879] 
[880]                 range = a->elts;
[881] 
[882]                 ngx_memmove(&range[i + 3], &range[i + 1],
[883]                             (a->nelts - 3 - i) * sizeof(ngx_http_geo_range_t));
[884] 
[885]                 range[i + 2].start = (u_short) (e + 1);
[886]                 range[i + 2].end = range[i].end;
[887]                 range[i + 2].value = range[i].value;
[888] 
[889]                 range[i + 1].start = (u_short) s;
[890]                 range[i + 1].end = (u_short) e;
[891]                 range[i + 1].value = ctx->value;
[892] 
[893]                 range[i].end = (u_short) (s - 1);
[894] 
[895]                 goto next;
[896]             }
[897] 
[898]             if (s == (ngx_uint_t) range[i].start
[899]                 && e < (ngx_uint_t) range[i].end)
[900]             {
[901]                 /* shift the range start and insert the new range */
[902] 
[903]                 range = ngx_array_push(a);
[904]                 if (range == NULL) {
[905]                     return NGX_CONF_ERROR;
[906]                 }
[907] 
[908]                 range = a->elts;
[909] 
[910]                 ngx_memmove(&range[i + 1], &range[i],
[911]                             (a->nelts - 1 - i) * sizeof(ngx_http_geo_range_t));
[912] 
[913]                 range[i + 1].start = (u_short) (e + 1);
[914] 
[915]                 range[i].start = (u_short) s;
[916]                 range[i].end = (u_short) e;
[917]                 range[i].value = ctx->value;
[918] 
[919]                 goto next;
[920]             }
[921] 
[922]             if (s > (ngx_uint_t) range[i].start
[923]                 && e == (ngx_uint_t) range[i].end)
[924]             {
[925]                 /* shift the range end and insert the new range */
[926] 
[927]                 range = ngx_array_push(a);
[928]                 if (range == NULL) {
[929]                     return NGX_CONF_ERROR;
[930]                 }
[931] 
[932]                 range = a->elts;
[933] 
[934]                 ngx_memmove(&range[i + 2], &range[i + 1],
[935]                             (a->nelts - 2 - i) * sizeof(ngx_http_geo_range_t));
[936] 
[937]                 range[i + 1].start = (u_short) s;
[938]                 range[i + 1].end = (u_short) e;
[939]                 range[i + 1].value = ctx->value;
[940] 
[941]                 range[i].end = (u_short) (s - 1);
[942] 
[943]                 goto next;
[944]             }
[945] 
[946]             s = (ngx_uint_t) range[i].start;
[947]             e = (ngx_uint_t) range[i].end;
[948] 
[949]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[950]                          "range \"%V\" overlaps \"%d.%d.%d.%d-%d.%d.%d.%d\"",
[951]                          ctx->net,
[952]                          h >> 8, h & 0xff, s >> 8, s & 0xff,
[953]                          h >> 8, h & 0xff, e >> 8, e & 0xff);
[954] 
[955]             return NGX_CONF_ERROR;
[956]         }
[957] 
[958]         /* add the first range */
[959] 
[960]         range = ngx_array_push(a);
[961]         if (range == NULL) {
[962]             return NGX_CONF_ERROR;
[963]         }
[964] 
[965]         range = a->elts;
[966] 
[967]         ngx_memmove(&range[1], &range[0],
[968]                     (a->nelts - 1) * sizeof(ngx_http_geo_range_t));
[969] 
[970]         range[0].start = (u_short) s;
[971]         range[0].end = (u_short) e;
[972]         range[0].value = ctx->value;
[973] 
[974]     next:
[975] 
[976]         if (h == 0xffff) {
[977]             break;
[978]         }
[979]     }
[980] 
[981]     return NGX_CONF_OK;
[982] }
[983] 
[984] 
[985] static ngx_uint_t
[986] ngx_http_geo_delete_range(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[987]     in_addr_t start, in_addr_t end)
[988] {
[989]     in_addr_t              n;
[990]     ngx_uint_t             h, i, s, e, warn;
[991]     ngx_array_t           *a;
[992]     ngx_http_geo_range_t  *range;
[993] 
[994]     warn = 0;
[995] 
[996]     for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {
[997] 
[998]         h = n >> 16;
[999] 
[1000]         if (n == start) {
[1001]             s = n & 0xffff;
[1002]         } else {
[1003]             s = 0;
[1004]         }
[1005] 
[1006]         if ((n | 0xffff) > end) {
[1007]             e = end & 0xffff;
[1008] 
[1009]         } else {
[1010]             e = 0xffff;
[1011]         }
[1012] 
[1013]         a = (ngx_array_t *) ctx->high.low[h];
[1014] 
[1015]         if (a == NULL || a->nelts == 0) {
[1016]             warn = 1;
[1017]             goto next;
[1018]         }
[1019] 
[1020]         range = a->elts;
[1021]         for (i = 0; i < a->nelts; i++) {
[1022] 
[1023]             if (s == (ngx_uint_t) range[i].start
[1024]                 && e == (ngx_uint_t) range[i].end)
[1025]             {
[1026]                 ngx_memmove(&range[i], &range[i + 1],
[1027]                             (a->nelts - 1 - i) * sizeof(ngx_http_geo_range_t));
[1028] 
[1029]                 a->nelts--;
[1030] 
[1031]                 break;
[1032]             }
[1033] 
[1034]             if (i == a->nelts - 1) {
[1035]                 warn = 1;
[1036]             }
[1037]         }
[1038] 
[1039]     next:
[1040] 
[1041]         if (h == 0xffff) {
[1042]             break;
[1043]         }
[1044]     }
[1045] 
[1046]     return warn;
[1047] }
[1048] 
[1049] 
[1050] static char *
[1051] ngx_http_geo_cidr(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[1052]     ngx_str_t *value)
[1053] {
[1054]     char        *rv;
[1055]     ngx_int_t    rc, del;
[1056]     ngx_str_t   *net;
[1057]     ngx_cidr_t   cidr;
[1058] 
[1059]     if (ctx->tree == NULL) {
[1060]         ctx->tree = ngx_radix_tree_create(ctx->pool, -1);
[1061]         if (ctx->tree == NULL) {
[1062]             return NGX_CONF_ERROR;
[1063]         }
[1064]     }
[1065] 
[1066] #if (NGX_HAVE_INET6)
[1067]     if (ctx->tree6 == NULL) {
[1068]         ctx->tree6 = ngx_radix_tree_create(ctx->pool, -1);
[1069]         if (ctx->tree6 == NULL) {
[1070]             return NGX_CONF_ERROR;
[1071]         }
[1072]     }
[1073] #endif
[1074] 
[1075]     if (ngx_strcmp(value[0].data, "default") == 0) {
[1076]         cidr.family = AF_INET;
[1077]         cidr.u.in.addr = 0;
[1078]         cidr.u.in.mask = 0;
[1079] 
[1080]         rv = ngx_http_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);
[1081] 
[1082]         if (rv != NGX_CONF_OK) {
[1083]             return rv;
[1084]         }
[1085] 
[1086] #if (NGX_HAVE_INET6)
[1087]         cidr.family = AF_INET6;
[1088]         ngx_memzero(&cidr.u.in6, sizeof(ngx_in6_cidr_t));
[1089] 
[1090]         rv = ngx_http_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);
[1091] 
[1092]         if (rv != NGX_CONF_OK) {
[1093]             return rv;
[1094]         }
[1095] #endif
[1096] 
[1097]         return NGX_CONF_OK;
[1098]     }
[1099] 
[1100]     if (ngx_strcmp(value[0].data, "delete") == 0) {
[1101]         net = &value[1];
[1102]         del = 1;
[1103] 
[1104]     } else {
[1105]         net = &value[0];
[1106]         del = 0;
[1107]     }
[1108] 
[1109]     if (ngx_http_geo_cidr_value(cf, net, &cidr) != NGX_OK) {
[1110]         return NGX_CONF_ERROR;
[1111]     }
[1112] 
[1113]     if (cidr.family == AF_INET) {
[1114]         cidr.u.in.addr = ntohl(cidr.u.in.addr);
[1115]         cidr.u.in.mask = ntohl(cidr.u.in.mask);
[1116]     }
[1117] 
[1118]     if (del) {
[1119]         switch (cidr.family) {
[1120] 
[1121] #if (NGX_HAVE_INET6)
[1122]         case AF_INET6:
[1123]             rc = ngx_radix128tree_delete(ctx->tree6,
[1124]                                          cidr.u.in6.addr.s6_addr,
[1125]                                          cidr.u.in6.mask.s6_addr);
[1126]             break;
[1127] #endif
[1128] 
[1129]         default: /* AF_INET */
[1130]             rc = ngx_radix32tree_delete(ctx->tree, cidr.u.in.addr,
[1131]                                         cidr.u.in.mask);
[1132]             break;
[1133]         }
[1134] 
[1135]         if (rc != NGX_OK) {
[1136]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1137]                                "no network \"%V\" to delete", net);
[1138]         }
[1139] 
[1140]         return NGX_CONF_OK;
[1141]     }
[1142] 
[1143]     return ngx_http_geo_cidr_add(cf, ctx, &cidr, &value[1], net);
[1144] }
[1145] 
[1146] 
[1147] static char *
[1148] ngx_http_geo_cidr_add(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[1149]     ngx_cidr_t *cidr, ngx_str_t *value, ngx_str_t *net)
[1150] {
[1151]     ngx_int_t                   rc;
[1152]     ngx_http_variable_value_t  *val, *old;
[1153] 
[1154]     val = ngx_http_geo_value(cf, ctx, value);
[1155] 
[1156]     if (val == NULL) {
[1157]         return NGX_CONF_ERROR;
[1158]     }
[1159] 
[1160]     switch (cidr->family) {
[1161] 
[1162] #if (NGX_HAVE_INET6)
[1163]     case AF_INET6:
[1164]         rc = ngx_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
[1165]                                      cidr->u.in6.mask.s6_addr,
[1166]                                      (uintptr_t) val);
[1167] 
[1168]         if (rc == NGX_OK) {
[1169]             return NGX_CONF_OK;
[1170]         }
[1171] 
[1172]         if (rc == NGX_ERROR) {
[1173]             return NGX_CONF_ERROR;
[1174]         }
[1175] 
[1176]         /* rc == NGX_BUSY */
[1177] 
[1178]         old = (ngx_http_variable_value_t *)
[1179]                    ngx_radix128tree_find(ctx->tree6,
[1180]                                          cidr->u.in6.addr.s6_addr);
[1181] 
[1182]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1183]               "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
[1184]               net, val, old);
[1185] 
[1186]         rc = ngx_radix128tree_delete(ctx->tree6,
[1187]                                      cidr->u.in6.addr.s6_addr,
[1188]                                      cidr->u.in6.mask.s6_addr);
[1189] 
[1190]         if (rc == NGX_ERROR) {
[1191]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid radix tree");
[1192]             return NGX_CONF_ERROR;
[1193]         }
[1194] 
[1195]         rc = ngx_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
[1196]                                      cidr->u.in6.mask.s6_addr,
[1197]                                      (uintptr_t) val);
[1198] 
[1199]         break;
[1200] #endif
[1201] 
[1202]     default: /* AF_INET */
[1203]         rc = ngx_radix32tree_insert(ctx->tree, cidr->u.in.addr,
[1204]                                     cidr->u.in.mask, (uintptr_t) val);
[1205] 
[1206]         if (rc == NGX_OK) {
[1207]             return NGX_CONF_OK;
[1208]         }
[1209] 
[1210]         if (rc == NGX_ERROR) {
[1211]             return NGX_CONF_ERROR;
[1212]         }
[1213] 
[1214]         /* rc == NGX_BUSY */
[1215] 
[1216]         old = (ngx_http_variable_value_t *)
[1217]                    ngx_radix32tree_find(ctx->tree, cidr->u.in.addr);
[1218] 
[1219]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1220]               "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
[1221]               net, val, old);
[1222] 
[1223]         rc = ngx_radix32tree_delete(ctx->tree,
[1224]                                     cidr->u.in.addr, cidr->u.in.mask);
[1225] 
[1226]         if (rc == NGX_ERROR) {
[1227]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid radix tree");
[1228]             return NGX_CONF_ERROR;
[1229]         }
[1230] 
[1231]         rc = ngx_radix32tree_insert(ctx->tree, cidr->u.in.addr,
[1232]                                     cidr->u.in.mask, (uintptr_t) val);
[1233] 
[1234]         break;
[1235]     }
[1236] 
[1237]     if (rc == NGX_OK) {
[1238]         return NGX_CONF_OK;
[1239]     }
[1240] 
[1241]     return NGX_CONF_ERROR;
[1242] }
[1243] 
[1244] 
[1245] static ngx_http_variable_value_t *
[1246] ngx_http_geo_value(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[1247]     ngx_str_t *value)
[1248] {
[1249]     uint32_t                             hash;
[1250]     ngx_http_variable_value_t           *val;
[1251]     ngx_http_geo_variable_value_node_t  *gvvn;
[1252] 
[1253]     hash = ngx_crc32_long(value->data, value->len);
[1254] 
[1255]     gvvn = (ngx_http_geo_variable_value_node_t *)
[1256]                ngx_str_rbtree_lookup(&ctx->rbtree, value, hash);
[1257] 
[1258]     if (gvvn) {
[1259]         return gvvn->value;
[1260]     }
[1261] 
[1262]     val = ngx_palloc(ctx->pool, sizeof(ngx_http_variable_value_t));
[1263]     if (val == NULL) {
[1264]         return NULL;
[1265]     }
[1266] 
[1267]     val->len = value->len;
[1268]     val->data = ngx_pstrdup(ctx->pool, value);
[1269]     if (val->data == NULL) {
[1270]         return NULL;
[1271]     }
[1272] 
[1273]     val->valid = 1;
[1274]     val->no_cacheable = 0;
[1275]     val->not_found = 0;
[1276] 
[1277]     gvvn = ngx_palloc(ctx->temp_pool,
[1278]                       sizeof(ngx_http_geo_variable_value_node_t));
[1279]     if (gvvn == NULL) {
[1280]         return NULL;
[1281]     }
[1282] 
[1283]     gvvn->sn.node.key = hash;
[1284]     gvvn->sn.str.len = val->len;
[1285]     gvvn->sn.str.data = val->data;
[1286]     gvvn->value = val;
[1287]     gvvn->offset = 0;
[1288] 
[1289]     ngx_rbtree_insert(&ctx->rbtree, &gvvn->sn.node);
[1290] 
[1291]     ctx->data_size += ngx_align(sizeof(ngx_http_variable_value_t) + value->len,
[1292]                                 sizeof(void *));
[1293] 
[1294]     return val;
[1295] }
[1296] 
[1297] 
[1298] static char *
[1299] ngx_http_geo_add_proxy(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[1300]     ngx_cidr_t *cidr)
[1301] {
[1302]     ngx_cidr_t  *c;
[1303] 
[1304]     if (ctx->proxies == NULL) {
[1305]         ctx->proxies = ngx_array_create(ctx->pool, 4, sizeof(ngx_cidr_t));
[1306]         if (ctx->proxies == NULL) {
[1307]             return NGX_CONF_ERROR;
[1308]         }
[1309]     }
[1310] 
[1311]     c = ngx_array_push(ctx->proxies);
[1312]     if (c == NULL) {
[1313]         return NGX_CONF_ERROR;
[1314]     }
[1315] 
[1316]     *c = *cidr;
[1317] 
[1318]     return NGX_CONF_OK;
[1319] }
[1320] 
[1321] 
[1322] static ngx_int_t
[1323] ngx_http_geo_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
[1324] {
[1325]     ngx_int_t  rc;
[1326] 
[1327]     if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
[1328]         cidr->family = AF_INET;
[1329]         cidr->u.in.addr = 0xffffffff;
[1330]         cidr->u.in.mask = 0xffffffff;
[1331] 
[1332]         return NGX_OK;
[1333]     }
[1334] 
[1335]     rc = ngx_ptocidr(net, cidr);
[1336] 
[1337]     if (rc == NGX_ERROR) {
[1338]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
[1339]         return NGX_ERROR;
[1340]     }
[1341] 
[1342]     if (rc == NGX_DONE) {
[1343]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1344]                            "low address bits of %V are meaningless", net);
[1345]     }
[1346] 
[1347]     return NGX_OK;
[1348] }
[1349] 
[1350] 
[1351] static char *
[1352] ngx_http_geo_include(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[1353]     ngx_str_t *name)
[1354] {
[1355]     char       *rv;
[1356]     ngx_str_t   file;
[1357] 
[1358]     file.len = name->len + 4;
[1359]     file.data = ngx_pnalloc(ctx->temp_pool, name->len + 5);
[1360]     if (file.data == NULL) {
[1361]         return NGX_CONF_ERROR;
[1362]     }
[1363] 
[1364]     ngx_sprintf(file.data, "%V.bin%Z", name);
[1365] 
[1366]     if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
[1367]         return NGX_CONF_ERROR;
[1368]     }
[1369] 
[1370]     if (ctx->ranges) {
[1371]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[1372] 
[1373]         switch (ngx_http_geo_include_binary_base(cf, ctx, &file)) {
[1374]         case NGX_OK:
[1375]             return NGX_CONF_OK;
[1376]         case NGX_ERROR:
[1377]             return NGX_CONF_ERROR;
[1378]         default:
[1379]             break;
[1380]         }
[1381]     }
[1382] 
[1383]     file.len -= 4;
[1384]     file.data[file.len] = '\0';
[1385] 
[1386]     ctx->include_name = file;
[1387] 
[1388]     if (ctx->outside_entries) {
[1389]         ctx->allow_binary_include = 0;
[1390]     }
[1391] 
[1392]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[1393] 
[1394]     rv = ngx_conf_parse(cf, &file);
[1395] 
[1396]     ctx->includes++;
[1397]     ctx->outside_entries = 0;
[1398] 
[1399]     return rv;
[1400] }
[1401] 
[1402] 
[1403] static ngx_int_t
[1404] ngx_http_geo_include_binary_base(ngx_conf_t *cf, ngx_http_geo_conf_ctx_t *ctx,
[1405]     ngx_str_t *name)
[1406] {
[1407]     u_char                     *base, ch;
[1408]     time_t                      mtime;
[1409]     size_t                      size, len;
[1410]     ssize_t                     n;
[1411]     uint32_t                    crc32;
[1412]     ngx_err_t                   err;
[1413]     ngx_int_t                   rc;
[1414]     ngx_uint_t                  i;
[1415]     ngx_file_t                  file;
[1416]     ngx_file_info_t             fi;
[1417]     ngx_http_geo_range_t       *range, **ranges;
[1418]     ngx_http_geo_header_t      *header;
[1419]     ngx_http_variable_value_t  *vv;
[1420] 
[1421]     ngx_memzero(&file, sizeof(ngx_file_t));
[1422]     file.name = *name;
[1423]     file.log = cf->log;
[1424] 
[1425]     file.fd = ngx_open_file(name->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
[1426] 
[1427]     if (file.fd == NGX_INVALID_FILE) {
[1428]         err = ngx_errno;
[1429]         if (err != NGX_ENOENT) {
[1430]             ngx_conf_log_error(NGX_LOG_CRIT, cf, err,
[1431]                                ngx_open_file_n " \"%s\" failed", name->data);
[1432]         }
[1433]         return NGX_DECLINED;
[1434]     }
[1435] 
[1436]     if (ctx->outside_entries) {
[1437]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1438]             "binary geo range base \"%s\" cannot be mixed with usual entries",
[1439]             name->data);
[1440]         rc = NGX_ERROR;
[1441]         goto done;
[1442]     }
[1443] 
[1444]     if (ctx->binary_include) {
[1445]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1446]             "second binary geo range base \"%s\" cannot be mixed with \"%s\"",
[1447]             name->data, ctx->include_name.data);
[1448]         rc = NGX_ERROR;
[1449]         goto done;
[1450]     }
[1451] 
[1452]     if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
[1453]         ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[1454]                            ngx_fd_info_n " \"%s\" failed", name->data);
[1455]         goto failed;
[1456]     }
[1457] 
[1458]     size = (size_t) ngx_file_size(&fi);
[1459]     mtime = ngx_file_mtime(&fi);
[1460] 
[1461]     ch = name->data[name->len - 4];
[1462]     name->data[name->len - 4] = '\0';
[1463] 
[1464]     if (ngx_file_info(name->data, &fi) == NGX_FILE_ERROR) {
[1465]         ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[1466]                            ngx_file_info_n " \"%s\" failed", name->data);
[1467]         goto failed;
[1468]     }
[1469] 
[1470]     name->data[name->len - 4] = ch;
[1471] 
[1472]     if (mtime < ngx_file_mtime(&fi)) {
[1473]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1474]                            "stale binary geo range base \"%s\"", name->data);
[1475]         goto failed;
[1476]     }
[1477] 
[1478]     base = ngx_palloc(ctx->pool, size);
[1479]     if (base == NULL) {
[1480]         goto failed;
[1481]     }
[1482] 
[1483]     n = ngx_read_file(&file, base, size, 0);
[1484] 
[1485]     if (n == NGX_ERROR) {
[1486]         ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[1487]                            ngx_read_file_n " \"%s\" failed", name->data);
[1488]         goto failed;
[1489]     }
[1490] 
[1491]     if ((size_t) n != size) {
[1492]         ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
[1493]             ngx_read_file_n " \"%s\" returned only %z bytes instead of %z",
[1494]             name->data, n, size);
[1495]         goto failed;
[1496]     }
[1497] 
[1498]     header = (ngx_http_geo_header_t *) base;
[1499] 
[1500]     if (size < 16 || ngx_memcmp(&ngx_http_geo_header, header, 12) != 0) {
[1501]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1502]              "incompatible binary geo range base \"%s\"", name->data);
[1503]         goto failed;
[1504]     }
[1505] 
[1506]     ngx_crc32_init(crc32);
[1507] 
[1508]     vv = (ngx_http_variable_value_t *) (base + sizeof(ngx_http_geo_header_t));
[1509] 
[1510]     while (vv->data) {
[1511]         len = ngx_align(sizeof(ngx_http_variable_value_t) + vv->len,
[1512]                         sizeof(void *));
[1513]         ngx_crc32_update(&crc32, (u_char *) vv, len);
[1514]         vv->data += (size_t) base;
[1515]         vv = (ngx_http_variable_value_t *) ((u_char *) vv + len);
[1516]     }
[1517]     ngx_crc32_update(&crc32, (u_char *) vv, sizeof(ngx_http_variable_value_t));
[1518]     vv++;
[1519] 
[1520]     ranges = (ngx_http_geo_range_t **) vv;
[1521] 
[1522]     for (i = 0; i < 0x10000; i++) {
[1523]         ngx_crc32_update(&crc32, (u_char *) &ranges[i], sizeof(void *));
[1524]         if (ranges[i]) {
[1525]             ranges[i] = (ngx_http_geo_range_t *)
[1526]                             ((u_char *) ranges[i] + (size_t) base);
[1527]         }
[1528]     }
[1529] 
[1530]     range = (ngx_http_geo_range_t *) &ranges[0x10000];
[1531] 
[1532]     while ((u_char *) range < base + size) {
[1533]         while (range->value) {
[1534]             ngx_crc32_update(&crc32, (u_char *) range,
[1535]                              sizeof(ngx_http_geo_range_t));
[1536]             range->value = (ngx_http_variable_value_t *)
[1537]                                ((u_char *) range->value + (size_t) base);
[1538]             range++;
[1539]         }
[1540]         ngx_crc32_update(&crc32, (u_char *) range, sizeof(void *));
[1541]         range = (ngx_http_geo_range_t *) ((u_char *) range + sizeof(void *));
[1542]     }
[1543] 
[1544]     ngx_crc32_final(crc32);
[1545] 
[1546]     if (crc32 != header->crc32) {
[1547]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1548]                   "CRC32 mismatch in binary geo range base \"%s\"", name->data);
[1549]         goto failed;
[1550]     }
[1551] 
[1552]     ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
[1553]                        "using binary geo range base \"%s\"", name->data);
[1554] 
[1555]     ctx->include_name = *name;
[1556]     ctx->binary_include = 1;
[1557]     ctx->high.low = ranges;
[1558]     rc = NGX_OK;
[1559] 
[1560]     goto done;
[1561] 
[1562] failed:
[1563] 
[1564]     rc = NGX_DECLINED;
[1565] 
[1566] done:
[1567] 
[1568]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[1569]         ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[1570]                       ngx_close_file_n " \"%s\" failed", name->data);
[1571]     }
[1572] 
[1573]     return rc;
[1574] }
[1575] 
[1576] 
[1577] static void
[1578] ngx_http_geo_create_binary_base(ngx_http_geo_conf_ctx_t *ctx)
[1579] {
[1580]     u_char                              *p;
[1581]     uint32_t                             hash;
[1582]     ngx_str_t                            s;
[1583]     ngx_uint_t                           i;
[1584]     ngx_file_mapping_t                   fm;
[1585]     ngx_http_geo_range_t                *r, *range, **ranges;
[1586]     ngx_http_geo_header_t               *header;
[1587]     ngx_http_geo_variable_value_node_t  *gvvn;
[1588] 
[1589]     fm.name = ngx_pnalloc(ctx->temp_pool, ctx->include_name.len + 5);
[1590]     if (fm.name == NULL) {
[1591]         return;
[1592]     }
[1593] 
[1594]     ngx_sprintf(fm.name, "%V.bin%Z", &ctx->include_name);
[1595] 
[1596]     fm.size = ctx->data_size;
[1597]     fm.log = ctx->pool->log;
[1598] 
[1599]     ngx_log_error(NGX_LOG_NOTICE, fm.log, 0,
[1600]                   "creating binary geo range base \"%s\"", fm.name);
[1601] 
[1602]     if (ngx_create_file_mapping(&fm) != NGX_OK) {
[1603]         return;
[1604]     }
[1605] 
[1606]     p = ngx_cpymem(fm.addr, &ngx_http_geo_header,
[1607]                    sizeof(ngx_http_geo_header_t));
[1608] 
[1609]     p = ngx_http_geo_copy_values(fm.addr, p, ctx->rbtree.root,
[1610]                                  ctx->rbtree.sentinel);
[1611] 
[1612]     p += sizeof(ngx_http_variable_value_t);
[1613] 
[1614]     ranges = (ngx_http_geo_range_t **) p;
[1615] 
[1616]     p += 0x10000 * sizeof(ngx_http_geo_range_t *);
[1617] 
[1618]     for (i = 0; i < 0x10000; i++) {
[1619]         r = ctx->high.low[i];
[1620]         if (r == NULL) {
[1621]             continue;
[1622]         }
[1623] 
[1624]         range = (ngx_http_geo_range_t *) p;
[1625]         ranges[i] = (ngx_http_geo_range_t *) (p - (u_char *) fm.addr);
[1626] 
[1627]         do {
[1628]             s.len = r->value->len;
[1629]             s.data = r->value->data;
[1630]             hash = ngx_crc32_long(s.data, s.len);
[1631]             gvvn = (ngx_http_geo_variable_value_node_t *)
[1632]                         ngx_str_rbtree_lookup(&ctx->rbtree, &s, hash);
[1633] 
[1634]             range->value = (ngx_http_variable_value_t *) gvvn->offset;
[1635]             range->start = r->start;
[1636]             range->end = r->end;
[1637]             range++;
[1638] 
[1639]         } while ((++r)->value);
[1640] 
[1641]         range->value = NULL;
[1642] 
[1643]         p = (u_char *) range + sizeof(void *);
[1644]     }
[1645] 
[1646]     header = fm.addr;
[1647]     header->crc32 = ngx_crc32_long((u_char *) fm.addr
[1648]                                        + sizeof(ngx_http_geo_header_t),
[1649]                                    fm.size - sizeof(ngx_http_geo_header_t));
[1650] 
[1651]     ngx_close_file_mapping(&fm);
[1652] }
[1653] 
[1654] 
[1655] static u_char *
[1656] ngx_http_geo_copy_values(u_char *base, u_char *p, ngx_rbtree_node_t *node,
[1657]     ngx_rbtree_node_t *sentinel)
[1658] {
[1659]     ngx_http_variable_value_t           *vv;
[1660]     ngx_http_geo_variable_value_node_t  *gvvn;
[1661] 
[1662]     if (node == sentinel) {
[1663]         return p;
[1664]     }
[1665] 
[1666]     gvvn = (ngx_http_geo_variable_value_node_t *) node;
[1667]     gvvn->offset = p - base;
[1668] 
[1669]     vv = (ngx_http_variable_value_t *) p;
[1670]     *vv = *gvvn->value;
[1671]     p += sizeof(ngx_http_variable_value_t);
[1672]     vv->data = (u_char *) (p - base);
[1673] 
[1674]     p = ngx_cpymem(p, gvvn->sn.str.data, gvvn->sn.str.len);
[1675] 
[1676]     p = ngx_align_ptr(p, sizeof(void *));
[1677] 
[1678]     p = ngx_http_geo_copy_values(base, p, node->left, sentinel);
[1679] 
[1680]     return ngx_http_geo_copy_values(base, p, node->right, sentinel);
[1681] }
