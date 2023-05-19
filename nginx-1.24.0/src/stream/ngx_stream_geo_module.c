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
[14]     ngx_stream_variable_value_t       *value;
[15]     u_short                            start;
[16]     u_short                            end;
[17] } ngx_stream_geo_range_t;
[18] 
[19] 
[20] typedef struct {
[21]     ngx_radix_tree_t                  *tree;
[22] #if (NGX_HAVE_INET6)
[23]     ngx_radix_tree_t                  *tree6;
[24] #endif
[25] } ngx_stream_geo_trees_t;
[26] 
[27] 
[28] typedef struct {
[29]     ngx_stream_geo_range_t           **low;
[30]     ngx_stream_variable_value_t       *default_value;
[31] } ngx_stream_geo_high_ranges_t;
[32] 
[33] 
[34] typedef struct {
[35]     ngx_str_node_t                     sn;
[36]     ngx_stream_variable_value_t       *value;
[37]     size_t                             offset;
[38] } ngx_stream_geo_variable_value_node_t;
[39] 
[40] 
[41] typedef struct {
[42]     ngx_stream_variable_value_t       *value;
[43]     ngx_str_t                         *net;
[44]     ngx_stream_geo_high_ranges_t       high;
[45]     ngx_radix_tree_t                  *tree;
[46] #if (NGX_HAVE_INET6)
[47]     ngx_radix_tree_t                  *tree6;
[48] #endif
[49]     ngx_rbtree_t                       rbtree;
[50]     ngx_rbtree_node_t                  sentinel;
[51]     ngx_pool_t                        *pool;
[52]     ngx_pool_t                        *temp_pool;
[53] 
[54]     size_t                             data_size;
[55] 
[56]     ngx_str_t                          include_name;
[57]     ngx_uint_t                         includes;
[58]     ngx_uint_t                         entries;
[59] 
[60]     unsigned                           ranges:1;
[61]     unsigned                           outside_entries:1;
[62]     unsigned                           allow_binary_include:1;
[63]     unsigned                           binary_include:1;
[64] } ngx_stream_geo_conf_ctx_t;
[65] 
[66] 
[67] typedef struct {
[68]     union {
[69]         ngx_stream_geo_trees_t         trees;
[70]         ngx_stream_geo_high_ranges_t   high;
[71]     } u;
[72] 
[73]     ngx_int_t                          index;
[74] } ngx_stream_geo_ctx_t;
[75] 
[76] 
[77] static ngx_int_t ngx_stream_geo_addr(ngx_stream_session_t *s,
[78]     ngx_stream_geo_ctx_t *ctx, ngx_addr_t *addr);
[79] 
[80] static char *ngx_stream_geo_block(ngx_conf_t *cf, ngx_command_t *cmd,
[81]     void *conf);
[82] static char *ngx_stream_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
[83] static char *ngx_stream_geo_range(ngx_conf_t *cf,
[84]     ngx_stream_geo_conf_ctx_t *ctx, ngx_str_t *value);
[85] static char *ngx_stream_geo_add_range(ngx_conf_t *cf,
[86]     ngx_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
[87] static ngx_uint_t ngx_stream_geo_delete_range(ngx_conf_t *cf,
[88]     ngx_stream_geo_conf_ctx_t *ctx, in_addr_t start, in_addr_t end);
[89] static char *ngx_stream_geo_cidr(ngx_conf_t *cf,
[90]     ngx_stream_geo_conf_ctx_t *ctx, ngx_str_t *value);
[91] static char *ngx_stream_geo_cidr_add(ngx_conf_t *cf,
[92]     ngx_stream_geo_conf_ctx_t *ctx, ngx_cidr_t *cidr, ngx_str_t *value,
[93]     ngx_str_t *net);
[94] static ngx_stream_variable_value_t *ngx_stream_geo_value(ngx_conf_t *cf,
[95]     ngx_stream_geo_conf_ctx_t *ctx, ngx_str_t *value);
[96] static ngx_int_t ngx_stream_geo_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
[97]     ngx_cidr_t *cidr);
[98] static char *ngx_stream_geo_include(ngx_conf_t *cf,
[99]     ngx_stream_geo_conf_ctx_t *ctx, ngx_str_t *name);
[100] static ngx_int_t ngx_stream_geo_include_binary_base(ngx_conf_t *cf,
[101]     ngx_stream_geo_conf_ctx_t *ctx, ngx_str_t *name);
[102] static void ngx_stream_geo_create_binary_base(ngx_stream_geo_conf_ctx_t *ctx);
[103] static u_char *ngx_stream_geo_copy_values(u_char *base, u_char *p,
[104]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[105] 
[106] 
[107] static ngx_command_t  ngx_stream_geo_commands[] = {
[108] 
[109]     { ngx_string("geo"),
[110]       NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
[111]       ngx_stream_geo_block,
[112]       0,
[113]       0,
[114]       NULL },
[115] 
[116]       ngx_null_command
[117] };
[118] 
[119] 
[120] static ngx_stream_module_t  ngx_stream_geo_module_ctx = {
[121]     NULL,                                  /* preconfiguration */
[122]     NULL,                                  /* postconfiguration */
[123] 
[124]     NULL,                                  /* create main configuration */
[125]     NULL,                                  /* init main configuration */
[126] 
[127]     NULL,                                  /* create server configuration */
[128]     NULL                                   /* merge server configuration */
[129] };
[130] 
[131] 
[132] ngx_module_t  ngx_stream_geo_module = {
[133]     NGX_MODULE_V1,
[134]     &ngx_stream_geo_module_ctx,            /* module context */
[135]     ngx_stream_geo_commands,               /* module directives */
[136]     NGX_STREAM_MODULE,                     /* module type */
[137]     NULL,                                  /* init master */
[138]     NULL,                                  /* init module */
[139]     NULL,                                  /* init process */
[140]     NULL,                                  /* init thread */
[141]     NULL,                                  /* exit thread */
[142]     NULL,                                  /* exit process */
[143]     NULL,                                  /* exit master */
[144]     NGX_MODULE_V1_PADDING
[145] };
[146] 
[147] 
[148] typedef struct {
[149]     u_char    GEORNG[6];
[150]     u_char    version;
[151]     u_char    ptr_size;
[152]     uint32_t  endianness;
[153]     uint32_t  crc32;
[154] } ngx_stream_geo_header_t;
[155] 
[156] 
[157] static ngx_stream_geo_header_t  ngx_stream_geo_header = {
[158]     { 'G', 'E', 'O', 'R', 'N', 'G' }, 0, sizeof(void *), 0x12345678, 0
[159] };
[160] 
[161] 
[162] /* geo range is AF_INET only */
[163] 
[164] static ngx_int_t
[165] ngx_stream_geo_cidr_variable(ngx_stream_session_t *s,
[166]     ngx_stream_variable_value_t *v, uintptr_t data)
[167] {
[168]     ngx_stream_geo_ctx_t *ctx = (ngx_stream_geo_ctx_t *) data;
[169] 
[170]     in_addr_t                     inaddr;
[171]     ngx_addr_t                    addr;
[172]     struct sockaddr_in           *sin;
[173]     ngx_stream_variable_value_t  *vv;
[174] #if (NGX_HAVE_INET6)
[175]     u_char                       *p;
[176]     struct in6_addr              *inaddr6;
[177] #endif
[178] 
[179]     if (ngx_stream_geo_addr(s, ctx, &addr) != NGX_OK) {
[180]         vv = (ngx_stream_variable_value_t *)
[181]                   ngx_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
[182]         goto done;
[183]     }
[184] 
[185]     switch (addr.sockaddr->sa_family) {
[186] 
[187] #if (NGX_HAVE_INET6)
[188]     case AF_INET6:
[189]         inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
[190]         p = inaddr6->s6_addr;
[191] 
[192]         if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[193]             inaddr = p[12] << 24;
[194]             inaddr += p[13] << 16;
[195]             inaddr += p[14] << 8;
[196]             inaddr += p[15];
[197] 
[198]             vv = (ngx_stream_variable_value_t *)
[199]                       ngx_radix32tree_find(ctx->u.trees.tree, inaddr);
[200] 
[201]         } else {
[202]             vv = (ngx_stream_variable_value_t *)
[203]                       ngx_radix128tree_find(ctx->u.trees.tree6, p);
[204]         }
[205] 
[206]         break;
[207] #endif
[208] 
[209] #if (NGX_HAVE_UNIX_DOMAIN)
[210]     case AF_UNIX:
[211]         vv = (ngx_stream_variable_value_t *)
[212]                   ngx_radix32tree_find(ctx->u.trees.tree, INADDR_NONE);
[213]         break;
[214] #endif
[215] 
[216]     default: /* AF_INET */
[217]         sin = (struct sockaddr_in *) addr.sockaddr;
[218]         inaddr = ntohl(sin->sin_addr.s_addr);
[219] 
[220]         vv = (ngx_stream_variable_value_t *)
[221]                   ngx_radix32tree_find(ctx->u.trees.tree, inaddr);
[222] 
[223]         break;
[224]     }
[225] 
[226] done:
[227] 
[228]     *v = *vv;
[229] 
[230]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[231]                    "stream geo: %v", v);
[232] 
[233]     return NGX_OK;
[234] }
[235] 
[236] 
[237] static ngx_int_t
[238] ngx_stream_geo_range_variable(ngx_stream_session_t *s,
[239]     ngx_stream_variable_value_t *v, uintptr_t data)
[240] {
[241]     ngx_stream_geo_ctx_t *ctx = (ngx_stream_geo_ctx_t *) data;
[242] 
[243]     in_addr_t                inaddr;
[244]     ngx_addr_t               addr;
[245]     ngx_uint_t               n;
[246]     struct sockaddr_in      *sin;
[247]     ngx_stream_geo_range_t  *range;
[248] #if (NGX_HAVE_INET6)
[249]     u_char                  *p;
[250]     struct in6_addr         *inaddr6;
[251] #endif
[252] 
[253]     *v = *ctx->u.high.default_value;
[254] 
[255]     if (ngx_stream_geo_addr(s, ctx, &addr) == NGX_OK) {
[256] 
[257]         switch (addr.sockaddr->sa_family) {
[258] 
[259] #if (NGX_HAVE_INET6)
[260]         case AF_INET6:
[261]             inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
[262] 
[263]             if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[264]                 p = inaddr6->s6_addr;
[265] 
[266]                 inaddr = p[12] << 24;
[267]                 inaddr += p[13] << 16;
[268]                 inaddr += p[14] << 8;
[269]                 inaddr += p[15];
[270] 
[271]             } else {
[272]                 inaddr = INADDR_NONE;
[273]             }
[274] 
[275]             break;
[276] #endif
[277] 
[278] #if (NGX_HAVE_UNIX_DOMAIN)
[279]         case AF_UNIX:
[280]             inaddr = INADDR_NONE;
[281]             break;
[282] #endif
[283] 
[284]         default: /* AF_INET */
[285]             sin = (struct sockaddr_in *) addr.sockaddr;
[286]             inaddr = ntohl(sin->sin_addr.s_addr);
[287]             break;
[288]         }
[289] 
[290]     } else {
[291]         inaddr = INADDR_NONE;
[292]     }
[293] 
[294]     if (ctx->u.high.low) {
[295]         range = ctx->u.high.low[inaddr >> 16];
[296] 
[297]         if (range) {
[298]             n = inaddr & 0xffff;
[299]             do {
[300]                 if (n >= (ngx_uint_t) range->start
[301]                     && n <= (ngx_uint_t) range->end)
[302]                 {
[303]                     *v = *range->value;
[304]                     break;
[305]                 }
[306]             } while ((++range)->value);
[307]         }
[308]     }
[309] 
[310]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[311]                    "stream geo: %v", v);
[312] 
[313]     return NGX_OK;
[314] }
[315] 
[316] 
[317] static ngx_int_t
[318] ngx_stream_geo_addr(ngx_stream_session_t *s, ngx_stream_geo_ctx_t *ctx,
[319]     ngx_addr_t *addr)
[320] {
[321]     ngx_stream_variable_value_t  *v;
[322] 
[323]     if (ctx->index == -1) {
[324]         ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[325]                        "stream geo started: %V", &s->connection->addr_text);
[326] 
[327]         addr->sockaddr = s->connection->sockaddr;
[328]         addr->socklen = s->connection->socklen;
[329]         /* addr->name = s->connection->addr_text; */
[330] 
[331]         return NGX_OK;
[332]     }
[333] 
[334]     v = ngx_stream_get_flushed_variable(s, ctx->index);
[335] 
[336]     if (v == NULL || v->not_found) {
[337]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[338]                        "stream geo not found");
[339] 
[340]         return NGX_ERROR;
[341]     }
[342] 
[343]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[344]                    "stream geo started: %v", v);
[345] 
[346]     if (ngx_parse_addr(s->connection->pool, addr, v->data, v->len) == NGX_OK) {
[347]         return NGX_OK;
[348]     }
[349] 
[350]     return NGX_ERROR;
[351] }
[352] 
[353] 
[354] static char *
[355] ngx_stream_geo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[356] {
[357]     char                       *rv;
[358]     size_t                      len;
[359]     ngx_str_t                  *value, name;
[360]     ngx_uint_t                  i;
[361]     ngx_conf_t                  save;
[362]     ngx_pool_t                 *pool;
[363]     ngx_array_t                *a;
[364]     ngx_stream_variable_t      *var;
[365]     ngx_stream_geo_ctx_t       *geo;
[366]     ngx_stream_geo_conf_ctx_t   ctx;
[367] #if (NGX_HAVE_INET6)
[368]     static struct in6_addr      zero;
[369] #endif
[370] 
[371]     value = cf->args->elts;
[372] 
[373]     geo = ngx_palloc(cf->pool, sizeof(ngx_stream_geo_ctx_t));
[374]     if (geo == NULL) {
[375]         return NGX_CONF_ERROR;
[376]     }
[377] 
[378]     name = value[1];
[379] 
[380]     if (name.data[0] != '$') {
[381]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[382]                            "invalid variable name \"%V\"", &name);
[383]         return NGX_CONF_ERROR;
[384]     }
[385] 
[386]     name.len--;
[387]     name.data++;
[388] 
[389]     if (cf->args->nelts == 3) {
[390] 
[391]         geo->index = ngx_stream_get_variable_index(cf, &name);
[392]         if (geo->index == NGX_ERROR) {
[393]             return NGX_CONF_ERROR;
[394]         }
[395] 
[396]         name = value[2];
[397] 
[398]         if (name.data[0] != '$') {
[399]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[400]                                "invalid variable name \"%V\"", &name);
[401]             return NGX_CONF_ERROR;
[402]         }
[403] 
[404]         name.len--;
[405]         name.data++;
[406] 
[407]     } else {
[408]         geo->index = -1;
[409]     }
[410] 
[411]     var = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
[412]     if (var == NULL) {
[413]         return NGX_CONF_ERROR;
[414]     }
[415] 
[416]     pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[417]     if (pool == NULL) {
[418]         return NGX_CONF_ERROR;
[419]     }
[420] 
[421]     ngx_memzero(&ctx, sizeof(ngx_stream_geo_conf_ctx_t));
[422] 
[423]     ctx.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
[424]     if (ctx.temp_pool == NULL) {
[425]         ngx_destroy_pool(pool);
[426]         return NGX_CONF_ERROR;
[427]     }
[428] 
[429]     ngx_rbtree_init(&ctx.rbtree, &ctx.sentinel, ngx_str_rbtree_insert_value);
[430] 
[431]     ctx.pool = cf->pool;
[432]     ctx.data_size = sizeof(ngx_stream_geo_header_t)
[433]                   + sizeof(ngx_stream_variable_value_t)
[434]                   + 0x10000 * sizeof(ngx_stream_geo_range_t *);
[435]     ctx.allow_binary_include = 1;
[436] 
[437]     save = *cf;
[438]     cf->pool = pool;
[439]     cf->ctx = &ctx;
[440]     cf->handler = ngx_stream_geo;
[441]     cf->handler_conf = conf;
[442] 
[443]     rv = ngx_conf_parse(cf, NULL);
[444] 
[445]     *cf = save;
[446] 
[447]     if (rv != NGX_CONF_OK) {
[448]         goto failed;
[449]     }
[450] 
[451]     if (ctx.ranges) {
[452] 
[453]         if (ctx.high.low && !ctx.binary_include) {
[454]             for (i = 0; i < 0x10000; i++) {
[455]                 a = (ngx_array_t *) ctx.high.low[i];
[456] 
[457]                 if (a == NULL) {
[458]                     continue;
[459]                 }
[460] 
[461]                 if (a->nelts == 0) {
[462]                     ctx.high.low[i] = NULL;
[463]                     continue;
[464]                 }
[465] 
[466]                 len = a->nelts * sizeof(ngx_stream_geo_range_t);
[467] 
[468]                 ctx.high.low[i] = ngx_palloc(cf->pool, len + sizeof(void *));
[469]                 if (ctx.high.low[i] == NULL) {
[470]                     goto failed;
[471]                 }
[472] 
[473]                 ngx_memcpy(ctx.high.low[i], a->elts, len);
[474]                 ctx.high.low[i][a->nelts].value = NULL;
[475]                 ctx.data_size += len + sizeof(void *);
[476]             }
[477] 
[478]             if (ctx.allow_binary_include
[479]                 && !ctx.outside_entries
[480]                 && ctx.entries > 100000
[481]                 && ctx.includes == 1)
[482]             {
[483]                 ngx_stream_geo_create_binary_base(&ctx);
[484]             }
[485]         }
[486] 
[487]         if (ctx.high.default_value == NULL) {
[488]             ctx.high.default_value = &ngx_stream_variable_null_value;
[489]         }
[490] 
[491]         geo->u.high = ctx.high;
[492] 
[493]         var->get_handler = ngx_stream_geo_range_variable;
[494]         var->data = (uintptr_t) geo;
[495] 
[496]     } else {
[497]         if (ctx.tree == NULL) {
[498]             ctx.tree = ngx_radix_tree_create(cf->pool, -1);
[499]             if (ctx.tree == NULL) {
[500]                 goto failed;
[501]             }
[502]         }
[503] 
[504]         geo->u.trees.tree = ctx.tree;
[505] 
[506] #if (NGX_HAVE_INET6)
[507]         if (ctx.tree6 == NULL) {
[508]             ctx.tree6 = ngx_radix_tree_create(cf->pool, -1);
[509]             if (ctx.tree6 == NULL) {
[510]                 goto failed;
[511]             }
[512]         }
[513] 
[514]         geo->u.trees.tree6 = ctx.tree6;
[515] #endif
[516] 
[517]         var->get_handler = ngx_stream_geo_cidr_variable;
[518]         var->data = (uintptr_t) geo;
[519] 
[520]         if (ngx_radix32tree_insert(ctx.tree, 0, 0,
[521]                                    (uintptr_t) &ngx_stream_variable_null_value)
[522]             == NGX_ERROR)
[523]         {
[524]             goto failed;
[525]         }
[526] 
[527]         /* NGX_BUSY is okay (default was set explicitly) */
[528] 
[529] #if (NGX_HAVE_INET6)
[530]         if (ngx_radix128tree_insert(ctx.tree6, zero.s6_addr, zero.s6_addr,
[531]                                     (uintptr_t) &ngx_stream_variable_null_value)
[532]             == NGX_ERROR)
[533]         {
[534]             goto failed;
[535]         }
[536] #endif
[537]     }
[538] 
[539]     ngx_destroy_pool(ctx.temp_pool);
[540]     ngx_destroy_pool(pool);
[541] 
[542]     return NGX_CONF_OK;
[543] 
[544] failed:
[545] 
[546]     ngx_destroy_pool(ctx.temp_pool);
[547]     ngx_destroy_pool(pool);
[548] 
[549]     return NGX_CONF_ERROR;
[550] }
[551] 
[552] 
[553] static char *
[554] ngx_stream_geo(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[555] {
[556]     char                       *rv;
[557]     ngx_str_t                  *value;
[558]     ngx_stream_geo_conf_ctx_t  *ctx;
[559] 
[560]     ctx = cf->ctx;
[561] 
[562]     value = cf->args->elts;
[563] 
[564]     if (cf->args->nelts == 1) {
[565] 
[566]         if (ngx_strcmp(value[0].data, "ranges") == 0) {
[567] 
[568]             if (ctx->tree
[569] #if (NGX_HAVE_INET6)
[570]                 || ctx->tree6
[571] #endif
[572]                )
[573]             {
[574]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[575]                                    "the \"ranges\" directive must be "
[576]                                    "the first directive inside \"geo\" block");
[577]                 goto failed;
[578]             }
[579] 
[580]             ctx->ranges = 1;
[581] 
[582]             rv = NGX_CONF_OK;
[583] 
[584]             goto done;
[585]         }
[586]     }
[587] 
[588]     if (cf->args->nelts != 2) {
[589]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[590]                            "invalid number of the geo parameters");
[591]         goto failed;
[592]     }
[593] 
[594]     if (ngx_strcmp(value[0].data, "include") == 0) {
[595] 
[596]         rv = ngx_stream_geo_include(cf, ctx, &value[1]);
[597] 
[598]         goto done;
[599]     }
[600] 
[601]     if (ctx->ranges) {
[602]         rv = ngx_stream_geo_range(cf, ctx, value);
[603] 
[604]     } else {
[605]         rv = ngx_stream_geo_cidr(cf, ctx, value);
[606]     }
[607] 
[608] done:
[609] 
[610]     ngx_reset_pool(cf->pool);
[611] 
[612]     return rv;
[613] 
[614] failed:
[615] 
[616]     ngx_reset_pool(cf->pool);
[617] 
[618]     return NGX_CONF_ERROR;
[619] }
[620] 
[621] 
[622] static char *
[623] ngx_stream_geo_range(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[624]     ngx_str_t *value)
[625] {
[626]     u_char      *p, *last;
[627]     in_addr_t    start, end;
[628]     ngx_str_t   *net;
[629]     ngx_uint_t   del;
[630] 
[631]     if (ngx_strcmp(value[0].data, "default") == 0) {
[632] 
[633]         if (ctx->high.default_value) {
[634]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[635]                 "duplicate default geo range value: \"%V\", old value: \"%v\"",
[636]                 &value[1], ctx->high.default_value);
[637]         }
[638] 
[639]         ctx->high.default_value = ngx_stream_geo_value(cf, ctx, &value[1]);
[640]         if (ctx->high.default_value == NULL) {
[641]             return NGX_CONF_ERROR;
[642]         }
[643] 
[644]         return NGX_CONF_OK;
[645]     }
[646] 
[647]     if (ctx->binary_include) {
[648]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[649]             "binary geo range base \"%s\" cannot be mixed with usual entries",
[650]             ctx->include_name.data);
[651]         return NGX_CONF_ERROR;
[652]     }
[653] 
[654]     if (ctx->high.low == NULL) {
[655]         ctx->high.low = ngx_pcalloc(ctx->pool,
[656]                                     0x10000 * sizeof(ngx_stream_geo_range_t *));
[657]         if (ctx->high.low == NULL) {
[658]             return NGX_CONF_ERROR;
[659]         }
[660]     }
[661] 
[662]     ctx->entries++;
[663]     ctx->outside_entries = 1;
[664] 
[665]     if (ngx_strcmp(value[0].data, "delete") == 0) {
[666]         net = &value[1];
[667]         del = 1;
[668] 
[669]     } else {
[670]         net = &value[0];
[671]         del = 0;
[672]     }
[673] 
[674]     last = net->data + net->len;
[675] 
[676]     p = ngx_strlchr(net->data, last, '-');
[677] 
[678]     if (p == NULL) {
[679]         goto invalid;
[680]     }
[681] 
[682]     start = ngx_inet_addr(net->data, p - net->data);
[683] 
[684]     if (start == INADDR_NONE) {
[685]         goto invalid;
[686]     }
[687] 
[688]     start = ntohl(start);
[689] 
[690]     p++;
[691] 
[692]     end = ngx_inet_addr(p, last - p);
[693] 
[694]     if (end == INADDR_NONE) {
[695]         goto invalid;
[696]     }
[697] 
[698]     end = ntohl(end);
[699] 
[700]     if (start > end) {
[701]         goto invalid;
[702]     }
[703] 
[704]     if (del) {
[705]         if (ngx_stream_geo_delete_range(cf, ctx, start, end)) {
[706]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[707]                                "no address range \"%V\" to delete", net);
[708]         }
[709] 
[710]         return NGX_CONF_OK;
[711]     }
[712] 
[713]     ctx->value = ngx_stream_geo_value(cf, ctx, &value[1]);
[714] 
[715]     if (ctx->value == NULL) {
[716]         return NGX_CONF_ERROR;
[717]     }
[718] 
[719]     ctx->net = net;
[720] 
[721]     return ngx_stream_geo_add_range(cf, ctx, start, end);
[722] 
[723] invalid:
[724] 
[725]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid range \"%V\"", net);
[726] 
[727]     return NGX_CONF_ERROR;
[728] }
[729] 
[730] 
[731] /* the add procedure is optimized to add a growing up sequence */
[732] 
[733] static char *
[734] ngx_stream_geo_add_range(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[735]     in_addr_t start, in_addr_t end)
[736] {
[737]     in_addr_t                n;
[738]     ngx_uint_t               h, i, s, e;
[739]     ngx_array_t             *a;
[740]     ngx_stream_geo_range_t  *range;
[741] 
[742]     for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {
[743] 
[744]         h = n >> 16;
[745] 
[746]         if (n == start) {
[747]             s = n & 0xffff;
[748]         } else {
[749]             s = 0;
[750]         }
[751] 
[752]         if ((n | 0xffff) > end) {
[753]             e = end & 0xffff;
[754] 
[755]         } else {
[756]             e = 0xffff;
[757]         }
[758] 
[759]         a = (ngx_array_t *) ctx->high.low[h];
[760] 
[761]         if (a == NULL) {
[762]             a = ngx_array_create(ctx->temp_pool, 64,
[763]                                  sizeof(ngx_stream_geo_range_t));
[764]             if (a == NULL) {
[765]                 return NGX_CONF_ERROR;
[766]             }
[767] 
[768]             ctx->high.low[h] = (ngx_stream_geo_range_t *) a;
[769]         }
[770] 
[771]         i = a->nelts;
[772]         range = a->elts;
[773] 
[774]         while (i) {
[775] 
[776]             i--;
[777] 
[778]             if (e < (ngx_uint_t) range[i].start) {
[779]                 continue;
[780]             }
[781] 
[782]             if (s > (ngx_uint_t) range[i].end) {
[783] 
[784]                 /* add after the range */
[785] 
[786]                 range = ngx_array_push(a);
[787]                 if (range == NULL) {
[788]                     return NGX_CONF_ERROR;
[789]                 }
[790] 
[791]                 range = a->elts;
[792] 
[793]                 ngx_memmove(&range[i + 2], &range[i + 1],
[794]                            (a->nelts - 2 - i) * sizeof(ngx_stream_geo_range_t));
[795] 
[796]                 range[i + 1].start = (u_short) s;
[797]                 range[i + 1].end = (u_short) e;
[798]                 range[i + 1].value = ctx->value;
[799] 
[800]                 goto next;
[801]             }
[802] 
[803]             if (s == (ngx_uint_t) range[i].start
[804]                 && e == (ngx_uint_t) range[i].end)
[805]             {
[806]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[807]                     "duplicate range \"%V\", value: \"%v\", old value: \"%v\"",
[808]                     ctx->net, ctx->value, range[i].value);
[809] 
[810]                 range[i].value = ctx->value;
[811] 
[812]                 goto next;
[813]             }
[814] 
[815]             if (s > (ngx_uint_t) range[i].start
[816]                 && e < (ngx_uint_t) range[i].end)
[817]             {
[818]                 /* split the range and insert the new one */
[819] 
[820]                 range = ngx_array_push(a);
[821]                 if (range == NULL) {
[822]                     return NGX_CONF_ERROR;
[823]                 }
[824] 
[825]                 range = ngx_array_push(a);
[826]                 if (range == NULL) {
[827]                     return NGX_CONF_ERROR;
[828]                 }
[829] 
[830]                 range = a->elts;
[831] 
[832]                 ngx_memmove(&range[i + 3], &range[i + 1],
[833]                            (a->nelts - 3 - i) * sizeof(ngx_stream_geo_range_t));
[834] 
[835]                 range[i + 2].start = (u_short) (e + 1);
[836]                 range[i + 2].end = range[i].end;
[837]                 range[i + 2].value = range[i].value;
[838] 
[839]                 range[i + 1].start = (u_short) s;
[840]                 range[i + 1].end = (u_short) e;
[841]                 range[i + 1].value = ctx->value;
[842] 
[843]                 range[i].end = (u_short) (s - 1);
[844] 
[845]                 goto next;
[846]             }
[847] 
[848]             if (s == (ngx_uint_t) range[i].start
[849]                 && e < (ngx_uint_t) range[i].end)
[850]             {
[851]                 /* shift the range start and insert the new range */
[852] 
[853]                 range = ngx_array_push(a);
[854]                 if (range == NULL) {
[855]                     return NGX_CONF_ERROR;
[856]                 }
[857] 
[858]                 range = a->elts;
[859] 
[860]                 ngx_memmove(&range[i + 1], &range[i],
[861]                            (a->nelts - 1 - i) * sizeof(ngx_stream_geo_range_t));
[862] 
[863]                 range[i + 1].start = (u_short) (e + 1);
[864] 
[865]                 range[i].start = (u_short) s;
[866]                 range[i].end = (u_short) e;
[867]                 range[i].value = ctx->value;
[868] 
[869]                 goto next;
[870]             }
[871] 
[872]             if (s > (ngx_uint_t) range[i].start
[873]                 && e == (ngx_uint_t) range[i].end)
[874]             {
[875]                 /* shift the range end and insert the new range */
[876] 
[877]                 range = ngx_array_push(a);
[878]                 if (range == NULL) {
[879]                     return NGX_CONF_ERROR;
[880]                 }
[881] 
[882]                 range = a->elts;
[883] 
[884]                 ngx_memmove(&range[i + 2], &range[i + 1],
[885]                            (a->nelts - 2 - i) * sizeof(ngx_stream_geo_range_t));
[886] 
[887]                 range[i + 1].start = (u_short) s;
[888]                 range[i + 1].end = (u_short) e;
[889]                 range[i + 1].value = ctx->value;
[890] 
[891]                 range[i].end = (u_short) (s - 1);
[892] 
[893]                 goto next;
[894]             }
[895] 
[896]             s = (ngx_uint_t) range[i].start;
[897]             e = (ngx_uint_t) range[i].end;
[898] 
[899]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[900]                          "range \"%V\" overlaps \"%d.%d.%d.%d-%d.%d.%d.%d\"",
[901]                          ctx->net,
[902]                          h >> 8, h & 0xff, s >> 8, s & 0xff,
[903]                          h >> 8, h & 0xff, e >> 8, e & 0xff);
[904] 
[905]             return NGX_CONF_ERROR;
[906]         }
[907] 
[908]         /* add the first range */
[909] 
[910]         range = ngx_array_push(a);
[911]         if (range == NULL) {
[912]             return NGX_CONF_ERROR;
[913]         }
[914] 
[915]         range = a->elts;
[916] 
[917]         ngx_memmove(&range[1], &range[0],
[918]                     (a->nelts - 1) * sizeof(ngx_stream_geo_range_t));
[919] 
[920]         range[0].start = (u_short) s;
[921]         range[0].end = (u_short) e;
[922]         range[0].value = ctx->value;
[923] 
[924]     next:
[925] 
[926]         if (h == 0xffff) {
[927]             break;
[928]         }
[929]     }
[930] 
[931]     return NGX_CONF_OK;
[932] }
[933] 
[934] 
[935] static ngx_uint_t
[936] ngx_stream_geo_delete_range(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[937]     in_addr_t start, in_addr_t end)
[938] {
[939]     in_addr_t                n;
[940]     ngx_uint_t               h, i, s, e, warn;
[941]     ngx_array_t             *a;
[942]     ngx_stream_geo_range_t  *range;
[943] 
[944]     warn = 0;
[945] 
[946]     for (n = start; n <= end; n = (n + 0x10000) & 0xffff0000) {
[947] 
[948]         h = n >> 16;
[949] 
[950]         if (n == start) {
[951]             s = n & 0xffff;
[952]         } else {
[953]             s = 0;
[954]         }
[955] 
[956]         if ((n | 0xffff) > end) {
[957]             e = end & 0xffff;
[958] 
[959]         } else {
[960]             e = 0xffff;
[961]         }
[962] 
[963]         a = (ngx_array_t *) ctx->high.low[h];
[964] 
[965]         if (a == NULL || a->nelts == 0) {
[966]             warn = 1;
[967]             goto next;
[968]         }
[969] 
[970]         range = a->elts;
[971]         for (i = 0; i < a->nelts; i++) {
[972] 
[973]             if (s == (ngx_uint_t) range[i].start
[974]                 && e == (ngx_uint_t) range[i].end)
[975]             {
[976]                 ngx_memmove(&range[i], &range[i + 1],
[977]                            (a->nelts - 1 - i) * sizeof(ngx_stream_geo_range_t));
[978] 
[979]                 a->nelts--;
[980] 
[981]                 break;
[982]             }
[983] 
[984]             if (i == a->nelts - 1) {
[985]                 warn = 1;
[986]             }
[987]         }
[988] 
[989]     next:
[990] 
[991]         if (h == 0xffff) {
[992]             break;
[993]         }
[994]     }
[995] 
[996]     return warn;
[997] }
[998] 
[999] 
[1000] static char *
[1001] ngx_stream_geo_cidr(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[1002]     ngx_str_t *value)
[1003] {
[1004]     char        *rv;
[1005]     ngx_int_t    rc, del;
[1006]     ngx_str_t   *net;
[1007]     ngx_cidr_t   cidr;
[1008] 
[1009]     if (ctx->tree == NULL) {
[1010]         ctx->tree = ngx_radix_tree_create(ctx->pool, -1);
[1011]         if (ctx->tree == NULL) {
[1012]             return NGX_CONF_ERROR;
[1013]         }
[1014]     }
[1015] 
[1016] #if (NGX_HAVE_INET6)
[1017]     if (ctx->tree6 == NULL) {
[1018]         ctx->tree6 = ngx_radix_tree_create(ctx->pool, -1);
[1019]         if (ctx->tree6 == NULL) {
[1020]             return NGX_CONF_ERROR;
[1021]         }
[1022]     }
[1023] #endif
[1024] 
[1025]     if (ngx_strcmp(value[0].data, "default") == 0) {
[1026]         cidr.family = AF_INET;
[1027]         cidr.u.in.addr = 0;
[1028]         cidr.u.in.mask = 0;
[1029] 
[1030]         rv = ngx_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);
[1031] 
[1032]         if (rv != NGX_CONF_OK) {
[1033]             return rv;
[1034]         }
[1035] 
[1036] #if (NGX_HAVE_INET6)
[1037]         cidr.family = AF_INET6;
[1038]         ngx_memzero(&cidr.u.in6, sizeof(ngx_in6_cidr_t));
[1039] 
[1040]         rv = ngx_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0]);
[1041] 
[1042]         if (rv != NGX_CONF_OK) {
[1043]             return rv;
[1044]         }
[1045] #endif
[1046] 
[1047]         return NGX_CONF_OK;
[1048]     }
[1049] 
[1050]     if (ngx_strcmp(value[0].data, "delete") == 0) {
[1051]         net = &value[1];
[1052]         del = 1;
[1053] 
[1054]     } else {
[1055]         net = &value[0];
[1056]         del = 0;
[1057]     }
[1058] 
[1059]     if (ngx_stream_geo_cidr_value(cf, net, &cidr) != NGX_OK) {
[1060]         return NGX_CONF_ERROR;
[1061]     }
[1062] 
[1063]     if (cidr.family == AF_INET) {
[1064]         cidr.u.in.addr = ntohl(cidr.u.in.addr);
[1065]         cidr.u.in.mask = ntohl(cidr.u.in.mask);
[1066]     }
[1067] 
[1068]     if (del) {
[1069]         switch (cidr.family) {
[1070] 
[1071] #if (NGX_HAVE_INET6)
[1072]         case AF_INET6:
[1073]             rc = ngx_radix128tree_delete(ctx->tree6,
[1074]                                          cidr.u.in6.addr.s6_addr,
[1075]                                          cidr.u.in6.mask.s6_addr);
[1076]             break;
[1077] #endif
[1078] 
[1079]         default: /* AF_INET */
[1080]             rc = ngx_radix32tree_delete(ctx->tree, cidr.u.in.addr,
[1081]                                         cidr.u.in.mask);
[1082]             break;
[1083]         }
[1084] 
[1085]         if (rc != NGX_OK) {
[1086]             ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1087]                                "no network \"%V\" to delete", net);
[1088]         }
[1089] 
[1090]         return NGX_CONF_OK;
[1091]     }
[1092] 
[1093]     return ngx_stream_geo_cidr_add(cf, ctx, &cidr, &value[1], net);
[1094] }
[1095] 
[1096] 
[1097] static char *
[1098] ngx_stream_geo_cidr_add(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[1099]     ngx_cidr_t *cidr, ngx_str_t *value, ngx_str_t *net)
[1100] {
[1101]     ngx_int_t                     rc;
[1102]     ngx_stream_variable_value_t  *val, *old;
[1103] 
[1104]     val = ngx_stream_geo_value(cf, ctx, value);
[1105] 
[1106]     if (val == NULL) {
[1107]         return NGX_CONF_ERROR;
[1108]     }
[1109] 
[1110]     switch (cidr->family) {
[1111] 
[1112] #if (NGX_HAVE_INET6)
[1113]     case AF_INET6:
[1114]         rc = ngx_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
[1115]                                      cidr->u.in6.mask.s6_addr,
[1116]                                      (uintptr_t) val);
[1117] 
[1118]         if (rc == NGX_OK) {
[1119]             return NGX_CONF_OK;
[1120]         }
[1121] 
[1122]         if (rc == NGX_ERROR) {
[1123]             return NGX_CONF_ERROR;
[1124]         }
[1125] 
[1126]         /* rc == NGX_BUSY */
[1127] 
[1128]         old = (ngx_stream_variable_value_t *)
[1129]                    ngx_radix128tree_find(ctx->tree6,
[1130]                                          cidr->u.in6.addr.s6_addr);
[1131] 
[1132]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1133]               "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
[1134]               net, val, old);
[1135] 
[1136]         rc = ngx_radix128tree_delete(ctx->tree6,
[1137]                                      cidr->u.in6.addr.s6_addr,
[1138]                                      cidr->u.in6.mask.s6_addr);
[1139] 
[1140]         if (rc == NGX_ERROR) {
[1141]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid radix tree");
[1142]             return NGX_CONF_ERROR;
[1143]         }
[1144] 
[1145]         rc = ngx_radix128tree_insert(ctx->tree6, cidr->u.in6.addr.s6_addr,
[1146]                                      cidr->u.in6.mask.s6_addr,
[1147]                                      (uintptr_t) val);
[1148] 
[1149]         break;
[1150] #endif
[1151] 
[1152]     default: /* AF_INET */
[1153]         rc = ngx_radix32tree_insert(ctx->tree, cidr->u.in.addr,
[1154]                                     cidr->u.in.mask, (uintptr_t) val);
[1155] 
[1156]         if (rc == NGX_OK) {
[1157]             return NGX_CONF_OK;
[1158]         }
[1159] 
[1160]         if (rc == NGX_ERROR) {
[1161]             return NGX_CONF_ERROR;
[1162]         }
[1163] 
[1164]         /* rc == NGX_BUSY */
[1165] 
[1166]         old = (ngx_stream_variable_value_t *)
[1167]                    ngx_radix32tree_find(ctx->tree, cidr->u.in.addr);
[1168] 
[1169]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1170]               "duplicate network \"%V\", value: \"%v\", old value: \"%v\"",
[1171]               net, val, old);
[1172] 
[1173]         rc = ngx_radix32tree_delete(ctx->tree,
[1174]                                     cidr->u.in.addr, cidr->u.in.mask);
[1175] 
[1176]         if (rc == NGX_ERROR) {
[1177]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid radix tree");
[1178]             return NGX_CONF_ERROR;
[1179]         }
[1180] 
[1181]         rc = ngx_radix32tree_insert(ctx->tree, cidr->u.in.addr,
[1182]                                     cidr->u.in.mask, (uintptr_t) val);
[1183] 
[1184]         break;
[1185]     }
[1186] 
[1187]     if (rc == NGX_OK) {
[1188]         return NGX_CONF_OK;
[1189]     }
[1190] 
[1191]     return NGX_CONF_ERROR;
[1192] }
[1193] 
[1194] 
[1195] static ngx_stream_variable_value_t *
[1196] ngx_stream_geo_value(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[1197]     ngx_str_t *value)
[1198] {
[1199]     uint32_t                               hash;
[1200]     ngx_stream_variable_value_t           *val;
[1201]     ngx_stream_geo_variable_value_node_t  *gvvn;
[1202] 
[1203]     hash = ngx_crc32_long(value->data, value->len);
[1204] 
[1205]     gvvn = (ngx_stream_geo_variable_value_node_t *)
[1206]                ngx_str_rbtree_lookup(&ctx->rbtree, value, hash);
[1207] 
[1208]     if (gvvn) {
[1209]         return gvvn->value;
[1210]     }
[1211] 
[1212]     val = ngx_palloc(ctx->pool, sizeof(ngx_stream_variable_value_t));
[1213]     if (val == NULL) {
[1214]         return NULL;
[1215]     }
[1216] 
[1217]     val->len = value->len;
[1218]     val->data = ngx_pstrdup(ctx->pool, value);
[1219]     if (val->data == NULL) {
[1220]         return NULL;
[1221]     }
[1222] 
[1223]     val->valid = 1;
[1224]     val->no_cacheable = 0;
[1225]     val->not_found = 0;
[1226] 
[1227]     gvvn = ngx_palloc(ctx->temp_pool,
[1228]                       sizeof(ngx_stream_geo_variable_value_node_t));
[1229]     if (gvvn == NULL) {
[1230]         return NULL;
[1231]     }
[1232] 
[1233]     gvvn->sn.node.key = hash;
[1234]     gvvn->sn.str.len = val->len;
[1235]     gvvn->sn.str.data = val->data;
[1236]     gvvn->value = val;
[1237]     gvvn->offset = 0;
[1238] 
[1239]     ngx_rbtree_insert(&ctx->rbtree, &gvvn->sn.node);
[1240] 
[1241]     ctx->data_size += ngx_align(sizeof(ngx_stream_variable_value_t)
[1242]                                 + value->len, sizeof(void *));
[1243] 
[1244]     return val;
[1245] }
[1246] 
[1247] 
[1248] static ngx_int_t
[1249] ngx_stream_geo_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
[1250] {
[1251]     ngx_int_t  rc;
[1252] 
[1253]     if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
[1254]         cidr->family = AF_INET;
[1255]         cidr->u.in.addr = 0xffffffff;
[1256]         cidr->u.in.mask = 0xffffffff;
[1257] 
[1258]         return NGX_OK;
[1259]     }
[1260] 
[1261]     rc = ngx_ptocidr(net, cidr);
[1262] 
[1263]     if (rc == NGX_ERROR) {
[1264]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
[1265]         return NGX_ERROR;
[1266]     }
[1267] 
[1268]     if (rc == NGX_DONE) {
[1269]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1270]                            "low address bits of %V are meaningless", net);
[1271]     }
[1272] 
[1273]     return NGX_OK;
[1274] }
[1275] 
[1276] 
[1277] static char *
[1278] ngx_stream_geo_include(ngx_conf_t *cf, ngx_stream_geo_conf_ctx_t *ctx,
[1279]     ngx_str_t *name)
[1280] {
[1281]     char       *rv;
[1282]     ngx_str_t   file;
[1283] 
[1284]     file.len = name->len + 4;
[1285]     file.data = ngx_pnalloc(ctx->temp_pool, name->len + 5);
[1286]     if (file.data == NULL) {
[1287]         return NGX_CONF_ERROR;
[1288]     }
[1289] 
[1290]     ngx_sprintf(file.data, "%V.bin%Z", name);
[1291] 
[1292]     if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
[1293]         return NGX_CONF_ERROR;
[1294]     }
[1295] 
[1296]     if (ctx->ranges) {
[1297]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[1298] 
[1299]         switch (ngx_stream_geo_include_binary_base(cf, ctx, &file)) {
[1300]         case NGX_OK:
[1301]             return NGX_CONF_OK;
[1302]         case NGX_ERROR:
[1303]             return NGX_CONF_ERROR;
[1304]         default:
[1305]             break;
[1306]         }
[1307]     }
[1308] 
[1309]     file.len -= 4;
[1310]     file.data[file.len] = '\0';
[1311] 
[1312]     ctx->include_name = file;
[1313] 
[1314]     if (ctx->outside_entries) {
[1315]         ctx->allow_binary_include = 0;
[1316]     }
[1317] 
[1318]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[1319] 
[1320]     rv = ngx_conf_parse(cf, &file);
[1321] 
[1322]     ctx->includes++;
[1323]     ctx->outside_entries = 0;
[1324] 
[1325]     return rv;
[1326] }
[1327] 
[1328] 
[1329] static ngx_int_t
[1330] ngx_stream_geo_include_binary_base(ngx_conf_t *cf,
[1331]     ngx_stream_geo_conf_ctx_t *ctx, ngx_str_t *name)
[1332] {
[1333]     u_char                       *base, ch;
[1334]     time_t                        mtime;
[1335]     size_t                        size, len;
[1336]     ssize_t                       n;
[1337]     uint32_t                      crc32;
[1338]     ngx_err_t                     err;
[1339]     ngx_int_t                     rc;
[1340]     ngx_uint_t                    i;
[1341]     ngx_file_t                    file;
[1342]     ngx_file_info_t               fi;
[1343]     ngx_stream_geo_range_t       *range, **ranges;
[1344]     ngx_stream_geo_header_t      *header;
[1345]     ngx_stream_variable_value_t  *vv;
[1346] 
[1347]     ngx_memzero(&file, sizeof(ngx_file_t));
[1348]     file.name = *name;
[1349]     file.log = cf->log;
[1350] 
[1351]     file.fd = ngx_open_file(name->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
[1352] 
[1353]     if (file.fd == NGX_INVALID_FILE) {
[1354]         err = ngx_errno;
[1355]         if (err != NGX_ENOENT) {
[1356]             ngx_conf_log_error(NGX_LOG_CRIT, cf, err,
[1357]                                ngx_open_file_n " \"%s\" failed", name->data);
[1358]         }
[1359]         return NGX_DECLINED;
[1360]     }
[1361] 
[1362]     if (ctx->outside_entries) {
[1363]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1364]             "binary geo range base \"%s\" cannot be mixed with usual entries",
[1365]             name->data);
[1366]         rc = NGX_ERROR;
[1367]         goto done;
[1368]     }
[1369] 
[1370]     if (ctx->binary_include) {
[1371]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1372]             "second binary geo range base \"%s\" cannot be mixed with \"%s\"",
[1373]             name->data, ctx->include_name.data);
[1374]         rc = NGX_ERROR;
[1375]         goto done;
[1376]     }
[1377] 
[1378]     if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
[1379]         ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[1380]                            ngx_fd_info_n " \"%s\" failed", name->data);
[1381]         goto failed;
[1382]     }
[1383] 
[1384]     size = (size_t) ngx_file_size(&fi);
[1385]     mtime = ngx_file_mtime(&fi);
[1386] 
[1387]     ch = name->data[name->len - 4];
[1388]     name->data[name->len - 4] = '\0';
[1389] 
[1390]     if (ngx_file_info(name->data, &fi) == NGX_FILE_ERROR) {
[1391]         ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[1392]                            ngx_file_info_n " \"%s\" failed", name->data);
[1393]         goto failed;
[1394]     }
[1395] 
[1396]     name->data[name->len - 4] = ch;
[1397] 
[1398]     if (mtime < ngx_file_mtime(&fi)) {
[1399]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1400]                            "stale binary geo range base \"%s\"", name->data);
[1401]         goto failed;
[1402]     }
[1403] 
[1404]     base = ngx_palloc(ctx->pool, size);
[1405]     if (base == NULL) {
[1406]         goto failed;
[1407]     }
[1408] 
[1409]     n = ngx_read_file(&file, base, size, 0);
[1410] 
[1411]     if (n == NGX_ERROR) {
[1412]         ngx_conf_log_error(NGX_LOG_CRIT, cf, ngx_errno,
[1413]                            ngx_read_file_n " \"%s\" failed", name->data);
[1414]         goto failed;
[1415]     }
[1416] 
[1417]     if ((size_t) n != size) {
[1418]         ngx_conf_log_error(NGX_LOG_CRIT, cf, 0,
[1419]             ngx_read_file_n " \"%s\" returned only %z bytes instead of %z",
[1420]             name->data, n, size);
[1421]         goto failed;
[1422]     }
[1423] 
[1424]     header = (ngx_stream_geo_header_t *) base;
[1425] 
[1426]     if (size < 16 || ngx_memcmp(&ngx_stream_geo_header, header, 12) != 0) {
[1427]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1428]              "incompatible binary geo range base \"%s\"", name->data);
[1429]         goto failed;
[1430]     }
[1431] 
[1432]     ngx_crc32_init(crc32);
[1433] 
[1434]     vv = (ngx_stream_variable_value_t *)
[1435]             (base + sizeof(ngx_stream_geo_header_t));
[1436] 
[1437]     while (vv->data) {
[1438]         len = ngx_align(sizeof(ngx_stream_variable_value_t) + vv->len,
[1439]                         sizeof(void *));
[1440]         ngx_crc32_update(&crc32, (u_char *) vv, len);
[1441]         vv->data += (size_t) base;
[1442]         vv = (ngx_stream_variable_value_t *) ((u_char *) vv + len);
[1443]     }
[1444]     ngx_crc32_update(&crc32, (u_char *) vv,
[1445]                      sizeof(ngx_stream_variable_value_t));
[1446]     vv++;
[1447] 
[1448]     ranges = (ngx_stream_geo_range_t **) vv;
[1449] 
[1450]     for (i = 0; i < 0x10000; i++) {
[1451]         ngx_crc32_update(&crc32, (u_char *) &ranges[i], sizeof(void *));
[1452]         if (ranges[i]) {
[1453]             ranges[i] = (ngx_stream_geo_range_t *)
[1454]                             ((u_char *) ranges[i] + (size_t) base);
[1455]         }
[1456]     }
[1457] 
[1458]     range = (ngx_stream_geo_range_t *) &ranges[0x10000];
[1459] 
[1460]     while ((u_char *) range < base + size) {
[1461]         while (range->value) {
[1462]             ngx_crc32_update(&crc32, (u_char *) range,
[1463]                              sizeof(ngx_stream_geo_range_t));
[1464]             range->value = (ngx_stream_variable_value_t *)
[1465]                                ((u_char *) range->value + (size_t) base);
[1466]             range++;
[1467]         }
[1468]         ngx_crc32_update(&crc32, (u_char *) range, sizeof(void *));
[1469]         range = (ngx_stream_geo_range_t *) ((u_char *) range + sizeof(void *));
[1470]     }
[1471] 
[1472]     ngx_crc32_final(crc32);
[1473] 
[1474]     if (crc32 != header->crc32) {
[1475]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1476]                   "CRC32 mismatch in binary geo range base \"%s\"", name->data);
[1477]         goto failed;
[1478]     }
[1479] 
[1480]     ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
[1481]                        "using binary geo range base \"%s\"", name->data);
[1482] 
[1483]     ctx->include_name = *name;
[1484]     ctx->binary_include = 1;
[1485]     ctx->high.low = ranges;
[1486]     rc = NGX_OK;
[1487] 
[1488]     goto done;
[1489] 
[1490] failed:
[1491] 
[1492]     rc = NGX_DECLINED;
[1493] 
[1494] done:
[1495] 
[1496]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[1497]         ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[1498]                       ngx_close_file_n " \"%s\" failed", name->data);
[1499]     }
[1500] 
[1501]     return rc;
[1502] }
[1503] 
[1504] 
[1505] static void
[1506] ngx_stream_geo_create_binary_base(ngx_stream_geo_conf_ctx_t *ctx)
[1507] {
[1508]     u_char                                *p;
[1509]     uint32_t                               hash;
[1510]     ngx_str_t                              s;
[1511]     ngx_uint_t                             i;
[1512]     ngx_file_mapping_t                     fm;
[1513]     ngx_stream_geo_range_t                *r, *range, **ranges;
[1514]     ngx_stream_geo_header_t               *header;
[1515]     ngx_stream_geo_variable_value_node_t  *gvvn;
[1516] 
[1517]     fm.name = ngx_pnalloc(ctx->temp_pool, ctx->include_name.len + 5);
[1518]     if (fm.name == NULL) {
[1519]         return;
[1520]     }
[1521] 
[1522]     ngx_sprintf(fm.name, "%V.bin%Z", &ctx->include_name);
[1523] 
[1524]     fm.size = ctx->data_size;
[1525]     fm.log = ctx->pool->log;
[1526] 
[1527]     ngx_log_error(NGX_LOG_NOTICE, fm.log, 0,
[1528]                   "creating binary geo range base \"%s\"", fm.name);
[1529] 
[1530]     if (ngx_create_file_mapping(&fm) != NGX_OK) {
[1531]         return;
[1532]     }
[1533] 
[1534]     p = ngx_cpymem(fm.addr, &ngx_stream_geo_header,
[1535]                    sizeof(ngx_stream_geo_header_t));
[1536] 
[1537]     p = ngx_stream_geo_copy_values(fm.addr, p, ctx->rbtree.root,
[1538]                                    ctx->rbtree.sentinel);
[1539] 
[1540]     p += sizeof(ngx_stream_variable_value_t);
[1541] 
[1542]     ranges = (ngx_stream_geo_range_t **) p;
[1543] 
[1544]     p += 0x10000 * sizeof(ngx_stream_geo_range_t *);
[1545] 
[1546]     for (i = 0; i < 0x10000; i++) {
[1547]         r = ctx->high.low[i];
[1548]         if (r == NULL) {
[1549]             continue;
[1550]         }
[1551] 
[1552]         range = (ngx_stream_geo_range_t *) p;
[1553]         ranges[i] = (ngx_stream_geo_range_t *) (p - (u_char *) fm.addr);
[1554] 
[1555]         do {
[1556]             s.len = r->value->len;
[1557]             s.data = r->value->data;
[1558]             hash = ngx_crc32_long(s.data, s.len);
[1559]             gvvn = (ngx_stream_geo_variable_value_node_t *)
[1560]                         ngx_str_rbtree_lookup(&ctx->rbtree, &s, hash);
[1561] 
[1562]             range->value = (ngx_stream_variable_value_t *) gvvn->offset;
[1563]             range->start = r->start;
[1564]             range->end = r->end;
[1565]             range++;
[1566] 
[1567]         } while ((++r)->value);
[1568] 
[1569]         range->value = NULL;
[1570] 
[1571]         p = (u_char *) range + sizeof(void *);
[1572]     }
[1573] 
[1574]     header = fm.addr;
[1575]     header->crc32 = ngx_crc32_long((u_char *) fm.addr
[1576]                                        + sizeof(ngx_stream_geo_header_t),
[1577]                                    fm.size - sizeof(ngx_stream_geo_header_t));
[1578] 
[1579]     ngx_close_file_mapping(&fm);
[1580] }
[1581] 
[1582] 
[1583] static u_char *
[1584] ngx_stream_geo_copy_values(u_char *base, u_char *p, ngx_rbtree_node_t *node,
[1585]     ngx_rbtree_node_t *sentinel)
[1586] {
[1587]     ngx_stream_variable_value_t           *vv;
[1588]     ngx_stream_geo_variable_value_node_t  *gvvn;
[1589] 
[1590]     if (node == sentinel) {
[1591]         return p;
[1592]     }
[1593] 
[1594]     gvvn = (ngx_stream_geo_variable_value_node_t *) node;
[1595]     gvvn->offset = p - base;
[1596] 
[1597]     vv = (ngx_stream_variable_value_t *) p;
[1598]     *vv = *gvvn->value;
[1599]     p += sizeof(ngx_stream_variable_value_t);
[1600]     vv->data = (u_char *) (p - base);
[1601] 
[1602]     p = ngx_cpymem(p, gvvn->sn.str.data, gvvn->sn.str.len);
[1603] 
[1604]     p = ngx_align_ptr(p, sizeof(void *));
[1605] 
[1606]     p = ngx_stream_geo_copy_values(base, p, node->left, sentinel);
[1607] 
[1608]     return ngx_stream_geo_copy_values(base, p, node->right, sentinel);
[1609] }
