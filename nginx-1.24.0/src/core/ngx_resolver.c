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
[11] 
[12] 
[13] #define NGX_RESOLVER_UDP_SIZE   4096
[14] 
[15] #define NGX_RESOLVER_TCP_RSIZE  (2 + 65535)
[16] #define NGX_RESOLVER_TCP_WSIZE  8192
[17] 
[18] 
[19] typedef struct {
[20]     u_char  ident_hi;
[21]     u_char  ident_lo;
[22]     u_char  flags_hi;
[23]     u_char  flags_lo;
[24]     u_char  nqs_hi;
[25]     u_char  nqs_lo;
[26]     u_char  nan_hi;
[27]     u_char  nan_lo;
[28]     u_char  nns_hi;
[29]     u_char  nns_lo;
[30]     u_char  nar_hi;
[31]     u_char  nar_lo;
[32] } ngx_resolver_hdr_t;
[33] 
[34] 
[35] typedef struct {
[36]     u_char  type_hi;
[37]     u_char  type_lo;
[38]     u_char  class_hi;
[39]     u_char  class_lo;
[40] } ngx_resolver_qs_t;
[41] 
[42] 
[43] typedef struct {
[44]     u_char  type_hi;
[45]     u_char  type_lo;
[46]     u_char  class_hi;
[47]     u_char  class_lo;
[48]     u_char  ttl[4];
[49]     u_char  len_hi;
[50]     u_char  len_lo;
[51] } ngx_resolver_an_t;
[52] 
[53] 
[54] #define ngx_resolver_node(n)  ngx_rbtree_data(n, ngx_resolver_node_t, node)
[55] 
[56] 
[57] static ngx_int_t ngx_udp_connect(ngx_resolver_connection_t *rec);
[58] static ngx_int_t ngx_tcp_connect(ngx_resolver_connection_t *rec);
[59] 
[60] 
[61] static void ngx_resolver_cleanup(void *data);
[62] static void ngx_resolver_cleanup_tree(ngx_resolver_t *r, ngx_rbtree_t *tree);
[63] static ngx_int_t ngx_resolve_name_locked(ngx_resolver_t *r,
[64]     ngx_resolver_ctx_t *ctx, ngx_str_t *name);
[65] static void ngx_resolver_expire(ngx_resolver_t *r, ngx_rbtree_t *tree,
[66]     ngx_queue_t *queue);
[67] static ngx_int_t ngx_resolver_send_query(ngx_resolver_t *r,
[68]     ngx_resolver_node_t *rn);
[69] static ngx_int_t ngx_resolver_send_udp_query(ngx_resolver_t *r,
[70]     ngx_resolver_connection_t *rec, u_char *query, u_short qlen);
[71] static ngx_int_t ngx_resolver_send_tcp_query(ngx_resolver_t *r,
[72]     ngx_resolver_connection_t *rec, u_char *query, u_short qlen);
[73] static ngx_int_t ngx_resolver_create_name_query(ngx_resolver_t *r,
[74]     ngx_resolver_node_t *rn, ngx_str_t *name);
[75] static ngx_int_t ngx_resolver_create_srv_query(ngx_resolver_t *r,
[76]     ngx_resolver_node_t *rn, ngx_str_t *name);
[77] static ngx_int_t ngx_resolver_create_addr_query(ngx_resolver_t *r,
[78]     ngx_resolver_node_t *rn, ngx_resolver_addr_t *addr);
[79] static void ngx_resolver_resend_handler(ngx_event_t *ev);
[80] static time_t ngx_resolver_resend(ngx_resolver_t *r, ngx_rbtree_t *tree,
[81]     ngx_queue_t *queue);
[82] static ngx_uint_t ngx_resolver_resend_empty(ngx_resolver_t *r);
[83] static void ngx_resolver_udp_read(ngx_event_t *rev);
[84] static void ngx_resolver_tcp_write(ngx_event_t *wev);
[85] static void ngx_resolver_tcp_read(ngx_event_t *rev);
[86] static void ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf,
[87]     size_t n, ngx_uint_t tcp);
[88] static void ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t n,
[89]     ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
[90]     ngx_uint_t nan, ngx_uint_t trunc, ngx_uint_t ans);
[91] static void ngx_resolver_process_srv(ngx_resolver_t *r, u_char *buf, size_t n,
[92]     ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan,
[93]     ngx_uint_t trunc, ngx_uint_t ans);
[94] static void ngx_resolver_process_ptr(ngx_resolver_t *r, u_char *buf, size_t n,
[95]     ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan);
[96] static ngx_resolver_node_t *ngx_resolver_lookup_name(ngx_resolver_t *r,
[97]     ngx_str_t *name, uint32_t hash);
[98] static ngx_resolver_node_t *ngx_resolver_lookup_srv(ngx_resolver_t *r,
[99]     ngx_str_t *name, uint32_t hash);
[100] static ngx_resolver_node_t *ngx_resolver_lookup_addr(ngx_resolver_t *r,
[101]     in_addr_t addr);
[102] static void ngx_resolver_rbtree_insert_value(ngx_rbtree_node_t *temp,
[103]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[104] static ngx_int_t ngx_resolver_copy(ngx_resolver_t *r, ngx_str_t *name,
[105]     u_char *buf, u_char *src, u_char *last);
[106] static ngx_int_t ngx_resolver_set_timeout(ngx_resolver_t *r,
[107]     ngx_resolver_ctx_t *ctx);
[108] static void ngx_resolver_timeout_handler(ngx_event_t *ev);
[109] static void ngx_resolver_free_node(ngx_resolver_t *r, ngx_resolver_node_t *rn);
[110] static void *ngx_resolver_alloc(ngx_resolver_t *r, size_t size);
[111] static void *ngx_resolver_calloc(ngx_resolver_t *r, size_t size);
[112] static void ngx_resolver_free(ngx_resolver_t *r, void *p);
[113] static void ngx_resolver_free_locked(ngx_resolver_t *r, void *p);
[114] static void *ngx_resolver_dup(ngx_resolver_t *r, void *src, size_t size);
[115] static ngx_resolver_addr_t *ngx_resolver_export(ngx_resolver_t *r,
[116]     ngx_resolver_node_t *rn, ngx_uint_t rotate);
[117] static void ngx_resolver_report_srv(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx);
[118] static u_char *ngx_resolver_log_error(ngx_log_t *log, u_char *buf, size_t len);
[119] static void ngx_resolver_resolve_srv_names(ngx_resolver_ctx_t *ctx,
[120]     ngx_resolver_node_t *rn);
[121] static void ngx_resolver_srv_names_handler(ngx_resolver_ctx_t *ctx);
[122] static ngx_int_t ngx_resolver_cmp_srvs(const void *one, const void *two);
[123] 
[124] #if (NGX_HAVE_INET6)
[125] static void ngx_resolver_rbtree_insert_addr6_value(ngx_rbtree_node_t *temp,
[126]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[127] static ngx_resolver_node_t *ngx_resolver_lookup_addr6(ngx_resolver_t *r,
[128]     struct in6_addr *addr, uint32_t hash);
[129] #endif
[130] 
[131] 
[132] ngx_resolver_t *
[133] ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names, ngx_uint_t n)
[134] {
[135]     ngx_str_t                   s;
[136]     ngx_url_t                   u;
[137]     ngx_uint_t                  i, j;
[138]     ngx_resolver_t             *r;
[139]     ngx_pool_cleanup_t         *cln;
[140]     ngx_resolver_connection_t  *rec;
[141] 
[142]     r = ngx_pcalloc(cf->pool, sizeof(ngx_resolver_t));
[143]     if (r == NULL) {
[144]         return NULL;
[145]     }
[146] 
[147]     r->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
[148]     if (r->event == NULL) {
[149]         return NULL;
[150]     }
[151] 
[152]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[153]     if (cln == NULL) {
[154]         return NULL;
[155]     }
[156] 
[157]     cln->handler = ngx_resolver_cleanup;
[158]     cln->data = r;
[159] 
[160]     r->ipv4 = 1;
[161] 
[162]     ngx_rbtree_init(&r->name_rbtree, &r->name_sentinel,
[163]                     ngx_resolver_rbtree_insert_value);
[164] 
[165]     ngx_rbtree_init(&r->srv_rbtree, &r->srv_sentinel,
[166]                     ngx_resolver_rbtree_insert_value);
[167] 
[168]     ngx_rbtree_init(&r->addr_rbtree, &r->addr_sentinel,
[169]                     ngx_rbtree_insert_value);
[170] 
[171]     ngx_queue_init(&r->name_resend_queue);
[172]     ngx_queue_init(&r->srv_resend_queue);
[173]     ngx_queue_init(&r->addr_resend_queue);
[174] 
[175]     ngx_queue_init(&r->name_expire_queue);
[176]     ngx_queue_init(&r->srv_expire_queue);
[177]     ngx_queue_init(&r->addr_expire_queue);
[178] 
[179] #if (NGX_HAVE_INET6)
[180]     r->ipv6 = 1;
[181] 
[182]     ngx_rbtree_init(&r->addr6_rbtree, &r->addr6_sentinel,
[183]                     ngx_resolver_rbtree_insert_addr6_value);
[184] 
[185]     ngx_queue_init(&r->addr6_resend_queue);
[186] 
[187]     ngx_queue_init(&r->addr6_expire_queue);
[188] #endif
[189] 
[190]     r->event->handler = ngx_resolver_resend_handler;
[191]     r->event->data = r;
[192]     r->event->log = &cf->cycle->new_log;
[193]     r->event->cancelable = 1;
[194]     r->ident = -1;
[195] 
[196]     r->resend_timeout = 5;
[197]     r->tcp_timeout = 5;
[198]     r->expire = 30;
[199]     r->valid = 0;
[200] 
[201]     r->log = &cf->cycle->new_log;
[202]     r->log_level = NGX_LOG_ERR;
[203] 
[204]     if (n) {
[205]         if (ngx_array_init(&r->connections, cf->pool, n,
[206]                            sizeof(ngx_resolver_connection_t))
[207]             != NGX_OK)
[208]         {
[209]             return NULL;
[210]         }
[211]     }
[212] 
[213]     for (i = 0; i < n; i++) {
[214]         if (ngx_strncmp(names[i].data, "valid=", 6) == 0) {
[215]             s.len = names[i].len - 6;
[216]             s.data = names[i].data + 6;
[217] 
[218]             r->valid = ngx_parse_time(&s, 1);
[219] 
[220]             if (r->valid == (time_t) NGX_ERROR) {
[221]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[222]                                    "invalid parameter: %V", &names[i]);
[223]                 return NULL;
[224]             }
[225] 
[226]             continue;
[227]         }
[228] 
[229] #if (NGX_HAVE_INET6)
[230]         if (ngx_strncmp(names[i].data, "ipv4=", 5) == 0) {
[231] 
[232]             if (ngx_strcmp(&names[i].data[5], "on") == 0) {
[233]                 r->ipv4 = 1;
[234] 
[235]             } else if (ngx_strcmp(&names[i].data[5], "off") == 0) {
[236]                 r->ipv4 = 0;
[237] 
[238]             } else {
[239]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[240]                                    "invalid parameter: %V", &names[i]);
[241]                 return NULL;
[242]             }
[243] 
[244]             continue;
[245]         }
[246] 
[247]         if (ngx_strncmp(names[i].data, "ipv6=", 5) == 0) {
[248] 
[249]             if (ngx_strcmp(&names[i].data[5], "on") == 0) {
[250]                 r->ipv6 = 1;
[251] 
[252]             } else if (ngx_strcmp(&names[i].data[5], "off") == 0) {
[253]                 r->ipv6 = 0;
[254] 
[255]             } else {
[256]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[257]                                    "invalid parameter: %V", &names[i]);
[258]                 return NULL;
[259]             }
[260] 
[261]             continue;
[262]         }
[263] #endif
[264] 
[265]         ngx_memzero(&u, sizeof(ngx_url_t));
[266] 
[267]         u.url = names[i];
[268]         u.default_port = 53;
[269] 
[270]         if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
[271]             if (u.err) {
[272]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[273]                                    "%s in resolver \"%V\"",
[274]                                    u.err, &u.url);
[275]             }
[276] 
[277]             return NULL;
[278]         }
[279] 
[280]         rec = ngx_array_push_n(&r->connections, u.naddrs);
[281]         if (rec == NULL) {
[282]             return NULL;
[283]         }
[284] 
[285]         ngx_memzero(rec, u.naddrs * sizeof(ngx_resolver_connection_t));
[286] 
[287]         for (j = 0; j < u.naddrs; j++) {
[288]             rec[j].sockaddr = u.addrs[j].sockaddr;
[289]             rec[j].socklen = u.addrs[j].socklen;
[290]             rec[j].server = u.addrs[j].name;
[291]             rec[j].resolver = r;
[292]         }
[293]     }
[294] 
[295] #if (NGX_HAVE_INET6)
[296]     if (r->ipv4 + r->ipv6 == 0) {
[297]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[298]                            "\"ipv4\" and \"ipv6\" cannot both be \"off\"");
[299]         return NULL;
[300]     }
[301] #endif
[302] 
[303]     if (n && r->connections.nelts == 0) {
[304]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no name servers defined");
[305]         return NULL;
[306]     }
[307] 
[308]     return r;
[309] }
[310] 
[311] 
[312] static void
[313] ngx_resolver_cleanup(void *data)
[314] {
[315]     ngx_resolver_t  *r = data;
[316] 
[317]     ngx_uint_t                  i;
[318]     ngx_resolver_connection_t  *rec;
[319] 
[320]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "cleanup resolver");
[321] 
[322]     ngx_resolver_cleanup_tree(r, &r->name_rbtree);
[323] 
[324]     ngx_resolver_cleanup_tree(r, &r->srv_rbtree);
[325] 
[326]     ngx_resolver_cleanup_tree(r, &r->addr_rbtree);
[327] 
[328] #if (NGX_HAVE_INET6)
[329]     ngx_resolver_cleanup_tree(r, &r->addr6_rbtree);
[330] #endif
[331] 
[332]     if (r->event->timer_set) {
[333]         ngx_del_timer(r->event);
[334]     }
[335] 
[336]     rec = r->connections.elts;
[337] 
[338]     for (i = 0; i < r->connections.nelts; i++) {
[339]         if (rec[i].udp) {
[340]             ngx_close_connection(rec[i].udp);
[341]         }
[342] 
[343]         if (rec[i].tcp) {
[344]             ngx_close_connection(rec[i].tcp);
[345]         }
[346] 
[347]         if (rec[i].read_buf) {
[348]             ngx_resolver_free(r, rec[i].read_buf->start);
[349]             ngx_resolver_free(r, rec[i].read_buf);
[350]         }
[351] 
[352]         if (rec[i].write_buf) {
[353]             ngx_resolver_free(r, rec[i].write_buf->start);
[354]             ngx_resolver_free(r, rec[i].write_buf);
[355]         }
[356]     }
[357] }
[358] 
[359] 
[360] static void
[361] ngx_resolver_cleanup_tree(ngx_resolver_t *r, ngx_rbtree_t *tree)
[362] {
[363]     ngx_resolver_ctx_t   *ctx, *next;
[364]     ngx_resolver_node_t  *rn;
[365] 
[366]     while (tree->root != tree->sentinel) {
[367] 
[368]         rn = ngx_resolver_node(ngx_rbtree_min(tree->root, tree->sentinel));
[369] 
[370]         ngx_queue_remove(&rn->queue);
[371] 
[372]         for (ctx = rn->waiting; ctx; ctx = next) {
[373]             next = ctx->next;
[374] 
[375]             if (ctx->event) {
[376]                 if (ctx->event->timer_set) {
[377]                     ngx_del_timer(ctx->event);
[378]                 }
[379] 
[380]                 ngx_resolver_free(r, ctx->event);
[381]             }
[382] 
[383]             ngx_resolver_free(r, ctx);
[384]         }
[385] 
[386]         ngx_rbtree_delete(tree, &rn->node);
[387] 
[388]         ngx_resolver_free_node(r, rn);
[389]     }
[390] }
[391] 
[392] 
[393] ngx_resolver_ctx_t *
[394] ngx_resolve_start(ngx_resolver_t *r, ngx_resolver_ctx_t *temp)
[395] {
[396]     in_addr_t            addr;
[397]     ngx_resolver_ctx_t  *ctx;
[398] 
[399]     if (temp) {
[400]         addr = ngx_inet_addr(temp->name.data, temp->name.len);
[401] 
[402]         if (addr != INADDR_NONE) {
[403]             temp->resolver = r;
[404]             temp->state = NGX_OK;
[405]             temp->naddrs = 1;
[406]             temp->addrs = &temp->addr;
[407]             temp->addr.sockaddr = (struct sockaddr *) &temp->sin;
[408]             temp->addr.socklen = sizeof(struct sockaddr_in);
[409]             ngx_memzero(&temp->sin, sizeof(struct sockaddr_in));
[410]             temp->sin.sin_family = AF_INET;
[411]             temp->sin.sin_addr.s_addr = addr;
[412]             temp->quick = 1;
[413] 
[414]             return temp;
[415]         }
[416]     }
[417] 
[418]     if (r->connections.nelts == 0) {
[419]         return NGX_NO_RESOLVER;
[420]     }
[421] 
[422]     ctx = ngx_resolver_calloc(r, sizeof(ngx_resolver_ctx_t));
[423] 
[424]     if (ctx) {
[425]         ctx->resolver = r;
[426]     }
[427] 
[428]     return ctx;
[429] }
[430] 
[431] 
[432] ngx_int_t
[433] ngx_resolve_name(ngx_resolver_ctx_t *ctx)
[434] {
[435]     size_t           slen;
[436]     ngx_int_t        rc;
[437]     ngx_str_t        name;
[438]     ngx_resolver_t  *r;
[439] 
[440]     r = ctx->resolver;
[441] 
[442]     if (ctx->name.len > 0 && ctx->name.data[ctx->name.len - 1] == '.') {
[443]         ctx->name.len--;
[444]     }
[445] 
[446]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
[447]                    "resolve: \"%V\"", &ctx->name);
[448] 
[449]     if (ctx->quick) {
[450]         ctx->handler(ctx);
[451]         return NGX_OK;
[452]     }
[453] 
[454]     if (ctx->service.len) {
[455]         slen = ctx->service.len;
[456] 
[457]         if (ngx_strlchr(ctx->service.data,
[458]                         ctx->service.data + ctx->service.len, '.')
[459]             == NULL)
[460]         {
[461]             slen += sizeof("_._tcp") - 1;
[462]         }
[463] 
[464]         name.len = slen + 1 + ctx->name.len;
[465] 
[466]         name.data = ngx_resolver_alloc(r, name.len);
[467]         if (name.data == NULL) {
[468]             goto failed;
[469]         }
[470] 
[471]         if (slen == ctx->service.len) {
[472]             ngx_sprintf(name.data, "%V.%V", &ctx->service, &ctx->name);
[473] 
[474]         } else {
[475]             ngx_sprintf(name.data, "_%V._tcp.%V", &ctx->service, &ctx->name);
[476]         }
[477] 
[478]         /* lock name mutex */
[479] 
[480]         rc = ngx_resolve_name_locked(r, ctx, &name);
[481] 
[482]         ngx_resolver_free(r, name.data);
[483] 
[484]     } else {
[485]         /* lock name mutex */
[486] 
[487]         rc = ngx_resolve_name_locked(r, ctx, &ctx->name);
[488]     }
[489] 
[490]     if (rc == NGX_OK) {
[491]         return NGX_OK;
[492]     }
[493] 
[494]     /* unlock name mutex */
[495] 
[496]     if (rc == NGX_AGAIN) {
[497]         return NGX_OK;
[498]     }
[499] 
[500]     /* NGX_ERROR */
[501] 
[502]     if (ctx->event) {
[503]         ngx_resolver_free(r, ctx->event);
[504]     }
[505] 
[506] failed:
[507] 
[508]     ngx_resolver_free(r, ctx);
[509] 
[510]     return NGX_ERROR;
[511] }
[512] 
[513] 
[514] void
[515] ngx_resolve_name_done(ngx_resolver_ctx_t *ctx)
[516] {
[517]     ngx_uint_t            i;
[518]     ngx_resolver_t       *r;
[519]     ngx_resolver_ctx_t   *w, **p;
[520]     ngx_resolver_node_t  *rn;
[521] 
[522]     r = ctx->resolver;
[523] 
[524]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
[525]                    "resolve name done: %i", ctx->state);
[526] 
[527]     if (ctx->quick) {
[528]         return;
[529]     }
[530] 
[531]     if (ctx->event && ctx->event->timer_set) {
[532]         ngx_del_timer(ctx->event);
[533]     }
[534] 
[535]     /* lock name mutex */
[536] 
[537]     if (ctx->nsrvs) {
[538]         for (i = 0; i < ctx->nsrvs; i++) {
[539]             if (ctx->srvs[i].ctx) {
[540]                 ngx_resolve_name_done(ctx->srvs[i].ctx);
[541]             }
[542] 
[543]             if (ctx->srvs[i].addrs) {
[544]                 ngx_resolver_free(r, ctx->srvs[i].addrs->sockaddr);
[545]                 ngx_resolver_free(r, ctx->srvs[i].addrs);
[546]             }
[547] 
[548]             ngx_resolver_free(r, ctx->srvs[i].name.data);
[549]         }
[550] 
[551]         ngx_resolver_free(r, ctx->srvs);
[552]     }
[553] 
[554]     if (ctx->state == NGX_AGAIN || ctx->state == NGX_RESOLVE_TIMEDOUT) {
[555] 
[556]         rn = ctx->node;
[557] 
[558]         if (rn) {
[559]             p = &rn->waiting;
[560]             w = rn->waiting;
[561] 
[562]             while (w) {
[563]                 if (w == ctx) {
[564]                     *p = w->next;
[565] 
[566]                     goto done;
[567]                 }
[568] 
[569]                 p = &w->next;
[570]                 w = w->next;
[571]             }
[572] 
[573]             ngx_log_error(NGX_LOG_ALERT, r->log, 0,
[574]                           "could not cancel %V resolving", &ctx->name);
[575]         }
[576]     }
[577] 
[578] done:
[579] 
[580]     if (ctx->service.len) {
[581]         ngx_resolver_expire(r, &r->srv_rbtree, &r->srv_expire_queue);
[582] 
[583]     } else {
[584]         ngx_resolver_expire(r, &r->name_rbtree, &r->name_expire_queue);
[585]     }
[586] 
[587]     /* unlock name mutex */
[588] 
[589]     /* lock alloc mutex */
[590] 
[591]     if (ctx->event) {
[592]         ngx_resolver_free_locked(r, ctx->event);
[593]     }
[594] 
[595]     ngx_resolver_free_locked(r, ctx);
[596] 
[597]     /* unlock alloc mutex */
[598] 
[599]     if (r->event->timer_set && ngx_resolver_resend_empty(r)) {
[600]         ngx_del_timer(r->event);
[601]     }
[602] }
[603] 
[604] 
[605] static ngx_int_t
[606] ngx_resolve_name_locked(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx,
[607]     ngx_str_t *name)
[608] {
[609]     uint32_t              hash;
[610]     ngx_int_t             rc;
[611]     ngx_str_t             cname;
[612]     ngx_uint_t            i, naddrs;
[613]     ngx_queue_t          *resend_queue, *expire_queue;
[614]     ngx_rbtree_t         *tree;
[615]     ngx_resolver_ctx_t   *next, *last;
[616]     ngx_resolver_addr_t  *addrs;
[617]     ngx_resolver_node_t  *rn;
[618] 
[619]     ngx_strlow(name->data, name->data, name->len);
[620] 
[621]     hash = ngx_crc32_short(name->data, name->len);
[622] 
[623]     if (ctx->service.len) {
[624]         rn = ngx_resolver_lookup_srv(r, name, hash);
[625] 
[626]         tree = &r->srv_rbtree;
[627]         resend_queue = &r->srv_resend_queue;
[628]         expire_queue = &r->srv_expire_queue;
[629] 
[630]     } else {
[631]         rn = ngx_resolver_lookup_name(r, name, hash);
[632] 
[633]         tree = &r->name_rbtree;
[634]         resend_queue = &r->name_resend_queue;
[635]         expire_queue = &r->name_expire_queue;
[636]     }
[637] 
[638]     if (rn) {
[639] 
[640]         /* ctx can be a list after NGX_RESOLVE_CNAME */
[641]         for (last = ctx; last->next; last = last->next);
[642] 
[643]         if (rn->valid >= ngx_time()) {
[644] 
[645]             ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolve cached");
[646] 
[647]             ngx_queue_remove(&rn->queue);
[648] 
[649]             rn->expire = ngx_time() + r->expire;
[650] 
[651]             ngx_queue_insert_head(expire_queue, &rn->queue);
[652] 
[653]             naddrs = (rn->naddrs == (u_short) -1) ? 0 : rn->naddrs;
[654] #if (NGX_HAVE_INET6)
[655]             naddrs += (rn->naddrs6 == (u_short) -1) ? 0 : rn->naddrs6;
[656] #endif
[657] 
[658]             if (naddrs) {
[659] 
[660]                 if (naddrs == 1 && rn->naddrs == 1) {
[661]                     addrs = NULL;
[662] 
[663]                 } else {
[664]                     addrs = ngx_resolver_export(r, rn, 1);
[665]                     if (addrs == NULL) {
[666]                         return NGX_ERROR;
[667]                     }
[668]                 }
[669] 
[670]                 last->next = rn->waiting;
[671]                 rn->waiting = NULL;
[672] 
[673]                 /* unlock name mutex */
[674] 
[675]                 do {
[676]                     ctx->state = NGX_OK;
[677]                     ctx->valid = rn->valid;
[678]                     ctx->naddrs = naddrs;
[679] 
[680]                     if (addrs == NULL) {
[681]                         ctx->addrs = &ctx->addr;
[682]                         ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
[683]                         ctx->addr.socklen = sizeof(struct sockaddr_in);
[684]                         ngx_memzero(&ctx->sin, sizeof(struct sockaddr_in));
[685]                         ctx->sin.sin_family = AF_INET;
[686]                         ctx->sin.sin_addr.s_addr = rn->u.addr;
[687] 
[688]                     } else {
[689]                         ctx->addrs = addrs;
[690]                     }
[691] 
[692]                     next = ctx->next;
[693] 
[694]                     ctx->handler(ctx);
[695] 
[696]                     ctx = next;
[697]                 } while (ctx);
[698] 
[699]                 if (addrs != NULL) {
[700]                     ngx_resolver_free(r, addrs->sockaddr);
[701]                     ngx_resolver_free(r, addrs);
[702]                 }
[703] 
[704]                 return NGX_OK;
[705]             }
[706] 
[707]             if (rn->nsrvs) {
[708]                 last->next = rn->waiting;
[709]                 rn->waiting = NULL;
[710] 
[711]                 /* unlock name mutex */
[712] 
[713]                 do {
[714]                     next = ctx->next;
[715] 
[716]                     ngx_resolver_resolve_srv_names(ctx, rn);
[717] 
[718]                     ctx = next;
[719]                 } while (ctx);
[720] 
[721]                 return NGX_OK;
[722]             }
[723] 
[724]             /* NGX_RESOLVE_CNAME */
[725] 
[726]             if (ctx->recursion++ < NGX_RESOLVER_MAX_RECURSION) {
[727] 
[728]                 cname.len = rn->cnlen;
[729]                 cname.data = rn->u.cname;
[730] 
[731]                 return ngx_resolve_name_locked(r, ctx, &cname);
[732]             }
[733] 
[734]             last->next = rn->waiting;
[735]             rn->waiting = NULL;
[736] 
[737]             /* unlock name mutex */
[738] 
[739]             do {
[740]                 ctx->state = NGX_RESOLVE_NXDOMAIN;
[741]                 ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[742]                 next = ctx->next;
[743] 
[744]                 ctx->handler(ctx);
[745] 
[746]                 ctx = next;
[747]             } while (ctx);
[748] 
[749]             return NGX_OK;
[750]         }
[751] 
[752]         if (rn->waiting) {
[753]             if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
[754]                 return NGX_ERROR;
[755]             }
[756] 
[757]             last->next = rn->waiting;
[758]             rn->waiting = ctx;
[759]             ctx->state = NGX_AGAIN;
[760]             ctx->async = 1;
[761] 
[762]             do {
[763]                 ctx->node = rn;
[764]                 ctx = ctx->next;
[765]             } while (ctx);
[766] 
[767]             return NGX_AGAIN;
[768]         }
[769] 
[770]         ngx_queue_remove(&rn->queue);
[771] 
[772]         /* lock alloc mutex */
[773] 
[774]         if (rn->query) {
[775]             ngx_resolver_free_locked(r, rn->query);
[776]             rn->query = NULL;
[777] #if (NGX_HAVE_INET6)
[778]             rn->query6 = NULL;
[779] #endif
[780]         }
[781] 
[782]         if (rn->cnlen) {
[783]             ngx_resolver_free_locked(r, rn->u.cname);
[784]         }
[785] 
[786]         if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
[787]             ngx_resolver_free_locked(r, rn->u.addrs);
[788]         }
[789] 
[790] #if (NGX_HAVE_INET6)
[791]         if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
[792]             ngx_resolver_free_locked(r, rn->u6.addrs6);
[793]         }
[794] #endif
[795] 
[796]         if (rn->nsrvs) {
[797]             for (i = 0; i < (ngx_uint_t) rn->nsrvs; i++) {
[798]                 if (rn->u.srvs[i].name.data) {
[799]                     ngx_resolver_free_locked(r, rn->u.srvs[i].name.data);
[800]                 }
[801]             }
[802] 
[803]             ngx_resolver_free_locked(r, rn->u.srvs);
[804]         }
[805] 
[806]         /* unlock alloc mutex */
[807] 
[808]     } else {
[809] 
[810]         rn = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
[811]         if (rn == NULL) {
[812]             return NGX_ERROR;
[813]         }
[814] 
[815]         rn->name = ngx_resolver_dup(r, name->data, name->len);
[816]         if (rn->name == NULL) {
[817]             ngx_resolver_free(r, rn);
[818]             return NGX_ERROR;
[819]         }
[820] 
[821]         rn->node.key = hash;
[822]         rn->nlen = (u_short) name->len;
[823]         rn->query = NULL;
[824] #if (NGX_HAVE_INET6)
[825]         rn->query6 = NULL;
[826] #endif
[827] 
[828]         ngx_rbtree_insert(tree, &rn->node);
[829]     }
[830] 
[831]     if (ctx->service.len) {
[832]         rc = ngx_resolver_create_srv_query(r, rn, name);
[833] 
[834]     } else {
[835]         rc = ngx_resolver_create_name_query(r, rn, name);
[836]     }
[837] 
[838]     if (rc == NGX_ERROR) {
[839]         goto failed;
[840]     }
[841] 
[842]     if (rc == NGX_DECLINED) {
[843]         ngx_rbtree_delete(tree, &rn->node);
[844] 
[845]         ngx_resolver_free(r, rn->query);
[846]         ngx_resolver_free(r, rn->name);
[847]         ngx_resolver_free(r, rn);
[848] 
[849]         do {
[850]             ctx->state = NGX_RESOLVE_NXDOMAIN;
[851]             next = ctx->next;
[852] 
[853]             ctx->handler(ctx);
[854] 
[855]             ctx = next;
[856]         } while (ctx);
[857] 
[858]         return NGX_OK;
[859]     }
[860] 
[861]     rn->last_connection = r->last_connection++;
[862]     if (r->last_connection == r->connections.nelts) {
[863]         r->last_connection = 0;
[864]     }
[865] 
[866]     rn->naddrs = r->ipv4 ? (u_short) -1 : 0;
[867]     rn->tcp = 0;
[868] #if (NGX_HAVE_INET6)
[869]     rn->naddrs6 = r->ipv6 ? (u_short) -1 : 0;
[870]     rn->tcp6 = 0;
[871] #endif
[872]     rn->nsrvs = 0;
[873] 
[874]     if (ngx_resolver_send_query(r, rn) != NGX_OK) {
[875] 
[876]         /* immediately retry once on failure */
[877] 
[878]         rn->last_connection++;
[879]         if (rn->last_connection == r->connections.nelts) {
[880]             rn->last_connection = 0;
[881]         }
[882] 
[883]         (void) ngx_resolver_send_query(r, rn);
[884]     }
[885] 
[886]     if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
[887]         goto failed;
[888]     }
[889] 
[890]     if (ngx_resolver_resend_empty(r)) {
[891]         ngx_add_timer(r->event, (ngx_msec_t) (r->resend_timeout * 1000));
[892]     }
[893] 
[894]     rn->expire = ngx_time() + r->resend_timeout;
[895] 
[896]     ngx_queue_insert_head(resend_queue, &rn->queue);
[897] 
[898]     rn->code = 0;
[899]     rn->cnlen = 0;
[900]     rn->valid = 0;
[901]     rn->ttl = NGX_MAX_UINT32_VALUE;
[902]     rn->waiting = ctx;
[903] 
[904]     ctx->state = NGX_AGAIN;
[905]     ctx->async = 1;
[906] 
[907]     do {
[908]         ctx->node = rn;
[909]         ctx = ctx->next;
[910]     } while (ctx);
[911] 
[912]     return NGX_AGAIN;
[913] 
[914] failed:
[915] 
[916]     ngx_rbtree_delete(tree, &rn->node);
[917] 
[918]     if (rn->query) {
[919]         ngx_resolver_free(r, rn->query);
[920]     }
[921] 
[922]     ngx_resolver_free(r, rn->name);
[923] 
[924]     ngx_resolver_free(r, rn);
[925] 
[926]     return NGX_ERROR;
[927] }
[928] 
[929] 
[930] ngx_int_t
[931] ngx_resolve_addr(ngx_resolver_ctx_t *ctx)
[932] {
[933]     u_char               *name;
[934]     in_addr_t             addr;
[935]     ngx_queue_t          *resend_queue, *expire_queue;
[936]     ngx_rbtree_t         *tree;
[937]     ngx_resolver_t       *r;
[938]     struct sockaddr_in   *sin;
[939]     ngx_resolver_node_t  *rn;
[940] #if (NGX_HAVE_INET6)
[941]     uint32_t              hash;
[942]     struct sockaddr_in6  *sin6;
[943] #endif
[944] 
[945] #if (NGX_SUPPRESS_WARN)
[946]     addr = 0;
[947] #if (NGX_HAVE_INET6)
[948]     hash = 0;
[949]     sin6 = NULL;
[950] #endif
[951] #endif
[952] 
[953]     r = ctx->resolver;
[954] 
[955]     switch (ctx->addr.sockaddr->sa_family) {
[956] 
[957] #if (NGX_HAVE_INET6)
[958]     case AF_INET6:
[959]         sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;
[960]         hash = ngx_crc32_short(sin6->sin6_addr.s6_addr, 16);
[961] 
[962]         /* lock addr mutex */
[963] 
[964]         rn = ngx_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);
[965] 
[966]         tree = &r->addr6_rbtree;
[967]         resend_queue = &r->addr6_resend_queue;
[968]         expire_queue = &r->addr6_expire_queue;
[969] 
[970]         break;
[971] #endif
[972] 
[973]     default: /* AF_INET */
[974]         sin = (struct sockaddr_in *) ctx->addr.sockaddr;
[975]         addr = ntohl(sin->sin_addr.s_addr);
[976] 
[977]         /* lock addr mutex */
[978] 
[979]         rn = ngx_resolver_lookup_addr(r, addr);
[980] 
[981]         tree = &r->addr_rbtree;
[982]         resend_queue = &r->addr_resend_queue;
[983]         expire_queue = &r->addr_expire_queue;
[984]     }
[985] 
[986]     if (rn) {
[987] 
[988]         if (rn->valid >= ngx_time()) {
[989] 
[990]             ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolve cached");
[991] 
[992]             ngx_queue_remove(&rn->queue);
[993] 
[994]             rn->expire = ngx_time() + r->expire;
[995] 
[996]             ngx_queue_insert_head(expire_queue, &rn->queue);
[997] 
[998]             name = ngx_resolver_dup(r, rn->name, rn->nlen);
[999]             if (name == NULL) {
[1000]                 ngx_resolver_free(r, ctx);
[1001]                 return NGX_ERROR;
[1002]             }
[1003] 
[1004]             ctx->name.len = rn->nlen;
[1005]             ctx->name.data = name;
[1006] 
[1007]             /* unlock addr mutex */
[1008] 
[1009]             ctx->state = NGX_OK;
[1010]             ctx->valid = rn->valid;
[1011] 
[1012]             ctx->handler(ctx);
[1013] 
[1014]             ngx_resolver_free(r, name);
[1015] 
[1016]             return NGX_OK;
[1017]         }
[1018] 
[1019]         if (rn->waiting) {
[1020]             if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
[1021]                 return NGX_ERROR;
[1022]             }
[1023] 
[1024]             ctx->next = rn->waiting;
[1025]             rn->waiting = ctx;
[1026]             ctx->state = NGX_AGAIN;
[1027]             ctx->async = 1;
[1028]             ctx->node = rn;
[1029] 
[1030]             /* unlock addr mutex */
[1031] 
[1032]             return NGX_OK;
[1033]         }
[1034] 
[1035]         ngx_queue_remove(&rn->queue);
[1036] 
[1037]         ngx_resolver_free(r, rn->query);
[1038]         rn->query = NULL;
[1039] #if (NGX_HAVE_INET6)
[1040]         rn->query6 = NULL;
[1041] #endif
[1042] 
[1043]     } else {
[1044]         rn = ngx_resolver_alloc(r, sizeof(ngx_resolver_node_t));
[1045]         if (rn == NULL) {
[1046]             goto failed;
[1047]         }
[1048] 
[1049]         switch (ctx->addr.sockaddr->sa_family) {
[1050] 
[1051] #if (NGX_HAVE_INET6)
[1052]         case AF_INET6:
[1053]             rn->addr6 = sin6->sin6_addr;
[1054]             rn->node.key = hash;
[1055]             break;
[1056] #endif
[1057] 
[1058]         default: /* AF_INET */
[1059]             rn->node.key = addr;
[1060]         }
[1061] 
[1062]         rn->query = NULL;
[1063] #if (NGX_HAVE_INET6)
[1064]         rn->query6 = NULL;
[1065] #endif
[1066] 
[1067]         ngx_rbtree_insert(tree, &rn->node);
[1068]     }
[1069] 
[1070]     if (ngx_resolver_create_addr_query(r, rn, &ctx->addr) != NGX_OK) {
[1071]         goto failed;
[1072]     }
[1073] 
[1074]     rn->last_connection = r->last_connection++;
[1075]     if (r->last_connection == r->connections.nelts) {
[1076]         r->last_connection = 0;
[1077]     }
[1078] 
[1079]     rn->naddrs = (u_short) -1;
[1080]     rn->tcp = 0;
[1081] #if (NGX_HAVE_INET6)
[1082]     rn->naddrs6 = (u_short) -1;
[1083]     rn->tcp6 = 0;
[1084] #endif
[1085]     rn->nsrvs = 0;
[1086] 
[1087]     if (ngx_resolver_send_query(r, rn) != NGX_OK) {
[1088] 
[1089]         /* immediately retry once on failure */
[1090] 
[1091]         rn->last_connection++;
[1092]         if (rn->last_connection == r->connections.nelts) {
[1093]             rn->last_connection = 0;
[1094]         }
[1095] 
[1096]         (void) ngx_resolver_send_query(r, rn);
[1097]     }
[1098] 
[1099]     if (ngx_resolver_set_timeout(r, ctx) != NGX_OK) {
[1100]         goto failed;
[1101]     }
[1102] 
[1103]     if (ngx_resolver_resend_empty(r)) {
[1104]         ngx_add_timer(r->event, (ngx_msec_t) (r->resend_timeout * 1000));
[1105]     }
[1106] 
[1107]     rn->expire = ngx_time() + r->resend_timeout;
[1108] 
[1109]     ngx_queue_insert_head(resend_queue, &rn->queue);
[1110] 
[1111]     rn->code = 0;
[1112]     rn->cnlen = 0;
[1113]     rn->name = NULL;
[1114]     rn->nlen = 0;
[1115]     rn->valid = 0;
[1116]     rn->ttl = NGX_MAX_UINT32_VALUE;
[1117]     rn->waiting = ctx;
[1118] 
[1119]     /* unlock addr mutex */
[1120] 
[1121]     ctx->state = NGX_AGAIN;
[1122]     ctx->async = 1;
[1123]     ctx->node = rn;
[1124] 
[1125]     return NGX_OK;
[1126] 
[1127] failed:
[1128] 
[1129]     if (rn) {
[1130]         ngx_rbtree_delete(tree, &rn->node);
[1131] 
[1132]         if (rn->query) {
[1133]             ngx_resolver_free(r, rn->query);
[1134]         }
[1135] 
[1136]         ngx_resolver_free(r, rn);
[1137]     }
[1138] 
[1139]     /* unlock addr mutex */
[1140] 
[1141]     if (ctx->event) {
[1142]         ngx_resolver_free(r, ctx->event);
[1143]     }
[1144] 
[1145]     ngx_resolver_free(r, ctx);
[1146] 
[1147]     return NGX_ERROR;
[1148] }
[1149] 
[1150] 
[1151] void
[1152] ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx)
[1153] {
[1154]     ngx_queue_t          *expire_queue;
[1155]     ngx_rbtree_t         *tree;
[1156]     ngx_resolver_t       *r;
[1157]     ngx_resolver_ctx_t   *w, **p;
[1158]     ngx_resolver_node_t  *rn;
[1159] 
[1160]     r = ctx->resolver;
[1161] 
[1162]     switch (ctx->addr.sockaddr->sa_family) {
[1163] 
[1164] #if (NGX_HAVE_INET6)
[1165]     case AF_INET6:
[1166]         tree = &r->addr6_rbtree;
[1167]         expire_queue = &r->addr6_expire_queue;
[1168]         break;
[1169] #endif
[1170] 
[1171]     default: /* AF_INET */
[1172]         tree = &r->addr_rbtree;
[1173]         expire_queue = &r->addr_expire_queue;
[1174]     }
[1175] 
[1176]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
[1177]                    "resolve addr done: %i", ctx->state);
[1178] 
[1179]     if (ctx->event && ctx->event->timer_set) {
[1180]         ngx_del_timer(ctx->event);
[1181]     }
[1182] 
[1183]     /* lock addr mutex */
[1184] 
[1185]     if (ctx->state == NGX_AGAIN || ctx->state == NGX_RESOLVE_TIMEDOUT) {
[1186] 
[1187]         rn = ctx->node;
[1188] 
[1189]         if (rn) {
[1190]             p = &rn->waiting;
[1191]             w = rn->waiting;
[1192] 
[1193]             while (w) {
[1194]                 if (w == ctx) {
[1195]                     *p = w->next;
[1196] 
[1197]                     goto done;
[1198]                 }
[1199] 
[1200]                 p = &w->next;
[1201]                 w = w->next;
[1202]             }
[1203]         }
[1204] 
[1205]         {
[1206]             u_char     text[NGX_SOCKADDR_STRLEN];
[1207]             ngx_str_t  addrtext;
[1208] 
[1209]             addrtext.data = text;
[1210]             addrtext.len = ngx_sock_ntop(ctx->addr.sockaddr, ctx->addr.socklen,
[1211]                                          text, NGX_SOCKADDR_STRLEN, 0);
[1212] 
[1213]             ngx_log_error(NGX_LOG_ALERT, r->log, 0,
[1214]                           "could not cancel %V resolving", &addrtext);
[1215]         }
[1216]     }
[1217] 
[1218] done:
[1219] 
[1220]     ngx_resolver_expire(r, tree, expire_queue);
[1221] 
[1222]     /* unlock addr mutex */
[1223] 
[1224]     /* lock alloc mutex */
[1225] 
[1226]     if (ctx->event) {
[1227]         ngx_resolver_free_locked(r, ctx->event);
[1228]     }
[1229] 
[1230]     ngx_resolver_free_locked(r, ctx);
[1231] 
[1232]     /* unlock alloc mutex */
[1233] 
[1234]     if (r->event->timer_set && ngx_resolver_resend_empty(r)) {
[1235]         ngx_del_timer(r->event);
[1236]     }
[1237] }
[1238] 
[1239] 
[1240] static void
[1241] ngx_resolver_expire(ngx_resolver_t *r, ngx_rbtree_t *tree, ngx_queue_t *queue)
[1242] {
[1243]     time_t                now;
[1244]     ngx_uint_t            i;
[1245]     ngx_queue_t          *q;
[1246]     ngx_resolver_node_t  *rn;
[1247] 
[1248]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver expire");
[1249] 
[1250]     now = ngx_time();
[1251] 
[1252]     for (i = 0; i < 2; i++) {
[1253]         if (ngx_queue_empty(queue)) {
[1254]             return;
[1255]         }
[1256] 
[1257]         q = ngx_queue_last(queue);
[1258] 
[1259]         rn = ngx_queue_data(q, ngx_resolver_node_t, queue);
[1260] 
[1261]         if (now <= rn->expire) {
[1262]             return;
[1263]         }
[1264] 
[1265]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
[1266]                        "resolver expire \"%*s\"", (size_t) rn->nlen, rn->name);
[1267] 
[1268]         ngx_queue_remove(q);
[1269] 
[1270]         ngx_rbtree_delete(tree, &rn->node);
[1271] 
[1272]         ngx_resolver_free_node(r, rn);
[1273]     }
[1274] }
[1275] 
[1276] 
[1277] static ngx_int_t
[1278] ngx_resolver_send_query(ngx_resolver_t *r, ngx_resolver_node_t *rn)
[1279] {
[1280]     ngx_int_t                   rc;
[1281]     ngx_resolver_connection_t  *rec;
[1282] 
[1283]     rec = r->connections.elts;
[1284]     rec = &rec[rn->last_connection];
[1285] 
[1286]     if (rec->log.handler == NULL) {
[1287]         rec->log = *r->log;
[1288]         rec->log.handler = ngx_resolver_log_error;
[1289]         rec->log.data = rec;
[1290]         rec->log.action = "resolving";
[1291]     }
[1292] 
[1293]     if (rn->query && rn->naddrs == (u_short) -1) {
[1294]         rc = rn->tcp ? ngx_resolver_send_tcp_query(r, rec, rn->query, rn->qlen)
[1295]                      : ngx_resolver_send_udp_query(r, rec, rn->query, rn->qlen);
[1296] 
[1297]         if (rc != NGX_OK) {
[1298]             return rc;
[1299]         }
[1300]     }
[1301] 
[1302] #if (NGX_HAVE_INET6)
[1303] 
[1304]     if (rn->query6 && rn->naddrs6 == (u_short) -1) {
[1305]         rc = rn->tcp6
[1306]                     ? ngx_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen)
[1307]                     : ngx_resolver_send_udp_query(r, rec, rn->query6, rn->qlen);
[1308] 
[1309]         if (rc != NGX_OK) {
[1310]             return rc;
[1311]         }
[1312]     }
[1313] 
[1314] #endif
[1315] 
[1316]     return NGX_OK;
[1317] }
[1318] 
[1319] 
[1320] static ngx_int_t
[1321] ngx_resolver_send_udp_query(ngx_resolver_t *r, ngx_resolver_connection_t  *rec,
[1322]     u_char *query, u_short qlen)
[1323] {
[1324]     ssize_t  n;
[1325] 
[1326]     if (rec->udp == NULL) {
[1327]         if (ngx_udp_connect(rec) != NGX_OK) {
[1328]             return NGX_ERROR;
[1329]         }
[1330] 
[1331]         rec->udp->data = rec;
[1332]         rec->udp->read->handler = ngx_resolver_udp_read;
[1333]         rec->udp->read->resolver = 1;
[1334]     }
[1335] 
[1336]     n = ngx_send(rec->udp, query, qlen);
[1337] 
[1338]     if (n == NGX_ERROR) {
[1339]         goto failed;
[1340]     }
[1341] 
[1342]     if ((size_t) n != (size_t) qlen) {
[1343]         ngx_log_error(NGX_LOG_CRIT, &rec->log, 0, "send() incomplete");
[1344]         goto failed;
[1345]     }
[1346] 
[1347]     return NGX_OK;
[1348] 
[1349] failed:
[1350] 
[1351]     ngx_close_connection(rec->udp);
[1352]     rec->udp = NULL;
[1353] 
[1354]     return NGX_ERROR;
[1355] }
[1356] 
[1357] 
[1358] static ngx_int_t
[1359] ngx_resolver_send_tcp_query(ngx_resolver_t *r, ngx_resolver_connection_t *rec,
[1360]     u_char *query, u_short qlen)
[1361] {
[1362]     ngx_buf_t  *b;
[1363]     ngx_int_t   rc;
[1364] 
[1365]     rc = NGX_OK;
[1366] 
[1367]     if (rec->tcp == NULL) {
[1368]         b = rec->read_buf;
[1369] 
[1370]         if (b == NULL) {
[1371]             b = ngx_resolver_calloc(r, sizeof(ngx_buf_t));
[1372]             if (b == NULL) {
[1373]                 return NGX_ERROR;
[1374]             }
[1375] 
[1376]             b->start = ngx_resolver_alloc(r, NGX_RESOLVER_TCP_RSIZE);
[1377]             if (b->start == NULL) {
[1378]                 ngx_resolver_free(r, b);
[1379]                 return NGX_ERROR;
[1380]             }
[1381] 
[1382]             b->end = b->start + NGX_RESOLVER_TCP_RSIZE;
[1383] 
[1384]             rec->read_buf = b;
[1385]         }
[1386] 
[1387]         b->pos = b->start;
[1388]         b->last = b->start;
[1389] 
[1390]         b = rec->write_buf;
[1391] 
[1392]         if (b == NULL) {
[1393]             b = ngx_resolver_calloc(r, sizeof(ngx_buf_t));
[1394]             if (b == NULL) {
[1395]                 return NGX_ERROR;
[1396]             }
[1397] 
[1398]             b->start = ngx_resolver_alloc(r, NGX_RESOLVER_TCP_WSIZE);
[1399]             if (b->start == NULL) {
[1400]                 ngx_resolver_free(r, b);
[1401]                 return NGX_ERROR;
[1402]             }
[1403] 
[1404]             b->end = b->start + NGX_RESOLVER_TCP_WSIZE;
[1405] 
[1406]             rec->write_buf = b;
[1407]         }
[1408] 
[1409]         b->pos = b->start;
[1410]         b->last = b->start;
[1411] 
[1412]         rc = ngx_tcp_connect(rec);
[1413]         if (rc == NGX_ERROR) {
[1414]             return NGX_ERROR;
[1415]         }
[1416] 
[1417]         rec->tcp->data = rec;
[1418]         rec->tcp->write->handler = ngx_resolver_tcp_write;
[1419]         rec->tcp->write->cancelable = 1;
[1420]         rec->tcp->read->handler = ngx_resolver_tcp_read;
[1421]         rec->tcp->read->resolver = 1;
[1422] 
[1423]         ngx_add_timer(rec->tcp->write, (ngx_msec_t) (r->tcp_timeout * 1000));
[1424]     }
[1425] 
[1426]     b = rec->write_buf;
[1427] 
[1428]     if (b->end - b->last <  2 + qlen) {
[1429]         ngx_log_error(NGX_LOG_CRIT, &rec->log, 0, "buffer overflow");
[1430]         return NGX_ERROR;
[1431]     }
[1432] 
[1433]     *b->last++ = (u_char) (qlen >> 8);
[1434]     *b->last++ = (u_char) qlen;
[1435]     b->last = ngx_cpymem(b->last, query, qlen);
[1436] 
[1437]     if (rc == NGX_OK) {
[1438]         ngx_resolver_tcp_write(rec->tcp->write);
[1439]     }
[1440] 
[1441]     return NGX_OK;
[1442] }
[1443] 
[1444] 
[1445] static void
[1446] ngx_resolver_resend_handler(ngx_event_t *ev)
[1447] {
[1448]     time_t           timer, atimer, stimer, ntimer;
[1449] #if (NGX_HAVE_INET6)
[1450]     time_t           a6timer;
[1451] #endif
[1452]     ngx_resolver_t  *r;
[1453] 
[1454]     r = ev->data;
[1455] 
[1456]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->log, 0,
[1457]                    "resolver resend handler");
[1458] 
[1459]     /* lock name mutex */
[1460] 
[1461]     ntimer = ngx_resolver_resend(r, &r->name_rbtree, &r->name_resend_queue);
[1462] 
[1463]     stimer = ngx_resolver_resend(r, &r->srv_rbtree, &r->srv_resend_queue);
[1464] 
[1465]     /* unlock name mutex */
[1466] 
[1467]     /* lock addr mutex */
[1468] 
[1469]     atimer = ngx_resolver_resend(r, &r->addr_rbtree, &r->addr_resend_queue);
[1470] 
[1471]     /* unlock addr mutex */
[1472] 
[1473] #if (NGX_HAVE_INET6)
[1474] 
[1475]     /* lock addr6 mutex */
[1476] 
[1477]     a6timer = ngx_resolver_resend(r, &r->addr6_rbtree, &r->addr6_resend_queue);
[1478] 
[1479]     /* unlock addr6 mutex */
[1480] 
[1481] #endif
[1482] 
[1483]     timer = ntimer;
[1484] 
[1485]     if (timer == 0) {
[1486]         timer = atimer;
[1487] 
[1488]     } else if (atimer) {
[1489]         timer = ngx_min(timer, atimer);
[1490]     }
[1491] 
[1492]     if (timer == 0) {
[1493]         timer = stimer;
[1494] 
[1495]     } else if (stimer) {
[1496]         timer = ngx_min(timer, stimer);
[1497]     }
[1498] 
[1499] #if (NGX_HAVE_INET6)
[1500] 
[1501]     if (timer == 0) {
[1502]         timer = a6timer;
[1503] 
[1504]     } else if (a6timer) {
[1505]         timer = ngx_min(timer, a6timer);
[1506]     }
[1507] 
[1508] #endif
[1509] 
[1510]     if (timer) {
[1511]         ngx_add_timer(r->event, (ngx_msec_t) (timer * 1000));
[1512]     }
[1513] }
[1514] 
[1515] 
[1516] static time_t
[1517] ngx_resolver_resend(ngx_resolver_t *r, ngx_rbtree_t *tree, ngx_queue_t *queue)
[1518] {
[1519]     time_t                now;
[1520]     ngx_queue_t          *q;
[1521]     ngx_resolver_node_t  *rn;
[1522] 
[1523]     now = ngx_time();
[1524] 
[1525]     for ( ;; ) {
[1526]         if (ngx_queue_empty(queue)) {
[1527]             return 0;
[1528]         }
[1529] 
[1530]         q = ngx_queue_last(queue);
[1531] 
[1532]         rn = ngx_queue_data(q, ngx_resolver_node_t, queue);
[1533] 
[1534]         if (now < rn->expire) {
[1535]             return rn->expire - now;
[1536]         }
[1537] 
[1538]         ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
[1539]                        "resolver resend \"%*s\" %p",
[1540]                        (size_t) rn->nlen, rn->name, rn->waiting);
[1541] 
[1542]         ngx_queue_remove(q);
[1543] 
[1544]         if (rn->waiting) {
[1545] 
[1546]             if (++rn->last_connection == r->connections.nelts) {
[1547]                 rn->last_connection = 0;
[1548]             }
[1549] 
[1550]             (void) ngx_resolver_send_query(r, rn);
[1551] 
[1552]             rn->expire = now + r->resend_timeout;
[1553] 
[1554]             ngx_queue_insert_head(queue, q);
[1555] 
[1556]             continue;
[1557]         }
[1558] 
[1559]         ngx_rbtree_delete(tree, &rn->node);
[1560] 
[1561]         ngx_resolver_free_node(r, rn);
[1562]     }
[1563] }
[1564] 
[1565] 
[1566] static ngx_uint_t
[1567] ngx_resolver_resend_empty(ngx_resolver_t *r)
[1568] {
[1569]     return ngx_queue_empty(&r->name_resend_queue)
[1570]            && ngx_queue_empty(&r->srv_resend_queue)
[1571] #if (NGX_HAVE_INET6)
[1572]            && ngx_queue_empty(&r->addr6_resend_queue)
[1573] #endif
[1574]            && ngx_queue_empty(&r->addr_resend_queue);
[1575] }
[1576] 
[1577] 
[1578] static void
[1579] ngx_resolver_udp_read(ngx_event_t *rev)
[1580] {
[1581]     ssize_t                     n;
[1582]     ngx_connection_t           *c;
[1583]     ngx_resolver_connection_t  *rec;
[1584]     u_char                      buf[NGX_RESOLVER_UDP_SIZE];
[1585] 
[1586]     c = rev->data;
[1587]     rec = c->data;
[1588] 
[1589]     do {
[1590]         n = ngx_udp_recv(c, buf, NGX_RESOLVER_UDP_SIZE);
[1591] 
[1592]         if (n == NGX_AGAIN) {
[1593]             break;
[1594]         }
[1595] 
[1596]         if (n == NGX_ERROR) {
[1597]             goto failed;
[1598]         }
[1599] 
[1600]         ngx_resolver_process_response(rec->resolver, buf, n, 0);
[1601] 
[1602]     } while (rev->ready);
[1603] 
[1604]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[1605]         goto failed;
[1606]     }
[1607] 
[1608]     return;
[1609] 
[1610] failed:
[1611] 
[1612]     ngx_close_connection(rec->udp);
[1613]     rec->udp = NULL;
[1614] }
[1615] 
[1616] 
[1617] static void
[1618] ngx_resolver_tcp_write(ngx_event_t *wev)
[1619] {
[1620]     off_t                       sent;
[1621]     ssize_t                     n;
[1622]     ngx_buf_t                  *b;
[1623]     ngx_resolver_t             *r;
[1624]     ngx_connection_t           *c;
[1625]     ngx_resolver_connection_t  *rec;
[1626] 
[1627]     c = wev->data;
[1628]     rec = c->data;
[1629]     b = rec->write_buf;
[1630]     r = rec->resolver;
[1631] 
[1632]     if (wev->timedout) {
[1633]         goto failed;
[1634]     }
[1635] 
[1636]     sent = c->sent;
[1637] 
[1638]     while (wev->ready && b->pos < b->last) {
[1639]         n = ngx_send(c, b->pos, b->last - b->pos);
[1640] 
[1641]         if (n == NGX_AGAIN) {
[1642]             break;
[1643]         }
[1644] 
[1645]         if (n == NGX_ERROR) {
[1646]             goto failed;
[1647]         }
[1648] 
[1649]         b->pos += n;
[1650]     }
[1651] 
[1652]     if (b->pos != b->start) {
[1653]         b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
[1654]         b->pos = b->start;
[1655]     }
[1656] 
[1657]     if (c->sent != sent) {
[1658]         ngx_add_timer(wev, (ngx_msec_t) (r->tcp_timeout * 1000));
[1659]     }
[1660] 
[1661]     if (ngx_handle_write_event(wev, 0) != NGX_OK) {
[1662]         goto failed;
[1663]     }
[1664] 
[1665]     return;
[1666] 
[1667] failed:
[1668] 
[1669]     ngx_close_connection(c);
[1670]     rec->tcp = NULL;
[1671] }
[1672] 
[1673] 
[1674] static void
[1675] ngx_resolver_tcp_read(ngx_event_t *rev)
[1676] {
[1677]     u_char                     *p;
[1678]     size_t                      size;
[1679]     ssize_t                     n;
[1680]     u_short                     qlen;
[1681]     ngx_buf_t                  *b;
[1682]     ngx_resolver_t             *r;
[1683]     ngx_connection_t           *c;
[1684]     ngx_resolver_connection_t  *rec;
[1685] 
[1686]     c = rev->data;
[1687]     rec = c->data;
[1688]     b = rec->read_buf;
[1689]     r = rec->resolver;
[1690] 
[1691]     while (rev->ready) {
[1692]         n = ngx_recv(c, b->last, b->end - b->last);
[1693] 
[1694]         if (n == NGX_AGAIN) {
[1695]             break;
[1696]         }
[1697] 
[1698]         if (n == NGX_ERROR || n == 0) {
[1699]             goto failed;
[1700]         }
[1701] 
[1702]         b->last += n;
[1703] 
[1704]         for ( ;; ) {
[1705]             p = b->pos;
[1706]             size = b->last - p;
[1707] 
[1708]             if (size < 2) {
[1709]                 break;
[1710]             }
[1711] 
[1712]             qlen = (u_short) *p++ << 8;
[1713]             qlen += *p++;
[1714] 
[1715]             if (size < (size_t) (2 + qlen)) {
[1716]                 break;
[1717]             }
[1718] 
[1719]             ngx_resolver_process_response(r, p, qlen, 1);
[1720] 
[1721]             b->pos += 2 + qlen;
[1722]         }
[1723] 
[1724]         if (b->pos != b->start) {
[1725]             b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
[1726]             b->pos = b->start;
[1727]         }
[1728]     }
[1729] 
[1730]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[1731]         goto failed;
[1732]     }
[1733] 
[1734]     return;
[1735] 
[1736] failed:
[1737] 
[1738]     ngx_close_connection(c);
[1739]     rec->tcp = NULL;
[1740] }
[1741] 
[1742] 
[1743] static void
[1744] ngx_resolver_process_response(ngx_resolver_t *r, u_char *buf, size_t n,
[1745]     ngx_uint_t tcp)
[1746] {
[1747]     char                 *err;
[1748]     ngx_uint_t            i, times, ident, qident, flags, code, nqs, nan, trunc,
[1749]                           qtype, qclass;
[1750] #if (NGX_HAVE_INET6)
[1751]     ngx_uint_t            qident6;
[1752] #endif
[1753]     ngx_queue_t          *q;
[1754]     ngx_resolver_qs_t    *qs;
[1755]     ngx_resolver_hdr_t   *response;
[1756]     ngx_resolver_node_t  *rn;
[1757] 
[1758]     if (n < sizeof(ngx_resolver_hdr_t)) {
[1759]         goto short_response;
[1760]     }
[1761] 
[1762]     response = (ngx_resolver_hdr_t *) buf;
[1763] 
[1764]     ident = (response->ident_hi << 8) + response->ident_lo;
[1765]     flags = (response->flags_hi << 8) + response->flags_lo;
[1766]     nqs = (response->nqs_hi << 8) + response->nqs_lo;
[1767]     nan = (response->nan_hi << 8) + response->nan_lo;
[1768]     trunc = flags & 0x0200;
[1769] 
[1770]     ngx_log_debug6(NGX_LOG_DEBUG_CORE, r->log, 0,
[1771]                    "resolver DNS response %ui fl:%04Xi %ui/%ui/%ud/%ud",
[1772]                    ident, flags, nqs, nan,
[1773]                    (response->nns_hi << 8) + response->nns_lo,
[1774]                    (response->nar_hi << 8) + response->nar_lo);
[1775] 
[1776]     /* response to a standard query */
[1777]     if ((flags & 0xf870) != 0x8000 || (trunc && tcp)) {
[1778]         ngx_log_error(r->log_level, r->log, 0,
[1779]                       "invalid %s DNS response %ui fl:%04Xi",
[1780]                       tcp ? "TCP" : "UDP", ident, flags);
[1781]         return;
[1782]     }
[1783] 
[1784]     code = flags & 0xf;
[1785] 
[1786]     if (code == NGX_RESOLVE_FORMERR) {
[1787] 
[1788]         times = 0;
[1789] 
[1790]         for (q = ngx_queue_head(&r->name_resend_queue);
[1791]              q != ngx_queue_sentinel(&r->name_resend_queue) && times++ < 100;
[1792]              q = ngx_queue_next(q))
[1793]         {
[1794]             rn = ngx_queue_data(q, ngx_resolver_node_t, queue);
[1795] 
[1796]             if (rn->query) {
[1797]                 qident = (rn->query[0] << 8) + rn->query[1];
[1798] 
[1799]                 if (qident == ident) {
[1800]                     goto dns_error_name;
[1801]                 }
[1802]             }
[1803] 
[1804] #if (NGX_HAVE_INET6)
[1805]             if (rn->query6) {
[1806]                 qident6 = (rn->query6[0] << 8) + rn->query6[1];
[1807] 
[1808]                 if (qident6 == ident) {
[1809]                     goto dns_error_name;
[1810]                 }
[1811]             }
[1812] #endif
[1813]         }
[1814] 
[1815]         goto dns_error;
[1816]     }
[1817] 
[1818]     if (code > NGX_RESOLVE_REFUSED) {
[1819]         goto dns_error;
[1820]     }
[1821] 
[1822]     if (nqs != 1) {
[1823]         err = "invalid number of questions in DNS response";
[1824]         goto done;
[1825]     }
[1826] 
[1827]     i = sizeof(ngx_resolver_hdr_t);
[1828] 
[1829]     while (i < (ngx_uint_t) n) {
[1830] 
[1831]         if (buf[i] & 0xc0) {
[1832]             err = "unexpected compression pointer in DNS response";
[1833]             goto done;
[1834]         }
[1835] 
[1836]         if (buf[i] == '\0') {
[1837]             goto found;
[1838]         }
[1839] 
[1840]         i += 1 + buf[i];
[1841]     }
[1842] 
[1843]     goto short_response;
[1844] 
[1845] found:
[1846] 
[1847]     if (i++ == sizeof(ngx_resolver_hdr_t)) {
[1848]         err = "zero-length domain name in DNS response";
[1849]         goto done;
[1850]     }
[1851] 
[1852]     if (i + sizeof(ngx_resolver_qs_t) + nan * (2 + sizeof(ngx_resolver_an_t))
[1853]         > (ngx_uint_t) n)
[1854]     {
[1855]         goto short_response;
[1856]     }
[1857] 
[1858]     qs = (ngx_resolver_qs_t *) &buf[i];
[1859] 
[1860]     qtype = (qs->type_hi << 8) + qs->type_lo;
[1861]     qclass = (qs->class_hi << 8) + qs->class_lo;
[1862] 
[1863]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
[1864]                    "resolver DNS response qt:%ui cl:%ui", qtype, qclass);
[1865] 
[1866]     if (qclass != 1) {
[1867]         ngx_log_error(r->log_level, r->log, 0,
[1868]                       "unknown query class %ui in DNS response", qclass);
[1869]         return;
[1870]     }
[1871] 
[1872]     switch (qtype) {
[1873] 
[1874]     case NGX_RESOLVE_A:
[1875] #if (NGX_HAVE_INET6)
[1876]     case NGX_RESOLVE_AAAA:
[1877] #endif
[1878] 
[1879]         ngx_resolver_process_a(r, buf, n, ident, code, qtype, nan, trunc,
[1880]                                i + sizeof(ngx_resolver_qs_t));
[1881] 
[1882]         break;
[1883] 
[1884]     case NGX_RESOLVE_SRV:
[1885] 
[1886]         ngx_resolver_process_srv(r, buf, n, ident, code, nan, trunc,
[1887]                                  i + sizeof(ngx_resolver_qs_t));
[1888] 
[1889]         break;
[1890] 
[1891]     case NGX_RESOLVE_PTR:
[1892] 
[1893]         ngx_resolver_process_ptr(r, buf, n, ident, code, nan);
[1894] 
[1895]         break;
[1896] 
[1897]     default:
[1898]         ngx_log_error(r->log_level, r->log, 0,
[1899]                       "unknown query type %ui in DNS response", qtype);
[1900]         return;
[1901]     }
[1902] 
[1903]     return;
[1904] 
[1905] short_response:
[1906] 
[1907]     err = "short DNS response";
[1908] 
[1909] done:
[1910] 
[1911]     ngx_log_error(r->log_level, r->log, 0, err);
[1912] 
[1913]     return;
[1914] 
[1915] dns_error_name:
[1916] 
[1917]     ngx_log_error(r->log_level, r->log, 0,
[1918]                   "DNS error (%ui: %s), query id:%ui, name:\"%*s\"",
[1919]                   code, ngx_resolver_strerror(code), ident,
[1920]                   (size_t) rn->nlen, rn->name);
[1921]     return;
[1922] 
[1923] dns_error:
[1924] 
[1925]     ngx_log_error(r->log_level, r->log, 0,
[1926]                   "DNS error (%ui: %s), query id:%ui",
[1927]                   code, ngx_resolver_strerror(code), ident);
[1928]     return;
[1929] }
[1930] 
[1931] 
[1932] static void
[1933] ngx_resolver_process_a(ngx_resolver_t *r, u_char *buf, size_t n,
[1934]     ngx_uint_t ident, ngx_uint_t code, ngx_uint_t qtype,
[1935]     ngx_uint_t nan, ngx_uint_t trunc, ngx_uint_t ans)
[1936] {
[1937]     char                       *err;
[1938]     u_char                     *cname;
[1939]     size_t                      len;
[1940]     int32_t                     ttl;
[1941]     uint32_t                    hash;
[1942]     in_addr_t                  *addr;
[1943]     ngx_str_t                   name;
[1944]     ngx_uint_t                  type, class, qident, naddrs, a, i, j, start;
[1945] #if (NGX_HAVE_INET6)
[1946]     struct in6_addr            *addr6;
[1947] #endif
[1948]     ngx_resolver_an_t          *an;
[1949]     ngx_resolver_ctx_t         *ctx, *next;
[1950]     ngx_resolver_node_t        *rn;
[1951]     ngx_resolver_addr_t        *addrs;
[1952]     ngx_resolver_connection_t  *rec;
[1953] 
[1954]     if (ngx_resolver_copy(r, &name, buf,
[1955]                           buf + sizeof(ngx_resolver_hdr_t), buf + n)
[1956]         != NGX_OK)
[1957]     {
[1958]         return;
[1959]     }
[1960] 
[1961]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);
[1962] 
[1963]     hash = ngx_crc32_short(name.data, name.len);
[1964] 
[1965]     /* lock name mutex */
[1966] 
[1967]     rn = ngx_resolver_lookup_name(r, &name, hash);
[1968] 
[1969]     if (rn == NULL) {
[1970]         ngx_log_error(r->log_level, r->log, 0,
[1971]                       "unexpected DNS response for %V", &name);
[1972]         ngx_resolver_free(r, name.data);
[1973]         goto failed;
[1974]     }
[1975] 
[1976]     switch (qtype) {
[1977] 
[1978] #if (NGX_HAVE_INET6)
[1979]     case NGX_RESOLVE_AAAA:
[1980] 
[1981]         if (rn->query6 == NULL || rn->naddrs6 != (u_short) -1) {
[1982]             ngx_log_error(r->log_level, r->log, 0,
[1983]                           "unexpected DNS response for %V", &name);
[1984]             ngx_resolver_free(r, name.data);
[1985]             goto failed;
[1986]         }
[1987] 
[1988]         if (trunc && rn->tcp6) {
[1989]             ngx_resolver_free(r, name.data);
[1990]             goto failed;
[1991]         }
[1992] 
[1993]         qident = (rn->query6[0] << 8) + rn->query6[1];
[1994] 
[1995]         break;
[1996] #endif
[1997] 
[1998]     default: /* NGX_RESOLVE_A */
[1999] 
[2000]         if (rn->query == NULL || rn->naddrs != (u_short) -1) {
[2001]             ngx_log_error(r->log_level, r->log, 0,
[2002]                           "unexpected DNS response for %V", &name);
[2003]             ngx_resolver_free(r, name.data);
[2004]             goto failed;
[2005]         }
[2006] 
[2007]         if (trunc && rn->tcp) {
[2008]             ngx_resolver_free(r, name.data);
[2009]             goto failed;
[2010]         }
[2011] 
[2012]         qident = (rn->query[0] << 8) + rn->query[1];
[2013]     }
[2014] 
[2015]     if (ident != qident) {
[2016]         ngx_log_error(r->log_level, r->log, 0,
[2017]                       "wrong ident %ui in DNS response for %V, expect %ui",
[2018]                       ident, &name, qident);
[2019]         ngx_resolver_free(r, name.data);
[2020]         goto failed;
[2021]     }
[2022] 
[2023]     ngx_resolver_free(r, name.data);
[2024] 
[2025]     if (trunc) {
[2026] 
[2027]         ngx_queue_remove(&rn->queue);
[2028] 
[2029]         if (rn->waiting == NULL) {
[2030]             ngx_rbtree_delete(&r->name_rbtree, &rn->node);
[2031]             ngx_resolver_free_node(r, rn);
[2032]             goto next;
[2033]         }
[2034] 
[2035]         rec = r->connections.elts;
[2036]         rec = &rec[rn->last_connection];
[2037] 
[2038]         switch (qtype) {
[2039] 
[2040] #if (NGX_HAVE_INET6)
[2041]         case NGX_RESOLVE_AAAA:
[2042] 
[2043]             rn->tcp6 = 1;
[2044] 
[2045]             (void) ngx_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen);
[2046] 
[2047]             break;
[2048] #endif
[2049] 
[2050]         default: /* NGX_RESOLVE_A */
[2051] 
[2052]             rn->tcp = 1;
[2053] 
[2054]             (void) ngx_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);
[2055]         }
[2056] 
[2057]         rn->expire = ngx_time() + r->resend_timeout;
[2058] 
[2059]         ngx_queue_insert_head(&r->name_resend_queue, &rn->queue);
[2060] 
[2061]         goto next;
[2062]     }
[2063] 
[2064]     if (code == 0 && rn->code) {
[2065]         code = rn->code;
[2066]     }
[2067] 
[2068]     if (code == 0 && nan == 0) {
[2069] 
[2070] #if (NGX_HAVE_INET6)
[2071]         switch (qtype) {
[2072] 
[2073]         case NGX_RESOLVE_AAAA:
[2074] 
[2075]             rn->naddrs6 = 0;
[2076] 
[2077]             if (rn->naddrs == (u_short) -1) {
[2078]                 goto next;
[2079]             }
[2080] 
[2081]             if (rn->naddrs) {
[2082]                 goto export;
[2083]             }
[2084] 
[2085]             break;
[2086] 
[2087]         default: /* NGX_RESOLVE_A */
[2088] 
[2089]             rn->naddrs = 0;
[2090] 
[2091]             if (rn->naddrs6 == (u_short) -1) {
[2092]                 goto next;
[2093]             }
[2094] 
[2095]             if (rn->naddrs6) {
[2096]                 goto export;
[2097]             }
[2098]         }
[2099] #endif
[2100] 
[2101]         code = NGX_RESOLVE_NXDOMAIN;
[2102]     }
[2103] 
[2104]     if (code) {
[2105] 
[2106] #if (NGX_HAVE_INET6)
[2107]         switch (qtype) {
[2108] 
[2109]         case NGX_RESOLVE_AAAA:
[2110] 
[2111]             rn->naddrs6 = 0;
[2112] 
[2113]             if (rn->naddrs == (u_short) -1) {
[2114]                 rn->code = (u_char) code;
[2115]                 goto next;
[2116]             }
[2117] 
[2118]             break;
[2119] 
[2120]         default: /* NGX_RESOLVE_A */
[2121] 
[2122]             rn->naddrs = 0;
[2123] 
[2124]             if (rn->naddrs6 == (u_short) -1) {
[2125]                 rn->code = (u_char) code;
[2126]                 goto next;
[2127]             }
[2128]         }
[2129] #endif
[2130] 
[2131]         next = rn->waiting;
[2132]         rn->waiting = NULL;
[2133] 
[2134]         ngx_queue_remove(&rn->queue);
[2135] 
[2136]         ngx_rbtree_delete(&r->name_rbtree, &rn->node);
[2137] 
[2138]         /* unlock name mutex */
[2139] 
[2140]         while (next) {
[2141]             ctx = next;
[2142]             ctx->state = code;
[2143]             ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[2144]             next = ctx->next;
[2145] 
[2146]             ctx->handler(ctx);
[2147]         }
[2148] 
[2149]         ngx_resolver_free_node(r, rn);
[2150] 
[2151]         return;
[2152]     }
[2153] 
[2154]     i = ans;
[2155]     naddrs = 0;
[2156]     cname = NULL;
[2157] 
[2158]     for (a = 0; a < nan; a++) {
[2159] 
[2160]         start = i;
[2161] 
[2162]         while (i < n) {
[2163] 
[2164]             if (buf[i] & 0xc0) {
[2165]                 i += 2;
[2166]                 goto found;
[2167]             }
[2168] 
[2169]             if (buf[i] == 0) {
[2170]                 i++;
[2171]                 goto test_length;
[2172]             }
[2173] 
[2174]             i += 1 + buf[i];
[2175]         }
[2176] 
[2177]         goto short_response;
[2178] 
[2179]     test_length:
[2180] 
[2181]         if (i - start < 2) {
[2182]             err = "invalid name in DNS response";
[2183]             goto invalid;
[2184]         }
[2185] 
[2186]     found:
[2187] 
[2188]         if (i + sizeof(ngx_resolver_an_t) >= n) {
[2189]             goto short_response;
[2190]         }
[2191] 
[2192]         an = (ngx_resolver_an_t *) &buf[i];
[2193] 
[2194]         type = (an->type_hi << 8) + an->type_lo;
[2195]         class = (an->class_hi << 8) + an->class_lo;
[2196]         len = (an->len_hi << 8) + an->len_lo;
[2197]         ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
[2198]             + (an->ttl[2] << 8) + (an->ttl[3]);
[2199] 
[2200]         if (class != 1) {
[2201]             ngx_log_error(r->log_level, r->log, 0,
[2202]                           "unexpected RR class %ui in DNS response", class);
[2203]             goto failed;
[2204]         }
[2205] 
[2206]         if (ttl < 0) {
[2207]             ttl = 0;
[2208]         }
[2209] 
[2210]         rn->ttl = ngx_min(rn->ttl, (uint32_t) ttl);
[2211] 
[2212]         i += sizeof(ngx_resolver_an_t);
[2213] 
[2214]         switch (type) {
[2215] 
[2216]         case NGX_RESOLVE_A:
[2217] 
[2218]             if (qtype != NGX_RESOLVE_A) {
[2219]                 err = "unexpected A record in DNS response";
[2220]                 goto invalid;
[2221]             }
[2222] 
[2223]             if (len != 4) {
[2224]                 err = "invalid A record in DNS response";
[2225]                 goto invalid;
[2226]             }
[2227] 
[2228]             if (i + 4 > n) {
[2229]                 goto short_response;
[2230]             }
[2231] 
[2232]             naddrs++;
[2233] 
[2234]             break;
[2235] 
[2236] #if (NGX_HAVE_INET6)
[2237]         case NGX_RESOLVE_AAAA:
[2238] 
[2239]             if (qtype != NGX_RESOLVE_AAAA) {
[2240]                 err = "unexpected AAAA record in DNS response";
[2241]                 goto invalid;
[2242]             }
[2243] 
[2244]             if (len != 16) {
[2245]                 err = "invalid AAAA record in DNS response";
[2246]                 goto invalid;
[2247]             }
[2248] 
[2249]             if (i + 16 > n) {
[2250]                 goto short_response;
[2251]             }
[2252] 
[2253]             naddrs++;
[2254] 
[2255]             break;
[2256] #endif
[2257] 
[2258]         case NGX_RESOLVE_CNAME:
[2259] 
[2260]             cname = &buf[i];
[2261] 
[2262]             break;
[2263] 
[2264]         case NGX_RESOLVE_DNAME:
[2265] 
[2266]             break;
[2267] 
[2268]         default:
[2269] 
[2270]             ngx_log_error(r->log_level, r->log, 0,
[2271]                           "unexpected RR type %ui in DNS response", type);
[2272]         }
[2273] 
[2274]         i += len;
[2275]     }
[2276] 
[2277]     ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
[2278]                    "resolver naddrs:%ui cname:%p ttl:%uD",
[2279]                    naddrs, cname, rn->ttl);
[2280] 
[2281]     if (naddrs) {
[2282] 
[2283]         switch (qtype) {
[2284] 
[2285] #if (NGX_HAVE_INET6)
[2286]         case NGX_RESOLVE_AAAA:
[2287] 
[2288]             if (naddrs == 1) {
[2289]                 addr6 = &rn->u6.addr6;
[2290]                 rn->naddrs6 = 1;
[2291] 
[2292]             } else {
[2293]                 addr6 = ngx_resolver_alloc(r, naddrs * sizeof(struct in6_addr));
[2294]                 if (addr6 == NULL) {
[2295]                     goto failed;
[2296]                 }
[2297] 
[2298]                 rn->u6.addrs6 = addr6;
[2299]                 rn->naddrs6 = (u_short) naddrs;
[2300]             }
[2301] 
[2302] #if (NGX_SUPPRESS_WARN)
[2303]             addr = NULL;
[2304] #endif
[2305] 
[2306]             break;
[2307] #endif
[2308] 
[2309]         default: /* NGX_RESOLVE_A */
[2310] 
[2311]             if (naddrs == 1) {
[2312]                 addr = &rn->u.addr;
[2313]                 rn->naddrs = 1;
[2314] 
[2315]             } else {
[2316]                 addr = ngx_resolver_alloc(r, naddrs * sizeof(in_addr_t));
[2317]                 if (addr == NULL) {
[2318]                     goto failed;
[2319]                 }
[2320] 
[2321]                 rn->u.addrs = addr;
[2322]                 rn->naddrs = (u_short) naddrs;
[2323]             }
[2324] 
[2325] #if (NGX_HAVE_INET6 && NGX_SUPPRESS_WARN)
[2326]             addr6 = NULL;
[2327] #endif
[2328]         }
[2329] 
[2330]         j = 0;
[2331]         i = ans;
[2332] 
[2333]         for (a = 0; a < nan; a++) {
[2334] 
[2335]             for ( ;; ) {
[2336] 
[2337]                 if (buf[i] & 0xc0) {
[2338]                     i += 2;
[2339]                     break;
[2340]                 }
[2341] 
[2342]                 if (buf[i] == 0) {
[2343]                     i++;
[2344]                     break;
[2345]                 }
[2346] 
[2347]                 i += 1 + buf[i];
[2348]             }
[2349] 
[2350]             an = (ngx_resolver_an_t *) &buf[i];
[2351] 
[2352]             type = (an->type_hi << 8) + an->type_lo;
[2353]             len = (an->len_hi << 8) + an->len_lo;
[2354] 
[2355]             i += sizeof(ngx_resolver_an_t);
[2356] 
[2357]             if (type == NGX_RESOLVE_A) {
[2358] 
[2359]                 addr[j] = htonl((buf[i] << 24) + (buf[i + 1] << 16)
[2360]                                 + (buf[i + 2] << 8) + (buf[i + 3]));
[2361] 
[2362]                 if (++j == naddrs) {
[2363] 
[2364] #if (NGX_HAVE_INET6)
[2365]                     if (rn->naddrs6 == (u_short) -1) {
[2366]                         goto next;
[2367]                     }
[2368] #endif
[2369] 
[2370]                     break;
[2371]                 }
[2372]             }
[2373] 
[2374] #if (NGX_HAVE_INET6)
[2375]             else if (type == NGX_RESOLVE_AAAA) {
[2376] 
[2377]                 ngx_memcpy(addr6[j].s6_addr, &buf[i], 16);
[2378] 
[2379]                 if (++j == naddrs) {
[2380] 
[2381]                     if (rn->naddrs == (u_short) -1) {
[2382]                         goto next;
[2383]                     }
[2384] 
[2385]                     break;
[2386]                 }
[2387]             }
[2388] #endif
[2389] 
[2390]             i += len;
[2391]         }
[2392]     }
[2393] 
[2394]     switch (qtype) {
[2395] 
[2396] #if (NGX_HAVE_INET6)
[2397]     case NGX_RESOLVE_AAAA:
[2398] 
[2399]         if (rn->naddrs6 == (u_short) -1) {
[2400]             rn->naddrs6 = 0;
[2401]         }
[2402] 
[2403]         break;
[2404] #endif
[2405] 
[2406]     default: /* NGX_RESOLVE_A */
[2407] 
[2408]         if (rn->naddrs == (u_short) -1) {
[2409]             rn->naddrs = 0;
[2410]         }
[2411]     }
[2412] 
[2413]     if (rn->naddrs != (u_short) -1
[2414] #if (NGX_HAVE_INET6)
[2415]         && rn->naddrs6 != (u_short) -1
[2416] #endif
[2417]         && rn->naddrs
[2418] #if (NGX_HAVE_INET6)
[2419]            + rn->naddrs6
[2420] #endif
[2421]            > 0)
[2422]     {
[2423] 
[2424] #if (NGX_HAVE_INET6)
[2425]     export:
[2426] #endif
[2427] 
[2428]         naddrs = rn->naddrs;
[2429] #if (NGX_HAVE_INET6)
[2430]         naddrs += rn->naddrs6;
[2431] #endif
[2432] 
[2433]         if (naddrs == 1 && rn->naddrs == 1) {
[2434]             addrs = NULL;
[2435] 
[2436]         } else {
[2437]             addrs = ngx_resolver_export(r, rn, 0);
[2438]             if (addrs == NULL) {
[2439]                 goto failed;
[2440]             }
[2441]         }
[2442] 
[2443]         ngx_queue_remove(&rn->queue);
[2444] 
[2445]         rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
[2446]         rn->expire = ngx_time() + r->expire;
[2447] 
[2448]         ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);
[2449] 
[2450]         next = rn->waiting;
[2451]         rn->waiting = NULL;
[2452] 
[2453]         /* unlock name mutex */
[2454] 
[2455]         while (next) {
[2456]             ctx = next;
[2457]             ctx->state = NGX_OK;
[2458]             ctx->valid = rn->valid;
[2459]             ctx->naddrs = naddrs;
[2460] 
[2461]             if (addrs == NULL) {
[2462]                 ctx->addrs = &ctx->addr;
[2463]                 ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
[2464]                 ctx->addr.socklen = sizeof(struct sockaddr_in);
[2465]                 ngx_memzero(&ctx->sin, sizeof(struct sockaddr_in));
[2466]                 ctx->sin.sin_family = AF_INET;
[2467]                 ctx->sin.sin_addr.s_addr = rn->u.addr;
[2468] 
[2469]             } else {
[2470]                 ctx->addrs = addrs;
[2471]             }
[2472] 
[2473]             next = ctx->next;
[2474] 
[2475]             ctx->handler(ctx);
[2476]         }
[2477] 
[2478]         if (addrs != NULL) {
[2479]             ngx_resolver_free(r, addrs->sockaddr);
[2480]             ngx_resolver_free(r, addrs);
[2481]         }
[2482] 
[2483]         ngx_resolver_free(r, rn->query);
[2484]         rn->query = NULL;
[2485] #if (NGX_HAVE_INET6)
[2486]         rn->query6 = NULL;
[2487] #endif
[2488] 
[2489]         return;
[2490]     }
[2491] 
[2492]     if (cname) {
[2493] 
[2494]         /* CNAME only */
[2495] 
[2496]         if (rn->naddrs == (u_short) -1
[2497] #if (NGX_HAVE_INET6)
[2498]             || rn->naddrs6 == (u_short) -1
[2499] #endif
[2500]             )
[2501]         {
[2502]             goto next;
[2503]         }
[2504] 
[2505]         if (ngx_resolver_copy(r, &name, buf, cname, buf + n) != NGX_OK) {
[2506]             goto failed;
[2507]         }
[2508] 
[2509]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
[2510]                        "resolver cname:\"%V\"", &name);
[2511] 
[2512]         ngx_queue_remove(&rn->queue);
[2513] 
[2514]         rn->cnlen = (u_short) name.len;
[2515]         rn->u.cname = name.data;
[2516] 
[2517]         rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
[2518]         rn->expire = ngx_time() + r->expire;
[2519] 
[2520]         ngx_queue_insert_head(&r->name_expire_queue, &rn->queue);
[2521] 
[2522]         ngx_resolver_free(r, rn->query);
[2523]         rn->query = NULL;
[2524] #if (NGX_HAVE_INET6)
[2525]         rn->query6 = NULL;
[2526] #endif
[2527] 
[2528]         ctx = rn->waiting;
[2529]         rn->waiting = NULL;
[2530] 
[2531]         if (ctx) {
[2532] 
[2533]             if (ctx->recursion++ >= NGX_RESOLVER_MAX_RECURSION) {
[2534] 
[2535]                 /* unlock name mutex */
[2536] 
[2537]                 do {
[2538]                     ctx->state = NGX_RESOLVE_NXDOMAIN;
[2539]                     next = ctx->next;
[2540] 
[2541]                     ctx->handler(ctx);
[2542] 
[2543]                     ctx = next;
[2544]                 } while (ctx);
[2545] 
[2546]                 return;
[2547]             }
[2548] 
[2549]             for (next = ctx; next; next = next->next) {
[2550]                 next->node = NULL;
[2551]             }
[2552] 
[2553]             (void) ngx_resolve_name_locked(r, ctx, &name);
[2554]         }
[2555] 
[2556]         /* unlock name mutex */
[2557] 
[2558]         return;
[2559]     }
[2560] 
[2561]     ngx_log_error(r->log_level, r->log, 0,
[2562]                   "no A or CNAME types in DNS response");
[2563]     return;
[2564] 
[2565] short_response:
[2566] 
[2567]     err = "short DNS response";
[2568] 
[2569] invalid:
[2570] 
[2571]     /* unlock name mutex */
[2572] 
[2573]     ngx_log_error(r->log_level, r->log, 0, err);
[2574] 
[2575]     return;
[2576] 
[2577] failed:
[2578] 
[2579] next:
[2580] 
[2581]     /* unlock name mutex */
[2582] 
[2583]     return;
[2584] }
[2585] 
[2586] 
[2587] static void
[2588] ngx_resolver_process_srv(ngx_resolver_t *r, u_char *buf, size_t n,
[2589]     ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan,
[2590]     ngx_uint_t trunc, ngx_uint_t ans)
[2591] {
[2592]     char                       *err;
[2593]     u_char                     *cname;
[2594]     size_t                      len;
[2595]     int32_t                     ttl;
[2596]     uint32_t                    hash;
[2597]     ngx_str_t                   name;
[2598]     ngx_uint_t                  type, qident, class, start, nsrvs, a, i, j;
[2599]     ngx_resolver_an_t          *an;
[2600]     ngx_resolver_ctx_t         *ctx, *next;
[2601]     ngx_resolver_srv_t         *srvs;
[2602]     ngx_resolver_node_t        *rn;
[2603]     ngx_resolver_connection_t  *rec;
[2604] 
[2605]     if (ngx_resolver_copy(r, &name, buf,
[2606]                           buf + sizeof(ngx_resolver_hdr_t), buf + n)
[2607]         != NGX_OK)
[2608]     {
[2609]         return;
[2610]     }
[2611] 
[2612]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);
[2613] 
[2614]     hash = ngx_crc32_short(name.data, name.len);
[2615] 
[2616]     rn = ngx_resolver_lookup_srv(r, &name, hash);
[2617] 
[2618]     if (rn == NULL || rn->query == NULL) {
[2619]         ngx_log_error(r->log_level, r->log, 0,
[2620]                       "unexpected DNS response for %V", &name);
[2621]         ngx_resolver_free(r, name.data);
[2622]         goto failed;
[2623]     }
[2624] 
[2625]     if (trunc && rn->tcp) {
[2626]         ngx_resolver_free(r, name.data);
[2627]         goto failed;
[2628]     }
[2629] 
[2630]     qident = (rn->query[0] << 8) + rn->query[1];
[2631] 
[2632]     if (ident != qident) {
[2633]         ngx_log_error(r->log_level, r->log, 0,
[2634]                       "wrong ident %ui in DNS response for %V, expect %ui",
[2635]                       ident, &name, qident);
[2636]         ngx_resolver_free(r, name.data);
[2637]         goto failed;
[2638]     }
[2639] 
[2640]     ngx_resolver_free(r, name.data);
[2641] 
[2642]     if (trunc) {
[2643] 
[2644]         ngx_queue_remove(&rn->queue);
[2645] 
[2646]         if (rn->waiting == NULL) {
[2647]             ngx_rbtree_delete(&r->srv_rbtree, &rn->node);
[2648]             ngx_resolver_free_node(r, rn);
[2649]             return;
[2650]         }
[2651] 
[2652]         rec = r->connections.elts;
[2653]         rec = &rec[rn->last_connection];
[2654] 
[2655]         rn->tcp = 1;
[2656] 
[2657]         (void) ngx_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);
[2658] 
[2659]         rn->expire = ngx_time() + r->resend_timeout;
[2660] 
[2661]         ngx_queue_insert_head(&r->srv_resend_queue, &rn->queue);
[2662] 
[2663]         return;
[2664]     }
[2665] 
[2666]     if (code == 0 && rn->code) {
[2667]         code = rn->code;
[2668]     }
[2669] 
[2670]     if (code == 0 && nan == 0) {
[2671]         code = NGX_RESOLVE_NXDOMAIN;
[2672]     }
[2673] 
[2674]     if (code) {
[2675]         next = rn->waiting;
[2676]         rn->waiting = NULL;
[2677] 
[2678]         ngx_queue_remove(&rn->queue);
[2679] 
[2680]         ngx_rbtree_delete(&r->srv_rbtree, &rn->node);
[2681] 
[2682]         while (next) {
[2683]             ctx = next;
[2684]             ctx->state = code;
[2685]             ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[2686]             next = ctx->next;
[2687] 
[2688]             ctx->handler(ctx);
[2689]         }
[2690] 
[2691]         ngx_resolver_free_node(r, rn);
[2692] 
[2693]         return;
[2694]     }
[2695] 
[2696]     i = ans;
[2697]     nsrvs = 0;
[2698]     cname = NULL;
[2699] 
[2700]     for (a = 0; a < nan; a++) {
[2701] 
[2702]         start = i;
[2703] 
[2704]         while (i < n) {
[2705] 
[2706]             if (buf[i] & 0xc0) {
[2707]                 i += 2;
[2708]                 goto found;
[2709]             }
[2710] 
[2711]             if (buf[i] == 0) {
[2712]                 i++;
[2713]                 goto test_length;
[2714]             }
[2715] 
[2716]             i += 1 + buf[i];
[2717]         }
[2718] 
[2719]         goto short_response;
[2720] 
[2721]     test_length:
[2722] 
[2723]         if (i - start < 2) {
[2724]             err = "invalid name DNS response";
[2725]             goto invalid;
[2726]         }
[2727] 
[2728]     found:
[2729] 
[2730]         if (i + sizeof(ngx_resolver_an_t) >= n) {
[2731]             goto short_response;
[2732]         }
[2733] 
[2734]         an = (ngx_resolver_an_t *) &buf[i];
[2735] 
[2736]         type = (an->type_hi << 8) + an->type_lo;
[2737]         class = (an->class_hi << 8) + an->class_lo;
[2738]         len = (an->len_hi << 8) + an->len_lo;
[2739]         ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
[2740]             + (an->ttl[2] << 8) + (an->ttl[3]);
[2741] 
[2742]         if (class != 1) {
[2743]             ngx_log_error(r->log_level, r->log, 0,
[2744]                           "unexpected RR class %ui in DNS response", class);
[2745]             goto failed;
[2746]         }
[2747] 
[2748]         if (ttl < 0) {
[2749]             ttl = 0;
[2750]         }
[2751] 
[2752]         rn->ttl = ngx_min(rn->ttl, (uint32_t) ttl);
[2753] 
[2754]         i += sizeof(ngx_resolver_an_t);
[2755] 
[2756]         switch (type) {
[2757] 
[2758]         case NGX_RESOLVE_SRV:
[2759] 
[2760]             if (i + 6 > n) {
[2761]                 goto short_response;
[2762]             }
[2763] 
[2764]             if (ngx_resolver_copy(r, NULL, buf, &buf[i + 6], buf + n)
[2765]                 != NGX_OK)
[2766]             {
[2767]                 goto failed;
[2768]             }
[2769] 
[2770]             nsrvs++;
[2771] 
[2772]             break;
[2773] 
[2774]         case NGX_RESOLVE_CNAME:
[2775] 
[2776]             cname = &buf[i];
[2777] 
[2778]             break;
[2779] 
[2780]         case NGX_RESOLVE_DNAME:
[2781] 
[2782]             break;
[2783] 
[2784]         default:
[2785] 
[2786]             ngx_log_error(r->log_level, r->log, 0,
[2787]                           "unexpected RR type %ui in DNS response", type);
[2788]         }
[2789] 
[2790]         i += len;
[2791]     }
[2792] 
[2793]     ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
[2794]                    "resolver nsrvs:%ui cname:%p ttl:%uD",
[2795]                    nsrvs, cname, rn->ttl);
[2796] 
[2797]     if (nsrvs) {
[2798] 
[2799]         srvs = ngx_resolver_calloc(r, nsrvs * sizeof(ngx_resolver_srv_t));
[2800]         if (srvs == NULL) {
[2801]             goto failed;
[2802]         }
[2803] 
[2804]         rn->u.srvs = srvs;
[2805]         rn->nsrvs = (u_short) nsrvs;
[2806] 
[2807]         j = 0;
[2808]         i = ans;
[2809] 
[2810]         for (a = 0; a < nan; a++) {
[2811] 
[2812]             for ( ;; ) {
[2813] 
[2814]                 if (buf[i] & 0xc0) {
[2815]                     i += 2;
[2816]                     break;
[2817]                 }
[2818] 
[2819]                 if (buf[i] == 0) {
[2820]                     i++;
[2821]                     break;
[2822]                 }
[2823] 
[2824]                 i += 1 + buf[i];
[2825]             }
[2826] 
[2827]             an = (ngx_resolver_an_t *) &buf[i];
[2828] 
[2829]             type = (an->type_hi << 8) + an->type_lo;
[2830]             len = (an->len_hi << 8) + an->len_lo;
[2831] 
[2832]             i += sizeof(ngx_resolver_an_t);
[2833] 
[2834]             if (type == NGX_RESOLVE_SRV) {
[2835] 
[2836]                 srvs[j].priority = (buf[i] << 8) + buf[i + 1];
[2837]                 srvs[j].weight = (buf[i + 2] << 8) + buf[i + 3];
[2838] 
[2839]                 if (srvs[j].weight == 0) {
[2840]                     srvs[j].weight = 1;
[2841]                 }
[2842] 
[2843]                 srvs[j].port = (buf[i + 4] << 8) + buf[i + 5];
[2844] 
[2845]                 if (ngx_resolver_copy(r, &srvs[j].name, buf, &buf[i + 6],
[2846]                                       buf + n)
[2847]                     != NGX_OK)
[2848]                 {
[2849]                     goto failed;
[2850]                 }
[2851] 
[2852]                 j++;
[2853]             }
[2854] 
[2855]             i += len;
[2856]         }
[2857] 
[2858]         ngx_sort(srvs, nsrvs, sizeof(ngx_resolver_srv_t),
[2859]                  ngx_resolver_cmp_srvs);
[2860] 
[2861]         ngx_resolver_free(r, rn->query);
[2862]         rn->query = NULL;
[2863] 
[2864]         ngx_queue_remove(&rn->queue);
[2865] 
[2866]         rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
[2867]         rn->expire = ngx_time() + r->expire;
[2868] 
[2869]         ngx_queue_insert_head(&r->srv_expire_queue, &rn->queue);
[2870] 
[2871]         next = rn->waiting;
[2872]         rn->waiting = NULL;
[2873] 
[2874]         while (next) {
[2875]             ctx = next;
[2876]             next = ctx->next;
[2877] 
[2878]             ngx_resolver_resolve_srv_names(ctx, rn);
[2879]         }
[2880] 
[2881]         return;
[2882]     }
[2883] 
[2884]     rn->nsrvs = 0;
[2885] 
[2886]     if (cname) {
[2887] 
[2888]         /* CNAME only */
[2889] 
[2890]         if (ngx_resolver_copy(r, &name, buf, cname, buf + n) != NGX_OK) {
[2891]             goto failed;
[2892]         }
[2893] 
[2894]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
[2895]                        "resolver cname:\"%V\"", &name);
[2896] 
[2897]         ngx_queue_remove(&rn->queue);
[2898] 
[2899]         rn->cnlen = (u_short) name.len;
[2900]         rn->u.cname = name.data;
[2901] 
[2902]         rn->valid = ngx_time() + (r->valid ? r->valid : (time_t) rn->ttl);
[2903]         rn->expire = ngx_time() + r->expire;
[2904] 
[2905]         ngx_queue_insert_head(&r->srv_expire_queue, &rn->queue);
[2906] 
[2907]         ngx_resolver_free(r, rn->query);
[2908]         rn->query = NULL;
[2909] #if (NGX_HAVE_INET6)
[2910]         rn->query6 = NULL;
[2911] #endif
[2912] 
[2913]         ctx = rn->waiting;
[2914]         rn->waiting = NULL;
[2915] 
[2916]         if (ctx) {
[2917] 
[2918]             if (ctx->recursion++ >= NGX_RESOLVER_MAX_RECURSION) {
[2919] 
[2920]                 /* unlock name mutex */
[2921] 
[2922]                 do {
[2923]                     ctx->state = NGX_RESOLVE_NXDOMAIN;
[2924]                     next = ctx->next;
[2925] 
[2926]                     ctx->handler(ctx);
[2927] 
[2928]                     ctx = next;
[2929]                 } while (ctx);
[2930] 
[2931]                 return;
[2932]             }
[2933] 
[2934]             for (next = ctx; next; next = next->next) {
[2935]                 next->node = NULL;
[2936]             }
[2937] 
[2938]             (void) ngx_resolve_name_locked(r, ctx, &name);
[2939]         }
[2940] 
[2941]         /* unlock name mutex */
[2942] 
[2943]         return;
[2944]     }
[2945] 
[2946]     ngx_log_error(r->log_level, r->log, 0, "no SRV type in DNS response");
[2947] 
[2948]     return;
[2949] 
[2950] short_response:
[2951] 
[2952]     err = "short DNS response";
[2953] 
[2954] invalid:
[2955] 
[2956]     /* unlock name mutex */
[2957] 
[2958]     ngx_log_error(r->log_level, r->log, 0, err);
[2959] 
[2960]     return;
[2961] 
[2962] failed:
[2963] 
[2964]     /* unlock name mutex */
[2965] 
[2966]     return;
[2967] }
[2968] 
[2969] 
[2970] static void
[2971] ngx_resolver_resolve_srv_names(ngx_resolver_ctx_t *ctx, ngx_resolver_node_t *rn)
[2972] {
[2973]     ngx_uint_t                i;
[2974]     ngx_resolver_t           *r;
[2975]     ngx_resolver_ctx_t       *cctx;
[2976]     ngx_resolver_srv_name_t  *srvs;
[2977] 
[2978]     r = ctx->resolver;
[2979] 
[2980]     ctx->node = NULL;
[2981]     ctx->state = NGX_OK;
[2982]     ctx->valid = rn->valid;
[2983]     ctx->count = rn->nsrvs;
[2984] 
[2985]     srvs = ngx_resolver_calloc(r, rn->nsrvs * sizeof(ngx_resolver_srv_name_t));
[2986]     if (srvs == NULL) {
[2987]         goto failed;
[2988]     }
[2989] 
[2990]     ctx->srvs = srvs;
[2991]     ctx->nsrvs = rn->nsrvs;
[2992] 
[2993]     if (ctx->event && ctx->event->timer_set) {
[2994]         ngx_del_timer(ctx->event);
[2995]     }
[2996] 
[2997]     for (i = 0; i < (ngx_uint_t) rn->nsrvs; i++) {
[2998]         srvs[i].name.data = ngx_resolver_alloc(r, rn->u.srvs[i].name.len);
[2999]         if (srvs[i].name.data == NULL) {
[3000]             goto failed;
[3001]         }
[3002] 
[3003]         srvs[i].name.len = rn->u.srvs[i].name.len;
[3004]         ngx_memcpy(srvs[i].name.data, rn->u.srvs[i].name.data,
[3005]                    srvs[i].name.len);
[3006] 
[3007]         cctx = ngx_resolve_start(r, NULL);
[3008]         if (cctx == NULL) {
[3009]             goto failed;
[3010]         }
[3011] 
[3012]         cctx->name = srvs[i].name;
[3013]         cctx->handler = ngx_resolver_srv_names_handler;
[3014]         cctx->data = ctx;
[3015]         cctx->srvs = &srvs[i];
[3016]         cctx->timeout = ctx->timeout;
[3017] 
[3018]         srvs[i].priority = rn->u.srvs[i].priority;
[3019]         srvs[i].weight = rn->u.srvs[i].weight;
[3020]         srvs[i].port = rn->u.srvs[i].port;
[3021]         srvs[i].ctx = cctx;
[3022] 
[3023]         if (ngx_resolve_name(cctx) == NGX_ERROR) {
[3024]             srvs[i].ctx = NULL;
[3025]             goto failed;
[3026]         }
[3027]     }
[3028] 
[3029]     return;
[3030] 
[3031] failed:
[3032] 
[3033]     ctx->state = NGX_ERROR;
[3034]     ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[3035] 
[3036]     ctx->handler(ctx);
[3037] }
[3038] 
[3039] 
[3040] static void
[3041] ngx_resolver_srv_names_handler(ngx_resolver_ctx_t *cctx)
[3042] {
[3043]     ngx_uint_t                i;
[3044]     ngx_addr_t               *addrs;
[3045]     ngx_resolver_t           *r;
[3046]     ngx_sockaddr_t           *sockaddr;
[3047]     ngx_resolver_ctx_t       *ctx;
[3048]     ngx_resolver_srv_name_t  *srv;
[3049] 
[3050]     r = cctx->resolver;
[3051]     ctx = cctx->data;
[3052]     srv = cctx->srvs;
[3053] 
[3054]     ctx->count--;
[3055]     ctx->async |= cctx->async;
[3056] 
[3057]     srv->ctx = NULL;
[3058]     srv->state = cctx->state;
[3059] 
[3060]     if (cctx->naddrs) {
[3061] 
[3062]         ctx->valid = ngx_min(ctx->valid, cctx->valid);
[3063] 
[3064]         addrs = ngx_resolver_calloc(r, cctx->naddrs * sizeof(ngx_addr_t));
[3065]         if (addrs == NULL) {
[3066]             srv->state = NGX_ERROR;
[3067]             goto done;
[3068]         }
[3069] 
[3070]         sockaddr = ngx_resolver_alloc(r, cctx->naddrs * sizeof(ngx_sockaddr_t));
[3071]         if (sockaddr == NULL) {
[3072]             ngx_resolver_free(r, addrs);
[3073]             srv->state = NGX_ERROR;
[3074]             goto done;
[3075]         }
[3076] 
[3077]         for (i = 0; i < cctx->naddrs; i++) {
[3078]             addrs[i].sockaddr = &sockaddr[i].sockaddr;
[3079]             addrs[i].socklen = cctx->addrs[i].socklen;
[3080] 
[3081]             ngx_memcpy(&sockaddr[i], cctx->addrs[i].sockaddr,
[3082]                        addrs[i].socklen);
[3083] 
[3084]             ngx_inet_set_port(addrs[i].sockaddr, srv->port);
[3085]         }
[3086] 
[3087]         srv->addrs = addrs;
[3088]         srv->naddrs = cctx->naddrs;
[3089]     }
[3090] 
[3091] done:
[3092] 
[3093]     ngx_resolve_name_done(cctx);
[3094] 
[3095]     if (ctx->count == 0) {
[3096]         ngx_resolver_report_srv(r, ctx);
[3097]     }
[3098] }
[3099] 
[3100] 
[3101] static void
[3102] ngx_resolver_process_ptr(ngx_resolver_t *r, u_char *buf, size_t n,
[3103]     ngx_uint_t ident, ngx_uint_t code, ngx_uint_t nan)
[3104] {
[3105]     char                 *err;
[3106]     size_t                len;
[3107]     in_addr_t             addr;
[3108]     int32_t               ttl;
[3109]     ngx_int_t             octet;
[3110]     ngx_str_t             name;
[3111]     ngx_uint_t            mask, type, class, qident, a, i, start;
[3112]     ngx_queue_t          *expire_queue;
[3113]     ngx_rbtree_t         *tree;
[3114]     ngx_resolver_an_t    *an;
[3115]     ngx_resolver_ctx_t   *ctx, *next;
[3116]     ngx_resolver_node_t  *rn;
[3117] #if (NGX_HAVE_INET6)
[3118]     uint32_t              hash;
[3119]     ngx_int_t             digit;
[3120]     struct in6_addr       addr6;
[3121] #endif
[3122] 
[3123]     if (ngx_resolver_copy(r, &name, buf,
[3124]                           buf + sizeof(ngx_resolver_hdr_t), buf + n)
[3125]         != NGX_OK)
[3126]     {
[3127]         return;
[3128]     }
[3129] 
[3130]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);
[3131] 
[3132]     /* AF_INET */
[3133] 
[3134]     addr = 0;
[3135]     i = sizeof(ngx_resolver_hdr_t);
[3136] 
[3137]     for (mask = 0; mask < 32; mask += 8) {
[3138]         len = buf[i++];
[3139] 
[3140]         octet = ngx_atoi(&buf[i], len);
[3141]         if (octet == NGX_ERROR || octet > 255) {
[3142]             goto invalid_in_addr_arpa;
[3143]         }
[3144] 
[3145]         addr += octet << mask;
[3146]         i += len;
[3147]     }
[3148] 
[3149]     if (ngx_strcasecmp(&buf[i], (u_char *) "\7in-addr\4arpa") == 0) {
[3150]         i += sizeof("\7in-addr\4arpa");
[3151] 
[3152]         /* lock addr mutex */
[3153] 
[3154]         rn = ngx_resolver_lookup_addr(r, addr);
[3155] 
[3156]         tree = &r->addr_rbtree;
[3157]         expire_queue = &r->addr_expire_queue;
[3158] 
[3159]         goto valid;
[3160]     }
[3161] 
[3162] invalid_in_addr_arpa:
[3163] 
[3164] #if (NGX_HAVE_INET6)
[3165] 
[3166]     i = sizeof(ngx_resolver_hdr_t);
[3167] 
[3168]     for (octet = 15; octet >= 0; octet--) {
[3169]         if (buf[i++] != '\1') {
[3170]             goto invalid_ip6_arpa;
[3171]         }
[3172] 
[3173]         digit = ngx_hextoi(&buf[i++], 1);
[3174]         if (digit == NGX_ERROR) {
[3175]             goto invalid_ip6_arpa;
[3176]         }
[3177] 
[3178]         addr6.s6_addr[octet] = (u_char) digit;
[3179] 
[3180]         if (buf[i++] != '\1') {
[3181]             goto invalid_ip6_arpa;
[3182]         }
[3183] 
[3184]         digit = ngx_hextoi(&buf[i++], 1);
[3185]         if (digit == NGX_ERROR) {
[3186]             goto invalid_ip6_arpa;
[3187]         }
[3188] 
[3189]         addr6.s6_addr[octet] += (u_char) (digit * 16);
[3190]     }
[3191] 
[3192]     if (ngx_strcasecmp(&buf[i], (u_char *) "\3ip6\4arpa") == 0) {
[3193]         i += sizeof("\3ip6\4arpa");
[3194] 
[3195]         /* lock addr mutex */
[3196] 
[3197]         hash = ngx_crc32_short(addr6.s6_addr, 16);
[3198]         rn = ngx_resolver_lookup_addr6(r, &addr6, hash);
[3199] 
[3200]         tree = &r->addr6_rbtree;
[3201]         expire_queue = &r->addr6_expire_queue;
[3202] 
[3203]         goto valid;
[3204]     }
[3205] 
[3206] invalid_ip6_arpa:
[3207] #endif
[3208] 
[3209]     ngx_log_error(r->log_level, r->log, 0,
[3210]                   "invalid in-addr.arpa or ip6.arpa name in DNS response");
[3211]     ngx_resolver_free(r, name.data);
[3212]     return;
[3213] 
[3214] valid:
[3215] 
[3216]     if (rn == NULL || rn->query == NULL) {
[3217]         ngx_log_error(r->log_level, r->log, 0,
[3218]                       "unexpected DNS response for %V", &name);
[3219]         ngx_resolver_free(r, name.data);
[3220]         goto failed;
[3221]     }
[3222] 
[3223]     qident = (rn->query[0] << 8) + rn->query[1];
[3224] 
[3225]     if (ident != qident) {
[3226]         ngx_log_error(r->log_level, r->log, 0,
[3227]                       "wrong ident %ui in DNS response for %V, expect %ui",
[3228]                       ident, &name, qident);
[3229]         ngx_resolver_free(r, name.data);
[3230]         goto failed;
[3231]     }
[3232] 
[3233]     ngx_resolver_free(r, name.data);
[3234] 
[3235]     if (code == 0 && nan == 0) {
[3236]         code = NGX_RESOLVE_NXDOMAIN;
[3237]     }
[3238] 
[3239]     if (code) {
[3240]         next = rn->waiting;
[3241]         rn->waiting = NULL;
[3242] 
[3243]         ngx_queue_remove(&rn->queue);
[3244] 
[3245]         ngx_rbtree_delete(tree, &rn->node);
[3246] 
[3247]         /* unlock addr mutex */
[3248] 
[3249]         while (next) {
[3250]             ctx = next;
[3251]             ctx->state = code;
[3252]             ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[3253]             next = ctx->next;
[3254] 
[3255]             ctx->handler(ctx);
[3256]         }
[3257] 
[3258]         ngx_resolver_free_node(r, rn);
[3259] 
[3260]         return;
[3261]     }
[3262] 
[3263]     i += sizeof(ngx_resolver_qs_t);
[3264] 
[3265]     for (a = 0; a < nan; a++) {
[3266] 
[3267]         start = i;
[3268] 
[3269]         while (i < n) {
[3270] 
[3271]             if (buf[i] & 0xc0) {
[3272]                 i += 2;
[3273]                 goto found;
[3274]             }
[3275] 
[3276]             if (buf[i] == 0) {
[3277]                 i++;
[3278]                 goto test_length;
[3279]             }
[3280] 
[3281]             i += 1 + buf[i];
[3282]         }
[3283] 
[3284]         goto short_response;
[3285] 
[3286]     test_length:
[3287] 
[3288]         if (i - start < 2) {
[3289]             err = "invalid name in DNS response";
[3290]             goto invalid;
[3291]         }
[3292] 
[3293]     found:
[3294] 
[3295]         if (i + sizeof(ngx_resolver_an_t) >= n) {
[3296]             goto short_response;
[3297]         }
[3298] 
[3299]         an = (ngx_resolver_an_t *) &buf[i];
[3300] 
[3301]         type = (an->type_hi << 8) + an->type_lo;
[3302]         class = (an->class_hi << 8) + an->class_lo;
[3303]         len = (an->len_hi << 8) + an->len_lo;
[3304]         ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
[3305]             + (an->ttl[2] << 8) + (an->ttl[3]);
[3306] 
[3307]         if (class != 1) {
[3308]             ngx_log_error(r->log_level, r->log, 0,
[3309]                           "unexpected RR class %ui in DNS response", class);
[3310]             goto failed;
[3311]         }
[3312] 
[3313]         if (ttl < 0) {
[3314]             ttl = 0;
[3315]         }
[3316] 
[3317]         ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
[3318]                       "resolver qt:%ui cl:%ui len:%uz",
[3319]                       type, class, len);
[3320] 
[3321]         i += sizeof(ngx_resolver_an_t);
[3322] 
[3323]         switch (type) {
[3324] 
[3325]         case NGX_RESOLVE_PTR:
[3326] 
[3327]             goto ptr;
[3328] 
[3329]         case NGX_RESOLVE_CNAME:
[3330] 
[3331]             break;
[3332] 
[3333]         default:
[3334] 
[3335]             ngx_log_error(r->log_level, r->log, 0,
[3336]                           "unexpected RR type %ui in DNS response", type);
[3337]         }
[3338] 
[3339]         i += len;
[3340]     }
[3341] 
[3342]     /* unlock addr mutex */
[3343] 
[3344]     ngx_log_error(r->log_level, r->log, 0,
[3345]                   "no PTR type in DNS response");
[3346]     return;
[3347] 
[3348] ptr:
[3349] 
[3350]     if (ngx_resolver_copy(r, &name, buf, buf + i, buf + n) != NGX_OK) {
[3351]         goto failed;
[3352]     }
[3353] 
[3354]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0, "resolver an:%V", &name);
[3355] 
[3356]     if (name.len != (size_t) rn->nlen
[3357]         || ngx_strncmp(name.data, rn->name, name.len) != 0)
[3358]     {
[3359]         if (rn->nlen) {
[3360]             ngx_resolver_free(r, rn->name);
[3361]         }
[3362] 
[3363]         rn->nlen = (u_short) name.len;
[3364]         rn->name = name.data;
[3365] 
[3366]         name.data = ngx_resolver_dup(r, rn->name, name.len);
[3367]         if (name.data == NULL) {
[3368]             goto failed;
[3369]         }
[3370]     }
[3371] 
[3372]     ngx_queue_remove(&rn->queue);
[3373] 
[3374]     rn->valid = ngx_time() + (r->valid ? r->valid : ttl);
[3375]     rn->expire = ngx_time() + r->expire;
[3376] 
[3377]     ngx_queue_insert_head(expire_queue, &rn->queue);
[3378] 
[3379]     next = rn->waiting;
[3380]     rn->waiting = NULL;
[3381] 
[3382]     /* unlock addr mutex */
[3383] 
[3384]     while (next) {
[3385]         ctx = next;
[3386]         ctx->state = NGX_OK;
[3387]         ctx->valid = rn->valid;
[3388]         ctx->name = name;
[3389]         next = ctx->next;
[3390] 
[3391]         ctx->handler(ctx);
[3392]     }
[3393] 
[3394]     ngx_resolver_free(r, name.data);
[3395] 
[3396]     return;
[3397] 
[3398] short_response:
[3399] 
[3400]     err = "short DNS response";
[3401] 
[3402] invalid:
[3403] 
[3404]     /* unlock addr mutex */
[3405] 
[3406]     ngx_log_error(r->log_level, r->log, 0, err);
[3407] 
[3408]     return;
[3409] 
[3410] failed:
[3411] 
[3412]     /* unlock addr mutex */
[3413] 
[3414]     return;
[3415] }
[3416] 
[3417] 
[3418] static ngx_resolver_node_t *
[3419] ngx_resolver_lookup_name(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash)
[3420] {
[3421]     ngx_int_t             rc;
[3422]     ngx_rbtree_node_t    *node, *sentinel;
[3423]     ngx_resolver_node_t  *rn;
[3424] 
[3425]     node = r->name_rbtree.root;
[3426]     sentinel = r->name_rbtree.sentinel;
[3427] 
[3428]     while (node != sentinel) {
[3429] 
[3430]         if (hash < node->key) {
[3431]             node = node->left;
[3432]             continue;
[3433]         }
[3434] 
[3435]         if (hash > node->key) {
[3436]             node = node->right;
[3437]             continue;
[3438]         }
[3439] 
[3440]         /* hash == node->key */
[3441] 
[3442]         rn = ngx_resolver_node(node);
[3443] 
[3444]         rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);
[3445] 
[3446]         if (rc == 0) {
[3447]             return rn;
[3448]         }
[3449] 
[3450]         node = (rc < 0) ? node->left : node->right;
[3451]     }
[3452] 
[3453]     /* not found */
[3454] 
[3455]     return NULL;
[3456] }
[3457] 
[3458] 
[3459] static ngx_resolver_node_t *
[3460] ngx_resolver_lookup_srv(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash)
[3461] {
[3462]     ngx_int_t             rc;
[3463]     ngx_rbtree_node_t    *node, *sentinel;
[3464]     ngx_resolver_node_t  *rn;
[3465] 
[3466]     node = r->srv_rbtree.root;
[3467]     sentinel = r->srv_rbtree.sentinel;
[3468] 
[3469]     while (node != sentinel) {
[3470] 
[3471]         if (hash < node->key) {
[3472]             node = node->left;
[3473]             continue;
[3474]         }
[3475] 
[3476]         if (hash > node->key) {
[3477]             node = node->right;
[3478]             continue;
[3479]         }
[3480] 
[3481]         /* hash == node->key */
[3482] 
[3483]         rn = ngx_resolver_node(node);
[3484] 
[3485]         rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);
[3486] 
[3487]         if (rc == 0) {
[3488]             return rn;
[3489]         }
[3490] 
[3491]         node = (rc < 0) ? node->left : node->right;
[3492]     }
[3493] 
[3494]     /* not found */
[3495] 
[3496]     return NULL;
[3497] }
[3498] 
[3499] 
[3500] static ngx_resolver_node_t *
[3501] ngx_resolver_lookup_addr(ngx_resolver_t *r, in_addr_t addr)
[3502] {
[3503]     ngx_rbtree_node_t  *node, *sentinel;
[3504] 
[3505]     node = r->addr_rbtree.root;
[3506]     sentinel = r->addr_rbtree.sentinel;
[3507] 
[3508]     while (node != sentinel) {
[3509] 
[3510]         if (addr < node->key) {
[3511]             node = node->left;
[3512]             continue;
[3513]         }
[3514] 
[3515]         if (addr > node->key) {
[3516]             node = node->right;
[3517]             continue;
[3518]         }
[3519] 
[3520]         /* addr == node->key */
[3521] 
[3522]         return ngx_resolver_node(node);
[3523]     }
[3524] 
[3525]     /* not found */
[3526] 
[3527]     return NULL;
[3528] }
[3529] 
[3530] 
[3531] #if (NGX_HAVE_INET6)
[3532] 
[3533] static ngx_resolver_node_t *
[3534] ngx_resolver_lookup_addr6(ngx_resolver_t *r, struct in6_addr *addr,
[3535]     uint32_t hash)
[3536] {
[3537]     ngx_int_t             rc;
[3538]     ngx_rbtree_node_t    *node, *sentinel;
[3539]     ngx_resolver_node_t  *rn;
[3540] 
[3541]     node = r->addr6_rbtree.root;
[3542]     sentinel = r->addr6_rbtree.sentinel;
[3543] 
[3544]     while (node != sentinel) {
[3545] 
[3546]         if (hash < node->key) {
[3547]             node = node->left;
[3548]             continue;
[3549]         }
[3550] 
[3551]         if (hash > node->key) {
[3552]             node = node->right;
[3553]             continue;
[3554]         }
[3555] 
[3556]         /* hash == node->key */
[3557] 
[3558]         rn = ngx_resolver_node(node);
[3559] 
[3560]         rc = ngx_memcmp(addr, &rn->addr6, 16);
[3561] 
[3562]         if (rc == 0) {
[3563]             return rn;
[3564]         }
[3565] 
[3566]         node = (rc < 0) ? node->left : node->right;
[3567]     }
[3568] 
[3569]     /* not found */
[3570] 
[3571]     return NULL;
[3572] }
[3573] 
[3574] #endif
[3575] 
[3576] 
[3577] static void
[3578] ngx_resolver_rbtree_insert_value(ngx_rbtree_node_t *temp,
[3579]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[3580] {
[3581]     ngx_rbtree_node_t    **p;
[3582]     ngx_resolver_node_t   *rn, *rn_temp;
[3583] 
[3584]     for ( ;; ) {
[3585] 
[3586]         if (node->key < temp->key) {
[3587] 
[3588]             p = &temp->left;
[3589] 
[3590]         } else if (node->key > temp->key) {
[3591] 
[3592]             p = &temp->right;
[3593] 
[3594]         } else { /* node->key == temp->key */
[3595] 
[3596]             rn = ngx_resolver_node(node);
[3597]             rn_temp = ngx_resolver_node(temp);
[3598] 
[3599]             p = (ngx_memn2cmp(rn->name, rn_temp->name, rn->nlen, rn_temp->nlen)
[3600]                  < 0) ? &temp->left : &temp->right;
[3601]         }
[3602] 
[3603]         if (*p == sentinel) {
[3604]             break;
[3605]         }
[3606] 
[3607]         temp = *p;
[3608]     }
[3609] 
[3610]     *p = node;
[3611]     node->parent = temp;
[3612]     node->left = sentinel;
[3613]     node->right = sentinel;
[3614]     ngx_rbt_red(node);
[3615] }
[3616] 
[3617] 
[3618] #if (NGX_HAVE_INET6)
[3619] 
[3620] static void
[3621] ngx_resolver_rbtree_insert_addr6_value(ngx_rbtree_node_t *temp,
[3622]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[3623] {
[3624]     ngx_rbtree_node_t    **p;
[3625]     ngx_resolver_node_t   *rn, *rn_temp;
[3626] 
[3627]     for ( ;; ) {
[3628] 
[3629]         if (node->key < temp->key) {
[3630] 
[3631]             p = &temp->left;
[3632] 
[3633]         } else if (node->key > temp->key) {
[3634] 
[3635]             p = &temp->right;
[3636] 
[3637]         } else { /* node->key == temp->key */
[3638] 
[3639]             rn = ngx_resolver_node(node);
[3640]             rn_temp = ngx_resolver_node(temp);
[3641] 
[3642]             p = (ngx_memcmp(&rn->addr6, &rn_temp->addr6, 16)
[3643]                  < 0) ? &temp->left : &temp->right;
[3644]         }
[3645] 
[3646]         if (*p == sentinel) {
[3647]             break;
[3648]         }
[3649] 
[3650]         temp = *p;
[3651]     }
[3652] 
[3653]     *p = node;
[3654]     node->parent = temp;
[3655]     node->left = sentinel;
[3656]     node->right = sentinel;
[3657]     ngx_rbt_red(node);
[3658] }
[3659] 
[3660] #endif
[3661] 
[3662] 
[3663] static ngx_int_t
[3664] ngx_resolver_create_name_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
[3665]     ngx_str_t *name)
[3666] {
[3667]     u_char              *p, *s;
[3668]     size_t               len, nlen;
[3669]     ngx_uint_t           ident;
[3670]     ngx_resolver_qs_t   *qs;
[3671]     ngx_resolver_hdr_t  *query;
[3672] 
[3673]     nlen = name->len ? (1 + name->len + 1) : 1;
[3674] 
[3675]     len = sizeof(ngx_resolver_hdr_t) + nlen + sizeof(ngx_resolver_qs_t);
[3676] 
[3677] #if (NGX_HAVE_INET6)
[3678]     p = ngx_resolver_alloc(r, len * (r->ipv4 + r->ipv6));
[3679] #else
[3680]     p = ngx_resolver_alloc(r, len);
[3681] #endif
[3682]     if (p == NULL) {
[3683]         return NGX_ERROR;
[3684]     }
[3685] 
[3686]     rn->qlen = (u_short) len;
[3687]     rn->query = p;
[3688] 
[3689] #if (NGX_HAVE_INET6)
[3690]     if (r->ipv6) {
[3691]         rn->query6 = r->ipv4 ? (p + len) : p;
[3692]     }
[3693] #endif
[3694] 
[3695]     query = (ngx_resolver_hdr_t *) p;
[3696] 
[3697]     if (r->ipv4) {
[3698]         ident = ngx_random();
[3699] 
[3700]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
[3701]                        "resolve: \"%V\" A %i", name, ident & 0xffff);
[3702] 
[3703]         query->ident_hi = (u_char) ((ident >> 8) & 0xff);
[3704]         query->ident_lo = (u_char) (ident & 0xff);
[3705]     }
[3706] 
[3707]     /* recursion query */
[3708]     query->flags_hi = 1; query->flags_lo = 0;
[3709] 
[3710]     /* one question */
[3711]     query->nqs_hi = 0; query->nqs_lo = 1;
[3712]     query->nan_hi = 0; query->nan_lo = 0;
[3713]     query->nns_hi = 0; query->nns_lo = 0;
[3714]     query->nar_hi = 0; query->nar_lo = 0;
[3715] 
[3716]     p += sizeof(ngx_resolver_hdr_t) + nlen;
[3717] 
[3718]     qs = (ngx_resolver_qs_t *) p;
[3719] 
[3720]     /* query type */
[3721]     qs->type_hi = 0; qs->type_lo = NGX_RESOLVE_A;
[3722] 
[3723]     /* IN query class */
[3724]     qs->class_hi = 0; qs->class_lo = 1;
[3725] 
[3726]     /* convert "www.example.com" to "\3www\7example\3com\0" */
[3727] 
[3728]     len = 0;
[3729]     p--;
[3730]     *p-- = '\0';
[3731] 
[3732]     if (name->len == 0)  {
[3733]         return NGX_DECLINED;
[3734]     }
[3735] 
[3736]     for (s = name->data + name->len - 1; s >= name->data; s--) {
[3737]         if (*s != '.') {
[3738]             *p = *s;
[3739]             len++;
[3740] 
[3741]         } else {
[3742]             if (len == 0 || len > 255) {
[3743]                 return NGX_DECLINED;
[3744]             }
[3745] 
[3746]             *p = (u_char) len;
[3747]             len = 0;
[3748]         }
[3749] 
[3750]         p--;
[3751]     }
[3752] 
[3753]     if (len == 0 || len > 255) {
[3754]         return NGX_DECLINED;
[3755]     }
[3756] 
[3757]     *p = (u_char) len;
[3758] 
[3759] #if (NGX_HAVE_INET6)
[3760]     if (!r->ipv6) {
[3761]         return NGX_OK;
[3762]     }
[3763] 
[3764]     p = rn->query6;
[3765] 
[3766]     if (r->ipv4) {
[3767]         ngx_memcpy(p, rn->query, rn->qlen);
[3768]     }
[3769] 
[3770]     query = (ngx_resolver_hdr_t *) p;
[3771] 
[3772]     ident = ngx_random();
[3773] 
[3774]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
[3775]                    "resolve: \"%V\" AAAA %i", name, ident & 0xffff);
[3776] 
[3777]     query->ident_hi = (u_char) ((ident >> 8) & 0xff);
[3778]     query->ident_lo = (u_char) (ident & 0xff);
[3779] 
[3780]     p += sizeof(ngx_resolver_hdr_t) + nlen;
[3781] 
[3782]     qs = (ngx_resolver_qs_t *) p;
[3783] 
[3784]     qs->type_lo = NGX_RESOLVE_AAAA;
[3785] #endif
[3786] 
[3787]     return NGX_OK;
[3788] }
[3789] 
[3790] 
[3791] static ngx_int_t
[3792] ngx_resolver_create_srv_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
[3793]     ngx_str_t *name)
[3794] {
[3795]     u_char              *p, *s;
[3796]     size_t               len, nlen;
[3797]     ngx_uint_t           ident;
[3798]     ngx_resolver_qs_t   *qs;
[3799]     ngx_resolver_hdr_t  *query;
[3800] 
[3801]     nlen = name->len ? (1 + name->len + 1) : 1;
[3802] 
[3803]     len = sizeof(ngx_resolver_hdr_t) + nlen + sizeof(ngx_resolver_qs_t);
[3804] 
[3805]     p = ngx_resolver_alloc(r, len);
[3806]     if (p == NULL) {
[3807]         return NGX_ERROR;
[3808]     }
[3809] 
[3810]     rn->qlen = (u_short) len;
[3811]     rn->query = p;
[3812] 
[3813]     query = (ngx_resolver_hdr_t *) p;
[3814] 
[3815]     ident = ngx_random();
[3816] 
[3817]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
[3818]                    "resolve: \"%V\" SRV %i", name, ident & 0xffff);
[3819] 
[3820]     query->ident_hi = (u_char) ((ident >> 8) & 0xff);
[3821]     query->ident_lo = (u_char) (ident & 0xff);
[3822] 
[3823]     /* recursion query */
[3824]     query->flags_hi = 1; query->flags_lo = 0;
[3825] 
[3826]     /* one question */
[3827]     query->nqs_hi = 0; query->nqs_lo = 1;
[3828]     query->nan_hi = 0; query->nan_lo = 0;
[3829]     query->nns_hi = 0; query->nns_lo = 0;
[3830]     query->nar_hi = 0; query->nar_lo = 0;
[3831] 
[3832]     p += sizeof(ngx_resolver_hdr_t) + nlen;
[3833] 
[3834]     qs = (ngx_resolver_qs_t *) p;
[3835] 
[3836]     /* query type */
[3837]     qs->type_hi = 0; qs->type_lo = NGX_RESOLVE_SRV;
[3838] 
[3839]     /* IN query class */
[3840]     qs->class_hi = 0; qs->class_lo = 1;
[3841] 
[3842]     /* converts "www.example.com" to "\3www\7example\3com\0" */
[3843] 
[3844]     len = 0;
[3845]     p--;
[3846]     *p-- = '\0';
[3847] 
[3848]     if (name->len == 0)  {
[3849]         return NGX_DECLINED;
[3850]     }
[3851] 
[3852]     for (s = name->data + name->len - 1; s >= name->data; s--) {
[3853]         if (*s != '.') {
[3854]             *p = *s;
[3855]             len++;
[3856] 
[3857]         } else {
[3858]             if (len == 0 || len > 255) {
[3859]                 return NGX_DECLINED;
[3860]             }
[3861] 
[3862]             *p = (u_char) len;
[3863]             len = 0;
[3864]         }
[3865] 
[3866]         p--;
[3867]     }
[3868] 
[3869]     if (len == 0 || len > 255) {
[3870]         return NGX_DECLINED;
[3871]     }
[3872] 
[3873]     *p = (u_char) len;
[3874] 
[3875]     return NGX_OK;
[3876] }
[3877] 
[3878] 
[3879] static ngx_int_t
[3880] ngx_resolver_create_addr_query(ngx_resolver_t *r, ngx_resolver_node_t *rn,
[3881]     ngx_resolver_addr_t *addr)
[3882] {
[3883]     u_char               *p, *d;
[3884]     size_t                len;
[3885]     in_addr_t             inaddr;
[3886]     ngx_int_t             n;
[3887]     ngx_uint_t            ident;
[3888]     ngx_resolver_hdr_t   *query;
[3889]     struct sockaddr_in   *sin;
[3890] #if (NGX_HAVE_INET6)
[3891]     struct sockaddr_in6  *sin6;
[3892] #endif
[3893] 
[3894]     switch (addr->sockaddr->sa_family) {
[3895] 
[3896] #if (NGX_HAVE_INET6)
[3897]     case AF_INET6:
[3898]         len = sizeof(ngx_resolver_hdr_t)
[3899]               + 64 + sizeof(".ip6.arpa.") - 1
[3900]               + sizeof(ngx_resolver_qs_t);
[3901] 
[3902]         break;
[3903] #endif
[3904] 
[3905]     default: /* AF_INET */
[3906]         len = sizeof(ngx_resolver_hdr_t)
[3907]               + sizeof(".255.255.255.255.in-addr.arpa.") - 1
[3908]               + sizeof(ngx_resolver_qs_t);
[3909]     }
[3910] 
[3911]     p = ngx_resolver_alloc(r, len);
[3912]     if (p == NULL) {
[3913]         return NGX_ERROR;
[3914]     }
[3915] 
[3916]     rn->query = p;
[3917]     query = (ngx_resolver_hdr_t *) p;
[3918] 
[3919]     ident = ngx_random();
[3920] 
[3921]     query->ident_hi = (u_char) ((ident >> 8) & 0xff);
[3922]     query->ident_lo = (u_char) (ident & 0xff);
[3923] 
[3924]     /* recursion query */
[3925]     query->flags_hi = 1; query->flags_lo = 0;
[3926] 
[3927]     /* one question */
[3928]     query->nqs_hi = 0; query->nqs_lo = 1;
[3929]     query->nan_hi = 0; query->nan_lo = 0;
[3930]     query->nns_hi = 0; query->nns_lo = 0;
[3931]     query->nar_hi = 0; query->nar_lo = 0;
[3932] 
[3933]     p += sizeof(ngx_resolver_hdr_t);
[3934] 
[3935]     switch (addr->sockaddr->sa_family) {
[3936] 
[3937] #if (NGX_HAVE_INET6)
[3938]     case AF_INET6:
[3939]         sin6 = (struct sockaddr_in6 *) addr->sockaddr;
[3940] 
[3941]         for (n = 15; n >= 0; n--) {
[3942]             p = ngx_sprintf(p, "\1%xd\1%xd",
[3943]                             sin6->sin6_addr.s6_addr[n] & 0xf,
[3944]                             (sin6->sin6_addr.s6_addr[n] >> 4) & 0xf);
[3945]         }
[3946] 
[3947]         p = ngx_cpymem(p, "\3ip6\4arpa\0", 10);
[3948] 
[3949]         break;
[3950] #endif
[3951] 
[3952]     default: /* AF_INET */
[3953] 
[3954]         sin = (struct sockaddr_in *) addr->sockaddr;
[3955]         inaddr = ntohl(sin->sin_addr.s_addr);
[3956] 
[3957]         for (n = 0; n < 32; n += 8) {
[3958]             d = ngx_sprintf(&p[1], "%ud", (inaddr >> n) & 0xff);
[3959]             *p = (u_char) (d - &p[1]);
[3960]             p = d;
[3961]         }
[3962] 
[3963]         p = ngx_cpymem(p, "\7in-addr\4arpa\0", 14);
[3964]     }
[3965] 
[3966]     /* query type "PTR", IN query class */
[3967]     p = ngx_cpymem(p, "\0\14\0\1", 4);
[3968] 
[3969]     rn->qlen = (u_short) (p - rn->query);
[3970] 
[3971]     return NGX_OK;
[3972] }
[3973] 
[3974] 
[3975] static ngx_int_t
[3976] ngx_resolver_copy(ngx_resolver_t *r, ngx_str_t *name, u_char *buf, u_char *src,
[3977]     u_char *last)
[3978] {
[3979]     char        *err;
[3980]     u_char      *p, *dst;
[3981]     size_t       len;
[3982]     ngx_uint_t   i, n;
[3983] 
[3984]     p = src;
[3985]     len = 0;
[3986] 
[3987]     /*
[3988]      * compression pointers allow to create endless loop, so we set limit;
[3989]      * 128 pointers should be enough to store 255-byte name
[3990]      */
[3991] 
[3992]     for (i = 0; i < 128; i++) {
[3993]         n = *p++;
[3994] 
[3995]         if (n == 0) {
[3996]             goto done;
[3997]         }
[3998] 
[3999]         if (n & 0xc0) {
[4000]             if ((n & 0xc0) != 0xc0) {
[4001]                 err = "invalid label type in DNS response";
[4002]                 goto invalid;
[4003]             }
[4004] 
[4005]             if (p >= last) {
[4006]                 err = "name is out of DNS response";
[4007]                 goto invalid;
[4008]             }
[4009] 
[4010]             n = ((n & 0x3f) << 8) + *p;
[4011]             p = &buf[n];
[4012] 
[4013]         } else {
[4014]             len += 1 + n;
[4015]             p = &p[n];
[4016]         }
[4017] 
[4018]         if (p >= last) {
[4019]             err = "name is out of DNS response";
[4020]             goto invalid;
[4021]         }
[4022]     }
[4023] 
[4024]     err = "compression pointers loop in DNS response";
[4025] 
[4026] invalid:
[4027] 
[4028]     ngx_log_error(r->log_level, r->log, 0, err);
[4029] 
[4030]     return NGX_ERROR;
[4031] 
[4032] done:
[4033] 
[4034]     if (name == NULL) {
[4035]         return NGX_OK;
[4036]     }
[4037] 
[4038]     if (len == 0) {
[4039]         ngx_str_null(name);
[4040]         return NGX_OK;
[4041]     }
[4042] 
[4043]     dst = ngx_resolver_alloc(r, len);
[4044]     if (dst == NULL) {
[4045]         return NGX_ERROR;
[4046]     }
[4047] 
[4048]     name->data = dst;
[4049] 
[4050]     for ( ;; ) {
[4051]         n = *src++;
[4052] 
[4053]         if (n == 0) {
[4054]             name->len = dst - name->data - 1;
[4055]             return NGX_OK;
[4056]         }
[4057] 
[4058]         if (n & 0xc0) {
[4059]             n = ((n & 0x3f) << 8) + *src;
[4060]             src = &buf[n];
[4061] 
[4062]         } else {
[4063]             ngx_strlow(dst, src, n);
[4064]             dst += n;
[4065]             src += n;
[4066]             *dst++ = '.';
[4067]         }
[4068]     }
[4069] }
[4070] 
[4071] 
[4072] static ngx_int_t
[4073] ngx_resolver_set_timeout(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx)
[4074] {
[4075]     if (ctx->event || ctx->timeout == 0) {
[4076]         return NGX_OK;
[4077]     }
[4078] 
[4079]     ctx->event = ngx_resolver_calloc(r, sizeof(ngx_event_t));
[4080]     if (ctx->event == NULL) {
[4081]         return NGX_ERROR;
[4082]     }
[4083] 
[4084]     ctx->event->handler = ngx_resolver_timeout_handler;
[4085]     ctx->event->data = ctx;
[4086]     ctx->event->log = r->log;
[4087]     ctx->event->cancelable = ctx->cancelable;
[4088]     ctx->ident = -1;
[4089] 
[4090]     ngx_add_timer(ctx->event, ctx->timeout);
[4091] 
[4092]     return NGX_OK;
[4093] }
[4094] 
[4095] 
[4096] static void
[4097] ngx_resolver_timeout_handler(ngx_event_t *ev)
[4098] {
[4099]     ngx_resolver_ctx_t  *ctx;
[4100] 
[4101]     ctx = ev->data;
[4102] 
[4103]     ctx->state = NGX_RESOLVE_TIMEDOUT;
[4104] 
[4105]     ctx->handler(ctx);
[4106] }
[4107] 
[4108] 
[4109] static void
[4110] ngx_resolver_free_node(ngx_resolver_t *r, ngx_resolver_node_t *rn)
[4111] {
[4112]     ngx_uint_t  i;
[4113] 
[4114]     /* lock alloc mutex */
[4115] 
[4116]     if (rn->query) {
[4117]         ngx_resolver_free_locked(r, rn->query);
[4118]     }
[4119] 
[4120]     if (rn->name) {
[4121]         ngx_resolver_free_locked(r, rn->name);
[4122]     }
[4123] 
[4124]     if (rn->cnlen) {
[4125]         ngx_resolver_free_locked(r, rn->u.cname);
[4126]     }
[4127] 
[4128]     if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
[4129]         ngx_resolver_free_locked(r, rn->u.addrs);
[4130]     }
[4131] 
[4132] #if (NGX_HAVE_INET6)
[4133]     if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
[4134]         ngx_resolver_free_locked(r, rn->u6.addrs6);
[4135]     }
[4136] #endif
[4137] 
[4138]     if (rn->nsrvs) {
[4139]         for (i = 0; i < (ngx_uint_t) rn->nsrvs; i++) {
[4140]             if (rn->u.srvs[i].name.data) {
[4141]                 ngx_resolver_free_locked(r, rn->u.srvs[i].name.data);
[4142]             }
[4143]         }
[4144] 
[4145]         ngx_resolver_free_locked(r, rn->u.srvs);
[4146]     }
[4147] 
[4148]     ngx_resolver_free_locked(r, rn);
[4149] 
[4150]     /* unlock alloc mutex */
[4151] }
[4152] 
[4153] 
[4154] static void *
[4155] ngx_resolver_alloc(ngx_resolver_t *r, size_t size)
[4156] {
[4157]     u_char  *p;
[4158] 
[4159]     /* lock alloc mutex */
[4160] 
[4161]     p = ngx_alloc(size, r->log);
[4162] 
[4163]     /* unlock alloc mutex */
[4164] 
[4165]     return p;
[4166] }
[4167] 
[4168] 
[4169] static void *
[4170] ngx_resolver_calloc(ngx_resolver_t *r, size_t size)
[4171] {
[4172]     u_char  *p;
[4173] 
[4174]     p = ngx_resolver_alloc(r, size);
[4175] 
[4176]     if (p) {
[4177]         ngx_memzero(p, size);
[4178]     }
[4179] 
[4180]     return p;
[4181] }
[4182] 
[4183] 
[4184] static void
[4185] ngx_resolver_free(ngx_resolver_t *r, void *p)
[4186] {
[4187]     /* lock alloc mutex */
[4188] 
[4189]     ngx_free(p);
[4190] 
[4191]     /* unlock alloc mutex */
[4192] }
[4193] 
[4194] 
[4195] static void
[4196] ngx_resolver_free_locked(ngx_resolver_t *r, void *p)
[4197] {
[4198]     ngx_free(p);
[4199] }
[4200] 
[4201] 
[4202] static void *
[4203] ngx_resolver_dup(ngx_resolver_t *r, void *src, size_t size)
[4204] {
[4205]     void  *dst;
[4206] 
[4207]     dst = ngx_resolver_alloc(r, size);
[4208] 
[4209]     if (dst == NULL) {
[4210]         return dst;
[4211]     }
[4212] 
[4213]     ngx_memcpy(dst, src, size);
[4214] 
[4215]     return dst;
[4216] }
[4217] 
[4218] 
[4219] static ngx_resolver_addr_t *
[4220] ngx_resolver_export(ngx_resolver_t *r, ngx_resolver_node_t *rn,
[4221]     ngx_uint_t rotate)
[4222] {
[4223]     ngx_uint_t            d, i, j, n;
[4224]     in_addr_t            *addr;
[4225]     ngx_sockaddr_t       *sockaddr;
[4226]     struct sockaddr_in   *sin;
[4227]     ngx_resolver_addr_t  *dst;
[4228] #if (NGX_HAVE_INET6)
[4229]     struct in6_addr      *addr6;
[4230]     struct sockaddr_in6  *sin6;
[4231] #endif
[4232] 
[4233]     n = rn->naddrs;
[4234] #if (NGX_HAVE_INET6)
[4235]     n += rn->naddrs6;
[4236] #endif
[4237] 
[4238]     dst = ngx_resolver_calloc(r, n * sizeof(ngx_resolver_addr_t));
[4239]     if (dst == NULL) {
[4240]         return NULL;
[4241]     }
[4242] 
[4243]     sockaddr = ngx_resolver_calloc(r, n * sizeof(ngx_sockaddr_t));
[4244]     if (sockaddr == NULL) {
[4245]         ngx_resolver_free(r, dst);
[4246]         return NULL;
[4247]     }
[4248] 
[4249]     i = 0;
[4250]     d = rotate ? ngx_random() % n : 0;
[4251] 
[4252]     if (rn->naddrs) {
[4253]         j = rotate ? ngx_random() % rn->naddrs : 0;
[4254] 
[4255]         addr = (rn->naddrs == 1) ? &rn->u.addr : rn->u.addrs;
[4256] 
[4257]         do {
[4258]             sin = &sockaddr[d].sockaddr_in;
[4259]             sin->sin_family = AF_INET;
[4260]             sin->sin_addr.s_addr = addr[j++];
[4261]             dst[d].sockaddr = (struct sockaddr *) sin;
[4262]             dst[d++].socklen = sizeof(struct sockaddr_in);
[4263] 
[4264]             if (d == n) {
[4265]                 d = 0;
[4266]             }
[4267] 
[4268]             if (j == (ngx_uint_t) rn->naddrs) {
[4269]                 j = 0;
[4270]             }
[4271]         } while (++i < (ngx_uint_t) rn->naddrs);
[4272]     }
[4273] 
[4274] #if (NGX_HAVE_INET6)
[4275]     if (rn->naddrs6) {
[4276]         j = rotate ? ngx_random() % rn->naddrs6 : 0;
[4277] 
[4278]         addr6 = (rn->naddrs6 == 1) ? &rn->u6.addr6 : rn->u6.addrs6;
[4279] 
[4280]         do {
[4281]             sin6 = &sockaddr[d].sockaddr_in6;
[4282]             sin6->sin6_family = AF_INET6;
[4283]             ngx_memcpy(sin6->sin6_addr.s6_addr, addr6[j++].s6_addr, 16);
[4284]             dst[d].sockaddr = (struct sockaddr *) sin6;
[4285]             dst[d++].socklen = sizeof(struct sockaddr_in6);
[4286] 
[4287]             if (d == n) {
[4288]                 d = 0;
[4289]             }
[4290] 
[4291]             if (j == rn->naddrs6) {
[4292]                 j = 0;
[4293]             }
[4294]         } while (++i < n);
[4295]     }
[4296] #endif
[4297] 
[4298]     return dst;
[4299] }
[4300] 
[4301] 
[4302] static void
[4303] ngx_resolver_report_srv(ngx_resolver_t *r, ngx_resolver_ctx_t *ctx)
[4304] {
[4305]     ngx_uint_t                naddrs, nsrvs, nw, i, j, k, l, m, n, w;
[4306]     ngx_resolver_addr_t      *addrs;
[4307]     ngx_resolver_srv_name_t  *srvs;
[4308] 
[4309]     srvs = ctx->srvs;
[4310]     nsrvs = ctx->nsrvs;
[4311] 
[4312]     naddrs = 0;
[4313] 
[4314]     for (i = 0; i < nsrvs; i++) {
[4315]         if (srvs[i].state == NGX_ERROR) {
[4316]             ctx->state = NGX_ERROR;
[4317]             ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[4318] 
[4319]             ctx->handler(ctx);
[4320]             return;
[4321]         }
[4322] 
[4323]         naddrs += srvs[i].naddrs;
[4324]     }
[4325] 
[4326]     if (naddrs == 0) {
[4327]         ctx->state = srvs[0].state;
[4328] 
[4329]         for (i = 0; i < nsrvs; i++) {
[4330]             if (srvs[i].state == NGX_RESOLVE_NXDOMAIN) {
[4331]                 ctx->state = NGX_RESOLVE_NXDOMAIN;
[4332]                 break;
[4333]             }
[4334]         }
[4335] 
[4336]         ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[4337] 
[4338]         ctx->handler(ctx);
[4339]         return;
[4340]     }
[4341] 
[4342]     addrs = ngx_resolver_calloc(r, naddrs * sizeof(ngx_resolver_addr_t));
[4343]     if (addrs == NULL) {
[4344]         ctx->state = NGX_ERROR;
[4345]         ctx->valid = ngx_time() + (r->valid ? r->valid : 10);
[4346] 
[4347]         ctx->handler(ctx);
[4348]         return;
[4349]     }
[4350] 
[4351]     i = 0;
[4352]     n = 0;
[4353] 
[4354]     do {
[4355]         nw = 0;
[4356] 
[4357]         for (j = i; j < nsrvs; j++) {
[4358]             if (srvs[j].priority != srvs[i].priority) {
[4359]                 break;
[4360]             }
[4361] 
[4362]             nw += srvs[j].naddrs * srvs[j].weight;
[4363]         }
[4364] 
[4365]         if (nw == 0) {
[4366]             goto next_srv;
[4367]         }
[4368] 
[4369]         w = ngx_random() % nw;
[4370] 
[4371]         for (k = i; k < j; k++) {
[4372]             if (w < srvs[k].naddrs * srvs[k].weight) {
[4373]                 break;
[4374]             }
[4375] 
[4376]             w -= srvs[k].naddrs * srvs[k].weight;
[4377]         }
[4378] 
[4379]         for (l = i; l < j; l++) {
[4380] 
[4381]             for (m = 0; m < srvs[k].naddrs; m++) {
[4382]                 addrs[n].socklen = srvs[k].addrs[m].socklen;
[4383]                 addrs[n].sockaddr = srvs[k].addrs[m].sockaddr;
[4384]                 addrs[n].name = srvs[k].name;
[4385]                 addrs[n].priority = srvs[k].priority;
[4386]                 addrs[n].weight = srvs[k].weight;
[4387]                 n++;
[4388]             }
[4389] 
[4390]             if (++k == j) {
[4391]                 k = i;
[4392]             }
[4393]         }
[4394] 
[4395] next_srv:
[4396] 
[4397]         i = j;
[4398] 
[4399]     } while (i < ctx->nsrvs);
[4400] 
[4401]     ctx->state = NGX_OK;
[4402]     ctx->addrs = addrs;
[4403]     ctx->naddrs = naddrs;
[4404] 
[4405]     ctx->handler(ctx);
[4406] 
[4407]     ngx_resolver_free(r, addrs);
[4408] }
[4409] 
[4410] 
[4411] char *
[4412] ngx_resolver_strerror(ngx_int_t err)
[4413] {
[4414]     static char *errors[] = {
[4415]         "Format error",     /* FORMERR */
[4416]         "Server failure",   /* SERVFAIL */
[4417]         "Host not found",   /* NXDOMAIN */
[4418]         "Unimplemented",    /* NOTIMP */
[4419]         "Operation refused" /* REFUSED */
[4420]     };
[4421] 
[4422]     if (err > 0 && err < 6) {
[4423]         return errors[err - 1];
[4424]     }
[4425] 
[4426]     if (err == NGX_RESOLVE_TIMEDOUT) {
[4427]         return "Operation timed out";
[4428]     }
[4429] 
[4430]     return "Unknown error";
[4431] }
[4432] 
[4433] 
[4434] static u_char *
[4435] ngx_resolver_log_error(ngx_log_t *log, u_char *buf, size_t len)
[4436] {
[4437]     u_char                     *p;
[4438]     ngx_resolver_connection_t  *rec;
[4439] 
[4440]     p = buf;
[4441] 
[4442]     if (log->action) {
[4443]         p = ngx_snprintf(buf, len, " while %s", log->action);
[4444]         len -= p - buf;
[4445]     }
[4446] 
[4447]     rec = log->data;
[4448] 
[4449]     if (rec) {
[4450]         p = ngx_snprintf(p, len, ", resolver: %V", &rec->server);
[4451]     }
[4452] 
[4453]     return p;
[4454] }
[4455] 
[4456] 
[4457] static ngx_int_t
[4458] ngx_udp_connect(ngx_resolver_connection_t *rec)
[4459] {
[4460]     int                rc;
[4461]     ngx_int_t          event;
[4462]     ngx_event_t       *rev, *wev;
[4463]     ngx_socket_t       s;
[4464]     ngx_connection_t  *c;
[4465] 
[4466]     s = ngx_socket(rec->sockaddr->sa_family, SOCK_DGRAM, 0);
[4467] 
[4468]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "UDP socket %d", s);
[4469] 
[4470]     if (s == (ngx_socket_t) -1) {
[4471]         ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4472]                       ngx_socket_n " failed");
[4473]         return NGX_ERROR;
[4474]     }
[4475] 
[4476]     c = ngx_get_connection(s, &rec->log);
[4477] 
[4478]     if (c == NULL) {
[4479]         if (ngx_close_socket(s) == -1) {
[4480]             ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4481]                           ngx_close_socket_n " failed");
[4482]         }
[4483] 
[4484]         return NGX_ERROR;
[4485]     }
[4486] 
[4487]     if (ngx_nonblocking(s) == -1) {
[4488]         ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4489]                       ngx_nonblocking_n " failed");
[4490] 
[4491]         goto failed;
[4492]     }
[4493] 
[4494]     rev = c->read;
[4495]     wev = c->write;
[4496] 
[4497]     rev->log = &rec->log;
[4498]     wev->log = &rec->log;
[4499] 
[4500]     rec->udp = c;
[4501] 
[4502]     c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
[4503] 
[4504]     c->start_time = ngx_current_msec;
[4505] 
[4506]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, &rec->log, 0,
[4507]                    "connect to %V, fd:%d #%uA", &rec->server, s, c->number);
[4508] 
[4509]     rc = connect(s, rec->sockaddr, rec->socklen);
[4510] 
[4511]     /* TODO: iocp */
[4512] 
[4513]     if (rc == -1) {
[4514]         ngx_log_error(NGX_LOG_CRIT, &rec->log, ngx_socket_errno,
[4515]                       "connect() failed");
[4516] 
[4517]         goto failed;
[4518]     }
[4519] 
[4520]     /* UDP sockets are always ready to write */
[4521]     wev->ready = 1;
[4522] 
[4523]     event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
[4524]                 /* kqueue, epoll */                 NGX_CLEAR_EVENT:
[4525]                 /* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
[4526]                 /* eventport event type has no meaning: oneshot only */
[4527] 
[4528]     if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
[4529]         goto failed;
[4530]     }
[4531] 
[4532]     return NGX_OK;
[4533] 
[4534] failed:
[4535] 
[4536]     ngx_close_connection(c);
[4537]     rec->udp = NULL;
[4538] 
[4539]     return NGX_ERROR;
[4540] }
[4541] 
[4542] 
[4543] static ngx_int_t
[4544] ngx_tcp_connect(ngx_resolver_connection_t *rec)
[4545] {
[4546]     int                rc;
[4547]     ngx_int_t          event;
[4548]     ngx_err_t          err;
[4549]     ngx_uint_t         level;
[4550]     ngx_socket_t       s;
[4551]     ngx_event_t       *rev, *wev;
[4552]     ngx_connection_t  *c;
[4553] 
[4554]     s = ngx_socket(rec->sockaddr->sa_family, SOCK_STREAM, 0);
[4555] 
[4556]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "TCP socket %d", s);
[4557] 
[4558]     if (s == (ngx_socket_t) -1) {
[4559]         ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4560]                       ngx_socket_n " failed");
[4561]         return NGX_ERROR;
[4562]     }
[4563] 
[4564]     c = ngx_get_connection(s, &rec->log);
[4565] 
[4566]     if (c == NULL) {
[4567]         if (ngx_close_socket(s) == -1) {
[4568]             ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4569]                           ngx_close_socket_n " failed");
[4570]         }
[4571] 
[4572]         return NGX_ERROR;
[4573]     }
[4574] 
[4575]     if (ngx_nonblocking(s) == -1) {
[4576]         ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4577]                       ngx_nonblocking_n " failed");
[4578] 
[4579]         goto failed;
[4580]     }
[4581] 
[4582]     rev = c->read;
[4583]     wev = c->write;
[4584] 
[4585]     rev->log = &rec->log;
[4586]     wev->log = &rec->log;
[4587] 
[4588]     rec->tcp = c;
[4589] 
[4590]     c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
[4591] 
[4592]     c->start_time = ngx_current_msec;
[4593] 
[4594]     if (ngx_add_conn) {
[4595]         if (ngx_add_conn(c) == NGX_ERROR) {
[4596]             goto failed;
[4597]         }
[4598]     }
[4599] 
[4600]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, &rec->log, 0,
[4601]                    "connect to %V, fd:%d #%uA", &rec->server, s, c->number);
[4602] 
[4603]     rc = connect(s, rec->sockaddr, rec->socklen);
[4604] 
[4605]     if (rc == -1) {
[4606]         err = ngx_socket_errno;
[4607] 
[4608] 
[4609]         if (err != NGX_EINPROGRESS
[4610] #if (NGX_WIN32)
[4611]             /* Winsock returns WSAEWOULDBLOCK (NGX_EAGAIN) */
[4612]             && err != NGX_EAGAIN
[4613] #endif
[4614]             )
[4615]         {
[4616]             if (err == NGX_ECONNREFUSED
[4617] #if (NGX_LINUX)
[4618]                 /*
[4619]                  * Linux returns EAGAIN instead of ECONNREFUSED
[4620]                  * for unix sockets if listen queue is full
[4621]                  */
[4622]                 || err == NGX_EAGAIN
[4623] #endif
[4624]                 || err == NGX_ECONNRESET
[4625]                 || err == NGX_ENETDOWN
[4626]                 || err == NGX_ENETUNREACH
[4627]                 || err == NGX_EHOSTDOWN
[4628]                 || err == NGX_EHOSTUNREACH)
[4629]             {
[4630]                 level = NGX_LOG_ERR;
[4631] 
[4632]             } else {
[4633]                 level = NGX_LOG_CRIT;
[4634]             }
[4635] 
[4636]             ngx_log_error(level, &rec->log, err, "connect() to %V failed",
[4637]                           &rec->server);
[4638] 
[4639]             ngx_close_connection(c);
[4640]             rec->tcp = NULL;
[4641] 
[4642]             return NGX_ERROR;
[4643]         }
[4644]     }
[4645] 
[4646]     if (ngx_add_conn) {
[4647]         if (rc == -1) {
[4648] 
[4649]             /* NGX_EINPROGRESS */
[4650] 
[4651]             return NGX_AGAIN;
[4652]         }
[4653] 
[4654]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "connected");
[4655] 
[4656]         wev->ready = 1;
[4657] 
[4658]         return NGX_OK;
[4659]     }
[4660] 
[4661]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[4662] 
[4663]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &rec->log, ngx_socket_errno,
[4664]                        "connect(): %d", rc);
[4665] 
[4666]         if (ngx_blocking(s) == -1) {
[4667]             ngx_log_error(NGX_LOG_ALERT, &rec->log, ngx_socket_errno,
[4668]                           ngx_blocking_n " failed");
[4669]             goto failed;
[4670]         }
[4671] 
[4672]         /*
[4673]          * FreeBSD's aio allows to post an operation on non-connected socket.
[4674]          * NT does not support it.
[4675]          *
[4676]          * TODO: check in Win32, etc. As workaround we can use NGX_ONESHOT_EVENT
[4677]          */
[4678] 
[4679]         rev->ready = 1;
[4680]         wev->ready = 1;
[4681] 
[4682]         return NGX_OK;
[4683]     }
[4684] 
[4685]     if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
[4686] 
[4687]         /* kqueue */
[4688] 
[4689]         event = NGX_CLEAR_EVENT;
[4690] 
[4691]     } else {
[4692] 
[4693]         /* select, poll, /dev/poll */
[4694] 
[4695]         event = NGX_LEVEL_EVENT;
[4696]     }
[4697] 
[4698]     if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
[4699]         goto failed;
[4700]     }
[4701] 
[4702]     if (rc == -1) {
[4703] 
[4704]         /* NGX_EINPROGRESS */
[4705] 
[4706]         if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
[4707]             goto failed;
[4708]         }
[4709] 
[4710]         return NGX_AGAIN;
[4711]     }
[4712] 
[4713]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, &rec->log, 0, "connected");
[4714] 
[4715]     wev->ready = 1;
[4716] 
[4717]     return NGX_OK;
[4718] 
[4719] failed:
[4720] 
[4721]     ngx_close_connection(c);
[4722]     rec->tcp = NULL;
[4723] 
[4724]     return NGX_ERROR;
[4725] }
[4726] 
[4727] 
[4728] static ngx_int_t
[4729] ngx_resolver_cmp_srvs(const void *one, const void *two)
[4730] {
[4731]     ngx_int_t            p1, p2;
[4732]     ngx_resolver_srv_t  *first, *second;
[4733] 
[4734]     first = (ngx_resolver_srv_t *) one;
[4735]     second = (ngx_resolver_srv_t *) two;
[4736] 
[4737]     p1 = first->priority;
[4738]     p2 = second->priority;
[4739] 
[4740]     return p1 - p2;
[4741] }
