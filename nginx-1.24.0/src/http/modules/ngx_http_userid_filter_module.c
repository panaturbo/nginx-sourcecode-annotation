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
[13] #define NGX_HTTP_USERID_OFF   0
[14] #define NGX_HTTP_USERID_LOG   1
[15] #define NGX_HTTP_USERID_V1    2
[16] #define NGX_HTTP_USERID_ON    3
[17] 
[18] #define NGX_HTTP_USERID_COOKIE_OFF              0x0002
[19] #define NGX_HTTP_USERID_COOKIE_SECURE           0x0004
[20] #define NGX_HTTP_USERID_COOKIE_HTTPONLY         0x0008
[21] #define NGX_HTTP_USERID_COOKIE_SAMESITE         0x0010
[22] #define NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT  0x0020
[23] #define NGX_HTTP_USERID_COOKIE_SAMESITE_LAX     0x0040
[24] #define NGX_HTTP_USERID_COOKIE_SAMESITE_NONE    0x0080
[25] 
[26] /* 31 Dec 2037 23:55:55 GMT */
[27] #define NGX_HTTP_USERID_MAX_EXPIRES  2145916555
[28] 
[29] 
[30] typedef struct {
[31]     ngx_uint_t  enable;
[32]     ngx_uint_t  flags;
[33] 
[34]     ngx_int_t   service;
[35] 
[36]     ngx_str_t   name;
[37]     ngx_str_t   domain;
[38]     ngx_str_t   path;
[39]     ngx_str_t   p3p;
[40] 
[41]     time_t      expires;
[42] 
[43]     u_char      mark;
[44] } ngx_http_userid_conf_t;
[45] 
[46] 
[47] typedef struct {
[48]     uint32_t    uid_got[4];
[49]     uint32_t    uid_set[4];
[50]     ngx_str_t   cookie;
[51]     ngx_uint_t  reset;
[52] } ngx_http_userid_ctx_t;
[53] 
[54] 
[55] static ngx_http_userid_ctx_t *ngx_http_userid_get_uid(ngx_http_request_t *r,
[56]     ngx_http_userid_conf_t *conf);
[57] static ngx_int_t ngx_http_userid_variable(ngx_http_request_t *r,
[58]     ngx_http_variable_value_t *v, ngx_str_t *name, uint32_t *uid);
[59] static ngx_int_t ngx_http_userid_set_uid(ngx_http_request_t *r,
[60]     ngx_http_userid_ctx_t *ctx, ngx_http_userid_conf_t *conf);
[61] static ngx_int_t ngx_http_userid_create_uid(ngx_http_request_t *r,
[62]     ngx_http_userid_ctx_t *ctx, ngx_http_userid_conf_t *conf);
[63] 
[64] static ngx_int_t ngx_http_userid_add_variables(ngx_conf_t *cf);
[65] static ngx_int_t ngx_http_userid_init(ngx_conf_t *cf);
[66] static void *ngx_http_userid_create_conf(ngx_conf_t *cf);
[67] static char *ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent,
[68]     void *child);
[69] static char *ngx_http_userid_domain(ngx_conf_t *cf, void *post, void *data);
[70] static char *ngx_http_userid_path(ngx_conf_t *cf, void *post, void *data);
[71] static char *ngx_http_userid_expires(ngx_conf_t *cf, ngx_command_t *cmd,
[72]     void *conf);
[73] static char *ngx_http_userid_p3p(ngx_conf_t *cf, void *post, void *data);
[74] static char *ngx_http_userid_mark(ngx_conf_t *cf, ngx_command_t *cmd,
[75]     void *conf);
[76] static ngx_int_t ngx_http_userid_init_worker(ngx_cycle_t *cycle);
[77] 
[78] 
[79] 
[80] static uint32_t  start_value;
[81] static uint32_t  sequencer_v1 = 1;
[82] static uint32_t  sequencer_v2 = 0x03030302;
[83] 
[84] 
[85] static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";
[86] 
[87] 
[88] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[89] 
[90] 
[91] static ngx_conf_enum_t  ngx_http_userid_state[] = {
[92]     { ngx_string("off"), NGX_HTTP_USERID_OFF },
[93]     { ngx_string("log"), NGX_HTTP_USERID_LOG },
[94]     { ngx_string("v1"), NGX_HTTP_USERID_V1 },
[95]     { ngx_string("on"), NGX_HTTP_USERID_ON },
[96]     { ngx_null_string, 0 }
[97] };
[98] 
[99] 
[100] static ngx_conf_bitmask_t  ngx_http_userid_flags[] = {
[101]     { ngx_string("off"), NGX_HTTP_USERID_COOKIE_OFF },
[102]     { ngx_string("secure"), NGX_HTTP_USERID_COOKIE_SECURE },
[103]     { ngx_string("httponly"), NGX_HTTP_USERID_COOKIE_HTTPONLY },
[104]     { ngx_string("samesite=strict"),
[105]       NGX_HTTP_USERID_COOKIE_SAMESITE|NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT },
[106]     { ngx_string("samesite=lax"),
[107]       NGX_HTTP_USERID_COOKIE_SAMESITE|NGX_HTTP_USERID_COOKIE_SAMESITE_LAX },
[108]     { ngx_string("samesite=none"),
[109]       NGX_HTTP_USERID_COOKIE_SAMESITE|NGX_HTTP_USERID_COOKIE_SAMESITE_NONE },
[110]     { ngx_null_string, 0 }
[111] };
[112] 
[113] 
[114] static ngx_conf_post_handler_pt  ngx_http_userid_domain_p =
[115]     ngx_http_userid_domain;
[116] static ngx_conf_post_handler_pt  ngx_http_userid_path_p = ngx_http_userid_path;
[117] static ngx_conf_post_handler_pt  ngx_http_userid_p3p_p = ngx_http_userid_p3p;
[118] 
[119] 
[120] static ngx_command_t  ngx_http_userid_commands[] = {
[121] 
[122]     { ngx_string("userid"),
[123]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[124]       ngx_conf_set_enum_slot,
[125]       NGX_HTTP_LOC_CONF_OFFSET,
[126]       offsetof(ngx_http_userid_conf_t, enable),
[127]       ngx_http_userid_state },
[128] 
[129]     { ngx_string("userid_service"),
[130]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[131]       ngx_conf_set_num_slot,
[132]       NGX_HTTP_LOC_CONF_OFFSET,
[133]       offsetof(ngx_http_userid_conf_t, service),
[134]       NULL },
[135] 
[136]     { ngx_string("userid_name"),
[137]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[138]       ngx_conf_set_str_slot,
[139]       NGX_HTTP_LOC_CONF_OFFSET,
[140]       offsetof(ngx_http_userid_conf_t, name),
[141]       NULL },
[142] 
[143]     { ngx_string("userid_domain"),
[144]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[145]       ngx_conf_set_str_slot,
[146]       NGX_HTTP_LOC_CONF_OFFSET,
[147]       offsetof(ngx_http_userid_conf_t, domain),
[148]       &ngx_http_userid_domain_p },
[149] 
[150]     { ngx_string("userid_path"),
[151]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[152]       ngx_conf_set_str_slot,
[153]       NGX_HTTP_LOC_CONF_OFFSET,
[154]       offsetof(ngx_http_userid_conf_t, path),
[155]       &ngx_http_userid_path_p },
[156] 
[157]     { ngx_string("userid_expires"),
[158]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[159]       ngx_http_userid_expires,
[160]       NGX_HTTP_LOC_CONF_OFFSET,
[161]       0,
[162]       NULL },
[163] 
[164]     { ngx_string("userid_flags"),
[165]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[166]       ngx_conf_set_bitmask_slot,
[167]       NGX_HTTP_LOC_CONF_OFFSET,
[168]       offsetof(ngx_http_userid_conf_t, flags),
[169]       &ngx_http_userid_flags },
[170] 
[171]     { ngx_string("userid_p3p"),
[172]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[173]       ngx_conf_set_str_slot,
[174]       NGX_HTTP_LOC_CONF_OFFSET,
[175]       offsetof(ngx_http_userid_conf_t, p3p),
[176]       &ngx_http_userid_p3p_p },
[177] 
[178]     { ngx_string("userid_mark"),
[179]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[180]       ngx_http_userid_mark,
[181]       NGX_HTTP_LOC_CONF_OFFSET,
[182]       0,
[183]       NULL },
[184] 
[185]       ngx_null_command
[186] };
[187] 
[188] 
[189] static ngx_http_module_t  ngx_http_userid_filter_module_ctx = {
[190]     ngx_http_userid_add_variables,         /* preconfiguration */
[191]     ngx_http_userid_init,                  /* postconfiguration */
[192] 
[193]     NULL,                                  /* create main configuration */
[194]     NULL,                                  /* init main configuration */
[195] 
[196]     NULL,                                  /* create server configuration */
[197]     NULL,                                  /* merge server configuration */
[198] 
[199]     ngx_http_userid_create_conf,           /* create location configuration */
[200]     ngx_http_userid_merge_conf             /* merge location configuration */
[201] };
[202] 
[203] 
[204] ngx_module_t  ngx_http_userid_filter_module = {
[205]     NGX_MODULE_V1,
[206]     &ngx_http_userid_filter_module_ctx,    /* module context */
[207]     ngx_http_userid_commands,              /* module directives */
[208]     NGX_HTTP_MODULE,                       /* module type */
[209]     NULL,                                  /* init master */
[210]     NULL,                                  /* init module */
[211]     ngx_http_userid_init_worker,           /* init process */
[212]     NULL,                                  /* init thread */
[213]     NULL,                                  /* exit thread */
[214]     NULL,                                  /* exit process */
[215]     NULL,                                  /* exit master */
[216]     NGX_MODULE_V1_PADDING
[217] };
[218] 
[219] 
[220] static ngx_str_t   ngx_http_userid_got = ngx_string("uid_got");
[221] static ngx_str_t   ngx_http_userid_set = ngx_string("uid_set");
[222] static ngx_str_t   ngx_http_userid_reset = ngx_string("uid_reset");
[223] static ngx_uint_t  ngx_http_userid_reset_index;
[224] 
[225] 
[226] static ngx_int_t
[227] ngx_http_userid_filter(ngx_http_request_t *r)
[228] {
[229]     ngx_http_userid_ctx_t   *ctx;
[230]     ngx_http_userid_conf_t  *conf;
[231] 
[232]     if (r != r->main) {
[233]         return ngx_http_next_header_filter(r);
[234]     }
[235] 
[236]     conf = ngx_http_get_module_loc_conf(r, ngx_http_userid_filter_module);
[237] 
[238]     if (conf->enable < NGX_HTTP_USERID_V1) {
[239]         return ngx_http_next_header_filter(r);
[240]     }
[241] 
[242]     ctx = ngx_http_userid_get_uid(r, conf);
[243] 
[244]     if (ctx == NULL) {
[245]         return NGX_ERROR;
[246]     }
[247] 
[248]     if (ngx_http_userid_set_uid(r, ctx, conf) == NGX_OK) {
[249]         return ngx_http_next_header_filter(r);
[250]     }
[251] 
[252]     return NGX_ERROR;
[253] }
[254] 
[255] 
[256] static ngx_int_t
[257] ngx_http_userid_got_variable(ngx_http_request_t *r,
[258]     ngx_http_variable_value_t *v, uintptr_t data)
[259] {
[260]     ngx_http_userid_ctx_t   *ctx;
[261]     ngx_http_userid_conf_t  *conf;
[262] 
[263]     conf = ngx_http_get_module_loc_conf(r->main, ngx_http_userid_filter_module);
[264] 
[265]     if (conf->enable == NGX_HTTP_USERID_OFF) {
[266]         v->not_found = 1;
[267]         return NGX_OK;
[268]     }
[269] 
[270]     ctx = ngx_http_userid_get_uid(r->main, conf);
[271] 
[272]     if (ctx == NULL) {
[273]         return NGX_ERROR;
[274]     }
[275] 
[276]     if (ctx->uid_got[3] != 0) {
[277]         return ngx_http_userid_variable(r->main, v, &conf->name, ctx->uid_got);
[278]     }
[279] 
[280]     v->not_found = 1;
[281] 
[282]     return NGX_OK;
[283] }
[284] 
[285] 
[286] static ngx_int_t
[287] ngx_http_userid_set_variable(ngx_http_request_t *r,
[288]     ngx_http_variable_value_t *v, uintptr_t data)
[289] {
[290]     ngx_http_userid_ctx_t   *ctx;
[291]     ngx_http_userid_conf_t  *conf;
[292] 
[293]     conf = ngx_http_get_module_loc_conf(r->main, ngx_http_userid_filter_module);
[294] 
[295]     if (conf->enable < NGX_HTTP_USERID_V1) {
[296]         v->not_found = 1;
[297]         return NGX_OK;
[298]     }
[299] 
[300]     ctx = ngx_http_userid_get_uid(r->main, conf);
[301] 
[302]     if (ctx == NULL) {
[303]         return NGX_ERROR;
[304]     }
[305] 
[306]     if (ngx_http_userid_create_uid(r->main, ctx, conf) != NGX_OK) {
[307]         return NGX_ERROR;
[308]     }
[309] 
[310]     if (ctx->uid_set[3] == 0) {
[311]         v->not_found = 1;
[312]         return NGX_OK;
[313]     }
[314] 
[315]     return ngx_http_userid_variable(r->main, v, &conf->name, ctx->uid_set);
[316] }
[317] 
[318] 
[319] static ngx_http_userid_ctx_t *
[320] ngx_http_userid_get_uid(ngx_http_request_t *r, ngx_http_userid_conf_t *conf)
[321] {
[322]     ngx_str_t               src, dst;
[323]     ngx_table_elt_t        *cookie;
[324]     ngx_http_userid_ctx_t  *ctx;
[325] 
[326]     ctx = ngx_http_get_module_ctx(r, ngx_http_userid_filter_module);
[327] 
[328]     if (ctx) {
[329]         return ctx;
[330]     }
[331] 
[332]     if (ctx == NULL) {
[333]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_userid_ctx_t));
[334]         if (ctx == NULL) {
[335]             return NULL;
[336]         }
[337] 
[338]         ngx_http_set_ctx(r, ctx, ngx_http_userid_filter_module);
[339]     }
[340] 
[341]     cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
[342]                                                &conf->name, &ctx->cookie);
[343]     if (cookie == NULL) {
[344]         return ctx;
[345]     }
[346] 
[347]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[348]                    "uid cookie: \"%V\"", &ctx->cookie);
[349] 
[350]     if (ctx->cookie.len < 22) {
[351]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[352]                       "client sent too short userid cookie \"%V\"",
[353]                       &cookie->value);
[354]         return ctx;
[355]     }
[356] 
[357]     src = ctx->cookie;
[358] 
[359]     /*
[360]      * we have to limit the encoded string to 22 characters because
[361]      *  1) cookie may be marked by "userid_mark",
[362]      *  2) and there are already the millions cookies with a garbage
[363]      *     instead of the correct base64 trail "=="
[364]      */
[365] 
[366]     src.len = 22;
[367] 
[368]     dst.data = (u_char *) ctx->uid_got;
[369] 
[370]     if (ngx_decode_base64(&dst, &src) == NGX_ERROR) {
[371]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[372]                       "client sent invalid userid cookie \"%V\"",
[373]                       &cookie->value);
[374]         return ctx;
[375]     }
[376] 
[377]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[378]                    "uid: %08XD%08XD%08XD%08XD",
[379]                    ctx->uid_got[0], ctx->uid_got[1],
[380]                    ctx->uid_got[2], ctx->uid_got[3]);
[381] 
[382]     return ctx;
[383] }
[384] 
[385] 
[386] static ngx_int_t
[387] ngx_http_userid_set_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,
[388]     ngx_http_userid_conf_t *conf)
[389] {
[390]     u_char           *cookie, *p;
[391]     size_t            len;
[392]     ngx_str_t         src, dst;
[393]     ngx_table_elt_t  *set_cookie, *p3p;
[394] 
[395]     if (ngx_http_userid_create_uid(r, ctx, conf) != NGX_OK) {
[396]         return NGX_ERROR;
[397]     }
[398] 
[399]     if (ctx->uid_set[3] == 0) {
[400]         return NGX_OK;
[401]     }
[402] 
[403]     len = conf->name.len + 1 + ngx_base64_encoded_length(16) + conf->path.len;
[404] 
[405]     if (conf->expires) {
[406]         len += sizeof(expires) - 1 + 2;
[407]     }
[408] 
[409]     if (conf->domain.len) {
[410]         len += conf->domain.len;
[411]     }
[412] 
[413]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SECURE) {
[414]         len += sizeof("; secure") - 1;
[415]     }
[416] 
[417]     if (conf->flags & NGX_HTTP_USERID_COOKIE_HTTPONLY) {
[418]         len += sizeof("; httponly") - 1;
[419]     }
[420] 
[421]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT) {
[422]         len += sizeof("; samesite=strict") - 1;
[423]     }
[424] 
[425]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_LAX) {
[426]         len += sizeof("; samesite=lax") - 1;
[427]     }
[428] 
[429]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_NONE) {
[430]         len += sizeof("; samesite=none") - 1;
[431]     }
[432] 
[433]     cookie = ngx_pnalloc(r->pool, len);
[434]     if (cookie == NULL) {
[435]         return NGX_ERROR;
[436]     }
[437] 
[438]     p = ngx_copy(cookie, conf->name.data, conf->name.len);
[439]     *p++ = '=';
[440] 
[441]     if (ctx->uid_got[3] == 0 || ctx->reset) {
[442]         src.len = 16;
[443]         src.data = (u_char *) ctx->uid_set;
[444]         dst.data = p;
[445] 
[446]         ngx_encode_base64(&dst, &src);
[447] 
[448]         p += dst.len;
[449] 
[450]         if (conf->mark) {
[451]             *(p - 2) = conf->mark;
[452]         }
[453] 
[454]     } else {
[455]         p = ngx_cpymem(p, ctx->cookie.data, 22);
[456]         *p++ = conf->mark;
[457]         *p++ = '=';
[458]     }
[459] 
[460]     if (conf->expires == NGX_HTTP_USERID_MAX_EXPIRES) {
[461]         p = ngx_cpymem(p, expires, sizeof(expires) - 1);
[462] 
[463]     } else if (conf->expires) {
[464]         p = ngx_cpymem(p, expires, sizeof("; expires=") - 1);
[465]         p = ngx_http_cookie_time(p, ngx_time() + conf->expires);
[466]     }
[467] 
[468]     p = ngx_copy(p, conf->domain.data, conf->domain.len);
[469] 
[470]     p = ngx_copy(p, conf->path.data, conf->path.len);
[471] 
[472]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SECURE) {
[473]         p = ngx_cpymem(p, "; secure", sizeof("; secure") - 1);
[474]     }
[475] 
[476]     if (conf->flags & NGX_HTTP_USERID_COOKIE_HTTPONLY) {
[477]         p = ngx_cpymem(p, "; httponly", sizeof("; httponly") - 1);
[478]     }
[479] 
[480]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT) {
[481]         p = ngx_cpymem(p, "; samesite=strict", sizeof("; samesite=strict") - 1);
[482]     }
[483] 
[484]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_LAX) {
[485]         p = ngx_cpymem(p, "; samesite=lax", sizeof("; samesite=lax") - 1);
[486]     }
[487] 
[488]     if (conf->flags & NGX_HTTP_USERID_COOKIE_SAMESITE_NONE) {
[489]         p = ngx_cpymem(p, "; samesite=none", sizeof("; samesite=none") - 1);
[490]     }
[491] 
[492]     set_cookie = ngx_list_push(&r->headers_out.headers);
[493]     if (set_cookie == NULL) {
[494]         return NGX_ERROR;
[495]     }
[496] 
[497]     set_cookie->hash = 1;
[498]     ngx_str_set(&set_cookie->key, "Set-Cookie");
[499]     set_cookie->value.len = p - cookie;
[500]     set_cookie->value.data = cookie;
[501] 
[502]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[503]                    "uid cookie: \"%V\"", &set_cookie->value);
[504] 
[505]     if (conf->p3p.len == 0) {
[506]         return NGX_OK;
[507]     }
[508] 
[509]     p3p = ngx_list_push(&r->headers_out.headers);
[510]     if (p3p == NULL) {
[511]         return NGX_ERROR;
[512]     }
[513] 
[514]     p3p->hash = 1;
[515]     ngx_str_set(&p3p->key, "P3P");
[516]     p3p->value = conf->p3p;
[517] 
[518]     return NGX_OK;
[519] }
[520] 
[521] 
[522] static ngx_int_t
[523] ngx_http_userid_create_uid(ngx_http_request_t *r, ngx_http_userid_ctx_t *ctx,
[524]     ngx_http_userid_conf_t *conf)
[525] {
[526]     ngx_connection_t           *c;
[527]     struct sockaddr_in         *sin;
[528]     ngx_http_variable_value_t  *vv;
[529] #if (NGX_HAVE_INET6)
[530]     u_char                     *p;
[531]     struct sockaddr_in6        *sin6;
[532] #endif
[533] 
[534]     if (ctx->uid_set[3] != 0) {
[535]         return NGX_OK;
[536]     }
[537] 
[538]     if (ctx->uid_got[3] != 0) {
[539] 
[540]         vv = ngx_http_get_indexed_variable(r, ngx_http_userid_reset_index);
[541] 
[542]         if (vv == NULL || vv->not_found) {
[543]             return NGX_ERROR;
[544]         }
[545] 
[546]         if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {
[547] 
[548]             if (conf->mark == '\0'
[549]                 || (ctx->cookie.len > 23
[550]                     && ctx->cookie.data[22] == conf->mark
[551]                     && ctx->cookie.data[23] == '='))
[552]             {
[553]                 return NGX_OK;
[554]             }
[555] 
[556]             ctx->uid_set[0] = ctx->uid_got[0];
[557]             ctx->uid_set[1] = ctx->uid_got[1];
[558]             ctx->uid_set[2] = ctx->uid_got[2];
[559]             ctx->uid_set[3] = ctx->uid_got[3];
[560] 
[561]             return NGX_OK;
[562] 
[563]         } else {
[564]             ctx->reset = 1;
[565] 
[566]             if (vv->len == 3 && ngx_strncmp(vv->data, "log", 3) == 0) {
[567]                 ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
[568]                         "userid cookie \"%V=%08XD%08XD%08XD%08XD\" was reset",
[569]                         &conf->name, ctx->uid_got[0], ctx->uid_got[1],
[570]                         ctx->uid_got[2], ctx->uid_got[3]);
[571]             }
[572]         }
[573]     }
[574] 
[575]     /*
[576]      * TODO: in the threaded mode the sequencers should be in TLS and their
[577]      * ranges should be divided between threads
[578]      */
[579] 
[580]     if (conf->enable == NGX_HTTP_USERID_V1) {
[581]         if (conf->service == NGX_CONF_UNSET) {
[582]             ctx->uid_set[0] = 0;
[583]         } else {
[584]             ctx->uid_set[0] = conf->service;
[585]         }
[586]         ctx->uid_set[1] = (uint32_t) ngx_time();
[587]         ctx->uid_set[2] = start_value;
[588]         ctx->uid_set[3] = sequencer_v1;
[589]         sequencer_v1 += 0x100;
[590] 
[591]     } else {
[592]         if (conf->service == NGX_CONF_UNSET) {
[593] 
[594]             c = r->connection;
[595] 
[596]             if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
[597]                 return NGX_ERROR;
[598]             }
[599] 
[600]             switch (c->local_sockaddr->sa_family) {
[601] 
[602] #if (NGX_HAVE_INET6)
[603]             case AF_INET6:
[604]                 sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
[605] 
[606]                 p = (u_char *) &ctx->uid_set[0];
[607] 
[608]                 *p++ = sin6->sin6_addr.s6_addr[12];
[609]                 *p++ = sin6->sin6_addr.s6_addr[13];
[610]                 *p++ = sin6->sin6_addr.s6_addr[14];
[611]                 *p = sin6->sin6_addr.s6_addr[15];
[612] 
[613]                 break;
[614] #endif
[615] 
[616] #if (NGX_HAVE_UNIX_DOMAIN)
[617]             case AF_UNIX:
[618]                 ctx->uid_set[0] = 0;
[619]                 break;
[620] #endif
[621] 
[622]             default: /* AF_INET */
[623]                 sin = (struct sockaddr_in *) c->local_sockaddr;
[624]                 ctx->uid_set[0] = sin->sin_addr.s_addr;
[625]                 break;
[626]             }
[627] 
[628]         } else {
[629]             ctx->uid_set[0] = htonl(conf->service);
[630]         }
[631] 
[632]         ctx->uid_set[1] = htonl((uint32_t) ngx_time());
[633]         ctx->uid_set[2] = htonl(start_value);
[634]         ctx->uid_set[3] = htonl(sequencer_v2);
[635]         sequencer_v2 += 0x100;
[636]         if (sequencer_v2 < 0x03030302) {
[637]             sequencer_v2 = 0x03030302;
[638]         }
[639]     }
[640] 
[641]     return NGX_OK;
[642] }
[643] 
[644] 
[645] static ngx_int_t
[646] ngx_http_userid_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[647]     ngx_str_t *name, uint32_t *uid)
[648] {
[649]     v->len = name->len + sizeof("=00001111222233334444555566667777") - 1;
[650]     v->data = ngx_pnalloc(r->pool, v->len);
[651]     if (v->data == NULL) {
[652]         return NGX_ERROR;
[653]     }
[654] 
[655]     v->valid = 1;
[656]     v->no_cacheable = 0;
[657]     v->not_found = 0;
[658] 
[659]     ngx_sprintf(v->data, "%V=%08XD%08XD%08XD%08XD",
[660]                 name, uid[0], uid[1], uid[2], uid[3]);
[661] 
[662]     return NGX_OK;
[663] }
[664] 
[665] 
[666] static ngx_int_t
[667] ngx_http_userid_reset_variable(ngx_http_request_t *r,
[668]     ngx_http_variable_value_t *v, uintptr_t data)
[669] {
[670]     *v = ngx_http_variable_null_value;
[671] 
[672]     return NGX_OK;
[673] }
[674] 
[675] 
[676] static ngx_int_t
[677] ngx_http_userid_add_variables(ngx_conf_t *cf)
[678] {
[679]     ngx_int_t             n;
[680]     ngx_http_variable_t  *var;
[681] 
[682]     var = ngx_http_add_variable(cf, &ngx_http_userid_got, 0);
[683]     if (var == NULL) {
[684]         return NGX_ERROR;
[685]     }
[686] 
[687]     var->get_handler = ngx_http_userid_got_variable;
[688] 
[689]     var = ngx_http_add_variable(cf, &ngx_http_userid_set, 0);
[690]     if (var == NULL) {
[691]         return NGX_ERROR;
[692]     }
[693] 
[694]     var->get_handler = ngx_http_userid_set_variable;
[695] 
[696]     var = ngx_http_add_variable(cf, &ngx_http_userid_reset,
[697]                                 NGX_HTTP_VAR_CHANGEABLE);
[698]     if (var == NULL) {
[699]         return NGX_ERROR;
[700]     }
[701] 
[702]     var->get_handler = ngx_http_userid_reset_variable;
[703] 
[704]     n = ngx_http_get_variable_index(cf, &ngx_http_userid_reset);
[705]     if (n == NGX_ERROR) {
[706]         return NGX_ERROR;
[707]     }
[708] 
[709]     ngx_http_userid_reset_index = n;
[710] 
[711]     return NGX_OK;
[712] }
[713] 
[714] 
[715] static void *
[716] ngx_http_userid_create_conf(ngx_conf_t *cf)
[717] {
[718]     ngx_http_userid_conf_t  *conf;
[719] 
[720]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_userid_conf_t));
[721]     if (conf == NULL) {
[722]         return NULL;
[723]     }
[724] 
[725]     /*
[726]      * set by ngx_pcalloc():
[727]      *
[728]      *     conf->flags = 0;
[729]      *     conf->name = { 0, NULL };
[730]      *     conf->domain = { 0, NULL };
[731]      *     conf->path = { 0, NULL };
[732]      *     conf->p3p = { 0, NULL };
[733]      */
[734] 
[735]     conf->enable = NGX_CONF_UNSET_UINT;
[736]     conf->service = NGX_CONF_UNSET;
[737]     conf->expires = NGX_CONF_UNSET;
[738]     conf->mark = (u_char) '\xFF';
[739] 
[740]     return conf;
[741] }
[742] 
[743] 
[744] static char *
[745] ngx_http_userid_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[746] {
[747]     ngx_http_userid_conf_t *prev = parent;
[748]     ngx_http_userid_conf_t *conf = child;
[749] 
[750]     ngx_conf_merge_uint_value(conf->enable, prev->enable,
[751]                               NGX_HTTP_USERID_OFF);
[752] 
[753]     ngx_conf_merge_bitmask_value(conf->flags, prev->flags,
[754]                             (NGX_CONF_BITMASK_SET|NGX_HTTP_USERID_COOKIE_OFF));
[755] 
[756]     ngx_conf_merge_str_value(conf->name, prev->name, "uid");
[757]     ngx_conf_merge_str_value(conf->domain, prev->domain, "");
[758]     ngx_conf_merge_str_value(conf->path, prev->path, "; path=/");
[759]     ngx_conf_merge_str_value(conf->p3p, prev->p3p, "");
[760] 
[761]     ngx_conf_merge_value(conf->service, prev->service, NGX_CONF_UNSET);
[762]     ngx_conf_merge_sec_value(conf->expires, prev->expires, 0);
[763] 
[764]     if (conf->mark == (u_char) '\xFF') {
[765]         if (prev->mark == (u_char) '\xFF') {
[766]             conf->mark = '\0';
[767]         } else {
[768]             conf->mark = prev->mark;
[769]         }
[770]     }
[771] 
[772]     return NGX_CONF_OK;
[773] }
[774] 
[775] 
[776] static ngx_int_t
[777] ngx_http_userid_init(ngx_conf_t *cf)
[778] {
[779]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[780]     ngx_http_top_header_filter = ngx_http_userid_filter;
[781] 
[782]     return NGX_OK;
[783] }
[784] 
[785] 
[786] static char *
[787] ngx_http_userid_domain(ngx_conf_t *cf, void *post, void *data)
[788] {
[789]     ngx_str_t  *domain = data;
[790] 
[791]     u_char  *p, *new;
[792] 
[793]     if (ngx_strcmp(domain->data, "none") == 0) {
[794]         ngx_str_set(domain, "");
[795]         return NGX_CONF_OK;
[796]     }
[797] 
[798]     new = ngx_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
[799]     if (new == NULL) {
[800]         return NGX_CONF_ERROR;
[801]     }
[802] 
[803]     p = ngx_cpymem(new, "; domain=", sizeof("; domain=") - 1);
[804]     ngx_memcpy(p, domain->data, domain->len);
[805] 
[806]     domain->len += sizeof("; domain=") - 1;
[807]     domain->data = new;
[808] 
[809]     return NGX_CONF_OK;
[810] }
[811] 
[812] 
[813] static char *
[814] ngx_http_userid_path(ngx_conf_t *cf, void *post, void *data)
[815] {
[816]     ngx_str_t  *path = data;
[817] 
[818]     u_char  *p, *new;
[819] 
[820]     new = ngx_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
[821]     if (new == NULL) {
[822]         return NGX_CONF_ERROR;
[823]     }
[824] 
[825]     p = ngx_cpymem(new, "; path=", sizeof("; path=") - 1);
[826]     ngx_memcpy(p, path->data, path->len);
[827] 
[828]     path->len += sizeof("; path=") - 1;
[829]     path->data = new;
[830] 
[831]     return NGX_CONF_OK;
[832] }
[833] 
[834] 
[835] static char *
[836] ngx_http_userid_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[837] {
[838]     ngx_http_userid_conf_t *ucf = conf;
[839] 
[840]     ngx_str_t  *value;
[841] 
[842]     if (ucf->expires != NGX_CONF_UNSET) {
[843]         return "is duplicate";
[844]     }
[845] 
[846]     value = cf->args->elts;
[847] 
[848]     if (ngx_strcmp(value[1].data, "max") == 0) {
[849]         ucf->expires = NGX_HTTP_USERID_MAX_EXPIRES;
[850]         return NGX_CONF_OK;
[851]     }
[852] 
[853]     if (ngx_strcmp(value[1].data, "off") == 0) {
[854]         ucf->expires = 0;
[855]         return NGX_CONF_OK;
[856]     }
[857] 
[858]     ucf->expires = ngx_parse_time(&value[1], 1);
[859]     if (ucf->expires == (time_t) NGX_ERROR) {
[860]         return "invalid value";
[861]     }
[862] 
[863]     return NGX_CONF_OK;
[864] }
[865] 
[866] 
[867] static char *
[868] ngx_http_userid_p3p(ngx_conf_t *cf, void *post, void *data)
[869] {
[870]     ngx_str_t  *p3p = data;
[871] 
[872]     if (ngx_strcmp(p3p->data, "none") == 0) {
[873]         ngx_str_set(p3p, "");
[874]     }
[875] 
[876]     return NGX_CONF_OK;
[877] }
[878] 
[879] 
[880] static char *
[881] ngx_http_userid_mark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[882] {
[883]     ngx_http_userid_conf_t *ucf = conf;
[884] 
[885]     ngx_str_t  *value;
[886] 
[887]     if (ucf->mark != (u_char) '\xFF') {
[888]         return "is duplicate";
[889]     }
[890] 
[891]     value = cf->args->elts;
[892] 
[893]     if (ngx_strcmp(value[1].data, "off") == 0) {
[894]         ucf->mark = '\0';
[895]         return NGX_CONF_OK;
[896]     }
[897] 
[898]     if (value[1].len != 1
[899]         || !((value[1].data[0] >= '0' && value[1].data[0] <= '9')
[900]               || (value[1].data[0] >= 'A' && value[1].data[0] <= 'Z')
[901]               || (value[1].data[0] >= 'a' && value[1].data[0] <= 'z')
[902]               || value[1].data[0] == '='))
[903]     {
[904]         return "value must be \"off\" or a single letter, digit or \"=\"";
[905]     }
[906] 
[907]     ucf->mark = value[1].data[0];
[908] 
[909]     return NGX_CONF_OK;
[910] }
[911] 
[912] 
[913] static ngx_int_t
[914] ngx_http_userid_init_worker(ngx_cycle_t *cycle)
[915] {
[916]     struct timeval  tp;
[917] 
[918]     ngx_gettimeofday(&tp);
[919] 
[920]     /* use the most significant usec part that fits to 16 bits */
[921]     start_value = (((uint32_t) tp.tv_usec / 20) << 16) | ngx_pid;
[922] 
[923]     return NGX_OK;
[924] }
