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
[14]     ngx_http_complex_value_t   match;
[15]     ngx_http_complex_value_t   value;
[16] } ngx_http_sub_pair_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_str_t                  match;
[21]     ngx_http_complex_value_t  *value;
[22] } ngx_http_sub_match_t;
[23] 
[24] 
[25] typedef struct {
[26]     ngx_uint_t                 min_match_len;
[27]     ngx_uint_t                 max_match_len;
[28] 
[29]     u_char                     index[257];
[30]     u_char                     shift[256];
[31] } ngx_http_sub_tables_t;
[32] 
[33] 
[34] typedef struct {
[35]     ngx_uint_t                 dynamic; /* unsigned dynamic:1; */
[36] 
[37]     ngx_array_t               *pairs;
[38] 
[39]     ngx_http_sub_tables_t     *tables;
[40] 
[41]     ngx_hash_t                 types;
[42] 
[43]     ngx_flag_t                 once;
[44]     ngx_flag_t                 last_modified;
[45] 
[46]     ngx_array_t               *types_keys;
[47]     ngx_array_t               *matches;
[48] } ngx_http_sub_loc_conf_t;
[49] 
[50] 
[51] typedef struct {
[52]     ngx_str_t                  saved;
[53]     ngx_str_t                  looked;
[54] 
[55]     ngx_uint_t                 once;   /* unsigned  once:1 */
[56] 
[57]     ngx_buf_t                 *buf;
[58] 
[59]     u_char                    *pos;
[60]     u_char                    *copy_start;
[61]     u_char                    *copy_end;
[62] 
[63]     ngx_chain_t               *in;
[64]     ngx_chain_t               *out;
[65]     ngx_chain_t              **last_out;
[66]     ngx_chain_t               *busy;
[67]     ngx_chain_t               *free;
[68] 
[69]     ngx_str_t                 *sub;
[70]     ngx_uint_t                 applied;
[71] 
[72]     ngx_int_t                  offset;
[73]     ngx_uint_t                 index;
[74] 
[75]     ngx_http_sub_tables_t     *tables;
[76]     ngx_array_t               *matches;
[77] } ngx_http_sub_ctx_t;
[78] 
[79] 
[80] static ngx_uint_t ngx_http_sub_cmp_index;
[81] 
[82] 
[83] static ngx_int_t ngx_http_sub_output(ngx_http_request_t *r,
[84]     ngx_http_sub_ctx_t *ctx);
[85] static ngx_int_t ngx_http_sub_parse(ngx_http_request_t *r,
[86]     ngx_http_sub_ctx_t *ctx, ngx_uint_t flush);
[87] static ngx_int_t ngx_http_sub_match(ngx_http_sub_ctx_t *ctx, ngx_int_t start,
[88]     ngx_str_t *m);
[89] 
[90] static char * ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd,
[91]     void *conf);
[92] static void *ngx_http_sub_create_conf(ngx_conf_t *cf);
[93] static char *ngx_http_sub_merge_conf(ngx_conf_t *cf,
[94]     void *parent, void *child);
[95] static void ngx_http_sub_init_tables(ngx_http_sub_tables_t *tables,
[96]     ngx_http_sub_match_t *match, ngx_uint_t n);
[97] static ngx_int_t ngx_http_sub_cmp_matches(const void *one, const void *two);
[98] static ngx_int_t ngx_http_sub_filter_init(ngx_conf_t *cf);
[99] 
[100] 
[101] static ngx_command_t  ngx_http_sub_filter_commands[] = {
[102] 
[103]     { ngx_string("sub_filter"),
[104]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[105]       ngx_http_sub_filter,
[106]       NGX_HTTP_LOC_CONF_OFFSET,
[107]       0,
[108]       NULL },
[109] 
[110]     { ngx_string("sub_filter_types"),
[111]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[112]       ngx_http_types_slot,
[113]       NGX_HTTP_LOC_CONF_OFFSET,
[114]       offsetof(ngx_http_sub_loc_conf_t, types_keys),
[115]       &ngx_http_html_default_types[0] },
[116] 
[117]     { ngx_string("sub_filter_once"),
[118]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[119]       ngx_conf_set_flag_slot,
[120]       NGX_HTTP_LOC_CONF_OFFSET,
[121]       offsetof(ngx_http_sub_loc_conf_t, once),
[122]       NULL },
[123] 
[124]     { ngx_string("sub_filter_last_modified"),
[125]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[126]       ngx_conf_set_flag_slot,
[127]       NGX_HTTP_LOC_CONF_OFFSET,
[128]       offsetof(ngx_http_sub_loc_conf_t, last_modified),
[129]       NULL },
[130] 
[131]       ngx_null_command
[132] };
[133] 
[134] 
[135] static ngx_http_module_t  ngx_http_sub_filter_module_ctx = {
[136]     NULL,                                  /* preconfiguration */
[137]     ngx_http_sub_filter_init,              /* postconfiguration */
[138] 
[139]     NULL,                                  /* create main configuration */
[140]     NULL,                                  /* init main configuration */
[141] 
[142]     NULL,                                  /* create server configuration */
[143]     NULL,                                  /* merge server configuration */
[144] 
[145]     ngx_http_sub_create_conf,              /* create location configuration */
[146]     ngx_http_sub_merge_conf                /* merge location configuration */
[147] };
[148] 
[149] 
[150] ngx_module_t  ngx_http_sub_filter_module = {
[151]     NGX_MODULE_V1,
[152]     &ngx_http_sub_filter_module_ctx,       /* module context */
[153]     ngx_http_sub_filter_commands,          /* module directives */
[154]     NGX_HTTP_MODULE,                       /* module type */
[155]     NULL,                                  /* init master */
[156]     NULL,                                  /* init module */
[157]     NULL,                                  /* init process */
[158]     NULL,                                  /* init thread */
[159]     NULL,                                  /* exit thread */
[160]     NULL,                                  /* exit process */
[161]     NULL,                                  /* exit master */
[162]     NGX_MODULE_V1_PADDING
[163] };
[164] 
[165] 
[166] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[167] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[168] 
[169] 
[170] static ngx_int_t
[171] ngx_http_sub_header_filter(ngx_http_request_t *r)
[172] {
[173]     ngx_str_t                *m;
[174]     ngx_uint_t                i, j, n;
[175]     ngx_http_sub_ctx_t       *ctx;
[176]     ngx_http_sub_pair_t      *pairs;
[177]     ngx_http_sub_match_t     *matches;
[178]     ngx_http_sub_loc_conf_t  *slcf;
[179] 
[180]     slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);
[181] 
[182]     if (slcf->pairs == NULL
[183]         || r->headers_out.content_length_n == 0
[184]         || ngx_http_test_content_type(r, &slcf->types) == NULL)
[185]     {
[186]         return ngx_http_next_header_filter(r);
[187]     }
[188] 
[189]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
[190]     if (ctx == NULL) {
[191]         return NGX_ERROR;
[192]     }
[193] 
[194]     if (slcf->dynamic == 0) {
[195]         ctx->tables = slcf->tables;
[196]         ctx->matches = slcf->matches;
[197] 
[198]     } else {
[199]         pairs = slcf->pairs->elts;
[200]         n = slcf->pairs->nelts;
[201] 
[202]         matches = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_match_t) * n);
[203]         if (matches == NULL) {
[204]             return NGX_ERROR;
[205]         }
[206] 
[207]         j = 0;
[208]         for (i = 0; i < n; i++) {
[209]             matches[j].value = &pairs[i].value;
[210] 
[211]             if (pairs[i].match.lengths == NULL) {
[212]                 matches[j].match = pairs[i].match.value;
[213]                 j++;
[214]                 continue;
[215]             }
[216] 
[217]             m = &matches[j].match;
[218]             if (ngx_http_complex_value(r, &pairs[i].match, m) != NGX_OK) {
[219]                 return NGX_ERROR;
[220]             }
[221] 
[222]             if (m->len == 0) {
[223]                 continue;
[224]             }
[225] 
[226]             ngx_strlow(m->data, m->data, m->len);
[227]             j++;
[228]         }
[229] 
[230]         if (j == 0) {
[231]             return ngx_http_next_header_filter(r);
[232]         }
[233] 
[234]         ctx->matches = ngx_palloc(r->pool, sizeof(ngx_array_t));
[235]         if (ctx->matches == NULL) {
[236]             return NGX_ERROR;
[237]         }
[238] 
[239]         ctx->matches->elts = matches;
[240]         ctx->matches->nelts = j;
[241] 
[242]         ctx->tables = ngx_palloc(r->pool, sizeof(ngx_http_sub_tables_t));
[243]         if (ctx->tables == NULL) {
[244]             return NGX_ERROR;
[245]         }
[246] 
[247]         ngx_http_sub_init_tables(ctx->tables, ctx->matches->elts,
[248]                                  ctx->matches->nelts);
[249]     }
[250] 
[251]     ctx->saved.data = ngx_pnalloc(r->pool, ctx->tables->max_match_len - 1);
[252]     if (ctx->saved.data == NULL) {
[253]         return NGX_ERROR;
[254]     }
[255] 
[256]     ctx->looked.data = ngx_pnalloc(r->pool, ctx->tables->max_match_len - 1);
[257]     if (ctx->looked.data == NULL) {
[258]         return NGX_ERROR;
[259]     }
[260] 
[261]     ngx_http_set_ctx(r, ctx, ngx_http_sub_filter_module);
[262] 
[263]     ctx->offset = ctx->tables->min_match_len - 1;
[264]     ctx->last_out = &ctx->out;
[265] 
[266]     r->filter_need_in_memory = 1;
[267] 
[268]     if (r == r->main) {
[269]         ngx_http_clear_content_length(r);
[270] 
[271]         if (!slcf->last_modified) {
[272]             ngx_http_clear_last_modified(r);
[273]             ngx_http_clear_etag(r);
[274] 
[275]         } else {
[276]             ngx_http_weak_etag(r);
[277]         }
[278]     }
[279] 
[280]     return ngx_http_next_header_filter(r);
[281] }
[282] 
[283] 
[284] static ngx_int_t
[285] ngx_http_sub_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[286] {
[287]     ngx_int_t                  rc;
[288]     ngx_buf_t                 *b;
[289]     ngx_str_t                 *sub;
[290]     ngx_uint_t                 flush, last;
[291]     ngx_chain_t               *cl;
[292]     ngx_http_sub_ctx_t        *ctx;
[293]     ngx_http_sub_match_t      *match;
[294]     ngx_http_sub_loc_conf_t   *slcf;
[295] 
[296]     ctx = ngx_http_get_module_ctx(r, ngx_http_sub_filter_module);
[297] 
[298]     if (ctx == NULL) {
[299]         return ngx_http_next_body_filter(r, in);
[300]     }
[301] 
[302]     if ((in == NULL
[303]          && ctx->buf == NULL
[304]          && ctx->in == NULL
[305]          && ctx->busy == NULL))
[306]     {
[307]         return ngx_http_next_body_filter(r, in);
[308]     }
[309] 
[310]     if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {
[311] 
[312]         if (ctx->busy) {
[313]             if (ngx_http_sub_output(r, ctx) == NGX_ERROR) {
[314]                 return NGX_ERROR;
[315]             }
[316]         }
[317] 
[318]         return ngx_http_next_body_filter(r, in);
[319]     }
[320] 
[321]     /* add the incoming chain to the chain ctx->in */
[322] 
[323]     if (in) {
[324]         if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
[325]             return NGX_ERROR;
[326]         }
[327]     }
[328] 
[329]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[330]                    "http sub filter \"%V\"", &r->uri);
[331] 
[332]     flush = 0;
[333]     last = 0;
[334] 
[335]     while (ctx->in || ctx->buf) {
[336] 
[337]         if (ctx->buf == NULL) {
[338]             ctx->buf = ctx->in->buf;
[339]             ctx->in = ctx->in->next;
[340]             ctx->pos = ctx->buf->pos;
[341]         }
[342] 
[343]         if (ctx->buf->flush || ctx->buf->recycled) {
[344]             flush = 1;
[345]         }
[346] 
[347]         if (ctx->in == NULL) {
[348]             last = flush;
[349]         }
[350] 
[351]         b = NULL;
[352] 
[353]         while (ctx->pos < ctx->buf->last) {
[354] 
[355]             rc = ngx_http_sub_parse(r, ctx, last);
[356] 
[357]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[358]                            "parse: %i, looked: \"%V\" %p-%p",
[359]                            rc, &ctx->looked, ctx->copy_start, ctx->copy_end);
[360] 
[361]             if (rc == NGX_ERROR) {
[362]                 return rc;
[363]             }
[364] 
[365]             if (ctx->saved.len) {
[366] 
[367]                 ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[368]                                "saved: \"%V\"", &ctx->saved);
[369] 
[370]                 cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[371]                 if (cl == NULL) {
[372]                     return NGX_ERROR;
[373]                 }
[374] 
[375]                 b = cl->buf;
[376] 
[377]                 ngx_memzero(b, sizeof(ngx_buf_t));
[378] 
[379]                 b->pos = ngx_pnalloc(r->pool, ctx->saved.len);
[380]                 if (b->pos == NULL) {
[381]                     return NGX_ERROR;
[382]                 }
[383] 
[384]                 ngx_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
[385]                 b->last = b->pos + ctx->saved.len;
[386]                 b->memory = 1;
[387] 
[388]                 *ctx->last_out = cl;
[389]                 ctx->last_out = &cl->next;
[390] 
[391]                 ctx->saved.len = 0;
[392]             }
[393] 
[394]             if (ctx->copy_start != ctx->copy_end) {
[395] 
[396]                 cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[397]                 if (cl == NULL) {
[398]                     return NGX_ERROR;
[399]                 }
[400] 
[401]                 b = cl->buf;
[402] 
[403]                 ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));
[404] 
[405]                 b->pos = ctx->copy_start;
[406]                 b->last = ctx->copy_end;
[407]                 b->shadow = NULL;
[408]                 b->last_buf = 0;
[409]                 b->last_in_chain = 0;
[410]                 b->recycled = 0;
[411] 
[412]                 if (b->in_file) {
[413]                     b->file_last = b->file_pos + (b->last - ctx->buf->pos);
[414]                     b->file_pos += b->pos - ctx->buf->pos;
[415]                 }
[416] 
[417]                 *ctx->last_out = cl;
[418]                 ctx->last_out = &cl->next;
[419]             }
[420] 
[421]             if (rc == NGX_AGAIN) {
[422]                 continue;
[423]             }
[424] 
[425] 
[426]             /* rc == NGX_OK */
[427] 
[428]             cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[429]             if (cl == NULL) {
[430]                 return NGX_ERROR;
[431]             }
[432] 
[433]             b = cl->buf;
[434] 
[435]             ngx_memzero(b, sizeof(ngx_buf_t));
[436] 
[437]             slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);
[438] 
[439]             if (ctx->sub == NULL) {
[440]                 ctx->sub = ngx_pcalloc(r->pool, sizeof(ngx_str_t)
[441]                                                 * ctx->matches->nelts);
[442]                 if (ctx->sub == NULL) {
[443]                     return NGX_ERROR;
[444]                 }
[445]             }
[446] 
[447]             sub = &ctx->sub[ctx->index];
[448] 
[449]             if (sub->data == NULL) {
[450]                 match = ctx->matches->elts;
[451] 
[452]                 if (ngx_http_complex_value(r, match[ctx->index].value, sub)
[453]                     != NGX_OK)
[454]                 {
[455]                     return NGX_ERROR;
[456]                 }
[457]             }
[458] 
[459]             if (sub->len) {
[460]                 b->memory = 1;
[461]                 b->pos = sub->data;
[462]                 b->last = sub->data + sub->len;
[463] 
[464]             } else {
[465]                 b->sync = 1;
[466]             }
[467] 
[468]             *ctx->last_out = cl;
[469]             ctx->last_out = &cl->next;
[470] 
[471]             ctx->index = 0;
[472]             ctx->once = slcf->once && (++ctx->applied == ctx->matches->nelts);
[473] 
[474]             continue;
[475]         }
[476] 
[477]         if (ctx->looked.len
[478]             && (ctx->buf->last_buf || ctx->buf->last_in_chain))
[479]         {
[480]             cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[481]             if (cl == NULL) {
[482]                 return NGX_ERROR;
[483]             }
[484] 
[485]             b = cl->buf;
[486] 
[487]             ngx_memzero(b, sizeof(ngx_buf_t));
[488] 
[489]             b->pos = ctx->looked.data;
[490]             b->last = b->pos + ctx->looked.len;
[491]             b->memory = 1;
[492] 
[493]             *ctx->last_out = cl;
[494]             ctx->last_out = &cl->next;
[495] 
[496]             ctx->looked.len = 0;
[497]         }
[498] 
[499]         if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
[500]             || ngx_buf_in_memory(ctx->buf))
[501]         {
[502]             if (b == NULL) {
[503]                 cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[504]                 if (cl == NULL) {
[505]                     return NGX_ERROR;
[506]                 }
[507] 
[508]                 b = cl->buf;
[509] 
[510]                 ngx_memzero(b, sizeof(ngx_buf_t));
[511] 
[512]                 b->sync = 1;
[513] 
[514]                 *ctx->last_out = cl;
[515]                 ctx->last_out = &cl->next;
[516]             }
[517] 
[518]             b->last_buf = ctx->buf->last_buf;
[519]             b->last_in_chain = ctx->buf->last_in_chain;
[520]             b->flush = ctx->buf->flush;
[521]             b->shadow = ctx->buf;
[522] 
[523]             b->recycled = ctx->buf->recycled;
[524]         }
[525] 
[526]         ctx->buf = NULL;
[527]     }
[528] 
[529]     if (ctx->out == NULL && ctx->busy == NULL) {
[530]         return NGX_OK;
[531]     }
[532] 
[533]     return ngx_http_sub_output(r, ctx);
[534] }
[535] 
[536] 
[537] static ngx_int_t
[538] ngx_http_sub_output(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx)
[539] {
[540]     ngx_int_t     rc;
[541]     ngx_buf_t    *b;
[542]     ngx_chain_t  *cl;
[543] 
[544] #if 1
[545]     b = NULL;
[546]     for (cl = ctx->out; cl; cl = cl->next) {
[547]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[548]                        "sub out: %p %p", cl->buf, cl->buf->pos);
[549]         if (cl->buf == b) {
[550]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[551]                           "the same buf was used in sub");
[552]             ngx_debug_point();
[553]             return NGX_ERROR;
[554]         }
[555]         b = cl->buf;
[556]     }
[557] #endif
[558] 
[559]     rc = ngx_http_next_body_filter(r, ctx->out);
[560] 
[561]     if (ctx->busy == NULL) {
[562]         ctx->busy = ctx->out;
[563] 
[564]     } else {
[565]         for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
[566]         cl->next = ctx->out;
[567]     }
[568] 
[569]     ctx->out = NULL;
[570]     ctx->last_out = &ctx->out;
[571] 
[572]     while (ctx->busy) {
[573] 
[574]         cl = ctx->busy;
[575]         b = cl->buf;
[576] 
[577]         if (ngx_buf_size(b) != 0) {
[578]             break;
[579]         }
[580] 
[581]         if (b->shadow) {
[582]             b->shadow->pos = b->shadow->last;
[583]         }
[584] 
[585]         ctx->busy = cl->next;
[586] 
[587]         if (ngx_buf_in_memory(b) || b->in_file) {
[588]             /* add data bufs only to the free buf chain */
[589] 
[590]             cl->next = ctx->free;
[591]             ctx->free = cl;
[592]         }
[593]     }
[594] 
[595]     if (ctx->in || ctx->buf) {
[596]         r->buffered |= NGX_HTTP_SUB_BUFFERED;
[597] 
[598]     } else {
[599]         r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
[600]     }
[601] 
[602]     return rc;
[603] }
[604] 
[605] 
[606] static ngx_int_t
[607] ngx_http_sub_parse(ngx_http_request_t *r, ngx_http_sub_ctx_t *ctx,
[608]     ngx_uint_t flush)
[609] {
[610]     u_char                   *p, c;
[611]     ngx_str_t                *m;
[612]     ngx_int_t                 offset, start, next, end, len, rc;
[613]     ngx_uint_t                shift, i, j;
[614]     ngx_http_sub_match_t     *match;
[615]     ngx_http_sub_tables_t    *tables;
[616]     ngx_http_sub_loc_conf_t  *slcf;
[617] 
[618]     slcf = ngx_http_get_module_loc_conf(r, ngx_http_sub_filter_module);
[619]     tables = ctx->tables;
[620]     match = ctx->matches->elts;
[621] 
[622]     offset = ctx->offset;
[623]     end = ctx->buf->last - ctx->pos;
[624] 
[625]     if (ctx->once) {
[626]         /* sets start and next to end */
[627]         offset = end + (ngx_int_t) tables->min_match_len - 1;
[628]         goto again;
[629]     }
[630] 
[631]     while (offset < end) {
[632] 
[633]         c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
[634]                        : ctx->pos[offset];
[635] 
[636]         c = ngx_tolower(c);
[637] 
[638]         shift = tables->shift[c];
[639]         if (shift > 0) {
[640]             offset += shift;
[641]             continue;
[642]         }
[643] 
[644]         /* a potential match */
[645] 
[646]         start = offset - (ngx_int_t) tables->min_match_len + 1;
[647] 
[648]         i = ngx_max((ngx_uint_t) tables->index[c], ctx->index);
[649]         j = tables->index[c + 1];
[650] 
[651]         while (i != j) {
[652] 
[653]             if (slcf->once && ctx->sub && ctx->sub[i].data) {
[654]                 goto next;
[655]             }
[656] 
[657]             m = &match[i].match;
[658] 
[659]             rc = ngx_http_sub_match(ctx, start, m);
[660] 
[661]             if (rc == NGX_DECLINED) {
[662]                 goto next;
[663]             }
[664] 
[665]             ctx->index = i;
[666] 
[667]             if (rc == NGX_AGAIN) {
[668]                 goto again;
[669]             }
[670] 
[671]             ctx->offset = offset + (ngx_int_t) m->len;
[672]             next = start + (ngx_int_t) m->len;
[673]             end = ngx_max(next, 0);
[674]             rc = NGX_OK;
[675] 
[676]             goto done;
[677] 
[678]         next:
[679] 
[680]             i++;
[681]         }
[682] 
[683]         offset++;
[684]         ctx->index = 0;
[685]     }
[686] 
[687]     if (flush) {
[688]         for ( ;; ) {
[689]             start = offset - (ngx_int_t) tables->min_match_len + 1;
[690] 
[691]             if (start >= end) {
[692]                 break;
[693]             }
[694] 
[695]             for (i = 0; i < ctx->matches->nelts; i++) {
[696]                 m = &match[i].match;
[697] 
[698]                 if (ngx_http_sub_match(ctx, start, m) == NGX_AGAIN) {
[699]                     goto again;
[700]                 }
[701]             }
[702] 
[703]             offset++;
[704]         }
[705]     }
[706] 
[707] again:
[708] 
[709]     ctx->offset = offset;
[710]     start = offset - (ngx_int_t) tables->min_match_len + 1;
[711]     next = start;
[712]     rc = NGX_AGAIN;
[713] 
[714] done:
[715] 
[716]     /* send [ - looked.len, start ] to client */
[717] 
[718]     ctx->saved.len = ctx->looked.len + ngx_min(start, 0);
[719]     ngx_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);
[720] 
[721]     ctx->copy_start = ctx->pos;
[722]     ctx->copy_end = ctx->pos + ngx_max(start, 0);
[723] 
[724]     /* save [ next, end ] in looked */
[725] 
[726]     len = ngx_min(next, 0);
[727]     p = ctx->looked.data;
[728]     p = ngx_movemem(p, p + ctx->looked.len + len, - len);
[729] 
[730]     len = ngx_max(next, 0);
[731]     p = ngx_cpymem(p, ctx->pos + len, end - len);
[732]     ctx->looked.len = p - ctx->looked.data;
[733] 
[734]     /* update position */
[735] 
[736]     ctx->pos += end;
[737]     ctx->offset -= end;
[738] 
[739]     return rc;
[740] }
[741] 
[742] 
[743] static ngx_int_t
[744] ngx_http_sub_match(ngx_http_sub_ctx_t *ctx, ngx_int_t start, ngx_str_t *m)
[745] {
[746]     u_char  *p, *last, *pat, *pat_end;
[747] 
[748]     pat = m->data;
[749]     pat_end = m->data + m->len;
[750] 
[751]     if (start >= 0) {
[752]         p = ctx->pos + start;
[753] 
[754]     } else {
[755]         last = ctx->looked.data + ctx->looked.len;
[756]         p = last + start;
[757] 
[758]         while (p < last && pat < pat_end) {
[759]             if (ngx_tolower(*p) != *pat) {
[760]                 return NGX_DECLINED;
[761]             }
[762] 
[763]             p++;
[764]             pat++;
[765]         }
[766] 
[767]         p = ctx->pos;
[768]     }
[769] 
[770]     while (p < ctx->buf->last && pat < pat_end) {
[771]         if (ngx_tolower(*p) != *pat) {
[772]             return NGX_DECLINED;
[773]         }
[774] 
[775]         p++;
[776]         pat++;
[777]     }
[778] 
[779]     if (pat != pat_end) {
[780]         /* partial match */
[781]         return NGX_AGAIN;
[782]     }
[783] 
[784]     return NGX_OK;
[785] }
[786] 
[787] 
[788] static char *
[789] ngx_http_sub_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[790] {
[791]     ngx_http_sub_loc_conf_t *slcf = conf;
[792] 
[793]     ngx_str_t                         *value;
[794]     ngx_http_sub_pair_t               *pair;
[795]     ngx_http_compile_complex_value_t   ccv;
[796] 
[797]     value = cf->args->elts;
[798] 
[799]     if (value[1].len == 0) {
[800]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty search pattern");
[801]         return NGX_CONF_ERROR;
[802]     }
[803] 
[804]     if (slcf->pairs == NULL) {
[805]         slcf->pairs = ngx_array_create(cf->pool, 1,
[806]                                        sizeof(ngx_http_sub_pair_t));
[807]         if (slcf->pairs == NULL) {
[808]             return NGX_CONF_ERROR;
[809]         }
[810]     }
[811] 
[812]     if (slcf->pairs->nelts == 255) {
[813]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[814]                            "number of search patterns exceeds 255");
[815]         return NGX_CONF_ERROR;
[816]     }
[817] 
[818]     ngx_strlow(value[1].data, value[1].data, value[1].len);
[819] 
[820]     pair = ngx_array_push(slcf->pairs);
[821]     if (pair == NULL) {
[822]         return NGX_CONF_ERROR;
[823]     }
[824] 
[825]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[826] 
[827]     ccv.cf = cf;
[828]     ccv.value = &value[1];
[829]     ccv.complex_value = &pair->match;
[830] 
[831]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[832]         return NGX_CONF_ERROR;
[833]     }
[834] 
[835]     if (ccv.complex_value->lengths != NULL) {
[836]         slcf->dynamic = 1;
[837] 
[838]     } else {
[839]         ngx_strlow(pair->match.value.data, pair->match.value.data,
[840]                    pair->match.value.len);
[841]     }
[842] 
[843]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[844] 
[845]     ccv.cf = cf;
[846]     ccv.value = &value[2];
[847]     ccv.complex_value = &pair->value;
[848] 
[849]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[850]         return NGX_CONF_ERROR;
[851]     }
[852] 
[853]     return NGX_CONF_OK;
[854] }
[855] 
[856] 
[857] static void *
[858] ngx_http_sub_create_conf(ngx_conf_t *cf)
[859] {
[860]     ngx_http_sub_loc_conf_t  *slcf;
[861] 
[862]     slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sub_loc_conf_t));
[863]     if (slcf == NULL) {
[864]         return NULL;
[865]     }
[866] 
[867]     /*
[868]      * set by ngx_pcalloc():
[869]      *
[870]      *     conf->dynamic = 0;
[871]      *     conf->pairs = NULL;
[872]      *     conf->tables = NULL;
[873]      *     conf->types = { NULL };
[874]      *     conf->types_keys = NULL;
[875]      *     conf->matches = NULL;
[876]      */
[877] 
[878]     slcf->once = NGX_CONF_UNSET;
[879]     slcf->last_modified = NGX_CONF_UNSET;
[880] 
[881]     return slcf;
[882] }
[883] 
[884] 
[885] static char *
[886] ngx_http_sub_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[887] {
[888]     ngx_uint_t                i, n;
[889]     ngx_http_sub_pair_t      *pairs;
[890]     ngx_http_sub_match_t     *matches;
[891]     ngx_http_sub_loc_conf_t  *prev = parent;
[892]     ngx_http_sub_loc_conf_t  *conf = child;
[893] 
[894]     ngx_conf_merge_value(conf->once, prev->once, 1);
[895]     ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);
[896] 
[897]     if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
[898]                              &prev->types_keys, &prev->types,
[899]                              ngx_http_html_default_types)
[900]         != NGX_OK)
[901]     {
[902]         return NGX_CONF_ERROR;
[903]     }
[904] 
[905]     if (conf->pairs == NULL) {
[906]         conf->dynamic = prev->dynamic;
[907]         conf->pairs = prev->pairs;
[908]         conf->matches = prev->matches;
[909]         conf->tables = prev->tables;
[910]     }
[911] 
[912]     if (conf->pairs && conf->dynamic == 0 && conf->tables == NULL) {
[913]         pairs = conf->pairs->elts;
[914]         n = conf->pairs->nelts;
[915] 
[916]         matches = ngx_palloc(cf->pool, sizeof(ngx_http_sub_match_t) * n);
[917]         if (matches == NULL) {
[918]             return NGX_CONF_ERROR;
[919]         }
[920] 
[921]         for (i = 0; i < n; i++) {
[922]             matches[i].match = pairs[i].match.value;
[923]             matches[i].value = &pairs[i].value;
[924]         }
[925] 
[926]         conf->matches = ngx_palloc(cf->pool, sizeof(ngx_array_t));
[927]         if (conf->matches == NULL) {
[928]             return NGX_CONF_ERROR;
[929]         }
[930] 
[931]         conf->matches->elts = matches;
[932]         conf->matches->nelts = n;
[933] 
[934]         conf->tables = ngx_palloc(cf->pool, sizeof(ngx_http_sub_tables_t));
[935]         if (conf->tables == NULL) {
[936]             return NGX_CONF_ERROR;
[937]         }
[938] 
[939]         ngx_http_sub_init_tables(conf->tables, conf->matches->elts,
[940]                                  conf->matches->nelts);
[941]     }
[942] 
[943]     return NGX_CONF_OK;
[944] }
[945] 
[946] 
[947] static void
[948] ngx_http_sub_init_tables(ngx_http_sub_tables_t *tables,
[949]     ngx_http_sub_match_t *match, ngx_uint_t n)
[950] {
[951]     u_char      c;
[952]     ngx_uint_t  i, j, min, max, ch;
[953] 
[954]     min = match[0].match.len;
[955]     max = match[0].match.len;
[956] 
[957]     for (i = 1; i < n; i++) {
[958]         min = ngx_min(min, match[i].match.len);
[959]         max = ngx_max(max, match[i].match.len);
[960]     }
[961] 
[962]     tables->min_match_len = min;
[963]     tables->max_match_len = max;
[964] 
[965]     ngx_http_sub_cmp_index = tables->min_match_len - 1;
[966]     ngx_sort(match, n, sizeof(ngx_http_sub_match_t), ngx_http_sub_cmp_matches);
[967] 
[968]     min = ngx_min(min, 255);
[969]     ngx_memset(tables->shift, min, 256);
[970] 
[971]     ch = 0;
[972] 
[973]     for (i = 0; i < n; i++) {
[974] 
[975]         for (j = 0; j < min; j++) {
[976]             c = match[i].match.data[tables->min_match_len - 1 - j];
[977]             tables->shift[c] = ngx_min(tables->shift[c], (u_char) j);
[978]         }
[979] 
[980]         c = match[i].match.data[tables->min_match_len - 1];
[981]         while (ch <= (ngx_uint_t) c) {
[982]             tables->index[ch++] = (u_char) i;
[983]         }
[984]     }
[985] 
[986]     while (ch < 257) {
[987]         tables->index[ch++] = (u_char) n;
[988]     }
[989] }
[990] 
[991] 
[992] static ngx_int_t
[993] ngx_http_sub_cmp_matches(const void *one, const void *two)
[994] {
[995]     ngx_int_t              c1, c2;
[996]     ngx_http_sub_match_t  *first, *second;
[997] 
[998]     first = (ngx_http_sub_match_t *) one;
[999]     second = (ngx_http_sub_match_t *) two;
[1000] 
[1001]     c1 = first->match.data[ngx_http_sub_cmp_index];
[1002]     c2 = second->match.data[ngx_http_sub_cmp_index];
[1003] 
[1004]     return c1 - c2;
[1005] }
[1006] 
[1007] 
[1008] static ngx_int_t
[1009] ngx_http_sub_filter_init(ngx_conf_t *cf)
[1010] {
[1011]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[1012]     ngx_http_top_header_filter = ngx_http_sub_header_filter;
[1013] 
[1014]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[1015]     ngx_http_top_body_filter = ngx_http_sub_body_filter;
[1016] 
[1017]     return NGX_OK;
[1018] }
