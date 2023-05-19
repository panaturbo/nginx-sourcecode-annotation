[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Maxim Dounin
[5]  * Copyright (C) Nginx, Inc.
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_http.h>
[12] 
[13] #include <zlib.h>
[14] 
[15] 
[16] typedef struct {
[17]     ngx_flag_t           enable;
[18]     ngx_bufs_t           bufs;
[19] } ngx_http_gunzip_conf_t;
[20] 
[21] 
[22] typedef struct {
[23]     ngx_chain_t         *in;
[24]     ngx_chain_t         *free;
[25]     ngx_chain_t         *busy;
[26]     ngx_chain_t         *out;
[27]     ngx_chain_t        **last_out;
[28] 
[29]     ngx_buf_t           *in_buf;
[30]     ngx_buf_t           *out_buf;
[31]     ngx_int_t            bufs;
[32] 
[33]     unsigned             started:1;
[34]     unsigned             flush:4;
[35]     unsigned             redo:1;
[36]     unsigned             done:1;
[37]     unsigned             nomem:1;
[38] 
[39]     z_stream             zstream;
[40]     ngx_http_request_t  *request;
[41] } ngx_http_gunzip_ctx_t;
[42] 
[43] 
[44] static ngx_int_t ngx_http_gunzip_filter_inflate_start(ngx_http_request_t *r,
[45]     ngx_http_gunzip_ctx_t *ctx);
[46] static ngx_int_t ngx_http_gunzip_filter_add_data(ngx_http_request_t *r,
[47]     ngx_http_gunzip_ctx_t *ctx);
[48] static ngx_int_t ngx_http_gunzip_filter_get_buf(ngx_http_request_t *r,
[49]     ngx_http_gunzip_ctx_t *ctx);
[50] static ngx_int_t ngx_http_gunzip_filter_inflate(ngx_http_request_t *r,
[51]     ngx_http_gunzip_ctx_t *ctx);
[52] static ngx_int_t ngx_http_gunzip_filter_inflate_end(ngx_http_request_t *r,
[53]     ngx_http_gunzip_ctx_t *ctx);
[54] 
[55] static void *ngx_http_gunzip_filter_alloc(void *opaque, u_int items,
[56]     u_int size);
[57] static void ngx_http_gunzip_filter_free(void *opaque, void *address);
[58] 
[59] static ngx_int_t ngx_http_gunzip_filter_init(ngx_conf_t *cf);
[60] static void *ngx_http_gunzip_create_conf(ngx_conf_t *cf);
[61] static char *ngx_http_gunzip_merge_conf(ngx_conf_t *cf,
[62]     void *parent, void *child);
[63] 
[64] 
[65] static ngx_command_t  ngx_http_gunzip_filter_commands[] = {
[66] 
[67]     { ngx_string("gunzip"),
[68]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[69]       ngx_conf_set_flag_slot,
[70]       NGX_HTTP_LOC_CONF_OFFSET,
[71]       offsetof(ngx_http_gunzip_conf_t, enable),
[72]       NULL },
[73] 
[74]     { ngx_string("gunzip_buffers"),
[75]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[76]       ngx_conf_set_bufs_slot,
[77]       NGX_HTTP_LOC_CONF_OFFSET,
[78]       offsetof(ngx_http_gunzip_conf_t, bufs),
[79]       NULL },
[80] 
[81]       ngx_null_command
[82] };
[83] 
[84] 
[85] static ngx_http_module_t  ngx_http_gunzip_filter_module_ctx = {
[86]     NULL,                                  /* preconfiguration */
[87]     ngx_http_gunzip_filter_init,           /* postconfiguration */
[88] 
[89]     NULL,                                  /* create main configuration */
[90]     NULL,                                  /* init main configuration */
[91] 
[92]     NULL,                                  /* create server configuration */
[93]     NULL,                                  /* merge server configuration */
[94] 
[95]     ngx_http_gunzip_create_conf,           /* create location configuration */
[96]     ngx_http_gunzip_merge_conf             /* merge location configuration */
[97] };
[98] 
[99] 
[100] ngx_module_t  ngx_http_gunzip_filter_module = {
[101]     NGX_MODULE_V1,
[102]     &ngx_http_gunzip_filter_module_ctx,    /* module context */
[103]     ngx_http_gunzip_filter_commands,       /* module directives */
[104]     NGX_HTTP_MODULE,                       /* module type */
[105]     NULL,                                  /* init master */
[106]     NULL,                                  /* init module */
[107]     NULL,                                  /* init process */
[108]     NULL,                                  /* init thread */
[109]     NULL,                                  /* exit thread */
[110]     NULL,                                  /* exit process */
[111]     NULL,                                  /* exit master */
[112]     NGX_MODULE_V1_PADDING
[113] };
[114] 
[115] 
[116] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[117] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[118] 
[119] 
[120] static ngx_int_t
[121] ngx_http_gunzip_header_filter(ngx_http_request_t *r)
[122] {
[123]     ngx_http_gunzip_ctx_t   *ctx;
[124]     ngx_http_gunzip_conf_t  *conf;
[125] 
[126]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gunzip_filter_module);
[127] 
[128]     /* TODO support multiple content-codings */
[129]     /* TODO always gunzip - due to configuration or module request */
[130]     /* TODO ignore content encoding? */
[131] 
[132]     if (!conf->enable
[133]         || r->headers_out.content_encoding == NULL
[134]         || r->headers_out.content_encoding->value.len != 4
[135]         || ngx_strncasecmp(r->headers_out.content_encoding->value.data,
[136]                            (u_char *) "gzip", 4) != 0)
[137]     {
[138]         return ngx_http_next_header_filter(r);
[139]     }
[140] 
[141]     r->gzip_vary = 1;
[142] 
[143]     if (!r->gzip_tested) {
[144]         if (ngx_http_gzip_ok(r) == NGX_OK) {
[145]             return ngx_http_next_header_filter(r);
[146]         }
[147] 
[148]     } else if (r->gzip_ok) {
[149]         return ngx_http_next_header_filter(r);
[150]     }
[151] 
[152]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gunzip_ctx_t));
[153]     if (ctx == NULL) {
[154]         return NGX_ERROR;
[155]     }
[156] 
[157]     ngx_http_set_ctx(r, ctx, ngx_http_gunzip_filter_module);
[158] 
[159]     ctx->request = r;
[160] 
[161]     r->filter_need_in_memory = 1;
[162] 
[163]     r->headers_out.content_encoding->hash = 0;
[164]     r->headers_out.content_encoding = NULL;
[165] 
[166]     ngx_http_clear_content_length(r);
[167]     ngx_http_clear_accept_ranges(r);
[168]     ngx_http_weak_etag(r);
[169] 
[170]     return ngx_http_next_header_filter(r);
[171] }
[172] 
[173] 
[174] static ngx_int_t
[175] ngx_http_gunzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[176] {
[177]     int                     rc;
[178]     ngx_uint_t              flush;
[179]     ngx_chain_t            *cl;
[180]     ngx_http_gunzip_ctx_t  *ctx;
[181] 
[182]     ctx = ngx_http_get_module_ctx(r, ngx_http_gunzip_filter_module);
[183] 
[184]     if (ctx == NULL || ctx->done) {
[185]         return ngx_http_next_body_filter(r, in);
[186]     }
[187] 
[188]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[189]                    "http gunzip filter");
[190] 
[191]     if (!ctx->started) {
[192]         if (ngx_http_gunzip_filter_inflate_start(r, ctx) != NGX_OK) {
[193]             goto failed;
[194]         }
[195]     }
[196] 
[197]     if (in) {
[198]         if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
[199]             goto failed;
[200]         }
[201]     }
[202] 
[203]     if (ctx->nomem) {
[204] 
[205]         /* flush busy buffers */
[206] 
[207]         if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
[208]             goto failed;
[209]         }
[210] 
[211]         cl = NULL;
[212] 
[213]         ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
[214]                                 (ngx_buf_tag_t) &ngx_http_gunzip_filter_module);
[215]         ctx->nomem = 0;
[216]         flush = 0;
[217] 
[218]     } else {
[219]         flush = ctx->busy ? 1 : 0;
[220]     }
[221] 
[222]     for ( ;; ) {
[223] 
[224]         /* cycle while we can write to a client */
[225] 
[226]         for ( ;; ) {
[227] 
[228]             /* cycle while there is data to feed zlib and ... */
[229] 
[230]             rc = ngx_http_gunzip_filter_add_data(r, ctx);
[231] 
[232]             if (rc == NGX_DECLINED) {
[233]                 break;
[234]             }
[235] 
[236]             if (rc == NGX_AGAIN) {
[237]                 continue;
[238]             }
[239] 
[240] 
[241]             /* ... there are buffers to write zlib output */
[242] 
[243]             rc = ngx_http_gunzip_filter_get_buf(r, ctx);
[244] 
[245]             if (rc == NGX_DECLINED) {
[246]                 break;
[247]             }
[248] 
[249]             if (rc == NGX_ERROR) {
[250]                 goto failed;
[251]             }
[252] 
[253]             rc = ngx_http_gunzip_filter_inflate(r, ctx);
[254] 
[255]             if (rc == NGX_OK) {
[256]                 break;
[257]             }
[258] 
[259]             if (rc == NGX_ERROR) {
[260]                 goto failed;
[261]             }
[262] 
[263]             /* rc == NGX_AGAIN */
[264]         }
[265] 
[266]         if (ctx->out == NULL && !flush) {
[267]             return ctx->busy ? NGX_AGAIN : NGX_OK;
[268]         }
[269] 
[270]         rc = ngx_http_next_body_filter(r, ctx->out);
[271] 
[272]         if (rc == NGX_ERROR) {
[273]             goto failed;
[274]         }
[275] 
[276]         ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
[277]                                 (ngx_buf_tag_t) &ngx_http_gunzip_filter_module);
[278]         ctx->last_out = &ctx->out;
[279] 
[280]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[281]                        "gunzip out: %p", ctx->out);
[282] 
[283]         ctx->nomem = 0;
[284]         flush = 0;
[285] 
[286]         if (ctx->done) {
[287]             return rc;
[288]         }
[289]     }
[290] 
[291]     /* unreachable */
[292] 
[293] failed:
[294] 
[295]     ctx->done = 1;
[296] 
[297]     return NGX_ERROR;
[298] }
[299] 
[300] 
[301] static ngx_int_t
[302] ngx_http_gunzip_filter_inflate_start(ngx_http_request_t *r,
[303]     ngx_http_gunzip_ctx_t *ctx)
[304] {
[305]     int  rc;
[306] 
[307]     ctx->zstream.next_in = Z_NULL;
[308]     ctx->zstream.avail_in = 0;
[309] 
[310]     ctx->zstream.zalloc = ngx_http_gunzip_filter_alloc;
[311]     ctx->zstream.zfree = ngx_http_gunzip_filter_free;
[312]     ctx->zstream.opaque = ctx;
[313] 
[314]     /* windowBits +16 to decode gzip, zlib 1.2.0.4+ */
[315]     rc = inflateInit2(&ctx->zstream, MAX_WBITS + 16);
[316] 
[317]     if (rc != Z_OK) {
[318]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[319]                       "inflateInit2() failed: %d", rc);
[320]         return NGX_ERROR;
[321]     }
[322] 
[323]     ctx->started = 1;
[324] 
[325]     ctx->last_out = &ctx->out;
[326]     ctx->flush = Z_NO_FLUSH;
[327] 
[328]     return NGX_OK;
[329] }
[330] 
[331] 
[332] static ngx_int_t
[333] ngx_http_gunzip_filter_add_data(ngx_http_request_t *r,
[334]     ngx_http_gunzip_ctx_t *ctx)
[335] {
[336]     if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
[337]         return NGX_OK;
[338]     }
[339] 
[340]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[341]                    "gunzip in: %p", ctx->in);
[342] 
[343]     if (ctx->in == NULL) {
[344]         return NGX_DECLINED;
[345]     }
[346] 
[347]     ctx->in_buf = ctx->in->buf;
[348]     ctx->in = ctx->in->next;
[349] 
[350]     ctx->zstream.next_in = ctx->in_buf->pos;
[351]     ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;
[352] 
[353]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[354]                    "gunzip in_buf:%p ni:%p ai:%ud",
[355]                    ctx->in_buf,
[356]                    ctx->zstream.next_in, ctx->zstream.avail_in);
[357] 
[358]     if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
[359]         ctx->flush = Z_FINISH;
[360] 
[361]     } else if (ctx->in_buf->flush) {
[362]         ctx->flush = Z_SYNC_FLUSH;
[363] 
[364]     } else if (ctx->zstream.avail_in == 0) {
[365]         /* ctx->flush == Z_NO_FLUSH */
[366]         return NGX_AGAIN;
[367]     }
[368] 
[369]     return NGX_OK;
[370] }
[371] 
[372] 
[373] static ngx_int_t
[374] ngx_http_gunzip_filter_get_buf(ngx_http_request_t *r,
[375]     ngx_http_gunzip_ctx_t *ctx)
[376] {
[377]     ngx_http_gunzip_conf_t  *conf;
[378] 
[379]     if (ctx->zstream.avail_out) {
[380]         return NGX_OK;
[381]     }
[382] 
[383]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gunzip_filter_module);
[384] 
[385]     if (ctx->free) {
[386]         ctx->out_buf = ctx->free->buf;
[387]         ctx->free = ctx->free->next;
[388] 
[389]         ctx->out_buf->flush = 0;
[390] 
[391]     } else if (ctx->bufs < conf->bufs.num) {
[392] 
[393]         ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
[394]         if (ctx->out_buf == NULL) {
[395]             return NGX_ERROR;
[396]         }
[397] 
[398]         ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_gunzip_filter_module;
[399]         ctx->out_buf->recycled = 1;
[400]         ctx->bufs++;
[401] 
[402]     } else {
[403]         ctx->nomem = 1;
[404]         return NGX_DECLINED;
[405]     }
[406] 
[407]     ctx->zstream.next_out = ctx->out_buf->pos;
[408]     ctx->zstream.avail_out = conf->bufs.size;
[409] 
[410]     return NGX_OK;
[411] }
[412] 
[413] 
[414] static ngx_int_t
[415] ngx_http_gunzip_filter_inflate(ngx_http_request_t *r,
[416]     ngx_http_gunzip_ctx_t *ctx)
[417] {
[418]     int           rc;
[419]     ngx_buf_t    *b;
[420]     ngx_chain_t  *cl;
[421] 
[422]     ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[423]                    "inflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
[424]                    ctx->zstream.next_in, ctx->zstream.next_out,
[425]                    ctx->zstream.avail_in, ctx->zstream.avail_out,
[426]                    ctx->flush, ctx->redo);
[427] 
[428]     rc = inflate(&ctx->zstream, ctx->flush);
[429] 
[430]     if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
[431]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[432]                       "inflate() failed: %d, %d", ctx->flush, rc);
[433]         return NGX_ERROR;
[434]     }
[435] 
[436]     ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[437]                    "inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
[438]                    ctx->zstream.next_in, ctx->zstream.next_out,
[439]                    ctx->zstream.avail_in, ctx->zstream.avail_out,
[440]                    rc);
[441] 
[442]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[443]                    "gunzip in_buf:%p pos:%p",
[444]                    ctx->in_buf, ctx->in_buf->pos);
[445] 
[446]     if (ctx->zstream.next_in) {
[447]         ctx->in_buf->pos = ctx->zstream.next_in;
[448] 
[449]         if (ctx->zstream.avail_in == 0) {
[450]             ctx->zstream.next_in = NULL;
[451]         }
[452]     }
[453] 
[454]     ctx->out_buf->last = ctx->zstream.next_out;
[455] 
[456]     if (ctx->zstream.avail_out == 0) {
[457] 
[458]         /* zlib wants to output some more data */
[459] 
[460]         cl = ngx_alloc_chain_link(r->pool);
[461]         if (cl == NULL) {
[462]             return NGX_ERROR;
[463]         }
[464] 
[465]         cl->buf = ctx->out_buf;
[466]         cl->next = NULL;
[467]         *ctx->last_out = cl;
[468]         ctx->last_out = &cl->next;
[469] 
[470]         ctx->redo = 1;
[471] 
[472]         return NGX_AGAIN;
[473]     }
[474] 
[475]     ctx->redo = 0;
[476] 
[477]     if (ctx->flush == Z_SYNC_FLUSH) {
[478] 
[479]         ctx->flush = Z_NO_FLUSH;
[480] 
[481]         cl = ngx_alloc_chain_link(r->pool);
[482]         if (cl == NULL) {
[483]             return NGX_ERROR;
[484]         }
[485] 
[486]         b = ctx->out_buf;
[487] 
[488]         if (ngx_buf_size(b) == 0) {
[489] 
[490]             b = ngx_calloc_buf(ctx->request->pool);
[491]             if (b == NULL) {
[492]                 return NGX_ERROR;
[493]             }
[494] 
[495]         } else {
[496]             ctx->zstream.avail_out = 0;
[497]         }
[498] 
[499]         b->flush = 1;
[500] 
[501]         cl->buf = b;
[502]         cl->next = NULL;
[503]         *ctx->last_out = cl;
[504]         ctx->last_out = &cl->next;
[505] 
[506]         return NGX_OK;
[507]     }
[508] 
[509]     if (ctx->flush == Z_FINISH && ctx->zstream.avail_in == 0) {
[510] 
[511]         if (rc != Z_STREAM_END) {
[512]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[513]                           "inflate() returned %d on response end", rc);
[514]             return NGX_ERROR;
[515]         }
[516] 
[517]         if (ngx_http_gunzip_filter_inflate_end(r, ctx) != NGX_OK) {
[518]             return NGX_ERROR;
[519]         }
[520] 
[521]         return NGX_OK;
[522]     }
[523] 
[524]     if (rc == Z_STREAM_END && ctx->zstream.avail_in > 0) {
[525] 
[526]         rc = inflateReset(&ctx->zstream);
[527] 
[528]         if (rc != Z_OK) {
[529]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[530]                           "inflateReset() failed: %d", rc);
[531]             return NGX_ERROR;
[532]         }
[533] 
[534]         ctx->redo = 1;
[535] 
[536]         return NGX_AGAIN;
[537]     }
[538] 
[539]     if (ctx->in == NULL) {
[540] 
[541]         b = ctx->out_buf;
[542] 
[543]         if (ngx_buf_size(b) == 0) {
[544]             return NGX_OK;
[545]         }
[546] 
[547]         cl = ngx_alloc_chain_link(r->pool);
[548]         if (cl == NULL) {
[549]             return NGX_ERROR;
[550]         }
[551] 
[552]         ctx->zstream.avail_out = 0;
[553] 
[554]         cl->buf = b;
[555]         cl->next = NULL;
[556]         *ctx->last_out = cl;
[557]         ctx->last_out = &cl->next;
[558] 
[559]         return NGX_OK;
[560]     }
[561] 
[562]     return NGX_AGAIN;
[563] }
[564] 
[565] 
[566] static ngx_int_t
[567] ngx_http_gunzip_filter_inflate_end(ngx_http_request_t *r,
[568]     ngx_http_gunzip_ctx_t *ctx)
[569] {
[570]     int           rc;
[571]     ngx_buf_t    *b;
[572]     ngx_chain_t  *cl;
[573] 
[574]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[575]                    "gunzip inflate end");
[576] 
[577]     rc = inflateEnd(&ctx->zstream);
[578] 
[579]     if (rc != Z_OK) {
[580]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[581]                       "inflateEnd() failed: %d", rc);
[582]         return NGX_ERROR;
[583]     }
[584] 
[585]     b = ctx->out_buf;
[586] 
[587]     if (ngx_buf_size(b) == 0) {
[588] 
[589]         b = ngx_calloc_buf(ctx->request->pool);
[590]         if (b == NULL) {
[591]             return NGX_ERROR;
[592]         }
[593]     }
[594] 
[595]     cl = ngx_alloc_chain_link(r->pool);
[596]     if (cl == NULL) {
[597]         return NGX_ERROR;
[598]     }
[599] 
[600]     cl->buf = b;
[601]     cl->next = NULL;
[602]     *ctx->last_out = cl;
[603]     ctx->last_out = &cl->next;
[604] 
[605]     b->last_buf = (r == r->main) ? 1 : 0;
[606]     b->last_in_chain = 1;
[607]     b->sync = 1;
[608] 
[609]     ctx->done = 1;
[610] 
[611]     return NGX_OK;
[612] }
[613] 
[614] 
[615] static void *
[616] ngx_http_gunzip_filter_alloc(void *opaque, u_int items, u_int size)
[617] {
[618]     ngx_http_gunzip_ctx_t *ctx = opaque;
[619] 
[620]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
[621]                    "gunzip alloc: n:%ud s:%ud",
[622]                    items, size);
[623] 
[624]     return ngx_palloc(ctx->request->pool, items * size);
[625] }
[626] 
[627] 
[628] static void
[629] ngx_http_gunzip_filter_free(void *opaque, void *address)
[630] {
[631] #if 0
[632]     ngx_http_gunzip_ctx_t *ctx = opaque;
[633] 
[634]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
[635]                    "gunzip free: %p", address);
[636] #endif
[637] }
[638] 
[639] 
[640] static void *
[641] ngx_http_gunzip_create_conf(ngx_conf_t *cf)
[642] {
[643]     ngx_http_gunzip_conf_t  *conf;
[644] 
[645]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gunzip_conf_t));
[646]     if (conf == NULL) {
[647]         return NULL;
[648]     }
[649] 
[650]     /*
[651]      * set by ngx_pcalloc():
[652]      *
[653]      *     conf->bufs.num = 0;
[654]      */
[655] 
[656]     conf->enable = NGX_CONF_UNSET;
[657] 
[658]     return conf;
[659] }
[660] 
[661] 
[662] static char *
[663] ngx_http_gunzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[664] {
[665]     ngx_http_gunzip_conf_t *prev = parent;
[666]     ngx_http_gunzip_conf_t *conf = child;
[667] 
[668]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[669] 
[670]     ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
[671]                               (128 * 1024) / ngx_pagesize, ngx_pagesize);
[672] 
[673]     return NGX_CONF_OK;
[674] }
[675] 
[676] 
[677] static ngx_int_t
[678] ngx_http_gunzip_filter_init(ngx_conf_t *cf)
[679] {
[680]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[681]     ngx_http_top_header_filter = ngx_http_gunzip_header_filter;
[682] 
[683]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[684]     ngx_http_top_body_filter = ngx_http_gunzip_body_filter;
[685] 
[686]     return NGX_OK;
[687] }
