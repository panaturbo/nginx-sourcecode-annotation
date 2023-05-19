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
[12] #include <zlib.h>
[13] 
[14] 
[15] typedef struct {
[16]     ngx_flag_t           enable;
[17]     ngx_flag_t           no_buffer;
[18] 
[19]     ngx_hash_t           types;
[20] 
[21]     ngx_bufs_t           bufs;
[22] 
[23]     size_t               postpone_gzipping;
[24]     ngx_int_t            level;
[25]     size_t               wbits;
[26]     size_t               memlevel;
[27]     ssize_t              min_length;
[28] 
[29]     ngx_array_t         *types_keys;
[30] } ngx_http_gzip_conf_t;
[31] 
[32] 
[33] typedef struct {
[34]     ngx_chain_t         *in;
[35]     ngx_chain_t         *free;
[36]     ngx_chain_t         *busy;
[37]     ngx_chain_t         *out;
[38]     ngx_chain_t        **last_out;
[39] 
[40]     ngx_chain_t         *copied;
[41]     ngx_chain_t         *copy_buf;
[42] 
[43]     ngx_buf_t           *in_buf;
[44]     ngx_buf_t           *out_buf;
[45]     ngx_int_t            bufs;
[46] 
[47]     void                *preallocated;
[48]     char                *free_mem;
[49]     ngx_uint_t           allocated;
[50] 
[51]     int                  wbits;
[52]     int                  memlevel;
[53] 
[54]     unsigned             flush:4;
[55]     unsigned             redo:1;
[56]     unsigned             done:1;
[57]     unsigned             nomem:1;
[58]     unsigned             buffering:1;
[59]     unsigned             zlib_ng:1;
[60]     unsigned             state_allocated:1;
[61] 
[62]     size_t               zin;
[63]     size_t               zout;
[64] 
[65]     z_stream             zstream;
[66]     ngx_http_request_t  *request;
[67] } ngx_http_gzip_ctx_t;
[68] 
[69] 
[70] static void ngx_http_gzip_filter_memory(ngx_http_request_t *r,
[71]     ngx_http_gzip_ctx_t *ctx);
[72] static ngx_int_t ngx_http_gzip_filter_buffer(ngx_http_gzip_ctx_t *ctx,
[73]     ngx_chain_t *in);
[74] static ngx_int_t ngx_http_gzip_filter_deflate_start(ngx_http_request_t *r,
[75]     ngx_http_gzip_ctx_t *ctx);
[76] static ngx_int_t ngx_http_gzip_filter_add_data(ngx_http_request_t *r,
[77]     ngx_http_gzip_ctx_t *ctx);
[78] static ngx_int_t ngx_http_gzip_filter_get_buf(ngx_http_request_t *r,
[79]     ngx_http_gzip_ctx_t *ctx);
[80] static ngx_int_t ngx_http_gzip_filter_deflate(ngx_http_request_t *r,
[81]     ngx_http_gzip_ctx_t *ctx);
[82] static ngx_int_t ngx_http_gzip_filter_deflate_end(ngx_http_request_t *r,
[83]     ngx_http_gzip_ctx_t *ctx);
[84] 
[85] static void *ngx_http_gzip_filter_alloc(void *opaque, u_int items,
[86]     u_int size);
[87] static void ngx_http_gzip_filter_free(void *opaque, void *address);
[88] static void ngx_http_gzip_filter_free_copy_buf(ngx_http_request_t *r,
[89]     ngx_http_gzip_ctx_t *ctx);
[90] 
[91] static ngx_int_t ngx_http_gzip_add_variables(ngx_conf_t *cf);
[92] static ngx_int_t ngx_http_gzip_ratio_variable(ngx_http_request_t *r,
[93]     ngx_http_variable_value_t *v, uintptr_t data);
[94] 
[95] static ngx_int_t ngx_http_gzip_filter_init(ngx_conf_t *cf);
[96] static void *ngx_http_gzip_create_conf(ngx_conf_t *cf);
[97] static char *ngx_http_gzip_merge_conf(ngx_conf_t *cf,
[98]     void *parent, void *child);
[99] static char *ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data);
[100] static char *ngx_http_gzip_hash(ngx_conf_t *cf, void *post, void *data);
[101] 
[102] 
[103] static ngx_conf_num_bounds_t  ngx_http_gzip_comp_level_bounds = {
[104]     ngx_conf_check_num_bounds, 1, 9
[105] };
[106] 
[107] static ngx_conf_post_handler_pt  ngx_http_gzip_window_p = ngx_http_gzip_window;
[108] static ngx_conf_post_handler_pt  ngx_http_gzip_hash_p = ngx_http_gzip_hash;
[109] 
[110] 
[111] static ngx_command_t  ngx_http_gzip_filter_commands[] = {
[112] 
[113]     { ngx_string("gzip"),
[114]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[115]                         |NGX_CONF_FLAG,
[116]       ngx_conf_set_flag_slot,
[117]       NGX_HTTP_LOC_CONF_OFFSET,
[118]       offsetof(ngx_http_gzip_conf_t, enable),
[119]       NULL },
[120] 
[121]     { ngx_string("gzip_buffers"),
[122]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[123]       ngx_conf_set_bufs_slot,
[124]       NGX_HTTP_LOC_CONF_OFFSET,
[125]       offsetof(ngx_http_gzip_conf_t, bufs),
[126]       NULL },
[127] 
[128]     { ngx_string("gzip_types"),
[129]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[130]       ngx_http_types_slot,
[131]       NGX_HTTP_LOC_CONF_OFFSET,
[132]       offsetof(ngx_http_gzip_conf_t, types_keys),
[133]       &ngx_http_html_default_types[0] },
[134] 
[135]     { ngx_string("gzip_comp_level"),
[136]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[137]       ngx_conf_set_num_slot,
[138]       NGX_HTTP_LOC_CONF_OFFSET,
[139]       offsetof(ngx_http_gzip_conf_t, level),
[140]       &ngx_http_gzip_comp_level_bounds },
[141] 
[142]     { ngx_string("gzip_window"),
[143]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[144]       ngx_conf_set_size_slot,
[145]       NGX_HTTP_LOC_CONF_OFFSET,
[146]       offsetof(ngx_http_gzip_conf_t, wbits),
[147]       &ngx_http_gzip_window_p },
[148] 
[149]     { ngx_string("gzip_hash"),
[150]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[151]       ngx_conf_set_size_slot,
[152]       NGX_HTTP_LOC_CONF_OFFSET,
[153]       offsetof(ngx_http_gzip_conf_t, memlevel),
[154]       &ngx_http_gzip_hash_p },
[155] 
[156]     { ngx_string("postpone_gzipping"),
[157]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[158]       ngx_conf_set_size_slot,
[159]       NGX_HTTP_LOC_CONF_OFFSET,
[160]       offsetof(ngx_http_gzip_conf_t, postpone_gzipping),
[161]       NULL },
[162] 
[163]     { ngx_string("gzip_no_buffer"),
[164]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[165]       ngx_conf_set_flag_slot,
[166]       NGX_HTTP_LOC_CONF_OFFSET,
[167]       offsetof(ngx_http_gzip_conf_t, no_buffer),
[168]       NULL },
[169] 
[170]     { ngx_string("gzip_min_length"),
[171]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[172]       ngx_conf_set_size_slot,
[173]       NGX_HTTP_LOC_CONF_OFFSET,
[174]       offsetof(ngx_http_gzip_conf_t, min_length),
[175]       NULL },
[176] 
[177]       ngx_null_command
[178] };
[179] 
[180] 
[181] static ngx_http_module_t  ngx_http_gzip_filter_module_ctx = {
[182]     ngx_http_gzip_add_variables,           /* preconfiguration */
[183]     ngx_http_gzip_filter_init,             /* postconfiguration */
[184] 
[185]     NULL,                                  /* create main configuration */
[186]     NULL,                                  /* init main configuration */
[187] 
[188]     NULL,                                  /* create server configuration */
[189]     NULL,                                  /* merge server configuration */
[190] 
[191]     ngx_http_gzip_create_conf,             /* create location configuration */
[192]     ngx_http_gzip_merge_conf               /* merge location configuration */
[193] };
[194] 
[195] 
[196] ngx_module_t  ngx_http_gzip_filter_module = {
[197]     NGX_MODULE_V1,
[198]     &ngx_http_gzip_filter_module_ctx,      /* module context */
[199]     ngx_http_gzip_filter_commands,         /* module directives */
[200]     NGX_HTTP_MODULE,                       /* module type */
[201]     NULL,                                  /* init master */
[202]     NULL,                                  /* init module */
[203]     NULL,                                  /* init process */
[204]     NULL,                                  /* init thread */
[205]     NULL,                                  /* exit thread */
[206]     NULL,                                  /* exit process */
[207]     NULL,                                  /* exit master */
[208]     NGX_MODULE_V1_PADDING
[209] };
[210] 
[211] 
[212] static ngx_str_t  ngx_http_gzip_ratio = ngx_string("gzip_ratio");
[213] 
[214] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[215] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[216] 
[217] static ngx_uint_t  ngx_http_gzip_assume_zlib_ng;
[218] 
[219] 
[220] static ngx_int_t
[221] ngx_http_gzip_header_filter(ngx_http_request_t *r)
[222] {
[223]     ngx_table_elt_t       *h;
[224]     ngx_http_gzip_ctx_t   *ctx;
[225]     ngx_http_gzip_conf_t  *conf;
[226] 
[227]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);
[228] 
[229]     if (!conf->enable
[230]         || (r->headers_out.status != NGX_HTTP_OK
[231]             && r->headers_out.status != NGX_HTTP_FORBIDDEN
[232]             && r->headers_out.status != NGX_HTTP_NOT_FOUND)
[233]         || (r->headers_out.content_encoding
[234]             && r->headers_out.content_encoding->value.len)
[235]         || (r->headers_out.content_length_n != -1
[236]             && r->headers_out.content_length_n < conf->min_length)
[237]         || ngx_http_test_content_type(r, &conf->types) == NULL
[238]         || r->header_only)
[239]     {
[240]         return ngx_http_next_header_filter(r);
[241]     }
[242] 
[243]     r->gzip_vary = 1;
[244] 
[245] #if (NGX_HTTP_DEGRADATION)
[246]     {
[247]     ngx_http_core_loc_conf_t  *clcf;
[248] 
[249]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[250] 
[251]     if (clcf->gzip_disable_degradation && ngx_http_degraded(r)) {
[252]         return ngx_http_next_header_filter(r);
[253]     }
[254]     }
[255] #endif
[256] 
[257]     if (!r->gzip_tested) {
[258]         if (ngx_http_gzip_ok(r) != NGX_OK) {
[259]             return ngx_http_next_header_filter(r);
[260]         }
[261] 
[262]     } else if (!r->gzip_ok) {
[263]         return ngx_http_next_header_filter(r);
[264]     }
[265] 
[266]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gzip_ctx_t));
[267]     if (ctx == NULL) {
[268]         return NGX_ERROR;
[269]     }
[270] 
[271]     ngx_http_set_ctx(r, ctx, ngx_http_gzip_filter_module);
[272] 
[273]     ctx->request = r;
[274]     ctx->buffering = (conf->postpone_gzipping != 0);
[275] 
[276]     ngx_http_gzip_filter_memory(r, ctx);
[277] 
[278]     h = ngx_list_push(&r->headers_out.headers);
[279]     if (h == NULL) {
[280]         return NGX_ERROR;
[281]     }
[282] 
[283]     h->hash = 1;
[284]     h->next = NULL;
[285]     ngx_str_set(&h->key, "Content-Encoding");
[286]     ngx_str_set(&h->value, "gzip");
[287]     r->headers_out.content_encoding = h;
[288] 
[289]     r->main_filter_need_in_memory = 1;
[290] 
[291]     ngx_http_clear_content_length(r);
[292]     ngx_http_clear_accept_ranges(r);
[293]     ngx_http_weak_etag(r);
[294] 
[295]     return ngx_http_next_header_filter(r);
[296] }
[297] 
[298] 
[299] static ngx_int_t
[300] ngx_http_gzip_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[301] {
[302]     int                   rc;
[303]     ngx_uint_t            flush;
[304]     ngx_chain_t          *cl;
[305]     ngx_http_gzip_ctx_t  *ctx;
[306] 
[307]     ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);
[308] 
[309]     if (ctx == NULL || ctx->done || r->header_only) {
[310]         return ngx_http_next_body_filter(r, in);
[311]     }
[312] 
[313]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[314]                    "http gzip filter");
[315] 
[316]     if (ctx->buffering) {
[317] 
[318]         /*
[319]          * With default memory settings zlib starts to output gzipped data
[320]          * only after it has got about 90K, so it makes sense to allocate
[321]          * zlib memory (200-400K) only after we have enough data to compress.
[322]          * Although we copy buffers, nevertheless for not big responses
[323]          * this allows to allocate zlib memory, to compress and to output
[324]          * the response in one step using hot CPU cache.
[325]          */
[326] 
[327]         if (in) {
[328]             switch (ngx_http_gzip_filter_buffer(ctx, in)) {
[329] 
[330]             case NGX_OK:
[331]                 return NGX_OK;
[332] 
[333]             case NGX_DONE:
[334]                 in = NULL;
[335]                 break;
[336] 
[337]             default:  /* NGX_ERROR */
[338]                 goto failed;
[339]             }
[340] 
[341]         } else {
[342]             ctx->buffering = 0;
[343]         }
[344]     }
[345] 
[346]     if (ctx->preallocated == NULL) {
[347]         if (ngx_http_gzip_filter_deflate_start(r, ctx) != NGX_OK) {
[348]             goto failed;
[349]         }
[350]     }
[351] 
[352]     if (in) {
[353]         if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
[354]             goto failed;
[355]         }
[356] 
[357]         r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
[358]     }
[359] 
[360]     if (ctx->nomem) {
[361] 
[362]         /* flush busy buffers */
[363] 
[364]         if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
[365]             goto failed;
[366]         }
[367] 
[368]         cl = NULL;
[369] 
[370]         ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
[371]                                 (ngx_buf_tag_t) &ngx_http_gzip_filter_module);
[372]         ctx->nomem = 0;
[373]         flush = 0;
[374] 
[375]     } else {
[376]         flush = ctx->busy ? 1 : 0;
[377]     }
[378] 
[379]     for ( ;; ) {
[380] 
[381]         /* cycle while we can write to a client */
[382] 
[383]         for ( ;; ) {
[384] 
[385]             /* cycle while there is data to feed zlib and ... */
[386] 
[387]             rc = ngx_http_gzip_filter_add_data(r, ctx);
[388] 
[389]             if (rc == NGX_DECLINED) {
[390]                 break;
[391]             }
[392] 
[393]             if (rc == NGX_AGAIN) {
[394]                 continue;
[395]             }
[396] 
[397] 
[398]             /* ... there are buffers to write zlib output */
[399] 
[400]             rc = ngx_http_gzip_filter_get_buf(r, ctx);
[401] 
[402]             if (rc == NGX_DECLINED) {
[403]                 break;
[404]             }
[405] 
[406]             if (rc == NGX_ERROR) {
[407]                 goto failed;
[408]             }
[409] 
[410] 
[411]             rc = ngx_http_gzip_filter_deflate(r, ctx);
[412] 
[413]             if (rc == NGX_OK) {
[414]                 break;
[415]             }
[416] 
[417]             if (rc == NGX_ERROR) {
[418]                 goto failed;
[419]             }
[420] 
[421]             /* rc == NGX_AGAIN */
[422]         }
[423] 
[424]         if (ctx->out == NULL && !flush) {
[425]             ngx_http_gzip_filter_free_copy_buf(r, ctx);
[426] 
[427]             return ctx->busy ? NGX_AGAIN : NGX_OK;
[428]         }
[429] 
[430]         rc = ngx_http_next_body_filter(r, ctx->out);
[431] 
[432]         if (rc == NGX_ERROR) {
[433]             goto failed;
[434]         }
[435] 
[436]         ngx_http_gzip_filter_free_copy_buf(r, ctx);
[437] 
[438]         ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
[439]                                 (ngx_buf_tag_t) &ngx_http_gzip_filter_module);
[440]         ctx->last_out = &ctx->out;
[441] 
[442]         ctx->nomem = 0;
[443]         flush = 0;
[444] 
[445]         if (ctx->done) {
[446]             return rc;
[447]         }
[448]     }
[449] 
[450]     /* unreachable */
[451] 
[452] failed:
[453] 
[454]     ctx->done = 1;
[455] 
[456]     if (ctx->preallocated) {
[457]         deflateEnd(&ctx->zstream);
[458] 
[459]         ngx_pfree(r->pool, ctx->preallocated);
[460]     }
[461] 
[462]     ngx_http_gzip_filter_free_copy_buf(r, ctx);
[463] 
[464]     return NGX_ERROR;
[465] }
[466] 
[467] 
[468] static void
[469] ngx_http_gzip_filter_memory(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
[470] {
[471]     int                    wbits, memlevel;
[472]     ngx_http_gzip_conf_t  *conf;
[473] 
[474]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);
[475] 
[476]     wbits = conf->wbits;
[477]     memlevel = conf->memlevel;
[478] 
[479]     if (r->headers_out.content_length_n > 0) {
[480] 
[481]         /* the actual zlib window size is smaller by 262 bytes */
[482] 
[483]         while (r->headers_out.content_length_n < ((1 << (wbits - 1)) - 262)) {
[484]             wbits--;
[485]             memlevel--;
[486]         }
[487] 
[488]         if (memlevel < 1) {
[489]             memlevel = 1;
[490]         }
[491]     }
[492] 
[493]     ctx->wbits = wbits;
[494]     ctx->memlevel = memlevel;
[495] 
[496]     /*
[497]      * We preallocate a memory for zlib in one buffer (200K-400K), this
[498]      * decreases a number of malloc() and free() calls and also probably
[499]      * decreases a number of syscalls (sbrk()/mmap() and so on).
[500]      * Besides we free the memory as soon as a gzipping will complete
[501]      * and do not wait while a whole response will be sent to a client.
[502]      *
[503]      * 8K is for zlib deflate_state, it takes
[504]      *  *) 5816 bytes on i386 and sparc64 (32-bit mode)
[505]      *  *) 5920 bytes on amd64 and sparc64
[506]      *
[507]      * A zlib variant from Intel (https://github.com/jtkukunas/zlib)
[508]      * uses additional 16-byte padding in one of window-sized buffers.
[509]      */
[510] 
[511]     if (!ngx_http_gzip_assume_zlib_ng) {
[512]         ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
[513]                          + (1 << (memlevel + 9));
[514] 
[515]     } else {
[516]         /*
[517]          * Another zlib variant, https://github.com/zlib-ng/zlib-ng.
[518]          * It used to force window bits to 13 for fast compression level,
[519]          * uses (64 + sizeof(void*)) additional space on all allocations
[520]          * for alignment, 16-byte padding in one of window-sized buffers,
[521]          * and 128K hash.
[522]          */
[523] 
[524]         if (conf->level == 1) {
[525]             wbits = ngx_max(wbits, 13);
[526]         }
[527] 
[528]         ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
[529]                          + 131072 + (1 << (memlevel + 8))
[530]                          + 4 * (64 + sizeof(void*));
[531]         ctx->zlib_ng = 1;
[532]     }
[533] }
[534] 
[535] 
[536] static ngx_int_t
[537] ngx_http_gzip_filter_buffer(ngx_http_gzip_ctx_t *ctx, ngx_chain_t *in)
[538] {
[539]     size_t                 size, buffered;
[540]     ngx_buf_t             *b, *buf;
[541]     ngx_chain_t           *cl, **ll;
[542]     ngx_http_request_t    *r;
[543]     ngx_http_gzip_conf_t  *conf;
[544] 
[545]     r = ctx->request;
[546] 
[547]     r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
[548] 
[549]     buffered = 0;
[550]     ll = &ctx->in;
[551] 
[552]     for (cl = ctx->in; cl; cl = cl->next) {
[553]         buffered += cl->buf->last - cl->buf->pos;
[554]         ll = &cl->next;
[555]     }
[556] 
[557]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);
[558] 
[559]     while (in) {
[560]         cl = ngx_alloc_chain_link(r->pool);
[561]         if (cl == NULL) {
[562]             return NGX_ERROR;
[563]         }
[564] 
[565]         b = in->buf;
[566] 
[567]         size = b->last - b->pos;
[568]         buffered += size;
[569] 
[570]         if (b->flush || b->last_buf || buffered > conf->postpone_gzipping) {
[571]             ctx->buffering = 0;
[572]         }
[573] 
[574]         if (ctx->buffering && size) {
[575] 
[576]             buf = ngx_create_temp_buf(r->pool, size);
[577]             if (buf == NULL) {
[578]                 return NGX_ERROR;
[579]             }
[580] 
[581]             buf->last = ngx_cpymem(buf->pos, b->pos, size);
[582]             b->pos = b->last;
[583] 
[584]             buf->last_buf = b->last_buf;
[585]             buf->tag = (ngx_buf_tag_t) &ngx_http_gzip_filter_module;
[586] 
[587]             cl->buf = buf;
[588] 
[589]         } else {
[590]             cl->buf = b;
[591]         }
[592] 
[593]         *ll = cl;
[594]         ll = &cl->next;
[595]         in = in->next;
[596]     }
[597] 
[598]     *ll = NULL;
[599] 
[600]     return ctx->buffering ? NGX_OK : NGX_DONE;
[601] }
[602] 
[603] 
[604] static ngx_int_t
[605] ngx_http_gzip_filter_deflate_start(ngx_http_request_t *r,
[606]     ngx_http_gzip_ctx_t *ctx)
[607] {
[608]     int                    rc;
[609]     ngx_http_gzip_conf_t  *conf;
[610] 
[611]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);
[612] 
[613]     ctx->preallocated = ngx_palloc(r->pool, ctx->allocated);
[614]     if (ctx->preallocated == NULL) {
[615]         return NGX_ERROR;
[616]     }
[617] 
[618]     ctx->free_mem = ctx->preallocated;
[619] 
[620]     ctx->zstream.zalloc = ngx_http_gzip_filter_alloc;
[621]     ctx->zstream.zfree = ngx_http_gzip_filter_free;
[622]     ctx->zstream.opaque = ctx;
[623] 
[624]     rc = deflateInit2(&ctx->zstream, (int) conf->level, Z_DEFLATED,
[625]                       ctx->wbits + 16, ctx->memlevel, Z_DEFAULT_STRATEGY);
[626] 
[627]     if (rc != Z_OK) {
[628]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[629]                       "deflateInit2() failed: %d", rc);
[630]         return NGX_ERROR;
[631]     }
[632] 
[633]     ctx->last_out = &ctx->out;
[634]     ctx->flush = Z_NO_FLUSH;
[635] 
[636]     return NGX_OK;
[637] }
[638] 
[639] 
[640] static ngx_int_t
[641] ngx_http_gzip_filter_add_data(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
[642] {
[643]     ngx_chain_t  *cl;
[644] 
[645]     if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
[646]         return NGX_OK;
[647]     }
[648] 
[649]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[650]                    "gzip in: %p", ctx->in);
[651] 
[652]     if (ctx->in == NULL) {
[653]         return NGX_DECLINED;
[654]     }
[655] 
[656]     if (ctx->copy_buf) {
[657] 
[658]         /*
[659]          * to avoid CPU cache trashing we do not free() just quit buf,
[660]          * but postpone free()ing after zlib compressing and data output
[661]          */
[662] 
[663]         ctx->copy_buf->next = ctx->copied;
[664]         ctx->copied = ctx->copy_buf;
[665]         ctx->copy_buf = NULL;
[666]     }
[667] 
[668]     cl = ctx->in;
[669]     ctx->in_buf = cl->buf;
[670]     ctx->in = cl->next;
[671] 
[672]     if (ctx->in_buf->tag == (ngx_buf_tag_t) &ngx_http_gzip_filter_module) {
[673]         ctx->copy_buf = cl;
[674] 
[675]     } else {
[676]         ngx_free_chain(r->pool, cl);
[677]     }
[678] 
[679]     ctx->zstream.next_in = ctx->in_buf->pos;
[680]     ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;
[681] 
[682]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[683]                    "gzip in_buf:%p ni:%p ai:%ud",
[684]                    ctx->in_buf,
[685]                    ctx->zstream.next_in, ctx->zstream.avail_in);
[686] 
[687]     if (ctx->in_buf->last_buf) {
[688]         ctx->flush = Z_FINISH;
[689] 
[690]     } else if (ctx->in_buf->flush) {
[691]         ctx->flush = Z_SYNC_FLUSH;
[692] 
[693]     } else if (ctx->zstream.avail_in == 0) {
[694]         /* ctx->flush == Z_NO_FLUSH */
[695]         return NGX_AGAIN;
[696]     }
[697] 
[698]     return NGX_OK;
[699] }
[700] 
[701] 
[702] static ngx_int_t
[703] ngx_http_gzip_filter_get_buf(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
[704] {
[705]     ngx_chain_t           *cl;
[706]     ngx_http_gzip_conf_t  *conf;
[707] 
[708]     if (ctx->zstream.avail_out) {
[709]         return NGX_OK;
[710]     }
[711] 
[712]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);
[713] 
[714]     if (ctx->free) {
[715] 
[716]         cl = ctx->free;
[717]         ctx->out_buf = cl->buf;
[718]         ctx->free = cl->next;
[719] 
[720]         ngx_free_chain(r->pool, cl);
[721] 
[722]     } else if (ctx->bufs < conf->bufs.num) {
[723] 
[724]         ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
[725]         if (ctx->out_buf == NULL) {
[726]             return NGX_ERROR;
[727]         }
[728] 
[729]         ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_gzip_filter_module;
[730]         ctx->out_buf->recycled = 1;
[731]         ctx->bufs++;
[732] 
[733]     } else {
[734]         ctx->nomem = 1;
[735]         return NGX_DECLINED;
[736]     }
[737] 
[738]     ctx->zstream.next_out = ctx->out_buf->pos;
[739]     ctx->zstream.avail_out = conf->bufs.size;
[740] 
[741]     return NGX_OK;
[742] }
[743] 
[744] 
[745] static ngx_int_t
[746] ngx_http_gzip_filter_deflate(ngx_http_request_t *r, ngx_http_gzip_ctx_t *ctx)
[747] {
[748]     int                    rc;
[749]     ngx_buf_t             *b;
[750]     ngx_chain_t           *cl;
[751]     ngx_http_gzip_conf_t  *conf;
[752] 
[753]     ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[754]                  "deflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
[755]                  ctx->zstream.next_in, ctx->zstream.next_out,
[756]                  ctx->zstream.avail_in, ctx->zstream.avail_out,
[757]                  ctx->flush, ctx->redo);
[758] 
[759]     rc = deflate(&ctx->zstream, ctx->flush);
[760] 
[761]     if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
[762]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[763]                       "deflate() failed: %d, %d", ctx->flush, rc);
[764]         return NGX_ERROR;
[765]     }
[766] 
[767]     ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[768]                    "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
[769]                    ctx->zstream.next_in, ctx->zstream.next_out,
[770]                    ctx->zstream.avail_in, ctx->zstream.avail_out,
[771]                    rc);
[772] 
[773]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[774]                    "gzip in_buf:%p pos:%p",
[775]                    ctx->in_buf, ctx->in_buf->pos);
[776] 
[777]     if (ctx->zstream.next_in) {
[778]         ctx->in_buf->pos = ctx->zstream.next_in;
[779] 
[780]         if (ctx->zstream.avail_in == 0) {
[781]             ctx->zstream.next_in = NULL;
[782]         }
[783]     }
[784] 
[785]     ctx->out_buf->last = ctx->zstream.next_out;
[786] 
[787]     if (ctx->zstream.avail_out == 0 && rc != Z_STREAM_END) {
[788] 
[789]         /* zlib wants to output some more gzipped data */
[790] 
[791]         cl = ngx_alloc_chain_link(r->pool);
[792]         if (cl == NULL) {
[793]             return NGX_ERROR;
[794]         }
[795] 
[796]         cl->buf = ctx->out_buf;
[797]         cl->next = NULL;
[798]         *ctx->last_out = cl;
[799]         ctx->last_out = &cl->next;
[800] 
[801]         ctx->redo = 1;
[802] 
[803]         return NGX_AGAIN;
[804]     }
[805] 
[806]     ctx->redo = 0;
[807] 
[808]     if (ctx->flush == Z_SYNC_FLUSH) {
[809] 
[810]         ctx->flush = Z_NO_FLUSH;
[811] 
[812]         cl = ngx_alloc_chain_link(r->pool);
[813]         if (cl == NULL) {
[814]             return NGX_ERROR;
[815]         }
[816] 
[817]         b = ctx->out_buf;
[818] 
[819]         if (ngx_buf_size(b) == 0) {
[820] 
[821]             b = ngx_calloc_buf(ctx->request->pool);
[822]             if (b == NULL) {
[823]                 return NGX_ERROR;
[824]             }
[825] 
[826]         } else {
[827]             ctx->zstream.avail_out = 0;
[828]         }
[829] 
[830]         b->flush = 1;
[831] 
[832]         cl->buf = b;
[833]         cl->next = NULL;
[834]         *ctx->last_out = cl;
[835]         ctx->last_out = &cl->next;
[836] 
[837]         r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;
[838] 
[839]         return NGX_OK;
[840]     }
[841] 
[842]     if (rc == Z_STREAM_END) {
[843] 
[844]         if (ngx_http_gzip_filter_deflate_end(r, ctx) != NGX_OK) {
[845]             return NGX_ERROR;
[846]         }
[847] 
[848]         return NGX_OK;
[849]     }
[850] 
[851]     conf = ngx_http_get_module_loc_conf(r, ngx_http_gzip_filter_module);
[852] 
[853]     if (conf->no_buffer && ctx->in == NULL) {
[854] 
[855]         cl = ngx_alloc_chain_link(r->pool);
[856]         if (cl == NULL) {
[857]             return NGX_ERROR;
[858]         }
[859] 
[860]         cl->buf = ctx->out_buf;
[861]         cl->next = NULL;
[862]         *ctx->last_out = cl;
[863]         ctx->last_out = &cl->next;
[864] 
[865]         return NGX_OK;
[866]     }
[867] 
[868]     return NGX_AGAIN;
[869] }
[870] 
[871] 
[872] static ngx_int_t
[873] ngx_http_gzip_filter_deflate_end(ngx_http_request_t *r,
[874]     ngx_http_gzip_ctx_t *ctx)
[875] {
[876]     int           rc;
[877]     ngx_buf_t    *b;
[878]     ngx_chain_t  *cl;
[879] 
[880]     ctx->zin = ctx->zstream.total_in;
[881]     ctx->zout = ctx->zstream.total_out;
[882] 
[883]     rc = deflateEnd(&ctx->zstream);
[884] 
[885]     if (rc != Z_OK) {
[886]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[887]                       "deflateEnd() failed: %d", rc);
[888]         return NGX_ERROR;
[889]     }
[890] 
[891]     ngx_pfree(r->pool, ctx->preallocated);
[892] 
[893]     cl = ngx_alloc_chain_link(r->pool);
[894]     if (cl == NULL) {
[895]         return NGX_ERROR;
[896]     }
[897] 
[898]     b = ctx->out_buf;
[899] 
[900]     if (ngx_buf_size(b) == 0) {
[901]         b->temporary = 0;
[902]     }
[903] 
[904]     b->last_buf = 1;
[905] 
[906]     cl->buf = b;
[907]     cl->next = NULL;
[908]     *ctx->last_out = cl;
[909]     ctx->last_out = &cl->next;
[910] 
[911]     ctx->zstream.avail_in = 0;
[912]     ctx->zstream.avail_out = 0;
[913] 
[914]     ctx->done = 1;
[915] 
[916]     r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;
[917] 
[918]     return NGX_OK;
[919] }
[920] 
[921] 
[922] static void *
[923] ngx_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
[924] {
[925]     ngx_http_gzip_ctx_t *ctx = opaque;
[926] 
[927]     void        *p;
[928]     ngx_uint_t   alloc;
[929] 
[930]     alloc = items * size;
[931] 
[932]     if (items == 1 && alloc % 512 != 0 && alloc < 8192
[933]         && !ctx->state_allocated)
[934]     {
[935]         /*
[936]          * The zlib deflate_state allocation, it takes about 6K,
[937]          * we allocate 8K.  Other allocations are divisible by 512.
[938]          */
[939] 
[940]         ctx->state_allocated = 1;
[941] 
[942]         alloc = 8192;
[943]     }
[944] 
[945]     if (alloc <= ctx->allocated) {
[946]         p = ctx->free_mem;
[947]         ctx->free_mem += alloc;
[948]         ctx->allocated -= alloc;
[949] 
[950]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
[951]                        "gzip alloc: n:%ud s:%ud a:%ui p:%p",
[952]                        items, size, alloc, p);
[953] 
[954]         return p;
[955]     }
[956] 
[957]     if (ctx->zlib_ng) {
[958]         ngx_log_error(NGX_LOG_ALERT, ctx->request->connection->log, 0,
[959]                       "gzip filter failed to use preallocated memory: "
[960]                       "%ud of %ui", items * size, ctx->allocated);
[961] 
[962]     } else {
[963]         ngx_http_gzip_assume_zlib_ng = 1;
[964]     }
[965] 
[966]     p = ngx_palloc(ctx->request->pool, items * size);
[967] 
[968]     return p;
[969] }
[970] 
[971] 
[972] static void
[973] ngx_http_gzip_filter_free(void *opaque, void *address)
[974] {
[975] #if 0
[976]     ngx_http_gzip_ctx_t *ctx = opaque;
[977] 
[978]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
[979]                    "gzip free: %p", address);
[980] #endif
[981] }
[982] 
[983] 
[984] static void
[985] ngx_http_gzip_filter_free_copy_buf(ngx_http_request_t *r,
[986]     ngx_http_gzip_ctx_t *ctx)
[987] {
[988]     ngx_chain_t  *cl;
[989] 
[990]     for (cl = ctx->copied; cl; cl = cl->next) {
[991]         ngx_pfree(r->pool, cl->buf->start);
[992]     }
[993] 
[994]     ctx->copied = NULL;
[995] }
[996] 
[997] 
[998] static ngx_int_t
[999] ngx_http_gzip_add_variables(ngx_conf_t *cf)
[1000] {
[1001]     ngx_http_variable_t  *var;
[1002] 
[1003]     var = ngx_http_add_variable(cf, &ngx_http_gzip_ratio, NGX_HTTP_VAR_NOHASH);
[1004]     if (var == NULL) {
[1005]         return NGX_ERROR;
[1006]     }
[1007] 
[1008]     var->get_handler = ngx_http_gzip_ratio_variable;
[1009] 
[1010]     return NGX_OK;
[1011] }
[1012] 
[1013] 
[1014] static ngx_int_t
[1015] ngx_http_gzip_ratio_variable(ngx_http_request_t *r,
[1016]     ngx_http_variable_value_t *v, uintptr_t data)
[1017] {
[1018]     ngx_uint_t            zint, zfrac;
[1019]     ngx_http_gzip_ctx_t  *ctx;
[1020] 
[1021]     ctx = ngx_http_get_module_ctx(r, ngx_http_gzip_filter_module);
[1022] 
[1023]     if (ctx == NULL || ctx->zout == 0) {
[1024]         v->not_found = 1;
[1025]         return NGX_OK;
[1026]     }
[1027] 
[1028]     v->valid = 1;
[1029]     v->no_cacheable = 0;
[1030]     v->not_found = 0;
[1031] 
[1032]     v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN + 3);
[1033]     if (v->data == NULL) {
[1034]         return NGX_ERROR;
[1035]     }
[1036] 
[1037]     zint = (ngx_uint_t) (ctx->zin / ctx->zout);
[1038]     zfrac = (ngx_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);
[1039] 
[1040]     if ((ctx->zin * 1000 / ctx->zout) % 10 > 4) {
[1041] 
[1042]         /* the rounding, e.g., 2.125 to 2.13 */
[1043] 
[1044]         zfrac++;
[1045] 
[1046]         if (zfrac > 99) {
[1047]             zint++;
[1048]             zfrac = 0;
[1049]         }
[1050]     }
[1051] 
[1052]     v->len = ngx_sprintf(v->data, "%ui.%02ui", zint, zfrac) - v->data;
[1053] 
[1054]     return NGX_OK;
[1055] }
[1056] 
[1057] 
[1058] static void *
[1059] ngx_http_gzip_create_conf(ngx_conf_t *cf)
[1060] {
[1061]     ngx_http_gzip_conf_t  *conf;
[1062] 
[1063]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gzip_conf_t));
[1064]     if (conf == NULL) {
[1065]         return NULL;
[1066]     }
[1067] 
[1068]     /*
[1069]      * set by ngx_pcalloc():
[1070]      *
[1071]      *     conf->bufs.num = 0;
[1072]      *     conf->types = { NULL };
[1073]      *     conf->types_keys = NULL;
[1074]      */
[1075] 
[1076]     conf->enable = NGX_CONF_UNSET;
[1077]     conf->no_buffer = NGX_CONF_UNSET;
[1078] 
[1079]     conf->postpone_gzipping = NGX_CONF_UNSET_SIZE;
[1080]     conf->level = NGX_CONF_UNSET;
[1081]     conf->wbits = NGX_CONF_UNSET_SIZE;
[1082]     conf->memlevel = NGX_CONF_UNSET_SIZE;
[1083]     conf->min_length = NGX_CONF_UNSET;
[1084] 
[1085]     return conf;
[1086] }
[1087] 
[1088] 
[1089] static char *
[1090] ngx_http_gzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[1091] {
[1092]     ngx_http_gzip_conf_t *prev = parent;
[1093]     ngx_http_gzip_conf_t *conf = child;
[1094] 
[1095]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[1096]     ngx_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);
[1097] 
[1098]     ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
[1099]                               (128 * 1024) / ngx_pagesize, ngx_pagesize);
[1100] 
[1101]     ngx_conf_merge_size_value(conf->postpone_gzipping, prev->postpone_gzipping,
[1102]                               0);
[1103]     ngx_conf_merge_value(conf->level, prev->level, 1);
[1104]     ngx_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
[1105]     ngx_conf_merge_size_value(conf->memlevel, prev->memlevel,
[1106]                               MAX_MEM_LEVEL - 1);
[1107]     ngx_conf_merge_value(conf->min_length, prev->min_length, 20);
[1108] 
[1109]     if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
[1110]                              &prev->types_keys, &prev->types,
[1111]                              ngx_http_html_default_types)
[1112]         != NGX_OK)
[1113]     {
[1114]         return NGX_CONF_ERROR;
[1115]     }
[1116] 
[1117]     return NGX_CONF_OK;
[1118] }
[1119] 
[1120] 
[1121] static ngx_int_t
[1122] ngx_http_gzip_filter_init(ngx_conf_t *cf)
[1123] {
[1124]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[1125]     ngx_http_top_header_filter = ngx_http_gzip_header_filter;
[1126] 
[1127]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[1128]     ngx_http_top_body_filter = ngx_http_gzip_body_filter;
[1129] 
[1130]     return NGX_OK;
[1131] }
[1132] 
[1133] 
[1134] static char *
[1135] ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data)
[1136] {
[1137]     size_t *np = data;
[1138] 
[1139]     size_t  wbits, wsize;
[1140] 
[1141]     wbits = 15;
[1142] 
[1143]     for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {
[1144] 
[1145]         if (wsize == *np) {
[1146]             *np = wbits;
[1147] 
[1148]             return NGX_CONF_OK;
[1149]         }
[1150] 
[1151]         wbits--;
[1152]     }
[1153] 
[1154]     return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
[1155] }
[1156] 
[1157] 
[1158] static char *
[1159] ngx_http_gzip_hash(ngx_conf_t *cf, void *post, void *data)
[1160] {
[1161]     size_t *np = data;
[1162] 
[1163]     size_t  memlevel, hsize;
[1164] 
[1165]     memlevel = 9;
[1166] 
[1167]     for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {
[1168] 
[1169]         if (hsize == *np) {
[1170]             *np = memlevel;
[1171] 
[1172]             return NGX_CONF_OK;
[1173]         }
[1174] 
[1175]         memlevel--;
[1176]     }
[1177] 
[1178]     return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
[1179] }
