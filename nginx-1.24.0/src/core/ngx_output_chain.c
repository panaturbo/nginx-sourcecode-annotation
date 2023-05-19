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
[13] #if 0
[14] #define NGX_SENDFILE_LIMIT  4096
[15] #endif
[16] 
[17] /*
[18]  * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
[19]  * to an application memory from a device if parameters are aligned
[20]  * to device sector boundary (512 bytes).  They fallback to usual read
[21]  * operation if the parameters are not aligned.
[22]  * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
[23]  * sector boundary, otherwise it returns EINVAL.  The sector size is
[24]  * usually 512 bytes, however, on XFS it may be 4096 bytes.
[25]  */
[26] 
[27] #define NGX_NONE            1
[28] 
[29] 
[30] static ngx_inline ngx_int_t
[31]     ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf);
[32] static ngx_int_t ngx_output_chain_add_copy(ngx_pool_t *pool,
[33]     ngx_chain_t **chain, ngx_chain_t *in);
[34] static ngx_int_t ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx,
[35]     off_t bsize);
[36] static ngx_int_t ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx,
[37]     off_t bsize);
[38] static ngx_int_t ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx);
[39] 
[40] 
[41] ngx_int_t
[42] ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in)
[43] {
[44]     off_t         bsize;
[45]     ngx_int_t     rc, last;
[46]     ngx_chain_t  *cl, *out, **last_out;
[47] 
[48]     if (ctx->in == NULL && ctx->busy == NULL
[49] #if (NGX_HAVE_FILE_AIO || NGX_THREADS)
[50]         && !ctx->aio
[51] #endif
[52]        )
[53]     {
[54]         /*
[55]          * the short path for the case when the ctx->in and ctx->busy chains
[56]          * are empty, the incoming chain is empty too or has the single buf
[57]          * that does not require the copy
[58]          */
[59] 
[60]         if (in == NULL) {
[61]             return ctx->output_filter(ctx->filter_ctx, in);
[62]         }
[63] 
[64]         if (in->next == NULL
[65] #if (NGX_SENDFILE_LIMIT)
[66]             && !(in->buf->in_file && in->buf->file_last > NGX_SENDFILE_LIMIT)
[67] #endif
[68]             && ngx_output_chain_as_is(ctx, in->buf))
[69]         {
[70]             return ctx->output_filter(ctx->filter_ctx, in);
[71]         }
[72]     }
[73] 
[74]     /* add the incoming buf to the chain ctx->in */
[75] 
[76]     if (in) {
[77]         if (ngx_output_chain_add_copy(ctx->pool, &ctx->in, in) == NGX_ERROR) {
[78]             return NGX_ERROR;
[79]         }
[80]     }
[81] 
[82]     out = NULL;
[83]     last_out = &out;
[84]     last = NGX_NONE;
[85] 
[86]     for ( ;; ) {
[87] 
[88] #if (NGX_HAVE_FILE_AIO || NGX_THREADS)
[89]         if (ctx->aio) {
[90]             return NGX_AGAIN;
[91]         }
[92] #endif
[93] 
[94]         while (ctx->in) {
[95] 
[96]             /*
[97]              * cycle while there are the ctx->in bufs
[98]              * and there are the free output bufs to copy in
[99]              */
[100] 
[101]             bsize = ngx_buf_size(ctx->in->buf);
[102] 
[103]             if (bsize == 0 && !ngx_buf_special(ctx->in->buf)) {
[104] 
[105]                 ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[106]                               "zero size buf in output "
[107]                               "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[108]                               ctx->in->buf->temporary,
[109]                               ctx->in->buf->recycled,
[110]                               ctx->in->buf->in_file,
[111]                               ctx->in->buf->start,
[112]                               ctx->in->buf->pos,
[113]                               ctx->in->buf->last,
[114]                               ctx->in->buf->file,
[115]                               ctx->in->buf->file_pos,
[116]                               ctx->in->buf->file_last);
[117] 
[118]                 ngx_debug_point();
[119] 
[120]                 ctx->in = ctx->in->next;
[121] 
[122]                 continue;
[123]             }
[124] 
[125]             if (bsize < 0) {
[126] 
[127]                 ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[128]                               "negative size buf in output "
[129]                               "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[130]                               ctx->in->buf->temporary,
[131]                               ctx->in->buf->recycled,
[132]                               ctx->in->buf->in_file,
[133]                               ctx->in->buf->start,
[134]                               ctx->in->buf->pos,
[135]                               ctx->in->buf->last,
[136]                               ctx->in->buf->file,
[137]                               ctx->in->buf->file_pos,
[138]                               ctx->in->buf->file_last);
[139] 
[140]                 ngx_debug_point();
[141] 
[142]                 return NGX_ERROR;
[143]             }
[144] 
[145]             if (ngx_output_chain_as_is(ctx, ctx->in->buf)) {
[146] 
[147]                 /* move the chain link to the output chain */
[148] 
[149]                 cl = ctx->in;
[150]                 ctx->in = cl->next;
[151] 
[152]                 *last_out = cl;
[153]                 last_out = &cl->next;
[154]                 cl->next = NULL;
[155] 
[156]                 continue;
[157]             }
[158] 
[159]             if (ctx->buf == NULL) {
[160] 
[161]                 rc = ngx_output_chain_align_file_buf(ctx, bsize);
[162] 
[163]                 if (rc == NGX_ERROR) {
[164]                     return NGX_ERROR;
[165]                 }
[166] 
[167]                 if (rc != NGX_OK) {
[168] 
[169]                     if (ctx->free) {
[170] 
[171]                         /* get the free buf */
[172] 
[173]                         cl = ctx->free;
[174]                         ctx->buf = cl->buf;
[175]                         ctx->free = cl->next;
[176] 
[177]                         ngx_free_chain(ctx->pool, cl);
[178] 
[179]                     } else if (out || ctx->allocated == ctx->bufs.num) {
[180] 
[181]                         break;
[182] 
[183]                     } else if (ngx_output_chain_get_buf(ctx, bsize) != NGX_OK) {
[184]                         return NGX_ERROR;
[185]                     }
[186]                 }
[187]             }
[188] 
[189]             rc = ngx_output_chain_copy_buf(ctx);
[190] 
[191]             if (rc == NGX_ERROR) {
[192]                 return rc;
[193]             }
[194] 
[195]             if (rc == NGX_AGAIN) {
[196]                 if (out) {
[197]                     break;
[198]                 }
[199] 
[200]                 return rc;
[201]             }
[202] 
[203]             /* delete the completed buf from the ctx->in chain */
[204] 
[205]             if (ngx_buf_size(ctx->in->buf) == 0) {
[206]                 ctx->in = ctx->in->next;
[207]             }
[208] 
[209]             cl = ngx_alloc_chain_link(ctx->pool);
[210]             if (cl == NULL) {
[211]                 return NGX_ERROR;
[212]             }
[213] 
[214]             cl->buf = ctx->buf;
[215]             cl->next = NULL;
[216]             *last_out = cl;
[217]             last_out = &cl->next;
[218]             ctx->buf = NULL;
[219]         }
[220] 
[221]         if (out == NULL && last != NGX_NONE) {
[222] 
[223]             if (ctx->in) {
[224]                 return NGX_AGAIN;
[225]             }
[226] 
[227]             return last;
[228]         }
[229] 
[230]         last = ctx->output_filter(ctx->filter_ctx, out);
[231] 
[232]         if (last == NGX_ERROR || last == NGX_DONE) {
[233]             return last;
[234]         }
[235] 
[236]         ngx_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &out,
[237]                                 ctx->tag);
[238]         last_out = &out;
[239]     }
[240] }
[241] 
[242] 
[243] static ngx_inline ngx_int_t
[244] ngx_output_chain_as_is(ngx_output_chain_ctx_t *ctx, ngx_buf_t *buf)
[245] {
[246]     ngx_uint_t  sendfile;
[247] 
[248]     if (ngx_buf_special(buf)) {
[249]         return 1;
[250]     }
[251] 
[252] #if (NGX_THREADS)
[253]     if (buf->in_file) {
[254]         buf->file->thread_handler = ctx->thread_handler;
[255]         buf->file->thread_ctx = ctx->filter_ctx;
[256]     }
[257] #endif
[258] 
[259]     sendfile = ctx->sendfile;
[260] 
[261] #if (NGX_SENDFILE_LIMIT)
[262] 
[263]     if (buf->in_file && buf->file_pos >= NGX_SENDFILE_LIMIT) {
[264]         sendfile = 0;
[265]     }
[266] 
[267] #endif
[268] 
[269] #if !(NGX_HAVE_SENDFILE_NODISKIO)
[270] 
[271]     /*
[272]      * With DIRECTIO, disable sendfile() unless sendfile(SF_NOCACHE)
[273]      * is available.
[274]      */
[275] 
[276]     if (buf->in_file && buf->file->directio) {
[277]         sendfile = 0;
[278]     }
[279] 
[280] #endif
[281] 
[282]     if (!sendfile) {
[283] 
[284]         if (!ngx_buf_in_memory(buf)) {
[285]             return 0;
[286]         }
[287] 
[288]         buf->in_file = 0;
[289]     }
[290] 
[291]     if (ctx->need_in_memory && !ngx_buf_in_memory(buf)) {
[292]         return 0;
[293]     }
[294] 
[295]     if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
[296]         return 0;
[297]     }
[298] 
[299]     return 1;
[300] }
[301] 
[302] 
[303] static ngx_int_t
[304] ngx_output_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
[305]     ngx_chain_t *in)
[306] {
[307]     ngx_chain_t  *cl, **ll;
[308] #if (NGX_SENDFILE_LIMIT)
[309]     ngx_buf_t    *b, *buf;
[310] #endif
[311] 
[312]     ll = chain;
[313] 
[314]     for (cl = *chain; cl; cl = cl->next) {
[315]         ll = &cl->next;
[316]     }
[317] 
[318]     while (in) {
[319] 
[320]         cl = ngx_alloc_chain_link(pool);
[321]         if (cl == NULL) {
[322]             return NGX_ERROR;
[323]         }
[324] 
[325] #if (NGX_SENDFILE_LIMIT)
[326] 
[327]         buf = in->buf;
[328] 
[329]         if (buf->in_file
[330]             && buf->file_pos < NGX_SENDFILE_LIMIT
[331]             && buf->file_last > NGX_SENDFILE_LIMIT)
[332]         {
[333]             /* split a file buf on two bufs by the sendfile limit */
[334] 
[335]             b = ngx_calloc_buf(pool);
[336]             if (b == NULL) {
[337]                 return NGX_ERROR;
[338]             }
[339] 
[340]             ngx_memcpy(b, buf, sizeof(ngx_buf_t));
[341] 
[342]             if (ngx_buf_in_memory(buf)) {
[343]                 buf->pos += (ssize_t) (NGX_SENDFILE_LIMIT - buf->file_pos);
[344]                 b->last = buf->pos;
[345]             }
[346] 
[347]             buf->file_pos = NGX_SENDFILE_LIMIT;
[348]             b->file_last = NGX_SENDFILE_LIMIT;
[349] 
[350]             cl->buf = b;
[351] 
[352]         } else {
[353]             cl->buf = buf;
[354]             in = in->next;
[355]         }
[356] 
[357] #else
[358]         cl->buf = in->buf;
[359]         in = in->next;
[360] 
[361] #endif
[362] 
[363]         cl->next = NULL;
[364]         *ll = cl;
[365]         ll = &cl->next;
[366]     }
[367] 
[368]     return NGX_OK;
[369] }
[370] 
[371] 
[372] static ngx_int_t
[373] ngx_output_chain_align_file_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
[374] {
[375]     size_t      size;
[376]     ngx_buf_t  *in;
[377] 
[378]     in = ctx->in->buf;
[379] 
[380]     if (in->file == NULL || !in->file->directio) {
[381]         return NGX_DECLINED;
[382]     }
[383] 
[384]     ctx->directio = 1;
[385] 
[386]     size = (size_t) (in->file_pos - (in->file_pos & ~(ctx->alignment - 1)));
[387] 
[388]     if (size == 0) {
[389] 
[390]         if (bsize >= (off_t) ctx->bufs.size) {
[391]             return NGX_DECLINED;
[392]         }
[393] 
[394]         size = (size_t) bsize;
[395] 
[396]     } else {
[397]         size = (size_t) ctx->alignment - size;
[398] 
[399]         if ((off_t) size > bsize) {
[400]             size = (size_t) bsize;
[401]         }
[402]     }
[403] 
[404]     ctx->buf = ngx_create_temp_buf(ctx->pool, size);
[405]     if (ctx->buf == NULL) {
[406]         return NGX_ERROR;
[407]     }
[408] 
[409]     /*
[410]      * we do not set ctx->buf->tag, because we do not want
[411]      * to reuse the buf via ctx->free list
[412]      */
[413] 
[414] #if (NGX_HAVE_ALIGNED_DIRECTIO)
[415]     ctx->unaligned = 1;
[416] #endif
[417] 
[418]     return NGX_OK;
[419] }
[420] 
[421] 
[422] static ngx_int_t
[423] ngx_output_chain_get_buf(ngx_output_chain_ctx_t *ctx, off_t bsize)
[424] {
[425]     size_t       size;
[426]     ngx_buf_t   *b, *in;
[427]     ngx_uint_t   recycled;
[428] 
[429]     in = ctx->in->buf;
[430]     size = ctx->bufs.size;
[431]     recycled = 1;
[432] 
[433]     if (in->last_in_chain) {
[434] 
[435]         if (bsize < (off_t) size) {
[436] 
[437]             /*
[438]              * allocate a small temp buf for a small last buf
[439]              * or its small last part
[440]              */
[441] 
[442]             size = (size_t) bsize;
[443]             recycled = 0;
[444] 
[445]         } else if (!ctx->directio
[446]                    && ctx->bufs.num == 1
[447]                    && (bsize < (off_t) (size + size / 4)))
[448]         {
[449]             /*
[450]              * allocate a temp buf that equals to a last buf,
[451]              * if there is no directio, the last buf size is lesser
[452]              * than 1.25 of bufs.size and the temp buf is single
[453]              */
[454] 
[455]             size = (size_t) bsize;
[456]             recycled = 0;
[457]         }
[458]     }
[459] 
[460]     b = ngx_calloc_buf(ctx->pool);
[461]     if (b == NULL) {
[462]         return NGX_ERROR;
[463]     }
[464] 
[465]     if (ctx->directio) {
[466] 
[467]         /*
[468]          * allocate block aligned to a disk sector size to enable
[469]          * userland buffer direct usage conjunctly with directio
[470]          */
[471] 
[472]         b->start = ngx_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
[473]         if (b->start == NULL) {
[474]             return NGX_ERROR;
[475]         }
[476] 
[477]     } else {
[478]         b->start = ngx_palloc(ctx->pool, size);
[479]         if (b->start == NULL) {
[480]             return NGX_ERROR;
[481]         }
[482]     }
[483] 
[484]     b->pos = b->start;
[485]     b->last = b->start;
[486]     b->end = b->last + size;
[487]     b->temporary = 1;
[488]     b->tag = ctx->tag;
[489]     b->recycled = recycled;
[490] 
[491]     ctx->buf = b;
[492]     ctx->allocated++;
[493] 
[494]     return NGX_OK;
[495] }
[496] 
[497] 
[498] static ngx_int_t
[499] ngx_output_chain_copy_buf(ngx_output_chain_ctx_t *ctx)
[500] {
[501]     off_t        size;
[502]     ssize_t      n;
[503]     ngx_buf_t   *src, *dst;
[504]     ngx_uint_t   sendfile;
[505] 
[506]     src = ctx->in->buf;
[507]     dst = ctx->buf;
[508] 
[509]     size = ngx_buf_size(src);
[510]     size = ngx_min(size, dst->end - dst->pos);
[511] 
[512]     sendfile = ctx->sendfile && !ctx->directio;
[513] 
[514] #if (NGX_SENDFILE_LIMIT)
[515] 
[516]     if (src->in_file && src->file_pos >= NGX_SENDFILE_LIMIT) {
[517]         sendfile = 0;
[518]     }
[519] 
[520] #endif
[521] 
[522]     if (ngx_buf_in_memory(src)) {
[523]         ngx_memcpy(dst->pos, src->pos, (size_t) size);
[524]         src->pos += (size_t) size;
[525]         dst->last += (size_t) size;
[526] 
[527]         if (src->in_file) {
[528] 
[529]             if (sendfile) {
[530]                 dst->in_file = 1;
[531]                 dst->file = src->file;
[532]                 dst->file_pos = src->file_pos;
[533]                 dst->file_last = src->file_pos + size;
[534] 
[535]             } else {
[536]                 dst->in_file = 0;
[537]             }
[538] 
[539]             src->file_pos += size;
[540] 
[541]         } else {
[542]             dst->in_file = 0;
[543]         }
[544] 
[545]         if (src->pos == src->last) {
[546]             dst->flush = src->flush;
[547]             dst->last_buf = src->last_buf;
[548]             dst->last_in_chain = src->last_in_chain;
[549]         }
[550] 
[551]     } else {
[552] 
[553] #if (NGX_HAVE_ALIGNED_DIRECTIO)
[554] 
[555]         if (ctx->unaligned) {
[556]             if (ngx_directio_off(src->file->fd) == NGX_FILE_ERROR) {
[557]                 ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
[558]                               ngx_directio_off_n " \"%s\" failed",
[559]                               src->file->name.data);
[560]             }
[561]         }
[562] 
[563] #endif
[564] 
[565] #if (NGX_HAVE_FILE_AIO)
[566]         if (ctx->aio_handler) {
[567]             n = ngx_file_aio_read(src->file, dst->pos, (size_t) size,
[568]                                   src->file_pos, ctx->pool);
[569]             if (n == NGX_AGAIN) {
[570]                 ctx->aio_handler(ctx, src->file);
[571]                 return NGX_AGAIN;
[572]             }
[573] 
[574]         } else
[575] #endif
[576] #if (NGX_THREADS)
[577]         if (ctx->thread_handler) {
[578]             src->file->thread_task = ctx->thread_task;
[579]             src->file->thread_handler = ctx->thread_handler;
[580]             src->file->thread_ctx = ctx->filter_ctx;
[581] 
[582]             n = ngx_thread_read(src->file, dst->pos, (size_t) size,
[583]                                 src->file_pos, ctx->pool);
[584]             if (n == NGX_AGAIN) {
[585]                 ctx->thread_task = src->file->thread_task;
[586]                 return NGX_AGAIN;
[587]             }
[588] 
[589]         } else
[590] #endif
[591]         {
[592]             n = ngx_read_file(src->file, dst->pos, (size_t) size,
[593]                               src->file_pos);
[594]         }
[595] 
[596] #if (NGX_HAVE_ALIGNED_DIRECTIO)
[597] 
[598]         if (ctx->unaligned) {
[599]             ngx_err_t  err;
[600] 
[601]             err = ngx_errno;
[602] 
[603]             if (ngx_directio_on(src->file->fd) == NGX_FILE_ERROR) {
[604]                 ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, ngx_errno,
[605]                               ngx_directio_on_n " \"%s\" failed",
[606]                               src->file->name.data);
[607]             }
[608] 
[609]             ngx_set_errno(err);
[610] 
[611]             ctx->unaligned = 0;
[612]         }
[613] 
[614] #endif
[615] 
[616]         if (n == NGX_ERROR) {
[617]             return (ngx_int_t) n;
[618]         }
[619] 
[620]         if (n != size) {
[621]             ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[622]                           ngx_read_file_n " read only %z of %O from \"%s\"",
[623]                           n, size, src->file->name.data);
[624]             return NGX_ERROR;
[625]         }
[626] 
[627]         dst->last += n;
[628] 
[629]         if (sendfile) {
[630]             dst->in_file = 1;
[631]             dst->file = src->file;
[632]             dst->file_pos = src->file_pos;
[633]             dst->file_last = src->file_pos + n;
[634] 
[635]         } else {
[636]             dst->in_file = 0;
[637]         }
[638] 
[639]         src->file_pos += n;
[640] 
[641]         if (src->file_pos == src->file_last) {
[642]             dst->flush = src->flush;
[643]             dst->last_buf = src->last_buf;
[644]             dst->last_in_chain = src->last_in_chain;
[645]         }
[646]     }
[647] 
[648]     return NGX_OK;
[649] }
[650] 
[651] 
[652] ngx_int_t
[653] ngx_chain_writer(void *data, ngx_chain_t *in)
[654] {
[655]     ngx_chain_writer_ctx_t *ctx = data;
[656] 
[657]     off_t              size;
[658]     ngx_chain_t       *cl, *ln, *chain;
[659]     ngx_connection_t  *c;
[660] 
[661]     c = ctx->connection;
[662] 
[663]     for (size = 0; in; in = in->next) {
[664] 
[665]         if (ngx_buf_size(in->buf) == 0 && !ngx_buf_special(in->buf)) {
[666] 
[667]             ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[668]                           "zero size buf in chain writer "
[669]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[670]                           in->buf->temporary,
[671]                           in->buf->recycled,
[672]                           in->buf->in_file,
[673]                           in->buf->start,
[674]                           in->buf->pos,
[675]                           in->buf->last,
[676]                           in->buf->file,
[677]                           in->buf->file_pos,
[678]                           in->buf->file_last);
[679] 
[680]             ngx_debug_point();
[681] 
[682]             continue;
[683]         }
[684] 
[685]         if (ngx_buf_size(in->buf) < 0) {
[686] 
[687]             ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[688]                           "negative size buf in chain writer "
[689]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[690]                           in->buf->temporary,
[691]                           in->buf->recycled,
[692]                           in->buf->in_file,
[693]                           in->buf->start,
[694]                           in->buf->pos,
[695]                           in->buf->last,
[696]                           in->buf->file,
[697]                           in->buf->file_pos,
[698]                           in->buf->file_last);
[699] 
[700]             ngx_debug_point();
[701] 
[702]             return NGX_ERROR;
[703]         }
[704] 
[705]         size += ngx_buf_size(in->buf);
[706] 
[707]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, c->log, 0,
[708]                        "chain writer buf fl:%d s:%uO",
[709]                        in->buf->flush, ngx_buf_size(in->buf));
[710] 
[711]         cl = ngx_alloc_chain_link(ctx->pool);
[712]         if (cl == NULL) {
[713]             return NGX_ERROR;
[714]         }
[715] 
[716]         cl->buf = in->buf;
[717]         cl->next = NULL;
[718]         *ctx->last = cl;
[719]         ctx->last = &cl->next;
[720]     }
[721] 
[722]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[723]                    "chain writer in: %p", ctx->out);
[724] 
[725]     for (cl = ctx->out; cl; cl = cl->next) {
[726] 
[727]         if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
[728] 
[729]             ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[730]                           "zero size buf in chain writer "
[731]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[732]                           cl->buf->temporary,
[733]                           cl->buf->recycled,
[734]                           cl->buf->in_file,
[735]                           cl->buf->start,
[736]                           cl->buf->pos,
[737]                           cl->buf->last,
[738]                           cl->buf->file,
[739]                           cl->buf->file_pos,
[740]                           cl->buf->file_last);
[741] 
[742]             ngx_debug_point();
[743] 
[744]             continue;
[745]         }
[746] 
[747]         if (ngx_buf_size(cl->buf) < 0) {
[748] 
[749]             ngx_log_error(NGX_LOG_ALERT, ctx->pool->log, 0,
[750]                           "negative size buf in chain writer "
[751]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[752]                           cl->buf->temporary,
[753]                           cl->buf->recycled,
[754]                           cl->buf->in_file,
[755]                           cl->buf->start,
[756]                           cl->buf->pos,
[757]                           cl->buf->last,
[758]                           cl->buf->file,
[759]                           cl->buf->file_pos,
[760]                           cl->buf->file_last);
[761] 
[762]             ngx_debug_point();
[763] 
[764]             return NGX_ERROR;
[765]         }
[766] 
[767]         size += ngx_buf_size(cl->buf);
[768]     }
[769] 
[770]     if (size == 0 && !c->buffered) {
[771]         return NGX_OK;
[772]     }
[773] 
[774]     chain = c->send_chain(c, ctx->out, ctx->limit);
[775] 
[776]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[777]                    "chain writer out: %p", chain);
[778] 
[779]     if (chain == NGX_CHAIN_ERROR) {
[780]         return NGX_ERROR;
[781]     }
[782] 
[783]     if (chain && c->write->ready) {
[784]         ngx_post_event(c->write, &ngx_posted_next_events);
[785]     }
[786] 
[787]     for (cl = ctx->out; cl && cl != chain; /* void */) {
[788]         ln = cl;
[789]         cl = cl->next;
[790]         ngx_free_chain(ctx->pool, ln);
[791]     }
[792] 
[793]     ctx->out = chain;
[794] 
[795]     if (ctx->out == NULL) {
[796]         ctx->last = &ctx->out;
[797] 
[798]         if (!c->buffered) {
[799]             return NGX_OK;
[800]         }
[801]     }
[802] 
[803]     return NGX_AGAIN;
[804] }
