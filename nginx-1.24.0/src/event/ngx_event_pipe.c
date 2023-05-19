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
[11] #include <ngx_event_pipe.h>
[12] 
[13] 
[14] static ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p);
[15] static ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p);
[16] 
[17] static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p);
[18] static ngx_inline void ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf);
[19] static ngx_int_t ngx_event_pipe_drain_chains(ngx_event_pipe_t *p);
[20] 
[21] 
[22] ngx_int_t
[23] ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write)
[24] {
[25]     ngx_int_t     rc;
[26]     ngx_uint_t    flags;
[27]     ngx_event_t  *rev, *wev;
[28] 
[29]     for ( ;; ) {
[30]         if (do_write) {
[31]             p->log->action = "sending to client";
[32] 
[33]             rc = ngx_event_pipe_write_to_downstream(p);
[34] 
[35]             if (rc == NGX_ABORT) {
[36]                 return NGX_ABORT;
[37]             }
[38] 
[39]             if (rc == NGX_BUSY) {
[40]                 return NGX_OK;
[41]             }
[42]         }
[43] 
[44]         p->read = 0;
[45]         p->upstream_blocked = 0;
[46] 
[47]         p->log->action = "reading upstream";
[48] 
[49]         if (ngx_event_pipe_read_upstream(p) == NGX_ABORT) {
[50]             return NGX_ABORT;
[51]         }
[52] 
[53]         if (!p->read && !p->upstream_blocked) {
[54]             break;
[55]         }
[56] 
[57]         do_write = 1;
[58]     }
[59] 
[60]     if (p->upstream->fd != (ngx_socket_t) -1) {
[61]         rev = p->upstream->read;
[62] 
[63]         flags = (rev->eof || rev->error) ? NGX_CLOSE_EVENT : 0;
[64] 
[65]         if (ngx_handle_read_event(rev, flags) != NGX_OK) {
[66]             return NGX_ABORT;
[67]         }
[68] 
[69]         if (!rev->delayed) {
[70]             if (rev->active && !rev->ready) {
[71]                 ngx_add_timer(rev, p->read_timeout);
[72] 
[73]             } else if (rev->timer_set) {
[74]                 ngx_del_timer(rev);
[75]             }
[76]         }
[77]     }
[78] 
[79]     if (p->downstream->fd != (ngx_socket_t) -1
[80]         && p->downstream->data == p->output_ctx)
[81]     {
[82]         wev = p->downstream->write;
[83]         if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
[84]             return NGX_ABORT;
[85]         }
[86] 
[87]         if (!wev->delayed) {
[88]             if (wev->active && !wev->ready) {
[89]                 ngx_add_timer(wev, p->send_timeout);
[90] 
[91]             } else if (wev->timer_set) {
[92]                 ngx_del_timer(wev);
[93]             }
[94]         }
[95]     }
[96] 
[97]     return NGX_OK;
[98] }
[99] 
[100] 
[101] static ngx_int_t
[102] ngx_event_pipe_read_upstream(ngx_event_pipe_t *p)
[103] {
[104]     off_t         limit;
[105]     ssize_t       n, size;
[106]     ngx_int_t     rc;
[107]     ngx_buf_t    *b;
[108]     ngx_msec_t    delay;
[109]     ngx_chain_t  *chain, *cl, *ln;
[110] 
[111]     if (p->upstream_eof || p->upstream_error || p->upstream_done) {
[112]         return NGX_OK;
[113]     }
[114] 
[115] #if (NGX_THREADS)
[116] 
[117]     if (p->aio) {
[118]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[119]                        "pipe read upstream: aio");
[120]         return NGX_AGAIN;
[121]     }
[122] 
[123]     if (p->writing) {
[124]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[125]                        "pipe read upstream: writing");
[126] 
[127]         rc = ngx_event_pipe_write_chain_to_temp_file(p);
[128] 
[129]         if (rc != NGX_OK) {
[130]             return rc;
[131]         }
[132]     }
[133] 
[134] #endif
[135] 
[136]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[137]                    "pipe read upstream: %d", p->upstream->read->ready);
[138] 
[139]     for ( ;; ) {
[140] 
[141]         if (p->upstream_eof || p->upstream_error || p->upstream_done) {
[142]             break;
[143]         }
[144] 
[145]         if (p->preread_bufs == NULL && !p->upstream->read->ready) {
[146]             break;
[147]         }
[148] 
[149]         if (p->preread_bufs) {
[150] 
[151]             /* use the pre-read bufs if they exist */
[152] 
[153]             chain = p->preread_bufs;
[154]             p->preread_bufs = NULL;
[155]             n = p->preread_size;
[156] 
[157]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[158]                            "pipe preread: %z", n);
[159] 
[160]             if (n) {
[161]                 p->read = 1;
[162]             }
[163] 
[164]         } else {
[165] 
[166] #if (NGX_HAVE_KQUEUE)
[167] 
[168]             /*
[169]              * kqueue notifies about the end of file or a pending error.
[170]              * This test allows not to allocate a buf on these conditions
[171]              * and not to call c->recv_chain().
[172]              */
[173] 
[174]             if (p->upstream->read->available == 0
[175]                 && p->upstream->read->pending_eof
[176] #if (NGX_SSL)
[177]                 && !p->upstream->ssl
[178] #endif
[179]                 )
[180]             {
[181]                 p->upstream->read->ready = 0;
[182]                 p->upstream->read->eof = 1;
[183]                 p->upstream_eof = 1;
[184]                 p->read = 1;
[185] 
[186]                 if (p->upstream->read->kq_errno) {
[187]                     p->upstream->read->error = 1;
[188]                     p->upstream_error = 1;
[189]                     p->upstream_eof = 0;
[190] 
[191]                     ngx_log_error(NGX_LOG_ERR, p->log,
[192]                                   p->upstream->read->kq_errno,
[193]                                   "kevent() reported that upstream "
[194]                                   "closed connection");
[195]                 }
[196] 
[197]                 break;
[198]             }
[199] #endif
[200] 
[201]             if (p->limit_rate) {
[202]                 if (p->upstream->read->delayed) {
[203]                     break;
[204]                 }
[205] 
[206]                 limit = (off_t) p->limit_rate * (ngx_time() - p->start_sec + 1)
[207]                         - p->read_length;
[208] 
[209]                 if (limit <= 0) {
[210]                     p->upstream->read->delayed = 1;
[211]                     delay = (ngx_msec_t) (- limit * 1000 / p->limit_rate + 1);
[212]                     ngx_add_timer(p->upstream->read, delay);
[213]                     break;
[214]                 }
[215] 
[216]             } else {
[217]                 limit = 0;
[218]             }
[219] 
[220]             if (p->free_raw_bufs) {
[221] 
[222]                 /* use the free bufs if they exist */
[223] 
[224]                 chain = p->free_raw_bufs;
[225]                 if (p->single_buf) {
[226]                     p->free_raw_bufs = p->free_raw_bufs->next;
[227]                     chain->next = NULL;
[228]                 } else {
[229]                     p->free_raw_bufs = NULL;
[230]                 }
[231] 
[232]             } else if (p->allocated < p->bufs.num) {
[233] 
[234]                 /* allocate a new buf if it's still allowed */
[235] 
[236]                 b = ngx_create_temp_buf(p->pool, p->bufs.size);
[237]                 if (b == NULL) {
[238]                     return NGX_ABORT;
[239]                 }
[240] 
[241]                 p->allocated++;
[242] 
[243]                 chain = ngx_alloc_chain_link(p->pool);
[244]                 if (chain == NULL) {
[245]                     return NGX_ABORT;
[246]                 }
[247] 
[248]                 chain->buf = b;
[249]                 chain->next = NULL;
[250] 
[251]             } else if (!p->cacheable
[252]                        && p->downstream->data == p->output_ctx
[253]                        && p->downstream->write->ready
[254]                        && !p->downstream->write->delayed)
[255]             {
[256]                 /*
[257]                  * if the bufs are not needed to be saved in a cache and
[258]                  * a downstream is ready then write the bufs to a downstream
[259]                  */
[260] 
[261]                 p->upstream_blocked = 1;
[262] 
[263]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[264]                                "pipe downstream ready");
[265] 
[266]                 break;
[267] 
[268]             } else if (p->cacheable
[269]                        || p->temp_file->offset < p->max_temp_file_size)
[270]             {
[271] 
[272]                 /*
[273]                  * if it is allowed, then save some bufs from p->in
[274]                  * to a temporary file, and add them to a p->out chain
[275]                  */
[276] 
[277]                 rc = ngx_event_pipe_write_chain_to_temp_file(p);
[278] 
[279]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[280]                                "pipe temp offset: %O", p->temp_file->offset);
[281] 
[282]                 if (rc == NGX_BUSY) {
[283]                     break;
[284]                 }
[285] 
[286]                 if (rc != NGX_OK) {
[287]                     return rc;
[288]                 }
[289] 
[290]                 chain = p->free_raw_bufs;
[291]                 if (p->single_buf) {
[292]                     p->free_raw_bufs = p->free_raw_bufs->next;
[293]                     chain->next = NULL;
[294]                 } else {
[295]                     p->free_raw_bufs = NULL;
[296]                 }
[297] 
[298]             } else {
[299] 
[300]                 /* there are no bufs to read in */
[301] 
[302]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[303]                                "no pipe bufs to read in");
[304] 
[305]                 break;
[306]             }
[307] 
[308]             n = p->upstream->recv_chain(p->upstream, chain, limit);
[309] 
[310]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[311]                            "pipe recv chain: %z", n);
[312] 
[313]             if (p->free_raw_bufs) {
[314]                 chain->next = p->free_raw_bufs;
[315]             }
[316]             p->free_raw_bufs = chain;
[317] 
[318]             if (n == NGX_ERROR) {
[319]                 p->upstream_error = 1;
[320]                 break;
[321]             }
[322] 
[323]             if (n == NGX_AGAIN) {
[324]                 if (p->single_buf) {
[325]                     ngx_event_pipe_remove_shadow_links(chain->buf);
[326]                 }
[327] 
[328]                 break;
[329]             }
[330] 
[331]             p->read = 1;
[332] 
[333]             if (n == 0) {
[334]                 p->upstream_eof = 1;
[335]                 break;
[336]             }
[337]         }
[338] 
[339]         delay = p->limit_rate ? (ngx_msec_t) n * 1000 / p->limit_rate : 0;
[340] 
[341]         p->read_length += n;
[342]         cl = chain;
[343]         p->free_raw_bufs = NULL;
[344] 
[345]         while (cl && n > 0) {
[346] 
[347]             ngx_event_pipe_remove_shadow_links(cl->buf);
[348] 
[349]             size = cl->buf->end - cl->buf->last;
[350] 
[351]             if (n >= size) {
[352]                 cl->buf->last = cl->buf->end;
[353] 
[354]                 /* STUB */ cl->buf->num = p->num++;
[355] 
[356]                 if (p->input_filter(p, cl->buf) == NGX_ERROR) {
[357]                     return NGX_ABORT;
[358]                 }
[359] 
[360]                 n -= size;
[361]                 ln = cl;
[362]                 cl = cl->next;
[363]                 ngx_free_chain(p->pool, ln);
[364] 
[365]             } else {
[366]                 cl->buf->last += n;
[367]                 n = 0;
[368]             }
[369]         }
[370] 
[371]         if (cl) {
[372]             for (ln = cl; ln->next; ln = ln->next) { /* void */ }
[373] 
[374]             ln->next = p->free_raw_bufs;
[375]             p->free_raw_bufs = cl;
[376]         }
[377] 
[378]         if (delay > 0) {
[379]             p->upstream->read->delayed = 1;
[380]             ngx_add_timer(p->upstream->read, delay);
[381]             break;
[382]         }
[383]     }
[384] 
[385] #if (NGX_DEBUG)
[386] 
[387]     for (cl = p->busy; cl; cl = cl->next) {
[388]         ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
[389]                        "pipe buf busy s:%d t:%d f:%d "
[390]                        "%p, pos %p, size: %z "
[391]                        "file: %O, size: %O",
[392]                        (cl->buf->shadow ? 1 : 0),
[393]                        cl->buf->temporary, cl->buf->in_file,
[394]                        cl->buf->start, cl->buf->pos,
[395]                        cl->buf->last - cl->buf->pos,
[396]                        cl->buf->file_pos,
[397]                        cl->buf->file_last - cl->buf->file_pos);
[398]     }
[399] 
[400]     for (cl = p->out; cl; cl = cl->next) {
[401]         ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
[402]                        "pipe buf out  s:%d t:%d f:%d "
[403]                        "%p, pos %p, size: %z "
[404]                        "file: %O, size: %O",
[405]                        (cl->buf->shadow ? 1 : 0),
[406]                        cl->buf->temporary, cl->buf->in_file,
[407]                        cl->buf->start, cl->buf->pos,
[408]                        cl->buf->last - cl->buf->pos,
[409]                        cl->buf->file_pos,
[410]                        cl->buf->file_last - cl->buf->file_pos);
[411]     }
[412] 
[413]     for (cl = p->in; cl; cl = cl->next) {
[414]         ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
[415]                        "pipe buf in   s:%d t:%d f:%d "
[416]                        "%p, pos %p, size: %z "
[417]                        "file: %O, size: %O",
[418]                        (cl->buf->shadow ? 1 : 0),
[419]                        cl->buf->temporary, cl->buf->in_file,
[420]                        cl->buf->start, cl->buf->pos,
[421]                        cl->buf->last - cl->buf->pos,
[422]                        cl->buf->file_pos,
[423]                        cl->buf->file_last - cl->buf->file_pos);
[424]     }
[425] 
[426]     for (cl = p->free_raw_bufs; cl; cl = cl->next) {
[427]         ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
[428]                        "pipe buf free s:%d t:%d f:%d "
[429]                        "%p, pos %p, size: %z "
[430]                        "file: %O, size: %O",
[431]                        (cl->buf->shadow ? 1 : 0),
[432]                        cl->buf->temporary, cl->buf->in_file,
[433]                        cl->buf->start, cl->buf->pos,
[434]                        cl->buf->last - cl->buf->pos,
[435]                        cl->buf->file_pos,
[436]                        cl->buf->file_last - cl->buf->file_pos);
[437]     }
[438] 
[439]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[440]                    "pipe length: %O", p->length);
[441] 
[442] #endif
[443] 
[444]     if (p->free_raw_bufs && p->length != -1) {
[445]         cl = p->free_raw_bufs;
[446] 
[447]         if (cl->buf->last - cl->buf->pos >= p->length) {
[448] 
[449]             p->free_raw_bufs = cl->next;
[450] 
[451]             /* STUB */ cl->buf->num = p->num++;
[452] 
[453]             if (p->input_filter(p, cl->buf) == NGX_ERROR) {
[454]                 return NGX_ABORT;
[455]             }
[456] 
[457]             ngx_free_chain(p->pool, cl);
[458]         }
[459]     }
[460] 
[461]     if (p->length == 0) {
[462]         p->upstream_done = 1;
[463]         p->read = 1;
[464]     }
[465] 
[466]     if ((p->upstream_eof || p->upstream_error) && p->free_raw_bufs) {
[467] 
[468]         /* STUB */ p->free_raw_bufs->buf->num = p->num++;
[469] 
[470]         if (p->input_filter(p, p->free_raw_bufs->buf) == NGX_ERROR) {
[471]             return NGX_ABORT;
[472]         }
[473] 
[474]         p->free_raw_bufs = p->free_raw_bufs->next;
[475] 
[476]         if (p->free_bufs && p->buf_to_file == NULL) {
[477]             for (cl = p->free_raw_bufs; cl; cl = cl->next) {
[478]                 if (cl->buf->shadow == NULL) {
[479]                     ngx_pfree(p->pool, cl->buf->start);
[480]                 }
[481]             }
[482]         }
[483]     }
[484] 
[485]     if (p->cacheable && (p->in || p->buf_to_file)) {
[486] 
[487]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[488]                        "pipe write chain");
[489] 
[490]         rc = ngx_event_pipe_write_chain_to_temp_file(p);
[491] 
[492]         if (rc != NGX_OK) {
[493]             return rc;
[494]         }
[495]     }
[496] 
[497]     return NGX_OK;
[498] }
[499] 
[500] 
[501] static ngx_int_t
[502] ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
[503] {
[504]     u_char            *prev;
[505]     size_t             bsize;
[506]     ngx_int_t          rc;
[507]     ngx_uint_t         flush, flushed, prev_last_shadow;
[508]     ngx_chain_t       *out, **ll, *cl;
[509]     ngx_connection_t  *downstream;
[510] 
[511]     downstream = p->downstream;
[512] 
[513]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[514]                    "pipe write downstream: %d", downstream->write->ready);
[515] 
[516] #if (NGX_THREADS)
[517] 
[518]     if (p->writing) {
[519]         rc = ngx_event_pipe_write_chain_to_temp_file(p);
[520] 
[521]         if (rc == NGX_ABORT) {
[522]             return NGX_ABORT;
[523]         }
[524]     }
[525] 
[526] #endif
[527] 
[528]     flushed = 0;
[529] 
[530]     for ( ;; ) {
[531]         if (p->downstream_error) {
[532]             return ngx_event_pipe_drain_chains(p);
[533]         }
[534] 
[535]         if (p->upstream_eof || p->upstream_error || p->upstream_done) {
[536] 
[537]             /* pass the p->out and p->in chains to the output filter */
[538] 
[539]             for (cl = p->busy; cl; cl = cl->next) {
[540]                 cl->buf->recycled = 0;
[541]             }
[542] 
[543]             if (p->out) {
[544]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[545]                                "pipe write downstream flush out");
[546] 
[547]                 for (cl = p->out; cl; cl = cl->next) {
[548]                     cl->buf->recycled = 0;
[549]                 }
[550] 
[551]                 rc = p->output_filter(p->output_ctx, p->out);
[552] 
[553]                 if (rc == NGX_ERROR) {
[554]                     p->downstream_error = 1;
[555]                     return ngx_event_pipe_drain_chains(p);
[556]                 }
[557] 
[558]                 p->out = NULL;
[559]             }
[560] 
[561]             if (p->writing) {
[562]                 break;
[563]             }
[564] 
[565]             if (p->in) {
[566]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[567]                                "pipe write downstream flush in");
[568] 
[569]                 for (cl = p->in; cl; cl = cl->next) {
[570]                     cl->buf->recycled = 0;
[571]                 }
[572] 
[573]                 rc = p->output_filter(p->output_ctx, p->in);
[574] 
[575]                 if (rc == NGX_ERROR) {
[576]                     p->downstream_error = 1;
[577]                     return ngx_event_pipe_drain_chains(p);
[578]                 }
[579] 
[580]                 p->in = NULL;
[581]             }
[582] 
[583]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[584]                            "pipe write downstream done");
[585] 
[586]             /* TODO: free unused bufs */
[587] 
[588]             p->downstream_done = 1;
[589]             break;
[590]         }
[591] 
[592]         if (downstream->data != p->output_ctx
[593]             || !downstream->write->ready
[594]             || downstream->write->delayed)
[595]         {
[596]             break;
[597]         }
[598] 
[599]         /* bsize is the size of the busy recycled bufs */
[600] 
[601]         prev = NULL;
[602]         bsize = 0;
[603] 
[604]         for (cl = p->busy; cl; cl = cl->next) {
[605] 
[606]             if (cl->buf->recycled) {
[607]                 if (prev == cl->buf->start) {
[608]                     continue;
[609]                 }
[610] 
[611]                 bsize += cl->buf->end - cl->buf->start;
[612]                 prev = cl->buf->start;
[613]             }
[614]         }
[615] 
[616]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[617]                        "pipe write busy: %uz", bsize);
[618] 
[619]         out = NULL;
[620] 
[621]         if (bsize >= (size_t) p->busy_size) {
[622]             flush = 1;
[623]             goto flush;
[624]         }
[625] 
[626]         flush = 0;
[627]         ll = NULL;
[628]         prev_last_shadow = 1;
[629] 
[630]         for ( ;; ) {
[631]             if (p->out) {
[632]                 cl = p->out;
[633] 
[634]                 if (cl->buf->recycled) {
[635]                     ngx_log_error(NGX_LOG_ALERT, p->log, 0,
[636]                                   "recycled buffer in pipe out chain");
[637]                 }
[638] 
[639]                 p->out = p->out->next;
[640] 
[641]             } else if (!p->cacheable && !p->writing && p->in) {
[642]                 cl = p->in;
[643] 
[644]                 ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
[645]                                "pipe write buf ls:%d %p %z",
[646]                                cl->buf->last_shadow,
[647]                                cl->buf->pos,
[648]                                cl->buf->last - cl->buf->pos);
[649] 
[650]                 if (cl->buf->recycled && prev_last_shadow) {
[651]                     if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
[652]                         flush = 1;
[653]                         break;
[654]                     }
[655] 
[656]                     bsize += cl->buf->end - cl->buf->start;
[657]                 }
[658] 
[659]                 prev_last_shadow = cl->buf->last_shadow;
[660] 
[661]                 p->in = p->in->next;
[662] 
[663]             } else {
[664]                 break;
[665]             }
[666] 
[667]             cl->next = NULL;
[668] 
[669]             if (out) {
[670]                 *ll = cl;
[671]             } else {
[672]                 out = cl;
[673]             }
[674]             ll = &cl->next;
[675]         }
[676] 
[677]     flush:
[678] 
[679]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
[680]                        "pipe write: out:%p, f:%ui", out, flush);
[681] 
[682]         if (out == NULL) {
[683] 
[684]             if (!flush) {
[685]                 break;
[686]             }
[687] 
[688]             /* a workaround for AIO */
[689]             if (flushed++ > 10) {
[690]                 return NGX_BUSY;
[691]             }
[692]         }
[693] 
[694]         rc = p->output_filter(p->output_ctx, out);
[695] 
[696]         ngx_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);
[697] 
[698]         if (rc == NGX_ERROR) {
[699]             p->downstream_error = 1;
[700]             return ngx_event_pipe_drain_chains(p);
[701]         }
[702] 
[703]         for (cl = p->free; cl; cl = cl->next) {
[704] 
[705]             if (cl->buf->temp_file) {
[706]                 if (p->cacheable || !p->cyclic_temp_file) {
[707]                     continue;
[708]                 }
[709] 
[710]                 /* reset p->temp_offset if all bufs had been sent */
[711] 
[712]                 if (cl->buf->file_last == p->temp_file->offset) {
[713]                     p->temp_file->offset = 0;
[714]                 }
[715]             }
[716] 
[717]             /* TODO: free buf if p->free_bufs && upstream done */
[718] 
[719]             /* add the free shadow raw buf to p->free_raw_bufs */
[720] 
[721]             if (cl->buf->last_shadow) {
[722]                 if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
[723]                     return NGX_ABORT;
[724]                 }
[725] 
[726]                 cl->buf->last_shadow = 0;
[727]             }
[728] 
[729]             cl->buf->shadow = NULL;
[730]         }
[731]     }
[732] 
[733]     return NGX_OK;
[734] }
[735] 
[736] 
[737] static ngx_int_t
[738] ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
[739] {
[740]     ssize_t       size, bsize, n;
[741]     ngx_buf_t    *b;
[742]     ngx_uint_t    prev_last_shadow;
[743]     ngx_chain_t  *cl, *tl, *next, *out, **ll, **last_out, **last_free;
[744] 
[745] #if (NGX_THREADS)
[746] 
[747]     if (p->writing) {
[748] 
[749]         if (p->aio) {
[750]             return NGX_AGAIN;
[751]         }
[752] 
[753]         out = p->writing;
[754]         p->writing = NULL;
[755] 
[756]         n = ngx_write_chain_to_temp_file(p->temp_file, NULL);
[757] 
[758]         if (n == NGX_ERROR) {
[759]             return NGX_ABORT;
[760]         }
[761] 
[762]         goto done;
[763]     }
[764] 
[765] #endif
[766] 
[767]     if (p->buf_to_file) {
[768]         out = ngx_alloc_chain_link(p->pool);
[769]         if (out == NULL) {
[770]             return NGX_ABORT;
[771]         }
[772] 
[773]         out->buf = p->buf_to_file;
[774]         out->next = p->in;
[775] 
[776]     } else {
[777]         out = p->in;
[778]     }
[779] 
[780]     if (!p->cacheable) {
[781] 
[782]         size = 0;
[783]         cl = out;
[784]         ll = NULL;
[785]         prev_last_shadow = 1;
[786] 
[787]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
[788]                        "pipe offset: %O", p->temp_file->offset);
[789] 
[790]         do {
[791]             bsize = cl->buf->last - cl->buf->pos;
[792] 
[793]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, p->log, 0,
[794]                            "pipe buf ls:%d %p, pos %p, size: %z",
[795]                            cl->buf->last_shadow, cl->buf->start,
[796]                            cl->buf->pos, bsize);
[797] 
[798]             if (prev_last_shadow
[799]                 && ((size + bsize > p->temp_file_write_size)
[800]                     || (p->temp_file->offset + size + bsize
[801]                         > p->max_temp_file_size)))
[802]             {
[803]                 break;
[804]             }
[805] 
[806]             prev_last_shadow = cl->buf->last_shadow;
[807] 
[808]             size += bsize;
[809]             ll = &cl->next;
[810]             cl = cl->next;
[811] 
[812]         } while (cl);
[813] 
[814]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);
[815] 
[816]         if (ll == NULL) {
[817]             return NGX_BUSY;
[818]         }
[819] 
[820]         if (cl) {
[821]             p->in = cl;
[822]             *ll = NULL;
[823] 
[824]         } else {
[825]             p->in = NULL;
[826]             p->last_in = &p->in;
[827]         }
[828] 
[829]     } else {
[830]         p->in = NULL;
[831]         p->last_in = &p->in;
[832]     }
[833] 
[834] #if (NGX_THREADS)
[835]     if (p->thread_handler) {
[836]         p->temp_file->thread_write = 1;
[837]         p->temp_file->file.thread_task = p->thread_task;
[838]         p->temp_file->file.thread_handler = p->thread_handler;
[839]         p->temp_file->file.thread_ctx = p->thread_ctx;
[840]     }
[841] #endif
[842] 
[843]     n = ngx_write_chain_to_temp_file(p->temp_file, out);
[844] 
[845]     if (n == NGX_ERROR) {
[846]         return NGX_ABORT;
[847]     }
[848] 
[849] #if (NGX_THREADS)
[850] 
[851]     if (n == NGX_AGAIN) {
[852]         p->writing = out;
[853]         p->thread_task = p->temp_file->file.thread_task;
[854]         return NGX_AGAIN;
[855]     }
[856] 
[857] done:
[858] 
[859] #endif
[860] 
[861]     if (p->buf_to_file) {
[862]         p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
[863]         n -= p->buf_to_file->last - p->buf_to_file->pos;
[864]         p->buf_to_file = NULL;
[865]         out = out->next;
[866]     }
[867] 
[868]     if (n > 0) {
[869]         /* update previous buffer or add new buffer */
[870] 
[871]         if (p->out) {
[872]             for (cl = p->out; cl->next; cl = cl->next) { /* void */ }
[873] 
[874]             b = cl->buf;
[875] 
[876]             if (b->file_last == p->temp_file->offset) {
[877]                 p->temp_file->offset += n;
[878]                 b->file_last = p->temp_file->offset;
[879]                 goto free;
[880]             }
[881] 
[882]             last_out = &cl->next;
[883] 
[884]         } else {
[885]             last_out = &p->out;
[886]         }
[887] 
[888]         cl = ngx_chain_get_free_buf(p->pool, &p->free);
[889]         if (cl == NULL) {
[890]             return NGX_ABORT;
[891]         }
[892] 
[893]         b = cl->buf;
[894] 
[895]         ngx_memzero(b, sizeof(ngx_buf_t));
[896] 
[897]         b->tag = p->tag;
[898] 
[899]         b->file = &p->temp_file->file;
[900]         b->file_pos = p->temp_file->offset;
[901]         p->temp_file->offset += n;
[902]         b->file_last = p->temp_file->offset;
[903] 
[904]         b->in_file = 1;
[905]         b->temp_file = 1;
[906] 
[907]         *last_out = cl;
[908]     }
[909] 
[910] free:
[911] 
[912]     for (last_free = &p->free_raw_bufs;
[913]          *last_free != NULL;
[914]          last_free = &(*last_free)->next)
[915]     {
[916]         /* void */
[917]     }
[918] 
[919]     for (cl = out; cl; cl = next) {
[920]         next = cl->next;
[921] 
[922]         cl->next = p->free;
[923]         p->free = cl;
[924] 
[925]         b = cl->buf;
[926] 
[927]         if (b->last_shadow) {
[928] 
[929]             tl = ngx_alloc_chain_link(p->pool);
[930]             if (tl == NULL) {
[931]                 return NGX_ABORT;
[932]             }
[933] 
[934]             tl->buf = b->shadow;
[935]             tl->next = NULL;
[936] 
[937]             *last_free = tl;
[938]             last_free = &tl->next;
[939] 
[940]             b->shadow->pos = b->shadow->start;
[941]             b->shadow->last = b->shadow->start;
[942] 
[943]             ngx_event_pipe_remove_shadow_links(b->shadow);
[944]         }
[945]     }
[946] 
[947]     return NGX_OK;
[948] }
[949] 
[950] 
[951] /* the copy input filter */
[952] 
[953] ngx_int_t
[954] ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
[955] {
[956]     ngx_buf_t    *b;
[957]     ngx_chain_t  *cl;
[958] 
[959]     if (buf->pos == buf->last) {
[960]         return NGX_OK;
[961]     }
[962] 
[963]     if (p->upstream_done) {
[964]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
[965]                        "input data after close");
[966]         return NGX_OK;
[967]     }
[968] 
[969]     if (p->length == 0) {
[970]         p->upstream_done = 1;
[971] 
[972]         ngx_log_error(NGX_LOG_WARN, p->log, 0,
[973]                       "upstream sent more data than specified in "
[974]                       "\"Content-Length\" header");
[975] 
[976]         return NGX_OK;
[977]     }
[978] 
[979]     cl = ngx_chain_get_free_buf(p->pool, &p->free);
[980]     if (cl == NULL) {
[981]         return NGX_ERROR;
[982]     }
[983] 
[984]     b = cl->buf;
[985] 
[986]     ngx_memcpy(b, buf, sizeof(ngx_buf_t));
[987]     b->shadow = buf;
[988]     b->tag = p->tag;
[989]     b->last_shadow = 1;
[990]     b->recycled = 1;
[991]     buf->shadow = b;
[992] 
[993]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);
[994] 
[995]     if (p->in) {
[996]         *p->last_in = cl;
[997]     } else {
[998]         p->in = cl;
[999]     }
[1000]     p->last_in = &cl->next;
[1001] 
[1002]     if (p->length == -1) {
[1003]         return NGX_OK;
[1004]     }
[1005] 
[1006]     if (b->last - b->pos > p->length) {
[1007] 
[1008]         ngx_log_error(NGX_LOG_WARN, p->log, 0,
[1009]                       "upstream sent more data than specified in "
[1010]                       "\"Content-Length\" header");
[1011] 
[1012]         b->last = b->pos + p->length;
[1013]         p->upstream_done = 1;
[1014] 
[1015]         return NGX_OK;
[1016]     }
[1017] 
[1018]     p->length -= b->last - b->pos;
[1019] 
[1020]     return NGX_OK;
[1021] }
[1022] 
[1023] 
[1024] static ngx_inline void
[1025] ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf)
[1026] {
[1027]     ngx_buf_t  *b, *next;
[1028] 
[1029]     b = buf->shadow;
[1030] 
[1031]     if (b == NULL) {
[1032]         return;
[1033]     }
[1034] 
[1035]     while (!b->last_shadow) {
[1036]         next = b->shadow;
[1037] 
[1038]         b->temporary = 0;
[1039]         b->recycled = 0;
[1040] 
[1041]         b->shadow = NULL;
[1042]         b = next;
[1043]     }
[1044] 
[1045]     b->temporary = 0;
[1046]     b->recycled = 0;
[1047]     b->last_shadow = 0;
[1048] 
[1049]     b->shadow = NULL;
[1050] 
[1051]     buf->shadow = NULL;
[1052] }
[1053] 
[1054] 
[1055] ngx_int_t
[1056] ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b)
[1057] {
[1058]     ngx_chain_t  *cl;
[1059] 
[1060]     cl = ngx_alloc_chain_link(p->pool);
[1061]     if (cl == NULL) {
[1062]         return NGX_ERROR;
[1063]     }
[1064] 
[1065]     if (p->buf_to_file && b->start == p->buf_to_file->start) {
[1066]         b->pos = p->buf_to_file->last;
[1067]         b->last = p->buf_to_file->last;
[1068] 
[1069]     } else {
[1070]         b->pos = b->start;
[1071]         b->last = b->start;
[1072]     }
[1073] 
[1074]     b->shadow = NULL;
[1075] 
[1076]     cl->buf = b;
[1077] 
[1078]     if (p->free_raw_bufs == NULL) {
[1079]         p->free_raw_bufs = cl;
[1080]         cl->next = NULL;
[1081] 
[1082]         return NGX_OK;
[1083]     }
[1084] 
[1085]     if (p->free_raw_bufs->buf->pos == p->free_raw_bufs->buf->last) {
[1086] 
[1087]         /* add the free buf to the list start */
[1088] 
[1089]         cl->next = p->free_raw_bufs;
[1090]         p->free_raw_bufs = cl;
[1091] 
[1092]         return NGX_OK;
[1093]     }
[1094] 
[1095]     /* the first free buf is partially filled, thus add the free buf after it */
[1096] 
[1097]     cl->next = p->free_raw_bufs->next;
[1098]     p->free_raw_bufs->next = cl;
[1099] 
[1100]     return NGX_OK;
[1101] }
[1102] 
[1103] 
[1104] static ngx_int_t
[1105] ngx_event_pipe_drain_chains(ngx_event_pipe_t *p)
[1106] {
[1107]     ngx_chain_t  *cl, *tl;
[1108] 
[1109]     for ( ;; ) {
[1110]         if (p->busy) {
[1111]             cl = p->busy;
[1112]             p->busy = NULL;
[1113] 
[1114]         } else if (p->out) {
[1115]             cl = p->out;
[1116]             p->out = NULL;
[1117] 
[1118]         } else if (p->in) {
[1119]             cl = p->in;
[1120]             p->in = NULL;
[1121] 
[1122]         } else {
[1123]             return NGX_OK;
[1124]         }
[1125] 
[1126]         while (cl) {
[1127]             if (cl->buf->last_shadow) {
[1128]                 if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
[1129]                     return NGX_ABORT;
[1130]                 }
[1131] 
[1132]                 cl->buf->last_shadow = 0;
[1133]             }
[1134] 
[1135]             cl->buf->shadow = NULL;
[1136]             tl = cl->next;
[1137]             cl->next = p->free;
[1138]             p->free = cl;
[1139]             cl = tl;
[1140]         }
[1141]     }
[1142] }
