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
[13] static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
[14] static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
[15] static ngx_int_t ngx_http_copy_pipelined_header(ngx_http_request_t *r,
[16]     ngx_buf_t *buf);
[17] static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);
[18] static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
[19] static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r,
[20]     ngx_buf_t *b);
[21] static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);
[22] 
[23] static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r,
[24]     ngx_chain_t *in);
[25] static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r,
[26]     ngx_chain_t *in);
[27] static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r,
[28]     ngx_chain_t *in);
[29] 
[30] 
[31] ngx_int_t
[32] ngx_http_read_client_request_body(ngx_http_request_t *r,
[33]     ngx_http_client_body_handler_pt post_handler)
[34] {
[35]     size_t                     preread;
[36]     ssize_t                    size;
[37]     ngx_int_t                  rc;
[38]     ngx_buf_t                 *b;
[39]     ngx_chain_t                out;
[40]     ngx_http_request_body_t   *rb;
[41]     ngx_http_core_loc_conf_t  *clcf;
[42] 
[43]     r->main->count++;
[44] 
[45]     if (r != r->main || r->request_body || r->discard_body) {
[46]         r->request_body_no_buffering = 0;
[47]         post_handler(r);
[48]         return NGX_OK;
[49]     }
[50] 
[51]     if (ngx_http_test_expect(r) != NGX_OK) {
[52]         rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[53]         goto done;
[54]     }
[55] 
[56]     rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
[57]     if (rb == NULL) {
[58]         rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[59]         goto done;
[60]     }
[61] 
[62]     /*
[63]      * set by ngx_pcalloc():
[64]      *
[65]      *     rb->temp_file = NULL;
[66]      *     rb->bufs = NULL;
[67]      *     rb->buf = NULL;
[68]      *     rb->free = NULL;
[69]      *     rb->busy = NULL;
[70]      *     rb->chunked = NULL;
[71]      *     rb->received = 0;
[72]      *     rb->filter_need_buffering = 0;
[73]      *     rb->last_sent = 0;
[74]      *     rb->last_saved = 0;
[75]      */
[76] 
[77]     rb->rest = -1;
[78]     rb->post_handler = post_handler;
[79] 
[80]     r->request_body = rb;
[81] 
[82]     if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
[83]         r->request_body_no_buffering = 0;
[84]         post_handler(r);
[85]         return NGX_OK;
[86]     }
[87] 
[88] #if (NGX_HTTP_V2)
[89]     if (r->stream) {
[90]         rc = ngx_http_v2_read_request_body(r);
[91]         goto done;
[92]     }
[93] #endif
[94] 
[95]     preread = r->header_in->last - r->header_in->pos;
[96] 
[97]     if (preread) {
[98] 
[99]         /* there is the pre-read part of the request body */
[100] 
[101]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[102]                        "http client request body preread %uz", preread);
[103] 
[104]         out.buf = r->header_in;
[105]         out.next = NULL;
[106] 
[107]         rc = ngx_http_request_body_filter(r, &out);
[108] 
[109]         if (rc != NGX_OK) {
[110]             goto done;
[111]         }
[112] 
[113]         r->request_length += preread - (r->header_in->last - r->header_in->pos);
[114] 
[115]         if (!r->headers_in.chunked
[116]             && rb->rest > 0
[117]             && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
[118]         {
[119]             /* the whole request body may be placed in r->header_in */
[120] 
[121]             b = ngx_calloc_buf(r->pool);
[122]             if (b == NULL) {
[123]                 rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[124]                 goto done;
[125]             }
[126] 
[127]             b->temporary = 1;
[128]             b->start = r->header_in->pos;
[129]             b->pos = r->header_in->pos;
[130]             b->last = r->header_in->last;
[131]             b->end = r->header_in->end;
[132] 
[133]             rb->buf = b;
[134] 
[135]             r->read_event_handler = ngx_http_read_client_request_body_handler;
[136]             r->write_event_handler = ngx_http_request_empty_handler;
[137] 
[138]             rc = ngx_http_do_read_client_request_body(r);
[139]             goto done;
[140]         }
[141] 
[142]     } else {
[143]         /* set rb->rest */
[144] 
[145]         rc = ngx_http_request_body_filter(r, NULL);
[146] 
[147]         if (rc != NGX_OK) {
[148]             goto done;
[149]         }
[150]     }
[151] 
[152]     if (rb->rest == 0 && rb->last_saved) {
[153]         /* the whole request body was pre-read */
[154]         r->request_body_no_buffering = 0;
[155]         post_handler(r);
[156]         return NGX_OK;
[157]     }
[158] 
[159]     if (rb->rest < 0) {
[160]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[161]                       "negative request body rest");
[162]         rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[163]         goto done;
[164]     }
[165] 
[166]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[167] 
[168]     size = clcf->client_body_buffer_size;
[169]     size += size >> 2;
[170] 
[171]     /* TODO: honor r->request_body_in_single_buf */
[172] 
[173]     if (!r->headers_in.chunked && rb->rest < size) {
[174]         size = (ssize_t) rb->rest;
[175] 
[176]         if (r->request_body_in_single_buf) {
[177]             size += preread;
[178]         }
[179] 
[180]         if (size == 0) {
[181]             size++;
[182]         }
[183] 
[184]     } else {
[185]         size = clcf->client_body_buffer_size;
[186]     }
[187] 
[188]     rb->buf = ngx_create_temp_buf(r->pool, size);
[189]     if (rb->buf == NULL) {
[190]         rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[191]         goto done;
[192]     }
[193] 
[194]     r->read_event_handler = ngx_http_read_client_request_body_handler;
[195]     r->write_event_handler = ngx_http_request_empty_handler;
[196] 
[197]     rc = ngx_http_do_read_client_request_body(r);
[198] 
[199] done:
[200] 
[201]     if (r->request_body_no_buffering
[202]         && (rc == NGX_OK || rc == NGX_AGAIN))
[203]     {
[204]         if (rc == NGX_OK) {
[205]             r->request_body_no_buffering = 0;
[206] 
[207]         } else {
[208]             /* rc == NGX_AGAIN */
[209]             r->reading_body = 1;
[210]         }
[211] 
[212]         r->read_event_handler = ngx_http_block_reading;
[213]         post_handler(r);
[214]     }
[215] 
[216]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[217]         r->main->count--;
[218]     }
[219] 
[220]     return rc;
[221] }
[222] 
[223] 
[224] ngx_int_t
[225] ngx_http_read_unbuffered_request_body(ngx_http_request_t *r)
[226] {
[227]     ngx_int_t  rc;
[228] 
[229] #if (NGX_HTTP_V2)
[230]     if (r->stream) {
[231]         rc = ngx_http_v2_read_unbuffered_request_body(r);
[232] 
[233]         if (rc == NGX_OK) {
[234]             r->reading_body = 0;
[235]         }
[236] 
[237]         return rc;
[238]     }
[239] #endif
[240] 
[241]     if (r->connection->read->timedout) {
[242]         r->connection->timedout = 1;
[243]         return NGX_HTTP_REQUEST_TIME_OUT;
[244]     }
[245] 
[246]     rc = ngx_http_do_read_client_request_body(r);
[247] 
[248]     if (rc == NGX_OK) {
[249]         r->reading_body = 0;
[250]     }
[251] 
[252]     return rc;
[253] }
[254] 
[255] 
[256] static void
[257] ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
[258] {
[259]     ngx_int_t  rc;
[260] 
[261]     if (r->connection->read->timedout) {
[262]         r->connection->timedout = 1;
[263]         ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
[264]         return;
[265]     }
[266] 
[267]     rc = ngx_http_do_read_client_request_body(r);
[268] 
[269]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[270]         ngx_http_finalize_request(r, rc);
[271]     }
[272] }
[273] 
[274] 
[275] static ngx_int_t
[276] ngx_http_do_read_client_request_body(ngx_http_request_t *r)
[277] {
[278]     off_t                      rest;
[279]     size_t                     size;
[280]     ssize_t                    n;
[281]     ngx_int_t                  rc;
[282]     ngx_uint_t                 flush;
[283]     ngx_chain_t                out;
[284]     ngx_connection_t          *c;
[285]     ngx_http_request_body_t   *rb;
[286]     ngx_http_core_loc_conf_t  *clcf;
[287] 
[288]     c = r->connection;
[289]     rb = r->request_body;
[290]     flush = 1;
[291] 
[292]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[293]                    "http read client request body");
[294] 
[295]     for ( ;; ) {
[296]         for ( ;; ) {
[297]             if (rb->rest == 0) {
[298]                 break;
[299]             }
[300] 
[301]             if (rb->buf->last == rb->buf->end) {
[302] 
[303]                 /* update chains */
[304] 
[305]                 rc = ngx_http_request_body_filter(r, NULL);
[306] 
[307]                 if (rc != NGX_OK) {
[308]                     return rc;
[309]                 }
[310] 
[311]                 if (rb->busy != NULL) {
[312]                     if (r->request_body_no_buffering) {
[313]                         if (c->read->timer_set) {
[314]                             ngx_del_timer(c->read);
[315]                         }
[316] 
[317]                         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[318]                             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[319]                         }
[320] 
[321]                         return NGX_AGAIN;
[322]                     }
[323] 
[324]                     if (rb->filter_need_buffering) {
[325]                         clcf = ngx_http_get_module_loc_conf(r,
[326]                                                          ngx_http_core_module);
[327]                         ngx_add_timer(c->read, clcf->client_body_timeout);
[328] 
[329]                         if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[330]                             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[331]                         }
[332] 
[333]                         return NGX_AGAIN;
[334]                     }
[335] 
[336]                     ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[337]                                   "busy buffers after request body flush");
[338] 
[339]                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[340]                 }
[341] 
[342]                 flush = 0;
[343]                 rb->buf->pos = rb->buf->start;
[344]                 rb->buf->last = rb->buf->start;
[345]             }
[346] 
[347]             size = rb->buf->end - rb->buf->last;
[348]             rest = rb->rest - (rb->buf->last - rb->buf->pos);
[349] 
[350]             if ((off_t) size > rest) {
[351]                 size = (size_t) rest;
[352]             }
[353] 
[354]             if (size == 0) {
[355]                 break;
[356]             }
[357] 
[358]             n = c->recv(c, rb->buf->last, size);
[359] 
[360]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[361]                            "http client request body recv %z", n);
[362] 
[363]             if (n == NGX_AGAIN) {
[364]                 break;
[365]             }
[366] 
[367]             if (n == 0) {
[368]                 ngx_log_error(NGX_LOG_INFO, c->log, 0,
[369]                               "client prematurely closed connection");
[370]             }
[371] 
[372]             if (n == 0 || n == NGX_ERROR) {
[373]                 c->error = 1;
[374]                 return NGX_HTTP_BAD_REQUEST;
[375]             }
[376] 
[377]             rb->buf->last += n;
[378]             r->request_length += n;
[379] 
[380]             /* pass buffer to request body filter chain */
[381] 
[382]             flush = 0;
[383]             out.buf = rb->buf;
[384]             out.next = NULL;
[385] 
[386]             rc = ngx_http_request_body_filter(r, &out);
[387] 
[388]             if (rc != NGX_OK) {
[389]                 return rc;
[390]             }
[391] 
[392]             if (rb->rest == 0) {
[393]                 break;
[394]             }
[395] 
[396]             if (rb->buf->last < rb->buf->end) {
[397]                 break;
[398]             }
[399]         }
[400] 
[401]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[402]                        "http client request body rest %O", rb->rest);
[403] 
[404]         if (flush) {
[405]             rc = ngx_http_request_body_filter(r, NULL);
[406] 
[407]             if (rc != NGX_OK) {
[408]                 return rc;
[409]             }
[410]         }
[411] 
[412]         if (rb->rest == 0 && rb->last_saved) {
[413]             break;
[414]         }
[415] 
[416]         if (!c->read->ready || rb->rest == 0) {
[417] 
[418]             clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[419]             ngx_add_timer(c->read, clcf->client_body_timeout);
[420] 
[421]             if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
[422]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[423]             }
[424] 
[425]             return NGX_AGAIN;
[426]         }
[427]     }
[428] 
[429]     if (ngx_http_copy_pipelined_header(r, rb->buf) != NGX_OK) {
[430]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[431]     }
[432] 
[433]     if (c->read->timer_set) {
[434]         ngx_del_timer(c->read);
[435]     }
[436] 
[437]     if (!r->request_body_no_buffering) {
[438]         r->read_event_handler = ngx_http_block_reading;
[439]         rb->post_handler(r);
[440]     }
[441] 
[442]     return NGX_OK;
[443] }
[444] 
[445] 
[446] static ngx_int_t
[447] ngx_http_copy_pipelined_header(ngx_http_request_t *r, ngx_buf_t *buf)
[448] {
[449]     size_t                     n;
[450]     ngx_buf_t                 *b;
[451]     ngx_chain_t               *cl;
[452]     ngx_http_connection_t     *hc;
[453]     ngx_http_core_srv_conf_t  *cscf;
[454] 
[455]     b = r->header_in;
[456]     n = buf->last - buf->pos;
[457] 
[458]     if (buf == b || n == 0) {
[459]         return NGX_OK;
[460]     }
[461] 
[462]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[463]                    "http body pipelined header: %uz", n);
[464] 
[465]     /*
[466]      * if there is a pipelined request in the client body buffer,
[467]      * copy it to the r->header_in buffer if there is enough room,
[468]      * or allocate a large client header buffer
[469]      */
[470] 
[471]     if (n > (size_t) (b->end - b->last)) {
[472] 
[473]         hc = r->http_connection;
[474] 
[475]         if (hc->free) {
[476]             cl = hc->free;
[477]             hc->free = cl->next;
[478] 
[479]             b = cl->buf;
[480] 
[481]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[482]                            "http large header free: %p %uz",
[483]                            b->pos, b->end - b->last);
[484] 
[485]         } else {
[486]             cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[487] 
[488]             b = ngx_create_temp_buf(r->connection->pool,
[489]                                     cscf->large_client_header_buffers.size);
[490]             if (b == NULL) {
[491]                 return NGX_ERROR;
[492]             }
[493] 
[494]             cl = ngx_alloc_chain_link(r->connection->pool);
[495]             if (cl == NULL) {
[496]                 return NGX_ERROR;
[497]             }
[498] 
[499]             cl->buf = b;
[500] 
[501]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[502]                            "http large header alloc: %p %uz",
[503]                            b->pos, b->end - b->last);
[504]         }
[505] 
[506]         cl->next = hc->busy;
[507]         hc->busy = cl;
[508]         hc->nbusy++;
[509] 
[510]         r->header_in = b;
[511] 
[512]         if (n > (size_t) (b->end - b->last)) {
[513]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[514]                           "too large pipelined header after reading body");
[515]             return NGX_ERROR;
[516]         }
[517]     }
[518] 
[519]     ngx_memcpy(b->last, buf->pos, n);
[520] 
[521]     b->last += n;
[522]     r->request_length -= n;
[523] 
[524]     return NGX_OK;
[525] }
[526] 
[527] 
[528] static ngx_int_t
[529] ngx_http_write_request_body(ngx_http_request_t *r)
[530] {
[531]     ssize_t                    n;
[532]     ngx_chain_t               *cl, *ln;
[533]     ngx_temp_file_t           *tf;
[534]     ngx_http_request_body_t   *rb;
[535]     ngx_http_core_loc_conf_t  *clcf;
[536] 
[537]     rb = r->request_body;
[538] 
[539]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[540]                    "http write client request body, bufs %p", rb->bufs);
[541] 
[542]     if (rb->temp_file == NULL) {
[543]         tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
[544]         if (tf == NULL) {
[545]             return NGX_ERROR;
[546]         }
[547] 
[548]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[549] 
[550]         tf->file.fd = NGX_INVALID_FILE;
[551]         tf->file.log = r->connection->log;
[552]         tf->path = clcf->client_body_temp_path;
[553]         tf->pool = r->pool;
[554]         tf->warn = "a client request body is buffered to a temporary file";
[555]         tf->log_level = r->request_body_file_log_level;
[556]         tf->persistent = r->request_body_in_persistent_file;
[557]         tf->clean = r->request_body_in_clean_file;
[558] 
[559]         if (r->request_body_file_group_access) {
[560]             tf->access = 0660;
[561]         }
[562] 
[563]         rb->temp_file = tf;
[564] 
[565]         if (rb->bufs == NULL) {
[566]             /* empty body with r->request_body_in_file_only */
[567] 
[568]             if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
[569]                                      tf->persistent, tf->clean, tf->access)
[570]                 != NGX_OK)
[571]             {
[572]                 return NGX_ERROR;
[573]             }
[574] 
[575]             return NGX_OK;
[576]         }
[577]     }
[578] 
[579]     if (rb->bufs == NULL) {
[580]         return NGX_OK;
[581]     }
[582] 
[583]     n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);
[584] 
[585]     /* TODO: n == 0 or not complete and level event */
[586] 
[587]     if (n == NGX_ERROR) {
[588]         return NGX_ERROR;
[589]     }
[590] 
[591]     rb->temp_file->offset += n;
[592] 
[593]     /* mark all buffers as written */
[594] 
[595]     for (cl = rb->bufs; cl; /* void */) {
[596] 
[597]         cl->buf->pos = cl->buf->last;
[598] 
[599]         ln = cl;
[600]         cl = cl->next;
[601]         ngx_free_chain(r->pool, ln);
[602]     }
[603] 
[604]     rb->bufs = NULL;
[605] 
[606]     return NGX_OK;
[607] }
[608] 
[609] 
[610] ngx_int_t
[611] ngx_http_discard_request_body(ngx_http_request_t *r)
[612] {
[613]     ssize_t       size;
[614]     ngx_int_t     rc;
[615]     ngx_event_t  *rev;
[616] 
[617]     if (r != r->main || r->discard_body || r->request_body) {
[618]         return NGX_OK;
[619]     }
[620] 
[621] #if (NGX_HTTP_V2)
[622]     if (r->stream) {
[623]         r->stream->skip_data = 1;
[624]         return NGX_OK;
[625]     }
[626] #endif
[627] 
[628]     if (ngx_http_test_expect(r) != NGX_OK) {
[629]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[630]     }
[631] 
[632]     rev = r->connection->read;
[633] 
[634]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");
[635] 
[636]     if (rev->timer_set) {
[637]         ngx_del_timer(rev);
[638]     }
[639] 
[640]     if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
[641]         return NGX_OK;
[642]     }
[643] 
[644]     size = r->header_in->last - r->header_in->pos;
[645] 
[646]     if (size || r->headers_in.chunked) {
[647]         rc = ngx_http_discard_request_body_filter(r, r->header_in);
[648] 
[649]         if (rc != NGX_OK) {
[650]             return rc;
[651]         }
[652] 
[653]         if (r->headers_in.content_length_n == 0) {
[654]             return NGX_OK;
[655]         }
[656]     }
[657] 
[658]     rc = ngx_http_read_discarded_request_body(r);
[659] 
[660]     if (rc == NGX_OK) {
[661]         r->lingering_close = 0;
[662]         return NGX_OK;
[663]     }
[664] 
[665]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[666]         return rc;
[667]     }
[668] 
[669]     /* rc == NGX_AGAIN */
[670] 
[671]     r->read_event_handler = ngx_http_discarded_request_body_handler;
[672] 
[673]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[674]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[675]     }
[676] 
[677]     r->count++;
[678]     r->discard_body = 1;
[679] 
[680]     return NGX_OK;
[681] }
[682] 
[683] 
[684] void
[685] ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
[686] {
[687]     ngx_int_t                  rc;
[688]     ngx_msec_t                 timer;
[689]     ngx_event_t               *rev;
[690]     ngx_connection_t          *c;
[691]     ngx_http_core_loc_conf_t  *clcf;
[692] 
[693]     c = r->connection;
[694]     rev = c->read;
[695] 
[696]     if (rev->timedout) {
[697]         c->timedout = 1;
[698]         c->error = 1;
[699]         ngx_http_finalize_request(r, NGX_ERROR);
[700]         return;
[701]     }
[702] 
[703]     if (r->lingering_time) {
[704]         timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();
[705] 
[706]         if ((ngx_msec_int_t) timer <= 0) {
[707]             r->discard_body = 0;
[708]             r->lingering_close = 0;
[709]             ngx_http_finalize_request(r, NGX_ERROR);
[710]             return;
[711]         }
[712] 
[713]     } else {
[714]         timer = 0;
[715]     }
[716] 
[717]     rc = ngx_http_read_discarded_request_body(r);
[718] 
[719]     if (rc == NGX_OK) {
[720]         r->discard_body = 0;
[721]         r->lingering_close = 0;
[722]         r->lingering_time = 0;
[723]         ngx_http_finalize_request(r, NGX_DONE);
[724]         return;
[725]     }
[726] 
[727]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[728]         c->error = 1;
[729]         ngx_http_finalize_request(r, NGX_ERROR);
[730]         return;
[731]     }
[732] 
[733]     /* rc == NGX_AGAIN */
[734] 
[735]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[736]         c->error = 1;
[737]         ngx_http_finalize_request(r, NGX_ERROR);
[738]         return;
[739]     }
[740] 
[741]     if (timer) {
[742] 
[743]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[744] 
[745]         timer *= 1000;
[746] 
[747]         if (timer > clcf->lingering_timeout) {
[748]             timer = clcf->lingering_timeout;
[749]         }
[750] 
[751]         ngx_add_timer(rev, timer);
[752]     }
[753] }
[754] 
[755] 
[756] static ngx_int_t
[757] ngx_http_read_discarded_request_body(ngx_http_request_t *r)
[758] {
[759]     size_t     size;
[760]     ssize_t    n;
[761]     ngx_int_t  rc;
[762]     ngx_buf_t  b;
[763]     u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];
[764] 
[765]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[766]                    "http read discarded body");
[767] 
[768]     ngx_memzero(&b, sizeof(ngx_buf_t));
[769] 
[770]     b.temporary = 1;
[771] 
[772]     for ( ;; ) {
[773]         if (r->headers_in.content_length_n == 0) {
[774]             break;
[775]         }
[776] 
[777]         if (!r->connection->read->ready) {
[778]             return NGX_AGAIN;
[779]         }
[780] 
[781]         size = (size_t) ngx_min(r->headers_in.content_length_n,
[782]                                 NGX_HTTP_DISCARD_BUFFER_SIZE);
[783] 
[784]         n = r->connection->recv(r->connection, buffer, size);
[785] 
[786]         if (n == NGX_ERROR) {
[787]             r->connection->error = 1;
[788]             return NGX_OK;
[789]         }
[790] 
[791]         if (n == NGX_AGAIN) {
[792]             return NGX_AGAIN;
[793]         }
[794] 
[795]         if (n == 0) {
[796]             return NGX_OK;
[797]         }
[798] 
[799]         b.pos = buffer;
[800]         b.last = buffer + n;
[801] 
[802]         rc = ngx_http_discard_request_body_filter(r, &b);
[803] 
[804]         if (rc != NGX_OK) {
[805]             return rc;
[806]         }
[807]     }
[808] 
[809]     if (ngx_http_copy_pipelined_header(r, &b) != NGX_OK) {
[810]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[811]     }
[812] 
[813]     r->read_event_handler = ngx_http_block_reading;
[814] 
[815]     return NGX_OK;
[816] }
[817] 
[818] 
[819] static ngx_int_t
[820] ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
[821] {
[822]     size_t                     size;
[823]     ngx_int_t                  rc;
[824]     ngx_http_request_body_t   *rb;
[825]     ngx_http_core_srv_conf_t  *cscf;
[826] 
[827]     if (r->headers_in.chunked) {
[828] 
[829]         rb = r->request_body;
[830] 
[831]         if (rb == NULL) {
[832] 
[833]             rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
[834]             if (rb == NULL) {
[835]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[836]             }
[837] 
[838]             rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
[839]             if (rb->chunked == NULL) {
[840]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[841]             }
[842] 
[843]             r->request_body = rb;
[844]         }
[845] 
[846]         for ( ;; ) {
[847] 
[848]             rc = ngx_http_parse_chunked(r, b, rb->chunked);
[849] 
[850]             if (rc == NGX_OK) {
[851] 
[852]                 /* a chunk has been parsed successfully */
[853] 
[854]                 size = b->last - b->pos;
[855] 
[856]                 if ((off_t) size > rb->chunked->size) {
[857]                     b->pos += (size_t) rb->chunked->size;
[858]                     rb->chunked->size = 0;
[859] 
[860]                 } else {
[861]                     rb->chunked->size -= size;
[862]                     b->pos = b->last;
[863]                 }
[864] 
[865]                 continue;
[866]             }
[867] 
[868]             if (rc == NGX_DONE) {
[869] 
[870]                 /* a whole response has been parsed successfully */
[871] 
[872]                 r->headers_in.content_length_n = 0;
[873]                 break;
[874]             }
[875] 
[876]             if (rc == NGX_AGAIN) {
[877] 
[878]                 /* set amount of data we want to see next time */
[879] 
[880]                 cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[881] 
[882]                 r->headers_in.content_length_n = ngx_max(rb->chunked->length,
[883]                                (off_t) cscf->large_client_header_buffers.size);
[884]                 break;
[885]             }
[886] 
[887]             /* invalid */
[888] 
[889]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[890]                           "client sent invalid chunked body");
[891] 
[892]             return NGX_HTTP_BAD_REQUEST;
[893]         }
[894] 
[895]     } else {
[896]         size = b->last - b->pos;
[897] 
[898]         if ((off_t) size > r->headers_in.content_length_n) {
[899]             b->pos += (size_t) r->headers_in.content_length_n;
[900]             r->headers_in.content_length_n = 0;
[901] 
[902]         } else {
[903]             b->pos = b->last;
[904]             r->headers_in.content_length_n -= size;
[905]         }
[906]     }
[907] 
[908]     return NGX_OK;
[909] }
[910] 
[911] 
[912] static ngx_int_t
[913] ngx_http_test_expect(ngx_http_request_t *r)
[914] {
[915]     ngx_int_t   n;
[916]     ngx_str_t  *expect;
[917] 
[918]     if (r->expect_tested
[919]         || r->headers_in.expect == NULL
[920]         || r->http_version < NGX_HTTP_VERSION_11
[921] #if (NGX_HTTP_V2)
[922]         || r->stream != NULL
[923] #endif
[924]        )
[925]     {
[926]         return NGX_OK;
[927]     }
[928] 
[929]     r->expect_tested = 1;
[930] 
[931]     expect = &r->headers_in.expect->value;
[932] 
[933]     if (expect->len != sizeof("100-continue") - 1
[934]         || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
[935]                            sizeof("100-continue") - 1)
[936]            != 0)
[937]     {
[938]         return NGX_OK;
[939]     }
[940] 
[941]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[942]                    "send 100 Continue");
[943] 
[944]     n = r->connection->send(r->connection,
[945]                             (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
[946]                             sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);
[947] 
[948]     if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
[949]         return NGX_OK;
[950]     }
[951] 
[952]     /* we assume that such small packet should be send successfully */
[953] 
[954]     r->connection->error = 1;
[955] 
[956]     return NGX_ERROR;
[957] }
[958] 
[959] 
[960] static ngx_int_t
[961] ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[962] {
[963]     if (r->headers_in.chunked) {
[964]         return ngx_http_request_body_chunked_filter(r, in);
[965] 
[966]     } else {
[967]         return ngx_http_request_body_length_filter(r, in);
[968]     }
[969] }
[970] 
[971] 
[972] static ngx_int_t
[973] ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
[974] {
[975]     size_t                     size;
[976]     ngx_int_t                  rc;
[977]     ngx_buf_t                 *b;
[978]     ngx_chain_t               *cl, *tl, *out, **ll;
[979]     ngx_http_request_body_t   *rb;
[980] 
[981]     rb = r->request_body;
[982] 
[983]     out = NULL;
[984]     ll = &out;
[985] 
[986]     if (rb->rest == -1) {
[987]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[988]                        "http request body content length filter");
[989] 
[990]         rb->rest = r->headers_in.content_length_n;
[991] 
[992]         if (rb->rest == 0) {
[993] 
[994]             tl = ngx_chain_get_free_buf(r->pool, &rb->free);
[995]             if (tl == NULL) {
[996]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[997]             }
[998] 
[999]             b = tl->buf;
[1000] 
[1001]             ngx_memzero(b, sizeof(ngx_buf_t));
[1002] 
[1003]             b->last_buf = 1;
[1004] 
[1005]             *ll = tl;
[1006]             ll = &tl->next;
[1007]         }
[1008]     }
[1009] 
[1010]     for (cl = in; cl; cl = cl->next) {
[1011] 
[1012]         if (rb->rest == 0) {
[1013]             break;
[1014]         }
[1015] 
[1016]         tl = ngx_chain_get_free_buf(r->pool, &rb->free);
[1017]         if (tl == NULL) {
[1018]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1019]         }
[1020] 
[1021]         b = tl->buf;
[1022] 
[1023]         ngx_memzero(b, sizeof(ngx_buf_t));
[1024] 
[1025]         b->temporary = 1;
[1026]         b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
[1027]         b->start = cl->buf->pos;
[1028]         b->pos = cl->buf->pos;
[1029]         b->last = cl->buf->last;
[1030]         b->end = cl->buf->end;
[1031]         b->flush = r->request_body_no_buffering;
[1032] 
[1033]         size = cl->buf->last - cl->buf->pos;
[1034] 
[1035]         if ((off_t) size < rb->rest) {
[1036]             cl->buf->pos = cl->buf->last;
[1037]             rb->rest -= size;
[1038] 
[1039]         } else {
[1040]             cl->buf->pos += (size_t) rb->rest;
[1041]             rb->rest = 0;
[1042]             b->last = cl->buf->pos;
[1043]             b->last_buf = 1;
[1044]         }
[1045] 
[1046]         *ll = tl;
[1047]         ll = &tl->next;
[1048]     }
[1049] 
[1050]     rc = ngx_http_top_request_body_filter(r, out);
[1051] 
[1052]     ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
[1053]                             (ngx_buf_tag_t) &ngx_http_read_client_request_body);
[1054] 
[1055]     return rc;
[1056] }
[1057] 
[1058] 
[1059] static ngx_int_t
[1060] ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
[1061] {
[1062]     size_t                     size;
[1063]     ngx_int_t                  rc;
[1064]     ngx_buf_t                 *b;
[1065]     ngx_chain_t               *cl, *out, *tl, **ll;
[1066]     ngx_http_request_body_t   *rb;
[1067]     ngx_http_core_loc_conf_t  *clcf;
[1068]     ngx_http_core_srv_conf_t  *cscf;
[1069] 
[1070]     rb = r->request_body;
[1071] 
[1072]     out = NULL;
[1073]     ll = &out;
[1074] 
[1075]     if (rb->rest == -1) {
[1076] 
[1077]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1078]                        "http request body chunked filter");
[1079] 
[1080]         rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
[1081]         if (rb->chunked == NULL) {
[1082]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1083]         }
[1084] 
[1085]         cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1086] 
[1087]         r->headers_in.content_length_n = 0;
[1088]         rb->rest = cscf->large_client_header_buffers.size;
[1089]     }
[1090] 
[1091]     for (cl = in; cl; cl = cl->next) {
[1092] 
[1093]         b = NULL;
[1094] 
[1095]         for ( ;; ) {
[1096] 
[1097]             ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1098]                            "http body chunked buf "
[1099]                            "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
[1100]                            cl->buf->temporary, cl->buf->in_file,
[1101]                            cl->buf->start, cl->buf->pos,
[1102]                            cl->buf->last - cl->buf->pos,
[1103]                            cl->buf->file_pos,
[1104]                            cl->buf->file_last - cl->buf->file_pos);
[1105] 
[1106]             rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked);
[1107] 
[1108]             if (rc == NGX_OK) {
[1109] 
[1110]                 /* a chunk has been parsed successfully */
[1111] 
[1112]                 clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1113] 
[1114]                 if (clcf->client_max_body_size
[1115]                     && clcf->client_max_body_size
[1116]                        - r->headers_in.content_length_n < rb->chunked->size)
[1117]                 {
[1118]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1119]                                   "client intended to send too large chunked "
[1120]                                   "body: %O+%O bytes",
[1121]                                   r->headers_in.content_length_n,
[1122]                                   rb->chunked->size);
[1123] 
[1124]                     r->lingering_close = 1;
[1125] 
[1126]                     return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
[1127]                 }
[1128] 
[1129]                 if (b
[1130]                     && rb->chunked->size <= 128
[1131]                     && cl->buf->last - cl->buf->pos >= rb->chunked->size)
[1132]                 {
[1133]                     r->headers_in.content_length_n += rb->chunked->size;
[1134] 
[1135]                     if (rb->chunked->size < 8) {
[1136] 
[1137]                         while (rb->chunked->size) {
[1138]                             *b->last++ = *cl->buf->pos++;
[1139]                             rb->chunked->size--;
[1140]                         }
[1141] 
[1142]                     } else {
[1143]                         ngx_memmove(b->last, cl->buf->pos, rb->chunked->size);
[1144]                         b->last += rb->chunked->size;
[1145]                         cl->buf->pos += rb->chunked->size;
[1146]                         rb->chunked->size = 0;
[1147]                     }
[1148] 
[1149]                     continue;
[1150]                 }
[1151] 
[1152]                 tl = ngx_chain_get_free_buf(r->pool, &rb->free);
[1153]                 if (tl == NULL) {
[1154]                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1155]                 }
[1156] 
[1157]                 b = tl->buf;
[1158] 
[1159]                 ngx_memzero(b, sizeof(ngx_buf_t));
[1160] 
[1161]                 b->temporary = 1;
[1162]                 b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
[1163]                 b->start = cl->buf->pos;
[1164]                 b->pos = cl->buf->pos;
[1165]                 b->last = cl->buf->last;
[1166]                 b->end = cl->buf->end;
[1167]                 b->flush = r->request_body_no_buffering;
[1168] 
[1169]                 *ll = tl;
[1170]                 ll = &tl->next;
[1171] 
[1172]                 size = cl->buf->last - cl->buf->pos;
[1173] 
[1174]                 if ((off_t) size > rb->chunked->size) {
[1175]                     cl->buf->pos += (size_t) rb->chunked->size;
[1176]                     r->headers_in.content_length_n += rb->chunked->size;
[1177]                     rb->chunked->size = 0;
[1178] 
[1179]                 } else {
[1180]                     rb->chunked->size -= size;
[1181]                     r->headers_in.content_length_n += size;
[1182]                     cl->buf->pos = cl->buf->last;
[1183]                 }
[1184] 
[1185]                 b->last = cl->buf->pos;
[1186] 
[1187]                 continue;
[1188]             }
[1189] 
[1190]             if (rc == NGX_DONE) {
[1191] 
[1192]                 /* a whole response has been parsed successfully */
[1193] 
[1194]                 rb->rest = 0;
[1195] 
[1196]                 tl = ngx_chain_get_free_buf(r->pool, &rb->free);
[1197]                 if (tl == NULL) {
[1198]                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1199]                 }
[1200] 
[1201]                 b = tl->buf;
[1202] 
[1203]                 ngx_memzero(b, sizeof(ngx_buf_t));
[1204] 
[1205]                 b->last_buf = 1;
[1206] 
[1207]                 *ll = tl;
[1208]                 ll = &tl->next;
[1209] 
[1210]                 break;
[1211]             }
[1212] 
[1213]             if (rc == NGX_AGAIN) {
[1214] 
[1215]                 /* set rb->rest, amount of data we want to see next time */
[1216] 
[1217]                 cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1218] 
[1219]                 rb->rest = ngx_max(rb->chunked->length,
[1220]                                (off_t) cscf->large_client_header_buffers.size);
[1221] 
[1222]                 break;
[1223]             }
[1224] 
[1225]             /* invalid */
[1226] 
[1227]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1228]                           "client sent invalid chunked body");
[1229] 
[1230]             return NGX_HTTP_BAD_REQUEST;
[1231]         }
[1232]     }
[1233] 
[1234]     rc = ngx_http_top_request_body_filter(r, out);
[1235] 
[1236]     ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
[1237]                             (ngx_buf_tag_t) &ngx_http_read_client_request_body);
[1238] 
[1239]     return rc;
[1240] }
[1241] 
[1242] 
[1243] ngx_int_t
[1244] ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
[1245] {
[1246]     ngx_buf_t                 *b;
[1247]     ngx_chain_t               *cl, *tl, **ll;
[1248]     ngx_http_request_body_t   *rb;
[1249] 
[1250]     rb = r->request_body;
[1251] 
[1252]     ll = &rb->bufs;
[1253] 
[1254]     for (cl = rb->bufs; cl; cl = cl->next) {
[1255] 
[1256] #if 0
[1257]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1258]                        "http body old buf t:%d f:%d %p, pos %p, size: %z "
[1259]                        "file: %O, size: %O",
[1260]                        cl->buf->temporary, cl->buf->in_file,
[1261]                        cl->buf->start, cl->buf->pos,
[1262]                        cl->buf->last - cl->buf->pos,
[1263]                        cl->buf->file_pos,
[1264]                        cl->buf->file_last - cl->buf->file_pos);
[1265] #endif
[1266] 
[1267]         ll = &cl->next;
[1268]     }
[1269] 
[1270]     for (cl = in; cl; cl = cl->next) {
[1271] 
[1272]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
[1273]                        "http body new buf t:%d f:%d %p, pos %p, size: %z "
[1274]                        "file: %O, size: %O",
[1275]                        cl->buf->temporary, cl->buf->in_file,
[1276]                        cl->buf->start, cl->buf->pos,
[1277]                        cl->buf->last - cl->buf->pos,
[1278]                        cl->buf->file_pos,
[1279]                        cl->buf->file_last - cl->buf->file_pos);
[1280] 
[1281]         if (cl->buf->last_buf) {
[1282] 
[1283]             if (rb->last_saved) {
[1284]                 ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1285]                               "duplicate last buf in save filter");
[1286]                 *ll = NULL;
[1287]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1288]             }
[1289] 
[1290]             rb->last_saved = 1;
[1291]         }
[1292] 
[1293]         tl = ngx_alloc_chain_link(r->pool);
[1294]         if (tl == NULL) {
[1295]             *ll = NULL;
[1296]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1297]         }
[1298] 
[1299]         tl->buf = cl->buf;
[1300]         *ll = tl;
[1301]         ll = &tl->next;
[1302]     }
[1303] 
[1304]     *ll = NULL;
[1305] 
[1306]     if (r->request_body_no_buffering) {
[1307]         return NGX_OK;
[1308]     }
[1309] 
[1310]     if (rb->rest > 0) {
[1311] 
[1312]         if (rb->bufs && rb->buf && rb->buf->last == rb->buf->end
[1313]             && ngx_http_write_request_body(r) != NGX_OK)
[1314]         {
[1315]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1316]         }
[1317] 
[1318]         return NGX_OK;
[1319]     }
[1320] 
[1321]     if (!rb->last_saved) {
[1322]         return NGX_OK;
[1323]     }
[1324] 
[1325]     if (rb->temp_file || r->request_body_in_file_only) {
[1326] 
[1327]         if (rb->bufs && rb->bufs->buf->in_file) {
[1328]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1329]                           "body already in file");
[1330]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1331]         }
[1332] 
[1333]         if (ngx_http_write_request_body(r) != NGX_OK) {
[1334]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1335]         }
[1336] 
[1337]         if (rb->temp_file->file.offset != 0) {
[1338] 
[1339]             cl = ngx_chain_get_free_buf(r->pool, &rb->free);
[1340]             if (cl == NULL) {
[1341]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[1342]             }
[1343] 
[1344]             b = cl->buf;
[1345] 
[1346]             ngx_memzero(b, sizeof(ngx_buf_t));
[1347] 
[1348]             b->in_file = 1;
[1349]             b->file_last = rb->temp_file->file.offset;
[1350]             b->file = &rb->temp_file->file;
[1351] 
[1352]             rb->bufs = cl;
[1353]         }
[1354]     }
[1355] 
[1356]     return NGX_OK;
[1357] }
