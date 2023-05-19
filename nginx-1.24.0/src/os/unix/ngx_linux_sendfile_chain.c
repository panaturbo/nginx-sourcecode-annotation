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
[13] static ssize_t ngx_linux_sendfile(ngx_connection_t *c, ngx_buf_t *file,
[14]     size_t size);
[15] 
[16] #if (NGX_THREADS)
[17] #include <ngx_thread_pool.h>
[18] 
[19] #if !(NGX_HAVE_SENDFILE64)
[20] #error sendfile64() is required!
[21] #endif
[22] 
[23] static ssize_t ngx_linux_sendfile_thread(ngx_connection_t *c, ngx_buf_t *file,
[24]     size_t size);
[25] static void ngx_linux_sendfile_thread_handler(void *data, ngx_log_t *log);
[26] #endif
[27] 
[28] 
[29] /*
[30]  * On Linux up to 2.4.21 sendfile() (syscall #187) works with 32-bit
[31]  * offsets only, and the including <sys/sendfile.h> breaks the compiling,
[32]  * if off_t is 64 bit wide.  So we use own sendfile() definition, where offset
[33]  * parameter is int32_t, and use sendfile() for the file parts below 2G only,
[34]  * see src/os/unix/ngx_linux_config.h
[35]  *
[36]  * Linux 2.4.21 has the new sendfile64() syscall #239.
[37]  *
[38]  * On Linux up to 2.6.16 sendfile() does not allow to pass the count parameter
[39]  * more than 2G-1 bytes even on 64-bit platforms: it returns EINVAL,
[40]  * so we limit it to 2G-1 bytes.
[41]  *
[42]  * On Linux 2.6.16 and later, sendfile() silently limits the count parameter
[43]  * to 2G minus the page size, even on 64-bit platforms.
[44]  */
[45] 
[46] #define NGX_SENDFILE_MAXSIZE  2147483647L
[47] 
[48] 
[49] ngx_chain_t *
[50] ngx_linux_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[51] {
[52]     int            tcp_nodelay;
[53]     off_t          send, prev_send;
[54]     size_t         file_size, sent;
[55]     ssize_t        n;
[56]     ngx_err_t      err;
[57]     ngx_buf_t     *file;
[58]     ngx_event_t   *wev;
[59]     ngx_chain_t   *cl;
[60]     ngx_iovec_t    header;
[61]     struct iovec   headers[NGX_IOVS_PREALLOCATE];
[62] 
[63]     wev = c->write;
[64] 
[65]     if (!wev->ready) {
[66]         return in;
[67]     }
[68] 
[69] 
[70]     /* the maximum limit size is 2G-1 - the page size */
[71] 
[72]     if (limit == 0 || limit > (off_t) (NGX_SENDFILE_MAXSIZE - ngx_pagesize)) {
[73]         limit = NGX_SENDFILE_MAXSIZE - ngx_pagesize;
[74]     }
[75] 
[76] 
[77]     send = 0;
[78] 
[79]     header.iovs = headers;
[80]     header.nalloc = NGX_IOVS_PREALLOCATE;
[81] 
[82]     for ( ;; ) {
[83]         prev_send = send;
[84] 
[85]         /* create the iovec and coalesce the neighbouring bufs */
[86] 
[87]         cl = ngx_output_chain_to_iovec(&header, in, limit - send, c->log);
[88] 
[89]         if (cl == NGX_CHAIN_ERROR) {
[90]             return NGX_CHAIN_ERROR;
[91]         }
[92] 
[93]         send += header.size;
[94] 
[95]         /* set TCP_CORK if there is a header before a file */
[96] 
[97]         if (c->tcp_nopush == NGX_TCP_NOPUSH_UNSET
[98]             && header.count != 0
[99]             && cl
[100]             && cl->buf->in_file)
[101]         {
[102]             /* the TCP_CORK and TCP_NODELAY are mutually exclusive */
[103] 
[104]             if (c->tcp_nodelay == NGX_TCP_NODELAY_SET) {
[105] 
[106]                 tcp_nodelay = 0;
[107] 
[108]                 if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
[109]                                (const void *) &tcp_nodelay, sizeof(int)) == -1)
[110]                 {
[111]                     err = ngx_socket_errno;
[112] 
[113]                     /*
[114]                      * there is a tiny chance to be interrupted, however,
[115]                      * we continue a processing with the TCP_NODELAY
[116]                      * and without the TCP_CORK
[117]                      */
[118] 
[119]                     if (err != NGX_EINTR) {
[120]                         wev->error = 1;
[121]                         ngx_connection_error(c, err,
[122]                                              "setsockopt(TCP_NODELAY) failed");
[123]                         return NGX_CHAIN_ERROR;
[124]                     }
[125] 
[126]                 } else {
[127]                     c->tcp_nodelay = NGX_TCP_NODELAY_UNSET;
[128] 
[129]                     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[130]                                    "no tcp_nodelay");
[131]                 }
[132]             }
[133] 
[134]             if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
[135] 
[136]                 if (ngx_tcp_nopush(c->fd) == -1) {
[137]                     err = ngx_socket_errno;
[138] 
[139]                     /*
[140]                      * there is a tiny chance to be interrupted, however,
[141]                      * we continue a processing without the TCP_CORK
[142]                      */
[143] 
[144]                     if (err != NGX_EINTR) {
[145]                         wev->error = 1;
[146]                         ngx_connection_error(c, err,
[147]                                              ngx_tcp_nopush_n " failed");
[148]                         return NGX_CHAIN_ERROR;
[149]                     }
[150] 
[151]                 } else {
[152]                     c->tcp_nopush = NGX_TCP_NOPUSH_SET;
[153] 
[154]                     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[155]                                    "tcp_nopush");
[156]                 }
[157]             }
[158]         }
[159] 
[160]         /* get the file buf */
[161] 
[162]         if (header.count == 0 && cl && cl->buf->in_file && send < limit) {
[163]             file = cl->buf;
[164] 
[165]             /* coalesce the neighbouring file bufs */
[166] 
[167]             file_size = (size_t) ngx_chain_coalesce_file(&cl, limit - send);
[168] 
[169]             send += file_size;
[170] #if 1
[171]             if (file_size == 0) {
[172]                 ngx_debug_point();
[173]                 return NGX_CHAIN_ERROR;
[174]             }
[175] #endif
[176] 
[177]             n = ngx_linux_sendfile(c, file, file_size);
[178] 
[179]             if (n == NGX_ERROR) {
[180]                 return NGX_CHAIN_ERROR;
[181]             }
[182] 
[183]             if (n == NGX_DONE) {
[184]                 /* thread task posted */
[185]                 return in;
[186]             }
[187] 
[188]             sent = (n == NGX_AGAIN) ? 0 : n;
[189] 
[190]         } else {
[191]             n = ngx_writev(c, &header);
[192] 
[193]             if (n == NGX_ERROR) {
[194]                 return NGX_CHAIN_ERROR;
[195]             }
[196] 
[197]             sent = (n == NGX_AGAIN) ? 0 : n;
[198]         }
[199] 
[200]         c->sent += sent;
[201] 
[202]         in = ngx_chain_update_sent(in, sent);
[203] 
[204]         if (n == NGX_AGAIN) {
[205]             wev->ready = 0;
[206]             return in;
[207]         }
[208] 
[209]         if ((size_t) (send - prev_send) != sent) {
[210] 
[211]             /*
[212]              * sendfile() on Linux 4.3+ might be interrupted at any time,
[213]              * and provides no indication if it was interrupted or not,
[214]              * so we have to retry till an explicit EAGAIN
[215]              *
[216]              * sendfile() in threads can also report less bytes written
[217]              * than we are prepared to send now, since it was started in
[218]              * some point in the past, so we again have to retry
[219]              */
[220] 
[221]             send = prev_send + sent;
[222]         }
[223] 
[224]         if (send >= limit || in == NULL) {
[225]             return in;
[226]         }
[227]     }
[228] }
[229] 
[230] 
[231] static ssize_t
[232] ngx_linux_sendfile(ngx_connection_t *c, ngx_buf_t *file, size_t size)
[233] {
[234] #if (NGX_HAVE_SENDFILE64)
[235]     off_t      offset;
[236] #else
[237]     int32_t    offset;
[238] #endif
[239]     ssize_t    n;
[240]     ngx_err_t  err;
[241] 
[242] #if (NGX_THREADS)
[243] 
[244]     if (file->file->thread_handler) {
[245]         return ngx_linux_sendfile_thread(c, file, size);
[246]     }
[247] 
[248] #endif
[249] 
[250] #if (NGX_HAVE_SENDFILE64)
[251]     offset = file->file_pos;
[252] #else
[253]     offset = (int32_t) file->file_pos;
[254] #endif
[255] 
[256] eintr:
[257] 
[258]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[259]                    "sendfile: @%O %uz", file->file_pos, size);
[260] 
[261]     n = sendfile(c->fd, file->file->fd, &offset, size);
[262] 
[263]     if (n == -1) {
[264]         err = ngx_errno;
[265] 
[266]         switch (err) {
[267]         case NGX_EAGAIN:
[268]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[269]                            "sendfile() is not ready");
[270]             return NGX_AGAIN;
[271] 
[272]         case NGX_EINTR:
[273]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[274]                            "sendfile() was interrupted");
[275]             goto eintr;
[276] 
[277]         default:
[278]             c->write->error = 1;
[279]             ngx_connection_error(c, err, "sendfile() failed");
[280]             return NGX_ERROR;
[281]         }
[282]     }
[283] 
[284]     if (n == 0) {
[285]         /*
[286]          * if sendfile returns zero, then someone has truncated the file,
[287]          * so the offset became beyond the end of the file
[288]          */
[289] 
[290]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[291]                       "sendfile() reported that \"%s\" was truncated at %O",
[292]                       file->file->name.data, file->file_pos);
[293] 
[294]         return NGX_ERROR;
[295]     }
[296] 
[297]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0, "sendfile: %z of %uz @%O",
[298]                    n, size, file->file_pos);
[299] 
[300]     return n;
[301] }
[302] 
[303] 
[304] #if (NGX_THREADS)
[305] 
[306] typedef struct {
[307]     ngx_buf_t     *file;
[308]     ngx_socket_t   socket;
[309]     size_t         size;
[310] 
[311]     size_t         sent;
[312]     ngx_err_t      err;
[313] } ngx_linux_sendfile_ctx_t;
[314] 
[315] 
[316] static ssize_t
[317] ngx_linux_sendfile_thread(ngx_connection_t *c, ngx_buf_t *file, size_t size)
[318] {
[319]     ngx_event_t               *wev;
[320]     ngx_thread_task_t         *task;
[321]     ngx_linux_sendfile_ctx_t  *ctx;
[322] 
[323]     ngx_log_debug3(NGX_LOG_DEBUG_CORE, c->log, 0,
[324]                    "linux sendfile thread: %d, %uz, %O",
[325]                    file->file->fd, size, file->file_pos);
[326] 
[327]     task = c->sendfile_task;
[328] 
[329]     if (task == NULL) {
[330]         task = ngx_thread_task_alloc(c->pool, sizeof(ngx_linux_sendfile_ctx_t));
[331]         if (task == NULL) {
[332]             return NGX_ERROR;
[333]         }
[334] 
[335]         task->handler = ngx_linux_sendfile_thread_handler;
[336] 
[337]         c->sendfile_task = task;
[338]     }
[339] 
[340]     ctx = task->ctx;
[341]     wev = c->write;
[342] 
[343]     if (task->event.complete) {
[344]         task->event.complete = 0;
[345] 
[346]         if (ctx->err == NGX_EAGAIN) {
[347]             /*
[348]              * if wev->complete is set, this means that a write event
[349]              * happened while we were waiting for the thread task, so
[350]              * we have to retry sending even on EAGAIN
[351]              */
[352] 
[353]             if (wev->complete) {
[354]                 return 0;
[355]             }
[356] 
[357]             return NGX_AGAIN;
[358]         }
[359] 
[360]         if (ctx->err) {
[361]             wev->error = 1;
[362]             ngx_connection_error(c, ctx->err, "sendfile() failed");
[363]             return NGX_ERROR;
[364]         }
[365] 
[366]         if (ctx->sent == 0) {
[367]             /*
[368]              * if sendfile returns zero, then someone has truncated the file,
[369]              * so the offset became beyond the end of the file
[370]              */
[371] 
[372]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[373]                           "sendfile() reported that \"%s\" was truncated at %O",
[374]                           file->file->name.data, file->file_pos);
[375] 
[376]             return NGX_ERROR;
[377]         }
[378] 
[379]         return ctx->sent;
[380]     }
[381] 
[382]     ctx->file = file;
[383]     ctx->socket = c->fd;
[384]     ctx->size = size;
[385] 
[386]     wev->complete = 0;
[387] 
[388]     if (file->file->thread_handler(task, file->file) != NGX_OK) {
[389]         return NGX_ERROR;
[390]     }
[391] 
[392]     return NGX_DONE;
[393] }
[394] 
[395] 
[396] static void
[397] ngx_linux_sendfile_thread_handler(void *data, ngx_log_t *log)
[398] {
[399]     ngx_linux_sendfile_ctx_t *ctx = data;
[400] 
[401]     off_t       offset;
[402]     ssize_t     n;
[403]     ngx_buf_t  *file;
[404] 
[405]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "linux sendfile thread handler");
[406] 
[407]     file = ctx->file;
[408]     offset = file->file_pos;
[409] 
[410] again:
[411] 
[412]     n = sendfile(ctx->socket, file->file->fd, &offset, ctx->size);
[413] 
[414]     if (n == -1) {
[415]         ctx->err = ngx_errno;
[416] 
[417]     } else {
[418]         ctx->sent = n;
[419]         ctx->err = 0;
[420]     }
[421] 
[422] #if 0
[423]     ngx_time_update();
[424] #endif
[425] 
[426]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
[427]                    "sendfile: %z (err: %d) of %uz @%O",
[428]                    n, ctx->err, ctx->size, file->file_pos);
[429] 
[430]     if (ctx->err == NGX_EINTR) {
[431]         goto again;
[432]     }
[433] }
[434] 
[435] #endif /* NGX_THREADS */
