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
[13] /*
[14]  * Although FreeBSD sendfile() allows to pass a header and a trailer,
[15]  * it cannot send a header with a part of the file in one packet until
[16]  * FreeBSD 5.3.  Besides, over the fast ethernet connection sendfile()
[17]  * may send the partially filled packets, i.e. the 8 file pages may be sent
[18]  * as the 11 full 1460-bytes packets, then one incomplete 324-bytes packet,
[19]  * and then again the 11 full 1460-bytes packets.
[20]  *
[21]  * Therefore we use the TCP_NOPUSH option (similar to Linux's TCP_CORK)
[22]  * to postpone the sending - it not only sends a header and the first part of
[23]  * the file in one packet, but also sends the file pages in the full packets.
[24]  *
[25]  * But until FreeBSD 4.5 turning TCP_NOPUSH off does not flush a pending
[26]  * data that less than MSS, so that data may be sent with 5 second delay.
[27]  * So we do not use TCP_NOPUSH on FreeBSD prior to 4.5, although it can be used
[28]  * for non-keepalive HTTP connections.
[29]  */
[30] 
[31] 
[32] ngx_chain_t *
[33] ngx_freebsd_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[34] {
[35]     int              rc, flags;
[36]     off_t            send, prev_send, sent;
[37]     size_t           file_size;
[38]     ssize_t          n;
[39]     ngx_err_t        err;
[40]     ngx_buf_t       *file;
[41]     ngx_uint_t       eintr, eagain;
[42] #if (NGX_HAVE_SENDFILE_NODISKIO)
[43]     ngx_uint_t       ebusy;
[44] #endif
[45]     ngx_event_t     *wev;
[46]     ngx_chain_t     *cl;
[47]     ngx_iovec_t      header, trailer;
[48]     struct sf_hdtr   hdtr;
[49]     struct iovec     headers[NGX_IOVS_PREALLOCATE];
[50]     struct iovec     trailers[NGX_IOVS_PREALLOCATE];
[51] 
[52]     wev = c->write;
[53] 
[54]     if (!wev->ready) {
[55]         return in;
[56]     }
[57] 
[58] #if (NGX_HAVE_KQUEUE)
[59] 
[60]     if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
[61]         (void) ngx_connection_error(c, wev->kq_errno,
[62]                                "kevent() reported about an closed connection");
[63]         wev->error = 1;
[64]         return NGX_CHAIN_ERROR;
[65]     }
[66] 
[67] #endif
[68] 
[69]     /* the maximum limit size is the maximum size_t value - the page size */
[70] 
[71]     if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
[72]         limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
[73]     }
[74] 
[75]     send = 0;
[76]     eagain = 0;
[77]     flags = 0;
[78] 
[79]     header.iovs = headers;
[80]     header.nalloc = NGX_IOVS_PREALLOCATE;
[81] 
[82]     trailer.iovs = trailers;
[83]     trailer.nalloc = NGX_IOVS_PREALLOCATE;
[84] 
[85]     for ( ;; ) {
[86]         eintr = 0;
[87] #if (NGX_HAVE_SENDFILE_NODISKIO)
[88]         ebusy = 0;
[89] #endif
[90]         prev_send = send;
[91] 
[92]         /* create the header iovec and coalesce the neighbouring bufs */
[93] 
[94]         cl = ngx_output_chain_to_iovec(&header, in, limit - send, c->log);
[95] 
[96]         if (cl == NGX_CHAIN_ERROR) {
[97]             return NGX_CHAIN_ERROR;
[98]         }
[99] 
[100]         send += header.size;
[101] 
[102]         if (cl && cl->buf->in_file && send < limit) {
[103]             file = cl->buf;
[104] 
[105]             /* coalesce the neighbouring file bufs */
[106] 
[107]             file_size = (size_t) ngx_chain_coalesce_file(&cl, limit - send);
[108] 
[109]             send += file_size;
[110] 
[111]             if (send < limit) {
[112] 
[113]                 /*
[114]                  * create the trailer iovec and coalesce the neighbouring bufs
[115]                  */
[116] 
[117]                 cl = ngx_output_chain_to_iovec(&trailer, cl, limit - send,
[118]                                                c->log);
[119]                 if (cl == NGX_CHAIN_ERROR) {
[120]                     return NGX_CHAIN_ERROR;
[121]                 }
[122] 
[123]                 send += trailer.size;
[124] 
[125]             } else {
[126]                 trailer.count = 0;
[127]             }
[128] 
[129]             if (ngx_freebsd_use_tcp_nopush
[130]                 && c->tcp_nopush == NGX_TCP_NOPUSH_UNSET)
[131]             {
[132]                 if (ngx_tcp_nopush(c->fd) == -1) {
[133]                     err = ngx_socket_errno;
[134] 
[135]                     /*
[136]                      * there is a tiny chance to be interrupted, however,
[137]                      * we continue a processing without the TCP_NOPUSH
[138]                      */
[139] 
[140]                     if (err != NGX_EINTR) {
[141]                         wev->error = 1;
[142]                         (void) ngx_connection_error(c, err,
[143]                                                     ngx_tcp_nopush_n " failed");
[144]                         return NGX_CHAIN_ERROR;
[145]                     }
[146] 
[147]                 } else {
[148]                     c->tcp_nopush = NGX_TCP_NOPUSH_SET;
[149] 
[150]                     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
[151]                                    "tcp_nopush");
[152]                 }
[153]             }
[154] 
[155]             /*
[156]              * sendfile() does unneeded work if sf_hdtr's count is 0,
[157]              * but corresponding pointer is not NULL
[158]              */
[159] 
[160]             hdtr.headers = header.count ? header.iovs : NULL;
[161]             hdtr.hdr_cnt = header.count;
[162]             hdtr.trailers = trailer.count ? trailer.iovs : NULL;
[163]             hdtr.trl_cnt = trailer.count;
[164] 
[165]             /*
[166]              * the "nbytes bug" of the old sendfile() syscall:
[167]              * http://bugs.freebsd.org/33771
[168]              */
[169] 
[170]             if (!ngx_freebsd_sendfile_nbytes_bug) {
[171]                 header.size = 0;
[172]             }
[173] 
[174]             sent = 0;
[175] 
[176] #if (NGX_HAVE_SENDFILE_NODISKIO)
[177] 
[178]             flags = (c->busy_count <= 2) ? SF_NODISKIO : 0;
[179] 
[180]             if (file->file->directio) {
[181]                 flags |= SF_NOCACHE;
[182]             }
[183] 
[184] #endif
[185] 
[186]             rc = sendfile(file->file->fd, c->fd, file->file_pos,
[187]                           file_size + header.size, &hdtr, &sent, flags);
[188] 
[189]             if (rc == -1) {
[190]                 err = ngx_errno;
[191] 
[192]                 switch (err) {
[193]                 case NGX_EAGAIN:
[194]                     eagain = 1;
[195]                     break;
[196] 
[197]                 case NGX_EINTR:
[198]                     eintr = 1;
[199]                     break;
[200] 
[201] #if (NGX_HAVE_SENDFILE_NODISKIO)
[202]                 case NGX_EBUSY:
[203]                     ebusy = 1;
[204]                     break;
[205] #endif
[206] 
[207]                 default:
[208]                     wev->error = 1;
[209]                     (void) ngx_connection_error(c, err, "sendfile() failed");
[210]                     return NGX_CHAIN_ERROR;
[211]                 }
[212] 
[213]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, err,
[214]                                "sendfile() sent only %O bytes", sent);
[215] 
[216]             /*
[217]              * sendfile() in FreeBSD 3.x-4.x may return value >= 0
[218]              * on success, although only 0 is documented
[219]              */
[220] 
[221]             } else if (rc >= 0 && sent == 0) {
[222] 
[223]                 /*
[224]                  * if rc is OK and sent equal to zero, then someone
[225]                  * has truncated the file, so the offset became beyond
[226]                  * the end of the file
[227]                  */
[228] 
[229]                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[230]                          "sendfile() reported that \"%s\" was truncated at %O",
[231]                          file->file->name.data, file->file_pos);
[232] 
[233]                 return NGX_CHAIN_ERROR;
[234]             }
[235] 
[236]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[237]                            "sendfile: %d, @%O %O:%uz",
[238]                            rc, file->file_pos, sent, file_size + header.size);
[239] 
[240]         } else {
[241]             n = ngx_writev(c, &header);
[242] 
[243]             if (n == NGX_ERROR) {
[244]                 return NGX_CHAIN_ERROR;
[245]             }
[246] 
[247]             sent = (n == NGX_AGAIN) ? 0 : n;
[248]         }
[249] 
[250]         c->sent += sent;
[251] 
[252]         in = ngx_chain_update_sent(in, sent);
[253] 
[254] #if (NGX_HAVE_SENDFILE_NODISKIO)
[255] 
[256]         if (ebusy) {
[257]             if (sent == 0) {
[258]                 c->busy_count++;
[259] 
[260]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[261]                                "sendfile() busy, count:%d", c->busy_count);
[262] 
[263]             } else {
[264]                 c->busy_count = 0;
[265]             }
[266] 
[267]             if (wev->posted) {
[268]                 ngx_delete_posted_event(wev);
[269]             }
[270] 
[271]             ngx_post_event(wev, &ngx_posted_next_events);
[272] 
[273]             wev->ready = 0;
[274]             return in;
[275]         }
[276] 
[277]         c->busy_count = 0;
[278] 
[279] #endif
[280] 
[281]         if (eagain) {
[282] 
[283]             /*
[284]              * sendfile() may return EAGAIN, even if it has sent a whole file
[285]              * part, it indicates that the successive sendfile() call would
[286]              * return EAGAIN right away and would not send anything.
[287]              * We use it as a hint.
[288]              */
[289] 
[290]             wev->ready = 0;
[291]             return in;
[292]         }
[293] 
[294]         if (eintr) {
[295]             send = prev_send + sent;
[296]             continue;
[297]         }
[298] 
[299]         if (send - prev_send != sent) {
[300]             wev->ready = 0;
[301]             return in;
[302]         }
[303] 
[304]         if (send >= limit || in == NULL) {
[305]             return in;
[306]         }
[307]     }
[308] }
