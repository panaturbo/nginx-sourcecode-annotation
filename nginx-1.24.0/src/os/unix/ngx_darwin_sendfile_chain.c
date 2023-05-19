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
[14]  * It seems that Darwin 9.4 (Mac OS X 1.5) sendfile() has the same
[15]  * old bug as early FreeBSD sendfile() syscall:
[16]  * http://bugs.freebsd.org/33771
[17]  *
[18]  * Besides sendfile() has another bug: if one calls sendfile()
[19]  * with both a header and a trailer, then sendfile() ignores a file part
[20]  * at all and sends only the header and the trailer together.
[21]  * For this reason we send a trailer only if there is no a header.
[22]  *
[23]  * Although sendfile() allows to pass a header or a trailer,
[24]  * it may send the header or the trailer and a part of the file
[25]  * in different packets.  And FreeBSD workaround (TCP_NOPUSH option)
[26]  * does not help.
[27]  */
[28] 
[29] 
[30] ngx_chain_t *
[31] ngx_darwin_sendfile_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[32] {
[33]     int              rc;
[34]     off_t            send, prev_send, sent;
[35]     off_t            file_size;
[36]     ssize_t          n;
[37]     ngx_uint_t       eintr;
[38]     ngx_err_t        err;
[39]     ngx_buf_t       *file;
[40]     ngx_event_t     *wev;
[41]     ngx_chain_t     *cl;
[42]     ngx_iovec_t      header, trailer;
[43]     struct sf_hdtr   hdtr;
[44]     struct iovec     headers[NGX_IOVS_PREALLOCATE];
[45]     struct iovec     trailers[NGX_IOVS_PREALLOCATE];
[46] 
[47]     wev = c->write;
[48] 
[49]     if (!wev->ready) {
[50]         return in;
[51]     }
[52] 
[53] #if (NGX_HAVE_KQUEUE)
[54] 
[55]     if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
[56]         (void) ngx_connection_error(c, wev->kq_errno,
[57]                                "kevent() reported about an closed connection");
[58]         wev->error = 1;
[59]         return NGX_CHAIN_ERROR;
[60]     }
[61] 
[62] #endif
[63] 
[64]     /* the maximum limit size is the maximum size_t value - the page size */
[65] 
[66]     if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
[67]         limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
[68]     }
[69] 
[70]     send = 0;
[71] 
[72]     header.iovs = headers;
[73]     header.nalloc = NGX_IOVS_PREALLOCATE;
[74] 
[75]     trailer.iovs = trailers;
[76]     trailer.nalloc = NGX_IOVS_PREALLOCATE;
[77] 
[78]     for ( ;; ) {
[79]         eintr = 0;
[80]         prev_send = send;
[81] 
[82]         /* create the header iovec and coalesce the neighbouring bufs */
[83] 
[84]         cl = ngx_output_chain_to_iovec(&header, in, limit - send, c->log);
[85] 
[86]         if (cl == NGX_CHAIN_ERROR) {
[87]             return NGX_CHAIN_ERROR;
[88]         }
[89] 
[90]         send += header.size;
[91] 
[92]         if (cl && cl->buf->in_file && send < limit) {
[93]             file = cl->buf;
[94] 
[95]             /* coalesce the neighbouring file bufs */
[96] 
[97]             file_size = ngx_chain_coalesce_file(&cl, limit - send);
[98] 
[99]             send += file_size;
[100] 
[101]             if (header.count == 0 && send < limit) {
[102] 
[103]                 /*
[104]                  * create the trailer iovec and coalesce the neighbouring bufs
[105]                  */
[106] 
[107]                 cl = ngx_output_chain_to_iovec(&trailer, cl, limit - send,
[108]                                                c->log);
[109]                 if (cl == NGX_CHAIN_ERROR) {
[110]                     return NGX_CHAIN_ERROR;
[111]                 }
[112] 
[113]                 send += trailer.size;
[114] 
[115]             } else {
[116]                 trailer.count = 0;
[117]             }
[118] 
[119]             /*
[120]              * sendfile() returns EINVAL if sf_hdtr's count is 0,
[121]              * but corresponding pointer is not NULL
[122]              */
[123] 
[124]             hdtr.headers = header.count ? header.iovs : NULL;
[125]             hdtr.hdr_cnt = header.count;
[126]             hdtr.trailers = trailer.count ? trailer.iovs : NULL;
[127]             hdtr.trl_cnt = trailer.count;
[128] 
[129]             sent = header.size + file_size;
[130] 
[131]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[132]                            "sendfile: @%O %O h:%uz",
[133]                            file->file_pos, sent, header.size);
[134] 
[135]             rc = sendfile(file->file->fd, c->fd, file->file_pos,
[136]                           &sent, &hdtr, 0);
[137] 
[138]             if (rc == -1) {
[139]                 err = ngx_errno;
[140] 
[141]                 switch (err) {
[142]                 case NGX_EAGAIN:
[143]                     break;
[144] 
[145]                 case NGX_EINTR:
[146]                     eintr = 1;
[147]                     break;
[148] 
[149]                 default:
[150]                     wev->error = 1;
[151]                     (void) ngx_connection_error(c, err, "sendfile() failed");
[152]                     return NGX_CHAIN_ERROR;
[153]                 }
[154] 
[155]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, err,
[156]                                "sendfile() sent only %O bytes", sent);
[157]             }
[158] 
[159]             if (rc == 0 && sent == 0) {
[160] 
[161]                 /*
[162]                  * if rc and sent equal to zero, then someone
[163]                  * has truncated the file, so the offset became beyond
[164]                  * the end of the file
[165]                  */
[166] 
[167]                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[168]                               "sendfile() reported that \"%s\" was truncated",
[169]                               file->file->name.data);
[170] 
[171]                 return NGX_CHAIN_ERROR;
[172]             }
[173] 
[174]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[175]                            "sendfile: %d, @%O %O:%O",
[176]                            rc, file->file_pos, sent, file_size + header.size);
[177] 
[178]         } else {
[179]             n = ngx_writev(c, &header);
[180] 
[181]             if (n == NGX_ERROR) {
[182]                 return NGX_CHAIN_ERROR;
[183]             }
[184] 
[185]             sent = (n == NGX_AGAIN) ? 0 : n;
[186]         }
[187] 
[188]         c->sent += sent;
[189] 
[190]         in = ngx_chain_update_sent(in, sent);
[191] 
[192]         if (eintr) {
[193]             send = prev_send + sent;
[194]             continue;
[195]         }
[196] 
[197]         if (send - prev_send != sent) {
[198]             wev->ready = 0;
[199]             return in;
[200]         }
[201] 
[202]         if (send >= limit || in == NULL) {
[203]             return in;
[204]         }
[205]     }
[206] }
