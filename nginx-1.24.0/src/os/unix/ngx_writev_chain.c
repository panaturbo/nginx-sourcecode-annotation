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
[13] ngx_chain_t *
[14] ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[15] {
[16]     ssize_t        n, sent;
[17]     off_t          send, prev_send;
[18]     ngx_chain_t   *cl;
[19]     ngx_event_t   *wev;
[20]     ngx_iovec_t    vec;
[21]     struct iovec   iovs[NGX_IOVS_PREALLOCATE];
[22] 
[23]     wev = c->write;
[24] 
[25]     if (!wev->ready) {
[26]         return in;
[27]     }
[28] 
[29] #if (NGX_HAVE_KQUEUE)
[30] 
[31]     if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
[32]         (void) ngx_connection_error(c, wev->kq_errno,
[33]                                "kevent() reported about an closed connection");
[34]         wev->error = 1;
[35]         return NGX_CHAIN_ERROR;
[36]     }
[37] 
[38] #endif
[39] 
[40]     /* the maximum limit size is the maximum size_t value - the page size */
[41] 
[42]     if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
[43]         limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
[44]     }
[45] 
[46]     send = 0;
[47] 
[48]     vec.iovs = iovs;
[49]     vec.nalloc = NGX_IOVS_PREALLOCATE;
[50] 
[51]     for ( ;; ) {
[52]         prev_send = send;
[53] 
[54]         /* create the iovec and coalesce the neighbouring bufs */
[55] 
[56]         cl = ngx_output_chain_to_iovec(&vec, in, limit - send, c->log);
[57] 
[58]         if (cl == NGX_CHAIN_ERROR) {
[59]             return NGX_CHAIN_ERROR;
[60]         }
[61] 
[62]         if (cl && cl->buf->in_file) {
[63]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[64]                           "file buf in writev "
[65]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[66]                           cl->buf->temporary,
[67]                           cl->buf->recycled,
[68]                           cl->buf->in_file,
[69]                           cl->buf->start,
[70]                           cl->buf->pos,
[71]                           cl->buf->last,
[72]                           cl->buf->file,
[73]                           cl->buf->file_pos,
[74]                           cl->buf->file_last);
[75] 
[76]             ngx_debug_point();
[77] 
[78]             return NGX_CHAIN_ERROR;
[79]         }
[80] 
[81]         send += vec.size;
[82] 
[83]         n = ngx_writev(c, &vec);
[84] 
[85]         if (n == NGX_ERROR) {
[86]             return NGX_CHAIN_ERROR;
[87]         }
[88] 
[89]         sent = (n == NGX_AGAIN) ? 0 : n;
[90] 
[91]         c->sent += sent;
[92] 
[93]         in = ngx_chain_update_sent(in, sent);
[94] 
[95]         if (send - prev_send != sent) {
[96]             wev->ready = 0;
[97]             return in;
[98]         }
[99] 
[100]         if (send >= limit || in == NULL) {
[101]             return in;
[102]         }
[103]     }
[104] }
[105] 
[106] 
[107] ngx_chain_t *
[108] ngx_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in, size_t limit,
[109]     ngx_log_t *log)
[110] {
[111]     size_t         total, size;
[112]     u_char        *prev;
[113]     ngx_uint_t     n;
[114]     struct iovec  *iov;
[115] 
[116]     iov = NULL;
[117]     prev = NULL;
[118]     total = 0;
[119]     n = 0;
[120] 
[121]     for ( /* void */ ; in && total < limit; in = in->next) {
[122] 
[123]         if (ngx_buf_special(in->buf)) {
[124]             continue;
[125]         }
[126] 
[127]         if (in->buf->in_file) {
[128]             break;
[129]         }
[130] 
[131]         if (!ngx_buf_in_memory(in->buf)) {
[132]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[133]                           "bad buf in output chain "
[134]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[135]                           in->buf->temporary,
[136]                           in->buf->recycled,
[137]                           in->buf->in_file,
[138]                           in->buf->start,
[139]                           in->buf->pos,
[140]                           in->buf->last,
[141]                           in->buf->file,
[142]                           in->buf->file_pos,
[143]                           in->buf->file_last);
[144] 
[145]             ngx_debug_point();
[146] 
[147]             return NGX_CHAIN_ERROR;
[148]         }
[149] 
[150]         size = in->buf->last - in->buf->pos;
[151] 
[152]         if (size > limit - total) {
[153]             size = limit - total;
[154]         }
[155] 
[156]         if (prev == in->buf->pos) {
[157]             iov->iov_len += size;
[158] 
[159]         } else {
[160]             if (n == vec->nalloc) {
[161]                 break;
[162]             }
[163] 
[164]             iov = &vec->iovs[n++];
[165] 
[166]             iov->iov_base = (void *) in->buf->pos;
[167]             iov->iov_len = size;
[168]         }
[169] 
[170]         prev = in->buf->pos + size;
[171]         total += size;
[172]     }
[173] 
[174]     vec->count = n;
[175]     vec->size = total;
[176] 
[177]     return in;
[178] }
[179] 
[180] 
[181] ssize_t
[182] ngx_writev(ngx_connection_t *c, ngx_iovec_t *vec)
[183] {
[184]     ssize_t    n;
[185]     ngx_err_t  err;
[186] 
[187] eintr:
[188] 
[189]     n = writev(c->fd, vec->iovs, vec->count);
[190] 
[191]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[192]                    "writev: %z of %uz", n, vec->size);
[193] 
[194]     if (n == -1) {
[195]         err = ngx_errno;
[196] 
[197]         switch (err) {
[198]         case NGX_EAGAIN:
[199]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[200]                            "writev() not ready");
[201]             return NGX_AGAIN;
[202] 
[203]         case NGX_EINTR:
[204]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[205]                            "writev() was interrupted");
[206]             goto eintr;
[207] 
[208]         default:
[209]             c->write->error = 1;
[210]             ngx_connection_error(c, err, "writev() failed");
[211]             return NGX_ERROR;
[212]         }
[213]     }
[214] 
[215]     return n;
[216] }
