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
[13] ssize_t
[14] ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *chain, off_t limit)
[15] {
[16]     u_char        *prev;
[17]     ssize_t        n, size;
[18]     ngx_err_t      err;
[19]     ngx_array_t    vec;
[20]     ngx_event_t   *rev;
[21]     struct iovec  *iov, iovs[NGX_IOVS_PREALLOCATE];
[22] 
[23]     rev = c->read;
[24] 
[25] #if (NGX_HAVE_KQUEUE)
[26] 
[27]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[28]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[29]                        "readv: eof:%d, avail:%d, err:%d",
[30]                        rev->pending_eof, rev->available, rev->kq_errno);
[31] 
[32]         if (rev->available == 0) {
[33]             if (rev->pending_eof) {
[34]                 rev->ready = 0;
[35]                 rev->eof = 1;
[36] 
[37]                 ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
[38]                               "kevent() reported about an closed connection");
[39] 
[40]                 if (rev->kq_errno) {
[41]                     rev->error = 1;
[42]                     ngx_set_socket_errno(rev->kq_errno);
[43]                     return NGX_ERROR;
[44]                 }
[45] 
[46]                 return 0;
[47] 
[48]             } else {
[49]                 rev->ready = 0;
[50]                 return NGX_AGAIN;
[51]             }
[52]         }
[53]     }
[54] 
[55] #endif
[56] 
[57] #if (NGX_HAVE_EPOLLRDHUP)
[58] 
[59]     if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
[60]         && ngx_use_epoll_rdhup)
[61]     {
[62]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[63]                        "readv: eof:%d, avail:%d",
[64]                        rev->pending_eof, rev->available);
[65] 
[66]         if (rev->available == 0 && !rev->pending_eof) {
[67]             rev->ready = 0;
[68]             return NGX_AGAIN;
[69]         }
[70]     }
[71] 
[72] #endif
[73] 
[74]     prev = NULL;
[75]     iov = NULL;
[76]     size = 0;
[77] 
[78]     vec.elts = iovs;
[79]     vec.nelts = 0;
[80]     vec.size = sizeof(struct iovec);
[81]     vec.nalloc = NGX_IOVS_PREALLOCATE;
[82]     vec.pool = c->pool;
[83] 
[84]     /* coalesce the neighbouring bufs */
[85] 
[86]     while (chain) {
[87]         n = chain->buf->end - chain->buf->last;
[88] 
[89]         if (limit) {
[90]             if (size >= limit) {
[91]                 break;
[92]             }
[93] 
[94]             if (size + n > limit) {
[95]                 n = (ssize_t) (limit - size);
[96]             }
[97]         }
[98] 
[99]         if (prev == chain->buf->last) {
[100]             iov->iov_len += n;
[101] 
[102]         } else {
[103]             if (vec.nelts == vec.nalloc) {
[104]                 break;
[105]             }
[106] 
[107]             iov = ngx_array_push(&vec);
[108]             if (iov == NULL) {
[109]                 return NGX_ERROR;
[110]             }
[111] 
[112]             iov->iov_base = (void *) chain->buf->last;
[113]             iov->iov_len = n;
[114]         }
[115] 
[116]         size += n;
[117]         prev = chain->buf->end;
[118]         chain = chain->next;
[119]     }
[120] 
[121]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[122]                    "readv: %ui, last:%uz", vec.nelts, iov->iov_len);
[123] 
[124]     do {
[125]         n = readv(c->fd, (struct iovec *) vec.elts, vec.nelts);
[126] 
[127]         if (n == 0) {
[128]             rev->ready = 0;
[129]             rev->eof = 1;
[130] 
[131] #if (NGX_HAVE_KQUEUE)
[132] 
[133]             /*
[134]              * on FreeBSD readv() may return 0 on closed socket
[135]              * even if kqueue reported about available data
[136]              */
[137] 
[138]             if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[139]                 rev->available = 0;
[140]             }
[141] 
[142] #endif
[143] 
[144]             return 0;
[145]         }
[146] 
[147]         if (n > 0) {
[148] 
[149] #if (NGX_HAVE_KQUEUE)
[150] 
[151]             if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[152]                 rev->available -= n;
[153] 
[154]                 /*
[155]                  * rev->available may be negative here because some additional
[156]                  * bytes may be received between kevent() and readv()
[157]                  */
[158] 
[159]                 if (rev->available <= 0) {
[160]                     if (!rev->pending_eof) {
[161]                         rev->ready = 0;
[162]                     }
[163] 
[164]                     rev->available = 0;
[165]                 }
[166] 
[167]                 return n;
[168]             }
[169] 
[170] #endif
[171] 
[172] #if (NGX_HAVE_FIONREAD)
[173] 
[174]             if (rev->available >= 0) {
[175]                 rev->available -= n;
[176] 
[177]                 /*
[178]                  * negative rev->available means some additional bytes
[179]                  * were received between kernel notification and readv(),
[180]                  * and therefore ev->ready can be safely reset even for
[181]                  * edge-triggered event methods
[182]                  */
[183] 
[184]                 if (rev->available < 0) {
[185]                     rev->available = 0;
[186]                     rev->ready = 0;
[187]                 }
[188] 
[189]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[190]                                "readv: avail:%d", rev->available);
[191] 
[192]             } else if (n == size) {
[193] 
[194]                 if (ngx_socket_nread(c->fd, &rev->available) == -1) {
[195]                     n = ngx_connection_error(c, ngx_socket_errno,
[196]                                              ngx_socket_nread_n " failed");
[197]                     break;
[198]                 }
[199] 
[200]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[201]                                "readv: avail:%d", rev->available);
[202]             }
[203] 
[204] #endif
[205] 
[206] #if (NGX_HAVE_EPOLLRDHUP)
[207] 
[208]             if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
[209]                 && ngx_use_epoll_rdhup)
[210]             {
[211]                 if (n < size) {
[212]                     if (!rev->pending_eof) {
[213]                         rev->ready = 0;
[214]                     }
[215] 
[216]                     rev->available = 0;
[217]                 }
[218] 
[219]                 return n;
[220]             }
[221] 
[222] #endif
[223] 
[224]             if (n < size && !(ngx_event_flags & NGX_USE_GREEDY_EVENT)) {
[225]                 rev->ready = 0;
[226]             }
[227] 
[228]             return n;
[229]         }
[230] 
[231]         err = ngx_socket_errno;
[232] 
[233]         if (err == NGX_EAGAIN || err == NGX_EINTR) {
[234]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[235]                            "readv() not ready");
[236]             n = NGX_AGAIN;
[237] 
[238]         } else {
[239]             n = ngx_connection_error(c, err, "readv() failed");
[240]             break;
[241]         }
[242] 
[243]     } while (err == NGX_EINTR);
[244] 
[245]     rev->ready = 0;
[246] 
[247]     if (n == NGX_ERROR) {
[248]         c->read->error = 1;
[249]     }
[250] 
[251]     return n;
[252] }
