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
[14] ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     ssize_t       n;
[17]     ngx_err_t     err;
[18]     ngx_event_t  *rev;
[19] 
[20]     rev = c->read;
[21] 
[22] #if (NGX_HAVE_KQUEUE)
[23] 
[24]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[25]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[26]                        "recv: eof:%d, avail:%d, err:%d",
[27]                        rev->pending_eof, rev->available, rev->kq_errno);
[28] 
[29]         if (rev->available == 0) {
[30]             if (rev->pending_eof) {
[31]                 rev->ready = 0;
[32]                 rev->eof = 1;
[33] 
[34]                 if (rev->kq_errno) {
[35]                     rev->error = 1;
[36]                     ngx_set_socket_errno(rev->kq_errno);
[37] 
[38]                     return ngx_connection_error(c, rev->kq_errno,
[39]                                "kevent() reported about an closed connection");
[40]                 }
[41] 
[42]                 return 0;
[43] 
[44]             } else {
[45]                 rev->ready = 0;
[46]                 return NGX_AGAIN;
[47]             }
[48]         }
[49]     }
[50] 
[51] #endif
[52] 
[53] #if (NGX_HAVE_EPOLLRDHUP)
[54] 
[55]     if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
[56]         && ngx_use_epoll_rdhup)
[57]     {
[58]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[59]                        "recv: eof:%d, avail:%d",
[60]                        rev->pending_eof, rev->available);
[61] 
[62]         if (rev->available == 0 && !rev->pending_eof) {
[63]             rev->ready = 0;
[64]             return NGX_AGAIN;
[65]         }
[66]     }
[67] 
[68] #endif
[69] 
[70]     do {
[71]         n = recv(c->fd, buf, size, 0);
[72] 
[73]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[74]                        "recv: fd:%d %z of %uz", c->fd, n, size);
[75] 
[76]         if (n == 0) {
[77]             rev->ready = 0;
[78]             rev->eof = 1;
[79] 
[80] #if (NGX_HAVE_KQUEUE)
[81] 
[82]             /*
[83]              * on FreeBSD recv() may return 0 on closed socket
[84]              * even if kqueue reported about available data
[85]              */
[86] 
[87]             if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[88]                 rev->available = 0;
[89]             }
[90] 
[91] #endif
[92] 
[93]             return 0;
[94]         }
[95] 
[96]         if (n > 0) {
[97] 
[98] #if (NGX_HAVE_KQUEUE)
[99] 
[100]             if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[101]                 rev->available -= n;
[102] 
[103]                 /*
[104]                  * rev->available may be negative here because some additional
[105]                  * bytes may be received between kevent() and recv()
[106]                  */
[107] 
[108]                 if (rev->available <= 0) {
[109]                     if (!rev->pending_eof) {
[110]                         rev->ready = 0;
[111]                     }
[112] 
[113]                     rev->available = 0;
[114]                 }
[115] 
[116]                 return n;
[117]             }
[118] 
[119] #endif
[120] 
[121] #if (NGX_HAVE_FIONREAD)
[122] 
[123]             if (rev->available >= 0) {
[124]                 rev->available -= n;
[125] 
[126]                 /*
[127]                  * negative rev->available means some additional bytes
[128]                  * were received between kernel notification and recv(),
[129]                  * and therefore ev->ready can be safely reset even for
[130]                  * edge-triggered event methods
[131]                  */
[132] 
[133]                 if (rev->available < 0) {
[134]                     rev->available = 0;
[135]                     rev->ready = 0;
[136]                 }
[137] 
[138]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[139]                                "recv: avail:%d", rev->available);
[140] 
[141]             } else if ((size_t) n == size) {
[142] 
[143]                 if (ngx_socket_nread(c->fd, &rev->available) == -1) {
[144]                     n = ngx_connection_error(c, ngx_socket_errno,
[145]                                              ngx_socket_nread_n " failed");
[146]                     break;
[147]                 }
[148] 
[149]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[150]                                "recv: avail:%d", rev->available);
[151]             }
[152] 
[153] #endif
[154] 
[155] #if (NGX_HAVE_EPOLLRDHUP)
[156] 
[157]             if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
[158]                 && ngx_use_epoll_rdhup)
[159]             {
[160]                 if ((size_t) n < size) {
[161]                     if (!rev->pending_eof) {
[162]                         rev->ready = 0;
[163]                     }
[164] 
[165]                     rev->available = 0;
[166]                 }
[167] 
[168]                 return n;
[169]             }
[170] 
[171] #endif
[172] 
[173]             if ((size_t) n < size
[174]                 && !(ngx_event_flags & NGX_USE_GREEDY_EVENT))
[175]             {
[176]                 rev->ready = 0;
[177]             }
[178] 
[179]             return n;
[180]         }
[181] 
[182]         err = ngx_socket_errno;
[183] 
[184]         if (err == NGX_EAGAIN || err == NGX_EINTR) {
[185]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[186]                            "recv() not ready");
[187]             n = NGX_AGAIN;
[188] 
[189]         } else {
[190]             n = ngx_connection_error(c, err, "recv() failed");
[191]             break;
[192]         }
[193] 
[194]     } while (err == NGX_EINTR);
[195] 
[196]     rev->ready = 0;
[197] 
[198]     if (n == NGX_ERROR) {
[199]         rev->error = 1;
[200]     }
[201] 
[202]     return n;
[203] }
