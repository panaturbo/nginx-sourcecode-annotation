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
[14] ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     ssize_t       n;
[17]     ngx_err_t     err;
[18]     ngx_event_t  *wev;
[19] 
[20]     wev = c->write;
[21] 
[22] #if (NGX_HAVE_KQUEUE)
[23] 
[24]     if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
[25]         (void) ngx_connection_error(c, wev->kq_errno,
[26]                                "kevent() reported about an closed connection");
[27]         wev->error = 1;
[28]         return NGX_ERROR;
[29]     }
[30] 
[31] #endif
[32] 
[33]     for ( ;; ) {
[34]         n = send(c->fd, buf, size, 0);
[35] 
[36]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[37]                        "send: fd:%d %z of %uz", c->fd, n, size);
[38] 
[39]         if (n > 0) {
[40]             if (n < (ssize_t) size) {
[41]                 wev->ready = 0;
[42]             }
[43] 
[44]             c->sent += n;
[45] 
[46]             return n;
[47]         }
[48] 
[49]         err = ngx_socket_errno;
[50] 
[51]         if (n == 0) {
[52]             ngx_log_error(NGX_LOG_ALERT, c->log, err, "send() returned zero");
[53]             wev->ready = 0;
[54]             return n;
[55]         }
[56] 
[57]         if (err == NGX_EAGAIN || err == NGX_EINTR) {
[58]             wev->ready = 0;
[59] 
[60]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[61]                            "send() not ready");
[62] 
[63]             if (err == NGX_EAGAIN) {
[64]                 return NGX_AGAIN;
[65]             }
[66] 
[67]         } else {
[68]             wev->error = 1;
[69]             (void) ngx_connection_error(c, err, "send() failed");
[70]             return NGX_ERROR;
[71]         }
[72]     }
[73] }
