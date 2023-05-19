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
[14] ngx_udp_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     ssize_t       n;
[17]     ngx_err_t     err;
[18]     ngx_event_t  *rev;
[19] 
[20]     rev = c->read;
[21] 
[22]     do {
[23]         n = recv(c->fd, buf, size, 0);
[24] 
[25]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[26]                        "recv: fd:%d %z of %uz", c->fd, n, size);
[27] 
[28]         if (n >= 0) {
[29] 
[30] #if (NGX_HAVE_KQUEUE)
[31] 
[32]             if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[33]                 rev->available -= n;
[34] 
[35]                 /*
[36]                  * rev->available may be negative here because some additional
[37]                  * bytes may be received between kevent() and recv()
[38]                  */
[39] 
[40]                 if (rev->available <= 0) {
[41]                     rev->ready = 0;
[42]                     rev->available = 0;
[43]                 }
[44]             }
[45] 
[46] #endif
[47] 
[48]             return n;
[49]         }
[50] 
[51]         err = ngx_socket_errno;
[52] 
[53]         if (err == NGX_EAGAIN || err == NGX_EINTR) {
[54]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[55]                            "recv() not ready");
[56]             n = NGX_AGAIN;
[57] 
[58]         } else {
[59]             n = ngx_connection_error(c, err, "recv() failed");
[60]             break;
[61]         }
[62] 
[63]     } while (err == NGX_EINTR);
[64] 
[65]     rev->ready = 0;
[66] 
[67]     if (n == NGX_ERROR) {
[68]         rev->error = 1;
[69]     }
[70] 
[71]     return n;
[72] }
