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
[14] ngx_udp_unix_send(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     ssize_t       n;
[17]     ngx_err_t     err;
[18]     ngx_event_t  *wev;
[19] 
[20]     wev = c->write;
[21] 
[22]     for ( ;; ) {
[23]         n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);
[24] 
[25]         ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[26]                        "sendto: fd:%d %z of %uz to \"%V\"",
[27]                        c->fd, n, size, &c->addr_text);
[28] 
[29]         if (n >= 0) {
[30]             if ((size_t) n != size) {
[31]                 wev->error = 1;
[32]                 (void) ngx_connection_error(c, 0, "sendto() incomplete");
[33]                 return NGX_ERROR;
[34]             }
[35] 
[36]             c->sent += n;
[37] 
[38]             return n;
[39]         }
[40] 
[41]         err = ngx_socket_errno;
[42] 
[43]         if (err == NGX_EAGAIN) {
[44]             wev->ready = 0;
[45]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, NGX_EAGAIN,
[46]                            "sendto() not ready");
[47]             return NGX_AGAIN;
[48]         }
[49] 
[50]         if (err != NGX_EINTR) {
[51]             wev->error = 1;
[52]             (void) ngx_connection_error(c, err, "sendto() failed");
[53]             return NGX_ERROR;
[54]         }
[55]     }
[56] }
