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
[14] ngx_udp_wsarecv(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     int           rc;
[17]     u_long        bytes, flags;
[18]     WSABUF        wsabuf[1];
[19]     ngx_err_t     err;
[20]     ngx_event_t  *rev;
[21] 
[22]     wsabuf[0].buf = (char *) buf;
[23]     wsabuf[0].len = size;
[24]     flags = 0;
[25]     bytes = 0;
[26] 
[27]     rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, NULL, NULL);
[28] 
[29]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[30]                    "WSARecv: fd:%d rc:%d %ul of %z", c->fd, rc, bytes, size);
[31] 
[32]     rev = c->read;
[33] 
[34]     if (rc == -1) {
[35]         rev->ready = 0;
[36]         err = ngx_socket_errno;
[37] 
[38]         if (err == WSAEWOULDBLOCK) {
[39]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[40]                            "WSARecv() not ready");
[41]             return NGX_AGAIN;
[42]         }
[43] 
[44]         rev->error = 1;
[45]         ngx_connection_error(c, err, "WSARecv() failed");
[46] 
[47]         return NGX_ERROR;
[48]     }
[49] 
[50]     return bytes;
[51] }
[52] 
[53] 
[54] ssize_t
[55] ngx_udp_overlapped_wsarecv(ngx_connection_t *c, u_char *buf, size_t size)
[56] {
[57]     int               rc;
[58]     u_long            bytes, flags;
[59]     WSABUF            wsabuf[1];
[60]     ngx_err_t         err;
[61]     ngx_event_t      *rev;
[62]     LPWSAOVERLAPPED   ovlp;
[63] 
[64]     rev = c->read;
[65] 
[66]     if (!rev->ready) {
[67]         ngx_log_error(NGX_LOG_ALERT, c->log, 0, "second wsa post");
[68]         return NGX_AGAIN;
[69]     }
[70] 
[71]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[72]                    "rev->complete: %d", rev->complete);
[73] 
[74]     if (rev->complete) {
[75]         rev->complete = 0;
[76] 
[77]         if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[78]             if (rev->ovlp.error) {
[79]                 ngx_connection_error(c, rev->ovlp.error, "WSARecv() failed");
[80]                 return NGX_ERROR;
[81]             }
[82] 
[83]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[84]                            "WSARecv ovlp: fd:%d %ul of %z",
[85]                            c->fd, rev->available, size);
[86] 
[87]             return rev->available;
[88]         }
[89] 
[90]         if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &rev->ovlp,
[91]                                    &bytes, 0, NULL)
[92]             == 0)
[93]         {
[94]             ngx_connection_error(c, ngx_socket_errno,
[95]                                "WSARecv() or WSAGetOverlappedResult() failed");
[96]             return NGX_ERROR;
[97]         }
[98] 
[99]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[100]                        "WSARecv: fd:%d %ul of %z", c->fd, bytes, size);
[101] 
[102]         return bytes;
[103]     }
[104] 
[105]     ovlp = (LPWSAOVERLAPPED) &rev->ovlp;
[106]     ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));
[107]     wsabuf[0].buf = (char *) buf;
[108]     wsabuf[0].len = size;
[109]     flags = 0;
[110]     bytes = 0;
[111] 
[112]     rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, ovlp, NULL);
[113] 
[114]     rev->complete = 0;
[115] 
[116]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[117]                    "WSARecv ovlp: fd:%d rc:%d %ul of %z",
[118]                    c->fd, rc, bytes, size);
[119] 
[120]     if (rc == -1) {
[121]         err = ngx_socket_errno;
[122]         if (err == WSA_IO_PENDING) {
[123]             rev->active = 1;
[124]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[125]                            "WSARecv() posted");
[126]             return NGX_AGAIN;
[127]         }
[128] 
[129]         rev->error = 1;
[130]         ngx_connection_error(c, err, "WSARecv() failed");
[131]         return NGX_ERROR;
[132]     }
[133] 
[134]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[135] 
[136]         /*
[137]          * if a socket was bound with I/O completion port
[138]          * then GetQueuedCompletionStatus() would anyway return its status
[139]          * despite that WSARecv() was already complete
[140]          */
[141] 
[142]         rev->active = 1;
[143]         return NGX_AGAIN;
[144]     }
[145] 
[146]     rev->active = 0;
[147] 
[148]     return bytes;
[149] }
