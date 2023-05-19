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
[14] ngx_wsasend(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     int           n;
[17]     u_long        sent;
[18]     ngx_err_t     err;
[19]     ngx_event_t  *wev;
[20]     WSABUF        wsabuf;
[21] 
[22]     wev = c->write;
[23] 
[24]     if (!wev->ready) {
[25]         return NGX_AGAIN;
[26]     }
[27] 
[28]     /*
[29]      * WSABUF must be 4-byte aligned otherwise
[30]      * WSASend() will return undocumented WSAEINVAL error.
[31]      */
[32] 
[33]     wsabuf.buf = (char *) buf;
[34]     wsabuf.len = size;
[35] 
[36]     sent = 0;
[37] 
[38]     n = WSASend(c->fd, &wsabuf, 1, &sent, 0, NULL, NULL);
[39] 
[40]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[41]                    "WSASend: fd:%d, %d, %ul of %uz", c->fd, n, sent, size);
[42] 
[43]     if (n == 0) {
[44]         if (sent < size) {
[45]             wev->ready = 0;
[46]         }
[47] 
[48]         c->sent += sent;
[49] 
[50]         return sent;
[51]     }
[52] 
[53]     err = ngx_socket_errno;
[54] 
[55]     if (err == WSAEWOULDBLOCK) {
[56]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err, "WSASend() not ready");
[57]         wev->ready = 0;
[58]         return NGX_AGAIN;
[59]     }
[60] 
[61]     wev->error = 1;
[62]     ngx_connection_error(c, err, "WSASend() failed");
[63] 
[64]     return NGX_ERROR;
[65] }
[66] 
[67] 
[68] ssize_t
[69] ngx_overlapped_wsasend(ngx_connection_t *c, u_char *buf, size_t size)
[70] {
[71]     int               n;
[72]     u_long            sent;
[73]     ngx_err_t         err;
[74]     ngx_event_t      *wev;
[75]     LPWSAOVERLAPPED   ovlp;
[76]     WSABUF            wsabuf;
[77] 
[78]     wev = c->write;
[79] 
[80]     if (!wev->ready) {
[81]         return NGX_AGAIN;
[82]     }
[83] 
[84]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[85]                    "wev->complete: %d", wev->complete);
[86] 
[87]     if (!wev->complete) {
[88] 
[89]         /* post the overlapped WSASend() */
[90] 
[91]         /*
[92]          * WSABUFs must be 4-byte aligned otherwise
[93]          * WSASend() will return undocumented WSAEINVAL error.
[94]          */
[95] 
[96]         wsabuf.buf = (char *) buf;
[97]         wsabuf.len = size;
[98] 
[99]         sent = 0;
[100] 
[101]         ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
[102]         ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));
[103] 
[104]         n = WSASend(c->fd, &wsabuf, 1, &sent, 0, ovlp, NULL);
[105] 
[106]         ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[107]                        "WSASend: fd:%d, %d, %ul of %uz", c->fd, n, sent, size);
[108] 
[109]         wev->complete = 0;
[110] 
[111]         if (n == 0) {
[112]             if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[113] 
[114]                 /*
[115]                  * if a socket was bound with I/O completion port then
[116]                  * GetQueuedCompletionStatus() would anyway return its status
[117]                  * despite that WSASend() was already complete
[118]                  */
[119] 
[120]                 wev->active = 1;
[121]                 return NGX_AGAIN;
[122]             }
[123] 
[124]             if (sent < size) {
[125]                 wev->ready = 0;
[126]             }
[127] 
[128]             c->sent += sent;
[129] 
[130]             return sent;
[131]         }
[132] 
[133]         err = ngx_socket_errno;
[134] 
[135]         if (err == WSA_IO_PENDING) {
[136]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[137]                            "WSASend() posted");
[138]             wev->active = 1;
[139]             return NGX_AGAIN;
[140]         }
[141] 
[142]         wev->error = 1;
[143]         ngx_connection_error(c, err, "WSASend() failed");
[144] 
[145]         return NGX_ERROR;
[146]     }
[147] 
[148]     /* the overlapped WSASend() complete */
[149] 
[150]     wev->complete = 0;
[151]     wev->active = 0;
[152] 
[153]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[154] 
[155]         if (wev->ovlp.error) {
[156]             ngx_connection_error(c, wev->ovlp.error, "WSASend() failed");
[157]             return NGX_ERROR;
[158]         }
[159] 
[160]         sent = wev->available;
[161] 
[162]     } else {
[163]         if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &wev->ovlp,
[164]                                    &sent, 0, NULL)
[165]             == 0)
[166]         {
[167]             ngx_connection_error(c, ngx_socket_errno,
[168]                            "WSASend() or WSAGetOverlappedResult() failed");
[169] 
[170]             return NGX_ERROR;
[171]         }
[172]     }
[173] 
[174]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[175]                    "WSAGetOverlappedResult: fd:%d, %ul of %uz",
[176]                    c->fd, sent, size);
[177] 
[178]     if (sent < size) {
[179]         wev->ready = 0;
[180]     }
[181] 
[182]     c->sent += sent;
[183] 
[184]     return sent;
[185] }
