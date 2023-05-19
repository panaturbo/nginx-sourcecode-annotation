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
[14] ngx_wsarecv(ngx_connection_t *c, u_char *buf, size_t size)
[15] {
[16]     int           rc;
[17]     u_long        bytes, flags;
[18]     WSABUF        wsabuf[1];
[19]     ngx_err_t     err;
[20]     ngx_int_t     n;
[21]     ngx_event_t  *rev;
[22] 
[23]     wsabuf[0].buf = (char *) buf;
[24]     wsabuf[0].len = size;
[25]     flags = 0;
[26]     bytes = 0;
[27] 
[28]     rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, NULL, NULL);
[29] 
[30]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[31]                    "WSARecv: fd:%d rc:%d %ul of %z", c->fd, rc, bytes, size);
[32] 
[33]     rev = c->read;
[34] 
[35]     if (rc == -1) {
[36]         rev->ready = 0;
[37]         err = ngx_socket_errno;
[38] 
[39]         if (err == WSAEWOULDBLOCK) {
[40]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[41]                            "WSARecv() not ready");
[42]             return NGX_AGAIN;
[43]         }
[44] 
[45]         n = ngx_connection_error(c, err, "WSARecv() failed");
[46] 
[47]         if (n == NGX_ERROR) {
[48]             rev->error = 1;
[49]         }
[50] 
[51]         return n;
[52]     }
[53] 
[54] #if (NGX_HAVE_FIONREAD)
[55] 
[56]     if (rev->available >= 0 && bytes > 0) {
[57]         rev->available -= bytes;
[58] 
[59]         /*
[60]          * negative rev->available means some additional bytes
[61]          * were received between kernel notification and WSARecv(),
[62]          * and therefore ev->ready can be safely reset even for
[63]          * edge-triggered event methods
[64]          */
[65] 
[66]         if (rev->available < 0) {
[67]             rev->available = 0;
[68]             rev->ready = 0;
[69]         }
[70] 
[71]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[72]                        "WSARecv: avail:%d", rev->available);
[73] 
[74]     } else if (bytes == size) {
[75] 
[76]         if (ngx_socket_nread(c->fd, &rev->available) == -1) {
[77]             n = ngx_connection_error(c, ngx_socket_errno,
[78]                                      ngx_socket_nread_n " failed");
[79] 
[80]             if (n == NGX_ERROR) {
[81]                 rev->ready = 0;
[82]                 rev->error = 1;
[83]             }
[84] 
[85]             return n;
[86]         }
[87] 
[88]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[89]                        "WSARecv: avail:%d", rev->available);
[90]     }
[91] 
[92] #endif
[93] 
[94]     if (bytes < size) {
[95]         rev->ready = 0;
[96]     }
[97] 
[98]     if (bytes == 0) {
[99]         rev->ready = 0;
[100]         rev->eof = 1;
[101]     }
[102] 
[103]     return bytes;
[104] }
[105] 
[106] 
[107] ssize_t
[108] ngx_overlapped_wsarecv(ngx_connection_t *c, u_char *buf, size_t size)
[109] {
[110]     int               rc;
[111]     u_long            bytes, flags;
[112]     WSABUF            wsabuf[1];
[113]     ngx_err_t         err;
[114]     ngx_int_t         n;
[115]     ngx_event_t      *rev;
[116]     LPWSAOVERLAPPED   ovlp;
[117] 
[118]     rev = c->read;
[119] 
[120]     if (!rev->ready) {
[121]         ngx_log_error(NGX_LOG_ALERT, c->log, 0, "second wsa post");
[122]         return NGX_AGAIN;
[123]     }
[124] 
[125]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[126]                    "rev->complete: %d", rev->complete);
[127] 
[128]     if (rev->complete) {
[129]         rev->complete = 0;
[130] 
[131]         if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[132]             if (rev->ovlp.error) {
[133]                 ngx_connection_error(c, rev->ovlp.error, "WSARecv() failed");
[134]                 return NGX_ERROR;
[135]             }
[136] 
[137]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[138]                            "WSARecv ovlp: fd:%d %ul of %z",
[139]                            c->fd, rev->available, size);
[140] 
[141]             return rev->available;
[142]         }
[143] 
[144]         if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &rev->ovlp,
[145]                                    &bytes, 0, NULL)
[146]             == 0)
[147]         {
[148]             ngx_connection_error(c, ngx_socket_errno,
[149]                                "WSARecv() or WSAGetOverlappedResult() failed");
[150]             return NGX_ERROR;
[151]         }
[152] 
[153]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
[154]                        "WSARecv: fd:%d %ul of %z", c->fd, bytes, size);
[155] 
[156]         return bytes;
[157]     }
[158] 
[159]     ovlp = (LPWSAOVERLAPPED) &rev->ovlp;
[160]     ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));
[161]     wsabuf[0].buf = (char *) buf;
[162]     wsabuf[0].len = size;
[163]     flags = 0;
[164]     bytes = 0;
[165] 
[166]     rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, ovlp, NULL);
[167] 
[168]     rev->complete = 0;
[169] 
[170]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, c->log, 0,
[171]                    "WSARecv ovlp: fd:%d rc:%d %ul of %z",
[172]                    c->fd, rc, bytes, size);
[173] 
[174]     if (rc == -1) {
[175]         err = ngx_socket_errno;
[176]         if (err == WSA_IO_PENDING) {
[177]             rev->active = 1;
[178]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[179]                            "WSARecv() posted");
[180]             return NGX_AGAIN;
[181]         }
[182] 
[183]         n = ngx_connection_error(c, err, "WSARecv() failed");
[184] 
[185]         if (n == NGX_ERROR) {
[186]             rev->error = 1;
[187]         }
[188] 
[189]         return n;
[190]     }
[191] 
[192]     if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[193] 
[194]         /*
[195]          * if a socket was bound with I/O completion port
[196]          * then GetQueuedCompletionStatus() would anyway return its status
[197]          * despite that WSARecv() was already complete
[198]          */
[199] 
[200]         rev->active = 1;
[201]         return NGX_AGAIN;
[202]     }
[203] 
[204]     if (bytes == 0) {
[205]         rev->eof = 1;
[206]         rev->ready = 0;
[207] 
[208]     } else {
[209]         rev->ready = 1;
[210]     }
[211] 
[212]     rev->active = 0;
[213] 
[214]     return bytes;
[215] }
