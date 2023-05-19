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
[13] #define NGX_WSABUFS  64
[14] 
[15] 
[16] ssize_t
[17] ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain, off_t limit)
[18] {
[19]     int           rc;
[20]     u_char       *prev;
[21]     u_long        bytes, flags;
[22]     size_t        n, size;
[23]     ngx_err_t     err;
[24]     ngx_array_t   vec;
[25]     ngx_event_t  *rev;
[26]     LPWSABUF      wsabuf;
[27]     WSABUF        wsabufs[NGX_WSABUFS];
[28] 
[29]     prev = NULL;
[30]     wsabuf = NULL;
[31]     flags = 0;
[32]     size = 0;
[33]     bytes = 0;
[34] 
[35]     vec.elts = wsabufs;
[36]     vec.nelts = 0;
[37]     vec.size = sizeof(WSABUF);
[38]     vec.nalloc = NGX_WSABUFS;
[39]     vec.pool = c->pool;
[40] 
[41]     /* coalesce the neighbouring bufs */
[42] 
[43]     while (chain) {
[44]         n = chain->buf->end - chain->buf->last;
[45] 
[46]         if (limit) {
[47]             if (size >= (size_t) limit) {
[48]                 break;
[49]             }
[50] 
[51]             if (size + n > (size_t) limit) {
[52]                 n = (size_t) limit - size;
[53]             }
[54]         }
[55] 
[56]         if (prev == chain->buf->last) {
[57]             wsabuf->len += n;
[58] 
[59]         } else {
[60]             if (vec.nelts == vec.nalloc) {
[61]                 break;
[62]             }
[63] 
[64]             wsabuf = ngx_array_push(&vec);
[65]             if (wsabuf == NULL) {
[66]                 return NGX_ERROR;
[67]             }
[68] 
[69]             wsabuf->buf = (char *) chain->buf->last;
[70]             wsabuf->len = n;
[71]         }
[72] 
[73]         size += n;
[74]         prev = chain->buf->end;
[75]         chain = chain->next;
[76]     }
[77] 
[78]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[79]                    "WSARecv: %d:%d", vec.nelts, wsabuf->len);
[80] 
[81] 
[82]     rc = WSARecv(c->fd, vec.elts, vec.nelts, &bytes, &flags, NULL, NULL);
[83] 
[84]     rev = c->read;
[85] 
[86]     if (rc == -1) {
[87]         rev->ready = 0;
[88]         err = ngx_socket_errno;
[89] 
[90]         if (err == WSAEWOULDBLOCK) {
[91]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[92]                            "WSARecv() not ready");
[93]             return NGX_AGAIN;
[94]         }
[95] 
[96]         rev->error = 1;
[97]         ngx_connection_error(c, err, "WSARecv() failed");
[98]         return NGX_ERROR;
[99]     }
[100] 
[101] #if (NGX_HAVE_FIONREAD)
[102] 
[103]     if (rev->available >= 0 && bytes > 0) {
[104]         rev->available -= bytes;
[105] 
[106]         /*
[107]          * negative rev->available means some additional bytes
[108]          * were received between kernel notification and WSARecv(),
[109]          * and therefore ev->ready can be safely reset even for
[110]          * edge-triggered event methods
[111]          */
[112] 
[113]         if (rev->available < 0) {
[114]             rev->available = 0;
[115]             rev->ready = 0;
[116]         }
[117] 
[118]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[119]                        "WSARecv: avail:%d", rev->available);
[120] 
[121]     } else if (bytes == size) {
[122] 
[123]         if (ngx_socket_nread(c->fd, &rev->available) == -1) {
[124]             rev->ready = 0;
[125]             rev->error = 1;
[126]             ngx_connection_error(c, ngx_socket_errno,
[127]                                  ngx_socket_nread_n " failed");
[128]             return NGX_ERROR;
[129]         }
[130] 
[131]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[132]                        "WSARecv: avail:%d", rev->available);
[133]     }
[134] 
[135] #endif
[136] 
[137]     if (bytes < size) {
[138]         rev->ready = 0;
[139]     }
[140] 
[141]     if (bytes == 0) {
[142]         rev->ready = 0;
[143]         rev->eof = 1;
[144]     }
[145] 
[146]     return bytes;
[147] }
