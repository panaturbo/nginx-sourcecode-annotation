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
[16] ngx_chain_t *
[17] ngx_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[18] {
[19]     int           rc;
[20]     u_char       *prev;
[21]     u_long        size, sent, send, prev_send;
[22]     ngx_err_t     err;
[23]     ngx_event_t  *wev;
[24]     ngx_array_t   vec;
[25]     ngx_chain_t  *cl;
[26]     LPWSABUF      wsabuf;
[27]     WSABUF        wsabufs[NGX_WSABUFS];
[28] 
[29]     wev = c->write;
[30] 
[31]     if (!wev->ready) {
[32]         return in;
[33]     }
[34] 
[35]     /* the maximum limit size is the maximum u_long value - the page size */
[36] 
[37]     if (limit == 0 || limit > (off_t) (NGX_MAX_UINT32_VALUE - ngx_pagesize)) {
[38]         limit = NGX_MAX_UINT32_VALUE - ngx_pagesize;
[39]     }
[40] 
[41]     send = 0;
[42] 
[43]     /*
[44]      * WSABUFs must be 4-byte aligned otherwise
[45]      * WSASend() will return undocumented WSAEINVAL error.
[46]      */
[47] 
[48]     vec.elts = wsabufs;
[49]     vec.size = sizeof(WSABUF);
[50]     vec.nalloc = ngx_min(NGX_WSABUFS, ngx_max_wsabufs);
[51]     vec.pool = c->pool;
[52] 
[53]     for ( ;; ) {
[54]         prev = NULL;
[55]         wsabuf = NULL;
[56]         prev_send = send;
[57] 
[58]         vec.nelts = 0;
[59] 
[60]         /* create the WSABUF and coalesce the neighbouring bufs */
[61] 
[62]         for (cl = in; cl && send < limit; cl = cl->next) {
[63] 
[64]             if (ngx_buf_special(cl->buf)) {
[65]                 continue;
[66]             }
[67] 
[68]             size = cl->buf->last - cl->buf->pos;
[69] 
[70]             if (send + size > limit) {
[71]                 size = (u_long) (limit - send);
[72]             }
[73] 
[74]             if (prev == cl->buf->pos) {
[75]                 wsabuf->len += cl->buf->last - cl->buf->pos;
[76] 
[77]             } else {
[78]                 if (vec.nelts == vec.nalloc) {
[79]                     break;
[80]                 }
[81] 
[82]                 wsabuf = ngx_array_push(&vec);
[83]                 if (wsabuf == NULL) {
[84]                     return NGX_CHAIN_ERROR;
[85]                 }
[86] 
[87]                 wsabuf->buf = (char *) cl->buf->pos;
[88]                 wsabuf->len = cl->buf->last - cl->buf->pos;
[89]             }
[90] 
[91]             prev = cl->buf->last;
[92]             send += size;
[93]         }
[94] 
[95]         sent = 0;
[96] 
[97]         rc = WSASend(c->fd, vec.elts, vec.nelts, &sent, 0, NULL, NULL);
[98] 
[99]         if (rc == -1) {
[100]             err = ngx_errno;
[101] 
[102]             if (err == WSAEWOULDBLOCK) {
[103]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[104]                                "WSASend() not ready");
[105] 
[106]             } else {
[107]                 wev->error = 1;
[108]                 ngx_connection_error(c, err, "WSASend() failed");
[109]                 return NGX_CHAIN_ERROR;
[110]             }
[111]         }
[112] 
[113]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[114]                        "WSASend: fd:%d, s:%ul", c->fd, sent);
[115] 
[116]         c->sent += sent;
[117] 
[118]         in = ngx_chain_update_sent(in, sent);
[119] 
[120]         if (send - prev_send != sent) {
[121]             wev->ready = 0;
[122]             return in;
[123]         }
[124] 
[125]         if (send >= limit || in == NULL) {
[126]             return in;
[127]         }
[128]     }
[129] }
[130] 
[131] 
[132] ngx_chain_t *
[133] ngx_overlapped_wsasend_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[134] {
[135]     int               rc;
[136]     u_char           *prev;
[137]     u_long            size, send, sent;
[138]     ngx_err_t         err;
[139]     ngx_event_t      *wev;
[140]     ngx_array_t       vec;
[141]     ngx_chain_t      *cl;
[142]     LPWSAOVERLAPPED   ovlp;
[143]     LPWSABUF          wsabuf;
[144]     WSABUF            wsabufs[NGX_WSABUFS];
[145] 
[146]     wev = c->write;
[147] 
[148]     if (!wev->ready) {
[149]         return in;
[150]     }
[151] 
[152]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[153]                    "wev->complete: %d", wev->complete);
[154] 
[155]     if (!wev->complete) {
[156] 
[157]         /* post the overlapped WSASend() */
[158] 
[159]         /* the maximum limit size is the maximum u_long value - the page size */
[160] 
[161]         if (limit == 0 || limit > (off_t) (NGX_MAX_UINT32_VALUE - ngx_pagesize))
[162]         {
[163]             limit = NGX_MAX_UINT32_VALUE - ngx_pagesize;
[164]         }
[165] 
[166]         /*
[167]          * WSABUFs must be 4-byte aligned otherwise
[168]          * WSASend() will return undocumented WSAEINVAL error.
[169]          */
[170] 
[171]         vec.elts = wsabufs;
[172]         vec.nelts = 0;
[173]         vec.size = sizeof(WSABUF);
[174]         vec.nalloc = ngx_min(NGX_WSABUFS, ngx_max_wsabufs);
[175]         vec.pool = c->pool;
[176] 
[177]         send = 0;
[178]         prev = NULL;
[179]         wsabuf = NULL;
[180] 
[181]         /* create the WSABUF and coalesce the neighbouring bufs */
[182] 
[183]         for (cl = in; cl && send < limit; cl = cl->next) {
[184] 
[185]             if (ngx_buf_special(cl->buf)) {
[186]                 continue;
[187]             }
[188] 
[189]             size = cl->buf->last - cl->buf->pos;
[190] 
[191]             if (send + size > limit) {
[192]                 size = (u_long) (limit - send);
[193]             }
[194] 
[195]             if (prev == cl->buf->pos) {
[196]                 wsabuf->len += cl->buf->last - cl->buf->pos;
[197] 
[198]             } else {
[199]                 if (vec.nelts == vec.nalloc) {
[200]                     break;
[201]                 }
[202] 
[203]                 wsabuf = ngx_array_push(&vec);
[204]                 if (wsabuf == NULL) {
[205]                     return NGX_CHAIN_ERROR;
[206]                 }
[207] 
[208]                 wsabuf->buf = (char *) cl->buf->pos;
[209]                 wsabuf->len = cl->buf->last - cl->buf->pos;
[210]             }
[211] 
[212]             prev = cl->buf->last;
[213]             send += size;
[214]         }
[215] 
[216]         ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
[217]         ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));
[218] 
[219]         rc = WSASend(c->fd, vec.elts, vec.nelts, &sent, 0, ovlp, NULL);
[220] 
[221]         wev->complete = 0;
[222] 
[223]         if (rc == -1) {
[224]             err = ngx_errno;
[225] 
[226]             if (err == WSA_IO_PENDING) {
[227]                 ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[228]                                "WSASend() posted");
[229]                 wev->active = 1;
[230]                 return in;
[231] 
[232]             } else {
[233]                 wev->error = 1;
[234]                 ngx_connection_error(c, err, "WSASend() failed");
[235]                 return NGX_CHAIN_ERROR;
[236]             }
[237] 
[238]         } else if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[239] 
[240]             /*
[241]              * if a socket was bound with I/O completion port then
[242]              * GetQueuedCompletionStatus() would anyway return its status
[243]              * despite that WSASend() was already complete
[244]              */
[245] 
[246]             wev->active = 1;
[247]             return in;
[248]         }
[249] 
[250]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[251]                        "WSASend: fd:%d, s:%ul", c->fd, sent);
[252] 
[253]     } else {
[254] 
[255]         /* the overlapped WSASend() complete */
[256] 
[257]         wev->complete = 0;
[258]         wev->active = 0;
[259] 
[260]         if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
[261]             if (wev->ovlp.error) {
[262]                 ngx_connection_error(c, wev->ovlp.error, "WSASend() failed");
[263]                 return NGX_CHAIN_ERROR;
[264]             }
[265] 
[266]             sent = wev->available;
[267] 
[268]         } else {
[269]             if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &wev->ovlp,
[270]                                        &sent, 0, NULL)
[271]                 == 0)
[272]             {
[273]                 ngx_connection_error(c, ngx_socket_errno,
[274]                                "WSASend() or WSAGetOverlappedResult() failed");
[275] 
[276]                 return NGX_CHAIN_ERROR;
[277]             }
[278]         }
[279]     }
[280] 
[281]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[282]                    "WSASend ovlp: fd:%d, s:%ul", c->fd, sent);
[283] 
[284]     c->sent += sent;
[285] 
[286]     in = ngx_chain_update_sent(in, sent);
[287] 
[288]     if (in) {
[289]         wev->ready = 0;
[290] 
[291]     } else {
[292]         wev->ready = 1;
[293]     }
[294] 
[295]     return in;
[296] }
