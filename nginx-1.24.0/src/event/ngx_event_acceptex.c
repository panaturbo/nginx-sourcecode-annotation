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
[13] static void ngx_close_posted_connection(ngx_connection_t *c);
[14] 
[15] 
[16] void
[17] ngx_event_acceptex(ngx_event_t *rev)
[18] {
[19]     ngx_listening_t   *ls;
[20]     ngx_connection_t  *c;
[21] 
[22]     c = rev->data;
[23]     ls = c->listening;
[24] 
[25]     c->log->handler = ngx_accept_log_error;
[26] 
[27]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "AcceptEx: %d", c->fd);
[28] 
[29]     if (rev->ovlp.error) {
[30]         ngx_log_error(NGX_LOG_CRIT, c->log, rev->ovlp.error,
[31]                       "AcceptEx() %V failed", &ls->addr_text);
[32]         return;
[33]     }
[34] 
[35]     /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */
[36] 
[37]     if (setsockopt(c->fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
[38]                    (char *) &ls->fd, sizeof(ngx_socket_t))
[39]         == -1)
[40]     {
[41]         ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
[42]                       "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed for %V",
[43]                       &c->addr_text);
[44]         /* TODO: close socket */
[45]         return;
[46]     }
[47] 
[48]     ngx_getacceptexsockaddrs(c->buffer->pos,
[49]                              ls->post_accept_buffer_size,
[50]                              ls->socklen + 16,
[51]                              ls->socklen + 16,
[52]                              &c->local_sockaddr, &c->local_socklen,
[53]                              &c->sockaddr, &c->socklen);
[54] 
[55]     if (ls->post_accept_buffer_size) {
[56]         c->buffer->last += rev->available;
[57]         c->buffer->end = c->buffer->start + ls->post_accept_buffer_size;
[58] 
[59]     } else {
[60]         c->buffer = NULL;
[61]     }
[62] 
[63]     if (ls->addr_ntop) {
[64]         c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
[65]         if (c->addr_text.data == NULL) {
[66]             /* TODO: close socket */
[67]             return;
[68]         }
[69] 
[70]         c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
[71]                                          c->addr_text.data,
[72]                                          ls->addr_text_max_len, 0);
[73]         if (c->addr_text.len == 0) {
[74]             /* TODO: close socket */
[75]             return;
[76]         }
[77]     }
[78] 
[79]     ngx_event_post_acceptex(ls, 1);
[80] 
[81]     c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
[82] 
[83]     c->start_time = ngx_current_msec;
[84] 
[85]     ls->handler(c);
[86] 
[87]     return;
[88] 
[89] }
[90] 
[91] 
[92] ngx_int_t
[93] ngx_event_post_acceptex(ngx_listening_t *ls, ngx_uint_t n)
[94] {
[95]     u_long             rcvd;
[96]     ngx_err_t          err;
[97]     ngx_log_t         *log;
[98]     ngx_uint_t         i;
[99]     ngx_event_t       *rev, *wev;
[100]     ngx_socket_t       s;
[101]     ngx_connection_t  *c;
[102] 
[103]     for (i = 0; i < n; i++) {
[104] 
[105]         /* TODO: look up reused sockets */
[106] 
[107]         s = ngx_socket(ls->sockaddr->sa_family, ls->type, 0);
[108] 
[109]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, &ls->log, 0,
[110]                        ngx_socket_n " s:%d", s);
[111] 
[112]         if (s == (ngx_socket_t) -1) {
[113]             ngx_log_error(NGX_LOG_ALERT, &ls->log, ngx_socket_errno,
[114]                           ngx_socket_n " failed");
[115] 
[116]             return NGX_ERROR;
[117]         }
[118] 
[119]         c = ngx_get_connection(s, &ls->log);
[120] 
[121]         if (c == NULL) {
[122]             return NGX_ERROR;
[123]         }
[124] 
[125]         c->pool = ngx_create_pool(ls->pool_size, &ls->log);
[126]         if (c->pool == NULL) {
[127]             ngx_close_posted_connection(c);
[128]             return NGX_ERROR;
[129]         }
[130] 
[131]         log = ngx_palloc(c->pool, sizeof(ngx_log_t));
[132]         if (log == NULL) {
[133]             ngx_close_posted_connection(c);
[134]             return NGX_ERROR;
[135]         }
[136] 
[137]         c->buffer = ngx_create_temp_buf(c->pool, ls->post_accept_buffer_size
[138]                                                  + 2 * (ls->socklen + 16));
[139]         if (c->buffer == NULL) {
[140]             ngx_close_posted_connection(c);
[141]             return NGX_ERROR;
[142]         }
[143] 
[144]         c->local_sockaddr = ngx_palloc(c->pool, ls->socklen);
[145]         if (c->local_sockaddr == NULL) {
[146]             ngx_close_posted_connection(c);
[147]             return NGX_ERROR;
[148]         }
[149] 
[150]         c->sockaddr = ngx_palloc(c->pool, ls->socklen);
[151]         if (c->sockaddr == NULL) {
[152]             ngx_close_posted_connection(c);
[153]             return NGX_ERROR;
[154]         }
[155] 
[156]         *log = ls->log;
[157]         c->log = log;
[158] 
[159]         c->recv = ngx_recv;
[160]         c->send = ngx_send;
[161]         c->recv_chain = ngx_recv_chain;
[162]         c->send_chain = ngx_send_chain;
[163] 
[164]         c->listening = ls;
[165] 
[166]         rev = c->read;
[167]         wev = c->write;
[168] 
[169]         rev->ovlp.event = rev;
[170]         wev->ovlp.event = wev;
[171]         rev->handler = ngx_event_acceptex;
[172] 
[173]         rev->ready = 1;
[174]         wev->ready = 1;
[175] 
[176]         rev->log = c->log;
[177]         wev->log = c->log;
[178] 
[179]         if (ngx_add_event(rev, 0, NGX_IOCP_IO) == NGX_ERROR) {
[180]             ngx_close_posted_connection(c);
[181]             return NGX_ERROR;
[182]         }
[183] 
[184]         if (ngx_acceptex(ls->fd, s, c->buffer->pos, ls->post_accept_buffer_size,
[185]                          ls->socklen + 16, ls->socklen + 16,
[186]                          &rcvd, (LPOVERLAPPED) &rev->ovlp)
[187]             == 0)
[188]         {
[189]             err = ngx_socket_errno;
[190]             if (err != WSA_IO_PENDING) {
[191]                 ngx_log_error(NGX_LOG_ALERT, &ls->log, err,
[192]                               "AcceptEx() %V failed", &ls->addr_text);
[193] 
[194]                 ngx_close_posted_connection(c);
[195]                 return NGX_ERROR;
[196]             }
[197]         }
[198]     }
[199] 
[200]     return NGX_OK;
[201] }
[202] 
[203] 
[204] static void
[205] ngx_close_posted_connection(ngx_connection_t *c)
[206] {
[207]     ngx_socket_t  fd;
[208] 
[209]     ngx_free_connection(c);
[210] 
[211]     fd = c->fd;
[212]     c->fd = (ngx_socket_t) -1;
[213] 
[214]     if (ngx_close_socket(fd) == -1) {
[215]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
[216]                       ngx_close_socket_n " failed");
[217]     }
[218] 
[219]     if (c->pool) {
[220]         ngx_destroy_pool(c->pool);
[221]     }
[222] }
[223] 
[224] 
[225] u_char *
[226] ngx_acceptex_log_error(ngx_log_t *log, u_char *buf, size_t len)
[227] {
[228]     return ngx_snprintf(buf, len, " while posting AcceptEx() on %V", log->data);
[229] }
