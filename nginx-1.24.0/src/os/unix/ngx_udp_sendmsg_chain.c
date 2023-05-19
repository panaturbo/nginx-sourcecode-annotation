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
[13] static ngx_chain_t *ngx_udp_output_chain_to_iovec(ngx_iovec_t *vec,
[14]     ngx_chain_t *in, ngx_log_t *log);
[15] static ssize_t ngx_sendmsg_vec(ngx_connection_t *c, ngx_iovec_t *vec);
[16] 
[17] 
[18] ngx_chain_t *
[19] ngx_udp_unix_sendmsg_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[20] {
[21]     ssize_t        n;
[22]     off_t          send;
[23]     ngx_chain_t   *cl;
[24]     ngx_event_t   *wev;
[25]     ngx_iovec_t    vec;
[26]     struct iovec   iovs[NGX_IOVS_PREALLOCATE];
[27] 
[28]     wev = c->write;
[29] 
[30]     if (!wev->ready) {
[31]         return in;
[32]     }
[33] 
[34] #if (NGX_HAVE_KQUEUE)
[35] 
[36]     if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
[37]         (void) ngx_connection_error(c, wev->kq_errno,
[38]                                "kevent() reported about an closed connection");
[39]         wev->error = 1;
[40]         return NGX_CHAIN_ERROR;
[41]     }
[42] 
[43] #endif
[44] 
[45]     /* the maximum limit size is the maximum size_t value - the page size */
[46] 
[47]     if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
[48]         limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
[49]     }
[50] 
[51]     send = 0;
[52] 
[53]     vec.iovs = iovs;
[54]     vec.nalloc = NGX_IOVS_PREALLOCATE;
[55] 
[56]     for ( ;; ) {
[57] 
[58]         /* create the iovec and coalesce the neighbouring bufs */
[59] 
[60]         cl = ngx_udp_output_chain_to_iovec(&vec, in, c->log);
[61] 
[62]         if (cl == NGX_CHAIN_ERROR) {
[63]             return NGX_CHAIN_ERROR;
[64]         }
[65] 
[66]         if (cl && cl->buf->in_file) {
[67]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[68]                           "file buf in sendmsg "
[69]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[70]                           cl->buf->temporary,
[71]                           cl->buf->recycled,
[72]                           cl->buf->in_file,
[73]                           cl->buf->start,
[74]                           cl->buf->pos,
[75]                           cl->buf->last,
[76]                           cl->buf->file,
[77]                           cl->buf->file_pos,
[78]                           cl->buf->file_last);
[79] 
[80]             ngx_debug_point();
[81] 
[82]             return NGX_CHAIN_ERROR;
[83]         }
[84] 
[85]         if (cl == in) {
[86]             return in;
[87]         }
[88] 
[89]         send += vec.size;
[90] 
[91]         n = ngx_sendmsg_vec(c, &vec);
[92] 
[93]         if (n == NGX_ERROR) {
[94]             return NGX_CHAIN_ERROR;
[95]         }
[96] 
[97]         if (n == NGX_AGAIN) {
[98]             wev->ready = 0;
[99]             return in;
[100]         }
[101] 
[102]         c->sent += n;
[103] 
[104]         in = ngx_chain_update_sent(in, n);
[105] 
[106]         if (send >= limit || in == NULL) {
[107]             return in;
[108]         }
[109]     }
[110] }
[111] 
[112] 
[113] static ngx_chain_t *
[114] ngx_udp_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in, ngx_log_t *log)
[115] {
[116]     size_t         total, size;
[117]     u_char        *prev;
[118]     ngx_uint_t     n, flush;
[119]     ngx_chain_t   *cl;
[120]     struct iovec  *iov;
[121] 
[122]     cl = in;
[123]     iov = NULL;
[124]     prev = NULL;
[125]     total = 0;
[126]     n = 0;
[127]     flush = 0;
[128] 
[129]     for ( /* void */ ; in && !flush; in = in->next) {
[130] 
[131]         if (in->buf->flush || in->buf->last_buf) {
[132]             flush = 1;
[133]         }
[134] 
[135]         if (ngx_buf_special(in->buf)) {
[136]             continue;
[137]         }
[138] 
[139]         if (in->buf->in_file) {
[140]             break;
[141]         }
[142] 
[143]         if (!ngx_buf_in_memory(in->buf)) {
[144]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[145]                           "bad buf in output chain "
[146]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[147]                           in->buf->temporary,
[148]                           in->buf->recycled,
[149]                           in->buf->in_file,
[150]                           in->buf->start,
[151]                           in->buf->pos,
[152]                           in->buf->last,
[153]                           in->buf->file,
[154]                           in->buf->file_pos,
[155]                           in->buf->file_last);
[156] 
[157]             ngx_debug_point();
[158] 
[159]             return NGX_CHAIN_ERROR;
[160]         }
[161] 
[162]         size = in->buf->last - in->buf->pos;
[163] 
[164]         if (prev == in->buf->pos) {
[165]             iov->iov_len += size;
[166] 
[167]         } else {
[168]             if (n == vec->nalloc) {
[169]                 ngx_log_error(NGX_LOG_ALERT, log, 0,
[170]                               "too many parts in a datagram");
[171]                 return NGX_CHAIN_ERROR;
[172]             }
[173] 
[174]             iov = &vec->iovs[n++];
[175] 
[176]             iov->iov_base = (void *) in->buf->pos;
[177]             iov->iov_len = size;
[178]         }
[179] 
[180]         prev = in->buf->pos + size;
[181]         total += size;
[182]     }
[183] 
[184]     if (!flush) {
[185] #if (NGX_SUPPRESS_WARN)
[186]         vec->size = 0;
[187]         vec->count = 0;
[188] #endif
[189]         return cl;
[190]     }
[191] 
[192]     /* zero-sized datagram; pretend to have at least 1 iov */
[193]     if (n == 0) {
[194]         iov = &vec->iovs[n++];
[195]         iov->iov_base = NULL;
[196]         iov->iov_len = 0;
[197]     }
[198] 
[199]     vec->count = n;
[200]     vec->size = total;
[201] 
[202]     return in;
[203] }
[204] 
[205] 
[206] static ssize_t
[207] ngx_sendmsg_vec(ngx_connection_t *c, ngx_iovec_t *vec)
[208] {
[209]     struct msghdr    msg;
[210] 
[211] #if (NGX_HAVE_ADDRINFO_CMSG)
[212]     struct cmsghdr  *cmsg;
[213]     u_char           msg_control[CMSG_SPACE(sizeof(ngx_addrinfo_t))];
[214] #endif
[215] 
[216]     ngx_memzero(&msg, sizeof(struct msghdr));
[217] 
[218]     if (c->socklen) {
[219]         msg.msg_name = c->sockaddr;
[220]         msg.msg_namelen = c->socklen;
[221]     }
[222] 
[223]     msg.msg_iov = vec->iovs;
[224]     msg.msg_iovlen = vec->count;
[225] 
[226] #if (NGX_HAVE_ADDRINFO_CMSG)
[227]     if (c->listening && c->listening->wildcard && c->local_sockaddr) {
[228] 
[229]         msg.msg_control = msg_control;
[230]         msg.msg_controllen = sizeof(msg_control);
[231]         ngx_memzero(msg_control, sizeof(msg_control));
[232] 
[233]         cmsg = CMSG_FIRSTHDR(&msg);
[234] 
[235]         msg.msg_controllen = ngx_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
[236]     }
[237] #endif
[238] 
[239]     return ngx_sendmsg(c, &msg, 0);
[240] }
[241] 
[242] 
[243] #if (NGX_HAVE_ADDRINFO_CMSG)
[244] 
[245] size_t
[246] ngx_set_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *local_sockaddr)
[247] {
[248]     size_t                len;
[249] #if (NGX_HAVE_IP_SENDSRCADDR)
[250]     struct in_addr       *addr;
[251]     struct sockaddr_in   *sin;
[252] #elif (NGX_HAVE_IP_PKTINFO)
[253]     struct in_pktinfo    *pkt;
[254]     struct sockaddr_in   *sin;
[255] #endif
[256] 
[257] #if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
[258]     struct in6_pktinfo   *pkt6;
[259]     struct sockaddr_in6  *sin6;
[260] #endif
[261] 
[262] 
[263] #if (NGX_HAVE_IP_SENDSRCADDR) || (NGX_HAVE_IP_PKTINFO)
[264] 
[265]     if (local_sockaddr->sa_family == AF_INET) {
[266] 
[267]         cmsg->cmsg_level = IPPROTO_IP;
[268] 
[269] #if (NGX_HAVE_IP_SENDSRCADDR)
[270] 
[271]         cmsg->cmsg_type = IP_SENDSRCADDR;
[272]         cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
[273]         len = CMSG_SPACE(sizeof(struct in_addr));
[274] 
[275]         sin = (struct sockaddr_in *) local_sockaddr;
[276] 
[277]         addr = (struct in_addr *) CMSG_DATA(cmsg);
[278]         *addr = sin->sin_addr;
[279] 
[280] #elif (NGX_HAVE_IP_PKTINFO)
[281] 
[282]         cmsg->cmsg_type = IP_PKTINFO;
[283]         cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
[284]         len = CMSG_SPACE(sizeof(struct in_pktinfo));
[285] 
[286]         sin = (struct sockaddr_in *) local_sockaddr;
[287] 
[288]         pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
[289]         ngx_memzero(pkt, sizeof(struct in_pktinfo));
[290]         pkt->ipi_spec_dst = sin->sin_addr;
[291] 
[292] #endif
[293]         return len;
[294]     }
[295] 
[296] #endif
[297] 
[298] #if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
[299]     if (local_sockaddr->sa_family == AF_INET6) {
[300] 
[301]         cmsg->cmsg_level = IPPROTO_IPV6;
[302]         cmsg->cmsg_type = IPV6_PKTINFO;
[303]         cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
[304]         len = CMSG_SPACE(sizeof(struct in6_pktinfo));
[305] 
[306]         sin6 = (struct sockaddr_in6 *) local_sockaddr;
[307] 
[308]         pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
[309]         ngx_memzero(pkt6, sizeof(struct in6_pktinfo));
[310]         pkt6->ipi6_addr = sin6->sin6_addr;
[311] 
[312]         return len;
[313]     }
[314] #endif
[315] 
[316]     return 0;
[317] }
[318] 
[319] 
[320] ngx_int_t
[321] ngx_get_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *local_sockaddr)
[322] {
[323] 
[324] #if (NGX_HAVE_IP_RECVDSTADDR)
[325]     struct in_addr       *addr;
[326]     struct sockaddr_in   *sin;
[327] #elif (NGX_HAVE_IP_PKTINFO)
[328]     struct in_pktinfo    *pkt;
[329]     struct sockaddr_in   *sin;
[330] #endif
[331] 
[332] #if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
[333]     struct in6_pktinfo   *pkt6;
[334]     struct sockaddr_in6  *sin6;
[335] #endif
[336] 
[337] 
[338] #if (NGX_HAVE_IP_RECVDSTADDR)
[339] 
[340]     if (cmsg->cmsg_level == IPPROTO_IP
[341]         && cmsg->cmsg_type == IP_RECVDSTADDR
[342]         && local_sockaddr->sa_family == AF_INET)
[343]     {
[344]         addr = (struct in_addr *) CMSG_DATA(cmsg);
[345]         sin = (struct sockaddr_in *) local_sockaddr;
[346]         sin->sin_addr = *addr;
[347] 
[348]         return NGX_OK;
[349]     }
[350] 
[351] #elif (NGX_HAVE_IP_PKTINFO)
[352] 
[353]     if (cmsg->cmsg_level == IPPROTO_IP
[354]         && cmsg->cmsg_type == IP_PKTINFO
[355]         && local_sockaddr->sa_family == AF_INET)
[356]     {
[357]         pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
[358]         sin = (struct sockaddr_in *) local_sockaddr;
[359]         sin->sin_addr = pkt->ipi_addr;
[360] 
[361]         return NGX_OK;
[362]     }
[363] 
[364] #endif
[365] 
[366] #if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
[367] 
[368]     if (cmsg->cmsg_level == IPPROTO_IPV6
[369]         && cmsg->cmsg_type == IPV6_PKTINFO
[370]         && local_sockaddr->sa_family == AF_INET6)
[371]     {
[372]         pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
[373]         sin6 = (struct sockaddr_in6 *) local_sockaddr;
[374]         sin6->sin6_addr = pkt6->ipi6_addr;
[375] 
[376]         return NGX_OK;
[377]     }
[378] 
[379] #endif
[380] 
[381]     return NGX_DECLINED;
[382] }
[383] 
[384] #endif
[385] 
[386] 
[387] ssize_t
[388] ngx_sendmsg(ngx_connection_t *c, struct msghdr *msg, int flags)
[389] {
[390]     ssize_t    n;
[391]     ngx_err_t  err;
[392] #if (NGX_DEBUG)
[393]     size_t      size;
[394]     ngx_uint_t  i;
[395] #endif
[396] 
[397] eintr:
[398] 
[399]     n = sendmsg(c->fd, msg, flags);
[400] 
[401]     if (n == -1) {
[402]         err = ngx_errno;
[403] 
[404]         switch (err) {
[405]         case NGX_EAGAIN:
[406]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[407]                            "sendmsg() not ready");
[408]             return NGX_AGAIN;
[409] 
[410]         case NGX_EINTR:
[411]             ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
[412]                            "sendmsg() was interrupted");
[413]             goto eintr;
[414] 
[415]         default:
[416]             c->write->error = 1;
[417]             ngx_connection_error(c, err, "sendmsg() failed");
[418]             return NGX_ERROR;
[419]         }
[420]     }
[421] 
[422] #if (NGX_DEBUG)
[423]     for (i = 0, size = 0; i < (size_t) msg->msg_iovlen; i++) {
[424]         size += msg->msg_iov[i].iov_len;
[425]     }
[426] 
[427]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[428]                    "sendmsg: %z of %uz", n, size);
[429] #endif
[430] 
[431]     return n;
[432] }
