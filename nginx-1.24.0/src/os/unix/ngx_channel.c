[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_channel.h>
[11] 
[12] 
[13] ngx_int_t
[14] ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
[15]     ngx_log_t *log)
[16] {
[17]     ssize_t             n;
[18]     ngx_err_t           err;
[19]     struct iovec        iov[1];
[20]     struct msghdr       msg;
[21] 
[22] #if (NGX_HAVE_MSGHDR_MSG_CONTROL)
[23] 
[24]     union {
[25]         struct cmsghdr  cm;
[26]         char            space[CMSG_SPACE(sizeof(int))];
[27]     } cmsg;
[28] 
[29]     if (ch->fd == -1) {
[30]         msg.msg_control = NULL;
[31]         msg.msg_controllen = 0;
[32] 
[33]     } else {
[34]         msg.msg_control = (caddr_t) &cmsg;
[35]         msg.msg_controllen = sizeof(cmsg);
[36] 
[37]         ngx_memzero(&cmsg, sizeof(cmsg));
[38] 
[39]         cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
[40]         cmsg.cm.cmsg_level = SOL_SOCKET;
[41]         cmsg.cm.cmsg_type = SCM_RIGHTS;
[42] 
[43]         /*
[44]          * We have to use ngx_memcpy() instead of simple
[45]          *   *(int *) CMSG_DATA(&cmsg.cm) = ch->fd;
[46]          * because some gcc 4.4 with -O2/3/s optimization issues the warning:
[47]          *   dereferencing type-punned pointer will break strict-aliasing rules
[48]          *
[49]          * Fortunately, gcc with -O1 compiles this ngx_memcpy()
[50]          * in the same simple assignment as in the code above
[51]          */
[52] 
[53]         ngx_memcpy(CMSG_DATA(&cmsg.cm), &ch->fd, sizeof(int));
[54]     }
[55] 
[56]     msg.msg_flags = 0;
[57] 
[58] #else
[59] 
[60]     if (ch->fd == -1) {
[61]         msg.msg_accrights = NULL;
[62]         msg.msg_accrightslen = 0;
[63] 
[64]     } else {
[65]         msg.msg_accrights = (caddr_t) &ch->fd;
[66]         msg.msg_accrightslen = sizeof(int);
[67]     }
[68] 
[69] #endif
[70] 
[71]     iov[0].iov_base = (char *) ch;
[72]     iov[0].iov_len = size;
[73] 
[74]     msg.msg_name = NULL;
[75]     msg.msg_namelen = 0;
[76]     msg.msg_iov = iov;
[77]     msg.msg_iovlen = 1;
[78] 
[79]     n = sendmsg(s, &msg, 0);
[80] 
[81]     if (n == -1) {
[82]         err = ngx_errno;
[83]         if (err == NGX_EAGAIN) {
[84]             return NGX_AGAIN;
[85]         }
[86] 
[87]         ngx_log_error(NGX_LOG_ALERT, log, err, "sendmsg() failed");
[88]         return NGX_ERROR;
[89]     }
[90] 
[91]     return NGX_OK;
[92] }
[93] 
[94] 
[95] ngx_int_t
[96] ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size, ngx_log_t *log)
[97] {
[98]     ssize_t             n;
[99]     ngx_err_t           err;
[100]     struct iovec        iov[1];
[101]     struct msghdr       msg;
[102] 
[103] #if (NGX_HAVE_MSGHDR_MSG_CONTROL)
[104]     union {
[105]         struct cmsghdr  cm;
[106]         char            space[CMSG_SPACE(sizeof(int))];
[107]     } cmsg;
[108] #else
[109]     int                 fd;
[110] #endif
[111] 
[112]     iov[0].iov_base = (char *) ch;
[113]     iov[0].iov_len = size;
[114] 
[115]     msg.msg_name = NULL;
[116]     msg.msg_namelen = 0;
[117]     msg.msg_iov = iov;
[118]     msg.msg_iovlen = 1;
[119] 
[120] #if (NGX_HAVE_MSGHDR_MSG_CONTROL)
[121]     msg.msg_control = (caddr_t) &cmsg;
[122]     msg.msg_controllen = sizeof(cmsg);
[123] #else
[124]     msg.msg_accrights = (caddr_t) &fd;
[125]     msg.msg_accrightslen = sizeof(int);
[126] #endif
[127] 
[128]     n = recvmsg(s, &msg, 0);
[129] 
[130]     if (n == -1) {
[131]         err = ngx_errno;
[132]         if (err == NGX_EAGAIN) {
[133]             return NGX_AGAIN;
[134]         }
[135] 
[136]         ngx_log_error(NGX_LOG_ALERT, log, err, "recvmsg() failed");
[137]         return NGX_ERROR;
[138]     }
[139] 
[140]     if (n == 0) {
[141]         ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "recvmsg() returned zero");
[142]         return NGX_ERROR;
[143]     }
[144] 
[145]     if ((size_t) n < sizeof(ngx_channel_t)) {
[146]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[147]                       "recvmsg() returned not enough data: %z", n);
[148]         return NGX_ERROR;
[149]     }
[150] 
[151] #if (NGX_HAVE_MSGHDR_MSG_CONTROL)
[152] 
[153]     if (ch->command == NGX_CMD_OPEN_CHANNEL) {
[154] 
[155]         if (cmsg.cm.cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
[156]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[157]                           "recvmsg() returned too small ancillary data");
[158]             return NGX_ERROR;
[159]         }
[160] 
[161]         if (cmsg.cm.cmsg_level != SOL_SOCKET || cmsg.cm.cmsg_type != SCM_RIGHTS)
[162]         {
[163]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[164]                           "recvmsg() returned invalid ancillary data "
[165]                           "level %d or type %d",
[166]                           cmsg.cm.cmsg_level, cmsg.cm.cmsg_type);
[167]             return NGX_ERROR;
[168]         }
[169] 
[170]         /* ch->fd = *(int *) CMSG_DATA(&cmsg.cm); */
[171] 
[172]         ngx_memcpy(&ch->fd, CMSG_DATA(&cmsg.cm), sizeof(int));
[173]     }
[174] 
[175]     if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
[176]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[177]                       "recvmsg() truncated data");
[178]     }
[179] 
[180] #else
[181] 
[182]     if (ch->command == NGX_CMD_OPEN_CHANNEL) {
[183]         if (msg.msg_accrightslen != sizeof(int)) {
[184]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[185]                           "recvmsg() returned no ancillary data");
[186]             return NGX_ERROR;
[187]         }
[188] 
[189]         ch->fd = fd;
[190]     }
[191] 
[192] #endif
[193] 
[194]     return n;
[195] }
[196] 
[197] 
[198] ngx_int_t
[199] ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd, ngx_int_t event,
[200]     ngx_event_handler_pt handler)
[201] {
[202]     ngx_event_t       *ev, *rev, *wev;
[203]     ngx_connection_t  *c;
[204] 
[205]     c = ngx_get_connection(fd, cycle->log);
[206] 
[207]     if (c == NULL) {
[208]         return NGX_ERROR;
[209]     }
[210] 
[211]     c->pool = cycle->pool;
[212] 
[213]     rev = c->read;
[214]     wev = c->write;
[215] 
[216]     rev->log = cycle->log;
[217]     wev->log = cycle->log;
[218] 
[219]     rev->channel = 1;
[220]     wev->channel = 1;
[221] 
[222]     ev = (event == NGX_READ_EVENT) ? rev : wev;
[223] 
[224]     ev->handler = handler;
[225] 
[226]     if (ngx_add_conn && (ngx_event_flags & NGX_USE_EPOLL_EVENT) == 0) {
[227]         if (ngx_add_conn(c) == NGX_ERROR) {
[228]             ngx_free_connection(c);
[229]             return NGX_ERROR;
[230]         }
[231] 
[232]     } else {
[233]         if (ngx_add_event(ev, event, 0) == NGX_ERROR) {
[234]             ngx_free_connection(c);
[235]             return NGX_ERROR;
[236]         }
[237]     }
[238] 
[239]     return NGX_OK;
[240] }
[241] 
[242] 
[243] void
[244] ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log)
[245] {
[246]     if (close(fd[0]) == -1) {
[247]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "close() channel failed");
[248]     }
[249] 
[250]     if (close(fd[1]) == -1) {
[251]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno, "close() channel failed");
[252]     }
[253] }
