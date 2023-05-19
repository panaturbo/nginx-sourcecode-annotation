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
[13] #if (NGX_TEST_BUILD_SOLARIS_SENDFILEV)
[14] 
[15] /* Solaris declarations */
[16] 
[17] typedef struct sendfilevec {
[18]     int     sfv_fd;
[19]     u_int   sfv_flag;
[20]     off_t   sfv_off;
[21]     size_t  sfv_len;
[22] } sendfilevec_t;
[23] 
[24] #define SFV_FD_SELF  -2
[25] 
[26] static ssize_t sendfilev(int fd, const struct sendfilevec *vec,
[27]     int sfvcnt, size_t *xferred)
[28] {
[29]     return -1;
[30] }
[31] 
[32] ngx_chain_t *ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in,
[33]     off_t limit);
[34] 
[35] #endif
[36] 
[37] 
[38] #define NGX_SENDFILEVECS  NGX_IOVS_PREALLOCATE
[39] 
[40] 
[41] ngx_chain_t *
[42] ngx_solaris_sendfilev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
[43] {
[44]     int             fd;
[45]     u_char         *prev;
[46]     off_t           size, send, prev_send, aligned, fprev;
[47]     size_t          sent;
[48]     ssize_t         n;
[49]     ngx_int_t       eintr;
[50]     ngx_err_t       err;
[51]     ngx_buf_t      *file;
[52]     ngx_uint_t      nsfv;
[53]     sendfilevec_t  *sfv, sfvs[NGX_SENDFILEVECS];
[54]     ngx_event_t    *wev;
[55]     ngx_chain_t    *cl;
[56] 
[57]     wev = c->write;
[58] 
[59]     if (!wev->ready) {
[60]         return in;
[61]     }
[62] 
[63]     if (!c->sendfile) {
[64]         return ngx_writev_chain(c, in, limit);
[65]     }
[66] 
[67] 
[68]     /* the maximum limit size is the maximum size_t value - the page size */
[69] 
[70]     if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
[71]         limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
[72]     }
[73] 
[74] 
[75]     send = 0;
[76] 
[77]     for ( ;; ) {
[78]         fd = SFV_FD_SELF;
[79]         prev = NULL;
[80]         fprev = 0;
[81]         file = NULL;
[82]         sfv = NULL;
[83]         eintr = 0;
[84]         sent = 0;
[85]         prev_send = send;
[86] 
[87]         nsfv = 0;
[88] 
[89]         /* create the sendfilevec and coalesce the neighbouring bufs */
[90] 
[91]         for (cl = in; cl && send < limit; cl = cl->next) {
[92] 
[93]             if (ngx_buf_special(cl->buf)) {
[94]                 continue;
[95]             }
[96] 
[97]             if (ngx_buf_in_memory_only(cl->buf)) {
[98]                 fd = SFV_FD_SELF;
[99] 
[100]                 size = cl->buf->last - cl->buf->pos;
[101] 
[102]                 if (send + size > limit) {
[103]                     size = limit - send;
[104]                 }
[105] 
[106]                 if (prev == cl->buf->pos) {
[107]                     sfv->sfv_len += (size_t) size;
[108] 
[109]                 } else {
[110]                     if (nsfv == NGX_SENDFILEVECS) {
[111]                         break;
[112]                     }
[113] 
[114]                     sfv = &sfvs[nsfv++];
[115] 
[116]                     sfv->sfv_fd = SFV_FD_SELF;
[117]                     sfv->sfv_flag = 0;
[118]                     sfv->sfv_off = (off_t) (uintptr_t) cl->buf->pos;
[119]                     sfv->sfv_len = (size_t) size;
[120]                 }
[121] 
[122]                 prev = cl->buf->pos + (size_t) size;
[123]                 send += size;
[124] 
[125]             } else {
[126]                 prev = NULL;
[127] 
[128]                 size = cl->buf->file_last - cl->buf->file_pos;
[129] 
[130]                 if (send + size > limit) {
[131]                     size = limit - send;
[132] 
[133]                     aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
[134]                                & ~((off_t) ngx_pagesize - 1);
[135] 
[136]                     if (aligned <= cl->buf->file_last) {
[137]                         size = aligned - cl->buf->file_pos;
[138]                     }
[139]                 }
[140] 
[141]                 if (fd == cl->buf->file->fd && fprev == cl->buf->file_pos) {
[142]                     sfv->sfv_len += (size_t) size;
[143] 
[144]                 } else {
[145]                     if (nsfv == NGX_SENDFILEVECS) {
[146]                         break;
[147]                     }
[148] 
[149]                     sfv = &sfvs[nsfv++];
[150] 
[151]                     fd = cl->buf->file->fd;
[152]                     sfv->sfv_fd = fd;
[153]                     sfv->sfv_flag = 0;
[154]                     sfv->sfv_off = cl->buf->file_pos;
[155]                     sfv->sfv_len = (size_t) size;
[156]                 }
[157] 
[158]                 file = cl->buf;
[159]                 fprev = cl->buf->file_pos + size;
[160]                 send += size;
[161]             }
[162]         }
[163] 
[164]         n = sendfilev(c->fd, sfvs, nsfv, &sent);
[165] 
[166]         if (n == -1) {
[167]             err = ngx_errno;
[168] 
[169]             switch (err) {
[170]             case NGX_EAGAIN:
[171]                 break;
[172] 
[173]             case NGX_EINTR:
[174]                 eintr = 1;
[175]                 break;
[176] 
[177]             default:
[178]                 wev->error = 1;
[179]                 ngx_connection_error(c, err, "sendfilev() failed");
[180]                 return NGX_CHAIN_ERROR;
[181]             }
[182] 
[183]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, err,
[184]                           "sendfilev() sent only %uz bytes", sent);
[185] 
[186]         } else if (n == 0 && sent == 0) {
[187] 
[188]             /*
[189]              * sendfilev() is documented to return -1 with errno
[190]              * set to EINVAL if svf_len is greater than the file size,
[191]              * but at least Solaris 11 returns 0 instead
[192]              */
[193] 
[194]             if (file) {
[195]                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[196]                         "sendfilev() reported that \"%s\" was truncated at %O",
[197]                         file->file->name.data, file->file_pos);
[198] 
[199]             } else {
[200]                 ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[201]                               "sendfilev() returned 0 with memory buffers");
[202]             }
[203] 
[204]             return NGX_CHAIN_ERROR;
[205]         }
[206] 
[207]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[208]                        "sendfilev: %z %z", n, sent);
[209] 
[210]         c->sent += sent;
[211] 
[212]         in = ngx_chain_update_sent(in, sent);
[213] 
[214]         if (eintr) {
[215]             send = prev_send + sent;
[216]             continue;
[217]         }
[218] 
[219]         if (send - prev_send != (off_t) sent) {
[220]             wev->ready = 0;
[221]             return in;
[222]         }
[223] 
[224]         if (send >= limit || in == NULL) {
[225]             return in;
[226]         }
[227]     }
[228] }
