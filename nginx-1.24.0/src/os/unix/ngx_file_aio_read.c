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
[13] /*
[14]  * FreeBSD file AIO features and quirks:
[15]  *
[16]  *    if an asked data are already in VM cache, then aio_error() returns 0,
[17]  *    and the data are already copied in buffer;
[18]  *
[19]  *    aio_read() preread in VM cache as minimum 16K (probably BKVASIZE);
[20]  *    the first AIO preload may be up to 128K;
[21]  *
[22]  *    aio_read/aio_error() may return EINPROGRESS for just written data;
[23]  *
[24]  *    kqueue EVFILT_AIO filter is level triggered only: an event repeats
[25]  *    until aio_return() will be called;
[26]  *
[27]  *    aio_cancel() cannot cancel file AIO: it returns AIO_NOTCANCELED always.
[28]  */
[29] 
[30] 
[31] extern int  ngx_kqueue;
[32] 
[33] 
[34] static ssize_t ngx_file_aio_result(ngx_file_t *file, ngx_event_aio_t *aio,
[35]     ngx_event_t *ev);
[36] static void ngx_file_aio_event_handler(ngx_event_t *ev);
[37] 
[38] 
[39] ngx_int_t
[40] ngx_file_aio_init(ngx_file_t *file, ngx_pool_t *pool)
[41] {
[42]     ngx_event_aio_t  *aio;
[43] 
[44]     aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
[45]     if (aio == NULL) {
[46]         return NGX_ERROR;
[47]     }
[48] 
[49]     aio->file = file;
[50]     aio->fd = file->fd;
[51]     aio->event.data = aio;
[52]     aio->event.ready = 1;
[53]     aio->event.log = file->log;
[54] 
[55]     file->aio = aio;
[56] 
[57]     return NGX_OK;
[58] }
[59] 
[60] 
[61] ssize_t
[62] ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
[63]     ngx_pool_t *pool)
[64] {
[65]     int               n;
[66]     ngx_event_t      *ev;
[67]     ngx_event_aio_t  *aio;
[68] 
[69]     if (!ngx_file_aio) {
[70]         return ngx_read_file(file, buf, size, offset);
[71]     }
[72] 
[73]     if (file->aio == NULL && ngx_file_aio_init(file, pool) != NGX_OK) {
[74]         return NGX_ERROR;
[75]     }
[76] 
[77]     aio = file->aio;
[78]     ev = &aio->event;
[79] 
[80]     if (!ev->ready) {
[81]         ngx_log_error(NGX_LOG_ALERT, file->log, 0,
[82]                       "second aio post for \"%V\"", &file->name);
[83]         return NGX_AGAIN;
[84]     }
[85] 
[86]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
[87]                    "aio complete:%d @%O:%uz %V",
[88]                    ev->complete, offset, size, &file->name);
[89] 
[90]     if (ev->complete) {
[91]         ev->complete = 0;
[92]         ngx_set_errno(aio->err);
[93] 
[94]         if (aio->err == 0) {
[95]             return aio->nbytes;
[96]         }
[97] 
[98]         ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[99]                       "aio read \"%s\" failed", file->name.data);
[100] 
[101]         return NGX_ERROR;
[102]     }
[103] 
[104]     ngx_memzero(&aio->aiocb, sizeof(struct aiocb));
[105] 
[106]     aio->aiocb.aio_fildes = file->fd;
[107]     aio->aiocb.aio_offset = offset;
[108]     aio->aiocb.aio_buf = buf;
[109]     aio->aiocb.aio_nbytes = size;
[110] #if (NGX_HAVE_KQUEUE)
[111]     aio->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
[112]     aio->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
[113]     aio->aiocb.aio_sigevent.sigev_value.sival_ptr = ev;
[114] #endif
[115]     ev->handler = ngx_file_aio_event_handler;
[116] 
[117]     n = aio_read(&aio->aiocb);
[118] 
[119]     if (n == -1) {
[120]         n = ngx_errno;
[121] 
[122]         if (n == NGX_EAGAIN) {
[123]             return ngx_read_file(file, buf, size, offset);
[124]         }
[125] 
[126]         ngx_log_error(NGX_LOG_CRIT, file->log, n,
[127]                       "aio_read(\"%V\") failed", &file->name);
[128] 
[129]         if (n == NGX_ENOSYS) {
[130]             ngx_file_aio = 0;
[131]             return ngx_read_file(file, buf, size, offset);
[132]         }
[133] 
[134]         return NGX_ERROR;
[135]     }
[136] 
[137]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
[138]                    "aio_read: fd:%d %d", file->fd, n);
[139] 
[140]     ev->active = 1;
[141]     ev->ready = 0;
[142]     ev->complete = 0;
[143] 
[144]     return ngx_file_aio_result(aio->file, aio, ev);
[145] }
[146] 
[147] 
[148] static ssize_t
[149] ngx_file_aio_result(ngx_file_t *file, ngx_event_aio_t *aio, ngx_event_t *ev)
[150] {
[151]     int        n;
[152]     ngx_err_t  err;
[153] 
[154]     n = aio_error(&aio->aiocb);
[155] 
[156]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
[157]                    "aio_error: fd:%d %d", file->fd, n);
[158] 
[159]     if (n == -1) {
[160]         err = ngx_errno;
[161]         aio->err = err;
[162] 
[163]         ngx_log_error(NGX_LOG_ALERT, file->log, err,
[164]                       "aio_error(\"%V\") failed", &file->name);
[165]         return NGX_ERROR;
[166]     }
[167] 
[168]     if (n == NGX_EINPROGRESS) {
[169]         if (ev->ready) {
[170]             ev->ready = 0;
[171]             ngx_log_error(NGX_LOG_ALERT, file->log, n,
[172]                           "aio_read(\"%V\") still in progress",
[173]                           &file->name);
[174]         }
[175] 
[176]         return NGX_AGAIN;
[177]     }
[178] 
[179]     n = aio_return(&aio->aiocb);
[180] 
[181]     if (n == -1) {
[182]         err = ngx_errno;
[183]         aio->err = err;
[184]         ev->ready = 1;
[185] 
[186]         ngx_log_error(NGX_LOG_CRIT, file->log, err,
[187]                       "aio_return(\"%V\") failed", &file->name);
[188]         return NGX_ERROR;
[189]     }
[190] 
[191]     aio->err = 0;
[192]     aio->nbytes = n;
[193]     ev->ready = 1;
[194]     ev->active = 0;
[195] 
[196]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
[197]                    "aio_return: fd:%d %d", file->fd, n);
[198] 
[199]     return n;
[200] }
[201] 
[202] 
[203] static void
[204] ngx_file_aio_event_handler(ngx_event_t *ev)
[205] {
[206]     ngx_event_aio_t  *aio;
[207] 
[208]     aio = ev->data;
[209] 
[210]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
[211]                    "aio event handler fd:%d %V", aio->fd, &aio->file->name);
[212] 
[213]     if (ngx_file_aio_result(aio->file, aio, ev) != NGX_AGAIN) {
[214]         aio->handler(ev);
[215]     }
[216] }
