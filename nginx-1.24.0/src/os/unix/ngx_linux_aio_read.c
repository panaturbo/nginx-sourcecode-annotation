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
[13] extern int            ngx_eventfd;
[14] extern aio_context_t  ngx_aio_ctx;
[15] 
[16] 
[17] static void ngx_file_aio_event_handler(ngx_event_t *ev);
[18] 
[19] 
[20] static int
[21] io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
[22] {
[23]     return syscall(SYS_io_submit, ctx, n, paiocb);
[24] }
[25] 
[26] 
[27] ngx_int_t
[28] ngx_file_aio_init(ngx_file_t *file, ngx_pool_t *pool)
[29] {
[30]     ngx_event_aio_t  *aio;
[31] 
[32]     aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
[33]     if (aio == NULL) {
[34]         return NGX_ERROR;
[35]     }
[36] 
[37]     aio->file = file;
[38]     aio->fd = file->fd;
[39]     aio->event.data = aio;
[40]     aio->event.ready = 1;
[41]     aio->event.log = file->log;
[42] 
[43]     file->aio = aio;
[44] 
[45]     return NGX_OK;
[46] }
[47] 
[48] 
[49] ssize_t
[50] ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
[51]     ngx_pool_t *pool)
[52] {
[53]     ngx_err_t         err;
[54]     struct iocb      *piocb[1];
[55]     ngx_event_t      *ev;
[56]     ngx_event_aio_t  *aio;
[57] 
[58]     if (!ngx_file_aio) {
[59]         return ngx_read_file(file, buf, size, offset);
[60]     }
[61] 
[62]     if (file->aio == NULL && ngx_file_aio_init(file, pool) != NGX_OK) {
[63]         return NGX_ERROR;
[64]     }
[65] 
[66]     aio = file->aio;
[67]     ev = &aio->event;
[68] 
[69]     if (!ev->ready) {
[70]         ngx_log_error(NGX_LOG_ALERT, file->log, 0,
[71]                       "second aio post for \"%V\"", &file->name);
[72]         return NGX_AGAIN;
[73]     }
[74] 
[75]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
[76]                    "aio complete:%d @%O:%uz %V",
[77]                    ev->complete, offset, size, &file->name);
[78] 
[79]     if (ev->complete) {
[80]         ev->active = 0;
[81]         ev->complete = 0;
[82] 
[83]         if (aio->res >= 0) {
[84]             ngx_set_errno(0);
[85]             return aio->res;
[86]         }
[87] 
[88]         ngx_set_errno(-aio->res);
[89] 
[90]         ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[91]                       "aio read \"%s\" failed", file->name.data);
[92] 
[93]         return NGX_ERROR;
[94]     }
[95] 
[96]     ngx_memzero(&aio->aiocb, sizeof(struct iocb));
[97] 
[98]     aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
[99]     aio->aiocb.aio_lio_opcode = IOCB_CMD_PREAD;
[100]     aio->aiocb.aio_fildes = file->fd;
[101]     aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
[102]     aio->aiocb.aio_nbytes = size;
[103]     aio->aiocb.aio_offset = offset;
[104]     aio->aiocb.aio_flags = IOCB_FLAG_RESFD;
[105]     aio->aiocb.aio_resfd = ngx_eventfd;
[106] 
[107]     ev->handler = ngx_file_aio_event_handler;
[108] 
[109]     piocb[0] = &aio->aiocb;
[110] 
[111]     if (io_submit(ngx_aio_ctx, 1, piocb) == 1) {
[112]         ev->active = 1;
[113]         ev->ready = 0;
[114]         ev->complete = 0;
[115] 
[116]         return NGX_AGAIN;
[117]     }
[118] 
[119]     err = ngx_errno;
[120] 
[121]     if (err == NGX_EAGAIN) {
[122]         return ngx_read_file(file, buf, size, offset);
[123]     }
[124] 
[125]     ngx_log_error(NGX_LOG_CRIT, file->log, err,
[126]                   "io_submit(\"%V\") failed", &file->name);
[127] 
[128]     if (err == NGX_ENOSYS) {
[129]         ngx_file_aio = 0;
[130]         return ngx_read_file(file, buf, size, offset);
[131]     }
[132] 
[133]     return NGX_ERROR;
[134] }
[135] 
[136] 
[137] static void
[138] ngx_file_aio_event_handler(ngx_event_t *ev)
[139] {
[140]     ngx_event_aio_t  *aio;
[141] 
[142]     aio = ev->data;
[143] 
[144]     ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
[145]                    "aio event handler fd:%d %V", aio->fd, &aio->file->name);
[146] 
[147]     aio->handler(ev);
[148] }
