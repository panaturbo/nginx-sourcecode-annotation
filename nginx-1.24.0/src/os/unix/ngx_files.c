[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] #if (NGX_THREADS)
[13] #include <ngx_thread_pool.h>
[14] static void ngx_thread_read_handler(void *data, ngx_log_t *log);
[15] static void ngx_thread_write_chain_to_file_handler(void *data, ngx_log_t *log);
[16] #endif
[17] 
[18] static ngx_chain_t *ngx_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *cl);
[19] static ssize_t ngx_writev_file(ngx_file_t *file, ngx_iovec_t *vec,
[20]     off_t offset);
[21] 
[22] 
[23] #if (NGX_HAVE_FILE_AIO)
[24] 
[25] ngx_uint_t  ngx_file_aio = 1;
[26] 
[27] #endif
[28] 
[29] 
[30] ssize_t
[31] ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
[32] {
[33]     ssize_t  n;
[34] 
[35]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
[36]                    "read: %d, %p, %uz, %O", file->fd, buf, size, offset);
[37] 
[38] #if (NGX_HAVE_PREAD)
[39] 
[40]     n = pread(file->fd, buf, size, offset);
[41] 
[42]     if (n == -1) {
[43]         ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[44]                       "pread() \"%s\" failed", file->name.data);
[45]         return NGX_ERROR;
[46]     }
[47] 
[48] #else
[49] 
[50]     if (file->sys_offset != offset) {
[51]         if (lseek(file->fd, offset, SEEK_SET) == -1) {
[52]             ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[53]                           "lseek() \"%s\" failed", file->name.data);
[54]             return NGX_ERROR;
[55]         }
[56] 
[57]         file->sys_offset = offset;
[58]     }
[59] 
[60]     n = read(file->fd, buf, size);
[61] 
[62]     if (n == -1) {
[63]         ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[64]                       "read() \"%s\" failed", file->name.data);
[65]         return NGX_ERROR;
[66]     }
[67] 
[68]     file->sys_offset += n;
[69] 
[70] #endif
[71] 
[72]     file->offset += n;
[73] 
[74]     return n;
[75] }
[76] 
[77] 
[78] #if (NGX_THREADS)
[79] 
[80] typedef struct {
[81]     ngx_fd_t       fd;
[82]     ngx_uint_t     write;   /* unsigned  write:1; */
[83] 
[84]     u_char        *buf;
[85]     size_t         size;
[86]     ngx_chain_t   *chain;
[87]     off_t          offset;
[88] 
[89]     size_t         nbytes;
[90]     ngx_err_t      err;
[91] } ngx_thread_file_ctx_t;
[92] 
[93] 
[94] ssize_t
[95] ngx_thread_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
[96]     ngx_pool_t *pool)
[97] {
[98]     ngx_thread_task_t      *task;
[99]     ngx_thread_file_ctx_t  *ctx;
[100] 
[101]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
[102]                    "thread read: %d, %p, %uz, %O",
[103]                    file->fd, buf, size, offset);
[104] 
[105]     task = file->thread_task;
[106] 
[107]     if (task == NULL) {
[108]         task = ngx_thread_task_alloc(pool, sizeof(ngx_thread_file_ctx_t));
[109]         if (task == NULL) {
[110]             return NGX_ERROR;
[111]         }
[112] 
[113]         file->thread_task = task;
[114]     }
[115] 
[116]     ctx = task->ctx;
[117] 
[118]     if (task->event.complete) {
[119]         task->event.complete = 0;
[120] 
[121]         if (ctx->write) {
[122]             ngx_log_error(NGX_LOG_ALERT, file->log, 0,
[123]                           "invalid thread call, read instead of write");
[124]             return NGX_ERROR;
[125]         }
[126] 
[127]         if (ctx->err) {
[128]             ngx_log_error(NGX_LOG_CRIT, file->log, ctx->err,
[129]                           "pread() \"%s\" failed", file->name.data);
[130]             return NGX_ERROR;
[131]         }
[132] 
[133]         return ctx->nbytes;
[134]     }
[135] 
[136]     task->handler = ngx_thread_read_handler;
[137] 
[138]     ctx->write = 0;
[139] 
[140]     ctx->fd = file->fd;
[141]     ctx->buf = buf;
[142]     ctx->size = size;
[143]     ctx->offset = offset;
[144] 
[145]     if (file->thread_handler(task, file) != NGX_OK) {
[146]         return NGX_ERROR;
[147]     }
[148] 
[149]     return NGX_AGAIN;
[150] }
[151] 
[152] 
[153] #if (NGX_HAVE_PREAD)
[154] 
[155] static void
[156] ngx_thread_read_handler(void *data, ngx_log_t *log)
[157] {
[158]     ngx_thread_file_ctx_t *ctx = data;
[159] 
[160]     ssize_t  n;
[161] 
[162]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "thread read handler");
[163] 
[164]     n = pread(ctx->fd, ctx->buf, ctx->size, ctx->offset);
[165] 
[166]     if (n == -1) {
[167]         ctx->err = ngx_errno;
[168] 
[169]     } else {
[170]         ctx->nbytes = n;
[171]         ctx->err = 0;
[172]     }
[173] 
[174] #if 0
[175]     ngx_time_update();
[176] #endif
[177] 
[178]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
[179]                    "pread: %z (err: %d) of %uz @%O",
[180]                    n, ctx->err, ctx->size, ctx->offset);
[181] }
[182] 
[183] #else
[184] 
[185] #error pread() is required!
[186] 
[187] #endif
[188] 
[189] #endif /* NGX_THREADS */
[190] 
[191] 
[192] ssize_t
[193] ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
[194] {
[195]     ssize_t    n, written;
[196]     ngx_err_t  err;
[197] 
[198]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
[199]                    "write: %d, %p, %uz, %O", file->fd, buf, size, offset);
[200] 
[201]     written = 0;
[202] 
[203] #if (NGX_HAVE_PWRITE)
[204] 
[205]     for ( ;; ) {
[206]         n = pwrite(file->fd, buf + written, size, offset);
[207] 
[208]         if (n == -1) {
[209]             err = ngx_errno;
[210] 
[211]             if (err == NGX_EINTR) {
[212]                 ngx_log_debug0(NGX_LOG_DEBUG_CORE, file->log, err,
[213]                                "pwrite() was interrupted");
[214]                 continue;
[215]             }
[216] 
[217]             ngx_log_error(NGX_LOG_CRIT, file->log, err,
[218]                           "pwrite() \"%s\" failed", file->name.data);
[219]             return NGX_ERROR;
[220]         }
[221] 
[222]         file->offset += n;
[223]         written += n;
[224] 
[225]         if ((size_t) n == size) {
[226]             return written;
[227]         }
[228] 
[229]         offset += n;
[230]         size -= n;
[231]     }
[232] 
[233] #else
[234] 
[235]     if (file->sys_offset != offset) {
[236]         if (lseek(file->fd, offset, SEEK_SET) == -1) {
[237]             ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[238]                           "lseek() \"%s\" failed", file->name.data);
[239]             return NGX_ERROR;
[240]         }
[241] 
[242]         file->sys_offset = offset;
[243]     }
[244] 
[245]     for ( ;; ) {
[246]         n = write(file->fd, buf + written, size);
[247] 
[248]         if (n == -1) {
[249]             err = ngx_errno;
[250] 
[251]             if (err == NGX_EINTR) {
[252]                 ngx_log_debug0(NGX_LOG_DEBUG_CORE, file->log, err,
[253]                                "write() was interrupted");
[254]                 continue;
[255]             }
[256] 
[257]             ngx_log_error(NGX_LOG_CRIT, file->log, err,
[258]                           "write() \"%s\" failed", file->name.data);
[259]             return NGX_ERROR;
[260]         }
[261] 
[262]         file->sys_offset += n;
[263]         file->offset += n;
[264]         written += n;
[265] 
[266]         if ((size_t) n == size) {
[267]             return written;
[268]         }
[269] 
[270]         size -= n;
[271]     }
[272] #endif
[273] }
[274] 
[275] 
[276] ngx_fd_t
[277] ngx_open_tempfile(u_char *name, ngx_uint_t persistent, ngx_uint_t access)
[278] {
[279]     ngx_fd_t  fd;
[280] 
[281]     fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR,
[282]               access ? access : 0600);
[283] 
[284]     if (fd != -1 && !persistent) {
[285]         (void) unlink((const char *) name);
[286]     }
[287] 
[288]     return fd;
[289] }
[290] 
[291] 
[292] ssize_t
[293] ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
[294]     ngx_pool_t *pool)
[295] {
[296]     ssize_t        total, n;
[297]     ngx_iovec_t    vec;
[298]     struct iovec   iovs[NGX_IOVS_PREALLOCATE];
[299] 
[300]     /* use pwrite() if there is the only buf in a chain */
[301] 
[302]     if (cl->next == NULL) {
[303]         return ngx_write_file(file, cl->buf->pos,
[304]                               (size_t) (cl->buf->last - cl->buf->pos),
[305]                               offset);
[306]     }
[307] 
[308]     total = 0;
[309] 
[310]     vec.iovs = iovs;
[311]     vec.nalloc = NGX_IOVS_PREALLOCATE;
[312] 
[313]     do {
[314]         /* create the iovec and coalesce the neighbouring bufs */
[315]         cl = ngx_chain_to_iovec(&vec, cl);
[316] 
[317]         /* use pwrite() if there is the only iovec buffer */
[318] 
[319]         if (vec.count == 1) {
[320]             n = ngx_write_file(file, (u_char *) iovs[0].iov_base,
[321]                                iovs[0].iov_len, offset);
[322] 
[323]             if (n == NGX_ERROR) {
[324]                 return n;
[325]             }
[326] 
[327]             return total + n;
[328]         }
[329] 
[330]         n = ngx_writev_file(file, &vec, offset);
[331] 
[332]         if (n == NGX_ERROR) {
[333]             return n;
[334]         }
[335] 
[336]         offset += n;
[337]         total += n;
[338] 
[339]     } while (cl);
[340] 
[341]     return total;
[342] }
[343] 
[344] 
[345] static ngx_chain_t *
[346] ngx_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *cl)
[347] {
[348]     size_t         total, size;
[349]     u_char        *prev;
[350]     ngx_uint_t     n;
[351]     struct iovec  *iov;
[352] 
[353]     iov = NULL;
[354]     prev = NULL;
[355]     total = 0;
[356]     n = 0;
[357] 
[358]     for ( /* void */ ; cl; cl = cl->next) {
[359] 
[360]         if (ngx_buf_special(cl->buf)) {
[361]             continue;
[362]         }
[363] 
[364]         size = cl->buf->last - cl->buf->pos;
[365] 
[366]         if (prev == cl->buf->pos) {
[367]             iov->iov_len += size;
[368] 
[369]         } else {
[370]             if (n == vec->nalloc) {
[371]                 break;
[372]             }
[373] 
[374]             iov = &vec->iovs[n++];
[375] 
[376]             iov->iov_base = (void *) cl->buf->pos;
[377]             iov->iov_len = size;
[378]         }
[379] 
[380]         prev = cl->buf->pos + size;
[381]         total += size;
[382]     }
[383] 
[384]     vec->count = n;
[385]     vec->size = total;
[386] 
[387]     return cl;
[388] }
[389] 
[390] 
[391] static ssize_t
[392] ngx_writev_file(ngx_file_t *file, ngx_iovec_t *vec, off_t offset)
[393] {
[394]     ssize_t    n;
[395]     ngx_err_t  err;
[396] 
[397]     ngx_log_debug3(NGX_LOG_DEBUG_CORE, file->log, 0,
[398]                    "writev: %d, %uz, %O", file->fd, vec->size, offset);
[399] 
[400] #if (NGX_HAVE_PWRITEV)
[401] 
[402] eintr:
[403] 
[404]     n = pwritev(file->fd, vec->iovs, vec->count, offset);
[405] 
[406]     if (n == -1) {
[407]         err = ngx_errno;
[408] 
[409]         if (err == NGX_EINTR) {
[410]             ngx_log_debug0(NGX_LOG_DEBUG_CORE, file->log, err,
[411]                            "pwritev() was interrupted");
[412]             goto eintr;
[413]         }
[414] 
[415]         ngx_log_error(NGX_LOG_CRIT, file->log, err,
[416]                       "pwritev() \"%s\" failed", file->name.data);
[417]         return NGX_ERROR;
[418]     }
[419] 
[420]     if ((size_t) n != vec->size) {
[421]         ngx_log_error(NGX_LOG_CRIT, file->log, 0,
[422]                       "pwritev() \"%s\" has written only %z of %uz",
[423]                       file->name.data, n, vec->size);
[424]         return NGX_ERROR;
[425]     }
[426] 
[427] #else
[428] 
[429]     if (file->sys_offset != offset) {
[430]         if (lseek(file->fd, offset, SEEK_SET) == -1) {
[431]             ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
[432]                           "lseek() \"%s\" failed", file->name.data);
[433]             return NGX_ERROR;
[434]         }
[435] 
[436]         file->sys_offset = offset;
[437]     }
[438] 
[439] eintr:
[440] 
[441]     n = writev(file->fd, vec->iovs, vec->count);
[442] 
[443]     if (n == -1) {
[444]         err = ngx_errno;
[445] 
[446]         if (err == NGX_EINTR) {
[447]             ngx_log_debug0(NGX_LOG_DEBUG_CORE, file->log, err,
[448]                            "writev() was interrupted");
[449]             goto eintr;
[450]         }
[451] 
[452]         ngx_log_error(NGX_LOG_CRIT, file->log, err,
[453]                       "writev() \"%s\" failed", file->name.data);
[454]         return NGX_ERROR;
[455]     }
[456] 
[457]     if ((size_t) n != vec->size) {
[458]         ngx_log_error(NGX_LOG_CRIT, file->log, 0,
[459]                       "writev() \"%s\" has written only %z of %uz",
[460]                       file->name.data, n, vec->size);
[461]         return NGX_ERROR;
[462]     }
[463] 
[464]     file->sys_offset += n;
[465] 
[466] #endif
[467] 
[468]     file->offset += n;
[469] 
[470]     return n;
[471] }
[472] 
[473] 
[474] #if (NGX_THREADS)
[475] 
[476] ssize_t
[477] ngx_thread_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
[478]     ngx_pool_t *pool)
[479] {
[480]     ngx_thread_task_t      *task;
[481]     ngx_thread_file_ctx_t  *ctx;
[482] 
[483]     ngx_log_debug3(NGX_LOG_DEBUG_CORE, file->log, 0,
[484]                    "thread write chain: %d, %p, %O",
[485]                    file->fd, cl, offset);
[486] 
[487]     task = file->thread_task;
[488] 
[489]     if (task == NULL) {
[490]         task = ngx_thread_task_alloc(pool,
[491]                                      sizeof(ngx_thread_file_ctx_t));
[492]         if (task == NULL) {
[493]             return NGX_ERROR;
[494]         }
[495] 
[496]         file->thread_task = task;
[497]     }
[498] 
[499]     ctx = task->ctx;
[500] 
[501]     if (task->event.complete) {
[502]         task->event.complete = 0;
[503] 
[504]         if (!ctx->write) {
[505]             ngx_log_error(NGX_LOG_ALERT, file->log, 0,
[506]                           "invalid thread call, write instead of read");
[507]             return NGX_ERROR;
[508]         }
[509] 
[510]         if (ctx->err || ctx->nbytes == 0) {
[511]             ngx_log_error(NGX_LOG_CRIT, file->log, ctx->err,
[512]                           "pwritev() \"%s\" failed", file->name.data);
[513]             return NGX_ERROR;
[514]         }
[515] 
[516]         file->offset += ctx->nbytes;
[517]         return ctx->nbytes;
[518]     }
[519] 
[520]     task->handler = ngx_thread_write_chain_to_file_handler;
[521] 
[522]     ctx->write = 1;
[523] 
[524]     ctx->fd = file->fd;
[525]     ctx->chain = cl;
[526]     ctx->offset = offset;
[527] 
[528]     if (file->thread_handler(task, file) != NGX_OK) {
[529]         return NGX_ERROR;
[530]     }
[531] 
[532]     return NGX_AGAIN;
[533] }
[534] 
[535] 
[536] static void
[537] ngx_thread_write_chain_to_file_handler(void *data, ngx_log_t *log)
[538] {
[539]     ngx_thread_file_ctx_t *ctx = data;
[540] 
[541] #if (NGX_HAVE_PWRITEV)
[542] 
[543]     off_t          offset;
[544]     ssize_t        n;
[545]     ngx_err_t      err;
[546]     ngx_chain_t   *cl;
[547]     ngx_iovec_t    vec;
[548]     struct iovec   iovs[NGX_IOVS_PREALLOCATE];
[549] 
[550]     vec.iovs = iovs;
[551]     vec.nalloc = NGX_IOVS_PREALLOCATE;
[552] 
[553]     cl = ctx->chain;
[554]     offset = ctx->offset;
[555] 
[556]     ctx->nbytes = 0;
[557]     ctx->err = 0;
[558] 
[559]     do {
[560]         /* create the iovec and coalesce the neighbouring bufs */
[561]         cl = ngx_chain_to_iovec(&vec, cl);
[562] 
[563] eintr:
[564] 
[565]         n = pwritev(ctx->fd, iovs, vec.count, offset);
[566] 
[567]         if (n == -1) {
[568]             err = ngx_errno;
[569] 
[570]             if (err == NGX_EINTR) {
[571]                 ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, err,
[572]                                "pwritev() was interrupted");
[573]                 goto eintr;
[574]             }
[575] 
[576]             ctx->err = err;
[577]             return;
[578]         }
[579] 
[580]         if ((size_t) n != vec.size) {
[581]             ctx->nbytes = 0;
[582]             return;
[583]         }
[584] 
[585]         ctx->nbytes += n;
[586]         offset += n;
[587]     } while (cl);
[588] 
[589] #else
[590] 
[591]     ctx->err = NGX_ENOSYS;
[592]     return;
[593] 
[594] #endif
[595] }
[596] 
[597] #endif /* NGX_THREADS */
[598] 
[599] 
[600] ngx_int_t
[601] ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s)
[602] {
[603]     struct timeval  tv[2];
[604] 
[605]     tv[0].tv_sec = ngx_time();
[606]     tv[0].tv_usec = 0;
[607]     tv[1].tv_sec = s;
[608]     tv[1].tv_usec = 0;
[609] 
[610]     if (utimes((char *) name, tv) != -1) {
[611]         return NGX_OK;
[612]     }
[613] 
[614]     return NGX_ERROR;
[615] }
[616] 
[617] 
[618] ngx_int_t
[619] ngx_create_file_mapping(ngx_file_mapping_t *fm)
[620] {
[621]     fm->fd = ngx_open_file(fm->name, NGX_FILE_RDWR, NGX_FILE_TRUNCATE,
[622]                            NGX_FILE_DEFAULT_ACCESS);
[623] 
[624]     if (fm->fd == NGX_INVALID_FILE) {
[625]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[626]                       ngx_open_file_n " \"%s\" failed", fm->name);
[627]         return NGX_ERROR;
[628]     }
[629] 
[630]     if (ftruncate(fm->fd, fm->size) == -1) {
[631]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[632]                       "ftruncate() \"%s\" failed", fm->name);
[633]         goto failed;
[634]     }
[635] 
[636]     fm->addr = mmap(NULL, fm->size, PROT_READ|PROT_WRITE, MAP_SHARED,
[637]                     fm->fd, 0);
[638]     if (fm->addr != MAP_FAILED) {
[639]         return NGX_OK;
[640]     }
[641] 
[642]     ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[643]                   "mmap(%uz) \"%s\" failed", fm->size, fm->name);
[644] 
[645] failed:
[646] 
[647]     if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
[648]         ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[649]                       ngx_close_file_n " \"%s\" failed", fm->name);
[650]     }
[651] 
[652]     return NGX_ERROR;
[653] }
[654] 
[655] 
[656] void
[657] ngx_close_file_mapping(ngx_file_mapping_t *fm)
[658] {
[659]     if (munmap(fm->addr, fm->size) == -1) {
[660]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[661]                       "munmap(%uz) \"%s\" failed", fm->size, fm->name);
[662]     }
[663] 
[664]     if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
[665]         ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[666]                       ngx_close_file_n " \"%s\" failed", fm->name);
[667]     }
[668] }
[669] 
[670] 
[671] ngx_int_t
[672] ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
[673] {
[674]     dir->dir = opendir((const char *) name->data);
[675] 
[676]     if (dir->dir == NULL) {
[677]         return NGX_ERROR;
[678]     }
[679] 
[680]     dir->valid_info = 0;
[681] 
[682]     return NGX_OK;
[683] }
[684] 
[685] 
[686] ngx_int_t
[687] ngx_read_dir(ngx_dir_t *dir)
[688] {
[689]     dir->de = readdir(dir->dir);
[690] 
[691]     if (dir->de) {
[692] #if (NGX_HAVE_D_TYPE)
[693]         dir->type = dir->de->d_type;
[694] #else
[695]         dir->type = 0;
[696] #endif
[697]         return NGX_OK;
[698]     }
[699] 
[700]     return NGX_ERROR;
[701] }
[702] 
[703] 
[704] ngx_int_t
[705] ngx_open_glob(ngx_glob_t *gl)
[706] {
[707]     int  n;
[708] 
[709]     n = glob((char *) gl->pattern, 0, NULL, &gl->pglob);
[710] 
[711]     if (n == 0) {
[712]         return NGX_OK;
[713]     }
[714] 
[715] #ifdef GLOB_NOMATCH
[716] 
[717]     if (n == GLOB_NOMATCH && gl->test) {
[718]         return NGX_OK;
[719]     }
[720] 
[721] #endif
[722] 
[723]     return NGX_ERROR;
[724] }
[725] 
[726] 
[727] ngx_int_t
[728] ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name)
[729] {
[730]     size_t  count;
[731] 
[732] #ifdef GLOB_NOMATCH
[733]     count = (size_t) gl->pglob.gl_pathc;
[734] #else
[735]     count = (size_t) gl->pglob.gl_matchc;
[736] #endif
[737] 
[738]     if (gl->n < count) {
[739] 
[740]         name->len = (size_t) ngx_strlen(gl->pglob.gl_pathv[gl->n]);
[741]         name->data = (u_char *) gl->pglob.gl_pathv[gl->n];
[742]         gl->n++;
[743] 
[744]         return NGX_OK;
[745]     }
[746] 
[747]     return NGX_DONE;
[748] }
[749] 
[750] 
[751] void
[752] ngx_close_glob(ngx_glob_t *gl)
[753] {
[754]     globfree(&gl->pglob);
[755] }
[756] 
[757] 
[758] ngx_err_t
[759] ngx_trylock_fd(ngx_fd_t fd)
[760] {
[761]     struct flock  fl;
[762] 
[763]     ngx_memzero(&fl, sizeof(struct flock));
[764]     fl.l_type = F_WRLCK;
[765]     fl.l_whence = SEEK_SET;
[766] 
[767]     if (fcntl(fd, F_SETLK, &fl) == -1) {
[768]         return ngx_errno;
[769]     }
[770] 
[771]     return 0;
[772] }
[773] 
[774] 
[775] ngx_err_t
[776] ngx_lock_fd(ngx_fd_t fd)
[777] {
[778]     struct flock  fl;
[779] 
[780]     ngx_memzero(&fl, sizeof(struct flock));
[781]     fl.l_type = F_WRLCK;
[782]     fl.l_whence = SEEK_SET;
[783] 
[784]     if (fcntl(fd, F_SETLKW, &fl) == -1) {
[785]         return ngx_errno;
[786]     }
[787] 
[788]     return 0;
[789] }
[790] 
[791] 
[792] ngx_err_t
[793] ngx_unlock_fd(ngx_fd_t fd)
[794] {
[795]     struct flock  fl;
[796] 
[797]     ngx_memzero(&fl, sizeof(struct flock));
[798]     fl.l_type = F_UNLCK;
[799]     fl.l_whence = SEEK_SET;
[800] 
[801]     if (fcntl(fd, F_SETLK, &fl) == -1) {
[802]         return  ngx_errno;
[803]     }
[804] 
[805]     return 0;
[806] }
[807] 
[808] 
[809] #if (NGX_HAVE_POSIX_FADVISE) && !(NGX_HAVE_F_READAHEAD)
[810] 
[811] ngx_int_t
[812] ngx_read_ahead(ngx_fd_t fd, size_t n)
[813] {
[814]     int  err;
[815] 
[816]     err = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
[817] 
[818]     if (err == 0) {
[819]         return 0;
[820]     }
[821] 
[822]     ngx_set_errno(err);
[823]     return NGX_FILE_ERROR;
[824] }
[825] 
[826] #endif
[827] 
[828] 
[829] #if (NGX_HAVE_O_DIRECT)
[830] 
[831] ngx_int_t
[832] ngx_directio_on(ngx_fd_t fd)
[833] {
[834]     int  flags;
[835] 
[836]     flags = fcntl(fd, F_GETFL);
[837] 
[838]     if (flags == -1) {
[839]         return NGX_FILE_ERROR;
[840]     }
[841] 
[842]     return fcntl(fd, F_SETFL, flags | O_DIRECT);
[843] }
[844] 
[845] 
[846] ngx_int_t
[847] ngx_directio_off(ngx_fd_t fd)
[848] {
[849]     int  flags;
[850] 
[851]     flags = fcntl(fd, F_GETFL);
[852] 
[853]     if (flags == -1) {
[854]         return NGX_FILE_ERROR;
[855]     }
[856] 
[857]     return fcntl(fd, F_SETFL, flags & ~O_DIRECT);
[858] }
[859] 
[860] #endif
[861] 
[862] 
[863] #if (NGX_HAVE_STATFS)
[864] 
[865] size_t
[866] ngx_fs_bsize(u_char *name)
[867] {
[868]     struct statfs  fs;
[869] 
[870]     if (statfs((char *) name, &fs) == -1) {
[871]         return 512;
[872]     }
[873] 
[874]     if ((fs.f_bsize % 512) != 0) {
[875]         return 512;
[876]     }
[877] 
[878] #if (NGX_LINUX)
[879]     if ((size_t) fs.f_bsize > ngx_pagesize) {
[880]         return 512;
[881]     }
[882] #endif
[883] 
[884]     return (size_t) fs.f_bsize;
[885] }
[886] 
[887] 
[888] off_t
[889] ngx_fs_available(u_char *name)
[890] {
[891]     struct statfs  fs;
[892] 
[893]     if (statfs((char *) name, &fs) == -1) {
[894]         return NGX_MAX_OFF_T_VALUE;
[895]     }
[896] 
[897]     return (off_t) fs.f_bavail * fs.f_bsize;
[898] }
[899] 
[900] #elif (NGX_HAVE_STATVFS)
[901] 
[902] size_t
[903] ngx_fs_bsize(u_char *name)
[904] {
[905]     struct statvfs  fs;
[906] 
[907]     if (statvfs((char *) name, &fs) == -1) {
[908]         return 512;
[909]     }
[910] 
[911]     if ((fs.f_frsize % 512) != 0) {
[912]         return 512;
[913]     }
[914] 
[915] #if (NGX_LINUX)
[916]     if ((size_t) fs.f_frsize > ngx_pagesize) {
[917]         return 512;
[918]     }
[919] #endif
[920] 
[921]     return (size_t) fs.f_frsize;
[922] }
[923] 
[924] 
[925] off_t
[926] ngx_fs_available(u_char *name)
[927] {
[928]     struct statvfs  fs;
[929] 
[930]     if (statvfs((char *) name, &fs) == -1) {
[931]         return NGX_MAX_OFF_T_VALUE;
[932]     }
[933] 
[934]     return (off_t) fs.f_bavail * fs.f_frsize;
[935] }
[936] 
[937] #else
[938] 
[939] size_t
[940] ngx_fs_bsize(u_char *name)
[941] {
[942]     return 512;
[943] }
[944] 
[945] 
[946] off_t
[947] ngx_fs_available(u_char *name)
[948] {
[949]     return NGX_MAX_OFF_T_VALUE;
[950] }
[951] 
[952] #endif
