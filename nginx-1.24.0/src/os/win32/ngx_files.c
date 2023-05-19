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
[12] #define NGX_UTF16_BUFLEN  256
[13] #define NGX_UTF8_BUFLEN   512
[14] 
[15] static ngx_int_t ngx_win32_check_filename(u_short *u, size_t len,
[16]     ngx_uint_t dirname);
[17] static u_short *ngx_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t *len,
[18]     size_t reserved);
[19] static u_char *ngx_utf16_to_utf8(u_char *utf8, u_short *utf16, size_t *len,
[20]     size_t *allocated);
[21] uint32_t ngx_utf16_decode(u_short **u, size_t n);
[22] 
[23] 
[24] /* FILE_FLAG_BACKUP_SEMANTICS allows to obtain a handle to a directory */
[25] 
[26] ngx_fd_t
[27] ngx_open_file(u_char *name, u_long mode, u_long create, u_long access)
[28] {
[29]     size_t      len;
[30]     u_short    *u;
[31]     ngx_fd_t    fd;
[32]     ngx_err_t   err;
[33]     u_short     utf16[NGX_UTF16_BUFLEN];
[34] 
[35]     len = NGX_UTF16_BUFLEN;
[36]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[37] 
[38]     if (u == NULL) {
[39]         return INVALID_HANDLE_VALUE;
[40]     }
[41] 
[42]     fd = INVALID_HANDLE_VALUE;
[43] 
[44]     if (create == NGX_FILE_OPEN
[45]         && ngx_win32_check_filename(u, len, 0) != NGX_OK)
[46]     {
[47]         goto failed;
[48]     }
[49] 
[50]     fd = CreateFileW(u, mode,
[51]                      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
[52]                      NULL, create, FILE_FLAG_BACKUP_SEMANTICS, NULL);
[53] 
[54] failed:
[55] 
[56]     if (u != utf16) {
[57]         err = ngx_errno;
[58]         ngx_free(u);
[59]         ngx_set_errno(err);
[60]     }
[61] 
[62]     return fd;
[63] }
[64] 
[65] 
[66] ngx_fd_t
[67] ngx_open_tempfile(u_char *name, ngx_uint_t persistent, ngx_uint_t access)
[68] {
[69]     size_t      len;
[70]     u_short    *u;
[71]     ngx_fd_t    fd;
[72]     ngx_err_t   err;
[73]     u_short     utf16[NGX_UTF16_BUFLEN];
[74] 
[75]     len = NGX_UTF16_BUFLEN;
[76]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[77] 
[78]     if (u == NULL) {
[79]         return INVALID_HANDLE_VALUE;
[80]     }
[81] 
[82]     fd = CreateFileW(u,
[83]                      GENERIC_READ|GENERIC_WRITE,
[84]                      FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
[85]                      NULL,
[86]                      CREATE_NEW,
[87]                      persistent ? 0:
[88]                          FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,
[89]                      NULL);
[90] 
[91]     if (u != utf16) {
[92]         err = ngx_errno;
[93]         ngx_free(u);
[94]         ngx_set_errno(err);
[95]     }
[96] 
[97]     return fd;
[98] }
[99] 
[100] 
[101] ssize_t
[102] ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
[103] {
[104]     u_long      n;
[105]     ngx_err_t   err;
[106]     OVERLAPPED  ovlp, *povlp;
[107] 
[108]     ovlp.Internal = 0;
[109]     ovlp.InternalHigh = 0;
[110]     ovlp.Offset = (u_long) offset;
[111]     ovlp.OffsetHigh = (u_long) (offset >> 32);
[112]     ovlp.hEvent = NULL;
[113] 
[114]     povlp = &ovlp;
[115] 
[116]     if (ReadFile(file->fd, buf, size, &n, povlp) == 0) {
[117]         err = ngx_errno;
[118] 
[119]         if (err == ERROR_HANDLE_EOF) {
[120]             return 0;
[121]         }
[122] 
[123]         ngx_log_error(NGX_LOG_ERR, file->log, err,
[124]                       "ReadFile() \"%s\" failed", file->name.data);
[125]         return NGX_ERROR;
[126]     }
[127] 
[128]     file->offset += n;
[129] 
[130]     return n;
[131] }
[132] 
[133] 
[134] ssize_t
[135] ngx_write_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
[136] {
[137]     u_long      n;
[138]     OVERLAPPED  ovlp, *povlp;
[139] 
[140]     ovlp.Internal = 0;
[141]     ovlp.InternalHigh = 0;
[142]     ovlp.Offset = (u_long) offset;
[143]     ovlp.OffsetHigh = (u_long) (offset >> 32);
[144]     ovlp.hEvent = NULL;
[145] 
[146]     povlp = &ovlp;
[147] 
[148]     if (WriteFile(file->fd, buf, size, &n, povlp) == 0) {
[149]         ngx_log_error(NGX_LOG_ERR, file->log, ngx_errno,
[150]                       "WriteFile() \"%s\" failed", file->name.data);
[151]         return NGX_ERROR;
[152]     }
[153] 
[154]     if (n != size) {
[155]         ngx_log_error(NGX_LOG_CRIT, file->log, 0,
[156]                       "WriteFile() \"%s\" has written only %ul of %uz",
[157]                       file->name.data, n, size);
[158]         return NGX_ERROR;
[159]     }
[160] 
[161]     file->offset += n;
[162] 
[163]     return n;
[164] }
[165] 
[166] 
[167] ssize_t
[168] ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl, off_t offset,
[169]     ngx_pool_t *pool)
[170] {
[171]     u_char   *buf, *prev;
[172]     size_t    size;
[173]     ssize_t   total, n;
[174] 
[175]     total = 0;
[176] 
[177]     while (cl) {
[178]         buf = cl->buf->pos;
[179]         prev = buf;
[180]         size = 0;
[181] 
[182]         /* coalesce the neighbouring bufs */
[183] 
[184]         while (cl && prev == cl->buf->pos) {
[185]             size += cl->buf->last - cl->buf->pos;
[186]             prev = cl->buf->last;
[187]             cl = cl->next;
[188]         }
[189] 
[190]         n = ngx_write_file(file, buf, size, offset);
[191] 
[192]         if (n == NGX_ERROR) {
[193]             return NGX_ERROR;
[194]         }
[195] 
[196]         total += n;
[197]         offset += n;
[198]     }
[199] 
[200]     return total;
[201] }
[202] 
[203] 
[204] ssize_t
[205] ngx_read_fd(ngx_fd_t fd, void *buf, size_t size)
[206] {
[207]     u_long  n;
[208] 
[209]     if (ReadFile(fd, buf, size, &n, NULL) != 0) {
[210]         return (size_t) n;
[211]     }
[212] 
[213]     return -1;
[214] }
[215] 
[216] 
[217] ssize_t
[218] ngx_write_fd(ngx_fd_t fd, void *buf, size_t size)
[219] {
[220]     u_long  n;
[221] 
[222]     if (WriteFile(fd, buf, size, &n, NULL) != 0) {
[223]         return (size_t) n;
[224]     }
[225] 
[226]     return -1;
[227] }
[228] 
[229] 
[230] ssize_t
[231] ngx_write_console(ngx_fd_t fd, void *buf, size_t size)
[232] {
[233]     u_long  n;
[234] 
[235]     (void) CharToOemBuff(buf, buf, size);
[236] 
[237]     if (WriteFile(fd, buf, size, &n, NULL) != 0) {
[238]         return (size_t) n;
[239]     }
[240] 
[241]     return -1;
[242] }
[243] 
[244] 
[245] ngx_int_t
[246] ngx_delete_file(u_char *name)
[247] {
[248]     long        rc;
[249]     size_t      len;
[250]     u_short    *u;
[251]     ngx_err_t   err;
[252]     u_short     utf16[NGX_UTF16_BUFLEN];
[253] 
[254]     len = NGX_UTF16_BUFLEN;
[255]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[256] 
[257]     if (u == NULL) {
[258]         return NGX_FILE_ERROR;
[259]     }
[260] 
[261]     rc = NGX_FILE_ERROR;
[262] 
[263]     if (ngx_win32_check_filename(u, len, 0) != NGX_OK) {
[264]         goto failed;
[265]     }
[266] 
[267]     rc = DeleteFileW(u);
[268] 
[269] failed:
[270] 
[271]     if (u != utf16) {
[272]         err = ngx_errno;
[273]         ngx_free(u);
[274]         ngx_set_errno(err);
[275]     }
[276] 
[277]     return rc;
[278] }
[279] 
[280] 
[281] ngx_int_t
[282] ngx_rename_file(u_char *from, u_char *to)
[283] {
[284]     long        rc;
[285]     size_t      len;
[286]     u_short    *fu, *tu;
[287]     ngx_err_t   err;
[288]     u_short     utf16f[NGX_UTF16_BUFLEN];
[289]     u_short     utf16t[NGX_UTF16_BUFLEN];
[290] 
[291]     len = NGX_UTF16_BUFLEN;
[292]     fu = ngx_utf8_to_utf16(utf16f, from, &len, 0);
[293] 
[294]     if (fu == NULL) {
[295]         return NGX_FILE_ERROR;
[296]     }
[297] 
[298]     rc = NGX_FILE_ERROR;
[299]     tu = NULL;
[300] 
[301]     if (ngx_win32_check_filename(fu, len, 0) != NGX_OK) {
[302]         goto failed;
[303]     }
[304] 
[305]     len = NGX_UTF16_BUFLEN;
[306]     tu = ngx_utf8_to_utf16(utf16t, to, &len, 0);
[307] 
[308]     if (tu == NULL) {
[309]         goto failed;
[310]     }
[311] 
[312]     if (ngx_win32_check_filename(tu, len, 1) != NGX_OK) {
[313]         goto failed;
[314]     }
[315] 
[316]     rc = MoveFileW(fu, tu);
[317] 
[318] failed:
[319] 
[320]     if (fu != utf16f) {
[321]         err = ngx_errno;
[322]         ngx_free(fu);
[323]         ngx_set_errno(err);
[324]     }
[325] 
[326]     if (tu && tu != utf16t) {
[327]         err = ngx_errno;
[328]         ngx_free(tu);
[329]         ngx_set_errno(err);
[330]     }
[331] 
[332]     return rc;
[333] }
[334] 
[335] 
[336] ngx_err_t
[337] ngx_win32_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_log_t *log)
[338] {
[339]     u_char             *name;
[340]     ngx_err_t           err;
[341]     ngx_uint_t          collision;
[342]     ngx_atomic_uint_t   num;
[343] 
[344]     name = ngx_alloc(to->len + 1 + NGX_ATOMIC_T_LEN + 1 + sizeof("DELETE"),
[345]                      log);
[346]     if (name == NULL) {
[347]         return NGX_ENOMEM;
[348]     }
[349] 
[350]     ngx_memcpy(name, to->data, to->len);
[351] 
[352]     collision = 0;
[353] 
[354]     /* mutex_lock() (per cache or single ?) */
[355] 
[356]     for ( ;; ) {
[357]         num = ngx_next_temp_number(collision);
[358] 
[359]         ngx_sprintf(name + to->len, ".%0muA.DELETE%Z", num);
[360] 
[361]         if (ngx_rename_file(to->data, name) != NGX_FILE_ERROR) {
[362]             break;
[363]         }
[364] 
[365]         err = ngx_errno;
[366] 
[367]         if (err == NGX_EEXIST || err == NGX_EEXIST_FILE) {
[368]             collision = 1;
[369]             continue;
[370]         }
[371] 
[372]         ngx_log_error(NGX_LOG_CRIT, log, err,
[373]                       "MoveFile() \"%s\" to \"%s\" failed", to->data, name);
[374]         goto failed;
[375]     }
[376] 
[377]     if (ngx_rename_file(from->data, to->data) == NGX_FILE_ERROR) {
[378]         err = ngx_errno;
[379] 
[380]     } else {
[381]         err = 0;
[382]     }
[383] 
[384]     if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[385]         ngx_log_error(NGX_LOG_CRIT, log, ngx_errno,
[386]                       "DeleteFile() \"%s\" failed", name);
[387]     }
[388] 
[389] failed:
[390] 
[391]     /* mutex_unlock() */
[392] 
[393]     ngx_free(name);
[394] 
[395]     return err;
[396] }
[397] 
[398] 
[399] ngx_int_t
[400] ngx_file_info(u_char *file, ngx_file_info_t *sb)
[401] {
[402]     size_t                      len;
[403]     long                        rc;
[404]     u_short                    *u;
[405]     ngx_err_t                   err;
[406]     WIN32_FILE_ATTRIBUTE_DATA   fa;
[407]     u_short                     utf16[NGX_UTF16_BUFLEN];
[408] 
[409]     len = NGX_UTF16_BUFLEN;
[410] 
[411]     u = ngx_utf8_to_utf16(utf16, file, &len, 0);
[412] 
[413]     if (u == NULL) {
[414]         return NGX_FILE_ERROR;
[415]     }
[416] 
[417]     rc = NGX_FILE_ERROR;
[418] 
[419]     if (ngx_win32_check_filename(u, len, 0) != NGX_OK) {
[420]         goto failed;
[421]     }
[422] 
[423]     rc = GetFileAttributesExW(u, GetFileExInfoStandard, &fa);
[424] 
[425]     sb->dwFileAttributes = fa.dwFileAttributes;
[426]     sb->ftCreationTime = fa.ftCreationTime;
[427]     sb->ftLastAccessTime = fa.ftLastAccessTime;
[428]     sb->ftLastWriteTime = fa.ftLastWriteTime;
[429]     sb->nFileSizeHigh = fa.nFileSizeHigh;
[430]     sb->nFileSizeLow = fa.nFileSizeLow;
[431] 
[432] failed:
[433] 
[434]     if (u != utf16) {
[435]         err = ngx_errno;
[436]         ngx_free(u);
[437]         ngx_set_errno(err);
[438]     }
[439] 
[440]     return rc;
[441] }
[442] 
[443] 
[444] ngx_int_t
[445] ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s)
[446] {
[447]     uint64_t  intervals;
[448]     FILETIME  ft;
[449] 
[450]     /* 116444736000000000 is commented in src/os/win32/ngx_time.c */
[451] 
[452]     intervals = s * 10000000 + 116444736000000000;
[453] 
[454]     ft.dwLowDateTime = (DWORD) intervals;
[455]     ft.dwHighDateTime = (DWORD) (intervals >> 32);
[456] 
[457]     if (SetFileTime(fd, NULL, NULL, &ft) != 0) {
[458]         return NGX_OK;
[459]     }
[460] 
[461]     return NGX_ERROR;
[462] }
[463] 
[464] 
[465] ngx_int_t
[466] ngx_create_file_mapping(ngx_file_mapping_t *fm)
[467] {
[468]     LARGE_INTEGER  size;
[469] 
[470]     fm->fd = ngx_open_file(fm->name, NGX_FILE_RDWR, NGX_FILE_TRUNCATE,
[471]                            NGX_FILE_DEFAULT_ACCESS);
[472] 
[473]     if (fm->fd == NGX_INVALID_FILE) {
[474]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[475]                       ngx_open_file_n " \"%s\" failed", fm->name);
[476]         return NGX_ERROR;
[477]     }
[478] 
[479]     fm->handle = NULL;
[480] 
[481]     size.QuadPart = fm->size;
[482] 
[483]     if (SetFilePointerEx(fm->fd, size, NULL, FILE_BEGIN) == 0) {
[484]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[485]                       "SetFilePointerEx(\"%s\", %uz) failed",
[486]                       fm->name, fm->size);
[487]         goto failed;
[488]     }
[489] 
[490]     if (SetEndOfFile(fm->fd) == 0) {
[491]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[492]                       "SetEndOfFile() \"%s\" failed", fm->name);
[493]         goto failed;
[494]     }
[495] 
[496]     fm->handle = CreateFileMapping(fm->fd, NULL, PAGE_READWRITE,
[497]                                    (u_long) ((off_t) fm->size >> 32),
[498]                                    (u_long) ((off_t) fm->size & 0xffffffff),
[499]                                    NULL);
[500]     if (fm->handle == NULL) {
[501]         ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[502]                       "CreateFileMapping(%s, %uz) failed",
[503]                       fm->name, fm->size);
[504]         goto failed;
[505]     }
[506] 
[507]     fm->addr = MapViewOfFile(fm->handle, FILE_MAP_WRITE, 0, 0, 0);
[508] 
[509]     if (fm->addr != NULL) {
[510]         return NGX_OK;
[511]     }
[512] 
[513]     ngx_log_error(NGX_LOG_CRIT, fm->log, ngx_errno,
[514]                   "MapViewOfFile(%uz) of file mapping \"%s\" failed",
[515]                   fm->size, fm->name);
[516] 
[517] failed:
[518] 
[519]     if (fm->handle) {
[520]         if (CloseHandle(fm->handle) == 0) {
[521]             ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[522]                           "CloseHandle() of file mapping \"%s\" failed",
[523]                           fm->name);
[524]         }
[525]     }
[526] 
[527]     if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
[528]         ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[529]                       ngx_close_file_n " \"%s\" failed", fm->name);
[530]     }
[531] 
[532]     return NGX_ERROR;
[533] }
[534] 
[535] 
[536] void
[537] ngx_close_file_mapping(ngx_file_mapping_t *fm)
[538] {
[539]     if (UnmapViewOfFile(fm->addr) == 0) {
[540]         ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[541]                       "UnmapViewOfFile(%p) of file mapping \"%s\" failed",
[542]                       fm->addr, &fm->name);
[543]     }
[544] 
[545]     if (CloseHandle(fm->handle) == 0) {
[546]         ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[547]                       "CloseHandle() of file mapping \"%s\" failed",
[548]                       &fm->name);
[549]     }
[550] 
[551]     if (ngx_close_file(fm->fd) == NGX_FILE_ERROR) {
[552]         ngx_log_error(NGX_LOG_ALERT, fm->log, ngx_errno,
[553]                       ngx_close_file_n " \"%s\" failed", fm->name);
[554]     }
[555] }
[556] 
[557] 
[558] u_char *
[559] ngx_realpath(u_char *path, u_char *resolved)
[560] {
[561]     /* STUB */
[562]     return path;
[563] }
[564] 
[565] 
[566] size_t
[567] ngx_getcwd(u_char *buf, size_t size)
[568] {
[569]     u_char   *p;
[570]     size_t    n;
[571]     u_short   utf16[NGX_MAX_PATH];
[572] 
[573]     n = GetCurrentDirectoryW(NGX_MAX_PATH, utf16);
[574] 
[575]     if (n == 0) {
[576]         return 0;
[577]     }
[578] 
[579]     if (n > NGX_MAX_PATH) {
[580]         ngx_set_errno(ERROR_INSUFFICIENT_BUFFER);
[581]         return 0;
[582]     }
[583] 
[584]     p = ngx_utf16_to_utf8(buf, utf16, &size, NULL);
[585] 
[586]     if (p == NULL) {
[587]         return 0;
[588]     }
[589] 
[590]     if (p != buf) {
[591]         ngx_free(p);
[592]         ngx_set_errno(ERROR_INSUFFICIENT_BUFFER);
[593]         return 0;
[594]     }
[595] 
[596]     return size - 1;
[597] }
[598] 
[599] 
[600] ngx_int_t
[601] ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir)
[602] {
[603]     size_t      len;
[604]     u_short    *u, *p;
[605]     ngx_err_t   err;
[606]     u_short     utf16[NGX_UTF16_BUFLEN];
[607] 
[608]     len = NGX_UTF16_BUFLEN - 2;
[609]     u = ngx_utf8_to_utf16(utf16, name->data, &len, 2);
[610] 
[611]     if (u == NULL) {
[612]         return NGX_ERROR;
[613]     }
[614] 
[615]     if (ngx_win32_check_filename(u, len, 0) != NGX_OK) {
[616]         goto failed;
[617]     }
[618] 
[619]     p = &u[len - 1];
[620] 
[621]     *p++ = '/';
[622]     *p++ = '*';
[623]     *p = '\0';
[624] 
[625]     dir->dir = FindFirstFileW(u, &dir->finddata);
[626] 
[627]     if (dir->dir == INVALID_HANDLE_VALUE) {
[628]         goto failed;
[629]     }
[630] 
[631]     if (u != utf16) {
[632]         ngx_free(u);
[633]     }
[634] 
[635]     dir->valid_info = 1;
[636]     dir->ready = 1;
[637]     dir->name = NULL;
[638]     dir->allocated = 0;
[639] 
[640]     return NGX_OK;
[641] 
[642] failed:
[643] 
[644]     if (u != utf16) {
[645]         err = ngx_errno;
[646]         ngx_free(u);
[647]         ngx_set_errno(err);
[648]     }
[649] 
[650]     return NGX_ERROR;
[651] }
[652] 
[653] 
[654] ngx_int_t
[655] ngx_read_dir(ngx_dir_t *dir)
[656] {
[657]     u_char  *name;
[658]     size_t   len, allocated;
[659] 
[660]     if (dir->ready) {
[661]         dir->ready = 0;
[662]         goto convert;
[663]     }
[664] 
[665]     if (FindNextFileW(dir->dir, &dir->finddata) != 0) {
[666]         dir->type = 1;
[667]         goto convert;
[668]     }
[669] 
[670]     return NGX_ERROR;
[671] 
[672] convert:
[673] 
[674]     name = dir->name;
[675]     len = dir->allocated;
[676] 
[677]     name = ngx_utf16_to_utf8(name, dir->finddata.cFileName, &len, &allocated);
[678] 
[679]     if (name == NULL) {
[680]         return NGX_ERROR;
[681]     }
[682] 
[683]     if (name != dir->name) {
[684] 
[685]         if (dir->name) {
[686]             ngx_free(dir->name);
[687]         }
[688] 
[689]         dir->name = name;
[690]         dir->allocated = allocated;
[691]     }
[692] 
[693]     dir->namelen = len - 1;
[694] 
[695]     return NGX_OK;
[696] }
[697] 
[698] 
[699] ngx_int_t
[700] ngx_close_dir(ngx_dir_t *dir)
[701] {
[702]     if (dir->name) {
[703]         ngx_free(dir->name);
[704]     }
[705] 
[706]     if (FindClose(dir->dir) == 0) {
[707]         return NGX_ERROR;
[708]     }
[709] 
[710]     return NGX_OK;
[711] }
[712] 
[713] 
[714] ngx_int_t
[715] ngx_create_dir(u_char *name, ngx_uint_t access)
[716] {
[717]     long        rc;
[718]     size_t      len;
[719]     u_short    *u;
[720]     ngx_err_t   err;
[721]     u_short     utf16[NGX_UTF16_BUFLEN];
[722] 
[723]     len = NGX_UTF16_BUFLEN;
[724]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[725] 
[726]     if (u == NULL) {
[727]         return NGX_FILE_ERROR;
[728]     }
[729] 
[730]     rc = NGX_FILE_ERROR;
[731] 
[732]     if (ngx_win32_check_filename(u, len, 1) != NGX_OK) {
[733]         goto failed;
[734]     }
[735] 
[736]     rc = CreateDirectoryW(u, NULL);
[737] 
[738] failed:
[739] 
[740]     if (u != utf16) {
[741]         err = ngx_errno;
[742]         ngx_free(u);
[743]         ngx_set_errno(err);
[744]     }
[745] 
[746]     return rc;
[747] }
[748] 
[749] 
[750] ngx_int_t
[751] ngx_delete_dir(u_char *name)
[752] {
[753]     long        rc;
[754]     size_t      len;
[755]     u_short    *u;
[756]     ngx_err_t   err;
[757]     u_short     utf16[NGX_UTF16_BUFLEN];
[758] 
[759]     len = NGX_UTF16_BUFLEN;
[760]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[761] 
[762]     if (u == NULL) {
[763]         return NGX_FILE_ERROR;
[764]     }
[765] 
[766]     rc = NGX_FILE_ERROR;
[767] 
[768]     if (ngx_win32_check_filename(u, len, 0) != NGX_OK) {
[769]         goto failed;
[770]     }
[771] 
[772]     rc = RemoveDirectoryW(u);
[773] 
[774] failed:
[775] 
[776]     if (u != utf16) {
[777]         err = ngx_errno;
[778]         ngx_free(u);
[779]         ngx_set_errno(err);
[780]     }
[781] 
[782]     return rc;
[783] }
[784] 
[785] 
[786] ngx_int_t
[787] ngx_open_glob(ngx_glob_t *gl)
[788] {
[789]     u_char     *p;
[790]     size_t      len;
[791]     u_short    *u;
[792]     ngx_err_t   err;
[793]     u_short     utf16[NGX_UTF16_BUFLEN];
[794] 
[795]     len = NGX_UTF16_BUFLEN;
[796]     u = ngx_utf8_to_utf16(utf16, gl->pattern, &len, 0);
[797] 
[798]     if (u == NULL) {
[799]         return NGX_ERROR;
[800]     }
[801] 
[802]     gl->dir = FindFirstFileW(u, &gl->finddata);
[803] 
[804]     if (gl->dir == INVALID_HANDLE_VALUE) {
[805] 
[806]         err = ngx_errno;
[807] 
[808]         if (u != utf16) {
[809]             ngx_free(u);
[810]         }
[811] 
[812]         if ((err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
[813]              && gl->test)
[814]         {
[815]             gl->no_match = 1;
[816]             return NGX_OK;
[817]         }
[818] 
[819]         ngx_set_errno(err);
[820] 
[821]         return NGX_ERROR;
[822]     }
[823] 
[824]     for (p = gl->pattern; *p; p++) {
[825]         if (*p == '/') {
[826]             gl->last = p + 1 - gl->pattern;
[827]         }
[828]     }
[829] 
[830]     if (u != utf16) {
[831]         ngx_free(u);
[832]     }
[833] 
[834]     gl->ready = 1;
[835] 
[836]     return NGX_OK;
[837] }
[838] 
[839] 
[840] ngx_int_t
[841] ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name)
[842] {
[843]     u_char     *p;
[844]     size_t      len;
[845]     ngx_err_t   err;
[846]     u_char      utf8[NGX_UTF8_BUFLEN];
[847] 
[848]     if (gl->no_match) {
[849]         return NGX_DONE;
[850]     }
[851] 
[852]     if (gl->ready) {
[853]         gl->ready = 0;
[854]         goto convert;
[855]     }
[856] 
[857]     ngx_free(gl->name.data);
[858]     gl->name.data = NULL;
[859] 
[860]     if (FindNextFileW(gl->dir, &gl->finddata) != 0) {
[861]         goto convert;
[862]     }
[863] 
[864]     err = ngx_errno;
[865] 
[866]     if (err == NGX_ENOMOREFILES) {
[867]         return NGX_DONE;
[868]     }
[869] 
[870]     ngx_log_error(NGX_LOG_ALERT, gl->log, err,
[871]                   "FindNextFile(%s) failed", gl->pattern);
[872] 
[873]     return NGX_ERROR;
[874] 
[875] convert:
[876] 
[877]     len = NGX_UTF8_BUFLEN;
[878]     p = ngx_utf16_to_utf8(utf8, gl->finddata.cFileName, &len, NULL);
[879] 
[880]     if (p == NULL) {
[881]         return NGX_ERROR;
[882]     }
[883] 
[884]     gl->name.len = gl->last + len - 1;
[885] 
[886]     gl->name.data = ngx_alloc(gl->name.len + 1, gl->log);
[887]     if (gl->name.data == NULL) {
[888]         goto failed;
[889]     }
[890] 
[891]     ngx_memcpy(gl->name.data, gl->pattern, gl->last);
[892]     ngx_cpystrn(gl->name.data + gl->last, p, len);
[893] 
[894]     if (p != utf8) {
[895]         ngx_free(p);
[896]     }
[897] 
[898]     *name = gl->name;
[899] 
[900]     return NGX_OK;
[901] 
[902] failed:
[903] 
[904]     if (p != utf8) {
[905]         err = ngx_errno;
[906]         ngx_free(p);
[907]         ngx_set_errno(err);
[908]     }
[909] 
[910]     return NGX_ERROR;
[911] }
[912] 
[913] 
[914] void
[915] ngx_close_glob(ngx_glob_t *gl)
[916] {
[917]     if (gl->name.data) {
[918]         ngx_free(gl->name.data);
[919]     }
[920] 
[921]     if (gl->dir == INVALID_HANDLE_VALUE) {
[922]         return;
[923]     }
[924] 
[925]     if (FindClose(gl->dir) == 0) {
[926]         ngx_log_error(NGX_LOG_ALERT, gl->log, ngx_errno,
[927]                       "FindClose(%s) failed", gl->pattern);
[928]     }
[929] }
[930] 
[931] 
[932] ngx_int_t
[933] ngx_de_info(u_char *name, ngx_dir_t *dir)
[934] {
[935]     return NGX_OK;
[936] }
[937] 
[938] 
[939] ngx_int_t
[940] ngx_de_link_info(u_char *name, ngx_dir_t *dir)
[941] {
[942]     return NGX_OK;
[943] }
[944] 
[945] 
[946] ngx_int_t
[947] ngx_read_ahead(ngx_fd_t fd, size_t n)
[948] {
[949]     return ~NGX_FILE_ERROR;
[950] }
[951] 
[952] 
[953] ngx_int_t
[954] ngx_directio_on(ngx_fd_t fd)
[955] {
[956]     return ~NGX_FILE_ERROR;
[957] }
[958] 
[959] 
[960] ngx_int_t
[961] ngx_directio_off(ngx_fd_t fd)
[962] {
[963]     return ~NGX_FILE_ERROR;
[964] }
[965] 
[966] 
[967] size_t
[968] ngx_fs_bsize(u_char *name)
[969] {
[970]     u_long    sc, bs, nfree, ncl;
[971]     size_t    len;
[972]     u_short  *u;
[973]     u_short   utf16[NGX_UTF16_BUFLEN];
[974] 
[975]     len = NGX_UTF16_BUFLEN;
[976]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[977] 
[978]     if (u == NULL) {
[979]         return 512;
[980]     }
[981] 
[982]     if (GetDiskFreeSpaceW(u, &sc, &bs, &nfree, &ncl) == 0) {
[983] 
[984]         if (u != utf16) {
[985]             ngx_free(u);
[986]         }
[987] 
[988]         return 512;
[989]     }
[990] 
[991]     if (u != utf16) {
[992]         ngx_free(u);
[993]     }
[994] 
[995]     return sc * bs;
[996] }
[997] 
[998] 
[999] off_t
[1000] ngx_fs_available(u_char *name)
[1001] {
[1002]     size_t           len;
[1003]     u_short         *u;
[1004]     ULARGE_INTEGER   navail;
[1005]     u_short          utf16[NGX_UTF16_BUFLEN];
[1006] 
[1007]     len = NGX_UTF16_BUFLEN;
[1008]     u = ngx_utf8_to_utf16(utf16, name, &len, 0);
[1009] 
[1010]     if (u == NULL) {
[1011]         return NGX_MAX_OFF_T_VALUE;
[1012]     }
[1013] 
[1014]     if (GetDiskFreeSpaceExW(u, &navail, NULL, NULL) == 0) {
[1015] 
[1016]         if (u != utf16) {
[1017]             ngx_free(u);
[1018]         }
[1019] 
[1020]         return NGX_MAX_OFF_T_VALUE;
[1021]     }
[1022] 
[1023]     if (u != utf16) {
[1024]         ngx_free(u);
[1025]     }
[1026] 
[1027]     return (off_t) navail.QuadPart;
[1028] }
[1029] 
[1030] 
[1031] static ngx_int_t
[1032] ngx_win32_check_filename(u_short *u, size_t len, ngx_uint_t dirname)
[1033] {
[1034]     u_long      n;
[1035]     u_short    *lu, *p, *slash, ch;
[1036]     ngx_err_t   err;
[1037]     enum {
[1038]         sw_start = 0,
[1039]         sw_normal,
[1040]         sw_after_slash,
[1041]         sw_after_colon,
[1042]         sw_after_dot
[1043]     } state;
[1044] 
[1045]     /* check for NTFS streams (":"), trailing dots and spaces */
[1046] 
[1047]     lu = NULL;
[1048]     slash = NULL;
[1049]     state = sw_start;
[1050] 
[1051] #if (NGX_SUPPRESS_WARN)
[1052]     ch = 0;
[1053] #endif
[1054] 
[1055]     for (p = u; *p; p++) {
[1056]         ch = *p;
[1057] 
[1058]         switch (state) {
[1059] 
[1060]         case sw_start:
[1061] 
[1062]             /*
[1063]              * skip till first "/" to allow paths starting with drive and
[1064]              * relative path, like "c:html/"
[1065]              */
[1066] 
[1067]             if (ch == '/' || ch == '\\') {
[1068]                 state = sw_after_slash;
[1069]                 slash = p;
[1070]             }
[1071] 
[1072]             break;
[1073] 
[1074]         case sw_normal:
[1075] 
[1076]             if (ch == ':') {
[1077]                 state = sw_after_colon;
[1078]                 break;
[1079]             }
[1080] 
[1081]             if (ch == '.' || ch == ' ') {
[1082]                 state = sw_after_dot;
[1083]                 break;
[1084]             }
[1085] 
[1086]             if (ch == '/' || ch == '\\') {
[1087]                 state = sw_after_slash;
[1088]                 slash = p;
[1089]                 break;
[1090]             }
[1091] 
[1092]             break;
[1093] 
[1094]         case sw_after_slash:
[1095] 
[1096]             if (ch == '/' || ch == '\\') {
[1097]                 break;
[1098]             }
[1099] 
[1100]             if (ch == '.') {
[1101]                 break;
[1102]             }
[1103] 
[1104]             if (ch == ':') {
[1105]                 state = sw_after_colon;
[1106]                 break;
[1107]             }
[1108] 
[1109]             state = sw_normal;
[1110]             break;
[1111] 
[1112]         case sw_after_colon:
[1113] 
[1114]             if (ch == '/' || ch == '\\') {
[1115]                 state = sw_after_slash;
[1116]                 slash = p;
[1117]                 break;
[1118]             }
[1119] 
[1120]             goto invalid;
[1121] 
[1122]         case sw_after_dot:
[1123] 
[1124]             if (ch == '/' || ch == '\\') {
[1125]                 goto invalid;
[1126]             }
[1127] 
[1128]             if (ch == ':') {
[1129]                 goto invalid;
[1130]             }
[1131] 
[1132]             if (ch == '.' || ch == ' ') {
[1133]                 break;
[1134]             }
[1135] 
[1136]             state = sw_normal;
[1137]             break;
[1138]         }
[1139]     }
[1140] 
[1141]     if (state == sw_after_dot) {
[1142]         goto invalid;
[1143]     }
[1144] 
[1145]     if (dirname && slash) {
[1146]         ch = *slash;
[1147]         *slash = '\0';
[1148]         len = slash - u + 1;
[1149]     }
[1150] 
[1151]     /* check if long name match */
[1152] 
[1153]     lu = malloc(len * 2);
[1154]     if (lu == NULL) {
[1155]         return NGX_ERROR;
[1156]     }
[1157] 
[1158]     n = GetLongPathNameW(u, lu, len);
[1159] 
[1160]     if (n == 0) {
[1161] 
[1162]         if (dirname && slash && ngx_errno == NGX_ENOENT) {
[1163]             ngx_set_errno(NGX_ENOPATH);
[1164]         }
[1165] 
[1166]         goto failed;
[1167]     }
[1168] 
[1169]     if (n != len - 1 || _wcsicmp(u, lu) != 0) {
[1170]         goto invalid;
[1171]     }
[1172] 
[1173]     if (dirname && slash) {
[1174]         *slash = ch;
[1175]     }
[1176] 
[1177]     ngx_free(lu);
[1178] 
[1179]     return NGX_OK;
[1180] 
[1181] invalid:
[1182] 
[1183]     ngx_set_errno(NGX_ENOENT);
[1184] 
[1185] failed:
[1186] 
[1187]     if (dirname && slash) {
[1188]         *slash = ch;
[1189]     }
[1190] 
[1191]     if (lu) {
[1192]         err = ngx_errno;
[1193]         ngx_free(lu);
[1194]         ngx_set_errno(err);
[1195]     }
[1196] 
[1197]     return NGX_ERROR;
[1198] }
[1199] 
[1200] 
[1201] static u_short *
[1202] ngx_utf8_to_utf16(u_short *utf16, u_char *utf8, size_t *len, size_t reserved)
[1203] {
[1204]     u_char    *p;
[1205]     u_short   *u, *last;
[1206]     uint32_t   n;
[1207] 
[1208]     p = utf8;
[1209]     u = utf16;
[1210]     last = utf16 + *len;
[1211] 
[1212]     while (u < last) {
[1213] 
[1214]         if (*p < 0x80) {
[1215]             *u++ = (u_short) *p;
[1216] 
[1217]             if (*p == 0) {
[1218]                 *len = u - utf16;
[1219]                 return utf16;
[1220]             }
[1221] 
[1222]             p++;
[1223] 
[1224]             continue;
[1225]         }
[1226] 
[1227]         if (u + 1 == last) {
[1228]             *len = u - utf16;
[1229]             break;
[1230]         }
[1231] 
[1232]         n = ngx_utf8_decode(&p, 4);
[1233] 
[1234]         if (n > 0x10ffff) {
[1235]             ngx_set_errno(NGX_EILSEQ);
[1236]             return NULL;
[1237]         }
[1238] 
[1239]         if (n > 0xffff) {
[1240]             n -= 0x10000;
[1241]             *u++ = (u_short) (0xd800 + (n >> 10));
[1242]             *u++ = (u_short) (0xdc00 + (n & 0x03ff));
[1243]             continue;
[1244]         }
[1245] 
[1246]         *u++ = (u_short) n;
[1247]     }
[1248] 
[1249]     /* the given buffer is not enough, allocate a new one */
[1250] 
[1251]     u = malloc(((p - utf8) + ngx_strlen(p) + 1 + reserved) * sizeof(u_short));
[1252]     if (u == NULL) {
[1253]         return NULL;
[1254]     }
[1255] 
[1256]     ngx_memcpy(u, utf16, *len * 2);
[1257] 
[1258]     utf16 = u;
[1259]     u += *len;
[1260] 
[1261]     for ( ;; ) {
[1262] 
[1263]         if (*p < 0x80) {
[1264]             *u++ = (u_short) *p;
[1265] 
[1266]             if (*p == 0) {
[1267]                 *len = u - utf16;
[1268]                 return utf16;
[1269]             }
[1270] 
[1271]             p++;
[1272] 
[1273]             continue;
[1274]         }
[1275] 
[1276]         n = ngx_utf8_decode(&p, 4);
[1277] 
[1278]         if (n > 0x10ffff) {
[1279]             ngx_free(utf16);
[1280]             ngx_set_errno(NGX_EILSEQ);
[1281]             return NULL;
[1282]         }
[1283] 
[1284]         if (n > 0xffff) {
[1285]             n -= 0x10000;
[1286]             *u++ = (u_short) (0xd800 + (n >> 10));
[1287]             *u++ = (u_short) (0xdc00 + (n & 0x03ff));
[1288]             continue;
[1289]         }
[1290] 
[1291]         *u++ = (u_short) n;
[1292]     }
[1293] 
[1294]     /* unreachable */
[1295] }
[1296] 
[1297] 
[1298] static u_char *
[1299] ngx_utf16_to_utf8(u_char *utf8, u_short *utf16, size_t *len, size_t *allocated)
[1300] {
[1301]     u_char    *p, *last;
[1302]     u_short   *u, *j;
[1303]     uint32_t   n;
[1304] 
[1305]     u = utf16;
[1306]     p = utf8;
[1307]     last = utf8 + *len;
[1308] 
[1309]     while (p < last) {
[1310] 
[1311]         if (*u < 0x80) {
[1312]             *p++ = (u_char) *u;
[1313] 
[1314]             if (*u == 0) {
[1315]                 *len = p - utf8;
[1316]                 return utf8;
[1317]             }
[1318] 
[1319]             u++;
[1320] 
[1321]             continue;
[1322]         }
[1323] 
[1324]         if (p >= last - 4) {
[1325]             *len = p - utf8;
[1326]             break;
[1327]         }
[1328] 
[1329]         n = ngx_utf16_decode(&u, 2);
[1330] 
[1331]         if (n > 0x10ffff) {
[1332]             ngx_set_errno(NGX_EILSEQ);
[1333]             return NULL;
[1334]         }
[1335] 
[1336]         if (n >= 0x10000) {
[1337]             *p++ = (u_char) (0xf0 + (n >> 18));
[1338]             *p++ = (u_char) (0x80 + ((n >> 12) & 0x3f));
[1339]             *p++ = (u_char) (0x80 + ((n >> 6) & 0x3f));
[1340]             *p++ = (u_char) (0x80 + (n & 0x3f));
[1341]             continue;
[1342]         }
[1343] 
[1344]         if (n >= 0x0800) {
[1345]             *p++ = (u_char) (0xe0 + (n >> 12));
[1346]             *p++ = (u_char) (0x80 + ((n >> 6) & 0x3f));
[1347]             *p++ = (u_char) (0x80 + (n & 0x3f));
[1348]             continue;
[1349]         }
[1350] 
[1351]         *p++ = (u_char) (0xc0 + (n >> 6));
[1352]         *p++ = (u_char) (0x80 + (n & 0x3f));
[1353]     }
[1354] 
[1355]     /* the given buffer is not enough, allocate a new one */
[1356] 
[1357]     for (j = u; *j; j++) { /* void */ }
[1358] 
[1359]     p = malloc((j - utf16) * 4 + 1);
[1360]     if (p == NULL) {
[1361]         return NULL;
[1362]     }
[1363] 
[1364]     if (allocated) {
[1365]         *allocated = (j - utf16) * 4 + 1;
[1366]     }
[1367] 
[1368]     ngx_memcpy(p, utf8, *len);
[1369] 
[1370]     utf8 = p;
[1371]     p += *len;
[1372] 
[1373]     for ( ;; ) {
[1374] 
[1375]         if (*u < 0x80) {
[1376]             *p++ = (u_char) *u;
[1377] 
[1378]             if (*u == 0) {
[1379]                 *len = p - utf8;
[1380]                 return utf8;
[1381]             }
[1382] 
[1383]             u++;
[1384] 
[1385]             continue;
[1386]         }
[1387] 
[1388]         n = ngx_utf16_decode(&u, 2);
[1389] 
[1390]         if (n > 0x10ffff) {
[1391]             ngx_free(utf8);
[1392]             ngx_set_errno(NGX_EILSEQ);
[1393]             return NULL;
[1394]         }
[1395] 
[1396]         if (n >= 0x10000) {
[1397]             *p++ = (u_char) (0xf0 + (n >> 18));
[1398]             *p++ = (u_char) (0x80 + ((n >> 12) & 0x3f));
[1399]             *p++ = (u_char) (0x80 + ((n >> 6) & 0x3f));
[1400]             *p++ = (u_char) (0x80 + (n & 0x3f));
[1401]             continue;
[1402]         }
[1403] 
[1404]         if (n >= 0x0800) {
[1405]             *p++ = (u_char) (0xe0 + (n >> 12));
[1406]             *p++ = (u_char) (0x80 + ((n >> 6) & 0x3f));
[1407]             *p++ = (u_char) (0x80 + (n & 0x3f));
[1408]             continue;
[1409]         }
[1410] 
[1411]         *p++ = (u_char) (0xc0 + (n >> 6));
[1412]         *p++ = (u_char) (0x80 + (n & 0x3f));
[1413]     }
[1414] 
[1415]     /* unreachable */
[1416] }
[1417] 
[1418] 
[1419] /*
[1420]  * ngx_utf16_decode() decodes one or two UTF-16 code units
[1421]  * the return values:
[1422]  *    0x80 - 0x10ffff         valid character
[1423]  *    0x110000 - 0xfffffffd   invalid sequence
[1424]  *    0xfffffffe              incomplete sequence
[1425]  *    0xffffffff              error
[1426]  */
[1427] 
[1428] uint32_t
[1429] ngx_utf16_decode(u_short **u, size_t n)
[1430] {
[1431]     uint32_t  k, m;
[1432] 
[1433]     k = **u;
[1434] 
[1435]     if (k < 0xd800 || k > 0xdfff) {
[1436]         (*u)++;
[1437]         return k;
[1438]     }
[1439] 
[1440]     if (k > 0xdbff) {
[1441]         (*u)++;
[1442]         return 0xffffffff;
[1443]     }
[1444] 
[1445]     if (n < 2) {
[1446]         return 0xfffffffe;
[1447]     }
[1448] 
[1449]     (*u)++;
[1450] 
[1451]     m = *(*u)++;
[1452] 
[1453]     if (m < 0xdc00 || m > 0xdfff) {
[1454]         return 0xffffffff;
[1455] 
[1456]     }
[1457] 
[1458]     return 0x10000 + ((k - 0xd800) << 10) + (m - 0xdc00);
[1459] }
