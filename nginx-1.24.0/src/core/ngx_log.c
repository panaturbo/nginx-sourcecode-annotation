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
[12] static char *ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[13] static char *ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log);
[14] static void ngx_log_insert(ngx_log_t *log, ngx_log_t *new_log);
[15] 
[16] 
[17] #if (NGX_DEBUG)
[18] 
[19] static void ngx_log_memory_writer(ngx_log_t *log, ngx_uint_t level,
[20]     u_char *buf, size_t len);
[21] static void ngx_log_memory_cleanup(void *data);
[22] 
[23] 
[24] typedef struct {
[25]     u_char        *start;
[26]     u_char        *end;
[27]     u_char        *pos;
[28]     ngx_atomic_t   written;
[29] } ngx_log_memory_buf_t;
[30] 
[31] #endif
[32] 
[33] 
[34] static ngx_command_t  ngx_errlog_commands[] = {
[35] 
[36]     { ngx_string("error_log"),
[37]       NGX_MAIN_CONF|NGX_CONF_1MORE,
[38]       ngx_error_log,
[39]       0,
[40]       0,
[41]       NULL },
[42] 
[43]       ngx_null_command
[44] };
[45] 
[46] 
[47] static ngx_core_module_t  ngx_errlog_module_ctx = {
[48]     ngx_string("errlog"),
[49]     NULL,
[50]     NULL
[51] };
[52] 
[53] 
[54] ngx_module_t  ngx_errlog_module = {
[55]     NGX_MODULE_V1,
[56]     &ngx_errlog_module_ctx,                /* module context */
[57]     ngx_errlog_commands,                   /* module directives */
[58]     NGX_CORE_MODULE,                       /* module type */
[59]     NULL,                                  /* init master */
[60]     NULL,                                  /* init module */
[61]     NULL,                                  /* init process */
[62]     NULL,                                  /* init thread */
[63]     NULL,                                  /* exit thread */
[64]     NULL,                                  /* exit process */
[65]     NULL,                                  /* exit master */
[66]     NGX_MODULE_V1_PADDING
[67] };
[68] 
[69] 
[70] static ngx_log_t        ngx_log;
[71] static ngx_open_file_t  ngx_log_file;
[72] ngx_uint_t              ngx_use_stderr = 1;
[73] 
[74] 
[75] static ngx_str_t err_levels[] = {
[76]     ngx_null_string,
[77]     ngx_string("emerg"),
[78]     ngx_string("alert"),
[79]     ngx_string("crit"),
[80]     ngx_string("error"),
[81]     ngx_string("warn"),
[82]     ngx_string("notice"),
[83]     ngx_string("info"),
[84]     ngx_string("debug")
[85] };
[86] 
[87] static const char *debug_levels[] = {
[88]     "debug_core", "debug_alloc", "debug_mutex", "debug_event",
[89]     "debug_http", "debug_mail", "debug_stream"
[90] };
[91] 
[92] 
[93] #if (NGX_HAVE_VARIADIC_MACROS)
[94] 
[95] void
[96] ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[97]     const char *fmt, ...)
[98] 
[99] #else
[100] 
[101] void
[102] ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[103]     const char *fmt, va_list args)
[104] 
[105] #endif
[106] {
[107] #if (NGX_HAVE_VARIADIC_MACROS)
[108]     va_list      args;
[109] #endif
[110]     u_char      *p, *last, *msg;
[111]     ssize_t      n;
[112]     ngx_uint_t   wrote_stderr, debug_connection;
[113]     u_char       errstr[NGX_MAX_ERROR_STR];
[114] 
[115]     last = errstr + NGX_MAX_ERROR_STR;
[116] 
[117]     p = ngx_cpymem(errstr, ngx_cached_err_log_time.data,
[118]                    ngx_cached_err_log_time.len);
[119] 
[120]     p = ngx_slprintf(p, last, " [%V] ", &err_levels[level]);
[121] 
[122]     /* pid#tid */
[123]     p = ngx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
[124]                     ngx_log_pid, ngx_log_tid);
[125] 
[126]     if (log->connection) {
[127]         p = ngx_slprintf(p, last, "*%uA ", log->connection);
[128]     }
[129] 
[130]     msg = p;
[131] 
[132] #if (NGX_HAVE_VARIADIC_MACROS)
[133] 
[134]     va_start(args, fmt);
[135]     p = ngx_vslprintf(p, last, fmt, args);
[136]     va_end(args);
[137] 
[138] #else
[139] 
[140]     p = ngx_vslprintf(p, last, fmt, args);
[141] 
[142] #endif
[143] 
[144]     if (err) {
[145]         p = ngx_log_errno(p, last, err);
[146]     }
[147] 
[148]     if (level != NGX_LOG_DEBUG && log->handler) {
[149]         p = log->handler(log, p, last - p);
[150]     }
[151] 
[152]     if (p > last - NGX_LINEFEED_SIZE) {
[153]         p = last - NGX_LINEFEED_SIZE;
[154]     }
[155] 
[156]     ngx_linefeed(p);
[157] 
[158]     wrote_stderr = 0;
[159]     debug_connection = (log->log_level & NGX_LOG_DEBUG_CONNECTION) != 0;
[160] 
[161]     while (log) {
[162] 
[163]         if (log->log_level < level && !debug_connection) {
[164]             break;
[165]         }
[166] 
[167]         if (log->writer) {
[168]             log->writer(log, level, errstr, p - errstr);
[169]             goto next;
[170]         }
[171] 
[172]         if (ngx_time() == log->disk_full_time) {
[173] 
[174]             /*
[175]              * on FreeBSD writing to a full filesystem with enabled softupdates
[176]              * may block process for much longer time than writing to non-full
[177]              * filesystem, so we skip writing to a log for one second
[178]              */
[179] 
[180]             goto next;
[181]         }
[182] 
[183]         n = ngx_write_fd(log->file->fd, errstr, p - errstr);
[184] 
[185]         if (n == -1 && ngx_errno == NGX_ENOSPC) {
[186]             log->disk_full_time = ngx_time();
[187]         }
[188] 
[189]         if (log->file->fd == ngx_stderr) {
[190]             wrote_stderr = 1;
[191]         }
[192] 
[193]     next:
[194] 
[195]         log = log->next;
[196]     }
[197] 
[198]     if (!ngx_use_stderr
[199]         || level > NGX_LOG_WARN
[200]         || wrote_stderr)
[201]     {
[202]         return;
[203]     }
[204] 
[205]     msg -= (7 + err_levels[level].len + 3);
[206] 
[207]     (void) ngx_sprintf(msg, "nginx: [%V] ", &err_levels[level]);
[208] 
[209]     (void) ngx_write_console(ngx_stderr, msg, p - msg);
[210] }
[211] 
[212] 
[213] #if !(NGX_HAVE_VARIADIC_MACROS)
[214] 
[215] void ngx_cdecl
[216] ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[217]     const char *fmt, ...)
[218] {
[219]     va_list  args;
[220] 
[221]     if (log->log_level >= level) {
[222]         va_start(args, fmt);
[223]         ngx_log_error_core(level, log, err, fmt, args);
[224]         va_end(args);
[225]     }
[226] }
[227] 
[228] 
[229] void ngx_cdecl
[230] ngx_log_debug_core(ngx_log_t *log, ngx_err_t err, const char *fmt, ...)
[231] {
[232]     va_list  args;
[233] 
[234]     va_start(args, fmt);
[235]     ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, args);
[236]     va_end(args);
[237] }
[238] 
[239] #endif
[240] 
[241] 
[242] void ngx_cdecl
[243] ngx_log_abort(ngx_err_t err, const char *fmt, ...)
[244] {
[245]     u_char   *p;
[246]     va_list   args;
[247]     u_char    errstr[NGX_MAX_CONF_ERRSTR];
[248] 
[249]     va_start(args, fmt);
[250]     p = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
[251]     va_end(args);
[252] 
[253]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
[254]                   "%*s", p - errstr, errstr);
[255] }
[256] 
[257] 
[258] void ngx_cdecl
[259] ngx_log_stderr(ngx_err_t err, const char *fmt, ...)
[260] {
[261]     u_char   *p, *last;
[262]     va_list   args;
[263]     u_char    errstr[NGX_MAX_ERROR_STR];
[264] 
[265]     last = errstr + NGX_MAX_ERROR_STR;
[266] 
[267]     p = ngx_cpymem(errstr, "nginx: ", 7);
[268] 
[269]     va_start(args, fmt);
[270]     p = ngx_vslprintf(p, last, fmt, args);
[271]     va_end(args);
[272] 
[273]     if (err) {
[274]         p = ngx_log_errno(p, last, err);
[275]     }
[276] 
[277]     if (p > last - NGX_LINEFEED_SIZE) {
[278]         p = last - NGX_LINEFEED_SIZE;
[279]     }
[280] 
[281]     ngx_linefeed(p);
[282] 
[283]     (void) ngx_write_console(ngx_stderr, errstr, p - errstr);
[284] }
[285] 
[286] 
[287] u_char *
[288] ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err)
[289] {
[290]     if (buf > last - 50) {
[291] 
[292]         /* leave a space for an error code */
[293] 
[294]         buf = last - 50;
[295]         *buf++ = '.';
[296]         *buf++ = '.';
[297]         *buf++ = '.';
[298]     }
[299] 
[300] #if (NGX_WIN32)
[301]     buf = ngx_slprintf(buf, last, ((unsigned) err < 0x80000000)
[302]                                        ? " (%d: " : " (%Xd: ", err);
[303] #else
[304]     buf = ngx_slprintf(buf, last, " (%d: ", err);
[305] #endif
[306] 
[307]     buf = ngx_strerror(err, buf, last - buf);
[308] 
[309]     if (buf < last) {
[310]         *buf++ = ')';
[311]     }
[312] 
[313]     return buf;
[314] }
[315] 
[316] 
[317] ngx_log_t *
[318] ngx_log_init(u_char *prefix, u_char *error_log)
[319] {
[320]     u_char  *p, *name;
[321]     size_t   nlen, plen;
[322] 
[323]     ngx_log.file = &ngx_log_file;
[324]     ngx_log.log_level = NGX_LOG_NOTICE;
[325] 
[326]     if (error_log == NULL) {
[327]         error_log = (u_char *) NGX_ERROR_LOG_PATH;
[328]     }
[329] 
[330]     name = error_log;
[331]     nlen = ngx_strlen(name);
[332] 
[333]     if (nlen == 0) {
[334]         ngx_log_file.fd = ngx_stderr;
[335]         return &ngx_log;
[336]     }
[337] 
[338]     p = NULL;
[339] 
[340] #if (NGX_WIN32)
[341]     if (name[1] != ':') {
[342] #else
[343]     if (name[0] != '/') {
[344] #endif
[345] 
[346]         if (prefix) {
[347]             plen = ngx_strlen(prefix);
[348] 
[349]         } else {
[350] #ifdef NGX_PREFIX
[351]             prefix = (u_char *) NGX_PREFIX;
[352]             plen = ngx_strlen(prefix);
[353] #else
[354]             plen = 0;
[355] #endif
[356]         }
[357] 
[358]         if (plen) {
[359]             name = malloc(plen + nlen + 2);
[360]             if (name == NULL) {
[361]                 return NULL;
[362]             }
[363] 
[364]             p = ngx_cpymem(name, prefix, plen);
[365] 
[366]             if (!ngx_path_separator(*(p - 1))) {
[367]                 *p++ = '/';
[368]             }
[369] 
[370]             ngx_cpystrn(p, error_log, nlen + 1);
[371] 
[372]             p = name;
[373]         }
[374]     }
[375] 
[376]     ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
[377]                                     NGX_FILE_CREATE_OR_OPEN,
[378]                                     NGX_FILE_DEFAULT_ACCESS);
[379] 
[380]     if (ngx_log_file.fd == NGX_INVALID_FILE) {
[381]         ngx_log_stderr(ngx_errno,
[382]                        "[alert] could not open error log file: "
[383]                        ngx_open_file_n " \"%s\" failed", name);
[384] #if (NGX_WIN32)
[385]         ngx_event_log(ngx_errno,
[386]                        "could not open error log file: "
[387]                        ngx_open_file_n " \"%s\" failed", name);
[388] #endif
[389] 
[390]         ngx_log_file.fd = ngx_stderr;
[391]     }
[392] 
[393]     if (p) {
[394]         ngx_free(p);
[395]     }
[396] 
[397]     return &ngx_log;
[398] }
[399] 
[400] 
[401] ngx_int_t
[402] ngx_log_open_default(ngx_cycle_t *cycle)
[403] {
[404]     ngx_log_t  *log;
[405] 
[406]     if (ngx_log_get_file_log(&cycle->new_log) != NULL) {
[407]         return NGX_OK;
[408]     }
[409] 
[410]     if (cycle->new_log.log_level != 0) {
[411]         /* there are some error logs, but no files */
[412] 
[413]         log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
[414]         if (log == NULL) {
[415]             return NGX_ERROR;
[416]         }
[417] 
[418]     } else {
[419]         /* no error logs at all */
[420]         log = &cycle->new_log;
[421]     }
[422] 
[423]     log->log_level = NGX_LOG_ERR;
[424] 
[425]     log->file = ngx_conf_open_file(cycle, &cycle->error_log);
[426]     if (log->file == NULL) {
[427]         return NGX_ERROR;
[428]     }
[429] 
[430]     if (log != &cycle->new_log) {
[431]         ngx_log_insert(&cycle->new_log, log);
[432]     }
[433] 
[434]     return NGX_OK;
[435] }
[436] 
[437] 
[438] ngx_int_t
[439] ngx_log_redirect_stderr(ngx_cycle_t *cycle)
[440] {
[441]     ngx_fd_t  fd;
[442] 
[443]     if (cycle->log_use_stderr) {
[444]         return NGX_OK;
[445]     }
[446] 
[447]     /* file log always exists when we are called */
[448]     fd = ngx_log_get_file_log(cycle->log)->file->fd;
[449] 
[450]     if (fd != ngx_stderr) {
[451]         if (ngx_set_stderr(fd) == NGX_FILE_ERROR) {
[452]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[453]                           ngx_set_stderr_n " failed");
[454] 
[455]             return NGX_ERROR;
[456]         }
[457]     }
[458] 
[459]     return NGX_OK;
[460] }
[461] 
[462] 
[463] ngx_log_t *
[464] ngx_log_get_file_log(ngx_log_t *head)
[465] {
[466]     ngx_log_t  *log;
[467] 
[468]     for (log = head; log; log = log->next) {
[469]         if (log->file != NULL) {
[470]             return log;
[471]         }
[472]     }
[473] 
[474]     return NULL;
[475] }
[476] 
[477] 
[478] static char *
[479] ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log)
[480] {
[481]     ngx_uint_t   i, n, d, found;
[482]     ngx_str_t   *value;
[483] 
[484]     if (cf->args->nelts == 2) {
[485]         log->log_level = NGX_LOG_ERR;
[486]         return NGX_CONF_OK;
[487]     }
[488] 
[489]     value = cf->args->elts;
[490] 
[491]     for (i = 2; i < cf->args->nelts; i++) {
[492]         found = 0;
[493] 
[494]         for (n = 1; n <= NGX_LOG_DEBUG; n++) {
[495]             if (ngx_strcmp(value[i].data, err_levels[n].data) == 0) {
[496] 
[497]                 if (log->log_level != 0) {
[498]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[499]                                        "duplicate log level \"%V\"",
[500]                                        &value[i]);
[501]                     return NGX_CONF_ERROR;
[502]                 }
[503] 
[504]                 log->log_level = n;
[505]                 found = 1;
[506]                 break;
[507]             }
[508]         }
[509] 
[510]         for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
[511]             if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {
[512]                 if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
[513]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[514]                                        "invalid log level \"%V\"",
[515]                                        &value[i]);
[516]                     return NGX_CONF_ERROR;
[517]                 }
[518] 
[519]                 log->log_level |= d;
[520]                 found = 1;
[521]                 break;
[522]             }
[523]         }
[524] 
[525] 
[526]         if (!found) {
[527]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[528]                                "invalid log level \"%V\"", &value[i]);
[529]             return NGX_CONF_ERROR;
[530]         }
[531]     }
[532] 
[533]     if (log->log_level == NGX_LOG_DEBUG) {
[534]         log->log_level = NGX_LOG_DEBUG_ALL;
[535]     }
[536] 
[537]     return NGX_CONF_OK;
[538] }
[539] 
[540] 
[541] static char *
[542] ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[543] {
[544]     ngx_log_t  *dummy;
[545] 
[546]     dummy = &cf->cycle->new_log;
[547] 
[548]     return ngx_log_set_log(cf, &dummy);
[549] }
[550] 
[551] 
[552] char *
[553] ngx_log_set_log(ngx_conf_t *cf, ngx_log_t **head)
[554] {
[555]     ngx_log_t          *new_log;
[556]     ngx_str_t          *value, name;
[557]     ngx_syslog_peer_t  *peer;
[558] 
[559]     if (*head != NULL && (*head)->log_level == 0) {
[560]         new_log = *head;
[561] 
[562]     } else {
[563] 
[564]         new_log = ngx_pcalloc(cf->pool, sizeof(ngx_log_t));
[565]         if (new_log == NULL) {
[566]             return NGX_CONF_ERROR;
[567]         }
[568] 
[569]         if (*head == NULL) {
[570]             *head = new_log;
[571]         }
[572]     }
[573] 
[574]     value = cf->args->elts;
[575] 
[576]     if (ngx_strcmp(value[1].data, "stderr") == 0) {
[577]         ngx_str_null(&name);
[578]         cf->cycle->log_use_stderr = 1;
[579] 
[580]         new_log->file = ngx_conf_open_file(cf->cycle, &name);
[581]         if (new_log->file == NULL) {
[582]             return NGX_CONF_ERROR;
[583]         }
[584] 
[585]     } else if (ngx_strncmp(value[1].data, "memory:", 7) == 0) {
[586] 
[587] #if (NGX_DEBUG)
[588]         size_t                 size, needed;
[589]         ngx_pool_cleanup_t    *cln;
[590]         ngx_log_memory_buf_t  *buf;
[591] 
[592]         value[1].len -= 7;
[593]         value[1].data += 7;
[594] 
[595]         needed = sizeof("MEMLOG  :" NGX_LINEFEED)
[596]                  + cf->conf_file->file.name.len
[597]                  + NGX_SIZE_T_LEN
[598]                  + NGX_INT_T_LEN
[599]                  + NGX_MAX_ERROR_STR;
[600] 
[601]         size = ngx_parse_size(&value[1]);
[602] 
[603]         if (size == (size_t) NGX_ERROR || size < needed) {
[604]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[605]                                "invalid buffer size \"%V\"", &value[1]);
[606]             return NGX_CONF_ERROR;
[607]         }
[608] 
[609]         buf = ngx_pcalloc(cf->pool, sizeof(ngx_log_memory_buf_t));
[610]         if (buf == NULL) {
[611]             return NGX_CONF_ERROR;
[612]         }
[613] 
[614]         buf->start = ngx_pnalloc(cf->pool, size);
[615]         if (buf->start == NULL) {
[616]             return NGX_CONF_ERROR;
[617]         }
[618] 
[619]         buf->end = buf->start + size;
[620] 
[621]         buf->pos = ngx_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
[622]                                 size, &cf->conf_file->file.name,
[623]                                 cf->conf_file->line);
[624] 
[625]         ngx_memset(buf->pos, ' ', buf->end - buf->pos);
[626] 
[627]         cln = ngx_pool_cleanup_add(cf->pool, 0);
[628]         if (cln == NULL) {
[629]             return NGX_CONF_ERROR;
[630]         }
[631] 
[632]         cln->data = new_log;
[633]         cln->handler = ngx_log_memory_cleanup;
[634] 
[635]         new_log->writer = ngx_log_memory_writer;
[636]         new_log->wdata = buf;
[637] 
[638] #else
[639]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[640]                            "nginx was built without debug support");
[641]         return NGX_CONF_ERROR;
[642] #endif
[643] 
[644]     } else if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {
[645]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
[646]         if (peer == NULL) {
[647]             return NGX_CONF_ERROR;
[648]         }
[649] 
[650]         if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
[651]             return NGX_CONF_ERROR;
[652]         }
[653] 
[654]         new_log->writer = ngx_syslog_writer;
[655]         new_log->wdata = peer;
[656] 
[657]     } else {
[658]         new_log->file = ngx_conf_open_file(cf->cycle, &value[1]);
[659]         if (new_log->file == NULL) {
[660]             return NGX_CONF_ERROR;
[661]         }
[662]     }
[663] 
[664]     if (ngx_log_set_levels(cf, new_log) != NGX_CONF_OK) {
[665]         return NGX_CONF_ERROR;
[666]     }
[667] 
[668]     if (*head != new_log) {
[669]         ngx_log_insert(*head, new_log);
[670]     }
[671] 
[672]     return NGX_CONF_OK;
[673] }
[674] 
[675] 
[676] static void
[677] ngx_log_insert(ngx_log_t *log, ngx_log_t *new_log)
[678] {
[679]     ngx_log_t  tmp;
[680] 
[681]     if (new_log->log_level > log->log_level) {
[682] 
[683]         /*
[684]          * list head address is permanent, insert new log after
[685]          * head and swap its contents with head
[686]          */
[687] 
[688]         tmp = *log;
[689]         *log = *new_log;
[690]         *new_log = tmp;
[691] 
[692]         log->next = new_log;
[693]         return;
[694]     }
[695] 
[696]     while (log->next) {
[697]         if (new_log->log_level > log->next->log_level) {
[698]             new_log->next = log->next;
[699]             log->next = new_log;
[700]             return;
[701]         }
[702] 
[703]         log = log->next;
[704]     }
[705] 
[706]     log->next = new_log;
[707] }
[708] 
[709] 
[710] #if (NGX_DEBUG)
[711] 
[712] static void
[713] ngx_log_memory_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
[714]     size_t len)
[715] {
[716]     u_char                *p;
[717]     size_t                 avail, written;
[718]     ngx_log_memory_buf_t  *mem;
[719] 
[720]     mem = log->wdata;
[721] 
[722]     if (mem == NULL) {
[723]         return;
[724]     }
[725] 
[726]     written = ngx_atomic_fetch_add(&mem->written, len);
[727] 
[728]     p = mem->pos + written % (mem->end - mem->pos);
[729] 
[730]     avail = mem->end - p;
[731] 
[732]     if (avail >= len) {
[733]         ngx_memcpy(p, buf, len);
[734] 
[735]     } else {
[736]         ngx_memcpy(p, buf, avail);
[737]         ngx_memcpy(mem->pos, buf + avail, len - avail);
[738]     }
[739] }
[740] 
[741] 
[742] static void
[743] ngx_log_memory_cleanup(void *data)
[744] {
[745]     ngx_log_t *log = data;
[746] 
[747]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");
[748] 
[749]     log->wdata = NULL;
[750] }
[751] 
[752] #endif
