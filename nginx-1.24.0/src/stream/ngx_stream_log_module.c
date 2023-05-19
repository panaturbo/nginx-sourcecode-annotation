[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] #if (NGX_ZLIB)
[13] #include <zlib.h>
[14] #endif
[15] 
[16] 
[17] typedef struct ngx_stream_log_op_s  ngx_stream_log_op_t;
[18] 
[19] typedef u_char *(*ngx_stream_log_op_run_pt) (ngx_stream_session_t *s,
[20]     u_char *buf, ngx_stream_log_op_t *op);
[21] 
[22] typedef size_t (*ngx_stream_log_op_getlen_pt) (ngx_stream_session_t *s,
[23]     uintptr_t data);
[24] 
[25] 
[26] struct ngx_stream_log_op_s {
[27]     size_t                       len;
[28]     ngx_stream_log_op_getlen_pt  getlen;
[29]     ngx_stream_log_op_run_pt     run;
[30]     uintptr_t                    data;
[31] };
[32] 
[33] 
[34] typedef struct {
[35]     ngx_str_t                    name;
[36]     ngx_array_t                 *flushes;
[37]     ngx_array_t                 *ops;        /* array of ngx_stream_log_op_t */
[38] } ngx_stream_log_fmt_t;
[39] 
[40] 
[41] typedef struct {
[42]     ngx_array_t                  formats;    /* array of ngx_stream_log_fmt_t */
[43] } ngx_stream_log_main_conf_t;
[44] 
[45] 
[46] typedef struct {
[47]     u_char                      *start;
[48]     u_char                      *pos;
[49]     u_char                      *last;
[50] 
[51]     ngx_event_t                 *event;
[52]     ngx_msec_t                   flush;
[53]     ngx_int_t                    gzip;
[54] } ngx_stream_log_buf_t;
[55] 
[56] 
[57] typedef struct {
[58]     ngx_array_t                 *lengths;
[59]     ngx_array_t                 *values;
[60] } ngx_stream_log_script_t;
[61] 
[62] 
[63] typedef struct {
[64]     ngx_open_file_t             *file;
[65]     ngx_stream_log_script_t     *script;
[66]     time_t                       disk_full_time;
[67]     time_t                       error_log_time;
[68]     ngx_syslog_peer_t           *syslog_peer;
[69]     ngx_stream_log_fmt_t        *format;
[70]     ngx_stream_complex_value_t  *filter;
[71] } ngx_stream_log_t;
[72] 
[73] 
[74] typedef struct {
[75]     ngx_array_t                 *logs;       /* array of ngx_stream_log_t */
[76] 
[77]     ngx_open_file_cache_t       *open_file_cache;
[78]     time_t                       open_file_cache_valid;
[79]     ngx_uint_t                   open_file_cache_min_uses;
[80] 
[81]     ngx_uint_t                   off;        /* unsigned  off:1 */
[82] } ngx_stream_log_srv_conf_t;
[83] 
[84] 
[85] typedef struct {
[86]     ngx_str_t                    name;
[87]     size_t                       len;
[88]     ngx_stream_log_op_run_pt     run;
[89] } ngx_stream_log_var_t;
[90] 
[91] 
[92] #define NGX_STREAM_LOG_ESCAPE_DEFAULT  0
[93] #define NGX_STREAM_LOG_ESCAPE_JSON     1
[94] #define NGX_STREAM_LOG_ESCAPE_NONE     2
[95] 
[96] 
[97] static void ngx_stream_log_write(ngx_stream_session_t *s, ngx_stream_log_t *log,
[98]     u_char *buf, size_t len);
[99] static ssize_t ngx_stream_log_script_write(ngx_stream_session_t *s,
[100]     ngx_stream_log_script_t *script, u_char **name, u_char *buf, size_t len);
[101] 
[102] #if (NGX_ZLIB)
[103] static ssize_t ngx_stream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len,
[104]     ngx_int_t level, ngx_log_t *log);
[105] 
[106] static void *ngx_stream_log_gzip_alloc(void *opaque, u_int items, u_int size);
[107] static void ngx_stream_log_gzip_free(void *opaque, void *address);
[108] #endif
[109] 
[110] static void ngx_stream_log_flush(ngx_open_file_t *file, ngx_log_t *log);
[111] static void ngx_stream_log_flush_handler(ngx_event_t *ev);
[112] 
[113] static ngx_int_t ngx_stream_log_variable_compile(ngx_conf_t *cf,
[114]     ngx_stream_log_op_t *op, ngx_str_t *value, ngx_uint_t escape);
[115] static size_t ngx_stream_log_variable_getlen(ngx_stream_session_t *s,
[116]     uintptr_t data);
[117] static u_char *ngx_stream_log_variable(ngx_stream_session_t *s, u_char *buf,
[118]     ngx_stream_log_op_t *op);
[119] static uintptr_t ngx_stream_log_escape(u_char *dst, u_char *src, size_t size);
[120] static size_t ngx_stream_log_json_variable_getlen(ngx_stream_session_t *s,
[121]     uintptr_t data);
[122] static u_char *ngx_stream_log_json_variable(ngx_stream_session_t *s,
[123]     u_char *buf, ngx_stream_log_op_t *op);
[124] static size_t ngx_stream_log_unescaped_variable_getlen(ngx_stream_session_t *s,
[125]     uintptr_t data);
[126] static u_char *ngx_stream_log_unescaped_variable(ngx_stream_session_t *s,
[127]     u_char *buf, ngx_stream_log_op_t *op);
[128] 
[129] 
[130] static void *ngx_stream_log_create_main_conf(ngx_conf_t *cf);
[131] static void *ngx_stream_log_create_srv_conf(ngx_conf_t *cf);
[132] static char *ngx_stream_log_merge_srv_conf(ngx_conf_t *cf, void *parent,
[133]     void *child);
[134] static char *ngx_stream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
[135]     void *conf);
[136] static char *ngx_stream_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
[137]     void *conf);
[138] static char *ngx_stream_log_compile_format(ngx_conf_t *cf,
[139]     ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
[140] static char *ngx_stream_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[141]     void *conf);
[142] static ngx_int_t ngx_stream_log_init(ngx_conf_t *cf);
[143] 
[144] 
[145] static ngx_command_t  ngx_stream_log_commands[] = {
[146] 
[147]     { ngx_string("log_format"),
[148]       NGX_STREAM_MAIN_CONF|NGX_CONF_2MORE,
[149]       ngx_stream_log_set_format,
[150]       NGX_STREAM_MAIN_CONF_OFFSET,
[151]       0,
[152]       NULL },
[153] 
[154]     { ngx_string("access_log"),
[155]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
[156]       ngx_stream_log_set_log,
[157]       NGX_STREAM_SRV_CONF_OFFSET,
[158]       0,
[159]       NULL },
[160] 
[161]     { ngx_string("open_log_file_cache"),
[162]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1234,
[163]       ngx_stream_log_open_file_cache,
[164]       NGX_STREAM_SRV_CONF_OFFSET,
[165]       0,
[166]       NULL },
[167] 
[168]       ngx_null_command
[169] };
[170] 
[171] 
[172] static ngx_stream_module_t  ngx_stream_log_module_ctx = {
[173]     NULL,                                  /* preconfiguration */
[174]     ngx_stream_log_init,                   /* postconfiguration */
[175] 
[176]     ngx_stream_log_create_main_conf,       /* create main configuration */
[177]     NULL,                                  /* init main configuration */
[178] 
[179]     ngx_stream_log_create_srv_conf,        /* create server configuration */
[180]     ngx_stream_log_merge_srv_conf          /* merge server configuration */
[181] };
[182] 
[183] 
[184] ngx_module_t  ngx_stream_log_module = {
[185]     NGX_MODULE_V1,
[186]     &ngx_stream_log_module_ctx,            /* module context */
[187]     ngx_stream_log_commands,               /* module directives */
[188]     NGX_STREAM_MODULE,                     /* module type */
[189]     NULL,                                  /* init master */
[190]     NULL,                                  /* init module */
[191]     NULL,                                  /* init process */
[192]     NULL,                                  /* init thread */
[193]     NULL,                                  /* exit thread */
[194]     NULL,                                  /* exit process */
[195]     NULL,                                  /* exit master */
[196]     NGX_MODULE_V1_PADDING
[197] };
[198] 
[199] 
[200] static ngx_int_t
[201] ngx_stream_log_handler(ngx_stream_session_t *s)
[202] {
[203]     u_char                     *line, *p;
[204]     size_t                      len, size;
[205]     ssize_t                     n;
[206]     ngx_str_t                   val;
[207]     ngx_uint_t                  i, l;
[208]     ngx_stream_log_t           *log;
[209]     ngx_stream_log_op_t        *op;
[210]     ngx_stream_log_buf_t       *buffer;
[211]     ngx_stream_log_srv_conf_t  *lscf;
[212] 
[213]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[214]                    "stream log handler");
[215] 
[216]     lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_log_module);
[217] 
[218]     if (lscf->off || lscf->logs == NULL) {
[219]         return NGX_OK;
[220]     }
[221] 
[222]     log = lscf->logs->elts;
[223]     for (l = 0; l < lscf->logs->nelts; l++) {
[224] 
[225]         if (log[l].filter) {
[226]             if (ngx_stream_complex_value(s, log[l].filter, &val) != NGX_OK) {
[227]                 return NGX_ERROR;
[228]             }
[229] 
[230]             if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
[231]                 continue;
[232]             }
[233]         }
[234] 
[235]         if (ngx_time() == log[l].disk_full_time) {
[236] 
[237]             /*
[238]              * on FreeBSD writing to a full filesystem with enabled softupdates
[239]              * may block process for much longer time than writing to non-full
[240]              * filesystem, so we skip writing to a log for one second
[241]              */
[242] 
[243]             continue;
[244]         }
[245] 
[246]         ngx_stream_script_flush_no_cacheable_variables(s,
[247]                                                        log[l].format->flushes);
[248] 
[249]         len = 0;
[250]         op = log[l].format->ops->elts;
[251]         for (i = 0; i < log[l].format->ops->nelts; i++) {
[252]             if (op[i].len == 0) {
[253]                 len += op[i].getlen(s, op[i].data);
[254] 
[255]             } else {
[256]                 len += op[i].len;
[257]             }
[258]         }
[259] 
[260]         if (log[l].syslog_peer) {
[261] 
[262]             /* length of syslog's PRI and HEADER message parts */
[263]             len += sizeof("<255>Jan 01 00:00:00 ") - 1
[264]                    + ngx_cycle->hostname.len + 1
[265]                    + log[l].syslog_peer->tag.len + 2;
[266] 
[267]             goto alloc_line;
[268]         }
[269] 
[270]         len += NGX_LINEFEED_SIZE;
[271] 
[272]         buffer = log[l].file ? log[l].file->data : NULL;
[273] 
[274]         if (buffer) {
[275] 
[276]             if (len > (size_t) (buffer->last - buffer->pos)) {
[277] 
[278]                 ngx_stream_log_write(s, &log[l], buffer->start,
[279]                                      buffer->pos - buffer->start);
[280] 
[281]                 buffer->pos = buffer->start;
[282]             }
[283] 
[284]             if (len <= (size_t) (buffer->last - buffer->pos)) {
[285] 
[286]                 p = buffer->pos;
[287] 
[288]                 if (buffer->event && p == buffer->start) {
[289]                     ngx_add_timer(buffer->event, buffer->flush);
[290]                 }
[291] 
[292]                 for (i = 0; i < log[l].format->ops->nelts; i++) {
[293]                     p = op[i].run(s, p, &op[i]);
[294]                 }
[295] 
[296]                 ngx_linefeed(p);
[297] 
[298]                 buffer->pos = p;
[299] 
[300]                 continue;
[301]             }
[302] 
[303]             if (buffer->event && buffer->event->timer_set) {
[304]                 ngx_del_timer(buffer->event);
[305]             }
[306]         }
[307] 
[308]     alloc_line:
[309] 
[310]         line = ngx_pnalloc(s->connection->pool, len);
[311]         if (line == NULL) {
[312]             return NGX_ERROR;
[313]         }
[314] 
[315]         p = line;
[316] 
[317]         if (log[l].syslog_peer) {
[318]             p = ngx_syslog_add_header(log[l].syslog_peer, line);
[319]         }
[320] 
[321]         for (i = 0; i < log[l].format->ops->nelts; i++) {
[322]             p = op[i].run(s, p, &op[i]);
[323]         }
[324] 
[325]         if (log[l].syslog_peer) {
[326] 
[327]             size = p - line;
[328] 
[329]             n = ngx_syslog_send(log[l].syslog_peer, line, size);
[330] 
[331]             if (n < 0) {
[332]                 ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
[333]                               "send() to syslog failed");
[334] 
[335]             } else if ((size_t) n != size) {
[336]                 ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
[337]                               "send() to syslog has written only %z of %uz",
[338]                               n, size);
[339]             }
[340] 
[341]             continue;
[342]         }
[343] 
[344]         ngx_linefeed(p);
[345] 
[346]         ngx_stream_log_write(s, &log[l], line, p - line);
[347]     }
[348] 
[349]     return NGX_OK;
[350] }
[351] 
[352] 
[353] static void
[354] ngx_stream_log_write(ngx_stream_session_t *s, ngx_stream_log_t *log,
[355]     u_char *buf, size_t len)
[356] {
[357]     u_char                *name;
[358]     time_t                 now;
[359]     ssize_t                n;
[360]     ngx_err_t              err;
[361] #if (NGX_ZLIB)
[362]     ngx_stream_log_buf_t  *buffer;
[363] #endif
[364] 
[365]     if (log->script == NULL) {
[366]         name = log->file->name.data;
[367] 
[368] #if (NGX_ZLIB)
[369]         buffer = log->file->data;
[370] 
[371]         if (buffer && buffer->gzip) {
[372]             n = ngx_stream_log_gzip(log->file->fd, buf, len, buffer->gzip,
[373]                                     s->connection->log);
[374]         } else {
[375]             n = ngx_write_fd(log->file->fd, buf, len);
[376]         }
[377] #else
[378]         n = ngx_write_fd(log->file->fd, buf, len);
[379] #endif
[380] 
[381]     } else {
[382]         name = NULL;
[383]         n = ngx_stream_log_script_write(s, log->script, &name, buf, len);
[384]     }
[385] 
[386]     if (n == (ssize_t) len) {
[387]         return;
[388]     }
[389] 
[390]     now = ngx_time();
[391] 
[392]     if (n == -1) {
[393]         err = ngx_errno;
[394] 
[395]         if (err == NGX_ENOSPC) {
[396]             log->disk_full_time = now;
[397]         }
[398] 
[399]         if (now - log->error_log_time > 59) {
[400]             ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
[401]                           ngx_write_fd_n " to \"%s\" failed", name);
[402] 
[403]             log->error_log_time = now;
[404]         }
[405] 
[406]         return;
[407]     }
[408] 
[409]     if (now - log->error_log_time > 59) {
[410]         ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
[411]                       ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
[412]                       name, n, len);
[413] 
[414]         log->error_log_time = now;
[415]     }
[416] }
[417] 
[418] 
[419] static ssize_t
[420] ngx_stream_log_script_write(ngx_stream_session_t *s,
[421]     ngx_stream_log_script_t *script, u_char **name, u_char *buf, size_t len)
[422] {
[423]     ssize_t                     n;
[424]     ngx_str_t                   log;
[425]     ngx_open_file_info_t        of;
[426]     ngx_stream_log_srv_conf_t  *lscf;
[427] 
[428]     if (ngx_stream_script_run(s, &log, script->lengths->elts, 1,
[429]                               script->values->elts)
[430]         == NULL)
[431]     {
[432]         /* simulate successful logging */
[433]         return len;
[434]     }
[435] 
[436]     log.data[log.len - 1] = '\0';
[437]     *name = log.data;
[438] 
[439]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[440]                    "stream log \"%s\"", log.data);
[441] 
[442]     lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_log_module);
[443] 
[444]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[445] 
[446]     of.log = 1;
[447]     of.valid = lscf->open_file_cache_valid;
[448]     of.min_uses = lscf->open_file_cache_min_uses;
[449]     of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;
[450] 
[451]     if (ngx_open_cached_file(lscf->open_file_cache, &log, &of,
[452]                              s->connection->pool)
[453]         != NGX_OK)
[454]     {
[455]         if (of.err == 0) {
[456]             /* simulate successful logging */
[457]             return len;
[458]         }
[459] 
[460]         ngx_log_error(NGX_LOG_CRIT, s->connection->log, ngx_errno,
[461]                       "%s \"%s\" failed", of.failed, log.data);
[462]         /* simulate successful logging */
[463]         return len;
[464]     }
[465] 
[466]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[467]                    "stream log #%d", of.fd);
[468] 
[469]     n = ngx_write_fd(of.fd, buf, len);
[470] 
[471]     return n;
[472] }
[473] 
[474] 
[475] #if (NGX_ZLIB)
[476] 
[477] static ssize_t
[478] ngx_stream_log_gzip(ngx_fd_t fd, u_char *buf, size_t len, ngx_int_t level,
[479]     ngx_log_t *log)
[480] {
[481]     int          rc, wbits, memlevel;
[482]     u_char      *out;
[483]     size_t       size;
[484]     ssize_t      n;
[485]     z_stream     zstream;
[486]     ngx_err_t    err;
[487]     ngx_pool_t  *pool;
[488] 
[489]     wbits = MAX_WBITS;
[490]     memlevel = MAX_MEM_LEVEL - 1;
[491] 
[492]     while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
[493]         wbits--;
[494]         memlevel--;
[495]     }
[496] 
[497]     /*
[498]      * This is a formula from deflateBound() for conservative upper bound of
[499]      * compressed data plus 18 bytes of gzip wrapper.
[500]      */
[501] 
[502]     size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;
[503] 
[504]     ngx_memzero(&zstream, sizeof(z_stream));
[505] 
[506]     pool = ngx_create_pool(256, log);
[507]     if (pool == NULL) {
[508]         /* simulate successful logging */
[509]         return len;
[510]     }
[511] 
[512]     pool->log = log;
[513] 
[514]     zstream.zalloc = ngx_stream_log_gzip_alloc;
[515]     zstream.zfree = ngx_stream_log_gzip_free;
[516]     zstream.opaque = pool;
[517] 
[518]     out = ngx_pnalloc(pool, size);
[519]     if (out == NULL) {
[520]         goto done;
[521]     }
[522] 
[523]     zstream.next_in = buf;
[524]     zstream.avail_in = len;
[525]     zstream.next_out = out;
[526]     zstream.avail_out = size;
[527] 
[528]     rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
[529]                       Z_DEFAULT_STRATEGY);
[530] 
[531]     if (rc != Z_OK) {
[532]         ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
[533]         goto done;
[534]     }
[535] 
[536]     ngx_log_debug4(NGX_LOG_DEBUG_STREAM, log, 0,
[537]                    "deflate in: ni:%p no:%p ai:%ud ao:%ud",
[538]                    zstream.next_in, zstream.next_out,
[539]                    zstream.avail_in, zstream.avail_out);
[540] 
[541]     rc = deflate(&zstream, Z_FINISH);
[542] 
[543]     if (rc != Z_STREAM_END) {
[544]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[545]                       "deflate(Z_FINISH) failed: %d", rc);
[546]         goto done;
[547]     }
[548] 
[549]     ngx_log_debug5(NGX_LOG_DEBUG_STREAM, log, 0,
[550]                    "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
[551]                    zstream.next_in, zstream.next_out,
[552]                    zstream.avail_in, zstream.avail_out,
[553]                    rc);
[554] 
[555]     size -= zstream.avail_out;
[556] 
[557]     rc = deflateEnd(&zstream);
[558] 
[559]     if (rc != Z_OK) {
[560]         ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
[561]         goto done;
[562]     }
[563] 
[564]     n = ngx_write_fd(fd, out, size);
[565] 
[566]     if (n != (ssize_t) size) {
[567]         err = (n == -1) ? ngx_errno : 0;
[568] 
[569]         ngx_destroy_pool(pool);
[570] 
[571]         ngx_set_errno(err);
[572]         return -1;
[573]     }
[574] 
[575] done:
[576] 
[577]     ngx_destroy_pool(pool);
[578] 
[579]     /* simulate successful logging */
[580]     return len;
[581] }
[582] 
[583] 
[584] static void *
[585] ngx_stream_log_gzip_alloc(void *opaque, u_int items, u_int size)
[586] {
[587]     ngx_pool_t *pool = opaque;
[588] 
[589]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, pool->log, 0,
[590]                    "gzip alloc: n:%ud s:%ud", items, size);
[591] 
[592]     return ngx_palloc(pool, items * size);
[593] }
[594] 
[595] 
[596] static void
[597] ngx_stream_log_gzip_free(void *opaque, void *address)
[598] {
[599] #if 0
[600]     ngx_pool_t *pool = opaque;
[601] 
[602]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, pool->log, 0,
[603]                    "gzip free: %p", address);
[604] #endif
[605] }
[606] 
[607] #endif
[608] 
[609] 
[610] static void
[611] ngx_stream_log_flush(ngx_open_file_t *file, ngx_log_t *log)
[612] {
[613]     size_t                 len;
[614]     ssize_t                n;
[615]     ngx_stream_log_buf_t  *buffer;
[616] 
[617]     buffer = file->data;
[618] 
[619]     len = buffer->pos - buffer->start;
[620] 
[621]     if (len == 0) {
[622]         return;
[623]     }
[624] 
[625] #if (NGX_ZLIB)
[626]     if (buffer->gzip) {
[627]         n = ngx_stream_log_gzip(file->fd, buffer->start, len, buffer->gzip,
[628]                                 log);
[629]     } else {
[630]         n = ngx_write_fd(file->fd, buffer->start, len);
[631]     }
[632] #else
[633]     n = ngx_write_fd(file->fd, buffer->start, len);
[634] #endif
[635] 
[636]     if (n == -1) {
[637]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[638]                       ngx_write_fd_n " to \"%s\" failed",
[639]                       file->name.data);
[640] 
[641]     } else if ((size_t) n != len) {
[642]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[643]                       ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
[644]                       file->name.data, n, len);
[645]     }
[646] 
[647]     buffer->pos = buffer->start;
[648] 
[649]     if (buffer->event && buffer->event->timer_set) {
[650]         ngx_del_timer(buffer->event);
[651]     }
[652] }
[653] 
[654] 
[655] static void
[656] ngx_stream_log_flush_handler(ngx_event_t *ev)
[657] {
[658]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[659]                    "stream log buffer flush handler");
[660] 
[661]     ngx_stream_log_flush(ev->data, ev->log);
[662] }
[663] 
[664] 
[665] static u_char *
[666] ngx_stream_log_copy_short(ngx_stream_session_t *s, u_char *buf,
[667]     ngx_stream_log_op_t *op)
[668] {
[669]     size_t     len;
[670]     uintptr_t  data;
[671] 
[672]     len = op->len;
[673]     data = op->data;
[674] 
[675]     while (len--) {
[676]         *buf++ = (u_char) (data & 0xff);
[677]         data >>= 8;
[678]     }
[679] 
[680]     return buf;
[681] }
[682] 
[683] 
[684] static u_char *
[685] ngx_stream_log_copy_long(ngx_stream_session_t *s, u_char *buf,
[686]     ngx_stream_log_op_t *op)
[687] {
[688]     return ngx_cpymem(buf, (u_char *) op->data, op->len);
[689] }
[690] 
[691] 
[692] static ngx_int_t
[693] ngx_stream_log_variable_compile(ngx_conf_t *cf, ngx_stream_log_op_t *op,
[694]     ngx_str_t *value, ngx_uint_t escape)
[695] {
[696]     ngx_int_t  index;
[697] 
[698]     index = ngx_stream_get_variable_index(cf, value);
[699]     if (index == NGX_ERROR) {
[700]         return NGX_ERROR;
[701]     }
[702] 
[703]     op->len = 0;
[704] 
[705]     switch (escape) {
[706]     case NGX_STREAM_LOG_ESCAPE_JSON:
[707]         op->getlen = ngx_stream_log_json_variable_getlen;
[708]         op->run = ngx_stream_log_json_variable;
[709]         break;
[710] 
[711]     case NGX_STREAM_LOG_ESCAPE_NONE:
[712]         op->getlen = ngx_stream_log_unescaped_variable_getlen;
[713]         op->run = ngx_stream_log_unescaped_variable;
[714]         break;
[715] 
[716]     default: /* NGX_STREAM_LOG_ESCAPE_DEFAULT */
[717]         op->getlen = ngx_stream_log_variable_getlen;
[718]         op->run = ngx_stream_log_variable;
[719]     }
[720] 
[721]     op->data = index;
[722] 
[723]     return NGX_OK;
[724] }
[725] 
[726] 
[727] static size_t
[728] ngx_stream_log_variable_getlen(ngx_stream_session_t *s, uintptr_t data)
[729] {
[730]     uintptr_t                     len;
[731]     ngx_stream_variable_value_t  *value;
[732] 
[733]     value = ngx_stream_get_indexed_variable(s, data);
[734] 
[735]     if (value == NULL || value->not_found) {
[736]         return 1;
[737]     }
[738] 
[739]     len = ngx_stream_log_escape(NULL, value->data, value->len);
[740] 
[741]     value->escape = len ? 1 : 0;
[742] 
[743]     return value->len + len * 3;
[744] }
[745] 
[746] 
[747] static u_char *
[748] ngx_stream_log_variable(ngx_stream_session_t *s, u_char *buf,
[749]     ngx_stream_log_op_t *op)
[750] {
[751]     ngx_stream_variable_value_t  *value;
[752] 
[753]     value = ngx_stream_get_indexed_variable(s, op->data);
[754] 
[755]     if (value == NULL || value->not_found) {
[756]         *buf = '-';
[757]         return buf + 1;
[758]     }
[759] 
[760]     if (value->escape == 0) {
[761]         return ngx_cpymem(buf, value->data, value->len);
[762] 
[763]     } else {
[764]         return (u_char *) ngx_stream_log_escape(buf, value->data, value->len);
[765]     }
[766] }
[767] 
[768] 
[769] static uintptr_t
[770] ngx_stream_log_escape(u_char *dst, u_char *src, size_t size)
[771] {
[772]     ngx_uint_t      n;
[773]     static u_char   hex[] = "0123456789ABCDEF";
[774] 
[775]     static uint32_t   escape[] = {
[776]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[777] 
[778]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[779]         0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */
[780] 
[781]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[782]         0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */
[783] 
[784]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[785]         0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */
[786] 
[787]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[788]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[789]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[790]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[791]     };
[792] 
[793] 
[794]     if (dst == NULL) {
[795] 
[796]         /* find the number of the characters to be escaped */
[797] 
[798]         n = 0;
[799] 
[800]         while (size) {
[801]             if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
[802]                 n++;
[803]             }
[804]             src++;
[805]             size--;
[806]         }
[807] 
[808]         return (uintptr_t) n;
[809]     }
[810] 
[811]     while (size) {
[812]         if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
[813]             *dst++ = '\\';
[814]             *dst++ = 'x';
[815]             *dst++ = hex[*src >> 4];
[816]             *dst++ = hex[*src & 0xf];
[817]             src++;
[818] 
[819]         } else {
[820]             *dst++ = *src++;
[821]         }
[822]         size--;
[823]     }
[824] 
[825]     return (uintptr_t) dst;
[826] }
[827] 
[828] 
[829] static size_t
[830] ngx_stream_log_json_variable_getlen(ngx_stream_session_t *s, uintptr_t data)
[831] {
[832]     uintptr_t                     len;
[833]     ngx_stream_variable_value_t  *value;
[834] 
[835]     value = ngx_stream_get_indexed_variable(s, data);
[836] 
[837]     if (value == NULL || value->not_found) {
[838]         return 0;
[839]     }
[840] 
[841]     len = ngx_escape_json(NULL, value->data, value->len);
[842] 
[843]     value->escape = len ? 1 : 0;
[844] 
[845]     return value->len + len;
[846] }
[847] 
[848] 
[849] static u_char *
[850] ngx_stream_log_json_variable(ngx_stream_session_t *s, u_char *buf,
[851]     ngx_stream_log_op_t *op)
[852] {
[853]     ngx_stream_variable_value_t  *value;
[854] 
[855]     value = ngx_stream_get_indexed_variable(s, op->data);
[856] 
[857]     if (value == NULL || value->not_found) {
[858]         return buf;
[859]     }
[860] 
[861]     if (value->escape == 0) {
[862]         return ngx_cpymem(buf, value->data, value->len);
[863] 
[864]     } else {
[865]         return (u_char *) ngx_escape_json(buf, value->data, value->len);
[866]     }
[867] }
[868] 
[869] 
[870] static size_t
[871] ngx_stream_log_unescaped_variable_getlen(ngx_stream_session_t *s,
[872]     uintptr_t data)
[873] {
[874]     ngx_stream_variable_value_t  *value;
[875] 
[876]     value = ngx_stream_get_indexed_variable(s, data);
[877] 
[878]     if (value == NULL || value->not_found) {
[879]         return 0;
[880]     }
[881] 
[882]     value->escape = 0;
[883] 
[884]     return value->len;
[885] }
[886] 
[887] 
[888] static u_char *
[889] ngx_stream_log_unescaped_variable(ngx_stream_session_t *s, u_char *buf,
[890]                                   ngx_stream_log_op_t *op)
[891] {
[892]     ngx_stream_variable_value_t  *value;
[893] 
[894]     value = ngx_stream_get_indexed_variable(s, op->data);
[895] 
[896]     if (value == NULL || value->not_found) {
[897]         return buf;
[898]     }
[899] 
[900]     return ngx_cpymem(buf, value->data, value->len);
[901] }
[902] 
[903] 
[904] static void *
[905] ngx_stream_log_create_main_conf(ngx_conf_t *cf)
[906] {
[907]     ngx_stream_log_main_conf_t  *conf;
[908] 
[909]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_main_conf_t));
[910]     if (conf == NULL) {
[911]         return NULL;
[912]     }
[913] 
[914]     if (ngx_array_init(&conf->formats, cf->pool, 4,
[915]                        sizeof(ngx_stream_log_fmt_t))
[916]         != NGX_OK)
[917]     {
[918]         return NULL;
[919]     }
[920] 
[921]     return conf;
[922] }
[923] 
[924] 
[925] static void *
[926] ngx_stream_log_create_srv_conf(ngx_conf_t *cf)
[927] {
[928]     ngx_stream_log_srv_conf_t  *conf;
[929] 
[930]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_srv_conf_t));
[931]     if (conf == NULL) {
[932]         return NULL;
[933]     }
[934] 
[935]     conf->open_file_cache = NGX_CONF_UNSET_PTR;
[936] 
[937]     return conf;
[938] }
[939] 
[940] 
[941] static char *
[942] ngx_stream_log_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[943] {
[944]     ngx_stream_log_srv_conf_t *prev = parent;
[945]     ngx_stream_log_srv_conf_t *conf = child;
[946] 
[947]     if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {
[948] 
[949]         conf->open_file_cache = prev->open_file_cache;
[950]         conf->open_file_cache_valid = prev->open_file_cache_valid;
[951]         conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;
[952] 
[953]         if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {
[954]             conf->open_file_cache = NULL;
[955]         }
[956]     }
[957] 
[958]     if (conf->logs || conf->off) {
[959]         return NGX_CONF_OK;
[960]     }
[961] 
[962]     conf->logs = prev->logs;
[963]     conf->off = prev->off;
[964] 
[965]     return NGX_CONF_OK;
[966] }
[967] 
[968] 
[969] static char *
[970] ngx_stream_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[971] {
[972]     ngx_stream_log_srv_conf_t *lscf = conf;
[973] 
[974]     ssize_t                              size;
[975]     ngx_int_t                            gzip;
[976]     ngx_uint_t                           i, n;
[977]     ngx_msec_t                           flush;
[978]     ngx_str_t                           *value, name, s;
[979]     ngx_stream_log_t                    *log;
[980]     ngx_syslog_peer_t                   *peer;
[981]     ngx_stream_log_buf_t                *buffer;
[982]     ngx_stream_log_fmt_t                *fmt;
[983]     ngx_stream_script_compile_t          sc;
[984]     ngx_stream_log_main_conf_t          *lmcf;
[985]     ngx_stream_compile_complex_value_t   ccv;
[986] 
[987]     value = cf->args->elts;
[988] 
[989]     if (ngx_strcmp(value[1].data, "off") == 0) {
[990]         lscf->off = 1;
[991]         if (cf->args->nelts == 2) {
[992]             return NGX_CONF_OK;
[993]         }
[994] 
[995]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[996]                            "invalid parameter \"%V\"", &value[2]);
[997]         return NGX_CONF_ERROR;
[998]     }
[999] 
[1000]     if (lscf->logs == NULL) {
[1001]         lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_stream_log_t));
[1002]         if (lscf->logs == NULL) {
[1003]             return NGX_CONF_ERROR;
[1004]         }
[1005]     }
[1006] 
[1007]     lmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_log_module);
[1008] 
[1009]     log = ngx_array_push(lscf->logs);
[1010]     if (log == NULL) {
[1011]         return NGX_CONF_ERROR;
[1012]     }
[1013] 
[1014]     ngx_memzero(log, sizeof(ngx_stream_log_t));
[1015] 
[1016] 
[1017]     if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {
[1018] 
[1019]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
[1020]         if (peer == NULL) {
[1021]             return NGX_CONF_ERROR;
[1022]         }
[1023] 
[1024]         if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
[1025]             return NGX_CONF_ERROR;
[1026]         }
[1027] 
[1028]         log->syslog_peer = peer;
[1029] 
[1030]         goto process_formats;
[1031]     }
[1032] 
[1033]     n = ngx_stream_script_variables_count(&value[1]);
[1034] 
[1035]     if (n == 0) {
[1036]         log->file = ngx_conf_open_file(cf->cycle, &value[1]);
[1037]         if (log->file == NULL) {
[1038]             return NGX_CONF_ERROR;
[1039]         }
[1040] 
[1041]     } else {
[1042]         if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
[1043]             return NGX_CONF_ERROR;
[1044]         }
[1045] 
[1046]         log->script = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_script_t));
[1047]         if (log->script == NULL) {
[1048]             return NGX_CONF_ERROR;
[1049]         }
[1050] 
[1051]         ngx_memzero(&sc, sizeof(ngx_stream_script_compile_t));
[1052] 
[1053]         sc.cf = cf;
[1054]         sc.source = &value[1];
[1055]         sc.lengths = &log->script->lengths;
[1056]         sc.values = &log->script->values;
[1057]         sc.variables = n;
[1058]         sc.complete_lengths = 1;
[1059]         sc.complete_values = 1;
[1060] 
[1061]         if (ngx_stream_script_compile(&sc) != NGX_OK) {
[1062]             return NGX_CONF_ERROR;
[1063]         }
[1064]     }
[1065] 
[1066] process_formats:
[1067] 
[1068]     if (cf->args->nelts >= 3) {
[1069]         name = value[2];
[1070] 
[1071]     } else {
[1072]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1073]                            "log format is not specified");
[1074]         return NGX_CONF_ERROR;
[1075]     }
[1076] 
[1077]     fmt = lmcf->formats.elts;
[1078]     for (i = 0; i < lmcf->formats.nelts; i++) {
[1079]         if (fmt[i].name.len == name.len
[1080]             && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
[1081]         {
[1082]             log->format = &fmt[i];
[1083]             break;
[1084]         }
[1085]     }
[1086] 
[1087]     if (log->format == NULL) {
[1088]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1089]                            "unknown log format \"%V\"", &name);
[1090]         return NGX_CONF_ERROR;
[1091]     }
[1092] 
[1093]     size = 0;
[1094]     flush = 0;
[1095]     gzip = 0;
[1096] 
[1097]     for (i = 3; i < cf->args->nelts; i++) {
[1098] 
[1099]         if (ngx_strncmp(value[i].data, "buffer=", 7) == 0) {
[1100]             s.len = value[i].len - 7;
[1101]             s.data = value[i].data + 7;
[1102] 
[1103]             size = ngx_parse_size(&s);
[1104] 
[1105]             if (size == NGX_ERROR || size == 0) {
[1106]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1107]                                    "invalid buffer size \"%V\"", &s);
[1108]                 return NGX_CONF_ERROR;
[1109]             }
[1110] 
[1111]             continue;
[1112]         }
[1113] 
[1114]         if (ngx_strncmp(value[i].data, "flush=", 6) == 0) {
[1115]             s.len = value[i].len - 6;
[1116]             s.data = value[i].data + 6;
[1117] 
[1118]             flush = ngx_parse_time(&s, 0);
[1119] 
[1120]             if (flush == (ngx_msec_t) NGX_ERROR || flush == 0) {
[1121]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1122]                                    "invalid flush time \"%V\"", &s);
[1123]                 return NGX_CONF_ERROR;
[1124]             }
[1125] 
[1126]             continue;
[1127]         }
[1128] 
[1129]         if (ngx_strncmp(value[i].data, "gzip", 4) == 0
[1130]             && (value[i].len == 4 || value[i].data[4] == '='))
[1131]         {
[1132] #if (NGX_ZLIB)
[1133]             if (size == 0) {
[1134]                 size = 64 * 1024;
[1135]             }
[1136] 
[1137]             if (value[i].len == 4) {
[1138]                 gzip = Z_BEST_SPEED;
[1139]                 continue;
[1140]             }
[1141] 
[1142]             s.len = value[i].len - 5;
[1143]             s.data = value[i].data + 5;
[1144] 
[1145]             gzip = ngx_atoi(s.data, s.len);
[1146] 
[1147]             if (gzip < 1 || gzip > 9) {
[1148]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1149]                                    "invalid compression level \"%V\"", &s);
[1150]                 return NGX_CONF_ERROR;
[1151]             }
[1152] 
[1153]             continue;
[1154] 
[1155] #else
[1156]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1157]                                "nginx was built without zlib support");
[1158]             return NGX_CONF_ERROR;
[1159] #endif
[1160]         }
[1161] 
[1162]         if (ngx_strncmp(value[i].data, "if=", 3) == 0) {
[1163]             s.len = value[i].len - 3;
[1164]             s.data = value[i].data + 3;
[1165] 
[1166]             ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[1167] 
[1168]             ccv.cf = cf;
[1169]             ccv.value = &s;
[1170]             ccv.complex_value = ngx_palloc(cf->pool,
[1171]                                            sizeof(ngx_stream_complex_value_t));
[1172]             if (ccv.complex_value == NULL) {
[1173]                 return NGX_CONF_ERROR;
[1174]             }
[1175] 
[1176]             if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[1177]                 return NGX_CONF_ERROR;
[1178]             }
[1179] 
[1180]             log->filter = ccv.complex_value;
[1181] 
[1182]             continue;
[1183]         }
[1184] 
[1185]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1186]                            "invalid parameter \"%V\"", &value[i]);
[1187]         return NGX_CONF_ERROR;
[1188]     }
[1189] 
[1190]     if (flush && size == 0) {
[1191]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1192]                            "no buffer is defined for access_log \"%V\"",
[1193]                            &value[1]);
[1194]         return NGX_CONF_ERROR;
[1195]     }
[1196] 
[1197]     if (size) {
[1198] 
[1199]         if (log->script) {
[1200]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1201]                                "buffered logs cannot have variables in name");
[1202]             return NGX_CONF_ERROR;
[1203]         }
[1204] 
[1205]         if (log->syslog_peer) {
[1206]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1207]                                "logs to syslog cannot be buffered");
[1208]             return NGX_CONF_ERROR;
[1209]         }
[1210] 
[1211]         if (log->file->data) {
[1212]             buffer = log->file->data;
[1213] 
[1214]             if (buffer->last - buffer->start != size
[1215]                 || buffer->flush != flush
[1216]                 || buffer->gzip != gzip)
[1217]             {
[1218]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1219]                                    "access_log \"%V\" already defined "
[1220]                                    "with conflicting parameters",
[1221]                                    &value[1]);
[1222]                 return NGX_CONF_ERROR;
[1223]             }
[1224] 
[1225]             return NGX_CONF_OK;
[1226]         }
[1227] 
[1228]         buffer = ngx_pcalloc(cf->pool, sizeof(ngx_stream_log_buf_t));
[1229]         if (buffer == NULL) {
[1230]             return NGX_CONF_ERROR;
[1231]         }
[1232] 
[1233]         buffer->start = ngx_pnalloc(cf->pool, size);
[1234]         if (buffer->start == NULL) {
[1235]             return NGX_CONF_ERROR;
[1236]         }
[1237] 
[1238]         buffer->pos = buffer->start;
[1239]         buffer->last = buffer->start + size;
[1240] 
[1241]         if (flush) {
[1242]             buffer->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
[1243]             if (buffer->event == NULL) {
[1244]                 return NGX_CONF_ERROR;
[1245]             }
[1246] 
[1247]             buffer->event->data = log->file;
[1248]             buffer->event->handler = ngx_stream_log_flush_handler;
[1249]             buffer->event->log = &cf->cycle->new_log;
[1250]             buffer->event->cancelable = 1;
[1251] 
[1252]             buffer->flush = flush;
[1253]         }
[1254] 
[1255]         buffer->gzip = gzip;
[1256] 
[1257]         log->file->flush = ngx_stream_log_flush;
[1258]         log->file->data = buffer;
[1259]     }
[1260] 
[1261]     return NGX_CONF_OK;
[1262] }
[1263] 
[1264] 
[1265] static char *
[1266] ngx_stream_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1267] {
[1268]     ngx_stream_log_main_conf_t *lmcf = conf;
[1269] 
[1270]     ngx_str_t             *value;
[1271]     ngx_uint_t             i;
[1272]     ngx_stream_log_fmt_t  *fmt;
[1273] 
[1274]     value = cf->args->elts;
[1275] 
[1276]     fmt = lmcf->formats.elts;
[1277]     for (i = 0; i < lmcf->formats.nelts; i++) {
[1278]         if (fmt[i].name.len == value[1].len
[1279]             && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
[1280]         {
[1281]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1282]                                "duplicate \"log_format\" name \"%V\"",
[1283]                                &value[1]);
[1284]             return NGX_CONF_ERROR;
[1285]         }
[1286]     }
[1287] 
[1288]     fmt = ngx_array_push(&lmcf->formats);
[1289]     if (fmt == NULL) {
[1290]         return NGX_CONF_ERROR;
[1291]     }
[1292] 
[1293]     fmt->name = value[1];
[1294] 
[1295]     fmt->flushes = ngx_array_create(cf->pool, 4, sizeof(ngx_int_t));
[1296]     if (fmt->flushes == NULL) {
[1297]         return NGX_CONF_ERROR;
[1298]     }
[1299] 
[1300]     fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_stream_log_op_t));
[1301]     if (fmt->ops == NULL) {
[1302]         return NGX_CONF_ERROR;
[1303]     }
[1304] 
[1305]     return ngx_stream_log_compile_format(cf, fmt->flushes, fmt->ops,
[1306]                                          cf->args, 2);
[1307] }
[1308] 
[1309] 
[1310] static char *
[1311] ngx_stream_log_compile_format(ngx_conf_t *cf, ngx_array_t *flushes,
[1312]     ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
[1313] {
[1314]     u_char                *data, *p, ch;
[1315]     size_t                 i, len;
[1316]     ngx_str_t             *value, var;
[1317]     ngx_int_t             *flush;
[1318]     ngx_uint_t             bracket, escape;
[1319]     ngx_stream_log_op_t   *op;
[1320] 
[1321]     escape = NGX_STREAM_LOG_ESCAPE_DEFAULT;
[1322]     value = args->elts;
[1323] 
[1324]     if (s < args->nelts && ngx_strncmp(value[s].data, "escape=", 7) == 0) {
[1325]         data = value[s].data + 7;
[1326] 
[1327]         if (ngx_strcmp(data, "json") == 0) {
[1328]             escape = NGX_STREAM_LOG_ESCAPE_JSON;
[1329] 
[1330]         } else if (ngx_strcmp(data, "none") == 0) {
[1331]             escape = NGX_STREAM_LOG_ESCAPE_NONE;
[1332] 
[1333]         } else if (ngx_strcmp(data, "default") != 0) {
[1334]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1335]                                "unknown log format escaping \"%s\"", data);
[1336]             return NGX_CONF_ERROR;
[1337]         }
[1338] 
[1339]         s++;
[1340]     }
[1341] 
[1342]     for ( /* void */ ; s < args->nelts; s++) {
[1343] 
[1344]         i = 0;
[1345] 
[1346]         while (i < value[s].len) {
[1347] 
[1348]             op = ngx_array_push(ops);
[1349]             if (op == NULL) {
[1350]                 return NGX_CONF_ERROR;
[1351]             }
[1352] 
[1353]             data = &value[s].data[i];
[1354] 
[1355]             if (value[s].data[i] == '$') {
[1356] 
[1357]                 if (++i == value[s].len) {
[1358]                     goto invalid;
[1359]                 }
[1360] 
[1361]                 if (value[s].data[i] == '{') {
[1362]                     bracket = 1;
[1363] 
[1364]                     if (++i == value[s].len) {
[1365]                         goto invalid;
[1366]                     }
[1367] 
[1368]                     var.data = &value[s].data[i];
[1369] 
[1370]                 } else {
[1371]                     bracket = 0;
[1372]                     var.data = &value[s].data[i];
[1373]                 }
[1374] 
[1375]                 for (var.len = 0; i < value[s].len; i++, var.len++) {
[1376]                     ch = value[s].data[i];
[1377] 
[1378]                     if (ch == '}' && bracket) {
[1379]                         i++;
[1380]                         bracket = 0;
[1381]                         break;
[1382]                     }
[1383] 
[1384]                     if ((ch >= 'A' && ch <= 'Z')
[1385]                         || (ch >= 'a' && ch <= 'z')
[1386]                         || (ch >= '0' && ch <= '9')
[1387]                         || ch == '_')
[1388]                     {
[1389]                         continue;
[1390]                     }
[1391] 
[1392]                     break;
[1393]                 }
[1394] 
[1395]                 if (bracket) {
[1396]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1397]                                        "the closing bracket in \"%V\" "
[1398]                                        "variable is missing", &var);
[1399]                     return NGX_CONF_ERROR;
[1400]                 }
[1401] 
[1402]                 if (var.len == 0) {
[1403]                     goto invalid;
[1404]                 }
[1405] 
[1406]                 if (ngx_stream_log_variable_compile(cf, op, &var, escape)
[1407]                     != NGX_OK)
[1408]                 {
[1409]                     return NGX_CONF_ERROR;
[1410]                 }
[1411] 
[1412]                 if (flushes) {
[1413] 
[1414]                     flush = ngx_array_push(flushes);
[1415]                     if (flush == NULL) {
[1416]                         return NGX_CONF_ERROR;
[1417]                     }
[1418] 
[1419]                     *flush = op->data; /* variable index */
[1420]                 }
[1421] 
[1422]                 continue;
[1423]             }
[1424] 
[1425]             i++;
[1426] 
[1427]             while (i < value[s].len && value[s].data[i] != '$') {
[1428]                 i++;
[1429]             }
[1430] 
[1431]             len = &value[s].data[i] - data;
[1432] 
[1433]             if (len) {
[1434] 
[1435]                 op->len = len;
[1436]                 op->getlen = NULL;
[1437] 
[1438]                 if (len <= sizeof(uintptr_t)) {
[1439]                     op->run = ngx_stream_log_copy_short;
[1440]                     op->data = 0;
[1441] 
[1442]                     while (len--) {
[1443]                         op->data <<= 8;
[1444]                         op->data |= data[len];
[1445]                     }
[1446] 
[1447]                 } else {
[1448]                     op->run = ngx_stream_log_copy_long;
[1449] 
[1450]                     p = ngx_pnalloc(cf->pool, len);
[1451]                     if (p == NULL) {
[1452]                         return NGX_CONF_ERROR;
[1453]                     }
[1454] 
[1455]                     ngx_memcpy(p, data, len);
[1456]                     op->data = (uintptr_t) p;
[1457]                 }
[1458]             }
[1459]         }
[1460]     }
[1461] 
[1462]     return NGX_CONF_OK;
[1463] 
[1464] invalid:
[1465] 
[1466]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);
[1467] 
[1468]     return NGX_CONF_ERROR;
[1469] }
[1470] 
[1471] 
[1472] static char *
[1473] ngx_stream_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1474] {
[1475]     ngx_stream_log_srv_conf_t *lscf = conf;
[1476] 
[1477]     time_t       inactive, valid;
[1478]     ngx_str_t   *value, s;
[1479]     ngx_int_t    max, min_uses;
[1480]     ngx_uint_t   i;
[1481] 
[1482]     if (lscf->open_file_cache != NGX_CONF_UNSET_PTR) {
[1483]         return "is duplicate";
[1484]     }
[1485] 
[1486]     value = cf->args->elts;
[1487] 
[1488]     max = 0;
[1489]     inactive = 10;
[1490]     valid = 60;
[1491]     min_uses = 1;
[1492] 
[1493]     for (i = 1; i < cf->args->nelts; i++) {
[1494] 
[1495]         if (ngx_strncmp(value[i].data, "max=", 4) == 0) {
[1496] 
[1497]             max = ngx_atoi(value[i].data + 4, value[i].len - 4);
[1498]             if (max == NGX_ERROR) {
[1499]                 goto failed;
[1500]             }
[1501] 
[1502]             continue;
[1503]         }
[1504] 
[1505]         if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
[1506] 
[1507]             s.len = value[i].len - 9;
[1508]             s.data = value[i].data + 9;
[1509] 
[1510]             inactive = ngx_parse_time(&s, 1);
[1511]             if (inactive == (time_t) NGX_ERROR) {
[1512]                 goto failed;
[1513]             }
[1514] 
[1515]             continue;
[1516]         }
[1517] 
[1518]         if (ngx_strncmp(value[i].data, "min_uses=", 9) == 0) {
[1519] 
[1520]             min_uses = ngx_atoi(value[i].data + 9, value[i].len - 9);
[1521]             if (min_uses == NGX_ERROR) {
[1522]                 goto failed;
[1523]             }
[1524] 
[1525]             continue;
[1526]         }
[1527] 
[1528]         if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {
[1529] 
[1530]             s.len = value[i].len - 6;
[1531]             s.data = value[i].data + 6;
[1532] 
[1533]             valid = ngx_parse_time(&s, 1);
[1534]             if (valid == (time_t) NGX_ERROR) {
[1535]                 goto failed;
[1536]             }
[1537] 
[1538]             continue;
[1539]         }
[1540] 
[1541]         if (ngx_strcmp(value[i].data, "off") == 0) {
[1542] 
[1543]             lscf->open_file_cache = NULL;
[1544] 
[1545]             continue;
[1546]         }
[1547] 
[1548]     failed:
[1549] 
[1550]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1551]                            "invalid \"open_log_file_cache\" parameter \"%V\"",
[1552]                            &value[i]);
[1553]         return NGX_CONF_ERROR;
[1554]     }
[1555] 
[1556]     if (lscf->open_file_cache == NULL) {
[1557]         return NGX_CONF_OK;
[1558]     }
[1559] 
[1560]     if (max == 0) {
[1561]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1562]                         "\"open_log_file_cache\" must have \"max\" parameter");
[1563]         return NGX_CONF_ERROR;
[1564]     }
[1565] 
[1566]     lscf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);
[1567] 
[1568]     if (lscf->open_file_cache) {
[1569] 
[1570]         lscf->open_file_cache_valid = valid;
[1571]         lscf->open_file_cache_min_uses = min_uses;
[1572] 
[1573]         return NGX_CONF_OK;
[1574]     }
[1575] 
[1576]     return NGX_CONF_ERROR;
[1577] }
[1578] 
[1579] 
[1580] static ngx_int_t
[1581] ngx_stream_log_init(ngx_conf_t *cf)
[1582] {
[1583]     ngx_stream_handler_pt        *h;
[1584]     ngx_stream_core_main_conf_t  *cmcf;
[1585] 
[1586]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[1587] 
[1588]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_LOG_PHASE].handlers);
[1589]     if (h == NULL) {
[1590]         return NGX_ERROR;
[1591]     }
[1592] 
[1593]     *h = ngx_stream_log_handler;
[1594] 
[1595]     return NGX_OK;
[1596] }
