[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] #if (NGX_ZLIB)
[13] #include <zlib.h>
[14] #endif
[15] 
[16] 
[17] typedef struct ngx_http_log_op_s  ngx_http_log_op_t;
[18] 
[19] typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
[20]     ngx_http_log_op_t *op);
[21] 
[22] typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
[23]     uintptr_t data);
[24] 
[25] 
[26] struct ngx_http_log_op_s {
[27]     size_t                      len;
[28]     ngx_http_log_op_getlen_pt   getlen;
[29]     ngx_http_log_op_run_pt      run;
[30]     uintptr_t                   data;
[31] };
[32] 
[33] 
[34] typedef struct {
[35]     ngx_str_t                   name;
[36]     ngx_array_t                *flushes;
[37]     ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
[38] } ngx_http_log_fmt_t;
[39] 
[40] 
[41] typedef struct {
[42]     ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
[43]     ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
[44] } ngx_http_log_main_conf_t;
[45] 
[46] 
[47] typedef struct {
[48]     u_char                     *start;
[49]     u_char                     *pos;
[50]     u_char                     *last;
[51] 
[52]     ngx_event_t                *event;
[53]     ngx_msec_t                  flush;
[54]     ngx_int_t                   gzip;
[55] } ngx_http_log_buf_t;
[56] 
[57] 
[58] typedef struct {
[59]     ngx_array_t                *lengths;
[60]     ngx_array_t                *values;
[61] } ngx_http_log_script_t;
[62] 
[63] 
[64] typedef struct {
[65]     ngx_open_file_t            *file;
[66]     ngx_http_log_script_t      *script;
[67]     time_t                      disk_full_time;
[68]     time_t                      error_log_time;
[69]     ngx_syslog_peer_t          *syslog_peer;
[70]     ngx_http_log_fmt_t         *format;
[71]     ngx_http_complex_value_t   *filter;
[72] } ngx_http_log_t;
[73] 
[74] 
[75] typedef struct {
[76]     ngx_array_t                *logs;       /* array of ngx_http_log_t */
[77] 
[78]     ngx_open_file_cache_t      *open_file_cache;
[79]     time_t                      open_file_cache_valid;
[80]     ngx_uint_t                  open_file_cache_min_uses;
[81] 
[82]     ngx_uint_t                  off;        /* unsigned  off:1 */
[83] } ngx_http_log_loc_conf_t;
[84] 
[85] 
[86] typedef struct {
[87]     ngx_str_t                   name;
[88]     size_t                      len;
[89]     ngx_http_log_op_run_pt      run;
[90] } ngx_http_log_var_t;
[91] 
[92] 
[93] #define NGX_HTTP_LOG_ESCAPE_DEFAULT  0
[94] #define NGX_HTTP_LOG_ESCAPE_JSON     1
[95] #define NGX_HTTP_LOG_ESCAPE_NONE     2
[96] 
[97] 
[98] static void ngx_http_log_write(ngx_http_request_t *r, ngx_http_log_t *log,
[99]     u_char *buf, size_t len);
[100] static ssize_t ngx_http_log_script_write(ngx_http_request_t *r,
[101]     ngx_http_log_script_t *script, u_char **name, u_char *buf, size_t len);
[102] 
[103] #if (NGX_ZLIB)
[104] static ssize_t ngx_http_log_gzip(ngx_fd_t fd, u_char *buf, size_t len,
[105]     ngx_int_t level, ngx_log_t *log);
[106] 
[107] static void *ngx_http_log_gzip_alloc(void *opaque, u_int items, u_int size);
[108] static void ngx_http_log_gzip_free(void *opaque, void *address);
[109] #endif
[110] 
[111] static void ngx_http_log_flush(ngx_open_file_t *file, ngx_log_t *log);
[112] static void ngx_http_log_flush_handler(ngx_event_t *ev);
[113] 
[114] static u_char *ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf,
[115]     ngx_http_log_op_t *op);
[116] static u_char *ngx_http_log_time(ngx_http_request_t *r, u_char *buf,
[117]     ngx_http_log_op_t *op);
[118] static u_char *ngx_http_log_iso8601(ngx_http_request_t *r, u_char *buf,
[119]     ngx_http_log_op_t *op);
[120] static u_char *ngx_http_log_msec(ngx_http_request_t *r, u_char *buf,
[121]     ngx_http_log_op_t *op);
[122] static u_char *ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
[123]     ngx_http_log_op_t *op);
[124] static u_char *ngx_http_log_status(ngx_http_request_t *r, u_char *buf,
[125]     ngx_http_log_op_t *op);
[126] static u_char *ngx_http_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
[127]     ngx_http_log_op_t *op);
[128] static u_char *ngx_http_log_body_bytes_sent(ngx_http_request_t *r,
[129]     u_char *buf, ngx_http_log_op_t *op);
[130] static u_char *ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
[131]     ngx_http_log_op_t *op);
[132] 
[133] static ngx_int_t ngx_http_log_variable_compile(ngx_conf_t *cf,
[134]     ngx_http_log_op_t *op, ngx_str_t *value, ngx_uint_t escape);
[135] static size_t ngx_http_log_variable_getlen(ngx_http_request_t *r,
[136]     uintptr_t data);
[137] static u_char *ngx_http_log_variable(ngx_http_request_t *r, u_char *buf,
[138]     ngx_http_log_op_t *op);
[139] static uintptr_t ngx_http_log_escape(u_char *dst, u_char *src, size_t size);
[140] static size_t ngx_http_log_json_variable_getlen(ngx_http_request_t *r,
[141]     uintptr_t data);
[142] static u_char *ngx_http_log_json_variable(ngx_http_request_t *r, u_char *buf,
[143]     ngx_http_log_op_t *op);
[144] static size_t ngx_http_log_unescaped_variable_getlen(ngx_http_request_t *r,
[145]     uintptr_t data);
[146] static u_char *ngx_http_log_unescaped_variable(ngx_http_request_t *r,
[147]     u_char *buf, ngx_http_log_op_t *op);
[148] 
[149] 
[150] static void *ngx_http_log_create_main_conf(ngx_conf_t *cf);
[151] static void *ngx_http_log_create_loc_conf(ngx_conf_t *cf);
[152] static char *ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent,
[153]     void *child);
[154] static char *ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
[155]     void *conf);
[156] static char *ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
[157]     void *conf);
[158] static char *ngx_http_log_compile_format(ngx_conf_t *cf,
[159]     ngx_array_t *flushes, ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s);
[160] static char *ngx_http_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
[161]     void *conf);
[162] static ngx_int_t ngx_http_log_init(ngx_conf_t *cf);
[163] 
[164] 
[165] static ngx_command_t  ngx_http_log_commands[] = {
[166] 
[167]     { ngx_string("log_format"),
[168]       NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
[169]       ngx_http_log_set_format,
[170]       NGX_HTTP_MAIN_CONF_OFFSET,
[171]       0,
[172]       NULL },
[173] 
[174]     { ngx_string("access_log"),
[175]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[176]                         |NGX_HTTP_LMT_CONF|NGX_CONF_1MORE,
[177]       ngx_http_log_set_log,
[178]       NGX_HTTP_LOC_CONF_OFFSET,
[179]       0,
[180]       NULL },
[181] 
[182]     { ngx_string("open_log_file_cache"),
[183]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
[184]       ngx_http_log_open_file_cache,
[185]       NGX_HTTP_LOC_CONF_OFFSET,
[186]       0,
[187]       NULL },
[188] 
[189]       ngx_null_command
[190] };
[191] 
[192] 
[193] static ngx_http_module_t  ngx_http_log_module_ctx = {
[194]     NULL,                                  /* preconfiguration */
[195]     ngx_http_log_init,                     /* postconfiguration */
[196] 
[197]     ngx_http_log_create_main_conf,         /* create main configuration */
[198]     NULL,                                  /* init main configuration */
[199] 
[200]     NULL,                                  /* create server configuration */
[201]     NULL,                                  /* merge server configuration */
[202] 
[203]     ngx_http_log_create_loc_conf,          /* create location configuration */
[204]     ngx_http_log_merge_loc_conf            /* merge location configuration */
[205] };
[206] 
[207] 
[208] ngx_module_t  ngx_http_log_module = {
[209]     NGX_MODULE_V1,
[210]     &ngx_http_log_module_ctx,              /* module context */
[211]     ngx_http_log_commands,                 /* module directives */
[212]     NGX_HTTP_MODULE,                       /* module type */
[213]     NULL,                                  /* init master */
[214]     NULL,                                  /* init module */
[215]     NULL,                                  /* init process */
[216]     NULL,                                  /* init thread */
[217]     NULL,                                  /* exit thread */
[218]     NULL,                                  /* exit process */
[219]     NULL,                                  /* exit master */
[220]     NGX_MODULE_V1_PADDING
[221] };
[222] 
[223] 
[224] static ngx_str_t  ngx_http_access_log = ngx_string(NGX_HTTP_LOG_PATH);
[225] 
[226] 
[227] static ngx_str_t  ngx_http_combined_fmt =
[228]     ngx_string("$remote_addr - $remote_user [$time_local] "
[229]                "\"$request\" $status $body_bytes_sent "
[230]                "\"$http_referer\" \"$http_user_agent\"");
[231] 
[232] 
[233] static ngx_http_log_var_t  ngx_http_log_vars[] = {
[234]     { ngx_string("pipe"), 1, ngx_http_log_pipe },
[235]     { ngx_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
[236]                           ngx_http_log_time },
[237]     { ngx_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
[238]                           ngx_http_log_iso8601 },
[239]     { ngx_string("msec"), NGX_TIME_T_LEN + 4, ngx_http_log_msec },
[240]     { ngx_string("request_time"), NGX_TIME_T_LEN + 4,
[241]                           ngx_http_log_request_time },
[242]     { ngx_string("status"), NGX_INT_T_LEN, ngx_http_log_status },
[243]     { ngx_string("bytes_sent"), NGX_OFF_T_LEN, ngx_http_log_bytes_sent },
[244]     { ngx_string("body_bytes_sent"), NGX_OFF_T_LEN,
[245]                           ngx_http_log_body_bytes_sent },
[246]     { ngx_string("request_length"), NGX_SIZE_T_LEN,
[247]                           ngx_http_log_request_length },
[248] 
[249]     { ngx_null_string, 0, NULL }
[250] };
[251] 
[252] 
[253] static ngx_int_t
[254] ngx_http_log_handler(ngx_http_request_t *r)
[255] {
[256]     u_char                   *line, *p;
[257]     size_t                    len, size;
[258]     ssize_t                   n;
[259]     ngx_str_t                 val;
[260]     ngx_uint_t                i, l;
[261]     ngx_http_log_t           *log;
[262]     ngx_http_log_op_t        *op;
[263]     ngx_http_log_buf_t       *buffer;
[264]     ngx_http_log_loc_conf_t  *lcf;
[265] 
[266]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[267]                    "http log handler");
[268] 
[269]     lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);
[270] 
[271]     if (lcf->off) {
[272]         return NGX_OK;
[273]     }
[274] 
[275]     log = lcf->logs->elts;
[276]     for (l = 0; l < lcf->logs->nelts; l++) {
[277] 
[278]         if (log[l].filter) {
[279]             if (ngx_http_complex_value(r, log[l].filter, &val) != NGX_OK) {
[280]                 return NGX_ERROR;
[281]             }
[282] 
[283]             if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
[284]                 continue;
[285]             }
[286]         }
[287] 
[288]         if (ngx_time() == log[l].disk_full_time) {
[289] 
[290]             /*
[291]              * on FreeBSD writing to a full filesystem with enabled softupdates
[292]              * may block process for much longer time than writing to non-full
[293]              * filesystem, so we skip writing to a log for one second
[294]              */
[295] 
[296]             continue;
[297]         }
[298] 
[299]         ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);
[300] 
[301]         len = 0;
[302]         op = log[l].format->ops->elts;
[303]         for (i = 0; i < log[l].format->ops->nelts; i++) {
[304]             if (op[i].len == 0) {
[305]                 len += op[i].getlen(r, op[i].data);
[306] 
[307]             } else {
[308]                 len += op[i].len;
[309]             }
[310]         }
[311] 
[312]         if (log[l].syslog_peer) {
[313] 
[314]             /* length of syslog's PRI and HEADER message parts */
[315]             len += sizeof("<255>Jan 01 00:00:00 ") - 1
[316]                    + ngx_cycle->hostname.len + 1
[317]                    + log[l].syslog_peer->tag.len + 2;
[318] 
[319]             goto alloc_line;
[320]         }
[321] 
[322]         len += NGX_LINEFEED_SIZE;
[323] 
[324]         buffer = log[l].file ? log[l].file->data : NULL;
[325] 
[326]         if (buffer) {
[327] 
[328]             if (len > (size_t) (buffer->last - buffer->pos)) {
[329] 
[330]                 ngx_http_log_write(r, &log[l], buffer->start,
[331]                                    buffer->pos - buffer->start);
[332] 
[333]                 buffer->pos = buffer->start;
[334]             }
[335] 
[336]             if (len <= (size_t) (buffer->last - buffer->pos)) {
[337] 
[338]                 p = buffer->pos;
[339] 
[340]                 if (buffer->event && p == buffer->start) {
[341]                     ngx_add_timer(buffer->event, buffer->flush);
[342]                 }
[343] 
[344]                 for (i = 0; i < log[l].format->ops->nelts; i++) {
[345]                     p = op[i].run(r, p, &op[i]);
[346]                 }
[347] 
[348]                 ngx_linefeed(p);
[349] 
[350]                 buffer->pos = p;
[351] 
[352]                 continue;
[353]             }
[354] 
[355]             if (buffer->event && buffer->event->timer_set) {
[356]                 ngx_del_timer(buffer->event);
[357]             }
[358]         }
[359] 
[360]     alloc_line:
[361] 
[362]         line = ngx_pnalloc(r->pool, len);
[363]         if (line == NULL) {
[364]             return NGX_ERROR;
[365]         }
[366] 
[367]         p = line;
[368] 
[369]         if (log[l].syslog_peer) {
[370]             p = ngx_syslog_add_header(log[l].syslog_peer, line);
[371]         }
[372] 
[373]         for (i = 0; i < log[l].format->ops->nelts; i++) {
[374]             p = op[i].run(r, p, &op[i]);
[375]         }
[376] 
[377]         if (log[l].syslog_peer) {
[378] 
[379]             size = p - line;
[380] 
[381]             n = ngx_syslog_send(log[l].syslog_peer, line, size);
[382] 
[383]             if (n < 0) {
[384]                 ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[385]                               "send() to syslog failed");
[386] 
[387]             } else if ((size_t) n != size) {
[388]                 ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
[389]                               "send() to syslog has written only %z of %uz",
[390]                               n, size);
[391]             }
[392] 
[393]             continue;
[394]         }
[395] 
[396]         ngx_linefeed(p);
[397] 
[398]         ngx_http_log_write(r, &log[l], line, p - line);
[399]     }
[400] 
[401]     return NGX_OK;
[402] }
[403] 
[404] 
[405] static void
[406] ngx_http_log_write(ngx_http_request_t *r, ngx_http_log_t *log, u_char *buf,
[407]     size_t len)
[408] {
[409]     u_char              *name;
[410]     time_t               now;
[411]     ssize_t              n;
[412]     ngx_err_t            err;
[413] #if (NGX_ZLIB)
[414]     ngx_http_log_buf_t  *buffer;
[415] #endif
[416] 
[417]     if (log->script == NULL) {
[418]         name = log->file->name.data;
[419] 
[420] #if (NGX_ZLIB)
[421]         buffer = log->file->data;
[422] 
[423]         if (buffer && buffer->gzip) {
[424]             n = ngx_http_log_gzip(log->file->fd, buf, len, buffer->gzip,
[425]                                   r->connection->log);
[426]         } else {
[427]             n = ngx_write_fd(log->file->fd, buf, len);
[428]         }
[429] #else
[430]         n = ngx_write_fd(log->file->fd, buf, len);
[431] #endif
[432] 
[433]     } else {
[434]         name = NULL;
[435]         n = ngx_http_log_script_write(r, log->script, &name, buf, len);
[436]     }
[437] 
[438]     if (n == (ssize_t) len) {
[439]         return;
[440]     }
[441] 
[442]     now = ngx_time();
[443] 
[444]     if (n == -1) {
[445]         err = ngx_errno;
[446] 
[447]         if (err == NGX_ENOSPC) {
[448]             log->disk_full_time = now;
[449]         }
[450] 
[451]         if (now - log->error_log_time > 59) {
[452]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
[453]                           ngx_write_fd_n " to \"%s\" failed", name);
[454] 
[455]             log->error_log_time = now;
[456]         }
[457] 
[458]         return;
[459]     }
[460] 
[461]     if (now - log->error_log_time > 59) {
[462]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[463]                       ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
[464]                       name, n, len);
[465] 
[466]         log->error_log_time = now;
[467]     }
[468] }
[469] 
[470] 
[471] static ssize_t
[472] ngx_http_log_script_write(ngx_http_request_t *r, ngx_http_log_script_t *script,
[473]     u_char **name, u_char *buf, size_t len)
[474] {
[475]     size_t                     root;
[476]     ssize_t                    n;
[477]     ngx_str_t                  log, path;
[478]     ngx_open_file_info_t       of;
[479]     ngx_http_log_loc_conf_t   *llcf;
[480]     ngx_http_core_loc_conf_t  *clcf;
[481] 
[482]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[483] 
[484]     if (!r->root_tested) {
[485] 
[486]         /* test root directory existence */
[487] 
[488]         if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
[489]             /* simulate successful logging */
[490]             return len;
[491]         }
[492] 
[493]         path.data[root] = '\0';
[494] 
[495]         ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[496] 
[497]         of.valid = clcf->open_file_cache_valid;
[498]         of.min_uses = clcf->open_file_cache_min_uses;
[499]         of.test_dir = 1;
[500]         of.test_only = 1;
[501]         of.errors = clcf->open_file_cache_errors;
[502]         of.events = clcf->open_file_cache_events;
[503] 
[504]         if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[505]             /* simulate successful logging */
[506]             return len;
[507]         }
[508] 
[509]         if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[510]             != NGX_OK)
[511]         {
[512]             if (of.err == 0) {
[513]                 /* simulate successful logging */
[514]                 return len;
[515]             }
[516] 
[517]             ngx_log_error(NGX_LOG_ERR, r->connection->log, of.err,
[518]                           "testing \"%s\" existence failed", path.data);
[519] 
[520]             /* simulate successful logging */
[521]             return len;
[522]         }
[523] 
[524]         if (!of.is_dir) {
[525]             ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ENOTDIR,
[526]                           "testing \"%s\" existence failed", path.data);
[527] 
[528]             /* simulate successful logging */
[529]             return len;
[530]         }
[531]     }
[532] 
[533]     if (ngx_http_script_run(r, &log, script->lengths->elts, 1,
[534]                             script->values->elts)
[535]         == NULL)
[536]     {
[537]         /* simulate successful logging */
[538]         return len;
[539]     }
[540] 
[541]     log.data[log.len - 1] = '\0';
[542]     *name = log.data;
[543] 
[544]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[545]                    "http log \"%s\"", log.data);
[546] 
[547]     llcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);
[548] 
[549]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[550] 
[551]     of.log = 1;
[552]     of.valid = llcf->open_file_cache_valid;
[553]     of.min_uses = llcf->open_file_cache_min_uses;
[554]     of.directio = NGX_OPEN_FILE_DIRECTIO_OFF;
[555] 
[556]     if (ngx_http_set_disable_symlinks(r, clcf, &log, &of) != NGX_OK) {
[557]         /* simulate successful logging */
[558]         return len;
[559]     }
[560] 
[561]     if (ngx_open_cached_file(llcf->open_file_cache, &log, &of, r->pool)
[562]         != NGX_OK)
[563]     {
[564]         if (of.err == 0) {
[565]             /* simulate successful logging */
[566]             return len;
[567]         }
[568] 
[569]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[570]                       "%s \"%s\" failed", of.failed, log.data);
[571]         /* simulate successful logging */
[572]         return len;
[573]     }
[574] 
[575]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[576]                    "http log #%d", of.fd);
[577] 
[578]     n = ngx_write_fd(of.fd, buf, len);
[579] 
[580]     return n;
[581] }
[582] 
[583] 
[584] #if (NGX_ZLIB)
[585] 
[586] static ssize_t
[587] ngx_http_log_gzip(ngx_fd_t fd, u_char *buf, size_t len, ngx_int_t level,
[588]     ngx_log_t *log)
[589] {
[590]     int          rc, wbits, memlevel;
[591]     u_char      *out;
[592]     size_t       size;
[593]     ssize_t      n;
[594]     z_stream     zstream;
[595]     ngx_err_t    err;
[596]     ngx_pool_t  *pool;
[597] 
[598]     wbits = MAX_WBITS;
[599]     memlevel = MAX_MEM_LEVEL - 1;
[600] 
[601]     while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
[602]         wbits--;
[603]         memlevel--;
[604]     }
[605] 
[606]     /*
[607]      * This is a formula from deflateBound() for conservative upper bound of
[608]      * compressed data plus 18 bytes of gzip wrapper.
[609]      */
[610] 
[611]     size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;
[612] 
[613]     ngx_memzero(&zstream, sizeof(z_stream));
[614] 
[615]     pool = ngx_create_pool(256, log);
[616]     if (pool == NULL) {
[617]         /* simulate successful logging */
[618]         return len;
[619]     }
[620] 
[621]     pool->log = log;
[622] 
[623]     zstream.zalloc = ngx_http_log_gzip_alloc;
[624]     zstream.zfree = ngx_http_log_gzip_free;
[625]     zstream.opaque = pool;
[626] 
[627]     out = ngx_pnalloc(pool, size);
[628]     if (out == NULL) {
[629]         goto done;
[630]     }
[631] 
[632]     zstream.next_in = buf;
[633]     zstream.avail_in = len;
[634]     zstream.next_out = out;
[635]     zstream.avail_out = size;
[636] 
[637]     rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
[638]                       Z_DEFAULT_STRATEGY);
[639] 
[640]     if (rc != Z_OK) {
[641]         ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
[642]         goto done;
[643]     }
[644] 
[645]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
[646]                    "deflate in: ni:%p no:%p ai:%ud ao:%ud",
[647]                    zstream.next_in, zstream.next_out,
[648]                    zstream.avail_in, zstream.avail_out);
[649] 
[650]     rc = deflate(&zstream, Z_FINISH);
[651] 
[652]     if (rc != Z_STREAM_END) {
[653]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[654]                       "deflate(Z_FINISH) failed: %d", rc);
[655]         goto done;
[656]     }
[657] 
[658]     ngx_log_debug5(NGX_LOG_DEBUG_HTTP, log, 0,
[659]                    "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
[660]                    zstream.next_in, zstream.next_out,
[661]                    zstream.avail_in, zstream.avail_out,
[662]                    rc);
[663] 
[664]     size -= zstream.avail_out;
[665] 
[666]     rc = deflateEnd(&zstream);
[667] 
[668]     if (rc != Z_OK) {
[669]         ngx_log_error(NGX_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
[670]         goto done;
[671]     }
[672] 
[673]     n = ngx_write_fd(fd, out, size);
[674] 
[675]     if (n != (ssize_t) size) {
[676]         err = (n == -1) ? ngx_errno : 0;
[677] 
[678]         ngx_destroy_pool(pool);
[679] 
[680]         ngx_set_errno(err);
[681]         return -1;
[682]     }
[683] 
[684] done:
[685] 
[686]     ngx_destroy_pool(pool);
[687] 
[688]     /* simulate successful logging */
[689]     return len;
[690] }
[691] 
[692] 
[693] static void *
[694] ngx_http_log_gzip_alloc(void *opaque, u_int items, u_int size)
[695] {
[696]     ngx_pool_t *pool = opaque;
[697] 
[698]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
[699]                    "gzip alloc: n:%ud s:%ud", items, size);
[700] 
[701]     return ngx_palloc(pool, items * size);
[702] }
[703] 
[704] 
[705] static void
[706] ngx_http_log_gzip_free(void *opaque, void *address)
[707] {
[708] #if 0
[709]     ngx_pool_t *pool = opaque;
[710] 
[711]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "gzip free: %p", address);
[712] #endif
[713] }
[714] 
[715] #endif
[716] 
[717] 
[718] static void
[719] ngx_http_log_flush(ngx_open_file_t *file, ngx_log_t *log)
[720] {
[721]     size_t               len;
[722]     ssize_t              n;
[723]     ngx_http_log_buf_t  *buffer;
[724] 
[725]     buffer = file->data;
[726] 
[727]     len = buffer->pos - buffer->start;
[728] 
[729]     if (len == 0) {
[730]         return;
[731]     }
[732] 
[733] #if (NGX_ZLIB)
[734]     if (buffer->gzip) {
[735]         n = ngx_http_log_gzip(file->fd, buffer->start, len, buffer->gzip, log);
[736]     } else {
[737]         n = ngx_write_fd(file->fd, buffer->start, len);
[738]     }
[739] #else
[740]     n = ngx_write_fd(file->fd, buffer->start, len);
[741] #endif
[742] 
[743]     if (n == -1) {
[744]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[745]                       ngx_write_fd_n " to \"%s\" failed",
[746]                       file->name.data);
[747] 
[748]     } else if ((size_t) n != len) {
[749]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[750]                       ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
[751]                       file->name.data, n, len);
[752]     }
[753] 
[754]     buffer->pos = buffer->start;
[755] 
[756]     if (buffer->event && buffer->event->timer_set) {
[757]         ngx_del_timer(buffer->event);
[758]     }
[759] }
[760] 
[761] 
[762] static void
[763] ngx_http_log_flush_handler(ngx_event_t *ev)
[764] {
[765]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[766]                    "http log buffer flush handler");
[767] 
[768]     ngx_http_log_flush(ev->data, ev->log);
[769] }
[770] 
[771] 
[772] static u_char *
[773] ngx_http_log_copy_short(ngx_http_request_t *r, u_char *buf,
[774]     ngx_http_log_op_t *op)
[775] {
[776]     size_t     len;
[777]     uintptr_t  data;
[778] 
[779]     len = op->len;
[780]     data = op->data;
[781] 
[782]     while (len--) {
[783]         *buf++ = (u_char) (data & 0xff);
[784]         data >>= 8;
[785]     }
[786] 
[787]     return buf;
[788] }
[789] 
[790] 
[791] static u_char *
[792] ngx_http_log_copy_long(ngx_http_request_t *r, u_char *buf,
[793]     ngx_http_log_op_t *op)
[794] {
[795]     return ngx_cpymem(buf, (u_char *) op->data, op->len);
[796] }
[797] 
[798] 
[799] static u_char *
[800] ngx_http_log_pipe(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
[801] {
[802]     if (r->pipeline) {
[803]         *buf = 'p';
[804]     } else {
[805]         *buf = '.';
[806]     }
[807] 
[808]     return buf + 1;
[809] }
[810] 
[811] 
[812] static u_char *
[813] ngx_http_log_time(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
[814] {
[815]     return ngx_cpymem(buf, ngx_cached_http_log_time.data,
[816]                       ngx_cached_http_log_time.len);
[817] }
[818] 
[819] static u_char *
[820] ngx_http_log_iso8601(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
[821] {
[822]     return ngx_cpymem(buf, ngx_cached_http_log_iso8601.data,
[823]                       ngx_cached_http_log_iso8601.len);
[824] }
[825] 
[826] static u_char *
[827] ngx_http_log_msec(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
[828] {
[829]     ngx_time_t  *tp;
[830] 
[831]     tp = ngx_timeofday();
[832] 
[833]     return ngx_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
[834] }
[835] 
[836] 
[837] static u_char *
[838] ngx_http_log_request_time(ngx_http_request_t *r, u_char *buf,
[839]     ngx_http_log_op_t *op)
[840] {
[841]     ngx_time_t      *tp;
[842]     ngx_msec_int_t   ms;
[843] 
[844]     tp = ngx_timeofday();
[845] 
[846]     ms = (ngx_msec_int_t)
[847]              ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
[848]     ms = ngx_max(ms, 0);
[849] 
[850]     return ngx_sprintf(buf, "%T.%03M", (time_t) ms / 1000, ms % 1000);
[851] }
[852] 
[853] 
[854] static u_char *
[855] ngx_http_log_status(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
[856] {
[857]     ngx_uint_t  status;
[858] 
[859]     if (r->err_status) {
[860]         status = r->err_status;
[861] 
[862]     } else if (r->headers_out.status) {
[863]         status = r->headers_out.status;
[864] 
[865]     } else if (r->http_version == NGX_HTTP_VERSION_9) {
[866]         status = 9;
[867] 
[868]     } else {
[869]         status = 0;
[870]     }
[871] 
[872]     return ngx_sprintf(buf, "%03ui", status);
[873] }
[874] 
[875] 
[876] static u_char *
[877] ngx_http_log_bytes_sent(ngx_http_request_t *r, u_char *buf,
[878]     ngx_http_log_op_t *op)
[879] {
[880]     return ngx_sprintf(buf, "%O", r->connection->sent);
[881] }
[882] 
[883] 
[884] /*
[885]  * although there is a real $body_bytes_sent variable,
[886]  * this log operation code function is more optimized for logging
[887]  */
[888] 
[889] static u_char *
[890] ngx_http_log_body_bytes_sent(ngx_http_request_t *r, u_char *buf,
[891]     ngx_http_log_op_t *op)
[892] {
[893]     off_t  length;
[894] 
[895]     length = r->connection->sent - r->header_size;
[896] 
[897]     if (length > 0) {
[898]         return ngx_sprintf(buf, "%O", length);
[899]     }
[900] 
[901]     *buf = '0';
[902] 
[903]     return buf + 1;
[904] }
[905] 
[906] 
[907] static u_char *
[908] ngx_http_log_request_length(ngx_http_request_t *r, u_char *buf,
[909]     ngx_http_log_op_t *op)
[910] {
[911]     return ngx_sprintf(buf, "%O", r->request_length);
[912] }
[913] 
[914] 
[915] static ngx_int_t
[916] ngx_http_log_variable_compile(ngx_conf_t *cf, ngx_http_log_op_t *op,
[917]     ngx_str_t *value, ngx_uint_t escape)
[918] {
[919]     ngx_int_t  index;
[920] 
[921]     index = ngx_http_get_variable_index(cf, value);
[922]     if (index == NGX_ERROR) {
[923]         return NGX_ERROR;
[924]     }
[925] 
[926]     op->len = 0;
[927] 
[928]     switch (escape) {
[929]     case NGX_HTTP_LOG_ESCAPE_JSON:
[930]         op->getlen = ngx_http_log_json_variable_getlen;
[931]         op->run = ngx_http_log_json_variable;
[932]         break;
[933] 
[934]     case NGX_HTTP_LOG_ESCAPE_NONE:
[935]         op->getlen = ngx_http_log_unescaped_variable_getlen;
[936]         op->run = ngx_http_log_unescaped_variable;
[937]         break;
[938] 
[939]     default: /* NGX_HTTP_LOG_ESCAPE_DEFAULT */
[940]         op->getlen = ngx_http_log_variable_getlen;
[941]         op->run = ngx_http_log_variable;
[942]     }
[943] 
[944]     op->data = index;
[945] 
[946]     return NGX_OK;
[947] }
[948] 
[949] 
[950] static size_t
[951] ngx_http_log_variable_getlen(ngx_http_request_t *r, uintptr_t data)
[952] {
[953]     uintptr_t                   len;
[954]     ngx_http_variable_value_t  *value;
[955] 
[956]     value = ngx_http_get_indexed_variable(r, data);
[957] 
[958]     if (value == NULL || value->not_found) {
[959]         return 1;
[960]     }
[961] 
[962]     len = ngx_http_log_escape(NULL, value->data, value->len);
[963] 
[964]     value->escape = len ? 1 : 0;
[965] 
[966]     return value->len + len * 3;
[967] }
[968] 
[969] 
[970] static u_char *
[971] ngx_http_log_variable(ngx_http_request_t *r, u_char *buf, ngx_http_log_op_t *op)
[972] {
[973]     ngx_http_variable_value_t  *value;
[974] 
[975]     value = ngx_http_get_indexed_variable(r, op->data);
[976] 
[977]     if (value == NULL || value->not_found) {
[978]         *buf = '-';
[979]         return buf + 1;
[980]     }
[981] 
[982]     if (value->escape == 0) {
[983]         return ngx_cpymem(buf, value->data, value->len);
[984] 
[985]     } else {
[986]         return (u_char *) ngx_http_log_escape(buf, value->data, value->len);
[987]     }
[988] }
[989] 
[990] 
[991] static uintptr_t
[992] ngx_http_log_escape(u_char *dst, u_char *src, size_t size)
[993] {
[994]     ngx_uint_t      n;
[995]     static u_char   hex[] = "0123456789ABCDEF";
[996] 
[997]     static uint32_t   escape[] = {
[998]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[999] 
[1000]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1001]         0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */
[1002] 
[1003]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1004]         0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */
[1005] 
[1006]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1007]         0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */
[1008] 
[1009]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1010]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1011]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1012]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1013]     };
[1014] 
[1015] 
[1016]     if (dst == NULL) {
[1017] 
[1018]         /* find the number of the characters to be escaped */
[1019] 
[1020]         n = 0;
[1021] 
[1022]         while (size) {
[1023]             if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
[1024]                 n++;
[1025]             }
[1026]             src++;
[1027]             size--;
[1028]         }
[1029] 
[1030]         return (uintptr_t) n;
[1031]     }
[1032] 
[1033]     while (size) {
[1034]         if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
[1035]             *dst++ = '\\';
[1036]             *dst++ = 'x';
[1037]             *dst++ = hex[*src >> 4];
[1038]             *dst++ = hex[*src & 0xf];
[1039]             src++;
[1040] 
[1041]         } else {
[1042]             *dst++ = *src++;
[1043]         }
[1044]         size--;
[1045]     }
[1046] 
[1047]     return (uintptr_t) dst;
[1048] }
[1049] 
[1050] 
[1051] static size_t
[1052] ngx_http_log_json_variable_getlen(ngx_http_request_t *r, uintptr_t data)
[1053] {
[1054]     uintptr_t                   len;
[1055]     ngx_http_variable_value_t  *value;
[1056] 
[1057]     value = ngx_http_get_indexed_variable(r, data);
[1058] 
[1059]     if (value == NULL || value->not_found) {
[1060]         return 0;
[1061]     }
[1062] 
[1063]     len = ngx_escape_json(NULL, value->data, value->len);
[1064] 
[1065]     value->escape = len ? 1 : 0;
[1066] 
[1067]     return value->len + len;
[1068] }
[1069] 
[1070] 
[1071] static u_char *
[1072] ngx_http_log_json_variable(ngx_http_request_t *r, u_char *buf,
[1073]     ngx_http_log_op_t *op)
[1074] {
[1075]     ngx_http_variable_value_t  *value;
[1076] 
[1077]     value = ngx_http_get_indexed_variable(r, op->data);
[1078] 
[1079]     if (value == NULL || value->not_found) {
[1080]         return buf;
[1081]     }
[1082] 
[1083]     if (value->escape == 0) {
[1084]         return ngx_cpymem(buf, value->data, value->len);
[1085] 
[1086]     } else {
[1087]         return (u_char *) ngx_escape_json(buf, value->data, value->len);
[1088]     }
[1089] }
[1090] 
[1091] 
[1092] static size_t
[1093] ngx_http_log_unescaped_variable_getlen(ngx_http_request_t *r, uintptr_t data)
[1094] {
[1095]     ngx_http_variable_value_t  *value;
[1096] 
[1097]     value = ngx_http_get_indexed_variable(r, data);
[1098] 
[1099]     if (value == NULL || value->not_found) {
[1100]         return 0;
[1101]     }
[1102] 
[1103]     value->escape = 0;
[1104] 
[1105]     return value->len;
[1106] }
[1107] 
[1108] 
[1109] static u_char *
[1110] ngx_http_log_unescaped_variable(ngx_http_request_t *r, u_char *buf,
[1111]     ngx_http_log_op_t *op)
[1112] {
[1113]     ngx_http_variable_value_t  *value;
[1114] 
[1115]     value = ngx_http_get_indexed_variable(r, op->data);
[1116] 
[1117]     if (value == NULL || value->not_found) {
[1118]         return buf;
[1119]     }
[1120] 
[1121]     return ngx_cpymem(buf, value->data, value->len);
[1122] }
[1123] 
[1124] 
[1125] static void *
[1126] ngx_http_log_create_main_conf(ngx_conf_t *cf)
[1127] {
[1128]     ngx_http_log_main_conf_t  *conf;
[1129] 
[1130]     ngx_http_log_fmt_t  *fmt;
[1131] 
[1132]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_main_conf_t));
[1133]     if (conf == NULL) {
[1134]         return NULL;
[1135]     }
[1136] 
[1137]     if (ngx_array_init(&conf->formats, cf->pool, 4, sizeof(ngx_http_log_fmt_t))
[1138]         != NGX_OK)
[1139]     {
[1140]         return NULL;
[1141]     }
[1142] 
[1143]     fmt = ngx_array_push(&conf->formats);
[1144]     if (fmt == NULL) {
[1145]         return NULL;
[1146]     }
[1147] 
[1148]     ngx_str_set(&fmt->name, "combined");
[1149] 
[1150]     fmt->flushes = NULL;
[1151] 
[1152]     fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_log_op_t));
[1153]     if (fmt->ops == NULL) {
[1154]         return NULL;
[1155]     }
[1156] 
[1157]     return conf;
[1158] }
[1159] 
[1160] 
[1161] static void *
[1162] ngx_http_log_create_loc_conf(ngx_conf_t *cf)
[1163] {
[1164]     ngx_http_log_loc_conf_t  *conf;
[1165] 
[1166]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_loc_conf_t));
[1167]     if (conf == NULL) {
[1168]         return NULL;
[1169]     }
[1170] 
[1171]     conf->open_file_cache = NGX_CONF_UNSET_PTR;
[1172] 
[1173]     return conf;
[1174] }
[1175] 
[1176] 
[1177] static char *
[1178] ngx_http_log_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[1179] {
[1180]     ngx_http_log_loc_conf_t *prev = parent;
[1181]     ngx_http_log_loc_conf_t *conf = child;
[1182] 
[1183]     ngx_http_log_t            *log;
[1184]     ngx_http_log_fmt_t        *fmt;
[1185]     ngx_http_log_main_conf_t  *lmcf;
[1186] 
[1187]     if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {
[1188] 
[1189]         conf->open_file_cache = prev->open_file_cache;
[1190]         conf->open_file_cache_valid = prev->open_file_cache_valid;
[1191]         conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;
[1192] 
[1193]         if (conf->open_file_cache == NGX_CONF_UNSET_PTR) {
[1194]             conf->open_file_cache = NULL;
[1195]         }
[1196]     }
[1197] 
[1198]     if (conf->logs || conf->off) {
[1199]         return NGX_CONF_OK;
[1200]     }
[1201] 
[1202]     conf->logs = prev->logs;
[1203]     conf->off = prev->off;
[1204] 
[1205]     if (conf->logs || conf->off) {
[1206]         return NGX_CONF_OK;
[1207]     }
[1208] 
[1209]     conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
[1210]     if (conf->logs == NULL) {
[1211]         return NGX_CONF_ERROR;
[1212]     }
[1213] 
[1214]     log = ngx_array_push(conf->logs);
[1215]     if (log == NULL) {
[1216]         return NGX_CONF_ERROR;
[1217]     }
[1218] 
[1219]     ngx_memzero(log, sizeof(ngx_http_log_t));
[1220] 
[1221]     log->file = ngx_conf_open_file(cf->cycle, &ngx_http_access_log);
[1222]     if (log->file == NULL) {
[1223]         return NGX_CONF_ERROR;
[1224]     }
[1225] 
[1226]     lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
[1227]     fmt = lmcf->formats.elts;
[1228] 
[1229]     /* the default "combined" format */
[1230]     log->format = &fmt[0];
[1231]     lmcf->combined_used = 1;
[1232] 
[1233]     return NGX_CONF_OK;
[1234] }
[1235] 
[1236] 
[1237] static char *
[1238] ngx_http_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1239] {
[1240]     ngx_http_log_loc_conf_t *llcf = conf;
[1241] 
[1242]     ssize_t                            size;
[1243]     ngx_int_t                          gzip;
[1244]     ngx_uint_t                         i, n;
[1245]     ngx_msec_t                         flush;
[1246]     ngx_str_t                         *value, name, s;
[1247]     ngx_http_log_t                    *log;
[1248]     ngx_syslog_peer_t                 *peer;
[1249]     ngx_http_log_buf_t                *buffer;
[1250]     ngx_http_log_fmt_t                *fmt;
[1251]     ngx_http_log_main_conf_t          *lmcf;
[1252]     ngx_http_script_compile_t          sc;
[1253]     ngx_http_compile_complex_value_t   ccv;
[1254] 
[1255]     value = cf->args->elts;
[1256] 
[1257]     if (ngx_strcmp(value[1].data, "off") == 0) {
[1258]         llcf->off = 1;
[1259]         if (cf->args->nelts == 2) {
[1260]             return NGX_CONF_OK;
[1261]         }
[1262] 
[1263]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1264]                            "invalid parameter \"%V\"", &value[2]);
[1265]         return NGX_CONF_ERROR;
[1266]     }
[1267] 
[1268]     if (llcf->logs == NULL) {
[1269]         llcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_log_t));
[1270]         if (llcf->logs == NULL) {
[1271]             return NGX_CONF_ERROR;
[1272]         }
[1273]     }
[1274] 
[1275]     lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
[1276] 
[1277]     log = ngx_array_push(llcf->logs);
[1278]     if (log == NULL) {
[1279]         return NGX_CONF_ERROR;
[1280]     }
[1281] 
[1282]     ngx_memzero(log, sizeof(ngx_http_log_t));
[1283] 
[1284] 
[1285]     if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {
[1286] 
[1287]         peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
[1288]         if (peer == NULL) {
[1289]             return NGX_CONF_ERROR;
[1290]         }
[1291] 
[1292]         if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
[1293]             return NGX_CONF_ERROR;
[1294]         }
[1295] 
[1296]         log->syslog_peer = peer;
[1297] 
[1298]         goto process_formats;
[1299]     }
[1300] 
[1301]     n = ngx_http_script_variables_count(&value[1]);
[1302] 
[1303]     if (n == 0) {
[1304]         log->file = ngx_conf_open_file(cf->cycle, &value[1]);
[1305]         if (log->file == NULL) {
[1306]             return NGX_CONF_ERROR;
[1307]         }
[1308] 
[1309]     } else {
[1310]         if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
[1311]             return NGX_CONF_ERROR;
[1312]         }
[1313] 
[1314]         log->script = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_script_t));
[1315]         if (log->script == NULL) {
[1316]             return NGX_CONF_ERROR;
[1317]         }
[1318] 
[1319]         ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[1320] 
[1321]         sc.cf = cf;
[1322]         sc.source = &value[1];
[1323]         sc.lengths = &log->script->lengths;
[1324]         sc.values = &log->script->values;
[1325]         sc.variables = n;
[1326]         sc.complete_lengths = 1;
[1327]         sc.complete_values = 1;
[1328] 
[1329]         if (ngx_http_script_compile(&sc) != NGX_OK) {
[1330]             return NGX_CONF_ERROR;
[1331]         }
[1332]     }
[1333] 
[1334] process_formats:
[1335] 
[1336]     if (cf->args->nelts >= 3) {
[1337]         name = value[2];
[1338] 
[1339]         if (ngx_strcmp(name.data, "combined") == 0) {
[1340]             lmcf->combined_used = 1;
[1341]         }
[1342] 
[1343]     } else {
[1344]         ngx_str_set(&name, "combined");
[1345]         lmcf->combined_used = 1;
[1346]     }
[1347] 
[1348]     fmt = lmcf->formats.elts;
[1349]     for (i = 0; i < lmcf->formats.nelts; i++) {
[1350]         if (fmt[i].name.len == name.len
[1351]             && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
[1352]         {
[1353]             log->format = &fmt[i];
[1354]             break;
[1355]         }
[1356]     }
[1357] 
[1358]     if (log->format == NULL) {
[1359]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1360]                            "unknown log format \"%V\"", &name);
[1361]         return NGX_CONF_ERROR;
[1362]     }
[1363] 
[1364]     size = 0;
[1365]     flush = 0;
[1366]     gzip = 0;
[1367] 
[1368]     for (i = 3; i < cf->args->nelts; i++) {
[1369] 
[1370]         if (ngx_strncmp(value[i].data, "buffer=", 7) == 0) {
[1371]             s.len = value[i].len - 7;
[1372]             s.data = value[i].data + 7;
[1373] 
[1374]             size = ngx_parse_size(&s);
[1375] 
[1376]             if (size == NGX_ERROR || size == 0) {
[1377]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1378]                                    "invalid buffer size \"%V\"", &s);
[1379]                 return NGX_CONF_ERROR;
[1380]             }
[1381] 
[1382]             continue;
[1383]         }
[1384] 
[1385]         if (ngx_strncmp(value[i].data, "flush=", 6) == 0) {
[1386]             s.len = value[i].len - 6;
[1387]             s.data = value[i].data + 6;
[1388] 
[1389]             flush = ngx_parse_time(&s, 0);
[1390] 
[1391]             if (flush == (ngx_msec_t) NGX_ERROR || flush == 0) {
[1392]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1393]                                    "invalid flush time \"%V\"", &s);
[1394]                 return NGX_CONF_ERROR;
[1395]             }
[1396] 
[1397]             continue;
[1398]         }
[1399] 
[1400]         if (ngx_strncmp(value[i].data, "gzip", 4) == 0
[1401]             && (value[i].len == 4 || value[i].data[4] == '='))
[1402]         {
[1403] #if (NGX_ZLIB)
[1404]             if (size == 0) {
[1405]                 size = 64 * 1024;
[1406]             }
[1407] 
[1408]             if (value[i].len == 4) {
[1409]                 gzip = Z_BEST_SPEED;
[1410]                 continue;
[1411]             }
[1412] 
[1413]             s.len = value[i].len - 5;
[1414]             s.data = value[i].data + 5;
[1415] 
[1416]             gzip = ngx_atoi(s.data, s.len);
[1417] 
[1418]             if (gzip < 1 || gzip > 9) {
[1419]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1420]                                    "invalid compression level \"%V\"", &s);
[1421]                 return NGX_CONF_ERROR;
[1422]             }
[1423] 
[1424]             continue;
[1425] 
[1426] #else
[1427]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1428]                                "nginx was built without zlib support");
[1429]             return NGX_CONF_ERROR;
[1430] #endif
[1431]         }
[1432] 
[1433]         if (ngx_strncmp(value[i].data, "if=", 3) == 0) {
[1434]             s.len = value[i].len - 3;
[1435]             s.data = value[i].data + 3;
[1436] 
[1437]             ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1438] 
[1439]             ccv.cf = cf;
[1440]             ccv.value = &s;
[1441]             ccv.complex_value = ngx_palloc(cf->pool,
[1442]                                            sizeof(ngx_http_complex_value_t));
[1443]             if (ccv.complex_value == NULL) {
[1444]                 return NGX_CONF_ERROR;
[1445]             }
[1446] 
[1447]             if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1448]                 return NGX_CONF_ERROR;
[1449]             }
[1450] 
[1451]             log->filter = ccv.complex_value;
[1452] 
[1453]             continue;
[1454]         }
[1455] 
[1456]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1457]                            "invalid parameter \"%V\"", &value[i]);
[1458]         return NGX_CONF_ERROR;
[1459]     }
[1460] 
[1461]     if (flush && size == 0) {
[1462]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1463]                            "no buffer is defined for access_log \"%V\"",
[1464]                            &value[1]);
[1465]         return NGX_CONF_ERROR;
[1466]     }
[1467] 
[1468]     if (size) {
[1469] 
[1470]         if (log->script) {
[1471]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1472]                                "buffered logs cannot have variables in name");
[1473]             return NGX_CONF_ERROR;
[1474]         }
[1475] 
[1476]         if (log->syslog_peer) {
[1477]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1478]                                "logs to syslog cannot be buffered");
[1479]             return NGX_CONF_ERROR;
[1480]         }
[1481] 
[1482]         if (log->file->data) {
[1483]             buffer = log->file->data;
[1484] 
[1485]             if (buffer->last - buffer->start != size
[1486]                 || buffer->flush != flush
[1487]                 || buffer->gzip != gzip)
[1488]             {
[1489]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1490]                                    "access_log \"%V\" already defined "
[1491]                                    "with conflicting parameters",
[1492]                                    &value[1]);
[1493]                 return NGX_CONF_ERROR;
[1494]             }
[1495] 
[1496]             return NGX_CONF_OK;
[1497]         }
[1498] 
[1499]         buffer = ngx_pcalloc(cf->pool, sizeof(ngx_http_log_buf_t));
[1500]         if (buffer == NULL) {
[1501]             return NGX_CONF_ERROR;
[1502]         }
[1503] 
[1504]         buffer->start = ngx_pnalloc(cf->pool, size);
[1505]         if (buffer->start == NULL) {
[1506]             return NGX_CONF_ERROR;
[1507]         }
[1508] 
[1509]         buffer->pos = buffer->start;
[1510]         buffer->last = buffer->start + size;
[1511] 
[1512]         if (flush) {
[1513]             buffer->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
[1514]             if (buffer->event == NULL) {
[1515]                 return NGX_CONF_ERROR;
[1516]             }
[1517] 
[1518]             buffer->event->data = log->file;
[1519]             buffer->event->handler = ngx_http_log_flush_handler;
[1520]             buffer->event->log = &cf->cycle->new_log;
[1521]             buffer->event->cancelable = 1;
[1522] 
[1523]             buffer->flush = flush;
[1524]         }
[1525] 
[1526]         buffer->gzip = gzip;
[1527] 
[1528]         log->file->flush = ngx_http_log_flush;
[1529]         log->file->data = buffer;
[1530]     }
[1531] 
[1532]     return NGX_CONF_OK;
[1533] }
[1534] 
[1535] 
[1536] static char *
[1537] ngx_http_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1538] {
[1539]     ngx_http_log_main_conf_t *lmcf = conf;
[1540] 
[1541]     ngx_str_t           *value;
[1542]     ngx_uint_t           i;
[1543]     ngx_http_log_fmt_t  *fmt;
[1544] 
[1545]     value = cf->args->elts;
[1546] 
[1547]     fmt = lmcf->formats.elts;
[1548]     for (i = 0; i < lmcf->formats.nelts; i++) {
[1549]         if (fmt[i].name.len == value[1].len
[1550]             && ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
[1551]         {
[1552]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1553]                                "duplicate \"log_format\" name \"%V\"",
[1554]                                &value[1]);
[1555]             return NGX_CONF_ERROR;
[1556]         }
[1557]     }
[1558] 
[1559]     fmt = ngx_array_push(&lmcf->formats);
[1560]     if (fmt == NULL) {
[1561]         return NGX_CONF_ERROR;
[1562]     }
[1563] 
[1564]     fmt->name = value[1];
[1565] 
[1566]     fmt->flushes = ngx_array_create(cf->pool, 4, sizeof(ngx_int_t));
[1567]     if (fmt->flushes == NULL) {
[1568]         return NGX_CONF_ERROR;
[1569]     }
[1570] 
[1571]     fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_http_log_op_t));
[1572]     if (fmt->ops == NULL) {
[1573]         return NGX_CONF_ERROR;
[1574]     }
[1575] 
[1576]     return ngx_http_log_compile_format(cf, fmt->flushes, fmt->ops, cf->args, 2);
[1577] }
[1578] 
[1579] 
[1580] static char *
[1581] ngx_http_log_compile_format(ngx_conf_t *cf, ngx_array_t *flushes,
[1582]     ngx_array_t *ops, ngx_array_t *args, ngx_uint_t s)
[1583] {
[1584]     u_char              *data, *p, ch;
[1585]     size_t               i, len;
[1586]     ngx_str_t           *value, var;
[1587]     ngx_int_t           *flush;
[1588]     ngx_uint_t           bracket, escape;
[1589]     ngx_http_log_op_t   *op;
[1590]     ngx_http_log_var_t  *v;
[1591] 
[1592]     escape = NGX_HTTP_LOG_ESCAPE_DEFAULT;
[1593]     value = args->elts;
[1594] 
[1595]     if (s < args->nelts && ngx_strncmp(value[s].data, "escape=", 7) == 0) {
[1596]         data = value[s].data + 7;
[1597] 
[1598]         if (ngx_strcmp(data, "json") == 0) {
[1599]             escape = NGX_HTTP_LOG_ESCAPE_JSON;
[1600] 
[1601]         } else if (ngx_strcmp(data, "none") == 0) {
[1602]             escape = NGX_HTTP_LOG_ESCAPE_NONE;
[1603] 
[1604]         } else if (ngx_strcmp(data, "default") != 0) {
[1605]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1606]                                "unknown log format escaping \"%s\"", data);
[1607]             return NGX_CONF_ERROR;
[1608]         }
[1609] 
[1610]         s++;
[1611]     }
[1612] 
[1613]     for ( /* void */ ; s < args->nelts; s++) {
[1614] 
[1615]         i = 0;
[1616] 
[1617]         while (i < value[s].len) {
[1618] 
[1619]             op = ngx_array_push(ops);
[1620]             if (op == NULL) {
[1621]                 return NGX_CONF_ERROR;
[1622]             }
[1623] 
[1624]             data = &value[s].data[i];
[1625] 
[1626]             if (value[s].data[i] == '$') {
[1627] 
[1628]                 if (++i == value[s].len) {
[1629]                     goto invalid;
[1630]                 }
[1631] 
[1632]                 if (value[s].data[i] == '{') {
[1633]                     bracket = 1;
[1634] 
[1635]                     if (++i == value[s].len) {
[1636]                         goto invalid;
[1637]                     }
[1638] 
[1639]                     var.data = &value[s].data[i];
[1640] 
[1641]                 } else {
[1642]                     bracket = 0;
[1643]                     var.data = &value[s].data[i];
[1644]                 }
[1645] 
[1646]                 for (var.len = 0; i < value[s].len; i++, var.len++) {
[1647]                     ch = value[s].data[i];
[1648] 
[1649]                     if (ch == '}' && bracket) {
[1650]                         i++;
[1651]                         bracket = 0;
[1652]                         break;
[1653]                     }
[1654] 
[1655]                     if ((ch >= 'A' && ch <= 'Z')
[1656]                         || (ch >= 'a' && ch <= 'z')
[1657]                         || (ch >= '0' && ch <= '9')
[1658]                         || ch == '_')
[1659]                     {
[1660]                         continue;
[1661]                     }
[1662] 
[1663]                     break;
[1664]                 }
[1665] 
[1666]                 if (bracket) {
[1667]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1668]                                        "the closing bracket in \"%V\" "
[1669]                                        "variable is missing", &var);
[1670]                     return NGX_CONF_ERROR;
[1671]                 }
[1672] 
[1673]                 if (var.len == 0) {
[1674]                     goto invalid;
[1675]                 }
[1676] 
[1677]                 for (v = ngx_http_log_vars; v->name.len; v++) {
[1678] 
[1679]                     if (v->name.len == var.len
[1680]                         && ngx_strncmp(v->name.data, var.data, var.len) == 0)
[1681]                     {
[1682]                         op->len = v->len;
[1683]                         op->getlen = NULL;
[1684]                         op->run = v->run;
[1685]                         op->data = 0;
[1686] 
[1687]                         goto found;
[1688]                     }
[1689]                 }
[1690] 
[1691]                 if (ngx_http_log_variable_compile(cf, op, &var, escape)
[1692]                     != NGX_OK)
[1693]                 {
[1694]                     return NGX_CONF_ERROR;
[1695]                 }
[1696] 
[1697]                 if (flushes) {
[1698] 
[1699]                     flush = ngx_array_push(flushes);
[1700]                     if (flush == NULL) {
[1701]                         return NGX_CONF_ERROR;
[1702]                     }
[1703] 
[1704]                     *flush = op->data; /* variable index */
[1705]                 }
[1706] 
[1707]             found:
[1708] 
[1709]                 continue;
[1710]             }
[1711] 
[1712]             i++;
[1713] 
[1714]             while (i < value[s].len && value[s].data[i] != '$') {
[1715]                 i++;
[1716]             }
[1717] 
[1718]             len = &value[s].data[i] - data;
[1719] 
[1720]             if (len) {
[1721] 
[1722]                 op->len = len;
[1723]                 op->getlen = NULL;
[1724] 
[1725]                 if (len <= sizeof(uintptr_t)) {
[1726]                     op->run = ngx_http_log_copy_short;
[1727]                     op->data = 0;
[1728] 
[1729]                     while (len--) {
[1730]                         op->data <<= 8;
[1731]                         op->data |= data[len];
[1732]                     }
[1733] 
[1734]                 } else {
[1735]                     op->run = ngx_http_log_copy_long;
[1736] 
[1737]                     p = ngx_pnalloc(cf->pool, len);
[1738]                     if (p == NULL) {
[1739]                         return NGX_CONF_ERROR;
[1740]                     }
[1741] 
[1742]                     ngx_memcpy(p, data, len);
[1743]                     op->data = (uintptr_t) p;
[1744]                 }
[1745]             }
[1746]         }
[1747]     }
[1748] 
[1749]     return NGX_CONF_OK;
[1750] 
[1751] invalid:
[1752] 
[1753]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);
[1754] 
[1755]     return NGX_CONF_ERROR;
[1756] }
[1757] 
[1758] 
[1759] static char *
[1760] ngx_http_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1761] {
[1762]     ngx_http_log_loc_conf_t *llcf = conf;
[1763] 
[1764]     time_t       inactive, valid;
[1765]     ngx_str_t   *value, s;
[1766]     ngx_int_t    max, min_uses;
[1767]     ngx_uint_t   i;
[1768] 
[1769]     if (llcf->open_file_cache != NGX_CONF_UNSET_PTR) {
[1770]         return "is duplicate";
[1771]     }
[1772] 
[1773]     value = cf->args->elts;
[1774] 
[1775]     max = 0;
[1776]     inactive = 10;
[1777]     valid = 60;
[1778]     min_uses = 1;
[1779] 
[1780]     for (i = 1; i < cf->args->nelts; i++) {
[1781] 
[1782]         if (ngx_strncmp(value[i].data, "max=", 4) == 0) {
[1783] 
[1784]             max = ngx_atoi(value[i].data + 4, value[i].len - 4);
[1785]             if (max == NGX_ERROR) {
[1786]                 goto failed;
[1787]             }
[1788] 
[1789]             continue;
[1790]         }
[1791] 
[1792]         if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {
[1793] 
[1794]             s.len = value[i].len - 9;
[1795]             s.data = value[i].data + 9;
[1796] 
[1797]             inactive = ngx_parse_time(&s, 1);
[1798]             if (inactive == (time_t) NGX_ERROR) {
[1799]                 goto failed;
[1800]             }
[1801] 
[1802]             continue;
[1803]         }
[1804] 
[1805]         if (ngx_strncmp(value[i].data, "min_uses=", 9) == 0) {
[1806] 
[1807]             min_uses = ngx_atoi(value[i].data + 9, value[i].len - 9);
[1808]             if (min_uses == NGX_ERROR) {
[1809]                 goto failed;
[1810]             }
[1811] 
[1812]             continue;
[1813]         }
[1814] 
[1815]         if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {
[1816] 
[1817]             s.len = value[i].len - 6;
[1818]             s.data = value[i].data + 6;
[1819] 
[1820]             valid = ngx_parse_time(&s, 1);
[1821]             if (valid == (time_t) NGX_ERROR) {
[1822]                 goto failed;
[1823]             }
[1824] 
[1825]             continue;
[1826]         }
[1827] 
[1828]         if (ngx_strcmp(value[i].data, "off") == 0) {
[1829] 
[1830]             llcf->open_file_cache = NULL;
[1831] 
[1832]             continue;
[1833]         }
[1834] 
[1835]     failed:
[1836] 
[1837]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1838]                            "invalid \"open_log_file_cache\" parameter \"%V\"",
[1839]                            &value[i]);
[1840]         return NGX_CONF_ERROR;
[1841]     }
[1842] 
[1843]     if (llcf->open_file_cache == NULL) {
[1844]         return NGX_CONF_OK;
[1845]     }
[1846] 
[1847]     if (max == 0) {
[1848]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1849]                         "\"open_log_file_cache\" must have \"max\" parameter");
[1850]         return NGX_CONF_ERROR;
[1851]     }
[1852] 
[1853]     llcf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);
[1854] 
[1855]     if (llcf->open_file_cache) {
[1856] 
[1857]         llcf->open_file_cache_valid = valid;
[1858]         llcf->open_file_cache_min_uses = min_uses;
[1859] 
[1860]         return NGX_CONF_OK;
[1861]     }
[1862] 
[1863]     return NGX_CONF_ERROR;
[1864] }
[1865] 
[1866] 
[1867] static ngx_int_t
[1868] ngx_http_log_init(ngx_conf_t *cf)
[1869] {
[1870]     ngx_str_t                  *value;
[1871]     ngx_array_t                 a;
[1872]     ngx_http_handler_pt        *h;
[1873]     ngx_http_log_fmt_t         *fmt;
[1874]     ngx_http_log_main_conf_t   *lmcf;
[1875]     ngx_http_core_main_conf_t  *cmcf;
[1876] 
[1877]     lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
[1878] 
[1879]     if (lmcf->combined_used) {
[1880]         if (ngx_array_init(&a, cf->pool, 1, sizeof(ngx_str_t)) != NGX_OK) {
[1881]             return NGX_ERROR;
[1882]         }
[1883] 
[1884]         value = ngx_array_push(&a);
[1885]         if (value == NULL) {
[1886]             return NGX_ERROR;
[1887]         }
[1888] 
[1889]         *value = ngx_http_combined_fmt;
[1890]         fmt = lmcf->formats.elts;
[1891] 
[1892]         if (ngx_http_log_compile_format(cf, NULL, fmt->ops, &a, 0)
[1893]             != NGX_CONF_OK)
[1894]         {
[1895]             return NGX_ERROR;
[1896]         }
[1897]     }
[1898] 
[1899]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[1900] 
[1901]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
[1902]     if (h == NULL) {
[1903]         return NGX_ERROR;
[1904]     }
[1905] 
[1906]     *h = ngx_http_log_handler;
[1907] 
[1908]     return NGX_OK;
[1909] }
