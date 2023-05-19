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
[12] 
[13] #if 0
[14] 
[15] typedef struct {
[16]     ngx_buf_t     *buf;
[17]     size_t         size;
[18]     ngx_pool_t    *pool;
[19]     size_t         alloc_size;
[20]     ngx_chain_t  **last_out;
[21] } ngx_http_autoindex_ctx_t;
[22] 
[23] #endif
[24] 
[25] 
[26] typedef struct {
[27]     ngx_str_t      name;
[28]     size_t         utf_len;
[29]     size_t         escape;
[30]     size_t         escape_html;
[31] 
[32]     unsigned       dir:1;
[33]     unsigned       file:1;
[34] 
[35]     time_t         mtime;
[36]     off_t          size;
[37] } ngx_http_autoindex_entry_t;
[38] 
[39] 
[40] typedef struct {
[41]     ngx_flag_t     enable;
[42]     ngx_uint_t     format;
[43]     ngx_flag_t     localtime;
[44]     ngx_flag_t     exact_size;
[45] } ngx_http_autoindex_loc_conf_t;
[46] 
[47] 
[48] #define NGX_HTTP_AUTOINDEX_HTML         0
[49] #define NGX_HTTP_AUTOINDEX_JSON         1
[50] #define NGX_HTTP_AUTOINDEX_JSONP        2
[51] #define NGX_HTTP_AUTOINDEX_XML          3
[52] 
[53] #define NGX_HTTP_AUTOINDEX_PREALLOCATE  50
[54] 
[55] #define NGX_HTTP_AUTOINDEX_NAME_LEN     50
[56] 
[57] 
[58] static ngx_buf_t *ngx_http_autoindex_html(ngx_http_request_t *r,
[59]     ngx_array_t *entries);
[60] static ngx_buf_t *ngx_http_autoindex_json(ngx_http_request_t *r,
[61]     ngx_array_t *entries, ngx_str_t *callback);
[62] static ngx_int_t ngx_http_autoindex_jsonp_callback(ngx_http_request_t *r,
[63]     ngx_str_t *callback);
[64] static ngx_buf_t *ngx_http_autoindex_xml(ngx_http_request_t *r,
[65]     ngx_array_t *entries);
[66] 
[67] static int ngx_libc_cdecl ngx_http_autoindex_cmp_entries(const void *one,
[68]     const void *two);
[69] static ngx_int_t ngx_http_autoindex_error(ngx_http_request_t *r,
[70]     ngx_dir_t *dir, ngx_str_t *name);
[71] 
[72] static ngx_int_t ngx_http_autoindex_init(ngx_conf_t *cf);
[73] static void *ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf);
[74] static char *ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf,
[75]     void *parent, void *child);
[76] 
[77] 
[78] static ngx_conf_enum_t  ngx_http_autoindex_format[] = {
[79]     { ngx_string("html"), NGX_HTTP_AUTOINDEX_HTML },
[80]     { ngx_string("json"), NGX_HTTP_AUTOINDEX_JSON },
[81]     { ngx_string("jsonp"), NGX_HTTP_AUTOINDEX_JSONP },
[82]     { ngx_string("xml"), NGX_HTTP_AUTOINDEX_XML },
[83]     { ngx_null_string, 0 }
[84] };
[85] 
[86] 
[87] static ngx_command_t  ngx_http_autoindex_commands[] = {
[88] 
[89]     { ngx_string("autoindex"),
[90]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[91]       ngx_conf_set_flag_slot,
[92]       NGX_HTTP_LOC_CONF_OFFSET,
[93]       offsetof(ngx_http_autoindex_loc_conf_t, enable),
[94]       NULL },
[95] 
[96]     { ngx_string("autoindex_format"),
[97]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[98]       ngx_conf_set_enum_slot,
[99]       NGX_HTTP_LOC_CONF_OFFSET,
[100]       offsetof(ngx_http_autoindex_loc_conf_t, format),
[101]       &ngx_http_autoindex_format },
[102] 
[103]     { ngx_string("autoindex_localtime"),
[104]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[105]       ngx_conf_set_flag_slot,
[106]       NGX_HTTP_LOC_CONF_OFFSET,
[107]       offsetof(ngx_http_autoindex_loc_conf_t, localtime),
[108]       NULL },
[109] 
[110]     { ngx_string("autoindex_exact_size"),
[111]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[112]       ngx_conf_set_flag_slot,
[113]       NGX_HTTP_LOC_CONF_OFFSET,
[114]       offsetof(ngx_http_autoindex_loc_conf_t, exact_size),
[115]       NULL },
[116] 
[117]       ngx_null_command
[118] };
[119] 
[120] 
[121] static ngx_http_module_t  ngx_http_autoindex_module_ctx = {
[122]     NULL,                                  /* preconfiguration */
[123]     ngx_http_autoindex_init,               /* postconfiguration */
[124] 
[125]     NULL,                                  /* create main configuration */
[126]     NULL,                                  /* init main configuration */
[127] 
[128]     NULL,                                  /* create server configuration */
[129]     NULL,                                  /* merge server configuration */
[130] 
[131]     ngx_http_autoindex_create_loc_conf,    /* create location configuration */
[132]     ngx_http_autoindex_merge_loc_conf      /* merge location configuration */
[133] };
[134] 
[135] 
[136] ngx_module_t  ngx_http_autoindex_module = {
[137]     NGX_MODULE_V1,
[138]     &ngx_http_autoindex_module_ctx,        /* module context */
[139]     ngx_http_autoindex_commands,           /* module directives */
[140]     NGX_HTTP_MODULE,                       /* module type */
[141]     NULL,                                  /* init master */
[142]     NULL,                                  /* init module */
[143]     NULL,                                  /* init process */
[144]     NULL,                                  /* init thread */
[145]     NULL,                                  /* exit thread */
[146]     NULL,                                  /* exit process */
[147]     NULL,                                  /* exit master */
[148]     NGX_MODULE_V1_PADDING
[149] };
[150] 
[151] 
[152] static ngx_int_t
[153] ngx_http_autoindex_handler(ngx_http_request_t *r)
[154] {
[155]     u_char                         *last, *filename;
[156]     size_t                          len, allocated, root;
[157]     ngx_err_t                       err;
[158]     ngx_buf_t                      *b;
[159]     ngx_int_t                       rc;
[160]     ngx_str_t                       path, callback;
[161]     ngx_dir_t                       dir;
[162]     ngx_uint_t                      level, format;
[163]     ngx_pool_t                     *pool;
[164]     ngx_chain_t                     out;
[165]     ngx_array_t                     entries;
[166]     ngx_http_autoindex_entry_t     *entry;
[167]     ngx_http_autoindex_loc_conf_t  *alcf;
[168] 
[169]     if (r->uri.data[r->uri.len - 1] != '/') {
[170]         return NGX_DECLINED;
[171]     }
[172] 
[173]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[174]         return NGX_DECLINED;
[175]     }
[176] 
[177]     alcf = ngx_http_get_module_loc_conf(r, ngx_http_autoindex_module);
[178] 
[179]     if (!alcf->enable) {
[180]         return NGX_DECLINED;
[181]     }
[182] 
[183]     rc = ngx_http_discard_request_body(r);
[184] 
[185]     if (rc != NGX_OK) {
[186]         return rc;
[187]     }
[188] 
[189]     last = ngx_http_map_uri_to_path(r, &path, &root,
[190]                                     NGX_HTTP_AUTOINDEX_PREALLOCATE);
[191]     if (last == NULL) {
[192]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[193]     }
[194] 
[195]     allocated = path.len;
[196]     path.len = last - path.data;
[197]     if (path.len > 1) {
[198]         path.len--;
[199]     }
[200]     path.data[path.len] = '\0';
[201] 
[202]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[203]                    "http autoindex: \"%s\"", path.data);
[204] 
[205]     format = alcf->format;
[206] 
[207]     if (format == NGX_HTTP_AUTOINDEX_JSONP) {
[208]         if (ngx_http_autoindex_jsonp_callback(r, &callback) != NGX_OK) {
[209]             return NGX_HTTP_BAD_REQUEST;
[210]         }
[211] 
[212]         if (callback.len == 0) {
[213]             format = NGX_HTTP_AUTOINDEX_JSON;
[214]         }
[215]     }
[216] 
[217]     if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
[218]         err = ngx_errno;
[219] 
[220]         if (err == NGX_ENOENT
[221]             || err == NGX_ENOTDIR
[222]             || err == NGX_ENAMETOOLONG)
[223]         {
[224]             level = NGX_LOG_ERR;
[225]             rc = NGX_HTTP_NOT_FOUND;
[226] 
[227]         } else if (err == NGX_EACCES) {
[228]             level = NGX_LOG_ERR;
[229]             rc = NGX_HTTP_FORBIDDEN;
[230] 
[231]         } else {
[232]             level = NGX_LOG_CRIT;
[233]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[234]         }
[235] 
[236]         ngx_log_error(level, r->connection->log, err,
[237]                       ngx_open_dir_n " \"%s\" failed", path.data);
[238] 
[239]         return rc;
[240]     }
[241] 
[242] #if (NGX_SUPPRESS_WARN)
[243] 
[244]     /* MSVC thinks 'entries' may be used without having been initialized */
[245]     ngx_memzero(&entries, sizeof(ngx_array_t));
[246] 
[247] #endif
[248] 
[249]     /* TODO: pool should be temporary pool */
[250]     pool = r->pool;
[251] 
[252]     if (ngx_array_init(&entries, pool, 40, sizeof(ngx_http_autoindex_entry_t))
[253]         != NGX_OK)
[254]     {
[255]         return ngx_http_autoindex_error(r, &dir, &path);
[256]     }
[257] 
[258]     r->headers_out.status = NGX_HTTP_OK;
[259] 
[260]     switch (format) {
[261] 
[262]     case NGX_HTTP_AUTOINDEX_JSON:
[263]         ngx_str_set(&r->headers_out.content_type, "application/json");
[264]         break;
[265] 
[266]     case NGX_HTTP_AUTOINDEX_JSONP:
[267]         ngx_str_set(&r->headers_out.content_type, "application/javascript");
[268]         break;
[269] 
[270]     case NGX_HTTP_AUTOINDEX_XML:
[271]         ngx_str_set(&r->headers_out.content_type, "text/xml");
[272]         ngx_str_set(&r->headers_out.charset, "utf-8");
[273]         break;
[274] 
[275]     default: /* NGX_HTTP_AUTOINDEX_HTML */
[276]         ngx_str_set(&r->headers_out.content_type, "text/html");
[277]         break;
[278]     }
[279] 
[280]     r->headers_out.content_type_len = r->headers_out.content_type.len;
[281]     r->headers_out.content_type_lowcase = NULL;
[282] 
[283]     rc = ngx_http_send_header(r);
[284] 
[285]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[286]         if (ngx_close_dir(&dir) == NGX_ERROR) {
[287]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[288]                           ngx_close_dir_n " \"%V\" failed", &path);
[289]         }
[290] 
[291]         return rc;
[292]     }
[293] 
[294]     filename = path.data;
[295]     filename[path.len] = '/';
[296] 
[297]     for ( ;; ) {
[298]         ngx_set_errno(0);
[299] 
[300]         if (ngx_read_dir(&dir) == NGX_ERROR) {
[301]             err = ngx_errno;
[302] 
[303]             if (err != NGX_ENOMOREFILES) {
[304]                 ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
[305]                               ngx_read_dir_n " \"%V\" failed", &path);
[306]                 return ngx_http_autoindex_error(r, &dir, &path);
[307]             }
[308] 
[309]             break;
[310]         }
[311] 
[312]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[313]                        "http autoindex file: \"%s\"", ngx_de_name(&dir));
[314] 
[315]         len = ngx_de_namelen(&dir);
[316] 
[317]         if (ngx_de_name(&dir)[0] == '.') {
[318]             continue;
[319]         }
[320] 
[321]         if (!dir.valid_info) {
[322] 
[323]             /* 1 byte for '/' and 1 byte for terminating '\0' */
[324] 
[325]             if (path.len + 1 + len + 1 > allocated) {
[326]                 allocated = path.len + 1 + len + 1
[327]                                      + NGX_HTTP_AUTOINDEX_PREALLOCATE;
[328] 
[329]                 filename = ngx_pnalloc(pool, allocated);
[330]                 if (filename == NULL) {
[331]                     return ngx_http_autoindex_error(r, &dir, &path);
[332]                 }
[333] 
[334]                 last = ngx_cpystrn(filename, path.data, path.len + 1);
[335]                 *last++ = '/';
[336]             }
[337] 
[338]             ngx_cpystrn(last, ngx_de_name(&dir), len + 1);
[339] 
[340]             if (ngx_de_info(filename, &dir) == NGX_FILE_ERROR) {
[341]                 err = ngx_errno;
[342] 
[343]                 if (err != NGX_ENOENT && err != NGX_ELOOP) {
[344]                     ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
[345]                                   ngx_de_info_n " \"%s\" failed", filename);
[346] 
[347]                     if (err == NGX_EACCES) {
[348]                         continue;
[349]                     }
[350] 
[351]                     return ngx_http_autoindex_error(r, &dir, &path);
[352]                 }
[353] 
[354]                 if (ngx_de_link_info(filename, &dir) == NGX_FILE_ERROR) {
[355]                     ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[356]                                   ngx_de_link_info_n " \"%s\" failed",
[357]                                   filename);
[358]                     return ngx_http_autoindex_error(r, &dir, &path);
[359]                 }
[360]             }
[361]         }
[362] 
[363]         entry = ngx_array_push(&entries);
[364]         if (entry == NULL) {
[365]             return ngx_http_autoindex_error(r, &dir, &path);
[366]         }
[367] 
[368]         entry->name.len = len;
[369] 
[370]         entry->name.data = ngx_pnalloc(pool, len + 1);
[371]         if (entry->name.data == NULL) {
[372]             return ngx_http_autoindex_error(r, &dir, &path);
[373]         }
[374] 
[375]         ngx_cpystrn(entry->name.data, ngx_de_name(&dir), len + 1);
[376] 
[377]         entry->dir = ngx_de_is_dir(&dir);
[378]         entry->file = ngx_de_is_file(&dir);
[379]         entry->mtime = ngx_de_mtime(&dir);
[380]         entry->size = ngx_de_size(&dir);
[381]     }
[382] 
[383]     if (ngx_close_dir(&dir) == NGX_ERROR) {
[384]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[385]                       ngx_close_dir_n " \"%V\" failed", &path);
[386]     }
[387] 
[388]     if (entries.nelts > 1) {
[389]         ngx_qsort(entries.elts, (size_t) entries.nelts,
[390]                   sizeof(ngx_http_autoindex_entry_t),
[391]                   ngx_http_autoindex_cmp_entries);
[392]     }
[393] 
[394]     switch (format) {
[395] 
[396]     case NGX_HTTP_AUTOINDEX_JSON:
[397]         b = ngx_http_autoindex_json(r, &entries, NULL);
[398]         break;
[399] 
[400]     case NGX_HTTP_AUTOINDEX_JSONP:
[401]         b = ngx_http_autoindex_json(r, &entries, &callback);
[402]         break;
[403] 
[404]     case NGX_HTTP_AUTOINDEX_XML:
[405]         b = ngx_http_autoindex_xml(r, &entries);
[406]         break;
[407] 
[408]     default: /* NGX_HTTP_AUTOINDEX_HTML */
[409]         b = ngx_http_autoindex_html(r, &entries);
[410]         break;
[411]     }
[412] 
[413]     if (b == NULL) {
[414]         return NGX_ERROR;
[415]     }
[416] 
[417]     /* TODO: free temporary pool */
[418] 
[419]     if (r == r->main) {
[420]         b->last_buf = 1;
[421]     }
[422] 
[423]     b->last_in_chain = 1;
[424] 
[425]     out.buf = b;
[426]     out.next = NULL;
[427] 
[428]     return ngx_http_output_filter(r, &out);
[429] }
[430] 
[431] 
[432] static ngx_buf_t *
[433] ngx_http_autoindex_html(ngx_http_request_t *r, ngx_array_t *entries)
[434] {
[435]     u_char                         *last, scale;
[436]     off_t                           length;
[437]     size_t                          len, entry_len, char_len, escape_html;
[438]     ngx_tm_t                        tm;
[439]     ngx_buf_t                      *b;
[440]     ngx_int_t                       size;
[441]     ngx_uint_t                      i, utf8;
[442]     ngx_time_t                     *tp;
[443]     ngx_http_autoindex_entry_t     *entry;
[444]     ngx_http_autoindex_loc_conf_t  *alcf;
[445] 
[446]     static u_char  title[] =
[447]         "<html>" CRLF
[448]         "<head><title>Index of "
[449]     ;
[450] 
[451]     static u_char  header[] =
[452]         "</title></head>" CRLF
[453]         "<body>" CRLF
[454]         "<h1>Index of "
[455]     ;
[456] 
[457]     static u_char  tail[] =
[458]         "</body>" CRLF
[459]         "</html>" CRLF
[460]     ;
[461] 
[462]     static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
[463]                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
[464] 
[465]     if (r->headers_out.charset.len == 5
[466]         && ngx_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)
[467]            == 0)
[468]     {
[469]         utf8 = 1;
[470] 
[471]     } else {
[472]         utf8 = 0;
[473]     }
[474] 
[475]     escape_html = ngx_escape_html(NULL, r->uri.data, r->uri.len);
[476] 
[477]     len = sizeof(title) - 1
[478]           + r->uri.len + escape_html
[479]           + sizeof(header) - 1
[480]           + r->uri.len + escape_html
[481]           + sizeof("</h1>") - 1
[482]           + sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1
[483]           + sizeof("</pre><hr>") - 1
[484]           + sizeof(tail) - 1;
[485] 
[486]     entry = entries->elts;
[487]     for (i = 0; i < entries->nelts; i++) {
[488]         entry[i].escape = 2 * ngx_escape_uri(NULL, entry[i].name.data,
[489]                                              entry[i].name.len,
[490]                                              NGX_ESCAPE_URI_COMPONENT);
[491] 
[492]         entry[i].escape_html = ngx_escape_html(NULL, entry[i].name.data,
[493]                                                entry[i].name.len);
[494] 
[495]         if (utf8) {
[496]             entry[i].utf_len = ngx_utf8_length(entry[i].name.data,
[497]                                                entry[i].name.len);
[498]         } else {
[499]             entry[i].utf_len = entry[i].name.len;
[500]         }
[501] 
[502]         entry_len = sizeof("<a href=\"") - 1
[503]                   + entry[i].name.len + entry[i].escape
[504]                   + 1                                    /* 1 is for "/" */
[505]                   + sizeof("\">") - 1
[506]                   + entry[i].name.len - entry[i].utf_len
[507]                   + entry[i].escape_html
[508]                   + NGX_HTTP_AUTOINDEX_NAME_LEN + sizeof("&gt;") - 2
[509]                   + sizeof("</a>") - 1
[510]                   + sizeof(" 28-Sep-1970 12:00 ") - 1
[511]                   + 20                                   /* the file size */
[512]                   + 2;
[513] 
[514]         if (len > NGX_MAX_SIZE_T_VALUE - entry_len) {
[515]             return NULL;
[516]         }
[517] 
[518]         len += entry_len;
[519]     }
[520] 
[521]     b = ngx_create_temp_buf(r->pool, len);
[522]     if (b == NULL) {
[523]         return NULL;
[524]     }
[525] 
[526]     b->last = ngx_cpymem(b->last, title, sizeof(title) - 1);
[527] 
[528]     if (escape_html) {
[529]         b->last = (u_char *) ngx_escape_html(b->last, r->uri.data, r->uri.len);
[530]         b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
[531]         b->last = (u_char *) ngx_escape_html(b->last, r->uri.data, r->uri.len);
[532] 
[533]     } else {
[534]         b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
[535]         b->last = ngx_cpymem(b->last, header, sizeof(header) - 1);
[536]         b->last = ngx_cpymem(b->last, r->uri.data, r->uri.len);
[537]     }
[538] 
[539]     b->last = ngx_cpymem(b->last, "</h1>", sizeof("</h1>") - 1);
[540] 
[541]     b->last = ngx_cpymem(b->last, "<hr><pre><a href=\"../\">../</a>" CRLF,
[542]                          sizeof("<hr><pre><a href=\"../\">../</a>" CRLF) - 1);
[543] 
[544]     alcf = ngx_http_get_module_loc_conf(r, ngx_http_autoindex_module);
[545]     tp = ngx_timeofday();
[546] 
[547]     for (i = 0; i < entries->nelts; i++) {
[548]         b->last = ngx_cpymem(b->last, "<a href=\"", sizeof("<a href=\"") - 1);
[549] 
[550]         if (entry[i].escape) {
[551]             ngx_escape_uri(b->last, entry[i].name.data, entry[i].name.len,
[552]                            NGX_ESCAPE_URI_COMPONENT);
[553] 
[554]             b->last += entry[i].name.len + entry[i].escape;
[555] 
[556]         } else {
[557]             b->last = ngx_cpymem(b->last, entry[i].name.data,
[558]                                  entry[i].name.len);
[559]         }
[560] 
[561]         if (entry[i].dir) {
[562]             *b->last++ = '/';
[563]         }
[564] 
[565]         *b->last++ = '"';
[566]         *b->last++ = '>';
[567] 
[568]         len = entry[i].utf_len;
[569] 
[570]         if (entry[i].name.len != len) {
[571]             if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
[572]                 char_len = NGX_HTTP_AUTOINDEX_NAME_LEN - 3 + 1;
[573] 
[574]             } else {
[575]                 char_len = NGX_HTTP_AUTOINDEX_NAME_LEN + 1;
[576]             }
[577] 
[578]             last = b->last;
[579]             b->last = ngx_utf8_cpystrn(b->last, entry[i].name.data,
[580]                                        char_len, entry[i].name.len + 1);
[581] 
[582]             if (entry[i].escape_html) {
[583]                 b->last = (u_char *) ngx_escape_html(last, entry[i].name.data,
[584]                                                      b->last - last);
[585]             }
[586] 
[587]             last = b->last;
[588] 
[589]         } else {
[590]             if (entry[i].escape_html) {
[591]                 if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
[592]                     char_len = NGX_HTTP_AUTOINDEX_NAME_LEN - 3;
[593] 
[594]                 } else {
[595]                     char_len = len;
[596]                 }
[597] 
[598]                 b->last = (u_char *) ngx_escape_html(b->last,
[599]                                                   entry[i].name.data, char_len);
[600]                 last = b->last;
[601] 
[602]             } else {
[603]                 b->last = ngx_cpystrn(b->last, entry[i].name.data,
[604]                                       NGX_HTTP_AUTOINDEX_NAME_LEN + 1);
[605]                 last = b->last - 3;
[606]             }
[607]         }
[608] 
[609]         if (len > NGX_HTTP_AUTOINDEX_NAME_LEN) {
[610]             b->last = ngx_cpymem(last, "..&gt;</a>", sizeof("..&gt;</a>") - 1);
[611] 
[612]         } else {
[613]             if (entry[i].dir && NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
[614]                 *b->last++ = '/';
[615]                 len++;
[616]             }
[617] 
[618]             b->last = ngx_cpymem(b->last, "</a>", sizeof("</a>") - 1);
[619] 
[620]             if (NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0) {
[621]                 ngx_memset(b->last, ' ', NGX_HTTP_AUTOINDEX_NAME_LEN - len);
[622]                 b->last += NGX_HTTP_AUTOINDEX_NAME_LEN - len;
[623]             }
[624]         }
[625] 
[626]         *b->last++ = ' ';
[627] 
[628]         ngx_gmtime(entry[i].mtime + tp->gmtoff * 60 * alcf->localtime, &tm);
[629] 
[630]         b->last = ngx_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
[631]                               tm.ngx_tm_mday,
[632]                               months[tm.ngx_tm_mon - 1],
[633]                               tm.ngx_tm_year,
[634]                               tm.ngx_tm_hour,
[635]                               tm.ngx_tm_min);
[636] 
[637]         if (alcf->exact_size) {
[638]             if (entry[i].dir) {
[639]                 b->last = ngx_cpymem(b->last,  "                  -",
[640]                                      sizeof("                  -") - 1);
[641]             } else {
[642]                 b->last = ngx_sprintf(b->last, "%19O", entry[i].size);
[643]             }
[644] 
[645]         } else {
[646]             if (entry[i].dir) {
[647]                 b->last = ngx_cpymem(b->last,  "      -",
[648]                                      sizeof("      -") - 1);
[649] 
[650]             } else {
[651]                 length = entry[i].size;
[652] 
[653]                 if (length > 1024 * 1024 * 1024 - 1) {
[654]                     size = (ngx_int_t) (length / (1024 * 1024 * 1024));
[655]                     if ((length % (1024 * 1024 * 1024))
[656]                                                 > (1024 * 1024 * 1024 / 2 - 1))
[657]                     {
[658]                         size++;
[659]                     }
[660]                     scale = 'G';
[661] 
[662]                 } else if (length > 1024 * 1024 - 1) {
[663]                     size = (ngx_int_t) (length / (1024 * 1024));
[664]                     if ((length % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
[665]                         size++;
[666]                     }
[667]                     scale = 'M';
[668] 
[669]                 } else if (length > 9999) {
[670]                     size = (ngx_int_t) (length / 1024);
[671]                     if (length % 1024 > 511) {
[672]                         size++;
[673]                     }
[674]                     scale = 'K';
[675] 
[676]                 } else {
[677]                     size = (ngx_int_t) length;
[678]                     scale = '\0';
[679]                 }
[680] 
[681]                 if (scale) {
[682]                     b->last = ngx_sprintf(b->last, "%6i%c", size, scale);
[683] 
[684]                 } else {
[685]                     b->last = ngx_sprintf(b->last, " %6i", size);
[686]                 }
[687]             }
[688]         }
[689] 
[690]         *b->last++ = CR;
[691]         *b->last++ = LF;
[692]     }
[693] 
[694]     b->last = ngx_cpymem(b->last, "</pre><hr>", sizeof("</pre><hr>") - 1);
[695] 
[696]     b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);
[697] 
[698]     return b;
[699] }
[700] 
[701] 
[702] static ngx_buf_t *
[703] ngx_http_autoindex_json(ngx_http_request_t *r, ngx_array_t *entries,
[704]     ngx_str_t *callback)
[705] {
[706]     size_t                       len, entry_len;
[707]     ngx_buf_t                   *b;
[708]     ngx_uint_t                   i;
[709]     ngx_http_autoindex_entry_t  *entry;
[710] 
[711]     len = sizeof("[" CRLF CRLF "]") - 1;
[712] 
[713]     if (callback) {
[714]         len += sizeof("/* callback */" CRLF "();") - 1 + callback->len;
[715]     }
[716] 
[717]     entry = entries->elts;
[718] 
[719]     for (i = 0; i < entries->nelts; i++) {
[720]         entry[i].escape = ngx_escape_json(NULL, entry[i].name.data,
[721]                                           entry[i].name.len);
[722] 
[723]         entry_len = sizeof("{  }," CRLF) - 1
[724]                   + sizeof("\"name\":\"\"") - 1
[725]                   + entry[i].name.len + entry[i].escape
[726]                   + sizeof(", \"type\":\"directory\"") - 1
[727]                   + sizeof(", \"mtime\":\"Wed, 31 Dec 1986 10:00:00 GMT\"") - 1;
[728] 
[729]         if (entry[i].file) {
[730]             entry_len += sizeof(", \"size\":") - 1 + NGX_OFF_T_LEN;
[731]         }
[732] 
[733]         if (len > NGX_MAX_SIZE_T_VALUE - entry_len) {
[734]             return NULL;
[735]         }
[736] 
[737]         len += entry_len;
[738]     }
[739] 
[740]     b = ngx_create_temp_buf(r->pool, len);
[741]     if (b == NULL) {
[742]         return NULL;
[743]     }
[744] 
[745]     if (callback) {
[746]         b->last = ngx_cpymem(b->last, "/* callback */" CRLF,
[747]                              sizeof("/* callback */" CRLF) - 1);
[748] 
[749]         b->last = ngx_cpymem(b->last, callback->data, callback->len);
[750] 
[751]         *b->last++ = '(';
[752]     }
[753] 
[754]     *b->last++ = '[';
[755] 
[756]     for (i = 0; i < entries->nelts; i++) {
[757]         b->last = ngx_cpymem(b->last, CRLF "{ \"name\":\"",
[758]                              sizeof(CRLF "{ \"name\":\"") - 1);
[759] 
[760]         if (entry[i].escape) {
[761]             b->last = (u_char *) ngx_escape_json(b->last, entry[i].name.data,
[762]                                                  entry[i].name.len);
[763]         } else {
[764]             b->last = ngx_cpymem(b->last, entry[i].name.data,
[765]                                  entry[i].name.len);
[766]         }
[767] 
[768]         b->last = ngx_cpymem(b->last, "\", \"type\":\"",
[769]                              sizeof("\", \"type\":\"") - 1);
[770] 
[771]         if (entry[i].dir) {
[772]             b->last = ngx_cpymem(b->last, "directory", sizeof("directory") - 1);
[773] 
[774]         } else if (entry[i].file) {
[775]             b->last = ngx_cpymem(b->last, "file", sizeof("file") - 1);
[776] 
[777]         } else {
[778]             b->last = ngx_cpymem(b->last, "other", sizeof("other") - 1);
[779]         }
[780] 
[781]         b->last = ngx_cpymem(b->last, "\", \"mtime\":\"",
[782]                              sizeof("\", \"mtime\":\"") - 1);
[783] 
[784]         b->last = ngx_http_time(b->last, entry[i].mtime);
[785] 
[786]         if (entry[i].file) {
[787]             b->last = ngx_cpymem(b->last, "\", \"size\":",
[788]                                  sizeof("\", \"size\":") - 1);
[789]             b->last = ngx_sprintf(b->last, "%O", entry[i].size);
[790] 
[791]         } else {
[792]             *b->last++ = '"';
[793]         }
[794] 
[795]         b->last = ngx_cpymem(b->last, " },", sizeof(" },") - 1);
[796]     }
[797] 
[798]     if (i > 0) {
[799]         b->last--;  /* strip last comma */
[800]     }
[801] 
[802]     b->last = ngx_cpymem(b->last, CRLF "]", sizeof(CRLF "]") - 1);
[803] 
[804]     if (callback) {
[805]         *b->last++ = ')'; *b->last++ = ';';
[806]     }
[807] 
[808]     return b;
[809] }
[810] 
[811] 
[812] static ngx_int_t
[813] ngx_http_autoindex_jsonp_callback(ngx_http_request_t *r, ngx_str_t *callback)
[814] {
[815]     u_char      *p, c, ch;
[816]     ngx_uint_t   i;
[817] 
[818]     if (ngx_http_arg(r, (u_char *) "callback", 8, callback) != NGX_OK) {
[819]         callback->len = 0;
[820]         return NGX_OK;
[821]     }
[822] 
[823]     if (callback->len > 128) {
[824]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[825]                       "client sent too long callback name: \"%V\"", callback);
[826]         return NGX_DECLINED;
[827]     }
[828] 
[829]     p = callback->data;
[830] 
[831]     for (i = 0; i < callback->len; i++) {
[832]         ch = p[i];
[833] 
[834]         c = (u_char) (ch | 0x20);
[835]         if (c >= 'a' && c <= 'z') {
[836]             continue;
[837]         }
[838] 
[839]         if ((ch >= '0' && ch <= '9') || ch == '_' || ch == '.') {
[840]             continue;
[841]         }
[842] 
[843]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[844]                       "client sent invalid callback name: \"%V\"", callback);
[845] 
[846]         return NGX_DECLINED;
[847]     }
[848] 
[849]     return NGX_OK;
[850] }
[851] 
[852] 
[853] static ngx_buf_t *
[854] ngx_http_autoindex_xml(ngx_http_request_t *r, ngx_array_t *entries)
[855] {
[856]     size_t                          len, entry_len;
[857]     ngx_tm_t                        tm;
[858]     ngx_buf_t                      *b;
[859]     ngx_str_t                       type;
[860]     ngx_uint_t                      i;
[861]     ngx_http_autoindex_entry_t     *entry;
[862] 
[863]     static u_char  head[] = "<?xml version=\"1.0\"?>" CRLF "<list>" CRLF;
[864]     static u_char  tail[] = "</list>" CRLF;
[865] 
[866]     len = sizeof(head) - 1 + sizeof(tail) - 1;
[867] 
[868]     entry = entries->elts;
[869] 
[870]     for (i = 0; i < entries->nelts; i++) {
[871]         entry[i].escape = ngx_escape_html(NULL, entry[i].name.data,
[872]                                           entry[i].name.len);
[873] 
[874]         entry_len = sizeof("<directory></directory>" CRLF) - 1
[875]                   + entry[i].name.len + entry[i].escape
[876]                   + sizeof(" mtime=\"1986-12-31T10:00:00Z\"") - 1;
[877] 
[878]         if (entry[i].file) {
[879]             entry_len += sizeof(" size=\"\"") - 1 + NGX_OFF_T_LEN;
[880]         }
[881] 
[882]         if (len > NGX_MAX_SIZE_T_VALUE - entry_len) {
[883]             return NULL;
[884]         }
[885] 
[886]         len += entry_len;
[887]     }
[888] 
[889]     b = ngx_create_temp_buf(r->pool, len);
[890]     if (b == NULL) {
[891]         return NULL;
[892]     }
[893] 
[894]     b->last = ngx_cpymem(b->last, head, sizeof(head) - 1);
[895] 
[896]     for (i = 0; i < entries->nelts; i++) {
[897]         *b->last++ = '<';
[898] 
[899]         if (entry[i].dir) {
[900]             ngx_str_set(&type, "directory");
[901] 
[902]         } else if (entry[i].file) {
[903]             ngx_str_set(&type, "file");
[904] 
[905]         } else {
[906]             ngx_str_set(&type, "other");
[907]         }
[908] 
[909]         b->last = ngx_cpymem(b->last, type.data, type.len);
[910] 
[911]         b->last = ngx_cpymem(b->last, " mtime=\"", sizeof(" mtime=\"") - 1);
[912] 
[913]         ngx_gmtime(entry[i].mtime, &tm);
[914] 
[915]         b->last = ngx_sprintf(b->last, "%4d-%02d-%02dT%02d:%02d:%02dZ",
[916]                               tm.ngx_tm_year, tm.ngx_tm_mon,
[917]                               tm.ngx_tm_mday, tm.ngx_tm_hour,
[918]                               tm.ngx_tm_min, tm.ngx_tm_sec);
[919] 
[920]         if (entry[i].file) {
[921]             b->last = ngx_cpymem(b->last, "\" size=\"",
[922]                                  sizeof("\" size=\"") - 1);
[923]             b->last = ngx_sprintf(b->last, "%O", entry[i].size);
[924]         }
[925] 
[926]         *b->last++ = '"'; *b->last++ = '>';
[927] 
[928]         if (entry[i].escape) {
[929]             b->last = (u_char *) ngx_escape_html(b->last, entry[i].name.data,
[930]                                                  entry[i].name.len);
[931]         } else {
[932]             b->last = ngx_cpymem(b->last, entry[i].name.data,
[933]                                  entry[i].name.len);
[934]         }
[935] 
[936]         *b->last++ = '<'; *b->last++ = '/';
[937] 
[938]         b->last = ngx_cpymem(b->last, type.data, type.len);
[939] 
[940]         *b->last++ = '>';
[941] 
[942]         *b->last++ = CR; *b->last++ = LF;
[943]     }
[944] 
[945]     b->last = ngx_cpymem(b->last, tail, sizeof(tail) - 1);
[946] 
[947]     return b;
[948] }
[949] 
[950] 
[951] static int ngx_libc_cdecl
[952] ngx_http_autoindex_cmp_entries(const void *one, const void *two)
[953] {
[954]     ngx_http_autoindex_entry_t *first = (ngx_http_autoindex_entry_t *) one;
[955]     ngx_http_autoindex_entry_t *second = (ngx_http_autoindex_entry_t *) two;
[956] 
[957]     if (first->dir && !second->dir) {
[958]         /* move the directories to the start */
[959]         return -1;
[960]     }
[961] 
[962]     if (!first->dir && second->dir) {
[963]         /* move the directories to the start */
[964]         return 1;
[965]     }
[966] 
[967]     return (int) ngx_strcmp(first->name.data, second->name.data);
[968] }
[969] 
[970] 
[971] #if 0
[972] 
[973] static ngx_buf_t *
[974] ngx_http_autoindex_alloc(ngx_http_autoindex_ctx_t *ctx, size_t size)
[975] {
[976]     ngx_chain_t  *cl;
[977] 
[978]     if (ctx->buf) {
[979] 
[980]         if ((size_t) (ctx->buf->end - ctx->buf->last) >= size) {
[981]             return ctx->buf;
[982]         }
[983] 
[984]         ctx->size += ctx->buf->last - ctx->buf->pos;
[985]     }
[986] 
[987]     ctx->buf = ngx_create_temp_buf(ctx->pool, ctx->alloc_size);
[988]     if (ctx->buf == NULL) {
[989]         return NULL;
[990]     }
[991] 
[992]     cl = ngx_alloc_chain_link(ctx->pool);
[993]     if (cl == NULL) {
[994]         return NULL;
[995]     }
[996] 
[997]     cl->buf = ctx->buf;
[998]     cl->next = NULL;
[999] 
[1000]     *ctx->last_out = cl;
[1001]     ctx->last_out = &cl->next;
[1002] 
[1003]     return ctx->buf;
[1004] }
[1005] 
[1006] #endif
[1007] 
[1008] 
[1009] static ngx_int_t
[1010] ngx_http_autoindex_error(ngx_http_request_t *r, ngx_dir_t *dir, ngx_str_t *name)
[1011] {
[1012]     if (ngx_close_dir(dir) == NGX_ERROR) {
[1013]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[1014]                       ngx_close_dir_n " \"%V\" failed", name);
[1015]     }
[1016] 
[1017]     return r->header_sent ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR;
[1018] }
[1019] 
[1020] 
[1021] static void *
[1022] ngx_http_autoindex_create_loc_conf(ngx_conf_t *cf)
[1023] {
[1024]     ngx_http_autoindex_loc_conf_t  *conf;
[1025] 
[1026]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_autoindex_loc_conf_t));
[1027]     if (conf == NULL) {
[1028]         return NULL;
[1029]     }
[1030] 
[1031]     conf->enable = NGX_CONF_UNSET;
[1032]     conf->format = NGX_CONF_UNSET_UINT;
[1033]     conf->localtime = NGX_CONF_UNSET;
[1034]     conf->exact_size = NGX_CONF_UNSET;
[1035] 
[1036]     return conf;
[1037] }
[1038] 
[1039] 
[1040] static char *
[1041] ngx_http_autoindex_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[1042] {
[1043]     ngx_http_autoindex_loc_conf_t *prev = parent;
[1044]     ngx_http_autoindex_loc_conf_t *conf = child;
[1045] 
[1046]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[1047]     ngx_conf_merge_uint_value(conf->format, prev->format,
[1048]                               NGX_HTTP_AUTOINDEX_HTML);
[1049]     ngx_conf_merge_value(conf->localtime, prev->localtime, 0);
[1050]     ngx_conf_merge_value(conf->exact_size, prev->exact_size, 1);
[1051] 
[1052]     return NGX_CONF_OK;
[1053] }
[1054] 
[1055] 
[1056] static ngx_int_t
[1057] ngx_http_autoindex_init(ngx_conf_t *cf)
[1058] {
[1059]     ngx_http_handler_pt        *h;
[1060]     ngx_http_core_main_conf_t  *cmcf;
[1061] 
[1062]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[1063] 
[1064]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
[1065]     if (h == NULL) {
[1066]         return NGX_ERROR;
[1067]     }
[1068] 
[1069]     *h = ngx_http_autoindex_handler;
[1070] 
[1071]     return NGX_OK;
[1072] }
