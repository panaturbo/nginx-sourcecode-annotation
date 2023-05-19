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
[11] #include <nginx.h>
[12] 
[13] 
[14] static ngx_int_t ngx_http_header_filter_init(ngx_conf_t *cf);
[15] static ngx_int_t ngx_http_header_filter(ngx_http_request_t *r);
[16] 
[17] 
[18] static ngx_http_module_t  ngx_http_header_filter_module_ctx = {
[19]     NULL,                                  /* preconfiguration */
[20]     ngx_http_header_filter_init,           /* postconfiguration */
[21] 
[22]     NULL,                                  /* create main configuration */
[23]     NULL,                                  /* init main configuration */
[24] 
[25]     NULL,                                  /* create server configuration */
[26]     NULL,                                  /* merge server configuration */
[27] 
[28]     NULL,                                  /* create location configuration */
[29]     NULL,                                  /* merge location configuration */
[30] };
[31] 
[32] 
[33] ngx_module_t  ngx_http_header_filter_module = {
[34]     NGX_MODULE_V1,
[35]     &ngx_http_header_filter_module_ctx,    /* module context */
[36]     NULL,                                  /* module directives */
[37]     NGX_HTTP_MODULE,                       /* module type */
[38]     NULL,                                  /* init master */
[39]     NULL,                                  /* init module */
[40]     NULL,                                  /* init process */
[41]     NULL,                                  /* init thread */
[42]     NULL,                                  /* exit thread */
[43]     NULL,                                  /* exit process */
[44]     NULL,                                  /* exit master */
[45]     NGX_MODULE_V1_PADDING
[46] };
[47] 
[48] 
[49] static u_char ngx_http_server_string[] = "Server: nginx" CRLF;
[50] static u_char ngx_http_server_full_string[] = "Server: " NGINX_VER CRLF;
[51] static u_char ngx_http_server_build_string[] = "Server: " NGINX_VER_BUILD CRLF;
[52] 
[53] 
[54] static ngx_str_t ngx_http_status_lines[] = {
[55] 
[56]     ngx_string("200 OK"),
[57]     ngx_string("201 Created"),
[58]     ngx_string("202 Accepted"),
[59]     ngx_null_string,  /* "203 Non-Authoritative Information" */
[60]     ngx_string("204 No Content"),
[61]     ngx_null_string,  /* "205 Reset Content" */
[62]     ngx_string("206 Partial Content"),
[63] 
[64]     /* ngx_null_string, */  /* "207 Multi-Status" */
[65] 
[66] #define NGX_HTTP_LAST_2XX  207
[67] #define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)
[68] 
[69]     /* ngx_null_string, */  /* "300 Multiple Choices" */
[70] 
[71]     ngx_string("301 Moved Permanently"),
[72]     ngx_string("302 Moved Temporarily"),
[73]     ngx_string("303 See Other"),
[74]     ngx_string("304 Not Modified"),
[75]     ngx_null_string,  /* "305 Use Proxy" */
[76]     ngx_null_string,  /* "306 unused" */
[77]     ngx_string("307 Temporary Redirect"),
[78]     ngx_string("308 Permanent Redirect"),
[79] 
[80] #define NGX_HTTP_LAST_3XX  309
[81] #define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)
[82] 
[83]     ngx_string("400 Bad Request"),
[84]     ngx_string("401 Unauthorized"),
[85]     ngx_string("402 Payment Required"),
[86]     ngx_string("403 Forbidden"),
[87]     ngx_string("404 Not Found"),
[88]     ngx_string("405 Not Allowed"),
[89]     ngx_string("406 Not Acceptable"),
[90]     ngx_null_string,  /* "407 Proxy Authentication Required" */
[91]     ngx_string("408 Request Time-out"),
[92]     ngx_string("409 Conflict"),
[93]     ngx_string("410 Gone"),
[94]     ngx_string("411 Length Required"),
[95]     ngx_string("412 Precondition Failed"),
[96]     ngx_string("413 Request Entity Too Large"),
[97]     ngx_string("414 Request-URI Too Large"),
[98]     ngx_string("415 Unsupported Media Type"),
[99]     ngx_string("416 Requested Range Not Satisfiable"),
[100]     ngx_null_string,  /* "417 Expectation Failed" */
[101]     ngx_null_string,  /* "418 unused" */
[102]     ngx_null_string,  /* "419 unused" */
[103]     ngx_null_string,  /* "420 unused" */
[104]     ngx_string("421 Misdirected Request"),
[105]     ngx_null_string,  /* "422 Unprocessable Entity" */
[106]     ngx_null_string,  /* "423 Locked" */
[107]     ngx_null_string,  /* "424 Failed Dependency" */
[108]     ngx_null_string,  /* "425 unused" */
[109]     ngx_null_string,  /* "426 Upgrade Required" */
[110]     ngx_null_string,  /* "427 unused" */
[111]     ngx_null_string,  /* "428 Precondition Required" */
[112]     ngx_string("429 Too Many Requests"),
[113] 
[114] #define NGX_HTTP_LAST_4XX  430
[115] #define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)
[116] 
[117]     ngx_string("500 Internal Server Error"),
[118]     ngx_string("501 Not Implemented"),
[119]     ngx_string("502 Bad Gateway"),
[120]     ngx_string("503 Service Temporarily Unavailable"),
[121]     ngx_string("504 Gateway Time-out"),
[122]     ngx_string("505 HTTP Version Not Supported"),
[123]     ngx_null_string,        /* "506 Variant Also Negotiates" */
[124]     ngx_string("507 Insufficient Storage"),
[125] 
[126]     /* ngx_null_string, */  /* "508 unused" */
[127]     /* ngx_null_string, */  /* "509 unused" */
[128]     /* ngx_null_string, */  /* "510 Not Extended" */
[129] 
[130] #define NGX_HTTP_LAST_5XX  508
[131] 
[132] };
[133] 
[134] 
[135] ngx_http_header_out_t  ngx_http_headers_out[] = {
[136]     { ngx_string("Server"), offsetof(ngx_http_headers_out_t, server) },
[137]     { ngx_string("Date"), offsetof(ngx_http_headers_out_t, date) },
[138]     { ngx_string("Content-Length"),
[139]                  offsetof(ngx_http_headers_out_t, content_length) },
[140]     { ngx_string("Content-Encoding"),
[141]                  offsetof(ngx_http_headers_out_t, content_encoding) },
[142]     { ngx_string("Location"), offsetof(ngx_http_headers_out_t, location) },
[143]     { ngx_string("Last-Modified"),
[144]                  offsetof(ngx_http_headers_out_t, last_modified) },
[145]     { ngx_string("Accept-Ranges"),
[146]                  offsetof(ngx_http_headers_out_t, accept_ranges) },
[147]     { ngx_string("Expires"), offsetof(ngx_http_headers_out_t, expires) },
[148]     { ngx_string("Cache-Control"),
[149]                  offsetof(ngx_http_headers_out_t, cache_control) },
[150]     { ngx_string("ETag"), offsetof(ngx_http_headers_out_t, etag) },
[151] 
[152]     { ngx_null_string, 0 }
[153] };
[154] 
[155] 
[156] static ngx_int_t
[157] ngx_http_header_filter(ngx_http_request_t *r)
[158] {
[159]     u_char                    *p;
[160]     size_t                     len;
[161]     ngx_str_t                  host, *status_line;
[162]     ngx_buf_t                 *b;
[163]     ngx_uint_t                 status, i, port;
[164]     ngx_chain_t                out;
[165]     ngx_list_part_t           *part;
[166]     ngx_table_elt_t           *header;
[167]     ngx_connection_t          *c;
[168]     ngx_http_core_loc_conf_t  *clcf;
[169]     ngx_http_core_srv_conf_t  *cscf;
[170]     u_char                     addr[NGX_SOCKADDR_STRLEN];
[171] 
[172]     if (r->header_sent) {
[173]         return NGX_OK;
[174]     }
[175] 
[176]     r->header_sent = 1;
[177] 
[178]     if (r != r->main) {
[179]         return NGX_OK;
[180]     }
[181] 
[182]     if (r->http_version < NGX_HTTP_VERSION_10) {
[183]         return NGX_OK;
[184]     }
[185] 
[186]     if (r->method == NGX_HTTP_HEAD) {
[187]         r->header_only = 1;
[188]     }
[189] 
[190]     if (r->headers_out.last_modified_time != -1) {
[191]         if (r->headers_out.status != NGX_HTTP_OK
[192]             && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
[193]             && r->headers_out.status != NGX_HTTP_NOT_MODIFIED)
[194]         {
[195]             r->headers_out.last_modified_time = -1;
[196]             r->headers_out.last_modified = NULL;
[197]         }
[198]     }
[199] 
[200]     if (r->keepalive && (ngx_terminate || ngx_exiting)) {
[201]         r->keepalive = 0;
[202]     }
[203] 
[204]     len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
[205]           /* the end of the header */
[206]           + sizeof(CRLF) - 1;
[207] 
[208]     /* status line */
[209] 
[210]     if (r->headers_out.status_line.len) {
[211]         len += r->headers_out.status_line.len;
[212]         status_line = &r->headers_out.status_line;
[213] #if (NGX_SUPPRESS_WARN)
[214]         status = 0;
[215] #endif
[216] 
[217]     } else {
[218] 
[219]         status = r->headers_out.status;
[220] 
[221]         if (status >= NGX_HTTP_OK
[222]             && status < NGX_HTTP_LAST_2XX)
[223]         {
[224]             /* 2XX */
[225] 
[226]             if (status == NGX_HTTP_NO_CONTENT) {
[227]                 r->header_only = 1;
[228]                 ngx_str_null(&r->headers_out.content_type);
[229]                 r->headers_out.last_modified_time = -1;
[230]                 r->headers_out.last_modified = NULL;
[231]                 r->headers_out.content_length = NULL;
[232]                 r->headers_out.content_length_n = -1;
[233]             }
[234] 
[235]             status -= NGX_HTTP_OK;
[236]             status_line = &ngx_http_status_lines[status];
[237]             len += ngx_http_status_lines[status].len;
[238] 
[239]         } else if (status >= NGX_HTTP_MOVED_PERMANENTLY
[240]                    && status < NGX_HTTP_LAST_3XX)
[241]         {
[242]             /* 3XX */
[243] 
[244]             if (status == NGX_HTTP_NOT_MODIFIED) {
[245]                 r->header_only = 1;
[246]             }
[247] 
[248]             status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
[249]             status_line = &ngx_http_status_lines[status];
[250]             len += ngx_http_status_lines[status].len;
[251] 
[252]         } else if (status >= NGX_HTTP_BAD_REQUEST
[253]                    && status < NGX_HTTP_LAST_4XX)
[254]         {
[255]             /* 4XX */
[256]             status = status - NGX_HTTP_BAD_REQUEST
[257]                             + NGX_HTTP_OFF_4XX;
[258] 
[259]             status_line = &ngx_http_status_lines[status];
[260]             len += ngx_http_status_lines[status].len;
[261] 
[262]         } else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR
[263]                    && status < NGX_HTTP_LAST_5XX)
[264]         {
[265]             /* 5XX */
[266]             status = status - NGX_HTTP_INTERNAL_SERVER_ERROR
[267]                             + NGX_HTTP_OFF_5XX;
[268] 
[269]             status_line = &ngx_http_status_lines[status];
[270]             len += ngx_http_status_lines[status].len;
[271] 
[272]         } else {
[273]             len += NGX_INT_T_LEN + 1 /* SP */;
[274]             status_line = NULL;
[275]         }
[276] 
[277]         if (status_line && status_line->len == 0) {
[278]             status = r->headers_out.status;
[279]             len += NGX_INT_T_LEN + 1 /* SP */;
[280]             status_line = NULL;
[281]         }
[282]     }
[283] 
[284]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[285] 
[286]     if (r->headers_out.server == NULL) {
[287]         if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
[288]             len += sizeof(ngx_http_server_full_string) - 1;
[289] 
[290]         } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
[291]             len += sizeof(ngx_http_server_build_string) - 1;
[292] 
[293]         } else {
[294]             len += sizeof(ngx_http_server_string) - 1;
[295]         }
[296]     }
[297] 
[298]     if (r->headers_out.date == NULL) {
[299]         len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
[300]     }
[301] 
[302]     if (r->headers_out.content_type.len) {
[303]         len += sizeof("Content-Type: ") - 1
[304]                + r->headers_out.content_type.len + 2;
[305] 
[306]         if (r->headers_out.content_type_len == r->headers_out.content_type.len
[307]             && r->headers_out.charset.len)
[308]         {
[309]             len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
[310]         }
[311]     }
[312] 
[313]     if (r->headers_out.content_length == NULL
[314]         && r->headers_out.content_length_n >= 0)
[315]     {
[316]         len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
[317]     }
[318] 
[319]     if (r->headers_out.last_modified == NULL
[320]         && r->headers_out.last_modified_time != -1)
[321]     {
[322]         len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
[323]     }
[324] 
[325]     c = r->connection;
[326] 
[327]     if (r->headers_out.location
[328]         && r->headers_out.location->value.len
[329]         && r->headers_out.location->value.data[0] == '/'
[330]         && clcf->absolute_redirect)
[331]     {
[332]         r->headers_out.location->hash = 0;
[333] 
[334]         if (clcf->server_name_in_redirect) {
[335]             cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[336]             host = cscf->server_name;
[337] 
[338]         } else if (r->headers_in.server.len) {
[339]             host = r->headers_in.server;
[340] 
[341]         } else {
[342]             host.len = NGX_SOCKADDR_STRLEN;
[343]             host.data = addr;
[344] 
[345]             if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
[346]                 return NGX_ERROR;
[347]             }
[348]         }
[349] 
[350]         port = ngx_inet_get_port(c->local_sockaddr);
[351] 
[352]         len += sizeof("Location: https://") - 1
[353]                + host.len
[354]                + r->headers_out.location->value.len + 2;
[355] 
[356]         if (clcf->port_in_redirect) {
[357] 
[358] #if (NGX_HTTP_SSL)
[359]             if (c->ssl)
[360]                 port = (port == 443) ? 0 : port;
[361]             else
[362] #endif
[363]                 port = (port == 80) ? 0 : port;
[364] 
[365]         } else {
[366]             port = 0;
[367]         }
[368] 
[369]         if (port) {
[370]             len += sizeof(":65535") - 1;
[371]         }
[372] 
[373]     } else {
[374]         ngx_str_null(&host);
[375]         port = 0;
[376]     }
[377] 
[378]     if (r->chunked) {
[379]         len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
[380]     }
[381] 
[382]     if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
[383]         len += sizeof("Connection: upgrade" CRLF) - 1;
[384] 
[385]     } else if (r->keepalive) {
[386]         len += sizeof("Connection: keep-alive" CRLF) - 1;
[387] 
[388]         /*
[389]          * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
[390]          * MSIE keeps the connection alive for about 60-65 seconds.
[391]          * Opera keeps the connection alive very long.
[392]          * Mozilla keeps the connection alive for N plus about 1-10 seconds.
[393]          * Konqueror keeps the connection alive for about N seconds.
[394]          */
[395] 
[396]         if (clcf->keepalive_header) {
[397]             len += sizeof("Keep-Alive: timeout=") - 1 + NGX_TIME_T_LEN + 2;
[398]         }
[399] 
[400]     } else {
[401]         len += sizeof("Connection: close" CRLF) - 1;
[402]     }
[403] 
[404] #if (NGX_HTTP_GZIP)
[405]     if (r->gzip_vary) {
[406]         if (clcf->gzip_vary) {
[407]             len += sizeof("Vary: Accept-Encoding" CRLF) - 1;
[408] 
[409]         } else {
[410]             r->gzip_vary = 0;
[411]         }
[412]     }
[413] #endif
[414] 
[415]     part = &r->headers_out.headers.part;
[416]     header = part->elts;
[417] 
[418]     for (i = 0; /* void */; i++) {
[419] 
[420]         if (i >= part->nelts) {
[421]             if (part->next == NULL) {
[422]                 break;
[423]             }
[424] 
[425]             part = part->next;
[426]             header = part->elts;
[427]             i = 0;
[428]         }
[429] 
[430]         if (header[i].hash == 0) {
[431]             continue;
[432]         }
[433] 
[434]         len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
[435]                + sizeof(CRLF) - 1;
[436]     }
[437] 
[438]     b = ngx_create_temp_buf(r->pool, len);
[439]     if (b == NULL) {
[440]         return NGX_ERROR;
[441]     }
[442] 
[443]     /* "HTTP/1.x " */
[444]     b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);
[445] 
[446]     /* status line */
[447]     if (status_line) {
[448]         b->last = ngx_copy(b->last, status_line->data, status_line->len);
[449] 
[450]     } else {
[451]         b->last = ngx_sprintf(b->last, "%03ui ", status);
[452]     }
[453]     *b->last++ = CR; *b->last++ = LF;
[454] 
[455]     if (r->headers_out.server == NULL) {
[456]         if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
[457]             p = ngx_http_server_full_string;
[458]             len = sizeof(ngx_http_server_full_string) - 1;
[459] 
[460]         } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
[461]             p = ngx_http_server_build_string;
[462]             len = sizeof(ngx_http_server_build_string) - 1;
[463] 
[464]         } else {
[465]             p = ngx_http_server_string;
[466]             len = sizeof(ngx_http_server_string) - 1;
[467]         }
[468] 
[469]         b->last = ngx_cpymem(b->last, p, len);
[470]     }
[471] 
[472]     if (r->headers_out.date == NULL) {
[473]         b->last = ngx_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
[474]         b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
[475]                              ngx_cached_http_time.len);
[476] 
[477]         *b->last++ = CR; *b->last++ = LF;
[478]     }
[479] 
[480]     if (r->headers_out.content_type.len) {
[481]         b->last = ngx_cpymem(b->last, "Content-Type: ",
[482]                              sizeof("Content-Type: ") - 1);
[483]         p = b->last;
[484]         b->last = ngx_copy(b->last, r->headers_out.content_type.data,
[485]                            r->headers_out.content_type.len);
[486] 
[487]         if (r->headers_out.content_type_len == r->headers_out.content_type.len
[488]             && r->headers_out.charset.len)
[489]         {
[490]             b->last = ngx_cpymem(b->last, "; charset=",
[491]                                  sizeof("; charset=") - 1);
[492]             b->last = ngx_copy(b->last, r->headers_out.charset.data,
[493]                                r->headers_out.charset.len);
[494] 
[495]             /* update r->headers_out.content_type for possible logging */
[496] 
[497]             r->headers_out.content_type.len = b->last - p;
[498]             r->headers_out.content_type.data = p;
[499]         }
[500] 
[501]         *b->last++ = CR; *b->last++ = LF;
[502]     }
[503] 
[504]     if (r->headers_out.content_length == NULL
[505]         && r->headers_out.content_length_n >= 0)
[506]     {
[507]         b->last = ngx_sprintf(b->last, "Content-Length: %O" CRLF,
[508]                               r->headers_out.content_length_n);
[509]     }
[510] 
[511]     if (r->headers_out.last_modified == NULL
[512]         && r->headers_out.last_modified_time != -1)
[513]     {
[514]         b->last = ngx_cpymem(b->last, "Last-Modified: ",
[515]                              sizeof("Last-Modified: ") - 1);
[516]         b->last = ngx_http_time(b->last, r->headers_out.last_modified_time);
[517] 
[518]         *b->last++ = CR; *b->last++ = LF;
[519]     }
[520] 
[521]     if (host.data) {
[522] 
[523]         p = b->last + sizeof("Location: ") - 1;
[524] 
[525]         b->last = ngx_cpymem(b->last, "Location: http",
[526]                              sizeof("Location: http") - 1);
[527] 
[528] #if (NGX_HTTP_SSL)
[529]         if (c->ssl) {
[530]             *b->last++ ='s';
[531]         }
[532] #endif
[533] 
[534]         *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';
[535]         b->last = ngx_copy(b->last, host.data, host.len);
[536] 
[537]         if (port) {
[538]             b->last = ngx_sprintf(b->last, ":%ui", port);
[539]         }
[540] 
[541]         b->last = ngx_copy(b->last, r->headers_out.location->value.data,
[542]                            r->headers_out.location->value.len);
[543] 
[544]         /* update r->headers_out.location->value for possible logging */
[545] 
[546]         r->headers_out.location->value.len = b->last - p;
[547]         r->headers_out.location->value.data = p;
[548]         ngx_str_set(&r->headers_out.location->key, "Location");
[549] 
[550]         *b->last++ = CR; *b->last++ = LF;
[551]     }
[552] 
[553]     if (r->chunked) {
[554]         b->last = ngx_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
[555]                              sizeof("Transfer-Encoding: chunked" CRLF) - 1);
[556]     }
[557] 
[558]     if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
[559]         b->last = ngx_cpymem(b->last, "Connection: upgrade" CRLF,
[560]                              sizeof("Connection: upgrade" CRLF) - 1);
[561] 
[562]     } else if (r->keepalive) {
[563]         b->last = ngx_cpymem(b->last, "Connection: keep-alive" CRLF,
[564]                              sizeof("Connection: keep-alive" CRLF) - 1);
[565] 
[566]         if (clcf->keepalive_header) {
[567]             b->last = ngx_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
[568]                                   clcf->keepalive_header);
[569]         }
[570] 
[571]     } else {
[572]         b->last = ngx_cpymem(b->last, "Connection: close" CRLF,
[573]                              sizeof("Connection: close" CRLF) - 1);
[574]     }
[575] 
[576] #if (NGX_HTTP_GZIP)
[577]     if (r->gzip_vary) {
[578]         b->last = ngx_cpymem(b->last, "Vary: Accept-Encoding" CRLF,
[579]                              sizeof("Vary: Accept-Encoding" CRLF) - 1);
[580]     }
[581] #endif
[582] 
[583]     part = &r->headers_out.headers.part;
[584]     header = part->elts;
[585] 
[586]     for (i = 0; /* void */; i++) {
[587] 
[588]         if (i >= part->nelts) {
[589]             if (part->next == NULL) {
[590]                 break;
[591]             }
[592] 
[593]             part = part->next;
[594]             header = part->elts;
[595]             i = 0;
[596]         }
[597] 
[598]         if (header[i].hash == 0) {
[599]             continue;
[600]         }
[601] 
[602]         b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
[603]         *b->last++ = ':'; *b->last++ = ' ';
[604] 
[605]         b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
[606]         *b->last++ = CR; *b->last++ = LF;
[607]     }
[608] 
[609]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[610]                    "%*s", (size_t) (b->last - b->pos), b->pos);
[611] 
[612]     /* the end of HTTP header */
[613]     *b->last++ = CR; *b->last++ = LF;
[614] 
[615]     r->header_size = b->last - b->pos;
[616] 
[617]     if (r->header_only) {
[618]         b->last_buf = 1;
[619]     }
[620] 
[621]     out.buf = b;
[622]     out.next = NULL;
[623] 
[624]     return ngx_http_write_filter(r, &out);
[625] }
[626] 
[627] 
[628] static ngx_int_t
[629] ngx_http_header_filter_init(ngx_conf_t *cf)
[630] {
[631]     ngx_http_top_header_filter = ngx_http_header_filter;
[632] 
[633]     return NGX_OK;
[634] }
