[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  * Copyright (C) Ruslan Ermilov
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_http.h>
[12] #include <nginx.h>
[13] #include <ngx_http_v2_module.h>
[14] 
[15] 
[16] /*
[17]  * This returns precise number of octets for values in range 0..253
[18]  * and estimate number for the rest, but not smaller than required.
[19]  */
[20] 
[21] #define ngx_http_v2_integer_octets(v)  (1 + (v) / 127)
[22] 
[23] #define ngx_http_v2_literal_size(h)                                           \
[24]     (ngx_http_v2_integer_octets(sizeof(h) - 1) + sizeof(h) - 1)
[25] 
[26] 
[27] #define NGX_HTTP_V2_NO_TRAILERS           (ngx_http_v2_out_frame_t *) -1
[28] 
[29] 
[30] typedef struct {
[31]     ngx_str_t      name;
[32]     u_char         index;
[33]     ngx_uint_t     offset;
[34] } ngx_http_v2_push_header_t;
[35] 
[36] 
[37] static ngx_http_v2_push_header_t  ngx_http_v2_push_headers[] = {
[38]     { ngx_string(":authority"), NGX_HTTP_V2_AUTHORITY_INDEX,
[39]       offsetof(ngx_http_headers_in_t, host) },
[40] 
[41]     { ngx_string("accept-encoding"), NGX_HTTP_V2_ACCEPT_ENCODING_INDEX,
[42]       offsetof(ngx_http_headers_in_t, accept_encoding) },
[43] 
[44]     { ngx_string("accept-language"), NGX_HTTP_V2_ACCEPT_LANGUAGE_INDEX,
[45]       offsetof(ngx_http_headers_in_t, accept_language) },
[46] 
[47]     { ngx_string("user-agent"), NGX_HTTP_V2_USER_AGENT_INDEX,
[48]       offsetof(ngx_http_headers_in_t, user_agent) },
[49] };
[50] 
[51] #define NGX_HTTP_V2_PUSH_HEADERS                                              \
[52]     (sizeof(ngx_http_v2_push_headers) / sizeof(ngx_http_v2_push_header_t))
[53] 
[54] 
[55] static ngx_int_t ngx_http_v2_push_resources(ngx_http_request_t *r);
[56] static ngx_int_t ngx_http_v2_push_resource(ngx_http_request_t *r,
[57]     ngx_str_t *path, ngx_str_t *binary);
[58] 
[59] static ngx_http_v2_out_frame_t *ngx_http_v2_create_headers_frame(
[60]     ngx_http_request_t *r, u_char *pos, u_char *end, ngx_uint_t fin);
[61] static ngx_http_v2_out_frame_t *ngx_http_v2_create_push_frame(
[62]     ngx_http_request_t *r, u_char *pos, u_char *end);
[63] static ngx_http_v2_out_frame_t *ngx_http_v2_create_trailers_frame(
[64]     ngx_http_request_t *r);
[65] 
[66] static ngx_chain_t *ngx_http_v2_send_chain(ngx_connection_t *fc,
[67]     ngx_chain_t *in, off_t limit);
[68] 
[69] static ngx_chain_t *ngx_http_v2_filter_get_shadow(
[70]     ngx_http_v2_stream_t *stream, ngx_buf_t *buf, off_t offset, off_t size);
[71] static ngx_http_v2_out_frame_t *ngx_http_v2_filter_get_data_frame(
[72]     ngx_http_v2_stream_t *stream, size_t len, ngx_chain_t *first,
[73]     ngx_chain_t *last);
[74] 
[75] static ngx_inline ngx_int_t ngx_http_v2_flow_control(
[76]     ngx_http_v2_connection_t *h2c, ngx_http_v2_stream_t *stream);
[77] static void ngx_http_v2_waiting_queue(ngx_http_v2_connection_t *h2c,
[78]     ngx_http_v2_stream_t *stream);
[79] 
[80] static ngx_inline ngx_int_t ngx_http_v2_filter_send(
[81]     ngx_connection_t *fc, ngx_http_v2_stream_t *stream);
[82] 
[83] static ngx_int_t ngx_http_v2_headers_frame_handler(
[84]     ngx_http_v2_connection_t *h2c, ngx_http_v2_out_frame_t *frame);
[85] static ngx_int_t ngx_http_v2_push_frame_handler(
[86]     ngx_http_v2_connection_t *h2c, ngx_http_v2_out_frame_t *frame);
[87] static ngx_int_t ngx_http_v2_data_frame_handler(
[88]     ngx_http_v2_connection_t *h2c, ngx_http_v2_out_frame_t *frame);
[89] static ngx_inline void ngx_http_v2_handle_frame(
[90]     ngx_http_v2_stream_t *stream, ngx_http_v2_out_frame_t *frame);
[91] static ngx_inline void ngx_http_v2_handle_stream(
[92]     ngx_http_v2_connection_t *h2c, ngx_http_v2_stream_t *stream);
[93] 
[94] static void ngx_http_v2_filter_cleanup(void *data);
[95] 
[96] static ngx_int_t ngx_http_v2_filter_init(ngx_conf_t *cf);
[97] 
[98] 
[99] static ngx_http_module_t  ngx_http_v2_filter_module_ctx = {
[100]     NULL,                                  /* preconfiguration */
[101]     ngx_http_v2_filter_init,               /* postconfiguration */
[102] 
[103]     NULL,                                  /* create main configuration */
[104]     NULL,                                  /* init main configuration */
[105] 
[106]     NULL,                                  /* create server configuration */
[107]     NULL,                                  /* merge server configuration */
[108] 
[109]     NULL,                                  /* create location configuration */
[110]     NULL                                   /* merge location configuration */
[111] };
[112] 
[113] 
[114] ngx_module_t  ngx_http_v2_filter_module = {
[115]     NGX_MODULE_V1,
[116]     &ngx_http_v2_filter_module_ctx,        /* module context */
[117]     NULL,                                  /* module directives */
[118]     NGX_HTTP_MODULE,                       /* module type */
[119]     NULL,                                  /* init master */
[120]     NULL,                                  /* init module */
[121]     NULL,                                  /* init process */
[122]     NULL,                                  /* init thread */
[123]     NULL,                                  /* exit thread */
[124]     NULL,                                  /* exit process */
[125]     NULL,                                  /* exit master */
[126]     NGX_MODULE_V1_PADDING
[127] };
[128] 
[129] 
[130] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[131] 
[132] 
[133] static ngx_int_t
[134] ngx_http_v2_header_filter(ngx_http_request_t *r)
[135] {
[136]     u_char                     status, *pos, *start, *p, *tmp;
[137]     size_t                     len, tmp_len;
[138]     ngx_str_t                  host, location;
[139]     ngx_uint_t                 i, port, fin;
[140]     ngx_list_part_t           *part;
[141]     ngx_table_elt_t           *header;
[142]     ngx_connection_t          *fc;
[143]     ngx_http_cleanup_t        *cln;
[144]     ngx_http_v2_stream_t      *stream;
[145]     ngx_http_v2_out_frame_t   *frame;
[146]     ngx_http_v2_connection_t  *h2c;
[147]     ngx_http_core_loc_conf_t  *clcf;
[148]     ngx_http_core_srv_conf_t  *cscf;
[149]     u_char                     addr[NGX_SOCKADDR_STRLEN];
[150] 
[151]     static const u_char nginx[5] = "\x84\xaa\x63\x55\xe7";
[152] #if (NGX_HTTP_GZIP)
[153]     static const u_char accept_encoding[12] =
[154]         "\x8b\x84\x84\x2d\x69\x5b\x05\x44\x3c\x86\xaa\x6f";
[155] #endif
[156] 
[157]     static size_t nginx_ver_len = ngx_http_v2_literal_size(NGINX_VER);
[158]     static u_char nginx_ver[ngx_http_v2_literal_size(NGINX_VER)];
[159] 
[160]     static size_t nginx_ver_build_len =
[161]                                   ngx_http_v2_literal_size(NGINX_VER_BUILD);
[162]     static u_char nginx_ver_build[ngx_http_v2_literal_size(NGINX_VER_BUILD)];
[163] 
[164]     stream = r->stream;
[165] 
[166]     if (!stream) {
[167]         return ngx_http_next_header_filter(r);
[168]     }
[169] 
[170]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[171]                    "http2 header filter");
[172] 
[173]     if (r->header_sent) {
[174]         return NGX_OK;
[175]     }
[176] 
[177]     r->header_sent = 1;
[178] 
[179]     if (r != r->main) {
[180]         return NGX_OK;
[181]     }
[182] 
[183]     fc = r->connection;
[184] 
[185]     if (fc->error) {
[186]         return NGX_ERROR;
[187]     }
[188] 
[189]     if (r->method == NGX_HTTP_HEAD) {
[190]         r->header_only = 1;
[191]     }
[192] 
[193]     switch (r->headers_out.status) {
[194] 
[195]     case NGX_HTTP_OK:
[196]         status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_200_INDEX);
[197]         break;
[198] 
[199]     case NGX_HTTP_NO_CONTENT:
[200]         r->header_only = 1;
[201] 
[202]         ngx_str_null(&r->headers_out.content_type);
[203] 
[204]         r->headers_out.content_length = NULL;
[205]         r->headers_out.content_length_n = -1;
[206] 
[207]         r->headers_out.last_modified_time = -1;
[208]         r->headers_out.last_modified = NULL;
[209] 
[210]         status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_204_INDEX);
[211]         break;
[212] 
[213]     case NGX_HTTP_PARTIAL_CONTENT:
[214]         status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_206_INDEX);
[215]         break;
[216] 
[217]     case NGX_HTTP_NOT_MODIFIED:
[218]         r->header_only = 1;
[219]         status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_304_INDEX);
[220]         break;
[221] 
[222]     default:
[223]         r->headers_out.last_modified_time = -1;
[224]         r->headers_out.last_modified = NULL;
[225] 
[226]         switch (r->headers_out.status) {
[227] 
[228]         case NGX_HTTP_BAD_REQUEST:
[229]             status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_400_INDEX);
[230]             break;
[231] 
[232]         case NGX_HTTP_NOT_FOUND:
[233]             status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_404_INDEX);
[234]             break;
[235] 
[236]         case NGX_HTTP_INTERNAL_SERVER_ERROR:
[237]             status = ngx_http_v2_indexed(NGX_HTTP_V2_STATUS_500_INDEX);
[238]             break;
[239] 
[240]         default:
[241]             status = 0;
[242]         }
[243]     }
[244] 
[245]     h2c = stream->connection;
[246] 
[247]     if (!h2c->push_disabled && !h2c->goaway
[248]         && stream->node->id % 2 == 1
[249]         && r->method != NGX_HTTP_HEAD)
[250]     {
[251]         if (ngx_http_v2_push_resources(r) != NGX_OK) {
[252]             return NGX_ERROR;
[253]         }
[254]     }
[255] 
[256]     len = h2c->table_update ? 1 : 0;
[257] 
[258]     len += status ? 1 : 1 + ngx_http_v2_literal_size("418");
[259] 
[260]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[261] 
[262]     if (r->headers_out.server == NULL) {
[263] 
[264]         if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
[265]             len += 1 + nginx_ver_len;
[266] 
[267]         } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
[268]             len += 1 + nginx_ver_build_len;
[269] 
[270]         } else {
[271]             len += 1 + sizeof(nginx);
[272]         }
[273]     }
[274] 
[275]     if (r->headers_out.date == NULL) {
[276]         len += 1 + ngx_http_v2_literal_size("Wed, 31 Dec 1986 18:00:00 GMT");
[277]     }
[278] 
[279]     if (r->headers_out.content_type.len) {
[280]         len += 1 + NGX_HTTP_V2_INT_OCTETS + r->headers_out.content_type.len;
[281] 
[282]         if (r->headers_out.content_type_len == r->headers_out.content_type.len
[283]             && r->headers_out.charset.len)
[284]         {
[285]             len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
[286]         }
[287]     }
[288] 
[289]     if (r->headers_out.content_length == NULL
[290]         && r->headers_out.content_length_n >= 0)
[291]     {
[292]         len += 1 + ngx_http_v2_integer_octets(NGX_OFF_T_LEN) + NGX_OFF_T_LEN;
[293]     }
[294] 
[295]     if (r->headers_out.last_modified == NULL
[296]         && r->headers_out.last_modified_time != -1)
[297]     {
[298]         len += 1 + ngx_http_v2_literal_size("Wed, 31 Dec 1986 18:00:00 GMT");
[299]     }
[300] 
[301]     if (r->headers_out.location && r->headers_out.location->value.len) {
[302] 
[303]         if (r->headers_out.location->value.data[0] == '/'
[304]             && clcf->absolute_redirect)
[305]         {
[306]             if (clcf->server_name_in_redirect) {
[307]                 cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[308]                 host = cscf->server_name;
[309] 
[310]             } else if (r->headers_in.server.len) {
[311]                 host = r->headers_in.server;
[312] 
[313]             } else {
[314]                 host.len = NGX_SOCKADDR_STRLEN;
[315]                 host.data = addr;
[316] 
[317]                 if (ngx_connection_local_sockaddr(fc, &host, 0) != NGX_OK) {
[318]                     return NGX_ERROR;
[319]                 }
[320]             }
[321] 
[322]             port = ngx_inet_get_port(fc->local_sockaddr);
[323] 
[324]             location.len = sizeof("https://") - 1 + host.len
[325]                            + r->headers_out.location->value.len;
[326] 
[327]             if (clcf->port_in_redirect) {
[328] 
[329] #if (NGX_HTTP_SSL)
[330]                 if (fc->ssl)
[331]                     port = (port == 443) ? 0 : port;
[332]                 else
[333] #endif
[334]                     port = (port == 80) ? 0 : port;
[335] 
[336]             } else {
[337]                 port = 0;
[338]             }
[339] 
[340]             if (port) {
[341]                 location.len += sizeof(":65535") - 1;
[342]             }
[343] 
[344]             location.data = ngx_pnalloc(r->pool, location.len);
[345]             if (location.data == NULL) {
[346]                 return NGX_ERROR;
[347]             }
[348] 
[349]             p = ngx_cpymem(location.data, "http", sizeof("http") - 1);
[350] 
[351] #if (NGX_HTTP_SSL)
[352]             if (fc->ssl) {
[353]                 *p++ = 's';
[354]             }
[355] #endif
[356] 
[357]             *p++ = ':'; *p++ = '/'; *p++ = '/';
[358]             p = ngx_cpymem(p, host.data, host.len);
[359] 
[360]             if (port) {
[361]                 p = ngx_sprintf(p, ":%ui", port);
[362]             }
[363] 
[364]             p = ngx_cpymem(p, r->headers_out.location->value.data,
[365]                               r->headers_out.location->value.len);
[366] 
[367]             /* update r->headers_out.location->value for possible logging */
[368] 
[369]             r->headers_out.location->value.len = p - location.data;
[370]             r->headers_out.location->value.data = location.data;
[371]             ngx_str_set(&r->headers_out.location->key, "Location");
[372]         }
[373] 
[374]         r->headers_out.location->hash = 0;
[375] 
[376]         len += 1 + NGX_HTTP_V2_INT_OCTETS + r->headers_out.location->value.len;
[377]     }
[378] 
[379]     tmp_len = len;
[380] 
[381] #if (NGX_HTTP_GZIP)
[382]     if (r->gzip_vary) {
[383]         if (clcf->gzip_vary) {
[384]             len += 1 + sizeof(accept_encoding);
[385] 
[386]         } else {
[387]             r->gzip_vary = 0;
[388]         }
[389]     }
[390] #endif
[391] 
[392]     part = &r->headers_out.headers.part;
[393]     header = part->elts;
[394] 
[395]     for (i = 0; /* void */; i++) {
[396] 
[397]         if (i >= part->nelts) {
[398]             if (part->next == NULL) {
[399]                 break;
[400]             }
[401] 
[402]             part = part->next;
[403]             header = part->elts;
[404]             i = 0;
[405]         }
[406] 
[407]         if (header[i].hash == 0) {
[408]             continue;
[409]         }
[410] 
[411]         if (header[i].key.len > NGX_HTTP_V2_MAX_FIELD) {
[412]             ngx_log_error(NGX_LOG_CRIT, fc->log, 0,
[413]                           "too long response header name: \"%V\"",
[414]                           &header[i].key);
[415]             return NGX_ERROR;
[416]         }
[417] 
[418]         if (header[i].value.len > NGX_HTTP_V2_MAX_FIELD) {
[419]             ngx_log_error(NGX_LOG_CRIT, fc->log, 0,
[420]                           "too long response header value: \"%V: %V\"",
[421]                           &header[i].key, &header[i].value);
[422]             return NGX_ERROR;
[423]         }
[424] 
[425]         len += 1 + NGX_HTTP_V2_INT_OCTETS + header[i].key.len
[426]                  + NGX_HTTP_V2_INT_OCTETS + header[i].value.len;
[427] 
[428]         if (header[i].key.len > tmp_len) {
[429]             tmp_len = header[i].key.len;
[430]         }
[431] 
[432]         if (header[i].value.len > tmp_len) {
[433]             tmp_len = header[i].value.len;
[434]         }
[435]     }
[436] 
[437]     tmp = ngx_palloc(r->pool, tmp_len);
[438]     pos = ngx_pnalloc(r->pool, len);
[439] 
[440]     if (pos == NULL || tmp == NULL) {
[441]         return NGX_ERROR;
[442]     }
[443] 
[444]     start = pos;
[445] 
[446]     if (h2c->table_update) {
[447]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[448]                        "http2 table size update: 0");
[449]         *pos++ = (1 << 5) | 0;
[450]         h2c->table_update = 0;
[451]     }
[452] 
[453]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[454]                    "http2 output header: \":status: %03ui\"",
[455]                    r->headers_out.status);
[456] 
[457]     if (status) {
[458]         *pos++ = status;
[459] 
[460]     } else {
[461]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_STATUS_INDEX);
[462]         *pos++ = NGX_HTTP_V2_ENCODE_RAW | 3;
[463]         pos = ngx_sprintf(pos, "%03ui", r->headers_out.status);
[464]     }
[465] 
[466]     if (r->headers_out.server == NULL) {
[467] 
[468]         if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
[469]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[470]                            "http2 output header: \"server: %s\"",
[471]                            NGINX_VER);
[472] 
[473]         } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
[474]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[475]                            "http2 output header: \"server: %s\"",
[476]                            NGINX_VER_BUILD);
[477] 
[478]         } else {
[479]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[480]                            "http2 output header: \"server: nginx\"");
[481]         }
[482] 
[483]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_SERVER_INDEX);
[484] 
[485]         if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
[486]             if (nginx_ver[0] == '\0') {
[487]                 p = ngx_http_v2_write_value(nginx_ver, (u_char *) NGINX_VER,
[488]                                             sizeof(NGINX_VER) - 1, tmp);
[489]                 nginx_ver_len = p - nginx_ver;
[490]             }
[491] 
[492]             pos = ngx_cpymem(pos, nginx_ver, nginx_ver_len);
[493] 
[494]         } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
[495]             if (nginx_ver_build[0] == '\0') {
[496]                 p = ngx_http_v2_write_value(nginx_ver_build,
[497]                                             (u_char *) NGINX_VER_BUILD,
[498]                                             sizeof(NGINX_VER_BUILD) - 1, tmp);
[499]                 nginx_ver_build_len = p - nginx_ver_build;
[500]             }
[501] 
[502]             pos = ngx_cpymem(pos, nginx_ver_build, nginx_ver_build_len);
[503] 
[504]         } else {
[505]             pos = ngx_cpymem(pos, nginx, sizeof(nginx));
[506]         }
[507]     }
[508] 
[509]     if (r->headers_out.date == NULL) {
[510]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[511]                        "http2 output header: \"date: %V\"",
[512]                        &ngx_cached_http_time);
[513] 
[514]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_DATE_INDEX);
[515]         pos = ngx_http_v2_write_value(pos, ngx_cached_http_time.data,
[516]                                       ngx_cached_http_time.len, tmp);
[517]     }
[518] 
[519]     if (r->headers_out.content_type.len) {
[520]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_CONTENT_TYPE_INDEX);
[521] 
[522]         if (r->headers_out.content_type_len == r->headers_out.content_type.len
[523]             && r->headers_out.charset.len)
[524]         {
[525]             len = r->headers_out.content_type.len + sizeof("; charset=") - 1
[526]                   + r->headers_out.charset.len;
[527] 
[528]             p = ngx_pnalloc(r->pool, len);
[529]             if (p == NULL) {
[530]                 return NGX_ERROR;
[531]             }
[532] 
[533]             p = ngx_cpymem(p, r->headers_out.content_type.data,
[534]                            r->headers_out.content_type.len);
[535] 
[536]             p = ngx_cpymem(p, "; charset=", sizeof("; charset=") - 1);
[537] 
[538]             p = ngx_cpymem(p, r->headers_out.charset.data,
[539]                            r->headers_out.charset.len);
[540] 
[541]             /* updated r->headers_out.content_type is also needed for logging */
[542] 
[543]             r->headers_out.content_type.len = len;
[544]             r->headers_out.content_type.data = p - len;
[545]         }
[546] 
[547]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[548]                        "http2 output header: \"content-type: %V\"",
[549]                        &r->headers_out.content_type);
[550] 
[551]         pos = ngx_http_v2_write_value(pos, r->headers_out.content_type.data,
[552]                                       r->headers_out.content_type.len, tmp);
[553]     }
[554] 
[555]     if (r->headers_out.content_length == NULL
[556]         && r->headers_out.content_length_n >= 0)
[557]     {
[558]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[559]                        "http2 output header: \"content-length: %O\"",
[560]                        r->headers_out.content_length_n);
[561] 
[562]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_CONTENT_LENGTH_INDEX);
[563] 
[564]         p = pos;
[565]         pos = ngx_sprintf(pos + 1, "%O", r->headers_out.content_length_n);
[566]         *p = NGX_HTTP_V2_ENCODE_RAW | (u_char) (pos - p - 1);
[567]     }
[568] 
[569]     if (r->headers_out.last_modified == NULL
[570]         && r->headers_out.last_modified_time != -1)
[571]     {
[572]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_LAST_MODIFIED_INDEX);
[573] 
[574]         ngx_http_time(pos, r->headers_out.last_modified_time);
[575]         len = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;
[576] 
[577]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[578]                        "http2 output header: \"last-modified: %*s\"",
[579]                        len, pos);
[580] 
[581]         /*
[582]          * Date will always be encoded using huffman in the temporary buffer,
[583]          * so it's safe here to use src and dst pointing to the same address.
[584]          */
[585]         pos = ngx_http_v2_write_value(pos, pos, len, tmp);
[586]     }
[587] 
[588]     if (r->headers_out.location && r->headers_out.location->value.len) {
[589]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[590]                        "http2 output header: \"location: %V\"",
[591]                        &r->headers_out.location->value);
[592] 
[593]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_LOCATION_INDEX);
[594]         pos = ngx_http_v2_write_value(pos, r->headers_out.location->value.data,
[595]                                       r->headers_out.location->value.len, tmp);
[596]     }
[597] 
[598] #if (NGX_HTTP_GZIP)
[599]     if (r->gzip_vary) {
[600]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[601]                        "http2 output header: \"vary: Accept-Encoding\"");
[602] 
[603]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_VARY_INDEX);
[604]         pos = ngx_cpymem(pos, accept_encoding, sizeof(accept_encoding));
[605]     }
[606] #endif
[607] 
[608]     part = &r->headers_out.headers.part;
[609]     header = part->elts;
[610] 
[611]     for (i = 0; /* void */; i++) {
[612] 
[613]         if (i >= part->nelts) {
[614]             if (part->next == NULL) {
[615]                 break;
[616]             }
[617] 
[618]             part = part->next;
[619]             header = part->elts;
[620]             i = 0;
[621]         }
[622] 
[623]         if (header[i].hash == 0) {
[624]             continue;
[625]         }
[626] 
[627] #if (NGX_DEBUG)
[628]         if (fc->log->log_level & NGX_LOG_DEBUG_HTTP) {
[629]             ngx_strlow(tmp, header[i].key.data, header[i].key.len);
[630] 
[631]             ngx_log_debug3(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[632]                            "http2 output header: \"%*s: %V\"",
[633]                            header[i].key.len, tmp, &header[i].value);
[634]         }
[635] #endif
[636] 
[637]         *pos++ = 0;
[638] 
[639]         pos = ngx_http_v2_write_name(pos, header[i].key.data,
[640]                                      header[i].key.len, tmp);
[641] 
[642]         pos = ngx_http_v2_write_value(pos, header[i].value.data,
[643]                                       header[i].value.len, tmp);
[644]     }
[645] 
[646]     fin = r->header_only
[647]           || (r->headers_out.content_length_n == 0 && !r->expect_trailers);
[648] 
[649]     frame = ngx_http_v2_create_headers_frame(r, start, pos, fin);
[650]     if (frame == NULL) {
[651]         return NGX_ERROR;
[652]     }
[653] 
[654]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[655] 
[656]     stream->queued++;
[657] 
[658]     cln = ngx_http_cleanup_add(r, 0);
[659]     if (cln == NULL) {
[660]         return NGX_ERROR;
[661]     }
[662] 
[663]     cln->handler = ngx_http_v2_filter_cleanup;
[664]     cln->data = stream;
[665] 
[666]     fc->send_chain = ngx_http_v2_send_chain;
[667]     fc->need_last_buf = 1;
[668]     fc->need_flush_buf = 1;
[669] 
[670]     return ngx_http_v2_filter_send(fc, stream);
[671] }
[672] 
[673] 
[674] static ngx_int_t
[675] ngx_http_v2_push_resources(ngx_http_request_t *r)
[676] {
[677]     u_char                    *start, *end, *last;
[678]     ngx_int_t                  rc;
[679]     ngx_str_t                  path;
[680]     ngx_uint_t                 i, push;
[681]     ngx_table_elt_t           *h;
[682]     ngx_http_v2_loc_conf_t    *h2lcf;
[683]     ngx_http_complex_value_t  *pushes;
[684]     ngx_str_t                  binary[NGX_HTTP_V2_PUSH_HEADERS];
[685] 
[686]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[687]                    "http2 push resources");
[688] 
[689]     ngx_memzero(binary, NGX_HTTP_V2_PUSH_HEADERS * sizeof(ngx_str_t));
[690] 
[691]     h2lcf = ngx_http_get_module_loc_conf(r, ngx_http_v2_module);
[692] 
[693]     if (h2lcf->pushes) {
[694]         pushes = h2lcf->pushes->elts;
[695] 
[696]         for (i = 0; i < h2lcf->pushes->nelts; i++) {
[697] 
[698]             if (ngx_http_complex_value(r, &pushes[i], &path) != NGX_OK) {
[699]                 return NGX_ERROR;
[700]             }
[701] 
[702]             if (path.len == 0) {
[703]                 continue;
[704]             }
[705] 
[706]             if (path.len == 3 && ngx_strncmp(path.data, "off", 3) == 0) {
[707]                 continue;
[708]             }
[709] 
[710]             rc = ngx_http_v2_push_resource(r, &path, binary);
[711] 
[712]             if (rc == NGX_ERROR) {
[713]                 return NGX_ERROR;
[714]             }
[715] 
[716]             if (rc == NGX_ABORT) {
[717]                 return NGX_OK;
[718]             }
[719] 
[720]             /* NGX_OK, NGX_DECLINED */
[721]         }
[722]     }
[723] 
[724]     if (!h2lcf->push_preload) {
[725]         return NGX_OK;
[726]     }
[727] 
[728]     for (h = r->headers_out.link; h; h = h->next) {
[729] 
[730]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[731]                        "http2 parse link: \"%V\"", &h->value);
[732] 
[733]         start = h->value.data;
[734]         end = h->value.data + h->value.len;
[735] 
[736]     next_link:
[737] 
[738]         while (start < end && *start == ' ') { start++; }
[739] 
[740]         if (start == end || *start++ != '<') {
[741]             continue;
[742]         }
[743] 
[744]         while (start < end && *start == ' ') { start++; }
[745] 
[746]         for (last = start; last < end && *last != '>'; last++) {
[747]             /* void */
[748]         }
[749] 
[750]         if (last == start || last == end) {
[751]             continue;
[752]         }
[753] 
[754]         path.len = last - start;
[755]         path.data = start;
[756] 
[757]         start = last + 1;
[758] 
[759]         while (start < end && *start == ' ') { start++; }
[760] 
[761]         if (start == end) {
[762]             continue;
[763]         }
[764] 
[765]         if (*start == ',') {
[766]             start++;
[767]             goto next_link;
[768]         }
[769] 
[770]         if (*start++ != ';') {
[771]             continue;
[772]         }
[773] 
[774]         last = ngx_strlchr(start, end, ',');
[775] 
[776]         if (last == NULL) {
[777]             last = end;
[778]         }
[779] 
[780]         push = 0;
[781] 
[782]         for ( ;; ) {
[783] 
[784]             while (start < last && *start == ' ') { start++; }
[785] 
[786]             if (last - start >= 6
[787]                 && ngx_strncasecmp(start, (u_char *) "nopush", 6) == 0)
[788]             {
[789]                 start += 6;
[790] 
[791]                 if (start == last || *start == ' ' || *start == ';') {
[792]                     push = 0;
[793]                     break;
[794]                 }
[795] 
[796]                 goto next_param;
[797]             }
[798] 
[799]             if (last - start >= 11
[800]                 && ngx_strncasecmp(start, (u_char *) "rel=preload", 11) == 0)
[801]             {
[802]                 start += 11;
[803] 
[804]                 if (start == last || *start == ' ' || *start == ';') {
[805]                     push = 1;
[806]                 }
[807] 
[808]                 goto next_param;
[809]             }
[810] 
[811]             if (last - start >= 4
[812]                 && ngx_strncasecmp(start, (u_char *) "rel=", 4) == 0)
[813]             {
[814]                 start += 4;
[815] 
[816]                 while (start < last && *start == ' ') { start++; }
[817] 
[818]                 if (start == last || *start++ != '"') {
[819]                     goto next_param;
[820]                 }
[821] 
[822]                 for ( ;; ) {
[823] 
[824]                     while (start < last && *start == ' ') { start++; }
[825] 
[826]                     if (last - start >= 7
[827]                         && ngx_strncasecmp(start, (u_char *) "preload", 7) == 0)
[828]                     {
[829]                         start += 7;
[830] 
[831]                         if (start < last && (*start == ' ' || *start == '"')) {
[832]                             push = 1;
[833]                             break;
[834]                         }
[835]                     }
[836] 
[837]                     while (start < last && *start != ' ' && *start != '"') {
[838]                         start++;
[839]                     }
[840] 
[841]                     if (start == last) {
[842]                         break;
[843]                     }
[844] 
[845]                     if (*start == '"') {
[846]                         break;
[847]                     }
[848] 
[849]                     start++;
[850]                 }
[851]             }
[852] 
[853]         next_param:
[854] 
[855]             start = ngx_strlchr(start, last, ';');
[856] 
[857]             if (start == NULL) {
[858]                 break;
[859]             }
[860] 
[861]             start++;
[862]         }
[863] 
[864]         if (push) {
[865]             while (path.len && path.data[path.len - 1] == ' ') {
[866]                 path.len--;
[867]             }
[868]         }
[869] 
[870]         if (push && path.len
[871]             && !(path.len > 1 && path.data[0] == '/' && path.data[1] == '/'))
[872]         {
[873]             rc = ngx_http_v2_push_resource(r, &path, binary);
[874] 
[875]             if (rc == NGX_ERROR) {
[876]                 return NGX_ERROR;
[877]             }
[878] 
[879]             if (rc == NGX_ABORT) {
[880]                 return NGX_OK;
[881]             }
[882] 
[883]             /* NGX_OK, NGX_DECLINED */
[884]         }
[885] 
[886]         if (last < end) {
[887]             start = last + 1;
[888]             goto next_link;
[889]         }
[890]     }
[891] 
[892]     return NGX_OK;
[893] }
[894] 
[895] 
[896] static ngx_int_t
[897] ngx_http_v2_push_resource(ngx_http_request_t *r, ngx_str_t *path,
[898]     ngx_str_t *binary)
[899] {
[900]     u_char                      *start, *pos, *tmp;
[901]     size_t                       len;
[902]     ngx_str_t                   *value;
[903]     ngx_uint_t                   i;
[904]     ngx_table_elt_t            **h;
[905]     ngx_connection_t            *fc;
[906]     ngx_http_v2_stream_t        *stream;
[907]     ngx_http_v2_out_frame_t     *frame;
[908]     ngx_http_v2_connection_t    *h2c;
[909]     ngx_http_v2_push_header_t   *ph;
[910] 
[911]     fc = r->connection;
[912] 
[913]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0, "http2 push resource");
[914] 
[915]     stream = r->stream;
[916]     h2c = stream->connection;
[917] 
[918]     if (!ngx_path_separator(path->data[0])) {
[919]         ngx_log_error(NGX_LOG_WARN, fc->log, 0,
[920]                       "non-absolute path \"%V\" not pushed", path);
[921]         return NGX_DECLINED;
[922]     }
[923] 
[924]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[925]                    "http2 pushing:%ui limit:%ui",
[926]                    h2c->pushing, h2c->concurrent_pushes);
[927] 
[928]     if (h2c->pushing >= h2c->concurrent_pushes) {
[929]         return NGX_ABORT;
[930]     }
[931] 
[932]     if (h2c->last_push == 0x7ffffffe) {
[933]         return NGX_ABORT;
[934]     }
[935] 
[936]     if (path->len > NGX_HTTP_V2_MAX_FIELD) {
[937]         return NGX_DECLINED;
[938]     }
[939] 
[940]     if (r->headers_in.host == NULL) {
[941]         return NGX_ABORT;
[942]     }
[943] 
[944]     ph = ngx_http_v2_push_headers;
[945] 
[946]     len = ngx_max(r->schema.len, path->len);
[947] 
[948]     if (binary[0].len) {
[949]         tmp = ngx_palloc(r->pool, len);
[950]         if (tmp == NULL) {
[951]             return NGX_ERROR;
[952]         }
[953] 
[954]     } else {
[955]         for (i = 0; i < NGX_HTTP_V2_PUSH_HEADERS; i++) {
[956]             h = (ngx_table_elt_t **) ((char *) &r->headers_in + ph[i].offset);
[957] 
[958]             if (*h) {
[959]                 len = ngx_max(len, (*h)->value.len);
[960]             }
[961]         }
[962] 
[963]         tmp = ngx_palloc(r->pool, len);
[964]         if (tmp == NULL) {
[965]             return NGX_ERROR;
[966]         }
[967] 
[968]         for (i = 0; i < NGX_HTTP_V2_PUSH_HEADERS; i++) {
[969]             h = (ngx_table_elt_t **) ((char *) &r->headers_in + ph[i].offset);
[970] 
[971]             if (*h == NULL) {
[972]                 continue;
[973]             }
[974] 
[975]             value = &(*h)->value;
[976] 
[977]             len = 1 + NGX_HTTP_V2_INT_OCTETS + value->len;
[978] 
[979]             pos = ngx_pnalloc(r->pool, len);
[980]             if (pos == NULL) {
[981]                 return NGX_ERROR;
[982]             }
[983] 
[984]             binary[i].data = pos;
[985] 
[986]             *pos++ = ngx_http_v2_inc_indexed(ph[i].index);
[987]             pos = ngx_http_v2_write_value(pos, value->data, value->len, tmp);
[988] 
[989]             binary[i].len = pos - binary[i].data;
[990]         }
[991]     }
[992] 
[993]     len = (h2c->table_update ? 1 : 0)
[994]           + 1
[995]           + 1 + NGX_HTTP_V2_INT_OCTETS + path->len
[996]           + 1 + NGX_HTTP_V2_INT_OCTETS + r->schema.len;
[997] 
[998]     for (i = 0; i < NGX_HTTP_V2_PUSH_HEADERS; i++) {
[999]         len += binary[i].len;
[1000]     }
[1001] 
[1002]     pos = ngx_pnalloc(r->pool, len);
[1003]     if (pos == NULL) {
[1004]         return NGX_ERROR;
[1005]     }
[1006] 
[1007]     start = pos;
[1008] 
[1009]     if (h2c->table_update) {
[1010]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1011]                        "http2 table size update: 0");
[1012]         *pos++ = (1 << 5) | 0;
[1013]         h2c->table_update = 0;
[1014]     }
[1015] 
[1016]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1017]                    "http2 push header: \":method: GET\"");
[1018] 
[1019]     *pos++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_GET_INDEX);
[1020] 
[1021]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1022]                    "http2 push header: \":path: %V\"", path);
[1023] 
[1024]     *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
[1025]     pos = ngx_http_v2_write_value(pos, path->data, path->len, tmp);
[1026] 
[1027]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1028]                    "http2 push header: \":scheme: %V\"", &r->schema);
[1029] 
[1030]     if (r->schema.len == 5 && ngx_strncmp(r->schema.data, "https", 5) == 0) {
[1031]         *pos++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX);
[1032] 
[1033]     } else if (r->schema.len == 4
[1034]                && ngx_strncmp(r->schema.data, "http", 4) == 0)
[1035]     {
[1036]         *pos++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX);
[1037] 
[1038]     } else {
[1039]         *pos++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX);
[1040]         pos = ngx_http_v2_write_value(pos, r->schema.data, r->schema.len, tmp);
[1041]     }
[1042] 
[1043]     for (i = 0; i < NGX_HTTP_V2_PUSH_HEADERS; i++) {
[1044]         h = (ngx_table_elt_t **) ((char *) &r->headers_in + ph[i].offset);
[1045] 
[1046]         if (*h == NULL) {
[1047]             continue;
[1048]         }
[1049] 
[1050]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1051]                        "http2 push header: \"%V: %V\"",
[1052]                        &ph[i].name, &(*h)->value);
[1053] 
[1054]         pos = ngx_cpymem(pos, binary[i].data, binary[i].len);
[1055]     }
[1056] 
[1057]     frame = ngx_http_v2_create_push_frame(r, start, pos);
[1058]     if (frame == NULL) {
[1059]         return NGX_ERROR;
[1060]     }
[1061] 
[1062]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[1063] 
[1064]     stream->queued++;
[1065] 
[1066]     stream = ngx_http_v2_push_stream(stream, path);
[1067] 
[1068]     if (stream) {
[1069]         stream->request->request_length = pos - start;
[1070]         return NGX_OK;
[1071]     }
[1072] 
[1073]     return NGX_ERROR;
[1074] }
[1075] 
[1076] 
[1077] static ngx_http_v2_out_frame_t *
[1078] ngx_http_v2_create_headers_frame(ngx_http_request_t *r, u_char *pos,
[1079]     u_char *end, ngx_uint_t fin)
[1080] {
[1081]     u_char                    type, flags;
[1082]     size_t                    rest, frame_size;
[1083]     ngx_buf_t                *b;
[1084]     ngx_chain_t              *cl, **ll;
[1085]     ngx_http_v2_stream_t     *stream;
[1086]     ngx_http_v2_out_frame_t  *frame;
[1087] 
[1088]     stream = r->stream;
[1089]     rest = end - pos;
[1090] 
[1091]     frame = ngx_palloc(r->pool, sizeof(ngx_http_v2_out_frame_t));
[1092]     if (frame == NULL) {
[1093]         return NULL;
[1094]     }
[1095] 
[1096]     frame->handler = ngx_http_v2_headers_frame_handler;
[1097]     frame->stream = stream;
[1098]     frame->length = rest;
[1099]     frame->blocked = 1;
[1100]     frame->fin = fin;
[1101] 
[1102]     ll = &frame->first;
[1103] 
[1104]     type = NGX_HTTP_V2_HEADERS_FRAME;
[1105]     flags = fin ? NGX_HTTP_V2_END_STREAM_FLAG : NGX_HTTP_V2_NO_FLAG;
[1106]     frame_size = stream->connection->frame_size;
[1107] 
[1108]     for ( ;; ) {
[1109]         if (rest <= frame_size) {
[1110]             frame_size = rest;
[1111]             flags |= NGX_HTTP_V2_END_HEADERS_FLAG;
[1112]         }
[1113] 
[1114]         b = ngx_create_temp_buf(r->pool, NGX_HTTP_V2_FRAME_HEADER_SIZE);
[1115]         if (b == NULL) {
[1116]             return NULL;
[1117]         }
[1118] 
[1119]         b->last = ngx_http_v2_write_len_and_type(b->last, frame_size, type);
[1120]         *b->last++ = flags;
[1121]         b->last = ngx_http_v2_write_sid(b->last, stream->node->id);
[1122] 
[1123]         b->tag = (ngx_buf_tag_t) &ngx_http_v2_module;
[1124] 
[1125]         cl = ngx_alloc_chain_link(r->pool);
[1126]         if (cl == NULL) {
[1127]             return NULL;
[1128]         }
[1129] 
[1130]         cl->buf = b;
[1131] 
[1132]         *ll = cl;
[1133]         ll = &cl->next;
[1134] 
[1135]         b = ngx_calloc_buf(r->pool);
[1136]         if (b == NULL) {
[1137]             return NULL;
[1138]         }
[1139] 
[1140]         b->pos = pos;
[1141] 
[1142]         pos += frame_size;
[1143] 
[1144]         b->last = pos;
[1145]         b->start = b->pos;
[1146]         b->end = b->last;
[1147]         b->temporary = 1;
[1148] 
[1149]         cl = ngx_alloc_chain_link(r->pool);
[1150]         if (cl == NULL) {
[1151]             return NULL;
[1152]         }
[1153] 
[1154]         cl->buf = b;
[1155] 
[1156]         *ll = cl;
[1157]         ll = &cl->next;
[1158] 
[1159]         rest -= frame_size;
[1160] 
[1161]         if (rest) {
[1162]             frame->length += NGX_HTTP_V2_FRAME_HEADER_SIZE;
[1163] 
[1164]             type = NGX_HTTP_V2_CONTINUATION_FRAME;
[1165]             flags = NGX_HTTP_V2_NO_FLAG;
[1166]             continue;
[1167]         }
[1168] 
[1169]         b->last_buf = fin;
[1170]         cl->next = NULL;
[1171]         frame->last = cl;
[1172] 
[1173]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1174]                        "http2:%ui create HEADERS frame %p: len:%uz fin:%ui",
[1175]                        stream->node->id, frame, frame->length, fin);
[1176] 
[1177]         return frame;
[1178]     }
[1179] }
[1180] 
[1181] 
[1182] static ngx_http_v2_out_frame_t *
[1183] ngx_http_v2_create_push_frame(ngx_http_request_t *r, u_char *pos, u_char *end)
[1184] {
[1185]     u_char                     type, flags;
[1186]     size_t                     rest, frame_size, len;
[1187]     ngx_buf_t                 *b;
[1188]     ngx_chain_t               *cl, **ll;
[1189]     ngx_http_v2_stream_t      *stream;
[1190]     ngx_http_v2_out_frame_t   *frame;
[1191]     ngx_http_v2_connection_t  *h2c;
[1192] 
[1193]     stream = r->stream;
[1194]     h2c = stream->connection;
[1195]     rest = NGX_HTTP_V2_STREAM_ID_SIZE + (end - pos);
[1196] 
[1197]     frame = ngx_palloc(r->pool, sizeof(ngx_http_v2_out_frame_t));
[1198]     if (frame == NULL) {
[1199]         return NULL;
[1200]     }
[1201] 
[1202]     frame->handler = ngx_http_v2_push_frame_handler;
[1203]     frame->stream = stream;
[1204]     frame->length = rest;
[1205]     frame->blocked = 1;
[1206]     frame->fin = 0;
[1207] 
[1208]     ll = &frame->first;
[1209] 
[1210]     type = NGX_HTTP_V2_PUSH_PROMISE_FRAME;
[1211]     flags = NGX_HTTP_V2_NO_FLAG;
[1212]     frame_size = h2c->frame_size;
[1213] 
[1214]     for ( ;; ) {
[1215]         if (rest <= frame_size) {
[1216]             frame_size = rest;
[1217]             flags |= NGX_HTTP_V2_END_HEADERS_FLAG;
[1218]         }
[1219] 
[1220]         b = ngx_create_temp_buf(r->pool,
[1221]                                 NGX_HTTP_V2_FRAME_HEADER_SIZE
[1222]                                 + ((type == NGX_HTTP_V2_PUSH_PROMISE_FRAME)
[1223]                                    ? NGX_HTTP_V2_STREAM_ID_SIZE : 0));
[1224]         if (b == NULL) {
[1225]             return NULL;
[1226]         }
[1227] 
[1228]         b->last = ngx_http_v2_write_len_and_type(b->last, frame_size, type);
[1229]         *b->last++ = flags;
[1230]         b->last = ngx_http_v2_write_sid(b->last, stream->node->id);
[1231] 
[1232]         b->tag = (ngx_buf_tag_t) &ngx_http_v2_module;
[1233] 
[1234]         if (type == NGX_HTTP_V2_PUSH_PROMISE_FRAME) {
[1235]             h2c->last_push += 2;
[1236] 
[1237]             b->last = ngx_http_v2_write_sid(b->last, h2c->last_push);
[1238]             len = frame_size - NGX_HTTP_V2_STREAM_ID_SIZE;
[1239] 
[1240]         } else {
[1241]             len = frame_size;
[1242]         }
[1243] 
[1244]         cl = ngx_alloc_chain_link(r->pool);
[1245]         if (cl == NULL) {
[1246]             return NULL;
[1247]         }
[1248] 
[1249]         cl->buf = b;
[1250] 
[1251]         *ll = cl;
[1252]         ll = &cl->next;
[1253] 
[1254]         b = ngx_calloc_buf(r->pool);
[1255]         if (b == NULL) {
[1256]             return NULL;
[1257]         }
[1258] 
[1259]         b->pos = pos;
[1260] 
[1261]         pos += len;
[1262] 
[1263]         b->last = pos;
[1264]         b->start = b->pos;
[1265]         b->end = b->last;
[1266]         b->temporary = 1;
[1267] 
[1268]         cl = ngx_alloc_chain_link(r->pool);
[1269]         if (cl == NULL) {
[1270]             return NULL;
[1271]         }
[1272] 
[1273]         cl->buf = b;
[1274] 
[1275]         *ll = cl;
[1276]         ll = &cl->next;
[1277] 
[1278]         rest -= frame_size;
[1279] 
[1280]         if (rest) {
[1281]             frame->length += NGX_HTTP_V2_FRAME_HEADER_SIZE;
[1282] 
[1283]             type = NGX_HTTP_V2_CONTINUATION_FRAME;
[1284]             continue;
[1285]         }
[1286] 
[1287]         cl->next = NULL;
[1288]         frame->last = cl;
[1289] 
[1290]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1291]                        "http2:%ui create PUSH_PROMISE frame %p: "
[1292]                        "sid:%ui len:%uz",
[1293]                        stream->node->id, frame, h2c->last_push,
[1294]                        frame->length);
[1295] 
[1296]         return frame;
[1297]     }
[1298] }
[1299] 
[1300] 
[1301] static ngx_http_v2_out_frame_t *
[1302] ngx_http_v2_create_trailers_frame(ngx_http_request_t *r)
[1303] {
[1304]     u_char            *pos, *start, *tmp;
[1305]     size_t             len, tmp_len;
[1306]     ngx_uint_t         i;
[1307]     ngx_list_part_t   *part;
[1308]     ngx_table_elt_t   *header;
[1309]     ngx_connection_t  *fc;
[1310] 
[1311]     fc = r->connection;
[1312]     len = 0;
[1313]     tmp_len = 0;
[1314] 
[1315]     part = &r->headers_out.trailers.part;
[1316]     header = part->elts;
[1317] 
[1318]     for (i = 0; /* void */; i++) {
[1319] 
[1320]         if (i >= part->nelts) {
[1321]             if (part->next == NULL) {
[1322]                 break;
[1323]             }
[1324] 
[1325]             part = part->next;
[1326]             header = part->elts;
[1327]             i = 0;
[1328]         }
[1329] 
[1330]         if (header[i].hash == 0) {
[1331]             continue;
[1332]         }
[1333] 
[1334]         if (header[i].key.len > NGX_HTTP_V2_MAX_FIELD) {
[1335]             ngx_log_error(NGX_LOG_CRIT, fc->log, 0,
[1336]                           "too long response trailer name: \"%V\"",
[1337]                           &header[i].key);
[1338]             return NULL;
[1339]         }
[1340] 
[1341]         if (header[i].value.len > NGX_HTTP_V2_MAX_FIELD) {
[1342]             ngx_log_error(NGX_LOG_CRIT, fc->log, 0,
[1343]                           "too long response trailer value: \"%V: %V\"",
[1344]                           &header[i].key, &header[i].value);
[1345]             return NULL;
[1346]         }
[1347] 
[1348]         len += 1 + NGX_HTTP_V2_INT_OCTETS + header[i].key.len
[1349]                  + NGX_HTTP_V2_INT_OCTETS + header[i].value.len;
[1350] 
[1351]         if (header[i].key.len > tmp_len) {
[1352]             tmp_len = header[i].key.len;
[1353]         }
[1354] 
[1355]         if (header[i].value.len > tmp_len) {
[1356]             tmp_len = header[i].value.len;
[1357]         }
[1358]     }
[1359] 
[1360]     if (len == 0) {
[1361]         return NGX_HTTP_V2_NO_TRAILERS;
[1362]     }
[1363] 
[1364]     tmp = ngx_palloc(r->pool, tmp_len);
[1365]     pos = ngx_pnalloc(r->pool, len);
[1366] 
[1367]     if (pos == NULL || tmp == NULL) {
[1368]         return NULL;
[1369]     }
[1370] 
[1371]     start = pos;
[1372] 
[1373]     part = &r->headers_out.trailers.part;
[1374]     header = part->elts;
[1375] 
[1376]     for (i = 0; /* void */; i++) {
[1377] 
[1378]         if (i >= part->nelts) {
[1379]             if (part->next == NULL) {
[1380]                 break;
[1381]             }
[1382] 
[1383]             part = part->next;
[1384]             header = part->elts;
[1385]             i = 0;
[1386]         }
[1387] 
[1388]         if (header[i].hash == 0) {
[1389]             continue;
[1390]         }
[1391] 
[1392] #if (NGX_DEBUG)
[1393]         if (fc->log->log_level & NGX_LOG_DEBUG_HTTP) {
[1394]             ngx_strlow(tmp, header[i].key.data, header[i].key.len);
[1395] 
[1396]             ngx_log_debug3(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1397]                            "http2 output trailer: \"%*s: %V\"",
[1398]                            header[i].key.len, tmp, &header[i].value);
[1399]         }
[1400] #endif
[1401] 
[1402]         *pos++ = 0;
[1403] 
[1404]         pos = ngx_http_v2_write_name(pos, header[i].key.data,
[1405]                                      header[i].key.len, tmp);
[1406] 
[1407]         pos = ngx_http_v2_write_value(pos, header[i].value.data,
[1408]                                       header[i].value.len, tmp);
[1409]     }
[1410] 
[1411]     return ngx_http_v2_create_headers_frame(r, start, pos, 1);
[1412] }
[1413] 
[1414] 
[1415] static ngx_chain_t *
[1416] ngx_http_v2_send_chain(ngx_connection_t *fc, ngx_chain_t *in, off_t limit)
[1417] {
[1418]     off_t                      size, offset;
[1419]     size_t                     rest, frame_size;
[1420]     ngx_chain_t               *cl, *out, **ln;
[1421]     ngx_http_request_t        *r;
[1422]     ngx_http_v2_stream_t      *stream;
[1423]     ngx_http_v2_loc_conf_t    *h2lcf;
[1424]     ngx_http_v2_out_frame_t   *frame, *trailers;
[1425]     ngx_http_v2_connection_t  *h2c;
[1426] 
[1427]     r = fc->data;
[1428]     stream = r->stream;
[1429] 
[1430] #if (NGX_SUPPRESS_WARN)
[1431]     size = 0;
[1432] #endif
[1433] 
[1434]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[1435]                    "http2 send chain: %p", in);
[1436] 
[1437]     while (in) {
[1438]         size = ngx_buf_size(in->buf);
[1439] 
[1440]         if (size || in->buf->last_buf) {
[1441]             break;
[1442]         }
[1443] 
[1444]         in = in->next;
[1445]     }
[1446] 
[1447]     if (in == NULL || stream->out_closed) {
[1448] 
[1449]         if (size) {
[1450]             ngx_log_error(NGX_LOG_ERR, fc->log, 0,
[1451]                           "output on closed stream");
[1452]             return NGX_CHAIN_ERROR;
[1453]         }
[1454] 
[1455]         if (ngx_http_v2_filter_send(fc, stream) == NGX_ERROR) {
[1456]             return NGX_CHAIN_ERROR;
[1457]         }
[1458] 
[1459]         return NULL;
[1460]     }
[1461] 
[1462]     h2c = stream->connection;
[1463] 
[1464]     if (size && ngx_http_v2_flow_control(h2c, stream) == NGX_DECLINED) {
[1465] 
[1466]         if (ngx_http_v2_filter_send(fc, stream) == NGX_ERROR) {
[1467]             return NGX_CHAIN_ERROR;
[1468]         }
[1469] 
[1470]         if (ngx_http_v2_flow_control(h2c, stream) == NGX_DECLINED) {
[1471]             fc->write->active = 1;
[1472]             fc->write->ready = 0;
[1473]             return in;
[1474]         }
[1475]     }
[1476] 
[1477]     if (in->buf->tag == (ngx_buf_tag_t) &ngx_http_v2_filter_get_shadow) {
[1478]         cl = ngx_alloc_chain_link(r->pool);
[1479]         if (cl == NULL) {
[1480]             return NGX_CHAIN_ERROR;
[1481]         }
[1482] 
[1483]         cl->buf = in->buf;
[1484]         in->buf = cl->buf->shadow;
[1485] 
[1486]         offset = ngx_buf_in_memory(in->buf)
[1487]                  ? (cl->buf->pos - in->buf->pos)
[1488]                  : (cl->buf->file_pos - in->buf->file_pos);
[1489] 
[1490]         cl->next = stream->free_bufs;
[1491]         stream->free_bufs = cl;
[1492] 
[1493]     } else {
[1494]         offset = 0;
[1495]     }
[1496] 
[1497]     if (limit == 0 || limit > (off_t) h2c->send_window) {
[1498]         limit = h2c->send_window;
[1499]     }
[1500] 
[1501]     if (limit > stream->send_window) {
[1502]         limit = (stream->send_window > 0) ? stream->send_window : 0;
[1503]     }
[1504] 
[1505]     h2lcf = ngx_http_get_module_loc_conf(r, ngx_http_v2_module);
[1506] 
[1507]     frame_size = (h2lcf->chunk_size < h2c->frame_size)
[1508]                  ? h2lcf->chunk_size : h2c->frame_size;
[1509] 
[1510]     trailers = NGX_HTTP_V2_NO_TRAILERS;
[1511] 
[1512] #if (NGX_SUPPRESS_WARN)
[1513]     cl = NULL;
[1514] #endif
[1515] 
[1516]     for ( ;; ) {
[1517]         if ((off_t) frame_size > limit) {
[1518]             frame_size = (size_t) limit;
[1519]         }
[1520] 
[1521]         ln = &out;
[1522]         rest = frame_size;
[1523] 
[1524]         while ((off_t) rest >= size) {
[1525] 
[1526]             if (offset) {
[1527]                 cl = ngx_http_v2_filter_get_shadow(stream, in->buf,
[1528]                                                    offset, size);
[1529]                 if (cl == NULL) {
[1530]                     return NGX_CHAIN_ERROR;
[1531]                 }
[1532] 
[1533]                 offset = 0;
[1534] 
[1535]             } else {
[1536]                 cl = ngx_alloc_chain_link(r->pool);
[1537]                 if (cl == NULL) {
[1538]                     return NGX_CHAIN_ERROR;
[1539]                 }
[1540] 
[1541]                 cl->buf = in->buf;
[1542]             }
[1543] 
[1544]             *ln = cl;
[1545]             ln = &cl->next;
[1546] 
[1547]             rest -= (size_t) size;
[1548]             in = in->next;
[1549] 
[1550]             if (in == NULL) {
[1551]                 frame_size -= rest;
[1552]                 rest = 0;
[1553]                 break;
[1554]             }
[1555] 
[1556]             size = ngx_buf_size(in->buf);
[1557]         }
[1558] 
[1559]         if (rest) {
[1560]             cl = ngx_http_v2_filter_get_shadow(stream, in->buf, offset, rest);
[1561]             if (cl == NULL) {
[1562]                 return NGX_CHAIN_ERROR;
[1563]             }
[1564] 
[1565]             cl->buf->flush = 0;
[1566]             cl->buf->last_buf = 0;
[1567] 
[1568]             *ln = cl;
[1569] 
[1570]             offset += rest;
[1571]             size -= rest;
[1572]         }
[1573] 
[1574]         if (cl->buf->last_buf) {
[1575]             trailers = ngx_http_v2_create_trailers_frame(r);
[1576]             if (trailers == NULL) {
[1577]                 return NGX_CHAIN_ERROR;
[1578]             }
[1579] 
[1580]             if (trailers != NGX_HTTP_V2_NO_TRAILERS) {
[1581]                 cl->buf->last_buf = 0;
[1582]             }
[1583]         }
[1584] 
[1585]         if (frame_size || cl->buf->last_buf) {
[1586]             frame = ngx_http_v2_filter_get_data_frame(stream, frame_size,
[1587]                                                       out, cl);
[1588]             if (frame == NULL) {
[1589]                 return NGX_CHAIN_ERROR;
[1590]             }
[1591] 
[1592]             ngx_http_v2_queue_frame(h2c, frame);
[1593] 
[1594]             h2c->send_window -= frame_size;
[1595] 
[1596]             stream->send_window -= frame_size;
[1597]             stream->queued++;
[1598]         }
[1599] 
[1600]         if (in == NULL) {
[1601] 
[1602]             if (trailers != NGX_HTTP_V2_NO_TRAILERS) {
[1603]                 ngx_http_v2_queue_frame(h2c, trailers);
[1604]                 stream->queued++;
[1605]             }
[1606] 
[1607]             break;
[1608]         }
[1609] 
[1610]         limit -= frame_size;
[1611] 
[1612]         if (limit == 0) {
[1613]             break;
[1614]         }
[1615]     }
[1616] 
[1617]     if (offset) {
[1618]         cl = ngx_http_v2_filter_get_shadow(stream, in->buf, offset, size);
[1619]         if (cl == NULL) {
[1620]             return NGX_CHAIN_ERROR;
[1621]         }
[1622] 
[1623]         in->buf = cl->buf;
[1624]         ngx_free_chain(r->pool, cl);
[1625]     }
[1626] 
[1627]     if (ngx_http_v2_filter_send(fc, stream) == NGX_ERROR) {
[1628]         return NGX_CHAIN_ERROR;
[1629]     }
[1630] 
[1631]     if (in && ngx_http_v2_flow_control(h2c, stream) == NGX_DECLINED) {
[1632]         fc->write->active = 1;
[1633]         fc->write->ready = 0;
[1634]     }
[1635] 
[1636]     return in;
[1637] }
[1638] 
[1639] 
[1640] static ngx_chain_t *
[1641] ngx_http_v2_filter_get_shadow(ngx_http_v2_stream_t *stream, ngx_buf_t *buf,
[1642]     off_t offset, off_t size)
[1643] {
[1644]     ngx_buf_t    *chunk;
[1645]     ngx_chain_t  *cl;
[1646] 
[1647]     cl = ngx_chain_get_free_buf(stream->request->pool, &stream->free_bufs);
[1648]     if (cl == NULL) {
[1649]         return NULL;
[1650]     }
[1651] 
[1652]     chunk = cl->buf;
[1653] 
[1654]     ngx_memcpy(chunk, buf, sizeof(ngx_buf_t));
[1655] 
[1656]     chunk->tag = (ngx_buf_tag_t) &ngx_http_v2_filter_get_shadow;
[1657]     chunk->shadow = buf;
[1658] 
[1659]     if (ngx_buf_in_memory(chunk)) {
[1660]         chunk->pos += offset;
[1661]         chunk->last = chunk->pos + size;
[1662]     }
[1663] 
[1664]     if (chunk->in_file) {
[1665]         chunk->file_pos += offset;
[1666]         chunk->file_last = chunk->file_pos + size;
[1667]     }
[1668] 
[1669]     return cl;
[1670] }
[1671] 
[1672] 
[1673] static ngx_http_v2_out_frame_t *
[1674] ngx_http_v2_filter_get_data_frame(ngx_http_v2_stream_t *stream,
[1675]     size_t len, ngx_chain_t *first, ngx_chain_t *last)
[1676] {
[1677]     u_char                     flags;
[1678]     ngx_buf_t                 *buf;
[1679]     ngx_chain_t               *cl;
[1680]     ngx_http_v2_out_frame_t   *frame;
[1681]     ngx_http_v2_connection_t  *h2c;
[1682] 
[1683]     frame = stream->free_frames;
[1684]     h2c = stream->connection;
[1685] 
[1686]     if (frame) {
[1687]         stream->free_frames = frame->next;
[1688] 
[1689]     } else if (h2c->frames < 10000) {
[1690]         frame = ngx_palloc(stream->request->pool,
[1691]                            sizeof(ngx_http_v2_out_frame_t));
[1692]         if (frame == NULL) {
[1693]             return NULL;
[1694]         }
[1695] 
[1696]         stream->frames++;
[1697]         h2c->frames++;
[1698] 
[1699]     } else {
[1700]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1701]                       "http2 flood detected");
[1702] 
[1703]         h2c->connection->error = 1;
[1704]         return NULL;
[1705]     }
[1706] 
[1707]     flags = last->buf->last_buf ? NGX_HTTP_V2_END_STREAM_FLAG : 0;
[1708] 
[1709]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
[1710]                    "http2:%ui create DATA frame %p: len:%uz flags:%ui",
[1711]                    stream->node->id, frame, len, (ngx_uint_t) flags);
[1712] 
[1713]     cl = ngx_chain_get_free_buf(stream->request->pool,
[1714]                                 &stream->free_frame_headers);
[1715]     if (cl == NULL) {
[1716]         return NULL;
[1717]     }
[1718] 
[1719]     buf = cl->buf;
[1720] 
[1721]     if (buf->start == NULL) {
[1722]         buf->start = ngx_palloc(stream->request->pool,
[1723]                                 NGX_HTTP_V2_FRAME_HEADER_SIZE);
[1724]         if (buf->start == NULL) {
[1725]             return NULL;
[1726]         }
[1727] 
[1728]         buf->end = buf->start + NGX_HTTP_V2_FRAME_HEADER_SIZE;
[1729]         buf->last = buf->end;
[1730] 
[1731]         buf->tag = (ngx_buf_tag_t) &ngx_http_v2_module;
[1732]         buf->memory = 1;
[1733]     }
[1734] 
[1735]     buf->pos = buf->start;
[1736]     buf->last = buf->pos;
[1737] 
[1738]     buf->last = ngx_http_v2_write_len_and_type(buf->last, len,
[1739]                                                NGX_HTTP_V2_DATA_FRAME);
[1740]     *buf->last++ = flags;
[1741] 
[1742]     buf->last = ngx_http_v2_write_sid(buf->last, stream->node->id);
[1743] 
[1744]     cl->next = first;
[1745]     first = cl;
[1746] 
[1747]     last->buf->flush = 1;
[1748] 
[1749]     frame->first = first;
[1750]     frame->last = last;
[1751]     frame->handler = ngx_http_v2_data_frame_handler;
[1752]     frame->stream = stream;
[1753]     frame->length = len;
[1754]     frame->blocked = 0;
[1755]     frame->fin = last->buf->last_buf;
[1756] 
[1757]     return frame;
[1758] }
[1759] 
[1760] 
[1761] static ngx_inline ngx_int_t
[1762] ngx_http_v2_flow_control(ngx_http_v2_connection_t *h2c,
[1763]     ngx_http_v2_stream_t *stream)
[1764] {
[1765]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1766]                    "http2:%ui windows: conn:%uz stream:%z",
[1767]                    stream->node->id, h2c->send_window, stream->send_window);
[1768] 
[1769]     if (stream->send_window <= 0) {
[1770]         stream->exhausted = 1;
[1771]         return NGX_DECLINED;
[1772]     }
[1773] 
[1774]     if (h2c->send_window == 0) {
[1775]         ngx_http_v2_waiting_queue(h2c, stream);
[1776]         return NGX_DECLINED;
[1777]     }
[1778] 
[1779]     return NGX_OK;
[1780] }
[1781] 
[1782] 
[1783] static void
[1784] ngx_http_v2_waiting_queue(ngx_http_v2_connection_t *h2c,
[1785]     ngx_http_v2_stream_t *stream)
[1786] {
[1787]     ngx_queue_t           *q;
[1788]     ngx_http_v2_stream_t  *s;
[1789] 
[1790]     if (stream->waiting) {
[1791]         return;
[1792]     }
[1793] 
[1794]     stream->waiting = 1;
[1795] 
[1796]     for (q = ngx_queue_last(&h2c->waiting);
[1797]          q != ngx_queue_sentinel(&h2c->waiting);
[1798]          q = ngx_queue_prev(q))
[1799]     {
[1800]         s = ngx_queue_data(q, ngx_http_v2_stream_t, queue);
[1801] 
[1802]         if (s->node->rank < stream->node->rank
[1803]             || (s->node->rank == stream->node->rank
[1804]                 && s->node->rel_weight >= stream->node->rel_weight))
[1805]         {
[1806]             break;
[1807]         }
[1808]     }
[1809] 
[1810]     ngx_queue_insert_after(q, &stream->queue);
[1811] }
[1812] 
[1813] 
[1814] static ngx_inline ngx_int_t
[1815] ngx_http_v2_filter_send(ngx_connection_t *fc, ngx_http_v2_stream_t *stream)
[1816] {
[1817]     ngx_connection_t  *c;
[1818] 
[1819]     c = stream->connection->connection;
[1820] 
[1821]     if (stream->queued == 0 && !c->buffered) {
[1822]         fc->buffered &= ~NGX_HTTP_V2_BUFFERED;
[1823]         return NGX_OK;
[1824]     }
[1825] 
[1826]     stream->blocked = 1;
[1827] 
[1828]     if (ngx_http_v2_send_output_queue(stream->connection) == NGX_ERROR) {
[1829]         fc->error = 1;
[1830]         return NGX_ERROR;
[1831]     }
[1832] 
[1833]     stream->blocked = 0;
[1834] 
[1835]     if (stream->queued) {
[1836]         fc->buffered |= NGX_HTTP_V2_BUFFERED;
[1837]         fc->write->active = 1;
[1838]         fc->write->ready = 0;
[1839]         return NGX_AGAIN;
[1840]     }
[1841] 
[1842]     fc->buffered &= ~NGX_HTTP_V2_BUFFERED;
[1843] 
[1844]     return NGX_OK;
[1845] }
[1846] 
[1847] 
[1848] static ngx_int_t
[1849] ngx_http_v2_headers_frame_handler(ngx_http_v2_connection_t *h2c,
[1850]     ngx_http_v2_out_frame_t *frame)
[1851] {
[1852]     ngx_chain_t           *cl, *ln;
[1853]     ngx_http_v2_stream_t  *stream;
[1854] 
[1855]     stream = frame->stream;
[1856]     cl = frame->first;
[1857] 
[1858]     for ( ;; ) {
[1859]         if (cl->buf->pos != cl->buf->last) {
[1860]             frame->first = cl;
[1861] 
[1862]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1863]                            "http2:%ui HEADERS frame %p was sent partially",
[1864]                            stream->node->id, frame);
[1865] 
[1866]             return NGX_AGAIN;
[1867]         }
[1868] 
[1869]         ln = cl->next;
[1870] 
[1871]         if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_v2_module) {
[1872]             cl->next = stream->free_frame_headers;
[1873]             stream->free_frame_headers = cl;
[1874] 
[1875]         } else {
[1876]             cl->next = stream->free_bufs;
[1877]             stream->free_bufs = cl;
[1878]         }
[1879] 
[1880]         if (cl == frame->last) {
[1881]             break;
[1882]         }
[1883] 
[1884]         cl = ln;
[1885]     }
[1886] 
[1887]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1888]                    "http2:%ui HEADERS frame %p was sent",
[1889]                    stream->node->id, frame);
[1890] 
[1891]     stream->request->header_size += NGX_HTTP_V2_FRAME_HEADER_SIZE
[1892]                                     + frame->length;
[1893] 
[1894]     h2c->payload_bytes += frame->length;
[1895] 
[1896]     ngx_http_v2_handle_frame(stream, frame);
[1897] 
[1898]     ngx_http_v2_handle_stream(h2c, stream);
[1899] 
[1900]     return NGX_OK;
[1901] }
[1902] 
[1903] 
[1904] static ngx_int_t
[1905] ngx_http_v2_push_frame_handler(ngx_http_v2_connection_t *h2c,
[1906]     ngx_http_v2_out_frame_t *frame)
[1907] {
[1908]     ngx_chain_t           *cl, *ln;
[1909]     ngx_http_v2_stream_t  *stream;
[1910] 
[1911]     stream = frame->stream;
[1912]     cl = frame->first;
[1913] 
[1914]     for ( ;; ) {
[1915]         if (cl->buf->pos != cl->buf->last) {
[1916]             frame->first = cl;
[1917] 
[1918]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1919]                            "http2:%ui PUSH_PROMISE frame %p was sent partially",
[1920]                            stream->node->id, frame);
[1921] 
[1922]             return NGX_AGAIN;
[1923]         }
[1924] 
[1925]         ln = cl->next;
[1926] 
[1927]         if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_v2_module) {
[1928]             cl->next = stream->free_frame_headers;
[1929]             stream->free_frame_headers = cl;
[1930] 
[1931]         } else {
[1932]             cl->next = stream->free_bufs;
[1933]             stream->free_bufs = cl;
[1934]         }
[1935] 
[1936]         if (cl == frame->last) {
[1937]             break;
[1938]         }
[1939] 
[1940]         cl = ln;
[1941]     }
[1942] 
[1943]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1944]                    "http2:%ui PUSH_PROMISE frame %p was sent",
[1945]                    stream->node->id, frame);
[1946] 
[1947]     stream->request->header_size += NGX_HTTP_V2_FRAME_HEADER_SIZE
[1948]                                     + frame->length;
[1949] 
[1950]     h2c->payload_bytes += frame->length;
[1951] 
[1952]     ngx_http_v2_handle_frame(stream, frame);
[1953] 
[1954]     ngx_http_v2_handle_stream(h2c, stream);
[1955] 
[1956]     return NGX_OK;
[1957] }
[1958] 
[1959] 
[1960] static ngx_int_t
[1961] ngx_http_v2_data_frame_handler(ngx_http_v2_connection_t *h2c,
[1962]     ngx_http_v2_out_frame_t *frame)
[1963] {
[1964]     ngx_buf_t             *buf;
[1965]     ngx_chain_t           *cl, *ln;
[1966]     ngx_http_v2_stream_t  *stream;
[1967] 
[1968]     stream = frame->stream;
[1969]     cl = frame->first;
[1970] 
[1971]     if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_v2_module) {
[1972] 
[1973]         if (cl->buf->pos != cl->buf->last) {
[1974]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1975]                            "http2:%ui DATA frame %p was sent partially",
[1976]                            stream->node->id, frame);
[1977] 
[1978]             return NGX_AGAIN;
[1979]         }
[1980] 
[1981]         ln = cl->next;
[1982] 
[1983]         cl->next = stream->free_frame_headers;
[1984]         stream->free_frame_headers = cl;
[1985] 
[1986]         if (cl == frame->last) {
[1987]             goto done;
[1988]         }
[1989] 
[1990]         cl = ln;
[1991]     }
[1992] 
[1993]     for ( ;; ) {
[1994]         if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_v2_filter_get_shadow) {
[1995]             buf = cl->buf->shadow;
[1996] 
[1997]             if (ngx_buf_in_memory(buf)) {
[1998]                 buf->pos = cl->buf->pos;
[1999]             }
[2000] 
[2001]             if (buf->in_file) {
[2002]                 buf->file_pos = cl->buf->file_pos;
[2003]             }
[2004]         }
[2005] 
[2006]         if (ngx_buf_size(cl->buf) != 0) {
[2007] 
[2008]             if (cl != frame->first) {
[2009]                 frame->first = cl;
[2010]                 ngx_http_v2_handle_stream(h2c, stream);
[2011]             }
[2012] 
[2013]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2014]                            "http2:%ui DATA frame %p was sent partially",
[2015]                            stream->node->id, frame);
[2016] 
[2017]             return NGX_AGAIN;
[2018]         }
[2019] 
[2020]         ln = cl->next;
[2021] 
[2022]         if (cl->buf->tag == (ngx_buf_tag_t) &ngx_http_v2_filter_get_shadow) {
[2023]             cl->next = stream->free_bufs;
[2024]             stream->free_bufs = cl;
[2025] 
[2026]         } else {
[2027]             ngx_free_chain(stream->request->pool, cl);
[2028]         }
[2029] 
[2030]         if (cl == frame->last) {
[2031]             goto done;
[2032]         }
[2033] 
[2034]         cl = ln;
[2035]     }
[2036] 
[2037] done:
[2038] 
[2039]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2040]                    "http2:%ui DATA frame %p was sent",
[2041]                    stream->node->id, frame);
[2042] 
[2043]     stream->request->header_size += NGX_HTTP_V2_FRAME_HEADER_SIZE;
[2044] 
[2045]     h2c->payload_bytes += frame->length;
[2046] 
[2047]     ngx_http_v2_handle_frame(stream, frame);
[2048] 
[2049]     ngx_http_v2_handle_stream(h2c, stream);
[2050] 
[2051]     return NGX_OK;
[2052] }
[2053] 
[2054] 
[2055] static ngx_inline void
[2056] ngx_http_v2_handle_frame(ngx_http_v2_stream_t *stream,
[2057]     ngx_http_v2_out_frame_t *frame)
[2058] {
[2059]     ngx_http_request_t        *r;
[2060]     ngx_http_v2_connection_t  *h2c;
[2061] 
[2062]     r = stream->request;
[2063] 
[2064]     r->connection->sent += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
[2065] 
[2066]     h2c = stream->connection;
[2067] 
[2068]     h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
[2069] 
[2070]     if (frame->fin) {
[2071]         stream->out_closed = 1;
[2072]     }
[2073] 
[2074]     frame->next = stream->free_frames;
[2075]     stream->free_frames = frame;
[2076] 
[2077]     stream->queued--;
[2078] }
[2079] 
[2080] 
[2081] static ngx_inline void
[2082] ngx_http_v2_handle_stream(ngx_http_v2_connection_t *h2c,
[2083]     ngx_http_v2_stream_t *stream)
[2084] {
[2085]     ngx_event_t       *wev;
[2086]     ngx_connection_t  *fc;
[2087] 
[2088]     if (stream->waiting || stream->blocked) {
[2089]         return;
[2090]     }
[2091] 
[2092]     fc = stream->request->connection;
[2093] 
[2094]     if (!fc->error && stream->exhausted) {
[2095]         return;
[2096]     }
[2097] 
[2098]     wev = fc->write;
[2099] 
[2100]     wev->active = 0;
[2101]     wev->ready = 1;
[2102] 
[2103]     if (!fc->error && wev->delayed) {
[2104]         return;
[2105]     }
[2106] 
[2107]     ngx_post_event(wev, &ngx_posted_events);
[2108] }
[2109] 
[2110] 
[2111] static void
[2112] ngx_http_v2_filter_cleanup(void *data)
[2113] {
[2114]     ngx_http_v2_stream_t *stream = data;
[2115] 
[2116]     size_t                     window;
[2117]     ngx_event_t               *wev;
[2118]     ngx_queue_t               *q;
[2119]     ngx_http_v2_out_frame_t   *frame, **fn;
[2120]     ngx_http_v2_connection_t  *h2c;
[2121] 
[2122]     if (stream->waiting) {
[2123]         stream->waiting = 0;
[2124]         ngx_queue_remove(&stream->queue);
[2125]     }
[2126] 
[2127]     if (stream->queued == 0) {
[2128]         return;
[2129]     }
[2130] 
[2131]     window = 0;
[2132]     h2c = stream->connection;
[2133]     fn = &h2c->last_out;
[2134] 
[2135]     for ( ;; ) {
[2136]         frame = *fn;
[2137] 
[2138]         if (frame == NULL) {
[2139]             break;
[2140]         }
[2141] 
[2142]         if (frame->stream == stream && !frame->blocked) {
[2143]             *fn = frame->next;
[2144] 
[2145]             window += frame->length;
[2146] 
[2147]             if (--stream->queued == 0) {
[2148]                 break;
[2149]             }
[2150] 
[2151]             continue;
[2152]         }
[2153] 
[2154]         fn = &frame->next;
[2155]     }
[2156] 
[2157]     if (h2c->send_window == 0 && window) {
[2158] 
[2159]         while (!ngx_queue_empty(&h2c->waiting)) {
[2160]             q = ngx_queue_head(&h2c->waiting);
[2161] 
[2162]             ngx_queue_remove(q);
[2163] 
[2164]             stream = ngx_queue_data(q, ngx_http_v2_stream_t, queue);
[2165] 
[2166]             stream->waiting = 0;
[2167] 
[2168]             wev = stream->request->connection->write;
[2169] 
[2170]             wev->active = 0;
[2171]             wev->ready = 1;
[2172] 
[2173]             if (!wev->delayed) {
[2174]                 ngx_post_event(wev, &ngx_posted_events);
[2175]             }
[2176]         }
[2177]     }
[2178] 
[2179]     h2c->send_window += window;
[2180] }
[2181] 
[2182] 
[2183] static ngx_int_t
[2184] ngx_http_v2_filter_init(ngx_conf_t *cf)
[2185] {
[2186]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[2187]     ngx_http_top_header_filter = ngx_http_v2_header_filter;
[2188] 
[2189]     return NGX_OK;
[2190] }
