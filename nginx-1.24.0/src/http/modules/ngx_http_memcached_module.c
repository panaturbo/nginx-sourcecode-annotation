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
[13] typedef struct {
[14]     ngx_http_upstream_conf_t   upstream;
[15]     ngx_int_t                  index;
[16]     ngx_uint_t                 gzip_flag;
[17] } ngx_http_memcached_loc_conf_t;
[18] 
[19] 
[20] typedef struct {
[21]     size_t                     rest;
[22]     ngx_http_request_t        *request;
[23]     ngx_str_t                  key;
[24] } ngx_http_memcached_ctx_t;
[25] 
[26] 
[27] static ngx_int_t ngx_http_memcached_create_request(ngx_http_request_t *r);
[28] static ngx_int_t ngx_http_memcached_reinit_request(ngx_http_request_t *r);
[29] static ngx_int_t ngx_http_memcached_process_header(ngx_http_request_t *r);
[30] static ngx_int_t ngx_http_memcached_filter_init(void *data);
[31] static ngx_int_t ngx_http_memcached_filter(void *data, ssize_t bytes);
[32] static void ngx_http_memcached_abort_request(ngx_http_request_t *r);
[33] static void ngx_http_memcached_finalize_request(ngx_http_request_t *r,
[34]     ngx_int_t rc);
[35] 
[36] static void *ngx_http_memcached_create_loc_conf(ngx_conf_t *cf);
[37] static char *ngx_http_memcached_merge_loc_conf(ngx_conf_t *cf,
[38]     void *parent, void *child);
[39] 
[40] static char *ngx_http_memcached_pass(ngx_conf_t *cf, ngx_command_t *cmd,
[41]     void *conf);
[42] 
[43] 
[44] static ngx_conf_bitmask_t  ngx_http_memcached_next_upstream_masks[] = {
[45]     { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
[46]     { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
[47]     { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
[48]     { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
[49]     { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
[50]     { ngx_null_string, 0 }
[51] };
[52] 
[53] 
[54] static ngx_command_t  ngx_http_memcached_commands[] = {
[55] 
[56]     { ngx_string("memcached_pass"),
[57]       NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[58]       ngx_http_memcached_pass,
[59]       NGX_HTTP_LOC_CONF_OFFSET,
[60]       0,
[61]       NULL },
[62] 
[63]     { ngx_string("memcached_bind"),
[64]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[65]       ngx_http_upstream_bind_set_slot,
[66]       NGX_HTTP_LOC_CONF_OFFSET,
[67]       offsetof(ngx_http_memcached_loc_conf_t, upstream.local),
[68]       NULL },
[69] 
[70]     { ngx_string("memcached_socket_keepalive"),
[71]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[72]       ngx_conf_set_flag_slot,
[73]       NGX_HTTP_LOC_CONF_OFFSET,
[74]       offsetof(ngx_http_memcached_loc_conf_t, upstream.socket_keepalive),
[75]       NULL },
[76] 
[77]     { ngx_string("memcached_connect_timeout"),
[78]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[79]       ngx_conf_set_msec_slot,
[80]       NGX_HTTP_LOC_CONF_OFFSET,
[81]       offsetof(ngx_http_memcached_loc_conf_t, upstream.connect_timeout),
[82]       NULL },
[83] 
[84]     { ngx_string("memcached_send_timeout"),
[85]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[86]       ngx_conf_set_msec_slot,
[87]       NGX_HTTP_LOC_CONF_OFFSET,
[88]       offsetof(ngx_http_memcached_loc_conf_t, upstream.send_timeout),
[89]       NULL },
[90] 
[91]     { ngx_string("memcached_buffer_size"),
[92]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[93]       ngx_conf_set_size_slot,
[94]       NGX_HTTP_LOC_CONF_OFFSET,
[95]       offsetof(ngx_http_memcached_loc_conf_t, upstream.buffer_size),
[96]       NULL },
[97] 
[98]     { ngx_string("memcached_read_timeout"),
[99]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[100]       ngx_conf_set_msec_slot,
[101]       NGX_HTTP_LOC_CONF_OFFSET,
[102]       offsetof(ngx_http_memcached_loc_conf_t, upstream.read_timeout),
[103]       NULL },
[104] 
[105]     { ngx_string("memcached_next_upstream"),
[106]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[107]       ngx_conf_set_bitmask_slot,
[108]       NGX_HTTP_LOC_CONF_OFFSET,
[109]       offsetof(ngx_http_memcached_loc_conf_t, upstream.next_upstream),
[110]       &ngx_http_memcached_next_upstream_masks },
[111] 
[112]     { ngx_string("memcached_next_upstream_tries"),
[113]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[114]       ngx_conf_set_num_slot,
[115]       NGX_HTTP_LOC_CONF_OFFSET,
[116]       offsetof(ngx_http_memcached_loc_conf_t, upstream.next_upstream_tries),
[117]       NULL },
[118] 
[119]     { ngx_string("memcached_next_upstream_timeout"),
[120]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[121]       ngx_conf_set_msec_slot,
[122]       NGX_HTTP_LOC_CONF_OFFSET,
[123]       offsetof(ngx_http_memcached_loc_conf_t, upstream.next_upstream_timeout),
[124]       NULL },
[125] 
[126]     { ngx_string("memcached_gzip_flag"),
[127]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[128]       ngx_conf_set_num_slot,
[129]       NGX_HTTP_LOC_CONF_OFFSET,
[130]       offsetof(ngx_http_memcached_loc_conf_t, gzip_flag),
[131]       NULL },
[132] 
[133]       ngx_null_command
[134] };
[135] 
[136] 
[137] static ngx_http_module_t  ngx_http_memcached_module_ctx = {
[138]     NULL,                                  /* preconfiguration */
[139]     NULL,                                  /* postconfiguration */
[140] 
[141]     NULL,                                  /* create main configuration */
[142]     NULL,                                  /* init main configuration */
[143] 
[144]     NULL,                                  /* create server configuration */
[145]     NULL,                                  /* merge server configuration */
[146] 
[147]     ngx_http_memcached_create_loc_conf,    /* create location configuration */
[148]     ngx_http_memcached_merge_loc_conf      /* merge location configuration */
[149] };
[150] 
[151] 
[152] ngx_module_t  ngx_http_memcached_module = {
[153]     NGX_MODULE_V1,
[154]     &ngx_http_memcached_module_ctx,        /* module context */
[155]     ngx_http_memcached_commands,           /* module directives */
[156]     NGX_HTTP_MODULE,                       /* module type */
[157]     NULL,                                  /* init master */
[158]     NULL,                                  /* init module */
[159]     NULL,                                  /* init process */
[160]     NULL,                                  /* init thread */
[161]     NULL,                                  /* exit thread */
[162]     NULL,                                  /* exit process */
[163]     NULL,                                  /* exit master */
[164]     NGX_MODULE_V1_PADDING
[165] };
[166] 
[167] 
[168] static ngx_str_t  ngx_http_memcached_key = ngx_string("memcached_key");
[169] 
[170] 
[171] #define NGX_HTTP_MEMCACHED_END   (sizeof(ngx_http_memcached_end) - 1)
[172] static u_char  ngx_http_memcached_end[] = CRLF "END" CRLF;
[173] 
[174] 
[175] static ngx_int_t
[176] ngx_http_memcached_handler(ngx_http_request_t *r)
[177] {
[178]     ngx_int_t                       rc;
[179]     ngx_http_upstream_t            *u;
[180]     ngx_http_memcached_ctx_t       *ctx;
[181]     ngx_http_memcached_loc_conf_t  *mlcf;
[182] 
[183]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[184]         return NGX_HTTP_NOT_ALLOWED;
[185]     }
[186] 
[187]     rc = ngx_http_discard_request_body(r);
[188] 
[189]     if (rc != NGX_OK) {
[190]         return rc;
[191]     }
[192] 
[193]     if (ngx_http_set_content_type(r) != NGX_OK) {
[194]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[195]     }
[196] 
[197]     if (ngx_http_upstream_create(r) != NGX_OK) {
[198]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[199]     }
[200] 
[201]     u = r->upstream;
[202] 
[203]     ngx_str_set(&u->schema, "memcached://");
[204]     u->output.tag = (ngx_buf_tag_t) &ngx_http_memcached_module;
[205] 
[206]     mlcf = ngx_http_get_module_loc_conf(r, ngx_http_memcached_module);
[207] 
[208]     u->conf = &mlcf->upstream;
[209] 
[210]     u->create_request = ngx_http_memcached_create_request;
[211]     u->reinit_request = ngx_http_memcached_reinit_request;
[212]     u->process_header = ngx_http_memcached_process_header;
[213]     u->abort_request = ngx_http_memcached_abort_request;
[214]     u->finalize_request = ngx_http_memcached_finalize_request;
[215] 
[216]     ctx = ngx_palloc(r->pool, sizeof(ngx_http_memcached_ctx_t));
[217]     if (ctx == NULL) {
[218]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[219]     }
[220] 
[221]     ctx->request = r;
[222] 
[223]     ngx_http_set_ctx(r, ctx, ngx_http_memcached_module);
[224] 
[225]     u->input_filter_init = ngx_http_memcached_filter_init;
[226]     u->input_filter = ngx_http_memcached_filter;
[227]     u->input_filter_ctx = ctx;
[228] 
[229]     r->main->count++;
[230] 
[231]     ngx_http_upstream_init(r);
[232] 
[233]     return NGX_DONE;
[234] }
[235] 
[236] 
[237] static ngx_int_t
[238] ngx_http_memcached_create_request(ngx_http_request_t *r)
[239] {
[240]     size_t                          len;
[241]     uintptr_t                       escape;
[242]     ngx_buf_t                      *b;
[243]     ngx_chain_t                    *cl;
[244]     ngx_http_memcached_ctx_t       *ctx;
[245]     ngx_http_variable_value_t      *vv;
[246]     ngx_http_memcached_loc_conf_t  *mlcf;
[247] 
[248]     mlcf = ngx_http_get_module_loc_conf(r, ngx_http_memcached_module);
[249] 
[250]     vv = ngx_http_get_indexed_variable(r, mlcf->index);
[251] 
[252]     if (vv == NULL || vv->not_found || vv->len == 0) {
[253]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[254]                       "the \"$memcached_key\" variable is not set");
[255]         return NGX_ERROR;
[256]     }
[257] 
[258]     escape = 2 * ngx_escape_uri(NULL, vv->data, vv->len, NGX_ESCAPE_MEMCACHED);
[259] 
[260]     len = sizeof("get ") - 1 + vv->len + escape + sizeof(CRLF) - 1;
[261] 
[262]     b = ngx_create_temp_buf(r->pool, len);
[263]     if (b == NULL) {
[264]         return NGX_ERROR;
[265]     }
[266] 
[267]     cl = ngx_alloc_chain_link(r->pool);
[268]     if (cl == NULL) {
[269]         return NGX_ERROR;
[270]     }
[271] 
[272]     cl->buf = b;
[273]     cl->next = NULL;
[274] 
[275]     r->upstream->request_bufs = cl;
[276] 
[277]     *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';
[278] 
[279]     ctx = ngx_http_get_module_ctx(r, ngx_http_memcached_module);
[280] 
[281]     ctx->key.data = b->last;
[282] 
[283]     if (escape == 0) {
[284]         b->last = ngx_copy(b->last, vv->data, vv->len);
[285] 
[286]     } else {
[287]         b->last = (u_char *) ngx_escape_uri(b->last, vv->data, vv->len,
[288]                                             NGX_ESCAPE_MEMCACHED);
[289]     }
[290] 
[291]     ctx->key.len = b->last - ctx->key.data;
[292] 
[293]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[294]                    "http memcached request: \"%V\"", &ctx->key);
[295] 
[296]     *b->last++ = CR; *b->last++ = LF;
[297] 
[298]     return NGX_OK;
[299] }
[300] 
[301] 
[302] static ngx_int_t
[303] ngx_http_memcached_reinit_request(ngx_http_request_t *r)
[304] {
[305]     return NGX_OK;
[306] }
[307] 
[308] 
[309] static ngx_int_t
[310] ngx_http_memcached_process_header(ngx_http_request_t *r)
[311] {
[312]     u_char                         *p, *start;
[313]     ngx_str_t                       line;
[314]     ngx_uint_t                      flags;
[315]     ngx_table_elt_t                *h;
[316]     ngx_http_upstream_t            *u;
[317]     ngx_http_memcached_ctx_t       *ctx;
[318]     ngx_http_memcached_loc_conf_t  *mlcf;
[319] 
[320]     u = r->upstream;
[321] 
[322]     for (p = u->buffer.pos; p < u->buffer.last; p++) {
[323]         if (*p == LF) {
[324]             goto found;
[325]         }
[326]     }
[327] 
[328]     return NGX_AGAIN;
[329] 
[330] found:
[331] 
[332]     line.data = u->buffer.pos;
[333]     line.len = p - u->buffer.pos;
[334] 
[335]     if (line.len == 0 || *(p - 1) != CR) {
[336]         goto no_valid;
[337]     }
[338] 
[339]     *p = '\0';
[340]     line.len--;
[341] 
[342]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[343]                    "memcached: \"%V\"", &line);
[344] 
[345]     p = u->buffer.pos;
[346] 
[347]     ctx = ngx_http_get_module_ctx(r, ngx_http_memcached_module);
[348]     mlcf = ngx_http_get_module_loc_conf(r, ngx_http_memcached_module);
[349] 
[350]     if (ngx_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {
[351] 
[352]         p += sizeof("VALUE ") - 1;
[353] 
[354]         if (ngx_strncmp(p, ctx->key.data, ctx->key.len) != 0) {
[355]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[356]                           "memcached sent invalid key in response \"%V\" "
[357]                           "for key \"%V\"",
[358]                           &line, &ctx->key);
[359] 
[360]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[361]         }
[362] 
[363]         p += ctx->key.len;
[364] 
[365]         if (*p++ != ' ') {
[366]             goto no_valid;
[367]         }
[368] 
[369]         /* flags */
[370] 
[371]         start = p;
[372] 
[373]         while (*p) {
[374]             if (*p++ == ' ') {
[375]                 if (mlcf->gzip_flag) {
[376]                     goto flags;
[377]                 } else {
[378]                     goto length;
[379]                 }
[380]             }
[381]         }
[382] 
[383]         goto no_valid;
[384] 
[385]     flags:
[386] 
[387]         flags = ngx_atoi(start, p - start - 1);
[388] 
[389]         if (flags == (ngx_uint_t) NGX_ERROR) {
[390]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[391]                           "memcached sent invalid flags in response \"%V\" "
[392]                           "for key \"%V\"",
[393]                           &line, &ctx->key);
[394]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[395]         }
[396] 
[397]         if (flags & mlcf->gzip_flag) {
[398]             h = ngx_list_push(&r->headers_out.headers);
[399]             if (h == NULL) {
[400]                 return NGX_ERROR;
[401]             }
[402] 
[403]             h->hash = 1;
[404]             h->next = NULL;
[405]             ngx_str_set(&h->key, "Content-Encoding");
[406]             ngx_str_set(&h->value, "gzip");
[407]             r->headers_out.content_encoding = h;
[408]         }
[409] 
[410]     length:
[411] 
[412]         start = p;
[413]         p = line.data + line.len;
[414] 
[415]         u->headers_in.content_length_n = ngx_atoof(start, p - start);
[416]         if (u->headers_in.content_length_n == NGX_ERROR) {
[417]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[418]                           "memcached sent invalid length in response \"%V\" "
[419]                           "for key \"%V\"",
[420]                           &line, &ctx->key);
[421]             return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[422]         }
[423] 
[424]         u->headers_in.status_n = 200;
[425]         u->state->status = 200;
[426]         u->buffer.pos = p + sizeof(CRLF) - 1;
[427] 
[428]         return NGX_OK;
[429]     }
[430] 
[431]     if (ngx_strcmp(p, "END\x0d") == 0) {
[432]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[433]                       "key: \"%V\" was not found by memcached", &ctx->key);
[434] 
[435]         u->headers_in.content_length_n = 0;
[436]         u->headers_in.status_n = 404;
[437]         u->state->status = 404;
[438]         u->buffer.pos = p + sizeof("END" CRLF) - 1;
[439]         u->keepalive = 1;
[440] 
[441]         return NGX_OK;
[442]     }
[443] 
[444] no_valid:
[445] 
[446]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[447]                   "memcached sent invalid response: \"%V\"", &line);
[448] 
[449]     return NGX_HTTP_UPSTREAM_INVALID_HEADER;
[450] }
[451] 
[452] 
[453] static ngx_int_t
[454] ngx_http_memcached_filter_init(void *data)
[455] {
[456]     ngx_http_memcached_ctx_t  *ctx = data;
[457] 
[458]     ngx_http_upstream_t  *u;
[459] 
[460]     u = ctx->request->upstream;
[461] 
[462]     if (u->headers_in.status_n != 404) {
[463]         u->length = u->headers_in.content_length_n + NGX_HTTP_MEMCACHED_END;
[464]         ctx->rest = NGX_HTTP_MEMCACHED_END;
[465] 
[466]     } else {
[467]         u->length = 0;
[468]     }
[469] 
[470]     return NGX_OK;
[471] }
[472] 
[473] 
[474] static ngx_int_t
[475] ngx_http_memcached_filter(void *data, ssize_t bytes)
[476] {
[477]     ngx_http_memcached_ctx_t  *ctx = data;
[478] 
[479]     u_char               *last;
[480]     ngx_buf_t            *b;
[481]     ngx_chain_t          *cl, **ll;
[482]     ngx_http_upstream_t  *u;
[483] 
[484]     u = ctx->request->upstream;
[485]     b = &u->buffer;
[486] 
[487]     if (u->length == (ssize_t) ctx->rest) {
[488] 
[489]         if (bytes > u->length
[490]             || ngx_strncmp(b->last,
[491]                    ngx_http_memcached_end + NGX_HTTP_MEMCACHED_END - ctx->rest,
[492]                    bytes)
[493]                != 0)
[494]         {
[495]             ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
[496]                           "memcached sent invalid trailer");
[497] 
[498]             u->length = 0;
[499]             ctx->rest = 0;
[500] 
[501]             return NGX_OK;
[502]         }
[503] 
[504]         u->length -= bytes;
[505]         ctx->rest -= bytes;
[506] 
[507]         if (u->length == 0) {
[508]             u->keepalive = 1;
[509]         }
[510] 
[511]         return NGX_OK;
[512]     }
[513] 
[514]     for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
[515]         ll = &cl->next;
[516]     }
[517] 
[518]     cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
[519]     if (cl == NULL) {
[520]         return NGX_ERROR;
[521]     }
[522] 
[523]     cl->buf->flush = 1;
[524]     cl->buf->memory = 1;
[525] 
[526]     *ll = cl;
[527] 
[528]     last = b->last;
[529]     cl->buf->pos = last;
[530]     b->last += bytes;
[531]     cl->buf->last = b->last;
[532]     cl->buf->tag = u->output.tag;
[533] 
[534]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
[535]                    "memcached filter bytes:%z size:%z length:%O rest:%z",
[536]                    bytes, b->last - b->pos, u->length, ctx->rest);
[537] 
[538]     if (bytes <= (ssize_t) (u->length - NGX_HTTP_MEMCACHED_END)) {
[539]         u->length -= bytes;
[540]         return NGX_OK;
[541]     }
[542] 
[543]     last += (size_t) (u->length - NGX_HTTP_MEMCACHED_END);
[544] 
[545]     if (bytes > u->length
[546]         || ngx_strncmp(last, ngx_http_memcached_end, b->last - last) != 0)
[547]     {
[548]         ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
[549]                       "memcached sent invalid trailer");
[550] 
[551]         b->last = last;
[552]         cl->buf->last = last;
[553]         u->length = 0;
[554]         ctx->rest = 0;
[555] 
[556]         return NGX_OK;
[557]     }
[558] 
[559]     ctx->rest -= b->last - last;
[560]     b->last = last;
[561]     cl->buf->last = last;
[562]     u->length = ctx->rest;
[563] 
[564]     if (u->length == 0) {
[565]         u->keepalive = 1;
[566]     }
[567] 
[568]     return NGX_OK;
[569] }
[570] 
[571] 
[572] static void
[573] ngx_http_memcached_abort_request(ngx_http_request_t *r)
[574] {
[575]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[576]                    "abort http memcached request");
[577]     return;
[578] }
[579] 
[580] 
[581] static void
[582] ngx_http_memcached_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
[583] {
[584]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[585]                    "finalize http memcached request");
[586]     return;
[587] }
[588] 
[589] 
[590] static void *
[591] ngx_http_memcached_create_loc_conf(ngx_conf_t *cf)
[592] {
[593]     ngx_http_memcached_loc_conf_t  *conf;
[594] 
[595]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_memcached_loc_conf_t));
[596]     if (conf == NULL) {
[597]         return NULL;
[598]     }
[599] 
[600]     /*
[601]      * set by ngx_pcalloc():
[602]      *
[603]      *     conf->upstream.bufs.num = 0;
[604]      *     conf->upstream.next_upstream = 0;
[605]      *     conf->upstream.temp_path = NULL;
[606]      */
[607] 
[608]     conf->upstream.local = NGX_CONF_UNSET_PTR;
[609]     conf->upstream.socket_keepalive = NGX_CONF_UNSET;
[610]     conf->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
[611]     conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
[612]     conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
[613]     conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
[614]     conf->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
[615] 
[616]     conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
[617] 
[618]     /* the hardcoded values */
[619]     conf->upstream.cyclic_temp_file = 0;
[620]     conf->upstream.buffering = 0;
[621]     conf->upstream.ignore_client_abort = 0;
[622]     conf->upstream.send_lowat = 0;
[623]     conf->upstream.bufs.num = 0;
[624]     conf->upstream.busy_buffers_size = 0;
[625]     conf->upstream.max_temp_file_size = 0;
[626]     conf->upstream.temp_file_write_size = 0;
[627]     conf->upstream.intercept_errors = 1;
[628]     conf->upstream.intercept_404 = 1;
[629]     conf->upstream.pass_request_headers = 0;
[630]     conf->upstream.pass_request_body = 0;
[631]     conf->upstream.force_ranges = 1;
[632] 
[633]     conf->index = NGX_CONF_UNSET;
[634]     conf->gzip_flag = NGX_CONF_UNSET_UINT;
[635] 
[636]     return conf;
[637] }
[638] 
[639] 
[640] static char *
[641] ngx_http_memcached_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[642] {
[643]     ngx_http_memcached_loc_conf_t *prev = parent;
[644]     ngx_http_memcached_loc_conf_t *conf = child;
[645] 
[646]     ngx_conf_merge_ptr_value(conf->upstream.local,
[647]                               prev->upstream.local, NULL);
[648] 
[649]     ngx_conf_merge_value(conf->upstream.socket_keepalive,
[650]                               prev->upstream.socket_keepalive, 0);
[651] 
[652]     ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries,
[653]                               prev->upstream.next_upstream_tries, 0);
[654] 
[655]     ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
[656]                               prev->upstream.connect_timeout, 60000);
[657] 
[658]     ngx_conf_merge_msec_value(conf->upstream.send_timeout,
[659]                               prev->upstream.send_timeout, 60000);
[660] 
[661]     ngx_conf_merge_msec_value(conf->upstream.read_timeout,
[662]                               prev->upstream.read_timeout, 60000);
[663] 
[664]     ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
[665]                               prev->upstream.next_upstream_timeout, 0);
[666] 
[667]     ngx_conf_merge_size_value(conf->upstream.buffer_size,
[668]                               prev->upstream.buffer_size,
[669]                               (size_t) ngx_pagesize);
[670] 
[671]     ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
[672]                               prev->upstream.next_upstream,
[673]                               (NGX_CONF_BITMASK_SET
[674]                                |NGX_HTTP_UPSTREAM_FT_ERROR
[675]                                |NGX_HTTP_UPSTREAM_FT_TIMEOUT));
[676] 
[677]     if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
[678]         conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
[679]                                        |NGX_HTTP_UPSTREAM_FT_OFF;
[680]     }
[681] 
[682]     if (conf->upstream.upstream == NULL) {
[683]         conf->upstream.upstream = prev->upstream.upstream;
[684]     }
[685] 
[686]     if (conf->index == NGX_CONF_UNSET) {
[687]         conf->index = prev->index;
[688]     }
[689] 
[690]     ngx_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);
[691] 
[692]     return NGX_CONF_OK;
[693] }
[694] 
[695] 
[696] static char *
[697] ngx_http_memcached_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[698] {
[699]     ngx_http_memcached_loc_conf_t *mlcf = conf;
[700] 
[701]     ngx_str_t                 *value;
[702]     ngx_url_t                  u;
[703]     ngx_http_core_loc_conf_t  *clcf;
[704] 
[705]     if (mlcf->upstream.upstream) {
[706]         return "is duplicate";
[707]     }
[708] 
[709]     value = cf->args->elts;
[710] 
[711]     ngx_memzero(&u, sizeof(ngx_url_t));
[712] 
[713]     u.url = value[1];
[714]     u.no_resolve = 1;
[715] 
[716]     mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
[717]     if (mlcf->upstream.upstream == NULL) {
[718]         return NGX_CONF_ERROR;
[719]     }
[720] 
[721]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[722] 
[723]     clcf->handler = ngx_http_memcached_handler;
[724] 
[725]     if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
[726]         clcf->auto_redirect = 1;
[727]     }
[728] 
[729]     mlcf->index = ngx_http_get_variable_index(cf, &ngx_http_memcached_key);
[730] 
[731]     if (mlcf->index == NGX_ERROR) {
[732]         return NGX_CONF_ERROR;
[733]     }
[734] 
[735]     return NGX_CONF_OK;
[736] }
