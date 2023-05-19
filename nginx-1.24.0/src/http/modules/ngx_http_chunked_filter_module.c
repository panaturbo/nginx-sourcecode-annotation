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
[14]     ngx_chain_t         *free;
[15]     ngx_chain_t         *busy;
[16] } ngx_http_chunked_filter_ctx_t;
[17] 
[18] 
[19] static ngx_int_t ngx_http_chunked_filter_init(ngx_conf_t *cf);
[20] static ngx_chain_t *ngx_http_chunked_create_trailers(ngx_http_request_t *r,
[21]     ngx_http_chunked_filter_ctx_t *ctx);
[22] 
[23] 
[24] static ngx_http_module_t  ngx_http_chunked_filter_module_ctx = {
[25]     NULL,                                  /* preconfiguration */
[26]     ngx_http_chunked_filter_init,          /* postconfiguration */
[27] 
[28]     NULL,                                  /* create main configuration */
[29]     NULL,                                  /* init main configuration */
[30] 
[31]     NULL,                                  /* create server configuration */
[32]     NULL,                                  /* merge server configuration */
[33] 
[34]     NULL,                                  /* create location configuration */
[35]     NULL                                   /* merge location configuration */
[36] };
[37] 
[38] 
[39] ngx_module_t  ngx_http_chunked_filter_module = {
[40]     NGX_MODULE_V1,
[41]     &ngx_http_chunked_filter_module_ctx,   /* module context */
[42]     NULL,                                  /* module directives */
[43]     NGX_HTTP_MODULE,                       /* module type */
[44]     NULL,                                  /* init master */
[45]     NULL,                                  /* init module */
[46]     NULL,                                  /* init process */
[47]     NULL,                                  /* init thread */
[48]     NULL,                                  /* exit thread */
[49]     NULL,                                  /* exit process */
[50]     NULL,                                  /* exit master */
[51]     NGX_MODULE_V1_PADDING
[52] };
[53] 
[54] 
[55] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[56] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[57] 
[58] 
[59] static ngx_int_t
[60] ngx_http_chunked_header_filter(ngx_http_request_t *r)
[61] {
[62]     ngx_http_core_loc_conf_t       *clcf;
[63]     ngx_http_chunked_filter_ctx_t  *ctx;
[64] 
[65]     if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED
[66]         || r->headers_out.status == NGX_HTTP_NO_CONTENT
[67]         || r->headers_out.status < NGX_HTTP_OK
[68]         || r != r->main
[69]         || r->method == NGX_HTTP_HEAD)
[70]     {
[71]         return ngx_http_next_header_filter(r);
[72]     }
[73] 
[74]     if (r->headers_out.content_length_n == -1
[75]         || r->expect_trailers)
[76]     {
[77]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[78] 
[79]         if (r->http_version >= NGX_HTTP_VERSION_11
[80]             && clcf->chunked_transfer_encoding)
[81]         {
[82]             if (r->expect_trailers) {
[83]                 ngx_http_clear_content_length(r);
[84]             }
[85] 
[86]             r->chunked = 1;
[87] 
[88]             ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_filter_ctx_t));
[89]             if (ctx == NULL) {
[90]                 return NGX_ERROR;
[91]             }
[92] 
[93]             ngx_http_set_ctx(r, ctx, ngx_http_chunked_filter_module);
[94] 
[95]         } else if (r->headers_out.content_length_n == -1) {
[96]             r->keepalive = 0;
[97]         }
[98]     }
[99] 
[100]     return ngx_http_next_header_filter(r);
[101] }
[102] 
[103] 
[104] static ngx_int_t
[105] ngx_http_chunked_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[106] {
[107]     u_char                         *chunk;
[108]     off_t                           size;
[109]     ngx_int_t                       rc;
[110]     ngx_buf_t                      *b;
[111]     ngx_chain_t                    *out, *cl, *tl, **ll;
[112]     ngx_http_chunked_filter_ctx_t  *ctx;
[113] 
[114]     if (in == NULL || !r->chunked || r->header_only) {
[115]         return ngx_http_next_body_filter(r, in);
[116]     }
[117] 
[118]     ctx = ngx_http_get_module_ctx(r, ngx_http_chunked_filter_module);
[119] 
[120]     out = NULL;
[121]     ll = &out;
[122] 
[123]     size = 0;
[124]     cl = in;
[125] 
[126]     for ( ;; ) {
[127]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[128]                        "http chunk: %O", ngx_buf_size(cl->buf));
[129] 
[130]         size += ngx_buf_size(cl->buf);
[131] 
[132]         if (cl->buf->flush
[133]             || cl->buf->sync
[134]             || ngx_buf_in_memory(cl->buf)
[135]             || cl->buf->in_file)
[136]         {
[137]             tl = ngx_alloc_chain_link(r->pool);
[138]             if (tl == NULL) {
[139]                 return NGX_ERROR;
[140]             }
[141] 
[142]             tl->buf = cl->buf;
[143]             *ll = tl;
[144]             ll = &tl->next;
[145]         }
[146] 
[147]         if (cl->next == NULL) {
[148]             break;
[149]         }
[150] 
[151]         cl = cl->next;
[152]     }
[153] 
[154]     if (size) {
[155]         tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[156]         if (tl == NULL) {
[157]             return NGX_ERROR;
[158]         }
[159] 
[160]         b = tl->buf;
[161]         chunk = b->start;
[162] 
[163]         if (chunk == NULL) {
[164]             /* the "0000000000000000" is 64-bit hexadecimal string */
[165] 
[166]             chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
[167]             if (chunk == NULL) {
[168]                 return NGX_ERROR;
[169]             }
[170] 
[171]             b->start = chunk;
[172]             b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
[173]         }
[174] 
[175]         b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
[176]         b->memory = 0;
[177]         b->temporary = 1;
[178]         b->pos = chunk;
[179]         b->last = ngx_sprintf(chunk, "%xO" CRLF, size);
[180] 
[181]         tl->next = out;
[182]         out = tl;
[183]     }
[184] 
[185]     if (cl->buf->last_buf) {
[186]         tl = ngx_http_chunked_create_trailers(r, ctx);
[187]         if (tl == NULL) {
[188]             return NGX_ERROR;
[189]         }
[190] 
[191]         cl->buf->last_buf = 0;
[192] 
[193]         *ll = tl;
[194] 
[195]         if (size == 0) {
[196]             tl->buf->pos += 2;
[197]         }
[198] 
[199]     } else if (size > 0) {
[200]         tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[201]         if (tl == NULL) {
[202]             return NGX_ERROR;
[203]         }
[204] 
[205]         b = tl->buf;
[206] 
[207]         b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
[208]         b->temporary = 0;
[209]         b->memory = 1;
[210]         b->pos = (u_char *) CRLF;
[211]         b->last = b->pos + 2;
[212] 
[213]         *ll = tl;
[214] 
[215]     } else {
[216]         *ll = NULL;
[217]     }
[218] 
[219]     rc = ngx_http_next_body_filter(r, out);
[220] 
[221]     ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
[222]                             (ngx_buf_tag_t) &ngx_http_chunked_filter_module);
[223] 
[224]     return rc;
[225] }
[226] 
[227] 
[228] static ngx_chain_t *
[229] ngx_http_chunked_create_trailers(ngx_http_request_t *r,
[230]     ngx_http_chunked_filter_ctx_t *ctx)
[231] {
[232]     size_t            len;
[233]     ngx_buf_t        *b;
[234]     ngx_uint_t        i;
[235]     ngx_chain_t      *cl;
[236]     ngx_list_part_t  *part;
[237]     ngx_table_elt_t  *header;
[238] 
[239]     len = 0;
[240] 
[241]     part = &r->headers_out.trailers.part;
[242]     header = part->elts;
[243] 
[244]     for (i = 0; /* void */; i++) {
[245] 
[246]         if (i >= part->nelts) {
[247]             if (part->next == NULL) {
[248]                 break;
[249]             }
[250] 
[251]             part = part->next;
[252]             header = part->elts;
[253]             i = 0;
[254]         }
[255] 
[256]         if (header[i].hash == 0) {
[257]             continue;
[258]         }
[259] 
[260]         len += header[i].key.len + sizeof(": ") - 1
[261]                + header[i].value.len + sizeof(CRLF) - 1;
[262]     }
[263] 
[264]     cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
[265]     if (cl == NULL) {
[266]         return NULL;
[267]     }
[268] 
[269]     b = cl->buf;
[270] 
[271]     b->tag = (ngx_buf_tag_t) &ngx_http_chunked_filter_module;
[272]     b->temporary = 0;
[273]     b->memory = 1;
[274]     b->last_buf = 1;
[275] 
[276]     if (len == 0) {
[277]         b->pos = (u_char *) CRLF "0" CRLF CRLF;
[278]         b->last = b->pos + sizeof(CRLF "0" CRLF CRLF) - 1;
[279]         return cl;
[280]     }
[281] 
[282]     len += sizeof(CRLF "0" CRLF CRLF) - 1;
[283] 
[284]     b->pos = ngx_palloc(r->pool, len);
[285]     if (b->pos == NULL) {
[286]         return NULL;
[287]     }
[288] 
[289]     b->last = b->pos;
[290] 
[291]     *b->last++ = CR; *b->last++ = LF;
[292]     *b->last++ = '0';
[293]     *b->last++ = CR; *b->last++ = LF;
[294] 
[295]     part = &r->headers_out.trailers.part;
[296]     header = part->elts;
[297] 
[298]     for (i = 0; /* void */; i++) {
[299] 
[300]         if (i >= part->nelts) {
[301]             if (part->next == NULL) {
[302]                 break;
[303]             }
[304] 
[305]             part = part->next;
[306]             header = part->elts;
[307]             i = 0;
[308]         }
[309] 
[310]         if (header[i].hash == 0) {
[311]             continue;
[312]         }
[313] 
[314]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[315]                        "http trailer: \"%V: %V\"",
[316]                        &header[i].key, &header[i].value);
[317] 
[318]         b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);
[319]         *b->last++ = ':'; *b->last++ = ' ';
[320] 
[321]         b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
[322]         *b->last++ = CR; *b->last++ = LF;
[323]     }
[324] 
[325]     *b->last++ = CR; *b->last++ = LF;
[326] 
[327]     return cl;
[328] }
[329] 
[330] 
[331] static ngx_int_t
[332] ngx_http_chunked_filter_init(ngx_conf_t *cf)
[333] {
[334]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[335]     ngx_http_top_header_filter = ngx_http_chunked_header_filter;
[336] 
[337]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[338]     ngx_http_top_body_filter = ngx_http_chunked_body_filter;
[339] 
[340]     return NGX_OK;
[341] }
