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
[13] static ngx_int_t ngx_http_postpone_filter_add(ngx_http_request_t *r,
[14]     ngx_chain_t *in);
[15] static ngx_int_t ngx_http_postpone_filter_in_memory(ngx_http_request_t *r,
[16]     ngx_chain_t *in);
[17] static ngx_int_t ngx_http_postpone_filter_init(ngx_conf_t *cf);
[18] 
[19] 
[20] static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
[21]     NULL,                                  /* preconfiguration */
[22]     ngx_http_postpone_filter_init,         /* postconfiguration */
[23] 
[24]     NULL,                                  /* create main configuration */
[25]     NULL,                                  /* init main configuration */
[26] 
[27]     NULL,                                  /* create server configuration */
[28]     NULL,                                  /* merge server configuration */
[29] 
[30]     NULL,                                  /* create location configuration */
[31]     NULL                                   /* merge location configuration */
[32] };
[33] 
[34] 
[35] ngx_module_t  ngx_http_postpone_filter_module = {
[36]     NGX_MODULE_V1,
[37]     &ngx_http_postpone_filter_module_ctx,  /* module context */
[38]     NULL,                                  /* module directives */
[39]     NGX_HTTP_MODULE,                       /* module type */
[40]     NULL,                                  /* init master */
[41]     NULL,                                  /* init module */
[42]     NULL,                                  /* init process */
[43]     NULL,                                  /* init thread */
[44]     NULL,                                  /* exit thread */
[45]     NULL,                                  /* exit process */
[46]     NULL,                                  /* exit master */
[47]     NGX_MODULE_V1_PADDING
[48] };
[49] 
[50] 
[51] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[52] 
[53] 
[54] static ngx_int_t
[55] ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
[56] {
[57]     ngx_connection_t              *c;
[58]     ngx_http_postponed_request_t  *pr;
[59] 
[60]     c = r->connection;
[61] 
[62]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
[63]                    "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);
[64] 
[65]     if (r->subrequest_in_memory) {
[66]         return ngx_http_postpone_filter_in_memory(r, in);
[67]     }
[68] 
[69]     if (r != c->data) {
[70] 
[71]         if (in) {
[72]             if (ngx_http_postpone_filter_add(r, in) != NGX_OK) {
[73]                 return NGX_ERROR;
[74]             }
[75] 
[76]             return NGX_OK;
[77]         }
[78] 
[79] #if 0
[80]         /* TODO: SSI may pass NULL */
[81]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[82]                       "http postpone filter NULL inactive request");
[83] #endif
[84] 
[85]         return NGX_OK;
[86]     }
[87] 
[88]     if (r->postponed == NULL) {
[89] 
[90]         if (in || c->buffered) {
[91]             return ngx_http_next_body_filter(r->main, in);
[92]         }
[93] 
[94]         return NGX_OK;
[95]     }
[96] 
[97]     if (in) {
[98]         if (ngx_http_postpone_filter_add(r, in) != NGX_OK) {
[99]             return NGX_ERROR;
[100]         }
[101]     }
[102] 
[103]     do {
[104]         pr = r->postponed;
[105] 
[106]         if (pr->request) {
[107] 
[108]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[109]                            "http postpone filter wake \"%V?%V\"",
[110]                            &pr->request->uri, &pr->request->args);
[111] 
[112]             r->postponed = pr->next;
[113] 
[114]             c->data = pr->request;
[115] 
[116]             return ngx_http_post_request(pr->request, NULL);
[117]         }
[118] 
[119]         if (pr->out == NULL) {
[120]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[121]                           "http postpone filter NULL output");
[122] 
[123]         } else {
[124]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[125]                            "http postpone filter output \"%V?%V\"",
[126]                            &r->uri, &r->args);
[127] 
[128]             if (ngx_http_next_body_filter(r->main, pr->out) == NGX_ERROR) {
[129]                 return NGX_ERROR;
[130]             }
[131]         }
[132] 
[133]         r->postponed = pr->next;
[134] 
[135]     } while (r->postponed);
[136] 
[137]     return NGX_OK;
[138] }
[139] 
[140] 
[141] static ngx_int_t
[142] ngx_http_postpone_filter_add(ngx_http_request_t *r, ngx_chain_t *in)
[143] {
[144]     ngx_http_postponed_request_t  *pr, **ppr;
[145] 
[146]     if (r->postponed) {
[147]         for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }
[148] 
[149]         if (pr->request == NULL) {
[150]             goto found;
[151]         }
[152] 
[153]         ppr = &pr->next;
[154] 
[155]     } else {
[156]         ppr = &r->postponed;
[157]     }
[158] 
[159]     pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
[160]     if (pr == NULL) {
[161]         return NGX_ERROR;
[162]     }
[163] 
[164]     *ppr = pr;
[165] 
[166]     pr->request = NULL;
[167]     pr->out = NULL;
[168]     pr->next = NULL;
[169] 
[170] found:
[171] 
[172]     if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_OK) {
[173]         return NGX_OK;
[174]     }
[175] 
[176]     return NGX_ERROR;
[177] }
[178] 
[179] 
[180] static ngx_int_t
[181] ngx_http_postpone_filter_in_memory(ngx_http_request_t *r, ngx_chain_t *in)
[182] {
[183]     size_t                     len;
[184]     ngx_buf_t                 *b;
[185]     ngx_connection_t          *c;
[186]     ngx_http_core_loc_conf_t  *clcf;
[187] 
[188]     c = r->connection;
[189] 
[190]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[191]                    "http postpone filter in memory");
[192] 
[193]     if (r->out == NULL) {
[194]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[195] 
[196]         if (r->headers_out.content_length_n != -1) {
[197]             len = r->headers_out.content_length_n;
[198] 
[199]             if (len > clcf->subrequest_output_buffer_size) {
[200]                 ngx_log_error(NGX_LOG_ERR, c->log, 0,
[201]                               "too big subrequest response: %uz", len);
[202]                 return NGX_ERROR;
[203]             }
[204] 
[205]         } else {
[206]             len = clcf->subrequest_output_buffer_size;
[207]         }
[208] 
[209]         b = ngx_create_temp_buf(r->pool, len);
[210]         if (b == NULL) {
[211]             return NGX_ERROR;
[212]         }
[213] 
[214]         b->last_buf = 1;
[215] 
[216]         r->out = ngx_alloc_chain_link(r->pool);
[217]         if (r->out == NULL) {
[218]             return NGX_ERROR;
[219]         }
[220] 
[221]         r->out->buf = b;
[222]         r->out->next = NULL;
[223]     }
[224] 
[225]     b = r->out->buf;
[226] 
[227]     for ( /* void */ ; in; in = in->next) {
[228] 
[229]         if (ngx_buf_special(in->buf)) {
[230]             continue;
[231]         }
[232] 
[233]         len = in->buf->last - in->buf->pos;
[234] 
[235]         if (len > (size_t) (b->end - b->last)) {
[236]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[237]                           "too big subrequest response");
[238]             return NGX_ERROR;
[239]         }
[240] 
[241]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[242]                        "http postpone filter in memory %uz bytes", len);
[243] 
[244]         b->last = ngx_cpymem(b->last, in->buf->pos, len);
[245]         in->buf->pos = in->buf->last;
[246]     }
[247] 
[248]     return NGX_OK;
[249] }
[250] 
[251] 
[252] static ngx_int_t
[253] ngx_http_postpone_filter_init(ngx_conf_t *cf)
[254] {
[255]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[256]     ngx_http_top_body_filter = ngx_http_postpone_filter;
[257] 
[258]     return NGX_OK;
[259] }
