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
[13] static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);
[14] 
[15] 
[16] static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
[17]     NULL,                                  /* preconfiguration */
[18]     ngx_http_write_filter_init,            /* postconfiguration */
[19] 
[20]     NULL,                                  /* create main configuration */
[21]     NULL,                                  /* init main configuration */
[22] 
[23]     NULL,                                  /* create server configuration */
[24]     NULL,                                  /* merge server configuration */
[25] 
[26]     NULL,                                  /* create location configuration */
[27]     NULL,                                  /* merge location configuration */
[28] };
[29] 
[30] 
[31] ngx_module_t  ngx_http_write_filter_module = {
[32]     NGX_MODULE_V1,
[33]     &ngx_http_write_filter_module_ctx,     /* module context */
[34]     NULL,                                  /* module directives */
[35]     NGX_HTTP_MODULE,                       /* module type */
[36]     NULL,                                  /* init master */
[37]     NULL,                                  /* init module */
[38]     NULL,                                  /* init process */
[39]     NULL,                                  /* init thread */
[40]     NULL,                                  /* exit thread */
[41]     NULL,                                  /* exit process */
[42]     NULL,                                  /* exit master */
[43]     NGX_MODULE_V1_PADDING
[44] };
[45] 
[46] 
[47] ngx_int_t
[48] ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
[49] {
[50]     off_t                      size, sent, nsent, limit;
[51]     ngx_uint_t                 last, flush, sync;
[52]     ngx_msec_t                 delay;
[53]     ngx_chain_t               *cl, *ln, **ll, *chain;
[54]     ngx_connection_t          *c;
[55]     ngx_http_core_loc_conf_t  *clcf;
[56] 
[57]     c = r->connection;
[58] 
[59]     if (c->error) {
[60]         return NGX_ERROR;
[61]     }
[62] 
[63]     size = 0;
[64]     flush = 0;
[65]     sync = 0;
[66]     last = 0;
[67]     ll = &r->out;
[68] 
[69]     /* find the size, the flush point and the last link of the saved chain */
[70] 
[71]     for (cl = r->out; cl; cl = cl->next) {
[72]         ll = &cl->next;
[73] 
[74]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
[75]                        "write old buf t:%d f:%d %p, pos %p, size: %z "
[76]                        "file: %O, size: %O",
[77]                        cl->buf->temporary, cl->buf->in_file,
[78]                        cl->buf->start, cl->buf->pos,
[79]                        cl->buf->last - cl->buf->pos,
[80]                        cl->buf->file_pos,
[81]                        cl->buf->file_last - cl->buf->file_pos);
[82] 
[83]         if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
[84]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[85]                           "zero size buf in writer "
[86]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[87]                           cl->buf->temporary,
[88]                           cl->buf->recycled,
[89]                           cl->buf->in_file,
[90]                           cl->buf->start,
[91]                           cl->buf->pos,
[92]                           cl->buf->last,
[93]                           cl->buf->file,
[94]                           cl->buf->file_pos,
[95]                           cl->buf->file_last);
[96] 
[97]             ngx_debug_point();
[98]             return NGX_ERROR;
[99]         }
[100] 
[101]         if (ngx_buf_size(cl->buf) < 0) {
[102]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[103]                           "negative size buf in writer "
[104]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[105]                           cl->buf->temporary,
[106]                           cl->buf->recycled,
[107]                           cl->buf->in_file,
[108]                           cl->buf->start,
[109]                           cl->buf->pos,
[110]                           cl->buf->last,
[111]                           cl->buf->file,
[112]                           cl->buf->file_pos,
[113]                           cl->buf->file_last);
[114] 
[115]             ngx_debug_point();
[116]             return NGX_ERROR;
[117]         }
[118] 
[119]         size += ngx_buf_size(cl->buf);
[120] 
[121]         if (cl->buf->flush || cl->buf->recycled) {
[122]             flush = 1;
[123]         }
[124] 
[125]         if (cl->buf->sync) {
[126]             sync = 1;
[127]         }
[128] 
[129]         if (cl->buf->last_buf) {
[130]             last = 1;
[131]         }
[132]     }
[133] 
[134]     /* add the new chain to the existent one */
[135] 
[136]     for (ln = in; ln; ln = ln->next) {
[137]         cl = ngx_alloc_chain_link(r->pool);
[138]         if (cl == NULL) {
[139]             return NGX_ERROR;
[140]         }
[141] 
[142]         cl->buf = ln->buf;
[143]         *ll = cl;
[144]         ll = &cl->next;
[145] 
[146]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
[147]                        "write new buf t:%d f:%d %p, pos %p, size: %z "
[148]                        "file: %O, size: %O",
[149]                        cl->buf->temporary, cl->buf->in_file,
[150]                        cl->buf->start, cl->buf->pos,
[151]                        cl->buf->last - cl->buf->pos,
[152]                        cl->buf->file_pos,
[153]                        cl->buf->file_last - cl->buf->file_pos);
[154] 
[155]         if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
[156]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[157]                           "zero size buf in writer "
[158]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[159]                           cl->buf->temporary,
[160]                           cl->buf->recycled,
[161]                           cl->buf->in_file,
[162]                           cl->buf->start,
[163]                           cl->buf->pos,
[164]                           cl->buf->last,
[165]                           cl->buf->file,
[166]                           cl->buf->file_pos,
[167]                           cl->buf->file_last);
[168] 
[169]             ngx_debug_point();
[170]             return NGX_ERROR;
[171]         }
[172] 
[173]         if (ngx_buf_size(cl->buf) < 0) {
[174]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[175]                           "negative size buf in writer "
[176]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[177]                           cl->buf->temporary,
[178]                           cl->buf->recycled,
[179]                           cl->buf->in_file,
[180]                           cl->buf->start,
[181]                           cl->buf->pos,
[182]                           cl->buf->last,
[183]                           cl->buf->file,
[184]                           cl->buf->file_pos,
[185]                           cl->buf->file_last);
[186] 
[187]             ngx_debug_point();
[188]             return NGX_ERROR;
[189]         }
[190] 
[191]         size += ngx_buf_size(cl->buf);
[192] 
[193]         if (cl->buf->flush || cl->buf->recycled) {
[194]             flush = 1;
[195]         }
[196] 
[197]         if (cl->buf->sync) {
[198]             sync = 1;
[199]         }
[200] 
[201]         if (cl->buf->last_buf) {
[202]             last = 1;
[203]         }
[204]     }
[205] 
[206]     *ll = NULL;
[207] 
[208]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
[209]                    "http write filter: l:%ui f:%ui s:%O", last, flush, size);
[210] 
[211]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[212] 
[213]     /*
[214]      * avoid the output if there are no last buf, no flush point,
[215]      * there are the incoming bufs and the size of all bufs
[216]      * is smaller than "postpone_output" directive
[217]      */
[218] 
[219]     if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
[220]         return NGX_OK;
[221]     }
[222] 
[223]     if (c->write->delayed) {
[224]         c->buffered |= NGX_HTTP_WRITE_BUFFERED;
[225]         return NGX_AGAIN;
[226]     }
[227] 
[228]     if (size == 0
[229]         && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
[230]         && !(last && c->need_last_buf)
[231]         && !(flush && c->need_flush_buf))
[232]     {
[233]         if (last || flush || sync) {
[234]             for (cl = r->out; cl; /* void */) {
[235]                 ln = cl;
[236]                 cl = cl->next;
[237]                 ngx_free_chain(r->pool, ln);
[238]             }
[239] 
[240]             r->out = NULL;
[241]             c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;
[242] 
[243]             return NGX_OK;
[244]         }
[245] 
[246]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[247]                       "the http output chain is empty");
[248] 
[249]         ngx_debug_point();
[250] 
[251]         return NGX_ERROR;
[252]     }
[253] 
[254]     if (!r->limit_rate_set) {
[255]         r->limit_rate = ngx_http_complex_value_size(r, clcf->limit_rate, 0);
[256]         r->limit_rate_set = 1;
[257]     }
[258] 
[259]     if (r->limit_rate) {
[260] 
[261]         if (!r->limit_rate_after_set) {
[262]             r->limit_rate_after = ngx_http_complex_value_size(r,
[263]                                                     clcf->limit_rate_after, 0);
[264]             r->limit_rate_after_set = 1;
[265]         }
[266] 
[267]         limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
[268]                 - (c->sent - r->limit_rate_after);
[269] 
[270]         if (limit <= 0) {
[271]             c->write->delayed = 1;
[272]             delay = (ngx_msec_t) (- limit * 1000 / r->limit_rate + 1);
[273]             ngx_add_timer(c->write, delay);
[274] 
[275]             c->buffered |= NGX_HTTP_WRITE_BUFFERED;
[276] 
[277]             return NGX_AGAIN;
[278]         }
[279] 
[280]         if (clcf->sendfile_max_chunk
[281]             && (off_t) clcf->sendfile_max_chunk < limit)
[282]         {
[283]             limit = clcf->sendfile_max_chunk;
[284]         }
[285] 
[286]     } else {
[287]         limit = clcf->sendfile_max_chunk;
[288]     }
[289] 
[290]     sent = c->sent;
[291] 
[292]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[293]                    "http write filter limit %O", limit);
[294] 
[295]     chain = c->send_chain(c, r->out, limit);
[296] 
[297]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
[298]                    "http write filter %p", chain);
[299] 
[300]     if (chain == NGX_CHAIN_ERROR) {
[301]         c->error = 1;
[302]         return NGX_ERROR;
[303]     }
[304] 
[305]     if (r->limit_rate) {
[306] 
[307]         nsent = c->sent;
[308] 
[309]         if (r->limit_rate_after) {
[310] 
[311]             sent -= r->limit_rate_after;
[312]             if (sent < 0) {
[313]                 sent = 0;
[314]             }
[315] 
[316]             nsent -= r->limit_rate_after;
[317]             if (nsent < 0) {
[318]                 nsent = 0;
[319]             }
[320]         }
[321] 
[322]         delay = (ngx_msec_t) ((nsent - sent) * 1000 / r->limit_rate);
[323] 
[324]         if (delay > 0) {
[325]             c->write->delayed = 1;
[326]             ngx_add_timer(c->write, delay);
[327]         }
[328]     }
[329] 
[330]     if (chain && c->write->ready && !c->write->delayed) {
[331]         ngx_post_event(c->write, &ngx_posted_next_events);
[332]     }
[333] 
[334]     for (cl = r->out; cl && cl != chain; /* void */) {
[335]         ln = cl;
[336]         cl = cl->next;
[337]         ngx_free_chain(r->pool, ln);
[338]     }
[339] 
[340]     r->out = chain;
[341] 
[342]     if (chain) {
[343]         c->buffered |= NGX_HTTP_WRITE_BUFFERED;
[344]         return NGX_AGAIN;
[345]     }
[346] 
[347]     c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;
[348] 
[349]     if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
[350]         return NGX_AGAIN;
[351]     }
[352] 
[353]     return NGX_OK;
[354] }
[355] 
[356] 
[357] static ngx_int_t
[358] ngx_http_write_filter_init(ngx_conf_t *cf)
[359] {
[360]     ngx_http_top_body_filter = ngx_http_write_filter;
[361] 
[362]     return NGX_OK;
[363] }
