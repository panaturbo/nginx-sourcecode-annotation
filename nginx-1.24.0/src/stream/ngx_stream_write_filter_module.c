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
[12] 
[13] typedef struct {
[14]     ngx_chain_t  *from_upstream;
[15]     ngx_chain_t  *from_downstream;
[16] } ngx_stream_write_filter_ctx_t;
[17] 
[18] 
[19] static ngx_int_t ngx_stream_write_filter(ngx_stream_session_t *s,
[20]     ngx_chain_t *in, ngx_uint_t from_upstream);
[21] static ngx_int_t ngx_stream_write_filter_init(ngx_conf_t *cf);
[22] 
[23] 
[24] static ngx_stream_module_t  ngx_stream_write_filter_module_ctx = {
[25]     NULL,                                  /* preconfiguration */
[26]     ngx_stream_write_filter_init,          /* postconfiguration */
[27] 
[28]     NULL,                                  /* create main configuration */
[29]     NULL,                                  /* init main configuration */
[30] 
[31]     NULL,                                  /* create server configuration */
[32]     NULL                                   /* merge server configuration */
[33] };
[34] 
[35] 
[36] ngx_module_t  ngx_stream_write_filter_module = {
[37]     NGX_MODULE_V1,
[38]     &ngx_stream_write_filter_module_ctx,   /* module context */
[39]     NULL,                                  /* module directives */
[40]     NGX_STREAM_MODULE,                     /* module type */
[41]     NULL,                                  /* init master */
[42]     NULL,                                  /* init module */
[43]     NULL,                                  /* init process */
[44]     NULL,                                  /* init thread */
[45]     NULL,                                  /* exit thread */
[46]     NULL,                                  /* exit process */
[47]     NULL,                                  /* exit master */
[48]     NGX_MODULE_V1_PADDING
[49] };
[50] 
[51] 
[52] static ngx_int_t
[53] ngx_stream_write_filter(ngx_stream_session_t *s, ngx_chain_t *in,
[54]     ngx_uint_t from_upstream)
[55] {
[56]     off_t                           size;
[57]     ngx_uint_t                      last, flush, sync;
[58]     ngx_chain_t                    *cl, *ln, **ll, **out, *chain;
[59]     ngx_connection_t               *c;
[60]     ngx_stream_write_filter_ctx_t  *ctx;
[61] 
[62]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_write_filter_module);
[63] 
[64]     if (ctx == NULL) {
[65]         ctx = ngx_pcalloc(s->connection->pool,
[66]                           sizeof(ngx_stream_write_filter_ctx_t));
[67]         if (ctx == NULL) {
[68]             return NGX_ERROR;
[69]         }
[70] 
[71]         ngx_stream_set_ctx(s, ctx, ngx_stream_write_filter_module);
[72]     }
[73] 
[74]     if (from_upstream) {
[75]         c = s->connection;
[76]         out = &ctx->from_upstream;
[77] 
[78]     } else {
[79]         c = s->upstream->peer.connection;
[80]         out = &ctx->from_downstream;
[81]     }
[82] 
[83]     if (c->error) {
[84]         return NGX_ERROR;
[85]     }
[86] 
[87]     size = 0;
[88]     flush = 0;
[89]     sync = 0;
[90]     last = 0;
[91]     ll = out;
[92] 
[93]     /* find the size, the flush point and the last link of the saved chain */
[94] 
[95]     for (cl = *out; cl; cl = cl->next) {
[96]         ll = &cl->next;
[97] 
[98]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
[99]                        "write old buf t:%d f:%d %p, pos %p, size: %z "
[100]                        "file: %O, size: %O",
[101]                        cl->buf->temporary, cl->buf->in_file,
[102]                        cl->buf->start, cl->buf->pos,
[103]                        cl->buf->last - cl->buf->pos,
[104]                        cl->buf->file_pos,
[105]                        cl->buf->file_last - cl->buf->file_pos);
[106] 
[107]         if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
[108]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[109]                           "zero size buf in writer "
[110]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[111]                           cl->buf->temporary,
[112]                           cl->buf->recycled,
[113]                           cl->buf->in_file,
[114]                           cl->buf->start,
[115]                           cl->buf->pos,
[116]                           cl->buf->last,
[117]                           cl->buf->file,
[118]                           cl->buf->file_pos,
[119]                           cl->buf->file_last);
[120] 
[121]             ngx_debug_point();
[122]             return NGX_ERROR;
[123]         }
[124] 
[125]         if (ngx_buf_size(cl->buf) < 0) {
[126]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[127]                           "negative size buf in writer "
[128]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[129]                           cl->buf->temporary,
[130]                           cl->buf->recycled,
[131]                           cl->buf->in_file,
[132]                           cl->buf->start,
[133]                           cl->buf->pos,
[134]                           cl->buf->last,
[135]                           cl->buf->file,
[136]                           cl->buf->file_pos,
[137]                           cl->buf->file_last);
[138] 
[139]             ngx_debug_point();
[140]             return NGX_ERROR;
[141]         }
[142] 
[143]         size += ngx_buf_size(cl->buf);
[144] 
[145]         if (cl->buf->flush || cl->buf->recycled) {
[146]             flush = 1;
[147]         }
[148] 
[149]         if (cl->buf->sync) {
[150]             sync = 1;
[151]         }
[152] 
[153]         if (cl->buf->last_buf) {
[154]             last = 1;
[155]         }
[156]     }
[157] 
[158]     /* add the new chain to the existent one */
[159] 
[160]     for (ln = in; ln; ln = ln->next) {
[161]         cl = ngx_alloc_chain_link(c->pool);
[162]         if (cl == NULL) {
[163]             return NGX_ERROR;
[164]         }
[165] 
[166]         cl->buf = ln->buf;
[167]         *ll = cl;
[168]         ll = &cl->next;
[169] 
[170]         ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
[171]                        "write new buf t:%d f:%d %p, pos %p, size: %z "
[172]                        "file: %O, size: %O",
[173]                        cl->buf->temporary, cl->buf->in_file,
[174]                        cl->buf->start, cl->buf->pos,
[175]                        cl->buf->last - cl->buf->pos,
[176]                        cl->buf->file_pos,
[177]                        cl->buf->file_last - cl->buf->file_pos);
[178] 
[179]         if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
[180]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[181]                           "zero size buf in writer "
[182]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[183]                           cl->buf->temporary,
[184]                           cl->buf->recycled,
[185]                           cl->buf->in_file,
[186]                           cl->buf->start,
[187]                           cl->buf->pos,
[188]                           cl->buf->last,
[189]                           cl->buf->file,
[190]                           cl->buf->file_pos,
[191]                           cl->buf->file_last);
[192] 
[193]             ngx_debug_point();
[194]             return NGX_ERROR;
[195]         }
[196] 
[197]         if (ngx_buf_size(cl->buf) < 0) {
[198]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[199]                           "negative size buf in writer "
[200]                           "t:%d r:%d f:%d %p %p-%p %p %O-%O",
[201]                           cl->buf->temporary,
[202]                           cl->buf->recycled,
[203]                           cl->buf->in_file,
[204]                           cl->buf->start,
[205]                           cl->buf->pos,
[206]                           cl->buf->last,
[207]                           cl->buf->file,
[208]                           cl->buf->file_pos,
[209]                           cl->buf->file_last);
[210] 
[211]             ngx_debug_point();
[212]             return NGX_ERROR;
[213]         }
[214] 
[215]         size += ngx_buf_size(cl->buf);
[216] 
[217]         if (cl->buf->flush || cl->buf->recycled) {
[218]             flush = 1;
[219]         }
[220] 
[221]         if (cl->buf->sync) {
[222]             sync = 1;
[223]         }
[224] 
[225]         if (cl->buf->last_buf) {
[226]             last = 1;
[227]         }
[228]     }
[229] 
[230]     *ll = NULL;
[231] 
[232]     ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
[233]                    "stream write filter: l:%ui f:%ui s:%O", last, flush, size);
[234] 
[235]     if (size == 0
[236]         && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
[237]         && !(last && c->need_last_buf)
[238]         && !(flush && c->need_flush_buf))
[239]     {
[240]         if (last || flush || sync) {
[241]             for (cl = *out; cl; /* void */) {
[242]                 ln = cl;
[243]                 cl = cl->next;
[244]                 ngx_free_chain(c->pool, ln);
[245]             }
[246] 
[247]             *out = NULL;
[248]             c->buffered &= ~NGX_STREAM_WRITE_BUFFERED;
[249] 
[250]             return NGX_OK;
[251]         }
[252] 
[253]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[254]                       "the stream output chain is empty");
[255] 
[256]         ngx_debug_point();
[257] 
[258]         return NGX_ERROR;
[259]     }
[260] 
[261]     chain = c->send_chain(c, *out, 0);
[262] 
[263]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[264]                    "stream write filter %p", chain);
[265] 
[266]     if (chain == NGX_CHAIN_ERROR) {
[267]         c->error = 1;
[268]         return NGX_ERROR;
[269]     }
[270] 
[271]     for (cl = *out; cl && cl != chain; /* void */) {
[272]         ln = cl;
[273]         cl = cl->next;
[274]         ngx_free_chain(c->pool, ln);
[275]     }
[276] 
[277]     *out = chain;
[278] 
[279]     if (chain) {
[280]         if (c->shared) {
[281]             ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[282]                           "shared connection is busy");
[283]             return NGX_ERROR;
[284]         }
[285] 
[286]         c->buffered |= NGX_STREAM_WRITE_BUFFERED;
[287]         return NGX_AGAIN;
[288]     }
[289] 
[290]     c->buffered &= ~NGX_STREAM_WRITE_BUFFERED;
[291] 
[292]     if (c->buffered & NGX_LOWLEVEL_BUFFERED) {
[293]         return NGX_AGAIN;
[294]     }
[295] 
[296]     return NGX_OK;
[297] }
[298] 
[299] 
[300] static ngx_int_t
[301] ngx_stream_write_filter_init(ngx_conf_t *cf)
[302] {
[303]     ngx_stream_top_filter = ngx_stream_write_filter;
[304] 
[305]     return NGX_OK;
[306] }
