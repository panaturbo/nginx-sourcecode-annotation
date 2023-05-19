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
[14]     ngx_bufs_t  bufs;
[15] } ngx_http_copy_filter_conf_t;
[16] 
[17] 
[18] #if (NGX_HAVE_FILE_AIO)
[19] static void ngx_http_copy_aio_handler(ngx_output_chain_ctx_t *ctx,
[20]     ngx_file_t *file);
[21] static void ngx_http_copy_aio_event_handler(ngx_event_t *ev);
[22] #endif
[23] #if (NGX_THREADS)
[24] static ngx_int_t ngx_http_copy_thread_handler(ngx_thread_task_t *task,
[25]     ngx_file_t *file);
[26] static void ngx_http_copy_thread_event_handler(ngx_event_t *ev);
[27] #endif
[28] 
[29] static void *ngx_http_copy_filter_create_conf(ngx_conf_t *cf);
[30] static char *ngx_http_copy_filter_merge_conf(ngx_conf_t *cf,
[31]     void *parent, void *child);
[32] static ngx_int_t ngx_http_copy_filter_init(ngx_conf_t *cf);
[33] 
[34] 
[35] static ngx_command_t  ngx_http_copy_filter_commands[] = {
[36] 
[37]     { ngx_string("output_buffers"),
[38]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[39]       ngx_conf_set_bufs_slot,
[40]       NGX_HTTP_LOC_CONF_OFFSET,
[41]       offsetof(ngx_http_copy_filter_conf_t, bufs),
[42]       NULL },
[43] 
[44]       ngx_null_command
[45] };
[46] 
[47] 
[48] static ngx_http_module_t  ngx_http_copy_filter_module_ctx = {
[49]     NULL,                                  /* preconfiguration */
[50]     ngx_http_copy_filter_init,             /* postconfiguration */
[51] 
[52]     NULL,                                  /* create main configuration */
[53]     NULL,                                  /* init main configuration */
[54] 
[55]     NULL,                                  /* create server configuration */
[56]     NULL,                                  /* merge server configuration */
[57] 
[58]     ngx_http_copy_filter_create_conf,      /* create location configuration */
[59]     ngx_http_copy_filter_merge_conf        /* merge location configuration */
[60] };
[61] 
[62] 
[63] ngx_module_t  ngx_http_copy_filter_module = {
[64]     NGX_MODULE_V1,
[65]     &ngx_http_copy_filter_module_ctx,      /* module context */
[66]     ngx_http_copy_filter_commands,         /* module directives */
[67]     NGX_HTTP_MODULE,                       /* module type */
[68]     NULL,                                  /* init master */
[69]     NULL,                                  /* init module */
[70]     NULL,                                  /* init process */
[71]     NULL,                                  /* init thread */
[72]     NULL,                                  /* exit thread */
[73]     NULL,                                  /* exit process */
[74]     NULL,                                  /* exit master */
[75]     NGX_MODULE_V1_PADDING
[76] };
[77] 
[78] 
[79] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[80] 
[81] 
[82] static ngx_int_t
[83] ngx_http_copy_filter(ngx_http_request_t *r, ngx_chain_t *in)
[84] {
[85]     ngx_int_t                     rc;
[86]     ngx_connection_t             *c;
[87]     ngx_output_chain_ctx_t       *ctx;
[88]     ngx_http_core_loc_conf_t     *clcf;
[89]     ngx_http_copy_filter_conf_t  *conf;
[90] 
[91]     c = r->connection;
[92] 
[93]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[94]                    "http copy filter: \"%V?%V\"", &r->uri, &r->args);
[95] 
[96]     ctx = ngx_http_get_module_ctx(r, ngx_http_copy_filter_module);
[97] 
[98]     if (ctx == NULL) {
[99]         ctx = ngx_pcalloc(r->pool, sizeof(ngx_output_chain_ctx_t));
[100]         if (ctx == NULL) {
[101]             return NGX_ERROR;
[102]         }
[103] 
[104]         ngx_http_set_ctx(r, ctx, ngx_http_copy_filter_module);
[105] 
[106]         conf = ngx_http_get_module_loc_conf(r, ngx_http_copy_filter_module);
[107]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[108] 
[109]         ctx->sendfile = c->sendfile;
[110]         ctx->need_in_memory = r->main_filter_need_in_memory
[111]                               || r->filter_need_in_memory;
[112]         ctx->need_in_temp = r->filter_need_temporary;
[113] 
[114]         ctx->alignment = clcf->directio_alignment;
[115] 
[116]         ctx->pool = r->pool;
[117]         ctx->bufs = conf->bufs;
[118]         ctx->tag = (ngx_buf_tag_t) &ngx_http_copy_filter_module;
[119] 
[120]         ctx->output_filter = (ngx_output_chain_filter_pt)
[121]                                   ngx_http_next_body_filter;
[122]         ctx->filter_ctx = r;
[123] 
[124] #if (NGX_HAVE_FILE_AIO)
[125]         if (ngx_file_aio && clcf->aio == NGX_HTTP_AIO_ON) {
[126]             ctx->aio_handler = ngx_http_copy_aio_handler;
[127]         }
[128] #endif
[129] 
[130] #if (NGX_THREADS)
[131]         if (clcf->aio == NGX_HTTP_AIO_THREADS) {
[132]             ctx->thread_handler = ngx_http_copy_thread_handler;
[133]         }
[134] #endif
[135] 
[136]         if (in && in->buf && ngx_buf_size(in->buf)) {
[137]             r->request_output = 1;
[138]         }
[139]     }
[140] 
[141] #if (NGX_HAVE_FILE_AIO || NGX_THREADS)
[142]     ctx->aio = r->aio;
[143] #endif
[144] 
[145]     rc = ngx_output_chain(ctx, in);
[146] 
[147]     if (ctx->in == NULL) {
[148]         r->buffered &= ~NGX_HTTP_COPY_BUFFERED;
[149] 
[150]     } else {
[151]         r->buffered |= NGX_HTTP_COPY_BUFFERED;
[152]     }
[153] 
[154]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
[155]                    "http copy filter: %i \"%V?%V\"", rc, &r->uri, &r->args);
[156] 
[157]     return rc;
[158] }
[159] 
[160] 
[161] #if (NGX_HAVE_FILE_AIO)
[162] 
[163] static void
[164] ngx_http_copy_aio_handler(ngx_output_chain_ctx_t *ctx, ngx_file_t *file)
[165] {
[166]     ngx_http_request_t *r;
[167] 
[168]     r = ctx->filter_ctx;
[169] 
[170]     file->aio->data = r;
[171]     file->aio->handler = ngx_http_copy_aio_event_handler;
[172] 
[173]     r->main->blocked++;
[174]     r->aio = 1;
[175]     ctx->aio = 1;
[176] }
[177] 
[178] 
[179] static void
[180] ngx_http_copy_aio_event_handler(ngx_event_t *ev)
[181] {
[182]     ngx_event_aio_t     *aio;
[183]     ngx_connection_t    *c;
[184]     ngx_http_request_t  *r;
[185] 
[186]     aio = ev->data;
[187]     r = aio->data;
[188]     c = r->connection;
[189] 
[190]     ngx_http_set_log_request(c->log, r);
[191] 
[192]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[193]                    "http aio: \"%V?%V\"", &r->uri, &r->args);
[194] 
[195]     r->main->blocked--;
[196]     r->aio = 0;
[197] 
[198]     r->write_event_handler(r);
[199] 
[200]     ngx_http_run_posted_requests(c);
[201] }
[202] 
[203] #endif
[204] 
[205] 
[206] #if (NGX_THREADS)
[207] 
[208] static ngx_int_t
[209] ngx_http_copy_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)
[210] {
[211]     ngx_str_t                  name;
[212]     ngx_connection_t          *c;
[213]     ngx_thread_pool_t         *tp;
[214]     ngx_http_request_t        *r;
[215]     ngx_output_chain_ctx_t    *ctx;
[216]     ngx_http_core_loc_conf_t  *clcf;
[217] 
[218]     r = file->thread_ctx;
[219] 
[220]     if (r->aio) {
[221]         /*
[222]          * tolerate sendfile() calls if another operation is already
[223]          * running; this can happen due to subrequests, multiple calls
[224]          * of the next body filter from a filter, or in HTTP/2 due to
[225]          * a write event on the main connection
[226]          */
[227] 
[228]         c = r->connection;
[229] 
[230] #if (NGX_HTTP_V2)
[231]         if (r->stream) {
[232]             c = r->stream->connection->connection;
[233]         }
[234] #endif
[235] 
[236]         if (task == c->sendfile_task) {
[237]             return NGX_OK;
[238]         }
[239]     }
[240] 
[241]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[242]     tp = clcf->thread_pool;
[243] 
[244]     if (tp == NULL) {
[245]         if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
[246]             != NGX_OK)
[247]         {
[248]             return NGX_ERROR;
[249]         }
[250] 
[251]         tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);
[252] 
[253]         if (tp == NULL) {
[254]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[255]                           "thread pool \"%V\" not found", &name);
[256]             return NGX_ERROR;
[257]         }
[258]     }
[259] 
[260]     task->event.data = r;
[261]     task->event.handler = ngx_http_copy_thread_event_handler;
[262] 
[263]     if (ngx_thread_task_post(tp, task) != NGX_OK) {
[264]         return NGX_ERROR;
[265]     }
[266] 
[267]     r->main->blocked++;
[268]     r->aio = 1;
[269] 
[270]     ctx = ngx_http_get_module_ctx(r, ngx_http_copy_filter_module);
[271]     ctx->aio = 1;
[272] 
[273]     return NGX_OK;
[274] }
[275] 
[276] 
[277] static void
[278] ngx_http_copy_thread_event_handler(ngx_event_t *ev)
[279] {
[280]     ngx_connection_t    *c;
[281]     ngx_http_request_t  *r;
[282] 
[283]     r = ev->data;
[284]     c = r->connection;
[285] 
[286]     ngx_http_set_log_request(c->log, r);
[287] 
[288]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
[289]                    "http thread: \"%V?%V\"", &r->uri, &r->args);
[290] 
[291]     r->main->blocked--;
[292]     r->aio = 0;
[293] 
[294] #if (NGX_HTTP_V2)
[295] 
[296]     if (r->stream) {
[297]         /*
[298]          * for HTTP/2, update write event to make sure processing will
[299]          * reach the main connection to handle sendfile() in threads
[300]          */
[301] 
[302]         c->write->ready = 1;
[303]         c->write->active = 0;
[304]     }
[305] 
[306] #endif
[307] 
[308]     if (r->done) {
[309]         /*
[310]          * trigger connection event handler if the subrequest was
[311]          * already finalized; this can happen if the handler is used
[312]          * for sendfile() in threads
[313]          */
[314] 
[315]         c->write->handler(c->write);
[316] 
[317]     } else {
[318]         r->write_event_handler(r);
[319]         ngx_http_run_posted_requests(c);
[320]     }
[321] }
[322] 
[323] #endif
[324] 
[325] 
[326] static void *
[327] ngx_http_copy_filter_create_conf(ngx_conf_t *cf)
[328] {
[329]     ngx_http_copy_filter_conf_t *conf;
[330] 
[331]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_copy_filter_conf_t));
[332]     if (conf == NULL) {
[333]         return NULL;
[334]     }
[335] 
[336]     conf->bufs.num = 0;
[337] 
[338]     return conf;
[339] }
[340] 
[341] 
[342] static char *
[343] ngx_http_copy_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[344] {
[345]     ngx_http_copy_filter_conf_t *prev = parent;
[346]     ngx_http_copy_filter_conf_t *conf = child;
[347] 
[348]     ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 2, 32768);
[349] 
[350]     return NULL;
[351] }
[352] 
[353] 
[354] static ngx_int_t
[355] ngx_http_copy_filter_init(ngx_conf_t *cf)
[356] {
[357]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[358]     ngx_http_top_body_filter = ngx_http_copy_filter;
[359] 
[360]     return NGX_OK;
[361] }
[362] 
