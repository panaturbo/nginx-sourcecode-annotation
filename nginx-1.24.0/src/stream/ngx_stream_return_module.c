[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
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
[14]     ngx_stream_complex_value_t   text;
[15] } ngx_stream_return_srv_conf_t;
[16] 
[17] 
[18] typedef struct {
[19]     ngx_chain_t                 *out;
[20] } ngx_stream_return_ctx_t;
[21] 
[22] 
[23] static void ngx_stream_return_handler(ngx_stream_session_t *s);
[24] static void ngx_stream_return_write_handler(ngx_event_t *ev);
[25] 
[26] static void *ngx_stream_return_create_srv_conf(ngx_conf_t *cf);
[27] static char *ngx_stream_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[28] 
[29] 
[30] static ngx_command_t  ngx_stream_return_commands[] = {
[31] 
[32]     { ngx_string("return"),
[33]       NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
[34]       ngx_stream_return,
[35]       NGX_STREAM_SRV_CONF_OFFSET,
[36]       0,
[37]       NULL },
[38] 
[39]       ngx_null_command
[40] };
[41] 
[42] 
[43] static ngx_stream_module_t  ngx_stream_return_module_ctx = {
[44]     NULL,                                  /* preconfiguration */
[45]     NULL,                                  /* postconfiguration */
[46] 
[47]     NULL,                                  /* create main configuration */
[48]     NULL,                                  /* init main configuration */
[49] 
[50]     ngx_stream_return_create_srv_conf,     /* create server configuration */
[51]     NULL                                   /* merge server configuration */
[52] };
[53] 
[54] 
[55] ngx_module_t  ngx_stream_return_module = {
[56]     NGX_MODULE_V1,
[57]     &ngx_stream_return_module_ctx,         /* module context */
[58]     ngx_stream_return_commands,            /* module directives */
[59]     NGX_STREAM_MODULE,                     /* module type */
[60]     NULL,                                  /* init master */
[61]     NULL,                                  /* init module */
[62]     NULL,                                  /* init process */
[63]     NULL,                                  /* init thread */
[64]     NULL,                                  /* exit thread */
[65]     NULL,                                  /* exit process */
[66]     NULL,                                  /* exit master */
[67]     NGX_MODULE_V1_PADDING
[68] };
[69] 
[70] 
[71] static void
[72] ngx_stream_return_handler(ngx_stream_session_t *s)
[73] {
[74]     ngx_str_t                      text;
[75]     ngx_buf_t                     *b;
[76]     ngx_connection_t              *c;
[77]     ngx_stream_return_ctx_t       *ctx;
[78]     ngx_stream_return_srv_conf_t  *rscf;
[79] 
[80]     c = s->connection;
[81] 
[82]     c->log->action = "returning text";
[83] 
[84]     rscf = ngx_stream_get_module_srv_conf(s, ngx_stream_return_module);
[85] 
[86]     if (ngx_stream_complex_value(s, &rscf->text, &text) != NGX_OK) {
[87]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[88]         return;
[89]     }
[90] 
[91]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
[92]                    "stream return text: \"%V\"", &text);
[93] 
[94]     if (text.len == 0) {
[95]         ngx_stream_finalize_session(s, NGX_STREAM_OK);
[96]         return;
[97]     }
[98] 
[99]     ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_return_ctx_t));
[100]     if (ctx == NULL) {
[101]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[102]         return;
[103]     }
[104] 
[105]     ngx_stream_set_ctx(s, ctx, ngx_stream_return_module);
[106] 
[107]     b = ngx_calloc_buf(c->pool);
[108]     if (b == NULL) {
[109]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[110]         return;
[111]     }
[112] 
[113]     b->memory = 1;
[114]     b->pos = text.data;
[115]     b->last = text.data + text.len;
[116]     b->last_buf = 1;
[117] 
[118]     ctx->out = ngx_alloc_chain_link(c->pool);
[119]     if (ctx->out == NULL) {
[120]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[121]         return;
[122]     }
[123] 
[124]     ctx->out->buf = b;
[125]     ctx->out->next = NULL;
[126] 
[127]     c->write->handler = ngx_stream_return_write_handler;
[128] 
[129]     ngx_stream_return_write_handler(c->write);
[130] }
[131] 
[132] 
[133] static void
[134] ngx_stream_return_write_handler(ngx_event_t *ev)
[135] {
[136]     ngx_connection_t         *c;
[137]     ngx_stream_session_t     *s;
[138]     ngx_stream_return_ctx_t  *ctx;
[139] 
[140]     c = ev->data;
[141]     s = c->data;
[142] 
[143]     if (ev->timedout) {
[144]         ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
[145]         ngx_stream_finalize_session(s, NGX_STREAM_OK);
[146]         return;
[147]     }
[148] 
[149]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_return_module);
[150] 
[151]     if (ngx_stream_top_filter(s, ctx->out, 1) == NGX_ERROR) {
[152]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[153]         return;
[154]     }
[155] 
[156]     ctx->out = NULL;
[157] 
[158]     if (!c->buffered) {
[159]         ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
[160]                        "stream return done sending");
[161]         ngx_stream_finalize_session(s, NGX_STREAM_OK);
[162]         return;
[163]     }
[164] 
[165]     if (ngx_handle_write_event(ev, 0) != NGX_OK) {
[166]         ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
[167]         return;
[168]     }
[169] 
[170]     ngx_add_timer(ev, 5000);
[171] }
[172] 
[173] 
[174] static void *
[175] ngx_stream_return_create_srv_conf(ngx_conf_t *cf)
[176] {
[177]     ngx_stream_return_srv_conf_t  *conf;
[178] 
[179]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_return_srv_conf_t));
[180]     if (conf == NULL) {
[181]         return NULL;
[182]     }
[183] 
[184]     return conf;
[185] }
[186] 
[187] 
[188] static char *
[189] ngx_stream_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[190] {
[191]     ngx_stream_return_srv_conf_t *rscf = conf;
[192] 
[193]     ngx_str_t                           *value;
[194]     ngx_stream_core_srv_conf_t          *cscf;
[195]     ngx_stream_compile_complex_value_t   ccv;
[196] 
[197]     if (rscf->text.value.data) {
[198]         return "is duplicate";
[199]     }
[200] 
[201]     value = cf->args->elts;
[202] 
[203]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[204] 
[205]     ccv.cf = cf;
[206]     ccv.value = &value[1];
[207]     ccv.complex_value = &rscf->text;
[208] 
[209]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[210]         return NGX_CONF_ERROR;
[211]     }
[212] 
[213]     cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
[214] 
[215]     cscf->handler = ngx_stream_return_handler;
[216] 
[217]     return NGX_CONF_OK;
[218] }
