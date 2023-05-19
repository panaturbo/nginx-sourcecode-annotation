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
[12] #define NGX_HTTP_SSI_ERROR          1
[13] 
[14] #define NGX_HTTP_SSI_DATE_LEN       2048
[15] 
[16] #define NGX_HTTP_SSI_ADD_PREFIX     1
[17] #define NGX_HTTP_SSI_ADD_ZERO       2
[18] 
[19] 
[20] typedef struct {
[21]     ngx_flag_t    enable;
[22]     ngx_flag_t    silent_errors;
[23]     ngx_flag_t    ignore_recycled_buffers;
[24]     ngx_flag_t    last_modified;
[25] 
[26]     ngx_hash_t    types;
[27] 
[28]     size_t        min_file_chunk;
[29]     size_t        value_len;
[30] 
[31]     ngx_array_t  *types_keys;
[32] } ngx_http_ssi_loc_conf_t;
[33] 
[34] 
[35] typedef struct {
[36]     ngx_str_t     name;
[37]     ngx_uint_t    key;
[38]     ngx_str_t     value;
[39] } ngx_http_ssi_var_t;
[40] 
[41] 
[42] typedef struct {
[43]     ngx_str_t     name;
[44]     ngx_chain_t  *bufs;
[45]     ngx_uint_t    count;
[46] } ngx_http_ssi_block_t;
[47] 
[48] 
[49] typedef enum {
[50]     ssi_start_state = 0,
[51]     ssi_tag_state,
[52]     ssi_comment0_state,
[53]     ssi_comment1_state,
[54]     ssi_sharp_state,
[55]     ssi_precommand_state,
[56]     ssi_command_state,
[57]     ssi_preparam_state,
[58]     ssi_param_state,
[59]     ssi_preequal_state,
[60]     ssi_prevalue_state,
[61]     ssi_double_quoted_value_state,
[62]     ssi_quoted_value_state,
[63]     ssi_quoted_symbol_state,
[64]     ssi_postparam_state,
[65]     ssi_comment_end0_state,
[66]     ssi_comment_end1_state,
[67]     ssi_error_state,
[68]     ssi_error_end0_state,
[69]     ssi_error_end1_state
[70] } ngx_http_ssi_state_e;
[71] 
[72] 
[73] static ngx_int_t ngx_http_ssi_output(ngx_http_request_t *r,
[74]     ngx_http_ssi_ctx_t *ctx);
[75] static void ngx_http_ssi_buffered(ngx_http_request_t *r,
[76]     ngx_http_ssi_ctx_t *ctx);
[77] static ngx_int_t ngx_http_ssi_parse(ngx_http_request_t *r,
[78]     ngx_http_ssi_ctx_t *ctx);
[79] static ngx_str_t *ngx_http_ssi_get_variable(ngx_http_request_t *r,
[80]     ngx_str_t *name, ngx_uint_t key);
[81] static ngx_int_t ngx_http_ssi_evaluate_string(ngx_http_request_t *r,
[82]     ngx_http_ssi_ctx_t *ctx, ngx_str_t *text, ngx_uint_t flags);
[83] static ngx_int_t ngx_http_ssi_regex_match(ngx_http_request_t *r,
[84]     ngx_str_t *pattern, ngx_str_t *str);
[85] 
[86] static ngx_int_t ngx_http_ssi_include(ngx_http_request_t *r,
[87]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[88] static ngx_int_t ngx_http_ssi_stub_output(ngx_http_request_t *r, void *data,
[89]     ngx_int_t rc);
[90] static ngx_int_t ngx_http_ssi_set_variable(ngx_http_request_t *r, void *data,
[91]     ngx_int_t rc);
[92] static ngx_int_t ngx_http_ssi_echo(ngx_http_request_t *r,
[93]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[94] static ngx_int_t ngx_http_ssi_config(ngx_http_request_t *r,
[95]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[96] static ngx_int_t ngx_http_ssi_set(ngx_http_request_t *r,
[97]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[98] static ngx_int_t ngx_http_ssi_if(ngx_http_request_t *r,
[99]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[100] static ngx_int_t ngx_http_ssi_else(ngx_http_request_t *r,
[101]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[102] static ngx_int_t ngx_http_ssi_endif(ngx_http_request_t *r,
[103]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[104] static ngx_int_t ngx_http_ssi_block(ngx_http_request_t *r,
[105]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[106] static ngx_int_t ngx_http_ssi_endblock(ngx_http_request_t *r,
[107]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **params);
[108] 
[109] static ngx_int_t ngx_http_ssi_date_gmt_local_variable(ngx_http_request_t *r,
[110]     ngx_http_variable_value_t *v, uintptr_t gmt);
[111] 
[112] static ngx_int_t ngx_http_ssi_preconfiguration(ngx_conf_t *cf);
[113] static void *ngx_http_ssi_create_main_conf(ngx_conf_t *cf);
[114] static char *ngx_http_ssi_init_main_conf(ngx_conf_t *cf, void *conf);
[115] static void *ngx_http_ssi_create_loc_conf(ngx_conf_t *cf);
[116] static char *ngx_http_ssi_merge_loc_conf(ngx_conf_t *cf,
[117]     void *parent, void *child);
[118] static ngx_int_t ngx_http_ssi_filter_init(ngx_conf_t *cf);
[119] 
[120] 
[121] static ngx_command_t  ngx_http_ssi_filter_commands[] = {
[122] 
[123]     { ngx_string("ssi"),
[124]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[125]                         |NGX_CONF_FLAG,
[126]       ngx_conf_set_flag_slot,
[127]       NGX_HTTP_LOC_CONF_OFFSET,
[128]       offsetof(ngx_http_ssi_loc_conf_t, enable),
[129]       NULL },
[130] 
[131]     { ngx_string("ssi_silent_errors"),
[132]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[133]       ngx_conf_set_flag_slot,
[134]       NGX_HTTP_LOC_CONF_OFFSET,
[135]       offsetof(ngx_http_ssi_loc_conf_t, silent_errors),
[136]       NULL },
[137] 
[138]     { ngx_string("ssi_ignore_recycled_buffers"),
[139]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[140]       ngx_conf_set_flag_slot,
[141]       NGX_HTTP_LOC_CONF_OFFSET,
[142]       offsetof(ngx_http_ssi_loc_conf_t, ignore_recycled_buffers),
[143]       NULL },
[144] 
[145]     { ngx_string("ssi_min_file_chunk"),
[146]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[147]       ngx_conf_set_size_slot,
[148]       NGX_HTTP_LOC_CONF_OFFSET,
[149]       offsetof(ngx_http_ssi_loc_conf_t, min_file_chunk),
[150]       NULL },
[151] 
[152]     { ngx_string("ssi_value_length"),
[153]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[154]       ngx_conf_set_size_slot,
[155]       NGX_HTTP_LOC_CONF_OFFSET,
[156]       offsetof(ngx_http_ssi_loc_conf_t, value_len),
[157]       NULL },
[158] 
[159]     { ngx_string("ssi_types"),
[160]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[161]       ngx_http_types_slot,
[162]       NGX_HTTP_LOC_CONF_OFFSET,
[163]       offsetof(ngx_http_ssi_loc_conf_t, types_keys),
[164]       &ngx_http_html_default_types[0] },
[165] 
[166]     { ngx_string("ssi_last_modified"),
[167]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[168]       ngx_conf_set_flag_slot,
[169]       NGX_HTTP_LOC_CONF_OFFSET,
[170]       offsetof(ngx_http_ssi_loc_conf_t, last_modified),
[171]       NULL },
[172] 
[173]       ngx_null_command
[174] };
[175] 
[176] 
[177] 
[178] static ngx_http_module_t  ngx_http_ssi_filter_module_ctx = {
[179]     ngx_http_ssi_preconfiguration,         /* preconfiguration */
[180]     ngx_http_ssi_filter_init,              /* postconfiguration */
[181] 
[182]     ngx_http_ssi_create_main_conf,         /* create main configuration */
[183]     ngx_http_ssi_init_main_conf,           /* init main configuration */
[184] 
[185]     NULL,                                  /* create server configuration */
[186]     NULL,                                  /* merge server configuration */
[187] 
[188]     ngx_http_ssi_create_loc_conf,          /* create location configuration */
[189]     ngx_http_ssi_merge_loc_conf            /* merge location configuration */
[190] };
[191] 
[192] 
[193] ngx_module_t  ngx_http_ssi_filter_module = {
[194]     NGX_MODULE_V1,
[195]     &ngx_http_ssi_filter_module_ctx,       /* module context */
[196]     ngx_http_ssi_filter_commands,          /* module directives */
[197]     NGX_HTTP_MODULE,                       /* module type */
[198]     NULL,                                  /* init master */
[199]     NULL,                                  /* init module */
[200]     NULL,                                  /* init process */
[201]     NULL,                                  /* init thread */
[202]     NULL,                                  /* exit thread */
[203]     NULL,                                  /* exit process */
[204]     NULL,                                  /* exit master */
[205]     NGX_MODULE_V1_PADDING
[206] };
[207] 
[208] 
[209] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[210] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[211] 
[212] 
[213] static u_char ngx_http_ssi_string[] = "<!--";
[214] 
[215] static ngx_str_t ngx_http_ssi_none = ngx_string("(none)");
[216] static ngx_str_t ngx_http_ssi_timefmt = ngx_string("%A, %d-%b-%Y %H:%M:%S %Z");
[217] static ngx_str_t ngx_http_ssi_null_string = ngx_null_string;
[218] 
[219] 
[220] #define  NGX_HTTP_SSI_INCLUDE_VIRTUAL  0
[221] #define  NGX_HTTP_SSI_INCLUDE_FILE     1
[222] #define  NGX_HTTP_SSI_INCLUDE_WAIT     2
[223] #define  NGX_HTTP_SSI_INCLUDE_SET      3
[224] #define  NGX_HTTP_SSI_INCLUDE_STUB     4
[225] 
[226] #define  NGX_HTTP_SSI_ECHO_VAR         0
[227] #define  NGX_HTTP_SSI_ECHO_DEFAULT     1
[228] #define  NGX_HTTP_SSI_ECHO_ENCODING    2
[229] 
[230] #define  NGX_HTTP_SSI_CONFIG_ERRMSG    0
[231] #define  NGX_HTTP_SSI_CONFIG_TIMEFMT   1
[232] 
[233] #define  NGX_HTTP_SSI_SET_VAR          0
[234] #define  NGX_HTTP_SSI_SET_VALUE        1
[235] 
[236] #define  NGX_HTTP_SSI_IF_EXPR          0
[237] 
[238] #define  NGX_HTTP_SSI_BLOCK_NAME       0
[239] 
[240] 
[241] static ngx_http_ssi_param_t  ngx_http_ssi_include_params[] = {
[242]     { ngx_string("virtual"), NGX_HTTP_SSI_INCLUDE_VIRTUAL, 0, 0 },
[243]     { ngx_string("file"), NGX_HTTP_SSI_INCLUDE_FILE, 0, 0 },
[244]     { ngx_string("wait"), NGX_HTTP_SSI_INCLUDE_WAIT, 0, 0 },
[245]     { ngx_string("set"), NGX_HTTP_SSI_INCLUDE_SET, 0, 0 },
[246]     { ngx_string("stub"), NGX_HTTP_SSI_INCLUDE_STUB, 0, 0 },
[247]     { ngx_null_string, 0, 0, 0 }
[248] };
[249] 
[250] 
[251] static ngx_http_ssi_param_t  ngx_http_ssi_echo_params[] = {
[252]     { ngx_string("var"), NGX_HTTP_SSI_ECHO_VAR, 1, 0 },
[253]     { ngx_string("default"), NGX_HTTP_SSI_ECHO_DEFAULT, 0, 0 },
[254]     { ngx_string("encoding"), NGX_HTTP_SSI_ECHO_ENCODING, 0, 0 },
[255]     { ngx_null_string, 0, 0, 0 }
[256] };
[257] 
[258] 
[259] static ngx_http_ssi_param_t  ngx_http_ssi_config_params[] = {
[260]     { ngx_string("errmsg"), NGX_HTTP_SSI_CONFIG_ERRMSG, 0, 0 },
[261]     { ngx_string("timefmt"), NGX_HTTP_SSI_CONFIG_TIMEFMT, 0, 0 },
[262]     { ngx_null_string, 0, 0, 0 }
[263] };
[264] 
[265] 
[266] static ngx_http_ssi_param_t  ngx_http_ssi_set_params[] = {
[267]     { ngx_string("var"), NGX_HTTP_SSI_SET_VAR, 1, 0 },
[268]     { ngx_string("value"), NGX_HTTP_SSI_SET_VALUE, 1, 0 },
[269]     { ngx_null_string, 0, 0, 0 }
[270] };
[271] 
[272] 
[273] static ngx_http_ssi_param_t  ngx_http_ssi_if_params[] = {
[274]     { ngx_string("expr"), NGX_HTTP_SSI_IF_EXPR, 1, 0 },
[275]     { ngx_null_string, 0, 0, 0 }
[276] };
[277] 
[278] 
[279] static ngx_http_ssi_param_t  ngx_http_ssi_block_params[] = {
[280]     { ngx_string("name"), NGX_HTTP_SSI_BLOCK_NAME, 1, 0 },
[281]     { ngx_null_string, 0, 0, 0 }
[282] };
[283] 
[284] 
[285] static ngx_http_ssi_param_t  ngx_http_ssi_no_params[] = {
[286]     { ngx_null_string, 0, 0, 0 }
[287] };
[288] 
[289] 
[290] static ngx_http_ssi_command_t  ngx_http_ssi_commands[] = {
[291]     { ngx_string("include"), ngx_http_ssi_include,
[292]                        ngx_http_ssi_include_params, 0, 0, 1 },
[293]     { ngx_string("echo"), ngx_http_ssi_echo,
[294]                        ngx_http_ssi_echo_params, 0, 0, 0 },
[295]     { ngx_string("config"), ngx_http_ssi_config,
[296]                        ngx_http_ssi_config_params, 0, 0, 0 },
[297]     { ngx_string("set"), ngx_http_ssi_set, ngx_http_ssi_set_params, 0, 0, 0 },
[298] 
[299]     { ngx_string("if"), ngx_http_ssi_if, ngx_http_ssi_if_params, 0, 0, 0 },
[300]     { ngx_string("elif"), ngx_http_ssi_if, ngx_http_ssi_if_params,
[301]                        NGX_HTTP_SSI_COND_IF, 0, 0 },
[302]     { ngx_string("else"), ngx_http_ssi_else, ngx_http_ssi_no_params,
[303]                        NGX_HTTP_SSI_COND_IF, 0, 0 },
[304]     { ngx_string("endif"), ngx_http_ssi_endif, ngx_http_ssi_no_params,
[305]                        NGX_HTTP_SSI_COND_ELSE, 0, 0 },
[306] 
[307]     { ngx_string("block"), ngx_http_ssi_block,
[308]                        ngx_http_ssi_block_params, 0, 0, 0 },
[309]     { ngx_string("endblock"), ngx_http_ssi_endblock,
[310]                        ngx_http_ssi_no_params, 0, 1, 0 },
[311] 
[312]     { ngx_null_string, NULL, NULL, 0, 0, 0 }
[313] };
[314] 
[315] 
[316] static ngx_http_variable_t  ngx_http_ssi_vars[] = {
[317] 
[318]     { ngx_string("date_local"), NULL, ngx_http_ssi_date_gmt_local_variable, 0,
[319]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[320] 
[321]     { ngx_string("date_gmt"), NULL, ngx_http_ssi_date_gmt_local_variable, 1,
[322]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[323] 
[324]       ngx_http_null_variable
[325] };
[326] 
[327] 
[328] 
[329] static ngx_int_t
[330] ngx_http_ssi_header_filter(ngx_http_request_t *r)
[331] {
[332]     ngx_http_ssi_ctx_t       *ctx, *mctx;
[333]     ngx_http_ssi_loc_conf_t  *slcf;
[334] 
[335]     slcf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);
[336] 
[337]     if (!slcf->enable
[338]         || r->headers_out.content_length_n == 0
[339]         || ngx_http_test_content_type(r, &slcf->types) == NULL)
[340]     {
[341]         return ngx_http_next_header_filter(r);
[342]     }
[343] 
[344]     mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);
[345] 
[346]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ssi_ctx_t));
[347]     if (ctx == NULL) {
[348]         return NGX_ERROR;
[349]     }
[350] 
[351]     ngx_http_set_ctx(r, ctx, ngx_http_ssi_filter_module);
[352] 
[353] 
[354]     ctx->value_len = slcf->value_len;
[355]     ctx->last_out = &ctx->out;
[356] 
[357]     ctx->encoding = NGX_HTTP_SSI_ENTITY_ENCODING;
[358]     ctx->output = 1;
[359] 
[360]     ctx->params.elts = ctx->params_array;
[361]     ctx->params.size = sizeof(ngx_table_elt_t);
[362]     ctx->params.nalloc = NGX_HTTP_SSI_PARAMS_N;
[363]     ctx->params.pool = r->pool;
[364] 
[365]     ctx->timefmt = ngx_http_ssi_timefmt;
[366]     ngx_str_set(&ctx->errmsg,
[367]                 "[an error occurred while processing the directive]");
[368] 
[369]     r->filter_need_in_memory = 1;
[370] 
[371]     if (r == r->main) {
[372] 
[373]         if (mctx) {
[374] 
[375]             /*
[376]              * if there was a shared context previously used as main,
[377]              * copy variables and blocks
[378]              */
[379] 
[380]             ctx->variables = mctx->variables;
[381]             ctx->blocks = mctx->blocks;
[382] 
[383] #if (NGX_PCRE)
[384]             ctx->ncaptures = mctx->ncaptures;
[385]             ctx->captures = mctx->captures;
[386]             ctx->captures_data = mctx->captures_data;
[387] #endif
[388] 
[389]             mctx->shared = 0;
[390]         }
[391] 
[392]         ngx_http_clear_content_length(r);
[393]         ngx_http_clear_accept_ranges(r);
[394] 
[395]         r->preserve_body = 1;
[396] 
[397]         if (!slcf->last_modified) {
[398]             ngx_http_clear_last_modified(r);
[399]             ngx_http_clear_etag(r);
[400] 
[401]         } else {
[402]             ngx_http_weak_etag(r);
[403]         }
[404] 
[405]     } else if (mctx == NULL) {
[406]         ngx_http_set_ctx(r->main, ctx, ngx_http_ssi_filter_module);
[407]         ctx->shared = 1;
[408]     }
[409] 
[410]     return ngx_http_next_header_filter(r);
[411] }
[412] 
[413] 
[414] static ngx_int_t
[415] ngx_http_ssi_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[416] {
[417]     size_t                     len;
[418]     ngx_int_t                  rc;
[419]     ngx_buf_t                 *b;
[420]     ngx_uint_t                 i, index;
[421]     ngx_chain_t               *cl, **ll;
[422]     ngx_table_elt_t           *param;
[423]     ngx_http_ssi_ctx_t        *ctx, *mctx;
[424]     ngx_http_ssi_block_t      *bl;
[425]     ngx_http_ssi_param_t      *prm;
[426]     ngx_http_ssi_command_t    *cmd;
[427]     ngx_http_ssi_loc_conf_t   *slcf;
[428]     ngx_http_ssi_main_conf_t  *smcf;
[429]     ngx_str_t                 *params[NGX_HTTP_SSI_MAX_PARAMS + 1];
[430] 
[431]     ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);
[432] 
[433]     if (ctx == NULL
[434]         || (ctx->shared && r == r->main)
[435]         || (in == NULL
[436]             && ctx->buf == NULL
[437]             && ctx->in == NULL
[438]             && ctx->busy == NULL))
[439]     {
[440]         return ngx_http_next_body_filter(r, in);
[441]     }
[442] 
[443]     /* add the incoming chain to the chain ctx->in */
[444] 
[445]     if (in) {
[446]         if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
[447]             return NGX_ERROR;
[448]         }
[449]     }
[450] 
[451]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[452]                    "http ssi filter \"%V?%V\"", &r->uri, &r->args);
[453] 
[454]     if (ctx->wait) {
[455] 
[456]         if (r != r->connection->data) {
[457]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[458]                            "http ssi filter wait \"%V?%V\" non-active",
[459]                            &ctx->wait->uri, &ctx->wait->args);
[460] 
[461]             return NGX_AGAIN;
[462]         }
[463] 
[464]         if (ctx->wait->done) {
[465]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[466]                            "http ssi filter wait \"%V?%V\" done",
[467]                            &ctx->wait->uri, &ctx->wait->args);
[468] 
[469]             ctx->wait = NULL;
[470] 
[471]         } else {
[472]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[473]                            "http ssi filter wait \"%V?%V\"",
[474]                            &ctx->wait->uri, &ctx->wait->args);
[475] 
[476]             return ngx_http_next_body_filter(r, NULL);
[477]         }
[478]     }
[479] 
[480]     slcf = ngx_http_get_module_loc_conf(r, ngx_http_ssi_filter_module);
[481] 
[482]     while (ctx->in || ctx->buf) {
[483] 
[484]         if (ctx->buf == NULL) {
[485]             ctx->buf = ctx->in->buf;
[486]             ctx->in = ctx->in->next;
[487]             ctx->pos = ctx->buf->pos;
[488]         }
[489] 
[490]         if (ctx->state == ssi_start_state) {
[491]             ctx->copy_start = ctx->pos;
[492]             ctx->copy_end = ctx->pos;
[493]         }
[494] 
[495]         b = NULL;
[496] 
[497]         while (ctx->pos < ctx->buf->last) {
[498] 
[499]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[500]                            "saved: %uz state: %ui", ctx->saved, ctx->state);
[501] 
[502]             rc = ngx_http_ssi_parse(r, ctx);
[503] 
[504]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[505]                            "parse: %i, looked: %uz %p-%p",
[506]                            rc, ctx->looked, ctx->copy_start, ctx->copy_end);
[507] 
[508]             if (rc == NGX_ERROR) {
[509]                 return rc;
[510]             }
[511] 
[512]             if (ctx->copy_start != ctx->copy_end) {
[513] 
[514]                 if (ctx->output) {
[515] 
[516]                     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[517]                                    "saved: %uz", ctx->saved);
[518] 
[519]                     if (ctx->saved) {
[520] 
[521]                         if (ctx->free) {
[522]                             cl = ctx->free;
[523]                             ctx->free = ctx->free->next;
[524]                             b = cl->buf;
[525]                             ngx_memzero(b, sizeof(ngx_buf_t));
[526] 
[527]                         } else {
[528]                             b = ngx_calloc_buf(r->pool);
[529]                             if (b == NULL) {
[530]                                 return NGX_ERROR;
[531]                             }
[532] 
[533]                             cl = ngx_alloc_chain_link(r->pool);
[534]                             if (cl == NULL) {
[535]                                 return NGX_ERROR;
[536]                             }
[537] 
[538]                             cl->buf = b;
[539]                         }
[540] 
[541]                         b->memory = 1;
[542]                         b->pos = ngx_http_ssi_string;
[543]                         b->last = ngx_http_ssi_string + ctx->saved;
[544] 
[545]                         *ctx->last_out = cl;
[546]                         ctx->last_out = &cl->next;
[547] 
[548]                         ctx->saved = 0;
[549]                     }
[550] 
[551]                     if (ctx->free) {
[552]                         cl = ctx->free;
[553]                         ctx->free = ctx->free->next;
[554]                         b = cl->buf;
[555] 
[556]                     } else {
[557]                         b = ngx_alloc_buf(r->pool);
[558]                         if (b == NULL) {
[559]                             return NGX_ERROR;
[560]                         }
[561] 
[562]                         cl = ngx_alloc_chain_link(r->pool);
[563]                         if (cl == NULL) {
[564]                             return NGX_ERROR;
[565]                         }
[566] 
[567]                         cl->buf = b;
[568]                     }
[569] 
[570]                     ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));
[571] 
[572]                     b->pos = ctx->copy_start;
[573]                     b->last = ctx->copy_end;
[574]                     b->shadow = NULL;
[575]                     b->last_buf = 0;
[576]                     b->recycled = 0;
[577] 
[578]                     if (b->in_file) {
[579]                         if (slcf->min_file_chunk < (size_t) (b->last - b->pos))
[580]                         {
[581]                             b->file_last = b->file_pos
[582]                                                    + (b->last - ctx->buf->pos);
[583]                             b->file_pos += b->pos - ctx->buf->pos;
[584] 
[585]                         } else {
[586]                             b->in_file = 0;
[587]                         }
[588]                     }
[589] 
[590]                     cl->next = NULL;
[591]                     *ctx->last_out = cl;
[592]                     ctx->last_out = &cl->next;
[593] 
[594]                 } else {
[595]                     if (ctx->block
[596]                         && ctx->saved + (ctx->copy_end - ctx->copy_start))
[597]                     {
[598]                         b = ngx_create_temp_buf(r->pool,
[599]                                ctx->saved + (ctx->copy_end - ctx->copy_start));
[600] 
[601]                         if (b == NULL) {
[602]                             return NGX_ERROR;
[603]                         }
[604] 
[605]                         if (ctx->saved) {
[606]                             b->last = ngx_cpymem(b->pos, ngx_http_ssi_string,
[607]                                                  ctx->saved);
[608]                         }
[609] 
[610]                         b->last = ngx_cpymem(b->last, ctx->copy_start,
[611]                                              ctx->copy_end - ctx->copy_start);
[612] 
[613]                         cl = ngx_alloc_chain_link(r->pool);
[614]                         if (cl == NULL) {
[615]                             return NGX_ERROR;
[616]                         }
[617] 
[618]                         cl->buf = b;
[619]                         cl->next = NULL;
[620] 
[621]                         b = NULL;
[622] 
[623]                         mctx = ngx_http_get_module_ctx(r->main,
[624]                                                    ngx_http_ssi_filter_module);
[625]                         bl = mctx->blocks->elts;
[626]                         for (ll = &bl[mctx->blocks->nelts - 1].bufs;
[627]                              *ll;
[628]                              ll = &(*ll)->next)
[629]                         {
[630]                             /* void */
[631]                         }
[632] 
[633]                         *ll = cl;
[634]                     }
[635] 
[636]                     ctx->saved = 0;
[637]                 }
[638]             }
[639] 
[640]             if (ctx->state == ssi_start_state) {
[641]                 ctx->copy_start = ctx->pos;
[642]                 ctx->copy_end = ctx->pos;
[643] 
[644]             } else {
[645]                 ctx->copy_start = NULL;
[646]                 ctx->copy_end = NULL;
[647]             }
[648] 
[649]             if (rc == NGX_AGAIN) {
[650]                 continue;
[651]             }
[652] 
[653] 
[654]             b = NULL;
[655] 
[656]             if (rc == NGX_OK) {
[657] 
[658]                 smcf = ngx_http_get_module_main_conf(r,
[659]                                                    ngx_http_ssi_filter_module);
[660] 
[661]                 cmd = ngx_hash_find(&smcf->hash, ctx->key, ctx->command.data,
[662]                                     ctx->command.len);
[663] 
[664]                 if (cmd == NULL) {
[665]                     if (ctx->output) {
[666]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[667]                                       "invalid SSI command: \"%V\"",
[668]                                       &ctx->command);
[669]                         goto ssi_error;
[670]                     }
[671] 
[672]                     continue;
[673]                 }
[674] 
[675]                 if (!ctx->output && !cmd->block) {
[676] 
[677]                     if (ctx->block) {
[678] 
[679]                         /* reconstruct the SSI command text */
[680] 
[681]                         len = 5 + ctx->command.len + 4;
[682] 
[683]                         param = ctx->params.elts;
[684]                         for (i = 0; i < ctx->params.nelts; i++) {
[685]                             len += 1 + param[i].key.len + 2
[686]                                 + param[i].value.len + 1;
[687]                         }
[688] 
[689]                         b = ngx_create_temp_buf(r->pool, len);
[690] 
[691]                         if (b == NULL) {
[692]                             return NGX_ERROR;
[693]                         }
[694] 
[695]                         cl = ngx_alloc_chain_link(r->pool);
[696]                         if (cl == NULL) {
[697]                             return NGX_ERROR;
[698]                         }
[699] 
[700]                         cl->buf = b;
[701]                         cl->next = NULL;
[702] 
[703]                         *b->last++ = '<';
[704]                         *b->last++ = '!';
[705]                         *b->last++ = '-';
[706]                         *b->last++ = '-';
[707]                         *b->last++ = '#';
[708] 
[709]                         b->last = ngx_cpymem(b->last, ctx->command.data,
[710]                                              ctx->command.len);
[711] 
[712]                         for (i = 0; i < ctx->params.nelts; i++) {
[713]                             *b->last++ = ' ';
[714]                             b->last = ngx_cpymem(b->last, param[i].key.data,
[715]                                                  param[i].key.len);
[716]                             *b->last++ = '=';
[717]                             *b->last++ = '"';
[718]                             b->last = ngx_cpymem(b->last, param[i].value.data,
[719]                                                  param[i].value.len);
[720]                             *b->last++ = '"';
[721]                         }
[722] 
[723]                         *b->last++ = ' ';
[724]                         *b->last++ = '-';
[725]                         *b->last++ = '-';
[726]                         *b->last++ = '>';
[727] 
[728]                         mctx = ngx_http_get_module_ctx(r->main,
[729]                                                    ngx_http_ssi_filter_module);
[730]                         bl = mctx->blocks->elts;
[731]                         for (ll = &bl[mctx->blocks->nelts - 1].bufs;
[732]                              *ll;
[733]                              ll = &(*ll)->next)
[734]                         {
[735]                             /* void */
[736]                         }
[737] 
[738]                         *ll = cl;
[739] 
[740]                         b = NULL;
[741] 
[742]                         continue;
[743]                     }
[744] 
[745]                     if (cmd->conditional == 0) {
[746]                         continue;
[747]                     }
[748]                 }
[749] 
[750]                 if (cmd->conditional
[751]                     && (ctx->conditional == 0
[752]                         || ctx->conditional > cmd->conditional))
[753]                 {
[754]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[755]                                   "invalid context of SSI command: \"%V\"",
[756]                                   &ctx->command);
[757]                     goto ssi_error;
[758]                 }
[759] 
[760]                 if (ctx->params.nelts > NGX_HTTP_SSI_MAX_PARAMS) {
[761]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[762]                                   "too many SSI command parameters: \"%V\"",
[763]                                   &ctx->command);
[764]                     goto ssi_error;
[765]                 }
[766] 
[767]                 ngx_memzero(params,
[768]                            (NGX_HTTP_SSI_MAX_PARAMS + 1) * sizeof(ngx_str_t *));
[769] 
[770]                 param = ctx->params.elts;
[771] 
[772]                 for (i = 0; i < ctx->params.nelts; i++) {
[773] 
[774]                     for (prm = cmd->params; prm->name.len; prm++) {
[775] 
[776]                         if (param[i].key.len != prm->name.len
[777]                             || ngx_strncmp(param[i].key.data, prm->name.data,
[778]                                            prm->name.len) != 0)
[779]                         {
[780]                             continue;
[781]                         }
[782] 
[783]                         if (!prm->multiple) {
[784]                             if (params[prm->index]) {
[785]                                 ngx_log_error(NGX_LOG_ERR,
[786]                                               r->connection->log, 0,
[787]                                               "duplicate \"%V\" parameter "
[788]                                               "in \"%V\" SSI command",
[789]                                               &param[i].key, &ctx->command);
[790] 
[791]                                 goto ssi_error;
[792]                             }
[793] 
[794]                             params[prm->index] = &param[i].value;
[795] 
[796]                             break;
[797]                         }
[798] 
[799]                         for (index = prm->index; params[index]; index++) {
[800]                             /* void */
[801]                         }
[802] 
[803]                         params[index] = &param[i].value;
[804] 
[805]                         break;
[806]                     }
[807] 
[808]                     if (prm->name.len == 0) {
[809]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[810]                                       "invalid parameter name: \"%V\" "
[811]                                       "in \"%V\" SSI command",
[812]                                       &param[i].key, &ctx->command);
[813] 
[814]                         goto ssi_error;
[815]                     }
[816]                 }
[817] 
[818]                 for (prm = cmd->params; prm->name.len; prm++) {
[819]                     if (prm->mandatory && params[prm->index] == 0) {
[820]                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[821]                                       "mandatory \"%V\" parameter is absent "
[822]                                       "in \"%V\" SSI command",
[823]                                       &prm->name, &ctx->command);
[824] 
[825]                         goto ssi_error;
[826]                     }
[827]                 }
[828] 
[829]                 if (cmd->flush && ctx->out) {
[830] 
[831]                     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[832]                                    "ssi flush");
[833] 
[834]                     if (ngx_http_ssi_output(r, ctx) == NGX_ERROR) {
[835]                         return NGX_ERROR;
[836]                     }
[837]                 }
[838] 
[839]                 rc = cmd->handler(r, ctx, params);
[840] 
[841]                 if (rc == NGX_OK) {
[842]                     continue;
[843]                 }
[844] 
[845]                 if (rc == NGX_DONE || rc == NGX_AGAIN || rc == NGX_ERROR) {
[846]                     ngx_http_ssi_buffered(r, ctx);
[847]                     return rc;
[848]                 }
[849]             }
[850] 
[851] 
[852]             /* rc == NGX_HTTP_SSI_ERROR */
[853] 
[854]     ssi_error:
[855] 
[856]             if (slcf->silent_errors) {
[857]                 continue;
[858]             }
[859] 
[860]             if (ctx->free) {
[861]                 cl = ctx->free;
[862]                 ctx->free = ctx->free->next;
[863]                 b = cl->buf;
[864]                 ngx_memzero(b, sizeof(ngx_buf_t));
[865] 
[866]             } else {
[867]                 b = ngx_calloc_buf(r->pool);
[868]                 if (b == NULL) {
[869]                     return NGX_ERROR;
[870]                 }
[871] 
[872]                 cl = ngx_alloc_chain_link(r->pool);
[873]                 if (cl == NULL) {
[874]                     return NGX_ERROR;
[875]                 }
[876] 
[877]                 cl->buf = b;
[878]             }
[879] 
[880]             b->memory = 1;
[881]             b->pos = ctx->errmsg.data;
[882]             b->last = ctx->errmsg.data + ctx->errmsg.len;
[883] 
[884]             cl->next = NULL;
[885]             *ctx->last_out = cl;
[886]             ctx->last_out = &cl->next;
[887] 
[888]             continue;
[889]         }
[890] 
[891]         if (ctx->buf->last_buf || ngx_buf_in_memory(ctx->buf)) {
[892]             if (b == NULL) {
[893]                 if (ctx->free) {
[894]                     cl = ctx->free;
[895]                     ctx->free = ctx->free->next;
[896]                     b = cl->buf;
[897]                     ngx_memzero(b, sizeof(ngx_buf_t));
[898] 
[899]                 } else {
[900]                     b = ngx_calloc_buf(r->pool);
[901]                     if (b == NULL) {
[902]                         return NGX_ERROR;
[903]                     }
[904] 
[905]                     cl = ngx_alloc_chain_link(r->pool);
[906]                     if (cl == NULL) {
[907]                         return NGX_ERROR;
[908]                     }
[909] 
[910]                     cl->buf = b;
[911]                 }
[912] 
[913]                 b->sync = 1;
[914] 
[915]                 cl->next = NULL;
[916]                 *ctx->last_out = cl;
[917]                 ctx->last_out = &cl->next;
[918]             }
[919] 
[920]             b->last_buf = ctx->buf->last_buf;
[921]             b->shadow = ctx->buf;
[922] 
[923]             if (slcf->ignore_recycled_buffers == 0)  {
[924]                 b->recycled = ctx->buf->recycled;
[925]             }
[926]         }
[927] 
[928]         ctx->buf = NULL;
[929] 
[930]         ctx->saved = ctx->looked;
[931]     }
[932] 
[933]     if (ctx->out == NULL && ctx->busy == NULL) {
[934]         return NGX_OK;
[935]     }
[936] 
[937]     return ngx_http_ssi_output(r, ctx);
[938] }
[939] 
[940] 
[941] static ngx_int_t
[942] ngx_http_ssi_output(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
[943] {
[944]     ngx_int_t     rc;
[945]     ngx_buf_t    *b;
[946]     ngx_chain_t  *cl;
[947] 
[948] #if 1
[949]     b = NULL;
[950]     for (cl = ctx->out; cl; cl = cl->next) {
[951]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[952]                        "ssi out: %p %p", cl->buf, cl->buf->pos);
[953]         if (cl->buf == b) {
[954]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[955]                           "the same buf was used in ssi");
[956]             ngx_debug_point();
[957]             return NGX_ERROR;
[958]         }
[959]         b = cl->buf;
[960]     }
[961] #endif
[962] 
[963]     rc = ngx_http_next_body_filter(r, ctx->out);
[964] 
[965]     if (ctx->busy == NULL) {
[966]         ctx->busy = ctx->out;
[967] 
[968]     } else {
[969]         for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
[970]         cl->next = ctx->out;
[971]     }
[972] 
[973]     ctx->out = NULL;
[974]     ctx->last_out = &ctx->out;
[975] 
[976]     while (ctx->busy) {
[977] 
[978]         cl = ctx->busy;
[979]         b = cl->buf;
[980] 
[981]         if (ngx_buf_size(b) != 0) {
[982]             break;
[983]         }
[984] 
[985]         if (b->shadow) {
[986]             b->shadow->pos = b->shadow->last;
[987]         }
[988] 
[989]         ctx->busy = cl->next;
[990] 
[991]         if (ngx_buf_in_memory(b) || b->in_file) {
[992]             /* add data bufs only to the free buf chain */
[993] 
[994]             cl->next = ctx->free;
[995]             ctx->free = cl;
[996]         }
[997]     }
[998] 
[999]     ngx_http_ssi_buffered(r, ctx);
[1000] 
[1001]     return rc;
[1002] }
[1003] 
[1004] 
[1005] static void
[1006] ngx_http_ssi_buffered(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
[1007] {
[1008]     if (ctx->in || ctx->buf) {
[1009]         r->buffered |= NGX_HTTP_SSI_BUFFERED;
[1010] 
[1011]     } else {
[1012]         r->buffered &= ~NGX_HTTP_SSI_BUFFERED;
[1013]     }
[1014] }
[1015] 
[1016] 
[1017] static ngx_int_t
[1018] ngx_http_ssi_parse(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx)
[1019] {
[1020]     u_char                *p, *value, *last, *copy_end, ch;
[1021]     size_t                 looked;
[1022]     ngx_http_ssi_state_e   state;
[1023] 
[1024]     state = ctx->state;
[1025]     looked = ctx->looked;
[1026]     last = ctx->buf->last;
[1027]     copy_end = ctx->copy_end;
[1028] 
[1029]     for (p = ctx->pos; p < last; p++) {
[1030] 
[1031]         ch = *p;
[1032] 
[1033]         if (state == ssi_start_state) {
[1034] 
[1035]             /* the tight loop */
[1036] 
[1037]             for ( ;; ) {
[1038]                 if (ch == '<') {
[1039]                     copy_end = p;
[1040]                     looked = 1;
[1041]                     state = ssi_tag_state;
[1042] 
[1043]                     goto tag_started;
[1044]                 }
[1045] 
[1046]                 if (++p == last) {
[1047]                     break;
[1048]                 }
[1049] 
[1050]                 ch = *p;
[1051]             }
[1052] 
[1053]             ctx->state = state;
[1054]             ctx->pos = p;
[1055]             ctx->looked = looked;
[1056]             ctx->copy_end = p;
[1057] 
[1058]             if (ctx->copy_start == NULL) {
[1059]                 ctx->copy_start = ctx->buf->pos;
[1060]             }
[1061] 
[1062]             return NGX_AGAIN;
[1063] 
[1064]         tag_started:
[1065] 
[1066]             continue;
[1067]         }
[1068] 
[1069]         switch (state) {
[1070] 
[1071]         case ssi_start_state:
[1072]             /* not reached */
[1073]             break;
[1074] 
[1075]         case ssi_tag_state:
[1076]             switch (ch) {
[1077]             case '!':
[1078]                 looked = 2;
[1079]                 state = ssi_comment0_state;
[1080]                 break;
[1081] 
[1082]             case '<':
[1083]                 copy_end = p;
[1084]                 break;
[1085] 
[1086]             default:
[1087]                 copy_end = p;
[1088]                 looked = 0;
[1089]                 state = ssi_start_state;
[1090]                 break;
[1091]             }
[1092] 
[1093]             break;
[1094] 
[1095]         case ssi_comment0_state:
[1096]             switch (ch) {
[1097]             case '-':
[1098]                 looked = 3;
[1099]                 state = ssi_comment1_state;
[1100]                 break;
[1101] 
[1102]             case '<':
[1103]                 copy_end = p;
[1104]                 looked = 1;
[1105]                 state = ssi_tag_state;
[1106]                 break;
[1107] 
[1108]             default:
[1109]                 copy_end = p;
[1110]                 looked = 0;
[1111]                 state = ssi_start_state;
[1112]                 break;
[1113]             }
[1114] 
[1115]             break;
[1116] 
[1117]         case ssi_comment1_state:
[1118]             switch (ch) {
[1119]             case '-':
[1120]                 looked = 4;
[1121]                 state = ssi_sharp_state;
[1122]                 break;
[1123] 
[1124]             case '<':
[1125]                 copy_end = p;
[1126]                 looked = 1;
[1127]                 state = ssi_tag_state;
[1128]                 break;
[1129] 
[1130]             default:
[1131]                 copy_end = p;
[1132]                 looked = 0;
[1133]                 state = ssi_start_state;
[1134]                 break;
[1135]             }
[1136] 
[1137]             break;
[1138] 
[1139]         case ssi_sharp_state:
[1140]             switch (ch) {
[1141]             case '#':
[1142]                 if (p - ctx->pos < 4) {
[1143]                     ctx->saved = 0;
[1144]                 }
[1145]                 looked = 0;
[1146]                 state = ssi_precommand_state;
[1147]                 break;
[1148] 
[1149]             case '<':
[1150]                 copy_end = p;
[1151]                 looked = 1;
[1152]                 state = ssi_tag_state;
[1153]                 break;
[1154] 
[1155]             default:
[1156]                 copy_end = p;
[1157]                 looked = 0;
[1158]                 state = ssi_start_state;
[1159]                 break;
[1160]             }
[1161] 
[1162]             break;
[1163] 
[1164]         case ssi_precommand_state:
[1165]             switch (ch) {
[1166]             case ' ':
[1167]             case CR:
[1168]             case LF:
[1169]             case '\t':
[1170]                 break;
[1171] 
[1172]             default:
[1173]                 ctx->command.len = 1;
[1174]                 ctx->command.data = ngx_pnalloc(r->pool,
[1175]                                                 NGX_HTTP_SSI_COMMAND_LEN);
[1176]                 if (ctx->command.data == NULL) {
[1177]                     return NGX_ERROR;
[1178]                 }
[1179] 
[1180]                 ctx->command.data[0] = ch;
[1181] 
[1182]                 ctx->key = 0;
[1183]                 ctx->key = ngx_hash(ctx->key, ch);
[1184] 
[1185]                 ctx->params.nelts = 0;
[1186] 
[1187]                 state = ssi_command_state;
[1188]                 break;
[1189]             }
[1190] 
[1191]             break;
[1192] 
[1193]         case ssi_command_state:
[1194]             switch (ch) {
[1195]             case ' ':
[1196]             case CR:
[1197]             case LF:
[1198]             case '\t':
[1199]                 state = ssi_preparam_state;
[1200]                 break;
[1201] 
[1202]             case '-':
[1203]                 state = ssi_comment_end0_state;
[1204]                 break;
[1205] 
[1206]             default:
[1207]                 if (ctx->command.len == NGX_HTTP_SSI_COMMAND_LEN) {
[1208]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1209]                                   "the \"%V%c...\" SSI command is too long",
[1210]                                   &ctx->command, ch);
[1211] 
[1212]                     state = ssi_error_state;
[1213]                     break;
[1214]                 }
[1215] 
[1216]                 ctx->command.data[ctx->command.len++] = ch;
[1217]                 ctx->key = ngx_hash(ctx->key, ch);
[1218]             }
[1219] 
[1220]             break;
[1221] 
[1222]         case ssi_preparam_state:
[1223]             switch (ch) {
[1224]             case ' ':
[1225]             case CR:
[1226]             case LF:
[1227]             case '\t':
[1228]                 break;
[1229] 
[1230]             case '-':
[1231]                 state = ssi_comment_end0_state;
[1232]                 break;
[1233] 
[1234]             default:
[1235]                 ctx->param = ngx_array_push(&ctx->params);
[1236]                 if (ctx->param == NULL) {
[1237]                     return NGX_ERROR;
[1238]                 }
[1239] 
[1240]                 ctx->param->key.len = 1;
[1241]                 ctx->param->key.data = ngx_pnalloc(r->pool,
[1242]                                                    NGX_HTTP_SSI_PARAM_LEN);
[1243]                 if (ctx->param->key.data == NULL) {
[1244]                     return NGX_ERROR;
[1245]                 }
[1246] 
[1247]                 ctx->param->key.data[0] = ch;
[1248] 
[1249]                 ctx->param->value.len = 0;
[1250] 
[1251]                 if (ctx->value_buf == NULL) {
[1252]                     ctx->param->value.data = ngx_pnalloc(r->pool,
[1253]                                                          ctx->value_len + 1);
[1254]                     if (ctx->param->value.data == NULL) {
[1255]                         return NGX_ERROR;
[1256]                     }
[1257] 
[1258]                 } else {
[1259]                     ctx->param->value.data = ctx->value_buf;
[1260]                 }
[1261] 
[1262]                 state = ssi_param_state;
[1263]                 break;
[1264]             }
[1265] 
[1266]             break;
[1267] 
[1268]         case ssi_param_state:
[1269]             switch (ch) {
[1270]             case ' ':
[1271]             case CR:
[1272]             case LF:
[1273]             case '\t':
[1274]                 state = ssi_preequal_state;
[1275]                 break;
[1276] 
[1277]             case '=':
[1278]                 state = ssi_prevalue_state;
[1279]                 break;
[1280] 
[1281]             case '-':
[1282]                 state = ssi_error_end0_state;
[1283] 
[1284]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1285]                               "unexpected \"-\" symbol after \"%V\" "
[1286]                               "parameter in \"%V\" SSI command",
[1287]                               &ctx->param->key, &ctx->command);
[1288]                 break;
[1289] 
[1290]             default:
[1291]                 if (ctx->param->key.len == NGX_HTTP_SSI_PARAM_LEN) {
[1292]                     state = ssi_error_state;
[1293]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1294]                                   "too long \"%V%c...\" parameter in "
[1295]                                   "\"%V\" SSI command",
[1296]                                   &ctx->param->key, ch, &ctx->command);
[1297]                     break;
[1298]                 }
[1299] 
[1300]                 ctx->param->key.data[ctx->param->key.len++] = ch;
[1301]             }
[1302] 
[1303]             break;
[1304] 
[1305]         case ssi_preequal_state:
[1306]             switch (ch) {
[1307]             case ' ':
[1308]             case CR:
[1309]             case LF:
[1310]             case '\t':
[1311]                 break;
[1312] 
[1313]             case '=':
[1314]                 state = ssi_prevalue_state;
[1315]                 break;
[1316] 
[1317]             default:
[1318]                 if (ch == '-') {
[1319]                     state = ssi_error_end0_state;
[1320]                 } else {
[1321]                     state = ssi_error_state;
[1322]                 }
[1323] 
[1324]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1325]                               "unexpected \"%c\" symbol after \"%V\" "
[1326]                               "parameter in \"%V\" SSI command",
[1327]                               ch, &ctx->param->key, &ctx->command);
[1328]                 break;
[1329]             }
[1330] 
[1331]             break;
[1332] 
[1333]         case ssi_prevalue_state:
[1334]             switch (ch) {
[1335]             case ' ':
[1336]             case CR:
[1337]             case LF:
[1338]             case '\t':
[1339]                 break;
[1340] 
[1341]             case '"':
[1342]                 state = ssi_double_quoted_value_state;
[1343]                 break;
[1344] 
[1345]             case '\'':
[1346]                 state = ssi_quoted_value_state;
[1347]                 break;
[1348] 
[1349]             default:
[1350]                 if (ch == '-') {
[1351]                     state = ssi_error_end0_state;
[1352]                 } else {
[1353]                     state = ssi_error_state;
[1354]                 }
[1355] 
[1356]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1357]                               "unexpected \"%c\" symbol before value of "
[1358]                               "\"%V\" parameter in \"%V\" SSI command",
[1359]                               ch, &ctx->param->key, &ctx->command);
[1360]                 break;
[1361]             }
[1362] 
[1363]             break;
[1364] 
[1365]         case ssi_double_quoted_value_state:
[1366]             switch (ch) {
[1367]             case '"':
[1368]                 state = ssi_postparam_state;
[1369]                 break;
[1370] 
[1371]             case '\\':
[1372]                 ctx->saved_state = ssi_double_quoted_value_state;
[1373]                 state = ssi_quoted_symbol_state;
[1374] 
[1375]                 /* fall through */
[1376] 
[1377]             default:
[1378]                 if (ctx->param->value.len == ctx->value_len) {
[1379]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1380]                                   "too long \"%V%c...\" value of \"%V\" "
[1381]                                   "parameter in \"%V\" SSI command",
[1382]                                   &ctx->param->value, ch, &ctx->param->key,
[1383]                                   &ctx->command);
[1384]                     state = ssi_error_state;
[1385]                     break;
[1386]                 }
[1387] 
[1388]                 ctx->param->value.data[ctx->param->value.len++] = ch;
[1389]             }
[1390] 
[1391]             break;
[1392] 
[1393]         case ssi_quoted_value_state:
[1394]             switch (ch) {
[1395]             case '\'':
[1396]                 state = ssi_postparam_state;
[1397]                 break;
[1398] 
[1399]             case '\\':
[1400]                 ctx->saved_state = ssi_quoted_value_state;
[1401]                 state = ssi_quoted_symbol_state;
[1402] 
[1403]                 /* fall through */
[1404] 
[1405]             default:
[1406]                 if (ctx->param->value.len == ctx->value_len) {
[1407]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1408]                                   "too long \"%V%c...\" value of \"%V\" "
[1409]                                   "parameter in \"%V\" SSI command",
[1410]                                   &ctx->param->value, ch, &ctx->param->key,
[1411]                                   &ctx->command);
[1412]                     state = ssi_error_state;
[1413]                     break;
[1414]                 }
[1415] 
[1416]                 ctx->param->value.data[ctx->param->value.len++] = ch;
[1417]             }
[1418] 
[1419]             break;
[1420] 
[1421]         case ssi_quoted_symbol_state:
[1422]             state = ctx->saved_state;
[1423] 
[1424]             if (ctx->param->value.len == ctx->value_len) {
[1425]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1426]                               "too long \"%V%c...\" value of \"%V\" "
[1427]                               "parameter in \"%V\" SSI command",
[1428]                               &ctx->param->value, ch, &ctx->param->key,
[1429]                               &ctx->command);
[1430]                 state = ssi_error_state;
[1431]                 break;
[1432]             }
[1433] 
[1434]             ctx->param->value.data[ctx->param->value.len++] = ch;
[1435] 
[1436]             break;
[1437] 
[1438]         case ssi_postparam_state:
[1439] 
[1440]             if (ctx->param->value.len + 1 < ctx->value_len / 2) {
[1441]                 value = ngx_pnalloc(r->pool, ctx->param->value.len + 1);
[1442]                 if (value == NULL) {
[1443]                     return NGX_ERROR;
[1444]                 }
[1445] 
[1446]                 ngx_memcpy(value, ctx->param->value.data,
[1447]                            ctx->param->value.len);
[1448] 
[1449]                 ctx->value_buf = ctx->param->value.data;
[1450]                 ctx->param->value.data = value;
[1451] 
[1452]             } else {
[1453]                 ctx->value_buf = NULL;
[1454]             }
[1455] 
[1456]             switch (ch) {
[1457]             case ' ':
[1458]             case CR:
[1459]             case LF:
[1460]             case '\t':
[1461]                 state = ssi_preparam_state;
[1462]                 break;
[1463] 
[1464]             case '-':
[1465]                 state = ssi_comment_end0_state;
[1466]                 break;
[1467] 
[1468]             default:
[1469]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1470]                               "unexpected \"%c\" symbol after \"%V\" value "
[1471]                               "of \"%V\" parameter in \"%V\" SSI command",
[1472]                               ch, &ctx->param->value, &ctx->param->key,
[1473]                               &ctx->command);
[1474]                 state = ssi_error_state;
[1475]                 break;
[1476]             }
[1477] 
[1478]             break;
[1479] 
[1480]         case ssi_comment_end0_state:
[1481]             switch (ch) {
[1482]             case '-':
[1483]                 state = ssi_comment_end1_state;
[1484]                 break;
[1485] 
[1486]             default:
[1487]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1488]                               "unexpected \"%c\" symbol in \"%V\" SSI command",
[1489]                               ch, &ctx->command);
[1490]                 state = ssi_error_state;
[1491]                 break;
[1492]             }
[1493] 
[1494]             break;
[1495] 
[1496]         case ssi_comment_end1_state:
[1497]             switch (ch) {
[1498]             case '>':
[1499]                 ctx->state = ssi_start_state;
[1500]                 ctx->pos = p + 1;
[1501]                 ctx->looked = looked;
[1502]                 ctx->copy_end = copy_end;
[1503] 
[1504]                 if (ctx->copy_start == NULL && copy_end) {
[1505]                     ctx->copy_start = ctx->buf->pos;
[1506]                 }
[1507] 
[1508]                 return NGX_OK;
[1509] 
[1510]             default:
[1511]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1512]                               "unexpected \"%c\" symbol in \"%V\" SSI command",
[1513]                               ch, &ctx->command);
[1514]                 state = ssi_error_state;
[1515]                 break;
[1516]             }
[1517] 
[1518]             break;
[1519] 
[1520]         case ssi_error_state:
[1521]             switch (ch) {
[1522]             case '-':
[1523]                 state = ssi_error_end0_state;
[1524]                 break;
[1525] 
[1526]             default:
[1527]                 break;
[1528]             }
[1529] 
[1530]             break;
[1531] 
[1532]         case ssi_error_end0_state:
[1533]             switch (ch) {
[1534]             case '-':
[1535]                 state = ssi_error_end1_state;
[1536]                 break;
[1537] 
[1538]             default:
[1539]                 state = ssi_error_state;
[1540]                 break;
[1541]             }
[1542] 
[1543]             break;
[1544] 
[1545]         case ssi_error_end1_state:
[1546]             switch (ch) {
[1547]             case '>':
[1548]                 ctx->state = ssi_start_state;
[1549]                 ctx->pos = p + 1;
[1550]                 ctx->looked = looked;
[1551]                 ctx->copy_end = copy_end;
[1552] 
[1553]                 if (ctx->copy_start == NULL && copy_end) {
[1554]                     ctx->copy_start = ctx->buf->pos;
[1555]                 }
[1556] 
[1557]                 return NGX_HTTP_SSI_ERROR;
[1558] 
[1559]             default:
[1560]                 state = ssi_error_state;
[1561]                 break;
[1562]             }
[1563] 
[1564]             break;
[1565]         }
[1566]     }
[1567] 
[1568]     ctx->state = state;
[1569]     ctx->pos = p;
[1570]     ctx->looked = looked;
[1571] 
[1572]     ctx->copy_end = (state == ssi_start_state) ? p : copy_end;
[1573] 
[1574]     if (ctx->copy_start == NULL && ctx->copy_end) {
[1575]         ctx->copy_start = ctx->buf->pos;
[1576]     }
[1577] 
[1578]     return NGX_AGAIN;
[1579] }
[1580] 
[1581] 
[1582] static ngx_str_t *
[1583] ngx_http_ssi_get_variable(ngx_http_request_t *r, ngx_str_t *name,
[1584]     ngx_uint_t key)
[1585] {
[1586]     ngx_uint_t           i;
[1587]     ngx_list_part_t     *part;
[1588]     ngx_http_ssi_var_t  *var;
[1589]     ngx_http_ssi_ctx_t  *ctx;
[1590] 
[1591]     ctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);
[1592] 
[1593] #if (NGX_PCRE)
[1594]     {
[1595]     ngx_str_t  *value;
[1596] 
[1597]     if (key >= '0' && key <= '9') {
[1598]         i = key - '0';
[1599] 
[1600]         if (i < ctx->ncaptures) {
[1601]             value = ngx_palloc(r->pool, sizeof(ngx_str_t));
[1602]             if (value == NULL) {
[1603]                 return NULL;
[1604]             }
[1605] 
[1606]             i *= 2;
[1607] 
[1608]             value->data = ctx->captures_data + ctx->captures[i];
[1609]             value->len = ctx->captures[i + 1] - ctx->captures[i];
[1610] 
[1611]             return value;
[1612]         }
[1613]     }
[1614]     }
[1615] #endif
[1616] 
[1617]     if (ctx->variables == NULL) {
[1618]         return NULL;
[1619]     }
[1620] 
[1621]     part = &ctx->variables->part;
[1622]     var = part->elts;
[1623] 
[1624]     for (i = 0; /* void */ ; i++) {
[1625] 
[1626]         if (i >= part->nelts) {
[1627]             if (part->next == NULL) {
[1628]                 break;
[1629]             }
[1630] 
[1631]             part = part->next;
[1632]             var = part->elts;
[1633]             i = 0;
[1634]         }
[1635] 
[1636]         if (name->len != var[i].name.len) {
[1637]             continue;
[1638]         }
[1639] 
[1640]         if (key != var[i].key) {
[1641]             continue;
[1642]         }
[1643] 
[1644]         if (ngx_strncmp(name->data, var[i].name.data, name->len) == 0) {
[1645]             return &var[i].value;
[1646]         }
[1647]     }
[1648] 
[1649]     return NULL;
[1650] }
[1651] 
[1652] 
[1653] static ngx_int_t
[1654] ngx_http_ssi_evaluate_string(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[1655]     ngx_str_t *text, ngx_uint_t flags)
[1656] {
[1657]     u_char                      ch, *p, **value, *data, *part_data;
[1658]     size_t                     *size, len, prefix, part_len;
[1659]     ngx_str_t                   var, *val;
[1660]     ngx_uint_t                  i, n, bracket, quoted, key;
[1661]     ngx_array_t                 lengths, values;
[1662]     ngx_http_variable_value_t  *vv;
[1663] 
[1664]     n = ngx_http_script_variables_count(text);
[1665] 
[1666]     if (n == 0) {
[1667] 
[1668]         data = text->data;
[1669]         p = data;
[1670] 
[1671]         if ((flags & NGX_HTTP_SSI_ADD_PREFIX) && text->data[0] != '/') {
[1672] 
[1673]             for (prefix = r->uri.len; prefix; prefix--) {
[1674]                 if (r->uri.data[prefix - 1] == '/') {
[1675]                     break;
[1676]                 }
[1677]             }
[1678] 
[1679]             if (prefix) {
[1680]                 len = prefix + text->len;
[1681] 
[1682]                 data = ngx_pnalloc(r->pool, len);
[1683]                 if (data == NULL) {
[1684]                     return NGX_ERROR;
[1685]                 }
[1686] 
[1687]                 p = ngx_copy(data, r->uri.data, prefix);
[1688]             }
[1689]         }
[1690] 
[1691]         quoted = 0;
[1692] 
[1693]         for (i = 0; i < text->len; i++) {
[1694]             ch = text->data[i];
[1695] 
[1696]             if (!quoted) {
[1697] 
[1698]                 if (ch == '\\') {
[1699]                     quoted = 1;
[1700]                     continue;
[1701]                 }
[1702] 
[1703]             } else {
[1704]                 quoted = 0;
[1705] 
[1706]                 if (ch != '\\' && ch != '\'' && ch != '"' && ch != '$') {
[1707]                     *p++ = '\\';
[1708]                 }
[1709]             }
[1710] 
[1711]             *p++ = ch;
[1712]         }
[1713] 
[1714]         text->len = p - data;
[1715]         text->data = data;
[1716] 
[1717]         return NGX_OK;
[1718]     }
[1719] 
[1720]     if (ngx_array_init(&lengths, r->pool, 8, sizeof(size_t *)) != NGX_OK) {
[1721]         return NGX_ERROR;
[1722]     }
[1723] 
[1724]     if (ngx_array_init(&values, r->pool, 8, sizeof(u_char *)) != NGX_OK) {
[1725]         return NGX_ERROR;
[1726]     }
[1727] 
[1728]     len = 0;
[1729]     i = 0;
[1730] 
[1731]     while (i < text->len) {
[1732] 
[1733]         if (text->data[i] == '$') {
[1734] 
[1735]             var.len = 0;
[1736] 
[1737]             if (++i == text->len) {
[1738]                 goto invalid_variable;
[1739]             }
[1740] 
[1741]             if (text->data[i] == '{') {
[1742]                 bracket = 1;
[1743] 
[1744]                 if (++i == text->len) {
[1745]                     goto invalid_variable;
[1746]                 }
[1747] 
[1748]                 var.data = &text->data[i];
[1749] 
[1750]             } else {
[1751]                 bracket = 0;
[1752]                 var.data = &text->data[i];
[1753]             }
[1754] 
[1755]             for ( /* void */ ; i < text->len; i++, var.len++) {
[1756]                 ch = text->data[i];
[1757] 
[1758]                 if (ch == '}' && bracket) {
[1759]                     i++;
[1760]                     bracket = 0;
[1761]                     break;
[1762]                 }
[1763] 
[1764]                 if ((ch >= 'A' && ch <= 'Z')
[1765]                     || (ch >= 'a' && ch <= 'z')
[1766]                     || (ch >= '0' && ch <= '9')
[1767]                     || ch == '_')
[1768]                 {
[1769]                     continue;
[1770]                 }
[1771] 
[1772]                 break;
[1773]             }
[1774] 
[1775]             if (bracket) {
[1776]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1777]                               "the closing bracket in \"%V\" "
[1778]                               "variable is missing", &var);
[1779]                 return NGX_HTTP_SSI_ERROR;
[1780]             }
[1781] 
[1782]             if (var.len == 0) {
[1783]                 goto invalid_variable;
[1784]             }
[1785] 
[1786]             key = ngx_hash_strlow(var.data, var.data, var.len);
[1787] 
[1788]             val = ngx_http_ssi_get_variable(r, &var, key);
[1789] 
[1790]             if (val == NULL) {
[1791]                 vv = ngx_http_get_variable(r, &var, key);
[1792]                 if (vv == NULL) {
[1793]                     return NGX_ERROR;
[1794]                 }
[1795] 
[1796]                 if (vv->not_found) {
[1797]                     continue;
[1798]                 }
[1799] 
[1800]                 part_data = vv->data;
[1801]                 part_len = vv->len;
[1802] 
[1803]             } else {
[1804]                 part_data = val->data;
[1805]                 part_len = val->len;
[1806]             }
[1807] 
[1808]         } else {
[1809]             part_data = &text->data[i];
[1810]             quoted = 0;
[1811] 
[1812]             for (p = part_data; i < text->len; i++) {
[1813]                 ch = text->data[i];
[1814] 
[1815]                 if (!quoted) {
[1816] 
[1817]                     if (ch == '\\') {
[1818]                         quoted = 1;
[1819]                         continue;
[1820]                     }
[1821] 
[1822]                     if (ch == '$') {
[1823]                         break;
[1824]                     }
[1825] 
[1826]                 } else {
[1827]                     quoted = 0;
[1828] 
[1829]                     if (ch != '\\' && ch != '\'' && ch != '"' && ch != '$') {
[1830]                         *p++ = '\\';
[1831]                     }
[1832]                 }
[1833] 
[1834]                 *p++ = ch;
[1835]             }
[1836] 
[1837]             part_len = p - part_data;
[1838]         }
[1839] 
[1840]         len += part_len;
[1841] 
[1842]         size = ngx_array_push(&lengths);
[1843]         if (size == NULL) {
[1844]             return NGX_ERROR;
[1845]         }
[1846] 
[1847]         *size = part_len;
[1848] 
[1849]         value = ngx_array_push(&values);
[1850]         if (value == NULL) {
[1851]             return NGX_ERROR;
[1852]         }
[1853] 
[1854]         *value = part_data;
[1855]     }
[1856] 
[1857]     prefix = 0;
[1858] 
[1859]     size = lengths.elts;
[1860]     value = values.elts;
[1861] 
[1862]     if (flags & NGX_HTTP_SSI_ADD_PREFIX) {
[1863]         for (i = 0; i < values.nelts; i++) {
[1864]             if (size[i] != 0) {
[1865]                 if (*value[i] != '/') {
[1866]                     for (prefix = r->uri.len; prefix; prefix--) {
[1867]                         if (r->uri.data[prefix - 1] == '/') {
[1868]                             len += prefix;
[1869]                             break;
[1870]                         }
[1871]                     }
[1872]                 }
[1873] 
[1874]                 break;
[1875]             }
[1876]         }
[1877]     }
[1878] 
[1879]     p = ngx_pnalloc(r->pool, len + ((flags & NGX_HTTP_SSI_ADD_ZERO) ? 1 : 0));
[1880]     if (p == NULL) {
[1881]         return NGX_ERROR;
[1882]     }
[1883] 
[1884]     text->len = len;
[1885]     text->data = p;
[1886] 
[1887]     p = ngx_copy(p, r->uri.data, prefix);
[1888] 
[1889]     for (i = 0; i < values.nelts; i++) {
[1890]         p = ngx_copy(p, value[i], size[i]);
[1891]     }
[1892] 
[1893]     return NGX_OK;
[1894] 
[1895] invalid_variable:
[1896] 
[1897]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1898]                   "invalid variable name in \"%V\"", text);
[1899] 
[1900]     return NGX_HTTP_SSI_ERROR;
[1901] }
[1902] 
[1903] 
[1904] static ngx_int_t
[1905] ngx_http_ssi_regex_match(ngx_http_request_t *r, ngx_str_t *pattern,
[1906]     ngx_str_t *str)
[1907] {
[1908] #if (NGX_PCRE)
[1909]     int                   rc, *captures;
[1910]     u_char               *p, errstr[NGX_MAX_CONF_ERRSTR];
[1911]     size_t                size;
[1912]     ngx_str_t            *vv, name, value;
[1913]     ngx_uint_t            i, n, key;
[1914]     ngx_http_ssi_ctx_t   *ctx;
[1915]     ngx_http_ssi_var_t   *var;
[1916]     ngx_regex_compile_t   rgc;
[1917] 
[1918]     ngx_memzero(&rgc, sizeof(ngx_regex_compile_t));
[1919] 
[1920]     rgc.pattern = *pattern;
[1921]     rgc.pool = r->pool;
[1922]     rgc.err.len = NGX_MAX_CONF_ERRSTR;
[1923]     rgc.err.data = errstr;
[1924] 
[1925]     if (ngx_regex_compile(&rgc) != NGX_OK) {
[1926]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V", &rgc.err);
[1927]         return NGX_HTTP_SSI_ERROR;
[1928]     }
[1929] 
[1930]     n = (rgc.captures + 1) * 3;
[1931] 
[1932]     captures = ngx_palloc(r->pool, n * sizeof(int));
[1933]     if (captures == NULL) {
[1934]         return NGX_ERROR;
[1935]     }
[1936] 
[1937]     rc = ngx_regex_exec(rgc.regex, str, captures, n);
[1938] 
[1939]     if (rc < NGX_REGEX_NO_MATCHED) {
[1940]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[1941]                       ngx_regex_exec_n " failed: %d on \"%V\" using \"%V\"",
[1942]                       rc, str, pattern);
[1943]         return NGX_HTTP_SSI_ERROR;
[1944]     }
[1945] 
[1946]     if (rc == NGX_REGEX_NO_MATCHED) {
[1947]         return NGX_DECLINED;
[1948]     }
[1949] 
[1950]     ctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);
[1951] 
[1952]     ctx->ncaptures = rc;
[1953]     ctx->captures = captures;
[1954]     ctx->captures_data = str->data;
[1955] 
[1956]     if (rgc.named_captures > 0) {
[1957] 
[1958]         if (ctx->variables == NULL) {
[1959]             ctx->variables = ngx_list_create(r->pool, 4,
[1960]                                              sizeof(ngx_http_ssi_var_t));
[1961]             if (ctx->variables == NULL) {
[1962]                 return NGX_ERROR;
[1963]             }
[1964]         }
[1965] 
[1966]         size = rgc.name_size;
[1967]         p = rgc.names;
[1968] 
[1969]         for (i = 0; i < (ngx_uint_t) rgc.named_captures; i++, p += size) {
[1970] 
[1971]             name.data = &p[2];
[1972]             name.len = ngx_strlen(name.data);
[1973] 
[1974]             n = 2 * ((p[0] << 8) + p[1]);
[1975] 
[1976]             value.data = &str->data[captures[n]];
[1977]             value.len = captures[n + 1] - captures[n];
[1978] 
[1979]             key = ngx_hash_strlow(name.data, name.data, name.len);
[1980] 
[1981]             vv = ngx_http_ssi_get_variable(r, &name, key);
[1982] 
[1983]             if (vv) {
[1984]                 *vv = value;
[1985]                 continue;
[1986]             }
[1987] 
[1988]             var = ngx_list_push(ctx->variables);
[1989]             if (var == NULL) {
[1990]                 return NGX_ERROR;
[1991]             }
[1992] 
[1993]             var->name = name;
[1994]             var->key = key;
[1995]             var->value = value;
[1996]         }
[1997]     }
[1998] 
[1999]     return NGX_OK;
[2000] 
[2001] #else
[2002] 
[2003]     ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[2004]                   "the using of the regex \"%V\" in SSI requires PCRE library",
[2005]                   pattern);
[2006]     return NGX_HTTP_SSI_ERROR;
[2007] 
[2008] #endif
[2009] }
[2010] 
[2011] 
[2012] static ngx_int_t
[2013] ngx_http_ssi_include(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2014]     ngx_str_t **params)
[2015] {
[2016]     ngx_int_t                    rc;
[2017]     ngx_str_t                   *uri, *file, *wait, *set, *stub, args;
[2018]     ngx_buf_t                   *b;
[2019]     ngx_uint_t                   flags, i, key;
[2020]     ngx_chain_t                 *cl, *tl, **ll, *out;
[2021]     ngx_http_request_t          *sr;
[2022]     ngx_http_ssi_var_t          *var;
[2023]     ngx_http_ssi_ctx_t          *mctx;
[2024]     ngx_http_ssi_block_t        *bl;
[2025]     ngx_http_post_subrequest_t  *psr;
[2026] 
[2027]     uri = params[NGX_HTTP_SSI_INCLUDE_VIRTUAL];
[2028]     file = params[NGX_HTTP_SSI_INCLUDE_FILE];
[2029]     wait = params[NGX_HTTP_SSI_INCLUDE_WAIT];
[2030]     set = params[NGX_HTTP_SSI_INCLUDE_SET];
[2031]     stub = params[NGX_HTTP_SSI_INCLUDE_STUB];
[2032] 
[2033]     if (uri && file) {
[2034]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2035]                       "inclusion may be either virtual=\"%V\" or file=\"%V\"",
[2036]                       uri, file);
[2037]         return NGX_HTTP_SSI_ERROR;
[2038]     }
[2039] 
[2040]     if (uri == NULL && file == NULL) {
[2041]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2042]                       "no parameter in \"include\" SSI command");
[2043]         return NGX_HTTP_SSI_ERROR;
[2044]     }
[2045] 
[2046]     if (set && stub) {
[2047]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2048]                       "\"set\" and \"stub\" cannot be used together "
[2049]                       "in \"include\" SSI command");
[2050]         return NGX_HTTP_SSI_ERROR;
[2051]     }
[2052] 
[2053]     if (wait) {
[2054]         if (uri == NULL) {
[2055]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2056]                           "\"wait\" cannot be used with file=\"%V\"", file);
[2057]             return NGX_HTTP_SSI_ERROR;
[2058]         }
[2059] 
[2060]         if (wait->len == 2
[2061]             && ngx_strncasecmp(wait->data, (u_char *) "no", 2) == 0)
[2062]         {
[2063]             wait = NULL;
[2064] 
[2065]         } else if (wait->len != 3
[2066]                    || ngx_strncasecmp(wait->data, (u_char *) "yes", 3) != 0)
[2067]         {
[2068]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2069]                           "invalid value \"%V\" in the \"wait\" parameter",
[2070]                           wait);
[2071]             return NGX_HTTP_SSI_ERROR;
[2072]         }
[2073]     }
[2074] 
[2075]     if (uri == NULL) {
[2076]         uri = file;
[2077]         wait = (ngx_str_t *) -1;
[2078]     }
[2079] 
[2080]     rc = ngx_http_ssi_evaluate_string(r, ctx, uri, NGX_HTTP_SSI_ADD_PREFIX);
[2081] 
[2082]     if (rc != NGX_OK) {
[2083]         return rc;
[2084]     }
[2085] 
[2086]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2087]                    "ssi include: \"%V\"", uri);
[2088] 
[2089]     ngx_str_null(&args);
[2090]     flags = NGX_HTTP_LOG_UNSAFE;
[2091] 
[2092]     if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
[2093]         return NGX_HTTP_SSI_ERROR;
[2094]     }
[2095] 
[2096]     psr = NULL;
[2097] 
[2098]     mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);
[2099] 
[2100]     if (stub) {
[2101]         if (mctx->blocks) {
[2102]             bl = mctx->blocks->elts;
[2103]             for (i = 0; i < mctx->blocks->nelts; i++) {
[2104]                 if (stub->len == bl[i].name.len
[2105]                     && ngx_strncmp(stub->data, bl[i].name.data, stub->len) == 0)
[2106]                 {
[2107]                     goto found;
[2108]                 }
[2109]             }
[2110]         }
[2111] 
[2112]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2113]                       "\"stub\"=\"%V\" for \"include\" not found", stub);
[2114]         return NGX_HTTP_SSI_ERROR;
[2115] 
[2116]     found:
[2117] 
[2118]         psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
[2119]         if (psr == NULL) {
[2120]             return NGX_ERROR;
[2121]         }
[2122] 
[2123]         psr->handler = ngx_http_ssi_stub_output;
[2124] 
[2125]         if (bl[i].count++) {
[2126] 
[2127]             out = NULL;
[2128]             ll = &out;
[2129] 
[2130]             for (tl = bl[i].bufs; tl; tl = tl->next) {
[2131] 
[2132]                 if (ctx->free) {
[2133]                     cl = ctx->free;
[2134]                     ctx->free = ctx->free->next;
[2135]                     b = cl->buf;
[2136] 
[2137]                 } else {
[2138]                     b = ngx_alloc_buf(r->pool);
[2139]                     if (b == NULL) {
[2140]                         return NGX_ERROR;
[2141]                     }
[2142] 
[2143]                     cl = ngx_alloc_chain_link(r->pool);
[2144]                     if (cl == NULL) {
[2145]                         return NGX_ERROR;
[2146]                     }
[2147] 
[2148]                     cl->buf = b;
[2149]                 }
[2150] 
[2151]                 ngx_memcpy(b, tl->buf, sizeof(ngx_buf_t));
[2152] 
[2153]                 b->pos = b->start;
[2154] 
[2155]                 *ll = cl;
[2156]                 cl->next = NULL;
[2157]                 ll = &cl->next;
[2158]             }
[2159] 
[2160]             psr->data = out;
[2161] 
[2162]         } else {
[2163]             psr->data = bl[i].bufs;
[2164]         }
[2165]     }
[2166] 
[2167]     if (wait) {
[2168]         flags |= NGX_HTTP_SUBREQUEST_WAITED;
[2169]     }
[2170] 
[2171]     if (set) {
[2172]         key = ngx_hash_strlow(set->data, set->data, set->len);
[2173] 
[2174]         psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
[2175]         if (psr == NULL) {
[2176]             return NGX_ERROR;
[2177]         }
[2178] 
[2179]         psr->handler = ngx_http_ssi_set_variable;
[2180]         psr->data = ngx_http_ssi_get_variable(r, set, key);
[2181] 
[2182]         if (psr->data == NULL) {
[2183] 
[2184]             if (mctx->variables == NULL) {
[2185]                 mctx->variables = ngx_list_create(r->pool, 4,
[2186]                                                   sizeof(ngx_http_ssi_var_t));
[2187]                 if (mctx->variables == NULL) {
[2188]                     return NGX_ERROR;
[2189]                 }
[2190]             }
[2191] 
[2192]             var = ngx_list_push(mctx->variables);
[2193]             if (var == NULL) {
[2194]                 return NGX_ERROR;
[2195]             }
[2196] 
[2197]             var->name = *set;
[2198]             var->key = key;
[2199]             var->value = ngx_http_ssi_null_string;
[2200]             psr->data = &var->value;
[2201]         }
[2202] 
[2203]         flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY|NGX_HTTP_SUBREQUEST_WAITED;
[2204]     }
[2205] 
[2206]     if (ngx_http_subrequest(r, uri, &args, &sr, psr, flags) != NGX_OK) {
[2207]         return NGX_HTTP_SSI_ERROR;
[2208]     }
[2209] 
[2210]     if (wait == NULL && set == NULL) {
[2211]         return NGX_OK;
[2212]     }
[2213] 
[2214]     if (ctx->wait == NULL) {
[2215]         ctx->wait = sr;
[2216] 
[2217]         return NGX_AGAIN;
[2218] 
[2219]     } else {
[2220]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2221]                       "can only wait for one subrequest at a time");
[2222]     }
[2223] 
[2224]     return NGX_OK;
[2225] }
[2226] 
[2227] 
[2228] static ngx_int_t
[2229] ngx_http_ssi_stub_output(ngx_http_request_t *r, void *data, ngx_int_t rc)
[2230] {
[2231]     ngx_chain_t  *out;
[2232] 
[2233]     if (rc == NGX_ERROR || r->connection->error || r->request_output) {
[2234]         return rc;
[2235]     }
[2236] 
[2237]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2238]                    "ssi stub output: \"%V?%V\"", &r->uri, &r->args);
[2239] 
[2240]     out = data;
[2241] 
[2242]     if (!r->header_sent) {
[2243]         r->headers_out.content_type_len =
[2244]                                       r->parent->headers_out.content_type_len;
[2245]         r->headers_out.content_type = r->parent->headers_out.content_type;
[2246] 
[2247]         if (ngx_http_send_header(r) == NGX_ERROR) {
[2248]             return NGX_ERROR;
[2249]         }
[2250]     }
[2251] 
[2252]     return ngx_http_output_filter(r, out);
[2253] }
[2254] 
[2255] 
[2256] static ngx_int_t
[2257] ngx_http_ssi_set_variable(ngx_http_request_t *r, void *data, ngx_int_t rc)
[2258] {
[2259]     ngx_str_t  *value = data;
[2260] 
[2261]     if (r->headers_out.status < NGX_HTTP_SPECIAL_RESPONSE
[2262]         && r->out && r->out->buf)
[2263]     {
[2264]         value->len = r->out->buf->last - r->out->buf->pos;
[2265]         value->data = r->out->buf->pos;
[2266]     }
[2267] 
[2268]     return rc;
[2269] }
[2270] 
[2271] 
[2272] static ngx_int_t
[2273] ngx_http_ssi_echo(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2274]     ngx_str_t **params)
[2275] {
[2276]     u_char                     *p;
[2277]     uintptr_t                   len;
[2278]     ngx_buf_t                  *b;
[2279]     ngx_str_t                  *var, *value, *enc, text;
[2280]     ngx_uint_t                  key;
[2281]     ngx_chain_t                *cl;
[2282]     ngx_http_variable_value_t  *vv;
[2283] 
[2284]     var = params[NGX_HTTP_SSI_ECHO_VAR];
[2285] 
[2286]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2287]                    "ssi echo \"%V\"", var);
[2288] 
[2289]     key = ngx_hash_strlow(var->data, var->data, var->len);
[2290] 
[2291]     value = ngx_http_ssi_get_variable(r, var, key);
[2292] 
[2293]     if (value == NULL) {
[2294]         vv = ngx_http_get_variable(r, var, key);
[2295] 
[2296]         if (vv == NULL) {
[2297]             return NGX_HTTP_SSI_ERROR;
[2298]         }
[2299] 
[2300]         if (!vv->not_found) {
[2301]             text.data = vv->data;
[2302]             text.len = vv->len;
[2303]             value = &text;
[2304]         }
[2305]     }
[2306] 
[2307]     if (value == NULL) {
[2308]         value = params[NGX_HTTP_SSI_ECHO_DEFAULT];
[2309] 
[2310]         if (value == NULL) {
[2311]             value = &ngx_http_ssi_none;
[2312] 
[2313]         } else if (value->len == 0) {
[2314]             return NGX_OK;
[2315]         }
[2316] 
[2317]     } else {
[2318]         if (value->len == 0) {
[2319]             return NGX_OK;
[2320]         }
[2321]     }
[2322] 
[2323]     enc = params[NGX_HTTP_SSI_ECHO_ENCODING];
[2324] 
[2325]     if (enc) {
[2326]         if (enc->len == 4 && ngx_strncmp(enc->data, "none", 4) == 0) {
[2327] 
[2328]             ctx->encoding = NGX_HTTP_SSI_NO_ENCODING;
[2329] 
[2330]         } else if (enc->len == 3 && ngx_strncmp(enc->data, "url", 3) == 0) {
[2331] 
[2332]             ctx->encoding = NGX_HTTP_SSI_URL_ENCODING;
[2333] 
[2334]         } else if (enc->len == 6 && ngx_strncmp(enc->data, "entity", 6) == 0) {
[2335] 
[2336]             ctx->encoding = NGX_HTTP_SSI_ENTITY_ENCODING;
[2337] 
[2338]         } else {
[2339]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2340]                           "unknown encoding \"%V\" in the \"echo\" command",
[2341]                           enc);
[2342]         }
[2343]     }
[2344] 
[2345]     p = value->data;
[2346] 
[2347]     switch (ctx->encoding) {
[2348] 
[2349]     case NGX_HTTP_SSI_URL_ENCODING:
[2350]         len = 2 * ngx_escape_uri(NULL, value->data, value->len,
[2351]                                  NGX_ESCAPE_HTML);
[2352] 
[2353]         if (len) {
[2354]             p = ngx_pnalloc(r->pool, value->len + len);
[2355]             if (p == NULL) {
[2356]                 return NGX_HTTP_SSI_ERROR;
[2357]             }
[2358] 
[2359]             (void) ngx_escape_uri(p, value->data, value->len, NGX_ESCAPE_HTML);
[2360]         }
[2361] 
[2362]         len += value->len;
[2363]         break;
[2364] 
[2365]     case NGX_HTTP_SSI_ENTITY_ENCODING:
[2366]         len = ngx_escape_html(NULL, value->data, value->len);
[2367] 
[2368]         if (len) {
[2369]             p = ngx_pnalloc(r->pool, value->len + len);
[2370]             if (p == NULL) {
[2371]                 return NGX_HTTP_SSI_ERROR;
[2372]             }
[2373] 
[2374]             (void) ngx_escape_html(p, value->data, value->len);
[2375]         }
[2376] 
[2377]         len += value->len;
[2378]         break;
[2379] 
[2380]     default: /* NGX_HTTP_SSI_NO_ENCODING */
[2381]         len = value->len;
[2382]         break;
[2383]     }
[2384] 
[2385]     b = ngx_calloc_buf(r->pool);
[2386]     if (b == NULL) {
[2387]         return NGX_HTTP_SSI_ERROR;
[2388]     }
[2389] 
[2390]     cl = ngx_alloc_chain_link(r->pool);
[2391]     if (cl == NULL) {
[2392]         return NGX_HTTP_SSI_ERROR;
[2393]     }
[2394] 
[2395]     b->memory = 1;
[2396]     b->pos = p;
[2397]     b->last = p + len;
[2398] 
[2399]     cl->buf = b;
[2400]     cl->next = NULL;
[2401]     *ctx->last_out = cl;
[2402]     ctx->last_out = &cl->next;
[2403] 
[2404]     return NGX_OK;
[2405] }
[2406] 
[2407] 
[2408] static ngx_int_t
[2409] ngx_http_ssi_config(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2410]     ngx_str_t **params)
[2411] {
[2412]     ngx_str_t  *value;
[2413] 
[2414]     value = params[NGX_HTTP_SSI_CONFIG_TIMEFMT];
[2415] 
[2416]     if (value) {
[2417]         ctx->timefmt.len = value->len;
[2418]         ctx->timefmt.data = ngx_pnalloc(r->pool, value->len + 1);
[2419]         if (ctx->timefmt.data == NULL) {
[2420]             return NGX_ERROR;
[2421]         }
[2422] 
[2423]         ngx_cpystrn(ctx->timefmt.data, value->data, value->len + 1);
[2424]     }
[2425] 
[2426]     value = params[NGX_HTTP_SSI_CONFIG_ERRMSG];
[2427] 
[2428]     if (value) {
[2429]         ctx->errmsg = *value;
[2430]     }
[2431] 
[2432]     return NGX_OK;
[2433] }
[2434] 
[2435] 
[2436] static ngx_int_t
[2437] ngx_http_ssi_set(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2438]     ngx_str_t **params)
[2439] {
[2440]     ngx_int_t            rc;
[2441]     ngx_str_t           *name, *value, *vv;
[2442]     ngx_uint_t           key;
[2443]     ngx_http_ssi_var_t  *var;
[2444]     ngx_http_ssi_ctx_t  *mctx;
[2445] 
[2446]     mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);
[2447] 
[2448]     if (mctx->variables == NULL) {
[2449]         mctx->variables = ngx_list_create(r->pool, 4,
[2450]                                           sizeof(ngx_http_ssi_var_t));
[2451]         if (mctx->variables == NULL) {
[2452]             return NGX_ERROR;
[2453]         }
[2454]     }
[2455] 
[2456]     name = params[NGX_HTTP_SSI_SET_VAR];
[2457]     value = params[NGX_HTTP_SSI_SET_VALUE];
[2458] 
[2459]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2460]                    "ssi set \"%V\" \"%V\"", name, value);
[2461] 
[2462]     rc = ngx_http_ssi_evaluate_string(r, ctx, value, 0);
[2463] 
[2464]     if (rc != NGX_OK) {
[2465]         return rc;
[2466]     }
[2467] 
[2468]     key = ngx_hash_strlow(name->data, name->data, name->len);
[2469] 
[2470]     vv = ngx_http_ssi_get_variable(r, name, key);
[2471] 
[2472]     if (vv) {
[2473]         *vv = *value;
[2474]         return NGX_OK;
[2475]     }
[2476] 
[2477]     var = ngx_list_push(mctx->variables);
[2478]     if (var == NULL) {
[2479]         return NGX_ERROR;
[2480]     }
[2481] 
[2482]     var->name = *name;
[2483]     var->key = key;
[2484]     var->value = *value;
[2485] 
[2486]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2487]                    "set: \"%V\"=\"%V\"", name, value);
[2488] 
[2489]     return NGX_OK;
[2490] }
[2491] 
[2492] 
[2493] static ngx_int_t
[2494] ngx_http_ssi_if(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2495]     ngx_str_t **params)
[2496] {
[2497]     u_char       *p, *last;
[2498]     ngx_str_t    *expr, left, right;
[2499]     ngx_int_t     rc;
[2500]     ngx_uint_t    negative, noregex, flags;
[2501] 
[2502]     if (ctx->command.len == 2) {
[2503]         if (ctx->conditional) {
[2504]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2505]                           "the \"if\" command inside the \"if\" command");
[2506]             return NGX_HTTP_SSI_ERROR;
[2507]         }
[2508]     }
[2509] 
[2510]     if (ctx->output_chosen) {
[2511]         ctx->output = 0;
[2512]         return NGX_OK;
[2513]     }
[2514] 
[2515]     expr = params[NGX_HTTP_SSI_IF_EXPR];
[2516] 
[2517]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2518]                    "ssi if expr=\"%V\"", expr);
[2519] 
[2520]     left.data = expr->data;
[2521]     last = expr->data + expr->len;
[2522] 
[2523]     for (p = left.data; p < last; p++) {
[2524]         if (*p >= 'A' && *p <= 'Z') {
[2525]             *p |= 0x20;
[2526]             continue;
[2527]         }
[2528] 
[2529]         if ((*p >= 'a' && *p <= 'z')
[2530]              || (*p >= '0' && *p <= '9')
[2531]              || *p == '$' || *p == '{' || *p == '}' || *p == '_'
[2532]              || *p == '"' || *p == '\'')
[2533]         {
[2534]             continue;
[2535]         }
[2536] 
[2537]         break;
[2538]     }
[2539] 
[2540]     left.len = p - left.data;
[2541] 
[2542]     while (p < last && *p == ' ') {
[2543]         p++;
[2544]     }
[2545] 
[2546]     flags = 0;
[2547] 
[2548]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2549]                    "left: \"%V\"", &left);
[2550] 
[2551]     rc = ngx_http_ssi_evaluate_string(r, ctx, &left, flags);
[2552] 
[2553]     if (rc != NGX_OK) {
[2554]         return rc;
[2555]     }
[2556] 
[2557]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2558]                    "evaluated left: \"%V\"", &left);
[2559] 
[2560]     if (p == last) {
[2561]         if (left.len) {
[2562]             ctx->output = 1;
[2563]             ctx->output_chosen = 1;
[2564] 
[2565]         } else {
[2566]             ctx->output = 0;
[2567]         }
[2568] 
[2569]         ctx->conditional = NGX_HTTP_SSI_COND_IF;
[2570] 
[2571]         return NGX_OK;
[2572]     }
[2573] 
[2574]     if (p < last && *p == '=') {
[2575]         negative = 0;
[2576]         p++;
[2577] 
[2578]     } else if (p + 1 < last && *p == '!' && *(p + 1) == '=') {
[2579]         negative = 1;
[2580]         p += 2;
[2581] 
[2582]     } else {
[2583]         goto invalid_expression;
[2584]     }
[2585] 
[2586]     while (p < last && *p == ' ') {
[2587]         p++;
[2588]     }
[2589] 
[2590]     if (p < last - 1 && *p == '/') {
[2591]         if (*(last - 1) != '/') {
[2592]             goto invalid_expression;
[2593]         }
[2594] 
[2595]         noregex = 0;
[2596]         flags = NGX_HTTP_SSI_ADD_ZERO;
[2597]         last--;
[2598]         p++;
[2599] 
[2600]     } else {
[2601]         noregex = 1;
[2602]         flags = 0;
[2603] 
[2604]         if (p < last - 1 && p[0] == '\\' && p[1] == '/') {
[2605]             p++;
[2606]         }
[2607]     }
[2608] 
[2609]     right.len = last - p;
[2610]     right.data = p;
[2611] 
[2612]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2613]                    "right: \"%V\"", &right);
[2614] 
[2615]     rc = ngx_http_ssi_evaluate_string(r, ctx, &right, flags);
[2616] 
[2617]     if (rc != NGX_OK) {
[2618]         return rc;
[2619]     }
[2620] 
[2621]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2622]                    "evaluated right: \"%V\"", &right);
[2623] 
[2624]     if (noregex) {
[2625]         if (left.len != right.len) {
[2626]             rc = -1;
[2627] 
[2628]         } else {
[2629]             rc = ngx_strncmp(left.data, right.data, right.len);
[2630]         }
[2631] 
[2632]     } else {
[2633]         right.data[right.len] = '\0';
[2634] 
[2635]         rc = ngx_http_ssi_regex_match(r, &right, &left);
[2636] 
[2637]         if (rc == NGX_OK) {
[2638]             rc = 0;
[2639]         } else if (rc == NGX_DECLINED) {
[2640]             rc = -1;
[2641]         } else {
[2642]             return rc;
[2643]         }
[2644]     }
[2645] 
[2646]     if ((rc == 0 && !negative) || (rc != 0 && negative)) {
[2647]         ctx->output = 1;
[2648]         ctx->output_chosen = 1;
[2649] 
[2650]     } else {
[2651]         ctx->output = 0;
[2652]     }
[2653] 
[2654]     ctx->conditional = NGX_HTTP_SSI_COND_IF;
[2655] 
[2656]     return NGX_OK;
[2657] 
[2658] invalid_expression:
[2659] 
[2660]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2661]                   "invalid expression in \"%V\"", expr);
[2662] 
[2663]     return NGX_HTTP_SSI_ERROR;
[2664] }
[2665] 
[2666] 
[2667] static ngx_int_t
[2668] ngx_http_ssi_else(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2669]     ngx_str_t **params)
[2670] {
[2671]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2672]                    "ssi else");
[2673] 
[2674]     if (ctx->output_chosen) {
[2675]         ctx->output = 0;
[2676]     } else {
[2677]         ctx->output = 1;
[2678]     }
[2679] 
[2680]     ctx->conditional = NGX_HTTP_SSI_COND_ELSE;
[2681] 
[2682]     return NGX_OK;
[2683] }
[2684] 
[2685] 
[2686] static ngx_int_t
[2687] ngx_http_ssi_endif(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2688]     ngx_str_t **params)
[2689] {
[2690]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2691]                    "ssi endif");
[2692] 
[2693]     ctx->output = 1;
[2694]     ctx->output_chosen = 0;
[2695]     ctx->conditional = 0;
[2696] 
[2697]     return NGX_OK;
[2698] }
[2699] 
[2700] 
[2701] static ngx_int_t
[2702] ngx_http_ssi_block(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2703]     ngx_str_t **params)
[2704] {
[2705]     ngx_http_ssi_ctx_t    *mctx;
[2706]     ngx_http_ssi_block_t  *bl;
[2707] 
[2708]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2709]                    "ssi block");
[2710] 
[2711]     mctx = ngx_http_get_module_ctx(r->main, ngx_http_ssi_filter_module);
[2712] 
[2713]     if (mctx->blocks == NULL) {
[2714]         mctx->blocks = ngx_array_create(r->pool, 4,
[2715]                                         sizeof(ngx_http_ssi_block_t));
[2716]         if (mctx->blocks == NULL) {
[2717]             return NGX_HTTP_SSI_ERROR;
[2718]         }
[2719]     }
[2720] 
[2721]     bl = ngx_array_push(mctx->blocks);
[2722]     if (bl == NULL) {
[2723]         return NGX_HTTP_SSI_ERROR;
[2724]     }
[2725] 
[2726]     bl->name = *params[NGX_HTTP_SSI_BLOCK_NAME];
[2727]     bl->bufs = NULL;
[2728]     bl->count = 0;
[2729] 
[2730]     ctx->output = 0;
[2731]     ctx->block = 1;
[2732] 
[2733]     return NGX_OK;
[2734] }
[2735] 
[2736] 
[2737] static ngx_int_t
[2738] ngx_http_ssi_endblock(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ctx,
[2739]     ngx_str_t **params)
[2740] {
[2741]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2742]                    "ssi endblock");
[2743] 
[2744]     ctx->output = 1;
[2745]     ctx->block = 0;
[2746] 
[2747]     return NGX_OK;
[2748] }
[2749] 
[2750] 
[2751] static ngx_int_t
[2752] ngx_http_ssi_date_gmt_local_variable(ngx_http_request_t *r,
[2753]     ngx_http_variable_value_t *v, uintptr_t gmt)
[2754] {
[2755]     time_t               now;
[2756]     ngx_http_ssi_ctx_t  *ctx;
[2757]     ngx_str_t           *timefmt;
[2758]     struct tm            tm;
[2759]     char                 buf[NGX_HTTP_SSI_DATE_LEN];
[2760] 
[2761]     v->valid = 1;
[2762]     v->no_cacheable = 0;
[2763]     v->not_found = 0;
[2764] 
[2765]     now = ngx_time();
[2766] 
[2767]     ctx = ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module);
[2768] 
[2769]     timefmt = ctx ? &ctx->timefmt : &ngx_http_ssi_timefmt;
[2770] 
[2771]     if (timefmt->len == sizeof("%s") - 1
[2772]         && timefmt->data[0] == '%' && timefmt->data[1] == 's')
[2773]     {
[2774]         v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
[2775]         if (v->data == NULL) {
[2776]             return NGX_ERROR;
[2777]         }
[2778] 
[2779]         v->len = ngx_sprintf(v->data, "%T", now) - v->data;
[2780] 
[2781]         return NGX_OK;
[2782]     }
[2783] 
[2784]     if (gmt) {
[2785]         ngx_libc_gmtime(now, &tm);
[2786]     } else {
[2787]         ngx_libc_localtime(now, &tm);
[2788]     }
[2789] 
[2790]     v->len = strftime(buf, NGX_HTTP_SSI_DATE_LEN,
[2791]                       (char *) timefmt->data, &tm);
[2792]     if (v->len == 0) {
[2793]         return NGX_ERROR;
[2794]     }
[2795] 
[2796]     v->data = ngx_pnalloc(r->pool, v->len);
[2797]     if (v->data == NULL) {
[2798]         return NGX_ERROR;
[2799]     }
[2800] 
[2801]     ngx_memcpy(v->data, buf, v->len);
[2802] 
[2803]     return NGX_OK;
[2804] }
[2805] 
[2806] 
[2807] static ngx_int_t
[2808] ngx_http_ssi_preconfiguration(ngx_conf_t *cf)
[2809] {
[2810]     ngx_int_t                  rc;
[2811]     ngx_http_variable_t       *var, *v;
[2812]     ngx_http_ssi_command_t    *cmd;
[2813]     ngx_http_ssi_main_conf_t  *smcf;
[2814] 
[2815]     for (v = ngx_http_ssi_vars; v->name.len; v++) {
[2816]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[2817]         if (var == NULL) {
[2818]             return NGX_ERROR;
[2819]         }
[2820] 
[2821]         var->get_handler = v->get_handler;
[2822]         var->data = v->data;
[2823]     }
[2824] 
[2825]     smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssi_filter_module);
[2826] 
[2827]     for (cmd = ngx_http_ssi_commands; cmd->name.len; cmd++) {
[2828]         rc = ngx_hash_add_key(&smcf->commands, &cmd->name, cmd,
[2829]                               NGX_HASH_READONLY_KEY);
[2830] 
[2831]         if (rc == NGX_OK) {
[2832]             continue;
[2833]         }
[2834] 
[2835]         if (rc == NGX_BUSY) {
[2836]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[2837]                                "conflicting SSI command \"%V\"", &cmd->name);
[2838]         }
[2839] 
[2840]         return NGX_ERROR;
[2841]     }
[2842] 
[2843]     return NGX_OK;
[2844] }
[2845] 
[2846] 
[2847] static void *
[2848] ngx_http_ssi_create_main_conf(ngx_conf_t *cf)
[2849] {
[2850]     ngx_http_ssi_main_conf_t  *smcf;
[2851] 
[2852]     smcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_main_conf_t));
[2853]     if (smcf == NULL) {
[2854]         return NULL;
[2855]     }
[2856] 
[2857]     smcf->commands.pool = cf->pool;
[2858]     smcf->commands.temp_pool = cf->temp_pool;
[2859] 
[2860]     if (ngx_hash_keys_array_init(&smcf->commands, NGX_HASH_SMALL) != NGX_OK) {
[2861]         return NULL;
[2862]     }
[2863] 
[2864]     return smcf;
[2865] }
[2866] 
[2867] 
[2868] static char *
[2869] ngx_http_ssi_init_main_conf(ngx_conf_t *cf, void *conf)
[2870] {
[2871]     ngx_http_ssi_main_conf_t *smcf = conf;
[2872] 
[2873]     ngx_hash_init_t  hash;
[2874] 
[2875]     hash.hash = &smcf->hash;
[2876]     hash.key = ngx_hash_key;
[2877]     hash.max_size = 1024;
[2878]     hash.bucket_size = ngx_cacheline_size;
[2879]     hash.name = "ssi_command_hash";
[2880]     hash.pool = cf->pool;
[2881]     hash.temp_pool = NULL;
[2882] 
[2883]     if (ngx_hash_init(&hash, smcf->commands.keys.elts,
[2884]                       smcf->commands.keys.nelts)
[2885]         != NGX_OK)
[2886]     {
[2887]         return NGX_CONF_ERROR;
[2888]     }
[2889] 
[2890]     return NGX_CONF_OK;
[2891] }
[2892] 
[2893] 
[2894] static void *
[2895] ngx_http_ssi_create_loc_conf(ngx_conf_t *cf)
[2896] {
[2897]     ngx_http_ssi_loc_conf_t  *slcf;
[2898] 
[2899]     slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssi_loc_conf_t));
[2900]     if (slcf == NULL) {
[2901]         return NULL;
[2902]     }
[2903] 
[2904]     /*
[2905]      * set by ngx_pcalloc():
[2906]      *
[2907]      *     conf->types = { NULL };
[2908]      *     conf->types_keys = NULL;
[2909]      */
[2910] 
[2911]     slcf->enable = NGX_CONF_UNSET;
[2912]     slcf->silent_errors = NGX_CONF_UNSET;
[2913]     slcf->ignore_recycled_buffers = NGX_CONF_UNSET;
[2914]     slcf->last_modified = NGX_CONF_UNSET;
[2915] 
[2916]     slcf->min_file_chunk = NGX_CONF_UNSET_SIZE;
[2917]     slcf->value_len = NGX_CONF_UNSET_SIZE;
[2918] 
[2919]     return slcf;
[2920] }
[2921] 
[2922] 
[2923] static char *
[2924] ngx_http_ssi_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[2925] {
[2926]     ngx_http_ssi_loc_conf_t *prev = parent;
[2927]     ngx_http_ssi_loc_conf_t *conf = child;
[2928] 
[2929]     ngx_conf_merge_value(conf->enable, prev->enable, 0);
[2930]     ngx_conf_merge_value(conf->silent_errors, prev->silent_errors, 0);
[2931]     ngx_conf_merge_value(conf->ignore_recycled_buffers,
[2932]                          prev->ignore_recycled_buffers, 0);
[2933]     ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);
[2934] 
[2935]     ngx_conf_merge_size_value(conf->min_file_chunk, prev->min_file_chunk, 1024);
[2936]     ngx_conf_merge_size_value(conf->value_len, prev->value_len, 255);
[2937] 
[2938]     if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
[2939]                              &prev->types_keys, &prev->types,
[2940]                              ngx_http_html_default_types)
[2941]         != NGX_OK)
[2942]     {
[2943]         return NGX_CONF_ERROR;
[2944]     }
[2945] 
[2946]     return NGX_CONF_OK;
[2947] }
[2948] 
[2949] 
[2950] static ngx_int_t
[2951] ngx_http_ssi_filter_init(ngx_conf_t *cf)
[2952] {
[2953]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[2954]     ngx_http_top_header_filter = ngx_http_ssi_header_filter;
[2955] 
[2956]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[2957]     ngx_http_top_body_filter = ngx_http_ssi_body_filter;
[2958] 
[2959]     return NGX_OK;
[2960] }
