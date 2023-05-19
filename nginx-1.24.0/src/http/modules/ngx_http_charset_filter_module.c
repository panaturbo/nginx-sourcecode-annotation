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
[13] #define NGX_HTTP_CHARSET_OFF    -2
[14] #define NGX_HTTP_NO_CHARSET     -3
[15] #define NGX_HTTP_CHARSET_VAR    0x10000
[16] 
[17] /* 1 byte length and up to 3 bytes for the UTF-8 encoding of the UCS-2 */
[18] #define NGX_UTF_LEN             4
[19] 
[20] #define NGX_HTML_ENTITY_LEN     (sizeof("&#1114111;") - 1)
[21] 
[22] 
[23] typedef struct {
[24]     u_char                    **tables;
[25]     ngx_str_t                   name;
[26] 
[27]     unsigned                    length:16;
[28]     unsigned                    utf8:1;
[29] } ngx_http_charset_t;
[30] 
[31] 
[32] typedef struct {
[33]     ngx_int_t                   src;
[34]     ngx_int_t                   dst;
[35] } ngx_http_charset_recode_t;
[36] 
[37] 
[38] typedef struct {
[39]     ngx_int_t                   src;
[40]     ngx_int_t                   dst;
[41]     u_char                     *src2dst;
[42]     u_char                     *dst2src;
[43] } ngx_http_charset_tables_t;
[44] 
[45] 
[46] typedef struct {
[47]     ngx_array_t                 charsets;       /* ngx_http_charset_t */
[48]     ngx_array_t                 tables;         /* ngx_http_charset_tables_t */
[49]     ngx_array_t                 recodes;        /* ngx_http_charset_recode_t */
[50] } ngx_http_charset_main_conf_t;
[51] 
[52] 
[53] typedef struct {
[54]     ngx_int_t                   charset;
[55]     ngx_int_t                   source_charset;
[56]     ngx_flag_t                  override_charset;
[57] 
[58]     ngx_hash_t                  types;
[59]     ngx_array_t                *types_keys;
[60] } ngx_http_charset_loc_conf_t;
[61] 
[62] 
[63] typedef struct {
[64]     u_char                     *table;
[65]     ngx_int_t                   charset;
[66]     ngx_str_t                   charset_name;
[67] 
[68]     ngx_chain_t                *busy;
[69]     ngx_chain_t                *free_bufs;
[70]     ngx_chain_t                *free_buffers;
[71] 
[72]     size_t                      saved_len;
[73]     u_char                      saved[NGX_UTF_LEN];
[74] 
[75]     unsigned                    length:16;
[76]     unsigned                    from_utf8:1;
[77]     unsigned                    to_utf8:1;
[78] } ngx_http_charset_ctx_t;
[79] 
[80] 
[81] typedef struct {
[82]     ngx_http_charset_tables_t  *table;
[83]     ngx_http_charset_t         *charset;
[84]     ngx_uint_t                  characters;
[85] } ngx_http_charset_conf_ctx_t;
[86] 
[87] 
[88] static ngx_int_t ngx_http_destination_charset(ngx_http_request_t *r,
[89]     ngx_str_t *name);
[90] static ngx_int_t ngx_http_main_request_charset(ngx_http_request_t *r,
[91]     ngx_str_t *name);
[92] static ngx_int_t ngx_http_source_charset(ngx_http_request_t *r,
[93]     ngx_str_t *name);
[94] static ngx_int_t ngx_http_get_charset(ngx_http_request_t *r, ngx_str_t *name);
[95] static ngx_inline void ngx_http_set_charset(ngx_http_request_t *r,
[96]     ngx_str_t *charset);
[97] static ngx_int_t ngx_http_charset_ctx(ngx_http_request_t *r,
[98]     ngx_http_charset_t *charsets, ngx_int_t charset, ngx_int_t source_charset);
[99] static ngx_uint_t ngx_http_charset_recode(ngx_buf_t *b, u_char *table);
[100] static ngx_chain_t *ngx_http_charset_recode_from_utf8(ngx_pool_t *pool,
[101]     ngx_buf_t *buf, ngx_http_charset_ctx_t *ctx);
[102] static ngx_chain_t *ngx_http_charset_recode_to_utf8(ngx_pool_t *pool,
[103]     ngx_buf_t *buf, ngx_http_charset_ctx_t *ctx);
[104] 
[105] static ngx_chain_t *ngx_http_charset_get_buf(ngx_pool_t *pool,
[106]     ngx_http_charset_ctx_t *ctx);
[107] static ngx_chain_t *ngx_http_charset_get_buffer(ngx_pool_t *pool,
[108]     ngx_http_charset_ctx_t *ctx, size_t size);
[109] 
[110] static char *ngx_http_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd,
[111]     void *conf);
[112] static char *ngx_http_charset_map(ngx_conf_t *cf, ngx_command_t *dummy,
[113]     void *conf);
[114] 
[115] static char *ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[116]     void *conf);
[117] static ngx_int_t ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name);
[118] 
[119] static void *ngx_http_charset_create_main_conf(ngx_conf_t *cf);
[120] static void *ngx_http_charset_create_loc_conf(ngx_conf_t *cf);
[121] static char *ngx_http_charset_merge_loc_conf(ngx_conf_t *cf,
[122]     void *parent, void *child);
[123] static ngx_int_t ngx_http_charset_postconfiguration(ngx_conf_t *cf);
[124] 
[125] 
[126] static ngx_str_t  ngx_http_charset_default_types[] = {
[127]     ngx_string("text/html"),
[128]     ngx_string("text/xml"),
[129]     ngx_string("text/plain"),
[130]     ngx_string("text/vnd.wap.wml"),
[131]     ngx_string("application/javascript"),
[132]     ngx_string("application/rss+xml"),
[133]     ngx_null_string
[134] };
[135] 
[136] 
[137] static ngx_command_t  ngx_http_charset_filter_commands[] = {
[138] 
[139]     { ngx_string("charset"),
[140]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
[141]                         |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[142]       ngx_http_set_charset_slot,
[143]       NGX_HTTP_LOC_CONF_OFFSET,
[144]       offsetof(ngx_http_charset_loc_conf_t, charset),
[145]       NULL },
[146] 
[147]     { ngx_string("source_charset"),
[148]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
[149]                         |NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
[150]       ngx_http_set_charset_slot,
[151]       NGX_HTTP_LOC_CONF_OFFSET,
[152]       offsetof(ngx_http_charset_loc_conf_t, source_charset),
[153]       NULL },
[154] 
[155]     { ngx_string("override_charset"),
[156]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
[157]                         |NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
[158]       ngx_conf_set_flag_slot,
[159]       NGX_HTTP_LOC_CONF_OFFSET,
[160]       offsetof(ngx_http_charset_loc_conf_t, override_charset),
[161]       NULL },
[162] 
[163]     { ngx_string("charset_types"),
[164]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[165]       ngx_http_types_slot,
[166]       NGX_HTTP_LOC_CONF_OFFSET,
[167]       offsetof(ngx_http_charset_loc_conf_t, types_keys),
[168]       &ngx_http_charset_default_types[0] },
[169] 
[170]     { ngx_string("charset_map"),
[171]       NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
[172]       ngx_http_charset_map_block,
[173]       NGX_HTTP_MAIN_CONF_OFFSET,
[174]       0,
[175]       NULL },
[176] 
[177]       ngx_null_command
[178] };
[179] 
[180] 
[181] static ngx_http_module_t  ngx_http_charset_filter_module_ctx = {
[182]     NULL,                                  /* preconfiguration */
[183]     ngx_http_charset_postconfiguration,    /* postconfiguration */
[184] 
[185]     ngx_http_charset_create_main_conf,     /* create main configuration */
[186]     NULL,                                  /* init main configuration */
[187] 
[188]     NULL,                                  /* create server configuration */
[189]     NULL,                                  /* merge server configuration */
[190] 
[191]     ngx_http_charset_create_loc_conf,      /* create location configuration */
[192]     ngx_http_charset_merge_loc_conf        /* merge location configuration */
[193] };
[194] 
[195] 
[196] ngx_module_t  ngx_http_charset_filter_module = {
[197]     NGX_MODULE_V1,
[198]     &ngx_http_charset_filter_module_ctx,   /* module context */
[199]     ngx_http_charset_filter_commands,      /* module directives */
[200]     NGX_HTTP_MODULE,                       /* module type */
[201]     NULL,                                  /* init master */
[202]     NULL,                                  /* init module */
[203]     NULL,                                  /* init process */
[204]     NULL,                                  /* init thread */
[205]     NULL,                                  /* exit thread */
[206]     NULL,                                  /* exit process */
[207]     NULL,                                  /* exit master */
[208]     NGX_MODULE_V1_PADDING
[209] };
[210] 
[211] 
[212] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[213] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[214] 
[215] 
[216] static ngx_int_t
[217] ngx_http_charset_header_filter(ngx_http_request_t *r)
[218] {
[219]     ngx_int_t                      charset, source_charset;
[220]     ngx_str_t                      dst, src;
[221]     ngx_http_charset_t            *charsets;
[222]     ngx_http_charset_main_conf_t  *mcf;
[223] 
[224]     if (r == r->main) {
[225]         charset = ngx_http_destination_charset(r, &dst);
[226] 
[227]     } else {
[228]         charset = ngx_http_main_request_charset(r, &dst);
[229]     }
[230] 
[231]     if (charset == NGX_ERROR) {
[232]         return NGX_ERROR;
[233]     }
[234] 
[235]     if (charset == NGX_DECLINED) {
[236]         return ngx_http_next_header_filter(r);
[237]     }
[238] 
[239]     /* charset: charset index or NGX_HTTP_NO_CHARSET */
[240] 
[241]     source_charset = ngx_http_source_charset(r, &src);
[242] 
[243]     if (source_charset == NGX_ERROR) {
[244]         return NGX_ERROR;
[245]     }
[246] 
[247]     /*
[248]      * source_charset: charset index, NGX_HTTP_NO_CHARSET,
[249]      *                 or NGX_HTTP_CHARSET_OFF
[250]      */
[251] 
[252]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[253]                    "charset: \"%V\" > \"%V\"", &src, &dst);
[254] 
[255]     if (source_charset == NGX_HTTP_CHARSET_OFF) {
[256]         ngx_http_set_charset(r, &dst);
[257] 
[258]         return ngx_http_next_header_filter(r);
[259]     }
[260] 
[261]     if (charset == NGX_HTTP_NO_CHARSET
[262]         || source_charset == NGX_HTTP_NO_CHARSET)
[263]     {
[264]         if (source_charset != charset
[265]             || ngx_strncasecmp(dst.data, src.data, dst.len) != 0)
[266]         {
[267]             goto no_charset_map;
[268]         }
[269] 
[270]         ngx_http_set_charset(r, &dst);
[271] 
[272]         return ngx_http_next_header_filter(r);
[273]     }
[274] 
[275]     if (source_charset == charset) {
[276]         r->headers_out.content_type.len = r->headers_out.content_type_len;
[277] 
[278]         ngx_http_set_charset(r, &dst);
[279] 
[280]         return ngx_http_next_header_filter(r);
[281]     }
[282] 
[283]     /* source_charset != charset */
[284] 
[285]     if (r->headers_out.content_encoding
[286]         && r->headers_out.content_encoding->value.len)
[287]     {
[288]         return ngx_http_next_header_filter(r);
[289]     }
[290] 
[291]     mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);
[292]     charsets = mcf->charsets.elts;
[293] 
[294]     if (charsets[source_charset].tables == NULL
[295]         || charsets[source_charset].tables[charset] == NULL)
[296]     {
[297]         goto no_charset_map;
[298]     }
[299] 
[300]     r->headers_out.content_type.len = r->headers_out.content_type_len;
[301] 
[302]     ngx_http_set_charset(r, &dst);
[303] 
[304]     return ngx_http_charset_ctx(r, charsets, charset, source_charset);
[305] 
[306] no_charset_map:
[307] 
[308]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[309]                   "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
[310]                   &src, &dst);
[311] 
[312]     return ngx_http_next_header_filter(r);
[313] }
[314] 
[315] 
[316] static ngx_int_t
[317] ngx_http_destination_charset(ngx_http_request_t *r, ngx_str_t *name)
[318] {
[319]     ngx_int_t                      charset;
[320]     ngx_http_charset_t            *charsets;
[321]     ngx_http_variable_value_t     *vv;
[322]     ngx_http_charset_loc_conf_t   *mlcf;
[323]     ngx_http_charset_main_conf_t  *mcf;
[324] 
[325]     if (r->headers_out.content_type.len == 0) {
[326]         return NGX_DECLINED;
[327]     }
[328] 
[329]     if (r->headers_out.override_charset
[330]         && r->headers_out.override_charset->len)
[331]     {
[332]         *name = *r->headers_out.override_charset;
[333] 
[334]         charset = ngx_http_get_charset(r, name);
[335] 
[336]         if (charset != NGX_HTTP_NO_CHARSET) {
[337]             return charset;
[338]         }
[339] 
[340]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[341]                       "unknown charset \"%V\" to override", name);
[342] 
[343]         return NGX_DECLINED;
[344]     }
[345] 
[346]     mlcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);
[347]     charset = mlcf->charset;
[348] 
[349]     if (charset == NGX_HTTP_CHARSET_OFF) {
[350]         return NGX_DECLINED;
[351]     }
[352] 
[353]     if (r->headers_out.charset.len) {
[354]         if (mlcf->override_charset == 0) {
[355]             return NGX_DECLINED;
[356]         }
[357] 
[358]     } else {
[359]         if (ngx_http_test_content_type(r, &mlcf->types) == NULL) {
[360]             return NGX_DECLINED;
[361]         }
[362]     }
[363] 
[364]     if (charset < NGX_HTTP_CHARSET_VAR) {
[365]         mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);
[366]         charsets = mcf->charsets.elts;
[367]         *name = charsets[charset].name;
[368]         return charset;
[369]     }
[370] 
[371]     vv = ngx_http_get_indexed_variable(r, charset - NGX_HTTP_CHARSET_VAR);
[372] 
[373]     if (vv == NULL || vv->not_found) {
[374]         return NGX_ERROR;
[375]     }
[376] 
[377]     name->len = vv->len;
[378]     name->data = vv->data;
[379] 
[380]     return ngx_http_get_charset(r, name);
[381] }
[382] 
[383] 
[384] static ngx_int_t
[385] ngx_http_main_request_charset(ngx_http_request_t *r, ngx_str_t *src)
[386] {
[387]     ngx_int_t                charset;
[388]     ngx_str_t               *main_charset;
[389]     ngx_http_charset_ctx_t  *ctx;
[390] 
[391]     ctx = ngx_http_get_module_ctx(r->main, ngx_http_charset_filter_module);
[392] 
[393]     if (ctx) {
[394]         *src = ctx->charset_name;
[395]         return ctx->charset;
[396]     }
[397] 
[398]     main_charset = &r->main->headers_out.charset;
[399] 
[400]     if (main_charset->len == 0) {
[401]         return NGX_DECLINED;
[402]     }
[403] 
[404]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_charset_ctx_t));
[405]     if (ctx == NULL) {
[406]         return NGX_ERROR;
[407]     }
[408] 
[409]     ngx_http_set_ctx(r->main, ctx, ngx_http_charset_filter_module);
[410] 
[411]     charset = ngx_http_get_charset(r, main_charset);
[412] 
[413]     ctx->charset = charset;
[414]     ctx->charset_name = *main_charset;
[415]     *src = *main_charset;
[416] 
[417]     return charset;
[418] }
[419] 
[420] 
[421] static ngx_int_t
[422] ngx_http_source_charset(ngx_http_request_t *r, ngx_str_t *name)
[423] {
[424]     ngx_int_t                      charset;
[425]     ngx_http_charset_t            *charsets;
[426]     ngx_http_variable_value_t     *vv;
[427]     ngx_http_charset_loc_conf_t   *lcf;
[428]     ngx_http_charset_main_conf_t  *mcf;
[429] 
[430]     if (r->headers_out.charset.len) {
[431]         *name = r->headers_out.charset;
[432]         return ngx_http_get_charset(r, name);
[433]     }
[434] 
[435]     lcf = ngx_http_get_module_loc_conf(r, ngx_http_charset_filter_module);
[436] 
[437]     charset = lcf->source_charset;
[438] 
[439]     if (charset == NGX_HTTP_CHARSET_OFF) {
[440]         name->len = 0;
[441]         return charset;
[442]     }
[443] 
[444]     if (charset < NGX_HTTP_CHARSET_VAR) {
[445]         mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);
[446]         charsets = mcf->charsets.elts;
[447]         *name = charsets[charset].name;
[448]         return charset;
[449]     }
[450] 
[451]     vv = ngx_http_get_indexed_variable(r, charset - NGX_HTTP_CHARSET_VAR);
[452] 
[453]     if (vv == NULL || vv->not_found) {
[454]         return NGX_ERROR;
[455]     }
[456] 
[457]     name->len = vv->len;
[458]     name->data = vv->data;
[459] 
[460]     return ngx_http_get_charset(r, name);
[461] }
[462] 
[463] 
[464] static ngx_int_t
[465] ngx_http_get_charset(ngx_http_request_t *r, ngx_str_t *name)
[466] {
[467]     ngx_uint_t                     i, n;
[468]     ngx_http_charset_t            *charset;
[469]     ngx_http_charset_main_conf_t  *mcf;
[470] 
[471]     mcf = ngx_http_get_module_main_conf(r, ngx_http_charset_filter_module);
[472] 
[473]     charset = mcf->charsets.elts;
[474]     n = mcf->charsets.nelts;
[475] 
[476]     for (i = 0; i < n; i++) {
[477]         if (charset[i].name.len != name->len) {
[478]             continue;
[479]         }
[480] 
[481]         if (ngx_strncasecmp(charset[i].name.data, name->data, name->len) == 0) {
[482]             return i;
[483]         }
[484]     }
[485] 
[486]     return NGX_HTTP_NO_CHARSET;
[487] }
[488] 
[489] 
[490] static ngx_inline void
[491] ngx_http_set_charset(ngx_http_request_t *r, ngx_str_t *charset)
[492] {
[493]     if (r != r->main) {
[494]         return;
[495]     }
[496] 
[497]     if (r->headers_out.status == NGX_HTTP_MOVED_PERMANENTLY
[498]         || r->headers_out.status == NGX_HTTP_MOVED_TEMPORARILY)
[499]     {
[500]         /*
[501]          * do not set charset for the redirect because NN 4.x
[502]          * use this charset instead of the next page charset
[503]          */
[504] 
[505]         r->headers_out.charset.len = 0;
[506]         return;
[507]     }
[508] 
[509]     r->headers_out.charset = *charset;
[510] }
[511] 
[512] 
[513] static ngx_int_t
[514] ngx_http_charset_ctx(ngx_http_request_t *r, ngx_http_charset_t *charsets,
[515]     ngx_int_t charset, ngx_int_t source_charset)
[516] {
[517]     ngx_http_charset_ctx_t  *ctx;
[518] 
[519]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_charset_ctx_t));
[520]     if (ctx == NULL) {
[521]         return NGX_ERROR;
[522]     }
[523] 
[524]     ngx_http_set_ctx(r, ctx, ngx_http_charset_filter_module);
[525] 
[526]     ctx->table = charsets[source_charset].tables[charset];
[527]     ctx->charset = charset;
[528]     ctx->charset_name = charsets[charset].name;
[529]     ctx->length = charsets[charset].length;
[530]     ctx->from_utf8 = charsets[source_charset].utf8;
[531]     ctx->to_utf8 = charsets[charset].utf8;
[532] 
[533]     r->filter_need_in_memory = 1;
[534] 
[535]     if ((ctx->to_utf8 || ctx->from_utf8) && r == r->main) {
[536]         ngx_http_clear_content_length(r);
[537] 
[538]     } else {
[539]         r->filter_need_temporary = 1;
[540]     }
[541] 
[542]     return ngx_http_next_header_filter(r);
[543] }
[544] 
[545] 
[546] static ngx_int_t
[547] ngx_http_charset_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[548] {
[549]     ngx_int_t                rc;
[550]     ngx_buf_t               *b;
[551]     ngx_chain_t             *cl, *out, **ll;
[552]     ngx_http_charset_ctx_t  *ctx;
[553] 
[554]     ctx = ngx_http_get_module_ctx(r, ngx_http_charset_filter_module);
[555] 
[556]     if (ctx == NULL || ctx->table == NULL) {
[557]         return ngx_http_next_body_filter(r, in);
[558]     }
[559] 
[560]     if ((ctx->to_utf8 || ctx->from_utf8) || ctx->busy) {
[561] 
[562]         out = NULL;
[563]         ll = &out;
[564] 
[565]         for (cl = in; cl; cl = cl->next) {
[566]             b = cl->buf;
[567] 
[568]             if (ngx_buf_size(b) == 0) {
[569] 
[570]                 *ll = ngx_alloc_chain_link(r->pool);
[571]                 if (*ll == NULL) {
[572]                     return NGX_ERROR;
[573]                 }
[574] 
[575]                 (*ll)->buf = b;
[576]                 (*ll)->next = NULL;
[577] 
[578]                 ll = &(*ll)->next;
[579] 
[580]                 continue;
[581]             }
[582] 
[583]             if (ctx->to_utf8) {
[584]                 *ll = ngx_http_charset_recode_to_utf8(r->pool, b, ctx);
[585] 
[586]             } else {
[587]                 *ll = ngx_http_charset_recode_from_utf8(r->pool, b, ctx);
[588]             }
[589] 
[590]             if (*ll == NULL) {
[591]                 return NGX_ERROR;
[592]             }
[593] 
[594]             while (*ll) {
[595]                 ll = &(*ll)->next;
[596]             }
[597]         }
[598] 
[599]         rc = ngx_http_next_body_filter(r, out);
[600] 
[601]         if (out) {
[602]             if (ctx->busy == NULL) {
[603]                 ctx->busy = out;
[604] 
[605]             } else {
[606]                 for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
[607]                 cl->next = out;
[608]             }
[609]         }
[610] 
[611]         while (ctx->busy) {
[612] 
[613]             cl = ctx->busy;
[614]             b = cl->buf;
[615] 
[616]             if (ngx_buf_size(b) != 0) {
[617]                 break;
[618]             }
[619] 
[620]             ctx->busy = cl->next;
[621] 
[622]             if (b->tag != (ngx_buf_tag_t) &ngx_http_charset_filter_module) {
[623]                 continue;
[624]             }
[625] 
[626]             if (b->shadow) {
[627]                 b->shadow->pos = b->shadow->last;
[628]             }
[629] 
[630]             if (b->pos) {
[631]                 cl->next = ctx->free_buffers;
[632]                 ctx->free_buffers = cl;
[633]                 continue;
[634]             }
[635] 
[636]             cl->next = ctx->free_bufs;
[637]             ctx->free_bufs = cl;
[638]         }
[639] 
[640]         return rc;
[641]     }
[642] 
[643]     for (cl = in; cl; cl = cl->next) {
[644]         (void) ngx_http_charset_recode(cl->buf, ctx->table);
[645]     }
[646] 
[647]     return ngx_http_next_body_filter(r, in);
[648] }
[649] 
[650] 
[651] static ngx_uint_t
[652] ngx_http_charset_recode(ngx_buf_t *b, u_char *table)
[653] {
[654]     u_char  *p, *last;
[655] 
[656]     last = b->last;
[657] 
[658]     for (p = b->pos; p < last; p++) {
[659] 
[660]         if (*p != table[*p]) {
[661]             goto recode;
[662]         }
[663]     }
[664] 
[665]     return 0;
[666] 
[667] recode:
[668] 
[669]     do {
[670]         if (*p != table[*p]) {
[671]             *p = table[*p];
[672]         }
[673] 
[674]         p++;
[675] 
[676]     } while (p < last);
[677] 
[678]     b->in_file = 0;
[679] 
[680]     return 1;
[681] }
[682] 
[683] 
[684] static ngx_chain_t *
[685] ngx_http_charset_recode_from_utf8(ngx_pool_t *pool, ngx_buf_t *buf,
[686]     ngx_http_charset_ctx_t *ctx)
[687] {
[688]     size_t        len, size;
[689]     u_char        c, *p, *src, *dst, *saved, **table;
[690]     uint32_t      n;
[691]     ngx_buf_t    *b;
[692]     ngx_uint_t    i;
[693]     ngx_chain_t  *out, *cl, **ll;
[694] 
[695]     src = buf->pos;
[696] 
[697]     if (ctx->saved_len == 0) {
[698] 
[699]         for ( /* void */ ; src < buf->last; src++) {
[700] 
[701]             if (*src < 0x80) {
[702]                 continue;
[703]             }
[704] 
[705]             len = src - buf->pos;
[706] 
[707]             if (len > 512) {
[708]                 out = ngx_http_charset_get_buf(pool, ctx);
[709]                 if (out == NULL) {
[710]                     return NULL;
[711]                 }
[712] 
[713]                 b = out->buf;
[714] 
[715]                 b->temporary = buf->temporary;
[716]                 b->memory = buf->memory;
[717]                 b->mmap = buf->mmap;
[718]                 b->flush = buf->flush;
[719] 
[720]                 b->pos = buf->pos;
[721]                 b->last = src;
[722] 
[723]                 out->buf = b;
[724]                 out->next = NULL;
[725] 
[726]                 size = buf->last - src;
[727] 
[728]                 saved = src;
[729]                 n = ngx_utf8_decode(&saved, size);
[730] 
[731]                 if (n == 0xfffffffe) {
[732]                     /* incomplete UTF-8 symbol */
[733] 
[734]                     ngx_memcpy(ctx->saved, src, size);
[735]                     ctx->saved_len = size;
[736] 
[737]                     b->shadow = buf;
[738] 
[739]                     return out;
[740]                 }
[741] 
[742]             } else {
[743]                 out = NULL;
[744]                 size = len + buf->last - src;
[745]                 src = buf->pos;
[746]             }
[747] 
[748]             if (size < NGX_HTML_ENTITY_LEN) {
[749]                 size += NGX_HTML_ENTITY_LEN;
[750]             }
[751] 
[752]             cl = ngx_http_charset_get_buffer(pool, ctx, size);
[753]             if (cl == NULL) {
[754]                 return NULL;
[755]             }
[756] 
[757]             if (out) {
[758]                 out->next = cl;
[759] 
[760]             } else {
[761]                 out = cl;
[762]             }
[763] 
[764]             b = cl->buf;
[765]             dst = b->pos;
[766] 
[767]             goto recode;
[768]         }
[769] 
[770]         out = ngx_alloc_chain_link(pool);
[771]         if (out == NULL) {
[772]             return NULL;
[773]         }
[774] 
[775]         out->buf = buf;
[776]         out->next = NULL;
[777] 
[778]         return out;
[779]     }
[780] 
[781]     /* process incomplete UTF sequence from previous buffer */
[782] 
[783]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
[784]                    "http charset utf saved: %z", ctx->saved_len);
[785] 
[786]     p = src;
[787] 
[788]     for (i = ctx->saved_len; i < NGX_UTF_LEN; i++) {
[789]         ctx->saved[i] = *p++;
[790] 
[791]         if (p == buf->last) {
[792]             break;
[793]         }
[794]     }
[795] 
[796]     saved = ctx->saved;
[797]     n = ngx_utf8_decode(&saved, i);
[798] 
[799]     c = '\0';
[800] 
[801]     if (n < 0x10000) {
[802]         table = (u_char **) ctx->table;
[803]         p = table[n >> 8];
[804] 
[805]         if (p) {
[806]             c = p[n & 0xff];
[807]         }
[808] 
[809]     } else if (n == 0xfffffffe) {
[810] 
[811]         /* incomplete UTF-8 symbol */
[812] 
[813]         if (i < NGX_UTF_LEN) {
[814]             out = ngx_http_charset_get_buf(pool, ctx);
[815]             if (out == NULL) {
[816]                 return NULL;
[817]             }
[818] 
[819]             b = out->buf;
[820] 
[821]             b->pos = buf->pos;
[822]             b->last = buf->last;
[823]             b->sync = 1;
[824]             b->shadow = buf;
[825] 
[826]             ngx_memcpy(&ctx->saved[ctx->saved_len], src, i);
[827]             ctx->saved_len += i;
[828] 
[829]             return out;
[830]         }
[831]     }
[832] 
[833]     size = buf->last - buf->pos;
[834] 
[835]     if (size < NGX_HTML_ENTITY_LEN) {
[836]         size += NGX_HTML_ENTITY_LEN;
[837]     }
[838] 
[839]     cl = ngx_http_charset_get_buffer(pool, ctx, size);
[840]     if (cl == NULL) {
[841]         return NULL;
[842]     }
[843] 
[844]     out = cl;
[845] 
[846]     b = cl->buf;
[847]     dst = b->pos;
[848] 
[849]     if (c) {
[850]         *dst++ = c;
[851] 
[852]     } else if (n == 0xfffffffe) {
[853]         *dst++ = '?';
[854] 
[855]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
[856]                        "http charset invalid utf 0");
[857] 
[858]         saved = &ctx->saved[NGX_UTF_LEN];
[859] 
[860]     } else if (n > 0x10ffff) {
[861]         *dst++ = '?';
[862] 
[863]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
[864]                        "http charset invalid utf 1");
[865] 
[866]     } else {
[867]         dst = ngx_sprintf(dst, "&#%uD;", n);
[868]     }
[869] 
[870]     src += (saved - ctx->saved) - ctx->saved_len;
[871]     ctx->saved_len = 0;
[872] 
[873] recode:
[874] 
[875]     ll = &cl->next;
[876] 
[877]     table = (u_char **) ctx->table;
[878] 
[879]     while (src < buf->last) {
[880] 
[881]         if ((size_t) (b->end - dst) < NGX_HTML_ENTITY_LEN) {
[882]             b->last = dst;
[883] 
[884]             size = buf->last - src + NGX_HTML_ENTITY_LEN;
[885] 
[886]             cl = ngx_http_charset_get_buffer(pool, ctx, size);
[887]             if (cl == NULL) {
[888]                 return NULL;
[889]             }
[890] 
[891]             *ll = cl;
[892]             ll = &cl->next;
[893] 
[894]             b = cl->buf;
[895]             dst = b->pos;
[896]         }
[897] 
[898]         if (*src < 0x80) {
[899]             *dst++ = *src++;
[900]             continue;
[901]         }
[902] 
[903]         len = buf->last - src;
[904] 
[905]         n = ngx_utf8_decode(&src, len);
[906] 
[907]         if (n < 0x10000) {
[908] 
[909]             p = table[n >> 8];
[910] 
[911]             if (p) {
[912]                 c = p[n & 0xff];
[913] 
[914]                 if (c) {
[915]                     *dst++ = c;
[916]                     continue;
[917]                 }
[918]             }
[919] 
[920]             dst = ngx_sprintf(dst, "&#%uD;", n);
[921] 
[922]             continue;
[923]         }
[924] 
[925]         if (n == 0xfffffffe) {
[926]             /* incomplete UTF-8 symbol */
[927] 
[928]             ngx_memcpy(ctx->saved, src, len);
[929]             ctx->saved_len = len;
[930] 
[931]             if (b->pos == dst) {
[932]                 b->sync = 1;
[933]                 b->temporary = 0;
[934]             }
[935] 
[936]             break;
[937]         }
[938] 
[939]         if (n > 0x10ffff) {
[940]             *dst++ = '?';
[941] 
[942]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pool->log, 0,
[943]                            "http charset invalid utf 2");
[944] 
[945]             continue;
[946]         }
[947] 
[948]         /* n > 0xffff */
[949] 
[950]         dst = ngx_sprintf(dst, "&#%uD;", n);
[951]     }
[952] 
[953]     b->last = dst;
[954] 
[955]     b->last_buf = buf->last_buf;
[956]     b->last_in_chain = buf->last_in_chain;
[957]     b->flush = buf->flush;
[958] 
[959]     b->shadow = buf;
[960] 
[961]     return out;
[962] }
[963] 
[964] 
[965] static ngx_chain_t *
[966] ngx_http_charset_recode_to_utf8(ngx_pool_t *pool, ngx_buf_t *buf,
[967]     ngx_http_charset_ctx_t *ctx)
[968] {
[969]     size_t        len, size;
[970]     u_char       *p, *src, *dst, *table;
[971]     ngx_buf_t    *b;
[972]     ngx_chain_t  *out, *cl, **ll;
[973] 
[974]     table = ctx->table;
[975] 
[976]     for (src = buf->pos; src < buf->last; src++) {
[977]         if (table[*src * NGX_UTF_LEN] == '\1') {
[978]             continue;
[979]         }
[980] 
[981]         goto recode;
[982]     }
[983] 
[984]     out = ngx_alloc_chain_link(pool);
[985]     if (out == NULL) {
[986]         return NULL;
[987]     }
[988] 
[989]     out->buf = buf;
[990]     out->next = NULL;
[991] 
[992]     return out;
[993] 
[994] recode:
[995] 
[996]     /*
[997]      * we assume that there are about half of characters to be recoded,
[998]      * so we preallocate "size / 2 + size / 2 * ctx->length"
[999]      */
[1000] 
[1001]     len = src - buf->pos;
[1002] 
[1003]     if (len > 512) {
[1004]         out = ngx_http_charset_get_buf(pool, ctx);
[1005]         if (out == NULL) {
[1006]             return NULL;
[1007]         }
[1008] 
[1009]         b = out->buf;
[1010] 
[1011]         b->temporary = buf->temporary;
[1012]         b->memory = buf->memory;
[1013]         b->mmap = buf->mmap;
[1014]         b->flush = buf->flush;
[1015] 
[1016]         b->pos = buf->pos;
[1017]         b->last = src;
[1018] 
[1019]         out->buf = b;
[1020]         out->next = NULL;
[1021] 
[1022]         size = buf->last - src;
[1023]         size = size / 2 + size / 2 * ctx->length;
[1024] 
[1025]     } else {
[1026]         out = NULL;
[1027] 
[1028]         size = buf->last - src;
[1029]         size = len + size / 2 + size / 2 * ctx->length;
[1030] 
[1031]         src = buf->pos;
[1032]     }
[1033] 
[1034]     cl = ngx_http_charset_get_buffer(pool, ctx, size);
[1035]     if (cl == NULL) {
[1036]         return NULL;
[1037]     }
[1038] 
[1039]     if (out) {
[1040]         out->next = cl;
[1041] 
[1042]     } else {
[1043]         out = cl;
[1044]     }
[1045] 
[1046]     ll = &cl->next;
[1047] 
[1048]     b = cl->buf;
[1049]     dst = b->pos;
[1050] 
[1051]     while (src < buf->last) {
[1052] 
[1053]         p = &table[*src++ * NGX_UTF_LEN];
[1054]         len = *p++;
[1055] 
[1056]         if ((size_t) (b->end - dst) < len) {
[1057]             b->last = dst;
[1058] 
[1059]             size = buf->last - src;
[1060]             size = len + size / 2 + size / 2 * ctx->length;
[1061] 
[1062]             cl = ngx_http_charset_get_buffer(pool, ctx, size);
[1063]             if (cl == NULL) {
[1064]                 return NULL;
[1065]             }
[1066] 
[1067]             *ll = cl;
[1068]             ll = &cl->next;
[1069] 
[1070]             b = cl->buf;
[1071]             dst = b->pos;
[1072]         }
[1073] 
[1074]         while (len) {
[1075]             *dst++ = *p++;
[1076]             len--;
[1077]         }
[1078]     }
[1079] 
[1080]     b->last = dst;
[1081] 
[1082]     b->last_buf = buf->last_buf;
[1083]     b->last_in_chain = buf->last_in_chain;
[1084]     b->flush = buf->flush;
[1085] 
[1086]     b->shadow = buf;
[1087] 
[1088]     return out;
[1089] }
[1090] 
[1091] 
[1092] static ngx_chain_t *
[1093] ngx_http_charset_get_buf(ngx_pool_t *pool, ngx_http_charset_ctx_t *ctx)
[1094] {
[1095]     ngx_chain_t  *cl;
[1096] 
[1097]     cl = ctx->free_bufs;
[1098] 
[1099]     if (cl) {
[1100]         ctx->free_bufs = cl->next;
[1101] 
[1102]         cl->buf->shadow = NULL;
[1103]         cl->next = NULL;
[1104] 
[1105]         return cl;
[1106]     }
[1107] 
[1108]     cl = ngx_alloc_chain_link(pool);
[1109]     if (cl == NULL) {
[1110]         return NULL;
[1111]     }
[1112] 
[1113]     cl->buf = ngx_calloc_buf(pool);
[1114]     if (cl->buf == NULL) {
[1115]         return NULL;
[1116]     }
[1117] 
[1118]     cl->next = NULL;
[1119] 
[1120]     cl->buf->tag = (ngx_buf_tag_t) &ngx_http_charset_filter_module;
[1121] 
[1122]     return cl;
[1123] }
[1124] 
[1125] 
[1126] static ngx_chain_t *
[1127] ngx_http_charset_get_buffer(ngx_pool_t *pool, ngx_http_charset_ctx_t *ctx,
[1128]     size_t size)
[1129] {
[1130]     ngx_buf_t    *b;
[1131]     ngx_chain_t  *cl, **ll;
[1132] 
[1133]     for (ll = &ctx->free_buffers, cl = ctx->free_buffers;
[1134]          cl;
[1135]          ll = &cl->next, cl = cl->next)
[1136]     {
[1137]         b = cl->buf;
[1138] 
[1139]         if ((size_t) (b->end - b->start) >= size) {
[1140]             *ll = cl->next;
[1141]             cl->next = NULL;
[1142] 
[1143]             b->pos = b->start;
[1144]             b->temporary = 1;
[1145]             b->shadow = NULL;
[1146] 
[1147]             return cl;
[1148]         }
[1149]     }
[1150] 
[1151]     cl = ngx_alloc_chain_link(pool);
[1152]     if (cl == NULL) {
[1153]         return NULL;
[1154]     }
[1155] 
[1156]     cl->buf = ngx_create_temp_buf(pool, size);
[1157]     if (cl->buf == NULL) {
[1158]         return NULL;
[1159]     }
[1160] 
[1161]     cl->next = NULL;
[1162] 
[1163]     cl->buf->temporary = 1;
[1164]     cl->buf->tag = (ngx_buf_tag_t) &ngx_http_charset_filter_module;
[1165] 
[1166]     return cl;
[1167] }
[1168] 
[1169] 
[1170] static char *
[1171] ngx_http_charset_map_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1172] {
[1173]     ngx_http_charset_main_conf_t  *mcf = conf;
[1174] 
[1175]     char                         *rv;
[1176]     u_char                       *p, *dst2src, **pp;
[1177]     ngx_int_t                     src, dst;
[1178]     ngx_uint_t                    i, n;
[1179]     ngx_str_t                    *value;
[1180]     ngx_conf_t                    pvcf;
[1181]     ngx_http_charset_t           *charset;
[1182]     ngx_http_charset_tables_t    *table;
[1183]     ngx_http_charset_conf_ctx_t   ctx;
[1184] 
[1185]     value = cf->args->elts;
[1186] 
[1187]     src = ngx_http_add_charset(&mcf->charsets, &value[1]);
[1188]     if (src == NGX_ERROR) {
[1189]         return NGX_CONF_ERROR;
[1190]     }
[1191] 
[1192]     dst = ngx_http_add_charset(&mcf->charsets, &value[2]);
[1193]     if (dst == NGX_ERROR) {
[1194]         return NGX_CONF_ERROR;
[1195]     }
[1196] 
[1197]     if (src == dst) {
[1198]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1199]                            "\"charset_map\" between the same charsets "
[1200]                            "\"%V\" and \"%V\"", &value[1], &value[2]);
[1201]         return NGX_CONF_ERROR;
[1202]     }
[1203] 
[1204]     table = mcf->tables.elts;
[1205]     for (i = 0; i < mcf->tables.nelts; i++) {
[1206]         if ((src == table->src && dst == table->dst)
[1207]              || (src == table->dst && dst == table->src))
[1208]         {
[1209]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1210]                                "duplicate \"charset_map\" between "
[1211]                                "\"%V\" and \"%V\"", &value[1], &value[2]);
[1212]             return NGX_CONF_ERROR;
[1213]         }
[1214]     }
[1215] 
[1216]     table = ngx_array_push(&mcf->tables);
[1217]     if (table == NULL) {
[1218]         return NGX_CONF_ERROR;
[1219]     }
[1220] 
[1221]     table->src = src;
[1222]     table->dst = dst;
[1223] 
[1224]     if (ngx_strcasecmp(value[2].data, (u_char *) "utf-8") == 0) {
[1225]         table->src2dst = ngx_pcalloc(cf->pool, 256 * NGX_UTF_LEN);
[1226]         if (table->src2dst == NULL) {
[1227]             return NGX_CONF_ERROR;
[1228]         }
[1229] 
[1230]         table->dst2src = ngx_pcalloc(cf->pool, 256 * sizeof(void *));
[1231]         if (table->dst2src == NULL) {
[1232]             return NGX_CONF_ERROR;
[1233]         }
[1234] 
[1235]         dst2src = ngx_pcalloc(cf->pool, 256);
[1236]         if (dst2src == NULL) {
[1237]             return NGX_CONF_ERROR;
[1238]         }
[1239] 
[1240]         pp = (u_char **) &table->dst2src[0];
[1241]         pp[0] = dst2src;
[1242] 
[1243]         for (i = 0; i < 128; i++) {
[1244]             p = &table->src2dst[i * NGX_UTF_LEN];
[1245]             p[0] = '\1';
[1246]             p[1] = (u_char) i;
[1247]             dst2src[i] = (u_char) i;
[1248]         }
[1249] 
[1250]         for (/* void */; i < 256; i++) {
[1251]             p = &table->src2dst[i * NGX_UTF_LEN];
[1252]             p[0] = '\1';
[1253]             p[1] = '?';
[1254]         }
[1255] 
[1256]     } else {
[1257]         table->src2dst = ngx_palloc(cf->pool, 256);
[1258]         if (table->src2dst == NULL) {
[1259]             return NGX_CONF_ERROR;
[1260]         }
[1261] 
[1262]         table->dst2src = ngx_palloc(cf->pool, 256);
[1263]         if (table->dst2src == NULL) {
[1264]             return NGX_CONF_ERROR;
[1265]         }
[1266] 
[1267]         for (i = 0; i < 128; i++) {
[1268]             table->src2dst[i] = (u_char) i;
[1269]             table->dst2src[i] = (u_char) i;
[1270]         }
[1271] 
[1272]         for (/* void */; i < 256; i++) {
[1273]             table->src2dst[i] = '?';
[1274]             table->dst2src[i] = '?';
[1275]         }
[1276]     }
[1277] 
[1278]     charset = mcf->charsets.elts;
[1279] 
[1280]     ctx.table = table;
[1281]     ctx.charset = &charset[dst];
[1282]     ctx.characters = 0;
[1283] 
[1284]     pvcf = *cf;
[1285]     cf->ctx = &ctx;
[1286]     cf->handler = ngx_http_charset_map;
[1287]     cf->handler_conf = conf;
[1288] 
[1289]     rv = ngx_conf_parse(cf, NULL);
[1290] 
[1291]     *cf = pvcf;
[1292] 
[1293]     if (ctx.characters) {
[1294]         n = ctx.charset->length;
[1295]         ctx.charset->length /= ctx.characters;
[1296] 
[1297]         if (((n * 10) / ctx.characters) % 10 > 4) {
[1298]             ctx.charset->length++;
[1299]         }
[1300]     }
[1301] 
[1302]     return rv;
[1303] }
[1304] 
[1305] 
[1306] static char *
[1307] ngx_http_charset_map(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[1308] {
[1309]     u_char                       *p, *dst2src, **pp;
[1310]     uint32_t                      n;
[1311]     ngx_int_t                     src, dst;
[1312]     ngx_str_t                    *value;
[1313]     ngx_uint_t                    i;
[1314]     ngx_http_charset_tables_t    *table;
[1315]     ngx_http_charset_conf_ctx_t  *ctx;
[1316] 
[1317]     if (cf->args->nelts != 2) {
[1318]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameters number");
[1319]         return NGX_CONF_ERROR;
[1320]     }
[1321] 
[1322]     value = cf->args->elts;
[1323] 
[1324]     src = ngx_hextoi(value[0].data, value[0].len);
[1325]     if (src == NGX_ERROR || src > 255) {
[1326]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1327]                            "invalid value \"%V\"", &value[0]);
[1328]         return NGX_CONF_ERROR;
[1329]     }
[1330] 
[1331]     ctx = cf->ctx;
[1332]     table = ctx->table;
[1333] 
[1334]     if (ctx->charset->utf8) {
[1335]         p = &table->src2dst[src * NGX_UTF_LEN];
[1336] 
[1337]         *p++ = (u_char) (value[1].len / 2);
[1338] 
[1339]         for (i = 0; i < value[1].len; i += 2) {
[1340]             dst = ngx_hextoi(&value[1].data[i], 2);
[1341]             if (dst == NGX_ERROR || dst > 255) {
[1342]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1343]                                    "invalid value \"%V\"", &value[1]);
[1344]                 return NGX_CONF_ERROR;
[1345]             }
[1346] 
[1347]             *p++ = (u_char) dst;
[1348]         }
[1349] 
[1350]         i /= 2;
[1351] 
[1352]         ctx->charset->length += i;
[1353]         ctx->characters++;
[1354] 
[1355]         p = &table->src2dst[src * NGX_UTF_LEN] + 1;
[1356] 
[1357]         n = ngx_utf8_decode(&p, i);
[1358] 
[1359]         if (n > 0xffff) {
[1360]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1361]                                "invalid value \"%V\"", &value[1]);
[1362]             return NGX_CONF_ERROR;
[1363]         }
[1364] 
[1365]         pp = (u_char **) &table->dst2src[0];
[1366] 
[1367]         dst2src = pp[n >> 8];
[1368] 
[1369]         if (dst2src == NULL) {
[1370]             dst2src = ngx_pcalloc(cf->pool, 256);
[1371]             if (dst2src == NULL) {
[1372]                 return NGX_CONF_ERROR;
[1373]             }
[1374] 
[1375]             pp[n >> 8] = dst2src;
[1376]         }
[1377] 
[1378]         dst2src[n & 0xff] = (u_char) src;
[1379] 
[1380]     } else {
[1381]         dst = ngx_hextoi(value[1].data, value[1].len);
[1382]         if (dst == NGX_ERROR || dst > 255) {
[1383]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1384]                                "invalid value \"%V\"", &value[1]);
[1385]             return NGX_CONF_ERROR;
[1386]         }
[1387] 
[1388]         table->src2dst[src] = (u_char) dst;
[1389]         table->dst2src[dst] = (u_char) src;
[1390]     }
[1391] 
[1392]     return NGX_CONF_OK;
[1393] }
[1394] 
[1395] 
[1396] static char *
[1397] ngx_http_set_charset_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1398] {
[1399]     char  *p = conf;
[1400] 
[1401]     ngx_int_t                     *cp;
[1402]     ngx_str_t                     *value, var;
[1403]     ngx_http_charset_main_conf_t  *mcf;
[1404] 
[1405]     cp = (ngx_int_t *) (p + cmd->offset);
[1406] 
[1407]     if (*cp != NGX_CONF_UNSET) {
[1408]         return "is duplicate";
[1409]     }
[1410] 
[1411]     value = cf->args->elts;
[1412] 
[1413]     if (cmd->offset == offsetof(ngx_http_charset_loc_conf_t, charset)
[1414]         && ngx_strcmp(value[1].data, "off") == 0)
[1415]     {
[1416]         *cp = NGX_HTTP_CHARSET_OFF;
[1417]         return NGX_CONF_OK;
[1418]     }
[1419] 
[1420] 
[1421]     if (value[1].data[0] == '$') {
[1422]         var.len = value[1].len - 1;
[1423]         var.data = value[1].data + 1;
[1424] 
[1425]         *cp = ngx_http_get_variable_index(cf, &var);
[1426] 
[1427]         if (*cp == NGX_ERROR) {
[1428]             return NGX_CONF_ERROR;
[1429]         }
[1430] 
[1431]         *cp += NGX_HTTP_CHARSET_VAR;
[1432] 
[1433]         return NGX_CONF_OK;
[1434]     }
[1435] 
[1436]     mcf = ngx_http_conf_get_module_main_conf(cf,
[1437]                                              ngx_http_charset_filter_module);
[1438] 
[1439]     *cp = ngx_http_add_charset(&mcf->charsets, &value[1]);
[1440]     if (*cp == NGX_ERROR) {
[1441]         return NGX_CONF_ERROR;
[1442]     }
[1443] 
[1444]     return NGX_CONF_OK;
[1445] }
[1446] 
[1447] 
[1448] static ngx_int_t
[1449] ngx_http_add_charset(ngx_array_t *charsets, ngx_str_t *name)
[1450] {
[1451]     ngx_uint_t           i;
[1452]     ngx_http_charset_t  *c;
[1453] 
[1454]     c = charsets->elts;
[1455]     for (i = 0; i < charsets->nelts; i++) {
[1456]         if (name->len != c[i].name.len) {
[1457]             continue;
[1458]         }
[1459] 
[1460]         if (ngx_strcasecmp(name->data, c[i].name.data) == 0) {
[1461]             break;
[1462]         }
[1463]     }
[1464] 
[1465]     if (i < charsets->nelts) {
[1466]         return i;
[1467]     }
[1468] 
[1469]     c = ngx_array_push(charsets);
[1470]     if (c == NULL) {
[1471]         return NGX_ERROR;
[1472]     }
[1473] 
[1474]     c->tables = NULL;
[1475]     c->name = *name;
[1476]     c->length = 0;
[1477] 
[1478]     if (ngx_strcasecmp(name->data, (u_char *) "utf-8") == 0) {
[1479]         c->utf8 = 1;
[1480] 
[1481]     } else {
[1482]         c->utf8 = 0;
[1483]     }
[1484] 
[1485]     return i;
[1486] }
[1487] 
[1488] 
[1489] static void *
[1490] ngx_http_charset_create_main_conf(ngx_conf_t *cf)
[1491] {
[1492]     ngx_http_charset_main_conf_t  *mcf;
[1493] 
[1494]     mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_main_conf_t));
[1495]     if (mcf == NULL) {
[1496]         return NULL;
[1497]     }
[1498] 
[1499]     if (ngx_array_init(&mcf->charsets, cf->pool, 2, sizeof(ngx_http_charset_t))
[1500]         != NGX_OK)
[1501]     {
[1502]         return NULL;
[1503]     }
[1504] 
[1505]     if (ngx_array_init(&mcf->tables, cf->pool, 1,
[1506]                        sizeof(ngx_http_charset_tables_t))
[1507]         != NGX_OK)
[1508]     {
[1509]         return NULL;
[1510]     }
[1511] 
[1512]     if (ngx_array_init(&mcf->recodes, cf->pool, 2,
[1513]                        sizeof(ngx_http_charset_recode_t))
[1514]         != NGX_OK)
[1515]     {
[1516]         return NULL;
[1517]     }
[1518] 
[1519]     return mcf;
[1520] }
[1521] 
[1522] 
[1523] static void *
[1524] ngx_http_charset_create_loc_conf(ngx_conf_t *cf)
[1525] {
[1526]     ngx_http_charset_loc_conf_t  *lcf;
[1527] 
[1528]     lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_charset_loc_conf_t));
[1529]     if (lcf == NULL) {
[1530]         return NULL;
[1531]     }
[1532] 
[1533]     /*
[1534]      * set by ngx_pcalloc():
[1535]      *
[1536]      *     lcf->types = { NULL };
[1537]      *     lcf->types_keys = NULL;
[1538]      */
[1539] 
[1540]     lcf->charset = NGX_CONF_UNSET;
[1541]     lcf->source_charset = NGX_CONF_UNSET;
[1542]     lcf->override_charset = NGX_CONF_UNSET;
[1543] 
[1544]     return lcf;
[1545] }
[1546] 
[1547] 
[1548] static char *
[1549] ngx_http_charset_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[1550] {
[1551]     ngx_http_charset_loc_conf_t *prev = parent;
[1552]     ngx_http_charset_loc_conf_t *conf = child;
[1553] 
[1554]     ngx_uint_t                     i;
[1555]     ngx_http_charset_recode_t     *recode;
[1556]     ngx_http_charset_main_conf_t  *mcf;
[1557] 
[1558]     if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
[1559]                              &prev->types_keys, &prev->types,
[1560]                              ngx_http_charset_default_types)
[1561]         != NGX_OK)
[1562]     {
[1563]         return NGX_CONF_ERROR;
[1564]     }
[1565] 
[1566]     ngx_conf_merge_value(conf->override_charset, prev->override_charset, 0);
[1567]     ngx_conf_merge_value(conf->charset, prev->charset, NGX_HTTP_CHARSET_OFF);
[1568]     ngx_conf_merge_value(conf->source_charset, prev->source_charset,
[1569]                          NGX_HTTP_CHARSET_OFF);
[1570] 
[1571]     if (conf->charset == NGX_HTTP_CHARSET_OFF
[1572]         || conf->source_charset == NGX_HTTP_CHARSET_OFF
[1573]         || conf->charset == conf->source_charset)
[1574]     {
[1575]         return NGX_CONF_OK;
[1576]     }
[1577] 
[1578]     if (conf->source_charset >= NGX_HTTP_CHARSET_VAR
[1579]         || conf->charset >= NGX_HTTP_CHARSET_VAR)
[1580]     {
[1581]         return NGX_CONF_OK;
[1582]     }
[1583] 
[1584]     mcf = ngx_http_conf_get_module_main_conf(cf,
[1585]                                              ngx_http_charset_filter_module);
[1586]     recode = mcf->recodes.elts;
[1587]     for (i = 0; i < mcf->recodes.nelts; i++) {
[1588]         if (conf->source_charset == recode[i].src
[1589]             && conf->charset == recode[i].dst)
[1590]         {
[1591]             return NGX_CONF_OK;
[1592]         }
[1593]     }
[1594] 
[1595]     recode = ngx_array_push(&mcf->recodes);
[1596]     if (recode == NULL) {
[1597]         return NGX_CONF_ERROR;
[1598]     }
[1599] 
[1600]     recode->src = conf->source_charset;
[1601]     recode->dst = conf->charset;
[1602] 
[1603]     return NGX_CONF_OK;
[1604] }
[1605] 
[1606] 
[1607] static ngx_int_t
[1608] ngx_http_charset_postconfiguration(ngx_conf_t *cf)
[1609] {
[1610]     u_char                       **src, **dst;
[1611]     ngx_int_t                      c;
[1612]     ngx_uint_t                     i, t;
[1613]     ngx_http_charset_t            *charset;
[1614]     ngx_http_charset_recode_t     *recode;
[1615]     ngx_http_charset_tables_t     *tables;
[1616]     ngx_http_charset_main_conf_t  *mcf;
[1617] 
[1618]     mcf = ngx_http_conf_get_module_main_conf(cf,
[1619]                                              ngx_http_charset_filter_module);
[1620] 
[1621]     recode = mcf->recodes.elts;
[1622]     tables = mcf->tables.elts;
[1623]     charset = mcf->charsets.elts;
[1624] 
[1625]     for (i = 0; i < mcf->recodes.nelts; i++) {
[1626] 
[1627]         c = recode[i].src;
[1628] 
[1629]         for (t = 0; t < mcf->tables.nelts; t++) {
[1630] 
[1631]             if (c == tables[t].src && recode[i].dst == tables[t].dst) {
[1632]                 goto next;
[1633]             }
[1634] 
[1635]             if (c == tables[t].dst && recode[i].dst == tables[t].src) {
[1636]                 goto next;
[1637]             }
[1638]         }
[1639] 
[1640]         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1641]                    "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
[1642]                    &charset[c].name, &charset[recode[i].dst].name);
[1643]         return NGX_ERROR;
[1644] 
[1645]     next:
[1646]         continue;
[1647]     }
[1648] 
[1649] 
[1650]     for (t = 0; t < mcf->tables.nelts; t++) {
[1651] 
[1652]         src = charset[tables[t].src].tables;
[1653] 
[1654]         if (src == NULL) {
[1655]             src = ngx_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
[1656]             if (src == NULL) {
[1657]                 return NGX_ERROR;
[1658]             }
[1659] 
[1660]             charset[tables[t].src].tables = src;
[1661]         }
[1662] 
[1663]         dst = charset[tables[t].dst].tables;
[1664] 
[1665]         if (dst == NULL) {
[1666]             dst = ngx_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
[1667]             if (dst == NULL) {
[1668]                 return NGX_ERROR;
[1669]             }
[1670] 
[1671]             charset[tables[t].dst].tables = dst;
[1672]         }
[1673] 
[1674]         src[tables[t].dst] = tables[t].src2dst;
[1675]         dst[tables[t].src] = tables[t].dst2src;
[1676]     }
[1677] 
[1678]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[1679]     ngx_http_top_header_filter = ngx_http_charset_header_filter;
[1680] 
[1681]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[1682]     ngx_http_top_body_filter = ngx_http_charset_body_filter;
[1683] 
[1684]     return NGX_OK;
[1685] }
