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
[12] #include <libxml/parser.h>
[13] #include <libxml/tree.h>
[14] #include <libxslt/xslt.h>
[15] #include <libxslt/xsltInternals.h>
[16] #include <libxslt/transform.h>
[17] #include <libxslt/variables.h>
[18] #include <libxslt/xsltutils.h>
[19] 
[20] #if (NGX_HAVE_EXSLT)
[21] #include <libexslt/exslt.h>
[22] #endif
[23] 
[24] 
[25] #ifndef NGX_HTTP_XSLT_REUSE_DTD
[26] #define NGX_HTTP_XSLT_REUSE_DTD  1
[27] #endif
[28] 
[29] 
[30] typedef struct {
[31]     u_char                    *name;
[32]     void                      *data;
[33] } ngx_http_xslt_file_t;
[34] 
[35] 
[36] typedef struct {
[37]     ngx_array_t                dtd_files;    /* ngx_http_xslt_file_t */
[38]     ngx_array_t                sheet_files;  /* ngx_http_xslt_file_t */
[39] } ngx_http_xslt_filter_main_conf_t;
[40] 
[41] 
[42] typedef struct {
[43]     u_char                    *name;
[44]     ngx_http_complex_value_t   value;
[45]     ngx_uint_t                 quote;        /* unsigned  quote:1; */
[46] } ngx_http_xslt_param_t;
[47] 
[48] 
[49] typedef struct {
[50]     xsltStylesheetPtr          stylesheet;
[51]     ngx_array_t                params;       /* ngx_http_xslt_param_t */
[52] } ngx_http_xslt_sheet_t;
[53] 
[54] 
[55] typedef struct {
[56]     xmlDtdPtr                  dtd;
[57]     ngx_array_t                sheets;       /* ngx_http_xslt_sheet_t */
[58]     ngx_hash_t                 types;
[59]     ngx_array_t               *types_keys;
[60]     ngx_array_t               *params;       /* ngx_http_xslt_param_t */
[61]     ngx_flag_t                 last_modified;
[62] } ngx_http_xslt_filter_loc_conf_t;
[63] 
[64] 
[65] typedef struct {
[66]     xmlDocPtr                  doc;
[67]     xmlParserCtxtPtr           ctxt;
[68]     xsltTransformContextPtr    transform;
[69]     ngx_http_request_t        *request;
[70]     ngx_array_t                params;
[71] 
[72]     ngx_uint_t                 done;         /* unsigned  done:1; */
[73] } ngx_http_xslt_filter_ctx_t;
[74] 
[75] 
[76] static ngx_int_t ngx_http_xslt_send(ngx_http_request_t *r,
[77]     ngx_http_xslt_filter_ctx_t *ctx, ngx_buf_t *b);
[78] static ngx_int_t ngx_http_xslt_add_chunk(ngx_http_request_t *r,
[79]     ngx_http_xslt_filter_ctx_t *ctx, ngx_buf_t *b);
[80] 
[81] 
[82] static void ngx_http_xslt_sax_external_subset(void *data, const xmlChar *name,
[83]     const xmlChar *externalId, const xmlChar *systemId);
[84] static void ngx_cdecl ngx_http_xslt_sax_error(void *data, const char *msg, ...);
[85] 
[86] 
[87] static ngx_buf_t *ngx_http_xslt_apply_stylesheet(ngx_http_request_t *r,
[88]     ngx_http_xslt_filter_ctx_t *ctx);
[89] static ngx_int_t ngx_http_xslt_params(ngx_http_request_t *r,
[90]     ngx_http_xslt_filter_ctx_t *ctx, ngx_array_t *params, ngx_uint_t final);
[91] static u_char *ngx_http_xslt_content_type(xsltStylesheetPtr s);
[92] static u_char *ngx_http_xslt_encoding(xsltStylesheetPtr s);
[93] static void ngx_http_xslt_cleanup(void *data);
[94] 
[95] static char *ngx_http_xslt_entities(ngx_conf_t *cf, ngx_command_t *cmd,
[96]     void *conf);
[97] static char *ngx_http_xslt_stylesheet(ngx_conf_t *cf, ngx_command_t *cmd,
[98]     void *conf);
[99] static char *ngx_http_xslt_param(ngx_conf_t *cf, ngx_command_t *cmd,
[100]     void *conf);
[101] static void ngx_http_xslt_cleanup_dtd(void *data);
[102] static void ngx_http_xslt_cleanup_stylesheet(void *data);
[103] static void *ngx_http_xslt_filter_create_main_conf(ngx_conf_t *cf);
[104] static void *ngx_http_xslt_filter_create_conf(ngx_conf_t *cf);
[105] static char *ngx_http_xslt_filter_merge_conf(ngx_conf_t *cf, void *parent,
[106]     void *child);
[107] static ngx_int_t ngx_http_xslt_filter_preconfiguration(ngx_conf_t *cf);
[108] static ngx_int_t ngx_http_xslt_filter_init(ngx_conf_t *cf);
[109] static void ngx_http_xslt_filter_exit(ngx_cycle_t *cycle);
[110] 
[111] 
[112] static ngx_str_t  ngx_http_xslt_default_types[] = {
[113]     ngx_string("text/xml"),
[114]     ngx_null_string
[115] };
[116] 
[117] 
[118] static ngx_command_t  ngx_http_xslt_filter_commands[] = {
[119] 
[120]     { ngx_string("xml_entities"),
[121]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[122]       ngx_http_xslt_entities,
[123]       NGX_HTTP_LOC_CONF_OFFSET,
[124]       0,
[125]       NULL },
[126] 
[127]     { ngx_string("xslt_stylesheet"),
[128]       NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[129]       ngx_http_xslt_stylesheet,
[130]       NGX_HTTP_LOC_CONF_OFFSET,
[131]       0,
[132]       NULL },
[133] 
[134]     { ngx_string("xslt_param"),
[135]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[136]       ngx_http_xslt_param,
[137]       NGX_HTTP_LOC_CONF_OFFSET,
[138]       0,
[139]       NULL },
[140] 
[141]     { ngx_string("xslt_string_param"),
[142]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
[143]       ngx_http_xslt_param,
[144]       NGX_HTTP_LOC_CONF_OFFSET,
[145]       0,
[146]       (void *) 1 },
[147] 
[148]     { ngx_string("xslt_types"),
[149]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[150]       ngx_http_types_slot,
[151]       NGX_HTTP_LOC_CONF_OFFSET,
[152]       offsetof(ngx_http_xslt_filter_loc_conf_t, types_keys),
[153]       &ngx_http_xslt_default_types[0] },
[154] 
[155]     { ngx_string("xslt_last_modified"),
[156]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[157]       ngx_conf_set_flag_slot,
[158]       NGX_HTTP_LOC_CONF_OFFSET,
[159]       offsetof(ngx_http_xslt_filter_loc_conf_t, last_modified),
[160]       NULL },
[161] 
[162]       ngx_null_command
[163] };
[164] 
[165] 
[166] static ngx_http_module_t  ngx_http_xslt_filter_module_ctx = {
[167]     ngx_http_xslt_filter_preconfiguration, /* preconfiguration */
[168]     ngx_http_xslt_filter_init,             /* postconfiguration */
[169] 
[170]     ngx_http_xslt_filter_create_main_conf, /* create main configuration */
[171]     NULL,                                  /* init main configuration */
[172] 
[173]     NULL,                                  /* create server configuration */
[174]     NULL,                                  /* merge server configuration */
[175] 
[176]     ngx_http_xslt_filter_create_conf,      /* create location configuration */
[177]     ngx_http_xslt_filter_merge_conf        /* merge location configuration */
[178] };
[179] 
[180] 
[181] ngx_module_t  ngx_http_xslt_filter_module = {
[182]     NGX_MODULE_V1,
[183]     &ngx_http_xslt_filter_module_ctx,      /* module context */
[184]     ngx_http_xslt_filter_commands,         /* module directives */
[185]     NGX_HTTP_MODULE,                       /* module type */
[186]     NULL,                                  /* init master */
[187]     NULL,                                  /* init module */
[188]     NULL,                                  /* init process */
[189]     NULL,                                  /* init thread */
[190]     NULL,                                  /* exit thread */
[191]     ngx_http_xslt_filter_exit,             /* exit process */
[192]     ngx_http_xslt_filter_exit,             /* exit master */
[193]     NGX_MODULE_V1_PADDING
[194] };
[195] 
[196] 
[197] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[198] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[199] 
[200] 
[201] static ngx_int_t
[202] ngx_http_xslt_header_filter(ngx_http_request_t *r)
[203] {
[204]     ngx_http_xslt_filter_ctx_t       *ctx;
[205]     ngx_http_xslt_filter_loc_conf_t  *conf;
[206] 
[207]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[208]                    "xslt filter header");
[209] 
[210]     if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
[211]         return ngx_http_next_header_filter(r);
[212]     }
[213] 
[214]     conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);
[215] 
[216]     if (conf->sheets.nelts == 0
[217]         || ngx_http_test_content_type(r, &conf->types) == NULL)
[218]     {
[219]         return ngx_http_next_header_filter(r);
[220]     }
[221] 
[222]     ctx = ngx_http_get_module_ctx(r, ngx_http_xslt_filter_module);
[223] 
[224]     if (ctx) {
[225]         return ngx_http_next_header_filter(r);
[226]     }
[227] 
[228]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_xslt_filter_ctx_t));
[229]     if (ctx == NULL) {
[230]         return NGX_ERROR;
[231]     }
[232] 
[233]     ngx_http_set_ctx(r, ctx, ngx_http_xslt_filter_module);
[234] 
[235]     r->main_filter_need_in_memory = 1;
[236]     r->allow_ranges = 0;
[237] 
[238]     return NGX_OK;
[239] }
[240] 
[241] 
[242] static ngx_int_t
[243] ngx_http_xslt_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[244] {
[245]     int                          wellFormed;
[246]     ngx_chain_t                 *cl;
[247]     ngx_http_xslt_filter_ctx_t  *ctx;
[248] 
[249]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[250]                    "xslt filter body");
[251] 
[252]     if (in == NULL) {
[253]         return ngx_http_next_body_filter(r, in);
[254]     }
[255] 
[256]     ctx = ngx_http_get_module_ctx(r, ngx_http_xslt_filter_module);
[257] 
[258]     if (ctx == NULL || ctx->done) {
[259]         return ngx_http_next_body_filter(r, in);
[260]     }
[261] 
[262]     for (cl = in; cl; cl = cl->next) {
[263] 
[264]         if (ngx_http_xslt_add_chunk(r, ctx, cl->buf) != NGX_OK) {
[265] 
[266]             if (ctx->ctxt->myDoc) {
[267] 
[268] #if (NGX_HTTP_XSLT_REUSE_DTD)
[269]                 ctx->ctxt->myDoc->extSubset = NULL;
[270] #endif
[271]                 xmlFreeDoc(ctx->ctxt->myDoc);
[272]             }
[273] 
[274]             xmlFreeParserCtxt(ctx->ctxt);
[275] 
[276]             return ngx_http_xslt_send(r, ctx, NULL);
[277]         }
[278] 
[279]         if (cl->buf->last_buf || cl->buf->last_in_chain) {
[280] 
[281]             ctx->doc = ctx->ctxt->myDoc;
[282] 
[283] #if (NGX_HTTP_XSLT_REUSE_DTD)
[284]             ctx->doc->extSubset = NULL;
[285] #endif
[286] 
[287]             wellFormed = ctx->ctxt->wellFormed;
[288] 
[289]             xmlFreeParserCtxt(ctx->ctxt);
[290] 
[291]             if (wellFormed) {
[292]                 return ngx_http_xslt_send(r, ctx,
[293]                                        ngx_http_xslt_apply_stylesheet(r, ctx));
[294]             }
[295] 
[296]             xmlFreeDoc(ctx->doc);
[297] 
[298]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[299]                           "not well formed XML document");
[300] 
[301]             return ngx_http_xslt_send(r, ctx, NULL);
[302]         }
[303]     }
[304] 
[305]     return NGX_OK;
[306] }
[307] 
[308] 
[309] static ngx_int_t
[310] ngx_http_xslt_send(ngx_http_request_t *r, ngx_http_xslt_filter_ctx_t *ctx,
[311]     ngx_buf_t *b)
[312] {
[313]     ngx_int_t                         rc;
[314]     ngx_chain_t                       out;
[315]     ngx_pool_cleanup_t               *cln;
[316]     ngx_http_xslt_filter_loc_conf_t  *conf;
[317] 
[318]     ctx->done = 1;
[319] 
[320]     if (b == NULL) {
[321]         return ngx_http_filter_finalize_request(r, &ngx_http_xslt_filter_module,
[322]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[323]     }
[324] 
[325]     cln = ngx_pool_cleanup_add(r->pool, 0);
[326] 
[327]     if (cln == NULL) {
[328]         ngx_free(b->pos);
[329]         return ngx_http_filter_finalize_request(r, &ngx_http_xslt_filter_module,
[330]                                                NGX_HTTP_INTERNAL_SERVER_ERROR);
[331]     }
[332] 
[333]     if (r == r->main) {
[334]         r->headers_out.content_length_n = b->last - b->pos;
[335] 
[336]         if (r->headers_out.content_length) {
[337]             r->headers_out.content_length->hash = 0;
[338]             r->headers_out.content_length = NULL;
[339]         }
[340] 
[341]         conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);
[342] 
[343]         if (!conf->last_modified) {
[344]             ngx_http_clear_last_modified(r);
[345]             ngx_http_clear_etag(r);
[346] 
[347]         } else {
[348]             ngx_http_weak_etag(r);
[349]         }
[350]     }
[351] 
[352]     rc = ngx_http_next_header_filter(r);
[353] 
[354]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[355]         ngx_free(b->pos);
[356]         return rc;
[357]     }
[358] 
[359]     cln->handler = ngx_http_xslt_cleanup;
[360]     cln->data = b->pos;
[361] 
[362]     out.buf = b;
[363]     out.next = NULL;
[364] 
[365]     return ngx_http_next_body_filter(r, &out);
[366] }
[367] 
[368] 
[369] static ngx_int_t
[370] ngx_http_xslt_add_chunk(ngx_http_request_t *r, ngx_http_xslt_filter_ctx_t *ctx,
[371]     ngx_buf_t *b)
[372] {
[373]     int               err;
[374]     xmlParserCtxtPtr  ctxt;
[375] 
[376]     if (ctx->ctxt == NULL) {
[377] 
[378]         ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
[379]         if (ctxt == NULL) {
[380]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[381]                           "xmlCreatePushParserCtxt() failed");
[382]             return NGX_ERROR;
[383]         }
[384]         xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT|XML_PARSE_DTDLOAD
[385]                                                |XML_PARSE_NOWARNING);
[386] 
[387]         ctxt->sax->externalSubset = ngx_http_xslt_sax_external_subset;
[388]         ctxt->sax->setDocumentLocator = NULL;
[389]         ctxt->sax->error = ngx_http_xslt_sax_error;
[390]         ctxt->sax->fatalError = ngx_http_xslt_sax_error;
[391]         ctxt->sax->_private = ctx;
[392] 
[393]         ctx->ctxt = ctxt;
[394]         ctx->request = r;
[395]     }
[396] 
[397]     err = xmlParseChunk(ctx->ctxt, (char *) b->pos, (int) (b->last - b->pos),
[398]                         (b->last_buf) || (b->last_in_chain));
[399] 
[400]     if (err == 0) {
[401]         b->pos = b->last;
[402]         return NGX_OK;
[403]     }
[404] 
[405]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[406]                   "xmlParseChunk() failed, error:%d", err);
[407] 
[408]     return NGX_ERROR;
[409] }
[410] 
[411] 
[412] static void
[413] ngx_http_xslt_sax_external_subset(void *data, const xmlChar *name,
[414]     const xmlChar *externalId, const xmlChar *systemId)
[415] {
[416]     xmlParserCtxtPtr ctxt = data;
[417] 
[418]     xmlDocPtr                         doc;
[419]     xmlDtdPtr                         dtd;
[420]     ngx_http_request_t               *r;
[421]     ngx_http_xslt_filter_ctx_t       *ctx;
[422]     ngx_http_xslt_filter_loc_conf_t  *conf;
[423] 
[424]     ctx = ctxt->sax->_private;
[425]     r = ctx->request;
[426] 
[427]     conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);
[428] 
[429]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[430]                    "xslt filter extSubset: \"%s\" \"%s\" \"%s\"",
[431]                    name ? name : (xmlChar *) "",
[432]                    externalId ? externalId : (xmlChar *) "",
[433]                    systemId ? systemId : (xmlChar *) "");
[434] 
[435]     doc = ctxt->myDoc;
[436] 
[437] #if (NGX_HTTP_XSLT_REUSE_DTD)
[438] 
[439]     dtd = conf->dtd;
[440] 
[441] #else
[442] 
[443]     dtd = xmlCopyDtd(conf->dtd);
[444]     if (dtd == NULL) {
[445]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[446]                       "xmlCopyDtd() failed");
[447]         return;
[448]     }
[449] 
[450]     if (doc->children == NULL) {
[451]         xmlAddChild((xmlNodePtr) doc, (xmlNodePtr) dtd);
[452] 
[453]     } else {
[454]         xmlAddPrevSibling(doc->children, (xmlNodePtr) dtd);
[455]     }
[456] 
[457] #endif
[458] 
[459]     doc->extSubset = dtd;
[460] }
[461] 
[462] 
[463] static void ngx_cdecl
[464] ngx_http_xslt_sax_error(void *data, const char *msg, ...)
[465] {
[466]     xmlParserCtxtPtr ctxt = data;
[467] 
[468]     size_t                       n;
[469]     va_list                      args;
[470]     ngx_http_xslt_filter_ctx_t  *ctx;
[471]     u_char                       buf[NGX_MAX_ERROR_STR];
[472] 
[473]     ctx = ctxt->sax->_private;
[474] 
[475]     buf[0] = '\0';
[476] 
[477]     va_start(args, msg);
[478]     n = (size_t) vsnprintf((char *) buf, NGX_MAX_ERROR_STR, msg, args);
[479]     va_end(args);
[480] 
[481]     while (--n && (buf[n] == CR || buf[n] == LF)) { /* void */ }
[482] 
[483]     ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
[484]                   "libxml2 error: \"%*s\"", n + 1, buf);
[485] }
[486] 
[487] 
[488] static ngx_buf_t *
[489] ngx_http_xslt_apply_stylesheet(ngx_http_request_t *r,
[490]     ngx_http_xslt_filter_ctx_t *ctx)
[491] {
[492]     int                               len, rc, doc_type;
[493]     u_char                           *type, *encoding;
[494]     ngx_buf_t                        *b;
[495]     ngx_uint_t                        i;
[496]     xmlChar                          *buf;
[497]     xmlDocPtr                         doc, res;
[498]     ngx_http_xslt_sheet_t            *sheet;
[499]     ngx_http_xslt_filter_loc_conf_t  *conf;
[500] 
[501]     conf = ngx_http_get_module_loc_conf(r, ngx_http_xslt_filter_module);
[502]     sheet = conf->sheets.elts;
[503]     doc = ctx->doc;
[504] 
[505]     /* preallocate array for 4 params */
[506] 
[507]     if (ngx_array_init(&ctx->params, r->pool, 4 * 2 + 1, sizeof(char *))
[508]         != NGX_OK)
[509]     {
[510]         xmlFreeDoc(doc);
[511]         return NULL;
[512]     }
[513] 
[514]     for (i = 0; i < conf->sheets.nelts; i++) {
[515] 
[516]         ctx->transform = xsltNewTransformContext(sheet[i].stylesheet, doc);
[517]         if (ctx->transform == NULL) {
[518]             xmlFreeDoc(doc);
[519]             return NULL;
[520]         }
[521] 
[522]         if (conf->params
[523]             && ngx_http_xslt_params(r, ctx, conf->params, 0) != NGX_OK)
[524]         {
[525]             xsltFreeTransformContext(ctx->transform);
[526]             xmlFreeDoc(doc);
[527]             return NULL;
[528]         }
[529] 
[530]         if (ngx_http_xslt_params(r, ctx, &sheet[i].params, 1) != NGX_OK) {
[531]             xsltFreeTransformContext(ctx->transform);
[532]             xmlFreeDoc(doc);
[533]             return NULL;
[534]         }
[535] 
[536]         res = xsltApplyStylesheetUser(sheet[i].stylesheet, doc,
[537]                                       ctx->params.elts, NULL, NULL,
[538]                                       ctx->transform);
[539] 
[540]         xsltFreeTransformContext(ctx->transform);
[541]         xmlFreeDoc(doc);
[542] 
[543]         if (res == NULL) {
[544]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[545]                           "xsltApplyStylesheet() failed");
[546]             return NULL;
[547]         }
[548] 
[549]         doc = res;
[550] 
[551]         /* reset array elements */
[552]         ctx->params.nelts = 0;
[553]     }
[554] 
[555]     /* there must be at least one stylesheet */
[556] 
[557]     if (r == r->main) {
[558]         type = ngx_http_xslt_content_type(sheet[i - 1].stylesheet);
[559] 
[560]     } else {
[561]         type = NULL;
[562]     }
[563] 
[564]     encoding = ngx_http_xslt_encoding(sheet[i - 1].stylesheet);
[565]     doc_type = doc->type;
[566] 
[567]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[568]                    "xslt filter type: %d t:%s e:%s",
[569]                    doc_type, type ? type : (u_char *) "(null)",
[570]                    encoding ? encoding : (u_char *) "(null)");
[571] 
[572]     rc = xsltSaveResultToString(&buf, &len, doc, sheet[i - 1].stylesheet);
[573] 
[574]     xmlFreeDoc(doc);
[575] 
[576]     if (rc != 0) {
[577]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[578]                       "xsltSaveResultToString() failed");
[579]         return NULL;
[580]     }
[581] 
[582]     if (len == 0) {
[583]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[584]                       "xsltSaveResultToString() returned zero-length result");
[585]         return NULL;
[586]     }
[587] 
[588]     b = ngx_calloc_buf(r->pool);
[589]     if (b == NULL) {
[590]         ngx_free(buf);
[591]         return NULL;
[592]     }
[593] 
[594]     b->pos = buf;
[595]     b->last = buf + len;
[596]     b->memory = 1;
[597] 
[598]     if (encoding) {
[599]         r->headers_out.charset.len = ngx_strlen(encoding);
[600]         r->headers_out.charset.data = encoding;
[601]     }
[602] 
[603]     if (r != r->main) {
[604]         return b;
[605]     }
[606] 
[607]     b->last_buf = 1;
[608] 
[609]     if (type) {
[610]         len = ngx_strlen(type);
[611] 
[612]         r->headers_out.content_type_len = len;
[613]         r->headers_out.content_type.len = len;
[614]         r->headers_out.content_type.data = type;
[615] 
[616]     } else if (doc_type == XML_HTML_DOCUMENT_NODE) {
[617] 
[618]         r->headers_out.content_type_len = sizeof("text/html") - 1;
[619]         ngx_str_set(&r->headers_out.content_type, "text/html");
[620]     }
[621] 
[622]     r->headers_out.content_type_lowcase = NULL;
[623] 
[624]     return b;
[625] }
[626] 
[627] 
[628] static ngx_int_t
[629] ngx_http_xslt_params(ngx_http_request_t *r, ngx_http_xslt_filter_ctx_t *ctx,
[630]     ngx_array_t *params, ngx_uint_t final)
[631] {
[632]     u_char                 *p, *value, *dst, *src, **s;
[633]     size_t                  len;
[634]     ngx_uint_t              i;
[635]     ngx_str_t               string;
[636]     ngx_http_xslt_param_t  *param;
[637] 
[638]     param = params->elts;
[639] 
[640]     for (i = 0; i < params->nelts; i++) {
[641] 
[642]         if (ngx_http_complex_value(r, &param[i].value, &string) != NGX_OK) {
[643]             return NGX_ERROR;
[644]         }
[645] 
[646]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[647]                        "xslt filter param: \"%s\"", string.data);
[648] 
[649]         if (param[i].name) {
[650] 
[651]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[652]                            "xslt filter param name: \"%s\"", param[i].name);
[653] 
[654]             if (param[i].quote) {
[655]                 if (xsltQuoteOneUserParam(ctx->transform, param[i].name,
[656]                                           string.data)
[657]                     != 0)
[658]                 {
[659]                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[660]                                 "xsltQuoteOneUserParam(\"%s\", \"%s\") failed",
[661]                                 param[i].name, string.data);
[662]                     return NGX_ERROR;
[663]                 }
[664] 
[665]                 continue;
[666]             }
[667] 
[668]             s = ngx_array_push(&ctx->params);
[669]             if (s == NULL) {
[670]                 return NGX_ERROR;
[671]             }
[672] 
[673]             *s = param[i].name;
[674] 
[675]             s = ngx_array_push(&ctx->params);
[676]             if (s == NULL) {
[677]                 return NGX_ERROR;
[678]             }
[679] 
[680]             *s = string.data;
[681] 
[682]             continue;
[683]         }
[684] 
[685]         /*
[686]          * parse param1=value1:param2=value2 syntax as used by parameters
[687]          * specified in xslt_stylesheet directives
[688]          */
[689] 
[690]         if (param[i].value.lengths) {
[691]             p = string.data;
[692] 
[693]         } else {
[694]             p = ngx_pnalloc(r->pool, string.len + 1);
[695]             if (p == NULL) {
[696]                 return NGX_ERROR;
[697]             }
[698] 
[699]             ngx_memcpy(p, string.data, string.len + 1);
[700]         }
[701] 
[702]         while (p && *p) {
[703] 
[704]             value = p;
[705]             p = (u_char *) ngx_strchr(p, '=');
[706]             if (p == NULL) {
[707]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[708]                                 "invalid libxslt parameter \"%s\"", value);
[709]                 return NGX_ERROR;
[710]             }
[711]             *p++ = '\0';
[712] 
[713]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[714]                            "xslt filter param name: \"%s\"", value);
[715] 
[716]             s = ngx_array_push(&ctx->params);
[717]             if (s == NULL) {
[718]                 return NGX_ERROR;
[719]             }
[720] 
[721]             *s = value;
[722] 
[723]             value = p;
[724]             p = (u_char *) ngx_strchr(p, ':');
[725] 
[726]             if (p) {
[727]                 len = p - value;
[728]                 *p++ = '\0';
[729] 
[730]             } else {
[731]                 len = ngx_strlen(value);
[732]             }
[733] 
[734]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[735]                            "xslt filter param value: \"%s\"", value);
[736] 
[737]             dst = value;
[738]             src = value;
[739] 
[740]             ngx_unescape_uri(&dst, &src, len, 0);
[741] 
[742]             *dst = '\0';
[743] 
[744]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[745]                            "xslt filter param unescaped: \"%s\"", value);
[746] 
[747]             s = ngx_array_push(&ctx->params);
[748]             if (s == NULL) {
[749]                 return NGX_ERROR;
[750]             }
[751] 
[752]             *s = value;
[753]         }
[754]     }
[755] 
[756]     if (final) {
[757]         s = ngx_array_push(&ctx->params);
[758]         if (s == NULL) {
[759]             return NGX_ERROR;
[760]         }
[761] 
[762]         *s = NULL;
[763]     }
[764] 
[765]     return NGX_OK;
[766] }
[767] 
[768] 
[769] static u_char *
[770] ngx_http_xslt_content_type(xsltStylesheetPtr s)
[771] {
[772]     u_char  *type;
[773] 
[774]     if (s->mediaType) {
[775]         return s->mediaType;
[776]     }
[777] 
[778]     for (s = s->imports; s; s = s->next) {
[779] 
[780]         type = ngx_http_xslt_content_type(s);
[781] 
[782]         if (type) {
[783]             return type;
[784]         }
[785]     }
[786] 
[787]     return NULL;
[788] }
[789] 
[790] 
[791] static u_char *
[792] ngx_http_xslt_encoding(xsltStylesheetPtr s)
[793] {
[794]     u_char  *encoding;
[795] 
[796]     if (s->encoding) {
[797]         return s->encoding;
[798]     }
[799] 
[800]     for (s = s->imports; s; s = s->next) {
[801] 
[802]         encoding = ngx_http_xslt_encoding(s);
[803] 
[804]         if (encoding) {
[805]             return encoding;
[806]         }
[807]     }
[808] 
[809]     return NULL;
[810] }
[811] 
[812] 
[813] static void
[814] ngx_http_xslt_cleanup(void *data)
[815] {
[816]     ngx_free(data);
[817] }
[818] 
[819] 
[820] static char *
[821] ngx_http_xslt_entities(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[822] {
[823]     ngx_http_xslt_filter_loc_conf_t *xlcf = conf;
[824] 
[825]     ngx_str_t                         *value;
[826]     ngx_uint_t                         i;
[827]     ngx_pool_cleanup_t                *cln;
[828]     ngx_http_xslt_file_t              *file;
[829]     ngx_http_xslt_filter_main_conf_t  *xmcf;
[830] 
[831]     if (xlcf->dtd) {
[832]         return "is duplicate";
[833]     }
[834] 
[835]     value = cf->args->elts;
[836] 
[837]     xmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xslt_filter_module);
[838] 
[839]     file = xmcf->dtd_files.elts;
[840]     for (i = 0; i < xmcf->dtd_files.nelts; i++) {
[841]         if (ngx_strcmp(file[i].name, value[1].data) == 0) {
[842]             xlcf->dtd = file[i].data;
[843]             return NGX_CONF_OK;
[844]         }
[845]     }
[846] 
[847]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[848]     if (cln == NULL) {
[849]         return NGX_CONF_ERROR;
[850]     }
[851] 
[852]     xlcf->dtd = xmlParseDTD(NULL, (xmlChar *) value[1].data);
[853] 
[854]     if (xlcf->dtd == NULL) {
[855]         ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "xmlParseDTD() failed");
[856]         return NGX_CONF_ERROR;
[857]     }
[858] 
[859]     cln->handler = ngx_http_xslt_cleanup_dtd;
[860]     cln->data = xlcf->dtd;
[861] 
[862]     file = ngx_array_push(&xmcf->dtd_files);
[863]     if (file == NULL) {
[864]         return NGX_CONF_ERROR;
[865]     }
[866] 
[867]     file->name = value[1].data;
[868]     file->data = xlcf->dtd;
[869] 
[870]     return NGX_CONF_OK;
[871] }
[872] 
[873] 
[874] 
[875] static char *
[876] ngx_http_xslt_stylesheet(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[877] {
[878]     ngx_http_xslt_filter_loc_conf_t *xlcf = conf;
[879] 
[880]     ngx_str_t                         *value;
[881]     ngx_uint_t                         i, n;
[882]     ngx_pool_cleanup_t                *cln;
[883]     ngx_http_xslt_file_t              *file;
[884]     ngx_http_xslt_sheet_t             *sheet;
[885]     ngx_http_xslt_param_t             *param;
[886]     ngx_http_compile_complex_value_t   ccv;
[887]     ngx_http_xslt_filter_main_conf_t  *xmcf;
[888] 
[889]     value = cf->args->elts;
[890] 
[891]     if (xlcf->sheets.elts == NULL) {
[892]         if (ngx_array_init(&xlcf->sheets, cf->pool, 1,
[893]                            sizeof(ngx_http_xslt_sheet_t))
[894]             != NGX_OK)
[895]         {
[896]             return NGX_CONF_ERROR;
[897]         }
[898]     }
[899] 
[900]     sheet = ngx_array_push(&xlcf->sheets);
[901]     if (sheet == NULL) {
[902]         return NGX_CONF_ERROR;
[903]     }
[904] 
[905]     ngx_memzero(sheet, sizeof(ngx_http_xslt_sheet_t));
[906] 
[907]     if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
[908]         return NGX_CONF_ERROR;
[909]     }
[910] 
[911]     xmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_xslt_filter_module);
[912] 
[913]     file = xmcf->sheet_files.elts;
[914]     for (i = 0; i < xmcf->sheet_files.nelts; i++) {
[915]         if (ngx_strcmp(file[i].name, value[1].data) == 0) {
[916]             sheet->stylesheet = file[i].data;
[917]             goto found;
[918]         }
[919]     }
[920] 
[921]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[922]     if (cln == NULL) {
[923]         return NGX_CONF_ERROR;
[924]     }
[925] 
[926]     sheet->stylesheet = xsltParseStylesheetFile(value[1].data);
[927]     if (sheet->stylesheet == NULL) {
[928]         ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
[929]                            "xsltParseStylesheetFile(\"%s\") failed",
[930]                            value[1].data);
[931]         return NGX_CONF_ERROR;
[932]     }
[933] 
[934]     cln->handler = ngx_http_xslt_cleanup_stylesheet;
[935]     cln->data = sheet->stylesheet;
[936] 
[937]     file = ngx_array_push(&xmcf->sheet_files);
[938]     if (file == NULL) {
[939]         return NGX_CONF_ERROR;
[940]     }
[941] 
[942]     file->name = value[1].data;
[943]     file->data = sheet->stylesheet;
[944] 
[945] found:
[946] 
[947]     n = cf->args->nelts;
[948] 
[949]     if (n == 2) {
[950]         return NGX_CONF_OK;
[951]     }
[952] 
[953]     if (ngx_array_init(&sheet->params, cf->pool, n - 2,
[954]                        sizeof(ngx_http_xslt_param_t))
[955]         != NGX_OK)
[956]     {
[957]         return NGX_CONF_ERROR;
[958]     }
[959] 
[960]     for (i = 2; i < n; i++) {
[961] 
[962]         param = ngx_array_push(&sheet->params);
[963]         if (param == NULL) {
[964]             return NGX_CONF_ERROR;
[965]         }
[966] 
[967]         ngx_memzero(param, sizeof(ngx_http_xslt_param_t));
[968]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[969] 
[970]         ccv.cf = cf;
[971]         ccv.value = &value[i];
[972]         ccv.complex_value = &param->value;
[973]         ccv.zero = 1;
[974] 
[975]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[976]             return NGX_CONF_ERROR;
[977]         }
[978]     }
[979] 
[980]     return NGX_CONF_OK;
[981] }
[982] 
[983] 
[984] static char *
[985] ngx_http_xslt_param(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[986] {
[987]     ngx_http_xslt_filter_loc_conf_t  *xlcf = conf;
[988] 
[989]     ngx_http_xslt_param_t            *param;
[990]     ngx_http_compile_complex_value_t  ccv;
[991]     ngx_str_t                        *value;
[992] 
[993]     value = cf->args->elts;
[994] 
[995]     if (xlcf->params == NULL) {
[996]         xlcf->params = ngx_array_create(cf->pool, 2,
[997]                                         sizeof(ngx_http_xslt_param_t));
[998]         if (xlcf->params == NULL) {
[999]             return NGX_CONF_ERROR;
[1000]         }
[1001]     }
[1002] 
[1003]     param = ngx_array_push(xlcf->params);
[1004]     if (param == NULL) {
[1005]         return NGX_CONF_ERROR;
[1006]     }
[1007] 
[1008]     param->name = value[1].data;
[1009]     param->quote = (cmd->post == NULL) ? 0 : 1;
[1010] 
[1011]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1012] 
[1013]     ccv.cf = cf;
[1014]     ccv.value = &value[2];
[1015]     ccv.complex_value = &param->value;
[1016]     ccv.zero = 1;
[1017] 
[1018]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1019]         return NGX_CONF_ERROR;
[1020]     }
[1021] 
[1022]     return NGX_CONF_OK;
[1023] }
[1024] 
[1025] 
[1026] static void
[1027] ngx_http_xslt_cleanup_dtd(void *data)
[1028] {
[1029]     xmlFreeDtd(data);
[1030] }
[1031] 
[1032] 
[1033] static void
[1034] ngx_http_xslt_cleanup_stylesheet(void *data)
[1035] {
[1036]     xsltFreeStylesheet(data);
[1037] }
[1038] 
[1039] 
[1040] static void *
[1041] ngx_http_xslt_filter_create_main_conf(ngx_conf_t *cf)
[1042] {
[1043]     ngx_http_xslt_filter_main_conf_t  *conf;
[1044] 
[1045]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_xslt_filter_main_conf_t));
[1046]     if (conf == NULL) {
[1047]         return NULL;
[1048]     }
[1049] 
[1050]     if (ngx_array_init(&conf->dtd_files, cf->pool, 1,
[1051]                        sizeof(ngx_http_xslt_file_t))
[1052]         != NGX_OK)
[1053]     {
[1054]         return NULL;
[1055]     }
[1056] 
[1057]     if (ngx_array_init(&conf->sheet_files, cf->pool, 1,
[1058]                        sizeof(ngx_http_xslt_file_t))
[1059]         != NGX_OK)
[1060]     {
[1061]         return NULL;
[1062]     }
[1063] 
[1064]     return conf;
[1065] }
[1066] 
[1067] 
[1068] static void *
[1069] ngx_http_xslt_filter_create_conf(ngx_conf_t *cf)
[1070] {
[1071]     ngx_http_xslt_filter_loc_conf_t  *conf;
[1072] 
[1073]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_xslt_filter_loc_conf_t));
[1074]     if (conf == NULL) {
[1075]         return NULL;
[1076]     }
[1077] 
[1078]     /*
[1079]      * set by ngx_pcalloc():
[1080]      *
[1081]      *     conf->dtd = NULL;
[1082]      *     conf->sheets = { NULL };
[1083]      *     conf->types = { NULL };
[1084]      *     conf->types_keys = NULL;
[1085]      *     conf->params = NULL;
[1086]      */
[1087] 
[1088]     conf->last_modified = NGX_CONF_UNSET;
[1089] 
[1090]     return conf;
[1091] }
[1092] 
[1093] 
[1094] static char *
[1095] ngx_http_xslt_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[1096] {
[1097]     ngx_http_xslt_filter_loc_conf_t *prev = parent;
[1098]     ngx_http_xslt_filter_loc_conf_t *conf = child;
[1099] 
[1100]     if (conf->dtd == NULL) {
[1101]         conf->dtd = prev->dtd;
[1102]     }
[1103] 
[1104]     if (conf->sheets.nelts == 0) {
[1105]         conf->sheets = prev->sheets;
[1106]     }
[1107] 
[1108]     if (conf->params == NULL) {
[1109]         conf->params = prev->params;
[1110]     }
[1111] 
[1112]     if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
[1113]                              &prev->types_keys, &prev->types,
[1114]                              ngx_http_xslt_default_types)
[1115]         != NGX_OK)
[1116]     {
[1117]         return NGX_CONF_ERROR;
[1118]     }
[1119] 
[1120]     ngx_conf_merge_value(conf->last_modified, prev->last_modified, 0);
[1121] 
[1122]     return NGX_CONF_OK;
[1123] }
[1124] 
[1125] 
[1126] static ngx_int_t
[1127] ngx_http_xslt_filter_preconfiguration(ngx_conf_t *cf)
[1128] {
[1129]     xmlInitParser();
[1130] 
[1131] #if (NGX_HAVE_EXSLT)
[1132]     exsltRegisterAll();
[1133] #endif
[1134] 
[1135]     return NGX_OK;
[1136] }
[1137] 
[1138] 
[1139] static ngx_int_t
[1140] ngx_http_xslt_filter_init(ngx_conf_t *cf)
[1141] {
[1142]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[1143]     ngx_http_top_header_filter = ngx_http_xslt_header_filter;
[1144] 
[1145]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[1146]     ngx_http_top_body_filter = ngx_http_xslt_body_filter;
[1147] 
[1148]     return NGX_OK;
[1149] }
[1150] 
[1151] 
[1152] static void
[1153] ngx_http_xslt_filter_exit(ngx_cycle_t *cycle)
[1154] {
[1155]     xsltCleanupGlobals();
[1156]     xmlCleanupParser();
[1157] }
