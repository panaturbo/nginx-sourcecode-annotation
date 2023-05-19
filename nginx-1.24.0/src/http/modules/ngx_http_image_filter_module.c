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
[12] #include <gd.h>
[13] 
[14] 
[15] #define NGX_HTTP_IMAGE_OFF       0
[16] #define NGX_HTTP_IMAGE_TEST      1
[17] #define NGX_HTTP_IMAGE_SIZE      2
[18] #define NGX_HTTP_IMAGE_RESIZE    3
[19] #define NGX_HTTP_IMAGE_CROP      4
[20] #define NGX_HTTP_IMAGE_ROTATE    5
[21] 
[22] 
[23] #define NGX_HTTP_IMAGE_START     0
[24] #define NGX_HTTP_IMAGE_READ      1
[25] #define NGX_HTTP_IMAGE_PROCESS   2
[26] #define NGX_HTTP_IMAGE_PASS      3
[27] #define NGX_HTTP_IMAGE_DONE      4
[28] 
[29] 
[30] #define NGX_HTTP_IMAGE_NONE      0
[31] #define NGX_HTTP_IMAGE_JPEG      1
[32] #define NGX_HTTP_IMAGE_GIF       2
[33] #define NGX_HTTP_IMAGE_PNG       3
[34] #define NGX_HTTP_IMAGE_WEBP      4
[35] 
[36] 
[37] #define NGX_HTTP_IMAGE_BUFFERED  0x08
[38] 
[39] 
[40] typedef struct {
[41]     ngx_uint_t                   filter;
[42]     ngx_uint_t                   width;
[43]     ngx_uint_t                   height;
[44]     ngx_uint_t                   angle;
[45]     ngx_uint_t                   jpeg_quality;
[46]     ngx_uint_t                   webp_quality;
[47]     ngx_uint_t                   sharpen;
[48] 
[49]     ngx_flag_t                   transparency;
[50]     ngx_flag_t                   interlace;
[51] 
[52]     ngx_http_complex_value_t    *wcv;
[53]     ngx_http_complex_value_t    *hcv;
[54]     ngx_http_complex_value_t    *acv;
[55]     ngx_http_complex_value_t    *jqcv;
[56]     ngx_http_complex_value_t    *wqcv;
[57]     ngx_http_complex_value_t    *shcv;
[58] 
[59]     size_t                       buffer_size;
[60] } ngx_http_image_filter_conf_t;
[61] 
[62] 
[63] typedef struct {
[64]     u_char                      *image;
[65]     u_char                      *last;
[66] 
[67]     size_t                       length;
[68] 
[69]     ngx_uint_t                   width;
[70]     ngx_uint_t                   height;
[71]     ngx_uint_t                   max_width;
[72]     ngx_uint_t                   max_height;
[73]     ngx_uint_t                   angle;
[74] 
[75]     ngx_uint_t                   phase;
[76]     ngx_uint_t                   type;
[77]     ngx_uint_t                   force;
[78] } ngx_http_image_filter_ctx_t;
[79] 
[80] 
[81] static ngx_int_t ngx_http_image_send(ngx_http_request_t *r,
[82]     ngx_http_image_filter_ctx_t *ctx, ngx_chain_t *in);
[83] static ngx_uint_t ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in);
[84] static ngx_int_t ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in);
[85] static ngx_buf_t *ngx_http_image_process(ngx_http_request_t *r);
[86] static ngx_buf_t *ngx_http_image_json(ngx_http_request_t *r,
[87]     ngx_http_image_filter_ctx_t *ctx);
[88] static ngx_buf_t *ngx_http_image_asis(ngx_http_request_t *r,
[89]     ngx_http_image_filter_ctx_t *ctx);
[90] static void ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b);
[91] static ngx_int_t ngx_http_image_size(ngx_http_request_t *r,
[92]     ngx_http_image_filter_ctx_t *ctx);
[93] 
[94] static ngx_buf_t *ngx_http_image_resize(ngx_http_request_t *r,
[95]     ngx_http_image_filter_ctx_t *ctx);
[96] static gdImagePtr ngx_http_image_source(ngx_http_request_t *r,
[97]     ngx_http_image_filter_ctx_t *ctx);
[98] static gdImagePtr ngx_http_image_new(ngx_http_request_t *r, int w, int h,
[99]     int colors);
[100] static u_char *ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type,
[101]     gdImagePtr img, int *size);
[102] static void ngx_http_image_cleanup(void *data);
[103] static ngx_uint_t ngx_http_image_filter_get_value(ngx_http_request_t *r,
[104]     ngx_http_complex_value_t *cv, ngx_uint_t v);
[105] static ngx_uint_t ngx_http_image_filter_value(ngx_str_t *value);
[106] 
[107] 
[108] static void *ngx_http_image_filter_create_conf(ngx_conf_t *cf);
[109] static char *ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent,
[110]     void *child);
[111] static char *ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd,
[112]     void *conf);
[113] static char *ngx_http_image_filter_jpeg_quality(ngx_conf_t *cf,
[114]     ngx_command_t *cmd, void *conf);
[115] static char *ngx_http_image_filter_webp_quality(ngx_conf_t *cf,
[116]     ngx_command_t *cmd, void *conf);
[117] static char *ngx_http_image_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd,
[118]     void *conf);
[119] static ngx_int_t ngx_http_image_filter_init(ngx_conf_t *cf);
[120] 
[121] 
[122] static ngx_command_t  ngx_http_image_filter_commands[] = {
[123] 
[124]     { ngx_string("image_filter"),
[125]       NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[126]       ngx_http_image_filter,
[127]       NGX_HTTP_LOC_CONF_OFFSET,
[128]       0,
[129]       NULL },
[130] 
[131]     { ngx_string("image_filter_jpeg_quality"),
[132]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[133]       ngx_http_image_filter_jpeg_quality,
[134]       NGX_HTTP_LOC_CONF_OFFSET,
[135]       0,
[136]       NULL },
[137] 
[138]     { ngx_string("image_filter_webp_quality"),
[139]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[140]       ngx_http_image_filter_webp_quality,
[141]       NGX_HTTP_LOC_CONF_OFFSET,
[142]       0,
[143]       NULL },
[144] 
[145]     { ngx_string("image_filter_sharpen"),
[146]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[147]       ngx_http_image_filter_sharpen,
[148]       NGX_HTTP_LOC_CONF_OFFSET,
[149]       0,
[150]       NULL },
[151] 
[152]     { ngx_string("image_filter_transparency"),
[153]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[154]       ngx_conf_set_flag_slot,
[155]       NGX_HTTP_LOC_CONF_OFFSET,
[156]       offsetof(ngx_http_image_filter_conf_t, transparency),
[157]       NULL },
[158] 
[159]     { ngx_string("image_filter_interlace"),
[160]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[161]       ngx_conf_set_flag_slot,
[162]       NGX_HTTP_LOC_CONF_OFFSET,
[163]       offsetof(ngx_http_image_filter_conf_t, interlace),
[164]       NULL },
[165] 
[166]     { ngx_string("image_filter_buffer"),
[167]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[168]       ngx_conf_set_size_slot,
[169]       NGX_HTTP_LOC_CONF_OFFSET,
[170]       offsetof(ngx_http_image_filter_conf_t, buffer_size),
[171]       NULL },
[172] 
[173]       ngx_null_command
[174] };
[175] 
[176] 
[177] static ngx_http_module_t  ngx_http_image_filter_module_ctx = {
[178]     NULL,                                  /* preconfiguration */
[179]     ngx_http_image_filter_init,            /* postconfiguration */
[180] 
[181]     NULL,                                  /* create main configuration */
[182]     NULL,                                  /* init main configuration */
[183] 
[184]     NULL,                                  /* create server configuration */
[185]     NULL,                                  /* merge server configuration */
[186] 
[187]     ngx_http_image_filter_create_conf,     /* create location configuration */
[188]     ngx_http_image_filter_merge_conf       /* merge location configuration */
[189] };
[190] 
[191] 
[192] ngx_module_t  ngx_http_image_filter_module = {
[193]     NGX_MODULE_V1,
[194]     &ngx_http_image_filter_module_ctx,     /* module context */
[195]     ngx_http_image_filter_commands,        /* module directives */
[196]     NGX_HTTP_MODULE,                       /* module type */
[197]     NULL,                                  /* init master */
[198]     NULL,                                  /* init module */
[199]     NULL,                                  /* init process */
[200]     NULL,                                  /* init thread */
[201]     NULL,                                  /* exit thread */
[202]     NULL,                                  /* exit process */
[203]     NULL,                                  /* exit master */
[204]     NGX_MODULE_V1_PADDING
[205] };
[206] 
[207] 
[208] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[209] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[210] 
[211] 
[212] static ngx_str_t  ngx_http_image_types[] = {
[213]     ngx_string("image/jpeg"),
[214]     ngx_string("image/gif"),
[215]     ngx_string("image/png"),
[216]     ngx_string("image/webp")
[217] };
[218] 
[219] 
[220] static ngx_int_t
[221] ngx_http_image_header_filter(ngx_http_request_t *r)
[222] {
[223]     off_t                          len;
[224]     ngx_http_image_filter_ctx_t   *ctx;
[225]     ngx_http_image_filter_conf_t  *conf;
[226] 
[227]     if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
[228]         return ngx_http_next_header_filter(r);
[229]     }
[230] 
[231]     ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);
[232] 
[233]     if (ctx) {
[234]         ngx_http_set_ctx(r, NULL, ngx_http_image_filter_module);
[235]         return ngx_http_next_header_filter(r);
[236]     }
[237] 
[238]     conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
[239] 
[240]     if (conf->filter == NGX_HTTP_IMAGE_OFF) {
[241]         return ngx_http_next_header_filter(r);
[242]     }
[243] 
[244]     if (r->headers_out.content_type.len
[245]             >= sizeof("multipart/x-mixed-replace") - 1
[246]         && ngx_strncasecmp(r->headers_out.content_type.data,
[247]                            (u_char *) "multipart/x-mixed-replace",
[248]                            sizeof("multipart/x-mixed-replace") - 1)
[249]            == 0)
[250]     {
[251]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[252]                       "image filter: multipart/x-mixed-replace response");
[253] 
[254]         return NGX_ERROR;
[255]     }
[256] 
[257]     ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_image_filter_ctx_t));
[258]     if (ctx == NULL) {
[259]         return NGX_ERROR;
[260]     }
[261] 
[262]     ngx_http_set_ctx(r, ctx, ngx_http_image_filter_module);
[263] 
[264]     len = r->headers_out.content_length_n;
[265] 
[266]     if (len != -1 && len > (off_t) conf->buffer_size) {
[267]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[268]                       "image filter: too big response: %O", len);
[269] 
[270]         return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
[271]     }
[272] 
[273]     if (len == -1) {
[274]         ctx->length = conf->buffer_size;
[275] 
[276]     } else {
[277]         ctx->length = (size_t) len;
[278]     }
[279] 
[280]     if (r->headers_out.refresh) {
[281]         r->headers_out.refresh->hash = 0;
[282]     }
[283] 
[284]     r->main_filter_need_in_memory = 1;
[285]     r->allow_ranges = 0;
[286] 
[287]     return NGX_OK;
[288] }
[289] 
[290] 
[291] static ngx_int_t
[292] ngx_http_image_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
[293] {
[294]     ngx_int_t                      rc;
[295]     ngx_str_t                     *ct;
[296]     ngx_chain_t                    out;
[297]     ngx_http_image_filter_ctx_t   *ctx;
[298]     ngx_http_image_filter_conf_t  *conf;
[299] 
[300]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");
[301] 
[302]     if (in == NULL) {
[303]         return ngx_http_next_body_filter(r, in);
[304]     }
[305] 
[306]     ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);
[307] 
[308]     if (ctx == NULL) {
[309]         return ngx_http_next_body_filter(r, in);
[310]     }
[311] 
[312]     switch (ctx->phase) {
[313] 
[314]     case NGX_HTTP_IMAGE_START:
[315] 
[316]         ctx->type = ngx_http_image_test(r, in);
[317] 
[318]         conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
[319] 
[320]         if (ctx->type == NGX_HTTP_IMAGE_NONE) {
[321] 
[322]             if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
[323]                 out.buf = ngx_http_image_json(r, NULL);
[324] 
[325]                 if (out.buf) {
[326]                     out.next = NULL;
[327]                     ctx->phase = NGX_HTTP_IMAGE_DONE;
[328] 
[329]                     return ngx_http_image_send(r, ctx, &out);
[330]                 }
[331]             }
[332] 
[333]             return ngx_http_filter_finalize_request(r,
[334]                                               &ngx_http_image_filter_module,
[335]                                               NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
[336]         }
[337] 
[338]         /* override content type */
[339] 
[340]         ct = &ngx_http_image_types[ctx->type - 1];
[341]         r->headers_out.content_type_len = ct->len;
[342]         r->headers_out.content_type = *ct;
[343]         r->headers_out.content_type_lowcase = NULL;
[344] 
[345]         if (conf->filter == NGX_HTTP_IMAGE_TEST) {
[346]             ctx->phase = NGX_HTTP_IMAGE_PASS;
[347] 
[348]             return ngx_http_image_send(r, ctx, in);
[349]         }
[350] 
[351]         ctx->phase = NGX_HTTP_IMAGE_READ;
[352] 
[353]         /* fall through */
[354] 
[355]     case NGX_HTTP_IMAGE_READ:
[356] 
[357]         rc = ngx_http_image_read(r, in);
[358] 
[359]         if (rc == NGX_AGAIN) {
[360]             return NGX_OK;
[361]         }
[362] 
[363]         if (rc == NGX_ERROR) {
[364]             return ngx_http_filter_finalize_request(r,
[365]                                               &ngx_http_image_filter_module,
[366]                                               NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
[367]         }
[368] 
[369]         /* fall through */
[370] 
[371]     case NGX_HTTP_IMAGE_PROCESS:
[372] 
[373]         out.buf = ngx_http_image_process(r);
[374] 
[375]         if (out.buf == NULL) {
[376]             return ngx_http_filter_finalize_request(r,
[377]                                               &ngx_http_image_filter_module,
[378]                                               NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
[379]         }
[380] 
[381]         out.next = NULL;
[382]         ctx->phase = NGX_HTTP_IMAGE_PASS;
[383] 
[384]         return ngx_http_image_send(r, ctx, &out);
[385] 
[386]     case NGX_HTTP_IMAGE_PASS:
[387] 
[388]         return ngx_http_next_body_filter(r, in);
[389] 
[390]     default: /* NGX_HTTP_IMAGE_DONE */
[391] 
[392]         rc = ngx_http_next_body_filter(r, NULL);
[393] 
[394]         /* NGX_ERROR resets any pending data */
[395]         return (rc == NGX_OK) ? NGX_ERROR : rc;
[396]     }
[397] }
[398] 
[399] 
[400] static ngx_int_t
[401] ngx_http_image_send(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx,
[402]     ngx_chain_t *in)
[403] {
[404]     ngx_int_t  rc;
[405] 
[406]     rc = ngx_http_next_header_filter(r);
[407] 
[408]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[409]         return NGX_ERROR;
[410]     }
[411] 
[412]     rc = ngx_http_next_body_filter(r, in);
[413] 
[414]     if (ctx->phase == NGX_HTTP_IMAGE_DONE) {
[415]         /* NGX_ERROR resets any pending data */
[416]         return (rc == NGX_OK) ? NGX_ERROR : rc;
[417]     }
[418] 
[419]     return rc;
[420] }
[421] 
[422] 
[423] static ngx_uint_t
[424] ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in)
[425] {
[426]     u_char  *p;
[427] 
[428]     p = in->buf->pos;
[429] 
[430]     if (in->buf->last - p < 16) {
[431]         return NGX_HTTP_IMAGE_NONE;
[432]     }
[433] 
[434]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[435]                    "image filter: \"%c%c\"", p[0], p[1]);
[436] 
[437]     if (p[0] == 0xff && p[1] == 0xd8) {
[438] 
[439]         /* JPEG */
[440] 
[441]         return NGX_HTTP_IMAGE_JPEG;
[442] 
[443]     } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
[444]                && p[5] == 'a')
[445]     {
[446]         if (p[4] == '9' || p[4] == '7') {
[447]             /* GIF */
[448]             return NGX_HTTP_IMAGE_GIF;
[449]         }
[450] 
[451]     } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
[452]                && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
[453]     {
[454]         /* PNG */
[455] 
[456]         return NGX_HTTP_IMAGE_PNG;
[457] 
[458]     } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F'
[459]                && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P')
[460]     {
[461]         /* WebP */
[462] 
[463]         return NGX_HTTP_IMAGE_WEBP;
[464]     }
[465] 
[466]     return NGX_HTTP_IMAGE_NONE;
[467] }
[468] 
[469] 
[470] static ngx_int_t
[471] ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in)
[472] {
[473]     u_char                       *p;
[474]     size_t                        size, rest;
[475]     ngx_buf_t                    *b;
[476]     ngx_chain_t                  *cl;
[477]     ngx_http_image_filter_ctx_t  *ctx;
[478] 
[479]     ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);
[480] 
[481]     if (ctx->image == NULL) {
[482]         ctx->image = ngx_palloc(r->pool, ctx->length);
[483]         if (ctx->image == NULL) {
[484]             return NGX_ERROR;
[485]         }
[486] 
[487]         ctx->last = ctx->image;
[488]     }
[489] 
[490]     p = ctx->last;
[491] 
[492]     for (cl = in; cl; cl = cl->next) {
[493] 
[494]         b = cl->buf;
[495]         size = b->last - b->pos;
[496] 
[497]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[498]                        "image buf: %uz", size);
[499] 
[500]         rest = ctx->image + ctx->length - p;
[501] 
[502]         if (size > rest) {
[503]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[504]                           "image filter: too big response");
[505]             return NGX_ERROR;
[506]         }
[507] 
[508]         p = ngx_cpymem(p, b->pos, size);
[509]         b->pos += size;
[510] 
[511]         if (b->last_buf) {
[512]             ctx->last = p;
[513]             return NGX_OK;
[514]         }
[515]     }
[516] 
[517]     ctx->last = p;
[518]     r->connection->buffered |= NGX_HTTP_IMAGE_BUFFERED;
[519] 
[520]     return NGX_AGAIN;
[521] }
[522] 
[523] 
[524] static ngx_buf_t *
[525] ngx_http_image_process(ngx_http_request_t *r)
[526] {
[527]     ngx_int_t                      rc;
[528]     ngx_http_image_filter_ctx_t   *ctx;
[529]     ngx_http_image_filter_conf_t  *conf;
[530] 
[531]     r->connection->buffered &= ~NGX_HTTP_IMAGE_BUFFERED;
[532] 
[533]     ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);
[534] 
[535]     rc = ngx_http_image_size(r, ctx);
[536] 
[537]     conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
[538] 
[539]     if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
[540]         return ngx_http_image_json(r, rc == NGX_OK ? ctx : NULL);
[541]     }
[542] 
[543]     ctx->angle = ngx_http_image_filter_get_value(r, conf->acv, conf->angle);
[544] 
[545]     if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {
[546] 
[547]         if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
[548]             return NULL;
[549]         }
[550] 
[551]         return ngx_http_image_resize(r, ctx);
[552]     }
[553] 
[554]     ctx->max_width = ngx_http_image_filter_get_value(r, conf->wcv, conf->width);
[555]     if (ctx->max_width == 0) {
[556]         return NULL;
[557]     }
[558] 
[559]     ctx->max_height = ngx_http_image_filter_get_value(r, conf->hcv,
[560]                                                       conf->height);
[561]     if (ctx->max_height == 0) {
[562]         return NULL;
[563]     }
[564] 
[565]     if (rc == NGX_OK
[566]         && ctx->width <= ctx->max_width
[567]         && ctx->height <= ctx->max_height
[568]         && ctx->angle == 0
[569]         && !ctx->force)
[570]     {
[571]         return ngx_http_image_asis(r, ctx);
[572]     }
[573] 
[574]     return ngx_http_image_resize(r, ctx);
[575] }
[576] 
[577] 
[578] static ngx_buf_t *
[579] ngx_http_image_json(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
[580] {
[581]     size_t      len;
[582]     ngx_buf_t  *b;
[583] 
[584]     b = ngx_calloc_buf(r->pool);
[585]     if (b == NULL) {
[586]         return NULL;
[587]     }
[588] 
[589]     b->memory = 1;
[590]     b->last_buf = 1;
[591] 
[592]     ngx_http_clean_header(r);
[593] 
[594]     r->headers_out.status = NGX_HTTP_OK;
[595]     r->headers_out.content_type_len = sizeof("application/json") - 1;
[596]     ngx_str_set(&r->headers_out.content_type, "application/json");
[597]     r->headers_out.content_type_lowcase = NULL;
[598] 
[599]     if (ctx == NULL) {
[600]         b->pos = (u_char *) "{}" CRLF;
[601]         b->last = b->pos + sizeof("{}" CRLF) - 1;
[602] 
[603]         ngx_http_image_length(r, b);
[604] 
[605]         return b;
[606]     }
[607] 
[608]     len = sizeof("{ \"img\" : "
[609]                  "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
[610]           + 2 * NGX_SIZE_T_LEN;
[611] 
[612]     b->pos = ngx_pnalloc(r->pool, len);
[613]     if (b->pos == NULL) {
[614]         return NULL;
[615]     }
[616] 
[617]     b->last = ngx_sprintf(b->pos,
[618]                           "{ \"img\" : "
[619]                                        "{ \"width\": %uz,"
[620]                                         " \"height\": %uz,"
[621]                                         " \"type\": \"%s\" } }" CRLF,
[622]                           ctx->width, ctx->height,
[623]                           ngx_http_image_types[ctx->type - 1].data + 6);
[624] 
[625]     ngx_http_image_length(r, b);
[626] 
[627]     return b;
[628] }
[629] 
[630] 
[631] static ngx_buf_t *
[632] ngx_http_image_asis(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
[633] {
[634]     ngx_buf_t  *b;
[635] 
[636]     b = ngx_calloc_buf(r->pool);
[637]     if (b == NULL) {
[638]         return NULL;
[639]     }
[640] 
[641]     b->pos = ctx->image;
[642]     b->last = ctx->last;
[643]     b->memory = 1;
[644]     b->last_buf = 1;
[645] 
[646]     ngx_http_image_length(r, b);
[647] 
[648]     return b;
[649] }
[650] 
[651] 
[652] static void
[653] ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b)
[654] {
[655]     r->headers_out.content_length_n = b->last - b->pos;
[656] 
[657]     if (r->headers_out.content_length) {
[658]         r->headers_out.content_length->hash = 0;
[659]     }
[660] 
[661]     r->headers_out.content_length = NULL;
[662] }
[663] 
[664] 
[665] static ngx_int_t
[666] ngx_http_image_size(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
[667] {
[668]     u_char      *p, *last;
[669]     size_t       len, app;
[670]     ngx_uint_t   width, height;
[671] 
[672]     p = ctx->image;
[673] 
[674]     switch (ctx->type) {
[675] 
[676]     case NGX_HTTP_IMAGE_JPEG:
[677] 
[678]         p += 2;
[679]         last = ctx->image + ctx->length - 10;
[680]         width = 0;
[681]         height = 0;
[682]         app = 0;
[683] 
[684]         while (p < last) {
[685] 
[686]             if (p[0] == 0xff && p[1] != 0xff) {
[687] 
[688]                 ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[689]                                "JPEG: %02xd %02xd", p[0], p[1]);
[690] 
[691]                 p++;
[692] 
[693]                 if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
[694]                      || *p == 0xc9 || *p == 0xca || *p == 0xcb)
[695]                     && (width == 0 || height == 0))
[696]                 {
[697]                     width = p[6] * 256 + p[7];
[698]                     height = p[4] * 256 + p[5];
[699]                 }
[700] 
[701]                 ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[702]                                "JPEG: %02xd %02xd", p[1], p[2]);
[703] 
[704]                 len = p[1] * 256 + p[2];
[705] 
[706]                 if (*p >= 0xe1 && *p <= 0xef) {
[707]                     /* application data, e.g., EXIF, Adobe XMP, etc. */
[708]                     app += len;
[709]                 }
[710] 
[711]                 p += len;
[712] 
[713]                 continue;
[714]             }
[715] 
[716]             p++;
[717]         }
[718] 
[719]         if (width == 0 || height == 0) {
[720]             return NGX_DECLINED;
[721]         }
[722] 
[723]         if (ctx->length / 20 < app) {
[724]             /* force conversion if application data consume more than 5% */
[725]             ctx->force = 1;
[726]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[727]                            "app data size: %uz", app);
[728]         }
[729] 
[730]         break;
[731] 
[732]     case NGX_HTTP_IMAGE_GIF:
[733] 
[734]         if (ctx->length < 10) {
[735]             return NGX_DECLINED;
[736]         }
[737] 
[738]         width = p[7] * 256 + p[6];
[739]         height = p[9] * 256 + p[8];
[740] 
[741]         break;
[742] 
[743]     case NGX_HTTP_IMAGE_PNG:
[744] 
[745]         if (ctx->length < 24) {
[746]             return NGX_DECLINED;
[747]         }
[748] 
[749]         width = p[18] * 256 + p[19];
[750]         height = p[22] * 256 + p[23];
[751] 
[752]         break;
[753] 
[754]     case NGX_HTTP_IMAGE_WEBP:
[755] 
[756]         if (ctx->length < 30) {
[757]             return NGX_DECLINED;
[758]         }
[759] 
[760]         if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
[761]             return NGX_DECLINED;
[762]         }
[763] 
[764]         switch (p[15]) {
[765] 
[766]         case ' ':
[767]             if (p[20] & 1) {
[768]                 /* not a key frame */
[769]                 return NGX_DECLINED;
[770]             }
[771] 
[772]             if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
[773]                 /* invalid start code */
[774]                 return NGX_DECLINED;
[775]             }
[776] 
[777]             width = (p[26] | p[27] << 8) & 0x3fff;
[778]             height = (p[28] | p[29] << 8) & 0x3fff;
[779] 
[780]             break;
[781] 
[782]         case 'L':
[783]             if (p[20] != 0x2f) {
[784]                 /* invalid signature */
[785]                 return NGX_DECLINED;
[786]             }
[787] 
[788]             width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
[789]             height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;
[790] 
[791]             break;
[792] 
[793]         case 'X':
[794]             width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
[795]             height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
[796]             break;
[797] 
[798]         default:
[799]             return NGX_DECLINED;
[800]         }
[801] 
[802]         break;
[803] 
[804]     default:
[805] 
[806]         return NGX_DECLINED;
[807]     }
[808] 
[809]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[810]                    "image size: %d x %d", (int) width, (int) height);
[811] 
[812]     ctx->width = width;
[813]     ctx->height = height;
[814] 
[815]     return NGX_OK;
[816] }
[817] 
[818] 
[819] static ngx_buf_t *
[820] ngx_http_image_resize(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
[821] {
[822]     int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
[823]                                    colors, palette, transparent, sharpen,
[824]                                    red, green, blue, t;
[825]     u_char                        *out;
[826]     ngx_buf_t                     *b;
[827]     ngx_uint_t                     resize;
[828]     gdImagePtr                     src, dst;
[829]     ngx_pool_cleanup_t            *cln;
[830]     ngx_http_image_filter_conf_t  *conf;
[831] 
[832]     src = ngx_http_image_source(r, ctx);
[833] 
[834]     if (src == NULL) {
[835]         return NULL;
[836]     }
[837] 
[838]     sx = gdImageSX(src);
[839]     sy = gdImageSY(src);
[840] 
[841]     conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
[842] 
[843]     if (!ctx->force
[844]         && ctx->angle == 0
[845]         && (ngx_uint_t) sx <= ctx->max_width
[846]         && (ngx_uint_t) sy <= ctx->max_height)
[847]     {
[848]         gdImageDestroy(src);
[849]         return ngx_http_image_asis(r, ctx);
[850]     }
[851] 
[852]     colors = gdImageColorsTotal(src);
[853] 
[854]     if (colors && conf->transparency) {
[855]         transparent = gdImageGetTransparent(src);
[856] 
[857]         if (transparent != -1) {
[858]             palette = colors;
[859]             red = gdImageRed(src, transparent);
[860]             green = gdImageGreen(src, transparent);
[861]             blue = gdImageBlue(src, transparent);
[862] 
[863]             goto transparent;
[864]         }
[865]     }
[866] 
[867]     palette = 0;
[868]     transparent = -1;
[869]     red = 0;
[870]     green = 0;
[871]     blue = 0;
[872] 
[873] transparent:
[874] 
[875]     gdImageColorTransparent(src, -1);
[876] 
[877]     dx = sx;
[878]     dy = sy;
[879] 
[880]     if (conf->filter == NGX_HTTP_IMAGE_RESIZE) {
[881] 
[882]         if ((ngx_uint_t) dx > ctx->max_width) {
[883]             dy = dy * ctx->max_width / dx;
[884]             dy = dy ? dy : 1;
[885]             dx = ctx->max_width;
[886]         }
[887] 
[888]         if ((ngx_uint_t) dy > ctx->max_height) {
[889]             dx = dx * ctx->max_height / dy;
[890]             dx = dx ? dx : 1;
[891]             dy = ctx->max_height;
[892]         }
[893] 
[894]         resize = 1;
[895] 
[896]     } else if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {
[897] 
[898]         resize = 0;
[899] 
[900]     } else { /* NGX_HTTP_IMAGE_CROP */
[901] 
[902]         resize = 0;
[903] 
[904]         if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
[905]             if ((ngx_uint_t) dx > ctx->max_width) {
[906]                 dy = dy * ctx->max_width / dx;
[907]                 dy = dy ? dy : 1;
[908]                 dx = ctx->max_width;
[909]                 resize = 1;
[910]             }
[911] 
[912]         } else {
[913]             if ((ngx_uint_t) dy > ctx->max_height) {
[914]                 dx = dx * ctx->max_height / dy;
[915]                 dx = dx ? dx : 1;
[916]                 dy = ctx->max_height;
[917]                 resize = 1;
[918]             }
[919]         }
[920]     }
[921] 
[922]     if (resize) {
[923]         dst = ngx_http_image_new(r, dx, dy, palette);
[924]         if (dst == NULL) {
[925]             gdImageDestroy(src);
[926]             return NULL;
[927]         }
[928] 
[929]         if (colors == 0) {
[930]             gdImageSaveAlpha(dst, 1);
[931]             gdImageAlphaBlending(dst, 0);
[932]         }
[933] 
[934]         gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);
[935] 
[936]         if (colors) {
[937]             gdImageTrueColorToPalette(dst, 1, 256);
[938]         }
[939] 
[940]         gdImageDestroy(src);
[941] 
[942]     } else {
[943]         dst = src;
[944]     }
[945] 
[946]     if (ctx->angle) {
[947]         src = dst;
[948] 
[949]         ax = (dx % 2 == 0) ? 1 : 0;
[950]         ay = (dy % 2 == 0) ? 1 : 0;
[951] 
[952]         switch (ctx->angle) {
[953] 
[954]         case 90:
[955]         case 270:
[956]             dst = ngx_http_image_new(r, dy, dx, palette);
[957]             if (dst == NULL) {
[958]                 gdImageDestroy(src);
[959]                 return NULL;
[960]             }
[961]             if (ctx->angle == 90) {
[962]                 ox = dy / 2 + ay;
[963]                 oy = dx / 2 - ax;
[964] 
[965]             } else {
[966]                 ox = dy / 2 - ay;
[967]                 oy = dx / 2 + ax;
[968]             }
[969] 
[970]             gdImageCopyRotated(dst, src, ox, oy, 0, 0,
[971]                                dx + ax, dy + ay, ctx->angle);
[972]             gdImageDestroy(src);
[973] 
[974]             t = dx;
[975]             dx = dy;
[976]             dy = t;
[977]             break;
[978] 
[979]         case 180:
[980]             dst = ngx_http_image_new(r, dx, dy, palette);
[981]             if (dst == NULL) {
[982]                 gdImageDestroy(src);
[983]                 return NULL;
[984]             }
[985]             gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
[986]                                dx + ax, dy + ay, ctx->angle);
[987]             gdImageDestroy(src);
[988]             break;
[989]         }
[990]     }
[991] 
[992]     if (conf->filter == NGX_HTTP_IMAGE_CROP) {
[993] 
[994]         src = dst;
[995] 
[996]         if ((ngx_uint_t) dx > ctx->max_width) {
[997]             ox = dx - ctx->max_width;
[998] 
[999]         } else {
[1000]             ox = 0;
[1001]         }
[1002] 
[1003]         if ((ngx_uint_t) dy > ctx->max_height) {
[1004]             oy = dy - ctx->max_height;
[1005] 
[1006]         } else {
[1007]             oy = 0;
[1008]         }
[1009] 
[1010]         if (ox || oy) {
[1011] 
[1012]             dst = ngx_http_image_new(r, dx - ox, dy - oy, colors);
[1013] 
[1014]             if (dst == NULL) {
[1015]                 gdImageDestroy(src);
[1016]                 return NULL;
[1017]             }
[1018] 
[1019]             ox /= 2;
[1020]             oy /= 2;
[1021] 
[1022]             ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1023]                            "image crop: %d x %d @ %d x %d",
[1024]                            dx, dy, ox, oy);
[1025] 
[1026]             if (colors == 0) {
[1027]                 gdImageSaveAlpha(dst, 1);
[1028]                 gdImageAlphaBlending(dst, 0);
[1029]             }
[1030] 
[1031]             gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);
[1032] 
[1033]             if (colors) {
[1034]                 gdImageTrueColorToPalette(dst, 1, 256);
[1035]             }
[1036] 
[1037]             gdImageDestroy(src);
[1038]         }
[1039]     }
[1040] 
[1041]     if (transparent != -1 && colors) {
[1042]         gdImageColorTransparent(dst, gdImageColorExact(dst, red, green, blue));
[1043]     }
[1044] 
[1045]     sharpen = ngx_http_image_filter_get_value(r, conf->shcv, conf->sharpen);
[1046]     if (sharpen > 0) {
[1047]         gdImageSharpen(dst, sharpen);
[1048]     }
[1049] 
[1050]     gdImageInterlace(dst, (int) conf->interlace);
[1051] 
[1052]     out = ngx_http_image_out(r, ctx->type, dst, &size);
[1053] 
[1054]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1055]                    "image: %d x %d %d", sx, sy, colors);
[1056] 
[1057]     gdImageDestroy(dst);
[1058]     ngx_pfree(r->pool, ctx->image);
[1059] 
[1060]     if (out == NULL) {
[1061]         return NULL;
[1062]     }
[1063] 
[1064]     cln = ngx_pool_cleanup_add(r->pool, 0);
[1065]     if (cln == NULL) {
[1066]         gdFree(out);
[1067]         return NULL;
[1068]     }
[1069] 
[1070]     b = ngx_calloc_buf(r->pool);
[1071]     if (b == NULL) {
[1072]         gdFree(out);
[1073]         return NULL;
[1074]     }
[1075] 
[1076]     cln->handler = ngx_http_image_cleanup;
[1077]     cln->data = out;
[1078] 
[1079]     b->pos = out;
[1080]     b->last = out + size;
[1081]     b->memory = 1;
[1082]     b->last_buf = 1;
[1083] 
[1084]     ngx_http_image_length(r, b);
[1085]     ngx_http_weak_etag(r);
[1086] 
[1087]     return b;
[1088] }
[1089] 
[1090] 
[1091] static gdImagePtr
[1092] ngx_http_image_source(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
[1093] {
[1094]     char        *failed;
[1095]     gdImagePtr   img;
[1096] 
[1097]     img = NULL;
[1098] 
[1099]     switch (ctx->type) {
[1100] 
[1101]     case NGX_HTTP_IMAGE_JPEG:
[1102]         img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
[1103]         failed = "gdImageCreateFromJpegPtr() failed";
[1104]         break;
[1105] 
[1106]     case NGX_HTTP_IMAGE_GIF:
[1107]         img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
[1108]         failed = "gdImageCreateFromGifPtr() failed";
[1109]         break;
[1110] 
[1111]     case NGX_HTTP_IMAGE_PNG:
[1112]         img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
[1113]         failed = "gdImageCreateFromPngPtr() failed";
[1114]         break;
[1115] 
[1116]     case NGX_HTTP_IMAGE_WEBP:
[1117] #if (NGX_HAVE_GD_WEBP)
[1118]         img = gdImageCreateFromWebpPtr(ctx->length, ctx->image);
[1119]         failed = "gdImageCreateFromWebpPtr() failed";
[1120] #else
[1121]         failed = "nginx was built without GD WebP support";
[1122] #endif
[1123]         break;
[1124] 
[1125]     default:
[1126]         failed = "unknown image type";
[1127]         break;
[1128]     }
[1129] 
[1130]     if (img == NULL) {
[1131]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
[1132]     }
[1133] 
[1134]     return img;
[1135] }
[1136] 
[1137] 
[1138] static gdImagePtr
[1139] ngx_http_image_new(ngx_http_request_t *r, int w, int h, int colors)
[1140] {
[1141]     gdImagePtr  img;
[1142] 
[1143]     if (colors == 0) {
[1144]         img = gdImageCreateTrueColor(w, h);
[1145] 
[1146]         if (img == NULL) {
[1147]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1148]                           "gdImageCreateTrueColor() failed");
[1149]             return NULL;
[1150]         }
[1151] 
[1152]     } else {
[1153]         img = gdImageCreate(w, h);
[1154] 
[1155]         if (img == NULL) {
[1156]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1157]                           "gdImageCreate() failed");
[1158]             return NULL;
[1159]         }
[1160]     }
[1161] 
[1162]     return img;
[1163] }
[1164] 
[1165] 
[1166] static u_char *
[1167] ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img,
[1168]     int *size)
[1169] {
[1170]     char                          *failed;
[1171]     u_char                        *out;
[1172]     ngx_int_t                      q;
[1173]     ngx_http_image_filter_conf_t  *conf;
[1174] 
[1175]     out = NULL;
[1176] 
[1177]     switch (type) {
[1178] 
[1179]     case NGX_HTTP_IMAGE_JPEG:
[1180]         conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
[1181] 
[1182]         q = ngx_http_image_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
[1183]         if (q <= 0) {
[1184]             return NULL;
[1185]         }
[1186] 
[1187]         out = gdImageJpegPtr(img, size, q);
[1188]         failed = "gdImageJpegPtr() failed";
[1189]         break;
[1190] 
[1191]     case NGX_HTTP_IMAGE_GIF:
[1192]         out = gdImageGifPtr(img, size);
[1193]         failed = "gdImageGifPtr() failed";
[1194]         break;
[1195] 
[1196]     case NGX_HTTP_IMAGE_PNG:
[1197]         out = gdImagePngPtr(img, size);
[1198]         failed = "gdImagePngPtr() failed";
[1199]         break;
[1200] 
[1201]     case NGX_HTTP_IMAGE_WEBP:
[1202] #if (NGX_HAVE_GD_WEBP)
[1203]         conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
[1204] 
[1205]         q = ngx_http_image_filter_get_value(r, conf->wqcv, conf->webp_quality);
[1206]         if (q <= 0) {
[1207]             return NULL;
[1208]         }
[1209] 
[1210]         out = gdImageWebpPtrEx(img, size, q);
[1211]         failed = "gdImageWebpPtrEx() failed";
[1212] #else
[1213]         failed = "nginx was built without GD WebP support";
[1214] #endif
[1215]         break;
[1216] 
[1217]     default:
[1218]         failed = "unknown image type";
[1219]         break;
[1220]     }
[1221] 
[1222]     if (out == NULL) {
[1223]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
[1224]     }
[1225] 
[1226]     return out;
[1227] }
[1228] 
[1229] 
[1230] static void
[1231] ngx_http_image_cleanup(void *data)
[1232] {
[1233]     gdFree(data);
[1234] }
[1235] 
[1236] 
[1237] static ngx_uint_t
[1238] ngx_http_image_filter_get_value(ngx_http_request_t *r,
[1239]     ngx_http_complex_value_t *cv, ngx_uint_t v)
[1240] {
[1241]     ngx_str_t  val;
[1242] 
[1243]     if (cv == NULL) {
[1244]         return v;
[1245]     }
[1246] 
[1247]     if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
[1248]         return 0;
[1249]     }
[1250] 
[1251]     return ngx_http_image_filter_value(&val);
[1252] }
[1253] 
[1254] 
[1255] static ngx_uint_t
[1256] ngx_http_image_filter_value(ngx_str_t *value)
[1257] {
[1258]     ngx_int_t  n;
[1259] 
[1260]     if (value->len == 1 && value->data[0] == '-') {
[1261]         return (ngx_uint_t) -1;
[1262]     }
[1263] 
[1264]     n = ngx_atoi(value->data, value->len);
[1265] 
[1266]     if (n > 0) {
[1267]         return (ngx_uint_t) n;
[1268]     }
[1269] 
[1270]     return 0;
[1271] }
[1272] 
[1273] 
[1274] static void *
[1275] ngx_http_image_filter_create_conf(ngx_conf_t *cf)
[1276] {
[1277]     ngx_http_image_filter_conf_t  *conf;
[1278] 
[1279]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_filter_conf_t));
[1280]     if (conf == NULL) {
[1281]         return NULL;
[1282]     }
[1283] 
[1284]     /*
[1285]      * set by ngx_pcalloc():
[1286]      *
[1287]      *     conf->width = 0;
[1288]      *     conf->height = 0;
[1289]      *     conf->angle = 0;
[1290]      *     conf->wcv = NULL;
[1291]      *     conf->hcv = NULL;
[1292]      *     conf->acv = NULL;
[1293]      *     conf->jqcv = NULL;
[1294]      *     conf->wqcv = NULL;
[1295]      *     conf->shcv = NULL;
[1296]      */
[1297] 
[1298]     conf->filter = NGX_CONF_UNSET_UINT;
[1299]     conf->jpeg_quality = NGX_CONF_UNSET_UINT;
[1300]     conf->webp_quality = NGX_CONF_UNSET_UINT;
[1301]     conf->sharpen = NGX_CONF_UNSET_UINT;
[1302]     conf->transparency = NGX_CONF_UNSET;
[1303]     conf->interlace = NGX_CONF_UNSET;
[1304]     conf->buffer_size = NGX_CONF_UNSET_SIZE;
[1305] 
[1306]     return conf;
[1307] }
[1308] 
[1309] 
[1310] static char *
[1311] ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[1312] {
[1313]     ngx_http_image_filter_conf_t *prev = parent;
[1314]     ngx_http_image_filter_conf_t *conf = child;
[1315] 
[1316]     if (conf->filter == NGX_CONF_UNSET_UINT) {
[1317] 
[1318]         if (prev->filter == NGX_CONF_UNSET_UINT) {
[1319]             conf->filter = NGX_HTTP_IMAGE_OFF;
[1320] 
[1321]         } else {
[1322]             conf->filter = prev->filter;
[1323]             conf->width = prev->width;
[1324]             conf->height = prev->height;
[1325]             conf->angle = prev->angle;
[1326]             conf->wcv = prev->wcv;
[1327]             conf->hcv = prev->hcv;
[1328]             conf->acv = prev->acv;
[1329]         }
[1330]     }
[1331] 
[1332]     if (conf->jpeg_quality == NGX_CONF_UNSET_UINT) {
[1333] 
[1334]         /* 75 is libjpeg default quality */
[1335]         ngx_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);
[1336] 
[1337]         if (conf->jqcv == NULL) {
[1338]             conf->jqcv = prev->jqcv;
[1339]         }
[1340]     }
[1341] 
[1342]     if (conf->webp_quality == NGX_CONF_UNSET_UINT) {
[1343] 
[1344]         /* 80 is libwebp default quality */
[1345]         ngx_conf_merge_uint_value(conf->webp_quality, prev->webp_quality, 80);
[1346] 
[1347]         if (conf->wqcv == NULL) {
[1348]             conf->wqcv = prev->wqcv;
[1349]         }
[1350]     }
[1351] 
[1352]     if (conf->sharpen == NGX_CONF_UNSET_UINT) {
[1353]         ngx_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);
[1354] 
[1355]         if (conf->shcv == NULL) {
[1356]             conf->shcv = prev->shcv;
[1357]         }
[1358]     }
[1359] 
[1360]     ngx_conf_merge_value(conf->transparency, prev->transparency, 1);
[1361] 
[1362]     ngx_conf_merge_value(conf->interlace, prev->interlace, 0);
[1363] 
[1364]     ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
[1365]                               1 * 1024 * 1024);
[1366] 
[1367]     return NGX_CONF_OK;
[1368] }
[1369] 
[1370] 
[1371] static char *
[1372] ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1373] {
[1374]     ngx_http_image_filter_conf_t *imcf = conf;
[1375] 
[1376]     ngx_str_t                         *value;
[1377]     ngx_int_t                          n;
[1378]     ngx_uint_t                         i;
[1379]     ngx_http_complex_value_t           cv;
[1380]     ngx_http_compile_complex_value_t   ccv;
[1381] 
[1382]     value = cf->args->elts;
[1383] 
[1384]     i = 1;
[1385] 
[1386]     if (cf->args->nelts == 2) {
[1387]         if (ngx_strcmp(value[i].data, "off") == 0) {
[1388]             imcf->filter = NGX_HTTP_IMAGE_OFF;
[1389] 
[1390]         } else if (ngx_strcmp(value[i].data, "test") == 0) {
[1391]             imcf->filter = NGX_HTTP_IMAGE_TEST;
[1392] 
[1393]         } else if (ngx_strcmp(value[i].data, "size") == 0) {
[1394]             imcf->filter = NGX_HTTP_IMAGE_SIZE;
[1395] 
[1396]         } else {
[1397]             goto failed;
[1398]         }
[1399] 
[1400]         return NGX_CONF_OK;
[1401] 
[1402]     } else if (cf->args->nelts == 3) {
[1403] 
[1404]         if (ngx_strcmp(value[i].data, "rotate") == 0) {
[1405]             if (imcf->filter != NGX_HTTP_IMAGE_RESIZE
[1406]                 && imcf->filter != NGX_HTTP_IMAGE_CROP)
[1407]             {
[1408]                 imcf->filter = NGX_HTTP_IMAGE_ROTATE;
[1409]             }
[1410] 
[1411]             ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1412] 
[1413]             ccv.cf = cf;
[1414]             ccv.value = &value[++i];
[1415]             ccv.complex_value = &cv;
[1416] 
[1417]             if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1418]                 return NGX_CONF_ERROR;
[1419]             }
[1420] 
[1421]             if (cv.lengths == NULL) {
[1422]                 n = ngx_http_image_filter_value(&value[i]);
[1423] 
[1424]                 if (n != 90 && n != 180 && n != 270) {
[1425]                     goto failed;
[1426]                 }
[1427] 
[1428]                 imcf->angle = (ngx_uint_t) n;
[1429] 
[1430]             } else {
[1431]                 imcf->acv = ngx_palloc(cf->pool,
[1432]                                        sizeof(ngx_http_complex_value_t));
[1433]                 if (imcf->acv == NULL) {
[1434]                     return NGX_CONF_ERROR;
[1435]                 }
[1436] 
[1437]                 *imcf->acv = cv;
[1438]             }
[1439] 
[1440]             return NGX_CONF_OK;
[1441] 
[1442]         } else {
[1443]             goto failed;
[1444]         }
[1445]     }
[1446] 
[1447]     if (ngx_strcmp(value[i].data, "resize") == 0) {
[1448]         imcf->filter = NGX_HTTP_IMAGE_RESIZE;
[1449] 
[1450]     } else if (ngx_strcmp(value[i].data, "crop") == 0) {
[1451]         imcf->filter = NGX_HTTP_IMAGE_CROP;
[1452] 
[1453]     } else {
[1454]         goto failed;
[1455]     }
[1456] 
[1457]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1458] 
[1459]     ccv.cf = cf;
[1460]     ccv.value = &value[++i];
[1461]     ccv.complex_value = &cv;
[1462] 
[1463]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1464]         return NGX_CONF_ERROR;
[1465]     }
[1466] 
[1467]     if (cv.lengths == NULL) {
[1468]         n = ngx_http_image_filter_value(&value[i]);
[1469] 
[1470]         if (n == 0) {
[1471]             goto failed;
[1472]         }
[1473] 
[1474]         imcf->width = (ngx_uint_t) n;
[1475] 
[1476]     } else {
[1477]         imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[1478]         if (imcf->wcv == NULL) {
[1479]             return NGX_CONF_ERROR;
[1480]         }
[1481] 
[1482]         *imcf->wcv = cv;
[1483]     }
[1484] 
[1485]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1486] 
[1487]     ccv.cf = cf;
[1488]     ccv.value = &value[++i];
[1489]     ccv.complex_value = &cv;
[1490] 
[1491]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1492]         return NGX_CONF_ERROR;
[1493]     }
[1494] 
[1495]     if (cv.lengths == NULL) {
[1496]         n = ngx_http_image_filter_value(&value[i]);
[1497] 
[1498]         if (n == 0) {
[1499]             goto failed;
[1500]         }
[1501] 
[1502]         imcf->height = (ngx_uint_t) n;
[1503] 
[1504]     } else {
[1505]         imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[1506]         if (imcf->hcv == NULL) {
[1507]             return NGX_CONF_ERROR;
[1508]         }
[1509] 
[1510]         *imcf->hcv = cv;
[1511]     }
[1512] 
[1513]     return NGX_CONF_OK;
[1514] 
[1515] failed:
[1516] 
[1517]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
[1518]                        &value[i]);
[1519] 
[1520]     return NGX_CONF_ERROR;
[1521] }
[1522] 
[1523] 
[1524] static char *
[1525] ngx_http_image_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd,
[1526]     void *conf)
[1527] {
[1528]     ngx_http_image_filter_conf_t *imcf = conf;
[1529] 
[1530]     ngx_str_t                         *value;
[1531]     ngx_int_t                          n;
[1532]     ngx_http_complex_value_t           cv;
[1533]     ngx_http_compile_complex_value_t   ccv;
[1534] 
[1535]     value = cf->args->elts;
[1536] 
[1537]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1538] 
[1539]     ccv.cf = cf;
[1540]     ccv.value = &value[1];
[1541]     ccv.complex_value = &cv;
[1542] 
[1543]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1544]         return NGX_CONF_ERROR;
[1545]     }
[1546] 
[1547]     if (cv.lengths == NULL) {
[1548]         n = ngx_http_image_filter_value(&value[1]);
[1549] 
[1550]         if (n <= 0) {
[1551]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1552]                                "invalid value \"%V\"", &value[1]);
[1553]             return NGX_CONF_ERROR;
[1554]         }
[1555] 
[1556]         imcf->jpeg_quality = (ngx_uint_t) n;
[1557] 
[1558]     } else {
[1559]         imcf->jqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[1560]         if (imcf->jqcv == NULL) {
[1561]             return NGX_CONF_ERROR;
[1562]         }
[1563] 
[1564]         *imcf->jqcv = cv;
[1565]     }
[1566] 
[1567]     return NGX_CONF_OK;
[1568] }
[1569] 
[1570] 
[1571] static char *
[1572] ngx_http_image_filter_webp_quality(ngx_conf_t *cf, ngx_command_t *cmd,
[1573]     void *conf)
[1574] {
[1575]     ngx_http_image_filter_conf_t *imcf = conf;
[1576] 
[1577]     ngx_str_t                         *value;
[1578]     ngx_int_t                          n;
[1579]     ngx_http_complex_value_t           cv;
[1580]     ngx_http_compile_complex_value_t   ccv;
[1581] 
[1582]     value = cf->args->elts;
[1583] 
[1584]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1585] 
[1586]     ccv.cf = cf;
[1587]     ccv.value = &value[1];
[1588]     ccv.complex_value = &cv;
[1589] 
[1590]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1591]         return NGX_CONF_ERROR;
[1592]     }
[1593] 
[1594]     if (cv.lengths == NULL) {
[1595]         n = ngx_http_image_filter_value(&value[1]);
[1596] 
[1597]         if (n <= 0) {
[1598]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1599]                                "invalid value \"%V\"", &value[1]);
[1600]             return NGX_CONF_ERROR;
[1601]         }
[1602] 
[1603]         imcf->webp_quality = (ngx_uint_t) n;
[1604] 
[1605]     } else {
[1606]         imcf->wqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[1607]         if (imcf->wqcv == NULL) {
[1608]             return NGX_CONF_ERROR;
[1609]         }
[1610] 
[1611]         *imcf->wqcv = cv;
[1612]     }
[1613] 
[1614]     return NGX_CONF_OK;
[1615] }
[1616] 
[1617] 
[1618] static char *
[1619] ngx_http_image_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd,
[1620]     void *conf)
[1621] {
[1622]     ngx_http_image_filter_conf_t *imcf = conf;
[1623] 
[1624]     ngx_str_t                         *value;
[1625]     ngx_int_t                          n;
[1626]     ngx_http_complex_value_t           cv;
[1627]     ngx_http_compile_complex_value_t   ccv;
[1628] 
[1629]     value = cf->args->elts;
[1630] 
[1631]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[1632] 
[1633]     ccv.cf = cf;
[1634]     ccv.value = &value[1];
[1635]     ccv.complex_value = &cv;
[1636] 
[1637]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[1638]         return NGX_CONF_ERROR;
[1639]     }
[1640] 
[1641]     if (cv.lengths == NULL) {
[1642]         n = ngx_http_image_filter_value(&value[1]);
[1643] 
[1644]         if (n < 0) {
[1645]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1646]                                "invalid value \"%V\"", &value[1]);
[1647]             return NGX_CONF_ERROR;
[1648]         }
[1649] 
[1650]         imcf->sharpen = (ngx_uint_t) n;
[1651] 
[1652]     } else {
[1653]         imcf->shcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[1654]         if (imcf->shcv == NULL) {
[1655]             return NGX_CONF_ERROR;
[1656]         }
[1657] 
[1658]         *imcf->shcv = cv;
[1659]     }
[1660] 
[1661]     return NGX_CONF_OK;
[1662] }
[1663] 
[1664] 
[1665] static ngx_int_t
[1666] ngx_http_image_filter_init(ngx_conf_t *cf)
[1667] {
[1668]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[1669]     ngx_http_top_header_filter = ngx_http_image_header_filter;
[1670] 
[1671]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[1672]     ngx_http_top_body_filter = ngx_http_image_body_filter;
[1673] 
[1674]     return NGX_OK;
[1675] }
