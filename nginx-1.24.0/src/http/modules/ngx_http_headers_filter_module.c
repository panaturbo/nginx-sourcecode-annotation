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
[13] typedef struct ngx_http_header_val_s  ngx_http_header_val_t;
[14] 
[15] typedef ngx_int_t (*ngx_http_set_header_pt)(ngx_http_request_t *r,
[16]     ngx_http_header_val_t *hv, ngx_str_t *value);
[17] 
[18] 
[19] typedef struct {
[20]     ngx_str_t                  name;
[21]     ngx_uint_t                 offset;
[22]     ngx_http_set_header_pt     handler;
[23] } ngx_http_set_header_t;
[24] 
[25] 
[26] struct ngx_http_header_val_s {
[27]     ngx_http_complex_value_t   value;
[28]     ngx_str_t                  key;
[29]     ngx_http_set_header_pt     handler;
[30]     ngx_uint_t                 offset;
[31]     ngx_uint_t                 always;  /* unsigned  always:1 */
[32] };
[33] 
[34] 
[35] typedef enum {
[36]     NGX_HTTP_EXPIRES_OFF,
[37]     NGX_HTTP_EXPIRES_EPOCH,
[38]     NGX_HTTP_EXPIRES_MAX,
[39]     NGX_HTTP_EXPIRES_ACCESS,
[40]     NGX_HTTP_EXPIRES_MODIFIED,
[41]     NGX_HTTP_EXPIRES_DAILY,
[42]     NGX_HTTP_EXPIRES_UNSET
[43] } ngx_http_expires_t;
[44] 
[45] 
[46] typedef struct {
[47]     ngx_http_expires_t         expires;
[48]     time_t                     expires_time;
[49]     ngx_http_complex_value_t  *expires_value;
[50]     ngx_array_t               *headers;
[51]     ngx_array_t               *trailers;
[52] } ngx_http_headers_conf_t;
[53] 
[54] 
[55] static ngx_int_t ngx_http_set_expires(ngx_http_request_t *r,
[56]     ngx_http_headers_conf_t *conf);
[57] static ngx_int_t ngx_http_parse_expires(ngx_str_t *value,
[58]     ngx_http_expires_t *expires, time_t *expires_time, char **err);
[59] static ngx_int_t ngx_http_add_multi_header_lines(ngx_http_request_t *r,
[60]     ngx_http_header_val_t *hv, ngx_str_t *value);
[61] static ngx_int_t ngx_http_add_header(ngx_http_request_t *r,
[62]     ngx_http_header_val_t *hv, ngx_str_t *value);
[63] static ngx_int_t ngx_http_set_last_modified(ngx_http_request_t *r,
[64]     ngx_http_header_val_t *hv, ngx_str_t *value);
[65] static ngx_int_t ngx_http_set_response_header(ngx_http_request_t *r,
[66]     ngx_http_header_val_t *hv, ngx_str_t *value);
[67] 
[68] static void *ngx_http_headers_create_conf(ngx_conf_t *cf);
[69] static char *ngx_http_headers_merge_conf(ngx_conf_t *cf,
[70]     void *parent, void *child);
[71] static ngx_int_t ngx_http_headers_filter_init(ngx_conf_t *cf);
[72] static char *ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd,
[73]     void *conf);
[74] static char *ngx_http_headers_add(ngx_conf_t *cf, ngx_command_t *cmd,
[75]     void *conf);
[76] 
[77] 
[78] static ngx_http_set_header_t  ngx_http_set_headers[] = {
[79] 
[80]     { ngx_string("Cache-Control"),
[81]                  offsetof(ngx_http_headers_out_t, cache_control),
[82]                  ngx_http_add_multi_header_lines },
[83] 
[84]     { ngx_string("Link"),
[85]                  offsetof(ngx_http_headers_out_t, link),
[86]                  ngx_http_add_multi_header_lines },
[87] 
[88]     { ngx_string("Last-Modified"),
[89]                  offsetof(ngx_http_headers_out_t, last_modified),
[90]                  ngx_http_set_last_modified },
[91] 
[92]     { ngx_string("ETag"),
[93]                  offsetof(ngx_http_headers_out_t, etag),
[94]                  ngx_http_set_response_header },
[95] 
[96]     { ngx_null_string, 0, NULL }
[97] };
[98] 
[99] 
[100] static ngx_command_t  ngx_http_headers_filter_commands[] = {
[101] 
[102]     { ngx_string("expires"),
[103]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[104]                         |NGX_CONF_TAKE12,
[105]       ngx_http_headers_expires,
[106]       NGX_HTTP_LOC_CONF_OFFSET,
[107]       0,
[108]       NULL },
[109] 
[110]     { ngx_string("add_header"),
[111]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[112]                         |NGX_CONF_TAKE23,
[113]       ngx_http_headers_add,
[114]       NGX_HTTP_LOC_CONF_OFFSET,
[115]       offsetof(ngx_http_headers_conf_t, headers),
[116]       NULL },
[117] 
[118]     { ngx_string("add_trailer"),
[119]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
[120]                         |NGX_CONF_TAKE23,
[121]       ngx_http_headers_add,
[122]       NGX_HTTP_LOC_CONF_OFFSET,
[123]       offsetof(ngx_http_headers_conf_t, trailers),
[124]       NULL },
[125] 
[126]       ngx_null_command
[127] };
[128] 
[129] 
[130] static ngx_http_module_t  ngx_http_headers_filter_module_ctx = {
[131]     NULL,                                  /* preconfiguration */
[132]     ngx_http_headers_filter_init,          /* postconfiguration */
[133] 
[134]     NULL,                                  /* create main configuration */
[135]     NULL,                                  /* init main configuration */
[136] 
[137]     NULL,                                  /* create server configuration */
[138]     NULL,                                  /* merge server configuration */
[139] 
[140]     ngx_http_headers_create_conf,          /* create location configuration */
[141]     ngx_http_headers_merge_conf            /* merge location configuration */
[142] };
[143] 
[144] 
[145] ngx_module_t  ngx_http_headers_filter_module = {
[146]     NGX_MODULE_V1,
[147]     &ngx_http_headers_filter_module_ctx,   /* module context */
[148]     ngx_http_headers_filter_commands,      /* module directives */
[149]     NGX_HTTP_MODULE,                       /* module type */
[150]     NULL,                                  /* init master */
[151]     NULL,                                  /* init module */
[152]     NULL,                                  /* init process */
[153]     NULL,                                  /* init thread */
[154]     NULL,                                  /* exit thread */
[155]     NULL,                                  /* exit process */
[156]     NULL,                                  /* exit master */
[157]     NGX_MODULE_V1_PADDING
[158] };
[159] 
[160] 
[161] static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
[162] static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
[163] 
[164] 
[165] static ngx_int_t
[166] ngx_http_headers_filter(ngx_http_request_t *r)
[167] {
[168]     ngx_str_t                 value;
[169]     ngx_uint_t                i, safe_status;
[170]     ngx_http_header_val_t    *h;
[171]     ngx_http_headers_conf_t  *conf;
[172] 
[173]     if (r != r->main) {
[174]         return ngx_http_next_header_filter(r);
[175]     }
[176] 
[177]     conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_filter_module);
[178] 
[179]     if (conf->expires == NGX_HTTP_EXPIRES_OFF
[180]         && conf->headers == NULL
[181]         && conf->trailers == NULL)
[182]     {
[183]         return ngx_http_next_header_filter(r);
[184]     }
[185] 
[186]     switch (r->headers_out.status) {
[187] 
[188]     case NGX_HTTP_OK:
[189]     case NGX_HTTP_CREATED:
[190]     case NGX_HTTP_NO_CONTENT:
[191]     case NGX_HTTP_PARTIAL_CONTENT:
[192]     case NGX_HTTP_MOVED_PERMANENTLY:
[193]     case NGX_HTTP_MOVED_TEMPORARILY:
[194]     case NGX_HTTP_SEE_OTHER:
[195]     case NGX_HTTP_NOT_MODIFIED:
[196]     case NGX_HTTP_TEMPORARY_REDIRECT:
[197]     case NGX_HTTP_PERMANENT_REDIRECT:
[198]         safe_status = 1;
[199]         break;
[200] 
[201]     default:
[202]         safe_status = 0;
[203]         break;
[204]     }
[205] 
[206]     if (conf->expires != NGX_HTTP_EXPIRES_OFF && safe_status) {
[207]         if (ngx_http_set_expires(r, conf) != NGX_OK) {
[208]             return NGX_ERROR;
[209]         }
[210]     }
[211] 
[212]     if (conf->headers) {
[213]         h = conf->headers->elts;
[214]         for (i = 0; i < conf->headers->nelts; i++) {
[215] 
[216]             if (!safe_status && !h[i].always) {
[217]                 continue;
[218]             }
[219] 
[220]             if (ngx_http_complex_value(r, &h[i].value, &value) != NGX_OK) {
[221]                 return NGX_ERROR;
[222]             }
[223] 
[224]             if (h[i].handler(r, &h[i], &value) != NGX_OK) {
[225]                 return NGX_ERROR;
[226]             }
[227]         }
[228]     }
[229] 
[230]     if (conf->trailers) {
[231]         h = conf->trailers->elts;
[232]         for (i = 0; i < conf->trailers->nelts; i++) {
[233] 
[234]             if (!safe_status && !h[i].always) {
[235]                 continue;
[236]             }
[237] 
[238]             r->expect_trailers = 1;
[239]             break;
[240]         }
[241]     }
[242] 
[243]     return ngx_http_next_header_filter(r);
[244] }
[245] 
[246] 
[247] static ngx_int_t
[248] ngx_http_trailers_filter(ngx_http_request_t *r, ngx_chain_t *in)
[249] {
[250]     ngx_str_t                 value;
[251]     ngx_uint_t                i, safe_status;
[252]     ngx_chain_t              *cl;
[253]     ngx_table_elt_t          *t;
[254]     ngx_http_header_val_t    *h;
[255]     ngx_http_headers_conf_t  *conf;
[256] 
[257]     conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_filter_module);
[258] 
[259]     if (in == NULL
[260]         || conf->trailers == NULL
[261]         || !r->expect_trailers
[262]         || r->header_only)
[263]     {
[264]         return ngx_http_next_body_filter(r, in);
[265]     }
[266] 
[267]     for (cl = in; cl; cl = cl->next) {
[268]         if (cl->buf->last_buf) {
[269]             break;
[270]         }
[271]     }
[272] 
[273]     if (cl == NULL) {
[274]         return ngx_http_next_body_filter(r, in);
[275]     }
[276] 
[277]     switch (r->headers_out.status) {
[278] 
[279]     case NGX_HTTP_OK:
[280]     case NGX_HTTP_CREATED:
[281]     case NGX_HTTP_NO_CONTENT:
[282]     case NGX_HTTP_PARTIAL_CONTENT:
[283]     case NGX_HTTP_MOVED_PERMANENTLY:
[284]     case NGX_HTTP_MOVED_TEMPORARILY:
[285]     case NGX_HTTP_SEE_OTHER:
[286]     case NGX_HTTP_NOT_MODIFIED:
[287]     case NGX_HTTP_TEMPORARY_REDIRECT:
[288]     case NGX_HTTP_PERMANENT_REDIRECT:
[289]         safe_status = 1;
[290]         break;
[291] 
[292]     default:
[293]         safe_status = 0;
[294]         break;
[295]     }
[296] 
[297]     h = conf->trailers->elts;
[298]     for (i = 0; i < conf->trailers->nelts; i++) {
[299] 
[300]         if (!safe_status && !h[i].always) {
[301]             continue;
[302]         }
[303] 
[304]         if (ngx_http_complex_value(r, &h[i].value, &value) != NGX_OK) {
[305]             return NGX_ERROR;
[306]         }
[307] 
[308]         if (value.len) {
[309]             t = ngx_list_push(&r->headers_out.trailers);
[310]             if (t == NULL) {
[311]                 return NGX_ERROR;
[312]             }
[313] 
[314]             t->key = h[i].key;
[315]             t->value = value;
[316]             t->hash = 1;
[317]         }
[318]     }
[319] 
[320]     return ngx_http_next_body_filter(r, in);
[321] }
[322] 
[323] 
[324] static ngx_int_t
[325] ngx_http_set_expires(ngx_http_request_t *r, ngx_http_headers_conf_t *conf)
[326] {
[327]     char                *err;
[328]     size_t               len;
[329]     time_t               now, expires_time, max_age;
[330]     ngx_str_t            value;
[331]     ngx_int_t            rc;
[332]     ngx_table_elt_t     *e, *cc;
[333]     ngx_http_expires_t   expires;
[334] 
[335]     expires = conf->expires;
[336]     expires_time = conf->expires_time;
[337] 
[338]     if (conf->expires_value != NULL) {
[339] 
[340]         if (ngx_http_complex_value(r, conf->expires_value, &value) != NGX_OK) {
[341]             return NGX_ERROR;
[342]         }
[343] 
[344]         rc = ngx_http_parse_expires(&value, &expires, &expires_time, &err);
[345] 
[346]         if (rc != NGX_OK) {
[347]             return NGX_OK;
[348]         }
[349] 
[350]         if (expires == NGX_HTTP_EXPIRES_OFF) {
[351]             return NGX_OK;
[352]         }
[353]     }
[354] 
[355]     e = r->headers_out.expires;
[356] 
[357]     if (e == NULL) {
[358] 
[359]         e = ngx_list_push(&r->headers_out.headers);
[360]         if (e == NULL) {
[361]             return NGX_ERROR;
[362]         }
[363] 
[364]         r->headers_out.expires = e;
[365]         e->next = NULL;
[366] 
[367]         e->hash = 1;
[368]         ngx_str_set(&e->key, "Expires");
[369]     }
[370] 
[371]     len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
[372]     e->value.len = len - 1;
[373] 
[374]     cc = r->headers_out.cache_control;
[375] 
[376]     if (cc == NULL) {
[377] 
[378]         cc = ngx_list_push(&r->headers_out.headers);
[379]         if (cc == NULL) {
[380]             e->hash = 0;
[381]             return NGX_ERROR;
[382]         }
[383] 
[384]         r->headers_out.cache_control = cc;
[385]         cc->next = NULL;
[386] 
[387]         cc->hash = 1;
[388]         ngx_str_set(&cc->key, "Cache-Control");
[389] 
[390]     } else {
[391]         for (cc = cc->next; cc; cc = cc->next) {
[392]             cc->hash = 0;
[393]         }
[394] 
[395]         cc = r->headers_out.cache_control;
[396]         cc->next = NULL;
[397]     }
[398] 
[399]     if (expires == NGX_HTTP_EXPIRES_EPOCH) {
[400]         e->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";
[401]         ngx_str_set(&cc->value, "no-cache");
[402]         return NGX_OK;
[403]     }
[404] 
[405]     if (expires == NGX_HTTP_EXPIRES_MAX) {
[406]         e->value.data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";
[407]         /* 10 years */
[408]         ngx_str_set(&cc->value, "max-age=315360000");
[409]         return NGX_OK;
[410]     }
[411] 
[412]     e->value.data = ngx_pnalloc(r->pool, len);
[413]     if (e->value.data == NULL) {
[414]         e->hash = 0;
[415]         cc->hash = 0;
[416]         return NGX_ERROR;
[417]     }
[418] 
[419]     if (expires_time == 0 && expires != NGX_HTTP_EXPIRES_DAILY) {
[420]         ngx_memcpy(e->value.data, ngx_cached_http_time.data,
[421]                    ngx_cached_http_time.len + 1);
[422]         ngx_str_set(&cc->value, "max-age=0");
[423]         return NGX_OK;
[424]     }
[425] 
[426]     now = ngx_time();
[427] 
[428]     if (expires == NGX_HTTP_EXPIRES_DAILY) {
[429]         expires_time = ngx_next_time(expires_time);
[430]         max_age = expires_time - now;
[431] 
[432]     } else if (expires == NGX_HTTP_EXPIRES_ACCESS
[433]                || r->headers_out.last_modified_time == -1)
[434]     {
[435]         max_age = expires_time;
[436]         expires_time += now;
[437] 
[438]     } else {
[439]         expires_time += r->headers_out.last_modified_time;
[440]         max_age = expires_time - now;
[441]     }
[442] 
[443]     ngx_http_time(e->value.data, expires_time);
[444] 
[445]     if (conf->expires_time < 0 || max_age < 0) {
[446]         ngx_str_set(&cc->value, "no-cache");
[447]         return NGX_OK;
[448]     }
[449] 
[450]     cc->value.data = ngx_pnalloc(r->pool,
[451]                                  sizeof("max-age=") + NGX_TIME_T_LEN + 1);
[452]     if (cc->value.data == NULL) {
[453]         cc->hash = 0;
[454]         return NGX_ERROR;
[455]     }
[456] 
[457]     cc->value.len = ngx_sprintf(cc->value.data, "max-age=%T", max_age)
[458]                     - cc->value.data;
[459] 
[460]     return NGX_OK;
[461] }
[462] 
[463] 
[464] static ngx_int_t
[465] ngx_http_parse_expires(ngx_str_t *value, ngx_http_expires_t *expires,
[466]     time_t *expires_time, char **err)
[467] {
[468]     ngx_uint_t  minus;
[469] 
[470]     if (*expires != NGX_HTTP_EXPIRES_MODIFIED) {
[471] 
[472]         if (value->len == 5 && ngx_strncmp(value->data, "epoch", 5) == 0) {
[473]             *expires = NGX_HTTP_EXPIRES_EPOCH;
[474]             return NGX_OK;
[475]         }
[476] 
[477]         if (value->len == 3 && ngx_strncmp(value->data, "max", 3) == 0) {
[478]             *expires = NGX_HTTP_EXPIRES_MAX;
[479]             return NGX_OK;
[480]         }
[481] 
[482]         if (value->len == 3 && ngx_strncmp(value->data, "off", 3) == 0) {
[483]             *expires = NGX_HTTP_EXPIRES_OFF;
[484]             return NGX_OK;
[485]         }
[486]     }
[487] 
[488]     if (value->len && value->data[0] == '@') {
[489]         value->data++;
[490]         value->len--;
[491]         minus = 0;
[492] 
[493]         if (*expires == NGX_HTTP_EXPIRES_MODIFIED) {
[494]             *err = "daily time cannot be used with \"modified\" parameter";
[495]             return NGX_ERROR;
[496]         }
[497] 
[498]         *expires = NGX_HTTP_EXPIRES_DAILY;
[499] 
[500]     } else if (value->len && value->data[0] == '+') {
[501]         value->data++;
[502]         value->len--;
[503]         minus = 0;
[504] 
[505]     } else if (value->len && value->data[0] == '-') {
[506]         value->data++;
[507]         value->len--;
[508]         minus = 1;
[509] 
[510]     } else {
[511]         minus = 0;
[512]     }
[513] 
[514]     *expires_time = ngx_parse_time(value, 1);
[515] 
[516]     if (*expires_time == (time_t) NGX_ERROR) {
[517]         *err = "invalid value";
[518]         return NGX_ERROR;
[519]     }
[520] 
[521]     if (*expires == NGX_HTTP_EXPIRES_DAILY
[522]         && *expires_time > 24 * 60 * 60)
[523]     {
[524]         *err = "daily time value must be less than 24 hours";
[525]         return NGX_ERROR;
[526]     }
[527] 
[528]     if (minus) {
[529]         *expires_time = - *expires_time;
[530]     }
[531] 
[532]     return NGX_OK;
[533] }
[534] 
[535] 
[536] static ngx_int_t
[537] ngx_http_add_header(ngx_http_request_t *r, ngx_http_header_val_t *hv,
[538]     ngx_str_t *value)
[539] {
[540]     ngx_table_elt_t  *h;
[541] 
[542]     if (value->len) {
[543]         h = ngx_list_push(&r->headers_out.headers);
[544]         if (h == NULL) {
[545]             return NGX_ERROR;
[546]         }
[547] 
[548]         h->hash = 1;
[549]         h->key = hv->key;
[550]         h->value = *value;
[551]     }
[552] 
[553]     return NGX_OK;
[554] }
[555] 
[556] 
[557] static ngx_int_t
[558] ngx_http_add_multi_header_lines(ngx_http_request_t *r,
[559]     ngx_http_header_val_t *hv, ngx_str_t *value)
[560] {
[561]     ngx_table_elt_t  *h, **ph;
[562] 
[563]     if (value->len == 0) {
[564]         return NGX_OK;
[565]     }
[566] 
[567]     h = ngx_list_push(&r->headers_out.headers);
[568]     if (h == NULL) {
[569]         return NGX_ERROR;
[570]     }
[571] 
[572]     h->hash = 1;
[573]     h->key = hv->key;
[574]     h->value = *value;
[575] 
[576]     ph = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);
[577] 
[578]     while (*ph) { ph = &(*ph)->next; }
[579] 
[580]     *ph = h;
[581]     h->next = NULL;
[582] 
[583]     return NGX_OK;
[584] }
[585] 
[586] 
[587] static ngx_int_t
[588] ngx_http_set_last_modified(ngx_http_request_t *r, ngx_http_header_val_t *hv,
[589]     ngx_str_t *value)
[590] {
[591]     if (ngx_http_set_response_header(r, hv, value) != NGX_OK) {
[592]         return NGX_ERROR;
[593]     }
[594] 
[595]     r->headers_out.last_modified_time =
[596]         (value->len) ? ngx_parse_http_time(value->data, value->len) : -1;
[597] 
[598]     return NGX_OK;
[599] }
[600] 
[601] 
[602] static ngx_int_t
[603] ngx_http_set_response_header(ngx_http_request_t *r, ngx_http_header_val_t *hv,
[604]     ngx_str_t *value)
[605] {
[606]     ngx_table_elt_t  *h, **old;
[607] 
[608]     old = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);
[609] 
[610]     if (value->len == 0) {
[611]         if (*old) {
[612]             (*old)->hash = 0;
[613]             *old = NULL;
[614]         }
[615] 
[616]         return NGX_OK;
[617]     }
[618] 
[619]     if (*old) {
[620]         h = *old;
[621] 
[622]     } else {
[623]         h = ngx_list_push(&r->headers_out.headers);
[624]         if (h == NULL) {
[625]             return NGX_ERROR;
[626]         }
[627] 
[628]         *old = h;
[629]         h->next = NULL;
[630]     }
[631] 
[632]     h->hash = 1;
[633]     h->key = hv->key;
[634]     h->value = *value;
[635] 
[636]     return NGX_OK;
[637] }
[638] 
[639] 
[640] static void *
[641] ngx_http_headers_create_conf(ngx_conf_t *cf)
[642] {
[643]     ngx_http_headers_conf_t  *conf;
[644] 
[645]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_headers_conf_t));
[646]     if (conf == NULL) {
[647]         return NULL;
[648]     }
[649] 
[650]     /*
[651]      * set by ngx_pcalloc():
[652]      *
[653]      *     conf->headers = NULL;
[654]      *     conf->trailers = NULL;
[655]      *     conf->expires_time = 0;
[656]      *     conf->expires_value = NULL;
[657]      */
[658] 
[659]     conf->expires = NGX_HTTP_EXPIRES_UNSET;
[660] 
[661]     return conf;
[662] }
[663] 
[664] 
[665] static char *
[666] ngx_http_headers_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[667] {
[668]     ngx_http_headers_conf_t *prev = parent;
[669]     ngx_http_headers_conf_t *conf = child;
[670] 
[671]     if (conf->expires == NGX_HTTP_EXPIRES_UNSET) {
[672]         conf->expires = prev->expires;
[673]         conf->expires_time = prev->expires_time;
[674]         conf->expires_value = prev->expires_value;
[675] 
[676]         if (conf->expires == NGX_HTTP_EXPIRES_UNSET) {
[677]             conf->expires = NGX_HTTP_EXPIRES_OFF;
[678]         }
[679]     }
[680] 
[681]     if (conf->headers == NULL) {
[682]         conf->headers = prev->headers;
[683]     }
[684] 
[685]     if (conf->trailers == NULL) {
[686]         conf->trailers = prev->trailers;
[687]     }
[688] 
[689]     return NGX_CONF_OK;
[690] }
[691] 
[692] 
[693] static ngx_int_t
[694] ngx_http_headers_filter_init(ngx_conf_t *cf)
[695] {
[696]     ngx_http_next_header_filter = ngx_http_top_header_filter;
[697]     ngx_http_top_header_filter = ngx_http_headers_filter;
[698] 
[699]     ngx_http_next_body_filter = ngx_http_top_body_filter;
[700]     ngx_http_top_body_filter = ngx_http_trailers_filter;
[701] 
[702]     return NGX_OK;
[703] }
[704] 
[705] 
[706] static char *
[707] ngx_http_headers_expires(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[708] {
[709]     ngx_http_headers_conf_t *hcf = conf;
[710] 
[711]     char                              *err;
[712]     ngx_str_t                         *value;
[713]     ngx_int_t                          rc;
[714]     ngx_uint_t                         n;
[715]     ngx_http_complex_value_t           cv;
[716]     ngx_http_compile_complex_value_t   ccv;
[717] 
[718]     if (hcf->expires != NGX_HTTP_EXPIRES_UNSET) {
[719]         return "is duplicate";
[720]     }
[721] 
[722]     value = cf->args->elts;
[723] 
[724]     if (cf->args->nelts == 2) {
[725] 
[726]         hcf->expires = NGX_HTTP_EXPIRES_ACCESS;
[727] 
[728]         n = 1;
[729] 
[730]     } else { /* cf->args->nelts == 3 */
[731] 
[732]         if (ngx_strcmp(value[1].data, "modified") != 0) {
[733]             return "invalid value";
[734]         }
[735] 
[736]         hcf->expires = NGX_HTTP_EXPIRES_MODIFIED;
[737] 
[738]         n = 2;
[739]     }
[740] 
[741]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[742] 
[743]     ccv.cf = cf;
[744]     ccv.value = &value[n];
[745]     ccv.complex_value = &cv;
[746] 
[747]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[748]         return NGX_CONF_ERROR;
[749]     }
[750] 
[751]     if (cv.lengths != NULL) {
[752] 
[753]         hcf->expires_value = ngx_palloc(cf->pool,
[754]                                         sizeof(ngx_http_complex_value_t));
[755]         if (hcf->expires_value == NULL) {
[756]             return NGX_CONF_ERROR;
[757]         }
[758] 
[759]         *hcf->expires_value = cv;
[760] 
[761]         return NGX_CONF_OK;
[762]     }
[763] 
[764]     rc = ngx_http_parse_expires(&value[n], &hcf->expires, &hcf->expires_time,
[765]                                 &err);
[766]     if (rc != NGX_OK) {
[767]         return err;
[768]     }
[769] 
[770]     return NGX_CONF_OK;
[771] }
[772] 
[773] 
[774] static char *
[775] ngx_http_headers_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[776] {
[777]     ngx_http_headers_conf_t *hcf = conf;
[778] 
[779]     ngx_str_t                          *value;
[780]     ngx_uint_t                          i;
[781]     ngx_array_t                       **headers;
[782]     ngx_http_header_val_t              *hv;
[783]     ngx_http_set_header_t              *set;
[784]     ngx_http_compile_complex_value_t    ccv;
[785] 
[786]     value = cf->args->elts;
[787] 
[788]     headers = (ngx_array_t **) ((char *) hcf + cmd->offset);
[789] 
[790]     if (*headers == NULL) {
[791]         *headers = ngx_array_create(cf->pool, 1,
[792]                                     sizeof(ngx_http_header_val_t));
[793]         if (*headers == NULL) {
[794]             return NGX_CONF_ERROR;
[795]         }
[796]     }
[797] 
[798]     hv = ngx_array_push(*headers);
[799]     if (hv == NULL) {
[800]         return NGX_CONF_ERROR;
[801]     }
[802] 
[803]     hv->key = value[1];
[804]     hv->handler = NULL;
[805]     hv->offset = 0;
[806]     hv->always = 0;
[807] 
[808]     if (headers == &hcf->headers) {
[809]         hv->handler = ngx_http_add_header;
[810] 
[811]         set = ngx_http_set_headers;
[812]         for (i = 0; set[i].name.len; i++) {
[813]             if (ngx_strcasecmp(value[1].data, set[i].name.data) != 0) {
[814]                 continue;
[815]             }
[816] 
[817]             hv->offset = set[i].offset;
[818]             hv->handler = set[i].handler;
[819] 
[820]             break;
[821]         }
[822]     }
[823] 
[824]     if (value[2].len == 0) {
[825]         ngx_memzero(&hv->value, sizeof(ngx_http_complex_value_t));
[826] 
[827]     } else {
[828]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[829] 
[830]         ccv.cf = cf;
[831]         ccv.value = &value[2];
[832]         ccv.complex_value = &hv->value;
[833] 
[834]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[835]             return NGX_CONF_ERROR;
[836]         }
[837]     }
[838] 
[839]     if (cf->args->nelts == 3) {
[840]         return NGX_CONF_OK;
[841]     }
[842] 
[843]     if (ngx_strcmp(value[3].data, "always") != 0) {
[844]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[845]                            "invalid parameter \"%V\"", &value[3]);
[846]         return NGX_CONF_ERROR;
[847]     }
[848] 
[849]     hv->always = 1;
[850] 
[851]     return NGX_CONF_OK;
[852] }
