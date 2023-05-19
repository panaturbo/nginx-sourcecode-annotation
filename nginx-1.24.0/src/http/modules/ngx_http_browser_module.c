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
[13] /*
[14]  * The module can check browser versions conforming to the following formats:
[15]  * X, X.X, X.X.X, and X.X.X.X.  The maximum values of each format may be
[16]  * 4000, 4000.99, 4000.99.99, and 4000.99.99.99.
[17]  */
[18] 
[19] 
[20] #define  NGX_HTTP_MODERN_BROWSER   0
[21] #define  NGX_HTTP_ANCIENT_BROWSER  1
[22] 
[23] 
[24] typedef struct {
[25]     u_char                      browser[12];
[26]     size_t                      skip;
[27]     size_t                      add;
[28]     u_char                      name[12];
[29] } ngx_http_modern_browser_mask_t;
[30] 
[31] 
[32] typedef struct {
[33]     ngx_uint_t                  version;
[34]     size_t                      skip;
[35]     size_t                      add;
[36]     u_char                      name[12];
[37] } ngx_http_modern_browser_t;
[38] 
[39] 
[40] typedef struct {
[41]     ngx_array_t                *modern_browsers;
[42]     ngx_array_t                *ancient_browsers;
[43]     ngx_http_variable_value_t  *modern_browser_value;
[44]     ngx_http_variable_value_t  *ancient_browser_value;
[45] 
[46]     unsigned                    modern_unlisted_browsers:1;
[47]     unsigned                    netscape4:1;
[48] } ngx_http_browser_conf_t;
[49] 
[50] 
[51] static ngx_int_t ngx_http_msie_variable(ngx_http_request_t *r,
[52]     ngx_http_variable_value_t *v, uintptr_t data);
[53] static ngx_int_t ngx_http_browser_variable(ngx_http_request_t *r,
[54]     ngx_http_variable_value_t *v, uintptr_t data);
[55] 
[56] static ngx_uint_t ngx_http_browser(ngx_http_request_t *r,
[57]     ngx_http_browser_conf_t *cf);
[58] 
[59] static ngx_int_t ngx_http_browser_add_variables(ngx_conf_t *cf);
[60] static void *ngx_http_browser_create_conf(ngx_conf_t *cf);
[61] static char *ngx_http_browser_merge_conf(ngx_conf_t *cf, void *parent,
[62]     void *child);
[63] static int ngx_libc_cdecl ngx_http_modern_browser_sort(const void *one,
[64]     const void *two);
[65] static char *ngx_http_modern_browser(ngx_conf_t *cf, ngx_command_t *cmd,
[66]     void *conf);
[67] static char *ngx_http_ancient_browser(ngx_conf_t *cf, ngx_command_t *cmd,
[68]     void *conf);
[69] static char *ngx_http_modern_browser_value(ngx_conf_t *cf, ngx_command_t *cmd,
[70]     void *conf);
[71] static char *ngx_http_ancient_browser_value(ngx_conf_t *cf, ngx_command_t *cmd,
[72]     void *conf);
[73] 
[74] 
[75] static ngx_command_t  ngx_http_browser_commands[] = {
[76] 
[77]     { ngx_string("modern_browser"),
[78]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
[79]       ngx_http_modern_browser,
[80]       NGX_HTTP_LOC_CONF_OFFSET,
[81]       0,
[82]       NULL },
[83] 
[84]     { ngx_string("ancient_browser"),
[85]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[86]       ngx_http_ancient_browser,
[87]       NGX_HTTP_LOC_CONF_OFFSET,
[88]       0,
[89]       NULL },
[90] 
[91]     { ngx_string("modern_browser_value"),
[92]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[93]       ngx_http_modern_browser_value,
[94]       NGX_HTTP_LOC_CONF_OFFSET,
[95]       0,
[96]       NULL },
[97] 
[98]     { ngx_string("ancient_browser_value"),
[99]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[100]       ngx_http_ancient_browser_value,
[101]       NGX_HTTP_LOC_CONF_OFFSET,
[102]       0,
[103]       NULL },
[104] 
[105]       ngx_null_command
[106] };
[107] 
[108] 
[109] static ngx_http_module_t  ngx_http_browser_module_ctx = {
[110]     ngx_http_browser_add_variables,        /* preconfiguration */
[111]     NULL,                                  /* postconfiguration */
[112] 
[113]     NULL,                                  /* create main configuration */
[114]     NULL,                                  /* init main configuration */
[115] 
[116]     NULL,                                  /* create server configuration */
[117]     NULL,                                  /* merge server configuration */
[118] 
[119]     ngx_http_browser_create_conf,          /* create location configuration */
[120]     ngx_http_browser_merge_conf            /* merge location configuration */
[121] };
[122] 
[123] 
[124] ngx_module_t  ngx_http_browser_module = {
[125]     NGX_MODULE_V1,
[126]     &ngx_http_browser_module_ctx,          /* module context */
[127]     ngx_http_browser_commands,             /* module directives */
[128]     NGX_HTTP_MODULE,                       /* module type */
[129]     NULL,                                  /* init master */
[130]     NULL,                                  /* init module */
[131]     NULL,                                  /* init process */
[132]     NULL,                                  /* init thread */
[133]     NULL,                                  /* exit thread */
[134]     NULL,                                  /* exit process */
[135]     NULL,                                  /* exit master */
[136]     NGX_MODULE_V1_PADDING
[137] };
[138] 
[139] 
[140] static ngx_http_modern_browser_mask_t  ngx_http_modern_browser_masks[] = {
[141] 
[142]     /* Opera must be the first browser to check */
[143] 
[144]     /*
[145]      * "Opera/7.50 (X11; FreeBSD i386; U)  [en]"
[146]      * "Mozilla/5.0 (X11; FreeBSD i386; U) Opera 7.50  [en]"
[147]      * "Mozilla/4.0 (compatible; MSIE 6.0; X11; FreeBSD i386) Opera 7.50  [en]"
[148]      * "Opera/8.0 (Windows NT 5.1; U; ru)"
[149]      * "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; en) Opera 8.0"
[150]      * "Opera/9.01 (X11; FreeBSD 6 i386; U; en)"
[151]      */
[152] 
[153]     { "opera",
[154]       0,
[155]       sizeof("Opera ") - 1,
[156]       "Opera"},
[157] 
[158]     /* "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" */
[159] 
[160]     { "msie",
[161]       sizeof("Mozilla/4.0 (compatible; ") - 1,
[162]       sizeof("MSIE ") - 1,
[163]       "MSIE "},
[164] 
[165]     /*
[166]      * "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.0.0) Gecko/20020610"
[167]      * "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:1.5) Gecko/20031006"
[168]      * "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:1.6) Gecko/20040206
[169]      *              Firefox/0.8"
[170]      * "Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:1.7.8)
[171]      *              Gecko/20050511 Firefox/1.0.4"
[172]      * "Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.8.0.5) Gecko/20060729
[173]      *              Firefox/1.5.0.5"
[174]      */
[175] 
[176]     { "gecko",
[177]       sizeof("Mozilla/5.0 (") - 1,
[178]       sizeof("rv:") - 1,
[179]       "rv:"},
[180] 
[181]     /*
[182]      * "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ru-ru) AppleWebKit/125.2
[183]      *              (KHTML, like Gecko) Safari/125.7"
[184]      * "Mozilla/5.0 (SymbianOS/9.1; U; en-us) AppleWebKit/413
[185]      *              (KHTML, like Gecko) Safari/413"
[186]      * "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/418
[187]      *              (KHTML, like Gecko) Safari/417.9.3"
[188]      * "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; ru-ru) AppleWebKit/418.8
[189]      *              (KHTML, like Gecko) Safari/419.3"
[190]      */
[191] 
[192]     { "safari",
[193]       sizeof("Mozilla/5.0 (") - 1,
[194]       sizeof("Safari/") - 1,
[195]       "Safari/"},
[196] 
[197]     /*
[198]      * "Mozilla/5.0 (compatible; Konqueror/3.1; Linux)"
[199]      * "Mozilla/5.0 (compatible; Konqueror/3.4; Linux) KHTML/3.4.2 (like Gecko)"
[200]      * "Mozilla/5.0 (compatible; Konqueror/3.5; FreeBSD) KHTML/3.5.1
[201]      *              (like Gecko)"
[202]      */
[203] 
[204]     { "konqueror",
[205]       sizeof("Mozilla/5.0 (compatible; ") - 1,
[206]       sizeof("Konqueror/") - 1,
[207]       "Konqueror/"},
[208] 
[209]     { "", 0, 0, "" }
[210] 
[211] };
[212] 
[213] 
[214] static ngx_http_variable_t  ngx_http_browser_vars[] = {
[215] 
[216]     { ngx_string("msie"), NULL, ngx_http_msie_variable,
[217]       0, NGX_HTTP_VAR_CHANGEABLE, 0 },
[218] 
[219]     { ngx_string("modern_browser"), NULL, ngx_http_browser_variable,
[220]       NGX_HTTP_MODERN_BROWSER, NGX_HTTP_VAR_CHANGEABLE, 0 },
[221] 
[222]     { ngx_string("ancient_browser"), NULL, ngx_http_browser_variable,
[223]       NGX_HTTP_ANCIENT_BROWSER, NGX_HTTP_VAR_CHANGEABLE, 0 },
[224] 
[225]       ngx_http_null_variable
[226] };
[227] 
[228] 
[229] static ngx_int_t
[230] ngx_http_browser_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[231]     uintptr_t data)
[232] {
[233]     ngx_uint_t                rc;
[234]     ngx_http_browser_conf_t  *cf;
[235] 
[236]     cf = ngx_http_get_module_loc_conf(r, ngx_http_browser_module);
[237] 
[238]     rc = ngx_http_browser(r, cf);
[239] 
[240]     if (data == NGX_HTTP_MODERN_BROWSER && rc == NGX_HTTP_MODERN_BROWSER) {
[241]         *v = *cf->modern_browser_value;
[242]         return NGX_OK;
[243]     }
[244] 
[245]     if (data == NGX_HTTP_ANCIENT_BROWSER && rc == NGX_HTTP_ANCIENT_BROWSER) {
[246]         *v = *cf->ancient_browser_value;
[247]         return NGX_OK;
[248]     }
[249] 
[250]     *v = ngx_http_variable_null_value;
[251]     return NGX_OK;
[252] }
[253] 
[254] 
[255] static ngx_uint_t
[256] ngx_http_browser(ngx_http_request_t *r, ngx_http_browser_conf_t *cf)
[257] {
[258]     size_t                      len;
[259]     u_char                     *name, *ua, *last, c;
[260]     ngx_str_t                  *ancient;
[261]     ngx_uint_t                  i, version, ver, scale;
[262]     ngx_http_modern_browser_t  *modern;
[263] 
[264]     if (r->headers_in.user_agent == NULL) {
[265]         if (cf->modern_unlisted_browsers) {
[266]             return NGX_HTTP_MODERN_BROWSER;
[267]         }
[268] 
[269]         return NGX_HTTP_ANCIENT_BROWSER;
[270]     }
[271] 
[272]     ua = r->headers_in.user_agent->value.data;
[273]     len = r->headers_in.user_agent->value.len;
[274]     last = ua + len;
[275] 
[276]     if (cf->modern_browsers) {
[277]         modern = cf->modern_browsers->elts;
[278] 
[279]         for (i = 0; i < cf->modern_browsers->nelts; i++) {
[280]             name = ua + modern[i].skip;
[281] 
[282]             if (name >= last) {
[283]                 continue;
[284]             }
[285] 
[286]             name = (u_char *) ngx_strstr(name, modern[i].name);
[287] 
[288]             if (name == NULL) {
[289]                 continue;
[290]             }
[291] 
[292]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[293]                            "browser: \"%s\"", name);
[294] 
[295]             name += modern[i].add;
[296] 
[297]             if (name >= last) {
[298]                 continue;
[299]             }
[300] 
[301]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[302]                            "version: \"%ui\" \"%s\"", modern[i].version, name);
[303] 
[304]             version = 0;
[305]             ver = 0;
[306]             scale = 1000000;
[307] 
[308]             while (name < last) {
[309] 
[310]                 c = *name++;
[311] 
[312]                 if (c >= '0' && c <= '9') {
[313]                     ver = ver * 10 + (c - '0');
[314]                     continue;
[315]                 }
[316] 
[317]                 if (c == '.') {
[318]                     version += ver * scale;
[319] 
[320]                     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[321]                                    "version: \"%ui\" \"%ui\"",
[322]                                    modern[i].version, version);
[323] 
[324]                     if (version > modern[i].version) {
[325]                         return NGX_HTTP_MODERN_BROWSER;
[326]                     }
[327] 
[328]                     ver = 0;
[329]                     scale /= 100;
[330]                     continue;
[331]                 }
[332] 
[333]                 break;
[334]             }
[335] 
[336]             version += ver * scale;
[337] 
[338]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[339]                            "version: \"%ui\" \"%ui\"",
[340]                            modern[i].version, version);
[341] 
[342]             if (version >= modern[i].version) {
[343]                 return NGX_HTTP_MODERN_BROWSER;
[344]             }
[345] 
[346]             return NGX_HTTP_ANCIENT_BROWSER;
[347]         }
[348] 
[349]         if (!cf->modern_unlisted_browsers) {
[350]             return NGX_HTTP_ANCIENT_BROWSER;
[351]         }
[352]     }
[353] 
[354]     if (cf->netscape4) {
[355]         if (len > sizeof("Mozilla/4.72 ") - 1
[356]             && ngx_strncmp(ua, "Mozilla/", sizeof("Mozilla/") - 1) == 0
[357]             && ua[8] > '0' && ua[8] < '5')
[358]         {
[359]             return NGX_HTTP_ANCIENT_BROWSER;
[360]         }
[361]     }
[362] 
[363]     if (cf->ancient_browsers) {
[364]         ancient = cf->ancient_browsers->elts;
[365] 
[366]         for (i = 0; i < cf->ancient_browsers->nelts; i++) {
[367]             if (len >= ancient[i].len
[368]                 && ngx_strstr(ua, ancient[i].data) != NULL)
[369]             {
[370]                 return NGX_HTTP_ANCIENT_BROWSER;
[371]             }
[372]         }
[373]     }
[374] 
[375]     if (cf->modern_unlisted_browsers) {
[376]         return NGX_HTTP_MODERN_BROWSER;
[377]     }
[378] 
[379]     return NGX_HTTP_ANCIENT_BROWSER;
[380] }
[381] 
[382] 
[383] static ngx_int_t
[384] ngx_http_msie_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[385]     uintptr_t data)
[386] {
[387]     if (r->headers_in.msie) {
[388]         *v = ngx_http_variable_true_value;
[389]         return NGX_OK;
[390]     }
[391] 
[392]     *v = ngx_http_variable_null_value;
[393]     return NGX_OK;
[394] }
[395] 
[396] 
[397] static ngx_int_t
[398] ngx_http_browser_add_variables(ngx_conf_t *cf)
[399] {
[400]     ngx_http_variable_t  *var, *v;
[401] 
[402]     for (v = ngx_http_browser_vars; v->name.len; v++) {
[403] 
[404]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[405]         if (var == NULL) {
[406]             return NGX_ERROR;
[407]         }
[408] 
[409]         var->get_handler = v->get_handler;
[410]         var->data = v->data;
[411]     }
[412] 
[413]     return NGX_OK;
[414] }
[415] 
[416] 
[417] static void *
[418] ngx_http_browser_create_conf(ngx_conf_t *cf)
[419] {
[420]     ngx_http_browser_conf_t  *conf;
[421] 
[422]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_browser_conf_t));
[423]     if (conf == NULL) {
[424]         return NULL;
[425]     }
[426] 
[427]     /*
[428]      * set by ngx_pcalloc():
[429]      *
[430]      *     conf->modern_browsers = NULL;
[431]      *     conf->ancient_browsers = NULL;
[432]      *     conf->modern_browser_value = NULL;
[433]      *     conf->ancient_browser_value = NULL;
[434]      *
[435]      *     conf->modern_unlisted_browsers = 0;
[436]      *     conf->netscape4 = 0;
[437]      */
[438] 
[439]     return conf;
[440] }
[441] 
[442] 
[443] static char *
[444] ngx_http_browser_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[445] {
[446]     ngx_http_browser_conf_t *prev = parent;
[447]     ngx_http_browser_conf_t *conf = child;
[448] 
[449]     ngx_uint_t                  i, n;
[450]     ngx_http_modern_browser_t  *browsers, *opera;
[451] 
[452]     /*
[453]      * At the merge the skip field is used to store the browser slot,
[454]      * it will be used in sorting and then will overwritten
[455]      * with a real skip value.  The zero value means Opera.
[456]      */
[457] 
[458]     if (conf->modern_browsers == NULL && conf->modern_unlisted_browsers == 0) {
[459]         conf->modern_browsers = prev->modern_browsers;
[460]         conf->modern_unlisted_browsers = prev->modern_unlisted_browsers;
[461] 
[462]     } else if (conf->modern_browsers != NULL) {
[463]         browsers = conf->modern_browsers->elts;
[464] 
[465]         for (i = 0; i < conf->modern_browsers->nelts; i++) {
[466]             if (browsers[i].skip == 0) {
[467]                 goto found;
[468]             }
[469]         }
[470] 
[471]         /*
[472]          * Opera may contain MSIE string, so if Opera was not enumerated
[473]          * as modern browsers, then add it and set a unreachable version
[474]          */
[475] 
[476]         opera = ngx_array_push(conf->modern_browsers);
[477]         if (opera == NULL) {
[478]             return NGX_CONF_ERROR;
[479]         }
[480] 
[481]         opera->skip = 0;
[482]         opera->version = 4001000000U;
[483] 
[484]         browsers = conf->modern_browsers->elts;
[485] 
[486] found:
[487] 
[488]         ngx_qsort(browsers, (size_t) conf->modern_browsers->nelts,
[489]                   sizeof(ngx_http_modern_browser_t),
[490]                   ngx_http_modern_browser_sort);
[491] 
[492]         for (i = 0; i < conf->modern_browsers->nelts; i++) {
[493]              n = browsers[i].skip;
[494] 
[495]              browsers[i].skip = ngx_http_modern_browser_masks[n].skip;
[496]              browsers[i].add = ngx_http_modern_browser_masks[n].add;
[497]              (void) ngx_cpystrn(browsers[i].name,
[498]                                 ngx_http_modern_browser_masks[n].name, 12);
[499]         }
[500]     }
[501] 
[502]     if (conf->ancient_browsers == NULL && conf->netscape4 == 0) {
[503]         conf->ancient_browsers = prev->ancient_browsers;
[504]         conf->netscape4 = prev->netscape4;
[505]     }
[506] 
[507]     if (conf->modern_browser_value == NULL) {
[508]         conf->modern_browser_value = prev->modern_browser_value;
[509]     }
[510] 
[511]     if (conf->modern_browser_value == NULL) {
[512]         conf->modern_browser_value = &ngx_http_variable_true_value;
[513]     }
[514] 
[515]     if (conf->ancient_browser_value == NULL) {
[516]         conf->ancient_browser_value = prev->ancient_browser_value;
[517]     }
[518] 
[519]     if (conf->ancient_browser_value == NULL) {
[520]         conf->ancient_browser_value = &ngx_http_variable_true_value;
[521]     }
[522] 
[523]     return NGX_CONF_OK;
[524] }
[525] 
[526] 
[527] static int ngx_libc_cdecl
[528] ngx_http_modern_browser_sort(const void *one, const void *two)
[529] {
[530]     ngx_http_modern_browser_t *first = (ngx_http_modern_browser_t *) one;
[531]     ngx_http_modern_browser_t *second = (ngx_http_modern_browser_t *) two;
[532] 
[533]     return (first->skip - second->skip);
[534] }
[535] 
[536] 
[537] static char *
[538] ngx_http_modern_browser(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[539] {
[540]     ngx_http_browser_conf_t *bcf = conf;
[541] 
[542]     u_char                           c;
[543]     ngx_str_t                       *value;
[544]     ngx_uint_t                       i, n, version, ver, scale;
[545]     ngx_http_modern_browser_t       *browser;
[546]     ngx_http_modern_browser_mask_t  *mask;
[547] 
[548]     value = cf->args->elts;
[549] 
[550]     if (cf->args->nelts == 2) {
[551]         if (ngx_strcmp(value[1].data, "unlisted") == 0) {
[552]             bcf->modern_unlisted_browsers = 1;
[553]             return NGX_CONF_OK;
[554]         }
[555] 
[556]         return NGX_CONF_ERROR;
[557]     }
[558] 
[559]     if (bcf->modern_browsers == NULL) {
[560]         bcf->modern_browsers = ngx_array_create(cf->pool, 5,
[561]                                             sizeof(ngx_http_modern_browser_t));
[562]         if (bcf->modern_browsers == NULL) {
[563]             return NGX_CONF_ERROR;
[564]         }
[565]     }
[566] 
[567]     browser = ngx_array_push(bcf->modern_browsers);
[568]     if (browser == NULL) {
[569]         return NGX_CONF_ERROR;
[570]     }
[571] 
[572]     mask = ngx_http_modern_browser_masks;
[573] 
[574]     for (n = 0; mask[n].browser[0] != '\0'; n++) {
[575]         if (ngx_strcasecmp(mask[n].browser, value[1].data) == 0) {
[576]             goto found;
[577]         }
[578]     }
[579] 
[580]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[581]                        "unknown browser name \"%V\"", &value[1]);
[582] 
[583]     return NGX_CONF_ERROR;
[584] 
[585] found:
[586] 
[587]     /*
[588]      * at this stage the skip field is used to store the browser slot,
[589]      * it will be used in sorting in merge stage and then will overwritten
[590]      * with a real value
[591]      */
[592] 
[593]     browser->skip = n;
[594] 
[595]     version = 0;
[596]     ver = 0;
[597]     scale = 1000000;
[598] 
[599]     for (i = 0; i < value[2].len; i++) {
[600] 
[601]         c = value[2].data[i];
[602] 
[603]         if (c >= '0' && c <= '9') {
[604]             ver = ver * 10 + (c - '0');
[605]             continue;
[606]         }
[607] 
[608]         if (c == '.') {
[609]             version += ver * scale;
[610]             ver = 0;
[611]             scale /= 100;
[612]             continue;
[613]         }
[614] 
[615]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[616]                            "invalid browser version \"%V\"", &value[2]);
[617] 
[618]         return NGX_CONF_ERROR;
[619]     }
[620] 
[621]     version += ver * scale;
[622] 
[623]     browser->version = version;
[624] 
[625]     return NGX_CONF_OK;
[626] }
[627] 
[628] 
[629] static char *
[630] ngx_http_ancient_browser(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[631] {
[632]     ngx_http_browser_conf_t *bcf = conf;
[633] 
[634]     ngx_str_t   *value, *browser;
[635]     ngx_uint_t   i;
[636] 
[637]     value = cf->args->elts;
[638] 
[639]     for (i = 1; i < cf->args->nelts; i++) {
[640]         if (ngx_strcmp(value[i].data, "netscape4") == 0) {
[641]             bcf->netscape4 = 1;
[642]             continue;
[643]         }
[644] 
[645]         if (bcf->ancient_browsers == NULL) {
[646]             bcf->ancient_browsers = ngx_array_create(cf->pool, 4,
[647]                                                      sizeof(ngx_str_t));
[648]             if (bcf->ancient_browsers == NULL) {
[649]                 return NGX_CONF_ERROR;
[650]             }
[651]         }
[652] 
[653]         browser = ngx_array_push(bcf->ancient_browsers);
[654]         if (browser == NULL) {
[655]             return NGX_CONF_ERROR;
[656]         }
[657] 
[658]         *browser = value[i];
[659]     }
[660] 
[661]     return NGX_CONF_OK;
[662] }
[663] 
[664] 
[665] static char *
[666] ngx_http_modern_browser_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[667] {
[668]     ngx_http_browser_conf_t *bcf = conf;
[669] 
[670]     ngx_str_t  *value;
[671] 
[672]     bcf->modern_browser_value = ngx_palloc(cf->pool,
[673]                                            sizeof(ngx_http_variable_value_t));
[674]     if (bcf->modern_browser_value == NULL) {
[675]         return NGX_CONF_ERROR;
[676]     }
[677] 
[678]     value = cf->args->elts;
[679] 
[680]     bcf->modern_browser_value->len = value[1].len;
[681]     bcf->modern_browser_value->valid = 1;
[682]     bcf->modern_browser_value->no_cacheable = 0;
[683]     bcf->modern_browser_value->not_found = 0;
[684]     bcf->modern_browser_value->data = value[1].data;
[685] 
[686]     return NGX_CONF_OK;
[687] }
[688] 
[689] 
[690] static char *
[691] ngx_http_ancient_browser_value(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[692] {
[693]     ngx_http_browser_conf_t *bcf = conf;
[694] 
[695]     ngx_str_t  *value;
[696] 
[697]     bcf->ancient_browser_value = ngx_palloc(cf->pool,
[698]                                             sizeof(ngx_http_variable_value_t));
[699]     if (bcf->ancient_browser_value == NULL) {
[700]         return NGX_CONF_ERROR;
[701]     }
[702] 
[703]     value = cf->args->elts;
[704] 
[705]     bcf->ancient_browser_value->len = value[1].len;
[706]     bcf->ancient_browser_value->valid = 1;
[707]     bcf->ancient_browser_value->no_cacheable = 0;
[708]     bcf->ancient_browser_value->not_found = 0;
[709]     bcf->ancient_browser_value->data = value[1].data;
[710] 
[711]     return NGX_CONF_OK;
[712] }
