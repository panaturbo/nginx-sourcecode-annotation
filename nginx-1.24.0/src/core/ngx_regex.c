[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] typedef struct {
[13]     ngx_flag_t   pcre_jit;
[14]     ngx_list_t  *studies;
[15] } ngx_regex_conf_t;
[16] 
[17] 
[18] static ngx_inline void ngx_regex_malloc_init(ngx_pool_t *pool);
[19] static ngx_inline void ngx_regex_malloc_done(void);
[20] 
[21] #if (NGX_PCRE2)
[22] static void * ngx_libc_cdecl ngx_regex_malloc(size_t size, void *data);
[23] static void ngx_libc_cdecl ngx_regex_free(void *p, void *data);
[24] #else
[25] static void * ngx_libc_cdecl ngx_regex_malloc(size_t size);
[26] static void ngx_libc_cdecl ngx_regex_free(void *p);
[27] #endif
[28] static void ngx_regex_cleanup(void *data);
[29] 
[30] static ngx_int_t ngx_regex_module_init(ngx_cycle_t *cycle);
[31] 
[32] static void *ngx_regex_create_conf(ngx_cycle_t *cycle);
[33] static char *ngx_regex_init_conf(ngx_cycle_t *cycle, void *conf);
[34] 
[35] static char *ngx_regex_pcre_jit(ngx_conf_t *cf, void *post, void *data);
[36] static ngx_conf_post_t  ngx_regex_pcre_jit_post = { ngx_regex_pcre_jit };
[37] 
[38] 
[39] static ngx_command_t  ngx_regex_commands[] = {
[40] 
[41]     { ngx_string("pcre_jit"),
[42]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
[43]       ngx_conf_set_flag_slot,
[44]       0,
[45]       offsetof(ngx_regex_conf_t, pcre_jit),
[46]       &ngx_regex_pcre_jit_post },
[47] 
[48]       ngx_null_command
[49] };
[50] 
[51] 
[52] static ngx_core_module_t  ngx_regex_module_ctx = {
[53]     ngx_string("regex"),
[54]     ngx_regex_create_conf,
[55]     ngx_regex_init_conf
[56] };
[57] 
[58] 
[59] ngx_module_t  ngx_regex_module = {
[60]     NGX_MODULE_V1,
[61]     &ngx_regex_module_ctx,                 /* module context */
[62]     ngx_regex_commands,                    /* module directives */
[63]     NGX_CORE_MODULE,                       /* module type */
[64]     NULL,                                  /* init master */
[65]     ngx_regex_module_init,                 /* init module */
[66]     NULL,                                  /* init process */
[67]     NULL,                                  /* init thread */
[68]     NULL,                                  /* exit thread */
[69]     NULL,                                  /* exit process */
[70]     NULL,                                  /* exit master */
[71]     NGX_MODULE_V1_PADDING
[72] };
[73] 
[74] 
[75] static ngx_pool_t             *ngx_regex_pool;
[76] static ngx_list_t             *ngx_regex_studies;
[77] static ngx_uint_t              ngx_regex_direct_alloc;
[78] 
[79] #if (NGX_PCRE2)
[80] static pcre2_compile_context  *ngx_regex_compile_context;
[81] static pcre2_match_data       *ngx_regex_match_data;
[82] static ngx_uint_t              ngx_regex_match_data_size;
[83] #endif
[84] 
[85] 
[86] void
[87] ngx_regex_init(void)
[88] {
[89] #if !(NGX_PCRE2)
[90]     pcre_malloc = ngx_regex_malloc;
[91]     pcre_free = ngx_regex_free;
[92] #endif
[93] }
[94] 
[95] 
[96] static ngx_inline void
[97] ngx_regex_malloc_init(ngx_pool_t *pool)
[98] {
[99]     ngx_regex_pool = pool;
[100]     ngx_regex_direct_alloc = (pool == NULL) ? 1 : 0;
[101] }
[102] 
[103] 
[104] static ngx_inline void
[105] ngx_regex_malloc_done(void)
[106] {
[107]     ngx_regex_pool = NULL;
[108]     ngx_regex_direct_alloc = 0;
[109] }
[110] 
[111] 
[112] #if (NGX_PCRE2)
[113] 
[114] ngx_int_t
[115] ngx_regex_compile(ngx_regex_compile_t *rc)
[116] {
[117]     int                     n, errcode;
[118]     char                   *p;
[119]     u_char                  errstr[128];
[120]     size_t                  erroff;
[121]     uint32_t                options;
[122]     pcre2_code             *re;
[123]     ngx_regex_elt_t        *elt;
[124]     pcre2_general_context  *gctx;
[125]     pcre2_compile_context  *cctx;
[126] 
[127]     if (ngx_regex_compile_context == NULL) {
[128]         /*
[129]          * Allocate a compile context if not yet allocated.  This uses
[130]          * direct allocations from heap, so the result can be cached
[131]          * even at runtime.
[132]          */
[133] 
[134]         ngx_regex_malloc_init(NULL);
[135] 
[136]         gctx = pcre2_general_context_create(ngx_regex_malloc, ngx_regex_free,
[137]                                             NULL);
[138]         if (gctx == NULL) {
[139]             ngx_regex_malloc_done();
[140]             goto nomem;
[141]         }
[142] 
[143]         cctx = pcre2_compile_context_create(gctx);
[144]         if (cctx == NULL) {
[145]             pcre2_general_context_free(gctx);
[146]             ngx_regex_malloc_done();
[147]             goto nomem;
[148]         }
[149] 
[150]         ngx_regex_compile_context = cctx;
[151] 
[152]         pcre2_general_context_free(gctx);
[153]         ngx_regex_malloc_done();
[154]     }
[155] 
[156]     options = 0;
[157] 
[158]     if (rc->options & NGX_REGEX_CASELESS) {
[159]         options |= PCRE2_CASELESS;
[160]     }
[161] 
[162]     if (rc->options & NGX_REGEX_MULTILINE) {
[163]         options |= PCRE2_MULTILINE;
[164]     }
[165] 
[166]     if (rc->options & ~(NGX_REGEX_CASELESS|NGX_REGEX_MULTILINE)) {
[167]         rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[168]                             "regex \"%V\" compilation failed: invalid options",
[169]                             &rc->pattern)
[170]                       - rc->err.data;
[171]         return NGX_ERROR;
[172]     }
[173] 
[174]     ngx_regex_malloc_init(rc->pool);
[175] 
[176]     re = pcre2_compile(rc->pattern.data, rc->pattern.len, options,
[177]                        &errcode, &erroff, ngx_regex_compile_context);
[178] 
[179]     /* ensure that there is no current pool */
[180]     ngx_regex_malloc_done();
[181] 
[182]     if (re == NULL) {
[183]         pcre2_get_error_message(errcode, errstr, 128);
[184] 
[185]         if ((size_t) erroff == rc->pattern.len) {
[186]             rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[187]                               "pcre2_compile() failed: %s in \"%V\"",
[188]                                errstr, &rc->pattern)
[189]                           - rc->err.data;
[190] 
[191]         } else {
[192]             rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[193]                               "pcre2_compile() failed: %s in \"%V\" at \"%s\"",
[194]                                errstr, &rc->pattern, rc->pattern.data + erroff)
[195]                           - rc->err.data;
[196]         }
[197] 
[198]         return NGX_ERROR;
[199]     }
[200] 
[201]     rc->regex = re;
[202] 
[203]     /* do not study at runtime */
[204] 
[205]     if (ngx_regex_studies != NULL) {
[206]         elt = ngx_list_push(ngx_regex_studies);
[207]         if (elt == NULL) {
[208]             goto nomem;
[209]         }
[210] 
[211]         elt->regex = rc->regex;
[212]         elt->name = rc->pattern.data;
[213]     }
[214] 
[215]     n = pcre2_pattern_info(re, PCRE2_INFO_CAPTURECOUNT, &rc->captures);
[216]     if (n < 0) {
[217]         p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_CAPTURECOUNT) failed: %d";
[218]         goto failed;
[219]     }
[220] 
[221]     if (rc->captures == 0) {
[222]         return NGX_OK;
[223]     }
[224] 
[225]     n = pcre2_pattern_info(re, PCRE2_INFO_NAMECOUNT, &rc->named_captures);
[226]     if (n < 0) {
[227]         p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_NAMECOUNT) failed: %d";
[228]         goto failed;
[229]     }
[230] 
[231]     if (rc->named_captures == 0) {
[232]         return NGX_OK;
[233]     }
[234] 
[235]     n = pcre2_pattern_info(re, PCRE2_INFO_NAMEENTRYSIZE, &rc->name_size);
[236]     if (n < 0) {
[237]         p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_NAMEENTRYSIZE) failed: %d";
[238]         goto failed;
[239]     }
[240] 
[241]     n = pcre2_pattern_info(re, PCRE2_INFO_NAMETABLE, &rc->names);
[242]     if (n < 0) {
[243]         p = "pcre2_pattern_info(\"%V\", PCRE2_INFO_NAMETABLE) failed: %d";
[244]         goto failed;
[245]     }
[246] 
[247]     return NGX_OK;
[248] 
[249] failed:
[250] 
[251]     rc->err.len = ngx_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
[252]                   - rc->err.data;
[253]     return NGX_ERROR;
[254] 
[255] nomem:
[256] 
[257]     rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[258]                                "regex \"%V\" compilation failed: no memory",
[259]                                &rc->pattern)
[260]                   - rc->err.data;
[261]     return NGX_ERROR;
[262] }
[263] 
[264] #else
[265] 
[266] ngx_int_t
[267] ngx_regex_compile(ngx_regex_compile_t *rc)
[268] {
[269]     int               n, erroff;
[270]     char             *p;
[271]     pcre             *re;
[272]     const char       *errstr;
[273]     ngx_uint_t        options;
[274]     ngx_regex_elt_t  *elt;
[275] 
[276]     options = 0;
[277] 
[278]     if (rc->options & NGX_REGEX_CASELESS) {
[279]         options |= PCRE_CASELESS;
[280]     }
[281] 
[282]     if (rc->options & NGX_REGEX_MULTILINE) {
[283]         options |= PCRE_MULTILINE;
[284]     }
[285] 
[286]     if (rc->options & ~(NGX_REGEX_CASELESS|NGX_REGEX_MULTILINE)) {
[287]         rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[288]                             "regex \"%V\" compilation failed: invalid options",
[289]                             &rc->pattern)
[290]                       - rc->err.data;
[291]         return NGX_ERROR;
[292]     }
[293] 
[294]     ngx_regex_malloc_init(rc->pool);
[295] 
[296]     re = pcre_compile((const char *) rc->pattern.data, (int) options,
[297]                       &errstr, &erroff, NULL);
[298] 
[299]     /* ensure that there is no current pool */
[300]     ngx_regex_malloc_done();
[301] 
[302]     if (re == NULL) {
[303]         if ((size_t) erroff == rc->pattern.len) {
[304]            rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[305]                               "pcre_compile() failed: %s in \"%V\"",
[306]                                errstr, &rc->pattern)
[307]                          - rc->err.data;
[308] 
[309]         } else {
[310]            rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[311]                               "pcre_compile() failed: %s in \"%V\" at \"%s\"",
[312]                                errstr, &rc->pattern, rc->pattern.data + erroff)
[313]                          - rc->err.data;
[314]         }
[315] 
[316]         return NGX_ERROR;
[317]     }
[318] 
[319]     rc->regex = ngx_pcalloc(rc->pool, sizeof(ngx_regex_t));
[320]     if (rc->regex == NULL) {
[321]         goto nomem;
[322]     }
[323] 
[324]     rc->regex->code = re;
[325] 
[326]     /* do not study at runtime */
[327] 
[328]     if (ngx_regex_studies != NULL) {
[329]         elt = ngx_list_push(ngx_regex_studies);
[330]         if (elt == NULL) {
[331]             goto nomem;
[332]         }
[333] 
[334]         elt->regex = rc->regex;
[335]         elt->name = rc->pattern.data;
[336]     }
[337] 
[338]     n = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &rc->captures);
[339]     if (n < 0) {
[340]         p = "pcre_fullinfo(\"%V\", PCRE_INFO_CAPTURECOUNT) failed: %d";
[341]         goto failed;
[342]     }
[343] 
[344]     if (rc->captures == 0) {
[345]         return NGX_OK;
[346]     }
[347] 
[348]     n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMECOUNT, &rc->named_captures);
[349]     if (n < 0) {
[350]         p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMECOUNT) failed: %d";
[351]         goto failed;
[352]     }
[353] 
[354]     if (rc->named_captures == 0) {
[355]         return NGX_OK;
[356]     }
[357] 
[358]     n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMEENTRYSIZE, &rc->name_size);
[359]     if (n < 0) {
[360]         p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMEENTRYSIZE) failed: %d";
[361]         goto failed;
[362]     }
[363] 
[364]     n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMETABLE, &rc->names);
[365]     if (n < 0) {
[366]         p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMETABLE) failed: %d";
[367]         goto failed;
[368]     }
[369] 
[370]     return NGX_OK;
[371] 
[372] failed:
[373] 
[374]     rc->err.len = ngx_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
[375]                   - rc->err.data;
[376]     return NGX_ERROR;
[377] 
[378] nomem:
[379] 
[380]     rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
[381]                                "regex \"%V\" compilation failed: no memory",
[382]                                &rc->pattern)
[383]                   - rc->err.data;
[384]     return NGX_ERROR;
[385] }
[386] 
[387] #endif
[388] 
[389] 
[390] #if (NGX_PCRE2)
[391] 
[392] ngx_int_t
[393] ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures, ngx_uint_t size)
[394] {
[395]     size_t      *ov;
[396]     ngx_int_t    rc;
[397]     ngx_uint_t   n, i;
[398] 
[399]     /*
[400]      * The pcre2_match() function might allocate memory for backtracking
[401]      * frames, typical allocations are from 40k and above.  So the allocator
[402]      * is configured to do direct allocations from heap during matching.
[403]      */
[404] 
[405]     ngx_regex_malloc_init(NULL);
[406] 
[407]     if (ngx_regex_match_data == NULL
[408]         || size > ngx_regex_match_data_size)
[409]     {
[410]         /*
[411]          * Allocate a match data if not yet allocated or smaller than
[412]          * needed.
[413]          */
[414] 
[415]         if (ngx_regex_match_data) {
[416]             pcre2_match_data_free(ngx_regex_match_data);
[417]         }
[418] 
[419]         ngx_regex_match_data_size = size;
[420]         ngx_regex_match_data = pcre2_match_data_create(size / 3, NULL);
[421] 
[422]         if (ngx_regex_match_data == NULL) {
[423]             rc = PCRE2_ERROR_NOMEMORY;
[424]             goto failed;
[425]         }
[426]     }
[427] 
[428]     rc = pcre2_match(re, s->data, s->len, 0, 0, ngx_regex_match_data, NULL);
[429] 
[430]     if (rc < 0) {
[431]         goto failed;
[432]     }
[433] 
[434]     n = pcre2_get_ovector_count(ngx_regex_match_data);
[435]     ov = pcre2_get_ovector_pointer(ngx_regex_match_data);
[436] 
[437]     if (n > size / 3) {
[438]         n = size / 3;
[439]     }
[440] 
[441]     for (i = 0; i < n; i++) {
[442]         captures[i * 2] = ov[i * 2];
[443]         captures[i * 2 + 1] = ov[i * 2 + 1];
[444]     }
[445] 
[446] failed:
[447] 
[448]     ngx_regex_malloc_done();
[449] 
[450]     return rc;
[451] }
[452] 
[453] #else
[454] 
[455] ngx_int_t
[456] ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures, ngx_uint_t size)
[457] {
[458]     return pcre_exec(re->code, re->extra, (const char *) s->data, s->len,
[459]                      0, 0, captures, size);
[460] }
[461] 
[462] #endif
[463] 
[464] 
[465] ngx_int_t
[466] ngx_regex_exec_array(ngx_array_t *a, ngx_str_t *s, ngx_log_t *log)
[467] {
[468]     ngx_int_t         n;
[469]     ngx_uint_t        i;
[470]     ngx_regex_elt_t  *re;
[471] 
[472]     re = a->elts;
[473] 
[474]     for (i = 0; i < a->nelts; i++) {
[475] 
[476]         n = ngx_regex_exec(re[i].regex, s, NULL, 0);
[477] 
[478]         if (n == NGX_REGEX_NO_MATCHED) {
[479]             continue;
[480]         }
[481] 
[482]         if (n < 0) {
[483]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[484]                           ngx_regex_exec_n " failed: %i on \"%V\" using \"%s\"",
[485]                           n, s, re[i].name);
[486]             return NGX_ERROR;
[487]         }
[488] 
[489]         /* match */
[490] 
[491]         return NGX_OK;
[492]     }
[493] 
[494]     return NGX_DECLINED;
[495] }
[496] 
[497] 
[498] #if (NGX_PCRE2)
[499] 
[500] static void * ngx_libc_cdecl
[501] ngx_regex_malloc(size_t size, void *data)
[502] {
[503]     if (ngx_regex_pool) {
[504]         return ngx_palloc(ngx_regex_pool, size);
[505]     }
[506] 
[507]     if (ngx_regex_direct_alloc) {
[508]         return ngx_alloc(size, ngx_cycle->log);
[509]     }
[510] 
[511]     return NULL;
[512] }
[513] 
[514] 
[515] static void ngx_libc_cdecl
[516] ngx_regex_free(void *p, void *data)
[517] {
[518]     if (ngx_regex_direct_alloc) {
[519]         ngx_free(p);
[520]     }
[521] 
[522]     return;
[523] }
[524] 
[525] #else
[526] 
[527] static void * ngx_libc_cdecl
[528] ngx_regex_malloc(size_t size)
[529] {
[530]     if (ngx_regex_pool) {
[531]         return ngx_palloc(ngx_regex_pool, size);
[532]     }
[533] 
[534]     return NULL;
[535] }
[536] 
[537] 
[538] static void ngx_libc_cdecl
[539] ngx_regex_free(void *p)
[540] {
[541]     return;
[542] }
[543] 
[544] #endif
[545] 
[546] 
[547] static void
[548] ngx_regex_cleanup(void *data)
[549] {
[550] #if (NGX_PCRE2 || NGX_HAVE_PCRE_JIT)
[551]     ngx_regex_conf_t *rcf = data;
[552] 
[553]     ngx_uint_t        i;
[554]     ngx_list_part_t  *part;
[555]     ngx_regex_elt_t  *elts;
[556] 
[557]     part = &rcf->studies->part;
[558]     elts = part->elts;
[559] 
[560]     for (i = 0; /* void */ ; i++) {
[561] 
[562]         if (i >= part->nelts) {
[563]             if (part->next == NULL) {
[564]                 break;
[565]             }
[566] 
[567]             part = part->next;
[568]             elts = part->elts;
[569]             i = 0;
[570]         }
[571] 
[572]         /*
[573]          * The PCRE JIT compiler uses mmap for its executable codes, so we
[574]          * have to explicitly call the pcre_free_study() function to free
[575]          * this memory.  In PCRE2, we call the pcre2_code_free() function
[576]          * for the same reason.
[577]          */
[578] 
[579] #if (NGX_PCRE2)
[580]         pcre2_code_free(elts[i].regex);
[581] #else
[582]         if (elts[i].regex->extra != NULL) {
[583]             pcre_free_study(elts[i].regex->extra);
[584]         }
[585] #endif
[586]     }
[587] #endif
[588] 
[589]     /*
[590]      * On configuration parsing errors ngx_regex_module_init() will not
[591]      * be called.  Make sure ngx_regex_studies is properly cleared anyway.
[592]      */
[593] 
[594]     ngx_regex_studies = NULL;
[595] 
[596] #if (NGX_PCRE2)
[597] 
[598]     /*
[599]      * Free compile context and match data.  If needed at runtime by
[600]      * the new cycle, these will be re-allocated.
[601]      */
[602] 
[603]     if (ngx_regex_compile_context) {
[604]         pcre2_compile_context_free(ngx_regex_compile_context);
[605]         ngx_regex_compile_context = NULL;
[606]     }
[607] 
[608]     if (ngx_regex_match_data) {
[609]         pcre2_match_data_free(ngx_regex_match_data);
[610]         ngx_regex_match_data = NULL;
[611]         ngx_regex_match_data_size = 0;
[612]     }
[613] 
[614] #endif
[615] }
[616] 
[617] 
[618] static ngx_int_t
[619] ngx_regex_module_init(ngx_cycle_t *cycle)
[620] {
[621]     int                opt;
[622] #if !(NGX_PCRE2)
[623]     const char        *errstr;
[624] #endif
[625]     ngx_uint_t         i;
[626]     ngx_list_part_t   *part;
[627]     ngx_regex_elt_t   *elts;
[628]     ngx_regex_conf_t  *rcf;
[629] 
[630]     opt = 0;
[631] 
[632]     rcf = (ngx_regex_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_regex_module);
[633] 
[634] #if (NGX_PCRE2 || NGX_HAVE_PCRE_JIT)
[635] 
[636]     if (rcf->pcre_jit) {
[637] #if (NGX_PCRE2)
[638]         opt = 1;
[639] #else
[640]         opt = PCRE_STUDY_JIT_COMPILE;
[641] #endif
[642]     }
[643] 
[644] #endif
[645] 
[646]     ngx_regex_malloc_init(cycle->pool);
[647] 
[648]     part = &rcf->studies->part;
[649]     elts = part->elts;
[650] 
[651]     for (i = 0; /* void */ ; i++) {
[652] 
[653]         if (i >= part->nelts) {
[654]             if (part->next == NULL) {
[655]                 break;
[656]             }
[657] 
[658]             part = part->next;
[659]             elts = part->elts;
[660]             i = 0;
[661]         }
[662] 
[663] #if (NGX_PCRE2)
[664] 
[665]         if (opt) {
[666]             int  n;
[667] 
[668]             n = pcre2_jit_compile(elts[i].regex, PCRE2_JIT_COMPLETE);
[669] 
[670]             if (n != 0) {
[671]                 ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
[672]                               "pcre2_jit_compile() failed: %d in \"%s\", "
[673]                               "ignored",
[674]                               n, elts[i].name);
[675]             }
[676]         }
[677] 
[678] #else
[679] 
[680]         elts[i].regex->extra = pcre_study(elts[i].regex->code, opt, &errstr);
[681] 
[682]         if (errstr != NULL) {
[683]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[684]                           "pcre_study() failed: %s in \"%s\"",
[685]                           errstr, elts[i].name);
[686]         }
[687] 
[688] #if (NGX_HAVE_PCRE_JIT)
[689]         if (opt & PCRE_STUDY_JIT_COMPILE) {
[690]             int jit, n;
[691] 
[692]             jit = 0;
[693]             n = pcre_fullinfo(elts[i].regex->code, elts[i].regex->extra,
[694]                               PCRE_INFO_JIT, &jit);
[695] 
[696]             if (n != 0 || jit != 1) {
[697]                 ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
[698]                               "JIT compiler does not support pattern: \"%s\"",
[699]                               elts[i].name);
[700]             }
[701]         }
[702] #endif
[703] #endif
[704]     }
[705] 
[706]     ngx_regex_malloc_done();
[707] 
[708]     ngx_regex_studies = NULL;
[709] #if (NGX_PCRE2)
[710]     ngx_regex_compile_context = NULL;
[711] #endif
[712] 
[713]     return NGX_OK;
[714] }
[715] 
[716] 
[717] static void *
[718] ngx_regex_create_conf(ngx_cycle_t *cycle)
[719] {
[720]     ngx_regex_conf_t    *rcf;
[721]     ngx_pool_cleanup_t  *cln;
[722] 
[723]     rcf = ngx_pcalloc(cycle->pool, sizeof(ngx_regex_conf_t));
[724]     if (rcf == NULL) {
[725]         return NULL;
[726]     }
[727] 
[728]     rcf->pcre_jit = NGX_CONF_UNSET;
[729] 
[730]     cln = ngx_pool_cleanup_add(cycle->pool, 0);
[731]     if (cln == NULL) {
[732]         return NULL;
[733]     }
[734] 
[735]     cln->handler = ngx_regex_cleanup;
[736]     cln->data = rcf;
[737] 
[738]     rcf->studies = ngx_list_create(cycle->pool, 8, sizeof(ngx_regex_elt_t));
[739]     if (rcf->studies == NULL) {
[740]         return NULL;
[741]     }
[742] 
[743]     ngx_regex_studies = rcf->studies;
[744] 
[745]     return rcf;
[746] }
[747] 
[748] 
[749] static char *
[750] ngx_regex_init_conf(ngx_cycle_t *cycle, void *conf)
[751] {
[752]     ngx_regex_conf_t *rcf = conf;
[753] 
[754]     ngx_conf_init_value(rcf->pcre_jit, 0);
[755] 
[756]     return NGX_CONF_OK;
[757] }
[758] 
[759] 
[760] static char *
[761] ngx_regex_pcre_jit(ngx_conf_t *cf, void *post, void *data)
[762] {
[763]     ngx_flag_t  *fp = data;
[764] 
[765]     if (*fp == 0) {
[766]         return NGX_CONF_OK;
[767]     }
[768] 
[769] #if (NGX_PCRE2)
[770]     {
[771]     int       r;
[772]     uint32_t  jit;
[773] 
[774]     jit = 0;
[775]     r = pcre2_config(PCRE2_CONFIG_JIT, &jit);
[776] 
[777]     if (r != 0 || jit != 1) {
[778]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[779]                            "PCRE2 library does not support JIT");
[780]         *fp = 0;
[781]     }
[782]     }
[783] #elif (NGX_HAVE_PCRE_JIT)
[784]     {
[785]     int  jit, r;
[786] 
[787]     jit = 0;
[788]     r = pcre_config(PCRE_CONFIG_JIT, &jit);
[789] 
[790]     if (r != 0 || jit != 1) {
[791]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[792]                            "PCRE library does not support JIT");
[793]         *fp = 0;
[794]     }
[795]     }
[796] #else
[797]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[798]                        "nginx was built without PCRE JIT support");
[799]     *fp = 0;
[800] #endif
[801] 
[802]     return NGX_CONF_OK;
[803] }
