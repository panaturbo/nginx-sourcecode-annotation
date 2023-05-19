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
[13] static ngx_int_t ngx_http_script_init_arrays(ngx_http_script_compile_t *sc);
[14] static ngx_int_t ngx_http_script_done(ngx_http_script_compile_t *sc);
[15] static ngx_int_t ngx_http_script_add_copy_code(ngx_http_script_compile_t *sc,
[16]     ngx_str_t *value, ngx_uint_t last);
[17] static ngx_int_t ngx_http_script_add_var_code(ngx_http_script_compile_t *sc,
[18]     ngx_str_t *name);
[19] static ngx_int_t ngx_http_script_add_args_code(ngx_http_script_compile_t *sc);
[20] #if (NGX_PCRE)
[21] static ngx_int_t ngx_http_script_add_capture_code(ngx_http_script_compile_t *sc,
[22]     ngx_uint_t n);
[23] #endif
[24] static ngx_int_t
[25]     ngx_http_script_add_full_name_code(ngx_http_script_compile_t *sc);
[26] static size_t ngx_http_script_full_name_len_code(ngx_http_script_engine_t *e);
[27] static void ngx_http_script_full_name_code(ngx_http_script_engine_t *e);
[28] 
[29] 
[30] #define ngx_http_script_exit  (u_char *) &ngx_http_script_exit_code
[31] 
[32] static uintptr_t ngx_http_script_exit_code = (uintptr_t) NULL;
[33] 
[34] 
[35] void
[36] ngx_http_script_flush_complex_value(ngx_http_request_t *r,
[37]     ngx_http_complex_value_t *val)
[38] {
[39]     ngx_uint_t *index;
[40] 
[41]     index = val->flushes;
[42] 
[43]     if (index) {
[44]         while (*index != (ngx_uint_t) -1) {
[45] 
[46]             if (r->variables[*index].no_cacheable) {
[47]                 r->variables[*index].valid = 0;
[48]                 r->variables[*index].not_found = 0;
[49]             }
[50] 
[51]             index++;
[52]         }
[53]     }
[54] }
[55] 
[56] 
[57] ngx_int_t
[58] ngx_http_complex_value(ngx_http_request_t *r, ngx_http_complex_value_t *val,
[59]     ngx_str_t *value)
[60] {
[61]     size_t                        len;
[62]     ngx_http_script_code_pt       code;
[63]     ngx_http_script_len_code_pt   lcode;
[64]     ngx_http_script_engine_t      e;
[65] 
[66]     if (val->lengths == NULL) {
[67]         *value = val->value;
[68]         return NGX_OK;
[69]     }
[70] 
[71]     ngx_http_script_flush_complex_value(r, val);
[72] 
[73]     ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[74] 
[75]     e.ip = val->lengths;
[76]     e.request = r;
[77]     e.flushed = 1;
[78] 
[79]     len = 0;
[80] 
[81]     while (*(uintptr_t *) e.ip) {
[82]         lcode = *(ngx_http_script_len_code_pt *) e.ip;
[83]         len += lcode(&e);
[84]     }
[85] 
[86]     value->len = len;
[87]     value->data = ngx_pnalloc(r->pool, len);
[88]     if (value->data == NULL) {
[89]         return NGX_ERROR;
[90]     }
[91] 
[92]     e.ip = val->values;
[93]     e.pos = value->data;
[94]     e.buf = *value;
[95] 
[96]     while (*(uintptr_t *) e.ip) {
[97]         code = *(ngx_http_script_code_pt *) e.ip;
[98]         code((ngx_http_script_engine_t *) &e);
[99]     }
[100] 
[101]     *value = e.buf;
[102] 
[103]     return NGX_OK;
[104] }
[105] 
[106] 
[107] size_t
[108] ngx_http_complex_value_size(ngx_http_request_t *r,
[109]     ngx_http_complex_value_t *val, size_t default_value)
[110] {
[111]     size_t     size;
[112]     ngx_str_t  value;
[113] 
[114]     if (val == NULL) {
[115]         return default_value;
[116]     }
[117] 
[118]     if (val->lengths == NULL) {
[119]         return val->u.size;
[120]     }
[121] 
[122]     if (ngx_http_complex_value(r, val, &value) != NGX_OK) {
[123]         return default_value;
[124]     }
[125] 
[126]     size = ngx_parse_size(&value);
[127] 
[128]     if (size == (size_t) NGX_ERROR) {
[129]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[130]                       "invalid size \"%V\"", &value);
[131]         return default_value;
[132]     }
[133] 
[134]     return size;
[135] }
[136] 
[137] 
[138] ngx_int_t
[139] ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv)
[140] {
[141]     ngx_str_t                  *v;
[142]     ngx_uint_t                  i, n, nv, nc;
[143]     ngx_array_t                 flushes, lengths, values, *pf, *pl, *pv;
[144]     ngx_http_script_compile_t   sc;
[145] 
[146]     v = ccv->value;
[147] 
[148]     nv = 0;
[149]     nc = 0;
[150] 
[151]     for (i = 0; i < v->len; i++) {
[152]         if (v->data[i] == '$') {
[153]             if (v->data[i + 1] >= '1' && v->data[i + 1] <= '9') {
[154]                 nc++;
[155] 
[156]             } else {
[157]                 nv++;
[158]             }
[159]         }
[160]     }
[161] 
[162]     if ((v->len == 0 || v->data[0] != '$')
[163]         && (ccv->conf_prefix || ccv->root_prefix))
[164]     {
[165]         if (ngx_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != NGX_OK) {
[166]             return NGX_ERROR;
[167]         }
[168] 
[169]         ccv->conf_prefix = 0;
[170]         ccv->root_prefix = 0;
[171]     }
[172] 
[173]     ccv->complex_value->value = *v;
[174]     ccv->complex_value->flushes = NULL;
[175]     ccv->complex_value->lengths = NULL;
[176]     ccv->complex_value->values = NULL;
[177] 
[178]     if (nv == 0 && nc == 0) {
[179]         return NGX_OK;
[180]     }
[181] 
[182]     n = nv + 1;
[183] 
[184]     if (ngx_array_init(&flushes, ccv->cf->pool, n, sizeof(ngx_uint_t))
[185]         != NGX_OK)
[186]     {
[187]         return NGX_ERROR;
[188]     }
[189] 
[190]     n = nv * (2 * sizeof(ngx_http_script_copy_code_t)
[191]                   + sizeof(ngx_http_script_var_code_t))
[192]         + sizeof(uintptr_t);
[193] 
[194]     if (ngx_array_init(&lengths, ccv->cf->pool, n, 1) != NGX_OK) {
[195]         return NGX_ERROR;
[196]     }
[197] 
[198]     n = (nv * (2 * sizeof(ngx_http_script_copy_code_t)
[199]                    + sizeof(ngx_http_script_var_code_t))
[200]                 + sizeof(uintptr_t)
[201]                 + v->len
[202]                 + sizeof(uintptr_t) - 1)
[203]             & ~(sizeof(uintptr_t) - 1);
[204] 
[205]     if (ngx_array_init(&values, ccv->cf->pool, n, 1) != NGX_OK) {
[206]         return NGX_ERROR;
[207]     }
[208] 
[209]     pf = &flushes;
[210]     pl = &lengths;
[211]     pv = &values;
[212] 
[213]     ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
[214] 
[215]     sc.cf = ccv->cf;
[216]     sc.source = v;
[217]     sc.flushes = &pf;
[218]     sc.lengths = &pl;
[219]     sc.values = &pv;
[220]     sc.complete_lengths = 1;
[221]     sc.complete_values = 1;
[222]     sc.zero = ccv->zero;
[223]     sc.conf_prefix = ccv->conf_prefix;
[224]     sc.root_prefix = ccv->root_prefix;
[225] 
[226]     if (ngx_http_script_compile(&sc) != NGX_OK) {
[227]         return NGX_ERROR;
[228]     }
[229] 
[230]     if (flushes.nelts) {
[231]         ccv->complex_value->flushes = flushes.elts;
[232]         ccv->complex_value->flushes[flushes.nelts] = (ngx_uint_t) -1;
[233]     }
[234] 
[235]     ccv->complex_value->lengths = lengths.elts;
[236]     ccv->complex_value->values = values.elts;
[237] 
[238]     return NGX_OK;
[239] }
[240] 
[241] 
[242] char *
[243] ngx_http_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[244] {
[245]     char  *p = conf;
[246] 
[247]     ngx_str_t                          *value;
[248]     ngx_http_complex_value_t          **cv;
[249]     ngx_http_compile_complex_value_t    ccv;
[250] 
[251]     cv = (ngx_http_complex_value_t **) (p + cmd->offset);
[252] 
[253]     if (*cv != NGX_CONF_UNSET_PTR && *cv != NULL) {
[254]         return "is duplicate";
[255]     }
[256] 
[257]     *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[258]     if (*cv == NULL) {
[259]         return NGX_CONF_ERROR;
[260]     }
[261] 
[262]     value = cf->args->elts;
[263] 
[264]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[265] 
[266]     ccv.cf = cf;
[267]     ccv.value = &value[1];
[268]     ccv.complex_value = *cv;
[269] 
[270]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[271]         return NGX_CONF_ERROR;
[272]     }
[273] 
[274]     return NGX_CONF_OK;
[275] }
[276] 
[277] 
[278] char *
[279] ngx_http_set_complex_value_zero_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[280]     void *conf)
[281] {
[282]     char  *p = conf;
[283] 
[284]     ngx_str_t                          *value;
[285]     ngx_http_complex_value_t          **cv;
[286]     ngx_http_compile_complex_value_t    ccv;
[287] 
[288]     cv = (ngx_http_complex_value_t **) (p + cmd->offset);
[289] 
[290]     if (*cv != NGX_CONF_UNSET_PTR) {
[291]         return "is duplicate";
[292]     }
[293] 
[294]     *cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[295]     if (*cv == NULL) {
[296]         return NGX_CONF_ERROR;
[297]     }
[298] 
[299]     value = cf->args->elts;
[300] 
[301]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[302] 
[303]     ccv.cf = cf;
[304]     ccv.value = &value[1];
[305]     ccv.complex_value = *cv;
[306]     ccv.zero = 1;
[307] 
[308]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[309]         return NGX_CONF_ERROR;
[310]     }
[311] 
[312]     return NGX_CONF_OK;
[313] }
[314] 
[315] 
[316] char *
[317] ngx_http_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[318]     void *conf)
[319] {
[320]     char  *p = conf;
[321] 
[322]     char                      *rv;
[323]     ngx_http_complex_value_t  *cv;
[324] 
[325]     rv = ngx_http_set_complex_value_slot(cf, cmd, conf);
[326] 
[327]     if (rv != NGX_CONF_OK) {
[328]         return rv;
[329]     }
[330] 
[331]     cv = *(ngx_http_complex_value_t **) (p + cmd->offset);
[332] 
[333]     if (cv->lengths) {
[334]         return NGX_CONF_OK;
[335]     }
[336] 
[337]     cv->u.size = ngx_parse_size(&cv->value);
[338]     if (cv->u.size == (size_t) NGX_ERROR) {
[339]         return "invalid value";
[340]     }
[341] 
[342]     return NGX_CONF_OK;
[343] }
[344] 
[345] 
[346] ngx_int_t
[347] ngx_http_test_predicates(ngx_http_request_t *r, ngx_array_t *predicates)
[348] {
[349]     ngx_str_t                  val;
[350]     ngx_uint_t                 i;
[351]     ngx_http_complex_value_t  *cv;
[352] 
[353]     if (predicates == NULL) {
[354]         return NGX_OK;
[355]     }
[356] 
[357]     cv = predicates->elts;
[358] 
[359]     for (i = 0; i < predicates->nelts; i++) {
[360]         if (ngx_http_complex_value(r, &cv[i], &val) != NGX_OK) {
[361]             return NGX_ERROR;
[362]         }
[363] 
[364]         if (val.len && (val.len != 1 || val.data[0] != '0')) {
[365]             return NGX_DECLINED;
[366]         }
[367]     }
[368] 
[369]     return NGX_OK;
[370] }
[371] 
[372] 
[373] ngx_int_t
[374] ngx_http_test_required_predicates(ngx_http_request_t *r,
[375]     ngx_array_t *predicates)
[376] {
[377]     ngx_str_t                  val;
[378]     ngx_uint_t                 i;
[379]     ngx_http_complex_value_t  *cv;
[380] 
[381]     if (predicates == NULL) {
[382]         return NGX_OK;
[383]     }
[384] 
[385]     cv = predicates->elts;
[386] 
[387]     for (i = 0; i < predicates->nelts; i++) {
[388]         if (ngx_http_complex_value(r, &cv[i], &val) != NGX_OK) {
[389]             return NGX_ERROR;
[390]         }
[391] 
[392]         if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
[393]             return NGX_DECLINED;
[394]         }
[395]     }
[396] 
[397]     return NGX_OK;
[398] }
[399] 
[400] 
[401] char *
[402] ngx_http_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[403] {
[404]     char  *p = conf;
[405] 
[406]     ngx_str_t                          *value;
[407]     ngx_uint_t                          i;
[408]     ngx_array_t                       **a;
[409]     ngx_http_complex_value_t           *cv;
[410]     ngx_http_compile_complex_value_t    ccv;
[411] 
[412]     a = (ngx_array_t **) (p + cmd->offset);
[413] 
[414]     if (*a == NGX_CONF_UNSET_PTR) {
[415]         *a = ngx_array_create(cf->pool, 1, sizeof(ngx_http_complex_value_t));
[416]         if (*a == NULL) {
[417]             return NGX_CONF_ERROR;
[418]         }
[419]     }
[420] 
[421]     value = cf->args->elts;
[422] 
[423]     for (i = 1; i < cf->args->nelts; i++) {
[424]         cv = ngx_array_push(*a);
[425]         if (cv == NULL) {
[426]             return NGX_CONF_ERROR;
[427]         }
[428] 
[429]         ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[430] 
[431]         ccv.cf = cf;
[432]         ccv.value = &value[i];
[433]         ccv.complex_value = cv;
[434] 
[435]         if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[436]             return NGX_CONF_ERROR;
[437]         }
[438]     }
[439] 
[440]     return NGX_CONF_OK;
[441] }
[442] 
[443] 
[444] ngx_uint_t
[445] ngx_http_script_variables_count(ngx_str_t *value)
[446] {
[447]     ngx_uint_t  i, n;
[448] 
[449]     for (n = 0, i = 0; i < value->len; i++) {
[450]         if (value->data[i] == '$') {
[451]             n++;
[452]         }
[453]     }
[454] 
[455]     return n;
[456] }
[457] 
[458] 
[459] ngx_int_t
[460] ngx_http_script_compile(ngx_http_script_compile_t *sc)
[461] {
[462]     u_char       ch;
[463]     ngx_str_t    name;
[464]     ngx_uint_t   i, bracket;
[465] 
[466]     if (ngx_http_script_init_arrays(sc) != NGX_OK) {
[467]         return NGX_ERROR;
[468]     }
[469] 
[470]     for (i = 0; i < sc->source->len; /* void */ ) {
[471] 
[472]         name.len = 0;
[473] 
[474]         if (sc->source->data[i] == '$') {
[475] 
[476]             if (++i == sc->source->len) {
[477]                 goto invalid_variable;
[478]             }
[479] 
[480]             if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {
[481] #if (NGX_PCRE)
[482]                 ngx_uint_t  n;
[483] 
[484]                 n = sc->source->data[i] - '0';
[485] 
[486]                 if (sc->captures_mask & ((ngx_uint_t) 1 << n)) {
[487]                     sc->dup_capture = 1;
[488]                 }
[489] 
[490]                 sc->captures_mask |= (ngx_uint_t) 1 << n;
[491] 
[492]                 if (ngx_http_script_add_capture_code(sc, n) != NGX_OK) {
[493]                     return NGX_ERROR;
[494]                 }
[495] 
[496]                 i++;
[497] 
[498]                 continue;
[499] #else
[500]                 ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
[501]                                    "using variable \"$%c\" requires "
[502]                                    "PCRE library", sc->source->data[i]);
[503]                 return NGX_ERROR;
[504] #endif
[505]             }
[506] 
[507]             if (sc->source->data[i] == '{') {
[508]                 bracket = 1;
[509] 
[510]                 if (++i == sc->source->len) {
[511]                     goto invalid_variable;
[512]                 }
[513] 
[514]                 name.data = &sc->source->data[i];
[515] 
[516]             } else {
[517]                 bracket = 0;
[518]                 name.data = &sc->source->data[i];
[519]             }
[520] 
[521]             for ( /* void */ ; i < sc->source->len; i++, name.len++) {
[522]                 ch = sc->source->data[i];
[523] 
[524]                 if (ch == '}' && bracket) {
[525]                     i++;
[526]                     bracket = 0;
[527]                     break;
[528]                 }
[529] 
[530]                 if ((ch >= 'A' && ch <= 'Z')
[531]                     || (ch >= 'a' && ch <= 'z')
[532]                     || (ch >= '0' && ch <= '9')
[533]                     || ch == '_')
[534]                 {
[535]                     continue;
[536]                 }
[537] 
[538]                 break;
[539]             }
[540] 
[541]             if (bracket) {
[542]                 ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
[543]                                    "the closing bracket in \"%V\" "
[544]                                    "variable is missing", &name);
[545]                 return NGX_ERROR;
[546]             }
[547] 
[548]             if (name.len == 0) {
[549]                 goto invalid_variable;
[550]             }
[551] 
[552]             sc->variables++;
[553] 
[554]             if (ngx_http_script_add_var_code(sc, &name) != NGX_OK) {
[555]                 return NGX_ERROR;
[556]             }
[557] 
[558]             continue;
[559]         }
[560] 
[561]         if (sc->source->data[i] == '?' && sc->compile_args) {
[562]             sc->args = 1;
[563]             sc->compile_args = 0;
[564] 
[565]             if (ngx_http_script_add_args_code(sc) != NGX_OK) {
[566]                 return NGX_ERROR;
[567]             }
[568] 
[569]             i++;
[570] 
[571]             continue;
[572]         }
[573] 
[574]         name.data = &sc->source->data[i];
[575] 
[576]         while (i < sc->source->len) {
[577] 
[578]             if (sc->source->data[i] == '$') {
[579]                 break;
[580]             }
[581] 
[582]             if (sc->source->data[i] == '?') {
[583] 
[584]                 sc->args = 1;
[585] 
[586]                 if (sc->compile_args) {
[587]                     break;
[588]                 }
[589]             }
[590] 
[591]             i++;
[592]             name.len++;
[593]         }
[594] 
[595]         sc->size += name.len;
[596] 
[597]         if (ngx_http_script_add_copy_code(sc, &name, (i == sc->source->len))
[598]             != NGX_OK)
[599]         {
[600]             return NGX_ERROR;
[601]         }
[602]     }
[603] 
[604]     return ngx_http_script_done(sc);
[605] 
[606] invalid_variable:
[607] 
[608]     ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0, "invalid variable name");
[609] 
[610]     return NGX_ERROR;
[611] }
[612] 
[613] 
[614] u_char *
[615] ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value,
[616]     void *code_lengths, size_t len, void *code_values)
[617] {
[618]     ngx_uint_t                    i;
[619]     ngx_http_script_code_pt       code;
[620]     ngx_http_script_len_code_pt   lcode;
[621]     ngx_http_script_engine_t      e;
[622]     ngx_http_core_main_conf_t    *cmcf;
[623] 
[624]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[625] 
[626]     for (i = 0; i < cmcf->variables.nelts; i++) {
[627]         if (r->variables[i].no_cacheable) {
[628]             r->variables[i].valid = 0;
[629]             r->variables[i].not_found = 0;
[630]         }
[631]     }
[632] 
[633]     ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
[634] 
[635]     e.ip = code_lengths;
[636]     e.request = r;
[637]     e.flushed = 1;
[638] 
[639]     while (*(uintptr_t *) e.ip) {
[640]         lcode = *(ngx_http_script_len_code_pt *) e.ip;
[641]         len += lcode(&e);
[642]     }
[643] 
[644] 
[645]     value->len = len;
[646]     value->data = ngx_pnalloc(r->pool, len);
[647]     if (value->data == NULL) {
[648]         return NULL;
[649]     }
[650] 
[651]     e.ip = code_values;
[652]     e.pos = value->data;
[653] 
[654]     while (*(uintptr_t *) e.ip) {
[655]         code = *(ngx_http_script_code_pt *) e.ip;
[656]         code((ngx_http_script_engine_t *) &e);
[657]     }
[658] 
[659]     return e.pos;
[660] }
[661] 
[662] 
[663] void
[664] ngx_http_script_flush_no_cacheable_variables(ngx_http_request_t *r,
[665]     ngx_array_t *indices)
[666] {
[667]     ngx_uint_t  n, *index;
[668] 
[669]     if (indices) {
[670]         index = indices->elts;
[671]         for (n = 0; n < indices->nelts; n++) {
[672]             if (r->variables[index[n]].no_cacheable) {
[673]                 r->variables[index[n]].valid = 0;
[674]                 r->variables[index[n]].not_found = 0;
[675]             }
[676]         }
[677]     }
[678] }
[679] 
[680] 
[681] static ngx_int_t
[682] ngx_http_script_init_arrays(ngx_http_script_compile_t *sc)
[683] {
[684]     ngx_uint_t   n;
[685] 
[686]     if (sc->flushes && *sc->flushes == NULL) {
[687]         n = sc->variables ? sc->variables : 1;
[688]         *sc->flushes = ngx_array_create(sc->cf->pool, n, sizeof(ngx_uint_t));
[689]         if (*sc->flushes == NULL) {
[690]             return NGX_ERROR;
[691]         }
[692]     }
[693] 
[694]     if (*sc->lengths == NULL) {
[695]         n = sc->variables * (2 * sizeof(ngx_http_script_copy_code_t)
[696]                              + sizeof(ngx_http_script_var_code_t))
[697]             + sizeof(uintptr_t);
[698] 
[699]         *sc->lengths = ngx_array_create(sc->cf->pool, n, 1);
[700]         if (*sc->lengths == NULL) {
[701]             return NGX_ERROR;
[702]         }
[703]     }
[704] 
[705]     if (*sc->values == NULL) {
[706]         n = (sc->variables * (2 * sizeof(ngx_http_script_copy_code_t)
[707]                               + sizeof(ngx_http_script_var_code_t))
[708]                 + sizeof(uintptr_t)
[709]                 + sc->source->len
[710]                 + sizeof(uintptr_t) - 1)
[711]             & ~(sizeof(uintptr_t) - 1);
[712] 
[713]         *sc->values = ngx_array_create(sc->cf->pool, n, 1);
[714]         if (*sc->values == NULL) {
[715]             return NGX_ERROR;
[716]         }
[717]     }
[718] 
[719]     sc->variables = 0;
[720] 
[721]     return NGX_OK;
[722] }
[723] 
[724] 
[725] static ngx_int_t
[726] ngx_http_script_done(ngx_http_script_compile_t *sc)
[727] {
[728]     ngx_str_t    zero;
[729]     uintptr_t   *code;
[730] 
[731]     if (sc->zero) {
[732] 
[733]         zero.len = 1;
[734]         zero.data = (u_char *) "\0";
[735] 
[736]         if (ngx_http_script_add_copy_code(sc, &zero, 0) != NGX_OK) {
[737]             return NGX_ERROR;
[738]         }
[739]     }
[740] 
[741]     if (sc->conf_prefix || sc->root_prefix) {
[742]         if (ngx_http_script_add_full_name_code(sc) != NGX_OK) {
[743]             return NGX_ERROR;
[744]         }
[745]     }
[746] 
[747]     if (sc->complete_lengths) {
[748]         code = ngx_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
[749]         if (code == NULL) {
[750]             return NGX_ERROR;
[751]         }
[752] 
[753]         *code = (uintptr_t) NULL;
[754]     }
[755] 
[756]     if (sc->complete_values) {
[757]         code = ngx_http_script_add_code(*sc->values, sizeof(uintptr_t),
[758]                                         &sc->main);
[759]         if (code == NULL) {
[760]             return NGX_ERROR;
[761]         }
[762] 
[763]         *code = (uintptr_t) NULL;
[764]     }
[765] 
[766]     return NGX_OK;
[767] }
[768] 
[769] 
[770] void *
[771] ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes, size_t size)
[772] {
[773]     if (*codes == NULL) {
[774]         *codes = ngx_array_create(pool, 256, 1);
[775]         if (*codes == NULL) {
[776]             return NULL;
[777]         }
[778]     }
[779] 
[780]     return ngx_array_push_n(*codes, size);
[781] }
[782] 
[783] 
[784] void *
[785] ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code)
[786] {
[787]     u_char  *elts, **p;
[788]     void    *new;
[789] 
[790]     elts = codes->elts;
[791] 
[792]     new = ngx_array_push_n(codes, size);
[793]     if (new == NULL) {
[794]         return NULL;
[795]     }
[796] 
[797]     if (code) {
[798]         if (elts != codes->elts) {
[799]             p = code;
[800]             *p += (u_char *) codes->elts - elts;
[801]         }
[802]     }
[803] 
[804]     return new;
[805] }
[806] 
[807] 
[808] static ngx_int_t
[809] ngx_http_script_add_copy_code(ngx_http_script_compile_t *sc, ngx_str_t *value,
[810]     ngx_uint_t last)
[811] {
[812]     u_char                       *p;
[813]     size_t                        size, len, zero;
[814]     ngx_http_script_copy_code_t  *code;
[815] 
[816]     zero = (sc->zero && last);
[817]     len = value->len + zero;
[818] 
[819]     code = ngx_http_script_add_code(*sc->lengths,
[820]                                     sizeof(ngx_http_script_copy_code_t), NULL);
[821]     if (code == NULL) {
[822]         return NGX_ERROR;
[823]     }
[824] 
[825]     code->code = (ngx_http_script_code_pt) (void *)
[826]                                                  ngx_http_script_copy_len_code;
[827]     code->len = len;
[828] 
[829]     size = (sizeof(ngx_http_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
[830]             & ~(sizeof(uintptr_t) - 1);
[831] 
[832]     code = ngx_http_script_add_code(*sc->values, size, &sc->main);
[833]     if (code == NULL) {
[834]         return NGX_ERROR;
[835]     }
[836] 
[837]     code->code = ngx_http_script_copy_code;
[838]     code->len = len;
[839] 
[840]     p = ngx_cpymem((u_char *) code + sizeof(ngx_http_script_copy_code_t),
[841]                    value->data, value->len);
[842] 
[843]     if (zero) {
[844]         *p = '\0';
[845]         sc->zero = 0;
[846]     }
[847] 
[848]     return NGX_OK;
[849] }
[850] 
[851] 
[852] size_t
[853] ngx_http_script_copy_len_code(ngx_http_script_engine_t *e)
[854] {
[855]     ngx_http_script_copy_code_t  *code;
[856] 
[857]     code = (ngx_http_script_copy_code_t *) e->ip;
[858] 
[859]     e->ip += sizeof(ngx_http_script_copy_code_t);
[860] 
[861]     return code->len;
[862] }
[863] 
[864] 
[865] void
[866] ngx_http_script_copy_code(ngx_http_script_engine_t *e)
[867] {
[868]     u_char                       *p;
[869]     ngx_http_script_copy_code_t  *code;
[870] 
[871]     code = (ngx_http_script_copy_code_t *) e->ip;
[872] 
[873]     p = e->pos;
[874] 
[875]     if (!e->skip) {
[876]         e->pos = ngx_copy(p, e->ip + sizeof(ngx_http_script_copy_code_t),
[877]                           code->len);
[878]     }
[879] 
[880]     e->ip += sizeof(ngx_http_script_copy_code_t)
[881]           + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
[882] 
[883]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[884]                    "http script copy: \"%*s\"", e->pos - p, p);
[885] }
[886] 
[887] 
[888] static ngx_int_t
[889] ngx_http_script_add_var_code(ngx_http_script_compile_t *sc, ngx_str_t *name)
[890] {
[891]     ngx_int_t                    index, *p;
[892]     ngx_http_script_var_code_t  *code;
[893] 
[894]     index = ngx_http_get_variable_index(sc->cf, name);
[895] 
[896]     if (index == NGX_ERROR) {
[897]         return NGX_ERROR;
[898]     }
[899] 
[900]     if (sc->flushes) {
[901]         p = ngx_array_push(*sc->flushes);
[902]         if (p == NULL) {
[903]             return NGX_ERROR;
[904]         }
[905] 
[906]         *p = index;
[907]     }
[908] 
[909]     code = ngx_http_script_add_code(*sc->lengths,
[910]                                     sizeof(ngx_http_script_var_code_t), NULL);
[911]     if (code == NULL) {
[912]         return NGX_ERROR;
[913]     }
[914] 
[915]     code->code = (ngx_http_script_code_pt) (void *)
[916]                                              ngx_http_script_copy_var_len_code;
[917]     code->index = (uintptr_t) index;
[918] 
[919]     code = ngx_http_script_add_code(*sc->values,
[920]                                     sizeof(ngx_http_script_var_code_t),
[921]                                     &sc->main);
[922]     if (code == NULL) {
[923]         return NGX_ERROR;
[924]     }
[925] 
[926]     code->code = ngx_http_script_copy_var_code;
[927]     code->index = (uintptr_t) index;
[928] 
[929]     return NGX_OK;
[930] }
[931] 
[932] 
[933] size_t
[934] ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e)
[935] {
[936]     ngx_http_variable_value_t   *value;
[937]     ngx_http_script_var_code_t  *code;
[938] 
[939]     code = (ngx_http_script_var_code_t *) e->ip;
[940] 
[941]     e->ip += sizeof(ngx_http_script_var_code_t);
[942] 
[943]     if (e->flushed) {
[944]         value = ngx_http_get_indexed_variable(e->request, code->index);
[945] 
[946]     } else {
[947]         value = ngx_http_get_flushed_variable(e->request, code->index);
[948]     }
[949] 
[950]     if (value && !value->not_found) {
[951]         return value->len;
[952]     }
[953] 
[954]     return 0;
[955] }
[956] 
[957] 
[958] void
[959] ngx_http_script_copy_var_code(ngx_http_script_engine_t *e)
[960] {
[961]     u_char                      *p;
[962]     ngx_http_variable_value_t   *value;
[963]     ngx_http_script_var_code_t  *code;
[964] 
[965]     code = (ngx_http_script_var_code_t *) e->ip;
[966] 
[967]     e->ip += sizeof(ngx_http_script_var_code_t);
[968] 
[969]     if (!e->skip) {
[970] 
[971]         if (e->flushed) {
[972]             value = ngx_http_get_indexed_variable(e->request, code->index);
[973] 
[974]         } else {
[975]             value = ngx_http_get_flushed_variable(e->request, code->index);
[976]         }
[977] 
[978]         if (value && !value->not_found) {
[979]             p = e->pos;
[980]             e->pos = ngx_copy(p, value->data, value->len);
[981] 
[982]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP,
[983]                            e->request->connection->log, 0,
[984]                            "http script var: \"%*s\"", e->pos - p, p);
[985]         }
[986]     }
[987] }
[988] 
[989] 
[990] static ngx_int_t
[991] ngx_http_script_add_args_code(ngx_http_script_compile_t *sc)
[992] {
[993]     uintptr_t   *code;
[994] 
[995]     code = ngx_http_script_add_code(*sc->lengths, sizeof(uintptr_t), NULL);
[996]     if (code == NULL) {
[997]         return NGX_ERROR;
[998]     }
[999] 
[1000]     *code = (uintptr_t) ngx_http_script_mark_args_code;
[1001] 
[1002]     code = ngx_http_script_add_code(*sc->values, sizeof(uintptr_t), &sc->main);
[1003]     if (code == NULL) {
[1004]         return NGX_ERROR;
[1005]     }
[1006] 
[1007]     *code = (uintptr_t) ngx_http_script_start_args_code;
[1008] 
[1009]     return NGX_OK;
[1010] }
[1011] 
[1012] 
[1013] size_t
[1014] ngx_http_script_mark_args_code(ngx_http_script_engine_t *e)
[1015] {
[1016]     e->is_args = 1;
[1017]     e->ip += sizeof(uintptr_t);
[1018] 
[1019]     return 1;
[1020] }
[1021] 
[1022] 
[1023] void
[1024] ngx_http_script_start_args_code(ngx_http_script_engine_t *e)
[1025] {
[1026]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1027]                    "http script args");
[1028] 
[1029]     e->is_args = 1;
[1030]     e->args = e->pos;
[1031]     e->ip += sizeof(uintptr_t);
[1032] }
[1033] 
[1034] 
[1035] #if (NGX_PCRE)
[1036] 
[1037] void
[1038] ngx_http_script_regex_start_code(ngx_http_script_engine_t *e)
[1039] {
[1040]     size_t                         len;
[1041]     ngx_int_t                      rc;
[1042]     ngx_uint_t                     n;
[1043]     ngx_http_request_t            *r;
[1044]     ngx_http_script_engine_t       le;
[1045]     ngx_http_script_len_code_pt    lcode;
[1046]     ngx_http_script_regex_code_t  *code;
[1047] 
[1048]     code = (ngx_http_script_regex_code_t *) e->ip;
[1049] 
[1050]     r = e->request;
[1051] 
[1052]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1053]                    "http script regex: \"%V\"", &code->name);
[1054] 
[1055]     if (code->uri) {
[1056]         e->line = r->uri;
[1057]     } else {
[1058]         e->sp--;
[1059]         e->line.len = e->sp->len;
[1060]         e->line.data = e->sp->data;
[1061]     }
[1062] 
[1063]     rc = ngx_http_regex_exec(r, code->regex, &e->line);
[1064] 
[1065]     if (rc == NGX_DECLINED) {
[1066]         if (e->log || (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP)) {
[1067]             ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
[1068]                           "\"%V\" does not match \"%V\"",
[1069]                           &code->name, &e->line);
[1070]         }
[1071] 
[1072]         r->ncaptures = 0;
[1073] 
[1074]         if (code->test) {
[1075]             if (code->negative_test) {
[1076]                 e->sp->len = 1;
[1077]                 e->sp->data = (u_char *) "1";
[1078] 
[1079]             } else {
[1080]                 e->sp->len = 0;
[1081]                 e->sp->data = (u_char *) "";
[1082]             }
[1083] 
[1084]             e->sp++;
[1085] 
[1086]             e->ip += sizeof(ngx_http_script_regex_code_t);
[1087]             return;
[1088]         }
[1089] 
[1090]         e->ip += code->next;
[1091]         return;
[1092]     }
[1093] 
[1094]     if (rc == NGX_ERROR) {
[1095]         e->ip = ngx_http_script_exit;
[1096]         e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1097]         return;
[1098]     }
[1099] 
[1100]     if (e->log || (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP)) {
[1101]         ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
[1102]                       "\"%V\" matches \"%V\"", &code->name, &e->line);
[1103]     }
[1104] 
[1105]     if (code->test) {
[1106]         if (code->negative_test) {
[1107]             e->sp->len = 0;
[1108]             e->sp->data = (u_char *) "";
[1109] 
[1110]         } else {
[1111]             e->sp->len = 1;
[1112]             e->sp->data = (u_char *) "1";
[1113]         }
[1114] 
[1115]         e->sp++;
[1116] 
[1117]         e->ip += sizeof(ngx_http_script_regex_code_t);
[1118]         return;
[1119]     }
[1120] 
[1121]     if (code->status) {
[1122]         e->status = code->status;
[1123] 
[1124]         if (!code->redirect) {
[1125]             e->ip = ngx_http_script_exit;
[1126]             return;
[1127]         }
[1128]     }
[1129] 
[1130]     if (code->uri) {
[1131]         r->internal = 1;
[1132]         r->valid_unparsed_uri = 0;
[1133] 
[1134]         if (code->break_cycle) {
[1135]             r->valid_location = 0;
[1136]             r->uri_changed = 0;
[1137] 
[1138]         } else {
[1139]             r->uri_changed = 1;
[1140]         }
[1141]     }
[1142] 
[1143]     if (code->lengths == NULL) {
[1144]         e->buf.len = code->size;
[1145] 
[1146]         if (code->uri) {
[1147]             if (r->ncaptures && (r->quoted_uri || r->plus_in_uri)) {
[1148]                 e->buf.len += 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
[1149]                                                  NGX_ESCAPE_ARGS);
[1150]             }
[1151]         }
[1152] 
[1153]         for (n = 2; n < r->ncaptures; n += 2) {
[1154]             e->buf.len += r->captures[n + 1] - r->captures[n];
[1155]         }
[1156] 
[1157]     } else {
[1158]         ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[1159] 
[1160]         le.ip = code->lengths->elts;
[1161]         le.line = e->line;
[1162]         le.request = r;
[1163]         le.quote = code->redirect;
[1164] 
[1165]         len = 0;
[1166] 
[1167]         while (*(uintptr_t *) le.ip) {
[1168]             lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1169]             len += lcode(&le);
[1170]         }
[1171] 
[1172]         e->buf.len = len;
[1173]     }
[1174] 
[1175]     if (code->add_args && r->args.len) {
[1176]         e->buf.len += r->args.len + 1;
[1177]     }
[1178] 
[1179]     e->buf.data = ngx_pnalloc(r->pool, e->buf.len);
[1180]     if (e->buf.data == NULL) {
[1181]         e->ip = ngx_http_script_exit;
[1182]         e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1183]         return;
[1184]     }
[1185] 
[1186]     e->quote = code->redirect;
[1187] 
[1188]     e->pos = e->buf.data;
[1189] 
[1190]     e->ip += sizeof(ngx_http_script_regex_code_t);
[1191] }
[1192] 
[1193] 
[1194] void
[1195] ngx_http_script_regex_end_code(ngx_http_script_engine_t *e)
[1196] {
[1197]     u_char                            *dst, *src;
[1198]     ngx_http_request_t                *r;
[1199]     ngx_http_script_regex_end_code_t  *code;
[1200] 
[1201]     code = (ngx_http_script_regex_end_code_t *) e->ip;
[1202] 
[1203]     r = e->request;
[1204] 
[1205]     e->quote = 0;
[1206] 
[1207]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1208]                    "http script regex end");
[1209] 
[1210]     if (code->redirect) {
[1211] 
[1212]         dst = e->buf.data;
[1213]         src = e->buf.data;
[1214] 
[1215]         ngx_unescape_uri(&dst, &src, e->pos - e->buf.data,
[1216]                          NGX_UNESCAPE_REDIRECT);
[1217] 
[1218]         if (src < e->pos) {
[1219]             dst = ngx_movemem(dst, src, e->pos - src);
[1220]         }
[1221] 
[1222]         e->pos = dst;
[1223] 
[1224]         if (code->add_args && r->args.len) {
[1225]             *e->pos++ = (u_char) (code->args ? '&' : '?');
[1226]             e->pos = ngx_copy(e->pos, r->args.data, r->args.len);
[1227]         }
[1228] 
[1229]         e->buf.len = e->pos - e->buf.data;
[1230] 
[1231]         if (e->log || (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP)) {
[1232]             ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
[1233]                           "rewritten redirect: \"%V\"", &e->buf);
[1234]         }
[1235] 
[1236]         ngx_http_clear_location(r);
[1237] 
[1238]         r->headers_out.location = ngx_list_push(&r->headers_out.headers);
[1239]         if (r->headers_out.location == NULL) {
[1240]             e->ip = ngx_http_script_exit;
[1241]             e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1242]             return;
[1243]         }
[1244] 
[1245]         r->headers_out.location->hash = 1;
[1246]         r->headers_out.location->next = NULL;
[1247]         ngx_str_set(&r->headers_out.location->key, "Location");
[1248]         r->headers_out.location->value = e->buf;
[1249] 
[1250]         e->ip += sizeof(ngx_http_script_regex_end_code_t);
[1251]         return;
[1252]     }
[1253] 
[1254]     if (e->args) {
[1255]         e->buf.len = e->args - e->buf.data;
[1256] 
[1257]         if (code->add_args && r->args.len) {
[1258]             *e->pos++ = '&';
[1259]             e->pos = ngx_copy(e->pos, r->args.data, r->args.len);
[1260]         }
[1261] 
[1262]         r->args.len = e->pos - e->args;
[1263]         r->args.data = e->args;
[1264] 
[1265]         e->args = NULL;
[1266] 
[1267]     } else {
[1268]         e->buf.len = e->pos - e->buf.data;
[1269] 
[1270]         if (!code->add_args) {
[1271]             r->args.len = 0;
[1272]         }
[1273]     }
[1274] 
[1275]     if (e->log || (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP)) {
[1276]         ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
[1277]                       "rewritten data: \"%V\", args: \"%V\"",
[1278]                       &e->buf, &r->args);
[1279]     }
[1280] 
[1281]     if (code->uri) {
[1282]         r->uri = e->buf;
[1283] 
[1284]         if (r->uri.len == 0) {
[1285]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1286]                           "the rewritten URI has a zero length");
[1287]             e->ip = ngx_http_script_exit;
[1288]             e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1289]             return;
[1290]         }
[1291] 
[1292]         ngx_http_set_exten(r);
[1293]     }
[1294] 
[1295]     e->ip += sizeof(ngx_http_script_regex_end_code_t);
[1296] }
[1297] 
[1298] 
[1299] static ngx_int_t
[1300] ngx_http_script_add_capture_code(ngx_http_script_compile_t *sc, ngx_uint_t n)
[1301] {
[1302]     ngx_http_script_copy_capture_code_t  *code;
[1303] 
[1304]     code = ngx_http_script_add_code(*sc->lengths,
[1305]                                     sizeof(ngx_http_script_copy_capture_code_t),
[1306]                                     NULL);
[1307]     if (code == NULL) {
[1308]         return NGX_ERROR;
[1309]     }
[1310] 
[1311]     code->code = (ngx_http_script_code_pt) (void *)
[1312]                                          ngx_http_script_copy_capture_len_code;
[1313]     code->n = 2 * n;
[1314] 
[1315] 
[1316]     code = ngx_http_script_add_code(*sc->values,
[1317]                                     sizeof(ngx_http_script_copy_capture_code_t),
[1318]                                     &sc->main);
[1319]     if (code == NULL) {
[1320]         return NGX_ERROR;
[1321]     }
[1322] 
[1323]     code->code = ngx_http_script_copy_capture_code;
[1324]     code->n = 2 * n;
[1325] 
[1326]     if (sc->ncaptures < n) {
[1327]         sc->ncaptures = n;
[1328]     }
[1329] 
[1330]     return NGX_OK;
[1331] }
[1332] 
[1333] 
[1334] size_t
[1335] ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e)
[1336] {
[1337]     int                                  *cap;
[1338]     u_char                               *p;
[1339]     ngx_uint_t                            n;
[1340]     ngx_http_request_t                   *r;
[1341]     ngx_http_script_copy_capture_code_t  *code;
[1342] 
[1343]     r = e->request;
[1344] 
[1345]     code = (ngx_http_script_copy_capture_code_t *) e->ip;
[1346] 
[1347]     e->ip += sizeof(ngx_http_script_copy_capture_code_t);
[1348] 
[1349]     n = code->n;
[1350] 
[1351]     if (n < r->ncaptures) {
[1352] 
[1353]         cap = r->captures;
[1354] 
[1355]         if ((e->is_args || e->quote)
[1356]             && (e->request->quoted_uri || e->request->plus_in_uri))
[1357]         {
[1358]             p = r->captures_data;
[1359] 
[1360]             return cap[n + 1] - cap[n]
[1361]                    + 2 * ngx_escape_uri(NULL, &p[cap[n]], cap[n + 1] - cap[n],
[1362]                                         NGX_ESCAPE_ARGS);
[1363]         } else {
[1364]             return cap[n + 1] - cap[n];
[1365]         }
[1366]     }
[1367] 
[1368]     return 0;
[1369] }
[1370] 
[1371] 
[1372] void
[1373] ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e)
[1374] {
[1375]     int                                  *cap;
[1376]     u_char                               *p, *pos;
[1377]     ngx_uint_t                            n;
[1378]     ngx_http_request_t                   *r;
[1379]     ngx_http_script_copy_capture_code_t  *code;
[1380] 
[1381]     r = e->request;
[1382] 
[1383]     code = (ngx_http_script_copy_capture_code_t *) e->ip;
[1384] 
[1385]     e->ip += sizeof(ngx_http_script_copy_capture_code_t);
[1386] 
[1387]     n = code->n;
[1388] 
[1389]     pos = e->pos;
[1390] 
[1391]     if (n < r->ncaptures) {
[1392] 
[1393]         cap = r->captures;
[1394]         p = r->captures_data;
[1395] 
[1396]         if ((e->is_args || e->quote)
[1397]             && (e->request->quoted_uri || e->request->plus_in_uri))
[1398]         {
[1399]             e->pos = (u_char *) ngx_escape_uri(pos, &p[cap[n]],
[1400]                                                cap[n + 1] - cap[n],
[1401]                                                NGX_ESCAPE_ARGS);
[1402]         } else {
[1403]             e->pos = ngx_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
[1404]         }
[1405]     }
[1406] 
[1407]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1408]                    "http script capture: \"%*s\"", e->pos - pos, pos);
[1409] }
[1410] 
[1411] #endif
[1412] 
[1413] 
[1414] static ngx_int_t
[1415] ngx_http_script_add_full_name_code(ngx_http_script_compile_t *sc)
[1416] {
[1417]     ngx_http_script_full_name_code_t  *code;
[1418] 
[1419]     code = ngx_http_script_add_code(*sc->lengths,
[1420]                                     sizeof(ngx_http_script_full_name_code_t),
[1421]                                     NULL);
[1422]     if (code == NULL) {
[1423]         return NGX_ERROR;
[1424]     }
[1425] 
[1426]     code->code = (ngx_http_script_code_pt) (void *)
[1427]                                             ngx_http_script_full_name_len_code;
[1428]     code->conf_prefix = sc->conf_prefix;
[1429] 
[1430]     code = ngx_http_script_add_code(*sc->values,
[1431]                                     sizeof(ngx_http_script_full_name_code_t),
[1432]                                     &sc->main);
[1433]     if (code == NULL) {
[1434]         return NGX_ERROR;
[1435]     }
[1436] 
[1437]     code->code = ngx_http_script_full_name_code;
[1438]     code->conf_prefix = sc->conf_prefix;
[1439] 
[1440]     return NGX_OK;
[1441] }
[1442] 
[1443] 
[1444] static size_t
[1445] ngx_http_script_full_name_len_code(ngx_http_script_engine_t *e)
[1446] {
[1447]     ngx_http_script_full_name_code_t  *code;
[1448] 
[1449]     code = (ngx_http_script_full_name_code_t *) e->ip;
[1450] 
[1451]     e->ip += sizeof(ngx_http_script_full_name_code_t);
[1452] 
[1453]     return code->conf_prefix ? ngx_cycle->conf_prefix.len:
[1454]                                ngx_cycle->prefix.len;
[1455] }
[1456] 
[1457] 
[1458] static void
[1459] ngx_http_script_full_name_code(ngx_http_script_engine_t *e)
[1460] {
[1461]     ngx_http_script_full_name_code_t  *code;
[1462] 
[1463]     ngx_str_t  value, *prefix;
[1464] 
[1465]     code = (ngx_http_script_full_name_code_t *) e->ip;
[1466] 
[1467]     value.data = e->buf.data;
[1468]     value.len = e->pos - e->buf.data;
[1469] 
[1470]     prefix = code->conf_prefix ? (ngx_str_t *) &ngx_cycle->conf_prefix:
[1471]                                  (ngx_str_t *) &ngx_cycle->prefix;
[1472] 
[1473]     if (ngx_get_full_name(e->request->pool, prefix, &value) != NGX_OK) {
[1474]         e->ip = ngx_http_script_exit;
[1475]         e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1476]         return;
[1477]     }
[1478] 
[1479]     e->buf = value;
[1480] 
[1481]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1482]                    "http script fullname: \"%V\"", &value);
[1483] 
[1484]     e->ip += sizeof(ngx_http_script_full_name_code_t);
[1485] }
[1486] 
[1487] 
[1488] void
[1489] ngx_http_script_return_code(ngx_http_script_engine_t *e)
[1490] {
[1491]     ngx_http_script_return_code_t  *code;
[1492] 
[1493]     code = (ngx_http_script_return_code_t *) e->ip;
[1494] 
[1495]     if (code->status < NGX_HTTP_BAD_REQUEST
[1496]         || code->text.value.len
[1497]         || code->text.lengths)
[1498]     {
[1499]         e->status = ngx_http_send_response(e->request, code->status, NULL,
[1500]                                            &code->text);
[1501]     } else {
[1502]         e->status = code->status;
[1503]     }
[1504] 
[1505]     e->ip = ngx_http_script_exit;
[1506] }
[1507] 
[1508] 
[1509] void
[1510] ngx_http_script_break_code(ngx_http_script_engine_t *e)
[1511] {
[1512]     ngx_http_request_t  *r;
[1513] 
[1514]     r = e->request;
[1515] 
[1516]     if (r->uri_changed) {
[1517]         r->valid_location = 0;
[1518]         r->uri_changed = 0;
[1519]     }
[1520] 
[1521]     e->ip = ngx_http_script_exit;
[1522] }
[1523] 
[1524] 
[1525] void
[1526] ngx_http_script_if_code(ngx_http_script_engine_t *e)
[1527] {
[1528]     ngx_http_script_if_code_t  *code;
[1529] 
[1530]     code = (ngx_http_script_if_code_t *) e->ip;
[1531] 
[1532]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1533]                    "http script if");
[1534] 
[1535]     e->sp--;
[1536] 
[1537]     if (e->sp->len && (e->sp->len != 1 || e->sp->data[0] != '0')) {
[1538]         if (code->loc_conf) {
[1539]             e->request->loc_conf = code->loc_conf;
[1540]             ngx_http_update_location_config(e->request);
[1541]         }
[1542] 
[1543]         e->ip += sizeof(ngx_http_script_if_code_t);
[1544]         return;
[1545]     }
[1546] 
[1547]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1548]                    "http script if: false");
[1549] 
[1550]     e->ip += code->next;
[1551] }
[1552] 
[1553] 
[1554] void
[1555] ngx_http_script_equal_code(ngx_http_script_engine_t *e)
[1556] {
[1557]     ngx_http_variable_value_t  *val, *res;
[1558] 
[1559]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1560]                    "http script equal");
[1561] 
[1562]     e->sp--;
[1563]     val = e->sp;
[1564]     res = e->sp - 1;
[1565] 
[1566]     e->ip += sizeof(uintptr_t);
[1567] 
[1568]     if (val->len == res->len
[1569]         && ngx_strncmp(val->data, res->data, res->len) == 0)
[1570]     {
[1571]         *res = ngx_http_variable_true_value;
[1572]         return;
[1573]     }
[1574] 
[1575]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1576]                    "http script equal: no");
[1577] 
[1578]     *res = ngx_http_variable_null_value;
[1579] }
[1580] 
[1581] 
[1582] void
[1583] ngx_http_script_not_equal_code(ngx_http_script_engine_t *e)
[1584] {
[1585]     ngx_http_variable_value_t  *val, *res;
[1586] 
[1587]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1588]                    "http script not equal");
[1589] 
[1590]     e->sp--;
[1591]     val = e->sp;
[1592]     res = e->sp - 1;
[1593] 
[1594]     e->ip += sizeof(uintptr_t);
[1595] 
[1596]     if (val->len == res->len
[1597]         && ngx_strncmp(val->data, res->data, res->len) == 0)
[1598]     {
[1599]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1600]                        "http script not equal: no");
[1601] 
[1602]         *res = ngx_http_variable_null_value;
[1603]         return;
[1604]     }
[1605] 
[1606]     *res = ngx_http_variable_true_value;
[1607] }
[1608] 
[1609] 
[1610] void
[1611] ngx_http_script_file_code(ngx_http_script_engine_t *e)
[1612] {
[1613]     ngx_str_t                     path;
[1614]     ngx_http_request_t           *r;
[1615]     ngx_open_file_info_t          of;
[1616]     ngx_http_core_loc_conf_t     *clcf;
[1617]     ngx_http_variable_value_t    *value;
[1618]     ngx_http_script_file_code_t  *code;
[1619] 
[1620]     value = e->sp - 1;
[1621] 
[1622]     code = (ngx_http_script_file_code_t *) e->ip;
[1623]     e->ip += sizeof(ngx_http_script_file_code_t);
[1624] 
[1625]     path.len = value->len - 1;
[1626]     path.data = value->data;
[1627] 
[1628]     r = e->request;
[1629] 
[1630]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1631]                    "http script file op %p \"%V\"", (void *) code->op, &path);
[1632] 
[1633]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1634] 
[1635]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[1636] 
[1637]     of.read_ahead = clcf->read_ahead;
[1638]     of.directio = clcf->directio;
[1639]     of.valid = clcf->open_file_cache_valid;
[1640]     of.min_uses = clcf->open_file_cache_min_uses;
[1641]     of.test_only = 1;
[1642]     of.errors = clcf->open_file_cache_errors;
[1643]     of.events = clcf->open_file_cache_events;
[1644] 
[1645]     if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[1646]         e->ip = ngx_http_script_exit;
[1647]         e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1648]         return;
[1649]     }
[1650] 
[1651]     if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[1652]         != NGX_OK)
[1653]     {
[1654]         if (of.err == 0) {
[1655]             e->ip = ngx_http_script_exit;
[1656]             e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1657]             return;
[1658]         }
[1659] 
[1660]         if (of.err != NGX_ENOENT
[1661]             && of.err != NGX_ENOTDIR
[1662]             && of.err != NGX_ENAMETOOLONG)
[1663]         {
[1664]             ngx_log_error(NGX_LOG_CRIT, r->connection->log, of.err,
[1665]                           "%s \"%s\" failed", of.failed, value->data);
[1666]         }
[1667] 
[1668]         switch (code->op) {
[1669] 
[1670]         case ngx_http_script_file_plain:
[1671]         case ngx_http_script_file_dir:
[1672]         case ngx_http_script_file_exists:
[1673]         case ngx_http_script_file_exec:
[1674]              goto false_value;
[1675] 
[1676]         case ngx_http_script_file_not_plain:
[1677]         case ngx_http_script_file_not_dir:
[1678]         case ngx_http_script_file_not_exists:
[1679]         case ngx_http_script_file_not_exec:
[1680]              goto true_value;
[1681]         }
[1682] 
[1683]         goto false_value;
[1684]     }
[1685] 
[1686]     switch (code->op) {
[1687]     case ngx_http_script_file_plain:
[1688]         if (of.is_file) {
[1689]              goto true_value;
[1690]         }
[1691]         goto false_value;
[1692] 
[1693]     case ngx_http_script_file_not_plain:
[1694]         if (of.is_file) {
[1695]             goto false_value;
[1696]         }
[1697]         goto true_value;
[1698] 
[1699]     case ngx_http_script_file_dir:
[1700]         if (of.is_dir) {
[1701]              goto true_value;
[1702]         }
[1703]         goto false_value;
[1704] 
[1705]     case ngx_http_script_file_not_dir:
[1706]         if (of.is_dir) {
[1707]             goto false_value;
[1708]         }
[1709]         goto true_value;
[1710] 
[1711]     case ngx_http_script_file_exists:
[1712]         if (of.is_file || of.is_dir || of.is_link) {
[1713]              goto true_value;
[1714]         }
[1715]         goto false_value;
[1716] 
[1717]     case ngx_http_script_file_not_exists:
[1718]         if (of.is_file || of.is_dir || of.is_link) {
[1719]             goto false_value;
[1720]         }
[1721]         goto true_value;
[1722] 
[1723]     case ngx_http_script_file_exec:
[1724]         if (of.is_exec) {
[1725]              goto true_value;
[1726]         }
[1727]         goto false_value;
[1728] 
[1729]     case ngx_http_script_file_not_exec:
[1730]         if (of.is_exec) {
[1731]             goto false_value;
[1732]         }
[1733]         goto true_value;
[1734]     }
[1735] 
[1736] false_value:
[1737] 
[1738]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1739]                    "http script file op false");
[1740] 
[1741]     *value = ngx_http_variable_null_value;
[1742]     return;
[1743] 
[1744] true_value:
[1745] 
[1746]     *value = ngx_http_variable_true_value;
[1747]     return;
[1748] }
[1749] 
[1750] 
[1751] void
[1752] ngx_http_script_complex_value_code(ngx_http_script_engine_t *e)
[1753] {
[1754]     size_t                                 len;
[1755]     ngx_http_script_engine_t               le;
[1756]     ngx_http_script_len_code_pt            lcode;
[1757]     ngx_http_script_complex_value_code_t  *code;
[1758] 
[1759]     code = (ngx_http_script_complex_value_code_t *) e->ip;
[1760] 
[1761]     e->ip += sizeof(ngx_http_script_complex_value_code_t);
[1762] 
[1763]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1764]                    "http script complex value");
[1765] 
[1766]     ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
[1767] 
[1768]     le.ip = code->lengths->elts;
[1769]     le.line = e->line;
[1770]     le.request = e->request;
[1771]     le.quote = e->quote;
[1772] 
[1773]     for (len = 0; *(uintptr_t *) le.ip; len += lcode(&le)) {
[1774]         lcode = *(ngx_http_script_len_code_pt *) le.ip;
[1775]     }
[1776] 
[1777]     e->buf.len = len;
[1778]     e->buf.data = ngx_pnalloc(e->request->pool, len);
[1779]     if (e->buf.data == NULL) {
[1780]         e->ip = ngx_http_script_exit;
[1781]         e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1782]         return;
[1783]     }
[1784] 
[1785]     e->pos = e->buf.data;
[1786] 
[1787]     e->sp->len = e->buf.len;
[1788]     e->sp->data = e->buf.data;
[1789]     e->sp++;
[1790] }
[1791] 
[1792] 
[1793] void
[1794] ngx_http_script_value_code(ngx_http_script_engine_t *e)
[1795] {
[1796]     ngx_http_script_value_code_t  *code;
[1797] 
[1798]     code = (ngx_http_script_value_code_t *) e->ip;
[1799] 
[1800]     e->ip += sizeof(ngx_http_script_value_code_t);
[1801] 
[1802]     e->sp->len = code->text_len;
[1803]     e->sp->data = (u_char *) code->text_data;
[1804] 
[1805]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1806]                    "http script value: \"%v\"", e->sp);
[1807] 
[1808]     e->sp++;
[1809] }
[1810] 
[1811] 
[1812] void
[1813] ngx_http_script_set_var_code(ngx_http_script_engine_t *e)
[1814] {
[1815]     ngx_http_request_t          *r;
[1816]     ngx_http_script_var_code_t  *code;
[1817] 
[1818]     code = (ngx_http_script_var_code_t *) e->ip;
[1819] 
[1820]     e->ip += sizeof(ngx_http_script_var_code_t);
[1821] 
[1822]     r = e->request;
[1823] 
[1824]     e->sp--;
[1825] 
[1826]     r->variables[code->index].len = e->sp->len;
[1827]     r->variables[code->index].valid = 1;
[1828]     r->variables[code->index].no_cacheable = 0;
[1829]     r->variables[code->index].not_found = 0;
[1830]     r->variables[code->index].data = e->sp->data;
[1831] 
[1832] #if (NGX_DEBUG)
[1833]     {
[1834]     ngx_http_variable_t        *v;
[1835]     ngx_http_core_main_conf_t  *cmcf;
[1836] 
[1837]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[1838] 
[1839]     v = cmcf->variables.elts;
[1840] 
[1841]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1842]                    "http script set $%V", &v[code->index].name);
[1843]     }
[1844] #endif
[1845] }
[1846] 
[1847] 
[1848] void
[1849] ngx_http_script_var_set_handler_code(ngx_http_script_engine_t *e)
[1850] {
[1851]     ngx_http_script_var_handler_code_t  *code;
[1852] 
[1853]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1854]                    "http script set var handler");
[1855] 
[1856]     code = (ngx_http_script_var_handler_code_t *) e->ip;
[1857] 
[1858]     e->ip += sizeof(ngx_http_script_var_handler_code_t);
[1859] 
[1860]     e->sp--;
[1861] 
[1862]     code->handler(e->request, e->sp, code->data);
[1863] }
[1864] 
[1865] 
[1866] void
[1867] ngx_http_script_var_code(ngx_http_script_engine_t *e)
[1868] {
[1869]     ngx_http_variable_value_t   *value;
[1870]     ngx_http_script_var_code_t  *code;
[1871] 
[1872]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1873]                    "http script var");
[1874] 
[1875]     code = (ngx_http_script_var_code_t *) e->ip;
[1876] 
[1877]     e->ip += sizeof(ngx_http_script_var_code_t);
[1878] 
[1879]     value = ngx_http_get_flushed_variable(e->request, code->index);
[1880] 
[1881]     if (value && !value->not_found) {
[1882]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
[1883]                        "http script var: \"%v\"", value);
[1884] 
[1885]         *e->sp = *value;
[1886]         e->sp++;
[1887] 
[1888]         return;
[1889]     }
[1890] 
[1891]     *e->sp = ngx_http_variable_null_value;
[1892]     e->sp++;
[1893] }
[1894] 
[1895] 
[1896] void
[1897] ngx_http_script_nop_code(ngx_http_script_engine_t *e)
[1898] {
[1899]     e->ip += sizeof(uintptr_t);
[1900] }
