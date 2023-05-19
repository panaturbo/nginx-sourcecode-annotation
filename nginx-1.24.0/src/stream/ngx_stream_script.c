[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] static ngx_int_t ngx_stream_script_init_arrays(
[14]     ngx_stream_script_compile_t *sc);
[15] static ngx_int_t ngx_stream_script_done(ngx_stream_script_compile_t *sc);
[16] static ngx_int_t ngx_stream_script_add_copy_code(
[17]     ngx_stream_script_compile_t *sc, ngx_str_t *value, ngx_uint_t last);
[18] static ngx_int_t ngx_stream_script_add_var_code(
[19]     ngx_stream_script_compile_t *sc, ngx_str_t *name);
[20] #if (NGX_PCRE)
[21] static ngx_int_t ngx_stream_script_add_capture_code(
[22]     ngx_stream_script_compile_t *sc, ngx_uint_t n);
[23] #endif
[24] static ngx_int_t ngx_stream_script_add_full_name_code(
[25]     ngx_stream_script_compile_t *sc);
[26] static size_t ngx_stream_script_full_name_len_code(
[27]     ngx_stream_script_engine_t *e);
[28] static void ngx_stream_script_full_name_code(ngx_stream_script_engine_t *e);
[29] 
[30] 
[31] #define ngx_stream_script_exit  (u_char *) &ngx_stream_script_exit_code
[32] 
[33] static uintptr_t ngx_stream_script_exit_code = (uintptr_t) NULL;
[34] 
[35] 
[36] void
[37] ngx_stream_script_flush_complex_value(ngx_stream_session_t *s,
[38]     ngx_stream_complex_value_t *val)
[39] {
[40]     ngx_uint_t *index;
[41] 
[42]     index = val->flushes;
[43] 
[44]     if (index) {
[45]         while (*index != (ngx_uint_t) -1) {
[46] 
[47]             if (s->variables[*index].no_cacheable) {
[48]                 s->variables[*index].valid = 0;
[49]                 s->variables[*index].not_found = 0;
[50]             }
[51] 
[52]             index++;
[53]         }
[54]     }
[55] }
[56] 
[57] 
[58] ngx_int_t
[59] ngx_stream_complex_value(ngx_stream_session_t *s,
[60]     ngx_stream_complex_value_t *val, ngx_str_t *value)
[61] {
[62]     size_t                         len;
[63]     ngx_stream_script_code_pt      code;
[64]     ngx_stream_script_engine_t     e;
[65]     ngx_stream_script_len_code_pt  lcode;
[66] 
[67]     if (val->lengths == NULL) {
[68]         *value = val->value;
[69]         return NGX_OK;
[70]     }
[71] 
[72]     ngx_stream_script_flush_complex_value(s, val);
[73] 
[74]     ngx_memzero(&e, sizeof(ngx_stream_script_engine_t));
[75] 
[76]     e.ip = val->lengths;
[77]     e.session = s;
[78]     e.flushed = 1;
[79] 
[80]     len = 0;
[81] 
[82]     while (*(uintptr_t *) e.ip) {
[83]         lcode = *(ngx_stream_script_len_code_pt *) e.ip;
[84]         len += lcode(&e);
[85]     }
[86] 
[87]     value->len = len;
[88]     value->data = ngx_pnalloc(s->connection->pool, len);
[89]     if (value->data == NULL) {
[90]         return NGX_ERROR;
[91]     }
[92] 
[93]     e.ip = val->values;
[94]     e.pos = value->data;
[95]     e.buf = *value;
[96] 
[97]     while (*(uintptr_t *) e.ip) {
[98]         code = *(ngx_stream_script_code_pt *) e.ip;
[99]         code((ngx_stream_script_engine_t *) &e);
[100]     }
[101] 
[102]     *value = e.buf;
[103] 
[104]     return NGX_OK;
[105] }
[106] 
[107] 
[108] size_t
[109] ngx_stream_complex_value_size(ngx_stream_session_t *s,
[110]     ngx_stream_complex_value_t *val, size_t default_value)
[111] {
[112]     size_t     size;
[113]     ngx_str_t  value;
[114] 
[115]     if (val == NULL) {
[116]         return default_value;
[117]     }
[118] 
[119]     if (val->lengths == NULL) {
[120]         return val->u.size;
[121]     }
[122] 
[123]     if (ngx_stream_complex_value(s, val, &value) != NGX_OK) {
[124]         return default_value;
[125]     }
[126] 
[127]     size = ngx_parse_size(&value);
[128] 
[129]     if (size == (size_t) NGX_ERROR) {
[130]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[131]                       "invalid size \"%V\"", &value);
[132]         return default_value;
[133]     }
[134] 
[135]     return size;
[136] }
[137] 
[138] 
[139] ngx_int_t
[140] ngx_stream_compile_complex_value(ngx_stream_compile_complex_value_t *ccv)
[141] {
[142]     ngx_str_t                    *v;
[143]     ngx_uint_t                    i, n, nv, nc;
[144]     ngx_array_t                   flushes, lengths, values, *pf, *pl, *pv;
[145]     ngx_stream_script_compile_t   sc;
[146] 
[147]     v = ccv->value;
[148] 
[149]     nv = 0;
[150]     nc = 0;
[151] 
[152]     for (i = 0; i < v->len; i++) {
[153]         if (v->data[i] == '$') {
[154]             if (v->data[i + 1] >= '1' && v->data[i + 1] <= '9') {
[155]                 nc++;
[156] 
[157]             } else {
[158]                 nv++;
[159]             }
[160]         }
[161]     }
[162] 
[163]     if ((v->len == 0 || v->data[0] != '$')
[164]         && (ccv->conf_prefix || ccv->root_prefix))
[165]     {
[166]         if (ngx_conf_full_name(ccv->cf->cycle, v, ccv->conf_prefix) != NGX_OK) {
[167]             return NGX_ERROR;
[168]         }
[169] 
[170]         ccv->conf_prefix = 0;
[171]         ccv->root_prefix = 0;
[172]     }
[173] 
[174]     ccv->complex_value->value = *v;
[175]     ccv->complex_value->flushes = NULL;
[176]     ccv->complex_value->lengths = NULL;
[177]     ccv->complex_value->values = NULL;
[178] 
[179]     if (nv == 0 && nc == 0) {
[180]         return NGX_OK;
[181]     }
[182] 
[183]     n = nv + 1;
[184] 
[185]     if (ngx_array_init(&flushes, ccv->cf->pool, n, sizeof(ngx_uint_t))
[186]         != NGX_OK)
[187]     {
[188]         return NGX_ERROR;
[189]     }
[190] 
[191]     n = nv * (2 * sizeof(ngx_stream_script_copy_code_t)
[192]                   + sizeof(ngx_stream_script_var_code_t))
[193]         + sizeof(uintptr_t);
[194] 
[195]     if (ngx_array_init(&lengths, ccv->cf->pool, n, 1) != NGX_OK) {
[196]         return NGX_ERROR;
[197]     }
[198] 
[199]     n = (nv * (2 * sizeof(ngx_stream_script_copy_code_t)
[200]                    + sizeof(ngx_stream_script_var_code_t))
[201]                 + sizeof(uintptr_t)
[202]                 + v->len
[203]                 + sizeof(uintptr_t) - 1)
[204]             & ~(sizeof(uintptr_t) - 1);
[205] 
[206]     if (ngx_array_init(&values, ccv->cf->pool, n, 1) != NGX_OK) {
[207]         return NGX_ERROR;
[208]     }
[209] 
[210]     pf = &flushes;
[211]     pl = &lengths;
[212]     pv = &values;
[213] 
[214]     ngx_memzero(&sc, sizeof(ngx_stream_script_compile_t));
[215] 
[216]     sc.cf = ccv->cf;
[217]     sc.source = v;
[218]     sc.flushes = &pf;
[219]     sc.lengths = &pl;
[220]     sc.values = &pv;
[221]     sc.complete_lengths = 1;
[222]     sc.complete_values = 1;
[223]     sc.zero = ccv->zero;
[224]     sc.conf_prefix = ccv->conf_prefix;
[225]     sc.root_prefix = ccv->root_prefix;
[226] 
[227]     if (ngx_stream_script_compile(&sc) != NGX_OK) {
[228]         return NGX_ERROR;
[229]     }
[230] 
[231]     if (flushes.nelts) {
[232]         ccv->complex_value->flushes = flushes.elts;
[233]         ccv->complex_value->flushes[flushes.nelts] = (ngx_uint_t) -1;
[234]     }
[235] 
[236]     ccv->complex_value->lengths = lengths.elts;
[237]     ccv->complex_value->values = values.elts;
[238] 
[239]     return NGX_OK;
[240] }
[241] 
[242] 
[243] char *
[244] ngx_stream_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[245]     void *conf)
[246] {
[247]     char  *p = conf;
[248] 
[249]     ngx_str_t                            *value;
[250]     ngx_stream_complex_value_t          **cv;
[251]     ngx_stream_compile_complex_value_t    ccv;
[252] 
[253]     cv = (ngx_stream_complex_value_t **) (p + cmd->offset);
[254] 
[255]     if (*cv != NGX_CONF_UNSET_PTR && *cv != NULL) {
[256]         return "is duplicate";
[257]     }
[258] 
[259]     *cv = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
[260]     if (*cv == NULL) {
[261]         return NGX_CONF_ERROR;
[262]     }
[263] 
[264]     value = cf->args->elts;
[265] 
[266]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[267] 
[268]     ccv.cf = cf;
[269]     ccv.value = &value[1];
[270]     ccv.complex_value = *cv;
[271] 
[272]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[273]         return NGX_CONF_ERROR;
[274]     }
[275] 
[276]     return NGX_CONF_OK;
[277] }
[278] 
[279] 
[280] char *
[281] ngx_stream_set_complex_value_zero_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[282]     void *conf)
[283] {
[284]     char  *p = conf;
[285] 
[286]     ngx_str_t                            *value;
[287]     ngx_stream_complex_value_t          **cv;
[288]     ngx_stream_compile_complex_value_t    ccv;
[289] 
[290]     cv = (ngx_stream_complex_value_t **) (p + cmd->offset);
[291] 
[292]     if (*cv != NGX_CONF_UNSET_PTR) {
[293]         return "is duplicate";
[294]     }
[295] 
[296]     *cv = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
[297]     if (*cv == NULL) {
[298]         return NGX_CONF_ERROR;
[299]     }
[300] 
[301]     value = cf->args->elts;
[302] 
[303]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[304] 
[305]     ccv.cf = cf;
[306]     ccv.value = &value[1];
[307]     ccv.complex_value = *cv;
[308]     ccv.zero = 1;
[309] 
[310]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[311]         return NGX_CONF_ERROR;
[312]     }
[313] 
[314]     return NGX_CONF_OK;
[315] }
[316] 
[317] 
[318] char *
[319] ngx_stream_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[320]     void *conf)
[321] {
[322]     char  *p = conf;
[323] 
[324]     char                        *rv;
[325]     ngx_stream_complex_value_t  *cv;
[326] 
[327]     rv = ngx_stream_set_complex_value_slot(cf, cmd, conf);
[328] 
[329]     if (rv != NGX_CONF_OK) {
[330]         return rv;
[331]     }
[332] 
[333]     cv = *(ngx_stream_complex_value_t **) (p + cmd->offset);
[334] 
[335]     if (cv->lengths) {
[336]         return NGX_CONF_OK;
[337]     }
[338] 
[339]     cv->u.size = ngx_parse_size(&cv->value);
[340]     if (cv->u.size == (size_t) NGX_ERROR) {
[341]         return "invalid value";
[342]     }
[343] 
[344]     return NGX_CONF_OK;
[345] }
[346] 
[347] 
[348] ngx_uint_t
[349] ngx_stream_script_variables_count(ngx_str_t *value)
[350] {
[351]     ngx_uint_t  i, n;
[352] 
[353]     for (n = 0, i = 0; i < value->len; i++) {
[354]         if (value->data[i] == '$') {
[355]             n++;
[356]         }
[357]     }
[358] 
[359]     return n;
[360] }
[361] 
[362] 
[363] ngx_int_t
[364] ngx_stream_script_compile(ngx_stream_script_compile_t *sc)
[365] {
[366]     u_char       ch;
[367]     ngx_str_t    name;
[368]     ngx_uint_t   i, bracket;
[369] 
[370]     if (ngx_stream_script_init_arrays(sc) != NGX_OK) {
[371]         return NGX_ERROR;
[372]     }
[373] 
[374]     for (i = 0; i < sc->source->len; /* void */ ) {
[375] 
[376]         name.len = 0;
[377] 
[378]         if (sc->source->data[i] == '$') {
[379] 
[380]             if (++i == sc->source->len) {
[381]                 goto invalid_variable;
[382]             }
[383] 
[384]             if (sc->source->data[i] >= '1' && sc->source->data[i] <= '9') {
[385] #if (NGX_PCRE)
[386]                 ngx_uint_t  n;
[387] 
[388]                 n = sc->source->data[i] - '0';
[389] 
[390]                 if (ngx_stream_script_add_capture_code(sc, n) != NGX_OK) {
[391]                     return NGX_ERROR;
[392]                 }
[393] 
[394]                 i++;
[395] 
[396]                 continue;
[397] #else
[398]                 ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
[399]                                    "using variable \"$%c\" requires "
[400]                                    "PCRE library", sc->source->data[i]);
[401]                 return NGX_ERROR;
[402] #endif
[403]             }
[404] 
[405]             if (sc->source->data[i] == '{') {
[406]                 bracket = 1;
[407] 
[408]                 if (++i == sc->source->len) {
[409]                     goto invalid_variable;
[410]                 }
[411] 
[412]                 name.data = &sc->source->data[i];
[413] 
[414]             } else {
[415]                 bracket = 0;
[416]                 name.data = &sc->source->data[i];
[417]             }
[418] 
[419]             for ( /* void */ ; i < sc->source->len; i++, name.len++) {
[420]                 ch = sc->source->data[i];
[421] 
[422]                 if (ch == '}' && bracket) {
[423]                     i++;
[424]                     bracket = 0;
[425]                     break;
[426]                 }
[427] 
[428]                 if ((ch >= 'A' && ch <= 'Z')
[429]                     || (ch >= 'a' && ch <= 'z')
[430]                     || (ch >= '0' && ch <= '9')
[431]                     || ch == '_')
[432]                 {
[433]                     continue;
[434]                 }
[435] 
[436]                 break;
[437]             }
[438] 
[439]             if (bracket) {
[440]                 ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0,
[441]                                    "the closing bracket in \"%V\" "
[442]                                    "variable is missing", &name);
[443]                 return NGX_ERROR;
[444]             }
[445] 
[446]             if (name.len == 0) {
[447]                 goto invalid_variable;
[448]             }
[449] 
[450]             sc->variables++;
[451] 
[452]             if (ngx_stream_script_add_var_code(sc, &name) != NGX_OK) {
[453]                 return NGX_ERROR;
[454]             }
[455] 
[456]             continue;
[457]         }
[458] 
[459]         name.data = &sc->source->data[i];
[460] 
[461]         while (i < sc->source->len) {
[462] 
[463]             if (sc->source->data[i] == '$') {
[464]                 break;
[465]             }
[466] 
[467]             i++;
[468]             name.len++;
[469]         }
[470] 
[471]         sc->size += name.len;
[472] 
[473]         if (ngx_stream_script_add_copy_code(sc, &name, (i == sc->source->len))
[474]             != NGX_OK)
[475]         {
[476]             return NGX_ERROR;
[477]         }
[478]     }
[479] 
[480]     return ngx_stream_script_done(sc);
[481] 
[482] invalid_variable:
[483] 
[484]     ngx_conf_log_error(NGX_LOG_EMERG, sc->cf, 0, "invalid variable name");
[485] 
[486]     return NGX_ERROR;
[487] }
[488] 
[489] 
[490] u_char *
[491] ngx_stream_script_run(ngx_stream_session_t *s, ngx_str_t *value,
[492]     void *code_lengths, size_t len, void *code_values)
[493] {
[494]     ngx_uint_t                      i;
[495]     ngx_stream_script_code_pt       code;
[496]     ngx_stream_script_engine_t      e;
[497]     ngx_stream_core_main_conf_t    *cmcf;
[498]     ngx_stream_script_len_code_pt   lcode;
[499] 
[500]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[501] 
[502]     for (i = 0; i < cmcf->variables.nelts; i++) {
[503]         if (s->variables[i].no_cacheable) {
[504]             s->variables[i].valid = 0;
[505]             s->variables[i].not_found = 0;
[506]         }
[507]     }
[508] 
[509]     ngx_memzero(&e, sizeof(ngx_stream_script_engine_t));
[510] 
[511]     e.ip = code_lengths;
[512]     e.session = s;
[513]     e.flushed = 1;
[514] 
[515]     while (*(uintptr_t *) e.ip) {
[516]         lcode = *(ngx_stream_script_len_code_pt *) e.ip;
[517]         len += lcode(&e);
[518]     }
[519] 
[520] 
[521]     value->len = len;
[522]     value->data = ngx_pnalloc(s->connection->pool, len);
[523]     if (value->data == NULL) {
[524]         return NULL;
[525]     }
[526] 
[527]     e.ip = code_values;
[528]     e.pos = value->data;
[529] 
[530]     while (*(uintptr_t *) e.ip) {
[531]         code = *(ngx_stream_script_code_pt *) e.ip;
[532]         code((ngx_stream_script_engine_t *) &e);
[533]     }
[534] 
[535]     return e.pos;
[536] }
[537] 
[538] 
[539] void
[540] ngx_stream_script_flush_no_cacheable_variables(ngx_stream_session_t *s,
[541]     ngx_array_t *indices)
[542] {
[543]     ngx_uint_t  n, *index;
[544] 
[545]     if (indices) {
[546]         index = indices->elts;
[547]         for (n = 0; n < indices->nelts; n++) {
[548]             if (s->variables[index[n]].no_cacheable) {
[549]                 s->variables[index[n]].valid = 0;
[550]                 s->variables[index[n]].not_found = 0;
[551]             }
[552]         }
[553]     }
[554] }
[555] 
[556] 
[557] static ngx_int_t
[558] ngx_stream_script_init_arrays(ngx_stream_script_compile_t *sc)
[559] {
[560]     ngx_uint_t   n;
[561] 
[562]     if (sc->flushes && *sc->flushes == NULL) {
[563]         n = sc->variables ? sc->variables : 1;
[564]         *sc->flushes = ngx_array_create(sc->cf->pool, n, sizeof(ngx_uint_t));
[565]         if (*sc->flushes == NULL) {
[566]             return NGX_ERROR;
[567]         }
[568]     }
[569] 
[570]     if (*sc->lengths == NULL) {
[571]         n = sc->variables * (2 * sizeof(ngx_stream_script_copy_code_t)
[572]                              + sizeof(ngx_stream_script_var_code_t))
[573]             + sizeof(uintptr_t);
[574] 
[575]         *sc->lengths = ngx_array_create(sc->cf->pool, n, 1);
[576]         if (*sc->lengths == NULL) {
[577]             return NGX_ERROR;
[578]         }
[579]     }
[580] 
[581]     if (*sc->values == NULL) {
[582]         n = (sc->variables * (2 * sizeof(ngx_stream_script_copy_code_t)
[583]                               + sizeof(ngx_stream_script_var_code_t))
[584]                 + sizeof(uintptr_t)
[585]                 + sc->source->len
[586]                 + sizeof(uintptr_t) - 1)
[587]             & ~(sizeof(uintptr_t) - 1);
[588] 
[589]         *sc->values = ngx_array_create(sc->cf->pool, n, 1);
[590]         if (*sc->values == NULL) {
[591]             return NGX_ERROR;
[592]         }
[593]     }
[594] 
[595]     sc->variables = 0;
[596] 
[597]     return NGX_OK;
[598] }
[599] 
[600] 
[601] static ngx_int_t
[602] ngx_stream_script_done(ngx_stream_script_compile_t *sc)
[603] {
[604]     ngx_str_t    zero;
[605]     uintptr_t   *code;
[606] 
[607]     if (sc->zero) {
[608] 
[609]         zero.len = 1;
[610]         zero.data = (u_char *) "\0";
[611] 
[612]         if (ngx_stream_script_add_copy_code(sc, &zero, 0) != NGX_OK) {
[613]             return NGX_ERROR;
[614]         }
[615]     }
[616] 
[617]     if (sc->conf_prefix || sc->root_prefix) {
[618]         if (ngx_stream_script_add_full_name_code(sc) != NGX_OK) {
[619]             return NGX_ERROR;
[620]         }
[621]     }
[622] 
[623]     if (sc->complete_lengths) {
[624]         code = ngx_stream_script_add_code(*sc->lengths, sizeof(uintptr_t),
[625]                                           NULL);
[626]         if (code == NULL) {
[627]             return NGX_ERROR;
[628]         }
[629] 
[630]         *code = (uintptr_t) NULL;
[631]     }
[632] 
[633]     if (sc->complete_values) {
[634]         code = ngx_stream_script_add_code(*sc->values, sizeof(uintptr_t),
[635]                                           &sc->main);
[636]         if (code == NULL) {
[637]             return NGX_ERROR;
[638]         }
[639] 
[640]         *code = (uintptr_t) NULL;
[641]     }
[642] 
[643]     return NGX_OK;
[644] }
[645] 
[646] 
[647] void *
[648] ngx_stream_script_add_code(ngx_array_t *codes, size_t size, void *code)
[649] {
[650]     u_char  *elts, **p;
[651]     void    *new;
[652] 
[653]     elts = codes->elts;
[654] 
[655]     new = ngx_array_push_n(codes, size);
[656]     if (new == NULL) {
[657]         return NULL;
[658]     }
[659] 
[660]     if (code) {
[661]         if (elts != codes->elts) {
[662]             p = code;
[663]             *p += (u_char *) codes->elts - elts;
[664]         }
[665]     }
[666] 
[667]     return new;
[668] }
[669] 
[670] 
[671] static ngx_int_t
[672] ngx_stream_script_add_copy_code(ngx_stream_script_compile_t *sc,
[673]     ngx_str_t *value, ngx_uint_t last)
[674] {
[675]     u_char                         *p;
[676]     size_t                          size, len, zero;
[677]     ngx_stream_script_copy_code_t  *code;
[678] 
[679]     zero = (sc->zero && last);
[680]     len = value->len + zero;
[681] 
[682]     code = ngx_stream_script_add_code(*sc->lengths,
[683]                                       sizeof(ngx_stream_script_copy_code_t),
[684]                                       NULL);
[685]     if (code == NULL) {
[686]         return NGX_ERROR;
[687]     }
[688] 
[689]     code->code = (ngx_stream_script_code_pt) (void *)
[690]                                                ngx_stream_script_copy_len_code;
[691]     code->len = len;
[692] 
[693]     size = (sizeof(ngx_stream_script_copy_code_t) + len + sizeof(uintptr_t) - 1)
[694]             & ~(sizeof(uintptr_t) - 1);
[695] 
[696]     code = ngx_stream_script_add_code(*sc->values, size, &sc->main);
[697]     if (code == NULL) {
[698]         return NGX_ERROR;
[699]     }
[700] 
[701]     code->code = ngx_stream_script_copy_code;
[702]     code->len = len;
[703] 
[704]     p = ngx_cpymem((u_char *) code + sizeof(ngx_stream_script_copy_code_t),
[705]                    value->data, value->len);
[706] 
[707]     if (zero) {
[708]         *p = '\0';
[709]         sc->zero = 0;
[710]     }
[711] 
[712]     return NGX_OK;
[713] }
[714] 
[715] 
[716] size_t
[717] ngx_stream_script_copy_len_code(ngx_stream_script_engine_t *e)
[718] {
[719]     ngx_stream_script_copy_code_t  *code;
[720] 
[721]     code = (ngx_stream_script_copy_code_t *) e->ip;
[722] 
[723]     e->ip += sizeof(ngx_stream_script_copy_code_t);
[724] 
[725]     return code->len;
[726] }
[727] 
[728] 
[729] void
[730] ngx_stream_script_copy_code(ngx_stream_script_engine_t *e)
[731] {
[732]     u_char                         *p;
[733]     ngx_stream_script_copy_code_t  *code;
[734] 
[735]     code = (ngx_stream_script_copy_code_t *) e->ip;
[736] 
[737]     p = e->pos;
[738] 
[739]     if (!e->skip) {
[740]         e->pos = ngx_copy(p, e->ip + sizeof(ngx_stream_script_copy_code_t),
[741]                           code->len);
[742]     }
[743] 
[744]     e->ip += sizeof(ngx_stream_script_copy_code_t)
[745]           + ((code->len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
[746] 
[747]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, e->session->connection->log, 0,
[748]                    "stream script copy: \"%*s\"", e->pos - p, p);
[749] }
[750] 
[751] 
[752] static ngx_int_t
[753] ngx_stream_script_add_var_code(ngx_stream_script_compile_t *sc, ngx_str_t *name)
[754] {
[755]     ngx_int_t                      index, *p;
[756]     ngx_stream_script_var_code_t  *code;
[757] 
[758]     index = ngx_stream_get_variable_index(sc->cf, name);
[759] 
[760]     if (index == NGX_ERROR) {
[761]         return NGX_ERROR;
[762]     }
[763] 
[764]     if (sc->flushes) {
[765]         p = ngx_array_push(*sc->flushes);
[766]         if (p == NULL) {
[767]             return NGX_ERROR;
[768]         }
[769] 
[770]         *p = index;
[771]     }
[772] 
[773]     code = ngx_stream_script_add_code(*sc->lengths,
[774]                                       sizeof(ngx_stream_script_var_code_t),
[775]                                       NULL);
[776]     if (code == NULL) {
[777]         return NGX_ERROR;
[778]     }
[779] 
[780]     code->code = (ngx_stream_script_code_pt) (void *)
[781]                                            ngx_stream_script_copy_var_len_code;
[782]     code->index = (uintptr_t) index;
[783] 
[784]     code = ngx_stream_script_add_code(*sc->values,
[785]                                       sizeof(ngx_stream_script_var_code_t),
[786]                                       &sc->main);
[787]     if (code == NULL) {
[788]         return NGX_ERROR;
[789]     }
[790] 
[791]     code->code = ngx_stream_script_copy_var_code;
[792]     code->index = (uintptr_t) index;
[793] 
[794]     return NGX_OK;
[795] }
[796] 
[797] 
[798] size_t
[799] ngx_stream_script_copy_var_len_code(ngx_stream_script_engine_t *e)
[800] {
[801]     ngx_stream_variable_value_t   *value;
[802]     ngx_stream_script_var_code_t  *code;
[803] 
[804]     code = (ngx_stream_script_var_code_t *) e->ip;
[805] 
[806]     e->ip += sizeof(ngx_stream_script_var_code_t);
[807] 
[808]     if (e->flushed) {
[809]         value = ngx_stream_get_indexed_variable(e->session, code->index);
[810] 
[811]     } else {
[812]         value = ngx_stream_get_flushed_variable(e->session, code->index);
[813]     }
[814] 
[815]     if (value && !value->not_found) {
[816]         return value->len;
[817]     }
[818] 
[819]     return 0;
[820] }
[821] 
[822] 
[823] void
[824] ngx_stream_script_copy_var_code(ngx_stream_script_engine_t *e)
[825] {
[826]     u_char                        *p;
[827]     ngx_stream_variable_value_t   *value;
[828]     ngx_stream_script_var_code_t  *code;
[829] 
[830]     code = (ngx_stream_script_var_code_t *) e->ip;
[831] 
[832]     e->ip += sizeof(ngx_stream_script_var_code_t);
[833] 
[834]     if (!e->skip) {
[835] 
[836]         if (e->flushed) {
[837]             value = ngx_stream_get_indexed_variable(e->session, code->index);
[838] 
[839]         } else {
[840]             value = ngx_stream_get_flushed_variable(e->session, code->index);
[841]         }
[842] 
[843]         if (value && !value->not_found) {
[844]             p = e->pos;
[845]             e->pos = ngx_copy(p, value->data, value->len);
[846] 
[847]             ngx_log_debug2(NGX_LOG_DEBUG_STREAM,
[848]                            e->session->connection->log, 0,
[849]                            "stream script var: \"%*s\"", e->pos - p, p);
[850]         }
[851]     }
[852] }
[853] 
[854] 
[855] #if (NGX_PCRE)
[856] 
[857] static ngx_int_t
[858] ngx_stream_script_add_capture_code(ngx_stream_script_compile_t *sc,
[859]     ngx_uint_t n)
[860] {
[861]     ngx_stream_script_copy_capture_code_t  *code;
[862] 
[863]     code = ngx_stream_script_add_code(*sc->lengths,
[864]                                   sizeof(ngx_stream_script_copy_capture_code_t),
[865]                                   NULL);
[866]     if (code == NULL) {
[867]         return NGX_ERROR;
[868]     }
[869] 
[870]     code->code = (ngx_stream_script_code_pt) (void *)
[871]                                        ngx_stream_script_copy_capture_len_code;
[872]     code->n = 2 * n;
[873] 
[874] 
[875]     code = ngx_stream_script_add_code(*sc->values,
[876]                                   sizeof(ngx_stream_script_copy_capture_code_t),
[877]                                   &sc->main);
[878]     if (code == NULL) {
[879]         return NGX_ERROR;
[880]     }
[881] 
[882]     code->code = ngx_stream_script_copy_capture_code;
[883]     code->n = 2 * n;
[884] 
[885]     if (sc->ncaptures < n) {
[886]         sc->ncaptures = n;
[887]     }
[888] 
[889]     return NGX_OK;
[890] }
[891] 
[892] 
[893] size_t
[894] ngx_stream_script_copy_capture_len_code(ngx_stream_script_engine_t *e)
[895] {
[896]     int                                    *cap;
[897]     ngx_uint_t                              n;
[898]     ngx_stream_session_t                   *s;
[899]     ngx_stream_script_copy_capture_code_t  *code;
[900] 
[901]     s = e->session;
[902] 
[903]     code = (ngx_stream_script_copy_capture_code_t *) e->ip;
[904] 
[905]     e->ip += sizeof(ngx_stream_script_copy_capture_code_t);
[906] 
[907]     n = code->n;
[908] 
[909]     if (n < s->ncaptures) {
[910]         cap = s->captures;
[911]         return cap[n + 1] - cap[n];
[912]     }
[913] 
[914]     return 0;
[915] }
[916] 
[917] 
[918] void
[919] ngx_stream_script_copy_capture_code(ngx_stream_script_engine_t *e)
[920] {
[921]     int                                    *cap;
[922]     u_char                                 *p, *pos;
[923]     ngx_uint_t                              n;
[924]     ngx_stream_session_t                   *s;
[925]     ngx_stream_script_copy_capture_code_t  *code;
[926] 
[927]     s = e->session;
[928] 
[929]     code = (ngx_stream_script_copy_capture_code_t *) e->ip;
[930] 
[931]     e->ip += sizeof(ngx_stream_script_copy_capture_code_t);
[932] 
[933]     n = code->n;
[934] 
[935]     pos = e->pos;
[936] 
[937]     if (n < s->ncaptures) {
[938]         cap = s->captures;
[939]         p = s->captures_data;
[940]         e->pos = ngx_copy(pos, &p[cap[n]], cap[n + 1] - cap[n]);
[941]     }
[942] 
[943]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, e->session->connection->log, 0,
[944]                    "stream script capture: \"%*s\"", e->pos - pos, pos);
[945] }
[946] 
[947] #endif
[948] 
[949] 
[950] static ngx_int_t
[951] ngx_stream_script_add_full_name_code(ngx_stream_script_compile_t *sc)
[952] {
[953]     ngx_stream_script_full_name_code_t  *code;
[954] 
[955]     code = ngx_stream_script_add_code(*sc->lengths,
[956]                                     sizeof(ngx_stream_script_full_name_code_t),
[957]                                     NULL);
[958]     if (code == NULL) {
[959]         return NGX_ERROR;
[960]     }
[961] 
[962]     code->code = (ngx_stream_script_code_pt) (void *)
[963]                                           ngx_stream_script_full_name_len_code;
[964]     code->conf_prefix = sc->conf_prefix;
[965] 
[966]     code = ngx_stream_script_add_code(*sc->values,
[967]                         sizeof(ngx_stream_script_full_name_code_t), &sc->main);
[968]     if (code == NULL) {
[969]         return NGX_ERROR;
[970]     }
[971] 
[972]     code->code = ngx_stream_script_full_name_code;
[973]     code->conf_prefix = sc->conf_prefix;
[974] 
[975]     return NGX_OK;
[976] }
[977] 
[978] 
[979] static size_t
[980] ngx_stream_script_full_name_len_code(ngx_stream_script_engine_t *e)
[981] {
[982]     ngx_stream_script_full_name_code_t  *code;
[983] 
[984]     code = (ngx_stream_script_full_name_code_t *) e->ip;
[985] 
[986]     e->ip += sizeof(ngx_stream_script_full_name_code_t);
[987] 
[988]     return code->conf_prefix ? ngx_cycle->conf_prefix.len:
[989]                                ngx_cycle->prefix.len;
[990] }
[991] 
[992] 
[993] static void
[994] ngx_stream_script_full_name_code(ngx_stream_script_engine_t *e)
[995] {
[996]     ngx_stream_script_full_name_code_t  *code;
[997] 
[998]     ngx_str_t  value, *prefix;
[999] 
[1000]     code = (ngx_stream_script_full_name_code_t *) e->ip;
[1001] 
[1002]     value.data = e->buf.data;
[1003]     value.len = e->pos - e->buf.data;
[1004] 
[1005]     prefix = code->conf_prefix ? (ngx_str_t *) &ngx_cycle->conf_prefix:
[1006]                                  (ngx_str_t *) &ngx_cycle->prefix;
[1007] 
[1008]     if (ngx_get_full_name(e->session->connection->pool, prefix, &value)
[1009]         != NGX_OK)
[1010]     {
[1011]         e->ip = ngx_stream_script_exit;
[1012]         return;
[1013]     }
[1014] 
[1015]     e->buf = value;
[1016] 
[1017]     ngx_log_debug1(NGX_LOG_DEBUG_STREAM, e->session->connection->log, 0,
[1018]                    "stream script fullname: \"%V\"", &value);
[1019] 
[1020]     e->ip += sizeof(ngx_stream_script_full_name_code_t);
[1021] }
