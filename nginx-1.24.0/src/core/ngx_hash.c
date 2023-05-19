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
[12] void *
[13] ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len)
[14] {
[15]     ngx_uint_t       i;
[16]     ngx_hash_elt_t  *elt;
[17] 
[18] #if 0
[19]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "hf:\"%*s\"", len, name);
[20] #endif
[21] 
[22]     elt = hash->buckets[key % hash->size];
[23] 
[24]     if (elt == NULL) {
[25]         return NULL;
[26]     }
[27] 
[28]     while (elt->value) {
[29]         if (len != (size_t) elt->len) {
[30]             goto next;
[31]         }
[32] 
[33]         for (i = 0; i < len; i++) {
[34]             if (name[i] != elt->name[i]) {
[35]                 goto next;
[36]             }
[37]         }
[38] 
[39]         return elt->value;
[40] 
[41]     next:
[42] 
[43]         elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
[44]                                                sizeof(void *));
[45]         continue;
[46]     }
[47] 
[48]     return NULL;
[49] }
[50] 
[51] 
[52] void *
[53] ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
[54] {
[55]     void        *value;
[56]     ngx_uint_t   i, n, key;
[57] 
[58] #if 0
[59]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wch:\"%*s\"", len, name);
[60] #endif
[61] 
[62]     n = len;
[63] 
[64]     while (n) {
[65]         if (name[n - 1] == '.') {
[66]             break;
[67]         }
[68] 
[69]         n--;
[70]     }
[71] 
[72]     key = 0;
[73] 
[74]     for (i = n; i < len; i++) {
[75]         key = ngx_hash(key, name[i]);
[76]     }
[77] 
[78] #if 0
[79]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
[80] #endif
[81] 
[82]     value = ngx_hash_find(&hwc->hash, key, &name[n], len - n);
[83] 
[84] #if 0
[85]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
[86] #endif
[87] 
[88]     if (value) {
[89] 
[90]         /*
[91]          * the 2 low bits of value have the special meaning:
[92]          *     00 - value is data pointer for both "example.com"
[93]          *          and "*.example.com";
[94]          *     01 - value is data pointer for "*.example.com" only;
[95]          *     10 - value is pointer to wildcard hash allowing
[96]          *          both "example.com" and "*.example.com";
[97]          *     11 - value is pointer to wildcard hash allowing
[98]          *          "*.example.com" only.
[99]          */
[100] 
[101]         if ((uintptr_t) value & 2) {
[102] 
[103]             if (n == 0) {
[104] 
[105]                 /* "example.com" */
[106] 
[107]                 if ((uintptr_t) value & 1) {
[108]                     return NULL;
[109]                 }
[110] 
[111]                 hwc = (ngx_hash_wildcard_t *)
[112]                                           ((uintptr_t) value & (uintptr_t) ~3);
[113]                 return hwc->value;
[114]             }
[115] 
[116]             hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);
[117] 
[118]             value = ngx_hash_find_wc_head(hwc, name, n - 1);
[119] 
[120]             if (value) {
[121]                 return value;
[122]             }
[123] 
[124]             return hwc->value;
[125]         }
[126] 
[127]         if ((uintptr_t) value & 1) {
[128] 
[129]             if (n == 0) {
[130] 
[131]                 /* "example.com" */
[132] 
[133]                 return NULL;
[134]             }
[135] 
[136]             return (void *) ((uintptr_t) value & (uintptr_t) ~3);
[137]         }
[138] 
[139]         return value;
[140]     }
[141] 
[142]     return hwc->value;
[143] }
[144] 
[145] 
[146] void *
[147] ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len)
[148] {
[149]     void        *value;
[150]     ngx_uint_t   i, key;
[151] 
[152] #if 0
[153]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "wct:\"%*s\"", len, name);
[154] #endif
[155] 
[156]     key = 0;
[157] 
[158]     for (i = 0; i < len; i++) {
[159]         if (name[i] == '.') {
[160]             break;
[161]         }
[162] 
[163]         key = ngx_hash(key, name[i]);
[164]     }
[165] 
[166]     if (i == len) {
[167]         return NULL;
[168]     }
[169] 
[170] #if 0
[171]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "key:\"%ui\"", key);
[172] #endif
[173] 
[174]     value = ngx_hash_find(&hwc->hash, key, name, i);
[175] 
[176] #if 0
[177]     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "value:\"%p\"", value);
[178] #endif
[179] 
[180]     if (value) {
[181] 
[182]         /*
[183]          * the 2 low bits of value have the special meaning:
[184]          *     00 - value is data pointer;
[185]          *     11 - value is pointer to wildcard hash allowing "example.*".
[186]          */
[187] 
[188]         if ((uintptr_t) value & 2) {
[189] 
[190]             i++;
[191] 
[192]             hwc = (ngx_hash_wildcard_t *) ((uintptr_t) value & (uintptr_t) ~3);
[193] 
[194]             value = ngx_hash_find_wc_tail(hwc, &name[i], len - i);
[195] 
[196]             if (value) {
[197]                 return value;
[198]             }
[199] 
[200]             return hwc->value;
[201]         }
[202] 
[203]         return value;
[204]     }
[205] 
[206]     return hwc->value;
[207] }
[208] 
[209] 
[210] void *
[211] ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key, u_char *name,
[212]     size_t len)
[213] {
[214]     void  *value;
[215] 
[216]     if (hash->hash.buckets) {
[217]         value = ngx_hash_find(&hash->hash, key, name, len);
[218] 
[219]         if (value) {
[220]             return value;
[221]         }
[222]     }
[223] 
[224]     if (len == 0) {
[225]         return NULL;
[226]     }
[227] 
[228]     if (hash->wc_head && hash->wc_head->hash.buckets) {
[229]         value = ngx_hash_find_wc_head(hash->wc_head, name, len);
[230] 
[231]         if (value) {
[232]             return value;
[233]         }
[234]     }
[235] 
[236]     if (hash->wc_tail && hash->wc_tail->hash.buckets) {
[237]         value = ngx_hash_find_wc_tail(hash->wc_tail, name, len);
[238] 
[239]         if (value) {
[240]             return value;
[241]         }
[242]     }
[243] 
[244]     return NULL;
[245] }
[246] 
[247] 
[248] #define NGX_HASH_ELT_SIZE(name)                                               \
[249]     (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))
[250] 
[251] ngx_int_t
[252] ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts)
[253] {
[254]     u_char          *elts;
[255]     size_t           len;
[256]     u_short         *test;
[257]     ngx_uint_t       i, n, key, size, start, bucket_size;
[258]     ngx_hash_elt_t  *elt, **buckets;
[259] 
[260]     if (hinit->max_size == 0) {
[261]         ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
[262]                       "could not build %s, you should "
[263]                       "increase %s_max_size: %i",
[264]                       hinit->name, hinit->name, hinit->max_size);
[265]         return NGX_ERROR;
[266]     }
[267] 
[268]     if (hinit->bucket_size > 65536 - ngx_cacheline_size) {
[269]         ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
[270]                       "could not build %s, too large "
[271]                       "%s_bucket_size: %i",
[272]                       hinit->name, hinit->name, hinit->bucket_size);
[273]         return NGX_ERROR;
[274]     }
[275] 
[276]     for (n = 0; n < nelts; n++) {
[277]         if (names[n].key.data == NULL) {
[278]             continue;
[279]         }
[280] 
[281]         if (hinit->bucket_size < NGX_HASH_ELT_SIZE(&names[n]) + sizeof(void *))
[282]         {
[283]             ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
[284]                           "could not build %s, you should "
[285]                           "increase %s_bucket_size: %i",
[286]                           hinit->name, hinit->name, hinit->bucket_size);
[287]             return NGX_ERROR;
[288]         }
[289]     }
[290] 
[291]     test = ngx_alloc(hinit->max_size * sizeof(u_short), hinit->pool->log);
[292]     if (test == NULL) {
[293]         return NGX_ERROR;
[294]     }
[295] 
[296]     bucket_size = hinit->bucket_size - sizeof(void *);
[297] 
[298]     start = nelts / (bucket_size / (2 * sizeof(void *)));
[299]     start = start ? start : 1;
[300] 
[301]     if (hinit->max_size > 10000 && nelts && hinit->max_size / nelts < 100) {
[302]         start = hinit->max_size - 1000;
[303]     }
[304] 
[305]     for (size = start; size <= hinit->max_size; size++) {
[306] 
[307]         ngx_memzero(test, size * sizeof(u_short));
[308] 
[309]         for (n = 0; n < nelts; n++) {
[310]             if (names[n].key.data == NULL) {
[311]                 continue;
[312]             }
[313] 
[314]             key = names[n].key_hash % size;
[315]             len = test[key] + NGX_HASH_ELT_SIZE(&names[n]);
[316] 
[317] #if 0
[318]             ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[319]                           "%ui: %ui %uz \"%V\"",
[320]                           size, key, len, &names[n].key);
[321] #endif
[322] 
[323]             if (len > bucket_size) {
[324]                 goto next;
[325]             }
[326] 
[327]             test[key] = (u_short) len;
[328]         }
[329] 
[330]         goto found;
[331] 
[332]     next:
[333] 
[334]         continue;
[335]     }
[336] 
[337]     size = hinit->max_size;
[338] 
[339]     ngx_log_error(NGX_LOG_WARN, hinit->pool->log, 0,
[340]                   "could not build optimal %s, you should increase "
[341]                   "either %s_max_size: %i or %s_bucket_size: %i; "
[342]                   "ignoring %s_bucket_size",
[343]                   hinit->name, hinit->name, hinit->max_size,
[344]                   hinit->name, hinit->bucket_size, hinit->name);
[345] 
[346] found:
[347] 
[348]     for (i = 0; i < size; i++) {
[349]         test[i] = sizeof(void *);
[350]     }
[351] 
[352]     for (n = 0; n < nelts; n++) {
[353]         if (names[n].key.data == NULL) {
[354]             continue;
[355]         }
[356] 
[357]         key = names[n].key_hash % size;
[358]         len = test[key] + NGX_HASH_ELT_SIZE(&names[n]);
[359] 
[360]         if (len > 65536 - ngx_cacheline_size) {
[361]             ngx_log_error(NGX_LOG_EMERG, hinit->pool->log, 0,
[362]                           "could not build %s, you should "
[363]                           "increase %s_max_size: %i",
[364]                           hinit->name, hinit->name, hinit->max_size);
[365]             ngx_free(test);
[366]             return NGX_ERROR;
[367]         }
[368] 
[369]         test[key] = (u_short) len;
[370]     }
[371] 
[372]     len = 0;
[373] 
[374]     for (i = 0; i < size; i++) {
[375]         if (test[i] == sizeof(void *)) {
[376]             continue;
[377]         }
[378] 
[379]         test[i] = (u_short) (ngx_align(test[i], ngx_cacheline_size));
[380] 
[381]         len += test[i];
[382]     }
[383] 
[384]     if (hinit->hash == NULL) {
[385]         hinit->hash = ngx_pcalloc(hinit->pool, sizeof(ngx_hash_wildcard_t)
[386]                                              + size * sizeof(ngx_hash_elt_t *));
[387]         if (hinit->hash == NULL) {
[388]             ngx_free(test);
[389]             return NGX_ERROR;
[390]         }
[391] 
[392]         buckets = (ngx_hash_elt_t **)
[393]                       ((u_char *) hinit->hash + sizeof(ngx_hash_wildcard_t));
[394] 
[395]     } else {
[396]         buckets = ngx_pcalloc(hinit->pool, size * sizeof(ngx_hash_elt_t *));
[397]         if (buckets == NULL) {
[398]             ngx_free(test);
[399]             return NGX_ERROR;
[400]         }
[401]     }
[402] 
[403]     elts = ngx_palloc(hinit->pool, len + ngx_cacheline_size);
[404]     if (elts == NULL) {
[405]         ngx_free(test);
[406]         return NGX_ERROR;
[407]     }
[408] 
[409]     elts = ngx_align_ptr(elts, ngx_cacheline_size);
[410] 
[411]     for (i = 0; i < size; i++) {
[412]         if (test[i] == sizeof(void *)) {
[413]             continue;
[414]         }
[415] 
[416]         buckets[i] = (ngx_hash_elt_t *) elts;
[417]         elts += test[i];
[418]     }
[419] 
[420]     for (i = 0; i < size; i++) {
[421]         test[i] = 0;
[422]     }
[423] 
[424]     for (n = 0; n < nelts; n++) {
[425]         if (names[n].key.data == NULL) {
[426]             continue;
[427]         }
[428] 
[429]         key = names[n].key_hash % size;
[430]         elt = (ngx_hash_elt_t *) ((u_char *) buckets[key] + test[key]);
[431] 
[432]         elt->value = names[n].value;
[433]         elt->len = (u_short) names[n].key.len;
[434] 
[435]         ngx_strlow(elt->name, names[n].key.data, names[n].key.len);
[436] 
[437]         test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&names[n]));
[438]     }
[439] 
[440]     for (i = 0; i < size; i++) {
[441]         if (buckets[i] == NULL) {
[442]             continue;
[443]         }
[444] 
[445]         elt = (ngx_hash_elt_t *) ((u_char *) buckets[i] + test[i]);
[446] 
[447]         elt->value = NULL;
[448]     }
[449] 
[450]     ngx_free(test);
[451] 
[452]     hinit->hash->buckets = buckets;
[453]     hinit->hash->size = size;
[454] 
[455] #if 0
[456] 
[457]     for (i = 0; i < size; i++) {
[458]         ngx_str_t   val;
[459]         ngx_uint_t  key;
[460] 
[461]         elt = buckets[i];
[462] 
[463]         if (elt == NULL) {
[464]             ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[465]                           "%ui: NULL", i);
[466]             continue;
[467]         }
[468] 
[469]         while (elt->value) {
[470]             val.len = elt->len;
[471]             val.data = &elt->name[0];
[472] 
[473]             key = hinit->key(val.data, val.len);
[474] 
[475]             ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[476]                           "%ui: %p \"%V\" %ui", i, elt, &val, key);
[477] 
[478]             elt = (ngx_hash_elt_t *) ngx_align_ptr(&elt->name[0] + elt->len,
[479]                                                    sizeof(void *));
[480]         }
[481]     }
[482] 
[483] #endif
[484] 
[485]     return NGX_OK;
[486] }
[487] 
[488] 
[489] ngx_int_t
[490] ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
[491]     ngx_uint_t nelts)
[492] {
[493]     size_t                len, dot_len;
[494]     ngx_uint_t            i, n, dot;
[495]     ngx_array_t           curr_names, next_names;
[496]     ngx_hash_key_t       *name, *next_name;
[497]     ngx_hash_init_t       h;
[498]     ngx_hash_wildcard_t  *wdc;
[499] 
[500]     if (ngx_array_init(&curr_names, hinit->temp_pool, nelts,
[501]                        sizeof(ngx_hash_key_t))
[502]         != NGX_OK)
[503]     {
[504]         return NGX_ERROR;
[505]     }
[506] 
[507]     if (ngx_array_init(&next_names, hinit->temp_pool, nelts,
[508]                        sizeof(ngx_hash_key_t))
[509]         != NGX_OK)
[510]     {
[511]         return NGX_ERROR;
[512]     }
[513] 
[514]     for (n = 0; n < nelts; n = i) {
[515] 
[516] #if 0
[517]         ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[518]                       "wc0: \"%V\"", &names[n].key);
[519] #endif
[520] 
[521]         dot = 0;
[522] 
[523]         for (len = 0; len < names[n].key.len; len++) {
[524]             if (names[n].key.data[len] == '.') {
[525]                 dot = 1;
[526]                 break;
[527]             }
[528]         }
[529] 
[530]         name = ngx_array_push(&curr_names);
[531]         if (name == NULL) {
[532]             return NGX_ERROR;
[533]         }
[534] 
[535]         name->key.len = len;
[536]         name->key.data = names[n].key.data;
[537]         name->key_hash = hinit->key(name->key.data, name->key.len);
[538]         name->value = names[n].value;
[539] 
[540] #if 0
[541]         ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[542]                       "wc1: \"%V\" %ui", &name->key, dot);
[543] #endif
[544] 
[545]         dot_len = len + 1;
[546] 
[547]         if (dot) {
[548]             len++;
[549]         }
[550] 
[551]         next_names.nelts = 0;
[552] 
[553]         if (names[n].key.len != len) {
[554]             next_name = ngx_array_push(&next_names);
[555]             if (next_name == NULL) {
[556]                 return NGX_ERROR;
[557]             }
[558] 
[559]             next_name->key.len = names[n].key.len - len;
[560]             next_name->key.data = names[n].key.data + len;
[561]             next_name->key_hash = 0;
[562]             next_name->value = names[n].value;
[563] 
[564] #if 0
[565]             ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[566]                           "wc2: \"%V\"", &next_name->key);
[567] #endif
[568]         }
[569] 
[570]         for (i = n + 1; i < nelts; i++) {
[571]             if (ngx_strncmp(names[n].key.data, names[i].key.data, len) != 0) {
[572]                 break;
[573]             }
[574] 
[575]             if (!dot
[576]                 && names[i].key.len > len
[577]                 && names[i].key.data[len] != '.')
[578]             {
[579]                 break;
[580]             }
[581] 
[582]             next_name = ngx_array_push(&next_names);
[583]             if (next_name == NULL) {
[584]                 return NGX_ERROR;
[585]             }
[586] 
[587]             next_name->key.len = names[i].key.len - dot_len;
[588]             next_name->key.data = names[i].key.data + dot_len;
[589]             next_name->key_hash = 0;
[590]             next_name->value = names[i].value;
[591] 
[592] #if 0
[593]             ngx_log_error(NGX_LOG_ALERT, hinit->pool->log, 0,
[594]                           "wc3: \"%V\"", &next_name->key);
[595] #endif
[596]         }
[597] 
[598]         if (next_names.nelts) {
[599] 
[600]             h = *hinit;
[601]             h.hash = NULL;
[602] 
[603]             if (ngx_hash_wildcard_init(&h, (ngx_hash_key_t *) next_names.elts,
[604]                                        next_names.nelts)
[605]                 != NGX_OK)
[606]             {
[607]                 return NGX_ERROR;
[608]             }
[609] 
[610]             wdc = (ngx_hash_wildcard_t *) h.hash;
[611] 
[612]             if (names[n].key.len == len) {
[613]                 wdc->value = names[n].value;
[614]             }
[615] 
[616]             name->value = (void *) ((uintptr_t) wdc | (dot ? 3 : 2));
[617] 
[618]         } else if (dot) {
[619]             name->value = (void *) ((uintptr_t) name->value | 1);
[620]         }
[621]     }
[622] 
[623]     if (ngx_hash_init(hinit, (ngx_hash_key_t *) curr_names.elts,
[624]                       curr_names.nelts)
[625]         != NGX_OK)
[626]     {
[627]         return NGX_ERROR;
[628]     }
[629] 
[630]     return NGX_OK;
[631] }
[632] 
[633] 
[634] ngx_uint_t
[635] ngx_hash_key(u_char *data, size_t len)
[636] {
[637]     ngx_uint_t  i, key;
[638] 
[639]     key = 0;
[640] 
[641]     for (i = 0; i < len; i++) {
[642]         key = ngx_hash(key, data[i]);
[643]     }
[644] 
[645]     return key;
[646] }
[647] 
[648] 
[649] ngx_uint_t
[650] ngx_hash_key_lc(u_char *data, size_t len)
[651] {
[652]     ngx_uint_t  i, key;
[653] 
[654]     key = 0;
[655] 
[656]     for (i = 0; i < len; i++) {
[657]         key = ngx_hash(key, ngx_tolower(data[i]));
[658]     }
[659] 
[660]     return key;
[661] }
[662] 
[663] 
[664] ngx_uint_t
[665] ngx_hash_strlow(u_char *dst, u_char *src, size_t n)
[666] {
[667]     ngx_uint_t  key;
[668] 
[669]     key = 0;
[670] 
[671]     while (n--) {
[672]         *dst = ngx_tolower(*src);
[673]         key = ngx_hash(key, *dst);
[674]         dst++;
[675]         src++;
[676]     }
[677] 
[678]     return key;
[679] }
[680] 
[681] 
[682] ngx_int_t
[683] ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type)
[684] {
[685]     ngx_uint_t  asize;
[686] 
[687]     if (type == NGX_HASH_SMALL) {
[688]         asize = 4;
[689]         ha->hsize = 107;
[690] 
[691]     } else {
[692]         asize = NGX_HASH_LARGE_ASIZE;
[693]         ha->hsize = NGX_HASH_LARGE_HSIZE;
[694]     }
[695] 
[696]     if (ngx_array_init(&ha->keys, ha->temp_pool, asize, sizeof(ngx_hash_key_t))
[697]         != NGX_OK)
[698]     {
[699]         return NGX_ERROR;
[700]     }
[701] 
[702]     if (ngx_array_init(&ha->dns_wc_head, ha->temp_pool, asize,
[703]                        sizeof(ngx_hash_key_t))
[704]         != NGX_OK)
[705]     {
[706]         return NGX_ERROR;
[707]     }
[708] 
[709]     if (ngx_array_init(&ha->dns_wc_tail, ha->temp_pool, asize,
[710]                        sizeof(ngx_hash_key_t))
[711]         != NGX_OK)
[712]     {
[713]         return NGX_ERROR;
[714]     }
[715] 
[716]     ha->keys_hash = ngx_pcalloc(ha->temp_pool, sizeof(ngx_array_t) * ha->hsize);
[717]     if (ha->keys_hash == NULL) {
[718]         return NGX_ERROR;
[719]     }
[720] 
[721]     ha->dns_wc_head_hash = ngx_pcalloc(ha->temp_pool,
[722]                                        sizeof(ngx_array_t) * ha->hsize);
[723]     if (ha->dns_wc_head_hash == NULL) {
[724]         return NGX_ERROR;
[725]     }
[726] 
[727]     ha->dns_wc_tail_hash = ngx_pcalloc(ha->temp_pool,
[728]                                        sizeof(ngx_array_t) * ha->hsize);
[729]     if (ha->dns_wc_tail_hash == NULL) {
[730]         return NGX_ERROR;
[731]     }
[732] 
[733]     return NGX_OK;
[734] }
[735] 
[736] 
[737] ngx_int_t
[738] ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key, void *value,
[739]     ngx_uint_t flags)
[740] {
[741]     size_t           len;
[742]     u_char          *p;
[743]     ngx_str_t       *name;
[744]     ngx_uint_t       i, k, n, skip, last;
[745]     ngx_array_t     *keys, *hwc;
[746]     ngx_hash_key_t  *hk;
[747] 
[748]     last = key->len;
[749] 
[750]     if (flags & NGX_HASH_WILDCARD_KEY) {
[751] 
[752]         /*
[753]          * supported wildcards:
[754]          *     "*.example.com", ".example.com", and "www.example.*"
[755]          */
[756] 
[757]         n = 0;
[758] 
[759]         for (i = 0; i < key->len; i++) {
[760] 
[761]             if (key->data[i] == '*') {
[762]                 if (++n > 1) {
[763]                     return NGX_DECLINED;
[764]                 }
[765]             }
[766] 
[767]             if (key->data[i] == '.' && key->data[i + 1] == '.') {
[768]                 return NGX_DECLINED;
[769]             }
[770] 
[771]             if (key->data[i] == '\0') {
[772]                 return NGX_DECLINED;
[773]             }
[774]         }
[775] 
[776]         if (key->len > 1 && key->data[0] == '.') {
[777]             skip = 1;
[778]             goto wildcard;
[779]         }
[780] 
[781]         if (key->len > 2) {
[782] 
[783]             if (key->data[0] == '*' && key->data[1] == '.') {
[784]                 skip = 2;
[785]                 goto wildcard;
[786]             }
[787] 
[788]             if (key->data[i - 2] == '.' && key->data[i - 1] == '*') {
[789]                 skip = 0;
[790]                 last -= 2;
[791]                 goto wildcard;
[792]             }
[793]         }
[794] 
[795]         if (n) {
[796]             return NGX_DECLINED;
[797]         }
[798]     }
[799] 
[800]     /* exact hash */
[801] 
[802]     k = 0;
[803] 
[804]     for (i = 0; i < last; i++) {
[805]         if (!(flags & NGX_HASH_READONLY_KEY)) {
[806]             key->data[i] = ngx_tolower(key->data[i]);
[807]         }
[808]         k = ngx_hash(k, key->data[i]);
[809]     }
[810] 
[811]     k %= ha->hsize;
[812] 
[813]     /* check conflicts in exact hash */
[814] 
[815]     name = ha->keys_hash[k].elts;
[816] 
[817]     if (name) {
[818]         for (i = 0; i < ha->keys_hash[k].nelts; i++) {
[819]             if (last != name[i].len) {
[820]                 continue;
[821]             }
[822] 
[823]             if (ngx_strncmp(key->data, name[i].data, last) == 0) {
[824]                 return NGX_BUSY;
[825]             }
[826]         }
[827] 
[828]     } else {
[829]         if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
[830]                            sizeof(ngx_str_t))
[831]             != NGX_OK)
[832]         {
[833]             return NGX_ERROR;
[834]         }
[835]     }
[836] 
[837]     name = ngx_array_push(&ha->keys_hash[k]);
[838]     if (name == NULL) {
[839]         return NGX_ERROR;
[840]     }
[841] 
[842]     *name = *key;
[843] 
[844]     hk = ngx_array_push(&ha->keys);
[845]     if (hk == NULL) {
[846]         return NGX_ERROR;
[847]     }
[848] 
[849]     hk->key = *key;
[850]     hk->key_hash = ngx_hash_key(key->data, last);
[851]     hk->value = value;
[852] 
[853]     return NGX_OK;
[854] 
[855] 
[856] wildcard:
[857] 
[858]     /* wildcard hash */
[859] 
[860]     k = ngx_hash_strlow(&key->data[skip], &key->data[skip], last - skip);
[861] 
[862]     k %= ha->hsize;
[863] 
[864]     if (skip == 1) {
[865] 
[866]         /* check conflicts in exact hash for ".example.com" */
[867] 
[868]         name = ha->keys_hash[k].elts;
[869] 
[870]         if (name) {
[871]             len = last - skip;
[872] 
[873]             for (i = 0; i < ha->keys_hash[k].nelts; i++) {
[874]                 if (len != name[i].len) {
[875]                     continue;
[876]                 }
[877] 
[878]                 if (ngx_strncmp(&key->data[1], name[i].data, len) == 0) {
[879]                     return NGX_BUSY;
[880]                 }
[881]             }
[882] 
[883]         } else {
[884]             if (ngx_array_init(&ha->keys_hash[k], ha->temp_pool, 4,
[885]                                sizeof(ngx_str_t))
[886]                 != NGX_OK)
[887]             {
[888]                 return NGX_ERROR;
[889]             }
[890]         }
[891] 
[892]         name = ngx_array_push(&ha->keys_hash[k]);
[893]         if (name == NULL) {
[894]             return NGX_ERROR;
[895]         }
[896] 
[897]         name->len = last - 1;
[898]         name->data = ngx_pnalloc(ha->temp_pool, name->len);
[899]         if (name->data == NULL) {
[900]             return NGX_ERROR;
[901]         }
[902] 
[903]         ngx_memcpy(name->data, &key->data[1], name->len);
[904]     }
[905] 
[906] 
[907]     if (skip) {
[908] 
[909]         /*
[910]          * convert "*.example.com" to "com.example.\0"
[911]          *      and ".example.com" to "com.example\0"
[912]          */
[913] 
[914]         p = ngx_pnalloc(ha->temp_pool, last);
[915]         if (p == NULL) {
[916]             return NGX_ERROR;
[917]         }
[918] 
[919]         len = 0;
[920]         n = 0;
[921] 
[922]         for (i = last - 1; i; i--) {
[923]             if (key->data[i] == '.') {
[924]                 ngx_memcpy(&p[n], &key->data[i + 1], len);
[925]                 n += len;
[926]                 p[n++] = '.';
[927]                 len = 0;
[928]                 continue;
[929]             }
[930] 
[931]             len++;
[932]         }
[933] 
[934]         if (len) {
[935]             ngx_memcpy(&p[n], &key->data[1], len);
[936]             n += len;
[937]         }
[938] 
[939]         p[n] = '\0';
[940] 
[941]         hwc = &ha->dns_wc_head;
[942]         keys = &ha->dns_wc_head_hash[k];
[943] 
[944]     } else {
[945] 
[946]         /* convert "www.example.*" to "www.example\0" */
[947] 
[948]         last++;
[949] 
[950]         p = ngx_pnalloc(ha->temp_pool, last);
[951]         if (p == NULL) {
[952]             return NGX_ERROR;
[953]         }
[954] 
[955]         ngx_cpystrn(p, key->data, last);
[956] 
[957]         hwc = &ha->dns_wc_tail;
[958]         keys = &ha->dns_wc_tail_hash[k];
[959]     }
[960] 
[961] 
[962]     /* check conflicts in wildcard hash */
[963] 
[964]     name = keys->elts;
[965] 
[966]     if (name) {
[967]         len = last - skip;
[968] 
[969]         for (i = 0; i < keys->nelts; i++) {
[970]             if (len != name[i].len) {
[971]                 continue;
[972]             }
[973] 
[974]             if (ngx_strncmp(key->data + skip, name[i].data, len) == 0) {
[975]                 return NGX_BUSY;
[976]             }
[977]         }
[978] 
[979]     } else {
[980]         if (ngx_array_init(keys, ha->temp_pool, 4, sizeof(ngx_str_t)) != NGX_OK)
[981]         {
[982]             return NGX_ERROR;
[983]         }
[984]     }
[985] 
[986]     name = ngx_array_push(keys);
[987]     if (name == NULL) {
[988]         return NGX_ERROR;
[989]     }
[990] 
[991]     name->len = last - skip;
[992]     name->data = ngx_pnalloc(ha->temp_pool, name->len);
[993]     if (name->data == NULL) {
[994]         return NGX_ERROR;
[995]     }
[996] 
[997]     ngx_memcpy(name->data, key->data + skip, name->len);
[998] 
[999] 
[1000]     /* add to wildcard hash */
[1001] 
[1002]     hk = ngx_array_push(hwc);
[1003]     if (hk == NULL) {
[1004]         return NGX_ERROR;
[1005]     }
[1006] 
[1007]     hk->key.len = last - 1;
[1008]     hk->key.data = p;
[1009]     hk->key_hash = 0;
[1010]     hk->value = value;
[1011] 
[1012]     return NGX_OK;
[1013] }
