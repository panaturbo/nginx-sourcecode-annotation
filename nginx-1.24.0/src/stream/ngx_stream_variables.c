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
[11] #include <nginx.h>
[12] 
[13] static ngx_stream_variable_t *ngx_stream_add_prefix_variable(ngx_conf_t *cf,
[14]     ngx_str_t *name, ngx_uint_t flags);
[15] 
[16] static ngx_int_t ngx_stream_variable_binary_remote_addr(
[17]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[18] static ngx_int_t ngx_stream_variable_remote_addr(ngx_stream_session_t *s,
[19]     ngx_stream_variable_value_t *v, uintptr_t data);
[20] static ngx_int_t ngx_stream_variable_remote_port(ngx_stream_session_t *s,
[21]     ngx_stream_variable_value_t *v, uintptr_t data);
[22] static ngx_int_t ngx_stream_variable_proxy_protocol_addr(
[23]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[24] static ngx_int_t ngx_stream_variable_proxy_protocol_port(
[25]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[26] static ngx_int_t ngx_stream_variable_proxy_protocol_tlv(
[27]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[28] static ngx_int_t ngx_stream_variable_server_addr(ngx_stream_session_t *s,
[29]     ngx_stream_variable_value_t *v, uintptr_t data);
[30] static ngx_int_t ngx_stream_variable_server_port(ngx_stream_session_t *s,
[31]     ngx_stream_variable_value_t *v, uintptr_t data);
[32] static ngx_int_t ngx_stream_variable_bytes(ngx_stream_session_t *s,
[33]     ngx_stream_variable_value_t *v, uintptr_t data);
[34] static ngx_int_t ngx_stream_variable_session_time(ngx_stream_session_t *s,
[35]     ngx_stream_variable_value_t *v, uintptr_t data);
[36] static ngx_int_t ngx_stream_variable_status(ngx_stream_session_t *s,
[37]     ngx_stream_variable_value_t *v, uintptr_t data);
[38] static ngx_int_t ngx_stream_variable_connection(ngx_stream_session_t *s,
[39]     ngx_stream_variable_value_t *v, uintptr_t data);
[40] 
[41] static ngx_int_t ngx_stream_variable_nginx_version(ngx_stream_session_t *s,
[42]     ngx_stream_variable_value_t *v, uintptr_t data);
[43] static ngx_int_t ngx_stream_variable_hostname(ngx_stream_session_t *s,
[44]     ngx_stream_variable_value_t *v, uintptr_t data);
[45] static ngx_int_t ngx_stream_variable_pid(ngx_stream_session_t *s,
[46]     ngx_stream_variable_value_t *v, uintptr_t data);
[47] static ngx_int_t ngx_stream_variable_msec(ngx_stream_session_t *s,
[48]     ngx_stream_variable_value_t *v, uintptr_t data);
[49] static ngx_int_t ngx_stream_variable_time_iso8601(ngx_stream_session_t *s,
[50]     ngx_stream_variable_value_t *v, uintptr_t data);
[51] static ngx_int_t ngx_stream_variable_time_local(ngx_stream_session_t *s,
[52]     ngx_stream_variable_value_t *v, uintptr_t data);
[53] static ngx_int_t ngx_stream_variable_protocol(ngx_stream_session_t *s,
[54]     ngx_stream_variable_value_t *v, uintptr_t data);
[55] 
[56] 
[57] static ngx_stream_variable_t  ngx_stream_core_variables[] = {
[58] 
[59]     { ngx_string("binary_remote_addr"), NULL,
[60]       ngx_stream_variable_binary_remote_addr, 0, 0, 0 },
[61] 
[62]     { ngx_string("remote_addr"), NULL,
[63]       ngx_stream_variable_remote_addr, 0, 0, 0 },
[64] 
[65]     { ngx_string("remote_port"), NULL,
[66]       ngx_stream_variable_remote_port, 0, 0, 0 },
[67] 
[68]     { ngx_string("proxy_protocol_addr"), NULL,
[69]       ngx_stream_variable_proxy_protocol_addr,
[70]       offsetof(ngx_proxy_protocol_t, src_addr), 0, 0 },
[71] 
[72]     { ngx_string("proxy_protocol_port"), NULL,
[73]       ngx_stream_variable_proxy_protocol_port,
[74]       offsetof(ngx_proxy_protocol_t, src_port), 0, 0 },
[75] 
[76]     { ngx_string("proxy_protocol_server_addr"), NULL,
[77]       ngx_stream_variable_proxy_protocol_addr,
[78]       offsetof(ngx_proxy_protocol_t, dst_addr), 0, 0 },
[79] 
[80]     { ngx_string("proxy_protocol_server_port"), NULL,
[81]       ngx_stream_variable_proxy_protocol_port,
[82]       offsetof(ngx_proxy_protocol_t, dst_port), 0, 0 },
[83] 
[84]     { ngx_string("proxy_protocol_tlv_"), NULL,
[85]       ngx_stream_variable_proxy_protocol_tlv,
[86]       0, NGX_STREAM_VAR_PREFIX, 0 },
[87] 
[88]     { ngx_string("server_addr"), NULL,
[89]       ngx_stream_variable_server_addr, 0, 0, 0 },
[90] 
[91]     { ngx_string("server_port"), NULL,
[92]       ngx_stream_variable_server_port, 0, 0, 0 },
[93] 
[94]     { ngx_string("bytes_sent"), NULL, ngx_stream_variable_bytes,
[95]       0, 0, 0 },
[96] 
[97]     { ngx_string("bytes_received"), NULL, ngx_stream_variable_bytes,
[98]       1, 0, 0 },
[99] 
[100]     { ngx_string("session_time"), NULL, ngx_stream_variable_session_time,
[101]       0, NGX_STREAM_VAR_NOCACHEABLE, 0 },
[102] 
[103]     { ngx_string("status"), NULL, ngx_stream_variable_status,
[104]       0, NGX_STREAM_VAR_NOCACHEABLE, 0 },
[105] 
[106]     { ngx_string("connection"), NULL,
[107]       ngx_stream_variable_connection, 0, 0, 0 },
[108] 
[109]     { ngx_string("nginx_version"), NULL, ngx_stream_variable_nginx_version,
[110]       0, 0, 0 },
[111] 
[112]     { ngx_string("hostname"), NULL, ngx_stream_variable_hostname,
[113]       0, 0, 0 },
[114] 
[115]     { ngx_string("pid"), NULL, ngx_stream_variable_pid,
[116]       0, 0, 0 },
[117] 
[118]     { ngx_string("msec"), NULL, ngx_stream_variable_msec,
[119]       0, NGX_STREAM_VAR_NOCACHEABLE, 0 },
[120] 
[121]     { ngx_string("time_iso8601"), NULL, ngx_stream_variable_time_iso8601,
[122]       0, NGX_STREAM_VAR_NOCACHEABLE, 0 },
[123] 
[124]     { ngx_string("time_local"), NULL, ngx_stream_variable_time_local,
[125]       0, NGX_STREAM_VAR_NOCACHEABLE, 0 },
[126] 
[127]     { ngx_string("protocol"), NULL,
[128]       ngx_stream_variable_protocol, 0, 0, 0 },
[129] 
[130]       ngx_stream_null_variable
[131] };
[132] 
[133] 
[134] ngx_stream_variable_value_t  ngx_stream_variable_null_value =
[135]     ngx_stream_variable("");
[136] ngx_stream_variable_value_t  ngx_stream_variable_true_value =
[137]     ngx_stream_variable("1");
[138] 
[139] 
[140] static ngx_uint_t  ngx_stream_variable_depth = 100;
[141] 
[142] 
[143] ngx_stream_variable_t *
[144] ngx_stream_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
[145] {
[146]     ngx_int_t                     rc;
[147]     ngx_uint_t                    i;
[148]     ngx_hash_key_t               *key;
[149]     ngx_stream_variable_t        *v;
[150]     ngx_stream_core_main_conf_t  *cmcf;
[151] 
[152]     if (name->len == 0) {
[153]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[154]                            "invalid variable name \"$\"");
[155]         return NULL;
[156]     }
[157] 
[158]     if (flags & NGX_STREAM_VAR_PREFIX) {
[159]         return ngx_stream_add_prefix_variable(cf, name, flags);
[160]     }
[161] 
[162]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[163] 
[164]     key = cmcf->variables_keys->keys.elts;
[165]     for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
[166]         if (name->len != key[i].key.len
[167]             || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
[168]         {
[169]             continue;
[170]         }
[171] 
[172]         v = key[i].value;
[173] 
[174]         if (!(v->flags & NGX_STREAM_VAR_CHANGEABLE)) {
[175]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[176]                                "the duplicate \"%V\" variable", name);
[177]             return NULL;
[178]         }
[179] 
[180]         if (!(flags & NGX_STREAM_VAR_WEAK)) {
[181]             v->flags &= ~NGX_STREAM_VAR_WEAK;
[182]         }
[183] 
[184]         return v;
[185]     }
[186] 
[187]     v = ngx_palloc(cf->pool, sizeof(ngx_stream_variable_t));
[188]     if (v == NULL) {
[189]         return NULL;
[190]     }
[191] 
[192]     v->name.len = name->len;
[193]     v->name.data = ngx_pnalloc(cf->pool, name->len);
[194]     if (v->name.data == NULL) {
[195]         return NULL;
[196]     }
[197] 
[198]     ngx_strlow(v->name.data, name->data, name->len);
[199] 
[200]     v->set_handler = NULL;
[201]     v->get_handler = NULL;
[202]     v->data = 0;
[203]     v->flags = flags;
[204]     v->index = 0;
[205] 
[206]     rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);
[207] 
[208]     if (rc == NGX_ERROR) {
[209]         return NULL;
[210]     }
[211] 
[212]     if (rc == NGX_BUSY) {
[213]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[214]                            "conflicting variable name \"%V\"", name);
[215]         return NULL;
[216]     }
[217] 
[218]     return v;
[219] }
[220] 
[221] 
[222] static ngx_stream_variable_t *
[223] ngx_stream_add_prefix_variable(ngx_conf_t *cf, ngx_str_t *name,
[224]     ngx_uint_t flags)
[225] {
[226]     ngx_uint_t                    i;
[227]     ngx_stream_variable_t        *v;
[228]     ngx_stream_core_main_conf_t  *cmcf;
[229] 
[230]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[231] 
[232]     v = cmcf->prefix_variables.elts;
[233]     for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
[234]         if (name->len != v[i].name.len
[235]             || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
[236]         {
[237]             continue;
[238]         }
[239] 
[240]         v = &v[i];
[241] 
[242]         if (!(v->flags & NGX_STREAM_VAR_CHANGEABLE)) {
[243]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[244]                                "the duplicate \"%V\" variable", name);
[245]             return NULL;
[246]         }
[247] 
[248]         if (!(flags & NGX_STREAM_VAR_WEAK)) {
[249]             v->flags &= ~NGX_STREAM_VAR_WEAK;
[250]         }
[251] 
[252]         return v;
[253]     }
[254] 
[255]     v = ngx_array_push(&cmcf->prefix_variables);
[256]     if (v == NULL) {
[257]         return NULL;
[258]     }
[259] 
[260]     v->name.len = name->len;
[261]     v->name.data = ngx_pnalloc(cf->pool, name->len);
[262]     if (v->name.data == NULL) {
[263]         return NULL;
[264]     }
[265] 
[266]     ngx_strlow(v->name.data, name->data, name->len);
[267] 
[268]     v->set_handler = NULL;
[269]     v->get_handler = NULL;
[270]     v->data = 0;
[271]     v->flags = flags;
[272]     v->index = 0;
[273] 
[274]     return v;
[275] }
[276] 
[277] 
[278] ngx_int_t
[279] ngx_stream_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
[280] {
[281]     ngx_uint_t                    i;
[282]     ngx_stream_variable_t        *v;
[283]     ngx_stream_core_main_conf_t  *cmcf;
[284] 
[285]     if (name->len == 0) {
[286]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[287]                            "invalid variable name \"$\"");
[288]         return NGX_ERROR;
[289]     }
[290] 
[291]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[292] 
[293]     v = cmcf->variables.elts;
[294] 
[295]     if (v == NULL) {
[296]         if (ngx_array_init(&cmcf->variables, cf->pool, 4,
[297]                            sizeof(ngx_stream_variable_t))
[298]             != NGX_OK)
[299]         {
[300]             return NGX_ERROR;
[301]         }
[302] 
[303]     } else {
[304]         for (i = 0; i < cmcf->variables.nelts; i++) {
[305]             if (name->len != v[i].name.len
[306]                 || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
[307]             {
[308]                 continue;
[309]             }
[310] 
[311]             return i;
[312]         }
[313]     }
[314] 
[315]     v = ngx_array_push(&cmcf->variables);
[316]     if (v == NULL) {
[317]         return NGX_ERROR;
[318]     }
[319] 
[320]     v->name.len = name->len;
[321]     v->name.data = ngx_pnalloc(cf->pool, name->len);
[322]     if (v->name.data == NULL) {
[323]         return NGX_ERROR;
[324]     }
[325] 
[326]     ngx_strlow(v->name.data, name->data, name->len);
[327] 
[328]     v->set_handler = NULL;
[329]     v->get_handler = NULL;
[330]     v->data = 0;
[331]     v->flags = 0;
[332]     v->index = cmcf->variables.nelts - 1;
[333] 
[334]     return v->index;
[335] }
[336] 
[337] 
[338] ngx_stream_variable_value_t *
[339] ngx_stream_get_indexed_variable(ngx_stream_session_t *s, ngx_uint_t index)
[340] {
[341]     ngx_stream_variable_t        *v;
[342]     ngx_stream_core_main_conf_t  *cmcf;
[343] 
[344]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[345] 
[346]     if (cmcf->variables.nelts <= index) {
[347]         ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
[348]                       "unknown variable index: %ui", index);
[349]         return NULL;
[350]     }
[351] 
[352]     if (s->variables[index].not_found || s->variables[index].valid) {
[353]         return &s->variables[index];
[354]     }
[355] 
[356]     v = cmcf->variables.elts;
[357] 
[358]     if (ngx_stream_variable_depth == 0) {
[359]         ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[360]                       "cycle while evaluating variable \"%V\"",
[361]                       &v[index].name);
[362]         return NULL;
[363]     }
[364] 
[365]     ngx_stream_variable_depth--;
[366] 
[367]     if (v[index].get_handler(s, &s->variables[index], v[index].data)
[368]         == NGX_OK)
[369]     {
[370]         ngx_stream_variable_depth++;
[371] 
[372]         if (v[index].flags & NGX_STREAM_VAR_NOCACHEABLE) {
[373]             s->variables[index].no_cacheable = 1;
[374]         }
[375] 
[376]         return &s->variables[index];
[377]     }
[378] 
[379]     ngx_stream_variable_depth++;
[380] 
[381]     s->variables[index].valid = 0;
[382]     s->variables[index].not_found = 1;
[383] 
[384]     return NULL;
[385] }
[386] 
[387] 
[388] ngx_stream_variable_value_t *
[389] ngx_stream_get_flushed_variable(ngx_stream_session_t *s, ngx_uint_t index)
[390] {
[391]     ngx_stream_variable_value_t  *v;
[392] 
[393]     v = &s->variables[index];
[394] 
[395]     if (v->valid || v->not_found) {
[396]         if (!v->no_cacheable) {
[397]             return v;
[398]         }
[399] 
[400]         v->valid = 0;
[401]         v->not_found = 0;
[402]     }
[403] 
[404]     return ngx_stream_get_indexed_variable(s, index);
[405] }
[406] 
[407] 
[408] ngx_stream_variable_value_t *
[409] ngx_stream_get_variable(ngx_stream_session_t *s, ngx_str_t *name,
[410]     ngx_uint_t key)
[411] {
[412]     size_t                        len;
[413]     ngx_uint_t                    i, n;
[414]     ngx_stream_variable_t        *v;
[415]     ngx_stream_variable_value_t  *vv;
[416]     ngx_stream_core_main_conf_t  *cmcf;
[417] 
[418]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[419] 
[420]     v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);
[421] 
[422]     if (v) {
[423]         if (v->flags & NGX_STREAM_VAR_INDEXED) {
[424]             return ngx_stream_get_flushed_variable(s, v->index);
[425]         }
[426] 
[427]         if (ngx_stream_variable_depth == 0) {
[428]             ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
[429]                           "cycle while evaluating variable \"%V\"", name);
[430]             return NULL;
[431]         }
[432] 
[433]         ngx_stream_variable_depth--;
[434] 
[435]         vv = ngx_palloc(s->connection->pool,
[436]                         sizeof(ngx_stream_variable_value_t));
[437] 
[438]         if (vv && v->get_handler(s, vv, v->data) == NGX_OK) {
[439]             ngx_stream_variable_depth++;
[440]             return vv;
[441]         }
[442] 
[443]         ngx_stream_variable_depth++;
[444]         return NULL;
[445]     }
[446] 
[447]     vv = ngx_palloc(s->connection->pool, sizeof(ngx_stream_variable_value_t));
[448]     if (vv == NULL) {
[449]         return NULL;
[450]     }
[451] 
[452]     len = 0;
[453] 
[454]     v = cmcf->prefix_variables.elts;
[455]     n = cmcf->prefix_variables.nelts;
[456] 
[457]     for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
[458]         if (name->len >= v[i].name.len && name->len > len
[459]             && ngx_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
[460]         {
[461]             len = v[i].name.len;
[462]             n = i;
[463]         }
[464]     }
[465] 
[466]     if (n != cmcf->prefix_variables.nelts) {
[467]         if (v[n].get_handler(s, vv, (uintptr_t) name) == NGX_OK) {
[468]             return vv;
[469]         }
[470] 
[471]         return NULL;
[472]     }
[473] 
[474]     vv->not_found = 1;
[475] 
[476]     return vv;
[477] }
[478] 
[479] 
[480] static ngx_int_t
[481] ngx_stream_variable_binary_remote_addr(ngx_stream_session_t *s,
[482]      ngx_stream_variable_value_t *v, uintptr_t data)
[483] {
[484]     struct sockaddr_in   *sin;
[485] #if (NGX_HAVE_INET6)
[486]     struct sockaddr_in6  *sin6;
[487] #endif
[488] 
[489]     switch (s->connection->sockaddr->sa_family) {
[490] 
[491] #if (NGX_HAVE_INET6)
[492]     case AF_INET6:
[493]         sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
[494] 
[495]         v->len = sizeof(struct in6_addr);
[496]         v->valid = 1;
[497]         v->no_cacheable = 0;
[498]         v->not_found = 0;
[499]         v->data = sin6->sin6_addr.s6_addr;
[500] 
[501]         break;
[502] #endif
[503] 
[504] #if (NGX_HAVE_UNIX_DOMAIN)
[505]     case AF_UNIX:
[506] 
[507]         v->len = s->connection->addr_text.len;
[508]         v->valid = 1;
[509]         v->no_cacheable = 0;
[510]         v->not_found = 0;
[511]         v->data = s->connection->addr_text.data;
[512] 
[513]         break;
[514] #endif
[515] 
[516]     default: /* AF_INET */
[517]         sin = (struct sockaddr_in *) s->connection->sockaddr;
[518] 
[519]         v->len = sizeof(in_addr_t);
[520]         v->valid = 1;
[521]         v->no_cacheable = 0;
[522]         v->not_found = 0;
[523]         v->data = (u_char *) &sin->sin_addr;
[524] 
[525]         break;
[526]     }
[527] 
[528]     return NGX_OK;
[529] }
[530] 
[531] 
[532] static ngx_int_t
[533] ngx_stream_variable_remote_addr(ngx_stream_session_t *s,
[534]     ngx_stream_variable_value_t *v, uintptr_t data)
[535] {
[536]     v->len = s->connection->addr_text.len;
[537]     v->valid = 1;
[538]     v->no_cacheable = 0;
[539]     v->not_found = 0;
[540]     v->data = s->connection->addr_text.data;
[541] 
[542]     return NGX_OK;
[543] }
[544] 
[545] 
[546] static ngx_int_t
[547] ngx_stream_variable_remote_port(ngx_stream_session_t *s,
[548]     ngx_stream_variable_value_t *v, uintptr_t data)
[549] {
[550]     ngx_uint_t  port;
[551] 
[552]     v->len = 0;
[553]     v->valid = 1;
[554]     v->no_cacheable = 0;
[555]     v->not_found = 0;
[556] 
[557]     v->data = ngx_pnalloc(s->connection->pool, sizeof("65535") - 1);
[558]     if (v->data == NULL) {
[559]         return NGX_ERROR;
[560]     }
[561] 
[562]     port = ngx_inet_get_port(s->connection->sockaddr);
[563] 
[564]     if (port > 0 && port < 65536) {
[565]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[566]     }
[567] 
[568]     return NGX_OK;
[569] }
[570] 
[571] 
[572] static ngx_int_t
[573] ngx_stream_variable_proxy_protocol_addr(ngx_stream_session_t *s,
[574]     ngx_stream_variable_value_t *v, uintptr_t data)
[575] {
[576]     ngx_str_t             *addr;
[577]     ngx_proxy_protocol_t  *pp;
[578] 
[579]     pp = s->connection->proxy_protocol;
[580]     if (pp == NULL) {
[581]         v->not_found = 1;
[582]         return NGX_OK;
[583]     }
[584] 
[585]     addr = (ngx_str_t *) ((char *) pp + data);
[586] 
[587]     v->len = addr->len;
[588]     v->valid = 1;
[589]     v->no_cacheable = 0;
[590]     v->not_found = 0;
[591]     v->data = addr->data;
[592] 
[593]     return NGX_OK;
[594] }
[595] 
[596] 
[597] static ngx_int_t
[598] ngx_stream_variable_proxy_protocol_port(ngx_stream_session_t *s,
[599]     ngx_stream_variable_value_t *v, uintptr_t data)
[600] {
[601]     ngx_uint_t             port;
[602]     ngx_proxy_protocol_t  *pp;
[603] 
[604]     pp = s->connection->proxy_protocol;
[605]     if (pp == NULL) {
[606]         v->not_found = 1;
[607]         return NGX_OK;
[608]     }
[609] 
[610]     v->len = 0;
[611]     v->valid = 1;
[612]     v->no_cacheable = 0;
[613]     v->not_found = 0;
[614] 
[615]     v->data = ngx_pnalloc(s->connection->pool, sizeof("65535") - 1);
[616]     if (v->data == NULL) {
[617]         return NGX_ERROR;
[618]     }
[619] 
[620]     port = *(in_port_t *) ((char *) pp + data);
[621] 
[622]     if (port > 0 && port < 65536) {
[623]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[624]     }
[625] 
[626]     return NGX_OK;
[627] }
[628] 
[629] 
[630] static ngx_int_t
[631] ngx_stream_variable_proxy_protocol_tlv(ngx_stream_session_t *s,
[632]     ngx_stream_variable_value_t *v, uintptr_t data)
[633] {
[634]     ngx_str_t *name = (ngx_str_t *) data;
[635] 
[636]     ngx_int_t  rc;
[637]     ngx_str_t  tlv, value;
[638] 
[639]     tlv.len = name->len - (sizeof("proxy_protocol_tlv_") - 1);
[640]     tlv.data = name->data + sizeof("proxy_protocol_tlv_") - 1;
[641] 
[642]     rc = ngx_proxy_protocol_get_tlv(s->connection, &tlv, &value);
[643] 
[644]     if (rc == NGX_ERROR) {
[645]         return NGX_ERROR;
[646]     }
[647] 
[648]     if (rc == NGX_DECLINED) {
[649]         v->not_found = 1;
[650]         return NGX_OK;
[651]     }
[652] 
[653]     v->len = value.len;
[654]     v->valid = 1;
[655]     v->no_cacheable = 0;
[656]     v->not_found = 0;
[657]     v->data = value.data;
[658] 
[659]     return NGX_OK;
[660] }
[661] 
[662] 
[663] static ngx_int_t
[664] ngx_stream_variable_server_addr(ngx_stream_session_t *s,
[665]     ngx_stream_variable_value_t *v, uintptr_t data)
[666] {
[667]     ngx_str_t  str;
[668]     u_char     addr[NGX_SOCKADDR_STRLEN];
[669] 
[670]     str.len = NGX_SOCKADDR_STRLEN;
[671]     str.data = addr;
[672] 
[673]     if (ngx_connection_local_sockaddr(s->connection, &str, 0) != NGX_OK) {
[674]         return NGX_ERROR;
[675]     }
[676] 
[677]     str.data = ngx_pnalloc(s->connection->pool, str.len);
[678]     if (str.data == NULL) {
[679]         return NGX_ERROR;
[680]     }
[681] 
[682]     ngx_memcpy(str.data, addr, str.len);
[683] 
[684]     v->len = str.len;
[685]     v->valid = 1;
[686]     v->no_cacheable = 0;
[687]     v->not_found = 0;
[688]     v->data = str.data;
[689] 
[690]     return NGX_OK;
[691] }
[692] 
[693] 
[694] static ngx_int_t
[695] ngx_stream_variable_server_port(ngx_stream_session_t *s,
[696]     ngx_stream_variable_value_t *v, uintptr_t data)
[697] {
[698]     ngx_uint_t  port;
[699] 
[700]     v->len = 0;
[701]     v->valid = 1;
[702]     v->no_cacheable = 0;
[703]     v->not_found = 0;
[704] 
[705]     if (ngx_connection_local_sockaddr(s->connection, NULL, 0) != NGX_OK) {
[706]         return NGX_ERROR;
[707]     }
[708] 
[709]     v->data = ngx_pnalloc(s->connection->pool, sizeof("65535") - 1);
[710]     if (v->data == NULL) {
[711]         return NGX_ERROR;
[712]     }
[713] 
[714]     port = ngx_inet_get_port(s->connection->local_sockaddr);
[715] 
[716]     if (port > 0 && port < 65536) {
[717]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[718]     }
[719] 
[720]     return NGX_OK;
[721] }
[722] 
[723] 
[724] static ngx_int_t
[725] ngx_stream_variable_bytes(ngx_stream_session_t *s,
[726]     ngx_stream_variable_value_t *v, uintptr_t data)
[727] {
[728]     u_char  *p;
[729] 
[730]     p = ngx_pnalloc(s->connection->pool, NGX_OFF_T_LEN);
[731]     if (p == NULL) {
[732]         return NGX_ERROR;
[733]     }
[734] 
[735]     if (data == 1) {
[736]         v->len = ngx_sprintf(p, "%O", s->received) - p;
[737] 
[738]     } else {
[739]         v->len = ngx_sprintf(p, "%O", s->connection->sent) - p;
[740]     }
[741] 
[742]     v->valid = 1;
[743]     v->no_cacheable = 0;
[744]     v->not_found = 0;
[745]     v->data = p;
[746] 
[747]     return NGX_OK;
[748] }
[749] 
[750] 
[751] static ngx_int_t
[752] ngx_stream_variable_session_time(ngx_stream_session_t *s,
[753]     ngx_stream_variable_value_t *v, uintptr_t data)
[754] {
[755]     u_char          *p;
[756]     ngx_time_t      *tp;
[757]     ngx_msec_int_t   ms;
[758] 
[759]     p = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN + 4);
[760]     if (p == NULL) {
[761]         return NGX_ERROR;
[762]     }
[763] 
[764]     tp = ngx_timeofday();
[765] 
[766]     ms = (ngx_msec_int_t)
[767]              ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
[768]     ms = ngx_max(ms, 0);
[769] 
[770]     v->len = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
[771]     v->valid = 1;
[772]     v->no_cacheable = 0;
[773]     v->not_found = 0;
[774]     v->data = p;
[775] 
[776]     return NGX_OK;
[777] }
[778] 
[779] 
[780] static ngx_int_t
[781] ngx_stream_variable_status(ngx_stream_session_t *s,
[782]     ngx_stream_variable_value_t *v, uintptr_t data)
[783] {
[784]     v->data = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
[785]     if (v->data == NULL) {
[786]         return NGX_ERROR;
[787]     }
[788] 
[789]     v->len = ngx_sprintf(v->data, "%03ui", s->status) - v->data;
[790]     v->valid = 1;
[791]     v->no_cacheable = 0;
[792]     v->not_found = 0;
[793] 
[794]     return NGX_OK;
[795] }
[796] 
[797] 
[798] static ngx_int_t
[799] ngx_stream_variable_connection(ngx_stream_session_t *s,
[800]     ngx_stream_variable_value_t *v, uintptr_t data)
[801] {
[802]     u_char  *p;
[803] 
[804]     p = ngx_pnalloc(s->connection->pool, NGX_ATOMIC_T_LEN);
[805]     if (p == NULL) {
[806]         return NGX_ERROR;
[807]     }
[808] 
[809]     v->len = ngx_sprintf(p, "%uA", s->connection->number) - p;
[810]     v->valid = 1;
[811]     v->no_cacheable = 0;
[812]     v->not_found = 0;
[813]     v->data = p;
[814] 
[815]     return NGX_OK;
[816] }
[817] 
[818] 
[819] static ngx_int_t
[820] ngx_stream_variable_nginx_version(ngx_stream_session_t *s,
[821]     ngx_stream_variable_value_t *v, uintptr_t data)
[822] {
[823]     v->len = sizeof(NGINX_VERSION) - 1;
[824]     v->valid = 1;
[825]     v->no_cacheable = 0;
[826]     v->not_found = 0;
[827]     v->data = (u_char *) NGINX_VERSION;
[828] 
[829]     return NGX_OK;
[830] }
[831] 
[832] 
[833] static ngx_int_t
[834] ngx_stream_variable_hostname(ngx_stream_session_t *s,
[835]     ngx_stream_variable_value_t *v, uintptr_t data)
[836] {
[837]     v->len = ngx_cycle->hostname.len;
[838]     v->valid = 1;
[839]     v->no_cacheable = 0;
[840]     v->not_found = 0;
[841]     v->data = ngx_cycle->hostname.data;
[842] 
[843]     return NGX_OK;
[844] }
[845] 
[846] 
[847] static ngx_int_t
[848] ngx_stream_variable_pid(ngx_stream_session_t *s,
[849]     ngx_stream_variable_value_t *v, uintptr_t data)
[850] {
[851]     u_char  *p;
[852] 
[853]     p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
[854]     if (p == NULL) {
[855]         return NGX_ERROR;
[856]     }
[857] 
[858]     v->len = ngx_sprintf(p, "%P", ngx_pid) - p;
[859]     v->valid = 1;
[860]     v->no_cacheable = 0;
[861]     v->not_found = 0;
[862]     v->data = p;
[863] 
[864]     return NGX_OK;
[865] }
[866] 
[867] 
[868] static ngx_int_t
[869] ngx_stream_variable_msec(ngx_stream_session_t *s,
[870]     ngx_stream_variable_value_t *v, uintptr_t data)
[871] {
[872]     u_char      *p;
[873]     ngx_time_t  *tp;
[874] 
[875]     p = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN + 4);
[876]     if (p == NULL) {
[877]         return NGX_ERROR;
[878]     }
[879] 
[880]     tp = ngx_timeofday();
[881] 
[882]     v->len = ngx_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
[883]     v->valid = 1;
[884]     v->no_cacheable = 0;
[885]     v->not_found = 0;
[886]     v->data = p;
[887] 
[888]     return NGX_OK;
[889] }
[890] 
[891] 
[892] static ngx_int_t
[893] ngx_stream_variable_time_iso8601(ngx_stream_session_t *s,
[894]     ngx_stream_variable_value_t *v, uintptr_t data)
[895] {
[896]     u_char  *p;
[897] 
[898]     p = ngx_pnalloc(s->connection->pool, ngx_cached_http_log_iso8601.len);
[899]     if (p == NULL) {
[900]         return NGX_ERROR;
[901]     }
[902] 
[903]     ngx_memcpy(p, ngx_cached_http_log_iso8601.data,
[904]                ngx_cached_http_log_iso8601.len);
[905] 
[906]     v->len = ngx_cached_http_log_iso8601.len;
[907]     v->valid = 1;
[908]     v->no_cacheable = 0;
[909]     v->not_found = 0;
[910]     v->data = p;
[911] 
[912]     return NGX_OK;
[913] }
[914] 
[915] 
[916] static ngx_int_t
[917] ngx_stream_variable_time_local(ngx_stream_session_t *s,
[918]     ngx_stream_variable_value_t *v, uintptr_t data)
[919] {
[920]     u_char  *p;
[921] 
[922]     p = ngx_pnalloc(s->connection->pool, ngx_cached_http_log_time.len);
[923]     if (p == NULL) {
[924]         return NGX_ERROR;
[925]     }
[926] 
[927]     ngx_memcpy(p, ngx_cached_http_log_time.data, ngx_cached_http_log_time.len);
[928] 
[929]     v->len = ngx_cached_http_log_time.len;
[930]     v->valid = 1;
[931]     v->no_cacheable = 0;
[932]     v->not_found = 0;
[933]     v->data = p;
[934] 
[935]     return NGX_OK;
[936] }
[937] 
[938] 
[939] static ngx_int_t
[940] ngx_stream_variable_protocol(ngx_stream_session_t *s,
[941]     ngx_stream_variable_value_t *v, uintptr_t data)
[942] {
[943]     v->len = 3;
[944]     v->valid = 1;
[945]     v->no_cacheable = 0;
[946]     v->not_found = 0;
[947]     v->data = (u_char *) (s->connection->type == SOCK_DGRAM ? "UDP" : "TCP");
[948] 
[949]     return NGX_OK;
[950] }
[951] 
[952] 
[953] void *
[954] ngx_stream_map_find(ngx_stream_session_t *s, ngx_stream_map_t *map,
[955]     ngx_str_t *match)
[956] {
[957]     void        *value;
[958]     u_char      *low;
[959]     size_t       len;
[960]     ngx_uint_t   key;
[961] 
[962]     len = match->len;
[963] 
[964]     if (len) {
[965]         low = ngx_pnalloc(s->connection->pool, len);
[966]         if (low == NULL) {
[967]             return NULL;
[968]         }
[969] 
[970]     } else {
[971]         low = NULL;
[972]     }
[973] 
[974]     key = ngx_hash_strlow(low, match->data, len);
[975] 
[976]     value = ngx_hash_find_combined(&map->hash, key, low, len);
[977]     if (value) {
[978]         return value;
[979]     }
[980] 
[981] #if (NGX_PCRE)
[982] 
[983]     if (len && map->nregex) {
[984]         ngx_int_t                n;
[985]         ngx_uint_t               i;
[986]         ngx_stream_map_regex_t  *reg;
[987] 
[988]         reg = map->regex;
[989] 
[990]         for (i = 0; i < map->nregex; i++) {
[991] 
[992]             n = ngx_stream_regex_exec(s, reg[i].regex, match);
[993] 
[994]             if (n == NGX_OK) {
[995]                 return reg[i].value;
[996]             }
[997] 
[998]             if (n == NGX_DECLINED) {
[999]                 continue;
[1000]             }
[1001] 
[1002]             /* NGX_ERROR */
[1003] 
[1004]             return NULL;
[1005]         }
[1006]     }
[1007] 
[1008] #endif
[1009] 
[1010]     return NULL;
[1011] }
[1012] 
[1013] 
[1014] #if (NGX_PCRE)
[1015] 
[1016] static ngx_int_t
[1017] ngx_stream_variable_not_found(ngx_stream_session_t *s,
[1018]     ngx_stream_variable_value_t *v, uintptr_t data)
[1019] {
[1020]     v->not_found = 1;
[1021]     return NGX_OK;
[1022] }
[1023] 
[1024] 
[1025] ngx_stream_regex_t *
[1026] ngx_stream_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
[1027] {
[1028]     u_char                       *p;
[1029]     size_t                        size;
[1030]     ngx_str_t                     name;
[1031]     ngx_uint_t                    i, n;
[1032]     ngx_stream_variable_t        *v;
[1033]     ngx_stream_regex_t           *re;
[1034]     ngx_stream_regex_variable_t  *rv;
[1035]     ngx_stream_core_main_conf_t  *cmcf;
[1036] 
[1037]     rc->pool = cf->pool;
[1038] 
[1039]     if (ngx_regex_compile(rc) != NGX_OK) {
[1040]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
[1041]         return NULL;
[1042]     }
[1043] 
[1044]     re = ngx_pcalloc(cf->pool, sizeof(ngx_stream_regex_t));
[1045]     if (re == NULL) {
[1046]         return NULL;
[1047]     }
[1048] 
[1049]     re->regex = rc->regex;
[1050]     re->ncaptures = rc->captures;
[1051]     re->name = rc->pattern;
[1052] 
[1053]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[1054]     cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);
[1055] 
[1056]     n = (ngx_uint_t) rc->named_captures;
[1057] 
[1058]     if (n == 0) {
[1059]         return re;
[1060]     }
[1061] 
[1062]     rv = ngx_palloc(rc->pool, n * sizeof(ngx_stream_regex_variable_t));
[1063]     if (rv == NULL) {
[1064]         return NULL;
[1065]     }
[1066] 
[1067]     re->variables = rv;
[1068]     re->nvariables = n;
[1069] 
[1070]     size = rc->name_size;
[1071]     p = rc->names;
[1072] 
[1073]     for (i = 0; i < n; i++) {
[1074]         rv[i].capture = 2 * ((p[0] << 8) + p[1]);
[1075] 
[1076]         name.data = &p[2];
[1077]         name.len = ngx_strlen(name.data);
[1078] 
[1079]         v = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
[1080]         if (v == NULL) {
[1081]             return NULL;
[1082]         }
[1083] 
[1084]         rv[i].index = ngx_stream_get_variable_index(cf, &name);
[1085]         if (rv[i].index == NGX_ERROR) {
[1086]             return NULL;
[1087]         }
[1088] 
[1089]         v->get_handler = ngx_stream_variable_not_found;
[1090] 
[1091]         p += size;
[1092]     }
[1093] 
[1094]     return re;
[1095] }
[1096] 
[1097] 
[1098] ngx_int_t
[1099] ngx_stream_regex_exec(ngx_stream_session_t *s, ngx_stream_regex_t *re,
[1100]     ngx_str_t *str)
[1101] {
[1102]     ngx_int_t                     rc, index;
[1103]     ngx_uint_t                    i, n, len;
[1104]     ngx_stream_variable_value_t  *vv;
[1105]     ngx_stream_core_main_conf_t  *cmcf;
[1106] 
[1107]     cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
[1108] 
[1109]     if (re->ncaptures) {
[1110]         len = cmcf->ncaptures;
[1111] 
[1112]         if (s->captures == NULL) {
[1113]             s->captures = ngx_palloc(s->connection->pool, len * sizeof(int));
[1114]             if (s->captures == NULL) {
[1115]                 return NGX_ERROR;
[1116]             }
[1117]         }
[1118] 
[1119]     } else {
[1120]         len = 0;
[1121]     }
[1122] 
[1123]     rc = ngx_regex_exec(re->regex, str, s->captures, len);
[1124] 
[1125]     if (rc == NGX_REGEX_NO_MATCHED) {
[1126]         return NGX_DECLINED;
[1127]     }
[1128] 
[1129]     if (rc < 0) {
[1130]         ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
[1131]                       ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
[1132]                       rc, str, &re->name);
[1133]         return NGX_ERROR;
[1134]     }
[1135] 
[1136]     for (i = 0; i < re->nvariables; i++) {
[1137] 
[1138]         n = re->variables[i].capture;
[1139]         index = re->variables[i].index;
[1140]         vv = &s->variables[index];
[1141] 
[1142]         vv->len = s->captures[n + 1] - s->captures[n];
[1143]         vv->valid = 1;
[1144]         vv->no_cacheable = 0;
[1145]         vv->not_found = 0;
[1146]         vv->data = &str->data[s->captures[n]];
[1147] 
[1148] #if (NGX_DEBUG)
[1149]         {
[1150]         ngx_stream_variable_t  *v;
[1151] 
[1152]         v = cmcf->variables.elts;
[1153] 
[1154]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[1155]                        "stream regex set $%V to \"%v\"", &v[index].name, vv);
[1156]         }
[1157] #endif
[1158]     }
[1159] 
[1160]     s->ncaptures = rc * 2;
[1161]     s->captures_data = str->data;
[1162] 
[1163]     return NGX_OK;
[1164] }
[1165] 
[1166] #endif
[1167] 
[1168] 
[1169] ngx_int_t
[1170] ngx_stream_variables_add_core_vars(ngx_conf_t *cf)
[1171] {
[1172]     ngx_stream_variable_t        *cv, *v;
[1173]     ngx_stream_core_main_conf_t  *cmcf;
[1174] 
[1175]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[1176] 
[1177]     cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
[1178]                                        sizeof(ngx_hash_keys_arrays_t));
[1179]     if (cmcf->variables_keys == NULL) {
[1180]         return NGX_ERROR;
[1181]     }
[1182] 
[1183]     cmcf->variables_keys->pool = cf->pool;
[1184]     cmcf->variables_keys->temp_pool = cf->pool;
[1185] 
[1186]     if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
[1187]         != NGX_OK)
[1188]     {
[1189]         return NGX_ERROR;
[1190]     }
[1191] 
[1192]     if (ngx_array_init(&cmcf->prefix_variables, cf->pool, 8,
[1193]                        sizeof(ngx_stream_variable_t))
[1194]         != NGX_OK)
[1195]     {
[1196]         return NGX_ERROR;
[1197]     }
[1198] 
[1199]     for (cv = ngx_stream_core_variables; cv->name.len; cv++) {
[1200]         v = ngx_stream_add_variable(cf, &cv->name, cv->flags);
[1201]         if (v == NULL) {
[1202]             return NGX_ERROR;
[1203]         }
[1204] 
[1205]         *v = *cv;
[1206]     }
[1207] 
[1208]     return NGX_OK;
[1209] }
[1210] 
[1211] 
[1212] ngx_int_t
[1213] ngx_stream_variables_init_vars(ngx_conf_t *cf)
[1214] {
[1215]     size_t                        len;
[1216]     ngx_uint_t                    i, n;
[1217]     ngx_hash_key_t               *key;
[1218]     ngx_hash_init_t               hash;
[1219]     ngx_stream_variable_t        *v, *av, *pv;
[1220]     ngx_stream_core_main_conf_t  *cmcf;
[1221] 
[1222]     /* set the handlers for the indexed stream variables */
[1223] 
[1224]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[1225] 
[1226]     v = cmcf->variables.elts;
[1227]     pv = cmcf->prefix_variables.elts;
[1228]     key = cmcf->variables_keys->keys.elts;
[1229] 
[1230]     for (i = 0; i < cmcf->variables.nelts; i++) {
[1231] 
[1232]         for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
[1233] 
[1234]             av = key[n].value;
[1235] 
[1236]             if (v[i].name.len == key[n].key.len
[1237]                 && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
[1238]                    == 0)
[1239]             {
[1240]                 v[i].get_handler = av->get_handler;
[1241]                 v[i].data = av->data;
[1242] 
[1243]                 av->flags |= NGX_STREAM_VAR_INDEXED;
[1244]                 v[i].flags = av->flags;
[1245] 
[1246]                 av->index = i;
[1247] 
[1248]                 if (av->get_handler == NULL
[1249]                     || (av->flags & NGX_STREAM_VAR_WEAK))
[1250]                 {
[1251]                     break;
[1252]                 }
[1253] 
[1254]                 goto next;
[1255]             }
[1256]         }
[1257] 
[1258]         len = 0;
[1259]         av = NULL;
[1260] 
[1261]         for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
[1262]             if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
[1263]                 && ngx_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
[1264]                    == 0)
[1265]             {
[1266]                 av = &pv[n];
[1267]                 len = pv[n].name.len;
[1268]             }
[1269]         }
[1270] 
[1271]         if (av) {
[1272]             v[i].get_handler = av->get_handler;
[1273]             v[i].data = (uintptr_t) &v[i].name;
[1274]             v[i].flags = av->flags;
[1275] 
[1276]             goto next;
[1277]          }
[1278] 
[1279]         if (v[i].get_handler == NULL) {
[1280]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[1281]                           "unknown \"%V\" variable", &v[i].name);
[1282]             return NGX_ERROR;
[1283]         }
[1284] 
[1285]     next:
[1286]         continue;
[1287]     }
[1288] 
[1289] 
[1290]     for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
[1291]         av = key[n].value;
[1292] 
[1293]         if (av->flags & NGX_STREAM_VAR_NOHASH) {
[1294]             key[n].key.data = NULL;
[1295]         }
[1296]     }
[1297] 
[1298] 
[1299]     hash.hash = &cmcf->variables_hash;
[1300]     hash.key = ngx_hash_key;
[1301]     hash.max_size = cmcf->variables_hash_max_size;
[1302]     hash.bucket_size = cmcf->variables_hash_bucket_size;
[1303]     hash.name = "variables_hash";
[1304]     hash.pool = cf->pool;
[1305]     hash.temp_pool = NULL;
[1306] 
[1307]     if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
[1308]                       cmcf->variables_keys->keys.nelts)
[1309]         != NGX_OK)
[1310]     {
[1311]         return NGX_ERROR;
[1312]     }
[1313] 
[1314]     cmcf->variables_keys = NULL;
[1315] 
[1316]     return NGX_OK;
[1317] }
