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
[12] #include <GeoIP.h>
[13] #include <GeoIPCity.h>
[14] 
[15] 
[16] #define NGX_GEOIP_COUNTRY_CODE   0
[17] #define NGX_GEOIP_COUNTRY_CODE3  1
[18] #define NGX_GEOIP_COUNTRY_NAME   2
[19] 
[20] 
[21] typedef struct {
[22]     GeoIP        *country;
[23]     GeoIP        *org;
[24]     GeoIP        *city;
[25] #if (NGX_HAVE_GEOIP_V6)
[26]     unsigned      country_v6:1;
[27]     unsigned      org_v6:1;
[28]     unsigned      city_v6:1;
[29] #endif
[30] } ngx_stream_geoip_conf_t;
[31] 
[32] 
[33] typedef struct {
[34]     ngx_str_t    *name;
[35]     uintptr_t     data;
[36] } ngx_stream_geoip_var_t;
[37] 
[38] 
[39] typedef const char *(*ngx_stream_geoip_variable_handler_pt)(GeoIP *,
[40]     u_long addr);
[41] 
[42] 
[43] ngx_stream_geoip_variable_handler_pt ngx_stream_geoip_country_functions[] = {
[44]     GeoIP_country_code_by_ipnum,
[45]     GeoIP_country_code3_by_ipnum,
[46]     GeoIP_country_name_by_ipnum,
[47] };
[48] 
[49] 
[50] #if (NGX_HAVE_GEOIP_V6)
[51] 
[52] typedef const char *(*ngx_stream_geoip_variable_handler_v6_pt)(GeoIP *,
[53]     geoipv6_t addr);
[54] 
[55] 
[56] ngx_stream_geoip_variable_handler_v6_pt
[57]     ngx_stream_geoip_country_v6_functions[] =
[58] {
[59]     GeoIP_country_code_by_ipnum_v6,
[60]     GeoIP_country_code3_by_ipnum_v6,
[61]     GeoIP_country_name_by_ipnum_v6,
[62] };
[63] 
[64] #endif
[65] 
[66] 
[67] static ngx_int_t ngx_stream_geoip_country_variable(ngx_stream_session_t *s,
[68]     ngx_stream_variable_value_t *v, uintptr_t data);
[69] static ngx_int_t ngx_stream_geoip_org_variable(ngx_stream_session_t *s,
[70]     ngx_stream_variable_value_t *v, uintptr_t data);
[71] static ngx_int_t ngx_stream_geoip_city_variable(ngx_stream_session_t *s,
[72]     ngx_stream_variable_value_t *v, uintptr_t data);
[73] static ngx_int_t ngx_stream_geoip_region_name_variable(ngx_stream_session_t *s,
[74]     ngx_stream_variable_value_t *v, uintptr_t data);
[75] static ngx_int_t ngx_stream_geoip_city_float_variable(ngx_stream_session_t *s,
[76]     ngx_stream_variable_value_t *v, uintptr_t data);
[77] static ngx_int_t ngx_stream_geoip_city_int_variable(ngx_stream_session_t *s,
[78]     ngx_stream_variable_value_t *v, uintptr_t data);
[79] static GeoIPRecord *ngx_stream_geoip_get_city_record(ngx_stream_session_t *s);
[80] 
[81] static ngx_int_t ngx_stream_geoip_add_variables(ngx_conf_t *cf);
[82] static void *ngx_stream_geoip_create_conf(ngx_conf_t *cf);
[83] static char *ngx_stream_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd,
[84]     void *conf);
[85] static char *ngx_stream_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd,
[86]     void *conf);
[87] static char *ngx_stream_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd,
[88]     void *conf);
[89] static void ngx_stream_geoip_cleanup(void *data);
[90] 
[91] 
[92] static ngx_command_t  ngx_stream_geoip_commands[] = {
[93] 
[94]     { ngx_string("geoip_country"),
[95]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE12,
[96]       ngx_stream_geoip_country,
[97]       NGX_STREAM_MAIN_CONF_OFFSET,
[98]       0,
[99]       NULL },
[100] 
[101]     { ngx_string("geoip_org"),
[102]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE12,
[103]       ngx_stream_geoip_org,
[104]       NGX_STREAM_MAIN_CONF_OFFSET,
[105]       0,
[106]       NULL },
[107] 
[108]     { ngx_string("geoip_city"),
[109]       NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE12,
[110]       ngx_stream_geoip_city,
[111]       NGX_STREAM_MAIN_CONF_OFFSET,
[112]       0,
[113]       NULL },
[114] 
[115]       ngx_null_command
[116] };
[117] 
[118] 
[119] static ngx_stream_module_t  ngx_stream_geoip_module_ctx = {
[120]     ngx_stream_geoip_add_variables,        /* preconfiguration */
[121]     NULL,                                  /* postconfiguration */
[122] 
[123]     ngx_stream_geoip_create_conf,          /* create main configuration */
[124]     NULL,                                  /* init main configuration */
[125] 
[126]     NULL,                                  /* create server configuration */
[127]     NULL                                   /* merge server configuration */
[128] };
[129] 
[130] 
[131] ngx_module_t  ngx_stream_geoip_module = {
[132]     NGX_MODULE_V1,
[133]     &ngx_stream_geoip_module_ctx,          /* module context */
[134]     ngx_stream_geoip_commands,             /* module directives */
[135]     NGX_STREAM_MODULE,                     /* module type */
[136]     NULL,                                  /* init master */
[137]     NULL,                                  /* init module */
[138]     NULL,                                  /* init process */
[139]     NULL,                                  /* init thread */
[140]     NULL,                                  /* exit thread */
[141]     NULL,                                  /* exit process */
[142]     NULL,                                  /* exit master */
[143]     NGX_MODULE_V1_PADDING
[144] };
[145] 
[146] 
[147] static ngx_stream_variable_t  ngx_stream_geoip_vars[] = {
[148] 
[149]     { ngx_string("geoip_country_code"), NULL,
[150]       ngx_stream_geoip_country_variable,
[151]       NGX_GEOIP_COUNTRY_CODE, 0, 0 },
[152] 
[153]     { ngx_string("geoip_country_code3"), NULL,
[154]       ngx_stream_geoip_country_variable,
[155]       NGX_GEOIP_COUNTRY_CODE3, 0, 0 },
[156] 
[157]     { ngx_string("geoip_country_name"), NULL,
[158]       ngx_stream_geoip_country_variable,
[159]       NGX_GEOIP_COUNTRY_NAME, 0, 0 },
[160] 
[161]     { ngx_string("geoip_org"), NULL,
[162]       ngx_stream_geoip_org_variable,
[163]       0, 0, 0 },
[164] 
[165]     { ngx_string("geoip_city_continent_code"), NULL,
[166]       ngx_stream_geoip_city_variable,
[167]       offsetof(GeoIPRecord, continent_code), 0, 0 },
[168] 
[169]     { ngx_string("geoip_city_country_code"), NULL,
[170]       ngx_stream_geoip_city_variable,
[171]       offsetof(GeoIPRecord, country_code), 0, 0 },
[172] 
[173]     { ngx_string("geoip_city_country_code3"), NULL,
[174]       ngx_stream_geoip_city_variable,
[175]       offsetof(GeoIPRecord, country_code3), 0, 0 },
[176] 
[177]     { ngx_string("geoip_city_country_name"), NULL,
[178]       ngx_stream_geoip_city_variable,
[179]       offsetof(GeoIPRecord, country_name), 0, 0 },
[180] 
[181]     { ngx_string("geoip_region"), NULL,
[182]       ngx_stream_geoip_city_variable,
[183]       offsetof(GeoIPRecord, region), 0, 0 },
[184] 
[185]     { ngx_string("geoip_region_name"), NULL,
[186]       ngx_stream_geoip_region_name_variable,
[187]       0, 0, 0 },
[188] 
[189]     { ngx_string("geoip_city"), NULL,
[190]       ngx_stream_geoip_city_variable,
[191]       offsetof(GeoIPRecord, city), 0, 0 },
[192] 
[193]     { ngx_string("geoip_postal_code"), NULL,
[194]       ngx_stream_geoip_city_variable,
[195]       offsetof(GeoIPRecord, postal_code), 0, 0 },
[196] 
[197]     { ngx_string("geoip_latitude"), NULL,
[198]       ngx_stream_geoip_city_float_variable,
[199]       offsetof(GeoIPRecord, latitude), 0, 0 },
[200] 
[201]     { ngx_string("geoip_longitude"), NULL,
[202]       ngx_stream_geoip_city_float_variable,
[203]       offsetof(GeoIPRecord, longitude), 0, 0 },
[204] 
[205]     { ngx_string("geoip_dma_code"), NULL,
[206]       ngx_stream_geoip_city_int_variable,
[207]       offsetof(GeoIPRecord, dma_code), 0, 0 },
[208] 
[209]     { ngx_string("geoip_area_code"), NULL,
[210]       ngx_stream_geoip_city_int_variable,
[211]       offsetof(GeoIPRecord, area_code), 0, 0 },
[212] 
[213]       ngx_stream_null_variable
[214] };
[215] 
[216] 
[217] static u_long
[218] ngx_stream_geoip_addr(ngx_stream_session_t *s, ngx_stream_geoip_conf_t *gcf)
[219] {
[220]     ngx_addr_t           addr;
[221]     struct sockaddr_in  *sin;
[222] 
[223]     addr.sockaddr = s->connection->sockaddr;
[224]     addr.socklen = s->connection->socklen;
[225]     /* addr.name = s->connection->addr_text; */
[226] 
[227] #if (NGX_HAVE_INET6)
[228] 
[229]     if (addr.sockaddr->sa_family == AF_INET6) {
[230]         u_char           *p;
[231]         in_addr_t         inaddr;
[232]         struct in6_addr  *inaddr6;
[233] 
[234]         inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
[235] 
[236]         if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[237]             p = inaddr6->s6_addr;
[238] 
[239]             inaddr = p[12] << 24;
[240]             inaddr += p[13] << 16;
[241]             inaddr += p[14] << 8;
[242]             inaddr += p[15];
[243] 
[244]             return inaddr;
[245]         }
[246]     }
[247] 
[248] #endif
[249] 
[250]     if (addr.sockaddr->sa_family != AF_INET) {
[251]         return INADDR_NONE;
[252]     }
[253] 
[254]     sin = (struct sockaddr_in *) addr.sockaddr;
[255]     return ntohl(sin->sin_addr.s_addr);
[256] }
[257] 
[258] 
[259] #if (NGX_HAVE_GEOIP_V6)
[260] 
[261] static geoipv6_t
[262] ngx_stream_geoip_addr_v6(ngx_stream_session_t *s, ngx_stream_geoip_conf_t *gcf)
[263] {
[264]     ngx_addr_t            addr;
[265]     in_addr_t             addr4;
[266]     struct in6_addr       addr6;
[267]     struct sockaddr_in   *sin;
[268]     struct sockaddr_in6  *sin6;
[269] 
[270]     addr.sockaddr = s->connection->sockaddr;
[271]     addr.socklen = s->connection->socklen;
[272]     /* addr.name = s->connection->addr_text; */
[273] 
[274]     switch (addr.sockaddr->sa_family) {
[275] 
[276]     case AF_INET:
[277]         /* Produce IPv4-mapped IPv6 address. */
[278]         sin = (struct sockaddr_in *) addr.sockaddr;
[279]         addr4 = ntohl(sin->sin_addr.s_addr);
[280] 
[281]         ngx_memzero(&addr6, sizeof(struct in6_addr));
[282]         addr6.s6_addr[10] = 0xff;
[283]         addr6.s6_addr[11] = 0xff;
[284]         addr6.s6_addr[12] = addr4 >> 24;
[285]         addr6.s6_addr[13] = addr4 >> 16;
[286]         addr6.s6_addr[14] = addr4 >> 8;
[287]         addr6.s6_addr[15] = addr4;
[288]         return addr6;
[289] 
[290]     case AF_INET6:
[291]         sin6 = (struct sockaddr_in6 *) addr.sockaddr;
[292]         return sin6->sin6_addr;
[293] 
[294]     default:
[295]         return in6addr_any;
[296]     }
[297] }
[298] 
[299] #endif
[300] 
[301] 
[302] static ngx_int_t
[303] ngx_stream_geoip_country_variable(ngx_stream_session_t *s,
[304]     ngx_stream_variable_value_t *v, uintptr_t data)
[305] {
[306]     ngx_stream_geoip_variable_handler_pt     handler =
[307]         ngx_stream_geoip_country_functions[data];
[308] #if (NGX_HAVE_GEOIP_V6)
[309]     ngx_stream_geoip_variable_handler_v6_pt  handler_v6 =
[310]         ngx_stream_geoip_country_v6_functions[data];
[311] #endif
[312] 
[313]     const char               *val;
[314]     ngx_stream_geoip_conf_t  *gcf;
[315] 
[316]     gcf = ngx_stream_get_module_main_conf(s, ngx_stream_geoip_module);
[317] 
[318]     if (gcf->country == NULL) {
[319]         goto not_found;
[320]     }
[321] 
[322] #if (NGX_HAVE_GEOIP_V6)
[323]     val = gcf->country_v6
[324]               ? handler_v6(gcf->country, ngx_stream_geoip_addr_v6(s, gcf))
[325]               : handler(gcf->country, ngx_stream_geoip_addr(s, gcf));
[326] #else
[327]     val = handler(gcf->country, ngx_stream_geoip_addr(s, gcf));
[328] #endif
[329] 
[330]     if (val == NULL) {
[331]         goto not_found;
[332]     }
[333] 
[334]     v->len = ngx_strlen(val);
[335]     v->valid = 1;
[336]     v->no_cacheable = 0;
[337]     v->not_found = 0;
[338]     v->data = (u_char *) val;
[339] 
[340]     return NGX_OK;
[341] 
[342] not_found:
[343] 
[344]     v->not_found = 1;
[345] 
[346]     return NGX_OK;
[347] }
[348] 
[349] 
[350] static ngx_int_t
[351] ngx_stream_geoip_org_variable(ngx_stream_session_t *s,
[352]     ngx_stream_variable_value_t *v, uintptr_t data)
[353] {
[354]     size_t                    len;
[355]     char                     *val;
[356]     ngx_stream_geoip_conf_t  *gcf;
[357] 
[358]     gcf = ngx_stream_get_module_main_conf(s, ngx_stream_geoip_module);
[359] 
[360]     if (gcf->org == NULL) {
[361]         goto not_found;
[362]     }
[363] 
[364] #if (NGX_HAVE_GEOIP_V6)
[365]     val = gcf->org_v6
[366]               ? GeoIP_name_by_ipnum_v6(gcf->org,
[367]                                        ngx_stream_geoip_addr_v6(s, gcf))
[368]               : GeoIP_name_by_ipnum(gcf->org,
[369]                                     ngx_stream_geoip_addr(s, gcf));
[370] #else
[371]     val = GeoIP_name_by_ipnum(gcf->org, ngx_stream_geoip_addr(s, gcf));
[372] #endif
[373] 
[374]     if (val == NULL) {
[375]         goto not_found;
[376]     }
[377] 
[378]     len = ngx_strlen(val);
[379]     v->data = ngx_pnalloc(s->connection->pool, len);
[380]     if (v->data == NULL) {
[381]         ngx_free(val);
[382]         return NGX_ERROR;
[383]     }
[384] 
[385]     ngx_memcpy(v->data, val, len);
[386] 
[387]     v->len = len;
[388]     v->valid = 1;
[389]     v->no_cacheable = 0;
[390]     v->not_found = 0;
[391] 
[392]     ngx_free(val);
[393] 
[394]     return NGX_OK;
[395] 
[396] not_found:
[397] 
[398]     v->not_found = 1;
[399] 
[400]     return NGX_OK;
[401] }
[402] 
[403] 
[404] static ngx_int_t
[405] ngx_stream_geoip_city_variable(ngx_stream_session_t *s,
[406]     ngx_stream_variable_value_t *v, uintptr_t data)
[407] {
[408]     char         *val;
[409]     size_t        len;
[410]     GeoIPRecord  *gr;
[411] 
[412]     gr = ngx_stream_geoip_get_city_record(s);
[413]     if (gr == NULL) {
[414]         goto not_found;
[415]     }
[416] 
[417]     val = *(char **) ((char *) gr + data);
[418]     if (val == NULL) {
[419]         goto no_value;
[420]     }
[421] 
[422]     len = ngx_strlen(val);
[423]     v->data = ngx_pnalloc(s->connection->pool, len);
[424]     if (v->data == NULL) {
[425]         GeoIPRecord_delete(gr);
[426]         return NGX_ERROR;
[427]     }
[428] 
[429]     ngx_memcpy(v->data, val, len);
[430] 
[431]     v->len = len;
[432]     v->valid = 1;
[433]     v->no_cacheable = 0;
[434]     v->not_found = 0;
[435] 
[436]     GeoIPRecord_delete(gr);
[437] 
[438]     return NGX_OK;
[439] 
[440] no_value:
[441] 
[442]     GeoIPRecord_delete(gr);
[443] 
[444] not_found:
[445] 
[446]     v->not_found = 1;
[447] 
[448]     return NGX_OK;
[449] }
[450] 
[451] 
[452] static ngx_int_t
[453] ngx_stream_geoip_region_name_variable(ngx_stream_session_t *s,
[454]     ngx_stream_variable_value_t *v, uintptr_t data)
[455] {
[456]     size_t        len;
[457]     const char   *val;
[458]     GeoIPRecord  *gr;
[459] 
[460]     gr = ngx_stream_geoip_get_city_record(s);
[461]     if (gr == NULL) {
[462]         goto not_found;
[463]     }
[464] 
[465]     val = GeoIP_region_name_by_code(gr->country_code, gr->region);
[466] 
[467]     GeoIPRecord_delete(gr);
[468] 
[469]     if (val == NULL) {
[470]         goto not_found;
[471]     }
[472] 
[473]     len = ngx_strlen(val);
[474]     v->data = ngx_pnalloc(s->connection->pool, len);
[475]     if (v->data == NULL) {
[476]         return NGX_ERROR;
[477]     }
[478] 
[479]     ngx_memcpy(v->data, val, len);
[480] 
[481]     v->len = len;
[482]     v->valid = 1;
[483]     v->no_cacheable = 0;
[484]     v->not_found = 0;
[485] 
[486]     return NGX_OK;
[487] 
[488] not_found:
[489] 
[490]     v->not_found = 1;
[491] 
[492]     return NGX_OK;
[493] }
[494] 
[495] 
[496] static ngx_int_t
[497] ngx_stream_geoip_city_float_variable(ngx_stream_session_t *s,
[498]     ngx_stream_variable_value_t *v, uintptr_t data)
[499] {
[500]     float         val;
[501]     GeoIPRecord  *gr;
[502] 
[503]     gr = ngx_stream_geoip_get_city_record(s);
[504]     if (gr == NULL) {
[505]         v->not_found = 1;
[506]         return NGX_OK;
[507]     }
[508] 
[509]     v->data = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN + 5);
[510]     if (v->data == NULL) {
[511]         GeoIPRecord_delete(gr);
[512]         return NGX_ERROR;
[513]     }
[514] 
[515]     val = *(float *) ((char *) gr + data);
[516] 
[517]     v->len = ngx_sprintf(v->data, "%.4f", val) - v->data;
[518]     v->valid = 1;
[519]     v->no_cacheable = 0;
[520]     v->not_found = 0;
[521] 
[522]     GeoIPRecord_delete(gr);
[523] 
[524]     return NGX_OK;
[525] }
[526] 
[527] 
[528] static ngx_int_t
[529] ngx_stream_geoip_city_int_variable(ngx_stream_session_t *s,
[530]     ngx_stream_variable_value_t *v, uintptr_t data)
[531] {
[532]     int           val;
[533]     GeoIPRecord  *gr;
[534] 
[535]     gr = ngx_stream_geoip_get_city_record(s);
[536]     if (gr == NULL) {
[537]         v->not_found = 1;
[538]         return NGX_OK;
[539]     }
[540] 
[541]     v->data = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
[542]     if (v->data == NULL) {
[543]         GeoIPRecord_delete(gr);
[544]         return NGX_ERROR;
[545]     }
[546] 
[547]     val = *(int *) ((char *) gr + data);
[548] 
[549]     v->len = ngx_sprintf(v->data, "%d", val) - v->data;
[550]     v->valid = 1;
[551]     v->no_cacheable = 0;
[552]     v->not_found = 0;
[553] 
[554]     GeoIPRecord_delete(gr);
[555] 
[556]     return NGX_OK;
[557] }
[558] 
[559] 
[560] static GeoIPRecord *
[561] ngx_stream_geoip_get_city_record(ngx_stream_session_t *s)
[562] {
[563]     ngx_stream_geoip_conf_t  *gcf;
[564] 
[565]     gcf = ngx_stream_get_module_main_conf(s, ngx_stream_geoip_module);
[566] 
[567]     if (gcf->city) {
[568] #if (NGX_HAVE_GEOIP_V6)
[569]         return gcf->city_v6
[570]                    ? GeoIP_record_by_ipnum_v6(gcf->city,
[571]                                               ngx_stream_geoip_addr_v6(s, gcf))
[572]                    : GeoIP_record_by_ipnum(gcf->city,
[573]                                            ngx_stream_geoip_addr(s, gcf));
[574] #else
[575]         return GeoIP_record_by_ipnum(gcf->city, ngx_stream_geoip_addr(s, gcf));
[576] #endif
[577]     }
[578] 
[579]     return NULL;
[580] }
[581] 
[582] 
[583] static ngx_int_t
[584] ngx_stream_geoip_add_variables(ngx_conf_t *cf)
[585] {
[586]     ngx_stream_variable_t  *var, *v;
[587] 
[588]     for (v = ngx_stream_geoip_vars; v->name.len; v++) {
[589]         var = ngx_stream_add_variable(cf, &v->name, v->flags);
[590]         if (var == NULL) {
[591]             return NGX_ERROR;
[592]         }
[593] 
[594]         var->get_handler = v->get_handler;
[595]         var->data = v->data;
[596]     }
[597] 
[598]     return NGX_OK;
[599] }
[600] 
[601] 
[602] static void *
[603] ngx_stream_geoip_create_conf(ngx_conf_t *cf)
[604] {
[605]     ngx_pool_cleanup_t       *cln;
[606]     ngx_stream_geoip_conf_t  *conf;
[607] 
[608]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_geoip_conf_t));
[609]     if (conf == NULL) {
[610]         return NULL;
[611]     }
[612] 
[613]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[614]     if (cln == NULL) {
[615]         return NULL;
[616]     }
[617] 
[618]     cln->handler = ngx_stream_geoip_cleanup;
[619]     cln->data = conf;
[620] 
[621]     return conf;
[622] }
[623] 
[624] 
[625] static char *
[626] ngx_stream_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[627] {
[628]     ngx_stream_geoip_conf_t  *gcf = conf;
[629] 
[630]     ngx_str_t  *value;
[631] 
[632]     if (gcf->country) {
[633]         return "is duplicate";
[634]     }
[635] 
[636]     value = cf->args->elts;
[637] 
[638]     gcf->country = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);
[639] 
[640]     if (gcf->country == NULL) {
[641]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[642]                            "GeoIP_open(\"%V\") failed", &value[1]);
[643] 
[644]         return NGX_CONF_ERROR;
[645]     }
[646] 
[647]     if (cf->args->nelts == 3) {
[648]         if (ngx_strcmp(value[2].data, "utf8") == 0) {
[649]             GeoIP_set_charset(gcf->country, GEOIP_CHARSET_UTF8);
[650] 
[651]         } else {
[652]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[653]                                "invalid parameter \"%V\"", &value[2]);
[654]             return NGX_CONF_ERROR;
[655]         }
[656]     }
[657] 
[658]     switch (gcf->country->databaseType) {
[659] 
[660]     case GEOIP_COUNTRY_EDITION:
[661] 
[662]         return NGX_CONF_OK;
[663] 
[664] #if (NGX_HAVE_GEOIP_V6)
[665]     case GEOIP_COUNTRY_EDITION_V6:
[666] 
[667]         gcf->country_v6 = 1;
[668]         return NGX_CONF_OK;
[669] #endif
[670] 
[671]     default:
[672]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[673]                            "invalid GeoIP database \"%V\" type:%d",
[674]                            &value[1], gcf->country->databaseType);
[675]         return NGX_CONF_ERROR;
[676]     }
[677] }
[678] 
[679] 
[680] static char *
[681] ngx_stream_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[682] {
[683]     ngx_stream_geoip_conf_t  *gcf = conf;
[684] 
[685]     ngx_str_t  *value;
[686] 
[687]     if (gcf->org) {
[688]         return "is duplicate";
[689]     }
[690] 
[691]     value = cf->args->elts;
[692] 
[693]     gcf->org = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);
[694] 
[695]     if (gcf->org == NULL) {
[696]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[697]                            "GeoIP_open(\"%V\") failed", &value[1]);
[698] 
[699]         return NGX_CONF_ERROR;
[700]     }
[701] 
[702]     if (cf->args->nelts == 3) {
[703]         if (ngx_strcmp(value[2].data, "utf8") == 0) {
[704]             GeoIP_set_charset(gcf->org, GEOIP_CHARSET_UTF8);
[705] 
[706]         } else {
[707]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[708]                                "invalid parameter \"%V\"", &value[2]);
[709]             return NGX_CONF_ERROR;
[710]         }
[711]     }
[712] 
[713]     switch (gcf->org->databaseType) {
[714] 
[715]     case GEOIP_ISP_EDITION:
[716]     case GEOIP_ORG_EDITION:
[717]     case GEOIP_DOMAIN_EDITION:
[718]     case GEOIP_ASNUM_EDITION:
[719] 
[720]         return NGX_CONF_OK;
[721] 
[722] #if (NGX_HAVE_GEOIP_V6)
[723]     case GEOIP_ISP_EDITION_V6:
[724]     case GEOIP_ORG_EDITION_V6:
[725]     case GEOIP_DOMAIN_EDITION_V6:
[726]     case GEOIP_ASNUM_EDITION_V6:
[727] 
[728]         gcf->org_v6 = 1;
[729]         return NGX_CONF_OK;
[730] #endif
[731] 
[732]     default:
[733]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[734]                            "invalid GeoIP database \"%V\" type:%d",
[735]                            &value[1], gcf->org->databaseType);
[736]         return NGX_CONF_ERROR;
[737]     }
[738] }
[739] 
[740] 
[741] static char *
[742] ngx_stream_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[743] {
[744]     ngx_stream_geoip_conf_t  *gcf = conf;
[745] 
[746]     ngx_str_t  *value;
[747] 
[748]     if (gcf->city) {
[749]         return "is duplicate";
[750]     }
[751] 
[752]     value = cf->args->elts;
[753] 
[754]     gcf->city = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);
[755] 
[756]     if (gcf->city == NULL) {
[757]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[758]                            "GeoIP_open(\"%V\") failed", &value[1]);
[759] 
[760]         return NGX_CONF_ERROR;
[761]     }
[762] 
[763]     if (cf->args->nelts == 3) {
[764]         if (ngx_strcmp(value[2].data, "utf8") == 0) {
[765]             GeoIP_set_charset(gcf->city, GEOIP_CHARSET_UTF8);
[766] 
[767]         } else {
[768]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[769]                                "invalid parameter \"%V\"", &value[2]);
[770]             return NGX_CONF_ERROR;
[771]         }
[772]     }
[773] 
[774]     switch (gcf->city->databaseType) {
[775] 
[776]     case GEOIP_CITY_EDITION_REV0:
[777]     case GEOIP_CITY_EDITION_REV1:
[778] 
[779]         return NGX_CONF_OK;
[780] 
[781] #if (NGX_HAVE_GEOIP_V6)
[782]     case GEOIP_CITY_EDITION_REV0_V6:
[783]     case GEOIP_CITY_EDITION_REV1_V6:
[784] 
[785]         gcf->city_v6 = 1;
[786]         return NGX_CONF_OK;
[787] #endif
[788] 
[789]     default:
[790]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[791]                            "invalid GeoIP City database \"%V\" type:%d",
[792]                            &value[1], gcf->city->databaseType);
[793]         return NGX_CONF_ERROR;
[794]     }
[795] }
[796] 
[797] 
[798] static void
[799] ngx_stream_geoip_cleanup(void *data)
[800] {
[801]     ngx_stream_geoip_conf_t  *gcf = data;
[802] 
[803]     if (gcf->country) {
[804]         GeoIP_delete(gcf->country);
[805]     }
[806] 
[807]     if (gcf->org) {
[808]         GeoIP_delete(gcf->org);
[809]     }
[810] 
[811]     if (gcf->city) {
[812]         GeoIP_delete(gcf->city);
[813]     }
[814] }
