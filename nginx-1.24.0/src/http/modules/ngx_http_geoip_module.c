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
[25]     ngx_array_t  *proxies;    /* array of ngx_cidr_t */
[26]     ngx_flag_t    proxy_recursive;
[27] #if (NGX_HAVE_GEOIP_V6)
[28]     unsigned      country_v6:1;
[29]     unsigned      org_v6:1;
[30]     unsigned      city_v6:1;
[31] #endif
[32] } ngx_http_geoip_conf_t;
[33] 
[34] 
[35] typedef struct {
[36]     ngx_str_t    *name;
[37]     uintptr_t     data;
[38] } ngx_http_geoip_var_t;
[39] 
[40] 
[41] typedef const char *(*ngx_http_geoip_variable_handler_pt)(GeoIP *,
[42]     u_long addr);
[43] 
[44] 
[45] ngx_http_geoip_variable_handler_pt ngx_http_geoip_country_functions[] = {
[46]     GeoIP_country_code_by_ipnum,
[47]     GeoIP_country_code3_by_ipnum,
[48]     GeoIP_country_name_by_ipnum,
[49] };
[50] 
[51] 
[52] #if (NGX_HAVE_GEOIP_V6)
[53] 
[54] typedef const char *(*ngx_http_geoip_variable_handler_v6_pt)(GeoIP *,
[55]     geoipv6_t addr);
[56] 
[57] 
[58] ngx_http_geoip_variable_handler_v6_pt ngx_http_geoip_country_v6_functions[] = {
[59]     GeoIP_country_code_by_ipnum_v6,
[60]     GeoIP_country_code3_by_ipnum_v6,
[61]     GeoIP_country_name_by_ipnum_v6,
[62] };
[63] 
[64] #endif
[65] 
[66] 
[67] static ngx_int_t ngx_http_geoip_country_variable(ngx_http_request_t *r,
[68]     ngx_http_variable_value_t *v, uintptr_t data);
[69] static ngx_int_t ngx_http_geoip_org_variable(ngx_http_request_t *r,
[70]     ngx_http_variable_value_t *v, uintptr_t data);
[71] static ngx_int_t ngx_http_geoip_city_variable(ngx_http_request_t *r,
[72]     ngx_http_variable_value_t *v, uintptr_t data);
[73] static ngx_int_t ngx_http_geoip_region_name_variable(ngx_http_request_t *r,
[74]     ngx_http_variable_value_t *v, uintptr_t data);
[75] static ngx_int_t ngx_http_geoip_city_float_variable(ngx_http_request_t *r,
[76]     ngx_http_variable_value_t *v, uintptr_t data);
[77] static ngx_int_t ngx_http_geoip_city_int_variable(ngx_http_request_t *r,
[78]     ngx_http_variable_value_t *v, uintptr_t data);
[79] static GeoIPRecord *ngx_http_geoip_get_city_record(ngx_http_request_t *r);
[80] 
[81] static ngx_int_t ngx_http_geoip_add_variables(ngx_conf_t *cf);
[82] static void *ngx_http_geoip_create_conf(ngx_conf_t *cf);
[83] static char *ngx_http_geoip_init_conf(ngx_conf_t *cf, void *conf);
[84] static char *ngx_http_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd,
[85]     void *conf);
[86] static char *ngx_http_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd,
[87]     void *conf);
[88] static char *ngx_http_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd,
[89]     void *conf);
[90] static char *ngx_http_geoip_proxy(ngx_conf_t *cf, ngx_command_t *cmd,
[91]     void *conf);
[92] static ngx_int_t ngx_http_geoip_cidr_value(ngx_conf_t *cf, ngx_str_t *net,
[93]     ngx_cidr_t *cidr);
[94] static void ngx_http_geoip_cleanup(void *data);
[95] 
[96] 
[97] static ngx_command_t  ngx_http_geoip_commands[] = {
[98] 
[99]     { ngx_string("geoip_country"),
[100]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
[101]       ngx_http_geoip_country,
[102]       NGX_HTTP_MAIN_CONF_OFFSET,
[103]       0,
[104]       NULL },
[105] 
[106]     { ngx_string("geoip_org"),
[107]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
[108]       ngx_http_geoip_org,
[109]       NGX_HTTP_MAIN_CONF_OFFSET,
[110]       0,
[111]       NULL },
[112] 
[113]     { ngx_string("geoip_city"),
[114]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
[115]       ngx_http_geoip_city,
[116]       NGX_HTTP_MAIN_CONF_OFFSET,
[117]       0,
[118]       NULL },
[119] 
[120]     { ngx_string("geoip_proxy"),
[121]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[122]       ngx_http_geoip_proxy,
[123]       NGX_HTTP_MAIN_CONF_OFFSET,
[124]       0,
[125]       NULL },
[126] 
[127]     { ngx_string("geoip_proxy_recursive"),
[128]       NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
[129]       ngx_conf_set_flag_slot,
[130]       NGX_HTTP_MAIN_CONF_OFFSET,
[131]       offsetof(ngx_http_geoip_conf_t, proxy_recursive),
[132]       NULL },
[133] 
[134]       ngx_null_command
[135] };
[136] 
[137] 
[138] static ngx_http_module_t  ngx_http_geoip_module_ctx = {
[139]     ngx_http_geoip_add_variables,          /* preconfiguration */
[140]     NULL,                                  /* postconfiguration */
[141] 
[142]     ngx_http_geoip_create_conf,            /* create main configuration */
[143]     ngx_http_geoip_init_conf,              /* init main configuration */
[144] 
[145]     NULL,                                  /* create server configuration */
[146]     NULL,                                  /* merge server configuration */
[147] 
[148]     NULL,                                  /* create location configuration */
[149]     NULL                                   /* merge location configuration */
[150] };
[151] 
[152] 
[153] ngx_module_t  ngx_http_geoip_module = {
[154]     NGX_MODULE_V1,
[155]     &ngx_http_geoip_module_ctx,            /* module context */
[156]     ngx_http_geoip_commands,               /* module directives */
[157]     NGX_HTTP_MODULE,                       /* module type */
[158]     NULL,                                  /* init master */
[159]     NULL,                                  /* init module */
[160]     NULL,                                  /* init process */
[161]     NULL,                                  /* init thread */
[162]     NULL,                                  /* exit thread */
[163]     NULL,                                  /* exit process */
[164]     NULL,                                  /* exit master */
[165]     NGX_MODULE_V1_PADDING
[166] };
[167] 
[168] 
[169] static ngx_http_variable_t  ngx_http_geoip_vars[] = {
[170] 
[171]     { ngx_string("geoip_country_code"), NULL,
[172]       ngx_http_geoip_country_variable,
[173]       NGX_GEOIP_COUNTRY_CODE, 0, 0 },
[174] 
[175]     { ngx_string("geoip_country_code3"), NULL,
[176]       ngx_http_geoip_country_variable,
[177]       NGX_GEOIP_COUNTRY_CODE3, 0, 0 },
[178] 
[179]     { ngx_string("geoip_country_name"), NULL,
[180]       ngx_http_geoip_country_variable,
[181]       NGX_GEOIP_COUNTRY_NAME, 0, 0 },
[182] 
[183]     { ngx_string("geoip_org"), NULL,
[184]       ngx_http_geoip_org_variable,
[185]       0, 0, 0 },
[186] 
[187]     { ngx_string("geoip_city_continent_code"), NULL,
[188]       ngx_http_geoip_city_variable,
[189]       offsetof(GeoIPRecord, continent_code), 0, 0 },
[190] 
[191]     { ngx_string("geoip_city_country_code"), NULL,
[192]       ngx_http_geoip_city_variable,
[193]       offsetof(GeoIPRecord, country_code), 0, 0 },
[194] 
[195]     { ngx_string("geoip_city_country_code3"), NULL,
[196]       ngx_http_geoip_city_variable,
[197]       offsetof(GeoIPRecord, country_code3), 0, 0 },
[198] 
[199]     { ngx_string("geoip_city_country_name"), NULL,
[200]       ngx_http_geoip_city_variable,
[201]       offsetof(GeoIPRecord, country_name), 0, 0 },
[202] 
[203]     { ngx_string("geoip_region"), NULL,
[204]       ngx_http_geoip_city_variable,
[205]       offsetof(GeoIPRecord, region), 0, 0 },
[206] 
[207]     { ngx_string("geoip_region_name"), NULL,
[208]       ngx_http_geoip_region_name_variable,
[209]       0, 0, 0 },
[210] 
[211]     { ngx_string("geoip_city"), NULL,
[212]       ngx_http_geoip_city_variable,
[213]       offsetof(GeoIPRecord, city), 0, 0 },
[214] 
[215]     { ngx_string("geoip_postal_code"), NULL,
[216]       ngx_http_geoip_city_variable,
[217]       offsetof(GeoIPRecord, postal_code), 0, 0 },
[218] 
[219]     { ngx_string("geoip_latitude"), NULL,
[220]       ngx_http_geoip_city_float_variable,
[221]       offsetof(GeoIPRecord, latitude), 0, 0 },
[222] 
[223]     { ngx_string("geoip_longitude"), NULL,
[224]       ngx_http_geoip_city_float_variable,
[225]       offsetof(GeoIPRecord, longitude), 0, 0 },
[226] 
[227]     { ngx_string("geoip_dma_code"), NULL,
[228]       ngx_http_geoip_city_int_variable,
[229]       offsetof(GeoIPRecord, dma_code), 0, 0 },
[230] 
[231]     { ngx_string("geoip_area_code"), NULL,
[232]       ngx_http_geoip_city_int_variable,
[233]       offsetof(GeoIPRecord, area_code), 0, 0 },
[234] 
[235]       ngx_http_null_variable
[236] };
[237] 
[238] 
[239] static u_long
[240] ngx_http_geoip_addr(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
[241] {
[242]     ngx_addr_t           addr;
[243]     ngx_table_elt_t     *xfwd;
[244]     struct sockaddr_in  *sin;
[245] 
[246]     addr.sockaddr = r->connection->sockaddr;
[247]     addr.socklen = r->connection->socklen;
[248]     /* addr.name = r->connection->addr_text; */
[249] 
[250]     xfwd = r->headers_in.x_forwarded_for;
[251] 
[252]     if (xfwd != NULL && gcf->proxies != NULL) {
[253]         (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
[254]                                            gcf->proxies, gcf->proxy_recursive);
[255]     }
[256] 
[257] #if (NGX_HAVE_INET6)
[258] 
[259]     if (addr.sockaddr->sa_family == AF_INET6) {
[260]         u_char           *p;
[261]         in_addr_t         inaddr;
[262]         struct in6_addr  *inaddr6;
[263] 
[264]         inaddr6 = &((struct sockaddr_in6 *) addr.sockaddr)->sin6_addr;
[265] 
[266]         if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[267]             p = inaddr6->s6_addr;
[268] 
[269]             inaddr = p[12] << 24;
[270]             inaddr += p[13] << 16;
[271]             inaddr += p[14] << 8;
[272]             inaddr += p[15];
[273] 
[274]             return inaddr;
[275]         }
[276]     }
[277] 
[278] #endif
[279] 
[280]     if (addr.sockaddr->sa_family != AF_INET) {
[281]         return INADDR_NONE;
[282]     }
[283] 
[284]     sin = (struct sockaddr_in *) addr.sockaddr;
[285]     return ntohl(sin->sin_addr.s_addr);
[286] }
[287] 
[288] 
[289] #if (NGX_HAVE_GEOIP_V6)
[290] 
[291] static geoipv6_t
[292] ngx_http_geoip_addr_v6(ngx_http_request_t *r, ngx_http_geoip_conf_t *gcf)
[293] {
[294]     ngx_addr_t            addr;
[295]     ngx_table_elt_t      *xfwd;
[296]     in_addr_t             addr4;
[297]     struct in6_addr       addr6;
[298]     struct sockaddr_in   *sin;
[299]     struct sockaddr_in6  *sin6;
[300] 
[301]     addr.sockaddr = r->connection->sockaddr;
[302]     addr.socklen = r->connection->socklen;
[303]     /* addr.name = r->connection->addr_text; */
[304] 
[305]     xfwd = r->headers_in.x_forwarded_for;
[306] 
[307]     if (xfwd != NULL && gcf->proxies != NULL) {
[308]         (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
[309]                                            gcf->proxies, gcf->proxy_recursive);
[310]     }
[311] 
[312]     switch (addr.sockaddr->sa_family) {
[313] 
[314]     case AF_INET:
[315]         /* Produce IPv4-mapped IPv6 address. */
[316]         sin = (struct sockaddr_in *) addr.sockaddr;
[317]         addr4 = ntohl(sin->sin_addr.s_addr);
[318] 
[319]         ngx_memzero(&addr6, sizeof(struct in6_addr));
[320]         addr6.s6_addr[10] = 0xff;
[321]         addr6.s6_addr[11] = 0xff;
[322]         addr6.s6_addr[12] = addr4 >> 24;
[323]         addr6.s6_addr[13] = addr4 >> 16;
[324]         addr6.s6_addr[14] = addr4 >> 8;
[325]         addr6.s6_addr[15] = addr4;
[326]         return addr6;
[327] 
[328]     case AF_INET6:
[329]         sin6 = (struct sockaddr_in6 *) addr.sockaddr;
[330]         return sin6->sin6_addr;
[331] 
[332]     default:
[333]         return in6addr_any;
[334]     }
[335] }
[336] 
[337] #endif
[338] 
[339] 
[340] static ngx_int_t
[341] ngx_http_geoip_country_variable(ngx_http_request_t *r,
[342]     ngx_http_variable_value_t *v, uintptr_t data)
[343] {
[344]     ngx_http_geoip_variable_handler_pt     handler =
[345]         ngx_http_geoip_country_functions[data];
[346] #if (NGX_HAVE_GEOIP_V6)
[347]     ngx_http_geoip_variable_handler_v6_pt  handler_v6 =
[348]         ngx_http_geoip_country_v6_functions[data];
[349] #endif
[350] 
[351]     const char             *val;
[352]     ngx_http_geoip_conf_t  *gcf;
[353] 
[354]     gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);
[355] 
[356]     if (gcf->country == NULL) {
[357]         goto not_found;
[358]     }
[359] 
[360] #if (NGX_HAVE_GEOIP_V6)
[361]     val = gcf->country_v6
[362]               ? handler_v6(gcf->country, ngx_http_geoip_addr_v6(r, gcf))
[363]               : handler(gcf->country, ngx_http_geoip_addr(r, gcf));
[364] #else
[365]     val = handler(gcf->country, ngx_http_geoip_addr(r, gcf));
[366] #endif
[367] 
[368]     if (val == NULL) {
[369]         goto not_found;
[370]     }
[371] 
[372]     v->len = ngx_strlen(val);
[373]     v->valid = 1;
[374]     v->no_cacheable = 0;
[375]     v->not_found = 0;
[376]     v->data = (u_char *) val;
[377] 
[378]     return NGX_OK;
[379] 
[380] not_found:
[381] 
[382]     v->not_found = 1;
[383] 
[384]     return NGX_OK;
[385] }
[386] 
[387] 
[388] static ngx_int_t
[389] ngx_http_geoip_org_variable(ngx_http_request_t *r,
[390]     ngx_http_variable_value_t *v, uintptr_t data)
[391] {
[392]     size_t                  len;
[393]     char                   *val;
[394]     ngx_http_geoip_conf_t  *gcf;
[395] 
[396]     gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);
[397] 
[398]     if (gcf->org == NULL) {
[399]         goto not_found;
[400]     }
[401] 
[402] #if (NGX_HAVE_GEOIP_V6)
[403]     val = gcf->org_v6
[404]               ? GeoIP_name_by_ipnum_v6(gcf->org,
[405]                                        ngx_http_geoip_addr_v6(r, gcf))
[406]               : GeoIP_name_by_ipnum(gcf->org,
[407]                                     ngx_http_geoip_addr(r, gcf));
[408] #else
[409]     val = GeoIP_name_by_ipnum(gcf->org, ngx_http_geoip_addr(r, gcf));
[410] #endif
[411] 
[412]     if (val == NULL) {
[413]         goto not_found;
[414]     }
[415] 
[416]     len = ngx_strlen(val);
[417]     v->data = ngx_pnalloc(r->pool, len);
[418]     if (v->data == NULL) {
[419]         ngx_free(val);
[420]         return NGX_ERROR;
[421]     }
[422] 
[423]     ngx_memcpy(v->data, val, len);
[424] 
[425]     v->len = len;
[426]     v->valid = 1;
[427]     v->no_cacheable = 0;
[428]     v->not_found = 0;
[429] 
[430]     ngx_free(val);
[431] 
[432]     return NGX_OK;
[433] 
[434] not_found:
[435] 
[436]     v->not_found = 1;
[437] 
[438]     return NGX_OK;
[439] }
[440] 
[441] 
[442] static ngx_int_t
[443] ngx_http_geoip_city_variable(ngx_http_request_t *r,
[444]     ngx_http_variable_value_t *v, uintptr_t data)
[445] {
[446]     char         *val;
[447]     size_t        len;
[448]     GeoIPRecord  *gr;
[449] 
[450]     gr = ngx_http_geoip_get_city_record(r);
[451]     if (gr == NULL) {
[452]         goto not_found;
[453]     }
[454] 
[455]     val = *(char **) ((char *) gr + data);
[456]     if (val == NULL) {
[457]         goto no_value;
[458]     }
[459] 
[460]     len = ngx_strlen(val);
[461]     v->data = ngx_pnalloc(r->pool, len);
[462]     if (v->data == NULL) {
[463]         GeoIPRecord_delete(gr);
[464]         return NGX_ERROR;
[465]     }
[466] 
[467]     ngx_memcpy(v->data, val, len);
[468] 
[469]     v->len = len;
[470]     v->valid = 1;
[471]     v->no_cacheable = 0;
[472]     v->not_found = 0;
[473] 
[474]     GeoIPRecord_delete(gr);
[475] 
[476]     return NGX_OK;
[477] 
[478] no_value:
[479] 
[480]     GeoIPRecord_delete(gr);
[481] 
[482] not_found:
[483] 
[484]     v->not_found = 1;
[485] 
[486]     return NGX_OK;
[487] }
[488] 
[489] 
[490] static ngx_int_t
[491] ngx_http_geoip_region_name_variable(ngx_http_request_t *r,
[492]     ngx_http_variable_value_t *v, uintptr_t data)
[493] {
[494]     size_t        len;
[495]     const char   *val;
[496]     GeoIPRecord  *gr;
[497] 
[498]     gr = ngx_http_geoip_get_city_record(r);
[499]     if (gr == NULL) {
[500]         goto not_found;
[501]     }
[502] 
[503]     val = GeoIP_region_name_by_code(gr->country_code, gr->region);
[504] 
[505]     GeoIPRecord_delete(gr);
[506] 
[507]     if (val == NULL) {
[508]         goto not_found;
[509]     }
[510] 
[511]     len = ngx_strlen(val);
[512]     v->data = ngx_pnalloc(r->pool, len);
[513]     if (v->data == NULL) {
[514]         return NGX_ERROR;
[515]     }
[516] 
[517]     ngx_memcpy(v->data, val, len);
[518] 
[519]     v->len = len;
[520]     v->valid = 1;
[521]     v->no_cacheable = 0;
[522]     v->not_found = 0;
[523] 
[524]     return NGX_OK;
[525] 
[526] not_found:
[527] 
[528]     v->not_found = 1;
[529] 
[530]     return NGX_OK;
[531] }
[532] 
[533] 
[534] static ngx_int_t
[535] ngx_http_geoip_city_float_variable(ngx_http_request_t *r,
[536]     ngx_http_variable_value_t *v, uintptr_t data)
[537] {
[538]     float         val;
[539]     GeoIPRecord  *gr;
[540] 
[541]     gr = ngx_http_geoip_get_city_record(r);
[542]     if (gr == NULL) {
[543]         v->not_found = 1;
[544]         return NGX_OK;
[545]     }
[546] 
[547]     v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
[548]     if (v->data == NULL) {
[549]         GeoIPRecord_delete(gr);
[550]         return NGX_ERROR;
[551]     }
[552] 
[553]     val = *(float *) ((char *) gr + data);
[554] 
[555]     v->len = ngx_sprintf(v->data, "%.4f", val) - v->data;
[556]     v->valid = 1;
[557]     v->no_cacheable = 0;
[558]     v->not_found = 0;
[559] 
[560]     GeoIPRecord_delete(gr);
[561] 
[562]     return NGX_OK;
[563] }
[564] 
[565] 
[566] static ngx_int_t
[567] ngx_http_geoip_city_int_variable(ngx_http_request_t *r,
[568]     ngx_http_variable_value_t *v, uintptr_t data)
[569] {
[570]     int           val;
[571]     GeoIPRecord  *gr;
[572] 
[573]     gr = ngx_http_geoip_get_city_record(r);
[574]     if (gr == NULL) {
[575]         v->not_found = 1;
[576]         return NGX_OK;
[577]     }
[578] 
[579]     v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
[580]     if (v->data == NULL) {
[581]         GeoIPRecord_delete(gr);
[582]         return NGX_ERROR;
[583]     }
[584] 
[585]     val = *(int *) ((char *) gr + data);
[586] 
[587]     v->len = ngx_sprintf(v->data, "%d", val) - v->data;
[588]     v->valid = 1;
[589]     v->no_cacheable = 0;
[590]     v->not_found = 0;
[591] 
[592]     GeoIPRecord_delete(gr);
[593] 
[594]     return NGX_OK;
[595] }
[596] 
[597] 
[598] static GeoIPRecord *
[599] ngx_http_geoip_get_city_record(ngx_http_request_t *r)
[600] {
[601]     ngx_http_geoip_conf_t  *gcf;
[602] 
[603]     gcf = ngx_http_get_module_main_conf(r, ngx_http_geoip_module);
[604] 
[605]     if (gcf->city) {
[606] #if (NGX_HAVE_GEOIP_V6)
[607]         return gcf->city_v6
[608]                    ? GeoIP_record_by_ipnum_v6(gcf->city,
[609]                                               ngx_http_geoip_addr_v6(r, gcf))
[610]                    : GeoIP_record_by_ipnum(gcf->city,
[611]                                            ngx_http_geoip_addr(r, gcf));
[612] #else
[613]         return GeoIP_record_by_ipnum(gcf->city, ngx_http_geoip_addr(r, gcf));
[614] #endif
[615]     }
[616] 
[617]     return NULL;
[618] }
[619] 
[620] 
[621] static ngx_int_t
[622] ngx_http_geoip_add_variables(ngx_conf_t *cf)
[623] {
[624]     ngx_http_variable_t  *var, *v;
[625] 
[626]     for (v = ngx_http_geoip_vars; v->name.len; v++) {
[627]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[628]         if (var == NULL) {
[629]             return NGX_ERROR;
[630]         }
[631] 
[632]         var->get_handler = v->get_handler;
[633]         var->data = v->data;
[634]     }
[635] 
[636]     return NGX_OK;
[637] }
[638] 
[639] 
[640] static void *
[641] ngx_http_geoip_create_conf(ngx_conf_t *cf)
[642] {
[643]     ngx_pool_cleanup_t     *cln;
[644]     ngx_http_geoip_conf_t  *conf;
[645] 
[646]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_geoip_conf_t));
[647]     if (conf == NULL) {
[648]         return NULL;
[649]     }
[650] 
[651]     conf->proxy_recursive = NGX_CONF_UNSET;
[652] 
[653]     cln = ngx_pool_cleanup_add(cf->pool, 0);
[654]     if (cln == NULL) {
[655]         return NULL;
[656]     }
[657] 
[658]     cln->handler = ngx_http_geoip_cleanup;
[659]     cln->data = conf;
[660] 
[661]     return conf;
[662] }
[663] 
[664] 
[665] static char *
[666] ngx_http_geoip_init_conf(ngx_conf_t *cf, void *conf)
[667] {
[668]     ngx_http_geoip_conf_t  *gcf = conf;
[669] 
[670]     ngx_conf_init_value(gcf->proxy_recursive, 0);
[671] 
[672]     return NGX_CONF_OK;
[673] }
[674] 
[675] 
[676] static char *
[677] ngx_http_geoip_country(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[678] {
[679]     ngx_http_geoip_conf_t  *gcf = conf;
[680] 
[681]     ngx_str_t  *value;
[682] 
[683]     if (gcf->country) {
[684]         return "is duplicate";
[685]     }
[686] 
[687]     value = cf->args->elts;
[688] 
[689]     gcf->country = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);
[690] 
[691]     if (gcf->country == NULL) {
[692]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[693]                            "GeoIP_open(\"%V\") failed", &value[1]);
[694] 
[695]         return NGX_CONF_ERROR;
[696]     }
[697] 
[698]     if (cf->args->nelts == 3) {
[699]         if (ngx_strcmp(value[2].data, "utf8") == 0) {
[700]             GeoIP_set_charset(gcf->country, GEOIP_CHARSET_UTF8);
[701] 
[702]         } else {
[703]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[704]                                "invalid parameter \"%V\"", &value[2]);
[705]             return NGX_CONF_ERROR;
[706]         }
[707]     }
[708] 
[709]     switch (gcf->country->databaseType) {
[710] 
[711]     case GEOIP_COUNTRY_EDITION:
[712] 
[713]         return NGX_CONF_OK;
[714] 
[715] #if (NGX_HAVE_GEOIP_V6)
[716]     case GEOIP_COUNTRY_EDITION_V6:
[717] 
[718]         gcf->country_v6 = 1;
[719]         return NGX_CONF_OK;
[720] #endif
[721] 
[722]     default:
[723]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[724]                            "invalid GeoIP database \"%V\" type:%d",
[725]                            &value[1], gcf->country->databaseType);
[726]         return NGX_CONF_ERROR;
[727]     }
[728] }
[729] 
[730] 
[731] static char *
[732] ngx_http_geoip_org(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[733] {
[734]     ngx_http_geoip_conf_t  *gcf = conf;
[735] 
[736]     ngx_str_t  *value;
[737] 
[738]     if (gcf->org) {
[739]         return "is duplicate";
[740]     }
[741] 
[742]     value = cf->args->elts;
[743] 
[744]     gcf->org = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);
[745] 
[746]     if (gcf->org == NULL) {
[747]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[748]                            "GeoIP_open(\"%V\") failed", &value[1]);
[749] 
[750]         return NGX_CONF_ERROR;
[751]     }
[752] 
[753]     if (cf->args->nelts == 3) {
[754]         if (ngx_strcmp(value[2].data, "utf8") == 0) {
[755]             GeoIP_set_charset(gcf->org, GEOIP_CHARSET_UTF8);
[756] 
[757]         } else {
[758]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[759]                                "invalid parameter \"%V\"", &value[2]);
[760]             return NGX_CONF_ERROR;
[761]         }
[762]     }
[763] 
[764]     switch (gcf->org->databaseType) {
[765] 
[766]     case GEOIP_ISP_EDITION:
[767]     case GEOIP_ORG_EDITION:
[768]     case GEOIP_DOMAIN_EDITION:
[769]     case GEOIP_ASNUM_EDITION:
[770] 
[771]         return NGX_CONF_OK;
[772] 
[773] #if (NGX_HAVE_GEOIP_V6)
[774]     case GEOIP_ISP_EDITION_V6:
[775]     case GEOIP_ORG_EDITION_V6:
[776]     case GEOIP_DOMAIN_EDITION_V6:
[777]     case GEOIP_ASNUM_EDITION_V6:
[778] 
[779]         gcf->org_v6 = 1;
[780]         return NGX_CONF_OK;
[781] #endif
[782] 
[783]     default:
[784]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[785]                            "invalid GeoIP database \"%V\" type:%d",
[786]                            &value[1], gcf->org->databaseType);
[787]         return NGX_CONF_ERROR;
[788]     }
[789] }
[790] 
[791] 
[792] static char *
[793] ngx_http_geoip_city(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[794] {
[795]     ngx_http_geoip_conf_t  *gcf = conf;
[796] 
[797]     ngx_str_t  *value;
[798] 
[799]     if (gcf->city) {
[800]         return "is duplicate";
[801]     }
[802] 
[803]     value = cf->args->elts;
[804] 
[805]     gcf->city = GeoIP_open((char *) value[1].data, GEOIP_MEMORY_CACHE);
[806] 
[807]     if (gcf->city == NULL) {
[808]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[809]                            "GeoIP_open(\"%V\") failed", &value[1]);
[810] 
[811]         return NGX_CONF_ERROR;
[812]     }
[813] 
[814]     if (cf->args->nelts == 3) {
[815]         if (ngx_strcmp(value[2].data, "utf8") == 0) {
[816]             GeoIP_set_charset(gcf->city, GEOIP_CHARSET_UTF8);
[817] 
[818]         } else {
[819]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[820]                                "invalid parameter \"%V\"", &value[2]);
[821]             return NGX_CONF_ERROR;
[822]         }
[823]     }
[824] 
[825]     switch (gcf->city->databaseType) {
[826] 
[827]     case GEOIP_CITY_EDITION_REV0:
[828]     case GEOIP_CITY_EDITION_REV1:
[829] 
[830]         return NGX_CONF_OK;
[831] 
[832] #if (NGX_HAVE_GEOIP_V6)
[833]     case GEOIP_CITY_EDITION_REV0_V6:
[834]     case GEOIP_CITY_EDITION_REV1_V6:
[835] 
[836]         gcf->city_v6 = 1;
[837]         return NGX_CONF_OK;
[838] #endif
[839] 
[840]     default:
[841]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[842]                            "invalid GeoIP City database \"%V\" type:%d",
[843]                            &value[1], gcf->city->databaseType);
[844]         return NGX_CONF_ERROR;
[845]     }
[846] }
[847] 
[848] 
[849] static char *
[850] ngx_http_geoip_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[851] {
[852]     ngx_http_geoip_conf_t  *gcf = conf;
[853] 
[854]     ngx_str_t   *value;
[855]     ngx_cidr_t  cidr, *c;
[856] 
[857]     value = cf->args->elts;
[858] 
[859]     if (ngx_http_geoip_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
[860]         return NGX_CONF_ERROR;
[861]     }
[862] 
[863]     if (gcf->proxies == NULL) {
[864]         gcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
[865]         if (gcf->proxies == NULL) {
[866]             return NGX_CONF_ERROR;
[867]         }
[868]     }
[869] 
[870]     c = ngx_array_push(gcf->proxies);
[871]     if (c == NULL) {
[872]         return NGX_CONF_ERROR;
[873]     }
[874] 
[875]     *c = cidr;
[876] 
[877]     return NGX_CONF_OK;
[878] }
[879] 
[880] static ngx_int_t
[881] ngx_http_geoip_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
[882] {
[883]     ngx_int_t  rc;
[884] 
[885]     if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
[886]         cidr->family = AF_INET;
[887]         cidr->u.in.addr = 0xffffffff;
[888]         cidr->u.in.mask = 0xffffffff;
[889] 
[890]         return NGX_OK;
[891]     }
[892] 
[893]     rc = ngx_ptocidr(net, cidr);
[894] 
[895]     if (rc == NGX_ERROR) {
[896]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
[897]         return NGX_ERROR;
[898]     }
[899] 
[900]     if (rc == NGX_DONE) {
[901]         ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[902]                            "low address bits of %V are meaningless", net);
[903]     }
[904] 
[905]     return NGX_OK;
[906] }
[907] 
[908] 
[909] static void
[910] ngx_http_geoip_cleanup(void *data)
[911] {
[912]     ngx_http_geoip_conf_t  *gcf = data;
[913] 
[914]     if (gcf->country) {
[915]         GeoIP_delete(gcf->country);
[916]     }
[917] 
[918]     if (gcf->org) {
[919]         GeoIP_delete(gcf->org);
[920]     }
[921] 
[922]     if (gcf->city) {
[923]         GeoIP_delete(gcf->city);
[924]     }
[925] }
