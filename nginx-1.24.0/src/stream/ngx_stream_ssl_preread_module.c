[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_stream.h>
[10] 
[11] 
[12] typedef struct {
[13]     ngx_flag_t      enabled;
[14] } ngx_stream_ssl_preread_srv_conf_t;
[15] 
[16] 
[17] typedef struct {
[18]     size_t          left;
[19]     size_t          size;
[20]     size_t          ext;
[21]     u_char         *pos;
[22]     u_char         *dst;
[23]     u_char          buf[4];
[24]     u_char          version[2];
[25]     ngx_str_t       host;
[26]     ngx_str_t       alpn;
[27]     ngx_log_t      *log;
[28]     ngx_pool_t     *pool;
[29]     ngx_uint_t      state;
[30] } ngx_stream_ssl_preread_ctx_t;
[31] 
[32] 
[33] static ngx_int_t ngx_stream_ssl_preread_handler(ngx_stream_session_t *s);
[34] static ngx_int_t ngx_stream_ssl_preread_parse_record(
[35]     ngx_stream_ssl_preread_ctx_t *ctx, u_char *pos, u_char *last);
[36] static ngx_int_t ngx_stream_ssl_preread_protocol_variable(
[37]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[38] static ngx_int_t ngx_stream_ssl_preread_server_name_variable(
[39]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[40] static ngx_int_t ngx_stream_ssl_preread_alpn_protocols_variable(
[41]     ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
[42] static ngx_int_t ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf);
[43] static void *ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf);
[44] static char *ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent,
[45]     void *child);
[46] static ngx_int_t ngx_stream_ssl_preread_init(ngx_conf_t *cf);
[47] 
[48] 
[49] static ngx_command_t  ngx_stream_ssl_preread_commands[] = {
[50] 
[51]     { ngx_string("ssl_preread"),
[52]       NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
[53]       ngx_conf_set_flag_slot,
[54]       NGX_STREAM_SRV_CONF_OFFSET,
[55]       offsetof(ngx_stream_ssl_preread_srv_conf_t, enabled),
[56]       NULL },
[57] 
[58]       ngx_null_command
[59] };
[60] 
[61] 
[62] static ngx_stream_module_t  ngx_stream_ssl_preread_module_ctx = {
[63]     ngx_stream_ssl_preread_add_variables,   /* preconfiguration */
[64]     ngx_stream_ssl_preread_init,            /* postconfiguration */
[65] 
[66]     NULL,                                   /* create main configuration */
[67]     NULL,                                   /* init main configuration */
[68] 
[69]     ngx_stream_ssl_preread_create_srv_conf, /* create server configuration */
[70]     ngx_stream_ssl_preread_merge_srv_conf   /* merge server configuration */
[71] };
[72] 
[73] 
[74] ngx_module_t  ngx_stream_ssl_preread_module = {
[75]     NGX_MODULE_V1,
[76]     &ngx_stream_ssl_preread_module_ctx,     /* module context */
[77]     ngx_stream_ssl_preread_commands,        /* module directives */
[78]     NGX_STREAM_MODULE,                      /* module type */
[79]     NULL,                                   /* init master */
[80]     NULL,                                   /* init module */
[81]     NULL,                                   /* init process */
[82]     NULL,                                   /* init thread */
[83]     NULL,                                   /* exit thread */
[84]     NULL,                                   /* exit process */
[85]     NULL,                                   /* exit master */
[86]     NGX_MODULE_V1_PADDING
[87] };
[88] 
[89] 
[90] static ngx_stream_variable_t  ngx_stream_ssl_preread_vars[] = {
[91] 
[92]     { ngx_string("ssl_preread_protocol"), NULL,
[93]       ngx_stream_ssl_preread_protocol_variable, 0, 0, 0 },
[94] 
[95]     { ngx_string("ssl_preread_server_name"), NULL,
[96]       ngx_stream_ssl_preread_server_name_variable, 0, 0, 0 },
[97] 
[98]     { ngx_string("ssl_preread_alpn_protocols"), NULL,
[99]       ngx_stream_ssl_preread_alpn_protocols_variable, 0, 0, 0 },
[100] 
[101]       ngx_stream_null_variable
[102] };
[103] 
[104] 
[105] static ngx_int_t
[106] ngx_stream_ssl_preread_handler(ngx_stream_session_t *s)
[107] {
[108]     u_char                             *last, *p;
[109]     size_t                              len;
[110]     ngx_int_t                           rc;
[111]     ngx_connection_t                   *c;
[112]     ngx_stream_ssl_preread_ctx_t       *ctx;
[113]     ngx_stream_ssl_preread_srv_conf_t  *sscf;
[114] 
[115]     c = s->connection;
[116] 
[117]     ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "ssl preread handler");
[118] 
[119]     sscf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_preread_module);
[120] 
[121]     if (!sscf->enabled) {
[122]         return NGX_DECLINED;
[123]     }
[124] 
[125]     if (c->type != SOCK_STREAM) {
[126]         return NGX_DECLINED;
[127]     }
[128] 
[129]     if (c->buffer == NULL) {
[130]         return NGX_AGAIN;
[131]     }
[132] 
[133]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
[134]     if (ctx == NULL) {
[135]         ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_ssl_preread_ctx_t));
[136]         if (ctx == NULL) {
[137]             return NGX_ERROR;
[138]         }
[139] 
[140]         ngx_stream_set_ctx(s, ctx, ngx_stream_ssl_preread_module);
[141] 
[142]         ctx->pool = c->pool;
[143]         ctx->log = c->log;
[144]         ctx->pos = c->buffer->pos;
[145]     }
[146] 
[147]     p = ctx->pos;
[148]     last = c->buffer->last;
[149] 
[150]     while (last - p >= 5) {
[151] 
[152]         if ((p[0] & 0x80) && p[2] == 1 && (p[3] == 0 || p[3] == 3)) {
[153]             ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[154]                            "ssl preread: version 2 ClientHello");
[155]             ctx->version[0] = p[3];
[156]             ctx->version[1] = p[4];
[157]             return NGX_OK;
[158]         }
[159] 
[160]         if (p[0] != 0x16) {
[161]             ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[162]                            "ssl preread: not a handshake");
[163]             ngx_stream_set_ctx(s, NULL, ngx_stream_ssl_preread_module);
[164]             return NGX_DECLINED;
[165]         }
[166] 
[167]         if (p[1] != 3) {
[168]             ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[169]                            "ssl preread: unsupported SSL version");
[170]             ngx_stream_set_ctx(s, NULL, ngx_stream_ssl_preread_module);
[171]             return NGX_DECLINED;
[172]         }
[173] 
[174]         len = (p[3] << 8) + p[4];
[175] 
[176]         /* read the whole record before parsing */
[177]         if ((size_t) (last - p) < len + 5) {
[178]             break;
[179]         }
[180] 
[181]         p += 5;
[182] 
[183]         rc = ngx_stream_ssl_preread_parse_record(ctx, p, p + len);
[184] 
[185]         if (rc == NGX_DECLINED) {
[186]             ngx_stream_set_ctx(s, NULL, ngx_stream_ssl_preread_module);
[187]             return NGX_DECLINED;
[188]         }
[189] 
[190]         if (rc != NGX_AGAIN) {
[191]             return rc;
[192]         }
[193] 
[194]         p += len;
[195]     }
[196] 
[197]     ctx->pos = p;
[198] 
[199]     return NGX_AGAIN;
[200] }
[201] 
[202] 
[203] static ngx_int_t
[204] ngx_stream_ssl_preread_parse_record(ngx_stream_ssl_preread_ctx_t *ctx,
[205]     u_char *pos, u_char *last)
[206] {
[207]     size_t   left, n, size, ext;
[208]     u_char  *dst, *p;
[209] 
[210]     enum {
[211]         sw_start = 0,
[212]         sw_header,          /* handshake msg_type, length */
[213]         sw_version,         /* client_version */
[214]         sw_random,          /* random */
[215]         sw_sid_len,         /* session_id length */
[216]         sw_sid,             /* session_id */
[217]         sw_cs_len,          /* cipher_suites length */
[218]         sw_cs,              /* cipher_suites */
[219]         sw_cm_len,          /* compression_methods length */
[220]         sw_cm,              /* compression_methods */
[221]         sw_ext,             /* extension */
[222]         sw_ext_header,      /* extension_type, extension_data length */
[223]         sw_sni_len,         /* SNI length */
[224]         sw_sni_host_head,   /* SNI name_type, host_name length */
[225]         sw_sni_host,        /* SNI host_name */
[226]         sw_alpn_len,        /* ALPN length */
[227]         sw_alpn_proto_len,  /* ALPN protocol_name length */
[228]         sw_alpn_proto_data, /* ALPN protocol_name */
[229]         sw_supver_len       /* supported_versions length */
[230]     } state;
[231] 
[232]     ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[233]                    "ssl preread: state %ui left %z", ctx->state, ctx->left);
[234] 
[235]     state = ctx->state;
[236]     size = ctx->size;
[237]     left = ctx->left;
[238]     ext = ctx->ext;
[239]     dst = ctx->dst;
[240]     p = ctx->buf;
[241] 
[242]     for ( ;; ) {
[243]         n = ngx_min((size_t) (last - pos), size);
[244] 
[245]         if (dst) {
[246]             dst = ngx_cpymem(dst, pos, n);
[247]         }
[248] 
[249]         pos += n;
[250]         size -= n;
[251]         left -= n;
[252] 
[253]         if (size != 0) {
[254]             break;
[255]         }
[256] 
[257]         switch (state) {
[258] 
[259]         case sw_start:
[260]             state = sw_header;
[261]             dst = p;
[262]             size = 4;
[263]             left = size;
[264]             break;
[265] 
[266]         case sw_header:
[267]             if (p[0] != 1) {
[268]                 ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[269]                                "ssl preread: not a client hello");
[270]                 return NGX_DECLINED;
[271]             }
[272] 
[273]             state = sw_version;
[274]             dst = ctx->version;
[275]             size = 2;
[276]             left = (p[1] << 16) + (p[2] << 8) + p[3];
[277]             break;
[278] 
[279]         case sw_version:
[280]             state = sw_random;
[281]             dst = NULL;
[282]             size = 32;
[283]             break;
[284] 
[285]         case sw_random:
[286]             state = sw_sid_len;
[287]             dst = p;
[288]             size = 1;
[289]             break;
[290] 
[291]         case sw_sid_len:
[292]             state = sw_sid;
[293]             dst = NULL;
[294]             size = p[0];
[295]             break;
[296] 
[297]         case sw_sid:
[298]             state = sw_cs_len;
[299]             dst = p;
[300]             size = 2;
[301]             break;
[302] 
[303]         case sw_cs_len:
[304]             state = sw_cs;
[305]             dst = NULL;
[306]             size = (p[0] << 8) + p[1];
[307]             break;
[308] 
[309]         case sw_cs:
[310]             state = sw_cm_len;
[311]             dst = p;
[312]             size = 1;
[313]             break;
[314] 
[315]         case sw_cm_len:
[316]             state = sw_cm;
[317]             dst = NULL;
[318]             size = p[0];
[319]             break;
[320] 
[321]         case sw_cm:
[322]             if (left == 0) {
[323]                 /* no extensions */
[324]                 return NGX_OK;
[325]             }
[326] 
[327]             state = sw_ext;
[328]             dst = p;
[329]             size = 2;
[330]             break;
[331] 
[332]         case sw_ext:
[333]             if (left == 0) {
[334]                 return NGX_OK;
[335]             }
[336] 
[337]             state = sw_ext_header;
[338]             dst = p;
[339]             size = 4;
[340]             break;
[341] 
[342]         case sw_ext_header:
[343]             if (p[0] == 0 && p[1] == 0 && ctx->host.data == NULL) {
[344]                 /* SNI extension */
[345]                 state = sw_sni_len;
[346]                 dst = p;
[347]                 size = 2;
[348]                 break;
[349]             }
[350] 
[351]             if (p[0] == 0 && p[1] == 16 && ctx->alpn.data == NULL) {
[352]                 /* ALPN extension */
[353]                 state = sw_alpn_len;
[354]                 dst = p;
[355]                 size = 2;
[356]                 break;
[357]             }
[358] 
[359]             if (p[0] == 0 && p[1] == 43) {
[360]                 /* supported_versions extension */
[361]                 state = sw_supver_len;
[362]                 dst = p;
[363]                 size = 1;
[364]                 break;
[365]             }
[366] 
[367]             state = sw_ext;
[368]             dst = NULL;
[369]             size = (p[2] << 8) + p[3];
[370]             break;
[371] 
[372]         case sw_sni_len:
[373]             ext = (p[0] << 8) + p[1];
[374]             state = sw_sni_host_head;
[375]             dst = p;
[376]             size = 3;
[377]             break;
[378] 
[379]         case sw_sni_host_head:
[380]             if (p[0] != 0) {
[381]                 ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[382]                                "ssl preread: SNI hostname type is not DNS");
[383]                 return NGX_DECLINED;
[384]             }
[385] 
[386]             size = (p[1] << 8) + p[2];
[387] 
[388]             if (ext < 3 + size) {
[389]                 ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[390]                                "ssl preread: SNI format error");
[391]                 return NGX_DECLINED;
[392]             }
[393]             ext -= 3 + size;
[394] 
[395]             ctx->host.data = ngx_pnalloc(ctx->pool, size);
[396]             if (ctx->host.data == NULL) {
[397]                 return NGX_ERROR;
[398]             }
[399] 
[400]             state = sw_sni_host;
[401]             dst = ctx->host.data;
[402]             break;
[403] 
[404]         case sw_sni_host:
[405]             ctx->host.len = (p[1] << 8) + p[2];
[406] 
[407]             ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[408]                            "ssl preread: SNI hostname \"%V\"", &ctx->host);
[409] 
[410]             state = sw_ext;
[411]             dst = NULL;
[412]             size = ext;
[413]             break;
[414] 
[415]         case sw_alpn_len:
[416]             ext = (p[0] << 8) + p[1];
[417] 
[418]             ctx->alpn.data = ngx_pnalloc(ctx->pool, ext);
[419]             if (ctx->alpn.data == NULL) {
[420]                 return NGX_ERROR;
[421]             }
[422] 
[423]             state = sw_alpn_proto_len;
[424]             dst = p;
[425]             size = 1;
[426]             break;
[427] 
[428]         case sw_alpn_proto_len:
[429]             size = p[0];
[430] 
[431]             if (size == 0) {
[432]                 ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[433]                                "ssl preread: ALPN empty protocol");
[434]                 return NGX_DECLINED;
[435]             }
[436] 
[437]             if (ext < 1 + size) {
[438]                 ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[439]                                "ssl preread: ALPN format error");
[440]                 return NGX_DECLINED;
[441]             }
[442]             ext -= 1 + size;
[443] 
[444]             state = sw_alpn_proto_data;
[445]             dst = ctx->alpn.data + ctx->alpn.len;
[446]             break;
[447] 
[448]         case sw_alpn_proto_data:
[449]             ctx->alpn.len += p[0];
[450] 
[451]             ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[452]                            "ssl preread: ALPN protocols \"%V\"", &ctx->alpn);
[453] 
[454]             if (ext) {
[455]                 ctx->alpn.data[ctx->alpn.len++] = ',';
[456] 
[457]                 state = sw_alpn_proto_len;
[458]                 dst = p;
[459]                 size = 1;
[460]                 break;
[461]             }
[462] 
[463]             state = sw_ext;
[464]             dst = NULL;
[465]             size = 0;
[466]             break;
[467] 
[468]         case sw_supver_len:
[469]             ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[470]                            "ssl preread: supported_versions");
[471] 
[472]             /* set TLSv1.3 */
[473]             ctx->version[0] = 3;
[474]             ctx->version[1] = 4;
[475] 
[476]             state = sw_ext;
[477]             dst = NULL;
[478]             size = p[0];
[479]             break;
[480]         }
[481] 
[482]         if (left < size) {
[483]             ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
[484]                            "ssl preread: failed to parse handshake");
[485]             return NGX_DECLINED;
[486]         }
[487]     }
[488] 
[489]     ctx->state = state;
[490]     ctx->size = size;
[491]     ctx->left = left;
[492]     ctx->ext = ext;
[493]     ctx->dst = dst;
[494] 
[495]     return NGX_AGAIN;
[496] }
[497] 
[498] 
[499] static ngx_int_t
[500] ngx_stream_ssl_preread_protocol_variable(ngx_stream_session_t *s,
[501]     ngx_variable_value_t *v, uintptr_t data)
[502] {
[503]     ngx_str_t                      version;
[504]     ngx_stream_ssl_preread_ctx_t  *ctx;
[505] 
[506]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
[507] 
[508]     if (ctx == NULL) {
[509]         v->not_found = 1;
[510]         return NGX_OK;
[511]     }
[512] 
[513]     /* SSL_get_version() format */
[514] 
[515]     ngx_str_null(&version);
[516] 
[517]     switch (ctx->version[0]) {
[518]     case 0:
[519]         switch (ctx->version[1]) {
[520]         case 2:
[521]             ngx_str_set(&version, "SSLv2");
[522]             break;
[523]         }
[524]         break;
[525]     case 3:
[526]         switch (ctx->version[1]) {
[527]         case 0:
[528]             ngx_str_set(&version, "SSLv3");
[529]             break;
[530]         case 1:
[531]             ngx_str_set(&version, "TLSv1");
[532]             break;
[533]         case 2:
[534]             ngx_str_set(&version, "TLSv1.1");
[535]             break;
[536]         case 3:
[537]             ngx_str_set(&version, "TLSv1.2");
[538]             break;
[539]         case 4:
[540]             ngx_str_set(&version, "TLSv1.3");
[541]             break;
[542]         }
[543]     }
[544] 
[545]     v->valid = 1;
[546]     v->no_cacheable = 0;
[547]     v->not_found = 0;
[548]     v->len = version.len;
[549]     v->data = version.data;
[550] 
[551]     return NGX_OK;
[552] }
[553] 
[554] 
[555] static ngx_int_t
[556] ngx_stream_ssl_preread_server_name_variable(ngx_stream_session_t *s,
[557]     ngx_variable_value_t *v, uintptr_t data)
[558] {
[559]     ngx_stream_ssl_preread_ctx_t  *ctx;
[560] 
[561]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
[562] 
[563]     if (ctx == NULL) {
[564]         v->not_found = 1;
[565]         return NGX_OK;
[566]     }
[567] 
[568]     v->valid = 1;
[569]     v->no_cacheable = 0;
[570]     v->not_found = 0;
[571]     v->len = ctx->host.len;
[572]     v->data = ctx->host.data;
[573] 
[574]     return NGX_OK;
[575] }
[576] 
[577] 
[578] static ngx_int_t
[579] ngx_stream_ssl_preread_alpn_protocols_variable(ngx_stream_session_t *s,
[580]     ngx_variable_value_t *v, uintptr_t data)
[581] {
[582]     ngx_stream_ssl_preread_ctx_t  *ctx;
[583] 
[584]     ctx = ngx_stream_get_module_ctx(s, ngx_stream_ssl_preread_module);
[585] 
[586]     if (ctx == NULL) {
[587]         v->not_found = 1;
[588]         return NGX_OK;
[589]     }
[590] 
[591]     v->valid = 1;
[592]     v->no_cacheable = 0;
[593]     v->not_found = 0;
[594]     v->len = ctx->alpn.len;
[595]     v->data = ctx->alpn.data;
[596] 
[597]     return NGX_OK;
[598] }
[599] 
[600] 
[601] static ngx_int_t
[602] ngx_stream_ssl_preread_add_variables(ngx_conf_t *cf)
[603] {
[604]     ngx_stream_variable_t  *var, *v;
[605] 
[606]     for (v = ngx_stream_ssl_preread_vars; v->name.len; v++) {
[607]         var = ngx_stream_add_variable(cf, &v->name, v->flags);
[608]         if (var == NULL) {
[609]             return NGX_ERROR;
[610]         }
[611] 
[612]         var->get_handler = v->get_handler;
[613]         var->data = v->data;
[614]     }
[615] 
[616]     return NGX_OK;
[617] }
[618] 
[619] 
[620] static void *
[621] ngx_stream_ssl_preread_create_srv_conf(ngx_conf_t *cf)
[622] {
[623]     ngx_stream_ssl_preread_srv_conf_t  *conf;
[624] 
[625]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ssl_preread_srv_conf_t));
[626]     if (conf == NULL) {
[627]         return NULL;
[628]     }
[629] 
[630]     conf->enabled = NGX_CONF_UNSET;
[631] 
[632]     return conf;
[633] }
[634] 
[635] 
[636] static char *
[637] ngx_stream_ssl_preread_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
[638] {
[639]     ngx_stream_ssl_preread_srv_conf_t *prev = parent;
[640]     ngx_stream_ssl_preread_srv_conf_t *conf = child;
[641] 
[642]     ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
[643] 
[644]     return NGX_CONF_OK;
[645] }
[646] 
[647] 
[648] static ngx_int_t
[649] ngx_stream_ssl_preread_init(ngx_conf_t *cf)
[650] {
[651]     ngx_stream_handler_pt        *h;
[652]     ngx_stream_core_main_conf_t  *cmcf;
[653] 
[654]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[655] 
[656]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
[657]     if (h == NULL) {
[658]         return NGX_ERROR;
[659]     }
[660] 
[661]     *h = ngx_stream_ssl_preread_handler;
[662] 
[663]     return NGX_OK;
[664] }
