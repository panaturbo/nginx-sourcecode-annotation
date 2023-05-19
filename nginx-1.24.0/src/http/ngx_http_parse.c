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
[13] static uint32_t  usual[] = {
[14]     0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[15] 
[16]                 /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[17]     0x7fff37d6, /* 0111 1111 1111 1111  0011 0111 1101 0110 */
[18] 
[19]                 /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[20] #if (NGX_WIN32)
[21]     0xefffffff, /* 1110 1111 1111 1111  1111 1111 1111 1111 */
[22] #else
[23]     0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[24] #endif
[25] 
[26]                 /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[27]     0x7fffffff, /* 0111 1111 1111 1111  1111 1111 1111 1111 */
[28] 
[29]     0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[30]     0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[31]     0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[32]     0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[33] };
[34] 
[35] 
[36] #if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)
[37] 
[38] #define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
[39]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)
[40] 
[41] #define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
[42]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)
[43] 
[44] #define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
[45]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)
[46] 
[47] #define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
[48]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
[49]         && m[4] == c4
[50] 
[51] #define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
[52]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
[53]         && (((uint32_t *) m)[1] & 0xffff) == ((c5 << 8) | c4)
[54] 
[55] #define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
[56]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
[57]         && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)
[58] 
[59] #define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
[60]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
[61]         && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)
[62] 
[63] #define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
[64]     *(uint32_t *) m == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)             \
[65]         && ((uint32_t *) m)[1] == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)  \
[66]         && m[8] == c8
[67] 
[68] #else /* !(NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED) */
[69] 
[70] #define ngx_str3_cmp(m, c0, c1, c2, c3)                                       \
[71]     m[0] == c0 && m[1] == c1 && m[2] == c2
[72] 
[73] #define ngx_str3Ocmp(m, c0, c1, c2, c3)                                       \
[74]     m[0] == c0 && m[2] == c2 && m[3] == c3
[75] 
[76] #define ngx_str4cmp(m, c0, c1, c2, c3)                                        \
[77]     m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3
[78] 
[79] #define ngx_str5cmp(m, c0, c1, c2, c3, c4)                                    \
[80]     m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4
[81] 
[82] #define ngx_str6cmp(m, c0, c1, c2, c3, c4, c5)                                \
[83]     m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
[84]         && m[4] == c4 && m[5] == c5
[85] 
[86] #define ngx_str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                       \
[87]     m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
[88]         && m[4] == c4 && m[5] == c5 && m[6] == c6
[89] 
[90] #define ngx_str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)                        \
[91]     m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
[92]         && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7
[93] 
[94] #define ngx_str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                    \
[95]     m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3                      \
[96]         && m[4] == c4 && m[5] == c5 && m[6] == c6 && m[7] == c7 && m[8] == c8
[97] 
[98] #endif
[99] 
[100] 
[101] /* gcc, icc, msvc and others compile these switches as an jump table */
[102] 
[103] ngx_int_t
[104] ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b)
[105] {
[106]     u_char  c, ch, *p, *m;
[107]     enum {
[108]         sw_start = 0,
[109]         sw_method,
[110]         sw_spaces_before_uri,
[111]         sw_schema,
[112]         sw_schema_slash,
[113]         sw_schema_slash_slash,
[114]         sw_host_start,
[115]         sw_host,
[116]         sw_host_end,
[117]         sw_host_ip_literal,
[118]         sw_port,
[119]         sw_after_slash_in_uri,
[120]         sw_check_uri,
[121]         sw_uri,
[122]         sw_http_09,
[123]         sw_http_H,
[124]         sw_http_HT,
[125]         sw_http_HTT,
[126]         sw_http_HTTP,
[127]         sw_first_major_digit,
[128]         sw_major_digit,
[129]         sw_first_minor_digit,
[130]         sw_minor_digit,
[131]         sw_spaces_after_digit,
[132]         sw_almost_done
[133]     } state;
[134] 
[135]     state = r->state;
[136] 
[137]     for (p = b->pos; p < b->last; p++) {
[138]         ch = *p;
[139] 
[140]         switch (state) {
[141] 
[142]         /* HTTP methods: GET, HEAD, POST */
[143]         case sw_start:
[144]             r->request_start = p;
[145] 
[146]             if (ch == CR || ch == LF) {
[147]                 break;
[148]             }
[149] 
[150]             if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
[151]                 return NGX_HTTP_PARSE_INVALID_METHOD;
[152]             }
[153] 
[154]             state = sw_method;
[155]             break;
[156] 
[157]         case sw_method:
[158]             if (ch == ' ') {
[159]                 r->method_end = p - 1;
[160]                 m = r->request_start;
[161] 
[162]                 switch (p - m) {
[163] 
[164]                 case 3:
[165]                     if (ngx_str3_cmp(m, 'G', 'E', 'T', ' ')) {
[166]                         r->method = NGX_HTTP_GET;
[167]                         break;
[168]                     }
[169] 
[170]                     if (ngx_str3_cmp(m, 'P', 'U', 'T', ' ')) {
[171]                         r->method = NGX_HTTP_PUT;
[172]                         break;
[173]                     }
[174] 
[175]                     break;
[176] 
[177]                 case 4:
[178]                     if (m[1] == 'O') {
[179] 
[180]                         if (ngx_str3Ocmp(m, 'P', 'O', 'S', 'T')) {
[181]                             r->method = NGX_HTTP_POST;
[182]                             break;
[183]                         }
[184] 
[185]                         if (ngx_str3Ocmp(m, 'C', 'O', 'P', 'Y')) {
[186]                             r->method = NGX_HTTP_COPY;
[187]                             break;
[188]                         }
[189] 
[190]                         if (ngx_str3Ocmp(m, 'M', 'O', 'V', 'E')) {
[191]                             r->method = NGX_HTTP_MOVE;
[192]                             break;
[193]                         }
[194] 
[195]                         if (ngx_str3Ocmp(m, 'L', 'O', 'C', 'K')) {
[196]                             r->method = NGX_HTTP_LOCK;
[197]                             break;
[198]                         }
[199] 
[200]                     } else {
[201] 
[202]                         if (ngx_str4cmp(m, 'H', 'E', 'A', 'D')) {
[203]                             r->method = NGX_HTTP_HEAD;
[204]                             break;
[205]                         }
[206]                     }
[207] 
[208]                     break;
[209] 
[210]                 case 5:
[211]                     if (ngx_str5cmp(m, 'M', 'K', 'C', 'O', 'L')) {
[212]                         r->method = NGX_HTTP_MKCOL;
[213]                         break;
[214]                     }
[215] 
[216]                     if (ngx_str5cmp(m, 'P', 'A', 'T', 'C', 'H')) {
[217]                         r->method = NGX_HTTP_PATCH;
[218]                         break;
[219]                     }
[220] 
[221]                     if (ngx_str5cmp(m, 'T', 'R', 'A', 'C', 'E')) {
[222]                         r->method = NGX_HTTP_TRACE;
[223]                         break;
[224]                     }
[225] 
[226]                     break;
[227] 
[228]                 case 6:
[229]                     if (ngx_str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E')) {
[230]                         r->method = NGX_HTTP_DELETE;
[231]                         break;
[232]                     }
[233] 
[234]                     if (ngx_str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K')) {
[235]                         r->method = NGX_HTTP_UNLOCK;
[236]                         break;
[237]                     }
[238] 
[239]                     break;
[240] 
[241]                 case 7:
[242]                     if (ngx_str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
[243]                     {
[244]                         r->method = NGX_HTTP_OPTIONS;
[245]                     }
[246] 
[247]                     if (ngx_str7_cmp(m, 'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '))
[248]                     {
[249]                         r->method = NGX_HTTP_CONNECT;
[250]                     }
[251] 
[252]                     break;
[253] 
[254]                 case 8:
[255]                     if (ngx_str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
[256]                     {
[257]                         r->method = NGX_HTTP_PROPFIND;
[258]                     }
[259] 
[260]                     break;
[261] 
[262]                 case 9:
[263]                     if (ngx_str9cmp(m,
[264]                             'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H'))
[265]                     {
[266]                         r->method = NGX_HTTP_PROPPATCH;
[267]                     }
[268] 
[269]                     break;
[270]                 }
[271] 
[272]                 state = sw_spaces_before_uri;
[273]                 break;
[274]             }
[275] 
[276]             if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
[277]                 return NGX_HTTP_PARSE_INVALID_METHOD;
[278]             }
[279] 
[280]             break;
[281] 
[282]         /* space* before URI */
[283]         case sw_spaces_before_uri:
[284] 
[285]             if (ch == '/') {
[286]                 r->uri_start = p;
[287]                 state = sw_after_slash_in_uri;
[288]                 break;
[289]             }
[290] 
[291]             c = (u_char) (ch | 0x20);
[292]             if (c >= 'a' && c <= 'z') {
[293]                 r->schema_start = p;
[294]                 state = sw_schema;
[295]                 break;
[296]             }
[297] 
[298]             switch (ch) {
[299]             case ' ':
[300]                 break;
[301]             default:
[302]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[303]             }
[304]             break;
[305] 
[306]         case sw_schema:
[307] 
[308]             c = (u_char) (ch | 0x20);
[309]             if (c >= 'a' && c <= 'z') {
[310]                 break;
[311]             }
[312] 
[313]             if ((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
[314]             {
[315]                 break;
[316]             }
[317] 
[318]             switch (ch) {
[319]             case ':':
[320]                 r->schema_end = p;
[321]                 state = sw_schema_slash;
[322]                 break;
[323]             default:
[324]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[325]             }
[326]             break;
[327] 
[328]         case sw_schema_slash:
[329]             switch (ch) {
[330]             case '/':
[331]                 state = sw_schema_slash_slash;
[332]                 break;
[333]             default:
[334]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[335]             }
[336]             break;
[337] 
[338]         case sw_schema_slash_slash:
[339]             switch (ch) {
[340]             case '/':
[341]                 state = sw_host_start;
[342]                 break;
[343]             default:
[344]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[345]             }
[346]             break;
[347] 
[348]         case sw_host_start:
[349] 
[350]             r->host_start = p;
[351] 
[352]             if (ch == '[') {
[353]                 state = sw_host_ip_literal;
[354]                 break;
[355]             }
[356] 
[357]             state = sw_host;
[358] 
[359]             /* fall through */
[360] 
[361]         case sw_host:
[362] 
[363]             c = (u_char) (ch | 0x20);
[364]             if (c >= 'a' && c <= 'z') {
[365]                 break;
[366]             }
[367] 
[368]             if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
[369]                 break;
[370]             }
[371] 
[372]             /* fall through */
[373] 
[374]         case sw_host_end:
[375] 
[376]             r->host_end = p;
[377] 
[378]             switch (ch) {
[379]             case ':':
[380]                 state = sw_port;
[381]                 break;
[382]             case '/':
[383]                 r->uri_start = p;
[384]                 state = sw_after_slash_in_uri;
[385]                 break;
[386]             case '?':
[387]                 r->uri_start = p;
[388]                 r->args_start = p + 1;
[389]                 r->empty_path_in_uri = 1;
[390]                 state = sw_uri;
[391]                 break;
[392]             case ' ':
[393]                 /*
[394]                  * use single "/" from request line to preserve pointers,
[395]                  * if request line will be copied to large client buffer
[396]                  */
[397]                 r->uri_start = r->schema_end + 1;
[398]                 r->uri_end = r->schema_end + 2;
[399]                 state = sw_http_09;
[400]                 break;
[401]             default:
[402]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[403]             }
[404]             break;
[405] 
[406]         case sw_host_ip_literal:
[407] 
[408]             if (ch >= '0' && ch <= '9') {
[409]                 break;
[410]             }
[411] 
[412]             c = (u_char) (ch | 0x20);
[413]             if (c >= 'a' && c <= 'z') {
[414]                 break;
[415]             }
[416] 
[417]             switch (ch) {
[418]             case ':':
[419]                 break;
[420]             case ']':
[421]                 state = sw_host_end;
[422]                 break;
[423]             case '-':
[424]             case '.':
[425]             case '_':
[426]             case '~':
[427]                 /* unreserved */
[428]                 break;
[429]             case '!':
[430]             case '$':
[431]             case '&':
[432]             case '\'':
[433]             case '(':
[434]             case ')':
[435]             case '*':
[436]             case '+':
[437]             case ',':
[438]             case ';':
[439]             case '=':
[440]                 /* sub-delims */
[441]                 break;
[442]             default:
[443]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[444]             }
[445]             break;
[446] 
[447]         case sw_port:
[448]             if (ch >= '0' && ch <= '9') {
[449]                 break;
[450]             }
[451] 
[452]             switch (ch) {
[453]             case '/':
[454]                 r->port_end = p;
[455]                 r->uri_start = p;
[456]                 state = sw_after_slash_in_uri;
[457]                 break;
[458]             case '?':
[459]                 r->port_end = p;
[460]                 r->uri_start = p;
[461]                 r->args_start = p + 1;
[462]                 r->empty_path_in_uri = 1;
[463]                 state = sw_uri;
[464]                 break;
[465]             case ' ':
[466]                 r->port_end = p;
[467]                 /*
[468]                  * use single "/" from request line to preserve pointers,
[469]                  * if request line will be copied to large client buffer
[470]                  */
[471]                 r->uri_start = r->schema_end + 1;
[472]                 r->uri_end = r->schema_end + 2;
[473]                 state = sw_http_09;
[474]                 break;
[475]             default:
[476]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[477]             }
[478]             break;
[479] 
[480]         /* check "/.", "//", "%", and "\" (Win32) in URI */
[481]         case sw_after_slash_in_uri:
[482] 
[483]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[484]                 state = sw_check_uri;
[485]                 break;
[486]             }
[487] 
[488]             switch (ch) {
[489]             case ' ':
[490]                 r->uri_end = p;
[491]                 state = sw_http_09;
[492]                 break;
[493]             case CR:
[494]                 r->uri_end = p;
[495]                 r->http_minor = 9;
[496]                 state = sw_almost_done;
[497]                 break;
[498]             case LF:
[499]                 r->uri_end = p;
[500]                 r->http_minor = 9;
[501]                 goto done;
[502]             case '.':
[503]                 r->complex_uri = 1;
[504]                 state = sw_uri;
[505]                 break;
[506]             case '%':
[507]                 r->quoted_uri = 1;
[508]                 state = sw_uri;
[509]                 break;
[510]             case '/':
[511]                 r->complex_uri = 1;
[512]                 state = sw_uri;
[513]                 break;
[514] #if (NGX_WIN32)
[515]             case '\\':
[516]                 r->complex_uri = 1;
[517]                 state = sw_uri;
[518]                 break;
[519] #endif
[520]             case '?':
[521]                 r->args_start = p + 1;
[522]                 state = sw_uri;
[523]                 break;
[524]             case '#':
[525]                 r->complex_uri = 1;
[526]                 state = sw_uri;
[527]                 break;
[528]             case '+':
[529]                 r->plus_in_uri = 1;
[530]                 break;
[531]             default:
[532]                 if (ch < 0x20 || ch == 0x7f) {
[533]                     return NGX_HTTP_PARSE_INVALID_REQUEST;
[534]                 }
[535]                 state = sw_check_uri;
[536]                 break;
[537]             }
[538]             break;
[539] 
[540]         /* check "/", "%" and "\" (Win32) in URI */
[541]         case sw_check_uri:
[542] 
[543]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[544]                 break;
[545]             }
[546] 
[547]             switch (ch) {
[548]             case '/':
[549] #if (NGX_WIN32)
[550]                 if (r->uri_ext == p) {
[551]                     r->complex_uri = 1;
[552]                     state = sw_uri;
[553]                     break;
[554]                 }
[555] #endif
[556]                 r->uri_ext = NULL;
[557]                 state = sw_after_slash_in_uri;
[558]                 break;
[559]             case '.':
[560]                 r->uri_ext = p + 1;
[561]                 break;
[562]             case ' ':
[563]                 r->uri_end = p;
[564]                 state = sw_http_09;
[565]                 break;
[566]             case CR:
[567]                 r->uri_end = p;
[568]                 r->http_minor = 9;
[569]                 state = sw_almost_done;
[570]                 break;
[571]             case LF:
[572]                 r->uri_end = p;
[573]                 r->http_minor = 9;
[574]                 goto done;
[575] #if (NGX_WIN32)
[576]             case '\\':
[577]                 r->complex_uri = 1;
[578]                 state = sw_after_slash_in_uri;
[579]                 break;
[580] #endif
[581]             case '%':
[582]                 r->quoted_uri = 1;
[583]                 state = sw_uri;
[584]                 break;
[585]             case '?':
[586]                 r->args_start = p + 1;
[587]                 state = sw_uri;
[588]                 break;
[589]             case '#':
[590]                 r->complex_uri = 1;
[591]                 state = sw_uri;
[592]                 break;
[593]             case '+':
[594]                 r->plus_in_uri = 1;
[595]                 break;
[596]             default:
[597]                 if (ch < 0x20 || ch == 0x7f) {
[598]                     return NGX_HTTP_PARSE_INVALID_REQUEST;
[599]                 }
[600]                 break;
[601]             }
[602]             break;
[603] 
[604]         /* URI */
[605]         case sw_uri:
[606] 
[607]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[608]                 break;
[609]             }
[610] 
[611]             switch (ch) {
[612]             case ' ':
[613]                 r->uri_end = p;
[614]                 state = sw_http_09;
[615]                 break;
[616]             case CR:
[617]                 r->uri_end = p;
[618]                 r->http_minor = 9;
[619]                 state = sw_almost_done;
[620]                 break;
[621]             case LF:
[622]                 r->uri_end = p;
[623]                 r->http_minor = 9;
[624]                 goto done;
[625]             case '#':
[626]                 r->complex_uri = 1;
[627]                 break;
[628]             default:
[629]                 if (ch < 0x20 || ch == 0x7f) {
[630]                     return NGX_HTTP_PARSE_INVALID_REQUEST;
[631]                 }
[632]                 break;
[633]             }
[634]             break;
[635] 
[636]         /* space+ after URI */
[637]         case sw_http_09:
[638]             switch (ch) {
[639]             case ' ':
[640]                 break;
[641]             case CR:
[642]                 r->http_minor = 9;
[643]                 state = sw_almost_done;
[644]                 break;
[645]             case LF:
[646]                 r->http_minor = 9;
[647]                 goto done;
[648]             case 'H':
[649]                 r->http_protocol.data = p;
[650]                 state = sw_http_H;
[651]                 break;
[652]             default:
[653]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[654]             }
[655]             break;
[656] 
[657]         case sw_http_H:
[658]             switch (ch) {
[659]             case 'T':
[660]                 state = sw_http_HT;
[661]                 break;
[662]             default:
[663]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[664]             }
[665]             break;
[666] 
[667]         case sw_http_HT:
[668]             switch (ch) {
[669]             case 'T':
[670]                 state = sw_http_HTT;
[671]                 break;
[672]             default:
[673]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[674]             }
[675]             break;
[676] 
[677]         case sw_http_HTT:
[678]             switch (ch) {
[679]             case 'P':
[680]                 state = sw_http_HTTP;
[681]                 break;
[682]             default:
[683]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[684]             }
[685]             break;
[686] 
[687]         case sw_http_HTTP:
[688]             switch (ch) {
[689]             case '/':
[690]                 state = sw_first_major_digit;
[691]                 break;
[692]             default:
[693]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[694]             }
[695]             break;
[696] 
[697]         /* first digit of major HTTP version */
[698]         case sw_first_major_digit:
[699]             if (ch < '1' || ch > '9') {
[700]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[701]             }
[702] 
[703]             r->http_major = ch - '0';
[704] 
[705]             if (r->http_major > 1) {
[706]                 return NGX_HTTP_PARSE_INVALID_VERSION;
[707]             }
[708] 
[709]             state = sw_major_digit;
[710]             break;
[711] 
[712]         /* major HTTP version or dot */
[713]         case sw_major_digit:
[714]             if (ch == '.') {
[715]                 state = sw_first_minor_digit;
[716]                 break;
[717]             }
[718] 
[719]             if (ch < '0' || ch > '9') {
[720]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[721]             }
[722] 
[723]             r->http_major = r->http_major * 10 + (ch - '0');
[724] 
[725]             if (r->http_major > 1) {
[726]                 return NGX_HTTP_PARSE_INVALID_VERSION;
[727]             }
[728] 
[729]             break;
[730] 
[731]         /* first digit of minor HTTP version */
[732]         case sw_first_minor_digit:
[733]             if (ch < '0' || ch > '9') {
[734]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[735]             }
[736] 
[737]             r->http_minor = ch - '0';
[738]             state = sw_minor_digit;
[739]             break;
[740] 
[741]         /* minor HTTP version or end of request line */
[742]         case sw_minor_digit:
[743]             if (ch == CR) {
[744]                 state = sw_almost_done;
[745]                 break;
[746]             }
[747] 
[748]             if (ch == LF) {
[749]                 goto done;
[750]             }
[751] 
[752]             if (ch == ' ') {
[753]                 state = sw_spaces_after_digit;
[754]                 break;
[755]             }
[756] 
[757]             if (ch < '0' || ch > '9') {
[758]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[759]             }
[760] 
[761]             if (r->http_minor > 99) {
[762]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[763]             }
[764] 
[765]             r->http_minor = r->http_minor * 10 + (ch - '0');
[766]             break;
[767] 
[768]         case sw_spaces_after_digit:
[769]             switch (ch) {
[770]             case ' ':
[771]                 break;
[772]             case CR:
[773]                 state = sw_almost_done;
[774]                 break;
[775]             case LF:
[776]                 goto done;
[777]             default:
[778]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[779]             }
[780]             break;
[781] 
[782]         /* end of request line */
[783]         case sw_almost_done:
[784]             r->request_end = p - 1;
[785]             switch (ch) {
[786]             case LF:
[787]                 goto done;
[788]             default:
[789]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[790]             }
[791]         }
[792]     }
[793] 
[794]     b->pos = p;
[795]     r->state = state;
[796] 
[797]     return NGX_AGAIN;
[798] 
[799] done:
[800] 
[801]     b->pos = p + 1;
[802] 
[803]     if (r->request_end == NULL) {
[804]         r->request_end = p;
[805]     }
[806] 
[807]     r->http_version = r->http_major * 1000 + r->http_minor;
[808]     r->state = sw_start;
[809] 
[810]     if (r->http_version == 9 && r->method != NGX_HTTP_GET) {
[811]         return NGX_HTTP_PARSE_INVALID_09_METHOD;
[812]     }
[813] 
[814]     return NGX_OK;
[815] }
[816] 
[817] 
[818] ngx_int_t
[819] ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b,
[820]     ngx_uint_t allow_underscores)
[821] {
[822]     u_char      c, ch, *p;
[823]     ngx_uint_t  hash, i;
[824]     enum {
[825]         sw_start = 0,
[826]         sw_name,
[827]         sw_space_before_value,
[828]         sw_value,
[829]         sw_space_after_value,
[830]         sw_ignore_line,
[831]         sw_almost_done,
[832]         sw_header_almost_done
[833]     } state;
[834] 
[835]     /* the last '\0' is not needed because string is zero terminated */
[836] 
[837]     static u_char  lowcase[] =
[838]         "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
[839]         "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
[840]         "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
[841]         "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
[842]         "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
[843]         "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
[844]         "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
[845]         "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
[846] 
[847]     state = r->state;
[848]     hash = r->header_hash;
[849]     i = r->lowcase_index;
[850] 
[851]     for (p = b->pos; p < b->last; p++) {
[852]         ch = *p;
[853] 
[854]         switch (state) {
[855] 
[856]         /* first char */
[857]         case sw_start:
[858]             r->header_name_start = p;
[859]             r->invalid_header = 0;
[860] 
[861]             switch (ch) {
[862]             case CR:
[863]                 r->header_end = p;
[864]                 state = sw_header_almost_done;
[865]                 break;
[866]             case LF:
[867]                 r->header_end = p;
[868]                 goto header_done;
[869]             default:
[870]                 state = sw_name;
[871] 
[872]                 c = lowcase[ch];
[873] 
[874]                 if (c) {
[875]                     hash = ngx_hash(0, c);
[876]                     r->lowcase_header[0] = c;
[877]                     i = 1;
[878]                     break;
[879]                 }
[880] 
[881]                 if (ch == '_') {
[882]                     if (allow_underscores) {
[883]                         hash = ngx_hash(0, ch);
[884]                         r->lowcase_header[0] = ch;
[885]                         i = 1;
[886] 
[887]                     } else {
[888]                         hash = 0;
[889]                         i = 0;
[890]                         r->invalid_header = 1;
[891]                     }
[892] 
[893]                     break;
[894]                 }
[895] 
[896]                 if (ch <= 0x20 || ch == 0x7f || ch == ':') {
[897]                     r->header_end = p;
[898]                     return NGX_HTTP_PARSE_INVALID_HEADER;
[899]                 }
[900] 
[901]                 hash = 0;
[902]                 i = 0;
[903]                 r->invalid_header = 1;
[904] 
[905]                 break;
[906] 
[907]             }
[908]             break;
[909] 
[910]         /* header name */
[911]         case sw_name:
[912]             c = lowcase[ch];
[913] 
[914]             if (c) {
[915]                 hash = ngx_hash(hash, c);
[916]                 r->lowcase_header[i++] = c;
[917]                 i &= (NGX_HTTP_LC_HEADER_LEN - 1);
[918]                 break;
[919]             }
[920] 
[921]             if (ch == '_') {
[922]                 if (allow_underscores) {
[923]                     hash = ngx_hash(hash, ch);
[924]                     r->lowcase_header[i++] = ch;
[925]                     i &= (NGX_HTTP_LC_HEADER_LEN - 1);
[926] 
[927]                 } else {
[928]                     r->invalid_header = 1;
[929]                 }
[930] 
[931]                 break;
[932]             }
[933] 
[934]             if (ch == ':') {
[935]                 r->header_name_end = p;
[936]                 state = sw_space_before_value;
[937]                 break;
[938]             }
[939] 
[940]             if (ch == CR) {
[941]                 r->header_name_end = p;
[942]                 r->header_start = p;
[943]                 r->header_end = p;
[944]                 state = sw_almost_done;
[945]                 break;
[946]             }
[947] 
[948]             if (ch == LF) {
[949]                 r->header_name_end = p;
[950]                 r->header_start = p;
[951]                 r->header_end = p;
[952]                 goto done;
[953]             }
[954] 
[955]             /* IIS may send the duplicate "HTTP/1.1 ..." lines */
[956]             if (ch == '/'
[957]                 && r->upstream
[958]                 && p - r->header_name_start == 4
[959]                 && ngx_strncmp(r->header_name_start, "HTTP", 4) == 0)
[960]             {
[961]                 state = sw_ignore_line;
[962]                 break;
[963]             }
[964] 
[965]             if (ch <= 0x20 || ch == 0x7f) {
[966]                 r->header_end = p;
[967]                 return NGX_HTTP_PARSE_INVALID_HEADER;
[968]             }
[969] 
[970]             r->invalid_header = 1;
[971] 
[972]             break;
[973] 
[974]         /* space* before header value */
[975]         case sw_space_before_value:
[976]             switch (ch) {
[977]             case ' ':
[978]                 break;
[979]             case CR:
[980]                 r->header_start = p;
[981]                 r->header_end = p;
[982]                 state = sw_almost_done;
[983]                 break;
[984]             case LF:
[985]                 r->header_start = p;
[986]                 r->header_end = p;
[987]                 goto done;
[988]             case '\0':
[989]                 r->header_end = p;
[990]                 return NGX_HTTP_PARSE_INVALID_HEADER;
[991]             default:
[992]                 r->header_start = p;
[993]                 state = sw_value;
[994]                 break;
[995]             }
[996]             break;
[997] 
[998]         /* header value */
[999]         case sw_value:
[1000]             switch (ch) {
[1001]             case ' ':
[1002]                 r->header_end = p;
[1003]                 state = sw_space_after_value;
[1004]                 break;
[1005]             case CR:
[1006]                 r->header_end = p;
[1007]                 state = sw_almost_done;
[1008]                 break;
[1009]             case LF:
[1010]                 r->header_end = p;
[1011]                 goto done;
[1012]             case '\0':
[1013]                 r->header_end = p;
[1014]                 return NGX_HTTP_PARSE_INVALID_HEADER;
[1015]             }
[1016]             break;
[1017] 
[1018]         /* space* before end of header line */
[1019]         case sw_space_after_value:
[1020]             switch (ch) {
[1021]             case ' ':
[1022]                 break;
[1023]             case CR:
[1024]                 state = sw_almost_done;
[1025]                 break;
[1026]             case LF:
[1027]                 goto done;
[1028]             case '\0':
[1029]                 r->header_end = p;
[1030]                 return NGX_HTTP_PARSE_INVALID_HEADER;
[1031]             default:
[1032]                 state = sw_value;
[1033]                 break;
[1034]             }
[1035]             break;
[1036] 
[1037]         /* ignore header line */
[1038]         case sw_ignore_line:
[1039]             switch (ch) {
[1040]             case LF:
[1041]                 state = sw_start;
[1042]                 break;
[1043]             default:
[1044]                 break;
[1045]             }
[1046]             break;
[1047] 
[1048]         /* end of header line */
[1049]         case sw_almost_done:
[1050]             switch (ch) {
[1051]             case LF:
[1052]                 goto done;
[1053]             case CR:
[1054]                 break;
[1055]             default:
[1056]                 return NGX_HTTP_PARSE_INVALID_HEADER;
[1057]             }
[1058]             break;
[1059] 
[1060]         /* end of header */
[1061]         case sw_header_almost_done:
[1062]             switch (ch) {
[1063]             case LF:
[1064]                 goto header_done;
[1065]             default:
[1066]                 return NGX_HTTP_PARSE_INVALID_HEADER;
[1067]             }
[1068]         }
[1069]     }
[1070] 
[1071]     b->pos = p;
[1072]     r->state = state;
[1073]     r->header_hash = hash;
[1074]     r->lowcase_index = i;
[1075] 
[1076]     return NGX_AGAIN;
[1077] 
[1078] done:
[1079] 
[1080]     b->pos = p + 1;
[1081]     r->state = sw_start;
[1082]     r->header_hash = hash;
[1083]     r->lowcase_index = i;
[1084] 
[1085]     return NGX_OK;
[1086] 
[1087] header_done:
[1088] 
[1089]     b->pos = p + 1;
[1090]     r->state = sw_start;
[1091] 
[1092]     return NGX_HTTP_PARSE_HEADER_DONE;
[1093] }
[1094] 
[1095] 
[1096] ngx_int_t
[1097] ngx_http_parse_uri(ngx_http_request_t *r)
[1098] {
[1099]     u_char  *p, ch;
[1100]     enum {
[1101]         sw_start = 0,
[1102]         sw_after_slash_in_uri,
[1103]         sw_check_uri,
[1104]         sw_uri
[1105]     } state;
[1106] 
[1107]     state = sw_start;
[1108] 
[1109]     for (p = r->uri_start; p != r->uri_end; p++) {
[1110] 
[1111]         ch = *p;
[1112] 
[1113]         switch (state) {
[1114] 
[1115]         case sw_start:
[1116] 
[1117]             if (ch != '/') {
[1118]                 return NGX_ERROR;
[1119]             }
[1120] 
[1121]             state = sw_after_slash_in_uri;
[1122]             break;
[1123] 
[1124]         /* check "/.", "//", "%", and "\" (Win32) in URI */
[1125]         case sw_after_slash_in_uri:
[1126] 
[1127]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1128]                 state = sw_check_uri;
[1129]                 break;
[1130]             }
[1131] 
[1132]             switch (ch) {
[1133]             case '.':
[1134]                 r->complex_uri = 1;
[1135]                 state = sw_uri;
[1136]                 break;
[1137]             case '%':
[1138]                 r->quoted_uri = 1;
[1139]                 state = sw_uri;
[1140]                 break;
[1141]             case '/':
[1142]                 r->complex_uri = 1;
[1143]                 state = sw_uri;
[1144]                 break;
[1145] #if (NGX_WIN32)
[1146]             case '\\':
[1147]                 r->complex_uri = 1;
[1148]                 state = sw_uri;
[1149]                 break;
[1150] #endif
[1151]             case '?':
[1152]                 r->args_start = p + 1;
[1153]                 state = sw_uri;
[1154]                 break;
[1155]             case '#':
[1156]                 r->complex_uri = 1;
[1157]                 state = sw_uri;
[1158]                 break;
[1159]             case '+':
[1160]                 r->plus_in_uri = 1;
[1161]                 break;
[1162]             default:
[1163]                 if (ch <= 0x20 || ch == 0x7f) {
[1164]                     return NGX_ERROR;
[1165]                 }
[1166]                 state = sw_check_uri;
[1167]                 break;
[1168]             }
[1169]             break;
[1170] 
[1171]         /* check "/", "%" and "\" (Win32) in URI */
[1172]         case sw_check_uri:
[1173] 
[1174]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1175]                 break;
[1176]             }
[1177] 
[1178]             switch (ch) {
[1179]             case '/':
[1180] #if (NGX_WIN32)
[1181]                 if (r->uri_ext == p) {
[1182]                     r->complex_uri = 1;
[1183]                     state = sw_uri;
[1184]                     break;
[1185]                 }
[1186] #endif
[1187]                 r->uri_ext = NULL;
[1188]                 state = sw_after_slash_in_uri;
[1189]                 break;
[1190]             case '.':
[1191]                 r->uri_ext = p + 1;
[1192]                 break;
[1193] #if (NGX_WIN32)
[1194]             case '\\':
[1195]                 r->complex_uri = 1;
[1196]                 state = sw_after_slash_in_uri;
[1197]                 break;
[1198] #endif
[1199]             case '%':
[1200]                 r->quoted_uri = 1;
[1201]                 state = sw_uri;
[1202]                 break;
[1203]             case '?':
[1204]                 r->args_start = p + 1;
[1205]                 state = sw_uri;
[1206]                 break;
[1207]             case '#':
[1208]                 r->complex_uri = 1;
[1209]                 state = sw_uri;
[1210]                 break;
[1211]             case '+':
[1212]                 r->plus_in_uri = 1;
[1213]                 break;
[1214]             default:
[1215]                 if (ch <= 0x20 || ch == 0x7f) {
[1216]                     return NGX_ERROR;
[1217]                 }
[1218]                 break;
[1219]             }
[1220]             break;
[1221] 
[1222]         /* URI */
[1223]         case sw_uri:
[1224] 
[1225]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1226]                 break;
[1227]             }
[1228] 
[1229]             switch (ch) {
[1230]             case '#':
[1231]                 r->complex_uri = 1;
[1232]                 break;
[1233]             default:
[1234]                 if (ch <= 0x20 || ch == 0x7f) {
[1235]                     return NGX_ERROR;
[1236]                 }
[1237]                 break;
[1238]             }
[1239]             break;
[1240]         }
[1241]     }
[1242] 
[1243]     return NGX_OK;
[1244] }
[1245] 
[1246] 
[1247] ngx_int_t
[1248] ngx_http_parse_complex_uri(ngx_http_request_t *r, ngx_uint_t merge_slashes)
[1249] {
[1250]     u_char  c, ch, decoded, *p, *u;
[1251]     enum {
[1252]         sw_usual = 0,
[1253]         sw_slash,
[1254]         sw_dot,
[1255]         sw_dot_dot,
[1256]         sw_quoted,
[1257]         sw_quoted_second
[1258]     } state, quoted_state;
[1259] 
[1260] #if (NGX_SUPPRESS_WARN)
[1261]     decoded = '\0';
[1262]     quoted_state = sw_usual;
[1263] #endif
[1264] 
[1265]     state = sw_usual;
[1266]     p = r->uri_start;
[1267]     u = r->uri.data;
[1268]     r->uri_ext = NULL;
[1269]     r->args_start = NULL;
[1270] 
[1271]     if (r->empty_path_in_uri) {
[1272]         *u++ = '/';
[1273]     }
[1274] 
[1275]     ch = *p++;
[1276] 
[1277]     while (p <= r->uri_end) {
[1278] 
[1279]         /*
[1280]          * we use "ch = *p++" inside the cycle, but this operation is safe,
[1281]          * because after the URI there is always at least one character:
[1282]          * the line feed
[1283]          */
[1284] 
[1285]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1286]                        "s:%d in:'%Xd:%c'", state, ch, ch);
[1287] 
[1288]         switch (state) {
[1289] 
[1290]         case sw_usual:
[1291] 
[1292]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1293]                 *u++ = ch;
[1294]                 ch = *p++;
[1295]                 break;
[1296]             }
[1297] 
[1298]             switch (ch) {
[1299] #if (NGX_WIN32)
[1300]             case '\\':
[1301]                 if (u - 2 >= r->uri.data
[1302]                     && *(u - 1) == '.' && *(u - 2) != '.')
[1303]                 {
[1304]                     u--;
[1305]                 }
[1306] 
[1307]                 r->uri_ext = NULL;
[1308] 
[1309]                 if (p == r->uri_start + r->uri.len) {
[1310] 
[1311]                     /*
[1312]                      * we omit the last "\" to cause redirect because
[1313]                      * the browsers do not treat "\" as "/" in relative URL path
[1314]                      */
[1315] 
[1316]                     break;
[1317]                 }
[1318] 
[1319]                 state = sw_slash;
[1320]                 *u++ = '/';
[1321]                 break;
[1322] #endif
[1323]             case '/':
[1324] #if (NGX_WIN32)
[1325]                 if (u - 2 >= r->uri.data
[1326]                     && *(u - 1) == '.' && *(u - 2) != '.')
[1327]                 {
[1328]                     u--;
[1329]                 }
[1330] #endif
[1331]                 r->uri_ext = NULL;
[1332]                 state = sw_slash;
[1333]                 *u++ = ch;
[1334]                 break;
[1335]             case '%':
[1336]                 quoted_state = state;
[1337]                 state = sw_quoted;
[1338]                 break;
[1339]             case '?':
[1340]                 r->args_start = p;
[1341]                 goto args;
[1342]             case '#':
[1343]                 goto done;
[1344]             case '.':
[1345]                 r->uri_ext = u + 1;
[1346]                 *u++ = ch;
[1347]                 break;
[1348]             case '+':
[1349]                 r->plus_in_uri = 1;
[1350]                 /* fall through */
[1351]             default:
[1352]                 *u++ = ch;
[1353]                 break;
[1354]             }
[1355] 
[1356]             ch = *p++;
[1357]             break;
[1358] 
[1359]         case sw_slash:
[1360] 
[1361]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1362]                 state = sw_usual;
[1363]                 *u++ = ch;
[1364]                 ch = *p++;
[1365]                 break;
[1366]             }
[1367] 
[1368]             switch (ch) {
[1369] #if (NGX_WIN32)
[1370]             case '\\':
[1371]                 break;
[1372] #endif
[1373]             case '/':
[1374]                 if (!merge_slashes) {
[1375]                     *u++ = ch;
[1376]                 }
[1377]                 break;
[1378]             case '.':
[1379]                 state = sw_dot;
[1380]                 *u++ = ch;
[1381]                 break;
[1382]             case '%':
[1383]                 quoted_state = state;
[1384]                 state = sw_quoted;
[1385]                 break;
[1386]             case '?':
[1387]                 r->args_start = p;
[1388]                 goto args;
[1389]             case '#':
[1390]                 goto done;
[1391]             case '+':
[1392]                 r->plus_in_uri = 1;
[1393]                 /* fall through */
[1394]             default:
[1395]                 state = sw_usual;
[1396]                 *u++ = ch;
[1397]                 break;
[1398]             }
[1399] 
[1400]             ch = *p++;
[1401]             break;
[1402] 
[1403]         case sw_dot:
[1404] 
[1405]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1406]                 state = sw_usual;
[1407]                 *u++ = ch;
[1408]                 ch = *p++;
[1409]                 break;
[1410]             }
[1411] 
[1412]             switch (ch) {
[1413] #if (NGX_WIN32)
[1414]             case '\\':
[1415] #endif
[1416]             case '/':
[1417]                 state = sw_slash;
[1418]                 u--;
[1419]                 break;
[1420]             case '.':
[1421]                 state = sw_dot_dot;
[1422]                 *u++ = ch;
[1423]                 break;
[1424]             case '%':
[1425]                 quoted_state = state;
[1426]                 state = sw_quoted;
[1427]                 break;
[1428]             case '?':
[1429]                 u--;
[1430]                 r->args_start = p;
[1431]                 goto args;
[1432]             case '#':
[1433]                 u--;
[1434]                 goto done;
[1435]             case '+':
[1436]                 r->plus_in_uri = 1;
[1437]                 /* fall through */
[1438]             default:
[1439]                 state = sw_usual;
[1440]                 *u++ = ch;
[1441]                 break;
[1442]             }
[1443] 
[1444]             ch = *p++;
[1445]             break;
[1446] 
[1447]         case sw_dot_dot:
[1448] 
[1449]             if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1450]                 state = sw_usual;
[1451]                 *u++ = ch;
[1452]                 ch = *p++;
[1453]                 break;
[1454]             }
[1455] 
[1456]             switch (ch) {
[1457] #if (NGX_WIN32)
[1458]             case '\\':
[1459] #endif
[1460]             case '/':
[1461]             case '?':
[1462]             case '#':
[1463]                 u -= 4;
[1464]                 for ( ;; ) {
[1465]                     if (u < r->uri.data) {
[1466]                         return NGX_HTTP_PARSE_INVALID_REQUEST;
[1467]                     }
[1468]                     if (*u == '/') {
[1469]                         u++;
[1470]                         break;
[1471]                     }
[1472]                     u--;
[1473]                 }
[1474]                 if (ch == '?') {
[1475]                     r->args_start = p;
[1476]                     goto args;
[1477]                 }
[1478]                 if (ch == '#') {
[1479]                     goto done;
[1480]                 }
[1481]                 state = sw_slash;
[1482]                 break;
[1483]             case '%':
[1484]                 quoted_state = state;
[1485]                 state = sw_quoted;
[1486]                 break;
[1487]             case '+':
[1488]                 r->plus_in_uri = 1;
[1489]                 /* fall through */
[1490]             default:
[1491]                 state = sw_usual;
[1492]                 *u++ = ch;
[1493]                 break;
[1494]             }
[1495] 
[1496]             ch = *p++;
[1497]             break;
[1498] 
[1499]         case sw_quoted:
[1500]             r->quoted_uri = 1;
[1501] 
[1502]             if (ch >= '0' && ch <= '9') {
[1503]                 decoded = (u_char) (ch - '0');
[1504]                 state = sw_quoted_second;
[1505]                 ch = *p++;
[1506]                 break;
[1507]             }
[1508] 
[1509]             c = (u_char) (ch | 0x20);
[1510]             if (c >= 'a' && c <= 'f') {
[1511]                 decoded = (u_char) (c - 'a' + 10);
[1512]                 state = sw_quoted_second;
[1513]                 ch = *p++;
[1514]                 break;
[1515]             }
[1516] 
[1517]             return NGX_HTTP_PARSE_INVALID_REQUEST;
[1518] 
[1519]         case sw_quoted_second:
[1520]             if (ch >= '0' && ch <= '9') {
[1521]                 ch = (u_char) ((decoded << 4) + (ch - '0'));
[1522] 
[1523]                 if (ch == '%' || ch == '#') {
[1524]                     state = sw_usual;
[1525]                     *u++ = ch;
[1526]                     ch = *p++;
[1527]                     break;
[1528] 
[1529]                 } else if (ch == '\0') {
[1530]                     return NGX_HTTP_PARSE_INVALID_REQUEST;
[1531]                 }
[1532] 
[1533]                 state = quoted_state;
[1534]                 break;
[1535]             }
[1536] 
[1537]             c = (u_char) (ch | 0x20);
[1538]             if (c >= 'a' && c <= 'f') {
[1539]                 ch = (u_char) ((decoded << 4) + (c - 'a') + 10);
[1540] 
[1541]                 if (ch == '?') {
[1542]                     state = sw_usual;
[1543]                     *u++ = ch;
[1544]                     ch = *p++;
[1545]                     break;
[1546] 
[1547]                 } else if (ch == '+') {
[1548]                     r->plus_in_uri = 1;
[1549]                 }
[1550] 
[1551]                 state = quoted_state;
[1552]                 break;
[1553]             }
[1554] 
[1555]             return NGX_HTTP_PARSE_INVALID_REQUEST;
[1556]         }
[1557]     }
[1558] 
[1559]     if (state == sw_quoted || state == sw_quoted_second) {
[1560]         return NGX_HTTP_PARSE_INVALID_REQUEST;
[1561]     }
[1562] 
[1563]     if (state == sw_dot) {
[1564]         u--;
[1565] 
[1566]     } else if (state == sw_dot_dot) {
[1567]         u -= 4;
[1568] 
[1569]         for ( ;; ) {
[1570]             if (u < r->uri.data) {
[1571]                 return NGX_HTTP_PARSE_INVALID_REQUEST;
[1572]             }
[1573] 
[1574]             if (*u == '/') {
[1575]                 u++;
[1576]                 break;
[1577]             }
[1578] 
[1579]             u--;
[1580]         }
[1581]     }
[1582] 
[1583] done:
[1584] 
[1585]     r->uri.len = u - r->uri.data;
[1586] 
[1587]     if (r->uri_ext) {
[1588]         r->exten.len = u - r->uri_ext;
[1589]         r->exten.data = r->uri_ext;
[1590]     }
[1591] 
[1592]     r->uri_ext = NULL;
[1593] 
[1594]     return NGX_OK;
[1595] 
[1596] args:
[1597] 
[1598]     while (p < r->uri_end) {
[1599]         if (*p++ != '#') {
[1600]             continue;
[1601]         }
[1602] 
[1603]         r->args.len = p - 1 - r->args_start;
[1604]         r->args.data = r->args_start;
[1605]         r->args_start = NULL;
[1606] 
[1607]         break;
[1608]     }
[1609] 
[1610]     r->uri.len = u - r->uri.data;
[1611] 
[1612]     if (r->uri_ext) {
[1613]         r->exten.len = u - r->uri_ext;
[1614]         r->exten.data = r->uri_ext;
[1615]     }
[1616] 
[1617]     r->uri_ext = NULL;
[1618] 
[1619]     return NGX_OK;
[1620] }
[1621] 
[1622] 
[1623] ngx_int_t
[1624] ngx_http_parse_status_line(ngx_http_request_t *r, ngx_buf_t *b,
[1625]     ngx_http_status_t *status)
[1626] {
[1627]     u_char   ch;
[1628]     u_char  *p;
[1629]     enum {
[1630]         sw_start = 0,
[1631]         sw_H,
[1632]         sw_HT,
[1633]         sw_HTT,
[1634]         sw_HTTP,
[1635]         sw_first_major_digit,
[1636]         sw_major_digit,
[1637]         sw_first_minor_digit,
[1638]         sw_minor_digit,
[1639]         sw_status,
[1640]         sw_space_after_status,
[1641]         sw_status_text,
[1642]         sw_almost_done
[1643]     } state;
[1644] 
[1645]     state = r->state;
[1646] 
[1647]     for (p = b->pos; p < b->last; p++) {
[1648]         ch = *p;
[1649] 
[1650]         switch (state) {
[1651] 
[1652]         /* "HTTP/" */
[1653]         case sw_start:
[1654]             switch (ch) {
[1655]             case 'H':
[1656]                 state = sw_H;
[1657]                 break;
[1658]             default:
[1659]                 return NGX_ERROR;
[1660]             }
[1661]             break;
[1662] 
[1663]         case sw_H:
[1664]             switch (ch) {
[1665]             case 'T':
[1666]                 state = sw_HT;
[1667]                 break;
[1668]             default:
[1669]                 return NGX_ERROR;
[1670]             }
[1671]             break;
[1672] 
[1673]         case sw_HT:
[1674]             switch (ch) {
[1675]             case 'T':
[1676]                 state = sw_HTT;
[1677]                 break;
[1678]             default:
[1679]                 return NGX_ERROR;
[1680]             }
[1681]             break;
[1682] 
[1683]         case sw_HTT:
[1684]             switch (ch) {
[1685]             case 'P':
[1686]                 state = sw_HTTP;
[1687]                 break;
[1688]             default:
[1689]                 return NGX_ERROR;
[1690]             }
[1691]             break;
[1692] 
[1693]         case sw_HTTP:
[1694]             switch (ch) {
[1695]             case '/':
[1696]                 state = sw_first_major_digit;
[1697]                 break;
[1698]             default:
[1699]                 return NGX_ERROR;
[1700]             }
[1701]             break;
[1702] 
[1703]         /* the first digit of major HTTP version */
[1704]         case sw_first_major_digit:
[1705]             if (ch < '1' || ch > '9') {
[1706]                 return NGX_ERROR;
[1707]             }
[1708] 
[1709]             r->http_major = ch - '0';
[1710]             state = sw_major_digit;
[1711]             break;
[1712] 
[1713]         /* the major HTTP version or dot */
[1714]         case sw_major_digit:
[1715]             if (ch == '.') {
[1716]                 state = sw_first_minor_digit;
[1717]                 break;
[1718]             }
[1719] 
[1720]             if (ch < '0' || ch > '9') {
[1721]                 return NGX_ERROR;
[1722]             }
[1723] 
[1724]             if (r->http_major > 99) {
[1725]                 return NGX_ERROR;
[1726]             }
[1727] 
[1728]             r->http_major = r->http_major * 10 + (ch - '0');
[1729]             break;
[1730] 
[1731]         /* the first digit of minor HTTP version */
[1732]         case sw_first_minor_digit:
[1733]             if (ch < '0' || ch > '9') {
[1734]                 return NGX_ERROR;
[1735]             }
[1736] 
[1737]             r->http_minor = ch - '0';
[1738]             state = sw_minor_digit;
[1739]             break;
[1740] 
[1741]         /* the minor HTTP version or the end of the request line */
[1742]         case sw_minor_digit:
[1743]             if (ch == ' ') {
[1744]                 state = sw_status;
[1745]                 break;
[1746]             }
[1747] 
[1748]             if (ch < '0' || ch > '9') {
[1749]                 return NGX_ERROR;
[1750]             }
[1751] 
[1752]             if (r->http_minor > 99) {
[1753]                 return NGX_ERROR;
[1754]             }
[1755] 
[1756]             r->http_minor = r->http_minor * 10 + (ch - '0');
[1757]             break;
[1758] 
[1759]         /* HTTP status code */
[1760]         case sw_status:
[1761]             if (ch == ' ') {
[1762]                 break;
[1763]             }
[1764] 
[1765]             if (ch < '0' || ch > '9') {
[1766]                 return NGX_ERROR;
[1767]             }
[1768] 
[1769]             status->code = status->code * 10 + (ch - '0');
[1770] 
[1771]             if (++status->count == 3) {
[1772]                 state = sw_space_after_status;
[1773]                 status->start = p - 2;
[1774]             }
[1775] 
[1776]             break;
[1777] 
[1778]         /* space or end of line */
[1779]         case sw_space_after_status:
[1780]             switch (ch) {
[1781]             case ' ':
[1782]                 state = sw_status_text;
[1783]                 break;
[1784]             case '.':                    /* IIS may send 403.1, 403.2, etc */
[1785]                 state = sw_status_text;
[1786]                 break;
[1787]             case CR:
[1788]                 state = sw_almost_done;
[1789]                 break;
[1790]             case LF:
[1791]                 goto done;
[1792]             default:
[1793]                 return NGX_ERROR;
[1794]             }
[1795]             break;
[1796] 
[1797]         /* any text until end of line */
[1798]         case sw_status_text:
[1799]             switch (ch) {
[1800]             case CR:
[1801]                 state = sw_almost_done;
[1802] 
[1803]                 break;
[1804]             case LF:
[1805]                 goto done;
[1806]             }
[1807]             break;
[1808] 
[1809]         /* end of status line */
[1810]         case sw_almost_done:
[1811]             status->end = p - 1;
[1812]             switch (ch) {
[1813]             case LF:
[1814]                 goto done;
[1815]             default:
[1816]                 return NGX_ERROR;
[1817]             }
[1818]         }
[1819]     }
[1820] 
[1821]     b->pos = p;
[1822]     r->state = state;
[1823] 
[1824]     return NGX_AGAIN;
[1825] 
[1826] done:
[1827] 
[1828]     b->pos = p + 1;
[1829] 
[1830]     if (status->end == NULL) {
[1831]         status->end = p;
[1832]     }
[1833] 
[1834]     status->http_version = r->http_major * 1000 + r->http_minor;
[1835]     r->state = sw_start;
[1836] 
[1837]     return NGX_OK;
[1838] }
[1839] 
[1840] 
[1841] ngx_int_t
[1842] ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
[1843]     ngx_str_t *args, ngx_uint_t *flags)
[1844] {
[1845]     u_char      ch, *p, *src, *dst;
[1846]     size_t      len;
[1847]     ngx_uint_t  quoted;
[1848] 
[1849]     len = uri->len;
[1850]     p = uri->data;
[1851]     quoted = 0;
[1852] 
[1853]     if (len == 0 || p[0] == '?') {
[1854]         goto unsafe;
[1855]     }
[1856] 
[1857]     if (p[0] == '.' && len > 1 && p[1] == '.'
[1858]         && (len == 2 || ngx_path_separator(p[2])))
[1859]     {
[1860]         goto unsafe;
[1861]     }
[1862] 
[1863]     for ( /* void */ ; len; len--) {
[1864] 
[1865]         ch = *p++;
[1866] 
[1867]         if (ch == '%') {
[1868]             quoted = 1;
[1869]             continue;
[1870]         }
[1871] 
[1872]         if (usual[ch >> 5] & (1U << (ch & 0x1f))) {
[1873]             continue;
[1874]         }
[1875] 
[1876]         if (ch == '?') {
[1877]             args->len = len - 1;
[1878]             args->data = p;
[1879]             uri->len -= len;
[1880] 
[1881]             break;
[1882]         }
[1883] 
[1884]         if (ch == '\0') {
[1885]             goto unsafe;
[1886]         }
[1887] 
[1888]         if (ngx_path_separator(ch) && len > 2) {
[1889] 
[1890]             /* detect "/../" and "/.." */
[1891] 
[1892]             if (p[0] == '.' && p[1] == '.'
[1893]                 && (len == 3 || ngx_path_separator(p[2])))
[1894]             {
[1895]                 goto unsafe;
[1896]             }
[1897]         }
[1898]     }
[1899] 
[1900]     if (quoted) {
[1901]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1902]                        "escaped URI: \"%V\"", uri);
[1903] 
[1904]         src = uri->data;
[1905] 
[1906]         dst = ngx_pnalloc(r->pool, uri->len);
[1907]         if (dst == NULL) {
[1908]             return NGX_ERROR;
[1909]         }
[1910] 
[1911]         uri->data = dst;
[1912] 
[1913]         ngx_unescape_uri(&dst, &src, uri->len, 0);
[1914] 
[1915]         uri->len = dst - uri->data;
[1916] 
[1917]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1918]                        "unescaped URI: \"%V\"", uri);
[1919] 
[1920]         len = uri->len;
[1921]         p = uri->data;
[1922] 
[1923]         if (p[0] == '.' && len > 1 && p[1] == '.'
[1924]             && (len == 2 || ngx_path_separator(p[2])))
[1925]         {
[1926]             goto unsafe;
[1927]         }
[1928] 
[1929]         for ( /* void */ ; len; len--) {
[1930] 
[1931]             ch = *p++;
[1932] 
[1933]             if (ch == '\0') {
[1934]                 goto unsafe;
[1935]             }
[1936] 
[1937]             if (ngx_path_separator(ch) && len > 2) {
[1938] 
[1939]                 /* detect "/../" and "/.." */
[1940] 
[1941]                 if (p[0] == '.' && p[1] == '.'
[1942]                     && (len == 3 || ngx_path_separator(p[2])))
[1943]                 {
[1944]                     goto unsafe;
[1945]                 }
[1946]             }
[1947]         }
[1948]     }
[1949] 
[1950]     return NGX_OK;
[1951] 
[1952] unsafe:
[1953] 
[1954]     if (*flags & NGX_HTTP_LOG_UNSAFE) {
[1955]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1956]                       "unsafe URI \"%V\" was detected", uri);
[1957]     }
[1958] 
[1959]     return NGX_ERROR;
[1960] }
[1961] 
[1962] 
[1963] ngx_table_elt_t *
[1964] ngx_http_parse_multi_header_lines(ngx_http_request_t *r,
[1965]     ngx_table_elt_t *headers, ngx_str_t *name, ngx_str_t *value)
[1966] {
[1967]     u_char           *start, *last, *end, ch;
[1968]     ngx_table_elt_t  *h;
[1969] 
[1970]     for (h = headers; h; h = h->next) {
[1971] 
[1972]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1973]                        "parse header: \"%V: %V\"", &h->key, &h->value);
[1974] 
[1975]         if (name->len > h->value.len) {
[1976]             continue;
[1977]         }
[1978] 
[1979]         start = h->value.data;
[1980]         end = h->value.data + h->value.len;
[1981] 
[1982]         while (start < end) {
[1983] 
[1984]             if (ngx_strncasecmp(start, name->data, name->len) != 0) {
[1985]                 goto skip;
[1986]             }
[1987] 
[1988]             for (start += name->len; start < end && *start == ' '; start++) {
[1989]                 /* void */
[1990]             }
[1991] 
[1992]             if (value == NULL) {
[1993]                 if (start == end || *start == ',') {
[1994]                     return h;
[1995]                 }
[1996] 
[1997]                 goto skip;
[1998]             }
[1999] 
[2000]             if (start == end || *start++ != '=') {
[2001]                 /* the invalid header value */
[2002]                 goto skip;
[2003]             }
[2004] 
[2005]             while (start < end && *start == ' ') { start++; }
[2006] 
[2007]             for (last = start; last < end && *last != ';'; last++) {
[2008]                 /* void */
[2009]             }
[2010] 
[2011]             value->len = last - start;
[2012]             value->data = start;
[2013] 
[2014]             return h;
[2015] 
[2016]         skip:
[2017] 
[2018]             while (start < end) {
[2019]                 ch = *start++;
[2020]                 if (ch == ';' || ch == ',') {
[2021]                     break;
[2022]                 }
[2023]             }
[2024] 
[2025]             while (start < end && *start == ' ') { start++; }
[2026]         }
[2027]     }
[2028] 
[2029]     return NULL;
[2030] }
[2031] 
[2032] 
[2033] ngx_table_elt_t *
[2034] ngx_http_parse_set_cookie_lines(ngx_http_request_t *r,
[2035]     ngx_table_elt_t *headers, ngx_str_t *name, ngx_str_t *value)
[2036] {
[2037]     u_char           *start, *last, *end;
[2038]     ngx_table_elt_t  *h;
[2039] 
[2040]     for (h = headers; h; h = h->next) {
[2041] 
[2042]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2043]                        "parse header: \"%V: %V\"", &h->key, &h->value);
[2044] 
[2045]         if (name->len >= h->value.len) {
[2046]             continue;
[2047]         }
[2048] 
[2049]         start = h->value.data;
[2050]         end = h->value.data + h->value.len;
[2051] 
[2052]         if (ngx_strncasecmp(start, name->data, name->len) != 0) {
[2053]             continue;
[2054]         }
[2055] 
[2056]         for (start += name->len; start < end && *start == ' '; start++) {
[2057]             /* void */
[2058]         }
[2059] 
[2060]         if (start == end || *start++ != '=') {
[2061]             /* the invalid header value */
[2062]             continue;
[2063]         }
[2064] 
[2065]         while (start < end && *start == ' ') { start++; }
[2066] 
[2067]         for (last = start; last < end && *last != ';'; last++) {
[2068]             /* void */
[2069]         }
[2070] 
[2071]         value->len = last - start;
[2072]         value->data = start;
[2073] 
[2074]         return h;
[2075]     }
[2076] 
[2077]     return NULL;
[2078] }
[2079] 
[2080] 
[2081] ngx_int_t
[2082] ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value)
[2083] {
[2084]     u_char  *p, *last;
[2085] 
[2086]     if (r->args.len == 0) {
[2087]         return NGX_DECLINED;
[2088]     }
[2089] 
[2090]     p = r->args.data;
[2091]     last = p + r->args.len;
[2092] 
[2093]     for ( /* void */ ; p < last; p++) {
[2094] 
[2095]         /* we need '=' after name, so drop one char from last */
[2096] 
[2097]         p = ngx_strlcasestrn(p, last - 1, name, len - 1);
[2098] 
[2099]         if (p == NULL) {
[2100]             return NGX_DECLINED;
[2101]         }
[2102] 
[2103]         if ((p == r->args.data || *(p - 1) == '&') && *(p + len) == '=') {
[2104] 
[2105]             value->data = p + len + 1;
[2106] 
[2107]             p = ngx_strlchr(p, last, '&');
[2108] 
[2109]             if (p == NULL) {
[2110]                 p = r->args.data + r->args.len;
[2111]             }
[2112] 
[2113]             value->len = p - value->data;
[2114] 
[2115]             return NGX_OK;
[2116]         }
[2117]     }
[2118] 
[2119]     return NGX_DECLINED;
[2120] }
[2121] 
[2122] 
[2123] void
[2124] ngx_http_split_args(ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *args)
[2125] {
[2126]     u_char  *p, *last;
[2127] 
[2128]     last = uri->data + uri->len;
[2129] 
[2130]     p = ngx_strlchr(uri->data, last, '?');
[2131] 
[2132]     if (p) {
[2133]         uri->len = p - uri->data;
[2134]         p++;
[2135]         args->len = last - p;
[2136]         args->data = p;
[2137] 
[2138]     } else {
[2139]         args->len = 0;
[2140]     }
[2141] }
[2142] 
[2143] 
[2144] ngx_int_t
[2145] ngx_http_parse_chunked(ngx_http_request_t *r, ngx_buf_t *b,
[2146]     ngx_http_chunked_t *ctx)
[2147] {
[2148]     u_char     *pos, ch, c;
[2149]     ngx_int_t   rc;
[2150]     enum {
[2151]         sw_chunk_start = 0,
[2152]         sw_chunk_size,
[2153]         sw_chunk_extension,
[2154]         sw_chunk_extension_almost_done,
[2155]         sw_chunk_data,
[2156]         sw_after_data,
[2157]         sw_after_data_almost_done,
[2158]         sw_last_chunk_extension,
[2159]         sw_last_chunk_extension_almost_done,
[2160]         sw_trailer,
[2161]         sw_trailer_almost_done,
[2162]         sw_trailer_header,
[2163]         sw_trailer_header_almost_done
[2164]     } state;
[2165] 
[2166]     state = ctx->state;
[2167] 
[2168]     if (state == sw_chunk_data && ctx->size == 0) {
[2169]         state = sw_after_data;
[2170]     }
[2171] 
[2172]     rc = NGX_AGAIN;
[2173] 
[2174]     for (pos = b->pos; pos < b->last; pos++) {
[2175] 
[2176]         ch = *pos;
[2177] 
[2178]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2179]                        "http chunked byte: %02Xd s:%d", ch, state);
[2180] 
[2181]         switch (state) {
[2182] 
[2183]         case sw_chunk_start:
[2184]             if (ch >= '0' && ch <= '9') {
[2185]                 state = sw_chunk_size;
[2186]                 ctx->size = ch - '0';
[2187]                 break;
[2188]             }
[2189] 
[2190]             c = (u_char) (ch | 0x20);
[2191] 
[2192]             if (c >= 'a' && c <= 'f') {
[2193]                 state = sw_chunk_size;
[2194]                 ctx->size = c - 'a' + 10;
[2195]                 break;
[2196]             }
[2197] 
[2198]             goto invalid;
[2199] 
[2200]         case sw_chunk_size:
[2201]             if (ctx->size > NGX_MAX_OFF_T_VALUE / 16) {
[2202]                 goto invalid;
[2203]             }
[2204] 
[2205]             if (ch >= '0' && ch <= '9') {
[2206]                 ctx->size = ctx->size * 16 + (ch - '0');
[2207]                 break;
[2208]             }
[2209] 
[2210]             c = (u_char) (ch | 0x20);
[2211] 
[2212]             if (c >= 'a' && c <= 'f') {
[2213]                 ctx->size = ctx->size * 16 + (c - 'a' + 10);
[2214]                 break;
[2215]             }
[2216] 
[2217]             if (ctx->size == 0) {
[2218] 
[2219]                 switch (ch) {
[2220]                 case CR:
[2221]                     state = sw_last_chunk_extension_almost_done;
[2222]                     break;
[2223]                 case LF:
[2224]                     state = sw_trailer;
[2225]                     break;
[2226]                 case ';':
[2227]                 case ' ':
[2228]                 case '\t':
[2229]                     state = sw_last_chunk_extension;
[2230]                     break;
[2231]                 default:
[2232]                     goto invalid;
[2233]                 }
[2234] 
[2235]                 break;
[2236]             }
[2237] 
[2238]             switch (ch) {
[2239]             case CR:
[2240]                 state = sw_chunk_extension_almost_done;
[2241]                 break;
[2242]             case LF:
[2243]                 state = sw_chunk_data;
[2244]                 break;
[2245]             case ';':
[2246]             case ' ':
[2247]             case '\t':
[2248]                 state = sw_chunk_extension;
[2249]                 break;
[2250]             default:
[2251]                 goto invalid;
[2252]             }
[2253] 
[2254]             break;
[2255] 
[2256]         case sw_chunk_extension:
[2257]             switch (ch) {
[2258]             case CR:
[2259]                 state = sw_chunk_extension_almost_done;
[2260]                 break;
[2261]             case LF:
[2262]                 state = sw_chunk_data;
[2263]             }
[2264]             break;
[2265] 
[2266]         case sw_chunk_extension_almost_done:
[2267]             if (ch == LF) {
[2268]                 state = sw_chunk_data;
[2269]                 break;
[2270]             }
[2271]             goto invalid;
[2272] 
[2273]         case sw_chunk_data:
[2274]             rc = NGX_OK;
[2275]             goto data;
[2276] 
[2277]         case sw_after_data:
[2278]             switch (ch) {
[2279]             case CR:
[2280]                 state = sw_after_data_almost_done;
[2281]                 break;
[2282]             case LF:
[2283]                 state = sw_chunk_start;
[2284]                 break;
[2285]             default:
[2286]                 goto invalid;
[2287]             }
[2288]             break;
[2289] 
[2290]         case sw_after_data_almost_done:
[2291]             if (ch == LF) {
[2292]                 state = sw_chunk_start;
[2293]                 break;
[2294]             }
[2295]             goto invalid;
[2296] 
[2297]         case sw_last_chunk_extension:
[2298]             switch (ch) {
[2299]             case CR:
[2300]                 state = sw_last_chunk_extension_almost_done;
[2301]                 break;
[2302]             case LF:
[2303]                 state = sw_trailer;
[2304]             }
[2305]             break;
[2306] 
[2307]         case sw_last_chunk_extension_almost_done:
[2308]             if (ch == LF) {
[2309]                 state = sw_trailer;
[2310]                 break;
[2311]             }
[2312]             goto invalid;
[2313] 
[2314]         case sw_trailer:
[2315]             switch (ch) {
[2316]             case CR:
[2317]                 state = sw_trailer_almost_done;
[2318]                 break;
[2319]             case LF:
[2320]                 goto done;
[2321]             default:
[2322]                 state = sw_trailer_header;
[2323]             }
[2324]             break;
[2325] 
[2326]         case sw_trailer_almost_done:
[2327]             if (ch == LF) {
[2328]                 goto done;
[2329]             }
[2330]             goto invalid;
[2331] 
[2332]         case sw_trailer_header:
[2333]             switch (ch) {
[2334]             case CR:
[2335]                 state = sw_trailer_header_almost_done;
[2336]                 break;
[2337]             case LF:
[2338]                 state = sw_trailer;
[2339]             }
[2340]             break;
[2341] 
[2342]         case sw_trailer_header_almost_done:
[2343]             if (ch == LF) {
[2344]                 state = sw_trailer;
[2345]                 break;
[2346]             }
[2347]             goto invalid;
[2348] 
[2349]         }
[2350]     }
[2351] 
[2352] data:
[2353] 
[2354]     ctx->state = state;
[2355]     b->pos = pos;
[2356] 
[2357]     if (ctx->size > NGX_MAX_OFF_T_VALUE - 5) {
[2358]         goto invalid;
[2359]     }
[2360] 
[2361]     switch (state) {
[2362] 
[2363]     case sw_chunk_start:
[2364]         ctx->length = 3 /* "0" LF LF */;
[2365]         break;
[2366]     case sw_chunk_size:
[2367]         ctx->length = 1 /* LF */
[2368]                       + (ctx->size ? ctx->size + 4 /* LF "0" LF LF */
[2369]                                    : 1 /* LF */);
[2370]         break;
[2371]     case sw_chunk_extension:
[2372]     case sw_chunk_extension_almost_done:
[2373]         ctx->length = 1 /* LF */ + ctx->size + 4 /* LF "0" LF LF */;
[2374]         break;
[2375]     case sw_chunk_data:
[2376]         ctx->length = ctx->size + 4 /* LF "0" LF LF */;
[2377]         break;
[2378]     case sw_after_data:
[2379]     case sw_after_data_almost_done:
[2380]         ctx->length = 4 /* LF "0" LF LF */;
[2381]         break;
[2382]     case sw_last_chunk_extension:
[2383]     case sw_last_chunk_extension_almost_done:
[2384]         ctx->length = 2 /* LF LF */;
[2385]         break;
[2386]     case sw_trailer:
[2387]     case sw_trailer_almost_done:
[2388]         ctx->length = 1 /* LF */;
[2389]         break;
[2390]     case sw_trailer_header:
[2391]     case sw_trailer_header_almost_done:
[2392]         ctx->length = 2 /* LF LF */;
[2393]         break;
[2394] 
[2395]     }
[2396] 
[2397]     return rc;
[2398] 
[2399] done:
[2400] 
[2401]     ctx->state = 0;
[2402]     b->pos = pos + 1;
[2403] 
[2404]     return NGX_DONE;
[2405] 
[2406] invalid:
[2407] 
[2408]     return NGX_ERROR;
[2409] }
