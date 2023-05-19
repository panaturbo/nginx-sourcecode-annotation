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
[12] static u_char *ngx_sprintf_num(u_char *buf, u_char *last, uint64_t ui64,
[13]     u_char zero, ngx_uint_t hexadecimal, ngx_uint_t width);
[14] static u_char *ngx_sprintf_str(u_char *buf, u_char *last, u_char *src,
[15]     size_t len, ngx_uint_t hexadecimal);
[16] static void ngx_encode_base64_internal(ngx_str_t *dst, ngx_str_t *src,
[17]     const u_char *basis, ngx_uint_t padding);
[18] static ngx_int_t ngx_decode_base64_internal(ngx_str_t *dst, ngx_str_t *src,
[19]     const u_char *basis);
[20] 
[21] 
[22] void
[23] ngx_strlow(u_char *dst, u_char *src, size_t n)
[24] {
[25]     while (n) {
[26]         *dst = ngx_tolower(*src);
[27]         dst++;
[28]         src++;
[29]         n--;
[30]     }
[31] }
[32] 
[33] 
[34] size_t
[35] ngx_strnlen(u_char *p, size_t n)
[36] {
[37]     size_t  i;
[38] 
[39]     for (i = 0; i < n; i++) {
[40] 
[41]         if (p[i] == '\0') {
[42]             return i;
[43]         }
[44]     }
[45] 
[46]     return n;
[47] }
[48] 
[49] 
[50] u_char *
[51] ngx_cpystrn(u_char *dst, u_char *src, size_t n)
[52] {
[53]     if (n == 0) {
[54]         return dst;
[55]     }
[56] 
[57]     while (--n) {
[58]         *dst = *src;
[59] 
[60]         if (*dst == '\0') {
[61]             return dst;
[62]         }
[63] 
[64]         dst++;
[65]         src++;
[66]     }
[67] 
[68]     *dst = '\0';
[69] 
[70]     return dst;
[71] }
[72] 
[73] 
[74] u_char *
[75] ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src)
[76] {
[77]     u_char  *dst;
[78] 
[79]     dst = ngx_pnalloc(pool, src->len);
[80]     if (dst == NULL) {
[81]         return NULL;
[82]     }
[83] 
[84]     ngx_memcpy(dst, src->data, src->len);
[85] 
[86]     return dst;
[87] }
[88] 
[89] 
[90] /*
[91]  * supported formats:
[92]  *    %[0][width][x][X]O        off_t
[93]  *    %[0][width]T              time_t
[94]  *    %[0][width][u][x|X]z      ssize_t/size_t
[95]  *    %[0][width][u][x|X]d      int/u_int
[96]  *    %[0][width][u][x|X]l      long
[97]  *    %[0][width|m][u][x|X]i    ngx_int_t/ngx_uint_t
[98]  *    %[0][width][u][x|X]D      int32_t/uint32_t
[99]  *    %[0][width][u][x|X]L      int64_t/uint64_t
[100]  *    %[0][width|m][u][x|X]A    ngx_atomic_int_t/ngx_atomic_uint_t
[101]  *    %[0][width][.width]f      double, max valid number fits to %18.15f
[102]  *    %P                        ngx_pid_t
[103]  *    %M                        ngx_msec_t
[104]  *    %r                        rlim_t
[105]  *    %p                        void *
[106]  *    %[x|X]V                   ngx_str_t *
[107]  *    %[x|X]v                   ngx_variable_value_t *
[108]  *    %[x|X]s                   null-terminated string
[109]  *    %*[x|X]s                  length and string
[110]  *    %Z                        '\0'
[111]  *    %N                        '\n'
[112]  *    %c                        char
[113]  *    %%                        %
[114]  *
[115]  *  reserved:
[116]  *    %t                        ptrdiff_t
[117]  *    %S                        null-terminated wchar string
[118]  *    %C                        wchar
[119]  */
[120] 
[121] 
[122] u_char * ngx_cdecl
[123] ngx_sprintf(u_char *buf, const char *fmt, ...)
[124] {
[125]     u_char   *p;
[126]     va_list   args;
[127] 
[128]     va_start(args, fmt);
[129]     p = ngx_vslprintf(buf, (void *) -1, fmt, args);
[130]     va_end(args);
[131] 
[132]     return p;
[133] }
[134] 
[135] 
[136] u_char * ngx_cdecl
[137] ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...)
[138] {
[139]     u_char   *p;
[140]     va_list   args;
[141] 
[142]     va_start(args, fmt);
[143]     p = ngx_vslprintf(buf, buf + max, fmt, args);
[144]     va_end(args);
[145] 
[146]     return p;
[147] }
[148] 
[149] 
[150] u_char * ngx_cdecl
[151] ngx_slprintf(u_char *buf, u_char *last, const char *fmt, ...)
[152] {
[153]     u_char   *p;
[154]     va_list   args;
[155] 
[156]     va_start(args, fmt);
[157]     p = ngx_vslprintf(buf, last, fmt, args);
[158]     va_end(args);
[159] 
[160]     return p;
[161] }
[162] 
[163] 
[164] u_char *
[165] ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args)
[166] {
[167]     u_char                *p, zero;
[168]     int                    d;
[169]     double                 f;
[170]     size_t                 slen;
[171]     int64_t                i64;
[172]     uint64_t               ui64, frac;
[173]     ngx_msec_t             ms;
[174]     ngx_uint_t             width, sign, hex, max_width, frac_width, scale, n;
[175]     ngx_str_t             *v;
[176]     ngx_variable_value_t  *vv;
[177] 
[178]     while (*fmt && buf < last) {
[179] 
[180]         /*
[181]          * "buf < last" means that we could copy at least one character:
[182]          * the plain character, "%%", "%c", and minus without the checking
[183]          */
[184] 
[185]         if (*fmt == '%') {
[186] 
[187]             i64 = 0;
[188]             ui64 = 0;
[189] 
[190]             zero = (u_char) ((*++fmt == '0') ? '0' : ' ');
[191]             width = 0;
[192]             sign = 1;
[193]             hex = 0;
[194]             max_width = 0;
[195]             frac_width = 0;
[196]             slen = (size_t) -1;
[197] 
[198]             while (*fmt >= '0' && *fmt <= '9') {
[199]                 width = width * 10 + (*fmt++ - '0');
[200]             }
[201] 
[202] 
[203]             for ( ;; ) {
[204]                 switch (*fmt) {
[205] 
[206]                 case 'u':
[207]                     sign = 0;
[208]                     fmt++;
[209]                     continue;
[210] 
[211]                 case 'm':
[212]                     max_width = 1;
[213]                     fmt++;
[214]                     continue;
[215] 
[216]                 case 'X':
[217]                     hex = 2;
[218]                     sign = 0;
[219]                     fmt++;
[220]                     continue;
[221] 
[222]                 case 'x':
[223]                     hex = 1;
[224]                     sign = 0;
[225]                     fmt++;
[226]                     continue;
[227] 
[228]                 case '.':
[229]                     fmt++;
[230] 
[231]                     while (*fmt >= '0' && *fmt <= '9') {
[232]                         frac_width = frac_width * 10 + (*fmt++ - '0');
[233]                     }
[234] 
[235]                     break;
[236] 
[237]                 case '*':
[238]                     slen = va_arg(args, size_t);
[239]                     fmt++;
[240]                     continue;
[241] 
[242]                 default:
[243]                     break;
[244]                 }
[245] 
[246]                 break;
[247]             }
[248] 
[249] 
[250]             switch (*fmt) {
[251] 
[252]             case 'V':
[253]                 v = va_arg(args, ngx_str_t *);
[254] 
[255]                 buf = ngx_sprintf_str(buf, last, v->data, v->len, hex);
[256]                 fmt++;
[257] 
[258]                 continue;
[259] 
[260]             case 'v':
[261]                 vv = va_arg(args, ngx_variable_value_t *);
[262] 
[263]                 buf = ngx_sprintf_str(buf, last, vv->data, vv->len, hex);
[264]                 fmt++;
[265] 
[266]                 continue;
[267] 
[268]             case 's':
[269]                 p = va_arg(args, u_char *);
[270] 
[271]                 buf = ngx_sprintf_str(buf, last, p, slen, hex);
[272]                 fmt++;
[273] 
[274]                 continue;
[275] 
[276]             case 'O':
[277]                 i64 = (int64_t) va_arg(args, off_t);
[278]                 sign = 1;
[279]                 break;
[280] 
[281]             case 'P':
[282]                 i64 = (int64_t) va_arg(args, ngx_pid_t);
[283]                 sign = 1;
[284]                 break;
[285] 
[286]             case 'T':
[287]                 i64 = (int64_t) va_arg(args, time_t);
[288]                 sign = 1;
[289]                 break;
[290] 
[291]             case 'M':
[292]                 ms = (ngx_msec_t) va_arg(args, ngx_msec_t);
[293]                 if ((ngx_msec_int_t) ms == -1) {
[294]                     sign = 1;
[295]                     i64 = -1;
[296]                 } else {
[297]                     sign = 0;
[298]                     ui64 = (uint64_t) ms;
[299]                 }
[300]                 break;
[301] 
[302]             case 'z':
[303]                 if (sign) {
[304]                     i64 = (int64_t) va_arg(args, ssize_t);
[305]                 } else {
[306]                     ui64 = (uint64_t) va_arg(args, size_t);
[307]                 }
[308]                 break;
[309] 
[310]             case 'i':
[311]                 if (sign) {
[312]                     i64 = (int64_t) va_arg(args, ngx_int_t);
[313]                 } else {
[314]                     ui64 = (uint64_t) va_arg(args, ngx_uint_t);
[315]                 }
[316] 
[317]                 if (max_width) {
[318]                     width = NGX_INT_T_LEN;
[319]                 }
[320] 
[321]                 break;
[322] 
[323]             case 'd':
[324]                 if (sign) {
[325]                     i64 = (int64_t) va_arg(args, int);
[326]                 } else {
[327]                     ui64 = (uint64_t) va_arg(args, u_int);
[328]                 }
[329]                 break;
[330] 
[331]             case 'l':
[332]                 if (sign) {
[333]                     i64 = (int64_t) va_arg(args, long);
[334]                 } else {
[335]                     ui64 = (uint64_t) va_arg(args, u_long);
[336]                 }
[337]                 break;
[338] 
[339]             case 'D':
[340]                 if (sign) {
[341]                     i64 = (int64_t) va_arg(args, int32_t);
[342]                 } else {
[343]                     ui64 = (uint64_t) va_arg(args, uint32_t);
[344]                 }
[345]                 break;
[346] 
[347]             case 'L':
[348]                 if (sign) {
[349]                     i64 = va_arg(args, int64_t);
[350]                 } else {
[351]                     ui64 = va_arg(args, uint64_t);
[352]                 }
[353]                 break;
[354] 
[355]             case 'A':
[356]                 if (sign) {
[357]                     i64 = (int64_t) va_arg(args, ngx_atomic_int_t);
[358]                 } else {
[359]                     ui64 = (uint64_t) va_arg(args, ngx_atomic_uint_t);
[360]                 }
[361] 
[362]                 if (max_width) {
[363]                     width = NGX_ATOMIC_T_LEN;
[364]                 }
[365] 
[366]                 break;
[367] 
[368]             case 'f':
[369]                 f = va_arg(args, double);
[370] 
[371]                 if (f < 0) {
[372]                     *buf++ = '-';
[373]                     f = -f;
[374]                 }
[375] 
[376]                 ui64 = (int64_t) f;
[377]                 frac = 0;
[378] 
[379]                 if (frac_width) {
[380] 
[381]                     scale = 1;
[382]                     for (n = frac_width; n; n--) {
[383]                         scale *= 10;
[384]                     }
[385] 
[386]                     frac = (uint64_t) ((f - (double) ui64) * scale + 0.5);
[387] 
[388]                     if (frac == scale) {
[389]                         ui64++;
[390]                         frac = 0;
[391]                     }
[392]                 }
[393] 
[394]                 buf = ngx_sprintf_num(buf, last, ui64, zero, 0, width);
[395] 
[396]                 if (frac_width) {
[397]                     if (buf < last) {
[398]                         *buf++ = '.';
[399]                     }
[400] 
[401]                     buf = ngx_sprintf_num(buf, last, frac, '0', 0, frac_width);
[402]                 }
[403] 
[404]                 fmt++;
[405] 
[406]                 continue;
[407] 
[408] #if !(NGX_WIN32)
[409]             case 'r':
[410]                 i64 = (int64_t) va_arg(args, rlim_t);
[411]                 sign = 1;
[412]                 break;
[413] #endif
[414] 
[415]             case 'p':
[416]                 ui64 = (uintptr_t) va_arg(args, void *);
[417]                 hex = 2;
[418]                 sign = 0;
[419]                 zero = '0';
[420]                 width = 2 * sizeof(void *);
[421]                 break;
[422] 
[423]             case 'c':
[424]                 d = va_arg(args, int);
[425]                 *buf++ = (u_char) (d & 0xff);
[426]                 fmt++;
[427] 
[428]                 continue;
[429] 
[430]             case 'Z':
[431]                 *buf++ = '\0';
[432]                 fmt++;
[433] 
[434]                 continue;
[435] 
[436]             case 'N':
[437] #if (NGX_WIN32)
[438]                 *buf++ = CR;
[439]                 if (buf < last) {
[440]                     *buf++ = LF;
[441]                 }
[442] #else
[443]                 *buf++ = LF;
[444] #endif
[445]                 fmt++;
[446] 
[447]                 continue;
[448] 
[449]             case '%':
[450]                 *buf++ = '%';
[451]                 fmt++;
[452] 
[453]                 continue;
[454] 
[455]             default:
[456]                 *buf++ = *fmt++;
[457] 
[458]                 continue;
[459]             }
[460] 
[461]             if (sign) {
[462]                 if (i64 < 0) {
[463]                     *buf++ = '-';
[464]                     ui64 = (uint64_t) -i64;
[465] 
[466]                 } else {
[467]                     ui64 = (uint64_t) i64;
[468]                 }
[469]             }
[470] 
[471]             buf = ngx_sprintf_num(buf, last, ui64, zero, hex, width);
[472] 
[473]             fmt++;
[474] 
[475]         } else {
[476]             *buf++ = *fmt++;
[477]         }
[478]     }
[479] 
[480]     return buf;
[481] }
[482] 
[483] 
[484] static u_char *
[485] ngx_sprintf_num(u_char *buf, u_char *last, uint64_t ui64, u_char zero,
[486]     ngx_uint_t hexadecimal, ngx_uint_t width)
[487] {
[488]     u_char         *p, temp[NGX_INT64_LEN + 1];
[489]                        /*
[490]                         * we need temp[NGX_INT64_LEN] only,
[491]                         * but icc issues the warning
[492]                         */
[493]     size_t          len;
[494]     uint32_t        ui32;
[495]     static u_char   hex[] = "0123456789abcdef";
[496]     static u_char   HEX[] = "0123456789ABCDEF";
[497] 
[498]     p = temp + NGX_INT64_LEN;
[499] 
[500]     if (hexadecimal == 0) {
[501] 
[502]         if (ui64 <= (uint64_t) NGX_MAX_UINT32_VALUE) {
[503] 
[504]             /*
[505]              * To divide 64-bit numbers and to find remainders
[506]              * on the x86 platform gcc and icc call the libc functions
[507]              * [u]divdi3() and [u]moddi3(), they call another function
[508]              * in its turn.  On FreeBSD it is the qdivrem() function,
[509]              * its source code is about 170 lines of the code.
[510]              * The glibc counterpart is about 150 lines of the code.
[511]              *
[512]              * For 32-bit numbers and some divisors gcc and icc use
[513]              * a inlined multiplication and shifts.  For example,
[514]              * unsigned "i32 / 10" is compiled to
[515]              *
[516]              *     (i32 * 0xCCCCCCCD) >> 35
[517]              */
[518] 
[519]             ui32 = (uint32_t) ui64;
[520] 
[521]             do {
[522]                 *--p = (u_char) (ui32 % 10 + '0');
[523]             } while (ui32 /= 10);
[524] 
[525]         } else {
[526]             do {
[527]                 *--p = (u_char) (ui64 % 10 + '0');
[528]             } while (ui64 /= 10);
[529]         }
[530] 
[531]     } else if (hexadecimal == 1) {
[532] 
[533]         do {
[534] 
[535]             /* the "(uint32_t)" cast disables the BCC's warning */
[536]             *--p = hex[(uint32_t) (ui64 & 0xf)];
[537] 
[538]         } while (ui64 >>= 4);
[539] 
[540]     } else { /* hexadecimal == 2 */
[541] 
[542]         do {
[543] 
[544]             /* the "(uint32_t)" cast disables the BCC's warning */
[545]             *--p = HEX[(uint32_t) (ui64 & 0xf)];
[546] 
[547]         } while (ui64 >>= 4);
[548]     }
[549] 
[550]     /* zero or space padding */
[551] 
[552]     len = (temp + NGX_INT64_LEN) - p;
[553] 
[554]     while (len++ < width && buf < last) {
[555]         *buf++ = zero;
[556]     }
[557] 
[558]     /* number safe copy */
[559] 
[560]     len = (temp + NGX_INT64_LEN) - p;
[561] 
[562]     if (buf + len > last) {
[563]         len = last - buf;
[564]     }
[565] 
[566]     return ngx_cpymem(buf, p, len);
[567] }
[568] 
[569] 
[570] static u_char *
[571] ngx_sprintf_str(u_char *buf, u_char *last, u_char *src, size_t len,
[572]     ngx_uint_t hexadecimal)
[573] {
[574]     static u_char   hex[] = "0123456789abcdef";
[575]     static u_char   HEX[] = "0123456789ABCDEF";
[576] 
[577]     if (hexadecimal == 0) {
[578] 
[579]         if (len == (size_t) -1) {
[580]             while (*src && buf < last) {
[581]                 *buf++ = *src++;
[582]             }
[583] 
[584]         } else {
[585]             len = ngx_min((size_t) (last - buf), len);
[586]             buf = ngx_cpymem(buf, src, len);
[587]         }
[588] 
[589]     } else if (hexadecimal == 1) {
[590] 
[591]         if (len == (size_t) -1) {
[592] 
[593]             while (*src && buf < last - 1) {
[594]                 *buf++ = hex[*src >> 4];
[595]                 *buf++ = hex[*src++ & 0xf];
[596]             }
[597] 
[598]         } else {
[599] 
[600]             while (len-- && buf < last - 1) {
[601]                 *buf++ = hex[*src >> 4];
[602]                 *buf++ = hex[*src++ & 0xf];
[603]             }
[604]         }
[605] 
[606]     } else { /* hexadecimal == 2 */
[607] 
[608]         if (len == (size_t) -1) {
[609] 
[610]             while (*src && buf < last - 1) {
[611]                 *buf++ = HEX[*src >> 4];
[612]                 *buf++ = HEX[*src++ & 0xf];
[613]             }
[614] 
[615]         } else {
[616] 
[617]             while (len-- && buf < last - 1) {
[618]                 *buf++ = HEX[*src >> 4];
[619]                 *buf++ = HEX[*src++ & 0xf];
[620]             }
[621]         }
[622]     }
[623] 
[624]     return buf;
[625] }
[626] 
[627] 
[628] /*
[629]  * We use ngx_strcasecmp()/ngx_strncasecmp() for 7-bit ASCII strings only,
[630]  * and implement our own ngx_strcasecmp()/ngx_strncasecmp()
[631]  * to avoid libc locale overhead.  Besides, we use the ngx_uint_t's
[632]  * instead of the u_char's, because they are slightly faster.
[633]  */
[634] 
[635] ngx_int_t
[636] ngx_strcasecmp(u_char *s1, u_char *s2)
[637] {
[638]     ngx_uint_t  c1, c2;
[639] 
[640]     for ( ;; ) {
[641]         c1 = (ngx_uint_t) *s1++;
[642]         c2 = (ngx_uint_t) *s2++;
[643] 
[644]         c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
[645]         c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
[646] 
[647]         if (c1 == c2) {
[648] 
[649]             if (c1) {
[650]                 continue;
[651]             }
[652] 
[653]             return 0;
[654]         }
[655] 
[656]         return c1 - c2;
[657]     }
[658] }
[659] 
[660] 
[661] ngx_int_t
[662] ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
[663] {
[664]     ngx_uint_t  c1, c2;
[665] 
[666]     while (n) {
[667]         c1 = (ngx_uint_t) *s1++;
[668]         c2 = (ngx_uint_t) *s2++;
[669] 
[670]         c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
[671]         c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
[672] 
[673]         if (c1 == c2) {
[674] 
[675]             if (c1) {
[676]                 n--;
[677]                 continue;
[678]             }
[679] 
[680]             return 0;
[681]         }
[682] 
[683]         return c1 - c2;
[684]     }
[685] 
[686]     return 0;
[687] }
[688] 
[689] 
[690] u_char *
[691] ngx_strnstr(u_char *s1, char *s2, size_t len)
[692] {
[693]     u_char  c1, c2;
[694]     size_t  n;
[695] 
[696]     c2 = *(u_char *) s2++;
[697] 
[698]     n = ngx_strlen(s2);
[699] 
[700]     do {
[701]         do {
[702]             if (len-- == 0) {
[703]                 return NULL;
[704]             }
[705] 
[706]             c1 = *s1++;
[707] 
[708]             if (c1 == 0) {
[709]                 return NULL;
[710]             }
[711] 
[712]         } while (c1 != c2);
[713] 
[714]         if (n > len) {
[715]             return NULL;
[716]         }
[717] 
[718]     } while (ngx_strncmp(s1, (u_char *) s2, n) != 0);
[719] 
[720]     return --s1;
[721] }
[722] 
[723] 
[724] /*
[725]  * ngx_strstrn() and ngx_strcasestrn() are intended to search for static
[726]  * substring with known length in null-terminated string. The argument n
[727]  * must be length of the second substring - 1.
[728]  */
[729] 
[730] u_char *
[731] ngx_strstrn(u_char *s1, char *s2, size_t n)
[732] {
[733]     u_char  c1, c2;
[734] 
[735]     c2 = *(u_char *) s2++;
[736] 
[737]     do {
[738]         do {
[739]             c1 = *s1++;
[740] 
[741]             if (c1 == 0) {
[742]                 return NULL;
[743]             }
[744] 
[745]         } while (c1 != c2);
[746] 
[747]     } while (ngx_strncmp(s1, (u_char *) s2, n) != 0);
[748] 
[749]     return --s1;
[750] }
[751] 
[752] 
[753] u_char *
[754] ngx_strcasestrn(u_char *s1, char *s2, size_t n)
[755] {
[756]     ngx_uint_t  c1, c2;
[757] 
[758]     c2 = (ngx_uint_t) *s2++;
[759]     c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
[760] 
[761]     do {
[762]         do {
[763]             c1 = (ngx_uint_t) *s1++;
[764] 
[765]             if (c1 == 0) {
[766]                 return NULL;
[767]             }
[768] 
[769]             c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
[770] 
[771]         } while (c1 != c2);
[772] 
[773]     } while (ngx_strncasecmp(s1, (u_char *) s2, n) != 0);
[774] 
[775]     return --s1;
[776] }
[777] 
[778] 
[779] /*
[780]  * ngx_strlcasestrn() is intended to search for static substring
[781]  * with known length in string until the argument last. The argument n
[782]  * must be length of the second substring - 1.
[783]  */
[784] 
[785] u_char *
[786] ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n)
[787] {
[788]     ngx_uint_t  c1, c2;
[789] 
[790]     c2 = (ngx_uint_t) *s2++;
[791]     c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
[792]     last -= n;
[793] 
[794]     do {
[795]         do {
[796]             if (s1 >= last) {
[797]                 return NULL;
[798]             }
[799] 
[800]             c1 = (ngx_uint_t) *s1++;
[801] 
[802]             c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
[803] 
[804]         } while (c1 != c2);
[805] 
[806]     } while (ngx_strncasecmp(s1, s2, n) != 0);
[807] 
[808]     return --s1;
[809] }
[810] 
[811] 
[812] ngx_int_t
[813] ngx_rstrncmp(u_char *s1, u_char *s2, size_t n)
[814] {
[815]     if (n == 0) {
[816]         return 0;
[817]     }
[818] 
[819]     n--;
[820] 
[821]     for ( ;; ) {
[822]         if (s1[n] != s2[n]) {
[823]             return s1[n] - s2[n];
[824]         }
[825] 
[826]         if (n == 0) {
[827]             return 0;
[828]         }
[829] 
[830]         n--;
[831]     }
[832] }
[833] 
[834] 
[835] ngx_int_t
[836] ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n)
[837] {
[838]     u_char  c1, c2;
[839] 
[840]     if (n == 0) {
[841]         return 0;
[842]     }
[843] 
[844]     n--;
[845] 
[846]     for ( ;; ) {
[847]         c1 = s1[n];
[848]         if (c1 >= 'a' && c1 <= 'z') {
[849]             c1 -= 'a' - 'A';
[850]         }
[851] 
[852]         c2 = s2[n];
[853]         if (c2 >= 'a' && c2 <= 'z') {
[854]             c2 -= 'a' - 'A';
[855]         }
[856] 
[857]         if (c1 != c2) {
[858]             return c1 - c2;
[859]         }
[860] 
[861]         if (n == 0) {
[862]             return 0;
[863]         }
[864] 
[865]         n--;
[866]     }
[867] }
[868] 
[869] 
[870] ngx_int_t
[871] ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2)
[872] {
[873]     size_t     n;
[874]     ngx_int_t  m, z;
[875] 
[876]     if (n1 <= n2) {
[877]         n = n1;
[878]         z = -1;
[879] 
[880]     } else {
[881]         n = n2;
[882]         z = 1;
[883]     }
[884] 
[885]     m = ngx_memcmp(s1, s2, n);
[886] 
[887]     if (m || n1 == n2) {
[888]         return m;
[889]     }
[890] 
[891]     return z;
[892] }
[893] 
[894] 
[895] ngx_int_t
[896] ngx_dns_strcmp(u_char *s1, u_char *s2)
[897] {
[898]     ngx_uint_t  c1, c2;
[899] 
[900]     for ( ;; ) {
[901]         c1 = (ngx_uint_t) *s1++;
[902]         c2 = (ngx_uint_t) *s2++;
[903] 
[904]         c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
[905]         c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;
[906] 
[907]         if (c1 == c2) {
[908] 
[909]             if (c1) {
[910]                 continue;
[911]             }
[912] 
[913]             return 0;
[914]         }
[915] 
[916]         /* in ASCII '.' > '-', but we need '.' to be the lowest character */
[917] 
[918]         c1 = (c1 == '.') ? ' ' : c1;
[919]         c2 = (c2 == '.') ? ' ' : c2;
[920] 
[921]         return c1 - c2;
[922]     }
[923] }
[924] 
[925] 
[926] ngx_int_t
[927] ngx_filename_cmp(u_char *s1, u_char *s2, size_t n)
[928] {
[929]     ngx_uint_t  c1, c2;
[930] 
[931]     while (n) {
[932]         c1 = (ngx_uint_t) *s1++;
[933]         c2 = (ngx_uint_t) *s2++;
[934] 
[935] #if (NGX_HAVE_CASELESS_FILESYSTEM)
[936]         c1 = tolower(c1);
[937]         c2 = tolower(c2);
[938] #endif
[939] 
[940]         if (c1 == c2) {
[941] 
[942]             if (c1) {
[943]                 n--;
[944]                 continue;
[945]             }
[946] 
[947]             return 0;
[948]         }
[949] 
[950]         /* we need '/' to be the lowest character */
[951] 
[952]         if (c1 == 0 || c2 == 0) {
[953]             return c1 - c2;
[954]         }
[955] 
[956]         c1 = (c1 == '/') ? 0 : c1;
[957]         c2 = (c2 == '/') ? 0 : c2;
[958] 
[959]         return c1 - c2;
[960]     }
[961] 
[962]     return 0;
[963] }
[964] 
[965] 
[966] ngx_int_t
[967] ngx_atoi(u_char *line, size_t n)
[968] {
[969]     ngx_int_t  value, cutoff, cutlim;
[970] 
[971]     if (n == 0) {
[972]         return NGX_ERROR;
[973]     }
[974] 
[975]     cutoff = NGX_MAX_INT_T_VALUE / 10;
[976]     cutlim = NGX_MAX_INT_T_VALUE % 10;
[977] 
[978]     for (value = 0; n--; line++) {
[979]         if (*line < '0' || *line > '9') {
[980]             return NGX_ERROR;
[981]         }
[982] 
[983]         if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
[984]             return NGX_ERROR;
[985]         }
[986] 
[987]         value = value * 10 + (*line - '0');
[988]     }
[989] 
[990]     return value;
[991] }
[992] 
[993] 
[994] /* parse a fixed point number, e.g., ngx_atofp("10.5", 4, 2) returns 1050 */
[995] 
[996] ngx_int_t
[997] ngx_atofp(u_char *line, size_t n, size_t point)
[998] {
[999]     ngx_int_t   value, cutoff, cutlim;
[1000]     ngx_uint_t  dot;
[1001] 
[1002]     if (n == 0) {
[1003]         return NGX_ERROR;
[1004]     }
[1005] 
[1006]     cutoff = NGX_MAX_INT_T_VALUE / 10;
[1007]     cutlim = NGX_MAX_INT_T_VALUE % 10;
[1008] 
[1009]     dot = 0;
[1010] 
[1011]     for (value = 0; n--; line++) {
[1012] 
[1013]         if (point == 0) {
[1014]             return NGX_ERROR;
[1015]         }
[1016] 
[1017]         if (*line == '.') {
[1018]             if (dot) {
[1019]                 return NGX_ERROR;
[1020]             }
[1021] 
[1022]             dot = 1;
[1023]             continue;
[1024]         }
[1025] 
[1026]         if (*line < '0' || *line > '9') {
[1027]             return NGX_ERROR;
[1028]         }
[1029] 
[1030]         if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
[1031]             return NGX_ERROR;
[1032]         }
[1033] 
[1034]         value = value * 10 + (*line - '0');
[1035]         point -= dot;
[1036]     }
[1037] 
[1038]     while (point--) {
[1039]         if (value > cutoff) {
[1040]             return NGX_ERROR;
[1041]         }
[1042] 
[1043]         value = value * 10;
[1044]     }
[1045] 
[1046]     return value;
[1047] }
[1048] 
[1049] 
[1050] ssize_t
[1051] ngx_atosz(u_char *line, size_t n)
[1052] {
[1053]     ssize_t  value, cutoff, cutlim;
[1054] 
[1055]     if (n == 0) {
[1056]         return NGX_ERROR;
[1057]     }
[1058] 
[1059]     cutoff = NGX_MAX_SIZE_T_VALUE / 10;
[1060]     cutlim = NGX_MAX_SIZE_T_VALUE % 10;
[1061] 
[1062]     for (value = 0; n--; line++) {
[1063]         if (*line < '0' || *line > '9') {
[1064]             return NGX_ERROR;
[1065]         }
[1066] 
[1067]         if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
[1068]             return NGX_ERROR;
[1069]         }
[1070] 
[1071]         value = value * 10 + (*line - '0');
[1072]     }
[1073] 
[1074]     return value;
[1075] }
[1076] 
[1077] 
[1078] off_t
[1079] ngx_atoof(u_char *line, size_t n)
[1080] {
[1081]     off_t  value, cutoff, cutlim;
[1082] 
[1083]     if (n == 0) {
[1084]         return NGX_ERROR;
[1085]     }
[1086] 
[1087]     cutoff = NGX_MAX_OFF_T_VALUE / 10;
[1088]     cutlim = NGX_MAX_OFF_T_VALUE % 10;
[1089] 
[1090]     for (value = 0; n--; line++) {
[1091]         if (*line < '0' || *line > '9') {
[1092]             return NGX_ERROR;
[1093]         }
[1094] 
[1095]         if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
[1096]             return NGX_ERROR;
[1097]         }
[1098] 
[1099]         value = value * 10 + (*line - '0');
[1100]     }
[1101] 
[1102]     return value;
[1103] }
[1104] 
[1105] 
[1106] time_t
[1107] ngx_atotm(u_char *line, size_t n)
[1108] {
[1109]     time_t  value, cutoff, cutlim;
[1110] 
[1111]     if (n == 0) {
[1112]         return NGX_ERROR;
[1113]     }
[1114] 
[1115]     cutoff = NGX_MAX_TIME_T_VALUE / 10;
[1116]     cutlim = NGX_MAX_TIME_T_VALUE % 10;
[1117] 
[1118]     for (value = 0; n--; line++) {
[1119]         if (*line < '0' || *line > '9') {
[1120]             return NGX_ERROR;
[1121]         }
[1122] 
[1123]         if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
[1124]             return NGX_ERROR;
[1125]         }
[1126] 
[1127]         value = value * 10 + (*line - '0');
[1128]     }
[1129] 
[1130]     return value;
[1131] }
[1132] 
[1133] 
[1134] ngx_int_t
[1135] ngx_hextoi(u_char *line, size_t n)
[1136] {
[1137]     u_char     c, ch;
[1138]     ngx_int_t  value, cutoff;
[1139] 
[1140]     if (n == 0) {
[1141]         return NGX_ERROR;
[1142]     }
[1143] 
[1144]     cutoff = NGX_MAX_INT_T_VALUE / 16;
[1145] 
[1146]     for (value = 0; n--; line++) {
[1147]         if (value > cutoff) {
[1148]             return NGX_ERROR;
[1149]         }
[1150] 
[1151]         ch = *line;
[1152] 
[1153]         if (ch >= '0' && ch <= '9') {
[1154]             value = value * 16 + (ch - '0');
[1155]             continue;
[1156]         }
[1157] 
[1158]         c = (u_char) (ch | 0x20);
[1159] 
[1160]         if (c >= 'a' && c <= 'f') {
[1161]             value = value * 16 + (c - 'a' + 10);
[1162]             continue;
[1163]         }
[1164] 
[1165]         return NGX_ERROR;
[1166]     }
[1167] 
[1168]     return value;
[1169] }
[1170] 
[1171] 
[1172] u_char *
[1173] ngx_hex_dump(u_char *dst, u_char *src, size_t len)
[1174] {
[1175]     static u_char  hex[] = "0123456789abcdef";
[1176] 
[1177]     while (len--) {
[1178]         *dst++ = hex[*src >> 4];
[1179]         *dst++ = hex[*src++ & 0xf];
[1180]     }
[1181] 
[1182]     return dst;
[1183] }
[1184] 
[1185] 
[1186] void
[1187] ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src)
[1188] {
[1189]     static u_char   basis64[] =
[1190]             "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
[1191] 
[1192]     ngx_encode_base64_internal(dst, src, basis64, 1);
[1193] }
[1194] 
[1195] 
[1196] void
[1197] ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src)
[1198] {
[1199]     static u_char   basis64[] =
[1200]             "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
[1201] 
[1202]     ngx_encode_base64_internal(dst, src, basis64, 0);
[1203] }
[1204] 
[1205] 
[1206] static void
[1207] ngx_encode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis,
[1208]     ngx_uint_t padding)
[1209] {
[1210]     u_char         *d, *s;
[1211]     size_t          len;
[1212] 
[1213]     len = src->len;
[1214]     s = src->data;
[1215]     d = dst->data;
[1216] 
[1217]     while (len > 2) {
[1218]         *d++ = basis[(s[0] >> 2) & 0x3f];
[1219]         *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
[1220]         *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
[1221]         *d++ = basis[s[2] & 0x3f];
[1222] 
[1223]         s += 3;
[1224]         len -= 3;
[1225]     }
[1226] 
[1227]     if (len) {
[1228]         *d++ = basis[(s[0] >> 2) & 0x3f];
[1229] 
[1230]         if (len == 1) {
[1231]             *d++ = basis[(s[0] & 3) << 4];
[1232]             if (padding) {
[1233]                 *d++ = '=';
[1234]             }
[1235] 
[1236]         } else {
[1237]             *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
[1238]             *d++ = basis[(s[1] & 0x0f) << 2];
[1239]         }
[1240] 
[1241]         if (padding) {
[1242]             *d++ = '=';
[1243]         }
[1244]     }
[1245] 
[1246]     dst->len = d - dst->data;
[1247] }
[1248] 
[1249] 
[1250] ngx_int_t
[1251] ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src)
[1252] {
[1253]     static u_char   basis64[] = {
[1254]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1255]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1256]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
[1257]         52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
[1258]         77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
[1259]         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
[1260]         77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
[1261]         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,
[1262] 
[1263]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1264]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1265]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1266]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1267]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1268]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1269]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1270]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
[1271]     };
[1272] 
[1273]     return ngx_decode_base64_internal(dst, src, basis64);
[1274] }
[1275] 
[1276] 
[1277] ngx_int_t
[1278] ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src)
[1279] {
[1280]     static u_char   basis64[] = {
[1281]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1282]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1283]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
[1284]         52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
[1285]         77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
[1286]         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
[1287]         77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
[1288]         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,
[1289] 
[1290]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1291]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1292]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1293]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1294]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1295]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1296]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
[1297]         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
[1298]     };
[1299] 
[1300]     return ngx_decode_base64_internal(dst, src, basis64);
[1301] }
[1302] 
[1303] 
[1304] static ngx_int_t
[1305] ngx_decode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis)
[1306] {
[1307]     size_t          len;
[1308]     u_char         *d, *s;
[1309] 
[1310]     for (len = 0; len < src->len; len++) {
[1311]         if (src->data[len] == '=') {
[1312]             break;
[1313]         }
[1314] 
[1315]         if (basis[src->data[len]] == 77) {
[1316]             return NGX_ERROR;
[1317]         }
[1318]     }
[1319] 
[1320]     if (len % 4 == 1) {
[1321]         return NGX_ERROR;
[1322]     }
[1323] 
[1324]     s = src->data;
[1325]     d = dst->data;
[1326] 
[1327]     while (len > 3) {
[1328]         *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
[1329]         *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
[1330]         *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);
[1331] 
[1332]         s += 4;
[1333]         len -= 4;
[1334]     }
[1335] 
[1336]     if (len > 1) {
[1337]         *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
[1338]     }
[1339] 
[1340]     if (len > 2) {
[1341]         *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
[1342]     }
[1343] 
[1344]     dst->len = d - dst->data;
[1345] 
[1346]     return NGX_OK;
[1347] }
[1348] 
[1349] 
[1350] /*
[1351]  * ngx_utf8_decode() decodes two and more bytes UTF sequences only
[1352]  * the return values:
[1353]  *    0x80 - 0x10ffff         valid character
[1354]  *    0x110000 - 0xfffffffd   invalid sequence
[1355]  *    0xfffffffe              incomplete sequence
[1356]  *    0xffffffff              error
[1357]  */
[1358] 
[1359] uint32_t
[1360] ngx_utf8_decode(u_char **p, size_t n)
[1361] {
[1362]     size_t    len;
[1363]     uint32_t  u, i, valid;
[1364] 
[1365]     u = **p;
[1366] 
[1367]     if (u >= 0xf8) {
[1368] 
[1369]         (*p)++;
[1370]         return 0xffffffff;
[1371] 
[1372]     } else if (u >= 0xf0) {
[1373] 
[1374]         u &= 0x07;
[1375]         valid = 0xffff;
[1376]         len = 3;
[1377] 
[1378]     } else if (u >= 0xe0) {
[1379] 
[1380]         u &= 0x0f;
[1381]         valid = 0x7ff;
[1382]         len = 2;
[1383] 
[1384]     } else if (u >= 0xc2) {
[1385] 
[1386]         u &= 0x1f;
[1387]         valid = 0x7f;
[1388]         len = 1;
[1389] 
[1390]     } else {
[1391]         (*p)++;
[1392]         return 0xffffffff;
[1393]     }
[1394] 
[1395]     if (n - 1 < len) {
[1396]         return 0xfffffffe;
[1397]     }
[1398] 
[1399]     (*p)++;
[1400] 
[1401]     while (len) {
[1402]         i = *(*p)++;
[1403] 
[1404]         if (i < 0x80) {
[1405]             return 0xffffffff;
[1406]         }
[1407] 
[1408]         u = (u << 6) | (i & 0x3f);
[1409] 
[1410]         len--;
[1411]     }
[1412] 
[1413]     if (u > valid) {
[1414]         return u;
[1415]     }
[1416] 
[1417]     return 0xffffffff;
[1418] }
[1419] 
[1420] 
[1421] size_t
[1422] ngx_utf8_length(u_char *p, size_t n)
[1423] {
[1424]     u_char  c, *last;
[1425]     size_t  len;
[1426] 
[1427]     last = p + n;
[1428] 
[1429]     for (len = 0; p < last; len++) {
[1430] 
[1431]         c = *p;
[1432] 
[1433]         if (c < 0x80) {
[1434]             p++;
[1435]             continue;
[1436]         }
[1437] 
[1438]         if (ngx_utf8_decode(&p, last - p) > 0x10ffff) {
[1439]             /* invalid UTF-8 */
[1440]             return n;
[1441]         }
[1442]     }
[1443] 
[1444]     return len;
[1445] }
[1446] 
[1447] 
[1448] u_char *
[1449] ngx_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len)
[1450] {
[1451]     u_char  c, *next;
[1452] 
[1453]     if (n == 0) {
[1454]         return dst;
[1455]     }
[1456] 
[1457]     while (--n) {
[1458] 
[1459]         c = *src;
[1460]         *dst = c;
[1461] 
[1462]         if (c < 0x80) {
[1463] 
[1464]             if (c != '\0') {
[1465]                 dst++;
[1466]                 src++;
[1467]                 len--;
[1468] 
[1469]                 continue;
[1470]             }
[1471] 
[1472]             return dst;
[1473]         }
[1474] 
[1475]         next = src;
[1476] 
[1477]         if (ngx_utf8_decode(&next, len) > 0x10ffff) {
[1478]             /* invalid UTF-8 */
[1479]             break;
[1480]         }
[1481] 
[1482]         while (src < next) {
[1483]             *dst++ = *src++;
[1484]             len--;
[1485]         }
[1486]     }
[1487] 
[1488]     *dst = '\0';
[1489] 
[1490]     return dst;
[1491] }
[1492] 
[1493] 
[1494] uintptr_t
[1495] ngx_escape_uri(u_char *dst, u_char *src, size_t size, ngx_uint_t type)
[1496] {
[1497]     ngx_uint_t      n;
[1498]     uint32_t       *escape;
[1499]     static u_char   hex[] = "0123456789ABCDEF";
[1500] 
[1501]     /*
[1502]      * Per RFC 3986 only the following chars are allowed in URIs unescaped:
[1503]      *
[1504]      * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
[1505]      * gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
[1506]      * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
[1507]      *               / "*" / "+" / "," / ";" / "="
[1508]      *
[1509]      * And "%" can appear as a part of escaping itself.  The following
[1510]      * characters are not allowed and need to be escaped: %00-%1F, %7F-%FF,
[1511]      * " ", """, "<", ">", "\", "^", "`", "{", "|", "}".
[1512]      */
[1513] 
[1514]                     /* " ", "#", "%", "?", not allowed */
[1515] 
[1516]     static uint32_t   uri[] = {
[1517]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1518] 
[1519]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1520]         0xd000002d, /* 1101 0000 0000 0000  0000 0000 0010 1101 */
[1521] 
[1522]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1523]         0x50000000, /* 0101 0000 0000 0000  0000 0000 0000 0000 */
[1524] 
[1525]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1526]         0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */
[1527] 
[1528]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1529]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1530]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1531]         0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1532]     };
[1533] 
[1534]                     /* " ", "#", "%", "&", "+", ";", "?", not allowed */
[1535] 
[1536]     static uint32_t   args[] = {
[1537]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1538] 
[1539]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1540]         0xd800086d, /* 1101 1000 0000 0000  0000 1000 0110 1101 */
[1541] 
[1542]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1543]         0x50000000, /* 0101 0000 0000 0000  0000 0000 0000 0000 */
[1544] 
[1545]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1546]         0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */
[1547] 
[1548]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1549]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1550]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1551]         0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1552]     };
[1553] 
[1554]                     /* not ALPHA, DIGIT, "-", ".", "_", "~" */
[1555] 
[1556]     static uint32_t   uri_component[] = {
[1557]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1558] 
[1559]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1560]         0xfc009fff, /* 1111 1100 0000 0000  1001 1111 1111 1111 */
[1561] 
[1562]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1563]         0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */
[1564] 
[1565]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1566]         0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */
[1567] 
[1568]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1569]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1570]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1571]         0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1572]     };
[1573] 
[1574]                     /* " ", "#", """, "%", "'", not allowed */
[1575] 
[1576]     static uint32_t   html[] = {
[1577]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1578] 
[1579]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1580]         0x500000ad, /* 0101 0000 0000 0000  0000 0000 1010 1101 */
[1581] 
[1582]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1583]         0x50000000, /* 0101 0000 0000 0000  0000 0000 0000 0000 */
[1584] 
[1585]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1586]         0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */
[1587] 
[1588]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1589]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1590]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1591]         0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1592]     };
[1593] 
[1594]                     /* " ", """, "'", not allowed */
[1595] 
[1596]     static uint32_t   refresh[] = {
[1597]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1598] 
[1599]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1600]         0x50000085, /* 0101 0000 0000 0000  0000 0000 1000 0101 */
[1601] 
[1602]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1603]         0x50000000, /* 0101 0000 0000 0000  0000 0000 0000 0000 */
[1604] 
[1605]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1606]         0xd8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */
[1607] 
[1608]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1609]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1610]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1611]         0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1612]     };
[1613] 
[1614]                     /* " ", "%", %00-%1F */
[1615] 
[1616]     static uint32_t   memcached[] = {
[1617]         0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
[1618] 
[1619]                     /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
[1620]         0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */
[1621] 
[1622]                     /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
[1623]         0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[1624] 
[1625]                     /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
[1626]         0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[1627] 
[1628]         0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[1629]         0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[1630]         0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[1631]         0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
[1632]     };
[1633] 
[1634]                     /* mail_auth is the same as memcached */
[1635] 
[1636]     static uint32_t  *map[] =
[1637]         { uri, args, uri_component, html, refresh, memcached, memcached };
[1638] 
[1639] 
[1640]     escape = map[type];
[1641] 
[1642]     if (dst == NULL) {
[1643] 
[1644]         /* find the number of the characters to be escaped */
[1645] 
[1646]         n = 0;
[1647] 
[1648]         while (size) {
[1649]             if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
[1650]                 n++;
[1651]             }
[1652]             src++;
[1653]             size--;
[1654]         }
[1655] 
[1656]         return (uintptr_t) n;
[1657]     }
[1658] 
[1659]     while (size) {
[1660]         if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
[1661]             *dst++ = '%';
[1662]             *dst++ = hex[*src >> 4];
[1663]             *dst++ = hex[*src & 0xf];
[1664]             src++;
[1665] 
[1666]         } else {
[1667]             *dst++ = *src++;
[1668]         }
[1669]         size--;
[1670]     }
[1671] 
[1672]     return (uintptr_t) dst;
[1673] }
[1674] 
[1675] 
[1676] void
[1677] ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type)
[1678] {
[1679]     u_char  *d, *s, ch, c, decoded;
[1680]     enum {
[1681]         sw_usual = 0,
[1682]         sw_quoted,
[1683]         sw_quoted_second
[1684]     } state;
[1685] 
[1686]     d = *dst;
[1687]     s = *src;
[1688] 
[1689]     state = 0;
[1690]     decoded = 0;
[1691] 
[1692]     while (size--) {
[1693] 
[1694]         ch = *s++;
[1695] 
[1696]         switch (state) {
[1697]         case sw_usual:
[1698]             if (ch == '?'
[1699]                 && (type & (NGX_UNESCAPE_URI|NGX_UNESCAPE_REDIRECT)))
[1700]             {
[1701]                 *d++ = ch;
[1702]                 goto done;
[1703]             }
[1704] 
[1705]             if (ch == '%') {
[1706]                 state = sw_quoted;
[1707]                 break;
[1708]             }
[1709] 
[1710]             *d++ = ch;
[1711]             break;
[1712] 
[1713]         case sw_quoted:
[1714] 
[1715]             if (ch >= '0' && ch <= '9') {
[1716]                 decoded = (u_char) (ch - '0');
[1717]                 state = sw_quoted_second;
[1718]                 break;
[1719]             }
[1720] 
[1721]             c = (u_char) (ch | 0x20);
[1722]             if (c >= 'a' && c <= 'f') {
[1723]                 decoded = (u_char) (c - 'a' + 10);
[1724]                 state = sw_quoted_second;
[1725]                 break;
[1726]             }
[1727] 
[1728]             /* the invalid quoted character */
[1729] 
[1730]             state = sw_usual;
[1731] 
[1732]             *d++ = ch;
[1733] 
[1734]             break;
[1735] 
[1736]         case sw_quoted_second:
[1737] 
[1738]             state = sw_usual;
[1739] 
[1740]             if (ch >= '0' && ch <= '9') {
[1741]                 ch = (u_char) ((decoded << 4) + (ch - '0'));
[1742] 
[1743]                 if (type & NGX_UNESCAPE_REDIRECT) {
[1744]                     if (ch > '%' && ch < 0x7f) {
[1745]                         *d++ = ch;
[1746]                         break;
[1747]                     }
[1748] 
[1749]                     *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
[1750] 
[1751]                     break;
[1752]                 }
[1753] 
[1754]                 *d++ = ch;
[1755] 
[1756]                 break;
[1757]             }
[1758] 
[1759]             c = (u_char) (ch | 0x20);
[1760]             if (c >= 'a' && c <= 'f') {
[1761]                 ch = (u_char) ((decoded << 4) + (c - 'a') + 10);
[1762] 
[1763]                 if (type & NGX_UNESCAPE_URI) {
[1764]                     if (ch == '?') {
[1765]                         *d++ = ch;
[1766]                         goto done;
[1767]                     }
[1768] 
[1769]                     *d++ = ch;
[1770]                     break;
[1771]                 }
[1772] 
[1773]                 if (type & NGX_UNESCAPE_REDIRECT) {
[1774]                     if (ch == '?') {
[1775]                         *d++ = ch;
[1776]                         goto done;
[1777]                     }
[1778] 
[1779]                     if (ch > '%' && ch < 0x7f) {
[1780]                         *d++ = ch;
[1781]                         break;
[1782]                     }
[1783] 
[1784]                     *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
[1785]                     break;
[1786]                 }
[1787] 
[1788]                 *d++ = ch;
[1789] 
[1790]                 break;
[1791]             }
[1792] 
[1793]             /* the invalid quoted character */
[1794] 
[1795]             break;
[1796]         }
[1797]     }
[1798] 
[1799] done:
[1800] 
[1801]     *dst = d;
[1802]     *src = s;
[1803] }
[1804] 
[1805] 
[1806] uintptr_t
[1807] ngx_escape_html(u_char *dst, u_char *src, size_t size)
[1808] {
[1809]     u_char      ch;
[1810]     ngx_uint_t  len;
[1811] 
[1812]     if (dst == NULL) {
[1813] 
[1814]         len = 0;
[1815] 
[1816]         while (size) {
[1817]             switch (*src++) {
[1818] 
[1819]             case '<':
[1820]                 len += sizeof("&lt;") - 2;
[1821]                 break;
[1822] 
[1823]             case '>':
[1824]                 len += sizeof("&gt;") - 2;
[1825]                 break;
[1826] 
[1827]             case '&':
[1828]                 len += sizeof("&amp;") - 2;
[1829]                 break;
[1830] 
[1831]             case '"':
[1832]                 len += sizeof("&quot;") - 2;
[1833]                 break;
[1834] 
[1835]             default:
[1836]                 break;
[1837]             }
[1838]             size--;
[1839]         }
[1840] 
[1841]         return (uintptr_t) len;
[1842]     }
[1843] 
[1844]     while (size) {
[1845]         ch = *src++;
[1846] 
[1847]         switch (ch) {
[1848] 
[1849]         case '<':
[1850]             *dst++ = '&'; *dst++ = 'l'; *dst++ = 't'; *dst++ = ';';
[1851]             break;
[1852] 
[1853]         case '>':
[1854]             *dst++ = '&'; *dst++ = 'g'; *dst++ = 't'; *dst++ = ';';
[1855]             break;
[1856] 
[1857]         case '&':
[1858]             *dst++ = '&'; *dst++ = 'a'; *dst++ = 'm'; *dst++ = 'p';
[1859]             *dst++ = ';';
[1860]             break;
[1861] 
[1862]         case '"':
[1863]             *dst++ = '&'; *dst++ = 'q'; *dst++ = 'u'; *dst++ = 'o';
[1864]             *dst++ = 't'; *dst++ = ';';
[1865]             break;
[1866] 
[1867]         default:
[1868]             *dst++ = ch;
[1869]             break;
[1870]         }
[1871]         size--;
[1872]     }
[1873] 
[1874]     return (uintptr_t) dst;
[1875] }
[1876] 
[1877] 
[1878] uintptr_t
[1879] ngx_escape_json(u_char *dst, u_char *src, size_t size)
[1880] {
[1881]     u_char      ch;
[1882]     ngx_uint_t  len;
[1883] 
[1884]     if (dst == NULL) {
[1885]         len = 0;
[1886] 
[1887]         while (size) {
[1888]             ch = *src++;
[1889] 
[1890]             if (ch == '\\' || ch == '"') {
[1891]                 len++;
[1892] 
[1893]             } else if (ch <= 0x1f) {
[1894] 
[1895]                 switch (ch) {
[1896]                 case '\n':
[1897]                 case '\r':
[1898]                 case '\t':
[1899]                 case '\b':
[1900]                 case '\f':
[1901]                     len++;
[1902]                     break;
[1903] 
[1904]                 default:
[1905]                     len += sizeof("\\u001F") - 2;
[1906]                 }
[1907]             }
[1908] 
[1909]             size--;
[1910]         }
[1911] 
[1912]         return (uintptr_t) len;
[1913]     }
[1914] 
[1915]     while (size) {
[1916]         ch = *src++;
[1917] 
[1918]         if (ch > 0x1f) {
[1919] 
[1920]             if (ch == '\\' || ch == '"') {
[1921]                 *dst++ = '\\';
[1922]             }
[1923] 
[1924]             *dst++ = ch;
[1925] 
[1926]         } else {
[1927]             *dst++ = '\\';
[1928] 
[1929]             switch (ch) {
[1930]             case '\n':
[1931]                 *dst++ = 'n';
[1932]                 break;
[1933] 
[1934]             case '\r':
[1935]                 *dst++ = 'r';
[1936]                 break;
[1937] 
[1938]             case '\t':
[1939]                 *dst++ = 't';
[1940]                 break;
[1941] 
[1942]             case '\b':
[1943]                 *dst++ = 'b';
[1944]                 break;
[1945] 
[1946]             case '\f':
[1947]                 *dst++ = 'f';
[1948]                 break;
[1949] 
[1950]             default:
[1951]                 *dst++ = 'u'; *dst++ = '0'; *dst++ = '0';
[1952]                 *dst++ = '0' + (ch >> 4);
[1953] 
[1954]                 ch &= 0xf;
[1955] 
[1956]                 *dst++ = (ch < 10) ? ('0' + ch) : ('A' + ch - 10);
[1957]             }
[1958]         }
[1959] 
[1960]         size--;
[1961]     }
[1962] 
[1963]     return (uintptr_t) dst;
[1964] }
[1965] 
[1966] 
[1967] void
[1968] ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
[1969]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[1970] {
[1971]     ngx_str_node_t      *n, *t;
[1972]     ngx_rbtree_node_t  **p;
[1973] 
[1974]     for ( ;; ) {
[1975] 
[1976]         n = (ngx_str_node_t *) node;
[1977]         t = (ngx_str_node_t *) temp;
[1978] 
[1979]         if (node->key != temp->key) {
[1980] 
[1981]             p = (node->key < temp->key) ? &temp->left : &temp->right;
[1982] 
[1983]         } else if (n->str.len != t->str.len) {
[1984] 
[1985]             p = (n->str.len < t->str.len) ? &temp->left : &temp->right;
[1986] 
[1987]         } else {
[1988]             p = (ngx_memcmp(n->str.data, t->str.data, n->str.len) < 0)
[1989]                  ? &temp->left : &temp->right;
[1990]         }
[1991] 
[1992]         if (*p == sentinel) {
[1993]             break;
[1994]         }
[1995] 
[1996]         temp = *p;
[1997]     }
[1998] 
[1999]     *p = node;
[2000]     node->parent = temp;
[2001]     node->left = sentinel;
[2002]     node->right = sentinel;
[2003]     ngx_rbt_red(node);
[2004] }
[2005] 
[2006] 
[2007] ngx_str_node_t *
[2008] ngx_str_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *val, uint32_t hash)
[2009] {
[2010]     ngx_int_t           rc;
[2011]     ngx_str_node_t     *n;
[2012]     ngx_rbtree_node_t  *node, *sentinel;
[2013] 
[2014]     node = rbtree->root;
[2015]     sentinel = rbtree->sentinel;
[2016] 
[2017]     while (node != sentinel) {
[2018] 
[2019]         n = (ngx_str_node_t *) node;
[2020] 
[2021]         if (hash != node->key) {
[2022]             node = (hash < node->key) ? node->left : node->right;
[2023]             continue;
[2024]         }
[2025] 
[2026]         if (val->len != n->str.len) {
[2027]             node = (val->len < n->str.len) ? node->left : node->right;
[2028]             continue;
[2029]         }
[2030] 
[2031]         rc = ngx_memcmp(val->data, n->str.data, val->len);
[2032] 
[2033]         if (rc < 0) {
[2034]             node = node->left;
[2035]             continue;
[2036]         }
[2037] 
[2038]         if (rc > 0) {
[2039]             node = node->right;
[2040]             continue;
[2041]         }
[2042] 
[2043]         return n;
[2044]     }
[2045] 
[2046]     return NULL;
[2047] }
[2048] 
[2049] 
[2050] /* ngx_sort() is implemented as insertion sort because we need stable sort */
[2051] 
[2052] void
[2053] ngx_sort(void *base, size_t n, size_t size,
[2054]     ngx_int_t (*cmp)(const void *, const void *))
[2055] {
[2056]     u_char  *p1, *p2, *p;
[2057] 
[2058]     p = ngx_alloc(size, ngx_cycle->log);
[2059]     if (p == NULL) {
[2060]         return;
[2061]     }
[2062] 
[2063]     for (p1 = (u_char *) base + size;
[2064]          p1 < (u_char *) base + n * size;
[2065]          p1 += size)
[2066]     {
[2067]         ngx_memcpy(p, p1, size);
[2068] 
[2069]         for (p2 = p1;
[2070]              p2 > (u_char *) base && cmp(p2 - size, p) > 0;
[2071]              p2 -= size)
[2072]         {
[2073]             ngx_memcpy(p2, p2 - size, size);
[2074]         }
[2075] 
[2076]         ngx_memcpy(p2, p, size);
[2077]     }
[2078] 
[2079]     ngx_free(p);
[2080] }
[2081] 
[2082] 
[2083] void
[2084] ngx_explicit_memzero(void *buf, size_t n)
[2085] {
[2086]     ngx_memzero(buf, n);
[2087]     ngx_memory_barrier();
[2088] }
[2089] 
[2090] 
[2091] #if (NGX_MEMCPY_LIMIT)
[2092] 
[2093] void *
[2094] ngx_memcpy(void *dst, const void *src, size_t n)
[2095] {
[2096]     if (n > NGX_MEMCPY_LIMIT) {
[2097]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "memcpy %uz bytes", n);
[2098]         ngx_debug_point();
[2099]     }
[2100] 
[2101]     return memcpy(dst, src, n);
[2102] }
[2103] 
[2104] #endif
