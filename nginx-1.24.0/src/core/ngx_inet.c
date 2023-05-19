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
[12] static ngx_int_t ngx_parse_unix_domain_url(ngx_pool_t *pool, ngx_url_t *u);
[13] static ngx_int_t ngx_parse_inet_url(ngx_pool_t *pool, ngx_url_t *u);
[14] static ngx_int_t ngx_parse_inet6_url(ngx_pool_t *pool, ngx_url_t *u);
[15] static ngx_int_t ngx_inet_add_addr(ngx_pool_t *pool, ngx_url_t *u,
[16]     struct sockaddr *sockaddr, socklen_t socklen, ngx_uint_t total);
[17] 
[18] 
[19] in_addr_t
[20] ngx_inet_addr(u_char *text, size_t len)
[21] {
[22]     u_char      *p, c;
[23]     in_addr_t    addr;
[24]     ngx_uint_t   octet, n;
[25] 
[26]     addr = 0;
[27]     octet = 0;
[28]     n = 0;
[29] 
[30]     for (p = text; p < text + len; p++) {
[31]         c = *p;
[32] 
[33]         if (c >= '0' && c <= '9') {
[34]             octet = octet * 10 + (c - '0');
[35] 
[36]             if (octet > 255) {
[37]                 return INADDR_NONE;
[38]             }
[39] 
[40]             continue;
[41]         }
[42] 
[43]         if (c == '.') {
[44]             addr = (addr << 8) + octet;
[45]             octet = 0;
[46]             n++;
[47]             continue;
[48]         }
[49] 
[50]         return INADDR_NONE;
[51]     }
[52] 
[53]     if (n == 3) {
[54]         addr = (addr << 8) + octet;
[55]         return htonl(addr);
[56]     }
[57] 
[58]     return INADDR_NONE;
[59] }
[60] 
[61] 
[62] #if (NGX_HAVE_INET6)
[63] 
[64] ngx_int_t
[65] ngx_inet6_addr(u_char *p, size_t len, u_char *addr)
[66] {
[67]     u_char      c, *zero, *digit, *s, *d;
[68]     size_t      len4;
[69]     ngx_uint_t  n, nibbles, word;
[70] 
[71]     if (len == 0) {
[72]         return NGX_ERROR;
[73]     }
[74] 
[75]     zero = NULL;
[76]     digit = NULL;
[77]     len4 = 0;
[78]     nibbles = 0;
[79]     word = 0;
[80]     n = 8;
[81] 
[82]     if (p[0] == ':') {
[83]         p++;
[84]         len--;
[85]     }
[86] 
[87]     for (/* void */; len; len--) {
[88]         c = *p++;
[89] 
[90]         if (c == ':') {
[91]             if (nibbles) {
[92]                 digit = p;
[93]                 len4 = len;
[94]                 *addr++ = (u_char) (word >> 8);
[95]                 *addr++ = (u_char) (word & 0xff);
[96] 
[97]                 if (--n) {
[98]                     nibbles = 0;
[99]                     word = 0;
[100]                     continue;
[101]                 }
[102] 
[103]             } else {
[104]                 if (zero == NULL) {
[105]                     digit = p;
[106]                     len4 = len;
[107]                     zero = addr;
[108]                     continue;
[109]                 }
[110]             }
[111] 
[112]             return NGX_ERROR;
[113]         }
[114] 
[115]         if (c == '.' && nibbles) {
[116]             if (n < 2 || digit == NULL) {
[117]                 return NGX_ERROR;
[118]             }
[119] 
[120]             word = ngx_inet_addr(digit, len4 - 1);
[121]             if (word == INADDR_NONE) {
[122]                 return NGX_ERROR;
[123]             }
[124] 
[125]             word = ntohl(word);
[126]             *addr++ = (u_char) ((word >> 24) & 0xff);
[127]             *addr++ = (u_char) ((word >> 16) & 0xff);
[128]             n--;
[129]             break;
[130]         }
[131] 
[132]         if (++nibbles > 4) {
[133]             return NGX_ERROR;
[134]         }
[135] 
[136]         if (c >= '0' && c <= '9') {
[137]             word = word * 16 + (c - '0');
[138]             continue;
[139]         }
[140] 
[141]         c |= 0x20;
[142] 
[143]         if (c >= 'a' && c <= 'f') {
[144]             word = word * 16 + (c - 'a') + 10;
[145]             continue;
[146]         }
[147] 
[148]         return NGX_ERROR;
[149]     }
[150] 
[151]     if (nibbles == 0 && zero == NULL) {
[152]         return NGX_ERROR;
[153]     }
[154] 
[155]     *addr++ = (u_char) (word >> 8);
[156]     *addr++ = (u_char) (word & 0xff);
[157] 
[158]     if (--n) {
[159]         if (zero) {
[160]             n *= 2;
[161]             s = addr - 1;
[162]             d = s + n;
[163]             while (s >= zero) {
[164]                 *d-- = *s--;
[165]             }
[166]             ngx_memzero(zero, n);
[167]             return NGX_OK;
[168]         }
[169] 
[170]     } else {
[171]         if (zero == NULL) {
[172]             return NGX_OK;
[173]         }
[174]     }
[175] 
[176]     return NGX_ERROR;
[177] }
[178] 
[179] #endif
[180] 
[181] 
[182] size_t
[183] ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text, size_t len,
[184]     ngx_uint_t port)
[185] {
[186]     u_char               *p;
[187] #if (NGX_HAVE_INET6 || NGX_HAVE_UNIX_DOMAIN)
[188]     size_t                n;
[189] #endif
[190]     struct sockaddr_in   *sin;
[191] #if (NGX_HAVE_INET6)
[192]     struct sockaddr_in6  *sin6;
[193] #endif
[194] #if (NGX_HAVE_UNIX_DOMAIN)
[195]     struct sockaddr_un   *saun;
[196] #endif
[197] 
[198]     switch (sa->sa_family) {
[199] 
[200]     case AF_INET:
[201] 
[202]         sin = (struct sockaddr_in *) sa;
[203]         p = (u_char *) &sin->sin_addr;
[204] 
[205]         if (port) {
[206]             p = ngx_snprintf(text, len, "%ud.%ud.%ud.%ud:%d",
[207]                              p[0], p[1], p[2], p[3], ntohs(sin->sin_port));
[208]         } else {
[209]             p = ngx_snprintf(text, len, "%ud.%ud.%ud.%ud",
[210]                              p[0], p[1], p[2], p[3]);
[211]         }
[212] 
[213]         return (p - text);
[214] 
[215] #if (NGX_HAVE_INET6)
[216] 
[217]     case AF_INET6:
[218] 
[219]         sin6 = (struct sockaddr_in6 *) sa;
[220] 
[221]         n = 0;
[222] 
[223]         if (port) {
[224]             text[n++] = '[';
[225]         }
[226] 
[227]         n = ngx_inet6_ntop(sin6->sin6_addr.s6_addr, &text[n], len);
[228] 
[229]         if (port) {
[230]             n = ngx_sprintf(&text[1 + n], "]:%d",
[231]                             ntohs(sin6->sin6_port)) - text;
[232]         }
[233] 
[234]         return n;
[235] #endif
[236] 
[237] #if (NGX_HAVE_UNIX_DOMAIN)
[238] 
[239]     case AF_UNIX:
[240]         saun = (struct sockaddr_un *) sa;
[241] 
[242]         /* on Linux sockaddr might not include sun_path at all */
[243] 
[244]         if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)) {
[245]             p = ngx_snprintf(text, len, "unix:%Z");
[246] 
[247]         } else {
[248]             n = ngx_strnlen((u_char *) saun->sun_path,
[249]                             socklen - offsetof(struct sockaddr_un, sun_path));
[250]             p = ngx_snprintf(text, len, "unix:%*s%Z", n, saun->sun_path);
[251]         }
[252] 
[253]         /* we do not include trailing zero in address length */
[254] 
[255]         return (p - text - 1);
[256] 
[257] #endif
[258] 
[259]     default:
[260]         return 0;
[261]     }
[262] }
[263] 
[264] 
[265] size_t
[266] ngx_inet_ntop(int family, void *addr, u_char *text, size_t len)
[267] {
[268]     u_char  *p;
[269] 
[270]     switch (family) {
[271] 
[272]     case AF_INET:
[273] 
[274]         p = addr;
[275] 
[276]         return ngx_snprintf(text, len, "%ud.%ud.%ud.%ud",
[277]                             p[0], p[1], p[2], p[3])
[278]                - text;
[279] 
[280] #if (NGX_HAVE_INET6)
[281] 
[282]     case AF_INET6:
[283]         return ngx_inet6_ntop(addr, text, len);
[284] 
[285] #endif
[286] 
[287]     default:
[288]         return 0;
[289]     }
[290] }
[291] 
[292] 
[293] #if (NGX_HAVE_INET6)
[294] 
[295] size_t
[296] ngx_inet6_ntop(u_char *p, u_char *text, size_t len)
[297] {
[298]     u_char      *dst;
[299]     size_t       max, n;
[300]     ngx_uint_t   i, zero, last;
[301] 
[302]     if (len < NGX_INET6_ADDRSTRLEN) {
[303]         return 0;
[304]     }
[305] 
[306]     zero = (ngx_uint_t) -1;
[307]     last = (ngx_uint_t) -1;
[308]     max = 1;
[309]     n = 0;
[310] 
[311]     for (i = 0; i < 16; i += 2) {
[312] 
[313]         if (p[i] || p[i + 1]) {
[314] 
[315]             if (max < n) {
[316]                 zero = last;
[317]                 max = n;
[318]             }
[319] 
[320]             n = 0;
[321]             continue;
[322]         }
[323] 
[324]         if (n++ == 0) {
[325]             last = i;
[326]         }
[327]     }
[328] 
[329]     if (max < n) {
[330]         zero = last;
[331]         max = n;
[332]     }
[333] 
[334]     dst = text;
[335]     n = 16;
[336] 
[337]     if (zero == 0) {
[338] 
[339]         if ((max == 5 && p[10] == 0xff && p[11] == 0xff)
[340]             || (max == 6)
[341]             || (max == 7 && p[14] != 0 && p[15] != 1))
[342]         {
[343]             n = 12;
[344]         }
[345] 
[346]         *dst++ = ':';
[347]     }
[348] 
[349]     for (i = 0; i < n; i += 2) {
[350] 
[351]         if (i == zero) {
[352]             *dst++ = ':';
[353]             i += (max - 1) * 2;
[354]             continue;
[355]         }
[356] 
[357]         dst = ngx_sprintf(dst, "%xd", p[i] * 256 + p[i + 1]);
[358] 
[359]         if (i < 14) {
[360]             *dst++ = ':';
[361]         }
[362]     }
[363] 
[364]     if (n == 12) {
[365]         dst = ngx_sprintf(dst, "%ud.%ud.%ud.%ud", p[12], p[13], p[14], p[15]);
[366]     }
[367] 
[368]     return dst - text;
[369] }
[370] 
[371] #endif
[372] 
[373] 
[374] ngx_int_t
[375] ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr)
[376] {
[377]     u_char      *addr, *mask, *last;
[378]     size_t       len;
[379]     ngx_int_t    shift;
[380] #if (NGX_HAVE_INET6)
[381]     ngx_int_t    rc;
[382]     ngx_uint_t   s, i;
[383] #endif
[384] 
[385]     addr = text->data;
[386]     last = addr + text->len;
[387] 
[388]     mask = ngx_strlchr(addr, last, '/');
[389]     len = (mask ? mask : last) - addr;
[390] 
[391]     cidr->u.in.addr = ngx_inet_addr(addr, len);
[392] 
[393]     if (cidr->u.in.addr != INADDR_NONE) {
[394]         cidr->family = AF_INET;
[395] 
[396]         if (mask == NULL) {
[397]             cidr->u.in.mask = 0xffffffff;
[398]             return NGX_OK;
[399]         }
[400] 
[401] #if (NGX_HAVE_INET6)
[402]     } else if (ngx_inet6_addr(addr, len, cidr->u.in6.addr.s6_addr) == NGX_OK) {
[403]         cidr->family = AF_INET6;
[404] 
[405]         if (mask == NULL) {
[406]             ngx_memset(cidr->u.in6.mask.s6_addr, 0xff, 16);
[407]             return NGX_OK;
[408]         }
[409] 
[410] #endif
[411]     } else {
[412]         return NGX_ERROR;
[413]     }
[414] 
[415]     mask++;
[416] 
[417]     shift = ngx_atoi(mask, last - mask);
[418]     if (shift == NGX_ERROR) {
[419]         return NGX_ERROR;
[420]     }
[421] 
[422]     switch (cidr->family) {
[423] 
[424] #if (NGX_HAVE_INET6)
[425]     case AF_INET6:
[426]         if (shift > 128) {
[427]             return NGX_ERROR;
[428]         }
[429] 
[430]         addr = cidr->u.in6.addr.s6_addr;
[431]         mask = cidr->u.in6.mask.s6_addr;
[432]         rc = NGX_OK;
[433] 
[434]         for (i = 0; i < 16; i++) {
[435] 
[436]             s = (shift > 8) ? 8 : shift;
[437]             shift -= s;
[438] 
[439]             mask[i] = (u_char) (0xffu << (8 - s));
[440] 
[441]             if (addr[i] != (addr[i] & mask[i])) {
[442]                 rc = NGX_DONE;
[443]                 addr[i] &= mask[i];
[444]             }
[445]         }
[446] 
[447]         return rc;
[448] #endif
[449] 
[450]     default: /* AF_INET */
[451]         if (shift > 32) {
[452]             return NGX_ERROR;
[453]         }
[454] 
[455]         if (shift) {
[456]             cidr->u.in.mask = htonl((uint32_t) (0xffffffffu << (32 - shift)));
[457] 
[458]         } else {
[459]             /* x86 compilers use a shl instruction that shifts by modulo 32 */
[460]             cidr->u.in.mask = 0;
[461]         }
[462] 
[463]         if (cidr->u.in.addr == (cidr->u.in.addr & cidr->u.in.mask)) {
[464]             return NGX_OK;
[465]         }
[466] 
[467]         cidr->u.in.addr &= cidr->u.in.mask;
[468] 
[469]         return NGX_DONE;
[470]     }
[471] }
[472] 
[473] 
[474] ngx_int_t
[475] ngx_cidr_match(struct sockaddr *sa, ngx_array_t *cidrs)
[476] {
[477] #if (NGX_HAVE_INET6)
[478]     u_char           *p;
[479] #endif
[480]     in_addr_t         inaddr;
[481]     ngx_cidr_t       *cidr;
[482]     ngx_uint_t        family, i;
[483] #if (NGX_HAVE_INET6)
[484]     ngx_uint_t        n;
[485]     struct in6_addr  *inaddr6;
[486] #endif
[487] 
[488] #if (NGX_SUPPRESS_WARN)
[489]     inaddr = 0;
[490] #if (NGX_HAVE_INET6)
[491]     inaddr6 = NULL;
[492] #endif
[493] #endif
[494] 
[495]     family = sa->sa_family;
[496] 
[497]     if (family == AF_INET) {
[498]         inaddr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
[499]     }
[500] 
[501] #if (NGX_HAVE_INET6)
[502]     else if (family == AF_INET6) {
[503]         inaddr6 = &((struct sockaddr_in6 *) sa)->sin6_addr;
[504] 
[505]         if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
[506]             family = AF_INET;
[507] 
[508]             p = inaddr6->s6_addr;
[509] 
[510]             inaddr = p[12] << 24;
[511]             inaddr += p[13] << 16;
[512]             inaddr += p[14] << 8;
[513]             inaddr += p[15];
[514] 
[515]             inaddr = htonl(inaddr);
[516]         }
[517]     }
[518] #endif
[519] 
[520]     for (cidr = cidrs->elts, i = 0; i < cidrs->nelts; i++) {
[521]         if (cidr[i].family != family) {
[522]             goto next;
[523]         }
[524] 
[525]         switch (family) {
[526] 
[527] #if (NGX_HAVE_INET6)
[528]         case AF_INET6:
[529]             for (n = 0; n < 16; n++) {
[530]                 if ((inaddr6->s6_addr[n] & cidr[i].u.in6.mask.s6_addr[n])
[531]                     != cidr[i].u.in6.addr.s6_addr[n])
[532]                 {
[533]                     goto next;
[534]                 }
[535]             }
[536]             break;
[537] #endif
[538] 
[539] #if (NGX_HAVE_UNIX_DOMAIN)
[540]         case AF_UNIX:
[541]             break;
[542] #endif
[543] 
[544]         default: /* AF_INET */
[545]             if ((inaddr & cidr[i].u.in.mask) != cidr[i].u.in.addr) {
[546]                 goto next;
[547]             }
[548]             break;
[549]         }
[550] 
[551]         return NGX_OK;
[552] 
[553]     next:
[554]         continue;
[555]     }
[556] 
[557]     return NGX_DECLINED;
[558] }
[559] 
[560] 
[561] ngx_int_t
[562] ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text, size_t len)
[563] {
[564]     in_addr_t             inaddr;
[565]     ngx_uint_t            family;
[566]     struct sockaddr_in   *sin;
[567] #if (NGX_HAVE_INET6)
[568]     struct in6_addr       inaddr6;
[569]     struct sockaddr_in6  *sin6;
[570] 
[571]     /*
[572]      * prevent MSVC8 warning:
[573]      *    potentially uninitialized local variable 'inaddr6' used
[574]      */
[575]     ngx_memzero(&inaddr6, sizeof(struct in6_addr));
[576] #endif
[577] 
[578]     inaddr = ngx_inet_addr(text, len);
[579] 
[580]     if (inaddr != INADDR_NONE) {
[581]         family = AF_INET;
[582]         len = sizeof(struct sockaddr_in);
[583] 
[584] #if (NGX_HAVE_INET6)
[585]     } else if (ngx_inet6_addr(text, len, inaddr6.s6_addr) == NGX_OK) {
[586]         family = AF_INET6;
[587]         len = sizeof(struct sockaddr_in6);
[588] 
[589] #endif
[590]     } else {
[591]         return NGX_DECLINED;
[592]     }
[593] 
[594]     addr->sockaddr = ngx_pcalloc(pool, len);
[595]     if (addr->sockaddr == NULL) {
[596]         return NGX_ERROR;
[597]     }
[598] 
[599]     addr->sockaddr->sa_family = (u_char) family;
[600]     addr->socklen = len;
[601] 
[602]     switch (family) {
[603] 
[604] #if (NGX_HAVE_INET6)
[605]     case AF_INET6:
[606]         sin6 = (struct sockaddr_in6 *) addr->sockaddr;
[607]         ngx_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
[608]         break;
[609] #endif
[610] 
[611]     default: /* AF_INET */
[612]         sin = (struct sockaddr_in *) addr->sockaddr;
[613]         sin->sin_addr.s_addr = inaddr;
[614]         break;
[615]     }
[616] 
[617]     return NGX_OK;
[618] }
[619] 
[620] 
[621] ngx_int_t
[622] ngx_parse_addr_port(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
[623]     size_t len)
[624] {
[625]     u_char     *p, *last;
[626]     size_t      plen;
[627]     ngx_int_t   rc, port;
[628] 
[629]     rc = ngx_parse_addr(pool, addr, text, len);
[630] 
[631]     if (rc != NGX_DECLINED) {
[632]         return rc;
[633]     }
[634] 
[635]     last = text + len;
[636] 
[637] #if (NGX_HAVE_INET6)
[638]     if (len && text[0] == '[') {
[639] 
[640]         p = ngx_strlchr(text, last, ']');
[641] 
[642]         if (p == NULL || p == last - 1 || *++p != ':') {
[643]             return NGX_DECLINED;
[644]         }
[645] 
[646]         text++;
[647]         len -= 2;
[648] 
[649]     } else
[650] #endif
[651] 
[652]     {
[653]         p = ngx_strlchr(text, last, ':');
[654] 
[655]         if (p == NULL) {
[656]             return NGX_DECLINED;
[657]         }
[658]     }
[659] 
[660]     p++;
[661]     plen = last - p;
[662] 
[663]     port = ngx_atoi(p, plen);
[664] 
[665]     if (port < 1 || port > 65535) {
[666]         return NGX_DECLINED;
[667]     }
[668] 
[669]     len -= plen + 1;
[670] 
[671]     rc = ngx_parse_addr(pool, addr, text, len);
[672] 
[673]     if (rc != NGX_OK) {
[674]         return rc;
[675]     }
[676] 
[677]     ngx_inet_set_port(addr->sockaddr, (in_port_t) port);
[678] 
[679]     return NGX_OK;
[680] }
[681] 
[682] 
[683] ngx_int_t
[684] ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u)
[685] {
[686]     u_char  *p;
[687]     size_t   len;
[688] 
[689]     p = u->url.data;
[690]     len = u->url.len;
[691] 
[692]     if (len >= 5 && ngx_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
[693]         return ngx_parse_unix_domain_url(pool, u);
[694]     }
[695] 
[696]     if (len && p[0] == '[') {
[697]         return ngx_parse_inet6_url(pool, u);
[698]     }
[699] 
[700]     return ngx_parse_inet_url(pool, u);
[701] }
[702] 
[703] 
[704] static ngx_int_t
[705] ngx_parse_unix_domain_url(ngx_pool_t *pool, ngx_url_t *u)
[706] {
[707] #if (NGX_HAVE_UNIX_DOMAIN)
[708]     u_char              *path, *uri, *last;
[709]     size_t               len;
[710]     struct sockaddr_un  *saun;
[711] 
[712]     len = u->url.len;
[713]     path = u->url.data;
[714] 
[715]     path += 5;
[716]     len -= 5;
[717] 
[718]     if (u->uri_part) {
[719] 
[720]         last = path + len;
[721]         uri = ngx_strlchr(path, last, ':');
[722] 
[723]         if (uri) {
[724]             len = uri - path;
[725]             uri++;
[726]             u->uri.len = last - uri;
[727]             u->uri.data = uri;
[728]         }
[729]     }
[730] 
[731]     if (len == 0) {
[732]         u->err = "no path in the unix domain socket";
[733]         return NGX_ERROR;
[734]     }
[735] 
[736]     u->host.len = len++;
[737]     u->host.data = path;
[738] 
[739]     if (len > sizeof(saun->sun_path)) {
[740]         u->err = "too long path in the unix domain socket";
[741]         return NGX_ERROR;
[742]     }
[743] 
[744]     u->socklen = sizeof(struct sockaddr_un);
[745]     saun = (struct sockaddr_un *) &u->sockaddr;
[746]     saun->sun_family = AF_UNIX;
[747]     (void) ngx_cpystrn((u_char *) saun->sun_path, path, len);
[748] 
[749]     u->addrs = ngx_pcalloc(pool, sizeof(ngx_addr_t));
[750]     if (u->addrs == NULL) {
[751]         return NGX_ERROR;
[752]     }
[753] 
[754]     saun = ngx_pcalloc(pool, sizeof(struct sockaddr_un));
[755]     if (saun == NULL) {
[756]         return NGX_ERROR;
[757]     }
[758] 
[759]     u->family = AF_UNIX;
[760]     u->naddrs = 1;
[761] 
[762]     saun->sun_family = AF_UNIX;
[763]     (void) ngx_cpystrn((u_char *) saun->sun_path, path, len);
[764] 
[765]     u->addrs[0].sockaddr = (struct sockaddr *) saun;
[766]     u->addrs[0].socklen = sizeof(struct sockaddr_un);
[767]     u->addrs[0].name.len = len + 4;
[768]     u->addrs[0].name.data = u->url.data;
[769] 
[770]     return NGX_OK;
[771] 
[772] #else
[773] 
[774]     u->err = "the unix domain sockets are not supported on this platform";
[775] 
[776]     return NGX_ERROR;
[777] 
[778] #endif
[779] }
[780] 
[781] 
[782] static ngx_int_t
[783] ngx_parse_inet_url(ngx_pool_t *pool, ngx_url_t *u)
[784] {
[785]     u_char              *host, *port, *last, *uri, *args, *dash;
[786]     size_t               len;
[787]     ngx_int_t            n;
[788]     struct sockaddr_in  *sin;
[789] 
[790]     u->socklen = sizeof(struct sockaddr_in);
[791]     sin = (struct sockaddr_in *) &u->sockaddr;
[792]     sin->sin_family = AF_INET;
[793] 
[794]     u->family = AF_INET;
[795] 
[796]     host = u->url.data;
[797] 
[798]     last = host + u->url.len;
[799] 
[800]     port = ngx_strlchr(host, last, ':');
[801] 
[802]     uri = ngx_strlchr(host, last, '/');
[803] 
[804]     args = ngx_strlchr(host, last, '?');
[805] 
[806]     if (args) {
[807]         if (uri == NULL || args < uri) {
[808]             uri = args;
[809]         }
[810]     }
[811] 
[812]     if (uri) {
[813]         if (u->listen || !u->uri_part) {
[814]             u->err = "invalid host";
[815]             return NGX_ERROR;
[816]         }
[817] 
[818]         u->uri.len = last - uri;
[819]         u->uri.data = uri;
[820] 
[821]         last = uri;
[822] 
[823]         if (uri < port) {
[824]             port = NULL;
[825]         }
[826]     }
[827] 
[828]     if (port) {
[829]         port++;
[830] 
[831]         len = last - port;
[832] 
[833]         if (u->listen) {
[834]             dash = ngx_strlchr(port, last, '-');
[835] 
[836]             if (dash) {
[837]                 dash++;
[838] 
[839]                 n = ngx_atoi(dash, last - dash);
[840] 
[841]                 if (n < 1 || n > 65535) {
[842]                     u->err = "invalid port";
[843]                     return NGX_ERROR;
[844]                 }
[845] 
[846]                 u->last_port = (in_port_t) n;
[847] 
[848]                 len = dash - port - 1;
[849]             }
[850]         }
[851] 
[852]         n = ngx_atoi(port, len);
[853] 
[854]         if (n < 1 || n > 65535) {
[855]             u->err = "invalid port";
[856]             return NGX_ERROR;
[857]         }
[858] 
[859]         if (u->last_port && n > u->last_port) {
[860]             u->err = "invalid port range";
[861]             return NGX_ERROR;
[862]         }
[863] 
[864]         u->port = (in_port_t) n;
[865]         sin->sin_port = htons((in_port_t) n);
[866] 
[867]         u->port_text.len = last - port;
[868]         u->port_text.data = port;
[869] 
[870]         last = port - 1;
[871] 
[872]     } else {
[873]         if (uri == NULL) {
[874] 
[875]             if (u->listen) {
[876] 
[877]                 /* test value as port only */
[878] 
[879]                 len = last - host;
[880] 
[881]                 dash = ngx_strlchr(host, last, '-');
[882] 
[883]                 if (dash) {
[884]                     dash++;
[885] 
[886]                     n = ngx_atoi(dash, last - dash);
[887] 
[888]                     if (n == NGX_ERROR) {
[889]                         goto no_port;
[890]                     }
[891] 
[892]                     if (n < 1 || n > 65535) {
[893]                         u->err = "invalid port";
[894] 
[895]                     } else {
[896]                         u->last_port = (in_port_t) n;
[897]                     }
[898] 
[899]                     len = dash - host - 1;
[900]                 }
[901] 
[902]                 n = ngx_atoi(host, len);
[903] 
[904]                 if (n != NGX_ERROR) {
[905] 
[906]                     if (u->err) {
[907]                         return NGX_ERROR;
[908]                     }
[909] 
[910]                     if (n < 1 || n > 65535) {
[911]                         u->err = "invalid port";
[912]                         return NGX_ERROR;
[913]                     }
[914] 
[915]                     if (u->last_port && n > u->last_port) {
[916]                         u->err = "invalid port range";
[917]                         return NGX_ERROR;
[918]                     }
[919] 
[920]                     u->port = (in_port_t) n;
[921]                     sin->sin_port = htons((in_port_t) n);
[922]                     sin->sin_addr.s_addr = INADDR_ANY;
[923] 
[924]                     u->port_text.len = last - host;
[925]                     u->port_text.data = host;
[926] 
[927]                     u->wildcard = 1;
[928] 
[929]                     return ngx_inet_add_addr(pool, u, &u->sockaddr.sockaddr,
[930]                                              u->socklen, 1);
[931]                 }
[932]             }
[933]         }
[934] 
[935] no_port:
[936] 
[937]         u->err = NULL;
[938]         u->no_port = 1;
[939]         u->port = u->default_port;
[940]         sin->sin_port = htons(u->default_port);
[941]         u->last_port = 0;
[942]     }
[943] 
[944]     len = last - host;
[945] 
[946]     if (len == 0) {
[947]         u->err = "no host";
[948]         return NGX_ERROR;
[949]     }
[950] 
[951]     u->host.len = len;
[952]     u->host.data = host;
[953] 
[954]     if (u->listen && len == 1 && *host == '*') {
[955]         sin->sin_addr.s_addr = INADDR_ANY;
[956]         u->wildcard = 1;
[957]         return ngx_inet_add_addr(pool, u, &u->sockaddr.sockaddr, u->socklen, 1);
[958]     }
[959] 
[960]     sin->sin_addr.s_addr = ngx_inet_addr(host, len);
[961] 
[962]     if (sin->sin_addr.s_addr != INADDR_NONE) {
[963] 
[964]         if (sin->sin_addr.s_addr == INADDR_ANY) {
[965]             u->wildcard = 1;
[966]         }
[967] 
[968]         return ngx_inet_add_addr(pool, u, &u->sockaddr.sockaddr, u->socklen, 1);
[969]     }
[970] 
[971]     if (u->no_resolve) {
[972]         return NGX_OK;
[973]     }
[974] 
[975]     if (ngx_inet_resolve_host(pool, u) != NGX_OK) {
[976]         return NGX_ERROR;
[977]     }
[978] 
[979]     u->family = u->addrs[0].sockaddr->sa_family;
[980]     u->socklen = u->addrs[0].socklen;
[981]     ngx_memcpy(&u->sockaddr, u->addrs[0].sockaddr, u->addrs[0].socklen);
[982]     u->wildcard = ngx_inet_wildcard(&u->sockaddr.sockaddr);
[983] 
[984]     return NGX_OK;
[985] }
[986] 
[987] 
[988] static ngx_int_t
[989] ngx_parse_inet6_url(ngx_pool_t *pool, ngx_url_t *u)
[990] {
[991] #if (NGX_HAVE_INET6)
[992]     u_char               *p, *host, *port, *last, *uri, *dash;
[993]     size_t                len;
[994]     ngx_int_t             n;
[995]     struct sockaddr_in6  *sin6;
[996] 
[997]     u->socklen = sizeof(struct sockaddr_in6);
[998]     sin6 = (struct sockaddr_in6 *) &u->sockaddr;
[999]     sin6->sin6_family = AF_INET6;
[1000] 
[1001]     host = u->url.data + 1;
[1002] 
[1003]     last = u->url.data + u->url.len;
[1004] 
[1005]     p = ngx_strlchr(host, last, ']');
[1006] 
[1007]     if (p == NULL) {
[1008]         u->err = "invalid host";
[1009]         return NGX_ERROR;
[1010]     }
[1011] 
[1012]     port = p + 1;
[1013] 
[1014]     uri = ngx_strlchr(port, last, '/');
[1015] 
[1016]     if (uri) {
[1017]         if (u->listen || !u->uri_part) {
[1018]             u->err = "invalid host";
[1019]             return NGX_ERROR;
[1020]         }
[1021] 
[1022]         u->uri.len = last - uri;
[1023]         u->uri.data = uri;
[1024] 
[1025]         last = uri;
[1026]     }
[1027] 
[1028]     if (port < last) {
[1029]         if (*port != ':') {
[1030]             u->err = "invalid host";
[1031]             return NGX_ERROR;
[1032]         }
[1033] 
[1034]         port++;
[1035] 
[1036]         len = last - port;
[1037] 
[1038]         if (u->listen) {
[1039]             dash = ngx_strlchr(port, last, '-');
[1040] 
[1041]             if (dash) {
[1042]                 dash++;
[1043] 
[1044]                 n = ngx_atoi(dash, last - dash);
[1045] 
[1046]                 if (n < 1 || n > 65535) {
[1047]                     u->err = "invalid port";
[1048]                     return NGX_ERROR;
[1049]                 }
[1050] 
[1051]                 u->last_port = (in_port_t) n;
[1052] 
[1053]                 len = dash - port - 1;
[1054]             }
[1055]         }
[1056] 
[1057]         n = ngx_atoi(port, len);
[1058] 
[1059]         if (n < 1 || n > 65535) {
[1060]             u->err = "invalid port";
[1061]             return NGX_ERROR;
[1062]         }
[1063] 
[1064]         if (u->last_port && n > u->last_port) {
[1065]             u->err = "invalid port range";
[1066]             return NGX_ERROR;
[1067]         }
[1068] 
[1069]         u->port = (in_port_t) n;
[1070]         sin6->sin6_port = htons((in_port_t) n);
[1071] 
[1072]         u->port_text.len = last - port;
[1073]         u->port_text.data = port;
[1074] 
[1075]     } else {
[1076]         u->no_port = 1;
[1077]         u->port = u->default_port;
[1078]         sin6->sin6_port = htons(u->default_port);
[1079]     }
[1080] 
[1081]     len = p - host;
[1082] 
[1083]     if (len == 0) {
[1084]         u->err = "no host";
[1085]         return NGX_ERROR;
[1086]     }
[1087] 
[1088]     u->host.len = len + 2;
[1089]     u->host.data = host - 1;
[1090] 
[1091]     if (ngx_inet6_addr(host, len, sin6->sin6_addr.s6_addr) != NGX_OK) {
[1092]         u->err = "invalid IPv6 address";
[1093]         return NGX_ERROR;
[1094]     }
[1095] 
[1096]     if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
[1097]         u->wildcard = 1;
[1098]     }
[1099] 
[1100]     u->family = AF_INET6;
[1101] 
[1102]     return ngx_inet_add_addr(pool, u, &u->sockaddr.sockaddr, u->socklen, 1);
[1103] 
[1104] #else
[1105] 
[1106]     u->err = "the INET6 sockets are not supported on this platform";
[1107] 
[1108]     return NGX_ERROR;
[1109] 
[1110] #endif
[1111] }
[1112] 
[1113] 
[1114] #if (NGX_HAVE_GETADDRINFO && NGX_HAVE_INET6)
[1115] 
[1116] ngx_int_t
[1117] ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u)
[1118] {
[1119]     u_char           *host;
[1120]     ngx_uint_t        n;
[1121]     struct addrinfo   hints, *res, *rp;
[1122] 
[1123]     host = ngx_alloc(u->host.len + 1, pool->log);
[1124]     if (host == NULL) {
[1125]         return NGX_ERROR;
[1126]     }
[1127] 
[1128]     (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);
[1129] 
[1130]     ngx_memzero(&hints, sizeof(struct addrinfo));
[1131]     hints.ai_family = AF_UNSPEC;
[1132]     hints.ai_socktype = SOCK_STREAM;
[1133] #ifdef AI_ADDRCONFIG
[1134]     hints.ai_flags = AI_ADDRCONFIG;
[1135] #endif
[1136] 
[1137]     if (getaddrinfo((char *) host, NULL, &hints, &res) != 0) {
[1138]         u->err = "host not found";
[1139]         ngx_free(host);
[1140]         return NGX_ERROR;
[1141]     }
[1142] 
[1143]     ngx_free(host);
[1144] 
[1145]     for (n = 0, rp = res; rp != NULL; rp = rp->ai_next) {
[1146] 
[1147]         switch (rp->ai_family) {
[1148] 
[1149]         case AF_INET:
[1150]         case AF_INET6:
[1151]             break;
[1152] 
[1153]         default:
[1154]             continue;
[1155]         }
[1156] 
[1157]         n++;
[1158]     }
[1159] 
[1160]     if (n == 0) {
[1161]         u->err = "host not found";
[1162]         goto failed;
[1163]     }
[1164] 
[1165]     /* MP: ngx_shared_palloc() */
[1166] 
[1167]     for (rp = res; rp != NULL; rp = rp->ai_next) {
[1168] 
[1169]         switch (rp->ai_family) {
[1170] 
[1171]         case AF_INET:
[1172]         case AF_INET6:
[1173]             break;
[1174] 
[1175]         default:
[1176]             continue;
[1177]         }
[1178] 
[1179]         if (ngx_inet_add_addr(pool, u, rp->ai_addr, rp->ai_addrlen, n)
[1180]             != NGX_OK)
[1181]         {
[1182]             goto failed;
[1183]         }
[1184]     }
[1185] 
[1186]     freeaddrinfo(res);
[1187]     return NGX_OK;
[1188] 
[1189] failed:
[1190] 
[1191]     freeaddrinfo(res);
[1192]     return NGX_ERROR;
[1193] }
[1194] 
[1195] #else /* !NGX_HAVE_GETADDRINFO || !NGX_HAVE_INET6 */
[1196] 
[1197] ngx_int_t
[1198] ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u)
[1199] {
[1200]     u_char              *host;
[1201]     ngx_uint_t           i, n;
[1202]     struct hostent      *h;
[1203]     struct sockaddr_in   sin;
[1204] 
[1205]     /* AF_INET only */
[1206] 
[1207]     ngx_memzero(&sin, sizeof(struct sockaddr_in));
[1208] 
[1209]     sin.sin_family = AF_INET;
[1210]     sin.sin_addr.s_addr = ngx_inet_addr(u->host.data, u->host.len);
[1211] 
[1212]     if (sin.sin_addr.s_addr == INADDR_NONE) {
[1213]         host = ngx_alloc(u->host.len + 1, pool->log);
[1214]         if (host == NULL) {
[1215]             return NGX_ERROR;
[1216]         }
[1217] 
[1218]         (void) ngx_cpystrn(host, u->host.data, u->host.len + 1);
[1219] 
[1220]         h = gethostbyname((char *) host);
[1221] 
[1222]         ngx_free(host);
[1223] 
[1224]         if (h == NULL || h->h_addr_list[0] == NULL) {
[1225]             u->err = "host not found";
[1226]             return NGX_ERROR;
[1227]         }
[1228] 
[1229]         for (n = 0; h->h_addr_list[n] != NULL; n++) { /* void */ }
[1230] 
[1231]         /* MP: ngx_shared_palloc() */
[1232] 
[1233]         for (i = 0; i < n; i++) {
[1234]             sin.sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);
[1235] 
[1236]             if (ngx_inet_add_addr(pool, u, (struct sockaddr *) &sin,
[1237]                                   sizeof(struct sockaddr_in), n)
[1238]                 != NGX_OK)
[1239]             {
[1240]                 return NGX_ERROR;
[1241]             }
[1242]         }
[1243] 
[1244]     } else {
[1245] 
[1246]         /* MP: ngx_shared_palloc() */
[1247] 
[1248]         if (ngx_inet_add_addr(pool, u, (struct sockaddr *) &sin,
[1249]                               sizeof(struct sockaddr_in), 1)
[1250]             != NGX_OK)
[1251]         {
[1252]             return NGX_ERROR;
[1253]         }
[1254]     }
[1255] 
[1256]     return NGX_OK;
[1257] }
[1258] 
[1259] #endif /* NGX_HAVE_GETADDRINFO && NGX_HAVE_INET6 */
[1260] 
[1261] 
[1262] static ngx_int_t
[1263] ngx_inet_add_addr(ngx_pool_t *pool, ngx_url_t *u, struct sockaddr *sockaddr,
[1264]     socklen_t socklen, ngx_uint_t total)
[1265] {
[1266]     u_char           *p;
[1267]     size_t            len;
[1268]     ngx_uint_t        i, nports;
[1269]     ngx_addr_t       *addr;
[1270]     struct sockaddr  *sa;
[1271] 
[1272]     nports = u->last_port ? u->last_port - u->port + 1 : 1;
[1273] 
[1274]     if (u->addrs == NULL) {
[1275]         u->addrs = ngx_palloc(pool, total * nports * sizeof(ngx_addr_t));
[1276]         if (u->addrs == NULL) {
[1277]             return NGX_ERROR;
[1278]         }
[1279]     }
[1280] 
[1281]     for (i = 0; i < nports; i++) {
[1282]         sa = ngx_pcalloc(pool, socklen);
[1283]         if (sa == NULL) {
[1284]             return NGX_ERROR;
[1285]         }
[1286] 
[1287]         ngx_memcpy(sa, sockaddr, socklen);
[1288] 
[1289]         ngx_inet_set_port(sa, u->port + i);
[1290] 
[1291]         switch (sa->sa_family) {
[1292] 
[1293] #if (NGX_HAVE_INET6)
[1294]         case AF_INET6:
[1295]             len = NGX_INET6_ADDRSTRLEN + sizeof("[]:65536") - 1;
[1296]             break;
[1297] #endif
[1298] 
[1299]         default: /* AF_INET */
[1300]             len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
[1301]         }
[1302] 
[1303]         p = ngx_pnalloc(pool, len);
[1304]         if (p == NULL) {
[1305]             return NGX_ERROR;
[1306]         }
[1307] 
[1308]         len = ngx_sock_ntop(sa, socklen, p, len, 1);
[1309] 
[1310]         addr = &u->addrs[u->naddrs++];
[1311] 
[1312]         addr->sockaddr = sa;
[1313]         addr->socklen = socklen;
[1314] 
[1315]         addr->name.len = len;
[1316]         addr->name.data = p;
[1317]     }
[1318] 
[1319]     return NGX_OK;
[1320] }
[1321] 
[1322] 
[1323] ngx_int_t
[1324] ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
[1325]     struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port)
[1326] {
[1327]     struct sockaddr_in   *sin1, *sin2;
[1328] #if (NGX_HAVE_INET6)
[1329]     struct sockaddr_in6  *sin61, *sin62;
[1330] #endif
[1331] #if (NGX_HAVE_UNIX_DOMAIN)
[1332]     size_t                len;
[1333]     struct sockaddr_un   *saun1, *saun2;
[1334] #endif
[1335] 
[1336]     if (sa1->sa_family != sa2->sa_family) {
[1337]         return NGX_DECLINED;
[1338]     }
[1339] 
[1340]     switch (sa1->sa_family) {
[1341] 
[1342] #if (NGX_HAVE_INET6)
[1343]     case AF_INET6:
[1344] 
[1345]         sin61 = (struct sockaddr_in6 *) sa1;
[1346]         sin62 = (struct sockaddr_in6 *) sa2;
[1347] 
[1348]         if (cmp_port && sin61->sin6_port != sin62->sin6_port) {
[1349]             return NGX_DECLINED;
[1350]         }
[1351] 
[1352]         if (ngx_memcmp(&sin61->sin6_addr, &sin62->sin6_addr, 16) != 0) {
[1353]             return NGX_DECLINED;
[1354]         }
[1355] 
[1356]         break;
[1357] #endif
[1358] 
[1359] #if (NGX_HAVE_UNIX_DOMAIN)
[1360]     case AF_UNIX:
[1361] 
[1362]         saun1 = (struct sockaddr_un *) sa1;
[1363]         saun2 = (struct sockaddr_un *) sa2;
[1364] 
[1365]         if (slen1 < slen2) {
[1366]             len = slen1 - offsetof(struct sockaddr_un, sun_path);
[1367] 
[1368]         } else {
[1369]             len = slen2 - offsetof(struct sockaddr_un, sun_path);
[1370]         }
[1371] 
[1372]         if (len > sizeof(saun1->sun_path)) {
[1373]             len = sizeof(saun1->sun_path);
[1374]         }
[1375] 
[1376]         if (ngx_memcmp(&saun1->sun_path, &saun2->sun_path, len) != 0) {
[1377]             return NGX_DECLINED;
[1378]         }
[1379] 
[1380]         break;
[1381] #endif
[1382] 
[1383]     default: /* AF_INET */
[1384] 
[1385]         sin1 = (struct sockaddr_in *) sa1;
[1386]         sin2 = (struct sockaddr_in *) sa2;
[1387] 
[1388]         if (cmp_port && sin1->sin_port != sin2->sin_port) {
[1389]             return NGX_DECLINED;
[1390]         }
[1391] 
[1392]         if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
[1393]             return NGX_DECLINED;
[1394]         }
[1395] 
[1396]         break;
[1397]     }
[1398] 
[1399]     return NGX_OK;
[1400] }
[1401] 
[1402] 
[1403] in_port_t
[1404] ngx_inet_get_port(struct sockaddr *sa)
[1405] {
[1406]     struct sockaddr_in   *sin;
[1407] #if (NGX_HAVE_INET6)
[1408]     struct sockaddr_in6  *sin6;
[1409] #endif
[1410] 
[1411]     switch (sa->sa_family) {
[1412] 
[1413] #if (NGX_HAVE_INET6)
[1414]     case AF_INET6:
[1415]         sin6 = (struct sockaddr_in6 *) sa;
[1416]         return ntohs(sin6->sin6_port);
[1417] #endif
[1418] 
[1419] #if (NGX_HAVE_UNIX_DOMAIN)
[1420]     case AF_UNIX:
[1421]         return 0;
[1422] #endif
[1423] 
[1424]     default: /* AF_INET */
[1425]         sin = (struct sockaddr_in *) sa;
[1426]         return ntohs(sin->sin_port);
[1427]     }
[1428] }
[1429] 
[1430] 
[1431] void
[1432] ngx_inet_set_port(struct sockaddr *sa, in_port_t port)
[1433] {
[1434]     struct sockaddr_in   *sin;
[1435] #if (NGX_HAVE_INET6)
[1436]     struct sockaddr_in6  *sin6;
[1437] #endif
[1438] 
[1439]     switch (sa->sa_family) {
[1440] 
[1441] #if (NGX_HAVE_INET6)
[1442]     case AF_INET6:
[1443]         sin6 = (struct sockaddr_in6 *) sa;
[1444]         sin6->sin6_port = htons(port);
[1445]         break;
[1446] #endif
[1447] 
[1448] #if (NGX_HAVE_UNIX_DOMAIN)
[1449]     case AF_UNIX:
[1450]         break;
[1451] #endif
[1452] 
[1453]     default: /* AF_INET */
[1454]         sin = (struct sockaddr_in *) sa;
[1455]         sin->sin_port = htons(port);
[1456]         break;
[1457]     }
[1458] }
[1459] 
[1460] 
[1461] ngx_uint_t
[1462] ngx_inet_wildcard(struct sockaddr *sa)
[1463] {
[1464]     struct sockaddr_in   *sin;
[1465] #if (NGX_HAVE_INET6)
[1466]     struct sockaddr_in6  *sin6;
[1467] #endif
[1468] 
[1469]     switch (sa->sa_family) {
[1470] 
[1471]     case AF_INET:
[1472]         sin = (struct sockaddr_in *) sa;
[1473] 
[1474]         if (sin->sin_addr.s_addr == INADDR_ANY) {
[1475]             return 1;
[1476]         }
[1477] 
[1478]         break;
[1479] 
[1480] #if (NGX_HAVE_INET6)
[1481] 
[1482]     case AF_INET6:
[1483]         sin6 = (struct sockaddr_in6 *) sa;
[1484] 
[1485]         if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
[1486]             return 1;
[1487]         }
[1488] 
[1489]         break;
[1490] 
[1491] #endif
[1492]     }
[1493] 
[1494]     return 0;
[1495] }
