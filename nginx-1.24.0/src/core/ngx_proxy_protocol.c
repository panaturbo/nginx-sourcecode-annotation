[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] #define NGX_PROXY_PROTOCOL_AF_INET          1
[13] #define NGX_PROXY_PROTOCOL_AF_INET6         2
[14] 
[15] 
[16] #define ngx_proxy_protocol_parse_uint16(p)                                    \
[17]     ( ((uint16_t) (p)[0] << 8)                                                \
[18]     + (           (p)[1]) )
[19] 
[20] #define ngx_proxy_protocol_parse_uint32(p)                                    \
[21]     ( ((uint32_t) (p)[0] << 24)                                               \
[22]     + (           (p)[1] << 16)                                               \
[23]     + (           (p)[2] << 8)                                                \
[24]     + (           (p)[3]) )
[25] 
[26] 
[27] typedef struct {
[28]     u_char                                  signature[12];
[29]     u_char                                  version_command;
[30]     u_char                                  family_transport;
[31]     u_char                                  len[2];
[32] } ngx_proxy_protocol_header_t;
[33] 
[34] 
[35] typedef struct {
[36]     u_char                                  src_addr[4];
[37]     u_char                                  dst_addr[4];
[38]     u_char                                  src_port[2];
[39]     u_char                                  dst_port[2];
[40] } ngx_proxy_protocol_inet_addrs_t;
[41] 
[42] 
[43] typedef struct {
[44]     u_char                                  src_addr[16];
[45]     u_char                                  dst_addr[16];
[46]     u_char                                  src_port[2];
[47]     u_char                                  dst_port[2];
[48] } ngx_proxy_protocol_inet6_addrs_t;
[49] 
[50] 
[51] typedef struct {
[52]     u_char                                  type;
[53]     u_char                                  len[2];
[54] } ngx_proxy_protocol_tlv_t;
[55] 
[56] 
[57] typedef struct {
[58]     u_char                                  client;
[59]     u_char                                  verify[4];
[60] } ngx_proxy_protocol_tlv_ssl_t;
[61] 
[62] 
[63] typedef struct {
[64]     ngx_str_t                               name;
[65]     ngx_uint_t                              type;
[66] } ngx_proxy_protocol_tlv_entry_t;
[67] 
[68] 
[69] static u_char *ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p,
[70]     u_char *last, ngx_str_t *addr);
[71] static u_char *ngx_proxy_protocol_read_port(u_char *p, u_char *last,
[72]     in_port_t *port, u_char sep);
[73] static u_char *ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf,
[74]     u_char *last);
[75] static ngx_int_t ngx_proxy_protocol_lookup_tlv(ngx_connection_t *c,
[76]     ngx_str_t *tlvs, ngx_uint_t type, ngx_str_t *value);
[77] 
[78] 
[79] static ngx_proxy_protocol_tlv_entry_t  ngx_proxy_protocol_tlv_entries[] = {
[80]     { ngx_string("alpn"),       0x01 },
[81]     { ngx_string("authority"),  0x02 },
[82]     { ngx_string("unique_id"),  0x05 },
[83]     { ngx_string("ssl"),        0x20 },
[84]     { ngx_string("netns"),      0x30 },
[85]     { ngx_null_string,          0x00 }
[86] };
[87] 
[88] 
[89] static ngx_proxy_protocol_tlv_entry_t  ngx_proxy_protocol_tlv_ssl_entries[] = {
[90]     { ngx_string("version"),    0x21 },
[91]     { ngx_string("cn"),         0x22 },
[92]     { ngx_string("cipher"),     0x23 },
[93]     { ngx_string("sig_alg"),    0x24 },
[94]     { ngx_string("key_alg"),    0x25 },
[95]     { ngx_null_string,          0x00 }
[96] };
[97] 
[98] 
[99] u_char *
[100] ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf, u_char *last)
[101] {
[102]     size_t                 len;
[103]     u_char                *p;
[104]     ngx_proxy_protocol_t  *pp;
[105] 
[106]     static const u_char signature[] = "\r\n\r\n\0\r\nQUIT\n";
[107] 
[108]     p = buf;
[109]     len = last - buf;
[110] 
[111]     if (len >= sizeof(ngx_proxy_protocol_header_t)
[112]         && ngx_memcmp(p, signature, sizeof(signature) - 1) == 0)
[113]     {
[114]         return ngx_proxy_protocol_v2_read(c, buf, last);
[115]     }
[116] 
[117]     if (len < 8 || ngx_strncmp(p, "PROXY ", 6) != 0) {
[118]         goto invalid;
[119]     }
[120] 
[121]     p += 6;
[122]     len -= 6;
[123] 
[124]     if (len >= 7 && ngx_strncmp(p, "UNKNOWN", 7) == 0) {
[125]         ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0,
[126]                        "PROXY protocol unknown protocol");
[127]         p += 7;
[128]         goto skip;
[129]     }
[130] 
[131]     if (len < 5 || ngx_strncmp(p, "TCP", 3) != 0
[132]         || (p[3] != '4' && p[3] != '6') || p[4] != ' ')
[133]     {
[134]         goto invalid;
[135]     }
[136] 
[137]     p += 5;
[138] 
[139]     pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
[140]     if (pp == NULL) {
[141]         return NULL;
[142]     }
[143] 
[144]     p = ngx_proxy_protocol_read_addr(c, p, last, &pp->src_addr);
[145]     if (p == NULL) {
[146]         goto invalid;
[147]     }
[148] 
[149]     p = ngx_proxy_protocol_read_addr(c, p, last, &pp->dst_addr);
[150]     if (p == NULL) {
[151]         goto invalid;
[152]     }
[153] 
[154]     p = ngx_proxy_protocol_read_port(p, last, &pp->src_port, ' ');
[155]     if (p == NULL) {
[156]         goto invalid;
[157]     }
[158] 
[159]     p = ngx_proxy_protocol_read_port(p, last, &pp->dst_port, CR);
[160]     if (p == NULL) {
[161]         goto invalid;
[162]     }
[163] 
[164]     if (p == last) {
[165]         goto invalid;
[166]     }
[167] 
[168]     if (*p++ != LF) {
[169]         goto invalid;
[170]     }
[171] 
[172]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
[173]                    "PROXY protocol src: %V %d, dst: %V %d",
[174]                    &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);
[175] 
[176]     c->proxy_protocol = pp;
[177] 
[178]     return p;
[179] 
[180] skip:
[181] 
[182]     for ( /* void */ ; p < last - 1; p++) {
[183]         if (p[0] == CR && p[1] == LF) {
[184]             return p + 2;
[185]         }
[186]     }
[187] 
[188] invalid:
[189] 
[190]     for (p = buf; p < last; p++) {
[191]         if (*p == CR || *p == LF) {
[192]             break;
[193]         }
[194]     }
[195] 
[196]     ngx_log_error(NGX_LOG_ERR, c->log, 0,
[197]                   "broken header: \"%*s\"", (size_t) (p - buf), buf);
[198] 
[199]     return NULL;
[200] }
[201] 
[202] 
[203] static u_char *
[204] ngx_proxy_protocol_read_addr(ngx_connection_t *c, u_char *p, u_char *last,
[205]     ngx_str_t *addr)
[206] {
[207]     size_t  len;
[208]     u_char  ch, *pos;
[209] 
[210]     pos = p;
[211] 
[212]     for ( ;; ) {
[213]         if (p == last) {
[214]             return NULL;
[215]         }
[216] 
[217]         ch = *p++;
[218] 
[219]         if (ch == ' ') {
[220]             break;
[221]         }
[222] 
[223]         if (ch != ':' && ch != '.'
[224]             && (ch < 'a' || ch > 'f')
[225]             && (ch < 'A' || ch > 'F')
[226]             && (ch < '0' || ch > '9'))
[227]         {
[228]             return NULL;
[229]         }
[230]     }
[231] 
[232]     len = p - pos - 1;
[233] 
[234]     addr->data = ngx_pnalloc(c->pool, len);
[235]     if (addr->data == NULL) {
[236]         return NULL;
[237]     }
[238] 
[239]     ngx_memcpy(addr->data, pos, len);
[240]     addr->len = len;
[241] 
[242]     return p;
[243] }
[244] 
[245] 
[246] static u_char *
[247] ngx_proxy_protocol_read_port(u_char *p, u_char *last, in_port_t *port,
[248]     u_char sep)
[249] {
[250]     size_t      len;
[251]     u_char     *pos;
[252]     ngx_int_t   n;
[253] 
[254]     pos = p;
[255] 
[256]     for ( ;; ) {
[257]         if (p == last) {
[258]             return NULL;
[259]         }
[260] 
[261]         if (*p++ == sep) {
[262]             break;
[263]         }
[264]     }
[265] 
[266]     len = p - pos - 1;
[267] 
[268]     n = ngx_atoi(pos, len);
[269]     if (n < 0 || n > 65535) {
[270]         return NULL;
[271]     }
[272] 
[273]     *port = (in_port_t) n;
[274] 
[275]     return p;
[276] }
[277] 
[278] 
[279] u_char *
[280] ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf, u_char *last)
[281] {
[282]     ngx_uint_t  port, lport;
[283] 
[284]     if (last - buf < NGX_PROXY_PROTOCOL_V1_MAX_HEADER) {
[285]         ngx_log_error(NGX_LOG_ALERT, c->log, 0,
[286]                       "too small buffer for PROXY protocol");
[287]         return NULL;
[288]     }
[289] 
[290]     if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
[291]         return NULL;
[292]     }
[293] 
[294]     switch (c->sockaddr->sa_family) {
[295] 
[296]     case AF_INET:
[297]         buf = ngx_cpymem(buf, "PROXY TCP4 ", sizeof("PROXY TCP4 ") - 1);
[298]         break;
[299] 
[300] #if (NGX_HAVE_INET6)
[301]     case AF_INET6:
[302]         buf = ngx_cpymem(buf, "PROXY TCP6 ", sizeof("PROXY TCP6 ") - 1);
[303]         break;
[304] #endif
[305] 
[306]     default:
[307]         return ngx_cpymem(buf, "PROXY UNKNOWN" CRLF,
[308]                           sizeof("PROXY UNKNOWN" CRLF) - 1);
[309]     }
[310] 
[311]     buf += ngx_sock_ntop(c->sockaddr, c->socklen, buf, last - buf, 0);
[312] 
[313]     *buf++ = ' ';
[314] 
[315]     buf += ngx_sock_ntop(c->local_sockaddr, c->local_socklen, buf, last - buf,
[316]                          0);
[317] 
[318]     port = ngx_inet_get_port(c->sockaddr);
[319]     lport = ngx_inet_get_port(c->local_sockaddr);
[320] 
[321]     return ngx_slprintf(buf, last, " %ui %ui" CRLF, port, lport);
[322] }
[323] 
[324] 
[325] static u_char *
[326] ngx_proxy_protocol_v2_read(ngx_connection_t *c, u_char *buf, u_char *last)
[327] {
[328]     u_char                             *end;
[329]     size_t                              len;
[330]     socklen_t                           socklen;
[331]     ngx_uint_t                          version, command, family, transport;
[332]     ngx_sockaddr_t                      src_sockaddr, dst_sockaddr;
[333]     ngx_proxy_protocol_t               *pp;
[334]     ngx_proxy_protocol_header_t        *header;
[335]     ngx_proxy_protocol_inet_addrs_t    *in;
[336] #if (NGX_HAVE_INET6)
[337]     ngx_proxy_protocol_inet6_addrs_t   *in6;
[338] #endif
[339] 
[340]     header = (ngx_proxy_protocol_header_t *) buf;
[341] 
[342]     buf += sizeof(ngx_proxy_protocol_header_t);
[343] 
[344]     version = header->version_command >> 4;
[345] 
[346]     if (version != 2) {
[347]         ngx_log_error(NGX_LOG_ERR, c->log, 0,
[348]                       "unknown PROXY protocol version: %ui", version);
[349]         return NULL;
[350]     }
[351] 
[352]     len = ngx_proxy_protocol_parse_uint16(header->len);
[353] 
[354]     if ((size_t) (last - buf) < len) {
[355]         ngx_log_error(NGX_LOG_ERR, c->log, 0, "header is too large");
[356]         return NULL;
[357]     }
[358] 
[359]     end = buf + len;
[360] 
[361]     command = header->version_command & 0x0f;
[362] 
[363]     /* only PROXY is supported */
[364]     if (command != 1) {
[365]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[366]                        "PROXY protocol v2 unsupported command %ui", command);
[367]         return end;
[368]     }
[369] 
[370]     transport = header->family_transport & 0x0f;
[371] 
[372]     /* only STREAM is supported */
[373]     if (transport != 1) {
[374]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[375]                        "PROXY protocol v2 unsupported transport %ui",
[376]                        transport);
[377]         return end;
[378]     }
[379] 
[380]     pp = ngx_pcalloc(c->pool, sizeof(ngx_proxy_protocol_t));
[381]     if (pp == NULL) {
[382]         return NULL;
[383]     }
[384] 
[385]     family = header->family_transport >> 4;
[386] 
[387]     switch (family) {
[388] 
[389]     case NGX_PROXY_PROTOCOL_AF_INET:
[390] 
[391]         if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet_addrs_t)) {
[392]             return NULL;
[393]         }
[394] 
[395]         in = (ngx_proxy_protocol_inet_addrs_t *) buf;
[396] 
[397]         src_sockaddr.sockaddr_in.sin_family = AF_INET;
[398]         src_sockaddr.sockaddr_in.sin_port = 0;
[399]         ngx_memcpy(&src_sockaddr.sockaddr_in.sin_addr, in->src_addr, 4);
[400] 
[401]         dst_sockaddr.sockaddr_in.sin_family = AF_INET;
[402]         dst_sockaddr.sockaddr_in.sin_port = 0;
[403]         ngx_memcpy(&dst_sockaddr.sockaddr_in.sin_addr, in->dst_addr, 4);
[404] 
[405]         pp->src_port = ngx_proxy_protocol_parse_uint16(in->src_port);
[406]         pp->dst_port = ngx_proxy_protocol_parse_uint16(in->dst_port);
[407] 
[408]         socklen = sizeof(struct sockaddr_in);
[409] 
[410]         buf += sizeof(ngx_proxy_protocol_inet_addrs_t);
[411] 
[412]         break;
[413] 
[414] #if (NGX_HAVE_INET6)
[415] 
[416]     case NGX_PROXY_PROTOCOL_AF_INET6:
[417] 
[418]         if ((size_t) (end - buf) < sizeof(ngx_proxy_protocol_inet6_addrs_t)) {
[419]             return NULL;
[420]         }
[421] 
[422]         in6 = (ngx_proxy_protocol_inet6_addrs_t *) buf;
[423] 
[424]         src_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
[425]         src_sockaddr.sockaddr_in6.sin6_port = 0;
[426]         ngx_memcpy(&src_sockaddr.sockaddr_in6.sin6_addr, in6->src_addr, 16);
[427] 
[428]         dst_sockaddr.sockaddr_in6.sin6_family = AF_INET6;
[429]         dst_sockaddr.sockaddr_in6.sin6_port = 0;
[430]         ngx_memcpy(&dst_sockaddr.sockaddr_in6.sin6_addr, in6->dst_addr, 16);
[431] 
[432]         pp->src_port = ngx_proxy_protocol_parse_uint16(in6->src_port);
[433]         pp->dst_port = ngx_proxy_protocol_parse_uint16(in6->dst_port);
[434] 
[435]         socklen = sizeof(struct sockaddr_in6);
[436] 
[437]         buf += sizeof(ngx_proxy_protocol_inet6_addrs_t);
[438] 
[439]         break;
[440] 
[441] #endif
[442] 
[443]     default:
[444]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[445]                        "PROXY protocol v2 unsupported address family %ui",
[446]                        family);
[447]         return end;
[448]     }
[449] 
[450]     pp->src_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
[451]     if (pp->src_addr.data == NULL) {
[452]         return NULL;
[453]     }
[454] 
[455]     pp->src_addr.len = ngx_sock_ntop(&src_sockaddr.sockaddr, socklen,
[456]                                      pp->src_addr.data, NGX_SOCKADDR_STRLEN, 0);
[457] 
[458]     pp->dst_addr.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
[459]     if (pp->dst_addr.data == NULL) {
[460]         return NULL;
[461]     }
[462] 
[463]     pp->dst_addr.len = ngx_sock_ntop(&dst_sockaddr.sockaddr, socklen,
[464]                                      pp->dst_addr.data, NGX_SOCKADDR_STRLEN, 0);
[465] 
[466]     ngx_log_debug4(NGX_LOG_DEBUG_CORE, c->log, 0,
[467]                    "PROXY protocol v2 src: %V %d, dst: %V %d",
[468]                    &pp->src_addr, pp->src_port, &pp->dst_addr, pp->dst_port);
[469] 
[470]     if (buf < end) {
[471]         pp->tlvs.data = ngx_pnalloc(c->pool, end - buf);
[472]         if (pp->tlvs.data == NULL) {
[473]             return NULL;
[474]         }
[475] 
[476]         ngx_memcpy(pp->tlvs.data, buf, end - buf);
[477]         pp->tlvs.len = end - buf;
[478]     }
[479] 
[480]     c->proxy_protocol = pp;
[481] 
[482]     return end;
[483] }
[484] 
[485] 
[486] ngx_int_t
[487] ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
[488]     ngx_str_t *value)
[489] {
[490]     u_char                          *p;
[491]     size_t                           n;
[492]     uint32_t                         verify;
[493]     ngx_str_t                        ssl, *tlvs;
[494]     ngx_int_t                        rc, type;
[495]     ngx_proxy_protocol_tlv_ssl_t    *tlv_ssl;
[496]     ngx_proxy_protocol_tlv_entry_t  *te;
[497] 
[498]     if (c->proxy_protocol == NULL) {
[499]         return NGX_DECLINED;
[500]     }
[501] 
[502]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[503]                    "PROXY protocol v2 get tlv \"%V\"", name);
[504] 
[505]     te = ngx_proxy_protocol_tlv_entries;
[506]     tlvs = &c->proxy_protocol->tlvs;
[507] 
[508]     p = name->data;
[509]     n = name->len;
[510] 
[511]     if (n >= 4 && p[0] == 's' && p[1] == 's' && p[2] == 'l' && p[3] == '_') {
[512] 
[513]         rc = ngx_proxy_protocol_lookup_tlv(c, tlvs, 0x20, &ssl);
[514]         if (rc != NGX_OK) {
[515]             return rc;
[516]         }
[517] 
[518]         if (ssl.len < sizeof(ngx_proxy_protocol_tlv_ssl_t)) {
[519]             return NGX_ERROR;
[520]         }
[521] 
[522]         p += 4;
[523]         n -= 4;
[524] 
[525]         if (n == 6 && ngx_strncmp(p, "verify", 6) == 0) {
[526] 
[527]             tlv_ssl = (ngx_proxy_protocol_tlv_ssl_t *) ssl.data;
[528]             verify = ngx_proxy_protocol_parse_uint32(tlv_ssl->verify);
[529] 
[530]             value->data = ngx_pnalloc(c->pool, NGX_INT32_LEN);
[531]             if (value->data == NULL) {
[532]                 return NGX_ERROR;
[533]             }
[534] 
[535]             value->len = ngx_sprintf(value->data, "%uD", verify)
[536]                          - value->data;
[537]             return NGX_OK;
[538]         }
[539] 
[540]         ssl.data += sizeof(ngx_proxy_protocol_tlv_ssl_t);
[541]         ssl.len -= sizeof(ngx_proxy_protocol_tlv_ssl_t);
[542] 
[543]         te = ngx_proxy_protocol_tlv_ssl_entries;
[544]         tlvs = &ssl;
[545]     }
[546] 
[547]     if (n >= 2 && p[0] == '0' && p[1] == 'x') {
[548] 
[549]         type = ngx_hextoi(p + 2, n - 2);
[550]         if (type == NGX_ERROR) {
[551]             ngx_log_error(NGX_LOG_ERR, c->log, 0,
[552]                           "invalid PROXY protocol TLV \"%V\"", name);
[553]             return NGX_ERROR;
[554]         }
[555] 
[556]         return ngx_proxy_protocol_lookup_tlv(c, tlvs, type, value);
[557]     }
[558] 
[559]     for ( /* void */ ; te->type; te++) {
[560]         if (te->name.len == n && ngx_strncmp(te->name.data, p, n) == 0) {
[561]             return ngx_proxy_protocol_lookup_tlv(c, tlvs, te->type, value);
[562]         }
[563]     }
[564] 
[565]     ngx_log_error(NGX_LOG_ERR, c->log, 0,
[566]                   "unknown PROXY protocol TLV \"%V\"", name);
[567] 
[568]     return NGX_DECLINED;
[569] }
[570] 
[571] 
[572] static ngx_int_t
[573] ngx_proxy_protocol_lookup_tlv(ngx_connection_t *c, ngx_str_t *tlvs,
[574]     ngx_uint_t type, ngx_str_t *value)
[575] {
[576]     u_char                    *p;
[577]     size_t                     n, len;
[578]     ngx_proxy_protocol_tlv_t  *tlv;
[579] 
[580]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
[581]                    "PROXY protocol v2 lookup tlv:%02xi", type);
[582] 
[583]     p = tlvs->data;
[584]     n = tlvs->len;
[585] 
[586]     while (n) {
[587]         if (n < sizeof(ngx_proxy_protocol_tlv_t)) {
[588]             ngx_log_error(NGX_LOG_ERR, c->log, 0, "broken PROXY protocol TLV");
[589]             return NGX_ERROR;
[590]         }
[591] 
[592]         tlv = (ngx_proxy_protocol_tlv_t *) p;
[593]         len = ngx_proxy_protocol_parse_uint16(tlv->len);
[594] 
[595]         p += sizeof(ngx_proxy_protocol_tlv_t);
[596]         n -= sizeof(ngx_proxy_protocol_tlv_t);
[597] 
[598]         if (n < len) {
[599]             ngx_log_error(NGX_LOG_ERR, c->log, 0, "broken PROXY protocol TLV");
[600]             return NGX_ERROR;
[601]         }
[602] 
[603]         if (tlv->type == type) {
[604]             value->data = p;
[605]             value->len = len;
[606]             return NGX_OK;
[607]         }
[608] 
[609]         p += len;
[610]         n -= len;
[611]     }
[612] 
[613]     return NGX_DECLINED;
[614] }
