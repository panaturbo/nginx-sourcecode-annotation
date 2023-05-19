[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] 
[12] 
[13] #define NGX_HTTP_V2_TABLE_SIZE  4096
[14] 
[15] 
[16] static ngx_int_t ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c,
[17]     size_t size);
[18] 
[19] 
[20] static ngx_http_v2_header_t  ngx_http_v2_static_table[] = {
[21]     { ngx_string(":authority"), ngx_string("") },
[22]     { ngx_string(":method"), ngx_string("GET") },
[23]     { ngx_string(":method"), ngx_string("POST") },
[24]     { ngx_string(":path"), ngx_string("/") },
[25]     { ngx_string(":path"), ngx_string("/index.html") },
[26]     { ngx_string(":scheme"), ngx_string("http") },
[27]     { ngx_string(":scheme"), ngx_string("https") },
[28]     { ngx_string(":status"), ngx_string("200") },
[29]     { ngx_string(":status"), ngx_string("204") },
[30]     { ngx_string(":status"), ngx_string("206") },
[31]     { ngx_string(":status"), ngx_string("304") },
[32]     { ngx_string(":status"), ngx_string("400") },
[33]     { ngx_string(":status"), ngx_string("404") },
[34]     { ngx_string(":status"), ngx_string("500") },
[35]     { ngx_string("accept-charset"), ngx_string("") },
[36]     { ngx_string("accept-encoding"), ngx_string("gzip, deflate") },
[37]     { ngx_string("accept-language"), ngx_string("") },
[38]     { ngx_string("accept-ranges"), ngx_string("") },
[39]     { ngx_string("accept"), ngx_string("") },
[40]     { ngx_string("access-control-allow-origin"), ngx_string("") },
[41]     { ngx_string("age"), ngx_string("") },
[42]     { ngx_string("allow"), ngx_string("") },
[43]     { ngx_string("authorization"), ngx_string("") },
[44]     { ngx_string("cache-control"), ngx_string("") },
[45]     { ngx_string("content-disposition"), ngx_string("") },
[46]     { ngx_string("content-encoding"), ngx_string("") },
[47]     { ngx_string("content-language"), ngx_string("") },
[48]     { ngx_string("content-length"), ngx_string("") },
[49]     { ngx_string("content-location"), ngx_string("") },
[50]     { ngx_string("content-range"), ngx_string("") },
[51]     { ngx_string("content-type"), ngx_string("") },
[52]     { ngx_string("cookie"), ngx_string("") },
[53]     { ngx_string("date"), ngx_string("") },
[54]     { ngx_string("etag"), ngx_string("") },
[55]     { ngx_string("expect"), ngx_string("") },
[56]     { ngx_string("expires"), ngx_string("") },
[57]     { ngx_string("from"), ngx_string("") },
[58]     { ngx_string("host"), ngx_string("") },
[59]     { ngx_string("if-match"), ngx_string("") },
[60]     { ngx_string("if-modified-since"), ngx_string("") },
[61]     { ngx_string("if-none-match"), ngx_string("") },
[62]     { ngx_string("if-range"), ngx_string("") },
[63]     { ngx_string("if-unmodified-since"), ngx_string("") },
[64]     { ngx_string("last-modified"), ngx_string("") },
[65]     { ngx_string("link"), ngx_string("") },
[66]     { ngx_string("location"), ngx_string("") },
[67]     { ngx_string("max-forwards"), ngx_string("") },
[68]     { ngx_string("proxy-authenticate"), ngx_string("") },
[69]     { ngx_string("proxy-authorization"), ngx_string("") },
[70]     { ngx_string("range"), ngx_string("") },
[71]     { ngx_string("referer"), ngx_string("") },
[72]     { ngx_string("refresh"), ngx_string("") },
[73]     { ngx_string("retry-after"), ngx_string("") },
[74]     { ngx_string("server"), ngx_string("") },
[75]     { ngx_string("set-cookie"), ngx_string("") },
[76]     { ngx_string("strict-transport-security"), ngx_string("") },
[77]     { ngx_string("transfer-encoding"), ngx_string("") },
[78]     { ngx_string("user-agent"), ngx_string("") },
[79]     { ngx_string("vary"), ngx_string("") },
[80]     { ngx_string("via"), ngx_string("") },
[81]     { ngx_string("www-authenticate"), ngx_string("") },
[82] };
[83] 
[84] #define NGX_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
[85]     (sizeof(ngx_http_v2_static_table)                                         \
[86]      / sizeof(ngx_http_v2_header_t))
[87] 
[88] 
[89] ngx_str_t *
[90] ngx_http_v2_get_static_name(ngx_uint_t index)
[91] {
[92]     return &ngx_http_v2_static_table[index - 1].name;
[93] }
[94] 
[95] 
[96] ngx_str_t *
[97] ngx_http_v2_get_static_value(ngx_uint_t index)
[98] {
[99]     return &ngx_http_v2_static_table[index - 1].value;
[100] }
[101] 
[102] 
[103] ngx_int_t
[104] ngx_http_v2_get_indexed_header(ngx_http_v2_connection_t *h2c, ngx_uint_t index,
[105]     ngx_uint_t name_only)
[106] {
[107]     u_char                *p;
[108]     size_t                 rest;
[109]     ngx_http_v2_header_t  *entry;
[110] 
[111]     if (index == 0) {
[112]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[113]                       "client sent invalid hpack table index 0");
[114]         return NGX_ERROR;
[115]     }
[116] 
[117]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[118]                    "http2 get indexed %s: %ui",
[119]                    name_only ? "name" : "header", index);
[120] 
[121]     index--;
[122] 
[123]     if (index < NGX_HTTP_V2_STATIC_TABLE_ENTRIES) {
[124]         h2c->state.header = ngx_http_v2_static_table[index];
[125]         return NGX_OK;
[126]     }
[127] 
[128]     index -= NGX_HTTP_V2_STATIC_TABLE_ENTRIES;
[129] 
[130]     if (index < h2c->hpack.added - h2c->hpack.deleted) {
[131]         index = (h2c->hpack.added - index - 1) % h2c->hpack.allocated;
[132]         entry = h2c->hpack.entries[index];
[133] 
[134]         p = ngx_pnalloc(h2c->state.pool, entry->name.len + 1);
[135]         if (p == NULL) {
[136]             return NGX_ERROR;
[137]         }
[138] 
[139]         h2c->state.header.name.len = entry->name.len;
[140]         h2c->state.header.name.data = p;
[141] 
[142]         rest = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - entry->name.data;
[143] 
[144]         if (entry->name.len > rest) {
[145]             p = ngx_cpymem(p, entry->name.data, rest);
[146]             p = ngx_cpymem(p, h2c->hpack.storage, entry->name.len - rest);
[147] 
[148]         } else {
[149]             p = ngx_cpymem(p, entry->name.data, entry->name.len);
[150]         }
[151] 
[152]         *p = '\0';
[153] 
[154]         if (name_only) {
[155]             return NGX_OK;
[156]         }
[157] 
[158]         p = ngx_pnalloc(h2c->state.pool, entry->value.len + 1);
[159]         if (p == NULL) {
[160]             return NGX_ERROR;
[161]         }
[162] 
[163]         h2c->state.header.value.len = entry->value.len;
[164]         h2c->state.header.value.data = p;
[165] 
[166]         rest = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - entry->value.data;
[167] 
[168]         if (entry->value.len > rest) {
[169]             p = ngx_cpymem(p, entry->value.data, rest);
[170]             p = ngx_cpymem(p, h2c->hpack.storage, entry->value.len - rest);
[171] 
[172]         } else {
[173]             p = ngx_cpymem(p, entry->value.data, entry->value.len);
[174]         }
[175] 
[176]         *p = '\0';
[177] 
[178]         return NGX_OK;
[179]     }
[180] 
[181]     ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[182]                   "client sent out of bound hpack table index: %ui", index);
[183] 
[184]     return NGX_ERROR;
[185] }
[186] 
[187] 
[188] ngx_int_t
[189] ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
[190]     ngx_http_v2_header_t *header)
[191] {
[192]     size_t                 avail;
[193]     ngx_uint_t             index;
[194]     ngx_http_v2_header_t  *entry, **entries;
[195] 
[196]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[197]                    "http2 table add: \"%V: %V\"",
[198]                    &header->name, &header->value);
[199] 
[200]     if (h2c->hpack.entries == NULL) {
[201]         h2c->hpack.allocated = 64;
[202]         h2c->hpack.size = NGX_HTTP_V2_TABLE_SIZE;
[203]         h2c->hpack.free = NGX_HTTP_V2_TABLE_SIZE;
[204] 
[205]         h2c->hpack.entries = ngx_palloc(h2c->connection->pool,
[206]                                         sizeof(ngx_http_v2_header_t *)
[207]                                         * h2c->hpack.allocated);
[208]         if (h2c->hpack.entries == NULL) {
[209]             return NGX_ERROR;
[210]         }
[211] 
[212]         h2c->hpack.storage = ngx_palloc(h2c->connection->pool,
[213]                                         h2c->hpack.free);
[214]         if (h2c->hpack.storage == NULL) {
[215]             return NGX_ERROR;
[216]         }
[217] 
[218]         h2c->hpack.pos = h2c->hpack.storage;
[219]     }
[220] 
[221]     if (ngx_http_v2_table_account(h2c, header->name.len + header->value.len)
[222]         != NGX_OK)
[223]     {
[224]         return NGX_OK;
[225]     }
[226] 
[227]     if (h2c->hpack.reused == h2c->hpack.deleted) {
[228]         entry = ngx_palloc(h2c->connection->pool, sizeof(ngx_http_v2_header_t));
[229]         if (entry == NULL) {
[230]             return NGX_ERROR;
[231]         }
[232] 
[233]     } else {
[234]         entry = h2c->hpack.entries[h2c->hpack.reused++ % h2c->hpack.allocated];
[235]     }
[236] 
[237]     avail = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - h2c->hpack.pos;
[238] 
[239]     entry->name.len = header->name.len;
[240]     entry->name.data = h2c->hpack.pos;
[241] 
[242]     if (avail >= header->name.len) {
[243]         h2c->hpack.pos = ngx_cpymem(h2c->hpack.pos, header->name.data,
[244]                                     header->name.len);
[245]     } else {
[246]         ngx_memcpy(h2c->hpack.pos, header->name.data, avail);
[247]         h2c->hpack.pos = ngx_cpymem(h2c->hpack.storage,
[248]                                     header->name.data + avail,
[249]                                     header->name.len - avail);
[250]         avail = NGX_HTTP_V2_TABLE_SIZE;
[251]     }
[252] 
[253]     avail -= header->name.len;
[254] 
[255]     entry->value.len = header->value.len;
[256]     entry->value.data = h2c->hpack.pos;
[257] 
[258]     if (avail >= header->value.len) {
[259]         h2c->hpack.pos = ngx_cpymem(h2c->hpack.pos, header->value.data,
[260]                                     header->value.len);
[261]     } else {
[262]         ngx_memcpy(h2c->hpack.pos, header->value.data, avail);
[263]         h2c->hpack.pos = ngx_cpymem(h2c->hpack.storage,
[264]                                     header->value.data + avail,
[265]                                     header->value.len - avail);
[266]     }
[267] 
[268]     if (h2c->hpack.allocated == h2c->hpack.added - h2c->hpack.deleted) {
[269] 
[270]         entries = ngx_palloc(h2c->connection->pool,
[271]                              sizeof(ngx_http_v2_header_t *)
[272]                              * (h2c->hpack.allocated + 64));
[273]         if (entries == NULL) {
[274]             return NGX_ERROR;
[275]         }
[276] 
[277]         index = h2c->hpack.deleted % h2c->hpack.allocated;
[278] 
[279]         ngx_memcpy(entries, &h2c->hpack.entries[index],
[280]                    (h2c->hpack.allocated - index)
[281]                    * sizeof(ngx_http_v2_header_t *));
[282] 
[283]         ngx_memcpy(&entries[h2c->hpack.allocated - index], h2c->hpack.entries,
[284]                    index * sizeof(ngx_http_v2_header_t *));
[285] 
[286]         (void) ngx_pfree(h2c->connection->pool, h2c->hpack.entries);
[287] 
[288]         h2c->hpack.entries = entries;
[289] 
[290]         h2c->hpack.added = h2c->hpack.allocated;
[291]         h2c->hpack.deleted = 0;
[292]         h2c->hpack.reused = 0;
[293]         h2c->hpack.allocated += 64;
[294]     }
[295] 
[296]     h2c->hpack.entries[h2c->hpack.added++ % h2c->hpack.allocated] = entry;
[297] 
[298]     return NGX_OK;
[299] }
[300] 
[301] 
[302] static ngx_int_t
[303] ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c, size_t size)
[304] {
[305]     ngx_http_v2_header_t  *entry;
[306] 
[307]     size += 32;
[308] 
[309]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[310]                    "http2 table account: %uz free:%uz",
[311]                    size, h2c->hpack.free);
[312] 
[313]     if (size <= h2c->hpack.free) {
[314]         h2c->hpack.free -= size;
[315]         return NGX_OK;
[316]     }
[317] 
[318]     if (size > h2c->hpack.size) {
[319]         h2c->hpack.deleted = h2c->hpack.added;
[320]         h2c->hpack.free = h2c->hpack.size;
[321]         return NGX_DECLINED;
[322]     }
[323] 
[324]     do {
[325]         entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
[326]         h2c->hpack.free += 32 + entry->name.len + entry->value.len;
[327]     } while (size > h2c->hpack.free);
[328] 
[329]     h2c->hpack.free -= size;
[330] 
[331]     return NGX_OK;
[332] }
[333] 
[334] 
[335] ngx_int_t
[336] ngx_http_v2_table_size(ngx_http_v2_connection_t *h2c, size_t size)
[337] {
[338]     ssize_t                needed;
[339]     ngx_http_v2_header_t  *entry;
[340] 
[341]     if (size > NGX_HTTP_V2_TABLE_SIZE) {
[342]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[343]                       "client sent invalid table size update: %uz", size);
[344] 
[345]         return NGX_ERROR;
[346]     }
[347] 
[348]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[349]                    "http2 new hpack table size: %uz was:%uz",
[350]                    size, h2c->hpack.size);
[351] 
[352]     needed = h2c->hpack.size - size;
[353] 
[354]     while (needed > (ssize_t) h2c->hpack.free) {
[355]         entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
[356]         h2c->hpack.free += 32 + entry->name.len + entry->value.len;
[357]     }
[358] 
[359]     h2c->hpack.size = size;
[360]     h2c->hpack.free -= needed;
[361] 
[362]     return NGX_OK;
[363] }
