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
[11] #include <nginx.h>
[12] 
[13] 
[14] static ngx_http_variable_t *ngx_http_add_prefix_variable(ngx_conf_t *cf,
[15]     ngx_str_t *name, ngx_uint_t flags);
[16] 
[17] static ngx_int_t ngx_http_variable_request(ngx_http_request_t *r,
[18]     ngx_http_variable_value_t *v, uintptr_t data);
[19] #if 0
[20] static void ngx_http_variable_request_set(ngx_http_request_t *r,
[21]     ngx_http_variable_value_t *v, uintptr_t data);
[22] #endif
[23] static ngx_int_t ngx_http_variable_request_get_size(ngx_http_request_t *r,
[24]     ngx_http_variable_value_t *v, uintptr_t data);
[25] static ngx_int_t ngx_http_variable_header(ngx_http_request_t *r,
[26]     ngx_http_variable_value_t *v, uintptr_t data);
[27] 
[28] static ngx_int_t ngx_http_variable_cookies(ngx_http_request_t *r,
[29]     ngx_http_variable_value_t *v, uintptr_t data);
[30] static ngx_int_t ngx_http_variable_headers_internal(ngx_http_request_t *r,
[31]     ngx_http_variable_value_t *v, uintptr_t data, u_char sep);
[32] 
[33] static ngx_int_t ngx_http_variable_unknown_header_in(ngx_http_request_t *r,
[34]     ngx_http_variable_value_t *v, uintptr_t data);
[35] static ngx_int_t ngx_http_variable_unknown_header_out(ngx_http_request_t *r,
[36]     ngx_http_variable_value_t *v, uintptr_t data);
[37] static ngx_int_t ngx_http_variable_unknown_trailer_out(ngx_http_request_t *r,
[38]     ngx_http_variable_value_t *v, uintptr_t data);
[39] static ngx_int_t ngx_http_variable_request_line(ngx_http_request_t *r,
[40]     ngx_http_variable_value_t *v, uintptr_t data);
[41] static ngx_int_t ngx_http_variable_cookie(ngx_http_request_t *r,
[42]     ngx_http_variable_value_t *v, uintptr_t data);
[43] static ngx_int_t ngx_http_variable_argument(ngx_http_request_t *r,
[44]     ngx_http_variable_value_t *v, uintptr_t data);
[45] #if (NGX_HAVE_TCP_INFO)
[46] static ngx_int_t ngx_http_variable_tcpinfo(ngx_http_request_t *r,
[47]     ngx_http_variable_value_t *v, uintptr_t data);
[48] #endif
[49] 
[50] static ngx_int_t ngx_http_variable_content_length(ngx_http_request_t *r,
[51]     ngx_http_variable_value_t *v, uintptr_t data);
[52] static ngx_int_t ngx_http_variable_host(ngx_http_request_t *r,
[53]     ngx_http_variable_value_t *v, uintptr_t data);
[54] static ngx_int_t ngx_http_variable_binary_remote_addr(ngx_http_request_t *r,
[55]     ngx_http_variable_value_t *v, uintptr_t data);
[56] static ngx_int_t ngx_http_variable_remote_addr(ngx_http_request_t *r,
[57]     ngx_http_variable_value_t *v, uintptr_t data);
[58] static ngx_int_t ngx_http_variable_remote_port(ngx_http_request_t *r,
[59]     ngx_http_variable_value_t *v, uintptr_t data);
[60] static ngx_int_t ngx_http_variable_proxy_protocol_addr(ngx_http_request_t *r,
[61]     ngx_http_variable_value_t *v, uintptr_t data);
[62] static ngx_int_t ngx_http_variable_proxy_protocol_port(ngx_http_request_t *r,
[63]     ngx_http_variable_value_t *v, uintptr_t data);
[64] static ngx_int_t ngx_http_variable_proxy_protocol_tlv(ngx_http_request_t *r,
[65]     ngx_http_variable_value_t *v, uintptr_t data);
[66] static ngx_int_t ngx_http_variable_server_addr(ngx_http_request_t *r,
[67]     ngx_http_variable_value_t *v, uintptr_t data);
[68] static ngx_int_t ngx_http_variable_server_port(ngx_http_request_t *r,
[69]     ngx_http_variable_value_t *v, uintptr_t data);
[70] static ngx_int_t ngx_http_variable_scheme(ngx_http_request_t *r,
[71]     ngx_http_variable_value_t *v, uintptr_t data);
[72] static ngx_int_t ngx_http_variable_https(ngx_http_request_t *r,
[73]     ngx_http_variable_value_t *v, uintptr_t data);
[74] static void ngx_http_variable_set_args(ngx_http_request_t *r,
[75]     ngx_http_variable_value_t *v, uintptr_t data);
[76] static ngx_int_t ngx_http_variable_is_args(ngx_http_request_t *r,
[77]     ngx_http_variable_value_t *v, uintptr_t data);
[78] static ngx_int_t ngx_http_variable_document_root(ngx_http_request_t *r,
[79]     ngx_http_variable_value_t *v, uintptr_t data);
[80] static ngx_int_t ngx_http_variable_realpath_root(ngx_http_request_t *r,
[81]     ngx_http_variable_value_t *v, uintptr_t data);
[82] static ngx_int_t ngx_http_variable_request_filename(ngx_http_request_t *r,
[83]     ngx_http_variable_value_t *v, uintptr_t data);
[84] static ngx_int_t ngx_http_variable_server_name(ngx_http_request_t *r,
[85]     ngx_http_variable_value_t *v, uintptr_t data);
[86] static ngx_int_t ngx_http_variable_request_method(ngx_http_request_t *r,
[87]     ngx_http_variable_value_t *v, uintptr_t data);
[88] static ngx_int_t ngx_http_variable_remote_user(ngx_http_request_t *r,
[89]     ngx_http_variable_value_t *v, uintptr_t data);
[90] static ngx_int_t ngx_http_variable_bytes_sent(ngx_http_request_t *r,
[91]     ngx_http_variable_value_t *v, uintptr_t data);
[92] static ngx_int_t ngx_http_variable_body_bytes_sent(ngx_http_request_t *r,
[93]     ngx_http_variable_value_t *v, uintptr_t data);
[94] static ngx_int_t ngx_http_variable_pipe(ngx_http_request_t *r,
[95]     ngx_http_variable_value_t *v, uintptr_t data);
[96] static ngx_int_t ngx_http_variable_request_completion(ngx_http_request_t *r,
[97]     ngx_http_variable_value_t *v, uintptr_t data);
[98] static ngx_int_t ngx_http_variable_request_body(ngx_http_request_t *r,
[99]     ngx_http_variable_value_t *v, uintptr_t data);
[100] static ngx_int_t ngx_http_variable_request_body_file(ngx_http_request_t *r,
[101]     ngx_http_variable_value_t *v, uintptr_t data);
[102] static ngx_int_t ngx_http_variable_request_length(ngx_http_request_t *r,
[103]     ngx_http_variable_value_t *v, uintptr_t data);
[104] static ngx_int_t ngx_http_variable_request_time(ngx_http_request_t *r,
[105]     ngx_http_variable_value_t *v, uintptr_t data);
[106] static ngx_int_t ngx_http_variable_request_id(ngx_http_request_t *r,
[107]     ngx_http_variable_value_t *v, uintptr_t data);
[108] static ngx_int_t ngx_http_variable_status(ngx_http_request_t *r,
[109]     ngx_http_variable_value_t *v, uintptr_t data);
[110] 
[111] static ngx_int_t ngx_http_variable_sent_content_type(ngx_http_request_t *r,
[112]     ngx_http_variable_value_t *v, uintptr_t data);
[113] static ngx_int_t ngx_http_variable_sent_content_length(ngx_http_request_t *r,
[114]     ngx_http_variable_value_t *v, uintptr_t data);
[115] static ngx_int_t ngx_http_variable_sent_location(ngx_http_request_t *r,
[116]     ngx_http_variable_value_t *v, uintptr_t data);
[117] static ngx_int_t ngx_http_variable_sent_last_modified(ngx_http_request_t *r,
[118]     ngx_http_variable_value_t *v, uintptr_t data);
[119] static ngx_int_t ngx_http_variable_sent_connection(ngx_http_request_t *r,
[120]     ngx_http_variable_value_t *v, uintptr_t data);
[121] static ngx_int_t ngx_http_variable_sent_keep_alive(ngx_http_request_t *r,
[122]     ngx_http_variable_value_t *v, uintptr_t data);
[123] static ngx_int_t ngx_http_variable_sent_transfer_encoding(ngx_http_request_t *r,
[124]     ngx_http_variable_value_t *v, uintptr_t data);
[125] static void ngx_http_variable_set_limit_rate(ngx_http_request_t *r,
[126]     ngx_http_variable_value_t *v, uintptr_t data);
[127] 
[128] static ngx_int_t ngx_http_variable_connection(ngx_http_request_t *r,
[129]     ngx_http_variable_value_t *v, uintptr_t data);
[130] static ngx_int_t ngx_http_variable_connection_requests(ngx_http_request_t *r,
[131]     ngx_http_variable_value_t *v, uintptr_t data);
[132] static ngx_int_t ngx_http_variable_connection_time(ngx_http_request_t *r,
[133]     ngx_http_variable_value_t *v, uintptr_t data);
[134] 
[135] static ngx_int_t ngx_http_variable_nginx_version(ngx_http_request_t *r,
[136]     ngx_http_variable_value_t *v, uintptr_t data);
[137] static ngx_int_t ngx_http_variable_hostname(ngx_http_request_t *r,
[138]     ngx_http_variable_value_t *v, uintptr_t data);
[139] static ngx_int_t ngx_http_variable_pid(ngx_http_request_t *r,
[140]     ngx_http_variable_value_t *v, uintptr_t data);
[141] static ngx_int_t ngx_http_variable_msec(ngx_http_request_t *r,
[142]     ngx_http_variable_value_t *v, uintptr_t data);
[143] static ngx_int_t ngx_http_variable_time_iso8601(ngx_http_request_t *r,
[144]     ngx_http_variable_value_t *v, uintptr_t data);
[145] static ngx_int_t ngx_http_variable_time_local(ngx_http_request_t *r,
[146]     ngx_http_variable_value_t *v, uintptr_t data);
[147] 
[148] /*
[149]  * TODO:
[150]  *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
[151]  *                 REMOTE_HOST (null), REMOTE_IDENT (null),
[152]  *                 SERVER_SOFTWARE
[153]  *
[154]  *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
[155]  */
[156] 
[157] /*
[158]  * the $http_host, $http_user_agent, $http_referer, and $http_via
[159]  * variables may be handled by generic
[160]  * ngx_http_variable_unknown_header_in(), but for performance reasons
[161]  * they are handled using dedicated entries
[162]  */
[163] 
[164] static ngx_http_variable_t  ngx_http_core_variables[] = {
[165] 
[166]     { ngx_string("http_host"), NULL, ngx_http_variable_header,
[167]       offsetof(ngx_http_request_t, headers_in.host), 0, 0 },
[168] 
[169]     { ngx_string("http_user_agent"), NULL, ngx_http_variable_header,
[170]       offsetof(ngx_http_request_t, headers_in.user_agent), 0, 0 },
[171] 
[172]     { ngx_string("http_referer"), NULL, ngx_http_variable_header,
[173]       offsetof(ngx_http_request_t, headers_in.referer), 0, 0 },
[174] 
[175] #if (NGX_HTTP_GZIP)
[176]     { ngx_string("http_via"), NULL, ngx_http_variable_header,
[177]       offsetof(ngx_http_request_t, headers_in.via), 0, 0 },
[178] #endif
[179] 
[180] #if (NGX_HTTP_X_FORWARDED_FOR)
[181]     { ngx_string("http_x_forwarded_for"), NULL, ngx_http_variable_header,
[182]       offsetof(ngx_http_request_t, headers_in.x_forwarded_for), 0, 0 },
[183] #endif
[184] 
[185]     { ngx_string("http_cookie"), NULL, ngx_http_variable_cookies,
[186]       offsetof(ngx_http_request_t, headers_in.cookie), 0, 0 },
[187] 
[188]     { ngx_string("content_length"), NULL, ngx_http_variable_content_length,
[189]       0, 0, 0 },
[190] 
[191]     { ngx_string("content_type"), NULL, ngx_http_variable_header,
[192]       offsetof(ngx_http_request_t, headers_in.content_type), 0, 0 },
[193] 
[194]     { ngx_string("host"), NULL, ngx_http_variable_host, 0, 0, 0 },
[195] 
[196]     { ngx_string("binary_remote_addr"), NULL,
[197]       ngx_http_variable_binary_remote_addr, 0, 0, 0 },
[198] 
[199]     { ngx_string("remote_addr"), NULL, ngx_http_variable_remote_addr, 0, 0, 0 },
[200] 
[201]     { ngx_string("remote_port"), NULL, ngx_http_variable_remote_port, 0, 0, 0 },
[202] 
[203]     { ngx_string("proxy_protocol_addr"), NULL,
[204]       ngx_http_variable_proxy_protocol_addr,
[205]       offsetof(ngx_proxy_protocol_t, src_addr), 0, 0 },
[206] 
[207]     { ngx_string("proxy_protocol_port"), NULL,
[208]       ngx_http_variable_proxy_protocol_port,
[209]       offsetof(ngx_proxy_protocol_t, src_port), 0, 0 },
[210] 
[211]     { ngx_string("proxy_protocol_server_addr"), NULL,
[212]       ngx_http_variable_proxy_protocol_addr,
[213]       offsetof(ngx_proxy_protocol_t, dst_addr), 0, 0 },
[214] 
[215]     { ngx_string("proxy_protocol_server_port"), NULL,
[216]       ngx_http_variable_proxy_protocol_port,
[217]       offsetof(ngx_proxy_protocol_t, dst_port), 0, 0 },
[218] 
[219]     { ngx_string("proxy_protocol_tlv_"), NULL,
[220]       ngx_http_variable_proxy_protocol_tlv,
[221]       0, NGX_HTTP_VAR_PREFIX, 0 },
[222] 
[223]     { ngx_string("server_addr"), NULL, ngx_http_variable_server_addr, 0, 0, 0 },
[224] 
[225]     { ngx_string("server_port"), NULL, ngx_http_variable_server_port, 0, 0, 0 },
[226] 
[227]     { ngx_string("server_protocol"), NULL, ngx_http_variable_request,
[228]       offsetof(ngx_http_request_t, http_protocol), 0, 0 },
[229] 
[230]     { ngx_string("scheme"), NULL, ngx_http_variable_scheme, 0, 0, 0 },
[231] 
[232]     { ngx_string("https"), NULL, ngx_http_variable_https, 0, 0, 0 },
[233] 
[234]     { ngx_string("request_uri"), NULL, ngx_http_variable_request,
[235]       offsetof(ngx_http_request_t, unparsed_uri), 0, 0 },
[236] 
[237]     { ngx_string("uri"), NULL, ngx_http_variable_request,
[238]       offsetof(ngx_http_request_t, uri),
[239]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[240] 
[241]     { ngx_string("document_uri"), NULL, ngx_http_variable_request,
[242]       offsetof(ngx_http_request_t, uri),
[243]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[244] 
[245]     { ngx_string("request"), NULL, ngx_http_variable_request_line, 0, 0, 0 },
[246] 
[247]     { ngx_string("document_root"), NULL,
[248]       ngx_http_variable_document_root, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[249] 
[250]     { ngx_string("realpath_root"), NULL,
[251]       ngx_http_variable_realpath_root, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[252] 
[253]     { ngx_string("query_string"), NULL, ngx_http_variable_request,
[254]       offsetof(ngx_http_request_t, args),
[255]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[256] 
[257]     { ngx_string("args"),
[258]       ngx_http_variable_set_args,
[259]       ngx_http_variable_request,
[260]       offsetof(ngx_http_request_t, args),
[261]       NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },
[262] 
[263]     { ngx_string("is_args"), NULL, ngx_http_variable_is_args,
[264]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[265] 
[266]     { ngx_string("request_filename"), NULL,
[267]       ngx_http_variable_request_filename, 0,
[268]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[269] 
[270]     { ngx_string("server_name"), NULL, ngx_http_variable_server_name, 0, 0, 0 },
[271] 
[272]     { ngx_string("request_method"), NULL,
[273]       ngx_http_variable_request_method, 0,
[274]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[275] 
[276]     { ngx_string("remote_user"), NULL, ngx_http_variable_remote_user, 0, 0, 0 },
[277] 
[278]     { ngx_string("bytes_sent"), NULL, ngx_http_variable_bytes_sent,
[279]       0, 0, 0 },
[280] 
[281]     { ngx_string("body_bytes_sent"), NULL, ngx_http_variable_body_bytes_sent,
[282]       0, 0, 0 },
[283] 
[284]     { ngx_string("pipe"), NULL, ngx_http_variable_pipe,
[285]       0, 0, 0 },
[286] 
[287]     { ngx_string("request_completion"), NULL,
[288]       ngx_http_variable_request_completion,
[289]       0, 0, 0 },
[290] 
[291]     { ngx_string("request_body"), NULL,
[292]       ngx_http_variable_request_body,
[293]       0, 0, 0 },
[294] 
[295]     { ngx_string("request_body_file"), NULL,
[296]       ngx_http_variable_request_body_file,
[297]       0, 0, 0 },
[298] 
[299]     { ngx_string("request_length"), NULL, ngx_http_variable_request_length,
[300]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[301] 
[302]     { ngx_string("request_time"), NULL, ngx_http_variable_request_time,
[303]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[304] 
[305]     { ngx_string("request_id"), NULL,
[306]       ngx_http_variable_request_id,
[307]       0, 0, 0 },
[308] 
[309]     { ngx_string("status"), NULL,
[310]       ngx_http_variable_status, 0,
[311]       NGX_HTTP_VAR_NOCACHEABLE, 0 },
[312] 
[313]     { ngx_string("sent_http_content_type"), NULL,
[314]       ngx_http_variable_sent_content_type, 0, 0, 0 },
[315] 
[316]     { ngx_string("sent_http_content_length"), NULL,
[317]       ngx_http_variable_sent_content_length, 0, 0, 0 },
[318] 
[319]     { ngx_string("sent_http_location"), NULL,
[320]       ngx_http_variable_sent_location, 0, 0, 0 },
[321] 
[322]     { ngx_string("sent_http_last_modified"), NULL,
[323]       ngx_http_variable_sent_last_modified, 0, 0, 0 },
[324] 
[325]     { ngx_string("sent_http_connection"), NULL,
[326]       ngx_http_variable_sent_connection, 0, 0, 0 },
[327] 
[328]     { ngx_string("sent_http_keep_alive"), NULL,
[329]       ngx_http_variable_sent_keep_alive, 0, 0, 0 },
[330] 
[331]     { ngx_string("sent_http_transfer_encoding"), NULL,
[332]       ngx_http_variable_sent_transfer_encoding, 0, 0, 0 },
[333] 
[334]     { ngx_string("sent_http_cache_control"), NULL, ngx_http_variable_header,
[335]       offsetof(ngx_http_request_t, headers_out.cache_control), 0, 0 },
[336] 
[337]     { ngx_string("sent_http_link"), NULL, ngx_http_variable_header,
[338]       offsetof(ngx_http_request_t, headers_out.link), 0, 0 },
[339] 
[340]     { ngx_string("limit_rate"), ngx_http_variable_set_limit_rate,
[341]       ngx_http_variable_request_get_size,
[342]       offsetof(ngx_http_request_t, limit_rate),
[343]       NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE, 0 },
[344] 
[345]     { ngx_string("connection"), NULL,
[346]       ngx_http_variable_connection, 0, 0, 0 },
[347] 
[348]     { ngx_string("connection_requests"), NULL,
[349]       ngx_http_variable_connection_requests, 0, 0, 0 },
[350] 
[351]     { ngx_string("connection_time"), NULL, ngx_http_variable_connection_time,
[352]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[353] 
[354]     { ngx_string("nginx_version"), NULL, ngx_http_variable_nginx_version,
[355]       0, 0, 0 },
[356] 
[357]     { ngx_string("hostname"), NULL, ngx_http_variable_hostname,
[358]       0, 0, 0 },
[359] 
[360]     { ngx_string("pid"), NULL, ngx_http_variable_pid,
[361]       0, 0, 0 },
[362] 
[363]     { ngx_string("msec"), NULL, ngx_http_variable_msec,
[364]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[365] 
[366]     { ngx_string("time_iso8601"), NULL, ngx_http_variable_time_iso8601,
[367]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[368] 
[369]     { ngx_string("time_local"), NULL, ngx_http_variable_time_local,
[370]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[371] 
[372] #if (NGX_HAVE_TCP_INFO)
[373]     { ngx_string("tcpinfo_rtt"), NULL, ngx_http_variable_tcpinfo,
[374]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[375] 
[376]     { ngx_string("tcpinfo_rttvar"), NULL, ngx_http_variable_tcpinfo,
[377]       1, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[378] 
[379]     { ngx_string("tcpinfo_snd_cwnd"), NULL, ngx_http_variable_tcpinfo,
[380]       2, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[381] 
[382]     { ngx_string("tcpinfo_rcv_space"), NULL, ngx_http_variable_tcpinfo,
[383]       3, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[384] #endif
[385] 
[386]     { ngx_string("http_"), NULL, ngx_http_variable_unknown_header_in,
[387]       0, NGX_HTTP_VAR_PREFIX, 0 },
[388] 
[389]     { ngx_string("sent_http_"), NULL, ngx_http_variable_unknown_header_out,
[390]       0, NGX_HTTP_VAR_PREFIX, 0 },
[391] 
[392]     { ngx_string("sent_trailer_"), NULL, ngx_http_variable_unknown_trailer_out,
[393]       0, NGX_HTTP_VAR_PREFIX, 0 },
[394] 
[395]     { ngx_string("cookie_"), NULL, ngx_http_variable_cookie,
[396]       0, NGX_HTTP_VAR_PREFIX, 0 },
[397] 
[398]     { ngx_string("arg_"), NULL, ngx_http_variable_argument,
[399]       0, NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_PREFIX, 0 },
[400] 
[401]       ngx_http_null_variable
[402] };
[403] 
[404] 
[405] ngx_http_variable_value_t  ngx_http_variable_null_value =
[406]     ngx_http_variable("");
[407] ngx_http_variable_value_t  ngx_http_variable_true_value =
[408]     ngx_http_variable("1");
[409] 
[410] 
[411] static ngx_uint_t  ngx_http_variable_depth = 100;
[412] 
[413] 
[414] ngx_http_variable_t *
[415] ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
[416] {
[417]     ngx_int_t                   rc;
[418]     ngx_uint_t                  i;
[419]     ngx_hash_key_t             *key;
[420]     ngx_http_variable_t        *v;
[421]     ngx_http_core_main_conf_t  *cmcf;
[422] 
[423]     if (name->len == 0) {
[424]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[425]                            "invalid variable name \"$\"");
[426]         return NULL;
[427]     }
[428] 
[429]     if (flags & NGX_HTTP_VAR_PREFIX) {
[430]         return ngx_http_add_prefix_variable(cf, name, flags);
[431]     }
[432] 
[433]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[434] 
[435]     key = cmcf->variables_keys->keys.elts;
[436]     for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
[437]         if (name->len != key[i].key.len
[438]             || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
[439]         {
[440]             continue;
[441]         }
[442] 
[443]         v = key[i].value;
[444] 
[445]         if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
[446]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[447]                                "the duplicate \"%V\" variable", name);
[448]             return NULL;
[449]         }
[450] 
[451]         if (!(flags & NGX_HTTP_VAR_WEAK)) {
[452]             v->flags &= ~NGX_HTTP_VAR_WEAK;
[453]         }
[454] 
[455]         return v;
[456]     }
[457] 
[458]     v = ngx_palloc(cf->pool, sizeof(ngx_http_variable_t));
[459]     if (v == NULL) {
[460]         return NULL;
[461]     }
[462] 
[463]     v->name.len = name->len;
[464]     v->name.data = ngx_pnalloc(cf->pool, name->len);
[465]     if (v->name.data == NULL) {
[466]         return NULL;
[467]     }
[468] 
[469]     ngx_strlow(v->name.data, name->data, name->len);
[470] 
[471]     v->set_handler = NULL;
[472]     v->get_handler = NULL;
[473]     v->data = 0;
[474]     v->flags = flags;
[475]     v->index = 0;
[476] 
[477]     rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);
[478] 
[479]     if (rc == NGX_ERROR) {
[480]         return NULL;
[481]     }
[482] 
[483]     if (rc == NGX_BUSY) {
[484]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[485]                            "conflicting variable name \"%V\"", name);
[486]         return NULL;
[487]     }
[488] 
[489]     return v;
[490] }
[491] 
[492] 
[493] static ngx_http_variable_t *
[494] ngx_http_add_prefix_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
[495] {
[496]     ngx_uint_t                  i;
[497]     ngx_http_variable_t        *v;
[498]     ngx_http_core_main_conf_t  *cmcf;
[499] 
[500]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[501] 
[502]     v = cmcf->prefix_variables.elts;
[503]     for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
[504]         if (name->len != v[i].name.len
[505]             || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
[506]         {
[507]             continue;
[508]         }
[509] 
[510]         v = &v[i];
[511] 
[512]         if (!(v->flags & NGX_HTTP_VAR_CHANGEABLE)) {
[513]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[514]                                "the duplicate \"%V\" variable", name);
[515]             return NULL;
[516]         }
[517] 
[518]         if (!(flags & NGX_HTTP_VAR_WEAK)) {
[519]             v->flags &= ~NGX_HTTP_VAR_WEAK;
[520]         }
[521] 
[522]         return v;
[523]     }
[524] 
[525]     v = ngx_array_push(&cmcf->prefix_variables);
[526]     if (v == NULL) {
[527]         return NULL;
[528]     }
[529] 
[530]     v->name.len = name->len;
[531]     v->name.data = ngx_pnalloc(cf->pool, name->len);
[532]     if (v->name.data == NULL) {
[533]         return NULL;
[534]     }
[535] 
[536]     ngx_strlow(v->name.data, name->data, name->len);
[537] 
[538]     v->set_handler = NULL;
[539]     v->get_handler = NULL;
[540]     v->data = 0;
[541]     v->flags = flags;
[542]     v->index = 0;
[543] 
[544]     return v;
[545] }
[546] 
[547] 
[548] ngx_int_t
[549] ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
[550] {
[551]     ngx_uint_t                  i;
[552]     ngx_http_variable_t        *v;
[553]     ngx_http_core_main_conf_t  *cmcf;
[554] 
[555]     if (name->len == 0) {
[556]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[557]                            "invalid variable name \"$\"");
[558]         return NGX_ERROR;
[559]     }
[560] 
[561]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[562] 
[563]     v = cmcf->variables.elts;
[564] 
[565]     if (v == NULL) {
[566]         if (ngx_array_init(&cmcf->variables, cf->pool, 4,
[567]                            sizeof(ngx_http_variable_t))
[568]             != NGX_OK)
[569]         {
[570]             return NGX_ERROR;
[571]         }
[572] 
[573]     } else {
[574]         for (i = 0; i < cmcf->variables.nelts; i++) {
[575]             if (name->len != v[i].name.len
[576]                 || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
[577]             {
[578]                 continue;
[579]             }
[580] 
[581]             return i;
[582]         }
[583]     }
[584] 
[585]     v = ngx_array_push(&cmcf->variables);
[586]     if (v == NULL) {
[587]         return NGX_ERROR;
[588]     }
[589] 
[590]     v->name.len = name->len;
[591]     v->name.data = ngx_pnalloc(cf->pool, name->len);
[592]     if (v->name.data == NULL) {
[593]         return NGX_ERROR;
[594]     }
[595] 
[596]     ngx_strlow(v->name.data, name->data, name->len);
[597] 
[598]     v->set_handler = NULL;
[599]     v->get_handler = NULL;
[600]     v->data = 0;
[601]     v->flags = 0;
[602]     v->index = cmcf->variables.nelts - 1;
[603] 
[604]     return v->index;
[605] }
[606] 
[607] 
[608] ngx_http_variable_value_t *
[609] ngx_http_get_indexed_variable(ngx_http_request_t *r, ngx_uint_t index)
[610] {
[611]     ngx_http_variable_t        *v;
[612]     ngx_http_core_main_conf_t  *cmcf;
[613] 
[614]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[615] 
[616]     if (cmcf->variables.nelts <= index) {
[617]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[618]                       "unknown variable index: %ui", index);
[619]         return NULL;
[620]     }
[621] 
[622]     if (r->variables[index].not_found || r->variables[index].valid) {
[623]         return &r->variables[index];
[624]     }
[625] 
[626]     v = cmcf->variables.elts;
[627] 
[628]     if (ngx_http_variable_depth == 0) {
[629]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[630]                       "cycle while evaluating variable \"%V\"",
[631]                       &v[index].name);
[632]         return NULL;
[633]     }
[634] 
[635]     ngx_http_variable_depth--;
[636] 
[637]     if (v[index].get_handler(r, &r->variables[index], v[index].data)
[638]         == NGX_OK)
[639]     {
[640]         ngx_http_variable_depth++;
[641] 
[642]         if (v[index].flags & NGX_HTTP_VAR_NOCACHEABLE) {
[643]             r->variables[index].no_cacheable = 1;
[644]         }
[645] 
[646]         return &r->variables[index];
[647]     }
[648] 
[649]     ngx_http_variable_depth++;
[650] 
[651]     r->variables[index].valid = 0;
[652]     r->variables[index].not_found = 1;
[653] 
[654]     return NULL;
[655] }
[656] 
[657] 
[658] ngx_http_variable_value_t *
[659] ngx_http_get_flushed_variable(ngx_http_request_t *r, ngx_uint_t index)
[660] {
[661]     ngx_http_variable_value_t  *v;
[662] 
[663]     v = &r->variables[index];
[664] 
[665]     if (v->valid || v->not_found) {
[666]         if (!v->no_cacheable) {
[667]             return v;
[668]         }
[669] 
[670]         v->valid = 0;
[671]         v->not_found = 0;
[672]     }
[673] 
[674]     return ngx_http_get_indexed_variable(r, index);
[675] }
[676] 
[677] 
[678] ngx_http_variable_value_t *
[679] ngx_http_get_variable(ngx_http_request_t *r, ngx_str_t *name, ngx_uint_t key)
[680] {
[681]     size_t                      len;
[682]     ngx_uint_t                  i, n;
[683]     ngx_http_variable_t        *v;
[684]     ngx_http_variable_value_t  *vv;
[685]     ngx_http_core_main_conf_t  *cmcf;
[686] 
[687]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[688] 
[689]     v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);
[690] 
[691]     if (v) {
[692]         if (v->flags & NGX_HTTP_VAR_INDEXED) {
[693]             return ngx_http_get_flushed_variable(r, v->index);
[694]         }
[695] 
[696]         if (ngx_http_variable_depth == 0) {
[697]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[698]                           "cycle while evaluating variable \"%V\"", name);
[699]             return NULL;
[700]         }
[701] 
[702]         ngx_http_variable_depth--;
[703] 
[704]         vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
[705] 
[706]         if (vv && v->get_handler(r, vv, v->data) == NGX_OK) {
[707]             ngx_http_variable_depth++;
[708]             return vv;
[709]         }
[710] 
[711]         ngx_http_variable_depth++;
[712]         return NULL;
[713]     }
[714] 
[715]     vv = ngx_palloc(r->pool, sizeof(ngx_http_variable_value_t));
[716]     if (vv == NULL) {
[717]         return NULL;
[718]     }
[719] 
[720]     len = 0;
[721] 
[722]     v = cmcf->prefix_variables.elts;
[723]     n = cmcf->prefix_variables.nelts;
[724] 
[725]     for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
[726]         if (name->len >= v[i].name.len && name->len > len
[727]             && ngx_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
[728]         {
[729]             len = v[i].name.len;
[730]             n = i;
[731]         }
[732]     }
[733] 
[734]     if (n != cmcf->prefix_variables.nelts) {
[735]         if (v[n].get_handler(r, vv, (uintptr_t) name) == NGX_OK) {
[736]             return vv;
[737]         }
[738] 
[739]         return NULL;
[740]     }
[741] 
[742]     vv->not_found = 1;
[743] 
[744]     return vv;
[745] }
[746] 
[747] 
[748] static ngx_int_t
[749] ngx_http_variable_request(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[750]     uintptr_t data)
[751] {
[752]     ngx_str_t  *s;
[753] 
[754]     s = (ngx_str_t *) ((char *) r + data);
[755] 
[756]     if (s->data) {
[757]         v->len = s->len;
[758]         v->valid = 1;
[759]         v->no_cacheable = 0;
[760]         v->not_found = 0;
[761]         v->data = s->data;
[762] 
[763]     } else {
[764]         v->not_found = 1;
[765]     }
[766] 
[767]     return NGX_OK;
[768] }
[769] 
[770] 
[771] #if 0
[772] 
[773] static void
[774] ngx_http_variable_request_set(ngx_http_request_t *r,
[775]     ngx_http_variable_value_t *v, uintptr_t data)
[776] {
[777]     ngx_str_t  *s;
[778] 
[779]     s = (ngx_str_t *) ((char *) r + data);
[780] 
[781]     s->len = v->len;
[782]     s->data = v->data;
[783] }
[784] 
[785] #endif
[786] 
[787] 
[788] static ngx_int_t
[789] ngx_http_variable_request_get_size(ngx_http_request_t *r,
[790]     ngx_http_variable_value_t *v, uintptr_t data)
[791] {
[792]     size_t  *sp;
[793] 
[794]     sp = (size_t *) ((char *) r + data);
[795] 
[796]     v->data = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
[797]     if (v->data == NULL) {
[798]         return NGX_ERROR;
[799]     }
[800] 
[801]     v->len = ngx_sprintf(v->data, "%uz", *sp) - v->data;
[802]     v->valid = 1;
[803]     v->no_cacheable = 0;
[804]     v->not_found = 0;
[805] 
[806]     return NGX_OK;
[807] }
[808] 
[809] 
[810] static ngx_int_t
[811] ngx_http_variable_header(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[812]     uintptr_t data)
[813] {
[814]     return ngx_http_variable_headers_internal(r, v, data, ',');
[815] }
[816] 
[817] 
[818] static ngx_int_t
[819] ngx_http_variable_cookies(ngx_http_request_t *r,
[820]     ngx_http_variable_value_t *v, uintptr_t data)
[821] {
[822]     return ngx_http_variable_headers_internal(r, v, data, ';');
[823] }
[824] 
[825] 
[826] static ngx_int_t
[827] ngx_http_variable_headers_internal(ngx_http_request_t *r,
[828]     ngx_http_variable_value_t *v, uintptr_t data, u_char sep)
[829] {
[830]     size_t            len;
[831]     u_char           *p;
[832]     ngx_table_elt_t  *h, *th;
[833] 
[834]     h = *(ngx_table_elt_t **) ((char *) r + data);
[835] 
[836]     len = 0;
[837] 
[838]     for (th = h; th; th = th->next) {
[839] 
[840]         if (th->hash == 0) {
[841]             continue;
[842]         }
[843] 
[844]         len += th->value.len + 2;
[845]     }
[846] 
[847]     if (len == 0) {
[848]         v->not_found = 1;
[849]         return NGX_OK;
[850]     }
[851] 
[852]     len -= 2;
[853] 
[854]     v->valid = 1;
[855]     v->no_cacheable = 0;
[856]     v->not_found = 0;
[857] 
[858]     if (h->next == NULL) {
[859]         v->len = h->value.len;
[860]         v->data = h->value.data;
[861] 
[862]         return NGX_OK;
[863]     }
[864] 
[865]     p = ngx_pnalloc(r->pool, len);
[866]     if (p == NULL) {
[867]         return NGX_ERROR;
[868]     }
[869] 
[870]     v->len = len;
[871]     v->data = p;
[872] 
[873]     for (th = h; th; th = th->next) {
[874] 
[875]         if (th->hash == 0) {
[876]             continue;
[877]         }
[878] 
[879]         p = ngx_copy(p, th->value.data, th->value.len);
[880] 
[881]         if (th->next == NULL) {
[882]             break;
[883]         }
[884] 
[885]         *p++ = sep; *p++ = ' ';
[886]     }
[887] 
[888]     return NGX_OK;
[889] }
[890] 
[891] 
[892] static ngx_int_t
[893] ngx_http_variable_unknown_header_in(ngx_http_request_t *r,
[894]     ngx_http_variable_value_t *v, uintptr_t data)
[895] {
[896]     return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
[897]                                             &r->headers_in.headers.part,
[898]                                             sizeof("http_") - 1);
[899] }
[900] 
[901] 
[902] static ngx_int_t
[903] ngx_http_variable_unknown_header_out(ngx_http_request_t *r,
[904]     ngx_http_variable_value_t *v, uintptr_t data)
[905] {
[906]     return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
[907]                                             &r->headers_out.headers.part,
[908]                                             sizeof("sent_http_") - 1);
[909] }
[910] 
[911] 
[912] static ngx_int_t
[913] ngx_http_variable_unknown_trailer_out(ngx_http_request_t *r,
[914]     ngx_http_variable_value_t *v, uintptr_t data)
[915] {
[916]     return ngx_http_variable_unknown_header(r, v, (ngx_str_t *) data,
[917]                                             &r->headers_out.trailers.part,
[918]                                             sizeof("sent_trailer_") - 1);
[919] }
[920] 
[921] 
[922] ngx_int_t
[923] ngx_http_variable_unknown_header(ngx_http_request_t *r,
[924]     ngx_http_variable_value_t *v, ngx_str_t *var,
[925]     ngx_list_part_t *part, size_t prefix)
[926] {
[927]     u_char           *p, ch;
[928]     size_t            len;
[929]     ngx_uint_t        i, n;
[930]     ngx_table_elt_t  *header, *h, **ph;
[931] 
[932]     ph = &h;
[933] #if (NGX_SUPPRESS_WARN)
[934]     len = 0;
[935] #endif
[936] 
[937]     header = part->elts;
[938] 
[939]     for (i = 0; /* void */ ; i++) {
[940] 
[941]         if (i >= part->nelts) {
[942]             if (part->next == NULL) {
[943]                 break;
[944]             }
[945] 
[946]             part = part->next;
[947]             header = part->elts;
[948]             i = 0;
[949]         }
[950] 
[951]         if (header[i].hash == 0) {
[952]             continue;
[953]         }
[954] 
[955]         if (header[i].key.len != var->len - prefix) {
[956]             continue;
[957]         }
[958] 
[959]         for (n = 0; n < var->len - prefix; n++) {
[960]             ch = header[i].key.data[n];
[961] 
[962]             if (ch >= 'A' && ch <= 'Z') {
[963]                 ch |= 0x20;
[964] 
[965]             } else if (ch == '-') {
[966]                 ch = '_';
[967]             }
[968] 
[969]             if (var->data[n + prefix] != ch) {
[970]                 break;
[971]             }
[972]         }
[973] 
[974]         if (n != var->len - prefix) {
[975]             continue;
[976]         }
[977] 
[978]         len += header[i].value.len + 2;
[979] 
[980]         *ph = &header[i];
[981]         ph = &header[i].next;
[982]     }
[983] 
[984]     *ph = NULL;
[985] 
[986]     if (h == NULL) {
[987]         v->not_found = 1;
[988]         return NGX_OK;
[989]     }
[990] 
[991]     len -= 2;
[992] 
[993]     if (h->next == NULL) {
[994] 
[995]         v->len = h->value.len;
[996]         v->valid = 1;
[997]         v->no_cacheable = 0;
[998]         v->not_found = 0;
[999]         v->data = h->value.data;
[1000] 
[1001]         return NGX_OK;
[1002]     }
[1003] 
[1004]     p = ngx_pnalloc(r->pool, len);
[1005]     if (p == NULL) {
[1006]         return NGX_ERROR;
[1007]     }
[1008] 
[1009]     v->len = len;
[1010]     v->valid = 1;
[1011]     v->no_cacheable = 0;
[1012]     v->not_found = 0;
[1013]     v->data = p;
[1014] 
[1015]     for ( ;; ) {
[1016] 
[1017]         p = ngx_copy(p, h->value.data, h->value.len);
[1018] 
[1019]         if (h->next == NULL) {
[1020]             break;
[1021]         }
[1022] 
[1023]         *p++ = ','; *p++ = ' ';
[1024] 
[1025]         h = h->next;
[1026]     }
[1027] 
[1028]     return NGX_OK;
[1029] }
[1030] 
[1031] 
[1032] static ngx_int_t
[1033] ngx_http_variable_request_line(ngx_http_request_t *r,
[1034]     ngx_http_variable_value_t *v, uintptr_t data)
[1035] {
[1036]     u_char  *p, *s;
[1037] 
[1038]     s = r->request_line.data;
[1039] 
[1040]     if (s == NULL) {
[1041]         s = r->request_start;
[1042] 
[1043]         if (s == NULL) {
[1044]             v->not_found = 1;
[1045]             return NGX_OK;
[1046]         }
[1047] 
[1048]         for (p = s; p < r->header_in->last; p++) {
[1049]             if (*p == CR || *p == LF) {
[1050]                 break;
[1051]             }
[1052]         }
[1053] 
[1054]         r->request_line.len = p - s;
[1055]         r->request_line.data = s;
[1056]     }
[1057] 
[1058]     v->len = r->request_line.len;
[1059]     v->valid = 1;
[1060]     v->no_cacheable = 0;
[1061]     v->not_found = 0;
[1062]     v->data = s;
[1063] 
[1064]     return NGX_OK;
[1065] }
[1066] 
[1067] 
[1068] static ngx_int_t
[1069] ngx_http_variable_cookie(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[1070]     uintptr_t data)
[1071] {
[1072]     ngx_str_t *name = (ngx_str_t *) data;
[1073] 
[1074]     ngx_str_t  cookie, s;
[1075] 
[1076]     s.len = name->len - (sizeof("cookie_") - 1);
[1077]     s.data = name->data + sizeof("cookie_") - 1;
[1078] 
[1079]     if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &s, &cookie)
[1080]         == NULL)
[1081]     {
[1082]         v->not_found = 1;
[1083]         return NGX_OK;
[1084]     }
[1085] 
[1086]     v->len = cookie.len;
[1087]     v->valid = 1;
[1088]     v->no_cacheable = 0;
[1089]     v->not_found = 0;
[1090]     v->data = cookie.data;
[1091] 
[1092]     return NGX_OK;
[1093] }
[1094] 
[1095] 
[1096] static ngx_int_t
[1097] ngx_http_variable_argument(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[1098]     uintptr_t data)
[1099] {
[1100]     ngx_str_t *name = (ngx_str_t *) data;
[1101] 
[1102]     u_char     *arg;
[1103]     size_t      len;
[1104]     ngx_str_t   value;
[1105] 
[1106]     len = name->len - (sizeof("arg_") - 1);
[1107]     arg = name->data + sizeof("arg_") - 1;
[1108] 
[1109]     if (len == 0 || ngx_http_arg(r, arg, len, &value) != NGX_OK) {
[1110]         v->not_found = 1;
[1111]         return NGX_OK;
[1112]     }
[1113] 
[1114]     v->data = value.data;
[1115]     v->len = value.len;
[1116]     v->valid = 1;
[1117]     v->no_cacheable = 0;
[1118]     v->not_found = 0;
[1119] 
[1120]     return NGX_OK;
[1121] }
[1122] 
[1123] 
[1124] #if (NGX_HAVE_TCP_INFO)
[1125] 
[1126] static ngx_int_t
[1127] ngx_http_variable_tcpinfo(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[1128]     uintptr_t data)
[1129] {
[1130]     struct tcp_info  ti;
[1131]     socklen_t        len;
[1132]     uint32_t         value;
[1133] 
[1134]     len = sizeof(struct tcp_info);
[1135]     if (getsockopt(r->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
[1136]         v->not_found = 1;
[1137]         return NGX_OK;
[1138]     }
[1139] 
[1140]     v->data = ngx_pnalloc(r->pool, NGX_INT32_LEN);
[1141]     if (v->data == NULL) {
[1142]         return NGX_ERROR;
[1143]     }
[1144] 
[1145]     switch (data) {
[1146]     case 0:
[1147]         value = ti.tcpi_rtt;
[1148]         break;
[1149] 
[1150]     case 1:
[1151]         value = ti.tcpi_rttvar;
[1152]         break;
[1153] 
[1154]     case 2:
[1155]         value = ti.tcpi_snd_cwnd;
[1156]         break;
[1157] 
[1158]     case 3:
[1159]         value = ti.tcpi_rcv_space;
[1160]         break;
[1161] 
[1162]     /* suppress warning */
[1163]     default:
[1164]         value = 0;
[1165]         break;
[1166]     }
[1167] 
[1168]     v->len = ngx_sprintf(v->data, "%uD", value) - v->data;
[1169]     v->valid = 1;
[1170]     v->no_cacheable = 0;
[1171]     v->not_found = 0;
[1172] 
[1173]     return NGX_OK;
[1174] }
[1175] 
[1176] #endif
[1177] 
[1178] 
[1179] static ngx_int_t
[1180] ngx_http_variable_content_length(ngx_http_request_t *r,
[1181]     ngx_http_variable_value_t *v, uintptr_t data)
[1182] {
[1183]     u_char  *p;
[1184] 
[1185]     if (r->headers_in.content_length) {
[1186]         v->len = r->headers_in.content_length->value.len;
[1187]         v->data = r->headers_in.content_length->value.data;
[1188]         v->valid = 1;
[1189]         v->no_cacheable = 0;
[1190]         v->not_found = 0;
[1191] 
[1192]     } else if (r->reading_body) {
[1193]         v->not_found = 1;
[1194]         v->no_cacheable = 1;
[1195] 
[1196]     } else if (r->headers_in.content_length_n >= 0) {
[1197]         p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
[1198]         if (p == NULL) {
[1199]             return NGX_ERROR;
[1200]         }
[1201] 
[1202]         v->len = ngx_sprintf(p, "%O", r->headers_in.content_length_n) - p;
[1203]         v->data = p;
[1204]         v->valid = 1;
[1205]         v->no_cacheable = 0;
[1206]         v->not_found = 0;
[1207] 
[1208]     } else if (r->headers_in.chunked) {
[1209]         v->not_found = 1;
[1210]         v->no_cacheable = 1;
[1211] 
[1212]     } else {
[1213]         v->not_found = 1;
[1214]     }
[1215] 
[1216]     return NGX_OK;
[1217] }
[1218] 
[1219] 
[1220] static ngx_int_t
[1221] ngx_http_variable_host(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[1222]     uintptr_t data)
[1223] {
[1224]     ngx_http_core_srv_conf_t  *cscf;
[1225] 
[1226]     if (r->headers_in.server.len) {
[1227]         v->len = r->headers_in.server.len;
[1228]         v->data = r->headers_in.server.data;
[1229] 
[1230]     } else {
[1231]         cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1232] 
[1233]         v->len = cscf->server_name.len;
[1234]         v->data = cscf->server_name.data;
[1235]     }
[1236] 
[1237]     v->valid = 1;
[1238]     v->no_cacheable = 0;
[1239]     v->not_found = 0;
[1240] 
[1241]     return NGX_OK;
[1242] }
[1243] 
[1244] 
[1245] static ngx_int_t
[1246] ngx_http_variable_binary_remote_addr(ngx_http_request_t *r,
[1247]     ngx_http_variable_value_t *v, uintptr_t data)
[1248] {
[1249]     struct sockaddr_in   *sin;
[1250] #if (NGX_HAVE_INET6)
[1251]     struct sockaddr_in6  *sin6;
[1252] #endif
[1253] 
[1254]     switch (r->connection->sockaddr->sa_family) {
[1255] 
[1256] #if (NGX_HAVE_INET6)
[1257]     case AF_INET6:
[1258]         sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
[1259] 
[1260]         v->len = sizeof(struct in6_addr);
[1261]         v->valid = 1;
[1262]         v->no_cacheable = 0;
[1263]         v->not_found = 0;
[1264]         v->data = sin6->sin6_addr.s6_addr;
[1265] 
[1266]         break;
[1267] #endif
[1268] 
[1269] #if (NGX_HAVE_UNIX_DOMAIN)
[1270]     case AF_UNIX:
[1271] 
[1272]         v->len = r->connection->addr_text.len;
[1273]         v->valid = 1;
[1274]         v->no_cacheable = 0;
[1275]         v->not_found = 0;
[1276]         v->data = r->connection->addr_text.data;
[1277] 
[1278]         break;
[1279] #endif
[1280] 
[1281]     default: /* AF_INET */
[1282]         sin = (struct sockaddr_in *) r->connection->sockaddr;
[1283] 
[1284]         v->len = sizeof(in_addr_t);
[1285]         v->valid = 1;
[1286]         v->no_cacheable = 0;
[1287]         v->not_found = 0;
[1288]         v->data = (u_char *) &sin->sin_addr;
[1289] 
[1290]         break;
[1291]     }
[1292] 
[1293]     return NGX_OK;
[1294] }
[1295] 
[1296] 
[1297] static ngx_int_t
[1298] ngx_http_variable_remote_addr(ngx_http_request_t *r,
[1299]     ngx_http_variable_value_t *v, uintptr_t data)
[1300] {
[1301]     v->len = r->connection->addr_text.len;
[1302]     v->valid = 1;
[1303]     v->no_cacheable = 0;
[1304]     v->not_found = 0;
[1305]     v->data = r->connection->addr_text.data;
[1306] 
[1307]     return NGX_OK;
[1308] }
[1309] 
[1310] 
[1311] static ngx_int_t
[1312] ngx_http_variable_remote_port(ngx_http_request_t *r,
[1313]     ngx_http_variable_value_t *v, uintptr_t data)
[1314] {
[1315]     ngx_uint_t  port;
[1316] 
[1317]     v->len = 0;
[1318]     v->valid = 1;
[1319]     v->no_cacheable = 0;
[1320]     v->not_found = 0;
[1321] 
[1322]     v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
[1323]     if (v->data == NULL) {
[1324]         return NGX_ERROR;
[1325]     }
[1326] 
[1327]     port = ngx_inet_get_port(r->connection->sockaddr);
[1328] 
[1329]     if (port > 0 && port < 65536) {
[1330]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[1331]     }
[1332] 
[1333]     return NGX_OK;
[1334] }
[1335] 
[1336] 
[1337] static ngx_int_t
[1338] ngx_http_variable_proxy_protocol_addr(ngx_http_request_t *r,
[1339]     ngx_http_variable_value_t *v, uintptr_t data)
[1340] {
[1341]     ngx_str_t             *addr;
[1342]     ngx_proxy_protocol_t  *pp;
[1343] 
[1344]     pp = r->connection->proxy_protocol;
[1345]     if (pp == NULL) {
[1346]         v->not_found = 1;
[1347]         return NGX_OK;
[1348]     }
[1349] 
[1350]     addr = (ngx_str_t *) ((char *) pp + data);
[1351] 
[1352]     v->len = addr->len;
[1353]     v->valid = 1;
[1354]     v->no_cacheable = 0;
[1355]     v->not_found = 0;
[1356]     v->data = addr->data;
[1357] 
[1358]     return NGX_OK;
[1359] }
[1360] 
[1361] 
[1362] static ngx_int_t
[1363] ngx_http_variable_proxy_protocol_port(ngx_http_request_t *r,
[1364]     ngx_http_variable_value_t *v, uintptr_t data)
[1365] {
[1366]     ngx_uint_t             port;
[1367]     ngx_proxy_protocol_t  *pp;
[1368] 
[1369]     pp = r->connection->proxy_protocol;
[1370]     if (pp == NULL) {
[1371]         v->not_found = 1;
[1372]         return NGX_OK;
[1373]     }
[1374] 
[1375]     v->len = 0;
[1376]     v->valid = 1;
[1377]     v->no_cacheable = 0;
[1378]     v->not_found = 0;
[1379] 
[1380]     v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
[1381]     if (v->data == NULL) {
[1382]         return NGX_ERROR;
[1383]     }
[1384] 
[1385]     port = *(in_port_t *) ((char *) pp + data);
[1386] 
[1387]     if (port > 0 && port < 65536) {
[1388]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[1389]     }
[1390] 
[1391]     return NGX_OK;
[1392] }
[1393] 
[1394] 
[1395] static ngx_int_t
[1396] ngx_http_variable_proxy_protocol_tlv(ngx_http_request_t *r,
[1397]     ngx_http_variable_value_t *v, uintptr_t data)
[1398] {
[1399]     ngx_str_t *name = (ngx_str_t *) data;
[1400] 
[1401]     ngx_int_t  rc;
[1402]     ngx_str_t  tlv, value;
[1403] 
[1404]     tlv.len = name->len - (sizeof("proxy_protocol_tlv_") - 1);
[1405]     tlv.data = name->data + sizeof("proxy_protocol_tlv_") - 1;
[1406] 
[1407]     rc = ngx_proxy_protocol_get_tlv(r->connection, &tlv, &value);
[1408] 
[1409]     if (rc == NGX_ERROR) {
[1410]         return NGX_ERROR;
[1411]     }
[1412] 
[1413]     if (rc == NGX_DECLINED) {
[1414]         v->not_found = 1;
[1415]         return NGX_OK;
[1416]     }
[1417] 
[1418]     v->len = value.len;
[1419]     v->valid = 1;
[1420]     v->no_cacheable = 0;
[1421]     v->not_found = 0;
[1422]     v->data = value.data;
[1423] 
[1424]     return NGX_OK;
[1425] }
[1426] 
[1427] 
[1428] static ngx_int_t
[1429] ngx_http_variable_server_addr(ngx_http_request_t *r,
[1430]     ngx_http_variable_value_t *v, uintptr_t data)
[1431] {
[1432]     ngx_str_t  s;
[1433]     u_char     addr[NGX_SOCKADDR_STRLEN];
[1434] 
[1435]     s.len = NGX_SOCKADDR_STRLEN;
[1436]     s.data = addr;
[1437] 
[1438]     if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
[1439]         return NGX_ERROR;
[1440]     }
[1441] 
[1442]     s.data = ngx_pnalloc(r->pool, s.len);
[1443]     if (s.data == NULL) {
[1444]         return NGX_ERROR;
[1445]     }
[1446] 
[1447]     ngx_memcpy(s.data, addr, s.len);
[1448] 
[1449]     v->len = s.len;
[1450]     v->valid = 1;
[1451]     v->no_cacheable = 0;
[1452]     v->not_found = 0;
[1453]     v->data = s.data;
[1454] 
[1455]     return NGX_OK;
[1456] }
[1457] 
[1458] 
[1459] static ngx_int_t
[1460] ngx_http_variable_server_port(ngx_http_request_t *r,
[1461]     ngx_http_variable_value_t *v, uintptr_t data)
[1462] {
[1463]     ngx_uint_t  port;
[1464] 
[1465]     v->len = 0;
[1466]     v->valid = 1;
[1467]     v->no_cacheable = 0;
[1468]     v->not_found = 0;
[1469] 
[1470]     if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
[1471]         return NGX_ERROR;
[1472]     }
[1473] 
[1474]     v->data = ngx_pnalloc(r->pool, sizeof("65535") - 1);
[1475]     if (v->data == NULL) {
[1476]         return NGX_ERROR;
[1477]     }
[1478] 
[1479]     port = ngx_inet_get_port(r->connection->local_sockaddr);
[1480] 
[1481]     if (port > 0 && port < 65536) {
[1482]         v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
[1483]     }
[1484] 
[1485]     return NGX_OK;
[1486] }
[1487] 
[1488] 
[1489] static ngx_int_t
[1490] ngx_http_variable_scheme(ngx_http_request_t *r,
[1491]     ngx_http_variable_value_t *v, uintptr_t data)
[1492] {
[1493] #if (NGX_HTTP_SSL)
[1494] 
[1495]     if (r->connection->ssl) {
[1496]         v->len = sizeof("https") - 1;
[1497]         v->valid = 1;
[1498]         v->no_cacheable = 0;
[1499]         v->not_found = 0;
[1500]         v->data = (u_char *) "https";
[1501] 
[1502]         return NGX_OK;
[1503]     }
[1504] 
[1505] #endif
[1506] 
[1507]     v->len = sizeof("http") - 1;
[1508]     v->valid = 1;
[1509]     v->no_cacheable = 0;
[1510]     v->not_found = 0;
[1511]     v->data = (u_char *) "http";
[1512] 
[1513]     return NGX_OK;
[1514] }
[1515] 
[1516] 
[1517] static ngx_int_t
[1518] ngx_http_variable_https(ngx_http_request_t *r,
[1519]     ngx_http_variable_value_t *v, uintptr_t data)
[1520] {
[1521] #if (NGX_HTTP_SSL)
[1522] 
[1523]     if (r->connection->ssl) {
[1524]         v->len = sizeof("on") - 1;
[1525]         v->valid = 1;
[1526]         v->no_cacheable = 0;
[1527]         v->not_found = 0;
[1528]         v->data = (u_char *) "on";
[1529] 
[1530]         return NGX_OK;
[1531]     }
[1532] 
[1533] #endif
[1534] 
[1535]     *v = ngx_http_variable_null_value;
[1536] 
[1537]     return NGX_OK;
[1538] }
[1539] 
[1540] 
[1541] static void
[1542] ngx_http_variable_set_args(ngx_http_request_t *r,
[1543]     ngx_http_variable_value_t *v, uintptr_t data)
[1544] {
[1545]     r->args.len = v->len;
[1546]     r->args.data = v->data;
[1547]     r->valid_unparsed_uri = 0;
[1548] }
[1549] 
[1550] 
[1551] static ngx_int_t
[1552] ngx_http_variable_is_args(ngx_http_request_t *r,
[1553]     ngx_http_variable_value_t *v, uintptr_t data)
[1554] {
[1555]     if (r->args.len == 0) {
[1556]         *v = ngx_http_variable_null_value;
[1557]         return NGX_OK;
[1558]     }
[1559] 
[1560]     v->len = 1;
[1561]     v->valid = 1;
[1562]     v->no_cacheable = 0;
[1563]     v->not_found = 0;
[1564]     v->data = (u_char *) "?";
[1565] 
[1566]     return NGX_OK;
[1567] }
[1568] 
[1569] 
[1570] static ngx_int_t
[1571] ngx_http_variable_document_root(ngx_http_request_t *r,
[1572]     ngx_http_variable_value_t *v, uintptr_t data)
[1573] {
[1574]     ngx_str_t                  path;
[1575]     ngx_http_core_loc_conf_t  *clcf;
[1576] 
[1577]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1578] 
[1579]     if (clcf->root_lengths == NULL) {
[1580]         v->len = clcf->root.len;
[1581]         v->valid = 1;
[1582]         v->no_cacheable = 0;
[1583]         v->not_found = 0;
[1584]         v->data = clcf->root.data;
[1585] 
[1586]     } else {
[1587]         if (ngx_http_script_run(r, &path, clcf->root_lengths->elts, 0,
[1588]                                 clcf->root_values->elts)
[1589]             == NULL)
[1590]         {
[1591]             return NGX_ERROR;
[1592]         }
[1593] 
[1594]         if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
[1595]             != NGX_OK)
[1596]         {
[1597]             return NGX_ERROR;
[1598]         }
[1599] 
[1600]         v->len = path.len;
[1601]         v->valid = 1;
[1602]         v->no_cacheable = 0;
[1603]         v->not_found = 0;
[1604]         v->data = path.data;
[1605]     }
[1606] 
[1607]     return NGX_OK;
[1608] }
[1609] 
[1610] 
[1611] static ngx_int_t
[1612] ngx_http_variable_realpath_root(ngx_http_request_t *r,
[1613]     ngx_http_variable_value_t *v, uintptr_t data)
[1614] {
[1615]     u_char                    *real;
[1616]     size_t                     len;
[1617]     ngx_str_t                  path;
[1618]     ngx_http_core_loc_conf_t  *clcf;
[1619] #if (NGX_HAVE_MAX_PATH)
[1620]     u_char                     buffer[NGX_MAX_PATH];
[1621] #endif
[1622] 
[1623]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[1624] 
[1625]     if (clcf->root_lengths == NULL) {
[1626]         path = clcf->root;
[1627] 
[1628]     } else {
[1629]         if (ngx_http_script_run(r, &path, clcf->root_lengths->elts, 1,
[1630]                                 clcf->root_values->elts)
[1631]             == NULL)
[1632]         {
[1633]             return NGX_ERROR;
[1634]         }
[1635] 
[1636]         path.data[path.len - 1] = '\0';
[1637] 
[1638]         if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
[1639]             != NGX_OK)
[1640]         {
[1641]             return NGX_ERROR;
[1642]         }
[1643]     }
[1644] 
[1645] #if (NGX_HAVE_MAX_PATH)
[1646]     real = buffer;
[1647] #else
[1648]     real = NULL;
[1649] #endif
[1650] 
[1651]     real = ngx_realpath(path.data, real);
[1652] 
[1653]     if (real == NULL) {
[1654]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[1655]                       ngx_realpath_n " \"%s\" failed", path.data);
[1656]         return NGX_ERROR;
[1657]     }
[1658] 
[1659]     len = ngx_strlen(real);
[1660] 
[1661]     v->data = ngx_pnalloc(r->pool, len);
[1662]     if (v->data == NULL) {
[1663] #if !(NGX_HAVE_MAX_PATH)
[1664]         ngx_free(real);
[1665] #endif
[1666]         return NGX_ERROR;
[1667]     }
[1668] 
[1669]     v->len = len;
[1670]     v->valid = 1;
[1671]     v->no_cacheable = 0;
[1672]     v->not_found = 0;
[1673] 
[1674]     ngx_memcpy(v->data, real, len);
[1675] 
[1676] #if !(NGX_HAVE_MAX_PATH)
[1677]     ngx_free(real);
[1678] #endif
[1679] 
[1680]     return NGX_OK;
[1681] }
[1682] 
[1683] 
[1684] static ngx_int_t
[1685] ngx_http_variable_request_filename(ngx_http_request_t *r,
[1686]     ngx_http_variable_value_t *v, uintptr_t data)
[1687] {
[1688]     size_t     root;
[1689]     ngx_str_t  path;
[1690] 
[1691]     if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
[1692]         return NGX_ERROR;
[1693]     }
[1694] 
[1695]     /* ngx_http_map_uri_to_path() allocates memory for terminating '\0' */
[1696] 
[1697]     v->len = path.len - 1;
[1698]     v->valid = 1;
[1699]     v->no_cacheable = 0;
[1700]     v->not_found = 0;
[1701]     v->data = path.data;
[1702] 
[1703]     return NGX_OK;
[1704] }
[1705] 
[1706] 
[1707] static ngx_int_t
[1708] ngx_http_variable_server_name(ngx_http_request_t *r,
[1709]     ngx_http_variable_value_t *v, uintptr_t data)
[1710] {
[1711]     ngx_http_core_srv_conf_t  *cscf;
[1712] 
[1713]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1714] 
[1715]     v->len = cscf->server_name.len;
[1716]     v->valid = 1;
[1717]     v->no_cacheable = 0;
[1718]     v->not_found = 0;
[1719]     v->data = cscf->server_name.data;
[1720] 
[1721]     return NGX_OK;
[1722] }
[1723] 
[1724] 
[1725] static ngx_int_t
[1726] ngx_http_variable_request_method(ngx_http_request_t *r,
[1727]     ngx_http_variable_value_t *v, uintptr_t data)
[1728] {
[1729]     if (r->main->method_name.data) {
[1730]         v->len = r->main->method_name.len;
[1731]         v->valid = 1;
[1732]         v->no_cacheable = 0;
[1733]         v->not_found = 0;
[1734]         v->data = r->main->method_name.data;
[1735] 
[1736]     } else {
[1737]         v->not_found = 1;
[1738]     }
[1739] 
[1740]     return NGX_OK;
[1741] }
[1742] 
[1743] 
[1744] static ngx_int_t
[1745] ngx_http_variable_remote_user(ngx_http_request_t *r,
[1746]     ngx_http_variable_value_t *v, uintptr_t data)
[1747] {
[1748]     ngx_int_t  rc;
[1749] 
[1750]     rc = ngx_http_auth_basic_user(r);
[1751] 
[1752]     if (rc == NGX_DECLINED) {
[1753]         v->not_found = 1;
[1754]         return NGX_OK;
[1755]     }
[1756] 
[1757]     if (rc == NGX_ERROR) {
[1758]         return NGX_ERROR;
[1759]     }
[1760] 
[1761]     v->len = r->headers_in.user.len;
[1762]     v->valid = 1;
[1763]     v->no_cacheable = 0;
[1764]     v->not_found = 0;
[1765]     v->data = r->headers_in.user.data;
[1766] 
[1767]     return NGX_OK;
[1768] }
[1769] 
[1770] 
[1771] static ngx_int_t
[1772] ngx_http_variable_bytes_sent(ngx_http_request_t *r,
[1773]     ngx_http_variable_value_t *v, uintptr_t data)
[1774] {
[1775]     u_char  *p;
[1776] 
[1777]     p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
[1778]     if (p == NULL) {
[1779]         return NGX_ERROR;
[1780]     }
[1781] 
[1782]     v->len = ngx_sprintf(p, "%O", r->connection->sent) - p;
[1783]     v->valid = 1;
[1784]     v->no_cacheable = 0;
[1785]     v->not_found = 0;
[1786]     v->data = p;
[1787] 
[1788]     return NGX_OK;
[1789] }
[1790] 
[1791] 
[1792] static ngx_int_t
[1793] ngx_http_variable_body_bytes_sent(ngx_http_request_t *r,
[1794]     ngx_http_variable_value_t *v, uintptr_t data)
[1795] {
[1796]     off_t    sent;
[1797]     u_char  *p;
[1798] 
[1799]     sent = r->connection->sent - r->header_size;
[1800] 
[1801]     if (sent < 0) {
[1802]         sent = 0;
[1803]     }
[1804] 
[1805]     p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
[1806]     if (p == NULL) {
[1807]         return NGX_ERROR;
[1808]     }
[1809] 
[1810]     v->len = ngx_sprintf(p, "%O", sent) - p;
[1811]     v->valid = 1;
[1812]     v->no_cacheable = 0;
[1813]     v->not_found = 0;
[1814]     v->data = p;
[1815] 
[1816]     return NGX_OK;
[1817] }
[1818] 
[1819] 
[1820] static ngx_int_t
[1821] ngx_http_variable_pipe(ngx_http_request_t *r,
[1822]     ngx_http_variable_value_t *v, uintptr_t data)
[1823] {
[1824]     v->data = (u_char *) (r->pipeline ? "p" : ".");
[1825]     v->len = 1;
[1826]     v->valid = 1;
[1827]     v->no_cacheable = 0;
[1828]     v->not_found = 0;
[1829] 
[1830]     return NGX_OK;
[1831] }
[1832] 
[1833] 
[1834] static ngx_int_t
[1835] ngx_http_variable_status(ngx_http_request_t *r,
[1836]     ngx_http_variable_value_t *v, uintptr_t data)
[1837] {
[1838]     ngx_uint_t  status;
[1839] 
[1840]     v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
[1841]     if (v->data == NULL) {
[1842]         return NGX_ERROR;
[1843]     }
[1844] 
[1845]     if (r->err_status) {
[1846]         status = r->err_status;
[1847] 
[1848]     } else if (r->headers_out.status) {
[1849]         status = r->headers_out.status;
[1850] 
[1851]     } else if (r->http_version == NGX_HTTP_VERSION_9) {
[1852]         status = 9;
[1853] 
[1854]     } else {
[1855]         status = 0;
[1856]     }
[1857] 
[1858]     v->len = ngx_sprintf(v->data, "%03ui", status) - v->data;
[1859]     v->valid = 1;
[1860]     v->no_cacheable = 0;
[1861]     v->not_found = 0;
[1862] 
[1863]     return NGX_OK;
[1864] }
[1865] 
[1866] 
[1867] static ngx_int_t
[1868] ngx_http_variable_sent_content_type(ngx_http_request_t *r,
[1869]     ngx_http_variable_value_t *v, uintptr_t data)
[1870] {
[1871]     if (r->headers_out.content_type.len) {
[1872]         v->len = r->headers_out.content_type.len;
[1873]         v->valid = 1;
[1874]         v->no_cacheable = 0;
[1875]         v->not_found = 0;
[1876]         v->data = r->headers_out.content_type.data;
[1877] 
[1878]     } else {
[1879]         v->not_found = 1;
[1880]     }
[1881] 
[1882]     return NGX_OK;
[1883] }
[1884] 
[1885] 
[1886] static ngx_int_t
[1887] ngx_http_variable_sent_content_length(ngx_http_request_t *r,
[1888]     ngx_http_variable_value_t *v, uintptr_t data)
[1889] {
[1890]     u_char  *p;
[1891] 
[1892]     if (r->headers_out.content_length) {
[1893]         v->len = r->headers_out.content_length->value.len;
[1894]         v->valid = 1;
[1895]         v->no_cacheable = 0;
[1896]         v->not_found = 0;
[1897]         v->data = r->headers_out.content_length->value.data;
[1898] 
[1899]         return NGX_OK;
[1900]     }
[1901] 
[1902]     if (r->headers_out.content_length_n >= 0) {
[1903]         p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
[1904]         if (p == NULL) {
[1905]             return NGX_ERROR;
[1906]         }
[1907] 
[1908]         v->len = ngx_sprintf(p, "%O", r->headers_out.content_length_n) - p;
[1909]         v->valid = 1;
[1910]         v->no_cacheable = 0;
[1911]         v->not_found = 0;
[1912]         v->data = p;
[1913] 
[1914]         return NGX_OK;
[1915]     }
[1916] 
[1917]     v->not_found = 1;
[1918] 
[1919]     return NGX_OK;
[1920] }
[1921] 
[1922] 
[1923] static ngx_int_t
[1924] ngx_http_variable_sent_location(ngx_http_request_t *r,
[1925]     ngx_http_variable_value_t *v, uintptr_t data)
[1926] {
[1927]     ngx_str_t  name;
[1928] 
[1929]     if (r->headers_out.location) {
[1930]         v->len = r->headers_out.location->value.len;
[1931]         v->valid = 1;
[1932]         v->no_cacheable = 0;
[1933]         v->not_found = 0;
[1934]         v->data = r->headers_out.location->value.data;
[1935] 
[1936]         return NGX_OK;
[1937]     }
[1938] 
[1939]     ngx_str_set(&name, "sent_http_location");
[1940] 
[1941]     return ngx_http_variable_unknown_header(r, v, &name,
[1942]                                             &r->headers_out.headers.part,
[1943]                                             sizeof("sent_http_") - 1);
[1944] }
[1945] 
[1946] 
[1947] static ngx_int_t
[1948] ngx_http_variable_sent_last_modified(ngx_http_request_t *r,
[1949]     ngx_http_variable_value_t *v, uintptr_t data)
[1950] {
[1951]     u_char  *p;
[1952] 
[1953]     if (r->headers_out.last_modified) {
[1954]         v->len = r->headers_out.last_modified->value.len;
[1955]         v->valid = 1;
[1956]         v->no_cacheable = 0;
[1957]         v->not_found = 0;
[1958]         v->data = r->headers_out.last_modified->value.data;
[1959] 
[1960]         return NGX_OK;
[1961]     }
[1962] 
[1963]     if (r->headers_out.last_modified_time >= 0) {
[1964]         p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
[1965]         if (p == NULL) {
[1966]             return NGX_ERROR;
[1967]         }
[1968] 
[1969]         v->len = ngx_http_time(p, r->headers_out.last_modified_time) - p;
[1970]         v->valid = 1;
[1971]         v->no_cacheable = 0;
[1972]         v->not_found = 0;
[1973]         v->data = p;
[1974] 
[1975]         return NGX_OK;
[1976]     }
[1977] 
[1978]     v->not_found = 1;
[1979] 
[1980]     return NGX_OK;
[1981] }
[1982] 
[1983] 
[1984] static ngx_int_t
[1985] ngx_http_variable_sent_connection(ngx_http_request_t *r,
[1986]     ngx_http_variable_value_t *v, uintptr_t data)
[1987] {
[1988]     size_t   len;
[1989]     char    *p;
[1990] 
[1991]     if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
[1992]         len = sizeof("upgrade") - 1;
[1993]         p = "upgrade";
[1994] 
[1995]     } else if (r->keepalive) {
[1996]         len = sizeof("keep-alive") - 1;
[1997]         p = "keep-alive";
[1998] 
[1999]     } else {
[2000]         len = sizeof("close") - 1;
[2001]         p = "close";
[2002]     }
[2003] 
[2004]     v->len = len;
[2005]     v->valid = 1;
[2006]     v->no_cacheable = 0;
[2007]     v->not_found = 0;
[2008]     v->data = (u_char *) p;
[2009] 
[2010]     return NGX_OK;
[2011] }
[2012] 
[2013] 
[2014] static ngx_int_t
[2015] ngx_http_variable_sent_keep_alive(ngx_http_request_t *r,
[2016]     ngx_http_variable_value_t *v, uintptr_t data)
[2017] {
[2018]     u_char                    *p;
[2019]     ngx_http_core_loc_conf_t  *clcf;
[2020] 
[2021]     if (r->keepalive) {
[2022]         clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[2023] 
[2024]         if (clcf->keepalive_header) {
[2025] 
[2026]             p = ngx_pnalloc(r->pool, sizeof("timeout=") - 1 + NGX_TIME_T_LEN);
[2027]             if (p == NULL) {
[2028]                 return NGX_ERROR;
[2029]             }
[2030] 
[2031]             v->len = ngx_sprintf(p, "timeout=%T", clcf->keepalive_header) - p;
[2032]             v->valid = 1;
[2033]             v->no_cacheable = 0;
[2034]             v->not_found = 0;
[2035]             v->data = p;
[2036] 
[2037]             return NGX_OK;
[2038]         }
[2039]     }
[2040] 
[2041]     v->not_found = 1;
[2042] 
[2043]     return NGX_OK;
[2044] }
[2045] 
[2046] 
[2047] static ngx_int_t
[2048] ngx_http_variable_sent_transfer_encoding(ngx_http_request_t *r,
[2049]     ngx_http_variable_value_t *v, uintptr_t data)
[2050] {
[2051]     if (r->chunked) {
[2052]         v->len = sizeof("chunked") - 1;
[2053]         v->valid = 1;
[2054]         v->no_cacheable = 0;
[2055]         v->not_found = 0;
[2056]         v->data = (u_char *) "chunked";
[2057] 
[2058]     } else {
[2059]         v->not_found = 1;
[2060]     }
[2061] 
[2062]     return NGX_OK;
[2063] }
[2064] 
[2065] 
[2066] static void
[2067] ngx_http_variable_set_limit_rate(ngx_http_request_t *r,
[2068]     ngx_http_variable_value_t *v, uintptr_t data)
[2069] {
[2070]     ssize_t    s;
[2071]     ngx_str_t  val;
[2072] 
[2073]     val.len = v->len;
[2074]     val.data = v->data;
[2075] 
[2076]     s = ngx_parse_size(&val);
[2077] 
[2078]     if (s == NGX_ERROR) {
[2079]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[2080]                       "invalid $limit_rate \"%V\"", &val);
[2081]         return;
[2082]     }
[2083] 
[2084]     r->limit_rate = s;
[2085]     r->limit_rate_set = 1;
[2086] }
[2087] 
[2088] 
[2089] static ngx_int_t
[2090] ngx_http_variable_request_completion(ngx_http_request_t *r,
[2091]     ngx_http_variable_value_t *v, uintptr_t data)
[2092] {
[2093]     if (r->request_complete) {
[2094]         v->len = 2;
[2095]         v->valid = 1;
[2096]         v->no_cacheable = 0;
[2097]         v->not_found = 0;
[2098]         v->data = (u_char *) "OK";
[2099] 
[2100]         return NGX_OK;
[2101]     }
[2102] 
[2103]     *v = ngx_http_variable_null_value;
[2104] 
[2105]     return NGX_OK;
[2106] }
[2107] 
[2108] 
[2109] static ngx_int_t
[2110] ngx_http_variable_request_body(ngx_http_request_t *r,
[2111]     ngx_http_variable_value_t *v, uintptr_t data)
[2112] {
[2113]     u_char       *p;
[2114]     size_t        len;
[2115]     ngx_buf_t    *buf;
[2116]     ngx_chain_t  *cl;
[2117] 
[2118]     if (r->request_body == NULL
[2119]         || r->request_body->bufs == NULL
[2120]         || r->request_body->temp_file)
[2121]     {
[2122]         v->not_found = 1;
[2123] 
[2124]         return NGX_OK;
[2125]     }
[2126] 
[2127]     cl = r->request_body->bufs;
[2128]     buf = cl->buf;
[2129] 
[2130]     if (cl->next == NULL) {
[2131]         v->len = buf->last - buf->pos;
[2132]         v->valid = 1;
[2133]         v->no_cacheable = 0;
[2134]         v->not_found = 0;
[2135]         v->data = buf->pos;
[2136] 
[2137]         return NGX_OK;
[2138]     }
[2139] 
[2140]     len = buf->last - buf->pos;
[2141]     cl = cl->next;
[2142] 
[2143]     for ( /* void */ ; cl; cl = cl->next) {
[2144]         buf = cl->buf;
[2145]         len += buf->last - buf->pos;
[2146]     }
[2147] 
[2148]     p = ngx_pnalloc(r->pool, len);
[2149]     if (p == NULL) {
[2150]         return NGX_ERROR;
[2151]     }
[2152] 
[2153]     v->data = p;
[2154]     cl = r->request_body->bufs;
[2155] 
[2156]     for ( /* void */ ; cl; cl = cl->next) {
[2157]         buf = cl->buf;
[2158]         p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
[2159]     }
[2160] 
[2161]     v->len = len;
[2162]     v->valid = 1;
[2163]     v->no_cacheable = 0;
[2164]     v->not_found = 0;
[2165] 
[2166]     return NGX_OK;
[2167] }
[2168] 
[2169] 
[2170] static ngx_int_t
[2171] ngx_http_variable_request_body_file(ngx_http_request_t *r,
[2172]     ngx_http_variable_value_t *v, uintptr_t data)
[2173] {
[2174]     if (r->request_body == NULL || r->request_body->temp_file == NULL) {
[2175]         v->not_found = 1;
[2176] 
[2177]         return NGX_OK;
[2178]     }
[2179] 
[2180]     v->len = r->request_body->temp_file->file.name.len;
[2181]     v->valid = 1;
[2182]     v->no_cacheable = 0;
[2183]     v->not_found = 0;
[2184]     v->data = r->request_body->temp_file->file.name.data;
[2185] 
[2186]     return NGX_OK;
[2187] }
[2188] 
[2189] 
[2190] static ngx_int_t
[2191] ngx_http_variable_request_length(ngx_http_request_t *r,
[2192]     ngx_http_variable_value_t *v, uintptr_t data)
[2193] {
[2194]     u_char  *p;
[2195] 
[2196]     p = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);
[2197]     if (p == NULL) {
[2198]         return NGX_ERROR;
[2199]     }
[2200] 
[2201]     v->len = ngx_sprintf(p, "%O", r->request_length) - p;
[2202]     v->valid = 1;
[2203]     v->no_cacheable = 0;
[2204]     v->not_found = 0;
[2205]     v->data = p;
[2206] 
[2207]     return NGX_OK;
[2208] }
[2209] 
[2210] 
[2211] static ngx_int_t
[2212] ngx_http_variable_request_time(ngx_http_request_t *r,
[2213]     ngx_http_variable_value_t *v, uintptr_t data)
[2214] {
[2215]     u_char          *p;
[2216]     ngx_time_t      *tp;
[2217]     ngx_msec_int_t   ms;
[2218] 
[2219]     p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
[2220]     if (p == NULL) {
[2221]         return NGX_ERROR;
[2222]     }
[2223] 
[2224]     tp = ngx_timeofday();
[2225] 
[2226]     ms = (ngx_msec_int_t)
[2227]              ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
[2228]     ms = ngx_max(ms, 0);
[2229] 
[2230]     v->len = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
[2231]     v->valid = 1;
[2232]     v->no_cacheable = 0;
[2233]     v->not_found = 0;
[2234]     v->data = p;
[2235] 
[2236]     return NGX_OK;
[2237] }
[2238] 
[2239] 
[2240] static ngx_int_t
[2241] ngx_http_variable_request_id(ngx_http_request_t *r,
[2242]     ngx_http_variable_value_t *v, uintptr_t data)
[2243] {
[2244]     u_char  *id;
[2245] 
[2246] #if (NGX_OPENSSL)
[2247]     u_char   random_bytes[16];
[2248] #endif
[2249] 
[2250]     id = ngx_pnalloc(r->pool, 32);
[2251]     if (id == NULL) {
[2252]         return NGX_ERROR;
[2253]     }
[2254] 
[2255]     v->valid = 1;
[2256]     v->no_cacheable = 0;
[2257]     v->not_found = 0;
[2258] 
[2259]     v->len = 32;
[2260]     v->data = id;
[2261] 
[2262] #if (NGX_OPENSSL)
[2263] 
[2264]     if (RAND_bytes(random_bytes, 16) == 1) {
[2265]         ngx_hex_dump(id, random_bytes, 16);
[2266]         return NGX_OK;
[2267]     }
[2268] 
[2269]     ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");
[2270] 
[2271] #endif
[2272] 
[2273]     ngx_sprintf(id, "%08xD%08xD%08xD%08xD",
[2274]                 (uint32_t) ngx_random(), (uint32_t) ngx_random(),
[2275]                 (uint32_t) ngx_random(), (uint32_t) ngx_random());
[2276] 
[2277]     return NGX_OK;
[2278] }
[2279] 
[2280] 
[2281] static ngx_int_t
[2282] ngx_http_variable_connection(ngx_http_request_t *r,
[2283]     ngx_http_variable_value_t *v, uintptr_t data)
[2284] {
[2285]     u_char  *p;
[2286] 
[2287]     p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
[2288]     if (p == NULL) {
[2289]         return NGX_ERROR;
[2290]     }
[2291] 
[2292]     v->len = ngx_sprintf(p, "%uA", r->connection->number) - p;
[2293]     v->valid = 1;
[2294]     v->no_cacheable = 0;
[2295]     v->not_found = 0;
[2296]     v->data = p;
[2297] 
[2298]     return NGX_OK;
[2299] }
[2300] 
[2301] 
[2302] static ngx_int_t
[2303] ngx_http_variable_connection_requests(ngx_http_request_t *r,
[2304]     ngx_http_variable_value_t *v, uintptr_t data)
[2305] {
[2306]     u_char  *p;
[2307] 
[2308]     p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
[2309]     if (p == NULL) {
[2310]         return NGX_ERROR;
[2311]     }
[2312] 
[2313]     v->len = ngx_sprintf(p, "%ui", r->connection->requests) - p;
[2314]     v->valid = 1;
[2315]     v->no_cacheable = 0;
[2316]     v->not_found = 0;
[2317]     v->data = p;
[2318] 
[2319]     return NGX_OK;
[2320] }
[2321] 
[2322] 
[2323] static ngx_int_t
[2324] ngx_http_variable_connection_time(ngx_http_request_t *r,
[2325]     ngx_http_variable_value_t *v, uintptr_t data)
[2326] {
[2327]     u_char          *p;
[2328]     ngx_msec_int_t   ms;
[2329] 
[2330]     p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
[2331]     if (p == NULL) {
[2332]         return NGX_ERROR;
[2333]     }
[2334] 
[2335]     ms = ngx_current_msec - r->connection->start_time;
[2336]     ms = ngx_max(ms, 0);
[2337] 
[2338]     v->len = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
[2339]     v->valid = 1;
[2340]     v->no_cacheable = 0;
[2341]     v->not_found = 0;
[2342]     v->data = p;
[2343] 
[2344]     return NGX_OK;
[2345] }
[2346] 
[2347] 
[2348] static ngx_int_t
[2349] ngx_http_variable_nginx_version(ngx_http_request_t *r,
[2350]     ngx_http_variable_value_t *v, uintptr_t data)
[2351] {
[2352]     v->len = sizeof(NGINX_VERSION) - 1;
[2353]     v->valid = 1;
[2354]     v->no_cacheable = 0;
[2355]     v->not_found = 0;
[2356]     v->data = (u_char *) NGINX_VERSION;
[2357] 
[2358]     return NGX_OK;
[2359] }
[2360] 
[2361] 
[2362] static ngx_int_t
[2363] ngx_http_variable_hostname(ngx_http_request_t *r,
[2364]     ngx_http_variable_value_t *v, uintptr_t data)
[2365] {
[2366]     v->len = ngx_cycle->hostname.len;
[2367]     v->valid = 1;
[2368]     v->no_cacheable = 0;
[2369]     v->not_found = 0;
[2370]     v->data = ngx_cycle->hostname.data;
[2371] 
[2372]     return NGX_OK;
[2373] }
[2374] 
[2375] 
[2376] static ngx_int_t
[2377] ngx_http_variable_pid(ngx_http_request_t *r,
[2378]     ngx_http_variable_value_t *v, uintptr_t data)
[2379] {
[2380]     u_char  *p;
[2381] 
[2382]     p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
[2383]     if (p == NULL) {
[2384]         return NGX_ERROR;
[2385]     }
[2386] 
[2387]     v->len = ngx_sprintf(p, "%P", ngx_pid) - p;
[2388]     v->valid = 1;
[2389]     v->no_cacheable = 0;
[2390]     v->not_found = 0;
[2391]     v->data = p;
[2392] 
[2393]     return NGX_OK;
[2394] }
[2395] 
[2396] 
[2397] static ngx_int_t
[2398] ngx_http_variable_msec(ngx_http_request_t *r,
[2399]     ngx_http_variable_value_t *v, uintptr_t data)
[2400] {
[2401]     u_char      *p;
[2402]     ngx_time_t  *tp;
[2403] 
[2404]     p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
[2405]     if (p == NULL) {
[2406]         return NGX_ERROR;
[2407]     }
[2408] 
[2409]     tp = ngx_timeofday();
[2410] 
[2411]     v->len = ngx_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
[2412]     v->valid = 1;
[2413]     v->no_cacheable = 0;
[2414]     v->not_found = 0;
[2415]     v->data = p;
[2416] 
[2417]     return NGX_OK;
[2418] }
[2419] 
[2420] 
[2421] static ngx_int_t
[2422] ngx_http_variable_time_iso8601(ngx_http_request_t *r,
[2423]     ngx_http_variable_value_t *v, uintptr_t data)
[2424] {
[2425]     u_char  *p;
[2426] 
[2427]     p = ngx_pnalloc(r->pool, ngx_cached_http_log_iso8601.len);
[2428]     if (p == NULL) {
[2429]         return NGX_ERROR;
[2430]     }
[2431] 
[2432]     ngx_memcpy(p, ngx_cached_http_log_iso8601.data,
[2433]                ngx_cached_http_log_iso8601.len);
[2434] 
[2435]     v->len = ngx_cached_http_log_iso8601.len;
[2436]     v->valid = 1;
[2437]     v->no_cacheable = 0;
[2438]     v->not_found = 0;
[2439]     v->data = p;
[2440] 
[2441]     return NGX_OK;
[2442] }
[2443] 
[2444] 
[2445] static ngx_int_t
[2446] ngx_http_variable_time_local(ngx_http_request_t *r,
[2447]     ngx_http_variable_value_t *v, uintptr_t data)
[2448] {
[2449]     u_char  *p;
[2450] 
[2451]     p = ngx_pnalloc(r->pool, ngx_cached_http_log_time.len);
[2452]     if (p == NULL) {
[2453]         return NGX_ERROR;
[2454]     }
[2455] 
[2456]     ngx_memcpy(p, ngx_cached_http_log_time.data, ngx_cached_http_log_time.len);
[2457] 
[2458]     v->len = ngx_cached_http_log_time.len;
[2459]     v->valid = 1;
[2460]     v->no_cacheable = 0;
[2461]     v->not_found = 0;
[2462]     v->data = p;
[2463] 
[2464]     return NGX_OK;
[2465] }
[2466] 
[2467] 
[2468] void *
[2469] ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map, ngx_str_t *match)
[2470] {
[2471]     void        *value;
[2472]     u_char      *low;
[2473]     size_t       len;
[2474]     ngx_uint_t   key;
[2475] 
[2476]     len = match->len;
[2477] 
[2478]     if (len) {
[2479]         low = ngx_pnalloc(r->pool, len);
[2480]         if (low == NULL) {
[2481]             return NULL;
[2482]         }
[2483] 
[2484]     } else {
[2485]         low = NULL;
[2486]     }
[2487] 
[2488]     key = ngx_hash_strlow(low, match->data, len);
[2489] 
[2490]     value = ngx_hash_find_combined(&map->hash, key, low, len);
[2491]     if (value) {
[2492]         return value;
[2493]     }
[2494] 
[2495] #if (NGX_PCRE)
[2496] 
[2497]     if (len && map->nregex) {
[2498]         ngx_int_t              n;
[2499]         ngx_uint_t             i;
[2500]         ngx_http_map_regex_t  *reg;
[2501] 
[2502]         reg = map->regex;
[2503] 
[2504]         for (i = 0; i < map->nregex; i++) {
[2505] 
[2506]             n = ngx_http_regex_exec(r, reg[i].regex, match);
[2507] 
[2508]             if (n == NGX_OK) {
[2509]                 return reg[i].value;
[2510]             }
[2511] 
[2512]             if (n == NGX_DECLINED) {
[2513]                 continue;
[2514]             }
[2515] 
[2516]             /* NGX_ERROR */
[2517] 
[2518]             return NULL;
[2519]         }
[2520]     }
[2521] 
[2522] #endif
[2523] 
[2524]     return NULL;
[2525] }
[2526] 
[2527] 
[2528] #if (NGX_PCRE)
[2529] 
[2530] static ngx_int_t
[2531] ngx_http_variable_not_found(ngx_http_request_t *r, ngx_http_variable_value_t *v,
[2532]     uintptr_t data)
[2533] {
[2534]     v->not_found = 1;
[2535]     return NGX_OK;
[2536] }
[2537] 
[2538] 
[2539] ngx_http_regex_t *
[2540] ngx_http_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
[2541] {
[2542]     u_char                     *p;
[2543]     size_t                      size;
[2544]     ngx_str_t                   name;
[2545]     ngx_uint_t                  i, n;
[2546]     ngx_http_variable_t        *v;
[2547]     ngx_http_regex_t           *re;
[2548]     ngx_http_regex_variable_t  *rv;
[2549]     ngx_http_core_main_conf_t  *cmcf;
[2550] 
[2551]     rc->pool = cf->pool;
[2552] 
[2553]     if (ngx_regex_compile(rc) != NGX_OK) {
[2554]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
[2555]         return NULL;
[2556]     }
[2557] 
[2558]     re = ngx_pcalloc(cf->pool, sizeof(ngx_http_regex_t));
[2559]     if (re == NULL) {
[2560]         return NULL;
[2561]     }
[2562] 
[2563]     re->regex = rc->regex;
[2564]     re->ncaptures = rc->captures;
[2565]     re->name = rc->pattern;
[2566] 
[2567]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[2568]     cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);
[2569] 
[2570]     n = (ngx_uint_t) rc->named_captures;
[2571] 
[2572]     if (n == 0) {
[2573]         return re;
[2574]     }
[2575] 
[2576]     rv = ngx_palloc(rc->pool, n * sizeof(ngx_http_regex_variable_t));
[2577]     if (rv == NULL) {
[2578]         return NULL;
[2579]     }
[2580] 
[2581]     re->variables = rv;
[2582]     re->nvariables = n;
[2583] 
[2584]     size = rc->name_size;
[2585]     p = rc->names;
[2586] 
[2587]     for (i = 0; i < n; i++) {
[2588]         rv[i].capture = 2 * ((p[0] << 8) + p[1]);
[2589] 
[2590]         name.data = &p[2];
[2591]         name.len = ngx_strlen(name.data);
[2592] 
[2593]         v = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
[2594]         if (v == NULL) {
[2595]             return NULL;
[2596]         }
[2597] 
[2598]         rv[i].index = ngx_http_get_variable_index(cf, &name);
[2599]         if (rv[i].index == NGX_ERROR) {
[2600]             return NULL;
[2601]         }
[2602] 
[2603]         v->get_handler = ngx_http_variable_not_found;
[2604] 
[2605]         p += size;
[2606]     }
[2607] 
[2608]     return re;
[2609] }
[2610] 
[2611] 
[2612] ngx_int_t
[2613] ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s)
[2614] {
[2615]     ngx_int_t                   rc, index;
[2616]     ngx_uint_t                  i, n, len;
[2617]     ngx_http_variable_value_t  *vv;
[2618]     ngx_http_core_main_conf_t  *cmcf;
[2619] 
[2620]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[2621] 
[2622]     if (re->ncaptures) {
[2623]         len = cmcf->ncaptures;
[2624] 
[2625]         if (r->captures == NULL || r->realloc_captures) {
[2626]             r->realloc_captures = 0;
[2627] 
[2628]             r->captures = ngx_palloc(r->pool, len * sizeof(int));
[2629]             if (r->captures == NULL) {
[2630]                 return NGX_ERROR;
[2631]             }
[2632]         }
[2633] 
[2634]     } else {
[2635]         len = 0;
[2636]     }
[2637] 
[2638]     rc = ngx_regex_exec(re->regex, s, r->captures, len);
[2639] 
[2640]     if (rc == NGX_REGEX_NO_MATCHED) {
[2641]         return NGX_DECLINED;
[2642]     }
[2643] 
[2644]     if (rc < 0) {
[2645]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[2646]                       ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
[2647]                       rc, s, &re->name);
[2648]         return NGX_ERROR;
[2649]     }
[2650] 
[2651]     for (i = 0; i < re->nvariables; i++) {
[2652] 
[2653]         n = re->variables[i].capture;
[2654]         index = re->variables[i].index;
[2655]         vv = &r->variables[index];
[2656] 
[2657]         vv->len = r->captures[n + 1] - r->captures[n];
[2658]         vv->valid = 1;
[2659]         vv->no_cacheable = 0;
[2660]         vv->not_found = 0;
[2661]         vv->data = &s->data[r->captures[n]];
[2662] 
[2663] #if (NGX_DEBUG)
[2664]         {
[2665]         ngx_http_variable_t  *v;
[2666] 
[2667]         v = cmcf->variables.elts;
[2668] 
[2669]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[2670]                        "http regex set $%V to \"%v\"", &v[index].name, vv);
[2671]         }
[2672] #endif
[2673]     }
[2674] 
[2675]     r->ncaptures = rc * 2;
[2676]     r->captures_data = s->data;
[2677] 
[2678]     return NGX_OK;
[2679] }
[2680] 
[2681] #endif
[2682] 
[2683] 
[2684] ngx_int_t
[2685] ngx_http_variables_add_core_vars(ngx_conf_t *cf)
[2686] {
[2687]     ngx_http_variable_t        *cv, *v;
[2688]     ngx_http_core_main_conf_t  *cmcf;
[2689] 
[2690]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[2691] 
[2692]     cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
[2693]                                        sizeof(ngx_hash_keys_arrays_t));
[2694]     if (cmcf->variables_keys == NULL) {
[2695]         return NGX_ERROR;
[2696]     }
[2697] 
[2698]     cmcf->variables_keys->pool = cf->pool;
[2699]     cmcf->variables_keys->temp_pool = cf->pool;
[2700] 
[2701]     if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
[2702]         != NGX_OK)
[2703]     {
[2704]         return NGX_ERROR;
[2705]     }
[2706] 
[2707]     if (ngx_array_init(&cmcf->prefix_variables, cf->pool, 8,
[2708]                        sizeof(ngx_http_variable_t))
[2709]         != NGX_OK)
[2710]     {
[2711]         return NGX_ERROR;
[2712]     }
[2713] 
[2714]     for (cv = ngx_http_core_variables; cv->name.len; cv++) {
[2715]         v = ngx_http_add_variable(cf, &cv->name, cv->flags);
[2716]         if (v == NULL) {
[2717]             return NGX_ERROR;
[2718]         }
[2719] 
[2720]         *v = *cv;
[2721]     }
[2722] 
[2723]     return NGX_OK;
[2724] }
[2725] 
[2726] 
[2727] ngx_int_t
[2728] ngx_http_variables_init_vars(ngx_conf_t *cf)
[2729] {
[2730]     size_t                      len;
[2731]     ngx_uint_t                  i, n;
[2732]     ngx_hash_key_t             *key;
[2733]     ngx_hash_init_t             hash;
[2734]     ngx_http_variable_t        *v, *av, *pv;
[2735]     ngx_http_core_main_conf_t  *cmcf;
[2736] 
[2737]     /* set the handlers for the indexed http variables */
[2738] 
[2739]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[2740] 
[2741]     v = cmcf->variables.elts;
[2742]     pv = cmcf->prefix_variables.elts;
[2743]     key = cmcf->variables_keys->keys.elts;
[2744] 
[2745]     for (i = 0; i < cmcf->variables.nelts; i++) {
[2746] 
[2747]         for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
[2748] 
[2749]             av = key[n].value;
[2750] 
[2751]             if (v[i].name.len == key[n].key.len
[2752]                 && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
[2753]                    == 0)
[2754]             {
[2755]                 v[i].get_handler = av->get_handler;
[2756]                 v[i].data = av->data;
[2757] 
[2758]                 av->flags |= NGX_HTTP_VAR_INDEXED;
[2759]                 v[i].flags = av->flags;
[2760] 
[2761]                 av->index = i;
[2762] 
[2763]                 if (av->get_handler == NULL
[2764]                     || (av->flags & NGX_HTTP_VAR_WEAK))
[2765]                 {
[2766]                     break;
[2767]                 }
[2768] 
[2769]                 goto next;
[2770]             }
[2771]         }
[2772] 
[2773]         len = 0;
[2774]         av = NULL;
[2775] 
[2776]         for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
[2777]             if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
[2778]                 && ngx_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
[2779]                    == 0)
[2780]             {
[2781]                 av = &pv[n];
[2782]                 len = pv[n].name.len;
[2783]             }
[2784]         }
[2785] 
[2786]         if (av) {
[2787]             v[i].get_handler = av->get_handler;
[2788]             v[i].data = (uintptr_t) &v[i].name;
[2789]             v[i].flags = av->flags;
[2790] 
[2791]             goto next;
[2792]         }
[2793] 
[2794]         if (v[i].get_handler == NULL) {
[2795]             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[2796]                           "unknown \"%V\" variable", &v[i].name);
[2797] 
[2798]             return NGX_ERROR;
[2799]         }
[2800] 
[2801]     next:
[2802]         continue;
[2803]     }
[2804] 
[2805] 
[2806]     for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
[2807]         av = key[n].value;
[2808] 
[2809]         if (av->flags & NGX_HTTP_VAR_NOHASH) {
[2810]             key[n].key.data = NULL;
[2811]         }
[2812]     }
[2813] 
[2814] 
[2815]     hash.hash = &cmcf->variables_hash;
[2816]     hash.key = ngx_hash_key;
[2817]     hash.max_size = cmcf->variables_hash_max_size;
[2818]     hash.bucket_size = cmcf->variables_hash_bucket_size;
[2819]     hash.name = "variables_hash";
[2820]     hash.pool = cf->pool;
[2821]     hash.temp_pool = NULL;
[2822] 
[2823]     if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
[2824]                       cmcf->variables_keys->keys.nelts)
[2825]         != NGX_OK)
[2826]     {
[2827]         return NGX_ERROR;
[2828]     }
[2829] 
[2830]     cmcf->variables_keys = NULL;
[2831] 
[2832]     return NGX_OK;
[2833] }
