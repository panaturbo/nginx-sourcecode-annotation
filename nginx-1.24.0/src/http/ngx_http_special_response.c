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
[14] static ngx_int_t ngx_http_send_error_page(ngx_http_request_t *r,
[15]     ngx_http_err_page_t *err_page);
[16] static ngx_int_t ngx_http_send_special_response(ngx_http_request_t *r,
[17]     ngx_http_core_loc_conf_t *clcf, ngx_uint_t err);
[18] static ngx_int_t ngx_http_send_refresh(ngx_http_request_t *r);
[19] 
[20] 
[21] static u_char ngx_http_error_full_tail[] =
[22] "<hr><center>" NGINX_VER "</center>" CRLF
[23] "</body>" CRLF
[24] "</html>" CRLF
[25] ;
[26] 
[27] 
[28] static u_char ngx_http_error_build_tail[] =
[29] "<hr><center>" NGINX_VER_BUILD "</center>" CRLF
[30] "</body>" CRLF
[31] "</html>" CRLF
[32] ;
[33] 
[34] 
[35] static u_char ngx_http_error_tail[] =
[36] "<hr><center>nginx</center>" CRLF
[37] "</body>" CRLF
[38] "</html>" CRLF
[39] ;
[40] 
[41] 
[42] static u_char ngx_http_msie_padding[] =
[43] "<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
[44] "<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
[45] "<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
[46] "<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
[47] "<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
[48] "<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
[49] ;
[50] 
[51] 
[52] static u_char ngx_http_msie_refresh_head[] =
[53] "<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";
[54] 
[55] 
[56] static u_char ngx_http_msie_refresh_tail[] =
[57] "\"></head><body></body></html>" CRLF;
[58] 
[59] 
[60] static char ngx_http_error_301_page[] =
[61] "<html>" CRLF
[62] "<head><title>301 Moved Permanently</title></head>" CRLF
[63] "<body>" CRLF
[64] "<center><h1>301 Moved Permanently</h1></center>" CRLF
[65] ;
[66] 
[67] 
[68] static char ngx_http_error_302_page[] =
[69] "<html>" CRLF
[70] "<head><title>302 Found</title></head>" CRLF
[71] "<body>" CRLF
[72] "<center><h1>302 Found</h1></center>" CRLF
[73] ;
[74] 
[75] 
[76] static char ngx_http_error_303_page[] =
[77] "<html>" CRLF
[78] "<head><title>303 See Other</title></head>" CRLF
[79] "<body>" CRLF
[80] "<center><h1>303 See Other</h1></center>" CRLF
[81] ;
[82] 
[83] 
[84] static char ngx_http_error_307_page[] =
[85] "<html>" CRLF
[86] "<head><title>307 Temporary Redirect</title></head>" CRLF
[87] "<body>" CRLF
[88] "<center><h1>307 Temporary Redirect</h1></center>" CRLF
[89] ;
[90] 
[91] 
[92] static char ngx_http_error_308_page[] =
[93] "<html>" CRLF
[94] "<head><title>308 Permanent Redirect</title></head>" CRLF
[95] "<body>" CRLF
[96] "<center><h1>308 Permanent Redirect</h1></center>" CRLF
[97] ;
[98] 
[99] 
[100] static char ngx_http_error_400_page[] =
[101] "<html>" CRLF
[102] "<head><title>400 Bad Request</title></head>" CRLF
[103] "<body>" CRLF
[104] "<center><h1>400 Bad Request</h1></center>" CRLF
[105] ;
[106] 
[107] 
[108] static char ngx_http_error_401_page[] =
[109] "<html>" CRLF
[110] "<head><title>401 Authorization Required</title></head>" CRLF
[111] "<body>" CRLF
[112] "<center><h1>401 Authorization Required</h1></center>" CRLF
[113] ;
[114] 
[115] 
[116] static char ngx_http_error_402_page[] =
[117] "<html>" CRLF
[118] "<head><title>402 Payment Required</title></head>" CRLF
[119] "<body>" CRLF
[120] "<center><h1>402 Payment Required</h1></center>" CRLF
[121] ;
[122] 
[123] 
[124] static char ngx_http_error_403_page[] =
[125] "<html>" CRLF
[126] "<head><title>403 Forbidden</title></head>" CRLF
[127] "<body>" CRLF
[128] "<center><h1>403 Forbidden</h1></center>" CRLF
[129] ;
[130] 
[131] 
[132] static char ngx_http_error_404_page[] =
[133] "<html>" CRLF
[134] "<head><title>404 Not Found</title></head>" CRLF
[135] "<body>" CRLF
[136] "<center><h1>404 Not Found</h1></center>" CRLF
[137] ;
[138] 
[139] 
[140] static char ngx_http_error_405_page[] =
[141] "<html>" CRLF
[142] "<head><title>405 Not Allowed</title></head>" CRLF
[143] "<body>" CRLF
[144] "<center><h1>405 Not Allowed</h1></center>" CRLF
[145] ;
[146] 
[147] 
[148] static char ngx_http_error_406_page[] =
[149] "<html>" CRLF
[150] "<head><title>406 Not Acceptable</title></head>" CRLF
[151] "<body>" CRLF
[152] "<center><h1>406 Not Acceptable</h1></center>" CRLF
[153] ;
[154] 
[155] 
[156] static char ngx_http_error_408_page[] =
[157] "<html>" CRLF
[158] "<head><title>408 Request Time-out</title></head>" CRLF
[159] "<body>" CRLF
[160] "<center><h1>408 Request Time-out</h1></center>" CRLF
[161] ;
[162] 
[163] 
[164] static char ngx_http_error_409_page[] =
[165] "<html>" CRLF
[166] "<head><title>409 Conflict</title></head>" CRLF
[167] "<body>" CRLF
[168] "<center><h1>409 Conflict</h1></center>" CRLF
[169] ;
[170] 
[171] 
[172] static char ngx_http_error_410_page[] =
[173] "<html>" CRLF
[174] "<head><title>410 Gone</title></head>" CRLF
[175] "<body>" CRLF
[176] "<center><h1>410 Gone</h1></center>" CRLF
[177] ;
[178] 
[179] 
[180] static char ngx_http_error_411_page[] =
[181] "<html>" CRLF
[182] "<head><title>411 Length Required</title></head>" CRLF
[183] "<body>" CRLF
[184] "<center><h1>411 Length Required</h1></center>" CRLF
[185] ;
[186] 
[187] 
[188] static char ngx_http_error_412_page[] =
[189] "<html>" CRLF
[190] "<head><title>412 Precondition Failed</title></head>" CRLF
[191] "<body>" CRLF
[192] "<center><h1>412 Precondition Failed</h1></center>" CRLF
[193] ;
[194] 
[195] 
[196] static char ngx_http_error_413_page[] =
[197] "<html>" CRLF
[198] "<head><title>413 Request Entity Too Large</title></head>" CRLF
[199] "<body>" CRLF
[200] "<center><h1>413 Request Entity Too Large</h1></center>" CRLF
[201] ;
[202] 
[203] 
[204] static char ngx_http_error_414_page[] =
[205] "<html>" CRLF
[206] "<head><title>414 Request-URI Too Large</title></head>" CRLF
[207] "<body>" CRLF
[208] "<center><h1>414 Request-URI Too Large</h1></center>" CRLF
[209] ;
[210] 
[211] 
[212] static char ngx_http_error_415_page[] =
[213] "<html>" CRLF
[214] "<head><title>415 Unsupported Media Type</title></head>" CRLF
[215] "<body>" CRLF
[216] "<center><h1>415 Unsupported Media Type</h1></center>" CRLF
[217] ;
[218] 
[219] 
[220] static char ngx_http_error_416_page[] =
[221] "<html>" CRLF
[222] "<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
[223] "<body>" CRLF
[224] "<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
[225] ;
[226] 
[227] 
[228] static char ngx_http_error_421_page[] =
[229] "<html>" CRLF
[230] "<head><title>421 Misdirected Request</title></head>" CRLF
[231] "<body>" CRLF
[232] "<center><h1>421 Misdirected Request</h1></center>" CRLF
[233] ;
[234] 
[235] 
[236] static char ngx_http_error_429_page[] =
[237] "<html>" CRLF
[238] "<head><title>429 Too Many Requests</title></head>" CRLF
[239] "<body>" CRLF
[240] "<center><h1>429 Too Many Requests</h1></center>" CRLF
[241] ;
[242] 
[243] 
[244] static char ngx_http_error_494_page[] =
[245] "<html>" CRLF
[246] "<head><title>400 Request Header Or Cookie Too Large</title></head>"
[247] CRLF
[248] "<body>" CRLF
[249] "<center><h1>400 Bad Request</h1></center>" CRLF
[250] "<center>Request Header Or Cookie Too Large</center>" CRLF
[251] ;
[252] 
[253] 
[254] static char ngx_http_error_495_page[] =
[255] "<html>" CRLF
[256] "<head><title>400 The SSL certificate error</title></head>"
[257] CRLF
[258] "<body>" CRLF
[259] "<center><h1>400 Bad Request</h1></center>" CRLF
[260] "<center>The SSL certificate error</center>" CRLF
[261] ;
[262] 
[263] 
[264] static char ngx_http_error_496_page[] =
[265] "<html>" CRLF
[266] "<head><title>400 No required SSL certificate was sent</title></head>"
[267] CRLF
[268] "<body>" CRLF
[269] "<center><h1>400 Bad Request</h1></center>" CRLF
[270] "<center>No required SSL certificate was sent</center>" CRLF
[271] ;
[272] 
[273] 
[274] static char ngx_http_error_497_page[] =
[275] "<html>" CRLF
[276] "<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
[277] CRLF
[278] "<body>" CRLF
[279] "<center><h1>400 Bad Request</h1></center>" CRLF
[280] "<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
[281] ;
[282] 
[283] 
[284] static char ngx_http_error_500_page[] =
[285] "<html>" CRLF
[286] "<head><title>500 Internal Server Error</title></head>" CRLF
[287] "<body>" CRLF
[288] "<center><h1>500 Internal Server Error</h1></center>" CRLF
[289] ;
[290] 
[291] 
[292] static char ngx_http_error_501_page[] =
[293] "<html>" CRLF
[294] "<head><title>501 Not Implemented</title></head>" CRLF
[295] "<body>" CRLF
[296] "<center><h1>501 Not Implemented</h1></center>" CRLF
[297] ;
[298] 
[299] 
[300] static char ngx_http_error_502_page[] =
[301] "<html>" CRLF
[302] "<head><title>502 Bad Gateway</title></head>" CRLF
[303] "<body>" CRLF
[304] "<center><h1>502 Bad Gateway</h1></center>" CRLF
[305] ;
[306] 
[307] 
[308] static char ngx_http_error_503_page[] =
[309] "<html>" CRLF
[310] "<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
[311] "<body>" CRLF
[312] "<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
[313] ;
[314] 
[315] 
[316] static char ngx_http_error_504_page[] =
[317] "<html>" CRLF
[318] "<head><title>504 Gateway Time-out</title></head>" CRLF
[319] "<body>" CRLF
[320] "<center><h1>504 Gateway Time-out</h1></center>" CRLF
[321] ;
[322] 
[323] 
[324] static char ngx_http_error_505_page[] =
[325] "<html>" CRLF
[326] "<head><title>505 HTTP Version Not Supported</title></head>" CRLF
[327] "<body>" CRLF
[328] "<center><h1>505 HTTP Version Not Supported</h1></center>" CRLF
[329] ;
[330] 
[331] 
[332] static char ngx_http_error_507_page[] =
[333] "<html>" CRLF
[334] "<head><title>507 Insufficient Storage</title></head>" CRLF
[335] "<body>" CRLF
[336] "<center><h1>507 Insufficient Storage</h1></center>" CRLF
[337] ;
[338] 
[339] 
[340] static ngx_str_t ngx_http_error_pages[] = {
[341] 
[342]     ngx_null_string,                     /* 201, 204 */
[343] 
[344] #define NGX_HTTP_LAST_2XX  202
[345] #define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 201)
[346] 
[347]     /* ngx_null_string, */               /* 300 */
[348]     ngx_string(ngx_http_error_301_page),
[349]     ngx_string(ngx_http_error_302_page),
[350]     ngx_string(ngx_http_error_303_page),
[351]     ngx_null_string,                     /* 304 */
[352]     ngx_null_string,                     /* 305 */
[353]     ngx_null_string,                     /* 306 */
[354]     ngx_string(ngx_http_error_307_page),
[355]     ngx_string(ngx_http_error_308_page),
[356] 
[357] #define NGX_HTTP_LAST_3XX  309
[358] #define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)
[359] 
[360]     ngx_string(ngx_http_error_400_page),
[361]     ngx_string(ngx_http_error_401_page),
[362]     ngx_string(ngx_http_error_402_page),
[363]     ngx_string(ngx_http_error_403_page),
[364]     ngx_string(ngx_http_error_404_page),
[365]     ngx_string(ngx_http_error_405_page),
[366]     ngx_string(ngx_http_error_406_page),
[367]     ngx_null_string,                     /* 407 */
[368]     ngx_string(ngx_http_error_408_page),
[369]     ngx_string(ngx_http_error_409_page),
[370]     ngx_string(ngx_http_error_410_page),
[371]     ngx_string(ngx_http_error_411_page),
[372]     ngx_string(ngx_http_error_412_page),
[373]     ngx_string(ngx_http_error_413_page),
[374]     ngx_string(ngx_http_error_414_page),
[375]     ngx_string(ngx_http_error_415_page),
[376]     ngx_string(ngx_http_error_416_page),
[377]     ngx_null_string,                     /* 417 */
[378]     ngx_null_string,                     /* 418 */
[379]     ngx_null_string,                     /* 419 */
[380]     ngx_null_string,                     /* 420 */
[381]     ngx_string(ngx_http_error_421_page),
[382]     ngx_null_string,                     /* 422 */
[383]     ngx_null_string,                     /* 423 */
[384]     ngx_null_string,                     /* 424 */
[385]     ngx_null_string,                     /* 425 */
[386]     ngx_null_string,                     /* 426 */
[387]     ngx_null_string,                     /* 427 */
[388]     ngx_null_string,                     /* 428 */
[389]     ngx_string(ngx_http_error_429_page),
[390] 
[391] #define NGX_HTTP_LAST_4XX  430
[392] #define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)
[393] 
[394]     ngx_string(ngx_http_error_494_page), /* 494, request header too large */
[395]     ngx_string(ngx_http_error_495_page), /* 495, https certificate error */
[396]     ngx_string(ngx_http_error_496_page), /* 496, https no certificate */
[397]     ngx_string(ngx_http_error_497_page), /* 497, http to https */
[398]     ngx_string(ngx_http_error_404_page), /* 498, canceled */
[399]     ngx_null_string,                     /* 499, client has closed connection */
[400] 
[401]     ngx_string(ngx_http_error_500_page),
[402]     ngx_string(ngx_http_error_501_page),
[403]     ngx_string(ngx_http_error_502_page),
[404]     ngx_string(ngx_http_error_503_page),
[405]     ngx_string(ngx_http_error_504_page),
[406]     ngx_string(ngx_http_error_505_page),
[407]     ngx_null_string,                     /* 506 */
[408]     ngx_string(ngx_http_error_507_page)
[409] 
[410] #define NGX_HTTP_LAST_5XX  508
[411] 
[412] };
[413] 
[414] 
[415] ngx_int_t
[416] ngx_http_special_response_handler(ngx_http_request_t *r, ngx_int_t error)
[417] {
[418]     ngx_uint_t                 i, err;
[419]     ngx_http_err_page_t       *err_page;
[420]     ngx_http_core_loc_conf_t  *clcf;
[421] 
[422]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[423]                    "http special response: %i, \"%V?%V\"",
[424]                    error, &r->uri, &r->args);
[425] 
[426]     r->err_status = error;
[427] 
[428]     if (r->keepalive) {
[429]         switch (error) {
[430]             case NGX_HTTP_BAD_REQUEST:
[431]             case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE:
[432]             case NGX_HTTP_REQUEST_URI_TOO_LARGE:
[433]             case NGX_HTTP_TO_HTTPS:
[434]             case NGX_HTTPS_CERT_ERROR:
[435]             case NGX_HTTPS_NO_CERT:
[436]             case NGX_HTTP_INTERNAL_SERVER_ERROR:
[437]             case NGX_HTTP_NOT_IMPLEMENTED:
[438]                 r->keepalive = 0;
[439]         }
[440]     }
[441] 
[442]     if (r->lingering_close) {
[443]         switch (error) {
[444]             case NGX_HTTP_BAD_REQUEST:
[445]             case NGX_HTTP_TO_HTTPS:
[446]             case NGX_HTTPS_CERT_ERROR:
[447]             case NGX_HTTPS_NO_CERT:
[448]                 r->lingering_close = 0;
[449]         }
[450]     }
[451] 
[452]     r->headers_out.content_type.len = 0;
[453] 
[454]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[455] 
[456]     if (!r->error_page && clcf->error_pages && r->uri_changes != 0) {
[457] 
[458]         if (clcf->recursive_error_pages == 0) {
[459]             r->error_page = 1;
[460]         }
[461] 
[462]         err_page = clcf->error_pages->elts;
[463] 
[464]         for (i = 0; i < clcf->error_pages->nelts; i++) {
[465]             if (err_page[i].status == error) {
[466]                 return ngx_http_send_error_page(r, &err_page[i]);
[467]             }
[468]         }
[469]     }
[470] 
[471]     r->expect_tested = 1;
[472] 
[473]     if (ngx_http_discard_request_body(r) != NGX_OK) {
[474]         r->keepalive = 0;
[475]     }
[476] 
[477]     if (clcf->msie_refresh
[478]         && r->headers_in.msie
[479]         && (error == NGX_HTTP_MOVED_PERMANENTLY
[480]             || error == NGX_HTTP_MOVED_TEMPORARILY))
[481]     {
[482]         return ngx_http_send_refresh(r);
[483]     }
[484] 
[485]     if (error == NGX_HTTP_CREATED) {
[486]         /* 201 */
[487]         err = 0;
[488] 
[489]     } else if (error == NGX_HTTP_NO_CONTENT) {
[490]         /* 204 */
[491]         err = 0;
[492] 
[493]     } else if (error >= NGX_HTTP_MOVED_PERMANENTLY
[494]                && error < NGX_HTTP_LAST_3XX)
[495]     {
[496]         /* 3XX */
[497]         err = error - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
[498] 
[499]     } else if (error >= NGX_HTTP_BAD_REQUEST
[500]                && error < NGX_HTTP_LAST_4XX)
[501]     {
[502]         /* 4XX */
[503]         err = error - NGX_HTTP_BAD_REQUEST + NGX_HTTP_OFF_4XX;
[504] 
[505]     } else if (error >= NGX_HTTP_NGINX_CODES
[506]                && error < NGX_HTTP_LAST_5XX)
[507]     {
[508]         /* 49X, 5XX */
[509]         err = error - NGX_HTTP_NGINX_CODES + NGX_HTTP_OFF_5XX;
[510]         switch (error) {
[511]             case NGX_HTTP_TO_HTTPS:
[512]             case NGX_HTTPS_CERT_ERROR:
[513]             case NGX_HTTPS_NO_CERT:
[514]             case NGX_HTTP_REQUEST_HEADER_TOO_LARGE:
[515]                 r->err_status = NGX_HTTP_BAD_REQUEST;
[516]         }
[517] 
[518]     } else {
[519]         /* unknown code, zero body */
[520]         err = 0;
[521]     }
[522] 
[523]     return ngx_http_send_special_response(r, clcf, err);
[524] }
[525] 
[526] 
[527] ngx_int_t
[528] ngx_http_filter_finalize_request(ngx_http_request_t *r, ngx_module_t *m,
[529]     ngx_int_t error)
[530] {
[531]     void       *ctx;
[532]     ngx_int_t   rc;
[533] 
[534]     ngx_http_clean_header(r);
[535] 
[536]     ctx = NULL;
[537] 
[538]     if (m) {
[539]         ctx = r->ctx[m->ctx_index];
[540]     }
[541] 
[542]     /* clear the modules contexts */
[543]     ngx_memzero(r->ctx, sizeof(void *) * ngx_http_max_module);
[544] 
[545]     if (m) {
[546]         r->ctx[m->ctx_index] = ctx;
[547]     }
[548] 
[549]     r->filter_finalize = 1;
[550] 
[551]     rc = ngx_http_special_response_handler(r, error);
[552] 
[553]     /* NGX_ERROR resets any pending data */
[554] 
[555]     switch (rc) {
[556] 
[557]     case NGX_OK:
[558]     case NGX_DONE:
[559]         return NGX_ERROR;
[560] 
[561]     default:
[562]         return rc;
[563]     }
[564] }
[565] 
[566] 
[567] void
[568] ngx_http_clean_header(ngx_http_request_t *r)
[569] {
[570]     ngx_memzero(&r->headers_out.status,
[571]                 sizeof(ngx_http_headers_out_t)
[572]                     - offsetof(ngx_http_headers_out_t, status));
[573] 
[574]     r->headers_out.headers.part.nelts = 0;
[575]     r->headers_out.headers.part.next = NULL;
[576]     r->headers_out.headers.last = &r->headers_out.headers.part;
[577] 
[578]     r->headers_out.trailers.part.nelts = 0;
[579]     r->headers_out.trailers.part.next = NULL;
[580]     r->headers_out.trailers.last = &r->headers_out.trailers.part;
[581] 
[582]     r->headers_out.content_length_n = -1;
[583]     r->headers_out.last_modified_time = -1;
[584] }
[585] 
[586] 
[587] static ngx_int_t
[588] ngx_http_send_error_page(ngx_http_request_t *r, ngx_http_err_page_t *err_page)
[589] {
[590]     ngx_int_t                  overwrite;
[591]     ngx_str_t                  uri, args;
[592]     ngx_table_elt_t           *location;
[593]     ngx_http_core_loc_conf_t  *clcf;
[594] 
[595]     overwrite = err_page->overwrite;
[596] 
[597]     if (overwrite && overwrite != NGX_HTTP_OK) {
[598]         r->expect_tested = 1;
[599]     }
[600] 
[601]     if (overwrite >= 0) {
[602]         r->err_status = overwrite;
[603]     }
[604] 
[605]     if (ngx_http_complex_value(r, &err_page->value, &uri) != NGX_OK) {
[606]         return NGX_ERROR;
[607]     }
[608] 
[609]     if (uri.len && uri.data[0] == '/') {
[610] 
[611]         if (err_page->value.lengths) {
[612]             ngx_http_split_args(r, &uri, &args);
[613] 
[614]         } else {
[615]             args = err_page->args;
[616]         }
[617] 
[618]         if (r->method != NGX_HTTP_HEAD) {
[619]             r->method = NGX_HTTP_GET;
[620]             r->method_name = ngx_http_core_get_method;
[621]         }
[622] 
[623]         return ngx_http_internal_redirect(r, &uri, &args);
[624]     }
[625] 
[626]     if (uri.len && uri.data[0] == '@') {
[627]         return ngx_http_named_location(r, &uri);
[628]     }
[629] 
[630]     r->expect_tested = 1;
[631] 
[632]     if (ngx_http_discard_request_body(r) != NGX_OK) {
[633]         r->keepalive = 0;
[634]     }
[635] 
[636]     location = ngx_list_push(&r->headers_out.headers);
[637] 
[638]     if (location == NULL) {
[639]         return NGX_ERROR;
[640]     }
[641] 
[642]     if (overwrite != NGX_HTTP_MOVED_PERMANENTLY
[643]         && overwrite != NGX_HTTP_MOVED_TEMPORARILY
[644]         && overwrite != NGX_HTTP_SEE_OTHER
[645]         && overwrite != NGX_HTTP_TEMPORARY_REDIRECT
[646]         && overwrite != NGX_HTTP_PERMANENT_REDIRECT)
[647]     {
[648]         r->err_status = NGX_HTTP_MOVED_TEMPORARILY;
[649]     }
[650] 
[651]     location->hash = 1;
[652]     location->next = NULL;
[653]     ngx_str_set(&location->key, "Location");
[654]     location->value = uri;
[655] 
[656]     ngx_http_clear_location(r);
[657] 
[658]     r->headers_out.location = location;
[659] 
[660]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[661] 
[662]     if (clcf->msie_refresh && r->headers_in.msie) {
[663]         return ngx_http_send_refresh(r);
[664]     }
[665] 
[666]     return ngx_http_send_special_response(r, clcf, r->err_status
[667]                                                    - NGX_HTTP_MOVED_PERMANENTLY
[668]                                                    + NGX_HTTP_OFF_3XX);
[669] }
[670] 
[671] 
[672] static ngx_int_t
[673] ngx_http_send_special_response(ngx_http_request_t *r,
[674]     ngx_http_core_loc_conf_t *clcf, ngx_uint_t err)
[675] {
[676]     u_char       *tail;
[677]     size_t        len;
[678]     ngx_int_t     rc;
[679]     ngx_buf_t    *b;
[680]     ngx_uint_t    msie_padding;
[681]     ngx_chain_t   out[3];
[682] 
[683]     if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
[684]         len = sizeof(ngx_http_error_full_tail) - 1;
[685]         tail = ngx_http_error_full_tail;
[686] 
[687]     } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
[688]         len = sizeof(ngx_http_error_build_tail) - 1;
[689]         tail = ngx_http_error_build_tail;
[690] 
[691]     } else {
[692]         len = sizeof(ngx_http_error_tail) - 1;
[693]         tail = ngx_http_error_tail;
[694]     }
[695] 
[696]     msie_padding = 0;
[697] 
[698]     if (ngx_http_error_pages[err].len) {
[699]         r->headers_out.content_length_n = ngx_http_error_pages[err].len + len;
[700]         if (clcf->msie_padding
[701]             && (r->headers_in.msie || r->headers_in.chrome)
[702]             && r->http_version >= NGX_HTTP_VERSION_10
[703]             && err >= NGX_HTTP_OFF_4XX)
[704]         {
[705]             r->headers_out.content_length_n +=
[706]                                          sizeof(ngx_http_msie_padding) - 1;
[707]             msie_padding = 1;
[708]         }
[709] 
[710]         r->headers_out.content_type_len = sizeof("text/html") - 1;
[711]         ngx_str_set(&r->headers_out.content_type, "text/html");
[712]         r->headers_out.content_type_lowcase = NULL;
[713] 
[714]     } else {
[715]         r->headers_out.content_length_n = 0;
[716]     }
[717] 
[718]     if (r->headers_out.content_length) {
[719]         r->headers_out.content_length->hash = 0;
[720]         r->headers_out.content_length = NULL;
[721]     }
[722] 
[723]     ngx_http_clear_accept_ranges(r);
[724]     ngx_http_clear_last_modified(r);
[725]     ngx_http_clear_etag(r);
[726] 
[727]     rc = ngx_http_send_header(r);
[728] 
[729]     if (rc == NGX_ERROR || r->header_only) {
[730]         return rc;
[731]     }
[732] 
[733]     if (ngx_http_error_pages[err].len == 0) {
[734]         return ngx_http_send_special(r, NGX_HTTP_LAST);
[735]     }
[736] 
[737]     b = ngx_calloc_buf(r->pool);
[738]     if (b == NULL) {
[739]         return NGX_ERROR;
[740]     }
[741] 
[742]     b->memory = 1;
[743]     b->pos = ngx_http_error_pages[err].data;
[744]     b->last = ngx_http_error_pages[err].data + ngx_http_error_pages[err].len;
[745] 
[746]     out[0].buf = b;
[747]     out[0].next = &out[1];
[748] 
[749]     b = ngx_calloc_buf(r->pool);
[750]     if (b == NULL) {
[751]         return NGX_ERROR;
[752]     }
[753] 
[754]     b->memory = 1;
[755] 
[756]     b->pos = tail;
[757]     b->last = tail + len;
[758] 
[759]     out[1].buf = b;
[760]     out[1].next = NULL;
[761] 
[762]     if (msie_padding) {
[763]         b = ngx_calloc_buf(r->pool);
[764]         if (b == NULL) {
[765]             return NGX_ERROR;
[766]         }
[767] 
[768]         b->memory = 1;
[769]         b->pos = ngx_http_msie_padding;
[770]         b->last = ngx_http_msie_padding + sizeof(ngx_http_msie_padding) - 1;
[771] 
[772]         out[1].next = &out[2];
[773]         out[2].buf = b;
[774]         out[2].next = NULL;
[775]     }
[776] 
[777]     if (r == r->main) {
[778]         b->last_buf = 1;
[779]     }
[780] 
[781]     b->last_in_chain = 1;
[782] 
[783]     return ngx_http_output_filter(r, &out[0]);
[784] }
[785] 
[786] 
[787] static ngx_int_t
[788] ngx_http_send_refresh(ngx_http_request_t *r)
[789] {
[790]     u_char       *p, *location;
[791]     size_t        len, size;
[792]     uintptr_t     escape;
[793]     ngx_int_t     rc;
[794]     ngx_buf_t    *b;
[795]     ngx_chain_t   out;
[796] 
[797]     len = r->headers_out.location->value.len;
[798]     location = r->headers_out.location->value.data;
[799] 
[800]     escape = 2 * ngx_escape_uri(NULL, location, len, NGX_ESCAPE_REFRESH);
[801] 
[802]     size = sizeof(ngx_http_msie_refresh_head) - 1
[803]            + escape + len
[804]            + sizeof(ngx_http_msie_refresh_tail) - 1;
[805] 
[806]     r->err_status = NGX_HTTP_OK;
[807] 
[808]     r->headers_out.content_type_len = sizeof("text/html") - 1;
[809]     ngx_str_set(&r->headers_out.content_type, "text/html");
[810]     r->headers_out.content_type_lowcase = NULL;
[811] 
[812]     r->headers_out.location->hash = 0;
[813]     r->headers_out.location = NULL;
[814] 
[815]     r->headers_out.content_length_n = size;
[816] 
[817]     if (r->headers_out.content_length) {
[818]         r->headers_out.content_length->hash = 0;
[819]         r->headers_out.content_length = NULL;
[820]     }
[821] 
[822]     ngx_http_clear_accept_ranges(r);
[823]     ngx_http_clear_last_modified(r);
[824]     ngx_http_clear_etag(r);
[825] 
[826]     rc = ngx_http_send_header(r);
[827] 
[828]     if (rc == NGX_ERROR || r->header_only) {
[829]         return rc;
[830]     }
[831] 
[832]     b = ngx_create_temp_buf(r->pool, size);
[833]     if (b == NULL) {
[834]         return NGX_ERROR;
[835]     }
[836] 
[837]     p = ngx_cpymem(b->pos, ngx_http_msie_refresh_head,
[838]                    sizeof(ngx_http_msie_refresh_head) - 1);
[839] 
[840]     if (escape == 0) {
[841]         p = ngx_cpymem(p, location, len);
[842] 
[843]     } else {
[844]         p = (u_char *) ngx_escape_uri(p, location, len, NGX_ESCAPE_REFRESH);
[845]     }
[846] 
[847]     b->last = ngx_cpymem(p, ngx_http_msie_refresh_tail,
[848]                          sizeof(ngx_http_msie_refresh_tail) - 1);
[849] 
[850]     b->last_buf = (r == r->main) ? 1 : 0;
[851]     b->last_in_chain = 1;
[852] 
[853]     out.buf = b;
[854]     out.next = NULL;
[855] 
[856]     return ngx_http_output_filter(r, &out);
[857] }
