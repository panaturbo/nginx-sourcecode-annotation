[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
[9] #define _NGX_HTTP_REQUEST_H_INCLUDED_
[10] 
[11] 
[12] #define NGX_HTTP_MAX_URI_CHANGES           10
[13] #define NGX_HTTP_MAX_SUBREQUESTS           50
[14] 
[15] /* must be 2^n */
[16] #define NGX_HTTP_LC_HEADER_LEN             32
[17] 
[18] 
[19] #define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
[20] #define NGX_HTTP_LINGERING_BUFFER_SIZE     4096
[21] 
[22] 
[23] #define NGX_HTTP_VERSION_9                 9
[24] #define NGX_HTTP_VERSION_10                1000
[25] #define NGX_HTTP_VERSION_11                1001
[26] #define NGX_HTTP_VERSION_20                2000
[27] 
[28] #define NGX_HTTP_UNKNOWN                   0x00000001
[29] #define NGX_HTTP_GET                       0x00000002
[30] #define NGX_HTTP_HEAD                      0x00000004
[31] #define NGX_HTTP_POST                      0x00000008
[32] #define NGX_HTTP_PUT                       0x00000010
[33] #define NGX_HTTP_DELETE                    0x00000020
[34] #define NGX_HTTP_MKCOL                     0x00000040
[35] #define NGX_HTTP_COPY                      0x00000080
[36] #define NGX_HTTP_MOVE                      0x00000100
[37] #define NGX_HTTP_OPTIONS                   0x00000200
[38] #define NGX_HTTP_PROPFIND                  0x00000400
[39] #define NGX_HTTP_PROPPATCH                 0x00000800
[40] #define NGX_HTTP_LOCK                      0x00001000
[41] #define NGX_HTTP_UNLOCK                    0x00002000
[42] #define NGX_HTTP_PATCH                     0x00004000
[43] #define NGX_HTTP_TRACE                     0x00008000
[44] #define NGX_HTTP_CONNECT                   0x00010000
[45] 
[46] #define NGX_HTTP_CONNECTION_CLOSE          1
[47] #define NGX_HTTP_CONNECTION_KEEP_ALIVE     2
[48] 
[49] 
[50] #define NGX_NONE                           1
[51] 
[52] 
[53] #define NGX_HTTP_PARSE_HEADER_DONE         1
[54] 
[55] #define NGX_HTTP_CLIENT_ERROR              10
[56] #define NGX_HTTP_PARSE_INVALID_METHOD      10
[57] #define NGX_HTTP_PARSE_INVALID_REQUEST     11
[58] #define NGX_HTTP_PARSE_INVALID_VERSION     12
[59] #define NGX_HTTP_PARSE_INVALID_09_METHOD   13
[60] 
[61] #define NGX_HTTP_PARSE_INVALID_HEADER      14
[62] 
[63] 
[64] /* unused                                  1 */
[65] #define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
[66] #define NGX_HTTP_SUBREQUEST_WAITED         4
[67] #define NGX_HTTP_SUBREQUEST_CLONE          8
[68] #define NGX_HTTP_SUBREQUEST_BACKGROUND     16
[69] 
[70] #define NGX_HTTP_LOG_UNSAFE                1
[71] 
[72] 
[73] #define NGX_HTTP_CONTINUE                  100
[74] #define NGX_HTTP_SWITCHING_PROTOCOLS       101
[75] #define NGX_HTTP_PROCESSING                102
[76] 
[77] #define NGX_HTTP_OK                        200
[78] #define NGX_HTTP_CREATED                   201
[79] #define NGX_HTTP_ACCEPTED                  202
[80] #define NGX_HTTP_NO_CONTENT                204
[81] #define NGX_HTTP_PARTIAL_CONTENT           206
[82] 
[83] #define NGX_HTTP_SPECIAL_RESPONSE          300
[84] #define NGX_HTTP_MOVED_PERMANENTLY         301
[85] #define NGX_HTTP_MOVED_TEMPORARILY         302
[86] #define NGX_HTTP_SEE_OTHER                 303
[87] #define NGX_HTTP_NOT_MODIFIED              304
[88] #define NGX_HTTP_TEMPORARY_REDIRECT        307
[89] #define NGX_HTTP_PERMANENT_REDIRECT        308
[90] 
[91] #define NGX_HTTP_BAD_REQUEST               400
[92] #define NGX_HTTP_UNAUTHORIZED              401
[93] #define NGX_HTTP_FORBIDDEN                 403
[94] #define NGX_HTTP_NOT_FOUND                 404
[95] #define NGX_HTTP_NOT_ALLOWED               405
[96] #define NGX_HTTP_REQUEST_TIME_OUT          408
[97] #define NGX_HTTP_CONFLICT                  409
[98] #define NGX_HTTP_LENGTH_REQUIRED           411
[99] #define NGX_HTTP_PRECONDITION_FAILED       412
[100] #define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
[101] #define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
[102] #define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
[103] #define NGX_HTTP_RANGE_NOT_SATISFIABLE     416
[104] #define NGX_HTTP_MISDIRECTED_REQUEST       421
[105] #define NGX_HTTP_TOO_MANY_REQUESTS         429
[106] 
[107] 
[108] /* Our own HTTP codes */
[109] 
[110] /* The special code to close connection without any response */
[111] #define NGX_HTTP_CLOSE                     444
[112] 
[113] #define NGX_HTTP_NGINX_CODES               494
[114] 
[115] #define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494
[116] 
[117] #define NGX_HTTPS_CERT_ERROR               495
[118] #define NGX_HTTPS_NO_CERT                  496
[119] 
[120] /*
[121]  * We use the special code for the plain HTTP requests that are sent to
[122]  * HTTPS port to distinguish it from 4XX in an error page redirection
[123]  */
[124] #define NGX_HTTP_TO_HTTPS                  497
[125] 
[126] /* 498 is the canceled code for the requests with invalid host name */
[127] 
[128] /*
[129]  * HTTP does not define the code for the case when a client closed
[130]  * the connection while we are processing its request so we introduce
[131]  * own code to log such situation when a client has closed the connection
[132]  * before we even try to send the HTTP header to it
[133]  */
[134] #define NGX_HTTP_CLIENT_CLOSED_REQUEST     499
[135] 
[136] 
[137] #define NGX_HTTP_INTERNAL_SERVER_ERROR     500
[138] #define NGX_HTTP_NOT_IMPLEMENTED           501
[139] #define NGX_HTTP_BAD_GATEWAY               502
[140] #define NGX_HTTP_SERVICE_UNAVAILABLE       503
[141] #define NGX_HTTP_GATEWAY_TIME_OUT          504
[142] #define NGX_HTTP_VERSION_NOT_SUPPORTED     505
[143] #define NGX_HTTP_INSUFFICIENT_STORAGE      507
[144] 
[145] 
[146] #define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
[147] #define NGX_HTTP_WRITE_BUFFERED            0x10
[148] #define NGX_HTTP_GZIP_BUFFERED             0x20
[149] #define NGX_HTTP_SSI_BUFFERED              0x01
[150] #define NGX_HTTP_SUB_BUFFERED              0x02
[151] #define NGX_HTTP_COPY_BUFFERED             0x04
[152] 
[153] 
[154] typedef enum {
[155]     NGX_HTTP_INITING_REQUEST_STATE = 0,
[156]     NGX_HTTP_READING_REQUEST_STATE,
[157]     NGX_HTTP_PROCESS_REQUEST_STATE,
[158] 
[159]     NGX_HTTP_CONNECT_UPSTREAM_STATE,
[160]     NGX_HTTP_WRITING_UPSTREAM_STATE,
[161]     NGX_HTTP_READING_UPSTREAM_STATE,
[162] 
[163]     NGX_HTTP_WRITING_REQUEST_STATE,
[164]     NGX_HTTP_LINGERING_CLOSE_STATE,
[165]     NGX_HTTP_KEEPALIVE_STATE
[166] } ngx_http_state_e;
[167] 
[168] 
[169] typedef struct {
[170]     ngx_str_t                         name;
[171]     ngx_uint_t                        offset;
[172]     ngx_http_header_handler_pt        handler;
[173] } ngx_http_header_t;
[174] 
[175] 
[176] typedef struct {
[177]     ngx_str_t                         name;
[178]     ngx_uint_t                        offset;
[179] } ngx_http_header_out_t;
[180] 
[181] 
[182] typedef struct {
[183]     ngx_list_t                        headers;
[184] 
[185]     ngx_table_elt_t                  *host;
[186]     ngx_table_elt_t                  *connection;
[187]     ngx_table_elt_t                  *if_modified_since;
[188]     ngx_table_elt_t                  *if_unmodified_since;
[189]     ngx_table_elt_t                  *if_match;
[190]     ngx_table_elt_t                  *if_none_match;
[191]     ngx_table_elt_t                  *user_agent;
[192]     ngx_table_elt_t                  *referer;
[193]     ngx_table_elt_t                  *content_length;
[194]     ngx_table_elt_t                  *content_range;
[195]     ngx_table_elt_t                  *content_type;
[196] 
[197]     ngx_table_elt_t                  *range;
[198]     ngx_table_elt_t                  *if_range;
[199] 
[200]     ngx_table_elt_t                  *transfer_encoding;
[201]     ngx_table_elt_t                  *te;
[202]     ngx_table_elt_t                  *expect;
[203]     ngx_table_elt_t                  *upgrade;
[204] 
[205] #if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
[206]     ngx_table_elt_t                  *accept_encoding;
[207]     ngx_table_elt_t                  *via;
[208] #endif
[209] 
[210]     ngx_table_elt_t                  *authorization;
[211] 
[212]     ngx_table_elt_t                  *keep_alive;
[213] 
[214] #if (NGX_HTTP_X_FORWARDED_FOR)
[215]     ngx_table_elt_t                  *x_forwarded_for;
[216] #endif
[217] 
[218] #if (NGX_HTTP_REALIP)
[219]     ngx_table_elt_t                  *x_real_ip;
[220] #endif
[221] 
[222] #if (NGX_HTTP_HEADERS)
[223]     ngx_table_elt_t                  *accept;
[224]     ngx_table_elt_t                  *accept_language;
[225] #endif
[226] 
[227] #if (NGX_HTTP_DAV)
[228]     ngx_table_elt_t                  *depth;
[229]     ngx_table_elt_t                  *destination;
[230]     ngx_table_elt_t                  *overwrite;
[231]     ngx_table_elt_t                  *date;
[232] #endif
[233] 
[234]     ngx_table_elt_t                  *cookie;
[235] 
[236]     ngx_str_t                         user;
[237]     ngx_str_t                         passwd;
[238] 
[239]     ngx_str_t                         server;
[240]     off_t                             content_length_n;
[241]     time_t                            keep_alive_n;
[242] 
[243]     unsigned                          connection_type:2;
[244]     unsigned                          chunked:1;
[245]     unsigned                          multi:1;
[246]     unsigned                          multi_linked:1;
[247]     unsigned                          msie:1;
[248]     unsigned                          msie6:1;
[249]     unsigned                          opera:1;
[250]     unsigned                          gecko:1;
[251]     unsigned                          chrome:1;
[252]     unsigned                          safari:1;
[253]     unsigned                          konqueror:1;
[254] } ngx_http_headers_in_t;
[255] 
[256] 
[257] typedef struct {
[258]     ngx_list_t                        headers;
[259]     ngx_list_t                        trailers;
[260] 
[261]     ngx_uint_t                        status;
[262]     ngx_str_t                         status_line;
[263] 
[264]     ngx_table_elt_t                  *server;
[265]     ngx_table_elt_t                  *date;
[266]     ngx_table_elt_t                  *content_length;
[267]     ngx_table_elt_t                  *content_encoding;
[268]     ngx_table_elt_t                  *location;
[269]     ngx_table_elt_t                  *refresh;
[270]     ngx_table_elt_t                  *last_modified;
[271]     ngx_table_elt_t                  *content_range;
[272]     ngx_table_elt_t                  *accept_ranges;
[273]     ngx_table_elt_t                  *www_authenticate;
[274]     ngx_table_elt_t                  *expires;
[275]     ngx_table_elt_t                  *etag;
[276] 
[277]     ngx_table_elt_t                  *cache_control;
[278]     ngx_table_elt_t                  *link;
[279] 
[280]     ngx_str_t                        *override_charset;
[281] 
[282]     size_t                            content_type_len;
[283]     ngx_str_t                         content_type;
[284]     ngx_str_t                         charset;
[285]     u_char                           *content_type_lowcase;
[286]     ngx_uint_t                        content_type_hash;
[287] 
[288]     off_t                             content_length_n;
[289]     off_t                             content_offset;
[290]     time_t                            date_time;
[291]     time_t                            last_modified_time;
[292] } ngx_http_headers_out_t;
[293] 
[294] 
[295] typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);
[296] 
[297] typedef struct {
[298]     ngx_temp_file_t                  *temp_file;
[299]     ngx_chain_t                      *bufs;
[300]     ngx_buf_t                        *buf;
[301]     off_t                             rest;
[302]     off_t                             received;
[303]     ngx_chain_t                      *free;
[304]     ngx_chain_t                      *busy;
[305]     ngx_http_chunked_t               *chunked;
[306]     ngx_http_client_body_handler_pt   post_handler;
[307]     unsigned                          filter_need_buffering:1;
[308]     unsigned                          last_sent:1;
[309]     unsigned                          last_saved:1;
[310] } ngx_http_request_body_t;
[311] 
[312] 
[313] typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;
[314] 
[315] typedef struct {
[316]     ngx_http_addr_conf_t             *addr_conf;
[317]     ngx_http_conf_ctx_t              *conf_ctx;
[318] 
[319] #if (NGX_HTTP_SSL || NGX_COMPAT)
[320]     ngx_str_t                        *ssl_servername;
[321] #if (NGX_PCRE)
[322]     ngx_http_regex_t                 *ssl_servername_regex;
[323] #endif
[324] #endif
[325] 
[326]     ngx_chain_t                      *busy;
[327]     ngx_int_t                         nbusy;
[328] 
[329]     ngx_chain_t                      *free;
[330] 
[331]     unsigned                          ssl:1;
[332]     unsigned                          proxy_protocol:1;
[333] } ngx_http_connection_t;
[334] 
[335] 
[336] typedef void (*ngx_http_cleanup_pt)(void *data);
[337] 
[338] typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;
[339] 
[340] struct ngx_http_cleanup_s {
[341]     ngx_http_cleanup_pt               handler;
[342]     void                             *data;
[343]     ngx_http_cleanup_t               *next;
[344] };
[345] 
[346] 
[347] typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
[348]     void *data, ngx_int_t rc);
[349] 
[350] typedef struct {
[351]     ngx_http_post_subrequest_pt       handler;
[352]     void                             *data;
[353] } ngx_http_post_subrequest_t;
[354] 
[355] 
[356] typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;
[357] 
[358] struct ngx_http_postponed_request_s {
[359]     ngx_http_request_t               *request;
[360]     ngx_chain_t                      *out;
[361]     ngx_http_postponed_request_t     *next;
[362] };
[363] 
[364] 
[365] typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;
[366] 
[367] struct ngx_http_posted_request_s {
[368]     ngx_http_request_t               *request;
[369]     ngx_http_posted_request_t        *next;
[370] };
[371] 
[372] 
[373] typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
[374] typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);
[375] 
[376] 
[377] struct ngx_http_request_s {
[378]     uint32_t                          signature;         /* "HTTP" */
[379] 
[380]     ngx_connection_t                 *connection;
[381] 
[382]     void                            **ctx;
[383]     void                            **main_conf;
[384]     void                            **srv_conf;
[385]     void                            **loc_conf;
[386] 
[387]     ngx_http_event_handler_pt         read_event_handler;
[388]     ngx_http_event_handler_pt         write_event_handler;
[389] 
[390] #if (NGX_HTTP_CACHE)
[391]     ngx_http_cache_t                 *cache;
[392] #endif
[393] 
[394]     ngx_http_upstream_t              *upstream;
[395]     ngx_array_t                      *upstream_states;
[396]                                          /* of ngx_http_upstream_state_t */
[397] 
[398]     ngx_pool_t                       *pool;
[399]     ngx_buf_t                        *header_in;
[400] 
[401]     ngx_http_headers_in_t             headers_in;
[402]     ngx_http_headers_out_t            headers_out;
[403] 
[404]     ngx_http_request_body_t          *request_body;
[405] 
[406]     time_t                            lingering_time;
[407]     time_t                            start_sec;
[408]     ngx_msec_t                        start_msec;
[409] 
[410]     ngx_uint_t                        method;
[411]     ngx_uint_t                        http_version;
[412] 
[413]     ngx_str_t                         request_line;
[414]     ngx_str_t                         uri;
[415]     ngx_str_t                         args;
[416]     ngx_str_t                         exten;
[417]     ngx_str_t                         unparsed_uri;
[418] 
[419]     ngx_str_t                         method_name;
[420]     ngx_str_t                         http_protocol;
[421]     ngx_str_t                         schema;
[422] 
[423]     ngx_chain_t                      *out;
[424]     ngx_http_request_t               *main;
[425]     ngx_http_request_t               *parent;
[426]     ngx_http_postponed_request_t     *postponed;
[427]     ngx_http_post_subrequest_t       *post_subrequest;
[428]     ngx_http_posted_request_t        *posted_requests;
[429] 
[430]     ngx_int_t                         phase_handler;
[431]     ngx_http_handler_pt               content_handler;
[432]     ngx_uint_t                        access_code;
[433] 
[434]     ngx_http_variable_value_t        *variables;
[435] 
[436] #if (NGX_PCRE)
[437]     ngx_uint_t                        ncaptures;
[438]     int                              *captures;
[439]     u_char                           *captures_data;
[440] #endif
[441] 
[442]     size_t                            limit_rate;
[443]     size_t                            limit_rate_after;
[444] 
[445]     /* used to learn the Apache compatible response length without a header */
[446]     size_t                            header_size;
[447] 
[448]     off_t                             request_length;
[449] 
[450]     ngx_uint_t                        err_status;
[451] 
[452]     ngx_http_connection_t            *http_connection;
[453]     ngx_http_v2_stream_t             *stream;
[454] 
[455]     ngx_http_log_handler_pt           log_handler;
[456] 
[457]     ngx_http_cleanup_t               *cleanup;
[458] 
[459]     unsigned                          count:16;
[460]     unsigned                          subrequests:8;
[461]     unsigned                          blocked:8;
[462] 
[463]     unsigned                          aio:1;
[464] 
[465]     unsigned                          http_state:4;
[466] 
[467]     /* URI with "/." and on Win32 with "//" */
[468]     unsigned                          complex_uri:1;
[469] 
[470]     /* URI with "%" */
[471]     unsigned                          quoted_uri:1;
[472] 
[473]     /* URI with "+" */
[474]     unsigned                          plus_in_uri:1;
[475] 
[476]     /* URI with empty path */
[477]     unsigned                          empty_path_in_uri:1;
[478] 
[479]     unsigned                          invalid_header:1;
[480] 
[481]     unsigned                          add_uri_to_alias:1;
[482]     unsigned                          valid_location:1;
[483]     unsigned                          valid_unparsed_uri:1;
[484]     unsigned                          uri_changed:1;
[485]     unsigned                          uri_changes:4;
[486] 
[487]     unsigned                          request_body_in_single_buf:1;
[488]     unsigned                          request_body_in_file_only:1;
[489]     unsigned                          request_body_in_persistent_file:1;
[490]     unsigned                          request_body_in_clean_file:1;
[491]     unsigned                          request_body_file_group_access:1;
[492]     unsigned                          request_body_file_log_level:3;
[493]     unsigned                          request_body_no_buffering:1;
[494] 
[495]     unsigned                          subrequest_in_memory:1;
[496]     unsigned                          waited:1;
[497] 
[498] #if (NGX_HTTP_CACHE)
[499]     unsigned                          cached:1;
[500] #endif
[501] 
[502] #if (NGX_HTTP_GZIP)
[503]     unsigned                          gzip_tested:1;
[504]     unsigned                          gzip_ok:1;
[505]     unsigned                          gzip_vary:1;
[506] #endif
[507] 
[508] #if (NGX_PCRE)
[509]     unsigned                          realloc_captures:1;
[510] #endif
[511] 
[512]     unsigned                          proxy:1;
[513]     unsigned                          bypass_cache:1;
[514]     unsigned                          no_cache:1;
[515] 
[516]     /*
[517]      * instead of using the request context data in
[518]      * ngx_http_limit_conn_module and ngx_http_limit_req_module
[519]      * we use the bit fields in the request structure
[520]      */
[521]     unsigned                          limit_conn_status:2;
[522]     unsigned                          limit_req_status:3;
[523] 
[524]     unsigned                          limit_rate_set:1;
[525]     unsigned                          limit_rate_after_set:1;
[526] 
[527] #if 0
[528]     unsigned                          cacheable:1;
[529] #endif
[530] 
[531]     unsigned                          pipeline:1;
[532]     unsigned                          chunked:1;
[533]     unsigned                          header_only:1;
[534]     unsigned                          expect_trailers:1;
[535]     unsigned                          keepalive:1;
[536]     unsigned                          lingering_close:1;
[537]     unsigned                          discard_body:1;
[538]     unsigned                          reading_body:1;
[539]     unsigned                          internal:1;
[540]     unsigned                          error_page:1;
[541]     unsigned                          filter_finalize:1;
[542]     unsigned                          post_action:1;
[543]     unsigned                          request_complete:1;
[544]     unsigned                          request_output:1;
[545]     unsigned                          header_sent:1;
[546]     unsigned                          expect_tested:1;
[547]     unsigned                          root_tested:1;
[548]     unsigned                          done:1;
[549]     unsigned                          logged:1;
[550] 
[551]     unsigned                          buffered:4;
[552] 
[553]     unsigned                          main_filter_need_in_memory:1;
[554]     unsigned                          filter_need_in_memory:1;
[555]     unsigned                          filter_need_temporary:1;
[556]     unsigned                          preserve_body:1;
[557]     unsigned                          allow_ranges:1;
[558]     unsigned                          subrequest_ranges:1;
[559]     unsigned                          single_range:1;
[560]     unsigned                          disable_not_modified:1;
[561]     unsigned                          stat_reading:1;
[562]     unsigned                          stat_writing:1;
[563]     unsigned                          stat_processing:1;
[564] 
[565]     unsigned                          background:1;
[566]     unsigned                          health_check:1;
[567] 
[568]     /* used to parse HTTP headers */
[569] 
[570]     ngx_uint_t                        state;
[571] 
[572]     ngx_uint_t                        header_hash;
[573]     ngx_uint_t                        lowcase_index;
[574]     u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];
[575] 
[576]     u_char                           *header_name_start;
[577]     u_char                           *header_name_end;
[578]     u_char                           *header_start;
[579]     u_char                           *header_end;
[580] 
[581]     /*
[582]      * a memory that can be reused after parsing a request line
[583]      * via ngx_http_ephemeral_t
[584]      */
[585] 
[586]     u_char                           *uri_start;
[587]     u_char                           *uri_end;
[588]     u_char                           *uri_ext;
[589]     u_char                           *args_start;
[590]     u_char                           *request_start;
[591]     u_char                           *request_end;
[592]     u_char                           *method_end;
[593]     u_char                           *schema_start;
[594]     u_char                           *schema_end;
[595]     u_char                           *host_start;
[596]     u_char                           *host_end;
[597]     u_char                           *port_start;
[598]     u_char                           *port_end;
[599] 
[600]     unsigned                          http_minor:16;
[601]     unsigned                          http_major:16;
[602] };
[603] 
[604] 
[605] typedef struct {
[606]     ngx_http_posted_request_t         terminal_posted_request;
[607] } ngx_http_ephemeral_t;
[608] 
[609] 
[610] #define ngx_http_ephemeral(r)  (void *) (&r->uri_start)
[611] 
[612] 
[613] extern ngx_http_header_t       ngx_http_headers_in[];
[614] extern ngx_http_header_out_t   ngx_http_headers_out[];
[615] 
[616] 
[617] #define ngx_http_set_log_request(log, r)                                      \
[618]     ((ngx_http_log_ctx_t *) log->data)->current_request = r
[619] 
[620] 
[621] #endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
