[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_H_INCLUDED_
[9] #define _NGX_HTTP_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct ngx_http_request_s     ngx_http_request_t;
[17] typedef struct ngx_http_upstream_s    ngx_http_upstream_t;
[18] typedef struct ngx_http_cache_s       ngx_http_cache_t;
[19] typedef struct ngx_http_file_cache_s  ngx_http_file_cache_t;
[20] typedef struct ngx_http_log_ctx_s     ngx_http_log_ctx_t;
[21] typedef struct ngx_http_chunked_s     ngx_http_chunked_t;
[22] typedef struct ngx_http_v2_stream_s   ngx_http_v2_stream_t;
[23] 
[24] typedef ngx_int_t (*ngx_http_header_handler_pt)(ngx_http_request_t *r,
[25]     ngx_table_elt_t *h, ngx_uint_t offset);
[26] typedef u_char *(*ngx_http_log_handler_pt)(ngx_http_request_t *r,
[27]     ngx_http_request_t *sr, u_char *buf, size_t len);
[28] 
[29] 
[30] #include <ngx_http_variables.h>
[31] #include <ngx_http_config.h>
[32] #include <ngx_http_request.h>
[33] #include <ngx_http_script.h>
[34] #include <ngx_http_upstream.h>
[35] #include <ngx_http_upstream_round_robin.h>
[36] #include <ngx_http_core_module.h>
[37] 
[38] #if (NGX_HTTP_V2)
[39] #include <ngx_http_v2.h>
[40] #endif
[41] #if (NGX_HTTP_CACHE)
[42] #include <ngx_http_cache.h>
[43] #endif
[44] #if (NGX_HTTP_SSI)
[45] #include <ngx_http_ssi_filter_module.h>
[46] #endif
[47] #if (NGX_HTTP_SSL)
[48] #include <ngx_http_ssl_module.h>
[49] #endif
[50] 
[51] 
[52] struct ngx_http_log_ctx_s {
[53]     ngx_connection_t    *connection;
[54]     ngx_http_request_t  *request;
[55]     ngx_http_request_t  *current_request;
[56] };
[57] 
[58] 
[59] struct ngx_http_chunked_s {
[60]     ngx_uint_t           state;
[61]     off_t                size;
[62]     off_t                length;
[63] };
[64] 
[65] 
[66] typedef struct {
[67]     ngx_uint_t           http_version;
[68]     ngx_uint_t           code;
[69]     ngx_uint_t           count;
[70]     u_char              *start;
[71]     u_char              *end;
[72] } ngx_http_status_t;
[73] 
[74] 
[75] #define ngx_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
[76] #define ngx_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;
[77] 
[78] 
[79] ngx_int_t ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
[80]     ngx_http_core_loc_conf_t *clcf);
[81] ngx_int_t ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
[82]     ngx_http_listen_opt_t *lsopt);
[83] 
[84] 
[85] void ngx_http_init_connection(ngx_connection_t *c);
[86] void ngx_http_close_connection(ngx_connection_t *c);
[87] 
[88] #if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
[89] int ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg);
[90] #endif
[91] #if (NGX_HTTP_SSL && defined SSL_R_CERT_CB_ERROR)
[92] int ngx_http_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg);
[93] #endif
[94] 
[95] 
[96] ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b);
[97] ngx_int_t ngx_http_parse_uri(ngx_http_request_t *r);
[98] ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r,
[99]     ngx_uint_t merge_slashes);
[100] ngx_int_t ngx_http_parse_status_line(ngx_http_request_t *r, ngx_buf_t *b,
[101]     ngx_http_status_t *status);
[102] ngx_int_t ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
[103]     ngx_str_t *args, ngx_uint_t *flags);
[104] ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b,
[105]     ngx_uint_t allow_underscores);
[106] ngx_table_elt_t *ngx_http_parse_multi_header_lines(ngx_http_request_t *r,
[107]     ngx_table_elt_t *headers, ngx_str_t *name, ngx_str_t *value);
[108] ngx_table_elt_t *ngx_http_parse_set_cookie_lines(ngx_http_request_t *r,
[109]     ngx_table_elt_t *headers, ngx_str_t *name, ngx_str_t *value);
[110] ngx_int_t ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len,
[111]     ngx_str_t *value);
[112] void ngx_http_split_args(ngx_http_request_t *r, ngx_str_t *uri,
[113]     ngx_str_t *args);
[114] ngx_int_t ngx_http_parse_chunked(ngx_http_request_t *r, ngx_buf_t *b,
[115]     ngx_http_chunked_t *ctx);
[116] 
[117] 
[118] ngx_http_request_t *ngx_http_create_request(ngx_connection_t *c);
[119] ngx_int_t ngx_http_process_request_uri(ngx_http_request_t *r);
[120] ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r);
[121] void ngx_http_process_request(ngx_http_request_t *r);
[122] void ngx_http_update_location_config(ngx_http_request_t *r);
[123] void ngx_http_handler(ngx_http_request_t *r);
[124] void ngx_http_run_posted_requests(ngx_connection_t *c);
[125] ngx_int_t ngx_http_post_request(ngx_http_request_t *r,
[126]     ngx_http_posted_request_t *pr);
[127] void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
[128] void ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc);
[129] 
[130] void ngx_http_empty_handler(ngx_event_t *wev);
[131] void ngx_http_request_empty_handler(ngx_http_request_t *r);
[132] 
[133] 
[134] #define NGX_HTTP_LAST   1
[135] #define NGX_HTTP_FLUSH  2
[136] 
[137] ngx_int_t ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags);
[138] 
[139] 
[140] ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
[141]     ngx_http_client_body_handler_pt post_handler);
[142] ngx_int_t ngx_http_read_unbuffered_request_body(ngx_http_request_t *r);
[143] 
[144] ngx_int_t ngx_http_send_header(ngx_http_request_t *r);
[145] ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r,
[146]     ngx_int_t error);
[147] ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r,
[148]     ngx_module_t *m, ngx_int_t error);
[149] void ngx_http_clean_header(ngx_http_request_t *r);
[150] 
[151] 
[152] ngx_int_t ngx_http_discard_request_body(ngx_http_request_t *r);
[153] void ngx_http_discarded_request_body_handler(ngx_http_request_t *r);
[154] void ngx_http_block_reading(ngx_http_request_t *r);
[155] void ngx_http_test_reading(ngx_http_request_t *r);
[156] 
[157] 
[158] char *ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[159] char *ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t **keys,
[160]     ngx_hash_t *types_hash, ngx_array_t **prev_keys,
[161]     ngx_hash_t *prev_types_hash, ngx_str_t *default_types);
[162] ngx_int_t ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
[163]     ngx_str_t *default_type);
[164] 
[165] #if (NGX_HTTP_DEGRADATION)
[166] ngx_uint_t  ngx_http_degraded(ngx_http_request_t *);
[167] #endif
[168] 
[169] 
[170] #if (NGX_HTTP_V2)
[171] ngx_int_t ngx_http_huff_decode(u_char *state, u_char *src, size_t len,
[172]     u_char **dst, ngx_uint_t last, ngx_log_t *log);
[173] size_t ngx_http_huff_encode(u_char *src, size_t len, u_char *dst,
[174]     ngx_uint_t lower);
[175] #endif
[176] 
[177] 
[178] extern ngx_module_t  ngx_http_module;
[179] 
[180] extern ngx_str_t  ngx_http_html_default_types[];
[181] 
[182] 
[183] extern ngx_http_output_header_filter_pt  ngx_http_top_header_filter;
[184] extern ngx_http_output_body_filter_pt    ngx_http_top_body_filter;
[185] extern ngx_http_request_body_filter_pt   ngx_http_top_request_body_filter;
[186] 
[187] 
[188] #endif /* _NGX_HTTP_H_INCLUDED_ */
