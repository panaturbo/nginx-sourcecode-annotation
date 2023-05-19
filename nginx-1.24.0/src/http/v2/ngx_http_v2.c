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
[11] #include <ngx_http_v2_module.h>
[12] 
[13] 
[14] typedef struct {
[15]     ngx_str_t           name;
[16]     ngx_uint_t          offset;
[17]     ngx_uint_t          hash;
[18]     ngx_http_header_t  *hh;
[19] } ngx_http_v2_parse_header_t;
[20] 
[21] 
[22] /* errors */
[23] #define NGX_HTTP_V2_NO_ERROR                     0x0
[24] #define NGX_HTTP_V2_PROTOCOL_ERROR               0x1
[25] #define NGX_HTTP_V2_INTERNAL_ERROR               0x2
[26] #define NGX_HTTP_V2_FLOW_CTRL_ERROR              0x3
[27] #define NGX_HTTP_V2_SETTINGS_TIMEOUT             0x4
[28] #define NGX_HTTP_V2_STREAM_CLOSED                0x5
[29] #define NGX_HTTP_V2_SIZE_ERROR                   0x6
[30] #define NGX_HTTP_V2_REFUSED_STREAM               0x7
[31] #define NGX_HTTP_V2_CANCEL                       0x8
[32] #define NGX_HTTP_V2_COMP_ERROR                   0x9
[33] #define NGX_HTTP_V2_CONNECT_ERROR                0xa
[34] #define NGX_HTTP_V2_ENHANCE_YOUR_CALM            0xb
[35] #define NGX_HTTP_V2_INADEQUATE_SECURITY          0xc
[36] #define NGX_HTTP_V2_HTTP_1_1_REQUIRED            0xd
[37] 
[38] /* frame sizes */
[39] #define NGX_HTTP_V2_SETTINGS_ACK_SIZE            0
[40] #define NGX_HTTP_V2_RST_STREAM_SIZE              4
[41] #define NGX_HTTP_V2_PRIORITY_SIZE                5
[42] #define NGX_HTTP_V2_PING_SIZE                    8
[43] #define NGX_HTTP_V2_GOAWAY_SIZE                  8
[44] #define NGX_HTTP_V2_WINDOW_UPDATE_SIZE           4
[45] 
[46] #define NGX_HTTP_V2_SETTINGS_PARAM_SIZE          6
[47] 
[48] /* settings fields */
[49] #define NGX_HTTP_V2_HEADER_TABLE_SIZE_SETTING    0x1
[50] #define NGX_HTTP_V2_ENABLE_PUSH_SETTING          0x2
[51] #define NGX_HTTP_V2_MAX_STREAMS_SETTING          0x3
[52] #define NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING     0x4
[53] #define NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING       0x5
[54] 
[55] #define NGX_HTTP_V2_FRAME_BUFFER_SIZE            24
[56] 
[57] #define NGX_HTTP_V2_ROOT                         (void *) -1
[58] 
[59] 
[60] static void ngx_http_v2_read_handler(ngx_event_t *rev);
[61] static void ngx_http_v2_write_handler(ngx_event_t *wev);
[62] static void ngx_http_v2_handle_connection(ngx_http_v2_connection_t *h2c);
[63] static void ngx_http_v2_lingering_close(ngx_connection_t *c);
[64] static void ngx_http_v2_lingering_close_handler(ngx_event_t *rev);
[65] 
[66] static u_char *ngx_http_v2_state_proxy_protocol(ngx_http_v2_connection_t *h2c,
[67]     u_char *pos, u_char *end);
[68] static u_char *ngx_http_v2_state_preface(ngx_http_v2_connection_t *h2c,
[69]     u_char *pos, u_char *end);
[70] static u_char *ngx_http_v2_state_preface_end(ngx_http_v2_connection_t *h2c,
[71]     u_char *pos, u_char *end);
[72] static u_char *ngx_http_v2_state_head(ngx_http_v2_connection_t *h2c,
[73]     u_char *pos, u_char *end);
[74] static u_char *ngx_http_v2_state_data(ngx_http_v2_connection_t *h2c,
[75]     u_char *pos, u_char *end);
[76] static u_char *ngx_http_v2_state_read_data(ngx_http_v2_connection_t *h2c,
[77]     u_char *pos, u_char *end);
[78] static u_char *ngx_http_v2_state_headers(ngx_http_v2_connection_t *h2c,
[79]     u_char *pos, u_char *end);
[80] static u_char *ngx_http_v2_state_header_block(ngx_http_v2_connection_t *h2c,
[81]     u_char *pos, u_char *end);
[82] static u_char *ngx_http_v2_state_field_len(ngx_http_v2_connection_t *h2c,
[83]     u_char *pos, u_char *end);
[84] static u_char *ngx_http_v2_state_field_huff(ngx_http_v2_connection_t *h2c,
[85]     u_char *pos, u_char *end);
[86] static u_char *ngx_http_v2_state_field_raw(ngx_http_v2_connection_t *h2c,
[87]     u_char *pos, u_char *end);
[88] static u_char *ngx_http_v2_state_field_skip(ngx_http_v2_connection_t *h2c,
[89]     u_char *pos, u_char *end);
[90] static u_char *ngx_http_v2_state_process_header(ngx_http_v2_connection_t *h2c,
[91]     u_char *pos, u_char *end);
[92] static u_char *ngx_http_v2_state_header_complete(ngx_http_v2_connection_t *h2c,
[93]     u_char *pos, u_char *end);
[94] static u_char *ngx_http_v2_handle_continuation(ngx_http_v2_connection_t *h2c,
[95]     u_char *pos, u_char *end, ngx_http_v2_handler_pt handler);
[96] static u_char *ngx_http_v2_state_priority(ngx_http_v2_connection_t *h2c,
[97]     u_char *pos, u_char *end);
[98] static u_char *ngx_http_v2_state_rst_stream(ngx_http_v2_connection_t *h2c,
[99]     u_char *pos, u_char *end);
[100] static u_char *ngx_http_v2_state_settings(ngx_http_v2_connection_t *h2c,
[101]     u_char *pos, u_char *end);
[102] static u_char *ngx_http_v2_state_settings_params(ngx_http_v2_connection_t *h2c,
[103]     u_char *pos, u_char *end);
[104] static u_char *ngx_http_v2_state_push_promise(ngx_http_v2_connection_t *h2c,
[105]     u_char *pos, u_char *end);
[106] static u_char *ngx_http_v2_state_ping(ngx_http_v2_connection_t *h2c,
[107]     u_char *pos, u_char *end);
[108] static u_char *ngx_http_v2_state_goaway(ngx_http_v2_connection_t *h2c,
[109]     u_char *pos, u_char *end);
[110] static u_char *ngx_http_v2_state_window_update(ngx_http_v2_connection_t *h2c,
[111]     u_char *pos, u_char *end);
[112] static u_char *ngx_http_v2_state_continuation(ngx_http_v2_connection_t *h2c,
[113]     u_char *pos, u_char *end);
[114] static u_char *ngx_http_v2_state_complete(ngx_http_v2_connection_t *h2c,
[115]     u_char *pos, u_char *end);
[116] static u_char *ngx_http_v2_state_skip_padded(ngx_http_v2_connection_t *h2c,
[117]     u_char *pos, u_char *end);
[118] static u_char *ngx_http_v2_state_skip(ngx_http_v2_connection_t *h2c,
[119]     u_char *pos, u_char *end);
[120] static u_char *ngx_http_v2_state_save(ngx_http_v2_connection_t *h2c,
[121]     u_char *pos, u_char *end, ngx_http_v2_handler_pt handler);
[122] static u_char *ngx_http_v2_state_headers_save(ngx_http_v2_connection_t *h2c,
[123]     u_char *pos, u_char *end, ngx_http_v2_handler_pt handler);
[124] static u_char *ngx_http_v2_connection_error(ngx_http_v2_connection_t *h2c,
[125]     ngx_uint_t err);
[126] 
[127] static ngx_int_t ngx_http_v2_parse_int(ngx_http_v2_connection_t *h2c,
[128]     u_char **pos, u_char *end, ngx_uint_t prefix);
[129] 
[130] static ngx_http_v2_stream_t *ngx_http_v2_create_stream(
[131]     ngx_http_v2_connection_t *h2c, ngx_uint_t push);
[132] static ngx_http_v2_node_t *ngx_http_v2_get_node_by_id(
[133]     ngx_http_v2_connection_t *h2c, ngx_uint_t sid, ngx_uint_t alloc);
[134] static ngx_http_v2_node_t *ngx_http_v2_get_closed_node(
[135]     ngx_http_v2_connection_t *h2c);
[136] #define ngx_http_v2_index_size(h2scf)  (h2scf->streams_index_mask + 1)
[137] #define ngx_http_v2_index(h2scf, sid)  ((sid >> 1) & h2scf->streams_index_mask)
[138] 
[139] static ngx_int_t ngx_http_v2_send_settings(ngx_http_v2_connection_t *h2c);
[140] static ngx_int_t ngx_http_v2_settings_frame_handler(
[141]     ngx_http_v2_connection_t *h2c, ngx_http_v2_out_frame_t *frame);
[142] static ngx_int_t ngx_http_v2_send_window_update(ngx_http_v2_connection_t *h2c,
[143]     ngx_uint_t sid, size_t window);
[144] static ngx_int_t ngx_http_v2_send_rst_stream(ngx_http_v2_connection_t *h2c,
[145]     ngx_uint_t sid, ngx_uint_t status);
[146] static ngx_int_t ngx_http_v2_send_goaway(ngx_http_v2_connection_t *h2c,
[147]     ngx_uint_t status);
[148] 
[149] static ngx_http_v2_out_frame_t *ngx_http_v2_get_frame(
[150]     ngx_http_v2_connection_t *h2c, size_t length, ngx_uint_t type,
[151]     u_char flags, ngx_uint_t sid);
[152] static ngx_int_t ngx_http_v2_frame_handler(ngx_http_v2_connection_t *h2c,
[153]     ngx_http_v2_out_frame_t *frame);
[154] 
[155] static ngx_int_t ngx_http_v2_validate_header(ngx_http_request_t *r,
[156]     ngx_http_v2_header_t *header);
[157] static ngx_int_t ngx_http_v2_pseudo_header(ngx_http_request_t *r,
[158]     ngx_http_v2_header_t *header);
[159] static ngx_int_t ngx_http_v2_parse_path(ngx_http_request_t *r,
[160]     ngx_str_t *value);
[161] static ngx_int_t ngx_http_v2_parse_method(ngx_http_request_t *r,
[162]     ngx_str_t *value);
[163] static ngx_int_t ngx_http_v2_parse_scheme(ngx_http_request_t *r,
[164]     ngx_str_t *value);
[165] static ngx_int_t ngx_http_v2_parse_authority(ngx_http_request_t *r,
[166]     ngx_str_t *value);
[167] static ngx_int_t ngx_http_v2_parse_header(ngx_http_request_t *r,
[168]     ngx_http_v2_parse_header_t *header, ngx_str_t *value);
[169] static ngx_int_t ngx_http_v2_construct_request_line(ngx_http_request_t *r);
[170] static ngx_int_t ngx_http_v2_cookie(ngx_http_request_t *r,
[171]     ngx_http_v2_header_t *header);
[172] static ngx_int_t ngx_http_v2_construct_cookie_header(ngx_http_request_t *r);
[173] static void ngx_http_v2_run_request(ngx_http_request_t *r);
[174] static void ngx_http_v2_run_request_handler(ngx_event_t *ev);
[175] static ngx_int_t ngx_http_v2_process_request_body(ngx_http_request_t *r,
[176]     u_char *pos, size_t size, ngx_uint_t last, ngx_uint_t flush);
[177] static ngx_int_t ngx_http_v2_filter_request_body(ngx_http_request_t *r);
[178] static void ngx_http_v2_read_client_request_body_handler(ngx_http_request_t *r);
[179] 
[180] static ngx_int_t ngx_http_v2_terminate_stream(ngx_http_v2_connection_t *h2c,
[181]     ngx_http_v2_stream_t *stream, ngx_uint_t status);
[182] static void ngx_http_v2_close_stream_handler(ngx_event_t *ev);
[183] static void ngx_http_v2_retry_close_stream_handler(ngx_event_t *ev);
[184] static void ngx_http_v2_handle_connection_handler(ngx_event_t *rev);
[185] static void ngx_http_v2_idle_handler(ngx_event_t *rev);
[186] static void ngx_http_v2_finalize_connection(ngx_http_v2_connection_t *h2c,
[187]     ngx_uint_t status);
[188] 
[189] static ngx_int_t ngx_http_v2_adjust_windows(ngx_http_v2_connection_t *h2c,
[190]     ssize_t delta);
[191] static void ngx_http_v2_set_dependency(ngx_http_v2_connection_t *h2c,
[192]     ngx_http_v2_node_t *node, ngx_uint_t depend, ngx_uint_t exclusive);
[193] static void ngx_http_v2_node_children_update(ngx_http_v2_node_t *node);
[194] 
[195] static void ngx_http_v2_pool_cleanup(void *data);
[196] 
[197] 
[198] static ngx_http_v2_handler_pt ngx_http_v2_frame_states[] = {
[199]     ngx_http_v2_state_data,               /* NGX_HTTP_V2_DATA_FRAME */
[200]     ngx_http_v2_state_headers,            /* NGX_HTTP_V2_HEADERS_FRAME */
[201]     ngx_http_v2_state_priority,           /* NGX_HTTP_V2_PRIORITY_FRAME */
[202]     ngx_http_v2_state_rst_stream,         /* NGX_HTTP_V2_RST_STREAM_FRAME */
[203]     ngx_http_v2_state_settings,           /* NGX_HTTP_V2_SETTINGS_FRAME */
[204]     ngx_http_v2_state_push_promise,       /* NGX_HTTP_V2_PUSH_PROMISE_FRAME */
[205]     ngx_http_v2_state_ping,               /* NGX_HTTP_V2_PING_FRAME */
[206]     ngx_http_v2_state_goaway,             /* NGX_HTTP_V2_GOAWAY_FRAME */
[207]     ngx_http_v2_state_window_update,      /* NGX_HTTP_V2_WINDOW_UPDATE_FRAME */
[208]     ngx_http_v2_state_continuation        /* NGX_HTTP_V2_CONTINUATION_FRAME */
[209] };
[210] 
[211] #define NGX_HTTP_V2_FRAME_STATES                                              \
[212]     (sizeof(ngx_http_v2_frame_states) / sizeof(ngx_http_v2_handler_pt))
[213] 
[214] 
[215] static ngx_http_v2_parse_header_t  ngx_http_v2_parse_headers[] = {
[216]     { ngx_string("host"),
[217]       offsetof(ngx_http_headers_in_t, host), 0, NULL },
[218] 
[219]     { ngx_string("accept-encoding"),
[220]       offsetof(ngx_http_headers_in_t, accept_encoding), 0, NULL },
[221] 
[222]     { ngx_string("accept-language"),
[223]       offsetof(ngx_http_headers_in_t, accept_language), 0, NULL },
[224] 
[225]     { ngx_string("user-agent"),
[226]       offsetof(ngx_http_headers_in_t, user_agent), 0, NULL },
[227] 
[228]     { ngx_null_string, 0, 0, NULL }
[229] };
[230] 
[231] 
[232] void
[233] ngx_http_v2_init(ngx_event_t *rev)
[234] {
[235]     ngx_connection_t          *c;
[236]     ngx_pool_cleanup_t        *cln;
[237]     ngx_http_connection_t     *hc;
[238]     ngx_http_v2_srv_conf_t    *h2scf;
[239]     ngx_http_v2_main_conf_t   *h2mcf;
[240]     ngx_http_v2_connection_t  *h2c;
[241]     ngx_http_core_srv_conf_t  *cscf;
[242] 
[243]     c = rev->data;
[244]     hc = c->data;
[245] 
[246]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "init http2 connection");
[247] 
[248]     c->log->action = "processing HTTP/2 connection";
[249] 
[250]     h2mcf = ngx_http_get_module_main_conf(hc->conf_ctx, ngx_http_v2_module);
[251] 
[252]     if (h2mcf->recv_buffer == NULL) {
[253]         h2mcf->recv_buffer = ngx_palloc(ngx_cycle->pool,
[254]                                         h2mcf->recv_buffer_size);
[255]         if (h2mcf->recv_buffer == NULL) {
[256]             ngx_http_close_connection(c);
[257]             return;
[258]         }
[259]     }
[260] 
[261]     h2c = ngx_pcalloc(c->pool, sizeof(ngx_http_v2_connection_t));
[262]     if (h2c == NULL) {
[263]         ngx_http_close_connection(c);
[264]         return;
[265]     }
[266] 
[267]     h2c->connection = c;
[268]     h2c->http_connection = hc;
[269] 
[270]     h2c->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
[271]     h2c->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[272] 
[273]     h2c->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
[274] 
[275]     h2c->frame_size = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
[276] 
[277]     h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);
[278] 
[279]     h2c->concurrent_pushes = h2scf->concurrent_pushes;
[280]     h2c->priority_limit = ngx_max(h2scf->concurrent_streams, 100);
[281] 
[282]     h2c->pool = ngx_create_pool(h2scf->pool_size, h2c->connection->log);
[283]     if (h2c->pool == NULL) {
[284]         ngx_http_close_connection(c);
[285]         return;
[286]     }
[287] 
[288]     cln = ngx_pool_cleanup_add(c->pool, 0);
[289]     if (cln == NULL) {
[290]         ngx_http_close_connection(c);
[291]         return;
[292]     }
[293] 
[294]     cln->handler = ngx_http_v2_pool_cleanup;
[295]     cln->data = h2c;
[296] 
[297]     h2c->streams_index = ngx_pcalloc(c->pool, ngx_http_v2_index_size(h2scf)
[298]                                               * sizeof(ngx_http_v2_node_t *));
[299]     if (h2c->streams_index == NULL) {
[300]         ngx_http_close_connection(c);
[301]         return;
[302]     }
[303] 
[304]     if (ngx_http_v2_send_settings(h2c) == NGX_ERROR) {
[305]         ngx_http_close_connection(c);
[306]         return;
[307]     }
[308] 
[309]     if (ngx_http_v2_send_window_update(h2c, 0, NGX_HTTP_V2_MAX_WINDOW
[310]                                                - NGX_HTTP_V2_DEFAULT_WINDOW)
[311]         == NGX_ERROR)
[312]     {
[313]         ngx_http_close_connection(c);
[314]         return;
[315]     }
[316] 
[317]     h2c->state.handler = hc->proxy_protocol ? ngx_http_v2_state_proxy_protocol
[318]                                             : ngx_http_v2_state_preface;
[319] 
[320]     ngx_queue_init(&h2c->waiting);
[321]     ngx_queue_init(&h2c->dependencies);
[322]     ngx_queue_init(&h2c->closed);
[323] 
[324]     c->data = h2c;
[325] 
[326]     rev->handler = ngx_http_v2_read_handler;
[327]     c->write->handler = ngx_http_v2_write_handler;
[328] 
[329]     if (!rev->timer_set) {
[330]         cscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
[331]                                             ngx_http_core_module);
[332]         ngx_add_timer(rev, cscf->client_header_timeout);
[333]     }
[334] 
[335]     c->idle = 1;
[336]     ngx_reusable_connection(c, 0);
[337] 
[338]     ngx_http_v2_read_handler(rev);
[339] }
[340] 
[341] 
[342] static void
[343] ngx_http_v2_read_handler(ngx_event_t *rev)
[344] {
[345]     u_char                    *p, *end;
[346]     size_t                     available;
[347]     ssize_t                    n;
[348]     ngx_connection_t          *c;
[349]     ngx_http_v2_main_conf_t   *h2mcf;
[350]     ngx_http_v2_connection_t  *h2c;
[351] 
[352]     c = rev->data;
[353]     h2c = c->data;
[354] 
[355]     if (rev->timedout) {
[356]         ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
[357]         ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[358]         return;
[359]     }
[360] 
[361]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 read handler");
[362] 
[363]     h2c->blocked = 1;
[364] 
[365]     if (c->close) {
[366]         c->close = 0;
[367] 
[368]         if (c->error) {
[369]             ngx_http_v2_finalize_connection(h2c, 0);
[370]             return;
[371]         }
[372] 
[373]         if (!h2c->processing && !h2c->pushing) {
[374]             ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
[375]             return;
[376]         }
[377] 
[378]         if (!h2c->goaway) {
[379]             h2c->goaway = 1;
[380] 
[381]             if (ngx_http_v2_send_goaway(h2c, NGX_HTTP_V2_NO_ERROR)
[382]                 == NGX_ERROR)
[383]             {
[384]                 ngx_http_v2_finalize_connection(h2c, 0);
[385]                 return;
[386]             }
[387] 
[388]             if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
[389]                 ngx_http_v2_finalize_connection(h2c, 0);
[390]                 return;
[391]             }
[392]         }
[393] 
[394]         h2c->blocked = 0;
[395] 
[396]         return;
[397]     }
[398] 
[399]     h2mcf = ngx_http_get_module_main_conf(h2c->http_connection->conf_ctx,
[400]                                           ngx_http_v2_module);
[401] 
[402]     available = h2mcf->recv_buffer_size - 2 * NGX_HTTP_V2_STATE_BUFFER_SIZE;
[403] 
[404]     do {
[405]         p = h2mcf->recv_buffer;
[406] 
[407]         ngx_memcpy(p, h2c->state.buffer, NGX_HTTP_V2_STATE_BUFFER_SIZE);
[408]         end = p + h2c->state.buffer_used;
[409] 
[410]         n = c->recv(c, end, available);
[411] 
[412]         if (n == NGX_AGAIN) {
[413]             break;
[414]         }
[415] 
[416]         if (n == 0
[417]             && (h2c->state.incomplete || h2c->processing || h2c->pushing))
[418]         {
[419]             ngx_log_error(NGX_LOG_INFO, c->log, 0,
[420]                           "client prematurely closed connection");
[421]         }
[422] 
[423]         if (n == 0 || n == NGX_ERROR) {
[424]             c->error = 1;
[425]             ngx_http_v2_finalize_connection(h2c, 0);
[426]             return;
[427]         }
[428] 
[429]         end += n;
[430] 
[431]         h2c->state.buffer_used = 0;
[432]         h2c->state.incomplete = 0;
[433] 
[434]         do {
[435]             p = h2c->state.handler(h2c, p, end);
[436] 
[437]             if (p == NULL) {
[438]                 return;
[439]             }
[440] 
[441]         } while (p != end);
[442] 
[443]         h2c->total_bytes += n;
[444] 
[445]         if (h2c->total_bytes / 8 > h2c->payload_bytes + 1048576) {
[446]             ngx_log_error(NGX_LOG_INFO, c->log, 0, "http2 flood detected");
[447]             ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
[448]             return;
[449]         }
[450] 
[451]     } while (rev->ready);
[452] 
[453]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[454]         ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[455]         return;
[456]     }
[457] 
[458]     if (h2c->last_out && ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
[459]         ngx_http_v2_finalize_connection(h2c, 0);
[460]         return;
[461]     }
[462] 
[463]     h2c->blocked = 0;
[464] 
[465]     ngx_http_v2_handle_connection(h2c);
[466] }
[467] 
[468] 
[469] static void
[470] ngx_http_v2_write_handler(ngx_event_t *wev)
[471] {
[472]     ngx_int_t                  rc;
[473]     ngx_connection_t          *c;
[474]     ngx_http_v2_connection_t  *h2c;
[475] 
[476]     c = wev->data;
[477]     h2c = c->data;
[478] 
[479]     if (wev->timedout) {
[480]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[481]                        "http2 write event timed out");
[482]         c->error = 1;
[483]         c->timedout = 1;
[484]         ngx_http_v2_finalize_connection(h2c, 0);
[485]         return;
[486]     }
[487] 
[488]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 write handler");
[489] 
[490]     if (h2c->last_out == NULL && !c->buffered) {
[491] 
[492]         if (wev->timer_set) {
[493]             ngx_del_timer(wev);
[494]         }
[495] 
[496]         ngx_http_v2_handle_connection(h2c);
[497]         return;
[498]     }
[499] 
[500]     h2c->blocked = 1;
[501] 
[502]     rc = ngx_http_v2_send_output_queue(h2c);
[503] 
[504]     if (rc == NGX_ERROR) {
[505]         ngx_http_v2_finalize_connection(h2c, 0);
[506]         return;
[507]     }
[508] 
[509]     h2c->blocked = 0;
[510] 
[511]     if (rc == NGX_AGAIN) {
[512]         return;
[513]     }
[514] 
[515]     ngx_http_v2_handle_connection(h2c);
[516] }
[517] 
[518] 
[519] ngx_int_t
[520] ngx_http_v2_send_output_queue(ngx_http_v2_connection_t *h2c)
[521] {
[522]     int                        tcp_nodelay;
[523]     ngx_chain_t               *cl;
[524]     ngx_event_t               *wev;
[525]     ngx_connection_t          *c;
[526]     ngx_http_v2_out_frame_t   *out, *frame, *fn;
[527]     ngx_http_core_loc_conf_t  *clcf;
[528] 
[529]     c = h2c->connection;
[530]     wev = c->write;
[531] 
[532]     if (c->error) {
[533]         goto error;
[534]     }
[535] 
[536]     if (!wev->ready) {
[537]         return NGX_AGAIN;
[538]     }
[539] 
[540]     cl = NULL;
[541]     out = NULL;
[542] 
[543]     for (frame = h2c->last_out; frame; frame = fn) {
[544]         frame->last->next = cl;
[545]         cl = frame->first;
[546] 
[547]         fn = frame->next;
[548]         frame->next = out;
[549]         out = frame;
[550] 
[551]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
[552]                        "http2 frame out: %p sid:%ui bl:%d len:%uz",
[553]                        out, out->stream ? out->stream->node->id : 0,
[554]                        out->blocked, out->length);
[555]     }
[556] 
[557]     cl = c->send_chain(c, cl, 0);
[558] 
[559]     if (cl == NGX_CHAIN_ERROR) {
[560]         goto error;
[561]     }
[562] 
[563]     clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
[564]                                         ngx_http_core_module);
[565] 
[566]     if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
[567]         goto error;
[568]     }
[569] 
[570]     if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
[571]         if (ngx_tcp_push(c->fd) == -1) {
[572]             ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
[573]             goto error;
[574]         }
[575] 
[576]         c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
[577]         tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;
[578] 
[579]     } else {
[580]         tcp_nodelay = 1;
[581]     }
[582] 
[583]     if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
[584]         goto error;
[585]     }
[586] 
[587]     for ( /* void */ ; out; out = fn) {
[588]         fn = out->next;
[589] 
[590]         if (out->handler(h2c, out) != NGX_OK) {
[591]             out->blocked = 1;
[592]             break;
[593]         }
[594] 
[595]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
[596]                        "http2 frame sent: %p sid:%ui bl:%d len:%uz",
[597]                        out, out->stream ? out->stream->node->id : 0,
[598]                        out->blocked, out->length);
[599]     }
[600] 
[601]     frame = NULL;
[602] 
[603]     for ( /* void */ ; out; out = fn) {
[604]         fn = out->next;
[605]         out->next = frame;
[606]         frame = out;
[607]     }
[608] 
[609]     h2c->last_out = frame;
[610] 
[611]     if (!wev->ready) {
[612]         ngx_add_timer(wev, clcf->send_timeout);
[613]         return NGX_AGAIN;
[614]     }
[615] 
[616]     if (wev->timer_set) {
[617]         ngx_del_timer(wev);
[618]     }
[619] 
[620]     return NGX_OK;
[621] 
[622] error:
[623] 
[624]     c->error = 1;
[625] 
[626]     if (!h2c->blocked) {
[627]         ngx_post_event(wev, &ngx_posted_events);
[628]     }
[629] 
[630]     return NGX_ERROR;
[631] }
[632] 
[633] 
[634] static void
[635] ngx_http_v2_handle_connection(ngx_http_v2_connection_t *h2c)
[636] {
[637]     ngx_int_t                  rc;
[638]     ngx_connection_t          *c;
[639]     ngx_http_core_loc_conf_t  *clcf;
[640] 
[641]     if (h2c->last_out || h2c->processing || h2c->pushing) {
[642]         return;
[643]     }
[644] 
[645]     c = h2c->connection;
[646] 
[647]     if (c->error) {
[648]         ngx_http_close_connection(c);
[649]         return;
[650]     }
[651] 
[652]     if (c->buffered) {
[653]         h2c->blocked = 1;
[654] 
[655]         rc = ngx_http_v2_send_output_queue(h2c);
[656] 
[657]         h2c->blocked = 0;
[658] 
[659]         if (rc == NGX_ERROR) {
[660]             ngx_http_close_connection(c);
[661]             return;
[662]         }
[663] 
[664]         if (rc == NGX_AGAIN) {
[665]             return;
[666]         }
[667] 
[668]         /* rc == NGX_OK */
[669]     }
[670] 
[671]     if (h2c->goaway) {
[672]         ngx_http_v2_lingering_close(c);
[673]         return;
[674]     }
[675] 
[676]     clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
[677]                                         ngx_http_core_module);
[678] 
[679]     if (!c->read->timer_set) {
[680]         ngx_add_timer(c->read, clcf->keepalive_timeout);
[681]     }
[682] 
[683]     ngx_reusable_connection(c, 1);
[684] 
[685]     if (h2c->state.incomplete) {
[686]         return;
[687]     }
[688] 
[689]     ngx_destroy_pool(h2c->pool);
[690] 
[691]     h2c->pool = NULL;
[692]     h2c->free_frames = NULL;
[693]     h2c->frames = 0;
[694]     h2c->free_fake_connections = NULL;
[695] 
[696] #if (NGX_HTTP_SSL)
[697]     if (c->ssl) {
[698]         ngx_ssl_free_buffer(c);
[699]     }
[700] #endif
[701] 
[702]     c->destroyed = 1;
[703] 
[704]     c->write->handler = ngx_http_empty_handler;
[705]     c->read->handler = ngx_http_v2_idle_handler;
[706] 
[707]     if (c->write->timer_set) {
[708]         ngx_del_timer(c->write);
[709]     }
[710] }
[711] 
[712] 
[713] static void
[714] ngx_http_v2_lingering_close(ngx_connection_t *c)
[715] {
[716]     ngx_event_t               *rev, *wev;
[717]     ngx_http_v2_connection_t  *h2c;
[718]     ngx_http_core_loc_conf_t  *clcf;
[719] 
[720]     h2c = c->data;
[721] 
[722]     clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
[723]                                         ngx_http_core_module);
[724] 
[725]     if (clcf->lingering_close == NGX_HTTP_LINGERING_OFF) {
[726]         ngx_http_close_connection(c);
[727]         return;
[728]     }
[729] 
[730]     if (h2c->lingering_time == 0) {
[731]         h2c->lingering_time = ngx_time()
[732]                               + (time_t) (clcf->lingering_time / 1000);
[733]     }
[734] 
[735] #if (NGX_HTTP_SSL)
[736]     if (c->ssl) {
[737]         ngx_int_t  rc;
[738] 
[739]         rc = ngx_ssl_shutdown(c);
[740] 
[741]         if (rc == NGX_ERROR) {
[742]             ngx_http_close_connection(c);
[743]             return;
[744]         }
[745] 
[746]         if (rc == NGX_AGAIN) {
[747]             c->ssl->handler = ngx_http_v2_lingering_close;
[748]             return;
[749]         }
[750]     }
[751] #endif
[752] 
[753]     rev = c->read;
[754]     rev->handler = ngx_http_v2_lingering_close_handler;
[755] 
[756]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[757]         ngx_http_close_connection(c);
[758]         return;
[759]     }
[760] 
[761]     wev = c->write;
[762]     wev->handler = ngx_http_empty_handler;
[763] 
[764]     if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
[765]         if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
[766]             ngx_http_close_connection(c);
[767]             return;
[768]         }
[769]     }
[770] 
[771]     if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
[772]         ngx_connection_error(c, ngx_socket_errno,
[773]                              ngx_shutdown_socket_n " failed");
[774]         ngx_http_close_connection(c);
[775]         return;
[776]     }
[777] 
[778]     c->close = 0;
[779]     ngx_reusable_connection(c, 1);
[780] 
[781]     ngx_add_timer(rev, clcf->lingering_timeout);
[782] 
[783]     if (rev->ready) {
[784]         ngx_http_v2_lingering_close_handler(rev);
[785]     }
[786] }
[787] 
[788] 
[789] static void
[790] ngx_http_v2_lingering_close_handler(ngx_event_t *rev)
[791] {
[792]     ssize_t                    n;
[793]     ngx_msec_t                 timer;
[794]     ngx_connection_t          *c;
[795]     ngx_http_core_loc_conf_t  *clcf;
[796]     ngx_http_v2_connection_t  *h2c;
[797]     u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];
[798] 
[799]     c = rev->data;
[800]     h2c = c->data;
[801] 
[802]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
[803]                    "http2 lingering close handler");
[804] 
[805]     if (rev->timedout || c->close) {
[806]         ngx_http_close_connection(c);
[807]         return;
[808]     }
[809] 
[810]     timer = (ngx_msec_t) h2c->lingering_time - (ngx_msec_t) ngx_time();
[811]     if ((ngx_msec_int_t) timer <= 0) {
[812]         ngx_http_close_connection(c);
[813]         return;
[814]     }
[815] 
[816]     do {
[817]         n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);
[818] 
[819]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);
[820] 
[821]         if (n == NGX_AGAIN) {
[822]             break;
[823]         }
[824] 
[825]         if (n == NGX_ERROR || n == 0) {
[826]             ngx_http_close_connection(c);
[827]             return;
[828]         }
[829] 
[830]     } while (rev->ready);
[831] 
[832]     if (ngx_handle_read_event(rev, 0) != NGX_OK) {
[833]         ngx_http_close_connection(c);
[834]         return;
[835]     }
[836] 
[837]     clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
[838]                                         ngx_http_core_module);
[839]     timer *= 1000;
[840] 
[841]     if (timer > clcf->lingering_timeout) {
[842]         timer = clcf->lingering_timeout;
[843]     }
[844] 
[845]     ngx_add_timer(rev, timer);
[846] }
[847] 
[848] 
[849] static u_char *
[850] ngx_http_v2_state_proxy_protocol(ngx_http_v2_connection_t *h2c, u_char *pos,
[851]     u_char *end)
[852] {
[853]     ngx_log_t  *log;
[854] 
[855]     log = h2c->connection->log;
[856]     log->action = "reading PROXY protocol";
[857] 
[858]     pos = ngx_proxy_protocol_read(h2c->connection, pos, end);
[859] 
[860]     log->action = "processing HTTP/2 connection";
[861] 
[862]     if (pos == NULL) {
[863]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[864]     }
[865] 
[866]     return ngx_http_v2_state_preface(h2c, pos, end);
[867] }
[868] 
[869] 
[870] static u_char *
[871] ngx_http_v2_state_preface(ngx_http_v2_connection_t *h2c, u_char *pos,
[872]     u_char *end)
[873] {
[874]     static const u_char preface[] = "PRI * HTTP/2.0\r\n";
[875] 
[876]     if ((size_t) (end - pos) < sizeof(preface) - 1) {
[877]         return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_preface);
[878]     }
[879] 
[880]     if (ngx_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
[881]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[882]                       "invalid connection preface");
[883] 
[884]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[885]     }
[886] 
[887]     return ngx_http_v2_state_preface_end(h2c, pos + sizeof(preface) - 1, end);
[888] }
[889] 
[890] 
[891] static u_char *
[892] ngx_http_v2_state_preface_end(ngx_http_v2_connection_t *h2c, u_char *pos,
[893]     u_char *end)
[894] {
[895]     static const u_char preface[] = "\r\nSM\r\n\r\n";
[896] 
[897]     if ((size_t) (end - pos) < sizeof(preface) - 1) {
[898]         return ngx_http_v2_state_save(h2c, pos, end,
[899]                                       ngx_http_v2_state_preface_end);
[900]     }
[901] 
[902]     if (ngx_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
[903]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[904]                       "invalid connection preface");
[905] 
[906]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[907]     }
[908] 
[909]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[910]                    "http2 preface verified");
[911] 
[912]     return ngx_http_v2_state_head(h2c, pos + sizeof(preface) - 1, end);
[913] }
[914] 
[915] 
[916] static u_char *
[917] ngx_http_v2_state_head(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
[918] {
[919]     uint32_t    head;
[920]     ngx_uint_t  type;
[921] 
[922]     if (end - pos < NGX_HTTP_V2_FRAME_HEADER_SIZE) {
[923]         return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_head);
[924]     }
[925] 
[926]     head = ngx_http_v2_parse_uint32(pos);
[927] 
[928]     h2c->state.length = ngx_http_v2_parse_length(head);
[929]     h2c->state.flags = pos[4];
[930] 
[931]     h2c->state.sid = ngx_http_v2_parse_sid(&pos[5]);
[932] 
[933]     pos += NGX_HTTP_V2_FRAME_HEADER_SIZE;
[934] 
[935]     type = ngx_http_v2_parse_type(head);
[936] 
[937]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[938]                    "http2 frame type:%ui f:%Xd l:%uz sid:%ui",
[939]                    type, h2c->state.flags, h2c->state.length, h2c->state.sid);
[940] 
[941]     if (type >= NGX_HTTP_V2_FRAME_STATES) {
[942]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[943]                       "client sent frame with unknown type %ui", type);
[944]         return ngx_http_v2_state_skip(h2c, pos, end);
[945]     }
[946] 
[947]     return ngx_http_v2_frame_states[type](h2c, pos, end);
[948] }
[949] 
[950] 
[951] static u_char *
[952] ngx_http_v2_state_data(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
[953] {
[954]     size_t                 size;
[955]     ngx_http_v2_node_t    *node;
[956]     ngx_http_v2_stream_t  *stream;
[957] 
[958]     size = h2c->state.length;
[959] 
[960]     if (h2c->state.flags & NGX_HTTP_V2_PADDED_FLAG) {
[961] 
[962]         if (h2c->state.length == 0) {
[963]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[964]                           "client sent padded DATA frame "
[965]                           "with incorrect length: 0");
[966] 
[967]             return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[968]         }
[969] 
[970]         if (end - pos == 0) {
[971]             return ngx_http_v2_state_save(h2c, pos, end,
[972]                                           ngx_http_v2_state_data);
[973]         }
[974] 
[975]         h2c->state.padding = *pos++;
[976] 
[977]         if (h2c->state.padding >= size) {
[978]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[979]                           "client sent padded DATA frame "
[980]                           "with incorrect length: %uz, padding: %uz",
[981]                           size, h2c->state.padding);
[982] 
[983]             return ngx_http_v2_connection_error(h2c,
[984]                                                 NGX_HTTP_V2_PROTOCOL_ERROR);
[985]         }
[986] 
[987]         h2c->state.length -= 1 + h2c->state.padding;
[988]     }
[989] 
[990]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[991]                    "http2 DATA frame");
[992] 
[993]     if (h2c->state.sid == 0) {
[994]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[995]                       "client sent DATA frame with incorrect identifier");
[996] 
[997]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[998]     }
[999] 
[1000]     if (size > h2c->recv_window) {
[1001]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1002]                       "client violated connection flow control: "
[1003]                       "received DATA frame length %uz, available window %uz",
[1004]                       size, h2c->recv_window);
[1005] 
[1006]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
[1007]     }
[1008] 
[1009]     h2c->recv_window -= size;
[1010] 
[1011]     if (h2c->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4) {
[1012] 
[1013]         if (ngx_http_v2_send_window_update(h2c, 0, NGX_HTTP_V2_MAX_WINDOW
[1014]                                                    - h2c->recv_window)
[1015]             == NGX_ERROR)
[1016]         {
[1017]             return ngx_http_v2_connection_error(h2c,
[1018]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1019]         }
[1020] 
[1021]         h2c->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[1022]     }
[1023] 
[1024]     node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);
[1025] 
[1026]     if (node == NULL || node->stream == NULL) {
[1027]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1028]                        "unknown http2 stream");
[1029] 
[1030]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1031]     }
[1032] 
[1033]     stream = node->stream;
[1034] 
[1035]     if (size > stream->recv_window) {
[1036]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1037]                       "client violated flow control for stream %ui: "
[1038]                       "received DATA frame length %uz, available window %uz",
[1039]                       node->id, size, stream->recv_window);
[1040] 
[1041]         if (ngx_http_v2_terminate_stream(h2c, stream,
[1042]                                          NGX_HTTP_V2_FLOW_CTRL_ERROR)
[1043]             == NGX_ERROR)
[1044]         {
[1045]             return ngx_http_v2_connection_error(h2c,
[1046]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1047]         }
[1048] 
[1049]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1050]     }
[1051] 
[1052]     stream->recv_window -= size;
[1053] 
[1054]     if (stream->no_flow_control
[1055]         && stream->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
[1056]     {
[1057]         if (ngx_http_v2_send_window_update(h2c, node->id,
[1058]                                            NGX_HTTP_V2_MAX_WINDOW
[1059]                                            - stream->recv_window)
[1060]             == NGX_ERROR)
[1061]         {
[1062]             return ngx_http_v2_connection_error(h2c,
[1063]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1064]         }
[1065] 
[1066]         stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;
[1067]     }
[1068] 
[1069]     if (stream->in_closed) {
[1070]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1071]                       "client sent DATA frame for half-closed stream %ui",
[1072]                       node->id);
[1073] 
[1074]         if (ngx_http_v2_terminate_stream(h2c, stream,
[1075]                                          NGX_HTTP_V2_STREAM_CLOSED)
[1076]             == NGX_ERROR)
[1077]         {
[1078]             return ngx_http_v2_connection_error(h2c,
[1079]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1080]         }
[1081] 
[1082]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1083]     }
[1084] 
[1085]     h2c->state.stream = stream;
[1086] 
[1087]     return ngx_http_v2_state_read_data(h2c, pos, end);
[1088] }
[1089] 
[1090] 
[1091] static u_char *
[1092] ngx_http_v2_state_read_data(ngx_http_v2_connection_t *h2c, u_char *pos,
[1093]     u_char *end)
[1094] {
[1095]     size_t                   size;
[1096]     ngx_buf_t               *buf;
[1097]     ngx_int_t                rc;
[1098]     ngx_connection_t        *fc;
[1099]     ngx_http_request_t      *r;
[1100]     ngx_http_v2_stream_t    *stream;
[1101]     ngx_http_v2_srv_conf_t  *h2scf;
[1102] 
[1103]     stream = h2c->state.stream;
[1104] 
[1105]     if (stream == NULL) {
[1106]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1107]     }
[1108] 
[1109]     if (stream->skip_data) {
[1110]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1111]                        "skipping http2 DATA frame");
[1112] 
[1113]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1114]     }
[1115] 
[1116]     r = stream->request;
[1117]     fc = r->connection;
[1118] 
[1119]     if (r->reading_body && !r->request_body_no_buffering) {
[1120]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1121]                        "skipping http2 DATA frame");
[1122] 
[1123]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1124]     }
[1125] 
[1126]     if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
[1127]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1128]                        "skipping http2 DATA frame");
[1129] 
[1130]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1131]     }
[1132] 
[1133]     size = end - pos;
[1134] 
[1135]     if (size >= h2c->state.length) {
[1136]         size = h2c->state.length;
[1137]         stream->in_closed = h2c->state.flags & NGX_HTTP_V2_END_STREAM_FLAG;
[1138]     }
[1139] 
[1140]     h2c->payload_bytes += size;
[1141] 
[1142]     if (r->request_body) {
[1143]         rc = ngx_http_v2_process_request_body(r, pos, size,
[1144]                                               stream->in_closed, 0);
[1145] 
[1146]         if (rc != NGX_OK && rc != NGX_AGAIN) {
[1147]             stream->skip_data = 1;
[1148]             ngx_http_finalize_request(r, rc);
[1149]         }
[1150] 
[1151]         ngx_http_run_posted_requests(fc);
[1152] 
[1153]     } else if (size) {
[1154]         buf = stream->preread;
[1155] 
[1156]         if (buf == NULL) {
[1157]             h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);
[1158] 
[1159]             buf = ngx_create_temp_buf(r->pool, h2scf->preread_size);
[1160]             if (buf == NULL) {
[1161]                 return ngx_http_v2_connection_error(h2c,
[1162]                                                     NGX_HTTP_V2_INTERNAL_ERROR);
[1163]             }
[1164] 
[1165]             stream->preread = buf;
[1166]         }
[1167] 
[1168]         if (size > (size_t) (buf->end - buf->last)) {
[1169]             ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
[1170]                           "http2 preread buffer overflow");
[1171]             return ngx_http_v2_connection_error(h2c,
[1172]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1173]         }
[1174] 
[1175]         buf->last = ngx_cpymem(buf->last, pos, size);
[1176]     }
[1177] 
[1178]     pos += size;
[1179]     h2c->state.length -= size;
[1180] 
[1181]     if (h2c->state.length) {
[1182]         return ngx_http_v2_state_save(h2c, pos, end,
[1183]                                       ngx_http_v2_state_read_data);
[1184]     }
[1185] 
[1186]     if (h2c->state.padding) {
[1187]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1188]     }
[1189] 
[1190]     return ngx_http_v2_state_complete(h2c, pos, end);
[1191] }
[1192] 
[1193] 
[1194] static u_char *
[1195] ngx_http_v2_state_headers(ngx_http_v2_connection_t *h2c, u_char *pos,
[1196]     u_char *end)
[1197] {
[1198]     size_t                     size;
[1199]     ngx_uint_t                 padded, priority, depend, dependency, excl,
[1200]                                weight;
[1201]     ngx_uint_t                 status;
[1202]     ngx_http_v2_node_t        *node;
[1203]     ngx_http_v2_stream_t      *stream;
[1204]     ngx_http_v2_srv_conf_t    *h2scf;
[1205]     ngx_http_core_srv_conf_t  *cscf;
[1206]     ngx_http_core_loc_conf_t  *clcf;
[1207] 
[1208]     padded = h2c->state.flags & NGX_HTTP_V2_PADDED_FLAG;
[1209]     priority = h2c->state.flags & NGX_HTTP_V2_PRIORITY_FLAG;
[1210] 
[1211]     size = 0;
[1212] 
[1213]     if (padded) {
[1214]         size++;
[1215]     }
[1216] 
[1217]     if (priority) {
[1218]         size += sizeof(uint32_t) + 1;
[1219]     }
[1220] 
[1221]     if (h2c->state.length < size) {
[1222]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1223]                       "client sent HEADERS frame with incorrect length %uz",
[1224]                       h2c->state.length);
[1225] 
[1226]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1227]     }
[1228] 
[1229]     if (h2c->state.length == size) {
[1230]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1231]                       "client sent HEADERS frame with empty header block");
[1232] 
[1233]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1234]     }
[1235] 
[1236]     if (h2c->goaway) {
[1237]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1238]                        "skipping http2 HEADERS frame");
[1239]         return ngx_http_v2_state_skip(h2c, pos, end);
[1240]     }
[1241] 
[1242]     if ((size_t) (end - pos) < size) {
[1243]         return ngx_http_v2_state_save(h2c, pos, end,
[1244]                                       ngx_http_v2_state_headers);
[1245]     }
[1246] 
[1247]     h2c->state.length -= size;
[1248] 
[1249]     if (padded) {
[1250]         h2c->state.padding = *pos++;
[1251] 
[1252]         if (h2c->state.padding > h2c->state.length) {
[1253]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1254]                           "client sent padded HEADERS frame "
[1255]                           "with incorrect length: %uz, padding: %uz",
[1256]                           h2c->state.length, h2c->state.padding);
[1257] 
[1258]             return ngx_http_v2_connection_error(h2c,
[1259]                                                 NGX_HTTP_V2_PROTOCOL_ERROR);
[1260]         }
[1261] 
[1262]         h2c->state.length -= h2c->state.padding;
[1263]     }
[1264] 
[1265]     depend = 0;
[1266]     excl = 0;
[1267]     weight = NGX_HTTP_V2_DEFAULT_WEIGHT;
[1268] 
[1269]     if (priority) {
[1270]         dependency = ngx_http_v2_parse_uint32(pos);
[1271] 
[1272]         depend = dependency & 0x7fffffff;
[1273]         excl = dependency >> 31;
[1274]         weight = pos[4] + 1;
[1275] 
[1276]         pos += sizeof(uint32_t) + 1;
[1277]     }
[1278] 
[1279]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1280]                    "http2 HEADERS frame sid:%ui "
[1281]                    "depends on %ui excl:%ui weight:%ui",
[1282]                    h2c->state.sid, depend, excl, weight);
[1283] 
[1284]     if (h2c->state.sid % 2 == 0 || h2c->state.sid <= h2c->last_sid) {
[1285]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1286]                       "client sent HEADERS frame with incorrect identifier "
[1287]                       "%ui, the last was %ui", h2c->state.sid, h2c->last_sid);
[1288] 
[1289]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[1290]     }
[1291] 
[1292]     if (depend == h2c->state.sid) {
[1293]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1294]                       "client sent HEADERS frame for stream %ui "
[1295]                       "with incorrect dependency", h2c->state.sid);
[1296] 
[1297]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[1298]     }
[1299] 
[1300]     h2c->last_sid = h2c->state.sid;
[1301] 
[1302]     h2c->state.pool = ngx_create_pool(1024, h2c->connection->log);
[1303]     if (h2c->state.pool == NULL) {
[1304]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[1305]     }
[1306] 
[1307]     cscf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[1308]                                         ngx_http_core_module);
[1309] 
[1310]     h2c->state.header_limit = cscf->large_client_header_buffers.size
[1311]                               * cscf->large_client_header_buffers.num;
[1312] 
[1313]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[1314]                                          ngx_http_v2_module);
[1315] 
[1316]     if (h2c->processing >= h2scf->concurrent_streams) {
[1317]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1318]                       "concurrent streams exceeded %ui", h2c->processing);
[1319] 
[1320]         status = NGX_HTTP_V2_REFUSED_STREAM;
[1321]         goto rst_stream;
[1322]     }
[1323] 
[1324]     if (!h2c->settings_ack
[1325]         && !(h2c->state.flags & NGX_HTTP_V2_END_STREAM_FLAG)
[1326]         && h2scf->preread_size < NGX_HTTP_V2_DEFAULT_WINDOW)
[1327]     {
[1328]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1329]                       "client sent stream with data "
[1330]                       "before settings were acknowledged");
[1331] 
[1332]         status = NGX_HTTP_V2_REFUSED_STREAM;
[1333]         goto rst_stream;
[1334]     }
[1335] 
[1336]     node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);
[1337] 
[1338]     if (node == NULL) {
[1339]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[1340]     }
[1341] 
[1342]     if (node->parent) {
[1343]         ngx_queue_remove(&node->reuse);
[1344]         h2c->closed_nodes--;
[1345]     }
[1346] 
[1347]     stream = ngx_http_v2_create_stream(h2c, 0);
[1348]     if (stream == NULL) {
[1349]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[1350]     }
[1351] 
[1352]     h2c->state.stream = stream;
[1353] 
[1354]     stream->pool = h2c->state.pool;
[1355]     h2c->state.keep_pool = 1;
[1356] 
[1357]     stream->request->request_length = h2c->state.length;
[1358] 
[1359]     stream->in_closed = h2c->state.flags & NGX_HTTP_V2_END_STREAM_FLAG;
[1360]     stream->node = node;
[1361] 
[1362]     node->stream = stream;
[1363] 
[1364]     if (priority || node->parent == NULL) {
[1365]         node->weight = weight;
[1366]         ngx_http_v2_set_dependency(h2c, node, depend, excl);
[1367]     }
[1368] 
[1369]     clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
[1370]                                         ngx_http_core_module);
[1371] 
[1372]     if (clcf->keepalive_timeout == 0
[1373]         || h2c->connection->requests >= clcf->keepalive_requests
[1374]         || ngx_current_msec - h2c->connection->start_time
[1375]            > clcf->keepalive_time)
[1376]     {
[1377]         h2c->goaway = 1;
[1378] 
[1379]         if (ngx_http_v2_send_goaway(h2c, NGX_HTTP_V2_NO_ERROR) == NGX_ERROR) {
[1380]             return ngx_http_v2_connection_error(h2c,
[1381]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1382]         }
[1383]     }
[1384] 
[1385]     return ngx_http_v2_state_header_block(h2c, pos, end);
[1386] 
[1387] rst_stream:
[1388] 
[1389]     if (ngx_http_v2_send_rst_stream(h2c, h2c->state.sid, status) != NGX_OK) {
[1390]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[1391]     }
[1392] 
[1393]     return ngx_http_v2_state_header_block(h2c, pos, end);
[1394] }
[1395] 
[1396] 
[1397] static u_char *
[1398] ngx_http_v2_state_header_block(ngx_http_v2_connection_t *h2c, u_char *pos,
[1399]     u_char *end)
[1400] {
[1401]     u_char      ch;
[1402]     ngx_int_t   value;
[1403]     ngx_uint_t  indexed, size_update, prefix;
[1404] 
[1405]     if (end - pos < 1) {
[1406]         return ngx_http_v2_state_headers_save(h2c, pos, end,
[1407]                                               ngx_http_v2_state_header_block);
[1408]     }
[1409] 
[1410]     if (!(h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG)
[1411]         && h2c->state.length < NGX_HTTP_V2_INT_OCTETS)
[1412]     {
[1413]         return ngx_http_v2_handle_continuation(h2c, pos, end,
[1414]                                                ngx_http_v2_state_header_block);
[1415]     }
[1416] 
[1417]     size_update = 0;
[1418]     indexed = 0;
[1419] 
[1420]     ch = *pos;
[1421] 
[1422]     if (ch >= (1 << 7)) {
[1423]         /* indexed header field */
[1424]         indexed = 1;
[1425]         prefix = ngx_http_v2_prefix(7);
[1426] 
[1427]     } else if (ch >= (1 << 6)) {
[1428]         /* literal header field with incremental indexing */
[1429]         h2c->state.index = 1;
[1430]         prefix = ngx_http_v2_prefix(6);
[1431] 
[1432]     } else if (ch >= (1 << 5)) {
[1433]         /* dynamic table size update */
[1434]         size_update = 1;
[1435]         prefix = ngx_http_v2_prefix(5);
[1436] 
[1437]     } else if (ch >= (1 << 4)) {
[1438]         /* literal header field never indexed */
[1439]         prefix = ngx_http_v2_prefix(4);
[1440] 
[1441]     } else {
[1442]         /* literal header field without indexing */
[1443]         prefix = ngx_http_v2_prefix(4);
[1444]     }
[1445] 
[1446]     value = ngx_http_v2_parse_int(h2c, &pos, end, prefix);
[1447] 
[1448]     if (value < 0) {
[1449]         if (value == NGX_AGAIN) {
[1450]             return ngx_http_v2_state_headers_save(h2c, pos, end,
[1451]                                                ngx_http_v2_state_header_block);
[1452]         }
[1453] 
[1454]         if (value == NGX_DECLINED) {
[1455]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1456]                           "client sent header block with too long %s value",
[1457]                           size_update ? "size update" : "header index");
[1458] 
[1459]             return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
[1460]         }
[1461] 
[1462]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1463]                       "client sent header block with incorrect length");
[1464] 
[1465]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1466]     }
[1467] 
[1468]     if (indexed) {
[1469]         if (ngx_http_v2_get_indexed_header(h2c, value, 0) != NGX_OK) {
[1470]             return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
[1471]         }
[1472] 
[1473]         return ngx_http_v2_state_process_header(h2c, pos, end);
[1474]     }
[1475] 
[1476]     if (size_update) {
[1477]         if (ngx_http_v2_table_size(h2c, value) != NGX_OK) {
[1478]             return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
[1479]         }
[1480] 
[1481]         return ngx_http_v2_state_header_complete(h2c, pos, end);
[1482]     }
[1483] 
[1484]     if (value == 0) {
[1485]         h2c->state.parse_name = 1;
[1486] 
[1487]     } else if (ngx_http_v2_get_indexed_header(h2c, value, 1) != NGX_OK) {
[1488]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
[1489]     }
[1490] 
[1491]     h2c->state.parse_value = 1;
[1492] 
[1493]     return ngx_http_v2_state_field_len(h2c, pos, end);
[1494] }
[1495] 
[1496] 
[1497] static u_char *
[1498] ngx_http_v2_state_field_len(ngx_http_v2_connection_t *h2c, u_char *pos,
[1499]     u_char *end)
[1500] {
[1501]     size_t                     alloc;
[1502]     ngx_int_t                  len;
[1503]     ngx_uint_t                 huff;
[1504]     ngx_http_core_srv_conf_t  *cscf;
[1505] 
[1506]     if (!(h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG)
[1507]         && h2c->state.length < NGX_HTTP_V2_INT_OCTETS)
[1508]     {
[1509]         return ngx_http_v2_handle_continuation(h2c, pos, end,
[1510]                                                ngx_http_v2_state_field_len);
[1511]     }
[1512] 
[1513]     if (h2c->state.length < 1) {
[1514]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1515]                       "client sent header block with incorrect length");
[1516] 
[1517]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1518]     }
[1519] 
[1520]     if (end - pos < 1) {
[1521]         return ngx_http_v2_state_headers_save(h2c, pos, end,
[1522]                                               ngx_http_v2_state_field_len);
[1523]     }
[1524] 
[1525]     huff = *pos >> 7;
[1526]     len = ngx_http_v2_parse_int(h2c, &pos, end, ngx_http_v2_prefix(7));
[1527] 
[1528]     if (len < 0) {
[1529]         if (len == NGX_AGAIN) {
[1530]             return ngx_http_v2_state_headers_save(h2c, pos, end,
[1531]                                                   ngx_http_v2_state_field_len);
[1532]         }
[1533] 
[1534]         if (len == NGX_DECLINED) {
[1535]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1536]                         "client sent header field with too long length value");
[1537] 
[1538]             return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
[1539]         }
[1540] 
[1541]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1542]                       "client sent header block with incorrect length");
[1543] 
[1544]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1545]     }
[1546] 
[1547]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[1548]                    "http2 %s string, len:%i",
[1549]                    huff ? "encoded" : "raw", len);
[1550] 
[1551]     cscf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[1552]                                         ngx_http_core_module);
[1553] 
[1554]     if ((size_t) len > cscf->large_client_header_buffers.size) {
[1555]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1556]                       "client sent too large header field");
[1557] 
[1558]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
[1559]     }
[1560] 
[1561]     h2c->state.field_rest = len;
[1562] 
[1563]     if (h2c->state.stream == NULL && !h2c->state.index) {
[1564]         return ngx_http_v2_state_field_skip(h2c, pos, end);
[1565]     }
[1566] 
[1567]     alloc = (huff ? len * 8 / 5 : len) + 1;
[1568] 
[1569]     h2c->state.field_start = ngx_pnalloc(h2c->state.pool, alloc);
[1570]     if (h2c->state.field_start == NULL) {
[1571]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[1572]     }
[1573] 
[1574]     h2c->state.field_end = h2c->state.field_start;
[1575] 
[1576]     if (huff) {
[1577]         return ngx_http_v2_state_field_huff(h2c, pos, end);
[1578]     }
[1579] 
[1580]     return ngx_http_v2_state_field_raw(h2c, pos, end);
[1581] }
[1582] 
[1583] 
[1584] static u_char *
[1585] ngx_http_v2_state_field_huff(ngx_http_v2_connection_t *h2c, u_char *pos,
[1586]     u_char *end)
[1587] {
[1588]     size_t  size;
[1589] 
[1590]     size = end - pos;
[1591] 
[1592]     if (size > h2c->state.field_rest) {
[1593]         size = h2c->state.field_rest;
[1594]     }
[1595] 
[1596]     if (size > h2c->state.length) {
[1597]         size = h2c->state.length;
[1598]     }
[1599] 
[1600]     h2c->state.length -= size;
[1601]     h2c->state.field_rest -= size;
[1602] 
[1603]     if (ngx_http_huff_decode(&h2c->state.field_state, pos, size,
[1604]                              &h2c->state.field_end,
[1605]                              h2c->state.field_rest == 0,
[1606]                              h2c->connection->log)
[1607]         != NGX_OK)
[1608]     {
[1609]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1610]                       "client sent invalid encoded header field");
[1611] 
[1612]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
[1613]     }
[1614] 
[1615]     pos += size;
[1616] 
[1617]     if (h2c->state.field_rest == 0) {
[1618]         *h2c->state.field_end = '\0';
[1619]         return ngx_http_v2_state_process_header(h2c, pos, end);
[1620]     }
[1621] 
[1622]     if (h2c->state.length) {
[1623]         return ngx_http_v2_state_headers_save(h2c, pos, end,
[1624]                                               ngx_http_v2_state_field_huff);
[1625]     }
[1626] 
[1627]     if (h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
[1628]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1629]                       "client sent header field with incorrect length");
[1630] 
[1631]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1632]     }
[1633] 
[1634]     return ngx_http_v2_handle_continuation(h2c, pos, end,
[1635]                                            ngx_http_v2_state_field_huff);
[1636] }
[1637] 
[1638] 
[1639] static u_char *
[1640] ngx_http_v2_state_field_raw(ngx_http_v2_connection_t *h2c, u_char *pos,
[1641]     u_char *end)
[1642] {
[1643]     size_t  size;
[1644] 
[1645]     size = end - pos;
[1646] 
[1647]     if (size > h2c->state.field_rest) {
[1648]         size = h2c->state.field_rest;
[1649]     }
[1650] 
[1651]     if (size > h2c->state.length) {
[1652]         size = h2c->state.length;
[1653]     }
[1654] 
[1655]     h2c->state.length -= size;
[1656]     h2c->state.field_rest -= size;
[1657] 
[1658]     h2c->state.field_end = ngx_cpymem(h2c->state.field_end, pos, size);
[1659] 
[1660]     pos += size;
[1661] 
[1662]     if (h2c->state.field_rest == 0) {
[1663]         *h2c->state.field_end = '\0';
[1664]         return ngx_http_v2_state_process_header(h2c, pos, end);
[1665]     }
[1666] 
[1667]     if (h2c->state.length) {
[1668]         return ngx_http_v2_state_headers_save(h2c, pos, end,
[1669]                                               ngx_http_v2_state_field_raw);
[1670]     }
[1671] 
[1672]     if (h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
[1673]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1674]                       "client sent header field with incorrect length");
[1675] 
[1676]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1677]     }
[1678] 
[1679]     return ngx_http_v2_handle_continuation(h2c, pos, end,
[1680]                                            ngx_http_v2_state_field_raw);
[1681] }
[1682] 
[1683] 
[1684] static u_char *
[1685] ngx_http_v2_state_field_skip(ngx_http_v2_connection_t *h2c, u_char *pos,
[1686]     u_char *end)
[1687] {
[1688]     size_t  size;
[1689] 
[1690]     size = end - pos;
[1691] 
[1692]     if (size > h2c->state.field_rest) {
[1693]         size = h2c->state.field_rest;
[1694]     }
[1695] 
[1696]     if (size > h2c->state.length) {
[1697]         size = h2c->state.length;
[1698]     }
[1699] 
[1700]     h2c->state.length -= size;
[1701]     h2c->state.field_rest -= size;
[1702] 
[1703]     pos += size;
[1704] 
[1705]     if (h2c->state.field_rest == 0) {
[1706]         return ngx_http_v2_state_process_header(h2c, pos, end);
[1707]     }
[1708] 
[1709]     if (h2c->state.length) {
[1710]         return ngx_http_v2_state_save(h2c, pos, end,
[1711]                                       ngx_http_v2_state_field_skip);
[1712]     }
[1713] 
[1714]     if (h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG) {
[1715]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1716]                       "client sent header field with incorrect length");
[1717] 
[1718]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[1719]     }
[1720] 
[1721]     return ngx_http_v2_handle_continuation(h2c, pos, end,
[1722]                                            ngx_http_v2_state_field_skip);
[1723] }
[1724] 
[1725] 
[1726] static u_char *
[1727] ngx_http_v2_state_process_header(ngx_http_v2_connection_t *h2c, u_char *pos,
[1728]     u_char *end)
[1729] {
[1730]     size_t                      len;
[1731]     ngx_int_t                   rc;
[1732]     ngx_table_elt_t            *h;
[1733]     ngx_connection_t           *fc;
[1734]     ngx_http_header_t          *hh;
[1735]     ngx_http_request_t         *r;
[1736]     ngx_http_v2_header_t       *header;
[1737]     ngx_http_core_srv_conf_t   *cscf;
[1738]     ngx_http_core_main_conf_t  *cmcf;
[1739] 
[1740]     static ngx_str_t cookie = ngx_string("cookie");
[1741] 
[1742]     header = &h2c->state.header;
[1743] 
[1744]     if (h2c->state.parse_name) {
[1745]         h2c->state.parse_name = 0;
[1746] 
[1747]         header->name.len = h2c->state.field_end - h2c->state.field_start;
[1748]         header->name.data = h2c->state.field_start;
[1749] 
[1750]         if (header->name.len == 0) {
[1751]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1752]                           "client sent zero header name length");
[1753] 
[1754]             return ngx_http_v2_connection_error(h2c,
[1755]                                                 NGX_HTTP_V2_PROTOCOL_ERROR);
[1756]         }
[1757] 
[1758]         return ngx_http_v2_state_field_len(h2c, pos, end);
[1759]     }
[1760] 
[1761]     if (h2c->state.parse_value) {
[1762]         h2c->state.parse_value = 0;
[1763] 
[1764]         header->value.len = h2c->state.field_end - h2c->state.field_start;
[1765]         header->value.data = h2c->state.field_start;
[1766]     }
[1767] 
[1768]     len = header->name.len + header->value.len;
[1769] 
[1770]     if (len > h2c->state.header_limit) {
[1771]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1772]                       "client sent too large header");
[1773] 
[1774]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
[1775]     }
[1776] 
[1777]     h2c->state.header_limit -= len;
[1778] 
[1779]     if (h2c->state.index) {
[1780]         if (ngx_http_v2_add_header(h2c, header) != NGX_OK) {
[1781]             return ngx_http_v2_connection_error(h2c,
[1782]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1783]         }
[1784] 
[1785]         h2c->state.index = 0;
[1786]     }
[1787] 
[1788]     if (h2c->state.stream == NULL) {
[1789]         return ngx_http_v2_state_header_complete(h2c, pos, end);
[1790]     }
[1791] 
[1792]     r = h2c->state.stream->request;
[1793]     fc = r->connection;
[1794] 
[1795]     /* TODO Optimization: validate headers while parsing. */
[1796]     if (ngx_http_v2_validate_header(r, header) != NGX_OK) {
[1797]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1798]         goto error;
[1799]     }
[1800] 
[1801]     if (header->name.data[0] == ':') {
[1802]         rc = ngx_http_v2_pseudo_header(r, header);
[1803] 
[1804]         if (rc == NGX_OK) {
[1805]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1806]                            "http2 header: \":%V: %V\"",
[1807]                            &header->name, &header->value);
[1808] 
[1809]             return ngx_http_v2_state_header_complete(h2c, pos, end);
[1810]         }
[1811] 
[1812]         if (rc == NGX_ABORT) {
[1813]             goto error;
[1814]         }
[1815] 
[1816]         if (rc == NGX_DECLINED) {
[1817]             ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[1818]             goto error;
[1819]         }
[1820] 
[1821]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[1822]     }
[1823] 
[1824]     if (r->invalid_header) {
[1825]         cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[1826] 
[1827]         if (cscf->ignore_invalid_headers) {
[1828]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[1829]                           "client sent invalid header: \"%V\"", &header->name);
[1830] 
[1831]             return ngx_http_v2_state_header_complete(h2c, pos, end);
[1832]         }
[1833]     }
[1834] 
[1835]     if (header->name.len == cookie.len
[1836]         && ngx_memcmp(header->name.data, cookie.data, cookie.len) == 0)
[1837]     {
[1838]         if (ngx_http_v2_cookie(r, header) != NGX_OK) {
[1839]             return ngx_http_v2_connection_error(h2c,
[1840]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1841]         }
[1842] 
[1843]     } else {
[1844]         h = ngx_list_push(&r->headers_in.headers);
[1845]         if (h == NULL) {
[1846]             return ngx_http_v2_connection_error(h2c,
[1847]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[1848]         }
[1849] 
[1850]         h->key.len = header->name.len;
[1851]         h->key.data = header->name.data;
[1852] 
[1853]         /*
[1854]          * TODO Optimization: precalculate hash
[1855]          * and handler for indexed headers.
[1856]          */
[1857]         h->hash = ngx_hash_key(h->key.data, h->key.len);
[1858] 
[1859]         h->value.len = header->value.len;
[1860]         h->value.data = header->value.data;
[1861] 
[1862]         h->lowcase_key = h->key.data;
[1863] 
[1864]         cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[1865] 
[1866]         hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
[1867]                            h->lowcase_key, h->key.len);
[1868] 
[1869]         if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
[1870]             goto error;
[1871]         }
[1872]     }
[1873] 
[1874]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1875]                    "http2 header: \"%V: %V\"",
[1876]                    &header->name, &header->value);
[1877] 
[1878]     return ngx_http_v2_state_header_complete(h2c, pos, end);
[1879] 
[1880] error:
[1881] 
[1882]     h2c->state.stream = NULL;
[1883] 
[1884]     ngx_http_run_posted_requests(fc);
[1885] 
[1886]     return ngx_http_v2_state_header_complete(h2c, pos, end);
[1887] }
[1888] 
[1889] 
[1890] static u_char *
[1891] ngx_http_v2_state_header_complete(ngx_http_v2_connection_t *h2c, u_char *pos,
[1892]     u_char *end)
[1893] {
[1894]     ngx_http_v2_stream_t  *stream;
[1895] 
[1896]     if (h2c->state.length) {
[1897]         if (end - pos > 0) {
[1898]             h2c->state.handler = ngx_http_v2_state_header_block;
[1899]             return pos;
[1900]         }
[1901] 
[1902]         return ngx_http_v2_state_headers_save(h2c, pos, end,
[1903]                                               ngx_http_v2_state_header_block);
[1904]     }
[1905] 
[1906]     if (!(h2c->state.flags & NGX_HTTP_V2_END_HEADERS_FLAG)) {
[1907]         return ngx_http_v2_handle_continuation(h2c, pos, end,
[1908]                                              ngx_http_v2_state_header_complete);
[1909]     }
[1910] 
[1911]     stream = h2c->state.stream;
[1912] 
[1913]     if (stream) {
[1914]         ngx_http_v2_run_request(stream->request);
[1915]     }
[1916] 
[1917]     if (!h2c->state.keep_pool) {
[1918]         ngx_destroy_pool(h2c->state.pool);
[1919]     }
[1920] 
[1921]     h2c->state.pool = NULL;
[1922]     h2c->state.keep_pool = 0;
[1923] 
[1924]     if (h2c->state.padding) {
[1925]         return ngx_http_v2_state_skip_padded(h2c, pos, end);
[1926]     }
[1927] 
[1928]     return ngx_http_v2_state_complete(h2c, pos, end);
[1929] }
[1930] 
[1931] 
[1932] static u_char *
[1933] ngx_http_v2_handle_continuation(ngx_http_v2_connection_t *h2c, u_char *pos,
[1934]     u_char *end, ngx_http_v2_handler_pt handler)
[1935] {
[1936]     u_char    *p;
[1937]     size_t     len, skip;
[1938]     uint32_t   head;
[1939] 
[1940]     len = h2c->state.length;
[1941] 
[1942]     if (h2c->state.padding && (size_t) (end - pos) > len) {
[1943]         skip = ngx_min(h2c->state.padding, (end - pos) - len);
[1944] 
[1945]         h2c->state.padding -= skip;
[1946] 
[1947]         p = pos;
[1948]         pos += skip;
[1949]         ngx_memmove(pos, p, len);
[1950]     }
[1951] 
[1952]     if ((size_t) (end - pos) < len + NGX_HTTP_V2_FRAME_HEADER_SIZE) {
[1953]         return ngx_http_v2_state_headers_save(h2c, pos, end, handler);
[1954]     }
[1955] 
[1956]     p = pos + len;
[1957] 
[1958]     head = ngx_http_v2_parse_uint32(p);
[1959] 
[1960]     if (ngx_http_v2_parse_type(head) != NGX_HTTP_V2_CONTINUATION_FRAME) {
[1961]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1962]              "client sent inappropriate frame while CONTINUATION was expected");
[1963] 
[1964]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[1965]     }
[1966] 
[1967]     h2c->state.flags |= p[4];
[1968] 
[1969]     if (h2c->state.sid != ngx_http_v2_parse_sid(&p[5])) {
[1970]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[1971]                     "client sent CONTINUATION frame with incorrect identifier");
[1972] 
[1973]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[1974]     }
[1975] 
[1976]     p = pos;
[1977]     pos += NGX_HTTP_V2_FRAME_HEADER_SIZE;
[1978] 
[1979]     ngx_memcpy(pos, p, len);
[1980] 
[1981]     len = ngx_http_v2_parse_length(head);
[1982] 
[1983]     h2c->state.length += len;
[1984] 
[1985]     if (h2c->state.stream) {
[1986]         h2c->state.stream->request->request_length += len;
[1987]     }
[1988] 
[1989]     h2c->state.handler = handler;
[1990]     return pos;
[1991] }
[1992] 
[1993] 
[1994] static u_char *
[1995] ngx_http_v2_state_priority(ngx_http_v2_connection_t *h2c, u_char *pos,
[1996]     u_char *end)
[1997] {
[1998]     ngx_uint_t           depend, dependency, excl, weight;
[1999]     ngx_http_v2_node_t  *node;
[2000] 
[2001]     if (h2c->state.length != NGX_HTTP_V2_PRIORITY_SIZE) {
[2002]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2003]                       "client sent PRIORITY frame with incorrect length %uz",
[2004]                       h2c->state.length);
[2005] 
[2006]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2007]     }
[2008] 
[2009]     if (--h2c->priority_limit == 0) {
[2010]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2011]                       "client sent too many PRIORITY frames");
[2012] 
[2013]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
[2014]     }
[2015] 
[2016]     if (end - pos < NGX_HTTP_V2_PRIORITY_SIZE) {
[2017]         return ngx_http_v2_state_save(h2c, pos, end,
[2018]                                       ngx_http_v2_state_priority);
[2019]     }
[2020] 
[2021]     dependency = ngx_http_v2_parse_uint32(pos);
[2022] 
[2023]     depend = dependency & 0x7fffffff;
[2024]     excl = dependency >> 31;
[2025]     weight = pos[4] + 1;
[2026] 
[2027]     pos += NGX_HTTP_V2_PRIORITY_SIZE;
[2028] 
[2029]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2030]                    "http2 PRIORITY frame sid:%ui "
[2031]                    "depends on %ui excl:%ui weight:%ui",
[2032]                    h2c->state.sid, depend, excl, weight);
[2033] 
[2034]     if (h2c->state.sid == 0) {
[2035]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2036]                       "client sent PRIORITY frame with incorrect identifier");
[2037] 
[2038]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2039]     }
[2040] 
[2041]     if (depend == h2c->state.sid) {
[2042]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2043]                       "client sent PRIORITY frame for stream %ui "
[2044]                       "with incorrect dependency", h2c->state.sid);
[2045] 
[2046]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2047]     }
[2048] 
[2049]     node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);
[2050] 
[2051]     if (node == NULL) {
[2052]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[2053]     }
[2054] 
[2055]     node->weight = weight;
[2056] 
[2057]     if (node->stream == NULL) {
[2058]         if (node->parent == NULL) {
[2059]             h2c->closed_nodes++;
[2060] 
[2061]         } else {
[2062]             ngx_queue_remove(&node->reuse);
[2063]         }
[2064] 
[2065]         ngx_queue_insert_tail(&h2c->closed, &node->reuse);
[2066]     }
[2067] 
[2068]     ngx_http_v2_set_dependency(h2c, node, depend, excl);
[2069] 
[2070]     return ngx_http_v2_state_complete(h2c, pos, end);
[2071] }
[2072] 
[2073] 
[2074] static u_char *
[2075] ngx_http_v2_state_rst_stream(ngx_http_v2_connection_t *h2c, u_char *pos,
[2076]     u_char *end)
[2077] {
[2078]     ngx_uint_t             status;
[2079]     ngx_event_t           *ev;
[2080]     ngx_connection_t      *fc;
[2081]     ngx_http_v2_node_t    *node;
[2082]     ngx_http_v2_stream_t  *stream;
[2083] 
[2084]     if (h2c->state.length != NGX_HTTP_V2_RST_STREAM_SIZE) {
[2085]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2086]                       "client sent RST_STREAM frame with incorrect length %uz",
[2087]                       h2c->state.length);
[2088] 
[2089]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2090]     }
[2091] 
[2092]     if (end - pos < NGX_HTTP_V2_RST_STREAM_SIZE) {
[2093]         return ngx_http_v2_state_save(h2c, pos, end,
[2094]                                       ngx_http_v2_state_rst_stream);
[2095]     }
[2096] 
[2097]     status = ngx_http_v2_parse_uint32(pos);
[2098] 
[2099]     pos += NGX_HTTP_V2_RST_STREAM_SIZE;
[2100] 
[2101]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2102]                    "http2 RST_STREAM frame, sid:%ui status:%ui",
[2103]                    h2c->state.sid, status);
[2104] 
[2105]     if (h2c->state.sid == 0) {
[2106]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2107]                       "client sent RST_STREAM frame with incorrect identifier");
[2108] 
[2109]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2110]     }
[2111] 
[2112]     node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);
[2113] 
[2114]     if (node == NULL || node->stream == NULL) {
[2115]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2116]                        "unknown http2 stream");
[2117] 
[2118]         return ngx_http_v2_state_complete(h2c, pos, end);
[2119]     }
[2120] 
[2121]     stream = node->stream;
[2122] 
[2123]     stream->in_closed = 1;
[2124]     stream->out_closed = 1;
[2125] 
[2126]     fc = stream->request->connection;
[2127]     fc->error = 1;
[2128] 
[2129]     switch (status) {
[2130] 
[2131]     case NGX_HTTP_V2_CANCEL:
[2132]         ngx_log_error(NGX_LOG_INFO, fc->log, 0,
[2133]                       "client canceled stream %ui", h2c->state.sid);
[2134]         break;
[2135] 
[2136]     case NGX_HTTP_V2_REFUSED_STREAM:
[2137]         ngx_log_error(NGX_LOG_INFO, fc->log, 0,
[2138]                       "client refused stream %ui", h2c->state.sid);
[2139]         break;
[2140] 
[2141]     case NGX_HTTP_V2_INTERNAL_ERROR:
[2142]         ngx_log_error(NGX_LOG_INFO, fc->log, 0,
[2143]                       "client terminated stream %ui due to internal error",
[2144]                       h2c->state.sid);
[2145]         break;
[2146] 
[2147]     default:
[2148]         ngx_log_error(NGX_LOG_INFO, fc->log, 0,
[2149]                       "client terminated stream %ui with status %ui",
[2150]                       h2c->state.sid, status);
[2151]         break;
[2152]     }
[2153] 
[2154]     ev = fc->read;
[2155]     ev->handler(ev);
[2156] 
[2157]     return ngx_http_v2_state_complete(h2c, pos, end);
[2158] }
[2159] 
[2160] 
[2161] static u_char *
[2162] ngx_http_v2_state_settings(ngx_http_v2_connection_t *h2c, u_char *pos,
[2163]     u_char *end)
[2164] {
[2165]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2166]                    "http2 SETTINGS frame");
[2167] 
[2168]     if (h2c->state.sid) {
[2169]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2170]                       "client sent SETTINGS frame with incorrect identifier");
[2171] 
[2172]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2173]     }
[2174] 
[2175]     if (h2c->state.flags == NGX_HTTP_V2_ACK_FLAG) {
[2176] 
[2177]         if (h2c->state.length != 0) {
[2178]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2179]                           "client sent SETTINGS frame with the ACK flag "
[2180]                           "and nonzero length");
[2181] 
[2182]             return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2183]         }
[2184] 
[2185]         h2c->settings_ack = 1;
[2186] 
[2187]         return ngx_http_v2_state_complete(h2c, pos, end);
[2188]     }
[2189] 
[2190]     if (h2c->state.length % NGX_HTTP_V2_SETTINGS_PARAM_SIZE) {
[2191]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2192]                       "client sent SETTINGS frame with incorrect length %uz",
[2193]                       h2c->state.length);
[2194] 
[2195]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2196]     }
[2197] 
[2198]     return ngx_http_v2_state_settings_params(h2c, pos, end);
[2199] }
[2200] 
[2201] 
[2202] static u_char *
[2203] ngx_http_v2_state_settings_params(ngx_http_v2_connection_t *h2c, u_char *pos,
[2204]     u_char *end)
[2205] {
[2206]     ssize_t                   window_delta;
[2207]     ngx_uint_t                id, value;
[2208]     ngx_http_v2_srv_conf_t   *h2scf;
[2209]     ngx_http_v2_out_frame_t  *frame;
[2210] 
[2211]     window_delta = 0;
[2212] 
[2213]     while (h2c->state.length) {
[2214]         if (end - pos < NGX_HTTP_V2_SETTINGS_PARAM_SIZE) {
[2215]             return ngx_http_v2_state_save(h2c, pos, end,
[2216]                                           ngx_http_v2_state_settings_params);
[2217]         }
[2218] 
[2219]         h2c->state.length -= NGX_HTTP_V2_SETTINGS_PARAM_SIZE;
[2220] 
[2221]         id = ngx_http_v2_parse_uint16(pos);
[2222]         value = ngx_http_v2_parse_uint32(&pos[2]);
[2223] 
[2224]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2225]                        "http2 setting %ui:%ui", id, value);
[2226] 
[2227]         switch (id) {
[2228] 
[2229]         case NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING:
[2230] 
[2231]             if (value > NGX_HTTP_V2_MAX_WINDOW) {
[2232]                 ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2233]                               "client sent SETTINGS frame with incorrect "
[2234]                               "INITIAL_WINDOW_SIZE value %ui", value);
[2235] 
[2236]                 return ngx_http_v2_connection_error(h2c,
[2237]                                                   NGX_HTTP_V2_FLOW_CTRL_ERROR);
[2238]             }
[2239] 
[2240]             window_delta = value - h2c->init_window;
[2241]             break;
[2242] 
[2243]         case NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING:
[2244] 
[2245]             if (value > NGX_HTTP_V2_MAX_FRAME_SIZE
[2246]                 || value < NGX_HTTP_V2_DEFAULT_FRAME_SIZE)
[2247]             {
[2248]                 ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2249]                               "client sent SETTINGS frame with incorrect "
[2250]                               "MAX_FRAME_SIZE value %ui", value);
[2251] 
[2252]                 return ngx_http_v2_connection_error(h2c,
[2253]                                                     NGX_HTTP_V2_PROTOCOL_ERROR);
[2254]             }
[2255] 
[2256]             h2c->frame_size = value;
[2257]             break;
[2258] 
[2259]         case NGX_HTTP_V2_ENABLE_PUSH_SETTING:
[2260] 
[2261]             if (value > 1) {
[2262]                 ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2263]                               "client sent SETTINGS frame with incorrect "
[2264]                               "ENABLE_PUSH value %ui", value);
[2265] 
[2266]                 return ngx_http_v2_connection_error(h2c,
[2267]                                                     NGX_HTTP_V2_PROTOCOL_ERROR);
[2268]             }
[2269] 
[2270]             h2c->push_disabled = !value;
[2271]             break;
[2272] 
[2273]         case NGX_HTTP_V2_MAX_STREAMS_SETTING:
[2274]             h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[2275]                                                  ngx_http_v2_module);
[2276] 
[2277]             h2c->concurrent_pushes = ngx_min(value, h2scf->concurrent_pushes);
[2278]             break;
[2279] 
[2280]         case NGX_HTTP_V2_HEADER_TABLE_SIZE_SETTING:
[2281] 
[2282]             h2c->table_update = 1;
[2283]             break;
[2284] 
[2285]         default:
[2286]             break;
[2287]         }
[2288] 
[2289]         pos += NGX_HTTP_V2_SETTINGS_PARAM_SIZE;
[2290]     }
[2291] 
[2292]     frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_SETTINGS_ACK_SIZE,
[2293]                                   NGX_HTTP_V2_SETTINGS_FRAME,
[2294]                                   NGX_HTTP_V2_ACK_FLAG, 0);
[2295]     if (frame == NULL) {
[2296]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[2297]     }
[2298] 
[2299]     ngx_http_v2_queue_ordered_frame(h2c, frame);
[2300] 
[2301]     if (window_delta) {
[2302]         h2c->init_window += window_delta;
[2303] 
[2304]         if (ngx_http_v2_adjust_windows(h2c, window_delta) != NGX_OK) {
[2305]             return ngx_http_v2_connection_error(h2c,
[2306]                                                 NGX_HTTP_V2_INTERNAL_ERROR);
[2307]         }
[2308]     }
[2309] 
[2310]     return ngx_http_v2_state_complete(h2c, pos, end);
[2311] }
[2312] 
[2313] 
[2314] static u_char *
[2315] ngx_http_v2_state_push_promise(ngx_http_v2_connection_t *h2c, u_char *pos,
[2316]     u_char *end)
[2317] {
[2318]     ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2319]                   "client sent PUSH_PROMISE frame");
[2320] 
[2321]     return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2322] }
[2323] 
[2324] 
[2325] static u_char *
[2326] ngx_http_v2_state_ping(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
[2327] {
[2328]     ngx_buf_t                *buf;
[2329]     ngx_http_v2_out_frame_t  *frame;
[2330] 
[2331]     if (h2c->state.length != NGX_HTTP_V2_PING_SIZE) {
[2332]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2333]                       "client sent PING frame with incorrect length %uz",
[2334]                       h2c->state.length);
[2335] 
[2336]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2337]     }
[2338] 
[2339]     if (end - pos < NGX_HTTP_V2_PING_SIZE) {
[2340]         return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_ping);
[2341]     }
[2342] 
[2343]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2344]                    "http2 PING frame");
[2345] 
[2346]     if (h2c->state.sid) {
[2347]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2348]                       "client sent PING frame with incorrect identifier");
[2349] 
[2350]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2351]     }
[2352] 
[2353]     if (h2c->state.flags & NGX_HTTP_V2_ACK_FLAG) {
[2354]         return ngx_http_v2_state_skip(h2c, pos, end);
[2355]     }
[2356] 
[2357]     frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_PING_SIZE,
[2358]                                   NGX_HTTP_V2_PING_FRAME,
[2359]                                   NGX_HTTP_V2_ACK_FLAG, 0);
[2360]     if (frame == NULL) {
[2361]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[2362]     }
[2363] 
[2364]     buf = frame->first->buf;
[2365] 
[2366]     buf->last = ngx_cpymem(buf->last, pos, NGX_HTTP_V2_PING_SIZE);
[2367] 
[2368]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[2369] 
[2370]     return ngx_http_v2_state_complete(h2c, pos + NGX_HTTP_V2_PING_SIZE, end);
[2371] }
[2372] 
[2373] 
[2374] static u_char *
[2375] ngx_http_v2_state_goaway(ngx_http_v2_connection_t *h2c, u_char *pos,
[2376]     u_char *end)
[2377] {
[2378] #if (NGX_DEBUG)
[2379]     ngx_uint_t  last_sid, error;
[2380] #endif
[2381] 
[2382]     if (h2c->state.length < NGX_HTTP_V2_GOAWAY_SIZE) {
[2383]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2384]                       "client sent GOAWAY frame "
[2385]                       "with incorrect length %uz", h2c->state.length);
[2386] 
[2387]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2388]     }
[2389] 
[2390]     if (end - pos < NGX_HTTP_V2_GOAWAY_SIZE) {
[2391]         return ngx_http_v2_state_save(h2c, pos, end, ngx_http_v2_state_goaway);
[2392]     }
[2393] 
[2394]     if (h2c->state.sid) {
[2395]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2396]                       "client sent GOAWAY frame with incorrect identifier");
[2397] 
[2398]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2399]     }
[2400] 
[2401] #if (NGX_DEBUG)
[2402]     h2c->state.length -= NGX_HTTP_V2_GOAWAY_SIZE;
[2403] 
[2404]     last_sid = ngx_http_v2_parse_sid(pos);
[2405]     error = ngx_http_v2_parse_uint32(&pos[4]);
[2406] 
[2407]     pos += NGX_HTTP_V2_GOAWAY_SIZE;
[2408] 
[2409]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2410]                    "http2 GOAWAY frame: last sid %ui, error %ui",
[2411]                    last_sid, error);
[2412] #endif
[2413] 
[2414]     return ngx_http_v2_state_skip(h2c, pos, end);
[2415] }
[2416] 
[2417] 
[2418] static u_char *
[2419] ngx_http_v2_state_window_update(ngx_http_v2_connection_t *h2c, u_char *pos,
[2420]     u_char *end)
[2421] {
[2422]     size_t                 window;
[2423]     ngx_event_t           *wev;
[2424]     ngx_queue_t           *q;
[2425]     ngx_http_v2_node_t    *node;
[2426]     ngx_http_v2_stream_t  *stream;
[2427] 
[2428]     if (h2c->state.length != NGX_HTTP_V2_WINDOW_UPDATE_SIZE) {
[2429]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2430]                       "client sent WINDOW_UPDATE frame "
[2431]                       "with incorrect length %uz", h2c->state.length);
[2432] 
[2433]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
[2434]     }
[2435] 
[2436]     if (end - pos < NGX_HTTP_V2_WINDOW_UPDATE_SIZE) {
[2437]         return ngx_http_v2_state_save(h2c, pos, end,
[2438]                                       ngx_http_v2_state_window_update);
[2439]     }
[2440] 
[2441]     window = ngx_http_v2_parse_window(pos);
[2442] 
[2443]     pos += NGX_HTTP_V2_WINDOW_UPDATE_SIZE;
[2444] 
[2445]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2446]                    "http2 WINDOW_UPDATE frame sid:%ui window:%uz",
[2447]                    h2c->state.sid, window);
[2448] 
[2449]     if (window == 0) {
[2450]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2451]                       "client sent WINDOW_UPDATE frame "
[2452]                       "with incorrect window increment 0");
[2453] 
[2454]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2455]     }
[2456] 
[2457]     if (h2c->state.sid) {
[2458]         node = ngx_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);
[2459] 
[2460]         if (node == NULL || node->stream == NULL) {
[2461]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2462]                            "unknown http2 stream");
[2463] 
[2464]             return ngx_http_v2_state_complete(h2c, pos, end);
[2465]         }
[2466] 
[2467]         stream = node->stream;
[2468] 
[2469]         if (window > (size_t) (NGX_HTTP_V2_MAX_WINDOW - stream->send_window)) {
[2470] 
[2471]             ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2472]                           "client violated flow control for stream %ui: "
[2473]                           "received WINDOW_UPDATE frame "
[2474]                           "with window increment %uz "
[2475]                           "not allowed for window %z",
[2476]                           h2c->state.sid, window, stream->send_window);
[2477] 
[2478]             if (ngx_http_v2_terminate_stream(h2c, stream,
[2479]                                              NGX_HTTP_V2_FLOW_CTRL_ERROR)
[2480]                 == NGX_ERROR)
[2481]             {
[2482]                 return ngx_http_v2_connection_error(h2c,
[2483]                                                     NGX_HTTP_V2_INTERNAL_ERROR);
[2484]             }
[2485] 
[2486]             return ngx_http_v2_state_complete(h2c, pos, end);
[2487]         }
[2488] 
[2489]         stream->send_window += window;
[2490] 
[2491]         if (stream->exhausted) {
[2492]             stream->exhausted = 0;
[2493] 
[2494]             wev = stream->request->connection->write;
[2495] 
[2496]             wev->active = 0;
[2497]             wev->ready = 1;
[2498] 
[2499]             if (!wev->delayed) {
[2500]                 wev->handler(wev);
[2501]             }
[2502]         }
[2503] 
[2504]         return ngx_http_v2_state_complete(h2c, pos, end);
[2505]     }
[2506] 
[2507]     if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window) {
[2508]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2509]                       "client violated connection flow control: "
[2510]                       "received WINDOW_UPDATE frame "
[2511]                       "with window increment %uz "
[2512]                       "not allowed for window %uz",
[2513]                       window, h2c->send_window);
[2514] 
[2515]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
[2516]     }
[2517] 
[2518]     h2c->send_window += window;
[2519] 
[2520]     while (!ngx_queue_empty(&h2c->waiting)) {
[2521]         q = ngx_queue_head(&h2c->waiting);
[2522] 
[2523]         ngx_queue_remove(q);
[2524] 
[2525]         stream = ngx_queue_data(q, ngx_http_v2_stream_t, queue);
[2526] 
[2527]         stream->waiting = 0;
[2528] 
[2529]         wev = stream->request->connection->write;
[2530] 
[2531]         wev->active = 0;
[2532]         wev->ready = 1;
[2533] 
[2534]         if (!wev->delayed) {
[2535]             wev->handler(wev);
[2536] 
[2537]             if (h2c->send_window == 0) {
[2538]                 break;
[2539]             }
[2540]         }
[2541]     }
[2542] 
[2543]     return ngx_http_v2_state_complete(h2c, pos, end);
[2544] }
[2545] 
[2546] 
[2547] static u_char *
[2548] ngx_http_v2_state_continuation(ngx_http_v2_connection_t *h2c, u_char *pos,
[2549]     u_char *end)
[2550] {
[2551]     ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[2552]                   "client sent unexpected CONTINUATION frame");
[2553] 
[2554]     return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
[2555] }
[2556] 
[2557] 
[2558] static u_char *
[2559] ngx_http_v2_state_complete(ngx_http_v2_connection_t *h2c, u_char *pos,
[2560]     u_char *end)
[2561] {
[2562]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2563]                    "http2 frame complete pos:%p end:%p", pos, end);
[2564] 
[2565]     if (pos > end) {
[2566]         ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
[2567]                       "receive buffer overrun");
[2568] 
[2569]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[2570]     }
[2571] 
[2572]     h2c->state.stream = NULL;
[2573]     h2c->state.handler = ngx_http_v2_state_head;
[2574] 
[2575]     return pos;
[2576] }
[2577] 
[2578] 
[2579] static u_char *
[2580] ngx_http_v2_state_skip_padded(ngx_http_v2_connection_t *h2c, u_char *pos,
[2581]     u_char *end)
[2582] {
[2583]     h2c->state.length += h2c->state.padding;
[2584]     h2c->state.padding = 0;
[2585] 
[2586]     return ngx_http_v2_state_skip(h2c, pos, end);
[2587] }
[2588] 
[2589] 
[2590] static u_char *
[2591] ngx_http_v2_state_skip(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end)
[2592] {
[2593]     size_t  size;
[2594] 
[2595]     size = end - pos;
[2596] 
[2597]     if (size < h2c->state.length) {
[2598]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2599]                        "http2 frame skip %uz of %uz", size, h2c->state.length);
[2600] 
[2601]         h2c->state.length -= size;
[2602]         return ngx_http_v2_state_save(h2c, end, end, ngx_http_v2_state_skip);
[2603]     }
[2604] 
[2605]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2606]                    "http2 frame skip %uz", h2c->state.length);
[2607] 
[2608]     return ngx_http_v2_state_complete(h2c, pos + h2c->state.length, end);
[2609] }
[2610] 
[2611] 
[2612] static u_char *
[2613] ngx_http_v2_state_save(ngx_http_v2_connection_t *h2c, u_char *pos, u_char *end,
[2614]     ngx_http_v2_handler_pt handler)
[2615] {
[2616]     size_t  size;
[2617] 
[2618]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2619]                    "http2 frame state save pos:%p end:%p handler:%p",
[2620]                    pos, end, handler);
[2621] 
[2622]     size = end - pos;
[2623] 
[2624]     if (size > NGX_HTTP_V2_STATE_BUFFER_SIZE) {
[2625]         ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
[2626]                       "state buffer overflow: %uz bytes required", size);
[2627] 
[2628]         return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[2629]     }
[2630] 
[2631]     ngx_memcpy(h2c->state.buffer, pos, NGX_HTTP_V2_STATE_BUFFER_SIZE);
[2632] 
[2633]     h2c->state.buffer_used = size;
[2634]     h2c->state.handler = handler;
[2635]     h2c->state.incomplete = 1;
[2636] 
[2637]     return end;
[2638] }
[2639] 
[2640] 
[2641] static u_char *
[2642] ngx_http_v2_state_headers_save(ngx_http_v2_connection_t *h2c, u_char *pos,
[2643]     u_char *end, ngx_http_v2_handler_pt handler)
[2644] {
[2645]     ngx_event_t               *rev;
[2646]     ngx_http_request_t        *r;
[2647]     ngx_http_core_srv_conf_t  *cscf;
[2648] 
[2649]     if (h2c->state.stream) {
[2650]         r = h2c->state.stream->request;
[2651]         rev = r->connection->read;
[2652] 
[2653]         if (!rev->timer_set) {
[2654]             cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[2655]             ngx_add_timer(rev, cscf->client_header_timeout);
[2656]         }
[2657]     }
[2658] 
[2659]     return ngx_http_v2_state_save(h2c, pos, end, handler);
[2660] }
[2661] 
[2662] 
[2663] static u_char *
[2664] ngx_http_v2_connection_error(ngx_http_v2_connection_t *h2c,
[2665]     ngx_uint_t err)
[2666] {
[2667]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2668]                    "http2 state connection error");
[2669] 
[2670]     ngx_http_v2_finalize_connection(h2c, err);
[2671] 
[2672]     return NULL;
[2673] }
[2674] 
[2675] 
[2676] static ngx_int_t
[2677] ngx_http_v2_parse_int(ngx_http_v2_connection_t *h2c, u_char **pos, u_char *end,
[2678]     ngx_uint_t prefix)
[2679] {
[2680]     u_char      *start, *p;
[2681]     ngx_uint_t   value, octet, shift;
[2682] 
[2683]     start = *pos;
[2684]     p = start;
[2685] 
[2686]     value = *p++ & prefix;
[2687] 
[2688]     if (value != prefix) {
[2689]         if (h2c->state.length == 0) {
[2690]             return NGX_ERROR;
[2691]         }
[2692] 
[2693]         h2c->state.length--;
[2694] 
[2695]         *pos = p;
[2696]         return value;
[2697]     }
[2698] 
[2699]     if (end - start > NGX_HTTP_V2_INT_OCTETS) {
[2700]         end = start + NGX_HTTP_V2_INT_OCTETS;
[2701]     }
[2702] 
[2703]     for (shift = 0; p != end; shift += 7) {
[2704]         octet = *p++;
[2705] 
[2706]         value += (octet & 0x7f) << shift;
[2707] 
[2708]         if (octet < 128) {
[2709]             if ((size_t) (p - start) > h2c->state.length) {
[2710]                 return NGX_ERROR;
[2711]             }
[2712] 
[2713]             h2c->state.length -= p - start;
[2714] 
[2715]             *pos = p;
[2716]             return value;
[2717]         }
[2718]     }
[2719] 
[2720]     if ((size_t) (end - start) >= h2c->state.length) {
[2721]         return NGX_ERROR;
[2722]     }
[2723] 
[2724]     if (end == start + NGX_HTTP_V2_INT_OCTETS) {
[2725]         return NGX_DECLINED;
[2726]     }
[2727] 
[2728]     return NGX_AGAIN;
[2729] }
[2730] 
[2731] 
[2732] ngx_http_v2_stream_t *
[2733] ngx_http_v2_push_stream(ngx_http_v2_stream_t *parent, ngx_str_t *path)
[2734] {
[2735]     ngx_int_t                     rc;
[2736]     ngx_str_t                     value;
[2737]     ngx_pool_t                   *pool;
[2738]     ngx_uint_t                    index;
[2739]     ngx_table_elt_t             **h;
[2740]     ngx_connection_t             *fc;
[2741]     ngx_http_request_t           *r;
[2742]     ngx_http_v2_node_t           *node;
[2743]     ngx_http_v2_stream_t         *stream;
[2744]     ngx_http_v2_srv_conf_t       *h2scf;
[2745]     ngx_http_v2_connection_t     *h2c;
[2746]     ngx_http_v2_parse_header_t   *header;
[2747] 
[2748]     h2c = parent->connection;
[2749] 
[2750]     pool = ngx_create_pool(1024, h2c->connection->log);
[2751]     if (pool == NULL) {
[2752]         goto rst_stream;
[2753]     }
[2754] 
[2755]     node = ngx_http_v2_get_node_by_id(h2c, h2c->last_push, 1);
[2756] 
[2757]     if (node == NULL) {
[2758]         ngx_destroy_pool(pool);
[2759]         goto rst_stream;
[2760]     }
[2761] 
[2762]     stream = ngx_http_v2_create_stream(h2c, 1);
[2763]     if (stream == NULL) {
[2764] 
[2765]         if (node->parent == NULL) {
[2766]             h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[2767]                                                  ngx_http_v2_module);
[2768] 
[2769]             index = ngx_http_v2_index(h2scf, h2c->last_push);
[2770]             h2c->streams_index[index] = node->index;
[2771] 
[2772]             ngx_queue_insert_tail(&h2c->closed, &node->reuse);
[2773]             h2c->closed_nodes++;
[2774]         }
[2775] 
[2776]         ngx_destroy_pool(pool);
[2777]         goto rst_stream;
[2778]     }
[2779] 
[2780]     if (node->parent) {
[2781]         ngx_queue_remove(&node->reuse);
[2782]         h2c->closed_nodes--;
[2783]     }
[2784] 
[2785]     stream->pool = pool;
[2786] 
[2787]     r = stream->request;
[2788]     fc = r->connection;
[2789] 
[2790]     stream->in_closed = 1;
[2791]     stream->node = node;
[2792] 
[2793]     node->stream = stream;
[2794] 
[2795]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2796]                    "http2 push stream sid:%ui "
[2797]                    "depends on %ui excl:0 weight:16",
[2798]                    h2c->last_push, parent->node->id);
[2799] 
[2800]     node->weight = NGX_HTTP_V2_DEFAULT_WEIGHT;
[2801]     ngx_http_v2_set_dependency(h2c, node, parent->node->id, 0);
[2802] 
[2803]     r->method_name = ngx_http_core_get_method;
[2804]     r->method = NGX_HTTP_GET;
[2805] 
[2806]     r->schema.data = ngx_pstrdup(pool, &parent->request->schema);
[2807]     if (r->schema.data == NULL) {
[2808]         goto close;
[2809]     }
[2810] 
[2811]     r->schema.len = parent->request->schema.len;
[2812] 
[2813]     value.data = ngx_pstrdup(pool, path);
[2814]     if (value.data == NULL) {
[2815]         goto close;
[2816]     }
[2817] 
[2818]     value.len = path->len;
[2819] 
[2820]     rc = ngx_http_v2_parse_path(r, &value);
[2821] 
[2822]     if (rc != NGX_OK) {
[2823]         goto error;
[2824]     }
[2825] 
[2826]     for (header = ngx_http_v2_parse_headers; header->name.len; header++) {
[2827]         h = (ngx_table_elt_t **)
[2828]                 ((char *) &parent->request->headers_in + header->offset);
[2829] 
[2830]         if (*h == NULL) {
[2831]             continue;
[2832]         }
[2833] 
[2834]         value.len = (*h)->value.len;
[2835] 
[2836]         value.data = ngx_pnalloc(pool, value.len + 1);
[2837]         if (value.data == NULL) {
[2838]             goto close;
[2839]         }
[2840] 
[2841]         ngx_memcpy(value.data, (*h)->value.data, value.len);
[2842]         value.data[value.len] = '\0';
[2843] 
[2844]         rc = ngx_http_v2_parse_header(r, header, &value);
[2845] 
[2846]         if (rc != NGX_OK) {
[2847]             goto error;
[2848]         }
[2849]     }
[2850] 
[2851]     fc->write->handler = ngx_http_v2_run_request_handler;
[2852]     ngx_post_event(fc->write, &ngx_posted_events);
[2853] 
[2854]     return stream;
[2855] 
[2856] error:
[2857] 
[2858]     if (rc == NGX_ABORT) {
[2859]         /* header handler has already finalized request */
[2860]         ngx_http_run_posted_requests(fc);
[2861]         return NULL;
[2862]     }
[2863] 
[2864]     if (rc == NGX_DECLINED) {
[2865]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[2866]         ngx_http_run_posted_requests(fc);
[2867]         return NULL;
[2868]     }
[2869] 
[2870] close:
[2871] 
[2872]     ngx_http_v2_close_stream(stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
[2873] 
[2874]     return NULL;
[2875] 
[2876] rst_stream:
[2877] 
[2878]     if (ngx_http_v2_send_rst_stream(h2c, h2c->last_push,
[2879]                                     NGX_HTTP_INTERNAL_SERVER_ERROR)
[2880]         != NGX_OK)
[2881]     {
[2882]         h2c->connection->error = 1;
[2883]     }
[2884] 
[2885]     return NULL;
[2886] }
[2887] 
[2888] 
[2889] static ngx_int_t
[2890] ngx_http_v2_send_settings(ngx_http_v2_connection_t *h2c)
[2891] {
[2892]     size_t                    len;
[2893]     ngx_buf_t                *buf;
[2894]     ngx_chain_t              *cl;
[2895]     ngx_http_v2_srv_conf_t   *h2scf;
[2896]     ngx_http_v2_out_frame_t  *frame;
[2897] 
[2898]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2899]                    "http2 send SETTINGS frame");
[2900] 
[2901]     frame = ngx_palloc(h2c->pool, sizeof(ngx_http_v2_out_frame_t));
[2902]     if (frame == NULL) {
[2903]         return NGX_ERROR;
[2904]     }
[2905] 
[2906]     cl = ngx_alloc_chain_link(h2c->pool);
[2907]     if (cl == NULL) {
[2908]         return NGX_ERROR;
[2909]     }
[2910] 
[2911]     len = NGX_HTTP_V2_SETTINGS_PARAM_SIZE * 3;
[2912] 
[2913]     buf = ngx_create_temp_buf(h2c->pool, NGX_HTTP_V2_FRAME_HEADER_SIZE + len);
[2914]     if (buf == NULL) {
[2915]         return NGX_ERROR;
[2916]     }
[2917] 
[2918]     buf->last_buf = 1;
[2919] 
[2920]     cl->buf = buf;
[2921]     cl->next = NULL;
[2922] 
[2923]     frame->first = cl;
[2924]     frame->last = cl;
[2925]     frame->handler = ngx_http_v2_settings_frame_handler;
[2926]     frame->stream = NULL;
[2927] #if (NGX_DEBUG)
[2928]     frame->length = len;
[2929] #endif
[2930]     frame->blocked = 0;
[2931] 
[2932]     buf->last = ngx_http_v2_write_len_and_type(buf->last, len,
[2933]                                                NGX_HTTP_V2_SETTINGS_FRAME);
[2934] 
[2935]     *buf->last++ = NGX_HTTP_V2_NO_FLAG;
[2936] 
[2937]     buf->last = ngx_http_v2_write_sid(buf->last, 0);
[2938] 
[2939]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[2940]                                          ngx_http_v2_module);
[2941] 
[2942]     buf->last = ngx_http_v2_write_uint16(buf->last,
[2943]                                          NGX_HTTP_V2_MAX_STREAMS_SETTING);
[2944]     buf->last = ngx_http_v2_write_uint32(buf->last,
[2945]                                          h2scf->concurrent_streams);
[2946] 
[2947]     buf->last = ngx_http_v2_write_uint16(buf->last,
[2948]                                          NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
[2949]     buf->last = ngx_http_v2_write_uint32(buf->last, h2scf->preread_size);
[2950] 
[2951]     buf->last = ngx_http_v2_write_uint16(buf->last,
[2952]                                          NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING);
[2953]     buf->last = ngx_http_v2_write_uint32(buf->last,
[2954]                                          NGX_HTTP_V2_MAX_FRAME_SIZE);
[2955] 
[2956]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[2957] 
[2958]     return NGX_OK;
[2959] }
[2960] 
[2961] 
[2962] static ngx_int_t
[2963] ngx_http_v2_settings_frame_handler(ngx_http_v2_connection_t *h2c,
[2964]     ngx_http_v2_out_frame_t *frame)
[2965] {
[2966]     ngx_buf_t  *buf;
[2967] 
[2968]     buf = frame->first->buf;
[2969] 
[2970]     if (buf->pos != buf->last) {
[2971]         return NGX_AGAIN;
[2972]     }
[2973] 
[2974]     ngx_free_chain(h2c->pool, frame->first);
[2975] 
[2976]     return NGX_OK;
[2977] }
[2978] 
[2979] 
[2980] static ngx_int_t
[2981] ngx_http_v2_send_window_update(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
[2982]     size_t window)
[2983] {
[2984]     ngx_buf_t                *buf;
[2985]     ngx_http_v2_out_frame_t  *frame;
[2986] 
[2987]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[2988]                    "http2 send WINDOW_UPDATE frame sid:%ui, window:%uz",
[2989]                    sid, window);
[2990] 
[2991]     frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_WINDOW_UPDATE_SIZE,
[2992]                                   NGX_HTTP_V2_WINDOW_UPDATE_FRAME,
[2993]                                   NGX_HTTP_V2_NO_FLAG, sid);
[2994]     if (frame == NULL) {
[2995]         return NGX_ERROR;
[2996]     }
[2997] 
[2998]     buf = frame->first->buf;
[2999] 
[3000]     buf->last = ngx_http_v2_write_uint32(buf->last, window);
[3001] 
[3002]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[3003] 
[3004]     return NGX_OK;
[3005] }
[3006] 
[3007] 
[3008] static ngx_int_t
[3009] ngx_http_v2_send_rst_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
[3010]     ngx_uint_t status)
[3011] {
[3012]     ngx_buf_t                *buf;
[3013]     ngx_http_v2_out_frame_t  *frame;
[3014] 
[3015]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[3016]                    "http2 send RST_STREAM frame sid:%ui, status:%ui",
[3017]                    sid, status);
[3018] 
[3019]     frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_RST_STREAM_SIZE,
[3020]                                   NGX_HTTP_V2_RST_STREAM_FRAME,
[3021]                                   NGX_HTTP_V2_NO_FLAG, sid);
[3022]     if (frame == NULL) {
[3023]         return NGX_ERROR;
[3024]     }
[3025] 
[3026]     buf = frame->first->buf;
[3027] 
[3028]     buf->last = ngx_http_v2_write_uint32(buf->last, status);
[3029] 
[3030]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[3031] 
[3032]     return NGX_OK;
[3033] }
[3034] 
[3035] 
[3036] static ngx_int_t
[3037] ngx_http_v2_send_goaway(ngx_http_v2_connection_t *h2c, ngx_uint_t status)
[3038] {
[3039]     ngx_buf_t                *buf;
[3040]     ngx_http_v2_out_frame_t  *frame;
[3041] 
[3042]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[3043]                    "http2 send GOAWAY frame: last sid %ui, error %ui",
[3044]                    h2c->last_sid, status);
[3045] 
[3046]     frame = ngx_http_v2_get_frame(h2c, NGX_HTTP_V2_GOAWAY_SIZE,
[3047]                                   NGX_HTTP_V2_GOAWAY_FRAME,
[3048]                                   NGX_HTTP_V2_NO_FLAG, 0);
[3049]     if (frame == NULL) {
[3050]         return NGX_ERROR;
[3051]     }
[3052] 
[3053]     buf = frame->first->buf;
[3054] 
[3055]     buf->last = ngx_http_v2_write_sid(buf->last, h2c->last_sid);
[3056]     buf->last = ngx_http_v2_write_uint32(buf->last, status);
[3057] 
[3058]     ngx_http_v2_queue_blocked_frame(h2c, frame);
[3059] 
[3060]     return NGX_OK;
[3061] }
[3062] 
[3063] 
[3064] static ngx_http_v2_out_frame_t *
[3065] ngx_http_v2_get_frame(ngx_http_v2_connection_t *h2c, size_t length,
[3066]     ngx_uint_t type, u_char flags, ngx_uint_t sid)
[3067] {
[3068]     ngx_buf_t                *buf;
[3069]     ngx_pool_t               *pool;
[3070]     ngx_http_v2_out_frame_t  *frame;
[3071] 
[3072]     frame = h2c->free_frames;
[3073] 
[3074]     if (frame) {
[3075]         h2c->free_frames = frame->next;
[3076] 
[3077]         buf = frame->first->buf;
[3078]         buf->pos = buf->start;
[3079] 
[3080]         frame->blocked = 0;
[3081] 
[3082]     } else if (h2c->frames < 10000) {
[3083]         pool = h2c->pool ? h2c->pool : h2c->connection->pool;
[3084] 
[3085]         frame = ngx_pcalloc(pool, sizeof(ngx_http_v2_out_frame_t));
[3086]         if (frame == NULL) {
[3087]             return NULL;
[3088]         }
[3089] 
[3090]         frame->first = ngx_alloc_chain_link(pool);
[3091]         if (frame->first == NULL) {
[3092]             return NULL;
[3093]         }
[3094] 
[3095]         buf = ngx_create_temp_buf(pool, NGX_HTTP_V2_FRAME_BUFFER_SIZE);
[3096]         if (buf == NULL) {
[3097]             return NULL;
[3098]         }
[3099] 
[3100]         buf->last_buf = 1;
[3101] 
[3102]         frame->first->buf = buf;
[3103]         frame->last = frame->first;
[3104] 
[3105]         frame->handler = ngx_http_v2_frame_handler;
[3106] 
[3107]         h2c->frames++;
[3108] 
[3109]     } else {
[3110]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[3111]                       "http2 flood detected");
[3112] 
[3113]         h2c->connection->error = 1;
[3114]         return NULL;
[3115]     }
[3116] 
[3117] #if (NGX_DEBUG)
[3118]     if (length > NGX_HTTP_V2_FRAME_BUFFER_SIZE - NGX_HTTP_V2_FRAME_HEADER_SIZE)
[3119]     {
[3120]         ngx_log_error(NGX_LOG_ALERT, h2c->connection->log, 0,
[3121]                       "requested control frame is too large: %uz", length);
[3122]         return NULL;
[3123]     }
[3124] #endif
[3125] 
[3126]     frame->length = length;
[3127] 
[3128]     buf->last = ngx_http_v2_write_len_and_type(buf->pos, length, type);
[3129] 
[3130]     *buf->last++ = flags;
[3131] 
[3132]     buf->last = ngx_http_v2_write_sid(buf->last, sid);
[3133] 
[3134]     return frame;
[3135] }
[3136] 
[3137] 
[3138] static ngx_int_t
[3139] ngx_http_v2_frame_handler(ngx_http_v2_connection_t *h2c,
[3140]     ngx_http_v2_out_frame_t *frame)
[3141] {
[3142]     ngx_buf_t  *buf;
[3143] 
[3144]     buf = frame->first->buf;
[3145] 
[3146]     if (buf->pos != buf->last) {
[3147]         return NGX_AGAIN;
[3148]     }
[3149] 
[3150]     frame->next = h2c->free_frames;
[3151]     h2c->free_frames = frame;
[3152] 
[3153]     h2c->total_bytes += NGX_HTTP_V2_FRAME_HEADER_SIZE + frame->length;
[3154] 
[3155]     return NGX_OK;
[3156] }
[3157] 
[3158] 
[3159] static ngx_http_v2_stream_t *
[3160] ngx_http_v2_create_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t push)
[3161] {
[3162]     ngx_log_t                 *log;
[3163]     ngx_event_t               *rev, *wev;
[3164]     ngx_connection_t          *fc;
[3165]     ngx_http_log_ctx_t        *ctx;
[3166]     ngx_http_request_t        *r;
[3167]     ngx_http_v2_stream_t      *stream;
[3168]     ngx_http_v2_srv_conf_t    *h2scf;
[3169]     ngx_http_core_srv_conf_t  *cscf;
[3170] 
[3171]     fc = h2c->free_fake_connections;
[3172] 
[3173]     if (fc) {
[3174]         h2c->free_fake_connections = fc->data;
[3175] 
[3176]         rev = fc->read;
[3177]         wev = fc->write;
[3178]         log = fc->log;
[3179]         ctx = log->data;
[3180] 
[3181]     } else {
[3182]         fc = ngx_palloc(h2c->pool, sizeof(ngx_connection_t));
[3183]         if (fc == NULL) {
[3184]             return NULL;
[3185]         }
[3186] 
[3187]         rev = ngx_palloc(h2c->pool, sizeof(ngx_event_t));
[3188]         if (rev == NULL) {
[3189]             return NULL;
[3190]         }
[3191] 
[3192]         wev = ngx_palloc(h2c->pool, sizeof(ngx_event_t));
[3193]         if (wev == NULL) {
[3194]             return NULL;
[3195]         }
[3196] 
[3197]         log = ngx_palloc(h2c->pool, sizeof(ngx_log_t));
[3198]         if (log == NULL) {
[3199]             return NULL;
[3200]         }
[3201] 
[3202]         ctx = ngx_palloc(h2c->pool, sizeof(ngx_http_log_ctx_t));
[3203]         if (ctx == NULL) {
[3204]             return NULL;
[3205]         }
[3206] 
[3207]         ctx->connection = fc;
[3208]         ctx->request = NULL;
[3209]         ctx->current_request = NULL;
[3210]     }
[3211] 
[3212]     ngx_memcpy(log, h2c->connection->log, sizeof(ngx_log_t));
[3213] 
[3214]     log->data = ctx;
[3215] 
[3216]     if (push) {
[3217]         log->action = "processing pushed request headers";
[3218] 
[3219]     } else {
[3220]         log->action = "reading client request headers";
[3221]     }
[3222] 
[3223]     ngx_memzero(rev, sizeof(ngx_event_t));
[3224] 
[3225]     rev->data = fc;
[3226]     rev->ready = 1;
[3227]     rev->handler = ngx_http_v2_close_stream_handler;
[3228]     rev->log = log;
[3229] 
[3230]     ngx_memcpy(wev, rev, sizeof(ngx_event_t));
[3231] 
[3232]     wev->write = 1;
[3233] 
[3234]     ngx_memcpy(fc, h2c->connection, sizeof(ngx_connection_t));
[3235] 
[3236]     fc->data = h2c->http_connection;
[3237]     fc->read = rev;
[3238]     fc->write = wev;
[3239]     fc->sent = 0;
[3240]     fc->log = log;
[3241]     fc->buffered = 0;
[3242]     fc->sndlowat = 1;
[3243]     fc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
[3244] 
[3245]     r = ngx_http_create_request(fc);
[3246]     if (r == NULL) {
[3247]         return NULL;
[3248]     }
[3249] 
[3250]     ngx_str_set(&r->http_protocol, "HTTP/2.0");
[3251] 
[3252]     r->http_version = NGX_HTTP_VERSION_20;
[3253]     r->valid_location = 1;
[3254] 
[3255]     fc->data = r;
[3256]     h2c->connection->requests++;
[3257] 
[3258]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[3259] 
[3260]     r->header_in = ngx_create_temp_buf(r->pool,
[3261]                                        cscf->client_header_buffer_size);
[3262]     if (r->header_in == NULL) {
[3263]         ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3264]         return NULL;
[3265]     }
[3266] 
[3267]     if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
[3268]                       sizeof(ngx_table_elt_t))
[3269]         != NGX_OK)
[3270]     {
[3271]         ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3272]         return NULL;
[3273]     }
[3274] 
[3275]     r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;
[3276] 
[3277]     stream = ngx_pcalloc(r->pool, sizeof(ngx_http_v2_stream_t));
[3278]     if (stream == NULL) {
[3279]         ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3280]         return NULL;
[3281]     }
[3282] 
[3283]     r->stream = stream;
[3284] 
[3285]     stream->request = r;
[3286]     stream->connection = h2c;
[3287] 
[3288]     h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);
[3289] 
[3290]     stream->send_window = h2c->init_window;
[3291]     stream->recv_window = h2scf->preread_size;
[3292] 
[3293]     if (push) {
[3294]         h2c->pushing++;
[3295] 
[3296]     } else {
[3297]         h2c->processing++;
[3298]     }
[3299] 
[3300]     h2c->priority_limit += h2scf->concurrent_streams;
[3301] 
[3302]     if (h2c->connection->read->timer_set) {
[3303]         ngx_del_timer(h2c->connection->read);
[3304]     }
[3305] 
[3306]     return stream;
[3307] }
[3308] 
[3309] 
[3310] static ngx_http_v2_node_t *
[3311] ngx_http_v2_get_node_by_id(ngx_http_v2_connection_t *h2c, ngx_uint_t sid,
[3312]     ngx_uint_t alloc)
[3313] {
[3314]     ngx_uint_t               index;
[3315]     ngx_http_v2_node_t      *node;
[3316]     ngx_http_v2_srv_conf_t  *h2scf;
[3317] 
[3318]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[3319]                                          ngx_http_v2_module);
[3320] 
[3321]     index = ngx_http_v2_index(h2scf, sid);
[3322] 
[3323]     for (node = h2c->streams_index[index]; node; node = node->index) {
[3324] 
[3325]         if (node->id == sid) {
[3326]             return node;
[3327]         }
[3328]     }
[3329] 
[3330]     if (!alloc) {
[3331]         return NULL;
[3332]     }
[3333] 
[3334]     if (h2c->closed_nodes < 32) {
[3335]         node = ngx_pcalloc(h2c->connection->pool, sizeof(ngx_http_v2_node_t));
[3336]         if (node == NULL) {
[3337]             return NULL;
[3338]         }
[3339] 
[3340]     } else {
[3341]         node = ngx_http_v2_get_closed_node(h2c);
[3342]     }
[3343] 
[3344]     node->id = sid;
[3345] 
[3346]     ngx_queue_init(&node->children);
[3347] 
[3348]     node->index = h2c->streams_index[index];
[3349]     h2c->streams_index[index] = node;
[3350] 
[3351]     return node;
[3352] }
[3353] 
[3354] 
[3355] static ngx_http_v2_node_t *
[3356] ngx_http_v2_get_closed_node(ngx_http_v2_connection_t *h2c)
[3357] {
[3358]     ngx_uint_t               weight;
[3359]     ngx_queue_t             *q, *children;
[3360]     ngx_http_v2_node_t      *node, **next, *n, *parent, *child;
[3361]     ngx_http_v2_srv_conf_t  *h2scf;
[3362] 
[3363]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[3364]                                          ngx_http_v2_module);
[3365] 
[3366]     h2c->closed_nodes--;
[3367] 
[3368]     q = ngx_queue_head(&h2c->closed);
[3369] 
[3370]     ngx_queue_remove(q);
[3371] 
[3372]     node = ngx_queue_data(q, ngx_http_v2_node_t, reuse);
[3373] 
[3374]     next = &h2c->streams_index[ngx_http_v2_index(h2scf, node->id)];
[3375] 
[3376]     for ( ;; ) {
[3377]         n = *next;
[3378] 
[3379]         if (n == node) {
[3380]             *next = n->index;
[3381]             break;
[3382]         }
[3383] 
[3384]         next = &n->index;
[3385]     }
[3386] 
[3387]     ngx_queue_remove(&node->queue);
[3388] 
[3389]     weight = 0;
[3390] 
[3391]     for (q = ngx_queue_head(&node->children);
[3392]          q != ngx_queue_sentinel(&node->children);
[3393]          q = ngx_queue_next(q))
[3394]     {
[3395]         child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
[3396]         weight += child->weight;
[3397]     }
[3398] 
[3399]     parent = node->parent;
[3400] 
[3401]     for (q = ngx_queue_head(&node->children);
[3402]          q != ngx_queue_sentinel(&node->children);
[3403]          q = ngx_queue_next(q))
[3404]     {
[3405]         child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
[3406]         child->parent = parent;
[3407]         child->weight = node->weight * child->weight / weight;
[3408] 
[3409]         if (child->weight == 0) {
[3410]             child->weight = 1;
[3411]         }
[3412]     }
[3413] 
[3414]     if (parent == NGX_HTTP_V2_ROOT) {
[3415]         node->rank = 0;
[3416]         node->rel_weight = 1.0;
[3417] 
[3418]         children = &h2c->dependencies;
[3419] 
[3420]     } else {
[3421]         node->rank = parent->rank;
[3422]         node->rel_weight = parent->rel_weight;
[3423] 
[3424]         children = &parent->children;
[3425]     }
[3426] 
[3427]     ngx_http_v2_node_children_update(node);
[3428]     ngx_queue_add(children, &node->children);
[3429] 
[3430]     ngx_memzero(node, sizeof(ngx_http_v2_node_t));
[3431] 
[3432]     return node;
[3433] }
[3434] 
[3435] 
[3436] static ngx_int_t
[3437] ngx_http_v2_validate_header(ngx_http_request_t *r, ngx_http_v2_header_t *header)
[3438] {
[3439]     u_char                     ch;
[3440]     ngx_uint_t                 i;
[3441]     ngx_http_core_srv_conf_t  *cscf;
[3442] 
[3443]     r->invalid_header = 0;
[3444] 
[3445]     cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
[3446] 
[3447]     for (i = (header->name.data[0] == ':'); i != header->name.len; i++) {
[3448]         ch = header->name.data[i];
[3449] 
[3450]         if ((ch >= 'a' && ch <= 'z')
[3451]             || (ch == '-')
[3452]             || (ch >= '0' && ch <= '9')
[3453]             || (ch == '_' && cscf->underscores_in_headers))
[3454]         {
[3455]             continue;
[3456]         }
[3457] 
[3458]         if (ch <= 0x20 || ch == 0x7f || ch == ':'
[3459]             || (ch >= 'A' && ch <= 'Z'))
[3460]         {
[3461]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3462]                           "client sent invalid header name: \"%V\"",
[3463]                           &header->name);
[3464] 
[3465]             return NGX_ERROR;
[3466]         }
[3467] 
[3468]         r->invalid_header = 1;
[3469]     }
[3470] 
[3471]     for (i = 0; i != header->value.len; i++) {
[3472]         ch = header->value.data[i];
[3473] 
[3474]         if (ch == '\0' || ch == LF || ch == CR) {
[3475]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3476]                           "client sent header \"%V\" with "
[3477]                           "invalid value: \"%V\"",
[3478]                           &header->name, &header->value);
[3479] 
[3480]             return NGX_ERROR;
[3481]         }
[3482]     }
[3483] 
[3484]     return NGX_OK;
[3485] }
[3486] 
[3487] 
[3488] static ngx_int_t
[3489] ngx_http_v2_pseudo_header(ngx_http_request_t *r, ngx_http_v2_header_t *header)
[3490] {
[3491]     header->name.len--;
[3492]     header->name.data++;
[3493] 
[3494]     switch (header->name.len) {
[3495]     case 4:
[3496]         if (ngx_memcmp(header->name.data, "path", sizeof("path") - 1)
[3497]             == 0)
[3498]         {
[3499]             return ngx_http_v2_parse_path(r, &header->value);
[3500]         }
[3501] 
[3502]         break;
[3503] 
[3504]     case 6:
[3505]         if (ngx_memcmp(header->name.data, "method", sizeof("method") - 1)
[3506]             == 0)
[3507]         {
[3508]             return ngx_http_v2_parse_method(r, &header->value);
[3509]         }
[3510] 
[3511]         if (ngx_memcmp(header->name.data, "scheme", sizeof("scheme") - 1)
[3512]             == 0)
[3513]         {
[3514]             return ngx_http_v2_parse_scheme(r, &header->value);
[3515]         }
[3516] 
[3517]         break;
[3518] 
[3519]     case 9:
[3520]         if (ngx_memcmp(header->name.data, "authority", sizeof("authority") - 1)
[3521]             == 0)
[3522]         {
[3523]             return ngx_http_v2_parse_authority(r, &header->value);
[3524]         }
[3525] 
[3526]         break;
[3527]     }
[3528] 
[3529]     ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3530]                   "client sent unknown pseudo-header \":%V\"",
[3531]                   &header->name);
[3532] 
[3533]     return NGX_DECLINED;
[3534] }
[3535] 
[3536] 
[3537] static ngx_int_t
[3538] ngx_http_v2_parse_path(ngx_http_request_t *r, ngx_str_t *value)
[3539] {
[3540]     if (r->unparsed_uri.len) {
[3541]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3542]                       "client sent duplicate :path header");
[3543] 
[3544]         return NGX_DECLINED;
[3545]     }
[3546] 
[3547]     if (value->len == 0) {
[3548]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3549]                       "client sent empty :path header");
[3550] 
[3551]         return NGX_DECLINED;
[3552]     }
[3553] 
[3554]     r->uri_start = value->data;
[3555]     r->uri_end = value->data + value->len;
[3556] 
[3557]     if (ngx_http_parse_uri(r) != NGX_OK) {
[3558]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3559]                       "client sent invalid :path header: \"%V\"", value);
[3560] 
[3561]         return NGX_DECLINED;
[3562]     }
[3563] 
[3564]     if (ngx_http_process_request_uri(r) != NGX_OK) {
[3565]         /*
[3566]          * request has been finalized already
[3567]          * in ngx_http_process_request_uri()
[3568]          */
[3569]         return NGX_ABORT;
[3570]     }
[3571] 
[3572]     return NGX_OK;
[3573] }
[3574] 
[3575] 
[3576] static ngx_int_t
[3577] ngx_http_v2_parse_method(ngx_http_request_t *r, ngx_str_t *value)
[3578] {
[3579]     size_t         k, len;
[3580]     ngx_uint_t     n;
[3581]     const u_char  *p, *m;
[3582] 
[3583]     /*
[3584]      * This array takes less than 256 sequential bytes,
[3585]      * and if typical CPU cache line size is 64 bytes,
[3586]      * it is prefetched for 4 load operations.
[3587]      */
[3588]     static const struct {
[3589]         u_char            len;
[3590]         const u_char      method[11];
[3591]         uint32_t          value;
[3592]     } tests[] = {
[3593]         { 3, "GET",       NGX_HTTP_GET },
[3594]         { 4, "POST",      NGX_HTTP_POST },
[3595]         { 4, "HEAD",      NGX_HTTP_HEAD },
[3596]         { 7, "OPTIONS",   NGX_HTTP_OPTIONS },
[3597]         { 8, "PROPFIND",  NGX_HTTP_PROPFIND },
[3598]         { 3, "PUT",       NGX_HTTP_PUT },
[3599]         { 5, "MKCOL",     NGX_HTTP_MKCOL },
[3600]         { 6, "DELETE",    NGX_HTTP_DELETE },
[3601]         { 4, "COPY",      NGX_HTTP_COPY },
[3602]         { 4, "MOVE",      NGX_HTTP_MOVE },
[3603]         { 9, "PROPPATCH", NGX_HTTP_PROPPATCH },
[3604]         { 4, "LOCK",      NGX_HTTP_LOCK },
[3605]         { 6, "UNLOCK",    NGX_HTTP_UNLOCK },
[3606]         { 5, "PATCH",     NGX_HTTP_PATCH },
[3607]         { 5, "TRACE",     NGX_HTTP_TRACE },
[3608]         { 7, "CONNECT",   NGX_HTTP_CONNECT }
[3609]     }, *test;
[3610] 
[3611]     if (r->method_name.len) {
[3612]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3613]                       "client sent duplicate :method header");
[3614] 
[3615]         return NGX_DECLINED;
[3616]     }
[3617] 
[3618]     if (value->len == 0) {
[3619]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3620]                       "client sent empty :method header");
[3621] 
[3622]         return NGX_DECLINED;
[3623]     }
[3624] 
[3625]     r->method_name.len = value->len;
[3626]     r->method_name.data = value->data;
[3627] 
[3628]     len = r->method_name.len;
[3629]     n = sizeof(tests) / sizeof(tests[0]);
[3630]     test = tests;
[3631] 
[3632]     do {
[3633]         if (len == test->len) {
[3634]             p = r->method_name.data;
[3635]             m = test->method;
[3636]             k = len;
[3637] 
[3638]             do {
[3639]                 if (*p++ != *m++) {
[3640]                     goto next;
[3641]                 }
[3642]             } while (--k);
[3643] 
[3644]             r->method = test->value;
[3645]             return NGX_OK;
[3646]         }
[3647] 
[3648]     next:
[3649]         test++;
[3650] 
[3651]     } while (--n);
[3652] 
[3653]     p = r->method_name.data;
[3654] 
[3655]     do {
[3656]         if ((*p < 'A' || *p > 'Z') && *p != '_' && *p != '-') {
[3657]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3658]                           "client sent invalid method: \"%V\"",
[3659]                           &r->method_name);
[3660] 
[3661]             return NGX_DECLINED;
[3662]         }
[3663] 
[3664]         p++;
[3665] 
[3666]     } while (--len);
[3667] 
[3668]     return NGX_OK;
[3669] }
[3670] 
[3671] 
[3672] static ngx_int_t
[3673] ngx_http_v2_parse_scheme(ngx_http_request_t *r, ngx_str_t *value)
[3674] {
[3675]     u_char      c, ch;
[3676]     ngx_uint_t  i;
[3677] 
[3678]     if (r->schema.len) {
[3679]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3680]                       "client sent duplicate :scheme header");
[3681] 
[3682]         return NGX_DECLINED;
[3683]     }
[3684] 
[3685]     if (value->len == 0) {
[3686]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3687]                       "client sent empty :scheme header");
[3688] 
[3689]         return NGX_DECLINED;
[3690]     }
[3691] 
[3692]     for (i = 0; i < value->len; i++) {
[3693]         ch = value->data[i];
[3694] 
[3695]         c = (u_char) (ch | 0x20);
[3696]         if (c >= 'a' && c <= 'z') {
[3697]             continue;
[3698]         }
[3699] 
[3700]         if (((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
[3701]             && i > 0)
[3702]         {
[3703]             continue;
[3704]         }
[3705] 
[3706]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3707]                       "client sent invalid :scheme header: \"%V\"", value);
[3708] 
[3709]         return NGX_DECLINED;
[3710]     }
[3711] 
[3712]     r->schema = *value;
[3713] 
[3714]     return NGX_OK;
[3715] }
[3716] 
[3717] 
[3718] static ngx_int_t
[3719] ngx_http_v2_parse_authority(ngx_http_request_t *r, ngx_str_t *value)
[3720] {
[3721]     return ngx_http_v2_parse_header(r, &ngx_http_v2_parse_headers[0], value);
[3722] }
[3723] 
[3724] 
[3725] static ngx_int_t
[3726] ngx_http_v2_parse_header(ngx_http_request_t *r,
[3727]     ngx_http_v2_parse_header_t *header, ngx_str_t *value)
[3728] {
[3729]     ngx_table_elt_t            *h;
[3730]     ngx_http_core_main_conf_t  *cmcf;
[3731] 
[3732]     h = ngx_list_push(&r->headers_in.headers);
[3733]     if (h == NULL) {
[3734]         return NGX_ERROR;
[3735]     }
[3736] 
[3737]     h->key.len = header->name.len;
[3738]     h->key.data = header->name.data;
[3739]     h->lowcase_key = header->name.data;
[3740] 
[3741]     if (header->hh == NULL) {
[3742]         header->hash = ngx_hash_key(header->name.data, header->name.len);
[3743] 
[3744]         cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[3745] 
[3746]         header->hh = ngx_hash_find(&cmcf->headers_in_hash, header->hash,
[3747]                                    h->lowcase_key, h->key.len);
[3748]         if (header->hh == NULL) {
[3749]             return NGX_ERROR;
[3750]         }
[3751]     }
[3752] 
[3753]     h->hash = header->hash;
[3754] 
[3755]     h->value.len = value->len;
[3756]     h->value.data = value->data;
[3757] 
[3758]     if (header->hh->handler(r, h, header->hh->offset) != NGX_OK) {
[3759]         /* header handler has already finalized request */
[3760]         return NGX_ABORT;
[3761]     }
[3762] 
[3763]     return NGX_OK;
[3764] }
[3765] 
[3766] 
[3767] static ngx_int_t
[3768] ngx_http_v2_construct_request_line(ngx_http_request_t *r)
[3769] {
[3770]     u_char  *p;
[3771] 
[3772]     static const u_char ending[] = " HTTP/2.0";
[3773] 
[3774]     if (r->method_name.len == 0
[3775]         || r->schema.len == 0
[3776]         || r->unparsed_uri.len == 0)
[3777]     {
[3778]         if (r->method_name.len == 0) {
[3779]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3780]                           "client sent no :method header");
[3781] 
[3782]         } else if (r->schema.len == 0) {
[3783]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3784]                           "client sent no :scheme header");
[3785] 
[3786]         } else {
[3787]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3788]                           "client sent no :path header");
[3789]         }
[3790] 
[3791]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[3792]         return NGX_ERROR;
[3793]     }
[3794] 
[3795]     r->request_line.len = r->method_name.len + 1
[3796]                           + r->unparsed_uri.len
[3797]                           + sizeof(ending) - 1;
[3798] 
[3799]     p = ngx_pnalloc(r->pool, r->request_line.len + 1);
[3800]     if (p == NULL) {
[3801]         ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3802]         return NGX_ERROR;
[3803]     }
[3804] 
[3805]     r->request_line.data = p;
[3806] 
[3807]     p = ngx_cpymem(p, r->method_name.data, r->method_name.len);
[3808] 
[3809]     *p++ = ' ';
[3810] 
[3811]     p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);
[3812] 
[3813]     ngx_memcpy(p, ending, sizeof(ending));
[3814] 
[3815]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[3816]                    "http2 request line: \"%V\"", &r->request_line);
[3817] 
[3818]     return NGX_OK;
[3819] }
[3820] 
[3821] 
[3822] static ngx_int_t
[3823] ngx_http_v2_cookie(ngx_http_request_t *r, ngx_http_v2_header_t *header)
[3824] {
[3825]     ngx_str_t    *val;
[3826]     ngx_array_t  *cookies;
[3827] 
[3828]     cookies = r->stream->cookies;
[3829] 
[3830]     if (cookies == NULL) {
[3831]         cookies = ngx_array_create(r->pool, 2, sizeof(ngx_str_t));
[3832]         if (cookies == NULL) {
[3833]             return NGX_ERROR;
[3834]         }
[3835] 
[3836]         r->stream->cookies = cookies;
[3837]     }
[3838] 
[3839]     val = ngx_array_push(cookies);
[3840]     if (val == NULL) {
[3841]         return NGX_ERROR;
[3842]     }
[3843] 
[3844]     val->len = header->value.len;
[3845]     val->data = header->value.data;
[3846] 
[3847]     return NGX_OK;
[3848] }
[3849] 
[3850] 
[3851] static ngx_int_t
[3852] ngx_http_v2_construct_cookie_header(ngx_http_request_t *r)
[3853] {
[3854]     u_char                     *buf, *p, *end;
[3855]     size_t                      len;
[3856]     ngx_str_t                  *vals;
[3857]     ngx_uint_t                  i;
[3858]     ngx_array_t                *cookies;
[3859]     ngx_table_elt_t            *h;
[3860]     ngx_http_header_t          *hh;
[3861]     ngx_http_core_main_conf_t  *cmcf;
[3862] 
[3863]     static ngx_str_t cookie = ngx_string("cookie");
[3864] 
[3865]     cookies = r->stream->cookies;
[3866] 
[3867]     if (cookies == NULL) {
[3868]         return NGX_OK;
[3869]     }
[3870] 
[3871]     vals = cookies->elts;
[3872] 
[3873]     i = 0;
[3874]     len = 0;
[3875] 
[3876]     do {
[3877]         len += vals[i].len + 2;
[3878]     } while (++i != cookies->nelts);
[3879] 
[3880]     len -= 2;
[3881] 
[3882]     buf = ngx_pnalloc(r->pool, len + 1);
[3883]     if (buf == NULL) {
[3884]         ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3885]         return NGX_ERROR;
[3886]     }
[3887] 
[3888]     p = buf;
[3889]     end = buf + len;
[3890] 
[3891]     for (i = 0; /* void */ ; i++) {
[3892] 
[3893]         p = ngx_cpymem(p, vals[i].data, vals[i].len);
[3894] 
[3895]         if (p == end) {
[3896]             *p = '\0';
[3897]             break;
[3898]         }
[3899] 
[3900]         *p++ = ';'; *p++ = ' ';
[3901]     }
[3902] 
[3903]     h = ngx_list_push(&r->headers_in.headers);
[3904]     if (h == NULL) {
[3905]         ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3906]         return NGX_ERROR;
[3907]     }
[3908] 
[3909]     h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
[3910]                                     ngx_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');
[3911] 
[3912]     h->key.len = cookie.len;
[3913]     h->key.data = cookie.data;
[3914] 
[3915]     h->value.len = len;
[3916]     h->value.data = buf;
[3917] 
[3918]     h->lowcase_key = cookie.data;
[3919] 
[3920]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[3921] 
[3922]     hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
[3923]                        h->lowcase_key, h->key.len);
[3924] 
[3925]     if (hh == NULL) {
[3926]         ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
[3927]         return NGX_ERROR;
[3928]     }
[3929] 
[3930]     if (hh->handler(r, h, hh->offset) != NGX_OK) {
[3931]         /*
[3932]          * request has been finalized already
[3933]          * in ngx_http_process_multi_header_lines()
[3934]          */
[3935]         return NGX_ERROR;
[3936]     }
[3937] 
[3938]     return NGX_OK;
[3939] }
[3940] 
[3941] 
[3942] static void
[3943] ngx_http_v2_run_request(ngx_http_request_t *r)
[3944] {
[3945]     ngx_connection_t          *fc;
[3946]     ngx_http_v2_connection_t  *h2c;
[3947] 
[3948]     fc = r->connection;
[3949] 
[3950]     if (ngx_http_v2_construct_request_line(r) != NGX_OK) {
[3951]         goto failed;
[3952]     }
[3953] 
[3954]     if (ngx_http_v2_construct_cookie_header(r) != NGX_OK) {
[3955]         goto failed;
[3956]     }
[3957] 
[3958]     r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;
[3959] 
[3960]     if (ngx_http_process_request_header(r) != NGX_OK) {
[3961]         goto failed;
[3962]     }
[3963] 
[3964]     if (r->headers_in.content_length_n > 0 && r->stream->in_closed) {
[3965]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[3966]                       "client prematurely closed stream");
[3967] 
[3968]         r->stream->skip_data = 1;
[3969] 
[3970]         ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
[3971]         goto failed;
[3972]     }
[3973] 
[3974]     if (r->headers_in.content_length_n == -1 && !r->stream->in_closed) {
[3975]         r->headers_in.chunked = 1;
[3976]     }
[3977] 
[3978]     h2c = r->stream->connection;
[3979] 
[3980]     h2c->payload_bytes += r->request_length;
[3981] 
[3982]     ngx_http_process_request(r);
[3983] 
[3984] failed:
[3985] 
[3986]     ngx_http_run_posted_requests(fc);
[3987] }
[3988] 
[3989] 
[3990] static void
[3991] ngx_http_v2_run_request_handler(ngx_event_t *ev)
[3992] {
[3993]     ngx_connection_t    *fc;
[3994]     ngx_http_request_t  *r;
[3995] 
[3996]     fc = ev->data;
[3997]     r = fc->data;
[3998] 
[3999]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4000]                    "http2 run request handler");
[4001] 
[4002]     ngx_http_v2_run_request(r);
[4003] }
[4004] 
[4005] 
[4006] ngx_int_t
[4007] ngx_http_v2_read_request_body(ngx_http_request_t *r)
[4008] {
[4009]     off_t                      len;
[4010]     size_t                     size;
[4011]     ngx_buf_t                 *buf;
[4012]     ngx_int_t                  rc;
[4013]     ngx_http_v2_stream_t      *stream;
[4014]     ngx_http_v2_srv_conf_t    *h2scf;
[4015]     ngx_http_request_body_t   *rb;
[4016]     ngx_http_core_loc_conf_t  *clcf;
[4017]     ngx_http_v2_connection_t  *h2c;
[4018] 
[4019]     stream = r->stream;
[4020]     rb = r->request_body;
[4021] 
[4022]     if (stream->skip_data) {
[4023]         r->request_body_no_buffering = 0;
[4024]         rb->post_handler(r);
[4025]         return NGX_OK;
[4026]     }
[4027] 
[4028]     rb->rest = 1;
[4029] 
[4030]     /* set rb->filter_need_buffering */
[4031] 
[4032]     rc = ngx_http_top_request_body_filter(r, NULL);
[4033] 
[4034]     if (rc != NGX_OK) {
[4035]         stream->skip_data = 1;
[4036]         return rc;
[4037]     }
[4038] 
[4039]     h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);
[4040]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[4041] 
[4042]     len = r->headers_in.content_length_n;
[4043] 
[4044]     if (len < 0 || len > (off_t) clcf->client_body_buffer_size) {
[4045]         len = clcf->client_body_buffer_size;
[4046] 
[4047]     } else {
[4048]         len++;
[4049]     }
[4050] 
[4051]     if (r->request_body_no_buffering || rb->filter_need_buffering) {
[4052] 
[4053]         /*
[4054]          * We need a room to store data up to the stream's initial window size,
[4055]          * at least until this window will be exhausted.
[4056]          */
[4057] 
[4058]         if (len < (off_t) h2scf->preread_size) {
[4059]             len = h2scf->preread_size;
[4060]         }
[4061] 
[4062]         if (len > NGX_HTTP_V2_MAX_WINDOW) {
[4063]             len = NGX_HTTP_V2_MAX_WINDOW;
[4064]         }
[4065]     }
[4066] 
[4067]     rb->buf = ngx_create_temp_buf(r->pool, (size_t) len);
[4068] 
[4069]     if (rb->buf == NULL) {
[4070]         stream->skip_data = 1;
[4071]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4072]     }
[4073] 
[4074]     buf = stream->preread;
[4075] 
[4076]     if (stream->in_closed) {
[4077]         if (!rb->filter_need_buffering) {
[4078]             r->request_body_no_buffering = 0;
[4079]         }
[4080] 
[4081]         if (buf) {
[4082]             rc = ngx_http_v2_process_request_body(r, buf->pos,
[4083]                                                   buf->last - buf->pos, 1, 0);
[4084]             ngx_pfree(r->pool, buf->start);
[4085] 
[4086]         } else {
[4087]             rc = ngx_http_v2_process_request_body(r, NULL, 0, 1, 0);
[4088]         }
[4089] 
[4090]         if (rc != NGX_AGAIN) {
[4091]             return rc;
[4092]         }
[4093] 
[4094]         r->read_event_handler = ngx_http_v2_read_client_request_body_handler;
[4095]         r->write_event_handler = ngx_http_request_empty_handler;
[4096] 
[4097]         return NGX_AGAIN;
[4098]     }
[4099] 
[4100]     if (buf) {
[4101]         rc = ngx_http_v2_process_request_body(r, buf->pos,
[4102]                                               buf->last - buf->pos, 0, 0);
[4103] 
[4104]         ngx_pfree(r->pool, buf->start);
[4105] 
[4106]         if (rc != NGX_OK && rc != NGX_AGAIN) {
[4107]             stream->skip_data = 1;
[4108]             return rc;
[4109]         }
[4110]     }
[4111] 
[4112]     if (r->request_body_no_buffering || rb->filter_need_buffering) {
[4113]         size = (size_t) len - h2scf->preread_size;
[4114] 
[4115]     } else {
[4116]         stream->no_flow_control = 1;
[4117]         size = NGX_HTTP_V2_MAX_WINDOW - stream->recv_window;
[4118]     }
[4119] 
[4120]     if (size) {
[4121]         if (ngx_http_v2_send_window_update(stream->connection,
[4122]                                            stream->node->id, size)
[4123]             == NGX_ERROR)
[4124]         {
[4125]             stream->skip_data = 1;
[4126]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4127]         }
[4128] 
[4129]         h2c = stream->connection;
[4130] 
[4131]         if (!h2c->blocked) {
[4132]             if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
[4133]                 stream->skip_data = 1;
[4134]                 return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4135]             }
[4136]         }
[4137] 
[4138]         stream->recv_window += size;
[4139]     }
[4140] 
[4141]     if (!buf) {
[4142]         ngx_add_timer(r->connection->read, clcf->client_body_timeout);
[4143]     }
[4144] 
[4145]     r->read_event_handler = ngx_http_v2_read_client_request_body_handler;
[4146]     r->write_event_handler = ngx_http_request_empty_handler;
[4147] 
[4148]     return NGX_AGAIN;
[4149] }
[4150] 
[4151] 
[4152] static ngx_int_t
[4153] ngx_http_v2_process_request_body(ngx_http_request_t *r, u_char *pos,
[4154]     size_t size, ngx_uint_t last, ngx_uint_t flush)
[4155] {
[4156]     size_t                     n;
[4157]     ngx_int_t                  rc;
[4158]     ngx_connection_t          *fc;
[4159]     ngx_http_request_body_t   *rb;
[4160]     ngx_http_core_loc_conf_t  *clcf;
[4161] 
[4162]     fc = r->connection;
[4163]     rb = r->request_body;
[4164] 
[4165]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4166]                    "http2 process request body");
[4167] 
[4168]     if (size == 0 && !last && !flush) {
[4169]         return NGX_AGAIN;
[4170]     }
[4171] 
[4172]     for ( ;; ) {
[4173]         for ( ;; ) {
[4174]             if (rb->buf->last == rb->buf->end && size) {
[4175] 
[4176]                 if (r->request_body_no_buffering) {
[4177] 
[4178]                     /* should never happen due to flow control */
[4179] 
[4180]                     ngx_log_error(NGX_LOG_ALERT, fc->log, 0,
[4181]                                   "no space in http2 body buffer");
[4182] 
[4183]                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4184]                 }
[4185] 
[4186]                 /* update chains */
[4187] 
[4188]                 ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4189]                                "http2 body update chains");
[4190] 
[4191]                 rc = ngx_http_v2_filter_request_body(r);
[4192] 
[4193]                 if (rc != NGX_OK) {
[4194]                     return rc;
[4195]                 }
[4196] 
[4197]                 if (rb->busy != NULL) {
[4198]                     ngx_log_error(NGX_LOG_ALERT, fc->log, 0,
[4199]                                   "busy buffers after request body flush");
[4200]                     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4201]                 }
[4202] 
[4203]                 rb->buf->pos = rb->buf->start;
[4204]                 rb->buf->last = rb->buf->start;
[4205]             }
[4206] 
[4207]             /* copy body data to the buffer */
[4208] 
[4209]             n = rb->buf->end - rb->buf->last;
[4210] 
[4211]             if (n > size) {
[4212]                 n = size;
[4213]             }
[4214] 
[4215]             if (n > 0) {
[4216]                 rb->buf->last = ngx_cpymem(rb->buf->last, pos, n);
[4217]             }
[4218] 
[4219]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4220]                            "http2 request body recv %uz", n);
[4221] 
[4222]             pos += n;
[4223]             size -= n;
[4224] 
[4225]             if (size == 0 && last) {
[4226]                 rb->rest = 0;
[4227]             }
[4228] 
[4229]             if (size == 0) {
[4230]                 break;
[4231]             }
[4232]         }
[4233] 
[4234]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4235]                        "http2 request body rest %O", rb->rest);
[4236] 
[4237]         if (flush) {
[4238]             rc = ngx_http_v2_filter_request_body(r);
[4239] 
[4240]             if (rc != NGX_OK) {
[4241]                 return rc;
[4242]             }
[4243]         }
[4244] 
[4245]         if (rb->rest == 0 && rb->last_saved) {
[4246]             break;
[4247]         }
[4248] 
[4249]         if (size == 0) {
[4250]             clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[4251]             ngx_add_timer(fc->read, clcf->client_body_timeout);
[4252] 
[4253]             if (!flush) {
[4254]                 ngx_post_event(fc->read, &ngx_posted_events);
[4255]             }
[4256] 
[4257]             return NGX_AGAIN;
[4258]         }
[4259]     }
[4260] 
[4261]     if (fc->read->timer_set) {
[4262]         ngx_del_timer(fc->read);
[4263]     }
[4264] 
[4265]     if (r->request_body_no_buffering) {
[4266]         if (!flush) {
[4267]             ngx_post_event(fc->read, &ngx_posted_events);
[4268]         }
[4269] 
[4270]         return NGX_OK;
[4271]     }
[4272] 
[4273]     if (r->headers_in.chunked) {
[4274]         r->headers_in.content_length_n = rb->received;
[4275]     }
[4276] 
[4277]     r->read_event_handler = ngx_http_block_reading;
[4278]     rb->post_handler(r);
[4279] 
[4280]     return NGX_OK;
[4281] }
[4282] 
[4283] 
[4284] static ngx_int_t
[4285] ngx_http_v2_filter_request_body(ngx_http_request_t *r)
[4286] {
[4287]     ngx_buf_t                 *b, *buf;
[4288]     ngx_int_t                  rc;
[4289]     ngx_chain_t               *cl;
[4290]     ngx_http_request_body_t   *rb;
[4291]     ngx_http_core_loc_conf_t  *clcf;
[4292] 
[4293]     rb = r->request_body;
[4294]     buf = rb->buf;
[4295] 
[4296]     if (buf->pos == buf->last && (rb->rest || rb->last_sent)) {
[4297]         cl = NULL;
[4298]         goto update;
[4299]     }
[4300] 
[4301]     cl = ngx_chain_get_free_buf(r->pool, &rb->free);
[4302]     if (cl == NULL) {
[4303]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4304]     }
[4305] 
[4306]     b = cl->buf;
[4307] 
[4308]     ngx_memzero(b, sizeof(ngx_buf_t));
[4309] 
[4310]     if (buf->pos != buf->last) {
[4311]         r->request_length += buf->last - buf->pos;
[4312]         rb->received += buf->last - buf->pos;
[4313] 
[4314]         if (r->headers_in.content_length_n != -1) {
[4315]             if (rb->received > r->headers_in.content_length_n) {
[4316]                 ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[4317]                               "client intended to send body data "
[4318]                               "larger than declared");
[4319] 
[4320]                 return NGX_HTTP_BAD_REQUEST;
[4321]             }
[4322] 
[4323]         } else {
[4324]             clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[4325] 
[4326]             if (clcf->client_max_body_size
[4327]                 && rb->received > clcf->client_max_body_size)
[4328]             {
[4329]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[4330]                               "client intended to send too large chunked body: "
[4331]                               "%O bytes", rb->received);
[4332] 
[4333]                 return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
[4334]             }
[4335]         }
[4336] 
[4337]         b->temporary = 1;
[4338]         b->pos = buf->pos;
[4339]         b->last = buf->last;
[4340]         b->start = b->pos;
[4341]         b->end = b->last;
[4342] 
[4343]         buf->pos = buf->last;
[4344]     }
[4345] 
[4346]     if (!rb->rest) {
[4347]         if (r->headers_in.content_length_n != -1
[4348]             && r->headers_in.content_length_n != rb->received)
[4349]         {
[4350]             ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[4351]                           "client prematurely closed stream: "
[4352]                           "only %O out of %O bytes of request body received",
[4353]                           rb->received, r->headers_in.content_length_n);
[4354] 
[4355]             return NGX_HTTP_BAD_REQUEST;
[4356]         }
[4357] 
[4358]         b->last_buf = 1;
[4359]         rb->last_sent = 1;
[4360]     }
[4361] 
[4362]     b->tag = (ngx_buf_tag_t) &ngx_http_v2_filter_request_body;
[4363]     b->flush = r->request_body_no_buffering;
[4364] 
[4365] update:
[4366] 
[4367]     rc = ngx_http_top_request_body_filter(r, cl);
[4368] 
[4369]     ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &cl,
[4370]                             (ngx_buf_tag_t) &ngx_http_v2_filter_request_body);
[4371] 
[4372]     return rc;
[4373] }
[4374] 
[4375] 
[4376] static void
[4377] ngx_http_v2_read_client_request_body_handler(ngx_http_request_t *r)
[4378] {
[4379]     size_t                     window;
[4380]     ngx_buf_t                 *buf;
[4381]     ngx_int_t                  rc;
[4382]     ngx_connection_t          *fc;
[4383]     ngx_http_v2_stream_t      *stream;
[4384]     ngx_http_v2_connection_t  *h2c;
[4385] 
[4386]     fc = r->connection;
[4387] 
[4388]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4389]                    "http2 read client request body handler");
[4390] 
[4391]     if (fc->read->timedout) {
[4392]         ngx_log_error(NGX_LOG_INFO, fc->log, NGX_ETIMEDOUT, "client timed out");
[4393] 
[4394]         fc->timedout = 1;
[4395]         r->stream->skip_data = 1;
[4396] 
[4397]         ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
[4398]         return;
[4399]     }
[4400] 
[4401]     if (fc->error) {
[4402]         ngx_log_error(NGX_LOG_INFO, fc->log, 0,
[4403]                       "client prematurely closed stream");
[4404] 
[4405]         r->stream->skip_data = 1;
[4406] 
[4407]         ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
[4408]         return;
[4409]     }
[4410] 
[4411]     rc = ngx_http_v2_process_request_body(r, NULL, 0, r->stream->in_closed, 1);
[4412] 
[4413]     if (rc != NGX_OK && rc != NGX_AGAIN) {
[4414]         r->stream->skip_data = 1;
[4415]         ngx_http_finalize_request(r, rc);
[4416]         return;
[4417]     }
[4418] 
[4419]     if (rc == NGX_OK) {
[4420]         return;
[4421]     }
[4422] 
[4423]     if (r->stream->no_flow_control) {
[4424]         return;
[4425]     }
[4426] 
[4427]     if (r->request_body->rest == 0) {
[4428]         return;
[4429]     }
[4430] 
[4431]     if (r->request_body->busy != NULL) {
[4432]         return;
[4433]     }
[4434] 
[4435]     stream = r->stream;
[4436]     h2c = stream->connection;
[4437] 
[4438]     buf = r->request_body->buf;
[4439] 
[4440]     buf->pos = buf->start;
[4441]     buf->last = buf->start;
[4442] 
[4443]     window = buf->end - buf->start;
[4444] 
[4445]     if (h2c->state.stream == stream) {
[4446]         window -= h2c->state.length;
[4447]     }
[4448] 
[4449]     if (window <= stream->recv_window) {
[4450]         if (window < stream->recv_window) {
[4451]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[4452]                           "http2 negative window update");
[4453] 
[4454]             stream->skip_data = 1;
[4455] 
[4456]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[4457]             return;
[4458]         }
[4459] 
[4460]         return;
[4461]     }
[4462] 
[4463]     if (ngx_http_v2_send_window_update(h2c, stream->node->id,
[4464]                                        window - stream->recv_window)
[4465]         == NGX_ERROR)
[4466]     {
[4467]         stream->skip_data = 1;
[4468]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[4469]         return;
[4470]     }
[4471] 
[4472]     stream->recv_window = window;
[4473] 
[4474]     if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
[4475]         stream->skip_data = 1;
[4476]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[4477]         return;
[4478]     }
[4479] }
[4480] 
[4481] 
[4482] ngx_int_t
[4483] ngx_http_v2_read_unbuffered_request_body(ngx_http_request_t *r)
[4484] {
[4485]     size_t                     window;
[4486]     ngx_buf_t                 *buf;
[4487]     ngx_int_t                  rc;
[4488]     ngx_connection_t          *fc;
[4489]     ngx_http_v2_stream_t      *stream;
[4490]     ngx_http_v2_connection_t  *h2c;
[4491] 
[4492]     stream = r->stream;
[4493]     fc = r->connection;
[4494] 
[4495]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4496]                    "http2 read unbuffered request body");
[4497] 
[4498]     if (fc->read->timedout) {
[4499]         if (stream->recv_window) {
[4500]             stream->skip_data = 1;
[4501]             fc->timedout = 1;
[4502] 
[4503]             return NGX_HTTP_REQUEST_TIME_OUT;
[4504]         }
[4505] 
[4506]         fc->read->timedout = 0;
[4507]     }
[4508] 
[4509]     if (fc->error) {
[4510]         stream->skip_data = 1;
[4511]         return NGX_HTTP_BAD_REQUEST;
[4512]     }
[4513] 
[4514]     rc = ngx_http_v2_process_request_body(r, NULL, 0, r->stream->in_closed, 1);
[4515] 
[4516]     if (rc != NGX_OK && rc != NGX_AGAIN) {
[4517]         stream->skip_data = 1;
[4518]         return rc;
[4519]     }
[4520] 
[4521]     if (rc == NGX_OK) {
[4522]         return NGX_OK;
[4523]     }
[4524] 
[4525]     if (r->request_body->rest == 0) {
[4526]         return NGX_AGAIN;
[4527]     }
[4528] 
[4529]     if (r->request_body->busy != NULL) {
[4530]         return NGX_AGAIN;
[4531]     }
[4532] 
[4533]     buf = r->request_body->buf;
[4534] 
[4535]     buf->pos = buf->start;
[4536]     buf->last = buf->start;
[4537] 
[4538]     window = buf->end - buf->start;
[4539]     h2c = stream->connection;
[4540] 
[4541]     if (h2c->state.stream == stream) {
[4542]         window -= h2c->state.length;
[4543]     }
[4544] 
[4545]     if (window <= stream->recv_window) {
[4546]         if (window < stream->recv_window) {
[4547]             ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
[4548]                           "http2 negative window update");
[4549]             stream->skip_data = 1;
[4550]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4551]         }
[4552] 
[4553]         return NGX_AGAIN;
[4554]     }
[4555] 
[4556]     if (ngx_http_v2_send_window_update(h2c, stream->node->id,
[4557]                                        window - stream->recv_window)
[4558]         == NGX_ERROR)
[4559]     {
[4560]         stream->skip_data = 1;
[4561]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4562]     }
[4563] 
[4564]     if (ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
[4565]         stream->skip_data = 1;
[4566]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[4567]     }
[4568] 
[4569]     stream->recv_window = window;
[4570] 
[4571]     return NGX_AGAIN;
[4572] }
[4573] 
[4574] 
[4575] static ngx_int_t
[4576] ngx_http_v2_terminate_stream(ngx_http_v2_connection_t *h2c,
[4577]     ngx_http_v2_stream_t *stream, ngx_uint_t status)
[4578] {
[4579]     ngx_event_t       *rev;
[4580]     ngx_connection_t  *fc;
[4581] 
[4582]     if (stream->rst_sent) {
[4583]         return NGX_OK;
[4584]     }
[4585] 
[4586]     if (ngx_http_v2_send_rst_stream(h2c, stream->node->id, status)
[4587]         == NGX_ERROR)
[4588]     {
[4589]         return NGX_ERROR;
[4590]     }
[4591] 
[4592]     stream->rst_sent = 1;
[4593]     stream->skip_data = 1;
[4594] 
[4595]     fc = stream->request->connection;
[4596]     fc->error = 1;
[4597] 
[4598]     rev = fc->read;
[4599]     rev->handler(rev);
[4600] 
[4601]     return NGX_OK;
[4602] }
[4603] 
[4604] 
[4605] void
[4606] ngx_http_v2_close_stream(ngx_http_v2_stream_t *stream, ngx_int_t rc)
[4607] {
[4608]     ngx_pool_t                *pool;
[4609]     ngx_uint_t                 push;
[4610]     ngx_event_t               *ev;
[4611]     ngx_connection_t          *fc;
[4612]     ngx_http_v2_node_t        *node;
[4613]     ngx_http_v2_connection_t  *h2c;
[4614] 
[4615]     h2c = stream->connection;
[4616]     node = stream->node;
[4617] 
[4618]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[4619]                    "http2 close stream %ui, queued %ui, "
[4620]                    "processing %ui, pushing %ui",
[4621]                    node->id, stream->queued, h2c->processing, h2c->pushing);
[4622] 
[4623]     fc = stream->request->connection;
[4624] 
[4625]     if (stream->queued) {
[4626]         fc->error = 1;
[4627]         fc->write->handler = ngx_http_v2_retry_close_stream_handler;
[4628]         fc->read->handler = ngx_http_v2_retry_close_stream_handler;
[4629]         return;
[4630]     }
[4631] 
[4632]     if (!stream->rst_sent && !h2c->connection->error) {
[4633] 
[4634]         if (!stream->out_closed) {
[4635]             if (ngx_http_v2_send_rst_stream(h2c, node->id,
[4636]                                       fc->timedout ? NGX_HTTP_V2_PROTOCOL_ERROR
[4637]                                                    : NGX_HTTP_V2_INTERNAL_ERROR)
[4638]                 != NGX_OK)
[4639]             {
[4640]                 h2c->connection->error = 1;
[4641]             }
[4642] 
[4643]         } else if (!stream->in_closed) {
[4644]             if (ngx_http_v2_send_rst_stream(h2c, node->id, NGX_HTTP_V2_NO_ERROR)
[4645]                 != NGX_OK)
[4646]             {
[4647]                 h2c->connection->error = 1;
[4648]             }
[4649]         }
[4650]     }
[4651] 
[4652]     if (h2c->state.stream == stream) {
[4653]         h2c->state.stream = NULL;
[4654]     }
[4655] 
[4656]     push = stream->node->id % 2 == 0;
[4657] 
[4658]     node->stream = NULL;
[4659] 
[4660]     ngx_queue_insert_tail(&h2c->closed, &node->reuse);
[4661]     h2c->closed_nodes++;
[4662] 
[4663]     /*
[4664]      * This pool keeps decoded request headers which can be used by log phase
[4665]      * handlers in ngx_http_free_request().
[4666]      *
[4667]      * The pointer is stored into local variable because the stream object
[4668]      * will be destroyed after a call to ngx_http_free_request().
[4669]      */
[4670]     pool = stream->pool;
[4671] 
[4672]     h2c->frames -= stream->frames;
[4673] 
[4674]     ngx_http_free_request(stream->request, rc);
[4675] 
[4676]     if (pool != h2c->state.pool) {
[4677]         ngx_destroy_pool(pool);
[4678] 
[4679]     } else {
[4680]         /* pool will be destroyed when the complete header is parsed */
[4681]         h2c->state.keep_pool = 0;
[4682]     }
[4683] 
[4684]     ev = fc->read;
[4685] 
[4686]     if (ev->timer_set) {
[4687]         ngx_del_timer(ev);
[4688]     }
[4689] 
[4690]     if (ev->posted) {
[4691]         ngx_delete_posted_event(ev);
[4692]     }
[4693] 
[4694]     ev = fc->write;
[4695] 
[4696]     if (ev->timer_set) {
[4697]         ngx_del_timer(ev);
[4698]     }
[4699] 
[4700]     if (ev->posted) {
[4701]         ngx_delete_posted_event(ev);
[4702]     }
[4703] 
[4704]     fc->data = h2c->free_fake_connections;
[4705]     h2c->free_fake_connections = fc;
[4706] 
[4707]     if (push) {
[4708]         h2c->pushing--;
[4709] 
[4710]     } else {
[4711]         h2c->processing--;
[4712]     }
[4713] 
[4714]     if (h2c->processing || h2c->pushing || h2c->blocked) {
[4715]         return;
[4716]     }
[4717] 
[4718]     ev = h2c->connection->read;
[4719] 
[4720]     ev->handler = ngx_http_v2_handle_connection_handler;
[4721]     ngx_post_event(ev, &ngx_posted_events);
[4722] }
[4723] 
[4724] 
[4725] static void
[4726] ngx_http_v2_close_stream_handler(ngx_event_t *ev)
[4727] {
[4728]     ngx_connection_t    *fc;
[4729]     ngx_http_request_t  *r;
[4730] 
[4731]     fc = ev->data;
[4732]     r = fc->data;
[4733] 
[4734]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4735]                    "http2 close stream handler");
[4736] 
[4737]     if (ev->timedout) {
[4738]         ngx_log_error(NGX_LOG_INFO, fc->log, NGX_ETIMEDOUT, "client timed out");
[4739] 
[4740]         fc->timedout = 1;
[4741] 
[4742]         ngx_http_v2_close_stream(r->stream, NGX_HTTP_REQUEST_TIME_OUT);
[4743]         return;
[4744]     }
[4745] 
[4746]     ngx_http_v2_close_stream(r->stream, 0);
[4747] }
[4748] 
[4749] 
[4750] static void
[4751] ngx_http_v2_retry_close_stream_handler(ngx_event_t *ev)
[4752] {
[4753]     ngx_connection_t    *fc;
[4754]     ngx_http_request_t  *r;
[4755] 
[4756]     fc = ev->data;
[4757]     r = fc->data;
[4758] 
[4759]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
[4760]                    "http2 retry close stream handler");
[4761] 
[4762]     ngx_http_v2_close_stream(r->stream, 0);
[4763] }
[4764] 
[4765] 
[4766] static void
[4767] ngx_http_v2_handle_connection_handler(ngx_event_t *rev)
[4768] {
[4769]     ngx_connection_t          *c;
[4770]     ngx_http_v2_connection_t  *h2c;
[4771] 
[4772]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
[4773]                    "http2 handle connection handler");
[4774] 
[4775]     c = rev->data;
[4776]     h2c = c->data;
[4777] 
[4778]     if (c->error) {
[4779]         ngx_http_v2_finalize_connection(h2c, 0);
[4780]         return;
[4781]     }
[4782] 
[4783]     rev->handler = ngx_http_v2_read_handler;
[4784] 
[4785]     if (rev->ready) {
[4786]         ngx_http_v2_read_handler(rev);
[4787]         return;
[4788]     }
[4789] 
[4790]     if (h2c->last_out && ngx_http_v2_send_output_queue(h2c) == NGX_ERROR) {
[4791]         ngx_http_v2_finalize_connection(h2c, 0);
[4792]         return;
[4793]     }
[4794] 
[4795]     ngx_http_v2_handle_connection(c->data);
[4796] }
[4797] 
[4798] 
[4799] static void
[4800] ngx_http_v2_idle_handler(ngx_event_t *rev)
[4801] {
[4802]     ngx_connection_t          *c;
[4803]     ngx_http_v2_srv_conf_t    *h2scf;
[4804]     ngx_http_v2_connection_t  *h2c;
[4805]     ngx_http_core_loc_conf_t  *clcf;
[4806] 
[4807]     c = rev->data;
[4808]     h2c = c->data;
[4809] 
[4810]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http2 idle handler");
[4811] 
[4812]     if (rev->timedout || c->close) {
[4813]         ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
[4814]         return;
[4815]     }
[4816] 
[4817] #if (NGX_HAVE_KQUEUE)
[4818] 
[4819]     if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
[4820]         if (rev->pending_eof) {
[4821]             c->log->handler = NULL;
[4822]             ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
[4823]                           "kevent() reported that client %V closed "
[4824]                           "idle connection", &c->addr_text);
[4825] #if (NGX_HTTP_SSL)
[4826]             if (c->ssl) {
[4827]                 c->ssl->no_send_shutdown = 1;
[4828]             }
[4829] #endif
[4830]             ngx_http_close_connection(c);
[4831]             return;
[4832]         }
[4833]     }
[4834] 
[4835] #endif
[4836] 
[4837]     clcf = ngx_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
[4838]                                         ngx_http_core_module);
[4839] 
[4840]     if (h2c->idle++ > 10 * clcf->keepalive_requests) {
[4841]         ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
[4842]                       "http2 flood detected");
[4843]         ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
[4844]         return;
[4845]     }
[4846] 
[4847]     c->destroyed = 0;
[4848]     ngx_reusable_connection(c, 0);
[4849] 
[4850]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[4851]                                          ngx_http_v2_module);
[4852] 
[4853]     h2c->pool = ngx_create_pool(h2scf->pool_size, h2c->connection->log);
[4854]     if (h2c->pool == NULL) {
[4855]         ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
[4856]         return;
[4857]     }
[4858] 
[4859]     c->write->handler = ngx_http_v2_write_handler;
[4860] 
[4861]     rev->handler = ngx_http_v2_read_handler;
[4862]     ngx_http_v2_read_handler(rev);
[4863] }
[4864] 
[4865] 
[4866] static void
[4867] ngx_http_v2_finalize_connection(ngx_http_v2_connection_t *h2c,
[4868]     ngx_uint_t status)
[4869] {
[4870]     ngx_uint_t               i, size;
[4871]     ngx_event_t             *ev;
[4872]     ngx_connection_t        *c, *fc;
[4873]     ngx_http_request_t      *r;
[4874]     ngx_http_v2_node_t      *node;
[4875]     ngx_http_v2_stream_t    *stream;
[4876]     ngx_http_v2_srv_conf_t  *h2scf;
[4877] 
[4878]     c = h2c->connection;
[4879] 
[4880]     h2c->blocked = 1;
[4881] 
[4882]     if (!c->error && !h2c->goaway) {
[4883]         h2c->goaway = 1;
[4884] 
[4885]         if (ngx_http_v2_send_goaway(h2c, status) != NGX_ERROR) {
[4886]             (void) ngx_http_v2_send_output_queue(h2c);
[4887]         }
[4888]     }
[4889] 
[4890]     if (!h2c->processing && !h2c->pushing) {
[4891]         goto done;
[4892]     }
[4893] 
[4894]     c->read->handler = ngx_http_empty_handler;
[4895]     c->write->handler = ngx_http_empty_handler;
[4896] 
[4897]     h2c->last_out = NULL;
[4898] 
[4899]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[4900]                                          ngx_http_v2_module);
[4901] 
[4902]     size = ngx_http_v2_index_size(h2scf);
[4903] 
[4904]     for (i = 0; i < size; i++) {
[4905] 
[4906]         for (node = h2c->streams_index[i]; node; node = node->index) {
[4907]             stream = node->stream;
[4908] 
[4909]             if (stream == NULL) {
[4910]                 continue;
[4911]             }
[4912] 
[4913]             stream->waiting = 0;
[4914] 
[4915]             r = stream->request;
[4916]             fc = r->connection;
[4917] 
[4918]             fc->error = 1;
[4919] 
[4920]             if (stream->queued) {
[4921]                 stream->queued = 0;
[4922] 
[4923]                 ev = fc->write;
[4924]                 ev->active = 0;
[4925]                 ev->ready = 1;
[4926] 
[4927]             } else {
[4928]                 ev = fc->read;
[4929]             }
[4930] 
[4931]             ev->eof = 1;
[4932]             ev->handler(ev);
[4933]         }
[4934]     }
[4935] 
[4936]     h2c->blocked = 0;
[4937] 
[4938]     if (h2c->processing || h2c->pushing) {
[4939]         c->error = 1;
[4940]         return;
[4941]     }
[4942] 
[4943] done:
[4944] 
[4945]     if (c->error) {
[4946]         ngx_http_close_connection(c);
[4947]         return;
[4948]     }
[4949] 
[4950]     ngx_http_v2_lingering_close(c);
[4951] }
[4952] 
[4953] 
[4954] static ngx_int_t
[4955] ngx_http_v2_adjust_windows(ngx_http_v2_connection_t *h2c, ssize_t delta)
[4956] {
[4957]     ngx_uint_t               i, size;
[4958]     ngx_event_t             *wev;
[4959]     ngx_http_v2_node_t      *node;
[4960]     ngx_http_v2_stream_t    *stream;
[4961]     ngx_http_v2_srv_conf_t  *h2scf;
[4962] 
[4963]     h2scf = ngx_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
[4964]                                          ngx_http_v2_module);
[4965] 
[4966]     size = ngx_http_v2_index_size(h2scf);
[4967] 
[4968]     for (i = 0; i < size; i++) {
[4969] 
[4970]         for (node = h2c->streams_index[i]; node; node = node->index) {
[4971]             stream = node->stream;
[4972] 
[4973]             if (stream == NULL) {
[4974]                 continue;
[4975]             }
[4976] 
[4977]             if (delta > 0
[4978]                 && stream->send_window
[4979]                       > (ssize_t) (NGX_HTTP_V2_MAX_WINDOW - delta))
[4980]             {
[4981]                 if (ngx_http_v2_terminate_stream(h2c, stream,
[4982]                                                  NGX_HTTP_V2_FLOW_CTRL_ERROR)
[4983]                     == NGX_ERROR)
[4984]                 {
[4985]                     return NGX_ERROR;
[4986]                 }
[4987] 
[4988]                 continue;
[4989]             }
[4990] 
[4991]             stream->send_window += delta;
[4992] 
[4993]             ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
[4994]                            "http2:%ui adjusted window: %z",
[4995]                            node->id, stream->send_window);
[4996] 
[4997]             if (stream->send_window > 0 && stream->exhausted) {
[4998]                 stream->exhausted = 0;
[4999] 
[5000]                 wev = stream->request->connection->write;
[5001] 
[5002]                 wev->active = 0;
[5003]                 wev->ready = 1;
[5004] 
[5005]                 if (!wev->delayed) {
[5006]                     wev->handler(wev);
[5007]                 }
[5008]             }
[5009]         }
[5010]     }
[5011] 
[5012]     return NGX_OK;
[5013] }
[5014] 
[5015] 
[5016] static void
[5017] ngx_http_v2_set_dependency(ngx_http_v2_connection_t *h2c,
[5018]     ngx_http_v2_node_t *node, ngx_uint_t depend, ngx_uint_t exclusive)
[5019] {
[5020]     ngx_queue_t         *children, *q;
[5021]     ngx_http_v2_node_t  *parent, *child, *next;
[5022] 
[5023]     parent = depend ? ngx_http_v2_get_node_by_id(h2c, depend, 0) : NULL;
[5024] 
[5025]     if (parent == NULL) {
[5026]         parent = NGX_HTTP_V2_ROOT;
[5027] 
[5028]         if (depend != 0) {
[5029]             exclusive = 0;
[5030]         }
[5031] 
[5032]         node->rank = 1;
[5033]         node->rel_weight = (1.0 / 256) * node->weight;
[5034] 
[5035]         children = &h2c->dependencies;
[5036] 
[5037]     } else {
[5038]         if (node->parent != NULL) {
[5039] 
[5040]             for (next = parent->parent;
[5041]                  next != NGX_HTTP_V2_ROOT && next->rank >= node->rank;
[5042]                  next = next->parent)
[5043]             {
[5044]                 if (next != node) {
[5045]                     continue;
[5046]                 }
[5047] 
[5048]                 ngx_queue_remove(&parent->queue);
[5049]                 ngx_queue_insert_after(&node->queue, &parent->queue);
[5050] 
[5051]                 parent->parent = node->parent;
[5052] 
[5053]                 if (node->parent == NGX_HTTP_V2_ROOT) {
[5054]                     parent->rank = 1;
[5055]                     parent->rel_weight = (1.0 / 256) * parent->weight;
[5056] 
[5057]                 } else {
[5058]                     parent->rank = node->parent->rank + 1;
[5059]                     parent->rel_weight = (node->parent->rel_weight / 256)
[5060]                                          * parent->weight;
[5061]                 }
[5062] 
[5063]                 if (!exclusive) {
[5064]                     ngx_http_v2_node_children_update(parent);
[5065]                 }
[5066] 
[5067]                 break;
[5068]             }
[5069]         }
[5070] 
[5071]         node->rank = parent->rank + 1;
[5072]         node->rel_weight = (parent->rel_weight / 256) * node->weight;
[5073] 
[5074]         if (parent->stream == NULL) {
[5075]             ngx_queue_remove(&parent->reuse);
[5076]             ngx_queue_insert_tail(&h2c->closed, &parent->reuse);
[5077]         }
[5078] 
[5079]         children = &parent->children;
[5080]     }
[5081] 
[5082]     if (exclusive) {
[5083]         for (q = ngx_queue_head(children);
[5084]              q != ngx_queue_sentinel(children);
[5085]              q = ngx_queue_next(q))
[5086]         {
[5087]             child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
[5088]             child->parent = node;
[5089]         }
[5090] 
[5091]         ngx_queue_add(&node->children, children);
[5092]         ngx_queue_init(children);
[5093]     }
[5094] 
[5095]     if (node->parent != NULL) {
[5096]         ngx_queue_remove(&node->queue);
[5097]     }
[5098] 
[5099]     ngx_queue_insert_tail(children, &node->queue);
[5100] 
[5101]     node->parent = parent;
[5102] 
[5103]     ngx_http_v2_node_children_update(node);
[5104] }
[5105] 
[5106] 
[5107] static void
[5108] ngx_http_v2_node_children_update(ngx_http_v2_node_t *node)
[5109] {
[5110]     ngx_queue_t         *q;
[5111]     ngx_http_v2_node_t  *child;
[5112] 
[5113]     for (q = ngx_queue_head(&node->children);
[5114]          q != ngx_queue_sentinel(&node->children);
[5115]          q = ngx_queue_next(q))
[5116]     {
[5117]         child = ngx_queue_data(q, ngx_http_v2_node_t, queue);
[5118] 
[5119]         child->rank = node->rank + 1;
[5120]         child->rel_weight = (node->rel_weight / 256) * child->weight;
[5121] 
[5122]         ngx_http_v2_node_children_update(child);
[5123]     }
[5124] }
[5125] 
[5126] 
[5127] static void
[5128] ngx_http_v2_pool_cleanup(void *data)
[5129] {
[5130]     ngx_http_v2_connection_t  *h2c = data;
[5131] 
[5132]     if (h2c->state.pool) {
[5133]         ngx_destroy_pool(h2c->state.pool);
[5134]     }
[5135] 
[5136]     if (h2c->pool) {
[5137]         ngx_destroy_pool(h2c->pool);
[5138]     }
[5139] }
