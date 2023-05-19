[1] /*
[2]  * Copyright (C) Nginx, Inc.
[3]  * Copyright (C) Valentin V. Bartenev
[4]  */
[5] 
[6] 
[7] #ifndef _NGX_HTTP_V2_H_INCLUDED_
[8] #define _NGX_HTTP_V2_H_INCLUDED_
[9] 
[10] 
[11] #include <ngx_config.h>
[12] #include <ngx_core.h>
[13] #include <ngx_http.h>
[14] 
[15] 
[16] #define NGX_HTTP_V2_ALPN_PROTO           "\x02h2"
[17] 
[18] #define NGX_HTTP_V2_STATE_BUFFER_SIZE    16
[19] 
[20] #define NGX_HTTP_V2_DEFAULT_FRAME_SIZE   (1 << 14)
[21] #define NGX_HTTP_V2_MAX_FRAME_SIZE       ((1 << 24) - 1)
[22] 
[23] #define NGX_HTTP_V2_INT_OCTETS           4
[24] #define NGX_HTTP_V2_MAX_FIELD                                                 \
[25]     (127 + (1 << (NGX_HTTP_V2_INT_OCTETS - 1) * 7) - 1)
[26] 
[27] #define NGX_HTTP_V2_STREAM_ID_SIZE       4
[28] 
[29] #define NGX_HTTP_V2_FRAME_HEADER_SIZE    9
[30] 
[31] /* frame types */
[32] #define NGX_HTTP_V2_DATA_FRAME           0x0
[33] #define NGX_HTTP_V2_HEADERS_FRAME        0x1
[34] #define NGX_HTTP_V2_PRIORITY_FRAME       0x2
[35] #define NGX_HTTP_V2_RST_STREAM_FRAME     0x3
[36] #define NGX_HTTP_V2_SETTINGS_FRAME       0x4
[37] #define NGX_HTTP_V2_PUSH_PROMISE_FRAME   0x5
[38] #define NGX_HTTP_V2_PING_FRAME           0x6
[39] #define NGX_HTTP_V2_GOAWAY_FRAME         0x7
[40] #define NGX_HTTP_V2_WINDOW_UPDATE_FRAME  0x8
[41] #define NGX_HTTP_V2_CONTINUATION_FRAME   0x9
[42] 
[43] /* frame flags */
[44] #define NGX_HTTP_V2_NO_FLAG              0x00
[45] #define NGX_HTTP_V2_ACK_FLAG             0x01
[46] #define NGX_HTTP_V2_END_STREAM_FLAG      0x01
[47] #define NGX_HTTP_V2_END_HEADERS_FLAG     0x04
[48] #define NGX_HTTP_V2_PADDED_FLAG          0x08
[49] #define NGX_HTTP_V2_PRIORITY_FLAG        0x20
[50] 
[51] #define NGX_HTTP_V2_MAX_WINDOW           ((1U << 31) - 1)
[52] #define NGX_HTTP_V2_DEFAULT_WINDOW       65535
[53] 
[54] #define NGX_HTTP_V2_DEFAULT_WEIGHT       16
[55] 
[56] 
[57] typedef struct ngx_http_v2_connection_s   ngx_http_v2_connection_t;
[58] typedef struct ngx_http_v2_node_s         ngx_http_v2_node_t;
[59] typedef struct ngx_http_v2_out_frame_s    ngx_http_v2_out_frame_t;
[60] 
[61] 
[62] typedef u_char *(*ngx_http_v2_handler_pt) (ngx_http_v2_connection_t *h2c,
[63]     u_char *pos, u_char *end);
[64] 
[65] 
[66] typedef struct {
[67]     ngx_str_t                        name;
[68]     ngx_str_t                        value;
[69] } ngx_http_v2_header_t;
[70] 
[71] 
[72] typedef struct {
[73]     ngx_uint_t                       sid;
[74]     size_t                           length;
[75]     size_t                           padding;
[76]     unsigned                         flags:8;
[77] 
[78]     unsigned                         incomplete:1;
[79]     unsigned                         keep_pool:1;
[80] 
[81]     /* HPACK */
[82]     unsigned                         parse_name:1;
[83]     unsigned                         parse_value:1;
[84]     unsigned                         index:1;
[85]     ngx_http_v2_header_t             header;
[86]     size_t                           header_limit;
[87]     u_char                           field_state;
[88]     u_char                          *field_start;
[89]     u_char                          *field_end;
[90]     size_t                           field_rest;
[91]     ngx_pool_t                      *pool;
[92] 
[93]     ngx_http_v2_stream_t            *stream;
[94] 
[95]     u_char                           buffer[NGX_HTTP_V2_STATE_BUFFER_SIZE];
[96]     size_t                           buffer_used;
[97]     ngx_http_v2_handler_pt           handler;
[98] } ngx_http_v2_state_t;
[99] 
[100] 
[101] 
[102] typedef struct {
[103]     ngx_http_v2_header_t           **entries;
[104] 
[105]     ngx_uint_t                       added;
[106]     ngx_uint_t                       deleted;
[107]     ngx_uint_t                       reused;
[108]     ngx_uint_t                       allocated;
[109] 
[110]     size_t                           size;
[111]     size_t                           free;
[112]     u_char                          *storage;
[113]     u_char                          *pos;
[114] } ngx_http_v2_hpack_t;
[115] 
[116] 
[117] struct ngx_http_v2_connection_s {
[118]     ngx_connection_t                *connection;
[119]     ngx_http_connection_t           *http_connection;
[120] 
[121]     off_t                            total_bytes;
[122]     off_t                            payload_bytes;
[123] 
[124]     ngx_uint_t                       processing;
[125]     ngx_uint_t                       frames;
[126]     ngx_uint_t                       idle;
[127]     ngx_uint_t                       priority_limit;
[128] 
[129]     ngx_uint_t                       pushing;
[130]     ngx_uint_t                       concurrent_pushes;
[131] 
[132]     size_t                           send_window;
[133]     size_t                           recv_window;
[134]     size_t                           init_window;
[135] 
[136]     size_t                           frame_size;
[137] 
[138]     ngx_queue_t                      waiting;
[139] 
[140]     ngx_http_v2_state_t              state;
[141] 
[142]     ngx_http_v2_hpack_t              hpack;
[143] 
[144]     ngx_pool_t                      *pool;
[145] 
[146]     ngx_http_v2_out_frame_t         *free_frames;
[147]     ngx_connection_t                *free_fake_connections;
[148] 
[149]     ngx_http_v2_node_t             **streams_index;
[150] 
[151]     ngx_http_v2_out_frame_t         *last_out;
[152] 
[153]     ngx_queue_t                      dependencies;
[154]     ngx_queue_t                      closed;
[155] 
[156]     ngx_uint_t                       closed_nodes;
[157]     ngx_uint_t                       last_sid;
[158]     ngx_uint_t                       last_push;
[159] 
[160]     time_t                           lingering_time;
[161] 
[162]     unsigned                         settings_ack:1;
[163]     unsigned                         table_update:1;
[164]     unsigned                         blocked:1;
[165]     unsigned                         goaway:1;
[166]     unsigned                         push_disabled:1;
[167] };
[168] 
[169] 
[170] struct ngx_http_v2_node_s {
[171]     ngx_uint_t                       id;
[172]     ngx_http_v2_node_t              *index;
[173]     ngx_http_v2_node_t              *parent;
[174]     ngx_queue_t                      queue;
[175]     ngx_queue_t                      children;
[176]     ngx_queue_t                      reuse;
[177]     ngx_uint_t                       rank;
[178]     ngx_uint_t                       weight;
[179]     double                           rel_weight;
[180]     ngx_http_v2_stream_t            *stream;
[181] };
[182] 
[183] 
[184] struct ngx_http_v2_stream_s {
[185]     ngx_http_request_t              *request;
[186]     ngx_http_v2_connection_t        *connection;
[187]     ngx_http_v2_node_t              *node;
[188] 
[189]     ngx_uint_t                       queued;
[190] 
[191]     /*
[192]      * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
[193]      * send_window to become negative, hence it's signed.
[194]      */
[195]     ssize_t                          send_window;
[196]     size_t                           recv_window;
[197] 
[198]     ngx_buf_t                       *preread;
[199] 
[200]     ngx_uint_t                       frames;
[201] 
[202]     ngx_http_v2_out_frame_t         *free_frames;
[203]     ngx_chain_t                     *free_frame_headers;
[204]     ngx_chain_t                     *free_bufs;
[205] 
[206]     ngx_queue_t                      queue;
[207] 
[208]     ngx_array_t                     *cookies;
[209] 
[210]     ngx_pool_t                      *pool;
[211] 
[212]     unsigned                         waiting:1;
[213]     unsigned                         blocked:1;
[214]     unsigned                         exhausted:1;
[215]     unsigned                         in_closed:1;
[216]     unsigned                         out_closed:1;
[217]     unsigned                         rst_sent:1;
[218]     unsigned                         no_flow_control:1;
[219]     unsigned                         skip_data:1;
[220] };
[221] 
[222] 
[223] struct ngx_http_v2_out_frame_s {
[224]     ngx_http_v2_out_frame_t         *next;
[225]     ngx_chain_t                     *first;
[226]     ngx_chain_t                     *last;
[227]     ngx_int_t                      (*handler)(ngx_http_v2_connection_t *h2c,
[228]                                         ngx_http_v2_out_frame_t *frame);
[229] 
[230]     ngx_http_v2_stream_t            *stream;
[231]     size_t                           length;
[232] 
[233]     unsigned                         blocked:1;
[234]     unsigned                         fin:1;
[235] };
[236] 
[237] 
[238] static ngx_inline void
[239] ngx_http_v2_queue_frame(ngx_http_v2_connection_t *h2c,
[240]     ngx_http_v2_out_frame_t *frame)
[241] {
[242]     ngx_http_v2_out_frame_t  **out;
[243] 
[244]     for (out = &h2c->last_out; *out; out = &(*out)->next) {
[245] 
[246]         if ((*out)->blocked || (*out)->stream == NULL) {
[247]             break;
[248]         }
[249] 
[250]         if ((*out)->stream->node->rank < frame->stream->node->rank
[251]             || ((*out)->stream->node->rank == frame->stream->node->rank
[252]                 && (*out)->stream->node->rel_weight
[253]                    >= frame->stream->node->rel_weight))
[254]         {
[255]             break;
[256]         }
[257]     }
[258] 
[259]     frame->next = *out;
[260]     *out = frame;
[261] }
[262] 
[263] 
[264] static ngx_inline void
[265] ngx_http_v2_queue_blocked_frame(ngx_http_v2_connection_t *h2c,
[266]     ngx_http_v2_out_frame_t *frame)
[267] {
[268]     ngx_http_v2_out_frame_t  **out;
[269] 
[270]     for (out = &h2c->last_out; *out; out = &(*out)->next) {
[271] 
[272]         if ((*out)->blocked || (*out)->stream == NULL) {
[273]             break;
[274]         }
[275]     }
[276] 
[277]     frame->next = *out;
[278]     *out = frame;
[279] }
[280] 
[281] 
[282] static ngx_inline void
[283] ngx_http_v2_queue_ordered_frame(ngx_http_v2_connection_t *h2c,
[284]     ngx_http_v2_out_frame_t *frame)
[285] {
[286]     frame->next = h2c->last_out;
[287]     h2c->last_out = frame;
[288] }
[289] 
[290] 
[291] void ngx_http_v2_init(ngx_event_t *rev);
[292] 
[293] ngx_int_t ngx_http_v2_read_request_body(ngx_http_request_t *r);
[294] ngx_int_t ngx_http_v2_read_unbuffered_request_body(ngx_http_request_t *r);
[295] 
[296] ngx_http_v2_stream_t *ngx_http_v2_push_stream(ngx_http_v2_stream_t *parent,
[297]     ngx_str_t *path);
[298] 
[299] void ngx_http_v2_close_stream(ngx_http_v2_stream_t *stream, ngx_int_t rc);
[300] 
[301] ngx_int_t ngx_http_v2_send_output_queue(ngx_http_v2_connection_t *h2c);
[302] 
[303] 
[304] ngx_str_t *ngx_http_v2_get_static_name(ngx_uint_t index);
[305] ngx_str_t *ngx_http_v2_get_static_value(ngx_uint_t index);
[306] 
[307] ngx_int_t ngx_http_v2_get_indexed_header(ngx_http_v2_connection_t *h2c,
[308]     ngx_uint_t index, ngx_uint_t name_only);
[309] ngx_int_t ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
[310]     ngx_http_v2_header_t *header);
[311] ngx_int_t ngx_http_v2_table_size(ngx_http_v2_connection_t *h2c, size_t size);
[312] 
[313] 
[314] #define ngx_http_v2_prefix(bits)  ((1 << (bits)) - 1)
[315] 
[316] 
[317] #if (NGX_HAVE_NONALIGNED)
[318] 
[319] #define ngx_http_v2_parse_uint16(p)  ntohs(*(uint16_t *) (p))
[320] #define ngx_http_v2_parse_uint32(p)  ntohl(*(uint32_t *) (p))
[321] 
[322] #else
[323] 
[324] #define ngx_http_v2_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
[325] #define ngx_http_v2_parse_uint32(p)                                           \
[326]     ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])
[327] 
[328] #endif
[329] 
[330] #define ngx_http_v2_parse_length(p)  ((p) >> 8)
[331] #define ngx_http_v2_parse_type(p)    ((p) & 0xff)
[332] #define ngx_http_v2_parse_sid(p)     (ngx_http_v2_parse_uint32(p) & 0x7fffffff)
[333] #define ngx_http_v2_parse_window(p)  (ngx_http_v2_parse_uint32(p) & 0x7fffffff)
[334] 
[335] 
[336] #define ngx_http_v2_write_uint16_aligned(p, s)                                \
[337]     (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))
[338] #define ngx_http_v2_write_uint32_aligned(p, s)                                \
[339]     (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))
[340] 
[341] #if (NGX_HAVE_NONALIGNED)
[342] 
[343] #define ngx_http_v2_write_uint16  ngx_http_v2_write_uint16_aligned
[344] #define ngx_http_v2_write_uint32  ngx_http_v2_write_uint32_aligned
[345] 
[346] #else
[347] 
[348] #define ngx_http_v2_write_uint16(p, s)                                        \
[349]     ((p)[0] = (u_char) ((s) >> 8),                                            \
[350]      (p)[1] = (u_char)  (s),                                                  \
[351]      (p) + sizeof(uint16_t))
[352] 
[353] #define ngx_http_v2_write_uint32(p, s)                                        \
[354]     ((p)[0] = (u_char) ((s) >> 24),                                           \
[355]      (p)[1] = (u_char) ((s) >> 16),                                           \
[356]      (p)[2] = (u_char) ((s) >> 8),                                            \
[357]      (p)[3] = (u_char)  (s),                                                  \
[358]      (p) + sizeof(uint32_t))
[359] 
[360] #endif
[361] 
[362] #define ngx_http_v2_write_len_and_type(p, l, t)                               \
[363]     ngx_http_v2_write_uint32_aligned(p, (l) << 8 | (t))
[364] 
[365] #define ngx_http_v2_write_sid  ngx_http_v2_write_uint32
[366] 
[367] 
[368] #define ngx_http_v2_indexed(i)      (128 + (i))
[369] #define ngx_http_v2_inc_indexed(i)  (64 + (i))
[370] 
[371] #define ngx_http_v2_write_name(dst, src, len, tmp)                            \
[372]     ngx_http_v2_string_encode(dst, src, len, tmp, 1)
[373] #define ngx_http_v2_write_value(dst, src, len, tmp)                           \
[374]     ngx_http_v2_string_encode(dst, src, len, tmp, 0)
[375] 
[376] #define NGX_HTTP_V2_ENCODE_RAW            0
[377] #define NGX_HTTP_V2_ENCODE_HUFF           0x80
[378] 
[379] #define NGX_HTTP_V2_AUTHORITY_INDEX       1
[380] 
[381] #define NGX_HTTP_V2_METHOD_INDEX          2
[382] #define NGX_HTTP_V2_METHOD_GET_INDEX      2
[383] #define NGX_HTTP_V2_METHOD_POST_INDEX     3
[384] 
[385] #define NGX_HTTP_V2_PATH_INDEX            4
[386] #define NGX_HTTP_V2_PATH_ROOT_INDEX       4
[387] 
[388] #define NGX_HTTP_V2_SCHEME_HTTP_INDEX     6
[389] #define NGX_HTTP_V2_SCHEME_HTTPS_INDEX    7
[390] 
[391] #define NGX_HTTP_V2_STATUS_INDEX          8
[392] #define NGX_HTTP_V2_STATUS_200_INDEX      8
[393] #define NGX_HTTP_V2_STATUS_204_INDEX      9
[394] #define NGX_HTTP_V2_STATUS_206_INDEX      10
[395] #define NGX_HTTP_V2_STATUS_304_INDEX      11
[396] #define NGX_HTTP_V2_STATUS_400_INDEX      12
[397] #define NGX_HTTP_V2_STATUS_404_INDEX      13
[398] #define NGX_HTTP_V2_STATUS_500_INDEX      14
[399] 
[400] #define NGX_HTTP_V2_ACCEPT_ENCODING_INDEX 16
[401] #define NGX_HTTP_V2_ACCEPT_LANGUAGE_INDEX 17
[402] #define NGX_HTTP_V2_CONTENT_LENGTH_INDEX  28
[403] #define NGX_HTTP_V2_CONTENT_TYPE_INDEX    31
[404] #define NGX_HTTP_V2_DATE_INDEX            33
[405] #define NGX_HTTP_V2_LAST_MODIFIED_INDEX   44
[406] #define NGX_HTTP_V2_LOCATION_INDEX        46
[407] #define NGX_HTTP_V2_SERVER_INDEX          54
[408] #define NGX_HTTP_V2_USER_AGENT_INDEX      58
[409] #define NGX_HTTP_V2_VARY_INDEX            59
[410] 
[411] 
[412] u_char *ngx_http_v2_string_encode(u_char *dst, u_char *src, size_t len,
[413]     u_char *tmp, ngx_uint_t lower);
[414] 
[415] 
[416] #endif /* _NGX_HTTP_V2_H_INCLUDED_ */
