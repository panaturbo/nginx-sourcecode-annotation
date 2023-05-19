[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_http.h>
[10] 
[11] 
[12] #define NGX_HTTP_MP4_TRAK_ATOM     0
[13] #define NGX_HTTP_MP4_TKHD_ATOM     1
[14] #define NGX_HTTP_MP4_EDTS_ATOM     2
[15] #define NGX_HTTP_MP4_ELST_ATOM     3
[16] #define NGX_HTTP_MP4_MDIA_ATOM     4
[17] #define NGX_HTTP_MP4_MDHD_ATOM     5
[18] #define NGX_HTTP_MP4_HDLR_ATOM     6
[19] #define NGX_HTTP_MP4_MINF_ATOM     7
[20] #define NGX_HTTP_MP4_VMHD_ATOM     8
[21] #define NGX_HTTP_MP4_SMHD_ATOM     9
[22] #define NGX_HTTP_MP4_DINF_ATOM    10
[23] #define NGX_HTTP_MP4_STBL_ATOM    11
[24] #define NGX_HTTP_MP4_STSD_ATOM    12
[25] #define NGX_HTTP_MP4_STTS_ATOM    13
[26] #define NGX_HTTP_MP4_STTS_DATA    14
[27] #define NGX_HTTP_MP4_STSS_ATOM    15
[28] #define NGX_HTTP_MP4_STSS_DATA    16
[29] #define NGX_HTTP_MP4_CTTS_ATOM    17
[30] #define NGX_HTTP_MP4_CTTS_DATA    18
[31] #define NGX_HTTP_MP4_STSC_ATOM    19
[32] #define NGX_HTTP_MP4_STSC_START   20
[33] #define NGX_HTTP_MP4_STSC_DATA    21
[34] #define NGX_HTTP_MP4_STSC_END     22
[35] #define NGX_HTTP_MP4_STSZ_ATOM    23
[36] #define NGX_HTTP_MP4_STSZ_DATA    24
[37] #define NGX_HTTP_MP4_STCO_ATOM    25
[38] #define NGX_HTTP_MP4_STCO_DATA    26
[39] #define NGX_HTTP_MP4_CO64_ATOM    27
[40] #define NGX_HTTP_MP4_CO64_DATA    28
[41] 
[42] #define NGX_HTTP_MP4_LAST_ATOM    NGX_HTTP_MP4_CO64_DATA
[43] 
[44] 
[45] typedef struct {
[46]     size_t                buffer_size;
[47]     size_t                max_buffer_size;
[48]     ngx_flag_t            start_key_frame;
[49] } ngx_http_mp4_conf_t;
[50] 
[51] 
[52] typedef struct {
[53]     u_char                chunk[4];
[54]     u_char                samples[4];
[55]     u_char                id[4];
[56] } ngx_mp4_stsc_entry_t;
[57] 
[58] 
[59] typedef struct {
[60]     u_char                size[4];
[61]     u_char                name[4];
[62] } ngx_mp4_edts_atom_t;
[63] 
[64] 
[65] typedef struct {
[66]     u_char                size[4];
[67]     u_char                name[4];
[68]     u_char                version[1];
[69]     u_char                flags[3];
[70]     u_char                entries[4];
[71]     u_char                duration[8];
[72]     u_char                media_time[8];
[73]     u_char                media_rate[2];
[74]     u_char                reserved[2];
[75] } ngx_mp4_elst_atom_t;
[76] 
[77] 
[78] typedef struct {
[79]     uint32_t              timescale;
[80]     uint32_t              time_to_sample_entries;
[81]     uint32_t              sample_to_chunk_entries;
[82]     uint32_t              sync_samples_entries;
[83]     uint32_t              composition_offset_entries;
[84]     uint32_t              sample_sizes_entries;
[85]     uint32_t              chunks;
[86] 
[87]     ngx_uint_t            start_sample;
[88]     ngx_uint_t            end_sample;
[89]     ngx_uint_t            start_chunk;
[90]     ngx_uint_t            end_chunk;
[91]     ngx_uint_t            start_chunk_samples;
[92]     ngx_uint_t            end_chunk_samples;
[93]     uint64_t              start_chunk_samples_size;
[94]     uint64_t              end_chunk_samples_size;
[95]     uint64_t              duration;
[96]     uint64_t              prefix;
[97]     uint64_t              movie_duration;
[98]     off_t                 start_offset;
[99]     off_t                 end_offset;
[100] 
[101]     size_t                tkhd_size;
[102]     size_t                mdhd_size;
[103]     size_t                hdlr_size;
[104]     size_t                vmhd_size;
[105]     size_t                smhd_size;
[106]     size_t                dinf_size;
[107]     size_t                size;
[108] 
[109]     ngx_chain_t           out[NGX_HTTP_MP4_LAST_ATOM + 1];
[110] 
[111]     ngx_buf_t             trak_atom_buf;
[112]     ngx_buf_t             tkhd_atom_buf;
[113]     ngx_buf_t             edts_atom_buf;
[114]     ngx_buf_t             elst_atom_buf;
[115]     ngx_buf_t             mdia_atom_buf;
[116]     ngx_buf_t             mdhd_atom_buf;
[117]     ngx_buf_t             hdlr_atom_buf;
[118]     ngx_buf_t             minf_atom_buf;
[119]     ngx_buf_t             vmhd_atom_buf;
[120]     ngx_buf_t             smhd_atom_buf;
[121]     ngx_buf_t             dinf_atom_buf;
[122]     ngx_buf_t             stbl_atom_buf;
[123]     ngx_buf_t             stsd_atom_buf;
[124]     ngx_buf_t             stts_atom_buf;
[125]     ngx_buf_t             stts_data_buf;
[126]     ngx_buf_t             stss_atom_buf;
[127]     ngx_buf_t             stss_data_buf;
[128]     ngx_buf_t             ctts_atom_buf;
[129]     ngx_buf_t             ctts_data_buf;
[130]     ngx_buf_t             stsc_atom_buf;
[131]     ngx_buf_t             stsc_start_chunk_buf;
[132]     ngx_buf_t             stsc_end_chunk_buf;
[133]     ngx_buf_t             stsc_data_buf;
[134]     ngx_buf_t             stsz_atom_buf;
[135]     ngx_buf_t             stsz_data_buf;
[136]     ngx_buf_t             stco_atom_buf;
[137]     ngx_buf_t             stco_data_buf;
[138]     ngx_buf_t             co64_atom_buf;
[139]     ngx_buf_t             co64_data_buf;
[140] 
[141]     ngx_mp4_edts_atom_t   edts_atom;
[142]     ngx_mp4_elst_atom_t   elst_atom;
[143]     ngx_mp4_stsc_entry_t  stsc_start_chunk_entry;
[144]     ngx_mp4_stsc_entry_t  stsc_end_chunk_entry;
[145] } ngx_http_mp4_trak_t;
[146] 
[147] 
[148] typedef struct {
[149]     ngx_file_t            file;
[150] 
[151]     u_char               *buffer;
[152]     u_char               *buffer_start;
[153]     u_char               *buffer_pos;
[154]     u_char               *buffer_end;
[155]     size_t                buffer_size;
[156] 
[157]     off_t                 offset;
[158]     off_t                 end;
[159]     off_t                 content_length;
[160]     ngx_uint_t            start;
[161]     ngx_uint_t            length;
[162]     uint32_t              timescale;
[163]     ngx_http_request_t   *request;
[164]     ngx_array_t           trak;
[165]     ngx_http_mp4_trak_t   traks[2];
[166] 
[167]     size_t                ftyp_size;
[168]     size_t                moov_size;
[169] 
[170]     ngx_chain_t          *out;
[171]     ngx_chain_t           ftyp_atom;
[172]     ngx_chain_t           moov_atom;
[173]     ngx_chain_t           mvhd_atom;
[174]     ngx_chain_t           mdat_atom;
[175]     ngx_chain_t           mdat_data;
[176] 
[177]     ngx_buf_t             ftyp_atom_buf;
[178]     ngx_buf_t             moov_atom_buf;
[179]     ngx_buf_t             mvhd_atom_buf;
[180]     ngx_buf_t             mdat_atom_buf;
[181]     ngx_buf_t             mdat_data_buf;
[182] 
[183]     u_char                moov_atom_header[8];
[184]     u_char                mdat_atom_header[16];
[185] } ngx_http_mp4_file_t;
[186] 
[187] 
[188] typedef struct {
[189]     char                 *name;
[190]     ngx_int_t           (*handler)(ngx_http_mp4_file_t *mp4,
[191]                                    uint64_t atom_data_size);
[192] } ngx_http_mp4_atom_handler_t;
[193] 
[194] 
[195] #define ngx_mp4_atom_header(mp4)   (mp4->buffer_pos - 8)
[196] #define ngx_mp4_atom_data(mp4)     mp4->buffer_pos
[197] #define ngx_mp4_atom_data_size(t)  (uint64_t) (sizeof(t) - 8)
[198] 
[199] 
[200] #define ngx_mp4_atom_next(mp4, n)                                             \
[201]                                                                               \
[202]     if (n > (size_t) (mp4->buffer_end - mp4->buffer_pos)) {                   \
[203]         mp4->buffer_pos = mp4->buffer_end;                                    \
[204]                                                                               \
[205]     } else {                                                                  \
[206]         mp4->buffer_pos += (size_t) n;                                        \
[207]     }                                                                         \
[208]                                                                               \
[209]     mp4->offset += n
[210] 
[211] 
[212] #define ngx_mp4_set_atom_name(p, n1, n2, n3, n4)                              \
[213]     ((u_char *) (p))[4] = n1;                                                 \
[214]     ((u_char *) (p))[5] = n2;                                                 \
[215]     ((u_char *) (p))[6] = n3;                                                 \
[216]     ((u_char *) (p))[7] = n4
[217] 
[218] #define ngx_mp4_get_16value(p)                                                \
[219]     ( ((uint16_t) ((u_char *) (p))[0] << 8)                                   \
[220]     + (           ((u_char *) (p))[1]) )
[221] 
[222] #define ngx_mp4_set_16value(p, n)                                             \
[223]     ((u_char *) (p))[0] = (u_char) ((n) >> 8);                                \
[224]     ((u_char *) (p))[1] = (u_char)  (n)
[225] 
[226] #define ngx_mp4_get_32value(p)                                                \
[227]     ( ((uint32_t) ((u_char *) (p))[0] << 24)                                  \
[228]     + (           ((u_char *) (p))[1] << 16)                                  \
[229]     + (           ((u_char *) (p))[2] << 8)                                   \
[230]     + (           ((u_char *) (p))[3]) )
[231] 
[232] #define ngx_mp4_set_32value(p, n)                                             \
[233]     ((u_char *) (p))[0] = (u_char) ((n) >> 24);                               \
[234]     ((u_char *) (p))[1] = (u_char) ((n) >> 16);                               \
[235]     ((u_char *) (p))[2] = (u_char) ((n) >> 8);                                \
[236]     ((u_char *) (p))[3] = (u_char)  (n)
[237] 
[238] #define ngx_mp4_get_64value(p)                                                \
[239]     ( ((uint64_t) ((u_char *) (p))[0] << 56)                                  \
[240]     + ((uint64_t) ((u_char *) (p))[1] << 48)                                  \
[241]     + ((uint64_t) ((u_char *) (p))[2] << 40)                                  \
[242]     + ((uint64_t) ((u_char *) (p))[3] << 32)                                  \
[243]     + ((uint64_t) ((u_char *) (p))[4] << 24)                                  \
[244]     + (           ((u_char *) (p))[5] << 16)                                  \
[245]     + (           ((u_char *) (p))[6] << 8)                                   \
[246]     + (           ((u_char *) (p))[7]) )
[247] 
[248] #define ngx_mp4_set_64value(p, n)                                             \
[249]     ((u_char *) (p))[0] = (u_char) ((uint64_t) (n) >> 56);                    \
[250]     ((u_char *) (p))[1] = (u_char) ((uint64_t) (n) >> 48);                    \
[251]     ((u_char *) (p))[2] = (u_char) ((uint64_t) (n) >> 40);                    \
[252]     ((u_char *) (p))[3] = (u_char) ((uint64_t) (n) >> 32);                    \
[253]     ((u_char *) (p))[4] = (u_char) (           (n) >> 24);                    \
[254]     ((u_char *) (p))[5] = (u_char) (           (n) >> 16);                    \
[255]     ((u_char *) (p))[6] = (u_char) (           (n) >> 8);                     \
[256]     ((u_char *) (p))[7] = (u_char)             (n)
[257] 
[258] #define ngx_mp4_last_trak(mp4)                                                \
[259]     &((ngx_http_mp4_trak_t *) mp4->trak.elts)[mp4->trak.nelts - 1]
[260] 
[261] 
[262] static ngx_int_t ngx_http_mp4_handler(ngx_http_request_t *r);
[263] static ngx_int_t ngx_http_mp4_atofp(u_char *line, size_t n, size_t point);
[264] 
[265] static ngx_int_t ngx_http_mp4_process(ngx_http_mp4_file_t *mp4);
[266] static ngx_int_t ngx_http_mp4_read_atom(ngx_http_mp4_file_t *mp4,
[267]     ngx_http_mp4_atom_handler_t *atom, uint64_t atom_data_size);
[268] static ngx_int_t ngx_http_mp4_read(ngx_http_mp4_file_t *mp4, size_t size);
[269] static ngx_int_t ngx_http_mp4_read_ftyp_atom(ngx_http_mp4_file_t *mp4,
[270]     uint64_t atom_data_size);
[271] static ngx_int_t ngx_http_mp4_read_moov_atom(ngx_http_mp4_file_t *mp4,
[272]     uint64_t atom_data_size);
[273] static ngx_int_t ngx_http_mp4_read_mdat_atom(ngx_http_mp4_file_t *mp4,
[274]     uint64_t atom_data_size);
[275] static size_t ngx_http_mp4_update_mdat_atom(ngx_http_mp4_file_t *mp4,
[276]     off_t start_offset, off_t end_offset);
[277] static ngx_int_t ngx_http_mp4_read_mvhd_atom(ngx_http_mp4_file_t *mp4,
[278]     uint64_t atom_data_size);
[279] static ngx_int_t ngx_http_mp4_read_trak_atom(ngx_http_mp4_file_t *mp4,
[280]     uint64_t atom_data_size);
[281] static void ngx_http_mp4_update_trak_atom(ngx_http_mp4_file_t *mp4,
[282]     ngx_http_mp4_trak_t *trak);
[283] static ngx_int_t ngx_http_mp4_read_cmov_atom(ngx_http_mp4_file_t *mp4,
[284]     uint64_t atom_data_size);
[285] static ngx_int_t ngx_http_mp4_read_tkhd_atom(ngx_http_mp4_file_t *mp4,
[286]     uint64_t atom_data_size);
[287] static ngx_int_t ngx_http_mp4_read_mdia_atom(ngx_http_mp4_file_t *mp4,
[288]     uint64_t atom_data_size);
[289] static void ngx_http_mp4_update_mdia_atom(ngx_http_mp4_file_t *mp4,
[290]     ngx_http_mp4_trak_t *trak);
[291] static ngx_int_t ngx_http_mp4_read_mdhd_atom(ngx_http_mp4_file_t *mp4,
[292]     uint64_t atom_data_size);
[293] static void ngx_http_mp4_update_mdhd_atom(ngx_http_mp4_file_t *mp4,
[294]     ngx_http_mp4_trak_t *trak);
[295] static ngx_int_t ngx_http_mp4_read_hdlr_atom(ngx_http_mp4_file_t *mp4,
[296]     uint64_t atom_data_size);
[297] static ngx_int_t ngx_http_mp4_read_minf_atom(ngx_http_mp4_file_t *mp4,
[298]     uint64_t atom_data_size);
[299] static void ngx_http_mp4_update_minf_atom(ngx_http_mp4_file_t *mp4,
[300]     ngx_http_mp4_trak_t *trak);
[301] static ngx_int_t ngx_http_mp4_read_dinf_atom(ngx_http_mp4_file_t *mp4,
[302]     uint64_t atom_data_size);
[303] static ngx_int_t ngx_http_mp4_read_vmhd_atom(ngx_http_mp4_file_t *mp4,
[304]     uint64_t atom_data_size);
[305] static ngx_int_t ngx_http_mp4_read_smhd_atom(ngx_http_mp4_file_t *mp4,
[306]     uint64_t atom_data_size);
[307] static ngx_int_t ngx_http_mp4_read_stbl_atom(ngx_http_mp4_file_t *mp4,
[308]     uint64_t atom_data_size);
[309] static void ngx_http_mp4_update_edts_atom(ngx_http_mp4_file_t *mp4,
[310]     ngx_http_mp4_trak_t *trak);
[311] static void ngx_http_mp4_update_stbl_atom(ngx_http_mp4_file_t *mp4,
[312]     ngx_http_mp4_trak_t *trak);
[313] static ngx_int_t ngx_http_mp4_read_stsd_atom(ngx_http_mp4_file_t *mp4,
[314]     uint64_t atom_data_size);
[315] static ngx_int_t ngx_http_mp4_read_stts_atom(ngx_http_mp4_file_t *mp4,
[316]     uint64_t atom_data_size);
[317] static ngx_int_t ngx_http_mp4_update_stts_atom(ngx_http_mp4_file_t *mp4,
[318]     ngx_http_mp4_trak_t *trak);
[319] static ngx_int_t ngx_http_mp4_crop_stts_data(ngx_http_mp4_file_t *mp4,
[320]     ngx_http_mp4_trak_t *trak, ngx_uint_t start);
[321] static uint32_t ngx_http_mp4_seek_key_frame(ngx_http_mp4_file_t *mp4,
[322]     ngx_http_mp4_trak_t *trak, uint32_t start_sample);
[323] static ngx_int_t ngx_http_mp4_read_stss_atom(ngx_http_mp4_file_t *mp4,
[324]     uint64_t atom_data_size);
[325] static ngx_int_t ngx_http_mp4_update_stss_atom(ngx_http_mp4_file_t *mp4,
[326]     ngx_http_mp4_trak_t *trak);
[327] static void ngx_http_mp4_crop_stss_data(ngx_http_mp4_file_t *mp4,
[328]     ngx_http_mp4_trak_t *trak, ngx_uint_t start);
[329] static ngx_int_t ngx_http_mp4_read_ctts_atom(ngx_http_mp4_file_t *mp4,
[330]     uint64_t atom_data_size);
[331] static void ngx_http_mp4_update_ctts_atom(ngx_http_mp4_file_t *mp4,
[332]     ngx_http_mp4_trak_t *trak);
[333] static void ngx_http_mp4_crop_ctts_data(ngx_http_mp4_file_t *mp4,
[334]     ngx_http_mp4_trak_t *trak, ngx_uint_t start);
[335] static ngx_int_t ngx_http_mp4_read_stsc_atom(ngx_http_mp4_file_t *mp4,
[336]     uint64_t atom_data_size);
[337] static ngx_int_t ngx_http_mp4_update_stsc_atom(ngx_http_mp4_file_t *mp4,
[338]     ngx_http_mp4_trak_t *trak);
[339] static ngx_int_t ngx_http_mp4_crop_stsc_data(ngx_http_mp4_file_t *mp4,
[340]     ngx_http_mp4_trak_t *trak, ngx_uint_t start);
[341] static ngx_int_t ngx_http_mp4_read_stsz_atom(ngx_http_mp4_file_t *mp4,
[342]     uint64_t atom_data_size);
[343] static ngx_int_t ngx_http_mp4_update_stsz_atom(ngx_http_mp4_file_t *mp4,
[344]     ngx_http_mp4_trak_t *trak);
[345] static ngx_int_t ngx_http_mp4_read_stco_atom(ngx_http_mp4_file_t *mp4,
[346]     uint64_t atom_data_size);
[347] static ngx_int_t ngx_http_mp4_update_stco_atom(ngx_http_mp4_file_t *mp4,
[348]     ngx_http_mp4_trak_t *trak);
[349] static void ngx_http_mp4_adjust_stco_atom(ngx_http_mp4_file_t *mp4,
[350]     ngx_http_mp4_trak_t *trak, int32_t adjustment);
[351] static ngx_int_t ngx_http_mp4_read_co64_atom(ngx_http_mp4_file_t *mp4,
[352]     uint64_t atom_data_size);
[353] static ngx_int_t ngx_http_mp4_update_co64_atom(ngx_http_mp4_file_t *mp4,
[354]     ngx_http_mp4_trak_t *trak);
[355] static void ngx_http_mp4_adjust_co64_atom(ngx_http_mp4_file_t *mp4,
[356]     ngx_http_mp4_trak_t *trak, off_t adjustment);
[357] 
[358] static char *ngx_http_mp4(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[359] static void *ngx_http_mp4_create_conf(ngx_conf_t *cf);
[360] static char *ngx_http_mp4_merge_conf(ngx_conf_t *cf, void *parent, void *child);
[361] 
[362] 
[363] static ngx_command_t  ngx_http_mp4_commands[] = {
[364] 
[365]     { ngx_string("mp4"),
[366]       NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
[367]       ngx_http_mp4,
[368]       0,
[369]       0,
[370]       NULL },
[371] 
[372]     { ngx_string("mp4_buffer_size"),
[373]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[374]       ngx_conf_set_size_slot,
[375]       NGX_HTTP_LOC_CONF_OFFSET,
[376]       offsetof(ngx_http_mp4_conf_t, buffer_size),
[377]       NULL },
[378] 
[379]     { ngx_string("mp4_max_buffer_size"),
[380]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[381]       ngx_conf_set_size_slot,
[382]       NGX_HTTP_LOC_CONF_OFFSET,
[383]       offsetof(ngx_http_mp4_conf_t, max_buffer_size),
[384]       NULL },
[385] 
[386]     { ngx_string("mp4_start_key_frame"),
[387]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[388]       ngx_conf_set_flag_slot,
[389]       NGX_HTTP_LOC_CONF_OFFSET,
[390]       offsetof(ngx_http_mp4_conf_t, start_key_frame),
[391]       NULL },
[392] 
[393]       ngx_null_command
[394] };
[395] 
[396] 
[397] static ngx_http_module_t  ngx_http_mp4_module_ctx = {
[398]     NULL,                          /* preconfiguration */
[399]     NULL,                          /* postconfiguration */
[400] 
[401]     NULL,                          /* create main configuration */
[402]     NULL,                          /* init main configuration */
[403] 
[404]     NULL,                          /* create server configuration */
[405]     NULL,                          /* merge server configuration */
[406] 
[407]     ngx_http_mp4_create_conf,      /* create location configuration */
[408]     ngx_http_mp4_merge_conf        /* merge location configuration */
[409] };
[410] 
[411] 
[412] ngx_module_t  ngx_http_mp4_module = {
[413]     NGX_MODULE_V1,
[414]     &ngx_http_mp4_module_ctx,      /* module context */
[415]     ngx_http_mp4_commands,         /* module directives */
[416]     NGX_HTTP_MODULE,               /* module type */
[417]     NULL,                          /* init master */
[418]     NULL,                          /* init module */
[419]     NULL,                          /* init process */
[420]     NULL,                          /* init thread */
[421]     NULL,                          /* exit thread */
[422]     NULL,                          /* exit process */
[423]     NULL,                          /* exit master */
[424]     NGX_MODULE_V1_PADDING
[425] };
[426] 
[427] 
[428] static ngx_http_mp4_atom_handler_t  ngx_http_mp4_atoms[] = {
[429]     { "ftyp", ngx_http_mp4_read_ftyp_atom },
[430]     { "moov", ngx_http_mp4_read_moov_atom },
[431]     { "mdat", ngx_http_mp4_read_mdat_atom },
[432]     { NULL, NULL }
[433] };
[434] 
[435] static ngx_http_mp4_atom_handler_t  ngx_http_mp4_moov_atoms[] = {
[436]     { "mvhd", ngx_http_mp4_read_mvhd_atom },
[437]     { "trak", ngx_http_mp4_read_trak_atom },
[438]     { "cmov", ngx_http_mp4_read_cmov_atom },
[439]     { NULL, NULL }
[440] };
[441] 
[442] static ngx_http_mp4_atom_handler_t  ngx_http_mp4_trak_atoms[] = {
[443]     { "tkhd", ngx_http_mp4_read_tkhd_atom },
[444]     { "mdia", ngx_http_mp4_read_mdia_atom },
[445]     { NULL, NULL }
[446] };
[447] 
[448] static ngx_http_mp4_atom_handler_t  ngx_http_mp4_mdia_atoms[] = {
[449]     { "mdhd", ngx_http_mp4_read_mdhd_atom },
[450]     { "hdlr", ngx_http_mp4_read_hdlr_atom },
[451]     { "minf", ngx_http_mp4_read_minf_atom },
[452]     { NULL, NULL }
[453] };
[454] 
[455] static ngx_http_mp4_atom_handler_t  ngx_http_mp4_minf_atoms[] = {
[456]     { "vmhd", ngx_http_mp4_read_vmhd_atom },
[457]     { "smhd", ngx_http_mp4_read_smhd_atom },
[458]     { "dinf", ngx_http_mp4_read_dinf_atom },
[459]     { "stbl", ngx_http_mp4_read_stbl_atom },
[460]     { NULL, NULL }
[461] };
[462] 
[463] static ngx_http_mp4_atom_handler_t  ngx_http_mp4_stbl_atoms[] = {
[464]     { "stsd", ngx_http_mp4_read_stsd_atom },
[465]     { "stts", ngx_http_mp4_read_stts_atom },
[466]     { "stss", ngx_http_mp4_read_stss_atom },
[467]     { "ctts", ngx_http_mp4_read_ctts_atom },
[468]     { "stsc", ngx_http_mp4_read_stsc_atom },
[469]     { "stsz", ngx_http_mp4_read_stsz_atom },
[470]     { "stco", ngx_http_mp4_read_stco_atom },
[471]     { "co64", ngx_http_mp4_read_co64_atom },
[472]     { NULL, NULL }
[473] };
[474] 
[475] 
[476] static ngx_int_t
[477] ngx_http_mp4_handler(ngx_http_request_t *r)
[478] {
[479]     u_char                    *last;
[480]     size_t                     root;
[481]     ngx_int_t                  rc, start, end;
[482]     ngx_uint_t                 level, length;
[483]     ngx_str_t                  path, value;
[484]     ngx_log_t                 *log;
[485]     ngx_buf_t                 *b;
[486]     ngx_chain_t                out;
[487]     ngx_http_mp4_file_t       *mp4;
[488]     ngx_open_file_info_t       of;
[489]     ngx_http_core_loc_conf_t  *clcf;
[490] 
[491]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[492]         return NGX_HTTP_NOT_ALLOWED;
[493]     }
[494] 
[495]     if (r->uri.data[r->uri.len - 1] == '/') {
[496]         return NGX_DECLINED;
[497]     }
[498] 
[499]     rc = ngx_http_discard_request_body(r);
[500] 
[501]     if (rc != NGX_OK) {
[502]         return rc;
[503]     }
[504] 
[505]     last = ngx_http_map_uri_to_path(r, &path, &root, 0);
[506]     if (last == NULL) {
[507]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[508]     }
[509] 
[510]     log = r->connection->log;
[511] 
[512]     path.len = last - path.data;
[513] 
[514]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
[515]                    "http mp4 filename: \"%V\"", &path);
[516] 
[517]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[518] 
[519]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[520] 
[521]     of.read_ahead = clcf->read_ahead;
[522]     of.directio = NGX_MAX_OFF_T_VALUE;
[523]     of.valid = clcf->open_file_cache_valid;
[524]     of.min_uses = clcf->open_file_cache_min_uses;
[525]     of.errors = clcf->open_file_cache_errors;
[526]     of.events = clcf->open_file_cache_events;
[527] 
[528]     if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[529]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[530]     }
[531] 
[532]     if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[533]         != NGX_OK)
[534]     {
[535]         switch (of.err) {
[536] 
[537]         case 0:
[538]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[539] 
[540]         case NGX_ENOENT:
[541]         case NGX_ENOTDIR:
[542]         case NGX_ENAMETOOLONG:
[543] 
[544]             level = NGX_LOG_ERR;
[545]             rc = NGX_HTTP_NOT_FOUND;
[546]             break;
[547] 
[548]         case NGX_EACCES:
[549] #if (NGX_HAVE_OPENAT)
[550]         case NGX_EMLINK:
[551]         case NGX_ELOOP:
[552] #endif
[553] 
[554]             level = NGX_LOG_ERR;
[555]             rc = NGX_HTTP_FORBIDDEN;
[556]             break;
[557] 
[558]         default:
[559] 
[560]             level = NGX_LOG_CRIT;
[561]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[562]             break;
[563]         }
[564] 
[565]         if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
[566]             ngx_log_error(level, log, of.err,
[567]                           "%s \"%s\" failed", of.failed, path.data);
[568]         }
[569] 
[570]         return rc;
[571]     }
[572] 
[573]     if (!of.is_file) {
[574]         return NGX_DECLINED;
[575]     }
[576] 
[577]     r->root_tested = !r->error_page;
[578]     r->allow_ranges = 1;
[579] 
[580]     start = -1;
[581]     length = 0;
[582]     r->headers_out.content_length_n = of.size;
[583]     mp4 = NULL;
[584]     b = NULL;
[585] 
[586]     if (r->args.len) {
[587] 
[588]         if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {
[589] 
[590]             /*
[591]              * A Flash player may send start value with a lot of digits
[592]              * after dot so a custom function is used instead of ngx_atofp().
[593]              */
[594] 
[595]             start = ngx_http_mp4_atofp(value.data, value.len, 3);
[596]         }
[597] 
[598]         if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK) {
[599] 
[600]             end = ngx_http_mp4_atofp(value.data, value.len, 3);
[601] 
[602]             if (end > 0) {
[603]                 if (start < 0) {
[604]                     start = 0;
[605]                 }
[606] 
[607]                 if (end > start) {
[608]                     length = end - start;
[609]                 }
[610]             }
[611]         }
[612]     }
[613] 
[614]     if (start >= 0) {
[615]         r->single_range = 1;
[616] 
[617]         mp4 = ngx_pcalloc(r->pool, sizeof(ngx_http_mp4_file_t));
[618]         if (mp4 == NULL) {
[619]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[620]         }
[621] 
[622]         mp4->file.fd = of.fd;
[623]         mp4->file.name = path;
[624]         mp4->file.log = r->connection->log;
[625]         mp4->end = of.size;
[626]         mp4->start = (ngx_uint_t) start;
[627]         mp4->length = length;
[628]         mp4->request = r;
[629] 
[630]         switch (ngx_http_mp4_process(mp4)) {
[631] 
[632]         case NGX_DECLINED:
[633]             if (mp4->buffer) {
[634]                 ngx_pfree(r->pool, mp4->buffer);
[635]             }
[636] 
[637]             ngx_pfree(r->pool, mp4);
[638]             mp4 = NULL;
[639] 
[640]             break;
[641] 
[642]         case NGX_OK:
[643]             r->headers_out.content_length_n = mp4->content_length;
[644]             break;
[645] 
[646]         default: /* NGX_ERROR */
[647]             if (mp4->buffer) {
[648]                 ngx_pfree(r->pool, mp4->buffer);
[649]             }
[650] 
[651]             ngx_pfree(r->pool, mp4);
[652] 
[653]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[654]         }
[655]     }
[656] 
[657]     log->action = "sending mp4 to client";
[658] 
[659]     if (clcf->directio <= of.size) {
[660] 
[661]         /*
[662]          * DIRECTIO is set on transfer only
[663]          * to allow kernel to cache "moov" atom
[664]          */
[665] 
[666]         if (ngx_directio_on(of.fd) == NGX_FILE_ERROR) {
[667]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[668]                           ngx_directio_on_n " \"%s\" failed", path.data);
[669]         }
[670] 
[671]         of.is_directio = 1;
[672] 
[673]         if (mp4) {
[674]             mp4->file.directio = 1;
[675]         }
[676]     }
[677] 
[678]     r->headers_out.status = NGX_HTTP_OK;
[679]     r->headers_out.last_modified_time = of.mtime;
[680] 
[681]     if (ngx_http_set_etag(r) != NGX_OK) {
[682]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[683]     }
[684] 
[685]     if (ngx_http_set_content_type(r) != NGX_OK) {
[686]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[687]     }
[688] 
[689]     if (mp4 == NULL) {
[690]         b = ngx_calloc_buf(r->pool);
[691]         if (b == NULL) {
[692]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[693]         }
[694] 
[695]         b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
[696]         if (b->file == NULL) {
[697]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[698]         }
[699]     }
[700] 
[701]     rc = ngx_http_send_header(r);
[702] 
[703]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[704]         return rc;
[705]     }
[706] 
[707]     if (mp4) {
[708]         return ngx_http_output_filter(r, mp4->out);
[709]     }
[710] 
[711]     b->file_pos = 0;
[712]     b->file_last = of.size;
[713] 
[714]     b->in_file = b->file_last ? 1 : 0;
[715]     b->last_buf = (r == r->main) ? 1 : 0;
[716]     b->last_in_chain = 1;
[717]     b->sync = (b->last_buf || b->in_file) ? 0 : 1;
[718] 
[719]     b->file->fd = of.fd;
[720]     b->file->name = path;
[721]     b->file->log = log;
[722]     b->file->directio = of.is_directio;
[723] 
[724]     out.buf = b;
[725]     out.next = NULL;
[726] 
[727]     return ngx_http_output_filter(r, &out);
[728] }
[729] 
[730] 
[731] static ngx_int_t
[732] ngx_http_mp4_atofp(u_char *line, size_t n, size_t point)
[733] {
[734]     ngx_int_t   value, cutoff, cutlim;
[735]     ngx_uint_t  dot;
[736] 
[737]     /* same as ngx_atofp(), but allows additional digits */
[738] 
[739]     if (n == 0) {
[740]         return NGX_ERROR;
[741]     }
[742] 
[743]     cutoff = NGX_MAX_INT_T_VALUE / 10;
[744]     cutlim = NGX_MAX_INT_T_VALUE % 10;
[745] 
[746]     dot = 0;
[747] 
[748]     for (value = 0; n--; line++) {
[749] 
[750]         if (*line == '.') {
[751]             if (dot) {
[752]                 return NGX_ERROR;
[753]             }
[754] 
[755]             dot = 1;
[756]             continue;
[757]         }
[758] 
[759]         if (*line < '0' || *line > '9') {
[760]             return NGX_ERROR;
[761]         }
[762] 
[763]         if (point == 0) {
[764]             continue;
[765]         }
[766] 
[767]         if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
[768]             return NGX_ERROR;
[769]         }
[770] 
[771]         value = value * 10 + (*line - '0');
[772]         point -= dot;
[773]     }
[774] 
[775]     while (point--) {
[776]         if (value > cutoff) {
[777]             return NGX_ERROR;
[778]         }
[779] 
[780]         value = value * 10;
[781]     }
[782] 
[783]     return value;
[784] }
[785] 
[786] 
[787] static ngx_int_t
[788] ngx_http_mp4_process(ngx_http_mp4_file_t *mp4)
[789] {
[790]     off_t                  start_offset, end_offset, adjustment;
[791]     ngx_int_t              rc;
[792]     ngx_uint_t             i, j;
[793]     ngx_chain_t          **prev;
[794]     ngx_http_mp4_trak_t   *trak;
[795]     ngx_http_mp4_conf_t   *conf;
[796] 
[797]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[798]                    "mp4 start:%ui, length:%ui", mp4->start, mp4->length);
[799] 
[800]     conf = ngx_http_get_module_loc_conf(mp4->request, ngx_http_mp4_module);
[801] 
[802]     mp4->buffer_size = conf->buffer_size;
[803] 
[804]     rc = ngx_http_mp4_read_atom(mp4, ngx_http_mp4_atoms, mp4->end);
[805]     if (rc != NGX_OK) {
[806]         return rc;
[807]     }
[808] 
[809]     if (mp4->trak.nelts == 0) {
[810]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[811]                       "no mp4 trak atoms were found in \"%s\"",
[812]                       mp4->file.name.data);
[813]         return NGX_ERROR;
[814]     }
[815] 
[816]     if (mp4->mdat_atom.buf == NULL) {
[817]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[818]                       "no mp4 mdat atom was found in \"%s\"",
[819]                       mp4->file.name.data);
[820]         return NGX_ERROR;
[821]     }
[822] 
[823]     prev = &mp4->out;
[824] 
[825]     if (mp4->ftyp_atom.buf) {
[826]         *prev = &mp4->ftyp_atom;
[827]         prev = &mp4->ftyp_atom.next;
[828]     }
[829] 
[830]     *prev = &mp4->moov_atom;
[831]     prev = &mp4->moov_atom.next;
[832] 
[833]     if (mp4->mvhd_atom.buf) {
[834]         mp4->moov_size += mp4->mvhd_atom_buf.last - mp4->mvhd_atom_buf.pos;
[835]         *prev = &mp4->mvhd_atom;
[836]         prev = &mp4->mvhd_atom.next;
[837]     }
[838] 
[839]     start_offset = mp4->end;
[840]     end_offset = 0;
[841]     trak = mp4->trak.elts;
[842] 
[843]     for (i = 0; i < mp4->trak.nelts; i++) {
[844] 
[845]         if (ngx_http_mp4_update_stts_atom(mp4, &trak[i]) != NGX_OK) {
[846]             return NGX_ERROR;
[847]         }
[848] 
[849]         if (ngx_http_mp4_update_stss_atom(mp4, &trak[i]) != NGX_OK) {
[850]             return NGX_ERROR;
[851]         }
[852] 
[853]         ngx_http_mp4_update_ctts_atom(mp4, &trak[i]);
[854] 
[855]         if (ngx_http_mp4_update_stsc_atom(mp4, &trak[i]) != NGX_OK) {
[856]             return NGX_ERROR;
[857]         }
[858] 
[859]         if (ngx_http_mp4_update_stsz_atom(mp4, &trak[i]) != NGX_OK) {
[860]             return NGX_ERROR;
[861]         }
[862] 
[863]         if (trak[i].out[NGX_HTTP_MP4_CO64_DATA].buf) {
[864]             if (ngx_http_mp4_update_co64_atom(mp4, &trak[i]) != NGX_OK) {
[865]                 return NGX_ERROR;
[866]             }
[867] 
[868]         } else {
[869]             if (ngx_http_mp4_update_stco_atom(mp4, &trak[i]) != NGX_OK) {
[870]                 return NGX_ERROR;
[871]             }
[872]         }
[873] 
[874]         ngx_http_mp4_update_stbl_atom(mp4, &trak[i]);
[875]         ngx_http_mp4_update_minf_atom(mp4, &trak[i]);
[876]         ngx_http_mp4_update_mdhd_atom(mp4, &trak[i]);
[877]         trak[i].size += trak[i].hdlr_size;
[878]         ngx_http_mp4_update_mdia_atom(mp4, &trak[i]);
[879]         trak[i].size += trak[i].tkhd_size;
[880]         ngx_http_mp4_update_edts_atom(mp4, &trak[i]);
[881]         ngx_http_mp4_update_trak_atom(mp4, &trak[i]);
[882] 
[883]         mp4->moov_size += trak[i].size;
[884] 
[885]         if (start_offset > trak[i].start_offset) {
[886]             start_offset = trak[i].start_offset;
[887]         }
[888] 
[889]         if (end_offset < trak[i].end_offset) {
[890]             end_offset = trak[i].end_offset;
[891]         }
[892] 
[893]         *prev = &trak[i].out[NGX_HTTP_MP4_TRAK_ATOM];
[894]         prev = &trak[i].out[NGX_HTTP_MP4_TRAK_ATOM].next;
[895] 
[896]         for (j = 0; j < NGX_HTTP_MP4_LAST_ATOM + 1; j++) {
[897]             if (trak[i].out[j].buf) {
[898]                 *prev = &trak[i].out[j];
[899]                 prev = &trak[i].out[j].next;
[900]             }
[901]         }
[902]     }
[903] 
[904]     if (end_offset < start_offset) {
[905]         end_offset = start_offset;
[906]     }
[907] 
[908]     mp4->moov_size += 8;
[909] 
[910]     ngx_mp4_set_32value(mp4->moov_atom_header, mp4->moov_size);
[911]     ngx_mp4_set_atom_name(mp4->moov_atom_header, 'm', 'o', 'o', 'v');
[912]     mp4->content_length += mp4->moov_size;
[913] 
[914]     *prev = &mp4->mdat_atom;
[915] 
[916]     if (start_offset > mp4->mdat_data.buf->file_last) {
[917]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[918]                       "start time is out mp4 mdat atom in \"%s\"",
[919]                       mp4->file.name.data);
[920]         return NGX_ERROR;
[921]     }
[922] 
[923]     adjustment = mp4->ftyp_size + mp4->moov_size
[924]                  + ngx_http_mp4_update_mdat_atom(mp4, start_offset, end_offset)
[925]                  - start_offset;
[926] 
[927]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[928]                    "mp4 adjustment:%O", adjustment);
[929] 
[930]     for (i = 0; i < mp4->trak.nelts; i++) {
[931]         if (trak[i].out[NGX_HTTP_MP4_CO64_DATA].buf) {
[932]             ngx_http_mp4_adjust_co64_atom(mp4, &trak[i], adjustment);
[933]         } else {
[934]             ngx_http_mp4_adjust_stco_atom(mp4, &trak[i], (int32_t) adjustment);
[935]         }
[936]     }
[937] 
[938]     return NGX_OK;
[939] }
[940] 
[941] 
[942] typedef struct {
[943]     u_char    size[4];
[944]     u_char    name[4];
[945] } ngx_mp4_atom_header_t;
[946] 
[947] typedef struct {
[948]     u_char    size[4];
[949]     u_char    name[4];
[950]     u_char    size64[8];
[951] } ngx_mp4_atom_header64_t;
[952] 
[953] 
[954] static ngx_int_t
[955] ngx_http_mp4_read_atom(ngx_http_mp4_file_t *mp4,
[956]     ngx_http_mp4_atom_handler_t *atom, uint64_t atom_data_size)
[957] {
[958]     off_t        end;
[959]     size_t       atom_header_size;
[960]     u_char      *atom_header, *atom_name;
[961]     uint64_t     atom_size;
[962]     ngx_int_t    rc;
[963]     ngx_uint_t   n;
[964] 
[965]     end = mp4->offset + atom_data_size;
[966] 
[967]     while (mp4->offset < end) {
[968] 
[969]         if (ngx_http_mp4_read(mp4, sizeof(uint32_t)) != NGX_OK) {
[970]             return NGX_ERROR;
[971]         }
[972] 
[973]         atom_header = mp4->buffer_pos;
[974]         atom_size = ngx_mp4_get_32value(atom_header);
[975]         atom_header_size = sizeof(ngx_mp4_atom_header_t);
[976] 
[977]         if (atom_size == 0) {
[978]             ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[979]                            "mp4 atom end");
[980]             return NGX_OK;
[981]         }
[982] 
[983]         if (atom_size < sizeof(ngx_mp4_atom_header_t)) {
[984] 
[985]             if (atom_size == 1) {
[986] 
[987]                 if (ngx_http_mp4_read(mp4, sizeof(ngx_mp4_atom_header64_t))
[988]                     != NGX_OK)
[989]                 {
[990]                     return NGX_ERROR;
[991]                 }
[992] 
[993]                 /* 64-bit atom size */
[994]                 atom_header = mp4->buffer_pos;
[995]                 atom_size = ngx_mp4_get_64value(atom_header + 8);
[996]                 atom_header_size = sizeof(ngx_mp4_atom_header64_t);
[997] 
[998]                 if (atom_size < sizeof(ngx_mp4_atom_header64_t)) {
[999]                     ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1000]                                   "\"%s\" mp4 atom is too small:%uL",
[1001]                                   mp4->file.name.data, atom_size);
[1002]                     return NGX_ERROR;
[1003]                 }
[1004] 
[1005]             } else {
[1006]                 ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1007]                               "\"%s\" mp4 atom is too small:%uL",
[1008]                               mp4->file.name.data, atom_size);
[1009]                 return NGX_ERROR;
[1010]             }
[1011]         }
[1012] 
[1013]         if (ngx_http_mp4_read(mp4, sizeof(ngx_mp4_atom_header_t)) != NGX_OK) {
[1014]             return NGX_ERROR;
[1015]         }
[1016] 
[1017]         atom_header = mp4->buffer_pos;
[1018]         atom_name = atom_header + sizeof(uint32_t);
[1019] 
[1020]         ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1021]                        "mp4 atom: %*s @%O:%uL",
[1022]                        (size_t) 4, atom_name, mp4->offset, atom_size);
[1023] 
[1024]         if (atom_size > (uint64_t) (NGX_MAX_OFF_T_VALUE - mp4->offset)
[1025]             || mp4->offset + (off_t) atom_size > end)
[1026]         {
[1027]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1028]                           "\"%s\" mp4 atom too large:%uL",
[1029]                           mp4->file.name.data, atom_size);
[1030]             return NGX_ERROR;
[1031]         }
[1032] 
[1033]         for (n = 0; atom[n].name; n++) {
[1034] 
[1035]             if (ngx_strncmp(atom_name, atom[n].name, 4) == 0) {
[1036] 
[1037]                 ngx_mp4_atom_next(mp4, atom_header_size);
[1038] 
[1039]                 rc = atom[n].handler(mp4, atom_size - atom_header_size);
[1040]                 if (rc != NGX_OK) {
[1041]                     return rc;
[1042]                 }
[1043] 
[1044]                 goto next;
[1045]             }
[1046]         }
[1047] 
[1048]         ngx_mp4_atom_next(mp4, atom_size);
[1049] 
[1050]     next:
[1051]         continue;
[1052]     }
[1053] 
[1054]     return NGX_OK;
[1055] }
[1056] 
[1057] 
[1058] static ngx_int_t
[1059] ngx_http_mp4_read(ngx_http_mp4_file_t *mp4, size_t size)
[1060] {
[1061]     ssize_t  n;
[1062] 
[1063]     if (mp4->buffer_pos + size <= mp4->buffer_end) {
[1064]         return NGX_OK;
[1065]     }
[1066] 
[1067]     if (mp4->offset + (off_t) mp4->buffer_size > mp4->end) {
[1068]         mp4->buffer_size = (size_t) (mp4->end - mp4->offset);
[1069]     }
[1070] 
[1071]     if (mp4->buffer_size < size) {
[1072]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1073]                       "\"%s\" mp4 file truncated", mp4->file.name.data);
[1074]         return NGX_ERROR;
[1075]     }
[1076] 
[1077]     if (mp4->buffer == NULL) {
[1078]         mp4->buffer = ngx_palloc(mp4->request->pool, mp4->buffer_size);
[1079]         if (mp4->buffer == NULL) {
[1080]             return NGX_ERROR;
[1081]         }
[1082] 
[1083]         mp4->buffer_start = mp4->buffer;
[1084]     }
[1085] 
[1086]     n = ngx_read_file(&mp4->file, mp4->buffer_start, mp4->buffer_size,
[1087]                       mp4->offset);
[1088] 
[1089]     if (n == NGX_ERROR) {
[1090]         return NGX_ERROR;
[1091]     }
[1092] 
[1093]     if ((size_t) n != mp4->buffer_size) {
[1094]         ngx_log_error(NGX_LOG_CRIT, mp4->file.log, 0,
[1095]                       ngx_read_file_n " read only %z of %z from \"%s\"",
[1096]                       n, mp4->buffer_size, mp4->file.name.data);
[1097]         return NGX_ERROR;
[1098]     }
[1099] 
[1100]     mp4->buffer_pos = mp4->buffer_start;
[1101]     mp4->buffer_end = mp4->buffer_start + mp4->buffer_size;
[1102] 
[1103]     return NGX_OK;
[1104] }
[1105] 
[1106] 
[1107] static ngx_int_t
[1108] ngx_http_mp4_read_ftyp_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1109] {
[1110]     u_char     *ftyp_atom;
[1111]     size_t      atom_size;
[1112]     ngx_buf_t  *atom;
[1113] 
[1114]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 ftyp atom");
[1115] 
[1116]     if (atom_data_size > 1024
[1117]         || ngx_mp4_atom_data(mp4) + (size_t) atom_data_size > mp4->buffer_end)
[1118]     {
[1119]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1120]                       "\"%s\" mp4 ftyp atom is too large:%uL",
[1121]                       mp4->file.name.data, atom_data_size);
[1122]         return NGX_ERROR;
[1123]     }
[1124] 
[1125]     if (mp4->ftyp_atom.buf) {
[1126]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1127]                       "duplicate mp4 ftyp atom in \"%s\"", mp4->file.name.data);
[1128]         return NGX_ERROR;
[1129]     }
[1130] 
[1131]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[1132] 
[1133]     ftyp_atom = ngx_palloc(mp4->request->pool, atom_size);
[1134]     if (ftyp_atom == NULL) {
[1135]         return NGX_ERROR;
[1136]     }
[1137] 
[1138]     ngx_mp4_set_32value(ftyp_atom, atom_size);
[1139]     ngx_mp4_set_atom_name(ftyp_atom, 'f', 't', 'y', 'p');
[1140] 
[1141]     /*
[1142]      * only moov atom content is guaranteed to be in mp4->buffer
[1143]      * during sending response, so ftyp atom content should be copied
[1144]      */
[1145]     ngx_memcpy(ftyp_atom + sizeof(ngx_mp4_atom_header_t),
[1146]                ngx_mp4_atom_data(mp4), (size_t) atom_data_size);
[1147] 
[1148]     atom = &mp4->ftyp_atom_buf;
[1149]     atom->temporary = 1;
[1150]     atom->pos = ftyp_atom;
[1151]     atom->last = ftyp_atom + atom_size;
[1152] 
[1153]     mp4->ftyp_atom.buf = atom;
[1154]     mp4->ftyp_size = atom_size;
[1155]     mp4->content_length = atom_size;
[1156] 
[1157]     ngx_mp4_atom_next(mp4, atom_data_size);
[1158] 
[1159]     return NGX_OK;
[1160] }
[1161] 
[1162] 
[1163] /*
[1164]  * Small excess buffer to process atoms after moov atom, mp4->buffer_start
[1165]  * will be set to this buffer part after moov atom processing.
[1166]  */
[1167] #define NGX_HTTP_MP4_MOOV_BUFFER_EXCESS  (4 * 1024)
[1168] 
[1169] static ngx_int_t
[1170] ngx_http_mp4_read_moov_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1171] {
[1172]     ngx_int_t             rc;
[1173]     ngx_uint_t            no_mdat;
[1174]     ngx_buf_t            *atom;
[1175]     ngx_http_mp4_conf_t  *conf;
[1176] 
[1177]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 moov atom");
[1178] 
[1179]     no_mdat = (mp4->mdat_atom.buf == NULL);
[1180] 
[1181]     if (no_mdat && mp4->start == 0 && mp4->length == 0) {
[1182]         /*
[1183]          * send original file if moov atom resides before
[1184]          * mdat atom and client requests integral file
[1185]          */
[1186]         return NGX_DECLINED;
[1187]     }
[1188] 
[1189]     if (mp4->moov_atom.buf) {
[1190]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1191]                       "duplicate mp4 moov atom in \"%s\"", mp4->file.name.data);
[1192]         return NGX_ERROR;
[1193]     }
[1194] 
[1195]     conf = ngx_http_get_module_loc_conf(mp4->request, ngx_http_mp4_module);
[1196] 
[1197]     if (atom_data_size > mp4->buffer_size) {
[1198] 
[1199]         if (atom_data_size > conf->max_buffer_size) {
[1200]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1201]                           "\"%s\" mp4 moov atom is too large:%uL, "
[1202]                           "you may want to increase mp4_max_buffer_size",
[1203]                           mp4->file.name.data, atom_data_size);
[1204]             return NGX_ERROR;
[1205]         }
[1206] 
[1207]         ngx_pfree(mp4->request->pool, mp4->buffer);
[1208]         mp4->buffer = NULL;
[1209]         mp4->buffer_pos = NULL;
[1210]         mp4->buffer_end = NULL;
[1211] 
[1212]         mp4->buffer_size = (size_t) atom_data_size
[1213]                          + NGX_HTTP_MP4_MOOV_BUFFER_EXCESS * no_mdat;
[1214]     }
[1215] 
[1216]     if (ngx_http_mp4_read(mp4, (size_t) atom_data_size) != NGX_OK) {
[1217]         return NGX_ERROR;
[1218]     }
[1219] 
[1220]     mp4->trak.elts = &mp4->traks;
[1221]     mp4->trak.size = sizeof(ngx_http_mp4_trak_t);
[1222]     mp4->trak.nalloc = 2;
[1223]     mp4->trak.pool = mp4->request->pool;
[1224] 
[1225]     atom = &mp4->moov_atom_buf;
[1226]     atom->temporary = 1;
[1227]     atom->pos = mp4->moov_atom_header;
[1228]     atom->last = mp4->moov_atom_header + 8;
[1229] 
[1230]     mp4->moov_atom.buf = &mp4->moov_atom_buf;
[1231] 
[1232]     rc = ngx_http_mp4_read_atom(mp4, ngx_http_mp4_moov_atoms, atom_data_size);
[1233] 
[1234]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 moov atom done");
[1235] 
[1236]     if (no_mdat) {
[1237]         mp4->buffer_start = mp4->buffer_pos;
[1238]         mp4->buffer_size = NGX_HTTP_MP4_MOOV_BUFFER_EXCESS;
[1239] 
[1240]         if (mp4->buffer_start + mp4->buffer_size > mp4->buffer_end) {
[1241]             mp4->buffer = NULL;
[1242]             mp4->buffer_pos = NULL;
[1243]             mp4->buffer_end = NULL;
[1244]         }
[1245] 
[1246]     } else {
[1247]         /* skip atoms after moov atom */
[1248]         mp4->offset = mp4->end;
[1249]     }
[1250] 
[1251]     return rc;
[1252] }
[1253] 
[1254] 
[1255] static ngx_int_t
[1256] ngx_http_mp4_read_mdat_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1257] {
[1258]     ngx_buf_t  *data;
[1259] 
[1260]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mdat atom");
[1261] 
[1262]     if (mp4->mdat_atom.buf) {
[1263]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1264]                       "duplicate mp4 mdat atom in \"%s\"", mp4->file.name.data);
[1265]         return NGX_ERROR;
[1266]     }
[1267] 
[1268]     data = &mp4->mdat_data_buf;
[1269]     data->file = &mp4->file;
[1270]     data->in_file = 1;
[1271]     data->last_buf = (mp4->request == mp4->request->main) ? 1 : 0;
[1272]     data->last_in_chain = 1;
[1273]     data->file_last = mp4->offset + atom_data_size;
[1274] 
[1275]     mp4->mdat_atom.buf = &mp4->mdat_atom_buf;
[1276]     mp4->mdat_atom.next = &mp4->mdat_data;
[1277]     mp4->mdat_data.buf = data;
[1278] 
[1279]     if (mp4->trak.nelts) {
[1280]         /* skip atoms after mdat atom */
[1281]         mp4->offset = mp4->end;
[1282] 
[1283]     } else {
[1284]         ngx_mp4_atom_next(mp4, atom_data_size);
[1285]     }
[1286] 
[1287]     return NGX_OK;
[1288] }
[1289] 
[1290] 
[1291] static size_t
[1292] ngx_http_mp4_update_mdat_atom(ngx_http_mp4_file_t *mp4, off_t start_offset,
[1293]     off_t end_offset)
[1294] {
[1295]     off_t       atom_data_size;
[1296]     u_char     *atom_header;
[1297]     uint32_t    atom_header_size;
[1298]     uint64_t    atom_size;
[1299]     ngx_buf_t  *atom;
[1300] 
[1301]     atom_data_size = end_offset - start_offset;
[1302]     mp4->mdat_data.buf->file_pos = start_offset;
[1303]     mp4->mdat_data.buf->file_last = end_offset;
[1304] 
[1305]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1306]                    "mdat new offset @%O:%O", start_offset, atom_data_size);
[1307] 
[1308]     atom_header = mp4->mdat_atom_header;
[1309] 
[1310]     if ((uint64_t) atom_data_size
[1311]         > (uint64_t) 0xffffffff - sizeof(ngx_mp4_atom_header_t))
[1312]     {
[1313]         atom_size = 1;
[1314]         atom_header_size = sizeof(ngx_mp4_atom_header64_t);
[1315]         ngx_mp4_set_64value(atom_header + sizeof(ngx_mp4_atom_header_t),
[1316]                             sizeof(ngx_mp4_atom_header64_t) + atom_data_size);
[1317]     } else {
[1318]         atom_size = sizeof(ngx_mp4_atom_header_t) + atom_data_size;
[1319]         atom_header_size = sizeof(ngx_mp4_atom_header_t);
[1320]     }
[1321] 
[1322]     mp4->content_length += atom_header_size + atom_data_size;
[1323] 
[1324]     ngx_mp4_set_32value(atom_header, atom_size);
[1325]     ngx_mp4_set_atom_name(atom_header, 'm', 'd', 'a', 't');
[1326] 
[1327]     atom = &mp4->mdat_atom_buf;
[1328]     atom->temporary = 1;
[1329]     atom->pos = atom_header;
[1330]     atom->last = atom_header + atom_header_size;
[1331] 
[1332]     return atom_header_size;
[1333] }
[1334] 
[1335] 
[1336] typedef struct {
[1337]     u_char    size[4];
[1338]     u_char    name[4];
[1339]     u_char    version[1];
[1340]     u_char    flags[3];
[1341]     u_char    creation_time[4];
[1342]     u_char    modification_time[4];
[1343]     u_char    timescale[4];
[1344]     u_char    duration[4];
[1345]     u_char    rate[4];
[1346]     u_char    volume[2];
[1347]     u_char    reserved[10];
[1348]     u_char    matrix[36];
[1349]     u_char    preview_time[4];
[1350]     u_char    preview_duration[4];
[1351]     u_char    poster_time[4];
[1352]     u_char    selection_time[4];
[1353]     u_char    selection_duration[4];
[1354]     u_char    current_time[4];
[1355]     u_char    next_track_id[4];
[1356] } ngx_mp4_mvhd_atom_t;
[1357] 
[1358] typedef struct {
[1359]     u_char    size[4];
[1360]     u_char    name[4];
[1361]     u_char    version[1];
[1362]     u_char    flags[3];
[1363]     u_char    creation_time[8];
[1364]     u_char    modification_time[8];
[1365]     u_char    timescale[4];
[1366]     u_char    duration[8];
[1367]     u_char    rate[4];
[1368]     u_char    volume[2];
[1369]     u_char    reserved[10];
[1370]     u_char    matrix[36];
[1371]     u_char    preview_time[4];
[1372]     u_char    preview_duration[4];
[1373]     u_char    poster_time[4];
[1374]     u_char    selection_time[4];
[1375]     u_char    selection_duration[4];
[1376]     u_char    current_time[4];
[1377]     u_char    next_track_id[4];
[1378] } ngx_mp4_mvhd64_atom_t;
[1379] 
[1380] 
[1381] static ngx_int_t
[1382] ngx_http_mp4_read_mvhd_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1383] {
[1384]     u_char                 *atom_header;
[1385]     size_t                  atom_size;
[1386]     uint32_t                timescale;
[1387]     uint64_t                duration, start_time, length_time;
[1388]     ngx_buf_t              *atom;
[1389]     ngx_mp4_mvhd_atom_t    *mvhd_atom;
[1390]     ngx_mp4_mvhd64_atom_t  *mvhd64_atom;
[1391] 
[1392]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mvhd atom");
[1393] 
[1394]     if (mp4->mvhd_atom.buf) {
[1395]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1396]                       "duplicate mp4 mvhd atom in \"%s\"", mp4->file.name.data);
[1397]         return NGX_ERROR;
[1398]     }
[1399] 
[1400]     atom_header = ngx_mp4_atom_header(mp4);
[1401]     mvhd_atom = (ngx_mp4_mvhd_atom_t *) atom_header;
[1402]     mvhd64_atom = (ngx_mp4_mvhd64_atom_t *) atom_header;
[1403]     ngx_mp4_set_atom_name(atom_header, 'm', 'v', 'h', 'd');
[1404] 
[1405]     if (ngx_mp4_atom_data_size(ngx_mp4_mvhd_atom_t) > atom_data_size) {
[1406]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1407]                       "\"%s\" mp4 mvhd atom too small", mp4->file.name.data);
[1408]         return NGX_ERROR;
[1409]     }
[1410] 
[1411]     if (mvhd_atom->version[0] == 0) {
[1412]         /* version 0: 32-bit duration */
[1413]         timescale = ngx_mp4_get_32value(mvhd_atom->timescale);
[1414]         duration = ngx_mp4_get_32value(mvhd_atom->duration);
[1415] 
[1416]     } else {
[1417]         /* version 1: 64-bit duration */
[1418] 
[1419]         if (ngx_mp4_atom_data_size(ngx_mp4_mvhd64_atom_t) > atom_data_size) {
[1420]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1421]                           "\"%s\" mp4 mvhd atom too small",
[1422]                           mp4->file.name.data);
[1423]             return NGX_ERROR;
[1424]         }
[1425] 
[1426]         timescale = ngx_mp4_get_32value(mvhd64_atom->timescale);
[1427]         duration = ngx_mp4_get_64value(mvhd64_atom->duration);
[1428]     }
[1429] 
[1430]     mp4->timescale = timescale;
[1431] 
[1432]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1433]                    "mvhd timescale:%uD, duration:%uL, time:%.3fs",
[1434]                    timescale, duration, (double) duration / timescale);
[1435] 
[1436]     start_time = (uint64_t) mp4->start * timescale / 1000;
[1437] 
[1438]     if (duration < start_time) {
[1439]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1440]                       "\"%s\" mp4 start time exceeds file duration",
[1441]                       mp4->file.name.data);
[1442]         return NGX_ERROR;
[1443]     }
[1444] 
[1445]     duration -= start_time;
[1446] 
[1447]     if (mp4->length) {
[1448]         length_time = (uint64_t) mp4->length * timescale / 1000;
[1449] 
[1450]         if (duration > length_time) {
[1451]             duration = length_time;
[1452]         }
[1453]     }
[1454] 
[1455]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1456]                    "mvhd new duration:%uL, time:%.3fs",
[1457]                    duration, (double) duration / timescale);
[1458] 
[1459]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[1460]     ngx_mp4_set_32value(mvhd_atom->size, atom_size);
[1461] 
[1462]     if (mvhd_atom->version[0] == 0) {
[1463]         ngx_mp4_set_32value(mvhd_atom->duration, duration);
[1464] 
[1465]     } else {
[1466]         ngx_mp4_set_64value(mvhd64_atom->duration, duration);
[1467]     }
[1468] 
[1469]     atom = &mp4->mvhd_atom_buf;
[1470]     atom->temporary = 1;
[1471]     atom->pos = atom_header;
[1472]     atom->last = atom_header + atom_size;
[1473] 
[1474]     mp4->mvhd_atom.buf = atom;
[1475] 
[1476]     ngx_mp4_atom_next(mp4, atom_data_size);
[1477] 
[1478]     return NGX_OK;
[1479] }
[1480] 
[1481] 
[1482] static ngx_int_t
[1483] ngx_http_mp4_read_trak_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1484] {
[1485]     u_char               *atom_header, *atom_end;
[1486]     off_t                 atom_file_end;
[1487]     ngx_int_t             rc;
[1488]     ngx_buf_t            *atom;
[1489]     ngx_http_mp4_trak_t  *trak;
[1490] 
[1491]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 trak atom");
[1492] 
[1493]     trak = ngx_array_push(&mp4->trak);
[1494]     if (trak == NULL) {
[1495]         return NGX_ERROR;
[1496]     }
[1497] 
[1498]     ngx_memzero(trak, sizeof(ngx_http_mp4_trak_t));
[1499] 
[1500]     atom_header = ngx_mp4_atom_header(mp4);
[1501]     ngx_mp4_set_atom_name(atom_header, 't', 'r', 'a', 'k');
[1502] 
[1503]     atom = &trak->trak_atom_buf;
[1504]     atom->temporary = 1;
[1505]     atom->pos = atom_header;
[1506]     atom->last = atom_header + sizeof(ngx_mp4_atom_header_t);
[1507] 
[1508]     trak->out[NGX_HTTP_MP4_TRAK_ATOM].buf = atom;
[1509] 
[1510]     atom_end = mp4->buffer_pos + (size_t) atom_data_size;
[1511]     atom_file_end = mp4->offset + atom_data_size;
[1512] 
[1513]     rc = ngx_http_mp4_read_atom(mp4, ngx_http_mp4_trak_atoms, atom_data_size);
[1514] 
[1515]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1516]                    "mp4 trak atom: %i", rc);
[1517] 
[1518]     if (rc == NGX_DECLINED) {
[1519]         /* skip this trak */
[1520]         ngx_memzero(trak, sizeof(ngx_http_mp4_trak_t));
[1521]         mp4->trak.nelts--;
[1522]         mp4->buffer_pos = atom_end;
[1523]         mp4->offset = atom_file_end;
[1524]         return NGX_OK;
[1525]     }
[1526] 
[1527]     return rc;
[1528] }
[1529] 
[1530] 
[1531] static void
[1532] ngx_http_mp4_update_trak_atom(ngx_http_mp4_file_t *mp4,
[1533]     ngx_http_mp4_trak_t *trak)
[1534] {
[1535]     ngx_buf_t  *atom;
[1536] 
[1537]     trak->size += sizeof(ngx_mp4_atom_header_t);
[1538]     atom = &trak->trak_atom_buf;
[1539]     ngx_mp4_set_32value(atom->pos, trak->size);
[1540] }
[1541] 
[1542] 
[1543] static ngx_int_t
[1544] ngx_http_mp4_read_cmov_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1545] {
[1546]     ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1547]                   "\"%s\" mp4 compressed moov atom (cmov) is not supported",
[1548]                   mp4->file.name.data);
[1549] 
[1550]     return NGX_ERROR;
[1551] }
[1552] 
[1553] 
[1554] typedef struct {
[1555]     u_char    size[4];
[1556]     u_char    name[4];
[1557]     u_char    version[1];
[1558]     u_char    flags[3];
[1559]     u_char    creation_time[4];
[1560]     u_char    modification_time[4];
[1561]     u_char    track_id[4];
[1562]     u_char    reserved1[4];
[1563]     u_char    duration[4];
[1564]     u_char    reserved2[8];
[1565]     u_char    layer[2];
[1566]     u_char    group[2];
[1567]     u_char    volume[2];
[1568]     u_char    reserved3[2];
[1569]     u_char    matrix[36];
[1570]     u_char    width[4];
[1571]     u_char    height[4];
[1572] } ngx_mp4_tkhd_atom_t;
[1573] 
[1574] typedef struct {
[1575]     u_char    size[4];
[1576]     u_char    name[4];
[1577]     u_char    version[1];
[1578]     u_char    flags[3];
[1579]     u_char    creation_time[8];
[1580]     u_char    modification_time[8];
[1581]     u_char    track_id[4];
[1582]     u_char    reserved1[4];
[1583]     u_char    duration[8];
[1584]     u_char    reserved2[8];
[1585]     u_char    layer[2];
[1586]     u_char    group[2];
[1587]     u_char    volume[2];
[1588]     u_char    reserved3[2];
[1589]     u_char    matrix[36];
[1590]     u_char    width[4];
[1591]     u_char    height[4];
[1592] } ngx_mp4_tkhd64_atom_t;
[1593] 
[1594] 
[1595] static ngx_int_t
[1596] ngx_http_mp4_read_tkhd_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1597] {
[1598]     u_char                 *atom_header;
[1599]     size_t                  atom_size;
[1600]     uint64_t                duration, start_time, length_time;
[1601]     ngx_buf_t              *atom;
[1602]     ngx_http_mp4_trak_t    *trak;
[1603]     ngx_mp4_tkhd_atom_t    *tkhd_atom;
[1604]     ngx_mp4_tkhd64_atom_t  *tkhd64_atom;
[1605] 
[1606]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 tkhd atom");
[1607] 
[1608]     atom_header = ngx_mp4_atom_header(mp4);
[1609]     tkhd_atom = (ngx_mp4_tkhd_atom_t *) atom_header;
[1610]     tkhd64_atom = (ngx_mp4_tkhd64_atom_t *) atom_header;
[1611]     ngx_mp4_set_atom_name(tkhd_atom, 't', 'k', 'h', 'd');
[1612] 
[1613]     if (ngx_mp4_atom_data_size(ngx_mp4_tkhd_atom_t) > atom_data_size) {
[1614]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1615]                       "\"%s\" mp4 tkhd atom too small", mp4->file.name.data);
[1616]         return NGX_ERROR;
[1617]     }
[1618] 
[1619]     if (tkhd_atom->version[0] == 0) {
[1620]         /* version 0: 32-bit duration */
[1621]         duration = ngx_mp4_get_32value(tkhd_atom->duration);
[1622] 
[1623]     } else {
[1624]         /* version 1: 64-bit duration */
[1625] 
[1626]         if (ngx_mp4_atom_data_size(ngx_mp4_tkhd64_atom_t) > atom_data_size) {
[1627]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1628]                           "\"%s\" mp4 tkhd atom too small",
[1629]                           mp4->file.name.data);
[1630]             return NGX_ERROR;
[1631]         }
[1632] 
[1633]         duration = ngx_mp4_get_64value(tkhd64_atom->duration);
[1634]     }
[1635] 
[1636]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1637]                    "tkhd duration:%uL, time:%.3fs",
[1638]                    duration, (double) duration / mp4->timescale);
[1639] 
[1640]     start_time = (uint64_t) mp4->start * mp4->timescale / 1000;
[1641] 
[1642]     if (duration <= start_time) {
[1643]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1644]                        "tkhd duration is less than start time");
[1645]         return NGX_DECLINED;
[1646]     }
[1647] 
[1648]     duration -= start_time;
[1649] 
[1650]     if (mp4->length) {
[1651]         length_time = (uint64_t) mp4->length * mp4->timescale / 1000;
[1652] 
[1653]         if (duration > length_time) {
[1654]             duration = length_time;
[1655]         }
[1656]     }
[1657] 
[1658]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1659]                    "tkhd new duration:%uL, time:%.3fs",
[1660]                    duration, (double) duration / mp4->timescale);
[1661] 
[1662]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[1663] 
[1664]     trak = ngx_mp4_last_trak(mp4);
[1665] 
[1666]     if (trak->out[NGX_HTTP_MP4_TKHD_ATOM].buf) {
[1667]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1668]                       "duplicate mp4 tkhd atom in \"%s\"", mp4->file.name.data);
[1669]         return NGX_ERROR;
[1670]     }
[1671] 
[1672]     trak->tkhd_size = atom_size;
[1673]     trak->movie_duration = duration;
[1674] 
[1675]     ngx_mp4_set_32value(tkhd_atom->size, atom_size);
[1676] 
[1677]     if (tkhd_atom->version[0] == 0) {
[1678]         ngx_mp4_set_32value(tkhd_atom->duration, duration);
[1679] 
[1680]     } else {
[1681]         ngx_mp4_set_64value(tkhd64_atom->duration, duration);
[1682]     }
[1683] 
[1684]     atom = &trak->tkhd_atom_buf;
[1685]     atom->temporary = 1;
[1686]     atom->pos = atom_header;
[1687]     atom->last = atom_header + atom_size;
[1688] 
[1689]     trak->out[NGX_HTTP_MP4_TKHD_ATOM].buf = atom;
[1690] 
[1691]     ngx_mp4_atom_next(mp4, atom_data_size);
[1692] 
[1693]     return NGX_OK;
[1694] }
[1695] 
[1696] 
[1697] static ngx_int_t
[1698] ngx_http_mp4_read_mdia_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1699] {
[1700]     u_char               *atom_header;
[1701]     ngx_buf_t            *atom;
[1702]     ngx_http_mp4_trak_t  *trak;
[1703] 
[1704]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "process mdia atom");
[1705] 
[1706]     atom_header = ngx_mp4_atom_header(mp4);
[1707]     ngx_mp4_set_atom_name(atom_header, 'm', 'd', 'i', 'a');
[1708] 
[1709]     trak = ngx_mp4_last_trak(mp4);
[1710] 
[1711]     if (trak->out[NGX_HTTP_MP4_MDIA_ATOM].buf) {
[1712]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1713]                       "duplicate mp4 mdia atom in \"%s\"", mp4->file.name.data);
[1714]         return NGX_ERROR;
[1715]     }
[1716] 
[1717]     atom = &trak->mdia_atom_buf;
[1718]     atom->temporary = 1;
[1719]     atom->pos = atom_header;
[1720]     atom->last = atom_header + sizeof(ngx_mp4_atom_header_t);
[1721] 
[1722]     trak->out[NGX_HTTP_MP4_MDIA_ATOM].buf = atom;
[1723] 
[1724]     return ngx_http_mp4_read_atom(mp4, ngx_http_mp4_mdia_atoms, atom_data_size);
[1725] }
[1726] 
[1727] 
[1728] static void
[1729] ngx_http_mp4_update_mdia_atom(ngx_http_mp4_file_t *mp4,
[1730]     ngx_http_mp4_trak_t *trak)
[1731] {
[1732]     ngx_buf_t  *atom;
[1733] 
[1734]     trak->size += sizeof(ngx_mp4_atom_header_t);
[1735]     atom = &trak->mdia_atom_buf;
[1736]     ngx_mp4_set_32value(atom->pos, trak->size);
[1737] }
[1738] 
[1739] 
[1740] typedef struct {
[1741]     u_char    size[4];
[1742]     u_char    name[4];
[1743]     u_char    version[1];
[1744]     u_char    flags[3];
[1745]     u_char    creation_time[4];
[1746]     u_char    modification_time[4];
[1747]     u_char    timescale[4];
[1748]     u_char    duration[4];
[1749]     u_char    language[2];
[1750]     u_char    quality[2];
[1751] } ngx_mp4_mdhd_atom_t;
[1752] 
[1753] typedef struct {
[1754]     u_char    size[4];
[1755]     u_char    name[4];
[1756]     u_char    version[1];
[1757]     u_char    flags[3];
[1758]     u_char    creation_time[8];
[1759]     u_char    modification_time[8];
[1760]     u_char    timescale[4];
[1761]     u_char    duration[8];
[1762]     u_char    language[2];
[1763]     u_char    quality[2];
[1764] } ngx_mp4_mdhd64_atom_t;
[1765] 
[1766] 
[1767] static ngx_int_t
[1768] ngx_http_mp4_read_mdhd_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1769] {
[1770]     u_char                 *atom_header;
[1771]     size_t                  atom_size;
[1772]     uint32_t                timescale;
[1773]     uint64_t                duration, start_time, length_time;
[1774]     ngx_buf_t              *atom;
[1775]     ngx_http_mp4_trak_t    *trak;
[1776]     ngx_mp4_mdhd_atom_t    *mdhd_atom;
[1777]     ngx_mp4_mdhd64_atom_t  *mdhd64_atom;
[1778] 
[1779]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 mdhd atom");
[1780] 
[1781]     atom_header = ngx_mp4_atom_header(mp4);
[1782]     mdhd_atom = (ngx_mp4_mdhd_atom_t *) atom_header;
[1783]     mdhd64_atom = (ngx_mp4_mdhd64_atom_t *) atom_header;
[1784]     ngx_mp4_set_atom_name(mdhd_atom, 'm', 'd', 'h', 'd');
[1785] 
[1786]     if (ngx_mp4_atom_data_size(ngx_mp4_mdhd_atom_t) > atom_data_size) {
[1787]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1788]                       "\"%s\" mp4 mdhd atom too small", mp4->file.name.data);
[1789]         return NGX_ERROR;
[1790]     }
[1791] 
[1792]     if (mdhd_atom->version[0] == 0) {
[1793]         /* version 0: everything is 32-bit */
[1794]         timescale = ngx_mp4_get_32value(mdhd_atom->timescale);
[1795]         duration = ngx_mp4_get_32value(mdhd_atom->duration);
[1796] 
[1797]     } else {
[1798]         /* version 1: 64-bit duration and 32-bit timescale */
[1799] 
[1800]         if (ngx_mp4_atom_data_size(ngx_mp4_mdhd64_atom_t) > atom_data_size) {
[1801]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1802]                           "\"%s\" mp4 mdhd atom too small",
[1803]                           mp4->file.name.data);
[1804]             return NGX_ERROR;
[1805]         }
[1806] 
[1807]         timescale = ngx_mp4_get_32value(mdhd64_atom->timescale);
[1808]         duration = ngx_mp4_get_64value(mdhd64_atom->duration);
[1809]     }
[1810] 
[1811]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1812]                    "mdhd timescale:%uD, duration:%uL, time:%.3fs",
[1813]                    timescale, duration, (double) duration / timescale);
[1814] 
[1815]     start_time = (uint64_t) mp4->start * timescale / 1000;
[1816] 
[1817]     if (duration <= start_time) {
[1818]         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1819]                        "mdhd duration is less than start time");
[1820]         return NGX_DECLINED;
[1821]     }
[1822] 
[1823]     duration -= start_time;
[1824] 
[1825]     if (mp4->length) {
[1826]         length_time = (uint64_t) mp4->length * timescale / 1000;
[1827] 
[1828]         if (duration > length_time) {
[1829]             duration = length_time;
[1830]         }
[1831]     }
[1832] 
[1833]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[1834]                    "mdhd new duration:%uL, time:%.3fs",
[1835]                    duration, (double) duration / timescale);
[1836] 
[1837]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[1838] 
[1839]     trak = ngx_mp4_last_trak(mp4);
[1840] 
[1841]     if (trak->out[NGX_HTTP_MP4_MDHD_ATOM].buf) {
[1842]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1843]                       "duplicate mp4 mdhd atom in \"%s\"", mp4->file.name.data);
[1844]         return NGX_ERROR;
[1845]     }
[1846] 
[1847]     trak->mdhd_size = atom_size;
[1848]     trak->timescale = timescale;
[1849]     trak->duration = duration;
[1850] 
[1851]     ngx_mp4_set_32value(mdhd_atom->size, atom_size);
[1852] 
[1853]     atom = &trak->mdhd_atom_buf;
[1854]     atom->temporary = 1;
[1855]     atom->pos = atom_header;
[1856]     atom->last = atom_header + atom_size;
[1857] 
[1858]     trak->out[NGX_HTTP_MP4_MDHD_ATOM].buf = atom;
[1859] 
[1860]     ngx_mp4_atom_next(mp4, atom_data_size);
[1861] 
[1862]     return NGX_OK;
[1863] }
[1864] 
[1865] 
[1866] static void
[1867] ngx_http_mp4_update_mdhd_atom(ngx_http_mp4_file_t *mp4,
[1868]             ngx_http_mp4_trak_t *trak)
[1869] {
[1870]     ngx_buf_t              *atom;
[1871]     ngx_mp4_mdhd_atom_t    *mdhd_atom;
[1872]     ngx_mp4_mdhd64_atom_t  *mdhd64_atom;
[1873] 
[1874]     atom = trak->out[NGX_HTTP_MP4_MDHD_ATOM].buf;
[1875]     if (atom == NULL) {
[1876]         return;
[1877]     }
[1878] 
[1879]     mdhd_atom = (ngx_mp4_mdhd_atom_t *) atom->pos;
[1880]     mdhd64_atom = (ngx_mp4_mdhd64_atom_t *) atom->pos;
[1881] 
[1882]     if (mdhd_atom->version[0] == 0) {
[1883]         ngx_mp4_set_32value(mdhd_atom->duration, trak->duration);
[1884] 
[1885]     } else {
[1886]         ngx_mp4_set_64value(mdhd64_atom->duration, trak->duration);
[1887]     }
[1888] 
[1889]     trak->size += trak->mdhd_size;
[1890] }
[1891] 
[1892] 
[1893] static ngx_int_t
[1894] ngx_http_mp4_read_hdlr_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1895] {
[1896]     u_char              *atom_header;
[1897]     size_t               atom_size;
[1898]     ngx_buf_t            *atom;
[1899]     ngx_http_mp4_trak_t  *trak;
[1900] 
[1901]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 hdlr atom");
[1902] 
[1903]     atom_header = ngx_mp4_atom_header(mp4);
[1904]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[1905]     ngx_mp4_set_32value(atom_header, atom_size);
[1906]     ngx_mp4_set_atom_name(atom_header, 'h', 'd', 'l', 'r');
[1907] 
[1908]     trak = ngx_mp4_last_trak(mp4);
[1909] 
[1910]     if (trak->out[NGX_HTTP_MP4_HDLR_ATOM].buf) {
[1911]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1912]                       "duplicate mp4 hdlr atom in \"%s\"", mp4->file.name.data);
[1913]         return NGX_ERROR;
[1914]     }
[1915] 
[1916]     atom = &trak->hdlr_atom_buf;
[1917]     atom->temporary = 1;
[1918]     atom->pos = atom_header;
[1919]     atom->last = atom_header + atom_size;
[1920] 
[1921]     trak->hdlr_size = atom_size;
[1922]     trak->out[NGX_HTTP_MP4_HDLR_ATOM].buf = atom;
[1923] 
[1924]     ngx_mp4_atom_next(mp4, atom_data_size);
[1925] 
[1926]     return NGX_OK;
[1927] }
[1928] 
[1929] 
[1930] static ngx_int_t
[1931] ngx_http_mp4_read_minf_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1932] {
[1933]     u_char               *atom_header;
[1934]     ngx_buf_t            *atom;
[1935]     ngx_http_mp4_trak_t  *trak;
[1936] 
[1937]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "process minf atom");
[1938] 
[1939]     atom_header = ngx_mp4_atom_header(mp4);
[1940]     ngx_mp4_set_atom_name(atom_header, 'm', 'i', 'n', 'f');
[1941] 
[1942]     trak = ngx_mp4_last_trak(mp4);
[1943] 
[1944]     if (trak->out[NGX_HTTP_MP4_MINF_ATOM].buf) {
[1945]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1946]                       "duplicate mp4 minf atom in \"%s\"", mp4->file.name.data);
[1947]         return NGX_ERROR;
[1948]     }
[1949] 
[1950]     atom = &trak->minf_atom_buf;
[1951]     atom->temporary = 1;
[1952]     atom->pos = atom_header;
[1953]     atom->last = atom_header + sizeof(ngx_mp4_atom_header_t);
[1954] 
[1955]     trak->out[NGX_HTTP_MP4_MINF_ATOM].buf = atom;
[1956] 
[1957]     return ngx_http_mp4_read_atom(mp4, ngx_http_mp4_minf_atoms, atom_data_size);
[1958] }
[1959] 
[1960] 
[1961] static void
[1962] ngx_http_mp4_update_minf_atom(ngx_http_mp4_file_t *mp4,
[1963]     ngx_http_mp4_trak_t *trak)
[1964] {
[1965]     ngx_buf_t  *atom;
[1966] 
[1967]     trak->size += sizeof(ngx_mp4_atom_header_t)
[1968]                + trak->vmhd_size
[1969]                + trak->smhd_size
[1970]                + trak->dinf_size;
[1971]     atom = &trak->minf_atom_buf;
[1972]     ngx_mp4_set_32value(atom->pos, trak->size);
[1973] }
[1974] 
[1975] 
[1976] static ngx_int_t
[1977] ngx_http_mp4_read_vmhd_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[1978] {
[1979]     u_char              *atom_header;
[1980]     size_t               atom_size;
[1981]     ngx_buf_t            *atom;
[1982]     ngx_http_mp4_trak_t  *trak;
[1983] 
[1984]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 vmhd atom");
[1985] 
[1986]     atom_header = ngx_mp4_atom_header(mp4);
[1987]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[1988]     ngx_mp4_set_32value(atom_header, atom_size);
[1989]     ngx_mp4_set_atom_name(atom_header, 'v', 'm', 'h', 'd');
[1990] 
[1991]     trak = ngx_mp4_last_trak(mp4);
[1992] 
[1993]     if (trak->out[NGX_HTTP_MP4_VMHD_ATOM].buf
[1994]         || trak->out[NGX_HTTP_MP4_SMHD_ATOM].buf)
[1995]     {
[1996]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[1997]                       "duplicate mp4 vmhd/smhd atom in \"%s\"",
[1998]                       mp4->file.name.data);
[1999]         return NGX_ERROR;
[2000]     }
[2001] 
[2002]     atom = &trak->vmhd_atom_buf;
[2003]     atom->temporary = 1;
[2004]     atom->pos = atom_header;
[2005]     atom->last = atom_header + atom_size;
[2006] 
[2007]     trak->vmhd_size += atom_size;
[2008]     trak->out[NGX_HTTP_MP4_VMHD_ATOM].buf = atom;
[2009] 
[2010]     ngx_mp4_atom_next(mp4, atom_data_size);
[2011] 
[2012]     return NGX_OK;
[2013] }
[2014] 
[2015] 
[2016] static ngx_int_t
[2017] ngx_http_mp4_read_smhd_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2018] {
[2019]     u_char              *atom_header;
[2020]     size_t               atom_size;
[2021]     ngx_buf_t            *atom;
[2022]     ngx_http_mp4_trak_t  *trak;
[2023] 
[2024]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 smhd atom");
[2025] 
[2026]     atom_header = ngx_mp4_atom_header(mp4);
[2027]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[2028]     ngx_mp4_set_32value(atom_header, atom_size);
[2029]     ngx_mp4_set_atom_name(atom_header, 's', 'm', 'h', 'd');
[2030] 
[2031]     trak = ngx_mp4_last_trak(mp4);
[2032] 
[2033]     if (trak->out[NGX_HTTP_MP4_VMHD_ATOM].buf
[2034]         || trak->out[NGX_HTTP_MP4_SMHD_ATOM].buf)
[2035]     {
[2036]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2037]                       "duplicate mp4 vmhd/smhd atom in \"%s\"",
[2038]                       mp4->file.name.data);
[2039]         return NGX_ERROR;
[2040]     }
[2041] 
[2042]     atom = &trak->smhd_atom_buf;
[2043]     atom->temporary = 1;
[2044]     atom->pos = atom_header;
[2045]     atom->last = atom_header + atom_size;
[2046] 
[2047]     trak->smhd_size += atom_size;
[2048]     trak->out[NGX_HTTP_MP4_SMHD_ATOM].buf = atom;
[2049] 
[2050]     ngx_mp4_atom_next(mp4, atom_data_size);
[2051] 
[2052]     return NGX_OK;
[2053] }
[2054] 
[2055] 
[2056] static ngx_int_t
[2057] ngx_http_mp4_read_dinf_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2058] {
[2059]     u_char              *atom_header;
[2060]     size_t               atom_size;
[2061]     ngx_buf_t            *atom;
[2062]     ngx_http_mp4_trak_t  *trak;
[2063] 
[2064]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 dinf atom");
[2065] 
[2066]     atom_header = ngx_mp4_atom_header(mp4);
[2067]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[2068]     ngx_mp4_set_32value(atom_header, atom_size);
[2069]     ngx_mp4_set_atom_name(atom_header, 'd', 'i', 'n', 'f');
[2070] 
[2071]     trak = ngx_mp4_last_trak(mp4);
[2072] 
[2073]     if (trak->out[NGX_HTTP_MP4_DINF_ATOM].buf) {
[2074]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2075]                       "duplicate mp4 dinf atom in \"%s\"", mp4->file.name.data);
[2076]         return NGX_ERROR;
[2077]     }
[2078] 
[2079]     atom = &trak->dinf_atom_buf;
[2080]     atom->temporary = 1;
[2081]     atom->pos = atom_header;
[2082]     atom->last = atom_header + atom_size;
[2083] 
[2084]     trak->dinf_size += atom_size;
[2085]     trak->out[NGX_HTTP_MP4_DINF_ATOM].buf = atom;
[2086] 
[2087]     ngx_mp4_atom_next(mp4, atom_data_size);
[2088] 
[2089]     return NGX_OK;
[2090] }
[2091] 
[2092] 
[2093] static ngx_int_t
[2094] ngx_http_mp4_read_stbl_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2095] {
[2096]     u_char               *atom_header;
[2097]     ngx_buf_t            *atom;
[2098]     ngx_http_mp4_trak_t  *trak;
[2099] 
[2100]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "process stbl atom");
[2101] 
[2102]     atom_header = ngx_mp4_atom_header(mp4);
[2103]     ngx_mp4_set_atom_name(atom_header, 's', 't', 'b', 'l');
[2104] 
[2105]     trak = ngx_mp4_last_trak(mp4);
[2106] 
[2107]     if (trak->out[NGX_HTTP_MP4_STBL_ATOM].buf) {
[2108]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2109]                       "duplicate mp4 stbl atom in \"%s\"", mp4->file.name.data);
[2110]         return NGX_ERROR;
[2111]     }
[2112] 
[2113]     atom = &trak->stbl_atom_buf;
[2114]     atom->temporary = 1;
[2115]     atom->pos = atom_header;
[2116]     atom->last = atom_header + sizeof(ngx_mp4_atom_header_t);
[2117] 
[2118]     trak->out[NGX_HTTP_MP4_STBL_ATOM].buf = atom;
[2119] 
[2120]     return ngx_http_mp4_read_atom(mp4, ngx_http_mp4_stbl_atoms, atom_data_size);
[2121] }
[2122] 
[2123] 
[2124] static void
[2125] ngx_http_mp4_update_edts_atom(ngx_http_mp4_file_t *mp4,
[2126]     ngx_http_mp4_trak_t *trak)
[2127] {
[2128]     ngx_buf_t            *atom;
[2129]     ngx_mp4_elst_atom_t  *elst_atom;
[2130]     ngx_mp4_edts_atom_t  *edts_atom;
[2131] 
[2132]     if (trak->prefix == 0) {
[2133]         return;
[2134]     }
[2135] 
[2136]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2137]                    "mp4 edts atom update prefix:%uL", trak->prefix);
[2138] 
[2139]     edts_atom = &trak->edts_atom;
[2140]     ngx_mp4_set_32value(edts_atom->size, sizeof(ngx_mp4_edts_atom_t)
[2141]                                          + sizeof(ngx_mp4_elst_atom_t));
[2142]     ngx_mp4_set_atom_name(edts_atom, 'e', 'd', 't', 's');
[2143] 
[2144]     atom = &trak->edts_atom_buf;
[2145]     atom->temporary = 1;
[2146]     atom->pos = (u_char *) edts_atom;
[2147]     atom->last = (u_char *) edts_atom + sizeof(ngx_mp4_edts_atom_t);
[2148] 
[2149]     trak->out[NGX_HTTP_MP4_EDTS_ATOM].buf = atom;
[2150] 
[2151]     elst_atom = &trak->elst_atom;
[2152]     ngx_mp4_set_32value(elst_atom->size, sizeof(ngx_mp4_elst_atom_t));
[2153]     ngx_mp4_set_atom_name(elst_atom, 'e', 'l', 's', 't');
[2154] 
[2155]     elst_atom->version[0] = 1;
[2156]     elst_atom->flags[0] = 0;
[2157]     elst_atom->flags[1] = 0;
[2158]     elst_atom->flags[2] = 0;
[2159] 
[2160]     ngx_mp4_set_32value(elst_atom->entries, 1);
[2161]     ngx_mp4_set_64value(elst_atom->duration, trak->movie_duration);
[2162]     ngx_mp4_set_64value(elst_atom->media_time, trak->prefix);
[2163]     ngx_mp4_set_16value(elst_atom->media_rate, 1);
[2164]     ngx_mp4_set_16value(elst_atom->reserved, 0);
[2165] 
[2166]     atom = &trak->elst_atom_buf;
[2167]     atom->temporary = 1;
[2168]     atom->pos = (u_char *) elst_atom;
[2169]     atom->last = (u_char *) elst_atom + sizeof(ngx_mp4_elst_atom_t);
[2170] 
[2171]     trak->out[NGX_HTTP_MP4_ELST_ATOM].buf = atom;
[2172] 
[2173]     trak->size += sizeof(ngx_mp4_edts_atom_t) + sizeof(ngx_mp4_elst_atom_t);
[2174] }
[2175] 
[2176] 
[2177] static void
[2178] ngx_http_mp4_update_stbl_atom(ngx_http_mp4_file_t *mp4,
[2179]     ngx_http_mp4_trak_t *trak)
[2180] {
[2181]     ngx_buf_t  *atom;
[2182] 
[2183]     trak->size += sizeof(ngx_mp4_atom_header_t);
[2184]     atom = &trak->stbl_atom_buf;
[2185]     ngx_mp4_set_32value(atom->pos, trak->size);
[2186] }
[2187] 
[2188] 
[2189] typedef struct {
[2190]     u_char    size[4];
[2191]     u_char    name[4];
[2192]     u_char    version[1];
[2193]     u_char    flags[3];
[2194]     u_char    entries[4];
[2195] 
[2196]     u_char    media_size[4];
[2197]     u_char    media_name[4];
[2198] } ngx_mp4_stsd_atom_t;
[2199] 
[2200] 
[2201] static ngx_int_t
[2202] ngx_http_mp4_read_stsd_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2203] {
[2204]     u_char               *atom_header, *atom_table;
[2205]     size_t                atom_size;
[2206]     ngx_buf_t            *atom;
[2207]     ngx_mp4_stsd_atom_t  *stsd_atom;
[2208]     ngx_http_mp4_trak_t  *trak;
[2209] 
[2210]     /* sample description atom */
[2211] 
[2212]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsd atom");
[2213] 
[2214]     atom_header = ngx_mp4_atom_header(mp4);
[2215]     stsd_atom = (ngx_mp4_stsd_atom_t *) atom_header;
[2216]     atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[2217]     atom_table = atom_header + atom_size;
[2218]     ngx_mp4_set_32value(stsd_atom->size, atom_size);
[2219]     ngx_mp4_set_atom_name(stsd_atom, 's', 't', 's', 'd');
[2220] 
[2221]     if (ngx_mp4_atom_data_size(ngx_mp4_stsd_atom_t) > atom_data_size) {
[2222]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2223]                       "\"%s\" mp4 stsd atom too small", mp4->file.name.data);
[2224]         return NGX_ERROR;
[2225]     }
[2226] 
[2227]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2228]                    "stsd entries:%uD, media:%*s",
[2229]                    ngx_mp4_get_32value(stsd_atom->entries),
[2230]                    (size_t) 4, stsd_atom->media_name);
[2231] 
[2232]     trak = ngx_mp4_last_trak(mp4);
[2233] 
[2234]     if (trak->out[NGX_HTTP_MP4_STSD_ATOM].buf) {
[2235]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2236]                       "duplicate mp4 stsd atom in \"%s\"", mp4->file.name.data);
[2237]         return NGX_ERROR;
[2238]     }
[2239] 
[2240]     atom = &trak->stsd_atom_buf;
[2241]     atom->temporary = 1;
[2242]     atom->pos = atom_header;
[2243]     atom->last = atom_table;
[2244] 
[2245]     trak->out[NGX_HTTP_MP4_STSD_ATOM].buf = atom;
[2246]     trak->size += atom_size;
[2247] 
[2248]     ngx_mp4_atom_next(mp4, atom_data_size);
[2249] 
[2250]     return NGX_OK;
[2251] }
[2252] 
[2253] 
[2254] typedef struct {
[2255]     u_char    size[4];
[2256]     u_char    name[4];
[2257]     u_char    version[1];
[2258]     u_char    flags[3];
[2259]     u_char    entries[4];
[2260] } ngx_mp4_stts_atom_t;
[2261] 
[2262] typedef struct {
[2263]     u_char    count[4];
[2264]     u_char    duration[4];
[2265] } ngx_mp4_stts_entry_t;
[2266] 
[2267] 
[2268] static ngx_int_t
[2269] ngx_http_mp4_read_stts_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2270] {
[2271]     u_char               *atom_header, *atom_table, *atom_end;
[2272]     uint32_t              entries;
[2273]     ngx_buf_t            *atom, *data;
[2274]     ngx_mp4_stts_atom_t  *stts_atom;
[2275]     ngx_http_mp4_trak_t  *trak;
[2276] 
[2277]     /* time-to-sample atom */
[2278] 
[2279]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stts atom");
[2280] 
[2281]     atom_header = ngx_mp4_atom_header(mp4);
[2282]     stts_atom = (ngx_mp4_stts_atom_t *) atom_header;
[2283]     ngx_mp4_set_atom_name(stts_atom, 's', 't', 't', 's');
[2284] 
[2285]     if (ngx_mp4_atom_data_size(ngx_mp4_stts_atom_t) > atom_data_size) {
[2286]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2287]                       "\"%s\" mp4 stts atom too small", mp4->file.name.data);
[2288]         return NGX_ERROR;
[2289]     }
[2290] 
[2291]     entries = ngx_mp4_get_32value(stts_atom->entries);
[2292] 
[2293]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2294]                    "mp4 time-to-sample entries:%uD", entries);
[2295] 
[2296]     if (ngx_mp4_atom_data_size(ngx_mp4_stts_atom_t)
[2297]         + entries * sizeof(ngx_mp4_stts_entry_t) > atom_data_size)
[2298]     {
[2299]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2300]                       "\"%s\" mp4 stts atom too small", mp4->file.name.data);
[2301]         return NGX_ERROR;
[2302]     }
[2303] 
[2304]     atom_table = atom_header + sizeof(ngx_mp4_stts_atom_t);
[2305]     atom_end = atom_table + entries * sizeof(ngx_mp4_stts_entry_t);
[2306] 
[2307]     trak = ngx_mp4_last_trak(mp4);
[2308] 
[2309]     if (trak->out[NGX_HTTP_MP4_STTS_ATOM].buf) {
[2310]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2311]                       "duplicate mp4 stts atom in \"%s\"", mp4->file.name.data);
[2312]         return NGX_ERROR;
[2313]     }
[2314] 
[2315]     trak->time_to_sample_entries = entries;
[2316] 
[2317]     atom = &trak->stts_atom_buf;
[2318]     atom->temporary = 1;
[2319]     atom->pos = atom_header;
[2320]     atom->last = atom_table;
[2321] 
[2322]     data = &trak->stts_data_buf;
[2323]     data->temporary = 1;
[2324]     data->pos = atom_table;
[2325]     data->last = atom_end;
[2326] 
[2327]     trak->out[NGX_HTTP_MP4_STTS_ATOM].buf = atom;
[2328]     trak->out[NGX_HTTP_MP4_STTS_DATA].buf = data;
[2329] 
[2330]     ngx_mp4_atom_next(mp4, atom_data_size);
[2331] 
[2332]     return NGX_OK;
[2333] }
[2334] 
[2335] 
[2336] static ngx_int_t
[2337] ngx_http_mp4_update_stts_atom(ngx_http_mp4_file_t *mp4,
[2338]     ngx_http_mp4_trak_t *trak)
[2339] {
[2340]     size_t                atom_size;
[2341]     ngx_buf_t            *atom, *data;
[2342]     ngx_mp4_stts_atom_t  *stts_atom;
[2343] 
[2344]     /*
[2345]      * mdia.minf.stbl.stts updating requires trak->timescale
[2346]      * from mdia.mdhd atom which may reside after mdia.minf
[2347]      */
[2348] 
[2349]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2350]                    "mp4 stts atom update");
[2351] 
[2352]     data = trak->out[NGX_HTTP_MP4_STTS_DATA].buf;
[2353] 
[2354]     if (data == NULL) {
[2355]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2356]                       "no mp4 stts atoms were found in \"%s\"",
[2357]                       mp4->file.name.data);
[2358]         return NGX_ERROR;
[2359]     }
[2360] 
[2361]     if (ngx_http_mp4_crop_stts_data(mp4, trak, 1) != NGX_OK) {
[2362]         return NGX_ERROR;
[2363]     }
[2364] 
[2365]     if (ngx_http_mp4_crop_stts_data(mp4, trak, 0) != NGX_OK) {
[2366]         return NGX_ERROR;
[2367]     }
[2368] 
[2369]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2370]                    "time-to-sample entries:%uD", trak->time_to_sample_entries);
[2371] 
[2372]     atom_size = sizeof(ngx_mp4_stts_atom_t) + (data->last - data->pos);
[2373]     trak->size += atom_size;
[2374] 
[2375]     atom = trak->out[NGX_HTTP_MP4_STTS_ATOM].buf;
[2376]     stts_atom = (ngx_mp4_stts_atom_t *) atom->pos;
[2377]     ngx_mp4_set_32value(stts_atom->size, atom_size);
[2378]     ngx_mp4_set_32value(stts_atom->entries, trak->time_to_sample_entries);
[2379] 
[2380]     return NGX_OK;
[2381] }
[2382] 
[2383] 
[2384] static ngx_int_t
[2385] ngx_http_mp4_crop_stts_data(ngx_http_mp4_file_t *mp4,
[2386]     ngx_http_mp4_trak_t *trak, ngx_uint_t start)
[2387] {
[2388]     uint32_t               count, duration, rest, key_prefix;
[2389]     uint64_t               start_time;
[2390]     ngx_buf_t             *data;
[2391]     ngx_uint_t             start_sample, entries, start_sec;
[2392]     ngx_mp4_stts_entry_t  *entry, *end;
[2393] 
[2394]     if (start) {
[2395]         start_sec = mp4->start;
[2396] 
[2397]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2398]                        "mp4 stts crop start_time:%ui", start_sec);
[2399] 
[2400]     } else if (mp4->length) {
[2401]         start_sec = mp4->length;
[2402] 
[2403]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2404]                        "mp4 stts crop end_time:%ui", start_sec);
[2405] 
[2406]     } else {
[2407]         return NGX_OK;
[2408]     }
[2409] 
[2410]     data = trak->out[NGX_HTTP_MP4_STTS_DATA].buf;
[2411] 
[2412]     start_time = (uint64_t) start_sec * trak->timescale / 1000 + trak->prefix;
[2413] 
[2414]     entries = trak->time_to_sample_entries;
[2415]     start_sample = 0;
[2416]     entry = (ngx_mp4_stts_entry_t *) data->pos;
[2417]     end = (ngx_mp4_stts_entry_t *) data->last;
[2418] 
[2419]     while (entry < end) {
[2420]         count = ngx_mp4_get_32value(entry->count);
[2421]         duration = ngx_mp4_get_32value(entry->duration);
[2422] 
[2423]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2424]                        "time:%uL, count:%uD, duration:%uD",
[2425]                        start_time, count, duration);
[2426] 
[2427]         if (start_time < (uint64_t) count * duration) {
[2428]             start_sample += (ngx_uint_t) (start_time / duration);
[2429]             rest = (uint32_t) (start_time / duration);
[2430]             goto found;
[2431]         }
[2432] 
[2433]         start_sample += count;
[2434]         start_time -= (uint64_t) count * duration;
[2435]         entries--;
[2436]         entry++;
[2437]     }
[2438] 
[2439]     if (start) {
[2440]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2441]                       "start time is out mp4 stts samples in \"%s\"",
[2442]                       mp4->file.name.data);
[2443] 
[2444]         return NGX_ERROR;
[2445] 
[2446]     } else {
[2447]         trak->end_sample = trak->start_sample + start_sample;
[2448] 
[2449]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2450]                        "end_sample:%ui", trak->end_sample);
[2451] 
[2452]         return NGX_OK;
[2453]     }
[2454] 
[2455] found:
[2456] 
[2457]     if (start) {
[2458]         key_prefix = ngx_http_mp4_seek_key_frame(mp4, trak, start_sample);
[2459] 
[2460]         start_sample -= key_prefix;
[2461] 
[2462]         while (rest < key_prefix) {
[2463]             trak->prefix += rest * duration;
[2464]             key_prefix -= rest;
[2465] 
[2466]             entry--;
[2467]             entries++;
[2468] 
[2469]             count = ngx_mp4_get_32value(entry->count);
[2470]             duration = ngx_mp4_get_32value(entry->duration);
[2471]             rest = count;
[2472]         }
[2473] 
[2474]         trak->prefix += key_prefix * duration;
[2475]         trak->duration += trak->prefix;
[2476]         rest -= key_prefix;
[2477] 
[2478]         ngx_mp4_set_32value(entry->count, count - rest);
[2479]         data->pos = (u_char *) entry;
[2480]         trak->time_to_sample_entries = entries;
[2481]         trak->start_sample = start_sample;
[2482] 
[2483]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2484]                        "start_sample:%ui, new count:%uD",
[2485]                        trak->start_sample, count - rest);
[2486] 
[2487]     } else {
[2488]         ngx_mp4_set_32value(entry->count, rest);
[2489]         data->last = (u_char *) (entry + 1);
[2490]         trak->time_to_sample_entries -= entries - 1;
[2491]         trak->end_sample = trak->start_sample + start_sample;
[2492] 
[2493]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2494]                        "end_sample:%ui, new count:%uD",
[2495]                        trak->end_sample, rest);
[2496]     }
[2497] 
[2498]     return NGX_OK;
[2499] }
[2500] 
[2501] 
[2502] static uint32_t
[2503] ngx_http_mp4_seek_key_frame(ngx_http_mp4_file_t *mp4, ngx_http_mp4_trak_t *trak,
[2504]     uint32_t start_sample)
[2505] {
[2506]     uint32_t              key_prefix, sample, *entry, *end;
[2507]     ngx_buf_t            *data;
[2508]     ngx_http_mp4_conf_t  *conf;
[2509] 
[2510]     conf = ngx_http_get_module_loc_conf(mp4->request, ngx_http_mp4_module);
[2511]     if (!conf->start_key_frame) {
[2512]         return 0;
[2513]     }
[2514] 
[2515]     data = trak->out[NGX_HTTP_MP4_STSS_DATA].buf;
[2516]     if (data == NULL) {
[2517]         return 0;
[2518]     }
[2519] 
[2520]     entry = (uint32_t *) data->pos;
[2521]     end = (uint32_t *) data->last;
[2522] 
[2523]     /* sync samples starts from 1 */
[2524]     start_sample++;
[2525] 
[2526]     key_prefix = 0;
[2527] 
[2528]     while (entry < end) {
[2529]         sample = ngx_mp4_get_32value(entry);
[2530]         if (sample > start_sample) {
[2531]             break;
[2532]         }
[2533] 
[2534]         key_prefix = start_sample - sample;
[2535]         entry++;
[2536]     }
[2537] 
[2538]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2539]                    "mp4 key frame prefix:%uD", key_prefix);
[2540] 
[2541]     return key_prefix;
[2542] }
[2543] 
[2544] 
[2545] typedef struct {
[2546]     u_char    size[4];
[2547]     u_char    name[4];
[2548]     u_char    version[1];
[2549]     u_char    flags[3];
[2550]     u_char    entries[4];
[2551] } ngx_http_mp4_stss_atom_t;
[2552] 
[2553] 
[2554] static ngx_int_t
[2555] ngx_http_mp4_read_stss_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2556] {
[2557]     u_char                    *atom_header, *atom_table, *atom_end;
[2558]     uint32_t                   entries;
[2559]     ngx_buf_t                 *atom, *data;
[2560]     ngx_http_mp4_trak_t       *trak;
[2561]     ngx_http_mp4_stss_atom_t  *stss_atom;
[2562] 
[2563]     /* sync samples atom */
[2564] 
[2565]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stss atom");
[2566] 
[2567]     atom_header = ngx_mp4_atom_header(mp4);
[2568]     stss_atom = (ngx_http_mp4_stss_atom_t *) atom_header;
[2569]     ngx_mp4_set_atom_name(stss_atom, 's', 't', 's', 's');
[2570] 
[2571]     if (ngx_mp4_atom_data_size(ngx_http_mp4_stss_atom_t) > atom_data_size) {
[2572]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2573]                       "\"%s\" mp4 stss atom too small", mp4->file.name.data);
[2574]         return NGX_ERROR;
[2575]     }
[2576] 
[2577]     entries = ngx_mp4_get_32value(stss_atom->entries);
[2578] 
[2579]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2580]                    "sync sample entries:%uD", entries);
[2581] 
[2582]     trak = ngx_mp4_last_trak(mp4);
[2583] 
[2584]     if (trak->out[NGX_HTTP_MP4_STSS_ATOM].buf) {
[2585]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2586]                       "duplicate mp4 stss atom in \"%s\"", mp4->file.name.data);
[2587]         return NGX_ERROR;
[2588]     }
[2589] 
[2590]     trak->sync_samples_entries = entries;
[2591] 
[2592]     atom_table = atom_header + sizeof(ngx_http_mp4_stss_atom_t);
[2593] 
[2594]     atom = &trak->stss_atom_buf;
[2595]     atom->temporary = 1;
[2596]     atom->pos = atom_header;
[2597]     atom->last = atom_table;
[2598] 
[2599]     if (ngx_mp4_atom_data_size(ngx_http_mp4_stss_atom_t)
[2600]         + entries * sizeof(uint32_t) > atom_data_size)
[2601]     {
[2602]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2603]                       "\"%s\" mp4 stss atom too small", mp4->file.name.data);
[2604]         return NGX_ERROR;
[2605]     }
[2606] 
[2607]     atom_end = atom_table + entries * sizeof(uint32_t);
[2608] 
[2609]     data = &trak->stss_data_buf;
[2610]     data->temporary = 1;
[2611]     data->pos = atom_table;
[2612]     data->last = atom_end;
[2613] 
[2614]     trak->out[NGX_HTTP_MP4_STSS_ATOM].buf = atom;
[2615]     trak->out[NGX_HTTP_MP4_STSS_DATA].buf = data;
[2616] 
[2617]     ngx_mp4_atom_next(mp4, atom_data_size);
[2618] 
[2619]     return NGX_OK;
[2620] }
[2621] 
[2622] 
[2623] static ngx_int_t
[2624] ngx_http_mp4_update_stss_atom(ngx_http_mp4_file_t *mp4,
[2625]     ngx_http_mp4_trak_t *trak)
[2626] {
[2627]     size_t                     atom_size;
[2628]     uint32_t                   sample, start_sample, *entry, *end;
[2629]     ngx_buf_t                 *atom, *data;
[2630]     ngx_http_mp4_stss_atom_t  *stss_atom;
[2631] 
[2632]     /*
[2633]      * mdia.minf.stbl.stss updating requires trak->start_sample
[2634]      * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
[2635]      * atom which may reside after mdia.minf
[2636]      */
[2637] 
[2638]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2639]                    "mp4 stss atom update");
[2640] 
[2641]     data = trak->out[NGX_HTTP_MP4_STSS_DATA].buf;
[2642] 
[2643]     if (data == NULL) {
[2644]         return NGX_OK;
[2645]     }
[2646] 
[2647]     ngx_http_mp4_crop_stss_data(mp4, trak, 1);
[2648]     ngx_http_mp4_crop_stss_data(mp4, trak, 0);
[2649] 
[2650]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2651]                    "sync sample entries:%uD", trak->sync_samples_entries);
[2652] 
[2653]     if (trak->sync_samples_entries) {
[2654]         entry = (uint32_t *) data->pos;
[2655]         end = (uint32_t *) data->last;
[2656] 
[2657]         start_sample = trak->start_sample;
[2658] 
[2659]         while (entry < end) {
[2660]             sample = ngx_mp4_get_32value(entry);
[2661]             sample -= start_sample;
[2662]             ngx_mp4_set_32value(entry, sample);
[2663]             entry++;
[2664]         }
[2665] 
[2666]     } else {
[2667]         trak->out[NGX_HTTP_MP4_STSS_DATA].buf = NULL;
[2668]     }
[2669] 
[2670]     atom_size = sizeof(ngx_http_mp4_stss_atom_t) + (data->last - data->pos);
[2671]     trak->size += atom_size;
[2672] 
[2673]     atom = trak->out[NGX_HTTP_MP4_STSS_ATOM].buf;
[2674]     stss_atom = (ngx_http_mp4_stss_atom_t *) atom->pos;
[2675] 
[2676]     ngx_mp4_set_32value(stss_atom->size, atom_size);
[2677]     ngx_mp4_set_32value(stss_atom->entries, trak->sync_samples_entries);
[2678] 
[2679]     return NGX_OK;
[2680] }
[2681] 
[2682] 
[2683] static void
[2684] ngx_http_mp4_crop_stss_data(ngx_http_mp4_file_t *mp4,
[2685]     ngx_http_mp4_trak_t *trak, ngx_uint_t start)
[2686] {
[2687]     uint32_t     sample, start_sample, *entry, *end;
[2688]     ngx_buf_t   *data;
[2689]     ngx_uint_t   entries;
[2690] 
[2691]     /* sync samples starts from 1 */
[2692] 
[2693]     if (start) {
[2694]         start_sample = trak->start_sample + 1;
[2695] 
[2696]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2697]                        "mp4 stss crop start_sample:%uD", start_sample);
[2698] 
[2699]     } else if (mp4->length) {
[2700]         start_sample = trak->end_sample + 1;
[2701] 
[2702]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2703]                        "mp4 stss crop end_sample:%uD", start_sample);
[2704] 
[2705]     } else {
[2706]         return;
[2707]     }
[2708] 
[2709]     data = trak->out[NGX_HTTP_MP4_STSS_DATA].buf;
[2710] 
[2711]     entries = trak->sync_samples_entries;
[2712]     entry = (uint32_t *) data->pos;
[2713]     end = (uint32_t *) data->last;
[2714] 
[2715]     while (entry < end) {
[2716]         sample = ngx_mp4_get_32value(entry);
[2717] 
[2718]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2719]                        "sync:%uD", sample);
[2720] 
[2721]         if (sample >= start_sample) {
[2722]             goto found;
[2723]         }
[2724] 
[2725]         entries--;
[2726]         entry++;
[2727]     }
[2728] 
[2729]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2730]                    "sample is out of mp4 stss atom");
[2731] 
[2732] found:
[2733] 
[2734]     if (start) {
[2735]         data->pos = (u_char *) entry;
[2736]         trak->sync_samples_entries = entries;
[2737] 
[2738]     } else {
[2739]         data->last = (u_char *) entry;
[2740]         trak->sync_samples_entries -= entries;
[2741]     }
[2742] }
[2743] 
[2744] 
[2745] typedef struct {
[2746]     u_char    size[4];
[2747]     u_char    name[4];
[2748]     u_char    version[1];
[2749]     u_char    flags[3];
[2750]     u_char    entries[4];
[2751] } ngx_mp4_ctts_atom_t;
[2752] 
[2753] typedef struct {
[2754]     u_char    count[4];
[2755]     u_char    offset[4];
[2756] } ngx_mp4_ctts_entry_t;
[2757] 
[2758] 
[2759] static ngx_int_t
[2760] ngx_http_mp4_read_ctts_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2761] {
[2762]     u_char               *atom_header, *atom_table, *atom_end;
[2763]     uint32_t              entries;
[2764]     ngx_buf_t            *atom, *data;
[2765]     ngx_mp4_ctts_atom_t  *ctts_atom;
[2766]     ngx_http_mp4_trak_t  *trak;
[2767] 
[2768]     /* composition offsets atom */
[2769] 
[2770]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 ctts atom");
[2771] 
[2772]     atom_header = ngx_mp4_atom_header(mp4);
[2773]     ctts_atom = (ngx_mp4_ctts_atom_t *) atom_header;
[2774]     ngx_mp4_set_atom_name(ctts_atom, 'c', 't', 't', 's');
[2775] 
[2776]     if (ngx_mp4_atom_data_size(ngx_mp4_ctts_atom_t) > atom_data_size) {
[2777]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2778]                       "\"%s\" mp4 ctts atom too small", mp4->file.name.data);
[2779]         return NGX_ERROR;
[2780]     }
[2781] 
[2782]     entries = ngx_mp4_get_32value(ctts_atom->entries);
[2783] 
[2784]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2785]                    "composition offset entries:%uD", entries);
[2786] 
[2787]     trak = ngx_mp4_last_trak(mp4);
[2788] 
[2789]     if (trak->out[NGX_HTTP_MP4_CTTS_ATOM].buf) {
[2790]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2791]                       "duplicate mp4 ctts atom in \"%s\"", mp4->file.name.data);
[2792]         return NGX_ERROR;
[2793]     }
[2794] 
[2795]     trak->composition_offset_entries = entries;
[2796] 
[2797]     atom_table = atom_header + sizeof(ngx_mp4_ctts_atom_t);
[2798] 
[2799]     atom = &trak->ctts_atom_buf;
[2800]     atom->temporary = 1;
[2801]     atom->pos = atom_header;
[2802]     atom->last = atom_table;
[2803] 
[2804]     if (ngx_mp4_atom_data_size(ngx_mp4_ctts_atom_t)
[2805]         + entries * sizeof(ngx_mp4_ctts_entry_t) > atom_data_size)
[2806]     {
[2807]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2808]                       "\"%s\" mp4 ctts atom too small", mp4->file.name.data);
[2809]         return NGX_ERROR;
[2810]     }
[2811] 
[2812]     atom_end = atom_table + entries * sizeof(ngx_mp4_ctts_entry_t);
[2813] 
[2814]     data = &trak->ctts_data_buf;
[2815]     data->temporary = 1;
[2816]     data->pos = atom_table;
[2817]     data->last = atom_end;
[2818] 
[2819]     trak->out[NGX_HTTP_MP4_CTTS_ATOM].buf = atom;
[2820]     trak->out[NGX_HTTP_MP4_CTTS_DATA].buf = data;
[2821] 
[2822]     ngx_mp4_atom_next(mp4, atom_data_size);
[2823] 
[2824]     return NGX_OK;
[2825] }
[2826] 
[2827] 
[2828] static void
[2829] ngx_http_mp4_update_ctts_atom(ngx_http_mp4_file_t *mp4,
[2830]     ngx_http_mp4_trak_t *trak)
[2831] {
[2832]     size_t                atom_size;
[2833]     ngx_buf_t            *atom, *data;
[2834]     ngx_mp4_ctts_atom_t  *ctts_atom;
[2835] 
[2836]     /*
[2837]      * mdia.minf.stbl.ctts updating requires trak->start_sample
[2838]      * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
[2839]      * atom which may reside after mdia.minf
[2840]      */
[2841] 
[2842]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2843]                    "mp4 ctts atom update");
[2844] 
[2845]     data = trak->out[NGX_HTTP_MP4_CTTS_DATA].buf;
[2846] 
[2847]     if (data == NULL) {
[2848]         return;
[2849]     }
[2850] 
[2851]     ngx_http_mp4_crop_ctts_data(mp4, trak, 1);
[2852]     ngx_http_mp4_crop_ctts_data(mp4, trak, 0);
[2853] 
[2854]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2855]                    "composition offset entries:%uD",
[2856]                    trak->composition_offset_entries);
[2857] 
[2858]     if (trak->composition_offset_entries == 0) {
[2859]         trak->out[NGX_HTTP_MP4_CTTS_ATOM].buf = NULL;
[2860]         trak->out[NGX_HTTP_MP4_CTTS_DATA].buf = NULL;
[2861]         return;
[2862]     }
[2863] 
[2864]     atom_size = sizeof(ngx_mp4_ctts_atom_t) + (data->last - data->pos);
[2865]     trak->size += atom_size;
[2866] 
[2867]     atom = trak->out[NGX_HTTP_MP4_CTTS_ATOM].buf;
[2868]     ctts_atom = (ngx_mp4_ctts_atom_t *) atom->pos;
[2869] 
[2870]     ngx_mp4_set_32value(ctts_atom->size, atom_size);
[2871]     ngx_mp4_set_32value(ctts_atom->entries, trak->composition_offset_entries);
[2872] 
[2873]     return;
[2874] }
[2875] 
[2876] 
[2877] static void
[2878] ngx_http_mp4_crop_ctts_data(ngx_http_mp4_file_t *mp4,
[2879]     ngx_http_mp4_trak_t *trak, ngx_uint_t start)
[2880] {
[2881]     uint32_t               count, start_sample, rest;
[2882]     ngx_buf_t             *data;
[2883]     ngx_uint_t             entries;
[2884]     ngx_mp4_ctts_entry_t  *entry, *end;
[2885] 
[2886]     /* sync samples starts from 1 */
[2887] 
[2888]     if (start) {
[2889]         start_sample = trak->start_sample + 1;
[2890] 
[2891]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2892]                        "mp4 ctts crop start_sample:%uD", start_sample);
[2893] 
[2894]     } else if (mp4->length) {
[2895]         start_sample = trak->end_sample - trak->start_sample + 1;
[2896] 
[2897]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2898]                        "mp4 ctts crop end_sample:%uD", start_sample);
[2899] 
[2900]     } else {
[2901]         return;
[2902]     }
[2903] 
[2904]     data = trak->out[NGX_HTTP_MP4_CTTS_DATA].buf;
[2905] 
[2906]     entries = trak->composition_offset_entries;
[2907]     entry = (ngx_mp4_ctts_entry_t *) data->pos;
[2908]     end = (ngx_mp4_ctts_entry_t *) data->last;
[2909] 
[2910]     while (entry < end) {
[2911]         count = ngx_mp4_get_32value(entry->count);
[2912] 
[2913]         ngx_log_debug3(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2914]                        "sample:%uD, count:%uD, offset:%uD",
[2915]                        start_sample, count, ngx_mp4_get_32value(entry->offset));
[2916] 
[2917]         if (start_sample <= count) {
[2918]             rest = start_sample - 1;
[2919]             goto found;
[2920]         }
[2921] 
[2922]         start_sample -= count;
[2923]         entries--;
[2924]         entry++;
[2925]     }
[2926] 
[2927]     if (start) {
[2928]         data->pos = (u_char *) end;
[2929]         trak->composition_offset_entries = 0;
[2930]     }
[2931] 
[2932]     return;
[2933] 
[2934] found:
[2935] 
[2936]     if (start) {
[2937]         ngx_mp4_set_32value(entry->count, count - rest);
[2938]         data->pos = (u_char *) entry;
[2939]         trak->composition_offset_entries = entries;
[2940] 
[2941]     } else {
[2942]         ngx_mp4_set_32value(entry->count, rest);
[2943]         data->last = (u_char *) (entry + 1);
[2944]         trak->composition_offset_entries -= entries - 1;
[2945]     }
[2946] }
[2947] 
[2948] 
[2949] typedef struct {
[2950]     u_char    size[4];
[2951]     u_char    name[4];
[2952]     u_char    version[1];
[2953]     u_char    flags[3];
[2954]     u_char    entries[4];
[2955] } ngx_mp4_stsc_atom_t;
[2956] 
[2957] 
[2958] static ngx_int_t
[2959] ngx_http_mp4_read_stsc_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[2960] {
[2961]     u_char               *atom_header, *atom_table, *atom_end;
[2962]     uint32_t              entries;
[2963]     ngx_buf_t            *atom, *data;
[2964]     ngx_mp4_stsc_atom_t  *stsc_atom;
[2965]     ngx_http_mp4_trak_t  *trak;
[2966] 
[2967]     /* sample-to-chunk atom */
[2968] 
[2969]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsc atom");
[2970] 
[2971]     atom_header = ngx_mp4_atom_header(mp4);
[2972]     stsc_atom = (ngx_mp4_stsc_atom_t *) atom_header;
[2973]     ngx_mp4_set_atom_name(stsc_atom, 's', 't', 's', 'c');
[2974] 
[2975]     if (ngx_mp4_atom_data_size(ngx_mp4_stsc_atom_t) > atom_data_size) {
[2976]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2977]                       "\"%s\" mp4 stsc atom too small", mp4->file.name.data);
[2978]         return NGX_ERROR;
[2979]     }
[2980] 
[2981]     entries = ngx_mp4_get_32value(stsc_atom->entries);
[2982] 
[2983]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[2984]                    "sample-to-chunk entries:%uD", entries);
[2985] 
[2986]     if (ngx_mp4_atom_data_size(ngx_mp4_stsc_atom_t)
[2987]         + entries * sizeof(ngx_mp4_stsc_entry_t) > atom_data_size)
[2988]     {
[2989]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[2990]                       "\"%s\" mp4 stsc atom too small", mp4->file.name.data);
[2991]         return NGX_ERROR;
[2992]     }
[2993] 
[2994]     atom_table = atom_header + sizeof(ngx_mp4_stsc_atom_t);
[2995]     atom_end = atom_table + entries * sizeof(ngx_mp4_stsc_entry_t);
[2996] 
[2997]     trak = ngx_mp4_last_trak(mp4);
[2998] 
[2999]     if (trak->out[NGX_HTTP_MP4_STSC_ATOM].buf) {
[3000]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3001]                       "duplicate mp4 stsc atom in \"%s\"", mp4->file.name.data);
[3002]         return NGX_ERROR;
[3003]     }
[3004] 
[3005]     trak->sample_to_chunk_entries = entries;
[3006] 
[3007]     atom = &trak->stsc_atom_buf;
[3008]     atom->temporary = 1;
[3009]     atom->pos = atom_header;
[3010]     atom->last = atom_table;
[3011] 
[3012]     data = &trak->stsc_data_buf;
[3013]     data->temporary = 1;
[3014]     data->pos = atom_table;
[3015]     data->last = atom_end;
[3016] 
[3017]     trak->out[NGX_HTTP_MP4_STSC_ATOM].buf = atom;
[3018]     trak->out[NGX_HTTP_MP4_STSC_DATA].buf = data;
[3019] 
[3020]     ngx_mp4_atom_next(mp4, atom_data_size);
[3021] 
[3022]     return NGX_OK;
[3023] }
[3024] 
[3025] 
[3026] static ngx_int_t
[3027] ngx_http_mp4_update_stsc_atom(ngx_http_mp4_file_t *mp4,
[3028]     ngx_http_mp4_trak_t *trak)
[3029] {
[3030]     size_t                 atom_size;
[3031]     uint32_t               chunk;
[3032]     ngx_buf_t             *atom, *data;
[3033]     ngx_mp4_stsc_atom_t   *stsc_atom;
[3034]     ngx_mp4_stsc_entry_t  *entry, *end;
[3035] 
[3036]     /*
[3037]      * mdia.minf.stbl.stsc updating requires trak->start_sample
[3038]      * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
[3039]      * atom which may reside after mdia.minf
[3040]      */
[3041] 
[3042]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3043]                    "mp4 stsc atom update");
[3044] 
[3045]     data = trak->out[NGX_HTTP_MP4_STSC_DATA].buf;
[3046] 
[3047]     if (data == NULL) {
[3048]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3049]                       "no mp4 stsc atoms were found in \"%s\"",
[3050]                       mp4->file.name.data);
[3051]         return NGX_ERROR;
[3052]     }
[3053] 
[3054]     if (trak->sample_to_chunk_entries == 0) {
[3055]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3056]                       "zero number of entries in stsc atom in \"%s\"",
[3057]                       mp4->file.name.data);
[3058]         return NGX_ERROR;
[3059]     }
[3060] 
[3061]     if (ngx_http_mp4_crop_stsc_data(mp4, trak, 1) != NGX_OK) {
[3062]         return NGX_ERROR;
[3063]     }
[3064] 
[3065]     if (ngx_http_mp4_crop_stsc_data(mp4, trak, 0) != NGX_OK) {
[3066]         return NGX_ERROR;
[3067]     }
[3068] 
[3069]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3070]                    "sample-to-chunk entries:%uD",
[3071]                    trak->sample_to_chunk_entries);
[3072] 
[3073]     entry = (ngx_mp4_stsc_entry_t *) data->pos;
[3074]     end = (ngx_mp4_stsc_entry_t *) data->last;
[3075] 
[3076]     while (entry < end) {
[3077]         chunk = ngx_mp4_get_32value(entry->chunk);
[3078]         chunk -= trak->start_chunk;
[3079]         ngx_mp4_set_32value(entry->chunk, chunk);
[3080]         entry++;
[3081]     }
[3082] 
[3083]     atom_size = sizeof(ngx_mp4_stsc_atom_t)
[3084]                 + trak->sample_to_chunk_entries * sizeof(ngx_mp4_stsc_entry_t);
[3085] 
[3086]     trak->size += atom_size;
[3087] 
[3088]     atom = trak->out[NGX_HTTP_MP4_STSC_ATOM].buf;
[3089]     stsc_atom = (ngx_mp4_stsc_atom_t *) atom->pos;
[3090] 
[3091]     ngx_mp4_set_32value(stsc_atom->size, atom_size);
[3092]     ngx_mp4_set_32value(stsc_atom->entries, trak->sample_to_chunk_entries);
[3093] 
[3094]     return NGX_OK;
[3095] }
[3096] 
[3097] 
[3098] static ngx_int_t
[3099] ngx_http_mp4_crop_stsc_data(ngx_http_mp4_file_t *mp4,
[3100]     ngx_http_mp4_trak_t *trak, ngx_uint_t start)
[3101] {
[3102]     uint32_t               start_sample, chunk, samples, id, next_chunk, n,
[3103]                            prev_samples;
[3104]     ngx_buf_t             *data, *buf;
[3105]     ngx_uint_t             entries, target_chunk, chunk_samples;
[3106]     ngx_mp4_stsc_entry_t  *entry, *end, *first;
[3107] 
[3108]     entries = trak->sample_to_chunk_entries - 1;
[3109] 
[3110]     if (start) {
[3111]         start_sample = (uint32_t) trak->start_sample;
[3112] 
[3113]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3114]                        "mp4 stsc crop start_sample:%uD", start_sample);
[3115] 
[3116]     } else if (mp4->length) {
[3117]         start_sample = (uint32_t) (trak->end_sample - trak->start_sample);
[3118]         samples = 0;
[3119] 
[3120]         data = trak->out[NGX_HTTP_MP4_STSC_START].buf;
[3121] 
[3122]         if (data) {
[3123]             entry = (ngx_mp4_stsc_entry_t *) data->pos;
[3124]             samples = ngx_mp4_get_32value(entry->samples);
[3125]             entries--;
[3126] 
[3127]             if (samples > start_sample) {
[3128]                 samples = start_sample;
[3129]                 ngx_mp4_set_32value(entry->samples, samples);
[3130]             }
[3131] 
[3132]             start_sample -= samples;
[3133]         }
[3134] 
[3135]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3136]                        "mp4 stsc crop end_sample:%uD, ext_samples:%uD",
[3137]                        start_sample, samples);
[3138] 
[3139]     } else {
[3140]         return NGX_OK;
[3141]     }
[3142] 
[3143]     data = trak->out[NGX_HTTP_MP4_STSC_DATA].buf;
[3144] 
[3145]     entry = (ngx_mp4_stsc_entry_t *) data->pos;
[3146]     end = (ngx_mp4_stsc_entry_t *) data->last;
[3147] 
[3148]     chunk = ngx_mp4_get_32value(entry->chunk);
[3149]     samples = ngx_mp4_get_32value(entry->samples);
[3150]     id = ngx_mp4_get_32value(entry->id);
[3151]     prev_samples = 0;
[3152]     entry++;
[3153] 
[3154]     while (entry < end) {
[3155] 
[3156]         next_chunk = ngx_mp4_get_32value(entry->chunk);
[3157] 
[3158]         ngx_log_debug5(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3159]                        "sample:%uD, chunk:%uD, chunks:%uD, "
[3160]                        "samples:%uD, id:%uD",
[3161]                        start_sample, chunk, next_chunk - chunk, samples, id);
[3162] 
[3163]         n = (next_chunk - chunk) * samples;
[3164] 
[3165]         if (start_sample < n) {
[3166]             goto found;
[3167]         }
[3168] 
[3169]         start_sample -= n;
[3170] 
[3171]         prev_samples = samples;
[3172]         chunk = next_chunk;
[3173]         samples = ngx_mp4_get_32value(entry->samples);
[3174]         id = ngx_mp4_get_32value(entry->id);
[3175]         entries--;
[3176]         entry++;
[3177]     }
[3178] 
[3179]     next_chunk = trak->chunks + 1;
[3180] 
[3181]     ngx_log_debug4(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3182]                    "sample:%uD, chunk:%uD, chunks:%uD, samples:%uD",
[3183]                    start_sample, chunk, next_chunk - chunk, samples);
[3184] 
[3185]     n = (next_chunk - chunk) * samples;
[3186] 
[3187]     if (start_sample > n) {
[3188]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3189]                       "%s time is out mp4 stsc chunks in \"%s\"",
[3190]                       start ? "start" : "end", mp4->file.name.data);
[3191]         return NGX_ERROR;
[3192]     }
[3193] 
[3194] found:
[3195] 
[3196]     entries++;
[3197]     entry--;
[3198] 
[3199]     if (samples == 0) {
[3200]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3201]                       "zero number of samples in \"%s\"",
[3202]                       mp4->file.name.data);
[3203]         return NGX_ERROR;
[3204]     }
[3205] 
[3206]     target_chunk = chunk - 1;
[3207]     target_chunk += start_sample / samples;
[3208]     chunk_samples = start_sample % samples;
[3209] 
[3210]     if (start) {
[3211]         data->pos = (u_char *) entry;
[3212] 
[3213]         trak->sample_to_chunk_entries = entries;
[3214]         trak->start_chunk = target_chunk;
[3215]         trak->start_chunk_samples = chunk_samples;
[3216] 
[3217]         ngx_mp4_set_32value(entry->chunk, trak->start_chunk + 1);
[3218] 
[3219]         samples -= chunk_samples;
[3220] 
[3221]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3222]                        "start_chunk:%ui, start_chunk_samples:%ui",
[3223]                        trak->start_chunk, trak->start_chunk_samples);
[3224] 
[3225]     } else {
[3226]         if (start_sample) {
[3227]             data->last = (u_char *) (entry + 1);
[3228]             trak->sample_to_chunk_entries -= entries - 1;
[3229]             trak->end_chunk_samples = samples;
[3230] 
[3231]         } else {
[3232]             data->last = (u_char *) entry;
[3233]             trak->sample_to_chunk_entries -= entries;
[3234]             trak->end_chunk_samples = prev_samples;
[3235]         }
[3236] 
[3237]         if (chunk_samples) {
[3238]             trak->end_chunk = target_chunk + 1;
[3239]             trak->end_chunk_samples = chunk_samples;
[3240] 
[3241]         } else {
[3242]             trak->end_chunk = target_chunk;
[3243]         }
[3244] 
[3245]         samples = chunk_samples;
[3246]         next_chunk = chunk + 1;
[3247] 
[3248]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3249]                        "end_chunk:%ui, end_chunk_samples:%ui",
[3250]                        trak->end_chunk, trak->end_chunk_samples);
[3251]     }
[3252] 
[3253]     if (chunk_samples && next_chunk - target_chunk == 2) {
[3254] 
[3255]         ngx_mp4_set_32value(entry->samples, samples);
[3256] 
[3257]     } else if (chunk_samples && start) {
[3258] 
[3259]         first = &trak->stsc_start_chunk_entry;
[3260]         ngx_mp4_set_32value(first->chunk, 1);
[3261]         ngx_mp4_set_32value(first->samples, samples);
[3262]         ngx_mp4_set_32value(first->id, id);
[3263] 
[3264]         buf = &trak->stsc_start_chunk_buf;
[3265]         buf->temporary = 1;
[3266]         buf->pos = (u_char *) first;
[3267]         buf->last = (u_char *) first + sizeof(ngx_mp4_stsc_entry_t);
[3268] 
[3269]         trak->out[NGX_HTTP_MP4_STSC_START].buf = buf;
[3270] 
[3271]         ngx_mp4_set_32value(entry->chunk, trak->start_chunk + 2);
[3272] 
[3273]         trak->sample_to_chunk_entries++;
[3274] 
[3275]     } else if (chunk_samples) {
[3276] 
[3277]         first = &trak->stsc_end_chunk_entry;
[3278]         ngx_mp4_set_32value(first->chunk, trak->end_chunk - trak->start_chunk);
[3279]         ngx_mp4_set_32value(first->samples, samples);
[3280]         ngx_mp4_set_32value(first->id, id);
[3281] 
[3282]         buf = &trak->stsc_end_chunk_buf;
[3283]         buf->temporary = 1;
[3284]         buf->pos = (u_char *) first;
[3285]         buf->last = (u_char *) first + sizeof(ngx_mp4_stsc_entry_t);
[3286] 
[3287]         trak->out[NGX_HTTP_MP4_STSC_END].buf = buf;
[3288] 
[3289]         trak->sample_to_chunk_entries++;
[3290]     }
[3291] 
[3292]     return NGX_OK;
[3293] }
[3294] 
[3295] 
[3296] typedef struct {
[3297]     u_char    size[4];
[3298]     u_char    name[4];
[3299]     u_char    version[1];
[3300]     u_char    flags[3];
[3301]     u_char    uniform_size[4];
[3302]     u_char    entries[4];
[3303] } ngx_mp4_stsz_atom_t;
[3304] 
[3305] 
[3306] static ngx_int_t
[3307] ngx_http_mp4_read_stsz_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[3308] {
[3309]     u_char               *atom_header, *atom_table, *atom_end;
[3310]     size_t                atom_size;
[3311]     uint32_t              entries, size;
[3312]     ngx_buf_t            *atom, *data;
[3313]     ngx_mp4_stsz_atom_t  *stsz_atom;
[3314]     ngx_http_mp4_trak_t  *trak;
[3315] 
[3316]     /* sample sizes atom */
[3317] 
[3318]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stsz atom");
[3319] 
[3320]     atom_header = ngx_mp4_atom_header(mp4);
[3321]     stsz_atom = (ngx_mp4_stsz_atom_t *) atom_header;
[3322]     ngx_mp4_set_atom_name(stsz_atom, 's', 't', 's', 'z');
[3323] 
[3324]     if (ngx_mp4_atom_data_size(ngx_mp4_stsz_atom_t) > atom_data_size) {
[3325]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3326]                       "\"%s\" mp4 stsz atom too small", mp4->file.name.data);
[3327]         return NGX_ERROR;
[3328]     }
[3329] 
[3330]     size = ngx_mp4_get_32value(stsz_atom->uniform_size);
[3331]     entries = ngx_mp4_get_32value(stsz_atom->entries);
[3332] 
[3333]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3334]                    "sample uniform size:%uD, entries:%uD", size, entries);
[3335] 
[3336]     trak = ngx_mp4_last_trak(mp4);
[3337] 
[3338]     if (trak->out[NGX_HTTP_MP4_STSZ_ATOM].buf) {
[3339]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3340]                       "duplicate mp4 stsz atom in \"%s\"", mp4->file.name.data);
[3341]         return NGX_ERROR;
[3342]     }
[3343] 
[3344]     trak->sample_sizes_entries = entries;
[3345] 
[3346]     atom_table = atom_header + sizeof(ngx_mp4_stsz_atom_t);
[3347] 
[3348]     atom = &trak->stsz_atom_buf;
[3349]     atom->temporary = 1;
[3350]     atom->pos = atom_header;
[3351]     atom->last = atom_table;
[3352] 
[3353]     trak->out[NGX_HTTP_MP4_STSZ_ATOM].buf = atom;
[3354] 
[3355]     if (size == 0) {
[3356]         if (ngx_mp4_atom_data_size(ngx_mp4_stsz_atom_t)
[3357]             + entries * sizeof(uint32_t) > atom_data_size)
[3358]         {
[3359]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3360]                           "\"%s\" mp4 stsz atom too small",
[3361]                           mp4->file.name.data);
[3362]             return NGX_ERROR;
[3363]         }
[3364] 
[3365]         atom_end = atom_table + entries * sizeof(uint32_t);
[3366] 
[3367]         data = &trak->stsz_data_buf;
[3368]         data->temporary = 1;
[3369]         data->pos = atom_table;
[3370]         data->last = atom_end;
[3371] 
[3372]         trak->out[NGX_HTTP_MP4_STSZ_DATA].buf = data;
[3373] 
[3374]     } else {
[3375]         /* if size != 0 then all samples are the same size */
[3376]         /* TODO : chunk samples */
[3377]         atom_size = sizeof(ngx_mp4_atom_header_t) + (size_t) atom_data_size;
[3378]         ngx_mp4_set_32value(atom_header, atom_size);
[3379]         trak->size += atom_size;
[3380]     }
[3381] 
[3382]     ngx_mp4_atom_next(mp4, atom_data_size);
[3383] 
[3384]     return NGX_OK;
[3385] }
[3386] 
[3387] 
[3388] static ngx_int_t
[3389] ngx_http_mp4_update_stsz_atom(ngx_http_mp4_file_t *mp4,
[3390]     ngx_http_mp4_trak_t *trak)
[3391] {
[3392]     size_t                atom_size;
[3393]     uint32_t             *pos, *end, entries;
[3394]     ngx_buf_t            *atom, *data;
[3395]     ngx_mp4_stsz_atom_t  *stsz_atom;
[3396] 
[3397]     /*
[3398]      * mdia.minf.stbl.stsz updating requires trak->start_sample
[3399]      * from mdia.minf.stbl.stts which depends on value from mdia.mdhd
[3400]      * atom which may reside after mdia.minf
[3401]      */
[3402] 
[3403]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3404]                    "mp4 stsz atom update");
[3405] 
[3406]     data = trak->out[NGX_HTTP_MP4_STSZ_DATA].buf;
[3407] 
[3408]     if (data) {
[3409]         entries = trak->sample_sizes_entries;
[3410] 
[3411]         if (trak->start_sample > entries) {
[3412]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3413]                           "start time is out mp4 stsz samples in \"%s\"",
[3414]                           mp4->file.name.data);
[3415]             return NGX_ERROR;
[3416]         }
[3417] 
[3418]         entries -= trak->start_sample;
[3419]         data->pos += trak->start_sample * sizeof(uint32_t);
[3420]         end = (uint32_t *) data->pos;
[3421] 
[3422]         for (pos = end - trak->start_chunk_samples; pos < end; pos++) {
[3423]             trak->start_chunk_samples_size += ngx_mp4_get_32value(pos);
[3424]         }
[3425] 
[3426]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3427]                        "chunk samples sizes:%uL",
[3428]                        trak->start_chunk_samples_size);
[3429] 
[3430]         if (trak->start_chunk_samples_size > (uint64_t) mp4->end) {
[3431]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3432]                           "too large mp4 start samples size in \"%s\"",
[3433]                           mp4->file.name.data);
[3434]             return NGX_ERROR;
[3435]         }
[3436] 
[3437]         if (mp4->length) {
[3438]             if (trak->end_sample - trak->start_sample > entries) {
[3439]                 ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3440]                               "end time is out mp4 stsz samples in \"%s\"",
[3441]                               mp4->file.name.data);
[3442]                 return NGX_ERROR;
[3443]             }
[3444] 
[3445]             entries = trak->end_sample - trak->start_sample;
[3446]             data->last = data->pos + entries * sizeof(uint32_t);
[3447]             end = (uint32_t *) data->last;
[3448] 
[3449]             for (pos = end - trak->end_chunk_samples; pos < end; pos++) {
[3450]                 trak->end_chunk_samples_size += ngx_mp4_get_32value(pos);
[3451]             }
[3452] 
[3453]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3454]                            "mp4 stsz end_chunk_samples_size:%uL",
[3455]                            trak->end_chunk_samples_size);
[3456] 
[3457]             if (trak->end_chunk_samples_size > (uint64_t) mp4->end) {
[3458]                 ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3459]                               "too large mp4 end samples size in \"%s\"",
[3460]                               mp4->file.name.data);
[3461]                 return NGX_ERROR;
[3462]             }
[3463]         }
[3464] 
[3465]         atom_size = sizeof(ngx_mp4_stsz_atom_t) + (data->last - data->pos);
[3466]         trak->size += atom_size;
[3467] 
[3468]         atom = trak->out[NGX_HTTP_MP4_STSZ_ATOM].buf;
[3469]         stsz_atom = (ngx_mp4_stsz_atom_t *) atom->pos;
[3470] 
[3471]         ngx_mp4_set_32value(stsz_atom->size, atom_size);
[3472]         ngx_mp4_set_32value(stsz_atom->entries, entries);
[3473]     }
[3474] 
[3475]     return NGX_OK;
[3476] }
[3477] 
[3478] 
[3479] typedef struct {
[3480]     u_char    size[4];
[3481]     u_char    name[4];
[3482]     u_char    version[1];
[3483]     u_char    flags[3];
[3484]     u_char    entries[4];
[3485] } ngx_mp4_stco_atom_t;
[3486] 
[3487] 
[3488] static ngx_int_t
[3489] ngx_http_mp4_read_stco_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[3490] {
[3491]     u_char               *atom_header, *atom_table, *atom_end;
[3492]     uint32_t              entries;
[3493]     ngx_buf_t            *atom, *data;
[3494]     ngx_mp4_stco_atom_t  *stco_atom;
[3495]     ngx_http_mp4_trak_t  *trak;
[3496] 
[3497]     /* chunk offsets atom */
[3498] 
[3499]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 stco atom");
[3500] 
[3501]     atom_header = ngx_mp4_atom_header(mp4);
[3502]     stco_atom = (ngx_mp4_stco_atom_t *) atom_header;
[3503]     ngx_mp4_set_atom_name(stco_atom, 's', 't', 'c', 'o');
[3504] 
[3505]     if (ngx_mp4_atom_data_size(ngx_mp4_stco_atom_t) > atom_data_size) {
[3506]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3507]                       "\"%s\" mp4 stco atom too small", mp4->file.name.data);
[3508]         return NGX_ERROR;
[3509]     }
[3510] 
[3511]     entries = ngx_mp4_get_32value(stco_atom->entries);
[3512] 
[3513]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "chunks:%uD", entries);
[3514] 
[3515]     if (ngx_mp4_atom_data_size(ngx_mp4_stco_atom_t)
[3516]         + entries * sizeof(uint32_t) > atom_data_size)
[3517]     {
[3518]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3519]                       "\"%s\" mp4 stco atom too small", mp4->file.name.data);
[3520]         return NGX_ERROR;
[3521]     }
[3522] 
[3523]     atom_table = atom_header + sizeof(ngx_mp4_stco_atom_t);
[3524]     atom_end = atom_table + entries * sizeof(uint32_t);
[3525] 
[3526]     trak = ngx_mp4_last_trak(mp4);
[3527] 
[3528]     if (trak->out[NGX_HTTP_MP4_STCO_ATOM].buf
[3529]         || trak->out[NGX_HTTP_MP4_CO64_ATOM].buf)
[3530]     {
[3531]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3532]                       "duplicate mp4 stco/co64 atom in \"%s\"",
[3533]                       mp4->file.name.data);
[3534]         return NGX_ERROR;
[3535]     }
[3536] 
[3537]     trak->chunks = entries;
[3538] 
[3539]     atom = &trak->stco_atom_buf;
[3540]     atom->temporary = 1;
[3541]     atom->pos = atom_header;
[3542]     atom->last = atom_table;
[3543] 
[3544]     data = &trak->stco_data_buf;
[3545]     data->temporary = 1;
[3546]     data->pos = atom_table;
[3547]     data->last = atom_end;
[3548] 
[3549]     trak->out[NGX_HTTP_MP4_STCO_ATOM].buf = atom;
[3550]     trak->out[NGX_HTTP_MP4_STCO_DATA].buf = data;
[3551] 
[3552]     ngx_mp4_atom_next(mp4, atom_data_size);
[3553] 
[3554]     return NGX_OK;
[3555] }
[3556] 
[3557] 
[3558] static ngx_int_t
[3559] ngx_http_mp4_update_stco_atom(ngx_http_mp4_file_t *mp4,
[3560]     ngx_http_mp4_trak_t *trak)
[3561] {
[3562]     size_t                atom_size;
[3563]     uint32_t              entries;
[3564]     uint64_t              chunk_offset, samples_size;
[3565]     ngx_buf_t            *atom, *data;
[3566]     ngx_mp4_stco_atom_t  *stco_atom;
[3567] 
[3568]     /*
[3569]      * mdia.minf.stbl.stco updating requires trak->start_chunk
[3570]      * from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
[3571]      * atom which may reside after mdia.minf
[3572]      */
[3573] 
[3574]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3575]                    "mp4 stco atom update");
[3576] 
[3577]     data = trak->out[NGX_HTTP_MP4_STCO_DATA].buf;
[3578] 
[3579]     if (data == NULL) {
[3580]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3581]                       "no mp4 stco atoms were found in \"%s\"",
[3582]                       mp4->file.name.data);
[3583]         return NGX_ERROR;
[3584]     }
[3585] 
[3586]     if (trak->start_chunk > trak->chunks) {
[3587]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3588]                       "start time is out mp4 stco chunks in \"%s\"",
[3589]                       mp4->file.name.data);
[3590]         return NGX_ERROR;
[3591]     }
[3592] 
[3593]     data->pos += trak->start_chunk * sizeof(uint32_t);
[3594] 
[3595]     chunk_offset = ngx_mp4_get_32value(data->pos);
[3596]     samples_size = trak->start_chunk_samples_size;
[3597] 
[3598]     if (chunk_offset > (uint64_t) mp4->end - samples_size
[3599]         || chunk_offset + samples_size > NGX_MAX_UINT32_VALUE)
[3600]     {
[3601]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3602]                       "too large chunk offset in \"%s\"",
[3603]                       mp4->file.name.data);
[3604]         return NGX_ERROR;
[3605]     }
[3606] 
[3607]     trak->start_offset = chunk_offset + samples_size;
[3608]     ngx_mp4_set_32value(data->pos, trak->start_offset);
[3609] 
[3610]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3611]                    "start chunk offset:%O", trak->start_offset);
[3612] 
[3613]     if (mp4->length) {
[3614] 
[3615]         if (trak->end_chunk > trak->chunks) {
[3616]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3617]                           "end time is out mp4 stco chunks in \"%s\"",
[3618]                           mp4->file.name.data);
[3619]             return NGX_ERROR;
[3620]         }
[3621] 
[3622]         entries = trak->end_chunk - trak->start_chunk;
[3623]         data->last = data->pos + entries * sizeof(uint32_t);
[3624] 
[3625]         if (entries) {
[3626]             chunk_offset = ngx_mp4_get_32value(data->last - sizeof(uint32_t));
[3627]             samples_size = trak->end_chunk_samples_size;
[3628] 
[3629]             if (chunk_offset > (uint64_t) mp4->end - samples_size
[3630]                 || chunk_offset + samples_size > NGX_MAX_UINT32_VALUE)
[3631]             {
[3632]                 ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3633]                               "too large chunk offset in \"%s\"",
[3634]                               mp4->file.name.data);
[3635]                 return NGX_ERROR;
[3636]             }
[3637] 
[3638]             trak->end_offset = chunk_offset + samples_size;
[3639] 
[3640]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3641]                            "end chunk offset:%O", trak->end_offset);
[3642]         }
[3643] 
[3644]     } else {
[3645]         entries = trak->chunks - trak->start_chunk;
[3646]         trak->end_offset = mp4->mdat_data.buf->file_last;
[3647]     }
[3648] 
[3649]     if (entries == 0) {
[3650]         trak->start_offset = mp4->end;
[3651]         trak->end_offset = 0;
[3652]     }
[3653] 
[3654]     atom_size = sizeof(ngx_mp4_stco_atom_t) + (data->last - data->pos);
[3655]     trak->size += atom_size;
[3656] 
[3657]     atom = trak->out[NGX_HTTP_MP4_STCO_ATOM].buf;
[3658]     stco_atom = (ngx_mp4_stco_atom_t *) atom->pos;
[3659] 
[3660]     ngx_mp4_set_32value(stco_atom->size, atom_size);
[3661]     ngx_mp4_set_32value(stco_atom->entries, entries);
[3662] 
[3663]     return NGX_OK;
[3664] }
[3665] 
[3666] 
[3667] static void
[3668] ngx_http_mp4_adjust_stco_atom(ngx_http_mp4_file_t *mp4,
[3669]     ngx_http_mp4_trak_t *trak, int32_t adjustment)
[3670] {
[3671]     uint32_t    offset, *entry, *end;
[3672]     ngx_buf_t  *data;
[3673] 
[3674]     /*
[3675]      * moov.trak.mdia.minf.stbl.stco adjustment requires
[3676]      * minimal start offset of all traks and new moov atom size
[3677]      */
[3678] 
[3679]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3680]                    "mp4 stco atom adjustment");
[3681] 
[3682]     data = trak->out[NGX_HTTP_MP4_STCO_DATA].buf;
[3683]     entry = (uint32_t *) data->pos;
[3684]     end = (uint32_t *) data->last;
[3685] 
[3686]     while (entry < end) {
[3687]         offset = ngx_mp4_get_32value(entry);
[3688]         offset += adjustment;
[3689]         ngx_mp4_set_32value(entry, offset);
[3690]         entry++;
[3691]     }
[3692] }
[3693] 
[3694] 
[3695] typedef struct {
[3696]     u_char    size[4];
[3697]     u_char    name[4];
[3698]     u_char    version[1];
[3699]     u_char    flags[3];
[3700]     u_char    entries[4];
[3701] } ngx_mp4_co64_atom_t;
[3702] 
[3703] 
[3704] static ngx_int_t
[3705] ngx_http_mp4_read_co64_atom(ngx_http_mp4_file_t *mp4, uint64_t atom_data_size)
[3706] {
[3707]     u_char               *atom_header, *atom_table, *atom_end;
[3708]     uint32_t              entries;
[3709]     ngx_buf_t            *atom, *data;
[3710]     ngx_mp4_co64_atom_t  *co64_atom;
[3711]     ngx_http_mp4_trak_t  *trak;
[3712] 
[3713]     /* chunk offsets atom */
[3714] 
[3715]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "mp4 co64 atom");
[3716] 
[3717]     atom_header = ngx_mp4_atom_header(mp4);
[3718]     co64_atom = (ngx_mp4_co64_atom_t *) atom_header;
[3719]     ngx_mp4_set_atom_name(co64_atom, 'c', 'o', '6', '4');
[3720] 
[3721]     if (ngx_mp4_atom_data_size(ngx_mp4_co64_atom_t) > atom_data_size) {
[3722]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3723]                       "\"%s\" mp4 co64 atom too small", mp4->file.name.data);
[3724]         return NGX_ERROR;
[3725]     }
[3726] 
[3727]     entries = ngx_mp4_get_32value(co64_atom->entries);
[3728] 
[3729]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0, "chunks:%uD", entries);
[3730] 
[3731]     if (ngx_mp4_atom_data_size(ngx_mp4_co64_atom_t)
[3732]         + entries * sizeof(uint64_t) > atom_data_size)
[3733]     {
[3734]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3735]                       "\"%s\" mp4 co64 atom too small", mp4->file.name.data);
[3736]         return NGX_ERROR;
[3737]     }
[3738] 
[3739]     atom_table = atom_header + sizeof(ngx_mp4_co64_atom_t);
[3740]     atom_end = atom_table + entries * sizeof(uint64_t);
[3741] 
[3742]     trak = ngx_mp4_last_trak(mp4);
[3743] 
[3744]     if (trak->out[NGX_HTTP_MP4_STCO_ATOM].buf
[3745]         || trak->out[NGX_HTTP_MP4_CO64_ATOM].buf)
[3746]     {
[3747]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3748]                       "duplicate mp4 stco/co64 atom in \"%s\"",
[3749]                       mp4->file.name.data);
[3750]         return NGX_ERROR;
[3751]     }
[3752] 
[3753]     trak->chunks = entries;
[3754] 
[3755]     atom = &trak->co64_atom_buf;
[3756]     atom->temporary = 1;
[3757]     atom->pos = atom_header;
[3758]     atom->last = atom_table;
[3759] 
[3760]     data = &trak->co64_data_buf;
[3761]     data->temporary = 1;
[3762]     data->pos = atom_table;
[3763]     data->last = atom_end;
[3764] 
[3765]     trak->out[NGX_HTTP_MP4_CO64_ATOM].buf = atom;
[3766]     trak->out[NGX_HTTP_MP4_CO64_DATA].buf = data;
[3767] 
[3768]     ngx_mp4_atom_next(mp4, atom_data_size);
[3769] 
[3770]     return NGX_OK;
[3771] }
[3772] 
[3773] 
[3774] static ngx_int_t
[3775] ngx_http_mp4_update_co64_atom(ngx_http_mp4_file_t *mp4,
[3776]     ngx_http_mp4_trak_t *trak)
[3777] {
[3778]     size_t                atom_size;
[3779]     uint64_t              entries, chunk_offset, samples_size;
[3780]     ngx_buf_t            *atom, *data;
[3781]     ngx_mp4_co64_atom_t  *co64_atom;
[3782] 
[3783]     /*
[3784]      * mdia.minf.stbl.co64 updating requires trak->start_chunk
[3785]      * from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
[3786]      * atom which may reside after mdia.minf
[3787]      */
[3788] 
[3789]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3790]                    "mp4 co64 atom update");
[3791] 
[3792]     data = trak->out[NGX_HTTP_MP4_CO64_DATA].buf;
[3793] 
[3794]     if (data == NULL) {
[3795]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3796]                       "no mp4 co64 atoms were found in \"%s\"",
[3797]                       mp4->file.name.data);
[3798]         return NGX_ERROR;
[3799]     }
[3800] 
[3801]     if (trak->start_chunk > trak->chunks) {
[3802]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3803]                       "start time is out mp4 co64 chunks in \"%s\"",
[3804]                       mp4->file.name.data);
[3805]         return NGX_ERROR;
[3806]     }
[3807] 
[3808]     data->pos += trak->start_chunk * sizeof(uint64_t);
[3809] 
[3810]     chunk_offset = ngx_mp4_get_64value(data->pos);
[3811]     samples_size = trak->start_chunk_samples_size;
[3812] 
[3813]     if (chunk_offset > (uint64_t) mp4->end - samples_size) {
[3814]         ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3815]                       "too large chunk offset in \"%s\"",
[3816]                       mp4->file.name.data);
[3817]         return NGX_ERROR;
[3818]     }
[3819] 
[3820]     trak->start_offset = chunk_offset + samples_size;
[3821]     ngx_mp4_set_64value(data->pos, trak->start_offset);
[3822] 
[3823]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3824]                    "start chunk offset:%O", trak->start_offset);
[3825] 
[3826]     if (mp4->length) {
[3827] 
[3828]         if (trak->end_chunk > trak->chunks) {
[3829]             ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3830]                           "end time is out mp4 co64 chunks in \"%s\"",
[3831]                           mp4->file.name.data);
[3832]             return NGX_ERROR;
[3833]         }
[3834] 
[3835]         entries = trak->end_chunk - trak->start_chunk;
[3836]         data->last = data->pos + entries * sizeof(uint64_t);
[3837] 
[3838]         if (entries) {
[3839]             chunk_offset = ngx_mp4_get_64value(data->last - sizeof(uint64_t));
[3840]             samples_size = trak->end_chunk_samples_size;
[3841] 
[3842]             if (chunk_offset > (uint64_t) mp4->end - samples_size) {
[3843]                 ngx_log_error(NGX_LOG_ERR, mp4->file.log, 0,
[3844]                               "too large chunk offset in \"%s\"",
[3845]                               mp4->file.name.data);
[3846]                 return NGX_ERROR;
[3847]             }
[3848] 
[3849]             trak->end_offset = chunk_offset + samples_size;
[3850] 
[3851]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3852]                            "end chunk offset:%O", trak->end_offset);
[3853]         }
[3854] 
[3855]     } else {
[3856]         entries = trak->chunks - trak->start_chunk;
[3857]         trak->end_offset = mp4->mdat_data.buf->file_last;
[3858]     }
[3859] 
[3860]     if (entries == 0) {
[3861]         trak->start_offset = mp4->end;
[3862]         trak->end_offset = 0;
[3863]     }
[3864] 
[3865]     atom_size = sizeof(ngx_mp4_co64_atom_t) + (data->last - data->pos);
[3866]     trak->size += atom_size;
[3867] 
[3868]     atom = trak->out[NGX_HTTP_MP4_CO64_ATOM].buf;
[3869]     co64_atom = (ngx_mp4_co64_atom_t *) atom->pos;
[3870] 
[3871]     ngx_mp4_set_32value(co64_atom->size, atom_size);
[3872]     ngx_mp4_set_32value(co64_atom->entries, entries);
[3873] 
[3874]     return NGX_OK;
[3875] }
[3876] 
[3877] 
[3878] static void
[3879] ngx_http_mp4_adjust_co64_atom(ngx_http_mp4_file_t *mp4,
[3880]     ngx_http_mp4_trak_t *trak, off_t adjustment)
[3881] {
[3882]     uint64_t    offset, *entry, *end;
[3883]     ngx_buf_t  *data;
[3884] 
[3885]     /*
[3886]      * moov.trak.mdia.minf.stbl.co64 adjustment requires
[3887]      * minimal start offset of all traks and new moov atom size
[3888]      */
[3889] 
[3890]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, mp4->file.log, 0,
[3891]                    "mp4 co64 atom adjustment");
[3892] 
[3893]     data = trak->out[NGX_HTTP_MP4_CO64_DATA].buf;
[3894]     entry = (uint64_t *) data->pos;
[3895]     end = (uint64_t *) data->last;
[3896] 
[3897]     while (entry < end) {
[3898]         offset = ngx_mp4_get_64value(entry);
[3899]         offset += adjustment;
[3900]         ngx_mp4_set_64value(entry, offset);
[3901]         entry++;
[3902]     }
[3903] }
[3904] 
[3905] 
[3906] static char *
[3907] ngx_http_mp4(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[3908] {
[3909]     ngx_http_core_loc_conf_t  *clcf;
[3910] 
[3911]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[3912]     clcf->handler = ngx_http_mp4_handler;
[3913] 
[3914]     return NGX_CONF_OK;
[3915] }
[3916] 
[3917] 
[3918] static void *
[3919] ngx_http_mp4_create_conf(ngx_conf_t *cf)
[3920] {
[3921]     ngx_http_mp4_conf_t  *conf;
[3922] 
[3923]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_mp4_conf_t));
[3924]     if (conf == NULL) {
[3925]         return NULL;
[3926]     }
[3927] 
[3928]     conf->buffer_size = NGX_CONF_UNSET_SIZE;
[3929]     conf->max_buffer_size = NGX_CONF_UNSET_SIZE;
[3930]     conf->start_key_frame = NGX_CONF_UNSET;
[3931] 
[3932]     return conf;
[3933] }
[3934] 
[3935] 
[3936] static char *
[3937] ngx_http_mp4_merge_conf(ngx_conf_t *cf, void *parent, void *child)
[3938] {
[3939]     ngx_http_mp4_conf_t *prev = parent;
[3940]     ngx_http_mp4_conf_t *conf = child;
[3941] 
[3942]     ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 512 * 1024);
[3943]     ngx_conf_merge_size_value(conf->max_buffer_size, prev->max_buffer_size,
[3944]                               10 * 1024 * 1024);
[3945]     ngx_conf_merge_value(conf->start_key_frame, prev->start_key_frame, 0);
[3946] 
[3947]     return NGX_CONF_OK;
[3948] }
