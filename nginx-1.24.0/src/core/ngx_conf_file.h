[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CONF_FILE_H_INCLUDED_
[9] #define _NGX_CONF_FILE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] /*
[17]  *        AAAA  number of arguments
[18]  *      FF      command flags
[19]  *    TT        command type, i.e. HTTP "location" or "server" command
[20]  */
[21] 
[22] #define NGX_CONF_NOARGS      0x00000001
[23] #define NGX_CONF_TAKE1       0x00000002
[24] #define NGX_CONF_TAKE2       0x00000004
[25] #define NGX_CONF_TAKE3       0x00000008
[26] #define NGX_CONF_TAKE4       0x00000010
[27] #define NGX_CONF_TAKE5       0x00000020
[28] #define NGX_CONF_TAKE6       0x00000040
[29] #define NGX_CONF_TAKE7       0x00000080
[30] 
[31] #define NGX_CONF_MAX_ARGS    8
[32] 
[33] #define NGX_CONF_TAKE12      (NGX_CONF_TAKE1|NGX_CONF_TAKE2)
[34] #define NGX_CONF_TAKE13      (NGX_CONF_TAKE1|NGX_CONF_TAKE3)
[35] 
[36] #define NGX_CONF_TAKE23      (NGX_CONF_TAKE2|NGX_CONF_TAKE3)
[37] 
[38] #define NGX_CONF_TAKE123     (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3)
[39] #define NGX_CONF_TAKE1234    (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3   \
[40]                               |NGX_CONF_TAKE4)
[41] 
[42] #define NGX_CONF_ARGS_NUMBER 0x000000ff
[43] #define NGX_CONF_BLOCK       0x00000100
[44] #define NGX_CONF_FLAG        0x00000200
[45] #define NGX_CONF_ANY         0x00000400
[46] #define NGX_CONF_1MORE       0x00000800
[47] #define NGX_CONF_2MORE       0x00001000
[48] 
[49] #define NGX_DIRECT_CONF      0x00010000
[50] 
[51] #define NGX_MAIN_CONF        0x01000000
[52] #define NGX_ANY_CONF         0xFF000000
[53] 
[54] 
[55] 
[56] #define NGX_CONF_UNSET       -1
[57] #define NGX_CONF_UNSET_UINT  (ngx_uint_t) -1
[58] #define NGX_CONF_UNSET_PTR   (void *) -1
[59] #define NGX_CONF_UNSET_SIZE  (size_t) -1
[60] #define NGX_CONF_UNSET_MSEC  (ngx_msec_t) -1
[61] 
[62] 
[63] #define NGX_CONF_OK          NULL
[64] #define NGX_CONF_ERROR       (void *) -1
[65] 
[66] #define NGX_CONF_BLOCK_START 1
[67] #define NGX_CONF_BLOCK_DONE  2
[68] #define NGX_CONF_FILE_DONE   3
[69] 
[70] #define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
[71] #define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */
[72] 
[73] 
[74] #define NGX_MAX_CONF_ERRSTR  1024
[75] 
[76] 
[77] struct ngx_command_s {
[78]     ngx_str_t             name;
[79]     ngx_uint_t            type;
[80]     char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[81]     ngx_uint_t            conf;
[82]     ngx_uint_t            offset;
[83]     void                 *post;
[84] };
[85] 
[86] #define ngx_null_command  { ngx_null_string, 0, NULL, 0, 0, NULL }
[87] 
[88] 
[89] struct ngx_open_file_s {
[90]     ngx_fd_t              fd;
[91]     ngx_str_t             name;
[92] 
[93]     void                (*flush)(ngx_open_file_t *file, ngx_log_t *log);
[94]     void                 *data;
[95] };
[96] 
[97] 
[98] typedef struct {
[99]     ngx_file_t            file;
[100]     ngx_buf_t            *buffer;
[101]     ngx_buf_t            *dump;
[102]     ngx_uint_t            line;
[103] } ngx_conf_file_t;
[104] 
[105] 
[106] typedef struct {
[107]     ngx_str_t             name;
[108]     ngx_buf_t            *buffer;
[109] } ngx_conf_dump_t;
[110] 
[111] 
[112] typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
[113]     ngx_command_t *dummy, void *conf);
[114] 
[115] 
[116] struct ngx_conf_s {
[117]     char                 *name;
[118]     ngx_array_t          *args;
[119] 
[120]     ngx_cycle_t          *cycle;
[121]     ngx_pool_t           *pool;
[122]     ngx_pool_t           *temp_pool;
[123]     ngx_conf_file_t      *conf_file;
[124]     ngx_log_t            *log;
[125] 
[126]     void                 *ctx;
[127]     ngx_uint_t            module_type;
[128]     ngx_uint_t            cmd_type;
[129] 
[130]     ngx_conf_handler_pt   handler;
[131]     void                 *handler_conf;
[132] };
[133] 
[134] 
[135] typedef char *(*ngx_conf_post_handler_pt) (ngx_conf_t *cf,
[136]     void *data, void *conf);
[137] 
[138] typedef struct {
[139]     ngx_conf_post_handler_pt  post_handler;
[140] } ngx_conf_post_t;
[141] 
[142] 
[143] typedef struct {
[144]     ngx_conf_post_handler_pt  post_handler;
[145]     char                     *old_name;
[146]     char                     *new_name;
[147] } ngx_conf_deprecated_t;
[148] 
[149] 
[150] typedef struct {
[151]     ngx_conf_post_handler_pt  post_handler;
[152]     ngx_int_t                 low;
[153]     ngx_int_t                 high;
[154] } ngx_conf_num_bounds_t;
[155] 
[156] 
[157] typedef struct {
[158]     ngx_str_t                 name;
[159]     ngx_uint_t                value;
[160] } ngx_conf_enum_t;
[161] 
[162] 
[163] #define NGX_CONF_BITMASK_SET  1
[164] 
[165] typedef struct {
[166]     ngx_str_t                 name;
[167]     ngx_uint_t                mask;
[168] } ngx_conf_bitmask_t;
[169] 
[170] 
[171] 
[172] char * ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data);
[173] char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data);
[174] 
[175] 
[176] #define ngx_get_conf(conf_ctx, module)  conf_ctx[module.index]
[177] 
[178] 
[179] 
[180] #define ngx_conf_init_value(conf, default)                                   \
[181]     if (conf == NGX_CONF_UNSET) {                                            \
[182]         conf = default;                                                      \
[183]     }
[184] 
[185] #define ngx_conf_init_ptr_value(conf, default)                               \
[186]     if (conf == NGX_CONF_UNSET_PTR) {                                        \
[187]         conf = default;                                                      \
[188]     }
[189] 
[190] #define ngx_conf_init_uint_value(conf, default)                              \
[191]     if (conf == NGX_CONF_UNSET_UINT) {                                       \
[192]         conf = default;                                                      \
[193]     }
[194] 
[195] #define ngx_conf_init_size_value(conf, default)                              \
[196]     if (conf == NGX_CONF_UNSET_SIZE) {                                       \
[197]         conf = default;                                                      \
[198]     }
[199] 
[200] #define ngx_conf_init_msec_value(conf, default)                              \
[201]     if (conf == NGX_CONF_UNSET_MSEC) {                                       \
[202]         conf = default;                                                      \
[203]     }
[204] 
[205] #define ngx_conf_merge_value(conf, prev, default)                            \
[206]     if (conf == NGX_CONF_UNSET) {                                            \
[207]         conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
[208]     }
[209] 
[210] #define ngx_conf_merge_ptr_value(conf, prev, default)                        \
[211]     if (conf == NGX_CONF_UNSET_PTR) {                                        \
[212]         conf = (prev == NGX_CONF_UNSET_PTR) ? default : prev;                \
[213]     }
[214] 
[215] #define ngx_conf_merge_uint_value(conf, prev, default)                       \
[216]     if (conf == NGX_CONF_UNSET_UINT) {                                       \
[217]         conf = (prev == NGX_CONF_UNSET_UINT) ? default : prev;               \
[218]     }
[219] 
[220] #define ngx_conf_merge_msec_value(conf, prev, default)                       \
[221]     if (conf == NGX_CONF_UNSET_MSEC) {                                       \
[222]         conf = (prev == NGX_CONF_UNSET_MSEC) ? default : prev;               \
[223]     }
[224] 
[225] #define ngx_conf_merge_sec_value(conf, prev, default)                        \
[226]     if (conf == NGX_CONF_UNSET) {                                            \
[227]         conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
[228]     }
[229] 
[230] #define ngx_conf_merge_size_value(conf, prev, default)                       \
[231]     if (conf == NGX_CONF_UNSET_SIZE) {                                       \
[232]         conf = (prev == NGX_CONF_UNSET_SIZE) ? default : prev;               \
[233]     }
[234] 
[235] #define ngx_conf_merge_off_value(conf, prev, default)                        \
[236]     if (conf == NGX_CONF_UNSET) {                                            \
[237]         conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
[238]     }
[239] 
[240] #define ngx_conf_merge_str_value(conf, prev, default)                        \
[241]     if (conf.data == NULL) {                                                 \
[242]         if (prev.data) {                                                     \
[243]             conf.len = prev.len;                                             \
[244]             conf.data = prev.data;                                           \
[245]         } else {                                                             \
[246]             conf.len = sizeof(default) - 1;                                  \
[247]             conf.data = (u_char *) default;                                  \
[248]         }                                                                    \
[249]     }
[250] 
[251] #define ngx_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
[252]     if (conf.num == 0) {                                                     \
[253]         if (prev.num) {                                                      \
[254]             conf.num = prev.num;                                             \
[255]             conf.size = prev.size;                                           \
[256]         } else {                                                             \
[257]             conf.num = default_num;                                          \
[258]             conf.size = default_size;                                        \
[259]         }                                                                    \
[260]     }
[261] 
[262] #define ngx_conf_merge_bitmask_value(conf, prev, default)                    \
[263]     if (conf == 0) {                                                         \
[264]         conf = (prev == 0) ? default : prev;                                 \
[265]     }
[266] 
[267] 
[268] char *ngx_conf_param(ngx_conf_t *cf);
[269] char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);
[270] char *ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[271] 
[272] 
[273] ngx_int_t ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name,
[274]     ngx_uint_t conf_prefix);
[275] ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name);
[276] void ngx_cdecl ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf,
[277]     ngx_err_t err, const char *fmt, ...);
[278] 
[279] 
[280] char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[281] char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[282] char *ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[283]     void *conf);
[284] char *ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[285] char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[286] char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[287] char *ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[288] char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[289] char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[290] char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[291] char *ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[292] char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[293] 
[294] 
[295] #endif /* _NGX_CONF_FILE_H_INCLUDED_ */
