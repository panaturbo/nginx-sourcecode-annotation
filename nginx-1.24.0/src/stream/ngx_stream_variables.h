[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STREAM_VARIABLES_H_INCLUDED_
[9] #define _NGX_STREAM_VARIABLES_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_stream.h>
[15] 
[16] 
[17] typedef ngx_variable_value_t  ngx_stream_variable_value_t;
[18] 
[19] #define ngx_stream_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }
[20] 
[21] typedef struct ngx_stream_variable_s  ngx_stream_variable_t;
[22] 
[23] typedef void (*ngx_stream_set_variable_pt) (ngx_stream_session_t *s,
[24]     ngx_stream_variable_value_t *v, uintptr_t data);
[25] typedef ngx_int_t (*ngx_stream_get_variable_pt) (ngx_stream_session_t *s,
[26]     ngx_stream_variable_value_t *v, uintptr_t data);
[27] 
[28] 
[29] #define NGX_STREAM_VAR_CHANGEABLE   1
[30] #define NGX_STREAM_VAR_NOCACHEABLE  2
[31] #define NGX_STREAM_VAR_INDEXED      4
[32] #define NGX_STREAM_VAR_NOHASH       8
[33] #define NGX_STREAM_VAR_WEAK         16
[34] #define NGX_STREAM_VAR_PREFIX       32
[35] 
[36] 
[37] struct ngx_stream_variable_s {
[38]     ngx_str_t                     name;   /* must be first to build the hash */
[39]     ngx_stream_set_variable_pt    set_handler;
[40]     ngx_stream_get_variable_pt    get_handler;
[41]     uintptr_t                     data;
[42]     ngx_uint_t                    flags;
[43]     ngx_uint_t                    index;
[44] };
[45] 
[46] #define ngx_stream_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }
[47] 
[48] 
[49] ngx_stream_variable_t *ngx_stream_add_variable(ngx_conf_t *cf, ngx_str_t *name,
[50]     ngx_uint_t flags);
[51] ngx_int_t ngx_stream_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
[52] ngx_stream_variable_value_t *ngx_stream_get_indexed_variable(
[53]     ngx_stream_session_t *s, ngx_uint_t index);
[54] ngx_stream_variable_value_t *ngx_stream_get_flushed_variable(
[55]     ngx_stream_session_t *s, ngx_uint_t index);
[56] 
[57] ngx_stream_variable_value_t *ngx_stream_get_variable(ngx_stream_session_t *s,
[58]     ngx_str_t *name, ngx_uint_t key);
[59] 
[60] 
[61] #if (NGX_PCRE)
[62] 
[63] typedef struct {
[64]     ngx_uint_t                    capture;
[65]     ngx_int_t                     index;
[66] } ngx_stream_regex_variable_t;
[67] 
[68] 
[69] typedef struct {
[70]     ngx_regex_t                  *regex;
[71]     ngx_uint_t                    ncaptures;
[72]     ngx_stream_regex_variable_t  *variables;
[73]     ngx_uint_t                    nvariables;
[74]     ngx_str_t                     name;
[75] } ngx_stream_regex_t;
[76] 
[77] 
[78] typedef struct {
[79]     ngx_stream_regex_t           *regex;
[80]     void                         *value;
[81] } ngx_stream_map_regex_t;
[82] 
[83] 
[84] ngx_stream_regex_t *ngx_stream_regex_compile(ngx_conf_t *cf,
[85]     ngx_regex_compile_t *rc);
[86] ngx_int_t ngx_stream_regex_exec(ngx_stream_session_t *s, ngx_stream_regex_t *re,
[87]     ngx_str_t *str);
[88] 
[89] #endif
[90] 
[91] 
[92] typedef struct {
[93]     ngx_hash_combined_t           hash;
[94] #if (NGX_PCRE)
[95]     ngx_stream_map_regex_t       *regex;
[96]     ngx_uint_t                    nregex;
[97] #endif
[98] } ngx_stream_map_t;
[99] 
[100] 
[101] void *ngx_stream_map_find(ngx_stream_session_t *s, ngx_stream_map_t *map,
[102]     ngx_str_t *match);
[103] 
[104] 
[105] ngx_int_t ngx_stream_variables_add_core_vars(ngx_conf_t *cf);
[106] ngx_int_t ngx_stream_variables_init_vars(ngx_conf_t *cf);
[107] 
[108] 
[109] extern ngx_stream_variable_value_t  ngx_stream_variable_null_value;
[110] extern ngx_stream_variable_value_t  ngx_stream_variable_true_value;
[111] 
[112] 
[113] #endif /* _NGX_STREAM_VARIABLES_H_INCLUDED_ */
