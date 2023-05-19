[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
[9] #define _NGX_HTTP_VARIABLES_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] typedef ngx_variable_value_t  ngx_http_variable_value_t;
[18] 
[19] #define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }
[20] 
[21] typedef struct ngx_http_variable_s  ngx_http_variable_t;
[22] 
[23] typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
[24]     ngx_http_variable_value_t *v, uintptr_t data);
[25] typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
[26]     ngx_http_variable_value_t *v, uintptr_t data);
[27] 
[28] 
[29] #define NGX_HTTP_VAR_CHANGEABLE   1
[30] #define NGX_HTTP_VAR_NOCACHEABLE  2
[31] #define NGX_HTTP_VAR_INDEXED      4
[32] #define NGX_HTTP_VAR_NOHASH       8
[33] #define NGX_HTTP_VAR_WEAK         16
[34] #define NGX_HTTP_VAR_PREFIX       32
[35] 
[36] 
[37] struct ngx_http_variable_s {
[38]     ngx_str_t                     name;   /* must be first to build the hash */
[39]     ngx_http_set_variable_pt      set_handler;
[40]     ngx_http_get_variable_pt      get_handler;
[41]     uintptr_t                     data;
[42]     ngx_uint_t                    flags;
[43]     ngx_uint_t                    index;
[44] };
[45] 
[46] #define ngx_http_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }
[47] 
[48] 
[49] ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
[50]     ngx_uint_t flags);
[51] ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
[52] ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
[53]     ngx_uint_t index);
[54] ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r,
[55]     ngx_uint_t index);
[56] 
[57] ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
[58]     ngx_str_t *name, ngx_uint_t key);
[59] 
[60] ngx_int_t ngx_http_variable_unknown_header(ngx_http_request_t *r,
[61]     ngx_http_variable_value_t *v, ngx_str_t *var, ngx_list_part_t *part,
[62]     size_t prefix);
[63] 
[64] 
[65] #if (NGX_PCRE)
[66] 
[67] typedef struct {
[68]     ngx_uint_t                    capture;
[69]     ngx_int_t                     index;
[70] } ngx_http_regex_variable_t;
[71] 
[72] 
[73] typedef struct {
[74]     ngx_regex_t                  *regex;
[75]     ngx_uint_t                    ncaptures;
[76]     ngx_http_regex_variable_t    *variables;
[77]     ngx_uint_t                    nvariables;
[78]     ngx_str_t                     name;
[79] } ngx_http_regex_t;
[80] 
[81] 
[82] typedef struct {
[83]     ngx_http_regex_t             *regex;
[84]     void                         *value;
[85] } ngx_http_map_regex_t;
[86] 
[87] 
[88] ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf,
[89]     ngx_regex_compile_t *rc);
[90] ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re,
[91]     ngx_str_t *s);
[92] 
[93] #endif
[94] 
[95] 
[96] typedef struct {
[97]     ngx_hash_combined_t           hash;
[98] #if (NGX_PCRE)
[99]     ngx_http_map_regex_t         *regex;
[100]     ngx_uint_t                    nregex;
[101] #endif
[102] } ngx_http_map_t;
[103] 
[104] 
[105] void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map,
[106]     ngx_str_t *match);
[107] 
[108] 
[109] ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
[110] ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);
[111] 
[112] 
[113] extern ngx_http_variable_value_t  ngx_http_variable_null_value;
[114] extern ngx_http_variable_value_t  ngx_http_variable_true_value;
[115] 
[116] 
[117] #endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
