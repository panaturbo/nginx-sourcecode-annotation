[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STREAM_SCRIPT_H_INCLUDED_
[9] #define _NGX_STREAM_SCRIPT_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_stream.h>
[15] 
[16] 
[17] typedef struct {
[18]     u_char                       *ip;
[19]     u_char                       *pos;
[20]     ngx_stream_variable_value_t  *sp;
[21] 
[22]     ngx_str_t                     buf;
[23]     ngx_str_t                     line;
[24] 
[25]     unsigned                      flushed:1;
[26]     unsigned                      skip:1;
[27] 
[28]     ngx_stream_session_t         *session;
[29] } ngx_stream_script_engine_t;
[30] 
[31] 
[32] typedef struct {
[33]     ngx_conf_t                   *cf;
[34]     ngx_str_t                    *source;
[35] 
[36]     ngx_array_t                 **flushes;
[37]     ngx_array_t                 **lengths;
[38]     ngx_array_t                 **values;
[39] 
[40]     ngx_uint_t                    variables;
[41]     ngx_uint_t                    ncaptures;
[42]     ngx_uint_t                    size;
[43] 
[44]     void                         *main;
[45] 
[46]     unsigned                      complete_lengths:1;
[47]     unsigned                      complete_values:1;
[48]     unsigned                      zero:1;
[49]     unsigned                      conf_prefix:1;
[50]     unsigned                      root_prefix:1;
[51] } ngx_stream_script_compile_t;
[52] 
[53] 
[54] typedef struct {
[55]     ngx_str_t                     value;
[56]     ngx_uint_t                   *flushes;
[57]     void                         *lengths;
[58]     void                         *values;
[59] 
[60]     union {
[61]         size_t                    size;
[62]     } u;
[63] } ngx_stream_complex_value_t;
[64] 
[65] 
[66] typedef struct {
[67]     ngx_conf_t                   *cf;
[68]     ngx_str_t                    *value;
[69]     ngx_stream_complex_value_t   *complex_value;
[70] 
[71]     unsigned                      zero:1;
[72]     unsigned                      conf_prefix:1;
[73]     unsigned                      root_prefix:1;
[74] } ngx_stream_compile_complex_value_t;
[75] 
[76] 
[77] typedef void (*ngx_stream_script_code_pt) (ngx_stream_script_engine_t *e);
[78] typedef size_t (*ngx_stream_script_len_code_pt) (ngx_stream_script_engine_t *e);
[79] 
[80] 
[81] typedef struct {
[82]     ngx_stream_script_code_pt     code;
[83]     uintptr_t                     len;
[84] } ngx_stream_script_copy_code_t;
[85] 
[86] 
[87] typedef struct {
[88]     ngx_stream_script_code_pt     code;
[89]     uintptr_t                     index;
[90] } ngx_stream_script_var_code_t;
[91] 
[92] 
[93] typedef struct {
[94]     ngx_stream_script_code_pt     code;
[95]     uintptr_t                     n;
[96] } ngx_stream_script_copy_capture_code_t;
[97] 
[98] 
[99] typedef struct {
[100]     ngx_stream_script_code_pt     code;
[101]     uintptr_t                     conf_prefix;
[102] } ngx_stream_script_full_name_code_t;
[103] 
[104] 
[105] void ngx_stream_script_flush_complex_value(ngx_stream_session_t *s,
[106]     ngx_stream_complex_value_t *val);
[107] ngx_int_t ngx_stream_complex_value(ngx_stream_session_t *s,
[108]     ngx_stream_complex_value_t *val, ngx_str_t *value);
[109] size_t ngx_stream_complex_value_size(ngx_stream_session_t *s,
[110]     ngx_stream_complex_value_t *val, size_t default_value);
[111] ngx_int_t ngx_stream_compile_complex_value(
[112]     ngx_stream_compile_complex_value_t *ccv);
[113] char *ngx_stream_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[114]     void *conf);
[115] char *ngx_stream_set_complex_value_zero_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[116]     void *conf);
[117] char *ngx_stream_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[118]     void *conf);
[119] 
[120] 
[121] ngx_uint_t ngx_stream_script_variables_count(ngx_str_t *value);
[122] ngx_int_t ngx_stream_script_compile(ngx_stream_script_compile_t *sc);
[123] u_char *ngx_stream_script_run(ngx_stream_session_t *s, ngx_str_t *value,
[124]     void *code_lengths, size_t reserved, void *code_values);
[125] void ngx_stream_script_flush_no_cacheable_variables(ngx_stream_session_t *s,
[126]     ngx_array_t *indices);
[127] 
[128] void *ngx_stream_script_add_code(ngx_array_t *codes, size_t size, void *code);
[129] 
[130] size_t ngx_stream_script_copy_len_code(ngx_stream_script_engine_t *e);
[131] void ngx_stream_script_copy_code(ngx_stream_script_engine_t *e);
[132] size_t ngx_stream_script_copy_var_len_code(ngx_stream_script_engine_t *e);
[133] void ngx_stream_script_copy_var_code(ngx_stream_script_engine_t *e);
[134] size_t ngx_stream_script_copy_capture_len_code(ngx_stream_script_engine_t *e);
[135] void ngx_stream_script_copy_capture_code(ngx_stream_script_engine_t *e);
[136] 
[137] #endif /* _NGX_STREAM_SCRIPT_H_INCLUDED_ */
