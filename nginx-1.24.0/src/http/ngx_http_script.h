[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
[9] #define _NGX_HTTP_SCRIPT_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] typedef struct {
[18]     u_char                     *ip;
[19]     u_char                     *pos;
[20]     ngx_http_variable_value_t  *sp;
[21] 
[22]     ngx_str_t                   buf;
[23]     ngx_str_t                   line;
[24] 
[25]     /* the start of the rewritten arguments */
[26]     u_char                     *args;
[27] 
[28]     unsigned                    flushed:1;
[29]     unsigned                    skip:1;
[30]     unsigned                    quote:1;
[31]     unsigned                    is_args:1;
[32]     unsigned                    log:1;
[33] 
[34]     ngx_int_t                   status;
[35]     ngx_http_request_t         *request;
[36] } ngx_http_script_engine_t;
[37] 
[38] 
[39] typedef struct {
[40]     ngx_conf_t                 *cf;
[41]     ngx_str_t                  *source;
[42] 
[43]     ngx_array_t               **flushes;
[44]     ngx_array_t               **lengths;
[45]     ngx_array_t               **values;
[46] 
[47]     ngx_uint_t                  variables;
[48]     ngx_uint_t                  ncaptures;
[49]     ngx_uint_t                  captures_mask;
[50]     ngx_uint_t                  size;
[51] 
[52]     void                       *main;
[53] 
[54]     unsigned                    compile_args:1;
[55]     unsigned                    complete_lengths:1;
[56]     unsigned                    complete_values:1;
[57]     unsigned                    zero:1;
[58]     unsigned                    conf_prefix:1;
[59]     unsigned                    root_prefix:1;
[60] 
[61]     unsigned                    dup_capture:1;
[62]     unsigned                    args:1;
[63] } ngx_http_script_compile_t;
[64] 
[65] 
[66] typedef struct {
[67]     ngx_str_t                   value;
[68]     ngx_uint_t                 *flushes;
[69]     void                       *lengths;
[70]     void                       *values;
[71] 
[72]     union {
[73]         size_t                  size;
[74]     } u;
[75] } ngx_http_complex_value_t;
[76] 
[77] 
[78] typedef struct {
[79]     ngx_conf_t                 *cf;
[80]     ngx_str_t                  *value;
[81]     ngx_http_complex_value_t   *complex_value;
[82] 
[83]     unsigned                    zero:1;
[84]     unsigned                    conf_prefix:1;
[85]     unsigned                    root_prefix:1;
[86] } ngx_http_compile_complex_value_t;
[87] 
[88] 
[89] typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
[90] typedef size_t (*ngx_http_script_len_code_pt) (ngx_http_script_engine_t *e);
[91] 
[92] 
[93] typedef struct {
[94]     ngx_http_script_code_pt     code;
[95]     uintptr_t                   len;
[96] } ngx_http_script_copy_code_t;
[97] 
[98] 
[99] typedef struct {
[100]     ngx_http_script_code_pt     code;
[101]     uintptr_t                   index;
[102] } ngx_http_script_var_code_t;
[103] 
[104] 
[105] typedef struct {
[106]     ngx_http_script_code_pt     code;
[107]     ngx_http_set_variable_pt    handler;
[108]     uintptr_t                   data;
[109] } ngx_http_script_var_handler_code_t;
[110] 
[111] 
[112] typedef struct {
[113]     ngx_http_script_code_pt     code;
[114]     uintptr_t                   n;
[115] } ngx_http_script_copy_capture_code_t;
[116] 
[117] 
[118] #if (NGX_PCRE)
[119] 
[120] typedef struct {
[121]     ngx_http_script_code_pt     code;
[122]     ngx_http_regex_t           *regex;
[123]     ngx_array_t                *lengths;
[124]     uintptr_t                   size;
[125]     uintptr_t                   status;
[126]     uintptr_t                   next;
[127] 
[128]     unsigned                    test:1;
[129]     unsigned                    negative_test:1;
[130]     unsigned                    uri:1;
[131]     unsigned                    args:1;
[132] 
[133]     /* add the r->args to the new arguments */
[134]     unsigned                    add_args:1;
[135] 
[136]     unsigned                    redirect:1;
[137]     unsigned                    break_cycle:1;
[138] 
[139]     ngx_str_t                   name;
[140] } ngx_http_script_regex_code_t;
[141] 
[142] 
[143] typedef struct {
[144]     ngx_http_script_code_pt     code;
[145] 
[146]     unsigned                    uri:1;
[147]     unsigned                    args:1;
[148] 
[149]     /* add the r->args to the new arguments */
[150]     unsigned                    add_args:1;
[151] 
[152]     unsigned                    redirect:1;
[153] } ngx_http_script_regex_end_code_t;
[154] 
[155] #endif
[156] 
[157] 
[158] typedef struct {
[159]     ngx_http_script_code_pt     code;
[160]     uintptr_t                   conf_prefix;
[161] } ngx_http_script_full_name_code_t;
[162] 
[163] 
[164] typedef struct {
[165]     ngx_http_script_code_pt     code;
[166]     uintptr_t                   status;
[167]     ngx_http_complex_value_t    text;
[168] } ngx_http_script_return_code_t;
[169] 
[170] 
[171] typedef enum {
[172]     ngx_http_script_file_plain = 0,
[173]     ngx_http_script_file_not_plain,
[174]     ngx_http_script_file_dir,
[175]     ngx_http_script_file_not_dir,
[176]     ngx_http_script_file_exists,
[177]     ngx_http_script_file_not_exists,
[178]     ngx_http_script_file_exec,
[179]     ngx_http_script_file_not_exec
[180] } ngx_http_script_file_op_e;
[181] 
[182] 
[183] typedef struct {
[184]     ngx_http_script_code_pt     code;
[185]     uintptr_t                   op;
[186] } ngx_http_script_file_code_t;
[187] 
[188] 
[189] typedef struct {
[190]     ngx_http_script_code_pt     code;
[191]     uintptr_t                   next;
[192]     void                      **loc_conf;
[193] } ngx_http_script_if_code_t;
[194] 
[195] 
[196] typedef struct {
[197]     ngx_http_script_code_pt     code;
[198]     ngx_array_t                *lengths;
[199] } ngx_http_script_complex_value_code_t;
[200] 
[201] 
[202] typedef struct {
[203]     ngx_http_script_code_pt     code;
[204]     uintptr_t                   value;
[205]     uintptr_t                   text_len;
[206]     uintptr_t                   text_data;
[207] } ngx_http_script_value_code_t;
[208] 
[209] 
[210] void ngx_http_script_flush_complex_value(ngx_http_request_t *r,
[211]     ngx_http_complex_value_t *val);
[212] ngx_int_t ngx_http_complex_value(ngx_http_request_t *r,
[213]     ngx_http_complex_value_t *val, ngx_str_t *value);
[214] size_t ngx_http_complex_value_size(ngx_http_request_t *r,
[215]     ngx_http_complex_value_t *val, size_t default_value);
[216] ngx_int_t ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv);
[217] char *ngx_http_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[218]     void *conf);
[219] char *ngx_http_set_complex_value_zero_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[220]     void *conf);
[221] char *ngx_http_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[222]     void *conf);
[223] 
[224] 
[225] ngx_int_t ngx_http_test_predicates(ngx_http_request_t *r,
[226]     ngx_array_t *predicates);
[227] ngx_int_t ngx_http_test_required_predicates(ngx_http_request_t *r,
[228]     ngx_array_t *predicates);
[229] char *ngx_http_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[230]     void *conf);
[231] 
[232] ngx_uint_t ngx_http_script_variables_count(ngx_str_t *value);
[233] ngx_int_t ngx_http_script_compile(ngx_http_script_compile_t *sc);
[234] u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value,
[235]     void *code_lengths, size_t reserved, void *code_values);
[236] void ngx_http_script_flush_no_cacheable_variables(ngx_http_request_t *r,
[237]     ngx_array_t *indices);
[238] 
[239] void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
[240]     size_t size);
[241] void *ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code);
[242] 
[243] size_t ngx_http_script_copy_len_code(ngx_http_script_engine_t *e);
[244] void ngx_http_script_copy_code(ngx_http_script_engine_t *e);
[245] size_t ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e);
[246] void ngx_http_script_copy_var_code(ngx_http_script_engine_t *e);
[247] size_t ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e);
[248] void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
[249] size_t ngx_http_script_mark_args_code(ngx_http_script_engine_t *e);
[250] void ngx_http_script_start_args_code(ngx_http_script_engine_t *e);
[251] #if (NGX_PCRE)
[252] void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
[253] void ngx_http_script_regex_end_code(ngx_http_script_engine_t *e);
[254] #endif
[255] void ngx_http_script_return_code(ngx_http_script_engine_t *e);
[256] void ngx_http_script_break_code(ngx_http_script_engine_t *e);
[257] void ngx_http_script_if_code(ngx_http_script_engine_t *e);
[258] void ngx_http_script_equal_code(ngx_http_script_engine_t *e);
[259] void ngx_http_script_not_equal_code(ngx_http_script_engine_t *e);
[260] void ngx_http_script_file_code(ngx_http_script_engine_t *e);
[261] void ngx_http_script_complex_value_code(ngx_http_script_engine_t *e);
[262] void ngx_http_script_value_code(ngx_http_script_engine_t *e);
[263] void ngx_http_script_set_var_code(ngx_http_script_engine_t *e);
[264] void ngx_http_script_var_set_handler_code(ngx_http_script_engine_t *e);
[265] void ngx_http_script_var_code(ngx_http_script_engine_t *e);
[266] void ngx_http_script_nop_code(ngx_http_script_engine_t *e);
[267] 
[268] 
[269] #endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
