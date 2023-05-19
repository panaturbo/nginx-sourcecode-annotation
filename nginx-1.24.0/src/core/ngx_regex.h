[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_REGEX_H_INCLUDED_
[9] #define _NGX_REGEX_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #if (NGX_PCRE2)
[17] 
[18] #define PCRE2_CODE_UNIT_WIDTH  8
[19] #include <pcre2.h>
[20] 
[21] #define NGX_REGEX_NO_MATCHED   PCRE2_ERROR_NOMATCH   /* -1 */
[22] 
[23] typedef pcre2_code  ngx_regex_t;
[24] 
[25] #else
[26] 
[27] #include <pcre.h>
[28] 
[29] #define NGX_REGEX_NO_MATCHED   PCRE_ERROR_NOMATCH    /* -1 */
[30] 
[31] typedef struct {
[32]     pcre        *code;
[33]     pcre_extra  *extra;
[34] } ngx_regex_t;
[35] 
[36] #endif
[37] 
[38] 
[39] #define NGX_REGEX_CASELESS     0x00000001
[40] #define NGX_REGEX_MULTILINE    0x00000002
[41] 
[42] 
[43] typedef struct {
[44]     ngx_str_t     pattern;
[45]     ngx_pool_t   *pool;
[46]     ngx_uint_t    options;
[47] 
[48]     ngx_regex_t  *regex;
[49]     int           captures;
[50]     int           named_captures;
[51]     int           name_size;
[52]     u_char       *names;
[53]     ngx_str_t     err;
[54] } ngx_regex_compile_t;
[55] 
[56] 
[57] typedef struct {
[58]     ngx_regex_t  *regex;
[59]     u_char       *name;
[60] } ngx_regex_elt_t;
[61] 
[62] 
[63] void ngx_regex_init(void);
[64] ngx_int_t ngx_regex_compile(ngx_regex_compile_t *rc);
[65] 
[66] ngx_int_t ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures,
[67]     ngx_uint_t size);
[68] 
[69] #if (NGX_PCRE2)
[70] #define ngx_regex_exec_n       "pcre2_match()"
[71] #else
[72] #define ngx_regex_exec_n       "pcre_exec()"
[73] #endif
[74] 
[75] ngx_int_t ngx_regex_exec_array(ngx_array_t *a, ngx_str_t *s, ngx_log_t *log);
[76] 
[77] 
[78] #endif /* _NGX_REGEX_H_INCLUDED_ */
