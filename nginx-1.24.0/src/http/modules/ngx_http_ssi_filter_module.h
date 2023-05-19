[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_SSI_FILTER_H_INCLUDED_
[9] #define _NGX_HTTP_SSI_FILTER_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] #define NGX_HTTP_SSI_MAX_PARAMS       16
[18] 
[19] #define NGX_HTTP_SSI_COMMAND_LEN      32
[20] #define NGX_HTTP_SSI_PARAM_LEN        32
[21] #define NGX_HTTP_SSI_PARAMS_N         4
[22] 
[23] 
[24] #define NGX_HTTP_SSI_COND_IF          1
[25] #define NGX_HTTP_SSI_COND_ELSE        2
[26] 
[27] 
[28] #define NGX_HTTP_SSI_NO_ENCODING      0
[29] #define NGX_HTTP_SSI_URL_ENCODING     1
[30] #define NGX_HTTP_SSI_ENTITY_ENCODING  2
[31] 
[32] 
[33] typedef struct {
[34]     ngx_hash_t                hash;
[35]     ngx_hash_keys_arrays_t    commands;
[36] } ngx_http_ssi_main_conf_t;
[37] 
[38] 
[39] typedef struct {
[40]     ngx_buf_t                *buf;
[41] 
[42]     u_char                   *pos;
[43]     u_char                   *copy_start;
[44]     u_char                   *copy_end;
[45] 
[46]     ngx_uint_t                key;
[47]     ngx_str_t                 command;
[48]     ngx_array_t               params;
[49]     ngx_table_elt_t          *param;
[50]     ngx_table_elt_t           params_array[NGX_HTTP_SSI_PARAMS_N];
[51] 
[52]     ngx_chain_t              *in;
[53]     ngx_chain_t              *out;
[54]     ngx_chain_t             **last_out;
[55]     ngx_chain_t              *busy;
[56]     ngx_chain_t              *free;
[57] 
[58]     ngx_uint_t                state;
[59]     ngx_uint_t                saved_state;
[60]     size_t                    saved;
[61]     size_t                    looked;
[62] 
[63]     size_t                    value_len;
[64] 
[65]     ngx_list_t               *variables;
[66]     ngx_array_t              *blocks;
[67] 
[68] #if (NGX_PCRE)
[69]     ngx_uint_t                ncaptures;
[70]     int                      *captures;
[71]     u_char                   *captures_data;
[72] #endif
[73] 
[74]     unsigned                  shared:1;
[75]     unsigned                  conditional:2;
[76]     unsigned                  encoding:2;
[77]     unsigned                  block:1;
[78]     unsigned                  output:1;
[79]     unsigned                  output_chosen:1;
[80] 
[81]     ngx_http_request_t       *wait;
[82]     void                     *value_buf;
[83]     ngx_str_t                 timefmt;
[84]     ngx_str_t                 errmsg;
[85] } ngx_http_ssi_ctx_t;
[86] 
[87] 
[88] typedef ngx_int_t (*ngx_http_ssi_command_pt) (ngx_http_request_t *r,
[89]     ngx_http_ssi_ctx_t *ctx, ngx_str_t **);
[90] 
[91] 
[92] typedef struct {
[93]     ngx_str_t                 name;
[94]     ngx_uint_t                index;
[95] 
[96]     unsigned                  mandatory:1;
[97]     unsigned                  multiple:1;
[98] } ngx_http_ssi_param_t;
[99] 
[100] 
[101] typedef struct {
[102]     ngx_str_t                 name;
[103]     ngx_http_ssi_command_pt   handler;
[104]     ngx_http_ssi_param_t     *params;
[105] 
[106]     unsigned                  conditional:2;
[107]     unsigned                  block:1;
[108]     unsigned                  flush:1;
[109] } ngx_http_ssi_command_t;
[110] 
[111] 
[112] extern ngx_module_t  ngx_http_ssi_filter_module;
[113] 
[114] 
[115] #endif /* _NGX_HTTP_SSI_FILTER_H_INCLUDED_ */
