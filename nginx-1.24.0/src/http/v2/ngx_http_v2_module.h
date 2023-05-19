[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  * Copyright (C) Valentin V. Bartenev
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_V2_MODULE_H_INCLUDED_
[9] #define _NGX_HTTP_V2_MODULE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] typedef struct {
[18]     size_t                          recv_buffer_size;
[19]     u_char                         *recv_buffer;
[20] } ngx_http_v2_main_conf_t;
[21] 
[22] 
[23] typedef struct {
[24]     size_t                          pool_size;
[25]     ngx_uint_t                      concurrent_streams;
[26]     ngx_uint_t                      concurrent_pushes;
[27]     size_t                          preread_size;
[28]     ngx_uint_t                      streams_index_mask;
[29] } ngx_http_v2_srv_conf_t;
[30] 
[31] 
[32] typedef struct {
[33]     size_t                          chunk_size;
[34] 
[35]     ngx_flag_t                      push_preload;
[36] 
[37]     ngx_flag_t                      push;
[38]     ngx_array_t                    *pushes;
[39] } ngx_http_v2_loc_conf_t;
[40] 
[41] 
[42] extern ngx_module_t  ngx_http_v2_module;
[43] 
[44] 
[45] #endif /* _NGX_HTTP_V2_MODULE_H_INCLUDED_ */
