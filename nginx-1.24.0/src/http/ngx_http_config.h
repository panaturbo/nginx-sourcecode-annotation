[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
[9] #define _NGX_HTTP_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] typedef struct {
[18]     void        **main_conf;
[19]     void        **srv_conf;
[20]     void        **loc_conf;
[21] } ngx_http_conf_ctx_t;
[22] 
[23] 
[24] typedef struct {
[25]     ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);
[26]     ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);
[27] 
[28]     void       *(*create_main_conf)(ngx_conf_t *cf);
[29]     char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);
[30] 
[31]     void       *(*create_srv_conf)(ngx_conf_t *cf);
[32]     char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
[33] 
[34]     void       *(*create_loc_conf)(ngx_conf_t *cf);
[35]     char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
[36] } ngx_http_module_t;
[37] 
[38] 
[39] #define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */
[40] 
[41] #define NGX_HTTP_MAIN_CONF        0x02000000
[42] #define NGX_HTTP_SRV_CONF         0x04000000
[43] #define NGX_HTTP_LOC_CONF         0x08000000
[44] #define NGX_HTTP_UPS_CONF         0x10000000
[45] #define NGX_HTTP_SIF_CONF         0x20000000
[46] #define NGX_HTTP_LIF_CONF         0x40000000
[47] #define NGX_HTTP_LMT_CONF         0x80000000
[48] 
[49] 
[50] #define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
[51] #define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
[52] #define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)
[53] 
[54] 
[55] #define ngx_http_get_module_main_conf(r, module)                             \
[56]     (r)->main_conf[module.ctx_index]
[57] #define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
[58] #define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]
[59] 
[60] 
[61] #define ngx_http_conf_get_module_main_conf(cf, module)                        \
[62]     ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
[63] #define ngx_http_conf_get_module_srv_conf(cf, module)                         \
[64]     ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
[65] #define ngx_http_conf_get_module_loc_conf(cf, module)                         \
[66]     ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]
[67] 
[68] #define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
[69]     (cycle->conf_ctx[ngx_http_module.index] ?                                 \
[70]         ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
[71]             ->main_conf[module.ctx_index]:                                    \
[72]         NULL)
[73] 
[74] 
[75] #endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
