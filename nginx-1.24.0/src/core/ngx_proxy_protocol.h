[1] 
[2] /*
[3]  * Copyright (C) Roman Arutyunyan
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
[9] #define _NGX_PROXY_PROTOCOL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_PROXY_PROTOCOL_V1_MAX_HEADER  107
[17] #define NGX_PROXY_PROTOCOL_MAX_HEADER     4096
[18] 
[19] 
[20] struct ngx_proxy_protocol_s {
[21]     ngx_str_t           src_addr;
[22]     ngx_str_t           dst_addr;
[23]     in_port_t           src_port;
[24]     in_port_t           dst_port;
[25]     ngx_str_t           tlvs;
[26] };
[27] 
[28] 
[29] u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
[30]     u_char *last);
[31] u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
[32]     u_char *last);
[33] ngx_int_t ngx_proxy_protocol_get_tlv(ngx_connection_t *c, ngx_str_t *name,
[34]     ngx_str_t *value);
[35] 
[36] 
[37] #endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
