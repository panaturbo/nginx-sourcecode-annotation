[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STREAM_SSL_H_INCLUDED_
[9] #define _NGX_STREAM_SSL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_stream.h>
[15] 
[16] 
[17] typedef struct {
[18]     ngx_msec_t       handshake_timeout;
[19] 
[20]     ngx_flag_t       prefer_server_ciphers;
[21] 
[22]     ngx_ssl_t        ssl;
[23] 
[24]     ngx_uint_t       listen;
[25]     ngx_uint_t       protocols;
[26] 
[27]     ngx_uint_t       verify;
[28]     ngx_uint_t       verify_depth;
[29] 
[30]     ssize_t          builtin_session_cache;
[31] 
[32]     time_t           session_timeout;
[33] 
[34]     ngx_array_t     *certificates;
[35]     ngx_array_t     *certificate_keys;
[36] 
[37]     ngx_array_t     *certificate_values;
[38]     ngx_array_t     *certificate_key_values;
[39] 
[40]     ngx_str_t        dhparam;
[41]     ngx_str_t        ecdh_curve;
[42]     ngx_str_t        client_certificate;
[43]     ngx_str_t        trusted_certificate;
[44]     ngx_str_t        crl;
[45]     ngx_str_t        alpn;
[46] 
[47]     ngx_str_t        ciphers;
[48] 
[49]     ngx_array_t     *passwords;
[50]     ngx_array_t     *conf_commands;
[51] 
[52]     ngx_shm_zone_t  *shm_zone;
[53] 
[54]     ngx_flag_t       session_tickets;
[55]     ngx_array_t     *session_ticket_keys;
[56] 
[57]     u_char          *file;
[58]     ngx_uint_t       line;
[59] } ngx_stream_ssl_conf_t;
[60] 
[61] 
[62] extern ngx_module_t  ngx_stream_ssl_module;
[63] 
[64] 
[65] #endif /* _NGX_STREAM_SSL_H_INCLUDED_ */
