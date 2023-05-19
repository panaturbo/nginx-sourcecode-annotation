[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_SSL_H_INCLUDED_
[9] #define _NGX_HTTP_SSL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] typedef struct {
[18]     ngx_flag_t                      enable;
[19] 
[20]     ngx_ssl_t                       ssl;
[21] 
[22]     ngx_flag_t                      prefer_server_ciphers;
[23]     ngx_flag_t                      early_data;
[24]     ngx_flag_t                      reject_handshake;
[25] 
[26]     ngx_uint_t                      protocols;
[27] 
[28]     ngx_uint_t                      verify;
[29]     ngx_uint_t                      verify_depth;
[30] 
[31]     size_t                          buffer_size;
[32] 
[33]     ssize_t                         builtin_session_cache;
[34] 
[35]     time_t                          session_timeout;
[36] 
[37]     ngx_array_t                    *certificates;
[38]     ngx_array_t                    *certificate_keys;
[39] 
[40]     ngx_array_t                    *certificate_values;
[41]     ngx_array_t                    *certificate_key_values;
[42] 
[43]     ngx_str_t                       dhparam;
[44]     ngx_str_t                       ecdh_curve;
[45]     ngx_str_t                       client_certificate;
[46]     ngx_str_t                       trusted_certificate;
[47]     ngx_str_t                       crl;
[48] 
[49]     ngx_str_t                       ciphers;
[50] 
[51]     ngx_array_t                    *passwords;
[52]     ngx_array_t                    *conf_commands;
[53] 
[54]     ngx_shm_zone_t                 *shm_zone;
[55] 
[56]     ngx_flag_t                      session_tickets;
[57]     ngx_array_t                    *session_ticket_keys;
[58] 
[59]     ngx_uint_t                      ocsp;
[60]     ngx_str_t                       ocsp_responder;
[61]     ngx_shm_zone_t                 *ocsp_cache_zone;
[62] 
[63]     ngx_flag_t                      stapling;
[64]     ngx_flag_t                      stapling_verify;
[65]     ngx_str_t                       stapling_file;
[66]     ngx_str_t                       stapling_responder;
[67] 
[68]     u_char                         *file;
[69]     ngx_uint_t                      line;
[70] } ngx_http_ssl_srv_conf_t;
[71] 
[72] 
[73] extern ngx_module_t  ngx_http_ssl_module;
[74] 
[75] 
[76] #endif /* _NGX_HTTP_SSL_H_INCLUDED_ */
