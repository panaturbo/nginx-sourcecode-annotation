[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MAIL_SSL_H_INCLUDED_
[9] #define _NGX_MAIL_SSL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_mail.h>
[15] 
[16] 
[17] #define NGX_MAIL_STARTTLS_OFF   0
[18] #define NGX_MAIL_STARTTLS_ON    1
[19] #define NGX_MAIL_STARTTLS_ONLY  2
[20] 
[21] 
[22] typedef struct {
[23]     ngx_flag_t       enable;
[24]     ngx_flag_t       prefer_server_ciphers;
[25] 
[26]     ngx_ssl_t        ssl;
[27] 
[28]     ngx_uint_t       starttls;
[29]     ngx_uint_t       listen;
[30]     ngx_uint_t       protocols;
[31] 
[32]     ngx_uint_t       verify;
[33]     ngx_uint_t       verify_depth;
[34] 
[35]     ssize_t          builtin_session_cache;
[36] 
[37]     time_t           session_timeout;
[38] 
[39]     ngx_array_t     *certificates;
[40]     ngx_array_t     *certificate_keys;
[41] 
[42]     ngx_str_t        dhparam;
[43]     ngx_str_t        ecdh_curve;
[44]     ngx_str_t        client_certificate;
[45]     ngx_str_t        trusted_certificate;
[46]     ngx_str_t        crl;
[47] 
[48]     ngx_str_t        ciphers;
[49] 
[50]     ngx_array_t     *passwords;
[51]     ngx_array_t     *conf_commands;
[52] 
[53]     ngx_shm_zone_t  *shm_zone;
[54] 
[55]     ngx_flag_t       session_tickets;
[56]     ngx_array_t     *session_ticket_keys;
[57] 
[58]     u_char          *file;
[59]     ngx_uint_t       line;
[60] } ngx_mail_ssl_conf_t;
[61] 
[62] 
[63] extern ngx_module_t  ngx_mail_ssl_module;
[64] 
[65] 
[66] #endif /* _NGX_MAIL_SSL_H_INCLUDED_ */
