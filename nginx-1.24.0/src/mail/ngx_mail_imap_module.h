[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MAIL_IMAP_MODULE_H_INCLUDED_
[9] #define _NGX_MAIL_IMAP_MODULE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_mail.h>
[15] 
[16] 
[17] typedef struct {
[18]     size_t       client_buffer_size;
[19] 
[20]     ngx_str_t    capability;
[21]     ngx_str_t    starttls_capability;
[22]     ngx_str_t    starttls_only_capability;
[23] 
[24]     ngx_uint_t   auth_methods;
[25] 
[26]     ngx_array_t  capabilities;
[27] } ngx_mail_imap_srv_conf_t;
[28] 
[29] 
[30] void ngx_mail_imap_init_session(ngx_mail_session_t *s, ngx_connection_t *c);
[31] void ngx_mail_imap_init_protocol(ngx_event_t *rev);
[32] void ngx_mail_imap_auth_state(ngx_event_t *rev);
[33] ngx_int_t ngx_mail_imap_parse_command(ngx_mail_session_t *s);
[34] 
[35] 
[36] extern ngx_module_t  ngx_mail_imap_module;
[37] 
[38] 
[39] #endif /* _NGX_MAIL_IMAP_MODULE_H_INCLUDED_ */
