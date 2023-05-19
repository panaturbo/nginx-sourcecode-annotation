[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MAIL_POP3_MODULE_H_INCLUDED_
[9] #define _NGX_MAIL_POP3_MODULE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_mail.h>
[15] 
[16] 
[17] typedef struct {
[18]     ngx_str_t    capability;
[19]     ngx_str_t    starttls_capability;
[20]     ngx_str_t    starttls_only_capability;
[21]     ngx_str_t    auth_capability;
[22] 
[23]     ngx_uint_t   auth_methods;
[24] 
[25]     ngx_array_t  capabilities;
[26] } ngx_mail_pop3_srv_conf_t;
[27] 
[28] 
[29] void ngx_mail_pop3_init_session(ngx_mail_session_t *s, ngx_connection_t *c);
[30] void ngx_mail_pop3_init_protocol(ngx_event_t *rev);
[31] void ngx_mail_pop3_auth_state(ngx_event_t *rev);
[32] ngx_int_t ngx_mail_pop3_parse_command(ngx_mail_session_t *s);
[33] 
[34] 
[35] extern ngx_module_t  ngx_mail_pop3_module;
[36] 
[37] 
[38] #endif /* _NGX_MAIL_POP3_MODULE_H_INCLUDED_ */
