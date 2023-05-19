[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_MAIL_SMTP_MODULE_H_INCLUDED_
[9] #define _NGX_MAIL_SMTP_MODULE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_mail.h>
[15] #include <ngx_mail_smtp_module.h>
[16] 
[17] 
[18] typedef struct {
[19]     ngx_msec_t   greeting_delay;
[20] 
[21]     size_t       client_buffer_size;
[22] 
[23]     ngx_str_t    capability;
[24]     ngx_str_t    starttls_capability;
[25]     ngx_str_t    starttls_only_capability;
[26] 
[27]     ngx_str_t    server_name;
[28]     ngx_str_t    greeting;
[29] 
[30]     ngx_uint_t   auth_methods;
[31] 
[32]     ngx_array_t  capabilities;
[33] } ngx_mail_smtp_srv_conf_t;
[34] 
[35] 
[36] void ngx_mail_smtp_init_session(ngx_mail_session_t *s, ngx_connection_t *c);
[37] void ngx_mail_smtp_init_protocol(ngx_event_t *rev);
[38] void ngx_mail_smtp_auth_state(ngx_event_t *rev);
[39] ngx_int_t ngx_mail_smtp_parse_command(ngx_mail_session_t *s);
[40] 
[41] 
[42] extern ngx_module_t  ngx_mail_smtp_module;
[43] 
[44] 
[45] #endif /* _NGX_MAIL_SMTP_MODULE_H_INCLUDED_ */
