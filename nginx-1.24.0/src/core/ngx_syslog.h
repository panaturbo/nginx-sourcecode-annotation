[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #ifndef _NGX_SYSLOG_H_INCLUDED_
[8] #define _NGX_SYSLOG_H_INCLUDED_
[9] 
[10] 
[11] typedef struct {
[12]     ngx_uint_t         facility;
[13]     ngx_uint_t         severity;
[14]     ngx_str_t          tag;
[15] 
[16]     ngx_str_t         *hostname;
[17] 
[18]     ngx_addr_t         server;
[19]     ngx_connection_t   conn;
[20] 
[21]     ngx_log_t          log;
[22]     ngx_log_t         *logp;
[23] 
[24]     unsigned           busy:1;
[25]     unsigned           nohostname:1;
[26] } ngx_syslog_peer_t;
[27] 
[28] 
[29] char *ngx_syslog_process_conf(ngx_conf_t *cf, ngx_syslog_peer_t *peer);
[30] u_char *ngx_syslog_add_header(ngx_syslog_peer_t *peer, u_char *buf);
[31] void ngx_syslog_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
[32]     size_t len);
[33] ssize_t ngx_syslog_send(ngx_syslog_peer_t *peer, u_char *buf, size_t len);
[34] 
[35] 
[36] #endif /* _NGX_SYSLOG_H_INCLUDED_ */
