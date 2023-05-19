[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CHANNEL_H_INCLUDED_
[9] #define _NGX_CHANNEL_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] 
[16] 
[17] typedef struct {
[18]     ngx_uint_t  command;
[19]     ngx_pid_t   pid;
[20]     ngx_int_t   slot;
[21]     ngx_fd_t    fd;
[22] } ngx_channel_t;
[23] 
[24] 
[25] ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
[26]     ngx_log_t *log);
[27] ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
[28]     ngx_log_t *log);
[29] ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
[30]     ngx_int_t event, ngx_event_handler_pt handler);
[31] void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);
[32] 
[33] 
[34] #endif /* _NGX_CHANNEL_H_INCLUDED_ */
