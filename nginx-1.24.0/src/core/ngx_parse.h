[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_PARSE_H_INCLUDED_
[9] #define _NGX_PARSE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] ssize_t ngx_parse_size(ngx_str_t *line);
[17] off_t ngx_parse_offset(ngx_str_t *line);
[18] ngx_int_t ngx_parse_time(ngx_str_t *line, ngx_uint_t is_sec);
[19] 
[20] 
[21] #endif /* _NGX_PARSE_H_INCLUDED_ */
