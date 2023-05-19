[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_PARSE_TIME_H_INCLUDED_
[9] #define _NGX_PARSE_TIME_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] time_t ngx_parse_http_time(u_char *value, size_t len);
[17] 
[18] /* compatibility */
[19] #define ngx_http_parse_time(value, len)  ngx_parse_http_time(value, len)
[20] 
[21] 
[22] #endif /* _NGX_PARSE_TIME_H_INCLUDED_ */
