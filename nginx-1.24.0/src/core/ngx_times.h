[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_TIMES_H_INCLUDED_
[9] #define _NGX_TIMES_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     time_t      sec;
[18]     ngx_uint_t  msec;
[19]     ngx_int_t   gmtoff;
[20] } ngx_time_t;
[21] 
[22] 
[23] void ngx_time_init(void);
[24] void ngx_time_update(void);
[25] void ngx_time_sigsafe_update(void);
[26] u_char *ngx_http_time(u_char *buf, time_t t);
[27] u_char *ngx_http_cookie_time(u_char *buf, time_t t);
[28] void ngx_gmtime(time_t t, ngx_tm_t *tp);
[29] 
[30] time_t ngx_next_time(time_t when);
[31] #define ngx_next_time_n      "mktime()"
[32] 
[33] 
[34] extern volatile ngx_time_t  *ngx_cached_time;
[35] 
[36] #define ngx_time()           ngx_cached_time->sec
[37] #define ngx_timeofday()      (ngx_time_t *) ngx_cached_time
[38] 
[39] extern volatile ngx_str_t    ngx_cached_err_log_time;
[40] extern volatile ngx_str_t    ngx_cached_http_time;
[41] extern volatile ngx_str_t    ngx_cached_http_log_time;
[42] extern volatile ngx_str_t    ngx_cached_http_log_iso8601;
[43] extern volatile ngx_str_t    ngx_cached_syslog_time;
[44] 
[45] /*
[46]  * milliseconds elapsed since some unspecified point in the past
[47]  * and truncated to ngx_msec_t, used in event timers
[48]  */
[49] extern volatile ngx_msec_t  ngx_current_msec;
[50] 
[51] 
[52] #endif /* _NGX_TIMES_H_INCLUDED_ */
