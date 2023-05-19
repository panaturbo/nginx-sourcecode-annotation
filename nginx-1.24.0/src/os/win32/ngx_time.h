[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_TIME_H_INCLUDED_
[9] #define _NGX_TIME_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef ngx_rbtree_key_t      ngx_msec_t;
[17] typedef ngx_rbtree_key_int_t  ngx_msec_int_t;
[18] 
[19] typedef SYSTEMTIME            ngx_tm_t;
[20] typedef FILETIME              ngx_mtime_t;
[21] 
[22] #define ngx_tm_sec            wSecond
[23] #define ngx_tm_min            wMinute
[24] #define ngx_tm_hour           wHour
[25] #define ngx_tm_mday           wDay
[26] #define ngx_tm_mon            wMonth
[27] #define ngx_tm_year           wYear
[28] #define ngx_tm_wday           wDayOfWeek
[29] 
[30] #define ngx_tm_sec_t          u_short
[31] #define ngx_tm_min_t          u_short
[32] #define ngx_tm_hour_t         u_short
[33] #define ngx_tm_mday_t         u_short
[34] #define ngx_tm_mon_t          u_short
[35] #define ngx_tm_year_t         u_short
[36] #define ngx_tm_wday_t         u_short
[37] 
[38] 
[39] #define ngx_msleep            Sleep
[40] 
[41] #define NGX_HAVE_GETTIMEZONE  1
[42] 
[43] #define  ngx_timezone_update()
[44] 
[45] ngx_int_t ngx_gettimezone(void);
[46] void ngx_libc_localtime(time_t s, struct tm *tm);
[47] void ngx_libc_gmtime(time_t s, struct tm *tm);
[48] void ngx_gettimeofday(struct timeval *tp);
[49] 
[50] 
[51] #endif /* _NGX_TIME_H_INCLUDED_ */
