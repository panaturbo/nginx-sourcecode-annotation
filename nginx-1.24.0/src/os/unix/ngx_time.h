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
[19] typedef struct tm             ngx_tm_t;
[20] 
[21] #define ngx_tm_sec            tm_sec
[22] #define ngx_tm_min            tm_min
[23] #define ngx_tm_hour           tm_hour
[24] #define ngx_tm_mday           tm_mday
[25] #define ngx_tm_mon            tm_mon
[26] #define ngx_tm_year           tm_year
[27] #define ngx_tm_wday           tm_wday
[28] #define ngx_tm_isdst          tm_isdst
[29] 
[30] #define ngx_tm_sec_t          int
[31] #define ngx_tm_min_t          int
[32] #define ngx_tm_hour_t         int
[33] #define ngx_tm_mday_t         int
[34] #define ngx_tm_mon_t          int
[35] #define ngx_tm_year_t         int
[36] #define ngx_tm_wday_t         int
[37] 
[38] 
[39] #if (NGX_HAVE_GMTOFF)
[40] #define ngx_tm_gmtoff         tm_gmtoff
[41] #define ngx_tm_zone           tm_zone
[42] #endif
[43] 
[44] 
[45] #if (NGX_SOLARIS)
[46] 
[47] #define ngx_timezone(isdst) (- (isdst ? altzone : timezone) / 60)
[48] 
[49] #else
[50] 
[51] #define ngx_timezone(isdst) (- (isdst ? timezone + 3600 : timezone) / 60)
[52] 
[53] #endif
[54] 
[55] 
[56] void ngx_timezone_update(void);
[57] void ngx_localtime(time_t s, ngx_tm_t *tm);
[58] void ngx_libc_localtime(time_t s, struct tm *tm);
[59] void ngx_libc_gmtime(time_t s, struct tm *tm);
[60] 
[61] #define ngx_gettimeofday(tp)  (void) gettimeofday(tp, NULL);
[62] #define ngx_msleep(ms)        (void) usleep(ms * 1000)
[63] #define ngx_sleep(s)          (void) sleep(s)
[64] 
[65] 
[66] #endif /* _NGX_TIME_H_INCLUDED_ */
