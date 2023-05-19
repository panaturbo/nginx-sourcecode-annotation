[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] void
[13] ngx_gettimeofday(struct timeval *tp)
[14] {
[15]     uint64_t  intervals;
[16]     FILETIME  ft;
[17] 
[18]     GetSystemTimeAsFileTime(&ft);
[19] 
[20]     /*
[21]      * A file time is a 64-bit value that represents the number
[22]      * of 100-nanosecond intervals that have elapsed since
[23]      * January 1, 1601 12:00 A.M. UTC.
[24]      *
[25]      * Between January 1, 1970 (Epoch) and January 1, 1601 there were
[26]      * 134774 days,
[27]      * 11644473600 seconds or
[28]      * 11644473600,000,000,0 100-nanosecond intervals.
[29]      *
[30]      * See also MSKB Q167296.
[31]      */
[32] 
[33]     intervals = ((uint64_t) ft.dwHighDateTime << 32) | ft.dwLowDateTime;
[34]     intervals -= 116444736000000000;
[35] 
[36]     tp->tv_sec = (long) (intervals / 10000000);
[37]     tp->tv_usec = (long) ((intervals % 10000000) / 10);
[38] }
[39] 
[40] 
[41] void
[42] ngx_libc_localtime(time_t s, struct tm *tm)
[43] {
[44]     struct tm  *t;
[45] 
[46]     t = localtime(&s);
[47]     *tm = *t;
[48] }
[49] 
[50] 
[51] void
[52] ngx_libc_gmtime(time_t s, struct tm *tm)
[53] {
[54]     struct tm  *t;
[55] 
[56]     t = gmtime(&s);
[57]     *tm = *t;
[58] }
[59] 
[60] 
[61] ngx_int_t
[62] ngx_gettimezone(void)
[63] {
[64]     u_long                 n;
[65]     TIME_ZONE_INFORMATION  tz;
[66] 
[67]     n = GetTimeZoneInformation(&tz);
[68] 
[69]     switch (n) {
[70] 
[71]     case TIME_ZONE_ID_UNKNOWN:
[72]         return -tz.Bias;
[73] 
[74]     case TIME_ZONE_ID_STANDARD:
[75]         return -(tz.Bias + tz.StandardBias);
[76] 
[77]     case TIME_ZONE_ID_DAYLIGHT:
[78]         return -(tz.Bias + tz.DaylightBias);
[79] 
[80]     default: /* TIME_ZONE_ID_INVALID */
[81]         return 0;
[82]     }
[83] }
