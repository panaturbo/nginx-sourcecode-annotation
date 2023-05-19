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
[12] /*
[13]  * FreeBSD does not test /etc/localtime change, however, we can workaround it
[14]  * by calling tzset() with TZ and then without TZ to update timezone.
[15]  * The trick should work since FreeBSD 2.1.0.
[16]  *
[17]  * Linux does not test /etc/localtime change in localtime(),
[18]  * but may stat("/etc/localtime") several times in every strftime(),
[19]  * therefore we use it to update timezone.
[20]  *
[21]  * Solaris does not test /etc/TIMEZONE change too and no workaround available.
[22]  */
[23] 
[24] void
[25] ngx_timezone_update(void)
[26] {
[27] #if (NGX_FREEBSD)
[28] 
[29]     if (getenv("TZ")) {
[30]         return;
[31]     }
[32] 
[33]     putenv("TZ=UTC");
[34] 
[35]     tzset();
[36] 
[37]     unsetenv("TZ");
[38] 
[39]     tzset();
[40] 
[41] #elif (NGX_LINUX)
[42]     time_t      s;
[43]     struct tm  *t;
[44]     char        buf[4];
[45] 
[46]     s = time(0);
[47] 
[48]     t = localtime(&s);
[49] 
[50]     strftime(buf, 4, "%H", t);
[51] 
[52] #endif
[53] }
[54] 
[55] 
[56] void
[57] ngx_localtime(time_t s, ngx_tm_t *tm)
[58] {
[59] #if (NGX_HAVE_LOCALTIME_R)
[60]     (void) localtime_r(&s, tm);
[61] 
[62] #else
[63]     ngx_tm_t  *t;
[64] 
[65]     t = localtime(&s);
[66]     *tm = *t;
[67] 
[68] #endif
[69] 
[70]     tm->ngx_tm_mon++;
[71]     tm->ngx_tm_year += 1900;
[72] }
[73] 
[74] 
[75] void
[76] ngx_libc_localtime(time_t s, struct tm *tm)
[77] {
[78] #if (NGX_HAVE_LOCALTIME_R)
[79]     (void) localtime_r(&s, tm);
[80] 
[81] #else
[82]     struct tm  *t;
[83] 
[84]     t = localtime(&s);
[85]     *tm = *t;
[86] 
[87] #endif
[88] }
[89] 
[90] 
[91] void
[92] ngx_libc_gmtime(time_t s, struct tm *tm)
[93] {
[94] #if (NGX_HAVE_LOCALTIME_R)
[95]     (void) gmtime_r(&s, tm);
[96] 
[97] #else
[98]     struct tm  *t;
[99] 
[100]     t = gmtime(&s);
[101]     *tm = *t;
[102] 
[103] #endif
[104] }
