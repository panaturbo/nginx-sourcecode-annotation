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
[12] static ngx_msec_t ngx_monotonic_time(time_t sec, ngx_uint_t msec);
[13] 
[14] 
[15] /*
[16]  * The time may be updated by signal handler or by several threads.
[17]  * The time update operations are rare and require to hold the ngx_time_lock.
[18]  * The time read operations are frequent, so they are lock-free and get time
[19]  * values and strings from the current slot.  Thus thread may get the corrupted
[20]  * values only if it is preempted while copying and then it is not scheduled
[21]  * to run more than NGX_TIME_SLOTS seconds.
[22]  */
[23] 
[24] #define NGX_TIME_SLOTS   64
[25] 
[26] static ngx_uint_t        slot;
[27] static ngx_atomic_t      ngx_time_lock;
[28] 
[29] volatile ngx_msec_t      ngx_current_msec;
[30] volatile ngx_time_t     *ngx_cached_time;
[31] volatile ngx_str_t       ngx_cached_err_log_time;
[32] volatile ngx_str_t       ngx_cached_http_time;
[33] volatile ngx_str_t       ngx_cached_http_log_time;
[34] volatile ngx_str_t       ngx_cached_http_log_iso8601;
[35] volatile ngx_str_t       ngx_cached_syslog_time;
[36] 
[37] #if !(NGX_WIN32)
[38] 
[39] /*
[40]  * localtime() and localtime_r() are not Async-Signal-Safe functions, therefore,
[41]  * they must not be called by a signal handler, so we use the cached
[42]  * GMT offset value. Fortunately the value is changed only two times a year.
[43]  */
[44] 
[45] static ngx_int_t         cached_gmtoff;
[46] #endif
[47] 
[48] static ngx_time_t        cached_time[NGX_TIME_SLOTS];
[49] static u_char            cached_err_log_time[NGX_TIME_SLOTS]
[50]                                     [sizeof("1970/09/28 12:00:00")];
[51] static u_char            cached_http_time[NGX_TIME_SLOTS]
[52]                                     [sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
[53] static u_char            cached_http_log_time[NGX_TIME_SLOTS]
[54]                                     [sizeof("28/Sep/1970:12:00:00 +0600")];
[55] static u_char            cached_http_log_iso8601[NGX_TIME_SLOTS]
[56]                                     [sizeof("1970-09-28T12:00:00+06:00")];
[57] static u_char            cached_syslog_time[NGX_TIME_SLOTS]
[58]                                     [sizeof("Sep 28 12:00:00")];
[59] 
[60] 
[61] static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
[62] static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
[63]                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
[64] 
[65] void
[66] ngx_time_init(void)
[67] {
[68]     ngx_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1;
[69]     ngx_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
[70]     ngx_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;
[71]     ngx_cached_http_log_iso8601.len = sizeof("1970-09-28T12:00:00+06:00") - 1;
[72]     ngx_cached_syslog_time.len = sizeof("Sep 28 12:00:00") - 1;
[73] 
[74]     ngx_cached_time = &cached_time[0];
[75] 
[76]     ngx_time_update();
[77] }
[78] 
[79] 
[80] void
[81] ngx_time_update(void)
[82] {
[83]     u_char          *p0, *p1, *p2, *p3, *p4;
[84]     ngx_tm_t         tm, gmt;
[85]     time_t           sec;
[86]     ngx_uint_t       msec;
[87]     ngx_time_t      *tp;
[88]     struct timeval   tv;
[89] 
[90]     if (!ngx_trylock(&ngx_time_lock)) {
[91]         return;
[92]     }
[93] 
[94]     ngx_gettimeofday(&tv);
[95] 
[96]     sec = tv.tv_sec;
[97]     msec = tv.tv_usec / 1000;
[98] 
[99]     ngx_current_msec = ngx_monotonic_time(sec, msec);
[100] 
[101]     tp = &cached_time[slot];
[102] 
[103]     if (tp->sec == sec) {
[104]         tp->msec = msec;
[105]         ngx_unlock(&ngx_time_lock);
[106]         return;
[107]     }
[108] 
[109]     if (slot == NGX_TIME_SLOTS - 1) {
[110]         slot = 0;
[111]     } else {
[112]         slot++;
[113]     }
[114] 
[115]     tp = &cached_time[slot];
[116] 
[117]     tp->sec = sec;
[118]     tp->msec = msec;
[119] 
[120]     ngx_gmtime(sec, &gmt);
[121] 
[122] 
[123]     p0 = &cached_http_time[slot][0];
[124] 
[125]     (void) ngx_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
[126]                        week[gmt.ngx_tm_wday], gmt.ngx_tm_mday,
[127]                        months[gmt.ngx_tm_mon - 1], gmt.ngx_tm_year,
[128]                        gmt.ngx_tm_hour, gmt.ngx_tm_min, gmt.ngx_tm_sec);
[129] 
[130] #if (NGX_HAVE_GETTIMEZONE)
[131] 
[132]     tp->gmtoff = ngx_gettimezone();
[133]     ngx_gmtime(sec + tp->gmtoff * 60, &tm);
[134] 
[135] #elif (NGX_HAVE_GMTOFF)
[136] 
[137]     ngx_localtime(sec, &tm);
[138]     cached_gmtoff = (ngx_int_t) (tm.ngx_tm_gmtoff / 60);
[139]     tp->gmtoff = cached_gmtoff;
[140] 
[141] #else
[142] 
[143]     ngx_localtime(sec, &tm);
[144]     cached_gmtoff = ngx_timezone(tm.ngx_tm_isdst);
[145]     tp->gmtoff = cached_gmtoff;
[146] 
[147] #endif
[148] 
[149] 
[150]     p1 = &cached_err_log_time[slot][0];
[151] 
[152]     (void) ngx_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d",
[153]                        tm.ngx_tm_year, tm.ngx_tm_mon,
[154]                        tm.ngx_tm_mday, tm.ngx_tm_hour,
[155]                        tm.ngx_tm_min, tm.ngx_tm_sec);
[156] 
[157] 
[158]     p2 = &cached_http_log_time[slot][0];
[159] 
[160]     (void) ngx_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02i%02i",
[161]                        tm.ngx_tm_mday, months[tm.ngx_tm_mon - 1],
[162]                        tm.ngx_tm_year, tm.ngx_tm_hour,
[163]                        tm.ngx_tm_min, tm.ngx_tm_sec,
[164]                        tp->gmtoff < 0 ? '-' : '+',
[165]                        ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));
[166] 
[167]     p3 = &cached_http_log_iso8601[slot][0];
[168] 
[169]     (void) ngx_sprintf(p3, "%4d-%02d-%02dT%02d:%02d:%02d%c%02i:%02i",
[170]                        tm.ngx_tm_year, tm.ngx_tm_mon,
[171]                        tm.ngx_tm_mday, tm.ngx_tm_hour,
[172]                        tm.ngx_tm_min, tm.ngx_tm_sec,
[173]                        tp->gmtoff < 0 ? '-' : '+',
[174]                        ngx_abs(tp->gmtoff / 60), ngx_abs(tp->gmtoff % 60));
[175] 
[176]     p4 = &cached_syslog_time[slot][0];
[177] 
[178]     (void) ngx_sprintf(p4, "%s %2d %02d:%02d:%02d",
[179]                        months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
[180]                        tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);
[181] 
[182]     ngx_memory_barrier();
[183] 
[184]     ngx_cached_time = tp;
[185]     ngx_cached_http_time.data = p0;
[186]     ngx_cached_err_log_time.data = p1;
[187]     ngx_cached_http_log_time.data = p2;
[188]     ngx_cached_http_log_iso8601.data = p3;
[189]     ngx_cached_syslog_time.data = p4;
[190] 
[191]     ngx_unlock(&ngx_time_lock);
[192] }
[193] 
[194] 
[195] static ngx_msec_t
[196] ngx_monotonic_time(time_t sec, ngx_uint_t msec)
[197] {
[198] #if (NGX_HAVE_CLOCK_MONOTONIC)
[199]     struct timespec  ts;
[200] 
[201] #if defined(CLOCK_MONOTONIC_FAST)
[202]     clock_gettime(CLOCK_MONOTONIC_FAST, &ts);
[203] #else
[204]     clock_gettime(CLOCK_MONOTONIC, &ts);
[205] #endif
[206] 
[207]     sec = ts.tv_sec;
[208]     msec = ts.tv_nsec / 1000000;
[209] 
[210] #endif
[211] 
[212]     return (ngx_msec_t) sec * 1000 + msec;
[213] }
[214] 
[215] 
[216] #if !(NGX_WIN32)
[217] 
[218] void
[219] ngx_time_sigsafe_update(void)
[220] {
[221]     u_char          *p, *p2;
[222]     ngx_tm_t         tm;
[223]     time_t           sec;
[224]     ngx_time_t      *tp;
[225]     struct timeval   tv;
[226] 
[227]     if (!ngx_trylock(&ngx_time_lock)) {
[228]         return;
[229]     }
[230] 
[231]     ngx_gettimeofday(&tv);
[232] 
[233]     sec = tv.tv_sec;
[234] 
[235]     tp = &cached_time[slot];
[236] 
[237]     if (tp->sec == sec) {
[238]         ngx_unlock(&ngx_time_lock);
[239]         return;
[240]     }
[241] 
[242]     if (slot == NGX_TIME_SLOTS - 1) {
[243]         slot = 0;
[244]     } else {
[245]         slot++;
[246]     }
[247] 
[248]     tp = &cached_time[slot];
[249] 
[250]     tp->sec = 0;
[251] 
[252]     ngx_gmtime(sec + cached_gmtoff * 60, &tm);
[253] 
[254]     p = &cached_err_log_time[slot][0];
[255] 
[256]     (void) ngx_sprintf(p, "%4d/%02d/%02d %02d:%02d:%02d",
[257]                        tm.ngx_tm_year, tm.ngx_tm_mon,
[258]                        tm.ngx_tm_mday, tm.ngx_tm_hour,
[259]                        tm.ngx_tm_min, tm.ngx_tm_sec);
[260] 
[261]     p2 = &cached_syslog_time[slot][0];
[262] 
[263]     (void) ngx_sprintf(p2, "%s %2d %02d:%02d:%02d",
[264]                        months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
[265]                        tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec);
[266] 
[267]     ngx_memory_barrier();
[268] 
[269]     ngx_cached_err_log_time.data = p;
[270]     ngx_cached_syslog_time.data = p2;
[271] 
[272]     ngx_unlock(&ngx_time_lock);
[273] }
[274] 
[275] #endif
[276] 
[277] 
[278] u_char *
[279] ngx_http_time(u_char *buf, time_t t)
[280] {
[281]     ngx_tm_t  tm;
[282] 
[283]     ngx_gmtime(t, &tm);
[284] 
[285]     return ngx_sprintf(buf, "%s, %02d %s %4d %02d:%02d:%02d GMT",
[286]                        week[tm.ngx_tm_wday],
[287]                        tm.ngx_tm_mday,
[288]                        months[tm.ngx_tm_mon - 1],
[289]                        tm.ngx_tm_year,
[290]                        tm.ngx_tm_hour,
[291]                        tm.ngx_tm_min,
[292]                        tm.ngx_tm_sec);
[293] }
[294] 
[295] 
[296] u_char *
[297] ngx_http_cookie_time(u_char *buf, time_t t)
[298] {
[299]     ngx_tm_t  tm;
[300] 
[301]     ngx_gmtime(t, &tm);
[302] 
[303]     /*
[304]      * Netscape 3.x does not understand 4-digit years at all and
[305]      * 2-digit years more than "37"
[306]      */
[307] 
[308]     return ngx_sprintf(buf,
[309]                        (tm.ngx_tm_year > 2037) ?
[310]                                          "%s, %02d-%s-%d %02d:%02d:%02d GMT":
[311]                                          "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
[312]                        week[tm.ngx_tm_wday],
[313]                        tm.ngx_tm_mday,
[314]                        months[tm.ngx_tm_mon - 1],
[315]                        (tm.ngx_tm_year > 2037) ? tm.ngx_tm_year:
[316]                                                  tm.ngx_tm_year % 100,
[317]                        tm.ngx_tm_hour,
[318]                        tm.ngx_tm_min,
[319]                        tm.ngx_tm_sec);
[320] }
[321] 
[322] 
[323] void
[324] ngx_gmtime(time_t t, ngx_tm_t *tp)
[325] {
[326]     ngx_int_t   yday;
[327]     ngx_uint_t  sec, min, hour, mday, mon, year, wday, days, leap;
[328] 
[329]     /* the calculation is valid for positive time_t only */
[330] 
[331]     if (t < 0) {
[332]         t = 0;
[333]     }
[334] 
[335]     days = t / 86400;
[336]     sec = t % 86400;
[337] 
[338]     /*
[339]      * no more than 4 year digits supported,
[340]      * truncate to December 31, 9999, 23:59:59
[341]      */
[342] 
[343]     if (days > 2932896) {
[344]         days = 2932896;
[345]         sec = 86399;
[346]     }
[347] 
[348]     /* January 1, 1970 was Thursday */
[349] 
[350]     wday = (4 + days) % 7;
[351] 
[352]     hour = sec / 3600;
[353]     sec %= 3600;
[354]     min = sec / 60;
[355]     sec %= 60;
[356] 
[357]     /*
[358]      * the algorithm based on Gauss' formula,
[359]      * see src/core/ngx_parse_time.c
[360]      */
[361] 
[362]     /* days since March 1, 1 BC */
[363]     days = days - (31 + 28) + 719527;
[364] 
[365]     /*
[366]      * The "days" should be adjusted to 1 only, however, some March 1st's go
[367]      * to previous year, so we adjust them to 2.  This causes also shift of the
[368]      * last February days to next year, but we catch the case when "yday"
[369]      * becomes negative.
[370]      */
[371] 
[372]     year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);
[373] 
[374]     yday = days - (365 * year + year / 4 - year / 100 + year / 400);
[375] 
[376]     if (yday < 0) {
[377]         leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
[378]         yday = 365 + leap + yday;
[379]         year--;
[380]     }
[381] 
[382]     /*
[383]      * The empirical formula that maps "yday" to month.
[384]      * There are at least 10 variants, some of them are:
[385]      *     mon = (yday + 31) * 15 / 459
[386]      *     mon = (yday + 31) * 17 / 520
[387]      *     mon = (yday + 31) * 20 / 612
[388]      */
[389] 
[390]     mon = (yday + 31) * 10 / 306;
[391] 
[392]     /* the Gauss' formula that evaluates days before the month */
[393] 
[394]     mday = yday - (367 * mon / 12 - 30) + 1;
[395] 
[396]     if (yday >= 306) {
[397] 
[398]         year++;
[399]         mon -= 10;
[400] 
[401]         /*
[402]          * there is no "yday" in Win32 SYSTEMTIME
[403]          *
[404]          * yday -= 306;
[405]          */
[406] 
[407]     } else {
[408] 
[409]         mon += 2;
[410] 
[411]         /*
[412]          * there is no "yday" in Win32 SYSTEMTIME
[413]          *
[414]          * yday += 31 + 28 + leap;
[415]          */
[416]     }
[417] 
[418]     tp->ngx_tm_sec = (ngx_tm_sec_t) sec;
[419]     tp->ngx_tm_min = (ngx_tm_min_t) min;
[420]     tp->ngx_tm_hour = (ngx_tm_hour_t) hour;
[421]     tp->ngx_tm_mday = (ngx_tm_mday_t) mday;
[422]     tp->ngx_tm_mon = (ngx_tm_mon_t) mon;
[423]     tp->ngx_tm_year = (ngx_tm_year_t) year;
[424]     tp->ngx_tm_wday = (ngx_tm_wday_t) wday;
[425] }
[426] 
[427] 
[428] time_t
[429] ngx_next_time(time_t when)
[430] {
[431]     time_t     now, next;
[432]     struct tm  tm;
[433] 
[434]     now = ngx_time();
[435] 
[436]     ngx_libc_localtime(now, &tm);
[437] 
[438]     tm.tm_hour = (int) (when / 3600);
[439]     when %= 3600;
[440]     tm.tm_min = (int) (when / 60);
[441]     tm.tm_sec = (int) (when % 60);
[442] 
[443]     next = mktime(&tm);
[444] 
[445]     if (next == -1) {
[446]         return -1;
[447]     }
[448] 
[449]     if (next - now > 0) {
[450]         return next;
[451]     }
[452] 
[453]     tm.tm_mday++;
[454] 
[455]     /* mktime() should normalize a date (Jan 32, etc) */
[456] 
[457]     next = mktime(&tm);
[458] 
[459]     if (next != -1) {
[460]         return next;
[461]     }
[462] 
[463]     return -1;
[464] }
