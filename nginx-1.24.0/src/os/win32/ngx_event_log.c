[1] /*
[2]  * Copyright (C) Igor Sysoev
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] 
[10] 
[11] #define NGX_MAX_ERROR_STR   2048
[12] 
[13] 
[14] void ngx_cdecl
[15] ngx_event_log(ngx_err_t err, const char *fmt, ...)
[16] {
[17]     u_char         *p, *last;
[18]     long            types;
[19]     HKEY            key;
[20]     HANDLE          ev;
[21]     va_list         args;
[22]     u_char          text[NGX_MAX_ERROR_STR];
[23]     const char     *msgarg[9];
[24]     static u_char   netmsg[] = "%SystemRoot%\\System32\\netmsg.dll";
[25] 
[26]     last = text + NGX_MAX_ERROR_STR;
[27]     p = text + GetModuleFileName(NULL, (char *) text, NGX_MAX_ERROR_STR - 50);
[28] 
[29]     *p++ = ':';
[30]     ngx_linefeed(p);
[31] 
[32]     va_start(args, fmt);
[33]     p = ngx_vslprintf(p, last, fmt, args);
[34]     va_end(args);
[35] 
[36]     if (err) {
[37]         p = ngx_log_errno(p, last, err);
[38]     }
[39] 
[40]     if (p > last - NGX_LINEFEED_SIZE - 1) {
[41]         p = last - NGX_LINEFEED_SIZE - 1;
[42]     }
[43] 
[44]     ngx_linefeed(p);
[45] 
[46]     *p = '\0';
[47] 
[48]     /*
[49]      * we do not log errors here since we use
[50]      * Event Log only to log our own logs open errors
[51]      */
[52] 
[53]     if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
[54]            "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\nginx",
[55]            0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL)
[56]         != 0)
[57]     {
[58]         return;
[59]     }
[60] 
[61]     if (RegSetValueEx(key, "EventMessageFile", 0, REG_EXPAND_SZ,
[62]                       netmsg, sizeof(netmsg) - 1)
[63]         != 0)
[64]     {
[65]         return;
[66]     }
[67] 
[68]     types = EVENTLOG_ERROR_TYPE;
[69] 
[70]     if (RegSetValueEx(key, "TypesSupported", 0, REG_DWORD,
[71]                       (u_char *) &types, sizeof(long))
[72]         != 0)
[73]     {
[74]         return;
[75]     }
[76] 
[77]     RegCloseKey(key);
[78] 
[79]     ev = RegisterEventSource(NULL, "nginx");
[80] 
[81]     msgarg[0] = (char *) text;
[82]     msgarg[1] = NULL;
[83]     msgarg[2] = NULL;
[84]     msgarg[3] = NULL;
[85]     msgarg[4] = NULL;
[86]     msgarg[5] = NULL;
[87]     msgarg[6] = NULL;
[88]     msgarg[7] = NULL;
[89]     msgarg[8] = NULL;
[90] 
[91]     /*
[92]      * the 3299 event id in netmsg.dll has the generic message format:
[93]      *     "%1 %2 %3 %4 %5 %6 %7 %8 %9"
[94]      */
[95] 
[96]     ReportEvent(ev, EVENTLOG_ERROR_TYPE, 0, 3299, NULL, 9, 0, msgarg, NULL);
[97] 
[98]     DeregisterEventSource(ev);
[99] }
