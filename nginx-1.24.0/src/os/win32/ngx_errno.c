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
[12] u_char *
[13] ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
[14] {
[15]     u_int          len;
[16]     static u_long  lang = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
[17] 
[18]     if (size == 0) {
[19]         return errstr;
[20]     }
[21] 
[22]     len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
[23]                         NULL, err, lang, (char *) errstr, size, NULL);
[24] 
[25]     if (len == 0 && lang) {
[26] 
[27]         /*
[28]          * Try to use English messages first and fallback to a language,
[29]          * based on locale: non-English Windows have no English messages
[30]          * at all.  This way allows to use English messages at least on
[31]          * Windows with MUI.
[32]          */
[33] 
[34]         lang = 0;
[35] 
[36]         len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
[37]                             NULL, err, lang, (char *) errstr, size, NULL);
[38]     }
[39] 
[40]     if (len == 0) {
[41]         return ngx_snprintf(errstr, size,
[42]                             "FormatMessage() error:(%d)", GetLastError());
[43]     }
[44] 
[45]     /* remove ".\r\n\0" */
[46]     while (errstr[len] == '\0' || errstr[len] == CR
[47]            || errstr[len] == LF || errstr[len] == '.')
[48]     {
[49]         --len;
[50]     }
[51] 
[52]     return &errstr[++len];
[53] }
[54] 
[55] 
[56] ngx_int_t
[57] ngx_strerror_init(void)
[58] {
[59]     return NGX_OK;
[60] }
