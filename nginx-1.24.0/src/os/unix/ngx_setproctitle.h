[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SETPROCTITLE_H_INCLUDED_
[9] #define _NGX_SETPROCTITLE_H_INCLUDED_
[10] 
[11] 
[12] #if (NGX_HAVE_SETPROCTITLE)
[13] 
[14] /* FreeBSD, NetBSD, OpenBSD */
[15] 
[16] #define ngx_init_setproctitle(log) NGX_OK
[17] #define ngx_setproctitle(title)    setproctitle("%s", title)
[18] 
[19] 
[20] #else /* !NGX_HAVE_SETPROCTITLE */
[21] 
[22] #if !defined NGX_SETPROCTITLE_USES_ENV
[23] 
[24] #if (NGX_SOLARIS)
[25] 
[26] #define NGX_SETPROCTITLE_USES_ENV  1
[27] #define NGX_SETPROCTITLE_PAD       ' '
[28] 
[29] ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
[30] void ngx_setproctitle(char *title);
[31] 
[32] #elif (NGX_LINUX) || (NGX_DARWIN)
[33] 
[34] #define NGX_SETPROCTITLE_USES_ENV  1
[35] #define NGX_SETPROCTITLE_PAD       '\0'
[36] 
[37] ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
[38] void ngx_setproctitle(char *title);
[39] 
[40] #else
[41] 
[42] #define ngx_init_setproctitle(log) NGX_OK
[43] #define ngx_setproctitle(title)
[44] 
[45] #endif /* OSes */
[46] 
[47] #endif /* NGX_SETPROCTITLE_USES_ENV */
[48] 
[49] #endif /* NGX_HAVE_SETPROCTITLE */
[50] 
[51] 
[52] #endif /* _NGX_SETPROCTITLE_H_INCLUDED_ */
