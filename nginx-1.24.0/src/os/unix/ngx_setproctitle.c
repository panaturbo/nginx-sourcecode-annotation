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
[12] #if (NGX_SETPROCTITLE_USES_ENV)
[13] 
[14] /*
[15]  * To change the process title in Linux and Solaris we have to set argv[1]
[16]  * to NULL and to copy the title to the same place where the argv[0] points to.
[17]  * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
[18]  * and Solaris store argv[] and environ[] one after another.  So we should
[19]  * ensure that is the continuous memory and then we allocate the new memory
[20]  * for environ[] and copy it.  After this we could use the memory starting
[21]  * from argv[0] for our process title.
[22]  *
[23]  * The Solaris's standard /bin/ps does not show the changed process title.
[24]  * You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
[25]  * show a new title if its length less than the origin command line length.
[26]  * To avoid it we append to a new title the origin command line in the
[27]  * parenthesis.
[28]  */
[29] 
[30] extern char **environ;
[31] 
[32] static char *ngx_os_argv_last;
[33] 
[34] ngx_int_t
[35] ngx_init_setproctitle(ngx_log_t *log)
[36] {
[37]     u_char      *p;
[38]     size_t       size;
[39]     ngx_uint_t   i;
[40] 
[41]     size = 0;
[42] 
[43]     for (i = 0; environ[i]; i++) {
[44]         size += ngx_strlen(environ[i]) + 1;
[45]     }
[46] 
[47]     p = ngx_alloc(size, log);
[48]     if (p == NULL) {
[49]         return NGX_ERROR;
[50]     }
[51] 
[52]     ngx_os_argv_last = ngx_os_argv[0];
[53] 
[54]     for (i = 0; ngx_os_argv[i]; i++) {
[55]         if (ngx_os_argv_last == ngx_os_argv[i]) {
[56]             ngx_os_argv_last = ngx_os_argv[i] + ngx_strlen(ngx_os_argv[i]) + 1;
[57]         }
[58]     }
[59] 
[60]     for (i = 0; environ[i]; i++) {
[61]         if (ngx_os_argv_last == environ[i]) {
[62] 
[63]             size = ngx_strlen(environ[i]) + 1;
[64]             ngx_os_argv_last = environ[i] + size;
[65] 
[66]             ngx_cpystrn(p, (u_char *) environ[i], size);
[67]             environ[i] = (char *) p;
[68]             p += size;
[69]         }
[70]     }
[71] 
[72]     ngx_os_argv_last--;
[73] 
[74]     return NGX_OK;
[75] }
[76] 
[77] 
[78] void
[79] ngx_setproctitle(char *title)
[80] {
[81]     u_char     *p;
[82] 
[83] #if (NGX_SOLARIS)
[84] 
[85]     ngx_int_t   i;
[86]     size_t      size;
[87] 
[88] #endif
[89] 
[90]     ngx_os_argv[1] = NULL;
[91] 
[92]     p = ngx_cpystrn((u_char *) ngx_os_argv[0], (u_char *) "nginx: ",
[93]                     ngx_os_argv_last - ngx_os_argv[0]);
[94] 
[95]     p = ngx_cpystrn(p, (u_char *) title, ngx_os_argv_last - (char *) p);
[96] 
[97] #if (NGX_SOLARIS)
[98] 
[99]     size = 0;
[100] 
[101]     for (i = 0; i < ngx_argc; i++) {
[102]         size += ngx_strlen(ngx_argv[i]) + 1;
[103]     }
[104] 
[105]     if (size > (size_t) ((char *) p - ngx_os_argv[0])) {
[106] 
[107]         /*
[108]          * ngx_setproctitle() is too rare operation so we use
[109]          * the non-optimized copies
[110]          */
[111] 
[112]         p = ngx_cpystrn(p, (u_char *) " (", ngx_os_argv_last - (char *) p);
[113] 
[114]         for (i = 0; i < ngx_argc; i++) {
[115]             p = ngx_cpystrn(p, (u_char *) ngx_argv[i],
[116]                             ngx_os_argv_last - (char *) p);
[117]             p = ngx_cpystrn(p, (u_char *) " ", ngx_os_argv_last - (char *) p);
[118]         }
[119] 
[120]         if (*(p - 1) == ' ') {
[121]             *(p - 1) = ')';
[122]         }
[123]     }
[124] 
[125] #endif
[126] 
[127]     if (ngx_os_argv_last - (char *) p) {
[128]         ngx_memset(p, NGX_SETPROCTITLE_PAD, ngx_os_argv_last - (char *) p);
[129]     }
[130] 
[131]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[132]                    "setproctitle: \"%s\"", ngx_os_argv[0]);
[133] }
[134] 
[135] #endif /* NGX_SETPROCTITLE_USES_ENV */
