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
[12] static ngx_str_t   ngx_unknown_error = ngx_string("Unknown error");
[13] 
[14] 
[15] #if (NGX_HAVE_STRERRORDESC_NP)
[16] 
[17] /*
[18]  * The strerrordesc_np() function, introduced in glibc 2.32, is
[19]  * async-signal-safe.  This makes it possible to use it directly,
[20]  * without copying error messages.
[21]  */
[22] 
[23] 
[24] u_char *
[25] ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
[26] {
[27]     size_t       len;
[28]     const char  *msg;
[29] 
[30]     msg = strerrordesc_np(err);
[31] 
[32]     if (msg == NULL) {
[33]         msg = (char *) ngx_unknown_error.data;
[34]         len = ngx_unknown_error.len;
[35] 
[36]     } else {
[37]         len = ngx_strlen(msg);
[38]     }
[39] 
[40]     size = ngx_min(size, len);
[41] 
[42]     return ngx_cpymem(errstr, msg, size);
[43] }
[44] 
[45] 
[46] ngx_int_t
[47] ngx_strerror_init(void)
[48] {
[49]     return NGX_OK;
[50] }
[51] 
[52] 
[53] #else
[54] 
[55] /*
[56]  * The strerror() messages are copied because:
[57]  *
[58]  * 1) strerror() and strerror_r() functions are not Async-Signal-Safe,
[59]  *    therefore, they cannot be used in signal handlers;
[60]  *
[61]  * 2) a direct sys_errlist[] array may be used instead of these functions,
[62]  *    but Linux linker warns about its usage:
[63]  *
[64]  * warning: `sys_errlist' is deprecated; use `strerror' or `strerror_r' instead
[65]  * warning: `sys_nerr' is deprecated; use `strerror' or `strerror_r' instead
[66]  *
[67]  *    causing false bug reports.
[68]  */
[69] 
[70] 
[71] static ngx_str_t  *ngx_sys_errlist;
[72] static ngx_err_t   ngx_first_error;
[73] static ngx_err_t   ngx_last_error;
[74] 
[75] 
[76] u_char *
[77] ngx_strerror(ngx_err_t err, u_char *errstr, size_t size)
[78] {
[79]     ngx_str_t  *msg;
[80] 
[81]     if (err >= ngx_first_error && err < ngx_last_error) {
[82]         msg = &ngx_sys_errlist[err - ngx_first_error];
[83] 
[84]     } else {
[85]         msg = &ngx_unknown_error;
[86]     }
[87] 
[88]     size = ngx_min(size, msg->len);
[89] 
[90]     return ngx_cpymem(errstr, msg->data, size);
[91] }
[92] 
[93] 
[94] ngx_int_t
[95] ngx_strerror_init(void)
[96] {
[97]     char       *msg;
[98]     u_char     *p;
[99]     size_t      len;
[100]     ngx_err_t   err;
[101] 
[102] #if (NGX_SYS_NERR)
[103]     ngx_first_error = 0;
[104]     ngx_last_error = NGX_SYS_NERR;
[105] 
[106] #elif (EPERM > 1000 && EPERM < 0x7fffffff - 1000)
[107] 
[108]     /*
[109]      * If number of errors is not known, and EPERM error code has large
[110]      * but reasonable value, guess possible error codes based on the error
[111]      * messages returned by strerror(), starting from EPERM.  Notably,
[112]      * this covers GNU/Hurd, where errors start at 0x40000001.
[113]      */
[114] 
[115]     for (err = EPERM; err > EPERM - 1000; err--) {
[116]         ngx_set_errno(0);
[117]         msg = strerror(err);
[118] 
[119]         if (errno == EINVAL
[120]             || msg == NULL
[121]             || strncmp(msg, "Unknown error", 13) == 0)
[122]         {
[123]             continue;
[124]         }
[125] 
[126]         ngx_first_error = err;
[127]     }
[128] 
[129]     for (err = EPERM; err < EPERM + 1000; err++) {
[130]         ngx_set_errno(0);
[131]         msg = strerror(err);
[132] 
[133]         if (errno == EINVAL
[134]             || msg == NULL
[135]             || strncmp(msg, "Unknown error", 13) == 0)
[136]         {
[137]             continue;
[138]         }
[139] 
[140]         ngx_last_error = err + 1;
[141]     }
[142] 
[143] #else
[144] 
[145]     /*
[146]      * If number of errors is not known, guess it based on the error
[147]      * messages returned by strerror().
[148]      */
[149] 
[150]     ngx_first_error = 0;
[151] 
[152]     for (err = 0; err < 1000; err++) {
[153]         ngx_set_errno(0);
[154]         msg = strerror(err);
[155] 
[156]         if (errno == EINVAL
[157]             || msg == NULL
[158]             || strncmp(msg, "Unknown error", 13) == 0)
[159]         {
[160]             continue;
[161]         }
[162] 
[163]         ngx_last_error = err + 1;
[164]     }
[165] 
[166] #endif
[167] 
[168]     /*
[169]      * ngx_strerror() is not ready to work at this stage, therefore,
[170]      * malloc() is used and possible errors are logged using strerror().
[171]      */
[172] 
[173]     len = (ngx_last_error - ngx_first_error) * sizeof(ngx_str_t);
[174] 
[175]     ngx_sys_errlist = malloc(len);
[176]     if (ngx_sys_errlist == NULL) {
[177]         goto failed;
[178]     }
[179] 
[180]     for (err = ngx_first_error; err < ngx_last_error; err++) {
[181]         msg = strerror(err);
[182] 
[183]         if (msg == NULL) {
[184]             ngx_sys_errlist[err - ngx_first_error] = ngx_unknown_error;
[185]             continue;
[186]         }
[187] 
[188]         len = ngx_strlen(msg);
[189] 
[190]         p = malloc(len);
[191]         if (p == NULL) {
[192]             goto failed;
[193]         }
[194] 
[195]         ngx_memcpy(p, msg, len);
[196]         ngx_sys_errlist[err - ngx_first_error].len = len;
[197]         ngx_sys_errlist[err - ngx_first_error].data = p;
[198]     }
[199] 
[200]     return NGX_OK;
[201] 
[202] failed:
[203] 
[204]     err = errno;
[205]     ngx_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));
[206] 
[207]     return NGX_ERROR;
[208] }
[209] 
[210] #endif
