[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] char *
[13] ngx_dlerror(void)
[14] {
[15]     u_char         *p;
[16]     static u_char   errstr[NGX_MAX_ERROR_STR];
[17] 
[18]     p = ngx_strerror(ngx_errno, errstr, NGX_MAX_ERROR_STR);
[19]     *p = '\0';
[20] 
[21]     return (char *) errstr;
[22] }
