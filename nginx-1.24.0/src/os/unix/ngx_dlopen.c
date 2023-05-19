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
[12] #if (NGX_HAVE_DLOPEN)
[13] 
[14] char *
[15] ngx_dlerror(void)
[16] {
[17]     char  *err;
[18] 
[19]     err = (char *) dlerror();
[20] 
[21]     if (err == NULL) {
[22]         return "";
[23]     }
[24] 
[25]     return err;
[26] }
[27] 
[28] #endif
