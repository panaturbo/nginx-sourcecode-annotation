[1] 
[2] /*
[3]  * Copyright (C) Maxim Dounin
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_DLOPEN_H_INCLUDED_
[9] #define _NGX_DLOPEN_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define ngx_dlopen(path)           dlopen((char *) path, RTLD_NOW | RTLD_GLOBAL)
[17] #define ngx_dlopen_n               "dlopen()"
[18] 
[19] #define ngx_dlsym(handle, symbol)  dlsym(handle, symbol)
[20] #define ngx_dlsym_n                "dlsym()"
[21] 
[22] #define ngx_dlclose(handle)        dlclose(handle)
[23] #define ngx_dlclose_n              "dlclose()"
[24] 
[25] 
[26] #if (NGX_HAVE_DLOPEN)
[27] char *ngx_dlerror(void);
[28] #endif
[29] 
[30] 
[31] #endif /* _NGX_DLOPEN_H_INCLUDED_ */
