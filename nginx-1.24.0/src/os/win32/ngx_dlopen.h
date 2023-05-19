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
[16] #define NGX_HAVE_DLOPEN  1
[17] 
[18] 
[19] #define ngx_dlopen(path)           LoadLibrary((char *) path)
[20] #define ngx_dlopen_n               "LoadLibrary()"
[21] 
[22] #define ngx_dlsym(handle, symbol)  (void *) GetProcAddress(handle, symbol)
[23] #define ngx_dlsym_n                "GetProcAddress()"
[24] 
[25] #define ngx_dlclose(handle)        (FreeLibrary(handle) ? 0 : -1)
[26] #define ngx_dlclose_n              "FreeLibrary()"
[27] 
[28] 
[29] char *ngx_dlerror(void);
[30] 
[31] 
[32] #endif /* _NGX_DLOPEN_H_INCLUDED_ */
