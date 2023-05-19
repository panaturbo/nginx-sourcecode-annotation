[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGINX_H_INCLUDED_
[9] #define _NGINX_H_INCLUDED_
[10] 
[11] 
[12] #define nginx_version      1024000
[13] #define NGINX_VERSION      "1.24.0"
[14] #define NGINX_VER          "nginx/" NGINX_VERSION
[15] 
[16] #ifdef NGX_BUILD
[17] #define NGINX_VER_BUILD    NGINX_VER " (" NGX_BUILD ")"
[18] #else
[19] #define NGINX_VER_BUILD    NGINX_VER
[20] #endif
[21] 
[22] #define NGINX_VAR          "NGINX"
[23] #define NGX_OLDPID_EXT     ".oldbin"
[24] 
[25] 
[26] #endif /* _NGINX_H_INCLUDED_ */
