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
[12] int ngx_file_type(char *file, ngx_file_info_t *sb)
[13] {
[14]     sb->dwFileAttributes = GetFileAttributes(file);
[15] 
[16]     if (sb->dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
[17]         return -1;
[18]     }
[19] 
[20]     return 0;
[21] }
[22] 
[23] /*
[24] int ngx_stat(char *file, ngx_stat_t *sb)
[25] {
[26]     *sb = GetFileAttributes(file);
[27] 
[28]     if (*sb == INVALID_FILE_ATTRIBUTES) {
[29]         return -1;
[30]     }
[31] 
[32]     return 0;
[33] }
[34] */
