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
[12] #if (NGX_CRYPT)
[13] 
[14] #if (NGX_HAVE_GNU_CRYPT_R)
[15] 
[16] ngx_int_t
[17] ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[18] {
[19]     char               *value;
[20]     size_t              len;
[21]     struct crypt_data   cd;
[22] 
[23]     cd.initialized = 0;
[24] 
[25]     value = crypt_r((char *) key, (char *) salt, &cd);
[26] 
[27]     if (value) {
[28]         len = ngx_strlen(value) + 1;
[29] 
[30]         *encrypted = ngx_pnalloc(pool, len);
[31]         if (*encrypted == NULL) {
[32]             return NGX_ERROR;
[33]         }
[34] 
[35]         ngx_memcpy(*encrypted, value, len);
[36]         return NGX_OK;
[37]     }
[38] 
[39]     ngx_log_error(NGX_LOG_CRIT, pool->log, ngx_errno, "crypt_r() failed");
[40] 
[41]     return NGX_ERROR;
[42] }
[43] 
[44] #else
[45] 
[46] ngx_int_t
[47] ngx_libc_crypt(ngx_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
[48] {
[49]     char       *value;
[50]     size_t      len;
[51]     ngx_err_t   err;
[52] 
[53]     value = crypt((char *) key, (char *) salt);
[54] 
[55]     if (value) {
[56]         len = ngx_strlen(value) + 1;
[57] 
[58]         *encrypted = ngx_pnalloc(pool, len);
[59]         if (*encrypted == NULL) {
[60]             return NGX_ERROR;
[61]         }
[62] 
[63]         ngx_memcpy(*encrypted, value, len);
[64]         return NGX_OK;
[65]     }
[66] 
[67]     err = ngx_errno;
[68] 
[69]     ngx_log_error(NGX_LOG_CRIT, pool->log, err, "crypt() failed");
[70] 
[71]     return NGX_ERROR;
[72] }
[73] 
[74] #endif
[75] 
[76] #endif /* NGX_CRYPT */
