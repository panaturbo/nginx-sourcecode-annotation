[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_ARRAY_H_INCLUDED_
[9] #define _NGX_ARRAY_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct {
[17]     void        *elts;
[18]     ngx_uint_t   nelts;
[19]     size_t       size;
[20]     ngx_uint_t   nalloc;
[21]     ngx_pool_t  *pool;
[22] } ngx_array_t;
[23] 
[24] 
[25] ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
[26] void ngx_array_destroy(ngx_array_t *a);
[27] void *ngx_array_push(ngx_array_t *a);
[28] void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);
[29] 
[30] 
[31] static ngx_inline ngx_int_t
[32] ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
[33] {
[34]     /*
[35]      * set "array->nelts" before "array->elts", otherwise MSVC thinks
[36]      * that "array->nelts" may be used without having been initialized
[37]      */
[38] 
[39]     array->nelts = 0;
[40]     array->size = size;
[41]     array->nalloc = n;
[42]     array->pool = pool;
[43] 
[44]     array->elts = ngx_palloc(pool, n * size);
[45]     if (array->elts == NULL) {
[46]         return NGX_ERROR;
[47]     }
[48] 
[49]     return NGX_OK;
[50] }
[51] 
[52] 
[53] #endif /* _NGX_ARRAY_H_INCLUDED_ */
