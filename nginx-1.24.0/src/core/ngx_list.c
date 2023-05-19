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
[12] ngx_list_t *
[13] ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
[14] {
[15]     ngx_list_t  *list;
[16] 
[17]     list = ngx_palloc(pool, sizeof(ngx_list_t));
[18]     if (list == NULL) {
[19]         return NULL;
[20]     }
[21] 
[22]     if (ngx_list_init(list, pool, n, size) != NGX_OK) {
[23]         return NULL;
[24]     }
[25] 
[26]     return list;
[27] }
[28] 
[29] 
[30] void *
[31] ngx_list_push(ngx_list_t *l)
[32] {
[33]     void             *elt;
[34]     ngx_list_part_t  *last;
[35] 
[36]     last = l->last;
[37] 
[38]     if (last->nelts == l->nalloc) {
[39] 
[40]         /* the last part is full, allocate a new list part */
[41] 
[42]         last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
[43]         if (last == NULL) {
[44]             return NULL;
[45]         }
[46] 
[47]         last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
[48]         if (last->elts == NULL) {
[49]             return NULL;
[50]         }
[51] 
[52]         last->nelts = 0;
[53]         last->next = NULL;
[54] 
[55]         l->last->next = last;
[56]         l->last = last;
[57]     }
[58] 
[59]     elt = (char *) last->elts + l->size * last->nelts;
[60]     last->nelts++;
[61] 
[62]     return elt;
[63] }
