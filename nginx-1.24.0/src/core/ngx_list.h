[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_LIST_H_INCLUDED_
[9] #define _NGX_LIST_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef struct ngx_list_part_s  ngx_list_part_t;
[17] 
[18] struct ngx_list_part_s {
[19]     void             *elts;
[20]     ngx_uint_t        nelts;
[21]     ngx_list_part_t  *next;
[22] };
[23] 
[24] 
[25] typedef struct {
[26]     ngx_list_part_t  *last;
[27]     ngx_list_part_t   part;
[28]     size_t            size;
[29]     ngx_uint_t        nalloc;
[30]     ngx_pool_t       *pool;
[31] } ngx_list_t;
[32] 
[33] 
[34] ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);
[35] 
[36] static ngx_inline ngx_int_t
[37] ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
[38] {
[39]     list->part.elts = ngx_palloc(pool, n * size);
[40]     if (list->part.elts == NULL) {
[41]         return NGX_ERROR;
[42]     }
[43] 
[44]     list->part.nelts = 0;
[45]     list->part.next = NULL;
[46]     list->last = &list->part;
[47]     list->size = size;
[48]     list->nalloc = n;
[49]     list->pool = pool;
[50] 
[51]     return NGX_OK;
[52] }
[53] 
[54] 
[55] /*
[56]  *
[57]  *  the iteration through the list:
[58]  *
[59]  *  part = &list.part;
[60]  *  data = part->elts;
[61]  *
[62]  *  for (i = 0 ;; i++) {
[63]  *
[64]  *      if (i >= part->nelts) {
[65]  *          if (part->next == NULL) {
[66]  *              break;
[67]  *          }
[68]  *
[69]  *          part = part->next;
[70]  *          data = part->elts;
[71]  *          i = 0;
[72]  *      }
[73]  *
[74]  *      ...  data[i] ...
[75]  *
[76]  *  }
[77]  */
[78] 
[79] 
[80] void *ngx_list_push(ngx_list_t *list);
[81] 
[82] 
[83] #endif /* _NGX_LIST_H_INCLUDED_ */
