[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_RADIX_TREE_H_INCLUDED_
[9] #define _NGX_RADIX_TREE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_RADIX_NO_VALUE   (uintptr_t) -1
[17] 
[18] typedef struct ngx_radix_node_s  ngx_radix_node_t;
[19] 
[20] struct ngx_radix_node_s {
[21]     ngx_radix_node_t  *right;
[22]     ngx_radix_node_t  *left;
[23]     ngx_radix_node_t  *parent;
[24]     uintptr_t          value;
[25] };
[26] 
[27] 
[28] typedef struct {
[29]     ngx_radix_node_t  *root;
[30]     ngx_pool_t        *pool;
[31]     ngx_radix_node_t  *free;
[32]     char              *start;
[33]     size_t             size;
[34] } ngx_radix_tree_t;
[35] 
[36] 
[37] ngx_radix_tree_t *ngx_radix_tree_create(ngx_pool_t *pool,
[38]     ngx_int_t preallocate);
[39] 
[40] ngx_int_t ngx_radix32tree_insert(ngx_radix_tree_t *tree,
[41]     uint32_t key, uint32_t mask, uintptr_t value);
[42] ngx_int_t ngx_radix32tree_delete(ngx_radix_tree_t *tree,
[43]     uint32_t key, uint32_t mask);
[44] uintptr_t ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key);
[45] 
[46] #if (NGX_HAVE_INET6)
[47] ngx_int_t ngx_radix128tree_insert(ngx_radix_tree_t *tree,
[48]     u_char *key, u_char *mask, uintptr_t value);
[49] ngx_int_t ngx_radix128tree_delete(ngx_radix_tree_t *tree,
[50]     u_char *key, u_char *mask);
[51] uintptr_t ngx_radix128tree_find(ngx_radix_tree_t *tree, u_char *key);
[52] #endif
[53] 
[54] 
[55] #endif /* _NGX_RADIX_TREE_H_INCLUDED_ */
