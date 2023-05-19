[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_RBTREE_H_INCLUDED_
[9] #define _NGX_RBTREE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef ngx_uint_t  ngx_rbtree_key_t;
[17] typedef ngx_int_t   ngx_rbtree_key_int_t;
[18] 
[19] 
[20] typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;
[21] 
[22] struct ngx_rbtree_node_s {
[23]     ngx_rbtree_key_t       key;
[24]     ngx_rbtree_node_t     *left;
[25]     ngx_rbtree_node_t     *right;
[26]     ngx_rbtree_node_t     *parent;
[27]     u_char                 color;
[28]     u_char                 data;
[29] };
[30] 
[31] 
[32] typedef struct ngx_rbtree_s  ngx_rbtree_t;
[33] 
[34] typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
[35]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[36] 
[37] struct ngx_rbtree_s {
[38]     ngx_rbtree_node_t     *root;
[39]     ngx_rbtree_node_t     *sentinel;
[40]     ngx_rbtree_insert_pt   insert;
[41] };
[42] 
[43] 
[44] #define ngx_rbtree_init(tree, s, i)                                           \
[45]     ngx_rbtree_sentinel_init(s);                                              \
[46]     (tree)->root = s;                                                         \
[47]     (tree)->sentinel = s;                                                     \
[48]     (tree)->insert = i
[49] 
[50] #define ngx_rbtree_data(node, type, link)                                     \
[51]     (type *) ((u_char *) (node) - offsetof(type, link))
[52] 
[53] 
[54] void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
[55] void ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
[56] void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
[57]     ngx_rbtree_node_t *sentinel);
[58] void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
[59]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[60] ngx_rbtree_node_t *ngx_rbtree_next(ngx_rbtree_t *tree,
[61]     ngx_rbtree_node_t *node);
[62] 
[63] 
[64] #define ngx_rbt_red(node)               ((node)->color = 1)
[65] #define ngx_rbt_black(node)             ((node)->color = 0)
[66] #define ngx_rbt_is_red(node)            ((node)->color)
[67] #define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))
[68] #define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)
[69] 
[70] 
[71] /* a sentinel must be black */
[72] 
[73] #define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)
[74] 
[75] 
[76] static ngx_inline ngx_rbtree_node_t *
[77] ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
[78] {
[79]     while (node->left != sentinel) {
[80]         node = node->left;
[81]     }
[82] 
[83]     return node;
[84] }
[85] 
[86] 
[87] #endif /* _NGX_RBTREE_H_INCLUDED_ */
