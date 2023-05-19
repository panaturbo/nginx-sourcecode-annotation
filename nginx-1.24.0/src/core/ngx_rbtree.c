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
[12] /*
[13]  * The red-black tree code is based on the algorithm described in
[14]  * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
[15]  */
[16] 
[17] 
[18] static ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_node_t **root,
[19]     ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);
[20] static ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_node_t **root,
[21]     ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node);
[22] 
[23] 
[24] void
[25] ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
[26] {
[27]     ngx_rbtree_node_t  **root, *temp, *sentinel;
[28] 
[29]     /* a binary tree insert */
[30] 
[31]     root = &tree->root;
[32]     sentinel = tree->sentinel;
[33] 
[34]     if (*root == sentinel) {
[35]         node->parent = NULL;
[36]         node->left = sentinel;
[37]         node->right = sentinel;
[38]         ngx_rbt_black(node);
[39]         *root = node;
[40] 
[41]         return;
[42]     }
[43] 
[44]     tree->insert(*root, node, sentinel);
[45] 
[46]     /* re-balance tree */
[47] 
[48]     while (node != *root && ngx_rbt_is_red(node->parent)) {
[49] 
[50]         if (node->parent == node->parent->parent->left) {
[51]             temp = node->parent->parent->right;
[52] 
[53]             if (ngx_rbt_is_red(temp)) {
[54]                 ngx_rbt_black(node->parent);
[55]                 ngx_rbt_black(temp);
[56]                 ngx_rbt_red(node->parent->parent);
[57]                 node = node->parent->parent;
[58] 
[59]             } else {
[60]                 if (node == node->parent->right) {
[61]                     node = node->parent;
[62]                     ngx_rbtree_left_rotate(root, sentinel, node);
[63]                 }
[64] 
[65]                 ngx_rbt_black(node->parent);
[66]                 ngx_rbt_red(node->parent->parent);
[67]                 ngx_rbtree_right_rotate(root, sentinel, node->parent->parent);
[68]             }
[69] 
[70]         } else {
[71]             temp = node->parent->parent->left;
[72] 
[73]             if (ngx_rbt_is_red(temp)) {
[74]                 ngx_rbt_black(node->parent);
[75]                 ngx_rbt_black(temp);
[76]                 ngx_rbt_red(node->parent->parent);
[77]                 node = node->parent->parent;
[78] 
[79]             } else {
[80]                 if (node == node->parent->left) {
[81]                     node = node->parent;
[82]                     ngx_rbtree_right_rotate(root, sentinel, node);
[83]                 }
[84] 
[85]                 ngx_rbt_black(node->parent);
[86]                 ngx_rbt_red(node->parent->parent);
[87]                 ngx_rbtree_left_rotate(root, sentinel, node->parent->parent);
[88]             }
[89]         }
[90]     }
[91] 
[92]     ngx_rbt_black(*root);
[93] }
[94] 
[95] 
[96] void
[97] ngx_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
[98]     ngx_rbtree_node_t *sentinel)
[99] {
[100]     ngx_rbtree_node_t  **p;
[101] 
[102]     for ( ;; ) {
[103] 
[104]         p = (node->key < temp->key) ? &temp->left : &temp->right;
[105] 
[106]         if (*p == sentinel) {
[107]             break;
[108]         }
[109] 
[110]         temp = *p;
[111]     }
[112] 
[113]     *p = node;
[114]     node->parent = temp;
[115]     node->left = sentinel;
[116]     node->right = sentinel;
[117]     ngx_rbt_red(node);
[118] }
[119] 
[120] 
[121] void
[122] ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
[123]     ngx_rbtree_node_t *sentinel)
[124] {
[125]     ngx_rbtree_node_t  **p;
[126] 
[127]     for ( ;; ) {
[128] 
[129]         /*
[130]          * Timer values
[131]          * 1) are spread in small range, usually several minutes,
[132]          * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
[133]          * The comparison takes into account that overflow.
[134]          */
[135] 
[136]         /*  node->key < temp->key */
[137] 
[138]         p = ((ngx_rbtree_key_int_t) (node->key - temp->key) < 0)
[139]             ? &temp->left : &temp->right;
[140] 
[141]         if (*p == sentinel) {
[142]             break;
[143]         }
[144] 
[145]         temp = *p;
[146]     }
[147] 
[148]     *p = node;
[149]     node->parent = temp;
[150]     node->left = sentinel;
[151]     node->right = sentinel;
[152]     ngx_rbt_red(node);
[153] }
[154] 
[155] 
[156] void
[157] ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
[158] {
[159]     ngx_uint_t           red;
[160]     ngx_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;
[161] 
[162]     /* a binary tree delete */
[163] 
[164]     root = &tree->root;
[165]     sentinel = tree->sentinel;
[166] 
[167]     if (node->left == sentinel) {
[168]         temp = node->right;
[169]         subst = node;
[170] 
[171]     } else if (node->right == sentinel) {
[172]         temp = node->left;
[173]         subst = node;
[174] 
[175]     } else {
[176]         subst = ngx_rbtree_min(node->right, sentinel);
[177]         temp = subst->right;
[178]     }
[179] 
[180]     if (subst == *root) {
[181]         *root = temp;
[182]         ngx_rbt_black(temp);
[183] 
[184]         /* DEBUG stuff */
[185]         node->left = NULL;
[186]         node->right = NULL;
[187]         node->parent = NULL;
[188]         node->key = 0;
[189] 
[190]         return;
[191]     }
[192] 
[193]     red = ngx_rbt_is_red(subst);
[194] 
[195]     if (subst == subst->parent->left) {
[196]         subst->parent->left = temp;
[197] 
[198]     } else {
[199]         subst->parent->right = temp;
[200]     }
[201] 
[202]     if (subst == node) {
[203] 
[204]         temp->parent = subst->parent;
[205] 
[206]     } else {
[207] 
[208]         if (subst->parent == node) {
[209]             temp->parent = subst;
[210] 
[211]         } else {
[212]             temp->parent = subst->parent;
[213]         }
[214] 
[215]         subst->left = node->left;
[216]         subst->right = node->right;
[217]         subst->parent = node->parent;
[218]         ngx_rbt_copy_color(subst, node);
[219] 
[220]         if (node == *root) {
[221]             *root = subst;
[222] 
[223]         } else {
[224]             if (node == node->parent->left) {
[225]                 node->parent->left = subst;
[226]             } else {
[227]                 node->parent->right = subst;
[228]             }
[229]         }
[230] 
[231]         if (subst->left != sentinel) {
[232]             subst->left->parent = subst;
[233]         }
[234] 
[235]         if (subst->right != sentinel) {
[236]             subst->right->parent = subst;
[237]         }
[238]     }
[239] 
[240]     /* DEBUG stuff */
[241]     node->left = NULL;
[242]     node->right = NULL;
[243]     node->parent = NULL;
[244]     node->key = 0;
[245] 
[246]     if (red) {
[247]         return;
[248]     }
[249] 
[250]     /* a delete fixup */
[251] 
[252]     while (temp != *root && ngx_rbt_is_black(temp)) {
[253] 
[254]         if (temp == temp->parent->left) {
[255]             w = temp->parent->right;
[256] 
[257]             if (ngx_rbt_is_red(w)) {
[258]                 ngx_rbt_black(w);
[259]                 ngx_rbt_red(temp->parent);
[260]                 ngx_rbtree_left_rotate(root, sentinel, temp->parent);
[261]                 w = temp->parent->right;
[262]             }
[263] 
[264]             if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
[265]                 ngx_rbt_red(w);
[266]                 temp = temp->parent;
[267] 
[268]             } else {
[269]                 if (ngx_rbt_is_black(w->right)) {
[270]                     ngx_rbt_black(w->left);
[271]                     ngx_rbt_red(w);
[272]                     ngx_rbtree_right_rotate(root, sentinel, w);
[273]                     w = temp->parent->right;
[274]                 }
[275] 
[276]                 ngx_rbt_copy_color(w, temp->parent);
[277]                 ngx_rbt_black(temp->parent);
[278]                 ngx_rbt_black(w->right);
[279]                 ngx_rbtree_left_rotate(root, sentinel, temp->parent);
[280]                 temp = *root;
[281]             }
[282] 
[283]         } else {
[284]             w = temp->parent->left;
[285] 
[286]             if (ngx_rbt_is_red(w)) {
[287]                 ngx_rbt_black(w);
[288]                 ngx_rbt_red(temp->parent);
[289]                 ngx_rbtree_right_rotate(root, sentinel, temp->parent);
[290]                 w = temp->parent->left;
[291]             }
[292] 
[293]             if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
[294]                 ngx_rbt_red(w);
[295]                 temp = temp->parent;
[296] 
[297]             } else {
[298]                 if (ngx_rbt_is_black(w->left)) {
[299]                     ngx_rbt_black(w->right);
[300]                     ngx_rbt_red(w);
[301]                     ngx_rbtree_left_rotate(root, sentinel, w);
[302]                     w = temp->parent->left;
[303]                 }
[304] 
[305]                 ngx_rbt_copy_color(w, temp->parent);
[306]                 ngx_rbt_black(temp->parent);
[307]                 ngx_rbt_black(w->left);
[308]                 ngx_rbtree_right_rotate(root, sentinel, temp->parent);
[309]                 temp = *root;
[310]             }
[311]         }
[312]     }
[313] 
[314]     ngx_rbt_black(temp);
[315] }
[316] 
[317] 
[318] static ngx_inline void
[319] ngx_rbtree_left_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
[320]     ngx_rbtree_node_t *node)
[321] {
[322]     ngx_rbtree_node_t  *temp;
[323] 
[324]     temp = node->right;
[325]     node->right = temp->left;
[326] 
[327]     if (temp->left != sentinel) {
[328]         temp->left->parent = node;
[329]     }
[330] 
[331]     temp->parent = node->parent;
[332] 
[333]     if (node == *root) {
[334]         *root = temp;
[335] 
[336]     } else if (node == node->parent->left) {
[337]         node->parent->left = temp;
[338] 
[339]     } else {
[340]         node->parent->right = temp;
[341]     }
[342] 
[343]     temp->left = node;
[344]     node->parent = temp;
[345] }
[346] 
[347] 
[348] static ngx_inline void
[349] ngx_rbtree_right_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
[350]     ngx_rbtree_node_t *node)
[351] {
[352]     ngx_rbtree_node_t  *temp;
[353] 
[354]     temp = node->left;
[355]     node->left = temp->right;
[356] 
[357]     if (temp->right != sentinel) {
[358]         temp->right->parent = node;
[359]     }
[360] 
[361]     temp->parent = node->parent;
[362] 
[363]     if (node == *root) {
[364]         *root = temp;
[365] 
[366]     } else if (node == node->parent->right) {
[367]         node->parent->right = temp;
[368] 
[369]     } else {
[370]         node->parent->left = temp;
[371]     }
[372] 
[373]     temp->right = node;
[374]     node->parent = temp;
[375] }
[376] 
[377] 
[378] ngx_rbtree_node_t *
[379] ngx_rbtree_next(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
[380] {
[381]     ngx_rbtree_node_t  *root, *sentinel, *parent;
[382] 
[383]     sentinel = tree->sentinel;
[384] 
[385]     if (node->right != sentinel) {
[386]         return ngx_rbtree_min(node->right, sentinel);
[387]     }
[388] 
[389]     root = tree->root;
[390] 
[391]     for ( ;; ) {
[392]         parent = node->parent;
[393] 
[394]         if (node == root) {
[395]             return NULL;
[396]         }
[397] 
[398]         if (node == parent->left) {
[399]             return parent;
[400]         }
[401] 
[402]         node = parent;
[403]     }
[404] }
