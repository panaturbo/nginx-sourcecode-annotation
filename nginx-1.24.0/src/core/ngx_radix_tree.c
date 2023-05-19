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
[12] static ngx_radix_node_t *ngx_radix_alloc(ngx_radix_tree_t *tree);
[13] 
[14] 
[15] ngx_radix_tree_t *
[16] ngx_radix_tree_create(ngx_pool_t *pool, ngx_int_t preallocate)
[17] {
[18]     uint32_t           key, mask, inc;
[19]     ngx_radix_tree_t  *tree;
[20] 
[21]     tree = ngx_palloc(pool, sizeof(ngx_radix_tree_t));
[22]     if (tree == NULL) {
[23]         return NULL;
[24]     }
[25] 
[26]     tree->pool = pool;
[27]     tree->free = NULL;
[28]     tree->start = NULL;
[29]     tree->size = 0;
[30] 
[31]     tree->root = ngx_radix_alloc(tree);
[32]     if (tree->root == NULL) {
[33]         return NULL;
[34]     }
[35] 
[36]     tree->root->right = NULL;
[37]     tree->root->left = NULL;
[38]     tree->root->parent = NULL;
[39]     tree->root->value = NGX_RADIX_NO_VALUE;
[40] 
[41]     if (preallocate == 0) {
[42]         return tree;
[43]     }
[44] 
[45]     /*
[46]      * Preallocation of first nodes : 0, 1, 00, 01, 10, 11, 000, 001, etc.
[47]      * increases TLB hits even if for first lookup iterations.
[48]      * On 32-bit platforms the 7 preallocated bits takes continuous 4K,
[49]      * 8 - 8K, 9 - 16K, etc.  On 64-bit platforms the 6 preallocated bits
[50]      * takes continuous 4K, 7 - 8K, 8 - 16K, etc.  There is no sense to
[51]      * to preallocate more than one page, because further preallocation
[52]      * distributes the only bit per page.  Instead, a random insertion
[53]      * may distribute several bits per page.
[54]      *
[55]      * Thus, by default we preallocate maximum
[56]      *     6 bits on amd64 (64-bit platform and 4K pages)
[57]      *     7 bits on i386 (32-bit platform and 4K pages)
[58]      *     7 bits on sparc64 in 64-bit mode (8K pages)
[59]      *     8 bits on sparc64 in 32-bit mode (8K pages)
[60]      */
[61] 
[62]     if (preallocate == -1) {
[63]         switch (ngx_pagesize / sizeof(ngx_radix_node_t)) {
[64] 
[65]         /* amd64 */
[66]         case 128:
[67]             preallocate = 6;
[68]             break;
[69] 
[70]         /* i386, sparc64 */
[71]         case 256:
[72]             preallocate = 7;
[73]             break;
[74] 
[75]         /* sparc64 in 32-bit mode */
[76]         default:
[77]             preallocate = 8;
[78]         }
[79]     }
[80] 
[81]     mask = 0;
[82]     inc = 0x80000000;
[83] 
[84]     while (preallocate--) {
[85] 
[86]         key = 0;
[87]         mask >>= 1;
[88]         mask |= 0x80000000;
[89] 
[90]         do {
[91]             if (ngx_radix32tree_insert(tree, key, mask, NGX_RADIX_NO_VALUE)
[92]                 != NGX_OK)
[93]             {
[94]                 return NULL;
[95]             }
[96] 
[97]             key += inc;
[98] 
[99]         } while (key);
[100] 
[101]         inc >>= 1;
[102]     }
[103] 
[104]     return tree;
[105] }
[106] 
[107] 
[108] ngx_int_t
[109] ngx_radix32tree_insert(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask,
[110]     uintptr_t value)
[111] {
[112]     uint32_t           bit;
[113]     ngx_radix_node_t  *node, *next;
[114] 
[115]     bit = 0x80000000;
[116] 
[117]     node = tree->root;
[118]     next = tree->root;
[119] 
[120]     while (bit & mask) {
[121]         if (key & bit) {
[122]             next = node->right;
[123] 
[124]         } else {
[125]             next = node->left;
[126]         }
[127] 
[128]         if (next == NULL) {
[129]             break;
[130]         }
[131] 
[132]         bit >>= 1;
[133]         node = next;
[134]     }
[135] 
[136]     if (next) {
[137]         if (node->value != NGX_RADIX_NO_VALUE) {
[138]             return NGX_BUSY;
[139]         }
[140] 
[141]         node->value = value;
[142]         return NGX_OK;
[143]     }
[144] 
[145]     while (bit & mask) {
[146]         next = ngx_radix_alloc(tree);
[147]         if (next == NULL) {
[148]             return NGX_ERROR;
[149]         }
[150] 
[151]         next->right = NULL;
[152]         next->left = NULL;
[153]         next->parent = node;
[154]         next->value = NGX_RADIX_NO_VALUE;
[155] 
[156]         if (key & bit) {
[157]             node->right = next;
[158] 
[159]         } else {
[160]             node->left = next;
[161]         }
[162] 
[163]         bit >>= 1;
[164]         node = next;
[165]     }
[166] 
[167]     node->value = value;
[168] 
[169]     return NGX_OK;
[170] }
[171] 
[172] 
[173] ngx_int_t
[174] ngx_radix32tree_delete(ngx_radix_tree_t *tree, uint32_t key, uint32_t mask)
[175] {
[176]     uint32_t           bit;
[177]     ngx_radix_node_t  *node;
[178] 
[179]     bit = 0x80000000;
[180]     node = tree->root;
[181] 
[182]     while (node && (bit & mask)) {
[183]         if (key & bit) {
[184]             node = node->right;
[185] 
[186]         } else {
[187]             node = node->left;
[188]         }
[189] 
[190]         bit >>= 1;
[191]     }
[192] 
[193]     if (node == NULL) {
[194]         return NGX_ERROR;
[195]     }
[196] 
[197]     if (node->right || node->left) {
[198]         if (node->value != NGX_RADIX_NO_VALUE) {
[199]             node->value = NGX_RADIX_NO_VALUE;
[200]             return NGX_OK;
[201]         }
[202] 
[203]         return NGX_ERROR;
[204]     }
[205] 
[206]     for ( ;; ) {
[207]         if (node->parent->right == node) {
[208]             node->parent->right = NULL;
[209] 
[210]         } else {
[211]             node->parent->left = NULL;
[212]         }
[213] 
[214]         node->right = tree->free;
[215]         tree->free = node;
[216] 
[217]         node = node->parent;
[218] 
[219]         if (node->right || node->left) {
[220]             break;
[221]         }
[222] 
[223]         if (node->value != NGX_RADIX_NO_VALUE) {
[224]             break;
[225]         }
[226] 
[227]         if (node->parent == NULL) {
[228]             break;
[229]         }
[230]     }
[231] 
[232]     return NGX_OK;
[233] }
[234] 
[235] 
[236] uintptr_t
[237] ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key)
[238] {
[239]     uint32_t           bit;
[240]     uintptr_t          value;
[241]     ngx_radix_node_t  *node;
[242] 
[243]     bit = 0x80000000;
[244]     value = NGX_RADIX_NO_VALUE;
[245]     node = tree->root;
[246] 
[247]     while (node) {
[248]         if (node->value != NGX_RADIX_NO_VALUE) {
[249]             value = node->value;
[250]         }
[251] 
[252]         if (key & bit) {
[253]             node = node->right;
[254] 
[255]         } else {
[256]             node = node->left;
[257]         }
[258] 
[259]         bit >>= 1;
[260]     }
[261] 
[262]     return value;
[263] }
[264] 
[265] 
[266] #if (NGX_HAVE_INET6)
[267] 
[268] ngx_int_t
[269] ngx_radix128tree_insert(ngx_radix_tree_t *tree, u_char *key, u_char *mask,
[270]     uintptr_t value)
[271] {
[272]     u_char             bit;
[273]     ngx_uint_t         i;
[274]     ngx_radix_node_t  *node, *next;
[275] 
[276]     i = 0;
[277]     bit = 0x80;
[278] 
[279]     node = tree->root;
[280]     next = tree->root;
[281] 
[282]     while (bit & mask[i]) {
[283]         if (key[i] & bit) {
[284]             next = node->right;
[285] 
[286]         } else {
[287]             next = node->left;
[288]         }
[289] 
[290]         if (next == NULL) {
[291]             break;
[292]         }
[293] 
[294]         bit >>= 1;
[295]         node = next;
[296] 
[297]         if (bit == 0) {
[298]             if (++i == 16) {
[299]                 break;
[300]             }
[301] 
[302]             bit = 0x80;
[303]         }
[304]     }
[305] 
[306]     if (next) {
[307]         if (node->value != NGX_RADIX_NO_VALUE) {
[308]             return NGX_BUSY;
[309]         }
[310] 
[311]         node->value = value;
[312]         return NGX_OK;
[313]     }
[314] 
[315]     while (bit & mask[i]) {
[316]         next = ngx_radix_alloc(tree);
[317]         if (next == NULL) {
[318]             return NGX_ERROR;
[319]         }
[320] 
[321]         next->right = NULL;
[322]         next->left = NULL;
[323]         next->parent = node;
[324]         next->value = NGX_RADIX_NO_VALUE;
[325] 
[326]         if (key[i] & bit) {
[327]             node->right = next;
[328] 
[329]         } else {
[330]             node->left = next;
[331]         }
[332] 
[333]         bit >>= 1;
[334]         node = next;
[335] 
[336]         if (bit == 0) {
[337]             if (++i == 16) {
[338]                 break;
[339]             }
[340] 
[341]             bit = 0x80;
[342]         }
[343]     }
[344] 
[345]     node->value = value;
[346] 
[347]     return NGX_OK;
[348] }
[349] 
[350] 
[351] ngx_int_t
[352] ngx_radix128tree_delete(ngx_radix_tree_t *tree, u_char *key, u_char *mask)
[353] {
[354]     u_char             bit;
[355]     ngx_uint_t         i;
[356]     ngx_radix_node_t  *node;
[357] 
[358]     i = 0;
[359]     bit = 0x80;
[360]     node = tree->root;
[361] 
[362]     while (node && (bit & mask[i])) {
[363]         if (key[i] & bit) {
[364]             node = node->right;
[365] 
[366]         } else {
[367]             node = node->left;
[368]         }
[369] 
[370]         bit >>= 1;
[371] 
[372]         if (bit == 0) {
[373]             if (++i == 16) {
[374]                 break;
[375]             }
[376] 
[377]             bit = 0x80;
[378]         }
[379]     }
[380] 
[381]     if (node == NULL) {
[382]         return NGX_ERROR;
[383]     }
[384] 
[385]     if (node->right || node->left) {
[386]         if (node->value != NGX_RADIX_NO_VALUE) {
[387]             node->value = NGX_RADIX_NO_VALUE;
[388]             return NGX_OK;
[389]         }
[390] 
[391]         return NGX_ERROR;
[392]     }
[393] 
[394]     for ( ;; ) {
[395]         if (node->parent->right == node) {
[396]             node->parent->right = NULL;
[397] 
[398]         } else {
[399]             node->parent->left = NULL;
[400]         }
[401] 
[402]         node->right = tree->free;
[403]         tree->free = node;
[404] 
[405]         node = node->parent;
[406] 
[407]         if (node->right || node->left) {
[408]             break;
[409]         }
[410] 
[411]         if (node->value != NGX_RADIX_NO_VALUE) {
[412]             break;
[413]         }
[414] 
[415]         if (node->parent == NULL) {
[416]             break;
[417]         }
[418]     }
[419] 
[420]     return NGX_OK;
[421] }
[422] 
[423] 
[424] uintptr_t
[425] ngx_radix128tree_find(ngx_radix_tree_t *tree, u_char *key)
[426] {
[427]     u_char             bit;
[428]     uintptr_t          value;
[429]     ngx_uint_t         i;
[430]     ngx_radix_node_t  *node;
[431] 
[432]     i = 0;
[433]     bit = 0x80;
[434]     value = NGX_RADIX_NO_VALUE;
[435]     node = tree->root;
[436] 
[437]     while (node) {
[438]         if (node->value != NGX_RADIX_NO_VALUE) {
[439]             value = node->value;
[440]         }
[441] 
[442]         if (key[i] & bit) {
[443]             node = node->right;
[444] 
[445]         } else {
[446]             node = node->left;
[447]         }
[448] 
[449]         bit >>= 1;
[450] 
[451]         if (bit == 0) {
[452]             i++;
[453]             bit = 0x80;
[454]         }
[455]     }
[456] 
[457]     return value;
[458] }
[459] 
[460] #endif
[461] 
[462] 
[463] static ngx_radix_node_t *
[464] ngx_radix_alloc(ngx_radix_tree_t *tree)
[465] {
[466]     ngx_radix_node_t  *p;
[467] 
[468]     if (tree->free) {
[469]         p = tree->free;
[470]         tree->free = tree->free->right;
[471]         return p;
[472]     }
[473] 
[474]     if (tree->size < sizeof(ngx_radix_node_t)) {
[475]         tree->start = ngx_pmemalign(tree->pool, ngx_pagesize, ngx_pagesize);
[476]         if (tree->start == NULL) {
[477]             return NULL;
[478]         }
[479] 
[480]         tree->size = ngx_pagesize;
[481]     }
[482] 
[483]     p = (ngx_radix_node_t *) tree->start;
[484]     tree->start += sizeof(ngx_radix_node_t);
[485]     tree->size -= sizeof(ngx_radix_node_t);
[486] 
[487]     return p;
[488] }
