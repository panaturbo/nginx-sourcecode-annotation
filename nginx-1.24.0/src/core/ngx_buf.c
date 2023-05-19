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
[12] ngx_buf_t *
[13] ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
[14] {
[15]     ngx_buf_t *b;
[16] 
[17]     b = ngx_calloc_buf(pool);
[18]     if (b == NULL) {
[19]         return NULL;
[20]     }
[21] 
[22]     b->start = ngx_palloc(pool, size);
[23]     if (b->start == NULL) {
[24]         return NULL;
[25]     }
[26] 
[27]     /*
[28]      * set by ngx_calloc_buf():
[29]      *
[30]      *     b->file_pos = 0;
[31]      *     b->file_last = 0;
[32]      *     b->file = NULL;
[33]      *     b->shadow = NULL;
[34]      *     b->tag = 0;
[35]      *     and flags
[36]      */
[37] 
[38]     b->pos = b->start;
[39]     b->last = b->start;
[40]     b->end = b->last + size;
[41]     b->temporary = 1;
[42] 
[43]     return b;
[44] }
[45] 
[46] 
[47] ngx_chain_t *
[48] ngx_alloc_chain_link(ngx_pool_t *pool)
[49] {
[50]     ngx_chain_t  *cl;
[51] 
[52]     cl = pool->chain;
[53] 
[54]     if (cl) {
[55]         pool->chain = cl->next;
[56]         return cl;
[57]     }
[58] 
[59]     cl = ngx_palloc(pool, sizeof(ngx_chain_t));
[60]     if (cl == NULL) {
[61]         return NULL;
[62]     }
[63] 
[64]     return cl;
[65] }
[66] 
[67] 
[68] ngx_chain_t *
[69] ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
[70] {
[71]     u_char       *p;
[72]     ngx_int_t     i;
[73]     ngx_buf_t    *b;
[74]     ngx_chain_t  *chain, *cl, **ll;
[75] 
[76]     p = ngx_palloc(pool, bufs->num * bufs->size);
[77]     if (p == NULL) {
[78]         return NULL;
[79]     }
[80] 
[81]     ll = &chain;
[82] 
[83]     for (i = 0; i < bufs->num; i++) {
[84] 
[85]         b = ngx_calloc_buf(pool);
[86]         if (b == NULL) {
[87]             return NULL;
[88]         }
[89] 
[90]         /*
[91]          * set by ngx_calloc_buf():
[92]          *
[93]          *     b->file_pos = 0;
[94]          *     b->file_last = 0;
[95]          *     b->file = NULL;
[96]          *     b->shadow = NULL;
[97]          *     b->tag = 0;
[98]          *     and flags
[99]          *
[100]          */
[101] 
[102]         b->pos = p;
[103]         b->last = p;
[104]         b->temporary = 1;
[105] 
[106]         b->start = p;
[107]         p += bufs->size;
[108]         b->end = p;
[109] 
[110]         cl = ngx_alloc_chain_link(pool);
[111]         if (cl == NULL) {
[112]             return NULL;
[113]         }
[114] 
[115]         cl->buf = b;
[116]         *ll = cl;
[117]         ll = &cl->next;
[118]     }
[119] 
[120]     *ll = NULL;
[121] 
[122]     return chain;
[123] }
[124] 
[125] 
[126] ngx_int_t
[127] ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
[128] {
[129]     ngx_chain_t  *cl, **ll;
[130] 
[131]     ll = chain;
[132] 
[133]     for (cl = *chain; cl; cl = cl->next) {
[134]         ll = &cl->next;
[135]     }
[136] 
[137]     while (in) {
[138]         cl = ngx_alloc_chain_link(pool);
[139]         if (cl == NULL) {
[140]             *ll = NULL;
[141]             return NGX_ERROR;
[142]         }
[143] 
[144]         cl->buf = in->buf;
[145]         *ll = cl;
[146]         ll = &cl->next;
[147]         in = in->next;
[148]     }
[149] 
[150]     *ll = NULL;
[151] 
[152]     return NGX_OK;
[153] }
[154] 
[155] 
[156] ngx_chain_t *
[157] ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
[158] {
[159]     ngx_chain_t  *cl;
[160] 
[161]     if (*free) {
[162]         cl = *free;
[163]         *free = cl->next;
[164]         cl->next = NULL;
[165]         return cl;
[166]     }
[167] 
[168]     cl = ngx_alloc_chain_link(p);
[169]     if (cl == NULL) {
[170]         return NULL;
[171]     }
[172] 
[173]     cl->buf = ngx_calloc_buf(p);
[174]     if (cl->buf == NULL) {
[175]         return NULL;
[176]     }
[177] 
[178]     cl->next = NULL;
[179] 
[180]     return cl;
[181] }
[182] 
[183] 
[184] void
[185] ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
[186]     ngx_chain_t **out, ngx_buf_tag_t tag)
[187] {
[188]     ngx_chain_t  *cl;
[189] 
[190]     if (*out) {
[191]         if (*busy == NULL) {
[192]             *busy = *out;
[193] 
[194]         } else {
[195]             for (cl = *busy; cl->next; cl = cl->next) { /* void */ }
[196] 
[197]             cl->next = *out;
[198]         }
[199] 
[200]         *out = NULL;
[201]     }
[202] 
[203]     while (*busy) {
[204]         cl = *busy;
[205] 
[206]         if (cl->buf->tag != tag) {
[207]             *busy = cl->next;
[208]             ngx_free_chain(p, cl);
[209]             continue;
[210]         }
[211] 
[212]         if (ngx_buf_size(cl->buf) != 0) {
[213]             break;
[214]         }
[215] 
[216]         cl->buf->pos = cl->buf->start;
[217]         cl->buf->last = cl->buf->start;
[218] 
[219]         *busy = cl->next;
[220]         cl->next = *free;
[221]         *free = cl;
[222]     }
[223] }
[224] 
[225] 
[226] off_t
[227] ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
[228] {
[229]     off_t         total, size, aligned, fprev;
[230]     ngx_fd_t      fd;
[231]     ngx_chain_t  *cl;
[232] 
[233]     total = 0;
[234] 
[235]     cl = *in;
[236]     fd = cl->buf->file->fd;
[237] 
[238]     do {
[239]         size = cl->buf->file_last - cl->buf->file_pos;
[240] 
[241]         if (size > limit - total) {
[242]             size = limit - total;
[243] 
[244]             aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
[245]                        & ~((off_t) ngx_pagesize - 1);
[246] 
[247]             if (aligned <= cl->buf->file_last) {
[248]                 size = aligned - cl->buf->file_pos;
[249]             }
[250] 
[251]             total += size;
[252]             break;
[253]         }
[254] 
[255]         total += size;
[256]         fprev = cl->buf->file_pos + size;
[257]         cl = cl->next;
[258] 
[259]     } while (cl
[260]              && cl->buf->in_file
[261]              && total < limit
[262]              && fd == cl->buf->file->fd
[263]              && fprev == cl->buf->file_pos);
[264] 
[265]     *in = cl;
[266] 
[267]     return total;
[268] }
[269] 
[270] 
[271] ngx_chain_t *
[272] ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
[273] {
[274]     off_t  size;
[275] 
[276]     for ( /* void */ ; in; in = in->next) {
[277] 
[278]         if (ngx_buf_special(in->buf)) {
[279]             continue;
[280]         }
[281] 
[282]         if (sent == 0) {
[283]             break;
[284]         }
[285] 
[286]         size = ngx_buf_size(in->buf);
[287] 
[288]         if (sent >= size) {
[289]             sent -= size;
[290] 
[291]             if (ngx_buf_in_memory(in->buf)) {
[292]                 in->buf->pos = in->buf->last;
[293]             }
[294] 
[295]             if (in->buf->in_file) {
[296]                 in->buf->file_pos = in->buf->file_last;
[297]             }
[298] 
[299]             continue;
[300]         }
[301] 
[302]         if (ngx_buf_in_memory(in->buf)) {
[303]             in->buf->pos += (size_t) sent;
[304]         }
[305] 
[306]         if (in->buf->in_file) {
[307]             in->buf->file_pos += sent;
[308]         }
[309] 
[310]         break;
[311]     }
[312] 
[313]     return in;
[314] }
