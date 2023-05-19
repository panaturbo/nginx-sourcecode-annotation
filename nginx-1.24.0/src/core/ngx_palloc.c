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
[12] static ngx_inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size,
[13]     ngx_uint_t align);
[14] static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);
[15] static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);
[16] 
[17] 
[18] ngx_pool_t *
[19] ngx_create_pool(size_t size, ngx_log_t *log)
[20] {
[21]     ngx_pool_t  *p;
[22] 
[23]     p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
[24]     if (p == NULL) {
[25]         return NULL;
[26]     }
[27] 
[28]     p->d.last = (u_char *) p + sizeof(ngx_pool_t);
[29]     p->d.end = (u_char *) p + size;
[30]     p->d.next = NULL;
[31]     p->d.failed = 0;
[32] 
[33]     size = size - sizeof(ngx_pool_t);
[34]     p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;
[35] 
[36]     p->current = p;
[37]     p->chain = NULL;
[38]     p->large = NULL;
[39]     p->cleanup = NULL;
[40]     p->log = log;
[41] 
[42]     return p;
[43] }
[44] 
[45] 
[46] void
[47] ngx_destroy_pool(ngx_pool_t *pool)
[48] {
[49]     ngx_pool_t          *p, *n;
[50]     ngx_pool_large_t    *l;
[51]     ngx_pool_cleanup_t  *c;
[52] 
[53]     for (c = pool->cleanup; c; c = c->next) {
[54]         if (c->handler) {
[55]             ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
[56]                            "run cleanup: %p", c);
[57]             c->handler(c->data);
[58]         }
[59]     }
[60] 
[61] #if (NGX_DEBUG)
[62] 
[63]     /*
[64]      * we could allocate the pool->log from this pool
[65]      * so we cannot use this log while free()ing the pool
[66]      */
[67] 
[68]     for (l = pool->large; l; l = l->next) {
[69]         ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
[70]     }
[71] 
[72]     for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
[73]         ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
[74]                        "free: %p, unused: %uz", p, p->d.end - p->d.last);
[75] 
[76]         if (n == NULL) {
[77]             break;
[78]         }
[79]     }
[80] 
[81] #endif
[82] 
[83]     for (l = pool->large; l; l = l->next) {
[84]         if (l->alloc) {
[85]             ngx_free(l->alloc);
[86]         }
[87]     }
[88] 
[89]     for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
[90]         ngx_free(p);
[91] 
[92]         if (n == NULL) {
[93]             break;
[94]         }
[95]     }
[96] }
[97] 
[98] 
[99] void
[100] ngx_reset_pool(ngx_pool_t *pool)
[101] {
[102]     ngx_pool_t        *p;
[103]     ngx_pool_large_t  *l;
[104] 
[105]     for (l = pool->large; l; l = l->next) {
[106]         if (l->alloc) {
[107]             ngx_free(l->alloc);
[108]         }
[109]     }
[110] 
[111]     for (p = pool; p; p = p->d.next) {
[112]         p->d.last = (u_char *) p + sizeof(ngx_pool_t);
[113]         p->d.failed = 0;
[114]     }
[115] 
[116]     pool->current = pool;
[117]     pool->chain = NULL;
[118]     pool->large = NULL;
[119] }
[120] 
[121] 
[122] void *
[123] ngx_palloc(ngx_pool_t *pool, size_t size)
[124] {
[125] #if !(NGX_DEBUG_PALLOC)
[126]     if (size <= pool->max) {
[127]         return ngx_palloc_small(pool, size, 1);
[128]     }
[129] #endif
[130] 
[131]     return ngx_palloc_large(pool, size);
[132] }
[133] 
[134] 
[135] void *
[136] ngx_pnalloc(ngx_pool_t *pool, size_t size)
[137] {
[138] #if !(NGX_DEBUG_PALLOC)
[139]     if (size <= pool->max) {
[140]         return ngx_palloc_small(pool, size, 0);
[141]     }
[142] #endif
[143] 
[144]     return ngx_palloc_large(pool, size);
[145] }
[146] 
[147] 
[148] static ngx_inline void *
[149] ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
[150] {
[151]     u_char      *m;
[152]     ngx_pool_t  *p;
[153] 
[154]     p = pool->current;
[155] 
[156]     do {
[157]         m = p->d.last;
[158] 
[159]         if (align) {
[160]             m = ngx_align_ptr(m, NGX_ALIGNMENT);
[161]         }
[162] 
[163]         if ((size_t) (p->d.end - m) >= size) {
[164]             p->d.last = m + size;
[165] 
[166]             return m;
[167]         }
[168] 
[169]         p = p->d.next;
[170] 
[171]     } while (p);
[172] 
[173]     return ngx_palloc_block(pool, size);
[174] }
[175] 
[176] 
[177] static void *
[178] ngx_palloc_block(ngx_pool_t *pool, size_t size)
[179] {
[180]     u_char      *m;
[181]     size_t       psize;
[182]     ngx_pool_t  *p, *new;
[183] 
[184]     psize = (size_t) (pool->d.end - (u_char *) pool);
[185] 
[186]     m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
[187]     if (m == NULL) {
[188]         return NULL;
[189]     }
[190] 
[191]     new = (ngx_pool_t *) m;
[192] 
[193]     new->d.end = m + psize;
[194]     new->d.next = NULL;
[195]     new->d.failed = 0;
[196] 
[197]     m += sizeof(ngx_pool_data_t);
[198]     m = ngx_align_ptr(m, NGX_ALIGNMENT);
[199]     new->d.last = m + size;
[200] 
[201]     for (p = pool->current; p->d.next; p = p->d.next) {
[202]         if (p->d.failed++ > 4) {
[203]             pool->current = p->d.next;
[204]         }
[205]     }
[206] 
[207]     p->d.next = new;
[208] 
[209]     return m;
[210] }
[211] 
[212] 
[213] static void *
[214] ngx_palloc_large(ngx_pool_t *pool, size_t size)
[215] {
[216]     void              *p;
[217]     ngx_uint_t         n;
[218]     ngx_pool_large_t  *large;
[219] 
[220]     p = ngx_alloc(size, pool->log);
[221]     if (p == NULL) {
[222]         return NULL;
[223]     }
[224] 
[225]     n = 0;
[226] 
[227]     for (large = pool->large; large; large = large->next) {
[228]         if (large->alloc == NULL) {
[229]             large->alloc = p;
[230]             return p;
[231]         }
[232] 
[233]         if (n++ > 3) {
[234]             break;
[235]         }
[236]     }
[237] 
[238]     large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
[239]     if (large == NULL) {
[240]         ngx_free(p);
[241]         return NULL;
[242]     }
[243] 
[244]     large->alloc = p;
[245]     large->next = pool->large;
[246]     pool->large = large;
[247] 
[248]     return p;
[249] }
[250] 
[251] 
[252] void *
[253] ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment)
[254] {
[255]     void              *p;
[256]     ngx_pool_large_t  *large;
[257] 
[258]     p = ngx_memalign(alignment, size, pool->log);
[259]     if (p == NULL) {
[260]         return NULL;
[261]     }
[262] 
[263]     large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
[264]     if (large == NULL) {
[265]         ngx_free(p);
[266]         return NULL;
[267]     }
[268] 
[269]     large->alloc = p;
[270]     large->next = pool->large;
[271]     pool->large = large;
[272] 
[273]     return p;
[274] }
[275] 
[276] 
[277] ngx_int_t
[278] ngx_pfree(ngx_pool_t *pool, void *p)
[279] {
[280]     ngx_pool_large_t  *l;
[281] 
[282]     for (l = pool->large; l; l = l->next) {
[283]         if (p == l->alloc) {
[284]             ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
[285]                            "free: %p", l->alloc);
[286]             ngx_free(l->alloc);
[287]             l->alloc = NULL;
[288] 
[289]             return NGX_OK;
[290]         }
[291]     }
[292] 
[293]     return NGX_DECLINED;
[294] }
[295] 
[296] 
[297] void *
[298] ngx_pcalloc(ngx_pool_t *pool, size_t size)
[299] {
[300]     void *p;
[301] 
[302]     p = ngx_palloc(pool, size);
[303]     if (p) {
[304]         ngx_memzero(p, size);
[305]     }
[306] 
[307]     return p;
[308] }
[309] 
[310] 
[311] ngx_pool_cleanup_t *
[312] ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
[313] {
[314]     ngx_pool_cleanup_t  *c;
[315] 
[316]     c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
[317]     if (c == NULL) {
[318]         return NULL;
[319]     }
[320] 
[321]     if (size) {
[322]         c->data = ngx_palloc(p, size);
[323]         if (c->data == NULL) {
[324]             return NULL;
[325]         }
[326] 
[327]     } else {
[328]         c->data = NULL;
[329]     }
[330] 
[331]     c->handler = NULL;
[332]     c->next = p->cleanup;
[333] 
[334]     p->cleanup = c;
[335] 
[336]     ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);
[337] 
[338]     return c;
[339] }
[340] 
[341] 
[342] void
[343] ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd)
[344] {
[345]     ngx_pool_cleanup_t       *c;
[346]     ngx_pool_cleanup_file_t  *cf;
[347] 
[348]     for (c = p->cleanup; c; c = c->next) {
[349]         if (c->handler == ngx_pool_cleanup_file) {
[350] 
[351]             cf = c->data;
[352] 
[353]             if (cf->fd == fd) {
[354]                 c->handler(cf);
[355]                 c->handler = NULL;
[356]                 return;
[357]             }
[358]         }
[359]     }
[360] }
[361] 
[362] 
[363] void
[364] ngx_pool_cleanup_file(void *data)
[365] {
[366]     ngx_pool_cleanup_file_t  *c = data;
[367] 
[368]     ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
[369]                    c->fd);
[370] 
[371]     if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
[372]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[373]                       ngx_close_file_n " \"%s\" failed", c->name);
[374]     }
[375] }
[376] 
[377] 
[378] void
[379] ngx_pool_delete_file(void *data)
[380] {
[381]     ngx_pool_cleanup_file_t  *c = data;
[382] 
[383]     ngx_err_t  err;
[384] 
[385]     ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
[386]                    c->fd, c->name);
[387] 
[388]     if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
[389]         err = ngx_errno;
[390] 
[391]         if (err != NGX_ENOENT) {
[392]             ngx_log_error(NGX_LOG_CRIT, c->log, err,
[393]                           ngx_delete_file_n " \"%s\" failed", c->name);
[394]         }
[395]     }
[396] 
[397]     if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
[398]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[399]                       ngx_close_file_n " \"%s\" failed", c->name);
[400]     }
[401] }
[402] 
[403] 
[404] #if 0
[405] 
[406] static void *
[407] ngx_get_cached_block(size_t size)
[408] {
[409]     void                     *p;
[410]     ngx_cached_block_slot_t  *slot;
[411] 
[412]     if (ngx_cycle->cache == NULL) {
[413]         return NULL;
[414]     }
[415] 
[416]     slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];
[417] 
[418]     slot->tries++;
[419] 
[420]     if (slot->number) {
[421]         p = slot->block;
[422]         slot->block = slot->block->next;
[423]         slot->number--;
[424]         return p;
[425]     }
[426] 
[427]     return NULL;
[428] }
[429] 
[430] #endif
