[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] 
[10] 
[11] #define NGX_SLAB_PAGE_MASK   3
[12] #define NGX_SLAB_PAGE        0
[13] #define NGX_SLAB_BIG         1
[14] #define NGX_SLAB_EXACT       2
[15] #define NGX_SLAB_SMALL       3
[16] 
[17] #if (NGX_PTR_SIZE == 4)
[18] 
[19] #define NGX_SLAB_PAGE_FREE   0
[20] #define NGX_SLAB_PAGE_BUSY   0xffffffff
[21] #define NGX_SLAB_PAGE_START  0x80000000
[22] 
[23] #define NGX_SLAB_SHIFT_MASK  0x0000000f
[24] #define NGX_SLAB_MAP_MASK    0xffff0000
[25] #define NGX_SLAB_MAP_SHIFT   16
[26] 
[27] #define NGX_SLAB_BUSY        0xffffffff
[28] 
[29] #else /* (NGX_PTR_SIZE == 8) */
[30] 
[31] #define NGX_SLAB_PAGE_FREE   0
[32] #define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
[33] #define NGX_SLAB_PAGE_START  0x8000000000000000
[34] 
[35] #define NGX_SLAB_SHIFT_MASK  0x000000000000000f
[36] #define NGX_SLAB_MAP_MASK    0xffffffff00000000
[37] #define NGX_SLAB_MAP_SHIFT   32
[38] 
[39] #define NGX_SLAB_BUSY        0xffffffffffffffff
[40] 
[41] #endif
[42] 
[43] 
[44] #define ngx_slab_slots(pool)                                                  \
[45]     (ngx_slab_page_t *) ((u_char *) (pool) + sizeof(ngx_slab_pool_t))
[46] 
[47] #define ngx_slab_page_type(page)   ((page)->prev & NGX_SLAB_PAGE_MASK)
[48] 
[49] #define ngx_slab_page_prev(page)                                              \
[50]     (ngx_slab_page_t *) ((page)->prev & ~NGX_SLAB_PAGE_MASK)
[51] 
[52] #define ngx_slab_page_addr(pool, page)                                        \
[53]     ((((page) - (pool)->pages) << ngx_pagesize_shift)                         \
[54]      + (uintptr_t) (pool)->start)
[55] 
[56] 
[57] #if (NGX_DEBUG_MALLOC)
[58] 
[59] #define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)
[60] 
[61] #elif (NGX_HAVE_DEBUG_MALLOC)
[62] 
[63] #define ngx_slab_junk(p, size)                                                \
[64]     if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)
[65] 
[66] #else
[67] 
[68] #define ngx_slab_junk(p, size)
[69] 
[70] #endif
[71] 
[72] static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
[73]     ngx_uint_t pages);
[74] static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
[75]     ngx_uint_t pages);
[76] static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
[77]     char *text);
[78] 
[79] 
[80] static ngx_uint_t  ngx_slab_max_size;
[81] static ngx_uint_t  ngx_slab_exact_size;
[82] static ngx_uint_t  ngx_slab_exact_shift;
[83] 
[84] 
[85] void
[86] ngx_slab_sizes_init(void)
[87] {
[88]     ngx_uint_t  n;
[89] 
[90]     ngx_slab_max_size = ngx_pagesize / 2;
[91]     ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));
[92]     for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
[93]         /* void */
[94]     }
[95] }
[96] 
[97] 
[98] void
[99] ngx_slab_init(ngx_slab_pool_t *pool)
[100] {
[101]     u_char           *p;
[102]     size_t            size;
[103]     ngx_int_t         m;
[104]     ngx_uint_t        i, n, pages;
[105]     ngx_slab_page_t  *slots, *page;
[106] 
[107]     pool->min_size = (size_t) 1 << pool->min_shift;
[108] 
[109]     slots = ngx_slab_slots(pool);
[110] 
[111]     p = (u_char *) slots;
[112]     size = pool->end - p;
[113] 
[114]     ngx_slab_junk(p, size);
[115] 
[116]     n = ngx_pagesize_shift - pool->min_shift;
[117] 
[118]     for (i = 0; i < n; i++) {
[119]         /* only "next" is used in list head */
[120]         slots[i].slab = 0;
[121]         slots[i].next = &slots[i];
[122]         slots[i].prev = 0;
[123]     }
[124] 
[125]     p += n * sizeof(ngx_slab_page_t);
[126] 
[127]     pool->stats = (ngx_slab_stat_t *) p;
[128]     ngx_memzero(pool->stats, n * sizeof(ngx_slab_stat_t));
[129] 
[130]     p += n * sizeof(ngx_slab_stat_t);
[131] 
[132]     size -= n * (sizeof(ngx_slab_page_t) + sizeof(ngx_slab_stat_t));
[133] 
[134]     pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));
[135] 
[136]     pool->pages = (ngx_slab_page_t *) p;
[137]     ngx_memzero(pool->pages, pages * sizeof(ngx_slab_page_t));
[138] 
[139]     page = pool->pages;
[140] 
[141]     /* only "next" is used in list head */
[142]     pool->free.slab = 0;
[143]     pool->free.next = page;
[144]     pool->free.prev = 0;
[145] 
[146]     page->slab = pages;
[147]     page->next = &pool->free;
[148]     page->prev = (uintptr_t) &pool->free;
[149] 
[150]     pool->start = ngx_align_ptr(p + pages * sizeof(ngx_slab_page_t),
[151]                                 ngx_pagesize);
[152] 
[153]     m = pages - (pool->end - pool->start) / ngx_pagesize;
[154]     if (m > 0) {
[155]         pages -= m;
[156]         page->slab = pages;
[157]     }
[158] 
[159]     pool->last = pool->pages + pages;
[160]     pool->pfree = pages;
[161] 
[162]     pool->log_nomem = 1;
[163]     pool->log_ctx = &pool->zero;
[164]     pool->zero = '\0';
[165] }
[166] 
[167] 
[168] void *
[169] ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
[170] {
[171]     void  *p;
[172] 
[173]     ngx_shmtx_lock(&pool->mutex);
[174] 
[175]     p = ngx_slab_alloc_locked(pool, size);
[176] 
[177]     ngx_shmtx_unlock(&pool->mutex);
[178] 
[179]     return p;
[180] }
[181] 
[182] 
[183] void *
[184] ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
[185] {
[186]     size_t            s;
[187]     uintptr_t         p, m, mask, *bitmap;
[188]     ngx_uint_t        i, n, slot, shift, map;
[189]     ngx_slab_page_t  *page, *prev, *slots;
[190] 
[191]     if (size > ngx_slab_max_size) {
[192] 
[193]         ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
[194]                        "slab alloc: %uz", size);
[195] 
[196]         page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
[197]                                           + ((size % ngx_pagesize) ? 1 : 0));
[198]         if (page) {
[199]             p = ngx_slab_page_addr(pool, page);
[200] 
[201]         } else {
[202]             p = 0;
[203]         }
[204] 
[205]         goto done;
[206]     }
[207] 
[208]     if (size > pool->min_size) {
[209]         shift = 1;
[210]         for (s = size - 1; s >>= 1; shift++) { /* void */ }
[211]         slot = shift - pool->min_shift;
[212] 
[213]     } else {
[214]         shift = pool->min_shift;
[215]         slot = 0;
[216]     }
[217] 
[218]     pool->stats[slot].reqs++;
[219] 
[220]     ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
[221]                    "slab alloc: %uz slot: %ui", size, slot);
[222] 
[223]     slots = ngx_slab_slots(pool);
[224]     page = slots[slot].next;
[225] 
[226]     if (page->next != page) {
[227] 
[228]         if (shift < ngx_slab_exact_shift) {
[229] 
[230]             bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);
[231] 
[232]             map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));
[233] 
[234]             for (n = 0; n < map; n++) {
[235] 
[236]                 if (bitmap[n] != NGX_SLAB_BUSY) {
[237] 
[238]                     for (m = 1, i = 0; m; m <<= 1, i++) {
[239]                         if (bitmap[n] & m) {
[240]                             continue;
[241]                         }
[242] 
[243]                         bitmap[n] |= m;
[244] 
[245]                         i = (n * 8 * sizeof(uintptr_t) + i) << shift;
[246] 
[247]                         p = (uintptr_t) bitmap + i;
[248] 
[249]                         pool->stats[slot].used++;
[250] 
[251]                         if (bitmap[n] == NGX_SLAB_BUSY) {
[252]                             for (n = n + 1; n < map; n++) {
[253]                                 if (bitmap[n] != NGX_SLAB_BUSY) {
[254]                                     goto done;
[255]                                 }
[256]                             }
[257] 
[258]                             prev = ngx_slab_page_prev(page);
[259]                             prev->next = page->next;
[260]                             page->next->prev = page->prev;
[261] 
[262]                             page->next = NULL;
[263]                             page->prev = NGX_SLAB_SMALL;
[264]                         }
[265] 
[266]                         goto done;
[267]                     }
[268]                 }
[269]             }
[270] 
[271]         } else if (shift == ngx_slab_exact_shift) {
[272] 
[273]             for (m = 1, i = 0; m; m <<= 1, i++) {
[274]                 if (page->slab & m) {
[275]                     continue;
[276]                 }
[277] 
[278]                 page->slab |= m;
[279] 
[280]                 if (page->slab == NGX_SLAB_BUSY) {
[281]                     prev = ngx_slab_page_prev(page);
[282]                     prev->next = page->next;
[283]                     page->next->prev = page->prev;
[284] 
[285]                     page->next = NULL;
[286]                     page->prev = NGX_SLAB_EXACT;
[287]                 }
[288] 
[289]                 p = ngx_slab_page_addr(pool, page) + (i << shift);
[290] 
[291]                 pool->stats[slot].used++;
[292] 
[293]                 goto done;
[294]             }
[295] 
[296]         } else { /* shift > ngx_slab_exact_shift */
[297] 
[298]             mask = ((uintptr_t) 1 << (ngx_pagesize >> shift)) - 1;
[299]             mask <<= NGX_SLAB_MAP_SHIFT;
[300] 
[301]             for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
[302]                  m & mask;
[303]                  m <<= 1, i++)
[304]             {
[305]                 if (page->slab & m) {
[306]                     continue;
[307]                 }
[308] 
[309]                 page->slab |= m;
[310] 
[311]                 if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
[312]                     prev = ngx_slab_page_prev(page);
[313]                     prev->next = page->next;
[314]                     page->next->prev = page->prev;
[315] 
[316]                     page->next = NULL;
[317]                     page->prev = NGX_SLAB_BIG;
[318]                 }
[319] 
[320]                 p = ngx_slab_page_addr(pool, page) + (i << shift);
[321] 
[322]                 pool->stats[slot].used++;
[323] 
[324]                 goto done;
[325]             }
[326]         }
[327] 
[328]         ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
[329]         ngx_debug_point();
[330]     }
[331] 
[332]     page = ngx_slab_alloc_pages(pool, 1);
[333] 
[334]     if (page) {
[335]         if (shift < ngx_slab_exact_shift) {
[336]             bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);
[337] 
[338]             n = (ngx_pagesize >> shift) / ((1 << shift) * 8);
[339] 
[340]             if (n == 0) {
[341]                 n = 1;
[342]             }
[343] 
[344]             /* "n" elements for bitmap, plus one requested */
[345] 
[346]             for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
[347]                 bitmap[i] = NGX_SLAB_BUSY;
[348]             }
[349] 
[350]             m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
[351]             bitmap[i] = m;
[352] 
[353]             map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));
[354] 
[355]             for (i = i + 1; i < map; i++) {
[356]                 bitmap[i] = 0;
[357]             }
[358] 
[359]             page->slab = shift;
[360]             page->next = &slots[slot];
[361]             page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
[362] 
[363]             slots[slot].next = page;
[364] 
[365]             pool->stats[slot].total += (ngx_pagesize >> shift) - n;
[366] 
[367]             p = ngx_slab_page_addr(pool, page) + (n << shift);
[368] 
[369]             pool->stats[slot].used++;
[370] 
[371]             goto done;
[372] 
[373]         } else if (shift == ngx_slab_exact_shift) {
[374] 
[375]             page->slab = 1;
[376]             page->next = &slots[slot];
[377]             page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
[378] 
[379]             slots[slot].next = page;
[380] 
[381]             pool->stats[slot].total += 8 * sizeof(uintptr_t);
[382] 
[383]             p = ngx_slab_page_addr(pool, page);
[384] 
[385]             pool->stats[slot].used++;
[386] 
[387]             goto done;
[388] 
[389]         } else { /* shift > ngx_slab_exact_shift */
[390] 
[391]             page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;
[392]             page->next = &slots[slot];
[393]             page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
[394] 
[395]             slots[slot].next = page;
[396] 
[397]             pool->stats[slot].total += ngx_pagesize >> shift;
[398] 
[399]             p = ngx_slab_page_addr(pool, page);
[400] 
[401]             pool->stats[slot].used++;
[402] 
[403]             goto done;
[404]         }
[405]     }
[406] 
[407]     p = 0;
[408] 
[409]     pool->stats[slot].fails++;
[410] 
[411] done:
[412] 
[413]     ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
[414]                    "slab alloc: %p", (void *) p);
[415] 
[416]     return (void *) p;
[417] }
[418] 
[419] 
[420] void *
[421] ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size)
[422] {
[423]     void  *p;
[424] 
[425]     ngx_shmtx_lock(&pool->mutex);
[426] 
[427]     p = ngx_slab_calloc_locked(pool, size);
[428] 
[429]     ngx_shmtx_unlock(&pool->mutex);
[430] 
[431]     return p;
[432] }
[433] 
[434] 
[435] void *
[436] ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size)
[437] {
[438]     void  *p;
[439] 
[440]     p = ngx_slab_alloc_locked(pool, size);
[441]     if (p) {
[442]         ngx_memzero(p, size);
[443]     }
[444] 
[445]     return p;
[446] }
[447] 
[448] 
[449] void
[450] ngx_slab_free(ngx_slab_pool_t *pool, void *p)
[451] {
[452]     ngx_shmtx_lock(&pool->mutex);
[453] 
[454]     ngx_slab_free_locked(pool, p);
[455] 
[456]     ngx_shmtx_unlock(&pool->mutex);
[457] }
[458] 
[459] 
[460] void
[461] ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
[462] {
[463]     size_t            size;
[464]     uintptr_t         slab, m, *bitmap;
[465]     ngx_uint_t        i, n, type, slot, shift, map;
[466]     ngx_slab_page_t  *slots, *page;
[467] 
[468]     ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);
[469] 
[470]     if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
[471]         ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
[472]         goto fail;
[473]     }
[474] 
[475]     n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
[476]     page = &pool->pages[n];
[477]     slab = page->slab;
[478]     type = ngx_slab_page_type(page);
[479] 
[480]     switch (type) {
[481] 
[482]     case NGX_SLAB_SMALL:
[483] 
[484]         shift = slab & NGX_SLAB_SHIFT_MASK;
[485]         size = (size_t) 1 << shift;
[486] 
[487]         if ((uintptr_t) p & (size - 1)) {
[488]             goto wrong_chunk;
[489]         }
[490] 
[491]         n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
[492]         m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
[493]         n /= 8 * sizeof(uintptr_t);
[494]         bitmap = (uintptr_t *)
[495]                              ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));
[496] 
[497]         if (bitmap[n] & m) {
[498]             slot = shift - pool->min_shift;
[499] 
[500]             if (page->next == NULL) {
[501]                 slots = ngx_slab_slots(pool);
[502] 
[503]                 page->next = slots[slot].next;
[504]                 slots[slot].next = page;
[505] 
[506]                 page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
[507]                 page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
[508]             }
[509] 
[510]             bitmap[n] &= ~m;
[511] 
[512]             n = (ngx_pagesize >> shift) / ((1 << shift) * 8);
[513] 
[514]             if (n == 0) {
[515]                 n = 1;
[516]             }
[517] 
[518]             i = n / (8 * sizeof(uintptr_t));
[519]             m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;
[520] 
[521]             if (bitmap[i] & ~m) {
[522]                 goto done;
[523]             }
[524] 
[525]             map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));
[526] 
[527]             for (i = i + 1; i < map; i++) {
[528]                 if (bitmap[i]) {
[529]                     goto done;
[530]                 }
[531]             }
[532] 
[533]             ngx_slab_free_pages(pool, page, 1);
[534] 
[535]             pool->stats[slot].total -= (ngx_pagesize >> shift) - n;
[536] 
[537]             goto done;
[538]         }
[539] 
[540]         goto chunk_already_free;
[541] 
[542]     case NGX_SLAB_EXACT:
[543] 
[544]         m = (uintptr_t) 1 <<
[545]                 (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
[546]         size = ngx_slab_exact_size;
[547] 
[548]         if ((uintptr_t) p & (size - 1)) {
[549]             goto wrong_chunk;
[550]         }
[551] 
[552]         if (slab & m) {
[553]             slot = ngx_slab_exact_shift - pool->min_shift;
[554] 
[555]             if (slab == NGX_SLAB_BUSY) {
[556]                 slots = ngx_slab_slots(pool);
[557] 
[558]                 page->next = slots[slot].next;
[559]                 slots[slot].next = page;
[560] 
[561]                 page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
[562]                 page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
[563]             }
[564] 
[565]             page->slab &= ~m;
[566] 
[567]             if (page->slab) {
[568]                 goto done;
[569]             }
[570] 
[571]             ngx_slab_free_pages(pool, page, 1);
[572] 
[573]             pool->stats[slot].total -= 8 * sizeof(uintptr_t);
[574] 
[575]             goto done;
[576]         }
[577] 
[578]         goto chunk_already_free;
[579] 
[580]     case NGX_SLAB_BIG:
[581] 
[582]         shift = slab & NGX_SLAB_SHIFT_MASK;
[583]         size = (size_t) 1 << shift;
[584] 
[585]         if ((uintptr_t) p & (size - 1)) {
[586]             goto wrong_chunk;
[587]         }
[588] 
[589]         m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
[590]                               + NGX_SLAB_MAP_SHIFT);
[591] 
[592]         if (slab & m) {
[593]             slot = shift - pool->min_shift;
[594] 
[595]             if (page->next == NULL) {
[596]                 slots = ngx_slab_slots(pool);
[597] 
[598]                 page->next = slots[slot].next;
[599]                 slots[slot].next = page;
[600] 
[601]                 page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
[602]                 page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
[603]             }
[604] 
[605]             page->slab &= ~m;
[606] 
[607]             if (page->slab & NGX_SLAB_MAP_MASK) {
[608]                 goto done;
[609]             }
[610] 
[611]             ngx_slab_free_pages(pool, page, 1);
[612] 
[613]             pool->stats[slot].total -= ngx_pagesize >> shift;
[614] 
[615]             goto done;
[616]         }
[617] 
[618]         goto chunk_already_free;
[619] 
[620]     case NGX_SLAB_PAGE:
[621] 
[622]         if ((uintptr_t) p & (ngx_pagesize - 1)) {
[623]             goto wrong_chunk;
[624]         }
[625] 
[626]         if (!(slab & NGX_SLAB_PAGE_START)) {
[627]             ngx_slab_error(pool, NGX_LOG_ALERT,
[628]                            "ngx_slab_free(): page is already free");
[629]             goto fail;
[630]         }
[631] 
[632]         if (slab == NGX_SLAB_PAGE_BUSY) {
[633]             ngx_slab_error(pool, NGX_LOG_ALERT,
[634]                            "ngx_slab_free(): pointer to wrong page");
[635]             goto fail;
[636]         }
[637] 
[638]         size = slab & ~NGX_SLAB_PAGE_START;
[639] 
[640]         ngx_slab_free_pages(pool, page, size);
[641] 
[642]         ngx_slab_junk(p, size << ngx_pagesize_shift);
[643] 
[644]         return;
[645]     }
[646] 
[647]     /* not reached */
[648] 
[649]     return;
[650] 
[651] done:
[652] 
[653]     pool->stats[slot].used--;
[654] 
[655]     ngx_slab_junk(p, size);
[656] 
[657]     return;
[658] 
[659] wrong_chunk:
[660] 
[661]     ngx_slab_error(pool, NGX_LOG_ALERT,
[662]                    "ngx_slab_free(): pointer to wrong chunk");
[663] 
[664]     goto fail;
[665] 
[666] chunk_already_free:
[667] 
[668]     ngx_slab_error(pool, NGX_LOG_ALERT,
[669]                    "ngx_slab_free(): chunk is already free");
[670] 
[671] fail:
[672] 
[673]     return;
[674] }
[675] 
[676] 
[677] static ngx_slab_page_t *
[678] ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
[679] {
[680]     ngx_slab_page_t  *page, *p;
[681] 
[682]     for (page = pool->free.next; page != &pool->free; page = page->next) {
[683] 
[684]         if (page->slab >= pages) {
[685] 
[686]             if (page->slab > pages) {
[687]                 page[page->slab - 1].prev = (uintptr_t) &page[pages];
[688] 
[689]                 page[pages].slab = page->slab - pages;
[690]                 page[pages].next = page->next;
[691]                 page[pages].prev = page->prev;
[692] 
[693]                 p = (ngx_slab_page_t *) page->prev;
[694]                 p->next = &page[pages];
[695]                 page->next->prev = (uintptr_t) &page[pages];
[696] 
[697]             } else {
[698]                 p = (ngx_slab_page_t *) page->prev;
[699]                 p->next = page->next;
[700]                 page->next->prev = page->prev;
[701]             }
[702] 
[703]             page->slab = pages | NGX_SLAB_PAGE_START;
[704]             page->next = NULL;
[705]             page->prev = NGX_SLAB_PAGE;
[706] 
[707]             pool->pfree -= pages;
[708] 
[709]             if (--pages == 0) {
[710]                 return page;
[711]             }
[712] 
[713]             for (p = page + 1; pages; pages--) {
[714]                 p->slab = NGX_SLAB_PAGE_BUSY;
[715]                 p->next = NULL;
[716]                 p->prev = NGX_SLAB_PAGE;
[717]                 p++;
[718]             }
[719] 
[720]             return page;
[721]         }
[722]     }
[723] 
[724]     if (pool->log_nomem) {
[725]         ngx_slab_error(pool, NGX_LOG_CRIT,
[726]                        "ngx_slab_alloc() failed: no memory");
[727]     }
[728] 
[729]     return NULL;
[730] }
[731] 
[732] 
[733] static void
[734] ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
[735]     ngx_uint_t pages)
[736] {
[737]     ngx_slab_page_t  *prev, *join;
[738] 
[739]     pool->pfree += pages;
[740] 
[741]     page->slab = pages--;
[742] 
[743]     if (pages) {
[744]         ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
[745]     }
[746] 
[747]     if (page->next) {
[748]         prev = ngx_slab_page_prev(page);
[749]         prev->next = page->next;
[750]         page->next->prev = page->prev;
[751]     }
[752] 
[753]     join = page + page->slab;
[754] 
[755]     if (join < pool->last) {
[756] 
[757]         if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {
[758] 
[759]             if (join->next != NULL) {
[760]                 pages += join->slab;
[761]                 page->slab += join->slab;
[762] 
[763]                 prev = ngx_slab_page_prev(join);
[764]                 prev->next = join->next;
[765]                 join->next->prev = join->prev;
[766] 
[767]                 join->slab = NGX_SLAB_PAGE_FREE;
[768]                 join->next = NULL;
[769]                 join->prev = NGX_SLAB_PAGE;
[770]             }
[771]         }
[772]     }
[773] 
[774]     if (page > pool->pages) {
[775]         join = page - 1;
[776] 
[777]         if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {
[778] 
[779]             if (join->slab == NGX_SLAB_PAGE_FREE) {
[780]                 join = ngx_slab_page_prev(join);
[781]             }
[782] 
[783]             if (join->next != NULL) {
[784]                 pages += join->slab;
[785]                 join->slab += page->slab;
[786] 
[787]                 prev = ngx_slab_page_prev(join);
[788]                 prev->next = join->next;
[789]                 join->next->prev = join->prev;
[790] 
[791]                 page->slab = NGX_SLAB_PAGE_FREE;
[792]                 page->next = NULL;
[793]                 page->prev = NGX_SLAB_PAGE;
[794] 
[795]                 page = join;
[796]             }
[797]         }
[798]     }
[799] 
[800]     if (pages) {
[801]         page[pages].prev = (uintptr_t) page;
[802]     }
[803] 
[804]     page->prev = (uintptr_t) &pool->free;
[805]     page->next = pool->free.next;
[806] 
[807]     page->next->prev = (uintptr_t) page;
[808] 
[809]     pool->free.next = page;
[810] }
[811] 
[812] 
[813] static void
[814] ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
[815] {
[816]     ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
[817] }
