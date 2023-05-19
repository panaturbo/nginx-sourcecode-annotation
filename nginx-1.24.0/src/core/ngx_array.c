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
[12] ngx_array_t *
[13] ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
[14] {
[15]     ngx_array_t *a;
[16] 
[17]     a = ngx_palloc(p, sizeof(ngx_array_t));
[18]     if (a == NULL) {
[19]         return NULL;
[20]     }
[21] 
[22]     if (ngx_array_init(a, p, n, size) != NGX_OK) {
[23]         return NULL;
[24]     }
[25] 
[26]     return a;
[27] }
[28] 
[29] 
[30] void
[31] ngx_array_destroy(ngx_array_t *a)
[32] {
[33]     ngx_pool_t  *p;
[34] 
[35]     p = a->pool;
[36] 
[37]     if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
[38]         p->d.last -= a->size * a->nalloc;
[39]     }
[40] 
[41]     if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
[42]         p->d.last = (u_char *) a;
[43]     }
[44] }
[45] 
[46] 
[47] void *
[48] ngx_array_push(ngx_array_t *a)
[49] {
[50]     void        *elt, *new;
[51]     size_t       size;
[52]     ngx_pool_t  *p;
[53] 
[54]     if (a->nelts == a->nalloc) {
[55] 
[56]         /* the array is full */
[57] 
[58]         size = a->size * a->nalloc;
[59] 
[60]         p = a->pool;
[61] 
[62]         if ((u_char *) a->elts + size == p->d.last
[63]             && p->d.last + a->size <= p->d.end)
[64]         {
[65]             /*
[66]              * the array allocation is the last in the pool
[67]              * and there is space for new allocation
[68]              */
[69] 
[70]             p->d.last += a->size;
[71]             a->nalloc++;
[72] 
[73]         } else {
[74]             /* allocate a new array */
[75] 
[76]             new = ngx_palloc(p, 2 * size);
[77]             if (new == NULL) {
[78]                 return NULL;
[79]             }
[80] 
[81]             ngx_memcpy(new, a->elts, size);
[82]             a->elts = new;
[83]             a->nalloc *= 2;
[84]         }
[85]     }
[86] 
[87]     elt = (u_char *) a->elts + a->size * a->nelts;
[88]     a->nelts++;
[89] 
[90]     return elt;
[91] }
[92] 
[93] 
[94] void *
[95] ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
[96] {
[97]     void        *elt, *new;
[98]     size_t       size;
[99]     ngx_uint_t   nalloc;
[100]     ngx_pool_t  *p;
[101] 
[102]     size = n * a->size;
[103] 
[104]     if (a->nelts + n > a->nalloc) {
[105] 
[106]         /* the array is full */
[107] 
[108]         p = a->pool;
[109] 
[110]         if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
[111]             && p->d.last + size <= p->d.end)
[112]         {
[113]             /*
[114]              * the array allocation is the last in the pool
[115]              * and there is space for new allocation
[116]              */
[117] 
[118]             p->d.last += size;
[119]             a->nalloc += n;
[120] 
[121]         } else {
[122]             /* allocate a new array */
[123] 
[124]             nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);
[125] 
[126]             new = ngx_palloc(p, nalloc * a->size);
[127]             if (new == NULL) {
[128]                 return NULL;
[129]             }
[130] 
[131]             ngx_memcpy(new, a->elts, a->nelts * a->size);
[132]             a->elts = new;
[133]             a->nalloc = nalloc;
[134]         }
[135]     }
[136] 
[137]     elt = (u_char *) a->elts + a->size * a->nelts;
[138]     a->nelts += n;
[139] 
[140]     return elt;
[141] }
