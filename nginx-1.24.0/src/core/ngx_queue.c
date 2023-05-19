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
[13]  * find the middle queue element if the queue has odd number of elements
[14]  * or the first element of the queue's second part otherwise
[15]  */
[16] 
[17] ngx_queue_t *
[18] ngx_queue_middle(ngx_queue_t *queue)
[19] {
[20]     ngx_queue_t  *middle, *next;
[21] 
[22]     middle = ngx_queue_head(queue);
[23] 
[24]     if (middle == ngx_queue_last(queue)) {
[25]         return middle;
[26]     }
[27] 
[28]     next = ngx_queue_head(queue);
[29] 
[30]     for ( ;; ) {
[31]         middle = ngx_queue_next(middle);
[32] 
[33]         next = ngx_queue_next(next);
[34] 
[35]         if (next == ngx_queue_last(queue)) {
[36]             return middle;
[37]         }
[38] 
[39]         next = ngx_queue_next(next);
[40] 
[41]         if (next == ngx_queue_last(queue)) {
[42]             return middle;
[43]         }
[44]     }
[45] }
[46] 
[47] 
[48] /* the stable insertion sort */
[49] 
[50] void
[51] ngx_queue_sort(ngx_queue_t *queue,
[52]     ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *))
[53] {
[54]     ngx_queue_t  *q, *prev, *next;
[55] 
[56]     q = ngx_queue_head(queue);
[57] 
[58]     if (q == ngx_queue_last(queue)) {
[59]         return;
[60]     }
[61] 
[62]     for (q = ngx_queue_next(q); q != ngx_queue_sentinel(queue); q = next) {
[63] 
[64]         prev = ngx_queue_prev(q);
[65]         next = ngx_queue_next(q);
[66] 
[67]         ngx_queue_remove(q);
[68] 
[69]         do {
[70]             if (cmp(prev, q) <= 0) {
[71]                 break;
[72]             }
[73] 
[74]             prev = ngx_queue_prev(prev);
[75] 
[76]         } while (prev != ngx_queue_sentinel(queue));
[77] 
[78]         ngx_queue_insert_after(prev, q);
[79]     }
[80] }
