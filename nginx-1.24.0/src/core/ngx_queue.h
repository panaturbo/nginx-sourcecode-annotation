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
[12] #ifndef _NGX_QUEUE_H_INCLUDED_
[13] #define _NGX_QUEUE_H_INCLUDED_
[14] 
[15] 
[16] typedef struct ngx_queue_s  ngx_queue_t;
[17] 
[18] struct ngx_queue_s {
[19]     ngx_queue_t  *prev;
[20]     ngx_queue_t  *next;
[21] };
[22] 
[23] 
[24] #define ngx_queue_init(q)                                                     \
[25]     (q)->prev = q;                                                            \
[26]     (q)->next = q
[27] 
[28] 
[29] #define ngx_queue_empty(h)                                                    \
[30]     (h == (h)->prev)
[31] 
[32] 
[33] #define ngx_queue_insert_head(h, x)                                           \
[34]     (x)->next = (h)->next;                                                    \
[35]     (x)->next->prev = x;                                                      \
[36]     (x)->prev = h;                                                            \
[37]     (h)->next = x
[38] 
[39] 
[40] #define ngx_queue_insert_after   ngx_queue_insert_head
[41] 
[42] 
[43] #define ngx_queue_insert_tail(h, x)                                           \
[44]     (x)->prev = (h)->prev;                                                    \
[45]     (x)->prev->next = x;                                                      \
[46]     (x)->next = h;                                                            \
[47]     (h)->prev = x
[48] 
[49] 
[50] #define ngx_queue_head(h)                                                     \
[51]     (h)->next
[52] 
[53] 
[54] #define ngx_queue_last(h)                                                     \
[55]     (h)->prev
[56] 
[57] 
[58] #define ngx_queue_sentinel(h)                                                 \
[59]     (h)
[60] 
[61] 
[62] #define ngx_queue_next(q)                                                     \
[63]     (q)->next
[64] 
[65] 
[66] #define ngx_queue_prev(q)                                                     \
[67]     (q)->prev
[68] 
[69] 
[70] #if (NGX_DEBUG)
[71] 
[72] #define ngx_queue_remove(x)                                                   \
[73]     (x)->next->prev = (x)->prev;                                              \
[74]     (x)->prev->next = (x)->next;                                              \
[75]     (x)->prev = NULL;                                                         \
[76]     (x)->next = NULL
[77] 
[78] #else
[79] 
[80] #define ngx_queue_remove(x)                                                   \
[81]     (x)->next->prev = (x)->prev;                                              \
[82]     (x)->prev->next = (x)->next
[83] 
[84] #endif
[85] 
[86] 
[87] #define ngx_queue_split(h, q, n)                                              \
[88]     (n)->prev = (h)->prev;                                                    \
[89]     (n)->prev->next = n;                                                      \
[90]     (n)->next = q;                                                            \
[91]     (h)->prev = (q)->prev;                                                    \
[92]     (h)->prev->next = h;                                                      \
[93]     (q)->prev = n;
[94] 
[95] 
[96] #define ngx_queue_add(h, n)                                                   \
[97]     (h)->prev->next = (n)->next;                                              \
[98]     (n)->next->prev = (h)->prev;                                              \
[99]     (h)->prev = (n)->prev;                                                    \
[100]     (h)->prev->next = h;
[101] 
[102] 
[103] #define ngx_queue_data(q, type, link)                                         \
[104]     (type *) ((u_char *) q - offsetof(type, link))
[105] 
[106] 
[107] ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);
[108] void ngx_queue_sort(ngx_queue_t *queue,
[109]     ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));
[110] 
[111] 
[112] #endif /* _NGX_QUEUE_H_INCLUDED_ */
