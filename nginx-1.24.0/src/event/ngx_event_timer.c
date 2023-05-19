[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] 
[12] 
[13] ngx_rbtree_t              ngx_event_timer_rbtree;
[14] static ngx_rbtree_node_t  ngx_event_timer_sentinel;
[15] 
[16] /*
[17]  * the event timer rbtree may contain the duplicate keys, however,
[18]  * it should not be a problem, because we use the rbtree to find
[19]  * a minimum timer value only
[20]  */
[21] 
[22] ngx_int_t
[23] ngx_event_timer_init(ngx_log_t *log)
[24] {
[25]     ngx_rbtree_init(&ngx_event_timer_rbtree, &ngx_event_timer_sentinel,
[26]                     ngx_rbtree_insert_timer_value);
[27] 
[28]     return NGX_OK;
[29] }
[30] 
[31] 
[32] ngx_msec_t
[33] ngx_event_find_timer(void)
[34] {
[35]     ngx_msec_int_t      timer;
[36]     ngx_rbtree_node_t  *node, *root, *sentinel;
[37] 
[38]     if (ngx_event_timer_rbtree.root == &ngx_event_timer_sentinel) {
[39]         return NGX_TIMER_INFINITE;
[40]     }
[41] 
[42]     root = ngx_event_timer_rbtree.root;
[43]     sentinel = ngx_event_timer_rbtree.sentinel;
[44] 
[45]     node = ngx_rbtree_min(root, sentinel);
[46] 
[47]     timer = (ngx_msec_int_t) (node->key - ngx_current_msec);
[48] 
[49]     return (ngx_msec_t) (timer > 0 ? timer : 0);
[50] }
[51] 
[52] 
[53] void
[54] ngx_event_expire_timers(void)
[55] {
[56]     ngx_event_t        *ev;
[57]     ngx_rbtree_node_t  *node, *root, *sentinel;
[58] 
[59]     sentinel = ngx_event_timer_rbtree.sentinel;
[60] 
[61]     for ( ;; ) {
[62]         root = ngx_event_timer_rbtree.root;
[63] 
[64]         if (root == sentinel) {
[65]             return;
[66]         }
[67] 
[68]         node = ngx_rbtree_min(root, sentinel);
[69] 
[70]         /* node->key > ngx_current_msec */
[71] 
[72]         if ((ngx_msec_int_t) (node->key - ngx_current_msec) > 0) {
[73]             return;
[74]         }
[75] 
[76]         ev = ngx_rbtree_data(node, ngx_event_t, timer);
[77] 
[78]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[79]                        "event timer del: %d: %M",
[80]                        ngx_event_ident(ev->data), ev->timer.key);
[81] 
[82]         ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);
[83] 
[84] #if (NGX_DEBUG)
[85]         ev->timer.left = NULL;
[86]         ev->timer.right = NULL;
[87]         ev->timer.parent = NULL;
[88] #endif
[89] 
[90]         ev->timer_set = 0;
[91] 
[92]         ev->timedout = 1;
[93] 
[94]         ev->handler(ev);
[95]     }
[96] }
[97] 
[98] 
[99] ngx_int_t
[100] ngx_event_no_timers_left(void)
[101] {
[102]     ngx_event_t        *ev;
[103]     ngx_rbtree_node_t  *node, *root, *sentinel;
[104] 
[105]     sentinel = ngx_event_timer_rbtree.sentinel;
[106]     root = ngx_event_timer_rbtree.root;
[107] 
[108]     if (root == sentinel) {
[109]         return NGX_OK;
[110]     }
[111] 
[112]     for (node = ngx_rbtree_min(root, sentinel);
[113]          node;
[114]          node = ngx_rbtree_next(&ngx_event_timer_rbtree, node))
[115]     {
[116]         ev = ngx_rbtree_data(node, ngx_event_t, timer);
[117] 
[118]         if (!ev->cancelable) {
[119]             return NGX_AGAIN;
[120]         }
[121]     }
[122] 
[123]     /* only cancelable timers left */
[124] 
[125]     return NGX_OK;
[126] }
