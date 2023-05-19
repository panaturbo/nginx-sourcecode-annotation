[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_EVENT_TIMER_H_INCLUDED_
[9] #define _NGX_EVENT_TIMER_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] 
[16] 
[17] #define NGX_TIMER_INFINITE  (ngx_msec_t) -1
[18] 
[19] #define NGX_TIMER_LAZY_DELAY  300
[20] 
[21] 
[22] ngx_int_t ngx_event_timer_init(ngx_log_t *log);
[23] ngx_msec_t ngx_event_find_timer(void);
[24] void ngx_event_expire_timers(void);
[25] ngx_int_t ngx_event_no_timers_left(void);
[26] 
[27] 
[28] extern ngx_rbtree_t  ngx_event_timer_rbtree;
[29] 
[30] 
[31] static ngx_inline void
[32] ngx_event_del_timer(ngx_event_t *ev)
[33] {
[34]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[35]                    "event timer del: %d: %M",
[36]                     ngx_event_ident(ev->data), ev->timer.key);
[37] 
[38]     ngx_rbtree_delete(&ngx_event_timer_rbtree, &ev->timer);
[39] 
[40] #if (NGX_DEBUG)
[41]     ev->timer.left = NULL;
[42]     ev->timer.right = NULL;
[43]     ev->timer.parent = NULL;
[44] #endif
[45] 
[46]     ev->timer_set = 0;
[47] }
[48] 
[49] 
[50] static ngx_inline void
[51] ngx_event_add_timer(ngx_event_t *ev, ngx_msec_t timer)
[52] {
[53]     ngx_msec_t      key;
[54]     ngx_msec_int_t  diff;
[55] 
[56]     key = ngx_current_msec + timer;
[57] 
[58]     if (ev->timer_set) {
[59] 
[60]         /*
[61]          * Use a previous timer value if difference between it and a new
[62]          * value is less than NGX_TIMER_LAZY_DELAY milliseconds: this allows
[63]          * to minimize the rbtree operations for fast connections.
[64]          */
[65] 
[66]         diff = (ngx_msec_int_t) (key - ev->timer.key);
[67] 
[68]         if (ngx_abs(diff) < NGX_TIMER_LAZY_DELAY) {
[69]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[70]                            "event timer: %d, old: %M, new: %M",
[71]                             ngx_event_ident(ev->data), ev->timer.key, key);
[72]             return;
[73]         }
[74] 
[75]         ngx_del_timer(ev);
[76]     }
[77] 
[78]     ev->timer.key = key;
[79] 
[80]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[81]                    "event timer add: %d: %M:%M",
[82]                     ngx_event_ident(ev->data), timer, ev->timer.key);
[83] 
[84]     ngx_rbtree_insert(&ngx_event_timer_rbtree, &ev->timer);
[85] 
[86]     ev->timer_set = 1;
[87] }
[88] 
[89] 
[90] #endif /* _NGX_EVENT_TIMER_H_INCLUDED_ */
