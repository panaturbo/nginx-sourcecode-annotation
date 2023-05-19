[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_EVENT_POSTED_H_INCLUDED_
[9] #define _NGX_EVENT_POSTED_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] 
[16] 
[17] #define ngx_post_event(ev, q)                                                 \
[18]                                                                               \
[19]     if (!(ev)->posted) {                                                      \
[20]         (ev)->posted = 1;                                                     \
[21]         ngx_queue_insert_tail(q, &(ev)->queue);                               \
[22]                                                                               \
[23]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
[24]                                                                               \
[25]     } else  {                                                                 \
[26]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                      \
[27]                        "update posted event %p", ev);                         \
[28]     }
[29] 
[30] 
[31] #define ngx_delete_posted_event(ev)                                           \
[32]                                                                               \
[33]     (ev)->posted = 0;                                                         \
[34]     ngx_queue_remove(&(ev)->queue);                                           \
[35]                                                                               \
[36]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                          \
[37]                    "delete posted event %p", ev);
[38] 
[39] 
[40] 
[41] void ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted);
[42] void ngx_event_move_posted_next(ngx_cycle_t *cycle);
[43] 
[44] 
[45] extern ngx_queue_t  ngx_posted_accept_events;
[46] extern ngx_queue_t  ngx_posted_next_events;
[47] extern ngx_queue_t  ngx_posted_events;
[48] 
[49] 
[50] #endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
