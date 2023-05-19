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
[13] ngx_queue_t  ngx_posted_accept_events;
[14] ngx_queue_t  ngx_posted_next_events;
[15] ngx_queue_t  ngx_posted_events;
[16] 
[17] 
[18] void
[19] ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
[20] {
[21]     ngx_queue_t  *q;
[22]     ngx_event_t  *ev;
[23] 
[24]     while (!ngx_queue_empty(posted)) {
[25] 
[26]         q = ngx_queue_head(posted);
[27]         ev = ngx_queue_data(q, ngx_event_t, queue);
[28] 
[29]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[30]                       "posted event %p", ev);
[31] 
[32]         ngx_delete_posted_event(ev);
[33] 
[34]         ev->handler(ev);
[35]     }
[36] }
[37] 
[38] 
[39] void
[40] ngx_event_move_posted_next(ngx_cycle_t *cycle)
[41] {
[42]     ngx_queue_t  *q;
[43]     ngx_event_t  *ev;
[44] 
[45]     for (q = ngx_queue_head(&ngx_posted_next_events);
[46]          q != ngx_queue_sentinel(&ngx_posted_next_events);
[47]          q = ngx_queue_next(q))
[48]     {
[49]         ev = ngx_queue_data(q, ngx_event_t, queue);
[50] 
[51]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[52]                       "posted next event %p", ev);
[53] 
[54]         ev->ready = 1;
[55]         ev->available = -1;
[56]     }
[57] 
[58]     ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
[59]     ngx_queue_init(&ngx_posted_next_events);
[60] }
