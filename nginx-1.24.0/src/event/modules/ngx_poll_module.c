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
[13] static ngx_int_t ngx_poll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[14] static void ngx_poll_done(ngx_cycle_t *cycle);
[15] static ngx_int_t ngx_poll_add_event(ngx_event_t *ev, ngx_int_t event,
[16]     ngx_uint_t flags);
[17] static ngx_int_t ngx_poll_del_event(ngx_event_t *ev, ngx_int_t event,
[18]     ngx_uint_t flags);
[19] static ngx_int_t ngx_poll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[20]     ngx_uint_t flags);
[21] static char *ngx_poll_init_conf(ngx_cycle_t *cycle, void *conf);
[22] 
[23] 
[24] static struct pollfd  *event_list;
[25] static ngx_uint_t      nevents;
[26] 
[27] 
[28] static ngx_str_t           poll_name = ngx_string("poll");
[29] 
[30] static ngx_event_module_t  ngx_poll_module_ctx = {
[31]     &poll_name,
[32]     NULL,                                  /* create configuration */
[33]     ngx_poll_init_conf,                    /* init configuration */
[34] 
[35]     {
[36]         ngx_poll_add_event,                /* add an event */
[37]         ngx_poll_del_event,                /* delete an event */
[38]         ngx_poll_add_event,                /* enable an event */
[39]         ngx_poll_del_event,                /* disable an event */
[40]         NULL,                              /* add an connection */
[41]         NULL,                              /* delete an connection */
[42]         NULL,                              /* trigger a notify */
[43]         ngx_poll_process_events,           /* process the events */
[44]         ngx_poll_init,                     /* init the events */
[45]         ngx_poll_done                      /* done the events */
[46]     }
[47] 
[48] };
[49] 
[50] ngx_module_t  ngx_poll_module = {
[51]     NGX_MODULE_V1,
[52]     &ngx_poll_module_ctx,                  /* module context */
[53]     NULL,                                  /* module directives */
[54]     NGX_EVENT_MODULE,                      /* module type */
[55]     NULL,                                  /* init master */
[56]     NULL,                                  /* init module */
[57]     NULL,                                  /* init process */
[58]     NULL,                                  /* init thread */
[59]     NULL,                                  /* exit thread */
[60]     NULL,                                  /* exit process */
[61]     NULL,                                  /* exit master */
[62]     NGX_MODULE_V1_PADDING
[63] };
[64] 
[65] 
[66] 
[67] static ngx_int_t
[68] ngx_poll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[69] {
[70]     struct pollfd   *list;
[71] 
[72]     if (event_list == NULL) {
[73]         nevents = 0;
[74]     }
[75] 
[76]     if (ngx_process >= NGX_PROCESS_WORKER
[77]         || cycle->old_cycle == NULL
[78]         || cycle->old_cycle->connection_n < cycle->connection_n)
[79]     {
[80]         list = ngx_alloc(sizeof(struct pollfd) * cycle->connection_n,
[81]                          cycle->log);
[82]         if (list == NULL) {
[83]             return NGX_ERROR;
[84]         }
[85] 
[86]         if (event_list) {
[87]             ngx_memcpy(list, event_list, sizeof(struct pollfd) * nevents);
[88]             ngx_free(event_list);
[89]         }
[90] 
[91]         event_list = list;
[92]     }
[93] 
[94]     ngx_io = ngx_os_io;
[95] 
[96]     ngx_event_actions = ngx_poll_module_ctx.actions;
[97] 
[98]     ngx_event_flags = NGX_USE_LEVEL_EVENT|NGX_USE_FD_EVENT;
[99] 
[100]     return NGX_OK;
[101] }
[102] 
[103] 
[104] static void
[105] ngx_poll_done(ngx_cycle_t *cycle)
[106] {
[107]     ngx_free(event_list);
[108] 
[109]     event_list = NULL;
[110] }
[111] 
[112] 
[113] static ngx_int_t
[114] ngx_poll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[115] {
[116]     ngx_event_t       *e;
[117]     ngx_connection_t  *c;
[118] 
[119]     c = ev->data;
[120] 
[121]     ev->active = 1;
[122] 
[123]     if (ev->index != NGX_INVALID_INDEX) {
[124]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[125]                       "poll event fd:%d ev:%i is already set", c->fd, event);
[126]         return NGX_OK;
[127]     }
[128] 
[129]     if (event == NGX_READ_EVENT) {
[130]         e = c->write;
[131] #if (NGX_READ_EVENT != POLLIN)
[132]         event = POLLIN;
[133] #endif
[134] 
[135]     } else {
[136]         e = c->read;
[137] #if (NGX_WRITE_EVENT != POLLOUT)
[138]         event = POLLOUT;
[139] #endif
[140]     }
[141] 
[142]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[143]                    "poll add event: fd:%d ev:%i", c->fd, event);
[144] 
[145]     if (e == NULL || e->index == NGX_INVALID_INDEX) {
[146]         event_list[nevents].fd = c->fd;
[147]         event_list[nevents].events = (short) event;
[148]         event_list[nevents].revents = 0;
[149] 
[150]         ev->index = nevents;
[151]         nevents++;
[152] 
[153]     } else {
[154]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[155]                        "poll add index: %i", e->index);
[156] 
[157]         event_list[e->index].events |= (short) event;
[158]         ev->index = e->index;
[159]     }
[160] 
[161]     return NGX_OK;
[162] }
[163] 
[164] 
[165] static ngx_int_t
[166] ngx_poll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[167] {
[168]     ngx_event_t       *e;
[169]     ngx_connection_t  *c;
[170] 
[171]     c = ev->data;
[172] 
[173]     ev->active = 0;
[174] 
[175]     if (ev->index == NGX_INVALID_INDEX) {
[176]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[177]                       "poll event fd:%d ev:%i is already deleted",
[178]                       c->fd, event);
[179]         return NGX_OK;
[180]     }
[181] 
[182]     if (event == NGX_READ_EVENT) {
[183]         e = c->write;
[184] #if (NGX_READ_EVENT != POLLIN)
[185]         event = POLLIN;
[186] #endif
[187] 
[188]     } else {
[189]         e = c->read;
[190] #if (NGX_WRITE_EVENT != POLLOUT)
[191]         event = POLLOUT;
[192] #endif
[193]     }
[194] 
[195]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[196]                    "poll del event: fd:%d ev:%i", c->fd, event);
[197] 
[198]     if (e == NULL || e->index == NGX_INVALID_INDEX) {
[199]         nevents--;
[200] 
[201]         if (ev->index < nevents) {
[202] 
[203]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[204]                            "index: copy event %ui to %i", nevents, ev->index);
[205] 
[206]             event_list[ev->index] = event_list[nevents];
[207] 
[208]             c = ngx_cycle->files[event_list[nevents].fd];
[209] 
[210]             if (c->fd == -1) {
[211]                 ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[212]                               "unexpected last event");
[213] 
[214]             } else {
[215]                 if (c->read->index == nevents) {
[216]                     c->read->index = ev->index;
[217]                 }
[218] 
[219]                 if (c->write->index == nevents) {
[220]                     c->write->index = ev->index;
[221]                 }
[222]             }
[223]         }
[224] 
[225]     } else {
[226]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[227]                        "poll del index: %i", e->index);
[228] 
[229]         event_list[e->index].events &= (short) ~event;
[230]     }
[231] 
[232]     ev->index = NGX_INVALID_INDEX;
[233] 
[234]     return NGX_OK;
[235] }
[236] 
[237] 
[238] static ngx_int_t
[239] ngx_poll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
[240] {
[241]     int                 ready, revents;
[242]     ngx_err_t           err;
[243]     ngx_uint_t          i, found, level;
[244]     ngx_event_t        *ev;
[245]     ngx_queue_t        *queue;
[246]     ngx_connection_t   *c;
[247] 
[248]     /* NGX_TIMER_INFINITE == INFTIM */
[249] 
[250] #if (NGX_DEBUG0)
[251]     if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
[252]         for (i = 0; i < nevents; i++) {
[253]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[254]                            "poll: %ui: fd:%d ev:%04Xd",
[255]                            i, event_list[i].fd, event_list[i].events);
[256]         }
[257]     }
[258] #endif
[259] 
[260]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "poll timer: %M", timer);
[261] 
[262]     ready = poll(event_list, (u_int) nevents, (int) timer);
[263] 
[264]     err = (ready == -1) ? ngx_errno : 0;
[265] 
[266]     if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
[267]         ngx_time_update();
[268]     }
[269] 
[270]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[271]                    "poll ready %d of %ui", ready, nevents);
[272] 
[273]     if (err) {
[274]         if (err == NGX_EINTR) {
[275] 
[276]             if (ngx_event_timer_alarm) {
[277]                 ngx_event_timer_alarm = 0;
[278]                 return NGX_OK;
[279]             }
[280] 
[281]             level = NGX_LOG_INFO;
[282] 
[283]         } else {
[284]             level = NGX_LOG_ALERT;
[285]         }
[286] 
[287]         ngx_log_error(level, cycle->log, err, "poll() failed");
[288]         return NGX_ERROR;
[289]     }
[290] 
[291]     if (ready == 0) {
[292]         if (timer != NGX_TIMER_INFINITE) {
[293]             return NGX_OK;
[294]         }
[295] 
[296]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[297]                       "poll() returned no events without timeout");
[298]         return NGX_ERROR;
[299]     }
[300] 
[301]     for (i = 0; i < nevents && ready; i++) {
[302] 
[303]         revents = event_list[i].revents;
[304] 
[305] #if 1
[306]         ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[307]                        "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
[308]                        i, event_list[i].fd, event_list[i].events, revents);
[309] #else
[310]         if (revents) {
[311]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[312]                            "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
[313]                            i, event_list[i].fd, event_list[i].events, revents);
[314]         }
[315] #endif
[316] 
[317]         if (revents & POLLNVAL) {
[318]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[319]                           "poll() error fd:%d ev:%04Xd rev:%04Xd",
[320]                           event_list[i].fd, event_list[i].events, revents);
[321]         }
[322] 
[323]         if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
[324]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[325]                           "strange poll() events fd:%d ev:%04Xd rev:%04Xd",
[326]                           event_list[i].fd, event_list[i].events, revents);
[327]         }
[328] 
[329]         if (event_list[i].fd == -1) {
[330]             /*
[331]              * the disabled event, a workaround for our possible bug,
[332]              * see the comment below
[333]              */
[334]             continue;
[335]         }
[336] 
[337]         c = ngx_cycle->files[event_list[i].fd];
[338] 
[339]         if (c->fd == -1) {
[340]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "unexpected event");
[341] 
[342]             /*
[343]              * it is certainly our fault and it should be investigated,
[344]              * in the meantime we disable this event to avoid a CPU spinning
[345]              */
[346] 
[347]             if (i == nevents - 1) {
[348]                 nevents--;
[349]             } else {
[350]                 event_list[i].fd = -1;
[351]             }
[352] 
[353]             continue;
[354]         }
[355] 
[356]         if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
[357] 
[358]             /*
[359]              * if the error events were returned, add POLLIN and POLLOUT
[360]              * to handle the events at least in one active handler
[361]              */
[362] 
[363]             revents |= POLLIN|POLLOUT;
[364]         }
[365] 
[366]         found = 0;
[367] 
[368]         if ((revents & POLLIN) && c->read->active) {
[369]             found = 1;
[370] 
[371]             ev = c->read;
[372]             ev->ready = 1;
[373]             ev->available = -1;
[374] 
[375]             queue = ev->accept ? &ngx_posted_accept_events
[376]                                : &ngx_posted_events;
[377] 
[378]             ngx_post_event(ev, queue);
[379]         }
[380] 
[381]         if ((revents & POLLOUT) && c->write->active) {
[382]             found = 1;
[383] 
[384]             ev = c->write;
[385]             ev->ready = 1;
[386] 
[387]             ngx_post_event(ev, &ngx_posted_events);
[388]         }
[389] 
[390]         if (found) {
[391]             ready--;
[392]             continue;
[393]         }
[394]     }
[395] 
[396]     if (ready != 0) {
[397]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "poll ready != events");
[398]     }
[399] 
[400]     return NGX_OK;
[401] }
[402] 
[403] 
[404] static char *
[405] ngx_poll_init_conf(ngx_cycle_t *cycle, void *conf)
[406] {
[407]     ngx_event_conf_t  *ecf;
[408] 
[409]     ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
[410] 
[411]     if (ecf->use != ngx_poll_module.ctx_index) {
[412]         return NGX_CONF_OK;
[413]     }
[414] 
[415]     return NGX_CONF_OK;
[416] }
