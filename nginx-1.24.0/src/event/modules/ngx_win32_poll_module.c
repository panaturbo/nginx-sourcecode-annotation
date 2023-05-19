[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Maxim Dounin
[5]  * Copyright (C) Nginx, Inc.
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] #include <ngx_event.h>
[12] 
[13] 
[14] static ngx_int_t ngx_poll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[15] static void ngx_poll_done(ngx_cycle_t *cycle);
[16] static ngx_int_t ngx_poll_add_event(ngx_event_t *ev, ngx_int_t event,
[17]     ngx_uint_t flags);
[18] static ngx_int_t ngx_poll_del_event(ngx_event_t *ev, ngx_int_t event,
[19]     ngx_uint_t flags);
[20] static ngx_int_t ngx_poll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[21]     ngx_uint_t flags);
[22] static char *ngx_poll_init_conf(ngx_cycle_t *cycle, void *conf);
[23] 
[24] 
[25] static struct pollfd      *event_list;
[26] static ngx_connection_t  **event_index;
[27] static ngx_uint_t          nevents;
[28] 
[29] 
[30] static ngx_str_t           poll_name = ngx_string("poll");
[31] 
[32] static ngx_event_module_t  ngx_poll_module_ctx = {
[33]     &poll_name,
[34]     NULL,                                  /* create configuration */
[35]     ngx_poll_init_conf,                    /* init configuration */
[36] 
[37]     {
[38]         ngx_poll_add_event,                /* add an event */
[39]         ngx_poll_del_event,                /* delete an event */
[40]         ngx_poll_add_event,                /* enable an event */
[41]         ngx_poll_del_event,                /* disable an event */
[42]         NULL,                              /* add an connection */
[43]         NULL,                              /* delete an connection */
[44]         NULL,                              /* trigger a notify */
[45]         ngx_poll_process_events,           /* process the events */
[46]         ngx_poll_init,                     /* init the events */
[47]         ngx_poll_done                      /* done the events */
[48]     }
[49] 
[50] };
[51] 
[52] ngx_module_t  ngx_poll_module = {
[53]     NGX_MODULE_V1,
[54]     &ngx_poll_module_ctx,                  /* module context */
[55]     NULL,                                  /* module directives */
[56]     NGX_EVENT_MODULE,                      /* module type */
[57]     NULL,                                  /* init master */
[58]     NULL,                                  /* init module */
[59]     NULL,                                  /* init process */
[60]     NULL,                                  /* init thread */
[61]     NULL,                                  /* exit thread */
[62]     NULL,                                  /* exit process */
[63]     NULL,                                  /* exit master */
[64]     NGX_MODULE_V1_PADDING
[65] };
[66] 
[67] 
[68] 
[69] static ngx_int_t
[70] ngx_poll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[71] {
[72]     struct pollfd      *list;
[73]     ngx_connection_t  **index;
[74] 
[75]     if (event_list == NULL) {
[76]         nevents = 0;
[77]     }
[78] 
[79]     if (ngx_process >= NGX_PROCESS_WORKER
[80]         || cycle->old_cycle == NULL
[81]         || cycle->old_cycle->connection_n < cycle->connection_n)
[82]     {
[83]         list = ngx_alloc(sizeof(struct pollfd) * cycle->connection_n,
[84]                          cycle->log);
[85]         if (list == NULL) {
[86]             return NGX_ERROR;
[87]         }
[88] 
[89]         if (event_list) {
[90]             ngx_memcpy(list, event_list, sizeof(struct pollfd) * nevents);
[91]             ngx_free(event_list);
[92]         }
[93] 
[94]         event_list = list;
[95] 
[96]         index = ngx_alloc(sizeof(ngx_connection_t *) * cycle->connection_n,
[97]                           cycle->log);
[98]         if (index == NULL) {
[99]             return NGX_ERROR;
[100]         }
[101] 
[102]         if (event_index) {
[103]             ngx_memcpy(index, event_index,
[104]                        sizeof(ngx_connection_t *) * nevents);
[105]             ngx_free(event_index);
[106]         }
[107] 
[108]         event_index = index;
[109]     }
[110] 
[111]     ngx_io = ngx_os_io;
[112] 
[113]     ngx_event_actions = ngx_poll_module_ctx.actions;
[114] 
[115]     ngx_event_flags = NGX_USE_LEVEL_EVENT;
[116] 
[117]     return NGX_OK;
[118] }
[119] 
[120] 
[121] static void
[122] ngx_poll_done(ngx_cycle_t *cycle)
[123] {
[124]     ngx_free(event_list);
[125]     ngx_free(event_index);
[126] 
[127]     event_list = NULL;
[128]     event_index = NULL;
[129] }
[130] 
[131] 
[132] static ngx_int_t
[133] ngx_poll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[134] {
[135]     ngx_event_t       *e;
[136]     ngx_connection_t  *c;
[137] 
[138]     c = ev->data;
[139] 
[140]     ev->active = 1;
[141] 
[142]     if (ev->index != NGX_INVALID_INDEX) {
[143]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[144]                       "poll event fd:%d ev:%i is already set", c->fd, event);
[145]         return NGX_OK;
[146]     }
[147] 
[148]     if (event == NGX_READ_EVENT) {
[149]         e = c->write;
[150] #if (NGX_READ_EVENT != POLLIN)
[151]         event = POLLIN;
[152] #endif
[153] 
[154]     } else {
[155]         e = c->read;
[156] #if (NGX_WRITE_EVENT != POLLOUT)
[157]         event = POLLOUT;
[158] #endif
[159]     }
[160] 
[161]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[162]                    "poll add event: fd:%d ev:%i", c->fd, event);
[163] 
[164]     if (e == NULL || e->index == NGX_INVALID_INDEX) {
[165] 
[166]         event_list[nevents].fd = c->fd;
[167]         event_list[nevents].events = (short) event;
[168]         event_list[nevents].revents = 0;
[169] 
[170]         event_index[nevents] = c;
[171] 
[172]         ev->index = nevents;
[173]         nevents++;
[174] 
[175]     } else {
[176]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[177]                        "poll add index: %i", e->index);
[178] 
[179]         event_list[e->index].events |= (short) event;
[180]         ev->index = e->index;
[181]     }
[182] 
[183]     return NGX_OK;
[184] }
[185] 
[186] 
[187] static ngx_int_t
[188] ngx_poll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[189] {
[190]     ngx_event_t       *e;
[191]     ngx_connection_t  *c;
[192] 
[193]     c = ev->data;
[194] 
[195]     ev->active = 0;
[196] 
[197]     if (ev->index == NGX_INVALID_INDEX) {
[198]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[199]                       "poll event fd:%d ev:%i is already deleted",
[200]                       c->fd, event);
[201]         return NGX_OK;
[202]     }
[203] 
[204]     if (event == NGX_READ_EVENT) {
[205]         e = c->write;
[206] #if (NGX_READ_EVENT != POLLIN)
[207]         event = POLLIN;
[208] #endif
[209] 
[210]     } else {
[211]         e = c->read;
[212] #if (NGX_WRITE_EVENT != POLLOUT)
[213]         event = POLLOUT;
[214] #endif
[215]     }
[216] 
[217]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[218]                    "poll del event: fd:%d ev:%i", c->fd, event);
[219] 
[220]     if (e == NULL || e->index == NGX_INVALID_INDEX) {
[221]         nevents--;
[222] 
[223]         if (ev->index < nevents) {
[224] 
[225]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[226]                            "index: copy event %ui to %i", nevents, ev->index);
[227] 
[228]             event_list[ev->index] = event_list[nevents];
[229]             event_index[ev->index] = event_index[nevents];
[230] 
[231]             c = event_index[ev->index];
[232] 
[233]             if (c->fd == (ngx_socket_t) -1) {
[234]                 ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[235]                               "unexpected last event");
[236] 
[237]             } else {
[238]                 if (c->read->index == nevents) {
[239]                     c->read->index = ev->index;
[240]                 }
[241] 
[242]                 if (c->write->index == nevents) {
[243]                     c->write->index = ev->index;
[244]                 }
[245]             }
[246]         }
[247] 
[248]     } else {
[249]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[250]                        "poll del index: %i", e->index);
[251] 
[252]         event_list[e->index].events &= (short) ~event;
[253]     }
[254] 
[255]     ev->index = NGX_INVALID_INDEX;
[256] 
[257]     return NGX_OK;
[258] }
[259] 
[260] 
[261] static ngx_int_t
[262] ngx_poll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
[263] {
[264]     int                 ready, revents;
[265]     ngx_err_t           err;
[266]     ngx_uint_t          i, found;
[267]     ngx_event_t        *ev;
[268]     ngx_queue_t        *queue;
[269]     ngx_connection_t   *c;
[270] 
[271]     /* NGX_TIMER_INFINITE == INFTIM */
[272] 
[273] #if (NGX_DEBUG0)
[274]     if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
[275]         for (i = 0; i < nevents; i++) {
[276]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[277]                            "poll: %ui: fd:%d ev:%04Xd",
[278]                            i, event_list[i].fd, event_list[i].events);
[279]         }
[280]     }
[281] #endif
[282] 
[283]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "poll timer: %M", timer);
[284] 
[285]     ready = WSAPoll(event_list, (u_int) nevents, (int) timer);
[286] 
[287]     err = (ready == -1) ? ngx_errno : 0;
[288] 
[289]     if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
[290]         ngx_time_update();
[291]     }
[292] 
[293]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[294]                    "poll ready %d of %ui", ready, nevents);
[295] 
[296]     if (err) {
[297]         ngx_log_error(NGX_LOG_ALERT, cycle->log, err, "WSAPoll() failed");
[298]         return NGX_ERROR;
[299]     }
[300] 
[301]     if (ready == 0) {
[302]         if (timer != NGX_TIMER_INFINITE) {
[303]             return NGX_OK;
[304]         }
[305] 
[306]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[307]                       "WSAPoll() returned no events without timeout");
[308]         return NGX_ERROR;
[309]     }
[310] 
[311]     for (i = 0; i < nevents && ready; i++) {
[312] 
[313]         revents = event_list[i].revents;
[314] 
[315] #if 1
[316]         ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[317]                        "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
[318]                        i, event_list[i].fd, event_list[i].events, revents);
[319] #else
[320]         if (revents) {
[321]             ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[322]                            "poll: %ui: fd:%d ev:%04Xd rev:%04Xd",
[323]                            i, event_list[i].fd, event_list[i].events, revents);
[324]         }
[325] #endif
[326] 
[327]         if (revents & POLLNVAL) {
[328]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[329]                           "poll() error fd:%d ev:%04Xd rev:%04Xd",
[330]                           event_list[i].fd, event_list[i].events, revents);
[331]         }
[332] 
[333]         if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
[334]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[335]                           "strange poll() events fd:%d ev:%04Xd rev:%04Xd",
[336]                           event_list[i].fd, event_list[i].events, revents);
[337]         }
[338] 
[339]         if (event_list[i].fd == (ngx_socket_t) -1) {
[340]             /*
[341]              * the disabled event, a workaround for our possible bug,
[342]              * see the comment below
[343]              */
[344]             continue;
[345]         }
[346] 
[347]         c = event_index[i];
[348] 
[349]         if (c->fd == (ngx_socket_t) -1) {
[350]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "unexpected event");
[351] 
[352]             /*
[353]              * it is certainly our fault and it should be investigated,
[354]              * in the meantime we disable this event to avoid a CPU spinning
[355]              */
[356] 
[357]             if (i == nevents - 1) {
[358]                 nevents--;
[359]             } else {
[360]                 event_list[i].fd = (ngx_socket_t) -1;
[361]             }
[362] 
[363]             continue;
[364]         }
[365] 
[366]         if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
[367] 
[368]             /*
[369]              * if the error events were returned, add POLLIN and POLLOUT
[370]              * to handle the events at least in one active handler
[371]              */
[372] 
[373]             revents |= POLLIN|POLLOUT;
[374]         }
[375] 
[376]         found = 0;
[377] 
[378]         if ((revents & POLLIN) && c->read->active) {
[379]             found = 1;
[380] 
[381]             ev = c->read;
[382]             ev->ready = 1;
[383]             ev->available = -1;
[384] 
[385]             queue = ev->accept ? &ngx_posted_accept_events
[386]                                : &ngx_posted_events;
[387] 
[388]             ngx_post_event(ev, queue);
[389]         }
[390] 
[391]         if ((revents & POLLOUT) && c->write->active) {
[392]             found = 1;
[393] 
[394]             ev = c->write;
[395]             ev->ready = 1;
[396] 
[397]             ngx_post_event(ev, &ngx_posted_events);
[398]         }
[399] 
[400]         if (found) {
[401]             ready--;
[402]             continue;
[403]         }
[404]     }
[405] 
[406]     if (ready != 0) {
[407]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "poll ready != events");
[408]     }
[409] 
[410]     return NGX_OK;
[411] }
[412] 
[413] 
[414] static char *
[415] ngx_poll_init_conf(ngx_cycle_t *cycle, void *conf)
[416] {
[417]     ngx_event_conf_t  *ecf;
[418] 
[419]     ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
[420] 
[421]     if (ecf->use != ngx_poll_module.ctx_index) {
[422]         return NGX_CONF_OK;
[423]     }
[424] 
[425] #if (NGX_LOAD_WSAPOLL)
[426] 
[427]     if (!ngx_have_wsapoll) {
[428]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[429]                       "poll is not available on this platform");
[430]         return NGX_CONF_ERROR;
[431]     }
[432] 
[433] #endif
[434] 
[435]     return NGX_CONF_OK;
[436] }
