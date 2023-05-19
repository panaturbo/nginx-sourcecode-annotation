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
[13] typedef struct {
[14]     ngx_uint_t  changes;
[15]     ngx_uint_t  events;
[16] } ngx_kqueue_conf_t;
[17] 
[18] 
[19] static ngx_int_t ngx_kqueue_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[20] #ifdef EVFILT_USER
[21] static ngx_int_t ngx_kqueue_notify_init(ngx_log_t *log);
[22] #endif
[23] static void ngx_kqueue_done(ngx_cycle_t *cycle);
[24] static ngx_int_t ngx_kqueue_add_event(ngx_event_t *ev, ngx_int_t event,
[25]     ngx_uint_t flags);
[26] static ngx_int_t ngx_kqueue_del_event(ngx_event_t *ev, ngx_int_t event,
[27]     ngx_uint_t flags);
[28] static ngx_int_t ngx_kqueue_set_event(ngx_event_t *ev, ngx_int_t filter,
[29]     ngx_uint_t flags);
[30] #ifdef EVFILT_USER
[31] static ngx_int_t ngx_kqueue_notify(ngx_event_handler_pt handler);
[32] #endif
[33] static ngx_int_t ngx_kqueue_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[34]     ngx_uint_t flags);
[35] static ngx_inline void ngx_kqueue_dump_event(ngx_log_t *log,
[36]     struct kevent *kev);
[37] 
[38] static void *ngx_kqueue_create_conf(ngx_cycle_t *cycle);
[39] static char *ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf);
[40] 
[41] 
[42] int                    ngx_kqueue = -1;
[43] 
[44] static struct kevent  *change_list;
[45] static struct kevent  *event_list;
[46] static ngx_uint_t      max_changes, nchanges, nevents;
[47] 
[48] #ifdef EVFILT_USER
[49] static ngx_event_t     notify_event;
[50] static struct kevent   notify_kev;
[51] #endif
[52] 
[53] 
[54] static ngx_str_t      kqueue_name = ngx_string("kqueue");
[55] 
[56] static ngx_command_t  ngx_kqueue_commands[] = {
[57] 
[58]     { ngx_string("kqueue_changes"),
[59]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[60]       ngx_conf_set_num_slot,
[61]       0,
[62]       offsetof(ngx_kqueue_conf_t, changes),
[63]       NULL },
[64] 
[65]     { ngx_string("kqueue_events"),
[66]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[67]       ngx_conf_set_num_slot,
[68]       0,
[69]       offsetof(ngx_kqueue_conf_t, events),
[70]       NULL },
[71] 
[72]       ngx_null_command
[73] };
[74] 
[75] 
[76] static ngx_event_module_t  ngx_kqueue_module_ctx = {
[77]     &kqueue_name,
[78]     ngx_kqueue_create_conf,                /* create configuration */
[79]     ngx_kqueue_init_conf,                  /* init configuration */
[80] 
[81]     {
[82]         ngx_kqueue_add_event,              /* add an event */
[83]         ngx_kqueue_del_event,              /* delete an event */
[84]         ngx_kqueue_add_event,              /* enable an event */
[85]         ngx_kqueue_del_event,              /* disable an event */
[86]         NULL,                              /* add an connection */
[87]         NULL,                              /* delete an connection */
[88] #ifdef EVFILT_USER
[89]         ngx_kqueue_notify,                 /* trigger a notify */
[90] #else
[91]         NULL,                              /* trigger a notify */
[92] #endif
[93]         ngx_kqueue_process_events,         /* process the events */
[94]         ngx_kqueue_init,                   /* init the events */
[95]         ngx_kqueue_done                    /* done the events */
[96]     }
[97] 
[98] };
[99] 
[100] ngx_module_t  ngx_kqueue_module = {
[101]     NGX_MODULE_V1,
[102]     &ngx_kqueue_module_ctx,                /* module context */
[103]     ngx_kqueue_commands,                   /* module directives */
[104]     NGX_EVENT_MODULE,                      /* module type */
[105]     NULL,                                  /* init master */
[106]     NULL,                                  /* init module */
[107]     NULL,                                  /* init process */
[108]     NULL,                                  /* init thread */
[109]     NULL,                                  /* exit thread */
[110]     NULL,                                  /* exit process */
[111]     NULL,                                  /* exit master */
[112]     NGX_MODULE_V1_PADDING
[113] };
[114] 
[115] 
[116] static ngx_int_t
[117] ngx_kqueue_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[118] {
[119]     ngx_kqueue_conf_t  *kcf;
[120]     struct timespec     ts;
[121] #if (NGX_HAVE_TIMER_EVENT)
[122]     struct kevent       kev;
[123] #endif
[124] 
[125]     kcf = ngx_event_get_conf(cycle->conf_ctx, ngx_kqueue_module);
[126] 
[127]     if (ngx_kqueue == -1) {
[128]         ngx_kqueue = kqueue();
[129] 
[130]         if (ngx_kqueue == -1) {
[131]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[132]                           "kqueue() failed");
[133]             return NGX_ERROR;
[134]         }
[135] 
[136] #ifdef EVFILT_USER
[137]         if (ngx_kqueue_notify_init(cycle->log) != NGX_OK) {
[138]             return NGX_ERROR;
[139]         }
[140] #endif
[141]     }
[142] 
[143]     if (max_changes < kcf->changes) {
[144]         if (nchanges) {
[145]             ts.tv_sec = 0;
[146]             ts.tv_nsec = 0;
[147] 
[148]             if (kevent(ngx_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
[149]                 == -1)
[150]             {
[151]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[152]                               "kevent() failed");
[153]                 return NGX_ERROR;
[154]             }
[155]             nchanges = 0;
[156]         }
[157] 
[158]         if (change_list) {
[159]             ngx_free(change_list);
[160]         }
[161] 
[162]         change_list = ngx_alloc(kcf->changes * sizeof(struct kevent),
[163]                                 cycle->log);
[164]         if (change_list == NULL) {
[165]             return NGX_ERROR;
[166]         }
[167]     }
[168] 
[169]     max_changes = kcf->changes;
[170] 
[171]     if (nevents < kcf->events) {
[172]         if (event_list) {
[173]             ngx_free(event_list);
[174]         }
[175] 
[176]         event_list = ngx_alloc(kcf->events * sizeof(struct kevent), cycle->log);
[177]         if (event_list == NULL) {
[178]             return NGX_ERROR;
[179]         }
[180]     }
[181] 
[182]     ngx_event_flags = NGX_USE_ONESHOT_EVENT
[183]                       |NGX_USE_KQUEUE_EVENT
[184]                       |NGX_USE_VNODE_EVENT;
[185] 
[186] #if (NGX_HAVE_TIMER_EVENT)
[187] 
[188]     if (timer) {
[189]         kev.ident = 0;
[190]         kev.filter = EVFILT_TIMER;
[191]         kev.flags = EV_ADD|EV_ENABLE;
[192]         kev.fflags = 0;
[193]         kev.data = timer;
[194]         kev.udata = 0;
[195] 
[196]         ts.tv_sec = 0;
[197]         ts.tv_nsec = 0;
[198] 
[199]         if (kevent(ngx_kqueue, &kev, 1, NULL, 0, &ts) == -1) {
[200]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[201]                           "kevent(EVFILT_TIMER) failed");
[202]             return NGX_ERROR;
[203]         }
[204] 
[205]         ngx_event_flags |= NGX_USE_TIMER_EVENT;
[206]     }
[207] 
[208] #endif
[209] 
[210] #if (NGX_HAVE_CLEAR_EVENT)
[211]     ngx_event_flags |= NGX_USE_CLEAR_EVENT;
[212] #else
[213]     ngx_event_flags |= NGX_USE_LEVEL_EVENT;
[214] #endif
[215] 
[216] #if (NGX_HAVE_LOWAT_EVENT)
[217]     ngx_event_flags |= NGX_USE_LOWAT_EVENT;
[218] #endif
[219] 
[220]     nevents = kcf->events;
[221] 
[222]     ngx_io = ngx_os_io;
[223] 
[224]     ngx_event_actions = ngx_kqueue_module_ctx.actions;
[225] 
[226]     return NGX_OK;
[227] }
[228] 
[229] 
[230] #ifdef EVFILT_USER
[231] 
[232] static ngx_int_t
[233] ngx_kqueue_notify_init(ngx_log_t *log)
[234] {
[235]     notify_kev.ident = 0;
[236]     notify_kev.filter = EVFILT_USER;
[237]     notify_kev.data = 0;
[238]     notify_kev.flags = EV_ADD|EV_CLEAR;
[239]     notify_kev.fflags = 0;
[240]     notify_kev.udata = 0;
[241] 
[242]     if (kevent(ngx_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
[243]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[244]                       "kevent(EVFILT_USER, EV_ADD) failed");
[245]         return NGX_ERROR;
[246]     }
[247] 
[248]     notify_event.active = 1;
[249]     notify_event.log = log;
[250] 
[251]     notify_kev.flags = 0;
[252]     notify_kev.fflags = NOTE_TRIGGER;
[253]     notify_kev.udata = NGX_KQUEUE_UDATA_T ((uintptr_t) &notify_event);
[254] 
[255]     return NGX_OK;
[256] }
[257] 
[258] #endif
[259] 
[260] 
[261] static void
[262] ngx_kqueue_done(ngx_cycle_t *cycle)
[263] {
[264]     if (close(ngx_kqueue) == -1) {
[265]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[266]                       "kqueue close() failed");
[267]     }
[268] 
[269]     ngx_kqueue = -1;
[270] 
[271]     ngx_free(change_list);
[272]     ngx_free(event_list);
[273] 
[274]     change_list = NULL;
[275]     event_list = NULL;
[276]     max_changes = 0;
[277]     nchanges = 0;
[278]     nevents = 0;
[279] }
[280] 
[281] 
[282] static ngx_int_t
[283] ngx_kqueue_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[284] {
[285]     ngx_int_t          rc;
[286] #if 0
[287]     ngx_event_t       *e;
[288]     ngx_connection_t  *c;
[289] #endif
[290] 
[291]     ev->active = 1;
[292]     ev->disabled = 0;
[293]     ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
[294] 
[295] #if 0
[296] 
[297]     if (ev->index < nchanges
[298]         && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
[299]             == (uintptr_t) ev)
[300]     {
[301]         if (change_list[ev->index].flags == EV_DISABLE) {
[302] 
[303]             /*
[304]              * if the EV_DISABLE is still not passed to a kernel
[305]              * we will not pass it
[306]              */
[307] 
[308]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[309]                            "kevent activated: %d: ft:%i",
[310]                            ngx_event_ident(ev->data), event);
[311] 
[312]             if (ev->index < --nchanges) {
[313]                 e = (ngx_event_t *)
[314]                     ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
[315]                 change_list[ev->index] = change_list[nchanges];
[316]                 e->index = ev->index;
[317]             }
[318] 
[319]             return NGX_OK;
[320]         }
[321] 
[322]         c = ev->data;
[323] 
[324]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[325]                       "previous event on #%d were not passed in kernel", c->fd);
[326] 
[327]         return NGX_ERROR;
[328]     }
[329] 
[330] #endif
[331] 
[332]     rc = ngx_kqueue_set_event(ev, event, EV_ADD|EV_ENABLE|flags);
[333] 
[334]     return rc;
[335] }
[336] 
[337] 
[338] static ngx_int_t
[339] ngx_kqueue_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[340] {
[341]     ngx_int_t     rc;
[342]     ngx_event_t  *e;
[343] 
[344]     ev->active = 0;
[345]     ev->disabled = 0;
[346] 
[347]     if (ev->index < nchanges
[348]         && ((uintptr_t) change_list[ev->index].udata & (uintptr_t) ~1)
[349]             == (uintptr_t) ev)
[350]     {
[351]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[352]                        "kevent deleted: %d: ft:%i",
[353]                        ngx_event_ident(ev->data), event);
[354] 
[355]         /* if the event is still not passed to a kernel we will not pass it */
[356] 
[357]         nchanges--;
[358] 
[359]         if (ev->index < nchanges) {
[360]             e = (ngx_event_t *)
[361]                     ((uintptr_t) change_list[nchanges].udata & (uintptr_t) ~1);
[362]             change_list[ev->index] = change_list[nchanges];
[363]             e->index = ev->index;
[364]         }
[365] 
[366]         return NGX_OK;
[367]     }
[368] 
[369]     /*
[370]      * when the file descriptor is closed the kqueue automatically deletes
[371]      * its filters so we do not need to delete explicitly the event
[372]      * before the closing the file descriptor.
[373]      */
[374] 
[375]     if (flags & NGX_CLOSE_EVENT) {
[376]         return NGX_OK;
[377]     }
[378] 
[379]     if (flags & NGX_DISABLE_EVENT) {
[380]         ev->disabled = 1;
[381] 
[382]     } else {
[383]         flags |= EV_DELETE;
[384]     }
[385] 
[386]     rc = ngx_kqueue_set_event(ev, event, flags);
[387] 
[388]     return rc;
[389] }
[390] 
[391] 
[392] static ngx_int_t
[393] ngx_kqueue_set_event(ngx_event_t *ev, ngx_int_t filter, ngx_uint_t flags)
[394] {
[395]     struct kevent     *kev;
[396]     struct timespec    ts;
[397]     ngx_connection_t  *c;
[398] 
[399]     c = ev->data;
[400] 
[401]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[402]                    "kevent set event: %d: ft:%i fl:%04Xi",
[403]                    c->fd, filter, flags);
[404] 
[405]     if (nchanges >= max_changes) {
[406]         ngx_log_error(NGX_LOG_WARN, ev->log, 0,
[407]                       "kqueue change list is filled up");
[408] 
[409]         ts.tv_sec = 0;
[410]         ts.tv_nsec = 0;
[411] 
[412]         if (kevent(ngx_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
[413]             == -1)
[414]         {
[415]             ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent() failed");
[416]             return NGX_ERROR;
[417]         }
[418] 
[419]         nchanges = 0;
[420]     }
[421] 
[422]     kev = &change_list[nchanges];
[423] 
[424]     kev->ident = c->fd;
[425]     kev->filter = (short) filter;
[426]     kev->flags = (u_short) flags;
[427]     kev->udata = NGX_KQUEUE_UDATA_T ((uintptr_t) ev | ev->instance);
[428] 
[429]     if (filter == EVFILT_VNODE) {
[430]         kev->fflags = NOTE_DELETE|NOTE_WRITE|NOTE_EXTEND
[431]                                  |NOTE_ATTRIB|NOTE_RENAME
[432] #if (__FreeBSD__ == 4 && __FreeBSD_version >= 430000) \
[433]     || __FreeBSD_version >= 500018
[434]                                  |NOTE_REVOKE
[435] #endif
[436]                       ;
[437]         kev->data = 0;
[438] 
[439]     } else {
[440] #if (NGX_HAVE_LOWAT_EVENT)
[441]         if (flags & NGX_LOWAT_EVENT) {
[442]             kev->fflags = NOTE_LOWAT;
[443]             kev->data = ev->available;
[444] 
[445]         } else {
[446]             kev->fflags = 0;
[447]             kev->data = 0;
[448]         }
[449] #else
[450]         kev->fflags = 0;
[451]         kev->data = 0;
[452] #endif
[453]     }
[454] 
[455]     ev->index = nchanges;
[456]     nchanges++;
[457] 
[458]     if (flags & NGX_FLUSH_EVENT) {
[459]         ts.tv_sec = 0;
[460]         ts.tv_nsec = 0;
[461] 
[462]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "kevent flush");
[463] 
[464]         if (kevent(ngx_kqueue, change_list, (int) nchanges, NULL, 0, &ts)
[465]             == -1)
[466]         {
[467]             ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "kevent() failed");
[468]             return NGX_ERROR;
[469]         }
[470] 
[471]         nchanges = 0;
[472]     }
[473] 
[474]     return NGX_OK;
[475] }
[476] 
[477] 
[478] #ifdef EVFILT_USER
[479] 
[480] static ngx_int_t
[481] ngx_kqueue_notify(ngx_event_handler_pt handler)
[482] {
[483]     notify_event.handler = handler;
[484] 
[485]     if (kevent(ngx_kqueue, &notify_kev, 1, NULL, 0, NULL) == -1) {
[486]         ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
[487]                       "kevent(EVFILT_USER, NOTE_TRIGGER) failed");
[488]         return NGX_ERROR;
[489]     }
[490] 
[491]     return NGX_OK;
[492] }
[493] 
[494] #endif
[495] 
[496] 
[497] static ngx_int_t
[498] ngx_kqueue_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[499]     ngx_uint_t flags)
[500] {
[501]     int               events, n;
[502]     ngx_int_t         i, instance;
[503]     ngx_uint_t        level;
[504]     ngx_err_t         err;
[505]     ngx_event_t      *ev;
[506]     ngx_queue_t      *queue;
[507]     struct timespec   ts, *tp;
[508] 
[509]     n = (int) nchanges;
[510]     nchanges = 0;
[511] 
[512]     if (timer == NGX_TIMER_INFINITE) {
[513]         tp = NULL;
[514] 
[515]     } else {
[516] 
[517]         ts.tv_sec = timer / 1000;
[518]         ts.tv_nsec = (timer % 1000) * 1000000;
[519] 
[520]         /*
[521]          * 64-bit Darwin kernel has the bug: kernel level ts.tv_nsec is
[522]          * the int32_t while user level ts.tv_nsec is the long (64-bit),
[523]          * so on the big endian PowerPC all nanoseconds are lost.
[524]          */
[525] 
[526] #if (NGX_DARWIN_KEVENT_BUG)
[527]         ts.tv_nsec <<= 32;
[528] #endif
[529] 
[530]         tp = &ts;
[531]     }
[532] 
[533]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[534]                    "kevent timer: %M, changes: %d", timer, n);
[535] 
[536]     events = kevent(ngx_kqueue, change_list, n, event_list, (int) nevents, tp);
[537] 
[538]     err = (events == -1) ? ngx_errno : 0;
[539] 
[540]     if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
[541]         ngx_time_update();
[542]     }
[543] 
[544]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[545]                    "kevent events: %d", events);
[546] 
[547]     if (err) {
[548]         if (err == NGX_EINTR) {
[549] 
[550]             if (ngx_event_timer_alarm) {
[551]                 ngx_event_timer_alarm = 0;
[552]                 return NGX_OK;
[553]             }
[554] 
[555]             level = NGX_LOG_INFO;
[556] 
[557]         } else {
[558]             level = NGX_LOG_ALERT;
[559]         }
[560] 
[561]         ngx_log_error(level, cycle->log, err, "kevent() failed");
[562]         return NGX_ERROR;
[563]     }
[564] 
[565]     if (events == 0) {
[566]         if (timer != NGX_TIMER_INFINITE) {
[567]             return NGX_OK;
[568]         }
[569] 
[570]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[571]                       "kevent() returned no events without timeout");
[572]         return NGX_ERROR;
[573]     }
[574] 
[575]     for (i = 0; i < events; i++) {
[576] 
[577]         ngx_kqueue_dump_event(cycle->log, &event_list[i]);
[578] 
[579]         if (event_list[i].flags & EV_ERROR) {
[580]             ngx_log_error(NGX_LOG_ALERT, cycle->log, event_list[i].data,
[581]                           "kevent() error on %d filter:%d flags:%04Xd",
[582]                           (int) event_list[i].ident, event_list[i].filter,
[583]                           event_list[i].flags);
[584]             continue;
[585]         }
[586] 
[587] #if (NGX_HAVE_TIMER_EVENT)
[588] 
[589]         if (event_list[i].filter == EVFILT_TIMER) {
[590]             ngx_time_update();
[591]             continue;
[592]         }
[593] 
[594] #endif
[595] 
[596]         ev = (ngx_event_t *) event_list[i].udata;
[597] 
[598]         switch (event_list[i].filter) {
[599] 
[600]         case EVFILT_READ:
[601]         case EVFILT_WRITE:
[602] 
[603]             instance = (uintptr_t) ev & 1;
[604]             ev = (ngx_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);
[605] 
[606]             if (ev->closed || ev->instance != instance) {
[607] 
[608]                 /*
[609]                  * the stale event from a file descriptor
[610]                  * that was just closed in this iteration
[611]                  */
[612] 
[613]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[614]                                "kevent: stale event %p", ev);
[615]                 continue;
[616]             }
[617] 
[618]             if (ev->log && (ev->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {
[619]                 ngx_kqueue_dump_event(ev->log, &event_list[i]);
[620]             }
[621] 
[622]             if (ev->oneshot) {
[623]                 ev->active = 0;
[624]             }
[625] 
[626]             ev->available = event_list[i].data;
[627] 
[628]             if (event_list[i].flags & EV_EOF) {
[629]                 ev->pending_eof = 1;
[630]                 ev->kq_errno = event_list[i].fflags;
[631]             }
[632] 
[633]             ev->ready = 1;
[634] 
[635]             break;
[636] 
[637]         case EVFILT_VNODE:
[638]             ev->kq_vnode = 1;
[639] 
[640]             break;
[641] 
[642]         case EVFILT_AIO:
[643]             ev->complete = 1;
[644]             ev->ready = 1;
[645] 
[646]             break;
[647] 
[648] #ifdef EVFILT_USER
[649]         case EVFILT_USER:
[650]             break;
[651] #endif
[652] 
[653]         default:
[654]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[655]                           "unexpected kevent() filter %d",
[656]                           event_list[i].filter);
[657]             continue;
[658]         }
[659] 
[660]         if (flags & NGX_POST_EVENTS) {
[661]             queue = ev->accept ? &ngx_posted_accept_events
[662]                                : &ngx_posted_events;
[663] 
[664]             ngx_post_event(ev, queue);
[665] 
[666]             continue;
[667]         }
[668] 
[669]         ev->handler(ev);
[670]     }
[671] 
[672]     return NGX_OK;
[673] }
[674] 
[675] 
[676] static ngx_inline void
[677] ngx_kqueue_dump_event(ngx_log_t *log, struct kevent *kev)
[678] {
[679]     if (kev->ident > 0x8000000 && kev->ident != (unsigned) -1) {
[680]         ngx_log_debug6(NGX_LOG_DEBUG_EVENT, log, 0,
[681]                        "kevent: %p: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
[682]                        (void *) kev->ident, kev->filter,
[683]                        kev->flags, kev->fflags,
[684]                        (int) kev->data, kev->udata);
[685] 
[686]     } else {
[687]         ngx_log_debug6(NGX_LOG_DEBUG_EVENT, log, 0,
[688]                        "kevent: %d: ft:%d fl:%04Xd ff:%08Xd d:%d ud:%p",
[689]                        (int) kev->ident, kev->filter,
[690]                        kev->flags, kev->fflags,
[691]                        (int) kev->data, kev->udata);
[692]     }
[693] }
[694] 
[695] 
[696] static void *
[697] ngx_kqueue_create_conf(ngx_cycle_t *cycle)
[698] {
[699]     ngx_kqueue_conf_t  *kcf;
[700] 
[701]     kcf = ngx_palloc(cycle->pool, sizeof(ngx_kqueue_conf_t));
[702]     if (kcf == NULL) {
[703]         return NULL;
[704]     }
[705] 
[706]     kcf->changes = NGX_CONF_UNSET;
[707]     kcf->events = NGX_CONF_UNSET;
[708] 
[709]     return kcf;
[710] }
[711] 
[712] 
[713] static char *
[714] ngx_kqueue_init_conf(ngx_cycle_t *cycle, void *conf)
[715] {
[716]     ngx_kqueue_conf_t *kcf = conf;
[717] 
[718]     ngx_conf_init_uint_value(kcf->changes, 512);
[719]     ngx_conf_init_uint_value(kcf->events, 512);
[720] 
[721]     return NGX_CONF_OK;
[722] }
