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
[13] #if (NGX_TEST_BUILD_EVENTPORT)
[14] 
[15] #define ushort_t  u_short
[16] #define uint_t    u_int
[17] 
[18] #ifndef CLOCK_REALTIME
[19] #define CLOCK_REALTIME          0
[20] typedef int     clockid_t;
[21] typedef void *  timer_t;
[22] #elif (NGX_DARWIN)
[23] typedef void *  timer_t;
[24] #endif
[25] 
[26] /* Solaris declarations */
[27] 
[28] #define PORT_SOURCE_AIO         1
[29] #define PORT_SOURCE_TIMER       2
[30] #define PORT_SOURCE_USER        3
[31] #define PORT_SOURCE_FD          4
[32] #define PORT_SOURCE_ALERT       5
[33] #define PORT_SOURCE_MQ          6
[34] 
[35] #ifndef ETIME
[36] #define ETIME                   64
[37] #endif
[38] 
[39] #define SIGEV_PORT              4
[40] 
[41] typedef struct {
[42]     int         portev_events;  /* event data is source specific */
[43]     ushort_t    portev_source;  /* event source */
[44]     ushort_t    portev_pad;     /* port internal use */
[45]     uintptr_t   portev_object;  /* source specific object */
[46]     void       *portev_user;    /* user cookie */
[47] } port_event_t;
[48] 
[49] typedef struct  port_notify {
[50]     int         portnfy_port;   /* bind request(s) to port */
[51]     void       *portnfy_user;   /* user defined */
[52] } port_notify_t;
[53] 
[54] #if (__FreeBSD__ && __FreeBSD_version < 700005) || (NGX_DARWIN)
[55] 
[56] typedef struct itimerspec {     /* definition per POSIX.4 */
[57]     struct timespec it_interval;/* timer period */
[58]     struct timespec it_value;   /* timer expiration */
[59] } itimerspec_t;
[60] 
[61] #endif
[62] 
[63] int port_create(void);
[64] 
[65] int port_create(void)
[66] {
[67]     return -1;
[68] }
[69] 
[70] 
[71] int port_associate(int port, int source, uintptr_t object, int events,
[72]     void *user);
[73] 
[74] int port_associate(int port, int source, uintptr_t object, int events,
[75]     void *user)
[76] {
[77]     return -1;
[78] }
[79] 
[80] 
[81] int port_dissociate(int port, int source, uintptr_t object);
[82] 
[83] int port_dissociate(int port, int source, uintptr_t object)
[84] {
[85]     return -1;
[86] }
[87] 
[88] 
[89] int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
[90]     struct timespec *timeout);
[91] 
[92] int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
[93]     struct timespec *timeout)
[94] {
[95]     return -1;
[96] }
[97] 
[98] int port_send(int port, int events, void *user);
[99] 
[100] int port_send(int port, int events, void *user)
[101] {
[102]     return -1;
[103] }
[104] 
[105] 
[106] int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid);
[107] 
[108] int timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid)
[109] {
[110]     return -1;
[111] }
[112] 
[113] 
[114] int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
[115]     struct itimerspec *ovalue);
[116] 
[117] int timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
[118]     struct itimerspec *ovalue)
[119] {
[120]     return -1;
[121] }
[122] 
[123] 
[124] int timer_delete(timer_t timerid);
[125] 
[126] int timer_delete(timer_t timerid)
[127] {
[128]     return -1;
[129] }
[130] 
[131] #endif
[132] 
[133] 
[134] typedef struct {
[135]     ngx_uint_t  events;
[136] } ngx_eventport_conf_t;
[137] 
[138] 
[139] static ngx_int_t ngx_eventport_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[140] static void ngx_eventport_done(ngx_cycle_t *cycle);
[141] static ngx_int_t ngx_eventport_add_event(ngx_event_t *ev, ngx_int_t event,
[142]     ngx_uint_t flags);
[143] static ngx_int_t ngx_eventport_del_event(ngx_event_t *ev, ngx_int_t event,
[144]     ngx_uint_t flags);
[145] static ngx_int_t ngx_eventport_notify(ngx_event_handler_pt handler);
[146] static ngx_int_t ngx_eventport_process_events(ngx_cycle_t *cycle,
[147]     ngx_msec_t timer, ngx_uint_t flags);
[148] 
[149] static void *ngx_eventport_create_conf(ngx_cycle_t *cycle);
[150] static char *ngx_eventport_init_conf(ngx_cycle_t *cycle, void *conf);
[151] 
[152] static int            ep = -1;
[153] static port_event_t  *event_list;
[154] static ngx_uint_t     nevents;
[155] static timer_t        event_timer = (timer_t) -1;
[156] static ngx_event_t    notify_event;
[157] 
[158] static ngx_str_t      eventport_name = ngx_string("eventport");
[159] 
[160] 
[161] static ngx_command_t  ngx_eventport_commands[] = {
[162] 
[163]     { ngx_string("eventport_events"),
[164]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[165]       ngx_conf_set_num_slot,
[166]       0,
[167]       offsetof(ngx_eventport_conf_t, events),
[168]       NULL },
[169] 
[170]       ngx_null_command
[171] };
[172] 
[173] 
[174] static ngx_event_module_t  ngx_eventport_module_ctx = {
[175]     &eventport_name,
[176]     ngx_eventport_create_conf,             /* create configuration */
[177]     ngx_eventport_init_conf,               /* init configuration */
[178] 
[179]     {
[180]         ngx_eventport_add_event,           /* add an event */
[181]         ngx_eventport_del_event,           /* delete an event */
[182]         ngx_eventport_add_event,           /* enable an event */
[183]         ngx_eventport_del_event,           /* disable an event */
[184]         NULL,                              /* add an connection */
[185]         NULL,                              /* delete an connection */
[186]         ngx_eventport_notify,              /* trigger a notify */
[187]         ngx_eventport_process_events,      /* process the events */
[188]         ngx_eventport_init,                /* init the events */
[189]         ngx_eventport_done,                /* done the events */
[190]     }
[191] 
[192] };
[193] 
[194] ngx_module_t  ngx_eventport_module = {
[195]     NGX_MODULE_V1,
[196]     &ngx_eventport_module_ctx,             /* module context */
[197]     ngx_eventport_commands,                /* module directives */
[198]     NGX_EVENT_MODULE,                      /* module type */
[199]     NULL,                                  /* init master */
[200]     NULL,                                  /* init module */
[201]     NULL,                                  /* init process */
[202]     NULL,                                  /* init thread */
[203]     NULL,                                  /* exit thread */
[204]     NULL,                                  /* exit process */
[205]     NULL,                                  /* exit master */
[206]     NGX_MODULE_V1_PADDING
[207] };
[208] 
[209] 
[210] static ngx_int_t
[211] ngx_eventport_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[212] {
[213]     port_notify_t          pn;
[214]     struct itimerspec      its;
[215]     struct sigevent        sev;
[216]     ngx_eventport_conf_t  *epcf;
[217] 
[218]     epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_eventport_module);
[219] 
[220]     if (ep == -1) {
[221]         ep = port_create();
[222] 
[223]         if (ep == -1) {
[224]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[225]                           "port_create() failed");
[226]             return NGX_ERROR;
[227]         }
[228] 
[229]         notify_event.active = 1;
[230]         notify_event.log = cycle->log;
[231]     }
[232] 
[233]     if (nevents < epcf->events) {
[234]         if (event_list) {
[235]             ngx_free(event_list);
[236]         }
[237] 
[238]         event_list = ngx_alloc(sizeof(port_event_t) * epcf->events,
[239]                                cycle->log);
[240]         if (event_list == NULL) {
[241]             return NGX_ERROR;
[242]         }
[243]     }
[244] 
[245]     ngx_event_flags = NGX_USE_EVENTPORT_EVENT;
[246] 
[247]     if (timer) {
[248]         ngx_memzero(&pn, sizeof(port_notify_t));
[249]         pn.portnfy_port = ep;
[250] 
[251]         ngx_memzero(&sev, sizeof(struct sigevent));
[252]         sev.sigev_notify = SIGEV_PORT;
[253]         sev.sigev_value.sival_ptr = &pn;
[254] 
[255]         if (timer_create(CLOCK_REALTIME, &sev, &event_timer) == -1) {
[256]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[257]                           "timer_create() failed");
[258]             return NGX_ERROR;
[259]         }
[260] 
[261]         its.it_interval.tv_sec = timer / 1000;
[262]         its.it_interval.tv_nsec = (timer % 1000) * 1000000;
[263]         its.it_value.tv_sec = timer / 1000;
[264]         its.it_value.tv_nsec = (timer % 1000) * 1000000;
[265] 
[266]         if (timer_settime(event_timer, 0, &its, NULL) == -1) {
[267]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[268]                           "timer_settime() failed");
[269]             return NGX_ERROR;
[270]         }
[271] 
[272]         ngx_event_flags |= NGX_USE_TIMER_EVENT;
[273]     }
[274] 
[275]     nevents = epcf->events;
[276] 
[277]     ngx_io = ngx_os_io;
[278] 
[279]     ngx_event_actions = ngx_eventport_module_ctx.actions;
[280] 
[281]     return NGX_OK;
[282] }
[283] 
[284] 
[285] static void
[286] ngx_eventport_done(ngx_cycle_t *cycle)
[287] {
[288]     if (event_timer != (timer_t) -1) {
[289]         if (timer_delete(event_timer) == -1) {
[290]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[291]                           "timer_delete() failed");
[292]         }
[293] 
[294]         event_timer = (timer_t) -1;
[295]     }
[296] 
[297]     if (close(ep) == -1) {
[298]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[299]                       "close() event port failed");
[300]     }
[301] 
[302]     ep = -1;
[303] 
[304]     ngx_free(event_list);
[305] 
[306]     event_list = NULL;
[307]     nevents = 0;
[308] }
[309] 
[310] 
[311] static ngx_int_t
[312] ngx_eventport_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[313] {
[314]     ngx_int_t          events, prev;
[315]     ngx_event_t       *e;
[316]     ngx_connection_t  *c;
[317] 
[318]     c = ev->data;
[319] 
[320]     events = event;
[321] 
[322]     if (event == NGX_READ_EVENT) {
[323]         e = c->write;
[324]         prev = POLLOUT;
[325] #if (NGX_READ_EVENT != POLLIN)
[326]         events = POLLIN;
[327] #endif
[328] 
[329]     } else {
[330]         e = c->read;
[331]         prev = POLLIN;
[332] #if (NGX_WRITE_EVENT != POLLOUT)
[333]         events = POLLOUT;
[334] #endif
[335]     }
[336] 
[337]     if (e->oneshot) {
[338]         events |= prev;
[339]     }
[340] 
[341]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[342]                    "eventport add event: fd:%d ev:%04Xi", c->fd, events);
[343] 
[344]     if (port_associate(ep, PORT_SOURCE_FD, c->fd, events,
[345]                        (void *) ((uintptr_t) ev | ev->instance))
[346]         == -1)
[347]     {
[348]         ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[349]                       "port_associate() failed");
[350]         return NGX_ERROR;
[351]     }
[352] 
[353]     ev->active = 1;
[354]     ev->oneshot = 1;
[355] 
[356]     return NGX_OK;
[357] }
[358] 
[359] 
[360] static ngx_int_t
[361] ngx_eventport_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[362] {
[363]     ngx_event_t       *e;
[364]     ngx_connection_t  *c;
[365] 
[366]     /*
[367]      * when the file descriptor is closed, the event port automatically
[368]      * dissociates it from the port, so we do not need to dissociate explicitly
[369]      * the event before the closing the file descriptor
[370]      */
[371] 
[372]     if (flags & NGX_CLOSE_EVENT) {
[373]         ev->active = 0;
[374]         ev->oneshot = 0;
[375]         return NGX_OK;
[376]     }
[377] 
[378]     c = ev->data;
[379] 
[380]     if (event == NGX_READ_EVENT) {
[381]         e = c->write;
[382]         event = POLLOUT;
[383] 
[384]     } else {
[385]         e = c->read;
[386]         event = POLLIN;
[387]     }
[388] 
[389]     if (e->oneshot) {
[390]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[391]                        "eventport change event: fd:%d ev:%04Xi", c->fd, event);
[392] 
[393]         if (port_associate(ep, PORT_SOURCE_FD, c->fd, event,
[394]                            (void *) ((uintptr_t) ev | ev->instance))
[395]             == -1)
[396]         {
[397]             ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[398]                           "port_associate() failed");
[399]             return NGX_ERROR;
[400]         }
[401] 
[402]     } else if (ev->active) {
[403]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[404]                        "eventport del event: fd:%d", c->fd);
[405] 
[406]         if (port_dissociate(ep, PORT_SOURCE_FD, c->fd) == -1) {
[407]             ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[408]                           "port_dissociate() failed");
[409]             return NGX_ERROR;
[410]         }
[411]     }
[412] 
[413]     ev->active = 0;
[414]     ev->oneshot = 0;
[415] 
[416]     return NGX_OK;
[417] }
[418] 
[419] 
[420] static ngx_int_t
[421] ngx_eventport_notify(ngx_event_handler_pt handler)
[422] {
[423]     notify_event.handler = handler;
[424] 
[425]     if (port_send(ep, 0, &notify_event) != 0) {
[426]         ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
[427]                       "port_send() failed");
[428]         return NGX_ERROR;
[429]     }
[430] 
[431]     return NGX_OK;
[432] }
[433] 
[434] 
[435] static ngx_int_t
[436] ngx_eventport_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[437]     ngx_uint_t flags)
[438] {
[439]     int                 n, revents;
[440]     u_int               events;
[441]     ngx_err_t           err;
[442]     ngx_int_t           instance;
[443]     ngx_uint_t          i, level;
[444]     ngx_event_t        *ev, *rev, *wev;
[445]     ngx_queue_t        *queue;
[446]     ngx_connection_t   *c;
[447]     struct timespec     ts, *tp;
[448] 
[449]     if (timer == NGX_TIMER_INFINITE) {
[450]         tp = NULL;
[451] 
[452]     } else {
[453]         ts.tv_sec = timer / 1000;
[454]         ts.tv_nsec = (timer % 1000) * 1000000;
[455]         tp = &ts;
[456]     }
[457] 
[458]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[459]                    "eventport timer: %M", timer);
[460] 
[461]     events = 1;
[462] 
[463]     n = port_getn(ep, event_list, (u_int) nevents, &events, tp);
[464] 
[465]     err = ngx_errno;
[466] 
[467]     if (flags & NGX_UPDATE_TIME) {
[468]         ngx_time_update();
[469]     }
[470] 
[471]     if (n == -1) {
[472]         if (err == ETIME) {
[473]             if (timer != NGX_TIMER_INFINITE) {
[474]                 return NGX_OK;
[475]             }
[476] 
[477]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[478]                           "port_getn() returned no events without timeout");
[479]             return NGX_ERROR;
[480]         }
[481] 
[482]         level = (err == NGX_EINTR) ? NGX_LOG_INFO : NGX_LOG_ALERT;
[483]         ngx_log_error(level, cycle->log, err, "port_getn() failed");
[484]         return NGX_ERROR;
[485]     }
[486] 
[487]     if (events == 0) {
[488]         if (timer != NGX_TIMER_INFINITE) {
[489]             return NGX_OK;
[490]         }
[491] 
[492]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[493]                       "port_getn() returned no events without timeout");
[494]         return NGX_ERROR;
[495]     }
[496] 
[497]     for (i = 0; i < events; i++) {
[498] 
[499]         if (event_list[i].portev_source == PORT_SOURCE_TIMER) {
[500]             ngx_time_update();
[501]             continue;
[502]         }
[503] 
[504]         ev = event_list[i].portev_user;
[505] 
[506]         switch (event_list[i].portev_source) {
[507] 
[508]         case PORT_SOURCE_FD:
[509] 
[510]             instance = (uintptr_t) ev & 1;
[511]             ev = (ngx_event_t *) ((uintptr_t) ev & (uintptr_t) ~1);
[512] 
[513]             if (ev->closed || ev->instance != instance) {
[514] 
[515]                 /*
[516]                  * the stale event from a file descriptor
[517]                  * that was just closed in this iteration
[518]                  */
[519] 
[520]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[521]                                "eventport: stale event %p", ev);
[522]                 continue;
[523]             }
[524] 
[525]             revents = event_list[i].portev_events;
[526] 
[527]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[528]                            "eventport: fd:%d, ev:%04Xd",
[529]                            (int) event_list[i].portev_object, revents);
[530] 
[531]             if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
[532]                 ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[533]                                "port_getn() error fd:%d ev:%04Xd",
[534]                                (int) event_list[i].portev_object, revents);
[535]             }
[536] 
[537]             if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
[538]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[539]                               "strange port_getn() events fd:%d ev:%04Xd",
[540]                               (int) event_list[i].portev_object, revents);
[541]             }
[542] 
[543]             if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
[544] 
[545]                 /*
[546]                  * if the error events were returned, add POLLIN and POLLOUT
[547]                  * to handle the events at least in one active handler
[548]                  */
[549] 
[550]                 revents |= POLLIN|POLLOUT;
[551]             }
[552] 
[553]             c = ev->data;
[554]             rev = c->read;
[555]             wev = c->write;
[556] 
[557]             rev->active = 0;
[558]             wev->active = 0;
[559] 
[560]             if (revents & POLLIN) {
[561]                 rev->ready = 1;
[562]                 rev->available = -1;
[563] 
[564]                 if (flags & NGX_POST_EVENTS) {
[565]                     queue = rev->accept ? &ngx_posted_accept_events
[566]                                         : &ngx_posted_events;
[567] 
[568]                     ngx_post_event(rev, queue);
[569] 
[570]                 } else {
[571]                     rev->handler(rev);
[572] 
[573]                     if (ev->closed || ev->instance != instance) {
[574]                         continue;
[575]                     }
[576]                 }
[577] 
[578]                 if (rev->accept) {
[579]                     if (ngx_use_accept_mutex) {
[580]                         ngx_accept_events = 1;
[581]                         continue;
[582]                     }
[583] 
[584]                     if (port_associate(ep, PORT_SOURCE_FD, c->fd, POLLIN,
[585]                                        (void *) ((uintptr_t) ev | ev->instance))
[586]                         == -1)
[587]                     {
[588]                         ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[589]                                       "port_associate() failed");
[590]                         return NGX_ERROR;
[591]                     }
[592]                 }
[593]             }
[594] 
[595]             if (revents & POLLOUT) {
[596]                 wev->ready = 1;
[597] 
[598]                 if (flags & NGX_POST_EVENTS) {
[599]                     ngx_post_event(wev, &ngx_posted_events);
[600] 
[601]                 } else {
[602]                     wev->handler(wev);
[603]                 }
[604]             }
[605] 
[606]             continue;
[607] 
[608]         case PORT_SOURCE_USER:
[609] 
[610]             ev->handler(ev);
[611] 
[612]             continue;
[613] 
[614]         default:
[615]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[616]                           "unexpected eventport object %d",
[617]                           (int) event_list[i].portev_object);
[618]             continue;
[619]         }
[620]     }
[621] 
[622]     return NGX_OK;
[623] }
[624] 
[625] 
[626] static void *
[627] ngx_eventport_create_conf(ngx_cycle_t *cycle)
[628] {
[629]     ngx_eventport_conf_t  *epcf;
[630] 
[631]     epcf = ngx_palloc(cycle->pool, sizeof(ngx_eventport_conf_t));
[632]     if (epcf == NULL) {
[633]         return NULL;
[634]     }
[635] 
[636]     epcf->events = NGX_CONF_UNSET;
[637] 
[638]     return epcf;
[639] }
[640] 
[641] 
[642] static char *
[643] ngx_eventport_init_conf(ngx_cycle_t *cycle, void *conf)
[644] {
[645]     ngx_eventport_conf_t *epcf = conf;
[646] 
[647]     ngx_conf_init_uint_value(epcf->events, 32);
[648] 
[649]     return NGX_CONF_OK;
[650] }
