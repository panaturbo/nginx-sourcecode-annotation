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
[13] #if (NGX_TEST_BUILD_DEVPOLL)
[14] 
[15] /* Solaris declarations */
[16] 
[17] #ifndef POLLREMOVE
[18] #define POLLREMOVE   0x0800
[19] #endif
[20] #define DP_POLL      0xD001
[21] #define DP_ISPOLLED  0xD002
[22] 
[23] struct dvpoll {
[24]     struct pollfd  *dp_fds;
[25]     int             dp_nfds;
[26]     int             dp_timeout;
[27] };
[28] 
[29] #endif
[30] 
[31] 
[32] typedef struct {
[33]     ngx_uint_t      changes;
[34]     ngx_uint_t      events;
[35] } ngx_devpoll_conf_t;
[36] 
[37] 
[38] static ngx_int_t ngx_devpoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[39] static void ngx_devpoll_done(ngx_cycle_t *cycle);
[40] static ngx_int_t ngx_devpoll_add_event(ngx_event_t *ev, ngx_int_t event,
[41]     ngx_uint_t flags);
[42] static ngx_int_t ngx_devpoll_del_event(ngx_event_t *ev, ngx_int_t event,
[43]     ngx_uint_t flags);
[44] static ngx_int_t ngx_devpoll_set_event(ngx_event_t *ev, ngx_int_t event,
[45]     ngx_uint_t flags);
[46] static ngx_int_t ngx_devpoll_process_events(ngx_cycle_t *cycle,
[47]     ngx_msec_t timer, ngx_uint_t flags);
[48] 
[49] static void *ngx_devpoll_create_conf(ngx_cycle_t *cycle);
[50] static char *ngx_devpoll_init_conf(ngx_cycle_t *cycle, void *conf);
[51] 
[52] static int              dp = -1;
[53] static struct pollfd   *change_list, *event_list;
[54] static ngx_uint_t       nchanges, max_changes, nevents;
[55] 
[56] static ngx_event_t    **change_index;
[57] 
[58] 
[59] static ngx_str_t      devpoll_name = ngx_string("/dev/poll");
[60] 
[61] static ngx_command_t  ngx_devpoll_commands[] = {
[62] 
[63]     { ngx_string("devpoll_changes"),
[64]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[65]       ngx_conf_set_num_slot,
[66]       0,
[67]       offsetof(ngx_devpoll_conf_t, changes),
[68]       NULL },
[69] 
[70]     { ngx_string("devpoll_events"),
[71]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[72]       ngx_conf_set_num_slot,
[73]       0,
[74]       offsetof(ngx_devpoll_conf_t, events),
[75]       NULL },
[76] 
[77]       ngx_null_command
[78] };
[79] 
[80] 
[81] static ngx_event_module_t  ngx_devpoll_module_ctx = {
[82]     &devpoll_name,
[83]     ngx_devpoll_create_conf,               /* create configuration */
[84]     ngx_devpoll_init_conf,                 /* init configuration */
[85] 
[86]     {
[87]         ngx_devpoll_add_event,             /* add an event */
[88]         ngx_devpoll_del_event,             /* delete an event */
[89]         ngx_devpoll_add_event,             /* enable an event */
[90]         ngx_devpoll_del_event,             /* disable an event */
[91]         NULL,                              /* add an connection */
[92]         NULL,                              /* delete an connection */
[93]         NULL,                              /* trigger a notify */
[94]         ngx_devpoll_process_events,        /* process the events */
[95]         ngx_devpoll_init,                  /* init the events */
[96]         ngx_devpoll_done,                  /* done the events */
[97]     }
[98] 
[99] };
[100] 
[101] ngx_module_t  ngx_devpoll_module = {
[102]     NGX_MODULE_V1,
[103]     &ngx_devpoll_module_ctx,               /* module context */
[104]     ngx_devpoll_commands,                  /* module directives */
[105]     NGX_EVENT_MODULE,                      /* module type */
[106]     NULL,                                  /* init master */
[107]     NULL,                                  /* init module */
[108]     NULL,                                  /* init process */
[109]     NULL,                                  /* init thread */
[110]     NULL,                                  /* exit thread */
[111]     NULL,                                  /* exit process */
[112]     NULL,                                  /* exit master */
[113]     NGX_MODULE_V1_PADDING
[114] };
[115] 
[116] 
[117] static ngx_int_t
[118] ngx_devpoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[119] {
[120]     size_t               n;
[121]     ngx_devpoll_conf_t  *dpcf;
[122] 
[123]     dpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_devpoll_module);
[124] 
[125]     if (dp == -1) {
[126]         dp = open("/dev/poll", O_RDWR);
[127] 
[128]         if (dp == -1) {
[129]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[130]                           "open(/dev/poll) failed");
[131]             return NGX_ERROR;
[132]         }
[133]     }
[134] 
[135]     if (max_changes < dpcf->changes) {
[136]         if (nchanges) {
[137]             n = nchanges * sizeof(struct pollfd);
[138]             if (write(dp, change_list, n) != (ssize_t) n) {
[139]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[140]                               "write(/dev/poll) failed");
[141]                 return NGX_ERROR;
[142]             }
[143] 
[144]             nchanges = 0;
[145]         }
[146] 
[147]         if (change_list) {
[148]             ngx_free(change_list);
[149]         }
[150] 
[151]         change_list = ngx_alloc(sizeof(struct pollfd) * dpcf->changes,
[152]                                 cycle->log);
[153]         if (change_list == NULL) {
[154]             return NGX_ERROR;
[155]         }
[156] 
[157]         if (change_index) {
[158]             ngx_free(change_index);
[159]         }
[160] 
[161]         change_index = ngx_alloc(sizeof(ngx_event_t *) * dpcf->changes,
[162]                                  cycle->log);
[163]         if (change_index == NULL) {
[164]             return NGX_ERROR;
[165]         }
[166]     }
[167] 
[168]     max_changes = dpcf->changes;
[169] 
[170]     if (nevents < dpcf->events) {
[171]         if (event_list) {
[172]             ngx_free(event_list);
[173]         }
[174] 
[175]         event_list = ngx_alloc(sizeof(struct pollfd) * dpcf->events,
[176]                                cycle->log);
[177]         if (event_list == NULL) {
[178]             return NGX_ERROR;
[179]         }
[180]     }
[181] 
[182]     nevents = dpcf->events;
[183] 
[184]     ngx_io = ngx_os_io;
[185] 
[186]     ngx_event_actions = ngx_devpoll_module_ctx.actions;
[187] 
[188]     ngx_event_flags = NGX_USE_LEVEL_EVENT|NGX_USE_FD_EVENT;
[189] 
[190]     return NGX_OK;
[191] }
[192] 
[193] 
[194] static void
[195] ngx_devpoll_done(ngx_cycle_t *cycle)
[196] {
[197]     if (close(dp) == -1) {
[198]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[199]                       "close(/dev/poll) failed");
[200]     }
[201] 
[202]     dp = -1;
[203] 
[204]     ngx_free(change_list);
[205]     ngx_free(event_list);
[206]     ngx_free(change_index);
[207] 
[208]     change_list = NULL;
[209]     event_list = NULL;
[210]     change_index = NULL;
[211]     max_changes = 0;
[212]     nchanges = 0;
[213]     nevents = 0;
[214] }
[215] 
[216] 
[217] static ngx_int_t
[218] ngx_devpoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[219] {
[220] #if (NGX_DEBUG)
[221]     ngx_connection_t *c;
[222] #endif
[223] 
[224] #if (NGX_READ_EVENT != POLLIN)
[225]     event = (event == NGX_READ_EVENT) ? POLLIN : POLLOUT;
[226] #endif
[227] 
[228] #if (NGX_DEBUG)
[229]     c = ev->data;
[230]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[231]                    "devpoll add event: fd:%d ev:%04Xi", c->fd, event);
[232] #endif
[233] 
[234]     ev->active = 1;
[235] 
[236]     return ngx_devpoll_set_event(ev, event, 0);
[237] }
[238] 
[239] 
[240] static ngx_int_t
[241] ngx_devpoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[242] {
[243]     ngx_event_t       *e;
[244]     ngx_connection_t  *c;
[245] 
[246]     c = ev->data;
[247] 
[248] #if (NGX_READ_EVENT != POLLIN)
[249]     event = (event == NGX_READ_EVENT) ? POLLIN : POLLOUT;
[250] #endif
[251] 
[252]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[253]                    "devpoll del event: fd:%d ev:%04Xi", c->fd, event);
[254] 
[255]     if (ngx_devpoll_set_event(ev, POLLREMOVE, flags) == NGX_ERROR) {
[256]         return NGX_ERROR;
[257]     }
[258] 
[259]     ev->active = 0;
[260] 
[261]     if (flags & NGX_CLOSE_EVENT) {
[262]         e = (event == POLLIN) ? c->write : c->read;
[263] 
[264]         if (e) {
[265]             e->active = 0;
[266]         }
[267] 
[268]         return NGX_OK;
[269]     }
[270] 
[271]     /* restore the pair event if it exists */
[272] 
[273]     if (event == POLLIN) {
[274]         e = c->write;
[275]         event = POLLOUT;
[276] 
[277]     } else {
[278]         e = c->read;
[279]         event = POLLIN;
[280]     }
[281] 
[282]     if (e && e->active) {
[283]         return ngx_devpoll_set_event(e, event, 0);
[284]     }
[285] 
[286]     return NGX_OK;
[287] }
[288] 
[289] 
[290] static ngx_int_t
[291] ngx_devpoll_set_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[292] {
[293]     size_t             n;
[294]     ngx_connection_t  *c;
[295] 
[296]     c = ev->data;
[297] 
[298]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[299]                    "devpoll fd:%d ev:%04Xi fl:%04Xi", c->fd, event, flags);
[300] 
[301]     if (nchanges >= max_changes) {
[302]         ngx_log_error(NGX_LOG_WARN, ev->log, 0,
[303]                       "/dev/pool change list is filled up");
[304] 
[305]         n = nchanges * sizeof(struct pollfd);
[306]         if (write(dp, change_list, n) != (ssize_t) n) {
[307]             ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[308]                           "write(/dev/poll) failed");
[309]             return NGX_ERROR;
[310]         }
[311] 
[312]         nchanges = 0;
[313]     }
[314] 
[315]     change_list[nchanges].fd = c->fd;
[316]     change_list[nchanges].events = (short) event;
[317]     change_list[nchanges].revents = 0;
[318] 
[319]     change_index[nchanges] = ev;
[320]     ev->index = nchanges;
[321] 
[322]     nchanges++;
[323] 
[324]     if (flags & NGX_CLOSE_EVENT) {
[325]         n = nchanges * sizeof(struct pollfd);
[326]         if (write(dp, change_list, n) != (ssize_t) n) {
[327]             ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[328]                           "write(/dev/poll) failed");
[329]             return NGX_ERROR;
[330]         }
[331] 
[332]         nchanges = 0;
[333]     }
[334] 
[335]     return NGX_OK;
[336] }
[337] 
[338] 
[339] static ngx_int_t
[340] ngx_devpoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[341]     ngx_uint_t flags)
[342] {
[343]     int                 events, revents, rc;
[344]     size_t              n;
[345]     ngx_fd_t            fd;
[346]     ngx_err_t           err;
[347]     ngx_int_t           i;
[348]     ngx_uint_t          level, instance;
[349]     ngx_event_t        *rev, *wev;
[350]     ngx_queue_t        *queue;
[351]     ngx_connection_t   *c;
[352]     struct pollfd       pfd;
[353]     struct dvpoll       dvp;
[354] 
[355]     /* NGX_TIMER_INFINITE == INFTIM */
[356] 
[357]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[358]                    "devpoll timer: %M", timer);
[359] 
[360]     if (nchanges) {
[361]         n = nchanges * sizeof(struct pollfd);
[362]         if (write(dp, change_list, n) != (ssize_t) n) {
[363]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[364]                           "write(/dev/poll) failed");
[365]             return NGX_ERROR;
[366]         }
[367] 
[368]         nchanges = 0;
[369]     }
[370] 
[371]     dvp.dp_fds = event_list;
[372]     dvp.dp_nfds = (int) nevents;
[373]     dvp.dp_timeout = timer;
[374]     events = ioctl(dp, DP_POLL, &dvp);
[375] 
[376]     err = (events == -1) ? ngx_errno : 0;
[377] 
[378]     if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
[379]         ngx_time_update();
[380]     }
[381] 
[382]     if (err) {
[383]         if (err == NGX_EINTR) {
[384] 
[385]             if (ngx_event_timer_alarm) {
[386]                 ngx_event_timer_alarm = 0;
[387]                 return NGX_OK;
[388]             }
[389] 
[390]             level = NGX_LOG_INFO;
[391] 
[392]         } else {
[393]             level = NGX_LOG_ALERT;
[394]         }
[395] 
[396]         ngx_log_error(level, cycle->log, err, "ioctl(DP_POLL) failed");
[397]         return NGX_ERROR;
[398]     }
[399] 
[400]     if (events == 0) {
[401]         if (timer != NGX_TIMER_INFINITE) {
[402]             return NGX_OK;
[403]         }
[404] 
[405]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[406]                       "ioctl(DP_POLL) returned no events without timeout");
[407]         return NGX_ERROR;
[408]     }
[409] 
[410]     for (i = 0; i < events; i++) {
[411] 
[412]         fd = event_list[i].fd;
[413]         revents = event_list[i].revents;
[414] 
[415]         c = ngx_cycle->files[fd];
[416] 
[417]         if (c == NULL || c->fd == -1) {
[418] 
[419]             pfd.fd = fd;
[420]             pfd.events = 0;
[421]             pfd.revents = 0;
[422] 
[423]             rc = ioctl(dp, DP_ISPOLLED, &pfd);
[424] 
[425]             switch (rc) {
[426] 
[427]             case -1:
[428]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[429]                     "ioctl(DP_ISPOLLED) failed for socket %d, event %04Xd",
[430]                     fd, revents);
[431]                 break;
[432] 
[433]             case 0:
[434]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[435]                     "phantom event %04Xd for closed and removed socket %d",
[436]                     revents, fd);
[437]                 break;
[438] 
[439]             default:
[440]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[441]                     "unexpected event %04Xd for closed and removed socket %d, "
[442]                     "ioctl(DP_ISPOLLED) returned rc:%d, fd:%d, event %04Xd",
[443]                     revents, fd, rc, pfd.fd, pfd.revents);
[444] 
[445]                 pfd.fd = fd;
[446]                 pfd.events = POLLREMOVE;
[447]                 pfd.revents = 0;
[448] 
[449]                 if (write(dp, &pfd, sizeof(struct pollfd))
[450]                     != (ssize_t) sizeof(struct pollfd))
[451]                 {
[452]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[453]                                   "write(/dev/poll) for %d failed", fd);
[454]                 }
[455] 
[456]                 if (close(fd) == -1) {
[457]                     ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[458]                                   "close(%d) failed", fd);
[459]                 }
[460] 
[461]                 break;
[462]             }
[463] 
[464]             continue;
[465]         }
[466] 
[467]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[468]                        "devpoll: fd:%d, ev:%04Xd, rev:%04Xd",
[469]                        fd, event_list[i].events, revents);
[470] 
[471]         if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
[472]             ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[473]                           "ioctl(DP_POLL) error fd:%d ev:%04Xd rev:%04Xd",
[474]                           fd, event_list[i].events, revents);
[475]         }
[476] 
[477]         if (revents & ~(POLLIN|POLLOUT|POLLERR|POLLHUP|POLLNVAL)) {
[478]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[479]                           "strange ioctl(DP_POLL) events "
[480]                           "fd:%d ev:%04Xd rev:%04Xd",
[481]                           fd, event_list[i].events, revents);
[482]         }
[483] 
[484]         if (revents & (POLLERR|POLLHUP|POLLNVAL)) {
[485] 
[486]             /*
[487]              * if the error events were returned, add POLLIN and POLLOUT
[488]              * to handle the events at least in one active handler
[489]              */
[490] 
[491]             revents |= POLLIN|POLLOUT;
[492]         }
[493] 
[494]         rev = c->read;
[495] 
[496]         if ((revents & POLLIN) && rev->active) {
[497]             rev->ready = 1;
[498]             rev->available = -1;
[499] 
[500]             if (flags & NGX_POST_EVENTS) {
[501]                 queue = rev->accept ? &ngx_posted_accept_events
[502]                                     : &ngx_posted_events;
[503] 
[504]                 ngx_post_event(rev, queue);
[505] 
[506]             } else {
[507]                 instance = rev->instance;
[508] 
[509]                 rev->handler(rev);
[510] 
[511]                 if (c->fd == -1 || rev->instance != instance) {
[512]                     continue;
[513]                 }
[514]             }
[515]         }
[516] 
[517]         wev = c->write;
[518] 
[519]         if ((revents & POLLOUT) && wev->active) {
[520]             wev->ready = 1;
[521] 
[522]             if (flags & NGX_POST_EVENTS) {
[523]                 ngx_post_event(wev, &ngx_posted_events);
[524] 
[525]             } else {
[526]                 wev->handler(wev);
[527]             }
[528]         }
[529]     }
[530] 
[531]     return NGX_OK;
[532] }
[533] 
[534] 
[535] static void *
[536] ngx_devpoll_create_conf(ngx_cycle_t *cycle)
[537] {
[538]     ngx_devpoll_conf_t  *dpcf;
[539] 
[540]     dpcf = ngx_palloc(cycle->pool, sizeof(ngx_devpoll_conf_t));
[541]     if (dpcf == NULL) {
[542]         return NULL;
[543]     }
[544] 
[545]     dpcf->changes = NGX_CONF_UNSET;
[546]     dpcf->events = NGX_CONF_UNSET;
[547] 
[548]     return dpcf;
[549] }
[550] 
[551] 
[552] static char *
[553] ngx_devpoll_init_conf(ngx_cycle_t *cycle, void *conf)
[554] {
[555]     ngx_devpoll_conf_t *dpcf = conf;
[556] 
[557]     ngx_conf_init_uint_value(dpcf->changes, 32);
[558]     ngx_conf_init_uint_value(dpcf->events, 32);
[559] 
[560]     return NGX_CONF_OK;
[561] }
