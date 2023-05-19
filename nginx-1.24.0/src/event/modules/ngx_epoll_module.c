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
[13] #if (NGX_TEST_BUILD_EPOLL)
[14] 
[15] /* epoll declarations */
[16] 
[17] #define EPOLLIN        0x001
[18] #define EPOLLPRI       0x002
[19] #define EPOLLOUT       0x004
[20] #define EPOLLERR       0x008
[21] #define EPOLLHUP       0x010
[22] #define EPOLLRDNORM    0x040
[23] #define EPOLLRDBAND    0x080
[24] #define EPOLLWRNORM    0x100
[25] #define EPOLLWRBAND    0x200
[26] #define EPOLLMSG       0x400
[27] 
[28] #define EPOLLRDHUP     0x2000
[29] 
[30] #define EPOLLEXCLUSIVE 0x10000000
[31] #define EPOLLONESHOT   0x40000000
[32] #define EPOLLET        0x80000000
[33] 
[34] #define EPOLL_CTL_ADD  1
[35] #define EPOLL_CTL_DEL  2
[36] #define EPOLL_CTL_MOD  3
[37] 
[38] typedef union epoll_data {
[39]     void         *ptr;
[40]     int           fd;
[41]     uint32_t      u32;
[42]     uint64_t      u64;
[43] } epoll_data_t;
[44] 
[45] struct epoll_event {
[46]     uint32_t      events;
[47]     epoll_data_t  data;
[48] };
[49] 
[50] 
[51] int epoll_create(int size);
[52] 
[53] int epoll_create(int size)
[54] {
[55]     return -1;
[56] }
[57] 
[58] 
[59] int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
[60] 
[61] int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
[62] {
[63]     return -1;
[64] }
[65] 
[66] 
[67] int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);
[68] 
[69] int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
[70] {
[71]     return -1;
[72] }
[73] 
[74] #if (NGX_HAVE_EVENTFD)
[75] #define SYS_eventfd       323
[76] #endif
[77] 
[78] #if (NGX_HAVE_FILE_AIO)
[79] 
[80] #define SYS_io_setup      245
[81] #define SYS_io_destroy    246
[82] #define SYS_io_getevents  247
[83] 
[84] typedef u_int  aio_context_t;
[85] 
[86] struct io_event {
[87]     uint64_t  data;  /* the data field from the iocb */
[88]     uint64_t  obj;   /* what iocb this event came from */
[89]     int64_t   res;   /* result code for this event */
[90]     int64_t   res2;  /* secondary result */
[91] };
[92] 
[93] 
[94] #endif
[95] #endif /* NGX_TEST_BUILD_EPOLL */
[96] 
[97] 
[98] typedef struct {
[99]     ngx_uint_t  events;
[100]     ngx_uint_t  aio_requests;
[101] } ngx_epoll_conf_t;
[102] 
[103] 
[104] static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[105] #if (NGX_HAVE_EVENTFD)
[106] static ngx_int_t ngx_epoll_notify_init(ngx_log_t *log);
[107] static void ngx_epoll_notify_handler(ngx_event_t *ev);
[108] #endif
[109] #if (NGX_HAVE_EPOLLRDHUP)
[110] static void ngx_epoll_test_rdhup(ngx_cycle_t *cycle);
[111] #endif
[112] static void ngx_epoll_done(ngx_cycle_t *cycle);
[113] static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
[114]     ngx_uint_t flags);
[115] static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
[116]     ngx_uint_t flags);
[117] static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
[118] static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
[119]     ngx_uint_t flags);
[120] #if (NGX_HAVE_EVENTFD)
[121] static ngx_int_t ngx_epoll_notify(ngx_event_handler_pt handler);
[122] #endif
[123] static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[124]     ngx_uint_t flags);
[125] 
[126] #if (NGX_HAVE_FILE_AIO)
[127] static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
[128] #endif
[129] 
[130] static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
[131] static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);
[132] 
[133] static int                  ep = -1;
[134] static struct epoll_event  *event_list;
[135] static ngx_uint_t           nevents;
[136] 
[137] #if (NGX_HAVE_EVENTFD)
[138] static int                  notify_fd = -1;
[139] static ngx_event_t          notify_event;
[140] static ngx_connection_t     notify_conn;
[141] #endif
[142] 
[143] #if (NGX_HAVE_FILE_AIO)
[144] 
[145] int                         ngx_eventfd = -1;
[146] aio_context_t               ngx_aio_ctx = 0;
[147] 
[148] static ngx_event_t          ngx_eventfd_event;
[149] static ngx_connection_t     ngx_eventfd_conn;
[150] 
[151] #endif
[152] 
[153] #if (NGX_HAVE_EPOLLRDHUP)
[154] ngx_uint_t                  ngx_use_epoll_rdhup;
[155] #endif
[156] 
[157] static ngx_str_t      epoll_name = ngx_string("epoll");
[158] 
[159] static ngx_command_t  ngx_epoll_commands[] = {
[160] 
[161]     { ngx_string("epoll_events"),
[162]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[163]       ngx_conf_set_num_slot,
[164]       0,
[165]       offsetof(ngx_epoll_conf_t, events),
[166]       NULL },
[167] 
[168]     { ngx_string("worker_aio_requests"),
[169]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[170]       ngx_conf_set_num_slot,
[171]       0,
[172]       offsetof(ngx_epoll_conf_t, aio_requests),
[173]       NULL },
[174] 
[175]       ngx_null_command
[176] };
[177] 
[178] 
[179] static ngx_event_module_t  ngx_epoll_module_ctx = {
[180]     &epoll_name,
[181]     ngx_epoll_create_conf,               /* create configuration */
[182]     ngx_epoll_init_conf,                 /* init configuration */
[183] 
[184]     {
[185]         ngx_epoll_add_event,             /* add an event */
[186]         ngx_epoll_del_event,             /* delete an event */
[187]         ngx_epoll_add_event,             /* enable an event */
[188]         ngx_epoll_del_event,             /* disable an event */
[189]         ngx_epoll_add_connection,        /* add an connection */
[190]         ngx_epoll_del_connection,        /* delete an connection */
[191] #if (NGX_HAVE_EVENTFD)
[192]         ngx_epoll_notify,                /* trigger a notify */
[193] #else
[194]         NULL,                            /* trigger a notify */
[195] #endif
[196]         ngx_epoll_process_events,        /* process the events */
[197]         ngx_epoll_init,                  /* init the events */
[198]         ngx_epoll_done,                  /* done the events */
[199]     }
[200] };
[201] 
[202] ngx_module_t  ngx_epoll_module = {
[203]     NGX_MODULE_V1,
[204]     &ngx_epoll_module_ctx,               /* module context */
[205]     ngx_epoll_commands,                  /* module directives */
[206]     NGX_EVENT_MODULE,                    /* module type */
[207]     NULL,                                /* init master */
[208]     NULL,                                /* init module */
[209]     NULL,                                /* init process */
[210]     NULL,                                /* init thread */
[211]     NULL,                                /* exit thread */
[212]     NULL,                                /* exit process */
[213]     NULL,                                /* exit master */
[214]     NGX_MODULE_V1_PADDING
[215] };
[216] 
[217] 
[218] #if (NGX_HAVE_FILE_AIO)
[219] 
[220] /*
[221]  * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
[222]  * as syscalls instead of libaio usage, because the library header file
[223]  * supports eventfd() since 0.3.107 version only.
[224]  */
[225] 
[226] static int
[227] io_setup(u_int nr_reqs, aio_context_t *ctx)
[228] {
[229]     return syscall(SYS_io_setup, nr_reqs, ctx);
[230] }
[231] 
[232] 
[233] static int
[234] io_destroy(aio_context_t ctx)
[235] {
[236]     return syscall(SYS_io_destroy, ctx);
[237] }
[238] 
[239] 
[240] static int
[241] io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
[242]     struct timespec *tmo)
[243] {
[244]     return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
[245] }
[246] 
[247] 
[248] static void
[249] ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
[250] {
[251]     int                 n;
[252]     struct epoll_event  ee;
[253] 
[254] #if (NGX_HAVE_SYS_EVENTFD_H)
[255]     ngx_eventfd = eventfd(0, 0);
[256] #else
[257]     ngx_eventfd = syscall(SYS_eventfd, 0);
[258] #endif
[259] 
[260]     if (ngx_eventfd == -1) {
[261]         ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[262]                       "eventfd() failed");
[263]         ngx_file_aio = 0;
[264]         return;
[265]     }
[266] 
[267]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[268]                    "eventfd: %d", ngx_eventfd);
[269] 
[270]     n = 1;
[271] 
[272]     if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
[273]         ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[274]                       "ioctl(eventfd, FIONBIO) failed");
[275]         goto failed;
[276]     }
[277] 
[278]     if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
[279]         ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[280]                       "io_setup() failed");
[281]         goto failed;
[282]     }
[283] 
[284]     ngx_eventfd_event.data = &ngx_eventfd_conn;
[285]     ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
[286]     ngx_eventfd_event.log = cycle->log;
[287]     ngx_eventfd_event.active = 1;
[288]     ngx_eventfd_conn.fd = ngx_eventfd;
[289]     ngx_eventfd_conn.read = &ngx_eventfd_event;
[290]     ngx_eventfd_conn.log = cycle->log;
[291] 
[292]     ee.events = EPOLLIN|EPOLLET;
[293]     ee.data.ptr = &ngx_eventfd_conn;
[294] 
[295]     if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
[296]         return;
[297]     }
[298] 
[299]     ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[300]                   "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");
[301] 
[302]     if (io_destroy(ngx_aio_ctx) == -1) {
[303]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[304]                       "io_destroy() failed");
[305]     }
[306] 
[307] failed:
[308] 
[309]     if (close(ngx_eventfd) == -1) {
[310]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[311]                       "eventfd close() failed");
[312]     }
[313] 
[314]     ngx_eventfd = -1;
[315]     ngx_aio_ctx = 0;
[316]     ngx_file_aio = 0;
[317] }
[318] 
[319] #endif
[320] 
[321] 
[322] static ngx_int_t
[323] ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[324] {
[325]     ngx_epoll_conf_t  *epcf;
[326] 
[327]     epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);
[328] 
[329]     if (ep == -1) {
[330]         ep = epoll_create(cycle->connection_n / 2);
[331] 
[332]         if (ep == -1) {
[333]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[334]                           "epoll_create() failed");
[335]             return NGX_ERROR;
[336]         }
[337] 
[338] #if (NGX_HAVE_EVENTFD)
[339]         if (ngx_epoll_notify_init(cycle->log) != NGX_OK) {
[340]             ngx_epoll_module_ctx.actions.notify = NULL;
[341]         }
[342] #endif
[343] 
[344] #if (NGX_HAVE_FILE_AIO)
[345]         ngx_epoll_aio_init(cycle, epcf);
[346] #endif
[347] 
[348] #if (NGX_HAVE_EPOLLRDHUP)
[349]         ngx_epoll_test_rdhup(cycle);
[350] #endif
[351]     }
[352] 
[353]     if (nevents < epcf->events) {
[354]         if (event_list) {
[355]             ngx_free(event_list);
[356]         }
[357] 
[358]         event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
[359]                                cycle->log);
[360]         if (event_list == NULL) {
[361]             return NGX_ERROR;
[362]         }
[363]     }
[364] 
[365]     nevents = epcf->events;
[366] 
[367]     ngx_io = ngx_os_io;
[368] 
[369]     ngx_event_actions = ngx_epoll_module_ctx.actions;
[370] 
[371] #if (NGX_HAVE_CLEAR_EVENT)
[372]     ngx_event_flags = NGX_USE_CLEAR_EVENT
[373] #else
[374]     ngx_event_flags = NGX_USE_LEVEL_EVENT
[375] #endif
[376]                       |NGX_USE_GREEDY_EVENT
[377]                       |NGX_USE_EPOLL_EVENT;
[378] 
[379]     return NGX_OK;
[380] }
[381] 
[382] 
[383] #if (NGX_HAVE_EVENTFD)
[384] 
[385] static ngx_int_t
[386] ngx_epoll_notify_init(ngx_log_t *log)
[387] {
[388]     struct epoll_event  ee;
[389] 
[390] #if (NGX_HAVE_SYS_EVENTFD_H)
[391]     notify_fd = eventfd(0, 0);
[392] #else
[393]     notify_fd = syscall(SYS_eventfd, 0);
[394] #endif
[395] 
[396]     if (notify_fd == -1) {
[397]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "eventfd() failed");
[398]         return NGX_ERROR;
[399]     }
[400] 
[401]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
[402]                    "notify eventfd: %d", notify_fd);
[403] 
[404]     notify_event.handler = ngx_epoll_notify_handler;
[405]     notify_event.log = log;
[406]     notify_event.active = 1;
[407] 
[408]     notify_conn.fd = notify_fd;
[409]     notify_conn.read = &notify_event;
[410]     notify_conn.log = log;
[411] 
[412]     ee.events = EPOLLIN|EPOLLET;
[413]     ee.data.ptr = &notify_conn;
[414] 
[415]     if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
[416]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[417]                       "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");
[418] 
[419]         if (close(notify_fd) == -1) {
[420]             ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[421]                             "eventfd close() failed");
[422]         }
[423] 
[424]         return NGX_ERROR;
[425]     }
[426] 
[427]     return NGX_OK;
[428] }
[429] 
[430] 
[431] static void
[432] ngx_epoll_notify_handler(ngx_event_t *ev)
[433] {
[434]     ssize_t               n;
[435]     uint64_t              count;
[436]     ngx_err_t             err;
[437]     ngx_event_handler_pt  handler;
[438] 
[439]     if (++ev->index == NGX_MAX_UINT32_VALUE) {
[440]         ev->index = 0;
[441] 
[442]         n = read(notify_fd, &count, sizeof(uint64_t));
[443] 
[444]         err = ngx_errno;
[445] 
[446]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[447]                        "read() eventfd %d: %z count:%uL", notify_fd, n, count);
[448] 
[449]         if ((size_t) n != sizeof(uint64_t)) {
[450]             ngx_log_error(NGX_LOG_ALERT, ev->log, err,
[451]                           "read() eventfd %d failed", notify_fd);
[452]         }
[453]     }
[454] 
[455]     handler = ev->data;
[456]     handler(ev);
[457] }
[458] 
[459] #endif
[460] 
[461] 
[462] #if (NGX_HAVE_EPOLLRDHUP)
[463] 
[464] static void
[465] ngx_epoll_test_rdhup(ngx_cycle_t *cycle)
[466] {
[467]     int                 s[2], events;
[468]     struct epoll_event  ee;
[469] 
[470]     if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == -1) {
[471]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[472]                       "socketpair() failed");
[473]         return;
[474]     }
[475] 
[476]     ee.events = EPOLLET|EPOLLIN|EPOLLRDHUP;
[477] 
[478]     if (epoll_ctl(ep, EPOLL_CTL_ADD, s[0], &ee) == -1) {
[479]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[480]                       "epoll_ctl() failed");
[481]         goto failed;
[482]     }
[483] 
[484]     if (close(s[1]) == -1) {
[485]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[486]                       "close() failed");
[487]         s[1] = -1;
[488]         goto failed;
[489]     }
[490] 
[491]     s[1] = -1;
[492] 
[493]     events = epoll_wait(ep, &ee, 1, 5000);
[494] 
[495]     if (events == -1) {
[496]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[497]                       "epoll_wait() failed");
[498]         goto failed;
[499]     }
[500] 
[501]     if (events) {
[502]         ngx_use_epoll_rdhup = ee.events & EPOLLRDHUP;
[503] 
[504]     } else {
[505]         ngx_log_error(NGX_LOG_ALERT, cycle->log, NGX_ETIMEDOUT,
[506]                       "epoll_wait() timed out");
[507]     }
[508] 
[509]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[510]                    "testing the EPOLLRDHUP flag: %s",
[511]                    ngx_use_epoll_rdhup ? "success" : "fail");
[512] 
[513] failed:
[514] 
[515]     if (s[1] != -1 && close(s[1]) == -1) {
[516]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[517]                       "close() failed");
[518]     }
[519] 
[520]     if (close(s[0]) == -1) {
[521]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[522]                       "close() failed");
[523]     }
[524] }
[525] 
[526] #endif
[527] 
[528] 
[529] static void
[530] ngx_epoll_done(ngx_cycle_t *cycle)
[531] {
[532]     if (close(ep) == -1) {
[533]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[534]                       "epoll close() failed");
[535]     }
[536] 
[537]     ep = -1;
[538] 
[539] #if (NGX_HAVE_EVENTFD)
[540] 
[541]     if (close(notify_fd) == -1) {
[542]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[543]                       "eventfd close() failed");
[544]     }
[545] 
[546]     notify_fd = -1;
[547] 
[548] #endif
[549] 
[550] #if (NGX_HAVE_FILE_AIO)
[551] 
[552]     if (ngx_eventfd != -1) {
[553] 
[554]         if (io_destroy(ngx_aio_ctx) == -1) {
[555]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[556]                           "io_destroy() failed");
[557]         }
[558] 
[559]         if (close(ngx_eventfd) == -1) {
[560]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[561]                           "eventfd close() failed");
[562]         }
[563] 
[564]         ngx_eventfd = -1;
[565]     }
[566] 
[567]     ngx_aio_ctx = 0;
[568] 
[569] #endif
[570] 
[571]     ngx_free(event_list);
[572] 
[573]     event_list = NULL;
[574]     nevents = 0;
[575] }
[576] 
[577] 
[578] static ngx_int_t
[579] ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[580] {
[581]     int                  op;
[582]     uint32_t             events, prev;
[583]     ngx_event_t         *e;
[584]     ngx_connection_t    *c;
[585]     struct epoll_event   ee;
[586] 
[587]     c = ev->data;
[588] 
[589]     events = (uint32_t) event;
[590] 
[591]     if (event == NGX_READ_EVENT) {
[592]         e = c->write;
[593]         prev = EPOLLOUT;
[594] #if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
[595]         events = EPOLLIN|EPOLLRDHUP;
[596] #endif
[597] 
[598]     } else {
[599]         e = c->read;
[600]         prev = EPOLLIN|EPOLLRDHUP;
[601] #if (NGX_WRITE_EVENT != EPOLLOUT)
[602]         events = EPOLLOUT;
[603] #endif
[604]     }
[605] 
[606]     if (e->active) {
[607]         op = EPOLL_CTL_MOD;
[608]         events |= prev;
[609] 
[610]     } else {
[611]         op = EPOLL_CTL_ADD;
[612]     }
[613] 
[614] #if (NGX_HAVE_EPOLLEXCLUSIVE && NGX_HAVE_EPOLLRDHUP)
[615]     if (flags & NGX_EXCLUSIVE_EVENT) {
[616]         events &= ~EPOLLRDHUP;
[617]     }
[618] #endif
[619] 
[620]     ee.events = events | (uint32_t) flags;
[621]     ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);
[622] 
[623]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[624]                    "epoll add event: fd:%d op:%d ev:%08XD",
[625]                    c->fd, op, ee.events);
[626] 
[627]     if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
[628]         ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[629]                       "epoll_ctl(%d, %d) failed", op, c->fd);
[630]         return NGX_ERROR;
[631]     }
[632] 
[633]     ev->active = 1;
[634] #if 0
[635]     ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
[636] #endif
[637] 
[638]     return NGX_OK;
[639] }
[640] 
[641] 
[642] static ngx_int_t
[643] ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[644] {
[645]     int                  op;
[646]     uint32_t             prev;
[647]     ngx_event_t         *e;
[648]     ngx_connection_t    *c;
[649]     struct epoll_event   ee;
[650] 
[651]     /*
[652]      * when the file descriptor is closed, the epoll automatically deletes
[653]      * it from its queue, so we do not need to delete explicitly the event
[654]      * before the closing the file descriptor
[655]      */
[656] 
[657]     if (flags & NGX_CLOSE_EVENT) {
[658]         ev->active = 0;
[659]         return NGX_OK;
[660]     }
[661] 
[662]     c = ev->data;
[663] 
[664]     if (event == NGX_READ_EVENT) {
[665]         e = c->write;
[666]         prev = EPOLLOUT;
[667] 
[668]     } else {
[669]         e = c->read;
[670]         prev = EPOLLIN|EPOLLRDHUP;
[671]     }
[672] 
[673]     if (e->active) {
[674]         op = EPOLL_CTL_MOD;
[675]         ee.events = prev | (uint32_t) flags;
[676]         ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);
[677] 
[678]     } else {
[679]         op = EPOLL_CTL_DEL;
[680]         ee.events = 0;
[681]         ee.data.ptr = NULL;
[682]     }
[683] 
[684]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[685]                    "epoll del event: fd:%d op:%d ev:%08XD",
[686]                    c->fd, op, ee.events);
[687] 
[688]     if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
[689]         ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[690]                       "epoll_ctl(%d, %d) failed", op, c->fd);
[691]         return NGX_ERROR;
[692]     }
[693] 
[694]     ev->active = 0;
[695] 
[696]     return NGX_OK;
[697] }
[698] 
[699] 
[700] static ngx_int_t
[701] ngx_epoll_add_connection(ngx_connection_t *c)
[702] {
[703]     struct epoll_event  ee;
[704] 
[705]     ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
[706]     ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);
[707] 
[708]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
[709]                    "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);
[710] 
[711]     if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
[712]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[713]                       "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
[714]         return NGX_ERROR;
[715]     }
[716] 
[717]     c->read->active = 1;
[718]     c->write->active = 1;
[719] 
[720]     return NGX_OK;
[721] }
[722] 
[723] 
[724] static ngx_int_t
[725] ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
[726] {
[727]     int                 op;
[728]     struct epoll_event  ee;
[729] 
[730]     /*
[731]      * when the file descriptor is closed the epoll automatically deletes
[732]      * it from its queue so we do not need to delete explicitly the event
[733]      * before the closing the file descriptor
[734]      */
[735] 
[736]     if (flags & NGX_CLOSE_EVENT) {
[737]         c->read->active = 0;
[738]         c->write->active = 0;
[739]         return NGX_OK;
[740]     }
[741] 
[742]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
[743]                    "epoll del connection: fd:%d", c->fd);
[744] 
[745]     op = EPOLL_CTL_DEL;
[746]     ee.events = 0;
[747]     ee.data.ptr = NULL;
[748] 
[749]     if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
[750]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[751]                       "epoll_ctl(%d, %d) failed", op, c->fd);
[752]         return NGX_ERROR;
[753]     }
[754] 
[755]     c->read->active = 0;
[756]     c->write->active = 0;
[757] 
[758]     return NGX_OK;
[759] }
[760] 
[761] 
[762] #if (NGX_HAVE_EVENTFD)
[763] 
[764] static ngx_int_t
[765] ngx_epoll_notify(ngx_event_handler_pt handler)
[766] {
[767]     static uint64_t inc = 1;
[768] 
[769]     notify_event.data = handler;
[770] 
[771]     if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
[772]         ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
[773]                       "write() to eventfd %d failed", notify_fd);
[774]         return NGX_ERROR;
[775]     }
[776] 
[777]     return NGX_OK;
[778] }
[779] 
[780] #endif
[781] 
[782] 
[783] static ngx_int_t
[784] ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
[785] {
[786]     int                events;
[787]     uint32_t           revents;
[788]     ngx_int_t          instance, i;
[789]     ngx_uint_t         level;
[790]     ngx_err_t          err;
[791]     ngx_event_t       *rev, *wev;
[792]     ngx_queue_t       *queue;
[793]     ngx_connection_t  *c;
[794] 
[795]     /* NGX_TIMER_INFINITE == INFTIM */
[796] 
[797]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[798]                    "epoll timer: %M", timer);
[799] 
[800]     events = epoll_wait(ep, event_list, (int) nevents, timer);
[801] 
[802]     err = (events == -1) ? ngx_errno : 0;
[803] 
[804]     if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
[805]         ngx_time_update();
[806]     }
[807] 
[808]     if (err) {
[809]         if (err == NGX_EINTR) {
[810] 
[811]             if (ngx_event_timer_alarm) {
[812]                 ngx_event_timer_alarm = 0;
[813]                 return NGX_OK;
[814]             }
[815] 
[816]             level = NGX_LOG_INFO;
[817] 
[818]         } else {
[819]             level = NGX_LOG_ALERT;
[820]         }
[821] 
[822]         ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
[823]         return NGX_ERROR;
[824]     }
[825] 
[826]     if (events == 0) {
[827]         if (timer != NGX_TIMER_INFINITE) {
[828]             return NGX_OK;
[829]         }
[830] 
[831]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[832]                       "epoll_wait() returned no events without timeout");
[833]         return NGX_ERROR;
[834]     }
[835] 
[836]     for (i = 0; i < events; i++) {
[837]         c = event_list[i].data.ptr;
[838] 
[839]         instance = (uintptr_t) c & 1;
[840]         c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);
[841] 
[842]         rev = c->read;
[843] 
[844]         if (c->fd == -1 || rev->instance != instance) {
[845] 
[846]             /*
[847]              * the stale event from a file descriptor
[848]              * that was just closed in this iteration
[849]              */
[850] 
[851]             ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[852]                            "epoll: stale event %p", c);
[853]             continue;
[854]         }
[855] 
[856]         revents = event_list[i].events;
[857] 
[858]         ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[859]                        "epoll: fd:%d ev:%04XD d:%p",
[860]                        c->fd, revents, event_list[i].data.ptr);
[861] 
[862]         if (revents & (EPOLLERR|EPOLLHUP)) {
[863]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[864]                            "epoll_wait() error on fd:%d ev:%04XD",
[865]                            c->fd, revents);
[866] 
[867]             /*
[868]              * if the error events were returned, add EPOLLIN and EPOLLOUT
[869]              * to handle the events at least in one active handler
[870]              */
[871] 
[872]             revents |= EPOLLIN|EPOLLOUT;
[873]         }
[874] 
[875] #if 0
[876]         if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
[877]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[878]                           "strange epoll_wait() events fd:%d ev:%04XD",
[879]                           c->fd, revents);
[880]         }
[881] #endif
[882] 
[883]         if ((revents & EPOLLIN) && rev->active) {
[884] 
[885] #if (NGX_HAVE_EPOLLRDHUP)
[886]             if (revents & EPOLLRDHUP) {
[887]                 rev->pending_eof = 1;
[888]             }
[889] #endif
[890] 
[891]             rev->ready = 1;
[892]             rev->available = -1;
[893] 
[894]             if (flags & NGX_POST_EVENTS) {
[895]                 queue = rev->accept ? &ngx_posted_accept_events
[896]                                     : &ngx_posted_events;
[897] 
[898]                 ngx_post_event(rev, queue);
[899] 
[900]             } else {
[901]                 rev->handler(rev);
[902]             }
[903]         }
[904] 
[905]         wev = c->write;
[906] 
[907]         if ((revents & EPOLLOUT) && wev->active) {
[908] 
[909]             if (c->fd == -1 || wev->instance != instance) {
[910] 
[911]                 /*
[912]                  * the stale event from a file descriptor
[913]                  * that was just closed in this iteration
[914]                  */
[915] 
[916]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[917]                                "epoll: stale event %p", c);
[918]                 continue;
[919]             }
[920] 
[921]             wev->ready = 1;
[922] #if (NGX_THREADS)
[923]             wev->complete = 1;
[924] #endif
[925] 
[926]             if (flags & NGX_POST_EVENTS) {
[927]                 ngx_post_event(wev, &ngx_posted_events);
[928] 
[929]             } else {
[930]                 wev->handler(wev);
[931]             }
[932]         }
[933]     }
[934] 
[935]     return NGX_OK;
[936] }
[937] 
[938] 
[939] #if (NGX_HAVE_FILE_AIO)
[940] 
[941] static void
[942] ngx_epoll_eventfd_handler(ngx_event_t *ev)
[943] {
[944]     int               n, events;
[945]     long              i;
[946]     uint64_t          ready;
[947]     ngx_err_t         err;
[948]     ngx_event_t      *e;
[949]     ngx_event_aio_t  *aio;
[950]     struct io_event   event[64];
[951]     struct timespec   ts;
[952] 
[953]     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");
[954] 
[955]     n = read(ngx_eventfd, &ready, 8);
[956] 
[957]     err = ngx_errno;
[958] 
[959]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);
[960] 
[961]     if (n != 8) {
[962]         if (n == -1) {
[963]             if (err == NGX_EAGAIN) {
[964]                 return;
[965]             }
[966] 
[967]             ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
[968]             return;
[969]         }
[970] 
[971]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[972]                       "read(eventfd) returned only %d bytes", n);
[973]         return;
[974]     }
[975] 
[976]     ts.tv_sec = 0;
[977]     ts.tv_nsec = 0;
[978] 
[979]     while (ready) {
[980] 
[981]         events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);
[982] 
[983]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[984]                        "io_getevents: %d", events);
[985] 
[986]         if (events > 0) {
[987]             ready -= events;
[988] 
[989]             for (i = 0; i < events; i++) {
[990] 
[991]                 ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[992]                                "io_event: %XL %XL %L %L",
[993]                                 event[i].data, event[i].obj,
[994]                                 event[i].res, event[i].res2);
[995] 
[996]                 e = (ngx_event_t *) (uintptr_t) event[i].data;
[997] 
[998]                 e->complete = 1;
[999]                 e->active = 0;
[1000]                 e->ready = 1;
[1001] 
[1002]                 aio = e->data;
[1003]                 aio->res = event[i].res;
[1004] 
[1005]                 ngx_post_event(e, &ngx_posted_events);
[1006]             }
[1007] 
[1008]             continue;
[1009]         }
[1010] 
[1011]         if (events == 0) {
[1012]             return;
[1013]         }
[1014] 
[1015]         /* events == -1 */
[1016]         ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
[1017]                       "io_getevents() failed");
[1018]         return;
[1019]     }
[1020] }
[1021] 
[1022] #endif
[1023] 
[1024] 
[1025] static void *
[1026] ngx_epoll_create_conf(ngx_cycle_t *cycle)
[1027] {
[1028]     ngx_epoll_conf_t  *epcf;
[1029] 
[1030]     epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
[1031]     if (epcf == NULL) {
[1032]         return NULL;
[1033]     }
[1034] 
[1035]     epcf->events = NGX_CONF_UNSET;
[1036]     epcf->aio_requests = NGX_CONF_UNSET;
[1037] 
[1038]     return epcf;
[1039] }
[1040] 
[1041] 
[1042] static char *
[1043] ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
[1044] {
[1045]     ngx_epoll_conf_t *epcf = conf;
[1046] 
[1047]     ngx_conf_init_uint_value(epcf->events, 512);
[1048]     ngx_conf_init_uint_value(epcf->aio_requests, 32);
[1049] 
[1050]     return NGX_CONF_OK;
[1051] }
