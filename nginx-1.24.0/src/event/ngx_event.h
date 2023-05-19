[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_EVENT_H_INCLUDED_
[9] #define _NGX_EVENT_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_INVALID_INDEX  0xd0d0d0d0
[17] 
[18] 
[19] #if (NGX_HAVE_IOCP)
[20] 
[21] typedef struct {
[22]     WSAOVERLAPPED    ovlp;
[23]     ngx_event_t     *event;
[24]     int              error;
[25] } ngx_event_ovlp_t;
[26] 
[27] #endif
[28] 
[29] 
[30] struct ngx_event_s {
[31]     void            *data;
[32] 
[33]     unsigned         write:1;
[34] 
[35]     unsigned         accept:1;
[36] 
[37]     /* used to detect the stale events in kqueue and epoll */
[38]     unsigned         instance:1;
[39] 
[40]     /*
[41]      * the event was passed or would be passed to a kernel;
[42]      * in aio mode - operation was posted.
[43]      */
[44]     unsigned         active:1;
[45] 
[46]     unsigned         disabled:1;
[47] 
[48]     /* the ready event; in aio mode 0 means that no operation can be posted */
[49]     unsigned         ready:1;
[50] 
[51]     unsigned         oneshot:1;
[52] 
[53]     /* aio operation is complete */
[54]     unsigned         complete:1;
[55] 
[56]     unsigned         eof:1;
[57]     unsigned         error:1;
[58] 
[59]     unsigned         timedout:1;
[60]     unsigned         timer_set:1;
[61] 
[62]     unsigned         delayed:1;
[63] 
[64]     unsigned         deferred_accept:1;
[65] 
[66]     /* the pending eof reported by kqueue, epoll or in aio chain operation */
[67]     unsigned         pending_eof:1;
[68] 
[69]     unsigned         posted:1;
[70] 
[71]     unsigned         closed:1;
[72] 
[73]     /* to test on worker exit */
[74]     unsigned         channel:1;
[75]     unsigned         resolver:1;
[76] 
[77]     unsigned         cancelable:1;
[78] 
[79] #if (NGX_HAVE_KQUEUE)
[80]     unsigned         kq_vnode:1;
[81] 
[82]     /* the pending errno reported by kqueue */
[83]     int              kq_errno;
[84] #endif
[85] 
[86]     /*
[87]      * kqueue only:
[88]      *   accept:     number of sockets that wait to be accepted
[89]      *   read:       bytes to read when event is ready
[90]      *               or lowat when event is set with NGX_LOWAT_EVENT flag
[91]      *   write:      available space in buffer when event is ready
[92]      *               or lowat when event is set with NGX_LOWAT_EVENT flag
[93]      *
[94]      * iocp: TODO
[95]      *
[96]      * otherwise:
[97]      *   accept:     1 if accept many, 0 otherwise
[98]      *   read:       bytes to read when event is ready, -1 if not known
[99]      */
[100] 
[101]     int              available;
[102] 
[103]     ngx_event_handler_pt  handler;
[104] 
[105] 
[106] #if (NGX_HAVE_IOCP)
[107]     ngx_event_ovlp_t ovlp;
[108] #endif
[109] 
[110]     ngx_uint_t       index;
[111] 
[112]     ngx_log_t       *log;
[113] 
[114]     ngx_rbtree_node_t   timer;
[115] 
[116]     /* the posted queue */
[117]     ngx_queue_t      queue;
[118] 
[119] #if 0
[120] 
[121]     /* the threads support */
[122] 
[123]     /*
[124]      * the event thread context, we store it here
[125]      * if $(CC) does not understand __thread declaration
[126]      * and pthread_getspecific() is too costly
[127]      */
[128] 
[129]     void            *thr_ctx;
[130] 
[131] #if (NGX_EVENT_T_PADDING)
[132] 
[133]     /* event should not cross cache line in SMP */
[134] 
[135]     uint32_t         padding[NGX_EVENT_T_PADDING];
[136] #endif
[137] #endif
[138] };
[139] 
[140] 
[141] #if (NGX_HAVE_FILE_AIO)
[142] 
[143] struct ngx_event_aio_s {
[144]     void                      *data;
[145]     ngx_event_handler_pt       handler;
[146]     ngx_file_t                *file;
[147] 
[148]     ngx_fd_t                   fd;
[149] 
[150] #if (NGX_HAVE_EVENTFD)
[151]     int64_t                    res;
[152] #endif
[153] 
[154] #if !(NGX_HAVE_EVENTFD) || (NGX_TEST_BUILD_EPOLL)
[155]     ngx_err_t                  err;
[156]     size_t                     nbytes;
[157] #endif
[158] 
[159]     ngx_aiocb_t                aiocb;
[160]     ngx_event_t                event;
[161] };
[162] 
[163] #endif
[164] 
[165] 
[166] typedef struct {
[167]     ngx_int_t  (*add)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
[168]     ngx_int_t  (*del)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
[169] 
[170]     ngx_int_t  (*enable)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
[171]     ngx_int_t  (*disable)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
[172] 
[173]     ngx_int_t  (*add_conn)(ngx_connection_t *c);
[174]     ngx_int_t  (*del_conn)(ngx_connection_t *c, ngx_uint_t flags);
[175] 
[176]     ngx_int_t  (*notify)(ngx_event_handler_pt handler);
[177] 
[178]     ngx_int_t  (*process_events)(ngx_cycle_t *cycle, ngx_msec_t timer,
[179]                                  ngx_uint_t flags);
[180] 
[181]     ngx_int_t  (*init)(ngx_cycle_t *cycle, ngx_msec_t timer);
[182]     void       (*done)(ngx_cycle_t *cycle);
[183] } ngx_event_actions_t;
[184] 
[185] 
[186] extern ngx_event_actions_t   ngx_event_actions;
[187] #if (NGX_HAVE_EPOLLRDHUP)
[188] extern ngx_uint_t            ngx_use_epoll_rdhup;
[189] #endif
[190] 
[191] 
[192] /*
[193]  * The event filter requires to read/write the whole data:
[194]  * select, poll, /dev/poll, kqueue, epoll.
[195]  */
[196] #define NGX_USE_LEVEL_EVENT      0x00000001
[197] 
[198] /*
[199]  * The event filter is deleted after a notification without an additional
[200]  * syscall: kqueue, epoll.
[201]  */
[202] #define NGX_USE_ONESHOT_EVENT    0x00000002
[203] 
[204] /*
[205]  * The event filter notifies only the changes and an initial level:
[206]  * kqueue, epoll.
[207]  */
[208] #define NGX_USE_CLEAR_EVENT      0x00000004
[209] 
[210] /*
[211]  * The event filter has kqueue features: the eof flag, errno,
[212]  * available data, etc.
[213]  */
[214] #define NGX_USE_KQUEUE_EVENT     0x00000008
[215] 
[216] /*
[217]  * The event filter supports low water mark: kqueue's NOTE_LOWAT.
[218]  * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
[219]  */
[220] #define NGX_USE_LOWAT_EVENT      0x00000010
[221] 
[222] /*
[223]  * The event filter requires to do i/o operation until EAGAIN: epoll.
[224]  */
[225] #define NGX_USE_GREEDY_EVENT     0x00000020
[226] 
[227] /*
[228]  * The event filter is epoll.
[229]  */
[230] #define NGX_USE_EPOLL_EVENT      0x00000040
[231] 
[232] /*
[233]  * Obsolete.
[234]  */
[235] #define NGX_USE_RTSIG_EVENT      0x00000080
[236] 
[237] /*
[238]  * Obsolete.
[239]  */
[240] #define NGX_USE_AIO_EVENT        0x00000100
[241] 
[242] /*
[243]  * Need to add socket or handle only once: i/o completion port.
[244]  */
[245] #define NGX_USE_IOCP_EVENT       0x00000200
[246] 
[247] /*
[248]  * The event filter has no opaque data and requires file descriptors table:
[249]  * poll, /dev/poll.
[250]  */
[251] #define NGX_USE_FD_EVENT         0x00000400
[252] 
[253] /*
[254]  * The event module handles periodic or absolute timer event by itself:
[255]  * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
[256]  */
[257] #define NGX_USE_TIMER_EVENT      0x00000800
[258] 
[259] /*
[260]  * All event filters on file descriptor are deleted after a notification:
[261]  * Solaris 10's event ports.
[262]  */
[263] #define NGX_USE_EVENTPORT_EVENT  0x00001000
[264] 
[265] /*
[266]  * The event filter support vnode notifications: kqueue.
[267]  */
[268] #define NGX_USE_VNODE_EVENT      0x00002000
[269] 
[270] 
[271] /*
[272]  * The event filter is deleted just before the closing file.
[273]  * Has no meaning for select and poll.
[274]  * kqueue, epoll, eventport:         allows to avoid explicit delete,
[275]  *                                   because filter automatically is deleted
[276]  *                                   on file close,
[277]  *
[278]  * /dev/poll:                        we need to flush POLLREMOVE event
[279]  *                                   before closing file.
[280]  */
[281] #define NGX_CLOSE_EVENT    1
[282] 
[283] /*
[284]  * disable temporarily event filter, this may avoid locks
[285]  * in kernel malloc()/free(): kqueue.
[286]  */
[287] #define NGX_DISABLE_EVENT  2
[288] 
[289] /*
[290]  * event must be passed to kernel right now, do not wait until batch processing.
[291]  */
[292] #define NGX_FLUSH_EVENT    4
[293] 
[294] 
[295] /* these flags have a meaning only for kqueue */
[296] #define NGX_LOWAT_EVENT    0
[297] #define NGX_VNODE_EVENT    0
[298] 
[299] 
[300] #if (NGX_HAVE_EPOLL) && !(NGX_HAVE_EPOLLRDHUP)
[301] #define EPOLLRDHUP         0
[302] #endif
[303] 
[304] 
[305] #if (NGX_HAVE_KQUEUE)
[306] 
[307] #define NGX_READ_EVENT     EVFILT_READ
[308] #define NGX_WRITE_EVENT    EVFILT_WRITE
[309] 
[310] #undef  NGX_VNODE_EVENT
[311] #define NGX_VNODE_EVENT    EVFILT_VNODE
[312] 
[313] /*
[314]  * NGX_CLOSE_EVENT, NGX_LOWAT_EVENT, and NGX_FLUSH_EVENT are the module flags
[315]  * and they must not go into a kernel so we need to choose the value
[316]  * that must not interfere with any existent and future kqueue flags.
[317]  * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
[318]  * they are reserved and cleared on a kernel entrance.
[319]  */
[320] #undef  NGX_CLOSE_EVENT
[321] #define NGX_CLOSE_EVENT    EV_EOF
[322] 
[323] #undef  NGX_LOWAT_EVENT
[324] #define NGX_LOWAT_EVENT    EV_FLAG1
[325] 
[326] #undef  NGX_FLUSH_EVENT
[327] #define NGX_FLUSH_EVENT    EV_ERROR
[328] 
[329] #define NGX_LEVEL_EVENT    0
[330] #define NGX_ONESHOT_EVENT  EV_ONESHOT
[331] #define NGX_CLEAR_EVENT    EV_CLEAR
[332] 
[333] #undef  NGX_DISABLE_EVENT
[334] #define NGX_DISABLE_EVENT  EV_DISABLE
[335] 
[336] 
[337] #elif (NGX_HAVE_DEVPOLL && !(NGX_TEST_BUILD_DEVPOLL)) \
[338]       || (NGX_HAVE_EVENTPORT && !(NGX_TEST_BUILD_EVENTPORT))
[339] 
[340] #define NGX_READ_EVENT     POLLIN
[341] #define NGX_WRITE_EVENT    POLLOUT
[342] 
[343] #define NGX_LEVEL_EVENT    0
[344] #define NGX_ONESHOT_EVENT  1
[345] 
[346] 
[347] #elif (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
[348] 
[349] #define NGX_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
[350] #define NGX_WRITE_EVENT    EPOLLOUT
[351] 
[352] #define NGX_LEVEL_EVENT    0
[353] #define NGX_CLEAR_EVENT    EPOLLET
[354] #define NGX_ONESHOT_EVENT  0x70000000
[355] #if 0
[356] #define NGX_ONESHOT_EVENT  EPOLLONESHOT
[357] #endif
[358] 
[359] #if (NGX_HAVE_EPOLLEXCLUSIVE)
[360] #define NGX_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
[361] #endif
[362] 
[363] #elif (NGX_HAVE_POLL)
[364] 
[365] #define NGX_READ_EVENT     POLLIN
[366] #define NGX_WRITE_EVENT    POLLOUT
[367] 
[368] #define NGX_LEVEL_EVENT    0
[369] #define NGX_ONESHOT_EVENT  1
[370] 
[371] 
[372] #else /* select */
[373] 
[374] #define NGX_READ_EVENT     0
[375] #define NGX_WRITE_EVENT    1
[376] 
[377] #define NGX_LEVEL_EVENT    0
[378] #define NGX_ONESHOT_EVENT  1
[379] 
[380] #endif /* NGX_HAVE_KQUEUE */
[381] 
[382] 
[383] #if (NGX_HAVE_IOCP)
[384] #define NGX_IOCP_ACCEPT      0
[385] #define NGX_IOCP_IO          1
[386] #define NGX_IOCP_CONNECT     2
[387] #endif
[388] 
[389] 
[390] #if (NGX_TEST_BUILD_EPOLL)
[391] #define NGX_EXCLUSIVE_EVENT  0
[392] #endif
[393] 
[394] 
[395] #ifndef NGX_CLEAR_EVENT
[396] #define NGX_CLEAR_EVENT    0    /* dummy declaration */
[397] #endif
[398] 
[399] 
[400] #define ngx_process_events   ngx_event_actions.process_events
[401] #define ngx_done_events      ngx_event_actions.done
[402] 
[403] #define ngx_add_event        ngx_event_actions.add
[404] #define ngx_del_event        ngx_event_actions.del
[405] #define ngx_add_conn         ngx_event_actions.add_conn
[406] #define ngx_del_conn         ngx_event_actions.del_conn
[407] 
[408] #define ngx_notify           ngx_event_actions.notify
[409] 
[410] #define ngx_add_timer        ngx_event_add_timer
[411] #define ngx_del_timer        ngx_event_del_timer
[412] 
[413] 
[414] extern ngx_os_io_t  ngx_io;
[415] 
[416] #define ngx_recv             ngx_io.recv
[417] #define ngx_recv_chain       ngx_io.recv_chain
[418] #define ngx_udp_recv         ngx_io.udp_recv
[419] #define ngx_send             ngx_io.send
[420] #define ngx_send_chain       ngx_io.send_chain
[421] #define ngx_udp_send         ngx_io.udp_send
[422] #define ngx_udp_send_chain   ngx_io.udp_send_chain
[423] 
[424] 
[425] #define NGX_EVENT_MODULE      0x544E5645  /* "EVNT" */
[426] #define NGX_EVENT_CONF        0x02000000
[427] 
[428] 
[429] typedef struct {
[430]     ngx_uint_t    connections;
[431]     ngx_uint_t    use;
[432] 
[433]     ngx_flag_t    multi_accept;
[434]     ngx_flag_t    accept_mutex;
[435] 
[436]     ngx_msec_t    accept_mutex_delay;
[437] 
[438]     u_char       *name;
[439] 
[440] #if (NGX_DEBUG)
[441]     ngx_array_t   debug_connection;
[442] #endif
[443] } ngx_event_conf_t;
[444] 
[445] 
[446] typedef struct {
[447]     ngx_str_t              *name;
[448] 
[449]     void                 *(*create_conf)(ngx_cycle_t *cycle);
[450]     char                 *(*init_conf)(ngx_cycle_t *cycle, void *conf);
[451] 
[452]     ngx_event_actions_t     actions;
[453] } ngx_event_module_t;
[454] 
[455] 
[456] extern ngx_atomic_t          *ngx_connection_counter;
[457] 
[458] extern ngx_atomic_t          *ngx_accept_mutex_ptr;
[459] extern ngx_shmtx_t            ngx_accept_mutex;
[460] extern ngx_uint_t             ngx_use_accept_mutex;
[461] extern ngx_uint_t             ngx_accept_events;
[462] extern ngx_uint_t             ngx_accept_mutex_held;
[463] extern ngx_msec_t             ngx_accept_mutex_delay;
[464] extern ngx_int_t              ngx_accept_disabled;
[465] extern ngx_uint_t             ngx_use_exclusive_accept;
[466] 
[467] 
[468] #if (NGX_STAT_STUB)
[469] 
[470] extern ngx_atomic_t  *ngx_stat_accepted;
[471] extern ngx_atomic_t  *ngx_stat_handled;
[472] extern ngx_atomic_t  *ngx_stat_requests;
[473] extern ngx_atomic_t  *ngx_stat_active;
[474] extern ngx_atomic_t  *ngx_stat_reading;
[475] extern ngx_atomic_t  *ngx_stat_writing;
[476] extern ngx_atomic_t  *ngx_stat_waiting;
[477] 
[478] #endif
[479] 
[480] 
[481] #define NGX_UPDATE_TIME         1
[482] #define NGX_POST_EVENTS         2
[483] 
[484] 
[485] extern sig_atomic_t           ngx_event_timer_alarm;
[486] extern ngx_uint_t             ngx_event_flags;
[487] extern ngx_module_t           ngx_events_module;
[488] extern ngx_module_t           ngx_event_core_module;
[489] 
[490] 
[491] #define ngx_event_get_conf(conf_ctx, module)                                  \
[492]              (*(ngx_get_conf(conf_ctx, ngx_events_module))) [module.ctx_index]
[493] 
[494] 
[495] 
[496] void ngx_event_accept(ngx_event_t *ev);
[497] ngx_int_t ngx_trylock_accept_mutex(ngx_cycle_t *cycle);
[498] ngx_int_t ngx_enable_accept_events(ngx_cycle_t *cycle);
[499] u_char *ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len);
[500] #if (NGX_DEBUG)
[501] void ngx_debug_accepted_connection(ngx_event_conf_t *ecf, ngx_connection_t *c);
[502] #endif
[503] 
[504] 
[505] void ngx_process_events_and_timers(ngx_cycle_t *cycle);
[506] ngx_int_t ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags);
[507] ngx_int_t ngx_handle_write_event(ngx_event_t *wev, size_t lowat);
[508] 
[509] 
[510] #if (NGX_WIN32)
[511] void ngx_event_acceptex(ngx_event_t *ev);
[512] ngx_int_t ngx_event_post_acceptex(ngx_listening_t *ls, ngx_uint_t n);
[513] u_char *ngx_acceptex_log_error(ngx_log_t *log, u_char *buf, size_t len);
[514] #endif
[515] 
[516] 
[517] ngx_int_t ngx_send_lowat(ngx_connection_t *c, size_t lowat);
[518] 
[519] 
[520] /* used in ngx_log_debugX() */
[521] #define ngx_event_ident(p)  ((ngx_connection_t *) (p))->fd
[522] 
[523] 
[524] #include <ngx_event_timer.h>
[525] #include <ngx_event_posted.h>
[526] #include <ngx_event_udp.h>
[527] 
[528] #if (NGX_WIN32)
[529] #include <ngx_iocp_module.h>
[530] #endif
[531] 
[532] 
[533] #endif /* _NGX_EVENT_H_INCLUDED_ */
