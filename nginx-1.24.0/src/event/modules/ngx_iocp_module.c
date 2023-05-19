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
[11] #include <ngx_iocp_module.h>
[12] 
[13] 
[14] static ngx_int_t ngx_iocp_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[15] static ngx_thread_value_t __stdcall ngx_iocp_timer(void *data);
[16] static void ngx_iocp_done(ngx_cycle_t *cycle);
[17] static ngx_int_t ngx_iocp_add_event(ngx_event_t *ev, ngx_int_t event,
[18]     ngx_uint_t key);
[19] static ngx_int_t ngx_iocp_del_connection(ngx_connection_t *c, ngx_uint_t flags);
[20] static ngx_int_t ngx_iocp_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[21]     ngx_uint_t flags);
[22] static void *ngx_iocp_create_conf(ngx_cycle_t *cycle);
[23] static char *ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf);
[24] 
[25] 
[26] static ngx_str_t      iocp_name = ngx_string("iocp");
[27] 
[28] static ngx_command_t  ngx_iocp_commands[] = {
[29] 
[30]     { ngx_string("iocp_threads"),
[31]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[32]       ngx_conf_set_num_slot,
[33]       0,
[34]       offsetof(ngx_iocp_conf_t, threads),
[35]       NULL },
[36] 
[37]     { ngx_string("post_acceptex"),
[38]       NGX_EVENT_CONF|NGX_CONF_TAKE1,
[39]       ngx_conf_set_num_slot,
[40]       0,
[41]       offsetof(ngx_iocp_conf_t, post_acceptex),
[42]       NULL },
[43] 
[44]     { ngx_string("acceptex_read"),
[45]       NGX_EVENT_CONF|NGX_CONF_FLAG,
[46]       ngx_conf_set_flag_slot,
[47]       0,
[48]       offsetof(ngx_iocp_conf_t, acceptex_read),
[49]       NULL },
[50] 
[51]       ngx_null_command
[52] };
[53] 
[54] 
[55] static ngx_event_module_t  ngx_iocp_module_ctx = {
[56]     &iocp_name,
[57]     ngx_iocp_create_conf,                  /* create configuration */
[58]     ngx_iocp_init_conf,                    /* init configuration */
[59] 
[60]     {
[61]         ngx_iocp_add_event,                /* add an event */
[62]         NULL,                              /* delete an event */
[63]         NULL,                              /* enable an event */
[64]         NULL,                              /* disable an event */
[65]         NULL,                              /* add an connection */
[66]         ngx_iocp_del_connection,           /* delete an connection */
[67]         NULL,                              /* trigger a notify */
[68]         ngx_iocp_process_events,           /* process the events */
[69]         ngx_iocp_init,                     /* init the events */
[70]         ngx_iocp_done                      /* done the events */
[71]     }
[72] 
[73] };
[74] 
[75] ngx_module_t  ngx_iocp_module = {
[76]     NGX_MODULE_V1,
[77]     &ngx_iocp_module_ctx,                  /* module context */
[78]     ngx_iocp_commands,                     /* module directives */
[79]     NGX_EVENT_MODULE,                      /* module type */
[80]     NULL,                                  /* init master */
[81]     NULL,                                  /* init module */
[82]     NULL,                                  /* init process */
[83]     NULL,                                  /* init thread */
[84]     NULL,                                  /* exit thread */
[85]     NULL,                                  /* exit process */
[86]     NULL,                                  /* exit master */
[87]     NGX_MODULE_V1_PADDING
[88] };
[89] 
[90] 
[91] ngx_os_io_t ngx_iocp_io = {
[92]     ngx_overlapped_wsarecv,
[93]     NULL,
[94]     ngx_udp_overlapped_wsarecv,
[95]     NULL,
[96]     NULL,
[97]     NULL,
[98]     ngx_overlapped_wsasend_chain,
[99]     0
[100] };
[101] 
[102] 
[103] static HANDLE      iocp;
[104] static ngx_tid_t   timer_thread;
[105] static ngx_msec_t  msec;
[106] 
[107] 
[108] static ngx_int_t
[109] ngx_iocp_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[110] {
[111]     ngx_iocp_conf_t  *cf;
[112] 
[113]     cf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
[114] 
[115]     if (iocp == NULL) {
[116]         iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0,
[117]                                       cf->threads);
[118]     }
[119] 
[120]     if (iocp == NULL) {
[121]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[122]                       "CreateIoCompletionPort() failed");
[123]         return NGX_ERROR;
[124]     }
[125] 
[126]     ngx_io = ngx_iocp_io;
[127] 
[128]     ngx_event_actions = ngx_iocp_module_ctx.actions;
[129] 
[130]     ngx_event_flags = NGX_USE_IOCP_EVENT;
[131] 
[132]     if (timer == 0) {
[133]         return NGX_OK;
[134]     }
[135] 
[136]     /*
[137]      * The waitable timer could not be used, because
[138]      * GetQueuedCompletionStatus() does not set a thread to alertable state
[139]      */
[140] 
[141]     if (timer_thread == NULL) {
[142] 
[143]         msec = timer;
[144] 
[145]         if (ngx_create_thread(&timer_thread, ngx_iocp_timer, &msec, cycle->log)
[146]             != 0)
[147]         {
[148]             return NGX_ERROR;
[149]         }
[150]     }
[151] 
[152]     ngx_event_flags |= NGX_USE_TIMER_EVENT;
[153] 
[154]     return NGX_OK;
[155] }
[156] 
[157] 
[158] static ngx_thread_value_t __stdcall
[159] ngx_iocp_timer(void *data)
[160] {
[161]     ngx_msec_t  timer = *(ngx_msec_t *) data;
[162] 
[163]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
[164]                    "THREAD %p %p", &msec, data);
[165] 
[166]     for ( ;; ) {
[167]         Sleep(timer);
[168] 
[169]         ngx_time_update();
[170] #if 1
[171]         ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer");
[172] #endif
[173]     }
[174] 
[175] #if defined(__WATCOMC__) || defined(__GNUC__)
[176]     return 0;
[177] #endif
[178] }
[179] 
[180] 
[181] static void
[182] ngx_iocp_done(ngx_cycle_t *cycle)
[183] {
[184]     if (CloseHandle(iocp) == -1) {
[185]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[186]                       "iocp CloseHandle() failed");
[187]     }
[188] 
[189]     iocp = NULL;
[190] }
[191] 
[192] 
[193] static ngx_int_t
[194] ngx_iocp_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t key)
[195] {
[196]     ngx_connection_t  *c;
[197] 
[198]     c = (ngx_connection_t *) ev->data;
[199] 
[200]     c->read->active = 1;
[201]     c->write->active = 1;
[202] 
[203]     ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[204]                    "iocp add: fd:%d k:%ui ov:%p", c->fd, key, &ev->ovlp);
[205] 
[206]     if (CreateIoCompletionPort((HANDLE) c->fd, iocp, key, 0) == NULL) {
[207]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[208]                       "CreateIoCompletionPort() failed");
[209]         return NGX_ERROR;
[210]     }
[211] 
[212]     return NGX_OK;
[213] }
[214] 
[215] 
[216] static ngx_int_t
[217] ngx_iocp_del_connection(ngx_connection_t *c, ngx_uint_t flags)
[218] {
[219] #if 0
[220]     if (flags & NGX_CLOSE_EVENT) {
[221]         return NGX_OK;
[222]     }
[223] 
[224]     if (CancelIo((HANDLE) c->fd) == 0) {
[225]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno, "CancelIo() failed");
[226]         return NGX_ERROR;
[227]     }
[228] #endif
[229] 
[230]     return NGX_OK;
[231] }
[232] 
[233] 
[234] static ngx_int_t
[235] ngx_iocp_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
[236] {
[237]     int                rc;
[238]     u_int              key;
[239]     u_long             bytes;
[240]     ngx_err_t          err;
[241]     ngx_msec_t         delta;
[242]     ngx_event_t       *ev;
[243]     ngx_event_ovlp_t  *ovlp;
[244] 
[245]     if (timer == NGX_TIMER_INFINITE) {
[246]         timer = INFINITE;
[247]     }
[248] 
[249]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "iocp timer: %M", timer);
[250] 
[251]     rc = GetQueuedCompletionStatus(iocp, &bytes, (PULONG_PTR) &key,
[252]                                    (LPOVERLAPPED *) &ovlp, (u_long) timer);
[253] 
[254]     if (rc == 0) {
[255]         err = ngx_errno;
[256]     } else {
[257]         err = 0;
[258]     }
[259] 
[260]     delta = ngx_current_msec;
[261] 
[262]     if (flags & NGX_UPDATE_TIME) {
[263]         ngx_time_update();
[264]     }
[265] 
[266]     ngx_log_debug4(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[267]                    "iocp: %d b:%d k:%d ov:%p", rc, bytes, key, ovlp);
[268] 
[269]     if (timer != INFINITE) {
[270]         delta = ngx_current_msec - delta;
[271] 
[272]         ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[273]                        "iocp timer: %M, delta: %M", timer, delta);
[274]     }
[275] 
[276]     if (err) {
[277]         if (ovlp == NULL) {
[278]             if (err != WAIT_TIMEOUT) {
[279]                 ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[280]                               "GetQueuedCompletionStatus() failed");
[281] 
[282]                 return NGX_ERROR;
[283]             }
[284] 
[285]             return NGX_OK;
[286]         }
[287] 
[288]         ovlp->error = err;
[289]     }
[290] 
[291]     if (ovlp == NULL) {
[292]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[293]                       "GetQueuedCompletionStatus() returned no operation");
[294]         return NGX_ERROR;
[295]     }
[296] 
[297] 
[298]     ev = ovlp->event;
[299] 
[300]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, err, "iocp event:%p", ev);
[301] 
[302] 
[303]     if (err == ERROR_NETNAME_DELETED /* the socket was closed */
[304]         || err == ERROR_OPERATION_ABORTED /* the operation was canceled */)
[305]     {
[306] 
[307]         /*
[308]          * the WSA_OPERATION_ABORTED completion notification
[309]          * for a file descriptor that was closed
[310]          */
[311] 
[312]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, err,
[313]                        "iocp: aborted event %p", ev);
[314] 
[315]         return NGX_OK;
[316]     }
[317] 
[318]     if (err) {
[319]         ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[320]                       "GetQueuedCompletionStatus() returned operation error");
[321]     }
[322] 
[323]     switch (key) {
[324] 
[325]     case NGX_IOCP_ACCEPT:
[326]         if (bytes) {
[327]             ev->ready = 1;
[328]         }
[329]         break;
[330] 
[331]     case NGX_IOCP_IO:
[332]         ev->complete = 1;
[333]         ev->ready = 1;
[334]         break;
[335] 
[336]     case NGX_IOCP_CONNECT:
[337]         ev->ready = 1;
[338]     }
[339] 
[340]     ev->available = bytes;
[341] 
[342]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[343]                    "iocp event handler: %p", ev->handler);
[344] 
[345]     ev->handler(ev);
[346] 
[347]     return NGX_OK;
[348] }
[349] 
[350] 
[351] static void *
[352] ngx_iocp_create_conf(ngx_cycle_t *cycle)
[353] {
[354]     ngx_iocp_conf_t  *cf;
[355] 
[356]     cf = ngx_palloc(cycle->pool, sizeof(ngx_iocp_conf_t));
[357]     if (cf == NULL) {
[358]         return NULL;
[359]     }
[360] 
[361]     cf->threads = NGX_CONF_UNSET;
[362]     cf->post_acceptex = NGX_CONF_UNSET;
[363]     cf->acceptex_read = NGX_CONF_UNSET;
[364] 
[365]     return cf;
[366] }
[367] 
[368] 
[369] static char *
[370] ngx_iocp_init_conf(ngx_cycle_t *cycle, void *conf)
[371] {
[372]     ngx_iocp_conf_t *cf = conf;
[373] 
[374]     ngx_conf_init_value(cf->threads, 0);
[375]     ngx_conf_init_value(cf->post_acceptex, 10);
[376]     ngx_conf_init_value(cf->acceptex_read, 1);
[377] 
[378]     return NGX_CONF_OK;
[379] }
