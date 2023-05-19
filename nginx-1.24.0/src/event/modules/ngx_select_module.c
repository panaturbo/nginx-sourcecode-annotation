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
[13] static ngx_int_t ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer);
[14] static void ngx_select_done(ngx_cycle_t *cycle);
[15] static ngx_int_t ngx_select_add_event(ngx_event_t *ev, ngx_int_t event,
[16]     ngx_uint_t flags);
[17] static ngx_int_t ngx_select_del_event(ngx_event_t *ev, ngx_int_t event,
[18]     ngx_uint_t flags);
[19] static ngx_int_t ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[20]     ngx_uint_t flags);
[21] static void ngx_select_repair_fd_sets(ngx_cycle_t *cycle);
[22] static char *ngx_select_init_conf(ngx_cycle_t *cycle, void *conf);
[23] 
[24] 
[25] static fd_set         master_read_fd_set;
[26] static fd_set         master_write_fd_set;
[27] static fd_set         work_read_fd_set;
[28] static fd_set         work_write_fd_set;
[29] 
[30] static ngx_int_t      max_fd;
[31] static ngx_uint_t     nevents;
[32] 
[33] static ngx_event_t  **event_index;
[34] 
[35] 
[36] static ngx_str_t           select_name = ngx_string("select");
[37] 
[38] static ngx_event_module_t  ngx_select_module_ctx = {
[39]     &select_name,
[40]     NULL,                                  /* create configuration */
[41]     ngx_select_init_conf,                  /* init configuration */
[42] 
[43]     {
[44]         ngx_select_add_event,              /* add an event */
[45]         ngx_select_del_event,              /* delete an event */
[46]         ngx_select_add_event,              /* enable an event */
[47]         ngx_select_del_event,              /* disable an event */
[48]         NULL,                              /* add an connection */
[49]         NULL,                              /* delete an connection */
[50]         NULL,                              /* trigger a notify */
[51]         ngx_select_process_events,         /* process the events */
[52]         ngx_select_init,                   /* init the events */
[53]         ngx_select_done                    /* done the events */
[54]     }
[55] 
[56] };
[57] 
[58] ngx_module_t  ngx_select_module = {
[59]     NGX_MODULE_V1,
[60]     &ngx_select_module_ctx,                /* module context */
[61]     NULL,                                  /* module directives */
[62]     NGX_EVENT_MODULE,                      /* module type */
[63]     NULL,                                  /* init master */
[64]     NULL,                                  /* init module */
[65]     NULL,                                  /* init process */
[66]     NULL,                                  /* init thread */
[67]     NULL,                                  /* exit thread */
[68]     NULL,                                  /* exit process */
[69]     NULL,                                  /* exit master */
[70]     NGX_MODULE_V1_PADDING
[71] };
[72] 
[73] 
[74] static ngx_int_t
[75] ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[76] {
[77]     ngx_event_t  **index;
[78] 
[79]     if (event_index == NULL) {
[80]         FD_ZERO(&master_read_fd_set);
[81]         FD_ZERO(&master_write_fd_set);
[82]         nevents = 0;
[83]     }
[84] 
[85]     if (ngx_process >= NGX_PROCESS_WORKER
[86]         || cycle->old_cycle == NULL
[87]         || cycle->old_cycle->connection_n < cycle->connection_n)
[88]     {
[89]         index = ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
[90]                           cycle->log);
[91]         if (index == NULL) {
[92]             return NGX_ERROR;
[93]         }
[94] 
[95]         if (event_index) {
[96]             ngx_memcpy(index, event_index, sizeof(ngx_event_t *) * nevents);
[97]             ngx_free(event_index);
[98]         }
[99] 
[100]         event_index = index;
[101]     }
[102] 
[103]     ngx_io = ngx_os_io;
[104] 
[105]     ngx_event_actions = ngx_select_module_ctx.actions;
[106] 
[107]     ngx_event_flags = NGX_USE_LEVEL_EVENT;
[108] 
[109]     max_fd = -1;
[110] 
[111]     return NGX_OK;
[112] }
[113] 
[114] 
[115] static void
[116] ngx_select_done(ngx_cycle_t *cycle)
[117] {
[118]     ngx_free(event_index);
[119] 
[120]     event_index = NULL;
[121] }
[122] 
[123] 
[124] static ngx_int_t
[125] ngx_select_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[126] {
[127]     ngx_connection_t  *c;
[128] 
[129]     c = ev->data;
[130] 
[131]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[132]                    "select add event fd:%d ev:%i", c->fd, event);
[133] 
[134]     if (ev->index != NGX_INVALID_INDEX) {
[135]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[136]                       "select event fd:%d ev:%i is already set", c->fd, event);
[137]         return NGX_OK;
[138]     }
[139] 
[140]     if ((event == NGX_READ_EVENT && ev->write)
[141]         || (event == NGX_WRITE_EVENT && !ev->write))
[142]     {
[143]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[144]                       "invalid select %s event fd:%d ev:%i",
[145]                       ev->write ? "write" : "read", c->fd, event);
[146]         return NGX_ERROR;
[147]     }
[148] 
[149]     if (event == NGX_READ_EVENT) {
[150]         FD_SET(c->fd, &master_read_fd_set);
[151] 
[152]     } else if (event == NGX_WRITE_EVENT) {
[153]         FD_SET(c->fd, &master_write_fd_set);
[154]     }
[155] 
[156]     if (max_fd != -1 && max_fd < c->fd) {
[157]         max_fd = c->fd;
[158]     }
[159] 
[160]     ev->active = 1;
[161] 
[162]     event_index[nevents] = ev;
[163]     ev->index = nevents;
[164]     nevents++;
[165] 
[166]     return NGX_OK;
[167] }
[168] 
[169] 
[170] static ngx_int_t
[171] ngx_select_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[172] {
[173]     ngx_event_t       *e;
[174]     ngx_connection_t  *c;
[175] 
[176]     c = ev->data;
[177] 
[178]     ev->active = 0;
[179] 
[180]     if (ev->index == NGX_INVALID_INDEX) {
[181]         return NGX_OK;
[182]     }
[183] 
[184]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[185]                    "select del event fd:%d ev:%i", c->fd, event);
[186] 
[187]     if (event == NGX_READ_EVENT) {
[188]         FD_CLR(c->fd, &master_read_fd_set);
[189] 
[190]     } else if (event == NGX_WRITE_EVENT) {
[191]         FD_CLR(c->fd, &master_write_fd_set);
[192]     }
[193] 
[194]     if (max_fd == c->fd) {
[195]         max_fd = -1;
[196]     }
[197] 
[198]     if (ev->index < --nevents) {
[199]         e = event_index[nevents];
[200]         event_index[ev->index] = e;
[201]         e->index = ev->index;
[202]     }
[203] 
[204]     ev->index = NGX_INVALID_INDEX;
[205] 
[206]     return NGX_OK;
[207] }
[208] 
[209] 
[210] static ngx_int_t
[211] ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[212]     ngx_uint_t flags)
[213] {
[214]     int                ready, nready;
[215]     ngx_err_t          err;
[216]     ngx_uint_t         i, found;
[217]     ngx_event_t       *ev;
[218]     ngx_queue_t       *queue;
[219]     struct timeval     tv, *tp;
[220]     ngx_connection_t  *c;
[221] 
[222]     if (max_fd == -1) {
[223]         for (i = 0; i < nevents; i++) {
[224]             c = event_index[i]->data;
[225]             if (max_fd < c->fd) {
[226]                 max_fd = c->fd;
[227]             }
[228]         }
[229] 
[230]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[231]                        "change max_fd: %i", max_fd);
[232]     }
[233] 
[234] #if (NGX_DEBUG)
[235]     if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
[236]         for (i = 0; i < nevents; i++) {
[237]             ev = event_index[i];
[238]             c = ev->data;
[239]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[240]                            "select event: fd:%d wr:%d", c->fd, ev->write);
[241]         }
[242] 
[243]         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[244]                        "max_fd: %i", max_fd);
[245]     }
[246] #endif
[247] 
[248]     if (timer == NGX_TIMER_INFINITE) {
[249]         tp = NULL;
[250] 
[251]     } else {
[252]         tv.tv_sec = (long) (timer / 1000);
[253]         tv.tv_usec = (long) ((timer % 1000) * 1000);
[254]         tp = &tv;
[255]     }
[256] 
[257]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[258]                    "select timer: %M", timer);
[259] 
[260]     work_read_fd_set = master_read_fd_set;
[261]     work_write_fd_set = master_write_fd_set;
[262] 
[263]     ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set, NULL, tp);
[264] 
[265]     err = (ready == -1) ? ngx_errno : 0;
[266] 
[267]     if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
[268]         ngx_time_update();
[269]     }
[270] 
[271]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[272]                    "select ready %d", ready);
[273] 
[274]     if (err) {
[275]         ngx_uint_t  level;
[276] 
[277]         if (err == NGX_EINTR) {
[278] 
[279]             if (ngx_event_timer_alarm) {
[280]                 ngx_event_timer_alarm = 0;
[281]                 return NGX_OK;
[282]             }
[283] 
[284]             level = NGX_LOG_INFO;
[285] 
[286]         } else {
[287]             level = NGX_LOG_ALERT;
[288]         }
[289] 
[290]         ngx_log_error(level, cycle->log, err, "select() failed");
[291] 
[292]         if (err == NGX_EBADF) {
[293]             ngx_select_repair_fd_sets(cycle);
[294]         }
[295] 
[296]         return NGX_ERROR;
[297]     }
[298] 
[299]     if (ready == 0) {
[300]         if (timer != NGX_TIMER_INFINITE) {
[301]             return NGX_OK;
[302]         }
[303] 
[304]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[305]                       "select() returned no events without timeout");
[306]         return NGX_ERROR;
[307]     }
[308] 
[309]     nready = 0;
[310] 
[311]     for (i = 0; i < nevents; i++) {
[312]         ev = event_index[i];
[313]         c = ev->data;
[314]         found = 0;
[315] 
[316]         if (ev->write) {
[317]             if (FD_ISSET(c->fd, &work_write_fd_set)) {
[318]                 found = 1;
[319]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[320]                                "select write %d", c->fd);
[321]             }
[322] 
[323]         } else {
[324]             if (FD_ISSET(c->fd, &work_read_fd_set)) {
[325]                 found = 1;
[326]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[327]                                "select read %d", c->fd);
[328]             }
[329]         }
[330] 
[331]         if (found) {
[332]             ev->ready = 1;
[333]             ev->available = -1;
[334] 
[335]             queue = ev->accept ? &ngx_posted_accept_events
[336]                                : &ngx_posted_events;
[337] 
[338]             ngx_post_event(ev, queue);
[339] 
[340]             nready++;
[341]         }
[342]     }
[343] 
[344]     if (ready != nready) {
[345]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[346]                       "select ready != events: %d:%d", ready, nready);
[347] 
[348]         ngx_select_repair_fd_sets(cycle);
[349]     }
[350] 
[351]     return NGX_OK;
[352] }
[353] 
[354] 
[355] static void
[356] ngx_select_repair_fd_sets(ngx_cycle_t *cycle)
[357] {
[358]     int           n;
[359]     socklen_t     len;
[360]     ngx_err_t     err;
[361]     ngx_socket_t  s;
[362] 
[363]     for (s = 0; s <= max_fd; s++) {
[364] 
[365]         if (FD_ISSET(s, &master_read_fd_set) == 0) {
[366]             continue;
[367]         }
[368] 
[369]         len = sizeof(int);
[370] 
[371]         if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
[372]             err = ngx_socket_errno;
[373] 
[374]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[375]                           "invalid descriptor #%d in read fd_set", s);
[376] 
[377]             FD_CLR(s, &master_read_fd_set);
[378]         }
[379]     }
[380] 
[381]     for (s = 0; s <= max_fd; s++) {
[382] 
[383]         if (FD_ISSET(s, &master_write_fd_set) == 0) {
[384]             continue;
[385]         }
[386] 
[387]         len = sizeof(int);
[388] 
[389]         if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
[390]             err = ngx_socket_errno;
[391] 
[392]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[393]                           "invalid descriptor #%d in write fd_set", s);
[394] 
[395]             FD_CLR(s, &master_write_fd_set);
[396]         }
[397]     }
[398] 
[399]     max_fd = -1;
[400] }
[401] 
[402] 
[403] static char *
[404] ngx_select_init_conf(ngx_cycle_t *cycle, void *conf)
[405] {
[406]     ngx_event_conf_t  *ecf;
[407] 
[408]     ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
[409] 
[410]     if (ecf->use != ngx_select_module.ctx_index) {
[411]         return NGX_CONF_OK;
[412]     }
[413] 
[414]     /* disable warning: the default FD_SETSIZE is 1024U in FreeBSD 5.x */
[415] 
[416]     if (cycle->connection_n > FD_SETSIZE) {
[417]         ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
[418]                       "the maximum number of files "
[419]                       "supported by select() is %ud", FD_SETSIZE);
[420]         return NGX_CONF_ERROR;
[421]     }
[422] 
[423]     return NGX_CONF_OK;
[424] }
