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
[29] static fd_set         work_except_fd_set;
[30] 
[31] static ngx_uint_t     max_read;
[32] static ngx_uint_t     max_write;
[33] static ngx_uint_t     nevents;
[34] 
[35] static ngx_event_t  **event_index;
[36] 
[37] 
[38] static ngx_str_t           select_name = ngx_string("select");
[39] 
[40] static ngx_event_module_t  ngx_select_module_ctx = {
[41]     &select_name,
[42]     NULL,                                  /* create configuration */
[43]     ngx_select_init_conf,                  /* init configuration */
[44] 
[45]     {
[46]         ngx_select_add_event,              /* add an event */
[47]         ngx_select_del_event,              /* delete an event */
[48]         ngx_select_add_event,              /* enable an event */
[49]         ngx_select_del_event,              /* disable an event */
[50]         NULL,                              /* add an connection */
[51]         NULL,                              /* delete an connection */
[52]         NULL,                              /* trigger a notify */
[53]         ngx_select_process_events,         /* process the events */
[54]         ngx_select_init,                   /* init the events */
[55]         ngx_select_done                    /* done the events */
[56]     }
[57] 
[58] };
[59] 
[60] ngx_module_t  ngx_select_module = {
[61]     NGX_MODULE_V1,
[62]     &ngx_select_module_ctx,                /* module context */
[63]     NULL,                                  /* module directives */
[64]     NGX_EVENT_MODULE,                      /* module type */
[65]     NULL,                                  /* init master */
[66]     NULL,                                  /* init module */
[67]     NULL,                                  /* init process */
[68]     NULL,                                  /* init thread */
[69]     NULL,                                  /* exit thread */
[70]     NULL,                                  /* exit process */
[71]     NULL,                                  /* exit master */
[72]     NGX_MODULE_V1_PADDING
[73] };
[74] 
[75] 
[76] static ngx_int_t
[77] ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer)
[78] {
[79]     ngx_event_t  **index;
[80] 
[81]     if (event_index == NULL) {
[82]         FD_ZERO(&master_read_fd_set);
[83]         FD_ZERO(&master_write_fd_set);
[84]         nevents = 0;
[85]     }
[86] 
[87]     if (ngx_process >= NGX_PROCESS_WORKER
[88]         || cycle->old_cycle == NULL
[89]         || cycle->old_cycle->connection_n < cycle->connection_n)
[90]     {
[91]         index = ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
[92]                           cycle->log);
[93]         if (index == NULL) {
[94]             return NGX_ERROR;
[95]         }
[96] 
[97]         if (event_index) {
[98]             ngx_memcpy(index, event_index, sizeof(ngx_event_t *) * nevents);
[99]             ngx_free(event_index);
[100]         }
[101] 
[102]         event_index = index;
[103]     }
[104] 
[105]     ngx_io = ngx_os_io;
[106] 
[107]     ngx_event_actions = ngx_select_module_ctx.actions;
[108] 
[109]     ngx_event_flags = NGX_USE_LEVEL_EVENT;
[110] 
[111]     max_read = 0;
[112]     max_write = 0;
[113] 
[114]     return NGX_OK;
[115] }
[116] 
[117] 
[118] static void
[119] ngx_select_done(ngx_cycle_t *cycle)
[120] {
[121]     ngx_free(event_index);
[122] 
[123]     event_index = NULL;
[124] }
[125] 
[126] 
[127] static ngx_int_t
[128] ngx_select_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[129] {
[130]     ngx_connection_t  *c;
[131] 
[132]     c = ev->data;
[133] 
[134]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[135]                    "select add event fd:%d ev:%i", c->fd, event);
[136] 
[137]     if (ev->index != NGX_INVALID_INDEX) {
[138]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[139]                       "select event fd:%d ev:%i is already set", c->fd, event);
[140]         return NGX_OK;
[141]     }
[142] 
[143]     if ((event == NGX_READ_EVENT && ev->write)
[144]         || (event == NGX_WRITE_EVENT && !ev->write))
[145]     {
[146]         ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
[147]                       "invalid select %s event fd:%d ev:%i",
[148]                       ev->write ? "write" : "read", c->fd, event);
[149]         return NGX_ERROR;
[150]     }
[151] 
[152]     if ((event == NGX_READ_EVENT && max_read >= FD_SETSIZE)
[153]         || (event == NGX_WRITE_EVENT && max_write >= FD_SETSIZE))
[154]     {
[155]         ngx_log_error(NGX_LOG_ERR, ev->log, 0,
[156]                       "maximum number of descriptors "
[157]                       "supported by select() is %d", FD_SETSIZE);
[158]         return NGX_ERROR;
[159]     }
[160] 
[161]     if (event == NGX_READ_EVENT) {
[162]         FD_SET(c->fd, &master_read_fd_set);
[163]         max_read++;
[164] 
[165]     } else if (event == NGX_WRITE_EVENT) {
[166]         FD_SET(c->fd, &master_write_fd_set);
[167]         max_write++;
[168]     }
[169] 
[170]     ev->active = 1;
[171] 
[172]     event_index[nevents] = ev;
[173]     ev->index = nevents;
[174]     nevents++;
[175] 
[176]     return NGX_OK;
[177] }
[178] 
[179] 
[180] static ngx_int_t
[181] ngx_select_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
[182] {
[183]     ngx_event_t       *e;
[184]     ngx_connection_t  *c;
[185] 
[186]     c = ev->data;
[187] 
[188]     ev->active = 0;
[189] 
[190]     if (ev->index == NGX_INVALID_INDEX) {
[191]         return NGX_OK;
[192]     }
[193] 
[194]     ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
[195]                    "select del event fd:%d ev:%i", c->fd, event);
[196] 
[197]     if (event == NGX_READ_EVENT) {
[198]         FD_CLR(c->fd, &master_read_fd_set);
[199]         max_read--;
[200] 
[201]     } else if (event == NGX_WRITE_EVENT) {
[202]         FD_CLR(c->fd, &master_write_fd_set);
[203]         max_write--;
[204]     }
[205] 
[206]     if (ev->index < --nevents) {
[207]         e = event_index[nevents];
[208]         event_index[ev->index] = e;
[209]         e->index = ev->index;
[210]     }
[211] 
[212]     ev->index = NGX_INVALID_INDEX;
[213] 
[214]     return NGX_OK;
[215] }
[216] 
[217] 
[218] static ngx_int_t
[219] ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
[220]     ngx_uint_t flags)
[221] {
[222]     int                ready, nready;
[223]     ngx_err_t          err;
[224]     ngx_uint_t         i, found;
[225]     ngx_event_t       *ev;
[226]     ngx_queue_t       *queue;
[227]     struct timeval     tv, *tp;
[228]     ngx_connection_t  *c;
[229] 
[230] #if (NGX_DEBUG)
[231]     if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
[232]         for (i = 0; i < nevents; i++) {
[233]             ev = event_index[i];
[234]             c = ev->data;
[235]             ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[236]                            "select event: fd:%d wr:%d", c->fd, ev->write);
[237]         }
[238]     }
[239] #endif
[240] 
[241]     if (timer == NGX_TIMER_INFINITE) {
[242]         tp = NULL;
[243] 
[244]     } else {
[245]         tv.tv_sec = (long) (timer / 1000);
[246]         tv.tv_usec = (long) ((timer % 1000) * 1000);
[247]         tp = &tv;
[248]     }
[249] 
[250]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[251]                    "select timer: %M", timer);
[252] 
[253]     work_read_fd_set = master_read_fd_set;
[254]     work_write_fd_set = master_write_fd_set;
[255]     work_except_fd_set = master_write_fd_set;
[256] 
[257]     if (max_read || max_write) {
[258]         ready = select(0, &work_read_fd_set, &work_write_fd_set,
[259]                        &work_except_fd_set, tp);
[260] 
[261]     } else {
[262] 
[263]         /*
[264]          * Winsock select() requires that at least one descriptor set must be
[265]          * be non-null, and any non-null descriptor set must contain at least
[266]          * one handle to a socket.  Otherwise select() returns WSAEINVAL.
[267]          */
[268] 
[269]         ngx_msleep(timer);
[270] 
[271]         ready = 0;
[272]     }
[273] 
[274]     err = (ready == -1) ? ngx_socket_errno : 0;
[275] 
[276]     if (flags & NGX_UPDATE_TIME) {
[277]         ngx_time_update();
[278]     }
[279] 
[280]     ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[281]                    "select ready %d", ready);
[282] 
[283]     if (err) {
[284]         ngx_log_error(NGX_LOG_ALERT, cycle->log, err, "select() failed");
[285] 
[286]         if (err == WSAENOTSOCK) {
[287]             ngx_select_repair_fd_sets(cycle);
[288]         }
[289] 
[290]         return NGX_ERROR;
[291]     }
[292] 
[293]     if (ready == 0) {
[294]         if (timer != NGX_TIMER_INFINITE) {
[295]             return NGX_OK;
[296]         }
[297] 
[298]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[299]                       "select() returned no events without timeout");
[300]         return NGX_ERROR;
[301]     }
[302] 
[303]     nready = 0;
[304] 
[305]     for (i = 0; i < nevents; i++) {
[306]         ev = event_index[i];
[307]         c = ev->data;
[308]         found = 0;
[309] 
[310]         if (ev->write) {
[311]             if (FD_ISSET(c->fd, &work_write_fd_set)) {
[312]                 found++;
[313]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[314]                                "select write %d", c->fd);
[315]             }
[316] 
[317]             if (FD_ISSET(c->fd, &work_except_fd_set)) {
[318]                 found++;
[319]                 ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
[320]                                "select except %d", c->fd);
[321]             }
[322] 
[323]         } else {
[324]             if (FD_ISSET(c->fd, &work_read_fd_set)) {
[325]                 found++;
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
[340]             nready += found;
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
[359]     u_int         i;
[360]     socklen_t     len;
[361]     ngx_err_t     err;
[362]     ngx_socket_t  s;
[363] 
[364]     for (i = 0; i < master_read_fd_set.fd_count; i++) {
[365] 
[366]         s = master_read_fd_set.fd_array[i];
[367]         len = sizeof(int);
[368] 
[369]         if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
[370]             err = ngx_socket_errno;
[371] 
[372]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[373]                           "invalid descriptor #%d in read fd_set", s);
[374] 
[375]             FD_CLR(s, &master_read_fd_set);
[376]         }
[377]     }
[378] 
[379]     for (i = 0; i < master_write_fd_set.fd_count; i++) {
[380] 
[381]         s = master_write_fd_set.fd_array[i];
[382]         len = sizeof(int);
[383] 
[384]         if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *) &n, &len) == -1) {
[385]             err = ngx_socket_errno;
[386] 
[387]             ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
[388]                           "invalid descriptor #%d in write fd_set", s);
[389] 
[390]             FD_CLR(s, &master_write_fd_set);
[391]         }
[392]     }
[393] }
[394] 
[395] 
[396] static char *
[397] ngx_select_init_conf(ngx_cycle_t *cycle, void *conf)
[398] {
[399]     ngx_event_conf_t  *ecf;
[400] 
[401]     ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
[402] 
[403]     if (ecf->use != ngx_select_module.ctx_index) {
[404]         return NGX_CONF_OK;
[405]     }
[406] 
[407]     return NGX_CONF_OK;
[408] }
