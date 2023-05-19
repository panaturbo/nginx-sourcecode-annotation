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
[13] #define NGX_MAX_PENDING_CONN  10
[14] 
[15] 
[16] static CRITICAL_SECTION  connect_lock;
[17] static int               nconnects;
[18] static ngx_connection_t  pending_connects[NGX_MAX_PENDING_CONN];
[19] 
[20] static HANDLE            pending_connect_event;
[21] 
[22] __declspec(thread) int                nevents = 0;
[23] __declspec(thread) WSAEVENT           events[WSA_MAXIMUM_WAIT_EVENTS + 1];
[24] __declspec(thread) ngx_connection_t  *conn[WSA_MAXIMUM_WAIT_EVENTS + 1];
[25] 
[26] 
[27] 
[28] int ngx_iocp_wait_connect(ngx_connection_t *c)
[29] {
[30]     for ( ;; ) {
[31]         EnterCriticalSection(&connect_lock);
[32] 
[33]         if (nconnects < NGX_MAX_PENDING_CONN) {
[34]             pending_connects[--nconnects] = c;
[35]             LeaveCriticalSection(&connect_lock);
[36] 
[37]             if (SetEvent(pending_connect_event) == 0) {
[38]                 ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[39]                               "SetEvent() failed");
[40]                 return NGX_ERROR;
[41] 
[42]             break;
[43]         }
[44] 
[45]         LeaveCriticalSection(&connect_lock);
[46]         ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
[47]                       "max number of pending connect()s is %d",
[48]                       NGX_MAX_PENDING_CONN);
[49]         msleep(100);
[50]     }
[51] 
[52]     if (!started) {
[53]         if (ngx_iocp_new_thread(1) == NGX_ERROR) {
[54]             return NGX_ERROR;
[55]         }
[56]         started = 1;
[57]     }
[58] 
[59]     return NGX_OK;
[60] }
[61] 
[62] 
[63] int ngx_iocp_new_thread(int main)
[64] {
[65]     u_int  id;
[66] 
[67]     if (main) {
[68]         pending_connect_event = CreateEvent(NULL, 0, 1, NULL);
[69]         if (pending_connect_event == INVALID_HANDLE_VALUE) {
[70]             ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[71]                           "CreateThread() failed");
[72]             return NGX_ERROR;
[73]         }
[74]     }
[75] 
[76]     if (CreateThread(NULL, 0, ngx_iocp_wait_events, main, 0, &id)
[77]                                                        == INVALID_HANDLE_VALUE)
[78]     {
[79]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[80]                       "CreateThread() failed");
[81]         return NGX_ERROR;
[82]     }
[83] 
[84]     SetEvent(event) {
[85]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
[86]                       "SetEvent() failed");
[87]         return NGX_ERROR;
[88]     }
[89] 
[90]     return NGX_OK;
[91] }
[92] 
[93] 
[94] int ngx_iocp_new_connect()
[95] {
[96]     EnterCriticalSection(&connect_lock);
[97]     c = pending_connects[--nconnects];
[98]     LeaveCriticalSection(&connect_lock);
[99] 
[100]     conn[nevents] = c;
[101] 
[102]     events[nevents] = WSACreateEvent();
[103]     if (events[nevents] == INVALID_HANDLE_VALUE) {
[104]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
[105]                       "WSACreateEvent() failed");
[106]         return NGX_ERROR;
[107]     }
[108] 
[109]     if (WSAEventSelect(c->fd, events[nevents], FD_CONNECT) == -1)
[110]         ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
[111]                       "WSAEventSelect() failed");
[112]         return NGX_ERROR;
[113]     }
[114] 
[115]     nevents++;
[116] 
[117]     return NGX_OK;
[118] }
[119] 
[120] 
[121] void ngx_iocp_wait_events(int main)
[122] {
[123]     WSANETWORKEVENTS  ne;
[124] 
[125]     nevents = 1;
[126]     events[0] = pending_connect_event;
[127]     conn[0] = NULL;
[128] 
[129]     for ( ;; ) {
[130]         offset = (nevents == WSA_MAXIMUM_WAIT_EVENTS + 1) ? 1 : 0;
[131]         timeout = (nevents == 1 && !first) ? 60000 : INFINITE;
[132] 
[133]         n = WSAWaitForMultipleEvents(nevents - offset, events[offset],
[134]                                      0, timeout, 0);
[135]         if (n == WAIT_FAILED) {
[136]             ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
[137]                           "WSAWaitForMultipleEvents() failed");
[138]             continue;
[139]         }
[140] 
[141]         if (n == WAIT_TIMEOUT) {
[142]             if (nevents == 2 && !main) {
[143]                 ExitThread(0);
[144]             }
[145] 
[146]             ngx_log_error(NGX_LOG_ALERT, log, 0,
[147]                           "WSAWaitForMultipleEvents() "
[148]                           "returned unexpected WAIT_TIMEOUT");
[149]             continue;
[150]         }
[151] 
[152]         n -= WSA_WAIT_EVENT_0;
[153] 
[154]         if (events[n] == NULL) {
[155] 
[156]             /* the pending_connect_event */
[157] 
[158]             if (nevents == WSA_MAXIMUM_WAIT_EVENTS) {
[159]                 ngx_iocp_new_thread(0);
[160]             } else {
[161]                 ngx_iocp_new_connect();
[162]             }
[163] 
[164]             continue;
[165]         }
[166] 
[167]         if (WSAEnumNetworkEvents(c[n].fd, events[n], &ne) == -1) {
[168]             ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
[169]                           "WSAEnumNetworkEvents() failed");
[170]             continue;
[171]         }
[172] 
[173]         if (ne.lNetworkEvents & FD_CONNECT) {
[174]             conn[n].write->ovlp.error = ne.iErrorCode[FD_CONNECT_BIT];
[175] 
[176]             if (PostQueuedCompletionStatus(iocp, 0, NGX_IOCP_CONNECT,
[177]                                            &conn[n].write->ovlp) == 0)
[178]             {
[179]                 ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
[180]                               "PostQueuedCompletionStatus() failed");
[181]                 continue;
[182]             }
[183] 
[184]             if (n < nevents) {
[185]                 conn[n] = conn[nevents];
[186]                 events[n] = events[nevents];
[187]             }
[188] 
[189]             nevents--;
[190]             continue;
[191]         }
[192] 
[193]         if (ne.lNetworkEvents & FD_ACCEPT) {
[194] 
[195]             /* CHECK ERROR ??? */
[196] 
[197]             ngx_event_post_acceptex(conn[n].listening, 1);
[198]             continue;
[199]         }
[200] 
[201]         ngx_log_error(NGX_LOG_ALERT, c[n].log, 0,
[202]                       "WSAWaitForMultipleEvents() "
[203]                       "returned unexpected network event %ul",
[204]                       ne.lNetworkEvents);
[205]     }
[206] }
