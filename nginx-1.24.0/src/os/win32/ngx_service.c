[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] 
[9] #define NGX_SERVICE_CONTROL_SHUTDOWN   128
[10] #define NGX_SERVICE_CONTROL_REOPEN     129
[11] 
[12] 
[13] SERVICE_TABLE_ENTRY st[] = {
[14]     { "nginx", service_main },
[15]     { NULL, NULL }
[16] };
[17] 
[18] 
[19] ngx_int_t
[20] ngx_service(ngx_log_t *log)
[21] {
[22]     /* primary thread */
[23] 
[24]     /* StartServiceCtrlDispatcher() should be called within 30 seconds */
[25] 
[26]     if (StartServiceCtrlDispatcher(st) == 0) {
[27]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[28]                       "StartServiceCtrlDispatcher() failed");
[29]         return NGX_ERROR;
[30]     }
[31] 
[32]     return NGX_OK;
[33] }
[34] 
[35] 
[36] void
[37] service_main(u_int argc, char **argv)
[38] {
[39]     SERVICE_STATUS         status;
[40]     SERVICE_STATUS_HANDLE  service;
[41] 
[42]     /* thread spawned by SCM */
[43] 
[44]     service = RegisterServiceCtrlHandlerEx("nginx", service_handler, ctx);
[45]     if (service == INVALID_HANDLE_VALUE) {
[46]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[47]                       "RegisterServiceCtrlHandlerEx() failed");
[48]         return;
[49]     }
[50] 
[51]     status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
[52]     status.dwCurrentState = SERVICE_START_PENDING;
[53]     status.dwControlsAccepted = SERVICE_ACCEPT_STOP
[54]                                 |SERVICE_ACCEPT_PARAMCHANGE;
[55]     status.dwWin32ExitCode = NO_ERROR;
[56]     status.dwServiceSpecificExitCode = 0;
[57]     status.dwCheckPoint = 1;
[58]     status.dwWaitHint = 2000;
[59] 
[60]     /* SetServiceStatus() should be called within 80 seconds */
[61] 
[62]     if (SetServiceStatus(service, &status) == 0) {
[63]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[64]                       "SetServiceStatus() failed");
[65]         return;
[66]     }
[67] 
[68]     /* init */
[69] 
[70]     status.dwCurrentState = SERVICE_RUNNING;
[71]     status.dwCheckPoint = 0;
[72]     status.dwWaitHint = 0;
[73] 
[74]     if (SetServiceStatus(service, &status) == 0) {
[75]         ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[76]                       "SetServiceStatus() failed");
[77]         return;
[78]     }
[79] 
[80]     /* call master or worker loop */
[81] 
[82]     /*
[83]      * master should use event notification and look status
[84]      * single should use iocp to get notifications from service handler
[85]      */
[86] 
[87] }
[88] 
[89] 
[90] u_int
[91] service_handler(u_int control, u_int type, void *data, void *ctx)
[92] {
[93]     /* primary thread */
[94] 
[95]     switch (control) {
[96] 
[97]     case SERVICE_CONTROL_INTERROGATE:
[98]         status = NGX_IOCP_INTERROGATE;
[99]         break;
[100] 
[101]     case SERVICE_CONTROL_STOP:
[102]         status = NGX_IOCP_STOP;
[103]         break;
[104] 
[105]     case SERVICE_CONTROL_PARAMCHANGE:
[106]         status = NGX_IOCP_RECONFIGURE;
[107]         break;
[108] 
[109]     case NGX_SERVICE_CONTROL_SHUTDOWN:
[110]         status = NGX_IOCP_REOPEN;
[111]         break;
[112] 
[113]     case NGX_SERVICE_CONTROL_REOPEN:
[114]         status = NGX_IOCP_REOPEN;
[115]         break;
[116] 
[117]     default:
[118]         return ERROR_CALL_NOT_IMPLEMENTED;
[119]     }
[120] 
[121]     if (ngx_single) {
[122]         if (PostQueuedCompletionStatus(iocp, ... status, ...) == 0) {
[123]             err = ngx_errno;
[124]             ngx_log_error(NGX_LOG_ALERT, log, err,
[125]                           "PostQueuedCompletionStatus() failed");
[126]             return err;
[127]         }
[128] 
[129]     } else {
[130]         Event
[131]     }
[132] 
[133]     return NO_ERROR;
[134] }
