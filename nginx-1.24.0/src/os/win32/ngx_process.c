[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] int              ngx_argc;
[13] char           **ngx_argv;
[14] char           **ngx_os_argv;
[15] 
[16] ngx_int_t        ngx_last_process;
[17] ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];
[18] 
[19] 
[20] ngx_pid_t
[21] ngx_spawn_process(ngx_cycle_t *cycle, char *name, ngx_int_t respawn)
[22] {
[23]     u_long          rc, n, code;
[24]     ngx_int_t       s;
[25]     ngx_pid_t       pid;
[26]     ngx_exec_ctx_t  ctx;
[27]     HANDLE          events[2];
[28]     char            file[MAX_PATH + 1];
[29] 
[30]     if (respawn >= 0) {
[31]         s = respawn;
[32] 
[33]     } else {
[34]         for (s = 0; s < ngx_last_process; s++) {
[35]             if (ngx_processes[s].handle == NULL) {
[36]                 break;
[37]             }
[38]         }
[39] 
[40]         if (s == NGX_MAX_PROCESSES) {
[41]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[42]                           "no more than %d processes can be spawned",
[43]                           NGX_MAX_PROCESSES);
[44]             return NGX_INVALID_PID;
[45]         }
[46]     }
[47] 
[48]     n = GetModuleFileName(NULL, file, MAX_PATH);
[49] 
[50]     if (n == 0) {
[51]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[52]                       "GetModuleFileName() failed");
[53]         return NGX_INVALID_PID;
[54]     }
[55] 
[56]     file[n] = '\0';
[57] 
[58]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[59]                    "GetModuleFileName: \"%s\"", file);
[60] 
[61]     ctx.path = file;
[62]     ctx.name = name;
[63]     ctx.args = GetCommandLine();
[64]     ctx.argv = NULL;
[65]     ctx.envp = NULL;
[66] 
[67]     pid = ngx_execute(cycle, &ctx);
[68] 
[69]     if (pid == NGX_INVALID_PID) {
[70]         return pid;
[71]     }
[72] 
[73]     ngx_memzero(&ngx_processes[s], sizeof(ngx_process_t));
[74] 
[75]     ngx_processes[s].handle = ctx.child;
[76]     ngx_processes[s].pid = pid;
[77]     ngx_processes[s].name = name;
[78] 
[79]     ngx_sprintf(ngx_processes[s].term_event, "ngx_%s_term_%P%Z", name, pid);
[80]     ngx_sprintf(ngx_processes[s].quit_event, "ngx_%s_quit_%P%Z", name, pid);
[81]     ngx_sprintf(ngx_processes[s].reopen_event, "ngx_%s_reopen_%P%Z",
[82]                 name, pid);
[83] 
[84]     events[0] = ngx_master_process_event;
[85]     events[1] = ctx.child;
[86] 
[87]     rc = WaitForMultipleObjects(2, events, 0, 5000);
[88] 
[89]     ngx_time_update();
[90] 
[91]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
[92]                    "WaitForMultipleObjects: %ul", rc);
[93] 
[94]     switch (rc) {
[95] 
[96]     case WAIT_OBJECT_0:
[97] 
[98]         ngx_processes[s].term = OpenEvent(EVENT_MODIFY_STATE, 0,
[99]                                           (char *) ngx_processes[s].term_event);
[100]         if (ngx_processes[s].term == NULL) {
[101]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[102]                           "OpenEvent(\"%s\") failed",
[103]                           ngx_processes[s].term_event);
[104]             goto failed;
[105]         }
[106] 
[107]         ngx_processes[s].quit = OpenEvent(EVENT_MODIFY_STATE, 0,
[108]                                           (char *) ngx_processes[s].quit_event);
[109]         if (ngx_processes[s].quit == NULL) {
[110]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[111]                           "OpenEvent(\"%s\") failed",
[112]                           ngx_processes[s].quit_event);
[113]             goto failed;
[114]         }
[115] 
[116]         ngx_processes[s].reopen = OpenEvent(EVENT_MODIFY_STATE, 0,
[117]                                        (char *) ngx_processes[s].reopen_event);
[118]         if (ngx_processes[s].reopen == NULL) {
[119]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[120]                           "OpenEvent(\"%s\") failed",
[121]                           ngx_processes[s].reopen_event);
[122]             goto failed;
[123]         }
[124] 
[125]         if (ResetEvent(ngx_master_process_event) == 0) {
[126]             ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[127]                           "ResetEvent(\"%s\") failed",
[128]                           ngx_master_process_event_name);
[129]             goto failed;
[130]         }
[131] 
[132]         break;
[133] 
[134]     case WAIT_OBJECT_0 + 1:
[135]         if (GetExitCodeProcess(ctx.child, &code) == 0) {
[136]             ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[137]                           "GetExitCodeProcess(%P) failed", pid);
[138]         }
[139] 
[140]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[141]                       "%s process %P exited with code %Xl",
[142]                       name, pid, code);
[143] 
[144]         goto failed;
[145] 
[146]     case WAIT_TIMEOUT:
[147]         ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
[148]                       "the event \"%s\" was not signaled for 5s",
[149]                       ngx_master_process_event_name);
[150]         goto failed;
[151] 
[152]     case WAIT_FAILED:
[153]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[154]                       "WaitForSingleObject(\"%s\") failed",
[155]                       ngx_master_process_event_name);
[156] 
[157]         goto failed;
[158]     }
[159] 
[160]     if (respawn >= 0) {
[161]         return pid;
[162]     }
[163] 
[164]     switch (respawn) {
[165] 
[166]     case NGX_PROCESS_RESPAWN:
[167]         ngx_processes[s].just_spawn = 0;
[168]         break;
[169] 
[170]     case NGX_PROCESS_JUST_RESPAWN:
[171]         ngx_processes[s].just_spawn = 1;
[172]         break;
[173]     }
[174] 
[175]     if (s == ngx_last_process) {
[176]         ngx_last_process++;
[177]     }
[178] 
[179]     return pid;
[180] 
[181] failed:
[182] 
[183]     if (ngx_processes[s].reopen) {
[184]         ngx_close_handle(ngx_processes[s].reopen);
[185]     }
[186] 
[187]     if (ngx_processes[s].quit) {
[188]         ngx_close_handle(ngx_processes[s].quit);
[189]     }
[190] 
[191]     if (ngx_processes[s].term) {
[192]         ngx_close_handle(ngx_processes[s].term);
[193]     }
[194] 
[195]     TerminateProcess(ngx_processes[s].handle, 2);
[196] 
[197]     if (ngx_processes[s].handle) {
[198]         ngx_close_handle(ngx_processes[s].handle);
[199]         ngx_processes[s].handle = NULL;
[200]     }
[201] 
[202]     return NGX_INVALID_PID;
[203] }
[204] 
[205] 
[206] ngx_pid_t
[207] ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
[208] {
[209]     STARTUPINFO          si;
[210]     PROCESS_INFORMATION  pi;
[211] 
[212]     ngx_memzero(&si, sizeof(STARTUPINFO));
[213]     si.cb = sizeof(STARTUPINFO);
[214] 
[215]     ngx_memzero(&pi, sizeof(PROCESS_INFORMATION));
[216] 
[217]     if (CreateProcess(ctx->path, ctx->args,
[218]                       NULL, NULL, 0, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)
[219]         == 0)
[220]     {
[221]         ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
[222]                       "CreateProcess(\"%s\") failed", ngx_argv[0]);
[223] 
[224]         return 0;
[225]     }
[226] 
[227]     ctx->child = pi.hProcess;
[228] 
[229]     if (CloseHandle(pi.hThread) == 0) {
[230]         ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
[231]                       "CloseHandle(pi.hThread) failed");
[232]     }
[233] 
[234]     ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
[235]                   "start %s process %P", ctx->name, pi.dwProcessId);
[236] 
[237]     return pi.dwProcessId;
[238] }
