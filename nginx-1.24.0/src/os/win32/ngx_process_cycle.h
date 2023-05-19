[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
[9] #define _NGX_PROCESS_CYCLE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_PROCESS_SINGLE     0
[17] #define NGX_PROCESS_MASTER     1
[18] #define NGX_PROCESS_SIGNALLER  2
[19] #define NGX_PROCESS_WORKER     3
[20] 
[21] 
[22] void ngx_master_process_cycle(ngx_cycle_t *cycle);
[23] void ngx_single_process_cycle(ngx_cycle_t *cycle);
[24] void ngx_close_handle(HANDLE h);
[25] 
[26] 
[27] extern ngx_uint_t      ngx_process;
[28] extern ngx_uint_t      ngx_worker;
[29] extern ngx_pid_t       ngx_pid;
[30] extern ngx_uint_t      ngx_exiting;
[31] 
[32] extern sig_atomic_t    ngx_quit;
[33] extern sig_atomic_t    ngx_terminate;
[34] extern sig_atomic_t    ngx_reopen;
[35] 
[36] extern ngx_uint_t      ngx_inherited;
[37] extern ngx_pid_t       ngx_new_binary;
[38] 
[39] 
[40] extern HANDLE          ngx_master_process_event;
[41] extern char            ngx_master_process_event_name[];
[42] 
[43] 
[44] #endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
