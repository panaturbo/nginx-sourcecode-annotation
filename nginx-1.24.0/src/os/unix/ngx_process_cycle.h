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
[16] #define NGX_CMD_OPEN_CHANNEL   1
[17] #define NGX_CMD_CLOSE_CHANNEL  2
[18] #define NGX_CMD_QUIT           3
[19] #define NGX_CMD_TERMINATE      4
[20] #define NGX_CMD_REOPEN         5
[21] 
[22] 
[23] #define NGX_PROCESS_SINGLE     0
[24] #define NGX_PROCESS_MASTER     1
[25] #define NGX_PROCESS_SIGNALLER  2
[26] #define NGX_PROCESS_WORKER     3
[27] #define NGX_PROCESS_HELPER     4
[28] 
[29] 
[30] typedef struct {
[31]     ngx_event_handler_pt       handler;
[32]     char                      *name;
[33]     ngx_msec_t                 delay;
[34] } ngx_cache_manager_ctx_t;
[35] 
[36] 
[37] void ngx_master_process_cycle(ngx_cycle_t *cycle);
[38] void ngx_single_process_cycle(ngx_cycle_t *cycle);
[39] 
[40] 
[41] extern ngx_uint_t      ngx_process;
[42] extern ngx_uint_t      ngx_worker;
[43] extern ngx_pid_t       ngx_pid;
[44] extern ngx_pid_t       ngx_new_binary;
[45] extern ngx_uint_t      ngx_inherited;
[46] extern ngx_uint_t      ngx_daemonized;
[47] extern ngx_uint_t      ngx_exiting;
[48] 
[49] extern sig_atomic_t    ngx_reap;
[50] extern sig_atomic_t    ngx_sigio;
[51] extern sig_atomic_t    ngx_sigalrm;
[52] extern sig_atomic_t    ngx_quit;
[53] extern sig_atomic_t    ngx_debug_quit;
[54] extern sig_atomic_t    ngx_terminate;
[55] extern sig_atomic_t    ngx_noaccept;
[56] extern sig_atomic_t    ngx_reconfigure;
[57] extern sig_atomic_t    ngx_reopen;
[58] extern sig_atomic_t    ngx_change_binary;
[59] 
[60] 
[61] #endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
