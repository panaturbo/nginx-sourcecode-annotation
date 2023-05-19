[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_PROCESS_H_INCLUDED_
[9] #define _NGX_PROCESS_H_INCLUDED_
[10] 
[11] 
[12] typedef DWORD               ngx_pid_t;
[13] #define NGX_INVALID_PID     0
[14] 
[15] 
[16] #define ngx_getpid          GetCurrentProcessId
[17] #define ngx_getppid()       0
[18] #define ngx_log_pid         ngx_pid
[19] 
[20] 
[21] #define NGX_PROCESS_SYNC_NAME                                                 \
[22]     (sizeof("ngx_cache_manager_mutex_") + NGX_INT32_LEN)
[23] 
[24] 
[25] typedef uint64_t            ngx_cpuset_t;
[26] 
[27] 
[28] typedef struct {
[29]     HANDLE                  handle;
[30]     ngx_pid_t               pid;
[31]     char                   *name;
[32] 
[33]     HANDLE                  term;
[34]     HANDLE                  quit;
[35]     HANDLE                  reopen;
[36] 
[37]     u_char                  term_event[NGX_PROCESS_SYNC_NAME];
[38]     u_char                  quit_event[NGX_PROCESS_SYNC_NAME];
[39]     u_char                  reopen_event[NGX_PROCESS_SYNC_NAME];
[40] 
[41]     unsigned                just_spawn:1;
[42]     unsigned                exiting:1;
[43] } ngx_process_t;
[44] 
[45] 
[46] typedef struct {
[47]     char                   *path;
[48]     char                   *name;
[49]     char                   *args;
[50]     char *const            *argv;
[51]     char *const            *envp;
[52]     HANDLE                  child;
[53] } ngx_exec_ctx_t;
[54] 
[55] 
[56] ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle, char *name, ngx_int_t respawn);
[57] ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
[58] 
[59] #define ngx_debug_point()
[60] #define ngx_sched_yield()   SwitchToThread()
[61] 
[62] 
[63] #define NGX_MAX_PROCESSES         (MAXIMUM_WAIT_OBJECTS - 4)
[64] 
[65] #define NGX_PROCESS_RESPAWN       -2
[66] #define NGX_PROCESS_JUST_RESPAWN  -3
[67] 
[68] 
[69] extern int                  ngx_argc;
[70] extern char               **ngx_argv;
[71] extern char               **ngx_os_argv;
[72] 
[73] extern ngx_int_t            ngx_last_process;
[74] extern ngx_process_t        ngx_processes[NGX_MAX_PROCESSES];
[75] 
[76] extern ngx_pid_t            ngx_pid;
[77] extern ngx_pid_t            ngx_parent;
[78] 
[79] 
[80] #endif /* _NGX_PROCESS_H_INCLUDED_ */
