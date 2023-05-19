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
[12] #include <ngx_setaffinity.h>
[13] #include <ngx_setproctitle.h>
[14] 
[15] 
[16] typedef pid_t       ngx_pid_t;
[17] 
[18] #define NGX_INVALID_PID  -1
[19] 
[20] typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);
[21] 
[22] typedef struct {
[23]     ngx_pid_t           pid;
[24]     int                 status;
[25]     ngx_socket_t        channel[2];
[26] 
[27]     ngx_spawn_proc_pt   proc;
[28]     void               *data;
[29]     char               *name;
[30] 
[31]     unsigned            respawn:1;
[32]     unsigned            just_spawn:1;
[33]     unsigned            detached:1;
[34]     unsigned            exiting:1;
[35]     unsigned            exited:1;
[36] } ngx_process_t;
[37] 
[38] 
[39] typedef struct {
[40]     char         *path;
[41]     char         *name;
[42]     char *const  *argv;
[43]     char *const  *envp;
[44] } ngx_exec_ctx_t;
[45] 
[46] 
[47] #define NGX_MAX_PROCESSES         1024
[48] 
[49] #define NGX_PROCESS_NORESPAWN     -1
[50] #define NGX_PROCESS_JUST_SPAWN    -2
[51] #define NGX_PROCESS_RESPAWN       -3
[52] #define NGX_PROCESS_JUST_RESPAWN  -4
[53] #define NGX_PROCESS_DETACHED      -5
[54] 
[55] 
[56] #define ngx_getpid   getpid
[57] #define ngx_getppid  getppid
[58] 
[59] #ifndef ngx_log_pid
[60] #define ngx_log_pid  ngx_pid
[61] #endif
[62] 
[63] 
[64] ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
[65]     ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
[66] ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
[67] ngx_int_t ngx_init_signals(ngx_log_t *log);
[68] void ngx_debug_point(void);
[69] 
[70] 
[71] #if (NGX_HAVE_SCHED_YIELD)
[72] #define ngx_sched_yield()  sched_yield()
[73] #else
[74] #define ngx_sched_yield()  usleep(1)
[75] #endif
[76] 
[77] 
[78] extern int            ngx_argc;
[79] extern char         **ngx_argv;
[80] extern char         **ngx_os_argv;
[81] 
[82] extern ngx_pid_t      ngx_pid;
[83] extern ngx_pid_t      ngx_parent;
[84] extern ngx_socket_t   ngx_channel;
[85] extern ngx_int_t      ngx_process_slot;
[86] extern ngx_int_t      ngx_last_process;
[87] extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];
[88] 
[89] 
[90] #endif /* _NGX_PROCESS_H_INCLUDED_ */
