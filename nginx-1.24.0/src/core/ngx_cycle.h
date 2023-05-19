[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CYCLE_H_INCLUDED_
[9] #define _NGX_CYCLE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #ifndef NGX_CYCLE_POOL_SIZE
[17] #define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
[18] #endif
[19] 
[20] 
[21] #define NGX_DEBUG_POINTS_STOP   1
[22] #define NGX_DEBUG_POINTS_ABORT  2
[23] 
[24] 
[25] typedef struct ngx_shm_zone_s  ngx_shm_zone_t;
[26] 
[27] typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);
[28] 
[29] struct ngx_shm_zone_s {
[30]     void                     *data;
[31]     ngx_shm_t                 shm;
[32]     ngx_shm_zone_init_pt      init;
[33]     void                     *tag;
[34]     void                     *sync;
[35]     ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
[36] };
[37] 
[38] 
[39] struct ngx_cycle_s {
[40]     void                  ****conf_ctx;
[41]     ngx_pool_t               *pool;
[42] 
[43]     ngx_log_t                *log;
[44]     ngx_log_t                 new_log;
[45] 
[46]     ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */
[47] 
[48]     ngx_connection_t        **files;
[49]     ngx_connection_t         *free_connections;
[50]     ngx_uint_t                free_connection_n;
[51] 
[52]     ngx_module_t            **modules;
[53]     ngx_uint_t                modules_n;
[54]     ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */
[55] 
[56]     ngx_queue_t               reusable_connections_queue;
[57]     ngx_uint_t                reusable_connections_n;
[58]     time_t                    connections_reuse_time;
[59] 
[60]     ngx_array_t               listening;
[61]     ngx_array_t               paths;
[62] 
[63]     ngx_array_t               config_dump;
[64]     ngx_rbtree_t              config_dump_rbtree;
[65]     ngx_rbtree_node_t         config_dump_sentinel;
[66] 
[67]     ngx_list_t                open_files;
[68]     ngx_list_t                shared_memory;
[69] 
[70]     ngx_uint_t                connection_n;
[71]     ngx_uint_t                files_n;
[72] 
[73]     ngx_connection_t         *connections;
[74]     ngx_event_t              *read_events;
[75]     ngx_event_t              *write_events;
[76] 
[77]     ngx_cycle_t              *old_cycle;
[78] 
[79]     ngx_str_t                 conf_file;
[80]     ngx_str_t                 conf_param;
[81]     ngx_str_t                 conf_prefix;
[82]     ngx_str_t                 prefix;
[83]     ngx_str_t                 error_log;
[84]     ngx_str_t                 lock_file;
[85]     ngx_str_t                 hostname;
[86] };
[87] 
[88] 
[89] typedef struct {
[90]     ngx_flag_t                daemon;
[91]     ngx_flag_t                master;
[92] 
[93]     ngx_msec_t                timer_resolution;
[94]     ngx_msec_t                shutdown_timeout;
[95] 
[96]     ngx_int_t                 worker_processes;
[97]     ngx_int_t                 debug_points;
[98] 
[99]     ngx_int_t                 rlimit_nofile;
[100]     off_t                     rlimit_core;
[101] 
[102]     int                       priority;
[103] 
[104]     ngx_uint_t                cpu_affinity_auto;
[105]     ngx_uint_t                cpu_affinity_n;
[106]     ngx_cpuset_t             *cpu_affinity;
[107] 
[108]     char                     *username;
[109]     ngx_uid_t                 user;
[110]     ngx_gid_t                 group;
[111] 
[112]     ngx_str_t                 working_directory;
[113]     ngx_str_t                 lock_file;
[114] 
[115]     ngx_str_t                 pid;
[116]     ngx_str_t                 oldpid;
[117] 
[118]     ngx_array_t               env;
[119]     char                    **environment;
[120] 
[121]     ngx_uint_t                transparent;  /* unsigned  transparent:1; */
[122] } ngx_core_conf_t;
[123] 
[124] 
[125] #define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)
[126] 
[127] 
[128] ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
[129] ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
[130] void ngx_delete_pidfile(ngx_cycle_t *cycle);
[131] ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
[132] void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
[133] char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
[134] ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
[135] ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
[136] ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
[137]     size_t size, void *tag);
[138] void ngx_set_shutdown_timer(ngx_cycle_t *cycle);
[139] 
[140] 
[141] extern volatile ngx_cycle_t  *ngx_cycle;
[142] extern ngx_array_t            ngx_old_cycles;
[143] extern ngx_module_t           ngx_core_module;
[144] extern ngx_uint_t             ngx_test_config;
[145] extern ngx_uint_t             ngx_dump_config;
[146] extern ngx_uint_t             ngx_quiet_mode;
[147] 
[148] 
[149] #endif /* _NGX_CYCLE_H_INCLUDED_ */
