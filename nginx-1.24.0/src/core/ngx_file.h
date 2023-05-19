[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_FILE_H_INCLUDED_
[9] #define _NGX_FILE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] struct ngx_file_s {
[17]     ngx_fd_t                   fd;
[18]     ngx_str_t                  name;
[19]     ngx_file_info_t            info;
[20] 
[21]     off_t                      offset;
[22]     off_t                      sys_offset;
[23] 
[24]     ngx_log_t                 *log;
[25] 
[26] #if (NGX_THREADS || NGX_COMPAT)
[27]     ngx_int_t                (*thread_handler)(ngx_thread_task_t *task,
[28]                                                ngx_file_t *file);
[29]     void                      *thread_ctx;
[30]     ngx_thread_task_t         *thread_task;
[31] #endif
[32] 
[33] #if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
[34]     ngx_event_aio_t           *aio;
[35] #endif
[36] 
[37]     unsigned                   valid_info:1;
[38]     unsigned                   directio:1;
[39] };
[40] 
[41] 
[42] #define NGX_MAX_PATH_LEVEL  3
[43] 
[44] 
[45] typedef ngx_msec_t (*ngx_path_manager_pt) (void *data);
[46] typedef ngx_msec_t (*ngx_path_purger_pt) (void *data);
[47] typedef void (*ngx_path_loader_pt) (void *data);
[48] 
[49] 
[50] typedef struct {
[51]     ngx_str_t                  name;
[52]     size_t                     len;
[53]     size_t                     level[NGX_MAX_PATH_LEVEL];
[54] 
[55]     ngx_path_manager_pt        manager;
[56]     ngx_path_purger_pt         purger;
[57]     ngx_path_loader_pt         loader;
[58]     void                      *data;
[59] 
[60]     u_char                    *conf_file;
[61]     ngx_uint_t                 line;
[62] } ngx_path_t;
[63] 
[64] 
[65] typedef struct {
[66]     ngx_str_t                  name;
[67]     size_t                     level[NGX_MAX_PATH_LEVEL];
[68] } ngx_path_init_t;
[69] 
[70] 
[71] typedef struct {
[72]     ngx_file_t                 file;
[73]     off_t                      offset;
[74]     ngx_path_t                *path;
[75]     ngx_pool_t                *pool;
[76]     char                      *warn;
[77] 
[78]     ngx_uint_t                 access;
[79] 
[80]     unsigned                   log_level:8;
[81]     unsigned                   persistent:1;
[82]     unsigned                   clean:1;
[83]     unsigned                   thread_write:1;
[84] } ngx_temp_file_t;
[85] 
[86] 
[87] typedef struct {
[88]     ngx_uint_t                 access;
[89]     ngx_uint_t                 path_access;
[90]     time_t                     time;
[91]     ngx_fd_t                   fd;
[92] 
[93]     unsigned                   create_path:1;
[94]     unsigned                   delete_file:1;
[95] 
[96]     ngx_log_t                 *log;
[97] } ngx_ext_rename_file_t;
[98] 
[99] 
[100] typedef struct {
[101]     off_t                      size;
[102]     size_t                     buf_size;
[103] 
[104]     ngx_uint_t                 access;
[105]     time_t                     time;
[106] 
[107]     ngx_log_t                 *log;
[108] } ngx_copy_file_t;
[109] 
[110] 
[111] typedef struct ngx_tree_ctx_s  ngx_tree_ctx_t;
[112] 
[113] typedef ngx_int_t (*ngx_tree_init_handler_pt) (void *ctx, void *prev);
[114] typedef ngx_int_t (*ngx_tree_handler_pt) (ngx_tree_ctx_t *ctx, ngx_str_t *name);
[115] 
[116] struct ngx_tree_ctx_s {
[117]     off_t                      size;
[118]     off_t                      fs_size;
[119]     ngx_uint_t                 access;
[120]     time_t                     mtime;
[121] 
[122]     ngx_tree_init_handler_pt   init_handler;
[123]     ngx_tree_handler_pt        file_handler;
[124]     ngx_tree_handler_pt        pre_tree_handler;
[125]     ngx_tree_handler_pt        post_tree_handler;
[126]     ngx_tree_handler_pt        spec_handler;
[127] 
[128]     void                      *data;
[129]     size_t                     alloc;
[130] 
[131]     ngx_log_t                 *log;
[132] };
[133] 
[134] 
[135] ngx_int_t ngx_get_full_name(ngx_pool_t *pool, ngx_str_t *prefix,
[136]     ngx_str_t *name);
[137] 
[138] ssize_t ngx_write_chain_to_temp_file(ngx_temp_file_t *tf, ngx_chain_t *chain);
[139] ngx_int_t ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path,
[140]     ngx_pool_t *pool, ngx_uint_t persistent, ngx_uint_t clean,
[141]     ngx_uint_t access);
[142] void ngx_create_hashed_filename(ngx_path_t *path, u_char *file, size_t len);
[143] ngx_int_t ngx_create_path(ngx_file_t *file, ngx_path_t *path);
[144] ngx_err_t ngx_create_full_path(u_char *dir, ngx_uint_t access);
[145] ngx_int_t ngx_add_path(ngx_conf_t *cf, ngx_path_t **slot);
[146] ngx_int_t ngx_create_paths(ngx_cycle_t *cycle, ngx_uid_t user);
[147] ngx_int_t ngx_ext_rename_file(ngx_str_t *src, ngx_str_t *to,
[148]     ngx_ext_rename_file_t *ext);
[149] ngx_int_t ngx_copy_file(u_char *from, u_char *to, ngx_copy_file_t *cf);
[150] ngx_int_t ngx_walk_tree(ngx_tree_ctx_t *ctx, ngx_str_t *tree);
[151] 
[152] ngx_atomic_uint_t ngx_next_temp_number(ngx_uint_t collision);
[153] 
[154] char *ngx_conf_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[155] char *ngx_conf_merge_path_value(ngx_conf_t *cf, ngx_path_t **path,
[156]     ngx_path_t *prev, ngx_path_init_t *init);
[157] char *ngx_conf_set_access_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[158] 
[159] 
[160] extern ngx_atomic_t      *ngx_temp_number;
[161] extern ngx_atomic_int_t   ngx_random_number;
[162] 
[163] 
[164] #endif /* _NGX_FILE_H_INCLUDED_ */
