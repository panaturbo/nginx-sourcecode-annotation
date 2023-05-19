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
[12] #ifndef _NGX_OPEN_FILE_CACHE_H_INCLUDED_
[13] #define _NGX_OPEN_FILE_CACHE_H_INCLUDED_
[14] 
[15] 
[16] #define NGX_OPEN_FILE_DIRECTIO_OFF  NGX_MAX_OFF_T_VALUE
[17] 
[18] 
[19] typedef struct {
[20]     ngx_fd_t                 fd;
[21]     ngx_file_uniq_t          uniq;
[22]     time_t                   mtime;
[23]     off_t                    size;
[24]     off_t                    fs_size;
[25]     off_t                    directio;
[26]     size_t                   read_ahead;
[27] 
[28]     ngx_err_t                err;
[29]     char                    *failed;
[30] 
[31]     time_t                   valid;
[32] 
[33]     ngx_uint_t               min_uses;
[34] 
[35] #if (NGX_HAVE_OPENAT)
[36]     size_t                   disable_symlinks_from;
[37]     unsigned                 disable_symlinks:2;
[38] #endif
[39] 
[40]     unsigned                 test_dir:1;
[41]     unsigned                 test_only:1;
[42]     unsigned                 log:1;
[43]     unsigned                 errors:1;
[44]     unsigned                 events:1;
[45] 
[46]     unsigned                 is_dir:1;
[47]     unsigned                 is_file:1;
[48]     unsigned                 is_link:1;
[49]     unsigned                 is_exec:1;
[50]     unsigned                 is_directio:1;
[51] } ngx_open_file_info_t;
[52] 
[53] 
[54] typedef struct ngx_cached_open_file_s  ngx_cached_open_file_t;
[55] 
[56] struct ngx_cached_open_file_s {
[57]     ngx_rbtree_node_t        node;
[58]     ngx_queue_t              queue;
[59] 
[60]     u_char                  *name;
[61]     time_t                   created;
[62]     time_t                   accessed;
[63] 
[64]     ngx_fd_t                 fd;
[65]     ngx_file_uniq_t          uniq;
[66]     time_t                   mtime;
[67]     off_t                    size;
[68]     ngx_err_t                err;
[69] 
[70]     uint32_t                 uses;
[71] 
[72] #if (NGX_HAVE_OPENAT)
[73]     size_t                   disable_symlinks_from;
[74]     unsigned                 disable_symlinks:2;
[75] #endif
[76] 
[77]     unsigned                 count:24;
[78]     unsigned                 close:1;
[79]     unsigned                 use_event:1;
[80] 
[81]     unsigned                 is_dir:1;
[82]     unsigned                 is_file:1;
[83]     unsigned                 is_link:1;
[84]     unsigned                 is_exec:1;
[85]     unsigned                 is_directio:1;
[86] 
[87]     ngx_event_t             *event;
[88] };
[89] 
[90] 
[91] typedef struct {
[92]     ngx_rbtree_t             rbtree;
[93]     ngx_rbtree_node_t        sentinel;
[94]     ngx_queue_t              expire_queue;
[95] 
[96]     ngx_uint_t               current;
[97]     ngx_uint_t               max;
[98]     time_t                   inactive;
[99] } ngx_open_file_cache_t;
[100] 
[101] 
[102] typedef struct {
[103]     ngx_open_file_cache_t   *cache;
[104]     ngx_cached_open_file_t  *file;
[105]     ngx_uint_t               min_uses;
[106]     ngx_log_t               *log;
[107] } ngx_open_file_cache_cleanup_t;
[108] 
[109] 
[110] typedef struct {
[111] 
[112]     /* ngx_connection_t stub to allow use c->fd as event ident */
[113]     void                    *data;
[114]     ngx_event_t             *read;
[115]     ngx_event_t             *write;
[116]     ngx_fd_t                 fd;
[117] 
[118]     ngx_cached_open_file_t  *file;
[119]     ngx_open_file_cache_t   *cache;
[120] } ngx_open_file_cache_event_t;
[121] 
[122] 
[123] ngx_open_file_cache_t *ngx_open_file_cache_init(ngx_pool_t *pool,
[124]     ngx_uint_t max, time_t inactive);
[125] ngx_int_t ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
[126]     ngx_open_file_info_t *of, ngx_pool_t *pool);
[127] 
[128] 
[129] #endif /* _NGX_OPEN_FILE_CACHE_H_INCLUDED_ */
