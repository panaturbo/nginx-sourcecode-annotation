[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_CACHE_H_INCLUDED_
[9] #define _NGX_HTTP_CACHE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] #define NGX_HTTP_CACHE_MISS          1
[18] #define NGX_HTTP_CACHE_BYPASS        2
[19] #define NGX_HTTP_CACHE_EXPIRED       3
[20] #define NGX_HTTP_CACHE_STALE         4
[21] #define NGX_HTTP_CACHE_UPDATING      5
[22] #define NGX_HTTP_CACHE_REVALIDATED   6
[23] #define NGX_HTTP_CACHE_HIT           7
[24] #define NGX_HTTP_CACHE_SCARCE        8
[25] 
[26] #define NGX_HTTP_CACHE_KEY_LEN       16
[27] #define NGX_HTTP_CACHE_ETAG_LEN      128
[28] #define NGX_HTTP_CACHE_VARY_LEN      128
[29] 
[30] #define NGX_HTTP_CACHE_VERSION       5
[31] 
[32] 
[33] typedef struct {
[34]     ngx_uint_t                       status;
[35]     time_t                           valid;
[36] } ngx_http_cache_valid_t;
[37] 
[38] 
[39] typedef struct {
[40]     ngx_rbtree_node_t                node;
[41]     ngx_queue_t                      queue;
[42] 
[43]     u_char                           key[NGX_HTTP_CACHE_KEY_LEN
[44]                                          - sizeof(ngx_rbtree_key_t)];
[45] 
[46]     unsigned                         count:20;
[47]     unsigned                         uses:10;
[48]     unsigned                         valid_msec:10;
[49]     unsigned                         error:10;
[50]     unsigned                         exists:1;
[51]     unsigned                         updating:1;
[52]     unsigned                         deleting:1;
[53]     unsigned                         purged:1;
[54]                                      /* 10 unused bits */
[55] 
[56]     ngx_file_uniq_t                  uniq;
[57]     time_t                           expire;
[58]     time_t                           valid_sec;
[59]     size_t                           body_start;
[60]     off_t                            fs_size;
[61]     ngx_msec_t                       lock_time;
[62] } ngx_http_file_cache_node_t;
[63] 
[64] 
[65] struct ngx_http_cache_s {
[66]     ngx_file_t                       file;
[67]     ngx_array_t                      keys;
[68]     uint32_t                         crc32;
[69]     u_char                           key[NGX_HTTP_CACHE_KEY_LEN];
[70]     u_char                           main[NGX_HTTP_CACHE_KEY_LEN];
[71] 
[72]     ngx_file_uniq_t                  uniq;
[73]     time_t                           valid_sec;
[74]     time_t                           updating_sec;
[75]     time_t                           error_sec;
[76]     time_t                           last_modified;
[77]     time_t                           date;
[78] 
[79]     ngx_str_t                        etag;
[80]     ngx_str_t                        vary;
[81]     u_char                           variant[NGX_HTTP_CACHE_KEY_LEN];
[82] 
[83]     size_t                           buffer_size;
[84]     size_t                           header_start;
[85]     size_t                           body_start;
[86]     off_t                            length;
[87]     off_t                            fs_size;
[88] 
[89]     ngx_uint_t                       min_uses;
[90]     ngx_uint_t                       error;
[91]     ngx_uint_t                       valid_msec;
[92]     ngx_uint_t                       vary_tag;
[93] 
[94]     ngx_buf_t                       *buf;
[95] 
[96]     ngx_http_file_cache_t           *file_cache;
[97]     ngx_http_file_cache_node_t      *node;
[98] 
[99] #if (NGX_THREADS || NGX_COMPAT)
[100]     ngx_thread_task_t               *thread_task;
[101] #endif
[102] 
[103]     ngx_msec_t                       lock_timeout;
[104]     ngx_msec_t                       lock_age;
[105]     ngx_msec_t                       lock_time;
[106]     ngx_msec_t                       wait_time;
[107] 
[108]     ngx_event_t                      wait_event;
[109] 
[110]     unsigned                         lock:1;
[111]     unsigned                         waiting:1;
[112] 
[113]     unsigned                         updated:1;
[114]     unsigned                         updating:1;
[115]     unsigned                         exists:1;
[116]     unsigned                         temp_file:1;
[117]     unsigned                         purged:1;
[118]     unsigned                         reading:1;
[119]     unsigned                         secondary:1;
[120]     unsigned                         update_variant:1;
[121]     unsigned                         background:1;
[122] 
[123]     unsigned                         stale_updating:1;
[124]     unsigned                         stale_error:1;
[125] };
[126] 
[127] 
[128] typedef struct {
[129]     ngx_uint_t                       version;
[130]     time_t                           valid_sec;
[131]     time_t                           updating_sec;
[132]     time_t                           error_sec;
[133]     time_t                           last_modified;
[134]     time_t                           date;
[135]     uint32_t                         crc32;
[136]     u_short                          valid_msec;
[137]     u_short                          header_start;
[138]     u_short                          body_start;
[139]     u_char                           etag_len;
[140]     u_char                           etag[NGX_HTTP_CACHE_ETAG_LEN];
[141]     u_char                           vary_len;
[142]     u_char                           vary[NGX_HTTP_CACHE_VARY_LEN];
[143]     u_char                           variant[NGX_HTTP_CACHE_KEY_LEN];
[144] } ngx_http_file_cache_header_t;
[145] 
[146] 
[147] typedef struct {
[148]     ngx_rbtree_t                     rbtree;
[149]     ngx_rbtree_node_t                sentinel;
[150]     ngx_queue_t                      queue;
[151]     ngx_atomic_t                     cold;
[152]     ngx_atomic_t                     loading;
[153]     off_t                            size;
[154]     ngx_uint_t                       count;
[155]     ngx_uint_t                       watermark;
[156] } ngx_http_file_cache_sh_t;
[157] 
[158] 
[159] struct ngx_http_file_cache_s {
[160]     ngx_http_file_cache_sh_t        *sh;
[161]     ngx_slab_pool_t                 *shpool;
[162] 
[163]     ngx_path_t                      *path;
[164] 
[165]     off_t                            min_free;
[166]     off_t                            max_size;
[167]     size_t                           bsize;
[168] 
[169]     time_t                           inactive;
[170] 
[171]     time_t                           fail_time;
[172] 
[173]     ngx_uint_t                       files;
[174]     ngx_uint_t                       loader_files;
[175]     ngx_msec_t                       last;
[176]     ngx_msec_t                       loader_sleep;
[177]     ngx_msec_t                       loader_threshold;
[178] 
[179]     ngx_uint_t                       manager_files;
[180]     ngx_msec_t                       manager_sleep;
[181]     ngx_msec_t                       manager_threshold;
[182] 
[183]     ngx_shm_zone_t                  *shm_zone;
[184] 
[185]     ngx_uint_t                       use_temp_path;
[186]                                      /* unsigned use_temp_path:1 */
[187] };
[188] 
[189] 
[190] ngx_int_t ngx_http_file_cache_new(ngx_http_request_t *r);
[191] ngx_int_t ngx_http_file_cache_create(ngx_http_request_t *r);
[192] void ngx_http_file_cache_create_key(ngx_http_request_t *r);
[193] ngx_int_t ngx_http_file_cache_open(ngx_http_request_t *r);
[194] ngx_int_t ngx_http_file_cache_set_header(ngx_http_request_t *r, u_char *buf);
[195] void ngx_http_file_cache_update(ngx_http_request_t *r, ngx_temp_file_t *tf);
[196] void ngx_http_file_cache_update_header(ngx_http_request_t *r);
[197] ngx_int_t ngx_http_cache_send(ngx_http_request_t *);
[198] void ngx_http_file_cache_free(ngx_http_cache_t *c, ngx_temp_file_t *tf);
[199] time_t ngx_http_file_cache_valid(ngx_array_t *cache_valid, ngx_uint_t status);
[200] 
[201] char *ngx_http_file_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[202]     void *conf);
[203] char *ngx_http_file_cache_valid_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
[204]     void *conf);
[205] 
[206] 
[207] extern ngx_str_t  ngx_http_cache_status[];
[208] 
[209] 
[210] #endif /* _NGX_HTTP_CACHE_H_INCLUDED_ */
