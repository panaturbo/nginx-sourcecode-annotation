[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_BUF_H_INCLUDED_
[9] #define _NGX_BUF_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef void *            ngx_buf_tag_t;
[17] 
[18] typedef struct ngx_buf_s  ngx_buf_t;
[19] 
[20] struct ngx_buf_s {
[21]     u_char          *pos;
[22]     u_char          *last;
[23]     off_t            file_pos;
[24]     off_t            file_last;
[25] 
[26]     u_char          *start;         /* start of buffer */
[27]     u_char          *end;           /* end of buffer */
[28]     ngx_buf_tag_t    tag;
[29]     ngx_file_t      *file;
[30]     ngx_buf_t       *shadow;
[31] 
[32] 
[33]     /* the buf's content could be changed */
[34]     unsigned         temporary:1;
[35] 
[36]     /*
[37]      * the buf's content is in a memory cache or in a read only memory
[38]      * and must not be changed
[39]      */
[40]     unsigned         memory:1;
[41] 
[42]     /* the buf's content is mmap()ed and must not be changed */
[43]     unsigned         mmap:1;
[44] 
[45]     unsigned         recycled:1;
[46]     unsigned         in_file:1;
[47]     unsigned         flush:1;
[48]     unsigned         sync:1;
[49]     unsigned         last_buf:1;
[50]     unsigned         last_in_chain:1;
[51] 
[52]     unsigned         last_shadow:1;
[53]     unsigned         temp_file:1;
[54] 
[55]     /* STUB */ int   num;
[56] };
[57] 
[58] 
[59] struct ngx_chain_s {
[60]     ngx_buf_t    *buf;
[61]     ngx_chain_t  *next;
[62] };
[63] 
[64] 
[65] typedef struct {
[66]     ngx_int_t    num;
[67]     size_t       size;
[68] } ngx_bufs_t;
[69] 
[70] 
[71] typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;
[72] 
[73] typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);
[74] 
[75] typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
[76]     ngx_file_t *file);
[77] 
[78] struct ngx_output_chain_ctx_s {
[79]     ngx_buf_t                   *buf;
[80]     ngx_chain_t                 *in;
[81]     ngx_chain_t                 *free;
[82]     ngx_chain_t                 *busy;
[83] 
[84]     unsigned                     sendfile:1;
[85]     unsigned                     directio:1;
[86]     unsigned                     unaligned:1;
[87]     unsigned                     need_in_memory:1;
[88]     unsigned                     need_in_temp:1;
[89]     unsigned                     aio:1;
[90] 
[91] #if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
[92]     ngx_output_chain_aio_pt      aio_handler;
[93] #endif
[94] 
[95] #if (NGX_THREADS || NGX_COMPAT)
[96]     ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
[97]                                                  ngx_file_t *file);
[98]     ngx_thread_task_t           *thread_task;
[99] #endif
[100] 
[101]     off_t                        alignment;
[102] 
[103]     ngx_pool_t                  *pool;
[104]     ngx_int_t                    allocated;
[105]     ngx_bufs_t                   bufs;
[106]     ngx_buf_tag_t                tag;
[107] 
[108]     ngx_output_chain_filter_pt   output_filter;
[109]     void                        *filter_ctx;
[110] };
[111] 
[112] 
[113] typedef struct {
[114]     ngx_chain_t                 *out;
[115]     ngx_chain_t                **last;
[116]     ngx_connection_t            *connection;
[117]     ngx_pool_t                  *pool;
[118]     off_t                        limit;
[119] } ngx_chain_writer_ctx_t;
[120] 
[121] 
[122] #define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR
[123] 
[124] 
[125] #define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
[126] #define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)
[127] 
[128] #define ngx_buf_special(b)                                                   \
[129]     (((b)->flush || (b)->last_buf || (b)->sync)                              \
[130]      && !ngx_buf_in_memory(b) && !(b)->in_file)
[131] 
[132] #define ngx_buf_sync_only(b)                                                 \
[133]     ((b)->sync && !ngx_buf_in_memory(b)                                      \
[134]      && !(b)->in_file && !(b)->flush && !(b)->last_buf)
[135] 
[136] #define ngx_buf_size(b)                                                      \
[137]     (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
[138]                             ((b)->file_last - (b)->file_pos))
[139] 
[140] ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
[141] ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);
[142] 
[143] 
[144] #define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
[145] #define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))
[146] 
[147] ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
[148] #define ngx_free_chain(pool, cl)                                             \
[149]     (cl)->next = (pool)->chain;                                              \
[150]     (pool)->chain = (cl)
[151] 
[152] 
[153] 
[154] ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
[155] ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);
[156] 
[157] ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
[158]     ngx_chain_t *in);
[159] ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
[160] void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
[161]     ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);
[162] 
[163] off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);
[164] 
[165] ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);
[166] 
[167] #endif /* _NGX_BUF_H_INCLUDED_ */
