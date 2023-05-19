[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_EVENT_PIPE_H_INCLUDED_
[9] #define _NGX_EVENT_PIPE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_event.h>
[15] 
[16] 
[17] typedef struct ngx_event_pipe_s  ngx_event_pipe_t;
[18] 
[19] typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
[20]                                                     ngx_buf_t *buf);
[21] typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
[22]                                                      ngx_chain_t *chain);
[23] 
[24] 
[25] struct ngx_event_pipe_s {
[26]     ngx_connection_t  *upstream;
[27]     ngx_connection_t  *downstream;
[28] 
[29]     ngx_chain_t       *free_raw_bufs;
[30]     ngx_chain_t       *in;
[31]     ngx_chain_t      **last_in;
[32] 
[33]     ngx_chain_t       *writing;
[34] 
[35]     ngx_chain_t       *out;
[36]     ngx_chain_t       *free;
[37]     ngx_chain_t       *busy;
[38] 
[39]     /*
[40]      * the input filter i.e. that moves HTTP/1.1 chunks
[41]      * from the raw bufs to an incoming chain
[42]      */
[43] 
[44]     ngx_event_pipe_input_filter_pt    input_filter;
[45]     void                             *input_ctx;
[46] 
[47]     ngx_event_pipe_output_filter_pt   output_filter;
[48]     void                             *output_ctx;
[49] 
[50] #if (NGX_THREADS || NGX_COMPAT)
[51]     ngx_int_t                       (*thread_handler)(ngx_thread_task_t *task,
[52]                                                       ngx_file_t *file);
[53]     void                             *thread_ctx;
[54]     ngx_thread_task_t                *thread_task;
[55] #endif
[56] 
[57]     unsigned           read:1;
[58]     unsigned           cacheable:1;
[59]     unsigned           single_buf:1;
[60]     unsigned           free_bufs:1;
[61]     unsigned           upstream_done:1;
[62]     unsigned           upstream_error:1;
[63]     unsigned           upstream_eof:1;
[64]     unsigned           upstream_blocked:1;
[65]     unsigned           downstream_done:1;
[66]     unsigned           downstream_error:1;
[67]     unsigned           cyclic_temp_file:1;
[68]     unsigned           aio:1;
[69] 
[70]     ngx_int_t          allocated;
[71]     ngx_bufs_t         bufs;
[72]     ngx_buf_tag_t      tag;
[73] 
[74]     ssize_t            busy_size;
[75] 
[76]     off_t              read_length;
[77]     off_t              length;
[78] 
[79]     off_t              max_temp_file_size;
[80]     ssize_t            temp_file_write_size;
[81] 
[82]     ngx_msec_t         read_timeout;
[83]     ngx_msec_t         send_timeout;
[84]     ssize_t            send_lowat;
[85] 
[86]     ngx_pool_t        *pool;
[87]     ngx_log_t         *log;
[88] 
[89]     ngx_chain_t       *preread_bufs;
[90]     size_t             preread_size;
[91]     ngx_buf_t         *buf_to_file;
[92] 
[93]     size_t             limit_rate;
[94]     time_t             start_sec;
[95] 
[96]     ngx_temp_file_t   *temp_file;
[97] 
[98]     /* STUB */ int     num;
[99] };
[100] 
[101] 
[102] ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
[103] ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
[104] ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);
[105] 
[106] 
[107] #endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
