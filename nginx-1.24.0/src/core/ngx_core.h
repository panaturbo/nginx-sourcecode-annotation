[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_CORE_H_INCLUDED_
[9] #define _NGX_CORE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] 
[14] 
[15] typedef struct ngx_module_s          ngx_module_t;
[16] typedef struct ngx_conf_s            ngx_conf_t;
[17] typedef struct ngx_cycle_s           ngx_cycle_t;
[18] typedef struct ngx_pool_s            ngx_pool_t;
[19] typedef struct ngx_chain_s           ngx_chain_t;
[20] typedef struct ngx_log_s             ngx_log_t;
[21] typedef struct ngx_open_file_s       ngx_open_file_t;
[22] typedef struct ngx_command_s         ngx_command_t;
[23] typedef struct ngx_file_s            ngx_file_t;
[24] typedef struct ngx_event_s           ngx_event_t;
[25] typedef struct ngx_event_aio_s       ngx_event_aio_t;
[26] typedef struct ngx_connection_s      ngx_connection_t;
[27] typedef struct ngx_thread_task_s     ngx_thread_task_t;
[28] typedef struct ngx_ssl_s             ngx_ssl_t;
[29] typedef struct ngx_proxy_protocol_s  ngx_proxy_protocol_t;
[30] typedef struct ngx_ssl_connection_s  ngx_ssl_connection_t;
[31] typedef struct ngx_udp_connection_s  ngx_udp_connection_t;
[32] 
[33] typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
[34] typedef void (*ngx_connection_handler_pt)(ngx_connection_t *c);
[35] 
[36] 
[37] #define  NGX_OK          0
[38] #define  NGX_ERROR      -1
[39] #define  NGX_AGAIN      -2
[40] #define  NGX_BUSY       -3
[41] #define  NGX_DONE       -4
[42] #define  NGX_DECLINED   -5
[43] #define  NGX_ABORT      -6
[44] 
[45] 
[46] #include <ngx_errno.h>
[47] #include <ngx_atomic.h>
[48] #include <ngx_thread.h>
[49] #include <ngx_rbtree.h>
[50] #include <ngx_time.h>
[51] #include <ngx_socket.h>
[52] #include <ngx_string.h>
[53] #include <ngx_files.h>
[54] #include <ngx_shmem.h>
[55] #include <ngx_process.h>
[56] #include <ngx_user.h>
[57] #include <ngx_dlopen.h>
[58] #include <ngx_parse.h>
[59] #include <ngx_parse_time.h>
[60] #include <ngx_log.h>
[61] #include <ngx_alloc.h>
[62] #include <ngx_palloc.h>
[63] #include <ngx_buf.h>
[64] #include <ngx_queue.h>
[65] #include <ngx_array.h>
[66] #include <ngx_list.h>
[67] #include <ngx_hash.h>
[68] #include <ngx_file.h>
[69] #include <ngx_crc.h>
[70] #include <ngx_crc32.h>
[71] #include <ngx_murmurhash.h>
[72] #if (NGX_PCRE)
[73] #include <ngx_regex.h>
[74] #endif
[75] #include <ngx_radix_tree.h>
[76] #include <ngx_times.h>
[77] #include <ngx_rwlock.h>
[78] #include <ngx_shmtx.h>
[79] #include <ngx_slab.h>
[80] #include <ngx_inet.h>
[81] #include <ngx_cycle.h>
[82] #include <ngx_resolver.h>
[83] #if (NGX_OPENSSL)
[84] #include <ngx_event_openssl.h>
[85] #endif
[86] #include <ngx_process_cycle.h>
[87] #include <ngx_conf_file.h>
[88] #include <ngx_module.h>
[89] #include <ngx_open_file_cache.h>
[90] #include <ngx_os.h>
[91] #include <ngx_connection.h>
[92] #include <ngx_syslog.h>
[93] #include <ngx_proxy_protocol.h>
[94] 
[95] 
[96] #define LF     (u_char) '\n'
[97] #define CR     (u_char) '\r'
[98] #define CRLF   "\r\n"
[99] 
[100] 
[101] #define ngx_abs(value)       (((value) >= 0) ? (value) : - (value))
[102] #define ngx_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
[103] #define ngx_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))
[104] 
[105] void ngx_cpuinfo(void);
[106] 
[107] #if (NGX_HAVE_OPENAT)
[108] #define NGX_DISABLE_SYMLINKS_OFF        0
[109] #define NGX_DISABLE_SYMLINKS_ON         1
[110] #define NGX_DISABLE_SYMLINKS_NOTOWNER   2
[111] #endif
[112] 
[113] #endif /* _NGX_CORE_H_INCLUDED_ */
