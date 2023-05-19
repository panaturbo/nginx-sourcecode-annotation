[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
[9] #define _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_stream.h>
[15] 
[16] 
[17] typedef struct ngx_stream_upstream_rr_peer_s   ngx_stream_upstream_rr_peer_t;
[18] 
[19] struct ngx_stream_upstream_rr_peer_s {
[20]     struct sockaddr                 *sockaddr;
[21]     socklen_t                        socklen;
[22]     ngx_str_t                        name;
[23]     ngx_str_t                        server;
[24] 
[25]     ngx_int_t                        current_weight;
[26]     ngx_int_t                        effective_weight;
[27]     ngx_int_t                        weight;
[28] 
[29]     ngx_uint_t                       conns;
[30]     ngx_uint_t                       max_conns;
[31] 
[32]     ngx_uint_t                       fails;
[33]     time_t                           accessed;
[34]     time_t                           checked;
[35] 
[36]     ngx_uint_t                       max_fails;
[37]     time_t                           fail_timeout;
[38]     ngx_msec_t                       slow_start;
[39]     ngx_msec_t                       start_time;
[40] 
[41]     ngx_uint_t                       down;
[42] 
[43]     void                            *ssl_session;
[44]     int                              ssl_session_len;
[45] 
[46] #if (NGX_STREAM_UPSTREAM_ZONE)
[47]     ngx_atomic_t                     lock;
[48] #endif
[49] 
[50]     ngx_stream_upstream_rr_peer_t   *next;
[51] 
[52]     NGX_COMPAT_BEGIN(25)
[53]     NGX_COMPAT_END
[54] };
[55] 
[56] 
[57] typedef struct ngx_stream_upstream_rr_peers_s  ngx_stream_upstream_rr_peers_t;
[58] 
[59] struct ngx_stream_upstream_rr_peers_s {
[60]     ngx_uint_t                       number;
[61] 
[62] #if (NGX_STREAM_UPSTREAM_ZONE)
[63]     ngx_slab_pool_t                 *shpool;
[64]     ngx_atomic_t                     rwlock;
[65]     ngx_stream_upstream_rr_peers_t  *zone_next;
[66] #endif
[67] 
[68]     ngx_uint_t                       total_weight;
[69]     ngx_uint_t                       tries;
[70] 
[71]     unsigned                         single:1;
[72]     unsigned                         weighted:1;
[73] 
[74]     ngx_str_t                       *name;
[75] 
[76]     ngx_stream_upstream_rr_peers_t  *next;
[77] 
[78]     ngx_stream_upstream_rr_peer_t   *peer;
[79] };
[80] 
[81] 
[82] #if (NGX_STREAM_UPSTREAM_ZONE)
[83] 
[84] #define ngx_stream_upstream_rr_peers_rlock(peers)                             \
[85]                                                                               \
[86]     if (peers->shpool) {                                                      \
[87]         ngx_rwlock_rlock(&peers->rwlock);                                     \
[88]     }
[89] 
[90] #define ngx_stream_upstream_rr_peers_wlock(peers)                             \
[91]                                                                               \
[92]     if (peers->shpool) {                                                      \
[93]         ngx_rwlock_wlock(&peers->rwlock);                                     \
[94]     }
[95] 
[96] #define ngx_stream_upstream_rr_peers_unlock(peers)                            \
[97]                                                                               \
[98]     if (peers->shpool) {                                                      \
[99]         ngx_rwlock_unlock(&peers->rwlock);                                    \
[100]     }
[101] 
[102] 
[103] #define ngx_stream_upstream_rr_peer_lock(peers, peer)                         \
[104]                                                                               \
[105]     if (peers->shpool) {                                                      \
[106]         ngx_rwlock_wlock(&peer->lock);                                        \
[107]     }
[108] 
[109] #define ngx_stream_upstream_rr_peer_unlock(peers, peer)                       \
[110]                                                                               \
[111]     if (peers->shpool) {                                                      \
[112]         ngx_rwlock_unlock(&peer->lock);                                       \
[113]     }
[114] 
[115] #else
[116] 
[117] #define ngx_stream_upstream_rr_peers_rlock(peers)
[118] #define ngx_stream_upstream_rr_peers_wlock(peers)
[119] #define ngx_stream_upstream_rr_peers_unlock(peers)
[120] #define ngx_stream_upstream_rr_peer_lock(peers, peer)
[121] #define ngx_stream_upstream_rr_peer_unlock(peers, peer)
[122] 
[123] #endif
[124] 
[125] 
[126] typedef struct {
[127]     ngx_uint_t                       config;
[128]     ngx_stream_upstream_rr_peers_t  *peers;
[129]     ngx_stream_upstream_rr_peer_t   *current;
[130]     uintptr_t                       *tried;
[131]     uintptr_t                        data;
[132] } ngx_stream_upstream_rr_peer_data_t;
[133] 
[134] 
[135] ngx_int_t ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
[136]     ngx_stream_upstream_srv_conf_t *us);
[137] ngx_int_t ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
[138]     ngx_stream_upstream_srv_conf_t *us);
[139] ngx_int_t ngx_stream_upstream_create_round_robin_peer(ngx_stream_session_t *s,
[140]     ngx_stream_upstream_resolved_t *ur);
[141] ngx_int_t ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
[142]     void *data);
[143] void ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
[144]     void *data, ngx_uint_t state);
[145] 
[146] 
[147] #endif /* _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
