[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
[9] #define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] 
[16] 
[17] typedef struct ngx_http_upstream_rr_peer_s   ngx_http_upstream_rr_peer_t;
[18] 
[19] struct ngx_http_upstream_rr_peer_s {
[20]     struct sockaddr                *sockaddr;
[21]     socklen_t                       socklen;
[22]     ngx_str_t                       name;
[23]     ngx_str_t                       server;
[24] 
[25]     ngx_int_t                       current_weight;
[26]     ngx_int_t                       effective_weight;
[27]     ngx_int_t                       weight;
[28] 
[29]     ngx_uint_t                      conns;
[30]     ngx_uint_t                      max_conns;
[31] 
[32]     ngx_uint_t                      fails;
[33]     time_t                          accessed;
[34]     time_t                          checked;
[35] 
[36]     ngx_uint_t                      max_fails;
[37]     time_t                          fail_timeout;
[38]     ngx_msec_t                      slow_start;
[39]     ngx_msec_t                      start_time;
[40] 
[41]     ngx_uint_t                      down;
[42] 
[43] #if (NGX_HTTP_SSL || NGX_COMPAT)
[44]     void                           *ssl_session;
[45]     int                             ssl_session_len;
[46] #endif
[47] 
[48] #if (NGX_HTTP_UPSTREAM_ZONE)
[49]     ngx_atomic_t                    lock;
[50] #endif
[51] 
[52]     ngx_http_upstream_rr_peer_t    *next;
[53] 
[54]     NGX_COMPAT_BEGIN(32)
[55]     NGX_COMPAT_END
[56] };
[57] 
[58] 
[59] typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;
[60] 
[61] struct ngx_http_upstream_rr_peers_s {
[62]     ngx_uint_t                      number;
[63] 
[64] #if (NGX_HTTP_UPSTREAM_ZONE)
[65]     ngx_slab_pool_t                *shpool;
[66]     ngx_atomic_t                    rwlock;
[67]     ngx_http_upstream_rr_peers_t   *zone_next;
[68] #endif
[69] 
[70]     ngx_uint_t                      total_weight;
[71]     ngx_uint_t                      tries;
[72] 
[73]     unsigned                        single:1;
[74]     unsigned                        weighted:1;
[75] 
[76]     ngx_str_t                      *name;
[77] 
[78]     ngx_http_upstream_rr_peers_t   *next;
[79] 
[80]     ngx_http_upstream_rr_peer_t    *peer;
[81] };
[82] 
[83] 
[84] #if (NGX_HTTP_UPSTREAM_ZONE)
[85] 
[86] #define ngx_http_upstream_rr_peers_rlock(peers)                               \
[87]                                                                               \
[88]     if (peers->shpool) {                                                      \
[89]         ngx_rwlock_rlock(&peers->rwlock);                                     \
[90]     }
[91] 
[92] #define ngx_http_upstream_rr_peers_wlock(peers)                               \
[93]                                                                               \
[94]     if (peers->shpool) {                                                      \
[95]         ngx_rwlock_wlock(&peers->rwlock);                                     \
[96]     }
[97] 
[98] #define ngx_http_upstream_rr_peers_unlock(peers)                              \
[99]                                                                               \
[100]     if (peers->shpool) {                                                      \
[101]         ngx_rwlock_unlock(&peers->rwlock);                                    \
[102]     }
[103] 
[104] 
[105] #define ngx_http_upstream_rr_peer_lock(peers, peer)                           \
[106]                                                                               \
[107]     if (peers->shpool) {                                                      \
[108]         ngx_rwlock_wlock(&peer->lock);                                        \
[109]     }
[110] 
[111] #define ngx_http_upstream_rr_peer_unlock(peers, peer)                         \
[112]                                                                               \
[113]     if (peers->shpool) {                                                      \
[114]         ngx_rwlock_unlock(&peer->lock);                                       \
[115]     }
[116] 
[117] #else
[118] 
[119] #define ngx_http_upstream_rr_peers_rlock(peers)
[120] #define ngx_http_upstream_rr_peers_wlock(peers)
[121] #define ngx_http_upstream_rr_peers_unlock(peers)
[122] #define ngx_http_upstream_rr_peer_lock(peers, peer)
[123] #define ngx_http_upstream_rr_peer_unlock(peers, peer)
[124] 
[125] #endif
[126] 
[127] 
[128] typedef struct {
[129]     ngx_uint_t                      config;
[130]     ngx_http_upstream_rr_peers_t   *peers;
[131]     ngx_http_upstream_rr_peer_t    *current;
[132]     uintptr_t                      *tried;
[133]     uintptr_t                       data;
[134] } ngx_http_upstream_rr_peer_data_t;
[135] 
[136] 
[137] ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
[138]     ngx_http_upstream_srv_conf_t *us);
[139] ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
[140]     ngx_http_upstream_srv_conf_t *us);
[141] ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
[142]     ngx_http_upstream_resolved_t *ur);
[143] ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
[144]     void *data);
[145] void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
[146]     void *data, ngx_uint_t state);
[147] 
[148] #if (NGX_HTTP_SSL)
[149] ngx_int_t
[150]     ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
[151]     void *data);
[152] void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
[153]     void *data);
[154] #endif
[155] 
[156] 
[157] #endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
