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
[12] #ifndef _NGX_RESOLVER_H_INCLUDED_
[13] #define _NGX_RESOLVER_H_INCLUDED_
[14] 
[15] 
[16] #define NGX_RESOLVE_A         1
[17] #define NGX_RESOLVE_CNAME     5
[18] #define NGX_RESOLVE_PTR       12
[19] #define NGX_RESOLVE_MX        15
[20] #define NGX_RESOLVE_TXT       16
[21] #if (NGX_HAVE_INET6)
[22] #define NGX_RESOLVE_AAAA      28
[23] #endif
[24] #define NGX_RESOLVE_SRV       33
[25] #define NGX_RESOLVE_DNAME     39
[26] 
[27] #define NGX_RESOLVE_FORMERR   1
[28] #define NGX_RESOLVE_SERVFAIL  2
[29] #define NGX_RESOLVE_NXDOMAIN  3
[30] #define NGX_RESOLVE_NOTIMP    4
[31] #define NGX_RESOLVE_REFUSED   5
[32] #define NGX_RESOLVE_TIMEDOUT  NGX_ETIMEDOUT
[33] 
[34] 
[35] #define NGX_NO_RESOLVER       (void *) -1
[36] 
[37] #define NGX_RESOLVER_MAX_RECURSION    50
[38] 
[39] 
[40] typedef struct ngx_resolver_s  ngx_resolver_t;
[41] 
[42] 
[43] typedef struct {
[44]     ngx_connection_t         *udp;
[45]     ngx_connection_t         *tcp;
[46]     struct sockaddr          *sockaddr;
[47]     socklen_t                 socklen;
[48]     ngx_str_t                 server;
[49]     ngx_log_t                 log;
[50]     ngx_buf_t                *read_buf;
[51]     ngx_buf_t                *write_buf;
[52]     ngx_resolver_t           *resolver;
[53] } ngx_resolver_connection_t;
[54] 
[55] 
[56] typedef struct ngx_resolver_ctx_s  ngx_resolver_ctx_t;
[57] 
[58] typedef void (*ngx_resolver_handler_pt)(ngx_resolver_ctx_t *ctx);
[59] 
[60] 
[61] typedef struct {
[62]     struct sockaddr          *sockaddr;
[63]     socklen_t                 socklen;
[64]     ngx_str_t                 name;
[65]     u_short                   priority;
[66]     u_short                   weight;
[67] } ngx_resolver_addr_t;
[68] 
[69] 
[70] typedef struct {
[71]     ngx_str_t                 name;
[72]     u_short                   priority;
[73]     u_short                   weight;
[74]     u_short                   port;
[75] } ngx_resolver_srv_t;
[76] 
[77] 
[78] typedef struct {
[79]     ngx_str_t                 name;
[80]     u_short                   priority;
[81]     u_short                   weight;
[82]     u_short                   port;
[83] 
[84]     ngx_resolver_ctx_t       *ctx;
[85]     ngx_int_t                 state;
[86] 
[87]     ngx_uint_t                naddrs;
[88]     ngx_addr_t               *addrs;
[89] } ngx_resolver_srv_name_t;
[90] 
[91] 
[92] typedef struct {
[93]     ngx_rbtree_node_t         node;
[94]     ngx_queue_t               queue;
[95] 
[96]     /* PTR: resolved name, A: name to resolve */
[97]     u_char                   *name;
[98] 
[99] #if (NGX_HAVE_INET6)
[100]     /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
[101]     struct in6_addr           addr6;
[102] #endif
[103] 
[104]     u_short                   nlen;
[105]     u_short                   qlen;
[106] 
[107]     u_char                   *query;
[108] #if (NGX_HAVE_INET6)
[109]     u_char                   *query6;
[110] #endif
[111] 
[112]     union {
[113]         in_addr_t             addr;
[114]         in_addr_t            *addrs;
[115]         u_char               *cname;
[116]         ngx_resolver_srv_t   *srvs;
[117]     } u;
[118] 
[119]     u_char                    code;
[120]     u_short                   naddrs;
[121]     u_short                   nsrvs;
[122]     u_short                   cnlen;
[123] 
[124] #if (NGX_HAVE_INET6)
[125]     union {
[126]         struct in6_addr       addr6;
[127]         struct in6_addr      *addrs6;
[128]     } u6;
[129] 
[130]     u_short                   naddrs6;
[131] #endif
[132] 
[133]     time_t                    expire;
[134]     time_t                    valid;
[135]     uint32_t                  ttl;
[136] 
[137]     unsigned                  tcp:1;
[138] #if (NGX_HAVE_INET6)
[139]     unsigned                  tcp6:1;
[140] #endif
[141] 
[142]     ngx_uint_t                last_connection;
[143] 
[144]     ngx_resolver_ctx_t       *waiting;
[145] } ngx_resolver_node_t;
[146] 
[147] 
[148] struct ngx_resolver_s {
[149]     /* has to be pointer because of "incomplete type" */
[150]     ngx_event_t              *event;
[151]     void                     *dummy;
[152]     ngx_log_t                *log;
[153] 
[154]     /* event ident must be after 3 pointers as in ngx_connection_t */
[155]     ngx_int_t                 ident;
[156] 
[157]     /* simple round robin DNS peers balancer */
[158]     ngx_array_t               connections;
[159]     ngx_uint_t                last_connection;
[160] 
[161]     ngx_rbtree_t              name_rbtree;
[162]     ngx_rbtree_node_t         name_sentinel;
[163] 
[164]     ngx_rbtree_t              srv_rbtree;
[165]     ngx_rbtree_node_t         srv_sentinel;
[166] 
[167]     ngx_rbtree_t              addr_rbtree;
[168]     ngx_rbtree_node_t         addr_sentinel;
[169] 
[170]     ngx_queue_t               name_resend_queue;
[171]     ngx_queue_t               srv_resend_queue;
[172]     ngx_queue_t               addr_resend_queue;
[173] 
[174]     ngx_queue_t               name_expire_queue;
[175]     ngx_queue_t               srv_expire_queue;
[176]     ngx_queue_t               addr_expire_queue;
[177] 
[178]     unsigned                  ipv4:1;
[179] 
[180] #if (NGX_HAVE_INET6)
[181]     unsigned                  ipv6:1;
[182]     ngx_rbtree_t              addr6_rbtree;
[183]     ngx_rbtree_node_t         addr6_sentinel;
[184]     ngx_queue_t               addr6_resend_queue;
[185]     ngx_queue_t               addr6_expire_queue;
[186] #endif
[187] 
[188]     time_t                    resend_timeout;
[189]     time_t                    tcp_timeout;
[190]     time_t                    expire;
[191]     time_t                    valid;
[192] 
[193]     ngx_uint_t                log_level;
[194] };
[195] 
[196] 
[197] struct ngx_resolver_ctx_s {
[198]     ngx_resolver_ctx_t       *next;
[199]     ngx_resolver_t           *resolver;
[200]     ngx_resolver_node_t      *node;
[201] 
[202]     /* event ident must be after 3 pointers as in ngx_connection_t */
[203]     ngx_int_t                 ident;
[204] 
[205]     ngx_int_t                 state;
[206]     ngx_str_t                 name;
[207]     ngx_str_t                 service;
[208] 
[209]     time_t                    valid;
[210]     ngx_uint_t                naddrs;
[211]     ngx_resolver_addr_t      *addrs;
[212]     ngx_resolver_addr_t       addr;
[213]     struct sockaddr_in        sin;
[214] 
[215]     ngx_uint_t                count;
[216]     ngx_uint_t                nsrvs;
[217]     ngx_resolver_srv_name_t  *srvs;
[218] 
[219]     ngx_resolver_handler_pt   handler;
[220]     void                     *data;
[221]     ngx_msec_t                timeout;
[222] 
[223]     unsigned                  quick:1;
[224]     unsigned                  async:1;
[225]     unsigned                  cancelable:1;
[226]     ngx_uint_t                recursion;
[227]     ngx_event_t              *event;
[228] };
[229] 
[230] 
[231] ngx_resolver_t *ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names,
[232]     ngx_uint_t n);
[233] ngx_resolver_ctx_t *ngx_resolve_start(ngx_resolver_t *r,
[234]     ngx_resolver_ctx_t *temp);
[235] ngx_int_t ngx_resolve_name(ngx_resolver_ctx_t *ctx);
[236] void ngx_resolve_name_done(ngx_resolver_ctx_t *ctx);
[237] ngx_int_t ngx_resolve_addr(ngx_resolver_ctx_t *ctx);
[238] void ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx);
[239] char *ngx_resolver_strerror(ngx_int_t err);
[240] 
[241] 
[242] #endif /* _NGX_RESOLVER_H_INCLUDED_ */
