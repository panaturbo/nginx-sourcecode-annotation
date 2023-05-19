[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_INET_H_INCLUDED_
[9] #define _NGX_INET_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
[17] #define NGX_INET6_ADDRSTRLEN                                                 \
[18]     (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
[19] #define NGX_UNIX_ADDRSTRLEN                                                  \
[20]     (sizeof("unix:") - 1 +                                                   \
[21]      sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))
[22] 
[23] #if (NGX_HAVE_UNIX_DOMAIN)
[24] #define NGX_SOCKADDR_STRLEN   NGX_UNIX_ADDRSTRLEN
[25] #elif (NGX_HAVE_INET6)
[26] #define NGX_SOCKADDR_STRLEN   (NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
[27] #else
[28] #define NGX_SOCKADDR_STRLEN   (NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1)
[29] #endif
[30] 
[31] /* compatibility */
[32] #define NGX_SOCKADDRLEN       sizeof(ngx_sockaddr_t)
[33] 
[34] 
[35] typedef union {
[36]     struct sockaddr           sockaddr;
[37]     struct sockaddr_in        sockaddr_in;
[38] #if (NGX_HAVE_INET6)
[39]     struct sockaddr_in6       sockaddr_in6;
[40] #endif
[41] #if (NGX_HAVE_UNIX_DOMAIN)
[42]     struct sockaddr_un        sockaddr_un;
[43] #endif
[44] } ngx_sockaddr_t;
[45] 
[46] 
[47] typedef struct {
[48]     in_addr_t                 addr;
[49]     in_addr_t                 mask;
[50] } ngx_in_cidr_t;
[51] 
[52] 
[53] #if (NGX_HAVE_INET6)
[54] 
[55] typedef struct {
[56]     struct in6_addr           addr;
[57]     struct in6_addr           mask;
[58] } ngx_in6_cidr_t;
[59] 
[60] #endif
[61] 
[62] 
[63] typedef struct {
[64]     ngx_uint_t                family;
[65]     union {
[66]         ngx_in_cidr_t         in;
[67] #if (NGX_HAVE_INET6)
[68]         ngx_in6_cidr_t        in6;
[69] #endif
[70]     } u;
[71] } ngx_cidr_t;
[72] 
[73] 
[74] typedef struct {
[75]     struct sockaddr          *sockaddr;
[76]     socklen_t                 socklen;
[77]     ngx_str_t                 name;
[78] } ngx_addr_t;
[79] 
[80] 
[81] typedef struct {
[82]     ngx_str_t                 url;
[83]     ngx_str_t                 host;
[84]     ngx_str_t                 port_text;
[85]     ngx_str_t                 uri;
[86] 
[87]     in_port_t                 port;
[88]     in_port_t                 default_port;
[89]     in_port_t                 last_port;
[90]     int                       family;
[91] 
[92]     unsigned                  listen:1;
[93]     unsigned                  uri_part:1;
[94]     unsigned                  no_resolve:1;
[95] 
[96]     unsigned                  no_port:1;
[97]     unsigned                  wildcard:1;
[98] 
[99]     socklen_t                 socklen;
[100]     ngx_sockaddr_t            sockaddr;
[101] 
[102]     ngx_addr_t               *addrs;
[103]     ngx_uint_t                naddrs;
[104] 
[105]     char                     *err;
[106] } ngx_url_t;
[107] 
[108] 
[109] in_addr_t ngx_inet_addr(u_char *text, size_t len);
[110] #if (NGX_HAVE_INET6)
[111] ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
[112] size_t ngx_inet6_ntop(u_char *p, u_char *text, size_t len);
[113] #endif
[114] size_t ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
[115]     size_t len, ngx_uint_t port);
[116] size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);
[117] ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);
[118] ngx_int_t ngx_cidr_match(struct sockaddr *sa, ngx_array_t *cidrs);
[119] ngx_int_t ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
[120]     size_t len);
[121] ngx_int_t ngx_parse_addr_port(ngx_pool_t *pool, ngx_addr_t *addr,
[122]     u_char *text, size_t len);
[123] ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);
[124] ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);
[125] ngx_int_t ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
[126]     struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port);
[127] in_port_t ngx_inet_get_port(struct sockaddr *sa);
[128] void ngx_inet_set_port(struct sockaddr *sa, in_port_t port);
[129] ngx_uint_t ngx_inet_wildcard(struct sockaddr *sa);
[130] 
[131] 
[132] #endif /* _NGX_INET_H_INCLUDED_ */
