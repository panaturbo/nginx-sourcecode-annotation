[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #ifndef _NGX_EVENT_UDP_H_INCLUDED_
[8] #define _NGX_EVENT_UDP_H_INCLUDED_
[9] 
[10] 
[11] #include <ngx_config.h>
[12] #include <ngx_core.h>
[13] 
[14] 
[15] #if !(NGX_WIN32)
[16] 
[17] #if ((NGX_HAVE_MSGHDR_MSG_CONTROL)                                            \
[18]      && (NGX_HAVE_IP_SENDSRCADDR || NGX_HAVE_IP_RECVDSTADDR                   \
[19]          || NGX_HAVE_IP_PKTINFO                                               \
[20]          || (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)))
[21] #define NGX_HAVE_ADDRINFO_CMSG  1
[22] 
[23] #endif
[24] 
[25] 
[26] #if (NGX_HAVE_ADDRINFO_CMSG)
[27] 
[28] typedef union {
[29] #if (NGX_HAVE_IP_SENDSRCADDR || NGX_HAVE_IP_RECVDSTADDR)
[30]     struct in_addr        addr;
[31] #endif
[32] 
[33] #if (NGX_HAVE_IP_PKTINFO)
[34]     struct in_pktinfo     pkt;
[35] #endif
[36] 
[37] #if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
[38]     struct in6_pktinfo    pkt6;
[39] #endif
[40] } ngx_addrinfo_t;
[41] 
[42] size_t ngx_set_srcaddr_cmsg(struct cmsghdr *cmsg,
[43]     struct sockaddr *local_sockaddr);
[44] ngx_int_t ngx_get_srcaddr_cmsg(struct cmsghdr *cmsg,
[45]     struct sockaddr *local_sockaddr);
[46] 
[47] #endif
[48] 
[49] void ngx_event_recvmsg(ngx_event_t *ev);
[50] ssize_t ngx_sendmsg(ngx_connection_t *c, struct msghdr *msg, int flags);
[51] void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
[52]     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
[53] #endif
[54] 
[55] void ngx_delete_udp_connection(void *data);
[56] 
[57] 
[58] #endif /* _NGX_EVENT_UDP_H_INCLUDED_ */
