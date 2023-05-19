[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SOCKET_H_INCLUDED_
[9] #define _NGX_SOCKET_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_WRITE_SHUTDOWN SD_SEND
[17] 
[18] 
[19] typedef SOCKET  ngx_socket_t;
[20] typedef int     socklen_t;
[21] 
[22] 
[23] #define ngx_socket(af, type, proto)                                          \
[24]     WSASocketW(af, type, proto, NULL, 0, WSA_FLAG_OVERLAPPED)
[25] 
[26] #define ngx_socket_n        "WSASocketW()"
[27] 
[28] int ngx_nonblocking(ngx_socket_t s);
[29] int ngx_blocking(ngx_socket_t s);
[30] 
[31] #define ngx_nonblocking_n   "ioctlsocket(FIONBIO)"
[32] #define ngx_blocking_n      "ioctlsocket(!FIONBIO)"
[33] 
[34] int ngx_socket_nread(ngx_socket_t s, int *n);
[35] #define ngx_socket_nread_n  "ioctlsocket(FIONREAD)"
[36] 
[37] #define ngx_shutdown_socket    shutdown
[38] #define ngx_shutdown_socket_n  "shutdown()"
[39] 
[40] #define ngx_close_socket    closesocket
[41] #define ngx_close_socket_n  "closesocket()"
[42] 
[43] 
[44] #ifndef WSAID_ACCEPTEX
[45] 
[46] typedef BOOL (PASCAL FAR * LPFN_ACCEPTEX)(
[47]     IN SOCKET sListenSocket,
[48]     IN SOCKET sAcceptSocket,
[49]     IN PVOID lpOutputBuffer,
[50]     IN DWORD dwReceiveDataLength,
[51]     IN DWORD dwLocalAddressLength,
[52]     IN DWORD dwRemoteAddressLength,
[53]     OUT LPDWORD lpdwBytesReceived,
[54]     IN LPOVERLAPPED lpOverlapped
[55]     );
[56] 
[57] #define WSAID_ACCEPTEX                                                       \
[58]     {0xb5367df1,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}
[59] 
[60] #endif
[61] 
[62] 
[63] #ifndef WSAID_GETACCEPTEXSOCKADDRS
[64] 
[65] typedef VOID (PASCAL FAR * LPFN_GETACCEPTEXSOCKADDRS)(
[66]     IN PVOID lpOutputBuffer,
[67]     IN DWORD dwReceiveDataLength,
[68]     IN DWORD dwLocalAddressLength,
[69]     IN DWORD dwRemoteAddressLength,
[70]     OUT struct sockaddr **LocalSockaddr,
[71]     OUT LPINT LocalSockaddrLength,
[72]     OUT struct sockaddr **RemoteSockaddr,
[73]     OUT LPINT RemoteSockaddrLength
[74]     );
[75] 
[76] #define WSAID_GETACCEPTEXSOCKADDRS                                           \
[77]         {0xb5367df2,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}
[78] 
[79] #endif
[80] 
[81] 
[82] #ifndef WSAID_TRANSMITFILE
[83] 
[84] #ifndef TF_DISCONNECT
[85] 
[86] #define TF_DISCONNECT           1
[87] #define TF_REUSE_SOCKET         2
[88] #define TF_WRITE_BEHIND         4
[89] #define TF_USE_DEFAULT_WORKER   0
[90] #define TF_USE_SYSTEM_THREAD    16
[91] #define TF_USE_KERNEL_APC       32
[92] 
[93] typedef struct _TRANSMIT_FILE_BUFFERS {
[94]     LPVOID Head;
[95]     DWORD HeadLength;
[96]     LPVOID Tail;
[97]     DWORD TailLength;
[98] } TRANSMIT_FILE_BUFFERS, *PTRANSMIT_FILE_BUFFERS, FAR *LPTRANSMIT_FILE_BUFFERS;
[99] 
[100] #endif
[101] 
[102] typedef BOOL (PASCAL FAR * LPFN_TRANSMITFILE)(
[103]     IN SOCKET hSocket,
[104]     IN HANDLE hFile,
[105]     IN DWORD nNumberOfBytesToWrite,
[106]     IN DWORD nNumberOfBytesPerSend,
[107]     IN LPOVERLAPPED lpOverlapped,
[108]     IN LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
[109]     IN DWORD dwReserved
[110]     );
[111] 
[112] #define WSAID_TRANSMITFILE                                                   \
[113]     {0xb5367df0,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}
[114] 
[115] #endif
[116] 
[117] 
[118] #ifndef WSAID_TRANSMITPACKETS
[119] 
[120] /* OpenWatcom has a swapped TP_ELEMENT_FILE and TP_ELEMENT_MEMORY definition */
[121] 
[122] #ifndef TP_ELEMENT_FILE
[123] 
[124] #ifdef _MSC_VER
[125] #pragma warning(disable:4201) /* Nonstandard extension, nameless struct/union */
[126] #endif
[127] 
[128] typedef struct _TRANSMIT_PACKETS_ELEMENT {
[129]     ULONG dwElFlags;
[130] #define TP_ELEMENT_MEMORY   1
[131] #define TP_ELEMENT_FILE     2
[132] #define TP_ELEMENT_EOP      4
[133]     ULONG cLength;
[134]     union {
[135]         struct {
[136]             LARGE_INTEGER nFileOffset;
[137]             HANDLE        hFile;
[138]         };
[139]         PVOID             pBuffer;
[140]     };
[141] } TRANSMIT_PACKETS_ELEMENT, *PTRANSMIT_PACKETS_ELEMENT,
[142]     FAR *LPTRANSMIT_PACKETS_ELEMENT;
[143] 
[144] #ifdef _MSC_VER
[145] #pragma warning(default:4201)
[146] #endif
[147] 
[148] #endif
[149] 
[150] typedef BOOL (PASCAL FAR * LPFN_TRANSMITPACKETS) (
[151]     SOCKET hSocket,
[152]     TRANSMIT_PACKETS_ELEMENT *lpPacketArray,
[153]     DWORD nElementCount,
[154]     DWORD nSendSize,
[155]     LPOVERLAPPED lpOverlapped,
[156]     DWORD dwFlags
[157]     );
[158] 
[159] #define WSAID_TRANSMITPACKETS                                                \
[160]     {0xd9689da0,0x1f90,0x11d3,{0x99,0x71,0x00,0xc0,0x4f,0x68,0xc8,0x76}}
[161] 
[162] #endif
[163] 
[164] 
[165] #ifndef WSAID_CONNECTEX
[166] 
[167] typedef BOOL (PASCAL FAR * LPFN_CONNECTEX) (
[168]     IN SOCKET s,
[169]     IN const struct sockaddr FAR *name,
[170]     IN int namelen,
[171]     IN PVOID lpSendBuffer OPTIONAL,
[172]     IN DWORD dwSendDataLength,
[173]     OUT LPDWORD lpdwBytesSent,
[174]     IN LPOVERLAPPED lpOverlapped
[175]     );
[176] 
[177] #define WSAID_CONNECTEX \
[178]     {0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}
[179] 
[180] #endif
[181] 
[182] 
[183] #ifndef WSAID_DISCONNECTEX
[184] 
[185] typedef BOOL (PASCAL FAR * LPFN_DISCONNECTEX) (
[186]     IN SOCKET s,
[187]     IN LPOVERLAPPED lpOverlapped,
[188]     IN DWORD  dwFlags,
[189]     IN DWORD  dwReserved
[190]     );
[191] 
[192] #define WSAID_DISCONNECTEX                                                   \
[193]     {0x7fda2e11,0x8630,0x436f,{0xa0,0x31,0xf5,0x36,0xa6,0xee,0xc1,0x57}}
[194] 
[195] #endif
[196] 
[197] 
[198] extern LPFN_ACCEPTEX              ngx_acceptex;
[199] extern LPFN_GETACCEPTEXSOCKADDRS  ngx_getacceptexsockaddrs;
[200] extern LPFN_TRANSMITFILE          ngx_transmitfile;
[201] extern LPFN_TRANSMITPACKETS       ngx_transmitpackets;
[202] extern LPFN_CONNECTEX             ngx_connectex;
[203] extern LPFN_DISCONNECTEX          ngx_disconnectex;
[204] 
[205] 
[206] #if (NGX_HAVE_POLL && !defined POLLIN)
[207] 
[208] /*
[209]  * WSAPoll() is only available if _WIN32_WINNT >= 0x0600.
[210]  * If it is not available during compilation, we try to
[211]  * load it dynamically at runtime.
[212]  */
[213] 
[214] #define NGX_LOAD_WSAPOLL 1
[215] 
[216] #define POLLRDNORM  0x0100
[217] #define POLLRDBAND  0x0200
[218] #define POLLIN      (POLLRDNORM | POLLRDBAND)
[219] #define POLLPRI     0x0400
[220] 
[221] #define POLLWRNORM  0x0010
[222] #define POLLOUT     (POLLWRNORM)
[223] #define POLLWRBAND  0x0020
[224] 
[225] #define POLLERR     0x0001
[226] #define POLLHUP     0x0002
[227] #define POLLNVAL    0x0004
[228] 
[229] typedef struct pollfd {
[230] 
[231]     SOCKET  fd;
[232]     SHORT   events;
[233]     SHORT   revents;
[234] 
[235] } WSAPOLLFD, *PWSAPOLLFD, FAR *LPWSAPOLLFD;
[236] 
[237] typedef int (WSAAPI *ngx_wsapoll_pt)(
[238]     LPWSAPOLLFD fdArray,
[239]     ULONG fds,
[240]     INT timeout
[241]     );
[242] 
[243] extern ngx_wsapoll_pt             WSAPoll;
[244] extern ngx_uint_t                 ngx_have_wsapoll;
[245] 
[246] #endif
[247] 
[248] 
[249] int ngx_tcp_push(ngx_socket_t s);
[250] #define ngx_tcp_push_n            "tcp_push()"
[251] 
[252] 
[253] #endif /* _NGX_SOCKET_H_INCLUDED_ */
