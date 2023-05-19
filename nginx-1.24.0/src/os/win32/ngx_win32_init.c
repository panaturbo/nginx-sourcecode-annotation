[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <nginx.h>
[11] 
[12] 
[13] ngx_uint_t  ngx_win32_version;
[14] ngx_uint_t  ngx_ncpu;
[15] ngx_uint_t  ngx_max_wsabufs;
[16] ngx_int_t   ngx_max_sockets;
[17] ngx_uint_t  ngx_inherited_nonblocking = 1;
[18] ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;
[19] 
[20] char        ngx_unique[NGX_INT32_LEN + 1];
[21] 
[22] 
[23] ngx_os_io_t ngx_os_io = {
[24]     ngx_wsarecv,
[25]     ngx_wsarecv_chain,
[26]     ngx_udp_wsarecv,
[27]     ngx_wsasend,
[28]     NULL,
[29]     NULL,
[30]     ngx_wsasend_chain,
[31]     0
[32] };
[33] 
[34] 
[35] typedef struct {
[36]     WORD  wServicePackMinor;
[37]     WORD  wSuiteMask;
[38]     BYTE  wProductType;
[39] } ngx_osviex_stub_t;
[40] 
[41] 
[42] static u_int               osviex;
[43] static OSVERSIONINFOEX     osvi;
[44] 
[45] /* Should these pointers be per protocol ? */
[46] LPFN_ACCEPTEX              ngx_acceptex;
[47] LPFN_GETACCEPTEXSOCKADDRS  ngx_getacceptexsockaddrs;
[48] LPFN_TRANSMITFILE          ngx_transmitfile;
[49] LPFN_TRANSMITPACKETS       ngx_transmitpackets;
[50] LPFN_CONNECTEX             ngx_connectex;
[51] LPFN_DISCONNECTEX          ngx_disconnectex;
[52] 
[53] static GUID ax_guid = WSAID_ACCEPTEX;
[54] static GUID as_guid = WSAID_GETACCEPTEXSOCKADDRS;
[55] static GUID tf_guid = WSAID_TRANSMITFILE;
[56] static GUID tp_guid = WSAID_TRANSMITPACKETS;
[57] static GUID cx_guid = WSAID_CONNECTEX;
[58] static GUID dx_guid = WSAID_DISCONNECTEX;
[59] 
[60] 
[61] #if (NGX_LOAD_WSAPOLL)
[62] ngx_wsapoll_pt             WSAPoll;
[63] ngx_uint_t                 ngx_have_wsapoll;
[64] #endif
[65] 
[66] 
[67] ngx_int_t
[68] ngx_os_init(ngx_log_t *log)
[69] {
[70]     DWORD         bytes;
[71]     SOCKET        s;
[72]     WSADATA       wsd;
[73]     ngx_err_t     err;
[74]     ngx_time_t   *tp;
[75]     ngx_uint_t    n;
[76]     SYSTEM_INFO   si;
[77] 
[78]     /* get Windows version */
[79] 
[80]     ngx_memzero(&osvi, sizeof(OSVERSIONINFOEX));
[81]     osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
[82] 
[83] #ifdef _MSC_VER
[84] #pragma warning(disable:4996)
[85] #endif
[86] 
[87]     osviex = GetVersionEx((OSVERSIONINFO *) &osvi);
[88] 
[89]     if (osviex == 0) {
[90]         osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
[91]         if (GetVersionEx((OSVERSIONINFO *) &osvi) == 0) {
[92]             ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
[93]                           "GetVersionEx() failed");
[94]             return NGX_ERROR;
[95]         }
[96]     }
[97] 
[98] #ifdef _MSC_VER
[99] #pragma warning(default:4996)
[100] #endif
[101] 
[102]     /*
[103]      *  Windows 3.1 Win32s   0xxxxx
[104]      *
[105]      *  Windows 95           140000
[106]      *  Windows 98           141000
[107]      *  Windows ME           149000
[108]      *  Windows NT 3.51      235100
[109]      *  Windows NT 4.0       240000
[110]      *  Windows NT 4.0 SP5   240050
[111]      *  Windows 2000         250000
[112]      *  Windows XP           250100
[113]      *  Windows 2003         250200
[114]      *  Windows Vista/2008   260000
[115]      *
[116]      *  Windows CE x.x       3xxxxx
[117]      */
[118] 
[119]     ngx_win32_version = osvi.dwPlatformId * 100000
[120]                         + osvi.dwMajorVersion * 10000
[121]                         + osvi.dwMinorVersion * 100;
[122] 
[123]     if (osviex) {
[124]         ngx_win32_version += osvi.wServicePackMajor * 10
[125]                              + osvi.wServicePackMinor;
[126]     }
[127] 
[128]     GetSystemInfo(&si);
[129]     ngx_pagesize = si.dwPageSize;
[130]     ngx_allocation_granularity = si.dwAllocationGranularity;
[131]     ngx_ncpu = si.dwNumberOfProcessors;
[132]     ngx_cacheline_size = NGX_CPU_CACHE_LINE;
[133] 
[134]     for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }
[135] 
[136]     /* delete default "C" locale for _wcsicmp() */
[137]     setlocale(LC_ALL, "");
[138] 
[139] 
[140]     /* init Winsock */
[141] 
[142]     if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
[143]         ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[144]                       "WSAStartup() failed");
[145]         return NGX_ERROR;
[146]     }
[147] 
[148]     if (ngx_win32_version < NGX_WIN_NT) {
[149]         ngx_max_wsabufs = 16;
[150]         return NGX_OK;
[151]     }
[152] 
[153]     /* STUB: ngx_uint_t max */
[154]     ngx_max_wsabufs = 1024 * 1024;
[155] 
[156]     /*
[157]      * get AcceptEx(), GetAcceptExSockAddrs(), TransmitFile(),
[158]      * TransmitPackets(), ConnectEx(), and DisconnectEx() addresses
[159]      */
[160] 
[161]     s = ngx_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
[162]     if (s == (ngx_socket_t) -1) {
[163]         ngx_log_error(NGX_LOG_EMERG, log, ngx_socket_errno,
[164]                       ngx_socket_n " failed");
[165]         return NGX_ERROR;
[166]     }
[167] 
[168]     if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &ax_guid, sizeof(GUID),
[169]                  &ngx_acceptex, sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL)
[170]         == -1)
[171]     {
[172]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
[173]                       "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
[174]                                "WSAID_ACCEPTEX) failed");
[175]     }
[176] 
[177]     if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &as_guid, sizeof(GUID),
[178]                  &ngx_getacceptexsockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
[179]                  &bytes, NULL, NULL)
[180]         == -1)
[181]     {
[182]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
[183]                       "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
[184]                                "WSAID_GETACCEPTEXSOCKADDRS) failed");
[185]     }
[186] 
[187]     if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tf_guid, sizeof(GUID),
[188]                  &ngx_transmitfile, sizeof(LPFN_TRANSMITFILE), &bytes,
[189]                  NULL, NULL)
[190]         == -1)
[191]     {
[192]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
[193]                       "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
[194]                                "WSAID_TRANSMITFILE) failed");
[195]     }
[196] 
[197]     if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &tp_guid, sizeof(GUID),
[198]                  &ngx_transmitpackets, sizeof(LPFN_TRANSMITPACKETS), &bytes,
[199]                  NULL, NULL)
[200]         == -1)
[201]     {
[202]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
[203]                       "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
[204]                                "WSAID_TRANSMITPACKETS) failed");
[205]     }
[206] 
[207]     if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &cx_guid, sizeof(GUID),
[208]                  &ngx_connectex, sizeof(LPFN_CONNECTEX), &bytes,
[209]                  NULL, NULL)
[210]         == -1)
[211]     {
[212]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
[213]                       "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
[214]                                "WSAID_CONNECTEX) failed");
[215]     }
[216] 
[217]     if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &dx_guid, sizeof(GUID),
[218]                  &ngx_disconnectex, sizeof(LPFN_DISCONNECTEX), &bytes,
[219]                  NULL, NULL)
[220]         == -1)
[221]     {
[222]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_socket_errno,
[223]                       "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, "
[224]                                "WSAID_DISCONNECTEX) failed");
[225]     }
[226] 
[227]     if (ngx_close_socket(s) == -1) {
[228]         ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
[229]                       ngx_close_socket_n " failed");
[230]     }
[231] 
[232] #if (NGX_LOAD_WSAPOLL)
[233]     {
[234]     HMODULE  hmod;
[235] 
[236]     hmod = GetModuleHandle("ws2_32.dll");
[237]     if (hmod == NULL) {
[238]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_errno,
[239]                       "GetModuleHandle(\"ws2_32.dll\") failed");
[240]         goto nopoll;
[241]     }
[242] 
[243]     WSAPoll = (ngx_wsapoll_pt) (void *) GetProcAddress(hmod, "WSAPoll");
[244]     if (WSAPoll == NULL) {
[245]         ngx_log_error(NGX_LOG_NOTICE, log, ngx_errno,
[246]                       "GetProcAddress(\"WSAPoll\") failed");
[247]         goto nopoll;
[248]     }
[249] 
[250]     ngx_have_wsapoll = 1;
[251] 
[252]     }
[253] 
[254] nopoll:
[255] 
[256] #endif
[257] 
[258]     if (GetEnvironmentVariable("ngx_unique", ngx_unique, NGX_INT32_LEN + 1)
[259]         != 0)
[260]     {
[261]         ngx_process = NGX_PROCESS_WORKER;
[262] 
[263]     } else {
[264]         err = ngx_errno;
[265] 
[266]         if (err != ERROR_ENVVAR_NOT_FOUND) {
[267]             ngx_log_error(NGX_LOG_EMERG, log, err,
[268]                           "GetEnvironmentVariable(\"ngx_unique\") failed");
[269]             return NGX_ERROR;
[270]         }
[271] 
[272]         ngx_sprintf((u_char *) ngx_unique, "%P%Z", ngx_pid);
[273]     }
[274] 
[275]     tp = ngx_timeofday();
[276]     srand((ngx_pid << 16) ^ (unsigned) tp->sec ^ tp->msec);
[277] 
[278]     return NGX_OK;
[279] }
[280] 
[281] 
[282] void
[283] ngx_os_status(ngx_log_t *log)
[284] {
[285]     ngx_osviex_stub_t  *osviex_stub;
[286] 
[287]     ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER_BUILD);
[288] 
[289]     if (osviex) {
[290] 
[291]         /*
[292]          * the MSVC 6.0 SP2 defines wSuiteMask and wProductType
[293]          * as WORD wReserved[2]
[294]          */
[295]         osviex_stub = (ngx_osviex_stub_t *) &osvi.wServicePackMinor;
[296] 
[297]         ngx_log_error(NGX_LOG_INFO, log, 0,
[298]                       "OS: %ui build:%ud, \"%s\", suite:%Xd, type:%ud",
[299]                       ngx_win32_version, osvi.dwBuildNumber, osvi.szCSDVersion,
[300]                       osviex_stub->wSuiteMask, osviex_stub->wProductType);
[301] 
[302]     } else {
[303]         if (osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) {
[304] 
[305]             /* Win9x build */
[306] 
[307]             ngx_log_error(NGX_LOG_INFO, log, 0,
[308]                           "OS: %ui build:%ud.%ud.%ud, \"%s\"",
[309]                           ngx_win32_version,
[310]                           osvi.dwBuildNumber >> 24,
[311]                           (osvi.dwBuildNumber >> 16) & 0xff,
[312]                           osvi.dwBuildNumber & 0xffff,
[313]                           osvi.szCSDVersion);
[314] 
[315]         } else {
[316] 
[317]             /*
[318]              * VER_PLATFORM_WIN32_NT
[319]              *
[320]              * we do not currently support VER_PLATFORM_WIN32_CE
[321]              * and we do not support VER_PLATFORM_WIN32s at all
[322]              */
[323] 
[324]             ngx_log_error(NGX_LOG_INFO, log, 0, "OS: %ui build:%ud, \"%s\"",
[325]                           ngx_win32_version, osvi.dwBuildNumber,
[326]                           osvi.szCSDVersion);
[327]         }
[328]     }
[329] }
