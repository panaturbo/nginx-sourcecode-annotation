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
[12] char    ngx_darwin_kern_ostype[16];
[13] char    ngx_darwin_kern_osrelease[128];
[14] int     ngx_darwin_hw_ncpu;
[15] int     ngx_darwin_kern_ipc_somaxconn;
[16] u_long  ngx_darwin_net_inet_tcp_sendspace;
[17] 
[18] ngx_uint_t  ngx_debug_malloc;
[19] 
[20] 
[21] static ngx_os_io_t ngx_darwin_io = {
[22]     ngx_unix_recv,
[23]     ngx_readv_chain,
[24]     ngx_udp_unix_recv,
[25]     ngx_unix_send,
[26]     ngx_udp_unix_send,
[27]     ngx_udp_unix_sendmsg_chain,
[28] #if (NGX_HAVE_SENDFILE)
[29]     ngx_darwin_sendfile_chain,
[30]     NGX_IO_SENDFILE
[31] #else
[32]     ngx_writev_chain,
[33]     0
[34] #endif
[35] };
[36] 
[37] 
[38] typedef struct {
[39]     char        *name;
[40]     void        *value;
[41]     size_t       size;
[42]     ngx_uint_t   exists;
[43] } sysctl_t;
[44] 
[45] 
[46] sysctl_t sysctls[] = {
[47]     { "hw.ncpu",
[48]       &ngx_darwin_hw_ncpu,
[49]       sizeof(ngx_darwin_hw_ncpu), 0 },
[50] 
[51]     { "net.inet.tcp.sendspace",
[52]       &ngx_darwin_net_inet_tcp_sendspace,
[53]       sizeof(ngx_darwin_net_inet_tcp_sendspace), 0 },
[54] 
[55]     { "kern.ipc.somaxconn",
[56]       &ngx_darwin_kern_ipc_somaxconn,
[57]       sizeof(ngx_darwin_kern_ipc_somaxconn), 0 },
[58] 
[59]     { NULL, NULL, 0, 0 }
[60] };
[61] 
[62] 
[63] void
[64] ngx_debug_init(void)
[65] {
[66] #if (NGX_DEBUG_MALLOC)
[67] 
[68]     /*
[69]      * MacOSX 10.6, 10.7:  MallocScribble fills freed memory with 0x55
[70]      *                     and fills allocated memory with 0xAA.
[71]      * MacOSX 10.4, 10.5:  MallocScribble fills freed memory with 0x55,
[72]      *                     MallocPreScribble fills allocated memory with 0xAA.
[73]      * MacOSX 10.3:        MallocScribble fills freed memory with 0x55,
[74]      *                     and no way to fill allocated memory.
[75]      */
[76] 
[77]     setenv("MallocScribble", "1", 0);
[78] 
[79]     ngx_debug_malloc = 1;
[80] 
[81] #else
[82] 
[83]     if (getenv("MallocScribble")) {
[84]         ngx_debug_malloc = 1;
[85]     }
[86] 
[87] #endif
[88] }
[89] 
[90] 
[91] ngx_int_t
[92] ngx_os_specific_init(ngx_log_t *log)
[93] {
[94]     size_t      size;
[95]     ngx_err_t   err;
[96]     ngx_uint_t  i;
[97] 
[98]     size = sizeof(ngx_darwin_kern_ostype);
[99]     if (sysctlbyname("kern.ostype", ngx_darwin_kern_ostype, &size, NULL, 0)
[100]         == -1)
[101]     {
[102]         err = ngx_errno;
[103] 
[104]         if (err != NGX_ENOENT) {
[105] 
[106]             ngx_log_error(NGX_LOG_ALERT, log, err,
[107]                           "sysctlbyname(kern.ostype) failed");
[108] 
[109]             if (err != NGX_ENOMEM) {
[110]                 return NGX_ERROR;
[111]             }
[112] 
[113]             ngx_darwin_kern_ostype[size - 1] = '\0';
[114]         }
[115]     }
[116] 
[117]     size = sizeof(ngx_darwin_kern_osrelease);
[118]     if (sysctlbyname("kern.osrelease", ngx_darwin_kern_osrelease, &size,
[119]                      NULL, 0)
[120]         == -1)
[121]     {
[122]         err = ngx_errno;
[123] 
[124]         if (err != NGX_ENOENT) {
[125] 
[126]             ngx_log_error(NGX_LOG_ALERT, log, err,
[127]                           "sysctlbyname(kern.osrelease) failed");
[128] 
[129]             if (err != NGX_ENOMEM) {
[130]                 return NGX_ERROR;
[131]             }
[132] 
[133]             ngx_darwin_kern_osrelease[size - 1] = '\0';
[134]         }
[135]     }
[136] 
[137]     for (i = 0; sysctls[i].name; i++) {
[138]         size = sysctls[i].size;
[139] 
[140]         if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
[141]             == 0)
[142]         {
[143]             sysctls[i].exists = 1;
[144]             continue;
[145]         }
[146] 
[147]         err = ngx_errno;
[148] 
[149]         if (err == NGX_ENOENT) {
[150]             continue;
[151]         }
[152] 
[153]         ngx_log_error(NGX_LOG_ALERT, log, err,
[154]                       "sysctlbyname(%s) failed", sysctls[i].name);
[155]         return NGX_ERROR;
[156]     }
[157] 
[158]     ngx_ncpu = ngx_darwin_hw_ncpu;
[159] 
[160]     if (ngx_darwin_kern_ipc_somaxconn > 32767) {
[161]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[162]                       "sysctl kern.ipc.somaxconn must be less than 32768");
[163]         return NGX_ERROR;
[164]     }
[165] 
[166]     ngx_tcp_nodelay_and_tcp_nopush = 1;
[167] 
[168]     ngx_os_io = ngx_darwin_io;
[169] 
[170]     return NGX_OK;
[171] }
[172] 
[173] 
[174] void
[175] ngx_os_specific_status(ngx_log_t *log)
[176] {
[177]     u_long      value;
[178]     ngx_uint_t  i;
[179] 
[180]     if (ngx_darwin_kern_ostype[0]) {
[181]         ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
[182]                       ngx_darwin_kern_ostype, ngx_darwin_kern_osrelease);
[183]     }
[184] 
[185]     for (i = 0; sysctls[i].name; i++) {
[186]         if (sysctls[i].exists) {
[187]             if (sysctls[i].size == sizeof(long)) {
[188]                 value = *(long *) sysctls[i].value;
[189] 
[190]             } else {
[191]                 value = *(int *) sysctls[i].value;
[192]             }
[193] 
[194]             ngx_log_error(NGX_LOG_NOTICE, log, 0, "%s: %l",
[195]                           sysctls[i].name, value);
[196]         }
[197]     }
[198] }
