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
[12] /* FreeBSD 3.0 at least */
[13] char    ngx_freebsd_kern_ostype[16];
[14] char    ngx_freebsd_kern_osrelease[128];
[15] int     ngx_freebsd_kern_osreldate;
[16] int     ngx_freebsd_hw_ncpu;
[17] int     ngx_freebsd_kern_ipc_somaxconn;
[18] u_long  ngx_freebsd_net_inet_tcp_sendspace;
[19] 
[20] /* FreeBSD 4.9 */
[21] int     ngx_freebsd_machdep_hlt_logical_cpus;
[22] 
[23] 
[24] ngx_uint_t  ngx_freebsd_sendfile_nbytes_bug;
[25] ngx_uint_t  ngx_freebsd_use_tcp_nopush;
[26] 
[27] ngx_uint_t  ngx_debug_malloc;
[28] 
[29] 
[30] static ngx_os_io_t ngx_freebsd_io = {
[31]     ngx_unix_recv,
[32]     ngx_readv_chain,
[33]     ngx_udp_unix_recv,
[34]     ngx_unix_send,
[35]     ngx_udp_unix_send,
[36]     ngx_udp_unix_sendmsg_chain,
[37] #if (NGX_HAVE_SENDFILE)
[38]     ngx_freebsd_sendfile_chain,
[39]     NGX_IO_SENDFILE
[40] #else
[41]     ngx_writev_chain,
[42]     0
[43] #endif
[44] };
[45] 
[46] 
[47] typedef struct {
[48]     char        *name;
[49]     void        *value;
[50]     size_t       size;
[51]     ngx_uint_t   exists;
[52] } sysctl_t;
[53] 
[54] 
[55] sysctl_t sysctls[] = {
[56]     { "hw.ncpu",
[57]       &ngx_freebsd_hw_ncpu,
[58]       sizeof(ngx_freebsd_hw_ncpu), 0 },
[59] 
[60]     { "machdep.hlt_logical_cpus",
[61]       &ngx_freebsd_machdep_hlt_logical_cpus,
[62]       sizeof(ngx_freebsd_machdep_hlt_logical_cpus), 0 },
[63] 
[64]     { "net.inet.tcp.sendspace",
[65]       &ngx_freebsd_net_inet_tcp_sendspace,
[66]       sizeof(ngx_freebsd_net_inet_tcp_sendspace), 0 },
[67] 
[68]     { "kern.ipc.somaxconn",
[69]       &ngx_freebsd_kern_ipc_somaxconn,
[70]       sizeof(ngx_freebsd_kern_ipc_somaxconn), 0 },
[71] 
[72]     { NULL, NULL, 0, 0 }
[73] };
[74] 
[75] 
[76] void
[77] ngx_debug_init(void)
[78] {
[79] #if (NGX_DEBUG_MALLOC)
[80] 
[81] #if __FreeBSD_version >= 500014 && __FreeBSD_version < 1000011
[82]     _malloc_options = "J";
[83] #elif __FreeBSD_version < 500014
[84]     malloc_options = "J";
[85] #endif
[86] 
[87]     ngx_debug_malloc = 1;
[88] 
[89] #else
[90]     char  *mo;
[91] 
[92]     mo = getenv("MALLOC_OPTIONS");
[93] 
[94]     if (mo && ngx_strchr(mo, 'J')) {
[95]         ngx_debug_malloc = 1;
[96]     }
[97] #endif
[98] }
[99] 
[100] 
[101] ngx_int_t
[102] ngx_os_specific_init(ngx_log_t *log)
[103] {
[104]     int         version;
[105]     size_t      size;
[106]     ngx_err_t   err;
[107]     ngx_uint_t  i;
[108] 
[109]     size = sizeof(ngx_freebsd_kern_ostype);
[110]     if (sysctlbyname("kern.ostype",
[111]                      ngx_freebsd_kern_ostype, &size, NULL, 0) == -1) {
[112]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[113]                       "sysctlbyname(kern.ostype) failed");
[114] 
[115]         if (ngx_errno != NGX_ENOMEM) {
[116]             return NGX_ERROR;
[117]         }
[118] 
[119]         ngx_freebsd_kern_ostype[size - 1] = '\0';
[120]     }
[121] 
[122]     size = sizeof(ngx_freebsd_kern_osrelease);
[123]     if (sysctlbyname("kern.osrelease",
[124]                      ngx_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
[125]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[126]                       "sysctlbyname(kern.osrelease) failed");
[127] 
[128]         if (ngx_errno != NGX_ENOMEM) {
[129]             return NGX_ERROR;
[130]         }
[131] 
[132]         ngx_freebsd_kern_osrelease[size - 1] = '\0';
[133]     }
[134] 
[135] 
[136]     size = sizeof(int);
[137]     if (sysctlbyname("kern.osreldate",
[138]                      &ngx_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
[139]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[140]                       "sysctlbyname(kern.osreldate) failed");
[141]         return NGX_ERROR;
[142]     }
[143] 
[144]     version = ngx_freebsd_kern_osreldate;
[145] 
[146] 
[147] #if (NGX_HAVE_SENDFILE)
[148] 
[149]     /*
[150]      * The determination of the sendfile() "nbytes bug" is complex enough.
[151]      * There are two sendfile() syscalls: a new #393 has no bug while
[152]      * an old #336 has the bug in some versions and has not in others.
[153]      * Besides libc_r wrapper also emulates the bug in some versions.
[154]      * There is no way to say exactly if syscall #336 in FreeBSD circa 4.6
[155]      * has the bug.  We use the algorithm that is correct at least for
[156]      * RELEASEs and for syscalls only (not libc_r wrapper).
[157]      *
[158]      * 4.6.1-RELEASE and below have the bug
[159]      * 4.6.2-RELEASE and above have the new syscall
[160]      *
[161]      * We detect the new sendfile() syscall available at the compile time
[162]      * to allow an old binary to run correctly on an updated FreeBSD system.
[163]      */
[164] 
[165] #if (__FreeBSD__ == 4 && __FreeBSD_version >= 460102) \
[166]     || __FreeBSD_version == 460002 || __FreeBSD_version >= 500039
[167] 
[168]     /* a new syscall without the bug */
[169] 
[170]     ngx_freebsd_sendfile_nbytes_bug = 0;
[171] 
[172] #else
[173] 
[174]     /* an old syscall that may have the bug */
[175] 
[176]     ngx_freebsd_sendfile_nbytes_bug = 1;
[177] 
[178] #endif
[179] 
[180] #endif /* NGX_HAVE_SENDFILE */
[181] 
[182] 
[183]     if ((version < 500000 && version >= 440003) || version >= 500017) {
[184]         ngx_freebsd_use_tcp_nopush = 1;
[185]     }
[186] 
[187] 
[188]     for (i = 0; sysctls[i].name; i++) {
[189]         size = sysctls[i].size;
[190] 
[191]         if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
[192]             == 0)
[193]         {
[194]             sysctls[i].exists = 1;
[195]             continue;
[196]         }
[197] 
[198]         err = ngx_errno;
[199] 
[200]         if (err == NGX_ENOENT) {
[201]             continue;
[202]         }
[203] 
[204]         ngx_log_error(NGX_LOG_ALERT, log, err,
[205]                       "sysctlbyname(%s) failed", sysctls[i].name);
[206]         return NGX_ERROR;
[207]     }
[208] 
[209]     if (ngx_freebsd_machdep_hlt_logical_cpus) {
[210]         ngx_ncpu = ngx_freebsd_hw_ncpu / 2;
[211] 
[212]     } else {
[213]         ngx_ncpu = ngx_freebsd_hw_ncpu;
[214]     }
[215] 
[216]     if (version < 600008 && ngx_freebsd_kern_ipc_somaxconn > 32767) {
[217]         ngx_log_error(NGX_LOG_ALERT, log, 0,
[218]                       "sysctl kern.ipc.somaxconn must be less than 32768");
[219]         return NGX_ERROR;
[220]     }
[221] 
[222]     ngx_tcp_nodelay_and_tcp_nopush = 1;
[223] 
[224]     ngx_os_io = ngx_freebsd_io;
[225] 
[226]     return NGX_OK;
[227] }
[228] 
[229] 
[230] void
[231] ngx_os_specific_status(ngx_log_t *log)
[232] {
[233]     u_long      value;
[234]     ngx_uint_t  i;
[235] 
[236]     ngx_log_error(NGX_LOG_NOTICE, log, 0, "OS: %s %s",
[237]                   ngx_freebsd_kern_ostype, ngx_freebsd_kern_osrelease);
[238] 
[239] #ifdef __DragonFly_version
[240]     ngx_log_error(NGX_LOG_NOTICE, log, 0,
[241]                   "kern.osreldate: %d, built on %d",
[242]                   ngx_freebsd_kern_osreldate, __DragonFly_version);
[243] #else
[244]     ngx_log_error(NGX_LOG_NOTICE, log, 0,
[245]                   "kern.osreldate: %d, built on %d",
[246]                   ngx_freebsd_kern_osreldate, __FreeBSD_version);
[247] #endif
[248] 
[249]     for (i = 0; sysctls[i].name; i++) {
[250]         if (sysctls[i].exists) {
[251]             if (sysctls[i].size == sizeof(long)) {
[252]                 value = *(long *) sysctls[i].value;
[253] 
[254]             } else {
[255]                 value = *(int *) sysctls[i].value;
[256]             }
[257] 
[258]             ngx_log_error(NGX_LOG_NOTICE, log, 0, "%s: %l",
[259]                           sysctls[i].name, value);
[260]         }
[261]     }
[262] }
