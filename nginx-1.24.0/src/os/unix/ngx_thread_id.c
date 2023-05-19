[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_thread_pool.h>
[11] 
[12] 
[13] #if (NGX_LINUX)
[14] 
[15] /*
[16]  * Linux thread id is a pid of thread created by clone(2),
[17]  * glibc does not provide a wrapper for gettid().
[18]  */
[19] 
[20] ngx_tid_t
[21] ngx_thread_tid(void)
[22] {
[23]     return syscall(SYS_gettid);
[24] }
[25] 
[26] #elif (NGX_FREEBSD) && (__FreeBSD_version >= 900031)
[27] 
[28] #include <pthread_np.h>
[29] 
[30] ngx_tid_t
[31] ngx_thread_tid(void)
[32] {
[33]     return pthread_getthreadid_np();
[34] }
[35] 
[36] #elif (NGX_DARWIN)
[37] 
[38] /*
[39]  * MacOSX thread has two thread ids:
[40]  *
[41]  * 1) MacOSX 10.6 (Snow Leoprad) has pthread_threadid_np() returning
[42]  *    an uint64_t value, which is obtained using the __thread_selfid()
[43]  *    syscall.  It is a number above 300,000.
[44]  */
[45] 
[46] ngx_tid_t
[47] ngx_thread_tid(void)
[48] {
[49]     uint64_t  tid;
[50] 
[51]     (void) pthread_threadid_np(NULL, &tid);
[52]     return tid;
[53] }
[54] 
[55] /*
[56]  * 2) Kernel thread mach_port_t returned by pthread_mach_thread_np().
[57]  *    It is a number in range 100-100,000.
[58]  *
[59]  * return pthread_mach_thread_np(pthread_self());
[60]  */
[61] 
[62] #else
[63] 
[64] ngx_tid_t
[65] ngx_thread_tid(void)
[66] {
[67]     return (uint64_t) (uintptr_t) pthread_self();
[68] }
[69] 
[70] #endif
