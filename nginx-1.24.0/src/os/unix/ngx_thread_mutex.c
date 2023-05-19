[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] 
[10] 
[11] /*
[12]  * All modern pthread mutex implementations try to acquire a lock
[13]  * atomically in userland before going to sleep in kernel.  Some
[14]  * spins before the sleeping.
[15]  *
[16]  * In Solaris since version 8 all mutex types spin before sleeping.
[17]  * The default spin count is 1000.  It can be overridden using
[18]  * _THREAD_ADAPTIVE_SPIN=100 environment variable.
[19]  *
[20]  * In MacOSX all mutex types spin to acquire a lock protecting a mutex's
[21]  * internals.  If the mutex is busy, thread calls Mach semaphore_wait().
[22]  *
[23]  *
[24]  * PTHREAD_MUTEX_NORMAL lacks deadlock detection and is the fastest
[25]  * mutex type.
[26]  *
[27]  *   Linux:    No spinning.  The internal name PTHREAD_MUTEX_TIMED_NP
[28]  *             remains from the times when pthread_mutex_timedlock() was
[29]  *             non-standard extension.  Alias name: PTHREAD_MUTEX_FAST_NP.
[30]  *   FreeBSD:  No spinning.
[31]  *
[32]  *
[33]  * PTHREAD_MUTEX_ERRORCHECK is usually as fast as PTHREAD_MUTEX_NORMAL
[34]  * yet has lightweight deadlock detection.
[35]  *
[36]  *   Linux:    No spinning.  The internal name: PTHREAD_MUTEX_ERRORCHECK_NP.
[37]  *   FreeBSD:  No spinning.
[38]  *
[39]  *
[40]  * PTHREAD_MUTEX_RECURSIVE allows recursive locking.
[41]  *
[42]  *   Linux:    No spinning.  The internal name: PTHREAD_MUTEX_RECURSIVE_NP.
[43]  *   FreeBSD:  No spinning.
[44]  *
[45]  *
[46]  * PTHREAD_MUTEX_ADAPTIVE_NP spins on SMP systems before sleeping.
[47]  *
[48]  *   Linux:    No deadlock detection.  Dynamically changes a spin count
[49]  *             for each mutex from 10 to 100 based on spin count taken
[50]  *             previously.
[51]  *   FreeBSD:  Deadlock detection.  The default spin count is 2000.
[52]  *             It can be overridden using LIBPTHREAD_SPINLOOPS environment
[53]  *             variable or by pthread_mutex_setspinloops_np().  If a lock
[54]  *             is still busy, sched_yield() can be called on both UP and
[55]  *             SMP systems.  The default yield loop count is zero, but
[56]  *             it can be set by LIBPTHREAD_YIELDLOOPS environment
[57]  *             variable or by pthread_mutex_setyieldloops_np().
[58]  *   Solaris:  No PTHREAD_MUTEX_ADAPTIVE_NP.
[59]  *   MacOSX:   No PTHREAD_MUTEX_ADAPTIVE_NP.
[60]  *
[61]  *
[62]  * PTHREAD_MUTEX_ELISION_NP is a Linux extension to elide locks using
[63]  * Intel Restricted Transactional Memory.  It is the most suitable for
[64]  * rwlock pattern access because it allows simultaneous reads without lock.
[65]  * Supported since glibc 2.18.
[66]  *
[67]  *
[68]  * PTHREAD_MUTEX_DEFAULT is default mutex type.
[69]  *
[70]  *   Linux:    PTHREAD_MUTEX_NORMAL.
[71]  *   FreeBSD:  PTHREAD_MUTEX_ERRORCHECK.
[72]  *   Solaris:  PTHREAD_MUTEX_NORMAL.
[73]  *   MacOSX:   PTHREAD_MUTEX_NORMAL.
[74]  */
[75] 
[76] 
[77] ngx_int_t
[78] ngx_thread_mutex_create(ngx_thread_mutex_t *mtx, ngx_log_t *log)
[79] {
[80]     ngx_err_t            err;
[81]     pthread_mutexattr_t  attr;
[82] 
[83]     err = pthread_mutexattr_init(&attr);
[84]     if (err != 0) {
[85]         ngx_log_error(NGX_LOG_EMERG, log, err,
[86]                       "pthread_mutexattr_init() failed");
[87]         return NGX_ERROR;
[88]     }
[89] 
[90]     err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
[91]     if (err != 0) {
[92]         ngx_log_error(NGX_LOG_EMERG, log, err,
[93]                       "pthread_mutexattr_settype"
[94]                       "(PTHREAD_MUTEX_ERRORCHECK) failed");
[95]         return NGX_ERROR;
[96]     }
[97] 
[98]     err = pthread_mutex_init(mtx, &attr);
[99]     if (err != 0) {
[100]         ngx_log_error(NGX_LOG_EMERG, log, err,
[101]                       "pthread_mutex_init() failed");
[102]         return NGX_ERROR;
[103]     }
[104] 
[105]     err = pthread_mutexattr_destroy(&attr);
[106]     if (err != 0) {
[107]         ngx_log_error(NGX_LOG_ALERT, log, err,
[108]                       "pthread_mutexattr_destroy() failed");
[109]     }
[110] 
[111]     return NGX_OK;
[112] }
[113] 
[114] 
[115] ngx_int_t
[116] ngx_thread_mutex_destroy(ngx_thread_mutex_t *mtx, ngx_log_t *log)
[117] {
[118]     ngx_err_t  err;
[119] 
[120]     err = pthread_mutex_destroy(mtx);
[121]     if (err != 0) {
[122]         ngx_log_error(NGX_LOG_ALERT, log, err,
[123]                       "pthread_mutex_destroy() failed");
[124]         return NGX_ERROR;
[125]     }
[126] 
[127]     return NGX_OK;
[128] }
[129] 
[130] 
[131] ngx_int_t
[132] ngx_thread_mutex_lock(ngx_thread_mutex_t *mtx, ngx_log_t *log)
[133] {
[134]     ngx_err_t  err;
[135] 
[136]     err = pthread_mutex_lock(mtx);
[137]     if (err == 0) {
[138]         return NGX_OK;
[139]     }
[140] 
[141]     ngx_log_error(NGX_LOG_ALERT, log, err, "pthread_mutex_lock() failed");
[142] 
[143]     return NGX_ERROR;
[144] }
[145] 
[146] 
[147] ngx_int_t
[148] ngx_thread_mutex_unlock(ngx_thread_mutex_t *mtx, ngx_log_t *log)
[149] {
[150]     ngx_err_t  err;
[151] 
[152]     err = pthread_mutex_unlock(mtx);
[153] 
[154] #if 0
[155]     ngx_time_update();
[156] #endif
[157] 
[158]     if (err == 0) {
[159]         return NGX_OK;
[160]     }
[161] 
[162]     ngx_log_error(NGX_LOG_ALERT, log, err, "pthread_mutex_unlock() failed");
[163] 
[164]     return NGX_ERROR;
[165] }
