[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] 
[10] 
[11] #if (NGX_HAVE_CPUSET_SETAFFINITY)
[12] 
[13] void
[14] ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log)
[15] {
[16]     ngx_uint_t  i;
[17] 
[18]     for (i = 0; i < CPU_SETSIZE; i++) {
[19]         if (CPU_ISSET(i, cpu_affinity)) {
[20]             ngx_log_error(NGX_LOG_NOTICE, log, 0,
[21]                           "cpuset_setaffinity(): using cpu #%ui", i);
[22]         }
[23]     }
[24] 
[25]     if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
[26]                            sizeof(cpuset_t), cpu_affinity) == -1)
[27]     {
[28]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[29]                       "cpuset_setaffinity() failed");
[30]     }
[31] }
[32] 
[33] #elif (NGX_HAVE_SCHED_SETAFFINITY)
[34] 
[35] void
[36] ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log)
[37] {
[38]     ngx_uint_t  i;
[39] 
[40]     for (i = 0; i < CPU_SETSIZE; i++) {
[41]         if (CPU_ISSET(i, cpu_affinity)) {
[42]             ngx_log_error(NGX_LOG_NOTICE, log, 0,
[43]                           "sched_setaffinity(): using cpu #%ui", i);
[44]         }
[45]     }
[46] 
[47]     if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) {
[48]         ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
[49]                       "sched_setaffinity() failed");
[50]     }
[51] }
[52] 
[53] #endif
