[1] 
[2] /*
[3]  * Copyright (C) Nginx, Inc.
[4]  */
[5] 
[6] #ifndef _NGX_SETAFFINITY_H_INCLUDED_
[7] #define _NGX_SETAFFINITY_H_INCLUDED_
[8] 
[9] 
[10] #if (NGX_HAVE_SCHED_SETAFFINITY || NGX_HAVE_CPUSET_SETAFFINITY)
[11] 
[12] #define NGX_HAVE_CPU_AFFINITY 1
[13] 
[14] #if (NGX_HAVE_SCHED_SETAFFINITY)
[15] 
[16] typedef cpu_set_t  ngx_cpuset_t;
[17] 
[18] #elif (NGX_HAVE_CPUSET_SETAFFINITY)
[19] 
[20] #include <sys/cpuset.h>
[21] 
[22] typedef cpuset_t  ngx_cpuset_t;
[23] 
[24] #endif
[25] 
[26] void ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log);
[27] 
[28] #else
[29] 
[30] #define ngx_setaffinity(cpu_affinity, log)
[31] 
[32] typedef uint64_t  ngx_cpuset_t;
[33] 
[34] #endif
[35] 
[36] 
[37] #endif /* _NGX_SETAFFINITY_H_INCLUDED_ */
