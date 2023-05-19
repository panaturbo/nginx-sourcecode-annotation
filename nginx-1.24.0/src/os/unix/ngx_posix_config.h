[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_POSIX_CONFIG_H_INCLUDED_
[9] #define _NGX_POSIX_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #if (NGX_HPUX)
[13] #define _XOPEN_SOURCE
[14] #define _XOPEN_SOURCE_EXTENDED  1
[15] #define _HPUX_ALT_XOPEN_SOCKET_API
[16] #endif
[17] 
[18] 
[19] #if (NGX_TRU64)
[20] #define _REENTRANT
[21] #endif
[22] 
[23] 
[24] #if (NGX_GNU_HURD)
[25] #ifndef _GNU_SOURCE
[26] #define _GNU_SOURCE             /* accept4() */
[27] #endif
[28] #define _FILE_OFFSET_BITS       64
[29] #endif
[30] 
[31] 
[32] #ifdef __CYGWIN__
[33] #define timezonevar             /* timezone is variable */
[34] #define NGX_BROKEN_SCM_RIGHTS   1
[35] #endif
[36] 
[37] 
[38] #include <sys/types.h>
[39] #include <sys/time.h>
[40] #if (NGX_HAVE_UNISTD_H)
[41] #include <unistd.h>
[42] #endif
[43] #if (NGX_HAVE_INTTYPES_H)
[44] #include <inttypes.h>
[45] #endif
[46] #include <stdarg.h>
[47] #include <stddef.h>             /* offsetof() */
[48] #include <stdio.h>
[49] #include <stdlib.h>
[50] #include <ctype.h>
[51] #include <errno.h>
[52] #include <string.h>
[53] #include <signal.h>
[54] #include <pwd.h>
[55] #include <grp.h>
[56] #include <dirent.h>
[57] #include <glob.h>
[58] #include <time.h>
[59] #if (NGX_HAVE_SYS_PARAM_H)
[60] #include <sys/param.h>          /* statfs() */
[61] #endif
[62] #if (NGX_HAVE_SYS_MOUNT_H)
[63] #include <sys/mount.h>          /* statfs() */
[64] #endif
[65] #if (NGX_HAVE_SYS_STATVFS_H)
[66] #include <sys/statvfs.h>        /* statvfs() */
[67] #endif
[68] 
[69] #if (NGX_HAVE_SYS_FILIO_H)
[70] #include <sys/filio.h>          /* FIONBIO */
[71] #endif
[72] #include <sys/ioctl.h>          /* FIONBIO */
[73] 
[74] #include <sys/uio.h>
[75] #include <sys/stat.h>
[76] #include <fcntl.h>
[77] 
[78] #include <sys/wait.h>
[79] #include <sys/mman.h>
[80] #include <sys/resource.h>
[81] #include <sched.h>
[82] 
[83] #include <sys/socket.h>
[84] #include <netinet/in.h>
[85] #include <netinet/tcp.h>        /* TCP_NODELAY */
[86] #include <arpa/inet.h>
[87] #include <netdb.h>
[88] #include <sys/un.h>
[89] 
[90] #if (NGX_HAVE_LIMITS_H)
[91] #include <limits.h>             /* IOV_MAX */
[92] #endif
[93] 
[94] #ifdef __CYGWIN__
[95] #include <malloc.h>             /* memalign() */
[96] #endif
[97] 
[98] #if (NGX_HAVE_CRYPT_H)
[99] #include <crypt.h>
[100] #endif
[101] 
[102] 
[103] #ifndef IOV_MAX
[104] #define IOV_MAX   16
[105] #endif
[106] 
[107] 
[108] #include <ngx_auto_config.h>
[109] 
[110] 
[111] #if (NGX_HAVE_DLOPEN)
[112] #include <dlfcn.h>
[113] #endif
[114] 
[115] 
[116] #if (NGX_HAVE_POSIX_SEM)
[117] #include <semaphore.h>
[118] #endif
[119] 
[120] 
[121] #if (NGX_HAVE_POLL)
[122] #include <poll.h>
[123] #endif
[124] 
[125] 
[126] #if (NGX_HAVE_KQUEUE)
[127] #include <sys/event.h>
[128] #endif
[129] 
[130] 
[131] #if (NGX_HAVE_DEVPOLL) && !(NGX_TEST_BUILD_DEVPOLL)
[132] #include <sys/ioctl.h>
[133] #include <sys/devpoll.h>
[134] #endif
[135] 
[136] 
[137] #if (NGX_HAVE_FILE_AIO)
[138] #include <aio.h>
[139] typedef struct aiocb  ngx_aiocb_t;
[140] #endif
[141] 
[142] 
[143] #define NGX_LISTEN_BACKLOG  511
[144] 
[145] #define ngx_debug_init()
[146] 
[147] 
[148] extern char **environ;
[149] 
[150] 
[151] #endif /* _NGX_POSIX_CONFIG_H_INCLUDED_ */
