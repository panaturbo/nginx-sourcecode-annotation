[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_FREEBSD_CONFIG_H_INCLUDED_
[9] #define _NGX_FREEBSD_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #include <sys/types.h>
[13] #include <sys/time.h>
[14] #include <unistd.h>
[15] #include <stdarg.h>
[16] #include <stddef.h>             /* offsetof() */
[17] #include <stdio.h>
[18] #include <stdlib.h>
[19] #include <ctype.h>
[20] #include <errno.h>
[21] #include <string.h>
[22] #include <signal.h>
[23] #include <pwd.h>
[24] #include <grp.h>
[25] #include <dirent.h>
[26] #include <glob.h>
[27] #include <time.h>
[28] #include <sys/param.h>          /* ALIGN() */
[29] #include <sys/mount.h>          /* statfs() */
[30] 
[31] #include <sys/filio.h>          /* FIONBIO */
[32] #include <sys/uio.h>
[33] #include <sys/stat.h>
[34] #include <fcntl.h>
[35] 
[36] #include <sys/wait.h>
[37] #include <sys/mman.h>
[38] #include <sys/resource.h>
[39] #include <sched.h>
[40] 
[41] #include <sys/socket.h>
[42] #include <netinet/in.h>
[43] #include <netinet/tcp.h>        /* TCP_NODELAY, TCP_NOPUSH */
[44] #include <arpa/inet.h>
[45] #include <netdb.h>
[46] #include <sys/un.h>
[47] 
[48] #include <libutil.h>            /* setproctitle() before 4.1 */
[49] #include <osreldate.h>
[50] #include <sys/sysctl.h>
[51] 
[52] #include <dlfcn.h>
[53] 
[54] 
[55] #if __FreeBSD_version < 400017
[56] 
[57] /*
[58]  * FreeBSD 3.x has no CMSG_SPACE() and CMSG_LEN() and has the broken CMSG_DATA()
[59]  */
[60] 
[61] #undef  CMSG_SPACE
[62] #define CMSG_SPACE(l)       (ALIGN(sizeof(struct cmsghdr)) + ALIGN(l))
[63] 
[64] #undef  CMSG_LEN
[65] #define CMSG_LEN(l)         (ALIGN(sizeof(struct cmsghdr)) + (l))
[66] 
[67] #undef  CMSG_DATA
[68] #define CMSG_DATA(cmsg)     ((u_char *)(cmsg) + ALIGN(sizeof(struct cmsghdr)))
[69] 
[70] #endif
[71] 
[72] 
[73] #include <ngx_auto_config.h>
[74] 
[75] 
[76] #if (NGX_HAVE_POSIX_SEM)
[77] #include <semaphore.h>
[78] #endif
[79] 
[80] 
[81] #if (NGX_HAVE_POLL)
[82] #include <poll.h>
[83] #endif
[84] 
[85] 
[86] #if (NGX_HAVE_KQUEUE)
[87] #include <sys/event.h>
[88] #endif
[89] 
[90] 
[91] #if (NGX_HAVE_FILE_AIO)
[92] 
[93] #include <aio.h>
[94] typedef struct aiocb  ngx_aiocb_t;
[95] 
[96] #if (__FreeBSD_version < 700005 && !defined __DragonFly__)
[97] #define sival_ptr     sigval_ptr
[98] #endif
[99] 
[100] #endif
[101] 
[102] 
[103] #define NGX_LISTEN_BACKLOG        -1
[104] 
[105] 
[106] #ifdef __DragonFly__
[107] #define NGX_KEEPALIVE_FACTOR      1000
[108] #endif
[109] 
[110] 
[111] #ifndef IOV_MAX
[112] #define IOV_MAX   1024
[113] #endif
[114] 
[115] 
[116] #ifndef NGX_HAVE_INHERITED_NONBLOCK
[117] #define NGX_HAVE_INHERITED_NONBLOCK  1
[118] #endif
[119] 
[120] 
[121] #define NGX_HAVE_OS_SPECIFIC_INIT    1
[122] #define NGX_HAVE_DEBUG_MALLOC        1
[123] 
[124] 
[125] extern char **environ;
[126] extern char  *malloc_options;
[127] 
[128] 
[129] #endif /* _NGX_FREEBSD_CONFIG_H_INCLUDED_ */
