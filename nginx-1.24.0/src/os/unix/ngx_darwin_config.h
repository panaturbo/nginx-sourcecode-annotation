[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_DARWIN_CONFIG_H_INCLUDED_
[9] #define _NGX_DARWIN_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #define __APPLE_USE_RFC_3542    /* IPV6_PKTINFO */
[13] 
[14] 
[15] #include <sys/types.h>
[16] #include <sys/time.h>
[17] #include <unistd.h>
[18] #include <inttypes.h>
[19] #include <stdarg.h>
[20] #include <stddef.h>             /* offsetof() */
[21] #include <stdio.h>
[22] #include <stdlib.h>
[23] #include <ctype.h>
[24] #include <errno.h>
[25] #include <string.h>
[26] #include <signal.h>
[27] #include <pwd.h>
[28] #include <grp.h>
[29] #include <dirent.h>
[30] #include <glob.h>
[31] #include <sys/mount.h>          /* statfs() */
[32] 
[33] #include <sys/filio.h>          /* FIONBIO */
[34] #include <sys/ioctl.h>
[35] #include <sys/uio.h>
[36] #include <sys/stat.h>
[37] #include <fcntl.h>
[38] 
[39] #include <sys/wait.h>
[40] #include <sys/mman.h>
[41] #include <sys/resource.h>
[42] #include <sched.h>
[43] 
[44] #include <sys/socket.h>
[45] #include <netinet/in.h>
[46] #include <netinet/tcp.h>        /* TCP_NODELAY */
[47] #include <arpa/inet.h>
[48] #include <netdb.h>
[49] #include <sys/un.h>
[50] 
[51] #include <sys/sysctl.h>
[52] #include <xlocale.h>
[53] 
[54] #include <dlfcn.h>
[55] 
[56] 
[57] #ifndef IOV_MAX
[58] #define IOV_MAX   64
[59] #endif
[60] 
[61] 
[62] #include <ngx_auto_config.h>
[63] 
[64] 
[65] #if (NGX_HAVE_POSIX_SEM)
[66] #include <semaphore.h>
[67] #endif
[68] 
[69] 
[70] #if (NGX_HAVE_POLL)
[71] #include <poll.h>
[72] #endif
[73] 
[74] 
[75] #if (NGX_HAVE_KQUEUE)
[76] #include <sys/event.h>
[77] #endif
[78] 
[79] 
[80] #define NGX_LISTEN_BACKLOG  -1
[81] 
[82] 
[83] #ifndef NGX_HAVE_INHERITED_NONBLOCK
[84] #define NGX_HAVE_INHERITED_NONBLOCK  1
[85] #endif
[86] 
[87] 
[88] #ifndef NGX_HAVE_CASELESS_FILESYSTEM
[89] #define NGX_HAVE_CASELESS_FILESYSTEM  1
[90] #endif
[91] 
[92] 
[93] #define NGX_HAVE_OS_SPECIFIC_INIT    1
[94] #define NGX_HAVE_DEBUG_MALLOC        1
[95] 
[96] 
[97] extern char **environ;
[98] 
[99] 
[100] #endif /* _NGX_DARWIN_CONFIG_H_INCLUDED_ */
