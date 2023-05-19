[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_SOLARIS_CONFIG_H_INCLUDED_
[9] #define _NGX_SOLARIS_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #ifndef _REENTRANT
[13] #define _REENTRANT
[14] #endif
[15] 
[16] #define _FILE_OFFSET_BITS  64   /* must be before <sys/types.h> */
[17] 
[18] #include <sys/types.h>
[19] #include <sys/time.h>
[20] #include <unistd.h>
[21] #include <stdarg.h>
[22] #include <stddef.h>             /* offsetof() */
[23] #include <stdio.h>
[24] #include <stdlib.h>
[25] #include <ctype.h>
[26] #include <errno.h>
[27] #include <string.h>
[28] #include <signal.h>
[29] #include <pwd.h>
[30] #include <grp.h>
[31] #include <dirent.h>
[32] #include <glob.h>
[33] #include <time.h>
[34] #include <sys/statvfs.h>        /* statvfs() */
[35] 
[36] #include <sys/filio.h>          /* FIONBIO */
[37] #include <sys/uio.h>
[38] #include <sys/stat.h>
[39] #include <fcntl.h>
[40] 
[41] #include <sys/wait.h>
[42] #include <sys/mman.h>
[43] #include <sys/resource.h>
[44] #include <sched.h>
[45] 
[46] #include <sys/socket.h>
[47] #include <netinet/in.h>
[48] #include <netinet/tcp.h>        /* TCP_NODELAY */
[49] #include <arpa/inet.h>
[50] #include <netdb.h>
[51] #include <sys/un.h>
[52] 
[53] #include <sys/systeminfo.h>
[54] #include <limits.h>             /* IOV_MAX */
[55] #include <inttypes.h>
[56] #include <crypt.h>
[57] 
[58] #include <dlfcn.h>
[59] 
[60] #define NGX_ALIGNMENT  _MAX_ALIGNMENT
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
[75] #if (NGX_HAVE_DEVPOLL)
[76] #include <sys/ioctl.h>
[77] #include <sys/devpoll.h>
[78] #endif
[79] 
[80] 
[81] #if (NGX_HAVE_EVENTPORT)
[82] #include <port.h>
[83] #endif
[84] 
[85] 
[86] #if (NGX_HAVE_SENDFILE)
[87] #include <sys/sendfile.h>
[88] #endif
[89] 
[90] 
[91] #define NGX_LISTEN_BACKLOG           511
[92] 
[93] 
[94] #ifndef NGX_HAVE_INHERITED_NONBLOCK
[95] #define NGX_HAVE_INHERITED_NONBLOCK  1
[96] #endif
[97] 
[98] 
[99] #ifndef NGX_HAVE_SO_SNDLOWAT
[100] /* setsockopt(SO_SNDLOWAT) returns ENOPROTOOPT */
[101] #define NGX_HAVE_SO_SNDLOWAT         0
[102] #endif
[103] 
[104] 
[105] #define NGX_HAVE_OS_SPECIFIC_INIT    1
[106] #define ngx_debug_init()
[107] 
[108] 
[109] extern char **environ;
[110] 
[111] 
[112] #endif /* _NGX_SOLARIS_CONFIG_H_INCLUDED_ */
