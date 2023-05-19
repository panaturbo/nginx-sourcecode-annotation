[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_LINUX_CONFIG_H_INCLUDED_
[9] #define _NGX_LINUX_CONFIG_H_INCLUDED_
[10] 
[11] 
[12] #ifndef _GNU_SOURCE
[13] #define _GNU_SOURCE             /* pread(), pwrite(), gethostname() */
[14] #endif
[15] 
[16] #define _FILE_OFFSET_BITS  64
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
[33] #include <sys/vfs.h>            /* statfs() */
[34] 
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
[46] #include <netinet/tcp.h>        /* TCP_NODELAY, TCP_CORK */
[47] #include <arpa/inet.h>
[48] #include <netdb.h>
[49] #include <sys/un.h>
[50] 
[51] #include <time.h>               /* tzset() */
[52] #include <malloc.h>             /* memalign() */
[53] #include <limits.h>             /* IOV_MAX */
[54] #include <sys/ioctl.h>
[55] #include <crypt.h>
[56] #include <sys/utsname.h>        /* uname() */
[57] 
[58] #include <dlfcn.h>
[59] 
[60] 
[61] #include <ngx_auto_config.h>
[62] 
[63] 
[64] #if (NGX_HAVE_POSIX_SEM)
[65] #include <semaphore.h>
[66] #endif
[67] 
[68] 
[69] #if (NGX_HAVE_SYS_PRCTL_H)
[70] #include <sys/prctl.h>
[71] #endif
[72] 
[73] 
[74] #if (NGX_HAVE_SENDFILE64)
[75] #include <sys/sendfile.h>
[76] #else
[77] extern ssize_t sendfile(int s, int fd, int32_t *offset, size_t size);
[78] #define NGX_SENDFILE_LIMIT  0x80000000
[79] #endif
[80] 
[81] 
[82] #if (NGX_HAVE_POLL)
[83] #include <poll.h>
[84] #endif
[85] 
[86] 
[87] #if (NGX_HAVE_EPOLL)
[88] #include <sys/epoll.h>
[89] #endif
[90] 
[91] 
[92] #if (NGX_HAVE_SYS_EVENTFD_H)
[93] #include <sys/eventfd.h>
[94] #endif
[95] #include <sys/syscall.h>
[96] #if (NGX_HAVE_FILE_AIO)
[97] #include <linux/aio_abi.h>
[98] typedef struct iocb  ngx_aiocb_t;
[99] #endif
[100] 
[101] 
[102] #if (NGX_HAVE_CAPABILITIES)
[103] #include <linux/capability.h>
[104] #endif
[105] 
[106] #if (NGX_HAVE_UDP_SEGMENT)
[107] #include <netinet/udp.h>
[108] #endif
[109] 
[110] 
[111] #define NGX_LISTEN_BACKLOG        511
[112] 
[113] 
[114] #ifndef NGX_HAVE_SO_SNDLOWAT
[115] /* setsockopt(SO_SNDLOWAT) returns ENOPROTOOPT */
[116] #define NGX_HAVE_SO_SNDLOWAT         0
[117] #endif
[118] 
[119] 
[120] #ifndef NGX_HAVE_INHERITED_NONBLOCK
[121] #define NGX_HAVE_INHERITED_NONBLOCK  0
[122] #endif
[123] 
[124] 
[125] #define NGX_HAVE_OS_SPECIFIC_INIT    1
[126] #define ngx_debug_init()
[127] 
[128] 
[129] extern char **environ;
[130] 
[131] 
[132] #endif /* _NGX_LINUX_CONFIG_H_INCLUDED_ */
