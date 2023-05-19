[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_ERRNO_H_INCLUDED_
[9] #define _NGX_ERRNO_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef int               ngx_err_t;
[17] 
[18] #define NGX_EPERM         EPERM
[19] #define NGX_ENOENT        ENOENT
[20] #define NGX_ENOPATH       ENOENT
[21] #define NGX_ESRCH         ESRCH
[22] #define NGX_EINTR         EINTR
[23] #define NGX_ECHILD        ECHILD
[24] #define NGX_ENOMEM        ENOMEM
[25] #define NGX_EACCES        EACCES
[26] #define NGX_EBUSY         EBUSY
[27] #define NGX_EEXIST        EEXIST
[28] #define NGX_EEXIST_FILE   EEXIST
[29] #define NGX_EXDEV         EXDEV
[30] #define NGX_ENOTDIR       ENOTDIR
[31] #define NGX_EISDIR        EISDIR
[32] #define NGX_EINVAL        EINVAL
[33] #define NGX_ENFILE        ENFILE
[34] #define NGX_EMFILE        EMFILE
[35] #define NGX_ENOSPC        ENOSPC
[36] #define NGX_EPIPE         EPIPE
[37] #define NGX_EINPROGRESS   EINPROGRESS
[38] #define NGX_ENOPROTOOPT   ENOPROTOOPT
[39] #define NGX_EOPNOTSUPP    EOPNOTSUPP
[40] #define NGX_EADDRINUSE    EADDRINUSE
[41] #define NGX_ECONNABORTED  ECONNABORTED
[42] #define NGX_ECONNRESET    ECONNRESET
[43] #define NGX_ENOTCONN      ENOTCONN
[44] #define NGX_ETIMEDOUT     ETIMEDOUT
[45] #define NGX_ECONNREFUSED  ECONNREFUSED
[46] #define NGX_ENAMETOOLONG  ENAMETOOLONG
[47] #define NGX_ENETDOWN      ENETDOWN
[48] #define NGX_ENETUNREACH   ENETUNREACH
[49] #define NGX_EHOSTDOWN     EHOSTDOWN
[50] #define NGX_EHOSTUNREACH  EHOSTUNREACH
[51] #define NGX_ENOSYS        ENOSYS
[52] #define NGX_ECANCELED     ECANCELED
[53] #define NGX_EILSEQ        EILSEQ
[54] #define NGX_ENOMOREFILES  0
[55] #define NGX_ELOOP         ELOOP
[56] #define NGX_EBADF         EBADF
[57] 
[58] #if (NGX_HAVE_OPENAT)
[59] #define NGX_EMLINK        EMLINK
[60] #endif
[61] 
[62] #if (__hpux__)
[63] #define NGX_EAGAIN        EWOULDBLOCK
[64] #else
[65] #define NGX_EAGAIN        EAGAIN
[66] #endif
[67] 
[68] 
[69] #define ngx_errno                  errno
[70] #define ngx_socket_errno           errno
[71] #define ngx_set_errno(err)         errno = err
[72] #define ngx_set_socket_errno(err)  errno = err
[73] 
[74] 
[75] u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
[76] ngx_int_t ngx_strerror_init(void);
[77] 
[78] 
[79] #endif /* _NGX_ERRNO_H_INCLUDED_ */
