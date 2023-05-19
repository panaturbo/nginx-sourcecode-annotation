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
[16] typedef DWORD                      ngx_err_t;
[17] 
[18] #define ngx_errno                  GetLastError()
[19] #define ngx_set_errno(err)         SetLastError(err)
[20] #define ngx_socket_errno           WSAGetLastError()
[21] #define ngx_set_socket_errno(err)  WSASetLastError(err)
[22] 
[23] #define NGX_EPERM                  ERROR_ACCESS_DENIED
[24] #define NGX_ENOENT                 ERROR_FILE_NOT_FOUND
[25] #define NGX_ENOPATH                ERROR_PATH_NOT_FOUND
[26] #define NGX_ENOMEM                 ERROR_NOT_ENOUGH_MEMORY
[27] #define NGX_EACCES                 ERROR_ACCESS_DENIED
[28] /*
[29]  * there are two EEXIST error codes:
[30]  * ERROR_FILE_EXISTS used by CreateFile(CREATE_NEW),
[31]  * and ERROR_ALREADY_EXISTS used by CreateDirectory();
[32]  * MoveFile() uses both
[33]  */
[34] #define NGX_EEXIST                 ERROR_ALREADY_EXISTS
[35] #define NGX_EEXIST_FILE            ERROR_FILE_EXISTS
[36] #define NGX_EXDEV                  ERROR_NOT_SAME_DEVICE
[37] #define NGX_ENOTDIR                ERROR_PATH_NOT_FOUND
[38] #define NGX_EISDIR                 ERROR_CANNOT_MAKE
[39] #define NGX_ENOSPC                 ERROR_DISK_FULL
[40] #define NGX_EPIPE                  EPIPE
[41] #define NGX_EAGAIN                 WSAEWOULDBLOCK
[42] #define NGX_EINPROGRESS            WSAEINPROGRESS
[43] #define NGX_ENOPROTOOPT            WSAENOPROTOOPT
[44] #define NGX_EOPNOTSUPP             WSAEOPNOTSUPP
[45] #define NGX_EADDRINUSE             WSAEADDRINUSE
[46] #define NGX_ECONNABORTED           WSAECONNABORTED
[47] #define NGX_ECONNRESET             WSAECONNRESET
[48] #define NGX_ENOTCONN               WSAENOTCONN
[49] #define NGX_ETIMEDOUT              WSAETIMEDOUT
[50] #define NGX_ECONNREFUSED           WSAECONNREFUSED
[51] #define NGX_ENAMETOOLONG           ERROR_BAD_PATHNAME
[52] #define NGX_ENETDOWN               WSAENETDOWN
[53] #define NGX_ENETUNREACH            WSAENETUNREACH
[54] #define NGX_EHOSTDOWN              WSAEHOSTDOWN
[55] #define NGX_EHOSTUNREACH           WSAEHOSTUNREACH
[56] #define NGX_ENOMOREFILES           ERROR_NO_MORE_FILES
[57] #define NGX_EILSEQ                 ERROR_NO_UNICODE_TRANSLATION
[58] #define NGX_ELOOP                  0
[59] #define NGX_EBADF                  WSAEBADF
[60] 
[61] #define NGX_EALREADY               WSAEALREADY
[62] #define NGX_EINVAL                 WSAEINVAL
[63] #define NGX_EMFILE                 WSAEMFILE
[64] #define NGX_ENFILE                 WSAEMFILE
[65] 
[66] 
[67] u_char *ngx_strerror(ngx_err_t err, u_char *errstr, size_t size);
[68] ngx_int_t ngx_strerror_init(void);
[69] 
[70] 
[71] #endif /* _NGX_ERRNO_H_INCLUDED_ */
