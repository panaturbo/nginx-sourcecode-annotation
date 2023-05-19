[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_FILES_H_INCLUDED_
[9] #define _NGX_FILES_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] typedef HANDLE                      ngx_fd_t;
[17] typedef BY_HANDLE_FILE_INFORMATION  ngx_file_info_t;
[18] typedef uint64_t                    ngx_file_uniq_t;
[19] 
[20] 
[21] typedef struct {
[22]     u_char                         *name;
[23]     size_t                          size;
[24]     void                           *addr;
[25]     ngx_fd_t                        fd;
[26]     HANDLE                          handle;
[27]     ngx_log_t                      *log;
[28] } ngx_file_mapping_t;
[29] 
[30] 
[31] typedef struct {
[32]     HANDLE                          dir;
[33]     WIN32_FIND_DATAW                finddata;
[34] 
[35]     u_char                         *name;
[36]     size_t                          namelen;
[37]     size_t                          allocated;
[38] 
[39]     unsigned                        valid_info:1;
[40]     unsigned                        type:1;
[41]     unsigned                        ready:1;
[42] } ngx_dir_t;
[43] 
[44] 
[45] typedef struct {
[46]     HANDLE                          dir;
[47]     WIN32_FIND_DATAW                finddata;
[48] 
[49]     unsigned                        ready:1;
[50]     unsigned                        test:1;
[51]     unsigned                        no_match:1;
[52] 
[53]     u_char                         *pattern;
[54]     ngx_str_t                       name;
[55]     size_t                          last;
[56]     ngx_log_t                      *log;
[57] } ngx_glob_t;
[58] 
[59] 
[60] 
[61] /* INVALID_FILE_ATTRIBUTES is specified but not defined at least in MSVC6SP2 */
[62] #ifndef INVALID_FILE_ATTRIBUTES
[63] #define INVALID_FILE_ATTRIBUTES     0xffffffff
[64] #endif
[65] 
[66] /* INVALID_SET_FILE_POINTER is not defined at least in MSVC6SP2 */
[67] #ifndef INVALID_SET_FILE_POINTER
[68] #define INVALID_SET_FILE_POINTER    0xffffffff
[69] #endif
[70] 
[71] 
[72] #define NGX_INVALID_FILE            INVALID_HANDLE_VALUE
[73] #define NGX_FILE_ERROR              0
[74] 
[75] 
[76] ngx_fd_t ngx_open_file(u_char *name, u_long mode, u_long create, u_long access);
[77] #define ngx_open_file_n             "CreateFile()"
[78] 
[79] #define NGX_FILE_RDONLY             GENERIC_READ
[80] #define NGX_FILE_WRONLY             GENERIC_WRITE
[81] #define NGX_FILE_RDWR               GENERIC_READ|GENERIC_WRITE
[82] #define NGX_FILE_APPEND             FILE_APPEND_DATA|SYNCHRONIZE
[83] #define NGX_FILE_NONBLOCK           0
[84] 
[85] #define NGX_FILE_CREATE_OR_OPEN     OPEN_ALWAYS
[86] #define NGX_FILE_OPEN               OPEN_EXISTING
[87] #define NGX_FILE_TRUNCATE           CREATE_ALWAYS
[88] 
[89] #define NGX_FILE_DEFAULT_ACCESS     0
[90] #define NGX_FILE_OWNER_ACCESS       0
[91] 
[92] 
[93] ngx_fd_t ngx_open_tempfile(u_char *name, ngx_uint_t persistent,
[94]     ngx_uint_t access);
[95] #define ngx_open_tempfile_n         "CreateFile()"
[96] 
[97] 
[98] #define ngx_close_file              CloseHandle
[99] #define ngx_close_file_n            "CloseHandle()"
[100] 
[101] 
[102] ssize_t ngx_read_fd(ngx_fd_t fd, void *buf, size_t size);
[103] #define ngx_read_fd_n               "ReadFile()"
[104] 
[105] 
[106] ssize_t ngx_write_fd(ngx_fd_t fd, void *buf, size_t size);
[107] #define ngx_write_fd_n              "WriteFile()"
[108] 
[109] 
[110] ssize_t ngx_write_console(ngx_fd_t fd, void *buf, size_t size);
[111] 
[112] 
[113] #define ngx_linefeed(p)             *p++ = CR; *p++ = LF;
[114] #define NGX_LINEFEED_SIZE           2
[115] #define NGX_LINEFEED                CRLF
[116] 
[117] 
[118] ngx_int_t ngx_delete_file(u_char *name);
[119] #define ngx_delete_file_n           "DeleteFile()"
[120] 
[121] 
[122] ngx_int_t ngx_rename_file(u_char *from, u_char *to);
[123] #define ngx_rename_file_n           "MoveFile()"
[124] ngx_err_t ngx_win32_rename_file(ngx_str_t *from, ngx_str_t *to, ngx_log_t *log);
[125] 
[126] 
[127] 
[128] ngx_int_t ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s);
[129] #define ngx_set_file_time_n         "SetFileTime()"
[130] 
[131] 
[132] ngx_int_t ngx_file_info(u_char *filename, ngx_file_info_t *fi);
[133] #define ngx_file_info_n             "GetFileAttributesEx()"
[134] 
[135] 
[136] #define ngx_fd_info(fd, fi)         GetFileInformationByHandle(fd, fi)
[137] #define ngx_fd_info_n               "GetFileInformationByHandle()"
[138] 
[139] 
[140] #define ngx_link_info(name, fi)     ngx_file_info(name, fi)
[141] #define ngx_link_info_n             "GetFileAttributesEx()"
[142] 
[143] 
[144] #define ngx_is_dir(fi)                                                       \
[145]     (((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
[146] #define ngx_is_file(fi)                                                      \
[147]     (((fi)->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
[148] #define ngx_is_link(fi)     0
[149] #define ngx_is_exec(fi)     0
[150] 
[151] #define ngx_file_access(fi) 0
[152] 
[153] #define ngx_file_size(fi)                                                    \
[154]     (((off_t) (fi)->nFileSizeHigh << 32) | (fi)->nFileSizeLow)
[155] #define ngx_file_fs_size(fi)        ngx_file_size(fi)
[156] 
[157] #define ngx_file_uniq(fi)   (*(ngx_file_uniq_t *) &(fi)->nFileIndexHigh)
[158] 
[159] 
[160] /* 116444736000000000 is commented in src/os/win32/ngx_time.c */
[161] 
[162] #define ngx_file_mtime(fi)                                                   \
[163]  (time_t) (((((unsigned __int64) (fi)->ftLastWriteTime.dwHighDateTime << 32) \
[164]                                | (fi)->ftLastWriteTime.dwLowDateTime)        \
[165]                                           - 116444736000000000) / 10000000)
[166] 
[167] ngx_int_t ngx_create_file_mapping(ngx_file_mapping_t *fm);
[168] void ngx_close_file_mapping(ngx_file_mapping_t *fm);
[169] 
[170] 
[171] u_char *ngx_realpath(u_char *path, u_char *resolved);
[172] #define ngx_realpath_n              ""
[173] 
[174] 
[175] size_t ngx_getcwd(u_char *buf, size_t size);
[176] #define ngx_getcwd_n                "GetCurrentDirectory()"
[177] 
[178] 
[179] #define ngx_path_separator(c)       ((c) == '/' || (c) == '\\')
[180] 
[181] #define NGX_HAVE_MAX_PATH           1
[182] #define NGX_MAX_PATH                MAX_PATH
[183] 
[184] 
[185] ngx_int_t ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir);
[186] #define ngx_open_dir_n              "FindFirstFile()"
[187] 
[188] 
[189] ngx_int_t ngx_read_dir(ngx_dir_t *dir);
[190] #define ngx_read_dir_n              "FindNextFile()"
[191] 
[192] 
[193] ngx_int_t ngx_close_dir(ngx_dir_t *dir);
[194] #define ngx_close_dir_n             "FindClose()"
[195] 
[196] 
[197] ngx_int_t ngx_create_dir(u_char *name, ngx_uint_t access);
[198] #define ngx_create_dir_n            "CreateDirectory()"
[199] 
[200] 
[201] ngx_int_t ngx_delete_dir(u_char *name);
[202] #define ngx_delete_dir_n            "RemoveDirectory()"
[203] 
[204] 
[205] #define ngx_dir_access(a)           (a)
[206] 
[207] 
[208] #define ngx_de_name(dir)            (dir)->name
[209] #define ngx_de_namelen(dir)         (dir)->namelen
[210] 
[211] ngx_int_t ngx_de_info(u_char *name, ngx_dir_t *dir);
[212] #define ngx_de_info_n               "dummy()"
[213] 
[214] ngx_int_t ngx_de_link_info(u_char *name, ngx_dir_t *dir);
[215] #define ngx_de_link_info_n          "dummy()"
[216] 
[217] #define ngx_de_is_dir(dir)                                                   \
[218]     (((dir)->finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
[219] #define ngx_de_is_file(dir)                                                  \
[220]     (((dir)->finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
[221] #define ngx_de_is_link(dir)         0
[222] #define ngx_de_access(dir)          0
[223] #define ngx_de_size(dir)                                                     \
[224]   (((off_t) (dir)->finddata.nFileSizeHigh << 32) | (dir)->finddata.nFileSizeLow)
[225] #define ngx_de_fs_size(dir)         ngx_de_size(dir)
[226] 
[227] /* 116444736000000000 is commented in src/os/win32/ngx_time.c */
[228] 
[229] #define ngx_de_mtime(dir)                                                    \
[230]     (time_t) (((((unsigned __int64)                                          \
[231]                      (dir)->finddata.ftLastWriteTime.dwHighDateTime << 32)   \
[232]                       | (dir)->finddata.ftLastWriteTime.dwLowDateTime)       \
[233]                                           - 116444736000000000) / 10000000)
[234] 
[235] 
[236] ngx_int_t ngx_open_glob(ngx_glob_t *gl);
[237] #define ngx_open_glob_n             "FindFirstFile()"
[238] 
[239] ngx_int_t ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name);
[240] void ngx_close_glob(ngx_glob_t *gl);
[241] 
[242] 
[243] ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset);
[244] #define ngx_read_file_n             "ReadFile()"
[245] 
[246] ssize_t ngx_write_file(ngx_file_t *file, u_char *buf, size_t size,
[247]     off_t offset);
[248] 
[249] ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
[250]     off_t offset, ngx_pool_t *pool);
[251] 
[252] ngx_int_t ngx_read_ahead(ngx_fd_t fd, size_t n);
[253] #define ngx_read_ahead_n            "ngx_read_ahead_n"
[254] 
[255] ngx_int_t ngx_directio_on(ngx_fd_t fd);
[256] #define ngx_directio_on_n           "ngx_directio_on_n"
[257] 
[258] ngx_int_t ngx_directio_off(ngx_fd_t fd);
[259] #define ngx_directio_off_n          "ngx_directio_off_n"
[260] 
[261] size_t ngx_fs_bsize(u_char *name);
[262] off_t ngx_fs_available(u_char *name);
[263] 
[264] 
[265] #define ngx_stdout               GetStdHandle(STD_OUTPUT_HANDLE)
[266] #define ngx_stderr               GetStdHandle(STD_ERROR_HANDLE)
[267] #define ngx_set_stderr(fd)       SetStdHandle(STD_ERROR_HANDLE, fd)
[268] #define ngx_set_stderr_n         "SetStdHandle(STD_ERROR_HANDLE)"
[269] 
[270] 
[271] #endif /* _NGX_FILES_H_INCLUDED_ */
