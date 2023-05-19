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
[16] typedef int                      ngx_fd_t;
[17] typedef struct stat              ngx_file_info_t;
[18] typedef ino_t                    ngx_file_uniq_t;
[19] 
[20] 
[21] typedef struct {
[22]     u_char                      *name;
[23]     size_t                       size;
[24]     void                        *addr;
[25]     ngx_fd_t                     fd;
[26]     ngx_log_t                   *log;
[27] } ngx_file_mapping_t;
[28] 
[29] 
[30] typedef struct {
[31]     DIR                         *dir;
[32]     struct dirent               *de;
[33]     struct stat                  info;
[34] 
[35]     unsigned                     type:8;
[36]     unsigned                     valid_info:1;
[37] } ngx_dir_t;
[38] 
[39] 
[40] typedef struct {
[41]     size_t                       n;
[42]     glob_t                       pglob;
[43]     u_char                      *pattern;
[44]     ngx_log_t                   *log;
[45]     ngx_uint_t                   test;
[46] } ngx_glob_t;
[47] 
[48] 
[49] #define NGX_INVALID_FILE         -1
[50] #define NGX_FILE_ERROR           -1
[51] 
[52] 
[53] 
[54] #ifdef __CYGWIN__
[55] 
[56] #ifndef NGX_HAVE_CASELESS_FILESYSTEM
[57] #define NGX_HAVE_CASELESS_FILESYSTEM  1
[58] #endif
[59] 
[60] #define ngx_open_file(name, mode, create, access)                            \
[61]     open((const char *) name, mode|create|O_BINARY, access)
[62] 
[63] #else
[64] 
[65] #define ngx_open_file(name, mode, create, access)                            \
[66]     open((const char *) name, mode|create, access)
[67] 
[68] #endif
[69] 
[70] #define ngx_open_file_n          "open()"
[71] 
[72] #define NGX_FILE_RDONLY          O_RDONLY
[73] #define NGX_FILE_WRONLY          O_WRONLY
[74] #define NGX_FILE_RDWR            O_RDWR
[75] #define NGX_FILE_CREATE_OR_OPEN  O_CREAT
[76] #define NGX_FILE_OPEN            0
[77] #define NGX_FILE_TRUNCATE        (O_CREAT|O_TRUNC)
[78] #define NGX_FILE_APPEND          (O_WRONLY|O_APPEND)
[79] #define NGX_FILE_NONBLOCK        O_NONBLOCK
[80] 
[81] #if (NGX_HAVE_OPENAT)
[82] #define NGX_FILE_NOFOLLOW        O_NOFOLLOW
[83] 
[84] #if defined(O_DIRECTORY)
[85] #define NGX_FILE_DIRECTORY       O_DIRECTORY
[86] #else
[87] #define NGX_FILE_DIRECTORY       0
[88] #endif
[89] 
[90] #if defined(O_SEARCH)
[91] #define NGX_FILE_SEARCH          (O_SEARCH|NGX_FILE_DIRECTORY)
[92] 
[93] #elif defined(O_EXEC)
[94] #define NGX_FILE_SEARCH          (O_EXEC|NGX_FILE_DIRECTORY)
[95] 
[96] #elif (NGX_HAVE_O_PATH)
[97] #define NGX_FILE_SEARCH          (O_PATH|O_RDONLY|NGX_FILE_DIRECTORY)
[98] 
[99] #else
[100] #define NGX_FILE_SEARCH          (O_RDONLY|NGX_FILE_DIRECTORY)
[101] #endif
[102] 
[103] #endif /* NGX_HAVE_OPENAT */
[104] 
[105] #define NGX_FILE_DEFAULT_ACCESS  0644
[106] #define NGX_FILE_OWNER_ACCESS    0600
[107] 
[108] 
[109] #define ngx_close_file           close
[110] #define ngx_close_file_n         "close()"
[111] 
[112] 
[113] #define ngx_delete_file(name)    unlink((const char *) name)
[114] #define ngx_delete_file_n        "unlink()"
[115] 
[116] 
[117] ngx_fd_t ngx_open_tempfile(u_char *name, ngx_uint_t persistent,
[118]     ngx_uint_t access);
[119] #define ngx_open_tempfile_n      "open()"
[120] 
[121] 
[122] ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset);
[123] #if (NGX_HAVE_PREAD)
[124] #define ngx_read_file_n          "pread()"
[125] #else
[126] #define ngx_read_file_n          "read()"
[127] #endif
[128] 
[129] ssize_t ngx_write_file(ngx_file_t *file, u_char *buf, size_t size,
[130]     off_t offset);
[131] 
[132] ssize_t ngx_write_chain_to_file(ngx_file_t *file, ngx_chain_t *ce,
[133]     off_t offset, ngx_pool_t *pool);
[134] 
[135] 
[136] #define ngx_read_fd              read
[137] #define ngx_read_fd_n            "read()"
[138] 
[139] /*
[140]  * we use inlined function instead of simple #define
[141]  * because glibc 2.3 sets warn_unused_result attribute for write()
[142]  * and in this case gcc 4.3 ignores (void) cast
[143]  */
[144] static ngx_inline ssize_t
[145] ngx_write_fd(ngx_fd_t fd, void *buf, size_t n)
[146] {
[147]     return write(fd, buf, n);
[148] }
[149] 
[150] #define ngx_write_fd_n           "write()"
[151] 
[152] 
[153] #define ngx_write_console        ngx_write_fd
[154] 
[155] 
[156] #define ngx_linefeed(p)          *p++ = LF;
[157] #define NGX_LINEFEED_SIZE        1
[158] #define NGX_LINEFEED             "\x0a"
[159] 
[160] 
[161] #define ngx_rename_file(o, n)    rename((const char *) o, (const char *) n)
[162] #define ngx_rename_file_n        "rename()"
[163] 
[164] 
[165] #define ngx_change_file_access(n, a) chmod((const char *) n, a)
[166] #define ngx_change_file_access_n "chmod()"
[167] 
[168] 
[169] ngx_int_t ngx_set_file_time(u_char *name, ngx_fd_t fd, time_t s);
[170] #define ngx_set_file_time_n      "utimes()"
[171] 
[172] 
[173] #define ngx_file_info(file, sb)  stat((const char *) file, sb)
[174] #define ngx_file_info_n          "stat()"
[175] 
[176] #define ngx_fd_info(fd, sb)      fstat(fd, sb)
[177] #define ngx_fd_info_n            "fstat()"
[178] 
[179] #define ngx_link_info(file, sb)  lstat((const char *) file, sb)
[180] #define ngx_link_info_n          "lstat()"
[181] 
[182] #define ngx_is_dir(sb)           (S_ISDIR((sb)->st_mode))
[183] #define ngx_is_file(sb)          (S_ISREG((sb)->st_mode))
[184] #define ngx_is_link(sb)          (S_ISLNK((sb)->st_mode))
[185] #define ngx_is_exec(sb)          (((sb)->st_mode & S_IXUSR) == S_IXUSR)
[186] #define ngx_file_access(sb)      ((sb)->st_mode & 0777)
[187] #define ngx_file_size(sb)        (sb)->st_size
[188] #define ngx_file_fs_size(sb)                                                 \
[189]     (((sb)->st_blocks * 512 > (sb)->st_size                                  \
[190]      && (sb)->st_blocks * 512 < (sb)->st_size + 8 * (sb)->st_blksize)        \
[191]      ? (sb)->st_blocks * 512 : (sb)->st_size)
[192] #define ngx_file_mtime(sb)       (sb)->st_mtime
[193] #define ngx_file_uniq(sb)        (sb)->st_ino
[194] 
[195] 
[196] ngx_int_t ngx_create_file_mapping(ngx_file_mapping_t *fm);
[197] void ngx_close_file_mapping(ngx_file_mapping_t *fm);
[198] 
[199] 
[200] #define ngx_realpath(p, r)       (u_char *) realpath((char *) p, (char *) r)
[201] #define ngx_realpath_n           "realpath()"
[202] #define ngx_getcwd(buf, size)    (getcwd((char *) buf, size) != NULL)
[203] #define ngx_getcwd_n             "getcwd()"
[204] #define ngx_path_separator(c)    ((c) == '/')
[205] 
[206] 
[207] #if defined(PATH_MAX)
[208] 
[209] #define NGX_HAVE_MAX_PATH        1
[210] #define NGX_MAX_PATH             PATH_MAX
[211] 
[212] #else
[213] 
[214] #define NGX_MAX_PATH             4096
[215] 
[216] #endif
[217] 
[218] 
[219] ngx_int_t ngx_open_dir(ngx_str_t *name, ngx_dir_t *dir);
[220] #define ngx_open_dir_n           "opendir()"
[221] 
[222] 
[223] #define ngx_close_dir(d)         closedir((d)->dir)
[224] #define ngx_close_dir_n          "closedir()"
[225] 
[226] 
[227] ngx_int_t ngx_read_dir(ngx_dir_t *dir);
[228] #define ngx_read_dir_n           "readdir()"
[229] 
[230] 
[231] #define ngx_create_dir(name, access) mkdir((const char *) name, access)
[232] #define ngx_create_dir_n         "mkdir()"
[233] 
[234] 
[235] #define ngx_delete_dir(name)     rmdir((const char *) name)
[236] #define ngx_delete_dir_n         "rmdir()"
[237] 
[238] 
[239] #define ngx_dir_access(a)        (a | (a & 0444) >> 2)
[240] 
[241] 
[242] #define ngx_de_name(dir)         ((u_char *) (dir)->de->d_name)
[243] #if (NGX_HAVE_D_NAMLEN)
[244] #define ngx_de_namelen(dir)      (dir)->de->d_namlen
[245] #else
[246] #define ngx_de_namelen(dir)      ngx_strlen((dir)->de->d_name)
[247] #endif
[248] 
[249] static ngx_inline ngx_int_t
[250] ngx_de_info(u_char *name, ngx_dir_t *dir)
[251] {
[252]     dir->type = 0;
[253]     return stat((const char *) name, &dir->info);
[254] }
[255] 
[256] #define ngx_de_info_n            "stat()"
[257] #define ngx_de_link_info(name, dir)  lstat((const char *) name, &(dir)->info)
[258] #define ngx_de_link_info_n       "lstat()"
[259] 
[260] #if (NGX_HAVE_D_TYPE)
[261] 
[262] /*
[263]  * some file systems (e.g. XFS on Linux and CD9660 on FreeBSD)
[264]  * do not set dirent.d_type
[265]  */
[266] 
[267] #define ngx_de_is_dir(dir)                                                   \
[268]     (((dir)->type) ? ((dir)->type == DT_DIR) : (S_ISDIR((dir)->info.st_mode)))
[269] #define ngx_de_is_file(dir)                                                  \
[270]     (((dir)->type) ? ((dir)->type == DT_REG) : (S_ISREG((dir)->info.st_mode)))
[271] #define ngx_de_is_link(dir)                                                  \
[272]     (((dir)->type) ? ((dir)->type == DT_LNK) : (S_ISLNK((dir)->info.st_mode)))
[273] 
[274] #else
[275] 
[276] #define ngx_de_is_dir(dir)       (S_ISDIR((dir)->info.st_mode))
[277] #define ngx_de_is_file(dir)      (S_ISREG((dir)->info.st_mode))
[278] #define ngx_de_is_link(dir)      (S_ISLNK((dir)->info.st_mode))
[279] 
[280] #endif
[281] 
[282] #define ngx_de_access(dir)       (((dir)->info.st_mode) & 0777)
[283] #define ngx_de_size(dir)         (dir)->info.st_size
[284] #define ngx_de_fs_size(dir)                                                  \
[285]     ngx_max((dir)->info.st_size, (dir)->info.st_blocks * 512)
[286] #define ngx_de_mtime(dir)        (dir)->info.st_mtime
[287] 
[288] 
[289] ngx_int_t ngx_open_glob(ngx_glob_t *gl);
[290] #define ngx_open_glob_n          "glob()"
[291] ngx_int_t ngx_read_glob(ngx_glob_t *gl, ngx_str_t *name);
[292] void ngx_close_glob(ngx_glob_t *gl);
[293] 
[294] 
[295] ngx_err_t ngx_trylock_fd(ngx_fd_t fd);
[296] ngx_err_t ngx_lock_fd(ngx_fd_t fd);
[297] ngx_err_t ngx_unlock_fd(ngx_fd_t fd);
[298] 
[299] #define ngx_trylock_fd_n         "fcntl(F_SETLK, F_WRLCK)"
[300] #define ngx_lock_fd_n            "fcntl(F_SETLKW, F_WRLCK)"
[301] #define ngx_unlock_fd_n          "fcntl(F_SETLK, F_UNLCK)"
[302] 
[303] 
[304] #if (NGX_HAVE_F_READAHEAD)
[305] 
[306] #define NGX_HAVE_READ_AHEAD      1
[307] 
[308] #define ngx_read_ahead(fd, n)    fcntl(fd, F_READAHEAD, (int) n)
[309] #define ngx_read_ahead_n         "fcntl(fd, F_READAHEAD)"
[310] 
[311] #elif (NGX_HAVE_POSIX_FADVISE)
[312] 
[313] #define NGX_HAVE_READ_AHEAD      1
[314] 
[315] ngx_int_t ngx_read_ahead(ngx_fd_t fd, size_t n);
[316] #define ngx_read_ahead_n         "posix_fadvise(POSIX_FADV_SEQUENTIAL)"
[317] 
[318] #else
[319] 
[320] #define ngx_read_ahead(fd, n)    0
[321] #define ngx_read_ahead_n         "ngx_read_ahead_n"
[322] 
[323] #endif
[324] 
[325] 
[326] #if (NGX_HAVE_O_DIRECT)
[327] 
[328] ngx_int_t ngx_directio_on(ngx_fd_t fd);
[329] #define ngx_directio_on_n        "fcntl(O_DIRECT)"
[330] 
[331] ngx_int_t ngx_directio_off(ngx_fd_t fd);
[332] #define ngx_directio_off_n       "fcntl(!O_DIRECT)"
[333] 
[334] #elif (NGX_HAVE_F_NOCACHE)
[335] 
[336] #define ngx_directio_on(fd)      fcntl(fd, F_NOCACHE, 1)
[337] #define ngx_directio_on_n        "fcntl(F_NOCACHE, 1)"
[338] 
[339] #elif (NGX_HAVE_DIRECTIO)
[340] 
[341] #define ngx_directio_on(fd)      directio(fd, DIRECTIO_ON)
[342] #define ngx_directio_on_n        "directio(DIRECTIO_ON)"
[343] 
[344] #else
[345] 
[346] #define ngx_directio_on(fd)      0
[347] #define ngx_directio_on_n        "ngx_directio_on_n"
[348] 
[349] #endif
[350] 
[351] size_t ngx_fs_bsize(u_char *name);
[352] off_t ngx_fs_available(u_char *name);
[353] 
[354] 
[355] #if (NGX_HAVE_OPENAT)
[356] 
[357] #define ngx_openat_file(fd, name, mode, create, access)                      \
[358]     openat(fd, (const char *) name, mode|create, access)
[359] 
[360] #define ngx_openat_file_n        "openat()"
[361] 
[362] #define ngx_file_at_info(fd, name, sb, flag)                                 \
[363]     fstatat(fd, (const char *) name, sb, flag)
[364] 
[365] #define ngx_file_at_info_n       "fstatat()"
[366] 
[367] #define NGX_AT_FDCWD             (ngx_fd_t) AT_FDCWD
[368] 
[369] #endif
[370] 
[371] 
[372] #define ngx_stdout               STDOUT_FILENO
[373] #define ngx_stderr               STDERR_FILENO
[374] #define ngx_set_stderr(fd)       dup2(fd, STDERR_FILENO)
[375] #define ngx_set_stderr_n         "dup2(STDERR_FILENO)"
[376] 
[377] 
[378] #if (NGX_HAVE_FILE_AIO)
[379] 
[380] ngx_int_t ngx_file_aio_init(ngx_file_t *file, ngx_pool_t *pool);
[381] ssize_t ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size,
[382]     off_t offset, ngx_pool_t *pool);
[383] 
[384] extern ngx_uint_t  ngx_file_aio;
[385] 
[386] #endif
[387] 
[388] #if (NGX_THREADS)
[389] ssize_t ngx_thread_read(ngx_file_t *file, u_char *buf, size_t size,
[390]     off_t offset, ngx_pool_t *pool);
[391] ssize_t ngx_thread_write_chain_to_file(ngx_file_t *file, ngx_chain_t *cl,
[392]     off_t offset, ngx_pool_t *pool);
[393] #endif
[394] 
[395] 
[396] #endif /* _NGX_FILES_H_INCLUDED_ */
