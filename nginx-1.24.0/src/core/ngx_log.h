[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_LOG_H_INCLUDED_
[9] #define _NGX_LOG_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] #define NGX_LOG_STDERR            0
[17] #define NGX_LOG_EMERG             1
[18] #define NGX_LOG_ALERT             2
[19] #define NGX_LOG_CRIT              3
[20] #define NGX_LOG_ERR               4
[21] #define NGX_LOG_WARN              5
[22] #define NGX_LOG_NOTICE            6
[23] #define NGX_LOG_INFO              7
[24] #define NGX_LOG_DEBUG             8
[25] 
[26] #define NGX_LOG_DEBUG_CORE        0x010
[27] #define NGX_LOG_DEBUG_ALLOC       0x020
[28] #define NGX_LOG_DEBUG_MUTEX       0x040
[29] #define NGX_LOG_DEBUG_EVENT       0x080
[30] #define NGX_LOG_DEBUG_HTTP        0x100
[31] #define NGX_LOG_DEBUG_MAIL        0x200
[32] #define NGX_LOG_DEBUG_STREAM      0x400
[33] 
[34] /*
[35]  * do not forget to update debug_levels[] in src/core/ngx_log.c
[36]  * after the adding a new debug level
[37]  */
[38] 
[39] #define NGX_LOG_DEBUG_FIRST       NGX_LOG_DEBUG_CORE
[40] #define NGX_LOG_DEBUG_LAST        NGX_LOG_DEBUG_STREAM
[41] #define NGX_LOG_DEBUG_CONNECTION  0x80000000
[42] #define NGX_LOG_DEBUG_ALL         0x7ffffff0
[43] 
[44] 
[45] typedef u_char *(*ngx_log_handler_pt) (ngx_log_t *log, u_char *buf, size_t len);
[46] typedef void (*ngx_log_writer_pt) (ngx_log_t *log, ngx_uint_t level,
[47]     u_char *buf, size_t len);
[48] 
[49] 
[50] struct ngx_log_s {
[51]     ngx_uint_t           log_level;
[52]     ngx_open_file_t     *file;
[53] 
[54]     ngx_atomic_uint_t    connection;
[55] 
[56]     time_t               disk_full_time;
[57] 
[58]     ngx_log_handler_pt   handler;
[59]     void                *data;
[60] 
[61]     ngx_log_writer_pt    writer;
[62]     void                *wdata;
[63] 
[64]     /*
[65]      * we declare "action" as "char *" because the actions are usually
[66]      * the static strings and in the "u_char *" case we have to override
[67]      * their types all the time
[68]      */
[69] 
[70]     char                *action;
[71] 
[72]     ngx_log_t           *next;
[73] };
[74] 
[75] 
[76] #define NGX_MAX_ERROR_STR   2048
[77] 
[78] 
[79] /*********************************/
[80] 
[81] #if (NGX_HAVE_C99_VARIADIC_MACROS)
[82] 
[83] #define NGX_HAVE_VARIADIC_MACROS  1
[84] 
[85] #define ngx_log_error(level, log, ...)                                        \
[86]     if ((log)->log_level >= level) ngx_log_error_core(level, log, __VA_ARGS__)
[87] 
[88] void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[89]     const char *fmt, ...);
[90] 
[91] #define ngx_log_debug(level, log, ...)                                        \
[92]     if ((log)->log_level & level)                                             \
[93]         ngx_log_error_core(NGX_LOG_DEBUG, log, __VA_ARGS__)
[94] 
[95] /*********************************/
[96] 
[97] #elif (NGX_HAVE_GCC_VARIADIC_MACROS)
[98] 
[99] #define NGX_HAVE_VARIADIC_MACROS  1
[100] 
[101] #define ngx_log_error(level, log, args...)                                    \
[102]     if ((log)->log_level >= level) ngx_log_error_core(level, log, args)
[103] 
[104] void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[105]     const char *fmt, ...);
[106] 
[107] #define ngx_log_debug(level, log, args...)                                    \
[108]     if ((log)->log_level & level)                                             \
[109]         ngx_log_error_core(NGX_LOG_DEBUG, log, args)
[110] 
[111] /*********************************/
[112] 
[113] #else /* no variadic macros */
[114] 
[115] #define NGX_HAVE_VARIADIC_MACROS  0
[116] 
[117] void ngx_cdecl ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[118]     const char *fmt, ...);
[119] void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
[120]     const char *fmt, va_list args);
[121] void ngx_cdecl ngx_log_debug_core(ngx_log_t *log, ngx_err_t err,
[122]     const char *fmt, ...);
[123] 
[124] 
[125] #endif /* variadic macros */
[126] 
[127] 
[128] /*********************************/
[129] 
[130] #if (NGX_DEBUG)
[131] 
[132] #if (NGX_HAVE_VARIADIC_MACROS)
[133] 
[134] #define ngx_log_debug0(level, log, err, fmt)                                  \
[135]         ngx_log_debug(level, log, err, fmt)
[136] 
[137] #define ngx_log_debug1(level, log, err, fmt, arg1)                            \
[138]         ngx_log_debug(level, log, err, fmt, arg1)
[139] 
[140] #define ngx_log_debug2(level, log, err, fmt, arg1, arg2)                      \
[141]         ngx_log_debug(level, log, err, fmt, arg1, arg2)
[142] 
[143] #define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
[144]         ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3)
[145] 
[146] #define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
[147]         ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4)
[148] 
[149] #define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
[150]         ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
[151] 
[152] #define ngx_log_debug6(level, log, err, fmt,                                  \
[153]                        arg1, arg2, arg3, arg4, arg5, arg6)                    \
[154]         ngx_log_debug(level, log, err, fmt,                                   \
[155]                        arg1, arg2, arg3, arg4, arg5, arg6)
[156] 
[157] #define ngx_log_debug7(level, log, err, fmt,                                  \
[158]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
[159]         ngx_log_debug(level, log, err, fmt,                                   \
[160]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7)
[161] 
[162] #define ngx_log_debug8(level, log, err, fmt,                                  \
[163]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
[164]         ngx_log_debug(level, log, err, fmt,                                   \
[165]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
[166] 
[167] 
[168] #else /* no variadic macros */
[169] 
[170] #define ngx_log_debug0(level, log, err, fmt)                                  \
[171]     if ((log)->log_level & level)                                             \
[172]         ngx_log_debug_core(log, err, fmt)
[173] 
[174] #define ngx_log_debug1(level, log, err, fmt, arg1)                            \
[175]     if ((log)->log_level & level)                                             \
[176]         ngx_log_debug_core(log, err, fmt, arg1)
[177] 
[178] #define ngx_log_debug2(level, log, err, fmt, arg1, arg2)                      \
[179]     if ((log)->log_level & level)                                             \
[180]         ngx_log_debug_core(log, err, fmt, arg1, arg2)
[181] 
[182] #define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
[183]     if ((log)->log_level & level)                                             \
[184]         ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3)
[185] 
[186] #define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
[187]     if ((log)->log_level & level)                                             \
[188]         ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4)
[189] 
[190] #define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
[191]     if ((log)->log_level & level)                                             \
[192]         ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5)
[193] 
[194] #define ngx_log_debug6(level, log, err, fmt,                                  \
[195]                        arg1, arg2, arg3, arg4, arg5, arg6)                    \
[196]     if ((log)->log_level & level)                                             \
[197]         ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
[198] 
[199] #define ngx_log_debug7(level, log, err, fmt,                                  \
[200]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
[201]     if ((log)->log_level & level)                                             \
[202]         ngx_log_debug_core(log, err, fmt,                                     \
[203]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7)
[204] 
[205] #define ngx_log_debug8(level, log, err, fmt,                                  \
[206]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
[207]     if ((log)->log_level & level)                                             \
[208]         ngx_log_debug_core(log, err, fmt,                                     \
[209]                        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
[210] 
[211] #endif
[212] 
[213] #else /* !NGX_DEBUG */
[214] 
[215] #define ngx_log_debug0(level, log, err, fmt)
[216] #define ngx_log_debug1(level, log, err, fmt, arg1)
[217] #define ngx_log_debug2(level, log, err, fmt, arg1, arg2)
[218] #define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
[219] #define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
[220] #define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
[221] #define ngx_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
[222] #define ngx_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
[223]                        arg6, arg7)
[224] #define ngx_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
[225]                        arg6, arg7, arg8)
[226] 
[227] #endif
[228] 
[229] /*********************************/
[230] 
[231] ngx_log_t *ngx_log_init(u_char *prefix, u_char *error_log);
[232] void ngx_cdecl ngx_log_abort(ngx_err_t err, const char *fmt, ...);
[233] void ngx_cdecl ngx_log_stderr(ngx_err_t err, const char *fmt, ...);
[234] u_char *ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err);
[235] ngx_int_t ngx_log_open_default(ngx_cycle_t *cycle);
[236] ngx_int_t ngx_log_redirect_stderr(ngx_cycle_t *cycle);
[237] ngx_log_t *ngx_log_get_file_log(ngx_log_t *head);
[238] char *ngx_log_set_log(ngx_conf_t *cf, ngx_log_t **head);
[239] 
[240] 
[241] /*
[242]  * ngx_write_stderr() cannot be implemented as macro, since
[243]  * MSVC does not allow to use #ifdef inside macro parameters.
[244]  *
[245]  * ngx_write_fd() is used instead of ngx_write_console(), since
[246]  * CharToOemBuff() inside ngx_write_console() cannot be used with
[247]  * read only buffer as destination and CharToOemBuff() is not needed
[248]  * for ngx_write_stderr() anyway.
[249]  */
[250] static ngx_inline void
[251] ngx_write_stderr(char *text)
[252] {
[253]     (void) ngx_write_fd(ngx_stderr, text, ngx_strlen(text));
[254] }
[255] 
[256] 
[257] static ngx_inline void
[258] ngx_write_stdout(char *text)
[259] {
[260]     (void) ngx_write_fd(ngx_stdout, text, ngx_strlen(text));
[261] }
[262] 
[263] 
[264] extern ngx_module_t  ngx_errlog_module;
[265] extern ngx_uint_t    ngx_use_stderr;
[266] 
[267] 
[268] #endif /* _NGX_LOG_H_INCLUDED_ */
