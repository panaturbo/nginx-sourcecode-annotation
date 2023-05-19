[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Maxim Dounin
[5]  * Copyright (C) Nginx, Inc.
[6]  */
[7] 
[8] 
[9] #ifndef _NGX_MODULE_H_INCLUDED_
[10] #define _NGX_MODULE_H_INCLUDED_
[11] 
[12] 
[13] #include <ngx_config.h>
[14] #include <ngx_core.h>
[15] #include <nginx.h>
[16] 
[17] 
[18] #define NGX_MODULE_UNSET_INDEX  (ngx_uint_t) -1
[19] 
[20] 
[21] #define NGX_MODULE_SIGNATURE_0                                                \
[22]     ngx_value(NGX_PTR_SIZE) ","                                               \
[23]     ngx_value(NGX_SIG_ATOMIC_T_SIZE) ","                                      \
[24]     ngx_value(NGX_TIME_T_SIZE) ","
[25] 
[26] #if (NGX_HAVE_KQUEUE)
[27] #define NGX_MODULE_SIGNATURE_1   "1"
[28] #else
[29] #define NGX_MODULE_SIGNATURE_1   "0"
[30] #endif
[31] 
[32] #if (NGX_HAVE_IOCP)
[33] #define NGX_MODULE_SIGNATURE_2   "1"
[34] #else
[35] #define NGX_MODULE_SIGNATURE_2   "0"
[36] #endif
[37] 
[38] #if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
[39] #define NGX_MODULE_SIGNATURE_3   "1"
[40] #else
[41] #define NGX_MODULE_SIGNATURE_3   "0"
[42] #endif
[43] 
[44] #if (NGX_HAVE_SENDFILE_NODISKIO || NGX_COMPAT)
[45] #define NGX_MODULE_SIGNATURE_4   "1"
[46] #else
[47] #define NGX_MODULE_SIGNATURE_4   "0"
[48] #endif
[49] 
[50] #if (NGX_HAVE_EVENTFD)
[51] #define NGX_MODULE_SIGNATURE_5   "1"
[52] #else
[53] #define NGX_MODULE_SIGNATURE_5   "0"
[54] #endif
[55] 
[56] #if (NGX_HAVE_EPOLL)
[57] #define NGX_MODULE_SIGNATURE_6   "1"
[58] #else
[59] #define NGX_MODULE_SIGNATURE_6   "0"
[60] #endif
[61] 
[62] #if (NGX_HAVE_KEEPALIVE_TUNABLE)
[63] #define NGX_MODULE_SIGNATURE_7   "1"
[64] #else
[65] #define NGX_MODULE_SIGNATURE_7   "0"
[66] #endif
[67] 
[68] #if (NGX_HAVE_INET6)
[69] #define NGX_MODULE_SIGNATURE_8   "1"
[70] #else
[71] #define NGX_MODULE_SIGNATURE_8   "0"
[72] #endif
[73] 
[74] #define NGX_MODULE_SIGNATURE_9   "1"
[75] #define NGX_MODULE_SIGNATURE_10  "1"
[76] 
[77] #if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
[78] #define NGX_MODULE_SIGNATURE_11  "1"
[79] #else
[80] #define NGX_MODULE_SIGNATURE_11  "0"
[81] #endif
[82] 
[83] #define NGX_MODULE_SIGNATURE_12  "1"
[84] 
[85] #if (NGX_HAVE_SETFIB)
[86] #define NGX_MODULE_SIGNATURE_13  "1"
[87] #else
[88] #define NGX_MODULE_SIGNATURE_13  "0"
[89] #endif
[90] 
[91] #if (NGX_HAVE_TCP_FASTOPEN)
[92] #define NGX_MODULE_SIGNATURE_14  "1"
[93] #else
[94] #define NGX_MODULE_SIGNATURE_14  "0"
[95] #endif
[96] 
[97] #if (NGX_HAVE_UNIX_DOMAIN)
[98] #define NGX_MODULE_SIGNATURE_15  "1"
[99] #else
[100] #define NGX_MODULE_SIGNATURE_15  "0"
[101] #endif
[102] 
[103] #if (NGX_HAVE_VARIADIC_MACROS)
[104] #define NGX_MODULE_SIGNATURE_16  "1"
[105] #else
[106] #define NGX_MODULE_SIGNATURE_16  "0"
[107] #endif
[108] 
[109] #define NGX_MODULE_SIGNATURE_17  "0"
[110] #define NGX_MODULE_SIGNATURE_18  "0"
[111] 
[112] #if (NGX_HAVE_OPENAT)
[113] #define NGX_MODULE_SIGNATURE_19  "1"
[114] #else
[115] #define NGX_MODULE_SIGNATURE_19  "0"
[116] #endif
[117] 
[118] #if (NGX_HAVE_ATOMIC_OPS)
[119] #define NGX_MODULE_SIGNATURE_20  "1"
[120] #else
[121] #define NGX_MODULE_SIGNATURE_20  "0"
[122] #endif
[123] 
[124] #if (NGX_HAVE_POSIX_SEM)
[125] #define NGX_MODULE_SIGNATURE_21  "1"
[126] #else
[127] #define NGX_MODULE_SIGNATURE_21  "0"
[128] #endif
[129] 
[130] #if (NGX_THREADS || NGX_COMPAT)
[131] #define NGX_MODULE_SIGNATURE_22  "1"
[132] #else
[133] #define NGX_MODULE_SIGNATURE_22  "0"
[134] #endif
[135] 
[136] #if (NGX_PCRE)
[137] #define NGX_MODULE_SIGNATURE_23  "1"
[138] #else
[139] #define NGX_MODULE_SIGNATURE_23  "0"
[140] #endif
[141] 
[142] #if (NGX_HTTP_SSL || NGX_COMPAT)
[143] #define NGX_MODULE_SIGNATURE_24  "1"
[144] #else
[145] #define NGX_MODULE_SIGNATURE_24  "0"
[146] #endif
[147] 
[148] #define NGX_MODULE_SIGNATURE_25  "1"
[149] 
[150] #if (NGX_HTTP_GZIP)
[151] #define NGX_MODULE_SIGNATURE_26  "1"
[152] #else
[153] #define NGX_MODULE_SIGNATURE_26  "0"
[154] #endif
[155] 
[156] #define NGX_MODULE_SIGNATURE_27  "1"
[157] 
[158] #if (NGX_HTTP_X_FORWARDED_FOR)
[159] #define NGX_MODULE_SIGNATURE_28  "1"
[160] #else
[161] #define NGX_MODULE_SIGNATURE_28  "0"
[162] #endif
[163] 
[164] #if (NGX_HTTP_REALIP)
[165] #define NGX_MODULE_SIGNATURE_29  "1"
[166] #else
[167] #define NGX_MODULE_SIGNATURE_29  "0"
[168] #endif
[169] 
[170] #if (NGX_HTTP_HEADERS)
[171] #define NGX_MODULE_SIGNATURE_30  "1"
[172] #else
[173] #define NGX_MODULE_SIGNATURE_30  "0"
[174] #endif
[175] 
[176] #if (NGX_HTTP_DAV)
[177] #define NGX_MODULE_SIGNATURE_31  "1"
[178] #else
[179] #define NGX_MODULE_SIGNATURE_31  "0"
[180] #endif
[181] 
[182] #if (NGX_HTTP_CACHE)
[183] #define NGX_MODULE_SIGNATURE_32  "1"
[184] #else
[185] #define NGX_MODULE_SIGNATURE_32  "0"
[186] #endif
[187] 
[188] #if (NGX_HTTP_UPSTREAM_ZONE)
[189] #define NGX_MODULE_SIGNATURE_33  "1"
[190] #else
[191] #define NGX_MODULE_SIGNATURE_33  "0"
[192] #endif
[193] 
[194] #if (NGX_COMPAT)
[195] #define NGX_MODULE_SIGNATURE_34  "1"
[196] #else
[197] #define NGX_MODULE_SIGNATURE_34  "0"
[198] #endif
[199] 
[200] #define NGX_MODULE_SIGNATURE                                                  \
[201]     NGX_MODULE_SIGNATURE_0 NGX_MODULE_SIGNATURE_1 NGX_MODULE_SIGNATURE_2      \
[202]     NGX_MODULE_SIGNATURE_3 NGX_MODULE_SIGNATURE_4 NGX_MODULE_SIGNATURE_5      \
[203]     NGX_MODULE_SIGNATURE_6 NGX_MODULE_SIGNATURE_7 NGX_MODULE_SIGNATURE_8      \
[204]     NGX_MODULE_SIGNATURE_9 NGX_MODULE_SIGNATURE_10 NGX_MODULE_SIGNATURE_11    \
[205]     NGX_MODULE_SIGNATURE_12 NGX_MODULE_SIGNATURE_13 NGX_MODULE_SIGNATURE_14   \
[206]     NGX_MODULE_SIGNATURE_15 NGX_MODULE_SIGNATURE_16 NGX_MODULE_SIGNATURE_17   \
[207]     NGX_MODULE_SIGNATURE_18 NGX_MODULE_SIGNATURE_19 NGX_MODULE_SIGNATURE_20   \
[208]     NGX_MODULE_SIGNATURE_21 NGX_MODULE_SIGNATURE_22 NGX_MODULE_SIGNATURE_23   \
[209]     NGX_MODULE_SIGNATURE_24 NGX_MODULE_SIGNATURE_25 NGX_MODULE_SIGNATURE_26   \
[210]     NGX_MODULE_SIGNATURE_27 NGX_MODULE_SIGNATURE_28 NGX_MODULE_SIGNATURE_29   \
[211]     NGX_MODULE_SIGNATURE_30 NGX_MODULE_SIGNATURE_31 NGX_MODULE_SIGNATURE_32   \
[212]     NGX_MODULE_SIGNATURE_33 NGX_MODULE_SIGNATURE_34
[213] 
[214] 
[215] #define NGX_MODULE_V1                                                         \
[216]     NGX_MODULE_UNSET_INDEX, NGX_MODULE_UNSET_INDEX,                           \
[217]     NULL, 0, 0, nginx_version, NGX_MODULE_SIGNATURE
[218] 
[219] #define NGX_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0
[220] 
[221] 
[222] struct ngx_module_s {
[223]     ngx_uint_t            ctx_index;
[224]     ngx_uint_t            index;
[225] 
[226]     char                 *name;
[227] 
[228]     ngx_uint_t            spare0;
[229]     ngx_uint_t            spare1;
[230] 
[231]     ngx_uint_t            version;
[232]     const char           *signature;
[233] 
[234]     void                 *ctx;
[235]     ngx_command_t        *commands;
[236]     ngx_uint_t            type;
[237] 
[238]     ngx_int_t           (*init_master)(ngx_log_t *log);
[239] 
[240]     ngx_int_t           (*init_module)(ngx_cycle_t *cycle);
[241] 
[242]     ngx_int_t           (*init_process)(ngx_cycle_t *cycle);
[243]     ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
[244]     void                (*exit_thread)(ngx_cycle_t *cycle);
[245]     void                (*exit_process)(ngx_cycle_t *cycle);
[246] 
[247]     void                (*exit_master)(ngx_cycle_t *cycle);
[248] 
[249]     uintptr_t             spare_hook0;
[250]     uintptr_t             spare_hook1;
[251]     uintptr_t             spare_hook2;
[252]     uintptr_t             spare_hook3;
[253]     uintptr_t             spare_hook4;
[254]     uintptr_t             spare_hook5;
[255]     uintptr_t             spare_hook6;
[256]     uintptr_t             spare_hook7;
[257] };
[258] 
[259] 
[260] typedef struct {
[261]     ngx_str_t             name;
[262]     void               *(*create_conf)(ngx_cycle_t *cycle);
[263]     char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
[264] } ngx_core_module_t;
[265] 
[266] 
[267] ngx_int_t ngx_preinit_modules(void);
[268] ngx_int_t ngx_cycle_modules(ngx_cycle_t *cycle);
[269] ngx_int_t ngx_init_modules(ngx_cycle_t *cycle);
[270] ngx_int_t ngx_count_modules(ngx_cycle_t *cycle, ngx_uint_t type);
[271] 
[272] 
[273] ngx_int_t ngx_add_module(ngx_conf_t *cf, ngx_str_t *file,
[274]     ngx_module_t *module, char **order);
[275] 
[276] 
[277] extern ngx_module_t  *ngx_modules[];
[278] extern ngx_uint_t     ngx_max_module;
[279] 
[280] extern char          *ngx_module_names[];
[281] 
[282] 
[283] #endif /* _NGX_MODULE_H_INCLUDED_ */
