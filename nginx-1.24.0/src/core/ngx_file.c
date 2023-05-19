[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] 
[11] 
[12] static ngx_int_t ngx_test_full_name(ngx_str_t *name);
[13] 
[14] 
[15] static ngx_atomic_t   temp_number = 0;
[16] ngx_atomic_t         *ngx_temp_number = &temp_number;
[17] ngx_atomic_int_t      ngx_random_number = 123456;
[18] 
[19] 
[20] ngx_int_t
[21] ngx_get_full_name(ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *name)
[22] {
[23]     size_t      len;
[24]     u_char     *p, *n;
[25]     ngx_int_t   rc;
[26] 
[27]     rc = ngx_test_full_name(name);
[28] 
[29]     if (rc == NGX_OK) {
[30]         return rc;
[31]     }
[32] 
[33]     len = prefix->len;
[34] 
[35] #if (NGX_WIN32)
[36] 
[37]     if (rc == 2) {
[38]         len = rc;
[39]     }
[40] 
[41] #endif
[42] 
[43]     n = ngx_pnalloc(pool, len + name->len + 1);
[44]     if (n == NULL) {
[45]         return NGX_ERROR;
[46]     }
[47] 
[48]     p = ngx_cpymem(n, prefix->data, len);
[49]     ngx_cpystrn(p, name->data, name->len + 1);
[50] 
[51]     name->len += len;
[52]     name->data = n;
[53] 
[54]     return NGX_OK;
[55] }
[56] 
[57] 
[58] static ngx_int_t
[59] ngx_test_full_name(ngx_str_t *name)
[60] {
[61] #if (NGX_WIN32)
[62]     u_char  c0, c1;
[63] 
[64]     c0 = name->data[0];
[65] 
[66]     if (name->len < 2) {
[67]         if (c0 == '/') {
[68]             return 2;
[69]         }
[70] 
[71]         return NGX_DECLINED;
[72]     }
[73] 
[74]     c1 = name->data[1];
[75] 
[76]     if (c1 == ':') {
[77]         c0 |= 0x20;
[78] 
[79]         if ((c0 >= 'a' && c0 <= 'z')) {
[80]             return NGX_OK;
[81]         }
[82] 
[83]         return NGX_DECLINED;
[84]     }
[85] 
[86]     if (c1 == '/') {
[87]         return NGX_OK;
[88]     }
[89] 
[90]     if (c0 == '/') {
[91]         return 2;
[92]     }
[93] 
[94]     return NGX_DECLINED;
[95] 
[96] #else
[97] 
[98]     if (name->data[0] == '/') {
[99]         return NGX_OK;
[100]     }
[101] 
[102]     return NGX_DECLINED;
[103] 
[104] #endif
[105] }
[106] 
[107] 
[108] ssize_t
[109] ngx_write_chain_to_temp_file(ngx_temp_file_t *tf, ngx_chain_t *chain)
[110] {
[111]     ngx_int_t  rc;
[112] 
[113]     if (tf->file.fd == NGX_INVALID_FILE) {
[114]         rc = ngx_create_temp_file(&tf->file, tf->path, tf->pool,
[115]                                   tf->persistent, tf->clean, tf->access);
[116] 
[117]         if (rc != NGX_OK) {
[118]             return rc;
[119]         }
[120] 
[121]         if (tf->log_level) {
[122]             ngx_log_error(tf->log_level, tf->file.log, 0, "%s %V",
[123]                           tf->warn, &tf->file.name);
[124]         }
[125]     }
[126] 
[127] #if (NGX_THREADS && NGX_HAVE_PWRITEV)
[128] 
[129]     if (tf->thread_write) {
[130]         return ngx_thread_write_chain_to_file(&tf->file, chain, tf->offset,
[131]                                               tf->pool);
[132]     }
[133] 
[134] #endif
[135] 
[136]     return ngx_write_chain_to_file(&tf->file, chain, tf->offset, tf->pool);
[137] }
[138] 
[139] 
[140] ngx_int_t
[141] ngx_create_temp_file(ngx_file_t *file, ngx_path_t *path, ngx_pool_t *pool,
[142]     ngx_uint_t persistent, ngx_uint_t clean, ngx_uint_t access)
[143] {
[144]     size_t                    levels;
[145]     u_char                   *p;
[146]     uint32_t                  n;
[147]     ngx_err_t                 err;
[148]     ngx_str_t                 name;
[149]     ngx_uint_t                prefix;
[150]     ngx_pool_cleanup_t       *cln;
[151]     ngx_pool_cleanup_file_t  *clnf;
[152] 
[153]     if (file->name.len) {
[154]         name = file->name;
[155]         levels = 0;
[156]         prefix = 1;
[157] 
[158]     } else {
[159]         name = path->name;
[160]         levels = path->len;
[161]         prefix = 0;
[162]     }
[163] 
[164]     file->name.len = name.len + 1 + levels + 10;
[165] 
[166]     file->name.data = ngx_pnalloc(pool, file->name.len + 1);
[167]     if (file->name.data == NULL) {
[168]         return NGX_ERROR;
[169]     }
[170] 
[171] #if 0
[172]     for (i = 0; i < file->name.len; i++) {
[173]         file->name.data[i] = 'X';
[174]     }
[175] #endif
[176] 
[177]     p = ngx_cpymem(file->name.data, name.data, name.len);
[178] 
[179]     if (prefix) {
[180]         *p = '.';
[181]     }
[182] 
[183]     p += 1 + levels;
[184] 
[185]     n = (uint32_t) ngx_next_temp_number(0);
[186] 
[187]     cln = ngx_pool_cleanup_add(pool, sizeof(ngx_pool_cleanup_file_t));
[188]     if (cln == NULL) {
[189]         return NGX_ERROR;
[190]     }
[191] 
[192]     for ( ;; ) {
[193]         (void) ngx_sprintf(p, "%010uD%Z", n);
[194] 
[195]         if (!prefix) {
[196]             ngx_create_hashed_filename(path, file->name.data, file->name.len);
[197]         }
[198] 
[199]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
[200]                        "hashed path: %s", file->name.data);
[201] 
[202]         file->fd = ngx_open_tempfile(file->name.data, persistent, access);
[203] 
[204]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
[205]                        "temp fd:%d", file->fd);
[206] 
[207]         if (file->fd != NGX_INVALID_FILE) {
[208] 
[209]             cln->handler = clean ? ngx_pool_delete_file : ngx_pool_cleanup_file;
[210]             clnf = cln->data;
[211] 
[212]             clnf->fd = file->fd;
[213]             clnf->name = file->name.data;
[214]             clnf->log = pool->log;
[215] 
[216]             return NGX_OK;
[217]         }
[218] 
[219]         err = ngx_errno;
[220] 
[221]         if (err == NGX_EEXIST_FILE) {
[222]             n = (uint32_t) ngx_next_temp_number(1);
[223]             continue;
[224]         }
[225] 
[226]         if ((path->level[0] == 0) || (err != NGX_ENOPATH)) {
[227]             ngx_log_error(NGX_LOG_CRIT, file->log, err,
[228]                           ngx_open_tempfile_n " \"%s\" failed",
[229]                           file->name.data);
[230]             return NGX_ERROR;
[231]         }
[232] 
[233]         if (ngx_create_path(file, path) == NGX_ERROR) {
[234]             return NGX_ERROR;
[235]         }
[236]     }
[237] }
[238] 
[239] 
[240] void
[241] ngx_create_hashed_filename(ngx_path_t *path, u_char *file, size_t len)
[242] {
[243]     size_t      i, level;
[244]     ngx_uint_t  n;
[245] 
[246]     i = path->name.len + 1;
[247] 
[248]     file[path->name.len + path->len]  = '/';
[249] 
[250]     for (n = 0; n < NGX_MAX_PATH_LEVEL; n++) {
[251]         level = path->level[n];
[252] 
[253]         if (level == 0) {
[254]             break;
[255]         }
[256] 
[257]         len -= level;
[258]         file[i - 1] = '/';
[259]         ngx_memcpy(&file[i], &file[len], level);
[260]         i += level + 1;
[261]     }
[262] }
[263] 
[264] 
[265] ngx_int_t
[266] ngx_create_path(ngx_file_t *file, ngx_path_t *path)
[267] {
[268]     size_t      pos;
[269]     ngx_err_t   err;
[270]     ngx_uint_t  i;
[271] 
[272]     pos = path->name.len;
[273] 
[274]     for (i = 0; i < NGX_MAX_PATH_LEVEL; i++) {
[275]         if (path->level[i] == 0) {
[276]             break;
[277]         }
[278] 
[279]         pos += path->level[i] + 1;
[280] 
[281]         file->name.data[pos] = '\0';
[282] 
[283]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
[284]                        "temp file: \"%s\"", file->name.data);
[285] 
[286]         if (ngx_create_dir(file->name.data, 0700) == NGX_FILE_ERROR) {
[287]             err = ngx_errno;
[288]             if (err != NGX_EEXIST) {
[289]                 ngx_log_error(NGX_LOG_CRIT, file->log, err,
[290]                               ngx_create_dir_n " \"%s\" failed",
[291]                               file->name.data);
[292]                 return NGX_ERROR;
[293]             }
[294]         }
[295] 
[296]         file->name.data[pos] = '/';
[297]     }
[298] 
[299]     return NGX_OK;
[300] }
[301] 
[302] 
[303] ngx_err_t
[304] ngx_create_full_path(u_char *dir, ngx_uint_t access)
[305] {
[306]     u_char     *p, ch;
[307]     ngx_err_t   err;
[308] 
[309]     err = 0;
[310] 
[311] #if (NGX_WIN32)
[312]     p = dir + 3;
[313] #else
[314]     p = dir + 1;
[315] #endif
[316] 
[317]     for ( /* void */ ; *p; p++) {
[318]         ch = *p;
[319] 
[320]         if (ch != '/') {
[321]             continue;
[322]         }
[323] 
[324]         *p = '\0';
[325] 
[326]         if (ngx_create_dir(dir, access) == NGX_FILE_ERROR) {
[327]             err = ngx_errno;
[328] 
[329]             switch (err) {
[330]             case NGX_EEXIST:
[331]                 err = 0;
[332]             case NGX_EACCES:
[333]                 break;
[334] 
[335]             default:
[336]                 return err;
[337]             }
[338]         }
[339] 
[340]         *p = '/';
[341]     }
[342] 
[343]     return err;
[344] }
[345] 
[346] 
[347] ngx_atomic_uint_t
[348] ngx_next_temp_number(ngx_uint_t collision)
[349] {
[350]     ngx_atomic_uint_t  n, add;
[351] 
[352]     add = collision ? ngx_random_number : 1;
[353] 
[354]     n = ngx_atomic_fetch_add(ngx_temp_number, add);
[355] 
[356]     return n + add;
[357] }
[358] 
[359] 
[360] char *
[361] ngx_conf_set_path_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[362] {
[363]     char  *p = conf;
[364] 
[365]     ssize_t      level;
[366]     ngx_str_t   *value;
[367]     ngx_uint_t   i, n;
[368]     ngx_path_t  *path, **slot;
[369] 
[370]     slot = (ngx_path_t **) (p + cmd->offset);
[371] 
[372]     if (*slot) {
[373]         return "is duplicate";
[374]     }
[375] 
[376]     path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
[377]     if (path == NULL) {
[378]         return NGX_CONF_ERROR;
[379]     }
[380] 
[381]     value = cf->args->elts;
[382] 
[383]     path->name = value[1];
[384] 
[385]     if (path->name.data[path->name.len - 1] == '/') {
[386]         path->name.len--;
[387]     }
[388] 
[389]     if (ngx_conf_full_name(cf->cycle, &path->name, 0) != NGX_OK) {
[390]         return NGX_CONF_ERROR;
[391]     }
[392] 
[393]     path->conf_file = cf->conf_file->file.name.data;
[394]     path->line = cf->conf_file->line;
[395] 
[396]     for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
[397]         level = ngx_atoi(value[n].data, value[n].len);
[398]         if (level == NGX_ERROR || level == 0) {
[399]             return "invalid value";
[400]         }
[401] 
[402]         path->level[i] = level;
[403]         path->len += level + 1;
[404]     }
[405] 
[406]     if (path->len > 10 + i) {
[407]         return "invalid value";
[408]     }
[409] 
[410]     *slot = path;
[411] 
[412]     if (ngx_add_path(cf, slot) == NGX_ERROR) {
[413]         return NGX_CONF_ERROR;
[414]     }
[415] 
[416]     return NGX_CONF_OK;
[417] }
[418] 
[419] 
[420] char *
[421] ngx_conf_merge_path_value(ngx_conf_t *cf, ngx_path_t **path, ngx_path_t *prev,
[422]     ngx_path_init_t *init)
[423] {
[424]     ngx_uint_t  i;
[425] 
[426]     if (*path) {
[427]         return NGX_CONF_OK;
[428]     }
[429] 
[430]     if (prev) {
[431]         *path = prev;
[432]         return NGX_CONF_OK;
[433]     }
[434] 
[435]     *path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
[436]     if (*path == NULL) {
[437]         return NGX_CONF_ERROR;
[438]     }
[439] 
[440]     (*path)->name = init->name;
[441] 
[442]     if (ngx_conf_full_name(cf->cycle, &(*path)->name, 0) != NGX_OK) {
[443]         return NGX_CONF_ERROR;
[444]     }
[445] 
[446]     for (i = 0; i < NGX_MAX_PATH_LEVEL; i++) {
[447]         (*path)->level[i] = init->level[i];
[448]         (*path)->len += init->level[i] + (init->level[i] ? 1 : 0);
[449]     }
[450] 
[451]     if (ngx_add_path(cf, path) != NGX_OK) {
[452]         return NGX_CONF_ERROR;
[453]     }
[454] 
[455]     return NGX_CONF_OK;
[456] }
[457] 
[458] 
[459] char *
[460] ngx_conf_set_access_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[461] {
[462]     char  *confp = conf;
[463] 
[464]     u_char      *p;
[465]     ngx_str_t   *value;
[466]     ngx_uint_t   i, right, shift, *access, user;
[467] 
[468]     access = (ngx_uint_t *) (confp + cmd->offset);
[469] 
[470]     if (*access != NGX_CONF_UNSET_UINT) {
[471]         return "is duplicate";
[472]     }
[473] 
[474]     value = cf->args->elts;
[475] 
[476]     *access = 0;
[477]     user = 0600;
[478] 
[479]     for (i = 1; i < cf->args->nelts; i++) {
[480] 
[481]         p = value[i].data;
[482] 
[483]         if (ngx_strncmp(p, "user:", sizeof("user:") - 1) == 0) {
[484]             shift = 6;
[485]             p += sizeof("user:") - 1;
[486]             user = 0;
[487] 
[488]         } else if (ngx_strncmp(p, "group:", sizeof("group:") - 1) == 0) {
[489]             shift = 3;
[490]             p += sizeof("group:") - 1;
[491] 
[492]         } else if (ngx_strncmp(p, "all:", sizeof("all:") - 1) == 0) {
[493]             shift = 0;
[494]             p += sizeof("all:") - 1;
[495] 
[496]         } else {
[497]             goto invalid;
[498]         }
[499] 
[500]         if (ngx_strcmp(p, "rw") == 0) {
[501]             right = 6;
[502] 
[503]         } else if (ngx_strcmp(p, "r") == 0) {
[504]             right = 4;
[505] 
[506]         } else {
[507]             goto invalid;
[508]         }
[509] 
[510]         *access |= right << shift;
[511]     }
[512] 
[513]     *access |= user;
[514] 
[515]     return NGX_CONF_OK;
[516] 
[517] invalid:
[518] 
[519]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[i]);
[520] 
[521]     return NGX_CONF_ERROR;
[522] }
[523] 
[524] 
[525] ngx_int_t
[526] ngx_add_path(ngx_conf_t *cf, ngx_path_t **slot)
[527] {
[528]     ngx_uint_t   i, n;
[529]     ngx_path_t  *path, **p;
[530] 
[531]     path = *slot;
[532] 
[533]     p = cf->cycle->paths.elts;
[534]     for (i = 0; i < cf->cycle->paths.nelts; i++) {
[535]         if (p[i]->name.len == path->name.len
[536]             && ngx_strcmp(p[i]->name.data, path->name.data) == 0)
[537]         {
[538]             if (p[i]->data != path->data) {
[539]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[540]                                    "the same path name \"%V\" "
[541]                                    "used in %s:%ui and",
[542]                                    &p[i]->name, p[i]->conf_file, p[i]->line);
[543]                 return NGX_ERROR;
[544]             }
[545] 
[546]             for (n = 0; n < NGX_MAX_PATH_LEVEL; n++) {
[547]                 if (p[i]->level[n] != path->level[n]) {
[548]                     if (path->conf_file == NULL) {
[549]                         if (p[i]->conf_file == NULL) {
[550]                             ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[551]                                       "the default path name \"%V\" has "
[552]                                       "the same name as another default path, "
[553]                                       "but the different levels, you need to "
[554]                                       "redefine one of them in http section",
[555]                                       &p[i]->name);
[556]                             return NGX_ERROR;
[557]                         }
[558] 
[559]                         ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
[560]                                       "the path name \"%V\" in %s:%ui has "
[561]                                       "the same name as default path, but "
[562]                                       "the different levels, you need to "
[563]                                       "define default path in http section",
[564]                                       &p[i]->name, p[i]->conf_file, p[i]->line);
[565]                         return NGX_ERROR;
[566]                     }
[567] 
[568]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[569]                                       "the same path name \"%V\" in %s:%ui "
[570]                                       "has the different levels than",
[571]                                       &p[i]->name, p[i]->conf_file, p[i]->line);
[572]                     return NGX_ERROR;
[573]                 }
[574] 
[575]                 if (p[i]->level[n] == 0) {
[576]                     break;
[577]                 }
[578]             }
[579] 
[580]             *slot = p[i];
[581] 
[582]             return NGX_OK;
[583]         }
[584]     }
[585] 
[586]     p = ngx_array_push(&cf->cycle->paths);
[587]     if (p == NULL) {
[588]         return NGX_ERROR;
[589]     }
[590] 
[591]     *p = path;
[592] 
[593]     return NGX_OK;
[594] }
[595] 
[596] 
[597] ngx_int_t
[598] ngx_create_paths(ngx_cycle_t *cycle, ngx_uid_t user)
[599] {
[600]     ngx_err_t         err;
[601]     ngx_uint_t        i;
[602]     ngx_path_t      **path;
[603] 
[604]     path = cycle->paths.elts;
[605]     for (i = 0; i < cycle->paths.nelts; i++) {
[606] 
[607]         if (ngx_create_dir(path[i]->name.data, 0700) == NGX_FILE_ERROR) {
[608]             err = ngx_errno;
[609]             if (err != NGX_EEXIST) {
[610]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
[611]                               ngx_create_dir_n " \"%s\" failed",
[612]                               path[i]->name.data);
[613]                 return NGX_ERROR;
[614]             }
[615]         }
[616] 
[617]         if (user == (ngx_uid_t) NGX_CONF_UNSET_UINT) {
[618]             continue;
[619]         }
[620] 
[621] #if !(NGX_WIN32)
[622]         {
[623]         ngx_file_info_t   fi;
[624] 
[625]         if (ngx_file_info(path[i]->name.data, &fi) == NGX_FILE_ERROR) {
[626]             ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[627]                           ngx_file_info_n " \"%s\" failed", path[i]->name.data);
[628]             return NGX_ERROR;
[629]         }
[630] 
[631]         if (fi.st_uid != user) {
[632]             if (chown((const char *) path[i]->name.data, user, -1) == -1) {
[633]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[634]                               "chown(\"%s\", %d) failed",
[635]                               path[i]->name.data, user);
[636]                 return NGX_ERROR;
[637]             }
[638]         }
[639] 
[640]         if ((fi.st_mode & (S_IRUSR|S_IWUSR|S_IXUSR))
[641]                                                   != (S_IRUSR|S_IWUSR|S_IXUSR))
[642]         {
[643]             fi.st_mode |= (S_IRUSR|S_IWUSR|S_IXUSR);
[644] 
[645]             if (chmod((const char *) path[i]->name.data, fi.st_mode) == -1) {
[646]                 ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
[647]                               "chmod() \"%s\" failed", path[i]->name.data);
[648]                 return NGX_ERROR;
[649]             }
[650]         }
[651]         }
[652] #endif
[653]     }
[654] 
[655]     return NGX_OK;
[656] }
[657] 
[658] 
[659] ngx_int_t
[660] ngx_ext_rename_file(ngx_str_t *src, ngx_str_t *to, ngx_ext_rename_file_t *ext)
[661] {
[662]     u_char           *name;
[663]     ngx_err_t         err;
[664]     ngx_copy_file_t   cf;
[665] 
[666] #if !(NGX_WIN32)
[667] 
[668]     if (ext->access) {
[669]         if (ngx_change_file_access(src->data, ext->access) == NGX_FILE_ERROR) {
[670]             ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
[671]                           ngx_change_file_access_n " \"%s\" failed", src->data);
[672]             err = 0;
[673]             goto failed;
[674]         }
[675]     }
[676] 
[677] #endif
[678] 
[679]     if (ext->time != -1) {
[680]         if (ngx_set_file_time(src->data, ext->fd, ext->time) != NGX_OK) {
[681]             ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
[682]                           ngx_set_file_time_n " \"%s\" failed", src->data);
[683]             err = 0;
[684]             goto failed;
[685]         }
[686]     }
[687] 
[688]     if (ngx_rename_file(src->data, to->data) != NGX_FILE_ERROR) {
[689]         return NGX_OK;
[690]     }
[691] 
[692]     err = ngx_errno;
[693] 
[694]     if (err == NGX_ENOPATH) {
[695] 
[696]         if (!ext->create_path) {
[697]             goto failed;
[698]         }
[699] 
[700]         err = ngx_create_full_path(to->data, ngx_dir_access(ext->path_access));
[701] 
[702]         if (err) {
[703]             ngx_log_error(NGX_LOG_CRIT, ext->log, err,
[704]                           ngx_create_dir_n " \"%s\" failed", to->data);
[705]             err = 0;
[706]             goto failed;
[707]         }
[708] 
[709]         if (ngx_rename_file(src->data, to->data) != NGX_FILE_ERROR) {
[710]             return NGX_OK;
[711]         }
[712] 
[713]         err = ngx_errno;
[714]     }
[715] 
[716] #if (NGX_WIN32)
[717] 
[718]     if (err == NGX_EEXIST || err == NGX_EEXIST_FILE) {
[719]         err = ngx_win32_rename_file(src, to, ext->log);
[720] 
[721]         if (err == 0) {
[722]             return NGX_OK;
[723]         }
[724]     }
[725] 
[726] #endif
[727] 
[728]     if (err == NGX_EXDEV) {
[729] 
[730]         cf.size = -1;
[731]         cf.buf_size = 0;
[732]         cf.access = ext->access;
[733]         cf.time = ext->time;
[734]         cf.log = ext->log;
[735] 
[736]         name = ngx_alloc(to->len + 1 + 10 + 1, ext->log);
[737]         if (name == NULL) {
[738]             return NGX_ERROR;
[739]         }
[740] 
[741]         (void) ngx_sprintf(name, "%*s.%010uD%Z", to->len, to->data,
[742]                            (uint32_t) ngx_next_temp_number(0));
[743] 
[744]         if (ngx_copy_file(src->data, name, &cf) == NGX_OK) {
[745] 
[746]             if (ngx_rename_file(name, to->data) != NGX_FILE_ERROR) {
[747]                 ngx_free(name);
[748] 
[749]                 if (ngx_delete_file(src->data) == NGX_FILE_ERROR) {
[750]                     ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
[751]                                   ngx_delete_file_n " \"%s\" failed",
[752]                                   src->data);
[753]                     return NGX_ERROR;
[754]                 }
[755] 
[756]                 return NGX_OK;
[757]             }
[758] 
[759]             ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
[760]                           ngx_rename_file_n " \"%s\" to \"%s\" failed",
[761]                           name, to->data);
[762] 
[763]             if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[764]                 ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
[765]                               ngx_delete_file_n " \"%s\" failed", name);
[766] 
[767]             }
[768]         }
[769] 
[770]         ngx_free(name);
[771] 
[772]         err = 0;
[773]     }
[774] 
[775] failed:
[776] 
[777]     if (ext->delete_file) {
[778]         if (ngx_delete_file(src->data) == NGX_FILE_ERROR) {
[779]             ngx_log_error(NGX_LOG_CRIT, ext->log, ngx_errno,
[780]                           ngx_delete_file_n " \"%s\" failed", src->data);
[781]         }
[782]     }
[783] 
[784]     if (err) {
[785]         ngx_log_error(NGX_LOG_CRIT, ext->log, err,
[786]                       ngx_rename_file_n " \"%s\" to \"%s\" failed",
[787]                       src->data, to->data);
[788]     }
[789] 
[790]     return NGX_ERROR;
[791] }
[792] 
[793] 
[794] ngx_int_t
[795] ngx_copy_file(u_char *from, u_char *to, ngx_copy_file_t *cf)
[796] {
[797]     char             *buf;
[798]     off_t             size;
[799]     time_t            time;
[800]     size_t            len;
[801]     ssize_t           n;
[802]     ngx_fd_t          fd, nfd;
[803]     ngx_int_t         rc;
[804]     ngx_uint_t        access;
[805]     ngx_file_info_t   fi;
[806] 
[807]     rc = NGX_ERROR;
[808]     buf = NULL;
[809]     nfd = NGX_INVALID_FILE;
[810] 
[811]     fd = ngx_open_file(from, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
[812] 
[813]     if (fd == NGX_INVALID_FILE) {
[814]         ngx_log_error(NGX_LOG_CRIT, cf->log, ngx_errno,
[815]                       ngx_open_file_n " \"%s\" failed", from);
[816]         goto failed;
[817]     }
[818] 
[819]     if (cf->size != -1 && cf->access != 0 && cf->time != -1) {
[820]         size = cf->size;
[821]         access = cf->access;
[822]         time = cf->time;
[823] 
[824]     } else {
[825]         if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
[826]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[827]                           ngx_fd_info_n " \"%s\" failed", from);
[828] 
[829]             goto failed;
[830]         }
[831] 
[832]         size = (cf->size != -1) ? cf->size : ngx_file_size(&fi);
[833]         access = cf->access ? cf->access : ngx_file_access(&fi);
[834]         time = (cf->time != -1) ? cf->time : ngx_file_mtime(&fi);
[835]     }
[836] 
[837]     len = cf->buf_size ? cf->buf_size : 65536;
[838] 
[839]     if ((off_t) len > size) {
[840]         len = (size_t) size;
[841]     }
[842] 
[843]     buf = ngx_alloc(len, cf->log);
[844]     if (buf == NULL) {
[845]         goto failed;
[846]     }
[847] 
[848]     nfd = ngx_open_file(to, NGX_FILE_WRONLY, NGX_FILE_TRUNCATE, access);
[849] 
[850]     if (nfd == NGX_INVALID_FILE) {
[851]         ngx_log_error(NGX_LOG_CRIT, cf->log, ngx_errno,
[852]                       ngx_open_file_n " \"%s\" failed", to);
[853]         goto failed;
[854]     }
[855] 
[856]     while (size > 0) {
[857] 
[858]         if ((off_t) len > size) {
[859]             len = (size_t) size;
[860]         }
[861] 
[862]         n = ngx_read_fd(fd, buf, len);
[863] 
[864]         if (n == -1) {
[865]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[866]                           ngx_read_fd_n " \"%s\" failed", from);
[867]             goto failed;
[868]         }
[869] 
[870]         if ((size_t) n != len) {
[871]             ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
[872]                           ngx_read_fd_n " has read only %z of %O from %s",
[873]                           n, size, from);
[874]             goto failed;
[875]         }
[876] 
[877]         n = ngx_write_fd(nfd, buf, len);
[878] 
[879]         if (n == -1) {
[880]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[881]                           ngx_write_fd_n " \"%s\" failed", to);
[882]             goto failed;
[883]         }
[884] 
[885]         if ((size_t) n != len) {
[886]             ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
[887]                           ngx_write_fd_n " has written only %z of %O to %s",
[888]                           n, size, to);
[889]             goto failed;
[890]         }
[891] 
[892]         size -= n;
[893]     }
[894] 
[895]     if (ngx_set_file_time(to, nfd, time) != NGX_OK) {
[896]         ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[897]                       ngx_set_file_time_n " \"%s\" failed", to);
[898]         goto failed;
[899]     }
[900] 
[901]     rc = NGX_OK;
[902] 
[903] failed:
[904] 
[905]     if (nfd != NGX_INVALID_FILE) {
[906]         if (ngx_close_file(nfd) == NGX_FILE_ERROR) {
[907]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[908]                           ngx_close_file_n " \"%s\" failed", to);
[909]         }
[910]     }
[911] 
[912]     if (fd != NGX_INVALID_FILE) {
[913]         if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[914]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[915]                           ngx_close_file_n " \"%s\" failed", from);
[916]         }
[917]     }
[918] 
[919]     if (buf) {
[920]         ngx_free(buf);
[921]     }
[922] 
[923]     return rc;
[924] }
[925] 
[926] 
[927] /*
[928]  * ctx->init_handler() - see ctx->alloc
[929]  * ctx->file_handler() - file handler
[930]  * ctx->pre_tree_handler() - handler is called before entering directory
[931]  * ctx->post_tree_handler() - handler is called after leaving directory
[932]  * ctx->spec_handler() - special (socket, FIFO, etc.) file handler
[933]  *
[934]  * ctx->data - some data structure, it may be the same on all levels, or
[935]  *     reallocated if ctx->alloc is nonzero
[936]  *
[937]  * ctx->alloc - a size of data structure that is allocated at every level
[938]  *     and is initialized by ctx->init_handler()
[939]  *
[940]  * ctx->log - a log
[941]  *
[942]  * on fatal (memory) error handler must return NGX_ABORT to stop walking tree
[943]  */
[944] 
[945] ngx_int_t
[946] ngx_walk_tree(ngx_tree_ctx_t *ctx, ngx_str_t *tree)
[947] {
[948]     void       *data, *prev;
[949]     u_char     *p, *name;
[950]     size_t      len;
[951]     ngx_int_t   rc;
[952]     ngx_err_t   err;
[953]     ngx_str_t   file, buf;
[954]     ngx_dir_t   dir;
[955] 
[956]     ngx_str_null(&buf);
[957] 
[958]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[959]                    "walk tree \"%V\"", tree);
[960] 
[961]     if (ngx_open_dir(tree, &dir) == NGX_ERROR) {
[962]         ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
[963]                       ngx_open_dir_n " \"%s\" failed", tree->data);
[964]         return NGX_ERROR;
[965]     }
[966] 
[967]     prev = ctx->data;
[968] 
[969]     if (ctx->alloc) {
[970]         data = ngx_alloc(ctx->alloc, ctx->log);
[971]         if (data == NULL) {
[972]             goto failed;
[973]         }
[974] 
[975]         if (ctx->init_handler(data, prev) == NGX_ABORT) {
[976]             goto failed;
[977]         }
[978] 
[979]         ctx->data = data;
[980] 
[981]     } else {
[982]         data = NULL;
[983]     }
[984] 
[985]     for ( ;; ) {
[986] 
[987]         ngx_set_errno(0);
[988] 
[989]         if (ngx_read_dir(&dir) == NGX_ERROR) {
[990]             err = ngx_errno;
[991] 
[992]             if (err == NGX_ENOMOREFILES) {
[993]                 rc = NGX_OK;
[994] 
[995]             } else {
[996]                 ngx_log_error(NGX_LOG_CRIT, ctx->log, err,
[997]                               ngx_read_dir_n " \"%s\" failed", tree->data);
[998]                 rc = NGX_ERROR;
[999]             }
[1000] 
[1001]             goto done;
[1002]         }
[1003] 
[1004]         len = ngx_de_namelen(&dir);
[1005]         name = ngx_de_name(&dir);
[1006] 
[1007]         ngx_log_debug2(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[1008]                       "tree name %uz:\"%s\"", len, name);
[1009] 
[1010]         if (len == 1 && name[0] == '.') {
[1011]             continue;
[1012]         }
[1013] 
[1014]         if (len == 2 && name[0] == '.' && name[1] == '.') {
[1015]             continue;
[1016]         }
[1017] 
[1018]         file.len = tree->len + 1 + len;
[1019] 
[1020]         if (file.len > buf.len) {
[1021] 
[1022]             if (buf.len) {
[1023]                 ngx_free(buf.data);
[1024]             }
[1025] 
[1026]             buf.len = tree->len + 1 + len;
[1027] 
[1028]             buf.data = ngx_alloc(buf.len + 1, ctx->log);
[1029]             if (buf.data == NULL) {
[1030]                 goto failed;
[1031]             }
[1032]         }
[1033] 
[1034]         p = ngx_cpymem(buf.data, tree->data, tree->len);
[1035]         *p++ = '/';
[1036]         ngx_memcpy(p, name, len + 1);
[1037] 
[1038]         file.data = buf.data;
[1039] 
[1040]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[1041]                        "tree path \"%s\"", file.data);
[1042] 
[1043]         if (!dir.valid_info) {
[1044]             if (ngx_de_info(file.data, &dir) == NGX_FILE_ERROR) {
[1045]                 ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
[1046]                               ngx_de_info_n " \"%s\" failed", file.data);
[1047]                 continue;
[1048]             }
[1049]         }
[1050] 
[1051]         if (ngx_de_is_file(&dir)) {
[1052] 
[1053]             ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[1054]                            "tree file \"%s\"", file.data);
[1055] 
[1056]             ctx->size = ngx_de_size(&dir);
[1057]             ctx->fs_size = ngx_de_fs_size(&dir);
[1058]             ctx->access = ngx_de_access(&dir);
[1059]             ctx->mtime = ngx_de_mtime(&dir);
[1060] 
[1061]             if (ctx->file_handler(ctx, &file) == NGX_ABORT) {
[1062]                 goto failed;
[1063]             }
[1064] 
[1065]         } else if (ngx_de_is_dir(&dir)) {
[1066] 
[1067]             ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[1068]                            "tree enter dir \"%s\"", file.data);
[1069] 
[1070]             ctx->access = ngx_de_access(&dir);
[1071]             ctx->mtime = ngx_de_mtime(&dir);
[1072] 
[1073]             rc = ctx->pre_tree_handler(ctx, &file);
[1074] 
[1075]             if (rc == NGX_ABORT) {
[1076]                 goto failed;
[1077]             }
[1078] 
[1079]             if (rc == NGX_DECLINED) {
[1080]                 ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[1081]                                "tree skip dir \"%s\"", file.data);
[1082]                 continue;
[1083]             }
[1084] 
[1085]             if (ngx_walk_tree(ctx, &file) == NGX_ABORT) {
[1086]                 goto failed;
[1087]             }
[1088] 
[1089]             ctx->access = ngx_de_access(&dir);
[1090]             ctx->mtime = ngx_de_mtime(&dir);
[1091] 
[1092]             if (ctx->post_tree_handler(ctx, &file) == NGX_ABORT) {
[1093]                 goto failed;
[1094]             }
[1095] 
[1096]         } else {
[1097] 
[1098]             ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
[1099]                            "tree special \"%s\"", file.data);
[1100] 
[1101]             if (ctx->spec_handler(ctx, &file) == NGX_ABORT) {
[1102]                 goto failed;
[1103]             }
[1104]         }
[1105]     }
[1106] 
[1107] failed:
[1108] 
[1109]     rc = NGX_ABORT;
[1110] 
[1111] done:
[1112] 
[1113]     if (buf.len) {
[1114]         ngx_free(buf.data);
[1115]     }
[1116] 
[1117]     if (data) {
[1118]         ngx_free(data);
[1119]         ctx->data = prev;
[1120]     }
[1121] 
[1122]     if (ngx_close_dir(&dir) == NGX_ERROR) {
[1123]         ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
[1124]                       ngx_close_dir_n " \"%s\" failed", tree->data);
[1125]     }
[1126] 
[1127]     return rc;
[1128] }
