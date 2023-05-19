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
[11] #define NGX_CONF_BUFFER  4096
[12] 
[13] static ngx_int_t ngx_conf_add_dump(ngx_conf_t *cf, ngx_str_t *filename);
[14] static ngx_int_t ngx_conf_handler(ngx_conf_t *cf, ngx_int_t last);
[15] static ngx_int_t ngx_conf_read_token(ngx_conf_t *cf);
[16] static void ngx_conf_flush_files(ngx_cycle_t *cycle);
[17] 
[18] 
[19] static ngx_command_t  ngx_conf_commands[] = {
[20] 
[21]     { ngx_string("include"),
[22]       NGX_ANY_CONF|NGX_CONF_TAKE1,
[23]       ngx_conf_include,
[24]       0,
[25]       0,
[26]       NULL },
[27] 
[28]       ngx_null_command
[29] };
[30] 
[31] 
[32] ngx_module_t  ngx_conf_module = {
[33]     NGX_MODULE_V1,
[34]     NULL,                                  /* module context */
[35]     ngx_conf_commands,                     /* module directives */
[36]     NGX_CONF_MODULE,                       /* module type */
[37]     NULL,                                  /* init master */
[38]     NULL,                                  /* init module */
[39]     NULL,                                  /* init process */
[40]     NULL,                                  /* init thread */
[41]     NULL,                                  /* exit thread */
[42]     ngx_conf_flush_files,                  /* exit process */
[43]     NULL,                                  /* exit master */
[44]     NGX_MODULE_V1_PADDING
[45] };
[46] 
[47] 
[48] /* The eight fixed arguments */
[49] 
[50] static ngx_uint_t argument_number[] = {
[51]     NGX_CONF_NOARGS,
[52]     NGX_CONF_TAKE1,
[53]     NGX_CONF_TAKE2,
[54]     NGX_CONF_TAKE3,
[55]     NGX_CONF_TAKE4,
[56]     NGX_CONF_TAKE5,
[57]     NGX_CONF_TAKE6,
[58]     NGX_CONF_TAKE7
[59] };
[60] 
[61] 
[62] char *
[63] ngx_conf_param(ngx_conf_t *cf)
[64] {
[65]     char             *rv;
[66]     ngx_str_t        *param;
[67]     ngx_buf_t         b;
[68]     ngx_conf_file_t   conf_file;
[69] 
[70]     param = &cf->cycle->conf_param;
[71] 
[72]     if (param->len == 0) {
[73]         return NGX_CONF_OK;
[74]     }
[75] 
[76]     ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));
[77] 
[78]     ngx_memzero(&b, sizeof(ngx_buf_t));
[79] 
[80]     b.start = param->data;
[81]     b.pos = param->data;
[82]     b.last = param->data + param->len;
[83]     b.end = b.last;
[84]     b.temporary = 1;
[85] 
[86]     conf_file.file.fd = NGX_INVALID_FILE;
[87]     conf_file.file.name.data = NULL;
[88]     conf_file.line = 0;
[89] 
[90]     cf->conf_file = &conf_file;
[91]     cf->conf_file->buffer = &b;
[92] 
[93]     rv = ngx_conf_parse(cf, NULL);
[94] 
[95]     cf->conf_file = NULL;
[96] 
[97]     return rv;
[98] }
[99] 
[100] 
[101] static ngx_int_t
[102] ngx_conf_add_dump(ngx_conf_t *cf, ngx_str_t *filename)
[103] {
[104]     off_t             size;
[105]     u_char           *p;
[106]     uint32_t          hash;
[107]     ngx_buf_t        *buf;
[108]     ngx_str_node_t   *sn;
[109]     ngx_conf_dump_t  *cd;
[110] 
[111]     hash = ngx_crc32_long(filename->data, filename->len);
[112] 
[113]     sn = ngx_str_rbtree_lookup(&cf->cycle->config_dump_rbtree, filename, hash);
[114] 
[115]     if (sn) {
[116]         cf->conf_file->dump = NULL;
[117]         return NGX_OK;
[118]     }
[119] 
[120]     p = ngx_pstrdup(cf->cycle->pool, filename);
[121]     if (p == NULL) {
[122]         return NGX_ERROR;
[123]     }
[124] 
[125]     cd = ngx_array_push(&cf->cycle->config_dump);
[126]     if (cd == NULL) {
[127]         return NGX_ERROR;
[128]     }
[129] 
[130]     size = ngx_file_size(&cf->conf_file->file.info);
[131] 
[132]     buf = ngx_create_temp_buf(cf->cycle->pool, (size_t) size);
[133]     if (buf == NULL) {
[134]         return NGX_ERROR;
[135]     }
[136] 
[137]     cd->name.data = p;
[138]     cd->name.len = filename->len;
[139]     cd->buffer = buf;
[140] 
[141]     cf->conf_file->dump = buf;
[142] 
[143]     sn = ngx_palloc(cf->temp_pool, sizeof(ngx_str_node_t));
[144]     if (sn == NULL) {
[145]         return NGX_ERROR;
[146]     }
[147] 
[148]     sn->node.key = hash;
[149]     sn->str = cd->name;
[150] 
[151]     ngx_rbtree_insert(&cf->cycle->config_dump_rbtree, &sn->node);
[152] 
[153]     return NGX_OK;
[154] }
[155] 
[156] 
[157] char *
[158] ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename)
[159] {
[160]     char             *rv;
[161]     ngx_fd_t          fd;
[162]     ngx_int_t         rc;
[163]     ngx_buf_t         buf;
[164]     ngx_conf_file_t  *prev, conf_file;
[165]     enum {
[166]         parse_file = 0,
[167]         parse_block,
[168]         parse_param
[169]     } type;
[170] 
[171] #if (NGX_SUPPRESS_WARN)
[172]     fd = NGX_INVALID_FILE;
[173]     prev = NULL;
[174] #endif
[175] 
[176]     if (filename) {
[177] 
[178]         /* open configuration file */
[179] 
[180]         fd = ngx_open_file(filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
[181] 
[182]         if (fd == NGX_INVALID_FILE) {
[183]             ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[184]                                ngx_open_file_n " \"%s\" failed",
[185]                                filename->data);
[186]             return NGX_CONF_ERROR;
[187]         }
[188] 
[189]         prev = cf->conf_file;
[190] 
[191]         cf->conf_file = &conf_file;
[192] 
[193]         if (ngx_fd_info(fd, &cf->conf_file->file.info) == NGX_FILE_ERROR) {
[194]             ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
[195]                           ngx_fd_info_n " \"%s\" failed", filename->data);
[196]         }
[197] 
[198]         cf->conf_file->buffer = &buf;
[199] 
[200]         buf.start = ngx_alloc(NGX_CONF_BUFFER, cf->log);
[201]         if (buf.start == NULL) {
[202]             goto failed;
[203]         }
[204] 
[205]         buf.pos = buf.start;
[206]         buf.last = buf.start;
[207]         buf.end = buf.last + NGX_CONF_BUFFER;
[208]         buf.temporary = 1;
[209] 
[210]         cf->conf_file->file.fd = fd;
[211]         cf->conf_file->file.name.len = filename->len;
[212]         cf->conf_file->file.name.data = filename->data;
[213]         cf->conf_file->file.offset = 0;
[214]         cf->conf_file->file.log = cf->log;
[215]         cf->conf_file->line = 1;
[216] 
[217]         type = parse_file;
[218] 
[219]         if (ngx_dump_config
[220] #if (NGX_DEBUG)
[221]             || 1
[222] #endif
[223]            )
[224]         {
[225]             if (ngx_conf_add_dump(cf, filename) != NGX_OK) {
[226]                 goto failed;
[227]             }
[228] 
[229]         } else {
[230]             cf->conf_file->dump = NULL;
[231]         }
[232] 
[233]     } else if (cf->conf_file->file.fd != NGX_INVALID_FILE) {
[234] 
[235]         type = parse_block;
[236] 
[237]     } else {
[238]         type = parse_param;
[239]     }
[240] 
[241] 
[242]     for ( ;; ) {
[243]         rc = ngx_conf_read_token(cf);
[244] 
[245]         /*
[246]          * ngx_conf_read_token() may return
[247]          *
[248]          *    NGX_ERROR             there is error
[249]          *    NGX_OK                the token terminated by ";" was found
[250]          *    NGX_CONF_BLOCK_START  the token terminated by "{" was found
[251]          *    NGX_CONF_BLOCK_DONE   the "}" was found
[252]          *    NGX_CONF_FILE_DONE    the configuration file is done
[253]          */
[254] 
[255]         if (rc == NGX_ERROR) {
[256]             goto done;
[257]         }
[258] 
[259]         if (rc == NGX_CONF_BLOCK_DONE) {
[260] 
[261]             if (type != parse_block) {
[262]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unexpected \"}\"");
[263]                 goto failed;
[264]             }
[265] 
[266]             goto done;
[267]         }
[268] 
[269]         if (rc == NGX_CONF_FILE_DONE) {
[270] 
[271]             if (type == parse_block) {
[272]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[273]                                    "unexpected end of file, expecting \"}\"");
[274]                 goto failed;
[275]             }
[276] 
[277]             goto done;
[278]         }
[279] 
[280]         if (rc == NGX_CONF_BLOCK_START) {
[281] 
[282]             if (type == parse_param) {
[283]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[284]                                    "block directives are not supported "
[285]                                    "in -g option");
[286]                 goto failed;
[287]             }
[288]         }
[289] 
[290]         /* rc == NGX_OK || rc == NGX_CONF_BLOCK_START */
[291] 
[292]         if (cf->handler) {
[293] 
[294]             /*
[295]              * the custom handler, i.e., that is used in the http's
[296]              * "types { ... }" directive
[297]              */
[298] 
[299]             if (rc == NGX_CONF_BLOCK_START) {
[300]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unexpected \"{\"");
[301]                 goto failed;
[302]             }
[303] 
[304]             rv = (*cf->handler)(cf, NULL, cf->handler_conf);
[305]             if (rv == NGX_CONF_OK) {
[306]                 continue;
[307]             }
[308] 
[309]             if (rv == NGX_CONF_ERROR) {
[310]                 goto failed;
[311]             }
[312] 
[313]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", rv);
[314] 
[315]             goto failed;
[316]         }
[317] 
[318] 
[319]         rc = ngx_conf_handler(cf, rc);
[320] 
[321]         if (rc == NGX_ERROR) {
[322]             goto failed;
[323]         }
[324]     }
[325] 
[326] failed:
[327] 
[328]     rc = NGX_ERROR;
[329] 
[330] done:
[331] 
[332]     if (filename) {
[333]         if (cf->conf_file->buffer->start) {
[334]             ngx_free(cf->conf_file->buffer->start);
[335]         }
[336] 
[337]         if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[338]             ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,
[339]                           ngx_close_file_n " %s failed",
[340]                           filename->data);
[341]             rc = NGX_ERROR;
[342]         }
[343] 
[344]         cf->conf_file = prev;
[345]     }
[346] 
[347]     if (rc == NGX_ERROR) {
[348]         return NGX_CONF_ERROR;
[349]     }
[350] 
[351]     return NGX_CONF_OK;
[352] }
[353] 
[354] 
[355] static ngx_int_t
[356] ngx_conf_handler(ngx_conf_t *cf, ngx_int_t last)
[357] {
[358]     char           *rv;
[359]     void           *conf, **confp;
[360]     ngx_uint_t      i, found;
[361]     ngx_str_t      *name;
[362]     ngx_command_t  *cmd;
[363] 
[364]     name = cf->args->elts;
[365] 
[366]     found = 0;
[367] 
[368]     for (i = 0; cf->cycle->modules[i]; i++) {
[369] 
[370]         cmd = cf->cycle->modules[i]->commands;
[371]         if (cmd == NULL) {
[372]             continue;
[373]         }
[374] 
[375]         for ( /* void */ ; cmd->name.len; cmd++) {
[376] 
[377]             if (name->len != cmd->name.len) {
[378]                 continue;
[379]             }
[380] 
[381]             if (ngx_strcmp(name->data, cmd->name.data) != 0) {
[382]                 continue;
[383]             }
[384] 
[385]             found = 1;
[386] 
[387]             if (cf->cycle->modules[i]->type != NGX_CONF_MODULE
[388]                 && cf->cycle->modules[i]->type != cf->module_type)
[389]             {
[390]                 continue;
[391]             }
[392] 
[393]             /* is the directive's location right ? */
[394] 
[395]             if (!(cmd->type & cf->cmd_type)) {
[396]                 continue;
[397]             }
[398] 
[399]             if (!(cmd->type & NGX_CONF_BLOCK) && last != NGX_OK) {
[400]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[401]                                   "directive \"%s\" is not terminated by \";\"",
[402]                                   name->data);
[403]                 return NGX_ERROR;
[404]             }
[405] 
[406]             if ((cmd->type & NGX_CONF_BLOCK) && last != NGX_CONF_BLOCK_START) {
[407]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[408]                                    "directive \"%s\" has no opening \"{\"",
[409]                                    name->data);
[410]                 return NGX_ERROR;
[411]             }
[412] 
[413]             /* is the directive's argument count right ? */
[414] 
[415]             if (!(cmd->type & NGX_CONF_ANY)) {
[416] 
[417]                 if (cmd->type & NGX_CONF_FLAG) {
[418] 
[419]                     if (cf->args->nelts != 2) {
[420]                         goto invalid;
[421]                     }
[422] 
[423]                 } else if (cmd->type & NGX_CONF_1MORE) {
[424] 
[425]                     if (cf->args->nelts < 2) {
[426]                         goto invalid;
[427]                     }
[428] 
[429]                 } else if (cmd->type & NGX_CONF_2MORE) {
[430] 
[431]                     if (cf->args->nelts < 3) {
[432]                         goto invalid;
[433]                     }
[434] 
[435]                 } else if (cf->args->nelts > NGX_CONF_MAX_ARGS) {
[436] 
[437]                     goto invalid;
[438] 
[439]                 } else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
[440]                 {
[441]                     goto invalid;
[442]                 }
[443]             }
[444] 
[445]             /* set up the directive's configuration context */
[446] 
[447]             conf = NULL;
[448] 
[449]             if (cmd->type & NGX_DIRECT_CONF) {
[450]                 conf = ((void **) cf->ctx)[cf->cycle->modules[i]->index];
[451] 
[452]             } else if (cmd->type & NGX_MAIN_CONF) {
[453]                 conf = &(((void **) cf->ctx)[cf->cycle->modules[i]->index]);
[454] 
[455]             } else if (cf->ctx) {
[456]                 confp = *(void **) ((char *) cf->ctx + cmd->conf);
[457] 
[458]                 if (confp) {
[459]                     conf = confp[cf->cycle->modules[i]->ctx_index];
[460]                 }
[461]             }
[462] 
[463]             rv = cmd->set(cf, cmd, conf);
[464] 
[465]             if (rv == NGX_CONF_OK) {
[466]                 return NGX_OK;
[467]             }
[468] 
[469]             if (rv == NGX_CONF_ERROR) {
[470]                 return NGX_ERROR;
[471]             }
[472] 
[473]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[474]                                "\"%s\" directive %s", name->data, rv);
[475] 
[476]             return NGX_ERROR;
[477]         }
[478]     }
[479] 
[480]     if (found) {
[481]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[482]                            "\"%s\" directive is not allowed here", name->data);
[483] 
[484]         return NGX_ERROR;
[485]     }
[486] 
[487]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[488]                        "unknown directive \"%s\"", name->data);
[489] 
[490]     return NGX_ERROR;
[491] 
[492] invalid:
[493] 
[494]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[495]                        "invalid number of arguments in \"%s\" directive",
[496]                        name->data);
[497] 
[498]     return NGX_ERROR;
[499] }
[500] 
[501] 
[502] static ngx_int_t
[503] ngx_conf_read_token(ngx_conf_t *cf)
[504] {
[505]     u_char      *start, ch, *src, *dst;
[506]     off_t        file_size;
[507]     size_t       len;
[508]     ssize_t      n, size;
[509]     ngx_uint_t   found, need_space, last_space, sharp_comment, variable;
[510]     ngx_uint_t   quoted, s_quoted, d_quoted, start_line;
[511]     ngx_str_t   *word;
[512]     ngx_buf_t   *b, *dump;
[513] 
[514]     found = 0;
[515]     need_space = 0;
[516]     last_space = 1;
[517]     sharp_comment = 0;
[518]     variable = 0;
[519]     quoted = 0;
[520]     s_quoted = 0;
[521]     d_quoted = 0;
[522] 
[523]     cf->args->nelts = 0;
[524]     b = cf->conf_file->buffer;
[525]     dump = cf->conf_file->dump;
[526]     start = b->pos;
[527]     start_line = cf->conf_file->line;
[528] 
[529]     file_size = ngx_file_size(&cf->conf_file->file.info);
[530] 
[531]     for ( ;; ) {
[532] 
[533]         if (b->pos >= b->last) {
[534] 
[535]             if (cf->conf_file->file.offset >= file_size) {
[536] 
[537]                 if (cf->args->nelts > 0 || !last_space) {
[538] 
[539]                     if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
[540]                         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[541]                                            "unexpected end of parameter, "
[542]                                            "expecting \";\"");
[543]                         return NGX_ERROR;
[544]                     }
[545] 
[546]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[547]                                        "unexpected end of file, "
[548]                                        "expecting \";\" or \"}\"");
[549]                     return NGX_ERROR;
[550]                 }
[551] 
[552]                 return NGX_CONF_FILE_DONE;
[553]             }
[554] 
[555]             len = b->pos - start;
[556] 
[557]             if (len == NGX_CONF_BUFFER) {
[558]                 cf->conf_file->line = start_line;
[559] 
[560]                 if (d_quoted) {
[561]                     ch = '"';
[562] 
[563]                 } else if (s_quoted) {
[564]                     ch = '\'';
[565] 
[566]                 } else {
[567]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[568]                                        "too long parameter \"%*s...\" started",
[569]                                        10, start);
[570]                     return NGX_ERROR;
[571]                 }
[572] 
[573]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[574]                                    "too long parameter, probably "
[575]                                    "missing terminating \"%c\" character", ch);
[576]                 return NGX_ERROR;
[577]             }
[578] 
[579]             if (len) {
[580]                 ngx_memmove(b->start, start, len);
[581]             }
[582] 
[583]             size = (ssize_t) (file_size - cf->conf_file->file.offset);
[584] 
[585]             if (size > b->end - (b->start + len)) {
[586]                 size = b->end - (b->start + len);
[587]             }
[588] 
[589]             n = ngx_read_file(&cf->conf_file->file, b->start + len, size,
[590]                               cf->conf_file->file.offset);
[591] 
[592]             if (n == NGX_ERROR) {
[593]                 return NGX_ERROR;
[594]             }
[595] 
[596]             if (n != size) {
[597]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[598]                                    ngx_read_file_n " returned "
[599]                                    "only %z bytes instead of %z",
[600]                                    n, size);
[601]                 return NGX_ERROR;
[602]             }
[603] 
[604]             b->pos = b->start + len;
[605]             b->last = b->pos + n;
[606]             start = b->start;
[607] 
[608]             if (dump) {
[609]                 dump->last = ngx_cpymem(dump->last, b->pos, size);
[610]             }
[611]         }
[612] 
[613]         ch = *b->pos++;
[614] 
[615]         if (ch == LF) {
[616]             cf->conf_file->line++;
[617] 
[618]             if (sharp_comment) {
[619]                 sharp_comment = 0;
[620]             }
[621]         }
[622] 
[623]         if (sharp_comment) {
[624]             continue;
[625]         }
[626] 
[627]         if (quoted) {
[628]             quoted = 0;
[629]             continue;
[630]         }
[631] 
[632]         if (need_space) {
[633]             if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
[634]                 last_space = 1;
[635]                 need_space = 0;
[636]                 continue;
[637]             }
[638] 
[639]             if (ch == ';') {
[640]                 return NGX_OK;
[641]             }
[642] 
[643]             if (ch == '{') {
[644]                 return NGX_CONF_BLOCK_START;
[645]             }
[646] 
[647]             if (ch == ')') {
[648]                 last_space = 1;
[649]                 need_space = 0;
[650] 
[651]             } else {
[652]                 ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[653]                                    "unexpected \"%c\"", ch);
[654]                 return NGX_ERROR;
[655]             }
[656]         }
[657] 
[658]         if (last_space) {
[659] 
[660]             start = b->pos - 1;
[661]             start_line = cf->conf_file->line;
[662] 
[663]             if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
[664]                 continue;
[665]             }
[666] 
[667]             switch (ch) {
[668] 
[669]             case ';':
[670]             case '{':
[671]                 if (cf->args->nelts == 0) {
[672]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[673]                                        "unexpected \"%c\"", ch);
[674]                     return NGX_ERROR;
[675]                 }
[676] 
[677]                 if (ch == '{') {
[678]                     return NGX_CONF_BLOCK_START;
[679]                 }
[680] 
[681]                 return NGX_OK;
[682] 
[683]             case '}':
[684]                 if (cf->args->nelts != 0) {
[685]                     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[686]                                        "unexpected \"}\"");
[687]                     return NGX_ERROR;
[688]                 }
[689] 
[690]                 return NGX_CONF_BLOCK_DONE;
[691] 
[692]             case '#':
[693]                 sharp_comment = 1;
[694]                 continue;
[695] 
[696]             case '\\':
[697]                 quoted = 1;
[698]                 last_space = 0;
[699]                 continue;
[700] 
[701]             case '"':
[702]                 start++;
[703]                 d_quoted = 1;
[704]                 last_space = 0;
[705]                 continue;
[706] 
[707]             case '\'':
[708]                 start++;
[709]                 s_quoted = 1;
[710]                 last_space = 0;
[711]                 continue;
[712] 
[713]             case '$':
[714]                 variable = 1;
[715]                 last_space = 0;
[716]                 continue;
[717] 
[718]             default:
[719]                 last_space = 0;
[720]             }
[721] 
[722]         } else {
[723]             if (ch == '{' && variable) {
[724]                 continue;
[725]             }
[726] 
[727]             variable = 0;
[728] 
[729]             if (ch == '\\') {
[730]                 quoted = 1;
[731]                 continue;
[732]             }
[733] 
[734]             if (ch == '$') {
[735]                 variable = 1;
[736]                 continue;
[737]             }
[738] 
[739]             if (d_quoted) {
[740]                 if (ch == '"') {
[741]                     d_quoted = 0;
[742]                     need_space = 1;
[743]                     found = 1;
[744]                 }
[745] 
[746]             } else if (s_quoted) {
[747]                 if (ch == '\'') {
[748]                     s_quoted = 0;
[749]                     need_space = 1;
[750]                     found = 1;
[751]                 }
[752] 
[753]             } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
[754]                        || ch == ';' || ch == '{')
[755]             {
[756]                 last_space = 1;
[757]                 found = 1;
[758]             }
[759] 
[760]             if (found) {
[761]                 word = ngx_array_push(cf->args);
[762]                 if (word == NULL) {
[763]                     return NGX_ERROR;
[764]                 }
[765] 
[766]                 word->data = ngx_pnalloc(cf->pool, b->pos - 1 - start + 1);
[767]                 if (word->data == NULL) {
[768]                     return NGX_ERROR;
[769]                 }
[770] 
[771]                 for (dst = word->data, src = start, len = 0;
[772]                      src < b->pos - 1;
[773]                      len++)
[774]                 {
[775]                     if (*src == '\\') {
[776]                         switch (src[1]) {
[777]                         case '"':
[778]                         case '\'':
[779]                         case '\\':
[780]                             src++;
[781]                             break;
[782] 
[783]                         case 't':
[784]                             *dst++ = '\t';
[785]                             src += 2;
[786]                             continue;
[787] 
[788]                         case 'r':
[789]                             *dst++ = '\r';
[790]                             src += 2;
[791]                             continue;
[792] 
[793]                         case 'n':
[794]                             *dst++ = '\n';
[795]                             src += 2;
[796]                             continue;
[797]                         }
[798] 
[799]                     }
[800]                     *dst++ = *src++;
[801]                 }
[802]                 *dst = '\0';
[803]                 word->len = len;
[804] 
[805]                 if (ch == ';') {
[806]                     return NGX_OK;
[807]                 }
[808] 
[809]                 if (ch == '{') {
[810]                     return NGX_CONF_BLOCK_START;
[811]                 }
[812] 
[813]                 found = 0;
[814]             }
[815]         }
[816]     }
[817] }
[818] 
[819] 
[820] char *
[821] ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[822] {
[823]     char        *rv;
[824]     ngx_int_t    n;
[825]     ngx_str_t   *value, file, name;
[826]     ngx_glob_t   gl;
[827] 
[828]     value = cf->args->elts;
[829]     file = value[1];
[830] 
[831]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[832] 
[833]     if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
[834]         return NGX_CONF_ERROR;
[835]     }
[836] 
[837]     if (strpbrk((char *) file.data, "*?[") == NULL) {
[838] 
[839]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[840] 
[841]         return ngx_conf_parse(cf, &file);
[842]     }
[843] 
[844]     ngx_memzero(&gl, sizeof(ngx_glob_t));
[845] 
[846]     gl.pattern = file.data;
[847]     gl.log = cf->log;
[848]     gl.test = 1;
[849] 
[850]     if (ngx_open_glob(&gl) != NGX_OK) {
[851]         ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
[852]                            ngx_open_glob_n " \"%s\" failed", file.data);
[853]         return NGX_CONF_ERROR;
[854]     }
[855] 
[856]     rv = NGX_CONF_OK;
[857] 
[858]     for ( ;; ) {
[859]         n = ngx_read_glob(&gl, &name);
[860] 
[861]         if (n != NGX_OK) {
[862]             break;
[863]         }
[864] 
[865]         file.len = name.len++;
[866]         file.data = ngx_pstrdup(cf->pool, &name);
[867]         if (file.data == NULL) {
[868]             return NGX_CONF_ERROR;
[869]         }
[870] 
[871]         ngx_log_debug1(NGX_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
[872] 
[873]         rv = ngx_conf_parse(cf, &file);
[874] 
[875]         if (rv != NGX_CONF_OK) {
[876]             break;
[877]         }
[878]     }
[879] 
[880]     ngx_close_glob(&gl);
[881] 
[882]     return rv;
[883] }
[884] 
[885] 
[886] ngx_int_t
[887] ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name, ngx_uint_t conf_prefix)
[888] {
[889]     ngx_str_t  *prefix;
[890] 
[891]     prefix = conf_prefix ? &cycle->conf_prefix : &cycle->prefix;
[892] 
[893]     return ngx_get_full_name(cycle->pool, prefix, name);
[894] }
[895] 
[896] 
[897] ngx_open_file_t *
[898] ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name)
[899] {
[900]     ngx_str_t         full;
[901]     ngx_uint_t        i;
[902]     ngx_list_part_t  *part;
[903]     ngx_open_file_t  *file;
[904] 
[905] #if (NGX_SUPPRESS_WARN)
[906]     ngx_str_null(&full);
[907] #endif
[908] 
[909]     if (name->len) {
[910]         full = *name;
[911] 
[912]         if (ngx_conf_full_name(cycle, &full, 0) != NGX_OK) {
[913]             return NULL;
[914]         }
[915] 
[916]         part = &cycle->open_files.part;
[917]         file = part->elts;
[918] 
[919]         for (i = 0; /* void */ ; i++) {
[920] 
[921]             if (i >= part->nelts) {
[922]                 if (part->next == NULL) {
[923]                     break;
[924]                 }
[925]                 part = part->next;
[926]                 file = part->elts;
[927]                 i = 0;
[928]             }
[929] 
[930]             if (full.len != file[i].name.len) {
[931]                 continue;
[932]             }
[933] 
[934]             if (ngx_strcmp(full.data, file[i].name.data) == 0) {
[935]                 return &file[i];
[936]             }
[937]         }
[938]     }
[939] 
[940]     file = ngx_list_push(&cycle->open_files);
[941]     if (file == NULL) {
[942]         return NULL;
[943]     }
[944] 
[945]     if (name->len) {
[946]         file->fd = NGX_INVALID_FILE;
[947]         file->name = full;
[948] 
[949]     } else {
[950]         file->fd = ngx_stderr;
[951]         file->name = *name;
[952]     }
[953] 
[954]     file->flush = NULL;
[955]     file->data = NULL;
[956] 
[957]     return file;
[958] }
[959] 
[960] 
[961] static void
[962] ngx_conf_flush_files(ngx_cycle_t *cycle)
[963] {
[964]     ngx_uint_t        i;
[965]     ngx_list_part_t  *part;
[966]     ngx_open_file_t  *file;
[967] 
[968]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "flush files");
[969] 
[970]     part = &cycle->open_files.part;
[971]     file = part->elts;
[972] 
[973]     for (i = 0; /* void */ ; i++) {
[974] 
[975]         if (i >= part->nelts) {
[976]             if (part->next == NULL) {
[977]                 break;
[978]             }
[979]             part = part->next;
[980]             file = part->elts;
[981]             i = 0;
[982]         }
[983] 
[984]         if (file[i].flush) {
[985]             file[i].flush(&file[i], cycle->log);
[986]         }
[987]     }
[988] }
[989] 
[990] 
[991] void ngx_cdecl
[992] ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
[993]     const char *fmt, ...)
[994] {
[995]     u_char   errstr[NGX_MAX_CONF_ERRSTR], *p, *last;
[996]     va_list  args;
[997] 
[998]     last = errstr + NGX_MAX_CONF_ERRSTR;
[999] 
[1000]     va_start(args, fmt);
[1001]     p = ngx_vslprintf(errstr, last, fmt, args);
[1002]     va_end(args);
[1003] 
[1004]     if (err) {
[1005]         p = ngx_log_errno(p, last, err);
[1006]     }
[1007] 
[1008]     if (cf->conf_file == NULL) {
[1009]         ngx_log_error(level, cf->log, 0, "%*s", p - errstr, errstr);
[1010]         return;
[1011]     }
[1012] 
[1013]     if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
[1014]         ngx_log_error(level, cf->log, 0, "%*s in command line",
[1015]                       p - errstr, errstr);
[1016]         return;
[1017]     }
[1018] 
[1019]     ngx_log_error(level, cf->log, 0, "%*s in %s:%ui",
[1020]                   p - errstr, errstr,
[1021]                   cf->conf_file->file.name.data, cf->conf_file->line);
[1022] }
[1023] 
[1024] 
[1025] char *
[1026] ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1027] {
[1028]     char  *p = conf;
[1029] 
[1030]     ngx_str_t        *value;
[1031]     ngx_flag_t       *fp;
[1032]     ngx_conf_post_t  *post;
[1033] 
[1034]     fp = (ngx_flag_t *) (p + cmd->offset);
[1035] 
[1036]     if (*fp != NGX_CONF_UNSET) {
[1037]         return "is duplicate";
[1038]     }
[1039] 
[1040]     value = cf->args->elts;
[1041] 
[1042]     if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
[1043]         *fp = 1;
[1044] 
[1045]     } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
[1046]         *fp = 0;
[1047] 
[1048]     } else {
[1049]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1050]                      "invalid value \"%s\" in \"%s\" directive, "
[1051]                      "it must be \"on\" or \"off\"",
[1052]                      value[1].data, cmd->name.data);
[1053]         return NGX_CONF_ERROR;
[1054]     }
[1055] 
[1056]     if (cmd->post) {
[1057]         post = cmd->post;
[1058]         return post->post_handler(cf, post, fp);
[1059]     }
[1060] 
[1061]     return NGX_CONF_OK;
[1062] }
[1063] 
[1064] 
[1065] char *
[1066] ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1067] {
[1068]     char  *p = conf;
[1069] 
[1070]     ngx_str_t        *field, *value;
[1071]     ngx_conf_post_t  *post;
[1072] 
[1073]     field = (ngx_str_t *) (p + cmd->offset);
[1074] 
[1075]     if (field->data) {
[1076]         return "is duplicate";
[1077]     }
[1078] 
[1079]     value = cf->args->elts;
[1080] 
[1081]     *field = value[1];
[1082] 
[1083]     if (cmd->post) {
[1084]         post = cmd->post;
[1085]         return post->post_handler(cf, post, field);
[1086]     }
[1087] 
[1088]     return NGX_CONF_OK;
[1089] }
[1090] 
[1091] 
[1092] char *
[1093] ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1094] {
[1095]     char  *p = conf;
[1096] 
[1097]     ngx_str_t         *value, *s;
[1098]     ngx_array_t      **a;
[1099]     ngx_conf_post_t   *post;
[1100] 
[1101]     a = (ngx_array_t **) (p + cmd->offset);
[1102] 
[1103]     if (*a == NGX_CONF_UNSET_PTR) {
[1104]         *a = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
[1105]         if (*a == NULL) {
[1106]             return NGX_CONF_ERROR;
[1107]         }
[1108]     }
[1109] 
[1110]     s = ngx_array_push(*a);
[1111]     if (s == NULL) {
[1112]         return NGX_CONF_ERROR;
[1113]     }
[1114] 
[1115]     value = cf->args->elts;
[1116] 
[1117]     *s = value[1];
[1118] 
[1119]     if (cmd->post) {
[1120]         post = cmd->post;
[1121]         return post->post_handler(cf, post, s);
[1122]     }
[1123] 
[1124]     return NGX_CONF_OK;
[1125] }
[1126] 
[1127] 
[1128] char *
[1129] ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1130] {
[1131]     char  *p = conf;
[1132] 
[1133]     ngx_str_t         *value;
[1134]     ngx_array_t      **a;
[1135]     ngx_keyval_t      *kv;
[1136]     ngx_conf_post_t   *post;
[1137] 
[1138]     a = (ngx_array_t **) (p + cmd->offset);
[1139] 
[1140]     if (*a == NGX_CONF_UNSET_PTR || *a == NULL) {
[1141]         *a = ngx_array_create(cf->pool, 4, sizeof(ngx_keyval_t));
[1142]         if (*a == NULL) {
[1143]             return NGX_CONF_ERROR;
[1144]         }
[1145]     }
[1146] 
[1147]     kv = ngx_array_push(*a);
[1148]     if (kv == NULL) {
[1149]         return NGX_CONF_ERROR;
[1150]     }
[1151] 
[1152]     value = cf->args->elts;
[1153] 
[1154]     kv->key = value[1];
[1155]     kv->value = value[2];
[1156] 
[1157]     if (cmd->post) {
[1158]         post = cmd->post;
[1159]         return post->post_handler(cf, post, kv);
[1160]     }
[1161] 
[1162]     return NGX_CONF_OK;
[1163] }
[1164] 
[1165] 
[1166] char *
[1167] ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1168] {
[1169]     char  *p = conf;
[1170] 
[1171]     ngx_int_t        *np;
[1172]     ngx_str_t        *value;
[1173]     ngx_conf_post_t  *post;
[1174] 
[1175] 
[1176]     np = (ngx_int_t *) (p + cmd->offset);
[1177] 
[1178]     if (*np != NGX_CONF_UNSET) {
[1179]         return "is duplicate";
[1180]     }
[1181] 
[1182]     value = cf->args->elts;
[1183]     *np = ngx_atoi(value[1].data, value[1].len);
[1184]     if (*np == NGX_ERROR) {
[1185]         return "invalid number";
[1186]     }
[1187] 
[1188]     if (cmd->post) {
[1189]         post = cmd->post;
[1190]         return post->post_handler(cf, post, np);
[1191]     }
[1192] 
[1193]     return NGX_CONF_OK;
[1194] }
[1195] 
[1196] 
[1197] char *
[1198] ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1199] {
[1200]     char  *p = conf;
[1201] 
[1202]     size_t           *sp;
[1203]     ngx_str_t        *value;
[1204]     ngx_conf_post_t  *post;
[1205] 
[1206] 
[1207]     sp = (size_t *) (p + cmd->offset);
[1208]     if (*sp != NGX_CONF_UNSET_SIZE) {
[1209]         return "is duplicate";
[1210]     }
[1211] 
[1212]     value = cf->args->elts;
[1213] 
[1214]     *sp = ngx_parse_size(&value[1]);
[1215]     if (*sp == (size_t) NGX_ERROR) {
[1216]         return "invalid value";
[1217]     }
[1218] 
[1219]     if (cmd->post) {
[1220]         post = cmd->post;
[1221]         return post->post_handler(cf, post, sp);
[1222]     }
[1223] 
[1224]     return NGX_CONF_OK;
[1225] }
[1226] 
[1227] 
[1228] char *
[1229] ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1230] {
[1231]     char  *p = conf;
[1232] 
[1233]     off_t            *op;
[1234]     ngx_str_t        *value;
[1235]     ngx_conf_post_t  *post;
[1236] 
[1237] 
[1238]     op = (off_t *) (p + cmd->offset);
[1239]     if (*op != NGX_CONF_UNSET) {
[1240]         return "is duplicate";
[1241]     }
[1242] 
[1243]     value = cf->args->elts;
[1244] 
[1245]     *op = ngx_parse_offset(&value[1]);
[1246]     if (*op == (off_t) NGX_ERROR) {
[1247]         return "invalid value";
[1248]     }
[1249] 
[1250]     if (cmd->post) {
[1251]         post = cmd->post;
[1252]         return post->post_handler(cf, post, op);
[1253]     }
[1254] 
[1255]     return NGX_CONF_OK;
[1256] }
[1257] 
[1258] 
[1259] char *
[1260] ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1261] {
[1262]     char  *p = conf;
[1263] 
[1264]     ngx_msec_t       *msp;
[1265]     ngx_str_t        *value;
[1266]     ngx_conf_post_t  *post;
[1267] 
[1268] 
[1269]     msp = (ngx_msec_t *) (p + cmd->offset);
[1270]     if (*msp != NGX_CONF_UNSET_MSEC) {
[1271]         return "is duplicate";
[1272]     }
[1273] 
[1274]     value = cf->args->elts;
[1275] 
[1276]     *msp = ngx_parse_time(&value[1], 0);
[1277]     if (*msp == (ngx_msec_t) NGX_ERROR) {
[1278]         return "invalid value";
[1279]     }
[1280] 
[1281]     if (cmd->post) {
[1282]         post = cmd->post;
[1283]         return post->post_handler(cf, post, msp);
[1284]     }
[1285] 
[1286]     return NGX_CONF_OK;
[1287] }
[1288] 
[1289] 
[1290] char *
[1291] ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1292] {
[1293]     char  *p = conf;
[1294] 
[1295]     time_t           *sp;
[1296]     ngx_str_t        *value;
[1297]     ngx_conf_post_t  *post;
[1298] 
[1299] 
[1300]     sp = (time_t *) (p + cmd->offset);
[1301]     if (*sp != NGX_CONF_UNSET) {
[1302]         return "is duplicate";
[1303]     }
[1304] 
[1305]     value = cf->args->elts;
[1306] 
[1307]     *sp = ngx_parse_time(&value[1], 1);
[1308]     if (*sp == (time_t) NGX_ERROR) {
[1309]         return "invalid value";
[1310]     }
[1311] 
[1312]     if (cmd->post) {
[1313]         post = cmd->post;
[1314]         return post->post_handler(cf, post, sp);
[1315]     }
[1316] 
[1317]     return NGX_CONF_OK;
[1318] }
[1319] 
[1320] 
[1321] char *
[1322] ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1323] {
[1324]     char *p = conf;
[1325] 
[1326]     ngx_str_t   *value;
[1327]     ngx_bufs_t  *bufs;
[1328] 
[1329] 
[1330]     bufs = (ngx_bufs_t *) (p + cmd->offset);
[1331]     if (bufs->num) {
[1332]         return "is duplicate";
[1333]     }
[1334] 
[1335]     value = cf->args->elts;
[1336] 
[1337]     bufs->num = ngx_atoi(value[1].data, value[1].len);
[1338]     if (bufs->num == NGX_ERROR || bufs->num == 0) {
[1339]         return "invalid value";
[1340]     }
[1341] 
[1342]     bufs->size = ngx_parse_size(&value[2]);
[1343]     if (bufs->size == (size_t) NGX_ERROR || bufs->size == 0) {
[1344]         return "invalid value";
[1345]     }
[1346] 
[1347]     return NGX_CONF_OK;
[1348] }
[1349] 
[1350] 
[1351] char *
[1352] ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1353] {
[1354]     char  *p = conf;
[1355] 
[1356]     ngx_uint_t       *np, i;
[1357]     ngx_str_t        *value;
[1358]     ngx_conf_enum_t  *e;
[1359] 
[1360]     np = (ngx_uint_t *) (p + cmd->offset);
[1361] 
[1362]     if (*np != NGX_CONF_UNSET_UINT) {
[1363]         return "is duplicate";
[1364]     }
[1365] 
[1366]     value = cf->args->elts;
[1367]     e = cmd->post;
[1368] 
[1369]     for (i = 0; e[i].name.len != 0; i++) {
[1370]         if (e[i].name.len != value[1].len
[1371]             || ngx_strcasecmp(e[i].name.data, value[1].data) != 0)
[1372]         {
[1373]             continue;
[1374]         }
[1375] 
[1376]         *np = e[i].value;
[1377] 
[1378]         return NGX_CONF_OK;
[1379]     }
[1380] 
[1381]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1382]                        "invalid value \"%s\"", value[1].data);
[1383] 
[1384]     return NGX_CONF_ERROR;
[1385] }
[1386] 
[1387] 
[1388] char *
[1389] ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1390] {
[1391]     char  *p = conf;
[1392] 
[1393]     ngx_uint_t          *np, i, m;
[1394]     ngx_str_t           *value;
[1395]     ngx_conf_bitmask_t  *mask;
[1396] 
[1397] 
[1398]     np = (ngx_uint_t *) (p + cmd->offset);
[1399]     value = cf->args->elts;
[1400]     mask = cmd->post;
[1401] 
[1402]     for (i = 1; i < cf->args->nelts; i++) {
[1403]         for (m = 0; mask[m].name.len != 0; m++) {
[1404] 
[1405]             if (mask[m].name.len != value[i].len
[1406]                 || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
[1407]             {
[1408]                 continue;
[1409]             }
[1410] 
[1411]             if (*np & mask[m].mask) {
[1412]                 ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1413]                                    "duplicate value \"%s\"", value[i].data);
[1414] 
[1415]             } else {
[1416]                 *np |= mask[m].mask;
[1417]             }
[1418] 
[1419]             break;
[1420]         }
[1421] 
[1422]         if (mask[m].name.len == 0) {
[1423]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1424]                                "invalid value \"%s\"", value[i].data);
[1425] 
[1426]             return NGX_CONF_ERROR;
[1427]         }
[1428]     }
[1429] 
[1430]     return NGX_CONF_OK;
[1431] }
[1432] 
[1433] 
[1434] #if 0
[1435] 
[1436] char *
[1437] ngx_conf_unsupported(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[1438] {
[1439]     return "unsupported on this platform";
[1440] }
[1441] 
[1442] #endif
[1443] 
[1444] 
[1445] char *
[1446] ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data)
[1447] {
[1448]     ngx_conf_deprecated_t  *d = post;
[1449] 
[1450]     ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
[1451]                        "the \"%s\" directive is deprecated, "
[1452]                        "use the \"%s\" directive instead",
[1453]                        d->old_name, d->new_name);
[1454] 
[1455]     return NGX_CONF_OK;
[1456] }
[1457] 
[1458] 
[1459] char *
[1460] ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data)
[1461] {
[1462]     ngx_conf_num_bounds_t  *bounds = post;
[1463]     ngx_int_t  *np = data;
[1464] 
[1465]     if (bounds->high == -1) {
[1466]         if (*np >= bounds->low) {
[1467]             return NGX_CONF_OK;
[1468]         }
[1469] 
[1470]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1471]                            "value must be equal to or greater than %i",
[1472]                            bounds->low);
[1473] 
[1474]         return NGX_CONF_ERROR;
[1475]     }
[1476] 
[1477]     if (*np >= bounds->low && *np <= bounds->high) {
[1478]         return NGX_CONF_OK;
[1479]     }
[1480] 
[1481]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[1482]                        "value must be between %i and %i",
[1483]                        bounds->low, bounds->high);
[1484] 
[1485]     return NGX_CONF_ERROR;
[1486] }
