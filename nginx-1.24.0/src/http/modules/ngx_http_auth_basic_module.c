[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_http.h>
[11] #include <ngx_crypt.h>
[12] 
[13] 
[14] #define NGX_HTTP_AUTH_BUF_SIZE  2048
[15] 
[16] 
[17] typedef struct {
[18]     ngx_http_complex_value_t  *realm;
[19]     ngx_http_complex_value_t  *user_file;
[20] } ngx_http_auth_basic_loc_conf_t;
[21] 
[22] 
[23] static ngx_int_t ngx_http_auth_basic_handler(ngx_http_request_t *r);
[24] static ngx_int_t ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r,
[25]     ngx_str_t *passwd, ngx_str_t *realm);
[26] static ngx_int_t ngx_http_auth_basic_set_realm(ngx_http_request_t *r,
[27]     ngx_str_t *realm);
[28] static void *ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf);
[29] static char *ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf,
[30]     void *parent, void *child);
[31] static ngx_int_t ngx_http_auth_basic_init(ngx_conf_t *cf);
[32] static char *ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
[33]     void *conf);
[34] 
[35] 
[36] static ngx_command_t  ngx_http_auth_basic_commands[] = {
[37] 
[38]     { ngx_string("auth_basic"),
[39]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
[40]                         |NGX_CONF_TAKE1,
[41]       ngx_http_set_complex_value_slot,
[42]       NGX_HTTP_LOC_CONF_OFFSET,
[43]       offsetof(ngx_http_auth_basic_loc_conf_t, realm),
[44]       NULL },
[45] 
[46]     { ngx_string("auth_basic_user_file"),
[47]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
[48]                         |NGX_CONF_TAKE1,
[49]       ngx_http_auth_basic_user_file,
[50]       NGX_HTTP_LOC_CONF_OFFSET,
[51]       offsetof(ngx_http_auth_basic_loc_conf_t, user_file),
[52]       NULL },
[53] 
[54]       ngx_null_command
[55] };
[56] 
[57] 
[58] static ngx_http_module_t  ngx_http_auth_basic_module_ctx = {
[59]     NULL,                                  /* preconfiguration */
[60]     ngx_http_auth_basic_init,              /* postconfiguration */
[61] 
[62]     NULL,                                  /* create main configuration */
[63]     NULL,                                  /* init main configuration */
[64] 
[65]     NULL,                                  /* create server configuration */
[66]     NULL,                                  /* merge server configuration */
[67] 
[68]     ngx_http_auth_basic_create_loc_conf,   /* create location configuration */
[69]     ngx_http_auth_basic_merge_loc_conf     /* merge location configuration */
[70] };
[71] 
[72] 
[73] ngx_module_t  ngx_http_auth_basic_module = {
[74]     NGX_MODULE_V1,
[75]     &ngx_http_auth_basic_module_ctx,       /* module context */
[76]     ngx_http_auth_basic_commands,          /* module directives */
[77]     NGX_HTTP_MODULE,                       /* module type */
[78]     NULL,                                  /* init master */
[79]     NULL,                                  /* init module */
[80]     NULL,                                  /* init process */
[81]     NULL,                                  /* init thread */
[82]     NULL,                                  /* exit thread */
[83]     NULL,                                  /* exit process */
[84]     NULL,                                  /* exit master */
[85]     NGX_MODULE_V1_PADDING
[86] };
[87] 
[88] 
[89] static ngx_int_t
[90] ngx_http_auth_basic_handler(ngx_http_request_t *r)
[91] {
[92]     off_t                            offset;
[93]     ssize_t                          n;
[94]     ngx_fd_t                         fd;
[95]     ngx_int_t                        rc;
[96]     ngx_err_t                        err;
[97]     ngx_str_t                        pwd, realm, user_file;
[98]     ngx_uint_t                       i, level, login, left, passwd;
[99]     ngx_file_t                       file;
[100]     ngx_http_auth_basic_loc_conf_t  *alcf;
[101]     u_char                           buf[NGX_HTTP_AUTH_BUF_SIZE];
[102]     enum {
[103]         sw_login,
[104]         sw_passwd,
[105]         sw_skip
[106]     } state;
[107] 
[108]     alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_module);
[109] 
[110]     if (alcf->realm == NULL || alcf->user_file == NULL) {
[111]         return NGX_DECLINED;
[112]     }
[113] 
[114]     if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
[115]         return NGX_ERROR;
[116]     }
[117] 
[118]     if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
[119]         return NGX_DECLINED;
[120]     }
[121] 
[122]     rc = ngx_http_auth_basic_user(r);
[123] 
[124]     if (rc == NGX_DECLINED) {
[125] 
[126]         ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
[127]                       "no user/password was provided for basic authentication");
[128] 
[129]         return ngx_http_auth_basic_set_realm(r, &realm);
[130]     }
[131] 
[132]     if (rc == NGX_ERROR) {
[133]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[134]     }
[135] 
[136]     if (ngx_http_complex_value(r, alcf->user_file, &user_file) != NGX_OK) {
[137]         return NGX_ERROR;
[138]     }
[139] 
[140]     fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
[141] 
[142]     if (fd == NGX_INVALID_FILE) {
[143]         err = ngx_errno;
[144] 
[145]         if (err == NGX_ENOENT) {
[146]             level = NGX_LOG_ERR;
[147]             rc = NGX_HTTP_FORBIDDEN;
[148] 
[149]         } else {
[150]             level = NGX_LOG_CRIT;
[151]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[152]         }
[153] 
[154]         ngx_log_error(level, r->connection->log, err,
[155]                       ngx_open_file_n " \"%s\" failed", user_file.data);
[156] 
[157]         return rc;
[158]     }
[159] 
[160]     ngx_memzero(&file, sizeof(ngx_file_t));
[161] 
[162]     file.fd = fd;
[163]     file.name = user_file;
[164]     file.log = r->connection->log;
[165] 
[166]     state = sw_login;
[167]     passwd = 0;
[168]     login = 0;
[169]     left = 0;
[170]     offset = 0;
[171] 
[172]     for ( ;; ) {
[173]         i = left;
[174] 
[175]         n = ngx_read_file(&file, buf + left, NGX_HTTP_AUTH_BUF_SIZE - left,
[176]                           offset);
[177] 
[178]         if (n == NGX_ERROR) {
[179]             rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[180]             goto cleanup;
[181]         }
[182] 
[183]         if (n == 0) {
[184]             break;
[185]         }
[186] 
[187]         for (i = left; i < left + n; i++) {
[188]             switch (state) {
[189] 
[190]             case sw_login:
[191]                 if (login == 0) {
[192] 
[193]                     if (buf[i] == '#' || buf[i] == CR) {
[194]                         state = sw_skip;
[195]                         break;
[196]                     }
[197] 
[198]                     if (buf[i] == LF) {
[199]                         break;
[200]                     }
[201]                 }
[202] 
[203]                 if (buf[i] != r->headers_in.user.data[login]) {
[204]                     state = sw_skip;
[205]                     break;
[206]                 }
[207] 
[208]                 if (login == r->headers_in.user.len) {
[209]                     state = sw_passwd;
[210]                     passwd = i + 1;
[211]                 }
[212] 
[213]                 login++;
[214] 
[215]                 break;
[216] 
[217]             case sw_passwd:
[218]                 if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
[219]                     buf[i] = '\0';
[220] 
[221]                     pwd.len = i - passwd;
[222]                     pwd.data = &buf[passwd];
[223] 
[224]                     rc = ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
[225]                     goto cleanup;
[226]                 }
[227] 
[228]                 break;
[229] 
[230]             case sw_skip:
[231]                 if (buf[i] == LF) {
[232]                     state = sw_login;
[233]                     login = 0;
[234]                 }
[235] 
[236]                 break;
[237]             }
[238]         }
[239] 
[240]         if (state == sw_passwd) {
[241]             left = left + n - passwd;
[242]             ngx_memmove(buf, &buf[passwd], left);
[243]             passwd = 0;
[244] 
[245]         } else {
[246]             left = 0;
[247]         }
[248] 
[249]         offset += n;
[250]     }
[251] 
[252]     if (state == sw_passwd) {
[253]         pwd.len = i - passwd;
[254]         pwd.data = ngx_pnalloc(r->pool, pwd.len + 1);
[255]         if (pwd.data == NULL) {
[256]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[257]         }
[258] 
[259]         ngx_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);
[260] 
[261]         rc = ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
[262]         goto cleanup;
[263]     }
[264] 
[265]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[266]                   "user \"%V\" was not found in \"%s\"",
[267]                   &r->headers_in.user, user_file.data);
[268] 
[269]     rc = ngx_http_auth_basic_set_realm(r, &realm);
[270] 
[271] cleanup:
[272] 
[273]     if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
[274]         ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
[275]                       ngx_close_file_n " \"%s\" failed", user_file.data);
[276]     }
[277] 
[278]     ngx_explicit_memzero(buf, NGX_HTTP_AUTH_BUF_SIZE);
[279] 
[280]     return rc;
[281] }
[282] 
[283] 
[284] static ngx_int_t
[285] ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r, ngx_str_t *passwd,
[286]     ngx_str_t *realm)
[287] {
[288]     ngx_int_t   rc;
[289]     u_char     *encrypted;
[290] 
[291]     rc = ngx_crypt(r->pool, r->headers_in.passwd.data, passwd->data,
[292]                    &encrypted);
[293] 
[294]     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[295]                    "rc: %i user: \"%V\" salt: \"%s\"",
[296]                    rc, &r->headers_in.user, passwd->data);
[297] 
[298]     if (rc != NGX_OK) {
[299]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[300]     }
[301] 
[302]     if (ngx_strcmp(encrypted, passwd->data) == 0) {
[303]         return NGX_OK;
[304]     }
[305] 
[306]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[307]                    "encrypted: \"%s\"", encrypted);
[308] 
[309]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[310]                   "user \"%V\": password mismatch",
[311]                   &r->headers_in.user);
[312] 
[313]     return ngx_http_auth_basic_set_realm(r, realm);
[314] }
[315] 
[316] 
[317] static ngx_int_t
[318] ngx_http_auth_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
[319] {
[320]     size_t   len;
[321]     u_char  *basic, *p;
[322] 
[323]     r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
[324]     if (r->headers_out.www_authenticate == NULL) {
[325]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[326]     }
[327] 
[328]     len = sizeof("Basic realm=\"\"") - 1 + realm->len;
[329] 
[330]     basic = ngx_pnalloc(r->pool, len);
[331]     if (basic == NULL) {
[332]         r->headers_out.www_authenticate->hash = 0;
[333]         r->headers_out.www_authenticate = NULL;
[334]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[335]     }
[336] 
[337]     p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
[338]     p = ngx_cpymem(p, realm->data, realm->len);
[339]     *p = '"';
[340] 
[341]     r->headers_out.www_authenticate->hash = 1;
[342]     r->headers_out.www_authenticate->next = NULL;
[343]     ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
[344]     r->headers_out.www_authenticate->value.data = basic;
[345]     r->headers_out.www_authenticate->value.len = len;
[346] 
[347]     return NGX_HTTP_UNAUTHORIZED;
[348] }
[349] 
[350] 
[351] static void *
[352] ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf)
[353] {
[354]     ngx_http_auth_basic_loc_conf_t  *conf;
[355] 
[356]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_loc_conf_t));
[357]     if (conf == NULL) {
[358]         return NULL;
[359]     }
[360] 
[361]     conf->realm = NGX_CONF_UNSET_PTR;
[362]     conf->user_file = NGX_CONF_UNSET_PTR;
[363] 
[364]     return conf;
[365] }
[366] 
[367] 
[368] static char *
[369] ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[370] {
[371]     ngx_http_auth_basic_loc_conf_t  *prev = parent;
[372]     ngx_http_auth_basic_loc_conf_t  *conf = child;
[373] 
[374]     ngx_conf_merge_ptr_value(conf->realm, prev->realm, NULL);
[375]     ngx_conf_merge_ptr_value(conf->user_file, prev->user_file, NULL);
[376] 
[377]     return NGX_CONF_OK;
[378] }
[379] 
[380] 
[381] static ngx_int_t
[382] ngx_http_auth_basic_init(ngx_conf_t *cf)
[383] {
[384]     ngx_http_handler_pt        *h;
[385]     ngx_http_core_main_conf_t  *cmcf;
[386] 
[387]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[388] 
[389]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
[390]     if (h == NULL) {
[391]         return NGX_ERROR;
[392]     }
[393] 
[394]     *h = ngx_http_auth_basic_handler;
[395] 
[396]     return NGX_OK;
[397] }
[398] 
[399] 
[400] static char *
[401] ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[402] {
[403]     ngx_http_auth_basic_loc_conf_t *alcf = conf;
[404] 
[405]     ngx_str_t                         *value;
[406]     ngx_http_compile_complex_value_t   ccv;
[407] 
[408]     if (alcf->user_file != NGX_CONF_UNSET_PTR) {
[409]         return "is duplicate";
[410]     }
[411] 
[412]     alcf->user_file = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
[413]     if (alcf->user_file == NULL) {
[414]         return NGX_CONF_ERROR;
[415]     }
[416] 
[417]     value = cf->args->elts;
[418] 
[419]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[420] 
[421]     ccv.cf = cf;
[422]     ccv.value = &value[1];
[423]     ccv.complex_value = alcf->user_file;
[424]     ccv.zero = 1;
[425]     ccv.conf_prefix = 1;
[426] 
[427]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[428]         return NGX_CONF_ERROR;
[429]     }
[430] 
[431]     return NGX_CONF_OK;
[432] }
