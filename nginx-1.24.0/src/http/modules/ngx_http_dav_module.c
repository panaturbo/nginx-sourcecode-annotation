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
[11] 
[12] 
[13] #define NGX_HTTP_DAV_OFF             2
[14] 
[15] 
[16] #define NGX_HTTP_DAV_NO_DEPTH        -3
[17] #define NGX_HTTP_DAV_INVALID_DEPTH   -2
[18] #define NGX_HTTP_DAV_INFINITY_DEPTH  -1
[19] 
[20] 
[21] typedef struct {
[22]     ngx_uint_t  methods;
[23]     ngx_uint_t  access;
[24]     ngx_uint_t  min_delete_depth;
[25]     ngx_flag_t  create_full_put_path;
[26] } ngx_http_dav_loc_conf_t;
[27] 
[28] 
[29] typedef struct {
[30]     ngx_str_t   path;
[31]     size_t      len;
[32] } ngx_http_dav_copy_ctx_t;
[33] 
[34] 
[35] static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);
[36] 
[37] static void ngx_http_dav_put_handler(ngx_http_request_t *r);
[38] 
[39] static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
[40] static ngx_int_t ngx_http_dav_delete_path(ngx_http_request_t *r,
[41]     ngx_str_t *path, ngx_uint_t dir);
[42] static ngx_int_t ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
[43] static ngx_int_t ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
[44] static ngx_int_t ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path);
[45] 
[46] static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r,
[47]     ngx_http_dav_loc_conf_t *dlcf);
[48] 
[49] static ngx_int_t ngx_http_dav_copy_move_handler(ngx_http_request_t *r);
[50] static ngx_int_t ngx_http_dav_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
[51] static ngx_int_t ngx_http_dav_copy_dir_time(ngx_tree_ctx_t *ctx,
[52]     ngx_str_t *path);
[53] static ngx_int_t ngx_http_dav_copy_tree_file(ngx_tree_ctx_t *ctx,
[54]     ngx_str_t *path);
[55] 
[56] static ngx_int_t ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt);
[57] static ngx_int_t ngx_http_dav_error(ngx_log_t *log, ngx_err_t err,
[58]     ngx_int_t not_found, char *failed, u_char *path);
[59] static ngx_int_t ngx_http_dav_location(ngx_http_request_t *r);
[60] static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
[61] static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf,
[62]     void *parent, void *child);
[63] static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);
[64] 
[65] 
[66] static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
[67]     { ngx_string("off"), NGX_HTTP_DAV_OFF },
[68]     { ngx_string("put"), NGX_HTTP_PUT },
[69]     { ngx_string("delete"), NGX_HTTP_DELETE },
[70]     { ngx_string("mkcol"), NGX_HTTP_MKCOL },
[71]     { ngx_string("copy"), NGX_HTTP_COPY },
[72]     { ngx_string("move"), NGX_HTTP_MOVE },
[73]     { ngx_null_string, 0 }
[74] };
[75] 
[76] 
[77] static ngx_command_t  ngx_http_dav_commands[] = {
[78] 
[79]     { ngx_string("dav_methods"),
[80]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
[81]       ngx_conf_set_bitmask_slot,
[82]       NGX_HTTP_LOC_CONF_OFFSET,
[83]       offsetof(ngx_http_dav_loc_conf_t, methods),
[84]       &ngx_http_dav_methods_mask },
[85] 
[86]     { ngx_string("create_full_put_path"),
[87]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
[88]       ngx_conf_set_flag_slot,
[89]       NGX_HTTP_LOC_CONF_OFFSET,
[90]       offsetof(ngx_http_dav_loc_conf_t, create_full_put_path),
[91]       NULL },
[92] 
[93]     { ngx_string("min_delete_depth"),
[94]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[95]       ngx_conf_set_num_slot,
[96]       NGX_HTTP_LOC_CONF_OFFSET,
[97]       offsetof(ngx_http_dav_loc_conf_t, min_delete_depth),
[98]       NULL },
[99] 
[100]     { ngx_string("dav_access"),
[101]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
[102]       ngx_conf_set_access_slot,
[103]       NGX_HTTP_LOC_CONF_OFFSET,
[104]       offsetof(ngx_http_dav_loc_conf_t, access),
[105]       NULL },
[106] 
[107]       ngx_null_command
[108] };
[109] 
[110] 
[111] static ngx_http_module_t  ngx_http_dav_module_ctx = {
[112]     NULL,                                  /* preconfiguration */
[113]     ngx_http_dav_init,                     /* postconfiguration */
[114] 
[115]     NULL,                                  /* create main configuration */
[116]     NULL,                                  /* init main configuration */
[117] 
[118]     NULL,                                  /* create server configuration */
[119]     NULL,                                  /* merge server configuration */
[120] 
[121]     ngx_http_dav_create_loc_conf,          /* create location configuration */
[122]     ngx_http_dav_merge_loc_conf            /* merge location configuration */
[123] };
[124] 
[125] 
[126] ngx_module_t  ngx_http_dav_module = {
[127]     NGX_MODULE_V1,
[128]     &ngx_http_dav_module_ctx,              /* module context */
[129]     ngx_http_dav_commands,                 /* module directives */
[130]     NGX_HTTP_MODULE,                       /* module type */
[131]     NULL,                                  /* init master */
[132]     NULL,                                  /* init module */
[133]     NULL,                                  /* init process */
[134]     NULL,                                  /* init thread */
[135]     NULL,                                  /* exit thread */
[136]     NULL,                                  /* exit process */
[137]     NULL,                                  /* exit master */
[138]     NGX_MODULE_V1_PADDING
[139] };
[140] 
[141] 
[142] static ngx_int_t
[143] ngx_http_dav_handler(ngx_http_request_t *r)
[144] {
[145]     ngx_int_t                 rc;
[146]     ngx_http_dav_loc_conf_t  *dlcf;
[147] 
[148]     dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
[149] 
[150]     if (!(r->method & dlcf->methods)) {
[151]         return NGX_DECLINED;
[152]     }
[153] 
[154]     switch (r->method) {
[155] 
[156]     case NGX_HTTP_PUT:
[157] 
[158]         if (r->uri.data[r->uri.len - 1] == '/') {
[159]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[160]                           "cannot PUT to a collection");
[161]             return NGX_HTTP_CONFLICT;
[162]         }
[163] 
[164]         if (r->headers_in.content_range) {
[165]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[166]                           "PUT with range is unsupported");
[167]             return NGX_HTTP_NOT_IMPLEMENTED;
[168]         }
[169] 
[170]         r->request_body_in_file_only = 1;
[171]         r->request_body_in_persistent_file = 1;
[172]         r->request_body_in_clean_file = 1;
[173]         r->request_body_file_group_access = 1;
[174]         r->request_body_file_log_level = 0;
[175] 
[176]         rc = ngx_http_read_client_request_body(r, ngx_http_dav_put_handler);
[177] 
[178]         if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[179]             return rc;
[180]         }
[181] 
[182]         return NGX_DONE;
[183] 
[184]     case NGX_HTTP_DELETE:
[185] 
[186]         return ngx_http_dav_delete_handler(r);
[187] 
[188]     case NGX_HTTP_MKCOL:
[189] 
[190]         return ngx_http_dav_mkcol_handler(r, dlcf);
[191] 
[192]     case NGX_HTTP_COPY:
[193] 
[194]         return ngx_http_dav_copy_move_handler(r);
[195] 
[196]     case NGX_HTTP_MOVE:
[197] 
[198]         return ngx_http_dav_copy_move_handler(r);
[199]     }
[200] 
[201]     return NGX_DECLINED;
[202] }
[203] 
[204] 
[205] static void
[206] ngx_http_dav_put_handler(ngx_http_request_t *r)
[207] {
[208]     size_t                    root;
[209]     time_t                    date;
[210]     ngx_str_t                *temp, path;
[211]     ngx_uint_t                status;
[212]     ngx_file_info_t           fi;
[213]     ngx_ext_rename_file_t     ext;
[214]     ngx_http_dav_loc_conf_t  *dlcf;
[215] 
[216]     if (r->request_body == NULL) {
[217]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[218]                       "PUT request body is unavailable");
[219]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[220]         return;
[221]     }
[222] 
[223]     if (r->request_body->temp_file == NULL) {
[224]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[225]                       "PUT request body must be in a file");
[226]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[227]         return;
[228]     }
[229] 
[230]     if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
[231]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[232]         return;
[233]     }
[234] 
[235]     path.len--;
[236] 
[237]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[238]                    "http put filename: \"%s\"", path.data);
[239] 
[240]     temp = &r->request_body->temp_file->file.name;
[241] 
[242]     if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
[243]         status = NGX_HTTP_CREATED;
[244] 
[245]     } else {
[246]         status = NGX_HTTP_NO_CONTENT;
[247] 
[248]         if (ngx_is_dir(&fi)) {
[249]             ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
[250]                           "\"%s\" could not be created", path.data);
[251] 
[252]             if (ngx_delete_file(temp->data) == NGX_FILE_ERROR) {
[253]                 ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[254]                               ngx_delete_file_n " \"%s\" failed",
[255]                               temp->data);
[256]             }
[257] 
[258]             ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
[259]             return;
[260]         }
[261]     }
[262] 
[263]     dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
[264] 
[265]     ext.access = dlcf->access;
[266]     ext.path_access = dlcf->access;
[267]     ext.time = -1;
[268]     ext.create_path = dlcf->create_full_put_path;
[269]     ext.delete_file = 1;
[270]     ext.log = r->connection->log;
[271] 
[272]     if (r->headers_in.date) {
[273]         date = ngx_parse_http_time(r->headers_in.date->value.data,
[274]                                    r->headers_in.date->value.len);
[275] 
[276]         if (date != NGX_ERROR) {
[277]             ext.time = date;
[278]             ext.fd = r->request_body->temp_file->file.fd;
[279]         }
[280]     }
[281] 
[282]     if (ngx_ext_rename_file(temp, &path, &ext) != NGX_OK) {
[283]         ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[284]         return;
[285]     }
[286] 
[287]     if (status == NGX_HTTP_CREATED) {
[288]         if (ngx_http_dav_location(r) != NGX_OK) {
[289]             ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
[290]             return;
[291]         }
[292] 
[293]         r->headers_out.content_length_n = 0;
[294]     }
[295] 
[296]     r->headers_out.status = status;
[297]     r->header_only = 1;
[298] 
[299]     ngx_http_finalize_request(r, ngx_http_send_header(r));
[300]     return;
[301] }
[302] 
[303] 
[304] static ngx_int_t
[305] ngx_http_dav_delete_handler(ngx_http_request_t *r)
[306] {
[307]     size_t                    root;
[308]     ngx_err_t                 err;
[309]     ngx_int_t                 rc, depth;
[310]     ngx_uint_t                i, d, dir;
[311]     ngx_str_t                 path;
[312]     ngx_file_info_t           fi;
[313]     ngx_http_dav_loc_conf_t  *dlcf;
[314] 
[315]     if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
[316]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[317]                       "DELETE with body is unsupported");
[318]         return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
[319]     }
[320] 
[321]     dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
[322] 
[323]     if (dlcf->min_delete_depth) {
[324]         d = 0;
[325] 
[326]         for (i = 0; i < r->uri.len; /* void */) {
[327]             if (r->uri.data[i++] == '/') {
[328]                 if (++d >= dlcf->min_delete_depth && i < r->uri.len) {
[329]                     goto ok;
[330]                 }
[331]             }
[332]         }
[333] 
[334]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[335]                       "insufficient URI depth:%i to DELETE", d);
[336]         return NGX_HTTP_CONFLICT;
[337]     }
[338] 
[339] ok:
[340] 
[341]     if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
[342]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[343]     }
[344] 
[345]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[346]                    "http delete filename: \"%s\"", path.data);
[347] 
[348]     if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
[349]         err = ngx_errno;
[350] 
[351]         rc = (err == NGX_ENOTDIR) ? NGX_HTTP_CONFLICT : NGX_HTTP_NOT_FOUND;
[352] 
[353]         return ngx_http_dav_error(r->connection->log, err,
[354]                                   rc, ngx_link_info_n, path.data);
[355]     }
[356] 
[357]     if (ngx_is_dir(&fi)) {
[358] 
[359]         if (r->uri.data[r->uri.len - 1] != '/') {
[360]             ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
[361]                           "DELETE \"%s\" failed", path.data);
[362]             return NGX_HTTP_CONFLICT;
[363]         }
[364] 
[365]         depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
[366] 
[367]         if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
[368]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[369]                           "\"Depth\" header must be infinity");
[370]             return NGX_HTTP_BAD_REQUEST;
[371]         }
[372] 
[373]         path.len -= 2;  /* omit "/\0" */
[374] 
[375]         dir = 1;
[376] 
[377]     } else {
[378] 
[379]         /*
[380]          * we do not need to test (r->uri.data[r->uri.len - 1] == '/')
[381]          * because ngx_link_info("/file/") returned NGX_ENOTDIR above
[382]          */
[383] 
[384]         depth = ngx_http_dav_depth(r, 0);
[385] 
[386]         if (depth != 0 && depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
[387]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[388]                           "\"Depth\" header must be 0 or infinity");
[389]             return NGX_HTTP_BAD_REQUEST;
[390]         }
[391] 
[392]         dir = 0;
[393]     }
[394] 
[395]     rc = ngx_http_dav_delete_path(r, &path, dir);
[396] 
[397]     if (rc == NGX_OK) {
[398]         return NGX_HTTP_NO_CONTENT;
[399]     }
[400] 
[401]     return rc;
[402] }
[403] 
[404] 
[405] static ngx_int_t
[406] ngx_http_dav_delete_path(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir)
[407] {
[408]     char            *failed;
[409]     ngx_tree_ctx_t   tree;
[410] 
[411]     if (dir) {
[412] 
[413]         tree.init_handler = NULL;
[414]         tree.file_handler = ngx_http_dav_delete_file;
[415]         tree.pre_tree_handler = ngx_http_dav_noop;
[416]         tree.post_tree_handler = ngx_http_dav_delete_dir;
[417]         tree.spec_handler = ngx_http_dav_delete_file;
[418]         tree.data = NULL;
[419]         tree.alloc = 0;
[420]         tree.log = r->connection->log;
[421] 
[422]         /* TODO: 207 */
[423] 
[424]         if (ngx_walk_tree(&tree, path) != NGX_OK) {
[425]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[426]         }
[427] 
[428]         if (ngx_delete_dir(path->data) != NGX_FILE_ERROR) {
[429]             return NGX_OK;
[430]         }
[431] 
[432]         failed = ngx_delete_dir_n;
[433] 
[434]     } else {
[435] 
[436]         if (ngx_delete_file(path->data) != NGX_FILE_ERROR) {
[437]             return NGX_OK;
[438]         }
[439] 
[440]         failed = ngx_delete_file_n;
[441]     }
[442] 
[443]     return ngx_http_dav_error(r->connection->log, ngx_errno,
[444]                               NGX_HTTP_NOT_FOUND, failed, path->data);
[445] }
[446] 
[447] 
[448] static ngx_int_t
[449] ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[450] {
[451]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[452]                    "http delete dir: \"%s\"", path->data);
[453] 
[454]     if (ngx_delete_dir(path->data) == NGX_FILE_ERROR) {
[455] 
[456]         /* TODO: add to 207 */
[457] 
[458]         (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_dir_n,
[459]                                   path->data);
[460]     }
[461] 
[462]     return NGX_OK;
[463] }
[464] 
[465] 
[466] static ngx_int_t
[467] ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[468] {
[469]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[470]                    "http delete file: \"%s\"", path->data);
[471] 
[472]     if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
[473] 
[474]         /* TODO: add to 207 */
[475] 
[476]         (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_file_n,
[477]                                   path->data);
[478]     }
[479] 
[480]     return NGX_OK;
[481] }
[482] 
[483] 
[484] static ngx_int_t
[485] ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[486] {
[487]     return NGX_OK;
[488] }
[489] 
[490] 
[491] static ngx_int_t
[492] ngx_http_dav_mkcol_handler(ngx_http_request_t *r, ngx_http_dav_loc_conf_t *dlcf)
[493] {
[494]     u_char    *p;
[495]     size_t     root;
[496]     ngx_str_t  path;
[497] 
[498]     if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
[499]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[500]                       "MKCOL with body is unsupported");
[501]         return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
[502]     }
[503] 
[504]     if (r->uri.data[r->uri.len - 1] != '/') {
[505]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[506]                       "MKCOL can create a collection only");
[507]         return NGX_HTTP_CONFLICT;
[508]     }
[509] 
[510]     p = ngx_http_map_uri_to_path(r, &path, &root, 0);
[511]     if (p == NULL) {
[512]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[513]     }
[514] 
[515]     *(p - 1) = '\0';
[516] 
[517]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[518]                    "http mkcol path: \"%s\"", path.data);
[519] 
[520]     if (ngx_create_dir(path.data, ngx_dir_access(dlcf->access))
[521]         != NGX_FILE_ERROR)
[522]     {
[523]         if (ngx_http_dav_location(r) != NGX_OK) {
[524]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[525]         }
[526] 
[527]         return NGX_HTTP_CREATED;
[528]     }
[529] 
[530]     return ngx_http_dav_error(r->connection->log, ngx_errno,
[531]                               NGX_HTTP_CONFLICT, ngx_create_dir_n, path.data);
[532] }
[533] 
[534] 
[535] static ngx_int_t
[536] ngx_http_dav_copy_move_handler(ngx_http_request_t *r)
[537] {
[538]     u_char                   *p, *host, *last, ch;
[539]     size_t                    len, root;
[540]     ngx_err_t                 err;
[541]     ngx_int_t                 rc, depth;
[542]     ngx_uint_t                overwrite, slash, dir, flags;
[543]     ngx_str_t                 path, uri, duri, args;
[544]     ngx_tree_ctx_t            tree;
[545]     ngx_copy_file_t           cf;
[546]     ngx_file_info_t           fi;
[547]     ngx_table_elt_t          *dest, *over;
[548]     ngx_ext_rename_file_t     ext;
[549]     ngx_http_dav_copy_ctx_t   copy;
[550]     ngx_http_dav_loc_conf_t  *dlcf;
[551] 
[552]     if (r->headers_in.content_length_n > 0 || r->headers_in.chunked) {
[553]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[554]                       "COPY and MOVE with body are unsupported");
[555]         return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
[556]     }
[557] 
[558]     dest = r->headers_in.destination;
[559] 
[560]     if (dest == NULL) {
[561]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[562]                       "client sent no \"Destination\" header");
[563]         return NGX_HTTP_BAD_REQUEST;
[564]     }
[565] 
[566]     p = dest->value.data;
[567]     /* there is always '\0' even after empty header value */
[568]     if (p[0] == '/') {
[569]         last = p + dest->value.len;
[570]         goto destination_done;
[571]     }
[572] 
[573]     len = r->headers_in.server.len;
[574] 
[575]     if (len == 0) {
[576]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[577]                       "client sent no \"Host\" header");
[578]         return NGX_HTTP_BAD_REQUEST;
[579]     }
[580] 
[581] #if (NGX_HTTP_SSL)
[582] 
[583]     if (r->connection->ssl) {
[584]         if (ngx_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
[585]             != 0)
[586]         {
[587]             goto invalid_destination;
[588]         }
[589] 
[590]         host = dest->value.data + sizeof("https://") - 1;
[591] 
[592]     } else
[593] #endif
[594]     {
[595]         if (ngx_strncmp(dest->value.data, "http://", sizeof("http://") - 1)
[596]             != 0)
[597]         {
[598]             goto invalid_destination;
[599]         }
[600] 
[601]         host = dest->value.data + sizeof("http://") - 1;
[602]     }
[603] 
[604]     if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
[605]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[606]                       "\"Destination\" URI \"%V\" is handled by "
[607]                       "different repository than the source URI",
[608]                       &dest->value);
[609]         return NGX_HTTP_BAD_REQUEST;
[610]     }
[611] 
[612]     last = dest->value.data + dest->value.len;
[613] 
[614]     for (p = host + len; p < last; p++) {
[615]         if (*p == '/') {
[616]             goto destination_done;
[617]         }
[618]     }
[619] 
[620] invalid_destination:
[621] 
[622]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[623]                   "client sent invalid \"Destination\" header: \"%V\"",
[624]                   &dest->value);
[625]     return NGX_HTTP_BAD_REQUEST;
[626] 
[627] destination_done:
[628] 
[629]     duri.len = last - p;
[630]     duri.data = p;
[631]     flags = NGX_HTTP_LOG_UNSAFE;
[632] 
[633]     if (ngx_http_parse_unsafe_uri(r, &duri, &args, &flags) != NGX_OK) {
[634]         goto invalid_destination;
[635]     }
[636] 
[637]     if ((r->uri.data[r->uri.len - 1] == '/' && *(last - 1) != '/')
[638]         || (r->uri.data[r->uri.len - 1] != '/' && *(last - 1) == '/'))
[639]     {
[640]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[641]                       "both URI \"%V\" and \"Destination\" URI \"%V\" "
[642]                       "should be either collections or non-collections",
[643]                       &r->uri, &dest->value);
[644]         return NGX_HTTP_CONFLICT;
[645]     }
[646] 
[647]     depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);
[648] 
[649]     if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
[650] 
[651]         if (r->method == NGX_HTTP_COPY) {
[652]             if (depth != 0) {
[653]                 ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[654]                               "\"Depth\" header must be 0 or infinity");
[655]                 return NGX_HTTP_BAD_REQUEST;
[656]             }
[657] 
[658]         } else {
[659]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[660]                           "\"Depth\" header must be infinity");
[661]             return NGX_HTTP_BAD_REQUEST;
[662]         }
[663]     }
[664] 
[665]     over = r->headers_in.overwrite;
[666] 
[667]     if (over) {
[668]         if (over->value.len == 1) {
[669]             ch = over->value.data[0];
[670] 
[671]             if (ch == 'T' || ch == 't') {
[672]                 overwrite = 1;
[673]                 goto overwrite_done;
[674]             }
[675] 
[676]             if (ch == 'F' || ch == 'f') {
[677]                 overwrite = 0;
[678]                 goto overwrite_done;
[679]             }
[680] 
[681]         }
[682] 
[683]         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[684]                       "client sent invalid \"Overwrite\" header: \"%V\"",
[685]                       &over->value);
[686]         return NGX_HTTP_BAD_REQUEST;
[687]     }
[688] 
[689]     overwrite = 1;
[690] 
[691] overwrite_done:
[692] 
[693]     if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
[694]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[695]     }
[696] 
[697]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[698]                    "http copy from: \"%s\"", path.data);
[699] 
[700]     uri = r->uri;
[701]     r->uri = duri;
[702] 
[703]     if (ngx_http_map_uri_to_path(r, &copy.path, &root, 0) == NULL) {
[704]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[705]     }
[706] 
[707]     r->uri = uri;
[708] 
[709]     copy.path.len--;  /* omit "\0" */
[710] 
[711]     if (copy.path.data[copy.path.len - 1] == '/') {
[712]         slash = 1;
[713]         copy.path.len--;
[714]         copy.path.data[copy.path.len] = '\0';
[715] 
[716]     } else {
[717]         slash = 0;
[718]     }
[719] 
[720]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[721]                    "http copy to: \"%s\"", copy.path.data);
[722] 
[723]     if (ngx_link_info(copy.path.data, &fi) == NGX_FILE_ERROR) {
[724]         err = ngx_errno;
[725] 
[726]         if (err != NGX_ENOENT) {
[727]             return ngx_http_dav_error(r->connection->log, err,
[728]                                       NGX_HTTP_NOT_FOUND, ngx_link_info_n,
[729]                                       copy.path.data);
[730]         }
[731] 
[732]         /* destination does not exist */
[733] 
[734]         overwrite = 0;
[735]         dir = 0;
[736] 
[737]     } else {
[738] 
[739]         /* destination exists */
[740] 
[741]         if (ngx_is_dir(&fi) && !slash) {
[742]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[743]                           "\"%V\" could not be %Ved to collection \"%V\"",
[744]                           &r->uri, &r->method_name, &dest->value);
[745]             return NGX_HTTP_CONFLICT;
[746]         }
[747] 
[748]         if (!overwrite) {
[749]             ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EEXIST,
[750]                           "\"%s\" could not be created", copy.path.data);
[751]             return NGX_HTTP_PRECONDITION_FAILED;
[752]         }
[753] 
[754]         dir = ngx_is_dir(&fi);
[755]     }
[756] 
[757]     if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
[758]         return ngx_http_dav_error(r->connection->log, ngx_errno,
[759]                                   NGX_HTTP_NOT_FOUND, ngx_link_info_n,
[760]                                   path.data);
[761]     }
[762] 
[763]     if (ngx_is_dir(&fi)) {
[764] 
[765]         if (r->uri.data[r->uri.len - 1] != '/') {
[766]             ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[767]                           "\"%V\" is collection", &r->uri);
[768]             return NGX_HTTP_BAD_REQUEST;
[769]         }
[770] 
[771]         if (overwrite) {
[772]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[773]                            "http delete: \"%s\"", copy.path.data);
[774] 
[775]             rc = ngx_http_dav_delete_path(r, &copy.path, dir);
[776] 
[777]             if (rc != NGX_OK) {
[778]                 return rc;
[779]             }
[780]         }
[781]     }
[782] 
[783]     if (ngx_is_dir(&fi)) {
[784] 
[785]         path.len -= 2;  /* omit "/\0" */
[786] 
[787]         if (r->method == NGX_HTTP_MOVE) {
[788]             if (ngx_rename_file(path.data, copy.path.data) != NGX_FILE_ERROR) {
[789]                 return NGX_HTTP_CREATED;
[790]             }
[791]         }
[792] 
[793]         if (ngx_create_dir(copy.path.data, ngx_file_access(&fi))
[794]             == NGX_FILE_ERROR)
[795]         {
[796]             return ngx_http_dav_error(r->connection->log, ngx_errno,
[797]                                       NGX_HTTP_NOT_FOUND,
[798]                                       ngx_create_dir_n, copy.path.data);
[799]         }
[800] 
[801]         copy.len = path.len;
[802] 
[803]         tree.init_handler = NULL;
[804]         tree.file_handler = ngx_http_dav_copy_tree_file;
[805]         tree.pre_tree_handler = ngx_http_dav_copy_dir;
[806]         tree.post_tree_handler = ngx_http_dav_copy_dir_time;
[807]         tree.spec_handler = ngx_http_dav_noop;
[808]         tree.data = &copy;
[809]         tree.alloc = 0;
[810]         tree.log = r->connection->log;
[811] 
[812]         if (ngx_walk_tree(&tree, &path) == NGX_OK) {
[813] 
[814]             if (r->method == NGX_HTTP_MOVE) {
[815]                 rc = ngx_http_dav_delete_path(r, &path, 1);
[816] 
[817]                 if (rc != NGX_OK) {
[818]                     return rc;
[819]                 }
[820]             }
[821] 
[822]             return NGX_HTTP_CREATED;
[823]         }
[824] 
[825]     } else {
[826] 
[827]         if (r->method == NGX_HTTP_MOVE) {
[828] 
[829]             dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
[830] 
[831]             ext.access = 0;
[832]             ext.path_access = dlcf->access;
[833]             ext.time = -1;
[834]             ext.create_path = 1;
[835]             ext.delete_file = 0;
[836]             ext.log = r->connection->log;
[837] 
[838]             if (ngx_ext_rename_file(&path, &copy.path, &ext) == NGX_OK) {
[839]                 return NGX_HTTP_NO_CONTENT;
[840]             }
[841] 
[842]             return NGX_HTTP_INTERNAL_SERVER_ERROR;
[843]         }
[844] 
[845]         cf.size = ngx_file_size(&fi);
[846]         cf.buf_size = 0;
[847]         cf.access = ngx_file_access(&fi);
[848]         cf.time = ngx_file_mtime(&fi);
[849]         cf.log = r->connection->log;
[850] 
[851]         if (ngx_copy_file(path.data, copy.path.data, &cf) == NGX_OK) {
[852]             return NGX_HTTP_NO_CONTENT;
[853]         }
[854]     }
[855] 
[856]     return NGX_HTTP_INTERNAL_SERVER_ERROR;
[857] }
[858] 
[859] 
[860] static ngx_int_t
[861] ngx_http_dav_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[862] {
[863]     u_char                   *p, *dir;
[864]     size_t                    len;
[865]     ngx_http_dav_copy_ctx_t  *copy;
[866] 
[867]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[868]                    "http copy dir: \"%s\"", path->data);
[869] 
[870]     copy = ctx->data;
[871] 
[872]     len = copy->path.len + path->len;
[873] 
[874]     dir = ngx_alloc(len + 1, ctx->log);
[875]     if (dir == NULL) {
[876]         return NGX_ABORT;
[877]     }
[878] 
[879]     p = ngx_cpymem(dir, copy->path.data, copy->path.len);
[880]     (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);
[881] 
[882]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[883]                    "http copy dir to: \"%s\"", dir);
[884] 
[885]     if (ngx_create_dir(dir, ngx_dir_access(ctx->access)) == NGX_FILE_ERROR) {
[886]         (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_create_dir_n,
[887]                                   dir);
[888]     }
[889] 
[890]     ngx_free(dir);
[891] 
[892]     return NGX_OK;
[893] }
[894] 
[895] 
[896] static ngx_int_t
[897] ngx_http_dav_copy_dir_time(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[898] {
[899]     u_char                   *p, *dir;
[900]     size_t                    len;
[901]     ngx_http_dav_copy_ctx_t  *copy;
[902] 
[903]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[904]                    "http copy dir time: \"%s\"", path->data);
[905] 
[906]     copy = ctx->data;
[907] 
[908]     len = copy->path.len + path->len;
[909] 
[910]     dir = ngx_alloc(len + 1, ctx->log);
[911]     if (dir == NULL) {
[912]         return NGX_ABORT;
[913]     }
[914] 
[915]     p = ngx_cpymem(dir, copy->path.data, copy->path.len);
[916]     (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);
[917] 
[918]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[919]                    "http copy dir time to: \"%s\"", dir);
[920] 
[921] #if (NGX_WIN32)
[922]     {
[923]     ngx_fd_t  fd;
[924] 
[925]     fd = ngx_open_file(dir, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);
[926] 
[927]     if (fd == NGX_INVALID_FILE) {
[928]         (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_open_file_n, dir);
[929]         goto failed;
[930]     }
[931] 
[932]     if (ngx_set_file_time(NULL, fd, ctx->mtime) != NGX_OK) {
[933]         ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
[934]                       ngx_set_file_time_n " \"%s\" failed", dir);
[935]     }
[936] 
[937]     if (ngx_close_file(fd) == NGX_FILE_ERROR) {
[938]         ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
[939]                       ngx_close_file_n " \"%s\" failed", dir);
[940]     }
[941]     }
[942] 
[943] failed:
[944] 
[945] #else
[946] 
[947]     if (ngx_set_file_time(dir, 0, ctx->mtime) != NGX_OK) {
[948]         ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
[949]                       ngx_set_file_time_n " \"%s\" failed", dir);
[950]     }
[951] 
[952] #endif
[953] 
[954]     ngx_free(dir);
[955] 
[956]     return NGX_OK;
[957] }
[958] 
[959] 
[960] static ngx_int_t
[961] ngx_http_dav_copy_tree_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
[962] {
[963]     u_char                   *p, *file;
[964]     size_t                    len;
[965]     ngx_copy_file_t           cf;
[966]     ngx_http_dav_copy_ctx_t  *copy;
[967] 
[968]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[969]                    "http copy file: \"%s\"", path->data);
[970] 
[971]     copy = ctx->data;
[972] 
[973]     len = copy->path.len + path->len;
[974] 
[975]     file = ngx_alloc(len + 1, ctx->log);
[976]     if (file == NULL) {
[977]         return NGX_ABORT;
[978]     }
[979] 
[980]     p = ngx_cpymem(file, copy->path.data, copy->path.len);
[981]     (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);
[982] 
[983]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
[984]                    "http copy file to: \"%s\"", file);
[985] 
[986]     cf.size = ctx->size;
[987]     cf.buf_size = 0;
[988]     cf.access = ctx->access;
[989]     cf.time = ctx->mtime;
[990]     cf.log = ctx->log;
[991] 
[992]     (void) ngx_copy_file(path->data, file, &cf);
[993] 
[994]     ngx_free(file);
[995] 
[996]     return NGX_OK;
[997] }
[998] 
[999] 
[1000] static ngx_int_t
[1001] ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt)
[1002] {
[1003]     ngx_table_elt_t  *depth;
[1004] 
[1005]     depth = r->headers_in.depth;
[1006] 
[1007]     if (depth == NULL) {
[1008]         return dflt;
[1009]     }
[1010] 
[1011]     if (depth->value.len == 1) {
[1012] 
[1013]         if (depth->value.data[0] == '0') {
[1014]             return 0;
[1015]         }
[1016] 
[1017]         if (depth->value.data[0] == '1') {
[1018]             return 1;
[1019]         }
[1020] 
[1021]     } else {
[1022] 
[1023]         if (depth->value.len == sizeof("infinity") - 1
[1024]             && ngx_strcmp(depth->value.data, "infinity") == 0)
[1025]         {
[1026]             return NGX_HTTP_DAV_INFINITY_DEPTH;
[1027]         }
[1028]     }
[1029] 
[1030]     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
[1031]                   "client sent invalid \"Depth\" header: \"%V\"",
[1032]                   &depth->value);
[1033] 
[1034]     return NGX_HTTP_DAV_INVALID_DEPTH;
[1035] }
[1036] 
[1037] 
[1038] static ngx_int_t
[1039] ngx_http_dav_error(ngx_log_t *log, ngx_err_t err, ngx_int_t not_found,
[1040]     char *failed, u_char *path)
[1041] {
[1042]     ngx_int_t   rc;
[1043]     ngx_uint_t  level;
[1044] 
[1045]     if (err == NGX_ENOENT || err == NGX_ENOTDIR || err == NGX_ENAMETOOLONG) {
[1046]         level = NGX_LOG_ERR;
[1047]         rc = not_found;
[1048] 
[1049]     } else if (err == NGX_EACCES || err == NGX_EPERM) {
[1050]         level = NGX_LOG_ERR;
[1051]         rc = NGX_HTTP_FORBIDDEN;
[1052] 
[1053]     } else if (err == NGX_EEXIST) {
[1054]         level = NGX_LOG_ERR;
[1055]         rc = NGX_HTTP_NOT_ALLOWED;
[1056] 
[1057]     } else if (err == NGX_ENOSPC) {
[1058]         level = NGX_LOG_CRIT;
[1059]         rc = NGX_HTTP_INSUFFICIENT_STORAGE;
[1060] 
[1061]     } else {
[1062]         level = NGX_LOG_CRIT;
[1063]         rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
[1064]     }
[1065] 
[1066]     ngx_log_error(level, log, err, "%s \"%s\" failed", failed, path);
[1067] 
[1068]     return rc;
[1069] }
[1070] 
[1071] 
[1072] static ngx_int_t
[1073] ngx_http_dav_location(ngx_http_request_t *r)
[1074] {
[1075]     u_char     *p;
[1076]     size_t      len;
[1077]     uintptr_t   escape;
[1078] 
[1079]     r->headers_out.location = ngx_list_push(&r->headers_out.headers);
[1080]     if (r->headers_out.location == NULL) {
[1081]         return NGX_ERROR;
[1082]     }
[1083] 
[1084]     r->headers_out.location->hash = 1;
[1085]     r->headers_out.location->next = NULL;
[1086]     ngx_str_set(&r->headers_out.location->key, "Location");
[1087] 
[1088]     escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
[1089] 
[1090]     if (escape) {
[1091]         len = r->uri.len + escape;
[1092] 
[1093]         p = ngx_pnalloc(r->pool, len);
[1094]         if (p == NULL) {
[1095]             ngx_http_clear_location(r);
[1096]             return NGX_ERROR;
[1097]         }
[1098] 
[1099]         r->headers_out.location->value.len = len;
[1100]         r->headers_out.location->value.data = p;
[1101] 
[1102]         ngx_escape_uri(p, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
[1103] 
[1104]     } else {
[1105]         r->headers_out.location->value = r->uri;
[1106]     }
[1107] 
[1108]     return NGX_OK;
[1109] }
[1110] 
[1111] 
[1112] static void *
[1113] ngx_http_dav_create_loc_conf(ngx_conf_t *cf)
[1114] {
[1115]     ngx_http_dav_loc_conf_t  *conf;
[1116] 
[1117]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_loc_conf_t));
[1118]     if (conf == NULL) {
[1119]         return NULL;
[1120]     }
[1121] 
[1122]     /*
[1123]      * set by ngx_pcalloc():
[1124]      *
[1125]      *     conf->methods = 0;
[1126]      */
[1127] 
[1128]     conf->min_delete_depth = NGX_CONF_UNSET_UINT;
[1129]     conf->access = NGX_CONF_UNSET_UINT;
[1130]     conf->create_full_put_path = NGX_CONF_UNSET;
[1131] 
[1132]     return conf;
[1133] }
[1134] 
[1135] 
[1136] static char *
[1137] ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[1138] {
[1139]     ngx_http_dav_loc_conf_t  *prev = parent;
[1140]     ngx_http_dav_loc_conf_t  *conf = child;
[1141] 
[1142]     ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
[1143]                          (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_OFF));
[1144] 
[1145]     ngx_conf_merge_uint_value(conf->min_delete_depth,
[1146]                          prev->min_delete_depth, 0);
[1147] 
[1148]     ngx_conf_merge_uint_value(conf->access, prev->access, 0600);
[1149] 
[1150]     ngx_conf_merge_value(conf->create_full_put_path,
[1151]                          prev->create_full_put_path, 0);
[1152] 
[1153]     return NGX_CONF_OK;
[1154] }
[1155] 
[1156] 
[1157] static ngx_int_t
[1158] ngx_http_dav_init(ngx_conf_t *cf)
[1159] {
[1160]     ngx_http_handler_pt        *h;
[1161]     ngx_http_core_main_conf_t  *cmcf;
[1162] 
[1163]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[1164] 
[1165]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
[1166]     if (h == NULL) {
[1167]         return NGX_ERROR;
[1168]     }
[1169] 
[1170]     *h = ngx_http_dav_handler;
[1171] 
[1172]     return NGX_OK;
[1173] }
