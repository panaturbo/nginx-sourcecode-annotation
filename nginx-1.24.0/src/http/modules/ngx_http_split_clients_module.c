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
[13] typedef struct {
[14]     uint32_t                    percent;
[15]     ngx_http_variable_value_t   value;
[16] } ngx_http_split_clients_part_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_http_complex_value_t    value;
[21]     ngx_array_t                 parts;
[22] } ngx_http_split_clients_ctx_t;
[23] 
[24] 
[25] static char *ngx_conf_split_clients_block(ngx_conf_t *cf, ngx_command_t *cmd,
[26]     void *conf);
[27] static char *ngx_http_split_clients(ngx_conf_t *cf, ngx_command_t *dummy,
[28]     void *conf);
[29] 
[30] static ngx_command_t  ngx_http_split_clients_commands[] = {
[31] 
[32]     { ngx_string("split_clients"),
[33]       NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
[34]       ngx_conf_split_clients_block,
[35]       NGX_HTTP_MAIN_CONF_OFFSET,
[36]       0,
[37]       NULL },
[38] 
[39]       ngx_null_command
[40] };
[41] 
[42] 
[43] static ngx_http_module_t  ngx_http_split_clients_module_ctx = {
[44]     NULL,                                  /* preconfiguration */
[45]     NULL,                                  /* postconfiguration */
[46] 
[47]     NULL,                                  /* create main configuration */
[48]     NULL,                                  /* init main configuration */
[49] 
[50]     NULL,                                  /* create server configuration */
[51]     NULL,                                  /* merge server configuration */
[52] 
[53]     NULL,                                  /* create location configuration */
[54]     NULL                                   /* merge location configuration */
[55] };
[56] 
[57] 
[58] ngx_module_t  ngx_http_split_clients_module = {
[59]     NGX_MODULE_V1,
[60]     &ngx_http_split_clients_module_ctx,    /* module context */
[61]     ngx_http_split_clients_commands,       /* module directives */
[62]     NGX_HTTP_MODULE,                       /* module type */
[63]     NULL,                                  /* init master */
[64]     NULL,                                  /* init module */
[65]     NULL,                                  /* init process */
[66]     NULL,                                  /* init thread */
[67]     NULL,                                  /* exit thread */
[68]     NULL,                                  /* exit process */
[69]     NULL,                                  /* exit master */
[70]     NGX_MODULE_V1_PADDING
[71] };
[72] 
[73] 
[74] static ngx_int_t
[75] ngx_http_split_clients_variable(ngx_http_request_t *r,
[76]     ngx_http_variable_value_t *v, uintptr_t data)
[77] {
[78]     ngx_http_split_clients_ctx_t *ctx = (ngx_http_split_clients_ctx_t *) data;
[79] 
[80]     uint32_t                        hash;
[81]     ngx_str_t                       val;
[82]     ngx_uint_t                      i;
[83]     ngx_http_split_clients_part_t  *part;
[84] 
[85]     *v = ngx_http_variable_null_value;
[86] 
[87]     if (ngx_http_complex_value(r, &ctx->value, &val) != NGX_OK) {
[88]         return NGX_OK;
[89]     }
[90] 
[91]     hash = ngx_murmur_hash2(val.data, val.len);
[92] 
[93]     part = ctx->parts.elts;
[94] 
[95]     for (i = 0; i < ctx->parts.nelts; i++) {
[96] 
[97]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[98]                        "http split: %uD %uD", hash, part[i].percent);
[99] 
[100]         if (hash < part[i].percent || part[i].percent == 0) {
[101]             *v = part[i].value;
[102]             return NGX_OK;
[103]         }
[104]     }
[105] 
[106]     return NGX_OK;
[107] }
[108] 
[109] 
[110] static char *
[111] ngx_conf_split_clients_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[112] {
[113]     char                                *rv;
[114]     uint32_t                             sum, last;
[115]     ngx_str_t                           *value, name;
[116]     ngx_uint_t                           i;
[117]     ngx_conf_t                           save;
[118]     ngx_http_variable_t                 *var;
[119]     ngx_http_split_clients_ctx_t        *ctx;
[120]     ngx_http_split_clients_part_t       *part;
[121]     ngx_http_compile_complex_value_t     ccv;
[122] 
[123]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_split_clients_ctx_t));
[124]     if (ctx == NULL) {
[125]         return NGX_CONF_ERROR;
[126]     }
[127] 
[128]     value = cf->args->elts;
[129] 
[130]     ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
[131] 
[132]     ccv.cf = cf;
[133]     ccv.value = &value[1];
[134]     ccv.complex_value = &ctx->value;
[135] 
[136]     if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
[137]         return NGX_CONF_ERROR;
[138]     }
[139] 
[140]     name = value[2];
[141] 
[142]     if (name.data[0] != '$') {
[143]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[144]                            "invalid variable name \"%V\"", &name);
[145]         return NGX_CONF_ERROR;
[146]     }
[147] 
[148]     name.len--;
[149]     name.data++;
[150] 
[151]     var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
[152]     if (var == NULL) {
[153]         return NGX_CONF_ERROR;
[154]     }
[155] 
[156]     var->get_handler = ngx_http_split_clients_variable;
[157]     var->data = (uintptr_t) ctx;
[158] 
[159]     if (ngx_array_init(&ctx->parts, cf->pool, 2,
[160]                        sizeof(ngx_http_split_clients_part_t))
[161]         != NGX_OK)
[162]     {
[163]         return NGX_CONF_ERROR;
[164]     }
[165] 
[166]     save = *cf;
[167]     cf->ctx = ctx;
[168]     cf->handler = ngx_http_split_clients;
[169]     cf->handler_conf = conf;
[170] 
[171]     rv = ngx_conf_parse(cf, NULL);
[172] 
[173]     *cf = save;
[174] 
[175]     if (rv != NGX_CONF_OK) {
[176]         return rv;
[177]     }
[178] 
[179]     sum = 0;
[180]     last = 0;
[181]     part = ctx->parts.elts;
[182] 
[183]     for (i = 0; i < ctx->parts.nelts; i++) {
[184]         sum = part[i].percent ? sum + part[i].percent : 10000;
[185]         if (sum > 10000) {
[186]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[187]                                "percent total is greater than 100%%");
[188]             return NGX_CONF_ERROR;
[189]         }
[190] 
[191]         if (part[i].percent) {
[192]             last += part[i].percent * (uint64_t) 0xffffffff / 10000;
[193]             part[i].percent = last;
[194]         }
[195]     }
[196] 
[197]     return rv;
[198] }
[199] 
[200] 
[201] static char *
[202] ngx_http_split_clients(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[203] {
[204]     ngx_int_t                       n;
[205]     ngx_str_t                      *value;
[206]     ngx_http_split_clients_ctx_t   *ctx;
[207]     ngx_http_split_clients_part_t  *part;
[208] 
[209]     ctx = cf->ctx;
[210]     value = cf->args->elts;
[211] 
[212]     part = ngx_array_push(&ctx->parts);
[213]     if (part == NULL) {
[214]         return NGX_CONF_ERROR;
[215]     }
[216] 
[217]     if (value[0].len == 1 && value[0].data[0] == '*') {
[218]         part->percent = 0;
[219] 
[220]     } else {
[221]         if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
[222]             goto invalid;
[223]         }
[224] 
[225]         n = ngx_atofp(value[0].data, value[0].len - 1, 2);
[226]         if (n == NGX_ERROR || n == 0) {
[227]             goto invalid;
[228]         }
[229] 
[230]         part->percent = (uint32_t) n;
[231]     }
[232] 
[233]     part->value.len = value[1].len;
[234]     part->value.valid = 1;
[235]     part->value.no_cacheable = 0;
[236]     part->value.not_found = 0;
[237]     part->value.data = value[1].data;
[238] 
[239]     return NGX_CONF_OK;
[240] 
[241] invalid:
[242] 
[243]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[244]                        "invalid percent value \"%V\"", &value[0]);
[245]     return NGX_CONF_ERROR;
[246] }
