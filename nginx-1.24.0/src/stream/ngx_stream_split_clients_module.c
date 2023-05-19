[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_stream.h>
[11] 
[12] 
[13] typedef struct {
[14]     uint32_t                      percent;
[15]     ngx_stream_variable_value_t   value;
[16] } ngx_stream_split_clients_part_t;
[17] 
[18] 
[19] typedef struct {
[20]     ngx_stream_complex_value_t    value;
[21]     ngx_array_t                   parts;
[22] } ngx_stream_split_clients_ctx_t;
[23] 
[24] 
[25] static char *ngx_conf_split_clients_block(ngx_conf_t *cf, ngx_command_t *cmd,
[26]     void *conf);
[27] static char *ngx_stream_split_clients(ngx_conf_t *cf, ngx_command_t *dummy,
[28]     void *conf);
[29] 
[30] static ngx_command_t  ngx_stream_split_clients_commands[] = {
[31] 
[32]     { ngx_string("split_clients"),
[33]       NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE2,
[34]       ngx_conf_split_clients_block,
[35]       NGX_STREAM_MAIN_CONF_OFFSET,
[36]       0,
[37]       NULL },
[38] 
[39]       ngx_null_command
[40] };
[41] 
[42] 
[43] static ngx_stream_module_t  ngx_stream_split_clients_module_ctx = {
[44]     NULL,                                  /* preconfiguration */
[45]     NULL,                                  /* postconfiguration */
[46] 
[47]     NULL,                                  /* create main configuration */
[48]     NULL,                                  /* init main configuration */
[49] 
[50]     NULL,                                  /* create server configuration */
[51]     NULL                                   /* merge server configuration */
[52] };
[53] 
[54] 
[55] ngx_module_t  ngx_stream_split_clients_module = {
[56]     NGX_MODULE_V1,
[57]     &ngx_stream_split_clients_module_ctx,  /* module context */
[58]     ngx_stream_split_clients_commands,     /* module directives */
[59]     NGX_STREAM_MODULE,                     /* module type */
[60]     NULL,                                  /* init master */
[61]     NULL,                                  /* init module */
[62]     NULL,                                  /* init process */
[63]     NULL,                                  /* init thread */
[64]     NULL,                                  /* exit thread */
[65]     NULL,                                  /* exit process */
[66]     NULL,                                  /* exit master */
[67]     NGX_MODULE_V1_PADDING
[68] };
[69] 
[70] 
[71] static ngx_int_t
[72] ngx_stream_split_clients_variable(ngx_stream_session_t *s,
[73]     ngx_stream_variable_value_t *v, uintptr_t data)
[74] {
[75]     ngx_stream_split_clients_ctx_t *ctx =
[76]                                        (ngx_stream_split_clients_ctx_t *) data;
[77] 
[78]     uint32_t                          hash;
[79]     ngx_str_t                         val;
[80]     ngx_uint_t                        i;
[81]     ngx_stream_split_clients_part_t  *part;
[82] 
[83]     *v = ngx_stream_variable_null_value;
[84] 
[85]     if (ngx_stream_complex_value(s, &ctx->value, &val) != NGX_OK) {
[86]         return NGX_OK;
[87]     }
[88] 
[89]     hash = ngx_murmur_hash2(val.data, val.len);
[90] 
[91]     part = ctx->parts.elts;
[92] 
[93]     for (i = 0; i < ctx->parts.nelts; i++) {
[94] 
[95]         ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
[96]                        "stream split: %uD %uD", hash, part[i].percent);
[97] 
[98]         if (hash < part[i].percent || part[i].percent == 0) {
[99]             *v = part[i].value;
[100]             return NGX_OK;
[101]         }
[102]     }
[103] 
[104]     return NGX_OK;
[105] }
[106] 
[107] 
[108] static char *
[109] ngx_conf_split_clients_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[110] {
[111]     char                                *rv;
[112]     uint32_t                             sum, last;
[113]     ngx_str_t                           *value, name;
[114]     ngx_uint_t                           i;
[115]     ngx_conf_t                           save;
[116]     ngx_stream_variable_t               *var;
[117]     ngx_stream_split_clients_ctx_t      *ctx;
[118]     ngx_stream_split_clients_part_t     *part;
[119]     ngx_stream_compile_complex_value_t   ccv;
[120] 
[121]     ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_split_clients_ctx_t));
[122]     if (ctx == NULL) {
[123]         return NGX_CONF_ERROR;
[124]     }
[125] 
[126]     value = cf->args->elts;
[127] 
[128]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[129] 
[130]     ccv.cf = cf;
[131]     ccv.value = &value[1];
[132]     ccv.complex_value = &ctx->value;
[133] 
[134]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[135]         return NGX_CONF_ERROR;
[136]     }
[137] 
[138]     name = value[2];
[139] 
[140]     if (name.data[0] != '$') {
[141]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[142]                            "invalid variable name \"%V\"", &name);
[143]         return NGX_CONF_ERROR;
[144]     }
[145] 
[146]     name.len--;
[147]     name.data++;
[148] 
[149]     var = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
[150]     if (var == NULL) {
[151]         return NGX_CONF_ERROR;
[152]     }
[153] 
[154]     var->get_handler = ngx_stream_split_clients_variable;
[155]     var->data = (uintptr_t) ctx;
[156] 
[157]     if (ngx_array_init(&ctx->parts, cf->pool, 2,
[158]                        sizeof(ngx_stream_split_clients_part_t))
[159]         != NGX_OK)
[160]     {
[161]         return NGX_CONF_ERROR;
[162]     }
[163] 
[164]     save = *cf;
[165]     cf->ctx = ctx;
[166]     cf->handler = ngx_stream_split_clients;
[167]     cf->handler_conf = conf;
[168] 
[169]     rv = ngx_conf_parse(cf, NULL);
[170] 
[171]     *cf = save;
[172] 
[173]     if (rv != NGX_CONF_OK) {
[174]         return rv;
[175]     }
[176] 
[177]     sum = 0;
[178]     last = 0;
[179]     part = ctx->parts.elts;
[180] 
[181]     for (i = 0; i < ctx->parts.nelts; i++) {
[182]         sum = part[i].percent ? sum + part[i].percent : 10000;
[183]         if (sum > 10000) {
[184]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[185]                                "percent total is greater than 100%%");
[186]             return NGX_CONF_ERROR;
[187]         }
[188] 
[189]         if (part[i].percent) {
[190]             last += part[i].percent * (uint64_t) 0xffffffff / 10000;
[191]             part[i].percent = last;
[192]         }
[193]     }
[194] 
[195]     return rv;
[196] }
[197] 
[198] 
[199] static char *
[200] ngx_stream_split_clients(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
[201] {
[202]     ngx_int_t                         n;
[203]     ngx_str_t                        *value;
[204]     ngx_stream_split_clients_ctx_t   *ctx;
[205]     ngx_stream_split_clients_part_t  *part;
[206] 
[207]     ctx = cf->ctx;
[208]     value = cf->args->elts;
[209] 
[210]     part = ngx_array_push(&ctx->parts);
[211]     if (part == NULL) {
[212]         return NGX_CONF_ERROR;
[213]     }
[214] 
[215]     if (value[0].len == 1 && value[0].data[0] == '*') {
[216]         part->percent = 0;
[217] 
[218]     } else {
[219]         if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
[220]             goto invalid;
[221]         }
[222] 
[223]         n = ngx_atofp(value[0].data, value[0].len - 1, 2);
[224]         if (n == NGX_ERROR || n == 0) {
[225]             goto invalid;
[226]         }
[227] 
[228]         part->percent = (uint32_t) n;
[229]     }
[230] 
[231]     part->value.len = value[1].len;
[232]     part->value.valid = 1;
[233]     part->value.no_cacheable = 0;
[234]     part->value.not_found = 0;
[235]     part->value.data = value[1].data;
[236] 
[237]     return NGX_CONF_OK;
[238] 
[239] invalid:
[240] 
[241]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[242]                        "invalid percent value \"%V\"", &value[0]);
[243]     return NGX_CONF_ERROR;
[244] }
