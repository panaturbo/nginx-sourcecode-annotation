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
[13] static ngx_int_t ngx_http_stub_status_handler(ngx_http_request_t *r);
[14] static ngx_int_t ngx_http_stub_status_variable(ngx_http_request_t *r,
[15]     ngx_http_variable_value_t *v, uintptr_t data);
[16] static ngx_int_t ngx_http_stub_status_add_variables(ngx_conf_t *cf);
[17] static char *ngx_http_set_stub_status(ngx_conf_t *cf, ngx_command_t *cmd,
[18]     void *conf);
[19] 
[20] 
[21] static ngx_command_t  ngx_http_status_commands[] = {
[22] 
[23]     { ngx_string("stub_status"),
[24]       NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
[25]       ngx_http_set_stub_status,
[26]       0,
[27]       0,
[28]       NULL },
[29] 
[30]       ngx_null_command
[31] };
[32] 
[33] 
[34] static ngx_http_module_t  ngx_http_stub_status_module_ctx = {
[35]     ngx_http_stub_status_add_variables,    /* preconfiguration */
[36]     NULL,                                  /* postconfiguration */
[37] 
[38]     NULL,                                  /* create main configuration */
[39]     NULL,                                  /* init main configuration */
[40] 
[41]     NULL,                                  /* create server configuration */
[42]     NULL,                                  /* merge server configuration */
[43] 
[44]     NULL,                                  /* create location configuration */
[45]     NULL                                   /* merge location configuration */
[46] };
[47] 
[48] 
[49] ngx_module_t  ngx_http_stub_status_module = {
[50]     NGX_MODULE_V1,
[51]     &ngx_http_stub_status_module_ctx,      /* module context */
[52]     ngx_http_status_commands,              /* module directives */
[53]     NGX_HTTP_MODULE,                       /* module type */
[54]     NULL,                                  /* init master */
[55]     NULL,                                  /* init module */
[56]     NULL,                                  /* init process */
[57]     NULL,                                  /* init thread */
[58]     NULL,                                  /* exit thread */
[59]     NULL,                                  /* exit process */
[60]     NULL,                                  /* exit master */
[61]     NGX_MODULE_V1_PADDING
[62] };
[63] 
[64] 
[65] static ngx_http_variable_t  ngx_http_stub_status_vars[] = {
[66] 
[67]     { ngx_string("connections_active"), NULL, ngx_http_stub_status_variable,
[68]       0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[69] 
[70]     { ngx_string("connections_reading"), NULL, ngx_http_stub_status_variable,
[71]       1, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[72] 
[73]     { ngx_string("connections_writing"), NULL, ngx_http_stub_status_variable,
[74]       2, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[75] 
[76]     { ngx_string("connections_waiting"), NULL, ngx_http_stub_status_variable,
[77]       3, NGX_HTTP_VAR_NOCACHEABLE, 0 },
[78] 
[79]       ngx_http_null_variable
[80] };
[81] 
[82] 
[83] static ngx_int_t
[84] ngx_http_stub_status_handler(ngx_http_request_t *r)
[85] {
[86]     size_t             size;
[87]     ngx_int_t          rc;
[88]     ngx_buf_t         *b;
[89]     ngx_chain_t        out;
[90]     ngx_atomic_int_t   ap, hn, ac, rq, rd, wr, wa;
[91] 
[92]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[93]         return NGX_HTTP_NOT_ALLOWED;
[94]     }
[95] 
[96]     rc = ngx_http_discard_request_body(r);
[97] 
[98]     if (rc != NGX_OK) {
[99]         return rc;
[100]     }
[101] 
[102]     r->headers_out.content_type_len = sizeof("text/plain") - 1;
[103]     ngx_str_set(&r->headers_out.content_type, "text/plain");
[104]     r->headers_out.content_type_lowcase = NULL;
[105] 
[106]     size = sizeof("Active connections:  \n") + NGX_ATOMIC_T_LEN
[107]            + sizeof("server accepts handled requests\n") - 1
[108]            + 6 + 3 * NGX_ATOMIC_T_LEN
[109]            + sizeof("Reading:  Writing:  Waiting:  \n") + 3 * NGX_ATOMIC_T_LEN;
[110] 
[111]     b = ngx_create_temp_buf(r->pool, size);
[112]     if (b == NULL) {
[113]         return NGX_HTTP_INTERNAL_SERVER_ERROR;
[114]     }
[115] 
[116]     out.buf = b;
[117]     out.next = NULL;
[118] 
[119]     ap = *ngx_stat_accepted;
[120]     hn = *ngx_stat_handled;
[121]     ac = *ngx_stat_active;
[122]     rq = *ngx_stat_requests;
[123]     rd = *ngx_stat_reading;
[124]     wr = *ngx_stat_writing;
[125]     wa = *ngx_stat_waiting;
[126] 
[127]     b->last = ngx_sprintf(b->last, "Active connections: %uA \n", ac);
[128] 
[129]     b->last = ngx_cpymem(b->last, "server accepts handled requests\n",
[130]                          sizeof("server accepts handled requests\n") - 1);
[131] 
[132]     b->last = ngx_sprintf(b->last, " %uA %uA %uA \n", ap, hn, rq);
[133] 
[134]     b->last = ngx_sprintf(b->last, "Reading: %uA Writing: %uA Waiting: %uA \n",
[135]                           rd, wr, wa);
[136] 
[137]     r->headers_out.status = NGX_HTTP_OK;
[138]     r->headers_out.content_length_n = b->last - b->pos;
[139] 
[140]     b->last_buf = (r == r->main) ? 1 : 0;
[141]     b->last_in_chain = 1;
[142] 
[143]     rc = ngx_http_send_header(r);
[144] 
[145]     if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
[146]         return rc;
[147]     }
[148] 
[149]     return ngx_http_output_filter(r, &out);
[150] }
[151] 
[152] 
[153] static ngx_int_t
[154] ngx_http_stub_status_variable(ngx_http_request_t *r,
[155]     ngx_http_variable_value_t *v, uintptr_t data)
[156] {
[157]     u_char            *p;
[158]     ngx_atomic_int_t   value;
[159] 
[160]     p = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
[161]     if (p == NULL) {
[162]         return NGX_ERROR;
[163]     }
[164] 
[165]     switch (data) {
[166]     case 0:
[167]         value = *ngx_stat_active;
[168]         break;
[169] 
[170]     case 1:
[171]         value = *ngx_stat_reading;
[172]         break;
[173] 
[174]     case 2:
[175]         value = *ngx_stat_writing;
[176]         break;
[177] 
[178]     case 3:
[179]         value = *ngx_stat_waiting;
[180]         break;
[181] 
[182]     /* suppress warning */
[183]     default:
[184]         value = 0;
[185]         break;
[186]     }
[187] 
[188]     v->len = ngx_sprintf(p, "%uA", value) - p;
[189]     v->valid = 1;
[190]     v->no_cacheable = 0;
[191]     v->not_found = 0;
[192]     v->data = p;
[193] 
[194]     return NGX_OK;
[195] }
[196] 
[197] 
[198] static ngx_int_t
[199] ngx_http_stub_status_add_variables(ngx_conf_t *cf)
[200] {
[201]     ngx_http_variable_t  *var, *v;
[202] 
[203]     for (v = ngx_http_stub_status_vars; v->name.len; v++) {
[204]         var = ngx_http_add_variable(cf, &v->name, v->flags);
[205]         if (var == NULL) {
[206]             return NGX_ERROR;
[207]         }
[208] 
[209]         var->get_handler = v->get_handler;
[210]         var->data = v->data;
[211]     }
[212] 
[213]     return NGX_OK;
[214] }
[215] 
[216] 
[217] static char *
[218] ngx_http_set_stub_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[219] {
[220]     ngx_http_core_loc_conf_t  *clcf;
[221] 
[222]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[223]     clcf->handler = ngx_http_stub_status_handler;
[224] 
[225]     return NGX_CONF_OK;
[226] }
