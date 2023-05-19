[1] 
[2] /*
[3]  * Copyright (C) Pavel Pautov
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
[14]     ngx_int_t                   index;
[15]     ngx_stream_set_variable_pt  set_handler;
[16]     uintptr_t                   data;
[17]     ngx_stream_complex_value_t  value;
[18] } ngx_stream_set_cmd_t;
[19] 
[20] 
[21] typedef struct {
[22]     ngx_array_t                 commands;
[23] } ngx_stream_set_srv_conf_t;
[24] 
[25] 
[26] static ngx_int_t ngx_stream_set_handler(ngx_stream_session_t *s);
[27] static ngx_int_t ngx_stream_set_var(ngx_stream_session_t *s,
[28]     ngx_stream_variable_value_t *v, uintptr_t data);
[29] static ngx_int_t ngx_stream_set_init(ngx_conf_t *cf);
[30] static void *ngx_stream_set_create_srv_conf(ngx_conf_t *cf);
[31] static char *ngx_stream_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
[32] 
[33] 
[34] static ngx_command_t  ngx_stream_set_commands[] = {
[35] 
[36]     { ngx_string("set"),
[37]       NGX_STREAM_SRV_CONF|NGX_CONF_TAKE2,
[38]       ngx_stream_set,
[39]       NGX_STREAM_SRV_CONF_OFFSET,
[40]       0,
[41]       NULL },
[42] 
[43]       ngx_null_command
[44] };
[45] 
[46] 
[47] static ngx_stream_module_t  ngx_stream_set_module_ctx = {
[48]     NULL,                                  /* preconfiguration */
[49]     ngx_stream_set_init,                   /* postconfiguration */
[50] 
[51]     NULL,                                  /* create main configuration */
[52]     NULL,                                  /* init main configuration */
[53] 
[54]     ngx_stream_set_create_srv_conf,        /* create server configuration */
[55]     NULL                                   /* merge server configuration */
[56] };
[57] 
[58] 
[59] ngx_module_t  ngx_stream_set_module = {
[60]     NGX_MODULE_V1,
[61]     &ngx_stream_set_module_ctx,            /* module context */
[62]     ngx_stream_set_commands,               /* module directives */
[63]     NGX_STREAM_MODULE,                     /* module type */
[64]     NULL,                                  /* init master */
[65]     NULL,                                  /* init module */
[66]     NULL,                                  /* init process */
[67]     NULL,                                  /* init thread */
[68]     NULL,                                  /* exit thread */
[69]     NULL,                                  /* exit process */
[70]     NULL,                                  /* exit master */
[71]     NGX_MODULE_V1_PADDING
[72] };
[73] 
[74] 
[75] static ngx_int_t
[76] ngx_stream_set_handler(ngx_stream_session_t *s)
[77] {
[78]     ngx_str_t                     str;
[79]     ngx_uint_t                    i;
[80]     ngx_stream_set_cmd_t         *cmds;
[81]     ngx_stream_set_srv_conf_t    *scf;
[82]     ngx_stream_variable_value_t   vv;
[83] 
[84]     scf = ngx_stream_get_module_srv_conf(s, ngx_stream_set_module);
[85]     cmds = scf->commands.elts;
[86]     vv = ngx_stream_variable_null_value;
[87] 
[88]     for (i = 0; i < scf->commands.nelts; i++) {
[89]         if (ngx_stream_complex_value(s, &cmds[i].value, &str) != NGX_OK) {
[90]             return NGX_ERROR;
[91]         }
[92] 
[93]         if (cmds[i].set_handler != NULL) {
[94]             vv.len = str.len;
[95]             vv.data = str.data;
[96]             cmds[i].set_handler(s, &vv, cmds[i].data);
[97] 
[98]         } else {
[99]             s->variables[cmds[i].index].len = str.len;
[100]             s->variables[cmds[i].index].valid = 1;
[101]             s->variables[cmds[i].index].no_cacheable = 0;
[102]             s->variables[cmds[i].index].not_found = 0;
[103]             s->variables[cmds[i].index].data = str.data;
[104]         }
[105]     }
[106] 
[107]     return NGX_DECLINED;
[108] }
[109] 
[110] 
[111] static ngx_int_t
[112] ngx_stream_set_var(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
[113]     uintptr_t data)
[114] {
[115]     *v = ngx_stream_variable_null_value;
[116] 
[117]     return NGX_OK;
[118] }
[119] 
[120] 
[121] static ngx_int_t
[122] ngx_stream_set_init(ngx_conf_t *cf)
[123] {
[124]     ngx_stream_handler_pt        *h;
[125]     ngx_stream_core_main_conf_t  *cmcf;
[126] 
[127]     cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
[128] 
[129]     h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREACCESS_PHASE].handlers);
[130]     if (h == NULL) {
[131]         return NGX_ERROR;
[132]     }
[133] 
[134]     *h = ngx_stream_set_handler;
[135] 
[136]     return NGX_OK;
[137] }
[138] 
[139] 
[140] static void *
[141] ngx_stream_set_create_srv_conf(ngx_conf_t *cf)
[142] {
[143]     ngx_stream_set_srv_conf_t  *conf;
[144] 
[145]     conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_set_srv_conf_t));
[146]     if (conf == NULL) {
[147]         return NULL;
[148]     }
[149] 
[150]     /*
[151]      * set by ngx_pcalloc():
[152]      *
[153]      *     conf->commands = { NULL };
[154]      */
[155] 
[156]     return conf;
[157] }
[158] 
[159] 
[160] static char *
[161] ngx_stream_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[162] {
[163]     ngx_stream_set_srv_conf_t  *scf = conf;
[164] 
[165]     ngx_str_t                           *args;
[166]     ngx_int_t                            index;
[167]     ngx_stream_set_cmd_t                *set_cmd;
[168]     ngx_stream_variable_t               *v;
[169]     ngx_stream_compile_complex_value_t   ccv;
[170] 
[171]     args = cf->args->elts;
[172] 
[173]     if (args[1].data[0] != '$') {
[174]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[175]                            "invalid variable name \"%V\"", &args[1]);
[176]         return NGX_CONF_ERROR;
[177]     }
[178] 
[179]     args[1].len--;
[180]     args[1].data++;
[181] 
[182]     v = ngx_stream_add_variable(cf, &args[1],
[183]                                 NGX_STREAM_VAR_CHANGEABLE|NGX_STREAM_VAR_WEAK);
[184]     if (v == NULL) {
[185]         return NGX_CONF_ERROR;
[186]     }
[187] 
[188]     index = ngx_stream_get_variable_index(cf, &args[1]);
[189]     if (index == NGX_ERROR) {
[190]         return NGX_CONF_ERROR;
[191]     }
[192] 
[193]     if (v->get_handler == NULL) {
[194]         v->get_handler = ngx_stream_set_var;
[195]     }
[196] 
[197]     if (scf->commands.elts == NULL) {
[198]         if (ngx_array_init(&scf->commands, cf->pool, 1,
[199]                            sizeof(ngx_stream_set_cmd_t))
[200]             != NGX_OK)
[201]         {
[202]             return NGX_CONF_ERROR;
[203]         }
[204]     }
[205] 
[206]     set_cmd = ngx_array_push(&scf->commands);
[207]     if (set_cmd == NULL) {
[208]         return NGX_CONF_ERROR;
[209]     }
[210] 
[211]     set_cmd->index = index;
[212]     set_cmd->set_handler = v->set_handler;
[213]     set_cmd->data = v->data;
[214] 
[215]     ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));
[216] 
[217]     ccv.cf = cf;
[218]     ccv.value = &args[2];
[219]     ccv.complex_value = &set_cmd->value;
[220] 
[221]     if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
[222]         return NGX_CONF_ERROR;
[223]     }
[224] 
[225]     return NGX_CONF_OK;
[226] }
