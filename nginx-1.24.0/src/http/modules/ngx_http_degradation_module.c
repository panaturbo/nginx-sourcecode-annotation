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
[14]     size_t      sbrk_size;
[15] } ngx_http_degradation_main_conf_t;
[16] 
[17] 
[18] typedef struct {
[19]     ngx_uint_t  degrade;
[20] } ngx_http_degradation_loc_conf_t;
[21] 
[22] 
[23] static ngx_conf_enum_t  ngx_http_degrade[] = {
[24]     { ngx_string("204"), 204 },
[25]     { ngx_string("444"), 444 },
[26]     { ngx_null_string, 0 }
[27] };
[28] 
[29] 
[30] static void *ngx_http_degradation_create_main_conf(ngx_conf_t *cf);
[31] static void *ngx_http_degradation_create_loc_conf(ngx_conf_t *cf);
[32] static char *ngx_http_degradation_merge_loc_conf(ngx_conf_t *cf, void *parent,
[33]     void *child);
[34] static char *ngx_http_degradation(ngx_conf_t *cf, ngx_command_t *cmd,
[35]     void *conf);
[36] static ngx_int_t ngx_http_degradation_init(ngx_conf_t *cf);
[37] 
[38] 
[39] static ngx_command_t  ngx_http_degradation_commands[] = {
[40] 
[41]     { ngx_string("degradation"),
[42]       NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
[43]       ngx_http_degradation,
[44]       NGX_HTTP_MAIN_CONF_OFFSET,
[45]       0,
[46]       NULL },
[47] 
[48]     { ngx_string("degrade"),
[49]       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
[50]       ngx_conf_set_enum_slot,
[51]       NGX_HTTP_LOC_CONF_OFFSET,
[52]       offsetof(ngx_http_degradation_loc_conf_t, degrade),
[53]       &ngx_http_degrade },
[54] 
[55]       ngx_null_command
[56] };
[57] 
[58] 
[59] static ngx_http_module_t  ngx_http_degradation_module_ctx = {
[60]     NULL,                                  /* preconfiguration */
[61]     ngx_http_degradation_init,             /* postconfiguration */
[62] 
[63]     ngx_http_degradation_create_main_conf, /* create main configuration */
[64]     NULL,                                  /* init main configuration */
[65] 
[66]     NULL,                                  /* create server configuration */
[67]     NULL,                                  /* merge server configuration */
[68] 
[69]     ngx_http_degradation_create_loc_conf,  /* create location configuration */
[70]     ngx_http_degradation_merge_loc_conf    /* merge location configuration */
[71] };
[72] 
[73] 
[74] ngx_module_t  ngx_http_degradation_module = {
[75]     NGX_MODULE_V1,
[76]     &ngx_http_degradation_module_ctx,      /* module context */
[77]     ngx_http_degradation_commands,         /* module directives */
[78]     NGX_HTTP_MODULE,                       /* module type */
[79]     NULL,                                  /* init master */
[80]     NULL,                                  /* init module */
[81]     NULL,                                  /* init process */
[82]     NULL,                                  /* init thread */
[83]     NULL,                                  /* exit thread */
[84]     NULL,                                  /* exit process */
[85]     NULL,                                  /* exit master */
[86]     NGX_MODULE_V1_PADDING
[87] };
[88] 
[89] 
[90] static ngx_int_t
[91] ngx_http_degradation_handler(ngx_http_request_t *r)
[92] {
[93]     ngx_http_degradation_loc_conf_t  *dlcf;
[94] 
[95]     dlcf = ngx_http_get_module_loc_conf(r, ngx_http_degradation_module);
[96] 
[97]     if (dlcf->degrade && ngx_http_degraded(r)) {
[98]         return dlcf->degrade;
[99]     }
[100] 
[101]     return NGX_DECLINED;
[102] }
[103] 
[104] 
[105] ngx_uint_t
[106] ngx_http_degraded(ngx_http_request_t *r)
[107] {
[108]     time_t                             now;
[109]     ngx_uint_t                         log;
[110]     static size_t                      sbrk_size;
[111]     static time_t                      sbrk_time;
[112]     ngx_http_degradation_main_conf_t  *dmcf;
[113] 
[114]     dmcf = ngx_http_get_module_main_conf(r, ngx_http_degradation_module);
[115] 
[116]     if (dmcf->sbrk_size) {
[117] 
[118]         log = 0;
[119]         now = ngx_time();
[120] 
[121]         /* lock mutex */
[122] 
[123]         if (now != sbrk_time) {
[124] 
[125]             /*
[126]              * ELF/i386 is loaded at 0x08000000, 128M
[127]              * ELF/amd64 is loaded at 0x00400000, 4M
[128]              *
[129]              * use a function address to subtract the loading address
[130]              */
[131] 
[132]             sbrk_size = (size_t) sbrk(0) - ((uintptr_t) ngx_palloc & ~0x3FFFFF);
[133]             sbrk_time = now;
[134]             log = 1;
[135]         }
[136] 
[137]         /* unlock mutex */
[138] 
[139]         if (sbrk_size >= dmcf->sbrk_size) {
[140]             if (log) {
[141]                 ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
[142]                               "degradation sbrk:%uzM",
[143]                               sbrk_size / (1024 * 1024));
[144]             }
[145] 
[146]             return 1;
[147]         }
[148]     }
[149] 
[150]     return 0;
[151] }
[152] 
[153] 
[154] static void *
[155] ngx_http_degradation_create_main_conf(ngx_conf_t *cf)
[156] {
[157]     ngx_http_degradation_main_conf_t  *dmcf;
[158] 
[159]     dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_degradation_main_conf_t));
[160]     if (dmcf == NULL) {
[161]         return NULL;
[162]     }
[163] 
[164]     return dmcf;
[165] }
[166] 
[167] 
[168] static void *
[169] ngx_http_degradation_create_loc_conf(ngx_conf_t *cf)
[170] {
[171]     ngx_http_degradation_loc_conf_t  *conf;
[172] 
[173]     conf = ngx_palloc(cf->pool, sizeof(ngx_http_degradation_loc_conf_t));
[174]     if (conf == NULL) {
[175]         return NULL;
[176]     }
[177] 
[178]     conf->degrade = NGX_CONF_UNSET_UINT;
[179] 
[180]     return conf;
[181] }
[182] 
[183] 
[184] static char *
[185] ngx_http_degradation_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
[186] {
[187]     ngx_http_degradation_loc_conf_t  *prev = parent;
[188]     ngx_http_degradation_loc_conf_t  *conf = child;
[189] 
[190]     ngx_conf_merge_uint_value(conf->degrade, prev->degrade, 0);
[191] 
[192]     return NGX_CONF_OK;
[193] }
[194] 
[195] 
[196] static char *
[197] ngx_http_degradation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[198] {
[199]     ngx_http_degradation_main_conf_t  *dmcf = conf;
[200] 
[201]     ngx_str_t  *value, s;
[202] 
[203]     value = cf->args->elts;
[204] 
[205]     if (ngx_strncmp(value[1].data, "sbrk=", 5) == 0) {
[206] 
[207]         s.len = value[1].len - 5;
[208]         s.data = value[1].data + 5;
[209] 
[210]         dmcf->sbrk_size = ngx_parse_size(&s);
[211]         if (dmcf->sbrk_size == (size_t) NGX_ERROR) {
[212]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[213]                                "invalid sbrk size \"%V\"", &value[1]);
[214]             return NGX_CONF_ERROR;
[215]         }
[216] 
[217]         return NGX_CONF_OK;
[218]     }
[219] 
[220]     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[221]                        "invalid parameter \"%V\"", &value[1]);
[222] 
[223]     return NGX_CONF_ERROR;
[224] }
[225] 
[226] 
[227] static ngx_int_t
[228] ngx_http_degradation_init(ngx_conf_t *cf)
[229] {
[230]     ngx_http_handler_pt        *h;
[231]     ngx_http_core_main_conf_t  *cmcf;
[232] 
[233]     cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
[234] 
[235]     h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
[236]     if (h == NULL) {
[237]         return NGX_ERROR;
[238]     }
[239] 
[240]     *h = ngx_http_degradation_handler;
[241] 
[242]     return NGX_OK;
[243] }
