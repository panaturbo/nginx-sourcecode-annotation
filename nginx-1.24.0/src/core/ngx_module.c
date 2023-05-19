[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Maxim Dounin
[5]  * Copyright (C) Nginx, Inc.
[6]  */
[7] 
[8] 
[9] #include <ngx_config.h>
[10] #include <ngx_core.h>
[11] 
[12] 
[13] #define NGX_MAX_DYNAMIC_MODULES  128
[14] 
[15] 
[16] static ngx_uint_t ngx_module_index(ngx_cycle_t *cycle);
[17] static ngx_uint_t ngx_module_ctx_index(ngx_cycle_t *cycle, ngx_uint_t type,
[18]     ngx_uint_t index);
[19] 
[20] 
[21] ngx_uint_t         ngx_max_module;
[22] static ngx_uint_t  ngx_modules_n;
[23] 
[24] 
[25] ngx_int_t
[26] ngx_preinit_modules(void)
[27] {
[28]     ngx_uint_t  i;
[29] 
[30]     for (i = 0; ngx_modules[i]; i++) {
[31]         ngx_modules[i]->index = i;
[32]         ngx_modules[i]->name = ngx_module_names[i];
[33]     }
[34] 
[35]     ngx_modules_n = i;
[36]     ngx_max_module = ngx_modules_n + NGX_MAX_DYNAMIC_MODULES;
[37] 
[38]     return NGX_OK;
[39] }
[40] 
[41] 
[42] ngx_int_t
[43] ngx_cycle_modules(ngx_cycle_t *cycle)
[44] {
[45]     /*
[46]      * create a list of modules to be used for this cycle,
[47]      * copy static modules to it
[48]      */
[49] 
[50]     cycle->modules = ngx_pcalloc(cycle->pool, (ngx_max_module + 1)
[51]                                               * sizeof(ngx_module_t *));
[52]     if (cycle->modules == NULL) {
[53]         return NGX_ERROR;
[54]     }
[55] 
[56]     ngx_memcpy(cycle->modules, ngx_modules,
[57]                ngx_modules_n * sizeof(ngx_module_t *));
[58] 
[59]     cycle->modules_n = ngx_modules_n;
[60] 
[61]     return NGX_OK;
[62] }
[63] 
[64] 
[65] ngx_int_t
[66] ngx_init_modules(ngx_cycle_t *cycle)
[67] {
[68]     ngx_uint_t  i;
[69] 
[70]     for (i = 0; cycle->modules[i]; i++) {
[71]         if (cycle->modules[i]->init_module) {
[72]             if (cycle->modules[i]->init_module(cycle) != NGX_OK) {
[73]                 return NGX_ERROR;
[74]             }
[75]         }
[76]     }
[77] 
[78]     return NGX_OK;
[79] }
[80] 
[81] 
[82] ngx_int_t
[83] ngx_count_modules(ngx_cycle_t *cycle, ngx_uint_t type)
[84] {
[85]     ngx_uint_t     i, next, max;
[86]     ngx_module_t  *module;
[87] 
[88]     next = 0;
[89]     max = 0;
[90] 
[91]     /* count appropriate modules, set up their indices */
[92] 
[93]     for (i = 0; cycle->modules[i]; i++) {
[94]         module = cycle->modules[i];
[95] 
[96]         if (module->type != type) {
[97]             continue;
[98]         }
[99] 
[100]         if (module->ctx_index != NGX_MODULE_UNSET_INDEX) {
[101] 
[102]             /* if ctx_index was assigned, preserve it */
[103] 
[104]             if (module->ctx_index > max) {
[105]                 max = module->ctx_index;
[106]             }
[107] 
[108]             if (module->ctx_index == next) {
[109]                 next++;
[110]             }
[111] 
[112]             continue;
[113]         }
[114] 
[115]         /* search for some free index */
[116] 
[117]         module->ctx_index = ngx_module_ctx_index(cycle, type, next);
[118] 
[119]         if (module->ctx_index > max) {
[120]             max = module->ctx_index;
[121]         }
[122] 
[123]         next = module->ctx_index + 1;
[124]     }
[125] 
[126]     /*
[127]      * make sure the number returned is big enough for previous
[128]      * cycle as well, else there will be problems if the number
[129]      * will be stored in a global variable (as it's used to be)
[130]      * and we'll have to roll back to the previous cycle
[131]      */
[132] 
[133]     if (cycle->old_cycle && cycle->old_cycle->modules) {
[134] 
[135]         for (i = 0; cycle->old_cycle->modules[i]; i++) {
[136]             module = cycle->old_cycle->modules[i];
[137] 
[138]             if (module->type != type) {
[139]                 continue;
[140]             }
[141] 
[142]             if (module->ctx_index > max) {
[143]                 max = module->ctx_index;
[144]             }
[145]         }
[146]     }
[147] 
[148]     /* prevent loading of additional modules */
[149] 
[150]     cycle->modules_used = 1;
[151] 
[152]     return max + 1;
[153] }
[154] 
[155] 
[156] ngx_int_t
[157] ngx_add_module(ngx_conf_t *cf, ngx_str_t *file, ngx_module_t *module,
[158]     char **order)
[159] {
[160]     void               *rv;
[161]     ngx_uint_t          i, m, before;
[162]     ngx_core_module_t  *core_module;
[163] 
[164]     if (cf->cycle->modules_n >= ngx_max_module) {
[165]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[166]                            "too many modules loaded");
[167]         return NGX_ERROR;
[168]     }
[169] 
[170]     if (module->version != nginx_version) {
[171]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[172]                            "module \"%V\" version %ui instead of %ui",
[173]                            file, module->version, (ngx_uint_t) nginx_version);
[174]         return NGX_ERROR;
[175]     }
[176] 
[177]     if (ngx_strcmp(module->signature, NGX_MODULE_SIGNATURE) != 0) {
[178]         ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[179]                            "module \"%V\" is not binary compatible",
[180]                            file);
[181]         return NGX_ERROR;
[182]     }
[183] 
[184]     for (m = 0; cf->cycle->modules[m]; m++) {
[185]         if (ngx_strcmp(cf->cycle->modules[m]->name, module->name) == 0) {
[186]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[187]                                "module \"%s\" is already loaded",
[188]                                module->name);
[189]             return NGX_ERROR;
[190]         }
[191]     }
[192] 
[193]     /*
[194]      * if the module wasn't previously loaded, assign an index
[195]      */
[196] 
[197]     if (module->index == NGX_MODULE_UNSET_INDEX) {
[198]         module->index = ngx_module_index(cf->cycle);
[199] 
[200]         if (module->index >= ngx_max_module) {
[201]             ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
[202]                                "too many modules loaded");
[203]             return NGX_ERROR;
[204]         }
[205]     }
[206] 
[207]     /*
[208]      * put the module into the cycle->modules array
[209]      */
[210] 
[211]     before = cf->cycle->modules_n;
[212] 
[213]     if (order) {
[214]         for (i = 0; order[i]; i++) {
[215]             if (ngx_strcmp(order[i], module->name) == 0) {
[216]                 i++;
[217]                 break;
[218]             }
[219]         }
[220] 
[221]         for ( /* void */ ; order[i]; i++) {
[222] 
[223] #if 0
[224]             ngx_log_debug2(NGX_LOG_DEBUG_CORE, cf->log, 0,
[225]                            "module: %s before %s",
[226]                            module->name, order[i]);
[227] #endif
[228] 
[229]             for (m = 0; m < before; m++) {
[230]                 if (ngx_strcmp(cf->cycle->modules[m]->name, order[i]) == 0) {
[231] 
[232]                     ngx_log_debug3(NGX_LOG_DEBUG_CORE, cf->log, 0,
[233]                                    "module: %s before %s:%i",
[234]                                    module->name, order[i], m);
[235] 
[236]                     before = m;
[237]                     break;
[238]                 }
[239]             }
[240]         }
[241]     }
[242] 
[243]     /* put the module before modules[before] */
[244] 
[245]     if (before != cf->cycle->modules_n) {
[246]         ngx_memmove(&cf->cycle->modules[before + 1],
[247]                     &cf->cycle->modules[before],
[248]                     (cf->cycle->modules_n - before) * sizeof(ngx_module_t *));
[249]     }
[250] 
[251]     cf->cycle->modules[before] = module;
[252]     cf->cycle->modules_n++;
[253] 
[254]     if (module->type == NGX_CORE_MODULE) {
[255] 
[256]         /*
[257]          * we are smart enough to initialize core modules;
[258]          * other modules are expected to be loaded before
[259]          * initialization - e.g., http modules must be loaded
[260]          * before http{} block
[261]          */
[262] 
[263]         core_module = module->ctx;
[264] 
[265]         if (core_module->create_conf) {
[266]             rv = core_module->create_conf(cf->cycle);
[267]             if (rv == NULL) {
[268]                 return NGX_ERROR;
[269]             }
[270] 
[271]             cf->cycle->conf_ctx[module->index] = rv;
[272]         }
[273]     }
[274] 
[275]     return NGX_OK;
[276] }
[277] 
[278] 
[279] static ngx_uint_t
[280] ngx_module_index(ngx_cycle_t *cycle)
[281] {
[282]     ngx_uint_t     i, index;
[283]     ngx_module_t  *module;
[284] 
[285]     index = 0;
[286] 
[287] again:
[288] 
[289]     /* find an unused index */
[290] 
[291]     for (i = 0; cycle->modules[i]; i++) {
[292]         module = cycle->modules[i];
[293] 
[294]         if (module->index == index) {
[295]             index++;
[296]             goto again;
[297]         }
[298]     }
[299] 
[300]     /* check previous cycle */
[301] 
[302]     if (cycle->old_cycle && cycle->old_cycle->modules) {
[303] 
[304]         for (i = 0; cycle->old_cycle->modules[i]; i++) {
[305]             module = cycle->old_cycle->modules[i];
[306] 
[307]             if (module->index == index) {
[308]                 index++;
[309]                 goto again;
[310]             }
[311]         }
[312]     }
[313] 
[314]     return index;
[315] }
[316] 
[317] 
[318] static ngx_uint_t
[319] ngx_module_ctx_index(ngx_cycle_t *cycle, ngx_uint_t type, ngx_uint_t index)
[320] {
[321]     ngx_uint_t     i;
[322]     ngx_module_t  *module;
[323] 
[324] again:
[325] 
[326]     /* find an unused ctx_index */
[327] 
[328]     for (i = 0; cycle->modules[i]; i++) {
[329]         module = cycle->modules[i];
[330] 
[331]         if (module->type != type) {
[332]             continue;
[333]         }
[334] 
[335]         if (module->ctx_index == index) {
[336]             index++;
[337]             goto again;
[338]         }
[339]     }
[340] 
[341]     /* check previous cycle */
[342] 
[343]     if (cycle->old_cycle && cycle->old_cycle->modules) {
[344] 
[345]         for (i = 0; cycle->old_cycle->modules[i]; i++) {
[346]             module = cycle->old_cycle->modules[i];
[347] 
[348]             if (module->type != type) {
[349]                 continue;
[350]             }
[351] 
[352]             if (module->ctx_index == index) {
[353]                 index++;
[354]                 goto again;
[355]             }
[356]         }
[357]     }
[358] 
[359]     return index;
[360] }
