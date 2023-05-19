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
[11] /*
[12]  * declare Profiler interface here because
[13]  * <google/profiler.h> is C++ header file
[14]  */
[15] 
[16] int ProfilerStart(u_char* fname);
[17] void ProfilerStop(void);
[18] void ProfilerRegisterThread(void);
[19] 
[20] 
[21] static void *ngx_google_perftools_create_conf(ngx_cycle_t *cycle);
[22] static ngx_int_t ngx_google_perftools_worker(ngx_cycle_t *cycle);
[23] 
[24] 
[25] typedef struct {
[26]     ngx_str_t  profiles;
[27] } ngx_google_perftools_conf_t;
[28] 
[29] 
[30] static ngx_command_t  ngx_google_perftools_commands[] = {
[31] 
[32]     { ngx_string("google_perftools_profiles"),
[33]       NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
[34]       ngx_conf_set_str_slot,
[35]       0,
[36]       offsetof(ngx_google_perftools_conf_t, profiles),
[37]       NULL },
[38] 
[39]       ngx_null_command
[40] };
[41] 
[42] 
[43] static ngx_core_module_t  ngx_google_perftools_module_ctx = {
[44]     ngx_string("google_perftools"),
[45]     ngx_google_perftools_create_conf,
[46]     NULL
[47] };
[48] 
[49] 
[50] ngx_module_t  ngx_google_perftools_module = {
[51]     NGX_MODULE_V1,
[52]     &ngx_google_perftools_module_ctx,      /* module context */
[53]     ngx_google_perftools_commands,         /* module directives */
[54]     NGX_CORE_MODULE,                       /* module type */
[55]     NULL,                                  /* init master */
[56]     NULL,                                  /* init module */
[57]     ngx_google_perftools_worker,           /* init process */
[58]     NULL,                                  /* init thread */
[59]     NULL,                                  /* exit thread */
[60]     NULL,                                  /* exit process */
[61]     NULL,                                  /* exit master */
[62]     NGX_MODULE_V1_PADDING
[63] };
[64] 
[65] 
[66] static void *
[67] ngx_google_perftools_create_conf(ngx_cycle_t *cycle)
[68] {
[69]     ngx_google_perftools_conf_t  *gptcf;
[70] 
[71]     gptcf = ngx_pcalloc(cycle->pool, sizeof(ngx_google_perftools_conf_t));
[72]     if (gptcf == NULL) {
[73]         return NULL;
[74]     }
[75] 
[76]     /*
[77]      * set by ngx_pcalloc()
[78]      *
[79]      *     gptcf->profiles = { 0, NULL };
[80]      */
[81] 
[82]     return gptcf;
[83] }
[84] 
[85] 
[86] static ngx_int_t
[87] ngx_google_perftools_worker(ngx_cycle_t *cycle)
[88] {
[89]     u_char                       *profile;
[90]     ngx_google_perftools_conf_t  *gptcf;
[91] 
[92]     gptcf = (ngx_google_perftools_conf_t *)
[93]                 ngx_get_conf(cycle->conf_ctx, ngx_google_perftools_module);
[94] 
[95]     if (gptcf->profiles.len == 0) {
[96]         return NGX_OK;
[97]     }
[98] 
[99]     profile = ngx_alloc(gptcf->profiles.len + NGX_INT_T_LEN + 2, cycle->log);
[100]     if (profile == NULL) {
[101]         return NGX_OK;
[102]     }
[103] 
[104]     if (getenv("CPUPROFILE")) {
[105]         /* disable inherited Profiler enabled in master process */
[106]         ProfilerStop();
[107]     }
[108] 
[109]     ngx_sprintf(profile, "%V.%d%Z", &gptcf->profiles, ngx_pid);
[110] 
[111]     if (ProfilerStart(profile)) {
[112]         /* start ITIMER_PROF timer */
[113]         ProfilerRegisterThread();
[114] 
[115]     } else {
[116]         ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
[117]                       "ProfilerStart(%s) failed", profile);
[118]     }
[119] 
[120]     ngx_free(profile);
[121] 
[122]     return NGX_OK;
[123] }
[124] 
[125] 
[126] /* ProfilerStop() is called on Profiler destruction */
