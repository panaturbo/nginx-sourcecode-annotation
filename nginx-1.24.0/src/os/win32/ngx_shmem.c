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
[11] 
[12] /*
[13]  * Base addresses selected by system for shared memory mappings are likely
[14]  * to be different on Windows Vista and later versions due to address space
[15]  * layout randomization.  This is however incompatible with storing absolute
[16]  * addresses within the shared memory.
[17]  *
[18]  * To make it possible to store absolute addresses we create mappings
[19]  * at the same address in all processes by starting mappings at predefined
[20]  * addresses.  The addresses were selected somewhat randomly in order to
[21]  * minimize the probability that some other library doing something similar
[22]  * conflicts with us.  The addresses are from the following typically free
[23]  * blocks:
[24]  *
[25]  * - 0x10000000 .. 0x70000000 (about 1.5 GB in total) on 32-bit platforms
[26]  * - 0x000000007fff0000 .. 0x000007f68e8b0000 (about 8 TB) on 64-bit platforms
[27]  *
[28]  * Additionally, we allow to change the mapping address once it was detected
[29]  * to be different from one originally used.  This is needed to support
[30]  * reconfiguration.
[31]  */
[32] 
[33] 
[34] #ifdef _WIN64
[35] #define NGX_SHMEM_BASE  0x0000047047e00000
[36] #else
[37] #define NGX_SHMEM_BASE  0x2efe0000
[38] #endif
[39] 
[40] 
[41] ngx_uint_t  ngx_allocation_granularity;
[42] 
[43] 
[44] ngx_int_t
[45] ngx_shm_alloc(ngx_shm_t *shm)
[46] {
[47]     u_char         *name;
[48]     uint64_t        size;
[49]     static u_char  *base = (u_char *) NGX_SHMEM_BASE;
[50] 
[51]     name = ngx_alloc(shm->name.len + 2 + NGX_INT32_LEN, shm->log);
[52]     if (name == NULL) {
[53]         return NGX_ERROR;
[54]     }
[55] 
[56]     (void) ngx_sprintf(name, "%V_%s%Z", &shm->name, ngx_unique);
[57] 
[58]     ngx_set_errno(0);
[59] 
[60]     size = shm->size;
[61] 
[62]     shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
[63]                                     (u_long) (size >> 32),
[64]                                     (u_long) (size & 0xffffffff),
[65]                                     (char *) name);
[66] 
[67]     if (shm->handle == NULL) {
[68]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[69]                       "CreateFileMapping(%uz, %s) failed",
[70]                       shm->size, name);
[71]         ngx_free(name);
[72] 
[73]         return NGX_ERROR;
[74]     }
[75] 
[76]     ngx_free(name);
[77] 
[78]     if (ngx_errno == ERROR_ALREADY_EXISTS) {
[79]         shm->exists = 1;
[80]     }
[81] 
[82]     shm->addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, base);
[83] 
[84]     if (shm->addr != NULL) {
[85]         base += ngx_align(size, ngx_allocation_granularity);
[86]         return NGX_OK;
[87]     }
[88] 
[89]     ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm->log, ngx_errno,
[90]                    "MapViewOfFileEx(%uz, %p) of file mapping \"%V\" failed, "
[91]                    "retry without a base address",
[92]                    shm->size, base, &shm->name);
[93] 
[94]     /*
[95]      * Order of shared memory zones may be different in the master process
[96]      * and worker processes after reconfiguration.  As a result, the above
[97]      * may fail due to a conflict with a previously created mapping remapped
[98]      * to a different address.  Additionally, there may be a conflict with
[99]      * some other uses of the memory.  In this case we retry without a base
[100]      * address to let the system assign the address itself.
[101]      */
[102] 
[103]     shm->addr = MapViewOfFile(shm->handle, FILE_MAP_WRITE, 0, 0, 0);
[104] 
[105]     if (shm->addr != NULL) {
[106]         return NGX_OK;
[107]     }
[108] 
[109]     ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[110]                   "MapViewOfFile(%uz) of file mapping \"%V\" failed",
[111]                   shm->size, &shm->name);
[112] 
[113]     if (CloseHandle(shm->handle) == 0) {
[114]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[115]                       "CloseHandle() of file mapping \"%V\" failed",
[116]                       &shm->name);
[117]     }
[118] 
[119]     return NGX_ERROR;
[120] }
[121] 
[122] 
[123] ngx_int_t
[124] ngx_shm_remap(ngx_shm_t *shm, u_char *addr)
[125] {
[126]     if (UnmapViewOfFile(shm->addr) == 0) {
[127]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[128]                       "UnmapViewOfFile(%p) of file mapping \"%V\" failed",
[129]                       shm->addr, &shm->name);
[130]         return NGX_ERROR;
[131]     }
[132] 
[133]     shm->addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, addr);
[134] 
[135]     if (shm->addr != NULL) {
[136]         return NGX_OK;
[137]     }
[138] 
[139]     ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[140]                   "MapViewOfFileEx(%uz, %p) of file mapping \"%V\" failed",
[141]                   shm->size, addr, &shm->name);
[142] 
[143]     return NGX_ERROR;
[144] }
[145] 
[146] 
[147] void
[148] ngx_shm_free(ngx_shm_t *shm)
[149] {
[150]     if (UnmapViewOfFile(shm->addr) == 0) {
[151]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[152]                       "UnmapViewOfFile(%p) of file mapping \"%V\" failed",
[153]                       shm->addr, &shm->name);
[154]     }
[155] 
[156]     if (CloseHandle(shm->handle) == 0) {
[157]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[158]                       "CloseHandle() of file mapping \"%V\" failed",
[159]                       &shm->name);
[160]     }
[161] }
