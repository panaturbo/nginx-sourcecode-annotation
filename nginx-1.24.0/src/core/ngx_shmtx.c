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
[12] #if (NGX_HAVE_ATOMIC_OPS)
[13] 
[14] 
[15] static void ngx_shmtx_wakeup(ngx_shmtx_t *mtx);
[16] 
[17] 
[18] ngx_int_t
[19] ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
[20] {
[21]     mtx->lock = &addr->lock;
[22] 
[23]     if (mtx->spin == (ngx_uint_t) -1) {
[24]         return NGX_OK;
[25]     }
[26] 
[27]     mtx->spin = 2048;
[28] 
[29] #if (NGX_HAVE_POSIX_SEM)
[30] 
[31]     mtx->wait = &addr->wait;
[32] 
[33]     if (sem_init(&mtx->sem, 1, 0) == -1) {
[34]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
[35]                       "sem_init() failed");
[36]     } else {
[37]         mtx->semaphore = 1;
[38]     }
[39] 
[40] #endif
[41] 
[42]     return NGX_OK;
[43] }
[44] 
[45] 
[46] void
[47] ngx_shmtx_destroy(ngx_shmtx_t *mtx)
[48] {
[49] #if (NGX_HAVE_POSIX_SEM)
[50] 
[51]     if (mtx->semaphore) {
[52]         if (sem_destroy(&mtx->sem) == -1) {
[53]             ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
[54]                           "sem_destroy() failed");
[55]         }
[56]     }
[57] 
[58] #endif
[59] }
[60] 
[61] 
[62] ngx_uint_t
[63] ngx_shmtx_trylock(ngx_shmtx_t *mtx)
[64] {
[65]     return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
[66] }
[67] 
[68] 
[69] void
[70] ngx_shmtx_lock(ngx_shmtx_t *mtx)
[71] {
[72]     ngx_uint_t         i, n;
[73] 
[74]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");
[75] 
[76]     for ( ;; ) {
[77] 
[78]         if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
[79]             return;
[80]         }
[81] 
[82]         if (ngx_ncpu > 1) {
[83] 
[84]             for (n = 1; n < mtx->spin; n <<= 1) {
[85] 
[86]                 for (i = 0; i < n; i++) {
[87]                     ngx_cpu_pause();
[88]                 }
[89] 
[90]                 if (*mtx->lock == 0
[91]                     && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid))
[92]                 {
[93]                     return;
[94]                 }
[95]             }
[96]         }
[97] 
[98] #if (NGX_HAVE_POSIX_SEM)
[99] 
[100]         if (mtx->semaphore) {
[101]             (void) ngx_atomic_fetch_add(mtx->wait, 1);
[102] 
[103]             if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
[104]                 (void) ngx_atomic_fetch_add(mtx->wait, -1);
[105]                 return;
[106]             }
[107] 
[108]             ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[109]                            "shmtx wait %uA", *mtx->wait);
[110] 
[111]             while (sem_wait(&mtx->sem) == -1) {
[112]                 ngx_err_t  err;
[113] 
[114]                 err = ngx_errno;
[115] 
[116]                 if (err != NGX_EINTR) {
[117]                     ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
[118]                                   "sem_wait() failed while waiting on shmtx");
[119]                     break;
[120]                 }
[121]             }
[122] 
[123]             ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[124]                            "shmtx awoke");
[125] 
[126]             continue;
[127]         }
[128] 
[129] #endif
[130] 
[131]         ngx_sched_yield();
[132]     }
[133] }
[134] 
[135] 
[136] void
[137] ngx_shmtx_unlock(ngx_shmtx_t *mtx)
[138] {
[139]     if (mtx->spin != (ngx_uint_t) -1) {
[140]         ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
[141]     }
[142] 
[143]     if (ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
[144]         ngx_shmtx_wakeup(mtx);
[145]     }
[146] }
[147] 
[148] 
[149] ngx_uint_t
[150] ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
[151] {
[152]     ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[153]                    "shmtx forced unlock");
[154] 
[155]     if (ngx_atomic_cmp_set(mtx->lock, pid, 0)) {
[156]         ngx_shmtx_wakeup(mtx);
[157]         return 1;
[158]     }
[159] 
[160]     return 0;
[161] }
[162] 
[163] 
[164] static void
[165] ngx_shmtx_wakeup(ngx_shmtx_t *mtx)
[166] {
[167] #if (NGX_HAVE_POSIX_SEM)
[168]     ngx_atomic_uint_t  wait;
[169] 
[170]     if (!mtx->semaphore) {
[171]         return;
[172]     }
[173] 
[174]     for ( ;; ) {
[175] 
[176]         wait = *mtx->wait;
[177] 
[178]         if ((ngx_atomic_int_t) wait <= 0) {
[179]             return;
[180]         }
[181] 
[182]         if (ngx_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
[183]             break;
[184]         }
[185]     }
[186] 
[187]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
[188]                    "shmtx wake %uA", wait);
[189] 
[190]     if (sem_post(&mtx->sem) == -1) {
[191]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
[192]                       "sem_post() failed while wake shmtx");
[193]     }
[194] 
[195] #endif
[196] }
[197] 
[198] 
[199] #else
[200] 
[201] 
[202] ngx_int_t
[203] ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
[204] {
[205]     if (mtx->name) {
[206] 
[207]         if (ngx_strcmp(name, mtx->name) == 0) {
[208]             mtx->name = name;
[209]             return NGX_OK;
[210]         }
[211] 
[212]         ngx_shmtx_destroy(mtx);
[213]     }
[214] 
[215]     mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
[216]                             NGX_FILE_DEFAULT_ACCESS);
[217] 
[218]     if (mtx->fd == NGX_INVALID_FILE) {
[219]         ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
[220]                       ngx_open_file_n " \"%s\" failed", name);
[221]         return NGX_ERROR;
[222]     }
[223] 
[224]     if (ngx_delete_file(name) == NGX_FILE_ERROR) {
[225]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
[226]                       ngx_delete_file_n " \"%s\" failed", name);
[227]     }
[228] 
[229]     mtx->name = name;
[230] 
[231]     return NGX_OK;
[232] }
[233] 
[234] 
[235] void
[236] ngx_shmtx_destroy(ngx_shmtx_t *mtx)
[237] {
[238]     if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
[239]         ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
[240]                       ngx_close_file_n " \"%s\" failed", mtx->name);
[241]     }
[242] }
[243] 
[244] 
[245] ngx_uint_t
[246] ngx_shmtx_trylock(ngx_shmtx_t *mtx)
[247] {
[248]     ngx_err_t  err;
[249] 
[250]     err = ngx_trylock_fd(mtx->fd);
[251] 
[252]     if (err == 0) {
[253]         return 1;
[254]     }
[255] 
[256]     if (err == NGX_EAGAIN) {
[257]         return 0;
[258]     }
[259] 
[260] #if __osf__ /* Tru64 UNIX */
[261] 
[262]     if (err == NGX_EACCES) {
[263]         return 0;
[264]     }
[265] 
[266] #endif
[267] 
[268]     ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);
[269] 
[270]     return 0;
[271] }
[272] 
[273] 
[274] void
[275] ngx_shmtx_lock(ngx_shmtx_t *mtx)
[276] {
[277]     ngx_err_t  err;
[278] 
[279]     err = ngx_lock_fd(mtx->fd);
[280] 
[281]     if (err == 0) {
[282]         return;
[283]     }
[284] 
[285]     ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
[286] }
[287] 
[288] 
[289] void
[290] ngx_shmtx_unlock(ngx_shmtx_t *mtx)
[291] {
[292]     ngx_err_t  err;
[293] 
[294]     err = ngx_unlock_fd(mtx->fd);
[295] 
[296]     if (err == 0) {
[297]         return;
[298]     }
[299] 
[300]     ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
[301] }
[302] 
[303] 
[304] ngx_uint_t
[305] ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
[306] {
[307]     return 0;
[308] }
[309] 
[310] #endif
