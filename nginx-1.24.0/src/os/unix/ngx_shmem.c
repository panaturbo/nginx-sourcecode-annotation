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
[12] #if (NGX_HAVE_MAP_ANON)
[13] 
[14] ngx_int_t
[15] ngx_shm_alloc(ngx_shm_t *shm)
[16] {
[17]     shm->addr = (u_char *) mmap(NULL, shm->size,
[18]                                 PROT_READ|PROT_WRITE,
[19]                                 MAP_ANON|MAP_SHARED, -1, 0);
[20] 
[21]     if (shm->addr == MAP_FAILED) {
[22]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[23]                       "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
[24]         return NGX_ERROR;
[25]     }
[26] 
[27]     return NGX_OK;
[28] }
[29] 
[30] 
[31] void
[32] ngx_shm_free(ngx_shm_t *shm)
[33] {
[34]     if (munmap((void *) shm->addr, shm->size) == -1) {
[35]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[36]                       "munmap(%p, %uz) failed", shm->addr, shm->size);
[37]     }
[38] }
[39] 
[40] #elif (NGX_HAVE_MAP_DEVZERO)
[41] 
[42] ngx_int_t
[43] ngx_shm_alloc(ngx_shm_t *shm)
[44] {
[45]     ngx_fd_t  fd;
[46] 
[47]     fd = open("/dev/zero", O_RDWR);
[48] 
[49]     if (fd == -1) {
[50]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[51]                       "open(\"/dev/zero\") failed");
[52]         return NGX_ERROR;
[53]     }
[54] 
[55]     shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE,
[56]                                 MAP_SHARED, fd, 0);
[57] 
[58]     if (shm->addr == MAP_FAILED) {
[59]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[60]                       "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
[61]     }
[62] 
[63]     if (close(fd) == -1) {
[64]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[65]                       "close(\"/dev/zero\") failed");
[66]     }
[67] 
[68]     return (shm->addr == MAP_FAILED) ? NGX_ERROR : NGX_OK;
[69] }
[70] 
[71] 
[72] void
[73] ngx_shm_free(ngx_shm_t *shm)
[74] {
[75]     if (munmap((void *) shm->addr, shm->size) == -1) {
[76]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[77]                       "munmap(%p, %uz) failed", shm->addr, shm->size);
[78]     }
[79] }
[80] 
[81] #elif (NGX_HAVE_SYSVSHM)
[82] 
[83] #include <sys/ipc.h>
[84] #include <sys/shm.h>
[85] 
[86] 
[87] ngx_int_t
[88] ngx_shm_alloc(ngx_shm_t *shm)
[89] {
[90]     int  id;
[91] 
[92]     id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));
[93] 
[94]     if (id == -1) {
[95]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[96]                       "shmget(%uz) failed", shm->size);
[97]         return NGX_ERROR;
[98]     }
[99] 
[100]     ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);
[101] 
[102]     shm->addr = shmat(id, NULL, 0);
[103] 
[104]     if (shm->addr == (void *) -1) {
[105]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno, "shmat() failed");
[106]     }
[107] 
[108]     if (shmctl(id, IPC_RMID, NULL) == -1) {
[109]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[110]                       "shmctl(IPC_RMID) failed");
[111]     }
[112] 
[113]     return (shm->addr == (void *) -1) ? NGX_ERROR : NGX_OK;
[114] }
[115] 
[116] 
[117] void
[118] ngx_shm_free(ngx_shm_t *shm)
[119] {
[120]     if (shmdt(shm->addr) == -1) {
[121]         ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
[122]                       "shmdt(%p) failed", shm->addr);
[123]     }
[124] }
[125] 
[126] #endif
