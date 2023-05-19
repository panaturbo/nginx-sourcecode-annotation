[1] 
[2] /*
[3]  * Copyright (C) Ruslan Ermilov
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_RWLOCK_H_INCLUDED_
[9] #define _NGX_RWLOCK_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] 
[15] 
[16] void ngx_rwlock_wlock(ngx_atomic_t *lock);
[17] void ngx_rwlock_rlock(ngx_atomic_t *lock);
[18] void ngx_rwlock_unlock(ngx_atomic_t *lock);
[19] void ngx_rwlock_downgrade(ngx_atomic_t *lock);
[20] 
[21] 
[22] #endif /* _NGX_RWLOCK_H_INCLUDED_ */
