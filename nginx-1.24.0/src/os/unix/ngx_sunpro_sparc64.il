[1] /
[2] / Copyright (C) Igor Sysoev
[3] / Copyright (C) Nginx, Inc.
[4] /
[5] 
[6] 
[7] /  "casa   [%o2] 0x80, %o1, %o0"  and
[8] /  "casxa  [%o2] 0x80, %o1, %o0"  do the following:
[9] /
[10] /       if ([%o2] == %o1) {
[11] /           swap(%o0, [%o2]);
[12] /       } else {
[13] /           %o0 = [%o2];
[14] /       }
[15] 
[16] 
[17] / ngx_atomic_uint_t ngx_casa(ngx_atomic_uint_t set, ngx_atomic_uint_t old,
[18] /      ngx_atomic_t *lock);
[19] /
[20] / the arguments are passed in the %o0, %o1, %o2
[21] / the result is returned in the %o0
[22] 
[23]         .inline ngx_casa,0
[24]         casa    [%o2] 0x80, %o1, %o0
[25]         .end
[26] 
[27] 
[28] / ngx_atomic_uint_t ngx_casxa(ngx_atomic_uint_t set, ngx_atomic_uint_t old,
[29] /      ngx_atomic_t *lock);
[30] /
[31] / the arguments are passed in the %o0, %o1, %o2
[32] / the result is returned in the %o0
[33] 
[34]         .inline ngx_casxa,0
[35]         casxa   [%o2] 0x80, %o1, %o0
[36]         .end
