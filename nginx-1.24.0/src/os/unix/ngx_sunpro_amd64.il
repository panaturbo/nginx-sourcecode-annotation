[1] /
[2] / Copyright (C) Igor Sysoev
[3] / Copyright (C) Nginx, Inc.
[4] /
[5] 
[6] / ngx_atomic_uint_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
[7] /     ngx_atomic_uint_t old, ngx_atomic_uint_t set);
[8] /
[9] / the arguments are passed in %rdi, %rsi, %rdx
[10] / the result is returned in the %rax
[11] 
[12]         .inline ngx_atomic_cmp_set,0
[13]         movq      %rsi, %rax
[14]         lock
[15]         cmpxchgq  %rdx, (%rdi)
[16]         setz      %al
[17]         movzbq    %al, %rax
[18]         .end
[19] 
[20] 
[21] / ngx_atomic_int_t ngx_atomic_fetch_add(ngx_atomic_t *value,
[22] /     ngx_atomic_int_t add);
[23] /
[24] / the arguments are passed in %rdi, %rsi
[25] / the result is returned in the %rax
[26] 
[27]         .inline ngx_atomic_fetch_add,0
[28]         movq      %rsi, %rax
[29]         lock
[30]         xaddq     %rax, (%rdi)
[31]         .end
[32] 
[33] 
[34] / ngx_cpu_pause()
[35] /
[36] / the "rep; nop" is used instead of "pause" to avoid the "[ PAUSE ]" hardware
[37] / capability added by linker because Solaris/amd64 does not know about it:
[38] /
[39] / ld.so.1: nginx: fatal: hardware capability unsupported: 0x2000 [ PAUSE ]
[40] 
[41]         .inline ngx_cpu_pause,0
[42]         rep; nop
[43]         .end
