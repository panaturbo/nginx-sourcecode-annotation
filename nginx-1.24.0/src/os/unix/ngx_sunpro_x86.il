[1] /
[2] / Copyright (C) Igor Sysoev
[3] / Copyright (C) Nginx, Inc.
[4] /
[5] 
[6] / ngx_atomic_uint_t ngx_atomic_cmp_set(ngx_atomic_t *lock,
[7] /     ngx_atomic_uint_t old, ngx_atomic_uint_t set);
[8] /
[9] / the arguments are passed on stack (%esp), 4(%esp), 8(%esp)
[10] 
[11]         .inline ngx_atomic_cmp_set,0
[12]         movl      (%esp), %ecx
[13]         movl      4(%esp), %eax
[14]         movl      8(%esp), %edx
[15]         lock
[16]         cmpxchgl  %edx, (%ecx)
[17]         setz      %al
[18]         movzbl    %al, %eax
[19]         .end
[20] 
[21] 
[22] / ngx_atomic_int_t ngx_atomic_fetch_add(ngx_atomic_t *value,
[23] /     ngx_atomic_int_t add);
[24] /
[25] / the arguments are passed on stack (%esp), 4(%esp)
[26] 
[27]         .inline ngx_atomic_fetch_add,0
[28]         movl      (%esp), %ecx
[29]         movl      4(%esp), %eax
[30]         lock
[31]         xaddl     %eax, (%ecx)
[32]         .end
[33] 
[34] 
[35] / ngx_cpu_pause()
[36] /
[37] / the "rep; nop" is used instead of "pause" to avoid the "[ PAUSE ]" hardware
[38] / capability added by linker because Solaris/i386 does not know about it:
[39] /
[40] / ld.so.1: nginx: fatal: hardware capability unsupported: 0x2000  [ PAUSE ]
[41] 
[42]         .inline ngx_cpu_pause,0
[43]         rep; nop
[44]         .end
