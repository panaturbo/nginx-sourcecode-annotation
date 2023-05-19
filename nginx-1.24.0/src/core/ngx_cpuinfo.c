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
[12] #if (( __i386__ || __amd64__ ) && ( __GNUC__ || __INTEL_COMPILER ))
[13] 
[14] 
[15] static ngx_inline void ngx_cpuid(uint32_t i, uint32_t *buf);
[16] 
[17] 
[18] #if ( __i386__ )
[19] 
[20] static ngx_inline void
[21] ngx_cpuid(uint32_t i, uint32_t *buf)
[22] {
[23] 
[24]     /*
[25]      * we could not use %ebx as output parameter if gcc builds PIC,
[26]      * and we could not save %ebx on stack, because %esp is used,
[27]      * when the -fomit-frame-pointer optimization is specified.
[28]      */
[29] 
[30]     __asm__ (
[31] 
[32]     "    mov    %%ebx, %%esi;  "
[33] 
[34]     "    cpuid;                "
[35]     "    mov    %%eax, (%1);   "
[36]     "    mov    %%ebx, 4(%1);  "
[37]     "    mov    %%edx, 8(%1);  "
[38]     "    mov    %%ecx, 12(%1); "
[39] 
[40]     "    mov    %%esi, %%ebx;  "
[41] 
[42]     : : "a" (i), "D" (buf) : "ecx", "edx", "esi", "memory" );
[43] }
[44] 
[45] 
[46] #else /* __amd64__ */
[47] 
[48] 
[49] static ngx_inline void
[50] ngx_cpuid(uint32_t i, uint32_t *buf)
[51] {
[52]     uint32_t  eax, ebx, ecx, edx;
[53] 
[54]     __asm__ (
[55] 
[56]         "cpuid"
[57] 
[58]     : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (i) );
[59] 
[60]     buf[0] = eax;
[61]     buf[1] = ebx;
[62]     buf[2] = edx;
[63]     buf[3] = ecx;
[64] }
[65] 
[66] 
[67] #endif
[68] 
[69] 
[70] /* auto detect the L2 cache line size of modern and widespread CPUs */
[71] 
[72] void
[73] ngx_cpuinfo(void)
[74] {
[75]     u_char    *vendor;
[76]     uint32_t   vbuf[5], cpu[4], model;
[77] 
[78]     vbuf[0] = 0;
[79]     vbuf[1] = 0;
[80]     vbuf[2] = 0;
[81]     vbuf[3] = 0;
[82]     vbuf[4] = 0;
[83] 
[84]     ngx_cpuid(0, vbuf);
[85] 
[86]     vendor = (u_char *) &vbuf[1];
[87] 
[88]     if (vbuf[0] == 0) {
[89]         return;
[90]     }
[91] 
[92]     ngx_cpuid(1, cpu);
[93] 
[94]     if (ngx_strcmp(vendor, "GenuineIntel") == 0) {
[95] 
[96]         switch ((cpu[0] & 0xf00) >> 8) {
[97] 
[98]         /* Pentium */
[99]         case 5:
[100]             ngx_cacheline_size = 32;
[101]             break;
[102] 
[103]         /* Pentium Pro, II, III */
[104]         case 6:
[105]             ngx_cacheline_size = 32;
[106] 
[107]             model = ((cpu[0] & 0xf0000) >> 8) | (cpu[0] & 0xf0);
[108] 
[109]             if (model >= 0xd0) {
[110]                 /* Intel Core, Core 2, Atom */
[111]                 ngx_cacheline_size = 64;
[112]             }
[113] 
[114]             break;
[115] 
[116]         /*
[117]          * Pentium 4, although its cache line size is 64 bytes,
[118]          * it prefetches up to two cache lines during memory read
[119]          */
[120]         case 15:
[121]             ngx_cacheline_size = 128;
[122]             break;
[123]         }
[124] 
[125]     } else if (ngx_strcmp(vendor, "AuthenticAMD") == 0) {
[126]         ngx_cacheline_size = 64;
[127]     }
[128] }
[129] 
[130] #else
[131] 
[132] 
[133] void
[134] ngx_cpuinfo(void)
[135] {
[136] }
[137] 
[138] 
[139] #endif
