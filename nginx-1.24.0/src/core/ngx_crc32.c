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
[13]  * The code and lookup tables are based on the algorithm
[14]  * described at http://www.w3.org/TR/PNG/
[15]  *
[16]  * The 256 element lookup table takes 1024 bytes, and it may be completely
[17]  * cached after processing about 30-60 bytes of data.  So for short data
[18]  * we use the 16 element lookup table that takes only 64 bytes and align it
[19]  * to CPU cache line size.  Of course, the small table adds code inside
[20]  * CRC32 loop, but the cache misses overhead is bigger than overhead of
[21]  * the additional code.  For example, ngx_crc32_short() of 16 bytes of data
[22]  * takes half as much CPU clocks than ngx_crc32_long().
[23]  */
[24] 
[25] 
[26] static uint32_t  ngx_crc32_table16[] = {
[27]     0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
[28]     0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
[29]     0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
[30]     0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
[31] };
[32] 
[33] 
[34] uint32_t  ngx_crc32_table256[] = {
[35]     0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
[36]     0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
[37]     0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
[38]     0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
[39]     0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
[40]     0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
[41]     0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
[42]     0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
[43]     0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
[44]     0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
[45]     0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
[46]     0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
[47]     0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
[48]     0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
[49]     0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
[50]     0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
[51]     0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
[52]     0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
[53]     0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
[54]     0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
[55]     0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
[56]     0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
[57]     0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
[58]     0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
[59]     0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
[60]     0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
[61]     0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
[62]     0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
[63]     0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
[64]     0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
[65]     0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
[66]     0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
[67]     0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
[68]     0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
[69]     0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
[70]     0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
[71]     0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
[72]     0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
[73]     0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
[74]     0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
[75]     0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
[76]     0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
[77]     0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
[78]     0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
[79]     0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
[80]     0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
[81]     0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
[82]     0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
[83]     0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
[84]     0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
[85]     0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
[86]     0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
[87]     0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
[88]     0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
[89]     0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
[90]     0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
[91]     0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
[92]     0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
[93]     0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
[94]     0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
[95]     0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
[96]     0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
[97]     0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
[98]     0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
[99] };
[100] 
[101] 
[102] uint32_t *ngx_crc32_table_short = ngx_crc32_table16;
[103] 
[104] 
[105] ngx_int_t
[106] ngx_crc32_table_init(void)
[107] {
[108]     void  *p;
[109] 
[110]     if (((uintptr_t) ngx_crc32_table_short
[111]           & ~((uintptr_t) ngx_cacheline_size - 1))
[112]         == (uintptr_t) ngx_crc32_table_short)
[113]     {
[114]         return NGX_OK;
[115]     }
[116] 
[117]     p = ngx_alloc(16 * sizeof(uint32_t) + ngx_cacheline_size, ngx_cycle->log);
[118]     if (p == NULL) {
[119]         return NGX_ERROR;
[120]     }
[121] 
[122]     p = ngx_align_ptr(p, ngx_cacheline_size);
[123] 
[124]     ngx_memcpy(p, ngx_crc32_table16, 16 * sizeof(uint32_t));
[125] 
[126]     ngx_crc32_table_short = p;
[127] 
[128]     return NGX_OK;
[129] }
