[1] 
[2] /*
[3]  * Copyright (C) Austin Appleby
[4]  */
[5] 
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] 
[10] 
[11] uint32_t
[12] ngx_murmur_hash2(u_char *data, size_t len)
[13] {
[14]     uint32_t  h, k;
[15] 
[16]     h = 0 ^ len;
[17] 
[18]     while (len >= 4) {
[19]         k  = data[0];
[20]         k |= data[1] << 8;
[21]         k |= data[2] << 16;
[22]         k |= data[3] << 24;
[23] 
[24]         k *= 0x5bd1e995;
[25]         k ^= k >> 24;
[26]         k *= 0x5bd1e995;
[27] 
[28]         h *= 0x5bd1e995;
[29]         h ^= k;
[30] 
[31]         data += 4;
[32]         len -= 4;
[33]     }
[34] 
[35]     switch (len) {
[36]     case 3:
[37]         h ^= data[2] << 16;
[38]         /* fall through */
[39]     case 2:
[40]         h ^= data[1] << 8;
[41]         /* fall through */
[42]     case 1:
[43]         h ^= data[0];
[44]         h *= 0x5bd1e995;
[45]     }
[46] 
[47]     h ^= h >> 13;
[48]     h *= 0x5bd1e995;
[49]     h ^= h >> 15;
[50] 
[51]     return h;
[52] }
