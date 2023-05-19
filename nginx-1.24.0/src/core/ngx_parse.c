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
[12] ssize_t
[13] ngx_parse_size(ngx_str_t *line)
[14] {
[15]     u_char   unit;
[16]     size_t   len;
[17]     ssize_t  size, scale, max;
[18] 
[19]     len = line->len;
[20] 
[21]     if (len == 0) {
[22]         return NGX_ERROR;
[23]     }
[24] 
[25]     unit = line->data[len - 1];
[26] 
[27]     switch (unit) {
[28]     case 'K':
[29]     case 'k':
[30]         len--;
[31]         max = NGX_MAX_SIZE_T_VALUE / 1024;
[32]         scale = 1024;
[33]         break;
[34] 
[35]     case 'M':
[36]     case 'm':
[37]         len--;
[38]         max = NGX_MAX_SIZE_T_VALUE / (1024 * 1024);
[39]         scale = 1024 * 1024;
[40]         break;
[41] 
[42]     default:
[43]         max = NGX_MAX_SIZE_T_VALUE;
[44]         scale = 1;
[45]     }
[46] 
[47]     size = ngx_atosz(line->data, len);
[48]     if (size == NGX_ERROR || size > max) {
[49]         return NGX_ERROR;
[50]     }
[51] 
[52]     size *= scale;
[53] 
[54]     return size;
[55] }
[56] 
[57] 
[58] off_t
[59] ngx_parse_offset(ngx_str_t *line)
[60] {
[61]     u_char  unit;
[62]     off_t   offset, scale, max;
[63]     size_t  len;
[64] 
[65]     len = line->len;
[66] 
[67]     if (len == 0) {
[68]         return NGX_ERROR;
[69]     }
[70] 
[71]     unit = line->data[len - 1];
[72] 
[73]     switch (unit) {
[74]     case 'K':
[75]     case 'k':
[76]         len--;
[77]         max = NGX_MAX_OFF_T_VALUE / 1024;
[78]         scale = 1024;
[79]         break;
[80] 
[81]     case 'M':
[82]     case 'm':
[83]         len--;
[84]         max = NGX_MAX_OFF_T_VALUE / (1024 * 1024);
[85]         scale = 1024 * 1024;
[86]         break;
[87] 
[88]     case 'G':
[89]     case 'g':
[90]         len--;
[91]         max = NGX_MAX_OFF_T_VALUE / (1024 * 1024 * 1024);
[92]         scale = 1024 * 1024 * 1024;
[93]         break;
[94] 
[95]     default:
[96]         max = NGX_MAX_OFF_T_VALUE;
[97]         scale = 1;
[98]     }
[99] 
[100]     offset = ngx_atoof(line->data, len);
[101]     if (offset == NGX_ERROR || offset > max) {
[102]         return NGX_ERROR;
[103]     }
[104] 
[105]     offset *= scale;
[106] 
[107]     return offset;
[108] }
[109] 
[110] 
[111] ngx_int_t
[112] ngx_parse_time(ngx_str_t *line, ngx_uint_t is_sec)
[113] {
[114]     u_char      *p, *last;
[115]     ngx_int_t    value, total, scale;
[116]     ngx_int_t    max, cutoff, cutlim;
[117]     ngx_uint_t   valid;
[118]     enum {
[119]         st_start = 0,
[120]         st_year,
[121]         st_month,
[122]         st_week,
[123]         st_day,
[124]         st_hour,
[125]         st_min,
[126]         st_sec,
[127]         st_msec,
[128]         st_last
[129]     } step;
[130] 
[131]     valid = 0;
[132]     value = 0;
[133]     total = 0;
[134]     cutoff = NGX_MAX_INT_T_VALUE / 10;
[135]     cutlim = NGX_MAX_INT_T_VALUE % 10;
[136]     step = is_sec ? st_start : st_month;
[137] 
[138]     p = line->data;
[139]     last = p + line->len;
[140] 
[141]     while (p < last) {
[142] 
[143]         if (*p >= '0' && *p <= '9') {
[144]             if (value >= cutoff && (value > cutoff || *p - '0' > cutlim)) {
[145]                 return NGX_ERROR;
[146]             }
[147] 
[148]             value = value * 10 + (*p++ - '0');
[149]             valid = 1;
[150]             continue;
[151]         }
[152] 
[153]         switch (*p++) {
[154] 
[155]         case 'y':
[156]             if (step > st_start) {
[157]                 return NGX_ERROR;
[158]             }
[159]             step = st_year;
[160]             max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24 * 365);
[161]             scale = 60 * 60 * 24 * 365;
[162]             break;
[163] 
[164]         case 'M':
[165]             if (step >= st_month) {
[166]                 return NGX_ERROR;
[167]             }
[168]             step = st_month;
[169]             max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24 * 30);
[170]             scale = 60 * 60 * 24 * 30;
[171]             break;
[172] 
[173]         case 'w':
[174]             if (step >= st_week) {
[175]                 return NGX_ERROR;
[176]             }
[177]             step = st_week;
[178]             max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24 * 7);
[179]             scale = 60 * 60 * 24 * 7;
[180]             break;
[181] 
[182]         case 'd':
[183]             if (step >= st_day) {
[184]                 return NGX_ERROR;
[185]             }
[186]             step = st_day;
[187]             max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24);
[188]             scale = 60 * 60 * 24;
[189]             break;
[190] 
[191]         case 'h':
[192]             if (step >= st_hour) {
[193]                 return NGX_ERROR;
[194]             }
[195]             step = st_hour;
[196]             max = NGX_MAX_INT_T_VALUE / (60 * 60);
[197]             scale = 60 * 60;
[198]             break;
[199] 
[200]         case 'm':
[201]             if (p < last && *p == 's') {
[202]                 if (is_sec || step >= st_msec) {
[203]                     return NGX_ERROR;
[204]                 }
[205]                 p++;
[206]                 step = st_msec;
[207]                 max = NGX_MAX_INT_T_VALUE;
[208]                 scale = 1;
[209]                 break;
[210]             }
[211] 
[212]             if (step >= st_min) {
[213]                 return NGX_ERROR;
[214]             }
[215]             step = st_min;
[216]             max = NGX_MAX_INT_T_VALUE / 60;
[217]             scale = 60;
[218]             break;
[219] 
[220]         case 's':
[221]             if (step >= st_sec) {
[222]                 return NGX_ERROR;
[223]             }
[224]             step = st_sec;
[225]             max = NGX_MAX_INT_T_VALUE;
[226]             scale = 1;
[227]             break;
[228] 
[229]         case ' ':
[230]             if (step >= st_sec) {
[231]                 return NGX_ERROR;
[232]             }
[233]             step = st_last;
[234]             max = NGX_MAX_INT_T_VALUE;
[235]             scale = 1;
[236]             break;
[237] 
[238]         default:
[239]             return NGX_ERROR;
[240]         }
[241] 
[242]         if (step != st_msec && !is_sec) {
[243]             scale *= 1000;
[244]             max /= 1000;
[245]         }
[246] 
[247]         if (value > max) {
[248]             return NGX_ERROR;
[249]         }
[250] 
[251]         value *= scale;
[252] 
[253]         if (total > NGX_MAX_INT_T_VALUE - value) {
[254]             return NGX_ERROR;
[255]         }
[256] 
[257]         total += value;
[258] 
[259]         value = 0;
[260] 
[261]         while (p < last && *p == ' ') {
[262]             p++;
[263]         }
[264]     }
[265] 
[266]     if (!valid) {
[267]         return NGX_ERROR;
[268]     }
[269] 
[270]     if (!is_sec) {
[271]         if (value > NGX_MAX_INT_T_VALUE / 1000) {
[272]             return NGX_ERROR;
[273]         }
[274] 
[275]         value *= 1000;
[276]     }
[277] 
[278]     if (total > NGX_MAX_INT_T_VALUE - value) {
[279]         return NGX_ERROR;
[280]     }
[281] 
[282]     return total + value;
[283] }
