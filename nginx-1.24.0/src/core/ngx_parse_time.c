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
[12] static ngx_uint_t  mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
[13] 
[14] time_t
[15] ngx_parse_http_time(u_char *value, size_t len)
[16] {
[17]     u_char      *p, *end;
[18]     ngx_int_t    month;
[19]     ngx_uint_t   day, year, hour, min, sec;
[20]     uint64_t     time;
[21]     enum {
[22]         no = 0,
[23]         rfc822,   /* Tue, 10 Nov 2002 23:50:13   */
[24]         rfc850,   /* Tuesday, 10-Dec-02 23:50:13 */
[25]         isoc      /* Tue Dec 10 23:50:13 2002    */
[26]     } fmt;
[27] 
[28]     fmt = 0;
[29]     end = value + len;
[30] 
[31] #if (NGX_SUPPRESS_WARN)
[32]     day = 32;
[33]     year = 2038;
[34] #endif
[35] 
[36]     for (p = value; p < end; p++) {
[37]         if (*p == ',') {
[38]             break;
[39]         }
[40] 
[41]         if (*p == ' ') {
[42]             fmt = isoc;
[43]             break;
[44]         }
[45]     }
[46] 
[47]     for (p++; p < end; p++) {
[48]         if (*p != ' ') {
[49]             break;
[50]         }
[51]     }
[52] 
[53]     if (end - p < 18) {
[54]         return NGX_ERROR;
[55]     }
[56] 
[57]     if (fmt != isoc) {
[58]         if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
[59]             return NGX_ERROR;
[60]         }
[61] 
[62]         day = (*p - '0') * 10 + (*(p + 1) - '0');
[63]         p += 2;
[64] 
[65]         if (*p == ' ') {
[66]             if (end - p < 18) {
[67]                 return NGX_ERROR;
[68]             }
[69]             fmt = rfc822;
[70] 
[71]         } else if (*p == '-') {
[72]             fmt = rfc850;
[73] 
[74]         } else {
[75]             return NGX_ERROR;
[76]         }
[77] 
[78]         p++;
[79]     }
[80] 
[81]     switch (*p) {
[82] 
[83]     case 'J':
[84]         month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
[85]         break;
[86] 
[87]     case 'F':
[88]         month = 1;
[89]         break;
[90] 
[91]     case 'M':
[92]         month = *(p + 2) == 'r' ? 2 : 4;
[93]         break;
[94] 
[95]     case 'A':
[96]         month = *(p + 1) == 'p' ? 3 : 7;
[97]         break;
[98] 
[99]     case 'S':
[100]         month = 8;
[101]         break;
[102] 
[103]     case 'O':
[104]         month = 9;
[105]         break;
[106] 
[107]     case 'N':
[108]         month = 10;
[109]         break;
[110] 
[111]     case 'D':
[112]         month = 11;
[113]         break;
[114] 
[115]     default:
[116]         return NGX_ERROR;
[117]     }
[118] 
[119]     p += 3;
[120] 
[121]     if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
[122]         return NGX_ERROR;
[123]     }
[124] 
[125]     p++;
[126] 
[127]     if (fmt == rfc822) {
[128]         if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
[129]             || *(p + 2) < '0' || *(p + 2) > '9'
[130]             || *(p + 3) < '0' || *(p + 3) > '9')
[131]         {
[132]             return NGX_ERROR;
[133]         }
[134] 
[135]         year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
[136]                + (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
[137]         p += 4;
[138] 
[139]     } else if (fmt == rfc850) {
[140]         if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
[141]             return NGX_ERROR;
[142]         }
[143] 
[144]         year = (*p - '0') * 10 + (*(p + 1) - '0');
[145]         year += (year < 70) ? 2000 : 1900;
[146]         p += 2;
[147]     }
[148] 
[149]     if (fmt == isoc) {
[150]         if (*p == ' ') {
[151]             p++;
[152]         }
[153] 
[154]         if (*p < '0' || *p > '9') {
[155]             return NGX_ERROR;
[156]         }
[157] 
[158]         day = *p++ - '0';
[159] 
[160]         if (*p != ' ') {
[161]             if (*p < '0' || *p > '9') {
[162]                 return NGX_ERROR;
[163]             }
[164] 
[165]             day = day * 10 + (*p++ - '0');
[166]         }
[167] 
[168]         if (end - p < 14) {
[169]             return NGX_ERROR;
[170]         }
[171]     }
[172] 
[173]     if (*p++ != ' ') {
[174]         return NGX_ERROR;
[175]     }
[176] 
[177]     if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
[178]         return NGX_ERROR;
[179]     }
[180] 
[181]     hour = (*p - '0') * 10 + (*(p + 1) - '0');
[182]     p += 2;
[183] 
[184]     if (*p++ != ':') {
[185]         return NGX_ERROR;
[186]     }
[187] 
[188]     if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
[189]         return NGX_ERROR;
[190]     }
[191] 
[192]     min = (*p - '0') * 10 + (*(p + 1) - '0');
[193]     p += 2;
[194] 
[195]     if (*p++ != ':') {
[196]         return NGX_ERROR;
[197]     }
[198] 
[199]     if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
[200]         return NGX_ERROR;
[201]     }
[202] 
[203]     sec = (*p - '0') * 10 + (*(p + 1) - '0');
[204] 
[205]     if (fmt == isoc) {
[206]         p += 2;
[207] 
[208]         if (*p++ != ' ') {
[209]             return NGX_ERROR;
[210]         }
[211] 
[212]         if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
[213]             || *(p + 2) < '0' || *(p + 2) > '9'
[214]             || *(p + 3) < '0' || *(p + 3) > '9')
[215]         {
[216]             return NGX_ERROR;
[217]         }
[218] 
[219]         year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
[220]                + (*(p + 2) - '0') * 10 + (*(p + 3) - '0');
[221]     }
[222] 
[223]     if (hour > 23 || min > 59 || sec > 59) {
[224]         return NGX_ERROR;
[225]     }
[226] 
[227]     if (day == 29 && month == 1) {
[228]         if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
[229]             return NGX_ERROR;
[230]         }
[231] 
[232]     } else if (day > mday[month]) {
[233]         return NGX_ERROR;
[234]     }
[235] 
[236]     /*
[237]      * shift new year to March 1 and start months from 1 (not 0),
[238]      * it is needed for Gauss' formula
[239]      */
[240] 
[241]     if (--month <= 0) {
[242]         month += 12;
[243]         year -= 1;
[244]     }
[245] 
[246]     /* Gauss' formula for Gregorian days since March 1, 1 BC */
[247] 
[248]     time = (uint64_t) (
[249]             /* days in years including leap years since March 1, 1 BC */
[250] 
[251]             365 * year + year / 4 - year / 100 + year / 400
[252] 
[253]             /* days before the month */
[254] 
[255]             + 367 * month / 12 - 30
[256] 
[257]             /* days before the day */
[258] 
[259]             + day - 1
[260] 
[261]             /*
[262]              * 719527 days were between March 1, 1 BC and March 1, 1970,
[263]              * 31 and 28 days were in January and February 1970
[264]              */
[265] 
[266]             - 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;
[267] 
[268] #if (NGX_TIME_T_SIZE <= 4)
[269] 
[270]     if (time > 0x7fffffff) {
[271]         return NGX_ERROR;
[272]     }
[273] 
[274] #endif
[275] 
[276]     return (time_t) time;
[277] }
