[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #include <ngx_config.h>
[9] #include <ngx_core.h>
[10] #include <ngx_event.h>
[11] #include <ngx_mail.h>
[12] #include <ngx_mail_pop3_module.h>
[13] #include <ngx_mail_imap_module.h>
[14] #include <ngx_mail_smtp_module.h>
[15] 
[16] 
[17] ngx_int_t
[18] ngx_mail_pop3_parse_command(ngx_mail_session_t *s)
[19] {
[20]     u_char      ch, *p, *c, c0, c1, c2, c3;
[21]     ngx_str_t  *arg;
[22]     enum {
[23]         sw_start = 0,
[24]         sw_command,
[25]         sw_invalid,
[26]         sw_spaces_before_argument,
[27]         sw_argument,
[28]         sw_almost_done
[29]     } state;
[30] 
[31]     state = s->state;
[32] 
[33]     for (p = s->buffer->pos; p < s->buffer->last; p++) {
[34]         ch = *p;
[35] 
[36]         switch (state) {
[37] 
[38]         /* POP3 command */
[39]         case sw_start:
[40]             s->cmd_start = p;
[41]             state = sw_command;
[42] 
[43]             /* fall through */
[44] 
[45]         case sw_command:
[46]             if (ch == ' ' || ch == CR || ch == LF) {
[47]                 c = s->cmd_start;
[48] 
[49]                 if (p - c == 4) {
[50] 
[51]                     c0 = ngx_toupper(c[0]);
[52]                     c1 = ngx_toupper(c[1]);
[53]                     c2 = ngx_toupper(c[2]);
[54]                     c3 = ngx_toupper(c[3]);
[55] 
[56]                     if (c0 == 'U' && c1 == 'S' && c2 == 'E' && c3 == 'R')
[57]                     {
[58]                         s->command = NGX_POP3_USER;
[59] 
[60]                     } else if (c0 == 'P' && c1 == 'A' && c2 == 'S' && c3 == 'S')
[61]                     {
[62]                         s->command = NGX_POP3_PASS;
[63] 
[64]                     } else if (c0 == 'A' && c1 == 'P' && c2 == 'O' && c3 == 'P')
[65]                     {
[66]                         s->command = NGX_POP3_APOP;
[67] 
[68]                     } else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T')
[69]                     {
[70]                         s->command = NGX_POP3_QUIT;
[71] 
[72]                     } else if (c0 == 'C' && c1 == 'A' && c2 == 'P' && c3 == 'A')
[73]                     {
[74]                         s->command = NGX_POP3_CAPA;
[75] 
[76]                     } else if (c0 == 'A' && c1 == 'U' && c2 == 'T' && c3 == 'H')
[77]                     {
[78]                         s->command = NGX_POP3_AUTH;
[79] 
[80]                     } else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P')
[81]                     {
[82]                         s->command = NGX_POP3_NOOP;
[83] #if (NGX_MAIL_SSL)
[84]                     } else if (c0 == 'S' && c1 == 'T' && c2 == 'L' && c3 == 'S')
[85]                     {
[86]                         s->command = NGX_POP3_STLS;
[87] #endif
[88]                     } else {
[89]                         goto invalid;
[90]                     }
[91] 
[92]                 } else {
[93]                     goto invalid;
[94]                 }
[95] 
[96]                 s->cmd.data = s->cmd_start;
[97]                 s->cmd.len = p - s->cmd_start;
[98] 
[99]                 switch (ch) {
[100]                 case ' ':
[101]                     state = sw_spaces_before_argument;
[102]                     break;
[103]                 case CR:
[104]                     state = sw_almost_done;
[105]                     break;
[106]                 case LF:
[107]                     goto done;
[108]                 }
[109]                 break;
[110]             }
[111] 
[112]             if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
[113]                 goto invalid;
[114]             }
[115] 
[116]             break;
[117] 
[118]         case sw_invalid:
[119]             goto invalid;
[120] 
[121]         case sw_spaces_before_argument:
[122]             switch (ch) {
[123]             case ' ':
[124]                 break;
[125]             case CR:
[126]                 state = sw_almost_done;
[127]                 break;
[128]             case LF:
[129]                 goto done;
[130]             default:
[131]                 if (s->args.nelts <= 2) {
[132]                     state = sw_argument;
[133]                     s->arg_start = p;
[134]                     break;
[135]                 }
[136]                 goto invalid;
[137]             }
[138]             break;
[139] 
[140]         case sw_argument:
[141]             switch (ch) {
[142] 
[143]             case ' ':
[144] 
[145]                 /*
[146]                  * the space should be considered as part of the at username
[147]                  * or password, but not of argument in other commands
[148]                  */
[149] 
[150]                 if (s->command == NGX_POP3_USER
[151]                     || s->command == NGX_POP3_PASS)
[152]                 {
[153]                     break;
[154]                 }
[155] 
[156]                 /* fall through */
[157] 
[158]             case CR:
[159]             case LF:
[160]                 arg = ngx_array_push(&s->args);
[161]                 if (arg == NULL) {
[162]                     return NGX_ERROR;
[163]                 }
[164]                 arg->len = p - s->arg_start;
[165]                 arg->data = s->arg_start;
[166]                 s->arg_start = NULL;
[167] 
[168]                 switch (ch) {
[169]                 case ' ':
[170]                     state = sw_spaces_before_argument;
[171]                     break;
[172]                 case CR:
[173]                     state = sw_almost_done;
[174]                     break;
[175]                 case LF:
[176]                     goto done;
[177]                 }
[178]                 break;
[179] 
[180]             default:
[181]                 break;
[182]             }
[183]             break;
[184] 
[185]         case sw_almost_done:
[186]             switch (ch) {
[187]             case LF:
[188]                 goto done;
[189]             default:
[190]                 goto invalid;
[191]             }
[192]         }
[193]     }
[194] 
[195]     s->buffer->pos = p;
[196]     s->state = state;
[197] 
[198]     return NGX_AGAIN;
[199] 
[200] done:
[201] 
[202]     s->buffer->pos = p + 1;
[203]     s->state = (s->command != NGX_POP3_AUTH) ? sw_start : sw_argument;
[204] 
[205]     return NGX_OK;
[206] 
[207] invalid:
[208] 
[209]     s->state = sw_invalid;
[210] 
[211]     /* skip invalid command till LF */
[212] 
[213]     for ( /* void */ ; p < s->buffer->last; p++) {
[214]         if (*p == LF) {
[215]             s->state = sw_start;
[216]             s->buffer->pos = p + 1;
[217]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[218]         }
[219]     }
[220] 
[221]     s->buffer->pos = p;
[222] 
[223]     return NGX_AGAIN;
[224] }
[225] 
[226] 
[227] ngx_int_t
[228] ngx_mail_imap_parse_command(ngx_mail_session_t *s)
[229] {
[230]     u_char      ch, *p, *c, *dst, *src, *end;
[231]     ngx_str_t  *arg;
[232]     enum {
[233]         sw_start = 0,
[234]         sw_tag,
[235]         sw_invalid,
[236]         sw_spaces_before_command,
[237]         sw_command,
[238]         sw_spaces_before_argument,
[239]         sw_argument,
[240]         sw_backslash,
[241]         sw_literal,
[242]         sw_no_sync_literal_argument,
[243]         sw_start_literal_argument,
[244]         sw_literal_argument,
[245]         sw_end_literal_argument,
[246]         sw_almost_done
[247]     } state;
[248] 
[249]     state = s->state;
[250] 
[251]     for (p = s->buffer->pos; p < s->buffer->last; p++) {
[252]         ch = *p;
[253] 
[254]         switch (state) {
[255] 
[256]         /* IMAP tag */
[257]         case sw_start:
[258]             s->tag_start = p;
[259]             state = sw_tag;
[260] 
[261]             /* fall through */
[262] 
[263]         case sw_tag:
[264]             switch (ch) {
[265]             case ' ':
[266]                 s->tag.len = p - s->tag_start + 1;
[267]                 s->tag.data = s->tag_start;
[268]                 state = sw_spaces_before_command;
[269]                 break;
[270]             case CR:
[271]             case LF:
[272]                 goto invalid;
[273]             default:
[274]                 if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')
[275]                     && (ch < '0' || ch > '9') && ch != '-' && ch != '.'
[276]                     && ch != '_')
[277]                 {
[278]                     goto invalid;
[279]                 }
[280]                 if (p - s->tag_start > 31) {
[281]                     goto invalid;
[282]                 }
[283]                 break;
[284]             }
[285]             break;
[286] 
[287]         case sw_invalid:
[288]             goto invalid;
[289] 
[290]         case sw_spaces_before_command:
[291]             switch (ch) {
[292]             case ' ':
[293]                 break;
[294]             case CR:
[295]             case LF:
[296]                 goto invalid;
[297]             default:
[298]                 s->cmd_start = p;
[299]                 state = sw_command;
[300]                 break;
[301]             }
[302]             break;
[303] 
[304]         case sw_command:
[305]             if (ch == ' ' || ch == CR || ch == LF) {
[306] 
[307]                 c = s->cmd_start;
[308] 
[309]                 switch (p - c) {
[310] 
[311]                 case 4:
[312]                     if ((c[0] == 'N' || c[0] == 'n')
[313]                         && (c[1] == 'O'|| c[1] == 'o')
[314]                         && (c[2] == 'O'|| c[2] == 'o')
[315]                         && (c[3] == 'P'|| c[3] == 'p'))
[316]                     {
[317]                         s->command = NGX_IMAP_NOOP;
[318] 
[319]                     } else {
[320]                         goto invalid;
[321]                     }
[322]                     break;
[323] 
[324]                 case 5:
[325]                     if ((c[0] == 'L'|| c[0] == 'l')
[326]                         && (c[1] == 'O'|| c[1] == 'o')
[327]                         && (c[2] == 'G'|| c[2] == 'g')
[328]                         && (c[3] == 'I'|| c[3] == 'i')
[329]                         && (c[4] == 'N'|| c[4] == 'n'))
[330]                     {
[331]                         s->command = NGX_IMAP_LOGIN;
[332] 
[333]                     } else {
[334]                         goto invalid;
[335]                     }
[336]                     break;
[337] 
[338]                 case 6:
[339]                     if ((c[0] == 'L'|| c[0] == 'l')
[340]                         && (c[1] == 'O'|| c[1] == 'o')
[341]                         && (c[2] == 'G'|| c[2] == 'g')
[342]                         && (c[3] == 'O'|| c[3] == 'o')
[343]                         && (c[4] == 'U'|| c[4] == 'u')
[344]                         && (c[5] == 'T'|| c[5] == 't'))
[345]                     {
[346]                         s->command = NGX_IMAP_LOGOUT;
[347] 
[348]                     } else {
[349]                         goto invalid;
[350]                     }
[351]                     break;
[352] 
[353] #if (NGX_MAIL_SSL)
[354]                 case 8:
[355]                     if ((c[0] == 'S'|| c[0] == 's')
[356]                         && (c[1] == 'T'|| c[1] == 't')
[357]                         && (c[2] == 'A'|| c[2] == 'a')
[358]                         && (c[3] == 'R'|| c[3] == 'r')
[359]                         && (c[4] == 'T'|| c[4] == 't')
[360]                         && (c[5] == 'T'|| c[5] == 't')
[361]                         && (c[6] == 'L'|| c[6] == 'l')
[362]                         && (c[7] == 'S'|| c[7] == 's'))
[363]                     {
[364]                         s->command = NGX_IMAP_STARTTLS;
[365] 
[366]                     } else {
[367]                         goto invalid;
[368]                     }
[369]                     break;
[370] #endif
[371] 
[372]                 case 10:
[373]                     if ((c[0] == 'C'|| c[0] == 'c')
[374]                         && (c[1] == 'A'|| c[1] == 'a')
[375]                         && (c[2] == 'P'|| c[2] == 'p')
[376]                         && (c[3] == 'A'|| c[3] == 'a')
[377]                         && (c[4] == 'B'|| c[4] == 'b')
[378]                         && (c[5] == 'I'|| c[5] == 'i')
[379]                         && (c[6] == 'L'|| c[6] == 'l')
[380]                         && (c[7] == 'I'|| c[7] == 'i')
[381]                         && (c[8] == 'T'|| c[8] == 't')
[382]                         && (c[9] == 'Y'|| c[9] == 'y'))
[383]                     {
[384]                         s->command = NGX_IMAP_CAPABILITY;
[385] 
[386]                     } else {
[387]                         goto invalid;
[388]                     }
[389]                     break;
[390] 
[391]                 case 12:
[392]                     if ((c[0] == 'A'|| c[0] == 'a')
[393]                         && (c[1] == 'U'|| c[1] == 'u')
[394]                         && (c[2] == 'T'|| c[2] == 't')
[395]                         && (c[3] == 'H'|| c[3] == 'h')
[396]                         && (c[4] == 'E'|| c[4] == 'e')
[397]                         && (c[5] == 'N'|| c[5] == 'n')
[398]                         && (c[6] == 'T'|| c[6] == 't')
[399]                         && (c[7] == 'I'|| c[7] == 'i')
[400]                         && (c[8] == 'C'|| c[8] == 'c')
[401]                         && (c[9] == 'A'|| c[9] == 'a')
[402]                         && (c[10] == 'T'|| c[10] == 't')
[403]                         && (c[11] == 'E'|| c[11] == 'e'))
[404]                     {
[405]                         s->command = NGX_IMAP_AUTHENTICATE;
[406] 
[407]                     } else {
[408]                         goto invalid;
[409]                     }
[410]                     break;
[411] 
[412]                 default:
[413]                     goto invalid;
[414]                 }
[415] 
[416]                 s->cmd.data = s->cmd_start;
[417]                 s->cmd.len = p - s->cmd_start;
[418] 
[419]                 switch (ch) {
[420]                 case ' ':
[421]                     state = sw_spaces_before_argument;
[422]                     break;
[423]                 case CR:
[424]                     state = sw_almost_done;
[425]                     break;
[426]                 case LF:
[427]                     goto done;
[428]                 }
[429]                 break;
[430]             }
[431] 
[432]             if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
[433]                 goto invalid;
[434]             }
[435] 
[436]             break;
[437] 
[438]         case sw_spaces_before_argument:
[439]             switch (ch) {
[440]             case ' ':
[441]                 break;
[442]             case CR:
[443]                 state = sw_almost_done;
[444]                 break;
[445]             case LF:
[446]                 goto done;
[447]             case '"':
[448]                 if (s->args.nelts <= 2) {
[449]                     s->quoted = 1;
[450]                     s->arg_start = p + 1;
[451]                     state = sw_argument;
[452]                     break;
[453]                 }
[454]                 goto invalid;
[455]             case '{':
[456]                 if (s->args.nelts <= 2) {
[457]                     state = sw_literal;
[458]                     break;
[459]                 }
[460]                 goto invalid;
[461]             default:
[462]                 if (s->args.nelts <= 2) {
[463]                     s->arg_start = p;
[464]                     state = sw_argument;
[465]                     break;
[466]                 }
[467]                 goto invalid;
[468]             }
[469]             break;
[470] 
[471]         case sw_argument:
[472]             if (ch == ' ' && s->quoted) {
[473]                 break;
[474]             }
[475] 
[476]             switch (ch) {
[477]             case '"':
[478]                 if (!s->quoted) {
[479]                     break;
[480]                 }
[481]                 s->quoted = 0;
[482]                 /* fall through */
[483]             case ' ':
[484]             case CR:
[485]             case LF:
[486]                 arg = ngx_array_push(&s->args);
[487]                 if (arg == NULL) {
[488]                     return NGX_ERROR;
[489]                 }
[490]                 arg->len = p - s->arg_start;
[491]                 arg->data = s->arg_start;
[492] 
[493]                 if (s->backslash) {
[494]                     dst = s->arg_start;
[495]                     end = p;
[496] 
[497]                     for (src = dst; src < end; dst++) {
[498]                         *dst = *src;
[499]                         if (*src++ == '\\') {
[500]                             *dst = *src++;
[501]                         }
[502]                     }
[503] 
[504]                     arg->len = dst - s->arg_start;
[505]                     s->backslash = 0;
[506]                 }
[507] 
[508]                 s->arg_start = NULL;
[509] 
[510]                 switch (ch) {
[511]                 case '"':
[512]                 case ' ':
[513]                     state = sw_spaces_before_argument;
[514]                     break;
[515]                 case CR:
[516]                     state = sw_almost_done;
[517]                     break;
[518]                 case LF:
[519]                     goto done;
[520]                 }
[521]                 break;
[522]             case '\\':
[523]                 if (s->quoted) {
[524]                     s->backslash = 1;
[525]                     state = sw_backslash;
[526]                 }
[527]                 break;
[528]             }
[529]             break;
[530] 
[531]         case sw_backslash:
[532]             switch (ch) {
[533]             case CR:
[534]             case LF:
[535]                 goto invalid;
[536]             default:
[537]                 state = sw_argument;
[538]             }
[539]             break;
[540] 
[541]         case sw_literal:
[542]             if (ch >= '0' && ch <= '9') {
[543]                 s->literal_len = s->literal_len * 10 + (ch - '0');
[544]                 break;
[545]             }
[546]             if (ch == '}') {
[547]                 state = sw_start_literal_argument;
[548]                 break;
[549]             }
[550]             if (ch == '+') {
[551]                 state = sw_no_sync_literal_argument;
[552]                 break;
[553]             }
[554]             goto invalid;
[555] 
[556]         case sw_no_sync_literal_argument:
[557]             if (ch == '}') {
[558]                 s->no_sync_literal = 1;
[559]                 state = sw_start_literal_argument;
[560]                 break;
[561]             }
[562]             goto invalid;
[563] 
[564]         case sw_start_literal_argument:
[565]             switch (ch) {
[566]             case CR:
[567]                 break;
[568]             case LF:
[569]                 s->buffer->pos = p + 1;
[570]                 s->arg_start = p + 1;
[571]                 if (s->no_sync_literal == 0) {
[572]                     s->state = sw_literal_argument;
[573]                     return NGX_IMAP_NEXT;
[574]                 }
[575]                 state = sw_literal_argument;
[576]                 s->no_sync_literal = 0;
[577]                 break;
[578]             default:
[579]                 goto invalid;
[580]             }
[581]             break;
[582] 
[583]         case sw_literal_argument:
[584]             if (s->literal_len && --s->literal_len) {
[585]                 break;
[586]             }
[587] 
[588]             arg = ngx_array_push(&s->args);
[589]             if (arg == NULL) {
[590]                 return NGX_ERROR;
[591]             }
[592]             arg->len = p + 1 - s->arg_start;
[593]             arg->data = s->arg_start;
[594]             s->arg_start = NULL;
[595]             state = sw_end_literal_argument;
[596] 
[597]             break;
[598] 
[599]         case sw_end_literal_argument:
[600]             switch (ch) {
[601]             case '{':
[602]                 if (s->args.nelts <= 2) {
[603]                     state = sw_literal;
[604]                     break;
[605]                 }
[606]                 goto invalid;
[607]             case CR:
[608]                 state = sw_almost_done;
[609]                 break;
[610]             case LF:
[611]                 goto done;
[612]             default:
[613]                 state = sw_spaces_before_argument;
[614]                 break;
[615]             }
[616]             break;
[617] 
[618]         case sw_almost_done:
[619]             switch (ch) {
[620]             case LF:
[621]                 goto done;
[622]             default:
[623]                 goto invalid;
[624]             }
[625]         }
[626]     }
[627] 
[628]     s->buffer->pos = p;
[629]     s->state = state;
[630] 
[631]     return NGX_AGAIN;
[632] 
[633] done:
[634] 
[635]     s->buffer->pos = p + 1;
[636]     s->state = (s->command != NGX_IMAP_AUTHENTICATE) ? sw_start : sw_argument;
[637] 
[638]     return NGX_OK;
[639] 
[640] invalid:
[641] 
[642]     s->state = sw_invalid;
[643]     s->quoted = 0;
[644]     s->backslash = 0;
[645]     s->no_sync_literal = 0;
[646]     s->literal_len = 0;
[647] 
[648]     /* skip invalid command till LF */
[649] 
[650]     for ( /* void */ ; p < s->buffer->last; p++) {
[651]         if (*p == LF) {
[652]             s->state = sw_start;
[653]             s->buffer->pos = p + 1;
[654] 
[655]             /* detect non-synchronizing literals */
[656] 
[657]             if ((size_t) (p - s->buffer->start) > sizeof("{1+}") - 1) {
[658]                 p--;
[659] 
[660]                 if (*p == CR) {
[661]                     p--;
[662]                 }
[663] 
[664]                 if (*p == '}' && *(p - 1) == '+') {
[665]                     s->quit = 1;
[666]                 }
[667]             }
[668] 
[669]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[670]         }
[671]     }
[672] 
[673]     s->buffer->pos = p;
[674] 
[675]     return NGX_AGAIN;
[676] }
[677] 
[678] 
[679] ngx_int_t
[680] ngx_mail_smtp_parse_command(ngx_mail_session_t *s)
[681] {
[682]     u_char      ch, *p, *c, c0, c1, c2, c3;
[683]     ngx_str_t  *arg;
[684]     enum {
[685]         sw_start = 0,
[686]         sw_command,
[687]         sw_invalid,
[688]         sw_spaces_before_argument,
[689]         sw_argument,
[690]         sw_almost_done
[691]     } state;
[692] 
[693]     state = s->state;
[694] 
[695]     for (p = s->buffer->pos; p < s->buffer->last; p++) {
[696]         ch = *p;
[697] 
[698]         switch (state) {
[699] 
[700]         /* SMTP command */
[701]         case sw_start:
[702]             s->cmd_start = p;
[703]             state = sw_command;
[704] 
[705]             /* fall through */
[706] 
[707]         case sw_command:
[708]             if (ch == ' ' || ch == CR || ch == LF) {
[709]                 c = s->cmd_start;
[710] 
[711]                 if (p - c == 4) {
[712] 
[713]                     c0 = ngx_toupper(c[0]);
[714]                     c1 = ngx_toupper(c[1]);
[715]                     c2 = ngx_toupper(c[2]);
[716]                     c3 = ngx_toupper(c[3]);
[717] 
[718]                     if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'O')
[719]                     {
[720]                         s->command = NGX_SMTP_HELO;
[721] 
[722]                     } else if (c0 == 'E' && c1 == 'H' && c2 == 'L' && c3 == 'O')
[723]                     {
[724]                         s->command = NGX_SMTP_EHLO;
[725] 
[726]                     } else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T')
[727]                     {
[728]                         s->command = NGX_SMTP_QUIT;
[729] 
[730]                     } else if (c0 == 'A' && c1 == 'U' && c2 == 'T' && c3 == 'H')
[731]                     {
[732]                         s->command = NGX_SMTP_AUTH;
[733] 
[734]                     } else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P')
[735]                     {
[736]                         s->command = NGX_SMTP_NOOP;
[737] 
[738]                     } else if (c0 == 'M' && c1 == 'A' && c2 == 'I' && c3 == 'L')
[739]                     {
[740]                         s->command = NGX_SMTP_MAIL;
[741] 
[742]                     } else if (c0 == 'R' && c1 == 'S' && c2 == 'E' && c3 == 'T')
[743]                     {
[744]                         s->command = NGX_SMTP_RSET;
[745] 
[746]                     } else if (c0 == 'R' && c1 == 'C' && c2 == 'P' && c3 == 'T')
[747]                     {
[748]                         s->command = NGX_SMTP_RCPT;
[749] 
[750]                     } else if (c0 == 'V' && c1 == 'R' && c2 == 'F' && c3 == 'Y')
[751]                     {
[752]                         s->command = NGX_SMTP_VRFY;
[753] 
[754]                     } else if (c0 == 'E' && c1 == 'X' && c2 == 'P' && c3 == 'N')
[755]                     {
[756]                         s->command = NGX_SMTP_EXPN;
[757] 
[758]                     } else if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'P')
[759]                     {
[760]                         s->command = NGX_SMTP_HELP;
[761] 
[762]                     } else {
[763]                         goto invalid;
[764]                     }
[765] #if (NGX_MAIL_SSL)
[766]                 } else if (p - c == 8) {
[767] 
[768]                     if ((c[0] == 'S'|| c[0] == 's')
[769]                         && (c[1] == 'T'|| c[1] == 't')
[770]                         && (c[2] == 'A'|| c[2] == 'a')
[771]                         && (c[3] == 'R'|| c[3] == 'r')
[772]                         && (c[4] == 'T'|| c[4] == 't')
[773]                         && (c[5] == 'T'|| c[5] == 't')
[774]                         && (c[6] == 'L'|| c[6] == 'l')
[775]                         && (c[7] == 'S'|| c[7] == 's'))
[776]                     {
[777]                         s->command = NGX_SMTP_STARTTLS;
[778] 
[779]                     } else {
[780]                         goto invalid;
[781]                     }
[782] #endif
[783]                 } else {
[784]                     goto invalid;
[785]                 }
[786] 
[787]                 s->cmd.data = s->cmd_start;
[788]                 s->cmd.len = p - s->cmd_start;
[789] 
[790]                 switch (ch) {
[791]                 case ' ':
[792]                     state = sw_spaces_before_argument;
[793]                     break;
[794]                 case CR:
[795]                     state = sw_almost_done;
[796]                     break;
[797]                 case LF:
[798]                     goto done;
[799]                 }
[800]                 break;
[801]             }
[802] 
[803]             if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
[804]                 goto invalid;
[805]             }
[806] 
[807]             break;
[808] 
[809]         case sw_invalid:
[810]             goto invalid;
[811] 
[812]         case sw_spaces_before_argument:
[813]             switch (ch) {
[814]             case ' ':
[815]                 break;
[816]             case CR:
[817]                 state = sw_almost_done;
[818]                 break;
[819]             case LF:
[820]                 goto done;
[821]             default:
[822]                 if (s->args.nelts <= 10) {
[823]                     state = sw_argument;
[824]                     s->arg_start = p;
[825]                     break;
[826]                 }
[827]                 goto invalid;
[828]             }
[829]             break;
[830] 
[831]         case sw_argument:
[832]             switch (ch) {
[833]             case ' ':
[834]             case CR:
[835]             case LF:
[836]                 arg = ngx_array_push(&s->args);
[837]                 if (arg == NULL) {
[838]                     return NGX_ERROR;
[839]                 }
[840]                 arg->len = p - s->arg_start;
[841]                 arg->data = s->arg_start;
[842]                 s->arg_start = NULL;
[843] 
[844]                 switch (ch) {
[845]                 case ' ':
[846]                     state = sw_spaces_before_argument;
[847]                     break;
[848]                 case CR:
[849]                     state = sw_almost_done;
[850]                     break;
[851]                 case LF:
[852]                     goto done;
[853]                 }
[854]                 break;
[855] 
[856]             default:
[857]                 break;
[858]             }
[859]             break;
[860] 
[861]         case sw_almost_done:
[862]             switch (ch) {
[863]             case LF:
[864]                 goto done;
[865]             default:
[866]                 goto invalid;
[867]             }
[868]         }
[869]     }
[870] 
[871]     s->buffer->pos = p;
[872]     s->state = state;
[873] 
[874]     return NGX_AGAIN;
[875] 
[876] done:
[877] 
[878]     s->buffer->pos = p + 1;
[879]     s->state = (s->command != NGX_SMTP_AUTH) ? sw_start : sw_argument;
[880] 
[881]     return NGX_OK;
[882] 
[883] invalid:
[884] 
[885]     s->state = sw_invalid;
[886] 
[887]     /* skip invalid command till LF */
[888] 
[889]     for ( /* void */ ; p < s->buffer->last; p++) {
[890]         if (*p == LF) {
[891]             s->state = sw_start;
[892]             s->buffer->pos = p + 1;
[893]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[894]         }
[895]     }
[896] 
[897]     s->buffer->pos = p;
[898] 
[899]     return NGX_AGAIN;
[900] }
[901] 
[902] 
[903] ngx_int_t
[904] ngx_mail_auth_parse(ngx_mail_session_t *s, ngx_connection_t *c)
[905] {
[906]     ngx_str_t                 *arg;
[907] 
[908] #if (NGX_MAIL_SSL)
[909]     if (ngx_mail_starttls_only(s, c)) {
[910]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[911]     }
[912] #endif
[913] 
[914]     if (s->args.nelts == 0) {
[915]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[916]     }
[917] 
[918]     arg = s->args.elts;
[919] 
[920]     if (arg[0].len == 5) {
[921] 
[922]         if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5) == 0) {
[923] 
[924]             if (s->args.nelts == 1) {
[925]                 return NGX_MAIL_AUTH_LOGIN;
[926]             }
[927] 
[928]             if (s->args.nelts == 2) {
[929]                 return NGX_MAIL_AUTH_LOGIN_USERNAME;
[930]             }
[931] 
[932]             return NGX_MAIL_PARSE_INVALID_COMMAND;
[933]         }
[934] 
[935]         if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN", 5) == 0) {
[936] 
[937]             if (s->args.nelts == 1) {
[938]                 return NGX_MAIL_AUTH_PLAIN;
[939]             }
[940] 
[941]             if (s->args.nelts == 2) {
[942]                 return ngx_mail_auth_plain(s, c, 1);
[943]             }
[944]         }
[945] 
[946]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[947]     }
[948] 
[949]     if (arg[0].len == 8) {
[950] 
[951]         if (ngx_strncasecmp(arg[0].data, (u_char *) "CRAM-MD5", 8) == 0) {
[952] 
[953]             if (s->args.nelts != 1) {
[954]                 return NGX_MAIL_PARSE_INVALID_COMMAND;
[955]             }
[956] 
[957]             return NGX_MAIL_AUTH_CRAM_MD5;
[958]         }
[959] 
[960]         if (ngx_strncasecmp(arg[0].data, (u_char *) "EXTERNAL", 8) == 0) {
[961] 
[962]             if (s->args.nelts == 1) {
[963]                 return NGX_MAIL_AUTH_EXTERNAL;
[964]             }
[965] 
[966]             if (s->args.nelts == 2) {
[967]                 return ngx_mail_auth_external(s, c, 1);
[968]             }
[969]         }
[970] 
[971]         return NGX_MAIL_PARSE_INVALID_COMMAND;
[972]     }
[973] 
[974]     return NGX_MAIL_PARSE_INVALID_COMMAND;
[975] }
