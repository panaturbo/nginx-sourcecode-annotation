[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #define PERL_NO_GET_CONTEXT
[9] 
[10] #include <ngx_config.h>
[11] #include <ngx_core.h>
[12] #include <ngx_http.h>
[13] #include <ngx_http_perl_module.h>
[14] 
[15] #include "XSUB.h"
[16] 
[17] 
[18] #define ngx_http_perl_set_request(r, ctx)                                     \
[19]                                                                               \
[20]     ctx = INT2PTR(ngx_http_perl_ctx_t *, SvIV((SV *) SvRV(ST(0))));           \
[21]     r = ctx->request
[22] 
[23] 
[24] #define ngx_http_perl_set_targ(p, len)                                        \
[25]                                                                               \
[26]     SvUPGRADE(TARG, SVt_PV);                                                  \
[27]     SvPOK_on(TARG);                                                           \
[28]     sv_setpvn(TARG, (char *) p, len)
[29] 
[30] 
[31] static ngx_int_t
[32] ngx_http_perl_sv2str(pTHX_ ngx_http_request_t *r, ngx_str_t *s, SV *sv)
[33] {
[34]     u_char  *p;
[35]     STRLEN   len;
[36] 
[37]     if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
[38]         sv = SvRV(sv);
[39]     }
[40] 
[41]     p = (u_char *) SvPV(sv, len);
[42] 
[43]     s->len = len;
[44] 
[45]     if (SvREADONLY(sv) && SvPOK(sv)) {
[46]         s->data = p;
[47] 
[48]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[49]                        "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);
[50] 
[51]         return NGX_OK;
[52]     }
[53] 
[54]     s->data = ngx_pnalloc(r->pool, len);
[55]     if (s->data == NULL) {
[56]         return NGX_ERROR;
[57]     }
[58] 
[59]     ngx_memcpy(s->data, p, len);
[60] 
[61]     ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[62]                    "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);
[63] 
[64]     return NGX_OK;
[65] }
[66] 
[67] 
[68] static ngx_int_t
[69] ngx_http_perl_output(ngx_http_request_t *r, ngx_http_perl_ctx_t *ctx,
[70]     ngx_buf_t *b)
[71] {
[72]     ngx_chain_t   out;
[73] #if (NGX_HTTP_SSI)
[74]     ngx_chain_t  *cl;
[75] 
[76]     if (ctx->ssi) {
[77]         cl = ngx_alloc_chain_link(r->pool);
[78]         if (cl == NULL) {
[79]             return NGX_ERROR;
[80]         }
[81] 
[82]         cl->buf = b;
[83]         cl->next = NULL;
[84]         *ctx->ssi->last_out = cl;
[85]         ctx->ssi->last_out = &cl->next;
[86] 
[87]         return NGX_OK;
[88]     }
[89] #endif
[90] 
[91]     out.buf = b;
[92]     out.next = NULL;
[93] 
[94]     return ngx_http_output_filter(r, &out);
[95] }
[96] 
[97] 
[98] MODULE = nginx    PACKAGE = nginx
[99] 
[100] 
[101] PROTOTYPES: DISABLE
[102] 
[103] 
[104] void
[105] status(r, code)
[106]     CODE:
[107] 
[108]     ngx_http_request_t   *r;
[109]     ngx_http_perl_ctx_t  *ctx;
[110] 
[111]     ngx_http_perl_set_request(r, ctx);
[112] 
[113]     if (ctx->variable) {
[114]         croak("status(): cannot be used in variable handler");
[115]     }
[116] 
[117]     r->headers_out.status = SvIV(ST(1));
[118] 
[119]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[120]                    "perl status: %d", r->headers_out.status);
[121] 
[122]     XSRETURN_UNDEF;
[123] 
[124] 
[125] void
[126] send_http_header(r, ...)
[127]     CODE:
[128] 
[129]     ngx_http_request_t   *r;
[130]     ngx_http_perl_ctx_t  *ctx;
[131]     SV                   *sv;
[132]     ngx_int_t             rc;
[133] 
[134]     ngx_http_perl_set_request(r, ctx);
[135] 
[136]     if (ctx->error) {
[137]         croak("send_http_header(): called after error");
[138]     }
[139] 
[140]     if (ctx->variable) {
[141]         croak("send_http_header(): cannot be used in variable handler");
[142]     }
[143] 
[144]     if (ctx->header_sent) {
[145]         croak("send_http_header(): header already sent");
[146]     }
[147] 
[148]     if (ctx->redirect_uri.len) {
[149]         croak("send_http_header(): cannot be used with internal_redirect()");
[150]     }
[151] 
[152]     if (r->headers_out.status == 0) {
[153]         r->headers_out.status = NGX_HTTP_OK;
[154]     }
[155] 
[156]     if (items != 1) {
[157]         sv = ST(1);
[158] 
[159]         if (ngx_http_perl_sv2str(aTHX_ r, &r->headers_out.content_type, sv)
[160]             != NGX_OK)
[161]         {
[162]             ctx->error = 1;
[163]             croak("ngx_http_perl_sv2str() failed");
[164]         }
[165] 
[166]         r->headers_out.content_type_len = r->headers_out.content_type.len;
[167] 
[168]     } else {
[169]         if (ngx_http_set_content_type(r) != NGX_OK) {
[170]             ctx->error = 1;
[171]             croak("ngx_http_set_content_type() failed");
[172]         }
[173]     }
[174] 
[175]     ctx->header_sent = 1;
[176] 
[177]     r->disable_not_modified = 1;
[178] 
[179]     rc = ngx_http_send_header(r);
[180] 
[181]     if (rc == NGX_ERROR || rc > NGX_OK) {
[182]         ctx->error = 1;
[183]         ctx->status = rc;
[184]         croak("ngx_http_send_header() failed");
[185]     }
[186] 
[187] 
[188] void
[189] header_only(r)
[190]     CODE:
[191] 
[192]     dXSTARG;
[193]     ngx_http_request_t   *r;
[194]     ngx_http_perl_ctx_t  *ctx;
[195] 
[196]     ngx_http_perl_set_request(r, ctx);
[197] 
[198]     sv_upgrade(TARG, SVt_IV);
[199]     sv_setiv(TARG, r->header_only);
[200] 
[201]     ST(0) = TARG;
[202] 
[203] 
[204] void
[205] uri(r)
[206]     CODE:
[207] 
[208]     dXSTARG;
[209]     ngx_http_request_t   *r;
[210]     ngx_http_perl_ctx_t  *ctx;
[211] 
[212]     ngx_http_perl_set_request(r, ctx);
[213]     ngx_http_perl_set_targ(r->uri.data, r->uri.len);
[214] 
[215]     ST(0) = TARG;
[216] 
[217] 
[218] void
[219] args(r)
[220]     CODE:
[221] 
[222]     dXSTARG;
[223]     ngx_http_request_t   *r;
[224]     ngx_http_perl_ctx_t  *ctx;
[225] 
[226]     ngx_http_perl_set_request(r, ctx);
[227]     ngx_http_perl_set_targ(r->args.data, r->args.len);
[228] 
[229]     ST(0) = TARG;
[230] 
[231] 
[232] void
[233] request_method(r)
[234]     CODE:
[235] 
[236]     dXSTARG;
[237]     ngx_http_request_t   *r;
[238]     ngx_http_perl_ctx_t  *ctx;
[239] 
[240]     ngx_http_perl_set_request(r, ctx);
[241]     ngx_http_perl_set_targ(r->method_name.data, r->method_name.len);
[242] 
[243]     ST(0) = TARG;
[244] 
[245] 
[246] void
[247] remote_addr(r)
[248]     CODE:
[249] 
[250]     dXSTARG;
[251]     ngx_http_request_t   *r;
[252]     ngx_http_perl_ctx_t  *ctx;
[253] 
[254]     ngx_http_perl_set_request(r, ctx);
[255]     ngx_http_perl_set_targ(r->connection->addr_text.data,
[256]                            r->connection->addr_text.len);
[257] 
[258]     ST(0) = TARG;
[259] 
[260] 
[261] void
[262] header_in(r, key)
[263]     CODE:
[264] 
[265]     dXSTARG;
[266]     ngx_http_request_t         *r;
[267]     ngx_http_perl_ctx_t        *ctx;
[268]     SV                         *key;
[269]     u_char                     *p, *lowcase_key, *value, sep;
[270]     STRLEN                      len;
[271]     ssize_t                     size;
[272]     ngx_uint_t                  i, hash;
[273]     ngx_list_part_t            *part;
[274]     ngx_table_elt_t            *h, *header, **ph;
[275]     ngx_http_header_t          *hh;
[276]     ngx_http_core_main_conf_t  *cmcf;
[277] 
[278]     ngx_http_perl_set_request(r, ctx);
[279] 
[280]     key = ST(1);
[281] 
[282]     if (SvROK(key) && SvTYPE(SvRV(key)) == SVt_PV) {
[283]         key = SvRV(key);
[284]     }
[285] 
[286]     p = (u_char *) SvPV(key, len);
[287] 
[288]     /* look up hashed headers */
[289] 
[290]     lowcase_key = ngx_pnalloc(r->pool, len);
[291]     if (lowcase_key == NULL) {
[292]         ctx->error = 1;
[293]         croak("ngx_pnalloc() failed");
[294]     }
[295] 
[296]     hash = ngx_hash_strlow(lowcase_key, p, len);
[297] 
[298]     cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
[299] 
[300]     hh = ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, len);
[301] 
[302]     if (hh) {
[303] 
[304]         if (hh->offset == offsetof(ngx_http_headers_in_t, cookie)) {
[305]             sep = ';';
[306] 
[307]         } else {
[308]             sep = ',';
[309]         }
[310] 
[311]         ph = (ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset);
[312] 
[313]         goto found;
[314]     }
[315] 
[316]     /* iterate over all headers */
[317] 
[318]     sep = ',';
[319]     ph = &header;
[320] 
[321]     part = &r->headers_in.headers.part;
[322]     h = part->elts;
[323] 
[324]     for (i = 0; /* void */ ; i++) {
[325] 
[326]         if (i >= part->nelts) {
[327]             if (part->next == NULL) {
[328]                 break;
[329]             }
[330] 
[331]             part = part->next;
[332]             h = part->elts;
[333]             i = 0;
[334]         }
[335] 
[336]         if (len != h[i].key.len
[337]             || ngx_strcasecmp(p, h[i].key.data) != 0)
[338]         {
[339]             continue;
[340]         }
[341] 
[342]         *ph = &h[i];
[343]         ph = &h[i].next;
[344]     }
[345] 
[346]     *ph = NULL;
[347]     ph = &header;
[348] 
[349]     found:
[350] 
[351]     if (*ph == NULL) {
[352]         XSRETURN_UNDEF;
[353]     }
[354] 
[355]     if ((*ph)->next == NULL) {
[356]         ngx_http_perl_set_targ((*ph)->value.data, (*ph)->value.len);
[357]         goto done;
[358]     }
[359] 
[360]     size = - (ssize_t) (sizeof("; ") - 1);
[361] 
[362]     for (h = *ph; h; h = h->next) {
[363]         size += h->value.len + sizeof("; ") - 1;
[364]     }
[365] 
[366]     value = ngx_pnalloc(r->pool, size);
[367]     if (value == NULL) {
[368]         ctx->error = 1;
[369]         croak("ngx_pnalloc() failed");
[370]     }
[371] 
[372]     p = value;
[373] 
[374]     for (h = *ph; h; h = h->next) {
[375]         p = ngx_copy(p, h->value.data, h->value.len);
[376] 
[377]         if (h->next == NULL) {
[378]             break;
[379]         }
[380] 
[381]         *p++ = sep; *p++ = ' ';
[382]     }
[383] 
[384]     ngx_http_perl_set_targ(value, size);
[385] 
[386]     done:
[387] 
[388]     ST(0) = TARG;
[389] 
[390] 
[391] void
[392] has_request_body(r, next)
[393]     CODE:
[394] 
[395]     dXSTARG;
[396]     ngx_http_request_t   *r;
[397]     ngx_http_perl_ctx_t  *ctx;
[398]     ngx_int_t             rc;
[399] 
[400]     ngx_http_perl_set_request(r, ctx);
[401] 
[402]     if (ctx->variable) {
[403]         croak("has_request_body(): cannot be used in variable handler");
[404]     }
[405] 
[406]     if (ctx->next) {
[407]         croak("has_request_body(): another handler active");
[408]     }
[409] 
[410]     if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
[411]         XSRETURN_UNDEF;
[412]     }
[413] 
[414]     ctx->next = SvRV(ST(1));
[415] 
[416]     r->request_body_in_single_buf = 1;
[417]     r->request_body_in_persistent_file = 1;
[418]     r->request_body_in_clean_file = 1;
[419] 
[420]     if (r->request_body_in_file_only) {
[421]         r->request_body_file_log_level = 0;
[422]     }
[423] 
[424]     rc = ngx_http_read_client_request_body(r, ngx_http_perl_handle_request);
[425] 
[426]     if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
[427]         ctx->error = 1;
[428]         ctx->status = rc;
[429]         ctx->next = NULL;
[430]         croak("ngx_http_read_client_request_body() failed");
[431]     }
[432] 
[433]     sv_upgrade(TARG, SVt_IV);
[434]     sv_setiv(TARG, 1);
[435] 
[436]     ST(0) = TARG;
[437] 
[438] 
[439] void
[440] request_body(r)
[441]     CODE:
[442] 
[443]     dXSTARG;
[444]     ngx_http_request_t   *r;
[445]     ngx_http_perl_ctx_t  *ctx;
[446]     u_char               *p, *data;
[447]     size_t                len;
[448]     ngx_buf_t            *buf;
[449]     ngx_chain_t          *cl;
[450] 
[451]     ngx_http_perl_set_request(r, ctx);
[452] 
[453]     if (r->request_body == NULL
[454]         || r->request_body->temp_file
[455]         || r->request_body->bufs == NULL)
[456]     {
[457]         XSRETURN_UNDEF;
[458]     }
[459] 
[460]     cl = r->request_body->bufs;
[461]     buf = cl->buf;
[462] 
[463]     if (cl->next == NULL) {
[464]         len = buf->last - buf->pos;
[465]         data = buf->pos;
[466]         goto done;
[467]     }
[468] 
[469]     len = buf->last - buf->pos;
[470]     cl = cl->next;
[471] 
[472]     for ( /* void */ ; cl; cl = cl->next) {
[473]         buf = cl->buf;
[474]         len += buf->last - buf->pos;
[475]     }
[476] 
[477]     p = ngx_pnalloc(r->pool, len);
[478]     if (p == NULL) {
[479]         ctx->error = 1;
[480]         croak("ngx_pnalloc() failed");
[481]     }
[482] 
[483]     data = p;
[484]     cl = r->request_body->bufs;
[485] 
[486]     for ( /* void */ ; cl; cl = cl->next) {
[487]         buf = cl->buf;
[488]         p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
[489]     }
[490] 
[491]     done:
[492] 
[493]     if (len == 0) {
[494]         XSRETURN_UNDEF;
[495]     }
[496] 
[497]     ngx_http_perl_set_targ(data, len);
[498] 
[499]     ST(0) = TARG;
[500] 
[501] 
[502] void
[503] request_body_file(r)
[504]     CODE:
[505] 
[506]     dXSTARG;
[507]     ngx_http_request_t   *r;
[508]     ngx_http_perl_ctx_t  *ctx;
[509] 
[510]     ngx_http_perl_set_request(r, ctx);
[511] 
[512]     if (r->request_body == NULL || r->request_body->temp_file == NULL) {
[513]         XSRETURN_UNDEF;
[514]     }
[515] 
[516]     ngx_http_perl_set_targ(r->request_body->temp_file->file.name.data,
[517]                            r->request_body->temp_file->file.name.len);
[518] 
[519]     ST(0) = TARG;
[520] 
[521] 
[522] void
[523] discard_request_body(r)
[524]     CODE:
[525] 
[526]     ngx_http_request_t   *r;
[527]     ngx_http_perl_ctx_t  *ctx;
[528]     ngx_int_t             rc;
[529] 
[530]     ngx_http_perl_set_request(r, ctx);
[531] 
[532]     if (ctx->variable) {
[533]         croak("discard_request_body(): cannot be used in variable handler");
[534]     }
[535] 
[536]     rc = ngx_http_discard_request_body(r);
[537] 
[538]     if (rc != NGX_OK) {
[539]         ctx->error = 1;
[540]         ctx->status = rc;
[541]         croak("ngx_http_discard_request_body() failed");
[542]     }
[543] 
[544] 
[545] void
[546] header_out(r, key, value)
[547]     CODE:
[548] 
[549]     ngx_http_request_t   *r;
[550]     ngx_http_perl_ctx_t  *ctx;
[551]     SV                   *key;
[552]     SV                   *value;
[553]     ngx_table_elt_t      *header;
[554] 
[555]     ngx_http_perl_set_request(r, ctx);
[556] 
[557]     if (ctx->error) {
[558]         croak("header_out(): called after error");
[559]     }
[560] 
[561]     if (ctx->variable) {
[562]         croak("header_out(): cannot be used in variable handler");
[563]     }
[564] 
[565]     key = ST(1);
[566]     value = ST(2);
[567] 
[568]     header = ngx_list_push(&r->headers_out.headers);
[569]     if (header == NULL) {
[570]         ctx->error = 1;
[571]         croak("ngx_list_push() failed");
[572]     }
[573] 
[574]     header->hash = 1;
[575]     header->next = NULL;
[576] 
[577]     if (ngx_http_perl_sv2str(aTHX_ r, &header->key, key) != NGX_OK) {
[578]         header->hash = 0;
[579]         ctx->error = 1;
[580]         croak("ngx_http_perl_sv2str() failed");
[581]     }
[582] 
[583]     if (ngx_http_perl_sv2str(aTHX_ r, &header->value, value) != NGX_OK) {
[584]         header->hash = 0;
[585]         ctx->error = 1;
[586]         croak("ngx_http_perl_sv2str() failed");
[587]     }
[588] 
[589]     if (header->key.len == sizeof("Content-Length") - 1
[590]         && ngx_strncasecmp(header->key.data, (u_char *) "Content-Length",
[591]                            sizeof("Content-Length") - 1) == 0)
[592]     {
[593]         r->headers_out.content_length_n = (off_t) SvIV(value);
[594]         r->headers_out.content_length = header;
[595]     }
[596] 
[597]     if (header->key.len == sizeof("Content-Encoding") - 1
[598]         && ngx_strncasecmp(header->key.data, (u_char *) "Content-Encoding",
[599]                            sizeof("Content-Encoding") - 1) == 0)
[600]     {
[601]         r->headers_out.content_encoding = header;
[602]     }
[603] 
[604] 
[605] void
[606] filename(r)
[607]     CODE:
[608] 
[609]     dXSTARG;
[610]     ngx_http_request_t   *r;
[611]     ngx_http_perl_ctx_t  *ctx;
[612]     size_t                root;
[613] 
[614]     ngx_http_perl_set_request(r, ctx);
[615] 
[616]     if (ctx->filename.data) {
[617]         goto done;
[618]     }
[619] 
[620]     if (ngx_http_map_uri_to_path(r, &ctx->filename, &root, 0) == NULL) {
[621]         ctx->error = 1;
[622]         croak("ngx_http_map_uri_to_path() failed");
[623]     }
[624] 
[625]     ctx->filename.len--;
[626]     sv_setpv(PL_statname, (char *) ctx->filename.data);
[627] 
[628]     done:
[629] 
[630]     ngx_http_perl_set_targ(ctx->filename.data, ctx->filename.len);
[631] 
[632]     ST(0) = TARG;
[633] 
[634] 
[635] void
[636] print(r, ...)
[637]     CODE:
[638] 
[639]     ngx_http_request_t   *r;
[640]     ngx_http_perl_ctx_t  *ctx;
[641]     SV                   *sv;
[642]     int                   i;
[643]     u_char               *p;
[644]     size_t                size;
[645]     STRLEN                len;
[646]     ngx_int_t             rc;
[647]     ngx_buf_t            *b;
[648] 
[649]     ngx_http_perl_set_request(r, ctx);
[650] 
[651]     if (ctx->error) {
[652]         croak("print(): called after error");
[653]     }
[654] 
[655]     if (ctx->variable) {
[656]         croak("print(): cannot be used in variable handler");
[657]     }
[658] 
[659]     if (!ctx->header_sent) {
[660]         croak("print(): header not sent");
[661]     }
[662] 
[663]     if (items == 2) {
[664] 
[665]         /*
[666]          * do zero copy for prolate single read-only SV:
[667]          *     $r->print("some text\n");
[668]          */
[669] 
[670]         sv = ST(1);
[671] 
[672]         if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
[673]             sv = SvRV(sv);
[674]         }
[675] 
[676]         if (SvREADONLY(sv) && SvPOK(sv)) {
[677] 
[678]             p = (u_char *) SvPV(sv, len);
[679] 
[680]             if (len == 0) {
[681]                 XSRETURN_EMPTY;
[682]             }
[683] 
[684]             b = ngx_calloc_buf(r->pool);
[685]             if (b == NULL) {
[686]                 ctx->error = 1;
[687]                 croak("ngx_calloc_buf() failed");
[688]             }
[689] 
[690]             b->memory = 1;
[691]             b->pos = p;
[692]             b->last = p + len;
[693]             b->start = p;
[694]             b->end = b->last;
[695] 
[696]             ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[697]                            "$r->print: read-only SV: %z", len);
[698] 
[699]             goto out;
[700]         }
[701]     }
[702] 
[703]     size = 0;
[704] 
[705]     for (i = 1; i < items; i++) {
[706] 
[707]         sv = ST(i);
[708] 
[709]         if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
[710]             sv = SvRV(sv);
[711]         }
[712] 
[713]         (void) SvPV(sv, len);
[714] 
[715]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[716]                        "$r->print: copy SV: %z", len);
[717] 
[718]         size += len;
[719]     }
[720] 
[721]     if (size == 0) {
[722]         XSRETURN_EMPTY;
[723]     }
[724] 
[725]     b = ngx_create_temp_buf(r->pool, size);
[726]     if (b == NULL) {
[727]         ctx->error = 1;
[728]         croak("ngx_create_temp_buf() failed");
[729]     }
[730] 
[731]     for (i = 1; i < items; i++) {
[732]         sv = ST(i);
[733] 
[734]         if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
[735]             sv = SvRV(sv);
[736]         }
[737] 
[738]         p = (u_char *) SvPV(sv, len);
[739]         b->last = ngx_cpymem(b->last, p, len);
[740]     }
[741] 
[742]     out:
[743] 
[744]     rc = ngx_http_perl_output(r, ctx, b);
[745] 
[746]     if (rc == NGX_ERROR) {
[747]         ctx->error = 1;
[748]         croak("ngx_http_perl_output() failed");
[749]     }
[750] 
[751] 
[752] void
[753] sendfile(r, filename, offset = -1, bytes = 0)
[754]     CODE:
[755] 
[756]     ngx_http_request_t        *r;
[757]     ngx_http_perl_ctx_t       *ctx;
[758]     char                      *filename;
[759]     off_t                      offset;
[760]     size_t                     bytes;
[761]     ngx_int_t                  rc;
[762]     ngx_str_t                  path;
[763]     ngx_buf_t                 *b;
[764]     ngx_open_file_info_t       of;
[765]     ngx_http_core_loc_conf_t  *clcf;
[766] 
[767]     ngx_http_perl_set_request(r, ctx);
[768] 
[769]     if (ctx->error) {
[770]         croak("sendfile(): called after error");
[771]     }
[772] 
[773]     if (ctx->variable) {
[774]         croak("sendfile(): cannot be used in variable handler");
[775]     }
[776] 
[777]     if (!ctx->header_sent) {
[778]         croak("sendfile(): header not sent");
[779]     }
[780] 
[781]     filename = SvPV_nolen(ST(1));
[782] 
[783]     if (filename == NULL) {
[784]         croak("sendfile(): NULL filename");
[785]     }
[786] 
[787]     offset = items < 3 ? -1 : SvIV(ST(2));
[788]     bytes = items < 4 ? 0 : SvIV(ST(3));
[789] 
[790]     b = ngx_calloc_buf(r->pool);
[791]     if (b == NULL) {
[792]         ctx->error = 1;
[793]         croak("ngx_calloc_buf() failed");
[794]     }
[795] 
[796]     b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
[797]     if (b->file == NULL) {
[798]         ctx->error = 1;
[799]         croak("ngx_pcalloc() failed");
[800]     }
[801] 
[802]     path.len = ngx_strlen(filename);
[803] 
[804]     path.data = ngx_pnalloc(r->pool, path.len + 1);
[805]     if (path.data == NULL) {
[806]         ctx->error = 1;
[807]         croak("ngx_pnalloc() failed");
[808]     }
[809] 
[810]     (void) ngx_cpystrn(path.data, (u_char *) filename, path.len + 1);
[811] 
[812]     clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
[813] 
[814]     ngx_memzero(&of, sizeof(ngx_open_file_info_t));
[815] 
[816]     of.read_ahead = clcf->read_ahead;
[817]     of.directio = clcf->directio;
[818]     of.valid = clcf->open_file_cache_valid;
[819]     of.min_uses = clcf->open_file_cache_min_uses;
[820]     of.errors = clcf->open_file_cache_errors;
[821]     of.events = clcf->open_file_cache_events;
[822] 
[823]     if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
[824]         ctx->error = 1;
[825]         croak("ngx_http_set_disable_symlinks() failed");
[826]     }
[827] 
[828]     if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
[829]         != NGX_OK)
[830]     {
[831]         if (of.err == 0) {
[832]             ctx->error = 1;
[833]             croak("ngx_open_cached_file() failed");
[834]         }
[835] 
[836]         ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
[837]                       "%s \"%s\" failed", of.failed, filename);
[838] 
[839]         ctx->error = 1;
[840]         croak("ngx_open_cached_file() failed");
[841]     }
[842] 
[843]     if (offset == -1) {
[844]         offset = 0;
[845]     }
[846] 
[847]     if (bytes == 0) {
[848]         bytes = of.size - offset;
[849]     }
[850] 
[851]     b->in_file = 1;
[852] 
[853]     b->file_pos = offset;
[854]     b->file_last = offset + bytes;
[855] 
[856]     b->file->fd = of.fd;
[857]     b->file->log = r->connection->log;
[858]     b->file->directio = of.is_directio;
[859] 
[860]     rc = ngx_http_perl_output(r, ctx, b);
[861] 
[862]     if (rc == NGX_ERROR) {
[863]         ctx->error = 1;
[864]         croak("ngx_http_perl_output() failed");
[865]     }
[866] 
[867] 
[868] void
[869] flush(r)
[870]     CODE:
[871] 
[872]     ngx_http_request_t   *r;
[873]     ngx_http_perl_ctx_t  *ctx;
[874]     ngx_int_t             rc;
[875]     ngx_buf_t            *b;
[876] 
[877]     ngx_http_perl_set_request(r, ctx);
[878] 
[879]     if (ctx->error) {
[880]         croak("flush(): called after error");
[881]     }
[882] 
[883]     if (ctx->variable) {
[884]         croak("flush(): cannot be used in variable handler");
[885]     }
[886] 
[887]     if (!ctx->header_sent) {
[888]         croak("flush(): header not sent");
[889]     }
[890] 
[891]     b = ngx_calloc_buf(r->pool);
[892]     if (b == NULL) {
[893]         ctx->error = 1;
[894]         croak("ngx_calloc_buf() failed");
[895]     }
[896] 
[897]     b->flush = 1;
[898] 
[899]     ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "$r->flush");
[900] 
[901]     rc = ngx_http_perl_output(r, ctx, b);
[902] 
[903]     if (rc == NGX_ERROR) {
[904]         ctx->error = 1;
[905]         croak("ngx_http_perl_output() failed");
[906]     }
[907] 
[908]     XSRETURN_EMPTY;
[909] 
[910] 
[911] void
[912] internal_redirect(r, uri)
[913]     CODE:
[914] 
[915]     ngx_http_request_t   *r;
[916]     ngx_http_perl_ctx_t  *ctx;
[917]     SV                   *uri;
[918] 
[919]     ngx_http_perl_set_request(r, ctx);
[920] 
[921]     if (ctx->variable) {
[922]         croak("internal_redirect(): cannot be used in variable handler");
[923]     }
[924] 
[925]     if (ctx->header_sent) {
[926]         croak("internal_redirect(): header already sent");
[927]     }
[928] 
[929]     uri = ST(1);
[930] 
[931]     if (ngx_http_perl_sv2str(aTHX_ r, &ctx->redirect_uri, uri) != NGX_OK) {
[932]         ctx->error = 1;
[933]         croak("ngx_http_perl_sv2str() failed");
[934]     }
[935] 
[936] 
[937] void
[938] allow_ranges(r)
[939]     CODE:
[940] 
[941]     ngx_http_request_t   *r;
[942]     ngx_http_perl_ctx_t  *ctx;
[943] 
[944]     ngx_http_perl_set_request(r, ctx);
[945] 
[946]     if (ctx->variable) {
[947]         croak("allow_ranges(): cannot be used in variable handler");
[948]     }
[949] 
[950]     r->allow_ranges = 1;
[951] 
[952] 
[953] void
[954] unescape(r, text, type = 0)
[955]     CODE:
[956] 
[957]     dXSTARG;
[958]     ngx_http_request_t   *r;
[959]     ngx_http_perl_ctx_t  *ctx;
[960]     SV                   *text;
[961]     int                   type;
[962]     u_char               *p, *dst, *src;
[963]     STRLEN                len;
[964] 
[965]     ngx_http_perl_set_request(r, ctx);
[966] 
[967]     text = ST(1);
[968] 
[969]     src = (u_char *) SvPV(text, len);
[970] 
[971]     p = ngx_pnalloc(r->pool, len + 1);
[972]     if (p == NULL) {
[973]         ctx->error = 1;
[974]         croak("ngx_pnalloc() failed");
[975]     }
[976] 
[977]     dst = p;
[978] 
[979]     type = items < 3 ? 0 : SvIV(ST(2));
[980] 
[981]     ngx_unescape_uri(&dst, &src, len, (ngx_uint_t) type);
[982]     *dst = '\0';
[983] 
[984]     ngx_http_perl_set_targ(p, dst - p);
[985] 
[986]     ST(0) = TARG;
[987] 
[988] 
[989] void
[990] variable(r, name, value = NULL)
[991]     CODE:
[992] 
[993]     dXSTARG;
[994]     ngx_http_request_t         *r;
[995]     ngx_http_perl_ctx_t        *ctx;
[996]     SV                         *name, *value;
[997]     u_char                     *p, *lowcase;
[998]     STRLEN                      len;
[999]     ngx_str_t                   var, val;
[1000]     ngx_uint_t                  i, hash;
[1001]     ngx_http_perl_var_t        *v;
[1002]     ngx_http_variable_value_t  *vv;
[1003] 
[1004]     ngx_http_perl_set_request(r, ctx);
[1005] 
[1006]     name = ST(1);
[1007] 
[1008]     if (SvROK(name) && SvTYPE(SvRV(name)) == SVt_PV) {
[1009]         name = SvRV(name);
[1010]     }
[1011] 
[1012]     if (items == 2) {
[1013]         value = NULL;
[1014] 
[1015]     } else {
[1016]         value = ST(2);
[1017] 
[1018]         if (SvROK(value) && SvTYPE(SvRV(value)) == SVt_PV) {
[1019]             value = SvRV(value);
[1020]         }
[1021] 
[1022]         if (ngx_http_perl_sv2str(aTHX_ r, &val, value) != NGX_OK) {
[1023]             ctx->error = 1;
[1024]             croak("ngx_http_perl_sv2str() failed");
[1025]         }
[1026]     }
[1027] 
[1028]     p = (u_char *) SvPV(name, len);
[1029] 
[1030]     lowcase = ngx_pnalloc(r->pool, len);
[1031]     if (lowcase == NULL) {
[1032]         ctx->error = 1;
[1033]         croak("ngx_pnalloc() failed");
[1034]     }
[1035] 
[1036]     hash = ngx_hash_strlow(lowcase, p, len);
[1037] 
[1038]     var.len = len;
[1039]     var.data = lowcase;
[1040] #if (NGX_DEBUG)
[1041] 
[1042]     if (value) {
[1043]         ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1044]                        "perl variable: \"%V\"=\"%V\"", &var, &val);
[1045]     } else {
[1046]         ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1047]                        "perl variable: \"%V\"", &var);
[1048]     }
[1049] #endif
[1050] 
[1051]     vv = ngx_http_get_variable(r, &var, hash);
[1052]     if (vv == NULL) {
[1053]         ctx->error = 1;
[1054]         croak("ngx_http_get_variable() failed");
[1055]     }
[1056] 
[1057]     if (vv->not_found) {
[1058] 
[1059]         if (ctx->variables) {
[1060] 
[1061]             v = ctx->variables->elts;
[1062]             for (i = 0; i < ctx->variables->nelts; i++) {
[1063] 
[1064]                 if (hash != v[i].hash
[1065]                     || len != v[i].name.len
[1066]                     || ngx_strncmp(lowcase, v[i].name.data, len) != 0)
[1067]                 {
[1068]                     continue;
[1069]                 }
[1070] 
[1071]                 if (value) {
[1072]                     v[i].value = val;
[1073]                     XSRETURN_UNDEF;
[1074]                 }
[1075] 
[1076]                 ngx_http_perl_set_targ(v[i].value.data, v[i].value.len);
[1077] 
[1078]                 goto done;
[1079]             }
[1080]         }
[1081] 
[1082]         if (value) {
[1083]             if (ctx->variables == NULL) {
[1084]                 ctx->variables = ngx_array_create(r->pool, 1,
[1085]                                                   sizeof(ngx_http_perl_var_t));
[1086]                 if (ctx->variables == NULL) {
[1087]                     ctx->error = 1;
[1088]                     croak("ngx_array_create() failed");
[1089]                 }
[1090]             }
[1091] 
[1092]             v = ngx_array_push(ctx->variables);
[1093]             if (v == NULL) {
[1094]                 ctx->error = 1;
[1095]                 croak("ngx_array_push() failed");
[1096]             }
[1097] 
[1098]             v->hash = hash;
[1099]             v->name.len = len;
[1100]             v->name.data = lowcase;
[1101]             v->value = val;
[1102] 
[1103]             XSRETURN_UNDEF;
[1104]         }
[1105] 
[1106]         XSRETURN_UNDEF;
[1107]     }
[1108] 
[1109]     if (value) {
[1110]         vv->len = val.len;
[1111]         vv->valid = 1;
[1112]         vv->no_cacheable = 0;
[1113]         vv->not_found = 0;
[1114]         vv->data = val.data;
[1115] 
[1116]         XSRETURN_UNDEF;
[1117]     }
[1118] 
[1119]     ngx_http_perl_set_targ(vv->data, vv->len);
[1120] 
[1121]     done:
[1122] 
[1123]     ST(0) = TARG;
[1124] 
[1125] 
[1126] void
[1127] sleep(r, sleep, next)
[1128]     CODE:
[1129] 
[1130]     ngx_http_request_t   *r;
[1131]     ngx_http_perl_ctx_t  *ctx;
[1132]     ngx_msec_t            sleep;
[1133] 
[1134]     ngx_http_perl_set_request(r, ctx);
[1135] 
[1136]     if (ctx->variable) {
[1137]         croak("sleep(): cannot be used in variable handler");
[1138]     }
[1139] 
[1140]     if (ctx->next) {
[1141]         croak("sleep(): another handler active");
[1142]     }
[1143] 
[1144]     sleep = (ngx_msec_t) SvIV(ST(1));
[1145] 
[1146]     ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
[1147]                    "perl sleep: %M", sleep);
[1148] 
[1149]     ctx->next = SvRV(ST(2));
[1150] 
[1151]     r->connection->write->delayed = 1;
[1152]     ngx_add_timer(r->connection->write, sleep);
[1153] 
[1154]     r->write_event_handler = ngx_http_perl_sleep_handler;
[1155]     r->main->count++;
[1156] 
[1157] 
[1158] void
[1159] log_error(r, err, msg)
[1160]     CODE:
[1161] 
[1162]     ngx_http_request_t   *r;
[1163]     ngx_http_perl_ctx_t  *ctx;
[1164]     SV                   *err, *msg;
[1165]     u_char               *p;
[1166]     STRLEN                len;
[1167]     ngx_err_t             e;
[1168] 
[1169]     ngx_http_perl_set_request(r, ctx);
[1170] 
[1171]     err = ST(1);
[1172] 
[1173]     if (SvROK(err) && SvTYPE(SvRV(err)) == SVt_PV) {
[1174]         err = SvRV(err);
[1175]     }
[1176] 
[1177]     e = SvIV(err);
[1178] 
[1179]     msg = ST(2);
[1180] 
[1181]     if (SvROK(msg) && SvTYPE(SvRV(msg)) == SVt_PV) {
[1182]         msg = SvRV(msg);
[1183]     }
[1184] 
[1185]     p = (u_char *) SvPV(msg, len);
[1186] 
[1187]     ngx_log_error(NGX_LOG_ERR, r->connection->log, e, "perl: %s", p);
