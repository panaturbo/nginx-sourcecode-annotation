[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] 
[8] #ifndef _NGX_HTTP_PERL_MODULE_H_INCLUDED_
[9] #define _NGX_HTTP_PERL_MODULE_H_INCLUDED_
[10] 
[11] 
[12] #include <ngx_config.h>
[13] #include <ngx_core.h>
[14] #include <ngx_http.h>
[15] #include <nginx.h>
[16] 
[17] #include <EXTERN.h>
[18] #include <perl.h>
[19] 
[20] 
[21] typedef ngx_http_request_t   *nginx;
[22] 
[23] typedef struct {
[24]     ngx_http_request_t       *request;
[25] 
[26]     ngx_str_t                 filename;
[27]     ngx_str_t                 redirect_uri;
[28] 
[29]     SV                       *next;
[30] 
[31]     ngx_int_t                 status;
[32] 
[33]     unsigned                  done:1;
[34]     unsigned                  error:1;
[35]     unsigned                  variable:1;
[36]     unsigned                  header_sent:1;
[37] 
[38]     ngx_array_t              *variables;  /* array of ngx_http_perl_var_t */
[39] 
[40] #if (NGX_HTTP_SSI)
[41]     ngx_http_ssi_ctx_t       *ssi;
[42] #endif
[43] } ngx_http_perl_ctx_t;
[44] 
[45] 
[46] typedef struct {
[47]     ngx_uint_t    hash;
[48]     ngx_str_t     name;
[49]     ngx_str_t     value;
[50] } ngx_http_perl_var_t;
[51] 
[52] 
[53] extern ngx_module_t  ngx_http_perl_module;
[54] 
[55] 
[56] /*
[57]  * workaround for "unused variable `Perl___notused'" warning
[58]  * when building with perl 5.6.1
[59]  */
[60] #ifndef PERL_IMPLICIT_CONTEXT
[61] #undef  dTHXa
[62] #define dTHXa(a)
[63] #endif
[64] 
[65] 
[66] extern void boot_DynaLoader(pTHX_ CV* cv);
[67] 
[68] 
[69] void ngx_http_perl_handle_request(ngx_http_request_t *r);
[70] void ngx_http_perl_sleep_handler(ngx_http_request_t *r);
[71] 
[72] 
[73] #endif /* _NGX_HTTP_PERL_MODULE_H_INCLUDED_ */
