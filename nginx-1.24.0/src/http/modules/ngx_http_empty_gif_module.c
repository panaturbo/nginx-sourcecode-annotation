[1] 
[2] /*
[3]  * Copyright (C) Igor Sysoev
[4]  * Copyright (C) Nginx, Inc.
[5]  */
[6] 
[7] #include <ngx_config.h>
[8] #include <ngx_core.h>
[9] #include <ngx_http.h>
[10] 
[11] 
[12] static char *ngx_http_empty_gif(ngx_conf_t *cf, ngx_command_t *cmd,
[13]     void *conf);
[14] 
[15] static ngx_command_t  ngx_http_empty_gif_commands[] = {
[16] 
[17]     { ngx_string("empty_gif"),
[18]       NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
[19]       ngx_http_empty_gif,
[20]       0,
[21]       0,
[22]       NULL },
[23] 
[24]       ngx_null_command
[25] };
[26] 
[27] 
[28] /* the minimal single pixel transparent GIF, 43 bytes */
[29] 
[30] static u_char  ngx_empty_gif[] = {
[31] 
[32]     'G', 'I', 'F', '8', '9', 'a',  /* header                                 */
[33] 
[34]                                    /* logical screen descriptor              */
[35]     0x01, 0x00,                    /* logical screen width                   */
[36]     0x01, 0x00,                    /* logical screen height                  */
[37]     0x80,                          /* global 1-bit color table               */
[38]     0x01,                          /* background color #1                    */
[39]     0x00,                          /* no aspect ratio                        */
[40] 
[41]                                    /* global color table                     */
[42]     0x00, 0x00, 0x00,              /* #0: black                              */
[43]     0xff, 0xff, 0xff,              /* #1: white                              */
[44] 
[45]                                    /* graphic control extension              */
[46]     0x21,                          /* extension introducer                   */
[47]     0xf9,                          /* graphic control label                  */
[48]     0x04,                          /* block size                             */
[49]     0x01,                          /* transparent color is given,            */
[50]                                    /*     no disposal specified,             */
[51]                                    /*     user input is not expected         */
[52]     0x00, 0x00,                    /* delay time                             */
[53]     0x01,                          /* transparent color #1                   */
[54]     0x00,                          /* block terminator                       */
[55] 
[56]                                    /* image descriptor                       */
[57]     0x2c,                          /* image separator                        */
[58]     0x00, 0x00,                    /* image left position                    */
[59]     0x00, 0x00,                    /* image top position                     */
[60]     0x01, 0x00,                    /* image width                            */
[61]     0x01, 0x00,                    /* image height                           */
[62]     0x00,                          /* no local color table, no interlaced    */
[63] 
[64]                                    /* table based image data                 */
[65]     0x02,                          /* LZW minimum code size,                 */
[66]                                    /*     must be at least 2-bit             */
[67]     0x02,                          /* block size                             */
[68]     0x4c, 0x01,                    /* compressed bytes 01_001_100, 0000000_1 */
[69]                                    /* 100: clear code                        */
[70]                                    /* 001: 1                                 */
[71]                                    /* 101: end of information code           */
[72]     0x00,                          /* block terminator                       */
[73] 
[74]     0x3B                           /* trailer                                */
[75] };
[76] 
[77] 
[78] static ngx_http_module_t  ngx_http_empty_gif_module_ctx = {
[79]     NULL,                          /* preconfiguration */
[80]     NULL,                          /* postconfiguration */
[81] 
[82]     NULL,                          /* create main configuration */
[83]     NULL,                          /* init main configuration */
[84] 
[85]     NULL,                          /* create server configuration */
[86]     NULL,                          /* merge server configuration */
[87] 
[88]     NULL,                          /* create location configuration */
[89]     NULL                           /* merge location configuration */
[90] };
[91] 
[92] 
[93] ngx_module_t  ngx_http_empty_gif_module = {
[94]     NGX_MODULE_V1,
[95]     &ngx_http_empty_gif_module_ctx, /* module context */
[96]     ngx_http_empty_gif_commands,   /* module directives */
[97]     NGX_HTTP_MODULE,               /* module type */
[98]     NULL,                          /* init master */
[99]     NULL,                          /* init module */
[100]     NULL,                          /* init process */
[101]     NULL,                          /* init thread */
[102]     NULL,                          /* exit thread */
[103]     NULL,                          /* exit process */
[104]     NULL,                          /* exit master */
[105]     NGX_MODULE_V1_PADDING
[106] };
[107] 
[108] 
[109] static ngx_str_t  ngx_http_gif_type = ngx_string("image/gif");
[110] 
[111] 
[112] static ngx_int_t
[113] ngx_http_empty_gif_handler(ngx_http_request_t *r)
[114] {
[115]     ngx_http_complex_value_t  cv;
[116] 
[117]     if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
[118]         return NGX_HTTP_NOT_ALLOWED;
[119]     }
[120] 
[121]     ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));
[122] 
[123]     cv.value.len = sizeof(ngx_empty_gif);
[124]     cv.value.data = ngx_empty_gif;
[125]     r->headers_out.last_modified_time = 23349600;
[126] 
[127]     return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_gif_type, &cv);
[128] }
[129] 
[130] 
[131] static char *
[132] ngx_http_empty_gif(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
[133] {
[134]     ngx_http_core_loc_conf_t  *clcf;
[135] 
[136]     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
[137]     clcf->handler = ngx_http_empty_gif_handler;
[138] 
[139]     return NGX_CONF_OK;
[140] }
