[1] 
[2] // stub module to test header files' C++ compatibility
[3] 
[4] extern "C" {
[5]   #include <ngx_config.h>
[6]   #include <ngx_core.h>
[7]   #include <ngx_event.h>
[8]   #include <ngx_event_connect.h>
[9]   #include <ngx_event_pipe.h>
[10] 
[11]   #include <ngx_http.h>
[12] 
[13]   #include <ngx_mail.h>
[14]   #include <ngx_mail_pop3_module.h>
[15]   #include <ngx_mail_imap_module.h>
[16]   #include <ngx_mail_smtp_module.h>
[17] 
[18]   #include <ngx_stream.h>
[19] }
[20] 
[21] // nginx header files should go before other, because they define 64-bit off_t
[22] // #include <string>
[23] 
[24] 
[25] void ngx_cpp_test_handler(void *data);
[26] 
[27] void
[28] ngx_cpp_test_handler(void *data)
[29] {
[30]     return;
[31] }
