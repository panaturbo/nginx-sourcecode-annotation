[1] package nginx;
[2] 
[3] use 5.006001;
[4] use strict;
[5] use warnings;
[6] 
[7] require Exporter;
[8] 
[9] our @ISA = qw(Exporter);
[10] 
[11] our @EXPORT = qw(
[12]     OK
[13]     DECLINED
[14] 
[15]     HTTP_OK
[16]     HTTP_CREATED
[17]     HTTP_ACCEPTED
[18]     HTTP_NO_CONTENT
[19]     HTTP_PARTIAL_CONTENT
[20] 
[21]     HTTP_MOVED_PERMANENTLY
[22]     HTTP_MOVED_TEMPORARILY
[23]     HTTP_REDIRECT
[24]     HTTP_SEE_OTHER
[25]     HTTP_NOT_MODIFIED
[26]     HTTP_TEMPORARY_REDIRECT
[27]     HTTP_PERMANENT_REDIRECT
[28] 
[29]     HTTP_BAD_REQUEST
[30]     HTTP_UNAUTHORIZED
[31]     HTTP_PAYMENT_REQUIRED
[32]     HTTP_FORBIDDEN
[33]     HTTP_NOT_FOUND
[34]     HTTP_NOT_ALLOWED
[35]     HTTP_NOT_ACCEPTABLE
[36]     HTTP_REQUEST_TIME_OUT
[37]     HTTP_CONFLICT
[38]     HTTP_GONE
[39]     HTTP_LENGTH_REQUIRED
[40]     HTTP_REQUEST_ENTITY_TOO_LARGE
[41]     HTTP_REQUEST_URI_TOO_LARGE
[42]     HTTP_UNSUPPORTED_MEDIA_TYPE
[43]     HTTP_RANGE_NOT_SATISFIABLE
[44] 
[45]     HTTP_INTERNAL_SERVER_ERROR
[46]     HTTP_SERVER_ERROR
[47]     HTTP_NOT_IMPLEMENTED
[48]     HTTP_BAD_GATEWAY
[49]     HTTP_SERVICE_UNAVAILABLE
[50]     HTTP_GATEWAY_TIME_OUT
[51]     HTTP_INSUFFICIENT_STORAGE
[52] );
[53] 
[54] our $VERSION = '%%VERSION%%';
[55] 
[56] require XSLoader;
[57] XSLoader::load('nginx', $VERSION);
[58] 
[59] # Preloaded methods go here.
[60] 
[61] use constant OK                             => 0;
[62] use constant DECLINED                       => -5;
[63] 
[64] use constant HTTP_OK                        => 200;
[65] use constant HTTP_CREATED                   => 201;
[66] use constant HTTP_ACCEPTED                  => 202;
[67] use constant HTTP_NO_CONTENT                => 204;
[68] use constant HTTP_PARTIAL_CONTENT           => 206;
[69] 
[70] use constant HTTP_MOVED_PERMANENTLY         => 301;
[71] use constant HTTP_MOVED_TEMPORARILY         => 302;
[72] use constant HTTP_REDIRECT                  => 302;
[73] use constant HTTP_SEE_OTHER                 => 303;
[74] use constant HTTP_NOT_MODIFIED              => 304;
[75] use constant HTTP_TEMPORARY_REDIRECT        => 307;
[76] use constant HTTP_PERMANENT_REDIRECT        => 308;
[77] 
[78] use constant HTTP_BAD_REQUEST               => 400;
[79] use constant HTTP_UNAUTHORIZED              => 401;
[80] use constant HTTP_PAYMENT_REQUIRED          => 402;
[81] use constant HTTP_FORBIDDEN                 => 403;
[82] use constant HTTP_NOT_FOUND                 => 404;
[83] use constant HTTP_NOT_ALLOWED               => 405;
[84] use constant HTTP_NOT_ACCEPTABLE            => 406;
[85] use constant HTTP_REQUEST_TIME_OUT          => 408;
[86] use constant HTTP_CONFLICT                  => 409;
[87] use constant HTTP_GONE                      => 410;
[88] use constant HTTP_LENGTH_REQUIRED           => 411;
[89] use constant HTTP_REQUEST_ENTITY_TOO_LARGE  => 413;
[90] use constant HTTP_REQUEST_URI_TOO_LARGE     => 414;
[91] use constant HTTP_UNSUPPORTED_MEDIA_TYPE    => 415;
[92] use constant HTTP_RANGE_NOT_SATISFIABLE     => 416;
[93] 
[94] use constant HTTP_INTERNAL_SERVER_ERROR     => 500;
[95] use constant HTTP_SERVER_ERROR              => 500;
[96] use constant HTTP_NOT_IMPLEMENTED           => 501;
[97] use constant HTTP_BAD_GATEWAY               => 502;
[98] use constant HTTP_SERVICE_UNAVAILABLE       => 503;
[99] use constant HTTP_GATEWAY_TIME_OUT          => 504;
[100] use constant HTTP_INSUFFICIENT_STORAGE      => 507;
[101] 
[102] 
[103] sub rflush {
[104]     my $r = shift;
[105] 
[106]     $r->flush;
[107] }
[108] 
[109] 
[110] 1;
[111] __END__
[112] 
[113] =head1 NAME
[114] 
[115] nginx - Perl interface to the nginx HTTP server API
[116] 
[117] =head1 SYNOPSIS
[118] 
[119]   use nginx;
[120] 
[121] =head1 DESCRIPTION
[122] 
[123] This module provides a Perl interface to the nginx HTTP server API.
[124] 
[125] 
[126] =head1 SEE ALSO
[127] 
[128] http://nginx.org/en/docs/http/ngx_http_perl_module.html
[129] 
[130] =head1 AUTHOR
[131] 
[132] Igor Sysoev
[133] 
[134] =head1 COPYRIGHT AND LICENSE
[135] 
[136] Copyright (C) Igor Sysoev
[137] Copyright (C) Nginx, Inc.
[138] 
[139] 
[140] =cut
