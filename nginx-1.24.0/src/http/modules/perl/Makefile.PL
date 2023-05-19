[1] 
[2] # Copyright (C) Igor Sysoev
[3] # Copyright (C) Nginx, Inc.
[4] 
[5] use 5.006001;
[6] use ExtUtils::MakeMaker;
[7] 
[8] WriteMakefile(
[9]     NAME              => 'nginx',
[10]     VERSION_FROM      => 'nginx.pm',     # finds $VERSION
[11]     PREREQ_PM         => {},             # e.g., Module::Name => 1.1
[12] 
[13]     ABSTRACT_FROM     => 'nginx.pm',     # retrieve abstract from module
[14]     AUTHOR            => 'Igor Sysoev',
[15] 
[16]     CCFLAGS           => "$ENV{NGX_PM_CFLAGS}",
[17]     OPTIMIZE          => '-O',
[18] 
[19]     LDDLFLAGS         => "$ENV{NGX_PM_LDFLAGS}",
[20] 
[21]     INC               => join(" ", map {
[22]                              m#^/# ? "-I $_" : "-I ../../../../../$_"
[23]                          } (split /\s+/, $ENV{NGX_INCS})),
[24] 
[25]     depend => {
[26]         'nginx.c'     => join(" ", map {
[27]                              m#^/# ? $_ : "../../../../../$_"
[28]                          } (split(/\s+/, $ENV{NGX_DEPS}),
[29]                             "src/http/modules/perl/ngx_http_perl_module.h"))
[30]     },
[31] 
[32]     PM => {
[33]         'nginx.pm'    => '$(INST_LIBDIR)/nginx.pm'
[34]     }
[35] );
