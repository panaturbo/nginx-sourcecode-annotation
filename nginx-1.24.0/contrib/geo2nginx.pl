[1] #!/usr/bin/perl -w
[2] 
[3] # (c) Andrei Nigmatulin, 2005
[4] #
[5] # this script provided "as is", without any warranties. use it at your own risk.
[6] #
[7] # special thanx to Andrew Sitnikov for perl port
[8] #
[9] # this script converts CSV geoip database (free download at http://www.maxmind.com/app/geoip_country)
[10] # to format, suitable for use with nginx_http_geo module (http://sysoev.ru/nginx)
[11] #
[12] # for example, line with ip range
[13] #
[14] #   "62.16.68.0","62.16.127.255","1041253376","1041268735","RU","Russian Federation"
[15] #
[16] # will be converted to four subnetworks:
[17] #
[18] #   62.16.68.0/22 RU;
[19] #   62.16.72.0/21 RU;
[20] #   62.16.80.0/20 RU;
[21] #   62.16.96.0/19 RU;
[22] 
[23] 
[24] use warnings;
[25] use strict;
[26] 
[27] while( <STDIN> ){
[28] 	if (/"[^"]+","[^"]+","([^"]+)","([^"]+)","([^"]+)"/){
[29] 		print_subnets($1, $2, $3);
[30] 	}
[31] }
[32] 
[33] sub  print_subnets {
[34] 	my ($a1, $a2, $c) = @_;
[35] 	my $l;
[36]     while ($a1 <= $a2) {
[37] 		for ($l = 0; ($a1 & (1 << $l)) == 0 && ($a1 + ((1 << ($l + 1)) - 1)) <= $a2; $l++){};
[38] 		print long2ip($a1) . "/" . (32 - $l) . " " . $c . ";\n";
[39]     	$a1 += (1 << $l);
[40] 	}
[41] }
[42] 
[43] sub long2ip {
[44] 	my $ip = shift;
[45] 
[46] 	my $str = 0;
[47] 
[48] 	$str = ($ip & 255);
[49] 
[50] 	$ip >>= 8;
[51] 	$str = ($ip & 255).".$str";
[52] 
[53] 	$ip >>= 8;
[54] 	$str = ($ip & 255).".$str";
[55] 
[56] 	$ip >>= 8;
[57] 	$str = ($ip & 255).".$str";
[58] }
