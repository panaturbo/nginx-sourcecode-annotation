[1] #!/usr/bin/perl -w
[2] 
[3] # Convert unicode mappings to nginx configuration file format.
[4] 
[5] # You may find useful mappings in various places, including
[6] # unicode.org official site:
[7] #
[8] # http://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1251.TXT
[9] # http://www.unicode.org/Public/MAPPINGS/VENDORS/MISC/KOI8-R.TXT
[10] 
[11] # Needs perl 5.6 or later.
[12] 
[13] # Written by Maxim Dounin, mdounin@mdounin.ru
[14] 
[15] ###############################################################################
[16] 
[17] require 5.006;
[18] 
[19] while (<>) {
[20] 	# Skip comments and empty lines
[21] 
[22] 	next if /^#/;
[23] 	next if /^\s*$/;
[24] 	chomp;
[25] 
[26] 	# Convert mappings
[27] 
[28] 	if (/^\s*0x(..)\s*0x(....)\s*(#.*)/) {
[29] 		# Mapping <from-code> <unicode-code> "#" <unicode-name>
[30] 		my $cs_code = $1;
[31] 		my $un_code = $2;
[32] 		my $un_name = $3;
[33] 
[34] 		# Produce UTF-8 sequence from character code;
[35] 
[36] 		my $un_utf8 = join('',
[37] 			map { sprintf("%02X", $_) }
[38] 			unpack("U0C*", pack("U", hex($un_code)))
[39] 		);
[40] 
[41] 		print "    $cs_code  $un_utf8 ; $un_name\n";
[42] 
[43] 	} else {
[44] 		warn "Unrecognized line: '$_'";
[45] 	}
[46] }
[47] 
[48] ###############################################################################
