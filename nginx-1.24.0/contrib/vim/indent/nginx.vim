[1] if exists("b:did_indent")
[2]     finish
[3] endif
[4] let b:did_indent = 1
[5] 
[6] setlocal indentexpr=
[7] 
[8] " cindent actually works for nginx' simple file structure
[9] setlocal cindent
[10] " Just make sure that the comments are not reset as defs would be.
[11] setlocal cinkeys-=0#
