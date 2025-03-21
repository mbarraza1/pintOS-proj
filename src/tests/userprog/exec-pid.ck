# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(exec-pid) begin
(child-simple) run
child-simple: exit(81)
(exec-pid) 4
(exec-pid) end
exec-pid: exit(0)
EOF
pass;
