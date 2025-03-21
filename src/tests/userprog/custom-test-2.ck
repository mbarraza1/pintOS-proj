# -*- perl -*-
use strict;
use warnings;
use tests::tests;

check_expected(IGNORE_USER_FAULTS => 1, [<<'EOF']);
(custom-test-2) begin
(exec) begin
child-simple: exit(0)
(exec-child-get-pid) begin
(exec-child-get-pid) end
wait(-1): exit(-1)
(custom-test) end
custom-test: exit(0)
EOF

pass;
