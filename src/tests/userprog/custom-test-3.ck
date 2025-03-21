# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(custom-test-3) begin
(custom-test-3) -1
(custom-test-3) end
custom-test-3: exit(0)
EOF
pass;