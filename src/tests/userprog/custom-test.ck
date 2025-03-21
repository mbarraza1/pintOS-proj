# -​*- perl -*​-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(custom-test) begin
(create-bad-ptr) begin
create-bad-ptr: exit(-1)
(custom-test) end
custom-test: exit(0)
EOF
pass;