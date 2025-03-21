# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(kernel-priority-donate) begin
(kernel-priority-donate) A: Creating B and C
(kernel-priority-donate) B: Acquiring lock
(kernel-priority-donate) B: Creating D
(kernel-priority-donate) D: Attempting to acquire lock
(kernel-priority-donate) B: Downing semaphore
(kernel-priority-donate) C: Downing semaphore
(kernel-priority-donate) A: Both B and C should be blocked. Calling first sema_up
(kernel-priority-donate) B
(kernel-priority-donate) B: Releasing lock
(kernel-priority-donate) D: Acquired lock
(kernel-priority-donate) D: Released lock
(kernel-priority-donate) A: Calling second sema_up
(kernel-priority-donate) C
(kernel-priority-donate) end
EOF
pass;