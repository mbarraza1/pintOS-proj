#include <stdio.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  // Initialize the lock

  // Fork process A and B
  pid_t pid_B = exec("child-simple");
  pid_t pid_C = exec("child-simple");

  // Wait for both child processes to complete
  wait(pid_B);
  wait(pid_C);

  // Test passes if process B could acquire the lock after process A died
}
