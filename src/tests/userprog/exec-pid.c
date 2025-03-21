#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  pid_t pid = exec("child-simple");
  msg("%d", pid);
}
