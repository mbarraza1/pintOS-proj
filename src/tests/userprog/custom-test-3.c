#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle = open("sample.txt");

  int pos = tell(100);
  msg("%d", pos);
}
