#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_cs3013_syscall1 355

long testCall1(void) { return (long)syscall(__NR_cs3013_syscall1); }

int main() {
  printf("The return values of cs3013_syscall1 calls is:%ld\n", testCall1());
  return 0;
}
