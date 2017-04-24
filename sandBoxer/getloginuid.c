#include "getloginuid.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  unsigned short uid; // The target uid
  unsigned short pid; // The target pid

  // Parse command line parameters
  if (argc > 2) {
    if (!strcmp(argv[1], "-p"))
      pid = atoi(argv[2]);
    else
      exit(0);

    // Invoke system call to modify process uid
    if (cs3013_syscall3(&pid, &uid) < 0)
      printf("Error: %s\n", strerror(errno));
    else
      printf("Process %d has loginuid %d\n", pid, uid);

  } else {
    printUsage();
  }
}

long cs3013_syscall3(unsigned short *target_pid, unsigned short *actual_uid) {
  return syscall(__NR_cs3013_syscall3, target_pid, actual_uid);
}

/*
 * This method print out usage information about the command
 */
void printUsage() { puts("Usage: ./getloginuid -p pid"); }
