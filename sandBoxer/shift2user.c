#include "shift2user.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

int main(int argc, char *argv[]) {
  unsigned short uid; // The target uid
  unsigned short pid; // The target pid

  // Parse command line parameters
  if (argc > 4) {
    if (!strcmp(argv[1], "-u") && !strcmp(argv[3], "-p")) {
      uid = atoi(argv[2]);
      pid = atoi(argv[4]);
    } else if (!strcmp(argv[1], "-p") && !strcmp(argv[3], "-u")) {
      uid = atoi(argv[4]);
      pid = atoi(argv[2]);
    } else {
      exit(0);
    }

    // Invoke system call to modify process uid
    if (cs3013_syscall2(&pid, &uid) < 0)
      printf("Error: %s\n", strerror(errno));
    else
      printf("Process %d has been shifted to user %d\n", pid, uid);
  } else {
    printUsage();
  }
}

/*
 * This method invoked the system call cs3013_syscall2
 * @param target_pid The target process id to modify
 * @param target_uid The new user id for the target process
 * @retrun 0, call succeed; others, invalid parameters or no access to the
 * process
 */
long cs3013_syscall2(unsigned short *target_pid, unsigned short *target_uid) {
  return (long)syscall(__NR_cs3013_syscall2, target_pid, target_uid);
}

/*
 * This method print out usage information about the command
 */
void printUsage() {
  puts("Usage: ./shift2user -u uid -p pid");
  puts("Usage: ./shift2user -p pid -u uid");
}
