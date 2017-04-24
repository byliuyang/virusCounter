#ifndef SHIFT_2_USER
#define SHIFT_2_USER
#define __NR_cs3013_syscall2 356
void printUsage();
long cs3013_syscall2(unsigned short *target_pid, unsigned short *target_uid);
#endif
