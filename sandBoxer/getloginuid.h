#ifndef GET_LOGIN_UID
#define GET_LOGIN_UID
#define __NR_cs3013_syscall3 357
void printUsage();
long cs3013_syscall3(unsigned short *target_pid, unsigned short *target_uid);
#endif
