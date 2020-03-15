#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>


#define CPSR_T_MASK ( 1u << 5)
#ifdef __aarch64__
  #define pt_regs  user_pt_regs
  #define uregs    regs
  #define ARM_r0   regs[0]
  #define ARM_lr   regs[30]
  #define ARM_sp   sp
  #define ARM_pc   pc
  #define ARM_cpsr pstate
  #define ALONG     unsigned long long
#else
  #define ALONG     unsigned long 
#endif

extern int errno;

ALONG findLibrary(const char *library, pid_t pid);
ALONG call_func(pid_t pid , void* function, int nargs, ... );
void ptraceWrite(pid_t pid , void *addr, void *data, int len);
