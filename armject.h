#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <elf.h>

#define CPSR_T_MASK ( 1u << 5)
#ifdef __aarch64__
  #define pt_regs  user_pt_regs
  #define uregs    regs
  #define ARM_r0   regs[0]
  #define ARM_lr   regs[30]
  #define ARM_sp   sp
  #define ARM_pc   pc
  #define ARM_cpsr pstate
  #define ALONG    unsigned long long  
  #define LIB 	   "lib64/"	
#else
  #define LIB 	   "lib/"	
  #define ALONG    unsigned long 
#endif

#define CLONE_NEWCGROUP		0x02000000	/* New cgroup namespace */
#define CLONE_NEWUTS		0x04000000	/* New utsname namespace */
#define CLONE_NEWIPC		0x08000000	/* New ipc namespace */
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#define CLONE_NEWPID		0x20000000	/* New pid namespace */
#define CLONE_NEWNET		0x40000000	/* New network namespace */

extern int errno;

ALONG findLibrary(const char *library, pid_t pid);
ALONG call_func(pid_t pid , void* function, int nargs, ... );
void ptraceWrite(pid_t pid , void *addr, void *data, int len);
void ptraceRead(pid_t pid , void *addr, void *data, int len) ;
