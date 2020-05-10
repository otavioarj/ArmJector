#include "armject.h"


void ptrace_getregs(pid_t pid , struct pt_regs *regs) 
{
    int ret=0;
    errno=0;
#ifdef __aarch64__
    struct {
      void* ufb;
      size_t len;
    } regsvec = { regs, sizeof(struct pt_regs) };   
    ret=ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regsvec);
#else
    ret=ptrace(PTRACE_GETREGS, pid, NULL, regs);
#endif

	if(ret==-1 && errno != 0)
	{
		mprintf("[!] Ptrace GetRegs Error: %d\n",errno); 
		exit(1);
	}
}

void ptrace_setregs(pid_t pid , struct pt_regs *regs) 
{
	int ret=0;
	errno=0;
#ifdef __aarch64__
    struct {
      void* ufb;
      size_t len;
    } regsvec = { regs, sizeof(struct pt_regs) };  
    ret=ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &regsvec);
#else
    ret=ptrace(PTRACE_SETREGS, pid, NULL, regs);
#endif
  
  	if(ret==-1 && errno != 0)
	{
		mprintf("[!] Ptrace SetRegs Error: %d\n",errno); 
		exit(1);
	}
}

void ptraceRead(pid_t pid , void *addr, void *data, int len) 
{
	ALONG word = 0;
	int i = 0;
	char *ptr = (char *)data;
	errno = 0;

	for (i=0; i < len; i+=sizeof(word), word=0) {
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1 && errno != 0) 
		{
			printf("[!] Ptrace PeekTxt Error: %d\n",errno);	
			exit(1);
		}
		//ptr[i] = word;
		memcpy(ptr,&word,len<sizeof(word)?len:sizeof(word));
	}
}

void ptraceWrite(pid_t pid , void *addr, void *data, int len) 
{
	ALONG word = 0;
	int i=0;
	errno = 0;

	for(; i < len; i+=sizeof(word)) {
		memcpy(&word, data + i, sizeof(word));
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1 && errno != 0) 
		{
			mprintf("[!] Ptrace PokeTxt Error: %d\n",errno);
			exit(1);
		}
	}
}


#ifdef __aarch64__
    #define RS 6    
#else
    #define RS 4
 #endif

ALONG call_func(pid_t pid , void* function, int nargs, ... ) 
{
    int i = 0, status=0;
    struct pt_regs regs, oldregs; 
    ALONG arg=0;
    
    ptrace_getregs(pid,&oldregs);    
    memcpy(&regs, &oldregs, sizeof(struct pt_regs));
    
    va_list vl;
    va_start(vl,nargs);

    for(; i < nargs; i++ )
    {
        arg = va_arg( vl, ALONG );        
        if( i < RS )
        {
           regs.uregs[i] = arg;     
#ifdef DE  
           mprintf("--Arg %d - %lx\n",i,regs.uregs[i]);  
#endif  
	   }  
       else 
        { // push remaining params onto stack
            regs.ARM_sp -= sizeof(arg) ;
#ifdef DE
            mprintf("--Arg %d %lx SP:%lu\n",i,arg,regs.ARM_sp); 
#endif          
            ptraceWrite(pid,(void*)regs.ARM_sp, &arg, sizeof(ALONG));           
            
        }
     }

    va_end(vl);
   
    regs.ARM_lr = 0;
    regs.ARM_pc = (ALONG) function;
#ifdef DE
    mprintf("--PC %lx\n",regs.ARM_pc);
#endif
    
 #ifndef __aarch64__    
    // setup the current processor status register
    if ( regs.ARM_pc & 1 ){
        /* thumb */
        regs.ARM_pc   &= (~1u);
        regs.ARM_cpsr |= CPSR_T_MASK;
    }
    else
        /* arm */
        regs.ARM_cpsr &= ~CPSR_T_MASK;
#endif
        
        
    ptrace_setregs(pid,&regs);   
    
    if(ptrace(PTRACE_CONT, pid, NULL, NULL)==-1 && errno != 0)
	 {
		mprintf("[!] Ptrace Continue Error: %d\n",errno); 
		exit(1);
	 }
	waitpid(pid, &status, WUNTRACED);
	
	// restore and backup return of function call (r0)
	ptrace_getregs(pid, &regs);
    ptrace_setregs(pid, &oldregs);    
    return regs.ARM_r0;    
}


ALONG findLibrary(const char *library, pid_t pid) 
{
	char mapFilename[32];
	char buffer[512];
	FILE *fd;
	ALONG addr = 0;

	if (!pid) 
		snprintf(mapFilename, sizeof(mapFilename), "/proc/self/maps");
	else 
		snprintf(mapFilename, sizeof(mapFilename), "/proc/%d/maps", pid);	

	fd = fopen(mapFilename, "r");
	if(!fd)
	{
		mprintf("[!] Invalid PID!\n");
		exit(1);
	}

	while(fgets(buffer, sizeof(buffer), fd)) {
		if (strstr(buffer, library)) {
			addr = strtoull(buffer, NULL, 16);
			break;
		}
	}

	fclose(fd);

	return addr;
}
