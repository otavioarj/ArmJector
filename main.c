#include "armject.h"

/*
void isolate(pid_t pid , void *remoteAddr) 
{
	
	ALONG tmp=0;
	int status=0;	
	errno = 0;
	
	// Attach to the target process
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL)==-1 && errno != 0)
	 {
		mprintf("[!] Ptrace Attach Error: %d\n",errno); 
		return;
	 }
	waitpid(pid, &status, WUNTRACED);
	
	tmp=call_func(pid,remoteAddr,1,(ALONG)CLONE_NEWNET);
	
	mprintf("[*] Remote call returned (R0): %p\n", (void*)tmp);		
	
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1 && errno != 0)
	{
		mprintf("[!] Ptrace Detach Error: %d\n",errno); 
		return;
	}
}
*/
void inject(pid_t pid , void *remoteAddr, char * path, void *dlerr) 
{
	
	ALONG locallibc=0, remotelibc=0, memaddr=0,tmp=0, err=0;
	int status=0;	
	errno = 0;	
    char errstr[1024];
	
	
	
	// Attach to the target process
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL)==-1 && errno != 0)
	 {
		mprintf("[!] Ptrace Attach Error: %d\n",errno); 
		return;
	 }
	waitpid(pid, &status, WUNTRACED);
	
	locallibc=findLibrary("libc.so", 0);
	remotelibc=findLibrary("libc.so", pid);
	mprintf("[*] Local libc at: %p - Remote(%d) at: %p\n", (void*)locallibc,pid,(void*)remotelibc);	
	tmp=(ALONG)mmap - locallibc;
	mprintf("[*] Local mmap at: %p - Remote(%d) at: %p\n",(void*) mmap,pid, (void*)(remotelibc+tmp));
	//mprintf("[*] Remote __loader_dlopen prev.calc at: %p\n", (void*)(remotelibc+(dlsym(dlopen("libdl.so", RTLD_NOW), "__loader_dlopen") -locallibc)));	
	
	memaddr=call_func(pid,(void*)(remotelibc+tmp),6,NULL,1024,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS, NULL,NULL);
	if(!memaddr || memaddr==-1)
	  {
		mprintf("[!] Mmap error: %p\n",(void *)memaddr); 
		return;
	 }
	tmp=0;
	mprintf("[*] Mmap addr: %p\n",(void *)memaddr); 
	ptraceWrite(pid,(void*)memaddr, path, strlen(path)+1);		
	ptraceRead(pid,(void *)(remoteAddr+0xC),&tmp,4); 	
	//tmp<<=sizeof(ALONG)*4;
	//tmp>>=sizeof(ALONG)*4;
	mprintf("[*] Remote __loader_dlopen instr: %p addr: %p\n",(void *)(tmp),remoteAddr-OFFSET);
	
	tmp=0; 
	
	// Offset to __loader_dlopen, bypassing Android >7.0.1 namespace loader check in dlopen
	//  3rd parameter is an addr of a lib in the app namespace :)

	tmp=call_func(pid,remoteAddr-OFFSET,3,memaddr,(ALONG)RTLD_LAZY,remotelibc);
	err=call_func(pid,dlerr,0);
	
	mprintf("[*] Injected library return (R0): %p\n", (void*)tmp);	
    if((!tmp || tmp==memaddr) && err)	
	{
	  errstr[0]=1;
	  for(int a=0;errstr[0]!=0 && a<1024;a++)
	   {	  	
	     ptraceRead(pid,(void *)(err+a),&errstr[0],1); 
	     errstr[a+1]=errstr[0];
	   }
	   
	  mprintf("[-] Dlerror: %s\n",errstr+1);
    }
	
		
		
	// TODO unmap memaddr :)
	// It may break the sharedlib if it's still using/ref the mmaped region!
	
	
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1 && errno != 0)
	{
		mprintf("[!] Ptrace Detach Error: %d\n",errno); 
		return;
	}
	
}

int main(int argc, char **argv) 
{
	ALONG remoteLib, localLib;
	void *remoteAddr = NULL;
	void *libAddr = NULL;
	void *dlerr=0;
	char ldmode=0, *cmdline=NULL;	

	if(argc<2)
	 {
		 mprintf("[!] %s [pid] [lib absolute path]\n",argv[0]);
		exit(1);
	 }
	
	libAddr =  dlopen("libdl.so", RTLD_NOW);
	if (libAddr == NULL) {
		mprintf("[!] Error opening libl.so\n");
		exit(1);
	}
	

	remoteAddr = dlsym(libAddr, "dlopen");	
	if (remoteAddr == NULL) 
	{
		mprintf("[-] Error locating dlopen() into libc, trying libdl!\n");
		libAddr =  dlopen("libdl.so", RTLD_NOW);
		if (libAddr == NULL) {
			mprintf("[!] Error opening libdl.so\n");
			exit(1);
		}
	
		//remoteAddr = dlsym(libAddr, "__loader_dlopen");	
		remoteAddr = dlsym(libAddr, "dlopen");			
		ldmode=1;
	}	
		
	if (remoteAddr == NULL) 
	{
		mprintf("[!] Error locating symbol!\n");
		exit(1);
	}		
	 
	mprintf("[*] Symbol is dlopen()\n");	
	mprintf("[*] Local symbol found at address %p\n", remoteAddr);
	//mprintf("[*] Local __loader dlopen found at address %p\n", __loader_dlopen);
	
	cmdline=moveLibrary(argv[2],atoi(argv[1]));
	if(!cmdline)
	{
		mprintf("[!] Error moving library to target!\n");
		exit(1);
	}
	
	if(!findLibrary(LIB, atoi(argv[1])))
	{
		mprintf("[!] Target task is on another arch!\n");
		exit(1);
	}
	remoteLib = findLibrary(ldmode?"libc":"libdl", atoi(argv[1]));
	localLib =  findLibrary(ldmode?"libc":"libdl", 0);
	//mprintf("[*] Local dl symbol located at address %p\n", (void*) localLib);	
	//mprintf("[*] Remote (%d) dl symbol located at address %p\n", atoi(argv[1]), (void*)remoteLib);		
	//mprintf("[*] dlopen() offset: %llx \n", (unsigned long)(remoteAddr - localLib));
	remoteAddr = (void *) (remoteLib + (remoteAddr - localLib));
	dlerr= (void *) (remoteLib + (dlerror - localLib));
	mprintf("[*] Remote (%d) symbol found at address %p\n",atoi(argv[1]),(void *)remoteAddr);
	
	
	//double check? :)
	if(!fopen(cmdline,"r"))
	{
		mprintf("[!] Lib %s cannot be found?\n",cmdline);
		exit(1);	   
	}	 
	mprintf("[*] Using lib as %s\n",cmdline);
	
	// Inject shared library into the target task
	inject(atoi(argv[1]), remoteAddr,cmdline,dlerr);
	
	//else
	//	isolate(atoi(argv[1]), remoteAddr,dlerroraddr);
	mprintf("[+] Done.\n");	
	mprintf("[*] Remove library from %s path? (*/n)",argv[1]);
	if(getchar()!='n')
	 if(remove(cmdline))
	  mprintf("[-] Can't remove file!\n");	
	   
}
