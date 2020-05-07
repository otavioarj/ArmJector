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
		printf("[!] Ptrace Attach Error: %d\n",errno); 
		return;
	 }
	waitpid(pid, &status, WUNTRACED);
	
	tmp=call_func(pid,remoteAddr,1,(ALONG)CLONE_NEWNET);
	
	printf("[*] Remote call returned (R0): %p\n", (void*)tmp);		
	
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1 && errno != 0)
	{
		printf("[!] Ptrace Detach Error: %d\n",errno); 
		return;
	}
}
*/
void inject(pid_t pid , void *remoteAddr, char * path, void *dlerr) 
{
	
	ALONG locallibc=0, remotelibc=0, memaddr=0,tmp=0, err=0;
	int status=0;	
	errno = 0;	
	char  errstr[1024];
	
	
	
	// Attach to the target process
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL)==-1 && errno != 0)
	 {
		printf("[!] Ptrace Attach Error: %d\n",errno); 
		return;
	 }
	waitpid(pid, &status, WUNTRACED);
	
	locallibc=findLibrary("libc.so", 0);
	remotelibc=findLibrary("libc.so", pid);
	printf("[*] Local libc at: %p - Remote at: %p\n", (void*)locallibc,(void*)remotelibc);	
	tmp=(ALONG)mmap - locallibc;
	printf("[*] Local mmap at: %p\n",(void*) mmap);	
	printf("[*] Remote (%d) mmap at: %p\n", pid, (void*)(remotelibc+tmp));	
	
	memaddr=call_func(pid,(void*)(remotelibc+tmp),6,NULL,1024,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS, NULL,NULL);
	if(!memaddr || memaddr==-1)
	  {
		printf("[!] Mmap error: %p\n",(void *)memaddr); 
		return;
	 }
	
	printf("[*] Mmap addr: %p\n",(void *)memaddr); 
	ptraceWrite(pid,(void*)memaddr, path, strlen(path)+1);	
	tmp=0; 
	 
	tmp=call_func(pid,remoteAddr,2,memaddr,(ALONG)RTLD_LAZY);
	err=call_func(pid,dlerr,0);
	
	printf("[*] Injected library return (R0): %p\n", (void*)tmp);
	if(!tmp && err)	
	{
	  errstr[0]=1;
	  for(int a=0;errstr[0]!=0 && a<1024;a++)
	   {	  	
	     ptraceRead(pid,(void *)(err+a),&errstr[0],1); 
	     errstr[a+1]=errstr[0];
	   }
	   
	  printf("[-] Dlerror: %s\n",errstr+1);
    }
	
		
		
	// TODO unmap memaddr :)
	// It may break the sharedlib if it's still using/ref the mmaped region!
	
	
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1 && errno != 0)
	{
		printf("[!] Ptrace Detach Error: %d\n",errno); 
		return;
	}
	
}

int main(int argc, char **argv) 
{
	ALONG remoteLib, localLib;
	void *remoteAddr = NULL;
	void *libAddr = NULL;
	void *dlerr=0;
	char ldmode=0;

	if(argc<2)
	 {
		 printf("[!] %s [pid] [lib absolute path]\n",argv[0]);
		exit(1);
	 }
	
	libAddr =  dlopen("libc.so", RTLD_NOW);
	if (libAddr == NULL) {
		printf("[!] Error opening libc.so\n");
		exit(1);
	}
	
	if(argc>2)
	{
		printf("[+] Symbol is for dlopen()\n");
		remoteAddr = dlsym(libAddr, "__libc_dlopen_mode");		
		if (remoteAddr == NULL) 
		{
			printf("[-] Error locating dlopen() into libc, trying libdl!\n");
			libAddr =  dlopen("libdl.so", RTLD_NOW);
			if (libAddr == NULL) {
				printf("[!] Error opening libdl.so\n");
				exit(1);
			}
		
			remoteAddr = dlsym(libAddr, "dlopen");			
			ldmode=1;
		}
	}
	
		
	if (remoteAddr == NULL) 
	{
		printf("[!] Error locating symbol!\n");
		exit(1);
	}		
	 
	//refatorar essa bagunça maluca de variaveis!!! oO
	printf("[*] Local symbol found at address %p\n", remoteAddr);
	
	if(!findLibrary(LIB, atoi(argv[1])))
	{
		printf("[!] Target task is on another arch!\n");
		exit(1);
	}
	remoteLib = findLibrary(ldmode?"libdl":"libc", atoi(argv[1]));
	localLib = findLibrary(ldmode?"libdl":"libc", 0);
	//printf("[*] Local dl symbol located at address %p\n", (void*) localLib);	
	//printf("[*] Remote (%d) dl symbol located at address %p\n", atoi(argv[1]), (void*)remoteLib);		
	//printf("[*] dlopen() offset: %llx \n", (unsigned long)(remoteAddr - localLib));
	remoteAddr = (void *) (remoteLib + (remoteAddr - localLib));
	dlerr= (void *) (remoteLib + (dlerror - localLib));
	printf("[*] Remote (%d) symbol found at address %p\n",atoi(argv[1]),(void *)remoteAddr);
	
	if(argc>2)
	{
		//one opened handle in vougue :)
		if(!fopen(argv[2],"r"))
		{
			printf("[!] Lib %s cannot be found?\n",argv[2]);
			exit(1);	   
		}	 
		// Inject shared library into the target task
		inject(atoi(argv[1]), remoteAddr, argv[2],dlerr);
	}
	//else
	//	isolate(atoi(argv[1]), remoteAddr,dlerroraddr);
	printf("[*] Done.\n");	
}
