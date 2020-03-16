#include "armject.h"


void inject(pid_t pid , void *dlopenAddr, char * path) 
{
	
	ALONG locallibc=0, remotelibc=0, memaddr=0,tmp=0;
	int status=0;	
	errno = 0;
	
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
	 
	tmp=call_func(pid,dlopenAddr,2,memaddr,(ALONG)RTLD_LAZY);
	
	printf("[*] Injected library return (R0): %p\n", (void*)tmp);
		
		
	// TODO unmap memaddr :)
	// It may break the sharedlib if it's still using/ref the mmaped region!
	
	
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL)==-1 && errno != 0)
	{
		printf("[!] Ptrace Detach Error: %d\n",errno); 
		return;
	}
	
}

int main(int argc, char **argv) {
ALONG remoteLib, localLib;
void *dlopenAddr = NULL;
void *libAddr = NULL;
char ldmode=0;

	if(argc<3)
	 {
		 printf("[!] %s [pid] [lib absolute path]\n",argv[0]);
		exit(1);
	 }
	
	libAddr =  dlopen("libc.so", RTLD_NOW);
	if (libAddr == NULL) {
		printf("[!] Error opening libc.so\n");
		exit(1);
	}
	
	dlopenAddr = dlsym(libAddr, "__libc_dlopen_mode");		
	if (dlopenAddr == NULL) 
	 {
		printf("[-] Error locating dlopen() into libc, trying libdl!\n");
		libAddr =  dlopen("libdl.so", RTLD_NOW);
		if (libAddr == NULL) {
			printf("[!] Error opening libdl.so\n");
			exit(1);
		}
		
		dlopenAddr = dlsym(libAddr, "dlopen");
		if (dlopenAddr == NULL) 
		 {
			printf("[!] Error locating dlopen()!\n");
			exit(1);
		 }
		 ldmode=1;
	 }
	printf("[*] Local dlopen() found at address %p\n", dlopenAddr);
	
	if(!findLibrary(LIB, atoi(argv[1])))
	{
		printf("[!] Target task is on another arch!\n");
		exit(1);
	}
	remoteLib = findLibrary(ldmode?"libdl":"libc", atoi(argv[1]));
	localLib = findLibrary(ldmode?"libdl":"libc", 0);
	//printf("[*] Local dl symbol located at address %p\n", (void*) localLib);	
	//printf("[*] Remote (%d) dl symbol located at address %p\n", atoi(argv[1]), (void*)remoteLib);		
	//printf("[*] dlopen() offset: %llx \n", (unsigned long)(dlopenAddr - localLib));
	dlopenAddr = (void *) (remoteLib + (dlopenAddr - localLib));
	printf("[*] Remote (%d) dlopen() found at address %p\n",atoi(argv[1]),(void *)dlopenAddr);
	
	//one opened handle in vougue :)
	if(!fopen(argv[2],"r"))
	 {
	   printf("[!] Lib %s cannot be found?\n",argv[2]);
	   exit(1);
	   
	 }	 
	// Inject shared library into the target task
	inject(atoi(argv[1]), dlopenAddr, argv[2]);
	printf("[*] DOne.\n");	
}
