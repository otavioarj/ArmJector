#define _GNU_SOURCE 
#include <stdlib.h>
#include <sched.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
 
#define STACK_SIZE 16384
#define mprint(args...) {printf(args);exit(1);}

/* From linux/sched.h:
	#define CLONE_NEWNS			0x00020000	// New filesystem namespace 
	#define CLONE_NEWUTS		0x04000000	// New utsname group? 
	#define CLONE_NEWIPC		0x08000000	// New ipcs 
	#define CLONE_NEWUSER		0x10000000	// New user namespace 
	#define CLONE_NEWPID		0x20000000	// New pid namespace 
	#define CLONE_NEWNET		0x40000000	// New network namespace 
*/



extern int errno;

struct pparam
{
	struct stat info;
	char * str;
	char * * env;
};

int ns_clone(void *arg)
{
	struct pparam *pp=arg;		
	//struct group  *gr = getgrgid(info->st_gid);
	char *param;	
	struct passwd *pw = getpwuid(pp->info.st_uid);
	errno = 0;
	
	printf("[+] Target uid: %d | gid: %d\n",pw->pw_uid,pw->pw_gid);
	if(!pw)
		mprint("[-] Cant get uid and gid. Err: %s (%d)\n",strerror(errno),errno);  	 
	
	
	if(setuid(pw->pw_uid))
		mprint("[-] Cant set uid!!. Err: %s (%d)\n",strerror(errno),errno); 
	
	if(setgid(pw->pw_gid))
		printf("[*] Cant set gid, non essential. Err: %s (%d)\n",strerror(errno),errno);  
		
	if(pp->str[0]!='/')
	 {
	   param=(char *)malloc(58+strlen(pp->str));
	   sprintf(param,"/system/bin/am start -a android.intent.action.MAIN -n %s",pp->str);
	   printf("[+] Exec: %s.\n",param);
	   return system(param);		
	 }
	
	param=pp->str;  
	printf("[+] Exec: %s.\n",param);
	execve(param,NULL ,pp->env);	
	return 0; // never reach :P
}
 
int main(int argc, char ** argv, char **env)
{
	//struct stat info;
	char cname[267], *stack;	
	int ret=0;
	errno = 0;
	struct pparam param={};
	param.str=(char *)malloc(256);
	
	if(argc<2)
	 mprint("[-] %s  absolute_path_elf OR com.app.name/.MainActivity\n",argv[0]);
		
	if(argv[1][0]!='/')
	{
		for(int i=0;i<256 && i<strlen(argv[1]);i++)
		{
			param.str[i]=argv[1][i];
			if(param.str[i]=='/')
			{
				param.str[i]='\0';
				break;
			}
		}
		sprintf(cname,"/data/data/%s",param.str);
	}
	else  
		sprintf(cname,"%s",argv[1]);
		
	printf("[+] Stating %s\n",cname);
	if(stat(cname, &param.info))
	 mprint("[-] Cant Stat app name!. Err: %s (%d)\n",strerror(errno),errno);  
	 
	free(param.str);
	param.str=argv[1];
	 
	 
	stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	
    if (stack == MAP_FAILED)
		mprint("[-] Cant alloc stack!. Err: %s (%d)\n",strerror(errno),errno);  
	param.env=env;
	 
	ret=clone(ns_clone,stack + STACK_SIZE, CLONE_NEWNET | CLONE_NEWNS ,&param);
	if(ret>0)
		printf("[+] Clone Pid: %d\n",ret);
	else
		printf("[-] Clone failed! Err: %s (%d)\n",strerror(errno),errno);
			
}
	
