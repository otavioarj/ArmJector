#include <stdio.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <errno.h>


#define mprintf(args...) {printf(args);goto exit;}

extern int errno;
// Driver function 
int main(int argc, char **argv) 
{ 
    int sockfd,connfd,sockcli=0;
    unsigned int port=2047, len, len2; 
    struct sockaddr_in servaddr, cli,clib,clip;
    char fridaip[16]="127.0.0.1";      
    char buff[1024];
    struct linger lin;
    lin.l_onoff = 1;
    lin.l_linger = 0; 
    errno=0; 
  
    
    sockfd  = socket(AF_INET, SOCK_STREAM, 0);      
    if (sockfd < 0  ) 
        mprintf("[-] Socket error. Err: %s (%d)\n",strerror(errno),errno); 
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &lin, sizeof(struct linger))<0)
	mprintf("[-] Set Socket error. Err: %s (%d)\n",strerror(errno),errno); 


    
    if (argc<2)
     printf("[*] Local port on %d, and using 127.0.0.1:%d for frida-server\n",port-2,port);
    else if (argc>2)
    { 	   	
      strcpy(fridaip,argv[1]);
      if(argc==3)
       port=atoi(argv[2]);
     }
    

    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(port-2); 

    clib.sin_family = AF_INET; 
    clib.sin_addr.s_addr = htonl(INADDR_ANY); 
    clib.sin_port = htons(1337); 
    
    // client to connect on remote frida server
    clip.sin_family = AF_INET; 
    clip.sin_addr.s_addr = inet_addr(fridaip); 
    clip.sin_port = htons(port); 
  
    if (bind(sockfd,(struct sockaddr*) &servaddr, sizeof(servaddr)) != 0) 
        mprintf("[-] Local server bind failed. Err:%s (%d)\n",strerror(errno),errno); 

    if ((listen(sockfd, 5)) != 0) 
        mprintf("[-] Listen failed! Err:%s (%d)\n",strerror(errno),errno);     
   
    printf("[*] Server listening at %d\n",port-2);  
    
	len=sizeof(cli);
  
	//Blocked to one conn per cycle!! If multi-conn is needed, all scope ({...}) must be in a separated thread!!
    while((connfd=accept(sockfd,(struct sockaddr*)&cli,&len))>=0)
    { 
      printf("[*] Con %d\n",ntohs(cli.sin_port));   
      sockcli = socket(AF_INET,SOCK_STREAM,0); 
      if (sockcli < 0 ) 
      	mprintf("[-] Cli-Socket error. Err: %s (%d)\n",strerror(errno),errno); 

      if (bind(sockcli,(struct sockaddr*) &clib, sizeof(clib)) != 0)  
        mprintf("[-] Cli-source port bind failed. Err: %s (%d)\n",strerror(errno),errno); 
	
      if (connect(sockcli,(struct sockaddr*) &clip, sizeof(clip)) != 0)  
        mprintf("[-] Cant connect to %s:%d! Err:%s (%d)\n",fridaip,port,strerror(errno),errno); 
     
      if (setsockopt(sockcli, SOL_SOCKET,  SO_LINGER,&lin, sizeof(struct linger))<0)
	mprintf("[-] Set CLi-Socket error. Err: %s (%d)\n",strerror(errno),errno); 
        
      while((len2=read(connfd, buff, sizeof(buff)))>0)   
       {    
         //printf("In: %s .Len:%d\n",buff,len2);  
         if(write(sockcli,buff,len2)<0)
          mprintf("[-] Cant send to frida! Err:%s (%d)\n",strerror(errno),errno);  
         memset(buff,0,sizeof(buff));    
     
         if((len2=recv(sockcli, buff, sizeof(buff),0))<0) // ASYNC!
           mprintf("[-] Cant read from frida! Err:%s (%d)\n",strerror(errno),errno);            	
 	 
          if(len2>0)
	   if(send(connfd,buff,len2,0)<0)
            mprintf("[-] Cant send to client. Err:%s (%d)\n",strerror(errno),errno);      
         

	}
      close(sockcli);
    }
exit:
   close(sockfd);
   close(sockcli); 


} 
