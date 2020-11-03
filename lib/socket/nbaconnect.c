/*
 * $QNXLicenseC:
 * Copyright 2007, QNX Software Systems. All Rights Reserved.
 * 
 * You must obtain a written license from and pay applicable license fees to QNX 
 * Software Systems before you may reproduce, modify or distribute this software, 
 * or any work that includes all or part of this software.   Free development 
 * licenses are available for evaluation and non-commercial purposes.  For more 
 * information visit http://licensing.qnx.com or email licensing@qnx.com.
 *  
 * This file may contain contributions from others.  Please review this entire 
 * file for other proprietary rights or license notices, as well as the QNX 
 * Development Suite License Guide at http://licensing.qnx.com/license-guide/ 
 * for other information.
 * $
 */




#include <errno.h>
#include <sys/dcmd_ip.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include "autoconnect.h"

struct connect_info{
	int sock;
        int rp;
	int err;
	struct sockaddr name;
 	size_t namelen;
};

void acon(struct connect_info *info);

int nbaconnect(int s, const struct sockaddr *name, socklen_t namelen)
{
    int ret;
    int flags;
    int err;	
    int p[2];
    pthread_attr_t attr;
    struct connect_info *info; 

    if((flags=fcntl(s,F_GETFL))==-1)
      return(-1);
    if((flags&O_NONBLOCK)==0){
      errno=EINVAL;
      return(-1);
    }    

    ret = _devctl(s, DCMD_IP_SDESTADDR, (void *)name, namelen, _DEVCTL_FLAG_NORETVAL);

    if (ret==-1 && (errno==EHOSTUNREACH || errno==EADDRNOTAVAIL) &&
	do_autocon() != 0) {
      err=errno;
      if(pipe(p)==-1)
        return (-1);
      info=malloc(sizeof(*info));
      if(info==NULL){
        close(p[0]);
        close(p[1]);
        return(-1);
      }
      info->sock=s;
      info->err=err;	
      info->rp=p[1];
      memcpy(&info->name,name,sizeof(info->name)); 
      info->namelen=namelen; 
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
      pthread_attr_setstacksize(&attr,8192); 
      pthread_create(NULL, &attr, (void *)&acon, (void *) info);
      ret=p[0];     

    }
    return(ret); 
}

void acon(struct connect_info *info)
{
   int ret;
   int response;
   int n,c=0;
   char *off;

   ret = autoconnect();
   if (ret == 0)
     ret = _devctl(info->sock, DCMD_IP_SDESTADDR, (void *)&info->name, info->namelen, _DEVCTL_FLAG_NORETVAL);           
   else if (ret > 0){
     errno = info->err;
     ret = -1;
   }
   if(ret == -1)
     response = errno;
   else
     response = EOK;
   n = sizeof(response);
   off = (char *)&response;   
   while(n){
     c=write(info->rp,off,n);
     if ((c == -1)&&(errno != EINTR))
       break;
     n=n-c;
     off=off+c;
   }
   close(info->rp);
   free(info);
}


int nbaconnect_result(int fd, int *error)
{
   int n,c;
   char *off;

   *error = 0;    
   off = (char *)error;

   n = sizeof(*error);
   
   do {
     c=read(fd,off,n);
     if (c == 0 || ((c == -1)&&(errno != EINTR)))
       break;
     n=n-c;
     off=off+c;
   } while(n);
   close(fd);
   if (c == 0){
     errno = ENOMSG;
     return(-1); 
   } 
   if (c == -1)
     return(-1);  
   return(0);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/nbaconnect.c $ $Rev: 729877 $")
#endif
