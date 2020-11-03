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




/******************************************************************************
 autoconnect()

 The environment variable AUTOCONNECT=1 must be set. 

 The way this is to work is that if there is a socket library error related
 to not having a required configuration parameter (route, resolv.conf etc)
 a script will be spawned which will attempt to resolve the tcpip configuration
 error before returning a failed status to the application. If the script is
 successfull, then the library function call can be recovered and will not
 return an error. 

 The first call into autoconnect() will spawn a script in an attempt to
 resolve the configuration error and wait for the exit status. If we
 are still waiting for the connection to be established, subsequent calls
 into autoconnect() will block waiting for the first attempt to complete. When
 the first attempt is finished, autoconnect() returns freeing all processes 
 that called autoconnect() returning the script status.                       

 Currently, any functions making use of autoconnect assume that a script
 exit status of zero was sucessfull and > 0 was not. If autoconnect returns
 -1, there was an error in autoconnect().  

 This function does not verify any of the scripts actions. It is assumed
 that the script verified anything that it attempted before returning
 its exit status or logged any events for debugging purposes. 

 Current socket library functions that call autoconnect() are:

 connect() 

 If this function returns -1 and errno is EHOSTUNREACH, it assumes that the
 default route is not set and a "standard" ISP supplied configuration does
 not exist. If the script returns an exit status of zero, the call will be
 attempted again before connect() returns to the application. If the script
 status was greater than zero, the connect is not attempted again.  

 sendto() 

 ""

 res_init()

 If a resolv.conf file or equivilent does not exist, then a "standard" ISP
 supplied configuration does not exist. If the script returns an exit status
 of zero, it attempts to find /etc/resolv.conf again. If the script exit status
 was greater than zero, it does not look a second time. 


******************************************************************************/ 


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <spawn.h>
#include <process.h>
#include <errno.h>
#include <share.h>
#include <resolv.h>
#include "autoconnect.h"

int __try_auto_connect = 1;

int autoconnect(void)
{
  int c,fd;
  int state;     
  pid_t pid;
  int ret=0;
  int err=0;
  char *argv[4];
  int fd_map[3];
  res_state resp;

  argv[0] = "sh";
  argv[1] = "-c";
  argv[2] = "/etc/autoconnect";
  argv[3] = NULL;

  c = sopen("/dev/socket/autoconnect",O_RDONLY,SH_DENYRD);
  state = c;

  if((state==-1)&&(errno==EBUSY)){
    while((c==-1)&&(errno==EBUSY)){
      sleep(10);
      c=sopen("/dev/socket/autoconnect",O_RDONLY,SH_COMPAT);
    }
  }
  else if (state == -1){
    ret = -1;
    err = errno;
  }
  else {
    fd=open("/dev/null",O_RDWR);	
    fd_map[0]=fd;
    fd_map[1]=fd;
    fd_map[2]=fd;
    pid=spawnp("sh",3,fd_map,NULL,argv,NULL);
    close(fd);	
    if(pid<0){
      ret = -1;
      err = errno;
    }
    else{
      if(waitpid(pid,&pid,0)!=-1){
        ret = pid;     
      }
      else{
        ret = -1;
        err = errno;
      }
    }
  }
  close(c);
  errno=err;

  /*
   * The point of this is to knock down RES_INIT for
   * situations where resolver data may exist as a default
   * configuration only to be overridden in the
   * autoconnection by for example ISP nameserver data.
   * Force the resolver libraries to re-read the nameserver
   * data.
   *
   * This hits the per thread context in multithreaded
   * programs.
   */
  if ((resp = __res_get_state()) != NULL) {
	  if (resp->options & RES_INIT) {
		  res_ndestroy(resp);
	  }
	  __res_put_state(resp);
  }

  return ret; 
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/autoconnect.c $ $Rev: 729877 $")
#endif
