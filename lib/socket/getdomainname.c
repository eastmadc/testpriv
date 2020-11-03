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




#include "namespace.h"
#include <unistd.h>
#include <errno.h>

#ifdef __weak_alias
__weak_alias(getdomainname,_getdomainname)
#endif

int
getdomainname(char *domain, size_t len)
{
   /*
    * This changed in the latest release, we'll just
    * return a truncated name according to posix.
    * 
    * if (confstr(_CS_DOMAIN, 0, 0) >= len) {
    *    errno = ENOMEM;
    *    return -1;
    * }
    * 
    * If an error occurs errno will be set in confstr()
    */
   
   if( confstr(_CS_DOMAIN, domain, len) == 0 ){
      return -1;
   }
   
   return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/getdomainname.c $ $Rev: 729877 $")
#endif
