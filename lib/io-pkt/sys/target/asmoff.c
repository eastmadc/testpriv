/*
 * $QNXtpLicenseC:
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


#include <mkasmoff.h>

#include <sys/param_bsd.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

COMMENT("struct mbuf offsets");
VALUE(M_LEN, offsetof(struct mbuf, m_len));
VALUE(M_DATA, offsetof(struct mbuf, m_data));
VALUE(M_NEXT, offsetof(struct mbuf, m_next));


COMMENT("struct ip offsets");
VALUE(IP_SRC, offsetof(struct ip, ip_src));
VALUE(IP_DST, offsetof(struct ip, ip_dst));

COMMENT("struct ip6_hdr offsets");
VALUE(IP6_SRC, offsetof(struct ip6_hdr, ip6_src));
VALUE(IP6_DST, offsetof(struct ip6_hdr, ip6_dst));

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/target/asmoff.c $ $Rev: 680336 $")
#endif
