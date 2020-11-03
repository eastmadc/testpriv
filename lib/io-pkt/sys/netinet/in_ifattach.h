#ifndef _NETINET_IN_IFATTACH_H_
#define	_NETINET_IN_IFATTACH_H_

void	in_domifdetach(struct ifnet *, void *);
void	*in_domifattach(struct ifnet *);

#endif /* !_NETINET_IN_IFATTACH_H_ */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/netinet/in_ifattach.h $ $Rev: 680336 $")
#endif
