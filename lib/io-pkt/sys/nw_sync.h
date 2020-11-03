#ifndef _NW_SYNC_H_INCLUDED
#include <sys/neutrino.h>

#if _NTO_VERSION >= 640
#define NW_SYNC_OWNER __owner
#else
#define NW_SYNC_OWNER owner
#endif
#endif /* !_NW_SYNC_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nw_sync.h $ $Rev: 680336 $")
#endif
