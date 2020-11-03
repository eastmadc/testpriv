/*
 * $QNXtpLicenseC:
 * Copyright 2007, 2009, QNX Software Systems. All Rights Reserved.
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

#include <sys/systm.h>
#include <sys/neutrino.h>
#include <sys/proc.h>


int
copyin(const void *src, void *dst, size_t len)
{
	struct proc		*p;
	char			*limp, *msgp, *srcp, *dstp;
	size_t			cur;
	int			ret;
	resmgr_context_t	*ctp;


	p = curproc;

	if (p->p_vmspace.vm_flags & VM_NOCTXT) {
		/*
		 * src may not point in a context.
		 * Boundary checking has already
		 * been performed.
		 */
		memcpy(dst, src, len);
		p->p_vmspace.vm_flags &= ~VM_NOCTXT;
		return 0;
	}

	ctp = &p->p_ctxt;

	msgp = (char *)ctp->msg;
	srcp = (char *)src;
	dstp = (char *)dst;

	if (srcp < msgp)
		return EFAULT;

	if (p->p_vmspace.vm_flags & VM_MSGLENCHECK) {
 		p->p_vmspace.vm_flags &= ~VM_MSGLENCHECK;
		if (ctp->info.srcmsglen < (len + (srcp-msgp)))
			return EMORE;
	}

	limp = msgp + p->p_ctxt.msg_max_size;
	if (srcp < limp) {
		cur = min(len, limp - srcp);
		memcpy(dstp, srcp, cur);
		if ((len -= cur) == 0)
			return 0;

		srcp += cur;
		dstp += cur;
	}

	ret = MsgRead_r(p->p_ctxt.rcvid, dstp, len, srcp - msgp);

	if (ret < 0)
		return -ret;

	return 0;
}

int
copyout(const void *src, void *dst, size_t len)
{
	struct proc		*p;
	char			*limp, *msgp, *srcp, *dstp;
	size_t			cur;
	int			ret;
	resmgr_context_t	*ctp;

	ret = 0;

	p = curproc;

	if (p->p_vmspace.vm_flags & VM_NOCTXT) {
		/*
		 * dst may not point in a context.
		 * Boundary checking has already
		 * been performed.
		 */
		memcpy(dst, src, len);
		p->p_vmspace.vm_flags &= ~VM_NOCTXT;
		return 0;
	}

	ctp = &p->p_ctxt;

	msgp = (char *)ctp->msg;
	srcp = (char *)src;
	dstp = (char *)dst;

	if (dstp < msgp)
		return EFAULT;

	if (p->p_vmspace.vm_flags & VM_MSGLENCHECK) {
 		p->p_vmspace.vm_flags &= ~VM_MSGLENCHECK;
		if (ctp->info.dstmsglen < (len + (dstp-msgp)))
			return EMORE;
	}

	limp = msgp + p->p_ctxt.msg_max_size;
	if ((p->p_vmspace.vm_flags & VM_OUTFORCE) == 0 && dstp < limp) {
		cur = min(len, limp - dstp);
		memcpy(dstp, srcp, cur);

		srcp += cur;
		dstp += cur;

		len -= cur;
		ret = 0;
	}

	if (len > 0)
		ret = MsgWrite_r(p->p_ctxt.rcvid, srcp, len, dstp - msgp);
	    
	if (ret < 0)
		return -ret;

	dstp += len;

	/*
	 * Inform MsgReply that more data may be
	 * in the context than was passed in.
	 *
	 * XXX this assumes copyout() is called to
	 * pass the data out in order.
	 */
	p->p_offset = dstp - msgp;

	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/copy.c $ $Rev: 680336 $")
#endif
