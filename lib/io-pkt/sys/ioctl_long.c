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

#include <sys/systm.h>
#include <sys/malloc.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <ioctl.h>
#include <ioctl_long.h>

void *
ioctl_long_alloc(void *vin, int cmd, size_t *sizep)
{
	void	*v;

	switch (cmd) {
	case DIOCADDRULE:
	case DIOCGETRULE:
	case DIOCCHANGERULE:
	case DIOCGETRULES: {
		struct pfioc_rule *p;

		*sizep = sizeof(*p);
		if ((v = malloc(sizeof(*p), M_TEMP, M_NOWAIT)) == NULL) 
			break;
		p = v;
		if (copyin(vin, p, sizeof(*p)) != 0) {
			free(v, M_TEMP);
			v = NULL;
		}
		break;
	}

	default:
		v = NULL;
		errno = EINVAL;
		break;
	}

	return v;
}

void
ioctl_long_free(void *v)
{
	free(v, M_TEMP);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/ioctl_long.c $ $Rev: 680336 $")
#endif
