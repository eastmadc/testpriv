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

#ifndef _PCI_CONV_BSD_H_INCLUDED
#define _PCI_CONV_BSD_H_INCLUDED

/*
 * This file is intended to be included from
 * QNX specific code.  The defined routines
 * are used to seed / pull out BSD spefific
 * info
 */

#include <hw/pci.h> /* The QNX one */
#include <pci/pci_conv.h>

/*
 * The NetBSD PCI layer's attach struct declared
 * in their <dev/pci/pcivar.h>.  Opaque to the
 * QNX PCI layer.
 */
struct pci_attach_args;

struct qnx_pci_args {
	struct pci_attach_args	*pa;
	struct pci_dev_info	info;
	uint16_t		cmdreg;
	void			*pci_dev_hdl;
};

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/pci/pci_conv_bsd.h $ $Rev: 680336 $")
#endif
