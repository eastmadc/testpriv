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

#ifndef _MACHINE_PCI_MACHDEP_H_INCLUDED
#define _MACHINE_PCI_MACHDEP_H_INCLUDED
#include <sys/param_bsd.h> /* __PCIREG_T */

typedef void *pci_chipset_tag_t;
typedef uint32_t pcitag_t;
typedef uint32_t pci_intr_handle_t;

struct		pci_attach_args;

#ifdef __PCIREG_T
typedef __PCIREG_T pcireg_t;
#undef __PCIREG_T
#endif
pcireg_t	pci_conf_read(pci_chipset_tag_t, pcitag_t, int);
void		pci_conf_write(pci_chipset_tag_t, pcitag_t, int,
		    pcireg_t);
int		pci_intr_map(struct pci_attach_args *, pci_intr_handle_t *);
const char	*pci_intr_string(pci_chipset_tag_t, pci_intr_handle_t);
void		*pci_intr_establish(pci_chipset_tag_t, pci_intr_handle_t,
		    int, int (*)(void *), void *);
#ifdef __QNXNTO__
void		*pci_intr_establish_exten(pci_chipset_tag_t, pci_intr_handle_t,
		    int, int (*)(void *), void *, int);
#endif
void		pci_intr_disestablish(pci_chipset_tag_t, void *);

#define pci_intr_map(_pa, _ihp) (*_ihp = _pa->pa_intrtag, 0)

#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/machine/pci_machdep.h $ $Rev: 680336 $")
#endif
