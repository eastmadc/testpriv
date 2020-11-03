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

#ifndef _PCI_CONV_H_INCLUDED
#define _PCI_CONV_H_INCLUDED

#include <device_qnx.h>
#include <stdint.h>
#include <machine/bus.h>

struct pci_dev_info;
struct pci_attach_args;
struct qnx_pci_args;

/* Seed NetBSD struct pci_attach_args from QNX code */
struct pci_conv_attach_args {
	int		qb_flags;

	unsigned	qb_bus;
	unsigned	qb_device;
	unsigned	qb_function;

	uint32_t	qb_tag;

	uint32_t	qb_class;
	uint32_t	qb_id;

	uint32_t	qb_intrline;
	uint64_t	qb_bmstr;
};

void pci_qnx_load_qconv(struct pci_conv_attach_args *, struct pci_dev_info *,
	uint16_t *);

unsigned	pci_qnx_conf_read(struct qnx_pci_args *, int);
void	pci_qnx_conf_write(struct qnx_pci_args *, int, uint32_t);
int	pci_qnx_mapreg_map(struct qnx_pci_args *, int, int,
	    uintptr_t *, bus_addr_t *, size_t *);
int	pci_qnx_mapreg_info(struct qnx_pci_args *, int, int, bus_addr_t *,
            size_t *sizep, int *flagsp);
int	pci_qnx_scan(void *, char *, char *, struct cfattach *, int);

/* Allocate struct pci_attach_args */
struct	pci_attach_args * pci_bsd_alloc_attach(void);
void	pci_bsd_free_attach(struct pci_attach_args *);
int	pci_bsd_print(void *, const char *);
/* Convert QNX args to BSD */
void	pci_bsd_conv_attach(struct pci_conv_attach_args *, struct qnx_pci_args *,
	    struct pci_attach_args *);
int	pci_bsd_type_is_mem(int);
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/pci/pci_conv.h $ $Rev: 680336 $")
#endif
