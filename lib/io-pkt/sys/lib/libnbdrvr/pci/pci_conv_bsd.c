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

/*
 * Copyright (c) 1995, 1996, 1997, 1998
 *     Christopher G. Demetriou.  All rights reserved.
 * Copyright (c) 1994 Charles M. Hannum.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Charles M. Hannum.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <pci/pci_conv.h>

/* bsd headers */
#include <dev/pci/pcivar.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <unistd.h>

int
pci_bsd_print(void *aux, const char *pnp)
{
	struct pci_attach_args	*pa;

	pa = aux;

	aprint_normal(" at pci%d dev %d function %d", pa->pa_bus,
	    pa->pa_device, pa->pa_function);

	return 0;
}
    
struct pci_attach_args *
pci_bsd_alloc_attach(void)
{
	struct pci_attach_args *pa;

	pa = malloc(sizeof(*pa), M_DEVBUF, M_NOWAIT | M_ZERO);

	return pa;
}

void
pci_bsd_free_attach(struct pci_attach_args *pa)
{
	free(pa, M_DEVBUF);
	return;
}

/* Convert QNX args to BSD.  */
void
pci_bsd_conv_attach(struct pci_conv_attach_args *q_to_b, struct qnx_pci_args *qpa,
        struct pci_attach_args *pa)
{
	memset(pa, 0x00, sizeof(*pa));

	pa->pa_bus = q_to_b->qb_bus;
	pa->pa_device = q_to_b->qb_device;
	pa->pa_function = q_to_b->qb_function;
	pa->pa_class = q_to_b->qb_class;
	pa->pa_id = q_to_b->qb_id;
	pa->pa_tag = q_to_b->qb_tag;
	pa->pa_flags = q_to_b->qb_flags;
	pa->pa_intrtag = q_to_b->qb_intrline;
	pa->pa_iot = BUS_SPACE_IO | BUS_SPACE_LE;
	pa->pa_memt = BUS_SPACE_MEM | BUS_SPACE_LE;

	pa->pa_pc = qpa;
	pa->pa_dmat = q_to_b->qb_bmstr;

	pa->pa_qpa = qpa;
	
	return;
}

int
pci_bsd_type_is_mem(int type)
{
	if (type == PCI_MAPREG_TYPE_MEM)
		return 1;
	else if (type == PCI_MAPREG_TYPE_IO)
		return 1;
	return -1;
}

#define _PCI_MAPREG_TYPEBITS(reg) \
	(PCI_MAPREG_TYPE(reg) == PCI_MAPREG_TYPE_IO ? \
	reg & PCI_MAPREG_TYPE_MASK : \
	reg & (PCI_MAPREG_TYPE_MASK|PCI_MAPREG_MEM_TYPE_MASK))

pcireg_t
pci_mapreg_type(pci_chipset_tag_t pc, pcitag_t tag, int reg)
{

	return (_PCI_MAPREG_TYPEBITS(pci_conf_read(pc, tag, reg)));
}


int
pci_mapreg_map(struct pci_attach_args *pa, int reg, pcireg_t type,
        int busflags, bus_space_tag_t *tagp, bus_space_handle_t *handlep,
	    bus_addr_t *basep, bus_size_t *sizep)
{
	type = PCI_MAPREG_TYPE(type);

	switch (type) {
	case PCI_MAPREG_TYPE_MEM:
		/* pci is inherently little endian */
		*tagp = BUS_SPACE_MEM | BUS_SPACE_LE;
		break;

	case PCI_MAPREG_TYPE_IO:
		/* pci is inherently little endian */
		*tagp = BUS_SPACE_IO | BUS_SPACE_LE;
		break;

	default:
		return 1;
		break;
	}

	if (pci_qnx_mapreg_map(pa->pa_qpa, reg, (type == PCI_MAPREG_TYPE_MEM),
	    handlep, basep, sizep) != 0)
		return 1;

	return 0;
}

int
pci_mapreg_info(pci_chipset_tag_t pc, pcitag_t tag, int reg, pcireg_t type,
    bus_addr_t *basep, bus_size_t *sizep, int *flagsp)
{
	if (pci_qnx_mapreg_info((struct qnx_pci_args *)pc, reg,
	    PCI_MAPREG_TYPE(type) == PCI_MAPREG_TYPE_MEM, basep, sizep,
	    flagsp) != 0)
		return 1;

	return 0;
}

int
pci_get_capability(pci_chipset_tag_t pc, pcitag_t tag, int capid, int *offset,
    pcireg_t *value)
{
	pcireg_t reg;
	unsigned int ofs;

	reg = pci_conf_read(pc, tag, PCI_COMMAND_STATUS_REG);
	if (!(reg & PCI_STATUS_CAPLIST_SUPPORT))
		return (0);

	/* Determine the Capability List Pointer register to start with. */
	reg = pci_conf_read(pc, tag, PCI_BHLC_REG);
	switch (PCI_HDRTYPE_TYPE(reg)) {
	case 0:	/* standard device header */
		ofs = PCI_CAPLISTPTR_REG;
		break;
	case 2:	/* PCI-CardBus Bridge header */
		ofs = PCI_CARDBUS_CAPLISTPTR_REG;
		break;
	default:
		return (0);
	}

	ofs = PCI_CAPLIST_PTR(pci_conf_read(pc, tag, ofs));
	while (ofs != 0) {
#ifdef DIAGNOSTIC
		if ((ofs & 3) || (ofs < 0x40))
			panic("pci_get_capability");
#endif
		reg = pci_conf_read(pc, tag, ofs);
		if (PCI_CAPLIST_CAP(reg) == capid) {
			if (offset)
				*offset = ofs;
			if (value)
				*value = reg;
			return (1);
		}
		ofs = PCI_CAPLIST_NEXT(reg);
	}

	return (0);
}




void
pci_conf_capture(pci_chipset_tag_t pc, pcitag_t tag,
		  struct pci_conf_state *pcs)
{
	int off;

	for (off = 0; off < 16; off++)
		pcs->reg[off] = pci_conf_read(pc, tag, (off * 4));

	return;
}

void
pci_conf_restore(pci_chipset_tag_t pc, pcitag_t tag,
		  struct pci_conf_state *pcs)
{
	int off;

	for (off = 0; off < 16; off++)
		pci_conf_write(pc, tag, (off * 4), pcs->reg[off]);

	return;
}

/*
 * Power Management Capability (Rev 2.2)
 */
int
pci_get_powerstate(pci_chipset_tag_t pc, pcitag_t tag , pcireg_t *state)
{
	int offset;
	pcireg_t value, cap, now;

	if (!pci_get_capability(pc, tag, PCI_CAP_PWRMGMT, &offset, &value))
		return EOPNOTSUPP;

	cap = value >> PCI_PMCR_SHIFT;
	value = pci_conf_read(pc, tag, offset + PCI_PMCSR);
	now = value & PCI_PMCSR_STATE_MASK;
	switch (now) {
	case PCI_PMCSR_STATE_D0:
	case PCI_PMCSR_STATE_D1:
	case PCI_PMCSR_STATE_D2:
	case PCI_PMCSR_STATE_D3:
		*state = now;
		return 0;
	default:
		return EINVAL;
	}
}

int
pci_set_powerstate(pci_chipset_tag_t pc, pcitag_t tag, pcireg_t state)
{
	int offset;
	pcireg_t value, cap, now;

	if (!pci_get_capability(pc, tag, PCI_CAP_PWRMGMT, &offset, &value))
		return EOPNOTSUPP;

	cap = value >> PCI_PMCR_SHIFT;
	value = pci_conf_read(pc, tag, offset + PCI_PMCSR);
	now = value & PCI_PMCSR_STATE_MASK;
	value &= ~PCI_PMCSR_STATE_MASK;

	if (now == state)
		return 0;
	switch (state) {
	case PCI_PMCSR_STATE_D0:
		value |= PCI_PMCSR_STATE_D0;
		break;
	case PCI_PMCSR_STATE_D1:
		if (now == PCI_PMCSR_STATE_D2 || now == PCI_PMCSR_STATE_D3)
			return EINVAL;
		if (!(cap & PCI_PMCR_D1SUPP))
			return EOPNOTSUPP;
		value |= PCI_PMCSR_STATE_D1;
		break;
	case PCI_PMCSR_STATE_D2:
		if (now == PCI_PMCSR_STATE_D3)
			return EINVAL;
		if (!(cap & PCI_PMCR_D2SUPP))
			return EOPNOTSUPP;
		value |= PCI_PMCSR_STATE_D2;
		break;
	case PCI_PMCSR_STATE_D3:
		if (now == PCI_PMCSR_STATE_D3)
			return 0;
		value |= PCI_PMCSR_STATE_D3;
		break;
	default:
		return EINVAL;
	}
	pci_conf_write(pc, tag, offset + PCI_PMCSR, value);
	DELAY(1000);
	return 0;
}

int
pci_activate(pci_chipset_tag_t pc, pcitag_t tag, void *sc,
    int (*wakefun)(pci_chipset_tag_t, pcitag_t, void *, pcireg_t))
{
	struct device *dv = sc;
	pcireg_t pmode;
	int error;

	if ((error = pci_get_powerstate(pc, tag, &pmode)))
		return error;

	switch (pmode) {
	case PCI_PMCSR_STATE_D0:
		break;
	case PCI_PMCSR_STATE_D3:
		if (wakefun == NULL) {
			/*
			 * The card has lost all configuration data in
			 * this state, so punt.
			 */
			aprint_error(
			    "%s: unable to wake up from power state D3\n",
			    dv->dv_xname);
			return EOPNOTSUPP;
		}
		/*FALLTHROUGH*/
	default:
		if (wakefun) {
			error = (*wakefun)(pc, tag, sc, pmode);
			if (error)
				return error;
		}
		aprint_normal("%s: waking up from power state D%d\n",
		    dv->dv_xname, pmode);
		if ((error = pci_set_powerstate(pc, tag, PCI_PMCSR_STATE_D0)))
			return error;
	}
	return 0;
}

int
pci_activate_null(pci_chipset_tag_t pc, pcitag_t tag,
    void *sc, pcireg_t state)
{
	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/pci/pci_conv_bsd.c $ $Rev: 680336 $")
#endif
