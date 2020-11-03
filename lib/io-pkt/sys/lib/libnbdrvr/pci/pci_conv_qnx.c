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


#define _STDDEF_H_INCLUDED
#include <sys/syspage.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/device.h>
#include <pci/pci_conv.h>
#include <pci/pci_conv_bsd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/io-pkt.h>
#include <sys/malloc.h>
#include <siglock.h>
#include <device_qnx.h>
#include <nw_pci.h>
#include <machine/pci_machdep.h>

void	pci_bus_detach(void *);
const struct sigevent *driver_isr(void *, int);
int driver_enable(void *);

int qnx_mapreg_internal(struct qnx_pci_args *, int, int,
    uintptr_t *, bus_addr_t *, size_t *);

static char *dev_opts[] = {
#define DEVOPT_DID 0
	"did",
#define DEVOPT_VID 1
	"vid",
#define DEVOPT_PCI 2
	"pci",
	NULL
};


int
pci_qnx_scan(void *dll_hdl, char *drvr, char *optstring, struct cfattach *ca,
    int class_flags)
{
	int				idx, idx_max, idx_start,err;
	int				success,single;
	struct pci_conv_attach_args	q_to_b;
	struct qnx_pci_args		*qpa;
	struct device			*dev;
	struct pci_attach_args		*pa;
	uint32_t			vendor_id = 0xffffffff;
	uint32_t			device_id = 0xffffffff;
	uint32_t			device_index = 0xffffffff;
	char				*opt_p = NULL;


	err = ENXIO;
	success = 0;
	qpa = NULL;

	single = 0;

	if (nw_pci_hdl == -1)
		return EAGAIN;

	idx_max = 8;
	idx_start = 0;
	/* 
	 * pull out specific options that cause single instance loading.
	 * We'll consume the options as they're used to see if any invalid
	 * options are left over that should generate an error. 
	 *
	 */
	if (optstring != NULL && *optstring != '\0') {
		opt_p = malloc(strlen(optstring)+1, M_TEMP, M_NOWAIT);
		if (opt_p == NULL) {
			return(ENOMEM);
		}
		strcpy(opt_p, optstring);
	}


	if (opt_p != NULL) {
		char 	*curr;
		char 	*last;

		curr = opt_p;
		last = opt_p;

		while (*curr != '\0') {
			char		*value;
			char		*restore;
			int 		consume;
			int			opt;

			consume = 1;
			restore = strchr(curr, ',');
			
			opt = getsubopt(&curr, dev_opts, &value);

			switch (opt) {
			case DEVOPT_DID:
				if (value != NULL) {
					 device_id = strtol(value, NULL, 0);
				}
				break;
			case DEVOPT_VID:
				if (value != NULL) {
					vendor_id = strtol(value, NULL, 0);
				}
				break;
			case DEVOPT_PCI: 
				if (value != NULL) {
					device_index = strtol(value, NULL, 0);
				}
				if ((device_index < idx_start) ||
				    (device_index >= idx_max)) {
					printf("Invalid PCI index passed to driver/n");		
					free(opt_p,M_TEMP);
					return(EINVAL);
				}
				idx_start = device_index;
				idx_max = device_index+1;
				single = 1;
				break;

			default:
				consume = 0;
		    	break;

			}
			if (consume) {
				char *dst;

				/* also consume last ',' if last and not only opt */
				dst = (*curr == '\0' && last != opt_p) ? last - 1 : last;
				memmove(dst, curr, strlen(curr) + 1);
				curr = dst;

			}
			else if (restore != NULL) {
				*restore = ',';
			}

			last = curr;
		}

	}

	if (device_id == -1 && vendor_id != -1) {
		printf("Can't specify PCI vendor ID without also specifying the device ID\n");
		free(opt_p,M_TEMP);
		return(EINVAL);
	}
	if (device_id != -1 && vendor_id == -1) {
		printf("Can't specify PCI device ID without also specifying the vendor ID\n");
		free(opt_p,M_TEMP);
		return(EINVAL);		
	}

	/* Find all occurences of the given class and check for match */
	for (idx = idx_start; idx < idx_max; idx++) {

		if (qpa == NULL &&
		    ((qpa = malloc(sizeof(*qpa), M_DEVBUF, M_NOWAIT)) == NULL ||
		    (qpa->pa = pci_bsd_alloc_attach()) == NULL)) {
			if (qpa != NULL) {
				free(qpa, M_DEVBUF);
				qpa = NULL;
			}
			err = ENOMEM;
			break;
		}
		pa = qpa->pa;
		memset(qpa, 0, sizeof(*qpa));
		qpa->pa = pa;

		/*
		 * Process options to fill the pci_info with vid/did
		 * and the idx
		 */
		qpa->info.Class = class_flags;

		qpa->pci_dev_hdl = pci_attach_device(NULL,
		    PCI_MASTER_ENABLE | PCI_INIT_ALL, idx, &qpa->info);

		if (qpa->pci_dev_hdl == NULL) {
			/* can't find a device */
			continue;
		}

		/* get the cmd register */
		if (pci_read_config16(qpa->info.BusNumber, qpa->info.DevFunc,
		    offsetof(struct _pci_config_regs, Command),
		    1, (char *)&qpa->cmdreg) == -1) {
			pci_detach_device(qpa->pci_dev_hdl);
			err = errno;
			continue;
		}

		pci_qnx_load_qconv(&q_to_b, &qpa->info, &qpa->cmdreg);
		pci_bsd_conv_attach(&q_to_b, qpa, pa);

		if ((device_id == 0xffffffff) || (vendor_id == 0xffffffff)) {
			/* Use driver match routines. */
			if (ca->ca_match(NULL, NULL, pa) == 0) {
				pci_detach_device(qpa->pci_dev_hdl);
				continue;
			}
		} else {
			/* Match only the passed device / vendor ID. */
			if ((qpa->info.DeviceId != device_id) || 
			    (qpa->info.VendorId != vendor_id)) {
				pci_detach_device(qpa->pci_dev_hdl);
				continue;
			}

		}
		
		/* Found one */

		/*
		 * Parent would normally be pciX which we don't track.
		 * Haven't come across a child of pci that needs it...
		 */
		dev = NULL; /* NULL == no parent */

		if ((err = dev_attach(drvr, opt_p, ca, pa, &single,
		    &dev, pci_bsd_print)) == EOK) {
			success++;
			dev->dv_dll_hdl = dll_hdl;
			dev->dv_bus_hdl = qpa;
			dev->dv_bus_detach = pci_bus_detach;
			qpa = NULL;
			pa = NULL;
		}
		else {
			pci_detach_device(qpa->pci_dev_hdl);
		}

		if (single) {
			break;
		}
	}
	
	if (qpa != NULL) {
		pci_bsd_free_attach(qpa->pa);
		free(qpa, M_DEVBUF);
	}
	if (opt_p != NULL) {
		free(opt_p,M_TEMP);
	}

	/* It at least one succeeded, indicate success */
	if (success)
		return EOK;

	return err;
}

void
pci_bus_detach(void *hdl)
{
	struct qnx_pci_args		*qpa;

	qpa = hdl;

	pci_detach_device(qpa->pci_dev_hdl);
	pci_bsd_free_attach(qpa->pa);
	free(qpa, M_DEVBUF);
}

void
pci_qnx_load_qconv(struct pci_conv_attach_args * q_to_b,
    struct pci_dev_info *infop, uint16_t *regcmdp)
{
	memset(q_to_b, 0x00, sizeof(*q_to_b));
	q_to_b->qb_bus = infop->BusNumber;
	q_to_b->qb_device = PCI_DEVNO(infop->DevFunc);
	q_to_b->qb_function = PCI_FUNCNO(infop->DevFunc);
	/* pa_class is class | subclass | interface | rev */
	q_to_b->qb_class = (infop->Class << 8) | (infop->Revision & 0xff);
	q_to_b->qb_id = (infop->DeviceId << 16) | infop->VendorId;
	q_to_b->qb_tag = (infop->BusNumber << 16) | infop->DevFunc;
	if (regcmdp != NULL)
		q_to_b->qb_flags = *regcmdp;
	q_to_b->qb_intrline = infop->Irq;
	q_to_b->qb_bmstr = infop->CpuBmstrTranslation;
}
    
uint32_t
pci_conf_read(pci_chipset_tag_t pc, pcitag_t tag, int off)
{
	uint32_t val;
	unsigned bus;
	unsigned dev_func;

	bus = ((unsigned)tag >> 16) & 0xffff;
	dev_func = (unsigned)tag & 0xffff;

	if (pci_read_config32(bus, dev_func, off, 1, &val) != PCI_SUCCESS) {
		errno = EINVAL;
		return -1;
	}

	return val;
}


void
pci_conf_write(pci_chipset_tag_t pc, pcitag_t tag, int off, uint32_t val)
{
	uint32_t v = val;
	unsigned bus;
	unsigned dev_func;

	bus = ((unsigned)tag >> 16) & 0xffff;
	dev_func = (unsigned)tag & 0xffff;

	pci_write_config32(bus, dev_func, off, 1, &v);

	return;
}

int
pci_qnx_mapreg_info(struct qnx_pci_args *qpa, int off, int is_mem, bus_addr_t *basep,
    size_t *sizep, int *flagsp)
{
	return qnx_mapreg_internal(qpa, off, is_mem, NULL, basep, sizep);
}

int
pci_qnx_mapreg_map(struct qnx_pci_args *qpa, int off, int is_mem,
    uintptr_t *hdlp, bus_addr_t *basep, size_t *sizep)
{
	if (hdlp == NULL)
		return 1;

	return qnx_mapreg_internal(qpa, off, is_mem, hdlp, basep, sizep);
}

int
qnx_mapreg_internal(struct qnx_pci_args *qpa, int off, int is_mem,
    uintptr_t *hdlp, bus_addr_t *basep, size_t *sizep)
{
	unsigned	bus;
	unsigned	devfunc;
	int		i, protflags;
	uint32_t	paddr_low, paddr_high;
	uint64_t	base, paddr;
	size_t		mapsize;
	uintptr_t	vaddr;

	base = vaddr = 0; /* silence warning */
	bus = qpa->info.BusNumber;
	devfunc = qpa->info.DevFunc;

	if (is_mem) {
		if ((qpa->cmdreg & PCI_COMMAND_MEM_ENABLE) == 0)
			return 1;

		/* Find the memory area. */
		if (pci_read_config32(bus, devfunc, off, 1, &paddr_low) == -1)
			return 1;

		paddr_high = 0;
		if (PCI_IS_MMAP64(paddr_low)) {
			if (pci_read_config32(bus, devfunc, off + 4, 1, &paddr_high) == -1)
				return 1;
		}

		paddr = paddr_high;
		paddr <<= 32;
		paddr |= paddr_low;

		for (i = 0, mapsize = 0;
		    i < (sizeof(qpa->info.CpuBaseAddress) /
		    sizeof(qpa->info.CpuBaseAddress[0]));
		    i++) {
			base = qpa->info.CpuBaseAddress[i];
			if ((base - qpa->info.CpuMemTranslation) == paddr) {
				base = PCI_MEM_ADDR(base);
				mapsize = qpa->info.BaseAddressSize[i];
				if (hdlp == NULL)
					break;
				protflags = PROT_READ | PROT_WRITE;
#ifndef __X86__
/* XXX need to be more sophisticated here */
				protflags |= PROT_NOCACHE;
#endif
				vaddr = (uintptr_t)mmap_device_memory(NULL, mapsize,
				    protflags, MAP_SHARED, base);
				break;
			}
		}
	} else {
		if ((qpa->cmdreg & PCI_COMMAND_IO_ENABLE) == 0)
			return 1;

		/*
		 * Find the io area.
		 *
		 * No such thing as a 64 bit io mapping.
		 */
		if (pci_read_config32(bus, devfunc, off, 1, &paddr_low) == -1)
			return 1;
		paddr = paddr_low;

		for (i = 0, mapsize = 0;
		    i < (sizeof(qpa->info.CpuBaseAddress) /
		    sizeof(qpa->info.CpuBaseAddress[0]));
		    i++) {
			base = qpa->info.CpuBaseAddress[i];
			if ((base - qpa->info.CpuIoTranslation) == paddr) {
				base &= ~0x03;
				mapsize = qpa->info.BaseAddressSize[i];
				if (hdlp == NULL)
					break;
				vaddr = mmap_device_io(mapsize, base);
				break;
			}
		}
	}

	if (mapsize == 0 || (hdlp != NULL && vaddr == MAP_DEVICE_FAILED))
		return 1;

	if (hdlp != NULL)
		*hdlp = vaddr;
	if (sizep != NULL)
		*sizep = mapsize;
	if (basep != NULL)
		*basep = base;

	return 0;
}

const char *
pci_intr_string(pci_chipset_tag_t pc, pci_intr_handle_t ih)
{
	static char irqstr[sizeof"irq " + 8 * sizeof(ih)];

	snprintf(irqstr, sizeof(irqstr), "irq %u", ih);
	return (irqstr);
}


struct intrinfo {
	struct _iopkt_self *iopkt;
	struct _iopkt_inter iointr;
	int intr_level;
	int intr_retid;
	int (*isr_func)(void *arg);
	void *isr_arg;
};

const struct sigevent *
driver_isr(void *arg, int iid)
{
	struct intrinfo		*intrs;
	struct _iopkt_inter	*ient;
	
	intrs = arg;
	ient = &intrs->iointr;
	/* In case driver_enable() gets called before the Attach() returns */
	intrs->intr_retid = iid;

	InterruptMask(intrs->intr_level, iid);

	return interrupt_queue(intrs->iopkt, ient);
}

int
driver_enable(void *arg)
{
	struct intrinfo *intrs = arg;

	InterruptUnmask(intrs->intr_level, intrs->intr_retid);
	return 0;
}

static int
driver_intr_wrap(void *arg, struct nw_work_thread *wtp)
{
	struct intrinfo *intrs = arg;

	intrs->isr_func(intrs->isr_arg);
	return 1;
}



void *
pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level,
    int (*func)(void *), void *arg)
{
	/*
	 * By default the porting lib throws IRUPT_NOTHREAD
	 * which will pare the stack down to single threaded
	 * pulse mode.  If you're sure the driver in question
	 * does all the right things WRT locking, use
	 * pci_intr_establish_exten().
	 */
	return pci_intr_establish_exten(pc, ih, level, func, arg,
	    IRUPT_NOTHREAD);
}

void *
pci_intr_establish_exten(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level,
    int (*func)(void *), void *arg, int safety)
{
	struct intrinfo *intrs;
	
	if ((intrs = malloc(sizeof(*intrs), M_DEVBUF, M_NOWAIT)) == NULL) {
		return NULL;
	}

	intrs->intr_level = ih;
	intrs->iopkt = iopkt_selfp;
	intrs->isr_func = func;
	intrs->isr_arg = arg;

	if (interrupt_entry_init(&intrs->iointr, safety, NULL,
	    IRUPT_PRIO_DEFAULT) != EOK) {
		free(intrs, M_DEVBUF);
		return NULL;
	}
	
	intrs->iointr.func = driver_intr_wrap;
	intrs->iointr.enable = driver_enable;
	intrs->iointr.arg = intrs;
	
	if ((intrs->intr_retid = InterruptAttach(ih, driver_isr, intrs,
	    sizeof(*intrs), _NTO_INTR_FLAGS_TRK_MSK)) == -1) {
		free(intrs, M_DEVBUF);
		return NULL;
	}
	
	return intrs;
}

void
pci_intr_disestablish(pci_chipset_tag_t pc, void *aux)
{
	struct intrinfo *intrs;

	intrs = aux;
	InterruptDetach(intrs->intr_retid);
	interrupt_entry_remove(&intrs->iointr, NULL);
	free(intrs, M_DEVBUF);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/pci/pci_conv_qnx.c $ $Rev: 680336 $")
#endif
