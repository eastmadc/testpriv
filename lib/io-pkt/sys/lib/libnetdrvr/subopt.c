/*
 * $QNXLicenseC:
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
 * This functionality in this file will be removed shortly, and should
 * not be used by drivers.
 */

#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <netdrvr/support.h>

static int drvr_parse_internal(void *hdl, char *dev, char *name, char *val);

#define DRVR_OFFSET(a) offsetof(drvr_options_t, a)

static drvr_subopt_tbl_t DrvrOptionsTable[] = 
{
	{ "verbose",     DRVR_OFFSET(verbose), 0, 0 },
	{ "bustype",     0, 0, drvr_parse_internal },
	{ "busindex",    DRVR_OFFSET(busindex), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "busdevice",   DRVR_OFFSET(busdevice), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "busvendor",   DRVR_OFFSET(busvendor), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "ioport",      DRVR_OFFSET(ioport), DRVR_OPT_FLAG_VAL_PADDR, 0 },
	{ "irq",         DRVR_OFFSET(irq), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "dma",         DRVR_OFFSET(dma), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "priority",    0, 0, drvr_parse_internal },

	/*
	 * Note: these are legacy names retained to not aggravate any exisitng cutomers etc.
	 */
	{ "pci",   DRVR_OFFSET(busindex), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "did",   DRVR_OFFSET(busdevice), DRVR_OPT_FLAG_VAL_UINT32, 0 },
	{ "vid",   DRVR_OFFSET(busvendor), DRVR_OPT_FLAG_VAL_UINT32, 0 },
};

static int
drvr_parse_internal(void *hdl, char *dev, char *name, char *val)
{
	drvr_options_t		*options;
	struct sched_param	param;

	options = (drvr_options_t *)hdl;

	if (strcmp(name, "bustype") == 0) {
        if (val == NULL) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
		    "%s: Malformed argument: bustype", dev);
		} else if (strcmp(val, "pci") == 0)
			options->bustype = DRVR_BUSTYPE_PCI;
		else if (strcmp(val, "isa") == 0)
			options->bustype = DRVR_BUSTYPE_ISA;
		else if (strcmp(val, "usb") == 0)
			options->bustype = DRVR_BUSTYPE_USB;
		else if (strcmp(val, "vme") == 0)
			options->bustype = DRVR_BUSTYPE_VME;
		else if (strcmp(val, "pccard") == 0)
			options->bustype = DRVR_BUSTYPE_PCCARD;
		else if (strcmp(val, "iee1394") == 0)
			options->bustype = DRVR_BUSTYPE_IEEE1394;
		else {
			nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
			    "%s: Unknown bustype: %s", dev, val);
		}
	} else if (strcmp(name, "priority") == 0) {
		/* Get the priority of thread 1 */
		SchedGet(0, 1, &param);

		if (val[0] == '+') {
			options->priority = param.sched_priority + strtol(&val[1], 0, 0);
		} else if (val[0] == '-') {
			options->priority = param.sched_priority - strtol(&val[1], 0, 0);
		} else {
			options->priority = strtol(val, 0, 0);
		}

		if (options->priority < 1)
			options->priority = 1;
	} else {
		return -1;
	}

	return 0;
}

int
drvr_parse_subopts(void *hdl,
    char *dev, char *args, drvr_subopt_tbl_chain_t *chain)
{
	char                    tempstr[PATH_MAX+1];
	char                    *name;
	char                    *val;
	char                    *ptr;
	int                     tblsize;
	drvr_subopt_tbl_t       *tbl;
	drvr_subopt_tbl_chain_t link, *linkp;
	int                     i;
	int                     found;
	uint32_t                *int_ptr;
	paddr_t                 *paddr_ptr;

	/* Put another link in the chain */
	link.next = chain;
	link.table = DrvrOptionsTable;
	link.table_size = sizeof(DrvrOptionsTable) / sizeof(drvr_subopt_tbl_t);
	chain = &link;

	ptr = strtok(args, ", ");
	while (ptr) {
		name = NULL;
		val = NULL;
		tempstr[PATH_MAX] = '\0';

		strncpy(tempstr, ptr, PATH_MAX);
		ptr = strtok(NULL, ", ");

		name = tempstr;
		val = strchr(name, '=');
		if (val != NULL) {
			*val = '\0';
			val++;
			if (*val == '\0')
				val = NULL;
		}

		found = 0;
		linkp = chain;
		while (!found && linkp) {
			tbl = linkp->table;
			tblsize = linkp->table_size;
			linkp = linkp->next;

			for (i=0; i<tblsize; i++) {
				if (strcmp(tbl[i].name, name) == 0) {
					found = 1;

					if (tbl[i].handler) {
						tbl[i].handler(hdl, dev, name, val);
					} else if (val == NULL && 
					     (tbl[i].flags & DRVR_OPT_FLAG_VAL_REQ)) {
						nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
						    "%s: Malformed argument: %s", dev, name);
					} else if (tbl[i].flags & DRVR_OPT_FLAG_VAL_PADDR) {
						paddr_ptr = (paddr_t *)((uint8_t *)hdl + tbl[i].offset);
						*paddr_ptr = (paddr_t)strtoull(val, 0, 0);
					} else if (tbl[i].flags & DRVR_OPT_FLAG_VAL_UINT32) {
						int_ptr = (uint32_t *)((uint8_t *)hdl + tbl[i].offset);
						*int_ptr = strtoul(val, 0, 0);
					} else {
						int_ptr = (uint32_t *)((uint8_t *)hdl + tbl[i].offset);
						if (val == NULL || 
						    tbl[i].flags & DRVR_OPT_FLAG_VAL_NONE) {
							*int_ptr += 1;
						} else 
							*int_ptr = strtoul(val, 0, 0);
					}
					break;
				}
			}
		}

		if (!found) {
			nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
			    "%s: Unsupported argument: %s", dev, name);
		}
	}

	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/subopt.c $ $Rev: 703003 $")
#endif
