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
 * The functionality in this file is to be removed - driver's should
 * stop using these functions.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netdrvr/support.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <sys/syspage.h>
#include <hw/sysinfo.h>

static int nic_parse_internal(void *hdl, char *dev, char *name, char *val);

#define NIC_OFFSET(a) offsetof(nic_options_t, a)
static drvr_subopt_tbl_t NicOptionsTable[] = 
{
    { "single",      NIC_OFFSET(single), DRVR_OPT_FLAG_VAL_NONE, 0 },
    { "duplex",      0, 0, nic_parse_internal },
    { "nomulticast", NIC_OFFSET(nomulticast), DRVR_OPT_FLAG_VAL_NONE, 0 },
    { "promiscuous", NIC_OFFSET(promiscuous), DRVR_OPT_FLAG_VAL_NONE, 0 },
    { "media",       NIC_OFFSET(media), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "smem",        NIC_OFFSET(smem), DRVR_OPT_FLAG_VAL_PADDR, 0 },
    { "smemsize",    NIC_OFFSET(smemsize), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "mtu",         NIC_OFFSET(mtu), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "mac",	     0, 0, nic_parse_internal },
    { "width",       NIC_OFFSET(width), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "chipset",     NIC_OFFSET(chipset), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "transmit",    NIC_OFFSET(transmit), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "receive",     NIC_OFFSET(receive), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "pktque",      NIC_OFFSET(pktque), DRVR_OPT_FLAG_VAL_UINT32, 0 },
    { "speed",	     0, 0, nic_parse_internal },
};

static int
nic_parse_internal(void *hdl, char *dev, char *name, char *val)
{
	nic_options_t	*options;
	char		macstr[13];
	int		i, j;

	options = (nic_options_t *)hdl;

	if (strcmp(name, "duplex") == 0) {
		if (val == NULL) {
			nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
			    "%s: Malformed argument: duplex", dev);
		} else if (strcmp(val, "half") == 0 || val[0] == '0') {
			options->fullduplex = 0;
		} else if (strcmp(val, "full") == 0 || val[0] == '1') {
			options->fullduplex = 1;
		} else {
			nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR, 
			    "%s: Unknown duplex: %s", dev, val);
		}
	} else if (strcmp(name, "mac") == 0) {
		if (val == NULL) {
			nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
			    "%s: Malformed argument: mac", dev);
		} else {
			memset(macstr, 0, sizeof(macstr));
			if (strchr(val, ':') != NULL) {
				j = 0;
				for (i=0; i<strlen(val); i++) {
					if (j < sizeof(macstr) && val[i] != ':') {
						macstr[j] = val[i];
						j++;
					}
				}
			} else {
				memcpy(macstr, val, 12);
			}

			nic_strtomac(macstr, options->mac);
		}
	} else if (strcmp(name, "speed") == 0) {
		if (val == NULL) {
			nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
			    "%s: Malformed argument: speed", dev);
		} else {
			if (strcmp(val, "10") == 0)
				options->speed = 10;
			else if (strcmp(val, "100") == 0)
				options->speed = 100;
			else if (strcmp(val, "1000") == 0)
				options->speed = 1000;
			else
				options->speed = 0;
		}
	} else {
		return -1;
	}

	return 0;
}

int
nic_parse_subopts(void *hdl,
    char *dev, char *args, drvr_subopt_tbl_chain_t *chain)
{
	drvr_subopt_tbl_chain_t	link;
	int			ret;
	char			*op;

	/* Put another link in the chain */
	link.next = chain;
	link.table = NicOptionsTable;
	link.table_size = sizeof(NicOptionsTable) / sizeof(drvr_subopt_tbl_t);
	chain = &link;

	ret = EOK;
	if (args) {
		ret = ENOMEM;
		if ((op = strdup(args)) != NULL) {
			ret = drvr_parse_subopts(hdl, dev, op, chain);
			free(op);
		}
	}

	return(ret);
}

Nic_t *
nic_create_dev(int ext_size)
{
	Nic_t *nic;

	/* allocate nic */
	if ((nic = (Nic_t *)calloc(1, sizeof(Nic_t))) == NULL) {
		nic_slogf(_SLOG_SETCODE(_SLOGC_NETWORK,0), _SLOG_ERROR,
			"Error allocating nic device");
		return(NULL);
	}

	/* allocate nic driver extension */
	if ((nic->ext = (Nic_Ext_t *)calloc(1, ext_size)) == NULL) {
		nic_slogf(_SLOG_SETCODE(_SLOGC_NETWORK,0), _SLOG_ERROR,
			"Error allocating nic device extension");
		free(nic);
		return(NULL);
	}

	nic->flags = NIC_FLAG_MULTICAST;
	return(nic);
}

int
nic_display_config(Nic_t *nic)
{
	int				cnt;
	Config_Info_t	*cfg;

	cfg = &nic->cfg;

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s", cfg->Description);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Vendor .............. 0x%lx", cfg->Device_ID.DevID & 0xffff);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Device .............. 0x%lx", cfg->Device_ID.DevID >> 16);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Revision ............ 0x%lx", cfg->Device_ID.SerialNum);
	for (cnt = 0; cnt < cfg->NumIOPorts; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "I/O port base ....... 0x%lx", cfg->IOPort_Base[cnt]);
	}
	for (cnt = 0; cnt < cfg->NumMemWindows; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Memory base ......... 0x%lx", cfg->MemBase[cnt]);
	}
	for (cnt = 0; cnt < cfg->NumIRQs; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Interrupt ........... 0x%lx", cfg->IRQRegisters[cnt]);
	}
	for (cnt = 0; cnt < cfg->NumDMAs; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "DMA ................. 0x%lx", cfg->DMALst[cnt]);
	}
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "MAC address ......... %04x%02x %02x%04x",
	    (uint16_t)((nic->current_address[0] << 8) | nic->current_address[1]),
	    nic->current_address[2], nic->current_address[3],
	    (uint16_t)((nic->current_address[4] << 8) | nic->current_address[5]));

	return(0);
}

extern char	*nic_drvr_opts[];

int
nic_drvr_options(Nic_t *nic, char *options)
{
	int		opt;
	int		cnt;
	char		*value;

	if ((opt = getsubopt(&options, nic_drvr_opts, &value)) == -1) {
		return(EINVAL);
	}

	if (nic == (Nic_t *)NULL) {
		return(EINVAL);
	}

	if (value == NULL)
		value = "";

	switch (opt) {
		case 0:
			nic->cfg.IOPort_Base[nic->cfg.NumIOPorts] = strtoul(value, 0, 0);
			nic->cfg.NumIOPorts++;
			break;

		case 1:
			nic->cfg.IRQRegisters[nic->cfg.NumIRQs] = strtoul(value, 0, 0);
			nic->cfg.NumIRQs++;
			break;

		case 2:
			nic->cfg.MemBase[nic->cfg.NumMemWindows] = strtoul(value, 0, 0);
			nic->cfg.NumMemWindows++;
			break;

		case 3:
			for (cnt = 0; cnt < MAX_MEM_REGISTERS; cnt++) {
				if (!nic->cfg.MemLength[cnt]) {
					break;
				}
			}
			nic->cfg.MemLength[cnt] = strtoul(value, 0, 0);
			break;

		case 4:
			nic->cfg.DMALst[nic->cfg.NumDMAs]	= strtoul(value, 0, 0);
			nic->cfg.NumDMAs++;
			break;

		case 5:		/* "vid" */
			/* Clear any existing VendorId & fill it in */
			nic->cfg.Device_ID.DevID &= (0xFFFF << 16);
			nic->cfg.Device_ID.DevID |= strtoul(value, 0, 0);
			break;

		case 6:		/* "did" */
			/* Clear any existing DendorId & fill it in */
			nic->cfg.Device_ID.DevID &= 0xFFFF;
			nic->cfg.Device_ID.DevID |= (strtoul(value, 0, 0)<< 16);
			break;

		case 7:		/* "pci" */
			nic->cfg.Device_ID.SerialNum |= strtoul(value, 0, 0);
			break;

		case 8:
			if (nic_strtomac(value, nic->current_address)) {
				nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
				    "%s is an invalid mac address", value);
			}
			break;

		case 9:
			nic->lan = strtoul(value, 0, 0);
			break;

		case 10:
			nic->mtu = strtoul(value, 0, 0);
			break;

		case 11:
			if (strtoul(value, 0, 0)) {
				nic->flags |= NIC_FLAG_FDX;
			}
			break;

		case 12:
			nic->media_rate = strtoul(value, 0, 0);
			nic->media_rate *= 1000;
			break;

		case 13:
			nic->media = strtoul(value, 0, 0);
			break;

		case 14:
			nic->flags &= ~NIC_FLAG_MULTICAST;
			break;

		case 15:
			nic->flags |= NIC_FLAG_PROMISCUOUS;
			break;

		case 16:
			switch(strtoul(value, 0, 0)) {
				case 0:
					nic->flags |= NIC_FLAG_BNC;
					break;
				case 1:
					nic->flags |= NIC_FLAG_UTP;
					break;
				case 2:
					nic->flags |= NIC_FLAG_AUI;
					break;
				case 3:
					nic->flags |= NIC_FLAG_FIBRE;
					break;
			}
			break;

		case 20:
			nic->phy = strtoul(value, 0, 0);
			break;
	}

	return(EOK);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/legacy.c $ $Rev: 703003 $")
#endif
