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





#include <ctype.h>
#include <sys/slog.h>
#include <sys/slogcodes.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/syspage.h>
#include <net/if_types.h>
#include <net/if_ether.h>
#include <hw/sysinfo.h>
#include <netdrvr/nicsupport.h>
#include <dlfcn.h>


struct nw_work_thread;

/* nic_slogf Initialization */
static void (*vlogp)(int level, const char *fmt, va_list ap);
static struct nw_work_thread *(*nw_thread_istrackedp)(void);
static pthread_once_t once_control = PTHREAD_ONCE_INIT;

#define hexval(x) (isalpha(x) ? 10 + toupper(x) - 'A' : (x) - '0')

int
nic_strtomac(const char *s, unsigned char *mac)
{
	int	i;
	
	for (i = 0; i < 6; i++) {
		unsigned char val= 0;
		while(isspace(*s)) ++s;
		if (!*s || !*(s + 1) || !isxdigit(*s) || !isxdigit(*(s + 1))) {
			return(1);
		}
		val= 0x10 * hexval(*s) + hexval(*(s + 1));
		s += 2;
		mac[i]= val;
	}

	return(0);
}

char *nic_drvr_opts[] = {
#define NICOPT_IOPORT		0
	"ioport",
#define NICOPT_IRQ		1
	"irq",
#define NICOPT_SMEM		2
	"smem",
#define NICOPT_SMEMSZ		3
	"smemsz",
#define NICOPT_DMA		4
	"dma",
#define NICOPT_VID		5
	"vid",
#define NICOPT_DID		6
	"did",
#define NICOPT_PCI		7
	"pci",
#define NICOPT_MAC		8
	"mac",
#define NICOPT_LAN		9
	"lan",
#define NICOPT_MTU		10
	"mtu",
#define NICOPT_DUPLEX		11
	"duplex",
#define NICOPT_SPEED		12
	"speed",
#define NICOPT_MEDIA		13
	"media",
#define NICOPT_NOMULTICAST	14
	"nomulticast",
#define NICOPT_PROMISCUOUS	15
	"promiscuous",
#define NICOPT_CONNECTOR	16
	"connector",
#define NICOPT_DEVICEINDEX	17
	"deviceindex",
#define NICOPT_PHY		18
	"phy",
#define NICOPT_MEMRANGE		19
	"memrange",
#define NICOPT_IORANGE		20
	"iorange",
#define NICOPT_VERBOSE		21
	"verbose",
#define NICOPT_IFTYPE		22
	"iftype",
#define NICOPT_UPTYPE		23
	"uptype",
#define NICOPT_MRU		24
	"mru",
#define NICOPT_PRIORITY		25
	"priority",
#define NICOPT_UNIT		26
	"unit",
#define NICOPT_NAME		27
	"name",

	NULL
};

/*
 * This is the function for parsing "standard" options, which have a
 * well-defined meaning and are consistent across network drivers.
 */
int
nic_parse_options(nic_config_t *cfg, char *option)
{
	int		opt;
	int		cnt;
	char		*value;

	if (option == NULL)
		return EINVAL;

	if ((opt = getsubopt(&option, nic_drvr_opts, &value)) == -1)
		return EINVAL;

	if (value == NULL) {
		switch (opt) {
			case NICOPT_IOPORT:
			case NICOPT_IRQ:
			case NICOPT_SMEM:
			case NICOPT_SMEMSZ:
			case NICOPT_DMA:
			case NICOPT_VID:
			case NICOPT_DID:
			case NICOPT_PCI:
			case NICOPT_MAC:
			case NICOPT_LAN:
			case NICOPT_UNIT:
			case NICOPT_NAME:
			case NICOPT_MTU:
			case NICOPT_DUPLEX:
			case NICOPT_SPEED:
			case NICOPT_MEDIA:
			case NICOPT_CONNECTOR:
			case NICOPT_DEVICEINDEX:
			case NICOPT_PHY:
			case NICOPT_MEMRANGE:
			case NICOPT_IORANGE:
			case NICOPT_MRU:
			case NICOPT_PRIORITY:
			case NICOPT_UPTYPE:
			case NICOPT_IFTYPE:
				nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
				    "Option %s requires an argument", option);
				return EINVAL;
		}
	}

	switch (opt) {
		case NICOPT_IOPORT:
			cfg->io_window_base[cfg->num_io_windows] =
			    strtoul(value, 0, 0);
			cfg->num_io_windows++;
			break;
		case NICOPT_IRQ:
			cfg->irq[cfg->num_irqs] = strtoul(value, 0, 0);
			cfg->num_irqs++;
			break;
		case NICOPT_SMEM:
			cfg->mem_window_base[cfg->num_mem_windows] =
			    strtoul(value, 0, 0);
			cfg->num_mem_windows++;
			break;
		case NICOPT_SMEMSZ:
			for (cnt = 0; cnt < sizeof(cfg->mem_window_base) /
			    sizeof(cfg->mem_window_base[0]); cnt++) {
				if (!cfg->mem_window_size[cnt]) {
					break;
				}
			}
			cfg->mem_window_size[cnt] = strtoul(value, 0, 0);
			break;
		case NICOPT_DMA:
			cfg->dma_channel[cfg->num_dma_channels] =
			    strtoul(value, 0, 0);
			cfg->num_dma_channels++;
			break;
		case NICOPT_VID:
			/* Clear any existing VendorId & fill it in */
			cfg->vendor_id = strtoul(value, 0, 0);
			break;
		case NICOPT_DID:
			cfg->device_id = strtoul(value, 0, 0);
			break;
		case NICOPT_PCI:
			cfg->device_index = strtoul(value, 0, 0);
			break;
		case NICOPT_MAC:
			if (nic_strtomac(value, cfg->current_address)) {
				nic_slogf(_SLOGC_NETWORK, _SLOG_ERROR,
				    "%s is an invalid mac address", value);
				return EINVAL;
			}
			break;
		case NICOPT_LAN:
		case NICOPT_UNIT:
			cfg->lan = strtol(value, 0, 0);
			break;
		case NICOPT_MTU:
			cfg->mtu = strtoul(value, 0, 0);
			break;
		case NICOPT_DUPLEX:
			cfg->duplex = strtoul(value, 0, 0);
			break;
		case NICOPT_SPEED:
			cfg->media_rate = strtoul(value, 0, 0) * 1000;
			break;
		case NICOPT_MEDIA:
			cfg->media = strtoul(value, 0, 0);
			break;
		case NICOPT_NOMULTICAST:
			cfg->flags &= ~NIC_FLAG_MULTICAST;
			break;
		case NICOPT_PROMISCUOUS:
			cfg->flags |= NIC_FLAG_PROMISCUOUS;
			break;
		case NICOPT_CONNECTOR:
			cfg->connector = strtoul(value, 0, 0);
			break;
		case NICOPT_DEVICEINDEX:
			cfg->device_index = strtoul(value, 0, 0);
			break;
		case NICOPT_PHY:
			cfg->phy_addr = strtoul(value, 0, 0);
			break;
		case NICOPT_MEMRANGE:
			cfg->mem_window_base[cfg->num_mem_windows] =
			    strtoul(value, &value, 0);
			if (value != NULL && *value == ':')
				cfg->mem_window_size[cfg->num_mem_windows] =
				    strtoul(value+1, 0, 0);
			cfg->num_mem_windows++;
			break;
		case NICOPT_IORANGE:
			cfg->io_window_base[cfg->num_io_windows] =
			    strtoul(value, &value, 0);
			if (value != NULL && *value == ':')
				cfg->io_window_size[cfg->num_io_windows] =
				    strtoul(value+1, 0, 0);
			cfg->num_io_windows++;
			break;
		case NICOPT_VERBOSE:
			if (value)
				cfg->verbose = strtoul(value, 0, 0);
			else
				cfg->verbose++;
			break;
		case NICOPT_MRU:
			cfg->mru = strtoul(value, 0, 0);
			break;
		case NICOPT_PRIORITY:
			cfg->priority = strtol(value, 0, 0);
			break;
		case NICOPT_UPTYPE:
			strncpy((char *)cfg->uptype, value, sizeof (cfg->uptype) - 1);
			break;
		case NICOPT_IFTYPE:
			cfg->iftype = strtol(value, 0, 0);
			break;
		case NICOPT_NAME:
			/* Don't have to do anything.  This is handled by dev_attach in the stack. */
			break;
		default:
			return EINVAL;
	}

	return EOK;
}


int	
nic_get_syspage_mac(char *mac)
{
	unsigned	start;
	struct		hwi_nicaddr *tag;

	if ((start = hwi_find_item (HWI_NULL_OFF, "network", NULL)) == HWI_NULL_OFF)
		return (-1);
		
	if ((start = hwi_find_tag(start,0,"nicaddr")) == HWI_NULL_OFF)
		return (-1);

	tag = hwi_off2tag (start);
	memcpy(mac,tag->addr,6);
	return (0);
}

void
nic_dump_config(nic_config_t *cfg)
{
	int	cnt;

	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "%s", cfg->device_description);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Vendor .............. 0x%x", cfg->vendor_id);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Device .............. 0x%x", cfg->device_id);
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Revision ............ 0x%x", cfg->device_revision);
	for (cnt = 0; cnt < cfg->num_io_windows; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "I/O port base ....... 0x%llx", cfg->io_window_base[cnt]);
	}
	for (cnt = 0; cnt < cfg->num_mem_windows; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Memory base ......... 0x%llx", cfg->mem_window_base[cnt]);
	}
	for (cnt = 0; cnt < cfg->num_irqs; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "Interrupt ........... 0x%x", cfg->irq[cnt]);
	}
	for (cnt = 0; cnt < cfg->num_dma_channels; cnt++) {
		nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "DMA ................. 0x%x", cfg->dma_channel[cnt]);
	}
	nic_slogf(_SLOGC_NETWORK, _SLOG_INFO, "MAC address ......... %02x%02x%02x %02x%02x%02x",
	    cfg->current_address[0], cfg->current_address[1],
	    cfg->current_address[2], cfg->current_address[3],
	    cfg->current_address[4], cfg->current_address[5]);
}

int
nic_ether_mcast_valid(struct _io_net_msg_mcast *mcast)
{
	if (mcast->mc_min.addr_dl.sdl_len != sizeof (struct sockaddr_dl) ||
	    mcast->mc_min.addr_dl.sdl_family != AF_LINK ||
	    mcast->mc_min.addr_dl.sdl_type != IFT_ETHER ||
	    mcast->mc_max.addr_dl.sdl_type != IFT_ETHER ||
	    mcast->mc_min.addr_dl.sdl_nlen != 0 ||
	    mcast->mc_max.addr_dl.sdl_nlen != 0 ||
	    mcast->mc_min.addr_dl.sdl_alen != 6 ||
	    mcast->mc_max.addr_dl.sdl_alen != 6 ||
	    ETHER_IS_MULTICAST(LLADDR(&mcast->mc_min.addr_dl)) == 0 ||
	    ETHER_IS_MULTICAST(LLADDR(&mcast->mc_max.addr_dl)) == 0)
		return -1;

	return 0;
}

static void nic_slogf_do_once(void)
{
	void *hdl;

        /*
         * dlopen(NULL) shouldn't go over the network
         * so we don't have to worry about blockop etc..
         */
        if ((hdl = dlopen(NULL, RTLD_WORLD)) == NULL ||
            (vlogp = dlsym(hdl, "vlog")) == NULL ||
            (nw_thread_istrackedp =
             dlsym(hdl, "nw_thread_istracked")) == NULL) {
                vlogp = (void *)-1;
                nw_thread_istrackedp = (void *)-1;
        }

        if (hdl != NULL)
                dlclose(hdl);
}	


int
nic_slogf(int opcode, int level, const char *fmt, ...)
{
	va_list				ap;
	int				ret;

	pthread_once(&once_control, nic_slogf_do_once);

	va_start(ap, fmt);

	if (vlogp == (void *)-1 ||		/* io-net */
	    (*nw_thread_istrackedp)() == NULL	/* not stack thread */
	    ) {
		ret = vslogf(opcode, level, fmt, ap);
	}
	else {
		/*
		 * Convert slog level to similar syslog level.
		 * slog has 2 debug, syslog has an extra LOG_ALERT.
		 */
		if (level > 1)
		        level++;

		(*vlogp)(level, fmt, ap);
		ret = 1; /* no one check this right ? */
	}
	va_end(ap);
	return ret;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnetdrvr/nic.c $ $Rev: 822252 $")
#endif
