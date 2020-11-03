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

#ifndef _USB_CONV_H_INCLUDED
#define _USB_CONV_H_INCLUDED

#include <device_qnx.h>
#include <sys/mbuf.h>
#include <pci/pci_conv.h>

#include "../../receive.h"

int usb_qnx_scan(void *dll_hdl, char *drvr, char *options, struct cfattach *ca);

int usb_qnx_to_bsd_status(int status);

struct qnx_usbd_interface;
struct qnx_usbd_pipe;
struct qnx_usbd_xfer;



struct qnx_usbd_pipe {
	struct qnx_usbd_interface	*intf;
	uint32_t			nxfers;
	struct qnx_usbd_xfer		*xfers;
	struct usbd_pipe		*pipe;
	uint8_t				flags;
	uint8_t				address;
};

struct qnx_usbd_device {
	struct usbd_device		*dev;
	uint32_t			nintfs;
	struct qnx_usbd_interface	*intfs;
	uint32_t			curr_conf;
	struct qnx_usbd_pipe		ctrl_pipe;
};

struct qnx_usbd_bus {
	uint32_t			ndevs;
	struct qnx_usbd_device		*devs;
};

struct qnx_usbd_endpoint {
	struct qnx_usbd_interface	*intf;
        usb_endpoint_descriptor_t	bsd_desc;
	usbd_descriptors_t		*qnx_desc;
};

struct qnx_usbd_interface {
	struct qnx_usbd_device		*dev;
	uint32_t			npipes;
	struct qnx_usbd_pipes		*pipes;
	uint32_t			curr_intf;
	struct usbd_desc_node		*node;
	usb_interface_descriptor_t	bsd_desc;
	uint32_t			nendpts;
	struct qnx_usbd_endpoint	*endpts;
};


struct qnx_usbd_xfer {
	struct stk_callback		stk_cb;
	struct usbd_urb			*urb;
	usbd_callback			callback;
	void				*priv;
	uint32_t			timeout;
	uint32_t			length;
	void				*buffer;
        struct qnx_usbd_pipe		*pipe;
	uint32_t			flags;
	unsigned			refcnt;
	void				*buf_usbd;
};



#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/usb/usb_conv.h $ $Rev: 680336 $")
#endif
