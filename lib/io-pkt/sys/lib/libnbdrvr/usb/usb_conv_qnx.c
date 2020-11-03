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


#include <assert.h>

#include <sys/malloc.h>
#include <sys/syslog.h>
#include <sys/usbdi.h>
#include <sys/device.h>
#include <sys/systm.h>
#include <sys/kthread.h>
#include <sys/neutrino.h>

#include <stdio.h>
#include <stdlib.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>

#undef usbd_status
#undef usbd_open_pipe
#undef usbd_close_pipe
#undef usbd_abort_pipe
                    
#include <usb/usb_conv.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/file_bsd.h>

static TAILQ_HEAD(, usb_task) usb_all_tasks = TAILQ_HEAD_INITIALIZER(usb_all_tasks);

typedef struct bsd_qnx_usb_extra {
	int	current_config;
} bsd_qnx_usb_extra;


/* Maintain a single connection to the USB stack per dll. */
static struct usbd_connection *usb_connection;
static volatile unsigned int usb_refcnt;

/* Device prefix being handled by this copy of the library. */
#define NAME_SIZE 31
static void	*dll_id;

#define MAX_USB_TIMEOUT 4000

#define USB_IDENT_STRING	"IS_A_USB_DEVICE"

struct usb_attach_arg_ex {
	char 						ident[16];
	struct usb_attach_arg		uua;
	struct qnx_usbd_device		device;
	usbd_device_instance_t 		instance;
	void						*dll_id;
};

 
static void usb_bus_detach(void *);
static void dofree(usbd_xfer_handle);
static int errno_to_status(int);
static int internal_disconnect(struct usbd_connection *conn);


static int usb_task_run;


static char *dev_opts[] = {
#define DEVOPT_DID 0
	"did",
#define DEVOPT_VID 1
	"vid",
#define DEVOPT_DEV 2
	"devno",
#define DEVOPT_BUS 3
	"busno",
	NULL
};


/* This routine must be run in the stack context in order to be able to use
the wakeup call to stop the USB task from running. */

static void stack_remove(void * arg)
{
	struct device *dev = arg;

	if (usb_refcnt == 1) {
		int s;

		/* This detach is going to result in the dll being unloaded
		when completed. Stop the usb co-routine from executing. */
		usb_task_run = 0;
		s = splusb();
		wakeup(&usb_all_tasks);
		splx(s);
	}

	/* Note that we can't call the detach directly from here since that would
	result in an attempt to run code in this DLL after it's been unloaded. */
	dev_remove(dev);
}


static void
usb_remove(struct usbd_connection *connection, usbd_device_instance_t *inst)
{
	struct device	*dev;
	struct usb_attach_arg_ex *uua_ex;
	usbd_device_instance_t *dev_inst;

	if (usb_refcnt == 0) {
		/* No device is using this DLL, so don't do anything. */
		return;
	}

	TAILQ_FOREACH(dev, &alldevs, dv_list) {
		uua_ex = dev->dv_bus_hdl;
		if (uua_ex == NULL) {
			continue;
		}

		if (strcmp(USB_IDENT_STRING, uua_ex->ident)) {
			/* Not a USB device. */
			continue;
		}

		dev_inst = &uua_ex->instance;

		if ((inst->path == dev_inst->path) && 
			(inst->devno == dev_inst->devno) &&
			(inst->ident.vendor == dev_inst->ident.vendor) &&
			(inst->ident.device == dev_inst->ident.device) &&
			(inst->iface == dev_inst->iface)) {

			/* Will get removal events from devices "owned" by
			other DLLs, so need to check that the device
			being removed is associated with this DLL. */
			if (dll_id == uua_ex->dll_id) {
				/* Must run the remove in the stack context.  This
				routine is run in a thread created by the USB library. */
				dev->dv_callback.func = stack_remove;
				dev->dv_callback.arg = dev;
				stk_context_callback(&dev->dv_callback);
			}
			return;
		}
	}

}


int
usb_qnx_scan(void *dll_hdl, char *drvr, char *optstring, struct cfattach *ca)
{
	usbd_device_instance_t 		*instance;
	struct qnx_usbd_device		*device;
	struct usb_attach_arg_ex	*uua_ex;
	struct usb_attach_arg		*uua;
	int				err, single;
	uint32_t			busno, bus_start=0, bus_end=9;
	uint32_t			devno, dev_start=0, dev_end=127;
	struct device			*dev;
	uint32_t			vendor_id = 0xffffffff;
	uint32_t			device_id = 0xffffffff;
	char				*opt_p = NULL;

 
	usbd_device_ident_t 	ident = {
		USBD_CONNECT_WILDCARD,
		USBD_CONNECT_WILDCARD,
		USBD_CONNECT_WILDCARD,
		USBD_CONNECT_WILDCARD,
		USBD_CONNECT_WILDCARD
	};

	usbd_funcs_t			funcs = {
		_USBDI_NFUNCS,
		NULL,
		usb_remove,
		NULL,
	};

	usbd_connect_parm_t		parm = {
		NULL,
		USB_VERSION,
		USBD_VERSION,
		0,
		0,
		NULL,
		0,
		&ident,
		&funcs,
		0
	};

	single = 0;
	uua_ex = NULL;


	/* Parse device options */
	if (optstring != NULL && *optstring != '\0') {
		opt_p = malloc(strlen(optstring)+1, M_TEMP, M_NOWAIT);
		if (opt_p == NULL) {
			return(ENOMEM);
		}
		strcpy(opt_p, optstring);
	}

	if (opt_p != NULL) {
		char *curr;
		char *last;

		curr = opt_p;
		last = curr;
		while (*curr != '\0') {
			char		*value;
			char 		*restore;
			int 		consume;
			int 		opt;

			consume = 1;
			restore = strchr(curr,',');
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
			case DEVOPT_DEV: /* For backwards compatibility. */
				if (value != NULL) {
					dev_end = dev_start = strtol(value, NULL, 0);
				}
				break;
			case DEVOPT_BUS: /* For backwards compatibility. */
				if (value != NULL) {
					bus_end = bus_start = strtol(value, NULL, 0);
				}
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

			} else if (restore != NULL) {
				*restore = ',';
			}

			last = curr;
		}

	}

	if (device_id == -1 && vendor_id != -1) {
		printf("Can't specify USB vendor ID without also specifying the product ID\n");
		/* Note that opt_pt must be non-null if one of the ids has been specified. */
		free(opt_p, M_TEMP);		
		return(EINVAL);
	}
	if (device_id != -1 && vendor_id == -1) {
		printf("Can't specify USB product ID without also specifying the vendor ID\n");
		/* Note that opt_pt must be non-null if one of the ids has been specified. */
		free(opt_p, M_TEMP);
		return(EINVAL);		
	}

	if (usb_connection == NULL) {
		/* Each DLL data section is loaded into different memory area.  By
		taking address of self, this will uniquely identify the DLL that this
		code is in. */
		dll_id = &dll_id;
		if ((err = usbd_connect(&parm, &usb_connection)) != EOK) {
			if (opt_p != NULL) {
				free(opt_p, M_TEMP);
			}
			return err;
		}
	}

	err = ENXIO;
	/*
	 * Scan USB devices, checking for driver match or override
	 * options match. The bus / device number can also be 
	 * specified which reduces the scan loops to a single pass.
	 *
	 * Apparently, we support up to 10 buses (0 to 9).
	 */
	for (busno = bus_start; busno <= bus_end; busno++) {
		for (devno = dev_start; devno <= dev_end; ++devno) {

			if ((uua_ex == NULL) && 
			    ((uua_ex = malloc(sizeof(*uua_ex), M_DEVBUF,M_NOWAIT | M_ZERO))
			    == NULL) ) {

				err = ENOMEM;
				goto out;
			}
			uua = &uua_ex->uua;
			strcpy(uua_ex->ident,USB_IDENT_STRING);
			device = &uua_ex->device;
			instance = &uua_ex->instance;
			memset(instance, USBD_CONNECT_WILDCARD,
			    sizeof(usbd_device_instance_t));
			instance->path = busno;
			instance->devno = devno;
			device->dev = NULL;
			if (usbd_attach(usb_connection, instance, 0,
			    &device->dev) != EOK)
				continue;
			/*
			 * Only matching what we need for now (may need
			 * more details for other drivers)
			 */
			uua->vendor = instance->ident.vendor;
			uua->product = instance->ident.device;

			if((vendor_id == 0xffffffff) || (device_id == 0xffffffff)) {
				if (ca->ca_match(NULL, NULL, uua) == 0) {
					usbd_detach(device->dev);
					continue;
				}
			} else {
				if ((vendor_id != uua->vendor) || 
					(device_id != uua->product)) {
					usbd_detach(device->dev);
					continue;
				}
			}
			/* We've found a match */
			printf("USB device vendor 0x%x, device 0x%x matched.\n", 
				instance->ident.vendor,
			    instance->ident.device);

			usbd_reset_device(device->dev);
			uua->device = device;
			uua_ex->dll_id = dll_id;
			dev = NULL; /* NULL == no parent */
			if ((err = dev_attach(drvr, opt_p, ca, uua, &single,
			    &dev, pci_bsd_print)) == EOK) {
				usb_refcnt++;
				dev->dv_dll_hdl = dll_hdl;
				dev->dv_bus_hdl = uua_ex;
				dev->dv_bus_detach = usb_bus_detach;
				uua_ex = NULL;
				uua = NULL;
				device = NULL;
			}
			else {
				usbd_detach(device->dev);
			}

			if (single)
				break;
		}
	}
out:
	if (uua_ex != NULL) {
		free(uua_ex, M_DEVBUF);
	}

	if (opt_p != NULL) {
		free(opt_p, M_TEMP);
	}

	/* It at least one succeeded, indicate success */
	if (usb_refcnt > 0) {
		return EOK;
	} else {
		/* No devices mounted.  Remove the USB connection. */
		internal_disconnect(usb_connection);
		usb_connection = NULL;
	}
	return err;
}



static void
usb_bus_detach(void *arg)
{
	struct usb_attach_arg_ex	*uua_ex;

	uua_ex = arg;
	usbd_detach(uua_ex->device.dev);
	if (--usb_refcnt == 0 && usb_connection != NULL) {
		internal_disconnect(usb_connection);
		usb_connection = NULL;
	}
	free(uua_ex, M_DEVBUF);
}

static int
internal_disconnect(struct usbd_connection *conn)
{
#if _NTO_VERSION >= 640 
	return usbd_disconnect(usb_connection);
#else /* PR 55482 */
	pthread_t	tid;
	int		ret, err, i;

	tid = *(pthread_t *)((uintptr_t)conn + 0x34);
	ret = usbd_disconnect(usb_connection);
	for (i = 20; i > 0; i--) {
		err = pthread_kill(tid, 0);
		if (err == ESRCH)
			break;

		if (err == EOK) {
			delay(100);
		}
		else {
			log(LOG_ERR, "usb disconnect: %d", err);
			break;
		}
	}
	if (i == 0)
		log(LOG_ERR, "usb disconnect: thread won't exit?");
	return ret;
#endif
}

static void
usb_handle_error(usbd_xfer_handle xfer, int status)
{
	usbd_pipe_handle	pipe;
	struct usbd_pipe	*upipe;

	pipe = xfer->pipe;
	if (pipe == NULL || (upipe = pipe->pipe) == NULL) {
		return;
	}

	if (((status & USBD_URB_STATUS_MASK) == USBD_STATUS_CMP) || 
		((status & USBD_URB_STATUS_MASK) == USBD_STATUS_INPROG) ) {
		return;
	}

	if ((status & USBD_USB_STATUS_MASK) == USBD_STATUS_STALL) {
		usbd_reset_pipe(upipe);
	} else {
		static int last_err;
		static int last_err_cnt;

		if (last_err != status) {
			last_err = status;
			last_err_cnt = 0;
		}
		/* You can end up with a burst of errors with the same status.  This provides
		the error information without polluting the logs. */
		if ((last_err_cnt++ % 20) == 0) {
			printf("USB error 0x%08x encountered  in io-pkt. \n", status);
		}
		usbd_abort_pipe(upipe);
		delay(250);
	}		
}


int
usb_qnx_to_bsd_status(int status)
{
	switch (status & USBD_URB_STATUS_MASK) {
	case USBD_STATUS_INPROG:
		return USBD_IN_PROGRESS;
	case USBD_STATUS_CMP:
		return USBD_NORMAL_COMPLETION;
	case USBD_STATUS_CMP_ERR:
		/* Start looking at USBD_USB_STATUS_MASK bits below */
		break;
	case USBD_STATUS_TIMEOUT:
		return USBD_TIMEOUT;
	case USBD_STATUS_ABORTED:
		return USBD_CANCELLED;
	default:
		/* Should always have a flag set, but just in case... */
		break;

	}

	switch (status & USBD_USB_STATUS_MASK) {
	case 0:
		/* We shouldn't get here, but it's best to have a safety. */
		/* Sending normal completion will result in the driver cleaning
		up the buffers and continuing on which may mean a lost packet,
		but that's preferable to doing nothing. */
		status = USBD_NORMAL_COMPLETION;
		break;
	case USBD_STATUS_STALL:
		status = USBD_STALLED;
		break;
	case USBD_STATUS_DEV_NOANSWER:
	case USBD_STATUS_PID_FAILURE:
	case USBD_STATUS_BAD_PID:
	case USBD_STATUS_DATA_OVERRUN:
	case USBD_STATUS_DATA_UNDERRUN:
	case USBD_STATUS_BUFFER_OVERRUN:
	case USBD_STATUS_BUFFER_UNDERRUN:
	case USBD_STATUS_NOT_ACCESSED:
	case USBD_STATUS_CRC_ERR:
	case USBD_STATUS_BITSTUFFING:
	case USBD_STATUS_TOGGLE_MISMATCH:
	default:
		status = USBD_ERROR_MAX + (status & USBD_USB_STATUS_MASK);
		break;
	}


	return status;
}

#if 1
usbd_status_bsd
usbd_set_config_no(usbd_device_handle dev, int no, int msg)
{
	int				error;
	usbd_device_descriptor_t	*dev_desc;

	error = usbd_select_config(dev->dev, no);
	if (error)
		return (USBD_INVAL);

	dev_desc = usbd_device_descriptor(dev->dev, NULL); 
	assert(dev_desc != NULL);

	/* Open a control pipe */
	error = usbd_open_pipe(dev->dev, (usbd_descriptors_t *)dev_desc,
	    &dev->ctrl_pipe.pipe);

	dev->curr_conf = no;

	return USBD_NORMAL_COMPLETION;
}

#else
usbd_status_bsd
usbd_set_config_no(usbd_device_handle dev, int no, int msg)
{
	int				error, i;
	usbd_descriptors_t		*desc;
	struct usbd_desc_node		*ifc, *ept;

	error = usbd_select_config(dev->dev, no);
	if (error)
		return USBD_INVAL;

	/* Open a control pipe */
	if (dev->ctrl_pipe == NULL) {
		/* Attach to configuration 1, interface 0 */
		if (usbd_interface_descriptor(dev->dev, 1, 0, 0, &ifc) == NULL)
			return USBD_INVAL;
		for (i = 0;
		    (desc = usbd_parse_descriptors(dev->dev, ifc, USB_DESC_ENDPOINT,
		    i, &ept)) != NULL;
		    i++) {
			if (desc->endpoint.bmAttributes == USB_ATTRIB_CONTROL) {
				if (usbd_open_pipe(dev->dev, desc, &dev->ctrl_pipe) != EOK ) {
					dev->ctrl_pipe = NULL;
					return USBD_INVAL;
				}
			}
		}
	}

	dev->curr_conf = no;

	return USBD_NORMAL_COMPLETION;
}
#endif

void
usbd_get_xfer_status(usbd_xfer_handle xfer, usbd_private_handle *priv,
		     void **buffer, u_int32_t *count, usbd_status_bsd *status)
{
	/* TODO */
	usbd_urb_status(xfer->urb, (_Uint32t *)status, count);
	if (status != NULL) {
		*status = usb_qnx_to_bsd_status(*status);
	}
}

usbd_status_bsd
usbd_clear_endpoint_stall_async(usbd_pipe_handle pipe)
{
	return usbd_reset_pipe(pipe->pipe);
}

static void
stack_urb_callback(void *arg)
{
	uint32_t		status = 0, length;
	usbd_xfer_handle	xfer;
	usbd_pipe_handle	pipe;
	struct usbd_pipe	*upipe;

	xfer = arg;

	pipe = xfer->pipe;
	if (pipe == NULL || (upipe = pipe->pipe) == NULL) {
		/*
		 * Because we have an extra level of indirection (i.e. usb
		 * callback sends a pulse to stack, but another message may be
		 * services in between, possibly shutting down the usb network
		 * device) we need to make sure the interface is still up
		 */
		status = USBD_STATUS_ABORTED;
	}
	else {
		usbd_urb_status(xfer->urb, &status, &length);

		if ((status & USBD_URB_STATUS_MASK) != USBD_STATUS_CMP) {
			usb_handle_error(xfer,status);
		}
		else {
			if ((xfer->flags & USBD_NO_COPY) == 0 &&
			    (pipe->address & UE_DIR_IN)) {
				memcpy(xfer->buffer, xfer->buf_usbd, length);
			}
		}
	}

	status = usb_qnx_to_bsd_status(status);

	if (xfer->flags & USBD_SYNCHRONOUS) {
		wakeup(xfer);
	}

	if (xfer->callback != NULL) {
		xfer->callback(xfer, xfer->priv, status);
	}

	if (cpu_atomic_dec_value(&xfer->refcnt) == 1) {
		dofree(xfer);
	}
}

static void
urb_callback(struct usbd_urb *urb, struct usbd_pipe *pipe, void *arg)
{
	usbd_xfer_handle	xfer = arg;

	if (!usb_task_run) {
		/* Don't do any callbacks if we're disconnecting from the USB
		stack.  */
		return;
	}
	xfer->stk_cb.func = stack_urb_callback;
	xfer->stk_cb.arg = xfer;
	stk_context_callback(&xfer->stk_cb);
}


void
usbd_devinfo_free(char *devinfop)
{
	free(devinfop, M_TEMP);
}

usbd_status_bsd
usbd_free_xfer(usbd_xfer_handle xfer)
{
	if (cpu_atomic_dec_value(&xfer->refcnt) == 1)
		dofree(xfer);
	return (USBD_NORMAL_COMPLETION);
}

static void
dofree(usbd_xfer_handle xfer)
{
	if (xfer->buf_usbd != NULL) {
		usbd_free(xfer->buf_usbd);
		xfer->buf_usbd = NULL;
	}
	usbd_free_urb(xfer->urb);
	free(xfer, M_DEVBUF);
}

usbd_status_bsd
usbd_device2interface_handle(usbd_device_handle dev,
			     u_int8_t ifaceno, usbd_interface_handle *iface)
{
	dev->intfs = malloc(sizeof(struct qnx_usbd_interface), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (dev->intfs == NULL)
		return ENOMEM;

	dev->nintfs = 1;
	dev->intfs->dev = dev;
        dev->intfs->curr_intf = ifaceno;

	*iface = dev->intfs;

	return EOK;
}

void
usbd_add_drv_event(int type, usbd_device_handle udev, device_ptr_t dev)
{
#if 0
	struct usb_event ue;

	ue.u.ue_driver.ue_cookie = udev->cookie;
	strncpy(ue.u.ue_driver.ue_devname, USBDEVPTRNAME(dev),
	    sizeof ue.u.ue_driver.ue_devname);
	usb_add_event(type, &ue);
#endif
}

static void
qnx_to_bsd_idesc(usb_interface_descriptor_t *bsd, usbd_interface_descriptor_t *qnx)
{
	bsd->bLength		= qnx->bLength;
	bsd->bDescriptorType	= qnx->bDescriptorType;
	bsd->bInterfaceNumber	= qnx->bInterfaceNumber;
	bsd->bAlternateSetting	= qnx->bAlternateSetting;
	bsd->bNumEndpoints	= qnx->bNumEndpoints + 1;
	bsd->bInterfaceClass	= qnx->bInterfaceClass;
	bsd->bInterfaceSubClass	= qnx->bInterfaceSubClass;
	bsd->bInterfaceProtocol	= qnx->bInterfaceProtocol;
	bsd->iInterface 	= qnx->iInterface;
}

usb_interface_descriptor_t *
usbd_get_interface_descriptor(usbd_interface_handle iface)
{
	usbd_interface_descriptor_t	*idesc;

	idesc = usbd_interface_descriptor(iface->dev->dev,
	    iface->dev->curr_conf, iface->curr_intf, 0, &iface->node);
	assert(idesc != NULL);

	qnx_to_bsd_idesc(&iface->bsd_desc, idesc);
	return &iface->bsd_desc;
}

static const char * const usbd_error_strs[] = {
	"NORMAL_COMPLETION",
	"IN_PROGRESS",
	"PENDING_REQUESTS",
	"NOT_STARTED",
	"INVAL",
	"NOMEM",
	"CANCELLED",
	"BAD_ADDRESS",
	"IN_USE",
	"NO_ADDR",
	"SET_ADDR_FAILED",
	"NO_POWER",
	"TOO_DEEP",
	"IOERROR",
	"NOT_CONFIGURED",
	"TIMEOUT",
	"SHORT_XFER",
	"STALLED",
	"INTERRUPTED",
	"XXX",
};

const char *
usbd_errstr(usbd_status_bsd err)
{
	static char buffer[5];

	if (err < USBD_ERROR_MAX) {
		return usbd_error_strs[err];
	} else {
		snprintf(buffer, sizeof buffer, "%d", err);
		return buffer;
	}
        return "";
}


static void
usb_task_thread(void * arg)
{
	struct usb_task		*task;
	int			s;
	struct nw_stk_ctl	*sctlp;

	sctlp = arg;

	s = splusb();
	while (usb_task_run) {
		task = TAILQ_FIRST(&usb_all_tasks);
		if (task == NULL) {
			tsleep(&usb_all_tasks, PWAIT, "usbtsk", 0);
			task = TAILQ_FIRST(&usb_all_tasks);
		}
		if (task != NULL) {
			TAILQ_REMOVE(&usb_all_tasks, task, next);
			task->queue = -1;
			splx(s);
			task->fun(task->arg);
			s = splusb();
		}
	}
	kthread_exit(0);
}




void
usb_init_task(struct usb_task *task, void (*fun)(void *), void *arg)
{
	static int done = 0;

	if (!done) {
		/* TODO nto allocate new proc */
		if (kthread_create1(usb_task_thread, &stk_ctl, NULL,
		    "USB thread") != EOK) {
			log(LOG_ERR, "unable to create usb tack thread");
		}
		else {
			done = 1;
			usb_task_run = 1;
		}
	}

	task->fun = fun;
	task->arg = arg;
	task->queue = -1;
}


/*
 * Add a task to be performed by the task thread.  This function can be
 * called from any context and the task will be executed in a process
 * context ASAP.
 */
void
usb_add_task(usbd_device_handle dev, struct usb_task *task, int queue)
{
	/* XXX queue */
	int s;

	if (!usb_task_run) {
		return;
	}

	s = splusb();
	if (task->queue == -1) {
		TAILQ_INSERT_TAIL(&usb_all_tasks, task, next);
		task->queue = 1;
	} else {
	}
	wakeup(&usb_all_tasks);
	splx(s);

}

void
usb_rem_task(usbd_device_handle dev, struct usb_task *task)
{
	int s;

	s = splusb();
	if (task->queue != -1) {
		TAILQ_REMOVE(&usb_all_tasks, task, next);
		task->queue = -1;
	}
	splx(s);
}

void *
usbd_alloc_buffer(usbd_xfer_handle xfer, u_int32_t size)
{
	if (xfer->buf_usbd != NULL)
		printf("usbd_alloc_buffer: already\n"); /* shouldn't happen */
	else
		xfer->buf_usbd = usbd_alloc(size);
	return xfer->buf_usbd;
}

void
usbd_setup_xfer(usbd_xfer_handle xfer, usbd_pipe_handle pipe,
		usbd_private_handle priv, void *buffer, u_int32_t length,
		u_int16_t flags, u_int32_t timeout,
		usbd_callback callback)
{

	xfer->callback = callback;
	xfer->length = length;
	xfer->buffer = buffer;
	xfer->priv = priv;
	xfer->pipe = pipe;
	xfer->flags = flags;

	if (timeout == 0)
		xfer->timeout = MAX_USB_TIMEOUT;
	else 
		xfer->timeout = timeout;

}


void
usbd_setup_default_xfer(usbd_xfer_handle xfer, usbd_device_handle dev,
			usbd_private_handle priv, u_int32_t timeout,
			usb_device_request_t *req, void *buffer,
			u_int32_t length, u_int16_t flags,
			usbd_callback callback)
{
	xfer->pipe = &dev->ctrl_pipe; /* ctrl pipe is the default in NetBSD */
	xfer->priv = priv;
	xfer->buffer = buffer;
	xfer->length = length;
	xfer->flags = flags;
	xfer->timeout = timeout;
	xfer->callback = callback;
#ifndef __QNXNTO__
	xfer->actlen = 0;
	xfer->status = USBD_NOT_STARTED;
	xfer->request = *req;
	xfer->rqflags |= URQ_REQUEST;
	xfer->nframes = 0;
#endif
}

usbd_status_bsd
usbd_transfer(usbd_xfer_handle xfer)
{
	int			err;
	usbd_pipe_handle	pipe;
	uint32_t		flags, qnxflags, status = 0, len;

	if (xfer->buf_usbd == NULL) {
		/* Don't currently support auto alloc / free */
		return EOPNOTSUPP;
	}

	if ((pipe = xfer->pipe) == NULL)
		return EAGAIN;

	flags = xfer->flags;

	qnxflags = 0;
	if (flags & USBD_SHORT_XFER_OK)
		qnxflags |= URB_SHORT_XFER_OK;

	if (flags & USBD_FORCE_SHORT_XFER)
		qnxflags |= URB_SHORT_XFER_OK;

	if (pipe->address & UE_DIR_IN)
		qnxflags |= URB_DIR_IN;
	else
		qnxflags |= URB_DIR_OUT;

	if (!(xfer->flags & USBD_NO_COPY) && xfer->length != 0 &&
	    (qnxflags & URB_DIR_OUT))
		memcpy(xfer->buf_usbd, xfer->buffer, xfer->length);

	/* The following can't fail */
	usbd_setup_bulk(xfer->urb, qnxflags, xfer->buf_usbd, xfer->length);

	cpu_atomic_inc(&xfer->refcnt);
	err = usbd_io(xfer->urb, xfer->pipe->pipe, urb_callback, xfer, xfer->timeout);
	if (err != EOK)
		cpu_atomic_dec(&xfer->refcnt);
	else if (xfer->flags & USBD_SYNCHRONOUS) {
		tsleep(xfer, PRIBIO, "usbsyn", 0);
		usbd_urb_status(xfer->urb, &status, &len);

		if ((status & USBD_URB_STATUS_MASK) != USBD_STATUS_CMP) {
			usb_handle_error(xfer,status);
		}

		status = usb_qnx_to_bsd_status(status);
	}

        return err;
}


/* Like usbd_transfer(), but waits for completion. */
usbd_status_bsd
usbd_sync_transfer(usbd_xfer_handle xfer)
{
	xfer->flags |= USBD_SYNCHRONOUS;

	return usbd_transfer(xfer);
}

usbd_xfer_handle
usbd_alloc_xfer(usbd_device_handle dev)
{
        struct qnx_usbd_xfer	*xfer;

	xfer = malloc(sizeof(*xfer), M_DEVBUF, M_NOWAIT | M_ZERO);
	xfer->refcnt = 1;
	if (xfer == NULL)
		return NULL;
	
	xfer->urb = usbd_alloc_urb(NULL);
	if (xfer->urb == NULL) {
		free(xfer, M_DEVBUF);
		xfer = NULL;
	}

	return xfer;
}

/*
 * Search for a vendor/product pair in an array.  The item size is
 * given as an argument.
 */
const struct usb_devno *
usb_match_device(const struct usb_devno *tbl, u_int nentries, u_int sz,
		 u_int16_t vendor, u_int16_t product)
{
	while (nentries-- > 0) {
		u_int16_t tproduct = tbl->ud_product;
		if (tbl->ud_vendor == vendor &&
		    (tproduct == product || tproduct == USB_PRODUCT_ANY))
			return (tbl);
		tbl = (const struct usb_devno *)((const char *)tbl + sz);
	}
	return (NULL);
}

usbd_status_bsd
usbd_do_request(usbd_device_handle dev, usb_device_request_t *reqp, void *data)
{
	struct usbd_urb			*urb;
	void 				*ubuf;
	int				error;
	uint32_t			flags;
	usbd_device_descriptor_t	*ddesc;
	uint16_t			req, rtype, value, index;
	uint32_t			len;

	ddesc = usbd_device_descriptor(dev->dev, NULL);
	assert(ddesc != NULL);

	req = reqp->bRequest;
	rtype = reqp->bmRequestType;
	value = UGETW(reqp->wValue);
	index = UGETW(reqp->wIndex);
	len = UGETW(reqp->wLength);

	urb = usbd_alloc_urb(NULL);
	if (urb == NULL)
		return USBD_NOMEM;

	ubuf = NULL;
	if (len != 0 && (ubuf = usbd_alloc(len)) == NULL) {
		usbd_free_urb(urb);
		return USBD_NOMEM;
	}

	if (rtype & UT_READ)
		flags = URB_DIR_IN;
	else {
		flags = URB_DIR_OUT;
		memcpy(ubuf, data, len);
	}

	/* Should never get and error from this call */
	error = usbd_setup_vendor(urb, flags, req, rtype, value, index,
	    ubuf, len);
	assert(error == EOK);

	error = usbd_io(urb, dev->ctrl_pipe.pipe, NULL, NULL,
	    MAX_USB_TIMEOUT); 

	if (error == EOK && flags == URB_DIR_IN)
		memcpy(data, ubuf, len);

	if (ubuf != NULL)
		usbd_free(ubuf);
	usbd_free_urb(urb);
	return error;

}

static void
qnx_to_bsd_edesc(usb_endpoint_descriptor_t *bsd, usbd_endpoint_descriptor_t *qnx)
{
	bsd->bLength = qnx->bLength;
	bsd->bDescriptorType = qnx->bDescriptorType;
	bsd->bEndpointAddress = qnx->bEndpointAddress;
	bsd->bmAttributes = qnx->bmAttributes;
	USETW(bsd->wMaxPacketSize, qnx->wMaxPacketSize);
	bsd->bInterval = qnx->bInterval;

}

usb_endpoint_descriptor_t *
usbd_interface2endpoint_descriptor(usbd_interface_handle iface, u_int8_t index)
{
	usbd_descriptors_t		*edesc;
	struct usbd_desc_node 		*ifc;
	int				i;
	size_t				size;

	if (iface->endpts == NULL) {
		size = iface->bsd_desc.bNumEndpoints * sizeof(*iface->endpts);
		iface->endpts = malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
		if (iface->endpts == NULL)
			return NULL;
		if (usbd_interface_descriptor(iface->dev->dev,
		    iface->dev->curr_conf, iface->curr_intf, 0,
		    &ifc) != NULL) {
			for (i = 0;
			    (edesc = usbd_parse_descriptors(iface->dev->dev,
			    ifc, USB_DESC_ENDPOINT, i, NULL)) != NULL; ++i) {
				qnx_to_bsd_edesc(&(iface->endpts + i)->bsd_desc,
				    &edesc->endpoint);
				(iface->endpts + i)->qnx_desc = edesc;
			}
		}
		iface->nendpts = iface->bsd_desc.bNumEndpoints;
	}

	return &(iface->endpts + index)->bsd_desc;
}

usbd_status_bsd
usbd_open_pipe_bsd(usbd_interface_handle iface, u_int8_t address,
    u_int8_t flags, usbd_pipe_handle *pipep)
{
	int i, err;
	usbd_pipe_handle pipe;

	/* Find the descriptor */
	for (i = 0; i < iface->nendpts; i++) {
		if (iface->endpts[i].bsd_desc.bEndpointAddress == address)
			break;
	}
	if (i >= iface->nendpts)
		return USBD_BAD_ADDRESS;

	pipe = malloc(sizeof(struct qnx_usbd_pipe), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (pipe == NULL)
		return USBD_NOMEM;
	*pipep = pipe;

	pipe->address = address;
	pipe->flags = flags;
	pipe->intf = iface;

	err = usbd_open_pipe(iface->dev->dev,
	    (usbd_descriptors_t *)iface->endpts[i].qnx_desc, &pipe->pipe);

	return errno_to_status(err);
}

usbd_status_bsd
usbd_open_pipe_intr(usbd_interface_handle iface, u_int8_t address,
		    u_int8_t flags, usbd_pipe_handle *pipe,
		    usbd_private_handle priv, void *buffer, u_int32_t len,
		    usbd_callback cb, int ival)
{
        panic("not implemented");
        return USBD_INVAL;
}

usbd_status_bsd
usbd_abort_pipe_bsd(usbd_pipe_handle pipe)
{
	return usbd_abort_pipe(pipe->pipe);
}

usbd_status_bsd
usbd_close_pipe_bsd(usbd_pipe_handle pipe)
{
	int error;

	error = usbd_close_pipe(pipe->pipe);
	pipe->pipe = NULL;

	return error;
}


static int
errno_to_status(int err)
{
	switch (err) {
	case EOK:
		return USBD_NORMAL_COMPLETION;

	case ENOMEM:
		return USBD_NOMEM;

	case EINVAL:
	default:
		return USBD_INVAL;
	}
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/lib/libnbdrvr/usb/usb_conv_qnx.c $ $Rev: 680336 $")
#endif
