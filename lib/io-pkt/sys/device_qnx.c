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

#include <sys/malloc.h>
#include <sys/device.h>
#include <device_qnx.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nw_dl.h>
#include <siglock.h>
#include <nw_thread.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/syslog.h>
#include <quiesce.h>

struct devicelist alldevs = TAILQ_HEAD_INITIALIZER(alldevs);

static char *dev_opts[] = {
#define DEVOPT_LAN	0
	"lan",
#define DEVOPT_UNIT	1
	"unit",
#define DEVOPT_NAME 2
	"name",
	NULL
};

/* Based on NetBSD's config_attach_loc():kern/subr_autoconf.c */

static void
dev_free(struct device *dev)
{
	if (dev->dv_options != NULL)  {
		free(dev->dv_options,M_DEVBUF);
		dev->dv_options = NULL;
	}
	if (dev->dv_flags & DVF_NAMEOPT) {
		free(dev->dv_cfdata, M_DEVBUF);
		dev->dv_cfdata = NULL;
	}
	free(dev->dv_alloc, M_DEVBUF);
}

int
dev_attach(char *drvr, char *options, struct cfattach *ca,
    void *cfat_arg, int *single, struct device **devp,
    int (*print)(void *, const char *))
{
	struct device		*dev, *parent;
	int			ret, unit, flag_name;
	void			*head;
	char			*opt_p;
	struct nw_work_thread	*wtp;

	if ((wtp = nw_thread_istracked()) == NULL || !ISSTACK_P(wtp))
		return EPERM;

	parent = *devp;
	*devp = NULL;
	opt_p = NULL;
	flag_name = 0;

	unit = -1;

	/* Create a new options string for exclusive use of the device. */
	if ((options != NULL) && (*options != '\0')) {
		opt_p = malloc(strlen(options) + 1, M_DEVBUF, M_NOWAIT);
		if (opt_p == NULL) {
			return ENOMEM;
		}
		strcpy(opt_p, options);
	}
	
	if (opt_p != NULL) {
		char *curr;
		char *last;

		curr = opt_p;
		last = curr;
		while (*curr != '\0') {
			char	*value;
			char 	*restore;
			int	consume;
			int	opt;

			consume = 1;
			restore = strchr(curr, ',');
			opt = getsubopt(&curr, dev_opts, &value);

			switch (opt) {
			case DEVOPT_LAN:
			case DEVOPT_UNIT:
				if (value != NULL) {
					unit = strtol(value, NULL, 0);
					*single = 1;
				}
				break;
			case DEVOPT_NAME:
				if (value != NULL) {
					drvr = malloc(sizeof(dev->dv_xname), M_DEVBUF, M_NOWAIT);
					if (drvr == NULL) {
						free(opt_p, M_DEVBUF);
						return ENOMEM;
					}
					flag_name = DVF_NAMEOPT;
					strlcpy(drvr, value, sizeof(dev->dv_xname));
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




	if (unit < 0) {
		unit = 0;
		for (;;) {
			TAILQ_FOREACH(dev, &alldevs, dv_list) {
				if (strcmp(dev->dv_cfdata, drvr) == 0 &&
				    dev->dv_unit == unit) {
					unit++;
					break;
				}
			}
			if (dev == NULL)
				break;
		}
	}
	else {
		TAILQ_FOREACH(dev, &alldevs, dv_list) {
			if (strcmp(dev->dv_cfdata, drvr) == 0 &&
			    dev->dv_unit == unit) {
				return EALREADY;
			}
		}
	}

	if ((head = malloc(ca->ca_devsize + NET_CACHELINE_SIZE, M_DEVBUF,
	    M_NOWAIT | M_ZERO)) == NULL)
		return ENOMEM;

	dev = NET_CACHELINE_ALIGN(head);
	dev->dv_alloc = head;

	if (opt_p && *opt_p != '\0') {
		dev->dv_options = opt_p;
	} else {
		/* No options passed or none left. */
		if (opt_p != NULL) {
			free(opt_p, M_DEVBUF);
		}
		dev->dv_options = NULL;
	}

	dev->dv_unit = unit;
	dev->dv_class = DV_IFNET;	/* XXX */
	dev->dv_flags = DVF_ACTIVE;	/* always initially active */
	dev->dv_flags |= flag_name;
	dev->dv_cfdata = drvr;
	dev->dv_parent = parent;
	dev->dv_cfattach = ca;
	if (snprintf(dev->dv_xname, sizeof(dev->dv_xname), "%s%d",
	    drvr, unit) >= sizeof(dev->dv_xname)) {
		dev_free(dev);
		return ENAMETOOLONG;
	}

	if (parent != NULL)
		aprint_normal("%s at %s\n", dev->dv_xname, parent->dv_xname);
	else
		aprint_normal("%s\n", dev->dv_xname);

	if (print != NULL)
		(*print)(cfat_arg, NULL);

	if ((ret = ca->ca_attach(parent, dev, cfat_arg)) == EOK) {
		TAILQ_INSERT_TAIL(&alldevs, dev, dv_list);
		*devp = dev;
	}
	else {
		dev_free(dev);
	}
	return ret;
}

static void
device_removal_callback_thread(void *arg)
{
	struct device	*dev;
	dev = arg;

	dev_detach(dev, dev->dv_detflags);
	kthread_exit(0);
}

static void 
device_removal_callback(void *arg)
{
	struct lwp	*l;
	int		ret;

	l = curlwp;

	if ((ret = proc0_getprivs(l)) != EOK) {
		log(LOG_ERR, "device rem: unexpected context: %d", ret);
		return;
	}

	kthread_create1(device_removal_callback_thread, arg, NULL, NULL);
	proc0_remprivs(l);
}


/* This function allows an external (non-stack) bus monitoring thread to
 detach the device by pushing the detach off into a stack callback. */

void
dev_remove(struct device *dev)
{
	struct cfattach		*ca;

	if (dev != NULL) {
		ca = dev->dv_cfattach;
		if (ca != NULL && *ca->ca_detach != NULL) {
			dev->dv_callback.func = device_removal_callback;
			dev->dv_callback.arg = dev;
			stk_context_callback(&dev->dv_callback);	
		}
	}

}



/* Based on NetBSD's config_detach():kern/subr_autoconf.c */
int
dev_detach(struct device *dev, int flags)
{
	struct cfattach		*ca;
	int			ret, last, quiesced;
	struct device		*d;
	struct nw_work_thread	*wtp;

	if ((wtp = nw_thread_istracked()) == NULL || !ISSTACK_P(wtp))
		return EPERM;

	ret = EOK;
	quiesced = 0;

	/*
	 * If they've specified this flag it means
	 * they'll handle their own quiescing.  Not
	 * doing it here lets the detach callout
	 * clean up any threads an attach may have
	 * created.
	 */
	if ((dev->dv_flags & DVF_QUIESCESELF) == 0) {
		quiesce_all();
		quiesced = 1;
	}

	last = 1;

	ca = dev->dv_cfattach;

	if (ca == NULL || ca->ca_detach == NULL) {
		ret = EOPNOTSUPP;
		goto out;
	}

	if (ca->ca_activate != NULL && (ret = config_deactivate(dev)) != EOK)
		goto out;

	if ((ret = (*ca->ca_detach)(dev, flags)) != EOK)
		goto out;

	TAILQ_FOREACH(d, &alldevs, dv_list) {
		if (d->dv_parent == dev) {
			panic("detached device has undetached children (%s line %d)", __FILE__,__LINE__);
		}
	}
	/* bus_detach is QNX specific */
	if (dev->dv_bus_detach != NULL)
		(*dev->dv_bus_detach)(dev->dv_bus_hdl);

	TAILQ_REMOVE(&alldevs, dev, dv_list);
	stk_context_callback_2_clean(dev);

	if (dev->dv_dll_hdl == NULL)
		last = 0;
	else {
		TAILQ_FOREACH(d, &alldevs, dv_list) {
			if (dev->dv_dll_hdl == d->dv_dll_hdl)
				last = 0;
		}
	}

	if (quiesced)
		unquiesce_all();

	if (dev->dv_dll_hdl != NULL && last) {
		nw_dlclose_p(dev->dv_dll_hdl, NULL);
	}

	dev_free(dev);

	return ret;
out:
	if (quiesced)
		unquiesce_all();

	return ret;
}

int
dev_detach_name(const char *name, int flags)
{
	struct device	*dev;

	TAILQ_FOREACH(dev, &alldevs, dv_list) {
		if (strncmp(dev->dv_xname, name, sizeof(dev->dv_xname)) == 0)
			break;
	}

	if (dev == NULL)
		return ENXIO;

	return dev_detach(dev, flags);
}

int
dev_update_name(const char *oname, const char *newname, const char *base, int unit)
{
	struct device	*dev;
	char		*newp;

	TAILQ_FOREACH(dev, &alldevs, dv_list) {
		if (strncmp(dev->dv_xname, oname, sizeof(dev->dv_xname)) == 0)
			break;
	}

	if (dev == NULL)
		return ENXIO;


	if ((newp = malloc(sizeof(dev->dv_xname), M_DEVBUF, M_NOWAIT)) == NULL)
		return ENOMEM;

	strlcpy(newp, base, sizeof(dev->dv_xname));

	if (dev->dv_flags & DVF_NAMEOPT) {
		free(dev->dv_cfdata, M_DEVBUF);
	}
	dev->dv_flags |= DVF_NAMEOPT;
	dev->dv_cfdata = newp;
	dev->dv_unit = unit;
	strlcpy(dev->dv_xname, newname, sizeof(dev->dv_xname));
	return EOK;
}

/* From NetBSD's kern/subr_autoconf.c */
int
config_deactivate(struct device *dev)
{
	const struct cfattach *ca = dev->dv_cfattach;
	int rv = 0, oflags = dev->dv_flags;

	if (ca->ca_activate == NULL)
		return (EOPNOTSUPP);

	if (dev->dv_flags & DVF_ACTIVE) {
		dev->dv_flags &= ~DVF_ACTIVE;
		rv = (*ca->ca_activate)(dev, DVACT_DEACTIVATE);
		if (rv)
			dev->dv_flags = oflags;
	}
	return (rv);
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/device_qnx.c $ $Rev: 834497 $")
#endif
