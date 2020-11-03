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





#include "opt_ionet_compat.h"
#ifdef IONET_COMPAT
#include "ionet_compat.h"
#endif

#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/syspage.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include "nw_datastruct.h"
#include "nw_dl.h"
#include "blockop.h"
#include <sys/io-pkt.h>
#include <sys/syslog.h>
#include <alloca.h>


/*
 * Auto generated file (see common.mk).
 * Contains STATIC_DRVR-* defines.
 * Edit static_drvr*.mk to alter bound driver list.
 */
#include <static_drvrs.h>

struct dlopen_blockop {
	const char	*db_path;
	int		db_mode;
	void		*db_hdl;
};

struct dlclose_blockop {
	void		*db_hdl;
	int		db_ret;
};

void nw_dlopen_blockop(void *);
void nw_dlclose_blockop(void *);



#ifdef STATIC_DRVR_EXTERNS

STATIC_DRVR_EXTERNS


struct dll_list {
	char				*fname;
	const struct nw_dll_syms	*syms;
};
static const struct dll_list dll_list[] = {
	/*
	 * If you add symbols here, you'll have to
	 * make sure they're found at link time by
	 * your favourite method:
	 * - install libs to stage
	 * - LIBS and maybe EXTRA_LIBVPATH in common.mk.
	 * - LDOPTS on command line.
	 */
	STATIC_DRVR_SYMS
	{NULL, NULL}
};


static char *_io_pkt_dl_error;

static int
is_bound(const struct dll_list *test)
{
	const struct dll_list	*l;

	for (l = dll_list; l->fname != NULL; l++) {
		if (l == test)
			return 1;
	}

	return 0;
}

#endif

void
nw_dlopen_blockop(void *arg)
{
	struct dlopen_blockop	*db;
	struct timespec		ts;

	db = arg;

	ts.tv_sec = 10;
	ts.tv_nsec = 0;
	timer_timeout(CLOCK_REALTIME, _NTO_TIMEOUT_REPLY | _NTO_TIMEOUT_SEND,
	    NULL, &ts, NULL);
	db->db_hdl = dlopen(db->db_path, db->db_mode);
}

void
nw_dlclose_blockop(void *arg)
{
	struct dlclose_blockop	*db;
	struct timespec		ts;

	db = arg;

	ts.tv_sec = 10;
	ts.tv_nsec = 0;
	timer_timeout(CLOCK_REALTIME, _NTO_TIMEOUT_REPLY | _NTO_TIMEOUT_SEND,
	    NULL, &ts, NULL);
	db->db_ret = dlclose(db->db_hdl);
}

void *
nw_dlopen(const char *pathname, int mode)
{
	return nw_dlopen_p(pathname, mode, NULL);
}

void *
nw_dlopen_p(const char *pathname, int mode, struct proc *p)
{
	struct dlopen_blockop	db;
	struct bop_dispatch	bop;

#ifndef STATIC_DRVR_EXTERNS
	if (curproc == stk_ctl.proc0) {
		/*
		 * Initial startup.  We shouldn't
		 * have received a message yet
		 * (or be able to receive a message)
		 * so can't get into the state
		 * where we dlopen via a server that
		 * needs network services.
		 */
		return dlopen(pathname, mode);
	}

	db.db_path = pathname;
	db.db_mode = mode;
	db.db_hdl = NULL;

	bop.bop_func = nw_dlopen_blockop;
	bop.bop_arg = &db;
	bop.bop_prio = curproc->p_ctxt.info.priority;
	blockop_dispatch(&bop, p);
	return db.db_hdl;
#else
	const struct dll_list	*l;
	const char		*cp;
	void			*ret;

	cp = pathname;

	for (l = dll_list; l->fname != NULL; l++) {
		if (!strcmp(l->fname, pathname))
			return (void *)l;
	}

	if (curproc == stk_ctl.proc0) {
		ret = dlopen(pathname, mode);
	}
	else {
		db.db_path = pathname;
		db.db_mode = mode;
		db.db_hdl = NULL;

		bop.bop_func = nw_dlopen_blockop;
		bop.bop_arg = &db;
		bop.bop_prio = curproc->p_ctxt.info.priority;
		blockop_dispatch(&bop, p);

		ret = db.db_hdl;
	}

	if (ret == NULL && (cp = strrchr(pathname, '/')) && *(++cp)) {
		for (l = dll_list; l->fname != NULL; l++) {
			if (!strcmp(l->fname, cp)) {
				ret = (void *)l;
				break;
			}
		}
	}

	return ret;
#endif
}


void *
nw_dlsym(void *handle, const char *name)
{
#ifndef STATIC_DRVR_EXTERNS
	return dlsym(handle, name);
#else
	const struct nw_dll_syms	*s;

	if (!is_bound(handle))
		return dlsym(handle, name);

	for (s = ((struct dll_list *)handle)->syms; s->symname != NULL; ++s) {
		if (!strcmp(name, s->symname))
			return s->addr;
	}

	_io_pkt_dl_error = "Symbol not found";

	return NULL;
#endif
}

int
nw_dlclose(void *hdl)
{
	return nw_dlclose_p(hdl, NULL);
}

int
nw_dlclose_p(void *hdl, struct proc *p)
{
	struct dlclose_blockop	db;
	struct bop_dispatch	bop;

#ifdef STATIC_DRVR_EXTERNS
	if (hdl == NULL || is_bound(hdl))
		return 0;
#endif

	if (curproc == stk_ctl.proc0)
		return dlclose(hdl);

	db.db_hdl = hdl;
	db.db_ret = -1;

	bop.bop_func = nw_dlclose_blockop;
	bop.bop_arg = &db;
	bop.bop_prio = curproc->p_ctxt.info.priority;
	blockop_dispatch(&bop, p);
	return db.db_ret;
}

char *
nw_dlerror(void)
{
#ifndef STATIC_DRVR_EXTERNS
	return dlerror();
#else
	char *p;

	if (_io_pkt_dl_error) {
		p = _io_pkt_dl_error;
		_io_pkt_dl_error = NULL;
		return p;
	}

	return dlerror();
#endif
}


int
nw_dlload_module(int cons, char *mp0, char *mod_opts, struct proc *p)
{
	struct _iopkt_self		*iopkt;
	struct nw_stk_ctl 		*sctlp;
	struct _iopkt_drvr_entry	*dentry;
	struct _iopkt_lsm_entry		*lentry;
	char				*string, *mp;
	void				*hdl;
	int				ret;
	void				(*logp)(int, const char *, ...);

	string = mod_opts;
	sctlp = &stk_ctl;
	iopkt = iopkt_selfp;

	if (cons)
		logp = &log_cons;
	else
		logp = log;

	mp = mp0;

	if (mp == NULL || mp[0] == '\0')
		return EINVAL;

	for (;;) {
		if ((hdl = nw_dlopen_p(mp, RTLD_WORLD | RTLD_GROUP | RTLD_LAZYLOAD, p)) != NULL)
			break;
#ifdef IONET_COMPAT
		/* if "devnp-*", try again with "devn-*" */
		if (mp == mp0 && strlen(mp) >= sizeof("devnp-") - 1 &&
		    strncmp(mp, "devnp-", sizeof("devnp-") - 1) == 0) {
			if ((mp = malloc(strlen(mp), M_TEMP,
			    M_NOWAIT)) == NULL) {
				(*logp)(LOG_ERR, "Unable to load %s: nomem\n", mp0);
				return ENOMEM;
			}
			strcpy(mp, "devn-");
			strcat(mp, mp0 + sizeof("devnp-") - 1);
			continue;
		}
#endif
		(*logp)(LOG_ERR, "Unable to load %s: %s\n", mp, nw_dlerror());
		ret = ENXIO;
		goto out;
	}


	if ((lentry = nw_dlsym(hdl, "iopkt_lsm_entry")) != NULL) {
		/* See matrix in nw_thread.c */
		if (
		    lentry->version != IOPKT_VERSION ||
#ifndef VARIANT_uni
		    /* general or smp stack might create threads */
		    lentry->type == IOPKT_MODULE_UNI
#else
		    /* uni stack doesn't init mutexes */	
		    lentry->type == IOPKT_MODULE_SMP
#endif
		    ) {
			(*logp)(LOG_ERR, "lsm variant mismatch.\n");
			nw_dlclose_p(hdl, p);
			ret = EINVAL;
			goto out;
		}

		log(LOG_INFO, "%s %s", mp, string);
		ret = (*lentry->lsm_init)(hdl, iopkt, string);
	}
	else {
		dentry = nw_dlsym(hdl, "iopkt_drvr_entry");

#ifdef IONET_COMPAT
		if (dentry == NULL &&
		    nw_dlsym(hdl, "io_net_dll_entry") != NULL) {
			nw_dlclose_p(hdl, p);
			hdl = nw_dlopen_p(IONET_SHIM_NAME,
			    RTLD_WORLD | RTLD_GROUP | RTLD_LAZYLOAD, p);
			if (hdl == NULL) {
				(*logp)(LOG_ERR, "Unable to load %s: %s\n",
				    IONET_SHIM_NAME, nw_dlerror());
				ret = ENXIO;
				goto out;
			}

			/*
			 * The driver API only allows for a single option
			 * string, but the shim needs both the original driver
			 * name as well as the options. The code below
			 * concatenates them into a single string. It allocates
			 * an extra byte for string termination, and, if needed,
			 * an extra byte for the space between name and options.
			 */
			string = alloca(strlen(mp) + 1 + (mod_opts ?
			    strlen(mod_opts) + 1: 0));
			if (string == NULL) {
				(*logp)(LOG_ERR, "Unable to load %s: no mem\n", mp);
				ret = ENOMEM;
				goto out;
			}

			strcpy(string, mp);
			if (mod_opts != NULL) {
				strcat(string, " ");
				strcat(string, mod_opts);
			}
			dentry = nw_dlsym(hdl, "iopkt_drvr_entry");
		}
#endif

		if (dentry == NULL) {
			(*logp)(LOG_ERR, "Unable to load %s: %s\n", mp,
			    nw_dlerror());
			nw_dlclose_p(hdl, p);
			ret = ENXIO;
			goto out;
		}

		/* See matrix in nw_thread.c */
		if (
		    dentry->version != IOPKT_VERSION ||
#ifndef VARIANT_uni
		    /* general or smp stack might create threads */
		    dentry->type == IOPKT_MODULE_UNI
#else
		    /* uni stack doesn't init mutexes */	
		    dentry->type == IOPKT_MODULE_SMP
#endif
		    ) {
			(*logp)(LOG_ERR, "Driver variant mismatch.\n");
			nw_dlclose_p(hdl, p);
			ret = EINVAL;
			goto out;
		}

		log(LOG_INFO, "%s %s", mp, string);
		ret = (*dentry->drvr_init)(hdl, iopkt, string);
	}

	if (ret != EOK) {
		(*logp)(LOG_ERR, "Unable to init %s: %s\n", mp, strerror(ret));
		nw_dlclose_p(hdl, p);
	}
out:
	if (mp != mp0)
		free(mp, M_TEMP);

	return ret;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nw_dl.c $ $Rev: 809199 $")
#endif
