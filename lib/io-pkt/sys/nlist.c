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






#include "opt_ipsec.h"
#include <sys/nlist.h>
#include <string.h>


__link_set_decl(nlist_exports, struct nlist_export);
#if defined(IPSEC) || defined(FAST_IPSEC)
extern int qnxnto_ipsec_enabled;
__link_set_decl(nlist_exports_ipsec, struct nlist_export);
#endif
static struct nlist_export *nlist_head;

void
nlist_init(void)
{
	struct nlist_export * const *nepp;

	__link_set_foreach(nepp, nlist_exports)
		nlist_add(*nepp);
#if defined(IPSEC) || defined(FAST_IPSEC)
	/* Don't export them if not enabled */
	if (qnxnto_ipsec_enabled) {
		__link_set_foreach(nepp, nlist_exports_ipsec)
			nlist_add(*nepp);
	}
#endif
}

void
nlist_add(struct nlist_export *nep)
{
	struct nlist_export *curp, **curpp;

	for (curpp = &nlist_head; (curp = *curpp) != NULL;
	    curpp = &curp->ne_next) {
		if (strcmp(curp->ne_name, nep->ne_name) > 0)
			break;
	}

	*curpp = nep;
	nep->ne_next = curp;

	return;
}


int
nlist_old(struct nlist_old *nl, int num) {
	struct nlist_export *nep;
	char *name;
	int c;

	for (; num; num--, nl++) {
		nl->n_value = 0;
		nl->n_type = 0;
		name = nl->n_name;
		if (*name == '_')
			name++;

		for (nep = nlist_head; nep; nep = nep->ne_next) {
			c = strncmp(nep->ne_name, name, sizeof nl->n_name - 2);

			if (c > 0)
				break;

			if (c == 0) {
				nl->n_value = (long)nep->ne_addr;
				nl->n_type = nep->ne_size;
				break;
			}
		}
	}
	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/nlist.c $ $Rev: 838599 $")
#endif
