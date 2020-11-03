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



#include <sys/param_bsd.h>
#include <sys/systm.h>
#include <tpass.h>
#include <siglock.h>



#ifndef VARIANT_uni
/*
 * A fair bit of info passed in to make this generic.  As such
 * we only lock the mutex after everything that can be is set up.
 *
 * A lot of indirection to generalize one func?  It was done this
 * way because the logic is subtle and was slightly botched more
 * than once.  Plus it tends to make the users of tpass easier
 * to follow outside of this func.
 */

/*
 * Notes on tpass:
 * This is intended to optimize data usage patterns found in
 * forwarding type situations: ip_flow, if_bridge.  ie patterns
 * where the high runner case is packets to a particular dst are
 * received in bursts on a particular iface.  The iface receiving
 * the packets are serviced by a particular thread.  This in
 * turn means the entry containing the forwarding info to locate
 * the dst is usually only looked at by a single thread in bursts.
 * This burst by thread behaviour should mean the entry is hot
 * in the thread in question's cache.
 *
 * There is usually a per thread hash of entries.  This means a
 * particular entry may be found by more than one thread but
 * each thread finds it via their own private route (ie method, not
 * ip routing).  This per thread hash avoids locking in the steady
 * state.  Since the same entry may be found by multiple threads,
 * it's optimal if the entry itself doesn't change when an add /
 * removal isn't being performed to avoid cache polution amongst
 * the multiple threads.  This last point isn't critical as again,
 * the expected high runner is for a particular entry to be
 * searched for by a single thread in bursts.  Plus if two threads
 * do collide, there's probably bigger issues when they run into
 * exclusion issues as they contend for access to the hardware.
 *
 * In summary, per thread hashes, single entries.  Add / remove
 * is more expensive so that the steady state is faster.  Things
 * probably work best when under load so the per thread create /
 * destroy queues don't grow overly long.
 */
void
tpass_start_rem(struct tpass_entry *tpass, struct tpass_queues *pass_qs, 
    struct tpass_queues *return_qs, int self, 
    struct tpass_reminfo *reminfo)
{
	int			i, toff, toff_in, lim;
	struct tpass_list	*tlist, *tlist_next;
	struct tpass_entry	*tpass_next;
	struct tpass_queues	*pq_cur;
	int 			tlist_next_off, pq_next_off;
	struct			nw_work_thread *wtp;

	wtp = WTP;
#ifndef NDEBUG
	if (!ISSTACK_P(wtp))
		panic("tpass_start_rem: called without stack.\n");
#endif
	tlist = (struct tpass_list *)((char *)tpass + reminfo->tpr_tlist_first_offset);
	tlist_next_off = reminfo->tpr_tlist_next_offset;
	pq_next_off = reminfo->tpr_pq_next_offset;
	lim = reminfo->tpr_lim;

	return_qs->tpq_items_changing = 0;
	return_qs->tpq_destroy_q = NULL;
	return_qs->tpq_create_q = NULL;

	/*
	 * The offset between the passed in tpass and current tlist.
	 * This increases with index i but to keep this generic, we
	 * don't assume that tlist directly follows tpass or what
	 * the offset to the next tlist is.  This removes any
	 * restrictions as to the layout of the parent structure.
	 */
	toff_in = (char *)tlist - (char *)tpass;
	toff = toff_in;
	pq_cur = pass_qs;
	NW_SIGLOCK_P(reminfo->tpr_mtx, iopkt_selfp, wtp);
	for (i = 0; i < lim; i++) {
		if (!TPASS_IS_OFFLIST(tlist)) {
			/*
			 * Didn't make it to this thread's private stash
			 * yet so don't have to wait for it to do its own
			 * removal.
			 */
			
			/*
			 * Similar to LIST_REMOVE(tlist, tpl_list) but
			 * we take into account gap between tpass and
			 * currently indexed tlist.
			 */
			if ((tpass_next = tlist->tpl_next) != NULL) {
				tlist_next = (struct tpass_list *)((char *)tpass_next + toff);
				tlist_next->tpl_prev = tlist->tpl_prev;
			}
			*tlist->tpl_prev = tlist->tpl_next;

			TPASS_MARK_OFFLIST(tlist);
			tpass->tpe_nthreads_creating--;
			pq_cur->tpq_items_changing--;
		}
		else {
			/*
			 * Similar to
			 * LIST_INSERT_HEAD(&pq_cur->tpq_destroy_q, tpass, ...)
			 * but we take into account gap between tpass and
			 * currently indexed tlist.
			 */
			if ((tlist->tpl_next = pq_cur->tpq_destroy_q) != 0) {
				tlist_next = (struct tpass_list *)((char *)tlist->tpl_next + toff);
				tlist_next->tpl_prev = &tlist->tpl_next;
			}
			pq_cur->tpq_destroy_q = tpass;
			tlist->tpl_prev = &pq_cur->tpq_destroy_q;
			
			tpass->tpe_nthreads_destroying++;
			pq_cur->tpq_items_changing++;
		}
		tlist = (struct tpass_list *)((char *)tlist + tlist_next_off);
		pq_cur = (struct tpass_queues *)((char *)pq_cur + pq_next_off);
		toff += tlist_next_off;
	}

	if (tpass->tpe_nthreads_creating != 0)
		panic("tpass: creating while destroying.\n");

	/* Clean up our own while here */
	toff = toff_in;
	toff += tlist_next_off * self;


	if (tpass->tpe_nthreads_destroying == 0) {
		tlist = (struct tpass_list *)((char *)tpass + toff);
		 /* Singly linked here */
		tlist->tpl_next = return_qs->tpq_destroy_q;
		return_qs->tpq_destroy_q = tpass;
		return_qs->tpq_items_changing++;
	}


	pq_cur = (struct tpass_queues *)((char *)pass_qs + pq_next_off * self);
	while ((tpass = pq_cur->tpq_destroy_q) != NULL) {
		tlist = (struct tpass_list *)((char *)tpass + toff);
		pq_cur->tpq_destroy_q = tlist->tpl_next;
		pq_cur->tpq_items_changing--;

		TPASS_MARK_OFFLIST(tlist);
		(*reminfo->tpr_rem_self)(tpass, self);
		if (--tpass->tpe_nthreads_destroying == 0) {
			 /* Singly linked here */
			tlist->tpl_next = return_qs->tpq_destroy_q;
			return_qs->tpq_destroy_q = tpass;
			return_qs->tpq_items_changing++;
		}
	}
	NW_SIGUNLOCK_P(reminfo->tpr_mtx, iopkt_selfp, wtp);

	return;
}
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/tpass.c $ $Rev: 680336 $")
#endif
