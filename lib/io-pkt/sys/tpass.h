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



#ifndef _TPASS_H_INCLUDED
#define _TPASS_H_INCLUDED

#ifndef _PTHREAD_H_INCLUDED
#include <pthread.h>
#endif

/*
 * A tpass_entry consists of a header and one
 * list entry per thread.  To allow extra per
 * thread info we separate the header and list
 * pointers into separate structs.
 */
struct tpass_entry {
	short tpe_nthreads_creating;
	short tpe_nthreads_destroying;
};

/*
 * The actual q pointers in tpass_list, tpass_queues overlap with
 * the LIST_ENTRY / LIST_HEAD members in their respective unions
 * instantiated by TPASS_*_DECLARE.  We don't use the actual 
 * LIST_ENTRY  / LIST_HEAD macros here as they don't really make
 * sense as the tpass_entry struct has no next / prev members.
 * Rather we used passed in offsets to index to the tpass_list
 * entry in question.
 *
 * Note for the instantiated unions to make sense, the tpass
 * entry has to be the first member of the passed composite.
 */
struct tpass_list {
	struct tpass_entry *tpl_next;
	struct tpass_entry **tpl_prev;
};

#define TPASS_LIST_DECLARE(utype, struct_type)				\
union utype {								\
	struct tpass_list tpl_private;					\
	LIST_ENTRY(struct_type) tpl_local;				\
}


struct tpass_queues {
	int tpq_items_changing;
	struct tpass_entry *tpq_create_q;
	struct tpass_entry *tpq_destroy_q;
};

struct tpass_reminfo {
	int			tpr_tlist_first_offset;
	int			tpr_tlist_next_offset;
	int			tpr_pq_next_offset;
	int			tpr_lim;
	void			(*tpr_rem_self)(struct tpass_entry *, int);
	pthread_mutex_t		*tpr_mtx;
};


#define TPASS_QUEUES_DECLARE(utype, struct_type)			\
union utype {								\
	struct tpass_queues tpq_private;				\
	struct {							\
		int	tpq_items_changing;				\
		LIST_HEAD(, struct_type) tpq_create_q;			\
		LIST_HEAD(, struct_type) tpq_destroy_q;			\
	} tpq_local;							\
}

#define TPASS_MARK_OFFLIST(tl)  \
        (tl)->tpl_prev = NULL, (tl)->tpl_next = NULL
#define TPASS_IS_OFFLIST(tl) ((tl)->tpl_prev == NULL)

void tpass_start_rem(struct tpass_entry *, struct tpass_queues *, 
	struct tpass_queues *, int, struct tpass_reminfo *);
	

#endif /* !_TPASS_H_INCLUDED */

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/tpass.h $ $Rev: 680336 $")
#endif
