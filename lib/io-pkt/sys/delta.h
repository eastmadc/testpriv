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





#ifndef _DELTA_H_INCLUDED
#define _DELTA_H_INCLUDED

#if defined(_KERNEL) && (!defined(TRACK_DELTAS) || !defined(USE_PULSE))
#define TASK_TIME_START(a) ((void)0)
#define TASK_TIME_STOP(a)  ((void)0)
#endif

#if defined(TRACK_DELTAS) || defined(FAKE_UP_WRITES)

#ifndef __SOCKMSG_H_INCLUDED
#include <sys/sockmsg.h>
#endif

#ifndef _NET_IF_H_INCLUDED
#include <net/if.h>
#endif


/* currently not used as a MSG_* flag in <sys/socket.h> XXX */
#define MSG_TIME 0x8000

/* currently not used as an _XTYPE in <sys/iomsg.h> XXX */
#define _IO_XTYPE_TCPIP_DBUG 10

struct sendto_dbug {
	io_sock_sendto_t msg;
	uint64_t send_start;
};

struct task_time {
	char desc[100];
	uint64_t ntimed;
	uint64_t cycles_tot;
	uint64_t cycles_start;
	uint64_t cycles_stop;
};

struct if_task_time {
	struct ifdrv cmd;
	struct task_time task_times;
};

#ifdef _KERNEL
#if defined(USE_PULSE) && defined(TRACK_DELTAS)
#define TASK_TIME_MSG_SEND            0
#define TASK_TIME_PROCESS_INTERRUPTS  1
#define TASK_TIME_SOFTCLOCK           2
#define TASK_TIME_RESMGR              3
#define TASK_TIME_TOT                 4

extern struct task_time task_times[TASK_TIME_TOT];

#define TASK_TIME_START(which) task_times[which].cycles_start = ClockCycles()

#define TASK_TIME_STOP(which) do { \
	task_times[which].cycles_stop = ClockCycles();	\
	task_times[which].cycles_tot +=			\
	    task_times[which].cycles_stop -		\
	    task_times[which].cycles_start;		\
	task_times[which].ntimed++;			\
} while(0)
#endif

#ifdef FAKE_UP_WRITES
extern void *fake_cpy_buf;
extern int nfake;
#endif
#else

int sendto_dbug(int fd, const void *buf, size_t len, int flags);

/*
 * Meant to be a replacement on client side for write(),
 * send(fd, buf, len, 0), or sendto(fd, buf, len, 0, NULL, 0)
 */
int
sendto_dbug(int fd, const void *buf, size_t len, int flags)
{
	struct sendto_dbug msg;
	iov_t iov_i[2];

	if (flags & ~MSG_TIME) {
		errno = EINVAL;
		return -1;
	}

	SETIOV(iov_i, &msg, sizeof msg);
	SETIOV(iov_i+1, buf, len);

	msg.msg.i.write.type        = _IO_WRITE;
	msg.msg.i.write.combine_len = sizeof msg.msg.i;
	msg.msg.i.write.nbytes      = len;
	msg.msg.i.write.xtype       = _IO_XTYPE_TCPIP_DBUG;
	msg.msg.i.flags             = flags;

	msg.msg.i.write.zero        = 0;
	msg.msg.i.addrlen           = sizeof(msg) - sizeof(msg.msg);

	if (flags & MSG_TIME)
		msg.send_start = ClockCycles();

	return  MsgSendv(fd, iov_i, 2, NULL, 0);
}

int
sendto_dbug_single(int fd, const void *buf, size_t len, int flags)
{
	struct sendto_dbug *msg;

	if (flags & ~MSG_TIME) {
		errno = EINVAL;
		return -1;
	};

	msg = (struct sendto_dbug *)((char *)buf - sizeof(struct sendto_dbug));

	msg->msg.i.write.type        = _IO_WRITE;
	msg->msg.i.write.combine_len = sizeof msg->msg.i;
	msg->msg.i.write.nbytes      = len;
	msg->msg.i.write.xtype       = _IO_XTYPE_TCPIP_DBUG;
	msg->msg.i.flags             = flags;

	msg->msg.i.write.zero        = 0;
	msg->msg.i.addrlen           = sizeof(*msg) - sizeof(msg->msg);

	if (flags & MSG_TIME)
		msg->send_start = ClockCycles();

	return MsgSend(fd, msg, len + sizeof *msg, NULL, 0);
	
}
#endif
#endif
#endif

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/io-pkt/sys/delta.h $ $Rev: 680336 $")
#endif
