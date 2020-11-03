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

#include "namespace.h"
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <share.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/iomsg.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockmsg.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <net/if_vlanvar.h>
#include <net80211/ieee80211_ioctl.h>


/* Opencrypto /dev/crypto */
#include <crypto/cryptodev.h>

/* Packet Filter /dev/pf */
#include <net/pfvar.h>

/* BPF */
#include <net/bpf.h>

#ifdef __weak_alias
__weak_alias(ioctl_socket,_ioctl_socket)
#endif

int ioctl_socket(int fd, int cmd, ...) {
	va_list			vl;
	void			*data;
	int			newfd;
	struct session_op	*sop;
	struct crypt_op		*cop;
	iov_t			siov[6], *siovp;
	int			sniov;
	iov_t			riov[6], *riovp;
	int			rniov;
	io_devctl_t		msg;
	int			ret, len, i;
	struct ifreq		*ifr;
	struct vlanreq		*vlr;
	struct ieee80211_nwid	*nwid;
	struct ieee80211_nwkey	*nwkey;
	struct if_clonereq	*ifcr;
	struct ifmediareq	*ifmr;
	struct ieee80211req	*ieee80211req;

	/* Pull out the data */
	va_start(vl, cmd);
	data = va_arg(vl, void *);
	va_end(vl);

	sop = NULL;


	switch (cmd) {
	case SIOCGETVLAN:
	case SIOCSETVLAN:
	case SIOCGETVLANPRIO:
	case SIOCSETVLANPRIO:
		ifr = data;
		vlr = (struct vlanreq *)ifr->ifr_data;
		SETIOV(&siov[1], ifr, sizeof(*ifr));
		SETIOV(&siov[2], vlr, sizeof(*vlr));

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
		
	case SIOCS80211:
	case SIOCG80211:
		ieee80211req = data;
		SETIOV(&siov[1], ieee80211req, sizeof(*ieee80211req));
		sniov = 1;

		if (ieee80211req->i_data && ieee80211req->i_len) {
			SETIOV(&siov[2], ieee80211req->i_data, ieee80211req->i_len);
			sniov++;
		}

		siovp = riovp = siov;
		rniov = sniov;
		break;
	case SIOCG80211NWID:
	case SIOCS80211NWID:
		ifr = data;
		nwid = (struct ieee80211_nwid *)ifr->ifr_data;
		SETIOV(&siov[1], ifr, sizeof(*ifr));
		SETIOV(&siov[2], nwid, sizeof(*nwid));

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
		
	case SIOCG80211NWKEY:
	case SIOCS80211NWKEY:
		nwkey = data;
		SETIOV(&siov[1], nwkey, sizeof(*nwkey));
		sniov = 1;

		/*
		 * Send up to four keys, any of which can be set. If only key1
		 * and key3 are set, the message gets untangled in the stack,
		 * because the stack also only reads in keys with length bigger
		 * then 0
		 */
		for(i = 0, len = 0; i < IEEE80211_WEP_NKID; i++) {
			if (nwkey->i_key[i].i_keylen <= 0)
				continue;
			SETIOV(&siov[1 + sniov], nwkey->i_key[i].i_keydat, nwkey->i_key[i].i_keylen);
			sniov++;
		}

		siovp = riovp = siov;
		rniov = sniov;
		break;

	case SIOCG80211STATS:
	case SIOCG80211ZSTATS:
		ifr = data;
		
		/* where ifr->ifr_buf points to a struct ieee80211_stats */
		SETIOV(&siov[1], ifr, sizeof(*ifr));
		SETIOV(&siov[2], ifr->ifr_buf, ifr->ifr_buflen);

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
		
	case SIOCIFGCLONERS:
		ifcr = data;
		SETIOV(&siov[1], ifcr, sizeof(*ifcr));
		SETIOV(&siov[2], ifcr->ifcr_buffer, ifcr->ifcr_count * IFNAMSIZ);

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
		
	case SIOCGIFMEDIA:
		ifmr = data;
		SETIOV(&siov[1], ifmr, sizeof(*ifmr));
		SETIOV(&siov[2], ifmr->ifm_ulist, ifmr->ifm_count * sizeof(int));

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
		
	case CRIOGET:
		newfd = open("/dev/crypto", 0);
		if (newfd >= 0) {
			*(int32_t *)data = newfd;
			return EOK;
		}
		return EINVAL;
		break;

	case CIOCGSESSION:
		sop = (struct session_op *)data;

		SETIOV(&siov[1], sop, sizeof(*sop));
		SETIOV(&siov[2], sop->key, sop->keylen);
		SETIOV(&siov[3], sop->mackey, sop->mackeylen);
		
		siovp = riovp = siov;
		sniov = rniov = 3;
		break;

	case CIOCCRYPT:
		cop = (struct crypt_op *)data;

		SETIOV(&siov[1], cop, sizeof(*cop));
		SETIOV(&riov[1], cop, sizeof(*cop));

		/* iv is on send and recv */
		len = (cop->ses & 0xFFFF000000000000ULL) >> 48;
		SETIOV(&siov[2], cop->iv, len);
		SETIOV(&riov[2], cop->iv, len);

		/* mac is on send and recv */
		len = (cop->ses & 0x0000FFFF00000000ULL) >> 32;
		SETIOV(&siov[3], cop->mac, len);
		SETIOV(&riov[3], cop->mac, len);
		
		/* have a src for send and a dest for recv */
		SETIOV(&siov[4], cop->src, cop->len);
		SETIOV(&riov[4], cop->dst, cop->len);

		siovp = siov;
		riovp = riov;
		sniov = rniov = 4;
		break;
#if 0
		// Increase size of siov and riov to be 10
	case CIOCKEY:
	{
		int size, i;

		kop = (struct crypt_kop *)data;

		SETIOV(&siov[1], kop, sizeof(*kop));
		SETIOV(&riov[1], kop, sizeof(*kop));
		sniov = rniov = 1;

		/* Setup all *input* IOV's */
		for (i = 0; i < kop->crk_iparams; i++) {
			size = (kop->crk_param[i].crp_nbits + 7) / 8;
			if (size == 0)
				continue;
			SETIOV(&siov[sniov], kop->crk_param[i].crp_p, size);
			sniov++;
		}

		/* Setup all *output* IOV's */
		for (i = kop->crk_iparams; i < kop->crk_iparams + kop->crk_oparams; i++) {
			size = (kop->crk_param[i].crp_nbits + 7) / 8;
			if (size == 0)
				continue;
			SETIOV(&riov[rniov], kop->crk_param[i].crp_p, size);
			rniov++;
		}

		siovp = siov;
		riovp = riov;

		break;
	}
#endif

	/* BPF translations */
	case BIOCSETF:
	{
		struct bpf_program *bp;
		bp = (struct bpf_program *)data;

		SETIOV(&siov[1], bp, sizeof(*bp));
		SETIOV(&siov[2], bp->bf_insns, bp->bf_len * sizeof(struct bpf_insn));

		siovp = siov;
		riovp = riov;

		sniov = 2;
		rniov = 0;
		break;
	}

	case BIOCGDLTLIST:
	{
		struct bpf_dltlist *bd = (struct bpf_dltlist *)data;

		SETIOV(&siov[1], bd, sizeof(*bd));

		SETIOV(&riov[1], bd, sizeof(*bd));
		SETIOV(&riov[2], bd->bfl_list, bd->bfl_len * sizeof(unsigned int));

		siovp = siov;
		riovp = riov;
		sniov = 1;
		rniov = 2;
		break;
	}
	/* END BPF translations */


	case DIOCIGETIFACES:
	{
		struct pfioc_iface *io = (struct pfioc_iface *)data;

		SETIOV(&siov[1], io, sizeof(*io));

		SETIOV(&riov[1], io, sizeof(*io));
		SETIOV(&riov[2], io->pfiio_buffer, io->pfiio_size * io->pfiio_esize);

		siovp = siov;
		riovp = riov;
		sniov = 1;
		rniov = 2;
		break;
	}


	case DIOCXBEGIN:
	case DIOCXCOMMIT:
	case DIOCXROLLBACK:
	{
		struct pfioc_trans *io = (struct pfioc_trans *)data;

		SETIOV(&siov[1], io, sizeof(*io));
		SETIOV(&siov[2], io->array, io->size * io->esize);

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
	}

	case DIOCGETSTATES:
	case DIOCGETSRCNODES:
	{
		struct pfioc_states *ps = (struct pfioc_states *)data;

		SETIOV(&siov[1], ps, sizeof(*ps));

		SETIOV(&riov[1], ps, sizeof(*ps));
		SETIOV(&riov[2], ps->ps_buf, ps->ps_len);

		siovp = siov;
		riovp = riov;
		sniov = 1;
		rniov = 2;
		break;
	}

	case DIOCRADDTABLES:
	case DIOCRDELTABLES:
	case DIOCRGETTABLES:
	case DIOCRGETTSTATS:
	case DIOCRCLRTSTATS:
	case DIOCRADDADDRS:
	case DIOCRDELADDRS:
	case DIOCRSETADDRS:
	case DIOCRGETADDRS:
	case DIOCRGETASTATS:
	case DIOCRCLRASTATS:
	case DIOCRTSTADDRS:
	case DIOCRSETTFLAGS:
	case DIOCRINADEFINE:
	{
		struct pfioc_table *io = (struct pfioc_table *)data;

		SETIOV(&siov[1], io, sizeof(*io));
		SETIOV(&siov[2], io->pfrio_buffer, io->pfrio_size * io->pfrio_esize);

		siovp = riovp = siov;
		sniov = rniov = 2;
		break;
	}

	default:
		return ioctl(fd, cmd, data);
	}

	/* The following may set the same iov twice if siovp == riovp */
	SETIOV(siovp, &msg, sizeof(msg)); /* msg.o same size as msg.i */
	SETIOV(riovp, &msg, sizeof(msg)); /* msg.o same size as msg.i */
	sniov++;
	rniov++;

	msg.i.type = _IO_DEVCTL;
	msg.i.combine_len = sizeof msg.i;
	msg.i.dcmd = cmd;
	msg.i.nbytes = IOCPARM_LEN((unsigned)cmd);
	msg.i.zero = 0;

	if ((ret = MsgSendv_r(fd, siovp, sniov, riovp, rniov)) != EOK) {
		errno = -ret;
		return -1;
	}

	if (cmd == CIOCGSESSION) {
		switch (sop->cipher) {
		case 0:
			break;
		case CRYPTO_AES_CBC:
#ifdef __QNXNTO__
		case CRYPTO_AES_CBC_HW:
		case CRYPTO_AES_CTR_HW:
#endif
			sop->ses |= (0x0010000000000000ULL);  /* IV 16 bytes */
			break;
		case CRYPTO_NULL_CBC:
			sop->ses |= (0x0004000000000000ULL);  /* IV 4 bytes */
			break;
		case CRYPTO_ARC4:
			sop->ses |= (0x0001000000000000ULL);  /* IV 1 bytes */
			break;
		case CRYPTO_DES_CBC:
		case CRYPTO_3DES_CBC:
		case CRYPTO_BLF_CBC:
		case CRYPTO_CAST_CBC:
		case CRYPTO_SKIPJACK_CBC:
		default:
			sop->ses |= (0x0008000000000000ULL);   /* IV 8 bytes */
			break;
		}

		switch (sop->mac) {
		case 0:
			break;
		case CRYPTO_MD5:
			sop->ses |= (0x0000001000000000ULL);   /* 16 bytes */
			break;
		case CRYPTO_SHA1:
			sop->ses |= (0x0000001400000000ULL);   /* 20 bytes */
			break;
		case CRYPTO_NULL_HMAC:
		case CRYPTO_MD5_HMAC:
		case CRYPTO_SHA1_HMAC:
		case CRYPTO_SHA2_HMAC:
		case CRYPTO_RIPEMD160_HMAC:
		default:
			sop->ses |= (0x0000000C00000000ULL);   /* 12 bytes */
			break;
		}
	}

	return 0;
}

#if defined(__QNXNTO__) && defined(__USESRCVERSION)
#include <sys/srcversion.h>
__SRCVERSION("$URL: http://svn.ott.qnx.com/product/branches/6.6.0/trunk/lib/socket/ioctlsocket.c $ $Rev: 776630 $")
#endif
