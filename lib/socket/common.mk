# 
# Copyright 2007, QNX Software Systems. All Rights Reserved.
# 
# You must obtain a written license from and pay applicable
# license fees to QNX Software Systems before you may reproduce,
# modify or distribute this software, or any work that includes
# all or part of this software.   Free development licenses are
# available for evaluation and non-commercial purposes.  For more
# information visit http://licensing.qnx.com or email
# licensing@qnx.com.
# 
# This file may contain contributions from others.  Please review
# this entire file for other proprietary rights or license notices,
# as well as the QNX Development Suite License Guide at
# http://licensing.qnx.com/license-guide/ for other information.
# 

ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)

export BISON_SIMPLE=$(QNX_HOST)/usr/share/bison/bison.simple

define PINFO
PINFO DESCRIPTION=Network sockets library
endef

PRE_TARGET = .pre_hinstall
include ../../seedhdr.mk
include ../../compat.mk
SOCKROOT:=$(call abspath_compat, $(CURDIR)/../..)
IOPKT_ROOT:=$(call abspath_compat, $(CURDIR)/../../../io-pkt)

empty:=
space:=$(empty) $(empty)
ISMIPS:= $(filter mips,$(subst /,$(space),$(patsubst $(SOCKROOT)%,%, $(CURDIR))))

GCCVER:=	$(if $(GCC_VERSION),$(GCC_VERSION),\
    $(shell qcc -V 2>&1 | grep default | sed -e 's/,.*//'))

ifneq ($(ISMIPS),)
    ifeq ($(filter 2.% 3.%, $(strip $(GCCVER))),)
        # This didn't work on mips with older linker.  Hopefully
	# it works with 4.2 tools.  See PRs 15888, 15986, 16878.
	LDFLAGS+= -Wl,--version-script -Wl,$(PROJECT_ROOT)/libsocket.ver
    endif
    # This one is to prevent small data sections from overflowing and
    # it looks like it'll have to stick around.
    CCFLAGS+= -Wc,-G0
else
LDFLAGS+= -Wl,--version-script -Wl,$(PROJECT_ROOT)/libsocket.ver
endif

# Defining INCVPATH early shorts the default of all SRCVPATH
# which is overkill here.
INCVPATH = $(empty)

SO_VERSION = 3


EXTRA_OBJS += nslexer.o nsparser.o

CCFLAGS+=	-Wp,-include \
		-Wp,$(PROJECT_ROOT)/cdefs_bsd.h
CCFLAGS+=	-Wall -Wpointer-arith	\
		-Wmissing-prototypes -Werror
CCFLAGS+=	-DINET6 -D_LIBSOCKET	\
		-D_REENTRANT -DUSE_POLL
# net/getnameinfo.c net/rcmd.c
CCFLAGS+= 	-DBSD4_4
# res_data.c / res_compat.c
CCFLAGS+=	-DCOMPAT__RES
CCFLAGS+=	-Wno-unused-but-set-variable
CCFLAGS+=	-Wno-uninitialized	# PR135638
CCFLAGS+=	-fno-strict-aliasing	# PR135638
ifndef DISABLE_MFIB
CCFLAGS += -DQNX_MFIB
endif
EXTRA_SRCVPATH =		\
	$(PROJECT_ROOT)/inet	\
	$(PROJECT_ROOT)/net	\
	$(PROJECT_ROOT)/resolve	\
	$(PROJECT_ROOT)/isc	\
	$(PROJECT_ROOT)/nameser	\
	$(PROJECT_ROOT)/rpc	\
	$(PROJECT_ROOT)/gen

EXTRA_INCVPATH+= $(PROJECT_ROOT)/include

PRE_TARGET+=						\
	$(PROJECT_ROOT)/net/nsparser.c			\
	$(PROJECT_ROOT)/net/nslexer.c

EXTRA_CLEAN =						\
	$(PROJECT_ROOT)/net/nsparser.c			\
	$(PROJECT_ROOT)/net/nslexer.c			\
	$(PROJECT_ROOT)/net/nsparser.h






# The idea is to eventually move the ones derived from
# NetBSD back to where they are located in the NetBSD
# tree.  They'll still have to be cleaned up to follow
# the QNX public header rules but they should be easier
# to find and their lineage should be more obvious.

# ones under $(PROJECT_ROOT)/public/
INCS_LIBSOCKET_PUBLIC += \
	net80211/ieee80211_var.h \
	net80211/_ieee80211.h \
	net80211/ieee80211_netbsd.h \
	net80211/ieee80211.h \
	net80211/ieee80211_radiotap.h \
	net80211/ieee80211_rssadapt.h \
	net80211/ieee80211_sysctl.h \
	net80211/ieee80211_proto.h \
	net80211/ieee80211_node.h \
	net80211/ieee80211_crypto.h \
	net80211/ieee80211_ioctl.h \
	arpa/ftp.h \
	arpa/nameser_compat.h \
	arpa/inet.h \
	arpa/tftp.h \
	arpa/telnet.h \
	arpa/nameser.h \
	protocols/rwhod.h \
	protocols/routed.h \
	nfs/rpcv2.h \
	net/if_gre.h \
	net/if_media.h \
	net/route.h \
	net/if_arp.h \
	net/if.h \
	net/zlib.h \
	net/if_ieee1394.h \
	net/bpf.h \
	net/radix.h \
	net/radix_mpath.h \
	net/if_types.h \
	net/ifdrvcom.h \
	net/netbyte.h \
	net/cacheline.h \
	net/if_dl.h \
	net/dlt.h \
	net/if_tun.h \
	net/if_gif.h \
	net/pfkeyv2.h \
	net/if_vlanvar.h \
	net/if_ether.h \
	net/if_ipsec.h \
	net/ethertypes.h \
	net/pfil.h \
	net/bpfdesc.h \
	netinet6/in6_var.h \
	netinet6/in6_pcb.h \
	netinet6/ipsec.h \
	netinet6/pim6_var.h \
	netinet6/ip6_var.h \
	netinet6/udp6.h \
	netinet6/nd6.h \
	netinet6/udp6_var.h \
	netinet6/raw_ip6.h \
	netinet6/ah.h \
	netinet6/in6.h \
	netinet6/scope6_var.h \
	netinet6/ip6_mroute.h \
	netkey/key_var.h \
	netkey/key.h \
	netkey/keysock.h \
	netkey/keydb.h \
	netkey/key_debug.h \
	altq/altq_priq.h \
	altq/altq.h \
	altq/altq_afmap.h \
	altq/altq_hfsc.h \
	altq/altq_classq.h \
	altq/altq_cdnr.h \
	altq/altq_var.h \
	altq/altq_blue.h \
	altq/altq_rio.h \
	altq/altq_wfq.h \
	altq/if_altq.h \
	altq/altq_rmclass.h \
	altq/altq_fifoq.h \
	altq/altq_flowvalve.h \
	altq/altq_cbq.h \
	altq/altq_jobs.h \
	altq/altq_red.h \
	altq/altq_rmclass_debug.h \
	netinet/ip_carp.h \
	netinet/udp_var.h \
	netinet/in.h \
	netinet/icmp6.h \
	netinet/tcp_timer.h \
	netinet/if_inarp.h \
	netinet/in_pcb_hdr.h \
	netinet/udp.h \
	netinet/in_pcb.h \
	netinet/tcp_fsm.h \
	netinet/pim_var.h \
	netinet/ip_ecn.h \
	netinet/ip6.h \
	netinet/tcp_seq.h \
	netinet/icmp_var.h \
	netinet/tcp_var.h \
	netinet/ip_mroute.h \
	netinet/igmp_var.h \
	netinet/in_systm.h \
	netinet/in_var.h \
	netinet/tcpip.h \
	netinet/ip_icmp.h \
	netinet/tcp_debug.h \
	netinet/pim.h \
	netinet/tcp.h \
	netinet/in_proto.h \
	netinet/igmp.h \
	netinet/ip_var.h \
	netinet/ip.h \
	netipsec/ah_var.h \
	netipsec/esp_var.h \
	netipsec/ipcomp_var.h \
	netipsec/ipip_var.h \
	netipsec/ipsec_var.h \
	netipsec/keydb.h \
	snmp/parse.h \
	snmp/view.h \
	snmp/snmp_client.h \
	snmp/snmp.h \
	snmp/snmp_impl.h \
	snmp/acl.h \
	snmp/party.h \
	snmp/asn1.h \
	snmp/context.h \
	snmp/md5.h \
	snmp/snmp_api.h \
	snmp/mib.h \
	sys/tree.h \
	sys/selinfo.h \
	sys/dcmd_ip.h \
	sys/sysctl.h \
	sys/protosw.h \
	sys/malloc.h \
	sys/sockmsg.h \
	sys/unpcb.h \
	sys/mbuf.h \
	sys/dcmd_pppoe.h \
	sys/ds_msg.h \
	sys/callout.h \
	sys/un.h \
	sys/queue.h \
	sys/pppoe.h \
	sys/sockio.h \
	sys/pool.h \
	sys/socket.h \
	sys/socketvar.h \
	sys/target_nto_sock.h \
	nlist.h \
	resolv.h \
	kvm.h \
	nsswitch.h \
	ds.h \
	hesiod.h \
	ifaddrs.h \
	netdb.h \
	res_update.h

#ones under $(IOPKT_ROOT)/sys/
INCS_LIBSOCKET_SYS += net/agr/if_agrioctl.h netinet/if_ether.h net/if_srt.h net/if_tap.h

#ones under $(IOPKT_ROOT)/sys/opencrypto
INCS_LIBSOCKET_OPENCRYPTO += cryptodev.h

#ones under $(IOPKT_ROOT)/sys/dist/pf
INCS_LIBSOCKET_PF += net/if_pflog.h net/pfvar.h

define TARGET_HINSTALL_LIBSOCKET
        @-$(foreach hdr, $(INCS_LIBSOCKET_PUBLIC), \
	    $(CP_HOST) $(PROJECT_ROOT)/public/$(hdr) \
	    $(INSTALL_ROOT_HDR)/$(hdr);)

        @-$(foreach hdr, $(INCS_LIBSOCKET_SYS), \
	    $(CP_HOST) $(IOPKT_ROOT)/sys/$(hdr) \
	    $(INSTALL_ROOT_HDR)/$(hdr);)

# this one is weird as it comes from opencrypto but goes to crypto
        @-$(foreach hdr, $(INCS_LIBSOCKET_OPENCRYPTO), \
	    $(CP_HOST) $(IOPKT_ROOT)/sys/opencrypto/$(hdr) \
	    $(INSTALL_ROOT_HDR)/crypto/$(hdr);)

        @-$(foreach hdr, $(INCS_LIBSOCKET_PF), \
	    $(CP_HOST) $(IOPKT_ROOT)/sys/dist/pf/$(hdr) \
	    $(INSTALL_ROOT_HDR)/$(hdr);)

# link queue.h -> sys/queue.h (PR 58074)
	$(LN_HOST) sys/queue.h $(INSTALL_ROOT_HDR)/queue.h
endef

define TARGET_HUNINSTALL_LIBSOCKET
        @-$(foreach hdr, $(INCS_LIBSOCKET_PUBLIC) $(INCS_LIBSOCKET_SYS) $(INCS_LIBSOCKET_PF), \
	    $(RM_HOST) $(INSTALL_ROOT_HDR)/$(hdr);)

        @-$(foreach hdr, $(INCS_LIBSOCKET_OPENCRYPTO), \
	    $(RM_HOST) $(INSTALL_ROOT_HDR)/crypto/$(hdr);)
endef




# The following two ifndefs should be
# able to be removed once the defines
# for FLEX_HOST, BISON_HOST have made
# there way into the various qconfig.mk
# files.  PR 53542.
ifndef FLEX_HOST
    FLEX_HOST=	$(QNX_HOST)/usr/bin/flex
endif

ifndef BISON_HOST
    BISON_HOST=	$(QNX_HOST)/usr/bin/bison
endif



COMMON_ORG=IO_PKT_LIBSOCKET
include $(IOPKT_ROOT)/common/srcs_common.mk

include $(MKFILES_ROOT)/qtargets.mk

clean: .pre_huninstall

# override TARGET_HINSTALL from qmacros.mk
define TARGET_HINSTALL
$(TARGET_HINSTALL_LIBSOCKET)
endef


# override TARGET_HUNINSTALL from qmacros.mk
define TARGET_HUNINSTALL
$(TARGET_HUNINSTALL_LIBSOCKET)
endef

$(PROJECT_ROOT)/net/nsparser.c: $(PROJECT_ROOT)/net/nsparser.y
	$(BISON_HOST) -p_nsyy -d -o $@ $<

$(PROJECT_ROOT)/net/nslexer.c: $(PROJECT_ROOT)/net/nslexer.l
	$(FLEX_HOST) -P_nsyy -t $< | sed -e '/YY_BUF_SIZE/s/16384/1024/' > $@

$(PROJECT_ROOT)/public/crypto/cryptodev.h: $(PROJECT_ROOT)/inc/opencrypto/cryptodev.h
	$(CP_HOST) $< $@

# flex issue.  PR 24736
FLAGS_nslexer=			-Wno-unused
# See what ALIGNBYTES value the "kernel" is compiled with.
FLAGS___cmsg_alignbytes=	-Wp,-include -Wp,$(IOPKT_ROOT)/sys/alignbytes.h

# getaddrinfo wants resolv/res_init_pps.h
FLAGS_getaddrinfo=		-I$(PROJECT_ROOT)/resolve
