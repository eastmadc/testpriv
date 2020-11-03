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

define PINFO
PINFO DESCRIPTION=TCP\/IP protocol module.
endef

IOPKT_MK= ../../../../io-pkt.mk
include $(IOPKT_MK)

.PHONY: libkern

include tgt.mk


NAME=io-pkt
empty:=
space:=$(empty) $(empty)
USEFILE= $(PRODUCT_ROOT)/$(NAME)-$(subst $(space),-,$(filter-out be le spe v7, $(VARIANT_LIST))).use

ISMIPS:= $(filter mips,$(subst /,$(space),$(patsubst $(IOPKT_ROOT)%,%, $(CURDIR))))
ISSH:= $(filter sh,$(subst /,$(space),$(patsubst $(IOPKT_ROOT)%,%, $(CURDIR))))
ISX86:= $(filter x86,$(subst /,$(space),$(patsubst $(IOPKT_ROOT)%,%, $(CURDIR))))
ISARM:= $(filter arm,$(subst /,$(space),$(patsubst $(IOPKT_ROOT)%,%, $(CURDIR))))

GCCVER:=	$(if $(GCC_VERSION),$(GCC_VERSION),\
    $(shell qcc -V 2>&1 | grep default | sed -e 's/,.*//'))

ifneq ($(filter 4.2.% 4.3.% 4.4.%, $(strip $(GCCVER))),)
    CCFLAGS+=	-Wno-pointer-sign
endif

PIESUPP:= $(shell qcc -nopie 2>&1 | grep unknown)

ifneq ($(ISMIPS),)
    ifeq (2.95.3,$(strip $(GCCVER)))
	# Section attribute isn't supported in mips 2.95.3
	# This assumes 3.3.5 is always available when 2.95.3 is.
	# If already at 3.3.5 or 4.x, leave alone.
	GCC_VERSION=3.3.5
    endif
endif

ifeq ($(ISARM),arm)
CCFLAGS+= -O2 -fno-strict-aliasing
endif

ifeq ($(ISX86),x86)
CCFLAGS+= -O2 -fno-strict-aliasing
endif

# General source

# Defining INCVPATH early shorts the default of all SRCVPATH
# which is overkill here.

INCVPATH = $(PRODUCT_ROOT)
EXTRA_INCVPATH+=						\
	$(PRODUCT_ROOT)/sys-nto					\
	$(PRODUCT_ROOT)/target/$(CPU)				\
	$(PRODUCT_ROOT)/../lib/socket/public			\
	$(PRODUCT_ROOT)/../lib/socket/inc

EXTRA_SRCVPATH =							\
	$(PRODUCT_ROOT) $(PRODUCT_ROOT)/kern $(PRODUCT_ROOT)/net	\
	$(PRODUCT_ROOT)/netinet						\
	$(PRODUCT_ROOT)/altq $(PRODUCT_ROOT)/compat/common		\
	$(PRODUCT_ROOT)/secmodel/bsd44


# Get qnx.h up front.
ifeq (2.95.3,$(strip $(GCCVER)))
CCFLAGS +=  -Wp,-include -Wp,$(PRODUCT_ROOT)/qnx.h
else
# No space for qcc
CCFLAGS +=  -Wp,-includeqnx.h  
endif
 

# gcc sometime after 2.95.3 added a builtin log()
CCFLAGS += -fno-builtin-log
# disable gcc mapping of printf -> puts as we have
# our own printf that goes to slog.
CCFLAGS += -fno-builtin-printf
CCFLAGS += -Wno-unused-but-set-variable -Wno-pointer-sign


PRE_TARGET+=	libkern
PRE_CLEAN=		$(MAKE) -C ../libkern clean


PRE_TARGET+=	$(CURDIR)/bridge.h			\
		$(CURDIR)/gre.h				\
		$(CURDIR)/gif.h				\
		$(CURDIR)/pppoe.h $(CURDIR)/opt_pppoe.h	\
		$(CURDIR)/opt_ipsec.h			\
		$(CURDIR)/srt.h				\
		$(CURDIR)/tun.h				\
		$(CURDIR)/tap.h


# Common src.  Could split this up a little better...
SRCS =	altq_afmap.c altq_blue.c altq_cbq.c altq_cdnr.c	\
	altq_conf.c altq_fifoq.c altq_hfsc.c altq_localq.c	\
	altq_priq.c altq_red.c altq_rio.c altq_rmclass.c altq_subr.c	\
	altq_wfq.c blockop.c bpf.c bpf_filter.c bsd-comp.c	\
	current_time.c device_qnx.c if.c if_arp.c if_ethersubr.c	\
	if_loop.c if_media.c if_vlan.c in_cksum.c init_main.c	\
	init_sysctl.c interrupt.c ionet_compat.c ip_ecn.c ip_encap.c	\
	kern_auth.c kern_clock.c kern_descrip.c kern_event.c	\
	kern_kthread.c kern_malloc.c kern_prot.c kern_resource.c	\
	kern_subr.c kern_synch.c kern_sysctl.c kern_time.c	\
	kern_timeout.c \
	nw_thread.c pfil.c proc.c quiesce.c radix.c raw_cb.c	\
	raw_usrreq.c receive.c route.c rtsock.c secmodel_bsd44.c	\
	secmodel_bsd44_logic.c secmodel_bsd44_securelevel.c	\
	secmodel_bsd44_suser.c slcompress.c stubs.c subr_autoconf.c	\
	subr_evcnt.c subr_once.c subr_pool.c sys_generic.c	\
	sys_socket.c tpass.c tty.c tty_subr.c	\
	uipc_domain.c uipc_mbuf.c uipc_mbuf2.c uipc_proto.c	\
	uipc_socket.c uipc_socket2.c uipc_syscalls.c	\
	uipc_syscalls_43.c uipc_usrreq.c zlib.c uipc_syscalls_40.c \
	link_proto.c subr_device.c portalgo.c

#QNX
SRCS+=	copy.c ioctl_long.c main.c msg.c nlist.c notify.c nw_dl.c \
	radix_mpath.c in_pcbunbind.c if_extra.c if_tcp_conf.c


#PF
#EXTRA_SRCVPATH+=        $(PRODUCT_ROOT)/dist/pf/net
#SRCS+=	pf_ioctl.c pf.c pf_if.c pf_table.c pf_norm.c pf_osfp.c if_pflog.c


SRCS_TCP=	tcp_input.c tcp_output.c tcp_sack.c tcp_subr.c	\
	tcp_timer.c tcp_usrreq.c tcp_congctl.c
ifdef TCP_DEBUG
SRCS_TCP+= tcp_debug.c
endif
SRCS_UDP=	udp_usrreq.c


HASH=\#

ifdef NWBLD_INET
	PRE_TARGET+=	$(CURDIR)/opt_inet.h
	PRE_TARGET+=	$(CURDIR)/opt_mrouting.h
	PRE_TARGET+=	$(CURDIR)/opt_gateway.h
	EXTRA_SRCVPATH+=	$(PRODUCT_ROOT)/netinet
	SRCS+= igmp.c in.c in_offload.c in_pcb.c in_proto.c		\
		ip_icmp.c ip_id.c ip_input.c ip_output.c raw_ip.c
	SRCS+= in4_cksum.c
#	SRCS+= in_selsrc.c

	ifdef NWBLD_MROUTING
		SRCS+= ip_mroute.c
		DEPOP_MROUTING="$(HASH)define MROUTING 1"
	else
		DEPOP_MROUTING="/* option \`MROUTING\' not defined */"
	endif

	ifdef NWBLD_GATEWAY
		SRCS+= ip_flow.c
		DEPOP_GATEWAY="$(HASH)define GATEWAY 1"
	else
		DEPOP_GATEWAY="/* option \`GATEWAY\' not defined */"
	endif

	ifndef NWBLD_OPT_INET
		NWBLD_OPT_INET="/* option \`IPSELSRC\' not defined */\n\
		    /* option \`TCP_REASS_COUNTERS\' not defined */\n\
		    /* option \`TCP_OUTPUT_COUNTERS\' not defined */\n\
		    /* option \`TCP_SIGNATURE\' not defined */"
	endif

	SRCS+=	$(SRCS_TCP) $(SRCS_UDP)
endif

# put netipsec/ in VPATH before netinet6/
ifdef NWBLD_FAST_IPSEC
	# as above with no IPSEC_NAT_T XXX fixme
	ifndef NWBLD_OPT_IPSEC
		NWBLD_OPT_IPSEC="$(HASH)define FAST_IPSEC 1\n\
		    $(HASH)define IPSEC_ESP 1\n\
		    $(HASH)define IPSEC_NAT_T 1\n\
		    $(HASH)ifndef QNXNTO_IPSEC_ALWAYS_ON\n\
		    $(HASH)define QNXNTO_IPSEC_ENABLED qnxnto_ipsec_enabled\n\
		    $(HASH)else\n\
		    $(HASH)define QNXNTO_IPSEC_ENABLED (1 /* CONSTCOND */)\n\
		    $(HASH)endif"
	endif
	EXTRA_SRCVPATH+= $(PRODUCT_ROOT)/netipsec
	SRCS+= ipsec.c ipsec_input.c ipsec_mbuf.c ipsec_output.c	\
		xform_ah.c xform_esp.c xform_ipcomp.c xform_ipip.c	\
		ipsec_netbsd.c key.c key_debug.c keysock.c

endif

ifdef NWBLD_OPENCRYPTO
	EXTRA_SRCVPATH+= $(PRODUCT_ROOT)/opencrypto
	SRCS+= criov.c crypto.c cryptodev.c cryptosoft.c xform.o	\
	    deflate.c
endif

ifdef NWBLD_INET6
	PRE_TARGET+=	$(CURDIR)/opt_inet.h
	PRE_TARGET+=	$(CURDIR)/opt_inet6.h
	ifndef NWBLD_OPT_INET6
		NWBLD_OPT_INET6="$(HASH)define RFC2292 1"
	endif
	EXTRA_SRCVPATH+= $(PRODUCT_ROOT)/netinet6
	SRCS+= dest6.c frag6.c icmp6.c in6.c in6_cksum.c in6_ifattach.c	\
		in6_offload.c in6_pcb.c in6_proto.c in6_src.c		\
		ip6_forward.c ip6_id.c ip6_input.c ip6_mroute.c		\
		ip6_output.c mld6.c nd6.c nd6_nbr.c nd6_rtr.c raw_ip6.c	\
		route6.c scope6.c udp6_output.c udp6_usrreq.c ip6_ifconf.c
	SRCS+=	$(SRCS_TCP) $(SRCS_UDP)
	EXTRA_SRCVPATH+=	$(PRODUCT_ROOT)/netinet
endif

ifdef NWBLD_CRYPTOS
	EXTRA_SRCVPATH+= \
		$(PRODUCT_ROOT)/crypto/arc4		\
		$(PRODUCT_ROOT)/crypto/des		\
		$(PRODUCT_ROOT)/crypto/blowfish		\
		$(PRODUCT_ROOT)/crypto/cast128		\
		$(PRODUCT_ROOT)/crypto/rijndael		\
		$(PRODUCT_ROOT)/crypto/skipjack
	SRCS+= arc4.c
	SRCS+= des_ecb.c des_setkey.c des_enc.c # des_cbc.c not needed ATM
	SRCS+= bf_ecb.c bf_enc.c bf_cbc.c bf_skey.c
	SRCS+= cast128.c
	SRCS+= rijndael-alg-fst.c rijndael-api-fst.c rijndael.c
	SRCS+= skipjack.c
endif

ifdef NWBLD_WLAN
	EXTRA_SRCVPATH+= $(PRODUCT_ROOT)/net80211
	SRCS+= ieee80211.c ieee80211_amrr.c				\
		ieee80211_crypto.c ieee80211_crypto_ccmp.c		\
		ieee80211_crypto_none.c ieee80211_crypto_tkip.c		\
		ieee80211_crypto_wep.c ieee80211_input.c		\
		ieee80211_ioctl.c ieee80211_netbsd.c ieee80211_node.c	\
		ieee80211_output.c ieee80211_proto.c			\
		ieee80211_rssadapt.c ieee80211_xauth.c
# not currently needed
#	SRCS+= ieee80211_acl.c 
endif

ifdef NWBLD_BRIDGE
	PRE_TARGET+=	$(CURDIR)/opt_bridge_ipf.h
	ifndef NWBLD_OPT_BRIDGE_IPF
		NWBLD_OPT_BRIDGE_IPF="/* option \`BRIDGE_IPF\' not defined */"
	endif
	SRCS+= if_bridge.c bridgestp.c
endif

ifdef NWBLD_GRE
	PRE_TARGET+=	$(CURDIR)/opt_gre.h
	ifndef NWBLD_OPT_GRE
		NWBLD_OPT_GRE="/* option \`GRE_DEBUG\' not defined */"
	endif
	SRCS+= if_gre.c
	ifdef NWBLD_INET
		SRCS+= ip_gre.c
	endif
endif

ifdef NWBLD_GIF
	SRCS+= if_gif.c
	ifdef NWBLD_INET
		SRCS+= in_gif.c
	endif
	ifdef NWBLD_INET6
		SRCS+= in6_gif.c
	endif
endif

ifdef NWBLD_PPP
	PRE_TARGET+=	$(CURDIR)/ppp.h $(CURDIR)/opt_ppp.h
	SRCS+= if_ppp.c if_spppsubr.c ppp-deflate.c ppp_tty.c 
	ifndef NWBLD_OPT_PPP
		NWBLD_OPT_PPP="/* option \`PPP_FILTER\' not defined */\n\
		    $(HASH)define PPP_BSDCOMP 1\n\
		    $(HASH)define PPP_DEFLATE 1\n\
		    $(HASH)define QNX_MULTILINKPPP 1"
	endif
	ifdef NWBLD_PPP_MPPE
		SRCS+= ppp_mppe_compress.c
	endif
endif

ifdef NWBLD_PPPOE
	SRCS+= if_pppoe.c
	ifndef NWBLD_OPT_PPPOE
		NWBLD_OPT_PPPOE="/* option \`PPPOE_TERM_UNKNOWN_SESSIONS\' not defined */\n\
		    $(HASH)define PPPOE_SERVER 1"
	endif
endif

ifdef NWBLD_SRT
	SRCS+= if_srt.c
endif

ifdef NWBLD_TUN
	SRCS+= if_tun.c
endif

ifdef NWBLD_TAP
	SRCS+= if_tap.c
endif

SRCS+= if_ipsec.c


DB+=-D_KERNEL -D_KERNEL_OPT -DLKM

DEFFILE = asmoff.def
ASMOFF_FORMAT_x86=cpp

# Until we get the full kern/kern_malloc.c going with the kmembucket stuff
DB += -DSIMPLE_MALLOC_BSD

# Use the bsd one instead of the libc version
DB += -DRANDOM_BSD

# Maxusers
DB += -DMAXUSERS=32

ifdef DEBUG
DB += -DKMEMSTATS
endif

ifneq ($(findstring -DNO_UNIX_DOMAIN, $(DB)),)
EXCLUDE_OBJS += uipc_usrreq.o uipc_proto.o
endif

# SIMPLE_MALLOC_BSD needs KMEMSTATS (see sys/malloc_bsd.h)
ifneq ($(findstring -DSIMPLE_MALLOC_BSD, $(DB)),)
ifeq ($(findstring -DKMEMSTATS, $(DB)),)
DB += -DKMEMSTATS
endif
endif

ifeq ($(findstring -DRANDOM_BSD, $(DB)),)
EXCLUDE_OBJS += random.o
endif

ifndef MPATH_OFF
DB += -DRADIX_MPATH
endif

ifdef TCP_DEBUG
DB+= -DTCP_DEBUG=1
endif

ifndef DISABLE_MFIB
DB += -DQNX_MFIB
endif


# x86 has specific versions of bf_cbc.S and bf_enc.S (EXTRA_SRCVPATH_x86
# below).  bf_enc.S will include one of bf_enc_586.S or bf_enc_686.S
# (default bf_enc_686.S) so exclude them as well
EXCLUDE_x86+=	bf_enc_586.o bf_enc_686.o
EXCLUDE_x86+=	in4_cksum.o in6_cksum.o
EXCLUDE_arm+=	in_cksum.o in4_cksum.o
EXCLUDE_ppc+=	in4_cksum.o
EXCLUDE_OBJS+=	$(EXCLUDE_$(CPU))

SRCS_arm += in_cksum_arm.S sched_arm.S
SRCS += $(SRCS_$(CPU))

# to pull in the x86 specific versions of bf_cbc.S and bf_enc.S
EXTRA_SRCVPATH_x86+=	$(PRODUCT_ROOT)/crypto/blowfish/x86
# to pull in the x86 specific versions of des_enc.S
EXTRA_SRCVPATH_x86+=	$(PRODUCT_ROOT)/crypto/des/x86
EXTRA_SRCVPATH+=	$(EXTRA_SRCVPATH_$(CPU))





STATIC_DRIVERS = $(STATIC_DRIVERS_QNX) $(STATIC_DRIVERS_NETBSD)

STATIC_DRIVER_LIBS =  $(addprefix devnp-, $(STATIC_DRIVERS))

EXTRA_CLEAN+= $(PRODUCT_ROOT)/static_drvrs.h
EXTRA_CLEAN+= $(PRE_TARGET)

LIBS += $(STATIC_DRIVER_LIBS)

# Headers that must be installed to allow drivers to build
INCS_IOPKT += \
	blockop.h \
	device_qnx.h \
	nw_datastruct.h \
	nw_defs.h \
	nw_dl.h \
	nw_intr.h \
	nw_pci.h \
	nw_sig.h \
	nw_thread.h \
	nw_tls.h \
	iopkt_driver.h \
	quiesce.h \
	receive.h \
	siglock.h \
	dev/mii/miivar.h \
	dev/pci/pcidevs.h \
	lib/libkern/libkern.h \
	machine/ansi.h \
	machine/bswap.h \
	machine/cpu.h \
	machine/endian.h\
	machine/intr.h \
	machine/param.h \
	machine/proc.h \
	machine/types.h \
	sys/cdefs_bsd.h \
	sys/cdefs_elf.h \
	sys/device.h \
	sys/evcnt.h \
	sys/event.h \
	sys/inttypes.h \
	sys/io-pkt.h \
	sys/kthread.h \
	sys/lock.h \
	sys/lwp.h \
	sys/mallocvar.h \
	sys/nw_cpu_atomic.h \
	sys/proc.h \
	sys/resourcevar.h \
	sys/rnd.h \
	sys/siginfo_bsd.h \
	sys/signal.h \
	sys/signalvar.h \
	sys/syslog.h \
	sys/systm.h \
	sys/types_bsd.h \
	sys-nto/bpfilter.h \
	target/arm/nw_cpu_atomic.h \
	target/mips/nw_cpu_atomic.h \
	target/ppc/nw_cpu_atomic.h \
	target/sh/nw_cpu_atomic.h \
	target/x86/nw_cpu_atomic.h \
	uvm/uvm_extern.h \
	uvm/uvm_param.h

INCS_IOPKT4SYS += \
	sys/dcmd_io-net.h \
	sys/io-net.h

define TARGET_HINSTALL_IOPKT
	@-$(foreach hdr, $(INCS_IOPKT), \
		$(CP_HOST) $(PROJECT_ROOT)/../$(hdr) $(INSTALL_ROOT_HDR)/io-pkt/$(hdr);)
	@-$(foreach hdr, $(INCS_IOPKT4SYS), \
		$(CP_HOST) $(PROJECT_ROOT)/../$(hdr) $(INSTALL_ROOT_HDR)/$(hdr);)
	echo $(PUBLIC_INCVPATH)

endef

define TARGET_HUNINSTALL_IOPKT
	@-$(foreach hdr, $(INCS_IOPKT), $(RM_HOST) $(INSTALL_ROOT_HDR)/io-pkt/$(hdr);)
	@-$(foreach hdr, $(INCS_IOPKT4SYS), $(RM_HOST) $(INSTALL_ROOT_HDR)/$(hdr);)

endef




#Define a PUBLIC_INVPATH so that hinstall will do something.  We override the
#TARGET_HINSTALL AND TARGET_HUNINSTALL to do what we want as opposed to what the
#default macros do
PUBLIC_INCVPATH=$(PROJECT_ROOT)

include $(MKFILES_ROOT)/qtargets.mk
PRE_TARGET+= hinstall
PRE_CLEAN+= huninstall



# override TARGET_HINSTALL from qmacros.mk
define TARGET_HINSTALL
$(TARGET_HINSTALL_IOPKT)
endef


# override TARGET_HUNINSTALL from qmacros.mk
define TARGET_HUNINSTALL
$(TARGET_HUNINSTALL_IOPKT)
endef




LIBKERN=	$(filter le be spe v7, $(VARIANT_LIST))
LIBKERNDIR=	a$(if $(LIBKERN),.$(subst $(space),.,$(strip $(LIBKERN))))
EXTRA_LIBVPATH+=	$(PROJECT_ROOT)/$(CPU)/libkern/$(LIBKERNDIR)
LIBS+=			kern

INSTALLDIR = sbin

include $(PRODUCT_ROOT)/static_drvr_qnx.mk	# Where STATIC_DRIVERS_QNX is defined
include $(PRODUCT_ROOT)/static_drvr_netbsd.mk	# Where STATIC_DRIVERS_NETBSD is defined

# If we're not linking in drivers that need the following,
# shouldn't bring anything in.
LIBS += cache netdrvr

# ECHO_HOST is missing a "-e" on Linux
ifeq (Linux,$(shell uname -s))
	ECHO_HOST = /bin/echo -e
endif

ifeq (Darwin,$(shell uname -s))
	ECHO_HOST = echo
endif

define ADD_DRVR_EXTERN
	'\t\t\t\\\n\textern struct nw_dll_syms $(drvr)_syms;'
endef

define ADD_DRVR_SYM
	'\t\t\t\\\n\t{"devnp-$(drvr).so", &$(drvr)_syms},'
endef

libkern:
	$(MAKE) -C ../libkern



nw_dl.o: $(PRODUCT_ROOT)/static_drvrs.h

$(PRODUCT_ROOT)/static_drvrs.h: $(PRODUCT_ROOT)/static_drvr_qnx.mk $(PRODUCT_ROOT)/static_drvr_netbsd.mk
	@$(ECHO_HOST) '\n**** Building $(notdir $@)\n'
	@$(ECHO_HOST)  >$@ '/*'
	@$(ECHO_HOST)  >>$@ ' * Auto generated file (see common.mk).'
	@$(ECHO_HOST)  >>$@ ' * Edit static_drvr*.mk to alter bound driver list.'
	@$(ECHO_HOST)  >>$@ ' */'
# Don't define them to anything if there are no static libs.
# This lets nw_dl.c use simple dlopen() etc.
	@$(if $(STATIC_DRIVER_LIBS), $(ECHO_HOST) >>$@ '#define STATIC_DRVR_EXTERNS\t\t' $(foreach drvr, $(STATIC_DRIVERS), $(ADD_DRVR_EXTERN)))
	@$(if $(STATIC_DRIVER_LIBS), $(ECHO_HOST) >>$@ '#define STATIC_DRVR_SYMS\t\t' $(foreach drvr, $(STATIC_DRIVERS), $(ADD_DRVR_SYM)))

$(CURDIR)/opt_inet.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_INET)
ifdef NWBLD_INET6
ifeq ($(CPU),x86)
	@$(ECHO_HOST) >>$@ "#define INET6_MD_CKSUM 1"
endif
	@$(ECHO_HOST) >>$@ "#define INET6 1"
endif
ifdef NWBLD_INET
	@$(ECHO_HOST) >>$@ "#define INET 1"
endif

$(CURDIR)/opt_ipsec.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_IPSEC)

$(CURDIR)/opt_inet6.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_INET6)

$(CURDIR)/opt_bridge_ipf.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_BRIDGE_IPF)

$(CURDIR)/bridge.h:
ifdef NWBLD_BRIDGE
	@$(ECHO_HOST) >$@ "#define NBRIDGE 1"
	@$(ECHO_HOST) >>$@ "void bridgeattach(int);"
else
	@$(ECHO_HOST) >$@ "#define NBRIDGE 0"
endif

$(CURDIR)/opt_gre.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_GRE)

$(CURDIR)/gre.h:
ifdef NWBLD_GRE
	@$(ECHO_HOST) >$@ "#define NGRE 1"
	@$(ECHO_HOST) >>$@ "void greattach(int);"
else
	@$(ECHO_HOST) >$@ "#define NGRE 0"
endif

$(CURDIR)/gif.h:
ifdef NWBLD_GIF
	@$(ECHO_HOST) >$@ "#define NGIF 1"
	@$(ECHO_HOST) >>$@ "void gifattach(int);"
else
	@$(ECHO_HOST) >$@ "#define NGIF 0"
endif

$(CURDIR)/opt_mrouting.h:
	@$(ECHO_HOST) >$@ $(DEPOP_MROUTING)

$(CURDIR)/opt_gateway.h:
	@$(ECHO_HOST) >$@ $(DEPOP_GATEWAY)

$(CURDIR)/ppp.h:
	@$(ECHO_HOST) >$@ "#define NPPP 1"

$(CURDIR)/opt_ppp.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_PPP)
ifdef NWBLD_PPP_MPPE
	@$(ECHO_HOST) >>$@ "#define PPP_MPPE        1"
endif

$(CURDIR)/pppoe.h:
ifdef NWBLD_PPPOE
	@$(ECHO_HOST) >$@ "#define NPPPOE 1"
else
	@$(ECHO_HOST) >$@ "#define NPPPOE 0"
endif

$(CURDIR)/opt_pppoe.h:
	@$(ECHO_HOST) >$@ $(NWBLD_OPT_PPPOE)

$(CURDIR)/srt.h:
ifdef NWBLD_SRT
	@$(ECHO_HOST) >$@ "#define NSRT 1"
	@$(ECHO_HOST) >>$@ "void srtattach(void);"
else
	@$(ECHO_HOST) >$@ "#define NSRT 0"
endif

$(CURDIR)/tun.h:
ifdef NWBLD_TUN
	@$(ECHO_HOST) >$@ "#define NTUN 1"
	@$(ECHO_HOST) >>$@ "void tunattach(int);"
else
	@$(ECHO_HOST) >$@ "#define NTUN 0"
endif

$(CURDIR)/tap.h:
ifdef NWBLD_TAP
	@$(ECHO_HOST) >$@ "#define NTAP 1"
	@$(ECHO_HOST) >>$@ "void tapattach(int);"
else
	@$(ECHO_HOST) >$@ "#define NTAP 0"
endif

CCFLAGS += $(DB)
CCFLAGS += -Wpointer-arith -Wmissing-prototypes -Werror -Wall
#CCFLAGS += -Wstrict-prototypes
CCFLAGS += -Wno-uninitialized
CCFLAGS += -fno-strict-aliasing -Wno-array-bounds # PR135638
CCFLAGS += -fno-PIE
LDFLAGS += -Wl,-E
ifeq ($(PIESUPP),)
LDFLAGS += -nopie
endif

ifneq ($(ISSH),)  # PR 64862
FLAGS_if_spppsubr += -O0
endif
FLAGS_kern_timeout+=	-D_CALLOUT_PRIVATE

CCVFLAG_g += -DDIAGNOSTIC
