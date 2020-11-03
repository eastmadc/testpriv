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

IOPKT_MK= ../../../../../io-pkt.mk
include $(IOPKT_MK)

CPU=arm

# For pre 6.4.2 builds
EXTRA_SILENT_VARIANTS=v7

NAME=		kern
INSTALLDIR=	/dev/null

# Defining INCVPATH early shorts the default of all SRCVPATH
# which is overkill here.

INCVPATH= $(PRODUCT_ROOT)
EXTRA_INCVPATH+=						\
	$(IOPKT_ROOT)/sys/					\
	$(IOPKT_ROOT)/sys/sys-nto

EXTRA_SRCVPATH = $(IOPKT_ROOT)/sys/lib/libkern

CCFLAGS+=	-Wp,-include -Wp,$(IOPKT_ROOT)/sys/qnx.h

CCFLAGS+=	-D_KERNEL

CCFLAGS+=	-O2 -fno-strict-aliasing

COMMON_ORG=IO_PKT_LIBKERN
include $(IOPKT_ROOT)/common/srcs_common.mk
	

include $(MKFILES_ROOT)/qtargets.mk

install:
