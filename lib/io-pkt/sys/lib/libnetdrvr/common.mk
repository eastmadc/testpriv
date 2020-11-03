ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)

define PINFO
PINFO DESCRIPTION = Support library for developing network drivers
endef

IOPKT_MK= ../../../../../io-pkt.mk
include $(IOPKT_MK)

PRE_TARGET+= $(IOPKT_ROOT)/sys/nw_tls.h $(IOPKT_ROOT)/sys/nw_sync.h

INSTALLDIR=usr/lib
NAME=netdrvr
USEFILE=

EXTRA_INCVPATH+=	$(IOPKT_ROOT)/sys

include $(MKFILES_ROOT)/qtargets.mk
