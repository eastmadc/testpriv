ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)

define PINFO
PINFO DESCRIPTION=Packet Filter loadable stack module.
endef

IOPKT_MK= ../../../../../../io-pkt.mk
include $(IOPKT_MK)

NAME=lsm-pf
USEFILE=$(PROJECT_ROOT)/pf.use

# Defining INCVPATH early shorts the default of all SRCVPATH
# which is overkill here.

INCVPATH+=i		$(PROJECT_ROOT)
EXTRA_INCVPATH+=	$(IOPKT_ROOT)/sys
EXTRA_SRCVPATH+=	$(IOPKT_ROOT)/sys/dist/pf/net

# We want to always include qnx.h, it should be
# -Wp,"-include $(SYS_ROOT)/qnx.h", but
# qcc/cc doesn't seem to support this so... 
CCFLAGS+=	-Wp,-include -Wp,$(IOPKT_ROOT)/sys/qnx.h

CCFLAGS+=	-D_KERNEL -D_LKM -DINET -DALTQ
ifndef MPATH_OFF
CCFLAGS+= -DRADIX_MPATH
endif

ifndef DISABLE_MFIB
CCFLAGS += -DQNX_MFIB
endif

CCFLAGS+=	-Wpointer-arith -Wmissing-prototypes -Werror -Wall
#CCFLAGS+=	-Wstrict-prototypes
CCFLAGS+=	-Wno-uninitialized
CCFLAGS+=	-Wno-unused-but-set-variable
CCFLAGS+=	-Wno-address
CCFLAGS+=	-fno-strict-aliasing # PR135638
LDFLAGS+=	-Wl,--allow-shlib-undefined

include $(MKFILES_ROOT)/qmacros.mk

ifneq ($(filter v6,$(VARIANTS)),)
	CCFLAGS+=	-DINET6
endif

include $(MKFILES_ROOT)/qtargets.mk
