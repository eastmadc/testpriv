ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)


IOPKT_MK= ../../../../../io-pkt.mk
include $(IOPKT_MK)

empty:=
space:=$(empty) $(empty)
ISMIPS:= $(filter mips,$(subst /,$(space),$(patsubst $(IOPKT_ROOT)%,%, $(CURDIR))))

GCCVER:=	$(if $(GCC_VERSION),$(GCC_VERSION),\
    $(shell qcc -V 2>&1 | grep default | sed -e 's/,.*//'))

ifneq ($(ISMIPS),)
    ifeq (2.95.3,$(strip $(GCCVER)))
	# Section attribute isn't supported in mips 2.95.3
	# This assumes 3.3.5 is always available when 2.95.3 is.
	# If already at 3.3.5 or 4.x, leave alone.
	GCC_VERSION=3.3.5
    endif
endif

EXTRA_INCVPATH +=					\
	$(IOPKT_ROOT)/sys $(IOPKT_ROOT)/sys/sys-nto	\
	$(IOPKT_ROOT)/sys/dev/qnx_inc			\
	$(IOPKT_ROOT)/sys/dev/lib			\
	$(IOPKT_ROOT)/lib/socket/public

CCFLAGS+=		-fno-builtin-log -D_KERNEL
CCFLAGS+=		-Wp,-include -Wp,$(IOPKT_ROOT)/sys/qnx.h

USEFILE=

EXTRA_SRCVPATH =				\
		$(PROJECT_ROOT)/pci		\
		$(PROJECT_ROOT)/usb		\
		$(IOPKT_ROOT)/sys/dev		\
		$(IOPKT_ROOT)/sys/dev/mii
NAME=nbdrvr
INSTALLDIR=usr/lib

include $(MKFILES_ROOT)/qtargets.mk

CCFLAGS += -Wpointer-arith -Wmissing-prototypes -Werror -Wall -Wno-unused-but-set-variable
