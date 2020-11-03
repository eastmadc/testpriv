# Root that included us has to set IOPKT_ROOT.
#
# By default all our objs are excluded.  You have to
# set up a COMMON_ORG and opt in on a per source file
# basis below.

COMMON_SRC_DIRS :=					\
	$(IOPKT_ROOT)/common/lib/libc/md		\
	$(IOPKT_ROOT)/common/lib/libc/string		\
	$(IOPKT_ROOT)/common/lib/libc/stdio		\
	$(IOPKT_ROOT)/common/lib/libc/hash/sha2		\
	$(IOPKT_ROOT)/common/lib/libc/hash/sha1		\
	$(IOPKT_ROOT)/common/lib/libc/hash/rmd160	\
	$(IOPKT_ROOT)/common/lib/libc/hash/aesxcbcmac	
COMMON_SRC := $(wildcard $(foreach dir, $(COMMON_SRC_DIRS), $(addprefix $(dir)/*., s S c cc)))
COMMON_OBJS := $(sort $(addsuffix .o, $(basename $(notdir $(COMMON_SRC)))))

EXTRA_SRCVPATH += $(COMMON_SRC_DIRS)

# Exclude everything.  Have to opt in individually below.
COMMON_EXCLUDE_OBJS := $(COMMON_OBJS)

# Objects may be in libsocket or libnbutil but not
# both (or at least not exported from libsocket if 
# also in libnbutil (see libsocket.ver))

ifeq ($(COMMON_ORG), IO_PKT_LIBKERN)
COMMON_ORG_SRC := md5c.c strlcpy.c strlcat.c sha2.c sha1.c rmd160.c aesxcbcmac.c
endif

ifeq ($(COMMON_ORG), IO_PKT_LIBSOCKET)
COMMON_ORG_SRC := strlcpy.c strlcat.c fparseln.c fgetln.c md5c.c
endif

ifeq ($(COMMON_ORG), IO_PKT_LIBNBUTIL)
COMMON_ORG_SRC := strlcpy.c strlcat.c md5c.c fparseln.c fgetln.c
endif

COMMON_ORG_OBJS := $(sort $(addsuffix .o, $(basename $(notdir $(COMMON_ORG_SRC)))))

EXCLUDE_OBJS += $(filter-out $(COMMON_ORG_OBJS), $(COMMON_EXCLUDE_OBJS))
