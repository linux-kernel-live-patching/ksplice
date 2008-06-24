ifneq ($(KERNELRELEASE),)

CFLAGS_ksplice.o += -DKSPLICE_STANDALONE
CFLAGS_primary.o += -DKSPLICE_STANDALONE
CFLAGS_helper.o += -DKSPLICE_STANDALONE

ifeq ($(KSPLICE_ID),)
    $(error "You must set KSPLICE_ID.")
endif
CFLAGS_primary.o += "-DKSPLICE_ID=$(KSPLICE_ID)"
CFLAGS_helper.o += "-DKSPLICE_ID=$(KSPLICE_ID)"

ifeq ($(map_printk),)
    $(error "You must set map_printk.")
endif
CFLAGS_primary.o += "-DMAP_PRINTK=0x$(map_printk)L"

KSPLICE = ksplice-$(KSPLICE_ID)

obj-m = $(KSPLICE)-helper.o $(KSPLICE).o
$(KSPLICE)-helper-objs = helper.o collection.o.helper
$(KSPLICE)-objs = primary.o ksplice.o collection.o.primary

else

all $(MAKECMDGOALS):
	$(MAKE) -C $(KERNELSRC) M=$(CURDIR) $(MAKECMDGOALS)

.PHONY: all $(MAKECMDGOALS)

endif
