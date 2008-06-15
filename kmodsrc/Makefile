ifneq ($(KERNELRELEASE),)

EXTRA_CFLAGS += "-DKSPLICE_ID=$(KSPLICE_ID)"
EXTRA_CFLAGS += "-Dmap_printk=((long)0x$(map_printk))"

KSPLICE = ksplice-$(KSPLICE_ID)

obj-m = $(KSPLICE)-helper.o $(KSPLICE).o
$(KSPLICE)-helper-objs = helper.o modcommon.o allcommon.o collection.o.helper
$(KSPLICE)-objs = primary.o modcommon.o allcommon.o collection.o.primary

else

all $(MAKECMDGOALS):
	$(MAKE) -C $(KERNELSRC) M=$(CURDIR) $(MAKECMDGOALS)

.PHONY: all $(MAKECMDGOALS)

endif
