obj-m = $(KSPLICE)-helper.o $(KSPLICE).o
$(KSPLICE)-helper-objs = helper.o modcommon.o allcommon.o collection.o.helper
$(KSPLICE)-objs = primary.o modcommon.o allcommon.o collection.o.primary

modules:
	make -C $(KERNELSRC) M=$(PWD) modules || exit 0

modules_clean:
	make -C $(KERNELSRC) M=$(PWD) clean
