ksplice-script = /usr/local/share/ksplice/ksplice.pl

ifneq ($(KERNELRELEASE),)

ifneq ($(KSPLICE_STANDALONE),)
CFLAGS_ksplice.o += -DKSPLICE_STANDALONE
CFLAGS_primary.o += -DKSPLICE_STANDALONE
CFLAGS_helper.o += -DKSPLICE_STANDALONE
endif

ifeq ($(KSPLICE_ID),)
    $(error "You must set KSPLICE_ID.")
endif
CFLAGS_primary.o += "-DKSPLICE_ID=$(KSPLICE_ID)"
CFLAGS_helper.o += "-DKSPLICE_ID=$(KSPLICE_ID)"

ifeq ($(KSPLICE_TARGET),)
    $(error "You must set KSPLICE_TARGET.")
endif
ifneq ($(KSPLICE_TARGET),vmlinux)
    CFLAGS_primary.o += "-DKSPLICE_TARGET=$(KSPLICE_TARGET)"
    CFLAGS_helper.o += "-DKSPLICE_TARGET=$(KSPLICE_TARGET)"
endif

ifeq ($(map_printk),)
    $(error "You must set map_printk.")
endif
CFLAGS_primary.o += "-DMAP_PRINTK=0x$(map_printk)L"

KSPLICE = ksplice-$(KSPLICE_ID)

obj-m = $(KSPLICE)-helper.o $(KSPLICE).o
$(KSPLICE)-helper-objs = helper.o collection.o.helper
ifeq ($(KSPLICE_STANDALONE),)
$(KSPLICE)-objs = primary.o collection.o.primary
else
$(KSPLICE)-objs = primary.o ksplice-rmsyms.o collection.o.primary
extra-y = ksplice.o

RMSYMS = \
	apply_paravirt \
	thread_return \
	bust_spinlocks \
	task_curr \
	__kernel_text_address \
	tasklist_lock \
	stop_machine_run \
	module_mutex \
	modules \
	init_mm \
	kallsyms_addresses \
	kallsyms_num_syms \
	kallsyms_names \
	kallsyms_token_table \
	kallsyms_token_index \
	module_text_address \
	lookup_address

quiet_cmd_ksplice-rmsyms = RMSYMS  $@
cmd_ksplice-rmsyms = \
	$(ksplice-script) rmsyms $< $(RMSYMS); \
	ld -r -o $@ $< $(src)/ksplice.lds
$(obj)/ksplice-rmsyms.o: $(obj)/ksplice.o FORCE
	$(call if_changed,ksplice-rmsyms)
endif # KSPLICE_STANDALONE

else

all $(MAKECMDGOALS):
	$(MAKE) -C $(KERNELSRC) M=$(CURDIR) $(MAKECMDGOALS)

.PHONY: all $(MAKECMDGOALS)

endif
