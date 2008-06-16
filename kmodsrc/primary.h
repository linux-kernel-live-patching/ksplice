int init_module(void);
void cleanup_module(void);
void cleanup_ksplice_module(struct module_pack *pack);
int activate_primary(struct module_pack *pack);
int resolve_patch_symbols(struct module_pack *pack);
int procfile_read(char *buffer, char **buffer_location, off_t offset,
		  int buffer_length, int *eof, void *data);
int procfile_write(struct file *file, const char *buffer,
		   unsigned long count, void *data);
int __apply_patches(void *packptr);
int __reverse_patches(void *packptr);
int check_each_task(struct module_pack *pack);
int check_task(struct module_pack *pack, struct task_struct *t);
int check_stack(struct module_pack *pack, struct thread_info *tinfo,
		long *stack);
int check_address_for_conflict(struct module_pack *pack, long addr);
int valid_stack_ptr(struct thread_info *tinfo, void *p);
