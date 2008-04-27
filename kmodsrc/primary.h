int init_module(void);
void cleanup_module(void);
int ksplice_do_primary(void);
int resolve_patch_symbols(void);
int procfile_read(char *buffer, char **buffer_location, off_t offset,
		  int buffer_length, int *eof, void *data);
int procfile_write(struct file *file, const char *buffer,
		   unsigned long count, void *data);
int __apply_patches(void *unused);
int __reverse_patches(void *unused);
int ksplice_on_each_task(int (*func) (struct task_struct * t, void *d),
			 void *data);
int check_task(struct task_struct *t, void *d);
int check_stack(struct thread_info *tinfo, long *stack);
int check_address_for_conflict(long addr);
int valid_stack_ptr(struct thread_info *tinfo, void *p);
