#include <linux/kernel.h>

#ifndef FUNCTION_SECTIONS
static const char jumps[256] = {
	[0x0f] = 4,		/* je */
	[0x70] = 1,		/* jo */
	[0x71] = 1,		/* jno */
	[0x72] = 1,		/* jb */
	[0x73] = 1,		/* jnb */
	[0x74] = 1,		/* jc */
	[0x75] = 1,		/* jne */
	[0x76] = 1,		/* jbe */
	[0x77] = 1,		/* ja */
	[0x78] = 1,		/* js */
	[0x79] = 1,		/* jns */
	[0x7a] = 1,		/* jp */
	[0x7b] = 1,		/* jnp */
	[0x7c] = 1,		/* jl */
	[0x7d] = 1,		/* jge */
	[0x7e] = 1,		/* jle */
	[0x7f] = 1,		/* jg */
	[0xe9] = 4,		/* jmp */
	[0xe8] = 4,		/* call */
	[0xeb] = 1,		/* jmp */
};

/* Various efficient no-op patterns for aligning code labels.
   Note: Don't try to assemble the instructions in the comments.
   0L and 0w are not legal. */

#define NUM_NOPS (sizeof(nops) / sizeof(nops[0]))
struct insn {
	size_t len;
	const unsigned char *data;
};

/* *INDENT-OFF* */
#define I(...) {							\
		.len = sizeof((const unsigned char []){__VA_ARGS__}),	\
		.data = ((const unsigned char []){__VA_ARGS__}),	\
	}
static const struct insn nops[] = {
/* GNU assembler no-op patterns from
   binutils-2.17/gas/config/tc-i386.c line 500 */
I(0x90),					/* nop                  */
I(0x89, 0xf6),					/* movl %esi,%esi       */
I(0x8d, 0x76, 0x00),				/* leal 0(%esi),%esi    */
I(0x8d, 0x74, 0x26, 0x00),			/* leal 0(%esi,1),%esi  */
I(0x90,						/* nop                  */
  0x8d, 0x74, 0x26, 0x00),			/* leal 0(%esi,1),%esi  */
I(0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00),		/* leal 0L(%esi),%esi   */
I(0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%esi,1),%esi */
I(0x90,						/* nop                  */
  0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%esi,1),%esi */
I(0x89, 0xf6,					/* movl %esi,%esi       */
  0x8d, 0xbc, 0x27, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%edi,1),%edi */
I(0x8d, 0x76, 0x00,				/* leal 0(%esi),%esi    */
  0x8d, 0xbc, 0x27, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%edi,1),%edi */
I(0x8d, 0x74, 0x26, 0x00,			/* leal 0(%esi,1),%esi  */
  0x8d, 0xbc, 0x27, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%edi,1),%edi */
I(0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00,		/* leal 0L(%esi),%esi   */
  0x8d, 0xbf, 0x00, 0x00, 0x00, 0x00),		/* leal 0L(%edi),%edi   */
I(0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00,		/* leal 0L(%esi),%esi   */
  0x8d, 0xbc, 0x27, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%edi,1),%edi */
I(0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00,	/* leal 0L(%esi,1),%esi */
  0x8d, 0xbc, 0x27, 0x00, 0x00, 0x00, 0x00),	/* leal 0L(%edi,1),%edi */
I(0xeb, 0x0d, 0x90, 0x90, 0x90, 0x90, 0x90,	/* jmp .+15; lotsa nops */
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90),

/* binutils-2.17/gas/config/tc-i386.c line 570 */
I(0x66, 0x90),					/* xchg %ax,%ax         */
I(0x66,						/* data16               */
  0x66, 0x90),					/* xchg %ax,%ax         */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x90),					/* xchg %ax,%ax         */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x90),					/* xchg %ax,%ax         */

/* binutils-2.18/gas/config/tc-i386.c line 572 */
I(0x0f, 0x1f, 0x00),				/* nopl (%[re]ax)       */
I(0x0f, 0x1f, 0x40, 0x00),			/* nopl 0(%[re]ax)      */
I(0x0f, 0x1f, 0x44, 0x00, 0x00),	/* nopl 0(%[re]ax,%[re]ax,1)    */
I(0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00),	/* nopw 0(%[re]ax,%[re]ax,1)    */
I(0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00),
					/* nopw 0(%[re]ax,%[re]ax,1)    */
I(0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
					/* nopl 0L(%[re]ax,%[re]ax,1)   */
I(0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
					/* nopw 0L(%[re]ax,%[re]ax,1)   */
I(0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x66,						/* data16               */
  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66,						/* data16               */
  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
				/* nopw %cs:0L(%[re]ax,%[re]ax,1)       */
I(0x0f, 0x1f, 0x44, 0x00, 0x00,		/* nopl 0(%[re]ax,%[re]ax,1)    */
  0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00),	/* nopw 0(%[re]ax,%[re]ax,1)    */
I(0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,	/* nopw 0(%[re]ax,%[re]ax,1)    */
  0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00),	/* nopw 0(%[re]ax,%[re]ax,1)    */
I(0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,	/* nopw 0(%[re]ax,%[re]ax,1)    */
  0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00),	/* nopl 0L(%[re]ax)     */
I(0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,	/* nopl 0L(%[re]ax)     */
  0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00),	/* nopl 0L(%[re]ax)     */
I(0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,	/* nopl 0L(%[re]ax)     */
  0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00),
					/* nopl 0L(%[re]ax,%[re]ax,1)   */
};
/* *INDENT-ON* */

static int match_nop(const unsigned char *addr);
static int jumplen(const unsigned char *addr);
static int jumpsize(const unsigned char *addr);
static int match_jump_types(const unsigned char *run, const unsigned char *pre);
static int canonicalize_jump(const unsigned char *addr);

static abort_t run_pre_cmp(struct module_pack *pack,
			   const struct ksplice_size *s, unsigned long run_addr,
			   int rerun)
{
	int runc, prec, matched;
	const unsigned char *run, *pre;
	abort_t ret;
	unsigned long pre_addr = s->thismod_addr;

	if (s->size == 0)
		return NO_MATCH;

	run_addr = follow_trampolines(pack, run_addr);

	run = (const unsigned char *)run_addr;
	pre = (const unsigned char *)pre_addr;

	while (run < (const unsigned char *)run_addr + s->size &&
	       pre < (const unsigned char *)pre_addr + s->size) {
		if (!virtual_address_mapped((unsigned long)run))
			return NO_MATCH;

		ret = handle_myst_reloc(pack, (unsigned long)pre,
					(unsigned long)run, rerun, &matched);
		if (ret != OK) {
			ksdebug(pack, 3, KERN_DEBUG "Matching failure at "
				"offset %lx\n", (unsigned long)pre - pre_addr);
			return ret;
		}
		if (matched > 0) {
			if (rerun)
				print_bytes(pack, run, matched, pre, matched);
			run += matched;
			pre += matched;
			continue;
		}

		if (*run == *pre && jumplen(run)) {
			int len = jumplen(run);
			if (jumpsize(run) != jumpsize(pre) ||
			    (jumpsize(run) == 2 && pre[1] != run[1]))
				return NO_MATCH;
			if (rerun)
				print_bytes(pack, run, jumpsize(run), pre,
					    jumpsize(pre));
			run += jumpsize(run);
			pre += jumpsize(pre);
			ret = handle_myst_reloc(pack, (unsigned long)pre,
						(unsigned long)run, rerun,
						&matched);
			if (ret != OK) {
				ksdebug(pack, 3, KERN_DEBUG "Matching failure "
					"at offset %lx\n", (unsigned long)pre -
					pre_addr);
				return NO_MATCH;
			}
			if (matched > 0) {
				if (rerun)
					print_bytes(pack, run, matched, pre,
						    matched);
				run += matched;
				pre += matched;
			} else {
				/* lenient; we should check these addresses */
				if (rerun)
					print_bytes(pack, run, len, pre, len);
				run += len;
				pre += len;
			}
			continue;
		}

		if (match_jump_types(run, pre)) {
			if (rerun)
				print_bytes(pack,
					    run, jumpsize(run) + jumplen(run),
					    pre, jumpsize(pre) + jumplen(pre));
			/* lenient; we should check these addresses */
			run += jumpsize(run) + jumplen(run);
			pre += jumpsize(pre) + jumplen(pre);
			continue;
		}

		runc = match_nop(run);
		prec = match_nop(pre);
		if (runc > 0 || prec > 0) {
			if (rerun)
				print_bytes(pack, run, runc, pre, prec);
			run += runc;
			pre += prec;
			continue;
		}

		if (*run == *pre) {
			if (rerun)
				print_bytes(pack, run, 1, pre, 1);
			run++;
			pre++;
			continue;
		}

		if (rerun) {
			print_bytes(pack, run, 1, pre, 1);
			ksdebug(pack, 0, "[p_o=%lx] ! ", (unsigned long)pre -
				pre_addr);
			print_bytes(pack, run + 1, 2, pre + 1, 2);
		}
		return NO_MATCH;
	}
	return OK;
}

static int jumplen(const unsigned char *addr)
{
	if (!jumps[addr[0]])
		return 0;
	if (addr[0] == 0x0f && (!virtual_address_mapped((unsigned long)&addr[1])
				|| addr[1] < 0x80 || addr[1] >= 0x90))
		return 0;
	return jumps[addr[0]];
}

static int jumpsize(const unsigned char *addr)
{
	if (!jumps[addr[0]])
		return 0;
	if (addr[0] == 0x0f && addr[1] >= 0x80 && addr[1] < 0x90)
		return 2;
	return 1;
}

static int canonicalize_jump(const unsigned char *addr)
{
	if (addr[0] == 0x0f)
		return addr[1] - 0x10;
	if (addr[0] == 0xe9)
		return 0xeb;
	return addr[0];
}

static int match_jump_types(const unsigned char *run, const unsigned char *pre)
{
	return jumplen(run) && jumplen(pre) &&
	    canonicalize_jump(run) == canonicalize_jump(pre);
}

static int match_nop(const unsigned char *addr)
{
	int i, j;
	const struct insn *nop;
	for (i = NUM_NOPS - 1; i >= 0; i--) {
		nop = &nops[i];
		for (j = 0; j < nop->len; j++) {
			if (!virtual_address_mapped((unsigned long)&addr[j]))
				break;
			if (addr[j] != nop->data[j])
				break;
		}
		if (j == nop->len)
			return j;
	}
	return 0;
}

#endif /* !FUNCTION_SECTIONS */

static unsigned long follow_trampolines(struct module_pack *pack,
					unsigned long addr)
{
	if (virtual_address_mapped(addr) &&
	    virtual_address_mapped(addr + 5 - 1) &&
	    *((const unsigned char *)addr) == 0xE9) {
		/* Remember to add the length of the e9 */
		unsigned long new_addr = addr + 5 + *(int32_t *)(addr + 1);
		/* Confirm that it is a jump into a ksplice module */
		struct module *m = __module_text_address(new_addr);
		if (m != NULL && m != pack->target &&
		    strncmp(m->name, "ksplice", strlen("ksplice")) == 0) {
			ksdebug(pack, 3, KERN_DEBUG "ksplice: Following "
				"trampoline %lx %lx\n", addr, new_addr);
			addr = new_addr;
		}
	}
	return addr;
}

static abort_t create_trampoline(struct ksplice_patch *p)
{
	p->trampoline[0] = 0xE9;
	*(u32 *)(&p->trampoline[1]) = p->repladdr - (p->oldaddr + 5);
	p->size = 5;
	return OK;
}

static abort_t handle_paravirt(struct module_pack *pack, unsigned long pre_addr,
			       unsigned long run_addr, int *matched)
{
	int32_t *run = (int32_t *)(run_addr + 1);
	int32_t *pre = (int32_t *)(pre_addr + 1);
	*matched = 0;

	if (!virtual_address_mapped(run_addr + 5) ||
	    !virtual_address_mapped(pre_addr + 5))
		return OK;

	if ((*(uint8_t *)run_addr == 0xe8 && *(uint8_t *)pre_addr == 0xe8) ||
	    (*(uint8_t *)run_addr == 0xe9 && *(uint8_t *)pre_addr == 0xe9))
		if ((unsigned long)run + *run == (unsigned long)pre + *pre)
			*matched = 5;
	return OK;
}
