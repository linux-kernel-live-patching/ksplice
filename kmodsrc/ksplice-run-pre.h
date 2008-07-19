#include <linux/kernel.h>

static const char jumps[256] = {
	[0x0f] = 5,		/* je */
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
	unsigned char *data;
};

/* *INDENT-OFF* */
#define I(...) {						\
		.len = sizeof((unsigned char []){__VA_ARGS__}),	\
		.data = ((unsigned char []){__VA_ARGS__}),	\
	}
static struct insn nops[] = {
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

static int match_nop(unsigned char *addr);
static void print_bytes(struct module_pack *pack, unsigned char *run, int runc,
			unsigned char *pre, int prec);
static int jumplen(unsigned char *addr);

static int run_pre_cmp(struct module_pack *pack, unsigned long run_addr,
		       unsigned long pre_addr, unsigned int size, int rerun)
{
	int lenient = 0;
	int runc, prec, matched;
	unsigned char *run, *pre;
	struct reloc_addrmap *map;

	if (size == 0)
		return 1;

	run = (unsigned char *)run_addr;
	pre = (unsigned char *)pre_addr;

	while (run < (unsigned char *)run_addr + size &&
	       pre < (unsigned char *)pre_addr + size) {

		if (lenient > 0)
			lenient--;

		if (!virtual_address_mapped((unsigned long)run))
			return 1;

		map = find_addrmap(pack, (unsigned long)pre);
		if (map != NULL) {
			if (!rerun)
				ksdebug(pack, 3, KERN_DEBUG "ksplice_h: "
					"run-pre: reloc at r_a=%" ADDR
					" p_o=%lx: ", run_addr,
					(unsigned long)pre - pre_addr);
			matched =
			    handle_myst_reloc(pack, (unsigned long)pre,
					      (unsigned long)run, map, rerun);
			if (matched < 0)
				return 1;
			if (rerun)
				print_bytes(pack, run, matched, pre, matched);
			run += matched;
			pre += matched;
			continue;
		}

		runc = match_nop(run);
		prec = match_nop(pre);
		if (rerun)
			print_bytes(pack, run, runc, pre, prec);
		if (runc > 0 || prec > 0) {
			run += runc;
			pre += prec;
			continue;
		}

		if (rerun)
			print_bytes(pack, run, 1, pre, 1);

		if (*run == *pre) {
			if (jumplen(pre))
				lenient = max(jumplen(pre) + 1, lenient);
			pre++, run++;
			continue;
		}

		if (jumplen(run) && jumplen(pre)) {
			run += 1 + jumplen(run);
			pre += 1 + jumplen(pre);
			continue;
		}
		if (lenient) {
			pre++, run++;
			continue;
		}
		if (rerun) {
			ksdebug(pack, 0, "[p_o=%lx] ! ", (unsigned long)pre -
				pre_addr);
			print_bytes(pack, run + 1, 2, pre + 1, 2);
		}
		return 1;
	}
	return 0;
}

static int jumplen(unsigned char *addr)
{
	if (!jumps[addr[0]])
		return 0;
	if (addr[0] == 0x0f && (!virtual_address_mapped((unsigned long)&addr[1])
				|| addr[1] < 0x80 || addr[1] >= 0x90))
		return 0;
	return jumps[addr[0]];
}

static int match_nop(unsigned char *addr)
{
	int i, j;
	struct insn *nop;
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

static void print_bytes(struct module_pack *pack, unsigned char *run, int runc,
			unsigned char *pre, int prec)
{
	int o;
	int matched = min(runc, prec);
	for (o = 0; o < matched; o++)
		ksdebug(pack, 0, "%02x/%02x ", run[o], pre[o]);
	for (o = matched; o < runc; o++)
		ksdebug(pack, 0, "%02x/ ", run[o]);
	for (o = matched; o < prec; o++)
		ksdebug(pack, 0, "/%02x ", pre[o]);
}
