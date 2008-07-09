#include <linux/kernel.h>

static const char jumplen[256] = {
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

static int run_pre_cmp(struct module_pack *pack, long run_addr, long pre_addr,
		       int size, int rerun)
{
	int run_o = 0, pre_o = 0, lenient = 0;
	int matched;
	int o;
	unsigned char run, pre;
	struct reloc_addrmap *map;

	if (size == 0)
		return 1;

	while (run_o < size && pre_o < size) {
		if (lenient > 0)
			lenient--;

		if (!virtual_address_mapped(run_addr + run_o))
			return 1;

		map = find_addrmap(pack, pre_addr + pre_o);
		if (map != NULL) {
			if (handle_myst_reloc
			    (pack, pre_addr, &pre_o, run_addr, &run_o, map,
			     rerun) == 1)
				return 1;
			continue;
		}

		matched = match_nop((unsigned char *)(run_addr + run_o));
		if (matched > 0) {
			if (rerun) {
				for (o = 0; o < matched; o++)
					printk("%02x/ ",
					       *(unsigned char *)(run_addr +
								  o));
			}
			run_o += matched;
			continue;
		}
		matched = match_nop((unsigned char *)(pre_addr + pre_o));
		if (matched > 0) {
			if (rerun) {
				for (o = 0; o < matched; o++)
					printk("/%02x ",
					       *(unsigned char *)(pre_addr
								  + o));
			}
			pre_o += matched;
			continue;
		}

		run = *(unsigned char *)(run_addr + run_o);
		pre = *(unsigned char *)(pre_addr + pre_o);

		if (rerun)
			printk("%02x/%02x ", run, pre);

		if (run == pre) {
			if (jumplen[pre])
				lenient = max(jumplen[pre] + 1, lenient);
			pre_o++, run_o++;
			continue;
		}

		if (jumplen[run] && jumplen[pre]) {
			run_o += 1 + jumplen[run];
			pre_o += 1 + jumplen[pre];
			continue;
		}
		if (lenient) {
			pre_o++, run_o++;
			continue;
		}
		if (rerun)
			printk("[p_o=%08x] ! %02x/%02x %02x/%02x",
			       pre_o,
			       *(unsigned char *)(run_addr + run_o + 1),
			       *(unsigned char *)(pre_addr + pre_o + 1),
			       *(unsigned char *)(run_addr + run_o + 2),
			       *(unsigned char *)(pre_addr + pre_o + 2));
		return 1;
	}
	return 0;
}

static int match_nop(unsigned char *addr)
{
	int i, j;
	struct insn *nop;
	for (i = NUM_NOPS - 1; i >= 0; i--) {
		nop = &nops[i];
		for (j = 0; j < nop->len; j++) {
			if (!virtual_address_mapped((long)&addr[j]))
				break;
			if (addr[j] != nop->data[j])
				break;
		}
		if (j == nop->len)
			return j;
	}
	return 0;
}
